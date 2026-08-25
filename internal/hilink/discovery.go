// Package hilink discovers and validates USB-Ethernet HiLink uplinks without
// treating transient Linux interface names as modem identity.
package hilink

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"

	"gateway-vpn/internal/modem"
)

const (
	DiscoveryUnadopted = "UNADOPTED"
	DiscoveryMatched   = "MATCHED"
	DiscoveryAmbiguous = "AMBIGUOUS"
)

type RawDevice struct {
	InterfaceName string
	VendorID      string
	ProductID     string
	USBSerial     string
	PermanentMAC  string
	USBTopology   string
	Driver        string
	Carrier       bool
}

type Probe interface {
	ListUSBNetworkDevices(context.Context) ([]RawDevice, error)
}

type Options struct {
	IdentitySalt []byte
	VendorIDs    []string
}

type Candidate struct {
	DiscoveryID   string
	InterfaceName string
	VendorID      string
	ProductID     string
	Driver        string
	Carrier       bool
	IdentityKind  string
	IdentityHash  string
	MaskedSerial  string
	TopologyHint  string
}

type Match struct {
	Candidate Candidate
	State     string
	ModemID   string
	Reason    string
}

func Discover(ctx context.Context, probe Probe, options Options) ([]Candidate, error) {
	if probe == nil || len(options.IdentitySalt) < 32 {
		return nil, errors.New("HiLink discovery probe and at least 32-byte identity salt are required")
	}
	allowedVendors := make(map[string]struct{})
	for _, vendor := range options.VendorIDs {
		vendor = strings.ToLower(strings.TrimSpace(vendor))
		if len(vendor) != 4 {
			return nil, errors.New("USB vendor ids must contain four hexadecimal characters")
		}
		if _, err := hex.DecodeString(vendor); err != nil {
			return nil, errors.New("USB vendor id is not hexadecimal")
		}
		allowedVendors[vendor] = struct{}{}
	}
	if len(allowedVendors) == 0 {
		allowedVendors["12d1"] = struct{}{}
	}
	raw, err := probe.ListUSBNetworkDevices(ctx)
	if err != nil {
		return nil, err
	}
	var result []Candidate
	seenInterfaces := make(map[string]struct{})
	for _, device := range raw {
		device.VendorID = strings.ToLower(strings.TrimSpace(device.VendorID))
		device.ProductID = strings.ToLower(strings.TrimSpace(device.ProductID))
		if _, allowed := allowedVendors[device.VendorID]; !allowed {
			continue
		}
		if !validInterfaceName(device.InterfaceName) || len(device.ProductID) != 4 {
			return nil, fmt.Errorf("invalid USB network device metadata for %q", device.InterfaceName)
		}
		if _, exists := seenInterfaces[device.InterfaceName]; exists {
			return nil, fmt.Errorf("duplicate USB network interface %s", device.InterfaceName)
		}
		seenInterfaces[device.InterfaceName] = struct{}{}
		kind, identity, masked, err := strongestIdentity(device)
		if err != nil {
			return nil, fmt.Errorf("identify USB network interface %s: %w", device.InterfaceName, err)
		}
		identityHash := saltedIdentityHash(options.IdentitySalt, kind, identity)
		discoveryDigest := sha256.Sum256([]byte(device.VendorID + "\x00" + device.ProductID + "\x00" + identityHash))
		result = append(result, Candidate{
			DiscoveryID:   "discovery-" + hex.EncodeToString(discoveryDigest[:12]),
			InterfaceName: device.InterfaceName, VendorID: device.VendorID, ProductID: device.ProductID,
			Driver: strings.TrimSpace(device.Driver), Carrier: device.Carrier,
			IdentityKind: kind, IdentityHash: identityHash, MaskedSerial: masked,
			TopologyHint: maskTopology(device.USBTopology),
		})
	}
	sort.Slice(result, func(i, j int) bool { return result[i].DiscoveryID < result[j].DiscoveryID })
	return result, nil
}

func MatchAdopted(candidates []Candidate, adopted []modem.Modem) []Match {
	records := make(map[string][]string)
	for _, item := range adopted {
		key := item.IdentityKind + "\x00" + item.IdentityHash
		records[key] = append(records[key], item.ID)
	}
	candidateCounts := make(map[string]int)
	for _, candidate := range candidates {
		candidateCounts[candidate.IdentityKind+"\x00"+candidate.IdentityHash]++
	}
	result := make([]Match, 0, len(candidates))
	for _, candidate := range candidates {
		key := candidate.IdentityKind + "\x00" + candidate.IdentityHash
		match := Match{Candidate: candidate, State: DiscoveryUnadopted}
		switch {
		case candidateCounts[key] > 1:
			match.State, match.Reason = DiscoveryAmbiguous, "multiple connected interfaces expose the same strongest identity"
		case len(records[key]) > 1:
			match.State, match.Reason = DiscoveryAmbiguous, "multiple adopted modem records share the same identity"
		case len(records[key]) == 1:
			match.State, match.ModemID = DiscoveryMatched, records[key][0]
		}
		result = append(result, match)
	}
	return result
}

func strongestIdentity(device RawDevice) (string, string, string, error) {
	if serial := strings.TrimSpace(device.USBSerial); serial != "" {
		return "usb_serial_hash", serial, maskSerial(serial), nil
	}
	if macText := strings.TrimSpace(device.PermanentMAC); macText != "" {
		mac, err := net.ParseMAC(macText)
		if err == nil && len(mac) == 6 && !isZeroMAC(mac) && mac[0]&1 == 0 {
			return "mac_hash", strings.ToLower(mac.String()), "", nil
		}
	}
	if topology := strings.TrimSpace(device.USBTopology); topology != "" && !strings.Contains(topology, "..") {
		return "usb_topology_hash", topology, "", nil
	}
	return "", "", "", errors.New("device has no usable USB serial, MAC, or topology identity")
}

func saltedIdentityHash(salt []byte, kind, identity string) string {
	digest := hmac.New(sha256.New, salt)
	digest.Write([]byte(kind))
	digest.Write([]byte{0})
	digest.Write([]byte(identity))
	return hex.EncodeToString(digest.Sum(nil))
}

func maskSerial(value string) string {
	runes := []rune(value)
	if len(runes) <= 4 {
		return "****"
	}
	return "****" + string(runes[len(runes)-4:])
}

func maskTopology(value string) string {
	parts := strings.Split(strings.TrimSpace(value), "/")
	if len(parts) == 0 {
		return ""
	}
	return parts[len(parts)-1]
}

func isZeroMAC(mac net.HardwareAddr) bool {
	for _, octet := range mac {
		if octet != 0 {
			return false
		}
	}
	return true
}

func validInterfaceName(value string) bool {
	if value == "" || len(value) > 15 {
		return false
	}
	for _, char := range value {
		if (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') || (char >= '0' && char <= '9') || strings.ContainsRune("_.:-", char) {
			continue
		}
		return false
	}
	return true
}
