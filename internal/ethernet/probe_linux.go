//go:build linux

package ethernet

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"gateway-vpn/internal/uplink"
)

type SysFSProbe struct {
	Root         string
	IdentitySalt []byte
	Addresses    func(string) ([]string, error)
}

func HostProbe(identitySalt []byte) Probe {
	return SysFSProbe{IdentitySalt: append([]byte(nil), identitySalt...)}
}

func (probe SysFSProbe) List(ctx context.Context) ([]Device, error) {
	if len(probe.IdentitySalt) < 32 {
		return nil, errors.New("at least 32-byte interface identity salt is required")
	}
	root := probe.Root
	if root == "" {
		root = "/sys"
	}
	entries, err := os.ReadDir(filepath.Join(root, "class", "net"))
	if err != nil {
		return nil, fmt.Errorf("read sysfs interface inventory: %w", err)
	}
	result := make([]Device, 0, len(entries))
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		name := entry.Name()
		if !validIfname(name) || name == "lo" {
			continue
		}
		base := filepath.Join(root, "class", "net", name)
		devicePath, err := filepath.EvalSymlinks(filepath.Join(base, "device"))
		if err != nil || !pathInside(root, devicePath) {
			continue
		}
		linkType, err := readInteger(filepath.Join(base, "type"), 0, 1<<31-1)
		if err != nil || linkType != 1 {
			continue
		}
		if usbVendor(devicePath, root) == "12d1" {
			continue
		}
		macText := strings.ToLower(strings.TrimSpace(readSmall(filepath.Join(base, "address"))))
		mac, macErr := net.ParseMAC(macText)
		addressAssignment, assignmentErr := readInteger(filepath.Join(base, "addr_assign_type"), 0, 4)
		topology, _ := filepath.Rel(filepath.Join(root, "devices"), devicePath)
		topology = filepath.ToSlash(topology)
		kind, identity, permanentMAC := "", "", ""
		if assignmentErr == nil && addressAssignment == 0 && macErr == nil && len(mac) == 6 && mac[0]&1 == 0 && !zeroMAC(mac) {
			kind, identity = "ETHERNET_PERMANENT_MAC", mac.String()
			permanentMAC = mac.String()
		} else if topology != "" && !strings.HasPrefix(topology, "..") {
			kind, identity = "ETHERNET_TOPOLOGY", topology
		} else {
			continue
		}
		hash := identityHash(probe.IdentitySalt, kind, identity)
		addressReader := probe.Addresses
		if addressReader == nil {
			addressReader = interfaceAddresses
		}
		addresses, err := addressReader(name)
		if err != nil {
			return nil, err
		}
		carrier := "UNKNOWN"
		switch strings.TrimSpace(readSmall(filepath.Join(base, "carrier"))) {
		case "1":
			carrier = "UP"
		case "0":
			carrier = "DOWN"
		}
		driver := ""
		if path, err := filepath.EvalSymlinks(filepath.Join(devicePath, "driver")); err == nil {
			driver = filepath.Base(path)
		}
		mtu, _ := readInteger(filepath.Join(base, "mtu"), 576, 9216)
		masterIfname := ""
		if masterPath, err := filepath.EvalSymlinks(filepath.Join(base, "master")); err == nil && pathInside(root, masterPath) {
			candidate := filepath.Base(masterPath)
			if validIfname(candidate) && candidate != name {
				masterIfname = candidate
			}
		}
		result = append(result, Device{Observation: uplink.InterfaceObservation{
			ID: "netif:ethernet:" + hash[:24], StableIdentityKind: kind,
			StableIdentityHash: hash, PermanentMAC: permanentMAC, TopologyPath: topology,
			CurrentIfname: name, Driver: driver,
			Vendor:       strings.TrimSpace(readSmall(filepath.Join(devicePath, "vendor"))),
			Model:        strings.TrimSpace(readSmall(filepath.Join(devicePath, "device"))),
			CarrierState: carrier, Addresses: addresses,
		}, MasterIfname: masterIfname, MTU: int64(mtu)})
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Observation.ID < result[j].Observation.ID })
	return result, nil
}

func interfaceAddresses(name string) ([]string, error) {
	item, err := net.InterfaceByName(name)
	if err != nil {
		return nil, fmt.Errorf("read interface %s addresses: %w", name, err)
	}
	addresses, err := item.Addrs()
	if err != nil {
		return nil, fmt.Errorf("read interface %s addresses: %w", name, err)
	}
	result := make([]string, 0, len(addresses))
	for _, address := range addresses {
		ip, _, err := net.ParseCIDR(address.String())
		if err != nil || ip == nil || ip.To4() == nil {
			continue
		}
		result = append(result, address.String())
	}
	sort.Strings(result)
	return result, nil
}

func identityHash(salt []byte, kind, identity string) string {
	digest := hmac.New(sha256.New, salt)
	digest.Write([]byte(kind))
	digest.Write([]byte{0})
	digest.Write([]byte(identity))
	return hex.EncodeToString(digest.Sum(nil))
}

func usbVendor(start, root string) string {
	current := start
	for pathInside(root, current) && current != root {
		if vendor := strings.ToLower(strings.TrimSpace(readSmall(filepath.Join(current, "idVendor")))); vendor != "" {
			return vendor
		}
		parent := filepath.Dir(current)
		if parent == current {
			break
		}
		current = parent
	}
	return ""
}

func pathInside(root, path string) bool {
	root, rootErr := filepath.Abs(root)
	path, pathErr := filepath.Abs(path)
	if rootErr != nil || pathErr != nil {
		return false
	}
	relative, err := filepath.Rel(root, path)
	return err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}

func readSmall(filename string) string {
	content, err := os.ReadFile(filename)
	if err != nil || len(content) > 4096 {
		return ""
	}
	return string(content)
}

func readInteger(filename string, minimum, maximum int) (int, error) {
	value, err := strconv.Atoi(strings.TrimSpace(readSmall(filename)))
	if err != nil || value < minimum || value > maximum {
		return 0, errors.New("sysfs integer is invalid")
	}
	return value, nil
}

func zeroMAC(address net.HardwareAddr) bool {
	for _, value := range address {
		if value != 0 {
			return false
		}
	}
	return true
}

func validIfname(value string) bool {
	if value == "" || len(value) > 15 {
		return false
	}
	for _, character := range value {
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') || (character >= '0' && character <= '9') || strings.ContainsRune("_.:-", character) {
			continue
		}
		return false
	}
	return true
}
