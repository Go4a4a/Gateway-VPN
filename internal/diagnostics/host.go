// Package diagnostics builds bounded, secret-free support artifacts for
// Gateway VPN. Privileged host collection is deliberately parameter-free.
package diagnostics

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	pathpkg "path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	loggingpkg "gateway-vpn/internal/logging"
	"gateway-vpn/internal/platformexec"
	"gateway-vpn/internal/routing"
)

const (
	HostSnapshotSchemaVersion = 1
	MaximumHostSnapshotBytes  = 60 << 10
	commandJSONLimit          = int64(24 << 10)
	commandTextLimit          = int64(4 << 10)
	maximumInterfaces         = 128
	maximumInterfaceAddresses = 256
)

var safeInterfaceName = regexp.MustCompile(`^[A-Za-z0-9_.:@-]{1,64}$`)

type SectionError struct {
	Section string `json:"section"`
	Code    string `json:"code"`
}

type OperatingSystem struct {
	ID         string `json:"id,omitempty"`
	VersionID  string `json:"version_id,omitempty"`
	PrettyName string `json:"pretty_name,omitempty"`
}

type InterfaceAddress struct {
	Family    string `json:"family"`
	Local     string `json:"local"`
	PrefixLen int    `json:"prefix_len"`
	Scope     string `json:"scope,omitempty"`
}

type InterfaceSummary struct {
	Name      string             `json:"name"`
	State     string             `json:"state,omitempty"`
	MTU       int                `json:"mtu,omitempty"`
	Addresses []InterfaceAddress `json:"addresses"`
}

type WireGuardPeerSummary struct {
	Index               int      `json:"index"`
	Endpoint            string   `json:"endpoint,omitempty"`
	AllowedIPs          []string `json:"allowed_ips"`
	LatestHandshakeAt   string   `json:"latest_handshake_at,omitempty"`
	TransferRXBytes     uint64   `json:"transfer_rx_bytes"`
	TransferTXBytes     uint64   `json:"transfer_tx_bytes"`
	PersistentKeepalive int      `json:"persistent_keepalive_seconds"`
}

type WireGuardSummary struct {
	Available  bool                   `json:"available"`
	ListenPort int                    `json:"listen_port,omitempty"`
	Fwmark     string                 `json:"fwmark,omitempty"`
	Peers      []WireGuardPeerSummary `json:"peers"`
}

type HostSnapshot struct {
	SchemaVersion int                `json:"schema_version"`
	CollectedAt   string             `json:"collected_at"`
	OS            OperatingSystem    `json:"os"`
	Kernel        string             `json:"kernel,omitempty"`
	Interfaces    []InterfaceSummary `json:"interfaces"`
	OwnedRoutes   json.RawMessage    `json:"owned_routes"`
	OwnedRules    json.RawMessage    `json:"owned_rules"`
	Nftables      json.RawMessage    `json:"nftables"`
	WireGuard     WireGuardSummary   `json:"wireguard"`
	MihomoVersion string             `json:"mihomo_version,omitempty"`
	SectionErrors []SectionError     `json:"section_errors"`
}

// HostCollector invokes only fixed absolute binaries with fixed arguments.
// Paths are set once from the strict bootstrap config by the root broker and
// are never accepted through HTTP.
type HostCollector struct {
	Executor      platformexec.Executor
	IP            string
	NFT           string
	WG            string
	Uname         string
	MihomoBinary  string
	OSReleaseFile string
	Now           func() time.Time
}

func (collector HostCollector) Collect(ctx context.Context) (HostSnapshot, error) {
	if err := collector.validate(); err != nil {
		return HostSnapshot{}, err
	}
	result := HostSnapshot{
		SchemaVersion: HostSnapshotSchemaVersion,
		CollectedAt:   collector.now().Format(time.RFC3339Nano),
		Interfaces:    []InterfaceSummary{},
		OwnedRoutes:   json.RawMessage("[]"),
		OwnedRules:    json.RawMessage("[]"),
		Nftables:      json.RawMessage("{}"),
		WireGuard:     WireGuardSummary{Peers: []WireGuardPeerSummary{}},
		SectionErrors: []SectionError{},
	}
	addError := func(section, code string) {
		result.SectionErrors = append(result.SectionErrors, SectionError{Section: section, Code: code})
	}

	if system, err := readOSRelease(collector.OSReleaseFile); err == nil {
		result.OS = system
	} else {
		addError("os", "OS_RELEASE_UNAVAILABLE")
	}
	if output, err := collector.run(ctx, collector.Uname, []string{"-r"}, commandTextLimit); err == nil {
		result.Kernel = boundedText(strings.TrimSpace(output), 256)
	} else {
		addError("kernel", "KERNEL_VERSION_UNAVAILABLE")
	}
	if output, err := collector.run(ctx, collector.IP, []string{"-json", "-4", "address", "show"}, commandJSONLimit); err == nil {
		interfaces, truncated, parseErr := decodeInterfaces([]byte(output))
		if parseErr == nil {
			result.Interfaces = interfaces
			if truncated {
				addError("interfaces", "INTERFACE_SUMMARY_TRUNCATED")
			}
		} else {
			addError("interfaces", "INTERFACE_SUMMARY_INVALID")
		}
	} else {
		addError("interfaces", "INTERFACE_SUMMARY_UNAVAILABLE")
	}
	if output, err := collector.run(ctx, collector.IP, []string{"-json", "-4", "route", "show", "table", "all", "protocol", strconv.Itoa(routing.OwnedProtocol)}, commandJSONLimit); err == nil {
		if sanitized, sanitizeErr := sanitizeJSONArray([]byte(output)); sanitizeErr == nil {
			result.OwnedRoutes = sanitized
		} else {
			addError("routes", "OWNED_ROUTE_SUMMARY_INVALID")
		}
	} else {
		addError("routes", "OWNED_ROUTE_SUMMARY_UNAVAILABLE")
	}
	if output, err := collector.run(ctx, collector.IP, []string{"-json", "-4", "rule", "show"}, commandJSONLimit); err == nil {
		if sanitized, sanitizeErr := sanitizeOwnedRules([]byte(output)); sanitizeErr == nil {
			result.OwnedRules = sanitized
		} else {
			addError("rules", "OWNED_RULE_SUMMARY_INVALID")
		}
	} else {
		addError("rules", "OWNED_RULE_SUMMARY_UNAVAILABLE")
	}
	if output, err := collector.run(ctx, collector.NFT, []string{"-j", "list", "table", "inet", "gateway_vpn"}, commandJSONLimit); err == nil {
		if sanitized, sanitizeErr := sanitizeJSONObject([]byte(output)); sanitizeErr == nil {
			result.Nftables = sanitized
		} else {
			addError("nftables", "NFTABLES_SUMMARY_INVALID")
		}
	} else {
		addError("nftables", "NFTABLES_SUMMARY_UNAVAILABLE")
	}
	if output, err := collector.run(ctx, collector.WG, []string{"show", "wg-mgmt", "dump"}, commandJSONLimit); err == nil {
		if summary, parseErr := decodeWireGuardDump(output); parseErr == nil {
			result.WireGuard = summary
		} else {
			addError("wireguard", "WIREGUARD_SUMMARY_INVALID")
		}
	} else {
		addError("wireguard", "WIREGUARD_SUMMARY_UNAVAILABLE")
	}
	if output, err := collector.run(ctx, collector.MihomoBinary, []string{"-v"}, commandTextLimit); err == nil {
		result.MihomoVersion = boundedText(strings.TrimSpace(output), 512)
	} else {
		addError("mihomo", "MIHOMO_VERSION_UNAVAILABLE")
	}

	payload, err := json.Marshal(result)
	if err != nil || len(payload) > MaximumHostSnapshotBytes {
		return HostSnapshot{}, errors.New("host diagnostic snapshot exceeds its fixed bound")
	}
	return result, nil
}

func (collector HostCollector) validate() error {
	if collector.Executor == nil {
		return errors.New("host diagnostic executor is required")
	}
	for _, path := range []string{collector.IP, collector.NFT, collector.WG, collector.Uname, collector.MihomoBinary, collector.OSReleaseFile} {
		if !filepath.IsAbs(path) && !pathpkg.IsAbs(path) {
			return errors.New("host diagnostic paths must be absolute")
		}
	}
	return nil
}

func (collector HostCollector) run(ctx context.Context, executable string, arguments []string, maximum int64) (string, error) {
	result, err := collector.Executor.Run(ctx, platformexec.Request{Executable: executable, Arguments: append([]string(nil), arguments...), MaxOutputBytes: maximum})
	if err != nil {
		return "", err
	}
	return result.Stdout, nil
}

func (collector HostCollector) now() time.Time {
	if collector.Now != nil {
		return collector.Now().UTC()
	}
	return time.Now().UTC()
}

func readOSRelease(filename string) (OperatingSystem, error) {
	info, err := os.Stat(filename)
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > 64<<10 {
		return OperatingSystem{}, errors.New("os-release is unavailable")
	}
	content, err := os.ReadFile(filename)
	if err != nil {
		return OperatingSystem{}, errors.New("read os-release failed")
	}
	values := map[string]string{}
	for _, line := range strings.Split(string(content), "\n") {
		key, value, found := strings.Cut(line, "=")
		if !found || (key != "ID" && key != "VERSION_ID" && key != "PRETTY_NAME") {
			continue
		}
		value = strings.Trim(strings.TrimSpace(value), `"'`)
		values[key] = boundedText(loggingpkg.SanitizeText(value), 256)
	}
	if values["ID"] == "" && values["PRETTY_NAME"] == "" {
		return OperatingSystem{}, errors.New("os-release has no supported fields")
	}
	return OperatingSystem{ID: values["ID"], VersionID: values["VERSION_ID"], PrettyName: values["PRETTY_NAME"]}, nil
}

func decodeInterfaces(payload []byte) ([]InterfaceSummary, bool, error) {
	var raw []struct {
		IfName    string `json:"ifname"`
		OperState string `json:"operstate"`
		MTU       int    `json:"mtu"`
		AddrInfo  []struct {
			Family    string `json:"family"`
			Local     string `json:"local"`
			PrefixLen int    `json:"prefixlen"`
			Scope     string `json:"scope"`
		} `json:"addr_info"`
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&raw); err != nil {
		// iproute2 grows fields over time. Fall back to an allowlisted map
		// decoder while still emitting only the typed fields below.
		var permissive []map[string]any
		if err := json.Unmarshal(payload, &permissive); err != nil {
			return nil, false, err
		}
		raw = make([]struct {
			IfName    string `json:"ifname"`
			OperState string `json:"operstate"`
			MTU       int    `json:"mtu"`
			AddrInfo  []struct {
				Family    string `json:"family"`
				Local     string `json:"local"`
				PrefixLen int    `json:"prefixlen"`
				Scope     string `json:"scope"`
			} `json:"addr_info"`
		}, 0, len(permissive))
		for _, item := range permissive {
			encoded, _ := json.Marshal(item)
			var decoded struct {
				IfName    string `json:"ifname"`
				OperState string `json:"operstate"`
				MTU       int    `json:"mtu"`
				AddrInfo  []struct {
					Family    string `json:"family"`
					Local     string `json:"local"`
					PrefixLen int    `json:"prefixlen"`
					Scope     string `json:"scope"`
				} `json:"addr_info"`
			}
			_ = json.Unmarshal(encoded, &decoded)
			raw = append(raw, decoded)
		}
	}
	result := make([]InterfaceSummary, 0, min(len(raw), maximumInterfaces))
	addressCount, truncated := 0, false
	for _, item := range raw {
		if len(result) == maximumInterfaces {
			truncated = true
			break
		}
		if !safeInterfaceName.MatchString(item.IfName) || item.MTU < 0 || item.MTU > 1<<20 {
			continue
		}
		summary := InterfaceSummary{Name: item.IfName, State: boundedText(item.OperState, 32), MTU: item.MTU, Addresses: []InterfaceAddress{}}
		for _, address := range item.AddrInfo {
			parsed, err := netip.ParseAddr(address.Local)
			if err != nil || !parsed.Is4() || address.PrefixLen < 0 || address.PrefixLen > 32 {
				continue
			}
			if addressCount == maximumInterfaceAddresses {
				truncated = true
				break
			}
			summary.Addresses = append(summary.Addresses, InterfaceAddress{Family: "inet", Local: parsed.String(), PrefixLen: address.PrefixLen, Scope: boundedText(address.Scope, 32)})
			addressCount++
		}
		result = append(result, summary)
	}
	return result, truncated, nil
}

func sanitizeJSONArray(payload []byte) (json.RawMessage, error) {
	var value []any
	if err := decodeJSONValue(payload, &value); err != nil {
		return nil, err
	}
	return marshalSanitizedJSON(value)
}

func sanitizeJSONObject(payload []byte) (json.RawMessage, error) {
	var value map[string]any
	if err := decodeJSONValue(payload, &value); err != nil {
		return nil, err
	}
	return marshalSanitizedJSON(value)
}

func sanitizeOwnedRules(payload []byte) (json.RawMessage, error) {
	var rules []map[string]any
	if err := decodeJSONValue(payload, &rules); err != nil {
		return nil, err
	}
	owned := make([]any, 0, len(rules))
	for _, rule := range rules {
		if integerValue(rule["protocol"]) != int64(routing.OwnedProtocol) {
			continue
		}
		owned = append(owned, rule)
	}
	return marshalSanitizedJSON(owned)
}

func decodeJSONValue(payload []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.UseNumber()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("diagnostic JSON contains trailing data")
	}
	return nil
}

func marshalSanitizedJSON(value any) (json.RawMessage, error) {
	content, err := json.Marshal(sanitizeJSONStrings(value))
	if err != nil || len(content) > int(commandJSONLimit) {
		return nil, errors.New("sanitized diagnostic JSON is invalid or oversized")
	}
	return json.RawMessage(content), nil
}

func sanitizeJSONStrings(value any) any {
	switch current := value.(type) {
	case map[string]any:
		result := make(map[string]any, len(current))
		for key, child := range current {
			result[boundedText(key, 128)] = sanitizeJSONStrings(child)
		}
		return result
	case []any:
		result := make([]any, len(current))
		for index, child := range current {
			result[index] = sanitizeJSONStrings(child)
		}
		return result
	case string:
		return boundedText(loggingpkg.SanitizeText(current), 1024)
	default:
		return current
	}
}

func decodeWireGuardDump(output string) (WireGuardSummary, error) {
	lines := strings.Split(strings.TrimSpace(output), "\n")
	if len(lines) == 0 || strings.TrimSpace(lines[0]) == "" {
		return WireGuardSummary{}, errors.New("WireGuard dump is empty")
	}
	interfaceFields := strings.Split(lines[0], "\t")
	if len(interfaceFields) != 4 {
		return WireGuardSummary{}, errors.New("WireGuard interface dump is invalid")
	}
	listenPort, err := strconv.Atoi(interfaceFields[2])
	if err != nil || listenPort < 0 || listenPort > 65535 {
		return WireGuardSummary{}, errors.New("WireGuard listen port is invalid")
	}
	result := WireGuardSummary{Available: true, ListenPort: listenPort, Fwmark: boundedText(interfaceFields[3], 32), Peers: []WireGuardPeerSummary{}}
	for index, line := range lines[1:] {
		fields := strings.Split(line, "\t")
		if len(fields) != 8 || len(result.Peers) >= 128 {
			return WireGuardSummary{}, errors.New("WireGuard peer dump is invalid or oversized")
		}
		handshake, err1 := strconv.ParseInt(fields[4], 10, 64)
		rx, err2 := strconv.ParseUint(fields[5], 10, 64)
		tx, err3 := strconv.ParseUint(fields[6], 10, 64)
		keepalive, err4 := strconv.Atoi(fields[7])
		if err1 != nil || err2 != nil || err3 != nil || err4 != nil || handshake < 0 || keepalive < 0 {
			return WireGuardSummary{}, errors.New("WireGuard peer counters are invalid")
		}
		peer := WireGuardPeerSummary{Index: index + 1, Endpoint: maskEndpoint(fields[2]), AllowedIPs: safeAllowedIPs(fields[3]), TransferRXBytes: rx, TransferTXBytes: tx, PersistentKeepalive: keepalive}
		if handshake > 0 {
			peer.LatestHandshakeAt = time.Unix(handshake, 0).UTC().Format(time.RFC3339Nano)
		}
		result.Peers = append(result.Peers, peer)
	}
	return result, nil
}

func maskEndpoint(value string) string {
	host, port, err := net.SplitHostPort(strings.TrimSpace(value))
	if err != nil || host == "" {
		return ""
	}
	parsedPort, err := strconv.Atoi(port)
	if err != nil || parsedPort < 1 || parsedPort > 65535 {
		return ""
	}
	return "[MASKED]:" + port
}

func safeAllowedIPs(value string) []string {
	result := []string{}
	for _, item := range strings.Split(value, ",") {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(item))
		if err == nil && len(result) < 32 {
			result = append(result, prefix.String())
		}
	}
	return result
}

func integerValue(value any) int64 {
	switch current := value.(type) {
	case json.Number:
		result, _ := current.Int64()
		return result
	case float64:
		return int64(current)
	case string:
		result, _ := strconv.ParseInt(current, 10, 64)
		return result
	default:
		return 0
	}
}

func boundedText(value string, maximum int) string {
	if maximum <= 0 || len(value) <= maximum {
		return value
	}
	value = value[:maximum]
	for !utf8.ValidString(value) {
		value = value[:len(value)-1]
	}
	return value
}
