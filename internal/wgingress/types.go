// Package wgingress owns the optional user/data-plane WireGuard server.  It is
// deliberately separate from the wg-mgmt administration tunnel.
package wgingress

import (
	"errors"
	"net"
	"net/netip"
	"regexp"
	"sort"
	"strings"
	"time"
)

const (
	DefaultServerID        = "wg-ingress-default"
	DefaultInterfaceName   = "wg-ingress"
	DefaultSubnet          = "10.90.0.0/24"
	DefaultListenPort      = 51820
	DefaultMTU             = 1420
	DefaultKeepalive       = 25
	MaximumPeers           = 1024
	MaximumPeerRoutes      = 64
	MaximumClientAllowedIP = 16
)

var safeIdentifier = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.:-]{0,127}$`)

type Server struct {
	ID                  string            `json:"id"`
	Enabled             bool              `json:"enabled"`
	Name                string            `json:"name"`
	InterfaceName       string            `json:"interface_name"`
	SubnetCIDR          string            `json:"subnet_cidr"`
	ServerAddress       string            `json:"server_address"`
	ListenPort          int               `json:"listen_port"`
	EndpointHost        string            `json:"endpoint_host"`
	Endpoint            string            `json:"endpoint"`
	MTU                 int               `json:"mtu"`
	PublicKey           string            `json:"public_key"`
	TopologyMode        string            `json:"topology_mode"`
	NetworkInterfaceID  string            `json:"network_interface_id,omitempty"`
	PrivateKeySecretRef string            `json:"-"`
	DNS                 []string          `json:"dns"`
	ListenInterfaces    []ListenInterface `json:"listen_interfaces"`
	ConfigGeneration    int64             `json:"config_generation"`
	DesiredGeneration   int64             `json:"desired_generation"`
	AppliedGeneration   int64             `json:"applied_generation"`
	State               string            `json:"state"`
	LastErrorCode       string            `json:"last_error_code,omitempty"`
	LastAppliedAt       string            `json:"last_applied_at,omitempty"`
	CreatedAt           string            `json:"created_at"`
	UpdatedAt           string            `json:"updated_at"`
}

type ListenInterface struct {
	NetworkInterfaceID string `json:"network_interface_id"`
	InterfaceName      string `json:"interface_name"`
	ExposureMode       string `json:"exposure_mode"`
	Priority           int    `json:"priority"`
}

type Peer struct {
	ID                     string   `json:"id"`
	ServerID               string   `json:"server_id"`
	DisplayNumber          int64    `json:"number"`
	Name                   string   `json:"name"`
	Enabled                bool     `json:"enabled"`
	PeerKind               string   `json:"peer_kind"`
	KeyMode                string   `json:"key_mode"`
	PublicKey              string   `json:"public_key"`
	PrivateKeyAvailable    bool     `json:"private_key_available"`
	AssignedAddress        string   `json:"assigned_address"`
	EndpointOverride       string   `json:"endpoint_override,omitempty"`
	PersistentKeepalive    int      `json:"persistent_keepalive"`
	AccessPolicyMode       string   `json:"access_policy_mode"`
	AllowWhitelistOnly     bool     `json:"allow_whitelist_only"`
	BlockWhenUnqualified   bool     `json:"block_when_unqualified"`
	ClientDNSEnabled       bool     `json:"client_dns_enabled"`
	BehindSubnets          []string `json:"behind_subnets"`
	ClientAllowedIPs       []string `json:"client_allowed_ips"`
	AllowedAccessMethodIDs []string `json:"allowed_access_method_ids"`
	RevokedAt              string   `json:"revoked_at,omitempty"`
	LastHandshakeAt        string   `json:"last_handshake_at,omitempty"`
	RXBytes                int64    `json:"rx_bytes"`
	TXBytes                int64    `json:"tx_bytes"`
	ObservedEndpoint       string   `json:"observed_endpoint,omitempty"`
	RuntimeState           string   `json:"runtime_state"`
	CreatedAt              string   `json:"created_at"`
	UpdatedAt              string   `json:"updated_at"`
	privateKeySecretRef    string
	presharedKeySecretRef  string
}

type ServerUpdate struct {
	Enabled            bool              `json:"enabled"`
	Name               string            `json:"name"`
	SubnetCIDR         string            `json:"subnet_cidr"`
	ListenPort         int               `json:"listen_port"`
	EndpointHost       string            `json:"endpoint_host"`
	MTU                int               `json:"mtu"`
	TopologyMode       string            `json:"topology_mode"`
	NetworkInterfaceID string            `json:"network_interface_id"`
	DNS                []string          `json:"dns"`
	ListenInterfaces   []ListenInterface `json:"listen_interfaces"`
}

type PeerCreate struct {
	Name                   string   `json:"name"`
	PeerKind               string   `json:"peer_kind"`
	KeyMode                string   `json:"key_mode"`
	PublicKey              string   `json:"public_key,omitempty"`
	AssignedAddress        string   `json:"assigned_address,omitempty"`
	EndpointOverride       string   `json:"endpoint_override,omitempty"`
	PersistentKeepalive    int      `json:"persistent_keepalive"`
	AccessPolicyMode       string   `json:"access_policy_mode"`
	AllowWhitelistOnly     bool     `json:"allow_whitelist_only"`
	BlockWhenUnqualified   bool     `json:"block_when_unqualified"`
	ClientDNSEnabled       bool     `json:"client_dns_enabled"`
	BehindSubnets          []string `json:"behind_subnets"`
	ClientAllowedIPs       []string `json:"client_allowed_ips"`
	AllowedAccessMethodIDs []string `json:"allowed_access_method_ids"`
}

type PeerUpdate struct {
	Name                   string   `json:"name"`
	Enabled                bool     `json:"enabled"`
	EndpointOverride       string   `json:"endpoint_override,omitempty"`
	PersistentKeepalive    int      `json:"persistent_keepalive"`
	AccessPolicyMode       string   `json:"access_policy_mode"`
	AllowWhitelistOnly     bool     `json:"allow_whitelist_only"`
	BlockWhenUnqualified   bool     `json:"block_when_unqualified"`
	ClientDNSEnabled       bool     `json:"client_dns_enabled"`
	BehindSubnets          []string `json:"behind_subnets"`
	ClientAllowedIPs       []string `json:"client_allowed_ips"`
	AllowedAccessMethodIDs []string `json:"allowed_access_method_ids"`
}

type PeerRuntime struct {
	PublicKey   string
	HandshakeAt time.Time
	RXBytes     int64
	TXBytes     int64
	Endpoint    string
}

type ExportedConfig struct {
	Filename string `json:"filename"`
	Content  string `json:"content"`
	Managed  bool   `json:"managed"`
}

func ValidateServerUpdate(input ServerUpdate) error {
	input.Name = strings.TrimSpace(input.Name)
	if input.Name == "" || len(input.Name) > 128 {
		return errors.New("WireGuard ingress server name is required")
	}
	prefix, err := canonicalIPv4Prefix(input.SubnetCIDR)
	if err != nil || prefix.Bits() < 16 || prefix.Bits() > 29 {
		return errors.New("WireGuard ingress subnet must be a canonical private IPv4 /16../29")
	}
	if !prefix.Addr().IsPrivate() {
		return errors.New("WireGuard ingress subnet must be private IPv4")
	}
	if input.ListenPort < 1 || input.ListenPort > 65535 || input.ListenPort == 51821 {
		return errors.New("WireGuard ingress listen port is invalid or conflicts with wg-mgmt")
	}
	if input.MTU < 576 || input.MTU > 9000 {
		return errors.New("WireGuard ingress MTU must be 576..9000")
	}
	if input.TopologyMode != "ROUTED" && input.TopologyMode != "ONE_ARM" {
		return errors.New("WireGuard ingress topology mode is invalid")
	}
	if input.Enabled && strings.TrimSpace(input.EndpointHost) == "" {
		return errors.New("WireGuard ingress endpoint host is required when enabled")
	}
	if input.EndpointHost != "" && !validEndpointHost(input.EndpointHost) {
		return errors.New("WireGuard ingress endpoint host is invalid")
	}
	if len(input.DNS) > 8 || len(input.ListenInterfaces) > 16 {
		return errors.New("WireGuard ingress DNS or listen interface list is too large")
	}
	dns, err := canonicalAddresses(input.DNS)
	if err != nil {
		return errors.New("WireGuard ingress DNS contains invalid IPv4")
	}
	for _, value := range dns {
		address, _ := netip.ParseAddr(value)
		if prefix.Contains(address) {
			return errors.New("WireGuard ingress DNS must be an external resolver; the Gateway tunnel address does not run a DNS service")
		}
	}
	seen := make(map[string]struct{}, len(input.ListenInterfaces))
	for index, item := range input.ListenInterfaces {
		if !safeIdentifier.MatchString(item.NetworkInterfaceID) || item.Priority != index+1 || item.ExposureMode != "LOCAL" && item.ExposureMode != "PUBLIC" {
			return errors.New("WireGuard ingress listen interface list is invalid")
		}
		if _, exists := seen[item.NetworkInterfaceID]; exists {
			return errors.New("WireGuard ingress listen interface is duplicated")
		}
		seen[item.NetworkInterfaceID] = struct{}{}
	}
	if input.Enabled && len(input.ListenInterfaces) == 0 {
		return errors.New("at least one WireGuard ingress listen interface is required")
	}
	return nil
}

func ValidatePeerCreate(input PeerCreate) error {
	if strings.TrimSpace(input.Name) == "" || len(strings.TrimSpace(input.Name)) > 128 {
		return errors.New("WireGuard peer name is required")
	}
	if input.PeerKind != "DEVICE" && input.PeerKind != "ROUTER_NAT" && input.PeerKind != "ROUTER_ROUTED" {
		return errors.New("WireGuard peer kind is invalid")
	}
	if input.KeyMode != "MANAGED" && input.KeyMode != "EXTERNAL" {
		return errors.New("WireGuard peer key mode is invalid")
	}
	if input.KeyMode == "EXTERNAL" && !ValidKey(input.PublicKey) || input.KeyMode == "MANAGED" && strings.TrimSpace(input.PublicKey) != "" {
		return errors.New("WireGuard peer public key does not match key mode")
	}
	return validatePeerMutable(input.PersistentKeepalive, input.AccessPolicyMode, input.EndpointOverride, input.BehindSubnets, input.ClientAllowedIPs, input.AllowedAccessMethodIDs)
}

func ValidatePeerUpdate(input PeerUpdate) error {
	if strings.TrimSpace(input.Name) == "" || len(strings.TrimSpace(input.Name)) > 128 {
		return errors.New("WireGuard peer name is required")
	}
	return validatePeerMutable(input.PersistentKeepalive, input.AccessPolicyMode, input.EndpointOverride, input.BehindSubnets, input.ClientAllowedIPs, input.AllowedAccessMethodIDs)
}

// ValidateInitialServerOptions validates the network values collected before
// the first database exists. The managed LAN listener itself is published only
// after installation and is therefore intentionally not part of this check.
func ValidateInitialServerOptions(endpointHost, subnetCIDR string, listenPort int, dns []string) error {
	return ValidateServerUpdate(ServerUpdate{
		Enabled: true, Name: "WireGuard для клиентов", SubnetCIDR: subnetCIDR,
		ListenPort: listenPort, EndpointHost: endpointHost, MTU: DefaultMTU,
		TopologyMode: "ROUTED", DNS: dns,
		ListenInterfaces: []ListenInterface{{NetworkInterfaceID: "netif:managed:lan", ExposureMode: "LOCAL", Priority: 1}},
	})
}

func validatePeerMutable(keepalive int, policy, endpoint string, behind, clientAllowed, methods []string) error {
	if keepalive < 0 || keepalive > 65535 {
		return errors.New("WireGuard peer keepalive is invalid")
	}
	if policy != "AUTO" && policy != "DIRECT_ONLY" && policy != "VPN_ONLY" {
		return errors.New("WireGuard peer access policy is invalid")
	}
	if endpoint != "" {
		if _, _, err := net.SplitHostPort(endpoint); err != nil {
			return errors.New("WireGuard peer endpoint override must use host:port")
		}
	}
	if len(behind) > MaximumPeerRoutes || len(clientAllowed) == 0 || len(clientAllowed) > MaximumClientAllowedIP || len(methods) > 256 {
		return errors.New("WireGuard peer route or access-method list size is invalid")
	}
	if _, err := canonicalPrefixes(behind, false); err != nil {
		return errors.New("WireGuard peer behind subnet is invalid")
	}
	if _, err := canonicalPrefixes(clientAllowed, true); err != nil {
		return errors.New("WireGuard client AllowedIPs are invalid")
	}
	seen := make(map[string]struct{}, len(methods))
	for _, id := range methods {
		if !safeIdentifier.MatchString(id) {
			return errors.New("WireGuard peer access method id is invalid")
		}
		if _, exists := seen[id]; exists {
			return errors.New("WireGuard peer access method is duplicated")
		}
		seen[id] = struct{}{}
	}
	return nil
}

func canonicalIPv4Prefix(value string) (netip.Prefix, error) {
	prefix, err := netip.ParsePrefix(strings.TrimSpace(value))
	if err != nil || !prefix.Addr().Is4() || prefix.Addr().IsUnspecified() || prefix.Masked() != prefix {
		return netip.Prefix{}, errors.New("canonical IPv4 prefix is required")
	}
	return prefix, nil
}

func canonicalPrefixes(values []string, allowDefault bool) ([]string, error) {
	result := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if allowDefault && strings.TrimSpace(value) == "0.0.0.0/0" {
			if _, exists := seen["0.0.0.0/0"]; exists {
				return nil, errors.New("duplicate IPv4 prefix")
			}
			seen["0.0.0.0/0"] = struct{}{}
			result = append(result, "0.0.0.0/0")
			continue
		}
		prefix, err := canonicalIPv4Prefix(value)
		if err != nil || !allowDefault && prefix.Bits() == 0 {
			return nil, errors.New("invalid IPv4 prefix")
		}
		canonical := prefix.String()
		if _, exists := seen[canonical]; exists {
			return nil, errors.New("duplicate IPv4 prefix")
		}
		seen[canonical] = struct{}{}
		result = append(result, canonical)
	}
	return result, nil
}

func canonicalAddresses(values []string) ([]string, error) {
	result := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		address, err := netip.ParseAddr(strings.TrimSpace(value))
		if err != nil || !address.Is4() || address.IsUnspecified() || address.IsMulticast() {
			return nil, errors.New("invalid IPv4 address")
		}
		canonical := address.Unmap().String()
		if _, exists := seen[canonical]; exists {
			return nil, errors.New("duplicate IPv4 address")
		}
		seen[canonical] = struct{}{}
		result = append(result, canonical)
	}
	return result, nil
}

func validEndpointHost(value string) bool {
	value = strings.TrimSpace(value)
	if address, err := netip.ParseAddr(value); err == nil {
		return address.Is4() && !address.IsUnspecified() && !address.IsMulticast()
	}
	if len(value) == 0 || len(value) > 253 || strings.ContainsAny(value, " /\\\x00") {
		return false
	}
	for _, label := range strings.Split(strings.TrimSuffix(value, "."), ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, character := range label {
			if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || character == '-' {
				continue
			}
			return false
		}
	}
	return true
}

func prefixesOverlap(left, right netip.Prefix) bool {
	return left.Contains(right.Addr()) || right.Contains(left.Addr())
}

func nextAddress(prefix netip.Prefix, offset uint64) (netip.Addr, bool) {
	address := prefix.Addr().As4()
	value := uint64(address[0])<<24 | uint64(address[1])<<16 | uint64(address[2])<<8 | uint64(address[3])
	maximum := uint64(1) << uint(32-prefix.Bits())
	if offset >= maximum-1 {
		return netip.Addr{}, false
	}
	value += offset
	return netip.AddrFrom4([4]byte{byte(value >> 24), byte(value >> 16), byte(value >> 8), byte(value)}), true
}

func sortedUnique(values []string) []string {
	result := append([]string(nil), values...)
	sort.Strings(result)
	return result
}
