// Package installtopology defines the pre-install, interface-name based
// topology contract shared by the interactive wizard and the verified
// installer. Runtime safe-apply converts these names to stable interface IDs;
// this package deliberately never guesses hardware identity.
package installtopology

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"sort"
	"strings"
)

const MaximumTokenBytes = 16 << 10

type Profile string

const (
	ProfileEthernetHiLink   Profile = "ETHERNET_HILINK"
	ProfileEthernetEthernet Profile = "ETHERNET_ETHERNET"
	ProfileOneArmWireGuard  Profile = "ONE_ARM_WIREGUARD"
	ProfileMixed            Profile = "MIXED"

	AddressDHCP   = "DHCP"
	AddressStatic = "STATIC"
)

type EthernetUplink struct {
	InterfaceName string   `json:"interface_name" yaml:"interface_name"`
	AddressMode   string   `json:"address_mode" yaml:"address_mode"`
	IPv4CIDR      string   `json:"ipv4_cidr,omitempty" yaml:"ipv4_cidr,omitempty"`
	Gateway       string   `json:"gateway,omitempty" yaml:"gateway,omitempty"`
	DNS           []string `json:"dns,omitempty" yaml:"dns,omitempty"`
	MTU           int64    `json:"mtu,omitempty" yaml:"mtu,omitempty"`
}

// Plan is the complete physical-role intent collected before first install.
// HiLink devices are not enumerated here because they are adopted by stable
// USB identity after boot; selecting a HiLink-capable profile only authorizes
// that runtime discovery path.
type Plan struct {
	Profile               Profile          `json:"profile" yaml:"profile"`
	LANMembers            []string         `json:"lan_members,omitempty" yaml:"lan_members,omitempty"`
	EthernetUplinks       []EthernetUplink `json:"ethernet_uplinks,omitempty" yaml:"ethernet_uplinks,omitempty"`
	SharedOneArmInterface string           `json:"shared_one_arm_interface,omitempty" yaml:"shared_one_arm_interface,omitempty"`
}

func (plan Plan) Validate() error {
	switch plan.Profile {
	case ProfileEthernetHiLink, ProfileEthernetEthernet, ProfileOneArmWireGuard, ProfileMixed:
	default:
		return errors.New("unsupported initial topology profile")
	}
	if len(plan.LANMembers) > 16 || len(plan.EthernetUplinks) > 16 {
		return errors.New("initial topology exceeds the sixteen-interface limit")
	}

	roles := make(map[string]string, len(plan.LANMembers)+len(plan.EthernetUplinks)+1)
	for _, member := range plan.LANMembers {
		if !validInterfaceName(member) {
			return fmt.Errorf("invalid LAN interface %q", member)
		}
		if previous := roles[member]; previous != "" {
			return fmt.Errorf("interface %s is assigned to both %s and LAN", member, previous)
		}
		roles[member] = "LAN"
	}
	for index, item := range plan.EthernetUplinks {
		if err := validateEthernetUplink(item); err != nil {
			return fmt.Errorf("Ethernet uplink %d: %w", index+1, err)
		}
		if previous := roles[item.InterfaceName]; previous != "" {
			return fmt.Errorf("interface %s is assigned to both %s and Ethernet uplink", item.InterfaceName, previous)
		}
		roles[item.InterfaceName] = "Ethernet uplink"
	}

	shared := strings.TrimSpace(plan.SharedOneArmInterface)
	if shared != "" && !validInterfaceName(shared) {
		return errors.New("shared one-arm interface name is invalid")
	}
	sharedUplink := false
	for _, item := range plan.EthernetUplinks {
		if item.InterfaceName == shared {
			sharedUplink = true
			break
		}
	}
	if shared != "" {
		if role := roles[shared]; role != "" && role != "Ethernet uplink" {
			return fmt.Errorf("shared one-arm interface %s is already assigned to %s", shared, role)
		}
		if !sharedUplink {
			return errors.New("shared one-arm interface must also be an explicit Ethernet uplink")
		}
	}

	switch plan.Profile {
	case ProfileEthernetHiLink:
		if len(plan.LANMembers) == 0 || len(plan.EthernetUplinks) != 0 || shared != "" {
			return errors.New("ETHERNET_HILINK requires LAN ports and no Ethernet or shared one-arm uplink")
		}
	case ProfileEthernetEthernet:
		if len(plan.LANMembers) == 0 || len(plan.EthernetUplinks) == 0 || shared != "" {
			return errors.New("ETHERNET_ETHERNET requires separate LAN ports and Ethernet uplinks")
		}
	case ProfileOneArmWireGuard:
		if len(plan.LANMembers) != 0 || len(plan.EthernetUplinks) != 1 || shared == "" {
			return errors.New("ONE_ARM_WIREGUARD requires exactly one shared Ethernet uplink and no plaintext LAN port")
		}
	case ProfileMixed:
		if len(plan.EthernetUplinks) == 0 || len(plan.LANMembers) == 0 && shared == "" {
			return errors.New("MIXED requires an Ethernet uplink plus Ethernet LAN or shared one-arm ingress")
		}
	}
	return nil
}

func (plan Plan) Canonical() Plan {
	result := plan
	result.SharedOneArmInterface = strings.TrimSpace(result.SharedOneArmInterface)
	result.LANMembers = append([]string(nil), result.LANMembers...)
	for index := range result.LANMembers {
		result.LANMembers[index] = strings.TrimSpace(result.LANMembers[index])
	}
	sort.Strings(result.LANMembers)
	result.EthernetUplinks = append([]EthernetUplink(nil), result.EthernetUplinks...)
	for index := range result.EthernetUplinks {
		result.EthernetUplinks[index].InterfaceName = strings.TrimSpace(result.EthernetUplinks[index].InterfaceName)
		result.EthernetUplinks[index].AddressMode = strings.ToUpper(strings.TrimSpace(result.EthernetUplinks[index].AddressMode))
		result.EthernetUplinks[index].IPv4CIDR = strings.TrimSpace(result.EthernetUplinks[index].IPv4CIDR)
		result.EthernetUplinks[index].Gateway = strings.TrimSpace(result.EthernetUplinks[index].Gateway)
		result.EthernetUplinks[index].DNS = append([]string(nil), result.EthernetUplinks[index].DNS...)
	}
	sort.Slice(result.EthernetUplinks, func(left, right int) bool {
		return result.EthernetUplinks[left].InterfaceName < result.EthernetUplinks[right].InterfaceName
	})
	return result
}

func (plan Plan) UsesEthernetLAN() bool {
	return plan.Profile != ProfileOneArmWireGuard && len(plan.LANMembers) != 0
}

func (plan Plan) UsesOneArmIngress() bool {
	return strings.TrimSpace(plan.SharedOneArmInterface) != ""
}

// CurrentLANPlan translates the legacy installer LAN arguments into the
// default typed initial-topology contract. It remains intentionally narrow so
// callers that only know the historical LAN flags cannot accidentally claim a
// richer profile.
func CurrentLANPlan(lanInterface string, lanMembers []string) (Plan, error) {
	lanInterface = strings.TrimSpace(lanInterface)
	members := append([]string(nil), lanMembers...)
	if len(members) == 0 {
		if !validInterfaceName(lanInterface) || lanInterface == "gateway-vpn-lan" {
			return Plan{}, errors.New("a physical direct LAN interface is required")
		}
		members = []string{lanInterface}
	} else if lanInterface != "gateway-vpn-lan" {
		return Plan{}, errors.New("LAN members require the managed gateway-vpn-lan bridge")
	}
	plan := Plan{Profile: ProfileEthernetHiLink, LANMembers: members}.Canonical()
	if err := plan.Validate(); err != nil {
		return Plan{}, err
	}
	return plan, nil
}

// ValidateInstallerBinding proves that a typed plan and the bootstrap's
// concrete LAN arguments refer to the same physical ports. The Ethernet
// uplink details remain in the signed token and are applied by the
// rollback-protected post-install topology transaction; they are deliberately
// not flattened into legacy LAN flags.
func ValidateInstallerBinding(plan Plan, lanInterface string, lanMembers []string) error {
	plan = plan.Canonical()
	if err := plan.Validate(); err != nil {
		return err
	}
	lanInterface = strings.TrimSpace(lanInterface)
	members := make([]string, len(lanMembers))
	for i, value := range lanMembers {
		members[i] = strings.TrimSpace(value)
		if members[i] != value {
			return errors.New("installer LAN member contains surrounding whitespace")
		}
	}
	sort.Strings(members)
	if len(members) > 16 {
		return errors.New("installer LAN member list is too large")
	}
	if len(members) > 0 && lanInterface != "gateway-vpn-lan" {
		return errors.New("physical LAN members require gateway-vpn-lan")
	}
	if len(members) == 0 && !validInterfaceName(lanInterface) {
		return errors.New("installer LAN interface is invalid")
	}
	var expected []string
	if plan.Profile == ProfileOneArmWireGuard {
		if len(members) != 0 || lanInterface != plan.SharedOneArmInterface {
			return errors.New("one-arm installer LAN binding must use the shared physical interface")
		}
		return nil
	}
	if plan.UsesEthernetLAN() {
		expected = append(expected, plan.LANMembers...)
		if len(members) == 0 {
			if len(expected) != 1 || lanInterface != expected[0] {
				return errors.New("installer LAN interface does not match the topology LAN port")
			}
			return nil
		}
	} else if len(members) != 0 {
		return errors.New("topology without plaintext LAN cannot receive LAN members")
	}
	if len(expected) != len(members) {
		return errors.New("installer LAN member count does not match the topology")
	}
	for i := range expected {
		if expected[i] != members[i] {
			return errors.New("installer LAN members do not match the topology")
		}
	}
	return nil
}

// ValidateCurrentLAN preserves the historical API and deliberately accepts
// only the default HiLink profile. New callers that carry a full typed plan
// must use ValidateInstallerBinding.
func ValidateCurrentLAN(plan Plan, lanInterface string, lanMembers []string) error {
	plan = plan.Canonical()
	if err := plan.Validate(); err != nil {
		return err
	}
	if plan.Profile != ProfileEthernetHiLink || plan.SharedOneArmInterface != "" || len(plan.EthernetUplinks) != 0 {
		return errors.New("initial topology profile does not yet have a first-install safe-apply backend")
	}
	return ValidateInstallerBinding(plan, lanInterface, lanMembers)
}

// EncodeToken produces a deterministic, non-secret argv-safe handoff between
// the administrative deploy binary, the independently verified bootstrap and
// the root installer. Interface names and IP policy are intentionally visible;
// credentials and key material are not part of Plan.
func EncodeToken(plan Plan) (string, error) {
	plan = plan.Canonical()
	if err := plan.Validate(); err != nil {
		return "", err
	}
	payload, err := json.Marshal(plan)
	if err != nil || len(payload) == 0 || len(payload) > MaximumTokenBytes {
		return "", errors.New("encode bounded initial topology failed")
	}
	return base64.RawURLEncoding.EncodeToString(payload), nil
}

func DecodeToken(token string) (Plan, error) {
	if token == "" || len(token) > base64.RawURLEncoding.EncodedLen(MaximumTokenBytes) {
		return Plan{}, errors.New("bounded initial topology token is required")
	}
	payload, err := base64.RawURLEncoding.Strict().DecodeString(token)
	if err != nil || len(payload) == 0 || len(payload) > MaximumTokenBytes {
		return Plan{}, errors.New("decode bounded initial topology failed")
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var plan Plan
	if err := decoder.Decode(&plan); err != nil {
		return Plan{}, errors.New("decode initial topology structure failed")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return Plan{}, errors.New("initial topology token contains trailing data")
	}
	plan = plan.Canonical()
	if err := plan.Validate(); err != nil {
		return Plan{}, err
	}
	return plan, nil
}

func validateEthernetUplink(item EthernetUplink) error {
	if !validInterfaceName(strings.TrimSpace(item.InterfaceName)) {
		return errors.New("interface name is invalid")
	}
	if item.AddressMode != AddressDHCP && item.AddressMode != AddressStatic {
		return errors.New("address mode must be DHCP or STATIC")
	}
	if item.MTU != 0 && (item.MTU < 576 || item.MTU > 9216) {
		return errors.New("MTU must be zero or between 576 and 9216")
	}
	if len(item.DNS) > 8 {
		return errors.New("at most eight DNS addresses are allowed")
	}
	seenDNS := make(map[netip.Addr]struct{}, len(item.DNS))
	for _, raw := range item.DNS {
		address, err := netip.ParseAddr(strings.TrimSpace(raw))
		if err != nil || !address.Is4() || address.IsUnspecified() || address.IsMulticast() {
			return fmt.Errorf("invalid DNS IPv4 address %q", raw)
		}
		if _, duplicate := seenDNS[address]; duplicate {
			return fmt.Errorf("duplicate DNS IPv4 address %q", raw)
		}
		seenDNS[address] = struct{}{}
	}
	if item.AddressMode == AddressDHCP {
		if item.IPv4CIDR != "" || item.Gateway != "" {
			return errors.New("DHCP uplink cannot also contain a static address or gateway")
		}
		return nil
	}
	prefix, err := netip.ParsePrefix(item.IPv4CIDR)
	if err != nil || !prefix.Addr().Is4() || prefix.Bits() < 8 || prefix.Bits() > 30 || !prefix.Addr().IsPrivate() {
		return errors.New("static uplink requires a private IPv4 host CIDR with /8 through /30")
	}
	gateway, err := netip.ParseAddr(item.Gateway)
	if err != nil || !gateway.Is4() || gateway == prefix.Addr() || !prefix.Masked().Contains(gateway) {
		return errors.New("static gateway must be a different IPv4 address inside the uplink subnet")
	}
	return nil
}

func validInterfaceName(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > 15 {
		return false
	}
	for _, character := range value {
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || strings.ContainsRune("_-.:", character) {
			continue
		}
		return false
	}
	return true
}
