// Package networkplan builds typed, validated desired policy-routing state. It
// does not execute iproute2 or nftables commands.
package networkplan

import (
	"errors"
	"fmt"
	"net/netip"
	"sort"
)

const Owner = "gateway-vpn"

type Input struct {
	LANPrefix       string
	WireGuardPrefix string
	Modems          []ModemInput
}

type ModemInput struct {
	ID               string
	Priority         int64
	InterfaceName    string
	ManagementPrefix string
	Gateway          string
	RoutingTableID   uint32
	Fwmark           uint32
}

type Plan struct {
	Owner  string
	Routes []Route
	Rules  []Rule
}

type Route struct {
	ModemID     string
	TableID     uint32
	Destination netip.Prefix
	Via         netip.Addr
	Device      string
	ScopeLink   bool
}

type Rule struct {
	ModemID  string
	Fwmark   uint32
	Mask     uint32
	TableID  uint32
	Priority uint32
}

func Build(input Input) (Plan, error) {
	lan, err := parseIPv4Prefix("LAN", input.LANPrefix)
	if err != nil {
		return Plan{}, err
	}
	wireGuard, err := parseIPv4Prefix("WireGuard", input.WireGuardPrefix)
	if err != nil {
		return Plan{}, err
	}
	if lan.Overlaps(wireGuard) {
		return Plan{}, errors.New("LAN and WireGuard prefixes overlap")
	}

	modems := append([]ModemInput(nil), input.Modems...)
	sort.SliceStable(modems, func(i, j int) bool {
		if modems[i].Priority == modems[j].Priority {
			return modems[i].ID < modems[j].ID
		}
		return modems[i].Priority < modems[j].Priority
	})
	seenIDs := make(map[string]struct{}, len(modems))
	seenInterfaces := make(map[string]string, len(modems))
	seenTables := make(map[uint32]string, len(modems))
	seenMarks := make(map[uint32]string, len(modems))
	managementPrefixes := make([]struct {
		id     string
		prefix netip.Prefix
	}, 0, len(modems))

	plan := Plan{Owner: Owner}
	for _, modem := range modems {
		if modem.ID == "" {
			return Plan{}, errors.New("modem id is required")
		}
		if _, exists := seenIDs[modem.ID]; exists {
			return Plan{}, fmt.Errorf("duplicate modem id %q", modem.ID)
		}
		seenIDs[modem.ID] = struct{}{}
		if !validInterfaceName(modem.InterfaceName) {
			return Plan{}, fmt.Errorf("modem %s has invalid Linux interface name", modem.ID)
		}
		if previous := seenInterfaces[modem.InterfaceName]; previous != "" {
			return Plan{}, fmt.Errorf("modems %s and %s share interface %s", previous, modem.ID, modem.InterfaceName)
		}
		seenInterfaces[modem.InterfaceName] = modem.ID
		if modem.RoutingTableID < 256 {
			return Plan{}, fmt.Errorf("modem %s uses reserved routing table %d", modem.ID, modem.RoutingTableID)
		}
		if previous := seenTables[modem.RoutingTableID]; previous != "" {
			return Plan{}, fmt.Errorf("modems %s and %s share routing table %d", previous, modem.ID, modem.RoutingTableID)
		}
		seenTables[modem.RoutingTableID] = modem.ID
		if modem.Fwmark == 0 {
			return Plan{}, fmt.Errorf("modem %s has zero fwmark", modem.ID)
		}
		if previous := seenMarks[modem.Fwmark]; previous != "" {
			return Plan{}, fmt.Errorf("modems %s and %s share fwmark %#x", previous, modem.ID, modem.Fwmark)
		}
		seenMarks[modem.Fwmark] = modem.ID

		management, err := parseIPv4Prefix("modem "+modem.ID+" management", modem.ManagementPrefix)
		if err != nil {
			return Plan{}, err
		}
		if management.Overlaps(lan) || management.Overlaps(wireGuard) {
			return Plan{}, fmt.Errorf("modem %s management prefix overlaps LAN or WireGuard", modem.ID)
		}
		for _, previous := range managementPrefixes {
			if management.Overlaps(previous.prefix) {
				return Plan{}, fmt.Errorf("modem management prefixes overlap: %s and %s", previous.id, modem.ID)
			}
		}
		managementPrefixes = append(managementPrefixes, struct {
			id     string
			prefix netip.Prefix
		}{modem.ID, management})

		gateway, err := netip.ParseAddr(modem.Gateway)
		if err != nil || !gateway.Is4() || !management.Contains(gateway) || gateway.IsUnspecified() || gateway.IsMulticast() {
			return Plan{}, fmt.Errorf("modem %s gateway must be a usable IPv4 address inside its management prefix", modem.ID)
		}

		plan.Routes = append(plan.Routes,
			Route{ModemID: modem.ID, TableID: modem.RoutingTableID, Destination: management.Masked(), Device: modem.InterfaceName, ScopeLink: true},
			Route{ModemID: modem.ID, TableID: modem.RoutingTableID, Destination: netip.MustParsePrefix("0.0.0.0/0"), Via: gateway, Device: modem.InterfaceName},
		)
		plan.Rules = append(plan.Rules, Rule{
			ModemID:  modem.ID,
			Fwmark:   modem.Fwmark,
			Mask:     0xffffffff,
			TableID:  modem.RoutingTableID,
			Priority: modem.RoutingTableID,
		})
	}
	return plan, nil
}

func parseIPv4Prefix(label, value string) (netip.Prefix, error) {
	prefix, err := netip.ParsePrefix(value)
	if err != nil || !prefix.Addr().Is4() {
		return netip.Prefix{}, fmt.Errorf("%s prefix must be IPv4", label)
	}
	return prefix.Masked(), nil
}

func validInterfaceName(value string) bool {
	if value == "" || len(value) > 15 {
		return false
	}
	for _, char := range value {
		if (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') || (char >= '0' && char <= '9') {
			continue
		}
		switch char {
		case '_', '-', '.', ':':
			continue
		default:
			return false
		}
	}
	return true
}
