// Package installpreflight performs read-only, typed clean-host checks used by
// the signed installers before any Gateway-owned host state is written.
package installpreflight

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strconv"

	"gateway-vpn/internal/netutil"
	"gateway-vpn/internal/platformexec"
)

const observationLimit = 4 << 20

type LANOptions struct {
	Interface string
	CIDR      string
	IPPath    string
}

type addressLink struct {
	Interface string `json:"ifname"`
	Addresses []struct {
		Family    string `json:"family"`
		Local     string `json:"local"`
		PrefixLen int    `json:"prefixlen"`
	} `json:"addr_info"`
}

type routeObservation struct {
	Type     string          `json:"type"`
	Dst      string          `json:"dst"`
	Dev      string          `json:"dev"`
	Protocol json.RawMessage `json:"protocol"`
	Scope    string          `json:"scope"`
	PrefSrc  string          `json:"prefsrc"`
}

// CheckGatewayLAN rejects a requested LAN that overlaps any observed host
// address or non-default route. The only exception is the exact set of kernel
// routes derived from the same already-configured address on the selected LAN
// interface, which makes the check safe for an idempotent reinstall.
func CheckGatewayLAN(ctx context.Context, executor platformexec.Executor, options LANOptions) error {
	requested, ok := netutil.ParseGatewayLAN(options.CIDR)
	if executor == nil || !validInterfaceName(options.Interface) || !ok || options.IPPath != "/usr/sbin/ip" {
		return errors.New("fixed ip executor, valid LAN interface, and safe private LAN CIDR are required")
	}
	addressesResult, err := executor.Run(ctx, platformexec.Request{
		Executable: options.IPPath, Arguments: []string{"-json", "-4", "address", "show"}, MaxOutputBytes: observationLimit,
	})
	if err != nil {
		return fmt.Errorf("observe host IPv4 addresses: %w", err)
	}
	var links []addressLink
	if err := json.Unmarshal([]byte(addressesResult.Stdout), &links); err != nil {
		return errors.New("decode host IPv4 address observation")
	}
	requestedPresent := false
	for _, link := range links {
		if !validObservedInterface(link.Interface) {
			return errors.New("host address observation contains an invalid interface name")
		}
		for _, item := range link.Addresses {
			if item.Family != "inet" {
				continue
			}
			observed, err := observedPrefix(item.Local, item.PrefixLen)
			if err != nil {
				return errors.New("host address observation contains an invalid IPv4 prefix")
			}
			if link.Interface == options.Interface && observed == requested {
				requestedPresent = true
				continue
			}
			if requested.Masked().Overlaps(observed.Masked()) {
				return fmt.Errorf("requested Gateway LAN overlaps address %s on interface %s", observed, link.Interface)
			}
		}
	}

	routesResult, err := executor.Run(ctx, platformexec.Request{
		Executable: options.IPPath, Arguments: []string{"-json", "-4", "route", "show", "table", "all"}, MaxOutputBytes: observationLimit,
	})
	if err != nil {
		return fmt.Errorf("observe host IPv4 routes: %w", err)
	}
	var routes []routeObservation
	if err := json.Unmarshal([]byte(routesResult.Stdout), &routes); err != nil {
		return errors.New("decode host IPv4 route observation")
	}
	for _, route := range routes {
		if route.Dst == "" || route.Dst == "default" {
			continue
		}
		observed, err := parseRoutePrefix(route.Dst)
		if err != nil {
			return errors.New("host route observation contains an invalid IPv4 destination")
		}
		if observed.Bits() == 0 || !requested.Masked().Overlaps(observed.Masked()) {
			continue
		}
		if requestedPresent && derivedLANRoute(route, observed, options.Interface, requested) {
			continue
		}
		return fmt.Errorf("requested Gateway LAN overlaps route %s on interface %s", observed, displayInterface(route.Dev))
	}
	return nil
}

func observedPrefix(addressText string, bits int) (netip.Prefix, error) {
	address, err := netip.ParseAddr(addressText)
	if err != nil || !address.Is4() || bits < 0 || bits > 32 {
		return netip.Prefix{}, errors.New("invalid observed prefix")
	}
	return netip.PrefixFrom(address, bits), nil
}

func parseRoutePrefix(value string) (netip.Prefix, error) {
	if address, err := netip.ParseAddr(value); err == nil && address.Is4() {
		return netip.PrefixFrom(address, 32), nil
	}
	prefix, err := netip.ParsePrefix(value)
	if err != nil || !prefix.Addr().Is4() {
		return netip.Prefix{}, errors.New("invalid route prefix")
	}
	return prefix, nil
}

func derivedLANRoute(route routeObservation, observed netip.Prefix, interfaceName string, requested netip.Prefix) bool {
	if route.Dev != interfaceName || protocolName(route.Protocol) != "kernel" || (route.PrefSrc != "" && route.PrefSrc != requested.Addr().String()) {
		return false
	}
	switch route.Type {
	case "", "unicast":
		return route.Scope == "link" && observed.Masked() == requested.Masked()
	case "local":
		return route.Scope == "host" && observed.Bits() == 32 && observed.Addr() == requested.Addr()
	case "broadcast":
		if route.Scope != "link" || observed.Bits() != 32 {
			return false
		}
		return observed.Addr() == requested.Masked().Addr() || observed.Addr() == broadcastAddress(requested)
	default:
		return false
	}
}

func protocolName(raw json.RawMessage) string {
	var text string
	if json.Unmarshal(raw, &text) == nil {
		return text
	}
	var number int
	if json.Unmarshal(raw, &number) == nil && number == 2 {
		return "kernel"
	}
	return ""
}

func broadcastAddress(prefix netip.Prefix) netip.Addr {
	bytes := prefix.Masked().Addr().As4()
	hostMask := uint32(1)<<(32-prefix.Bits()) - 1
	value := uint32(bytes[0])<<24 | uint32(bytes[1])<<16 | uint32(bytes[2])<<8 | uint32(bytes[3]) | hostMask
	return netip.AddrFrom4([4]byte{byte(value >> 24), byte(value >> 16), byte(value >> 8), byte(value)})
}

func validInterfaceName(value string) bool {
	if value == "" || len(value) > 15 {
		return false
	}
	for _, character := range value {
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') || (character >= '0' && character <= '9') {
			continue
		}
		if character != '_' && character != '-' && character != '.' && character != ':' {
			return false
		}
	}
	return true
}

func validObservedInterface(value string) bool {
	return value == "" || validInterfaceName(value)
}

func displayInterface(value string) string {
	if value == "" {
		return "<none>"
	}
	return strconv.Quote(value)
}
