package hilink

import (
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

type Lease struct {
	InterfaceName    string
	Address          netip.Prefix
	ManagementPrefix netip.Prefix
	Gateway          netip.Addr
	DNS              []netip.Addr
	MTU              int
}

func ParseNetworkdLease(content []byte, interfaceName string, mtu int) (Lease, error) {
	if !validInterfaceName(interfaceName) || len(content) == 0 || len(content) > 64*1024 || mtu < 576 || mtu > 9000 {
		return Lease{}, errors.New("invalid networkd lease input")
	}
	values := make(map[string]string)
	for number, line := range strings.Split(strings.ReplaceAll(string(content), "\r\n", "\n"), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, found := strings.Cut(line, "=")
		if !found || key == "" {
			return Lease{}, fmt.Errorf("invalid networkd lease line %d", number+1)
		}
		if _, duplicate := values[key]; duplicate {
			return Lease{}, fmt.Errorf("duplicate networkd lease field %s", key)
		}
		values[key] = strings.TrimSpace(value)
	}
	address, err := netip.ParseAddr(values["ADDRESS"])
	if err != nil || !usableIPv4(address) {
		return Lease{}, errors.New("networkd lease ADDRESS must be usable IPv4")
	}
	prefixLength, err := strconv.Atoi(values["PREFIXLEN"])
	if err != nil || prefixLength < 8 || prefixLength > 30 {
		return Lease{}, errors.New("networkd lease PREFIXLEN must be 8..30")
	}
	prefix := netip.PrefixFrom(address, prefixLength)
	management := prefix.Masked()
	routers := strings.Fields(values["ROUTER"])
	if len(routers) != 1 {
		return Lease{}, errors.New("networkd lease must contain exactly one ROUTER")
	}
	gateway, err := netip.ParseAddr(routers[0])
	if err != nil || !usableIPv4(gateway) || !management.Contains(gateway) || gateway == address {
		return Lease{}, errors.New("networkd lease ROUTER must be another usable address in management subnet")
	}
	lease := Lease{InterfaceName: interfaceName, Address: prefix, ManagementPrefix: management, Gateway: gateway, MTU: mtu}
	seenDNS := make(map[netip.Addr]struct{})
	for _, raw := range strings.Fields(values["DNS"]) {
		dns, err := netip.ParseAddr(raw)
		if err != nil || !usableIPv4(dns) {
			return Lease{}, errors.New("networkd lease DNS contains invalid IPv4 address")
		}
		if _, exists := seenDNS[dns]; !exists {
			lease.DNS = append(lease.DNS, dns)
			seenDNS[dns] = struct{}{}
		}
	}
	if len(lease.DNS) == 0 {
		lease.DNS = []netip.Addr{gateway}
	}
	return lease, nil
}

func RenderNetworkdConfig(interfaceName string) (string, error) {
	if !validInterfaceName(interfaceName) {
		return "", errors.New("invalid HiLink interface name")
	}
	return fmt.Sprintf(`[Match]
Name=%s

[Link]
RequiredForOnline=no

[Network]
DHCP=ipv4
IPv6AcceptRA=no
LinkLocalAddressing=no

[DHCPv4]
UseRoutes=no
UseGateway=no
UseDNS=no
UseNTP=no
UseHostname=no
SendHostname=no
`, interfaceName), nil
}

func usableIPv4(address netip.Addr) bool {
	return address.Is4() && !address.IsUnspecified() && !address.IsMulticast() && !address.IsLoopback() && !address.IsLinkLocalUnicast()
}
