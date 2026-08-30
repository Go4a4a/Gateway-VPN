// Package gatewayfabric renders and applies the root-owned Gateway side of
// Management Fabric.  Renderers consume only the validated typed host plan;
// they cannot express arbitrary nftables objects or commands from WebUI.
package gatewayfabric

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"

	"gateway-vpn/internal/managementfabric"
)

// RenderFirewallTransaction replaces only the dynamic Management Fabric sets
// and regular chains that belong to firewall schema 5.  The surrounding
// gateway_vpn table, base-chain policies, counters and foreign tables are
// deliberately outside this transaction.
func RenderFirewallTransaction(plan managementfabric.GatewayHostPlan) ([]byte, error) {
	if err := managementfabric.ValidateGatewayHostPlan(plan); err != nil {
		return nil, err
	}
	var output strings.Builder
	for _, chain := range []string{"management_fabric_input", "management_fabric_forward", "management_fabric_postrouting", "management_fabric_prerouting"} {
		fmt.Fprintf(&output, "flush chain inet gateway_vpn %s\n", chain)
	}
	for _, set := range []string{"management_fabric_interfaces", "management_fabric_endpoints", "management_fabric_generation"} {
		fmt.Fprintf(&output, "flush set inet gateway_vpn %s\n", set)
	}
	if len(plan.Links) != 0 {
		interfaces := make([]string, 0, len(plan.Links))
		endpoints := make([]string, 0, len(plan.Links))
		for _, link := range plan.Links {
			interfaces = append(interfaces, strconv.Quote(link.InterfaceName))
			endpoints = append(endpoints, fmt.Sprintf("%s . 0x%08x . %s . %d", strconv.Quote(link.UplinkInterface), uint32(link.UplinkMark), link.EndpointAddress, link.EndpointPort))
		}
		sort.Strings(interfaces)
		sort.Strings(endpoints)
		fmt.Fprintf(&output, "add element inet gateway_vpn management_fabric_interfaces { %s }\n", strings.Join(interfaces, ", "))
		fmt.Fprintf(&output, "add element inet gateway_vpn management_fabric_endpoints { %s }\n", strings.Join(endpoints, ", "))
	}
	if plan.Generation > 0 {
		fmt.Fprintf(&output, "add element inet gateway_vpn management_fabric_generation { %d }\n", plan.Generation)
	}
	fmt.Fprintf(&output, "add rule inet gateway_vpn management_fabric_input counter comment %s\n", strconv.Quote(fmt.Sprintf("gateway-vpn management fabric generation %d plan %s", plan.Generation, planDigest(plan))))
	if len(plan.ACL) != 0 {
		output.WriteString("add rule inet gateway_vpn management_fabric_forward iifname @management_fabric_interfaces ct state { established, related } counter accept comment \"gateway-vpn management fabric established requests\"\n")
		output.WriteString("add rule inet gateway_vpn management_fabric_forward oifname @management_fabric_interfaces ct state { established, related } counter accept comment \"gateway-vpn management fabric replies\"\n")
	}
	for _, rule := range plan.ACL {
		alias, local, err := translationPrefixes(rule.PublishedAlias, rule.LocalDestination)
		if err != nil {
			return nil, err
		}
		matcher, err := protocolMatcher(rule.Protocol, rule.PortStart, rule.PortEnd)
		if err != nil {
			return nil, err
		}
		comment := strconv.Quote("gateway-vpn management ACL " + rule.RuleID + " " + planDigest(plan))
		base := fmt.Sprintf("iifname %s ip saddr %s ip daddr %s %s", strconv.Quote(rule.InputInterface), rule.Source, alias.String(), matcher)
		if alias.Bits() == 32 {
			fmt.Fprintf(&output, "add rule inet gateway_vpn management_fabric_prerouting %s counter dnat ip to %s comment %s\n", base, local.Addr(), comment)
		} else {
			fmt.Fprintf(&output, "add rule inet gateway_vpn management_fabric_prerouting %s counter dnat ip prefix to ip daddr map { %s : %s } comment %s\n", base, alias, local, comment)
		}
		filterBase := fmt.Sprintf("iifname %s ip saddr %s ip daddr %s ct state new %s", strconv.Quote(rule.InputInterface), rule.Source, local.String(), matcher)
		if rule.AccessProfile == managementfabric.ProfileGatewayOnly {
			fmt.Fprintf(&output, "add rule inet gateway_vpn management_fabric_input %s counter accept comment %s\n", filterBase, comment)
			continue
		}
		fmt.Fprintf(&output, "add rule inet gateway_vpn management_fabric_forward %s counter accept comment %s\n", filterBase, comment)
		fmt.Fprintf(&output, "add rule inet gateway_vpn management_fabric_postrouting %s counter masquerade comment %s\n", filterBase, comment)
	}
	return []byte(output.String()), nil
}

func protocolMatcher(protocol string, start, end int) (string, error) {
	switch protocol {
	case managementfabric.ProtocolTCP, managementfabric.ProtocolUDP:
		ports := strconv.Itoa(start)
		if start != end {
			ports = fmt.Sprintf("%d-%d", start, end)
		}
		return strings.ToLower(protocol) + " dport " + ports, nil
	case managementfabric.ProtocolICMP:
		return "icmp type echo-request", nil
	default:
		return "", errors.New("unsupported Gateway Management Fabric ACL protocol")
	}
}

func translationPrefixes(aliasRaw, localRaw string) (netip.Prefix, netip.Prefix, error) {
	alias, err := netip.ParsePrefix(aliasRaw)
	if err != nil {
		return netip.Prefix{}, netip.Prefix{}, errors.New("invalid Gateway Management Fabric alias")
	}
	local, err := netip.ParsePrefix(localRaw)
	if err != nil {
		address, addressErr := netip.ParseAddr(localRaw)
		if addressErr != nil {
			return netip.Prefix{}, netip.Prefix{}, errors.New("invalid Gateway Management Fabric destination")
		}
		local = netip.PrefixFrom(address, 32)
	}
	if !alias.Addr().Is4() || !local.Addr().Is4() || alias.Bits() != local.Bits() || alias.Bits() == 0 {
		return netip.Prefix{}, netip.Prefix{}, errors.New("Gateway Management Fabric translation size changed")
	}
	return alias.Masked(), local.Masked(), nil
}

func planDigest(plan managementfabric.GatewayHostPlan) string {
	content, _ := json.Marshal(plan)
	digest := sha256.Sum256(content)
	return hex.EncodeToString(digest[:])
}
