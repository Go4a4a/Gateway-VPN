// Package vpsfabric applies the VPS-owned WireGuard, route and nftables
// projection. It never accepts commands, executable paths or host object names
// from HTTP or from the database.
package vpsfabric

import (
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"gateway-vpn/internal/vpsagent"
	"gateway-vpn/internal/wgingress"
)

func RenderWireGuard(plan vpsagent.VPSHostPlan, privateKey string) ([]byte, error) {
	if err := vpsagent.ValidateHostPlan(plan); err != nil {
		return nil, err
	}
	privateKey = strings.TrimSpace(privateKey)
	if public, err := wgingress.PublicKey(privateKey); err != nil || public == "" {
		return nil, errors.New("VPS WireGuard private key is invalid")
	}
	if len(plan.InterfaceAddresses) == 0 {
		return nil, errors.New("VPS host-plan requires at least one interface address")
	}
	var output strings.Builder
	output.WriteString("[Interface]\n")
	output.WriteString("Address = " + strings.Join(plan.InterfaceAddresses, ", ") + "\n")
	fmt.Fprintf(&output, "ListenPort = %d\n", plan.ListenPort)
	output.WriteString("PrivateKey = " + privateKey + "\n")
	output.WriteString("Table = off\n")
	for _, peer := range plan.Peers {
		output.WriteString("\n[Peer]\n")
		output.WriteString("PublicKey = " + peer.PublicKey + "\n")
		output.WriteString("AllowedIPs = " + strings.Join(peer.AllowedIPs, ", ") + "\n")
	}
	return []byte(output.String()), nil
}

func RenderFirewall(plan vpsagent.VPSHostPlan) ([]byte, error) {
	if err := vpsagent.ValidateHostPlan(plan); err != nil {
		return nil, err
	}
	var output strings.Builder
	output.WriteString("table inet gateway_vpn_vps {\n")
	output.WriteString("    chain input {\n        type filter hook input priority filter; policy accept;\n")
	fmt.Fprintf(&output, "        counter comment \"gateway-vpn fabric generation %d plan %s\"\n", plan.Generation, planDigest(plan))
	output.WriteString("        iifname \"wg-mgmt\" ct state established,related counter accept comment \"gateway-vpn hub replies\"\n")
	for _, source := range plan.HubAdminSources {
		for _, destination := range plan.InterfaceAddresses {
			address := strings.Split(destination, "/")[0]
			fmt.Fprintf(&output, "        iifname \"wg-mgmt\" ip saddr %s ip daddr %s ct state new tcp dport { 22, 9443 } counter accept comment \"gateway-vpn hub admin\"\n", source, address)
			fmt.Fprintf(&output, "        iifname \"wg-mgmt\" ip saddr %s ip daddr %s icmp type echo-request counter accept comment \"gateway-vpn hub diagnostics\"\n", source, address)
		}
	}
	output.WriteString("        iifname \"wg-mgmt\" counter reject with icmpx type admin-prohibited comment \"gateway-vpn deny non-admin hub access\"\n")
	output.WriteString("    }\n\n    chain forward {\n        type filter hook forward priority filter; policy accept;\n")
	output.WriteString("        iifname \"wg-mgmt\" oifname \"wg-mgmt\" ct state established,related counter accept comment \"gateway-vpn fabric replies\"\n")
	gatewayAddresses := make([]string, 0)
	for _, peer := range plan.Peers {
		if peer.Kind == "GATEWAY" {
			gatewayAddresses = append(gatewayAddresses, peer.Address)
		}
	}
	sort.Strings(gatewayAddresses)
	for _, source := range plan.HubAdminSources {
		for _, destination := range gatewayAddresses {
			ports := []int{22}
			for _, peer := range plan.Peers {
				if peer.Kind == "GATEWAY" && peer.Address == destination && peer.WebUIPort != 22 {
					ports = append(ports, peer.WebUIPort)
				}
			}
			sort.Ints(ports)
			portText := make([]string, 0, len(ports))
			for _, port := range ports {
				portText = append(portText, fmt.Sprintf("%d", port))
			}
			fmt.Fprintf(&output, "        iifname \"wg-mgmt\" oifname \"wg-mgmt\" ip saddr %s ip daddr %s ct state new tcp dport { %s } counter accept comment \"gateway-vpn gateway management\"\n", source, destination, strings.Join(portText, ", "))
			fmt.Fprintf(&output, "        iifname \"wg-mgmt\" oifname \"wg-mgmt\" ip saddr %s ip daddr %s icmp type echo-request counter accept comment \"gateway-vpn gateway diagnostics\"\n", source, destination)
		}
	}
	for _, rule := range plan.ACL {
		switch rule.Protocol {
		case "TCP", "UDP":
			protocol := strings.ToLower(rule.Protocol)
			ports := fmt.Sprintf("%d", rule.PortStart)
			if rule.PortStart != rule.PortEnd {
				ports = fmt.Sprintf("%d-%d", rule.PortStart, rule.PortEnd)
			}
			fmt.Fprintf(&output, "        iifname \"wg-mgmt\" oifname \"wg-mgmt\" ip saddr %s ip daddr %s ct state new %s dport %s counter accept comment \"gateway-vpn resource acl\"\n", rule.Source, rule.Destination, protocol, ports)
		case "ICMP":
			fmt.Fprintf(&output, "        iifname \"wg-mgmt\" oifname \"wg-mgmt\" ip saddr %s ip daddr %s icmp type echo-request counter accept comment \"gateway-vpn resource icmp acl\"\n", rule.Source, rule.Destination)
		default:
			return nil, errors.New("VPS host-plan contains unsupported ACL protocol")
		}
	}
	output.WriteString("        iifname \"wg-mgmt\" counter reject with icmpx type admin-prohibited comment \"gateway-vpn deny other fabric ingress forwarding\"\n")
	output.WriteString("        oifname \"wg-mgmt\" counter reject with icmpx type admin-prohibited comment \"gateway-vpn deny other fabric egress forwarding\"\n")
	output.WriteString("    }\n}\n")
	return []byte(output.String()), nil
}

func routeDestinations(plan vpsagent.VPSHostPlan) ([]string, error) {
	if err := vpsagent.ValidateHostPlan(plan); err != nil {
		return nil, err
	}
	seen := map[string]struct{}{}
	for _, peer := range plan.Peers {
		for _, raw := range peer.AllowedIPs {
			prefix, err := netip.ParsePrefix(raw)
			if err != nil || prefix.Bits() == 0 {
				return nil, errors.New("invalid owned VPS fabric route")
			}
			seen[prefix.String()] = struct{}{}
		}
	}
	result := make([]string, 0, len(seen))
	for value := range seen {
		result = append(result, value)
	}
	sort.Strings(result)
	return result, nil
}
