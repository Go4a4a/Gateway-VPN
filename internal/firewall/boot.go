// Package firewall renders and safely validates Gateway VPN-owned nftables
// rulesets.
package firewall

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"gateway-vpn/internal/platformexec"
)

const (
	TableName        = "gateway_vpn"
	SchemaGeneration = 4
)

type BootConfig struct {
	LANInterface         string
	TUNInterface         string
	WireGuardInterface   string
	APIPort              uint16
	WireGuardListenPort  uint16
	DisableSSHManagement bool
}

type Ruleset struct {
	Text   string
	SHA256 string
}

func RenderBootBlocked(config BootConfig) (Ruleset, error) {
	if !validInterfaceName(config.LANInterface) || !validInterfaceName(config.TUNInterface) || !validInterfaceName(config.WireGuardInterface) {
		return Ruleset{}, errors.New("firewall interface names must be valid Linux interface names")
	}
	if config.APIPort == 0 || config.WireGuardListenPort == 0 {
		return Ruleset{}, errors.New("firewall ports must be non-zero")
	}

	sshRule := ""
	if !config.DisableSSHManagement {
		sshRule = fmt.Sprintf("        iifname %s tcp dport 22 accept comment \"gateway-vpn LAN SSH\"\n", nftString(config.LANInterface))
	}

	text := fmt.Sprintf(`table inet %s {
    set firewall_schema_generation {
		type mark
        elements = { %d }
    }

    set hilink_interfaces {
        type ifname
        flags dynamic
    }

    set hilink_management_v4 {
		type ifname . ipv4_addr
    }

	set wireguard_endpoint_v4 {
		type ifname . mark . ipv4_addr
	}

	set wireguard_endpoint_generation {
		type mark
	}

    set bootstrap_dns_v4 {
		type ifname . mark . ipv4_addr
    }

    set bootstrap_http_v4 {
		type ifname . mark . ipv4_addr . inet_service
		flags timeout
		timeout 2m
	}

	set mihomo_endpoint_tcp_v4 {
		type ifname . mark . ipv4_addr . inet_service
	}

	set mihomo_endpoint_udp_v4 {
		type ifname . mark . ipv4_addr . inet_service
	}

	set mihomo_endpoint_generation {
		type mark
	}

	set service_context_generation {
		type mark
	}

	set user_ingress_interfaces {
		type ifname
		elements = { %s, "wg-ingress" }
	}

	set wireguard_ingress_listeners {
		type ifname . inet_service
	}

	set wireguard_ingress_allowed_v4 {
		type ipv4_addr
		flags interval
	}

	set active_tun_interfaces {
        type ifname
    }

	set active_direct_interfaces {
		type ifname
	}

	set active_direct_context {
		type ifname . mark
	}

	map active_direct_marks {
		type ifname : mark
	}

    set active_path_generation {
		type mark
    }

	set active_route_generation {
		type mark
	}

    counter user_upload {
        comment "gateway-vpn authoritative user upload"
    }

    counter user_download {
        comment "gateway-vpn authoritative user download"
    }

    counter service_upload {
        comment "gateway-vpn authoritative direct service upload"
    }

    counter service_download {
        comment "gateway-vpn authoritative direct service download"
    }

    chain prerouting {
		type filter hook prerouting priority mangle;
        meta nfproto ipv4 iifname @user_ingress_interfaces meta mark set iifname map @active_direct_marks comment "gateway-vpn selected direct uplink mark"
	}

    chain input {
        type filter hook input priority filter; policy drop;
        iifname "lo" accept comment "gateway-vpn loopback"
        ct state invalid drop
        iifname @hilink_interfaces ct state { established, related } counter name service_download accept comment "gateway-vpn direct service download"
        ct state { established, related } accept
        iifname %s udp sport 68 udp dport 67 accept comment "gateway-vpn LAN DHCP request"
        iifname %s udp dport 53 accept comment "gateway-vpn LAN DNS UDP"
        iifname %s tcp dport 53 accept comment "gateway-vpn LAN DNS TCP"
		iifname "wg-ingress" udp dport 53 accept comment "gateway-vpn WireGuard client DNS UDP"
		iifname "wg-ingress" tcp dport 53 accept comment "gateway-vpn WireGuard client DNS TCP"
        iifname %s tcp dport %d accept comment "gateway-vpn LAN API"
%s        iifname %s tcp dport %d accept comment "gateway-vpn WireGuard API"
		iifname . udp dport @wireguard_ingress_listeners accept comment "gateway-vpn selected WireGuard ingress listener"
        iifname @hilink_interfaces udp sport 67 udp dport 68 counter name service_download accept comment "gateway-vpn modem DHCP reply"
    }

    chain forward {
        type filter hook forward priority filter; policy drop;
        ct state invalid drop
        meta nfproto ipv4 iifname %s oifname @active_tun_interfaces counter name user_upload accept comment "gateway-vpn LAN to verified TUN"
		meta nfproto ipv4 iifname "wg-ingress" ip saddr @wireguard_ingress_allowed_v4 oifname @active_tun_interfaces counter name user_upload accept comment "gateway-vpn allowed WireGuard client to verified TUN"
        meta nfproto ipv4 iifname @active_tun_interfaces oifname %s ct state { established, related } counter name user_download accept comment "gateway-vpn verified TUN to LAN"
		meta nfproto ipv4 iifname @active_tun_interfaces oifname "wg-ingress" ip daddr @wireguard_ingress_allowed_v4 ct state { established, related } counter name user_download accept comment "gateway-vpn verified TUN to allowed WireGuard client"
		meta nfproto ipv4 iifname %s oifname . meta mark @active_direct_context counter name user_upload accept comment "gateway-vpn LAN to verified direct uplink"
		meta nfproto ipv4 iifname "wg-ingress" ip saddr @wireguard_ingress_allowed_v4 oifname . meta mark @active_direct_context counter name user_upload accept comment "gateway-vpn allowed WireGuard client to verified direct uplink"
		meta nfproto ipv4 iifname @active_direct_interfaces oifname %s ct state { established, related } counter name user_download accept comment "gateway-vpn verified direct uplink to LAN"
		meta nfproto ipv4 iifname @active_direct_interfaces oifname "wg-ingress" ip daddr @wireguard_ingress_allowed_v4 ct state { established, related } counter name user_download accept comment "gateway-vpn verified direct uplink to allowed WireGuard client"
        counter comment "gateway-vpn PATH_BLOCKED"
    }

	chain postrouting {
		type nat hook postrouting priority srcnat;
		meta nfproto ipv4 iifname %s oifname . meta mark @active_direct_context masquerade comment "gateway-vpn selected direct LAN NAT"
		meta nfproto ipv4 iifname "wg-ingress" ip saddr @wireguard_ingress_allowed_v4 oifname . meta mark @active_direct_context masquerade comment "gateway-vpn selected direct WireGuard NAT"
	}

    chain output {
        type filter hook output priority filter; policy drop;
        oifname "lo" accept comment "gateway-vpn loopback"
        ct state invalid drop
        oifname @hilink_interfaces ct state { established, related } counter name service_upload accept comment "gateway-vpn direct service upload"
        ct state { established, related } accept
        oifname %s udp sport 67 udp dport 68 accept comment "gateway-vpn LAN DHCP reply"
        oifname @hilink_interfaces udp sport 68 udp dport 67 counter name service_upload accept comment "gateway-vpn modem DHCP request"
		oifname . ip daddr @hilink_management_v4 tcp dport { 80, 443 } counter name service_upload accept comment "gateway-vpn modem management"
		oifname . meta mark . ip daddr @wireguard_endpoint_v4 udp dport %d counter name service_upload accept comment "gateway-vpn WireGuard endpoint"
		meta skuid "gateway-vpn" oifname . meta mark . ip daddr @bootstrap_dns_v4 udp dport 53 counter name service_upload accept comment "gateway-vpn control bootstrap DNS UDP"
		meta skuid "gateway-vpn" oifname . meta mark . ip daddr @bootstrap_dns_v4 tcp dport 53 counter name service_upload accept comment "gateway-vpn control bootstrap DNS TCP"
		meta skuid "gateway-vpn" oifname . meta mark . ip daddr . tcp dport @bootstrap_http_v4 counter name service_upload accept comment "gateway-vpn subscription HTTPS"
		meta skuid 0 oifname . meta mark . ip daddr @bootstrap_dns_v4 udp dport 53 counter name service_upload accept comment "gateway-vpn root endpoint DNS UDP"
		meta skuid 0 oifname . meta mark . ip daddr @bootstrap_dns_v4 tcp dport 53 counter name service_upload accept comment "gateway-vpn root endpoint DNS TCP"
		meta skuid "gateway-vpn-mihomo" oifname . meta mark . ip daddr @bootstrap_dns_v4 udp dport 53 counter name service_upload accept comment "gateway-vpn Mihomo bootstrap DNS UDP"
		meta skuid "gateway-vpn-mihomo" oifname . meta mark . ip daddr @bootstrap_dns_v4 tcp dport 53 counter name service_upload accept comment "gateway-vpn Mihomo bootstrap DNS TCP"
		meta skuid "gateway-vpn-mihomo" oifname . meta mark . ip daddr . tcp dport @mihomo_endpoint_tcp_v4 counter name service_upload accept comment "gateway-vpn Mihomo proxy TCP"
		meta skuid "gateway-vpn-mihomo" oifname . meta mark . ip daddr . udp dport @mihomo_endpoint_udp_v4 counter name service_upload accept comment "gateway-vpn Mihomo proxy UDP"
    }
}
`,
		TableName,
		SchemaGeneration,
		nftString(config.LANInterface),
		nftString(config.LANInterface),
		nftString(config.LANInterface),
		nftString(config.LANInterface),
		nftString(config.LANInterface),
		config.APIPort,
		sshRule,
		nftString(config.WireGuardInterface),
		config.APIPort,
		nftString(config.LANInterface),
		nftString(config.LANInterface),
		nftString(config.LANInterface),
		nftString(config.LANInterface),
		nftString(config.LANInterface),
		nftString(config.LANInterface),
		config.WireGuardListenPort,
	)
	digest := sha256.Sum256([]byte(text))
	return Ruleset{Text: text, SHA256: hex.EncodeToString(digest[:])}, nil
}

type LoadOptions struct {
	NFTExecutable string
	Mutate        bool
}

func ValidateAndLoad(ctx context.Context, executor platformexec.Executor, ruleset Ruleset, options LoadOptions) error {
	if ruleset.Text == "" {
		return errors.New("nftables ruleset is empty")
	}
	digest := sha256.Sum256([]byte(ruleset.Text))
	if hex.EncodeToString(digest[:]) != ruleset.SHA256 {
		return errors.New("nftables ruleset checksum mismatch")
	}
	if !strings.Contains(ruleset.Text, "table inet "+TableName) {
		return errors.New("nftables ruleset does not own the expected table")
	}
	if !options.Mutate {
		return nil
	}
	payload := ruleset.Text
	probe := platformexec.Request{
		Executable: options.NFTExecutable,
		Arguments:  []string{"list", "table", "inet", TableName},
	}
	result, err := executor.Run(ctx, probe)
	switch {
	case err == nil:
		// Deleting and recreating only the owned table happens in the same nft
		// netlink transaction as the replacement ruleset.
		payload = "delete table inet " + TableName + "\n" + payload
	case result.ExitCode == 1:
		// The owned table does not exist yet; first boot creates it.
	default:
		return fmt.Errorf("inspect owned nftables table: %s: %w", strings.TrimSpace(result.Stderr), err)
	}
	check := platformexec.Request{
		Executable: options.NFTExecutable,
		Arguments:  []string{"--check", "--file", "-"},
		Stdin:      []byte(payload),
	}
	if result, err := executor.Run(ctx, check); err != nil {
		return fmt.Errorf("validate nftables ruleset: %s: %w", strings.TrimSpace(result.Stderr), err)
	}
	load := platformexec.Request{
		Executable: options.NFTExecutable,
		Arguments:  []string{"--file", "-"},
		Stdin:      []byte(payload),
	}
	if result, err := executor.Run(ctx, load); err != nil {
		return fmt.Errorf("load nftables ruleset: %s: %w", strings.TrimSpace(result.Stderr), err)
	}
	return nil
}

func nftString(value string) string {
	return strconv.Quote(value)
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
