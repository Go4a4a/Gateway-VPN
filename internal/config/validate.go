package config

import (
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"path"
	"strings"

	"gateway-vpn/internal/bypass"
	"gateway-vpn/internal/netutil"
)

type FieldError struct {
	Field   string
	Message string
}

func (e FieldError) Error() string {
	return e.Field + ": " + e.Message
}

type ValidationErrors []FieldError

func (errors ValidationErrors) Error() string {
	parts := make([]string, 0, len(errors))
	for _, err := range errors {
		parts = append(parts, err.Error())
	}
	return strings.Join(parts, "; ")
}

func (c Config) Validate() error {
	var errors ValidationErrors

	if c.Version != CurrentVersion {
		errors.add("version", fmt.Sprintf("must be %d", CurrentVersion))
	}

	errors.requireAbsolutePath("system.state_dir", c.System.StateDir)
	errors.requireAbsolutePath("system.database", c.System.Database)
	cleanStateDirectory, cleanDatabase := path.Clean(c.System.StateDir), path.Clean(c.System.Database)
	if path.IsAbs(cleanStateDirectory) && path.IsAbs(cleanDatabase) && (cleanStateDirectory == "/" || !strings.HasPrefix(cleanDatabase, strings.TrimSuffix(cleanStateDirectory, "/")+"/")) {
		errors.add("system.database", "must be stored inside system.state_dir for atomic backup and corruption recovery")
	}
	if !oneOf(strings.ToUpper(c.System.LogLevel), "INFO", "WARN", "ERROR") {
		errors.add("system.log_level", "must be INFO, WARN, or ERROR; temporary DEBUG is enabled only through WebUI with a TTL")
	}

	if !validInterfaceName(c.Network.LANInterface) {
		errors.add("network.lan_interface", "must be a valid Linux interface name")
	}
	if !netutil.ValidGatewayLAN(c.Network.LANAddress) {
		errors.add("network.lan_address", "must be a usable private IPv4 host CIDR with /16../30 and must not overlap WireGuard management")
	}
	if c.Network.IPv6Mode != "disabled" {
		errors.add("network.ipv6_mode", "must be disabled in MVP")
	}

	if c.Modems.Type != "hilink" {
		errors.add("modems.type", "must be hilink in MVP")
	}
	if !c.Modems.RequireAdoption {
		errors.add("modems.require_adoption", "must be true to prevent ambiguous devices from taking saved routes")
	}
	if !c.Modems.RequireUniqueManagementSubnets {
		errors.add("modems.require_unique_management_subnets", "must be true in MVP")
	}
	if c.Modems.RoutingTableStart < 256 {
		errors.add("modems.routing_table_start", "must avoid Linux reserved routing tables 0-255")
	}
	if c.Modems.FwmarkStart == 0 {
		errors.add("modems.fwmark_start", "must not be zero")
	}

	errors.requireAbsolutePath("mihomo.binary", c.Mihomo.Binary)
	if path.Clean(c.Mihomo.Binary) != "/opt/gateway-vpn/current/libexec/mihomo" {
		errors.add("mihomo.binary", "must use the fixed versioned Gateway VPN Mihomo path")
	}
	if !validInterfaceName(c.Mihomo.TunName) {
		errors.add("mihomo.tun_name", "must be a valid Linux interface name")
	}
	if !oneOf(c.Mihomo.Stack, "mixed", "system", "gvisor") {
		errors.add("mihomo.stack", "must be mixed, system, or gvisor")
	}
	if addr, ok := parseListenAddress("mihomo.api_address", c.Mihomo.APIAddress, &errors); ok && !addr.IsLoopback() {
		errors.add("mihomo.api_address", "must bind to loopback")
	}
	if addr, ok := parseListenAddress("mihomo.probe_address", c.Mihomo.ProbeAddress, &errors); ok && !addr.IsLoopback() {
		errors.add("mihomo.probe_address", "must bind to loopback")
	}
	if c.Mihomo.ProbeAddress == c.Mihomo.APIAddress {
		errors.add("mihomo.probe_address", "must differ from mihomo.api_address")
	}
	errors.requireAbsolutePath("mihomo.api_secret_file", c.Mihomo.APISecretFile)
	if path.Clean(c.Mihomo.APISecretFile) != path.Join(cleanStateDirectory, "secrets", "mihomo-api-secret") {
		errors.add("mihomo.api_secret_file", "must use the fixed protected state secret path")
	}
	if len(c.Mihomo.BootstrapDNS) == 0 || len(c.Mihomo.BootstrapDNS) > 8 {
		errors.add("mihomo.bootstrap_dns", "must contain 1..8 IPv4 DNS addresses")
	}
	seenDNS := make(map[netip.Addr]struct{}, len(c.Mihomo.BootstrapDNS))
	for index, value := range c.Mihomo.BootstrapDNS {
		field := fmt.Sprintf("mihomo.bootstrap_dns[%d]", index)
		address, err := netip.ParseAddr(value)
		if err != nil || !address.Is4() || !address.IsGlobalUnicast() || address.IsLoopback() || address.IsMulticast() || address.IsUnspecified() {
			errors.add(field, "must be a usable unicast IPv4 address")
			continue
		}
		if _, exists := seenDNS[address]; exists {
			errors.add(field, "duplicates another bootstrap DNS address")
		}
		seenDNS[address] = struct{}{}
	}
	probeURL, err := url.Parse(c.Mihomo.TransportProbeURL)
	if err != nil || probeURL.Scheme != "https" || probeURL.Host == "" || probeURL.User != nil || probeURL.Fragment != "" {
		errors.add("mihomo.transport_probe_url", "must be an HTTPS URL without credentials or fragment")
	} else if !validPublicProbeHost(probeURL.Hostname()) {
		errors.add("mihomo.transport_probe_url", "must use a public IP or fully-qualified public hostname")
	}
	if c.Mihomo.TransportProbeTimeoutSeconds < 1 || c.Mihomo.TransportProbeTimeoutSeconds > 60 {
		errors.add("mihomo.transport_probe_timeout_seconds", "must be between 1 and 60")
	}
	if _, err := bypass.NormalizeStatusExpression(c.Mihomo.TransportExpectedStatus); err != nil {
		errors.add("mihomo.transport_expected_status", "must be a valid HTTP status expression such as 204, 200-399, or 200/302")
	}

	if len(c.API.Listen) == 0 {
		errors.add("api.listen", "must contain at least one address")
	}
	seen := make(map[string]struct{}, len(c.API.Listen))
	for i, listen := range c.API.Listen {
		field := fmt.Sprintf("api.listen[%d]", i)
		addr, ok := parseListenAddress(field, listen, &errors)
		if ok && (!addr.Is4() || !addr.IsPrivate() || addr.IsUnspecified() || addr.IsLoopback()) {
			errors.add(field, "must bind to a private, non-loopback IPv4 address")
		}
		if _, exists := seen[listen]; exists {
			errors.add(field, "duplicates another listen address")
		}
		seen[listen] = struct{}{}
	}
	errors.requireAbsolutePath("api.tls_cert", c.API.TLSCert)
	errors.requireAbsolutePath("api.tls_key", c.API.TLSKey)
	if path.Clean(c.API.TLSCert) != path.Join(cleanStateDirectory, "tls", "cert.pem") {
		errors.add("api.tls_cert", "must use the fixed protected state TLS certificate path")
	}
	if path.Clean(c.API.TLSKey) != path.Join(cleanStateDirectory, "tls", "key.pem") {
		errors.add("api.tls_key", "must use the fixed protected state TLS key path")
	}

	if len(errors) != 0 {
		return errors
	}
	return nil
}

func validPublicProbeHost(value string) bool {
	host := strings.ToLower(strings.TrimSuffix(value, "."))
	if address, err := netip.ParseAddr(host); err == nil {
		return address.IsGlobalUnicast() && !address.IsPrivate() && !address.IsLoopback() && !address.IsLinkLocalUnicast()
	}
	if host == "" || len(host) > 253 || host == "localhost" || strings.HasSuffix(host, ".localhost") || strings.HasSuffix(host, ".local") || strings.HasSuffix(host, ".lan") || strings.HasSuffix(host, ".internal") {
		return false
	}
	labels := strings.Split(host, ".")
	if len(labels) < 2 {
		return false
	}
	for _, label := range labels {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, char := range label {
			if (char >= 'a' && char <= 'z') || (char >= '0' && char <= '9') || char == '-' {
				continue
			}
			return false
		}
	}
	return true
}

func (errors *ValidationErrors) add(field, message string) {
	*errors = append(*errors, FieldError{Field: field, Message: message})
}

func (errors *ValidationErrors) requireAbsolutePath(field, value string) {
	if value == "" || !path.IsAbs(value) {
		errors.add(field, "must be an absolute Linux path")
	}
}

func parseListenAddress(field, value string, errors *ValidationErrors) (netip.Addr, bool) {
	host, port, err := net.SplitHostPort(value)
	if err != nil {
		errors.add(field, "must use host:port syntax")
		return netip.Addr{}, false
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		errors.add(field, "host must be an IP address")
		return netip.Addr{}, false
	}
	parsedPort, err := netip.ParseAddrPort(net.JoinHostPort(host, port))
	if err != nil || parsedPort.Port() == 0 {
		errors.add(field, "port must be between 1 and 65535")
		return netip.Addr{}, false
	}
	return addr, true
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

func oneOf(value string, allowed ...string) bool {
	for _, candidate := range allowed {
		if value == candidate {
			return true
		}
	}
	return false
}
