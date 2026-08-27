package firewall

import (
	"context"
	"errors"
	"strings"
	"testing"

	"gateway-vpn/internal/platformexec"
)

func TestBootRulesetIsFailClosedAndOwned(t *testing.T) {
	ruleset, err := RenderBootBlocked(BootConfig{
		LANInterface:        "enp2s0",
		TUNInterface:        "gateway-vpn-tun",
		WireGuardInterface:  "wg-mgmt",
		APIPort:             8443,
		WireGuardListenPort: 51821,
	})
	if err != nil {
		t.Fatalf("RenderBootBlocked() error = %v", err)
	}
	for _, expected := range []string{
		"table inet gateway_vpn",
		"set firewall_schema_generation",
		"type mark",
		"elements = { 2 }",
		"set active_tun_interfaces",
		"set active_path_generation",
		"set bootstrap_dns_v4",
		"set wireguard_endpoint_generation",
		"set bootstrap_http_v4",
		"set mihomo_endpoint_tcp_v4",
		"set mihomo_endpoint_udp_v4",
		"set mihomo_endpoint_generation",
		"set service_context_generation",
		"counter user_upload",
		"counter user_download",
		"counter service_upload",
		"counter service_download",
		"iifname @hilink_interfaces ct state { established, related } counter name service_download",
		"oifname @hilink_interfaces ct state { established, related } counter name service_upload",
		"hook input priority filter; policy drop",
		"hook forward priority filter; policy drop",
		"hook output priority filter; policy drop",
		"gateway-vpn PATH_BLOCKED",
		"iifname \"enp2s0\" tcp dport 8443 accept",
		"iifname \"enp2s0\" tcp dport 22 accept",
		"iifname \"wg-mgmt\" tcp dport 8443 accept",
		"meta nfproto ipv4 iifname \"enp2s0\" oifname @active_tun_interfaces",
		"meta nfproto ipv4 iifname @active_tun_interfaces oifname \"enp2s0\"",
		"meta skuid \"gateway-vpn\" oifname . meta mark . ip daddr @bootstrap_dns_v4 udp dport 53",
		"meta skuid \"gateway-vpn\" oifname . meta mark . ip daddr . tcp dport @bootstrap_http_v4",
		"meta skuid \"gateway-vpn-mihomo\" oifname . meta mark . ip daddr . tcp dport @mihomo_endpoint_tcp_v4",
		"meta skuid 0 oifname . meta mark . ip daddr @bootstrap_dns_v4 udp dport 53",
		"@wireguard_endpoint_v4 udp dport 51821 counter name service_upload",
	} {
		if !strings.Contains(ruleset.Text, expected) {
			t.Errorf("ruleset missing %q:\n%s", expected, ruleset.Text)
		}
	}
	for _, forbidden := range []string{"flush ruleset", "policy accept", "type integer", "enp2s0\" oifname @hilink_interfaces accept"} {
		if strings.Contains(ruleset.Text, forbidden) {
			t.Errorf("ruleset contains forbidden %q", forbidden)
		}
	}
	if len(ruleset.SHA256) != 64 {
		t.Fatalf("ruleset SHA256 length = %d", len(ruleset.SHA256))
	}
}

func TestBootRulesetAccountsEveryAllowedDirectServiceDirection(t *testing.T) {
	ruleset, err := RenderBootBlocked(BootConfig{LANInterface: "enp2s0", TUNInterface: "gateway-vpn-tun", WireGuardInterface: "wg-mgmt", APIPort: 8443, WireGuardListenPort: 51821})
	if err != nil {
		t.Fatal(err)
	}
	inputScoped := `iifname @hilink_interfaces ct state { established, related } counter name service_download accept`
	outputScoped := `oifname @hilink_interfaces ct state { established, related } counter name service_upload accept`
	if strings.Index(ruleset.Text, inputScoped) < 0 || strings.Index(ruleset.Text, inputScoped) > strings.Index(ruleset.Text, "        ct state { established, related } accept") {
		t.Fatal("modem download accounting does not precede generic established input")
	}
	outputStart := strings.Index(ruleset.Text, "    chain output {")
	if outputStart < 0 {
		t.Fatal("output chain is missing")
	}
	output := ruleset.Text[outputStart:]
	if strings.Index(output, outputScoped) < 0 || strings.Index(output, outputScoped) > strings.Index(output, "        ct state { established, related } accept") {
		t.Fatal("modem upload accounting does not precede generic established output")
	}
	for _, directRule := range []string{
		`modem DHCP request`, `modem management`, `WireGuard endpoint`,
		`control bootstrap DNS UDP`, `control bootstrap DNS TCP`, `subscription HTTPS`,
		`root endpoint DNS UDP`, `root endpoint DNS TCP`,
		`Mihomo bootstrap DNS UDP`, `Mihomo bootstrap DNS TCP`, `Mihomo proxy TCP`, `Mihomo proxy UDP`,
	} {
		line := ""
		for _, candidate := range strings.Split(output, "\n") {
			if strings.Contains(candidate, `comment "gateway-vpn `+directRule+`"`) {
				line = candidate
				break
			}
		}
		if line == "" || !strings.Contains(line, "counter name service_upload accept") {
			t.Errorf("direct service rule %q is not upload-accounted: %q", directRule, line)
		}
	}
	if !strings.Contains(ruleset.Text, `modem DHCP reply"`) || !strings.Contains(ruleset.Text, `udp sport 67 udp dport 68 counter name service_download accept`) {
		t.Fatal("modem DHCP download is not separately accounted")
	}
}

func TestValidateAndLoadIsDryByDefaultAndChecksBeforeLoad(t *testing.T) {
	ruleset, err := RenderBootBlocked(BootConfig{LANInterface: "enp2s0", TUNInterface: "gateway-vpn-tun", WireGuardInterface: "wg-mgmt", APIPort: 8443, WireGuardListenPort: 51821})
	if err != nil {
		t.Fatalf("RenderBootBlocked() error = %v", err)
	}
	executor := &fakeExecutor{}
	if err := ValidateAndLoad(context.Background(), executor, ruleset, LoadOptions{NFTExecutable: "/usr/sbin/nft"}); err != nil {
		t.Fatalf("dry ValidateAndLoad() error = %v", err)
	}
	if len(executor.requests) != 0 {
		t.Fatalf("dry load executed %d requests", len(executor.requests))
	}
	if err := ValidateAndLoad(context.Background(), executor, ruleset, LoadOptions{NFTExecutable: "/usr/sbin/nft", Mutate: true}); err != nil {
		t.Fatalf("mutating ValidateAndLoad() error = %v", err)
	}
	if len(executor.requests) != 3 {
		t.Fatalf("load request count = %d, want 3", len(executor.requests))
	}
	if strings.Join(executor.requests[0].Arguments, " ") != "list table inet gateway_vpn" || strings.Join(executor.requests[1].Arguments, " ") != "--check --file -" || strings.Join(executor.requests[2].Arguments, " ") != "--file -" {
		t.Fatalf("unexpected nft requests: %+v", executor.requests)
	}
	if !strings.HasPrefix(string(executor.requests[1].Stdin), "delete table inet gateway_vpn\n") {
		t.Fatal("existing owned table is not replaced in the same nft transaction")
	}
}

func TestValidationFailurePreventsLoad(t *testing.T) {
	ruleset, err := RenderBootBlocked(BootConfig{LANInterface: "enp2s0", TUNInterface: "gateway-vpn-tun", WireGuardInterface: "wg-mgmt", APIPort: 8443, WireGuardListenPort: 51821})
	if err != nil {
		t.Fatalf("RenderBootBlocked() error = %v", err)
	}
	executor := &fakeExecutor{errors: []error{nil, errors.New("syntax error")}}
	err = ValidateAndLoad(context.Background(), executor, ruleset, LoadOptions{NFTExecutable: "/usr/sbin/nft", Mutate: true})
	if err == nil {
		t.Fatal("ValidateAndLoad() error = nil, want syntax error")
	}
	if len(executor.requests) != 2 {
		t.Fatalf("validation failure executed %d requests, want 2", len(executor.requests))
	}
}

type fakeExecutor struct {
	requests []platformexec.Request
	errors   []error
}

func (executor *fakeExecutor) Run(_ context.Context, request platformexec.Request) (platformexec.Result, error) {
	executor.requests = append(executor.requests, request)
	if len(executor.errors) == 0 {
		return platformexec.Result{}, nil
	}
	err := executor.errors[0]
	executor.errors = executor.errors[1:]
	return platformexec.Result{ExitCode: 1, Stderr: "syntax error"}, err
}
