package networkapply

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gateway-vpn/internal/config"
	"gateway-vpn/internal/firewall"
	"gateway-vpn/internal/platformexec"

	"go.yaml.in/yaml/v3"
)

func TestUbuntuBackendSnapshotApplyCommitAndRollbackUseTypedAssets(t *testing.T) {
	ctx := context.Background()
	backend, executor, manifest, transactionDirectory := ubuntuBackendFixture(t)
	if err := backend.Snapshot(ctx, manifest, transactionDirectory); err != nil {
		t.Fatalf("Snapshot() error = %v", err)
	}
	candidateConfig, err := config.Load(filepath.Join(transactionDirectory, "candidate", "config.yaml"))
	if err != nil || candidateConfig.Network.LANAddress != manifest.NewLANCIDR || candidateConfig.API.Listen[0] != "192.168.210.1:8443" {
		t.Fatalf("candidate config = %+v, %v", candidateConfig, err)
	}
	dnsmasq, err := os.ReadFile(filepath.Join(transactionDirectory, "candidate", "dnsmasq.conf"))
	if err != nil || !strings.Contains(string(dnsmasq), "dhcp-range=192.168.210.100,192.168.210.200") {
		t.Fatalf("candidate dnsmasq = %q, %v", dnsmasq, err)
	}
	if err := backend.Apply(ctx, manifest, transactionDirectory); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	if !executor.addresses[manifest.OldLANCIDR] || !executor.addresses[manifest.NewLANCIDR] {
		t.Fatalf("addresses after apply = %+v", executor.addresses)
	}
	installed, err := config.Load(backend.Paths.ConfigFile)
	if err != nil || installed.Network.LANAddress != manifest.NewLANCIDR {
		t.Fatalf("installed candidate config = %+v, %v", installed, err)
	}
	lanNetwork, err := os.ReadFile(backend.Paths.LANNetworkFile)
	if err != nil || !strings.Contains(string(lanNetwork), "Address="+manifest.NewLANCIDR) {
		t.Fatalf("installed LAN persistence = %q, %v", lanNetwork, err)
	}
	if !executor.called(backend.Paths.NFT, "--check", "--file", filepath.Join(transactionDirectory, "candidate", "boot.nft")) || !executor.called(backend.Paths.Systemctl, "--no-block", "restart", "gateway-vpn.service") || !executor.called(backend.Paths.Networkctl, "reload") {
		t.Fatalf("missing typed apply calls: %+v", executor.calls)
	}
	if err := backend.Commit(ctx, manifest, transactionDirectory); err != nil {
		t.Fatalf("Commit() error = %v", err)
	}
	if executor.addresses[manifest.OldLANCIDR] || !executor.addresses[manifest.NewLANCIDR] {
		t.Fatalf("addresses after commit = %+v", executor.addresses)
	}

	// Rollback is idempotent with respect to address presence and restores only
	// the fixed snapshotted Gateway VPN assets.
	if err := backend.Rollback(ctx, manifest, transactionDirectory); err != nil {
		t.Fatalf("Rollback() error = %v", err)
	}
	restored, err := config.Load(backend.Paths.ConfigFile)
	if err != nil || restored.Network.LANAddress != manifest.OldLANCIDR {
		t.Fatalf("restored config = %+v, %v", restored, err)
	}
	lanNetwork, err = os.ReadFile(backend.Paths.LANNetworkFile)
	if err != nil || !strings.Contains(string(lanNetwork), "Address="+manifest.OldLANCIDR) {
		t.Fatalf("restored LAN persistence = %q, %v", lanNetwork, err)
	}
	if !executor.addresses[manifest.OldLANCIDR] || executor.addresses[manifest.NewLANCIDR] {
		t.Fatalf("addresses after rollback = %+v", executor.addresses)
	}
}

func TestUbuntuBackendRejectsSnapshotWhenObservedAddressDoesNotMatch(t *testing.T) {
	backend, executor, manifest, transactionDirectory := ubuntuBackendFixture(t)
	delete(executor.addresses, manifest.OldLANCIDR)
	if err := backend.Snapshot(context.Background(), manifest, transactionDirectory); err == nil || !strings.Contains(err.Error(), "address") {
		t.Fatalf("Snapshot(missing old address) error = %v", err)
	}
}

func TestUbuntuBackendRejectsNewLANOverlappingAnyObservedHostInterface(t *testing.T) {
	backend, executor, manifest, transactionDirectory := ubuntuBackendFixture(t)
	executor.hostAddressJSON = `[{"ifname":"enp2s0","addr_info":[{"family":"inet","local":"192.168.200.1","prefixlen":24}]},{"ifname":"wg-extra","addr_info":[{"family":"inet","local":"192.168.210.2","prefixlen":24}]}]`
	if err := backend.Snapshot(context.Background(), manifest, transactionDirectory); err == nil || !strings.Contains(err.Error(), "wg-extra") {
		t.Fatalf("Snapshot(overlap) error = %v", err)
	}
}

func ubuntuBackendFixture(t *testing.T) (UbuntuBackend, *statefulBackendExecutor, Manifest, string) {
	t.Helper()
	root := t.TempDir()
	paths := UbuntuPaths{
		ConfigFile:     filepath.Join(root, "etc", "config.yaml"),
		DNSMasqFile:    filepath.Join(root, "etc", "dnsmasq.conf"),
		BootNFTFile:    filepath.Join(root, "etc", "boot.nft"),
		LANNetDevFile:  filepath.Join(root, "etc", "lan.netdev"),
		LANNetworkFile: filepath.Join(root, "etc", "lan.network"),
		IP:             filepath.Join(root, "bin", "ip"), NFT: filepath.Join(root, "bin", "nft"),
		DNSMasq: filepath.Join(root, "bin", "dnsmasq"), Systemctl: filepath.Join(root, "bin", "systemctl"), Networkctl: filepath.Join(root, "bin", "networkctl"),
		ConfigGID: -1,
	}
	if err := os.MkdirAll(filepath.Dir(paths.ConfigFile), 0o700); err != nil {
		t.Fatal(err)
	}
	configuration := config.Default()
	configuration.Network.LANInterface = "enp2s0"
	configuration.Network.LANAddress = "192.168.200.1/24"
	configuration.API.Listen = []string{"192.168.200.1:8443", "10.80.0.2:8443"}
	encoded, err := yaml.Marshal(configuration)
	if err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, paths.ConfigFile, encoded)
	ruleset, err := firewall.RenderBootBlocked(firewall.BootConfig{LANInterface: "enp2s0", TUNInterface: "gateway-vpn-tun", WireGuardInterface: "wg-mgmt", APIPort: 8443, WireGuardListenPort: 51821})
	if err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, paths.BootNFTFile, []byte(ruleset.Text))
	lanNetwork, err := renderLANNetwork("enp2s0", "192.168.200.1/24")
	if err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, paths.LANNetworkFile, []byte(lanNetwork))
	dnsmasq, err := renderDNSMasq("enp2s0", "192.168.200.1/24")
	if err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, paths.DNSMasqFile, []byte(dnsmasq))
	transactionDirectory := filepath.Join(root, "transactions", "apply-test")
	if err := os.MkdirAll(transactionDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	manifest := Manifest{
		SchemaVersion: LegacyManifestSchema, ID: "apply-test", InterfaceName: "enp2s0",
		OldLANCIDR: "192.168.200.1/24", NewLANCIDR: "192.168.210.1/24",
		OldURL: "https://192.168.200.1:8443", NewURL: "https://192.168.210.1:8443",
		NewDestinationIP: "192.168.210.1",
		CreatedAt:        time.Date(2026, 8, 24, 10, 0, 0, 0, time.UTC).Format(time.RFC3339Nano),
		RollbackDeadline: time.Date(2026, 8, 24, 10, 1, 0, 0, time.UTC).Format(time.RFC3339Nano),
	}
	executor := &statefulBackendExecutor{addresses: map[string]bool{manifest.OldLANCIDR: true}, runtimeFirewall: ruleset.Text}
	return UbuntuBackend{Executor: executor, Paths: paths}, executor, manifest, transactionDirectory
}

func writeTestFile(t *testing.T, filename string, content []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(filename), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filename, content, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filename, 0o600); err != nil {
		t.Fatal(err)
	}
}

type statefulBackendExecutor struct {
	addresses       map[string]bool
	runtimeFirewall string
	hostAddressJSON string
	calls           []platformexec.Request
}

func (executor *statefulBackendExecutor) Run(_ context.Context, request platformexec.Request) (platformexec.Result, error) {
	executor.calls = append(executor.calls, request)
	base := filepath.Base(request.Executable)
	switch base {
	case "ip":
		if len(request.Arguments) >= 5 && request.Arguments[0] == "address" && request.Arguments[1] == "replace" {
			executor.addresses[request.Arguments[2]] = true
			return platformexec.Result{}, nil
		}
		if len(request.Arguments) >= 5 && request.Arguments[0] == "address" && request.Arguments[1] == "del" {
			delete(executor.addresses, request.Arguments[2])
			return platformexec.Result{}, nil
		}
		if len(request.Arguments) == 5 && request.Arguments[0] == "-json" {
			type address struct {
				Family    string `json:"family"`
				Local     string `json:"local"`
				PrefixLen int    `json:"prefixlen"`
			}
			var items []address
			for cidr, present := range executor.addresses {
				if !present {
					continue
				}
				parts := strings.Split(cidr, "/")
				prefix := 0
				_, _ = fmt.Sscanf(parts[1], "%d", &prefix)
				items = append(items, address{Family: "inet", Local: parts[0], PrefixLen: prefix})
			}
			payload, _ := json.Marshal([]any{map[string]any{"addr_info": items}})
			return platformexec.Result{Stdout: string(payload)}, nil
		}
		if len(request.Arguments) == 3 && request.Arguments[0] == "-json" {
			if executor.hostAddressJSON != "" {
				return platformexec.Result{Stdout: executor.hostAddressJSON}, nil
			}
			type address struct {
				Family    string `json:"family"`
				Local     string `json:"local"`
				PrefixLen int    `json:"prefixlen"`
			}
			var items []address
			for cidr, present := range executor.addresses {
				if !present {
					continue
				}
				parts := strings.Split(cidr, "/")
				prefix := 0
				_, _ = fmt.Sscanf(parts[1], "%d", &prefix)
				items = append(items, address{Family: "inet", Local: parts[0], PrefixLen: prefix})
			}
			payload, _ := json.Marshal([]any{map[string]any{"ifname": "enp2s0", "addr_info": items}})
			return platformexec.Result{Stdout: string(payload)}, nil
		}
	case "nft":
		if len(request.Arguments) >= 1 && request.Arguments[0] == "list" {
			return platformexec.Result{Stdout: executor.runtimeFirewall}, nil
		}
		if len(request.Stdin) != 0 && request.Arguments[len(request.Arguments)-1] == "-" {
			if !strings.HasPrefix(string(request.Stdin), "delete table") {
				executor.runtimeFirewall = string(request.Stdin)
			}
			return platformexec.Result{}, nil
		}
		return platformexec.Result{}, nil
	case "dnsmasq", "systemctl", "networkctl":
		return platformexec.Result{}, nil
	}
	return platformexec.Result{}, errors.New("unexpected command")
}

func (executor *statefulBackendExecutor) called(executable string, arguments ...string) bool {
	for _, call := range executor.calls {
		if call.Executable == executable && strings.Join(call.Arguments, "\x00") == strings.Join(arguments, "\x00") {
			return true
		}
	}
	return false
}
