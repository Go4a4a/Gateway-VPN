//go:build linux

package vpsfabric

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"gateway-vpn/internal/platformexec"
	"gateway-vpn/internal/vpsagent"
	"gateway-vpn/internal/wgingress"
)

type kernelRollbackExecutor struct {
	configuration           string
	failCandidateValidation bool
	inner                   platformexec.OSExecutor
}

func (executor *kernelRollbackExecutor) Run(ctx context.Context, request platformexec.Request) (platformexec.Result, error) {
	command := filepath.Base(request.Executable)
	arguments := strings.Join(request.Arguments, " ")
	if command == "systemctl" && arguments == "restart wg-quick@wg-mgmt.service" {
		if output, err := exec.CommandContext(ctx, "/usr/bin/wg-quick", "down", executor.configuration).CombinedOutput(); err != nil {
			return platformexec.Result{Stderr: string(output)}, fmt.Errorf("test wg-quick down: %w", err)
		}
		if output, err := exec.CommandContext(ctx, "/usr/bin/wg-quick", "up", executor.configuration).CombinedOutput(); err != nil {
			return platformexec.Result{Stderr: string(output)}, fmt.Errorf("test wg-quick up: %w", err)
		}
		return platformexec.Result{}, nil
	}
	if command == "wg" && arguments == "show wg-mgmt listen-port" && executor.failCandidateValidation {
		executor.failCandidateValidation = false
		return platformexec.Result{}, errors.New("injected post-route runtime validation failure")
	}
	return executor.inner.Run(ctx, request)
}

func TestVPSFabricKernelRollbackRestoresExactPreviousProjection(t *testing.T) {
	if os.Getenv(fabricKernelIntegrationEnvironment) != "1" {
		t.Skip("set GATEWAY_VPN_VPS_FABRIC_KERNEL_INTEGRATION=1 inside a disposable privileged Linux host")
	}
	requireKernelCommands(t, "/usr/sbin/ip", "/usr/bin/wg", "/usr/bin/wg-quick", "/usr/sbin/nft")
	ctx := context.Background()
	root := t.TempDir()
	stateRoot := filepath.Join(root, "state")
	transactionRoot := filepath.Join(root, "fabric")
	keyRoot := filepath.Join(root, "secrets", "wireguard")
	for _, directory := range []string{stateRoot, transactionRoot, keyRoot} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	database, err := vpsagent.Open(ctx, filepath.Join(stateRoot, "vps-agent.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	hub, _ := wgingress.GenerateKeyPair()
	gateway, _ := wgingress.GenerateKeyPair()
	admin, _ := wgingress.GenerateKeyPair()
	if _, err := vpsagent.InitializeIdentity(ctx, database, vpsagent.IdentityInput{
		VPSID: "vps:kernel-rollback", DisplayName: "Kernel rollback", IdentityFingerprint: strings.Repeat("b", 64), PublicKey: hub.Public,
		PrivateKeySecretRef: "/var/lib/gateway-vpn-vps/agent/secrets/wireguard/server.key", UpdateIdentityRef: "/var/lib/gateway-vpn-vps/agent/secrets/update/identity.key",
	}, time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)); err != nil {
		t.Fatal(err)
	}
	repository := vpsagent.HubRepository{Database: database, Now: func() time.Time { return time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC) }}
	if _, err := repository.AdoptLegacyInstallerPeers(ctx, vpsagent.LegacyAdoptionInput{GatewayPublicKey: gateway.Public, AdminPublicKey: admin.Public, Endpoint: "127.0.0.1:51821"}); err != nil {
		t.Fatal(err)
	}
	previousPlan, err := repository.RenderHostPlan(ctx)
	if err != nil {
		t.Fatal(err)
	}
	previousWireGuard, err := RenderWireGuard(previousPlan, hub.Private)
	if err != nil {
		t.Fatal(err)
	}
	previousFirewall, err := RenderFirewall(previousPlan)
	if err != nil {
		t.Fatal(err)
	}
	wireGuardPath := filepath.Join(root, "wg-mgmt.conf")
	firewallPath := filepath.Join(root, "firewall.nft")
	privateKeyPath := filepath.Join(keyRoot, "server.key")
	for path, item := range map[string]struct {
		content []byte
		mode    os.FileMode
	}{
		wireGuardPath:  {content: previousWireGuard, mode: 0o600},
		firewallPath:   {content: previousFirewall, mode: 0o640},
		privateKeyPath: {content: []byte(hub.Private + "\n"), mode: 0o600},
	} {
		if err := os.WriteFile(path, item.content, item.mode); err != nil {
			t.Fatal(err)
		}
	}
	if output, err := exec.Command("/usr/bin/wg-quick", "up", wireGuardPath).CombinedOutput(); err != nil {
		t.Fatalf("bring up baseline wg-mgmt: %v: %s", err, output)
	}
	t.Cleanup(func() { _, _ = exec.Command("/usr/bin/wg-quick", "down", wireGuardPath).CombinedOutput() })
	if output, err := nftInput(previousFirewall); err != nil {
		t.Fatalf("load baseline owned firewall: %v: %s", err, output)
	}
	t.Cleanup(func() {
		_, _ = nftInput([]byte("delete table inet gateway_vpn_vps\ndelete table inet ufw_rollback_gate\ndelete table inet docker_rollback_gate\ndelete table inet amnezia_rollback_gate\n"))
	})
	previousRoutes, err := routeDestinations(previousPlan)
	if err != nil {
		t.Fatal(err)
	}
	for _, route := range previousRoutes {
		kernelCommand(t, "/usr/sbin/ip", "-4", "route", "replace", route, "dev", "wg-mgmt", "protocol", "186")
	}
	foreign := []byte(`table inet ufw_rollback_gate {
    chain input {
        counter accept
    }
}
table inet docker_rollback_gate {
    chain forward {
        counter accept
    }
}
table inet amnezia_rollback_gate {
    chain vpn {
        counter accept
    }
}
`)
	if output, err := nftInput(foreign); err != nil {
		t.Fatalf("create rollback foreign fixtures: %v: %s", err, output)
	}
	foreignBefore := snapshotForeignTables(t, "ufw_rollback_gate", "docker_rollback_gate", "amnezia_rollback_gate")

	executor := &kernelRollbackExecutor{configuration: wireGuardPath}
	applier := &Applier{Repository: repository, Executor: executor, Paths: Paths{
		TransactionRoot: transactionRoot, WireGuardConfig: wireGuardPath, FirewallConfig: firewallPath, PrivateKey: privateKeyPath,
		IP: "/usr/sbin/ip", NFT: "/usr/sbin/nft", WG: "/usr/bin/wg", Systemctl: "/usr/bin/systemctl",
	}}
	if err := applier.Apply(ctx); err != nil {
		t.Fatalf("seed baseline receipt through real kernel: %v", err)
	}
	previousWireGuard, _ = os.ReadFile(wireGuardPath)
	previousFirewall, _ = os.ReadFile(firewallPath)
	receipt, exists, err := applier.readReceipt()
	if err != nil || !exists || receipt.Generation != previousPlan.Generation {
		t.Fatalf("baseline receipt generation=%d exists=%t err=%v", receipt.Generation, exists, err)
	}

	secondAdmin, _ := wgingress.GenerateKeyPair()
	if _, err := repository.CreateAdmin(ctx, vpsagent.AdminCreateInput{Name: "Rollback admin", PublicKey: secondAdmin.Public, AssignedAddress: "10.81.0.11", KeyMode: "EXTERNAL"}); err != nil {
		t.Fatal(err)
	}
	targetPlan, err := repository.RenderHostPlan(ctx)
	if err != nil || targetPlan.Generation <= previousPlan.Generation {
		t.Fatalf("target generation did not advance: %d -> %d err=%v", previousPlan.Generation, targetPlan.Generation, err)
	}
	executor.failCandidateValidation = true
	applyErr := applier.Apply(ctx)
	if applyErr == nil || !strings.Contains(applyErr.Error(), "safely rolled back") {
		t.Fatalf("injected kernel apply failure was not safely rolled back: %v", applyErr)
	}

	currentWireGuard, _ := os.ReadFile(wireGuardPath)
	currentFirewall, _ := os.ReadFile(firewallPath)
	if !equalBytes(currentWireGuard, previousWireGuard) || !equalBytes(currentFirewall, previousFirewall) {
		t.Fatal("persistent VPS fabric files differ after kernel rollback")
	}
	actualPeersOutput, err := exec.Command("/usr/bin/wg", "show", "wg-mgmt", "peers").CombinedOutput()
	if err != nil {
		t.Fatal(err)
	}
	actualPeers := strings.Fields(string(actualPeersOutput))
	expectedPeers := make([]string, 0, len(previousPlan.Peers))
	for _, peer := range previousPlan.Peers {
		expectedPeers = append(expectedPeers, peer.PublicKey)
	}
	sort.Strings(actualPeers)
	sort.Strings(expectedPeers)
	if strings.Join(actualPeers, "\n") != strings.Join(expectedPeers, "\n") {
		t.Fatalf("WireGuard peers were not rolled back: got=%v want=%v", actualPeers, expectedPeers)
	}
	actualRoutes, err := applier.readOwnedRoutes(ctx)
	if err != nil || !equalStrings(actualRoutes, previousRoutes) {
		t.Fatalf("owned routes were not rolled back: got=%v want=%v err=%v", actualRoutes, previousRoutes, err)
	}
	actualFirewall, err := exec.Command("/usr/sbin/nft", "list", "table", "inet", "gateway_vpn_vps").CombinedOutput()
	previousMarker := "gateway-vpn fabric generation " + fmt.Sprint(previousPlan.Generation) + " plan " + planDigest(previousPlan)
	targetMarker := "gateway-vpn fabric generation " + fmt.Sprint(targetPlan.Generation) + " plan " + planDigest(targetPlan)
	if err != nil || !strings.Contains(string(actualFirewall), previousMarker) || strings.Contains(string(actualFirewall), targetMarker) {
		t.Fatalf("owned firewall was not rolled back: %v: %s", err, actualFirewall)
	}
	desired, applied, err := repository.FabricGenerations(ctx)
	if err != nil || desired != targetPlan.Generation || applied != previousPlan.Generation {
		t.Fatalf("database generations after rollback desired=%d applied=%d err=%v", desired, applied, err)
	}
	receipt, exists, err = applier.readReceipt()
	if err != nil || !exists || receipt.Generation != previousPlan.Generation || existsFile(applier.journalPath()) {
		t.Fatalf("receipt/journal after rollback generation=%d exists=%t journal=%t err=%v", receipt.Generation, exists, existsFile(applier.journalPath()), err)
	}
	needed, reason, err := applier.NeedsApply(ctx)
	if err != nil || !needed || reason != "DESIRED_GENERATION_PENDING" {
		t.Fatalf("watchdog state after rollback needed=%t reason=%s err=%v", needed, reason, err)
	}
	assertForeignTables(t, foreignBefore)
}

func equalBytes(left, right []byte) bool { return string(left) == string(right) }

func existsFile(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
