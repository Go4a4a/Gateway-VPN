package deploy

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"gateway-vpn/internal/distribution"
)

type fakeRemoteExecutor struct {
	now               time.Time
	commands          []string
	failContains      string
	handshakeReady    bool
	internetPathReady bool
}

func (executor *fakeRemoteExecutor) Run(_ context.Context, host Host, command string) (RemoteResult, error) {
	executor.commands = append(executor.commands, host.Destination+"\x00"+command)
	if executor.failContains != "" && strings.Contains(command, executor.failContains) {
		return RemoteResult{ExitCode: 1}, errors.New("synthetic remote failure")
	}
	switch command {
	case gatewayInspectKeyCommand:
		return jsonRemote(deployKeyResponse{State: "UNCONFIGURED"}), nil
	case gatewayPrepareKeyCommand:
		return jsonRemote(deployKeyResponse{State: "PENDING", PublicKey: testPublicKey(4)}), nil
	case vpsInstallReportCommand:
		return jsonRemote(vpsInstallReport{
			Version: "1.2.0", Profile: "ubuntu-24.04", PublicEndpoint: "1.1.1.1:51821",
			Interface: "wg-mgmt", VPSAddress: "10.80.0.1/24", GatewayAddress: "10.80.0.2/32",
			AdminAddress: "10.80.0.10/32", VPSPublicKey: testPublicKey(5), State: StateInstalledNotReady,
		}), nil
	case gatewayHandshakeCommand:
		if !executor.handshakeReady {
			return RemoteResult{ExitCode: 1}, errors.New("interface not ready")
		}
		return RemoteResult{Stdout: []byte(testPublicKey(5) + "\t" + strconv.FormatInt(executor.now.Unix()-5, 10) + "\n")}, nil
	case gatewayRuntimeStatusCommand:
		state := "BLOCKED"
		path := "PATH_BLOCKED"
		if executor.internetPathReady {
			state = "ACTIVE"
			path = "PATH_ACTIVE"
		}
		return jsonRemote(map[string]any{"runtime": map[string]any{"GatewayState": state, "PathState": path, "ActiveModemID": "modem-a"}, "paths": []any{}}), nil
	}
	if strings.Contains(command, "deploy-wireguard-finalize") {
		return jsonRemote(deployKeyResponse{State: "CONFIGURED", PublicKey: testPublicKey(4)}), nil
	}
	return RemoteResult{ExitCode: 0}, nil
}

func TestOrchestratorUsesExistingGatewayPublicKeyForInitialResumePreflight(t *testing.T) {
	now := time.Now().UTC()
	executor := &resumeRemoteExecutor{fakeRemoteExecutor: fakeRemoteExecutor{now: now, handshakeReady: true, internetPathReady: true}}
	request := validDeployRequest(t)
	report, err := (Orchestrator{Executor: executor, Now: func() time.Time { return now }, Sleep: func(context.Context, time.Duration) error { return nil }}).Run(context.Background(), request)
	if err != nil || report.State != StateReady {
		t.Fatalf("resume failed: report=%+v err=%v", report, err)
	}
	for _, command := range executor.commands {
		if strings.Contains(command, "install-vps") && !strings.Contains(command, "--apply") && !strings.Contains(command, testPublicKey(4)) {
			t.Fatal("initial VPS resume preflight did not use the existing Gateway public key")
		}
	}
}

type resumeRemoteExecutor struct{ fakeRemoteExecutor }

func (executor *resumeRemoteExecutor) Run(ctx context.Context, host Host, command string) (RemoteResult, error) {
	if command == gatewayInspectKeyCommand {
		executor.commands = append(executor.commands, host.Destination+"\x00"+command)
		return jsonRemote(deployKeyResponse{State: "CONFIGURED", PublicKey: testPublicKey(4)}), nil
	}
	return executor.fakeRemoteExecutor.Run(ctx, host, command)
}

func jsonRemote(value any) RemoteResult {
	content, _ := json.Marshal(value)
	return RemoteResult{Stdout: append(content, '\n'), ExitCode: 0}
}

func TestOrchestratorReachesReadyWithoutTransportingPrivateKeys(t *testing.T) {
	now := time.Date(2026, 8, 25, 10, 0, 0, 0, time.UTC)
	executor := &fakeRemoteExecutor{now: now, handshakeReady: true, internetPathReady: true}
	request := validDeployRequest(t)
	report, err := (Orchestrator{
		Executor: executor, Now: func() time.Time { return now },
		Sleep: func(context.Context, time.Duration) error { return nil },
	}).Run(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if report.State != StateReady || !report.WireGuardConfigured || !report.WireGuardHandshake || !report.InternetPathActive || report.GatewayInstallation != "APPLIED" || report.VPSInstallation != "APPLIED" {
		t.Fatalf("unexpected report: %+v", report)
	}
	joined := strings.Join(executor.commands, "\n")
	for _, required := range []string{"install-gateway", "install-vps", "sudo -n", "deploy-wireguard-prepare", "deploy-wireguard-finalize", "--apply"} {
		if !strings.Contains(joined, required) {
			t.Errorf("workflow missing %q", required)
		}
	}
	if strings.Contains(strings.ToLower(joined), "private-key") {
		t.Fatal("workflow transported a private-key argument")
	}
	encoded, err := json.Marshal(report)
	if err != nil || strings.Contains(string(encoded), testPublicKey(5)) {
		t.Fatal("redacted deployment report exposed the raw VPS public key")
	}
	firstApply := -1
	rolePreflights := 0
	for index, command := range executor.commands {
		if strings.Contains(command, "install-gateway") || strings.Contains(command, "install-vps") {
			if strings.Contains(command, "--apply") && firstApply < 0 {
				firstApply = index
			}
			if !strings.Contains(command, "--apply") && firstApply < 0 {
				rolePreflights++
			}
		}
	}
	if rolePreflights != 2 || firstApply < 0 {
		t.Fatalf("both role preflights did not precede mutation: calls=%d first_apply=%d", rolePreflights, firstApply)
	}
}

func TestGatewayBaseReadinessIncludesBoundedWatchdog(t *testing.T) {
	command := gatewayBaseReadinessCommand("192.168.200.1/24")
	for _, required := range []string{
		"systemctl is-active --quiet gateway-vpn-watchdog.service",
		"/run/gateway-vpn-watchdog/status.json",
		"/run/gateway-vpn-watchdog/control.json",
	} {
		if !strings.Contains(command, required) {
			t.Errorf("Gateway readiness command missing %q", required)
		}
	}
}

func TestOrchestratorRunsBothRolePreflightsBeforeReturningFailure(t *testing.T) {
	executor := &fakeRemoteExecutor{now: time.Now(), failContains: "install-gateway"}
	report, err := (Orchestrator{Executor: executor, Sleep: func(context.Context, time.Duration) error { return nil }}).Run(context.Background(), validDeployRequest(t))
	if err == nil || report.State != StateFailed || report.FailurePhase != "GATEWAY_ROLE_PREFLIGHT" {
		t.Fatalf("unexpected failure: report=%+v err=%v", report, err)
	}
	roleCalls := 0
	for _, command := range executor.commands {
		if strings.Contains(command, "install-gateway") || strings.Contains(command, "install-vps") {
			roleCalls++
			if strings.Contains(command, "--apply") {
				t.Fatal("mutation started after failed preflight")
			}
		}
	}
	if roleCalls != 2 {
		t.Fatalf("expected both role preflights, got %d", roleCalls)
	}
}

func TestOrchestratorReportsInstalledNotReadyWithoutFalseSuccess(t *testing.T) {
	executor := &fakeRemoteExecutor{now: time.Now()}
	request := validDeployRequest(t)
	request.ReadinessAttempts = 2
	report, err := (Orchestrator{Executor: executor, Sleep: func(context.Context, time.Duration) error { return nil }}).Run(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if report.State != StateInstalledNotReady || report.WireGuardHandshake || report.InternetPathActive || len(report.DiagnosticCodes) != 2 {
		t.Fatalf("unexpected readiness report: %+v", report)
	}
}

func TestOrchestratorRejectsDifferentUsersOnTheSameSSHHost(t *testing.T) {
	request := validDeployRequest(t)
	request.VPS.Destination = "root@gateway.example"
	report, err := (Orchestrator{Executor: &fakeRemoteExecutor{}}).Run(context.Background(), request)
	if err == nil || report.FailurePhase != "LOCAL_VALIDATION" {
		t.Fatalf("same physical SSH host accepted: report=%+v err=%v", report, err)
	}
}

func TestOrchestratorLeavesGatewayDiagnosableWhenVPSApplyFails(t *testing.T) {
	executor := &fakeRemoteExecutor{now: time.Now(), failContains: "install-vps"}
	request := validDeployRequest(t)
	// Fail only apply, not preflight.
	executor.failContains = "--gateway-public-key " + testPublicKey(4) + " --admin-public-key " + request.AdminPublicKey + " --install-dependencies --apply"
	report, err := (Orchestrator{Executor: executor, Sleep: func(context.Context, time.Duration) error { return nil }}).Run(context.Background(), request)
	if err == nil || report.GatewayInstallation != "APPLIED" || report.VPSInstallation != "NOT_RUN" || report.FailurePhase != "VPS_INSTALL" {
		t.Fatalf("unexpected partial-state report: %+v err=%v", report, err)
	}
}

func validDeployRequest(t *testing.T) Request {
	t.Helper()
	directory := t.TempDir()
	knownHosts := filepath.Join(directory, "known_hosts")
	identity := filepath.Join(directory, "id_ed25519")
	if err := os.WriteFile(knownHosts, []byte("gateway ssh-ed25519 AAAA\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(identity, []byte("synthetic-private-identity\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	manifest := distribution.Manifest{
		FormatVersion: distribution.ChannelFormatVersion, Channel: "stable", ReleaseVersion: "1.2.0",
		GeneratedAt: "2026-08-25T00:00:00Z", SourceCommit: strings.Repeat("a", 40), SignerKeySHA256: strings.Repeat("f", 64),
		Artifacts: []distribution.Artifact{
			{Role: distribution.RoleBootstrap, OS: "linux", Arch: "amd64", Filename: "gateway-vpn-bootstrap-1.2.0-linux-amd64", SHA256: strings.Repeat("1", 64), Bytes: 100, MediaType: "application/octet-stream"},
			{Role: distribution.RoleDeploy, OS: "linux", Arch: "amd64", Filename: "gateway-vpn-deploy-1.2.0-linux-amd64", SHA256: strings.Repeat("2", 64), Bytes: 100, MediaType: "application/octet-stream"},
			{Role: distribution.RoleGateway, OS: "linux", Arch: "amd64", Filename: "gateway-vpn-gateway-1.2.0-linux-amd64.tar.gz", SHA256: strings.Repeat("3", 64), Bytes: 100, MediaType: "application/gzip"},
			{Role: distribution.RoleVPS, OS: "linux", Arch: "amd64", Filename: "gateway-vpn-vps-1.2.0-linux-amd64.tar.gz", SHA256: strings.Repeat("4", 64), Bytes: 100, MediaType: "application/gzip"},
		},
	}
	distribution.SortArtifacts(manifest.Artifacts)
	return Request{
		Manifest: manifest, ManifestSHA256: strings.Repeat("e", 64), SignerKeySHA256: manifest.SignerKeySHA256,
		Repository: "owner/gateway-vpn", ReleaseTag: "v1.2.0",
		Gateway:      Host{Destination: "operator@gateway.example", Port: 22, Identity: identity, KnownHosts: knownHosts},
		VPS:          Host{Destination: "root@vps.example", Port: 22, Identity: identity, KnownHosts: knownHosts},
		LANInterface: "enp2s0", LANAddress: "192.168.200.1/24", EnableDHCP: true,
		PublicEndpoint: "1.1.1.1:51821", AdminPublicKey: testPublicKey(6),
		InstallDependencies: true, ReadinessAttempts: 1, ReadinessInterval: 0,
	}
}

func testPublicKey(seed byte) string {
	return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{seed}, 32))
}
