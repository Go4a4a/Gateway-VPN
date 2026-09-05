package main

import (
	"context"
	"encoding/base64"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"gateway-vpn/internal/config"
	"gateway-vpn/internal/db"
	"gateway-vpn/internal/installtopology"
	"gateway-vpn/internal/networkapply"
)

func TestInitialTopologyCheckIsStrictAndReadOnly(t *testing.T) {
	token, err := installtopology.EncodeToken(installtopology.Plan{
		Profile: installtopology.ProfileEthernetHiLink, LANMembers: []string{"enp2s0"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if code := runInitialTopologyCheck([]string{"--token", token}); code != 0 {
		t.Fatalf("runInitialTopologyCheck(valid) = %d", code)
	}
	if code := runInitialTopologyCheck([]string{"--token", token, "--lan-interface", "enp2s0"}); code != 0 {
		t.Fatalf("runInitialTopologyCheck(bound valid) = %d", code)
	}
	if code := runInitialTopologyCheck([]string{"--token", token, "--lan-interface", "enp3s0"}); code != 1 {
		t.Fatalf("runInitialTopologyCheck(bound mismatch) = %d", code)
	}
	bridgeToken, err := installtopology.EncodeToken(installtopology.Plan{
		Profile: installtopology.ProfileEthernetHiLink, LANMembers: []string{"enp3s0", "enp2s0"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if code := runInitialTopologyCheck([]string{"--token", bridgeToken, "--lan-interface", "gateway-vpn-lan", "--lan-members", "enp2s0,enp3s0"}); code != 0 {
		t.Fatalf("runInitialTopologyCheck(bridge valid) = %d", code)
	}
	foreign := base64.RawURLEncoding.EncodeToString([]byte(`{"profile":"ETHERNET_HILINK","lan_members":["enp2s0"],"private_key":"forbidden"}`))
	if code := runInitialTopologyCheck([]string{"--token", foreign}); code != 1 {
		t.Fatalf("runInitialTopologyCheck(foreign) = %d", code)
	}
	if code := runInitialTopologyCheck(nil); code != 2 {
		t.Fatalf("runInitialTopologyCheck(empty) = %d", code)
	}
}

func TestInitialTopologyAutoConfirmRequiresExactRetainedManagementOrigin(t *testing.T) {
	if !initialTopologyAutoConfirmAllowed("https://192.168.200.1:8443", "https://192.168.200.1:8443") {
		t.Fatal("unchanged management origin was not eligible for local installer confirmation")
	}
	for _, candidate := range [][2]string{
		{"https://192.168.200.1:8443", "https://10.90.0.1:8443"},
		{"", ""},
		{"", "https://192.168.200.1:8443"},
	} {
		if initialTopologyAutoConfirmAllowed(candidate[0], candidate[1]) {
			t.Fatalf("management move was eligible for automatic confirmation: %q -> %q", candidate[0], candidate[1])
		}
	}
}

func TestInitialTopologyIndependentConsoleContractRejectsSSHAndBoundsInput(t *testing.T) {
	for _, accepted := range []string{"/dev/console", "/dev/tty1", "/dev/tty63", "/dev/ttyS0", "/dev/ttyAMA1", "/dev/hvc0"} {
		if !isIndependentConsolePath(accepted) {
			t.Errorf("independent console path was rejected: %s", accepted)
		}
	}
	for _, rejected := range []string{"", "/dev/tty", "/dev/tty0", "/dev/tty64", "/dev/pts/0", "/dev/stdin", "/tmp/console", "/dev/ttyUSB0"} {
		if isIndependentConsolePath(rejected) {
			t.Errorf("non-independent console path was accepted: %s", rejected)
		}
	}
	phrase := initialTopologyConsolePhrase("apply-0123456789abcdef")
	line, err := readBoundedConsoleLine(strings.NewReader(phrase + "\r\n"))
	if err != nil || line != phrase {
		t.Fatalf("bounded confirmation line = %q, %v", line, err)
	}
	if _, err := readBoundedConsoleLine(strings.NewReader(strings.Repeat("x", 258) + "\n")); err == nil {
		t.Fatal("oversized console confirmation was accepted")
	}
	if _, err := readBoundedConsoleLine(strings.NewReader(phrase)); err == nil {
		t.Fatal("unterminated console confirmation was accepted")
	}
	line, err = readBoundedConsoleLine(strings.NewReader(" " + phrase + " \n"))
	if err != nil || line == phrase {
		t.Fatalf("non-exact console phrase was normalized: %q, %v", line, err)
	}
}

func TestRequireIndependentLocalConsoleRejectsPipeOrPTY(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux console identity is verified by the Linux fixture")
	}
	if _, err := requireIndependentLocalConsole(os.Stdin); err == nil {
		t.Fatal("pipe or pseudo-terminal stdin was accepted as an independent local console")
	}
}

func TestWaitForExternalTopologyConfirmationObservesDurableTerminalState(t *testing.T) {
	ctx := context.Background()
	database, err := db.Open(ctx, db.OpenOptions{Path: filepath.Join(t.TempDir(), "wait.db")})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if err := db.Migrate(ctx, database); err != nil {
		t.Fatal(err)
	}
	repository := networkapply.NewRepository(database)
	create := func(id string) {
		t.Helper()
		err := repository.Create(ctx, networkapply.Transaction{
			ID: id, State: networkapply.StatePreparing, ConfirmTokenSHA256: strings.Repeat("a", 64),
			ManifestSchema: networkapply.TopologyManifestSchema, OperationKind: networkapply.OperationTopologyProfile,
			CandidateJSON: `{"profile":"ONE_ARM_WIREGUARD"}`, OldURL: "https://192.168.200.1:8443",
			NewURL: "https://10.90.0.1:8443", NewDestinationIP: "10.90.0.1",
			RollbackDeadline: time.Now().UTC().Add(time.Minute).Format(time.RFC3339Nano), TransactionDir: "/run/gateway-vpn-test/" + id,
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	create("apply-external-confirmed")
	if err := repository.Transition(ctx, "apply-external-confirmed", []string{networkapply.StatePreparing}, networkapply.StateConfirmed, ""); err != nil {
		t.Fatal(err)
	}
	if err := waitForExternalTopologyConfirmation(ctx, repository, "apply-external-confirmed", time.Now().Add(time.Second)); err != nil {
		t.Fatalf("confirmed external transaction was not observed: %v", err)
	}
	create("apply-external-rollback")
	if err := repository.Transition(ctx, "apply-external-rollback", []string{networkapply.StatePreparing}, networkapply.StateRolledBack, "UNCONFIRMED"); err != nil {
		t.Fatal(err)
	}
	if err := waitForExternalTopologyConfirmation(ctx, repository, "apply-external-rollback", time.Now().Add(time.Second)); err == nil || !strings.Contains(err.Error(), "rolled back") {
		t.Fatalf("rolled-back external transaction result = %v", err)
	}
}

func TestTopologyStateReadsConvergedRuntimeWithoutMutation(t *testing.T) {
	ctx := context.Background()
	database, err := db.Open(ctx, db.OpenOptions{Path: filepath.Join(t.TempDir(), "state.db")})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if err := db.Migrate(ctx, database); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(ctx, `
UPDATE topology_profile_state
SET active_profile='ONE_ARM_WIREGUARD',desired_generation=2,applied_generation=2,state='ACTIVE'
WHERE singleton_id=1`); err != nil {
		t.Fatal(err)
	}
	configuration := config.Default()
	configuration.Network.LANInterface = "wg-ingress"
	configuration.Network.LANAddress = "10.90.0.1/24"
	configuration.Network.LANServiceMode = "disabled"
	state, err := readConvergedTopologyState(ctx, database, configuration)
	if err != nil {
		t.Fatal(err)
	}
	if state.Profile != "ONE_ARM_WIREGUARD" || state.DesiredGeneration != 2 || state.AppliedGeneration != 2 || state.State != "ACTIVE" || state.LANInterface != "wg-ingress" || state.LANAddress != "10.90.0.1/24" || state.DHCPDNS {
		t.Fatalf("topology state = %+v", state)
	}
	var desired, applied int64
	if err := database.QueryRowContext(ctx, `SELECT desired_generation,applied_generation FROM topology_profile_state WHERE singleton_id=1`).Scan(&desired, &applied); err != nil || desired != 2 || applied != 2 {
		t.Fatalf("topology state changed = %d/%d, %v", desired, applied, err)
	}
	if _, err := database.ExecContext(ctx, `UPDATE topology_profile_state SET state='APPLYING' WHERE singleton_id=1`); err != nil {
		t.Fatal(err)
	}
	if _, err := readConvergedTopologyState(ctx, database, configuration); err == nil {
		t.Fatal("non-converged topology was accepted")
	}
}

func TestTopologyStateProfileAllowlist(t *testing.T) {
	for _, profile := range []string{"ETHERNET_HILINK", "ETHERNET_ETHERNET", "ONE_ARM_WIREGUARD", "MIXED"} {
		if !validTopologyStateProfile(profile) {
			t.Errorf("valid topology profile rejected: %s", profile)
		}
	}
	for _, profile := range []string{"", "UNKNOWN", "ethernet_hilink"} {
		if validTopologyStateProfile(profile) {
			t.Errorf("invalid topology profile accepted: %s", profile)
		}
	}
}
