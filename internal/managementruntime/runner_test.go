package managementruntime

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	databasepkg "gateway-vpn/internal/db"
	"gateway-vpn/internal/managementfabric"
	"gateway-vpn/internal/networkapply"
	"gateway-vpn/internal/wgingress"
)

type fakeSource struct {
	status networkapply.ManagementFabricStatus
	err    error
}

func (source *fakeSource) ManagementFabricStatus(context.Context) (networkapply.ManagementFabricStatus, error) {
	return source.status, source.err
}

func TestRunnerPersistsAvailableProjectionAndExpiresItWhenRootDisappears(t *testing.T) {
	ctx, _, repository, linkID, generation := runtimeFixture(t)
	now := time.Date(2026, 8, 30, 16, 0, 0, 0, time.UTC)
	handshake := now.Add(-30 * time.Second).Format(time.RFC3339Nano)
	source := &fakeSource{status: networkapply.ManagementFabricStatus{
		ObservationState: "AVAILABLE", ObservationGeneration: generation,
		Links: []managementfabric.LinkRuntimeObservation{{LinkID: linkID, State: managementfabric.RuntimeLinkReachable, LastHandshakeAt: handshake}},
	}}
	runner := &Runner{Source: source, Repository: repository, Now: func() time.Time { return now }}
	result, err := runner.Reconcile(ctx)
	if err != nil || result.ObservedLinks != 1 || result.ExpiredLinks != 0 {
		t.Fatalf("available Reconcile() = %+v, %v", result, err)
	}
	stored, err := repository.GetLink(ctx, linkID)
	if err != nil || stored.State != managementfabric.RuntimeLinkReachable || stored.LastHandshakeAt != handshake {
		t.Fatalf("stored link = %+v, %v", stored, err)
	}

	source.status = networkapply.ManagementFabricStatus{ObservationState: "UNAVAILABLE", ObservationErrorCode: "MANAGEMENT_LINK_OBSERVATION_FAILED"}
	runner.Now = func() time.Time { return now.Add(managementfabric.RuntimeHandshakeFreshness + time.Minute) }
	result, err = runner.Reconcile(ctx)
	if !errors.Is(err, ErrObservationUnavailable) || result.ExpiredLinks != 1 {
		t.Fatalf("unavailable Reconcile() = %+v, %v", result, err)
	}
	stored, _ = repository.GetLink(ctx, linkID)
	if stored.State != managementfabric.RuntimeLinkStale || stored.LastErrorCode != "HANDSHAKE_OBSERVATION_EXPIRED" {
		t.Fatalf("unavailable source left authoritative runtime = %+v", stored)
	}

	source.status = networkapply.ManagementFabricStatus{ObservationState: "DEFERRED"}
	if _, err := runner.Reconcile(ctx); err != nil {
		t.Fatalf("generation transition should defer without failure: %v", err)
	}
}

func TestRunnerReportsProgressEvenWhenObservationUnavailable(t *testing.T) {
	ctx, _, repository, _, _ := runtimeFixture(t)
	cycles, failures := 0, 0
	runner := &Runner{
		Source: &fakeSource{err: errors.New("private root detail /etc/shadow")}, Repository: repository,
		Now:     func() time.Time { return time.Date(2026, 8, 30, 16, 0, 0, 0, time.UTC) },
		OnCycle: func(Result) { cycles++ }, OnError: func(err error) {
			failures++
			if !errors.Is(err, ErrObservationUnavailable) || strings.Contains(err.Error(), "/etc/shadow") {
				t.Fatalf("observer error was not fixed/redacted: %v", err)
			}
		},
	}
	runner.runCycle(ctx)
	if cycles != 1 || failures != 1 {
		t.Fatalf("cycle/failure callbacks = %d/%d", cycles, failures)
	}
}

func runtimeFixture(t *testing.T) (context.Context, *sql.DB, *managementfabric.Repository, string, int64) {
	t.Helper()
	ctx := context.Background()
	database, err := databasepkg.Open(ctx, databasepkg.OpenOptions{Path: filepath.Join(t.TempDir(), "state.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	if err := databasepkg.Migrate(ctx, database); err != nil {
		t.Fatal(err)
	}
	repository := managementfabric.NewRepository(database, nil)
	if _, err := repository.EnsureLocalSite(ctx, "site:home", "Home"); err != nil {
		t.Fatal(err)
	}
	remote, _ := wgingress.GenerateKeyPair()
	local, _ := wgingress.GenerateKeyPair()
	vps, err := repository.CreateVPS(ctx, managementfabric.CreateVPSInput{
		ID: "vps:a", Name: "VPS", VerifiedFingerprint: strings.Repeat("a", 64), PublicKey: remote.Public,
		AdminAddressPool: "10.81.0.0/24", ResourceAliasPool: "10.96.0.0/16",
	})
	if err != nil {
		t.Fatal(err)
	}
	link, err := repository.CreateLink(ctx, managementfabric.CreateLinkInput{
		ID: "link:a", SiteID: "site:home", VPSID: vps.ID, Enabled: true,
		ManagementSubnet: "10.82.0.0/24", LocalAddress: "10.82.0.2", RemoteAddress: "10.82.0.1",
		LocalPrivateKeySecretRef: "/var/lib/gateway-vpn/secrets/management/link-a.key",
		LocalPublicKey:           local.Public, RemotePublicKey: remote.Public,
		UplinkPolicy: managementfabric.UplinkAuto, PersistentKeepalive: 25,
		Endpoints: []managementfabric.EndpointSpec{{Host: "203.0.113.10", Port: 51821}},
	})
	if err != nil {
		t.Fatal(err)
	}
	var generation int64
	if err := database.QueryRowContext(ctx, `SELECT desired_generation FROM management_fabric_generations WHERE singleton_id=1`).Scan(&generation); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(ctx, `UPDATE management_fabric_generations SET applied_generation=desired_generation,state='APPLIED'`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(ctx, `UPDATE management_links SET applied_route_generation=desired_route_generation,applied_acl_generation=desired_acl_generation,state='CONNECTING' WHERE id=?`, link.ID); err != nil {
		t.Fatal(err)
	}
	return ctx, database, repository, link.ID, generation
}
