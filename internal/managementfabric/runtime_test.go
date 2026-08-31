package managementfabric

import (
	"strings"
	"testing"
	"time"
)

func TestRecordLinkRuntimeObservationsIsCompleteGenerationBoundAndExpires(t *testing.T) {
	ctx, database, repository := managementFixture(t)
	if _, err := repository.EnsureLocalSite(ctx, "site:home", "Home"); err != nil {
		t.Fatal(err)
	}
	vps, err := repository.CreateVPS(ctx, CreateVPSInput{
		ID: "vps:a", Name: "VPS", VerifiedFingerprint: strings.Repeat("a", 64),
		PublicKey: testPublicKey(t), AdminAddressPool: "10.81.0.0/24", ResourceAliasPool: "10.96.0.0/16",
	})
	if err != nil {
		t.Fatal(err)
	}
	link := createTestLink(t, ctx, repository, "link:a", vps, "10.82.0.0/24", "10.82.0.2", "10.82.0.1")
	var generation int64
	if err := database.QueryRowContext(ctx, `SELECT desired_generation FROM management_fabric_generations WHERE singleton_id=1`).Scan(&generation); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(ctx, `
UPDATE management_fabric_generations SET applied_generation=desired_generation,state='APPLIED';
UPDATE management_links SET applied_route_generation=desired_route_generation,
  applied_acl_generation=desired_acl_generation,state='CONNECTING' WHERE id=?`, link.ID); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 30, 16, 0, 0, 0, time.UTC)
	handshake := now.Add(-45 * time.Second).Format(time.RFC3339Nano)
	if err := repository.RecordLinkRuntimeObservations(ctx, generation, []LinkRuntimeObservation{{
		LinkID: link.ID, State: RuntimeLinkReachable, LastHandshakeAt: handshake,
	}}, now); err != nil {
		t.Fatal(err)
	}
	stored, err := repository.GetLink(ctx, link.ID)
	if err != nil || stored.State != RuntimeLinkReachable || stored.LastHandshakeAt != handshake || stored.LastErrorCode != "" {
		t.Fatalf("stored reachable observation = %+v error %v", stored, err)
	}
	if err := repository.RecordLinkRuntimeObservations(ctx, generation, nil, now); err == nil {
		t.Fatal("incomplete runtime observation was accepted")
	}
	if _, err := database.ExecContext(ctx, `UPDATE management_fabric_generations SET desired_generation=desired_generation+1,state='PENDING'`); err != nil {
		t.Fatal(err)
	}
	if err := repository.RecordLinkRuntimeObservations(ctx, generation, []LinkRuntimeObservation{{
		LinkID: link.ID, State: RuntimeLinkConnecting, ErrorCode: "NEVER_CONNECTED",
	}}, now); err == nil {
		t.Fatal("stale generation runtime observation was accepted")
	}
	if _, err := database.ExecContext(ctx, `UPDATE management_fabric_generations SET desired_generation=?,applied_generation=?,state='APPLIED'`, generation, generation); err != nil {
		t.Fatal(err)
	}
	expired, err := repository.ExpireLinkRuntimeObservations(ctx, now.Add(RuntimeHandshakeFreshness+time.Minute))
	if err != nil || expired != 1 {
		t.Fatalf("ExpireLinkRuntimeObservations() = %d, %v", expired, err)
	}
	stored, err = repository.GetLink(ctx, link.ID)
	if err != nil || stored.State != RuntimeLinkStale || stored.LastErrorCode != "HANDSHAKE_OBSERVATION_EXPIRED" || stored.LastHandshakeAt != handshake {
		t.Fatalf("expired runtime observation = %+v error %v", stored, err)
	}
}

func TestRecordLinkRuntimeObservationsRejectsInvalidProjection(t *testing.T) {
	now := time.Date(2026, 8, 30, 16, 0, 0, 0, time.UTC)
	for name, observation := range map[string]LinkRuntimeObservation{
		"unknown error":               {LinkID: "link:a", State: RuntimeLinkDegraded, ErrorCode: "PRIVATE_PATH_/etc/shadow"},
		"reachable without handshake": {LinkID: "link:a", State: RuntimeLinkReachable},
		"future handshake":            {LinkID: "link:a", State: RuntimeLinkReachable, LastHandshakeAt: now.Add(time.Minute).Format(time.RFC3339Nano)},
		"stale marked reachable":      {LinkID: "link:a", State: RuntimeLinkReachable, LastHandshakeAt: now.Add(-10 * time.Minute).Format(time.RFC3339Nano)},
	} {
		t.Run(name, func(t *testing.T) {
			if err := validateLinkRuntimeObservation(observation, now); err == nil {
				t.Fatalf("invalid observation accepted: %+v", observation)
			}
		})
	}
}
