package pathmatrix

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"path/filepath"
	"testing"
	"time"

	databasepkg "gateway-vpn/internal/db"
	"gateway-vpn/internal/modem"
	"gateway-vpn/internal/store"
	"gateway-vpn/internal/subscription"
)

func TestReconcileBuildsCanonicalMatrixInPriorityOrder(t *testing.T) {
	ctx, database := migratedDatabase(t)
	modems := seedModems(t, ctx, database, "modem-a", "modem-b")
	subscriptions := seedSubscriptions(t, ctx, database, "sub-a", "sub-b")
	if err := modems.ReorderEnabled(ctx, []string{"modem-b", "modem-a"}); err != nil {
		t.Fatalf("reorder modems: %v", err)
	}
	if err := subscriptions.ReorderEnabled(ctx, []string{"sub-b", "sub-a"}); err != nil {
		t.Fatalf("reorder subscriptions: %v", err)
	}
	if _, err := database.ExecContext(ctx, "UPDATE modems SET state='MODEM_READY'"); err != nil {
		t.Fatalf("mark modems ready: %v", err)
	}

	repository := NewRepository(database)
	if err := repository.ReconcileCells(ctx); err != nil {
		t.Fatalf("ReconcileCells() error = %v", err)
	}
	cells, err := repository.List(ctx)
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if len(cells) != 4 {
		t.Fatalf("cell count = %d, want 4", len(cells))
	}
	want := [][2]string{{"modem-b", "sub-b"}, {"modem-b", "sub-a"}, {"modem-a", "sub-b"}, {"modem-a", "sub-a"}}
	for index, expected := range want {
		if cells[index].ModemID != expected[0] || cells[index].SubscriptionID != expected[1] || cells[index].State != StateUntested {
			t.Errorf("cell[%d] = %s/%s/%s, want %s/%s/%s", index, cells[index].ModemID, cells[index].SubscriptionID, cells[index].State, expected[0], expected[1], StateUntested)
		}
	}
}

func TestGenerationChangeRejectsStaleProbeResult(t *testing.T) {
	ctx, database := migratedDatabase(t)
	seedModems(t, ctx, database, "modem-a", "modem-b")
	seedSubscriptions(t, ctx, database, "sub-a", "sub-b")
	if _, err := database.ExecContext(ctx, "UPDATE modems SET state='MODEM_READY'"); err != nil {
		t.Fatalf("mark modems ready: %v", err)
	}
	seedNode(t, ctx, database, "sub-a", "node-a")

	repository := NewRepository(database)
	if err := repository.ReconcileCells(ctx); err != nil {
		t.Fatalf("ReconcileCells() error = %v", err)
	}
	cell, err := repository.Get(ctx, "modem-a", "sub-a")
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	checkedAt := time.Now().UTC()
	update := ResultUpdate{
		PathID:                   cell.ID,
		ExpectedPolicyGeneration: cell.PolicyGeneration,
		ExpectedRouteGeneration:  cell.RouteGeneration,
		State:                    StateQualified,
		TransportState:           "PASSED",
		SelectedNodeID:           "node-a",
		CandidateNodes:           2,
		QualifiedNodes:           1,
		RequiredTargetsPassed:    2,
		RequiredTargetsTotal:     2,
		LatencyMS:                123,
		LastCheckedAt:            checkedAt,
		ExpiresAt:                checkedAt.Add(15 * time.Minute),
	}
	if err := repository.UpdateResult(ctx, update); err != nil {
		t.Fatalf("UpdateResult() error = %v", err)
	}

	if err := repository.BumpRouteGeneration(ctx, "modem-a"); err != nil {
		t.Fatalf("BumpRouteGeneration() error = %v", err)
	}
	staleCell, err := repository.Get(ctx, "modem-a", "sub-a")
	if err != nil {
		t.Fatalf("Get(after bump) error = %v", err)
	}
	if staleCell.State != StateStale || staleCell.RouteGeneration != cell.RouteGeneration+1 || staleCell.SelectedNodeID != "" {
		t.Fatalf("cell after route bump = %+v", staleCell)
	}
	if err := repository.UpdateResult(ctx, update); !errors.Is(err, store.ErrStaleGeneration) {
		t.Fatalf("old UpdateResult() error = %v, want ErrStaleGeneration", err)
	}

	otherCell, err := repository.Get(ctx, "modem-b", "sub-a")
	if err != nil {
		t.Fatalf("Get(other modem) error = %v", err)
	}
	if otherCell.RouteGeneration != 0 || otherCell.State != StateUntested {
		t.Fatalf("other modem cell changed: %+v", otherCell)
	}
}

func TestPolicyInvalidationAndOfflineAreMatrixScoped(t *testing.T) {
	ctx, database := migratedDatabase(t)
	seedModems(t, ctx, database, "modem-a", "modem-b")
	seedSubscriptions(t, ctx, database, "sub-a", "sub-b")
	if _, err := database.ExecContext(ctx, "UPDATE modems SET state='MODEM_READY'"); err != nil {
		t.Fatalf("mark modems ready: %v", err)
	}
	repository := NewRepository(database)
	if err := repository.ReconcileCells(ctx); err != nil {
		t.Fatalf("ReconcileCells() error = %v", err)
	}
	generation, err := repository.BumpPolicyGeneration(ctx)
	if err != nil {
		t.Fatalf("BumpPolicyGeneration() error = %v", err)
	}
	if generation != 1 {
		t.Fatalf("policy generation = %d, want 1", generation)
	}
	if err := repository.MarkModemOffline(ctx, "modem-a"); err != nil {
		t.Fatalf("MarkModemOffline() error = %v", err)
	}
	cells, err := repository.List(ctx)
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	for _, cell := range cells {
		if cell.PolicyGeneration != 1 {
			t.Errorf("cell %s policy generation = %d, want 1", cell.ID, cell.PolicyGeneration)
		}
		if cell.ModemID == "modem-a" && cell.State != StateModemOffline {
			t.Errorf("offline modem cell %s state = %s", cell.ID, cell.State)
		}
		if cell.ModemID == "modem-b" && cell.State != StateStale {
			t.Errorf("other modem cell %s state = %s, want STALE", cell.ID, cell.State)
		}
	}
}

func TestReconcileUsesCurrentPolicyGenerationForNewCells(t *testing.T) {
	ctx, database := migratedDatabase(t)
	seedModems(t, ctx, database, "modem-a")
	seedSubscriptions(t, ctx, database, "sub-a")
	if _, err := database.ExecContext(ctx, "UPDATE modems SET state='MODEM_READY'"); err != nil {
		t.Fatal(err)
	}
	repository := NewRepository(database)
	if generation, err := repository.BumpPolicyGeneration(ctx); err != nil || generation != 1 {
		t.Fatalf("BumpPolicyGeneration() = %d, %v", generation, err)
	}
	if err := repository.ReconcileCells(ctx); err != nil {
		t.Fatalf("ReconcileCells() error = %v", err)
	}
	cell, err := repository.Get(ctx, "modem-a", "sub-a")
	if err != nil || cell.PolicyGeneration != 1 {
		t.Fatalf("new cell policy generation = %+v, %v", cell, err)
	}
}

func TestQualifiedResultRequiresCompleteEvidence(t *testing.T) {
	repository := NewRepository(nil)
	err := repository.UpdateResult(context.Background(), ResultUpdate{
		PathID:         "path",
		State:          StateQualified,
		TransportState: "PASSED",
		CandidateNodes: 1,
		QualifiedNodes: 1,
	})
	if err == nil {
		t.Fatal("UpdateResult(incomplete qualified) error = nil")
	}
}

func TestReconcileDisabledSubscriptionOverridesQualifiedCell(t *testing.T) {
	ctx, database := migratedDatabase(t)
	seedModems(t, ctx, database, "modem-a")
	seedSubscriptions(t, ctx, database, "sub-a")
	if _, err := database.ExecContext(ctx, "UPDATE modems SET state='MODEM_READY'"); err != nil {
		t.Fatalf("mark modem ready: %v", err)
	}
	seedNode(t, ctx, database, "sub-a", "node-a")
	repository := NewRepository(database)
	if err := repository.ReconcileCells(ctx); err != nil {
		t.Fatalf("ReconcileCells() error = %v", err)
	}
	cell, err := repository.Get(ctx, "modem-a", "sub-a")
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	now := time.Now().UTC()
	if err := repository.UpdateResult(ctx, ResultUpdate{
		PathID:                   cell.ID,
		ExpectedPolicyGeneration: 0,
		ExpectedRouteGeneration:  0,
		State:                    StateQualified,
		TransportState:           "PASSED",
		SelectedNodeID:           "node-a",
		CandidateNodes:           1,
		QualifiedNodes:           1,
		RequiredTargetsPassed:    1,
		RequiredTargetsTotal:     1,
		LatencyMS:                50,
		LastCheckedAt:            now,
		ExpiresAt:                now.Add(time.Minute),
	}); err != nil {
		t.Fatalf("UpdateResult() error = %v", err)
	}
	if _, err := database.ExecContext(ctx, "UPDATE subscriptions SET enabled=0 WHERE id='sub-a'"); err != nil {
		t.Fatalf("disable subscription: %v", err)
	}
	if err := repository.ReconcileCells(ctx); err != nil {
		t.Fatalf("ReconcileCells(disabled) error = %v", err)
	}
	disabled, err := repository.Get(ctx, "modem-a", "sub-a")
	if err != nil {
		t.Fatalf("Get(disabled) error = %v", err)
	}
	if disabled.State != StateSubscriptionDisabled || disabled.SelectedNodeID != "" || disabled.QualifiedNodes != 0 {
		t.Fatalf("disabled cell = %+v", disabled)
	}
	if _, err := database.ExecContext(ctx, "UPDATE subscriptions SET enabled=1 WHERE id='sub-a'"); err != nil {
		t.Fatalf("enable subscription: %v", err)
	}
	if err := repository.ReconcileCells(ctx); err != nil {
		t.Fatalf("ReconcileCells(enabled) error = %v", err)
	}
	reenabled, err := repository.Get(ctx, "modem-a", "sub-a")
	if err != nil {
		t.Fatalf("Get(re-enabled) error = %v", err)
	}
	if reenabled.State != StateUntested {
		t.Fatalf("re-enabled cell state = %s, want UNTESTED", reenabled.State)
	}
}

func migratedDatabase(t *testing.T) (context.Context, *sql.DB) {
	t.Helper()
	ctx := context.Background()
	database, err := databasepkg.Open(ctx, databasepkg.OpenOptions{Path: filepath.Join(t.TempDir(), "state.db")})
	if err != nil {
		t.Fatalf("db.Open() error = %v", err)
	}
	t.Cleanup(func() { database.Close() })
	if err := databasepkg.Migrate(ctx, database); err != nil {
		t.Fatalf("db.Migrate() error = %v", err)
	}
	return ctx, database
}

func seedModems(t *testing.T, ctx context.Context, database *sql.DB, ids ...string) *modem.Repository {
	t.Helper()
	repository := modem.NewRepository(database, 1101, 0x1101)
	for _, id := range ids {
		digest := sha256.Sum256([]byte(id))
		_, err := repository.Adopt(ctx, modem.AdoptInput{
			ID:           id,
			Name:         id,
			IdentityKind: "usb_serial_hash",
			IdentityHash: hex.EncodeToString(digest[:]),
		})
		if err != nil {
			t.Fatalf("adopt modem %s: %v", id, err)
		}
	}
	return repository
}

func seedSubscriptions(t *testing.T, ctx context.Context, database *sql.DB, ids ...string) *subscription.Repository {
	t.Helper()
	repository := subscription.NewRepository(database)
	for _, id := range ids {
		_, err := repository.Create(ctx, subscription.CreateInput{
			ID:              id,
			Name:            id,
			SourceType:      "url",
			SourceSecretRef: "/var/lib/gateway-vpn/secrets/subscriptions/" + id,
			RefreshInterval: time.Hour,
		})
		if err != nil {
			t.Fatalf("create subscription %s: %v", id, err)
		}
	}
	return repository
}

func seedNode(t *testing.T, ctx context.Context, database *sql.DB, subscriptionID, nodeID string) {
	t.Helper()
	versionID := "version:" + subscriptionID
	if _, err := database.ExecContext(ctx, `
INSERT INTO subscription_versions(id, subscription_id, content_sha256, nodes_total, state, created_at)
VALUES (?, ?, ?, 1, 'LKG', ?)`, versionID, subscriptionID, hex.EncodeToString(make([]byte, 32)), time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		t.Fatalf("insert subscription version: %v", err)
	}
	if _, err := database.ExecContext(ctx, `
INSERT INTO nodes(id, version_id, external_name, normalized_name, fingerprint, proxy_type)
VALUES (?, ?, ?, ?, ?, 'vless')`, nodeID, versionID, nodeID, nodeID, "fingerprint:"+nodeID); err != nil {
		t.Fatalf("insert node: %v", err)
	}
}
