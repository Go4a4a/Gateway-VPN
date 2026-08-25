package modem

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"testing"

	databasepkg "gateway-vpn/internal/db"
	"gateway-vpn/internal/pathmatrix"
)

func TestLeaseChangeInvalidatesOnlyItsPathsAndOfflinePreservesRecord(t *testing.T) {
	ctx := context.Background()
	database, err := databasepkg.Open(ctx, databasepkg.OpenOptions{Path: filepath.Join(t.TempDir(), "state.db")})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if err := databasepkg.Migrate(ctx, database); err != nil {
		t.Fatal(err)
	}
	repository := NewRepository(database, 1101, 0x1101)
	for _, id := range []string{"m1", "m2"} {
		digest := sha256.Sum256([]byte(id))
		if _, err := repository.Adopt(ctx, AdoptInput{ID: id, Name: id, IdentityKind: "usb_serial_hash", IdentityHash: hex.EncodeToString(digest[:])}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := database.ExecContext(ctx, `
INSERT INTO subscriptions (
    id, display_number, name, source_type, source_secret_ref, enabled, priority, auto_refresh,
    refresh_interval_seconds, fallback_when_named_candidates_fail, status,
    created_at, updated_at
) VALUES ('s1', 1, 's1', 'url', '/secret', 1, 10, 1, 3600, 0, 'UNKNOWN',
          '2026-08-24T00:00:00Z', '2026-08-24T00:00:00Z')`); err != nil {
		t.Fatal(err)
	}
	matrix := pathmatrix.NewRepository(database)
	if err := matrix.ReconcileCells(ctx); err != nil {
		t.Fatal(err)
	}
	update, err := repository.ApplyLease(ctx, "m1", LeaseInput{InterfaceName: "enxm1", ManagementCIDR: "192.168.8.0/24", Gateway: "192.168.8.1", DNS: []string{"192.168.8.1"}, MTU: 1500, State: StateReady})
	if err != nil || !update.RouteContextChanged || update.PathsInvalidated != 1 {
		t.Fatalf("ApplyLease(first) = %+v, %v", update, err)
	}
	m1, _ := matrix.Get(ctx, "m1", "s1")
	m2, _ := matrix.Get(ctx, "m2", "s1")
	if m1.RouteGeneration != 1 || m1.State != pathmatrix.StateStale || m2.RouteGeneration != 0 {
		t.Fatalf("path generations/states = %+v / %+v", m1, m2)
	}
	update, err = repository.ApplyLease(ctx, "m1", LeaseInput{InterfaceName: "enxm1", ManagementCIDR: "192.168.8.0/24", Gateway: "192.168.8.1", DNS: []string{"1.1.1.1"}, MTU: 1500, State: StateReady})
	if err != nil || update.RouteContextChanged {
		t.Fatalf("ApplyLease(DNS-only) = %+v, %v", update, err)
	}
	if err := repository.MarkOffline(ctx, "m1"); err != nil {
		t.Fatal(err)
	}
	record, err := repository.Get(ctx, "m1")
	if err != nil || record.State != StateConfiguredOffline || record.InterfaceName != "" || record.IdentityHash == "" {
		t.Fatalf("offline modem record = %+v, %v", record, err)
	}
	offlinePath, _ := matrix.Get(ctx, "m1", "s1")
	if offlinePath.State != pathmatrix.StateModemOffline {
		t.Fatalf("offline path = %+v", offlinePath)
	}
}
