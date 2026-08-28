package modem

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"path/filepath"
	"testing"

	databasepkg "gateway-vpn/internal/db"
	"gateway-vpn/internal/store"
)

func TestAdoptAllocatesStableMonotonicResources(t *testing.T) {
	ctx, database := migratedDatabase(t)
	repository := NewRepository(database, 1101, 0x1101)

	first, err := repository.Adopt(ctx, adoptInput("modem-a", "Operator A"))
	if err != nil {
		t.Fatalf("Adopt(first) error = %v", err)
	}
	second, err := repository.Adopt(ctx, adoptInput("modem-b", "Operator B"))
	if err != nil {
		t.Fatalf("Adopt(second) error = %v", err)
	}
	if first.DisplayNumber != 1 || second.DisplayNumber != 2 {
		t.Fatalf("display numbers = %d,%d, want 1,2", first.DisplayNumber, second.DisplayNumber)
	}
	if first.RoutingTableID != 1101 || second.RoutingTableID != 1102 {
		t.Fatalf("routing tables = %d,%d, want 1101,1102", first.RoutingTableID, second.RoutingTableID)
	}
	if first.Fwmark != 0x1101 || second.Fwmark != 0x1102 {
		t.Fatalf("fwmarks = %#x,%#x, want 0x1101,0x1102", first.Fwmark, second.Fwmark)
	}

	if _, err := database.ExecContext(ctx, "DELETE FROM modems WHERE id=?", second.ID); err != nil {
		t.Fatalf("delete second modem: %v", err)
	}
	third, err := repository.Adopt(ctx, adoptInput("modem-c", "Operator C"))
	if err != nil {
		t.Fatalf("Adopt(third) error = %v", err)
	}
	if third.DisplayNumber != 3 || third.RoutingTableID != 1103 || third.Fwmark != 0x1103 {
		t.Fatalf("third allocations = number %d table %d mark %#x, want 3/1103/0x1103", third.DisplayNumber, third.RoutingTableID, third.Fwmark)
	}
}

func TestAdoptRollsBackCountersOnIdentityConflict(t *testing.T) {
	ctx, database := migratedDatabase(t)
	repository := NewRepository(database, 1101, 0x1101)
	input := adoptInput("modem-a", "Operator A")
	if _, err := repository.Adopt(ctx, input); err != nil {
		t.Fatalf("Adopt(first) error = %v", err)
	}
	conflict := input
	conflict.ID = "modem-conflict"
	if _, err := repository.Adopt(ctx, conflict); err == nil {
		t.Fatal("Adopt(conflict) error = nil, want unique identity error")
	}
	next, err := repository.Adopt(ctx, adoptInput("modem-b", "Operator B"))
	if err != nil {
		t.Fatalf("Adopt(next) error = %v", err)
	}
	if next.DisplayNumber != 2 {
		t.Fatalf("next display number = %d, want 2 after rolled back conflict", next.DisplayNumber)
	}
}

func TestReorderEnabledIsAtomicAndRequiresCompleteSet(t *testing.T) {
	ctx, database := migratedDatabase(t)
	repository := NewRepository(database, 1101, 0x1101)
	for _, id := range []string{"modem-a", "modem-b", "modem-c"} {
		if _, err := repository.Adopt(ctx, adoptInput(id, id)); err != nil {
			t.Fatalf("Adopt(%s) error = %v", id, err)
		}
	}
	if err := repository.ReorderEnabled(ctx, []string{"modem-c", "modem-a", "modem-b"}); err != nil {
		t.Fatalf("ReorderEnabled() error = %v", err)
	}
	items, err := repository.List(ctx)
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	for index, want := range []string{"modem-c", "modem-a", "modem-b"} {
		if items[index].ID != want || items[index].Priority != int64((index+1)*10) {
			t.Errorf("item[%d] = %s/%d, want %s/%d", index, items[index].ID, items[index].Priority, want, (index+1)*10)
		}
	}
	if err := repository.ReorderEnabled(ctx, []string{"modem-a", "modem-a", "modem-b"}); !errors.Is(err, store.ErrPrioritySetMismatch) {
		t.Fatalf("duplicate reorder error = %v, want ErrPrioritySetMismatch", err)
	}
	itemsAfterFailure, err := repository.List(ctx)
	if err != nil {
		t.Fatalf("List(after failure) error = %v", err)
	}
	for index := range items {
		if itemsAfterFailure[index].ID != items[index].ID || itemsAfterFailure[index].Priority != items[index].Priority {
			t.Fatalf("failed reorder changed persisted order")
		}
	}
}

func TestModemLifecycleOperationsAreSafeAndAudited(t *testing.T) {
	ctx, database := migratedDatabase(t)
	repository := NewRepository(database, 1101, 0x1101)
	if _, err := repository.Adopt(ctx, adoptInput("modem-a", "Operator A")); err != nil {
		t.Fatal(err)
	}
	if _, err := repository.Adopt(ctx, adoptInput("modem-b", "Operator B")); err != nil {
		t.Fatal(err)
	}
	if _, err := repository.ApplyLease(ctx, "modem-a", LeaseInput{InterfaceName: "enx1", ManagementCIDR: "192.168.8.0/24", Gateway: "192.168.8.1", DNS: []string{"192.168.8.1"}, MTU: 1500, State: StateReady}); err != nil {
		t.Fatal(err)
	}
	if err := repository.SetEnabled(ctx, "modem-a", false); err != nil {
		t.Fatal(err)
	}
	disabled, _ := repository.Get(ctx, "modem-a")
	if disabled.Enabled || disabled.State != StateDisabled || disabled.InterfaceName != "" || disabled.ManagementReachabilityState != "STALE" {
		t.Fatalf("disabled modem = %+v", disabled)
	}
	if err := repository.SetEnabled(ctx, "modem-a", true); err != nil {
		t.Fatal(err)
	}
	if err := repository.MarkOffline(ctx, "modem-a"); err != nil {
		t.Fatal(err)
	}
	replacement := adoptInput("replacement", "")
	if err := repository.ReplaceIdentity(ctx, "modem-a", ReplaceIdentityInput{IdentityKind: replacement.IdentityKind, IdentityHash: replacement.IdentityHash, MaskedSerial: replacement.MaskedSerial}); err != nil {
		t.Fatal(err)
	}
	if err := repository.ReplaceIdentity(ctx, "modem-b", ReplaceIdentityInput{IdentityKind: replacement.IdentityKind, IdentityHash: replacement.IdentityHash, MaskedSerial: replacement.MaskedSerial}); err == nil {
		t.Fatal("duplicate replacement identity was accepted")
	}
	if err := repository.Update(ctx, "modem-a", UpdateInput{Name: "Backup LTE", OperatorLabel: "Operator C"}); err != nil {
		t.Fatal(err)
	}
	updated, _ := repository.Get(ctx, "modem-a")
	if updated.Name != "Backup LTE" || updated.OperatorLabel != "Operator C" || updated.IdentityHash != replacement.IdentityHash {
		t.Fatalf("updated modem = %+v", updated)
	}
	if err := repository.Forget(ctx, "modem-a"); err != nil {
		t.Fatal(err)
	}
	if _, err := repository.Get(ctx, "modem-a"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("forgotten modem Get() error = %v", err)
	}
	var auditCount int
	if err := database.QueryRowContext(ctx, "SELECT COUNT(*) FROM events WHERE type IN ('MODEM_ADOPTED','MODEM_ENABLED_CHANGED','MODEM_RECOVERY_REQUESTED','MODEM_IDENTITY_REPLACED','MODEM_UPDATED','MODEM_FORGOTTEN')").Scan(&auditCount); err != nil || auditCount < 7 {
		t.Fatalf("modem audit events = %d, %v", auditCount, err)
	}
}

func TestForgetRejectsRuntimeReferencedModem(t *testing.T) {
	ctx, database := migratedDatabase(t)
	repository := NewRepository(database, 1101, 0x1101)
	if _, err := repository.Adopt(ctx, adoptInput("modem-a", "Operator A")); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(ctx, "UPDATE runtime_state SET management_modem_id='modem-a' WHERE singleton_id=1"); err != nil {
		t.Fatal(err)
	}
	if err := repository.Forget(ctx, "modem-a"); err == nil {
		t.Fatal("runtime-referenced modem was forgotten")
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

func adoptInput(id, label string) AdoptInput {
	digest := sha256.Sum256([]byte(id))
	return AdoptInput{
		ID:            id,
		Name:          "Modem " + id,
		OperatorLabel: label,
		IdentityKind:  "usb_serial_hash",
		IdentityHash:  hex.EncodeToString(digest[:]),
		MaskedSerial:  "***" + id,
	}
}
