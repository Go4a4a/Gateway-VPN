package removal

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	databasepkg "gateway-vpn/internal/db"
	"gateway-vpn/internal/platformexec"
	updatepkg "gateway-vpn/internal/update"
)

type removalExecutor struct{}

func (removalExecutor) Run(_ context.Context, request platformexec.Request) (platformexec.Result, error) {
	if len(request.Arguments) != 0 && request.Arguments[0] == "show" {
		return platformexec.Result{Stdout: "inactive\n"}, nil
	}
	return platformexec.Result{}, nil
}

func TestRequestValidationIsTypedAndBounded(t *testing.T) {
	validID := "uninstall-0123456789abcdef0123456789abcdef"
	for _, mode := range []Mode{ModePreserveData, ModePurgeData} {
		if err := (Request{OperationID: validID, Mode: mode}).Validate(); err != nil {
			t.Fatalf("valid request rejected: %v", err)
		}
	}
	for _, request := range []Request{
		{OperationID: "", Mode: ModePreserveData},
		{OperationID: validID, Mode: "DELETE_PACKAGES"},
		{OperationID: "uninstall-../../root", Mode: ModePurgeData},
	} {
		if err := request.Validate(); !errors.Is(err, ErrInvalidRequest) {
			t.Fatalf("invalid request %+v = %v", request, err)
		}
	}
}

func TestWriteMarkerIsDurableTypedAndExclusive(t *testing.T) {
	root := filepath.Join(t.TempDir(), "uninstall")
	request := Request{OperationID: "uninstall-0123456789abcdef0123456789abcdef", Mode: ModePurgeData}
	if err := writeMarker(root, request); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(filepath.Join(root, "active"))
	if err != nil || !info.Mode().IsRegular() || !hasSecureMode(info, 0o600) {
		t.Fatalf("marker info = %+v, %v", info, err)
	}
	content, err := os.ReadFile(filepath.Join(root, "active"))
	if err != nil || string(content) != "format=1\noperation_id=uninstall-0123456789abcdef0123456789abcdef\nmode=PURGE_DATA\n" {
		t.Fatalf("marker = %q, %v", content, err)
	}
	if err := writeMarker(root, request); err == nil {
		t.Fatal("second marker unexpectedly replaced active uninstall")
	}
}

func TestRepositorySerializesAndAuditsUninstall(t *testing.T) {
	ctx := context.Background()
	database, err := databasepkg.Open(ctx, databasepkg.OpenOptions{Path: filepath.Join(t.TempDir(), "state.db")})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if err := databasepkg.Migrate(ctx, database); err != nil {
		t.Fatal(err)
	}
	repository := Repository{Database: database}
	operation, err := repository.Start(ctx, "admin", ModePreserveData)
	if err != nil || !strings.HasPrefix(operation.ID, "uninstall-") || operation.ScopeID != string(ModePreserveData) {
		t.Fatalf("start = %+v, %v", operation, err)
	}
	if _, err := repository.Start(ctx, "admin", ModePurgeData); !errors.Is(err, ErrOperationInProgress) {
		t.Fatalf("parallel uninstall = %v", err)
	}
	finished, err := repository.Finish(ctx, operation.ID, true, "")
	if err != nil || finished.Status != "SUCCEEDED" || finished.SummaryCode != "UNINSTALL_DISPATCHED" {
		t.Fatalf("finish = %+v, %v", finished, err)
	}
	var requested, dispatched int
	_ = database.QueryRowContext(ctx, "SELECT COUNT(*) FROM events WHERE type='SYSTEM_UNINSTALL_REQUESTED'").Scan(&requested)
	_ = database.QueryRowContext(ctx, "SELECT COUNT(*) FROM events WHERE type='SYSTEM_UNINSTALL_DISPATCHED'").Scan(&dispatched)
	if requested != 1 || dispatched != 1 {
		t.Fatalf("audit counts = %d/%d", requested, dispatched)
	}
	latest, exists, err := repository.Latest(ctx)
	if err != nil || !exists || latest.ID != operation.ID {
		t.Fatalf("latest = %+v, %v, %v", latest, exists, err)
	}
}

func TestLinuxBackendBlocksEveryDurableUpdateAndRestoreBoundary(t *testing.T) {
	ctx := context.Background()
	database, err := databasepkg.Open(ctx, databasepkg.OpenOptions{Path: filepath.Join(t.TempDir(), "state.db")})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if err := databasepkg.Migrate(ctx, database); err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	backend := DefaultLinuxBackend(database, removalExecutor{})
	backend.InstallMarker = filepath.Join(root, "install")
	backend.HostUpgrade = filepath.Join(root, "host-upgrade")
	backend.InstallRunMarker = filepath.Join(root, "install-run")
	backend.UpdateStaging = filepath.Join(root, "update-staging")
	backend.UpdateJournalRoot = filepath.Join(root, "update-journals")
	backend.UpdateRollback = filepath.Join(root, "update-rollback")
	backend.RestoreMarker = filepath.Join(root, "restore")

	for _, marker := range []string{
		backend.UpdateStaging, backend.UpdateRollback, backend.RestoreMarker,
	} {
		if err := os.WriteFile(marker, []byte("active\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		active, code := backend.maintenance(ctx)
		if !active || code != "LIFECYCLE_TRANSACTION_ACTIVE" {
			t.Fatalf("marker %q maintenance = %t,%q", marker, active, code)
		}
		if err := os.Remove(marker); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(backend.UpdateJournalRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	journal := updatepkg.Journal{
		FormatVersion: updatepkg.JournalFormatVersion,
		UpdateID:      "update-20260831T120000Z-0123456789abcdef01234567", State: updatepkg.StatePrepared,
		StartedAt: now.Format(time.RFC3339Nano), UpdatedAt: now.Format(time.RFC3339Nano),
		OldVersion: "1.0.0", NewVersion: "1.1.0",
		OldCurrentTarget: "releases/v1.0.0", NewCurrentTarget: "releases/v1.1.0",
	}
	store := updatepkg.JournalStore{Root: backend.UpdateJournalRoot}
	if err := store.Save(journal); err != nil {
		t.Fatal(err)
	}
	active, code := backend.maintenance(ctx)
	if !active || code != "UPDATE_TRANSACTION_ACTIVE_OR_UNKNOWN" {
		t.Fatalf("unfinished journal maintenance = %t,%q", active, code)
	}
	journal.State = updatepkg.StateRolledBack
	journal.UpdatedAt = now.Add(time.Minute).Format(time.RFC3339Nano)
	if err := store.Save(journal); err != nil {
		t.Fatal(err)
	}
	active, code = backend.maintenance(ctx)
	if active {
		t.Fatalf("terminal journal blocked uninstall = %t,%q", active, code)
	}
}
