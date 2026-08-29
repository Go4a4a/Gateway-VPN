package removal

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	databasepkg "gateway-vpn/internal/db"
)

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
