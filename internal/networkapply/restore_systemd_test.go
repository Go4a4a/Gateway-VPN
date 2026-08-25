package networkapply

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	updatepkg "gateway-vpn/internal/update"
)

func TestSystemdRestoreAdminStartsOnlyFixedNoBlockUnit(t *testing.T) {
	executor := &recordingExecutor{}
	admin := SystemdRestoreAdmin{Executor: executor, Systemctl: filepath.Join(t.TempDir(), "systemctl")}
	if err := admin.ApplyPendingRestore(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(executor.requests) != 1 || strings.Join(executor.requests[0].Arguments, " ") != "start --no-block gateway-vpn-database-restore.service" {
		t.Fatalf("restore systemctl requests = %+v", executor.requests)
	}
	executor.err = errors.New("private unit failure")
	if err := admin.ApplyPendingRestore(context.Background()); err == nil {
		t.Fatal("restore systemd error = nil")
	}
}

func TestSystemdUpdateAdminStartsOnlyFixedNoBlockUnit(t *testing.T) {
	executor := &recordingExecutor{}
	admin := SystemdUpdateAdmin{Executor: executor, Systemctl: filepath.Join(t.TempDir(), "systemctl")}
	if err := admin.ApplyPendingUpdate(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(executor.requests) != 1 || strings.Join(executor.requests[0].Arguments, " ") != "start --no-block gateway-vpn-update.service" {
		t.Fatalf("update systemctl requests = %+v", executor.requests)
	}
	executor.err = errors.New("private unit failure")
	if err := admin.ApplyPendingUpdate(context.Background()); err == nil {
		t.Fatal("update systemd error = nil")
	}
}

func TestSystemdUpdateAdminReturnsOnlySanitizedRootJournalStatus(t *testing.T) {
	root := filepath.Join(t.TempDir(), "update-transactions")
	now := time.Date(2026, 8, 25, 0, 0, 0, 0, time.UTC).Format(time.RFC3339Nano)
	journal := updatepkg.Journal{
		FormatVersion:    updatepkg.JournalFormatVersion,
		UpdateID:         "update-20260825T000000Z-0123456789abcdef01234567",
		State:            updatepkg.StateRolledBack,
		StartedAt:        now,
		UpdatedAt:        now,
		OldVersion:       "1.1.0",
		NewVersion:       "1.2.0",
		OldCurrentTarget: "releases/v1.1.0",
		NewCurrentTarget: "releases/v1.2.0",
		ErrorCode:        "NEW_RELEASE_HEALTH_FAILED",
	}
	if err := (updatepkg.JournalStore{Root: root}).Save(journal); err != nil {
		t.Fatal(err)
	}
	admin := SystemdUpdateAdmin{JournalRoot: root}
	status, err := admin.UpdateStatus(context.Background())
	if err != nil || !status.Exists || status.UpdateID != journal.UpdateID || status.State != string(updatepkg.StateRolledBack) || status.ErrorCode != journal.ErrorCode || status.OldVersion != journal.OldVersion || status.NewVersion != journal.NewVersion {
		t.Fatalf("UpdateStatus() = %+v,%v", status, err)
	}
	if _, err := (SystemdUpdateAdmin{JournalRoot: t.TempDir()}).UpdateStatus(context.Background()); err == nil {
		t.Fatal("unsafe update journal root was accepted")
	}
}
