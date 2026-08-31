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
	if len(executor.requests) != 1 || strings.Join(executor.requests[0].Arguments, " ") != "start --no-block gateway-vpn-database-restore-dispatch.service" {
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

func TestSystemdUpdateAdminStagesRollbackAndStartsOnlyFixedHelper(t *testing.T) {
	const pointID = "point-20260831T010000Z-0123456789abcdef01234567"
	controller := &fakeUpdateRestorePointController{}
	executor := &recordingExecutor{}
	admin := SystemdUpdateAdmin{
		Executor: executor, Systemctl: filepath.Join(t.TempDir(), "systemctl"), RestorePoints: controller,
	}
	if err := admin.RollbackToRestorePoint(context.Background(), pointID); err != nil {
		t.Fatal(err)
	}
	if controller.staged != pointID || controller.discarded != "" {
		t.Fatalf("rollback controller staged=%q discarded=%q", controller.staged, controller.discarded)
	}
	if len(executor.requests) != 1 || strings.Join(executor.requests[0].Arguments, " ") != "start --no-block gateway-vpn-update-rollback.service" {
		t.Fatalf("rollback systemctl requests = %+v", executor.requests)
	}
	for _, argument := range executor.requests[0].Arguments {
		if strings.Contains(argument, pointID) || strings.Contains(argument, "update-restore-points") {
			t.Fatalf("rollback identity or path crossed systemctl boundary: %+v", executor.requests[0])
		}
	}
}

func TestSystemdUpdateAdminDiscardsRequestWhenHelperStartFails(t *testing.T) {
	const pointID = "point-20260831T010000Z-0123456789abcdef01234567"
	controller := &fakeUpdateRestorePointController{}
	executor := &recordingExecutor{err: errors.New("systemd unavailable")}
	admin := SystemdUpdateAdmin{
		Executor: executor, Systemctl: filepath.Join(t.TempDir(), "systemctl"), RestorePoints: controller,
	}
	if err := admin.RollbackToRestorePoint(context.Background(), pointID); err == nil {
		t.Fatal("systemctl start failure was hidden")
	}
	if controller.staged != pointID || controller.discarded != pointID {
		t.Fatalf("failed dispatch staged=%q discarded=%q", controller.staged, controller.discarded)
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

type fakeUpdateRestorePointController struct {
	staged    string
	discarded string
}

func (controller *fakeUpdateRestorePointController) Inventory(context.Context) ([]updatepkg.RestorePoint, error) {
	return nil, nil
}

func (controller *fakeUpdateRestorePointController) Delete(context.Context, string) error { return nil }

func (controller *fakeUpdateRestorePointController) Prune(context.Context, updatepkg.RestorePointPolicy) ([]string, error) {
	return nil, nil
}

func (controller *fakeUpdateRestorePointController) StageRollback(_ context.Context, pointID string) (updatepkg.RollbackRequest, error) {
	controller.staged = pointID
	return updatepkg.RollbackRequest{PointID: pointID}, nil
}

func (controller *fakeUpdateRestorePointController) DiscardRollback(pointID string) error {
	controller.discarded = pointID
	return nil
}
