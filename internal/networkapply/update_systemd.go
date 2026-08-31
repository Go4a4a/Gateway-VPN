package networkapply

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"

	"gateway-vpn/internal/platformexec"
	updatepkg "gateway-vpn/internal/update"
)

const (
	signedUpdateUnit         = "gateway-vpn-update.service"
	restorePointRollbackUnit = "gateway-vpn-update-rollback.service"
)

type SystemdUpdateAdmin struct {
	Executor      platformexec.Executor
	Systemctl     string
	JournalRoot   string
	RestorePoints updateRestorePointController
}

type updateRestorePointController interface {
	Inventory(context.Context) ([]updatepkg.RestorePoint, error)
	Delete(context.Context, string) error
	Prune(context.Context, updatepkg.RestorePointPolicy) ([]string, error)
	StageRollback(context.Context, string) (updatepkg.RollbackRequest, error)
	DiscardRollback(string) error
}

func (admin SystemdUpdateAdmin) RestorePointInventory(ctx context.Context) ([]updatepkg.RestorePoint, error) {
	if admin.RestorePoints == nil {
		return nil, errors.New("update restore point controller is unavailable")
	}
	return admin.RestorePoints.Inventory(ctx)
}

func (admin SystemdUpdateAdmin) DeleteRestorePoint(ctx context.Context, pointID string) error {
	if admin.RestorePoints == nil {
		return errors.New("update restore point controller is unavailable")
	}
	return admin.RestorePoints.Delete(ctx, pointID)
}

func (admin SystemdUpdateAdmin) PruneRestorePoints(ctx context.Context, policy updatepkg.RestorePointPolicy) ([]string, error) {
	if admin.RestorePoints == nil {
		return nil, errors.New("update restore point controller is unavailable")
	}
	return admin.RestorePoints.Prune(ctx, policy)
}

func (admin SystemdUpdateAdmin) RollbackToRestorePoint(ctx context.Context, pointID string) error {
	if admin.RestorePoints == nil || admin.Executor == nil || !filepath.IsAbs(admin.Systemctl) {
		return errors.New("systemd restore point rollback admin is unavailable")
	}
	request, err := admin.RestorePoints.StageRollback(ctx, pointID)
	if err != nil {
		return err
	}
	if _, err := admin.Executor.Run(ctx, platformexec.Request{
		Executable: admin.Systemctl,
		Arguments:  []string{"start", "--no-block", restorePointRollbackUnit},
	}); err != nil {
		_ = admin.RestorePoints.DiscardRollback(request.PointID)
		return fmt.Errorf("start fixed restore point rollback helper: %w", err)
	}
	return nil
}

func (admin SystemdUpdateAdmin) ApplyPendingUpdate(ctx context.Context) error {
	if admin.Executor == nil || !filepath.IsAbs(admin.Systemctl) {
		return errors.New("systemd update admin requires an executor and absolute systemctl path")
	}
	if _, err := admin.Executor.Run(ctx, platformexec.Request{
		Executable: admin.Systemctl,
		Arguments:  []string{"start", "--no-block", signedUpdateUnit},
	}); err != nil {
		return fmt.Errorf("start fixed signed update helper: %w", err)
	}
	return nil
}

func (admin SystemdUpdateAdmin) UpdateStatus(ctx context.Context) (UpdateTransactionStatus, error) {
	if err := ctx.Err(); err != nil {
		return UpdateTransactionStatus{}, err
	}
	root := filepath.Clean(admin.JournalRoot)
	if !filepath.IsAbs(root) || filepath.Base(root) != "update-transactions" {
		return UpdateTransactionStatus{}, errors.New("fixed absolute update journal root is required")
	}
	journal, exists, err := (updatepkg.JournalStore{Root: root}).LoadActive()
	if err != nil {
		return UpdateTransactionStatus{}, errors.New("read verified update transaction status failed")
	}
	if !exists {
		return UpdateTransactionStatus{Exists: false}, nil
	}
	return UpdateTransactionStatus{
		Exists:             true,
		OperationKind:      string(journal.TransactionKind()),
		UpdateID:           journal.UpdateID,
		State:              string(journal.State),
		StartedAt:          journal.StartedAt,
		UpdatedAt:          journal.UpdatedAt,
		OldVersion:         journal.OldVersion,
		NewVersion:         journal.NewVersion,
		StabilityDeadline:  journal.StabilityDeadline,
		ErrorCode:          journal.ErrorCode,
		SourceKind:         journal.SourceKind,
		SourceChannel:      journal.SourceChannel,
		SourceReference:    journal.SourceReference,
		TargetRestorePoint: journal.TargetRestorePointID,
	}, nil
}
