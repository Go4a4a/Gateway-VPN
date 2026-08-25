package networkapply

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"

	"gateway-vpn/internal/platformexec"
	updatepkg "gateway-vpn/internal/update"
)

const signedUpdateUnit = "gateway-vpn-update.service"

type SystemdUpdateAdmin struct {
	Executor    platformexec.Executor
	Systemctl   string
	JournalRoot string
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
		Exists:            true,
		UpdateID:          journal.UpdateID,
		State:             string(journal.State),
		StartedAt:         journal.StartedAt,
		UpdatedAt:         journal.UpdatedAt,
		OldVersion:        journal.OldVersion,
		NewVersion:        journal.NewVersion,
		StabilityDeadline: journal.StabilityDeadline,
		ErrorCode:         journal.ErrorCode,
	}, nil
}
