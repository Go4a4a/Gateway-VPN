package networkapply

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"

	"gateway-vpn/internal/platformexec"
)

const databaseRestoreDispatchUnit = "gateway-vpn-database-restore-dispatch.service"

type SystemdRestoreAdmin struct {
	Executor  platformexec.Executor
	Systemctl string
}

func (admin SystemdRestoreAdmin) ApplyPendingRestore(ctx context.Context) error {
	if admin.Executor == nil || !filepath.IsAbs(admin.Systemctl) {
		return errors.New("systemd restore admin requires an executor and absolute systemctl path")
	}
	if _, err := admin.Executor.Run(ctx, platformexec.Request{
		Executable: admin.Systemctl,
		Arguments:  []string{"start", "--no-block", databaseRestoreDispatchUnit},
	}); err != nil {
		return fmt.Errorf("start fixed database restore helper: %w", err)
	}
	return nil
}
