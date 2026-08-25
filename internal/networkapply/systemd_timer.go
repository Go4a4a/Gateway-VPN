package networkapply

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"time"

	"gateway-vpn/internal/platformexec"
)

type SystemdRollbackTimer struct {
	Executor  platformexec.Executor
	Systemctl string
	Now       func() time.Time
}

func (timer SystemdRollbackTimer) Arm(ctx context.Context, applyID string, deadline time.Time) error {
	if err := timer.validate(); err != nil {
		return err
	}
	if !safeID(applyID) {
		return errors.New("safe network apply id is required for rollback timer")
	}
	delay := deadline.UTC().Sub(timer.now().UTC())
	// The packaged template has OnActiveSec=60s. Reject timing drift rather
	// than silently promising a deadline the independent timer cannot meet.
	if delay < 55*time.Second || delay > 65*time.Second {
		return errors.New("systemd rollback timer requires a 60-second deadline")
	}
	unit := "gateway-vpn-network-rollback@" + applyID + ".timer"
	if _, err := timer.Executor.Run(ctx, platformexec.Request{Executable: timer.Systemctl, Arguments: []string{"start", unit}}); err != nil {
		return fmt.Errorf("arm systemd network rollback timer: %w", err)
	}
	return nil
}

func (timer SystemdRollbackTimer) Disarm(ctx context.Context, applyID string) error {
	if err := timer.validate(); err != nil {
		return err
	}
	if !safeID(applyID) {
		return errors.New("safe network apply id is required for rollback timer")
	}
	unit := "gateway-vpn-network-rollback@" + applyID + ".timer"
	if _, err := timer.Executor.Run(ctx, platformexec.Request{Executable: timer.Systemctl, Arguments: []string{"stop", unit}}); err != nil {
		return fmt.Errorf("disarm systemd network rollback timer: %w", err)
	}
	return nil
}

func (timer SystemdRollbackTimer) validate() error {
	if timer.Executor == nil || !filepath.IsAbs(timer.Systemctl) {
		return errors.New("systemd rollback timer executor and absolute systemctl path are required")
	}
	return nil
}

func (timer SystemdRollbackTimer) now() time.Time {
	if timer.Now != nil {
		return timer.Now()
	}
	return time.Now()
}
