package vpsupdate

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"gateway-vpn/internal/platformexec"
)

var managedControlUnits = []string{
	"gateway-vpn-vps-agent.service",
	"gateway-vpn-vps-restore.path",
	"gateway-vpn-vps-fabric.path",
	"gateway-vpn-vps-fabric-watchdog.timer",
	"gateway-vpn-vps-operations.timer",
}

var managedStartUnits = []string{
	"gateway-vpn-vps-firewall.service",
	"wg-quick@wg-mgmt.service",
	"gateway-vpn-vps-restore-recovery.service",
	"gateway-vpn-vps-fabric-recovery.service",
	"gateway-vpn-vps-restore.path",
	"gateway-vpn-vps-fabric.path",
	"gateway-vpn-vps-fabric-watchdog.timer",
	"gateway-vpn-vps-operations.timer",
	"gateway-vpn-vps-agent.service",
}

type SystemRuntime struct {
	Executor    platformexec.Executor
	Systemctl   string
	ReleaseRoot string
}

func (runtime SystemRuntime) Quiesce(ctx context.Context) error {
	if err := runtime.validate(); err != nil {
		return err
	}
	arguments := append([]string{"stop"}, managedControlUnits...)
	if _, err := runtime.Executor.Run(ctx, platformexec.Request{Executable: runtime.Systemctl, Arguments: arguments, MaxOutputBytes: 64 << 10}); err != nil {
		return fmt.Errorf("quiesce VPS Hub control-plane units: %w", err)
	}
	return nil
}

func (runtime SystemRuntime) OfflineCheck(ctx context.Context, candidateBinary, databasePath, configPath, version string, schema int64) (OfflineResult, error) {
	if err := runtime.validate(); err != nil {
		return OfflineResult{}, err
	}
	if !filepath.IsAbs(candidateBinary) || !inside(filepath.Join(runtime.ReleaseRoot, "releases"), candidateBinary) || !filepath.IsAbs(databasePath) || !filepath.IsAbs(configPath) || schema < 1 {
		return OfflineResult{}, errors.New("VPS candidate check arguments escape the fixed update contract")
	}
	result, err := runtime.Executor.Run(ctx, platformexec.Request{Executable: candidateBinary, Arguments: []string{"update-offline-check", "--database", databasePath, "--config", configPath, "--expected-version", version, "--expected-schema", strconv.FormatInt(schema, 10), "--json"}, MaxOutputBytes: 64 << 10})
	if err != nil {
		return OfflineResult{}, fmt.Errorf("VPS candidate offline process failed: %w", err)
	}
	var offline OfflineResult
	if decodeStrict([]byte(result.Stdout), &offline) != nil || !validOffline(offline, version, schema) {
		return OfflineResult{}, errors.New("VPS candidate offline result is invalid")
	}
	return offline, nil
}

func (runtime SystemRuntime) StartAndHealth(ctx context.Context, version, databasePath string) error {
	if err := runtime.validate(); err != nil {
		return err
	}
	if !filepath.IsAbs(databasePath) {
		return errors.New("absolute VPS database path is required")
	}
	if err := runtime.resetStartLimits(ctx); err != nil {
		return err
	}
	if _, err := runtime.Executor.Run(ctx, platformexec.Request{Executable: runtime.Systemctl, Arguments: append([]string{"start"}, managedStartUnits...), MaxOutputBytes: 64 << 10}); err != nil {
		return fmt.Errorf("start selected VPS Hub release: %w", err)
	}
	required := append([]string{"gateway-vpn-vps-firewall.service", "wg-quick@wg-mgmt.service"}, managedControlUnits...)
	deadline := time.Now().Add(30 * time.Second)
	consecutive := 0
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		healthy := true
		for _, unit := range required {
			active, err := runtime.unitActive(ctx, unit)
			if err != nil {
				return err
			}
			if !active {
				healthy = false
				break
			}
		}
		if healthy && runtime.checkVersionAndState(ctx, version, databasePath) == nil {
			consecutive++
		} else {
			consecutive = 0
		}
		if consecutive == 3 {
			return nil
		}
		if time.Now().After(deadline) {
			return errors.New("selected VPS Hub release did not remain healthy")
		}
		timer := time.NewTimer(time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func (runtime SystemRuntime) VerifyCurrent(ctx context.Context, version, databasePath string) error {
	if err := runtime.validateDatabasePath(databasePath); err != nil {
		return err
	}
	return runtime.checkVersionAndState(ctx, version, databasePath)
}

func (runtime SystemRuntime) ScheduleStart(ctx context.Context, version, databasePath string) error {
	if err := runtime.validateDatabasePath(databasePath); err != nil {
		return err
	}
	if err := runtime.checkVersionAndState(ctx, version, databasePath); err != nil {
		return err
	}
	if err := runtime.resetStartLimits(ctx); err != nil {
		return err
	}
	arguments := append([]string{"start", "--no-block"}, managedStartUnits...)
	if _, err := runtime.Executor.Run(ctx, platformexec.Request{Executable: runtime.Systemctl, Arguments: arguments, MaxOutputBytes: 64 << 10}); err != nil {
		return fmt.Errorf("schedule selected VPS Hub release after recovery: %w", err)
	}
	return nil
}

func (runtime SystemRuntime) resetStartLimits(ctx context.Context) error {
	reset := append([]string{"reset-failed", "gateway-vpn-vps-firewall.service", "wg-quick@wg-mgmt.service", "gateway-vpn-vps-restore-recovery.service", "gateway-vpn-vps-fabric-recovery.service"}, managedControlUnits...)
	if _, err := runtime.Executor.Run(ctx, platformexec.Request{Executable: runtime.Systemctl, Arguments: reset, MaxOutputBytes: 64 << 10}); err != nil {
		return fmt.Errorf("reset owned VPS unit start limits: %w", err)
	}
	return nil
}

func (runtime SystemRuntime) validateDatabasePath(databasePath string) error {
	if err := runtime.validate(); err != nil {
		return err
	}
	if !filepath.IsAbs(databasePath) {
		return errors.New("absolute VPS database path is required")
	}
	return nil
}

func (runtime SystemRuntime) checkVersionAndState(ctx context.Context, version, databasePath string) error {
	binary := filepath.Join(runtime.ReleaseRoot, "current", "bin", "gateway-vpn-vps-agent")
	result, err := runtime.Executor.Run(ctx, platformexec.Request{Executable: binary, Arguments: []string{"--version"}, MaxOutputBytes: 16 << 10})
	if err != nil || !strings.HasPrefix(strings.TrimSpace(result.Stdout), "gateway-vpn-vps-agent "+version+" (") {
		return errors.New("current VPS Agent version does not match the update journal")
	}
	if _, err := runtime.Executor.Run(ctx, platformexec.Request{Executable: binary, Arguments: []string{"state-check", "--config", "/etc/gateway-vpn-vps/config.yaml"}, MaxOutputBytes: 64 << 10}); err != nil {
		return errors.New("current VPS Agent state verification failed")
	}
	return nil
}

func (runtime SystemRuntime) unitActive(ctx context.Context, unit string) (bool, error) {
	result, err := runtime.Executor.Run(ctx, platformexec.Request{Executable: runtime.Systemctl, Arguments: []string{"is-active", "--quiet", unit}, MaxOutputBytes: 4096})
	if err == nil {
		return true, nil
	}
	if result.ExitCode > 0 {
		return false, nil
	}
	return false, err
}

func (runtime SystemRuntime) validate() error {
	if runtime.Executor == nil || !filepath.IsAbs(runtime.Systemctl) || !filepath.IsAbs(runtime.ReleaseRoot) {
		return errors.New("fixed VPS system runtime is required")
	}
	return nil
}

func inside(root, path string) bool {
	relative, err := filepath.Rel(filepath.Clean(root), filepath.Clean(path))
	return err == nil && relative != "." && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}
