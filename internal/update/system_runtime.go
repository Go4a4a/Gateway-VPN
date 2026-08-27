package update

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"gateway-vpn/internal/platformexec"
	"gateway-vpn/internal/watchdog"
)

const (
	controlUnit  = "gateway-vpn.service"
	brokerUnit   = "gateway-vpn-network-broker.socket"
	mihomoUnit   = "gateway-vpn-mihomo.service"
	dnsmasqUnit  = "gateway-vpn-dnsmasq.service"
	firewallUnit = "gateway-vpn-firewall.service"
	guardUnit    = "gateway-vpn-firewall-guard.service"
	watchdogUnit = "gateway-vpn-watchdog.service"

	watchdogStatusPath   = "/run/gateway-vpn-watchdog/status.json"
	controlHeartbeatPath = "/run/gateway-vpn-watchdog/control.json"
)

type SystemRuntime struct {
	Executor     platformexec.Executor
	Systemctl    string
	ReleaseRoot  string
	RecoveryOnly bool
}

func (runtime SystemRuntime) Observe(ctx context.Context) (ManagedRuntimeState, error) {
	if err := runtime.validate(); err != nil {
		return ManagedRuntimeState{}, err
	}
	mihomo, err := runtime.unitActive(ctx, mihomoUnit)
	if err != nil {
		return ManagedRuntimeState{}, err
	}
	dnsmasq, err := runtime.unitActive(ctx, dnsmasqUnit)
	if err != nil {
		return ManagedRuntimeState{}, err
	}
	return ManagedRuntimeState{MihomoActive: mihomo, DNSMasqActive: dnsmasq}, nil
}

func (runtime SystemRuntime) Quiesce(ctx context.Context) error {
	if err := runtime.validate(); err != nil {
		return err
	}
	_, err := runtime.Executor.Run(ctx, platformexec.Request{
		Executable:     runtime.Systemctl,
		Arguments:      []string{"stop", controlUnit, "gateway-vpn-network-broker.service", brokerUnit, mihomoUnit, dnsmasqUnit},
		MaxOutputBytes: 64 << 10,
	})
	if err != nil {
		return fmt.Errorf("quiesce Gateway VPN managed services: %w", err)
	}
	// Stop order and start order are resolved by the existing systemd
	// Before=/After= relationship: guard stops first, then the oneshot firewall
	// reloads a PATH_BLOCKED table from the selected release, then guard starts.
	// A single transaction prevents a live guard from racing a structural
	// firewall schema replacement.
	if err := runtime.synchronizeFailClosedFirewall(ctx); err != nil {
		return fmt.Errorf("enforce fail-closed firewall while quiescing: %w", err)
	}
	return nil
}

func (runtime SystemRuntime) OfflineCheck(ctx context.Context, candidateBinary, databasePath, configPath, expectedVersion, expectedMihomo string, expectedSchema int64) (OfflineResult, error) {
	if err := runtime.validate(); err != nil {
		return OfflineResult{}, err
	}
	if !filepath.IsAbs(candidateBinary) || !pathInside(filepath.Join(runtime.ReleaseRoot, "releases"), candidateBinary) || !filepath.IsAbs(databasePath) || !filepath.IsAbs(configPath) || !versionPattern.MatchString(expectedVersion) || !mihomoVersionPattern.MatchString(expectedMihomo) || expectedSchema < 1 {
		return OfflineResult{}, errors.New("candidate offline check arguments are outside the fixed update contract")
	}
	result, err := runtime.Executor.Run(ctx, platformexec.Request{
		Executable: candidateBinary,
		Arguments: []string{
			"update-offline-check", "--database", databasePath, "--config", configPath,
			"--expected-version", expectedVersion, "--expected-mihomo-version", expectedMihomo,
			"--expected-schema", strconv.FormatInt(expectedSchema, 10), "--json",
		},
		MaxOutputBytes: 64 << 10,
	})
	if err != nil {
		return OfflineResult{}, fmt.Errorf("candidate offline compatibility process failed: %w", err)
	}
	var offline OfflineResult
	if err := decodeStrict([]byte(result.Stdout), &offline); err != nil {
		return OfflineResult{}, errors.New("candidate offline compatibility output is invalid")
	}
	if err := verifyOfflineResult(offline, expectedSchema); err != nil {
		return OfflineResult{}, err
	}
	return offline, nil
}

func (runtime SystemRuntime) StartAndHealth(ctx context.Context, expectedVersion, databasePath string, previous ManagedRuntimeState) error {
	if err := runtime.validate(); err != nil {
		return err
	}
	if !versionPattern.MatchString(expectedVersion) || !filepath.IsAbs(databasePath) {
		return errors.New("expected release version and database path are required")
	}
	if err := runtime.synchronizeFailClosedFirewall(ctx); err != nil {
		return fmt.Errorf("activate selected release firewall schema: %w", err)
	}
	if runtime.RecoveryOnly {
		return runtime.checkVersionAndState(ctx, expectedVersion, databasePath)
	}
	if _, err := runtime.Executor.Run(ctx, platformexec.Request{Executable: runtime.Systemctl, Arguments: []string{"restart", watchdogUnit}, MaxOutputBytes: 64 << 10}); err != nil {
		return fmt.Errorf("restart switched Gateway VPN watchdog: %w", err)
	}
	units := []string{brokerUnit, controlUnit}
	if previous.MihomoActive {
		units = append(units, mihomoUnit)
	}
	if previous.DNSMasqActive {
		units = append(units, dnsmasqUnit)
	}
	if _, err := runtime.Executor.Run(ctx, platformexec.Request{Executable: runtime.Systemctl, Arguments: append([]string{"start"}, units...), MaxOutputBytes: 64 << 10}); err != nil {
		return fmt.Errorf("start switched Gateway VPN services: %w", err)
	}
	required := []string{firewallUnit, guardUnit, watchdogUnit, brokerUnit, controlUnit}
	if previous.MihomoActive {
		required = append(required, mihomoUnit)
	}
	if previous.DNSMasqActive {
		required = append(required, dnsmasqUnit)
	}
	deadline := time.Now().Add(30 * time.Second)
	consecutive := 0
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		allActive := true
		for _, unit := range required {
			active, err := runtime.unitActive(ctx, unit)
			if err != nil {
				return err
			}
			if !active {
				allActive = false
				break
			}
		}
		if allActive {
			versionErr := runtime.checkVersionAndState(ctx, expectedVersion, databasePath)
			watchdogErr := checkWatchdogRuntimeFiles(watchdogStatusPath, controlHeartbeatPath, time.Now().UTC())
			if versionErr == nil && watchdogErr == nil {
				consecutive++
				if consecutive == 3 {
					return nil
				}
			} else {
				consecutive = 0
			}
		} else {
			consecutive = 0
		}
		if time.Now().After(deadline) {
			return errors.New("switched Gateway VPN services did not remain healthy")
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

func (runtime SystemRuntime) synchronizeFailClosedFirewall(ctx context.Context) error {
	if err := runtime.validate(); err != nil {
		return err
	}
	// A rejected release can legitimately select PATH_BLOCKED several times in
	// quick succession: quiesce, candidate activation, rollback quiesce, old
	// release activation, and then boot/OnFailure recovery. systemd counts even
	// successful oneshot starts towards the unit start limit, so without an
	// explicit reset a healthy rollback can be stranded at start-limit-hit.
	// Reset only the two owned units immediately before their atomic restart;
	// this neither weakens fail-closed policy nor touches unrelated services.
	if _, err := runtime.Executor.Run(ctx, platformexec.Request{
		Executable:     runtime.Systemctl,
		Arguments:      []string{"reset-failed", firewallUnit, guardUnit},
		MaxOutputBytes: 64 << 10,
	}); err != nil {
		return fmt.Errorf("reset selected firewall and integrity guard start limits: %w", err)
	}
	_, err := runtime.Executor.Run(ctx, platformexec.Request{
		Executable:     runtime.Systemctl,
		Arguments:      []string{"restart", firewallUnit, guardUnit},
		MaxOutputBytes: 64 << 10,
	})
	if err != nil {
		return fmt.Errorf("restart selected firewall and integrity guard: %w", err)
	}
	return nil
}

func checkWatchdogRuntimeFiles(statusPath, heartbeatPath string, now time.Time) error {
	status, err := (watchdog.StatusFile{Path: statusPath}).Read()
	if err != nil || status.ValidateFresh(now, 2*time.Minute) != nil {
		return errors.New("switched Gateway watchdog status is unavailable or stale")
	}
	if _, err := (watchdog.HeartbeatFile{Path: heartbeatPath}).Read(now, 30*time.Second); err != nil {
		return errors.New("switched Gateway control heartbeat is unavailable or stale")
	}
	return nil
}

func (runtime SystemRuntime) checkVersionAndState(ctx context.Context, expectedVersion, databasePath string) error {
	binary := filepath.Join(runtime.ReleaseRoot, "current", "bin", "gateway-vpn")
	result, err := runtime.Executor.Run(ctx, platformexec.Request{Executable: binary, Arguments: []string{"--version"}, MaxOutputBytes: 16 << 10})
	if err != nil || !strings.HasPrefix(strings.TrimSpace(result.Stdout), "gateway-vpn "+expectedVersion+" (") {
		return errors.New("current Gateway binary version does not match the update journal")
	}
	controller := filepath.Join(runtime.ReleaseRoot, "current", "bin", "gateway-vpnctl")
	if _, err := runtime.Executor.Run(ctx, platformexec.Request{Executable: controller, Arguments: []string{"status", "--database", databasePath, "--json"}, MaxOutputBytes: 1 << 20}); err != nil {
		return errors.New("current Gateway state command failed")
	}
	return nil
}

func (runtime SystemRuntime) unitActive(ctx context.Context, unit string) (bool, error) {
	result, err := runtime.Executor.Run(ctx, platformexec.Request{Executable: runtime.Systemctl, Arguments: []string{"is-active", "--quiet", unit}, MaxOutputBytes: 16 << 10})
	if err == nil {
		return true, nil
	}
	if result.ExitCode > 0 {
		return false, nil
	}
	return false, fmt.Errorf("inspect managed systemd unit %s: %w", unit, err)
}

func (runtime SystemRuntime) validate() error {
	if runtime.Executor == nil || !filepath.IsAbs(runtime.Systemctl) || !filepath.IsAbs(runtime.ReleaseRoot) {
		return errors.New("system update runtime requires fixed absolute executables and release root")
	}
	return nil
}

func pathInside(root, path string) bool {
	root, path = filepath.Clean(root), filepath.Clean(path)
	relative, err := filepath.Rel(root, path)
	return err == nil && relative != "." && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}
