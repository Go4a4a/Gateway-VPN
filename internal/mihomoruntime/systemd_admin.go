package mihomoruntime

import (
	"context"
	"errors"
	"fmt"

	"gateway-vpn/internal/platformexec"
)

const (
	MihomoUnit   = "gateway-vpn-mihomo.service"
	FirewallUnit = "gateway-vpn-firewall.service"
)

// SystemdAdmin runs only fixed unit actions from the root broker. No command,
// unit, argument, or path comes from an API request.
type SystemdAdmin struct {
	Executor  platformexec.Executor
	Systemctl string
}

func (admin SystemdAdmin) RestartMihomo(ctx context.Context) error {
	if err := admin.validate(); err != nil {
		return err
	}
	if _, err := admin.Executor.Run(ctx, platformexec.Request{Executable: admin.Systemctl, Arguments: []string{"restart", MihomoUnit}}); err != nil {
		return fmt.Errorf("restart fixed Mihomo unit: %w", err)
	}
	return nil
}

func (admin SystemdAdmin) FailClosedMihomo(ctx context.Context) error {
	if err := admin.validate(); err != nil {
		return err
	}
	_, firewallErr := admin.Executor.Run(ctx, platformexec.Request{Executable: admin.Systemctl, Arguments: []string{"reload", FirewallUnit}})
	_, stopErr := admin.Executor.Run(ctx, platformexec.Request{Executable: admin.Systemctl, Arguments: []string{"stop", MihomoUnit}})
	if firewallErr != nil {
		firewallErr = fmt.Errorf("reload fixed fail-closed firewall unit: %w", firewallErr)
	}
	if stopErr != nil {
		stopErr = fmt.Errorf("stop fixed Mihomo unit: %w", stopErr)
	}
	return errors.Join(firewallErr, stopErr)
}

func (admin SystemdAdmin) validate() error {
	if admin.Executor == nil || admin.Systemctl != "/usr/bin/systemctl" {
		return errors.New("fixed Ubuntu systemctl executor is required")
	}
	return nil
}
