package watchdog

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	databasepkg "gateway-vpn/internal/db"
	"gateway-vpn/internal/firewall"
	"gateway-vpn/internal/platformexec"
)

const (
	unitControl       = "gateway-vpn.service"
	unitFirewall      = "gateway-vpn-firewall.service"
	unitFirewallGuard = "gateway-vpn-firewall-guard.service"
	unitBroker        = "gateway-vpn-network-broker.service"
	unitDNSMasq       = "gateway-vpn-dnsmasq.service"
	unitMihomo        = "gateway-vpn-mihomo.service"
)

var restartUnits = map[string][]string{
	ComponentControl:         {unitControl},
	ComponentSQLite:          {unitControl},
	ComponentFirewallGuard:   {unitFirewall, unitFirewallGuard},
	ComponentFirewallRuleset: {unitFirewall, unitFirewallGuard},
	ComponentNetworkBroker:   {unitBroker},
	ComponentDNSMasq:         {unitDNSMasq},
	ComponentMihomo:          {unitMihomo},
}

var maintenanceUnits = []struct {
	unit string
	code string
}{
	{"gateway-vpn-install-recovery.service", "INSTALL_RECOVERY_ACTIVE"},
	{"gateway-vpn-update.service", "UPDATE_ACTIVE"},
	{"gateway-vpn-update-recovery.service", "UPDATE_RECOVERY_ACTIVE"},
	{"gateway-vpn-update-finalize.service", "UPDATE_FINALIZE_ACTIVE"},
	{"gateway-vpn-update-resume.service", "UPDATE_RESUME_ACTIVE"},
	{"gateway-vpn-database-restore.service", "RESTORE_ACTIVE"},
	{"gateway-vpn-database-restore-boot.service", "RESTORE_RECOVERY_ACTIVE"},
	{"gateway-vpn-database-restore-dispatch.service", "RESTORE_DISPATCH_ACTIVE"},
	{"gateway-vpn-database-restore-resume.service", "RESTORE_RESUME_ACTIVE"},
	{"gateway-vpn-network-recovery.service", "NETWORK_RECOVERY_ACTIVE"},
}

type SystemProbe struct {
	Executor          platformexec.Executor
	Systemctl         string
	NFT               string
	IP                string
	GatewayBinary     string
	ConfigPath        string
	DatabasePath      string
	HeartbeatPath     string
	MihomoConfigPath  string
	MihomoTUN         string
	InstallMarkerPath string
	Now               func() time.Time

	quickCheckMutex sync.Mutex
	lastQuickCheck  time.Time
	quickCheckError error
}

func (probe *SystemProbe) Snapshot(ctx context.Context) (ProbeSnapshot, error) {
	if err := probe.validate(); err != nil {
		return ProbeSnapshot{}, err
	}
	now := probe.now()
	maintenance, maintenanceCode := probe.maintenance(ctx)
	databaseHealthy, connectivity, networkApply, databaseCode := probe.databaseHealth(ctx, now)
	if networkApply {
		maintenance, maintenanceCode = true, "NETWORK_APPLY_ACTIVE"
	}
	controlActive := probe.unitActive(ctx, unitControl)
	heartbeat, heartbeatErr := (HeartbeatFile{Path: probe.HeartbeatPath}).Read(now, 90*time.Second)
	controlHealthy := controlActive && heartbeatErr == nil
	controlCode := ""
	if !controlActive {
		controlCode = "CONTROL_UNIT_INACTIVE"
	} else if heartbeatErr != nil {
		controlCode = "CONTROL_HEARTBEAT_STALE"
	} else if heartbeat.ReconcileLastAt == "" {
		controlHealthy, controlCode = false, "RECONCILE_HEARTBEAT_MISSING"
	}
	items := []Observation{
		{ComponentID: ComponentControl, Applicable: true, Healthy: controlHealthy, ErrorCode: controlCode},
		{ComponentID: ComponentSQLite, Applicable: true, Healthy: databaseHealthy, ErrorCode: databaseCode},
		{ComponentID: ComponentFirewallGuard, Applicable: true, Healthy: probe.unitActive(ctx, unitFirewallGuard), ErrorCode: "FIREWALL_GUARD_INACTIVE"},
		{ComponentID: ComponentFirewallRuleset, Applicable: true, Healthy: probe.firewallHealthy(ctx), ErrorCode: "FIREWALL_RULESET_INVALID"},
		{ComponentID: ComponentNetworkBroker, Applicable: true, Healthy: probe.unitActive(ctx, unitBroker), ErrorCode: "NETWORK_BROKER_INACTIVE"},
	}
	dnsApplicable := regularFileExists("/etc/gateway-vpn/dnsmasq.conf")
	items = append(items, Observation{ComponentID: ComponentDNSMasq, Applicable: dnsApplicable, Healthy: !dnsApplicable || probe.unitActive(ctx, unitDNSMasq), ErrorCode: "DNSMASQ_INACTIVE"})
	mihomoApplicable := pathExists(probe.MihomoConfigPath)
	mihomoHealthy := !mihomoApplicable || probe.unitActive(ctx, unitMihomo) && probe.tunHealthy(ctx)
	items = append(items, Observation{ComponentID: ComponentMihomo, Applicable: mihomoApplicable, Healthy: mihomoHealthy, ErrorCode: "MIHOMO_OR_TUN_UNAVAILABLE"})
	resourceHealthy, resourceCode, details := systemResourceHealth(probe.DatabasePath)
	items = append(items, Observation{ComponentID: ComponentResources, Applicable: true, Healthy: resourceHealthy, ErrorCode: resourceCode, Details: details})
	for index := range items {
		if items[index].Healthy {
			items[index].ErrorCode = ""
		}
	}
	return ProbeSnapshot{
		ObservedAt: now, Maintenance: maintenance, MaintenanceCode: maintenanceCode,
		Connectivity: connectivity, Components: items,
	}, nil
}

func (probe *SystemProbe) Reconcile(ctx context.Context, componentID string) error {
	if err := probe.validate(); err != nil {
		return err
	}
	if !validComponentID(componentID) {
		return errors.New("unknown watchdog component")
	}
	// SIGHUP is a fixed, non-privilege-expanding request for the control plane
	// to run its existing idempotent routing/WireGuard/data-plane reconcile.
	return probe.run(ctx, probe.Systemctl, "kill", "--kill-who=main", "--signal=SIGHUP", unitControl)
}

func (probe *SystemProbe) FailClosed(ctx context.Context) error {
	if err := probe.validate(); err != nil {
		return err
	}
	return probe.run(ctx, probe.GatewayBinary, "firewall-boot", "--config", probe.ConfigPath, "--apply")
}

func (probe *SystemProbe) Restart(ctx context.Context, componentID string) error {
	if err := probe.validate(); err != nil {
		return err
	}
	units, exists := restartUnits[componentID]
	if !exists || len(units) == 0 {
		return errors.New("component has no fixed restart operation")
	}
	for _, unit := range units {
		if err := probe.run(ctx, probe.Systemctl, "restart", unit); err != nil {
			return fmt.Errorf("restart fixed component %s failed: %w", componentID, err)
		}
	}
	return nil
}

func (probe *SystemProbe) Reboot(ctx context.Context) error {
	if err := probe.validate(); err != nil {
		return err
	}
	return probe.run(ctx, probe.Systemctl, "--no-block", "reboot")
}

func (probe *SystemProbe) databaseHealth(ctx context.Context, now time.Time) (healthy bool, connectivity string, networkApply bool, errorCode string) {
	database, err := databasepkg.OpenReadOnly(ctx, probe.DatabasePath)
	if err != nil {
		return false, "UNKNOWN", false, "SQLITE_OPEN_FAILED"
	}
	defer database.Close()
	var gatewayState, pathState string
	if err := database.QueryRowContext(ctx, "SELECT gateway_state, path_state FROM runtime_state WHERE singleton_id=1").Scan(&gatewayState, &pathState); err != nil {
		return false, "UNKNOWN", false, "SQLITE_RUNTIME_READ_FAILED"
	}
	connectivity = "UNAVAILABLE"
	if pathState == "PATH_ACTIVE" {
		connectivity = "AVAILABLE"
	} else if gatewayState == "BOOTING" || gatewayState == "VERIFYING" || gatewayState == "VERIFYING_POLICY" || gatewayState == "SWITCHING" {
		connectivity = "CHECKING"
	}
	var active int
	if err := database.QueryRowContext(ctx, "SELECT COUNT(*) FROM network_apply_transactions WHERE state IN ('PREPARING','ARMED','APPLIED','CONFIRMING')").Scan(&active); err != nil {
		return false, connectivity, false, "SQLITE_TRANSACTION_READ_FAILED"
	}
	probe.quickCheckMutex.Lock()
	defer probe.quickCheckMutex.Unlock()
	if probe.lastQuickCheck.IsZero() || now.Sub(probe.lastQuickCheck) >= 15*time.Minute {
		probe.quickCheckError = databasepkg.QuickCheck(ctx, database)
		probe.lastQuickCheck = now
	}
	if probe.quickCheckError != nil {
		return false, connectivity, active != 0, "SQLITE_QUICK_CHECK_FAILED"
	}
	return true, connectivity, active != 0, ""
}

func (probe *SystemProbe) maintenance(ctx context.Context) (bool, string) {
	if pathExists(probe.InstallMarkerPath) || pathExists("/run/gateway-vpn-install-authorized") {
		return true, "INSTALL_ACTIVE"
	}
	for _, item := range maintenanceUnits {
		if probe.unitTransitioning(ctx, item.unit) {
			return true, item.code
		}
	}
	return false, ""
}

func (probe *SystemProbe) unitTransitioning(ctx context.Context, unit string) bool {
	if !fixedUnit(unit) {
		return false
	}
	result, err := probe.Executor.Run(ctx, platformexec.Request{Executable: probe.Systemctl, Arguments: []string{"show", "--property=ActiveState", "--value", unit}, MaxOutputBytes: 16 << 10})
	if err != nil {
		return false
	}
	switch strings.TrimSpace(result.Stdout) {
	case "activating", "deactivating", "reloading":
		return true
	default:
		return false
	}
}

func (probe *SystemProbe) firewallHealthy(ctx context.Context) bool {
	result, err := probe.Executor.Run(ctx, platformexec.Request{Executable: probe.NFT, Arguments: []string{"list", "table", "inet", firewall.TableName}, MaxOutputBytes: 256 << 10})
	if err != nil {
		return false
	}
	for _, marker := range []string{
		"table inet " + firewall.TableName, "firewall_schema_generation", "chain forward {", "policy drop", "gateway-vpn PATH_BLOCKED",
		"counter user_upload", "counter user_download", "counter service_upload", "counter service_download",
	} {
		if !strings.Contains(result.Stdout, marker) {
			return false
		}
	}
	return true
}

func (probe *SystemProbe) tunHealthy(ctx context.Context) bool {
	_, err := probe.Executor.Run(ctx, platformexec.Request{Executable: probe.IP, Arguments: []string{"link", "show", "dev", probe.MihomoTUN}, MaxOutputBytes: 32 << 10})
	return err == nil
}

func (probe *SystemProbe) unitActive(ctx context.Context, unit string) bool {
	if !fixedUnit(unit) {
		return false
	}
	_, err := probe.Executor.Run(ctx, platformexec.Request{Executable: probe.Systemctl, Arguments: []string{"is-active", "--quiet", unit}, MaxOutputBytes: 16 << 10})
	return err == nil
}

func fixedUnit(unit string) bool {
	for _, expected := range []string{unitControl, unitFirewall, unitFirewallGuard, unitBroker, unitDNSMasq, unitMihomo} {
		if unit == expected {
			return true
		}
	}
	for _, expected := range maintenanceUnits {
		if unit == expected.unit {
			return true
		}
	}
	return false
}

func (probe *SystemProbe) run(ctx context.Context, executable string, arguments ...string) error {
	operation, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	_, err := probe.Executor.Run(operation, platformexec.Request{Executable: executable, Arguments: append([]string(nil), arguments...), MaxOutputBytes: 64 << 10})
	return err
}

func (probe *SystemProbe) validate() error {
	if probe == nil || probe.Executor == nil || probe.Systemctl != "/usr/bin/systemctl" || probe.NFT != "/usr/sbin/nft" || probe.IP != "/usr/sbin/ip" || probe.GatewayBinary != "/opt/gateway-vpn/current/bin/gateway-vpn" || probe.ConfigPath != "/etc/gateway-vpn/config.yaml" || probe.DatabasePath != "/var/lib/gateway-vpn/state.db" || probe.HeartbeatPath != "/run/gateway-vpn-watchdog/control.json" || probe.MihomoConfigPath != "/var/lib/gateway-vpn/mihomo/active/config.yaml" || probe.InstallMarkerPath != "/var/lib/gateway-vpn-privileged/install-transactions/active" || probe.MihomoTUN == "" || len(probe.MihomoTUN) > 15 {
		return errors.New("complete fixed system watchdog probe configuration is required")
	}
	return nil
}

func (probe *SystemProbe) now() time.Time {
	if probe.Now != nil {
		return probe.Now().UTC()
	}
	return time.Now().UTC()
}

func regularFileExists(path string) bool {
	info, err := os.Lstat(path)
	return err == nil && info.Mode()&os.ModeSymlink == 0 && info.Mode().IsRegular()
}

func pathExists(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}
