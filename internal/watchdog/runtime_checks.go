package watchdog

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"gateway-vpn/internal/backup"
	"gateway-vpn/internal/dataplane"
	databasepkg "gateway-vpn/internal/db"
	"gateway-vpn/internal/platformexec"
	"gateway-vpn/internal/routing"
	"gateway-vpn/internal/uplink"
	wireguardpkg "gateway-vpn/internal/wireguard"
)

func workerRuntimeHealth(heartbeat ControlHeartbeat, heartbeatErr error, now time.Time, policy Policy) (bool, string, map[string]any) {
	details := map[string]any{"workers_total": len(heartbeat.Workers), "stale_workers": []string{}}
	if heartbeatErr != nil {
		return false, "WORKER_HEARTBEAT_UNAVAILABLE", details
	}
	stale := make([]string, 0)
	for id, progress := range heartbeat.Workers {
		last, err := time.Parse(time.RFC3339Nano, progress.LastProgressAt)
		if err != nil {
			if progress.Critical {
				stale = append(stale, id)
			}
			continue
		}
		maximum := time.Duration(progress.MaximumSilenceSeconds) * time.Second
		minimum := time.Duration(policy.WorkerStaleSeconds) * time.Second
		if maximum < minimum {
			maximum = minimum
		}
		if progress.Critical && now.Sub(last) > maximum {
			stale = append(stale, id)
		}
	}
	details["stale_workers"] = stale
	if len(stale) != 0 || !heartbeat.WorkersOK {
		return false, "CRITICAL_WORKER_STALE", details
	}
	return true, "", details
}

func (probe *SystemProbe) policyRoutingHealth(ctx context.Context) (bool, string, map[string]any) {
	details := map[string]any{}
	database, err := databasepkg.OpenReadOnly(ctx, probe.DatabasePath)
	if err != nil {
		return false, "ROUTING_DATABASE_UNAVAILABLE", details
	}
	defer database.Close()
	backend := dataplane.RoutingBackend{
		Uplinks: uplink.NewRepository(database, probe.RoutingTableStart, probe.FwmarkStart), Executor: probe.Executor, IP: probe.IP,
		LANPrefix: probe.LANPrefix, WireGuardPrefix: probe.WireGuardPrefix,
		BootstrapDNS:      append([]string(nil), probe.BootstrapDNS...),
		RoutingTableStart: probe.RoutingTableStart, FwmarkStart: probe.FwmarkStart,
	}
	result, err := backend.CheckRouting(ctx)
	details["ready_uplinks"] = result.ReadyUplinks
	details["owned_rules"] = result.Rules
	details["owned_routes"] = result.Routes
	if err != nil {
		return false, "POLICY_ROUTING_DIVERGED", details
	}
	return true, "", details
}

func (probe *SystemProbe) wireGuardManagementHealth(ctx context.Context, now time.Time, policy Policy) Observation {
	observation := Observation{ComponentID: ComponentWireGuardMgmt, Applicable: pathExists(probe.WireGuardConfigPath), Details: map[string]any{}}
	if !observation.Applicable {
		observation.Healthy = true
		return observation
	}
	configuration, err := wireguardpkg.LoadConfig(probe.WireGuardConfigPath)
	if err != nil {
		observation.ErrorCode = "WG_CONFIG_INVALID"
		return observation
	}
	database, err := databasepkg.OpenReadOnly(ctx, probe.DatabasePath)
	if err != nil {
		observation.ErrorCode = "WG_RUNTIME_DATABASE_UNAVAILABLE"
		return observation
	}
	defer database.Close()
	var readyUplinks int
	if err := database.QueryRowContext(ctx, "SELECT COUNT(*) FROM uplinks WHERE enabled=1 AND state='UPLINK_READY'").Scan(&readyUplinks); err != nil {
		observation.ErrorCode = "WG_UPLINK_STATE_UNAVAILABLE"
		return observation
	}
	observation.Details["ready_uplinks"] = readyUplinks
	if readyUplinks == 0 {
		observation.Classification = ClassificationExternal
		observation.ErrorCode = "WG_NO_READY_UPLINK"
		return observation
	}
	runtimeState, err := (wireguardpkg.RuntimeStore{Database: database}).Get(ctx)
	if err != nil {
		observation.ErrorCode = "WG_RUNTIME_STATE_INVALID"
		return observation
	}
	if runtimeState.RouteFwmark < probe.FwmarkStart || runtimeState.RouteTableID < probe.RoutingTableStart || runtimeState.RouteInterface == "" || runtimeState.EndpointIP == "" {
		observation.ErrorCode = "WG_ROUTE_STATE_MISSING"
		return observation
	}
	endpoint, err := netip.ParseAddr(runtimeState.EndpointIP)
	if err != nil || !endpoint.Is4() || !endpoint.IsGlobalUnicast() || endpoint.IsPrivate() {
		observation.ErrorCode = "WG_ENDPOINT_STATE_INVALID"
		return observation
	}
	if !probe.wireGuardLinkAndAddressHealthy(ctx, configuration) {
		observation.ErrorCode = "WG_INTERFACE_OR_ADDRESS_INVALID"
		return observation
	}
	if !probe.wireGuardManagementRouteHealthy(ctx) {
		observation.ErrorCode = "WG_MANAGEMENT_ROUTE_MISSING"
		return observation
	}
	peers, err := probe.fixedOutput(ctx, probe.WG, "show", "wg-mgmt", "peers")
	if err != nil || !containsExactLine(peers, configuration.PeerPublicKey) {
		observation.ErrorCode = "WG_PEER_CONFIG_MISMATCH"
		return observation
	}
	fwmark, err := probe.fixedOutput(ctx, probe.WG, "show", "wg-mgmt", "fwmark")
	if err != nil || !sameFwmark(strings.TrimSpace(fwmark), runtimeState.RouteFwmark) {
		observation.ErrorCode = "WG_FWMARK_MISMATCH"
		return observation
	}
	if !probe.wireGuardEndpointRouteHealthy(ctx, runtimeState, endpoint.String()) {
		observation.ErrorCode = "WG_ENDPOINT_ROUTE_MISMATCH"
		return observation
	}
	handshakes, err := probe.fixedOutput(ctx, probe.WG, "show", "wg-mgmt", "latest-handshakes")
	if err != nil {
		observation.ErrorCode = "WG_HANDSHAKE_READ_FAILED"
		return observation
	}
	latest := peerHandshake(handshakes, configuration.PeerPublicKey)
	if latest.IsZero() || now.Sub(latest) > time.Duration(policy.WireGuardHandshakeStaleSeconds)*time.Second {
		observation.Classification = ClassificationExternal
		observation.ErrorCode = "WG_VPS_HANDSHAKE_STALE"
		if !latest.IsZero() {
			observation.Details["handshake_age_seconds"] = int64(now.Sub(latest) / time.Second)
		}
		return observation
	}
	observation.Details["handshake_age_seconds"] = int64(now.Sub(latest) / time.Second)
	observation.Healthy = true
	return observation
}

func (probe *SystemProbe) wireGuardIngressHealth(ctx context.Context) Observation {
	observation := Observation{ComponentID: ComponentWireGuardIngress, Details: map[string]any{}}
	database, err := databasepkg.OpenReadOnly(ctx, probe.DatabasePath)
	if err != nil {
		observation.Applicable = true
		observation.ErrorCode = "WG_INGRESS_DATABASE_UNAVAILABLE"
		return observation
	}
	defer database.Close()
	var enabled, divergent int
	err = database.QueryRowContext(ctx, `
SELECT COUNT(*), COALESCE(SUM(CASE WHEN s.interface_name!='wg-ingress' OR r.applied_generation!=r.desired_generation OR r.state!='ACTIVE' THEN 1 ELSE 0 END), 0)
FROM wireguard_ingress_servers AS s
LEFT JOIN wireguard_ingress_runtime AS r ON r.server_id=s.id
WHERE s.enabled=1`).Scan(&enabled, &divergent)
	if err != nil {
		observation.Applicable = true
		observation.ErrorCode = "WG_INGRESS_STATE_UNAVAILABLE"
		return observation
	}
	observation.Applicable = enabled != 0
	observation.Details["enabled_servers"] = enabled
	if enabled == 0 {
		observation.Healthy = true
		return observation
	}
	if divergent != 0 {
		observation.ErrorCode = "WG_INGRESS_GENERATION_DIVERGED"
		return observation
	}
	if _, err := probe.fixedOutput(ctx, probe.IP, "link", "show", "dev", "wg-ingress"); err != nil {
		observation.ErrorCode = "WG_INGRESS_INTERFACE_MISSING"
		return observation
	}
	observation.Healthy = true
	return observation
}

func (probe *SystemProbe) convergenceHealth(ctx context.Context, now time.Time, policy Policy) (bool, string, map[string]any) {
	details := map[string]any{}
	database, err := databasepkg.OpenReadOnly(ctx, probe.DatabasePath)
	if err != nil {
		return false, "CONVERGENCE_DATABASE_UNAVAILABLE", details
	}
	defer database.Close()
	cutoff := now.Add(-time.Duration(policy.WorkerStaleSeconds) * time.Second).Format(time.RFC3339Nano)
	var pending, stale, ingress int
	if err := database.QueryRowContext(ctx, `
SELECT
  COALESCE(SUM(CASE WHEN desired_generation!=observed_generation THEN 1 ELSE 0 END), 0),
  COALESCE(SUM(CASE WHEN desired_generation!=observed_generation AND state='UPLINK_READY' AND datetime(updated_at)<datetime(?) THEN 1 ELSE 0 END), 0)
FROM uplinks WHERE enabled=1`, cutoff).Scan(&pending, &stale); err != nil {
		return false, "CONVERGENCE_UPLINK_READ_FAILED", details
	}
	if err := database.QueryRowContext(ctx, `
SELECT COUNT(*) FROM wireguard_ingress_servers AS s
JOIN wireguard_ingress_runtime AS r ON r.server_id=s.id
WHERE s.enabled=1 AND r.desired_generation!=r.applied_generation`).Scan(&ingress); err != nil {
		return false, "CONVERGENCE_INGRESS_READ_FAILED", details
	}
	details["pending_uplinks"] = pending
	details["stale_ready_uplinks"] = stale
	details["pending_wireguard_ingress"] = ingress
	if stale != 0 || ingress != 0 {
		return false, "CONFIGURATION_GENERATION_STALE", details
	}
	return true, "", details
}

func (probe *SystemProbe) databaseBackupHealth(ctx context.Context, now time.Time, policy Policy) (bool, string, map[string]any) {
	details := map[string]any{}
	walBytes, err := safeRegularFileSize(probe.DatabasePath + "-wal")
	if err != nil {
		return false, "DATABASE_WAL_UNSAFE", details
	}
	details["wal_bytes"] = walBytes
	if walBytes > policy.DatabaseWALMaxBytes {
		return false, "DATABASE_WAL_TOO_LARGE", details
	}
	root := filepath.Join(filepath.Dir(probe.DatabasePath), "backups", "snapshots")
	snapshot, err := backup.ReadOnlyLatest(ctx, root, backup.KindDaily)
	if err != nil {
		database, openErr := databasepkg.OpenReadOnly(ctx, probe.DatabasePath)
		var installedAt string
		if openErr == nil {
			openErr = database.QueryRowContext(ctx, "SELECT MIN(applied_at) FROM schema_migrations").Scan(&installedAt)
			database.Close()
		}
		installed, parseErr := time.Parse(time.RFC3339Nano, installedAt)
		if openErr == nil && parseErr == nil && now.Sub(installed) <= time.Duration(policy.BackupMaxAgeHours)*time.Hour {
			details["initial_backup_pending"] = true
			return true, "", details
		}
		return false, "VERIFIED_DAILY_BACKUP_MISSING", details
	}
	created, err := time.Parse(time.RFC3339Nano, snapshot.Manifest.CreatedAt)
	if err != nil {
		return false, "BACKUP_TIMESTAMP_INVALID", details
	}
	age := now.Sub(created)
	details["latest_daily_age_seconds"] = int64(age / time.Second)
	details["latest_daily_schema_version"] = snapshot.Manifest.SchemaVersion
	if age > time.Duration(policy.BackupMaxAgeHours)*time.Hour {
		return false, "VERIFIED_DAILY_BACKUP_STALE", details
	}
	return true, "", details
}

func (probe *SystemProbe) wireGuardLinkAndAddressHealthy(ctx context.Context, configuration wireguardpkg.Config) bool {
	links, err := probe.fixedOutput(ctx, probe.IP, "-json", "link", "show", "dev", "wg-mgmt")
	if err != nil || !jsonFlagsContain(links, "UP") {
		return false
	}
	addresses, err := probe.fixedOutput(ctx, probe.IP, "-json", "-4", "address", "show", "dev", "wg-mgmt")
	return err == nil && jsonAddressContains(addresses, configuration.Address)
}

func (probe *SystemProbe) wireGuardManagementRouteHealthy(ctx context.Context) bool {
	output, err := probe.fixedOutput(ctx, probe.IP, "-N", "-json", "-4", "route", "show", "10.80.0.0/24")
	return err == nil && jsonRouteContains(output, "10.80.0.0/24", "wg-mgmt", routing.OwnedProtocol, 0, "")
}

func (probe *SystemProbe) wireGuardEndpointRouteHealthy(ctx context.Context, state wireguardpkg.RuntimeState, endpoint string) bool {
	output, err := probe.fixedOutput(ctx, probe.IP, "-N", "-json", "-4", "route", "get", endpoint, "mark", fmt.Sprintf("%#x", state.RouteFwmark))
	return err == nil && jsonRouteContains(output, endpoint, state.RouteInterface, 0, state.RouteTableID, state.RouteGateway)
}

func (probe *SystemProbe) fixedOutput(ctx context.Context, executable string, arguments ...string) (string, error) {
	operation, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	result, err := probe.Executor.Run(operation, platformexec.Request{Executable: executable, Arguments: arguments, MaxOutputBytes: 256 << 10})
	return result.Stdout, err
}

func containsExactLine(output, expected string) bool {
	for _, line := range strings.Split(strings.TrimSpace(output), "\n") {
		if strings.TrimSpace(line) == expected {
			return true
		}
	}
	return false
}

func sameFwmark(value string, expected uint32) bool {
	parsed, err := strconv.ParseUint(strings.TrimPrefix(strings.ToLower(value), "0x"), 16, 32)
	return err == nil && uint32(parsed) == expected
}

func peerHandshake(output, peer string) time.Time {
	for _, line := range strings.Split(strings.TrimSpace(output), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 || fields[0] != peer {
			continue
		}
		seconds, err := strconv.ParseInt(fields[1], 10, 64)
		if err == nil && seconds > 0 {
			return time.Unix(seconds, 0).UTC()
		}
	}
	return time.Time{}
}

func jsonFlagsContain(output, expected string) bool {
	var rows []struct {
		Flags []string `json:"flags"`
	}
	if json.Unmarshal([]byte(output), &rows) != nil {
		return false
	}
	for _, row := range rows {
		for _, flag := range row.Flags {
			if flag == expected {
				return true
			}
		}
	}
	return false
}

func jsonAddressContains(output, expected string) bool {
	prefix, err := netip.ParsePrefix(expected)
	if err != nil {
		return false
	}
	var rows []struct {
		Addresses []struct {
			Local     string `json:"local"`
			PrefixLen int    `json:"prefixlen"`
		} `json:"addr_info"`
	}
	if json.Unmarshal([]byte(output), &rows) != nil {
		return false
	}
	for _, row := range rows {
		for _, address := range row.Addresses {
			if address.Local == prefix.Addr().String() && address.PrefixLen == prefix.Bits() {
				return true
			}
		}
	}
	return false
}

func jsonRouteContains(output, destination, device string, protocol int, table uint32, gateway string) bool {
	var rows []map[string]json.RawMessage
	if json.Unmarshal([]byte(output), &rows) != nil {
		return false
	}
	for _, row := range rows {
		var dst, dev, via string
		_ = json.Unmarshal(row["dst"], &dst)
		_ = json.Unmarshal(row["dev"], &dev)
		_ = json.Unmarshal(row["gateway"], &via)
		if destination != "" && dst != destination || dev != device || gateway != "" && via != gateway {
			continue
		}
		if protocol != 0 {
			observed, ok := jsonUint32(row["protocol"])
			if !ok || observed != uint32(protocol) {
				continue
			}
		}
		if table != 0 {
			observed, ok := jsonUint32(row["table"])
			if !ok || observed != table {
				continue
			}
		}
		return true
	}
	return false
}

func jsonUint32(raw json.RawMessage) (uint32, bool) {
	var numeric uint32
	if json.Unmarshal(raw, &numeric) == nil {
		return numeric, true
	}
	var textual string
	if json.Unmarshal(raw, &textual) != nil || textual == "" {
		return 0, false
	}
	parsed, err := strconv.ParseUint(textual, 10, 32)
	return uint32(parsed), err == nil
}

func safeRegularFileSize(filename string) (int64, error) {
	info, err := os.Lstat(filename)
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return 0, errors.New("file is unavailable or unsafe")
	}
	return info.Size(), nil
}
