package watchdog

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"gateway-vpn/internal/backup"
	"gateway-vpn/internal/dataplane"
	databasepkg "gateway-vpn/internal/db"
	loggingpkg "gateway-vpn/internal/logging"
	"gateway-vpn/internal/platformexec"
	"gateway-vpn/internal/routing"
	"gateway-vpn/internal/uplink"
	"gateway-vpn/internal/wgingress"
	wireguardpkg "gateway-vpn/internal/wireguard"
)

var nftIngressListenerTuple = regexp.MustCompile(`"([A-Za-z0-9_.:-]{1,15})"\s+\.\s+([0-9]{1,5})`)

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

func (probe *SystemProbe) loggingPipelineHealth(ctx context.Context) Observation {
	observation := Observation{ComponentID: ComponentLogging, Applicable: true, Details: map[string]any{}}
	if !probe.unitActive(ctx, unitJournald) {
		observation.ErrorCode = "NAMESPACED_JOURNALD_INACTIVE"
		return observation
	}
	database, err := databasepkg.OpenReadOnly(ctx, probe.DatabasePath)
	if err != nil {
		observation.ErrorCode = "LOGGING_DATABASE_UNAVAILABLE"
		return observation
	}
	defer database.Close()
	retention, err := (loggingpkg.RuntimeRepository{Database: database}).Get(ctx)
	if err != nil {
		observation.ErrorCode = "JOURNALD_RETENTION_STATE_UNAVAILABLE"
		return observation
	}
	observation.Details["retention_state"] = retention.State
	if retention.State != loggingpkg.RetentionApplied || retention.DesiredSHA256 == "" || retention.DesiredSHA256 != retention.AppliedSHA256 {
		observation.ErrorCode = "JOURNALD_RETENTION_DIVERGED"
		return observation
	}
	exportPolicy, err := (loggingpkg.ExportRepository{Database: database}).Get(ctx)
	if err != nil {
		observation.ErrorCode = "LOG_EXPORT_STATE_UNAVAILABLE"
		return observation
	}
	observation.Details["export_state"] = exportPolicy.State
	observation.Details["export_desired_generation"] = exportPolicy.DesiredGeneration
	observation.Details["export_applied_generation"] = exportPolicy.AppliedGeneration
	if !exportPolicy.Enabled {
		if exportPolicy.State != loggingpkg.ExportDisabled || exportPolicy.AppliedGeneration != exportPolicy.DesiredGeneration {
			observation.ErrorCode = "LOG_EXPORT_DISABLED_STATE_DIVERGED"
			return observation
		}
		observation.Healthy = true
		return observation
	}
	if exportPolicy.State != loggingpkg.ExportApplied || exportPolicy.AppliedGeneration != exportPolicy.DesiredGeneration {
		observation.ErrorCode = "LOG_EXPORT_GENERATION_DIVERGED"
		return observation
	}
	maximum := exportPolicy.MaxFileBytes
	if divided := exportPolicy.MaxTotalBytes / int64(len(exportPolicy.Categories)); divided < maximum {
		maximum = divided
	}
	for _, category := range exportPolicy.Categories {
		filename := filepath.Join(probe.LogExportRoot, "current", category+".log")
		info, err := os.Lstat(filename)
		if err != nil {
			observation.Details["invalid_category"] = category
			observation.Details["invalid_reason"] = "missing_or_unreadable"
			observation.ErrorCode = "LOG_EXPORT_FILE_INVALID"
			return observation
		}
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			observation.Details["invalid_category"] = category
			observation.Details["invalid_reason"] = "unsafe_file_type"
			observation.ErrorCode = "LOG_EXPORT_FILE_INVALID"
			return observation
		}
		if info.Size() <= 0 || info.Size() > maximum {
			observation.Details["invalid_category"] = category
			observation.Details["invalid_reason"] = "size_out_of_bounds"
			observation.Details["invalid_size_bytes"] = info.Size()
			observation.ErrorCode = "LOG_EXPORT_FILE_INVALID"
			return observation
		}
		if info.Mode().Perm() != 0o640 {
			observation.Details["invalid_category"] = category
			observation.Details["invalid_reason"] = "unsafe_permissions"
			observation.ErrorCode = "LOG_EXPORT_FILE_INVALID"
			return observation
		}
	}
	observation.Details["categories"] = len(exportPolicy.Categories)
	observation.Healthy = true
	return observation
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

func (probe *SystemProbe) managementFabricRouteHealth(ctx context.Context) Observation {
	observation := Observation{ComponentID: ComponentManagementFabric, Details: map[string]any{}}
	database, err := databasepkg.OpenReadOnly(ctx, probe.DatabasePath)
	if err != nil {
		observation.Applicable = true
		observation.ErrorCode = "MANAGEMENT_FABRIC_DATABASE_UNAVAILABLE"
		return observation
	}
	defer database.Close()
	var enabled int
	var desired, applied int64
	var state, lastError string
	if err := database.QueryRowContext(ctx, `
SELECT
  (SELECT COUNT(*)
     FROM management_links AS l
     JOIN management_sites AS s ON s.id=l.site_id
     JOIN vps_nodes AS v ON v.id=l.vps_id
    WHERE l.enabled=1 AND l.state NOT IN ('DISABLED','REVOKED')
      AND s.is_local=1 AND s.identity_state='ACTIVE'
      AND v.enabled=1 AND v.state!='REVOKED'),
  desired_generation,applied_generation,state,last_error_code
FROM management_fabric_generations WHERE singleton_id=1`).Scan(&enabled, &desired, &applied, &state, &lastError); err != nil {
		observation.Applicable = true
		observation.ErrorCode = "MANAGEMENT_FABRIC_STATE_UNAVAILABLE"
		return observation
	}
	observation.Details["enabled_links"] = enabled
	observation.Details["desired_generation"] = desired
	observation.Details["applied_generation"] = applied
	observation.Details["apply_state"] = state
	if lastError != "" {
		observation.Details["last_error_code"] = safeCode(lastError)
	}
	// A generation mismatch remains applicable even after the final link is
	// disabled: root must remove its old interface/routes/ACL projection.
	observation.Applicable = enabled > 0 || desired != applied
	if !observation.Applicable {
		observation.Healthy = true
		return observation
	}
	if probe.ManagementFabric == nil {
		observation.ErrorCode = "MANAGEMENT_FABRIC_BROKER_CLIENT_UNAVAILABLE"
		return observation
	}
	status, err := probe.ManagementFabric.ManagementFabricStatus(ctx)
	if err != nil {
		observation.ErrorCode = "MANAGEMENT_FABRIC_STATUS_UNAVAILABLE"
		return observation
	}
	if status.Reason != "" {
		observation.Details["runtime_reason"] = safeCode(status.Reason)
	}
	if status.NeedsApply || desired != applied {
		observation.ErrorCode = "MANAGEMENT_FABRIC_DIVERGED"
		return observation
	}
	observation.Healthy = true
	return observation
}

type wireGuardAdminLink struct {
	ID, InterfaceName, LocalAddress, LocalPublicKey, RemotePublicKey string
	SelectedUplinkID, UplinkState                                    string
}

func (probe *SystemProbe) wireGuardAdminHealth(ctx context.Context, now time.Time, policy Policy) Observation {
	observation := Observation{ComponentID: ComponentWireGuardAdmin, Details: map[string]any{}}
	database, err := databasepkg.OpenReadOnly(ctx, probe.DatabasePath)
	if err != nil {
		observation.Applicable = true
		observation.ErrorCode = "WG_ADMIN_DATABASE_UNAVAILABLE"
		return observation
	}
	defer database.Close()
	var desired, applied int64
	if err := database.QueryRowContext(ctx, `SELECT desired_generation,applied_generation FROM management_fabric_generations WHERE singleton_id=1`).Scan(&desired, &applied); err != nil {
		observation.Applicable = true
		observation.ErrorCode = "WG_ADMIN_GENERATION_UNAVAILABLE"
		return observation
	}
	rows, err := database.QueryContext(ctx, `
SELECT l.id,l.interface_name,l.local_address,l.local_public_key,l.remote_public_key,
       COALESCE(l.selected_uplink_id,''),COALESCE(u.state,'')
FROM management_links AS l
JOIN management_sites AS s ON s.id=l.site_id
JOIN vps_nodes AS v ON v.id=l.vps_id
LEFT JOIN uplinks AS u ON u.id=l.selected_uplink_id
WHERE l.enabled=1 AND l.state NOT IN ('DISABLED','REVOKED')
  AND s.is_local=1 AND s.identity_state='ACTIVE'
  AND v.enabled=1 AND v.state!='REVOKED'
ORDER BY l.slot,l.id`)
	if err != nil {
		observation.Applicable = true
		observation.ErrorCode = "WG_ADMIN_LINKS_UNAVAILABLE"
		return observation
	}
	links := make([]wireGuardAdminLink, 0)
	for rows.Next() {
		var link wireGuardAdminLink
		if err := rows.Scan(&link.ID, &link.InterfaceName, &link.LocalAddress, &link.LocalPublicKey, &link.RemotePublicKey, &link.SelectedUplinkID, &link.UplinkState); err != nil {
			rows.Close()
			observation.Applicable = true
			observation.ErrorCode = "WG_ADMIN_LINK_STATE_INVALID"
			return observation
		}
		links = append(links, link)
	}
	if err := rows.Close(); err != nil {
		observation.Applicable = true
		observation.ErrorCode = "WG_ADMIN_LINKS_UNAVAILABLE"
		return observation
	}
	observation.Applicable = len(links) > 0
	observation.Details["enabled_links"] = len(links)
	if !observation.Applicable {
		observation.Healthy = true
		return observation
	}
	// The route/ACL component owns convergence. Avoid racing it or issuing two
	// root syncs while a newly edited generation is still being applied.
	if desired != applied {
		observation.Details["awaiting_management_fabric_generation"] = desired
		observation.Healthy = true
		return observation
	}
	localFailures := make([]string, 0)
	externalFailures := make([]string, 0)
	handshakeAges := make(map[string]int64, len(links))
	for _, link := range links {
		if link.SelectedUplinkID == "" {
			localFailures = append(localFailures, link.ID+":UPLINK_SELECTION_MISSING")
			continue
		}
		if !probe.wireGuardAdminLocalStateHealthy(ctx, link) {
			localFailures = append(localFailures, link.ID+":LOCAL_RUNTIME_DRIFT")
			continue
		}
		if link.UplinkState != "UPLINK_READY" {
			externalFailures = append(externalFailures, link.ID+":UPLINK_NOT_READY")
			continue
		}
		handshakes, err := probe.fixedOutput(ctx, probe.WG, "show", link.InterfaceName, "latest-handshakes")
		if err != nil {
			localFailures = append(localFailures, link.ID+":HANDSHAKE_READ_FAILED")
			continue
		}
		latest := peerHandshake(handshakes, link.RemotePublicKey)
		if latest.IsZero() {
			externalFailures = append(externalFailures, link.ID+":NEVER_CONNECTED")
			continue
		}
		age := now.Sub(latest)
		if age < 0 {
			age = 0
		}
		handshakeAges[link.ID] = int64(age / time.Second)
		if age > time.Duration(policy.WireGuardHandshakeStaleSeconds)*time.Second {
			externalFailures = append(externalFailures, link.ID+":HANDSHAKE_STALE")
		}
	}
	observation.Details["handshake_age_seconds"] = handshakeAges
	if len(localFailures) != 0 {
		observation.Details["local_failures"] = localFailures
		observation.ErrorCode = "WG_ADMIN_LOCAL_DRIFT"
		return observation
	}
	if len(externalFailures) != 0 {
		observation.Details["external_failures"] = externalFailures
		observation.Classification = ClassificationExternal
		observation.ErrorCode = "WG_ADMIN_EXTERNAL_OUTAGE"
		return observation
	}
	observation.Healthy = true
	return observation
}

func (probe *SystemProbe) wireGuardAdminLocalStateHealthy(ctx context.Context, link wireGuardAdminLink) bool {
	links, err := probe.fixedOutput(ctx, probe.IP, "-json", "link", "show", "dev", link.InterfaceName)
	if err != nil || !jsonFlagsContain(links, "UP") {
		return false
	}
	addresses, err := probe.fixedOutput(ctx, probe.IP, "-json", "-4", "address", "show", "dev", link.InterfaceName)
	if err != nil || !jsonAddressContains(addresses, link.LocalAddress+"/32") {
		return false
	}
	publicKey, err := probe.fixedOutput(ctx, probe.WG, "show", link.InterfaceName, "public-key")
	if err != nil || strings.TrimSpace(publicKey) != link.LocalPublicKey {
		return false
	}
	peers, err := probe.fixedOutput(ctx, probe.WG, "show", link.InterfaceName, "peers")
	return err == nil && exactLineSet(peers, []string{link.RemotePublicKey})
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
	var subnet, publicKey string
	var listenPort int
	err = database.QueryRowContext(ctx, `
SELECT COUNT(*),
       COALESCE(SUM(CASE WHEN s.interface_name!='wg-ingress' OR r.applied_generation!=r.desired_generation OR r.state!='ACTIVE' THEN 1 ELSE 0 END), 0),
       COALESCE(MAX(s.subnet_cidr), ''), COALESCE(MAX(s.listen_port), 0), COALESCE(MAX(s.public_key), '')
FROM wireguard_ingress_servers AS s
LEFT JOIN wireguard_ingress_runtime AS r ON r.server_id=s.id
WHERE s.enabled=1`).Scan(&enabled, &divergent, &subnet, &listenPort, &publicKey)
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
	prefix, err := netip.ParsePrefix(subnet)
	if err != nil || !prefix.Addr().Is4() || prefix.Bits() < 16 || prefix.Bits() > 29 || !wgingress.ValidKey(publicKey) || listenPort < 1 || listenPort > 65535 {
		observation.ErrorCode = "WG_INGRESS_CONFIG_INVALID"
		return observation
	}
	serverAddress := prefix.Addr().Next().String() + "/" + strconv.Itoa(prefix.Bits())
	links, err := probe.fixedOutput(ctx, probe.IP, "-json", "link", "show", "dev", wgingress.DefaultInterfaceName)
	if err != nil || !jsonFlagsContain(links, "UP") {
		observation.ErrorCode = "WG_INGRESS_INTERFACE_MISSING_OR_DOWN"
		return observation
	}
	addresses, err := probe.fixedOutput(ctx, probe.IP, "-json", "-4", "address", "show", "dev", wgingress.DefaultInterfaceName)
	if err != nil || !jsonAddressContains(addresses, serverAddress) {
		observation.ErrorCode = "WG_INGRESS_ADDRESS_MISMATCH"
		return observation
	}
	observedPublicKey, err := probe.fixedOutput(ctx, probe.WG, "show", wgingress.DefaultInterfaceName, "public-key")
	if err != nil || strings.TrimSpace(observedPublicKey) != publicKey {
		observation.ErrorCode = "WG_INGRESS_SERVER_KEY_MISMATCH"
		return observation
	}
	observedPort, err := probe.fixedOutput(ctx, probe.WG, "show", wgingress.DefaultInterfaceName, "listen-port")
	if err != nil || strings.TrimSpace(observedPort) != strconv.Itoa(listenPort) {
		observation.ErrorCode = "WG_INGRESS_LISTEN_PORT_MISMATCH"
		return observation
	}
	expectedPeers, expectedRoutes, err := ingressPeerContour(ctx, database)
	if err != nil {
		observation.ErrorCode = "WG_INGRESS_PEER_STATE_UNAVAILABLE"
		return observation
	}
	observedPeers, err := probe.fixedOutput(ctx, probe.WG, "show", wgingress.DefaultInterfaceName, "peers")
	if err != nil || !exactLineSet(observedPeers, expectedPeers) {
		observation.ErrorCode = "WG_INGRESS_PEER_CONFIG_MISMATCH"
		return observation
	}
	observedRoutes, err := probe.fixedOutput(ctx, probe.IP, "-N", "-json", "-4", "route", "show", "dev", wgingress.DefaultInterfaceName, "protocol", strconv.Itoa(routing.OwnedProtocol))
	if err != nil || !jsonRouteSetExact(observedRoutes, wgingress.DefaultInterfaceName, routing.OwnedProtocol, expectedRoutes) {
		observation.ErrorCode = "WG_INGRESS_PEER_ROUTE_MISMATCH"
		return observation
	}
	expectedListeners, err := ingressListenerContour(ctx, database, listenPort)
	if err != nil || len(expectedListeners) == 0 {
		observation.ErrorCode = "WG_INGRESS_LISTENER_STATE_UNAVAILABLE"
		return observation
	}
	listenerSet, err := probe.fixedOutput(ctx, probe.NFT, "list", "set", "inet", "gateway_vpn", "wireguard_ingress_listeners")
	if err != nil || !nftListenerSetExact(listenerSet, expectedListeners) {
		observation.ErrorCode = "WG_INGRESS_FIREWALL_LISTENER_MISMATCH"
		return observation
	}
	observation.Details["enabled_peers"] = len(expectedPeers)
	observation.Details["behind_subnets"] = len(expectedRoutes)
	observation.Details["listen_interfaces"] = len(expectedListeners)
	observation.Healthy = true
	return observation
}

func ingressPeerContour(ctx context.Context, database *sql.DB) ([]string, map[string]struct{}, error) {
	rows, err := database.QueryContext(ctx, `
SELECT p.public_key, COALESCE(r.cidr, '')
FROM wireguard_ingress_peers AS p
LEFT JOIN wireguard_ingress_peer_routes AS r ON r.peer_id=p.id AND r.direction='INGRESS'
WHERE p.enabled=1 AND p.revoked_at IS NULL
ORDER BY p.public_key, r.cidr`)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	peerSet := map[string]struct{}{}
	routes := map[string]struct{}{}
	for rows.Next() {
		var key, route string
		if err := rows.Scan(&key, &route); err != nil || !wgingress.ValidKey(key) {
			return nil, nil, errors.New("stored WireGuard ingress peer contour is invalid")
		}
		peerSet[key] = struct{}{}
		if route != "" {
			prefix, parseErr := netip.ParsePrefix(route)
			if parseErr != nil || !prefix.Addr().Is4() || prefix.String() != route {
				return nil, nil, errors.New("stored WireGuard ingress route is invalid")
			}
			routes[route] = struct{}{}
		}
	}
	peers := make([]string, 0, len(peerSet))
	for key := range peerSet {
		peers = append(peers, key)
	}
	sort.Strings(peers)
	return peers, routes, rows.Err()
}

func ingressListenerContour(ctx context.Context, database *sql.DB, port int) (map[string]int, error) {
	rows, err := database.QueryContext(ctx, `
SELECT n.current_ifname
FROM wireguard_ingress_listen_interfaces AS l
JOIN network_interfaces AS n ON n.id=l.network_interface_id
JOIN wireguard_ingress_servers AS s ON s.id=l.server_id
WHERE s.enabled=1 ORDER BY l.priority`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := map[string]int{}
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil || name == "" || len(name) > 15 {
			return nil, errors.New("stored WireGuard ingress listener is invalid")
		}
		if _, duplicate := result[name]; duplicate {
			return nil, errors.New("stored WireGuard ingress listener is duplicated")
		}
		result[name] = port
	}
	return result, rows.Err()
}

func exactLineSet(output string, expected []string) bool {
	actual := make([]string, 0)
	for _, line := range strings.Split(strings.TrimSpace(output), "\n") {
		if value := strings.TrimSpace(line); value != "" {
			actual = append(actual, value)
		}
	}
	sort.Strings(actual)
	return slices.Equal(actual, expected)
}

func nftListenerSetExact(output string, expected map[string]int) bool {
	matches := nftIngressListenerTuple.FindAllStringSubmatch(output, -1)
	if len(matches) != len(expected) {
		return false
	}
	seen := map[string]struct{}{}
	for _, match := range matches {
		port, err := strconv.Atoi(match[2])
		if err != nil || expected[match[1]] != port {
			return false
		}
		if _, duplicate := seen[match[1]]; duplicate {
			return false
		}
		seen[match[1]] = struct{}{}
	}
	return len(seen) == len(expected)
}

func jsonRouteSetExact(output, device string, protocol int, expected map[string]struct{}) bool {
	var rows []map[string]json.RawMessage
	if json.Unmarshal([]byte(output), &rows) != nil || len(rows) != len(expected) {
		return false
	}
	seen := map[string]struct{}{}
	for _, row := range rows {
		var destination, observedDevice string
		if json.Unmarshal(row["dst"], &destination) != nil || json.Unmarshal(row["dev"], &observedDevice) != nil || observedDevice != device {
			return false
		}
		observedProtocol, ok := jsonUint32(row["protocol"])
		if !ok || observedProtocol != uint32(protocol) {
			return false
		}
		if _, ok := expected[destination]; !ok {
			return false
		}
		seen[destination] = struct{}{}
	}
	return len(seen) == len(expected)
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
