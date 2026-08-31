package db

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"testing/fstest"

	"gateway-vpn/migrations"
)

func TestEnsureExactModeSkipsUnneededChmod(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows does not expose verifiable POSIX modes")
	}
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	called := false
	refuseChmod := func(string, os.FileMode) error {
		called = true
		return errors.New("chmod must not run")
	}
	if err := ensureExactMode(directory, 0o700, true, refuseChmod); err != nil || called {
		t.Fatalf("private directory mode convergence = %v, chmod called=%t", err, called)
	}

	file := filepath.Join(directory, "state.db")
	if err := os.WriteFile(file, []byte("fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(file, 0o600); err != nil {
		t.Fatal(err)
	}
	called = false
	if err := ensureExactMode(file, 0o600, false, refuseChmod); err != nil || called {
		t.Fatalf("private file mode convergence = %v, chmod called=%t", err, called)
	}
}

func TestEnsureExactModeCorrectsUnsafeModeAndRejectsUnsafeType(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows does not expose verifiable POSIX modes")
	}
	directory := t.TempDir()
	file := filepath.Join(directory, "state.db")
	if err := os.WriteFile(file, []byte("fixture"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(file, 0o644); err != nil {
		t.Fatal(err)
	}
	called := false
	if err := ensureExactMode(file, 0o600, false, func(path string, mode os.FileMode) error {
		called = true
		return os.Chmod(path, mode)
	}); err != nil || !called {
		t.Fatalf("unsafe file mode convergence = %v, chmod called=%t", err, called)
	}
	if err := ensureExactMode(directory, 0o600, false, os.Chmod); err == nil {
		t.Fatal("directory accepted as database file")
	}
}

func TestOpenConfiguresSafetyPragmas(t *testing.T) {
	ctx := context.Background()
	database, err := Open(ctx, OpenOptions{Path: filepath.Join(t.TempDir(), "state.db")})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer database.Close()

	checks := []struct {
		pragma string
		want   string
	}{
		{"PRAGMA journal_mode", "wal"},
		{"PRAGMA foreign_keys", "1"},
		{"PRAGMA busy_timeout", "5000"},
		{"PRAGMA synchronous", "1"},
	}
	for _, check := range checks {
		var got string
		if err := database.QueryRowContext(ctx, check.pragma).Scan(&got); err != nil {
			t.Fatalf("%s error = %v", check.pragma, err)
		}
		if got != check.want {
			t.Errorf("%s = %q, want %q", check.pragma, got, check.want)
		}
	}
}

func TestOpenReadOnlyCannotCreateOrMutateDatabase(t *testing.T) {
	ctx := context.Background()
	missing := filepath.Join(t.TempDir(), "missing.db")
	if _, err := OpenReadOnly(ctx, missing); err == nil {
		t.Fatal("OpenReadOnly(missing) error = nil")
	}
	path := filepath.Join(t.TempDir(), "state.db")
	writable, err := Open(ctx, OpenOptions{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	if err := Migrate(ctx, writable); err != nil {
		t.Fatal(err)
	}
	writable.Close()
	readOnly, err := OpenReadOnly(ctx, path)
	if err != nil {
		t.Fatalf("OpenReadOnly() error = %v", err)
	}
	defer readOnly.Close()
	if _, err := readOnly.ExecContext(ctx, "UPDATE runtime_state SET gateway_state='ACTIVE'"); err == nil {
		t.Fatal("read-only database accepted UPDATE")
	}
	version, err := ReadSchemaVersion(ctx, readOnly)
	if err != nil || version != 32 {
		t.Fatalf("ReadSchemaVersion(read-only) = %d, %v", version, err)
	}
	if err := ForeignKeyCheck(ctx, readOnly); err != nil {
		t.Fatalf("ForeignKeyCheck(read-only) error = %v", err)
	}
}

func TestReadSchemaVersionDoesNotCreateMigrationTable(t *testing.T) {
	ctx := context.Background()
	database, err := Open(ctx, OpenOptions{Path: filepath.Join(t.TempDir(), "empty.db")})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	version, err := ReadSchemaVersion(ctx, database)
	if err != nil || version != 0 {
		t.Fatalf("ReadSchemaVersion(empty) = %d, %v", version, err)
	}
	var count int
	if err := database.QueryRowContext(ctx, "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='schema_migrations'").Scan(&count); err != nil || count != 0 {
		t.Fatalf("migration table count = %d, %v", count, err)
	}
	latest, err := LatestSchemaVersion()
	if err != nil || latest != 32 {
		t.Fatalf("LatestSchemaVersion() = %d, %v", latest, err)
	}
}

func TestMigrateCreatesInitialSchema(t *testing.T) {
	ctx := context.Background()
	database, err := Open(ctx, OpenOptions{Path: filepath.Join(t.TempDir(), "state.db")})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer database.Close()

	if err := Migrate(ctx, database); err != nil {
		t.Fatalf("Migrate() error = %v", err)
	}
	if err := QuickCheck(ctx, database); err != nil {
		t.Fatalf("QuickCheck() error = %v", err)
	}
	if err := IntegrityCheck(ctx, database); err != nil {
		t.Fatalf("IntegrityCheck() error = %v", err)
	}

	wantTables := []string{
		"bypass_probe_targets",
		"access_methods",
		"access_policy",
		"access_selection_runtime",
		"direct_modem_paths",
		"direct_path_target_results",
		"events",
		"health_samples",
		"modems",
		"node_matchers",
		"operation_steps",
		"operations",
		"nodes",
		"network_apply_transactions",
		"topology_profile_state",
		"path_node_target_results",
		"path_nodes",
		"path_health_runtime",
		"runtime_state",
		"schema_migrations",
		"sessions",
		"settings",
		"subscription_modem_paths",
		"subscription_node_preferences",
		"subscription_refresh_state",
		"subscription_versions",
		"subscriptions",
		"traffic_daily_totals",
		"users",
		"login_attempts",
		"logging_runtime",
		"network_interfaces",
		"interface_role_assignments",
		"uplinks",
		"hilink_modems",
		"legacy_modem_uplink_map",
		"subscription_uplink_paths",
		"uplink_path_nodes",
		"uplink_path_node_target_results",
		"direct_uplink_paths",
		"direct_uplink_path_target_results",
		"wireguard_ingress_servers",
		"wireguard_ingress_peers",
		"wireguard_ingress_peer_routes",
		"wireguard_ingress_runtime",
		"wireguard_ingress_peer_runtime",
		"wireguard_ingress_server_dns",
		"wireguard_ingress_listen_interfaces",
		"wireguard_ingress_peer_client_allowed_ips",
		"wireguard_ingress_peer_access_methods",
		"wireguard_ingress_counters",
		"modem_recovery_policy",
		"modem_recovery_runtime",
		"modem_recovery_attempts",
		"log_export_policy",
		"management_sites",
		"management_fabric_counters",
		"vps_nodes",
		"management_links",
		"management_link_endpoints",
		"management_pairing_invitations",
		"management_link_key_rotations",
		"management_admins",
		"management_admin_vps_peers",
		"management_admin_contour",
		"management_admin_relays",
		"management_admin_tunnels",
		"management_resources",
		"management_resource_ports",
		"management_resource_publications",
		"management_resource_acl",
		"management_fabric_generations",
		"management_fabric_operations",
	}
	for _, table := range wantTables {
		var count int
		if err := database.QueryRowContext(ctx, "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?", table).Scan(&count); err != nil {
			t.Fatalf("query table %s: %v", table, err)
		}
		if count != 1 {
			t.Errorf("table %s count = %d, want 1", table, count)
		}
	}

	version, err := SchemaVersion(ctx, database)
	if err != nil {
		t.Fatalf("SchemaVersion() error = %v", err)
	}
	if version != 32 {
		t.Fatalf("SchemaVersion() = %d, want 32", version)
	}
	for _, column := range []string{"service_download_bytes", "service_upload_bytes"} {
		var count int
		if err := database.QueryRowContext(ctx, "SELECT COUNT(*) FROM pragma_table_info('traffic_daily_totals') WHERE name=?", column).Scan(&count); err != nil || count != 1 {
			t.Errorf("traffic service column %s count = %d, %v", column, count, err)
		}
	}
	if _, err := database.ExecContext(ctx, `
INSERT INTO subscriptions (
    id, display_number, name, source_type, enabled, priority, auto_refresh,
    refresh_interval_seconds, fallback_when_named_candidates_fail, status,
    created_at, updated_at
) VALUES ('missing-number', NULL, 'Invalid', 'url', 0, 999, 1, 3600, 0, 'UNKNOWN', 'now', 'now')`); err == nil {
		t.Fatal("migration v5 accepted a subscription without display_number")
	}

	var gatewayState, pathState string
	if err := database.QueryRowContext(ctx, "SELECT gateway_state, path_state FROM runtime_state WHERE singleton_id=1").Scan(&gatewayState, &pathState); err != nil {
		t.Fatalf("read runtime_state: %v", err)
	}
	if gatewayState != "BOOTING" || pathState != "PATH_BLOCKED" {
		t.Errorf("runtime state = %s/%s, want BOOTING/PATH_BLOCKED", gatewayState, pathState)
	}
}

func TestMigrateIsIdempotent(t *testing.T) {
	ctx := context.Background()
	database, err := Open(ctx, OpenOptions{Path: filepath.Join(t.TempDir(), "state.db")})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer database.Close()

	if err := Migrate(ctx, database); err != nil {
		t.Fatalf("first Migrate() error = %v", err)
	}
	if err := Migrate(ctx, database); err != nil {
		t.Fatalf("second Migrate() error = %v", err)
	}
	var count int
	if err := database.QueryRowContext(ctx, "SELECT COUNT(*) FROM schema_migrations").Scan(&count); err != nil {
		t.Fatalf("count migrations: %v", err)
	}
	if count != 32 {
		t.Fatalf("migration count = %d, want 32", count)
	}
}

func TestMigration23PreservesIngressPeersAndAddsSecretFreeLifecycle(t *testing.T) {
	ctx := context.Background()
	database, err := Open(ctx, OpenOptions{Path: filepath.Join(t.TempDir(), "state.db")})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if err := migrateFS(ctx, database, migrationsThrough(t, 22)); err != nil {
		t.Fatalf("migrate schema 22: %v", err)
	}
	const key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	if _, err := database.ExecContext(ctx, `
INSERT INTO wireguard_ingress_servers(
  id,enabled,name,interface_name,subnet_cidr,listen_port,endpoint_host,mtu,
  private_key_secret_ref,topology_mode,created_at,updated_at
) VALUES('wg-ingress-default',0,'Ingress','wg-ingress','10.90.0.0/24',51820,'',1420,
  '/var/lib/gateway-vpn/secrets/wireguard-ingress/servers/wg-ingress-default.key','ROUTED','now','now');
INSERT INTO wireguard_ingress_runtime(server_id,desired_generation,applied_generation,state,updated_at)
VALUES('wg-ingress-default',1,0,'DISABLED','now');
INSERT INTO wireguard_ingress_peers(
  id,server_id,display_number,name,enabled,peer_kind,key_mode,public_key,
  private_key_secret_ref,preshared_key_secret_ref,assigned_address,
  endpoint_override,persistent_keepalive,access_policy_mode,created_at,updated_at
) VALUES('wgpeer:legacy','wg-ingress-default',7,'Legacy',1,'DEVICE','MANAGED',?,
  '/var/lib/gateway-vpn/secrets/wireguard-ingress/peers/legacy.key',
  '/var/lib/gateway-vpn/secrets/wireguard-ingress/peers/legacy.psk','10.90.0.7','',25,'AUTO','now','now');
INSERT INTO wireguard_ingress_peer_runtime(peer_id,state,updated_at)
VALUES('wgpeer:legacy','NEVER_CONNECTED','now')`, key); err != nil {
		t.Fatal(err)
	}
	if err := migrateFS(ctx, database, migrationsThrough(t, 23)); err != nil {
		t.Fatalf("migrate schema 23: %v", err)
	}
	var version, nextNumber, configGeneration int64
	var publicKey string
	var clientDNS, allowWhitelist, blockUnqualified int
	if err := database.QueryRowContext(ctx, "SELECT version FROM schema_migrations ORDER BY version DESC LIMIT 1").Scan(&version); err != nil {
		t.Fatal(err)
	}
	if err := database.QueryRowContext(ctx, "SELECT next_peer_number FROM wireguard_ingress_counters WHERE singleton_id=1").Scan(&nextNumber); err != nil {
		t.Fatal(err)
	}
	if err := database.QueryRowContext(ctx, "SELECT public_key,config_generation FROM wireguard_ingress_servers WHERE id='wg-ingress-default'").Scan(&publicKey, &configGeneration); err != nil {
		t.Fatal(err)
	}
	if err := database.QueryRowContext(ctx, "SELECT client_dns_enabled,allow_whitelist_only,block_when_unqualified FROM wireguard_ingress_peers WHERE id='wgpeer:legacy'").Scan(&clientDNS, &allowWhitelist, &blockUnqualified); err != nil {
		t.Fatal(err)
	}
	if version != 23 || nextNumber != 8 || publicKey != "" || configGeneration != 1 || clientDNS != 1 || allowWhitelist != 1 || blockUnqualified != 1 {
		t.Fatalf("migration 23 result = version:%d next:%d public:%q generation:%d flags:%d/%d/%d", version, nextNumber, publicKey, configGeneration, clientDNS, allowWhitelist, blockUnqualified)
	}
	if err := ForeignKeyCheck(ctx, database); err != nil {
		t.Fatalf("migration 23 foreign keys: %v", err)
	}
}

func TestMigration22PreservesExistingWatchdogChoicesAndAddsFixedContour(t *testing.T) {
	ctx := context.Background()
	database, err := Open(ctx, OpenOptions{Path: filepath.Join(t.TempDir(), "state.db")})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if err := migrateFS(ctx, database, migrationsThrough(t, 21)); err != nil {
		t.Fatalf("migrate schema 21: %v", err)
	}
	if _, err := database.ExecContext(ctx, `
UPDATE settings
SET value_json=json_set(value_json, '$.check_interval_seconds', 42, '$.host_reboot_enabled', 1)
WHERE key='watchdog'`); err != nil {
		t.Fatal(err)
	}
	if err := migrateFS(ctx, database, migrationsThrough(t, 22)); err != nil {
		t.Fatalf("migrate schema 22: %v", err)
	}
	var schema, interval, reboot int
	var componentModesType string
	if err := database.QueryRowContext(ctx, `
SELECT
  json_extract(value_json, '$.schema_version'),
  json_extract(value_json, '$.check_interval_seconds'),
  json_extract(value_json, '$.host_reboot_enabled'),
  json_type(value_json, '$.component_recovery_modes')
FROM settings WHERE key='watchdog'`).Scan(&schema, &interval, &reboot, &componentModesType); err != nil {
		t.Fatal(err)
	}
	var modeCount int
	if err := database.QueryRowContext(ctx, "SELECT COUNT(*) FROM json_each((SELECT json_extract(value_json, '$.component_recovery_modes') FROM settings WHERE key='watchdog'))").Scan(&modeCount); err != nil {
		t.Fatal(err)
	}
	if schema != 2 || interval != 42 || reboot != 1 || modeCount != 16 || componentModesType != "object" {
		t.Fatalf("migrated watchdog = schema:%d interval:%d reboot:%d modes:%d type:%s", schema, interval, reboot, modeCount, componentModesType)
	}
}

func TestMigration24AddsLoggingPipelineWithoutChangingWatchdogChoices(t *testing.T) {
	ctx := context.Background()
	database, err := Open(ctx, OpenOptions{Path: filepath.Join(t.TempDir(), "state.db")})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if err := migrateFS(ctx, database, migrationsThrough(t, 23)); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(ctx, `
UPDATE settings SET value_json=json_set(value_json, '$.check_interval_seconds', 42)
WHERE key='watchdog'`); err != nil {
		t.Fatal(err)
	}
	if err := Migrate(ctx, database); err != nil {
		t.Fatal(err)
	}
	var version, interval int
	var loggingMode, managementFabricMode, wireGuardAdminMode string
	if err := database.QueryRowContext(ctx, `
SELECT (SELECT MAX(version) FROM schema_migrations),
       json_extract(value_json, '$.check_interval_seconds'),
	   json_extract(value_json, '$.component_recovery_modes.logging_pipeline'),
	   json_extract(value_json, '$.component_recovery_modes.management_fabric_routes'),
	   json_extract(value_json, '$.component_recovery_modes.wireguard_admin')
FROM settings WHERE key='watchdog'`).Scan(&version, &interval, &loggingMode, &managementFabricMode, &wireGuardAdminMode); err != nil {
		t.Fatal(err)
	}
	var modeCount int
	if err := database.QueryRowContext(ctx, "SELECT COUNT(*) FROM json_each((SELECT json_extract(value_json, '$.component_recovery_modes') FROM settings WHERE key='watchdog'))").Scan(&modeCount); err != nil {
		t.Fatal(err)
	}
	if version != 32 || interval != 42 || loggingMode != "RESTART" || managementFabricMode != "RESTART" || wireGuardAdminMode != "RESTART" || modeCount != 19 {
		t.Fatalf("watchdog migrations = version:%d interval:%d modes:%s/%s/%s count:%d", version, interval, loggingMode, managementFabricMode, wireGuardAdminMode, modeCount)
	}
}

func TestMigration29PreservesRoutedHubAdminsAndAddsEndToEndContour(t *testing.T) {
	ctx := context.Background()
	database, err := Open(ctx, OpenOptions{Path: filepath.Join(t.TempDir(), "state.db")})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if err := migrateFS(ctx, database, migrationsThrough(t, 28)); err != nil {
		t.Fatalf("migrate schema 28: %v", err)
	}
	if _, err := database.ExecContext(ctx, `
INSERT INTO management_sites(id,display_name,is_local,identity_state,created_at,updated_at)
VALUES('site:home','Home',1,'ACTIVE','now','now');
INSERT INTO vps_nodes(
  id,display_number,name,enabled,priority,verified_fingerprint,public_key,
  admin_address_pool,resource_alias_pool,state,created_at,updated_at
) VALUES('vps:a',1,'VPS A',1,1,?,'vps-public-key','10.81.0.0/24','10.96.0.0/16','CONFIGURED','now','now');
INSERT INTO management_admins(id,name,identity_kind,enabled,state,created_at,updated_at)
VALUES('admin:a','Administrator','ADMIN',1,'ACTIVE','now','now');
INSERT INTO management_admin_vps_peers(
  id,admin_id,vps_id,public_key,assigned_address,state,
  desired_generation,applied_generation,created_at,updated_at
) VALUES('admin-peer:a','admin:a','vps:a','admin-public-key','10.81.0.10','ACTIVE',3,2,'now','now')`, strings.Repeat("a", 64)); err != nil {
		t.Fatal(err)
	}
	if err := migrateFS(ctx, database, migrationsThrough(t, 29)); err != nil {
		t.Fatalf("migrate schema 29: %v", err)
	}
	var version, desired, applied int
	var trustMode, state string
	if err := database.QueryRowContext(ctx, `
SELECT (SELECT MAX(version) FROM schema_migrations),trust_mode,state,desired_generation,applied_generation
FROM management_admin_vps_peers WHERE id='admin-peer:a'`).Scan(&version, &trustMode, &state, &desired, &applied); err != nil {
		t.Fatal(err)
	}
	if version != 29 || trustMode != "ROUTED_HUB" || state != "ACTIVE" || desired != 3 || applied != 2 {
		t.Fatalf("migration 29 admin = version:%d trust:%s state:%s generations:%d/%d", version, trustMode, state, desired, applied)
	}
	for _, table := range []string{"management_admin_contour", "management_admin_relays", "management_admin_tunnels"} {
		var count int
		if err := database.QueryRowContext(ctx, "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?", table).Scan(&count); err != nil || count != 1 {
			t.Fatalf("migration 29 table %s count = %d, %v", table, count, err)
		}
	}
	if _, err := database.ExecContext(ctx, "UPDATE management_admin_vps_peers SET trust_mode='UNSAFE' WHERE id='admin-peer:a'"); err == nil {
		t.Fatal("migration 29 accepted an unknown administrator trust mode")
	}
	if err := ForeignKeyCheck(ctx, database); err != nil {
		t.Fatalf("migration 29 foreign keys: %v", err)
	}
}

func TestMigration30PreservesTypedTransactionsAndInitializesTopologyProfile(t *testing.T) {
	profiles := []struct {
		name    string
		prepare []string
		want    string
	}{
		{name: "HiLink default", want: "ETHERNET_HILINK"},
		{name: "Ethernet uplink", want: "ETHERNET_ETHERNET", prepare: []string{
			`INSERT INTO network_interfaces(id,stable_identity_kind,stable_identity_hash,current_ifname,carrier_state,created_at,updated_at) VALUES('netif:lan','MAC','lan-hash','enp1s0','UP','now','now')`,
			`INSERT INTO network_interfaces(id,stable_identity_kind,stable_identity_hash,current_ifname,carrier_state,created_at,updated_at) VALUES('netif:wan','MAC','wan-hash','enp2s0','UP','now','now')`,
			`INSERT INTO uplinks(id,display_number,type,name,enabled,priority,network_interface_id,address_mode,dns_json,routing_table_id,fwmark,state,created_at,updated_at) VALUES('uplink:wan',1,'ETHERNET','WAN',1,1,'netif:wan','DHCP','[]',1101,4353,'UPLINK_READY','now','now')`,
			`INSERT INTO interface_role_assignments(id,network_interface_id,role,created_at,updated_at) VALUES('role:lan','netif:lan','LAN_MEMBER','now','now')`,
		}},
		{name: "mixed uplinks", want: "MIXED", prepare: []string{
			`INSERT INTO network_interfaces(id,stable_identity_kind,stable_identity_hash,current_ifname,carrier_state,created_at,updated_at) VALUES('netif:lan','MAC','lan-hash','enp1s0','UP','now','now')`,
			`INSERT INTO uplinks(id,display_number,type,name,enabled,priority,address_mode,dns_json,routing_table_id,fwmark,state,created_at,updated_at) VALUES('uplink:wan',1,'ETHERNET','WAN',1,1,'DHCP','[]',1101,4353,'UPLINK_READY','now','now')`,
			`INSERT INTO uplinks(id,display_number,type,name,enabled,priority,address_mode,dns_json,routing_table_id,fwmark,state,created_at,updated_at) VALUES('uplink:hilink',2,'HILINK','LTE',1,2,'DHCP','[]',1102,4354,'UPLINK_READY','now','now')`,
			`INSERT INTO interface_role_assignments(id,network_interface_id,role,created_at,updated_at) VALUES('role:lan','netif:lan','LAN_MEMBER','now','now')`,
		}},
		{name: "one arm", want: "ONE_ARM_WIREGUARD", prepare: []string{
			`INSERT INTO network_interfaces(id,stable_identity_kind,stable_identity_hash,current_ifname,carrier_state,created_at,updated_at) VALUES('netif:shared','MAC','shared-hash','enp1s0','UP','now','now')`,
			`INSERT INTO interface_role_assignments(id,network_interface_id,role,created_at,updated_at) VALUES('role:shared','netif:shared','SHARED_ONE_ARM','now','now')`,
		}},
	}
	for _, profile := range profiles {
		t.Run(profile.name, func(t *testing.T) {
			ctx := context.Background()
			database, err := Open(ctx, OpenOptions{Path: filepath.Join(t.TempDir(), "state.db")})
			if err != nil {
				t.Fatal(err)
			}
			defer database.Close()
			if err := migrateFS(ctx, database, migrationsThrough(t, 29)); err != nil {
				t.Fatalf("migrate schema 29: %v", err)
			}
			for _, statement := range profile.prepare {
				if _, err := database.ExecContext(ctx, statement); err != nil {
					t.Fatalf("prepare topology profile: %v", err)
				}
			}
			if _, err := database.ExecContext(ctx, `
INSERT INTO network_apply_transactions(
 id,state,confirm_token_sha256,interface_name,old_lan_cidr,new_lan_cidr,
 old_url,new_url,new_destination_ip,rollback_deadline,transaction_dir,
 created_at,updated_at,manifest_schema,operation_kind,candidate_json
) VALUES(
 'apply-ethernet','CONFIRMED','digest','','','',
 'https://192.168.200.1:8443','https://192.168.200.1:8443','192.168.200.1',
 '2026-08-30T12:01:00Z','/var/lib/gateway-vpn-privileged/network-transactions/apply-ethernet',
 '2026-08-30T12:00:00Z','2026-08-30T12:00:30Z',2,'ETHERNET_UPLINK','{"operation":"CREATE"}'
)`); err != nil {
				t.Fatalf("insert schema-2 transaction: %v", err)
			}
			if err := Migrate(ctx, database); err != nil {
				t.Fatalf("migrate schema 30: %v", err)
			}
			var active, state, kind, candidate string
			var desired, applied, schema int64
			if err := database.QueryRowContext(ctx, `SELECT active_profile,desired_generation,applied_generation,state FROM topology_profile_state WHERE singleton_id=1`).Scan(&active, &desired, &applied, &state); err != nil {
				t.Fatal(err)
			}
			if err := database.QueryRowContext(ctx, `SELECT manifest_schema,operation_kind,candidate_json FROM network_apply_transactions WHERE id='apply-ethernet'`).Scan(&schema, &kind, &candidate); err != nil {
				t.Fatal(err)
			}
			if active != profile.want || desired != 1 || applied != 1 || state != "ACTIVE" {
				t.Fatalf("initial topology = %s %d/%d %s, want %s 1/1 ACTIVE", active, desired, applied, state, profile.want)
			}
			if schema != 2 || kind != "ETHERNET_UPLINK" || candidate != `{"operation":"CREATE"}` {
				t.Fatalf("preserved transaction = %d / %s / %s", schema, kind, candidate)
			}
			if _, err := database.ExecContext(ctx, `INSERT INTO network_apply_transactions(
 id,state,confirm_token_sha256,interface_name,old_lan_cidr,new_lan_cidr,old_url,new_url,
 new_destination_ip,rollback_deadline,transaction_dir,created_at,updated_at,
 manifest_schema,operation_kind,candidate_json
) VALUES('invalid','FAILED','digest','','','','https://192.168.200.1:8443',
 'https://192.168.200.1:8443','192.168.200.1','2026-08-30T12:01:00Z','/tmp/invalid',
 '2026-08-30T12:00:00Z','2026-08-30T12:00:00Z',4,'TOPOLOGY_PROFILE','{}')`); err == nil {
				t.Fatal("migration 30 accepted unknown manifest schema")
			}
			if err := ForeignKeyCheck(ctx, database); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestMigration19BackfillsLegacyNetworkApplyAndAddsTypedMetadata(t *testing.T) {
	ctx := context.Background()
	database, err := Open(ctx, OpenOptions{Path: filepath.Join(t.TempDir(), "state.db")})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if err := migrateFS(ctx, database, migrationsThrough(t, 18)); err != nil {
		t.Fatalf("migrate schema 18: %v", err)
	}
	_, err = database.ExecContext(ctx, `
INSERT INTO network_apply_transactions(
    id, state, confirm_token_sha256, interface_name, old_lan_cidr, new_lan_cidr,
    old_url, new_url, new_destination_ip, rollback_deadline, transaction_dir,
    created_at, updated_at
) VALUES (
    'apply-legacy', 'CONFIRMED', 'digest', 'enp2s0', '192.168.200.1/24',
    '192.168.210.1/24', 'https://192.168.200.1:8443',
    'https://192.168.210.1:8443', '192.168.210.1', '2026-08-28T12:01:00Z',
    '/var/lib/gateway-vpn-privileged/network-transactions/apply-legacy',
    '2026-08-28T12:00:00Z', '2026-08-28T12:00:30Z'
)`)
	if err != nil {
		t.Fatalf("insert schema-18 transaction: %v", err)
	}
	if err := Migrate(ctx, database); err != nil {
		t.Fatalf("migrate schema 19: %v", err)
	}
	var schema int
	var kind, candidate string
	if err := database.QueryRowContext(ctx, `
SELECT manifest_schema, operation_kind, candidate_json
FROM network_apply_transactions WHERE id='apply-legacy'`).Scan(&schema, &kind, &candidate); err != nil {
		t.Fatal(err)
	}
	if schema != 1 || kind != "LAN_ADDRESS" || candidate != "{}" {
		t.Fatalf("legacy metadata = %d / %s / %s", schema, kind, candidate)
	}
}

func TestMigration17PreservesHiLinkPathsAndRuntimeIdentity(t *testing.T) {
	ctx := context.Background()
	database, err := Open(ctx, OpenOptions{Path: filepath.Join(t.TempDir(), "state.db")})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	legacyFS := migrationsThrough(t, 16)
	if err := migrateFS(ctx, database, legacyFS); err != nil {
		t.Fatalf("migrate legacy schema: %v", err)
	}
	now := "2026-08-28T12:00:00Z"
	statements := []string{
		`INSERT INTO modems (
            id, display_number, name, operator_label, identity_kind, identity_hash,
            enabled, priority, interface_name, management_cidr, gateway, dns_json,
            routing_table_id, fwmark, route_generation, state, telemetry_state,
            management_reachability_state, created_at, updated_at
        ) VALUES (
            'modem-a', 1, 'Operator A', 'A', 'USB_SERIAL', 'identity-a',
            1, 10, 'enx-a', '192.168.8.2/24', '192.168.8.1', '["192.168.8.1"]',
            1101, 4353, 7, 'MODEM_READY', 'AVAILABLE', 'REACHABLE', '` + now + `', '` + now + `'
        )`,
		`INSERT INTO subscriptions (
            id, display_number, name, source_type, enabled, priority, auto_refresh,
            refresh_interval_seconds, fallback_when_named_candidates_fail, status,
            created_at, updated_at
        ) VALUES ('sub-a', 1, 'Bypass', 'url', 1, 10, 1, 3600, 0, 'ONLINE', '` + now + `', '` + now + `')`,
		`INSERT INTO access_methods (
            id, kind, subscription_id, enabled, priority, immutable, created_at, updated_at
        ) VALUES ('access:subscription:sub-a', 'SUBSCRIPTION', 'sub-a', 1, 20, 0, '` + now + `', '` + now + `')`,
		`INSERT INTO subscription_versions (
            id, subscription_id, content_sha256, nodes_total, state, created_at, activated_at
        ) VALUES ('version-a', 'sub-a', 'sha-a', 1, 'LKG', '` + now + `', '` + now + `')`,
		`UPDATE subscriptions SET active_version_id='version-a' WHERE id='sub-a'`,
		`INSERT INTO nodes (
            id, version_id, external_name, normalized_name, fingerprint, proxy_type, enabled,
		    selection_override, candidate_source, matched_matcher_id
        ) VALUES ('node-a', 'version-a', 'LTE A', 'lte a', 'fingerprint-a', 'vless', 1, 'auto', 'MATCHER', NULL)`,
		`INSERT INTO bypass_probe_targets (
            id, name, target_kind, target_value, normalized_url, enabled, required,
            priority, timeout_seconds, success_mode, state, created_at, updated_at
        ) VALUES ('target-a', 'Global', 'url', 'https://example.com/', 'https://example.com/', 1, 1, 10, 8, 'any_http_response', 'NORMAL', '` + now + `', '` + now + `')`,
		`INSERT INTO subscription_modem_paths (
            id, modem_id, subscription_id, state, transport_state, selected_node_id,
            candidate_nodes, qualified_nodes, required_targets_passed, required_targets_total,
            quality_class, functional_score, policy_generation, route_generation,
            last_checked_at, expires_at, created_at, updated_at
        ) VALUES (
            'path:modem-a:sub-a', 'modem-a', 'sub-a', 'QUALIFIED', 'PASSED', 'node-a',
            1, 1, 1, 1, 'FULL', 1000, 4, 7, '` + now + `', '2026-08-28T12:15:00Z', '` + now + `', '` + now + `'
        )`,
		`INSERT INTO path_nodes (
            path_id, node_id, qualification_state, qualification_generation,
            route_generation, qualification_expires_at, latency_ms, last_success_at
        ) VALUES ('path:modem-a:sub-a', 'node-a', 'BYPASS_QUALIFIED', 4, 7, '2026-08-28T12:15:00Z', 42, '` + now + `')`,
		`INSERT INTO path_node_target_results (
            path_id, node_id, target_id, state, latency_ms, http_status, checked_at,
            expires_at, policy_generation, route_generation
        ) VALUES ('path:modem-a:sub-a', 'node-a', 'target-a', 'PASSED', 42, 200, '` + now + `', '2026-08-28T12:15:00Z', 4, 7)`,
		`INSERT INTO direct_modem_paths (
            id, modem_id, state, transport_state, quality_class, functional_score,
            required_targets_passed, required_targets_total, policy_generation,
            route_generation, last_checked_at, expires_at, created_at, updated_at
        ) VALUES ('direct:path:modem-a', 'modem-a', 'FAILED', 'PASSED', 'FAILED', 0, 0, 1, 4, 7, '` + now + `', '2026-08-28T12:15:00Z', '` + now + `', '` + now + `')`,
		`INSERT INTO direct_path_target_results (
            path_id, target_id, state, latency_ms, http_status, checked_at, expires_at,
            policy_generation, route_generation
        ) VALUES ('direct:path:modem-a', 'target-a', 'FAILED', 50, 503, '` + now + `', '2026-08-28T12:15:00Z', 4, 7)`,
		`UPDATE runtime_state SET
            gateway_state='ACTIVE', path_state='PATH_ACTIVE', active_modem_id='modem-a',
            active_path_id='path:modem-a:sub-a', active_method_id='access:subscription:sub-a',
            active_method_kind='SUBSCRIPTION', active_quality_class='FULL',
            active_subscription_id='sub-a', active_node_id='node-a', management_modem_id='modem-a'
        WHERE singleton_id=1`,
	}
	for _, statement := range statements {
		if _, err := database.ExecContext(ctx, statement); err != nil {
			t.Fatalf("prepare legacy fixture: %v\n%s", err, statement)
		}
	}
	if err := Migrate(ctx, database); err != nil {
		t.Fatalf("migrate to schema 17: %v", err)
	}
	var uplinkType, uplinkState, modemState, interfaceName string
	var routeGeneration int64
	if err := database.QueryRowContext(ctx, `
SELECT u.type, u.state, h.modem_state, n.current_ifname, u.route_generation
FROM uplinks AS u
JOIN hilink_modems AS h ON h.uplink_id=u.id
JOIN network_interfaces AS n ON n.id=u.network_interface_id
WHERE u.id='modem-a'`).Scan(&uplinkType, &uplinkState, &modemState, &interfaceName, &routeGeneration); err != nil {
		t.Fatal(err)
	}
	if uplinkType != "HILINK" || uplinkState != "UPLINK_READY" || modemState != "MODEM_READY" || interfaceName != "enx-a" || routeGeneration != 7 {
		t.Fatalf("migrated uplink = %s/%s/%s/%s/%d", uplinkType, uplinkState, modemState, interfaceName, routeGeneration)
	}
	var pathID, nodeID, targetClass, activeUplink, managementUplink string
	if err := database.QueryRowContext(ctx, `
SELECT p.id, pn.node_id, r.target_class, s.active_uplink_id, s.management_uplink_id
FROM subscription_uplink_paths AS p
JOIN uplink_path_nodes AS pn ON pn.path_id=p.id
JOIN uplink_path_node_target_results AS nr ON nr.path_id=pn.path_id AND nr.node_id=pn.node_id
JOIN direct_uplink_path_target_results AS r ON r.target_id=nr.target_id
JOIN runtime_state AS s ON s.singleton_id=1
WHERE p.uplink_id='modem-a'`).Scan(&pathID, &nodeID, &targetClass, &activeUplink, &managementUplink); err != nil {
		t.Fatal(err)
	}
	if pathID != "path:modem-a:sub-a" || nodeID != "node-a" || targetClass != "GLOBAL_REQUIRED" || activeUplink != "modem-a" || managementUplink != "modem-a" {
		t.Fatalf("preserved identities = %s/%s/%s/%s/%s", pathID, nodeID, targetClass, activeUplink, managementUplink)
	}
	if err := ForeignKeyCheck(ctx, database); err != nil {
		t.Fatalf("foreign key check after migration: %v", err)
	}
}

func TestMigration17CompatibilityBridgeMirrorsLegacyWritesAtomically(t *testing.T) {
	ctx := context.Background()
	database, err := Open(ctx, OpenOptions{Path: filepath.Join(t.TempDir(), "state.db")})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if err := migrateFS(ctx, database, migrationsThrough(t, 17)); err != nil {
		t.Fatal(err)
	}
	now := "2026-08-28T13:00:00Z"
	statements := []string{
		`INSERT INTO modems (
            id, display_number, name, identity_kind, identity_hash, enabled, priority,
            routing_table_id, fwmark, route_generation, state, telemetry_state,
            management_reachability_state, created_at, updated_at
        ) VALUES (
            'modem-bridge', 1, 'Bridge modem', 'USB_SERIAL',
            'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
            1, 10, 1101, 4353, 0, 'MODEM_CONFIGURED_OFFLINE', 'UNKNOWN', 'UNTESTED', '` + now + `', '` + now + `'
        )`,
		`UPDATE modems SET interface_name='enx-bridge', management_cidr='192.168.9.2/24',
            gateway='192.168.9.1', dns_json='["192.168.9.1"]', route_generation=2,
            state='MODEM_READY', updated_at='2026-08-28T13:01:00Z'
        WHERE id='modem-bridge'`,
		`INSERT INTO subscriptions (
            id, display_number, name, source_type, enabled, priority, auto_refresh,
            refresh_interval_seconds, fallback_when_named_candidates_fail, status,
            created_at, updated_at
        ) VALUES ('sub-bridge', 1, 'Bridge subscription', 'url', 1, 10, 1, 3600, 0, 'ONLINE', '` + now + `', '` + now + `')`,
		`INSERT INTO subscription_modem_paths (
            id, modem_id, subscription_id, state, transport_state, candidate_nodes,
            qualified_nodes, required_targets_passed, required_targets_total,
            quality_class, functional_score, policy_generation, route_generation,
            created_at, updated_at
        ) VALUES (
            'path:bridge', 'modem-bridge', 'sub-bridge', 'FAILED', 'FAILED', 1, 0,
            0, 1, 'FAILED', 0, 3, 2, '` + now + `', '` + now + `'
        )`,
		`UPDATE subscription_modem_paths SET state='MODEM_OFFLINE', updated_at='2026-08-28T13:02:00Z' WHERE id='path:bridge'`,
		`UPDATE runtime_state SET active_modem_id='modem-bridge', management_modem_id='modem-bridge' WHERE singleton_id=1`,
	}
	for _, statement := range statements {
		if _, err := database.ExecContext(ctx, statement); err != nil {
			t.Fatalf("legacy compatibility write: %v\n%s", err, statement)
		}
	}
	var uplinkState, interfaceName, pathState, activeUplink, managementUplink string
	var routeGeneration int64
	if err := database.QueryRowContext(ctx, `
SELECT u.state, n.current_ifname, u.route_generation, p.state,
       r.active_uplink_id, r.management_uplink_id
FROM uplinks AS u
JOIN network_interfaces AS n ON n.id=u.network_interface_id
JOIN subscription_uplink_paths AS p ON p.uplink_id=u.id
JOIN runtime_state AS r ON r.singleton_id=1
WHERE u.id='modem-bridge'`).Scan(
		&uplinkState, &interfaceName, &routeGeneration, &pathState,
		&activeUplink, &managementUplink); err != nil {
		t.Fatal(err)
	}
	if uplinkState != "UPLINK_READY" || interfaceName != "enx-bridge" || routeGeneration != 2 || pathState != "UPLINK_OFFLINE" || activeUplink != "modem-bridge" || managementUplink != "modem-bridge" {
		t.Fatalf("compatibility projection = %s/%s/%d/%s/%s/%s", uplinkState, interfaceName, routeGeneration, pathState, activeUplink, managementUplink)
	}
	if _, err := database.ExecContext(ctx, "DELETE FROM modems WHERE id='modem-bridge'"); err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"uplinks", "hilink_modems", "subscription_uplink_paths"} {
		var count int
		if err := database.QueryRowContext(ctx, "SELECT COUNT(*) FROM "+table+" WHERE "+map[string]string{
			"uplinks": "id", "hilink_modems": "uplink_id", "subscription_uplink_paths": "uplink_id",
		}[table]+"='modem-bridge'").Scan(&count); err != nil || count != 0 {
			t.Fatalf("%s rows after legacy delete = %d, %v", table, count, err)
		}
	}
	if err := ForeignKeyCheck(ctx, database); err != nil {
		t.Fatal(err)
	}
}

func migrationsThrough(t *testing.T, maximum int64) fs.FS {
	t.Helper()
	entries, err := fs.ReadDir(migrations.Files, ".")
	if err != nil {
		t.Fatal(err)
	}
	result := fstest.MapFS{}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".sql") {
			continue
		}
		version, err := migrationVersion(entry.Name())
		if err != nil {
			t.Fatal(err)
		}
		if version > maximum {
			continue
		}
		content, err := fs.ReadFile(migrations.Files, entry.Name())
		if err != nil {
			t.Fatal(err)
		}
		result[entry.Name()] = &fstest.MapFile{Data: content}
	}
	return result
}

func migrationVersion(name string) (int64, error) {
	prefix := strings.SplitN(name, "_", 2)[0]
	return strconv.ParseInt(prefix, 10, 64)
}

func TestMigrationRollsBackPartialDDL(t *testing.T) {
	ctx := context.Background()
	database, err := Open(ctx, OpenOptions{Path: filepath.Join(t.TempDir(), "state.db")})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer database.Close()

	broken := fstest.MapFS{
		"000001_broken.sql": &fstest.MapFile{Data: []byte("CREATE TABLE must_rollback (id INTEGER); INVALID SQL;")},
	}
	if err := migrateFS(ctx, database, broken); err == nil {
		t.Fatal("migrateFS() error = nil, want SQL error")
	}
	var count int
	if err := database.QueryRowContext(ctx, "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='must_rollback'").Scan(&count); err != nil {
		t.Fatalf("query rolled back table: %v", err)
	}
	if count != 0 {
		t.Fatalf("must_rollback table count = %d, want 0", count)
	}
}

func TestMigrateRejectsChangedAppliedMigration(t *testing.T) {
	ctx := context.Background()
	database, err := Open(ctx, OpenOptions{Path: filepath.Join(t.TempDir(), "state.db")})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer database.Close()

	original := fstest.MapFS{
		"000001_test.sql": &fstest.MapFile{Data: []byte("CREATE TABLE stable (id INTEGER);")},
	}
	changed := fstest.MapFS{
		"000001_test.sql": &fstest.MapFile{Data: []byte("CREATE TABLE stable (id INTEGER, changed TEXT);")},
	}
	if err := migrateFS(ctx, database, original); err != nil {
		t.Fatalf("first migrateFS() error = %v", err)
	}
	err = migrateFS(ctx, database, changed)
	if !errors.Is(err, ErrMigrationChecksum) {
		t.Fatalf("second migrateFS() error = %v, want ErrMigrationChecksum", err)
	}
}

func TestLoadMigrationsRejectsSequenceGap(t *testing.T) {
	files := fstest.MapFS{
		"000002_gap.sql": &fstest.MapFile{Data: []byte("SELECT 1;")},
	}
	_, err := loadMigrations(files)
	if err == nil {
		t.Fatal("loadMigrations() error = nil, want sequence gap")
	}
}
