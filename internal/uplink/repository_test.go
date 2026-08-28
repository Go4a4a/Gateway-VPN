package uplink

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
	"time"

	databasepkg "gateway-vpn/internal/db"
	"gateway-vpn/internal/store"
)

func TestRepositoryMigratesHiLinkAndCreatesEthernetFromUnusedInterface(t *testing.T) {
	ctx, database, repository := newFixture(t)
	insertLegacyHiLinkProjection(t, database)
	observed, err := repository.ObserveInterface(ctx, InterfaceObservation{
		ID: "netif:ethernet:a", StableIdentityKind: "PERMANENT_MAC",
		StableIdentityHash: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		PermanentMAC:       "02:00:00:00:00:01", CurrentIfname: "enp3s0", Driver: "igc",
		CarrierState: "UP", Addresses: []string{"192.0.2.2/24"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if observed.CurrentIfname != "enp3s0" || observed.CarrierState != "UP" {
		t.Fatalf("observed interface = %+v", observed)
	}
	inventory, err := repository.ListInterfaces(ctx)
	if err != nil || len(inventory) != 2 {
		t.Fatalf("interface inventory before Ethernet assignment = %+v, %v", inventory, err)
	}
	created, err := repository.CreateEthernet(ctx, CreateEthernetInput{
		ID: "uplink-ethernet-a", Name: "Основной Ethernet", NetworkInterfaceID: observed.ID,
		AddressMode: AddressDHCP, DNS: []string{"1.1.1.1"}, MTU: 1500,
	})
	if err != nil {
		t.Fatal(err)
	}
	if created.Type != TypeEthernet || created.DisplayNumber != 2 || created.Priority != 20 || created.RoutingTableID != 1102 || created.Fwmark != 4354 {
		t.Fatalf("created Ethernet uplink = %+v", created)
	}
	items, err := repository.List(ctx)
	if err != nil || len(items) != 2 || items[0].Type != TypeHiLink || items[1].Type != TypeEthernet {
		t.Fatalf("uplinks = %+v, %v", items, err)
	}
	hilink, err := repository.GetHiLink(ctx, "modem-a")
	if err != nil || hilink.ModemState != "MODEM_READY" || hilink.CurrentIfname != "enx-a" {
		t.Fatalf("migrated HiLink = %+v, %v", hilink, err)
	}
	var role string
	if err := database.QueryRowContext(ctx, "SELECT role FROM interface_role_assignments WHERE uplink_id=?", created.ID).Scan(&role); err != nil || role != "ETHERNET_UPLINK" {
		t.Fatalf("Ethernet role = %q, %v", role, err)
	}
	inventory, err = repository.ListInterfaces(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var ethernet InterfaceInventory
	for _, item := range inventory {
		if item.ID == observed.ID {
			ethernet = item
		}
	}
	if ethernet.CurrentIfname != "enp3s0" || len(ethernet.Roles) != 1 || ethernet.Roles[0].Role != "ETHERNET_UPLINK" || ethernet.Roles[0].UplinkID != created.ID {
		t.Fatalf("Ethernet inventory = %+v", ethernet)
	}
}

func TestRepositoryRejectsUnsafeOrAlreadyAssignedEthernetInterface(t *testing.T) {
	ctx, database, repository := newFixture(t)
	_, err := repository.ObserveInterface(ctx, InterfaceObservation{
		ID: "netif:a", StableIdentityKind: "PERMANENT_MAC",
		StableIdentityHash: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		CurrentIfname:      "enp4s0", CarrierState: "DOWN",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repository.CreateEthernet(ctx, CreateEthernetInput{
		ID: "bad-static", Name: "Bad", NetworkInterfaceID: "netif:a", AddressMode: AddressStatic,
		IPv4CIDR: "192.168.1.10/24", Gateway: "198.51.100.1",
	}); err == nil {
		t.Fatal("out-of-subnet static gateway accepted")
	}
	first, err := repository.CreateEthernet(ctx, CreateEthernetInput{
		ID: "ethernet-a", Name: "A", NetworkInterfaceID: "netif:a", AddressMode: AddressDHCP,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repository.CreateEthernet(ctx, CreateEthernetInput{
		ID: "ethernet-b", Name: "B", NetworkInterfaceID: "netif:a", AddressMode: AddressDHCP,
	}); err == nil {
		t.Fatal("interface with an active role was assigned twice")
	}
	if _, err := repository.ObserveInterface(ctx, InterfaceObservation{
		ID: "netif:a", StableIdentityKind: "PERMANENT_MAC",
		StableIdentityHash: "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
		CurrentIfname:      "enp4s0", CarrierState: "UP",
	}); err == nil {
		t.Fatal("existing interface id accepted a different stable identity")
	}
	if got, err := repository.Get(ctx, first.ID); err != nil || got.NetworkInterfaceID != "netif:a" {
		t.Fatalf("first uplink changed after rejected operations: %+v, %v", got, err)
	}
	var count int
	if err := database.QueryRowContext(ctx, "SELECT COUNT(*) FROM uplinks WHERE type='ETHERNET'").Scan(&count); err != nil || count != 1 {
		t.Fatalf("Ethernet count = %d, %v", count, err)
	}
}

func TestReplaceInterfaceUsesGenerationAndInvalidatesOnlyOwnedPaths(t *testing.T) {
	ctx, database, repository := newFixture(t)
	for _, item := range []InterfaceObservation{
		{ID: "netif:old", StableIdentityKind: "PERMANENT_MAC", StableIdentityHash: "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd", CurrentIfname: "enp1s0", CarrierState: "UP"},
		{ID: "netif:new", StableIdentityKind: "PERMANENT_MAC", StableIdentityHash: "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee", CurrentIfname: "enp2s0", CarrierState: "DOWN"},
	} {
		if _, err := repository.ObserveInterface(ctx, item); err != nil {
			t.Fatal(err)
		}
	}
	created, err := repository.CreateEthernet(ctx, CreateEthernetInput{
		ID: "ethernet-a", Name: "Replaceable", NetworkInterfaceID: "netif:old", AddressMode: AddressDHCP,
	})
	if err != nil {
		t.Fatal(err)
	}
	seedGenericPaths(t, database, created.ID, created.RouteGeneration)
	result, err := repository.ReplaceInterface(ctx, created.ID, "netif:new", created.DesiredGeneration)
	if err != nil {
		t.Fatal(err)
	}
	if result.PreviousInterfaceID != "netif:old" || result.ReplacementInterface != "netif:new" || result.DesiredGeneration != 2 || result.RouteGeneration != 1 || result.InvalidatedVPNPaths != 1 || result.InvalidatedDirect != 1 {
		t.Fatalf("replacement result = %+v", result)
	}
	updated, err := repository.Get(ctx, created.ID)
	if err != nil || updated.NetworkInterfaceID != "netif:new" || updated.State != StateConfiguring || updated.RouteGeneration != 1 {
		t.Fatalf("updated uplink = %+v, %v", updated, err)
	}
	var vpnState, directState, oldRole string
	var vpnGeneration, directGeneration int64
	if err := database.QueryRowContext(ctx, "SELECT state, route_generation FROM subscription_uplink_paths WHERE uplink_id=?", created.ID).Scan(&vpnState, &vpnGeneration); err != nil {
		t.Fatal(err)
	}
	if err := database.QueryRowContext(ctx, "SELECT state, route_generation FROM direct_uplink_paths WHERE uplink_id=?", created.ID).Scan(&directState, &directGeneration); err != nil {
		t.Fatal(err)
	}
	if err := database.QueryRowContext(ctx, "SELECT role FROM interface_role_assignments WHERE network_interface_id='netif:old'").Scan(&oldRole); err != nil {
		t.Fatal(err)
	}
	if vpnState != "STALE" || directState != "STALE" || vpnGeneration != 1 || directGeneration != 1 || oldRole != "UNUSED" {
		t.Fatalf("invalidated paths/role = %s/%d %s/%d %s", vpnState, vpnGeneration, directState, directGeneration, oldRole)
	}
	if _, err := repository.ReplaceInterface(ctx, created.ID, "netif:old", created.DesiredGeneration); !errors.Is(err, store.ErrStaleGeneration) {
		t.Fatalf("stale replacement error = %v", err)
	}
}

func newFixture(t *testing.T) (context.Context, *sql.DB, *Repository) {
	t.Helper()
	ctx := context.Background()
	database, err := databasepkg.Open(ctx, databasepkg.OpenOptions{Path: filepath.Join(t.TempDir(), "state.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	if err := databasepkg.Migrate(ctx, database); err != nil {
		t.Fatal(err)
	}
	repository := NewRepository(database, 1101, 0x1101)
	repository.now = func() time.Time { return time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC) }
	return ctx, database, repository
}

func insertLegacyHiLinkProjection(t *testing.T, database *sql.DB) {
	t.Helper()
	now := "2026-08-28T11:00:00Z"
	statements := []string{
		`INSERT INTO network_interfaces (
            id, stable_identity_kind, stable_identity_hash, current_ifname,
            carrier_state, observed_at, created_at, updated_at
        ) VALUES ('netif:legacy:modem-a', 'HILINK_USB_SERIAL', '` + "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" + `', 'enx-a', 'UP', '` + now + `', '` + now + `', '` + now + `')`,
		`INSERT INTO uplinks (
            id, display_number, type, name, enabled, priority, network_interface_id,
            address_mode, ipv4_cidr, gateway, dns_json, routing_table_id, fwmark,
            route_generation, state, created_at, updated_at
        ) VALUES ('modem-a', 1, 'HILINK', 'HiLink A', 1, 10, 'netif:legacy:modem-a', 'DHCP', '192.168.8.2/24', '192.168.8.1', '[]', 1101, 4353, 3, 'UPLINK_READY', '` + now + `', '` + now + `')`,
		`INSERT INTO hilink_modems (
            uplink_id, identity_kind, identity_hash, modem_state, telemetry_state,
            management_reachability_state, created_at, updated_at
        ) VALUES ('modem-a', 'USB_SERIAL', '` + "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" + `', 'MODEM_READY', 'AVAILABLE', 'REACHABLE', '` + now + `', '` + now + `')`,
		`INSERT INTO interface_role_assignments (
            id, network_interface_id, role, uplink_id, created_at, updated_at
        ) VALUES ('role:hilink:modem-a', 'netif:legacy:modem-a', 'HILINK_UPLINK', 'modem-a', '` + now + `', '` + now + `')`,
		`UPDATE settings SET value_json='2' WHERE key='next_uplink_display_number'`,
		`UPDATE settings SET value_json='1102' WHERE key='next_uplink_routing_table'`,
		`UPDATE settings SET value_json='4354' WHERE key='next_uplink_fwmark'`,
	}
	for _, statement := range statements {
		if _, err := database.Exec(statement); err != nil {
			t.Fatalf("insert HiLink projection: %v\n%s", err, statement)
		}
	}
}

func seedGenericPaths(t *testing.T, database *sql.DB, uplinkID string, routeGeneration int64) {
	t.Helper()
	now := "2026-08-28T12:00:00Z"
	statements := []string{
		`INSERT INTO subscriptions (
            id, display_number, name, source_type, enabled, priority, auto_refresh,
            refresh_interval_seconds, fallback_when_named_candidates_fail, status,
            created_at, updated_at
        ) VALUES ('sub-a', 1, 'A', 'url', 1, 10, 1, 3600, 0, 'ONLINE', '` + now + `', '` + now + `')`,
		`INSERT INTO subscription_uplink_paths (
            id, uplink_id, subscription_id, state, transport_state, quality_class,
            functional_score, required_targets_passed, required_targets_total,
            policy_generation, route_generation, last_checked_at, expires_at, created_at, updated_at
        ) VALUES ('path:ethernet-a:sub-a', '` + uplinkID + `', 'sub-a', 'QUALIFIED', 'PASSED', 'FULL', 1000, 1, 1, 1, ` + "0" + `, '` + now + `', '2026-08-28T12:15:00Z', '` + now + `', '` + now + `')`,
		`INSERT INTO direct_uplink_paths (
            id, uplink_id, state, transport_state, quality_class, functional_score,
            required_targets_passed, required_targets_total, policy_generation,
            route_generation, last_checked_at, expires_at, created_at, updated_at
        ) VALUES ('direct:path:ethernet-a', '` + uplinkID + `', 'QUALIFIED', 'PASSED', 'FULL', 1000, 1, 1, 1, ` + "0" + `, '` + now + `', '2026-08-28T12:15:00Z', '` + now + `', '` + now + `')`,
	}
	_ = routeGeneration
	for _, statement := range statements {
		if _, err := database.Exec(statement); err != nil {
			t.Fatalf("seed generic paths: %v\n%s", err, statement)
		}
	}
}
