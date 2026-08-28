package ethernet

import (
	"context"
	"database/sql"
	"errors"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"

	databasepkg "gateway-vpn/internal/db"
	"gateway-vpn/internal/hilink"
	"gateway-vpn/internal/uplink"
)

type probeFixture struct {
	devices []Device
	err     error
}

func (probe probeFixture) List(context.Context) ([]Device, error) {
	return append([]Device(nil), probe.devices...), probe.err
}

type leaseFixture struct {
	lease hilink.Lease
	err   error
}

func (reader leaseFixture) Lease(context.Context, string) (hilink.Lease, error) {
	return reader.lease, reader.err
}

type routeFixture struct {
	calls int
	err   error
}

func (routes *routeFixture) SyncRouting(context.Context) error {
	routes.calls++
	return routes.err
}

func TestManagerConvergesDHCPAndInvalidatesOnceOnCarrierLoss(t *testing.T) {
	ctx, database, repository, created := ethernetFixture(t, uplink.AddressDHCP)
	routes := &routeFixture{}
	device := observedDevice("netif:wan", "enp3s0", "UP", []string{"172.20.1.2/24"})
	manager := &Manager{
		Probe: probeFixture{devices: []Device{device}}, LeaseReader: leaseFixture{lease: hilink.Lease{
			InterfaceName: "enp3s0", Address: netip.MustParsePrefix("172.20.1.2/24"),
			ManagementPrefix: netip.MustParsePrefix("172.20.1.0/24"), Gateway: netip.MustParseAddr("172.20.1.1"),
			DNS: []netip.Addr{netip.MustParseAddr("1.1.1.1")}, MTU: 1500,
		}}, Routes: routes, Uplinks: repository, LANPrefix: "192.168.200.1/24", WireGuardPrefix: "10.80.0.0/24",
	}
	result, err := manager.Reconcile(ctx)
	if err != nil || len(result.ReadyUplinks) != 1 || result.ReadyUplinks[0] != created.ID || routes.calls != 1 {
		t.Fatalf("ready reconcile = %+v, %v; route calls=%d", result, err, routes.calls)
	}
	ready, err := repository.Get(ctx, created.ID)
	if err != nil || ready.State != uplink.StateReady || ready.ReadinessReason != ReasonReady || ready.IPv4CIDR != "172.20.1.2/24" || ready.Gateway != "172.20.1.1" || ready.ObservedGeneration != ready.DesiredGeneration || ready.RouteGeneration != 1 {
		t.Fatalf("ready Ethernet = %+v, %v", ready, err)
	}
	var roleState string
	var roleObserved int64
	if err := database.QueryRow("SELECT state, observed_generation FROM interface_role_assignments WHERE uplink_id=?", created.ID).Scan(&roleState, &roleObserved); err != nil || roleState != "APPLIED" || roleObserved != ready.DesiredGeneration {
		t.Fatalf("ready role = %s/%d, %v", roleState, roleObserved, err)
	}

	manager.Probe = probeFixture{devices: []Device{observedDevice("netif:wan", "enp3s0", "DOWN", nil)}}
	result, err = manager.Reconcile(ctx)
	if err != nil || result.Reasons[created.ID] != ReasonCarrierDown {
		t.Fatalf("carrier-down reconcile = %+v, %v", result, err)
	}
	offline, _ := repository.Get(ctx, created.ID)
	if offline.State != uplink.StateConfiguredOffline || offline.ReadinessReason != ReasonCarrierDown || offline.RouteGeneration != 2 || offline.ObservedGeneration != 0 {
		t.Fatalf("offline Ethernet = %+v", offline)
	}
	if _, err := manager.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	stillOffline, _ := repository.Get(ctx, created.ID)
	if stillOffline.RouteGeneration != 2 {
		t.Fatalf("repeated carrier loss advanced route generation to %d", stillOffline.RouteGeneration)
	}
}

func TestManagerUsesConfiguredDHCPDNSWithoutLosingLeaseAddress(t *testing.T) {
	ctx, _, repository, created := ethernetFixture(t, uplink.AddressDHCP)
	configured, err := repository.UpdateEthernetConfiguration(ctx, created.ID, uplink.UpdateEthernetInput{
		NetworkInterfaceID: created.NetworkInterfaceID, AddressMode: uplink.AddressDHCP,
		DNS: []string{"9.9.9.9"}, ExpectedDesiredGeneration: created.DesiredGeneration,
	})
	if err != nil {
		t.Fatal(err)
	}
	manager := &Manager{
		Probe: probeFixture{devices: []Device{observedDevice("netif:wan", "enp3s0", "UP", []string{"172.20.1.2/24"})}},
		LeaseReader: leaseFixture{lease: hilink.Lease{
			InterfaceName: "enp3s0", Address: netip.MustParsePrefix("172.20.1.2/24"),
			ManagementPrefix: netip.MustParsePrefix("172.20.1.0/24"), Gateway: netip.MustParseAddr("172.20.1.1"),
			DNS: []netip.Addr{netip.MustParseAddr("1.1.1.1")}, MTU: 1500,
		}}, Routes: &routeFixture{}, Uplinks: repository,
		LANPrefix: "192.168.200.1/24", WireGuardPrefix: "10.80.0.0/24",
	}
	if _, err := manager.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	stored, err := repository.Get(ctx, created.ID)
	if err != nil || stored.IPv4CIDR != "172.20.1.2/24" || stored.Gateway != "172.20.1.1" ||
		stored.DNSJSON != `["9.9.9.9"]` || stored.ConfiguredDNSJSON != `["9.9.9.9"]` ||
		stored.DesiredGeneration != configured.DesiredGeneration {
		t.Fatalf("configured DHCP runtime = %+v, %v", stored, err)
	}
}

func TestManagerDetectsEthernetSubnetConflictWithoutRoutingIt(t *testing.T) {
	ctx, _, repository, created := ethernetFixture(t, uplink.AddressStatic)
	routes := &routeFixture{}
	manager := &Manager{
		Probe:       probeFixture{devices: []Device{observedDevice("netif:wan", "enp3s0", "UP", []string{"192.168.200.20/24"})}},
		LeaseReader: leaseFixture{}, Routes: routes, Uplinks: repository,
		LANPrefix: "192.168.200.1/24", WireGuardPrefix: "10.80.0.0/24",
	}
	result, err := manager.Reconcile(ctx)
	if err != nil || result.ConflictUplinks[created.ID] == "" || len(result.ReadyUplinks) != 0 {
		t.Fatalf("conflict reconcile = %+v, %v", result, err)
	}
	stored, _ := repository.Get(ctx, created.ID)
	if stored.State != uplink.StateSubnetConflict || stored.ReadinessReason != ReasonSubnetConflict || stored.ObservedGeneration != stored.DesiredGeneration {
		t.Fatalf("conflicting Ethernet = %+v", stored)
	}
}

func TestManagerFailsClosedWhenAuthoritativeRoutingCannotConverge(t *testing.T) {
	ctx, _, repository, created := ethernetFixture(t, uplink.AddressDHCP)
	routes := &routeFixture{err: errors.New("private iproute failure")}
	manager := &Manager{
		Probe: probeFixture{devices: []Device{observedDevice("netif:wan", "enp3s0", "UP", []string{"172.20.1.2/24"})}},
		LeaseReader: leaseFixture{lease: hilink.Lease{
			InterfaceName: "enp3s0", Address: netip.MustParsePrefix("172.20.1.2/24"),
			ManagementPrefix: netip.MustParsePrefix("172.20.1.0/24"), Gateway: netip.MustParseAddr("172.20.1.1"),
			DNS: []netip.Addr{netip.MustParseAddr("1.1.1.1")}, MTU: 1500,
		}}, Routes: routes, Uplinks: repository, LANPrefix: "192.168.200.1/24", WireGuardPrefix: "10.80.0.0/24",
	}
	if _, err := manager.Reconcile(ctx); err == nil || strings.Contains(err.Error(), "private iproute") == false {
		t.Fatalf("routing failure = %v", err)
	}
	stored, _ := repository.Get(ctx, created.ID)
	if stored.State != uplink.StateConfiguring || stored.ReadinessReason != ReasonRoutingSyncFailed || stored.ObservedGeneration != 0 || routes.calls != 2 {
		t.Fatalf("routing-failed Ethernet = %+v; calls=%d", stored, routes.calls)
	}
}

func ethernetFixture(t *testing.T, addressMode string) (context.Context, *sql.DB, *uplink.Repository, uplink.Uplink) {
	t.Helper()
	ctx := context.Background()
	database, err := databasepkg.Open(ctx, databasepkg.OpenOptions{Path: filepath.Join(t.TempDir(), "state.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	if err := databasepkg.Migrate(ctx, database); err != nil {
		t.Fatal(err)
	}
	repository := uplink.NewRepository(database, 1101, 0x1101)
	device := observedDevice("netif:wan", "enp3s0", "UP", nil)
	if _, err := repository.ObserveInterface(ctx, device.Observation); err != nil {
		t.Fatal(err)
	}
	input := uplink.CreateEthernetInput{ID: "ethernet-a", Name: "Provider A", NetworkInterfaceID: "netif:wan", AddressMode: addressMode}
	if addressMode == uplink.AddressStatic {
		input.IPv4CIDR, input.Gateway, input.DNS = "192.168.200.20/24", "192.168.200.2", []string{"1.1.1.1"}
	}
	created, err := repository.CreateEthernet(ctx, input)
	if err != nil {
		t.Fatal(err)
	}
	return ctx, database, repository, created
}

func observedDevice(id, ifname, carrier string, addresses []string) Device {
	return Device{Observation: uplink.InterfaceObservation{
		ID: id, StableIdentityKind: "ETHERNET_PERMANENT_MAC",
		StableIdentityHash: strings.Repeat("a", 64), PermanentMAC: "02:00:00:00:00:01",
		CurrentIfname: ifname, CarrierState: carrier, Addresses: addresses,
	}, MTU: 1500}
}
