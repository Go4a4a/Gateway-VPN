package networkapply

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"gateway-vpn/internal/uplink"
)

func TestUbuntuBackendEthernetCreateIsDurableAndRollbackRemovesCandidate(t *testing.T) {
	ctx, database := networkApplyDatabase(t)
	backend, executor, _, transactionDirectory := ubuntuBackendFixture(t)
	backend.Database = database
	backend.RoutingTableStart = 1101
	backend.FwmarkStart = 0x1101
	backend.Paths.EthernetNetworkDir = filepath.Join(filepath.Dir(backend.Paths.LANNetworkFile), "ethernet")
	if err := os.MkdirAll(backend.Paths.EthernetNetworkDir, 0o700); err != nil {
		t.Fatal(err)
	}
	repository := uplink.NewRepository(database, 1101, 0x1101)
	observeEthernetTestInterface(t, repository, "netif:wan", "enp3s0", "3")
	manifest := ethernetTestManifest(EthernetMutation{
		Operation: EthernetCreate, UplinkID: "ethernet-a", TargetInterfaceID: "netif:wan",
		Name: "WAN", AddressMode: uplink.AddressStatic, IPv4CIDR: "172.20.1.2/24",
		Gateway: "172.20.1.1", DNS: []string{"1.1.1.1"}, MTU: 1500,
	})
	if err := backend.Snapshot(ctx, manifest, transactionDirectory); err != nil {
		t.Fatalf("Snapshot(Ethernet create) error = %v", err)
	}
	if err := backend.Apply(ctx, manifest, transactionDirectory); err != nil {
		t.Fatalf("Apply(Ethernet create) error = %v", err)
	}
	created, err := repository.Get(ctx, "ethernet-a")
	if err != nil || created.NetworkInterfaceID != "netif:wan" || created.AddressMode != uplink.AddressStatic {
		t.Fatalf("created Ethernet = %+v, %v", created, err)
	}
	owned := backend.ethernetOwnedPath("ethernet-a")
	if _, err := os.Stat(owned); err != nil {
		t.Fatalf("owned networkd file: %v", err)
	}
	if !executor.called(backend.Paths.Networkctl, "reload") || !executor.called(backend.Paths.Networkctl, "reconfigure", "enp3s0") {
		t.Fatalf("networkctl calls = %+v", executor.calls)
	}
	if err := backend.Commit(ctx, manifest, transactionDirectory); err != nil {
		t.Fatalf("Commit(Ethernet create) error = %v", err)
	}
	if err := backend.Rollback(ctx, manifest, transactionDirectory); err != nil {
		t.Fatalf("Rollback(Ethernet create) error = %v", err)
	}
	if _, err := repository.Get(ctx, "ethernet-a"); err == nil {
		t.Fatal("rolled-back Ethernet uplink still exists")
	}
	if _, err := os.Stat(owned); !os.IsNotExist(err) {
		t.Fatalf("rolled-back networkd file error = %v", err)
	}
}

func TestUbuntuBackendEthernetReplacementRollbackRestoresRoleAndAdvancesGeneration(t *testing.T) {
	ctx, database := networkApplyDatabase(t)
	backend, _, _, transactionDirectory := ubuntuBackendFixture(t)
	backend.Database = database
	backend.RoutingTableStart = 1101
	backend.FwmarkStart = 0x1101
	backend.Paths.EthernetNetworkDir = filepath.Join(filepath.Dir(backend.Paths.LANNetworkFile), "ethernet")
	if err := os.MkdirAll(backend.Paths.EthernetNetworkDir, 0o700); err != nil {
		t.Fatal(err)
	}
	repository := uplink.NewRepository(database, 1101, 0x1101)
	observeEthernetTestInterface(t, repository, "netif:old", "enp3s0", "4")
	observeEthernetTestInterface(t, repository, "netif:new", "enp4s0", "5")
	created, err := repository.CreateEthernet(ctx, uplink.CreateEthernetInput{
		ID: "ethernet-a", Name: "WAN", NetworkInterfaceID: "netif:old", AddressMode: uplink.AddressDHCP,
	})
	if err != nil {
		t.Fatal(err)
	}
	manifest := ethernetTestManifest(EthernetMutation{
		Operation: EthernetReplaceInterface, UplinkID: created.ID,
		ExpectedDesiredGeneration: created.DesiredGeneration, TargetInterfaceID: "netif:new",
		AddressMode: uplink.AddressDHCP, DNS: []string{},
	})
	if err := backend.Snapshot(ctx, manifest, transactionDirectory); err != nil {
		t.Fatal(err)
	}
	if err := backend.Apply(ctx, manifest, transactionDirectory); err != nil {
		t.Fatal(err)
	}
	replaced, err := repository.Get(ctx, created.ID)
	if err != nil || replaced.NetworkInterfaceID != "netif:new" {
		t.Fatalf("replaced Ethernet = %+v, %v", replaced, err)
	}
	if err := backend.Rollback(ctx, manifest, transactionDirectory); err != nil {
		t.Fatal(err)
	}
	restored, err := repository.Get(ctx, created.ID)
	if err != nil || restored.NetworkInterfaceID != "netif:old" || restored.DesiredGeneration <= replaced.DesiredGeneration || restored.RouteGeneration <= replaced.RouteGeneration {
		t.Fatalf("restored Ethernet = %+v, %v; replaced=%+v", restored, err, replaced)
	}
	var role string
	if err := database.QueryRowContext(ctx, "SELECT role FROM interface_role_assignments WHERE network_interface_id='netif:old'").Scan(&role); err != nil || role != "ETHERNET_UPLINK" {
		t.Fatalf("restored old role = %s, %v", role, err)
	}
}

func TestUbuntuBackendEthernetStaticToDHCPRollbackRestoresPreviousNetwork(t *testing.T) {
	ctx, database := networkApplyDatabase(t)
	backend, _, _, transactionDirectory := ubuntuBackendFixture(t)
	backend.Database = database
	backend.RoutingTableStart = 1101
	backend.FwmarkStart = 0x1101
	backend.Paths.EthernetNetworkDir = filepath.Join(filepath.Dir(backend.Paths.LANNetworkFile), "ethernet")
	if err := os.MkdirAll(backend.Paths.EthernetNetworkDir, 0o700); err != nil {
		t.Fatal(err)
	}
	repository := uplink.NewRepository(database, 1101, 0x1101)
	observeEthernetTestInterface(t, repository, "netif:wan", "enp3s0", "8")
	created, err := repository.CreateEthernet(ctx, uplink.CreateEthernetInput{
		ID: "ethernet-a", Name: "WAN", NetworkInterfaceID: "netif:wan",
		AddressMode: uplink.AddressStatic, IPv4CIDR: "172.20.1.2/24",
		Gateway: "172.20.1.1", DNS: []string{"1.1.1.1"}, MTU: 1500,
	})
	if err != nil {
		t.Fatal(err)
	}
	previousNetwork, err := renderEthernetNetwork(created)
	if err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, backend.ethernetOwnedPath(created.ID), []byte(previousNetwork))
	manifest := ethernetTestManifest(EthernetMutation{
		Operation: EthernetUpdateAddress, UplinkID: created.ID,
		ExpectedDesiredGeneration: created.DesiredGeneration, TargetInterfaceID: "netif:wan",
		AddressMode: uplink.AddressDHCP, DNS: []string{}, MTU: 1500,
	})
	if err := backend.Snapshot(ctx, manifest, transactionDirectory); err != nil {
		t.Fatal(err)
	}
	if err := backend.Apply(ctx, manifest, transactionDirectory); err != nil {
		t.Fatal(err)
	}
	dhcp, err := repository.Get(ctx, created.ID)
	if err != nil || dhcp.AddressMode != uplink.AddressDHCP {
		t.Fatalf("DHCP candidate = %+v, %v", dhcp, err)
	}
	if err := backend.Rollback(ctx, manifest, transactionDirectory); err != nil {
		t.Fatal(err)
	}
	restored, err := repository.Get(ctx, created.ID)
	if err != nil || restored.AddressMode != uplink.AddressStatic || restored.IPv4CIDR != created.IPv4CIDR || restored.Gateway != created.Gateway || restored.DesiredGeneration <= dhcp.DesiredGeneration {
		t.Fatalf("restored static Ethernet = %+v, %v; DHCP=%+v", restored, err, dhcp)
	}
	content, err := os.ReadFile(backend.ethernetOwnedPath(created.ID))
	if err != nil || string(content) != previousNetwork {
		t.Fatalf("restored networkd = %v / %q", err, content)
	}
}

func TestUbuntuBackendEthernetRejectsRoleAndSubnetConflictsBeforeSnapshot(t *testing.T) {
	ctx, database := networkApplyDatabase(t)
	backend, _, _, transactionDirectory := ubuntuBackendFixture(t)
	backend.Database = database
	backend.RoutingTableStart = 1101
	backend.FwmarkStart = 0x1101
	backend.Paths.EthernetNetworkDir = filepath.Join(filepath.Dir(backend.Paths.LANNetworkFile), "ethernet")
	if err := os.MkdirAll(backend.Paths.EthernetNetworkDir, 0o700); err != nil {
		t.Fatal(err)
	}
	repository := uplink.NewRepository(database, 1101, 0x1101)
	observeEthernetTestInterface(t, repository, "netif:wan", "enp3s0", "6")
	manifest := ethernetTestManifest(EthernetMutation{
		Operation: EthernetCreate, UplinkID: "ethernet-a", TargetInterfaceID: "netif:wan",
		Name: "WAN", AddressMode: uplink.AddressStatic, IPv4CIDR: "192.168.200.2/24",
		Gateway: "192.168.200.254", DNS: []string{},
	})
	if err := backend.Snapshot(ctx, manifest, transactionDirectory); err == nil {
		t.Fatal("Snapshot accepted Ethernet subnet overlapping management LAN")
	}
	now := "2026-08-28T12:00:00Z"
	if _, err := database.ExecContext(ctx, `
INSERT INTO interface_role_assignments(id, network_interface_id, role, created_at, updated_at)
VALUES ('role:management:wan', 'netif:wan', 'MANAGEMENT', ?, ?)`, now, now); err != nil {
		t.Fatal(err)
	}
	manifest = ethernetTestManifest(EthernetMutation{
		Operation: EthernetCreate, UplinkID: "ethernet-a", TargetInterfaceID: "netif:wan",
		Name: "WAN", AddressMode: uplink.AddressDHCP, DNS: []string{},
	})
	if err := backend.Snapshot(ctx, manifest, transactionDirectory); err == nil {
		t.Fatal("Snapshot accepted interface with a conflicting management role")
	}
}

func TestUbuntuBackendEthernetRejectsInterfaceRemovedAfterSnapshot(t *testing.T) {
	ctx, database := networkApplyDatabase(t)
	backend, _, _, transactionDirectory := ubuntuBackendFixture(t)
	backend.Database = database
	backend.RoutingTableStart = 1101
	backend.FwmarkStart = 0x1101
	backend.Paths.EthernetNetworkDir = filepath.Join(filepath.Dir(backend.Paths.LANNetworkFile), "ethernet")
	if err := os.MkdirAll(backend.Paths.EthernetNetworkDir, 0o700); err != nil {
		t.Fatal(err)
	}
	repository := uplink.NewRepository(database, 1101, 0x1101)
	observeEthernetTestInterface(t, repository, "netif:wan", "enp3s0", "9")
	manifest := ethernetTestManifest(EthernetMutation{
		Operation: EthernetCreate, UplinkID: "ethernet-a", TargetInterfaceID: "netif:wan",
		Name: "WAN", AddressMode: uplink.AddressDHCP, DNS: []string{},
	})
	if err := backend.Snapshot(ctx, manifest, transactionDirectory); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(ctx, "UPDATE network_interfaces SET current_ifname=NULL, carrier_state='ABSENT' WHERE id='netif:wan'"); err != nil {
		t.Fatal(err)
	}
	if err := backend.Apply(ctx, manifest, transactionDirectory); err == nil {
		t.Fatal("Apply accepted target NIC removed after snapshot")
	}
	if _, err := repository.Get(ctx, "ethernet-a"); err == nil {
		t.Fatal("removed-NIC apply mutated canonical uplink state")
	}
}

func TestUbuntuBackendEthernetDeleteKeepsCanonicalStateUntilConfirmationAndRollsBackFile(t *testing.T) {
	ctx, database := networkApplyDatabase(t)
	backend, _, _, transactionDirectory := ubuntuBackendFixture(t)
	backend.Database = database
	backend.RoutingTableStart = 1101
	backend.FwmarkStart = 0x1101
	backend.Paths.EthernetNetworkDir = filepath.Join(filepath.Dir(backend.Paths.LANNetworkFile), "ethernet")
	if err := os.MkdirAll(backend.Paths.EthernetNetworkDir, 0o700); err != nil {
		t.Fatal(err)
	}
	repository := uplink.NewRepository(database, 1101, 0x1101)
	observeEthernetTestInterface(t, repository, "netif:wan", "enp3s0", "a")
	created, err := repository.CreateEthernet(ctx, uplink.CreateEthernetInput{
		ID: "ethernet-a", Name: "WAN", NetworkInterfaceID: "netif:wan",
		AddressMode: uplink.AddressDHCP, DNS: []string{"9.9.9.9"},
	})
	if err != nil {
		t.Fatal(err)
	}
	disabled, err := repository.SetEthernetEnabled(ctx, created.ID, uplink.SetEthernetEnabledInput{Enabled: false, ExpectedDesiredGeneration: created.DesiredGeneration})
	if err != nil {
		t.Fatal(err)
	}
	owned := backend.ethernetOwnedPath(created.ID)
	previousNetwork, err := renderEthernetNetwork(disabled)
	if err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, owned, []byte(previousNetwork))
	manifest := ethernetTestManifest(EthernetMutation{
		Operation: EthernetDelete, UplinkID: disabled.ID,
		ExpectedDesiredGeneration: disabled.DesiredGeneration, TargetInterfaceID: disabled.NetworkInterfaceID,
	})
	if err := backend.Snapshot(ctx, manifest, transactionDirectory); err != nil {
		t.Fatal(err)
	}
	if err := backend.Apply(ctx, manifest, transactionDirectory); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(owned); !os.IsNotExist(err) {
		t.Fatalf("delete candidate owned file = %v", err)
	}
	stillStored, err := repository.Get(ctx, disabled.ID)
	if err != nil || stillStored.DesiredGeneration != disabled.DesiredGeneration {
		t.Fatalf("unconfirmed delete changed canonical state = %+v, %v", stillStored, err)
	}
	if err := backend.Rollback(ctx, manifest, transactionDirectory); err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(owned)
	if err != nil || string(content) != previousNetwork {
		t.Fatalf("delete rollback file = %q, %v", content, err)
	}
	restored, err := repository.Get(ctx, disabled.ID)
	if err != nil || restored.DesiredGeneration != disabled.DesiredGeneration || restored.Enabled {
		t.Fatalf("delete rollback canonical state = %+v, %v", restored, err)
	}
}

func TestUbuntuBackendEthernetDeleteCommitAtomicallyRemovesDisabledUplink(t *testing.T) {
	ctx, database := networkApplyDatabase(t)
	backend, _, _, transactionDirectory := ubuntuBackendFixture(t)
	backend.Database = database
	backend.RoutingTableStart = 1101
	backend.FwmarkStart = 0x1101
	backend.Paths.EthernetNetworkDir = filepath.Join(filepath.Dir(backend.Paths.LANNetworkFile), "ethernet")
	if err := os.MkdirAll(backend.Paths.EthernetNetworkDir, 0o700); err != nil {
		t.Fatal(err)
	}
	repository := uplink.NewRepository(database, 1101, 0x1101)
	observeEthernetTestInterface(t, repository, "netif:wan", "enp3s0", "b")
	created, err := repository.CreateEthernet(ctx, uplink.CreateEthernetInput{ID: "ethernet-a", Name: "WAN", NetworkInterfaceID: "netif:wan", AddressMode: uplink.AddressDHCP})
	if err != nil {
		t.Fatal(err)
	}
	disabled, err := repository.SetEthernetEnabled(ctx, created.ID, uplink.SetEthernetEnabledInput{Enabled: false, ExpectedDesiredGeneration: created.DesiredGeneration})
	if err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, backend.ethernetOwnedPath(created.ID), []byte("owned"))
	manifest := ethernetTestManifest(EthernetMutation{Operation: EthernetDelete, UplinkID: disabled.ID, ExpectedDesiredGeneration: disabled.DesiredGeneration, TargetInterfaceID: disabled.NetworkInterfaceID})
	if err := backend.Snapshot(ctx, manifest, transactionDirectory); err != nil {
		t.Fatal(err)
	}
	if err := backend.Apply(ctx, manifest, transactionDirectory); err != nil {
		t.Fatal(err)
	}
	if err := backend.Commit(ctx, manifest, transactionDirectory); err != nil {
		t.Fatal(err)
	}
	if _, err := repository.Get(ctx, disabled.ID); err == nil {
		t.Fatal("confirmed delete retained Ethernet uplink")
	}
	var roles int
	if err := database.QueryRowContext(ctx, "SELECT COUNT(*) FROM interface_role_assignments WHERE uplink_id=?", disabled.ID).Scan(&roles); err != nil || roles != 0 {
		t.Fatalf("confirmed delete roles = %d, %v", roles, err)
	}
	// Confirmation replay after a crash is intentionally idempotent.
	if err := backend.Commit(ctx, manifest, transactionDirectory); err != nil {
		t.Fatalf("idempotent delete commit = %v", err)
	}
}

func observeEthernetTestInterface(t *testing.T, repository *uplink.Repository, id, ifname, digit string) {
	t.Helper()
	if _, err := repository.ObserveInterface(context.Background(), uplink.InterfaceObservation{
		ID: id, StableIdentityKind: "PERMANENT_MAC",
		StableIdentityHash: digit + "000000000000000000000000000000000000000000000000000000000000000",
		CurrentIfname:      ifname, CarrierState: "UP",
	}); err != nil {
		t.Fatal(err)
	}
}

func ethernetTestManifest(mutation EthernetMutation) Manifest {
	created := time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC)
	return Manifest{
		SchemaVersion: ManifestSchema, ID: "apply-ethernet", OperationKind: OperationEthernetUplink,
		OldURL: "https://192.168.200.1:8443", NewURL: "https://192.168.200.1:8443",
		NewDestinationIP: "192.168.200.1", Ethernet: &mutation,
		CreatedAt: created.Format(time.RFC3339Nano), RollbackDeadline: created.Add(time.Minute).Format(time.RFC3339Nano),
	}
}
