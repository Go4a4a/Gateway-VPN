package networkapply

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gateway-vpn/internal/store"
	"gateway-vpn/internal/uplink"
	"gateway-vpn/internal/wgingress"
)

type topologyGateFake struct {
	calls int
	err   error
}

func (gate *topologyGateFake) BlockPath(context.Context) error {
	gate.calls++
	return gate.err
}

type topologyRoutingFake struct {
	calls int
	err   error
}

func (routing *topologyRoutingFake) SyncRouting(context.Context) error {
	routing.calls++
	return routing.err
}

type topologyContextFake struct {
	interfaceName string
	lanCIDR       string
	calls         int
}

func (runtime *topologyContextFake) SetTopologyNetwork(interfaceName, lanCIDR string) error {
	runtime.interfaceName, runtime.lanCIDR = interfaceName, lanCIDR
	runtime.calls++
	return nil
}

type topologyIngressFake struct {
	updates []wgingress.ServerUpdate
	syncs   int
}

func (ingress *topologyIngressFake) UpdateServer(_ context.Context, update wgingress.ServerUpdate) (wgingress.Server, error) {
	ingress.updates = append(ingress.updates, update)
	return wgingress.Server{}, nil
}

func (ingress *topologyIngressFake) Sync(context.Context) error {
	ingress.syncs++
	return nil
}

func TestUbuntuBackendTopologyApplyCommitIsRecoverableAndRollbackRestoresLKG(t *testing.T) {
	ctx, database := networkApplyDatabase(t)
	backend, executor, _, transactionDirectory := ubuntuBackendFixture(t)
	gate := &topologyGateFake{}
	routing := &topologyRoutingFake{}
	runtime := &topologyContextFake{}
	ingress := &topologyIngressFake{}
	configureTopologyBackendFixture(t, ctx, &backend, database, gate, routing, runtime, ingress)
	manifest := topologyTestManifest()

	if err := backend.Snapshot(ctx, manifest, transactionDirectory); err != nil {
		t.Fatalf("Snapshot(topology) error = %v", err)
	}
	if err := backend.Apply(ctx, manifest, transactionDirectory); err != nil {
		t.Fatalf("Apply(topology) error = %v", err)
	}
	if !executor.addresses[manifest.Topology.LANAddress] || !executor.addresses["192.168.200.1/24"] {
		t.Fatalf("grace addresses after apply = %+v", executor.addresses)
	}
	if runtime.interfaceName != "gateway-vpn-lan" || runtime.lanCIDR != "192.168.210.1/24" || gate.calls < 2 || routing.calls != 1 {
		t.Fatalf("candidate runtime = %s %s gate:%d routing:%d", runtime.interfaceName, runtime.lanCIDR, gate.calls, routing.calls)
	}
	if executor.called(backend.Paths.Networkctl, "reconfigure", "enxhilink0") {
		t.Fatal("topology apply reconfigured an unrelated HiLink uplink")
	}
	legacyMember := filepath.Join(backend.Paths.EthernetNetworkDir, "06-gateway-vpn-lan-enp2s0.network")
	if _, err := os.Stat(legacyMember); err != nil {
		t.Fatalf("legacy member was removed before confirmation: %v", err)
	}
	if _, err := os.Stat(backend.Paths.LANNetDevFile); err != nil {
		t.Fatalf("owned bridge netdev was not created: %v", err)
	}
	var profile, state string
	var desired, applied int64
	if err := database.QueryRowContext(ctx, `SELECT active_profile,desired_generation,applied_generation,state FROM topology_profile_state WHERE singleton_id=1`).Scan(&profile, &desired, &applied, &state); err != nil {
		t.Fatal(err)
	}
	if profile != TopologyEthernetHiLink || desired != 2 || applied != 1 || state != "APPLYING" {
		t.Fatalf("applied topology DB = %s %d/%d %s", profile, desired, applied, state)
	}

	if err := backend.Commit(ctx, manifest, transactionDirectory); err != nil {
		t.Fatalf("Commit(topology) error = %v", err)
	}
	if err := backend.Commit(ctx, manifest, transactionDirectory); err != nil {
		t.Fatalf("recovered idempotent Commit(topology) error = %v", err)
	}
	if err := database.QueryRowContext(ctx, `SELECT active_profile,desired_generation,applied_generation,state FROM topology_profile_state WHERE singleton_id=1`).Scan(&profile, &desired, &applied, &state); err != nil {
		t.Fatal(err)
	}
	if desired != 2 || applied != 2 || state != "ACTIVE" || executor.addresses["192.168.200.1/24"] {
		t.Fatalf("confirmed topology = %s %d/%d %s addresses=%+v", profile, desired, applied, state, executor.addresses)
	}
	if _, err := os.Stat(legacyMember); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("legacy member was not retired after confirmation: %v", err)
	}
	installed, err := os.ReadFile(backend.Paths.ConfigFile)
	if err != nil || !strings.Contains(string(installed), "lan_interface: gateway-vpn-lan") || strings.Count(string(installed), "192.168.200.1:8443") != 0 {
		t.Fatalf("final topology config = %v / %s", err, installed)
	}

	if err := backend.Rollback(ctx, manifest, transactionDirectory); err != nil {
		t.Fatalf("Rollback(confirmed topology) error = %v", err)
	}
	if err := database.QueryRowContext(ctx, `SELECT active_profile,desired_generation,applied_generation,state FROM topology_profile_state WHERE singleton_id=1`).Scan(&profile, &desired, &applied, &state); err != nil {
		t.Fatal(err)
	}
	if desired != 1 || applied != 1 || state != "ACTIVE" || runtime.interfaceName != "enp2s0" || runtime.lanCIDR != "192.168.200.1/24" {
		t.Fatalf("restored topology = %s %d/%d %s runtime=%s/%s", profile, desired, applied, state, runtime.interfaceName, runtime.lanCIDR)
	}
	if !executor.addresses["192.168.200.1/24"] || executor.addresses[manifest.Topology.LANAddress] {
		t.Fatalf("rollback addresses = %+v", executor.addresses)
	}
	if content, err := os.ReadFile(legacyMember); err != nil || !strings.Contains(string(content), "legacy installer member") {
		t.Fatalf("rollback did not restore legacy member: %v / %s", err, content)
	}
	if _, err := os.Stat(backend.Paths.LANNetDevFile); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("rollback did not remove newly-created bridge netdev: %v", err)
	}
	var oldRoles int
	if err := database.QueryRowContext(ctx, `SELECT COUNT(*) FROM interface_role_assignments WHERE network_interface_id='netif:lan' AND role IN ('LAN_MEMBER','MANAGEMENT')`).Scan(&oldRoles); err != nil || oldRoles != 2 {
		t.Fatalf("restored LAN roles = %d, %v", oldRoles, err)
	}
}

func TestUbuntuBackendOneArmPreviewUsesWireGuardIngressAsPeerScopedManagementPath(t *testing.T) {
	ctx, database := networkApplyDatabase(t)
	backend, _, _, _ := ubuntuBackendFixture(t)
	configureTopologyBackendFixture(t, ctx, &backend, database, &topologyGateFake{}, &topologyRoutingFake{}, &topologyContextFake{}, &topologyIngressFake{})
	if _, err := database.ExecContext(ctx, `
INSERT INTO network_interfaces(id,stable_identity_kind,stable_identity_hash,current_ifname,carrier_state,created_at,updated_at)
VALUES('netif:wan','PERMANENT_MAC','wan-hash','enp3s0','UP','now','now');
INSERT INTO uplinks(id,display_number,type,name,enabled,priority,network_interface_id,address_mode,routing_table_id,fwmark,state,created_at,updated_at)
VALUES('ethernet-a',2,'ETHERNET','Router uplink',1,2,'netif:wan','DHCP',1102,4354,'UPLINK_READY','now','now');
INSERT INTO interface_role_assignments(id,network_interface_id,role,uplink_id,created_at,updated_at)
VALUES('role:wan','netif:wan','ETHERNET_UPLINK','ethernet-a','now','now');
INSERT INTO wireguard_ingress_servers(
 id,enabled,name,interface_name,subnet_cidr,listen_port,endpoint_host,mtu,
 private_key_secret_ref,public_key,topology_mode,config_generation,created_at,updated_at
) VALUES('wg-ingress-default',1,'Ingress','wg-ingress','10.90.0.0/24',51820,'router.example',1420,
 '/tmp/key','AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=','ROUTED',1,'now','now');
INSERT INTO wireguard_ingress_runtime(server_id,desired_generation,applied_generation,state,updated_at)
VALUES('wg-ingress-default',1,1,'ACTIVE','now');
`); err != nil {
		t.Fatal(err)
	}
	manifest := topologyTestManifest()
	manifest.NewURL = "https://10.90.0.1:8443"
	manifest.NewDestinationIP = "10.90.0.1"
	manifest.Topology = &TopologyMutation{
		ExpectedDesiredGeneration: 1, Profile: TopologyOneArmWireGuard,
		ManagementInterfaceIDs: []string{"netif:wan"}, SharedOneArmInterfaceID: "netif:wan",
		LANInterfaceName: "wg-ingress", LANAddress: "10.90.0.1/24",
		IngressEnabled: true, IngressTopologyMode: "ONE_ARM",
		IngressListenInterfaces: []TopologyListenInterface{{NetworkInterfaceID: "netif:wan", ExposureMode: "PUBLIC", Priority: 1}},
	}
	preview, err := backend.PreviewTopology(ctx, manifest)
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(preview.ManagementInterfaces, ",")
	if joined != "wg-ingress,enp3s0" {
		t.Fatalf("one-arm management interfaces = %q", joined)
	}
}

func TestUbuntuBackendTopologyEthernetIntentIsTransactionOwnedAndRollbackRemovesIt(t *testing.T) {
	ctx, database := networkApplyDatabase(t)
	backend, executor, _, transactionDirectory := ubuntuBackendFixture(t)
	gate := &topologyGateFake{}
	routing := &topologyRoutingFake{}
	runtime := &topologyContextFake{}
	configureTopologyBackendFixture(t, ctx, &backend, database, gate, routing, runtime, &topologyIngressFake{})
	// The shared topology fixture already contains a HiLink row at the legacy
	// 1101/0x1101 counters; start newly-created Ethernet records above it.
	backend.RoutingTableStart = 2001
	backend.FwmarkStart = 0x2201
	if _, err := database.ExecContext(ctx, `
UPDATE settings SET value_json='3' WHERE key='next_uplink_display_number';
UPDATE settings SET value_json='2001' WHERE key='next_uplink_routing_table';
UPDATE settings SET value_json='8705' WHERE key='next_uplink_fwmark';
`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(ctx, `
INSERT INTO network_interfaces(id,stable_identity_kind,stable_identity_hash,current_ifname,carrier_state,created_at,updated_at)
VALUES
 ('netif:wan1','PERMANENT_MAC','wan1-hash','enp3s0','UP','now','now'),
 ('netif:wan2','PERMANENT_MAC','wan2-hash','enp4s0','UP','now','now');
`); err != nil {
		t.Fatal(err)
	}
	manifest := topologyTestManifest()
	manifest.Topology.Profile = TopologyEthernetEthernet
	manifest.Topology.EthernetUplinks = []TopologyEthernetUplink{
		{ID: "initial-ethernet-a", Name: "Ethernet enp3s0", NetworkInterfaceID: "netif:wan1", AddressMode: "DHCP"},
		{ID: "initial-ethernet-b", Name: "Ethernet enp4s0", NetworkInterfaceID: "netif:wan2", AddressMode: "DHCP"},
	}

	if err := backend.Snapshot(ctx, manifest, transactionDirectory); err != nil {
		t.Fatalf("Snapshot(topology with Ethernet intent) error = %v", err)
	}
	for _, item := range manifest.Topology.EthernetUplinks {
		if _, err := (uplink.NewRepository(database, 2001, 0x2201)).Get(ctx, item.ID); err == nil {
			t.Fatalf("uplink %s was created before apply", item.ID)
		}
		if _, err := os.Stat(backend.ethernetOwnedPath(item.ID)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("networkd policy %s exists before apply: %v", item.ID, err)
		}
	}
	if err := backend.Apply(ctx, manifest, transactionDirectory); err != nil {
		t.Fatalf("Apply(topology with Ethernet intent) error = %v", err)
	}
	for _, item := range manifest.Topology.EthernetUplinks {
		created, err := (uplink.NewRepository(database, 2001, 0x2201)).Get(ctx, item.ID)
		if err != nil || created.Type != uplink.TypeEthernet || created.NetworkInterfaceID != item.NetworkInterfaceID {
			t.Fatalf("applied uplink %s = %+v, %v", item.ID, created, err)
		}
		if _, err := os.Stat(backend.ethernetOwnedPath(item.ID)); err != nil {
			t.Fatalf("networkd policy %s missing after apply: %v", item.ID, err)
		}
	}
	if !executor.called(backend.Paths.Networkctl, "reconfigure", "enp3s0") || !executor.called(backend.Paths.Networkctl, "reconfigure", "enp4s0") {
		t.Fatal("topology apply did not reconfigure every newly-created Ethernet uplink")
	}

	if err := backend.Rollback(ctx, manifest, transactionDirectory); err != nil {
		t.Fatalf("Rollback(topology with Ethernet intent) error = %v", err)
	}
	for _, item := range manifest.Topology.EthernetUplinks {
		if _, err := (uplink.NewRepository(database, 2001, 0x2201)).Get(ctx, item.ID); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("rolled-back uplink %s still exists: %v", item.ID, err)
		}
		if _, err := os.Stat(backend.ethernetOwnedPath(item.ID)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("rolled-back networkd policy %s still exists: %v", item.ID, err)
		}
		var roles int
		if err := database.QueryRowContext(ctx, `SELECT COUNT(*) FROM interface_role_assignments WHERE uplink_id=?`, item.ID).Scan(&roles); err != nil || roles != 0 {
			t.Fatalf("rolled-back Ethernet roles for %s = %d, %v", item.ID, roles, err)
		}
	}
}

func TestUbuntuBackendTopologyRollbackRetainsBlockedFirewallAfterPartialFailure(t *testing.T) {
	ctx, database := networkApplyDatabase(t)
	backend, executor, _, transactionDirectory := ubuntuBackendFixture(t)
	gate := &topologyGateFake{}
	routing := &topologyRoutingFake{err: errors.New("routing unavailable")}
	configureTopologyBackendFixture(t, ctx, &backend, database, gate, routing, &topologyContextFake{}, &topologyIngressFake{})
	manifest := topologyTestManifest()
	if err := backend.Snapshot(ctx, manifest, transactionDirectory); err != nil {
		t.Fatal(err)
	}
	if err := backend.Apply(ctx, manifest, transactionDirectory); err == nil {
		t.Fatal("topology apply unexpectedly ignored routing failure")
	}
	loadsBeforeRollback := countNFTLoads(executor)
	if err := backend.Rollback(ctx, manifest, transactionDirectory); err == nil {
		t.Fatal("topology rollback unexpectedly reported success with failed routing")
	}
	if countNFTLoads(executor) != loadsBeforeRollback {
		t.Fatal("rollback reopened the snapshotted active firewall after an incomplete LKG restore")
	}
}

func TestUbuntuBackendRejectsTamperedTopologySnapshotMembers(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*topologySnapshot)
	}{
		{name: "unknown path kind", mutate: func(snapshot *topologySnapshot) { snapshot.Members[0].PathKind = "absolute" }},
		{name: "duplicate member", mutate: func(snapshot *topologySnapshot) { snapshot.Members = append(snapshot.Members, snapshot.Members[0]) }},
		{name: "missing path pair", mutate: func(snapshot *topologySnapshot) {
			for index, member := range snapshot.Members {
				if member.NetworkInterfaceID == "netif:lan" {
					snapshot.Members = append(snapshot.Members[:index], snapshot.Members[index+1:]...)
					return
				}
			}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx, database := networkApplyDatabase(t)
			backend, _, _, transactionDirectory := ubuntuBackendFixture(t)
			gate := &topologyGateFake{}
			configureTopologyBackendFixture(t, ctx, &backend, database, gate, &topologyRoutingFake{}, &topologyContextFake{}, &topologyIngressFake{})
			manifest := topologyTestManifest()
			if err := backend.Snapshot(ctx, manifest, transactionDirectory); err != nil {
				t.Fatal(err)
			}
			filename := filepath.Join(transactionDirectory, "snapshot", "topology-state.json")
			payload, err := os.ReadFile(filename)
			if err != nil {
				t.Fatal(err)
			}
			var snapshot topologySnapshot
			if err := json.Unmarshal(payload, &snapshot); err != nil {
				t.Fatal(err)
			}
			test.mutate(&snapshot)
			payload, err = json.Marshal(snapshot)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filename, payload, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := backend.Apply(ctx, manifest, transactionDirectory); err == nil {
				t.Fatal("tampered topology snapshot was accepted")
			}
			if gate.calls != 0 {
				t.Fatal("data path was changed before tampered snapshot rejection")
			}
		})
	}
}

func configureTopologyBackendFixture(t *testing.T, ctx context.Context, backend *UbuntuBackend, database *sql.DB, gate TopologyPathGate, routing TopologyRoutingSynchronizer, runtime TopologyRuntimeContext, ingress TopologyIngressController) {
	t.Helper()
	backend.Database = database
	backend.RoutingTableStart = 1101
	backend.FwmarkStart = 0x1101
	backend.TopologyGate = gate
	backend.TopologyRouting = routing
	backend.TopologyContext = runtime
	backend.TopologyIngress = ingress
	backend.Paths.EthernetNetworkDir = filepath.Join(filepath.Dir(backend.Paths.LANNetworkFile), "members")
	if err := os.MkdirAll(backend.Paths.EthernetNetworkDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(backend.Paths.EthernetNetworkDir, "06-gateway-vpn-lan-enp2s0.network"), []byte("# legacy installer member\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(ctx, `
INSERT INTO network_interfaces(
 id,stable_identity_kind,stable_identity_hash,current_ifname,carrier_state,created_at,updated_at
) VALUES
 ('netif:lan','PERMANENT_MAC','lan-hash','enp2s0','UP','now','now'),
 ('netif:hilink','USB_SERIAL','hilink-hash','enxhilink0','UP','now','now');
INSERT INTO uplinks(
 id,display_number,type,name,enabled,priority,network_interface_id,address_mode,
 ipv4_cidr,gateway,dns_json,routing_table_id,fwmark,state,created_at,updated_at
) VALUES(
 'modem-a',1,'HILINK','LTE',1,1,'netif:hilink','DHCP',
 '192.168.8.2/24','192.168.8.1','["192.168.8.1"]',1101,4353,'UPLINK_READY','now','now'
);
INSERT INTO interface_role_assignments(id,network_interface_id,role,uplink_id,created_at,updated_at) VALUES
 ('role:lan','netif:lan','LAN_MEMBER',NULL,'2026-08-30T12:00:00Z','2026-08-30T12:00:00Z'),
 ('role:management','netif:lan','MANAGEMENT',NULL,'2026-08-30T12:00:00Z','2026-08-30T12:00:00Z'),
 ('role:hilink','netif:hilink','HILINK_UPLINK','modem-a','now','now');
`); err != nil {
		t.Fatal(err)
	}
}

func topologyTestManifest() Manifest {
	created := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	return Manifest{
		SchemaVersion: TopologyManifestSchema, ID: "apply-topology", OperationKind: OperationTopologyProfile,
		OldURL: "https://192.168.200.1:8443", NewURL: "https://192.168.210.1:8443",
		NewDestinationIP: "192.168.210.1",
		Topology: &TopologyMutation{
			ExpectedDesiredGeneration: 1, Profile: TopologyEthernetHiLink,
			LANInterfaceIDs: []string{"netif:lan"}, ManagementInterfaceIDs: []string{"netif:lan"},
			LANInterfaceName: "gateway-vpn-lan", LANAddress: "192.168.210.1/24", DHCPDNSEnabled: true,
			IngressTopologyMode:       "ROUTED",
			AcknowledgedPrerequisites: []string{"ACCEPT_TEMPORARY_DISCONNECT", "CONFIGURE_KEENETIC_WAN_DHCP"},
		},
		CreatedAt: created.Format(time.RFC3339Nano), RollbackDeadline: created.Add(time.Minute).Format(time.RFC3339Nano),
	}
}

func countNFTLoads(executor *statefulBackendExecutor) int {
	count := 0
	for _, call := range executor.calls {
		if filepath.Base(call.Executable) == "nft" && len(call.Arguments) == 2 && call.Arguments[0] == "--file" && call.Arguments[1] == "-" {
			count++
		}
	}
	return count
}
