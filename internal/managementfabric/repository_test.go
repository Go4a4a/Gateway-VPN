package managementfabric

import (
	"context"
	"database/sql"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	databasepkg "gateway-vpn/internal/db"
	"gateway-vpn/internal/modem"
	"gateway-vpn/internal/wgingress"
)

func TestRepositoryCreatesTwoVPSAndIndependentMonotonicLinks(t *testing.T) {
	ctx, database, repository := managementFixture(t)
	site, err := repository.EnsureLocalSite(ctx, "site:home", "Дом")
	if err != nil || !site.Local || site.IdentityState != "ACTIVE" {
		t.Fatalf("EnsureLocalSite() = %+v, %v", site, err)
	}
	if _, err := repository.EnsureLocalSite(ctx, "site:other", "Clone"); err == nil {
		t.Fatal("a second immutable local site was accepted")
	}

	vpsKey1 := testPublicKey(t)
	vpsKey2 := testPublicKey(t)
	vps1, err := repository.CreateVPS(ctx, CreateVPSInput{
		ID: "vps:a", Name: "VPS Москва", VerifiedFingerprint: strings.Repeat("a", 64),
		PublicKey: vpsKey1, AdminAddressPool: "10.81.0.0/24", ResourceAliasPool: "10.96.0.0/16",
	})
	if err != nil {
		t.Fatal(err)
	}
	vps2, err := repository.CreateVPS(ctx, CreateVPSInput{
		ID: "vps:b", Name: "VPS резерв", VerifiedFingerprint: strings.Repeat("b", 64),
		PublicKey: vpsKey2, AdminAddressPool: "10.83.0.0/24", ResourceAliasPool: "10.97.0.0/16",
	})
	if err != nil {
		t.Fatal(err)
	}
	if vps1.DisplayNumber != 1 || vps1.Priority != 10 || vps2.DisplayNumber != 2 || vps2.Priority != 20 {
		t.Fatalf("VPS allocation = %+v / %+v", vps1, vps2)
	}

	link1 := createTestLink(t, ctx, repository, "link:a", vps1, "10.80.0.0/24", "10.80.0.2", "10.80.0.1")
	link2 := createTestLink(t, ctx, repository, "link:b", vps2, "10.82.0.0/24", "10.82.0.2", "10.82.0.1")
	if link1.Slot != 1 || link1.InterfaceName != "gvm1" || link2.Slot != 2 || link2.InterfaceName != "gvm2" {
		t.Fatalf("link allocation = %+v / %+v", link1, link2)
	}
	if len(link1.Endpoints) != 2 || link1.Endpoints[0].Priority != 1 || link1.Endpoints[1].Host != "203.0.113.10" {
		t.Fatalf("link endpoints = %+v", link1.Endpoints)
	}
	items, err := repository.ListLinks(ctx)
	if err != nil || len(items) != 2 || items[0].ID != link1.ID || items[1].ID != link2.ID {
		t.Fatalf("ListLinks() = %+v, %v", items, err)
	}

	encoded, err := json.Marshal(link1)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "local_private_key_secret_ref") || strings.Contains(string(encoded), "/var/lib/gateway-vpn/secrets/") {
		t.Fatalf("link JSON exposed private secret reference: %s", encoded)
	}
	var storedRef string
	if err := database.QueryRowContext(ctx, "SELECT local_private_key_secret_ref FROM management_links WHERE id=?", link1.ID).Scan(&storedRef); err != nil {
		t.Fatal(err)
	}
	if storedRef != "/var/lib/gateway-vpn/secrets/management/link:a.key" || wgingress.ValidKey(storedRef) {
		t.Fatalf("stored private material is not a fixed reference: %q", storedRef)
	}

	if _, err := database.ExecContext(ctx, "DELETE FROM management_links WHERE id=?", link1.ID); err != nil {
		t.Fatal(err)
	}
	link3 := createTestLink(t, ctx, repository, "link:c", vps1, "10.84.0.0/24", "10.84.0.2", "10.84.0.1")
	if link3.Slot != 3 || link3.InterfaceName != "gvm3" {
		t.Fatalf("deleted slot was reused: %+v", link3)
	}
	var nextVPS, nextLink int64
	if err := database.QueryRowContext(ctx, "SELECT next_vps_number,next_link_slot FROM management_fabric_counters WHERE singleton_id=1").Scan(&nextVPS, &nextLink); err != nil {
		t.Fatal(err)
	}
	if nextVPS != 3 || nextLink != 4 {
		t.Fatalf("management counters = VPS %d link %d", nextVPS, nextLink)
	}
}

func TestRepositoryRejectsIdentityAndNetworkCollisionsAtomically(t *testing.T) {
	ctx, database, repository := managementFixture(t)
	if _, err := repository.EnsureLocalSite(ctx, "site:home", "Дом"); err != nil {
		t.Fatal(err)
	}
	vpsKey := testPublicKey(t)
	vps, err := repository.CreateVPS(ctx, CreateVPSInput{
		ID: "vps:a", Name: "VPS A", VerifiedFingerprint: strings.Repeat("a", 64), PublicKey: vpsKey,
		AdminAddressPool: "10.81.0.0/24", ResourceAliasPool: "10.96.0.0/16",
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, input := range []CreateVPSInput{
		{ID: "vps:duplicate-fingerprint", Name: "Bad", VerifiedFingerprint: strings.Repeat("a", 64), PublicKey: testPublicKey(t), AdminAddressPool: "10.85.0.0/24", ResourceAliasPool: "10.98.0.0/16"},
		{ID: "vps:duplicate-key", Name: "Bad", VerifiedFingerprint: strings.Repeat("c", 64), PublicKey: vpsKey, AdminAddressPool: "10.86.0.0/24", ResourceAliasPool: "10.99.0.0/16"},
		{ID: "vps:reserved", Name: "Bad", VerifiedFingerprint: strings.Repeat("d", 64), PublicKey: testPublicKey(t), AdminAddressPool: "192.168.200.0/24", ResourceAliasPool: "10.100.0.0/16"},
	} {
		if _, err := repository.CreateVPS(ctx, input); err == nil {
			t.Fatalf("colliding VPS was accepted: %+v", input)
		}
	}
	first := createTestLink(t, ctx, repository, "link:a", vps, "10.80.0.0/24", "10.80.0.2", "10.80.0.1")
	badKey := testPublicKey(t)
	_, err = repository.CreateLink(ctx, CreateLinkInput{
		ID: "link:overlap", SiteID: "site:home", VPSID: vps.ID, Enabled: true,
		ManagementSubnet: "10.80.0.0/25", LocalAddress: "10.80.0.3", RemoteAddress: "10.80.0.4",
		LocalPrivateKeySecretRef: "/var/lib/gateway-vpn/secrets/management/link:overlap.key",
		LocalPublicKey:           badKey, RemotePublicKey: vps.PublicKey, UplinkPolicy: UplinkAuto,
		PersistentKeepalive: 25, Endpoints: []EndpointSpec{{Host: "vps-a.example.net", Port: 51821}},
	})
	if err == nil {
		t.Fatal("overlapping management subnet was accepted")
	}
	var nextSlot, links int64
	if err := database.QueryRowContext(ctx, "SELECT next_link_slot FROM management_fabric_counters WHERE singleton_id=1").Scan(&nextSlot); err != nil {
		t.Fatal(err)
	}
	if err := database.QueryRowContext(ctx, "SELECT COUNT(*) FROM management_links").Scan(&links); err != nil {
		t.Fatal(err)
	}
	if first.Slot != 1 || nextSlot != 2 || links != 1 {
		t.Fatalf("failed link create was not atomic: first=%+v next=%d count=%d", first, nextSlot, links)
	}
	if _, err := repository.CreateLink(ctx, CreateLinkInput{
		ID: "link:raw", SiteID: "site:home", VPSID: vps.ID, Enabled: true,
		ManagementSubnet: "10.88.0.0/24", LocalAddress: "10.88.0.2", RemoteAddress: "10.88.0.1",
		LocalPrivateKeySecretRef: testPublicKey(t), LocalPublicKey: testPublicKey(t), RemotePublicKey: vps.PublicKey,
		UplinkPolicy: UplinkAuto, PersistentKeepalive: 25, Endpoints: []EndpointSpec{{Host: "vps-a.example.net", Port: 51821}},
	}); err == nil {
		t.Fatal("raw key material was accepted as a SQLite secret reference")
	}
}

func TestPrefixCollisionInventoryAcceptsHostAddressCIDRAndStillRejectsOverlap(t *testing.T) {
	ctx, database, repository := managementFixture(t)
	modems := modem.NewRepository(database, 1101, 0x1101)
	if _, err := modems.Adopt(ctx, modem.AdoptInput{ID: "modem:a", Name: "A", IdentityKind: "hilink_serial_hash", IdentityHash: strings.Repeat("e", 64)}); err != nil {
		t.Fatal(err)
	}
	if _, err := modems.ApplyLease(ctx, "modem:a", modem.LeaseInput{InterfaceName: "enx-a", ManagementCIDR: "172.20.1.0/24", Gateway: "172.20.1.1", DNS: []string{"1.1.1.1"}, MTU: 1500, State: modem.StateReady}); err != nil {
		t.Fatal(err)
	}
	// Ethernet runtime stores the host address together with its prefix. The
	// Management Fabric collision inventory must compare its masked network.
	if _, err := database.ExecContext(ctx, "UPDATE uplinks SET ipv4_cidr='172.20.1.2/24' WHERE id='modem:a'"); err != nil {
		t.Fatal(err)
	}
	if _, err := repository.CreateVPS(ctx, CreateVPSInput{
		ID: "vps:overlap", Name: "Bad", VerifiedFingerprint: strings.Repeat("a", 64), PublicKey: testPublicKey(t),
		AdminAddressPool: "172.20.1.0/24", ResourceAliasPool: "10.96.0.0/16",
	}); err == nil || !strings.Contains(err.Error(), "overlap") {
		t.Fatalf("uplink host-address CIDR overlap = %v", err)
	}
	if _, err := repository.CreateVPS(ctx, CreateVPSInput{
		ID: "vps:safe", Name: "Safe", VerifiedFingerprint: strings.Repeat("b", 64), PublicKey: testPublicKey(t),
		AdminAddressPool: "10.81.0.0/24", ResourceAliasPool: "10.96.0.0/16",
	}); err != nil {
		t.Fatalf("non-overlapping VPS rejected after host-address CIDR inventory: %v", err)
	}
}

func TestValidateFabricRequiresTypedBoundedSameSiteACL(t *testing.T) {
	localKey := testPublicKey(t)
	remoteKey := testPublicKey(t)
	valid := FabricSpec{
		ReservedPrefixes: []ReservedPrefix{{Owner: "gateway-lan", CIDR: "192.168.200.0/24"}},
		Links: []LinkSpec{{
			ID: "link:a", SiteID: "site:a", VPSID: "vps:a", Slot: 1, InterfaceName: "gvm1",
			ManagementSubnet: "10.80.0.0/24", LocalAddress: "10.80.0.2", RemoteAddress: "10.80.0.1",
			LocalPrivateKeySecretRef: "/var/lib/gateway-vpn/secrets/management/link:a.key",
			LocalPublicKey:           localKey, RemotePublicKey: remoteKey, UplinkPolicy: UplinkAuto,
			PersistentKeepalive: 25, Endpoints: []EndpointSpec{{Host: "vps-a.example.net", Port: 51821}},
		}},
		Admins: []AdminSpec{{ID: "admin:a", VPSID: "vps:a", AssignedAddress: "10.81.0.10", TrustMode: TrustRoutedHub}},
		Resources: []ResourceSpec{{
			ID: "resource:host", SiteID: "site:a", Kind: ResourceLocalHost,
			AccessProfile: ProfileDedicatedLAN, LocalDestination: "192.168.50.10",
		}},
		Publications: []PublicationSpec{{
			ID: "publication:a", ResourceID: "resource:host", LinkID: "link:a",
			LocalDestination: "192.168.50.10", PublishedAlias: "10.96.1.10/32",
		}},
		ACL: []ACLSpec{{ID: "acl:a", AdminID: "admin:a", ResourceID: "resource:host", Protocol: ProtocolTCP, PortStart: 443, PortEnd: 443}},
	}
	if err := ValidateFabric(valid); err != nil {
		t.Fatalf("valid fabric rejected: %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*FabricSpec)
	}{
		{"wildcard resource", func(spec *FabricSpec) {
			spec.Resources[0].Kind = ResourceLocalSubnet
			spec.Resources[0].LocalDestination = "0.0.0.0/0"
			spec.Resources[0].AdvancedScopeAcknowledged = true
		}},
		{"unacknowledged subnet", func(spec *FabricSpec) {
			spec.Resources[0].Kind = ResourceLocalSubnet
			spec.Resources[0].LocalDestination = "192.168.50.0/24"
			spec.Publications[0].LocalDestination = "192.168.50.0/24"
			spec.Publications[0].PublishedAlias = "10.96.1.0/24"
		}},
		{"invalid ACL protocol", func(spec *FabricSpec) { spec.ACL[0].Protocol = "ANY" }},
		{"wildcard TCP ports", func(spec *FabricSpec) { spec.ACL[0].PortStart = 0; spec.ACL[0].PortEnd = 65535 }},
		{"alias overlaps management", func(spec *FabricSpec) { spec.Publications[0].PublishedAlias = "10.80.0.10/32" }},
		{"wrong VPS ACL", func(spec *FabricSpec) { spec.Admins[0].VPSID = "vps:b" }},
		{"duplicate interface", func(spec *FabricSpec) {
			duplicate := spec.Links[0]
			duplicate.ID = "link:b"
			duplicate.VPSID = "vps:b"
			duplicate.ManagementSubnet = "10.82.0.0/24"
			duplicate.LocalAddress = "10.82.0.2"
			duplicate.RemoteAddress = "10.82.0.1"
			duplicate.LocalPublicKey = testPublicKey(t)
			spec.Links = append(spec.Links, duplicate)
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			copySpec := cloneFabric(t, valid)
			test.mutate(&copySpec)
			if err := ValidateFabric(copySpec); err == nil {
				t.Fatal("invalid management fabric was accepted")
			}
		})
	}
}

func managementFixture(t *testing.T) (context.Context, *sql.DB, *Repository) {
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
	repository := NewRepository(database, []ReservedPrefix{{Owner: "gateway-lan", CIDR: "192.168.200.0/24"}})
	repository.Now = func() time.Time { return time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC) }
	return ctx, database, repository
}

func createTestLink(t *testing.T, ctx context.Context, repository *Repository, id string, vps VPSNode, subnet, local, remote string) Link {
	t.Helper()
	item, err := repository.CreateLink(ctx, CreateLinkInput{
		ID: id, SiteID: "site:home", VPSID: vps.ID, Enabled: true,
		ManagementSubnet: subnet, LocalAddress: local, RemoteAddress: remote,
		LocalPrivateKeySecretRef: "/var/lib/gateway-vpn/secrets/management/" + id + ".key",
		LocalPublicKey:           testPublicKey(t), RemotePublicKey: vps.PublicKey,
		UplinkPolicy: UplinkAuto, PersistentKeepalive: 25,
		Endpoints: []EndpointSpec{{Host: "vps-a.example.net", Port: 51821}, {Host: "203.0.113.10", Port: 51822}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return item
}

func testPublicKey(t *testing.T) string {
	t.Helper()
	pair, err := wgingress.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	return pair.Public
}

func cloneFabric(t *testing.T, input FabricSpec) FabricSpec {
	t.Helper()
	encoded, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	var result FabricSpec
	if err := json.Unmarshal(encoded, &result); err != nil {
		t.Fatal(err)
	}
	return result
}
