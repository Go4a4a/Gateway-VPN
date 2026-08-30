package managementfabric

import (
	"context"
	"database/sql"
	"slices"
	"strings"
	"testing"

	"gateway-vpn/internal/modem"
)

func TestBuildGatewayHostPlanSelectsReadyUplinkAndTypedResources(t *testing.T) {
	ctx, database, repository := managementFixture(t)
	if _, err := repository.EnsureLocalSite(ctx, "site:home", "Дом"); err != nil {
		t.Fatal(err)
	}
	vps, err := repository.CreateVPS(ctx, CreateVPSInput{
		ID: "vps:a", Name: "VPS A", VerifiedFingerprint: strings.Repeat("a", 64), PublicKey: testPublicKey(t),
		AdminAddressPool: "10.81.0.0/24", ResourceAliasPool: "10.96.0.0/16",
	})
	if err != nil {
		t.Fatal(err)
	}
	modems := modem.NewRepository(database, 1101, 0x1101)
	if _, err := modems.Adopt(ctx, modem.AdoptInput{ID: "modem:a", Name: "Operator A", IdentityKind: "hilink_serial_hash", IdentityHash: strings.Repeat("b", 64)}); err != nil {
		t.Fatal(err)
	}
	if _, err := modems.ApplyLease(ctx, "modem:a", modem.LeaseInput{
		InterfaceName: "enx0001", ManagementCIDR: "192.168.8.0/24", Gateway: "192.168.8.1",
		DNS: []string{"1.1.1.1"}, MTU: 1500, State: modem.StateReady,
	}); err != nil {
		t.Fatal(err)
	}
	link, err := repository.CreateLink(ctx, CreateLinkInput{
		ID: "link:a", SiteID: "site:home", VPSID: vps.ID, Enabled: true,
		ManagementSubnet: "10.82.0.0/24", LocalAddress: "10.82.0.2", RemoteAddress: "10.82.0.1",
		LocalPrivateKeySecretRef: "/var/lib/gateway-vpn/secrets/management/link:a.key",
		LocalPublicKey:           testPublicKey(t), RemotePublicKey: vps.PublicKey,
		UplinkPolicy: UplinkAuto, PersistentKeepalive: 25,
		Endpoints: []EndpointSpec{{Host: "203.0.113.10", Port: 51821}},
	})
	if err != nil {
		t.Fatal(err)
	}
	insertGatewayHostPlanObjects(t, ctx, database, link)

	plan, err := repository.BuildGatewayHostPlan(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Generation <= 0 || len(plan.Links) != 1 || len(plan.Aliases) != 1 || len(plan.ACL) != 1 {
		t.Fatalf("Gateway host plan = %+v", plan)
	}
	hostLink := plan.Links[0]
	if hostLink.LinkID != link.ID || hostLink.InterfaceName != "gvm1" || hostLink.EndpointAddress != "203.0.113.10" || hostLink.EndpointPort != 51821 ||
		hostLink.UplinkID != "modem:a" || hostLink.UplinkInterface != "enx0001" || hostLink.UplinkGateway != "192.168.8.1" ||
		hostLink.UplinkTable != 1101 || hostLink.UplinkMark != 0x1101 || len(hostLink.Routes) != 3 {
		t.Fatalf("Gateway host link = %+v", hostLink)
	}
	for _, expected := range []string{"10.81.0.10/32", "10.82.0.1/32"} {
		if !slices.Contains(hostLink.AllowedIPs, expected) {
			t.Fatalf("Gateway host link AllowedIPs %v miss %s", hostLink.AllowedIPs, expected)
		}
	}
	if plan.ACL[0].Source != "10.81.0.10/32" || plan.ACL[0].PublishedAlias != "10.96.1.10/32" || plan.ACL[0].LocalDestination != "192.168.50.10" || plan.ACL[0].ResourceKind != ResourceLocalHost || plan.ACL[0].AccessProfile != ProfileDedicatedLAN {
		t.Fatalf("Gateway host ACL = %+v", plan.ACL[0])
	}
}

func TestBuildGatewayHostPlanRequiresResolvedEndpointAndPinnedReadyUplink(t *testing.T) {
	ctx, _, repository := managementFixture(t)
	if _, err := repository.EnsureLocalSite(ctx, "site:home", "Дом"); err != nil {
		t.Fatal(err)
	}
	vps, err := repository.CreateVPS(ctx, CreateVPSInput{
		ID: "vps:a", Name: "VPS A", VerifiedFingerprint: strings.Repeat("a", 64), PublicKey: testPublicKey(t),
		AdminAddressPool: "10.81.0.0/24", ResourceAliasPool: "10.96.0.0/16",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repository.CreateLink(ctx, CreateLinkInput{
		ID: "link:a", SiteID: "site:home", VPSID: vps.ID, Enabled: true,
		ManagementSubnet: "10.82.0.0/24", LocalAddress: "10.82.0.2", RemoteAddress: "10.82.0.1",
		LocalPrivateKeySecretRef: "/var/lib/gateway-vpn/secrets/management/link:a.key",
		LocalPublicKey:           testPublicKey(t), RemotePublicKey: vps.PublicKey,
		UplinkPolicy: UplinkPinnedOnly, PinnedUplinkID: "missing", PersistentKeepalive: 25,
		Endpoints: []EndpointSpec{{Host: "vps-a.example.net", Port: 51821}},
	}); err == nil {
		t.Fatal("link accepted a missing pinned uplink")
	}
}

func insertGatewayHostPlanObjects(t *testing.T, ctx context.Context, database *sql.DB, link Link) {
	t.Helper()
	stamp := "2026-08-30T12:00:00Z"
	statements := []struct {
		query string
		args  []any
	}{
		{`INSERT INTO management_admins(id,name,identity_kind,enabled,state,created_at,updated_at)
VALUES('admin:a','Administrator','ADMIN',1,'ACTIVE',?,?)`, []any{stamp, stamp}},
		{`INSERT INTO management_admin_vps_peers(
id,admin_id,vps_id,public_key,assigned_address,state,desired_generation,applied_generation,created_at,updated_at
) VALUES('admin-peer:a','admin:a',?,?,'10.81.0.10','CONFIGURED',1,0,?,?)`, []any{link.VPSID, testPublicKey(t), stamp, stamp}},
		{`INSERT INTO management_resources(
id,site_id,name,resource_kind,access_profile,local_destination,enabled,advanced_scope_acknowledged,
desired_route_generation,applied_route_generation,health_state,created_at,updated_at
) VALUES('resource:a','site:home','Local service','LOCAL_HOST','VIA_DEDICATED_LAN','192.168.50.10',1,0,1,0,'UNKNOWN',?,?)`, []any{stamp, stamp}},
		{`INSERT INTO management_resource_publications(
id,resource_id,link_id,published_alias,desired_route_generation,applied_route_generation,
desired_acl_generation,applied_acl_generation,state,created_at,updated_at
) VALUES('publication:a','resource:a',?,'10.96.1.10/32',1,0,1,0,'PENDING',?,?)`, []any{link.ID, stamp, stamp}},
		{`INSERT INTO management_resource_acl(
id,admin_id,resource_id,protocol,port_start,port_end,enabled,generation,created_at,updated_at
) VALUES('acl:a','admin:a','resource:a','TCP',443,443,1,1,?,?)`, []any{stamp, stamp}},
	}
	for _, statement := range statements {
		if _, err := database.ExecContext(ctx, statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
}
