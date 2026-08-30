package managementfabric

import (
	"encoding/json"
	"strings"
	"testing"

	"gateway-vpn/internal/wgingress"
)

func TestAdminRelayRepositoryLifecycleIsTypedAndSecretFree(t *testing.T) {
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
	link := createTestLink(t, ctx, repository, "link:a", vps, "10.80.0.0/24", "10.80.0.2", "10.80.0.1")
	serverKeys, err := wgingress.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	contour, err := repository.ConfigureAdminContour(ctx, AdminContourRootInput{
		Enabled: true, InterfaceName: AdminInterfaceName, PrivateKeySecretRef: AdminPrivateKeySecretRef,
		PublicKey: serverKeys.Public, Subnet: "10.85.0.0/24", GatewayAddress: "10.85.0.1", ListenPort: AdminListenPort,
	})
	if err != nil || !contour.Enabled || contour.InterfaceName != AdminInterfaceName || contour.DesiredGeneration != 1 {
		t.Fatalf("ConfigureAdminContour() = %+v, %v", contour, err)
	}
	encoded, err := json.Marshal(contour)
	if err != nil || strings.Contains(string(encoded), "secret") || strings.Contains(string(encoded), "/var/lib/") {
		t.Fatalf("administrator contour JSON exposed a secret reference: %s / %v", encoded, err)
	}
	if _, err := repository.CreateVPS(ctx, CreateVPSInput{
		ID: "vps:overlap", Name: "Overlap", VerifiedFingerprint: strings.Repeat("b", 64), PublicKey: testPublicKey(t),
		AdminAddressPool: "10.85.0.0/25", ResourceAliasPool: "10.98.0.0/16",
	}); err == nil || !strings.Contains(err.Error(), "overlap") {
		t.Fatalf("administrator contour prefix was absent from collision inventory: %v", err)
	}

	adminKeys, err := wgingress.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	stamp := "2026-08-30T12:00:00Z"
	if _, err := database.ExecContext(ctx, `
INSERT INTO management_admins(id,name,identity_kind,enabled,state,created_at,updated_at)
	VALUES('admin:a','Администратор','ADMIN',1,'ACTIVE',?,?)`, stamp, stamp); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(ctx, `
INSERT INTO management_admin_vps_peers(
 id,admin_id,vps_id,public_key,assigned_address,state,desired_generation,applied_generation,created_at,updated_at
) VALUES('admin-peer:a','admin:a','vps:a',?,'10.81.0.10','CONFIGURED',1,0,?,?)`, adminKeys.Public, stamp, stamp); err != nil {
		t.Fatal(err)
	}
	relay, err := repository.CreateAdminRelay(ctx, AdminRelayInput{
		ID: "relay:a", LinkID: link.ID, Enabled: true, PublicEndpointHost: "relay.example.net",
		PublicBindAddress: "203.0.113.20", PublicUDPPort: 53000,
	})
	if err != nil || relay.DestinationPort != AdminListenPort || relay.RateLimitPerSecond != 100 || relay.BurstPackets != 200 {
		t.Fatalf("CreateAdminRelay() = %+v, %v", relay, err)
	}
	if _, err := repository.CreateAdminRelay(ctx, AdminRelayInput{
		ID: "relay:duplicate", LinkID: link.ID, Enabled: true, PublicEndpointHost: "relay.example.net",
		PublicBindAddress: "203.0.113.21", PublicUDPPort: 53001,
	}); err == nil {
		t.Fatal("a second relay on one management link was accepted")
	}
	if _, err := repository.CreateAdminTunnel(ctx, AdminTunnelInput{
		ID: "tunnel:wrong", AdminID: "admin:a", RelayID: relay.ID, PublicKey: testPublicKey(t), AssignedAddress: "10.85.0.10",
	}); err == nil {
		t.Fatal("an inner key different from the paired administrator identity was accepted")
	}
	tunnel, err := repository.CreateAdminTunnel(ctx, AdminTunnelInput{
		ID: "tunnel:a", AdminID: "admin:a", RelayID: relay.ID, PublicKey: adminKeys.Public, AssignedAddress: "10.85.0.10",
	})
	if err != nil || tunnel.State != "CONFIGURED" || tunnel.AssignedAddress != "10.85.0.10" {
		t.Fatalf("CreateAdminTunnel() = %+v, %v", tunnel, err)
	}
	var trustMode string
	if err := database.QueryRowContext(ctx, "SELECT trust_mode FROM management_admin_vps_peers WHERE id='admin-peer:a'").Scan(&trustMode); err != nil || trustMode != TrustEndToEndRelay {
		t.Fatalf("inner tunnel did not atomically select END_TO_END_RELAY: %q / %v", trustMode, err)
	}
	if err := repository.SetAdminTrustMode(ctx, "admin:a", "vps:a", TrustRoutedHub); err == nil {
		t.Fatal("ROUTED_HUB was selected while an active inner tunnel remained")
	}
	if _, err := repository.RevokeAdminTunnel(ctx, tunnel.ID); err != nil {
		t.Fatal(err)
	}
	if err := repository.SetAdminTrustMode(ctx, "admin:a", "vps:a", TrustRoutedHub); err != nil {
		t.Fatalf("ROUTED_HUB was not restored after inner revoke: %v", err)
	}
	relay.Enabled = false
	updated, err := repository.UpdateAdminRelay(ctx, relay.ID, AdminRelayInput{
		LinkID: relay.LinkID, Enabled: false, PublicEndpointHost: relay.PublicEndpointHost,
		PublicBindAddress: relay.PublicBindAddress, PublicUDPPort: relay.PublicUDPPort,
		RateLimitPerSecond: relay.RateLimitPerSecond, BurstPackets: relay.BurstPackets,
	})
	if err != nil || updated.Enabled || updated.State != "DISABLED" {
		t.Fatalf("disable relay = %+v, %v", updated, err)
	}
	if err := repository.DeleteAdminTunnel(ctx, tunnel.ID); err != nil {
		t.Fatal(err)
	}
	if err := repository.DeleteAdminRelay(ctx, relay.ID); err != nil {
		t.Fatal(err)
	}
	if relays, err := repository.ListAdminRelays(ctx); err != nil || len(relays) != 0 {
		t.Fatalf("relays after delete = %+v, %v", relays, err)
	}
}

func TestAdminContourIdentityRotationMarksClientsForUpdate(t *testing.T) {
	ctx, _, repository := managementFixture(t)
	first, _ := wgingress.GenerateKeyPair()
	if _, err := repository.ConfigureAdminContour(ctx, AdminContourRootInput{
		Enabled: true, InterfaceName: AdminInterfaceName, PrivateKeySecretRef: AdminPrivateKeySecretRef,
		PublicKey: first.Public, Subnet: "10.85.0.0/24", GatewayAddress: "10.85.0.1", ListenPort: AdminListenPort,
	}); err != nil {
		t.Fatal(err)
	}
	second, _ := wgingress.GenerateKeyPair()
	rotated, err := repository.RotateAdminContourIdentity(ctx, second.Public)
	if err != nil || rotated.PublicKey != second.Public || rotated.LastErrorCode != "IDENTITY_ROTATED_CLIENT_UPDATE_REQUIRED" {
		t.Fatalf("RotateAdminContourIdentity() = %+v, %v", rotated, err)
	}
	if _, err := repository.ConfigureAdminContour(ctx, AdminContourRootInput{
		Enabled: true, InterfaceName: AdminInterfaceName, PrivateKeySecretRef: AdminPrivateKeySecretRef,
		PublicKey: first.Public, Subnet: "10.85.0.0/24", GatewayAddress: "10.85.0.1", ListenPort: AdminListenPort,
	}); err == nil {
		t.Fatal("normal contour update replaced a rotated root identity")
	}
}
