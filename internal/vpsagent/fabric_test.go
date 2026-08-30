package vpsagent

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gateway-vpn/internal/wgingress"
)

func TestHubPairingIsBoundedDigestOnlyAndAtomic(t *testing.T) {
	ctx := context.Background()
	repository := testHubRepository(t)
	bundle, err := repository.CreatePairing(ctx, PairingCreateInput{
		GatewayName: "Дом", Endpoint: "VPS.Example:51820", Subnet: "10.82.0.0/30", ExpiresIn: 15 * time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	if bundle.Token == "" || bundle.Endpoint != "vps.example:51820" || bundle.VPSAddress != "10.82.0.1" || bundle.GatewayAddress != "10.82.0.2" {
		t.Fatalf("pairing bundle = %+v", bundle)
	}
	var digest, payload string
	if err := repository.Database.QueryRowContext(ctx, "SELECT token_sha256,payload_json FROM pairing_invitations WHERE id=?", bundle.InvitationID).Scan(&digest, &payload); err != nil {
		t.Fatal(err)
	}
	expected := sha256.Sum256([]byte(bundle.Token))
	if digest != hex.EncodeToString(expected[:]) || strings.Contains(payload, bundle.Token) {
		t.Fatal("pairing token was not stored digest-only")
	}
	listed, err := repository.ListPairings(ctx)
	if err != nil || len(listed) != 1 || listed[0].Token != "" {
		t.Fatalf("ListPairings() = %+v, %v", listed, err)
	}
	pair, err := wgingress.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	completion := PairingCompletion{
		InvitationID: bundle.InvitationID, Token: "wrong-token", SiteID: "site:home",
		DisplayName: "Дом", PublicKey: pair.Public, WebUIURL: "https://10.82.0.2/",
	}
	if _, err := repository.CompletePairing(ctx, completion); !errors.Is(err, ErrPairingRejected) {
		t.Fatalf("wrong-token completion error = %v", err)
	}
	if err := repository.Database.QueryRowContext(ctx, "SELECT attempt_count FROM pairing_invitations WHERE id=?", bundle.InvitationID).Scan(&listed[0].AttemptCount); err != nil || listed[0].AttemptCount != 1 {
		t.Fatalf("attempt count = %d, %v", listed[0].AttemptCount, err)
	}
	completion.Token = bundle.Token
	peer, err := repository.CompletePairing(ctx, completion)
	if err != nil {
		t.Fatal(err)
	}
	if peer.SiteID != "site:home" || peer.State != "PAIRING" || peer.AssignedAddress != "10.82.0.2" || peer.RemoteAddress != "10.82.0.1" || peer.StatusReason != "AWAITING_HOST_APPLY" {
		t.Fatalf("Gateway peer = %+v", peer)
	}
	if _, err := repository.CompletePairing(ctx, completion); !errors.Is(err, ErrPairingRejected) {
		t.Fatalf("pairing replay error = %v", err)
	}
	var owner, state string
	if err := repository.Database.QueryRowContext(ctx, "SELECT owner_id,state FROM prefix_allocations WHERE prefix='10.82.0.0/30'").Scan(&owner, &state); err != nil || owner != peer.ID || state != "ALLOCATED" {
		t.Fatalf("prefix owner/state = %q/%q, %v", owner, state, err)
	}
	if _, err := repository.CreatePairing(ctx, PairingCreateInput{GatewayName: "Conflict", Endpoint: "vps.example:51820", Subnet: "10.82.0.0/30"}); !errors.Is(err, ErrHubConflict) {
		t.Fatalf("overlapping invitation error = %v", err)
	}
}

func TestHubAdministratorsResourcesACLAndRevocation(t *testing.T) {
	ctx := context.Background()
	repository := testHubRepository(t)
	gateway := pairTestGateway(t, repository, "10.82.0.0/30")
	adminKey, err := wgingress.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	admin, err := repository.CreateAdmin(ctx, AdminCreateInput{Name: "Ноутбук", PublicKey: adminKey.Public, AssignedAddress: "10.81.0.10", KeyMode: "EXTERNAL"})
	if err != nil {
		t.Fatal(err)
	}
	if admin.State != "CONFIGURED" || admin.KeyMode != "EXTERNAL" || admin.StatusReason != "AWAITING_HOST_APPLY" {
		t.Fatalf("administrator = %+v", admin)
	}
	identity, err := ReadIdentity(ctx, repository.Database)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repository.CreateAdmin(ctx, AdminCreateInput{Name: "Duplicate VPS key", PublicKey: identity.PublicKey, AssignedAddress: "10.81.0.11", KeyMode: "EXTERNAL"}); !errors.Is(err, ErrHubConflict) {
		t.Fatalf("VPS identity key reuse error = %v", err)
	}
	otherKey, _ := wgingress.GenerateKeyPair()
	if _, err := repository.CreateAdmin(ctx, AdminCreateInput{Name: "Overlap", PublicKey: otherKey.Public, AssignedAddress: "10.82.0.2", KeyMode: "EXTERNAL"}); !errors.Is(err, ErrHubConflict) {
		t.Fatalf("overlapping administrator error = %v", err)
	}
	if _, err := repository.CreateResource(ctx, ResourceInput{
		GatewayPeerID: gateway.ID, ResourceID: "lan:all", DisplayName: "Вся сеть", ResourceKind: "LOCAL_SUBNET",
		LocalDestination: "192.168.50.0/24", PublishedAlias: "10.96.1.0/24", AccessProfile: "VIA_DEDICATED_LAN", Enabled: true,
	}); err == nil {
		t.Fatal("LOCAL_SUBNET without acknowledgement was accepted")
	}
	resource, err := repository.CreateResource(ctx, ResourceInput{
		GatewayPeerID: gateway.ID, ResourceID: "gateway:web", DisplayName: "Gateway WebUI", ResourceKind: "GATEWAY_SERVICE",
		LocalDestination: "192.168.200.2", PublishedAlias: "10.96.0.2", AccessProfile: "GATEWAY_ONLY", Enabled: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if resource.State != "PENDING" || resource.DesiredGeneration != 1 || resource.Health != "UNKNOWN" {
		t.Fatalf("resource = %+v", resource)
	}
	grant, err := repository.CreateACL(ctx, ACLInput{AdminPeerID: admin.ID, PublicationID: resource.ID, Protocol: "TCP", PortStart: 443, PortEnd: 443})
	if err != nil {
		t.Fatal(err)
	}
	if grant.Generation <= 1 {
		t.Fatalf("ACL generation = %d", grant.Generation)
	}
	if _, err := repository.CreateACL(ctx, ACLInput{AdminPeerID: admin.ID, PublicationID: resource.ID, Protocol: "TCP", PortStart: 0, PortEnd: 65535}); err == nil {
		t.Fatal("wildcard TCP ACL was accepted")
	}
	overview, err := repository.Overview(ctx)
	if err != nil || overview.Gateways["PAIRING"] != 1 || overview.Administrators["CONFIGURED"] != 1 || overview.Resources["PENDING"] != 1 || overview.ACLGrants != 1 || overview.HostApplyAvailable {
		t.Fatalf("Overview() = %+v, %v", overview, err)
	}
	health := repository.ControllerHealth(ctx)
	if health.State != "PENDING" || len(health.Components) != 6 {
		t.Fatalf("ControllerHealth() = %+v", health)
	}
	if err := repository.RevokeAdmin(ctx, admin.ID); err != nil {
		t.Fatal(err)
	}
	if grants, err := repository.ListACL(ctx); err != nil || len(grants) != 0 {
		t.Fatalf("ACL after admin revoke = %+v, %v", grants, err)
	}
	if err := repository.RevokeGateway(ctx, gateway.ID); err != nil {
		t.Fatal(err)
	}
	revoked, err := repository.GetGateway(ctx, gateway.ID)
	if err != nil || revoked.State != "REVOKED" {
		t.Fatalf("revoked Gateway = %+v, %v", revoked, err)
	}
	disabled, err := repository.GetResource(ctx, resource.ID)
	if err != nil || disabled.State != "DISABLED" || disabled.Enabled {
		t.Fatalf("resource after Gateway revoke = %+v, %v", disabled, err)
	}
}

func TestHubResourceUpdateDeleteAndPairingAttemptBudget(t *testing.T) {
	ctx := context.Background()
	repository := testHubRepository(t)
	gateway := pairTestGateway(t, repository, "10.82.0.0/30")
	resource, err := repository.CreateResource(ctx, ResourceInput{
		GatewayPeerID: gateway.ID, ResourceID: "host:nas", DisplayName: "NAS", ResourceKind: "LOCAL_HOST",
		LocalDestination: "192.168.50.10", PublishedAlias: "10.96.0.10", AccessProfile: "VIA_KEENETIC_WAN_ROUTED", Enabled: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	updated, err := repository.UpdateResource(ctx, resource.ID, ResourceInput{
		GatewayPeerID: gateway.ID, ResourceID: "host:nas", DisplayName: "NAS HTTPS", ResourceKind: "CUSTOM_SERVICE",
		LocalDestination: "192.168.50.10", PublishedAlias: "10.96.0.11", AccessProfile: "VIA_KEENETIC_WAN_ROUTED", Enabled: false,
	})
	if err != nil || updated.DisplayName != "NAS HTTPS" || updated.PublishedAlias != "10.96.0.11" || updated.State != "DISABLED" {
		t.Fatalf("UpdateResource() = %+v, %v", updated, err)
	}
	if err := repository.DeleteResource(ctx, resource.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := repository.GetResource(ctx, resource.ID); !errors.Is(err, ErrHubNotFound) {
		t.Fatalf("deleted resource error = %v", err)
	}

	bundle, err := repository.CreatePairing(ctx, PairingCreateInput{GatewayName: "Budget", Endpoint: "vps.example:51820", Subnet: "10.84.0.0/30"})
	if err != nil {
		t.Fatal(err)
	}
	pair, _ := wgingress.GenerateKeyPair()
	completion := PairingCompletion{InvitationID: bundle.InvitationID, Token: "wrong", SiteID: "site:budget", DisplayName: "Budget", PublicKey: pair.Public}
	for attempt := 0; attempt < 8; attempt++ {
		if _, err := repository.CompletePairing(ctx, completion); !errors.Is(err, ErrPairingRejected) {
			t.Fatalf("attempt %d error = %v", attempt, err)
		}
	}
	var state string
	var attempts int
	if err := repository.Database.QueryRowContext(ctx, "SELECT state,attempt_count FROM pairing_invitations WHERE id=?", bundle.InvitationID).Scan(&state, &attempts); err != nil || state != "REJECTED" || attempts != 8 {
		t.Fatalf("attempt budget state/count = %s/%d, %v", state, attempts, err)
	}
	completion.Token = bundle.Token
	if _, err := repository.CompletePairing(ctx, completion); !errors.Is(err, ErrPairingRejected) {
		t.Fatalf("budget-exhausted invitation accepted: %v", err)
	}
}

func TestVPSAgentMigratesExactV1PrefixToV2(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "legacy.db")
	database, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if _, err := database.ExecContext(ctx, `CREATE TABLE schema_migrations(version INTEGER PRIMARY KEY,name TEXT NOT NULL,checksum_sha256 TEXT NOT NULL,applied_at TEXT NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(ctx, schemaV1); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(ctx, "INSERT INTO schema_migrations(version,name,checksum_sha256,applied_at) VALUES(1,?,?,?)", migrations[0].name, schemaChecksum(schemaV1), "2026-08-30T00:00:00Z"); err != nil {
		t.Fatal(err)
	}
	if err := Migrate(ctx, database); err != nil {
		t.Fatal(err)
	}
	if version, err := Schema(ctx, database); err != nil || version != 2 {
		t.Fatalf("migrated schema = %d, %v", version, err)
	}
	var count int
	if err := database.QueryRowContext(ctx, "SELECT COUNT(*) FROM pragma_table_info('pairing_invitations') WHERE name='payload_json'").Scan(&count); err != nil || count != 1 {
		t.Fatalf("payload_json column count = %d, %v", count, err)
	}
}

func testHubRepository(t *testing.T) HubRepository {
	t.Helper()
	ctx := context.Background()
	database, err := Open(ctx, filepath.Join(t.TempDir(), "hub.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	pair, err := wgingress.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := InitializeIdentity(ctx, database, IdentityInput{
		VPSID: "vps:hub", DisplayName: "Main VPS", IdentityFingerprint: strings.Repeat("a", 64), PublicKey: pair.Public,
		PrivateKeySecretRef: "/var/lib/gateway-vpn-vps/agent/secrets/wireguard/server.key",
		UpdateIdentityRef:   "/var/lib/gateway-vpn-vps/agent/secrets/update/identity.key",
	}, time.Date(2026, 8, 30, 20, 0, 0, 0, time.UTC)); err != nil {
		t.Fatal(err)
	}
	return HubRepository{Database: database, Now: func() time.Time { return time.Date(2026, 8, 30, 20, 0, 0, 0, time.UTC) }}
}

func pairTestGateway(t *testing.T, repository HubRepository, subnet string) GatewayPeer {
	t.Helper()
	bundle, err := repository.CreatePairing(context.Background(), PairingCreateInput{GatewayName: "Test Gateway", Endpoint: "vps.example:51820", Subnet: subnet})
	if err != nil {
		t.Fatal(err)
	}
	pair, err := wgingress.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	peer, err := repository.CompletePairing(context.Background(), PairingCompletion{
		InvitationID: bundle.InvitationID, Token: bundle.Token, SiteID: "site:" + strings.NewReplacer(".", "_", "/", "_").Replace(subnet), DisplayName: "Test Gateway", PublicKey: pair.Public,
	})
	if err != nil {
		t.Fatal(err)
	}
	return peer
}
