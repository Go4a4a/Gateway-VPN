package vpsagent

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gateway-vpn/internal/wgingress"
)

func TestManagedAdministratorConfigIsOneUseAndRotationIsMakeBeforeBreak(t *testing.T) {
	ctx := context.Background()
	stateDirectory := filepath.Join(t.TempDir(), "state")
	database, err := Open(ctx, filepath.Join(stateDirectory, "vps-agent.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	vpsPair, err := wgingress.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	clock := func() time.Time { return time.Date(2026, 8, 30, 22, 0, 0, 0, time.UTC) }
	if _, err := InitializeIdentity(ctx, database, IdentityInput{
		VPSID: "vps:managed", DisplayName: "Managed VPS", IdentityFingerprint: strings.Repeat("e", 64), PublicKey: vpsPair.Public,
		PrivateKeySecretRef: "/var/lib/gateway-vpn-vps/agent/secrets/wireguard/server.key",
		UpdateIdentityRef:   "/var/lib/gateway-vpn-vps/agent/secrets/update/identity.key",
	}, clock()); err != nil {
		t.Fatal(err)
	}
	repository := HubRepository{Database: database, Now: clock}
	gateway := pairTestGateway(t, repository, "10.82.0.0/30")
	manager, err := NewAdminKeyManager(database, stateDirectory, clock)
	if err != nil {
		t.Fatal(err)
	}
	admin, err := manager.Create(ctx, "Ноутбук", "10.81.0.10")
	if err != nil {
		t.Fatal(err)
	}
	if admin.KeyMode != "MANAGED" || admin.ConfigState != "AVAILABLE" || admin.RotationSourceID != "" {
		t.Fatalf("managed administrator = %+v", admin)
	}
	encoded, _ := json.Marshal(admin)
	if strings.Contains(string(encoded), "private") || strings.Contains(string(encoded), "secret_ref") {
		t.Fatalf("administrator JSON leaked secret metadata: %s", encoded)
	}
	resource, err := repository.CreateResource(ctx, ResourceInput{
		GatewayPeerID: gateway.ID, ResourceID: "gateway:web", DisplayName: "Gateway WebUI",
		ResourceKind: "GATEWAY_SERVICE", LocalDestination: "192.168.200.2", PublishedAlias: "10.96.0.2",
		AccessProfile: "GATEWAY_ONLY", Enabled: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repository.CreateACL(ctx, ACLInput{AdminPeerID: admin.ID, PublicationID: resource.ID, Protocol: "TCP", PortStart: 443, PortEnd: 443}); err != nil {
		t.Fatal(err)
	}
	var reference string
	if err := database.QueryRowContext(ctx, "SELECT private_key_secret_ref FROM admin_peers WHERE id=?", admin.ID).Scan(&reference); err != nil {
		t.Fatal(err)
	}
	physical, err := manager.physicalPath(reference)
	if err != nil {
		t.Fatal(err)
	}
	if info, err := os.Lstat(physical); err != nil || !info.Mode().IsRegular() {
		t.Fatalf("managed secret before download = %v, %v", info, err)
	}
	artifact, err := manager.Export(ctx, admin.ID, "VPS.Example:51820")
	if err != nil {
		t.Fatal(err)
	}
	configuration := string(artifact.Content)
	for _, expected := range []string{
		"[Interface]", "PrivateKey = ", "Address = 10.81.0.10/32", "PublicKey = " + vpsPair.Public,
		"Endpoint = vps.example:51820", "10.82.0.1/32", "10.82.0.2/32", "10.96.0.2/32",
	} {
		if !strings.Contains(configuration, expected) {
			t.Fatalf("managed configuration misses %q: %s", expected, configuration)
		}
	}
	if _, err := os.Lstat(physical); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("consumed private key still exists: %v", err)
	}
	if _, err := manager.Export(ctx, admin.ID, "vps.example:51820"); !errors.Is(err, ErrHubConflict) {
		t.Fatalf("second config download error = %v", err)
	}
	consumed, err := repository.GetAdmin(ctx, admin.ID)
	if err != nil || consumed.ConfigState != "CONSUMED" || consumed.ConfigDownloadedAt == "" {
		t.Fatalf("consumed administrator = %+v, %v", consumed, err)
	}
	replacement, err := manager.Rotate(ctx, admin.ID, "", "10.81.0.11")
	if err != nil {
		t.Fatal(err)
	}
	if replacement.RotationSourceID != admin.ID || replacement.ConfigState != "AVAILABLE" || replacement.State == "REVOKED" {
		t.Fatalf("replacement administrator = %+v", replacement)
	}
	if source, err := repository.GetAdmin(ctx, admin.ID); err != nil || source.State == "REVOKED" {
		t.Fatalf("rotation revoked the proven source prematurely: %+v, %v", source, err)
	}
	if err := manager.Revoke(ctx, replacement.ID); err != nil {
		t.Fatal(err)
	}
	if revoked, err := repository.GetAdmin(ctx, replacement.ID); err != nil || revoked.State != "REVOKED" {
		t.Fatalf("replacement revoke = %+v, %v", revoked, err)
	}
}

func TestManagedAdministratorRejectsUnsafeEndpointAndExternalRotation(t *testing.T) {
	ctx := context.Background()
	repository := testHubRepository(t)
	stateDirectory := filepath.Join(t.TempDir(), "state")
	manager, err := NewAdminKeyManager(repository.Database, stateDirectory, repository.Now)
	if err != nil {
		t.Fatal(err)
	}
	admin, err := manager.Create(ctx, "Телефон", "10.81.0.20")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Export(ctx, admin.ID, "https://user:secret@example.invalid/"); err == nil {
		t.Fatal("unsafe endpoint was accepted")
	}
	pair, _ := wgingress.GenerateKeyPair()
	external, err := repository.CreateAdmin(ctx, AdminCreateInput{Name: "External", PublicKey: pair.Public, AssignedAddress: "10.81.0.21", KeyMode: "EXTERNAL"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Rotate(ctx, external.ID, "", "10.81.0.22"); err == nil {
		t.Fatal("external administrator rotation generated a server-owned private key")
	}
}
