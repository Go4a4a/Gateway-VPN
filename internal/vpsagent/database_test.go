package vpsagent

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gateway-vpn/internal/wgingress"
)

func TestVPSAgentSchemaIdentityAndPortableSanitization(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "vps-state.db")
	database, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	liveDatabase := database
	t.Cleanup(func() { _ = liveDatabase.Close() })
	if schema, err := Schema(ctx, database); err != nil || schema != SchemaVersion {
		t.Fatalf("schema = %d, %v", schema, err)
	}
	pair, err := wgingress.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	input := IdentityInput{
		VPSID: "vps:primary", DisplayName: "Основной VPS",
		IdentityFingerprint: strings.Repeat("a", 64), PublicKey: pair.Public,
		PrivateKeySecretRef: "/var/lib/gateway-vpn-vps/agent/secrets/wireguard/server.key",
		UpdateIdentityRef:   "/var/lib/gateway-vpn-vps/agent/secrets/update/identity.key",
	}
	identity, err := InitializeIdentity(ctx, database, input, time.Date(2026, 8, 30, 16, 0, 0, 0, time.UTC))
	if err != nil || identity.VPSID != input.VPSID {
		t.Fatalf("InitializeIdentity() = %+v, %v", identity, err)
	}
	encoded, _ := json.Marshal(identity)
	if strings.Contains(string(encoded), "secret") || strings.Contains(string(encoded), "private_key") {
		t.Fatalf("identity JSON exposed secret refs: %s", encoded)
	}
	changed := input
	changed.VPSID = "vps:clone"
	if _, err := InitializeIdentity(ctx, database, changed, time.Now()); err == nil {
		t.Fatal("immutable VPS identity was replaced")
	}

	ephmeralSecret := "session-secret-must-not-survive-portable-vacuum"
	if _, err := database.ExecContext(ctx, "INSERT INTO users(id,username,password_hash,enabled,must_change_password,created_at,updated_at) VALUES('user:test','test','hash',1,0,'now','now')"); err != nil {
		t.Fatal(err)
	}
	statements := []struct {
		query string
		value string
	}{
		{"INSERT INTO sessions(id_hash,user_id,csrf_hash,created_at,expires_at,last_seen_at,client_key_hash) VALUES(?,'user:test','csrf','now','later','now','client')", ephmeralSecret},
		{"INSERT INTO pairing_invitations(id,token_sha256,state,attempt_count,expires_at,created_at,updated_at) VALUES('invite:a',?,'OPEN',0,'later','now','now')", strings.Repeat("b", 64)},
		{"INSERT INTO audit_events(occurred_at,severity,event_type,details_json) VALUES('now','INFO','PAIRING',?)", `{"secret":"` + ephmeralSecret + `"}`},
	}
	for _, statement := range statements {
		if _, err := database.ExecContext(ctx, statement.query, statement.value); err != nil {
			t.Fatal(err)
		}
	}
	if err := Verify(ctx, database); err != nil {
		t.Fatal(err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	copyPath := filepath.Join(t.TempDir(), "portable.db")
	if err := os.WriteFile(copyPath, content, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := SanitizePortableCopy(ctx, copyPath); err != nil {
		t.Fatal(err)
	}
	sanitized, err := os.ReadFile(copyPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(sanitized), ephmeralSecret) {
		t.Fatal("VACUUMed portable VPS database retained ephemeral secret bytes")
	}
	portable, err := Open(ctx, copyPath)
	if err != nil {
		t.Fatal(err)
	}
	defer portable.Close()
	for _, table := range []string{"sessions", "pairing_invitations", "events", "audit_events", "operations", "login_attempts"} {
		var count int
		if err := portable.QueryRowContext(ctx, "SELECT COUNT(*) FROM "+table).Scan(&count); err != nil || count != 0 {
			t.Fatalf("portable ephemeral table %s count = %d, %v", table, count, err)
		}
	}
	portableIdentity, err := ReadIdentity(ctx, portable)
	if err != nil || portableIdentity.VPSID != input.VPSID || portableIdentity.PublicKey != input.PublicKey {
		t.Fatalf("portable identity = %+v, %v", portableIdentity, err)
	}
}

func TestVPSAgentMigrationRejectsChecksumAndUnsafeIdentity(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "vps-state.db")
	database, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(ctx, "UPDATE schema_migrations SET checksum_sha256='tampered' WHERE version=1"); err != nil {
		t.Fatal(err)
	}
	if err := Migrate(ctx, database); err == nil {
		t.Fatal("tampered VPS migration history was accepted")
	}
	database.Close()

	database, err = Open(ctx, filepath.Join(t.TempDir(), "fresh.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if _, err := InitializeIdentity(ctx, database, IdentityInput{
		VPSID: "../bad", DisplayName: "Bad", IdentityFingerprint: strings.Repeat("a", 64),
		PublicKey: testVPSPublicKey(t), PrivateKeySecretRef: "raw-private-key",
		UpdateIdentityRef: "/var/lib/gateway-vpn-vps/agent/secrets/update/key",
	}, time.Now()); err == nil {
		t.Fatal("unsafe VPS identity was accepted")
	}
}

func TestRestoredVPSIdentityQuarantineAndImportAsNew(t *testing.T) {
	ctx := context.Background()
	database, err := Open(ctx, filepath.Join(t.TempDir(), "vps-state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	originalPair, err := wgingress.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := InitializeIdentity(ctx, database, IdentityInput{
		VPSID: "vps:source", DisplayName: "Source", IdentityFingerprint: strings.Repeat("a", 64), PublicKey: originalPair.Public,
		PrivateKeySecretRef: "/var/lib/gateway-vpn-vps/agent/secrets/wireguard/server.key",
		UpdateIdentityRef:   "/var/lib/gateway-vpn-vps/agent/secrets/update/identity.key",
	}, time.Now()); err != nil {
		t.Fatal(err)
	}
	for _, statement := range []string{
		`INSERT INTO gateway_peers(id,site_id,display_name,public_key,assigned_subnet,assigned_address,remote_address,state,created_at,updated_at) VALUES('peer:1','site:1','Gateway', '` + testVPSPublicKey(t) + `','10.80.1.0/30','10.80.1.1','10.80.1.2','ACTIVE','now','now')`,
		`INSERT INTO prefix_allocations(id,owner_kind,owner_id,prefix,state,created_at,updated_at) VALUES('prefix:1','GATEWAY_LINK','peer:1','10.80.1.0/30','ACTIVE','now','now')`,
		`INSERT INTO users(id,username,password_hash,enabled,must_change_password,created_at,updated_at) VALUES('user:test','test','hash',1,0,'now','now')`,
		`INSERT INTO sessions(id_hash,user_id,csrf_hash,created_at,expires_at,last_seen_at,client_key_hash) VALUES('session-secret','user:test','csrf','now','later','now','client')`,
	} {
		if _, err := database.ExecContext(ctx, statement); err != nil {
			t.Fatal(err)
		}
	}
	if err := QuarantineRestoredRuntime(ctx, database, time.Now()); err != nil {
		t.Fatal(err)
	}
	var peerState, prefixState string
	if err := database.QueryRowContext(ctx, "SELECT state FROM gateway_peers WHERE id='peer:1'").Scan(&peerState); err != nil || peerState != "QUARANTINED" {
		t.Fatalf("peer state = %q, %v", peerState, err)
	}
	if err := database.QueryRowContext(ctx, "SELECT state FROM prefix_allocations WHERE id='prefix:1'").Scan(&prefixState); err != nil || prefixState != "QUARANTINED" {
		t.Fatalf("prefix state = %q, %v", prefixState, err)
	}
	newPair, err := wgingress.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	identity, err := ImportPortableAsNew(ctx, database, IdentityInput{
		VPSID: "vps:new", DisplayName: "Imported VPS", IdentityFingerprint: strings.Repeat("b", 64), PublicKey: newPair.Public,
		PrivateKeySecretRef: "/var/lib/gateway-vpn-vps/agent/secrets/wireguard/server.key",
		UpdateIdentityRef:   "/var/lib/gateway-vpn-vps/agent/secrets/update/identity.key",
	}, time.Now())
	if err != nil || identity.VPSID != "vps:new" || identity.PublicKey != newPair.Public {
		t.Fatalf("ImportPortableAsNew() = %+v, %v", identity, err)
	}
	for _, table := range []string{"gateway_peers", "admin_peers", "prefix_allocations", "resource_publications", "acl_grants", "sessions"} {
		var count int
		if err := database.QueryRowContext(ctx, "SELECT COUNT(*) FROM "+table).Scan(&count); err != nil || count != 0 {
			t.Fatalf("new VPS table %s count = %d, %v", table, count, err)
		}
	}
}

func testVPSPublicKey(t *testing.T) string {
	t.Helper()
	pair, err := wgingress.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	return pair.Public
}
