package backup

import (
	"archive/zip"
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	databasepkg "gateway-vpn/internal/db"
)

func TestPortableBackupEncryptsSecretsAuthenticatesChunksAndContainsVerifiedManifest(t *testing.T) {
	ctx, database, snapshots := snapshotTestManager(t)
	stateDirectory := filepath.Dir(snapshots.DatabasePath)
	configurationDirectory := t.TempDir()
	configurationPath := filepath.Join(configurationDirectory, "config.yaml")
	files := map[string]string{
		configurationPath: "version: 1\nsystem:\n  state_dir: /var/lib/gateway-vpn\n",
		filepath.Join(stateDirectory, "secrets", "management", "link-a.key"):                    "management-fabric-private-secret",
		filepath.Join(stateDirectory, "secrets", "management", "wg-admin.key"):                  "gateway-admin-contour-private-secret",
		filepath.Join(stateDirectory, "secrets", "subscriptions", "sub-a.url"):                  "https://subscription.example/private?token=subscription-secret",
		filepath.Join(stateDirectory, "secrets", "wireguard.yaml"):                              "private_key: wireguard-private-secret",
		filepath.Join(stateDirectory, "secrets", "wireguard-ingress", "servers", "default.key"): "wireguard-ingress-server-private-secret",
		filepath.Join(stateDirectory, "secrets", "wireguard-ingress", "peers", "peer-a.key"):    "wireguard-ingress-peer-private-secret",
		filepath.Join(stateDirectory, "secrets", "wireguard-ingress", "peers", "peer-a.psk"):    "wireguard-ingress-peer-preshared-secret",
		filepath.Join(stateDirectory, "secrets", "mihomo-api-secret"):                           "mihomo-api-secret-value",
		filepath.Join(stateDirectory, "subscriptions", "version-a", "nodes.json"):               `{"uuid":"proxy-private-secret"}`,
		filepath.Join(stateDirectory, "tls", "key.pem"):                                         "tls-private-secret",
		filepath.Join(stateDirectory, "tls", "cert.pem"):                                        "safe-certificate",
		filepath.Join(stateDirectory, "mihomo", "generations", "generation-a", "config.yaml"):   "password: mihomo-private-secret",
		filepath.Join(stateDirectory, "mihomo", "state", "lkg-generation"):                      "generation-a\n",
	}
	for filename, content := range files {
		if err := os.MkdirAll(filepath.Dir(filename), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filename, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := database.ExecContext(ctx, `INSERT INTO events(occurred_at,severity,type,details_json) VALUES('2026-08-24T14:00:00Z','INFO','PORTABLE_SOURCE','{}')`); err != nil {
		t.Fatal(err)
	}
	seedManagementFabricBackupFixture(t, ctx, database, "restored", "/var/lib/gateway-vpn/secrets/management/link-a.key", 7, 6)
	seedAdministratorRelayBackupFixture(t, ctx, database, "restored")
	manager, err := NewPortableManager(snapshots, stateDirectory, configurationPath, "gateway-vpn test")
	if err != nil {
		t.Fatal(err)
	}
	manager.Now = func() time.Time { return time.Date(2026, 8, 24, 14, 30, 0, 0, time.UTC) }
	manager.TransientSnapshot = true
	passphrase := "correct horse battery staple"
	artifact, err := manager.Build(ctx, passphrase)
	if err != nil {
		t.Fatal(err)
	}
	if !portableNamePattern.MatchString(artifact.Filename) || artifact.Bytes <= 0 || artifact.Bytes > MaximumPortableBackupBytes || len(artifact.SHA256) != 64 || artifact.SnapshotID == "" || !artifact.Manifest.SecretsIncluded {
		t.Fatalf("portable artifact = %+v", artifact)
	}
	if _, err := os.Stat(filepath.Join(snapshots.Root, artifact.SnapshotID)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("privileged transient snapshot remains after encryption: %v", err)
	}
	encrypted, err := os.ReadFile(artifact.Path)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{
		"management-fabric-private-secret", "gateway-admin-contour-private-secret", "subscription-secret", "wireguard-private-secret", "wireguard-ingress-server-private-secret",
		"wireguard-ingress-peer-private-secret", "wireguard-ingress-peer-preshared-secret",
		"proxy-private-secret", "tls-private-secret", "mihomo-private-secret",
	} {
		if bytes.Contains(encrypted, []byte(secret)) {
			t.Fatalf("encrypted artifact contains plaintext %q", secret)
		}
	}

	decryptedPath := filepath.Join(t.TempDir(), "portable.zip")
	plainBytes, err := DecryptToZIP(ctx, artifact.Path, decryptedPath, passphrase)
	if err != nil || plainBytes <= 0 || plainBytes > MaximumPortablePlainBytes {
		t.Fatalf("DecryptToZIP() = %d, %v", plainBytes, err)
	}
	archive, err := zip.OpenReader(decryptedPath)
	if err != nil {
		t.Fatal(err)
	}
	defer archive.Close()
	contents := map[string][]byte{}
	for _, item := range archive.File {
		if !safePortablePath(item.Name) || item.Mode().Perm() != 0o600 {
			t.Fatalf("unsafe ZIP entry %q mode %o", item.Name, item.Mode().Perm())
		}
		reader, err := item.Open()
		if err != nil {
			t.Fatal(err)
		}
		content, err := io.ReadAll(io.LimitReader(reader, MaximumPortablePlainBytes+1))
		reader.Close()
		if err != nil {
			t.Fatal(err)
		}
		contents[item.Name] = content
	}
	for _, name := range []string{
		"manifest.json", "database/state.db", "config/config.yaml",
		"state/secrets/management/link-a.key", "state/secrets/management/wg-admin.key",
		"state/secrets/subscriptions/sub-a.url", "state/secrets/wireguard.yaml",
		"state/secrets/wireguard-ingress/servers/default.key",
		"state/secrets/wireguard-ingress/peers/peer-a.key",
		"state/secrets/wireguard-ingress/peers/peer-a.psk",
		"state/subscriptions/version-a/nodes.json", "state/tls/key.pem", "state/tls/cert.pem",
		"state/mihomo/generations/generation-a/config.yaml", "state/mihomo/state/lkg-generation",
	} {
		if _, exists := contents[name]; !exists {
			t.Fatalf("portable backup missing %s", name)
		}
	}
	var manifest PortableManifest
	if err := json.Unmarshal(contents["manifest.json"], &manifest); err != nil || !manifest.SecretsIncluded || manifest.SnapshotID != artifact.SnapshotID || manifest.SchemaVersion != 31 || len(manifest.Files) != len(contents)-1 {
		t.Fatalf("portable manifest = %+v, %v", manifest, err)
	}
	extractedDatabase := filepath.Join(t.TempDir(), "state.db")
	if err := os.WriteFile(extractedDatabase, contents["database/state.db"], 0o600); err != nil {
		t.Fatal(err)
	}
	verifiedDatabase, err := databasepkg.OpenImmutable(ctx, extractedDatabase)
	if err != nil {
		t.Fatal(err)
	}
	if err := databasepkg.IntegrityCheck(ctx, verifiedDatabase); err != nil {
		verifiedDatabase.Close()
		t.Fatal(err)
	}
	assertManagementFabricBackupFixture(t, ctx, verifiedDatabase, "restored", "/var/lib/gateway-vpn/secrets/management/link-a.key", 7, 6)
	assertAdministratorRelayBackupFixture(t, ctx, verifiedDatabase, "restored")
	verifiedDatabase.Close()

	wrongDestination := filepath.Join(t.TempDir(), "wrong.zip")
	if _, err := DecryptToZIP(ctx, artifact.Path, wrongDestination, "wrong passphrase long enough"); err == nil || !strings.Contains(err.Error(), "passphrase or artifact") {
		t.Fatalf("wrong passphrase error = %v", err)
	}
	if _, err := os.Stat(wrongDestination); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("wrong-passphrase plaintext remains: %v", err)
	}
	tamperedPath := filepath.Join(t.TempDir(), "tampered.gvpn")
	tampered := append([]byte(nil), encrypted...)
	tampered[len(tampered)-8] ^= 0x80
	if err := os.WriteFile(tamperedPath, tampered, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := DecryptToZIP(ctx, tamperedPath, filepath.Join(t.TempDir(), "tampered.zip"), passphrase); err == nil {
		t.Fatal("tampered encrypted backup was accepted")
	}
	truncatedPath := filepath.Join(t.TempDir(), "truncated.gvpn")
	if err := os.WriteFile(truncatedPath, encrypted[:len(encrypted)-5], 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := DecryptToZIP(ctx, truncatedPath, filepath.Join(t.TempDir(), "truncated.zip"), passphrase); err == nil {
		t.Fatal("backup without authenticated final record was accepted")
	}
	if err := manager.Remove(artifact); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(artifact.Path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("served portable artifact remains: %v", err)
	}
}

func seedManagementFabricBackupFixture(t *testing.T, ctx context.Context, database *sql.DB, suffix, privateKeyReference string, desiredGeneration, appliedGeneration int64) {
	t.Helper()
	stamp := "2026-08-30T12:00:00Z"
	statements := []struct {
		query string
		args  []any
	}{
		{`INSERT INTO management_sites(id,display_name,is_local,identity_state,created_at,updated_at) VALUES(?,?,1,'ACTIVE',?,?)`, []any{"site:" + suffix, "Site " + suffix, stamp, stamp}},
		{`INSERT INTO vps_nodes(id,display_number,name,enabled,priority,verified_fingerprint,public_key,admin_address_pool,resource_alias_pool,state,created_at,updated_at) VALUES(?,1,?,1,1,?,?,? ,?,'REACHABLE',?,?)`, []any{"vps:" + suffix, "VPS " + suffix, strings.Repeat("a", 64), "remote-public-" + suffix, "10.90.0.0/24", "10.91.0.0/24", stamp, stamp}},
		{`INSERT INTO management_links(id,site_id,vps_id,slot,interface_name,enabled,management_subnet,local_address,remote_address,local_private_key_secret_ref,local_public_key,remote_public_key,uplink_policy,persistent_keepalive,desired_route_generation,applied_route_generation,desired_acl_generation,applied_acl_generation,state,created_at,updated_at) VALUES(?,?,?,1,'gvm1',1,'10.81.0.0/30','10.81.0.2/32','10.81.0.1/32',?,?,?,'AUTO',25,7,6,7,6,'REACHABLE',?,?)`, []any{"link:" + suffix, "site:" + suffix, "vps:" + suffix, privateKeyReference, "local-public-" + suffix, "remote-public-" + suffix, stamp, stamp}},
		{`UPDATE management_fabric_generations SET desired_generation=?,applied_generation=?,state='PENDING',last_error_code='RESTORE_FIXTURE',updated_at=? WHERE singleton_id=1`, []any{desiredGeneration, appliedGeneration, stamp}},
	}
	for _, statement := range statements {
		if _, err := database.ExecContext(ctx, statement.query, statement.args...); err != nil {
			t.Fatalf("seed management fabric backup fixture: %v", err)
		}
	}
}

func assertManagementFabricBackupFixture(t *testing.T, ctx context.Context, database *sql.DB, suffix, privateKeyReference string, desiredGeneration, appliedGeneration int64) {
	t.Helper()
	var reference, interfaceName, state, errorCode string
	var desired, applied int64
	err := database.QueryRowContext(ctx, `
SELECT l.local_private_key_secret_ref,l.interface_name,g.desired_generation,g.applied_generation,g.state,g.last_error_code
FROM management_links AS l
CROSS JOIN management_fabric_generations AS g
WHERE l.id=? AND g.singleton_id=1`, "link:"+suffix).Scan(&reference, &interfaceName, &desired, &applied, &state, &errorCode)
	if err != nil || reference != privateKeyReference || interfaceName != "gvm1" || desired != desiredGeneration || applied != appliedGeneration || state != "PENDING" || errorCode != "RESTORE_FIXTURE" {
		t.Fatalf("management fabric backup fixture = ref=%q interface=%q generation=%d/%d state=%q error=%q, %v", reference, interfaceName, desired, applied, state, errorCode, err)
	}
}

func seedAdministratorRelayBackupFixture(t *testing.T, ctx context.Context, database *sql.DB, suffix string) {
	t.Helper()
	stamp := "2026-08-30T12:30:00Z"
	statements := []struct {
		query string
		args  []any
	}{
		{`INSERT INTO management_admins(id,name,identity_kind,enabled,state,created_at,updated_at) VALUES(?,?,'ADMIN',1,'ACTIVE',?,?)`, []any{"admin:" + suffix, "Administrator " + suffix, stamp, stamp}},
		{`INSERT INTO management_admin_vps_peers(id,admin_id,vps_id,public_key,assigned_address,state,desired_generation,applied_generation,created_at,updated_at,trust_mode) VALUES(?,?,?,?,?,'ACTIVE',9,8,?,?, 'END_TO_END_RELAY')`, []any{"admin-peer:" + suffix, "admin:" + suffix, "vps:" + suffix, "outer-admin-public-" + suffix, "10.90.0.10", stamp, stamp}},
		{`INSERT INTO management_admin_contour(singleton_id,enabled,interface_name,private_key_secret_ref,public_key,subnet,gateway_address,listen_port,desired_generation,applied_generation,state,last_error_code,created_at,updated_at) VALUES(1,1,'wg-admin','/var/lib/gateway-vpn/secrets/management/wg-admin.key',?,'10.83.0.0/24','10.83.0.1',51822,11,10,'ACTIVE','',?,?)`, []any{"contour-public-" + suffix, stamp, stamp}},
		{`INSERT INTO management_admin_relays(id,link_id,enabled,public_endpoint_host,public_bind_address,public_udp_port,destination_port,rate_limit_per_second,burst_packets,desired_generation,applied_generation,state,last_error_code,created_at,updated_at) VALUES(?,?,1,?,'203.0.113.10',55182,51822,137,271,12,11,'ACTIVE','',?,?)`, []any{"relay:" + suffix, "link:" + suffix, "relay-" + suffix + ".example", stamp, stamp}},
		{`INSERT INTO management_admin_tunnels(id,admin_id,relay_id,public_key,assigned_address,state,desired_generation,applied_generation,latest_handshake_at,rx_bytes,tx_bytes,last_error_code,created_at,updated_at) VALUES(?,?,?,?,?,'ACTIVE',13,12,?,1234,5678,'',?,?)`, []any{"admin-tunnel:" + suffix, "admin:" + suffix, "relay:" + suffix, "inner-admin-public-" + suffix, "10.83.0.10", stamp, stamp, stamp}},
	}
	for _, statement := range statements {
		if _, err := database.ExecContext(ctx, statement.query, statement.args...); err != nil {
			t.Fatalf("seed administrator relay backup fixture: %v", err)
		}
	}
}

func assertAdministratorRelayBackupFixture(t *testing.T, ctx context.Context, database *sql.DB, suffix string) {
	t.Helper()
	var secretReference, contourPublic, subnet, gatewayAddress, contourState string
	var listenPort int
	var contourDesired, contourApplied int64
	if err := database.QueryRowContext(ctx, `SELECT private_key_secret_ref,public_key,subnet,gateway_address,listen_port,desired_generation,applied_generation,state FROM management_admin_contour WHERE singleton_id=1`).Scan(&secretReference, &contourPublic, &subnet, &gatewayAddress, &listenPort, &contourDesired, &contourApplied, &contourState); err != nil || secretReference != "/var/lib/gateway-vpn/secrets/management/wg-admin.key" || contourPublic != "contour-public-"+suffix || subnet != "10.83.0.0/24" || gatewayAddress != "10.83.0.1" || listenPort != 51822 || contourDesired != 11 || contourApplied != 10 || contourState != "ACTIVE" {
		t.Fatalf("administrator contour backup fixture = secret=%q public=%q subnet=%q gateway=%q port=%d generation=%d/%d state=%q, %v", secretReference, contourPublic, subnet, gatewayAddress, listenPort, contourDesired, contourApplied, contourState, err)
	}
	var trustMode, outerPublic, outerAddress, outerState string
	var outerDesired, outerApplied int64
	if err := database.QueryRowContext(ctx, `SELECT public_key,assigned_address,state,desired_generation,applied_generation,trust_mode FROM management_admin_vps_peers WHERE id=?`, "admin-peer:"+suffix).Scan(&outerPublic, &outerAddress, &outerState, &outerDesired, &outerApplied, &trustMode); err != nil || outerPublic != "outer-admin-public-"+suffix || outerAddress != "10.90.0.10" || outerState != "ACTIVE" || outerDesired != 9 || outerApplied != 8 || trustMode != "END_TO_END_RELAY" {
		t.Fatalf("administrator trust-mode backup fixture = public=%q address=%q state=%q generation=%d/%d trust=%q, %v", outerPublic, outerAddress, outerState, outerDesired, outerApplied, trustMode, err)
	}
	var linkID, endpoint, bindAddress, relayState string
	var publicPort, destinationPort, rate, burst int
	var relayDesired, relayApplied int64
	if err := database.QueryRowContext(ctx, `SELECT link_id,public_endpoint_host,public_bind_address,public_udp_port,destination_port,rate_limit_per_second,burst_packets,desired_generation,applied_generation,state FROM management_admin_relays WHERE id=?`, "relay:"+suffix).Scan(&linkID, &endpoint, &bindAddress, &publicPort, &destinationPort, &rate, &burst, &relayDesired, &relayApplied, &relayState); err != nil || linkID != "link:"+suffix || endpoint != "relay-"+suffix+".example" || bindAddress != "203.0.113.10" || publicPort != 55182 || destinationPort != 51822 || rate != 137 || burst != 271 || relayDesired != 12 || relayApplied != 11 || relayState != "ACTIVE" {
		t.Fatalf("administrator relay backup fixture = link=%q endpoint=%q bind=%q ports=%d/%d rate=%d/%d generation=%d/%d state=%q, %v", linkID, endpoint, bindAddress, publicPort, destinationPort, rate, burst, relayDesired, relayApplied, relayState, err)
	}
	var adminID, relayID, innerPublic, innerAddress, tunnelState string
	var tunnelDesired, tunnelApplied, rxBytes, txBytes int64
	if err := database.QueryRowContext(ctx, `SELECT admin_id,relay_id,public_key,assigned_address,state,desired_generation,applied_generation,rx_bytes,tx_bytes FROM management_admin_tunnels WHERE id=?`, "admin-tunnel:"+suffix).Scan(&adminID, &relayID, &innerPublic, &innerAddress, &tunnelState, &tunnelDesired, &tunnelApplied, &rxBytes, &txBytes); err != nil || adminID != "admin:"+suffix || relayID != "relay:"+suffix || innerPublic != "inner-admin-public-"+suffix || innerAddress != "10.83.0.10" || tunnelState != "ACTIVE" || tunnelDesired != 13 || tunnelApplied != 12 || rxBytes != 1234 || txBytes != 5678 {
		t.Fatalf("administrator tunnel backup fixture = admin=%q relay=%q public=%q address=%q state=%q generation=%d/%d traffic=%d/%d, %v", adminID, relayID, innerPublic, innerAddress, tunnelState, tunnelDesired, tunnelApplied, rxBytes, txBytes, err)
	}
}

func TestPortableBackupRejectsWeakPassphraseAndSymlinkedSecret(t *testing.T) {
	ctx, _, snapshots := snapshotTestManager(t)
	stateDirectory := filepath.Dir(snapshots.DatabasePath)
	configurationPath := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(configurationPath, []byte("version: 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	manager, err := NewPortableManager(snapshots, stateDirectory, configurationPath, "test")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Build(ctx, "short"); err == nil {
		t.Fatal("weak portable backup passphrase was accepted")
	}
	secretDirectory := filepath.Join(stateDirectory, "secrets")
	if err := os.MkdirAll(secretDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "outside-secret")
	if err := os.WriteFile(target, []byte("must-not-follow"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(secretDirectory, "linked-secret")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if _, err := manager.Build(ctx, "correct horse battery staple"); err == nil {
		t.Fatal("symlinked secret was accepted")
	}
}
