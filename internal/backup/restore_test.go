package backup

import (
	"archive/zip"
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRestoreStageAuthenticatesExtractsVerifiesAndPersistsNoPassphrase(t *testing.T) {
	ctx, _, snapshots := snapshotTestManager(t)
	stateDirectory := filepath.Dir(snapshots.DatabasePath)
	configurationPath := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(configurationPath, []byte(validRestoreConfig()), 0o600); err != nil {
		t.Fatal(err)
	}
	secretPath := filepath.Join(stateDirectory, "secrets", "subscriptions", "sub-a.url")
	if err := os.MkdirAll(filepath.Dir(secretPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(secretPath, []byte("https://subscription.example/private?token=restore-secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	for filename, content := range map[string]string{
		filepath.Join(stateDirectory, "secrets", "mihomo-api-secret"): "mihomo-api-secret-value",
		filepath.Join(stateDirectory, "tls", "cert.pem"):              "test-certificate",
		filepath.Join(stateDirectory, "tls", "key.pem"):               "test-private-key",
	} {
		if err := os.MkdirAll(filepath.Dir(filename), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filename, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	portable, err := NewPortableManager(snapshots, stateDirectory, configurationPath, "gateway-vpn restore-test")
	if err != nil {
		t.Fatal(err)
	}
	passphrase := "correct horse battery staple"
	artifact, err := portable.Build(ctx, passphrase)
	if err != nil {
		t.Fatal(err)
	}
	defer portable.Remove(artifact)
	restoreState := t.TempDir()
	restoreDatabase := filepath.Join(restoreState, "state.db")
	restoreConfig := filepath.Join(t.TempDir(), "config.yaml")
	restorer, err := NewRestoreManager(restoreState, restoreDatabase, restoreConfig)
	if err != nil {
		t.Fatal(err)
	}
	restorer.ExpectedStateDirectory = "/var/lib/gateway-vpn"
	restorer.ExpectedDatabasePath = "/var/lib/gateway-vpn/state.db"
	restorer.ExpectedMihomoBinary = "/opt/gateway-vpn/current/libexec/mihomo"
	restorer.ExpectedAPISecretPath = "/var/lib/gateway-vpn/secrets/mihomo-api-secret"
	restorer.ExpectedTLSCertPath = "/var/lib/gateway-vpn/tls/cert.pem"
	restorer.ExpectedTLSKeyPath = "/var/lib/gateway-vpn/tls/key.pem"
	reader, err := portable.Open(artifact)
	if err != nil {
		t.Fatal(err)
	}
	operation, err := restorer.Stage(ctx, reader, passphrase)
	reader.Close()
	if err != nil {
		t.Fatal(err)
	}
	if operation.State != RestoreStateStaged || !restoreIDPattern.MatchString(operation.RestoreID) || operation.SnapshotID != artifact.SnapshotID || operation.PortableSHA256 != artifact.SHA256 || operation.Files < 3 {
		t.Fatalf("restore operation = %+v", operation)
	}
	status, exists, err := restorer.Status()
	if err != nil || !exists || status.RestoreID != operation.RestoreID {
		t.Fatalf("restore Status() = %+v, %v, %v", status, exists, err)
	}
	operationRoot := filepath.Join(restorer.Root, operation.RestoreID)
	for _, absent := range []string{"upload.gvpn", "payload.zip"} {
		if _, err := os.Stat(filepath.Join(operationRoot, absent)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("temporary restore artifact %s remains: %v", absent, err)
		}
	}
	for _, present := range []string{"operation.json", "portable-manifest.json", "tree/database/state.db", "tree/config/config.yaml", "tree/state/secrets/subscriptions/sub-a.url"} {
		if _, err := os.Stat(filepath.Join(operationRoot, filepath.FromSlash(present))); err != nil {
			t.Fatalf("verified restore file %s missing: %v", present, err)
		}
	}
	err = filepath.WalkDir(filepath.Join(restoreState, "recovery"), func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil || entry.IsDir() {
			return walkErr
		}
		content, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if bytes.Contains(content, []byte(passphrase)) {
			t.Fatalf("restore staging persisted passphrase in %s", path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	reader, err = portable.Open(artifact)
	if err != nil {
		t.Fatal(err)
	}
	_, secondErr := restorer.Stage(ctx, reader, passphrase)
	reader.Close()
	if !errors.Is(secondErr, ErrRestorePending) {
		t.Fatalf("second Stage() error = %v", secondErr)
	}
	if _, err := restorer.VerifyPending(ctx); !errors.Is(err, ErrRestoreNotAuthorized) {
		t.Fatalf("VerifyPending before explicit authorization error = %v", err)
	}
	// Simulate power loss after the pointer-like marker was updated but before
	// operation.json became the authorization commit point. The restore must
	// remain staged and non-destructive.
	tornAuthorization := operation
	tornAuthorization.State = RestoreStateApplyRequested
	tornAuthorization.ApplyAuthorization = strings.Repeat("a", 64)
	if err := writeJSONFile(restorer.pendingPath(), tornAuthorization, true); err != nil {
		t.Fatal(err)
	}
	status, exists, err = restorer.Status()
	if err != nil || !exists || status.State != RestoreStateStaged {
		t.Fatalf("torn authorization status = %+v, %t, %v", status, exists, err)
	}
	if _, err := restorer.AuthorizeApply("restore-00000000000000000000000000000000"); !errors.Is(err, ErrRestoreNotPending) {
		t.Fatalf("AuthorizeApply(other) error = %v", err)
	}
	authorized, err := restorer.AuthorizeApply(operation.RestoreID)
	if err != nil || authorized.State != RestoreStateApplyRequested || !validDigest(authorized.ApplyAuthorization) || authorized.ApplyErrorCode != "" {
		t.Fatalf("AuthorizeApply() = %+v, %v", authorized, err)
	}
	idempotent, err := restorer.AuthorizeApply(operation.RestoreID)
	if err != nil || idempotent.ApplyAuthorization != authorized.ApplyAuthorization {
		t.Fatalf("idempotent AuthorizeApply() = %+v, %v", idempotent, err)
	}
	if _, err := restorer.VerifyPending(ctx); err != nil {
		t.Fatalf("VerifyPending after authorization = %v", err)
	}
	if err := restorer.markApplyFailure(operation.RestoreID, "INJECTED_RETRYABLE_FAILURE"); err != nil {
		t.Fatal(err)
	}
	// Simulate power loss after operation.json was replaced but before the
	// pointer-like pending marker was updated.
	if err := writeJSONFile(restorer.pendingPath(), operation, true); err != nil {
		t.Fatal(err)
	}
	tornStatus, exists, err := restorer.Status()
	if err != nil || !exists || tornStatus.ApplyErrorCode != "INJECTED_RETRYABLE_FAILURE" {
		t.Fatalf("torn pending marker recovery = %+v, %t, %v", tornStatus, exists, err)
	}
	if tornStatus.State != RestoreStateStaged {
		t.Fatalf("failed restore did not revoke apply authorization: %+v", tornStatus)
	}
	if _, err := restorer.VerifyPending(ctx); !errors.Is(err, ErrRestoreNotAuthorized) {
		t.Fatalf("VerifyPending after failed apply error = %v", err)
	}
	reauthorized, err := restorer.AuthorizeApply(operation.RestoreID)
	if err != nil || reauthorized.State != RestoreStateApplyRequested || !validDigest(reauthorized.ApplyAuthorization) || reauthorized.ApplyAuthorization == authorized.ApplyAuthorization || reauthorized.ApplyErrorCode != "" {
		t.Fatalf("retry AuthorizeApply() = %+v, %v", reauthorized, err)
	}
	if err := restorer.markApplyFailure(operation.RestoreID, "RETRY_CANCELLED_FOR_DISCARD"); err != nil {
		t.Fatal(err)
	}
	if err := restorer.Discard(ctx, "restore-00000000000000000000000000000000"); !errors.Is(err, ErrRestoreNotPending) {
		t.Fatalf("Discard(other) error = %v", err)
	}
	if err := restorer.Discard(ctx, operation.RestoreID); err != nil {
		t.Fatalf("Discard(staged) error = %v", err)
	}
	if _, exists, err := restorer.Status(); err != nil || exists {
		t.Fatalf("discarded restore pending status = %v, %v", exists, err)
	}
	if _, err := os.Stat(operationRoot); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("discarded restore directory remains: %v", err)
	}
	if err := restorer.Discard(ctx, operation.RestoreID); !errors.Is(err, ErrRestoreNotPending) {
		t.Fatalf("Discard(already discarded) error = %v", err)
	}
}

func TestRestoreStageRejectsWrongPassphraseTamperingTraversalAndLeavesNoPending(t *testing.T) {
	ctx, _, snapshots := snapshotTestManager(t)
	stateDirectory := filepath.Dir(snapshots.DatabasePath)
	configurationPath := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(configurationPath, []byte(validRestoreConfig()), 0o600); err != nil {
		t.Fatal(err)
	}
	for filename, content := range map[string]string{
		filepath.Join(stateDirectory, "secrets", "mihomo-api-secret"): "mihomo-api-secret-value",
		filepath.Join(stateDirectory, "tls", "cert.pem"):              "test-certificate",
		filepath.Join(stateDirectory, "tls", "key.pem"):               "test-private-key",
	} {
		if err := os.MkdirAll(filepath.Dir(filename), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filename, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	portable, err := NewPortableManager(snapshots, stateDirectory, configurationPath, "test")
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := portable.Build(ctx, "correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	defer portable.Remove(artifact)
	content, err := os.ReadFile(artifact.Path)
	if err != nil {
		t.Fatal(err)
	}
	content[len(content)/2] ^= 0x01

	for name, input := range map[string]struct {
		content    []byte
		passphrase string
	}{
		"wrong-passphrase": {content: mustReadFile(t, artifact.Path), passphrase: "another valid passphrase"},
		"tampered":         {content: content, passphrase: "correct horse battery staple"},
	} {
		t.Run(name, func(t *testing.T) {
			restoreState := t.TempDir()
			restorer, err := NewRestoreManager(restoreState, filepath.Join(restoreState, "state.db"), filepath.Join(t.TempDir(), "config.yaml"))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := restorer.Stage(ctx, bytes.NewReader(input.content), input.passphrase); err == nil || !strings.Contains(err.Error(), "passphrase or backup") {
				t.Fatalf("Stage() error = %v", err)
			}
			if _, exists, err := restorer.Status(); err != nil || exists {
				t.Fatalf("failed stage pending status = %v, %v", exists, err)
			}
		})
	}

	malicious := encryptedZIP(t, "correct horse battery staple", map[string][]byte{"manifest.json": []byte(`{}`), "../escape": []byte("secret")})
	restoreState := t.TempDir()
	restorer, err := NewRestoreManager(restoreState, filepath.Join(restoreState, "state.db"), filepath.Join(t.TempDir(), "config.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := restorer.Stage(ctx, bytes.NewReader(malicious), "correct horse battery staple"); err == nil || !strings.Contains(err.Error(), "unsafe entry") {
		t.Fatalf("traversal Stage() error = %v", err)
	}
	if _, err := os.Stat(filepath.Join(restoreState, "escape")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("traversal file escaped restore root: %v", err)
	}
}

func encryptedZIP(t *testing.T, passphrase string, entries map[string][]byte) []byte {
	t.Helper()
	var output bytes.Buffer
	encrypted, err := newChunkEncryptWriter(&output, passphrase)
	if err != nil {
		t.Fatal(err)
	}
	archive := zip.NewWriter(encrypted)
	for name, content := range entries {
		header := &zip.FileHeader{Name: name, Method: zip.Deflate}
		header.SetMode(0o600)
		writer, err := archive.CreateHeader(header)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := writer.Write(content); err != nil {
			t.Fatal(err)
		}
	}
	if err := archive.Close(); err != nil {
		t.Fatal(err)
	}
	if err := encrypted.Close(); err != nil {
		t.Fatal(err)
	}
	return output.Bytes()
}

func mustReadFile(t *testing.T, filename string) []byte {
	t.Helper()
	content, err := os.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	return content
}

func validRestoreConfig() string {
	return `version: 1
system:
  state_dir: /var/lib/gateway-vpn
  database: /var/lib/gateway-vpn/state.db
  log_level: INFO
network:
  lan_interface: enp2s0
  lan_address: 192.168.200.1/24
  ipv6_mode: disabled
modems:
  type: hilink
  auto_discover: true
  require_adoption: true
  require_unique_management_subnets: true
  routing_table_start: 1101
  fwmark_start: 4353
mihomo:
  binary: /opt/gateway-vpn/current/libexec/mihomo
  tun_name: gateway-vpn-tun
  stack: mixed
  api_address: 127.0.0.1:9090
  probe_address: 127.0.0.1:17890
  api_secret_file: /var/lib/gateway-vpn/secrets/mihomo-api-secret
  bootstrap_dns: [1.1.1.1]
  transport_probe_url: https://cp.cloudflare.com/generate_204
  transport_probe_timeout_seconds: 8
  transport_expected_status: "204"
api:
  listen: [192.168.200.1:8443, 10.80.0.2:8443]
  tls_cert: /var/lib/gateway-vpn/tls/cert.pem
  tls_key: /var/lib/gateway-vpn/tls/key.pem
`
}
