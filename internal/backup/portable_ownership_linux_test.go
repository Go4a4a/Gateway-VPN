//go:build linux

package backup

import (
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"testing"

	databasepkg "gateway-vpn/internal/db"
)

func TestRootOwnedManagementKeyIsUnreadableToControlUIDButEncryptedInPortableBackup(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root ownership boundary requires a privileged Linux test")
	}
	setpriv, err := exec.LookPath("setpriv")
	if err != nil {
		t.Skip("setpriv is required for the cross-UID ownership assertion")
	}
	testBinary, err := exec.LookPath("test")
	if err != nil {
		t.Skip("test utility is required for the cross-UID ownership assertion")
	}
	account, err := user.Lookup("nobody")
	if err != nil {
		t.Skip("nobody account is unavailable")
	}
	uid, err := strconv.Atoi(account.Uid)
	if err != nil {
		t.Fatal(err)
	}
	group, err := user.LookupGroupId(account.Gid)
	if err != nil {
		t.Fatal(err)
	}
	gid, err := strconv.Atoi(group.Gid)
	if err != nil {
		t.Fatal(err)
	}

	root, err := os.MkdirTemp("", "gateway-vpn-backup-ownership-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	if err := os.Chmod(root, 0o755); err != nil {
		t.Fatal(err)
	}
	stateDirectory := filepath.Join(root, "state")
	if err := os.Mkdir(stateDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	databasePath := filepath.Join(stateDirectory, "state.db")
	ctx := context.Background()
	database, err := databasepkg.Open(ctx, databasepkg.OpenOptions{Path: databasePath})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if err := databasepkg.Migrate(ctx, database); err != nil {
		t.Fatal(err)
	}
	write := func(path, content string, mode os.FileMode) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), mode); err != nil {
			t.Fatal(err)
		}
	}
	normalSecret := filepath.Join(stateDirectory, "secrets", "mihomo-api-secret")
	managementRoot := filepath.Join(stateDirectory, "secrets", "management")
	managementKey := filepath.Join(managementRoot, "link-a.key")
	managementPlaintext := "root-only-management-private-key"
	write(normalSecret, "ordinary-control-secret", 0o600)
	write(managementKey, managementPlaintext, 0o600)
	write(filepath.Join(stateDirectory, "tls", "cert.pem"), "certificate", 0o600)
	write(filepath.Join(stateDirectory, "tls", "key.pem"), "tls-private", 0o600)
	configurationPath := filepath.Join(root, "config.yaml")
	write(configurationPath, "version: 1\n", 0o600)

	for _, path := range []string{stateDirectory, filepath.Join(stateDirectory, "secrets"), normalSecret} {
		if err := os.Chown(path, uid, gid); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(managementRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(managementRoot, 0, 0); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(managementKey, 0, 0); err != nil {
		t.Fatal(err)
	}
	readableAsControlUID := func(path string) error {
		return exec.Command(setpriv, "--reuid", strconv.Itoa(uid), "--regid", strconv.Itoa(gid), "--clear-groups", "--", testBinary, "-r", path).Run()
	}
	if err := readableAsControlUID(normalSecret); err != nil {
		t.Fatalf("control UID cannot read its ordinary secret: %v", err)
	}
	if err := readableAsControlUID(managementKey); err == nil {
		t.Fatal("control UID read the root-owned Management Fabric private key")
	}

	snapshots, err := NewManager(database, stateDirectory, databasePath)
	if err != nil {
		t.Fatal(err)
	}
	privilegedRoot := filepath.Join(root, "privileged-backup")
	snapshots.Root = filepath.Join(privilegedRoot, "snapshots")
	manager, err := NewPortableManager(snapshots, stateDirectory, configurationPath, "ownership-test")
	if err != nil {
		t.Fatal(err)
	}
	manager.ExportRoot = filepath.Join(privilegedRoot, "artifacts")
	manager.TransientSnapshot = true
	passphrase := "correct horse battery staple"
	artifact, err := manager.Build(ctx, passphrase)
	if err != nil {
		t.Fatal(err)
	}
	encrypted, err := os.ReadFile(artifact.Path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encrypted, []byte(managementPlaintext)) {
		t.Fatal("encrypted portable artifact exposes the Management Fabric private key")
	}
	decrypted := filepath.Join(root, "decrypted.zip")
	if _, err := DecryptToZIP(ctx, artifact.Path, decrypted, passphrase); err != nil {
		t.Fatal(err)
	}
	archive, err := zip.OpenReader(decrypted)
	if err != nil {
		t.Fatal(err)
	}
	defer archive.Close()
	found := false
	for _, entry := range archive.File {
		if entry.Name != "state/secrets/management/link-a.key" {
			continue
		}
		reader, err := entry.Open()
		if err != nil {
			t.Fatal(err)
		}
		content, readErr := io.ReadAll(reader)
		closeErr := reader.Close()
		if readErr != nil || closeErr != nil || string(content) != managementPlaintext {
			t.Fatalf("decrypted management key mismatch: %q, %v, %v", content, readErr, closeErr)
		}
		found = true
	}
	if !found {
		t.Fatal("root-built encrypted portable backup omitted the Management Fabric key")
	}
	if _, err := os.Stat(filepath.Join(snapshots.Root, artifact.SnapshotID)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("root staging snapshot remains: %v", err)
	}
}
