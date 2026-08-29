package wgingress

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestKeyStoreKeepsWireGuardSecretsBoundedAndPrivate(t *testing.T) {
	store := KeyStore{Root: filepath.Join(t.TempDir(), "wireguard-ingress")}
	pair, err := GenerateKeyPair()
	if err != nil || !ValidKey(pair.Private) || !ValidKey(pair.Public) {
		t.Fatalf("GenerateKeyPair() = %+v, %v", pair, err)
	}
	if derived, err := PublicKey(pair.Private); err != nil || derived != pair.Public {
		t.Fatalf("PublicKey() = %q, %v", derived, err)
	}
	path, err := store.PeerPrivatePath("wgpeer-one")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Write(path, pair.Private); err != nil {
		t.Fatal(err)
	}
	if value, err := store.Read(path); err != nil || value != pair.Private {
		t.Fatalf("Read() = %q, %v", value, err)
	}
	if runtime.GOOS != "windows" {
		if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("secret mode = %v, %v", info.Mode().Perm(), err)
		}
	}
	if err := store.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := store.Remove(path); err != nil {
		t.Fatalf("Remove(missing) = %v", err)
	}
}

func TestKeyStoreRejectsEscapesInvalidKeysAndSymlinks(t *testing.T) {
	root := filepath.Join(t.TempDir(), "wireguard-ingress")
	store := KeyStore{Root: root}
	if err := store.Write(filepath.Join(filepath.Dir(root), "escape.key"), strings.Repeat("A", 44)); err == nil {
		t.Fatal("KeyStore accepted path escape")
	}
	path, _ := store.PeerPrivatePath("wgpeer-one")
	if err := store.Write(path, "not-a-key"); err == nil {
		t.Fatal("KeyStore accepted invalid key")
	}
	if runtime.GOOS == "windows" {
		return
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "target")
	if err := os.WriteFile(target, []byte("do-not-replace"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	pair, _ := GenerateKeyPair()
	if err := store.Write(path, pair.Private); err == nil {
		t.Fatal("KeyStore accepted symlink destination")
	}
}
