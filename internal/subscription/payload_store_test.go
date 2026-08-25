package subscription

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNormalizedPayloadRoundTripAndImmutability(t *testing.T) {
	imported, err := Import([]byte("vless://11111111-1111-1111-1111-111111111111@one.example:443#LTE%20one"))
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(t.TempDir(), "subscriptions")
	filename, err := WriteNormalizedPayload(root, "sub-a", "version-1", imported)
	if err != nil {
		t.Fatalf("WriteNormalizedPayload() error = %v", err)
	}
	loaded, err := LoadNormalizedPayload(root, "sub-a", "version-1")
	if err != nil {
		t.Fatalf("LoadNormalizedPayload() error = %v", err)
	}
	if len(loaded.Nodes) != 1 || loaded.Nodes[0].Fingerprint != imported.Nodes[0].Fingerprint || loaded.Nodes[0].ExternalName != "LTE one" {
		t.Fatalf("loaded payload = %+v", loaded)
	}
	if _, err := WriteNormalizedPayload(root, "sub-a", "version-1", imported); err == nil {
		t.Fatal("second WriteNormalizedPayload() error = nil")
	}
	if info, err := os.Stat(filename); err != nil || !info.Mode().IsRegular() {
		t.Fatalf("payload file = %v, %v", info, err)
	}
	if err := DeleteSubscriptionPayloads(root, "sub-a"); err != nil {
		t.Fatalf("DeleteSubscriptionPayloads() error = %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "sub-a")); !os.IsNotExist(err) {
		t.Fatalf("subscription payload directory remains: %v", err)
	}
}

func TestNormalizedPayloadRejectsTraversalAndSymlink(t *testing.T) {
	imported, err := Import([]byte("vless://11111111-1111-1111-1111-111111111111@one.example:443#one"))
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(t.TempDir(), "subscriptions")
	if _, err := WriteNormalizedPayload(root, "../outside", "version-1", imported); err == nil {
		t.Fatal("WriteNormalizedPayload(traversal) error = nil")
	}
	filename, err := WriteNormalizedPayload(root, "sub-a", "version-1", imported)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filename); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "target.yaml")
	if err := os.WriteFile(target, []byte("proxies: []\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filename); err != nil {
		t.Skipf("symlink not available: %v", err)
	}
	if _, err := LoadNormalizedPayload(root, "sub-a", "version-1"); err == nil {
		t.Fatal("LoadNormalizedPayload(symlink) error = nil")
	}
}
