package wireguard

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDeployKeyLifecycleKeepsPrivateKeyLocal(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(directory, "wireguard.yaml")
	pendingPath := filepath.Join(directory, ".deploy-wireguard.key")
	prepared, err := PrepareDeployKey(configPath, pendingPath)
	if err != nil {
		t.Fatal(err)
	}
	if prepared.State != "PENDING" || !validKey(prepared.PublicKey) {
		t.Fatalf("unexpected prepared state: %+v", prepared)
	}
	inspected, err := InspectDeployKey(configPath, pendingPath)
	if err != nil || inspected != prepared {
		t.Fatalf("read-only pending inspection mismatch: %+v %v", inspected, err)
	}
	content, err := os.ReadFile(pendingPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) == prepared.PublicKey+"\n" {
		t.Fatal("pending file contains the public rather than private key")
	}
	peer := testKey('p')
	finalized, err := FinalizeDeployKey(DeployFinalizeOptions{
		ConfigPath: configPath, PendingKeyPath: pendingPath, PeerPublicKey: peer,
		Endpoint: "203.0.113.10:51821", KeepaliveSeconds: 25, HandshakeSeconds: 45,
	})
	if err != nil {
		t.Fatal(err)
	}
	if finalized.State != "CONFIGURED" || finalized.PublicKey != prepared.PublicKey {
		t.Fatalf("unexpected finalized state: %+v", finalized)
	}
	if _, err := os.Lstat(pendingPath); !os.IsNotExist(err) {
		t.Fatal("pending private key was not removed")
	}
	configuration, err := LoadConfig(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if configuration.PeerPublicKey != peer || configuration.Endpoint != "203.0.113.10:51821" {
		t.Fatalf("unexpected stored config: %+v", configuration)
	}

	repeated, err := PrepareDeployKey(configPath, pendingPath)
	if err != nil || repeated.State != "CONFIGURED" || repeated.PublicKey != prepared.PublicKey {
		t.Fatalf("prepare is not idempotent: %+v %v", repeated, err)
	}
	inspected, err = InspectDeployKey(configPath, pendingPath)
	if err != nil || inspected.State != "CONFIGURED" || inspected.PublicKey != prepared.PublicKey {
		t.Fatalf("read-only configured inspection mismatch: %+v %v", inspected, err)
	}
	if _, err := FinalizeDeployKey(DeployFinalizeOptions{
		ConfigPath: configPath, PendingKeyPath: pendingPath, PeerPublicKey: peer,
		Endpoint: "203.0.113.10:51821", KeepaliveSeconds: 25, HandshakeSeconds: 45,
	}); err != nil {
		t.Fatalf("finalize is not idempotent: %v", err)
	}
}

func TestInspectDeployKeyDoesNotCreateMaterial(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(directory, "wireguard.yaml")
	pendingPath := filepath.Join(directory, ".deploy-wireguard.key")
	state, err := InspectDeployKey(configPath, pendingPath)
	if err != nil || state.State != "UNCONFIGURED" || state.PublicKey != "" {
		t.Fatalf("unexpected empty inspection: %+v %v", state, err)
	}
	if _, err := os.Lstat(pendingPath); !os.IsNotExist(err) {
		t.Fatal("read-only inspection created pending material")
	}
}

func TestDeployKeyRefusesUnsafePendingAndConfigReplacement(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(directory, "wireguard.yaml")
	pendingPath := filepath.Join(directory, ".deploy-wireguard.key")
	if err := os.WriteFile(pendingPath, []byte("not-a-key\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := PrepareDeployKey(configPath, pendingPath); err == nil {
		t.Fatal("invalid pending key accepted")
	}
	if err := os.Remove(pendingPath); err != nil {
		t.Fatal(err)
	}
	prepared, err := PrepareDeployKey(configPath, pendingPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := FinalizeDeployKey(DeployFinalizeOptions{
		ConfigPath: configPath, PendingKeyPath: pendingPath, PeerPublicKey: testKey('q'),
		Endpoint: "203.0.113.10:51821", KeepaliveSeconds: 25, HandshakeSeconds: 45,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := FinalizeDeployKey(DeployFinalizeOptions{
		ConfigPath: configPath, PendingKeyPath: pendingPath, PeerPublicKey: testKey('r'),
		Endpoint: "203.0.113.10:51821", KeepaliveSeconds: 25, HandshakeSeconds: 45,
	}); err == nil {
		t.Fatal("incompatible existing config was overwritten")
	}
	if prepared.PublicKey == "" {
		t.Fatal("missing prepared public key")
	}
}

func TestDeployKeyRefusesSymlinkPendingFile(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(directory, "target")
	if err := os.WriteFile(target, []byte(testKey('s')+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	pending := filepath.Join(directory, ".deploy-wireguard.key")
	if err := os.Symlink(target, pending); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if _, err := PrepareDeployKey(filepath.Join(directory, "wireguard.yaml"), pending); err == nil {
		t.Fatal("symlink pending key accepted")
	}
}
