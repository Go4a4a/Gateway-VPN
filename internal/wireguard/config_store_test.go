package wireguard

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestLoadConfigIsStrictAndSecure(t *testing.T) {
	filename := filepath.Join(t.TempDir(), "wireguard.yaml")
	content := "interface_name: wg-mgmt\naddress: 10.80.0.2/32\nprivate_key: " + testKey('a') + "\npeer_public_key: " + testKey('b') + "\nendpoint: 203.0.113.10:51821\nallowed_ips: [10.80.0.0/24]\npersistent_keepalive: 25\n"
	if err := os.WriteFile(filename, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	config, err := LoadConfig(filename)
	if err != nil || config.Endpoint != "203.0.113.10:51821" {
		t.Fatalf("LoadConfig() = %+v, %v", config, err)
	}
	if err := os.WriteFile(filename, []byte(content+"unknown: true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(filename); err == nil {
		t.Fatal("LoadConfig(unknown field) error = nil")
	}
}

func TestSaveConfigCreatesAtomicProtectedRoundTrip(t *testing.T) {
	filename := filepath.Join(t.TempDir(), "wireguard.yaml")
	expected := Config{
		InterfaceName: "wg-mgmt", Address: "10.80.0.2/32", PrivateKey: testKey('a'),
		PeerPublicKey: testKey('b'), Endpoint: "203.0.113.10:51821",
		AllowedIPs: []string{"10.80.0.0/24"}, PersistentKeepalive: 25,
	}
	if err := SaveConfig(filename, expected); err != nil {
		t.Fatalf("SaveConfig() error = %v", err)
	}
	actual, err := LoadConfig(filename)
	if err != nil || actual.Endpoint != expected.Endpoint || actual.PrivateKey != expected.PrivateKey {
		t.Fatalf("LoadConfig(saved) = %+v, %v", actual, err)
	}
	info, err := os.Lstat(filename)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || (runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0) {
		t.Fatalf("saved config mode = %v, %v", info.Mode(), err)
	}
	if matches, _ := filepath.Glob(filepath.Join(filepath.Dir(filename), ".wireguard-*.tmp")); len(matches) != 0 {
		t.Fatalf("temporary configs remain: %v", matches)
	}
}

func TestSaveConfigRejectsNonMVPPort(t *testing.T) {
	config := Config{
		InterfaceName: "wg-mgmt", Address: "10.80.0.2/32", PrivateKey: testKey('a'),
		PeerPublicKey: testKey('b'), Endpoint: "203.0.113.10:51820",
		AllowedIPs: []string{"10.80.0.0/24"}, PersistentKeepalive: 25,
	}
	if err := SaveConfig(filepath.Join(t.TempDir(), "wireguard.yaml"), config); err == nil {
		t.Fatal("SaveConfig(non-MVP port) error = nil")
	}
}

func TestHandshakeTimeoutHasSafeConfigurableBounds(t *testing.T) {
	if actual := HandshakeTimeout(Config{}); actual != 45*time.Second {
		t.Fatalf("default HandshakeTimeout() = %s", actual)
	}
	config := Config{
		InterfaceName: "wg-mgmt", Address: "10.80.0.2/32", PrivateKey: testKey('a'),
		PeerPublicKey: testKey('b'), Endpoint: "203.0.113.10:51821",
		AllowedIPs: []string{"10.80.0.0/24"}, PersistentKeepalive: 25, HandshakeTimeout: 20,
	}
	if err := ValidateConfig(config); err == nil {
		t.Fatal("ValidateConfig(short handshake timeout) error = nil")
	}
}
