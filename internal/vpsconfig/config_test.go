package vpsconfig

import (
	"os"
	"path/filepath"
	"testing"
)

func TestVPSConfigAllowsOnlyLoopbackOrExplicitAdminPrefix(t *testing.T) {
	configuration := Default()
	if err := configuration.Validate(); err != nil {
		t.Fatal(err)
	}
	configuration.Listen = []string{"0.0.0.0:9443"}
	if err := configuration.Validate(); err == nil {
		t.Fatal("wildcard public listener was accepted")
	}
	configuration.Listen = []string{"192.168.1.20:9443"}
	if err := configuration.Validate(); err == nil {
		t.Fatal("LAN listener outside admin prefix was accepted")
	}
	configuration.Listen = []string{"10.84.0.1:9443", "127.0.0.1:9443"}
	if err := configuration.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestVPSConfigLoadIsStrictAndRoleBounded(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vps.yaml")
	content := `version: 1
system:
  state_directory: /var/lib/gateway-vpn-vps/agent
  database: /var/lib/gateway-vpn-vps/agent/vps-agent.db
  transaction_root: /var/lib/gateway-vpn-vps-privileged/restore-transactions
listen: [127.0.0.1:9443, 10.84.0.1:9443]
admin_prefixes: [10.84.0.0/24]
tls:
  certificate: /var/lib/gateway-vpn-vps/agent/tls/cert.pem
  private_key: /var/lib/gateway-vpn-vps/agent/tls/key.pem
`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	if loaded, err := Load(path); err != nil || len(loaded.Listen) != 2 {
		t.Fatalf("Load() = %+v, %v", loaded, err)
	}
	if err := os.WriteFile(path, []byte(content+"unknown_field: true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("unknown VPS Agent config field was accepted")
	}
}
