package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadStrictConfig(t *testing.T) {
	filename := writeConfig(t, validYAML())
	config, err := Load(filename)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if config.Network.LANInterface != "enp2s0" || config.Mihomo.TunName != "gateway-vpn-tun" {
		t.Fatalf("Load() config = %+v", config)
	}
}

func TestLoadRejectsUnknownDuplicateAndMultipleDocuments(t *testing.T) {
	tests := []struct {
		name    string
		content string
	}{
		{"unknown field", validYAML() + "unknown_root: true\n"},
		{"duplicate field", validYAML() + "version: 1\n"},
		{"multiple documents", validYAML() + "---\nversion: 1\n"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := Load(writeConfig(t, test.content)); err == nil {
				t.Fatal("Load() error = nil")
			}
		})
	}
}

func TestLoadRejectsUnsafeValues(t *testing.T) {
	content := strings.Replace(validYAML(), "192.168.200.1:8443", "0.0.0.0:8443", 1)
	if _, err := Load(writeConfig(t, content)); err == nil || !strings.Contains(err.Error(), "api.listen[0]") {
		t.Fatalf("Load() error = %v, want unsafe API bind error", err)
	}
}

func TestLoadRejectsOversizedFileAndSymlink(t *testing.T) {
	oversized := filepath.Join(t.TempDir(), "oversized.yaml")
	if err := os.WriteFile(oversized, []byte(strings.Repeat("x", MaxFileSize+1)), 0o600); err != nil {
		t.Fatalf("write oversized config: %v", err)
	}
	if _, err := Load(oversized); err == nil {
		t.Fatal("Load(oversized) error = nil")
	}

	target := writeConfig(t, validYAML())
	link := filepath.Join(t.TempDir(), "config-link.yaml")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if _, err := Load(link); err == nil {
		t.Fatal("Load(symlink) error = nil")
	}
}

func writeConfig(t *testing.T, content string) string {
	t.Helper()
	filename := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(filename, []byte(content), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return filename
}

func validYAML() string {
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
  api_address: 127.0.0.1:9090
  api_secret_file: /var/lib/gateway-vpn/secrets/mihomo-api-secret
api:
  listen:
    - 192.168.200.1:8443
    - 10.80.0.2:8443
  tls_cert: /var/lib/gateway-vpn/tls/cert.pem
  tls_key: /var/lib/gateway-vpn/tls/key.pem
`
}
