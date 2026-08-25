package config

import (
	"strings"
	"testing"
)

func TestDefaultIsValid(t *testing.T) {
	if err := Default().Validate(); err != nil {
		t.Fatalf("Default().Validate() error = %v", err)
	}
}

func TestValidateRejectsUnsafeBootstrapConfig(t *testing.T) {
	tests := []struct {
		name      string
		mutate    func(*Config)
		wantField string
	}{
		{
			name: "unsupported version",
			mutate: func(config *Config) {
				config.Version = CurrentVersion + 1
			},
			wantField: "version",
		},
		{
			name: "permanent bootstrap debug is forbidden",
			mutate: func(config *Config) {
				config.System.LogLevel = "DEBUG"
			},
			wantField: "system.log_level",
		},
		{
			name: "database outside state directory",
			mutate: func(config *Config) {
				config.System.Database = "/srv/gateway-vpn/state.db"
			},
			wantField: "system.database",
		},
		{
			name: "invalid LAN prefix",
			mutate: func(config *Config) {
				config.Network.LANAddress = "not-a-prefix"
			},
			wantField: "network.lan_address",
		},
		{
			name: "public LAN prefix",
			mutate: func(config *Config) {
				config.Network.LANAddress = "8.8.8.8/24"
			},
			wantField: "network.lan_address",
		},
		{
			name: "LAN network address is not a host",
			mutate: func(config *Config) {
				config.Network.LANAddress = "192.168.200.0/24"
			},
			wantField: "network.lan_address",
		},
		{
			name: "IPv6 cannot be enabled in MVP",
			mutate: func(config *Config) {
				config.Network.IPv6Mode = "enabled"
			},
			wantField: "network.ipv6_mode",
		},
		{
			name: "ambiguous modem adoption is forbidden",
			mutate: func(config *Config) {
				config.Modems.RequireAdoption = false
			},
			wantField: "modems.require_adoption",
		},
		{
			name: "Mihomo API cannot listen on LAN",
			mutate: func(config *Config) {
				config.Mihomo.APIAddress = "192.168.200.1:9090"
			},
			wantField: "mihomo.api_address",
		},
		{
			name: "unsupported Mihomo TUN stack",
			mutate: func(config *Config) {
				config.Mihomo.Stack = "magic"
			},
			wantField: "mihomo.stack",
		},
		{
			name: "duplicate bootstrap DNS",
			mutate: func(config *Config) {
				config.Mihomo.BootstrapDNS = []string{"1.1.1.1", "1.1.1.1"}
			},
			wantField: "mihomo.bootstrap_dns[1]",
		},
		{
			name: "local transport probe",
			mutate: func(config *Config) {
				config.Mihomo.TransportProbeURL = "https://127.0.0.1/health"
			},
			wantField: "mihomo.transport_probe_url",
		},
		{
			name: "Gateway API cannot bind wildcard",
			mutate: func(config *Config) {
				config.API.Listen = []string{"0.0.0.0:8443"}
			},
			wantField: "api.listen[0]",
		},
		{
			name: "duplicate API address",
			mutate: func(config *Config) {
				config.API.Listen = []string{"10.80.0.2:8443", "10.80.0.2:8443"}
			},
			wantField: "api.listen[1]",
		},
		{
			name: "relative secret path",
			mutate: func(config *Config) {
				config.Mihomo.APISecretFile = "secrets/mihomo"
			},
			wantField: "mihomo.api_secret_file",
		},
		{
			name: "arbitrary root executable is forbidden",
			mutate: func(config *Config) {
				config.Mihomo.Binary = "/tmp/attacker-controlled-mihomo"
			},
			wantField: "mihomo.binary",
		},
		{
			name: "secret outside fixed state path is forbidden",
			mutate: func(config *Config) {
				config.Mihomo.APISecretFile = "/etc/shadow"
			},
			wantField: "mihomo.api_secret_file",
		},
		{
			name: "TLS key outside fixed state path is forbidden",
			mutate: func(config *Config) {
				config.API.TLSKey = "/etc/gateway-vpn/private.key"
			},
			wantField: "api.tls_key",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := Default()
			test.mutate(&config)
			err := config.Validate()
			if err == nil {
				t.Fatal("Validate() error = nil, want validation error")
			}
			if !strings.Contains(err.Error(), test.wantField) {
				t.Fatalf("Validate() error = %q, want field %q", err, test.wantField)
			}
		})
	}
}

func TestValidateReturnsAllErrors(t *testing.T) {
	config := Default()
	config.Version = 0
	config.Network.IPv6Mode = "enabled"
	config.Mihomo.APIAddress = "192.168.200.1:9090"

	err := config.Validate()
	if err == nil {
		t.Fatal("Validate() error = nil, want validation errors")
	}
	for _, field := range []string{"version", "network.ipv6_mode", "mihomo.api_address"} {
		if !strings.Contains(err.Error(), field) {
			t.Errorf("Validate() error = %q, missing field %q", err, field)
		}
	}
}
