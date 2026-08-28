// Package config defines and validates the immutable bootstrap configuration.
package config

const CurrentVersion = 1

type Config struct {
	Version int                  `yaml:"version"`
	System  SystemConfig         `yaml:"system"`
	Network NetworkConfig        `yaml:"network"`
	Modems  ModemDiscoveryConfig `yaml:"modems"`
	Mihomo  MihomoConfig         `yaml:"mihomo"`
	API     APIConfig            `yaml:"api"`
}

type SystemConfig struct {
	StateDir string `yaml:"state_dir"`
	Database string `yaml:"database"`
	LogLevel string `yaml:"log_level"`
}

type NetworkConfig struct {
	LANInterface         string `yaml:"lan_interface"`
	LANAddress           string `yaml:"lan_address"`
	IPv6Mode             string `yaml:"ipv6_mode"`
	DisableSSHManagement bool   `yaml:"disable_ssh_management"`
}

type ModemDiscoveryConfig struct {
	Type                           string `yaml:"type"`
	AutoDiscover                   bool   `yaml:"auto_discover"`
	RequireAdoption                bool   `yaml:"require_adoption"`
	RequireUniqueManagementSubnets bool   `yaml:"require_unique_management_subnets"`
	RoutingTableStart              uint32 `yaml:"routing_table_start"`
	FwmarkStart                    uint32 `yaml:"fwmark_start"`
}

type MihomoConfig struct {
	Binary                       string   `yaml:"binary"`
	TunName                      string   `yaml:"tun_name"`
	Stack                        string   `yaml:"stack"`
	APIAddress                   string   `yaml:"api_address"`
	ProbeAddress                 string   `yaml:"probe_address"`
	APISecretFile                string   `yaml:"api_secret_file"`
	BootstrapDNS                 []string `yaml:"bootstrap_dns"`
	TransportProbeURL            string   `yaml:"transport_probe_url"`
	TransportProbeTimeoutSeconds int      `yaml:"transport_probe_timeout_seconds"`
	TransportExpectedStatus      string   `yaml:"transport_expected_status"`
}

type APIConfig struct {
	Listen  []string `yaml:"listen"`
	TLSCert string   `yaml:"tls_cert"`
	TLSKey  string   `yaml:"tls_key"`
}

func Default() Config {
	return Config{
		Version: CurrentVersion,
		System: SystemConfig{
			StateDir: "/var/lib/gateway-vpn",
			Database: "/var/lib/gateway-vpn/state.db",
			LogLevel: "INFO",
		},
		Network: NetworkConfig{
			LANInterface:         "enp2s0",
			LANAddress:           "192.168.200.1/24",
			IPv6Mode:             "disabled",
			DisableSSHManagement: false,
		},
		Modems: ModemDiscoveryConfig{
			Type:                           "hilink",
			AutoDiscover:                   true,
			RequireAdoption:                true,
			RequireUniqueManagementSubnets: true,
			RoutingTableStart:              1101,
			FwmarkStart:                    0x1101,
		},
		Mihomo: MihomoConfig{
			Binary:                       "/opt/gateway-vpn/current/libexec/mihomo",
			TunName:                      "gateway-vpn-tun",
			Stack:                        "mixed",
			APIAddress:                   "127.0.0.1:9090",
			ProbeAddress:                 "127.0.0.1:17890",
			APISecretFile:                "/var/lib/gateway-vpn/secrets/mihomo-api-secret",
			BootstrapDNS:                 []string{"1.1.1.1"},
			TransportProbeURL:            "https://cp.cloudflare.com/generate_204",
			TransportProbeTimeoutSeconds: 8,
			TransportExpectedStatus:      "204",
		},
		API: APIConfig{
			Listen: []string{
				"192.168.200.1:8443",
				"10.80.0.2:8443",
			},
			TLSCert: "/var/lib/gateway-vpn/tls/cert.pem",
			TLSKey:  "/var/lib/gateway-vpn/tls/key.pem",
		},
	}
}
