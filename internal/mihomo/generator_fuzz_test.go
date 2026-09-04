package mihomo

import (
	"path"
	"strings"
	"testing"

	"gateway-vpn/internal/subscription"

	"go.yaml.in/yaml/v3"
)

func FuzzGenerate(f *testing.F) {
	for _, seed := range [][]byte{
		[]byte("vless://11111111-1111-1111-1111-111111111111@proxy.example.com:443?security=tls#Bypass"),
		[]byte("proxies:\n  - {name: LTE, type: trojan, server: proxy.example.com, port: 443, password: fixture-password-not-production}\n"),
		[]byte("not a subscription"),
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, payload []byte) {
		// The importer supports larger real subscriptions; this fuzz target keeps
		// each generated Mihomo bundle bounded so the short CI smoke stays useful.
		if len(payload) > 64<<10 {
			return
		}
		imported, err := subscription.Import(payload)
		if err != nil {
			return
		}
		bundle, err := Generate(Input{
			ExternalController: "127.0.0.1:9090", ProbeListener: "127.0.0.1:17890",
			APISecret: "fixture-secret-not-production", TUNName: "gateway-vpn-tun", TUNStack: "mixed",
			LANInterface: "enp2s0", ProviderDirectory: "providers", BootstrapDNS: []string{"1.1.1.1"},
			Uplinks:       []Uplink{{ID: "uplink-a", Priority: 1, InterfaceName: "wan0", Fwmark: 0x1101, Enabled: true, Online: true}},
			Subscriptions: []Subscription{{ID: "sub-a", Priority: 1, Enabled: true, Nodes: imported.Nodes}},
		})
		if err != nil {
			t.Fatalf("sanitized subscription could not generate a bundle: %v", err)
		}
		if len(bundle.Paths) != 1 || len(bundle.Providers) != 1 || len(bundle.Main) == 0 {
			t.Fatalf("generated bundle cardinality is invalid: paths=%d providers=%d", len(bundle.Paths), len(bundle.Providers))
		}
		var main map[string]any
		if err := yaml.Unmarshal(bundle.Main, &main); err != nil {
			t.Fatalf("generated main config is not YAML: %v", err)
		}
		for filename, provider := range bundle.Providers {
			if path.IsAbs(filename) || filename != path.Clean(filename) || !strings.HasPrefix(filename, "providers/") || strings.Contains(filename, "..") {
				t.Fatalf("generated provider path is unsafe: %q", filename)
			}
			var decoded struct {
				Proxies []map[string]any `yaml:"proxies"`
			}
			if err := yaml.Unmarshal(provider, &decoded); err != nil || len(decoded.Proxies) != len(imported.Nodes) {
				t.Fatalf("generated provider is invalid: nodes=%d error=%v", len(decoded.Proxies), err)
			}
		}
	})
}
