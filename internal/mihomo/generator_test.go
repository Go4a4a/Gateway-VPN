package mihomo

import (
	"strings"
	"testing"

	"gateway-vpn/internal/subscription"

	"go.yaml.in/yaml/v3"
)

func TestGenerateCreatesProviderAndGroupPerPath(t *testing.T) {
	node := importedNode(t)
	bundle, err := Generate(Input{
		ExternalController: "127.0.0.1:9090",
		ProbeListener:      "127.0.0.1:17890",
		APISecret:          "test-secret",
		TUNName:            "gateway-vpn-tun",
		TUNStack:           "mixed",
		LANInterface:       "enp2s0",
		ProviderDirectory:  "providers",
		BootstrapDNS:       []string{"1.1.1.1"},
		Modems: []Modem{
			{ID: "modem-b", Priority: 20, InterfaceName: "enx0002", Fwmark: 0x1102, Enabled: true, Online: true},
			{ID: "modem-a", Priority: 10, InterfaceName: "enx0001", Fwmark: 0x1101, Enabled: true, Online: true},
		},
		Subscriptions: []Subscription{{ID: "sub-a", Priority: 10, Enabled: true, Nodes: []subscription.ImportedNode{node}}},
	})
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}
	if len(bundle.Paths) != 2 || len(bundle.Providers) != 2 {
		t.Fatalf("bundle paths/providers = %d/%d", len(bundle.Paths), len(bundle.Providers))
	}
	if bundle.Paths[0].ModemID != "modem-a" || bundle.Paths[1].ModemID != "modem-b" {
		t.Fatalf("path order = %+v", bundle.Paths)
	}

	var decoded struct {
		ProxyProviders map[string]providerConfig `yaml:"proxy-providers"`
		ProxyGroups    []proxyGroup              `yaml:"proxy-groups"`
		Listeners      []listenerConfig          `yaml:"listeners"`
		Rules          []string                  `yaml:"rules"`
	}
	if err := yaml.Unmarshal(bundle.Main, &decoded); err != nil {
		t.Fatalf("decode generated main config: %v", err)
	}
	if len(decoded.ProxyProviders) != 2 || len(decoded.ProxyGroups) != 6 {
		t.Fatalf("main providers/groups = %d/%d", len(decoded.ProxyProviders), len(decoded.ProxyGroups))
	}
	active := findProxyGroup(t, decoded.ProxyGroups, ActiveGroupName)
	if active.Name != ActiveGroupName || len(active.Proxies) != 3 || active.Proxies[0] != "REJECT" {
		t.Fatalf("active group = %+v", active)
	}
	firstProvider := decoded.ProxyProviders[bundle.Paths[0].ProviderName]
	if firstProvider.Override.InterfaceName != "enx0001" || firstProvider.Override.RoutingMark != 0x1101 {
		t.Fatalf("first provider override = %+v", firstProvider.Override)
	}
	if !strings.HasPrefix(firstProvider.Path, "providers/") || strings.Contains(firstProvider.Path, "..") {
		t.Fatalf("unsafe provider path %q", firstProvider.Path)
	}
	if decoded.Rules[0] != "MATCH,"+ActiveGroupName {
		t.Fatalf("rules = %+v", decoded.Rules)
	}
	probe := findProxyGroup(t, decoded.ProxyGroups, ProbeGroupName)
	if len(probe.Proxies) != 2 || len(decoded.Listeners) != 1 || decoded.Listeners[0].Listen != "127.0.0.1" || decoded.Listeners[0].Port != 17890 || decoded.Listeners[0].Proxy != ProbeGroupName {
		t.Fatalf("probe group/listener = %+v / %+v", probe, decoded.Listeners)
	}
	if bundle.Paths[0].ProbeGroupName == bundle.Paths[0].GroupName || probe.Proxies[0] != bundle.Paths[0].ProbeGroupName {
		t.Fatalf("probe path is not isolated from active path: %+v / %+v", bundle.Paths[0], probe)
	}
}

func TestGenerateExcludesOfflineAndDisabledPaths(t *testing.T) {
	node := importedNode(t)
	bundle, err := Generate(Input{
		ExternalController: "127.0.0.1:9090", ProbeListener: "127.0.0.1:17890", APISecret: "secret", TUNName: "gateway-vpn-tun", TUNStack: "mixed", LANInterface: "enp2s0", ProviderDirectory: "providers", BootstrapDNS: []string{"1.1.1.1"},
		Modems: []Modem{
			{ID: "online", Priority: 10, InterfaceName: "enx1", Fwmark: 1, Enabled: true, Online: true},
			{ID: "offline", Priority: 20, InterfaceName: "enx2", Fwmark: 2, Enabled: true, Online: false},
		},
		Subscriptions: []Subscription{{ID: "enabled", Enabled: true, Nodes: []subscription.ImportedNode{node}}, {ID: "disabled", Enabled: false, Nodes: []subscription.ImportedNode{node}}},
	})
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}
	if len(bundle.Paths) != 1 || bundle.Paths[0].ModemID != "online" || bundle.Paths[0].SubscriptionID != "enabled" {
		t.Fatalf("generated paths = %+v", bundle.Paths)
	}
}

func TestGenerateKeepsQualificationShadowOutOfActiveGroup(t *testing.T) {
	node := importedNode(t)
	bundle, err := Generate(Input{
		ExternalController: "127.0.0.1:9090",
		ProbeListener:      "127.0.0.1:17890",
		APISecret:          "secret",
		TUNName:            "gateway-vpn-tun",
		TUNStack:           "mixed",
		LANInterface:       "enp2s0",
		ProviderDirectory:  "providers",
		BootstrapDNS:       []string{"1.1.1.1"},
		Modems: []Modem{{
			ID: "modem-a", Priority: 10, InterfaceName: "enx1", Fwmark: 1, Enabled: true, Online: true,
		}},
		Subscriptions: []Subscription{
			{ID: "sub-a", RuntimeKey: "sub-a-active", Priority: 10, Enabled: true, Nodes: []subscription.ImportedNode{node}},
			{ID: "sub-a", RuntimeKey: "sub-a-candidate-v2", Priority: 10, Enabled: true, QualificationOnly: true, Nodes: []subscription.ImportedNode{node}},
		},
	})
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}
	if len(bundle.Paths) != 2 || len(bundle.Providers) != 2 {
		t.Fatalf("bundle paths/providers = %d/%d", len(bundle.Paths), len(bundle.Providers))
	}
	activePath, shadowPath := bundle.Paths[0], bundle.Paths[1]
	if activePath.QualificationOnly || !shadowPath.QualificationOnly {
		t.Fatalf("qualification flags = %t/%t", activePath.QualificationOnly, shadowPath.QualificationOnly)
	}
	if activePath.SubscriptionID != shadowPath.SubscriptionID || activePath.RuntimeKey == shadowPath.RuntimeKey {
		t.Fatalf("logical/runtime identities = %+v / %+v", activePath, shadowPath)
	}
	if activePath.ProviderName == shadowPath.ProviderName || activePath.GroupName == shadowPath.GroupName || activePath.NodePrefix == shadowPath.NodePrefix {
		t.Fatalf("shadow names must be isolated: %+v / %+v", activePath, shadowPath)
	}

	var decoded struct {
		ProxyProviders map[string]providerConfig `yaml:"proxy-providers"`
		ProxyGroups    []proxyGroup              `yaml:"proxy-groups"`
	}
	if err := yaml.Unmarshal(bundle.Main, &decoded); err != nil {
		t.Fatalf("decode generated main config: %v", err)
	}
	if len(decoded.ProxyProviders) != 2 || len(decoded.ProxyGroups) != 6 {
		t.Fatalf("main providers/groups = %d/%d", len(decoded.ProxyProviders), len(decoded.ProxyGroups))
	}
	active := findProxyGroup(t, decoded.ProxyGroups, ActiveGroupName)
	if len(active.Proxies) != 2 || active.Proxies[0] != "REJECT" || active.Proxies[1] != activePath.GroupName {
		t.Fatalf("active group = %+v", active)
	}
	for _, choice := range active.Proxies {
		if choice == shadowPath.GroupName {
			t.Fatalf("qualification-only shadow leaked into active group: %+v", active)
		}
	}
	probe := findProxyGroup(t, decoded.ProxyGroups, ProbeGroupName)
	if len(probe.Proxies) != 2 || probe.Proxies[0] != activePath.ProbeGroupName || probe.Proxies[1] != shadowPath.ProbeGroupName {
		t.Fatalf("probe group must contain active and shadow paths: %+v", probe)
	}
}

func TestGenerateRejectsUnsafeProviderDirectoryAndEmptyPaths(t *testing.T) {
	base := Input{ExternalController: "127.0.0.1:9090", ProbeListener: "127.0.0.1:17890", APISecret: "secret", TUNName: "gateway-vpn-tun", TUNStack: "mixed", LANInterface: "enp2s0", ProviderDirectory: "../providers", BootstrapDNS: []string{"1.1.1.1"}}
	if _, err := Generate(base); err == nil {
		t.Fatal("Generate(unsafe path) error = nil")
	}
	base.ProviderDirectory = "providers"
	if _, err := Generate(base); err == nil {
		t.Fatal("Generate(no paths) error = nil")
	}
}

func TestStablePathNamesMatchNormalGeneratedPath(t *testing.T) {
	names, err := StablePathNames("modem-a", "sub-a")
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := Generate(Input{
		ExternalController: "127.0.0.1:9090", ProbeListener: "127.0.0.1:17890", APISecret: "secret", TUNName: "gateway-vpn-tun", TUNStack: "mixed", LANInterface: "enp2s0", ProviderDirectory: "providers", BootstrapDNS: []string{"1.1.1.1"},
		Modems:        []Modem{{ID: "modem-a", InterfaceName: "enx1", Fwmark: 1, Enabled: true, Online: true}},
		Subscriptions: []Subscription{{ID: "sub-a", Enabled: true, Nodes: []subscription.ImportedNode{importedNode(t)}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	path := bundle.Paths[0]
	if names.ProviderName != path.ProviderName || names.GroupName != path.GroupName || names.ProbeGroupName != path.ProbeGroupName || names.NodePrefix != path.NodePrefix {
		t.Fatalf("stable/generated names = %+v / %+v", names, path)
	}
}

func findProxyGroup(t *testing.T, groups []proxyGroup, name string) proxyGroup {
	t.Helper()
	for _, group := range groups {
		if group.Name == name {
			return group
		}
	}
	t.Fatalf("proxy group %s not found in %+v", name, groups)
	return proxyGroup{}
}

func importedNode(t *testing.T) subscription.ImportedNode {
	t.Helper()
	result, err := subscription.Import([]byte("vless://11111111-1111-1111-1111-111111111111@proxy.example.com:443?security=tls#Bypass"))
	if err != nil {
		t.Fatalf("subscription.Import() error = %v", err)
	}
	return result.Nodes[0]
}
