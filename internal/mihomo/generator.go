// Package mihomo generates the single-process runtime configuration and local
// provider files.
package mihomo

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"path"
	"sort"
	"strings"

	"gateway-vpn/internal/subscription"

	"go.yaml.in/yaml/v3"
)

const (
	ActiveGroupName     = "gateway-vpn-active"
	ProbeGroupName      = "gateway-vpn-probe"
	ProbeListenerName   = "gateway-vpn-probe-in"
	MaxGeneratedProxies = 20000
)

type Input struct {
	ExternalController string
	ProbeListener      string
	APISecret          string
	TUNName            string
	TUNStack           string
	LANInterface       string
	ProviderDirectory  string
	BootstrapDNS       []string
	Modems             []Modem
	Subscriptions      []Subscription
}

type Modem struct {
	ID            string
	Priority      int64
	InterfaceName string
	Fwmark        uint32
	Enabled       bool
	Online        bool
}

type Subscription struct {
	ID                string
	RuntimeKey        string
	Priority          int64
	Enabled           bool
	QualificationOnly bool
	Nodes             []subscription.ImportedNode
}

type Path struct {
	ModemID           string
	SubscriptionID    string
	RuntimeKey        string
	ProviderName      string
	ProviderFile      string
	GroupName         string
	ProbeGroupName    string
	NodePrefix        string
	QualificationOnly bool
}

type Bundle struct {
	Main      []byte
	Providers map[string][]byte
	Paths     []Path
}

type PathNames struct {
	ProviderName   string
	GroupName      string
	ProbeGroupName string
	NodePrefix     string
}

// StablePathNames returns the deterministic names used by a normal active
// modem × subscription path. Candidate shadow paths intentionally use a
// different runtime key and are not returned by this helper.
func StablePathNames(modemID, subscriptionID string) (PathNames, error) {
	if strings.TrimSpace(modemID) == "" || strings.TrimSpace(subscriptionID) == "" {
		return PathNames{}, errors.New("modem and subscription ids are required")
	}
	modemKey := shortID(modemID)
	subscriptionKey := shortID(subscriptionID)
	return PathNames{
		ProviderName:   "provider-" + modemKey + "-" + subscriptionKey,
		GroupName:      "path-" + modemKey + "-" + subscriptionKey,
		ProbeGroupName: "probe-path-" + modemKey + "-" + subscriptionKey,
		NodePrefix:     modemKey + "/" + subscriptionKey + "/",
	}, nil
}

func Generate(input Input) (Bundle, error) {
	if err := validateInput(input); err != nil {
		return Bundle{}, err
	}
	modems := append([]Modem(nil), input.Modems...)
	sort.SliceStable(modems, func(i, j int) bool { return modems[i].Priority < modems[j].Priority })
	subscriptions := append([]Subscription(nil), input.Subscriptions...)
	sort.SliceStable(subscriptions, func(i, j int) bool { return subscriptions[i].Priority < subscriptions[j].Priority })

	probeAddress, _ := netip.ParseAddrPort(input.ProbeListener)
	configuration := mainConfig{
		IPv6:               false,
		Mode:               "rule",
		AllowLAN:           false,
		LogLevel:           "warning",
		ExternalController: input.ExternalController,
		Secret:             input.APISecret,
		TUN: tunConfig{
			Enable:              true,
			Stack:               input.TUNStack,
			Device:              input.TUNName,
			AutoRoute:           true,
			AutoRedirect:        true,
			AutoDetectInterface: false,
			DNSHijack:           []string{"any:53", "tcp://any:53"},
			StrictRoute:         true,
			IncludeInterface:    []string{input.LANInterface},
		},
		DNS: dnsConfig{
			Enable:                true,
			Listen:                "127.0.0.1:1053",
			IPv6:                  false,
			EnhancedMode:          "fake-ip",
			FakeIPRange:           "198.18.0.1/16",
			RespectRules:          true,
			DefaultNameserver:     append([]string(nil), input.BootstrapDNS...),
			ProxyServerNameserver: append([]string(nil), input.BootstrapDNS...),
			Nameserver:            []string{"https://1.1.1.1/dns-query"},
		},
		ProxyProviders: make(map[string]providerConfig),
		Listeners: []listenerConfig{{
			Name: ProbeListenerName, Type: "mixed", Listen: probeAddress.Addr().String(),
			Port: int(probeAddress.Port()), UDP: false, Proxy: ProbeGroupName,
		}},
	}
	bundle := Bundle{Providers: make(map[string][]byte)}
	activeChoices := []string{"REJECT"}
	probeChoices := make([]string, 0)
	generatedProxies := 0
	for _, modem := range modems {
		if !modem.Enabled || !modem.Online {
			continue
		}
		for _, currentSubscription := range subscriptions {
			if !currentSubscription.Enabled || len(currentSubscription.Nodes) == 0 {
				continue
			}
			generatedProxies += len(currentSubscription.Nodes)
			if generatedProxies > MaxGeneratedProxies {
				return Bundle{}, fmt.Errorf("generated proxy count exceeds hard limit %d", MaxGeneratedProxies)
			}
			modemKey := shortID(modem.ID)
			runtimeKey := currentSubscription.RuntimeKey
			if runtimeKey == "" {
				runtimeKey = currentSubscription.ID
			}
			subscriptionKey := shortID(runtimeKey)
			providerName := "provider-" + modemKey + "-" + subscriptionKey
			groupName := "path-" + modemKey + "-" + subscriptionKey
			probeGroupName := "probe-" + groupName
			providerFile := path.Join(input.ProviderDirectory, providerName+".yaml")
			configuration.ProxyProviders[providerName] = providerConfig{
				Type:        "file",
				Path:        providerFile,
				HealthCheck: providerHealthCheck{Enable: false},
				Override: providerOverride{
					AdditionalPrefix: modemKey + "/" + subscriptionKey + "/",
					InterfaceName:    modem.InterfaceName,
					RoutingMark:      modem.Fwmark,
				},
			}
			providerPayload := struct {
				Proxies []map[string]any `yaml:"proxies"`
			}{Proxies: make([]map[string]any, 0, len(currentSubscription.Nodes))}
			for _, node := range currentSubscription.Nodes {
				providerPayload.Proxies = append(providerPayload.Proxies, cloneMap(node.Config))
			}
			encodedProvider, err := yaml.Marshal(providerPayload)
			if err != nil {
				return Bundle{}, fmt.Errorf("encode provider %s: %w", providerName, err)
			}
			bundle.Providers[providerFile] = encodedProvider
			configuration.ProxyGroups = append(configuration.ProxyGroups, proxyGroup{Name: groupName, Type: "select", Use: []string{providerName}})
			configuration.ProxyGroups = append(configuration.ProxyGroups, proxyGroup{Name: probeGroupName, Type: "select", Use: []string{providerName}})
			probeChoices = append(probeChoices, probeGroupName)
			if !currentSubscription.QualificationOnly {
				activeChoices = append(activeChoices, groupName)
			}
			bundle.Paths = append(bundle.Paths, Path{ModemID: modem.ID, SubscriptionID: currentSubscription.ID, RuntimeKey: runtimeKey, ProviderName: providerName, ProviderFile: providerFile, GroupName: groupName, ProbeGroupName: probeGroupName, NodePrefix: modemKey + "/" + subscriptionKey + "/", QualificationOnly: currentSubscription.QualificationOnly})
		}
	}
	if len(bundle.Paths) == 0 {
		return Bundle{}, errors.New("no enabled online modem/subscription path can be generated")
	}
	configuration.ProxyGroups = append(configuration.ProxyGroups, proxyGroup{Name: ActiveGroupName, Type: "select", Proxies: activeChoices})
	configuration.ProxyGroups = append(configuration.ProxyGroups, proxyGroup{Name: ProbeGroupName, Type: "select", Proxies: probeChoices})
	configuration.Rules = []string{"MATCH," + ActiveGroupName}
	encodedMain, err := yaml.Marshal(configuration)
	if err != nil {
		return Bundle{}, fmt.Errorf("encode Mihomo main config: %w", err)
	}
	bundle.Main = encodedMain
	return bundle, nil
}

func validateInput(input Input) error {
	if input.ExternalController == "" || input.APISecret == "" {
		return errors.New("Mihomo controller address and secret are required")
	}
	probeAddress, err := netip.ParseAddrPort(input.ProbeListener)
	if err != nil || !probeAddress.Addr().IsLoopback() || probeAddress.Port() == 0 {
		return errors.New("Mihomo probe listener must be a numeric loopback address with a port")
	}
	controllerAddress, err := netip.ParseAddrPort(input.ExternalController)
	if err == nil && controllerAddress == probeAddress {
		return errors.New("Mihomo controller and probe listener must use different addresses")
	}
	if !validInterfaceName(input.TUNName) || !validInterfaceName(input.LANInterface) {
		return errors.New("Mihomo TUN and LAN interface names must be valid")
	}
	if !oneOf(input.TUNStack, "mixed", "system", "gvisor") {
		return errors.New("Mihomo TUN stack must be mixed, system, or gvisor")
	}
	if input.ProviderDirectory == "" || path.IsAbs(input.ProviderDirectory) || strings.Contains(input.ProviderDirectory, "..") {
		return errors.New("Mihomo provider directory must be a safe relative path below HomeDir")
	}
	if len(input.BootstrapDNS) == 0 {
		return errors.New("at least one bootstrap DNS server is required")
	}
	seenModems := make(map[string]struct{})
	for _, modem := range input.Modems {
		if modem.ID == "" || !validInterfaceName(modem.InterfaceName) || modem.Fwmark == 0 {
			return errors.New("Mihomo modem id, interface, and fwmark are required")
		}
		if _, exists := seenModems[modem.ID]; exists {
			return fmt.Errorf("duplicate Mihomo modem id %q", modem.ID)
		}
		seenModems[modem.ID] = struct{}{}
	}
	seenRuntimeKeys := make(map[string]struct{})
	activeSubscriptions := make(map[string]struct{})
	for _, currentSubscription := range input.Subscriptions {
		if currentSubscription.ID == "" {
			return errors.New("Mihomo subscription id is required")
		}
		runtimeKey := currentSubscription.RuntimeKey
		if runtimeKey == "" {
			runtimeKey = currentSubscription.ID
		}
		if _, exists := seenRuntimeKeys[runtimeKey]; exists {
			return fmt.Errorf("duplicate Mihomo subscription runtime key %q", runtimeKey)
		}
		seenRuntimeKeys[runtimeKey] = struct{}{}
		if !currentSubscription.QualificationOnly {
			if _, exists := activeSubscriptions[currentSubscription.ID]; exists {
				return fmt.Errorf("duplicate active Mihomo subscription id %q", currentSubscription.ID)
			}
			activeSubscriptions[currentSubscription.ID] = struct{}{}
		}
	}
	return nil
}

func shortID(value string) string {
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:6])
}

func cloneMap(source map[string]any) map[string]any {
	result := make(map[string]any, len(source))
	for key, value := range source {
		result[key] = value
	}
	return result
}

func validInterfaceName(value string) bool {
	if value == "" || len(value) > 15 {
		return false
	}
	for _, char := range value {
		if (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') || (char >= '0' && char <= '9') {
			continue
		}
		switch char {
		case '_', '-', '.', ':':
			continue
		default:
			return false
		}
	}
	return true
}

func oneOf(value string, allowed ...string) bool {
	for _, candidate := range allowed {
		if value == candidate {
			return true
		}
	}
	return false
}

type mainConfig struct {
	IPv6               bool                      `yaml:"ipv6"`
	Mode               string                    `yaml:"mode"`
	AllowLAN           bool                      `yaml:"allow-lan"`
	LogLevel           string                    `yaml:"log-level"`
	ExternalController string                    `yaml:"external-controller"`
	Secret             string                    `yaml:"secret"`
	TUN                tunConfig                 `yaml:"tun"`
	DNS                dnsConfig                 `yaml:"dns"`
	ProxyProviders     map[string]providerConfig `yaml:"proxy-providers"`
	ProxyGroups        []proxyGroup              `yaml:"proxy-groups"`
	Listeners          []listenerConfig          `yaml:"listeners"`
	Rules              []string                  `yaml:"rules"`
}

type tunConfig struct {
	Enable              bool     `yaml:"enable"`
	Stack               string   `yaml:"stack"`
	Device              string   `yaml:"device"`
	AutoRoute           bool     `yaml:"auto-route"`
	AutoRedirect        bool     `yaml:"auto-redirect"`
	AutoDetectInterface bool     `yaml:"auto-detect-interface"`
	DNSHijack           []string `yaml:"dns-hijack"`
	StrictRoute         bool     `yaml:"strict-route"`
	IncludeInterface    []string `yaml:"include-interface"`
}

type dnsConfig struct {
	Enable                bool     `yaml:"enable"`
	Listen                string   `yaml:"listen"`
	IPv6                  bool     `yaml:"ipv6"`
	EnhancedMode          string   `yaml:"enhanced-mode"`
	FakeIPRange           string   `yaml:"fake-ip-range"`
	RespectRules          bool     `yaml:"respect-rules"`
	DefaultNameserver     []string `yaml:"default-nameserver"`
	ProxyServerNameserver []string `yaml:"proxy-server-nameserver"`
	Nameserver            []string `yaml:"nameserver"`
}

type providerConfig struct {
	Type        string              `yaml:"type"`
	Path        string              `yaml:"path"`
	HealthCheck providerHealthCheck `yaml:"health-check"`
	Override    providerOverride    `yaml:"override"`
}

type providerHealthCheck struct {
	Enable bool `yaml:"enable"`
}

type providerOverride struct {
	AdditionalPrefix string `yaml:"additional-prefix"`
	InterfaceName    string `yaml:"interface-name"`
	RoutingMark      uint32 `yaml:"routing-mark"`
}

type proxyGroup struct {
	Name    string   `yaml:"name"`
	Type    string   `yaml:"type"`
	Use     []string `yaml:"use,omitempty"`
	Proxies []string `yaml:"proxies,omitempty"`
}

type listenerConfig struct {
	Name   string `yaml:"name"`
	Type   string `yaml:"type"`
	Listen string `yaml:"listen"`
	Port   int    `yaml:"port"`
	UDP    bool   `yaml:"udp"`
	Proxy  string `yaml:"proxy"`
}
