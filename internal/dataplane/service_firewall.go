package dataplane

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"gateway-vpn/internal/accesspolicy"
	"gateway-vpn/internal/bypass"
	"gateway-vpn/internal/firewall"
	"gateway-vpn/internal/modem"
	"gateway-vpn/internal/netbind"
	"gateway-vpn/internal/platformexec"
	"gateway-vpn/internal/subscription"
	wireguardpkg "gateway-vpn/internal/wireguard"
)

const (
	hilinkInterfacesSet      = "hilink_interfaces"
	hilinkManagementSet      = "hilink_management_v4"
	wireGuardEndpointSet     = "wireguard_endpoint_v4"
	wireGuardGenerationSet   = "wireguard_endpoint_generation"
	bootstrapDNSSet          = "bootstrap_dns_v4"
	bootstrapHTTPSet         = "bootstrap_http_v4"
	mihomoEndpointTCPSet     = "mihomo_endpoint_tcp_v4"
	mihomoEndpointUDPSet     = "mihomo_endpoint_udp_v4"
	mihomoEndpointGeneration = "mihomo_endpoint_generation"
	serviceContextGeneration = "service_context_generation"
	bootstrapHTTPTimeout     = "2m"
)

type BootstrapAuthorization struct {
	ModemID        string   `json:"modem_id"`
	SubscriptionID string   `json:"subscription_id"`
	Addresses      []string `json:"addresses"`
	Port           uint16   `json:"port"`
}

type MihomoEndpointAuthorization struct {
	VersionIDs []string `json:"version_ids"`
}

type DirectProbeAuthorization struct {
	ModemID   string   `json:"modem_id"`
	TargetID  string   `json:"target_id"`
	Addresses []string `json:"addresses"`
	Port      uint16   `json:"port"`
}

// ServiceFirewallBackend combines route reconciliation with the exact direct
// service allowlists that those marked routes may use.
type ServiceFirewallBackend struct {
	Routing       RoutingBackend
	Modems        *modem.Repository
	Subscriptions *subscription.Repository
	Targets       *bypass.Repository
	Executor      platformexec.Executor
	NFT           string
	BootstrapDNS  []string
	Versions      *subscription.VersionRepository
	PayloadRoot   string
	AccessPolicy  *accesspolicy.Repository
	mutex         sync.Mutex
}

func (backend *ServiceFirewallBackend) SyncRouting(ctx context.Context) error {
	if backend == nil {
		return errors.New("service firewall backend is nil")
	}
	backend.mutex.Lock()
	defer backend.mutex.Unlock()
	return backend.syncRoutingLocked(ctx)
}

func (backend *ServiceFirewallBackend) syncRoutingLocked(ctx context.Context) error {
	if err := backend.validate(); err != nil {
		return err
	}
	if err := backend.Routing.SyncRouting(ctx); err != nil {
		return err
	}
	if err := backend.syncServiceContext(ctx); err != nil {
		return errors.Join(err, backend.Routing.Gate.BlockPath(context.WithoutCancel(ctx)))
	}
	return nil
}

func (backend *ServiceFirewallBackend) AuthorizeBootstrap(ctx context.Context, authorization BootstrapAuthorization) error {
	if backend == nil {
		return errors.New("service firewall backend is nil")
	}
	backend.mutex.Lock()
	defer backend.mutex.Unlock()
	if err := backend.syncRoutingLocked(ctx); err != nil {
		return err
	}
	if strings.TrimSpace(authorization.ModemID) == "" || strings.TrimSpace(authorization.SubscriptionID) == "" || authorization.Port != 443 || len(authorization.Addresses) == 0 || len(authorization.Addresses) > 16 {
		return errors.New("bounded HTTPS bootstrap authorization is required")
	}
	currentModem, err := backend.Modems.Get(ctx, authorization.ModemID)
	if err != nil || !currentModem.Enabled || currentModem.State != modem.StateReady {
		return errors.New("bootstrap modem is not ready")
	}
	currentSubscription, err := backend.Subscriptions.Get(ctx, authorization.SubscriptionID)
	if err != nil || currentSubscription.SourceType != "url" {
		return errors.New("bootstrap subscription is not a URL source")
	}
	policy, err := backend.AccessPolicy.GetPolicy(ctx)
	if err != nil || !policy.DirectServiceRefresh {
		return errors.New("direct subscription refresh is disabled by policy")
	}
	addresses, err := validatedPublicAddresses(authorization.Addresses)
	if err != nil {
		return err
	}
	if err := backend.authorizeTransientHTTPS(ctx, currentModem, addresses, authorization.Port); err != nil {
		return fmt.Errorf("authorize modem-bound subscription endpoint: %w", err)
	}
	return nil
}

func (backend *ServiceFirewallBackend) AuthorizeDirectProbe(ctx context.Context, authorization DirectProbeAuthorization) error {
	if backend == nil {
		return errors.New("service firewall backend is nil")
	}
	backend.mutex.Lock()
	defer backend.mutex.Unlock()
	if err := backend.syncRoutingLocked(ctx); err != nil {
		return err
	}
	if backend.Targets == nil || strings.TrimSpace(authorization.ModemID) == "" || strings.TrimSpace(authorization.TargetID) == "" || authorization.Port == 0 {
		return errors.New("bounded direct probe authorization is required")
	}
	currentModem, err := backend.Modems.Get(ctx, authorization.ModemID)
	if err != nil || !currentModem.Enabled || currentModem.State != modem.StateReady {
		return errors.New("direct probe modem is not ready")
	}
	target, err := backend.Targets.Get(ctx, authorization.TargetID)
	if err != nil || !target.Enabled {
		return errors.New("direct probe target is not enabled")
	}
	parsed, err := url.Parse(target.NormalizedURL)
	if err != nil || parsed.Scheme != "https" || parsed.Hostname() == "" {
		return errors.New("stored direct probe target is invalid")
	}
	expectedPort := uint16(443)
	if parsed.Port() != "" {
		value, parseErr := strconv.ParseUint(parsed.Port(), 10, 16)
		if parseErr != nil || value == 0 {
			return errors.New("stored direct probe target port is invalid")
		}
		expectedPort = uint16(value)
	}
	if authorization.Port != expectedPort {
		return errors.New("direct probe authorization port does not match target policy")
	}
	addresses, err := validatedPublicAddresses(authorization.Addresses)
	if err != nil {
		return err
	}
	if err := backend.authorizeTransientHTTPS(ctx, currentModem, addresses, authorization.Port); err != nil {
		return fmt.Errorf("authorize modem-bound direct probe endpoint: %w", err)
	}
	return nil
}

func (backend *ServiceFirewallBackend) authorizeTransientHTTPS(ctx context.Context, currentModem modem.Modem, addresses []string, port uint16) error {
	var commands strings.Builder
	for _, address := range addresses {
		element := serviceTuple(currentModem.InterfaceName, currentModem.Fwmark, address, port)
		fmt.Fprintf(&commands, "destroy element inet %s %s { %s }\n", firewall.TableName, bootstrapHTTPSet, element)
		fmt.Fprintf(&commands, "add element inet %s %s { %s timeout %s }\n", firewall.TableName, bootstrapHTTPSet, element, bootstrapHTTPTimeout)
	}
	return backend.applyTransaction(ctx, commands.String())
}

func validatedPublicAddresses(rawAddresses []string) ([]string, error) {
	if len(rawAddresses) == 0 || len(rawAddresses) > 16 {
		return nil, errors.New("bounded public IPv4 endpoint set is required")
	}
	addresses := make([]string, 0, len(rawAddresses))
	seen := make(map[string]struct{}, len(rawAddresses))
	for _, raw := range rawAddresses {
		address, err := netip.ParseAddr(raw)
		if err != nil || !publicIPv4(address.Unmap()) {
			return nil, errors.New("endpoint must contain only public IPv4 addresses")
		}
		value := address.Unmap().String()
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		addresses = append(addresses, value)
	}
	sort.Strings(addresses)
	if len(addresses) == 0 {
		return nil, errors.New("endpoint address set is empty")
	}
	return addresses, nil
}

func (backend *ServiceFirewallBackend) AuthorizeWireGuardEndpoint(ctx context.Context, currentModem modem.Modem, address string) error {
	if backend == nil {
		return errors.New("service firewall backend is nil")
	}
	backend.mutex.Lock()
	defer backend.mutex.Unlock()
	if err := backend.syncRoutingLocked(ctx); err != nil {
		return err
	}
	stored, err := backend.Modems.Get(ctx, currentModem.ID)
	if err != nil || !stored.Enabled || stored.State != modem.StateReady || stored.InterfaceName != currentModem.InterfaceName || stored.Fwmark != currentModem.Fwmark {
		return errors.New("WireGuard endpoint modem context is stale")
	}
	parsed, err := netip.ParseAddr(address)
	if err != nil || !publicIPv4(parsed.Unmap()) {
		return errors.New("WireGuard endpoint must be public IPv4")
	}
	element := serviceTuple(stored.InterfaceName, stored.Fwmark, parsed.Unmap().String(), 0)
	generation := twoPartGeneration([]byte(element))
	observed, err := backend.observeGenerationSet(ctx, wireGuardGenerationSet)
	if err != nil {
		return err
	}
	if observed == generation {
		return nil
	}
	var payload strings.Builder
	fmt.Fprintf(&payload, "flush set inet %s %s\n", firewall.TableName, wireGuardEndpointSet)
	fmt.Fprintf(&payload, "flush set inet %s %s\n", firewall.TableName, wireGuardGenerationSet)
	fmt.Fprintf(&payload, "add element inet %s %s { %d, %d }\n", firewall.TableName, wireGuardGenerationSet, generation[0], generation[1])
	fmt.Fprintf(&payload, "add element inet %s %s { %s }\n", firewall.TableName, wireGuardEndpointSet, element)
	if err := backend.applyTransaction(ctx, payload.String()); err != nil {
		return fmt.Errorf("authorize WireGuard endpoint tuple: %w", err)
	}
	verified, err := backend.observeGenerationSet(ctx, wireGuardGenerationSet)
	if err != nil {
		return err
	}
	if verified != generation {
		return errors.New("WireGuard endpoint generation verification mismatch")
	}
	return nil
}

func (backend *ServiceFirewallBackend) ResolveWireGuardEndpoint(ctx context.Context, currentModem modem.Modem, hostname string) ([]string, error) {
	if backend == nil {
		return nil, errors.New("service firewall backend is nil")
	}
	backend.mutex.Lock()
	defer backend.mutex.Unlock()
	if err := backend.syncRoutingLocked(ctx); err != nil {
		return nil, err
	}
	stored, err := backend.Modems.Get(ctx, currentModem.ID)
	if err != nil || !stored.Enabled || stored.State != modem.StateReady || stored.InterfaceName != currentModem.InterfaceName || stored.Fwmark != currentModem.Fwmark {
		return nil, errors.New("WireGuard DNS modem context is stale")
	}
	if !wireguardpkg.ValidEndpointHostname(hostname) {
		return nil, errors.New("WireGuard endpoint hostname is invalid")
	}
	resolver, err := backend.modemResolver(stored)
	if err != nil {
		return nil, err
	}
	addresses, err := resolveProxyEndpoint(ctx, resolver, hostname)
	if err != nil {
		return nil, errors.New("modem-bound WireGuard endpoint DNS failed")
	}
	return addresses, nil
}

func (backend *ServiceFirewallBackend) AuthorizeMihomoEndpoints(ctx context.Context, authorization MihomoEndpointAuthorization) error {
	if backend == nil {
		return errors.New("service firewall backend is nil")
	}
	backend.mutex.Lock()
	defer backend.mutex.Unlock()
	if err := backend.syncRoutingLocked(ctx); err != nil {
		return err
	}
	if backend.Versions == nil || strings.TrimSpace(backend.PayloadRoot) == "" || len(authorization.VersionIDs) == 0 || len(authorization.VersionIDs) > 128 {
		return errors.New("bounded Mihomo version authorization is required")
	}
	versionIDs := append([]string(nil), authorization.VersionIDs...)
	sort.Strings(versionIDs)
	for index := 1; index < len(versionIDs); index++ {
		if versionIDs[index] == versionIDs[index-1] {
			return errors.New("Mihomo endpoint authorization contains duplicate versions")
		}
	}
	endpoints := make(map[string]proxyEndpoint)
	for _, versionID := range versionIDs {
		version, err := backend.Versions.Get(ctx, versionID)
		if err != nil || (version.State != subscription.VersionCandidate && version.State != subscription.VersionLKG && version.State != subscription.VersionRetained) {
			return errors.New("Mihomo endpoint version is not an active or candidate generation")
		}
		imported, err := subscription.LoadNormalizedPayload(backend.PayloadRoot, version.SubscriptionID, version.ID)
		if err != nil {
			return fmt.Errorf("load normalized Mihomo endpoint version: %w", err)
		}
		enabled, err := backend.Versions.ListNodes(ctx, version.ID, true)
		if err != nil {
			return fmt.Errorf("read enabled Mihomo endpoint nodes: %w", err)
		}
		fingerprints := make(map[string]struct{}, len(enabled))
		for _, node := range enabled {
			fingerprints[node.Fingerprint] = struct{}{}
		}
		for _, node := range imported.Nodes {
			if _, exists := fingerprints[node.Fingerprint]; !exists {
				continue
			}
			endpoint, err := endpointFromNode(node)
			if err != nil {
				return err
			}
			endpoints[endpoint.host+"\x00"+strconv.FormatUint(uint64(endpoint.port), 10)] = endpoint
		}
	}
	if len(endpoints) == 0 || len(endpoints) > 5000 {
		return errors.New("Mihomo endpoint authorization has invalid endpoint cardinality")
	}

	stored, err := backend.Modems.List(ctx)
	if err != nil {
		return fmt.Errorf("read modems for Mihomo endpoint authorization: %w", err)
	}
	ready := make([]modem.Modem, 0, len(stored))
	for _, item := range stored {
		if item.Enabled && item.State == modem.StateReady {
			ready = append(ready, item)
		}
	}
	if len(ready) == 0 {
		return errors.New("Mihomo endpoint authorization requires a ready modem")
	}
	tuples := make([]mihomoEndpointTuple, 0, len(ready)*len(endpoints))
	for _, currentModem := range ready {
		resolver, err := backend.modemResolver(currentModem)
		if err != nil {
			return err
		}
		for _, endpoint := range endpoints {
			addresses, err := resolveProxyEndpoint(ctx, resolver, endpoint.host)
			if err != nil {
				return fmt.Errorf("resolve proxy endpoint through modem %s: %w", currentModem.ID, err)
			}
			for _, address := range addresses {
				tuples = append(tuples, mihomoEndpointTuple{interfaceName: currentModem.InterfaceName, fwmark: currentModem.Fwmark, address: address, port: endpoint.port})
				if len(tuples) > 20000 {
					return errors.New("resolved Mihomo endpoint tuple count exceeds hard limit")
				}
			}
		}
	}
	sort.Slice(tuples, func(i, j int) bool { return tuples[i].key() < tuples[j].key() })
	tuples = uniqueMihomoTuples(tuples)
	generation := mihomoGeneration(versionIDs, tuples)
	if err := backend.applyTransaction(ctx, renderMihomoEndpoints(generation, tuples)); err != nil {
		return fmt.Errorf("apply Mihomo endpoint allowlist: %w", err)
	}
	verified, err := backend.observeGenerationSet(ctx, mihomoEndpointGeneration)
	if err != nil {
		return err
	}
	if verified != generation {
		return errors.New("Mihomo endpoint generation verification mismatch")
	}
	return nil
}

func (backend *ServiceFirewallBackend) validate() error {
	if backend.Modems == nil || backend.Subscriptions == nil || backend.AccessPolicy == nil || backend.Executor == nil || backend.NFT != "/usr/sbin/nft" {
		return errors.New("fixed Ubuntu nft backend and authoritative repositories are required")
	}
	if backend.Routing.Modems != backend.Modems || backend.Routing.Executor == nil || len(backend.BootstrapDNS) == 0 {
		return errors.New("service firewall and routing must share modem inventory and bootstrap DNS")
	}
	return nil
}

type serviceModem struct {
	interfaceName string
	managementIP  string
	fwmark        uint32
}

func (backend *ServiceFirewallBackend) syncServiceContext(ctx context.Context) error {
	stored, err := backend.Modems.List(ctx)
	if err != nil {
		return fmt.Errorf("read modem service contexts: %w", err)
	}
	ready := make([]serviceModem, 0, len(stored))
	for _, item := range stored {
		if !item.Enabled || item.State != modem.StateReady {
			continue
		}
		if !validInterfaceName(item.InterfaceName) || item.Fwmark == 0 {
			return fmt.Errorf("modem %s has invalid service routing context", item.ID)
		}
		management, err := netip.ParseAddr(item.Gateway)
		if err != nil || !management.Is4() {
			return fmt.Errorf("modem %s has invalid management endpoint", item.ID)
		}
		ready = append(ready, serviceModem{interfaceName: item.InterfaceName, managementIP: management.String(), fwmark: item.Fwmark})
	}
	sort.Slice(ready, func(i, j int) bool {
		if ready[i].interfaceName == ready[j].interfaceName {
			return ready[i].fwmark < ready[j].fwmark
		}
		return ready[i].interfaceName < ready[j].interfaceName
	})
	desiredGeneration := serviceGeneration(ready, backend.BootstrapDNS)
	observedGeneration, err := backend.observeServiceGeneration(ctx)
	if err != nil {
		return err
	}
	if observedGeneration == desiredGeneration {
		return nil
	}
	payload := renderServiceContext(desiredGeneration, ready, backend.BootstrapDNS)
	if err := backend.applyTransaction(ctx, payload); err != nil {
		return err
	}
	verified, err := backend.observeServiceGeneration(ctx)
	if err != nil {
		return err
	}
	if verified != desiredGeneration {
		return errors.New("service firewall generation verification mismatch")
	}
	return nil
}

func (backend *ServiceFirewallBackend) observeServiceGeneration(ctx context.Context) ([2]uint32, error) {
	return backend.observeGenerationSet(ctx, serviceContextGeneration)
}

func (backend *ServiceFirewallBackend) observeGenerationSet(ctx context.Context, setName string) ([2]uint32, error) {
	if err := backend.inspectIntegrity(ctx); err != nil {
		return [2]uint32{}, err
	}
	result, err := backend.Executor.Run(ctx, platformexec.Request{Executable: backend.NFT, Arguments: []string{"--json", "list", "set", "inet", firewall.TableName, setName}})
	if err != nil {
		return [2]uint32{}, fmt.Errorf("observe service firewall generation: %w", err)
	}
	var document struct {
		NFTables []map[string]json.RawMessage `json:"nftables"`
	}
	if err := json.Unmarshal([]byte(result.Stdout), &document); err != nil {
		return [2]uint32{}, fmt.Errorf("decode service firewall generation: %w", err)
	}
	var elements []any
	found := false
	for _, object := range document.NFTables {
		raw, exists := object["set"]
		if !exists {
			continue
		}
		var set struct {
			Family string `json:"family"`
			Table  string `json:"table"`
			Name   string `json:"name"`
			Elem   []any  `json:"elem"`
		}
		if json.Unmarshal(raw, &set) != nil {
			return [2]uint32{}, errors.New("invalid service generation set JSON")
		}
		if set.Family == "inet" && set.Table == firewall.TableName && set.Name == setName {
			found, elements = true, set.Elem
		}
	}
	if !found {
		return [2]uint32{}, errors.New("service generation set is missing")
	}
	if len(elements) == 0 {
		return [2]uint32{}, nil
	}
	if len(elements) != 2 {
		return [2]uint32{}, errors.New("service generation set has invalid cardinality")
	}
	first, okFirst := uint32Element(elements[0])
	second, okSecond := uint32Element(elements[1])
	if !okFirst || !okSecond || first == second {
		return [2]uint32{}, errors.New("service generation elements are invalid")
	}
	if first > second {
		first, second = second, first
	}
	return [2]uint32{first, second}, nil
}

func (backend *ServiceFirewallBackend) inspectIntegrity(ctx context.Context) error {
	result, err := backend.Executor.Run(ctx, platformexec.Request{Executable: backend.NFT, Arguments: []string{"list", "table", "inet", firewall.TableName}})
	if err != nil {
		return fmt.Errorf("inspect owned service firewall table: %w", err)
	}
	for _, marker := range []string{
		"set firewall_schema_generation",
		"set " + hilinkInterfacesSet,
		"set " + hilinkManagementSet,
		"set " + wireGuardEndpointSet,
		"set " + wireGuardGenerationSet,
		"set " + bootstrapDNSSet,
		"set " + bootstrapHTTPSet,
		"set " + mihomoEndpointTCPSet,
		"set " + mihomoEndpointUDPSet,
		"set " + mihomoEndpointGeneration,
		"set " + serviceContextGeneration,
		"counter service_upload",
		"counter service_download",
		"policy drop",
		"oifname . meta mark . ip daddr @" + bootstrapDNSSet,
	} {
		if !strings.Contains(result.Stdout, marker) {
			return fmt.Errorf("owned service firewall table is missing integrity marker %q", marker)
		}
	}
	return nil
}

func (backend *ServiceFirewallBackend) applyTransaction(ctx context.Context, payload string) error {
	if strings.TrimSpace(payload) == "" {
		return errors.New("empty service firewall transaction")
	}
	if err := backend.inspectIntegrity(ctx); err != nil {
		return err
	}
	for _, arguments := range [][]string{{"--check", "--file", "-"}, {"--file", "-"}} {
		result, err := backend.Executor.Run(ctx, platformexec.Request{Executable: backend.NFT, Arguments: arguments, Stdin: []byte(payload)})
		if err != nil {
			return fmt.Errorf("nft service transaction failed: %s: %w", bounded(result.Stderr), err)
		}
	}
	return nil
}

func renderServiceContext(generation [2]uint32, modems []serviceModem, bootstrapDNS []string) string {
	sets := []string{
		serviceContextGeneration, hilinkInterfacesSet, hilinkManagementSet,
		wireGuardEndpointSet, wireGuardGenerationSet, bootstrapDNSSet, bootstrapHTTPSet,
		mihomoEndpointTCPSet, mihomoEndpointUDPSet, mihomoEndpointGeneration,
	}
	var builder strings.Builder
	for _, set := range sets {
		builder.WriteString("flush set inet ")
		builder.WriteString(firewall.TableName)
		builder.WriteByte(' ')
		builder.WriteString(set)
		builder.WriteByte('\n')
	}
	fmt.Fprintf(&builder, "add element inet %s %s { %d, %d }\n", firewall.TableName, serviceContextGeneration, generation[0], generation[1])
	for _, current := range modems {
		fmt.Fprintf(&builder, "add element inet %s %s { %s }\n", firewall.TableName, hilinkInterfacesSet, strconv.Quote(current.interfaceName))
		fmt.Fprintf(&builder, "add element inet %s %s { %s . %s }\n", firewall.TableName, hilinkManagementSet, strconv.Quote(current.interfaceName), current.managementIP)
		for _, dns := range bootstrapDNS {
			fmt.Fprintf(&builder, "add element inet %s %s { %s }\n", firewall.TableName, bootstrapDNSSet, serviceTuple(current.interfaceName, current.fwmark, dns, 0))
		}
	}
	return builder.String()
}

func serviceGeneration(modems []serviceModem, dns []string) [2]uint32 {
	values := append([]string(nil), dns...)
	sort.Strings(values)
	var builder strings.Builder
	for _, current := range modems {
		fmt.Fprintf(&builder, "%s\x00%08x\x00%s\n", current.interfaceName, current.fwmark, current.managementIP)
	}
	for _, value := range values {
		builder.WriteString(value)
		builder.WriteByte('\n')
	}
	digest := sha256.Sum256([]byte(builder.String()))
	first := binary.BigEndian.Uint32(digest[0:4])
	second := binary.BigEndian.Uint32(digest[4:8])
	if first == 0 {
		first = 1
	}
	if second == 0 || second == first {
		second = first ^ 0xa5a5a5a5
		if second == 0 {
			second = 2
		}
	}
	if first > second {
		first, second = second, first
	}
	return [2]uint32{first, second}
}

func serviceTuple(interfaceName string, mark uint32, address string, port uint16) string {
	value := fmt.Sprintf("%s . %#x . %s", strconv.Quote(interfaceName), mark, address)
	if port != 0 {
		value += " . " + strconv.FormatUint(uint64(port), 10)
	}
	return value
}

type proxyEndpoint struct {
	host string
	port uint16
}

type mihomoEndpointTuple struct {
	interfaceName string
	fwmark        uint32
	address       string
	port          uint16
}

func (tuple mihomoEndpointTuple) key() string {
	return serviceTuple(tuple.interfaceName, tuple.fwmark, tuple.address, tuple.port)
}

func endpointFromNode(node subscription.ImportedNode) (proxyEndpoint, error) {
	host, ok := node.Config["server"].(string)
	host = strings.TrimSpace(strings.ToLower(host))
	if !ok || host == "" || len(host) > 253 {
		return proxyEndpoint{}, errors.New("normalized proxy node has invalid server")
	}
	port, ok := numericEndpointPort(node.Config["port"])
	if !ok {
		return proxyEndpoint{}, errors.New("normalized proxy node has invalid port")
	}
	return proxyEndpoint{host: host, port: port}, nil
}

func numericEndpointPort(value any) (uint16, bool) {
	var number uint64
	switch typed := value.(type) {
	case int:
		if typed < 0 {
			return 0, false
		}
		number = uint64(typed)
	case int64:
		if typed < 0 {
			return 0, false
		}
		number = uint64(typed)
	case uint64:
		number = typed
	case uint:
		number = uint64(typed)
	case float64:
		if typed < 0 || typed != float64(uint64(typed)) {
			return 0, false
		}
		number = uint64(typed)
	case string:
		parsed, err := strconv.ParseUint(typed, 10, 16)
		if err != nil {
			return 0, false
		}
		number = parsed
	default:
		return 0, false
	}
	return uint16(number), number > 0 && number <= 65535
}

func (backend *ServiceFirewallBackend) modemResolver(current modem.Modem) (*net.Resolver, error) {
	configuration := netbind.Config{InterfaceName: current.InterfaceName, Fwmark: current.Fwmark}
	if err := configuration.Validate(); err != nil {
		return nil, fmt.Errorf("invalid modem resolver context: %w", err)
	}
	dialer := &net.Dialer{Timeout: 8 * time.Second, Control: netbind.SocketControl(configuration)}
	return &net.Resolver{
		PreferGo: true, StrictErrors: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			if strings.HasPrefix(network, "tcp") {
				network = "tcp4"
			} else {
				network = "udp4"
			}
			return dialer.DialContext(ctx, network, net.JoinHostPort(backend.BootstrapDNS[0], "53"))
		},
	}, nil
}

func resolveProxyEndpoint(ctx context.Context, resolver *net.Resolver, host string) ([]string, error) {
	if address, err := netip.ParseAddr(host); err == nil {
		address = address.Unmap()
		if !publicIPv4(address) {
			return nil, errors.New("proxy endpoint IP must be public IPv4")
		}
		return []string{address.String()}, nil
	}
	addresses, err := resolver.LookupNetIP(ctx, "ip4", host)
	if err != nil || len(addresses) == 0 || len(addresses) > 64 {
		return nil, errors.New("proxy endpoint DNS resolution failed")
	}
	seen := make(map[string]struct{}, len(addresses))
	result := make([]string, 0, len(addresses))
	for _, address := range addresses {
		address = address.Unmap()
		if !publicIPv4(address) {
			return nil, errors.New("proxy endpoint DNS returned a non-public IPv4 address")
		}
		value := address.String()
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	sort.Strings(result)
	return result, nil
}

func uniqueMihomoTuples(values []mihomoEndpointTuple) []mihomoEndpointTuple {
	if len(values) < 2 {
		return values
	}
	result := values[:1]
	for _, value := range values[1:] {
		if value.key() != result[len(result)-1].key() {
			result = append(result, value)
		}
	}
	return result
}

func mihomoGeneration(versionIDs []string, tuples []mihomoEndpointTuple) [2]uint32 {
	var builder strings.Builder
	for _, versionID := range versionIDs {
		builder.WriteString(versionID)
		builder.WriteByte('\n')
	}
	for _, tuple := range tuples {
		builder.WriteString(tuple.key())
		builder.WriteByte('\n')
	}
	return twoPartGeneration([]byte(builder.String()))
}

func renderMihomoEndpoints(generation [2]uint32, tuples []mihomoEndpointTuple) string {
	var builder strings.Builder
	for _, set := range []string{mihomoEndpointTCPSet, mihomoEndpointUDPSet, mihomoEndpointGeneration} {
		fmt.Fprintf(&builder, "flush set inet %s %s\n", firewall.TableName, set)
	}
	fmt.Fprintf(&builder, "add element inet %s %s { %d, %d }\n", firewall.TableName, mihomoEndpointGeneration, generation[0], generation[1])
	for _, tuple := range tuples {
		for _, set := range []string{mihomoEndpointTCPSet, mihomoEndpointUDPSet} {
			fmt.Fprintf(&builder, "add element inet %s %s { %s }\n", firewall.TableName, set, tuple.key())
		}
	}
	return builder.String()
}

func twoPartGeneration(payload []byte) [2]uint32 {
	digest := sha256.Sum256(payload)
	first := binary.BigEndian.Uint32(digest[0:4])
	second := binary.BigEndian.Uint32(digest[4:8])
	if first == 0 {
		first = 1
	}
	if second == 0 || second == first {
		second = first ^ 0xa5a5a5a5
		if second == 0 {
			second = 2
		}
	}
	if first > second {
		first, second = second, first
	}
	return [2]uint32{first, second}
}

func publicIPv4(address netip.Addr) bool {
	return address.Is4() && address.IsGlobalUnicast() && !address.IsPrivate() && !address.IsLoopback() && !address.IsLinkLocalUnicast() && !address.IsMulticast() && !address.IsUnspecified()
}
