package dataplane

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"

	"gateway-vpn/internal/networkplan"
	"gateway-vpn/internal/platformexec"
	"gateway-vpn/internal/routing"
	"gateway-vpn/internal/uplink"
)

const maximumUplinkAllocations = 1 << 16

// PathBlocker is intentionally narrower than the complete path firewall API.
// A routing mutation may close the verified TUN gate, but it can never open it.
type PathBlocker interface {
	BlockPath(context.Context) error
}

// RoutingBackend reconciles the privileged policy-routing state from the
// authoritative uplink inventory. The caller supplies no routes, marks, tables,
// interfaces, or gateways across the privilege boundary.
type RoutingBackend struct {
	Uplinks           *uplink.Repository
	Executor          platformexec.Executor
	IP                string
	Sysctl            string
	LANPrefix         string
	WireGuardPrefix   string
	BootstrapDNS      []string
	RoutingTableStart uint32
	FwmarkStart       uint32
	Gate              PathBlocker
}

type RoutingCheckResult struct {
	ReadyUplinks int
	Rules        int
	Routes       int
}

func (backend RoutingBackend) SyncRouting(ctx context.Context) error {
	if err := backend.validate(); err != nil {
		return err
	}
	if err := backend.verifySourceMarkRouting(ctx); err != nil {
		return errors.Join(err, backend.Gate.BlockPath(context.WithoutCancel(ctx)))
	}
	desired, readyUplinks, err := backend.desiredPlan(ctx)
	if err != nil {
		return err
	}
	_ = readyUplinks
	current, err := backend.observe(ctx)
	if err != nil {
		return errors.Join(err, backend.Gate.BlockPath(context.WithoutCancel(ctx)))
	}
	if current.matches(desired) {
		if err := backend.verifyLookups(ctx, desired); err != nil {
			return errors.Join(err, backend.Gate.BlockPath(context.WithoutCancel(ctx)))
		}
		return nil
	}

	if err := backend.Gate.BlockPath(ctx); err != nil {
		return fmt.Errorf("block verified path before routing mutation: %w", err)
	}
	if err := backend.replace(ctx, current, desired); err != nil {
		cleanupCtx := context.WithoutCancel(ctx)
		cleanup, cleanupErr := backend.observe(cleanupCtx)
		if cleanupErr == nil {
			cleanupErr = backend.removeOwnedBase(cleanupCtx, cleanup)
		}
		return errors.Join(err, cleanupErr)
	}
	observed, err := backend.observe(ctx)
	if err != nil {
		return err
	}
	if !observed.matches(desired) {
		return errors.New("policy-routing verification differs from authoritative uplink plan")
	}
	return backend.verifyLookups(ctx, desired)
}

// CheckRouting performs the same authoritative comparison and marked lookup
// verification as SyncRouting, but cannot mutate routes or open a data path.
func (backend RoutingBackend) CheckRouting(ctx context.Context) (RoutingCheckResult, error) {
	if err := backend.validateReadOnly(); err != nil {
		return RoutingCheckResult{}, err
	}
	if err := backend.verifySourceMarkRouting(ctx); err != nil {
		return RoutingCheckResult{}, err
	}
	desired, readyUplinks, err := backend.desiredPlan(ctx)
	if err != nil {
		return RoutingCheckResult{}, err
	}
	current, err := backend.observe(ctx)
	if err != nil {
		return RoutingCheckResult{}, err
	}
	result := RoutingCheckResult{ReadyUplinks: readyUplinks, Rules: len(current.rules), Routes: len(current.routes)}
	if !current.matches(desired) {
		return result, errors.New("observed policy routing differs from authoritative uplink plan")
	}
	if err := backend.verifyLookups(ctx, desired); err != nil {
		return result, err
	}
	return result, nil
}

func (backend RoutingBackend) desiredPlan(ctx context.Context) (networkplan.Plan, int, error) {
	stored, err := backend.Uplinks.List(ctx)
	if err != nil {
		return networkplan.Plan{}, 0, fmt.Errorf("read authoritative uplink inventory: %w", err)
	}
	inputs := make([]networkplan.ModemInput, 0, len(stored))
	for _, item := range stored {
		if err := backend.validateAllocation(item); err != nil {
			return networkplan.Plan{}, 0, err
		}
		if !item.Enabled || item.State != uplink.StateReady {
			continue
		}
		inputs = append(inputs, networkplan.ModemInput{
			ID: item.ID, Priority: item.Priority, InterfaceName: item.CurrentIfname,
			ManagementPrefix: item.IPv4CIDR, Gateway: item.Gateway,
			RoutingTableID: uint32(item.RoutingTableID), Fwmark: uint32(item.Fwmark),
		})
	}
	desired, err := networkplan.Build(networkplan.Input{
		LANPrefix: backend.LANPrefix, WireGuardPrefix: backend.WireGuardPrefix, Modems: inputs,
	})
	if err != nil {
		return networkplan.Plan{}, 0, fmt.Errorf("build authoritative uplink routing plan: %w", err)
	}
	return desired, len(inputs), nil
}

func (backend RoutingBackend) validate() error {
	if err := backend.validateReadOnly(); err != nil {
		return err
	}
	if backend.Gate == nil {
		return errors.New("fixed Ubuntu iproute2 backend, uplink inventory, and path blocker are required")
	}
	return nil
}

func (backend RoutingBackend) validateReadOnly() error {
	if backend.Uplinks == nil || backend.Executor == nil || backend.IP != "/usr/sbin/ip" {
		return errors.New("fixed Ubuntu iproute2 backend and uplink inventory are required")
	}
	if backend.Sysctl != "/usr/sbin/sysctl" {
		return errors.New("source-mark routing check requires the fixed Ubuntu sysctl executable")
	}
	if backend.RoutingTableStart < 256 || backend.FwmarkStart == 0 {
		return errors.New("valid modem routing allocation ranges are required")
	}
	if _, err := parsePrefix(backend.LANPrefix); err != nil {
		return fmt.Errorf("invalid LAN prefix: %w", err)
	}
	if _, err := parsePrefix(backend.WireGuardPrefix); err != nil {
		return fmt.Errorf("invalid WireGuard prefix: %w", err)
	}
	if len(backend.BootstrapDNS) == 0 || len(backend.BootstrapDNS) > 8 {
		return errors.New("one to eight bootstrap DNS addresses are required")
	}
	for _, value := range backend.BootstrapDNS {
		address, err := netip.ParseAddr(value)
		if err != nil || !address.Is4() || address.IsUnspecified() || address.IsMulticast() {
			return errors.New("bootstrap DNS must contain usable IPv4 addresses")
		}
	}
	return nil
}

func (backend RoutingBackend) verifySourceMarkRouting(ctx context.Context) error {
	result, err := backend.Executor.Run(ctx, platformexec.Request{
		Executable: backend.Sysctl,
		Arguments:  []string{"-n", "net.ipv4.conf.all.src_valid_mark"},
	})
	if err != nil || strings.TrimSpace(result.Stdout) != "1" {
		return errors.New("IPv4 source-mark reverse-path validation is unavailable")
	}
	return nil
}

func (backend RoutingBackend) validateAllocation(item uplink.Uplink) error {
	tableLimit := uint64(backend.RoutingTableStart) + maximumUplinkAllocations
	markLimit := uint64(backend.FwmarkStart) + maximumUplinkAllocations
	if uint64(item.RoutingTableID) < uint64(backend.RoutingTableStart) || uint64(item.RoutingTableID) >= tableLimit {
		return fmt.Errorf("uplink %s routing table is outside the configured allocation range", item.ID)
	}
	if uint64(item.Fwmark) < uint64(backend.FwmarkStart) || uint64(item.Fwmark) >= markLimit {
		return fmt.Errorf("uplink %s fwmark is outside the configured allocation range", item.ID)
	}
	return nil
}

type observedRouting struct {
	rules  []observedRule
	routes []observedRoute
}

type observedRule struct {
	priority uint32
	table    uint32
	fwmark   uint32
	fwmask   uint32
}

type observedRoute struct {
	table   uint32
	dst     string
	gateway string
	device  string
	scope   string
}

func (backend RoutingBackend) observe(ctx context.Context) (observedRouting, error) {
	// iproute2 renders protocol 186 as the symbolic name "bgp" by default.
	// Numeric mode keeps ownership fields stable across distributions and
	// /etc/iproute2 protocol-name mappings.
	rulesResult, err := backend.Executor.Run(ctx, platformexec.Request{Executable: backend.IP, Arguments: []string{"-N", "-json", "-4", "rule", "show"}})
	if err != nil {
		return observedRouting{}, fmt.Errorf("observe IPv4 policy rules: %w", err)
	}
	routesResult, err := backend.Executor.Run(ctx, platformexec.Request{Executable: backend.IP, Arguments: []string{"-json", "-4", "route", "show", "table", "all", "protocol", strconv.Itoa(routing.OwnedProtocol)}})
	if err != nil {
		return observedRouting{}, fmt.Errorf("observe owned IPv4 routes: %w", err)
	}
	rules, err := decodeOwnedRules([]byte(rulesResult.Stdout))
	if err != nil {
		return observedRouting{}, fmt.Errorf("decode owned IPv4 policy rules: %w", err)
	}
	routes, err := decodeOwnedBaseRoutes([]byte(routesResult.Stdout))
	if err != nil {
		return observedRouting{}, fmt.Errorf("decode owned IPv4 routes: %w", err)
	}
	return observedRouting{rules: rules, routes: routes}, nil
}

func (backend RoutingBackend) replace(ctx context.Context, current observedRouting, desired networkplan.Plan) error {
	if err := backend.removeOwnedBase(ctx, current); err != nil {
		return err
	}
	operations, err := routing.Render(desired, backend.IP)
	if err != nil {
		return err
	}
	if err := routing.Apply(ctx, backend.Executor, operations, routing.ApplyOptions{Mutate: true}); err != nil {
		return fmt.Errorf("apply authoritative modem routing plan: %w", err)
	}
	return nil
}

func (backend RoutingBackend) removeOwnedBase(ctx context.Context, current observedRouting) error {
	for _, rule := range current.rules {
		request := platformexec.Request{Executable: backend.IP, Arguments: []string{
			"-4", "rule", "del", "priority", strconv.FormatUint(uint64(rule.priority), 10), "protocol", strconv.Itoa(routing.OwnedProtocol),
		}}
		if err := backend.runDelete(ctx, request, "remove stale Gateway VPN policy rule"); err != nil {
			return err
		}
	}
	for _, route := range current.routes {
		request := platformexec.Request{Executable: backend.IP, Arguments: []string{
			"-4", "route", "del", route.dst, "table", strconv.FormatUint(uint64(route.table), 10), "protocol", strconv.Itoa(routing.OwnedProtocol),
		}}
		if err := backend.runDelete(ctx, request, "remove stale Gateway VPN base route"); err != nil {
			return err
		}
	}
	return nil
}

func (backend RoutingBackend) runDelete(ctx context.Context, request platformexec.Request, description string) error {
	result, err := backend.Executor.Run(ctx, request)
	if err == nil || result.ExitCode == 2 {
		return nil
	}
	return fmt.Errorf("%s: %w", description, err)
}

func (backend RoutingBackend) verifyLookups(ctx context.Context, plan networkplan.Plan) error {
	rules := make(map[string]networkplan.Rule, len(plan.Rules))
	for _, rule := range plan.Rules {
		rules[rule.ModemID] = rule
	}
	for _, route := range plan.Routes {
		if route.Destination.Bits() != 0 {
			continue
		}
		rule, exists := rules[route.ModemID]
		if !exists {
			return fmt.Errorf("modem %s default route has no policy rule", route.ModemID)
		}
		for _, endpoint := range backend.BootstrapDNS {
			result, err := backend.Executor.Run(ctx, platformexec.Request{Executable: backend.IP, Arguments: []string{
				"-json", "-4", "route", "get", endpoint, "mark", fmt.Sprintf("%#x", rule.Fwmark),
			}})
			if err != nil {
				return fmt.Errorf("verify modem %s marked bootstrap route: %w", route.ModemID, err)
			}
			if err := verifyRouteGet([]byte(result.Stdout), route); err != nil {
				return fmt.Errorf("verify modem %s marked bootstrap route: %w", route.ModemID, err)
			}
		}
	}
	return nil
}

func (current observedRouting) matches(plan networkplan.Plan) bool {
	desiredRules := make([]string, 0, len(plan.Rules))
	for _, rule := range plan.Rules {
		desiredRules = append(desiredRules, ruleKey(observedRule{priority: rule.Priority, table: rule.TableID, fwmark: rule.Fwmark, fwmask: rule.Mask}))
	}
	observedRules := make([]string, 0, len(current.rules))
	for _, rule := range current.rules {
		observedRules = append(observedRules, ruleKey(rule))
	}
	desiredRoutes := make([]string, 0, len(plan.Routes))
	for _, route := range plan.Routes {
		scope := ""
		if route.ScopeLink {
			scope = "link"
		}
		gateway := ""
		if route.Via.IsValid() {
			gateway = route.Via.String()
		}
		desiredRoutes = append(desiredRoutes, routeKey(observedRoute{table: route.TableID, dst: route.Destination.String(), gateway: gateway, device: route.Device, scope: scope}))
	}
	observedRoutes := make([]string, 0, len(current.routes))
	for _, route := range current.routes {
		observedRoutes = append(observedRoutes, routeKey(route))
	}
	sort.Strings(desiredRules)
	sort.Strings(observedRules)
	sort.Strings(desiredRoutes)
	sort.Strings(observedRoutes)
	return slicesEqual(desiredRules, observedRules) && slicesEqual(desiredRoutes, observedRoutes)
}

func ruleKey(rule observedRule) string {
	return fmt.Sprintf("%d/%d/%08x/%08x", rule.priority, rule.table, rule.fwmark, rule.fwmask)
}

func routeKey(route observedRoute) string {
	return fmt.Sprintf("%d/%s/%s/%s/%s", route.table, normalizeDestination(route.dst), route.gateway, route.device, normalizeScope(route.scope))
}

func slicesEqual(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func decodeOwnedRules(payload []byte) ([]observedRule, error) {
	var rows []map[string]json.RawMessage
	if err := json.Unmarshal(payload, &rows); err != nil {
		return nil, err
	}
	result := make([]observedRule, 0)
	for _, row := range rows {
		protocol, ok := parseUint(row["protocol"])
		if !ok || protocol != routing.OwnedProtocol {
			continue
		}
		priority, priorityOK := parseUint(row["priority"])
		table, tableOK := parseUint(row["table"])
		mark, markOK := parseUint(row["fwmark"])
		mask, maskOK := parseUint(row["fwmask"])
		if !maskOK {
			mask = 0xffffffff
		}
		if !priorityOK || !tableOK || !markOK || priority == 0 || table < 256 || mark == 0 || mask > 0xffffffff || priority > 0xffffffff || table > 0xffffffff || mark > 0xffffffff {
			return nil, errors.New("owned policy rule has invalid or incomplete fields")
		}
		result = append(result, observedRule{priority: uint32(priority), table: uint32(table), fwmark: uint32(mark), fwmask: uint32(mask)})
	}
	return result, nil
}

func decodeOwnedBaseRoutes(payload []byte) ([]observedRoute, error) {
	var rows []map[string]json.RawMessage
	if err := json.Unmarshal(payload, &rows); err != nil {
		return nil, err
	}
	result := make([]observedRoute, 0)
	for _, row := range rows {
		// `ip route show ... protocol 186` performs the ownership filter in
		// the kernel query but omits the protocol field from JSON on Ubuntu's
		// iproute2. If a version does return the field, reject anything other
		// than the owned protocol rather than broadening ownership.
		if len(row["protocol"]) != 0 {
			protocol, ok := parseUint(row["protocol"])
			if !ok || protocol != routing.OwnedProtocol {
				continue
			}
		}
		table, ok := parseUint(row["table"])
		if !ok || table < 256 || table > 0xffffffff {
			return nil, errors.New("owned route has invalid routing table")
		}
		dst := normalizeDestination(parseString(row["dst"]))
		gateway := parseString(row["gateway"])
		scope := normalizeScope(parseString(row["scope"]))
		// Protocol 186 is shared with modem-scoped WireGuard endpoint host
		// routes. Only default and link-scope base routes belong to this sync.
		if dst != "0.0.0.0/0" && !(gateway == "" && scope == "link") {
			continue
		}
		device := parseString(row["dev"])
		if device == "" || (dst != "0.0.0.0/0" && parseRoutePrefix(dst) == "") {
			return nil, errors.New("owned base route has invalid or incomplete fields")
		}
		result = append(result, observedRoute{table: uint32(table), dst: dst, gateway: gateway, device: device, scope: scope})
	}
	return result, nil
}

func verifyRouteGet(payload []byte, expected networkplan.Route) error {
	var rows []map[string]json.RawMessage
	if err := json.Unmarshal(payload, &rows); err != nil || len(rows) != 1 {
		return errors.New("ip route get returned invalid JSON")
	}
	table, ok := parseUint(rows[0]["table"])
	if !ok || table != uint64(expected.TableID) || parseString(rows[0]["dev"]) != expected.Device || parseString(rows[0]["gateway"]) != expected.Via.String() {
		return errors.New("marked route resolved through the wrong table, interface, or gateway")
	}
	return nil
}

func parseUint(raw json.RawMessage) (uint64, bool) {
	if len(raw) == 0 {
		return 0, false
	}
	var number uint64
	if err := json.Unmarshal(raw, &number); err == nil {
		return number, true
	}
	var value string
	if err := json.Unmarshal(raw, &value); err != nil {
		return 0, false
	}
	value = strings.TrimSpace(value)
	if value == "main" {
		return 254, true
	}
	if value == "default" {
		return 253, true
	}
	if value == "local" {
		return 255, true
	}
	number, err := strconv.ParseUint(value, 0, 64)
	return number, err == nil
}

func parseString(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var value string
	if json.Unmarshal(raw, &value) != nil {
		return ""
	}
	return value
}

func normalizeDestination(value string) string {
	if value == "" || value == "default" {
		return "0.0.0.0/0"
	}
	return value
}

func normalizeScope(value string) string {
	if value == "universe" || value == "global" {
		return ""
	}
	return value
}

func parseRoutePrefix(value string) string {
	prefix, err := netip.ParsePrefix(value)
	if err != nil || !prefix.Addr().Is4() || prefix != prefix.Masked() {
		return ""
	}
	return prefix.String()
}

func parsePrefix(value string) (netip.Prefix, error) {
	prefix, err := netip.ParsePrefix(value)
	if err != nil || !prefix.Addr().Is4() {
		return netip.Prefix{}, errors.New("IPv4 prefix is required")
	}
	return prefix.Masked(), nil
}
