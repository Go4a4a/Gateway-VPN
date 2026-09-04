// Package dataplane owns the small privileged runtime surface that opens or
// closes verified LAN traffic through exactly one selected access method. It
// mutates only bounded gate collections in the Gateway VPN-owned table.
package dataplane

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"gateway-vpn/internal/firewall"
	"gateway-vpn/internal/platformexec"
	"gateway-vpn/internal/uplink"
)

const (
	PathModeTUN    = "TUN"
	PathModeDirect = "DIRECT"

	activeTUNSet             = "active_tun_interfaces"
	activeDirectInterfaceSet = "active_direct_interfaces"
	activeDirectContextSet   = "active_direct_context"
	activeDirectMarkMap      = "active_direct_marks"
	activeGenerationSet      = "active_path_generation"
	activeRouteGenerationSet = "active_route_generation"
	wireGuardAllowedV4Set    = "wireguard_ingress_allowed_v4"
	wireGuardIngressName     = "wg-ingress"
)

type PathState struct {
	Active          bool   `json:"active"`
	Mode            string `json:"mode,omitempty"`
	Generation      uint32 `json:"generation"`
	DirectInterface string `json:"direct_interface,omitempty"`
	DirectMark      uint32 `json:"direct_mark,omitempty"`
	RouteGeneration uint32 `json:"route_generation,omitempty"`
}

type RoutingSynchronizer interface {
	SyncRouting(context.Context) error
}

type FirewallBackend struct {
	Database *sql.DB
	Uplinks  *uplink.Repository
	Routing  RoutingSynchronizer
	Executor platformexec.Executor
	NFT      string
	TUNName  string
	LANName  string
	mutex    sync.Mutex
}

func (backend *FirewallBackend) ActivatePath(ctx context.Context, generation uint32) error {
	if generation == 0 {
		return errors.New("active path generation must be non-zero")
	}
	return backend.apply(ctx, PathState{Active: true, Mode: PathModeTUN, Generation: generation})
}

func (backend *FirewallBackend) ActivateDirectPath(ctx context.Context, uplinkID string, routeGeneration int64) error {
	if backend == nil || backend.Database == nil || backend.Uplinks == nil || backend.Routing == nil || !validInterfaceName(backend.LANName) || strings.TrimSpace(uplinkID) == "" || routeGeneration <= 0 || routeGeneration > math.MaxUint32 {
		return errors.New("bounded authoritative direct path activation is required")
	}
	if err := backend.Routing.SyncRouting(ctx); err != nil {
		return fmt.Errorf("synchronize direct uplink routing before activation: %w", err)
	}
	currentUplink, err := backend.Uplinks.Get(ctx, uplinkID)
	if err != nil || !currentUplink.Enabled || currentUplink.State != uplink.StateReady || currentUplink.RouteGeneration != routeGeneration || !validInterfaceName(currentUplink.CurrentIfname) || currentUplink.Fwmark == 0 {
		return errors.New("direct activation uplink context is unavailable or stale")
	}
	var configGeneration int64
	err = backend.Database.QueryRowContext(ctx, `
SELECT r.config_generation
FROM runtime_state AS r
JOIN direct_uplink_paths AS p ON p.id=r.active_direct_path_id AND p.uplink_id=r.active_uplink_id
JOIN access_methods AS a ON a.id=r.active_method_id AND a.id='access:direct'
JOIN uplinks AS u ON u.id=p.uplink_id
WHERE r.singleton_id=1 AND r.gateway_state='VERIFYING' AND r.path_state='PATH_VERIFYING'
  AND r.active_method_kind='DIRECT' AND r.active_subscription_id IS NULL AND r.active_node_id IS NULL
  AND r.active_path_id IS NULL AND r.active_direct_path_id IS NOT NULL
  AND r.active_uplink_id=? AND p.route_generation=? AND p.route_generation=u.route_generation
  AND p.quality_class IN ('FULL', 'LIMITED', 'WHITELIST_ONLY') AND julianday(p.expires_at)>julianday(?)
  AND p.policy_generation=COALESCE(CAST((SELECT value_json FROM settings WHERE key='next_policy_generation') AS INTEGER)-1, 0)
  AND a.enabled=1 AND u.enabled=1 AND u.state='UPLINK_READY'`,
		uplinkID, routeGeneration, time.Now().UTC().Format(time.RFC3339Nano)).Scan(&configGeneration)
	if errors.Is(err, sql.ErrNoRows) {
		return errors.New("direct activation intent or fresh evidence is unavailable")
	}
	if err != nil {
		return fmt.Errorf("read authoritative direct activation intent: %w", err)
	}
	if configGeneration <= 0 || configGeneration > math.MaxUint32 {
		return errors.New("direct activation config generation is invalid")
	}
	return backend.apply(ctx, PathState{
		Active: true, Mode: PathModeDirect, Generation: uint32(configGeneration),
		DirectInterface: currentUplink.CurrentIfname, DirectMark: uint32(currentUplink.Fwmark),
		RouteGeneration: uint32(routeGeneration),
	})
}

func (backend *FirewallBackend) BlockPath(ctx context.Context) error {
	return backend.apply(ctx, PathState{})
}

func (backend *FirewallBackend) ObservePath(ctx context.Context) (PathState, error) {
	if err := backend.validate(); err != nil {
		return PathState{}, err
	}
	result, err := backend.Executor.Run(ctx, platformexec.Request{Executable: backend.NFT, Arguments: []string{"--json", "list", "table", "inet", firewall.TableName}})
	if err != nil {
		return PathState{}, fmt.Errorf("observe owned data-plane table: %w", err)
	}
	state, err := decodePathState([]byte(result.Stdout), backend.TUNName, backend.LANName)
	if err != nil {
		return PathState{}, fmt.Errorf("decode owned data-plane state: %w", err)
	}
	return state, nil
}

func (backend *FirewallBackend) apply(ctx context.Context, desired PathState) error {
	backend.mutex.Lock()
	defer backend.mutex.Unlock()
	if err := backend.validate(); err != nil {
		return err
	}
	current, err := backend.Executor.Run(ctx, platformexec.Request{Executable: backend.NFT, Arguments: []string{"list", "table", "inet", firewall.TableName}})
	if err != nil {
		return fmt.Errorf("inspect owned data-plane table: %w", err)
	}
	for _, marker := range []string{
		"table inet " + firewall.TableName,
		"set firewall_schema_generation",
		"set " + activeTUNSet,
		"set " + activeDirectInterfaceSet,
		"set " + activeDirectContextSet,
		"map " + activeDirectMarkMap,
		"set " + activeGenerationSet,
		"set " + activeRouteGenerationSet,
		"set user_ingress_interfaces",
		"set wireguard_ingress_listeners",
		"set " + wireGuardAllowedV4Set,
		"chain forward_mss",
		"hook forward priority mangle; policy accept",
		"tcp flags syn tcp option maxseg size set rt mtu",
		"hook forward priority filter; policy drop",
		"gateway-vpn PATH_BLOCKED",
		"oifname @" + activeTUNSet,
		"oifname . meta mark @" + activeDirectContextSet,
		"map @" + activeDirectMarkMap,
		"iifname . udp dport @wireguard_ingress_listeners",
		"counter user_upload",
		"counter user_download",
		"counter service_upload",
		"counter service_download",
	} {
		if !strings.Contains(current.Stdout, marker) {
			return fmt.Errorf("owned data-plane table is missing integrity marker %q", marker)
		}
	}
	generation, err := backend.Executor.Run(ctx, platformexec.Request{Executable: backend.NFT, Arguments: []string{"--json", "list", "set", "inet", firewall.TableName, firewall.SchemaGenerationSet}})
	if err != nil {
		return errors.New("owned data-plane schema generation is unavailable")
	}
	if err := firewall.ValidateSchemaGenerationJSON([]byte(generation.Stdout)); err != nil {
		return fmt.Errorf("validate owned data-plane schema generation: %w", err)
	}
	var wireGuardSources []string
	if desired.Active {
		wireGuardSources, err = backend.allowedWireGuardSources(ctx)
		if err != nil {
			return fmt.Errorf("resolve WireGuard ingress access policy: %w", err)
		}
	}
	payload, err := renderPathTransaction(desired, backend.TUNName, backend.LANName, wireGuardSources)
	if err != nil {
		return err
	}
	if result, err := backend.Executor.Run(ctx, platformexec.Request{Executable: backend.NFT, Arguments: []string{"--check", "--file", "-"}, Stdin: payload}); err != nil {
		return fmt.Errorf("validate atomic data-plane state: %s: %w", bounded(result.Stderr), err)
	}
	if result, err := backend.Executor.Run(ctx, platformexec.Request{Executable: backend.NFT, Arguments: []string{"--file", "-"}, Stdin: payload}); err != nil {
		return fmt.Errorf("apply atomic data-plane state: %s: %w", bounded(result.Stderr), err)
	}
	observed, err := backend.ObservePath(ctx)
	if err != nil {
		return err
	}
	if observed != desired {
		return fmt.Errorf("data-plane state verification mismatch: observed=%+v desired=%+v", observed, desired)
	}
	return nil
}

func (backend *FirewallBackend) validate() error {
	if backend == nil || backend.Executor == nil || backend.NFT != "/usr/sbin/nft" || !validInterfaceName(backend.TUNName) || !validInterfaceName(backend.LANName) {
		return errors.New("fixed Ubuntu nft executor and valid Mihomo TUN/LAN interfaces are required")
	}
	return nil
}

func renderPathTransaction(state PathState, tunName, lanName string, wireGuardSources []string) ([]byte, error) {
	if state.Active {
		switch state.Mode {
		case PathModeTUN:
			if state.Generation == 0 || state.DirectInterface != "" || state.DirectMark != 0 || state.RouteGeneration != 0 {
				return nil, errors.New("TUN path state is invalid")
			}
		case PathModeDirect:
			if state.Generation == 0 || state.RouteGeneration == 0 || state.DirectMark == 0 || !validInterfaceName(state.DirectInterface) || !validInterfaceName(lanName) {
				return nil, errors.New("direct path state is invalid")
			}
		default:
			return nil, errors.New("active path mode is invalid")
		}
	} else if state != (PathState{}) {
		return nil, errors.New("blocked path state must be empty")
	}
	canonicalSources := make([]string, 0, len(wireGuardSources))
	seenSources := make(map[string]struct{}, len(wireGuardSources))
	for _, value := range wireGuardSources {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(value))
		if err != nil || !prefix.Addr().Is4() || prefix.Addr().IsUnspecified() || prefix.Masked() != prefix {
			return nil, errors.New("WireGuard ingress source policy contains an invalid IPv4 prefix")
		}
		canonical := prefix.String()
		if _, exists := seenSources[canonical]; exists {
			continue
		}
		seenSources[canonical] = struct{}{}
		canonicalSources = append(canonicalSources, canonical)
	}
	sort.Strings(canonicalSources)
	var builder strings.Builder
	builder.WriteString("flush set inet ")
	builder.WriteString(firewall.TableName)
	builder.WriteByte(' ')
	builder.WriteString(activeTUNSet)
	builder.WriteByte('\n')
	builder.WriteString("flush set inet ")
	builder.WriteString(firewall.TableName)
	builder.WriteByte(' ')
	builder.WriteString(activeDirectInterfaceSet)
	builder.WriteByte('\n')
	builder.WriteString("flush set inet ")
	builder.WriteString(firewall.TableName)
	builder.WriteByte(' ')
	builder.WriteString(activeDirectContextSet)
	builder.WriteByte('\n')
	builder.WriteString("flush map inet ")
	builder.WriteString(firewall.TableName)
	builder.WriteByte(' ')
	builder.WriteString(activeDirectMarkMap)
	builder.WriteByte('\n')
	builder.WriteString("flush set inet ")
	builder.WriteString(firewall.TableName)
	builder.WriteByte(' ')
	builder.WriteString(activeGenerationSet)
	builder.WriteByte('\n')
	builder.WriteString("flush set inet ")
	builder.WriteString(firewall.TableName)
	builder.WriteByte(' ')
	builder.WriteString(activeRouteGenerationSet)
	builder.WriteByte('\n')
	builder.WriteString("flush set inet ")
	builder.WriteString(firewall.TableName)
	builder.WriteByte(' ')
	builder.WriteString(wireGuardAllowedV4Set)
	builder.WriteByte('\n')
	if state.Active {
		for _, prefix := range canonicalSources {
			fmt.Fprintf(&builder, "add element inet %s %s { %s }\n", firewall.TableName, wireGuardAllowedV4Set, prefix)
		}
		builder.WriteString("add element inet ")
		builder.WriteString(firewall.TableName)
		builder.WriteByte(' ')
		builder.WriteString(activeGenerationSet)
		builder.WriteString(" { ")
		builder.WriteString(strconv.FormatUint(uint64(state.Generation), 10))
		builder.WriteString(" }\n")
		if state.Mode == PathModeTUN {
			builder.WriteString("add element inet ")
			builder.WriteString(firewall.TableName)
			builder.WriteByte(' ')
			builder.WriteString(activeTUNSet)
			builder.WriteString(" { ")
			builder.WriteString(strconv.Quote(tunName))
			builder.WriteString(" }\n")
		} else {
			mark := fmt.Sprintf("0x%08x", state.DirectMark)
			fmt.Fprintf(&builder, "add element inet %s %s { %d }\n", firewall.TableName, activeRouteGenerationSet, state.RouteGeneration)
			fmt.Fprintf(&builder, "add element inet %s %s { %s }\n", firewall.TableName, activeDirectInterfaceSet, strconv.Quote(state.DirectInterface))
			fmt.Fprintf(&builder, "add element inet %s %s { %s . %s }\n", firewall.TableName, activeDirectContextSet, strconv.Quote(state.DirectInterface), mark)
			fmt.Fprintf(&builder, "add element inet %s %s { %s : %s }\n", firewall.TableName, activeDirectMarkMap, strconv.Quote(lanName), mark)
			if lanName != wireGuardIngressName {
				fmt.Fprintf(&builder, "add element inet %s %s { %s : %s }\n", firewall.TableName, activeDirectMarkMap, strconv.Quote(wireGuardIngressName), mark)
			}
		}
	}
	return []byte(builder.String()), nil
}

func (backend *FirewallBackend) allowedWireGuardSources(ctx context.Context) ([]string, error) {
	if backend.Database == nil {
		return nil, errors.New("WireGuard ingress policy database is unavailable")
	}
	var methodID, methodKind, quality string
	err := backend.Database.QueryRowContext(ctx, `
SELECT active_method_id, active_method_kind, active_quality_class
FROM runtime_state
WHERE singleton_id=1 AND gateway_state IN ('VERIFYING','ONLINE')
  AND path_state IN ('PATH_VERIFYING','PATH_ACTIVE')
  AND active_method_id IS NOT NULL AND active_method_kind IS NOT NULL
  AND active_quality_class IS NOT NULL`).Scan(&methodID, &methodKind, &quality)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, errors.New("active access method policy is unavailable")
	}
	if err != nil {
		return nil, fmt.Errorf("read active access method policy: %w", err)
	}
	if methodKind != "DIRECT" && methodKind != "SUBSCRIPTION" || methodID == "" {
		return nil, errors.New("active access method identity is invalid")
	}
	if quality != "FULL" && quality != "LIMITED" && quality != "WHITELIST_ONLY" {
		return nil, errors.New("active access method is not qualified")
	}
	rows, err := backend.Database.QueryContext(ctx, `
SELECT p.id, p.assigned_address, p.access_policy_mode,
       p.allow_whitelist_only, p.block_when_unqualified,
       (SELECT COUNT(*) FROM wireguard_ingress_peer_access_methods AS a WHERE a.peer_id=p.id),
       (SELECT COUNT(*) FROM wireguard_ingress_peer_access_methods AS a WHERE a.peer_id=p.id AND a.access_method_id=?),
       r.cidr
FROM wireguard_ingress_peers AS p
LEFT JOIN wireguard_ingress_peer_routes AS r
  ON r.peer_id=p.id AND r.direction='INGRESS'
WHERE p.enabled=1 AND p.revoked_at IS NULL
ORDER BY p.display_number, r.cidr`, methodID)
	if err != nil {
		return nil, fmt.Errorf("read WireGuard ingress peer policy: %w", err)
	}
	defer rows.Close()
	allowedPeers := make(map[string]bool)
	seenPeers := make(map[string]bool)
	prefixes := make(map[string]struct{})
	for rows.Next() {
		var peerID, assigned, mode string
		var allowWhitelist, blockUnqualified, methodCount, selectedCount int
		var route sql.NullString
		if err := rows.Scan(&peerID, &assigned, &mode, &allowWhitelist, &blockUnqualified, &methodCount, &selectedCount, &route); err != nil {
			return nil, err
		}
		if !seenPeers[peerID] {
			modeMatches := mode == "AUTO" || mode == "DIRECT_ONLY" && methodKind == "DIRECT" || mode == "VPN_ONLY" && methodKind == "SUBSCRIPTION"
			methodMatches := methodCount == 0 || selectedCount == 1
			qualified := modeMatches && methodMatches
			allowedPeers[peerID] = (qualified || blockUnqualified == 0) && (quality != "WHITELIST_ONLY" || allowWhitelist != 0)
			seenPeers[peerID] = true
			address, parseErr := netip.ParseAddr(assigned)
			if parseErr != nil || !address.Is4() || address.IsUnspecified() {
				return nil, errors.New("stored WireGuard ingress peer address is invalid")
			}
			if allowedPeers[peerID] {
				prefixes[netip.PrefixFrom(address, 32).String()] = struct{}{}
			}
		}
		if route.Valid && allowedPeers[peerID] {
			prefix, parseErr := netip.ParsePrefix(route.String)
			if parseErr != nil || !prefix.Addr().Is4() || prefix.Addr().IsUnspecified() || prefix.Masked() != prefix {
				return nil, errors.New("stored WireGuard ingress peer route is invalid")
			}
			prefixes[prefix.String()] = struct{}{}
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	result := make([]string, 0, len(prefixes))
	for prefix := range prefixes {
		result = append(result, prefix)
	}
	sort.Strings(result)
	return result, nil
}

func decodePathState(payload []byte, tunName, lanName string) (PathState, error) {
	if !validInterfaceName(tunName) || !validInterfaceName(lanName) {
		return PathState{}, errors.New("valid TUN and LAN interfaces are required")
	}
	var document struct {
		NFTables []map[string]json.RawMessage `json:"nftables"`
	}
	if err := json.Unmarshal(payload, &document); err != nil {
		return PathState{}, err
	}
	foundTUN, foundDirectInterfaces, foundDirectContext := false, false, false
	foundDirectMarks, foundGeneration, foundRouteGeneration := false, false, false
	var tunElements, directInterfaceElements, directContextElements []any
	var directMarkElements, generationElements, routeGenerationElements []any
	for _, object := range document.NFTables {
		raw, exists := object["set"]
		isMap := false
		if !exists {
			raw, exists = object["map"]
			isMap = exists
		}
		if !exists {
			continue
		}
		var set struct {
			Family string `json:"family"`
			Table  string `json:"table"`
			Name   string `json:"name"`
			Elem   []any  `json:"elem"`
		}
		if err := json.Unmarshal(raw, &set); err != nil {
			return PathState{}, err
		}
		if set.Family != "inet" || set.Table != firewall.TableName {
			continue
		}
		switch set.Name {
		case activeTUNSet:
			foundTUN, tunElements = true, set.Elem
		case activeDirectInterfaceSet:
			foundDirectInterfaces, directInterfaceElements = true, set.Elem
		case activeDirectContextSet:
			foundDirectContext, directContextElements = true, set.Elem
		case activeDirectMarkMap:
			if !isMap && len(set.Elem) != 0 {
				return PathState{}, errors.New("active direct mark object is not a map")
			}
			foundDirectMarks, directMarkElements = true, set.Elem
		case activeGenerationSet:
			foundGeneration, generationElements = true, set.Elem
		case activeRouteGenerationSet:
			foundRouteGeneration, routeGenerationElements = true, set.Elem
		}
	}
	if !foundTUN || !foundDirectInterfaces || !foundDirectContext || !foundDirectMarks || !foundGeneration || !foundRouteGeneration {
		return PathState{}, errors.New("active path sets are missing")
	}
	if len(tunElements) == 0 && len(directInterfaceElements) == 0 && len(directContextElements) == 0 && len(directMarkElements) == 0 && len(generationElements) == 0 && len(routeGenerationElements) == 0 {
		return PathState{}, nil
	}
	if len(generationElements) != 1 {
		return PathState{}, errors.New("active path generation cardinality is invalid")
	}
	generation, ok := uint32Element(generationElements[0])
	if !ok || generation == 0 {
		return PathState{}, errors.New("active path generation is invalid")
	}
	if len(tunElements) == 1 && stringElement(tunElements[0]) == tunName {
		if len(directInterfaceElements) != 0 || len(directContextElements) != 0 || len(directMarkElements) != 0 || len(routeGenerationElements) != 0 {
			return PathState{}, errors.New("TUN and direct path gates are active together")
		}
		return PathState{Active: true, Mode: PathModeTUN, Generation: generation}, nil
	}
	if len(tunElements) != 0 || len(directInterfaceElements) != 1 || len(directContextElements) != 1 || len(directMarkElements) != 2 || len(routeGenerationElements) != 1 {
		return PathState{}, errors.New("active direct path set cardinality is invalid")
	}
	interfaceName := stringElement(directInterfaceElements[0])
	contextInterface, mark, ok := directContextElement(directContextElements[0])
	if !ok || !validInterfaceName(interfaceName) || contextInterface != interfaceName || mark == 0 {
		return PathState{}, errors.New("active direct path context is invalid")
	}
	markMap := make(map[string]uint32, len(directMarkElements))
	for _, element := range directMarkElements {
		mapInterface, mapMark, valid := directMapElement(element)
		if !valid || mapMark != mark {
			return PathState{}, errors.New("active direct mark map is invalid")
		}
		markMap[mapInterface] = mapMark
	}
	if len(markMap) != 2 || markMap[lanName] != mark || markMap[wireGuardIngressName] != mark {
		return PathState{}, errors.New("active direct ingress mark map is incomplete")
	}
	routeGeneration, ok := uint32Element(routeGenerationElements[0])
	if !ok || routeGeneration == 0 {
		return PathState{}, errors.New("active direct route generation is invalid")
	}
	return PathState{Active: true, Mode: PathModeDirect, Generation: generation, DirectInterface: interfaceName, DirectMark: mark, RouteGeneration: routeGeneration}, nil
}

func stringElement(value any) string {
	switch typed := value.(type) {
	case string:
		return typed
	case map[string]any:
		if nested, ok := typed["val"].(string); ok {
			return nested
		}
	}
	return ""
}

func uint32Element(value any) (uint32, bool) {
	if object, ok := value.(map[string]any); ok {
		value = object["val"]
	}
	if text, ok := value.(string); ok {
		number, err := strconv.ParseUint(text, 0, 32)
		return uint32(number), err == nil && number > 0
	}
	number, ok := value.(float64)
	if !ok || number < 1 || number > math.MaxUint32 || math.Trunc(number) != number {
		return 0, false
	}
	return uint32(number), true
}

func directMapElement(value any) (string, uint32, bool) {
	if object, ok := value.(map[string]any); ok {
		for _, wrapper := range []string{"elem", "map"} {
			if nested, exists := object[wrapper]; exists {
				if interfaceName, mark, valid := directMapElement(nested); valid {
					return interfaceName, mark, true
				}
			}
		}
		key, keyExists := object["val"]
		if !keyExists {
			key, keyExists = object["key"]
		}
		data, dataExists := object["data"]
		if keyExists && dataExists {
			interfaceName := stringElement(key)
			mark, valid := uint32Element(data)
			return interfaceName, mark, valid && interfaceName != ""
		}
	}
	if values, ok := value.([]any); ok && len(values) == 2 {
		interfaceName := stringElement(values[0])
		mark, valid := uint32Element(values[1])
		return interfaceName, mark, valid && interfaceName != ""
	}
	return "", 0, false
}

func directContextElement(value any) (string, uint32, bool) {
	if object, ok := value.(map[string]any); ok {
		for _, key := range []string{"val", "elem"} {
			if nested, exists := object[key]; exists {
				if interfaceName, mark, valid := directContextElement(nested); valid {
					return interfaceName, mark, true
				}
			}
		}
		if concat, ok := object["concat"].([]any); ok && len(concat) == 2 {
			interfaceName := stringElement(concat[0])
			mark, valid := uint32Element(concat[1])
			return interfaceName, mark, valid && interfaceName != ""
		}
	}
	if values, ok := value.([]any); ok && len(values) == 2 {
		interfaceName := stringElement(values[0])
		mark, valid := uint32Element(values[1])
		return interfaceName, mark, valid && interfaceName != ""
	}
	return "", 0, false
}

func bounded(value string) string {
	value = strings.TrimSpace(value)
	if len(value) > 512 {
		return value[:512]
	}
	return value
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
