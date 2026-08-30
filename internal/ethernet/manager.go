// Package ethernet observes generic physical Ethernet uplinks. It owns no
// privileged mutation: persistent networkd changes use safe apply, while
// policy routing is reconciled by the parameterless root broker.
package ethernet

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"sync"

	"gateway-vpn/internal/hilink"
	"gateway-vpn/internal/uplink"
)

const (
	ReasonReady                = "READY"
	ReasonDisabled             = "DISABLED_BY_USER"
	ReasonSafeApplyPending     = "SAFE_APPLY_CONFIRMATION_PENDING"
	ReasonDeviceAbsent         = "DEVICE_ABSENT"
	ReasonCarrierDown          = "CARRIER_DOWN"
	ReasonCarrierUnknown       = "CARRIER_UNKNOWN"
	ReasonDHCPLeaseMissing     = "DHCP_LEASE_MISSING"
	ReasonStaticAddressMissing = "STATIC_ADDRESS_MISSING"
	ReasonSubnetConflict       = "SUBNET_CONFLICT"
	ReasonRoutingSyncFailed    = "ROUTING_SYNC_FAILED"
)

type Device struct {
	Observation  uplink.InterfaceObservation
	MasterIfname string
	MTU          int64
}

type Probe interface {
	List(context.Context) ([]Device, error)
}

type LeaseReader interface {
	Lease(context.Context, string) (hilink.Lease, error)
}

type RoutingSynchronizer interface {
	SyncRouting(context.Context) error
}

type Manager struct {
	mutex           sync.Mutex
	Probe           Probe
	LeaseReader     LeaseReader
	Routes          RoutingSynchronizer
	Uplinks         *uplink.Repository
	LANInterface    string
	LANPrefix       string
	WireGuardPrefix string
}

type CycleResult struct {
	ObservedInterfaces []string
	ImportedLANMembers []string
	ReadyUplinks       []string
	OfflineUplinks     []string
	ConflictUplinks    map[string]string
	Reasons            map[string]string
	RouteChanges       []string
	Errors             map[string]string
}

type candidate struct {
	uplink     uplink.Uplink
	device     Device
	cidr       string
	gateway    string
	dns        []string
	state      string
	reason     string
	converged  bool
	routeMoved bool
	prefix     netip.Prefix
}

func (manager *Manager) Reconcile(ctx context.Context) (CycleResult, error) {
	manager.mutex.Lock()
	defer manager.mutex.Unlock()
	if manager.Probe == nil || manager.LeaseReader == nil || manager.Routes == nil || manager.Uplinks == nil {
		return CycleResult{}, errors.New("complete Ethernet observer dependencies are required")
	}
	lan, err := parseNetwork(manager.LANPrefix)
	if err != nil {
		return CycleResult{}, fmt.Errorf("invalid LAN prefix: %w", err)
	}
	wireGuard, err := parseNetwork(manager.WireGuardPrefix)
	if err != nil {
		return CycleResult{}, fmt.Errorf("invalid WireGuard prefix: %w", err)
	}
	if lan.Overlaps(wireGuard) {
		return CycleResult{}, errors.New("LAN and WireGuard prefixes overlap")
	}
	before, err := manager.Uplinks.ListInterfaces(ctx)
	if err != nil {
		return CycleResult{}, err
	}
	previousIfname := make(map[string]string, len(before))
	hiLinkIfnames := make(map[string]struct{})
	for _, item := range before {
		previousIfname[item.ID] = item.CurrentIfname
		for _, role := range item.Roles {
			if role.Role == "HILINK_UPLINK" && item.CurrentIfname != "" {
				hiLinkIfnames[item.CurrentIfname] = struct{}{}
			}
		}
	}
	devices, err := manager.Probe.List(ctx)
	if err != nil {
		return CycleResult{}, fmt.Errorf("observe physical Ethernet inventory: %w", err)
	}
	result := CycleResult{ConflictUplinks: map[string]string{}, Reasons: map[string]string{}, Errors: map[string]string{}}
	seen := make(map[string]struct{}, len(devices))
	byID := make(map[string]Device, len(devices))
	for _, device := range devices {
		if _, hiLink := hiLinkIfnames[device.Observation.CurrentIfname]; hiLink {
			continue
		}
		if _, duplicate := seen[device.Observation.ID]; duplicate {
			return result, fmt.Errorf("duplicate Ethernet stable identity %s", device.Observation.ID)
		}
		if _, err := manager.Uplinks.ObserveInterface(ctx, device.Observation); err != nil {
			return result, err
		}
		seen[device.Observation.ID] = struct{}{}
		byID[device.Observation.ID] = device
		result.ObservedInterfaces = append(result.ObservedInterfaces, device.Observation.ID)
	}
	if manager.LANInterface != "" {
		observations := make([]uplink.InitialLANObservation, 0, len(byID))
		for _, device := range byID {
			observations = append(observations, uplink.InitialLANObservation{
				NetworkInterfaceID: device.Observation.ID,
				CurrentIfname:      device.Observation.CurrentIfname,
				MasterIfname:       device.MasterIfname,
			})
		}
		result.ImportedLANMembers, err = manager.Uplinks.SeedInitialLANRoles(ctx, manager.LANInterface, observations)
		if err != nil {
			return result, fmt.Errorf("import installer LAN interface roles: %w", err)
		}
	}
	if err := manager.Uplinks.MarkUnseenEthernetInterfacesAbsent(ctx, seen); err != nil {
		return result, err
	}
	stored, err := manager.Uplinks.List(ctx)
	if err != nil {
		return result, err
	}
	candidates := make(map[string]*candidate)
	occupied := []struct {
		id     string
		prefix netip.Prefix
	}{}
	for _, item := range stored {
		if item.Type == uplink.TypeHiLink && item.Enabled && item.State == uplink.StateReady {
			prefix, parseErr := parseNetwork(item.IPv4CIDR)
			if parseErr == nil {
				occupied = append(occupied, struct {
					id     string
					prefix netip.Prefix
				}{id: item.ID, prefix: prefix})
			}
		}
		if item.Type != uplink.TypeEthernet {
			continue
		}
		current := &candidate{uplink: item, state: uplink.StateConfiguredOffline, reason: ReasonDeviceAbsent}
		candidates[item.ID] = current
		if !item.Enabled {
			current.state, current.reason = uplink.StateDisabled, ReasonDisabled
			continue
		}
		pending, pendingErr := manager.Uplinks.EthernetApplyInProgress(ctx, item.ID)
		if pendingErr != nil {
			result.Errors[item.ID] = "SAFE_APPLY_STATE_INVALID"
			continue
		}
		if pending {
			current.state, current.reason = uplink.StateConfiguring, ReasonSafeApplyPending
			continue
		}
		device, present := byID[item.NetworkInterfaceID]
		if !present {
			continue
		}
		current.device = device
		current.routeMoved = previousIfname[item.NetworkInterfaceID] != "" && previousIfname[item.NetworkInterfaceID] != device.Observation.CurrentIfname
		switch device.Observation.CarrierState {
		case "DOWN":
			current.reason = ReasonCarrierDown
			continue
		case "UP":
		default:
			current.state, current.reason = uplink.StateConfiguring, ReasonCarrierUnknown
			continue
		}
		if item.AddressMode == uplink.AddressDHCP {
			lease, leaseErr := manager.LeaseReader.Lease(ctx, device.Observation.CurrentIfname)
			if leaseErr != nil {
				current.state, current.reason = uplink.StateConfiguring, ReasonDHCPLeaseMissing
				continue
			}
			current.cidr = lease.Address.String()
			current.gateway = lease.Gateway.String()
			if err := json.Unmarshal([]byte(item.ConfiguredDNSJSON), &current.dns); err != nil {
				result.Errors[item.ID] = "STORED_CONFIGURED_DNS_INVALID"
				continue
			}
			if len(current.dns) == 0 {
				for _, address := range lease.DNS {
					current.dns = append(current.dns, address.String())
				}
			}
		} else {
			if !containsAddress(device.Observation.Addresses, item.ConfiguredIPv4CIDR) {
				current.state, current.reason = uplink.StateConfiguring, ReasonStaticAddressMissing
				continue
			}
			current.cidr, current.gateway = item.ConfiguredIPv4CIDR, item.ConfiguredGateway
			if err := json.Unmarshal([]byte(item.ConfiguredDNSJSON), &current.dns); err != nil {
				result.Errors[item.ID] = "STORED_DNS_INVALID"
				continue
			}
		}
		prefix, parseErr := parseNetwork(current.cidr)
		if parseErr != nil {
			result.Errors[item.ID] = "IPV4_CONTEXT_INVALID"
			continue
		}
		current.prefix, current.converged = prefix, true
		current.state, current.reason = uplink.StateReady, ReasonReady
		if prefix.Overlaps(lan) || prefix.Overlaps(wireGuard) {
			current.state, current.reason = uplink.StateSubnetConflict, ReasonSubnetConflict
			result.ConflictUplinks[item.ID] = "overlaps Gateway LAN or WireGuard"
		}
	}
	ids := make([]string, 0, len(candidates))
	for id := range candidates {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		current := candidates[id]
		if !current.converged || current.state == uplink.StateSubnetConflict {
			continue
		}
		for _, other := range occupied {
			if current.prefix.Overlaps(other.prefix) {
				current.state, current.reason = uplink.StateSubnetConflict, ReasonSubnetConflict
				result.ConflictUplinks[id] = "overlaps uplink " + other.id
			}
		}
	}
	for left := 0; left < len(ids); left++ {
		first := candidates[ids[left]]
		if !first.converged {
			continue
		}
		for right := left + 1; right < len(ids); right++ {
			second := candidates[ids[right]]
			if second.converged && first.prefix.Overlaps(second.prefix) {
				first.state, first.reason = uplink.StateSubnetConflict, ReasonSubnetConflict
				second.state, second.reason = uplink.StateSubnetConflict, ReasonSubnetConflict
				result.ConflictUplinks[ids[left]] = "overlaps uplink " + ids[right]
				result.ConflictUplinks[ids[right]] = "overlaps uplink " + ids[left]
			}
		}
	}
	for _, id := range ids {
		current := candidates[id]
		observation := uplink.EthernetRuntimeObservation{
			NetworkInterfaceID:   current.uplink.NetworkInterfaceID,
			InterfaceName:        current.device.Observation.CurrentIfname,
			IPv4CIDR:             current.cidr,
			Gateway:              current.gateway,
			DNS:                  append([]string(nil), current.dns...),
			State:                current.state,
			ReadinessReason:      current.reason,
			ConfigurationSeen:    current.converged,
			RouteIdentityChanged: current.routeMoved,
		}
		update, observeErr := manager.Uplinks.ObserveEthernetRuntime(ctx, id, observation)
		if observeErr != nil {
			result.Errors[id] = stableError(observeErr)
			continue
		}
		result.Reasons[id] = current.reason
		if update.RouteContextChanged {
			result.RouteChanges = append(result.RouteChanges, id)
		}
		if current.state == uplink.StateReady {
			result.ReadyUplinks = append(result.ReadyUplinks, id)
		} else {
			result.OfflineUplinks = append(result.OfflineUplinks, id)
		}
	}
	if err := manager.Routes.SyncRouting(ctx); err != nil {
		for _, id := range result.ReadyUplinks {
			current := candidates[id]
			_, markErr := manager.Uplinks.ObserveEthernetRuntime(context.WithoutCancel(ctx), id, uplink.EthernetRuntimeObservation{
				NetworkInterfaceID: current.uplink.NetworkInterfaceID,
				InterfaceName:      current.device.Observation.CurrentIfname,
				State:              uplink.StateConfiguring, ReadinessReason: ReasonRoutingSyncFailed,
			})
			if markErr != nil {
				result.Errors[id] = stableError(markErr)
			} else {
				result.Reasons[id] = ReasonRoutingSyncFailed
			}
		}
		_ = manager.Routes.SyncRouting(context.WithoutCancel(ctx))
		return result, fmt.Errorf("synchronize Ethernet policy routing: %w", err)
	}
	sort.Strings(result.ObservedInterfaces)
	sort.Strings(result.ImportedLANMembers)
	sort.Strings(result.ReadyUplinks)
	sort.Strings(result.OfflineUplinks)
	sort.Strings(result.RouteChanges)
	return result, nil
}

func parseNetwork(value string) (netip.Prefix, error) {
	prefix, err := netip.ParsePrefix(strings.TrimSpace(value))
	if err != nil || !prefix.Addr().Is4() || prefix.Bits() < 8 || prefix.Bits() > 30 {
		return netip.Prefix{}, errors.New("usable IPv4 prefix is required")
	}
	return prefix.Masked(), nil
}

func containsAddress(addresses []string, wanted string) bool {
	wantedPrefix, err := netip.ParsePrefix(wanted)
	if err != nil {
		return false
	}
	for _, raw := range addresses {
		observed, err := netip.ParsePrefix(raw)
		if err == nil && observed == wantedPrefix {
			return true
		}
	}
	return false
}

func stableError(err error) string {
	if errors.Is(err, context.Canceled) {
		return "CANCELLED"
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "TIMEOUT"
	}
	return "ETHERNET_OBSERVATION_FAILED"
}
