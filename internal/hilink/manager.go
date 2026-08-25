package hilink

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"sync"

	"gateway-vpn/internal/modem"
	"gateway-vpn/internal/networkplan"
)

type LeaseReader interface {
	Lease(context.Context, string) (Lease, error)
}

type RouteController interface {
	ApplyPlan(context.Context, networkplan.Plan) error
	RemoveModem(context.Context, modem.Modem) error
}

type Manager struct {
	mutex           sync.Mutex
	Probe           Probe
	LeaseReader     LeaseReader
	Routes          RouteController
	Modems          *modem.Repository
	IdentitySalt    []byte
	VendorIDs       []string
	LANPrefix       string
	WireGuardPrefix string
}

type CycleResult struct {
	Matches        []Match
	ReadyModems    []string
	OfflineModems  []string
	ConflictModems map[string]string
	Errors         map[string]string
}

func (manager *Manager) Reconcile(ctx context.Context) (CycleResult, error) {
	manager.mutex.Lock()
	defer manager.mutex.Unlock()
	if manager.Probe == nil || manager.LeaseReader == nil || manager.Routes == nil || manager.Modems == nil {
		return CycleResult{}, errors.New("complete HiLink manager dependencies are required")
	}
	candidates, err := Discover(ctx, manager.Probe, Options{IdentitySalt: manager.IdentitySalt, VendorIDs: manager.VendorIDs})
	if err != nil {
		return CycleResult{}, err
	}
	adopted, err := manager.Modems.List(ctx)
	if err != nil {
		return CycleResult{}, err
	}
	matches := MatchAdopted(candidates, adopted)
	result := CycleResult{Matches: matches, ConflictModems: make(map[string]string), Errors: make(map[string]string)}
	records := make(map[string]modem.Modem, len(adopted))
	for _, record := range adopted {
		records[record.ID] = record
	}
	seen := make(map[string]bool)
	leases := make(map[string]Lease)
	for _, match := range matches {
		if match.State != DiscoveryMatched {
			continue
		}
		record := records[match.ModemID]
		seen[record.ID] = true
		if !record.Enabled {
			continue
		}
		if !match.Candidate.Carrier {
			if err := manager.removeAndMarkOffline(ctx, record); err != nil {
				result.Errors[record.ID] = err.Error()
			} else {
				result.OfflineModems = append(result.OfflineModems, record.ID)
			}
			continue
		}
		lease, err := manager.LeaseReader.Lease(ctx, match.Candidate.InterfaceName)
		if err != nil {
			_ = manager.Modems.SetObservedState(ctx, record.ID, modem.StateConfiguring)
			result.Errors[record.ID] = err.Error()
			continue
		}
		leases[record.ID] = lease
	}
	for _, record := range adopted {
		if !record.Enabled || seen[record.ID] || record.State == modem.StateConfiguredOffline || record.State == modem.StateDisabled {
			continue
		}
		if err := manager.removeAndMarkOffline(ctx, record); err != nil {
			result.Errors[record.ID] = err.Error()
		} else {
			result.OfflineModems = append(result.OfflineModems, record.ID)
		}
	}
	conflicts, err := DetectLeaseConflicts(manager.LANPrefix, manager.WireGuardPrefix, leases)
	if err != nil {
		return result, err
	}
	inputs := make([]networkplan.ModemInput, 0, len(leases))
	for modemID, lease := range leases {
		record := records[modemID]
		if reason := conflicts[modemID]; reason != "" {
			result.ConflictModems[modemID] = reason
			if _, applyErr := manager.Modems.ApplyLease(ctx, modemID, leaseInput(lease, modem.StateSubnetConflict)); applyErr != nil {
				result.Errors[modemID] = applyErr.Error()
			}
			continue
		}
		inputs = append(inputs, networkplan.ModemInput{ID: modemID, Priority: record.Priority, InterfaceName: lease.InterfaceName, ManagementPrefix: lease.ManagementPrefix.String(), Gateway: lease.Gateway.String(), RoutingTableID: record.RoutingTableID, Fwmark: record.Fwmark})
	}
	readyInputs := make([]networkplan.ModemInput, 0, len(inputs))
	for _, input := range inputs {
		if _, err := manager.Modems.ApplyLease(ctx, input.ID, leaseInput(leases[input.ID], modem.StateReady)); err != nil {
			result.Errors[input.ID] = err.Error()
			continue
		}
		readyInputs = append(readyInputs, input)
	}
	plan, err := networkplan.Build(networkplan.Input{LANPrefix: manager.LANPrefix, WireGuardPrefix: manager.WireGuardPrefix, Modems: readyInputs})
	if err != nil {
		return result, err
	}
	if err := manager.Routes.ApplyPlan(ctx, plan); err != nil {
		cleanupErrors := []error{fmt.Errorf("apply HiLink route plan: %w", err)}
		for _, input := range readyInputs {
			_ = manager.Modems.SetObservedState(ctx, input.ID, modem.StateError)
			if current, getErr := manager.Modems.Get(ctx, input.ID); getErr == nil {
				cleanupErrors = append(cleanupErrors, manager.Routes.RemoveModem(context.WithoutCancel(ctx), current))
			}
			result.Errors[input.ID] = "ROUTING_SYNC_FAILED"
		}
		return result, errors.Join(cleanupErrors...)
	}
	for _, input := range readyInputs {
		result.ReadyModems = append(result.ReadyModems, input.ID)
	}
	sort.Strings(result.ReadyModems)
	sort.Strings(result.OfflineModems)
	return result, nil
}

func (manager *Manager) removeAndMarkOffline(ctx context.Context, record modem.Modem) error {
	if err := manager.Modems.MarkOffline(ctx, record.ID); err != nil {
		return err
	}
	return manager.Routes.RemoveModem(ctx, record)
}

func DetectLeaseConflicts(lanPrefix, wireGuardPrefix string, leases map[string]Lease) (map[string]string, error) {
	lan, err := netip.ParsePrefix(lanPrefix)
	if err != nil || !lan.Addr().Is4() {
		return nil, errors.New("LAN prefix must be IPv4")
	}
	wireGuard, err := netip.ParsePrefix(wireGuardPrefix)
	if err != nil || !wireGuard.Addr().Is4() {
		return nil, errors.New("WireGuard prefix must be IPv4")
	}
	result := make(map[string]string)
	ids := make([]string, 0, len(leases))
	for id, lease := range leases {
		ids = append(ids, id)
		if lease.ManagementPrefix.Overlaps(lan) || lease.ManagementPrefix.Overlaps(wireGuard) {
			result[id] = "management subnet overlaps transit LAN or WireGuard"
		}
	}
	sort.Strings(ids)
	for left := 0; left < len(ids); left++ {
		for right := left + 1; right < len(ids); right++ {
			if leases[ids[left]].ManagementPrefix.Overlaps(leases[ids[right]].ManagementPrefix) {
				result[ids[left]] = "management subnet overlaps modem " + ids[right]
				result[ids[right]] = "management subnet overlaps modem " + ids[left]
			}
		}
	}
	return result, nil
}

func leaseInput(lease Lease, state string) modem.LeaseInput {
	dns := make([]string, len(lease.DNS))
	for index, address := range lease.DNS {
		dns[index] = address.String()
	}
	return modem.LeaseInput{InterfaceName: lease.InterfaceName, ManagementCIDR: lease.ManagementPrefix.String(), Gateway: lease.Gateway.String(), DNS: dns, MTU: int64(lease.MTU), State: state}
}
