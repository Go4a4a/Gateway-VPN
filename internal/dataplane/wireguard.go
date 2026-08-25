package dataplane

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"gateway-vpn/internal/modem"
	"gateway-vpn/internal/platformexec"
	"gateway-vpn/internal/state"
	wireguardpkg "gateway-vpn/internal/wireguard"
)

type WireGuardEndpointAccess interface {
	AuthorizeWireGuardEndpoint(context.Context, modem.Modem, string) error
}

type WireGuardEndpointResolver interface {
	ResolveWireGuardEndpoint(context.Context, modem.Modem, string) ([]string, error)
}

type WireGuardBackend struct {
	mu           sync.Mutex
	Modems       *modem.Repository
	States       *state.Repository
	Runtime      wireguardpkg.RuntimeStore
	Endpoints    WireGuardEndpointAccess
	Executor     platformexec.Executor
	IP           string
	WG           string
	ConfigPath   string
	ProbeTimeout time.Duration
	Policy       wireguardpkg.SelectionPolicy
	Now          func() time.Time
}

const (
	wireGuardEndpointDNSCacheTTL = 5 * time.Minute
	wireGuardEndpointDNSRetryTTL = time.Minute
)

func (backend *WireGuardBackend) SyncWireGuard(ctx context.Context) error {
	backend.mu.Lock()
	defer backend.mu.Unlock()

	if err := backend.validate(); err != nil {
		return err
	}
	configuration, err := wireguardpkg.LoadConfig(backend.ConfigPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("load management WireGuard config: %w", err)
	}
	renderedConfig, err := wireguardpkg.RenderSyncConf(configuration)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(renderedConfig)
	desiredConfigSHA256 := hex.EncodeToString(digest[:])
	now := backend.now().UTC()
	runtimeState, err := backend.Runtime.Get(ctx)
	if err != nil {
		return err
	}
	snapshot, err := backend.States.Get(ctx)
	if err != nil {
		return err
	}
	if runtimeState.CurrentModemID == "" {
		runtimeState.CurrentModemID = snapshot.ManagementModemID
	}
	modems, err := backend.Modems.List(ctx)
	if err != nil {
		return fmt.Errorf("list management modem candidates: %w", err)
	}
	byID := make(map[string]modem.Modem, len(modems))
	for _, item := range modems {
		byID[item.ID] = item
	}
	configChanged := runtimeState.ConfigSHA256 != desiredConfigSHA256
	if runtimeState.CandidateModemID != "" && configChanged {
		if candidate, exists := byID[runtimeState.CandidateModemID]; exists && candidate.Enabled && candidate.State == modem.StateReady {
			if err := backend.Modems.SetManagementReachability(ctx, candidate.ID, "STALE"); err != nil {
				return err
			}
		}
		runtimeState.CandidateModemID = ""
		runtimeState.ProbeStartedAt = ""
		if err := backend.Runtime.Put(ctx, runtimeState, now); err != nil {
			return err
		}
	}
	if runtimeState.CandidateModemID != "" {
		candidate, exists := byID[runtimeState.CandidateModemID]
		candidateReady := exists && candidate.Enabled && candidate.State == modem.StateReady &&
			candidate.InterfaceName == runtimeState.RouteInterface && candidate.Gateway == runtimeState.RouteGateway &&
			candidate.RoutingTableID == runtimeState.RouteTableID && candidate.Fwmark == runtimeState.RouteFwmark
		if !candidateReady {
			runtimeState.CandidateModemID = ""
			runtimeState.ProbeStartedAt = ""
			if err := backend.Runtime.Put(ctx, runtimeState, now); err != nil {
				return err
			}
		}
	}
	if runtimeState.CandidateModemID != "" {
		probeStarted, parseErr := time.Parse(time.RFC3339Nano, runtimeState.ProbeStartedAt)
		if parseErr != nil {
			return errors.New("stored WireGuard probe start is invalid")
		}
		handshake, _ := backend.latestHandshake(ctx, configuration)
		if handshake.After(probeStarted) {
			if err := backend.Modems.SetManagementReachability(ctx, runtimeState.CandidateModemID, "REACHABLE"); err != nil {
				return err
			}
			runtimeState.CurrentModemID = runtimeState.CandidateModemID
			runtimeState.CandidateModemID = ""
			runtimeState.ProbeStartedAt = ""
			runtimeState.LastSwitchAt = now.Format(time.RFC3339Nano)
			runtimeState.LastHandshakeAt = handshake.Format(time.RFC3339Nano)
			if _, _, err := backend.States.SetManagementModem(ctx, runtimeState.CurrentModemID, "WIREGUARD_HANDSHAKE_CONFIRMED"); err != nil {
				return err
			}
			return backend.Runtime.Put(ctx, runtimeState, now)
		}
		if now.Sub(probeStarted) < backend.probeTimeout(configuration) {
			return nil
		}
		if err := backend.Modems.SetManagementReachability(ctx, runtimeState.CandidateModemID, "BLOCKED"); err != nil {
			return err
		}
		runtimeState.CandidateModemID = ""
		runtimeState.ProbeStartedAt = ""
		if err := backend.Runtime.Put(ctx, runtimeState, now); err != nil {
			return err
		}
	}

	lastSwitch, _ := time.Parse(time.RFC3339Nano, runtimeState.LastSwitchAt)
	selection := wireguardpkg.SelectManagementModem(modems, runtimeState.CurrentModemID, lastSwitch, now, backend.selectionPolicy())
	refreshEndpoint := wireGuardEndpointRefreshDue(configuration.Endpoint, runtimeState, now)
	if selection.Modem.ID != "" && (!selection.Changed || selection.Modem.ID == runtimeState.CurrentModemID) && runtimeState.RouteModemID == runtimeState.CurrentModemID && !configChanged && !refreshEndpoint {
		endpointIP, parseErr := netip.ParseAddr(runtimeState.EndpointIP)
		if parseErr == nil && publicIPv4(endpointIP.Unmap()) {
			return backend.Endpoints.AuthorizeWireGuardEndpoint(ctx, selection.Modem, endpointIP.Unmap().String())
		}
	}
	var candidate modem.Modem
	if selection.Modem.ID != "" {
		candidate = selection.Modem
	} else {
		candidate = nextManagementCandidate(modems, now)
	}
	if candidate.ID == "" {
		if _, _, err := backend.States.SetManagementModem(ctx, "", "NO_REACHABLE_MANAGEMENT_MODEM"); err != nil {
			return err
		}
		runtimeState.CurrentModemID = ""
		return backend.Runtime.Put(ctx, runtimeState, now)
	}
	endpointIP, err := backend.resolveEndpoint(ctx, candidate, configuration.Endpoint)
	if err != nil {
		cached, cachedErr := netip.ParseAddr(runtimeState.EndpointIP)
		if !configChanged && candidate.ID == runtimeState.CurrentModemID && runtimeState.RouteModemID == runtimeState.CurrentModemID && wireGuardEndpointHostname(configuration.Endpoint) != "" && cachedErr == nil && publicIPv4(cached.Unmap()) {
			if authorizationErr := backend.Endpoints.AuthorizeWireGuardEndpoint(ctx, candidate, cached.Unmap().String()); authorizationErr != nil {
				return authorizationErr
			}
			runtimeState.EndpointExpiresAt = now.Add(wireGuardEndpointDNSRetryTTL).Format(time.RFC3339Nano)
			return backend.Runtime.Put(ctx, runtimeState, now)
		}
		if stateErr := backend.Modems.SetManagementReachability(ctx, candidate.ID, "BLOCKED"); stateErr != nil {
			return errors.Join(err, stateErr)
		}
		return fmt.Errorf("resolve WireGuard endpoint through modem %s: %w", candidate.ID, err)
	}
	if !configChanged && candidate.ID == runtimeState.CurrentModemID && runtimeState.RouteModemID == runtimeState.CurrentModemID && endpointIP.String() == runtimeState.EndpointIP {
		if err := backend.Endpoints.AuthorizeWireGuardEndpoint(ctx, candidate, endpointIP.String()); err != nil {
			return err
		}
		runtimeState.EndpointResolvedAt = now.Format(time.RFC3339Nano)
		runtimeState.EndpointExpiresAt = now.Add(wireGuardEndpointDNSCacheTTL).Format(time.RFC3339Nano)
		return backend.Runtime.Put(ctx, runtimeState, now)
	}
	if err := backend.Endpoints.AuthorizeWireGuardEndpoint(ctx, candidate, endpointIP.String()); err != nil {
		return err
	}
	previous := runtimeRouteModem(runtimeState)
	previousEndpoint, _ := netip.ParseAddr(runtimeState.EndpointIP)
	configured := configuration
	_, port, _ := net.SplitHostPort(configuration.Endpoint)
	configured.Endpoint = net.JoinHostPort(endpointIP.String(), port)
	controller := wireguardpkg.Controller{Executor: backend.Executor, IPExecutable: backend.IP, WGExecutable: backend.WG, Mutate: true}
	configureOperations, err := wireguardpkg.RenderConfigure(configured, backend.IP, backend.WG)
	if err != nil {
		return err
	}
	if err := controller.Apply(ctx, configureOperations); err != nil {
		return err
	}
	switchOperations, err := wireguardpkg.RenderUplinkSwitch(configuration.InterfaceName, endpointIP, previousEndpoint, previous, candidate, backend.IP, backend.WG)
	if err != nil {
		return err
	}
	if err := controller.Apply(ctx, switchOperations); err != nil {
		return err
	}
	if err := backend.Modems.SetManagementReachability(ctx, candidate.ID, "PROBING"); err != nil {
		return err
	}
	runtimeState.CandidateModemID = candidate.ID
	runtimeState.EndpointIP = endpointIP.String()
	if wireGuardEndpointHostname(configuration.Endpoint) != "" {
		runtimeState.EndpointResolvedAt = now.Format(time.RFC3339Nano)
		runtimeState.EndpointExpiresAt = now.Add(wireGuardEndpointDNSCacheTTL).Format(time.RFC3339Nano)
	} else {
		runtimeState.EndpointResolvedAt = ""
		runtimeState.EndpointExpiresAt = ""
	}
	runtimeState.ProbeStartedAt = now.Format(time.RFC3339Nano)
	runtimeState.ConfigSHA256 = desiredConfigSHA256
	runtimeState.RouteModemID = candidate.ID
	runtimeState.RouteInterface = candidate.InterfaceName
	runtimeState.RouteGateway = candidate.Gateway
	runtimeState.RouteTableID = candidate.RoutingTableID
	runtimeState.RouteFwmark = candidate.Fwmark
	return backend.Runtime.Put(ctx, runtimeState, now)
}

func (backend *WireGuardBackend) validate() error {
	if backend == nil || backend.Modems == nil || backend.States == nil || backend.Runtime.Database == nil || backend.Endpoints == nil || backend.Executor == nil || backend.IP != "/usr/sbin/ip" || backend.WG != "/usr/bin/wg" || !filepath.IsAbs(backend.ConfigPath) {
		return errors.New("complete fixed Ubuntu WireGuard backend is required")
	}
	return nil
}

func (backend *WireGuardBackend) latestHandshake(ctx context.Context, configuration wireguardpkg.Config) (time.Time, error) {
	result, err := backend.Executor.Run(ctx, platformexec.Request{Executable: backend.WG, Arguments: []string{"show", configuration.InterfaceName, "latest-handshakes"}})
	if err != nil {
		return time.Time{}, err
	}
	for _, line := range strings.Split(strings.TrimSpace(result.Stdout), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 || fields[0] != configuration.PeerPublicKey {
			continue
		}
		seconds, err := strconv.ParseInt(fields[1], 10, 64)
		if err != nil || seconds <= 0 {
			return time.Time{}, errors.New("WireGuard handshake timestamp is invalid")
		}
		return time.Unix(seconds, 0).UTC(), nil
	}
	return time.Time{}, errors.New("WireGuard peer handshake is unavailable")
}

func (backend *WireGuardBackend) resolveEndpoint(ctx context.Context, current modem.Modem, endpoint string) (netip.Addr, error) {
	host, _, err := net.SplitHostPort(endpoint)
	if err != nil {
		return netip.Addr{}, err
	}
	if address, err := netip.ParseAddr(host); err == nil {
		address = address.Unmap()
		if !publicIPv4(address) {
			return netip.Addr{}, errors.New("WireGuard endpoint is not public IPv4")
		}
		return address, nil
	}
	resolverBackend, ok := backend.Endpoints.(WireGuardEndpointResolver)
	if !ok {
		return netip.Addr{}, errors.New("hostname endpoint requires service firewall resolver")
	}
	addresses, err := resolverBackend.ResolveWireGuardEndpoint(ctx, current, host)
	if err != nil || len(addresses) == 0 {
		return netip.Addr{}, errors.New("WireGuard endpoint DNS failed")
	}
	address, err := netip.ParseAddr(addresses[0])
	if err != nil || !publicIPv4(address.Unmap()) {
		return netip.Addr{}, errors.New("WireGuard endpoint DNS returned an invalid address")
	}
	return address.Unmap(), nil
}

func nextManagementCandidate(items []modem.Modem, now time.Time) modem.Modem {
	ready := make([]modem.Modem, 0, len(items))
	for _, item := range items {
		if !item.Enabled || item.State != modem.StateReady || item.ManagementReachabilityState == "PROBING" || item.ManagementReachabilityState == "REACHABLE" {
			continue
		}
		if item.ManagementReachabilityState == "BLOCKED" {
			blockedAt, err := time.Parse(time.RFC3339Nano, item.UpdatedAt)
			if err != nil || now.Sub(blockedAt) < 5*time.Minute {
				continue
			}
		}
		ready = append(ready, item)
	}
	sort.SliceStable(ready, func(i, j int) bool {
		if ready[i].Priority == ready[j].Priority {
			return ready[i].DisplayNumber < ready[j].DisplayNumber
		}
		return ready[i].Priority < ready[j].Priority
	})
	if len(ready) == 0 {
		return modem.Modem{}
	}
	return ready[0]
}

func runtimeRouteModem(runtime wireguardpkg.RuntimeState) *modem.Modem {
	if runtime.RouteInterface == "" || runtime.RouteGateway == "" || runtime.RouteTableID < 256 || runtime.RouteFwmark == 0 {
		return nil
	}
	return &modem.Modem{ID: runtime.RouteModemID, InterfaceName: runtime.RouteInterface, Gateway: runtime.RouteGateway, RoutingTableID: runtime.RouteTableID, Fwmark: runtime.RouteFwmark}
}

func wireGuardEndpointHostname(endpoint string) string {
	host, _, err := net.SplitHostPort(endpoint)
	if err != nil {
		return ""
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return ""
	}
	return strings.ToLower(strings.TrimSuffix(host, "."))
}

func wireGuardEndpointRefreshDue(endpoint string, runtimeState wireguardpkg.RuntimeState, now time.Time) bool {
	if wireGuardEndpointHostname(endpoint) == "" {
		return false
	}
	expiresAt, err := time.Parse(time.RFC3339Nano, runtimeState.EndpointExpiresAt)
	return err != nil || !expiresAt.After(now)
}

func (backend *WireGuardBackend) probeTimeout(configuration wireguardpkg.Config) time.Duration {
	if backend.ProbeTimeout > 0 {
		return backend.ProbeTimeout
	}
	return wireguardpkg.HandshakeTimeout(configuration)
}

func (backend *WireGuardBackend) selectionPolicy() wireguardpkg.SelectionPolicy {
	policy := backend.Policy
	if policy.ReconnectStable <= 0 {
		policy.ReconnectStable = 3 * time.Minute
	}
	if policy.FailbackCooldown <= 0 {
		policy.FailbackCooldown = 15 * time.Minute
	}
	return policy
}

func (backend *WireGuardBackend) now() time.Time {
	if backend.Now != nil {
		return backend.Now()
	}
	return time.Now()
}
