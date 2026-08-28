// Package pathruntime binds the reconciler to the selected Mihomo path and the
// privileged nftables TUN gate. Selection and end-to-end verification happen
// while LAN forwarding is blocked. Ordinary activation opens the gate only
// after every enabled required target succeeds. A boot-policy-approved exact
// recovery may use one bounded transport check before full background checks.
package pathruntime

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math"
	"net/url"
	"sync"
	"time"

	"gateway-vpn/internal/accesspolicy"
	"gateway-vpn/internal/bypass"
	"gateway-vpn/internal/dataplane"
	"gateway-vpn/internal/health"
	"gateway-vpn/internal/mihomo"
	"gateway-vpn/internal/reconcile"
	"gateway-vpn/internal/state"
)

type Broker interface {
	ActivatePath(context.Context, uint32) error
	ActivateDirectPath(context.Context, string, int64) error
	BlockPath(context.Context) error
	ObservePath(context.Context) (dataplane.PathState, error)
	FailClosedMihomo(context.Context) error
	AuthorizeMihomoVersions(context.Context, []string) error
}

type MihomoControl interface {
	GetVersion(context.Context) (mihomo.Version, error)
	Select(context.Context, string, string) error
	Selected(context.Context, string) (mihomo.ProxyState, error)
	ProxyDelay(context.Context, string, string, time.Duration, string) (uint16, error)
}

type TUNInspector interface {
	RequireReady(context.Context, string) error
}

type TargetProber interface {
	ProbeTarget(context.Context, health.Path, health.Candidate, health.Target) health.ProbeResult
}

type Actuator struct {
	Database             *sql.DB
	Targets              *bypass.Repository
	Broker               Broker
	Mihomo               MihomoControl
	BodyProber           TargetProber
	StartupProbeURL      string
	StartupProbeTimeout  time.Duration
	StartupProbeExpected string
	Now                  func() time.Time
	OperationLock        sync.Locker

	mutex sync.Mutex
}

type selectedPath struct {
	PathID         string
	UplinkID       string
	SubscriptionID string
	NodeID         string
	VersionID      string
	ExternalName   string
	Names          mihomo.PathNames
}

func (actuator *Actuator) Activate(ctx context.Context, candidate reconcile.Candidate) error {
	actuator.mutex.Lock()
	defer actuator.mutex.Unlock()
	if actuator.OperationLock != nil {
		actuator.OperationLock.Lock()
		defer actuator.OperationLock.Unlock()
	}
	if err := actuator.validate(); err != nil {
		return err
	}
	if candidate.ConfigGeneration <= 0 || candidate.ConfigGeneration > math.MaxUint32 {
		return errors.New("path activation config generation is invalid")
	}
	if err := actuator.Broker.BlockPath(ctx); err != nil {
		return errors.Join(fmt.Errorf("block LAN before path activation: %w", err), actuator.Broker.FailClosedMihomo(ctx))
	}
	if candidate.MethodKind == accesspolicy.MethodDirect {
		if candidate.PathID == "" || candidate.UplinkID == "" || candidate.RouteGeneration <= 0 || candidate.PolicyGeneration < 0 || candidate.SubscriptionID != "" || candidate.NodeID != "" {
			return actuator.activationFailure(ctx, errors.New("direct path activation candidate is invalid"))
		}
		// Direct mode does not depend on Mihomo health. REJECT is best-effort;
		// nftables has already closed every previous TUN/direct gate.
		_ = actuator.Mihomo.Select(ctx, mihomo.ActiveGroupName, "REJECT")
		if err := actuator.Broker.ActivateDirectPath(ctx, candidate.UplinkID, candidate.RouteGeneration); err != nil {
			return actuator.activationFailure(ctx, fmt.Errorf("open verified direct firewall gate: %w", err))
		}
		return nil
	}
	selection, err := actuator.loadSelectedPath(ctx, candidate)
	if err != nil {
		return actuator.activationFailure(ctx, err)
	}
	if err := actuator.Broker.AuthorizeMihomoVersions(ctx, []string{selection.VersionID}); err != nil {
		return actuator.activationFailure(ctx, fmt.Errorf("restore active Mihomo endpoint allowlist: %w", err))
	}
	proxyName := selection.Names.NodePrefix + selection.ExternalName
	if err := actuator.Mihomo.Select(ctx, selection.Names.GroupName, proxyName); err != nil {
		return actuator.activationFailure(ctx, fmt.Errorf("select qualified node in path group: %w", err))
	}
	if err := actuator.Mihomo.Select(ctx, mihomo.ActiveGroupName, selection.Names.GroupName); err != nil {
		return actuator.activationFailure(ctx, fmt.Errorf("select qualified path in active group: %w", err))
	}
	pathState, err := actuator.Mihomo.Selected(ctx, selection.Names.GroupName)
	if err != nil {
		return actuator.activationFailure(ctx, fmt.Errorf("read selected path node: %w", err))
	}
	if pathState.Now != proxyName {
		return actuator.activationFailure(ctx, fmt.Errorf("selected path node is %q, expected %q", pathState.Now, proxyName))
	}
	activeState, err := actuator.Mihomo.Selected(ctx, mihomo.ActiveGroupName)
	if err != nil {
		return actuator.activationFailure(ctx, fmt.Errorf("read active Mihomo group: %w", err))
	}
	if activeState.Now != selection.Names.GroupName {
		return actuator.activationFailure(ctx, fmt.Errorf("active Mihomo path is %q, expected %q", activeState.Now, selection.Names.GroupName))
	}
	if candidate.StartupRecovery {
		if err := actuator.validateStartupProbe(); err != nil {
			return actuator.activationFailure(ctx, err)
		}
		if _, err := actuator.Mihomo.ProxyDelay(ctx, mihomo.ActiveGroupName, actuator.StartupProbeURL, actuator.StartupProbeTimeout, actuator.StartupProbeExpected); err != nil {
			return actuator.activationFailure(ctx, fmt.Errorf("minimal startup transport verification failed: %w", err))
		}
	} else {
		targets, err := actuator.activationTargets(ctx, candidate)
		if err != nil {
			return actuator.activationFailure(ctx, err)
		}
		for _, target := range targets {
			expected := ""
			switch target.SuccessMode {
			case bypass.SuccessAnyHTTPResponse:
			case bypass.SuccessExpectedStatus:
				expected = target.ExpectedStatus
			case bypass.SuccessExpectedBody:
				if actuator.BodyProber == nil {
					return actuator.activationFailure(ctx, fmt.Errorf("required target %s needs an unavailable body verifier", target.ID))
				}
				result := actuator.BodyProber.ProbeTarget(ctx,
					health.Path{ID: selection.PathID, ModemID: selection.UplinkID, SubscriptionID: selection.SubscriptionID, ProviderName: selection.Names.ProviderName, ProbeGroupName: selection.Names.ProbeGroupName},
					health.Candidate{NodeID: selection.NodeID, ProviderNodeName: selection.Names.NodePrefix + selection.ExternalName},
					health.Target{ID: target.ID, URL: target.NormalizedURL, Timeout: time.Duration(target.TimeoutSeconds) * time.Second, ExpectedStatus: target.ExpectedStatus, ExpectedBodySubstring: target.ExpectedBodySubstring},
				)
				if result.State != health.ProbePassed {
					return actuator.activationFailure(ctx, fmt.Errorf("reverify required target %s body through selected path: %s", target.ID, result.ErrorCode))
				}
				continue
			default:
				return actuator.activationFailure(ctx, fmt.Errorf("required target %s has invalid success mode", target.ID))
			}
			if _, err := actuator.Mihomo.ProxyDelay(ctx, mihomo.ActiveGroupName, target.NormalizedURL, time.Duration(target.TimeoutSeconds)*time.Second, expected); err != nil {
				return actuator.activationFailure(ctx, fmt.Errorf("reverify required target %s through active path: %w", target.ID, err))
			}
		}
	}
	if err := actuator.Broker.ActivatePath(ctx, uint32(candidate.ConfigGeneration)); err != nil {
		return actuator.activationFailure(ctx, fmt.Errorf("open verified TUN firewall gate: %w", err))
	}
	return nil
}

func (actuator *Actuator) Block(ctx context.Context, _ string) error {
	actuator.mutex.Lock()
	defer actuator.mutex.Unlock()
	if actuator.OperationLock != nil {
		actuator.OperationLock.Lock()
		defer actuator.OperationLock.Unlock()
	}
	if err := actuator.validate(); err != nil {
		return err
	}
	blockErr := actuator.Broker.BlockPath(ctx)
	selectErr := actuator.Mihomo.Select(ctx, mihomo.ActiveGroupName, "REJECT")
	if blockErr != nil {
		return errors.Join(fmt.Errorf("block TUN firewall gate: %w", blockErr), actuator.Broker.FailClosedMihomo(ctx), selectErr)
	}
	// The nftables TUN gate is the authoritative fail-closed boundary. Mihomo
	// can legitimately have no API before the first validated generation or
	// after a crash; once the gate is proven closed, a best-effort REJECT
	// selection must not turn an already-safe blocked state into a noisy error.
	return nil
}

func (actuator *Actuator) activationFailure(ctx context.Context, cause error) error {
	blockErr := actuator.Broker.BlockPath(ctx)
	selectErr := actuator.Mihomo.Select(ctx, mihomo.ActiveGroupName, "REJECT")
	if blockErr != nil {
		blockErr = errors.Join(blockErr, actuator.Broker.FailClosedMihomo(ctx))
	}
	return errors.Join(cause, blockErr, selectErr)
}

func (actuator *Actuator) loadSelectedPath(ctx context.Context, candidate reconcile.Candidate) (selectedPath, error) {
	now := time.Now
	if actuator.Now != nil {
		now = actuator.Now
	}
	var result selectedPath
	err := actuator.Database.QueryRowContext(ctx, `
SELECT p.id, p.uplink_id, p.subscription_id, n.id, v.id, n.external_name
FROM subscription_uplink_paths AS p
JOIN subscriptions AS s ON s.id=p.subscription_id
JOIN uplinks AS u ON u.id=p.uplink_id
JOIN nodes AS n ON n.id=?
JOIN subscription_versions AS v ON v.id=n.version_id AND v.id=s.active_version_id
JOIN uplink_path_nodes AS pn ON pn.path_id=p.id AND pn.node_id=n.id
WHERE p.id=? AND p.uplink_id=? AND p.subscription_id=? AND n.id=?
  AND p.policy_generation=? AND p.route_generation=? AND p.expires_at>?
  AND (((?='' OR ?='FULL') AND p.state='QUALIFIED' AND p.quality_class='FULL' AND pn.qualification_state='BYPASS_QUALIFIED')
       OR (?='LIMITED' AND p.state='DEGRADED' AND p.quality_class='LIMITED' AND pn.qualification_state='BYPASS_LIMITED'))
  AND pn.qualification_generation=p.policy_generation
	  AND pn.route_generation=p.route_generation AND pn.qualification_expires_at>?
	  AND n.enabled=1 AND u.enabled=1 AND u.state='UPLINK_READY' AND s.enabled=1`,
		candidate.NodeID, candidate.PathID, candidate.UplinkID, candidate.SubscriptionID, candidate.NodeID,
		candidate.PolicyGeneration, candidate.RouteGeneration,
		now().UTC().Format(time.RFC3339Nano), candidate.QualityClass, candidate.QualityClass,
		candidate.QualityClass, now().UTC().Format(time.RFC3339Nano),
	).Scan(&result.PathID, &result.UplinkID, &result.SubscriptionID, &result.NodeID, &result.VersionID, &result.ExternalName)
	if errors.Is(err, sql.ErrNoRows) {
		return selectedPath{}, errors.New("selected path became stale before activation")
	}
	if err != nil {
		return selectedPath{}, fmt.Errorf("read selected path for activation: %w", err)
	}
	result.Names, err = mihomo.StablePathNames(result.UplinkID, result.SubscriptionID)
	if err != nil {
		return selectedPath{}, err
	}
	return result, nil
}

func (actuator *Actuator) activationTargets(ctx context.Context, candidate reconcile.Candidate) ([]bypass.Target, error) {
	if candidate.QualityClass != accesspolicy.QualityLimited {
		return actuator.requiredTargets(ctx)
	}
	rows, err := actuator.Database.QueryContext(ctx, `
SELECT r.target_id
FROM uplink_path_node_target_results AS r
JOIN bypass_probe_targets AS t ON t.id=r.target_id AND t.enabled=1
WHERE r.path_id=? AND r.node_id=? AND r.state='PASSED'
	  AND t.target_class IN ('GLOBAL_REQUIRED','GLOBAL_OPTIONAL')
  AND r.policy_generation=? AND r.route_generation=? AND r.expires_at>?
ORDER BY t.priority, t.id`, candidate.PathID, candidate.NodeID,
		candidate.PolicyGeneration, candidate.RouteGeneration,
		actuator.now().Format(time.RFC3339Nano))
	if err != nil {
		return nil, fmt.Errorf("read LIMITED path target evidence: %w", err)
	}
	defer rows.Close()
	passed := map[string]struct{}{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("scan LIMITED path target evidence: %w", err)
		}
		passed[id] = struct{}{}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate LIMITED path target evidence: %w", err)
	}
	if len(passed) == 0 {
		return nil, errors.New("LIMITED path has no fresh passed target evidence")
	}
	items, err := actuator.Targets.List(ctx)
	if err != nil {
		return nil, fmt.Errorf("list targets for LIMITED path activation: %w", err)
	}
	result := make([]bypass.Target, 0, len(passed))
	for _, item := range items {
		if _, exists := passed[item.ID]; exists && item.Enabled && (item.TargetClass == bypass.TargetClassGlobalRequired || item.TargetClass == bypass.TargetClassGlobalOptional) {
			result = append(result, item)
		}
	}
	if len(result) != len(passed) {
		return nil, errors.New("LIMITED path evidence does not match active targets")
	}
	return result, nil
}

func (actuator *Actuator) now() time.Time {
	if actuator.Now != nil {
		return actuator.Now().UTC()
	}
	return time.Now().UTC()
}

func (actuator *Actuator) requiredTargets(ctx context.Context) ([]bypass.Target, error) {
	items, err := actuator.Targets.List(ctx)
	if err != nil {
		return nil, fmt.Errorf("list targets for path activation: %w", err)
	}
	result := make([]bypass.Target, 0, len(items))
	for _, item := range items {
		if item.Enabled && item.TargetClass == bypass.TargetClassGlobalRequired {
			result = append(result, item)
		}
	}
	if len(result) == 0 {
		return nil, errors.New("path activation requires at least one enabled required target")
	}
	return result, nil
}

func (actuator *Actuator) validate() error {
	if actuator == nil || actuator.Database == nil || actuator.Targets == nil || actuator.Broker == nil || actuator.Mihomo == nil {
		return errors.New("complete path actuator dependencies are required")
	}
	return nil
}

func (actuator *Actuator) validateStartupProbe() error {
	parsed, err := url.Parse(actuator.StartupProbeURL)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" || actuator.StartupProbeTimeout < time.Second || actuator.StartupProbeTimeout > time.Minute {
		return errors.New("bounded HTTPS startup transport probe is required")
	}
	if _, err := bypass.NormalizeStatusExpression(actuator.StartupProbeExpected); err != nil {
		return errors.New("startup transport status expression is invalid")
	}
	return nil
}

type Observer struct {
	Database        *sql.DB
	Broker          Broker
	Mihomo          MihomoControl
	TUN             TUNInspector
	State           *state.Repository
	TUNName         string
	ExpectedVersion string
	OperationLock   sync.Locker
}

func (observer Observer) Observe(ctx context.Context) (reconcile.Observed, error) {
	if observer.OperationLock != nil {
		observer.OperationLock.Lock()
		defer observer.OperationLock.Unlock()
	}
	if observer.Database == nil || observer.Broker == nil || observer.Mihomo == nil || observer.TUN == nil || observer.State == nil || observer.TUNName == "" || observer.ExpectedVersion == "" {
		return reconcile.Observed{}, errors.New("complete path observer dependencies are required")
	}
	firewallState, err := observer.Broker.ObservePath(ctx)
	if err != nil {
		return reconcile.Observed{}, fmt.Errorf("observe privileged firewall path state: %w", err)
	}
	result := reconcile.Observed{FirewallReady: true}
	version, apiErr := observer.Mihomo.GetVersion(ctx)
	result.MihomoReady = apiErr == nil && version.Version == observer.ExpectedVersion
	result.TUNReady = observer.TUN.RequireReady(ctx, observer.TUNName) == nil
	if !firewallState.Active {
		return result, nil
	}
	snapshot, err := observer.State.Get(ctx)
	if err != nil {
		return reconcile.Observed{}, err
	}
	if snapshot.ConfigGeneration <= 0 || snapshot.ConfigGeneration > math.MaxUint32 || uint32(snapshot.ConfigGeneration) != firewallState.Generation || snapshot.ActiveUplinkID == "" {
		return reconcile.Observed{}, errors.New("active firewall generation does not match desired runtime state")
	}
	if snapshot.ActiveMethodKind == accesspolicy.MethodDirect {
		if firewallState.Mode != dataplane.PathModeDirect || snapshot.ActiveDirectPathID == "" || snapshot.ActivePathID != "" || snapshot.ActiveSubscriptionID != "" || snapshot.ActiveNodeID != "" {
			return reconcile.Observed{}, errors.New("active direct firewall does not match desired runtime state")
		}
		var interfaceName string
		var fwmark, routeGeneration int64
		err := observer.Database.QueryRowContext(ctx, `
SELECT n.current_ifname, u.fwmark, p.route_generation
FROM direct_uplink_paths AS p
JOIN uplinks AS u ON u.id=p.uplink_id
JOIN network_interfaces AS n ON n.id=u.network_interface_id
WHERE p.id=? AND p.uplink_id=? AND p.route_generation=u.route_generation`,
			snapshot.ActiveDirectPathID, snapshot.ActiveUplinkID).Scan(&interfaceName, &fwmark, &routeGeneration)
		if err != nil || interfaceName != firewallState.DirectInterface || fwmark <= 0 || uint32(fwmark) != firewallState.DirectMark || routeGeneration <= 0 || uint32(routeGeneration) != firewallState.RouteGeneration {
			return reconcile.Observed{}, errors.New("active direct firewall context is stale")
		}
		result.MethodKind = accesspolicy.MethodDirect
		result.ActiveDirectPathID = snapshot.ActiveDirectPathID
		return result, nil
	}
	if snapshot.ActiveMethodKind != "" && snapshot.ActiveMethodKind != accesspolicy.MethodSubscription {
		return reconcile.Observed{}, errors.New("active runtime method kind is invalid")
	}
	if firewallState.Mode != dataplane.PathModeTUN || snapshot.ActivePathID == "" || snapshot.ActiveSubscriptionID == "" || snapshot.ActiveNodeID == "" || snapshot.ActiveDirectPathID != "" {
		return reconcile.Observed{}, errors.New("active TUN firewall does not match desired runtime state")
	}
	names, err := mihomo.StablePathNames(snapshot.ActiveUplinkID, snapshot.ActiveSubscriptionID)
	if err != nil {
		return reconcile.Observed{}, err
	}
	selected, err := observer.Mihomo.Selected(ctx, mihomo.ActiveGroupName)
	if err != nil || selected.Now != names.GroupName {
		result.MihomoReady = false
		return result, nil
	}
	var externalName string
	err = observer.Database.QueryRowContext(ctx, `
SELECT n.external_name
FROM nodes AS n
JOIN subscription_versions AS v ON v.id=n.version_id
JOIN subscriptions AS s ON s.id=v.subscription_id AND s.active_version_id=v.id
WHERE n.id=? AND s.id=?`, snapshot.ActiveNodeID, snapshot.ActiveSubscriptionID).Scan(&externalName)
	if err != nil {
		return reconcile.Observed{}, fmt.Errorf("read active node identity: %w", err)
	}
	selectedNode, err := observer.Mihomo.Selected(ctx, names.GroupName)
	if err != nil || selectedNode.Now != names.NodePrefix+externalName {
		result.MihomoReady = false
		return result, nil
	}
	result.ActivePathID = snapshot.ActivePathID
	result.ActiveNodeID = snapshot.ActiveNodeID
	result.MethodKind = accesspolicy.MethodSubscription
	return result, nil
}
