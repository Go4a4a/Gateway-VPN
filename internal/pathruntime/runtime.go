// Package pathruntime binds the reconciler to the selected Mihomo path and the
// privileged nftables TUN gate. Selection and end-to-end verification happen
// while LAN forwarding is blocked; the gate opens only after every enabled
// required target succeeds through gateway-vpn-active.
package pathruntime

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math"
	"sync"
	"time"

	"gateway-vpn/internal/bypass"
	"gateway-vpn/internal/dataplane"
	"gateway-vpn/internal/health"
	"gateway-vpn/internal/mihomo"
	"gateway-vpn/internal/reconcile"
	"gateway-vpn/internal/state"
)

type Broker interface {
	ActivatePath(context.Context, uint32) error
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
	Database      *sql.DB
	Targets       *bypass.Repository
	Broker        Broker
	Mihomo        MihomoControl
	BodyProber    TargetProber
	Now           func() time.Time
	OperationLock sync.Locker

	mutex sync.Mutex
}

type selectedPath struct {
	PathID         string
	ModemID        string
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
	targets, err := actuator.requiredTargets(ctx)
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
				health.Path{ID: selection.PathID, ModemID: selection.ModemID, SubscriptionID: selection.SubscriptionID, ProviderName: selection.Names.ProviderName, ProbeGroupName: selection.Names.ProbeGroupName},
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
	return selectErr
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
SELECT p.id, p.modem_id, p.subscription_id, n.id, v.id, n.external_name
FROM subscription_modem_paths AS p
JOIN subscriptions AS s ON s.id=p.subscription_id
JOIN modems AS m ON m.id=p.modem_id
JOIN nodes AS n ON n.id=?
JOIN subscription_versions AS v ON v.id=n.version_id AND v.id=s.active_version_id
JOIN path_nodes AS pn ON pn.path_id=p.id AND pn.node_id=n.id
WHERE p.id=? AND p.modem_id=? AND p.subscription_id=? AND n.id=?
  AND p.state='QUALIFIED' AND p.policy_generation=? AND p.route_generation=?
  AND p.expires_at>? AND pn.qualification_state='BYPASS_QUALIFIED'
  AND pn.qualification_generation=p.policy_generation
	  AND pn.route_generation=p.route_generation AND pn.qualification_expires_at>?
	  AND n.enabled=1 AND m.enabled=1 AND m.state='MODEM_READY' AND s.enabled=1`,
		candidate.NodeID, candidate.PathID, candidate.ModemID, candidate.SubscriptionID, candidate.NodeID,
		candidate.PolicyGeneration, candidate.RouteGeneration,
		now().UTC().Format(time.RFC3339Nano), now().UTC().Format(time.RFC3339Nano),
	).Scan(&result.PathID, &result.ModemID, &result.SubscriptionID, &result.NodeID, &result.VersionID, &result.ExternalName)
	if errors.Is(err, sql.ErrNoRows) {
		return selectedPath{}, errors.New("selected path became stale before activation")
	}
	if err != nil {
		return selectedPath{}, fmt.Errorf("read selected path for activation: %w", err)
	}
	result.Names, err = mihomo.StablePathNames(result.ModemID, result.SubscriptionID)
	if err != nil {
		return selectedPath{}, err
	}
	return result, nil
}

func (actuator *Actuator) requiredTargets(ctx context.Context) ([]bypass.Target, error) {
	items, err := actuator.Targets.List(ctx)
	if err != nil {
		return nil, fmt.Errorf("list targets for path activation: %w", err)
	}
	result := make([]bypass.Target, 0, len(items))
	for _, item := range items {
		if item.Enabled && item.Required {
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
	if snapshot.ConfigGeneration <= 0 || snapshot.ConfigGeneration > math.MaxUint32 || uint32(snapshot.ConfigGeneration) != firewallState.Generation || snapshot.ActivePathID == "" || snapshot.ActiveModemID == "" || snapshot.ActiveSubscriptionID == "" {
		return reconcile.Observed{}, errors.New("active firewall generation does not match desired runtime state")
	}
	names, err := mihomo.StablePathNames(snapshot.ActiveModemID, snapshot.ActiveSubscriptionID)
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
	return result, nil
}
