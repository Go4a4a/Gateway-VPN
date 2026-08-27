// Package candidateruntime implements the two-phase subscription refresh
// runtime: a candidate is first exposed only through shadow Mihomo providers,
// qualified in memory through every ready modem, and published only after the
// subscription version becomes the SQLite LKG.
package candidateruntime

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"gateway-vpn/internal/bypass"
	"gateway-vpn/internal/health"
	"gateway-vpn/internal/mihomo"
	"gateway-vpn/internal/modem"
	"gateway-vpn/internal/pathmatrix"
	"gateway-vpn/internal/state"
	"gateway-vpn/internal/subscription"
)

const defaultEvidenceTTL = 5 * time.Minute

type GenerationController interface {
	Apply(context.Context, string, mihomo.Bundle) (mihomo.ApplyResult, error)
	Restore(context.Context, string) error
}

type NodeSelector interface {
	Select(context.Context, string, string) error
}

type RoutingSynchronizer interface {
	SyncRouting(context.Context) error
}

type MihomoEndpointAuthorizer interface {
	AuthorizeMihomoVersions(context.Context, []string) error
}

type TargetStateEvaluator interface {
	Evaluate(context.Context, string) (health.TargetAssessment, error)
}

type Runtime struct {
	Subscriptions  *subscription.Repository
	Versions       *subscription.VersionRepository
	Modems         *modem.Repository
	Targets        *bypass.Repository
	Paths          *pathmatrix.Repository
	State          *state.Repository
	TargetStates   TargetStateEvaluator
	Controller     GenerationController
	Selector       NodeSelector
	Routing        RoutingSynchronizer
	EndpointAccess MihomoEndpointAuthorizer
	Prober         health.Prober
	ProberForClass func(string) health.Prober
	Qualifier      health.Qualifier
	PayloadRoot    string
	BaseInput      mihomo.Input
	EvidenceTTL    time.Duration
	Now            func() time.Time
	OperationLock  sync.Locker

	mutex sync.Mutex
}

type nodeIdentity struct {
	ID           string
	Fingerprint  string
	ExternalName string
}

type candidateMaterial struct {
	Subscription subscription.Subscription
	VersionID    string
	Imported     []subscription.ImportedNode
	NodesByID    map[string]nodeIdentity
}

type qualification struct {
	Result           health.CellResult
	PolicyGeneration int64
	RouteGeneration  int64
}

type RequalificationResult struct {
	ModemID              string
	SubscriptionsChecked int
	Qualified            int
	Failed               int
	CheckedAt            time.Time
}

type promotion struct {
	runtime                  *Runtime
	candidate                candidateMaterial
	qualifications           []qualification
	previousGeneration       string
	previousEndpointVersions []string
	mutex                    sync.Mutex
	committed                bool
	rolledBack               bool
	released                 bool
}

func (current *Runtime) Promote(ctx context.Context, candidate subscription.Candidate) (subscription.CandidatePromotion, error) {
	if current == nil {
		return nil, errors.New("candidate runtime is nil")
	}
	current.mutex.Lock()
	if current.OperationLock != nil {
		current.OperationLock.Lock()
	}
	release := true
	defer func() {
		if release {
			if current.OperationLock != nil {
				current.OperationLock.Unlock()
			}
			current.mutex.Unlock()
		}
	}()
	if err := current.validate(); err != nil {
		return nil, err
	}
	if err := current.Routing.SyncRouting(ctx); err != nil {
		return nil, fmt.Errorf("synchronize modem routing before candidate qualification: %w", err)
	}
	material, err := current.loadCandidate(ctx, candidate)
	if err != nil {
		return nil, err
	}
	modems, err := current.readyModems(ctx)
	if err != nil {
		return nil, err
	}
	targets, err := current.probeTargets(ctx)
	if err != nil {
		return nil, err
	}
	if err := current.Paths.ReconcileCells(ctx); err != nil {
		return nil, fmt.Errorf("reconcile path matrix before candidate qualification: %w", err)
	}
	temporaryBundle, err := current.buildBundle(ctx, modems, &material)
	if err != nil {
		return nil, err
	}
	previousEndpointVersions, err := current.endpointVersionIDs(ctx, nil)
	if err != nil {
		return nil, err
	}
	temporaryEndpointVersions := append([]string(nil), previousEndpointVersions...)
	if !containsString(temporaryEndpointVersions, material.VersionID) {
		temporaryEndpointVersions = append(temporaryEndpointVersions, material.VersionID)
		sort.Strings(temporaryEndpointVersions)
	}
	if err := current.EndpointAccess.AuthorizeMihomoVersions(ctx, temporaryEndpointVersions); err != nil {
		return nil, fmt.Errorf("authorize candidate Mihomo endpoints: %w", err)
	}
	apply, err := current.Controller.Apply(ctx, generationID("shadow", material.VersionID), temporaryBundle)
	if err != nil {
		return nil, fmt.Errorf("apply candidate shadow generation: %w", err)
	}
	qualifications, err := current.qualify(ctx, material, temporaryBundle, targets)
	if err == nil && !hasQualifiedPath(qualifications) {
		err = errors.New("candidate has no BYPASS_QUALIFIED path through any ready modem")
	}
	if err != nil {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
		restoreErr := current.Controller.Restore(cleanup, apply.PreviousGeneration)
		cancel()
		return nil, errors.Join(err, restoreErr)
	}
	release = false
	return &promotion{
		runtime:                  current,
		candidate:                material,
		qualifications:           qualifications,
		previousGeneration:       apply.PreviousGeneration,
		previousEndpointVersions: previousEndpointVersions,
	}, nil
}

// RequalifyModem rebuilds the complete active LKG bundle and refreshes path
// evidence only for one ready modem. It never stages or promotes a new
// subscription version and therefore is suitable for the manual Modem Probe
// operation and post-recovery verification.
func (current *Runtime) RequalifyModem(ctx context.Context, modemID string) (RequalificationResult, error) {
	if current == nil {
		return RequalificationResult{}, errors.New("candidate runtime is nil")
	}
	current.mutex.Lock()
	defer current.mutex.Unlock()
	if current.OperationLock != nil {
		current.OperationLock.Lock()
		defer current.OperationLock.Unlock()
	}
	if err := current.validate(); err != nil {
		return RequalificationResult{}, err
	}
	if strings.TrimSpace(modemID) == "" {
		return RequalificationResult{}, errors.New("modem id is required for requalification")
	}
	if err := current.Routing.SyncRouting(ctx); err != nil {
		return RequalificationResult{}, fmt.Errorf("synchronize modem routing before requalification: %w", err)
	}
	readyModems, err := current.readyModems(ctx)
	if err != nil {
		return RequalificationResult{}, err
	}
	ready := false
	for _, item := range readyModems {
		if item.ID == modemID {
			ready = true
			break
		}
	}
	if !ready {
		return RequalificationResult{}, errors.New("requested modem is not ready")
	}
	if err := current.Paths.ReconcileCells(ctx); err != nil {
		return RequalificationResult{}, fmt.Errorf("reconcile path matrix before modem requalification: %w", err)
	}
	targets, err := current.probeTargets(ctx)
	if err != nil {
		return RequalificationResult{}, err
	}
	storedSubscriptions, err := current.Subscriptions.List(ctx)
	if err != nil {
		return RequalificationResult{}, err
	}
	materials := make([]candidateMaterial, 0, len(storedSubscriptions))
	versionIDs := make([]string, 0, len(storedSubscriptions))
	for _, item := range storedSubscriptions {
		if !item.Enabled || item.ActiveVersionID == "" {
			continue
		}
		material, err := current.loadActive(ctx, item)
		if err != nil {
			return RequalificationResult{}, err
		}
		materials = append(materials, material)
		versionIDs = append(versionIDs, material.VersionID)
	}
	if len(materials) == 0 {
		return RequalificationResult{}, errors.New("modem requalification requires at least one active subscription LKG")
	}
	transition, transitioning, err := current.policyTransition(ctx)
	if err != nil {
		return RequalificationResult{}, err
	}
	if transitioning && transition.ActiveModemID == modemID {
		sort.SliceStable(materials, func(i, j int) bool {
			return materials[i].Subscription.ID == transition.ActiveSubscriptionID && materials[j].Subscription.ID != transition.ActiveSubscriptionID
		})
	}
	bundle, err := current.buildBundle(ctx, readyModems, nil)
	if err != nil {
		return RequalificationResult{}, err
	}
	sort.Strings(versionIDs)
	if err := current.EndpointAccess.AuthorizeMihomoVersions(ctx, versionIDs); err != nil {
		return RequalificationResult{}, fmt.Errorf("authorize active endpoints before modem requalification: %w", err)
	}
	apply, err := current.Controller.Apply(ctx, generationID("requalify-"+modemID, strings.Join(versionIDs, ",")), bundle)
	if err != nil {
		return RequalificationResult{}, fmt.Errorf("apply active bundle for modem requalification: %w", err)
	}
	restoreOnError := func(cause error) (RequalificationResult, error) {
		restoreCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
		defer cancel()
		return RequalificationResult{}, errors.Join(cause, current.Controller.Restore(restoreCtx, apply.PreviousGeneration))
	}
	checkedAt := current.now().UTC()
	result := RequalificationResult{ModemID: modemID, CheckedAt: checkedAt}
	for _, material := range materials {
		qualifications, err := current.qualifyPaths(ctx, material, bundle, targets, func(path mihomo.Path) bool {
			return !path.QualificationOnly && path.SubscriptionID == material.Subscription.ID && path.ModemID == modemID
		})
		if err != nil {
			return restoreOnError(err)
		}
		if len(qualifications) != 1 {
			return restoreOnError(fmt.Errorf("active bundle has %d paths for modem %s subscription %s", len(qualifications), modemID, material.Subscription.ID))
		}
		item := qualifications[0]
		snapshot := pathmatrix.SnapshotFromHealth(item.Result, item.PolicyGeneration, item.RouteGeneration, checkedAt, checkedAt.Add(current.evidenceTTL()))
		if err := current.Paths.StoreQualification(ctx, snapshot); err != nil {
			return restoreOnError(fmt.Errorf("store modem requalification for path %s: %w", item.Result.PathID, err))
		}
		result.SubscriptionsChecked++
		if item.Result.State == health.CellQualified && item.Result.SelectedNodeID != "" {
			identity, exists := material.NodesByID[item.Result.SelectedNodeID]
			if !exists {
				return restoreOnError(errors.New("requalified node identity is unavailable"))
			}
			var generatedPath mihomo.Path
			for _, path := range bundle.Paths {
				if !path.QualificationOnly && path.SubscriptionID == material.Subscription.ID && path.ModemID == modemID {
					generatedPath = path
					break
				}
			}
			if generatedPath.GroupName == "" {
				return restoreOnError(errors.New("requalified Mihomo path is unavailable"))
			}
			if err := current.Selector.Select(ctx, generatedPath.GroupName, generatedPath.NodePrefix+identity.ExternalName); err != nil {
				return restoreOnError(fmt.Errorf("select requalified node: %w", err))
			}
			result.Qualified++
		} else {
			result.Failed++
		}
	}
	current.evaluateTargetStates(ctx, targets)
	return result, nil
}

func (current *Runtime) validate() error {
	if current.Subscriptions == nil || current.Versions == nil || current.Modems == nil || current.Targets == nil || current.Paths == nil || current.State == nil || current.TargetStates == nil || current.Controller == nil || current.Selector == nil || current.Routing == nil || current.EndpointAccess == nil || current.Prober == nil || strings.TrimSpace(current.PayloadRoot) == "" {
		return errors.New("candidate runtime dependencies are incomplete")
	}
	if current.EvidenceTTL < 0 {
		return errors.New("candidate evidence TTL cannot be negative")
	}
	return nil
}

func (current *Runtime) loadCandidate(ctx context.Context, candidate subscription.Candidate) (candidateMaterial, error) {
	if candidate.Subscription.ID == "" || candidate.Version.Version.ID == "" || candidate.Version.Version.SubscriptionID != candidate.Subscription.ID || candidate.Version.Version.State != subscription.VersionCandidate {
		return candidateMaterial{}, errors.New("complete staged candidate identity is required")
	}
	storedVersion, err := current.Versions.Get(ctx, candidate.Version.Version.ID)
	if err != nil {
		return candidateMaterial{}, fmt.Errorf("read staged candidate version: %w", err)
	}
	if storedVersion.SubscriptionID != candidate.Subscription.ID || storedVersion.State != subscription.VersionCandidate {
		return candidateMaterial{}, errors.New("candidate version is not staged for the requested subscription")
	}
	freshSubscription, err := current.Subscriptions.Get(ctx, candidate.Subscription.ID)
	if err != nil {
		return candidateMaterial{}, fmt.Errorf("read candidate subscription: %w", err)
	}
	expectedPath := filepath.Join(current.PayloadRoot, candidate.Subscription.ID, candidate.Version.Version.ID, "payload.yaml")
	if !samePath(candidate.PayloadPath, expectedPath) {
		return candidateMaterial{}, errors.New("candidate payload path is outside its immutable version directory")
	}
	imported, err := subscription.LoadNormalizedPayload(current.PayloadRoot, candidate.Subscription.ID, candidate.Version.Version.ID)
	if err != nil {
		return candidateMaterial{}, err
	}
	storedNodes, err := current.Versions.ListNodes(ctx, candidate.Version.Version.ID, true)
	if err != nil {
		return candidateMaterial{}, fmt.Errorf("read candidate nodes: %w", err)
	}
	filtered, identities, err := filterEnabledNodes(imported.Nodes, storedNodes)
	if err != nil {
		return candidateMaterial{}, fmt.Errorf("match candidate payload to stored nodes: %w", err)
	}
	if len(filtered) == 0 {
		return candidateMaterial{}, errors.New("candidate has no enabled nodes")
	}
	return candidateMaterial{Subscription: freshSubscription, VersionID: storedVersion.ID, Imported: filtered, NodesByID: identities}, nil
}

func (current *Runtime) loadActive(ctx context.Context, currentSubscription subscription.Subscription) (candidateMaterial, error) {
	version, err := current.Versions.Get(ctx, currentSubscription.ActiveVersionID)
	if err != nil {
		return candidateMaterial{}, fmt.Errorf("read active subscription version: %w", err)
	}
	if version.SubscriptionID != currentSubscription.ID || version.State != subscription.VersionLKG {
		return candidateMaterial{}, errors.New("active subscription pointer does not reference an LKG")
	}
	imported, err := subscription.LoadNormalizedPayload(current.PayloadRoot, currentSubscription.ID, version.ID)
	if err != nil {
		return candidateMaterial{}, err
	}
	storedNodes, err := current.Versions.ListNodes(ctx, version.ID, true)
	if err != nil {
		return candidateMaterial{}, fmt.Errorf("read active subscription nodes: %w", err)
	}
	filtered, identities, err := filterEnabledNodes(imported.Nodes, storedNodes)
	if err != nil {
		return candidateMaterial{}, fmt.Errorf("match active payload to stored nodes: %w", err)
	}
	if len(filtered) == 0 {
		transition, transitioning, err := current.policyTransition(ctx)
		if err != nil {
			return candidateMaterial{}, err
		}
		if !transitioning || transition.ActiveSubscriptionID != currentSubscription.ID {
			return candidateMaterial{}, errors.New("active subscription has no enabled nodes")
		}
	}
	return candidateMaterial{Subscription: currentSubscription, VersionID: version.ID, Imported: filtered, NodesByID: identities}, nil
}

func (current *Runtime) readyModems(ctx context.Context) ([]mihomo.Modem, error) {
	stored, err := current.Modems.List(ctx)
	if err != nil {
		return nil, fmt.Errorf("list modems for candidate runtime: %w", err)
	}
	result := make([]mihomo.Modem, 0, len(stored))
	for _, item := range stored {
		if !item.Enabled || item.State != modem.StateReady {
			continue
		}
		result = append(result, mihomo.Modem{ID: item.ID, Priority: item.Priority, InterfaceName: item.InterfaceName, Fwmark: item.Fwmark, Enabled: true, Online: true})
	}
	if len(result) == 0 {
		return nil, errors.New("candidate qualification requires at least one ready modem")
	}
	return result, nil
}

func (current *Runtime) probeTargets(ctx context.Context) ([]health.Target, error) {
	stored, err := current.Targets.List(ctx)
	if err != nil {
		return nil, fmt.Errorf("list candidate probe targets: %w", err)
	}
	result := make([]health.Target, 0, len(stored))
	required := 0
	for _, item := range stored {
		if !item.Enabled {
			continue
		}
		expectedStatus := ""
		if item.SuccessMode == bypass.SuccessExpectedStatus || item.SuccessMode == bypass.SuccessExpectedBody {
			expectedStatus = item.ExpectedStatus
		}
		result = append(result, health.Target{ID: item.ID, Name: item.Name, URL: item.NormalizedURL, Priority: int(item.Priority), Required: item.Required, Timeout: time.Duration(item.TimeoutSeconds) * time.Second, ExpectedStatus: expectedStatus, ExpectedBodySubstring: item.ExpectedBodySubstring})
		if item.Required {
			required++
		}
	}
	if required == 0 {
		return nil, errors.New("candidate qualification requires at least one enabled required target")
	}
	return result, nil
}

// buildBundle loads every enabled subscription from its immutable SQLite LKG
// pointer. When shadow is non-nil, that version is added under an isolated
// runtime key and never appears in gateway-vpn-active.
func (current *Runtime) buildBundle(ctx context.Context, modems []mihomo.Modem, shadow *candidateMaterial) (mihomo.Bundle, error) {
	transition, transitioning, err := current.policyTransition(ctx)
	if err != nil {
		return mihomo.Bundle{}, err
	}
	storedSubscriptions, err := current.Subscriptions.List(ctx)
	if err != nil {
		return mihomo.Bundle{}, fmt.Errorf("list subscriptions for Mihomo bundle: %w", err)
	}
	generated := make([]mihomo.Subscription, 0, len(storedSubscriptions)+1)
	for _, item := range storedSubscriptions {
		if item.ActiveVersionID == "" {
			continue
		}
		imported, err := subscription.LoadNormalizedPayload(current.PayloadRoot, item.ID, item.ActiveVersionID)
		if err != nil {
			return mihomo.Bundle{}, fmt.Errorf("load active payload for subscription %s: %w", item.ID, err)
		}
		storedNodes, err := current.Versions.ListNodes(ctx, item.ActiveVersionID, true)
		if err != nil {
			return mihomo.Bundle{}, fmt.Errorf("read active nodes for subscription %s: %w", item.ID, err)
		}
		filtered, _, err := filterEnabledNodes(imported.Nodes, storedNodes)
		if err != nil {
			return mihomo.Bundle{}, fmt.Errorf("match active payload for subscription %s: %w", item.ID, err)
		}
		if len(filtered) == 0 {
			if !transitioning || transition.ActiveSubscriptionID != item.ID {
				continue
			}
		}
		if transitioning && transition.ActiveSubscriptionID == item.ID {
			allNodes, err := current.Versions.ListNodes(ctx, item.ActiveVersionID, false)
			if err != nil {
				return mihomo.Bundle{}, fmt.Errorf("read grace node for subscription %s: %w", item.ID, err)
			}
			filtered, err = preserveTransitionNode(imported.Nodes, filtered, allNodes, transition.ActiveNodeID)
			if err != nil {
				return mihomo.Bundle{}, fmt.Errorf("preserve active grace node for subscription %s: %w", item.ID, err)
			}
		}
		// access-method enablement controls the user routing group only. Every
		// active LKG remains present behind its isolated probe group so disabled
		// subscriptions can refresh through their own/other allowed nodes.
		generated = append(generated, mihomo.Subscription{ID: item.ID, Priority: item.Priority, Enabled: true, QualificationOnly: !item.Enabled, Nodes: filtered})
	}
	if shadow != nil {
		generated = append(generated, mihomo.Subscription{
			ID:                shadow.Subscription.ID,
			RuntimeKey:        "qualification-shadow-" + shadow.VersionID,
			Priority:          shadow.Subscription.Priority,
			Enabled:           true,
			QualificationOnly: true,
			Nodes:             shadow.Imported,
		})
	}
	input := current.BaseInput
	input.Modems = append([]mihomo.Modem(nil), modems...)
	input.Subscriptions = generated
	input.BootstrapDNS = append([]string(nil), current.BaseInput.BootstrapDNS...)
	bundle, err := mihomo.Generate(input)
	if err != nil {
		return mihomo.Bundle{}, fmt.Errorf("generate Mihomo candidate bundle: %w", err)
	}
	return bundle, nil
}

func (current *Runtime) qualify(ctx context.Context, material candidateMaterial, bundle mihomo.Bundle, targets []health.Target) ([]qualification, error) {
	return current.qualifyPaths(ctx, material, bundle, targets, func(item mihomo.Path) bool {
		return item.QualificationOnly && item.SubscriptionID == material.Subscription.ID && item.RuntimeKey == "qualification-shadow-"+material.VersionID
	})
}

func (current *Runtime) qualifyPaths(ctx context.Context, material candidateMaterial, bundle mihomo.Bundle, targets []health.Target, include func(mihomo.Path) bool) ([]qualification, error) {
	transition, transitioning, err := current.policyTransition(ctx)
	if err != nil {
		return nil, err
	}
	paths := make([]mihomo.Path, 0)
	for _, item := range bundle.Paths {
		if include(item) {
			paths = append(paths, item)
		}
	}
	if len(paths) == 0 {
		return nil, errors.New("generated Mihomo bundle has no requested qualification paths")
	}
	identities := make([]nodeIdentity, 0, len(material.NodesByID))
	for _, identity := range material.NodesByID {
		identities = append(identities, identity)
	}
	sort.Slice(identities, func(i, j int) bool { return identities[i].ID < identities[j].ID })
	results := make([]qualification, 0, len(paths))
	for _, generatedPath := range paths {
		cell, err := current.Paths.Get(ctx, generatedPath.ModemID, material.Subscription.ID)
		if err != nil {
			return nil, fmt.Errorf("read path matrix cell for qualification: %w", err)
		}
		healthPath := health.Path{ID: cell.ID, ModemID: generatedPath.ModemID, SubscriptionID: material.Subscription.ID, ProviderName: generatedPath.ProviderName, ProbeGroupName: generatedPath.ProbeGroupName}
		if transitioning && !generatedPath.QualificationOnly && transition.ActivePathID == cell.ID && transition.PolicyTransitionGeneration == cell.PolicyGeneration {
			healthPath.PreferredNodeID = transition.ActiveNodeID
		}
		for _, identity := range identities {
			healthPath.Candidates = append(healthPath.Candidates, health.Candidate{NodeID: identity.ID, Fingerprint: identity.Fingerprint, ProviderNodeName: generatedPath.NodePrefix + identity.ExternalName})
		}
		result, err := current.Qualifier.QualifyCell(ctx, current.Prober, healthPath, targets)
		if err != nil {
			return nil, fmt.Errorf("qualify path %s: %w", cell.ID, err)
		}
		results = append(results, qualification{Result: result, PolicyGeneration: cell.PolicyGeneration, RouteGeneration: cell.RouteGeneration})
	}
	return results, nil
}

func (current *Runtime) policyTransition(ctx context.Context) (state.Snapshot, bool, error) {
	snapshot, err := current.State.Get(ctx)
	if err != nil {
		return state.Snapshot{}, false, fmt.Errorf("read runtime policy transition: %w", err)
	}
	return snapshot, snapshot.PolicyTransitionActive(), nil
}

func preserveTransitionNode(imported, filtered []subscription.ImportedNode, stored []subscription.StoredNode, nodeID string) ([]subscription.ImportedNode, error) {
	if nodeID == "" {
		return nil, errors.New("active grace node id is required")
	}
	var fingerprint string
	for _, item := range stored {
		if item.ID == nodeID {
			fingerprint = item.Fingerprint
			break
		}
	}
	if fingerprint == "" {
		return nil, errors.New("active grace node is absent from the active version")
	}
	for _, item := range filtered {
		if item.Fingerprint == fingerprint {
			return filtered, nil
		}
	}
	for _, item := range imported {
		if item.Fingerprint == fingerprint {
			result := make([]subscription.ImportedNode, 0, len(filtered)+1)
			result = append(result, item)
			result = append(result, filtered...)
			return result, nil
		}
	}
	return nil, errors.New("active grace node is absent from the immutable payload")
}

func (current *promotion) Commit(ctx context.Context) error {
	current.mutex.Lock()
	defer current.mutex.Unlock()
	if current.committed {
		return nil
	}
	if current.rolledBack {
		return errors.New("candidate promotion was already rolled back")
	}
	active, err := current.runtime.Versions.Active(ctx, current.candidate.Subscription.ID)
	if err != nil {
		return fmt.Errorf("verify active candidate before runtime commit: %w", err)
	}
	if active.ID != current.candidate.VersionID || active.State != subscription.VersionLKG {
		return errors.New("candidate must be the SQLite LKG before runtime commit")
	}
	freshSubscription, err := current.runtime.Subscriptions.Get(ctx, current.candidate.Subscription.ID)
	if err != nil {
		return fmt.Errorf("read candidate subscription routing state before runtime commit: %w", err)
	}
	currentEnabled := freshSubscription.Enabled
	modems, err := current.runtime.readyModems(ctx)
	if err != nil {
		return err
	}
	finalBundle, err := current.runtime.buildBundle(ctx, modems, nil)
	if err != nil {
		return err
	}
	finalEndpointVersions, err := current.runtime.endpointVersionIDs(ctx, nil)
	if err != nil {
		return err
	}
	if err := current.runtime.EndpointAccess.AuthorizeMihomoVersions(ctx, finalEndpointVersions); err != nil {
		return fmt.Errorf("authorize final Mihomo endpoints: %w", err)
	}
	if _, err := current.runtime.Controller.Apply(ctx, generationID("active", current.candidate.VersionID), finalBundle); err != nil {
		return fmt.Errorf("apply final candidate generation: %w", err)
	}
	verifiedSubscription, err := current.runtime.Subscriptions.Get(ctx, current.candidate.Subscription.ID)
	if err != nil || verifiedSubscription.Enabled != currentEnabled || verifiedSubscription.ActiveVersionID != current.candidate.VersionID {
		return errors.New("candidate subscription routing state changed during runtime commit")
	}
	finalPaths := make(map[string]mihomo.Path)
	for _, item := range finalBundle.Paths {
		if item.SubscriptionID == current.candidate.Subscription.ID && (!item.QualificationOnly || !currentEnabled) {
			finalPaths[item.ModemID] = item
		}
	}
	for _, item := range current.qualifications {
		if item.Result.State != health.CellQualified {
			continue
		}
		generatedPath, exists := finalPaths[item.Result.ModemID]
		if !exists {
			return fmt.Errorf("final Mihomo bundle has no path for qualified modem %s", item.Result.ModemID)
		}
		identity, exists := current.candidate.NodesByID[item.Result.SelectedNodeID]
		if !exists {
			return fmt.Errorf("qualified node %s is absent from candidate identity map", item.Result.SelectedNodeID)
		}
		selectorGroup := generatedPath.GroupName
		if !currentEnabled {
			selectorGroup = generatedPath.ProbeGroupName
		}
		if err := current.runtime.Selector.Select(ctx, selectorGroup, generatedPath.NodePrefix+identity.ExternalName); err != nil {
			return fmt.Errorf("select qualified candidate node for modem %s: %w", item.Result.ModemID, err)
		}
	}
	if !currentEnabled {
		// Qualification proves the refreshed LKG is usable, but a disabled user
		// access method must retain SUBSCRIPTION_DISABLED aggregate state and
		// must not become eligible for the unified user selector.
		current.committed = true
		current.releaseRuntime()
		return nil
	}
	checkedAt := current.runtime.now().UTC()
	expiresAt := checkedAt.Add(current.runtime.evidenceTTL())
	for _, item := range current.qualifications {
		snapshot := pathmatrix.SnapshotFromHealth(item.Result, item.PolicyGeneration, item.RouteGeneration, checkedAt, expiresAt)
		if err := current.runtime.Paths.StoreQualification(ctx, snapshot); err != nil {
			return fmt.Errorf("persist candidate qualification for path %s: %w", item.Result.PathID, err)
		}
	}
	current.runtime.evaluateTargetStates(ctx, mustProbeTargets(current.runtime, ctx))
	current.committed = true
	current.releaseRuntime()
	return nil
}

func (current *Runtime) evaluateTargetStates(ctx context.Context, targets []health.Target) {
	for _, target := range targets {
		if _, err := current.TargetStates.Evaluate(ctx, target.ID); err != nil {
			_ = current.State.AppendEvent(ctx, state.EventInput{
				Severity: "ERROR", Type: "TARGET_OUTAGE_EVALUATION_FAILED",
				Details: map[string]any{"target_id": target.ID, "error": err.Error()},
			})
		}
	}
}

func mustProbeTargets(current *Runtime, ctx context.Context) []health.Target {
	targets, err := current.probeTargets(ctx)
	if err != nil {
		_ = current.State.AppendEvent(ctx, state.EventInput{Severity: "ERROR", Type: "TARGET_OUTAGE_EVALUATION_SKIPPED", Details: map[string]any{"error": err.Error()}})
		return nil
	}
	return targets
}

func (current *promotion) Rollback(ctx context.Context) error {
	current.mutex.Lock()
	defer current.mutex.Unlock()
	if current.rolledBack {
		return nil
	}
	if current.committed {
		return errors.New("committed candidate promotion cannot be rolled back")
	}
	authorizeErr := current.runtime.EndpointAccess.AuthorizeMihomoVersions(ctx, current.previousEndpointVersions)
	restoreErr := current.runtime.Controller.Restore(ctx, current.previousGeneration)
	invalidateErr := current.runtime.Paths.InvalidateVersionEvidence(ctx, current.candidate.Subscription.ID, current.candidate.VersionID)
	current.rolledBack = true
	current.releaseRuntime()
	return errors.Join(authorizeErr, restoreErr, invalidateErr)
}

func (current *Runtime) endpointVersionIDs(ctx context.Context, shadow *candidateMaterial) ([]string, error) {
	stored, err := current.Subscriptions.List(ctx)
	if err != nil {
		return nil, fmt.Errorf("list subscriptions for endpoint authorization: %w", err)
	}
	result := make([]string, 0, len(stored)+1)
	for _, item := range stored {
		// Disabled access methods still retain service-only probe providers for
		// their LKG, so their exact proxy endpoints must remain authorized too.
		if item.ActiveVersionID != "" {
			result = append(result, item.ActiveVersionID)
		}
	}
	if shadow != nil && !containsString(result, shadow.VersionID) {
		result = append(result, shadow.VersionID)
	}
	sort.Strings(result)
	if len(result) == 0 {
		return nil, errors.New("Mihomo endpoint authorization has no active or candidate versions")
	}
	return result, nil
}

func containsString(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func (current *promotion) releaseRuntime() {
	if current.released {
		return
	}
	current.released = true
	if current.runtime.OperationLock != nil {
		current.runtime.OperationLock.Unlock()
	}
	current.runtime.mutex.Unlock()
}

func (current *Runtime) now() time.Time {
	if current.Now != nil {
		return current.Now()
	}
	return time.Now()
}

func (current *Runtime) evidenceTTL() time.Duration {
	if current.EvidenceTTL > 0 {
		return current.EvidenceTTL
	}
	return defaultEvidenceTTL
}

func filterEnabledNodes(imported []subscription.ImportedNode, stored []subscription.StoredNode) ([]subscription.ImportedNode, map[string]nodeIdentity, error) {
	storedByFingerprint := make(map[string]subscription.StoredNode, len(stored))
	for _, item := range stored {
		if !item.Enabled {
			continue
		}
		if _, exists := storedByFingerprint[item.Fingerprint]; exists {
			return nil, nil, errors.New("duplicate stored node fingerprint")
		}
		storedByFingerprint[item.Fingerprint] = item
	}
	filtered := make([]subscription.ImportedNode, 0, len(storedByFingerprint))
	identities := make(map[string]nodeIdentity, len(storedByFingerprint))
	for _, item := range imported {
		storedNode, exists := storedByFingerprint[item.Fingerprint]
		if !exists {
			continue
		}
		filtered = append(filtered, item)
		identities[storedNode.ID] = nodeIdentity{ID: storedNode.ID, Fingerprint: item.Fingerprint, ExternalName: item.ExternalName}
		delete(storedByFingerprint, item.Fingerprint)
	}
	if len(storedByFingerprint) != 0 {
		return nil, nil, errors.New("stored enabled node is absent from immutable payload")
	}
	return filtered, identities, nil
}

func hasQualifiedPath(items []qualification) bool {
	for _, item := range items {
		if item.Result.State == health.CellQualified && item.Result.SelectedNodeID != "" {
			return true
		}
	}
	return false
}

func generationID(phase, versionID string) string {
	digest := sha256.Sum256([]byte(phase + "\x00" + versionID))
	return phase + "-" + hex.EncodeToString(digest[:16])
}

func samePath(left, right string) bool {
	if left == "" || right == "" {
		return false
	}
	left = filepath.Clean(left)
	right = filepath.Clean(right)
	if runtime.GOOS == "windows" {
		return strings.EqualFold(left, right)
	}
	return left == right
}
