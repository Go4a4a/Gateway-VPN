package candidateruntime

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"gateway-vpn/internal/health"
	"gateway-vpn/internal/mihomo"
	"gateway-vpn/internal/pathmatrix"
	"gateway-vpn/internal/state"
)

var (
	ErrPathNotReady    = errors.New("requested path is not ready")
	ErrNodeNotEligible = errors.New("requested node is not an enabled active-LKG candidate")
)

type PathOperationResult struct {
	PathID              string
	NodeID              string
	Authoritative       bool
	PolicyGeneration    int64
	RouteGeneration     int64
	CheckedAt           time.Time
	ExpiresAt           time.Time
	CandidateNodesTotal int
	DeferredReason      string
	Result              health.CellResult
}

type pathOperationOptions struct {
	Authoritative     bool
	ProbeClass        string
	Qualifier         health.Qualifier
	Phase             string
	DiagnosticEvent   string
	PathEvent         string
	NodeEvent         string
	SkipDeferredStore bool
}

// ProbeNode runs a diagnostic check for one exact modem/subscription/node
// tuple. It restores the previous Mihomo generation and does not change the
// authoritative path or node evidence.
func (current *Runtime) ProbeNode(ctx context.Context, pathID, nodeID string) (PathOperationResult, error) {
	return current.runPathOperation(ctx, pathID, nodeID, pathOperationOptions{
		Phase: "manual-probe", DiagnosticEvent: "MANUAL_NODE_PROBED", Qualifier: current.Qualifier,
	})
}

// QualifyNode refreshes authoritative evidence only for one exact node while
// preserving fresh current-generation evidence for the other path candidates.
func (current *Runtime) QualifyNode(ctx context.Context, pathID, nodeID string) (PathOperationResult, error) {
	return current.runPathOperation(ctx, pathID, nodeID, pathOperationOptions{
		Authoritative: true, Phase: "manual-qualify", NodeEvent: "MANUAL_NODE_QUALIFIED", Qualifier: current.Qualifier,
	})
}

// QualifyPath checks the complete enabled active-LKG candidate set for one
// modem/subscription path and atomically replaces that cell's evidence.
func (current *Runtime) QualifyPath(ctx context.Context, pathID string) (PathOperationResult, error) {
	return current.runPathOperation(ctx, pathID, "", pathOperationOptions{
		Authoritative: true, Phase: "manual-qualify", PathEvent: "MANUAL_PATH_QUALIFIED", Qualifier: current.Qualifier,
	})
}

func (current *Runtime) runPathOperation(ctx context.Context, pathID, nodeID string, options pathOperationOptions) (PathOperationResult, error) {
	if current == nil {
		return PathOperationResult{}, errors.New("candidate runtime is nil")
	}
	current.mutex.Lock()
	defer current.mutex.Unlock()
	if current.OperationLock != nil {
		current.OperationLock.Lock()
		defer current.OperationLock.Unlock()
	}
	if err := current.validate(); err != nil {
		return PathOperationResult{}, err
	}
	if strings.TrimSpace(pathID) == "" || (nodeID != "" && strings.TrimSpace(nodeID) == "") {
		return PathOperationResult{}, errors.New("path id and optional node id must be non-empty")
	}
	if err := current.Routing.SyncRouting(ctx); err != nil {
		return PathOperationResult{}, fmt.Errorf("synchronize modem routing before path operation: %w", err)
	}
	if err := current.Paths.ReconcileCells(ctx); err != nil {
		return PathOperationResult{}, fmt.Errorf("reconcile path matrix before path operation: %w", err)
	}
	cell, err := current.Paths.GetByID(ctx, pathID)
	if err != nil {
		return PathOperationResult{}, err
	}
	readyModems, err := current.readyModems(ctx)
	if err != nil {
		return PathOperationResult{}, err
	}
	pathModemReady := false
	for _, item := range readyModems {
		if item.ID == cell.ModemID {
			pathModemReady = true
			break
		}
	}
	if !pathModemReady {
		return PathOperationResult{}, ErrPathNotReady
	}
	currentSubscription, err := current.Subscriptions.Get(ctx, cell.SubscriptionID)
	if err != nil {
		return PathOperationResult{}, err
	}
	if !currentSubscription.Enabled || currentSubscription.ActiveVersionID == "" {
		return PathOperationResult{}, ErrPathNotReady
	}
	material, err := current.loadActive(ctx, currentSubscription)
	if err != nil {
		return PathOperationResult{}, err
	}
	if nodeID != "" {
		if _, exists := material.NodesByID[nodeID]; !exists {
			return PathOperationResult{}, ErrNodeNotEligible
		}
	}
	targets, err := current.probeTargets(ctx)
	if err != nil {
		return PathOperationResult{}, err
	}
	bundle, err := current.buildBundle(ctx, readyModems, nil)
	if err != nil {
		return PathOperationResult{}, err
	}
	generatedPath, exists := findGeneratedPath(bundle.Paths, cell.ModemID, cell.SubscriptionID)
	if !exists {
		return PathOperationResult{}, errors.New("active Mihomo bundle has no requested path")
	}
	versionIDs, err := current.endpointVersionIDs(ctx, nil)
	if err != nil {
		return PathOperationResult{}, err
	}
	if err := current.EndpointAccess.AuthorizeMihomoVersions(ctx, versionIDs); err != nil {
		return PathOperationResult{}, fmt.Errorf("authorize active endpoints before path operation: %w", err)
	}
	startedAt := current.now().UTC()
	seed := pathID + ":" + nodeID + ":" + strconv.FormatInt(cell.PolicyGeneration, 10) + ":" + strconv.FormatInt(cell.RouteGeneration, 10) + ":" + strconv.FormatInt(startedAt.UnixNano(), 10)
	phase := options.Phase
	if phase == "" {
		phase = "path-operation"
	}
	apply, err := current.Controller.Apply(ctx, generationID(phase, seed), bundle)
	if err != nil {
		return PathOperationResult{}, fmt.Errorf("apply active bundle for path operation: %w", err)
	}
	restore := func(cause error) error {
		restoreCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
		defer cancel()
		return errors.Join(cause, current.Controller.Restore(restoreCtx, apply.PreviousGeneration))
	}
	healthPath := health.Path{
		ID:             cell.ID,
		ModemID:        cell.ModemID,
		SubscriptionID: cell.SubscriptionID,
		ProviderName:   generatedPath.ProviderName,
		ProbeGroupName: generatedPath.ProbeGroupName,
	}
	transition, transitioning, err := current.policyTransition(ctx)
	if err != nil {
		return PathOperationResult{}, restore(err)
	}
	stickyNodeID := ""
	if nodeID == "" && transitioning && transition.ActivePathID == cell.ID && transition.PolicyTransitionGeneration == cell.PolicyGeneration {
		stickyNodeID = transition.ActiveNodeID
	}
	if nodeID == "" {
		healthPath.PreferredNodeIDs, err = current.preferredNodeIDs(ctx, material, stickyNodeID)
		if err != nil {
			return PathOperationResult{}, restore(err)
		}
	}
	identities := make([]nodeIdentity, 0, len(material.NodesByID))
	for _, identity := range material.NodesByID {
		if nodeID == "" || identity.ID == nodeID {
			identities = append(identities, identity)
		}
	}
	sort.Slice(identities, func(i, j int) bool { return identities[i].ID < identities[j].ID })
	for _, identity := range identities {
		healthPath.Candidates = append(healthPath.Candidates, health.Candidate{
			NodeID: identity.ID, Fingerprint: identity.Fingerprint,
			ProviderNodeName: generatedPath.NodePrefix + identity.ExternalName,
		})
	}
	qualifier := options.Qualifier
	prober := current.Prober
	if current.ProberForClass != nil && options.ProbeClass != "" {
		if selected := current.ProberForClass(options.ProbeClass); selected != nil {
			prober = selected
		}
	}
	qualified, err := qualifier.QualifyCell(ctx, prober, healthPath, targets)
	if err != nil {
		return PathOperationResult{}, restore(fmt.Errorf("qualify exact path: %w", err))
	}
	checkedAt := current.now().UTC()
	expiresAt := checkedAt.Add(current.evidenceTTL())
	operation := PathOperationResult{
		PathID: cell.ID, NodeID: nodeID, Authoritative: options.Authoritative,
		PolicyGeneration: cell.PolicyGeneration, RouteGeneration: cell.RouteGeneration,
		CheckedAt: checkedAt, ExpiresAt: expiresAt, CandidateNodesTotal: len(material.NodesByID), Result: qualified,
	}
	if deferred := deferredReason(qualified); deferred != "" && options.SkipDeferredStore && qualified.State != health.CellQualified {
		operation.Authoritative = false
		operation.DeferredReason = deferred
		if err := restore(nil); err != nil {
			return PathOperationResult{}, err
		}
		current.appendPathOperationEvent(ctx, "PERIODIC_PATH_DEFERRED", operation)
		return operation, nil
	}
	if !options.Authoritative {
		if err := restore(nil); err != nil {
			return PathOperationResult{}, err
		}
		if options.DiagnosticEvent != "" {
			current.appendPathOperationEvent(ctx, options.DiagnosticEvent, operation)
		}
		return operation, nil
	}
	snapshot := pathmatrix.SnapshotFromHealth(qualified, cell.PolicyGeneration, cell.RouteGeneration, checkedAt, expiresAt)
	selectedNodeID := qualified.SelectedNodeID
	if nodeID == "" {
		if err := current.Paths.StoreQualification(ctx, snapshot); err != nil {
			return PathOperationResult{}, restore(fmt.Errorf("store manual path qualification: %w", err))
		}
	} else {
		if len(snapshot.Nodes) != 1 {
			return PathOperationResult{}, restore(errors.New("exact node qualification produced an invalid result count"))
		}
		aggregate, err := current.Paths.StoreNodeQualification(ctx, pathmatrix.NodeQualificationSnapshot{
			PathID: cell.ID, ExpectedPolicyGeneration: cell.PolicyGeneration,
			ExpectedRouteGeneration: cell.RouteGeneration, CandidateNodes: int64(len(material.NodesByID)),
			RequiredTargetsTotal: int64(qualified.RequiredTargetsTotal), CheckedAt: checkedAt,
			ExpiresAt: expiresAt, Node: snapshot.Nodes[0],
		})
		if err != nil {
			return PathOperationResult{}, restore(fmt.Errorf("store manual node qualification: %w", err))
		}
		selectedNodeID = aggregate.SelectedNodeID
	}
	if selectedNodeID != "" {
		identity, exists := material.NodesByID[selectedNodeID]
		if !exists {
			return PathOperationResult{}, restore(errors.New("qualified node identity is unavailable after commit"))
		}
		if err := current.Selector.Select(ctx, generatedPath.GroupName, generatedPath.NodePrefix+identity.ExternalName); err != nil {
			return PathOperationResult{}, restore(fmt.Errorf("select manually qualified path node: %w", err))
		}
	}
	current.evaluateTargetStates(ctx, targets)
	eventType := options.PathEvent
	if nodeID != "" && options.NodeEvent != "" {
		eventType = options.NodeEvent
	}
	if eventType != "" {
		current.appendPathOperationEvent(ctx, eventType, operation)
	}
	return operation, nil
}

func (current *Runtime) periodicProbeNode(ctx context.Context, pathID, nodeID, probeClass string) (PathOperationResult, error) {
	qualifier := current.Qualifier
	qualifier.ContinueAfterRequiredFailure = true
	return current.runPathOperation(ctx, pathID, nodeID, pathOperationOptions{
		ProbeClass: probeClass, Qualifier: qualifier, Phase: "periodic-active-probe",
		DiagnosticEvent: "PERIODIC_ACTIVE_NODE_PROBED",
	})
}

func (current *Runtime) periodicProbePath(ctx context.Context, pathID, probeClass string, exhaustive bool) (PathOperationResult, error) {
	qualifier := current.Qualifier
	qualifier.ContinueAfterRequiredFailure = exhaustive
	return current.runPathOperation(ctx, pathID, "", pathOperationOptions{
		ProbeClass: probeClass, Qualifier: qualifier, Phase: "periodic-path-probe",
		DiagnosticEvent: "PERIODIC_STANDBY_PATH_PROBED",
	})
}

func (current *Runtime) periodicQualifyNode(ctx context.Context, pathID, nodeID, probeClass string, exhaustive bool) (PathOperationResult, error) {
	qualifier := current.Qualifier
	qualifier.ContinueAfterRequiredFailure = exhaustive
	return current.runPathOperation(ctx, pathID, nodeID, pathOperationOptions{
		Authoritative: true, ProbeClass: probeClass, Qualifier: qualifier,
		Phase: "periodic-node-qualify", NodeEvent: "PERIODIC_ACTIVE_NODE_QUALIFIED",
		SkipDeferredStore: true,
	})
}

func (current *Runtime) periodicQualifyPath(ctx context.Context, pathID, probeClass string, exhaustive bool) (PathOperationResult, error) {
	qualifier := current.Qualifier
	qualifier.ContinueAfterRequiredFailure = exhaustive
	return current.runPathOperation(ctx, pathID, "", pathOperationOptions{
		Authoritative: true, ProbeClass: probeClass, Qualifier: qualifier,
		Phase: "periodic-path-qualify", PathEvent: "PERIODIC_PATH_QUALIFIED",
		SkipDeferredStore: true,
	})
}

func deferredReason(result health.CellResult) string {
	for _, node := range result.Nodes {
		if node.Transport.ErrorCode == "DEFERRED_BUDGET" {
			return node.Transport.ErrorCode
		}
		for _, target := range node.Targets {
			if target.ErrorCode == "DEFERRED_BUDGET" {
				return target.ErrorCode
			}
		}
	}
	return ""
}

func findGeneratedPath(paths []mihomo.Path, modemID, subscriptionID string) (mihomo.Path, bool) {
	for _, item := range paths {
		if !item.QualificationOnly && item.ModemID == modemID && item.SubscriptionID == subscriptionID {
			return item, true
		}
	}
	return mihomo.Path{}, false
}

func (current *Runtime) appendPathOperationEvent(ctx context.Context, eventType string, operation PathOperationResult) {
	details := map[string]any{
		"node_id": operation.NodeID, "state": operation.Result.State,
		"policy_generation": operation.PolicyGeneration, "route_generation": operation.RouteGeneration,
		"authoritative": operation.Authoritative,
	}
	_ = current.State.AppendEvent(ctx, state.EventInput{
		Severity: "INFO", Type: eventType, ModemID: operation.Result.ModemID,
		SubscriptionID: operation.Result.SubscriptionID, PathID: operation.PathID, Details: details,
	})
}
