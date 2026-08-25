// Package health qualifies path-scoped nodes against ordered required and
// optional targets.
package health

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"
)

const (
	CellQualified = "QUALIFIED"
	CellFailed    = "FAILED"
	NodeQualified = "BYPASS_QUALIFIED"
	NodeFailed    = "BYPASS_FAILED"
	NodeCancelled = "CANCELLED"
	ProbePassed   = "PASSED"
	ProbeFailed   = "FAILED"
)

type Target struct {
	ID                    string
	Name                  string
	URL                   string
	Priority              int
	Required              bool
	Timeout               time.Duration
	ExpectedStatus        string
	ExpectedBodySubstring string
}

type Candidate struct {
	NodeID           string
	Fingerprint      string
	ProviderNodeName string
}

type Path struct {
	ID              string
	ModemID         string
	SubscriptionID  string
	ProviderName    string
	ProbeGroupName  string
	PreferredNodeID string
	Candidates      []Candidate
}

type ProbeResult struct {
	State      string
	LatencyMS  int64
	HTTPStatus int
	ErrorCode  string
}

type Prober interface {
	ProbeTransport(context.Context, Path, Candidate) ProbeResult
	ProbeTarget(context.Context, Path, Candidate, Target) ProbeResult
}

type TargetResult struct {
	TargetID   string
	Required   bool
	State      string
	LatencyMS  int64
	HTTPStatus int
	ErrorCode  string
}

type NodeResult struct {
	NodeID             string
	Fingerprint        string
	State              string
	Transport          ProbeResult
	Targets            []TargetResult
	RequiredPassed     int
	RequiredTotal      int
	AggregateLatencyMS int64
}

type CellResult struct {
	PathID                string
	ModemID               string
	SubscriptionID        string
	State                 string
	TransportState        string
	SelectedNodeID        string
	CandidateNodes        int
	QualifiedNodes        int
	RequiredTargetsPassed int
	RequiredTargetsTotal  int
	LatencyMS             int64
	Nodes                 []NodeResult
}

type Qualifier struct {
	MaxConcurrency               int
	ContinueAfterRequiredFailure bool
}

func (qualifier Qualifier) QualifyCell(ctx context.Context, prober Prober, currentPath Path, targets []Target) (CellResult, error) {
	if prober == nil {
		return CellResult{}, errors.New("health prober is required")
	}
	if currentPath.ID == "" || currentPath.ModemID == "" || currentPath.SubscriptionID == "" || currentPath.ProviderName == "" {
		return CellResult{}, errors.New("complete path identity is required")
	}
	orderedTargets, requiredTotal, err := validateTargets(targets)
	if err != nil {
		return CellResult{}, err
	}
	if requiredTotal == 0 {
		return CellResult{}, errors.New("at least one required bypass target is required")
	}
	if len(currentPath.Candidates) == 0 {
		return CellResult{PathID: currentPath.ID, ModemID: currentPath.ModemID, SubscriptionID: currentPath.SubscriptionID, State: CellFailed, TransportState: ProbeFailed, RequiredTargetsTotal: requiredTotal}, nil
	}
	candidates := append([]Candidate(nil), currentPath.Candidates...)
	results := make([]NodeResult, 0, len(candidates))
	if currentPath.PreferredNodeID != "" {
		for index, candidate := range candidates {
			if candidate.NodeID != currentPath.PreferredNodeID {
				continue
			}
			preferred := qualifyNode(ctx, prober, currentPath, candidate, orderedTargets, requiredTotal, qualifier.ContinueAfterRequiredFailure)
			if err := ctx.Err(); err != nil {
				return CellResult{}, err
			}
			results = append(results, preferred)
			candidates = append(candidates[:index], candidates[index+1:]...)
			if preferred.State == NodeQualified {
				return buildCellResult(currentPath, len(currentPath.Candidates), requiredTotal, results), nil
			}
			break
		}
	}
	remaining, err := qualifier.qualifyCandidates(ctx, prober, currentPath, candidates, orderedTargets, requiredTotal)
	if err != nil {
		return CellResult{}, err
	}
	results = append(results, remaining...)
	return buildCellResult(currentPath, len(currentPath.Candidates), requiredTotal, results), nil
}

func (qualifier Qualifier) qualifyCandidates(ctx context.Context, prober Prober, currentPath Path, candidates []Candidate, targets []Target, requiredTotal int) ([]NodeResult, error) {
	if len(candidates) == 0 {
		return nil, nil
	}
	concurrency := qualifier.MaxConcurrency
	if concurrency <= 0 {
		concurrency = 1
	}
	if concurrency > len(candidates) {
		concurrency = len(candidates)
	}
	semaphore := make(chan struct{}, concurrency)
	results := make([]NodeResult, len(candidates))
	var wait sync.WaitGroup
	for index, candidate := range candidates {
		index, candidate := index, candidate
		wait.Add(1)
		go func() {
			defer wait.Done()
			select {
			case semaphore <- struct{}{}:
				defer func() { <-semaphore }()
			case <-ctx.Done():
				results[index] = NodeResult{NodeID: candidate.NodeID, Fingerprint: candidate.Fingerprint, State: NodeCancelled, RequiredTotal: requiredTotal}
				return
			}
			results[index] = qualifyNode(ctx, prober, currentPath, candidate, targets, requiredTotal, qualifier.ContinueAfterRequiredFailure)
		}()
	}
	wait.Wait()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return results, nil
}

func buildCellResult(currentPath Path, candidateCount, requiredTotal int, results []NodeResult) CellResult {
	cell := CellResult{
		PathID:               currentPath.ID,
		ModemID:              currentPath.ModemID,
		SubscriptionID:       currentPath.SubscriptionID,
		State:                CellFailed,
		TransportState:       ProbeFailed,
		CandidateNodes:       candidateCount,
		RequiredTargetsTotal: requiredTotal,
		Nodes:                results,
	}
	bestIndex := -1
	for index, result := range results {
		if result.Transport.State == ProbePassed {
			cell.TransportState = ProbePassed
		}
		if result.State != NodeQualified {
			continue
		}
		cell.QualifiedNodes++
		if bestIndex == -1 || result.AggregateLatencyMS < results[bestIndex].AggregateLatencyMS || (result.AggregateLatencyMS == results[bestIndex].AggregateLatencyMS && result.NodeID < results[bestIndex].NodeID) {
			bestIndex = index
		}
	}
	if bestIndex >= 0 {
		best := results[bestIndex]
		cell.State = CellQualified
		cell.SelectedNodeID = best.NodeID
		cell.RequiredTargetsPassed = best.RequiredPassed
		cell.LatencyMS = best.AggregateLatencyMS
	}
	return cell
}

func qualifyNode(ctx context.Context, prober Prober, currentPath Path, candidate Candidate, targets []Target, requiredTotal int, continueAfterRequiredFailure bool) NodeResult {
	result := NodeResult{NodeID: candidate.NodeID, Fingerprint: candidate.Fingerprint, State: NodeFailed, RequiredTotal: requiredTotal}
	result.Transport = prober.ProbeTransport(ctx, currentPath, candidate)
	if result.Transport.State != ProbePassed {
		return result
	}
	result.AggregateLatencyMS = result.Transport.LatencyMS
	for _, target := range targets {
		if err := ctx.Err(); err != nil {
			result.State = NodeCancelled
			return result
		}
		probe := prober.ProbeTarget(ctx, currentPath, candidate, target)
		result.Targets = append(result.Targets, TargetResult{TargetID: target.ID, Required: target.Required, State: probe.State, LatencyMS: probe.LatencyMS, HTTPStatus: probe.HTTPStatus, ErrorCode: probe.ErrorCode})
		if probe.State == ProbePassed {
			result.AggregateLatencyMS += probe.LatencyMS
			if target.Required {
				result.RequiredPassed++
			}
			continue
		}
		if target.Required && !continueAfterRequiredFailure {
			return result
		}
	}
	if result.RequiredPassed == requiredTotal {
		result.State = NodeQualified
	}
	return result
}

func validateTargets(targets []Target) ([]Target, int, error) {
	ordered := append([]Target(nil), targets...)
	sort.SliceStable(ordered, func(i, j int) bool { return ordered[i].Priority < ordered[j].Priority })
	seenIDs := make(map[string]struct{}, len(ordered))
	required := 0
	for _, target := range ordered {
		if target.ID == "" || target.URL == "" || target.Timeout <= 0 || target.Timeout > 60*time.Second {
			return nil, 0, fmt.Errorf("invalid probe target %q", target.ID)
		}
		if _, exists := seenIDs[target.ID]; exists {
			return nil, 0, fmt.Errorf("duplicate probe target %q", target.ID)
		}
		seenIDs[target.ID] = struct{}{}
		if target.Required {
			required++
		}
	}
	return ordered, required, nil
}
