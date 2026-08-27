package health

import (
	"context"
	"sync"
	"testing"
	"time"
)

func TestQualifyCellSelectsLowestLatencyQualifiedNode(t *testing.T) {
	prober := &fakeProber{
		transport: map[string]ProbeResult{"node-a": pass(20), "node-b": pass(10), "node-c": ProbeResult{State: ProbeFailed, ErrorCode: "CONNECT"}},
		targets: map[string]map[string]ProbeResult{
			"node-a": {"required": pass(80), "optional": ProbeResult{State: ProbeFailed, ErrorCode: "OPTIONAL"}},
			"node-b": {"required": pass(30), "optional": pass(10)},
		},
	}
	result, err := (Qualifier{MaxConcurrency: 2}).QualifyCell(context.Background(), prober, testPath(), testTargets())
	if err != nil {
		t.Fatalf("QualifyCell() error = %v", err)
	}
	if result.State != CellQualified || result.SelectedNodeID != "node-b" || result.QualifiedNodes != 2 || result.RequiredTargetsPassed != 1 {
		t.Fatalf("cell result = %+v", result)
	}
	if prober.maxInFlight > 2 {
		t.Fatalf("max concurrent probes = %d, want <=2", prober.maxInFlight)
	}
}

func TestRequiredFailureIsFailFastButOptionalFailureIsNot(t *testing.T) {
	prober := &fakeProber{
		transport: map[string]ProbeResult{"node-a": pass(1), "node-b": pass(1), "node-c": pass(1)},
		targets: map[string]map[string]ProbeResult{
			"node-a": {"required": ProbeResult{State: ProbeFailed}, "optional": pass(1)},
			"node-b": {"required": pass(1), "optional": ProbeResult{State: ProbeFailed}},
			"node-c": {"required": ProbeResult{State: ProbeFailed}, "optional": pass(1)},
		},
	}
	result, err := (Qualifier{MaxConcurrency: 1}).QualifyCell(context.Background(), prober, testPath(), testTargets())
	if err != nil {
		t.Fatalf("QualifyCell() error = %v", err)
	}
	if result.SelectedNodeID != "node-b" {
		t.Fatalf("selected node = %s, want node-b", result.SelectedNodeID)
	}
	for _, node := range result.Nodes {
		if node.NodeID == "node-a" && len(node.Targets) != 1 {
			t.Fatalf("required failure did not stop remaining targets: %+v", node.Targets)
		}
		if node.NodeID == "node-b" && node.State != NodeQualified {
			t.Fatalf("optional failure disqualified node-b: %+v", node)
		}
	}
}

func TestOutageConfirmationContinuesAfterRequiredFailure(t *testing.T) {
	prober := &fakeProber{
		transport: map[string]ProbeResult{"node-a": pass(1)},
		targets: map[string]map[string]ProbeResult{
			"node-a": {"required": {State: ProbeFailed, ErrorCode: "TARGET_DOWN"}, "optional": pass(1)},
		},
	}
	path := testPath()
	path.Candidates = path.Candidates[:1]
	result, err := (Qualifier{MaxConcurrency: 1, ContinueAfterRequiredFailure: true}).QualifyCell(context.Background(), prober, path, testTargets())
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Nodes) != 1 || len(result.Nodes[0].Targets) != 2 || result.Nodes[0].State != NodeLimited || result.State != CellDegraded || result.SelectedNodeID != "node-a" || result.FunctionalScore != 1 {
		t.Fatalf("exhaustive outage result = %+v", result)
	}
}

func TestNoRequiredTargetsBlocksQualification(t *testing.T) {
	_, err := (Qualifier{}).QualifyCell(context.Background(), &fakeProber{}, testPath(), []Target{{ID: "optional", URL: "https://example.com", Timeout: time.Second}})
	if err == nil {
		t.Fatal("QualifyCell(no required targets) error = nil")
	}
}

func TestPreferredActiveNodeIsCheckedAloneFirstAndRetainedWhenQualified(t *testing.T) {
	prober := &fakeProber{
		transport: map[string]ProbeResult{"node-a": pass(100), "node-b": pass(1), "node-c": pass(1)},
		targets: map[string]map[string]ProbeResult{
			"node-a": {"required": pass(100), "optional": pass(100)},
			"node-b": {"required": pass(1), "optional": pass(1)},
			"node-c": {"required": pass(1), "optional": pass(1)},
		},
	}
	path := testPath()
	path.PreferredNodeID = "node-a"
	result, err := (Qualifier{MaxConcurrency: 2}).QualifyCell(context.Background(), prober, path, testTargets())
	if err != nil || result.SelectedNodeID != "node-a" || result.CandidateNodes != 3 || len(result.Nodes) != 1 {
		t.Fatalf("preferred qualification = %+v, %v", result, err)
	}
}

func TestPreferredActiveNodeFailureFallsThroughToRemainingCandidates(t *testing.T) {
	prober := &fakeProber{
		transport: map[string]ProbeResult{"node-a": pass(1), "node-b": pass(2), "node-c": pass(3)},
		targets: map[string]map[string]ProbeResult{
			"node-a": {"required": {State: ProbeFailed, ErrorCode: "POLICY"}},
			"node-b": {"required": pass(2), "optional": pass(2)},
			"node-c": {"required": pass(3), "optional": pass(3)},
		},
	}
	path := testPath()
	path.PreferredNodeID = "node-a"
	result, err := (Qualifier{MaxConcurrency: 2}).QualifyCell(context.Background(), prober, path, testTargets())
	if err != nil || result.SelectedNodeID != "node-b" || len(result.Nodes) != 3 || result.Nodes[0].NodeID != "node-a" || result.Nodes[0].State != NodeFailed {
		t.Fatalf("preferred fallback qualification = %+v, %v", result, err)
	}
}

func testPath() Path {
	return Path{
		ID: "path-a", ModemID: "modem-a", SubscriptionID: "sub-a", ProviderName: "provider-a",
		Candidates: []Candidate{{NodeID: "node-a", Fingerprint: "a"}, {NodeID: "node-b", Fingerprint: "b"}, {NodeID: "node-c", Fingerprint: "c"}},
	}
}

func testTargets() []Target {
	return []Target{
		{ID: "optional", URL: "https://optional.example.com", Priority: 20, Required: false, Timeout: time.Second},
		{ID: "required", URL: "https://required.example.com", Priority: 10, Required: true, Timeout: time.Second},
	}
}

func pass(latency int64) ProbeResult { return ProbeResult{State: ProbePassed, LatencyMS: latency} }

type fakeProber struct {
	mu          sync.Mutex
	transport   map[string]ProbeResult
	targets     map[string]map[string]ProbeResult
	inFlight    int
	maxInFlight int
}

func (prober *fakeProber) ProbeTransport(_ context.Context, _ Path, candidate Candidate) ProbeResult {
	prober.enter()
	defer prober.leave()
	time.Sleep(time.Millisecond)
	return prober.transport[candidate.NodeID]
}

func (prober *fakeProber) ProbeTarget(_ context.Context, _ Path, candidate Candidate, target Target) ProbeResult {
	prober.enter()
	defer prober.leave()
	time.Sleep(time.Millisecond)
	return prober.targets[candidate.NodeID][target.ID]
}

func (prober *fakeProber) enter() {
	prober.mu.Lock()
	defer prober.mu.Unlock()
	prober.inFlight++
	if prober.inFlight > prober.maxInFlight {
		prober.maxInFlight = prober.inFlight
	}
}

func (prober *fakeProber) leave() {
	prober.mu.Lock()
	defer prober.mu.Unlock()
	prober.inFlight--
}
