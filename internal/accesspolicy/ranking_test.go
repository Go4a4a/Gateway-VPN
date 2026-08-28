package accesspolicy

import (
	"errors"
	"testing"
)

func TestRankPrefersFullRegardlessOfMethodPriority(t *testing.T) {
	direct := candidate("direct-a", MethodDirect, QualityWhitelistOnly, 900, 1, 1, 0)
	vpn := candidate("vpn-a", MethodSubscription, QualityFull, 0, 20, 2, 1)
	decision, err := Rank([]Candidate{direct, vpn}, "direct-a")
	if err != nil || decision.Candidate.Key != "vpn-a" || decision.Sticky {
		t.Fatalf("Rank() = %+v, %v", decision, err)
	}
}

func TestRankLimitedUsesFunctionBeforePriority(t *testing.T) {
	preferred := candidate("direct-a", MethodDirect, QualityLimited, 20, 1, 1, 0)
	functional := candidate("vpn-a", MethodSubscription, QualityLimited, 80, 20, 2, 1)
	decision, err := Rank([]Candidate{preferred, functional}, "")
	if err != nil || decision.Candidate.Key != "vpn-a" || decision.Reason != "LIMITED_FUNCTIONAL_SCORE" {
		t.Fatalf("Rank() = %+v, %v", decision, err)
	}
}

func TestRankUsesMethodUplinkNodeAndStickyTie(t *testing.T) {
	items := []Candidate{
		candidate("method-second", MethodSubscription, QualityFull, 0, 20, 1, 1),
		candidate("modem-second", MethodSubscription, QualityFull, 0, 10, 2, 1),
		candidate("node-second", MethodSubscription, QualityFull, 0, 10, 1, 2),
		candidate("node-first-a", MethodSubscription, QualityFull, 0, 10, 1, 1),
		candidate("node-first-b", MethodSubscription, QualityFull, 0, 10, 1, 1),
	}
	decision, err := Rank(items, "node-first-b")
	if err != nil || decision.Candidate.Key != "node-first-b" || !decision.Sticky || decision.Reason != "FULL_PRIORITY_STICKY_TIE" {
		t.Fatalf("Rank() = %+v, %v", decision, err)
	}
	decision, err = Rank(items, "missing")
	if err != nil || decision.Candidate.Key != "node-first-a" || decision.Sticky {
		t.Fatalf("deterministic Rank() = %+v, %v", decision, err)
	}
}

func TestRankFiltersUnavailableAndRejectsInvalidCandidates(t *testing.T) {
	unavailable := candidate("offline", MethodDirect, QualityFull, 0, 1, 1, 0)
	unavailable.UplinkReady = false
	failed := candidate("failed", MethodDirect, QualityFailed, 0, 1, 1, 0)
	if _, err := Rank([]Candidate{unavailable, failed}, ""); !errors.Is(err, ErrNoCandidate) {
		t.Fatalf("Rank() error = %v, want ErrNoCandidate", err)
	}
	invalid := candidate("invalid", MethodDirect, QualityFull, 0, 1, 1, 0)
	invalid.NodeID = "not-allowed"
	if _, err := Rank([]Candidate{invalid}, ""); err == nil {
		t.Fatal("Rank() accepted direct candidate with a node")
	}
}

func candidate(key, kind, quality string, score, methodPriority, uplinkPriority, nodePriority int64) Candidate {
	item := Candidate{
		Key: key, MethodID: "method:" + key, MethodKind: kind, UplinkID: "modem-a",
		Quality: quality, FunctionalScore: score, MethodPriority: methodPriority,
		UplinkPriority: uplinkPriority, NodePriority: nodePriority,
		MethodEnabled: true, UplinkReady: true, NodeAllowed: true, Fresh: true,
	}
	if kind == MethodSubscription {
		item.SubscriptionID = "sub-a"
		item.NodeID = "node-a"
	}
	return item
}
