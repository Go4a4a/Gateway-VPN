// Package accesspolicy owns the unified direct/VPN access-method policy.
package accesspolicy

import (
	"errors"
	"fmt"
	"sort"
	"strings"
)

const (
	MethodDirect       = "DIRECT"
	MethodSubscription = "SUBSCRIPTION"

	QualityUnknown = "UNKNOWN"
	QualityFull    = "FULL"
	QualityLimited = "LIMITED"
	QualityFailed  = "FAILED"
)

var ErrNoCandidate = errors.New("no eligible access candidate")

// Candidate is a fresh, concrete method/modem/(optional node) choice. The
// ranker is deliberately independent from SQL so the exact failover ordering
// is deterministic and can be tested without a network namespace.
type Candidate struct {
	Key              string
	PathID           string
	MethodID         string
	MethodKind       string
	ModemID          string
	SubscriptionID   string
	NodeID           string
	Quality          string
	FunctionalScore  int64
	MethodPriority   int64
	ModemPriority    int64
	NodePriority     int64
	MethodEnabled    bool
	ModemReady       bool
	NodeAllowed      bool
	Fresh            bool
	PolicyGeneration int64
	RouteGeneration  int64
}

type Decision struct {
	Candidate Candidate
	Sticky    bool
	Reason    string
}

// Rank applies the architectural order:
//
//	FULL -> highest LIMITED score -> method -> modem -> node -> sticky tie.
//
// Latency is intentionally absent. A small latency change must not move a
// stable user path; operators control the order explicitly.
func Rank(candidates []Candidate, currentKey string) (Decision, error) {
	seen := make(map[string]struct{}, len(candidates))
	eligible := make([]Candidate, 0, len(candidates))
	for _, candidate := range candidates {
		if err := validateCandidate(candidate); err != nil {
			return Decision{}, err
		}
		if _, exists := seen[candidate.Key]; exists {
			return Decision{}, fmt.Errorf("duplicate access candidate key %q", candidate.Key)
		}
		seen[candidate.Key] = struct{}{}
		if !candidate.MethodEnabled || !candidate.ModemReady || !candidate.NodeAllowed || !candidate.Fresh {
			continue
		}
		if candidate.Quality != QualityFull && candidate.Quality != QualityLimited {
			continue
		}
		eligible = append(eligible, candidate)
	}
	if len(eligible) == 0 {
		return Decision{}, ErrNoCandidate
	}
	sort.SliceStable(eligible, func(left, right int) bool {
		return candidateLess(eligible[left], eligible[right], currentKey)
	})
	winner := eligible[0]
	sticky := winner.Key == currentKey
	reason := "FULL_PRIORITY"
	if winner.Quality == QualityLimited {
		reason = "LIMITED_FUNCTIONAL_SCORE"
	}
	if sticky {
		reason += "_STICKY_TIE"
	}
	return Decision{Candidate: winner, Sticky: sticky, Reason: reason}, nil
}

func candidateLess(left, right Candidate, currentKey string) bool {
	leftClass, rightClass := qualityRank(left.Quality), qualityRank(right.Quality)
	if leftClass != rightClass {
		return leftClass > rightClass
	}
	if left.Quality == QualityLimited && left.FunctionalScore != right.FunctionalScore {
		return left.FunctionalScore > right.FunctionalScore
	}
	if left.MethodPriority != right.MethodPriority {
		return left.MethodPriority < right.MethodPriority
	}
	if left.ModemPriority != right.ModemPriority {
		return left.ModemPriority < right.ModemPriority
	}
	if left.NodePriority != right.NodePriority {
		return left.NodePriority < right.NodePriority
	}
	leftCurrent, rightCurrent := left.Key == currentKey, right.Key == currentKey
	if leftCurrent != rightCurrent {
		return leftCurrent
	}
	return left.Key < right.Key
}

func qualityRank(value string) int {
	switch value {
	case QualityFull:
		return 2
	case QualityLimited:
		return 1
	default:
		return 0
	}
}

func validateCandidate(candidate Candidate) error {
	if strings.TrimSpace(candidate.Key) == "" || strings.TrimSpace(candidate.MethodID) == "" || strings.TrimSpace(candidate.ModemID) == "" {
		return errors.New("access candidate key, method, and modem are required")
	}
	if candidate.MethodPriority <= 0 || candidate.ModemPriority <= 0 || candidate.FunctionalScore < 0 {
		return errors.New("access candidate priorities and functional score are invalid")
	}
	switch candidate.Quality {
	case QualityUnknown, QualityFull, QualityLimited, QualityFailed:
	default:
		return fmt.Errorf("access candidate %s has invalid quality %q", candidate.Key, candidate.Quality)
	}
	if candidate.Quality == QualityLimited && candidate.FunctionalScore == 0 {
		return errors.New("LIMITED access candidate requires a positive functional score")
	}
	switch candidate.MethodKind {
	case MethodDirect:
		if candidate.SubscriptionID != "" || candidate.NodeID != "" || candidate.NodePriority != 0 {
			return errors.New("direct candidate cannot contain subscription or node identity")
		}
	case MethodSubscription:
		if strings.TrimSpace(candidate.SubscriptionID) == "" || strings.TrimSpace(candidate.NodeID) == "" || candidate.NodePriority <= 0 {
			return errors.New("subscription candidate requires subscription, node, and node priority")
		}
	default:
		return fmt.Errorf("access candidate %s has invalid method kind %q", candidate.Key, candidate.MethodKind)
	}
	return nil
}
