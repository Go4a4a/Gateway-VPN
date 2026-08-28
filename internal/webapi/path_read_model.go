package webapi

import (
	"context"
	"fmt"
	"sort"
	"time"

	"gateway-vpn/internal/accesspolicy"
	"gateway-vpn/internal/pathmatrix"
	"gateway-vpn/internal/state"
)

// pathReadItem is the canonical Web API view for every user access path.
// DIRECT and SUBSCRIPTION rows intentionally share the same quality/evidence
// fields so Modems, Subscriptions, and Path Matrix cannot disagree.
type pathReadItem struct {
	ID                     string `json:"id"`
	Kind                   string `json:"kind"`
	MethodID               string `json:"method_id"`
	MethodName             string `json:"method_name"`
	MethodEnabled          bool   `json:"method_enabled"`
	MethodPriority         int64  `json:"method_priority"`
	UplinkID               string `json:"uplink_id"`
	UplinkNumber           int64  `json:"uplink_number"`
	UplinkType             string `json:"uplink_type"`
	UplinkName             string `json:"uplink_name"`
	UplinkPriority         int64  `json:"uplink_priority"`
	ModemID                string `json:"modem_id,omitempty"`
	ModemNumber            int64  `json:"modem_number,omitempty"`
	ModemName              string `json:"modem_name,omitempty"`
	ModemPriority          int64  `json:"modem_priority,omitempty"`
	SubscriptionID         string `json:"subscription_id"`
	SubscriptionName       string `json:"subscription_name"`
	SubscriptionPriority   int64  `json:"subscription_priority"`
	State                  string `json:"state"`
	StoredState            string `json:"stored_state"`
	ReasonCode             string `json:"reason_code"`
	TransportState         string `json:"transport_state"`
	QualityClass           string `json:"quality_class"`
	FunctionalScore        int64  `json:"functional_score"`
	SelectedNodeID         string `json:"selected_node_id"`
	CandidateNodes         int64  `json:"candidate_nodes"`
	QualifiedNodes         int64  `json:"qualified_nodes"`
	RequiredTargetsPassed  int64  `json:"required_targets_passed"`
	RequiredTargetsTotal   int64  `json:"required_targets_total"`
	OptionalTargetsPassed  int64  `json:"optional_targets_passed"`
	OptionalTargetsTotal   int64  `json:"optional_targets_total"`
	WhitelistTargetsPassed int64  `json:"whitelist_targets_passed"`
	WhitelistTargetsTotal  int64  `json:"whitelist_targets_total"`
	LatencyMS              int64  `json:"latency_ms"`
	PolicyGeneration       int64  `json:"policy_generation"`
	RouteGeneration        int64  `json:"route_generation"`
	LastCheckedAt          string `json:"last_checked_at"`
	ExpiresAt              string `json:"expires_at"`
	FailureCode            string `json:"failure_code"`
	Active                 bool   `json:"active"`
}

func (server *Server) readAccessPaths(ctx context.Context) ([]pathReadItem, error) {
	vpnPaths, err := server.dependencies.Paths.List(ctx)
	if err != nil {
		return nil, err
	}
	directPaths, err := server.dependencies.DirectPaths.List(ctx)
	if err != nil {
		return nil, err
	}
	methods, err := server.dependencies.AccessPolicy.ListMethods(ctx)
	if err != nil {
		return nil, err
	}
	snapshot, err := server.dependencies.State.Get(ctx)
	if err != nil {
		return nil, err
	}
	methodsBySubscription := make(map[string]accesspolicy.Method, len(methods))
	for _, method := range methods {
		if method.SubscriptionID != "" {
			methodsBySubscription[method.SubscriptionID] = method
		}
	}
	now := server.now()
	result := make([]pathReadItem, 0, len(vpnPaths)+len(directPaths))
	for _, cell := range vpnPaths {
		method, exists := methodsBySubscription[cell.SubscriptionID]
		if !exists {
			return nil, fmt.Errorf("subscription %s has no access method", cell.SubscriptionID)
		}
		effectiveState, reason := effectivePathState(cell, now)
		item := pathReadItem{
			ID: cell.ID, Kind: accesspolicy.MethodSubscription,
			MethodID: method.ID, MethodName: method.Name, MethodEnabled: method.Enabled, MethodPriority: method.Priority,
			UplinkID: cell.UplinkID, UplinkNumber: cell.UplinkDisplayNumber, UplinkType: cell.UplinkType, UplinkName: cell.UplinkName, UplinkPriority: cell.UplinkPriority,
			SubscriptionID: cell.SubscriptionID, SubscriptionName: cell.SubscriptionName, SubscriptionPriority: cell.SubscriptionPriority,
			State: effectiveState, StoredState: cell.State, ReasonCode: reason,
			TransportState: cell.TransportState, QualityClass: cell.QualityClass, FunctionalScore: cell.FunctionalScore,
			SelectedNodeID: cell.SelectedNodeID, CandidateNodes: cell.CandidateNodes, QualifiedNodes: cell.QualifiedNodes,
			RequiredTargetsPassed: cell.RequiredTargetsPassed, RequiredTargetsTotal: cell.RequiredTargetsTotal,
			OptionalTargetsPassed: cell.OptionalTargetsPassed, OptionalTargetsTotal: cell.OptionalTargetsTotal,
			LatencyMS: cell.LatencyMS, PolicyGeneration: cell.PolicyGeneration, RouteGeneration: cell.RouteGeneration,
			LastCheckedAt: cell.LastCheckedAt, ExpiresAt: cell.ExpiresAt,
			Active: snapshot.PathState == state.PathActive && snapshot.ActivePathID == cell.ID,
		}
		if cell.UplinkType == "HILINK" {
			item.ModemID, item.ModemNumber, item.ModemName, item.ModemPriority = cell.UplinkID, cell.UplinkDisplayNumber, cell.UplinkName, cell.UplinkPriority
		}
		result = append(result, item)
	}
	for _, path := range directPaths {
		effectiveState, reason := effectiveDirectPathState(path, now)
		item := pathReadItem{
			ID: path.ID, Kind: accesspolicy.MethodDirect,
			MethodID: accesspolicy.DirectMethodID, MethodName: "Прямой интернет", MethodEnabled: path.MethodEnabled, MethodPriority: path.MethodPriority,
			UplinkID: path.UplinkID, UplinkNumber: path.UplinkNumber, UplinkType: path.UplinkType, UplinkName: path.UplinkName, UplinkPriority: path.UplinkPriority,
			State: effectiveState, StoredState: path.State, ReasonCode: reason,
			TransportState: path.TransportState, QualityClass: path.QualityClass, FunctionalScore: path.FunctionalScore,
			RequiredTargetsPassed: path.RequiredTargetsPassed, RequiredTargetsTotal: path.RequiredTargetsTotal,
			OptionalTargetsPassed: path.OptionalTargetsPassed, OptionalTargetsTotal: path.OptionalTargetsTotal,
			WhitelistTargetsPassed: path.WhitelistTargetsPassed, WhitelistTargetsTotal: path.WhitelistTargetsTotal,
			LatencyMS: path.LatencyMS, PolicyGeneration: path.PolicyGeneration, RouteGeneration: path.RouteGeneration,
			LastCheckedAt: path.LastCheckedAt, ExpiresAt: path.ExpiresAt, FailureCode: path.FailureCode,
			Active: snapshot.PathState == state.PathActive && snapshot.ActiveDirectPathID == path.ID,
		}
		if path.UplinkType == "HILINK" {
			item.ModemID, item.ModemNumber, item.ModemName, item.ModemPriority = path.UplinkID, path.UplinkNumber, path.UplinkName, path.UplinkPriority
		}
		result = append(result, item)
	}
	sort.SliceStable(result, func(left, right int) bool {
		if result[left].UplinkPriority != result[right].UplinkPriority {
			return result[left].UplinkPriority < result[right].UplinkPriority
		}
		if result[left].UplinkNumber != result[right].UplinkNumber {
			return result[left].UplinkNumber < result[right].UplinkNumber
		}
		if result[left].MethodEnabled != result[right].MethodEnabled {
			return result[left].MethodEnabled
		}
		if result[left].MethodPriority != result[right].MethodPriority {
			return result[left].MethodPriority < result[right].MethodPriority
		}
		return result[left].ID < result[right].ID
	})
	return result, nil
}

func effectiveDirectPathState(path accesspolicy.DirectPath, now time.Time) (string, string) {
	if path.State == pathmatrix.StateQualified || path.State == pathmatrix.StateDegraded {
		expires, err := time.Parse(time.RFC3339Nano, path.ExpiresAt)
		if err != nil || !expires.After(now) {
			return pathmatrix.StateStale, "RESULT_EXPIRED"
		}
		if path.State == pathmatrix.StateQualified {
			return path.State, "FRESH_FULL"
		}
		return path.State, "FRESH_LIMITED"
	}
	if path.FailureCode != "" {
		return path.State, path.FailureCode
	}
	return path.State, path.State
}
