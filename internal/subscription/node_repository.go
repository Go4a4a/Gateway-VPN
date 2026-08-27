package subscription

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"gateway-vpn/internal/store"
)

type NodeRepository struct {
	database *sql.DB
	now      func() time.Time
}

type ActiveNode struct {
	ID                 string
	VersionID          string
	SubscriptionID     string
	SubscriptionNumber int64
	SubscriptionName   string
	ExternalName       string
	ProxyType          string
	Fingerprint        string
	Enabled            bool
	SelectionOverride  string
	PreferredRank      int64
	UserLabel          string
	CandidateSource    string
	MatchedMatcherID   string
	Modems             []NodeModemStatus
}

type NodeModemStatus struct {
	PathID             string
	ModemID            string
	ModemNumber        int64
	ModemName          string
	PathState          string
	QualificationState string
	LatencyMS          int64
	FailureCode        string
	ExpiresAt          string
	CurrentEvidence    bool
}

type MatcherPreviewInput struct {
	ID      string
	Pattern string
	Type    string
	Enabled bool
}

type MatcherPreviewSubscription struct {
	SubscriptionID     string               `json:"subscription_id"`
	SubscriptionNumber int64                `json:"subscription_number"`
	SubscriptionName   string               `json:"subscription_name"`
	Candidates         int                  `json:"candidates"`
	Filtered           int                  `json:"filtered"`
	Excluded           int                  `json:"excluded"`
	Nodes              []MatcherPreviewNode `json:"nodes"`
}

type MatcherPreviewNode struct {
	ID                string `json:"id"`
	ExternalName      string `json:"external_name"`
	ProxyType         string `json:"proxy_type"`
	Candidate         bool   `json:"candidate"`
	CandidateSource   string `json:"candidate_source"`
	MatchedMatcherID  string `json:"matched_matcher_id"`
	SelectionOverride string `json:"selection_override"`
}

func NewNodeRepository(database *sql.DB) *NodeRepository {
	return &NodeRepository{database: database, now: time.Now}
}

func (repository *NodeRepository) ListActive(ctx context.Context, subscriptionID string) ([]ActiveNode, error) {
	if repository == nil || repository.database == nil {
		return nil, errors.New("node repository database is required")
	}
	query := `
SELECT n.id, n.version_id, s.id, s.display_number, s.name,
	   n.external_name, n.proxy_type, n.fingerprint, n.enabled, n.selection_override,
	   pref.preferred_rank, pref.user_label, n.candidate_source, n.matched_matcher_id
FROM subscriptions AS s
JOIN nodes AS n ON n.version_id=s.active_version_id
LEFT JOIN subscription_node_preferences AS pref
	   ON pref.subscription_id=s.id AND pref.fingerprint=n.fingerprint`
	arguments := []any{}
	if strings.TrimSpace(subscriptionID) != "" {
		query += " WHERE s.id=?"
		arguments = append(arguments, strings.TrimSpace(subscriptionID))
	}
	query += " ORDER BY s.enabled DESC, s.priority, s.display_number, n.normalized_name, n.id"
	rows, err := repository.database.QueryContext(ctx, query, arguments...)
	if err != nil {
		return nil, fmt.Errorf("list active subscription nodes: %w", err)
	}
	defer rows.Close()
	result := []ActiveNode{}
	for rows.Next() {
		var item ActiveNode
		var enabled int
		var rank sql.NullInt64
		var label, matched sql.NullString
		if err := rows.Scan(&item.ID, &item.VersionID, &item.SubscriptionID, &item.SubscriptionNumber, &item.SubscriptionName, &item.ExternalName, &item.ProxyType, &item.Fingerprint, &enabled, &item.SelectionOverride, &rank, &label, &item.CandidateSource, &matched); err != nil {
			return nil, fmt.Errorf("scan active subscription node: %w", err)
		}
		item.Enabled = enabled != 0
		item.PreferredRank = rank.Int64
		item.UserLabel = label.String
		item.MatchedMatcherID = matched.String
		result = append(result, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate active subscription nodes: %w", err)
	}
	for index := range result {
		statuses, err := repository.nodeModemStatuses(ctx, result[index])
		if err != nil {
			return nil, err
		}
		result[index].Modems = statuses
	}
	return result, nil
}

func (repository *NodeRepository) SetOverride(ctx context.Context, nodeID, override string) (string, error) {
	override = strings.TrimSpace(override)
	if override != OverrideAuto && override != OverrideInclude && override != OverrideExclude {
		return "", errors.New("node selection override must be auto, include, or exclude")
	}
	transaction, err := repository.database.BeginTx(ctx, nil)
	if err != nil {
		return "", fmt.Errorf("begin node override: %w", err)
	}
	defer transaction.Rollback()
	var versionID, subscriptionID, fingerprint string
	err = transaction.QueryRowContext(ctx, `
SELECT n.version_id, s.id, n.fingerprint
FROM nodes AS n
JOIN subscriptions AS s ON s.active_version_id=n.version_id
WHERE n.id=?`, strings.TrimSpace(nodeID)).Scan(&versionID, &subscriptionID, &fingerprint)
	if errors.Is(err, sql.ErrNoRows) {
		return "", store.ErrNotFound
	}
	if err != nil {
		return "", fmt.Errorf("read active node for override: %w", err)
	}
	matchers, err := loadMatchersTx(ctx, transaction)
	if err != nil {
		return "", err
	}
	if err := reclassifyVersionNodesTx(ctx, transaction, versionID, matchers, nodeID, override); err != nil {
		return "", err
	}
	now := repository.now().UTC().Format(time.RFC3339Nano)
	if _, err := transaction.ExecContext(ctx, `
INSERT INTO subscription_node_preferences (
    subscription_id, fingerprint, selection_override, last_seen_version_id,
    created_at, updated_at
) VALUES (?, ?, ?, ?, ?, ?)
ON CONFLICT(subscription_id, fingerprint) DO UPDATE SET
    selection_override=excluded.selection_override,
    last_seen_version_id=excluded.last_seen_version_id,
    missing_since=NULL,
    updated_at=excluded.updated_at`, subscriptionID, fingerprint, override, versionID, now, now); err != nil {
		return "", fmt.Errorf("persist subscription node preference: %w", err)
	}
	if _, err := store.InvalidatePathPolicy(ctx, transaction, now); err != nil {
		return "", fmt.Errorf("invalidate paths after node override: %w", err)
	}
	if err := appendSubscriptionEventTx(ctx, transaction, now, "NODE_OVERRIDE_CHANGED", subscriptionID, map[string]any{"node_id": nodeID, "selection_override": override}); err != nil {
		return "", err
	}
	if err := transaction.Commit(); err != nil {
		return "", fmt.Errorf("commit node override: %w", err)
	}
	return subscriptionID, nil
}

func (repository *MatcherRepository) Preview(ctx context.Context, input MatcherPreviewInput) ([]MatcherPreviewSubscription, error) {
	transaction, err := repository.database.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, fmt.Errorf("begin matcher preview: %w", err)
	}
	defer transaction.Rollback()
	matchers, err := loadMatchersTx(ctx, transaction)
	if err != nil {
		return nil, err
	}
	proposal := Matcher{ID: strings.TrimSpace(input.ID), Pattern: strings.TrimSpace(input.Pattern), Type: input.Type, Enabled: input.Enabled}
	if proposal.ID == "" {
		proposal.ID = "preview-new-matcher"
		proposal.Enabled = true
		maxPriority := 0
		for _, matcher := range matchers {
			if matcher.Priority > maxPriority {
				maxPriority = matcher.Priority
			}
		}
		proposal.Priority = maxPriority + 10
		matchers = append(matchers, proposal)
	} else {
		found := false
		for index := range matchers {
			if matchers[index].ID == proposal.ID {
				proposal.Priority = matchers[index].Priority
				matchers[index] = proposal
				found = true
				break
			}
		}
		if !found {
			return nil, store.ErrNotFound
		}
	}
	if _, err := CompileMatchers(matchers); err != nil {
		return nil, err
	}
	rows, err := transaction.QueryContext(ctx, `
SELECT s.id, s.display_number, s.name, s.active_version_id
FROM subscriptions AS s
WHERE s.active_version_id IS NOT NULL
ORDER BY s.enabled DESC, s.priority, s.display_number`)
	if err != nil {
		return nil, fmt.Errorf("list subscriptions for matcher preview: %w", err)
	}
	type activeVersion struct {
		subscriptionID string
		number         int64
		name           string
		versionID      string
	}
	versions := []activeVersion{}
	for rows.Next() {
		var item activeVersion
		if err := rows.Scan(&item.subscriptionID, &item.number, &item.name, &item.versionID); err != nil {
			rows.Close()
			return nil, err
		}
		versions = append(versions, item)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	result := make([]MatcherPreviewSubscription, 0, len(versions))
	for _, version := range versions {
		nodes, overrides, err := loadVersionNodesTx(ctx, transaction, version.versionID, "", "")
		if err != nil {
			return nil, err
		}
		classified, err := Classify(nodes, matchers, overrides)
		if err != nil {
			return nil, err
		}
		item := MatcherPreviewSubscription{SubscriptionID: version.subscriptionID, SubscriptionNumber: version.number, SubscriptionName: version.name, Nodes: make([]MatcherPreviewNode, 0, len(classified))}
		for _, classification := range classified {
			node := MatcherPreviewNode{ID: stableNodeID(version.versionID, classification.Node.Fingerprint), ExternalName: classification.Node.ExternalName, ProxyType: classification.Node.ProxyType, Candidate: classification.Candidate, CandidateSource: classification.CandidateSource, MatchedMatcherID: classification.MatchedMatcher, SelectionOverride: overrides[classification.Node.Fingerprint]}
			if node.SelectionOverride == "" {
				node.SelectionOverride = OverrideAuto
			}
			item.Nodes = append(item.Nodes, node)
			switch classification.CandidateSource {
			case "MANUAL_EXCLUDE":
				item.Excluded++
			case "NAME_FILTERED":
				item.Filtered++
			default:
				if classification.Candidate {
					item.Candidates++
				}
			}
		}
		result = append(result, item)
	}
	return result, nil
}

func (repository *NodeRepository) nodeModemStatuses(ctx context.Context, node ActiveNode) ([]NodeModemStatus, error) {
	rows, err := repository.database.QueryContext(ctx, `
SELECT COALESCE(p.id, ''), m.id, m.display_number, m.name,
       COALESCE(p.state, 'UNTESTED'), COALESCE(pn.qualification_state, 'UNTESTED'),
       COALESCE(pn.latency_ms, 0), COALESCE(pn.failure_code, ''),
       COALESCE(pn.qualification_expires_at, ''),
       COALESCE(p.policy_generation, 0), COALESCE(p.route_generation, 0),
       COALESCE(pn.qualification_generation, 0), COALESCE(pn.route_generation, 0)
FROM modems AS m
LEFT JOIN subscription_modem_paths AS p
       ON p.modem_id=m.id AND p.subscription_id=?
LEFT JOIN path_nodes AS pn ON pn.path_id=p.id AND pn.node_id=?
ORDER BY m.enabled DESC, m.priority, m.display_number`, node.SubscriptionID, node.ID)
	if err != nil {
		return nil, fmt.Errorf("list node modem statuses: %w", err)
	}
	defer rows.Close()
	result := []NodeModemStatus{}
	now := repository.now().UTC()
	for rows.Next() {
		var item NodeModemStatus
		var pathPolicyGeneration, pathRouteGeneration, evidencePolicyGeneration, evidenceRouteGeneration int64
		if err := rows.Scan(&item.PathID, &item.ModemID, &item.ModemNumber, &item.ModemName, &item.PathState, &item.QualificationState, &item.LatencyMS, &item.FailureCode, &item.ExpiresAt, &pathPolicyGeneration, &pathRouteGeneration, &evidencePolicyGeneration, &evidenceRouteGeneration); err != nil {
			return nil, err
		}
		if item.PathState == "MODEM_OFFLINE" || item.PathState == "MODEM_DISABLED" || item.PathState == "SUBSCRIPTION_DISABLED" {
			item.QualificationState = item.PathState
		} else if item.ExpiresAt != "" {
			expires, parseErr := time.Parse(time.RFC3339Nano, item.ExpiresAt)
			item.CurrentEvidence = parseErr == nil && expires.After(now) && evidencePolicyGeneration == pathPolicyGeneration && evidenceRouteGeneration == pathRouteGeneration
			if !item.CurrentEvidence {
				item.QualificationState = "STALE"
			}
		}
		result = append(result, item)
	}
	return result, rows.Err()
}

func loadMatchersTx(ctx context.Context, transaction *sql.Tx) ([]Matcher, error) {
	rows, err := transaction.QueryContext(ctx, "SELECT id, pattern, match_type, priority, enabled FROM node_matchers ORDER BY enabled DESC, priority, id")
	if err != nil {
		return nil, fmt.Errorf("list node matchers: %w", err)
	}
	defer rows.Close()
	result := []Matcher{}
	for rows.Next() {
		var matcher Matcher
		var enabled int
		if err := rows.Scan(&matcher.ID, &matcher.Pattern, &matcher.Type, &matcher.Priority, &enabled); err != nil {
			return nil, err
		}
		matcher.Enabled = enabled != 0
		result = append(result, matcher)
	}
	return result, rows.Err()
}

func reclassifyAllActiveNodesTx(ctx context.Context, transaction *sql.Tx) error {
	matchers, err := loadMatchersTx(ctx, transaction)
	if err != nil {
		return err
	}
	if _, err := CompileMatchers(matchers); err != nil {
		return err
	}
	rows, err := transaction.QueryContext(ctx, "SELECT active_version_id FROM subscriptions WHERE active_version_id IS NOT NULL")
	if err != nil {
		return err
	}
	versionIDs := []string{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		versionIDs = append(versionIDs, id)
	}
	if err := rows.Close(); err != nil {
		return err
	}
	for _, versionID := range versionIDs {
		if err := reclassifyVersionNodesTx(ctx, transaction, versionID, matchers, "", ""); err != nil {
			return err
		}
	}
	return nil
}

func reclassifyVersionNodesTx(ctx context.Context, transaction *sql.Tx, versionID string, matchers []Matcher, overrideNodeID, replacementOverride string) error {
	nodes, overrides, err := loadVersionNodesTx(ctx, transaction, versionID, overrideNodeID, replacementOverride)
	if err != nil {
		return err
	}
	classified, err := Classify(nodes, matchers, overrides)
	if err != nil {
		return err
	}
	for _, item := range classified {
		override := overrides[item.Node.Fingerprint]
		if override == "" {
			override = OverrideAuto
		}
		result, err := transaction.ExecContext(ctx, `
UPDATE nodes
SET enabled=?, selection_override=?, candidate_source=?, matched_matcher_id=?
WHERE id=? AND version_id=?`, boolToInt(item.Candidate), override, item.CandidateSource, nullIfEmpty(item.MatchedMatcher), stableNodeID(versionID, item.Node.Fingerprint), versionID)
		if err != nil {
			return fmt.Errorf("update node classification: %w", err)
		}
		count, err := result.RowsAffected()
		if err != nil || count != 1 {
			return errors.New("node classification update count mismatch")
		}
	}
	return nil
}

func loadVersionNodesTx(ctx context.Context, transaction *sql.Tx, versionID, overrideNodeID, replacementOverride string) ([]ImportedNode, map[string]string, error) {
	rows, err := transaction.QueryContext(ctx, `
SELECT id, external_name, normalized_name, fingerprint, proxy_type, selection_override
FROM nodes WHERE version_id=? ORDER BY normalized_name, id`, versionID)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	nodes := []ImportedNode{}
	overrides := map[string]string{}
	foundOverrideNode := overrideNodeID == ""
	for rows.Next() {
		var id, externalName, normalizedName, fingerprint, proxyType, override string
		if err := rows.Scan(&id, &externalName, &normalizedName, &fingerprint, &proxyType, &override); err != nil {
			return nil, nil, err
		}
		if id == overrideNodeID {
			override = replacementOverride
			foundOverrideNode = true
		}
		nodes = append(nodes, ImportedNode{ExternalName: externalName, MatchName: normalizedName, NormalizedName: normalizedName, Fingerprint: fingerprint, ProxyType: proxyType})
		overrides[fingerprint] = override
	}
	if err := rows.Err(); err != nil {
		return nil, nil, err
	}
	if !foundOverrideNode {
		return nil, nil, store.ErrNotFound
	}
	return nodes, overrides, nil
}
