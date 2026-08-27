package subscription

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"gateway-vpn/internal/store"
)

const (
	VersionCandidate  = "CANDIDATE"
	VersionLKG        = "LKG"
	VersionRetained   = "RETAINED"
	VersionFailed     = "FAILED"
	CandidateName     = "NAME_MATCH"
	CandidateFallback = "NO_NAME_MATCH_FALLBACK_ALL"
)

// VersionRepository persists immutable subscription versions and their node
// identities. The normalized proxy payload itself is intentionally stored in
// the protected subscription payload directory, not duplicated in SQLite.
type VersionRepository struct {
	database *sql.DB
	now      func() time.Time
}

type StageInput struct {
	VersionID      string
	SubscriptionID string
	Payload        []byte
	Matchers       []Matcher
	Overrides      map[string]string
}

type Version struct {
	ID             string
	SubscriptionID string
	ContentSHA256  string
	NodesTotal     int64
	State          string
	Error          string
	CreatedAt      string
	ActivatedAt    string
}

type StoredNode struct {
	ID                string
	VersionID         string
	ExternalName      string
	NormalizedName    string
	Fingerprint       string
	ProxyType         string
	Enabled           bool
	SelectionOverride string
	CandidateSource   string
	MatchedMatcherID  string
}

type StagedVersion struct {
	Version Version
	Format  string
	Nodes   []StoredNode
	Import  ImportResult
}

func NewVersionRepository(database *sql.DB) *VersionRepository {
	return &VersionRepository{database: database, now: time.Now}
}

func (repository *VersionRepository) Stage(ctx context.Context, input StageInput) (StagedVersion, error) {
	if strings.TrimSpace(input.VersionID) == "" || strings.TrimSpace(input.SubscriptionID) == "" {
		return StagedVersion{}, errors.New("version and subscription ids are required")
	}
	imported, err := Import(input.Payload)
	if err != nil {
		return StagedVersion{}, err
	}
	matchers := input.Matchers
	if matchers == nil {
		matchers = DefaultMatchers()
	}
	classified, err := Classify(imported.Nodes, matchers, input.Overrides)
	if err != nil {
		return StagedVersion{}, err
	}
	digest := sha256.Sum256(input.Payload)
	contentSHA := hex.EncodeToString(digest[:])
	now := repository.now().UTC().Format(time.RFC3339Nano)

	transaction, err := repository.database.BeginTx(ctx, nil)
	if err != nil {
		return StagedVersion{}, fmt.Errorf("begin subscription version stage: %w", err)
	}
	defer transaction.Rollback()
	var subscriptionExists int
	if err := transaction.QueryRowContext(ctx, "SELECT COUNT(*) FROM subscriptions WHERE id=?", input.SubscriptionID).Scan(&subscriptionExists); err != nil {
		return StagedVersion{}, fmt.Errorf("find subscription for version: %w", err)
	}
	if subscriptionExists != 1 {
		return StagedVersion{}, store.ErrNotFound
	}
	_, err = transaction.ExecContext(ctx, `
INSERT INTO subscription_versions (
    id, subscription_id, content_sha256, nodes_total, state, created_at
) VALUES (?, ?, ?, ?, ?, ?)`, input.VersionID, input.SubscriptionID, contentSHA, len(classified), VersionCandidate, now)
	if err != nil {
		return StagedVersion{}, fmt.Errorf("insert subscription version: %w", err)
	}
	stored := make([]StoredNode, 0, len(classified))
	for _, item := range classified {
		override := input.Overrides[item.Node.Fingerprint]
		if override == "" {
			override = OverrideAuto
		}
		node := StoredNode{
			ID:                stableNodeID(input.VersionID, item.Node.Fingerprint),
			VersionID:         input.VersionID,
			ExternalName:      item.Node.ExternalName,
			NormalizedName:    item.Node.NormalizedName,
			Fingerprint:       item.Node.Fingerprint,
			ProxyType:         item.Node.ProxyType,
			Enabled:           item.Candidate,
			SelectionOverride: override,
			CandidateSource:   item.CandidateSource,
		}
		_, err := transaction.ExecContext(ctx, `
INSERT INTO nodes (
    id, version_id, external_name, normalized_name, fingerprint, proxy_type,
    enabled, selection_override, candidate_source, matched_matcher_id
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, node.ID, node.VersionID, node.ExternalName, node.NormalizedName, node.Fingerprint, node.ProxyType, boolToInt(node.Enabled), node.SelectionOverride, node.CandidateSource, nullIfEmpty(item.MatchedMatcher))
		if err != nil {
			return StagedVersion{}, fmt.Errorf("insert subscription node %q: %w", node.ExternalName, err)
		}
		stored = append(stored, node)
	}
	if err := transaction.Commit(); err != nil {
		return StagedVersion{}, fmt.Errorf("commit subscription version stage: %w", err)
	}
	return StagedVersion{
		Version: Version{ID: input.VersionID, SubscriptionID: input.SubscriptionID, ContentSHA256: contentSHA, NodesTotal: int64(len(stored)), State: VersionCandidate, CreatedAt: now},
		Format:  imported.Format,
		Nodes:   stored,
		Import:  imported,
	}, nil
}

func (repository *VersionRepository) Activate(ctx context.Context, versionID string) error {
	transaction, err := repository.database.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin subscription version activation: %w", err)
	}
	defer transaction.Rollback()
	var subscriptionID, state string
	if err := transaction.QueryRowContext(ctx, "SELECT subscription_id, state FROM subscription_versions WHERE id=?", versionID).Scan(&subscriptionID, &state); errors.Is(err, sql.ErrNoRows) {
		return store.ErrNotFound
	} else if err != nil {
		return fmt.Errorf("read candidate subscription version: %w", err)
	}
	if state != VersionCandidate {
		return fmt.Errorf("subscription version %s is %s, not %s", versionID, state, VersionCandidate)
	}
	now := repository.now().UTC().Format(time.RFC3339Nano)
	if _, err := transaction.ExecContext(ctx, "UPDATE subscription_versions SET state=? WHERE subscription_id=? AND state=?", VersionRetained, subscriptionID, VersionLKG); err != nil {
		return fmt.Errorf("retain previous LKG subscription version: %w", err)
	}
	if _, err := transaction.ExecContext(ctx, "UPDATE subscription_versions SET state=?, activated_at=? WHERE id=?", VersionLKG, now, versionID); err != nil {
		return fmt.Errorf("activate subscription version: %w", err)
	}
	if _, err := transaction.ExecContext(ctx, `
INSERT INTO subscription_node_preferences (
    subscription_id, fingerprint, selection_override, last_seen_version_id,
    created_at, updated_at
)
SELECT ?, fingerprint, selection_override, ?, ?, ?
FROM nodes WHERE version_id=?
ON CONFLICT(subscription_id, fingerprint) DO NOTHING`, subscriptionID, versionID, now, now, versionID); err != nil {
		return fmt.Errorf("insert new subscription node preferences: %w", err)
	}
	if _, err := transaction.ExecContext(ctx, `
UPDATE subscription_node_preferences
SET missing_since=COALESCE(missing_since, ?), updated_at=?
WHERE subscription_id=?
  AND NOT EXISTS (
      SELECT 1 FROM nodes
      WHERE nodes.version_id=?
        AND nodes.fingerprint=subscription_node_preferences.fingerprint
  )`, now, now, subscriptionID, versionID); err != nil {
		return fmt.Errorf("mark missing subscription node preferences: %w", err)
	}
	if _, err := transaction.ExecContext(ctx, `
UPDATE subscription_node_preferences
SET last_seen_version_id=?, missing_since=NULL, updated_at=?
WHERE subscription_id=?
  AND EXISTS (
      SELECT 1 FROM nodes
      WHERE nodes.version_id=?
        AND nodes.fingerprint=subscription_node_preferences.fingerprint
  )`, versionID, now, subscriptionID, versionID); err != nil {
		return fmt.Errorf("refresh present subscription node preferences: %w", err)
	}
	if _, err := transaction.ExecContext(ctx, `
UPDATE subscriptions
SET active_version_id=?, status='HEALTHY', last_refresh_at=?, last_success_at=?, updated_at=?
WHERE id=?`, versionID, now, now, now, subscriptionID); err != nil {
		return fmt.Errorf("point subscription to active version: %w", err)
	}
	if err := transaction.Commit(); err != nil {
		return fmt.Errorf("commit subscription version activation: %w", err)
	}
	return nil
}

func (repository *VersionRepository) MarkFailed(ctx context.Context, versionID string, failure error) error {
	message := "unknown failure"
	if failure != nil {
		message = strings.TrimSpace(failure.Error())
	}
	if len(message) > 2048 {
		message = message[:2048]
	}
	result, err := repository.database.ExecContext(ctx, "UPDATE subscription_versions SET state=?, error=? WHERE id=? AND state=?", VersionFailed, message, versionID, VersionCandidate)
	if err != nil {
		return fmt.Errorf("mark subscription version failed: %w", err)
	}
	count, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("read failed version update count: %w", err)
	}
	if count != 1 {
		return store.ErrNotFound
	}
	return nil
}

func (repository *VersionRepository) Get(ctx context.Context, versionID string) (Version, error) {
	var item Version
	var failure, activated sql.NullString
	err := repository.database.QueryRowContext(ctx, `
SELECT id, subscription_id, content_sha256, nodes_total, state, error, created_at, activated_at
FROM subscription_versions WHERE id=?`, versionID).Scan(&item.ID, &item.SubscriptionID, &item.ContentSHA256, &item.NodesTotal, &item.State, &failure, &item.CreatedAt, &activated)
	if errors.Is(err, sql.ErrNoRows) {
		return Version{}, store.ErrNotFound
	}
	if err != nil {
		return Version{}, fmt.Errorf("get subscription version: %w", err)
	}
	item.Error = failure.String
	item.ActivatedAt = activated.String
	return item, nil
}

func (repository *VersionRepository) Active(ctx context.Context, subscriptionID string) (Version, error) {
	var item Version
	var failure, activated sql.NullString
	err := repository.database.QueryRowContext(ctx, `
SELECT v.id, v.subscription_id, v.content_sha256, v.nodes_total, v.state,
       v.error, v.created_at, v.activated_at
FROM subscriptions AS s
JOIN subscription_versions AS v ON v.id=s.active_version_id
WHERE s.id=?`, subscriptionID).Scan(&item.ID, &item.SubscriptionID, &item.ContentSHA256, &item.NodesTotal, &item.State, &failure, &item.CreatedAt, &activated)
	if errors.Is(err, sql.ErrNoRows) {
		return Version{}, store.ErrNotFound
	}
	if err != nil {
		return Version{}, fmt.Errorf("get active subscription version: %w", err)
	}
	item.Error = failure.String
	item.ActivatedAt = activated.String
	return item, nil
}

func (repository *VersionRepository) ListNodes(ctx context.Context, versionID string, candidatesOnly bool) ([]StoredNode, error) {
	query := `
SELECT id, version_id, external_name, normalized_name, fingerprint, proxy_type,
       enabled, selection_override, candidate_source, matched_matcher_id
FROM nodes WHERE version_id=?`
	if candidatesOnly {
		query += " AND enabled=1"
	}
	query += " ORDER BY normalized_name, id"
	rows, err := repository.database.QueryContext(ctx, query, versionID)
	if err != nil {
		return nil, fmt.Errorf("list subscription version nodes: %w", err)
	}
	defer rows.Close()
	var result []StoredNode
	for rows.Next() {
		var item StoredNode
		var enabled int
		var matchedMatcher sql.NullString
		if err := rows.Scan(&item.ID, &item.VersionID, &item.ExternalName, &item.NormalizedName, &item.Fingerprint, &item.ProxyType, &enabled, &item.SelectionOverride, &item.CandidateSource, &matchedMatcher); err != nil {
			return nil, fmt.Errorf("scan subscription version node: %w", err)
		}
		item.Enabled = enabled != 0
		item.MatchedMatcherID = matchedMatcher.String
		result = append(result, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate subscription version nodes: %w", err)
	}
	return result, nil
}

// ActiveOverrides transfers durable node choices to a new immutable version
// by stable fingerprint. Preferences survive temporary disappearance from the
// active version, so a returning server does not silently lose an explicit
// include/exclude decision.
func (repository *VersionRepository) ActiveOverrides(ctx context.Context, subscriptionID string) (map[string]string, error) {
	rows, err := repository.database.QueryContext(ctx, `
SELECT fingerprint, selection_override
FROM subscription_node_preferences
WHERE subscription_id=?`, subscriptionID)
	if err != nil {
		return nil, fmt.Errorf("list active subscription node overrides: %w", err)
	}
	defer rows.Close()
	result := make(map[string]string)
	for rows.Next() {
		var fingerprint, override string
		if err := rows.Scan(&fingerprint, &override); err != nil {
			return nil, fmt.Errorf("scan active subscription node override: %w", err)
		}
		if override != OverrideAuto && override != OverrideInclude && override != OverrideExclude {
			return nil, errors.New("stored subscription node override is invalid")
		}
		result[fingerprint] = override
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate active subscription node overrides: %w", err)
	}
	return result, nil
}

// AbortActivation compensates an uncertain SQLite activation after the
// external runtime has been successfully rolled back. It handles both a
// candidate transaction that never committed and one whose COMMIT reached
// disk before database/sql reported an error.
func (repository *VersionRepository) AbortActivation(ctx context.Context, versionID string, failure error) error {
	message := "LKG_ACTIVATE_FAILED"
	if failure != nil && strings.TrimSpace(failure.Error()) != "" {
		message = strings.TrimSpace(failure.Error())
	}
	if len(message) > 2048 {
		message = message[:2048]
	}
	transaction, err := repository.database.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin subscription activation compensation: %w", err)
	}
	defer transaction.Rollback()
	var subscriptionID, currentState string
	err = transaction.QueryRowContext(ctx, "SELECT subscription_id, state FROM subscription_versions WHERE id=?", versionID).Scan(&subscriptionID, &currentState)
	if errors.Is(err, sql.ErrNoRows) {
		return store.ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("read subscription version for compensation: %w", err)
	}
	if currentState == VersionFailed {
		return nil
	}
	if currentState != VersionCandidate && currentState != VersionLKG {
		return fmt.Errorf("subscription version %s cannot be aborted from state %s", versionID, currentState)
	}
	if _, err := transaction.ExecContext(ctx, "UPDATE subscription_versions SET state=?, error=? WHERE id=?", VersionFailed, message, versionID); err != nil {
		return fmt.Errorf("mark aborted subscription version failed: %w", err)
	}
	if currentState == VersionLKG {
		var previousID string
		var previousActivated sql.NullString
		err := transaction.QueryRowContext(ctx, `
SELECT id, activated_at
FROM subscription_versions
WHERE subscription_id=? AND state=? AND id<>? AND activated_at IS NOT NULL
ORDER BY activated_at DESC, created_at DESC
LIMIT 1`, subscriptionID, VersionRetained, versionID).Scan(&previousID, &previousActivated)
		now := repository.now().UTC().Format(time.RFC3339Nano)
		switch {
		case errors.Is(err, sql.ErrNoRows):
			if _, err := transaction.ExecContext(ctx, "UPDATE subscriptions SET active_version_id=NULL, status='UNKNOWN', last_success_at=NULL, updated_at=? WHERE id=?", now, subscriptionID); err != nil {
				return fmt.Errorf("clear aborted first subscription LKG: %w", err)
			}
		case err != nil:
			return fmt.Errorf("find previous subscription LKG: %w", err)
		default:
			if _, err := transaction.ExecContext(ctx, "UPDATE subscription_versions SET state=? WHERE id=?", VersionLKG, previousID); err != nil {
				return fmt.Errorf("restore previous subscription LKG state: %w", err)
			}
			if _, err := transaction.ExecContext(ctx, "UPDATE subscriptions SET active_version_id=?, status='HEALTHY', last_success_at=?, updated_at=? WHERE id=?", previousID, previousActivated, now, subscriptionID); err != nil {
				return fmt.Errorf("restore previous subscription LKG pointer: %w", err)
			}
		}
	}
	if err := transaction.Commit(); err != nil {
		return fmt.Errorf("commit subscription activation compensation: %w", err)
	}
	return nil
}

func stableNodeID(versionID, fingerprint string) string {
	digest := sha256.Sum256([]byte(versionID + "\x00" + fingerprint))
	return "node:" + hex.EncodeToString(digest[:16])
}

func boolToInt(value bool) int {
	if value {
		return 1
	}
	return 0
}
