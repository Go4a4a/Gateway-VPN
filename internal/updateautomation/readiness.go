package updateautomation

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"gateway-vpn/internal/managementfabric"
	"gateway-vpn/internal/wireguard"
)

const (
	ReadinessFullPathUnavailable          = "AUTO_FULL_PATH_UNAVAILABLE"
	ReadinessManagementChannelUnavailable = "AUTO_MANAGEMENT_CHANNEL_UNAVAILABLE"
)

// ApplyReadiness proves the two external safety prerequisites required before
// unattended mutation. It returns only a fixed reason code; backend detail is
// never persisted in scheduler state or exposed to the Web API.
type ApplyReadiness interface {
	Check(context.Context, time.Time) (string, error)
}

type SQLiteApplyReadiness struct {
	Database *sql.DB
}

func (readiness SQLiteApplyReadiness) Check(ctx context.Context, now time.Time) (string, error) {
	if readiness.Database == nil || now.IsZero() {
		return "", errors.New("automatic update readiness database and time are required")
	}
	now = now.UTC()
	full, err := readiness.freshFullPath(ctx, now)
	if err != nil {
		return "", err
	}
	if !full {
		return ReadinessFullPathUnavailable, nil
	}
	management, err := readiness.freshManagementChannel(ctx, now)
	if err != nil {
		return "", err
	}
	if !management {
		return ReadinessManagementChannelUnavailable, nil
	}
	return "", nil
}

func (readiness SQLiteApplyReadiness) freshFullPath(ctx context.Context, now time.Time) (bool, error) {
	var count int
	stamp := now.Format(time.RFC3339Nano)
	err := readiness.Database.QueryRowContext(ctx, `
SELECT COUNT(*) FROM (
    SELECT 1
    FROM runtime_state AS r
    JOIN direct_uplink_paths AS p ON p.id=r.active_direct_path_id
    JOIN uplinks AS u ON u.id=p.uplink_id AND u.id=r.active_uplink_id
    JOIN access_methods AS a ON a.id=r.active_method_id AND a.kind='DIRECT'
    WHERE r.singleton_id=1 AND r.path_state='PATH_ACTIVE'
      AND r.active_method_kind='DIRECT' AND r.active_quality_class='FULL'
      AND p.state='QUALIFIED' AND p.transport_state='PASSED' AND p.quality_class='FULL'
      AND p.required_targets_total>0 AND p.required_targets_passed=p.required_targets_total
      AND julianday(p.expires_at)>julianday(?)
      AND p.policy_generation=COALESCE(CAST((SELECT value_json FROM settings WHERE key='next_policy_generation') AS INTEGER)-1,0)
      AND p.route_generation=u.route_generation
      AND a.enabled=1 AND u.enabled=1 AND u.state='UPLINK_READY'
    UNION ALL
    SELECT 1
    FROM runtime_state AS r
    JOIN subscription_uplink_paths AS p ON p.id=r.active_path_id
    JOIN uplinks AS u ON u.id=p.uplink_id AND u.id=r.active_uplink_id
    JOIN subscriptions AS s ON s.id=p.subscription_id AND s.id=r.active_subscription_id
    JOIN subscription_versions AS v ON v.id=s.active_version_id AND v.state='LKG'
    JOIN nodes AS n ON n.id=r.active_node_id AND n.id=p.selected_node_id AND n.version_id=v.id
    JOIN uplink_path_nodes AS pn ON pn.path_id=p.id AND pn.node_id=n.id
    JOIN access_methods AS a ON a.id=r.active_method_id AND a.kind='SUBSCRIPTION' AND a.subscription_id=s.id
    WHERE r.singleton_id=1 AND r.path_state='PATH_ACTIVE'
      AND r.active_method_kind='SUBSCRIPTION' AND r.active_quality_class='FULL'
      AND p.state='QUALIFIED' AND p.transport_state='PASSED' AND p.quality_class='FULL'
      AND p.required_targets_total>0 AND p.required_targets_passed=p.required_targets_total
      AND julianday(p.expires_at)>julianday(?)
      AND pn.qualification_state='BYPASS_QUALIFIED'
      AND pn.qualification_generation=p.policy_generation
      AND pn.route_generation=p.route_generation
      AND julianday(pn.qualification_expires_at)>julianday(?)
      AND p.policy_generation=COALESCE(CAST((SELECT value_json FROM settings WHERE key='next_policy_generation') AS INTEGER)-1,0)
      AND p.route_generation=u.route_generation
      AND a.enabled=1 AND s.enabled=1 AND u.enabled=1 AND u.state='UPLINK_READY'
      AND n.enabled=1 AND n.selection_override<>'exclude'
)`, stamp, stamp, stamp).Scan(&count)
	return count > 0, err
}

func (readiness SQLiteApplyReadiness) freshManagementChannel(ctx context.Context, now time.Time) (bool, error) {
	cutoff := now.Add(-managementfabric.RuntimeHandshakeFreshness).Format(time.RFC3339Nano)
	var count int
	if err := readiness.Database.QueryRowContext(ctx, `
SELECT COUNT(*) FROM management_links
WHERE enabled=1 AND state='REACHABLE'
  AND desired_route_generation=applied_route_generation
  AND desired_acl_generation=applied_acl_generation
  AND last_handshake_at IS NOT NULL
  AND julianday(last_handshake_at)>=julianday(?)`, cutoff).Scan(&count); err != nil {
		return false, err
	}
	if count > 0 {
		return true, nil
	}
	legacy, err := (wireguard.RuntimeStore{Database: readiness.Database}).Get(ctx)
	if err != nil {
		return false, err
	}
	handshake, err := time.Parse(time.RFC3339Nano, legacy.LastHandshakeAt)
	return err == nil && !handshake.Before(now.Add(-managementfabric.RuntimeHandshakeFreshness)), nil
}
