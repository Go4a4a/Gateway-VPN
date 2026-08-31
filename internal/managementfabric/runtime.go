package managementfabric

import (
	"context"
	"errors"
	"time"
)

const RuntimeHandshakeFreshness = 3 * time.Minute

const (
	RuntimeLinkConnecting = "CONNECTING"
	RuntimeLinkReachable  = "REACHABLE"
	RuntimeLinkDegraded   = "DEGRADED"
	RuntimeLinkStale      = "STALE"
)

var runtimeObservationErrorCodes = map[string]struct{}{
	"":                              {},
	"NEVER_CONNECTED":               {},
	"HANDSHAKE_STALE":               {},
	"HANDSHAKE_READ_FAILED":         {},
	"HANDSHAKE_OUTPUT_INVALID":      {},
	"HANDSHAKE_TIME_INVALID":        {},
	"HANDSHAKE_OBSERVATION_EXPIRED": {},
}

// LinkRuntimeObservation is the deliberately small, secret-free projection
// returned by the privileged broker. Public keys, endpoints and command output
// never cross the privilege boundary.
type LinkRuntimeObservation struct {
	LinkID          string `json:"link_id"`
	State           string `json:"state"`
	LastHandshakeAt string `json:"last_handshake_at,omitempty"`
	ErrorCode       string `json:"error_code,omitempty"`
}

// RecordLinkRuntimeObservations atomically accepts one complete observation
// for the currently applied fabric generation. A concurrent WebUI mutation or
// a partial root response is rejected without changing any link.
func (repository *Repository) RecordLinkRuntimeObservations(ctx context.Context, generation int64, observations []LinkRuntimeObservation, now time.Time) error {
	if repository == nil || repository.Database == nil || generation <= 0 || now.IsZero() || len(observations) > MaximumLinks {
		return errors.New("valid management runtime observation is required")
	}
	now = now.UTC()
	seen := make(map[string]struct{}, len(observations))
	for _, observation := range observations {
		if err := validateLinkRuntimeObservation(observation, now); err != nil {
			return err
		}
		if _, exists := seen[observation.LinkID]; exists {
			return errors.New("management runtime observation contains duplicate links")
		}
		seen[observation.LinkID] = struct{}{}
	}

	tx, err := repository.Database.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var desired, applied int64
	if err := tx.QueryRowContext(ctx, `SELECT desired_generation,applied_generation FROM management_fabric_generations WHERE singleton_id=1`).Scan(&desired, &applied); err != nil || desired != generation || applied != generation {
		return errors.New("management runtime observation generation is stale")
	}
	var expected int
	if err := tx.QueryRowContext(ctx, `
SELECT COUNT(*)
FROM management_links AS l
JOIN management_sites AS s ON s.id=l.site_id
JOIN vps_nodes AS v ON v.id=l.vps_id
WHERE l.enabled=1 AND l.state NOT IN ('DISABLED','REVOKED')
  AND s.is_local=1 AND s.identity_state='ACTIVE'
  AND v.enabled=1 AND v.state!='REVOKED'
  AND l.desired_route_generation=l.applied_route_generation
  AND l.desired_acl_generation=l.applied_acl_generation`).Scan(&expected); err != nil {
		return err
	}
	if expected != len(observations) {
		return errors.New("management runtime observation is incomplete")
	}
	stamp := now.Format(time.RFC3339Nano)
	for _, observation := range observations {
		authoritativeHandshake := observation.State != RuntimeLinkDegraded
		result, err := tx.ExecContext(ctx, `
UPDATE management_links
SET state=?,last_error_code=?,
    last_handshake_at=CASE WHEN ?=1 THEN NULLIF(?, '') ELSE last_handshake_at END,
    updated_at=?
WHERE id=? AND enabled=1 AND state NOT IN ('DISABLED','REVOKED')
  AND desired_route_generation=applied_route_generation
  AND desired_acl_generation=applied_acl_generation
  AND site_id IN (SELECT id FROM management_sites WHERE is_local=1 AND identity_state='ACTIVE')
  AND vps_id IN (SELECT id FROM vps_nodes WHERE enabled=1 AND state!='REVOKED')`,
			observation.State, observation.ErrorCode, authoritativeHandshake, observation.LastHandshakeAt,
			stamp, observation.LinkID)
		if err != nil {
			return err
		}
		if changed, _ := result.RowsAffected(); changed != 1 {
			return errors.New("management runtime link changed during observation")
		}
	}
	return tx.Commit()
}

// ExpireLinkRuntimeObservations prevents an old REACHABLE row from remaining
// authoritative when the root observer or broker becomes unavailable.
func (repository *Repository) ExpireLinkRuntimeObservations(ctx context.Context, now time.Time) (int64, error) {
	if repository == nil || repository.Database == nil || now.IsZero() {
		return 0, errors.New("management runtime repository and time are required")
	}
	now = now.UTC()
	result, err := repository.Database.ExecContext(ctx, `
UPDATE management_links
SET state='STALE',last_error_code='HANDSHAKE_OBSERVATION_EXPIRED',updated_at=?
WHERE enabled=1 AND state='REACHABLE'
  AND (last_handshake_at IS NULL OR julianday(last_handshake_at)<julianday(?))`,
		now.Format(time.RFC3339Nano), now.Add(-RuntimeHandshakeFreshness).Format(time.RFC3339Nano))
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

func validateLinkRuntimeObservation(observation LinkRuntimeObservation, now time.Time) error {
	if !safeIdentifier.MatchString(observation.LinkID) {
		return errors.New("management runtime observation link id is invalid")
	}
	if _, valid := runtimeObservationErrorCodes[observation.ErrorCode]; !valid {
		return errors.New("management runtime observation error code is invalid")
	}
	var handshake time.Time
	if observation.LastHandshakeAt != "" {
		parsed, err := time.Parse(time.RFC3339Nano, observation.LastHandshakeAt)
		if err != nil || parsed.Location() != time.UTC || parsed.After(now.Add(30*time.Second)) {
			return errors.New("management runtime handshake time is invalid")
		}
		handshake = parsed
	}
	switch observation.State {
	case RuntimeLinkReachable:
		if handshake.IsZero() || now.Sub(handshake) > RuntimeHandshakeFreshness || observation.ErrorCode != "" {
			return errors.New("reachable management runtime observation is inconsistent")
		}
	case RuntimeLinkStale:
		if handshake.IsZero() || now.Sub(handshake) <= RuntimeHandshakeFreshness || observation.ErrorCode != "HANDSHAKE_STALE" {
			return errors.New("stale management runtime observation is inconsistent")
		}
	case RuntimeLinkConnecting:
		if !handshake.IsZero() || observation.ErrorCode != "NEVER_CONNECTED" {
			return errors.New("connecting management runtime observation is inconsistent")
		}
	case RuntimeLinkDegraded:
		if observation.ErrorCode != "HANDSHAKE_READ_FAILED" && observation.ErrorCode != "HANDSHAKE_OUTPUT_INVALID" && observation.ErrorCode != "HANDSHAKE_TIME_INVALID" {
			return errors.New("degraded management runtime observation is inconsistent")
		}
	default:
		return errors.New("management runtime observation state is invalid")
	}
	return nil
}
