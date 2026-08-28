package modemrecovery

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"gateway-vpn/internal/store"
)

type Repository struct {
	Database *sql.DB
	Now      func() time.Time
}

func NewRepository(database *sql.DB) *Repository {
	return &Repository{Database: database, Now: time.Now}
}

func (repository *Repository) Snapshot(ctx context.Context, uplinkID string, limit int) (Snapshot, error) {
	if repository == nil || repository.Database == nil || !validID(uplinkID) {
		return Snapshot{}, errors.New("valid modem recovery repository and uplink id are required")
	}
	if limit <= 0 {
		limit = 20
	}
	if limit > 100 {
		limit = 100
	}
	policy, err := repository.readPolicy(ctx, repository.Database, uplinkID)
	if err != nil {
		return Snapshot{}, err
	}
	runtimeState, err := repository.readRuntime(ctx, repository.Database, uplinkID)
	if err != nil {
		return Snapshot{}, err
	}
	rows, err := repository.Database.QueryContext(ctx, `
SELECT id, uplink_id, policy_generation, action, requested_by, status,
	       reason_code, started_at, COALESCE(finished_at, ''), details_json
FROM modem_recovery_attempts
WHERE uplink_id=?
ORDER BY started_at DESC, id DESC
LIMIT ?`, uplinkID, limit)
	if err != nil {
		return Snapshot{}, fmt.Errorf("read modem recovery attempts: %w", err)
	}
	defer rows.Close()
	result := Snapshot{Policy: policy, Runtime: runtimeState}
	for rows.Next() {
		var item Attempt
		var details string
		if err := rows.Scan(&item.ID, &item.UplinkID, &item.PolicyGeneration, &item.Action, &item.RequestedBy, &item.Status, &item.ReasonCode, &item.StartedAt, &item.FinishedAt, &details); err != nil {
			return Snapshot{}, fmt.Errorf("scan modem recovery attempt: %w", err)
		}
		var decoded struct {
			FailureReason string `json:"failure_reason"`
		}
		if err := json.Unmarshal([]byte(details), &decoded); err != nil {
			return Snapshot{}, errors.New("stored modem recovery attempt details are invalid")
		}
		if validFailure(decoded.FailureReason) {
			item.FailureReason = decoded.FailureReason
		}
		result.Attempts = append(result.Attempts, item)
	}
	if err := rows.Err(); err != nil {
		return Snapshot{}, fmt.Errorf("iterate modem recovery attempts: %w", err)
	}
	return result, nil
}

func (repository *Repository) UpdatePolicy(ctx context.Context, uplinkID string, input PolicyUpdate) (Policy, error) {
	if repository == nil || repository.Database == nil || !validID(uplinkID) {
		return Policy{}, errors.New("valid modem recovery repository and uplink id are required")
	}
	if err := validatePolicyUpdate(input); err != nil {
		return Policy{}, err
	}
	transaction, err := repository.Database.BeginTx(ctx, nil)
	if err != nil {
		return Policy{}, fmt.Errorf("begin modem recovery policy update: %w", err)
	}
	defer transaction.Rollback()
	var activeAttempt string
	if err := transaction.QueryRowContext(ctx, `
SELECT COALESCE(r.active_attempt_id, '')
FROM modem_recovery_runtime AS r
JOIN hilink_modems AS h ON h.uplink_id=r.uplink_id
WHERE r.uplink_id=?`, uplinkID).Scan(&activeAttempt); errors.Is(err, sql.ErrNoRows) {
		return Policy{}, store.ErrNotFound
	} else if err != nil {
		return Policy{}, fmt.Errorf("read modem recovery policy state: %w", err)
	}
	if activeAttempt != "" {
		return Policy{}, errors.New("modem recovery policy cannot change during an active attempt")
	}
	now := repository.now().Format(time.RFC3339Nano)
	result, err := transaction.ExecContext(ctx, `
UPDATE modem_recovery_policy
SET enabled=?, dhcp_retry_after_seconds=?, api_retry_after_seconds=?,
    mobile_session_restart_after_seconds=?, usb_rebind_after_seconds=?,
    usb_reset_after_seconds=?, usb_reset_cooldown_seconds=?,
    max_usb_resets_per_window=?, usb_reset_window_seconds=?,
    allow_hub_port_power_cycle=?, policy_generation=policy_generation+1,
    updated_at=?
WHERE uplink_id=?`, boolInt(input.Enabled), input.DHCPRetryAfterSeconds, input.APIRetryAfterSeconds,
		input.MobileSessionRestartAfterSeconds, input.USBRebindAfterSeconds,
		input.USBResetAfterSeconds, input.USBResetCooldownSeconds,
		input.MaxUSBResetsPerWindow, input.USBResetWindowSeconds,
		boolInt(input.AllowHubPortPowerCycle), now, uplinkID)
	if err != nil {
		return Policy{}, fmt.Errorf("update modem recovery policy: %w", err)
	}
	if count, countErr := result.RowsAffected(); countErr != nil || count != 1 {
		return Policy{}, store.ErrNotFound
	}
	if _, err := transaction.ExecContext(ctx, `
UPDATE modem_recovery_runtime
SET policy_generation=(SELECT policy_generation FROM modem_recovery_policy WHERE uplink_id=?),
	    state='IDLE', failure_started_at=NULL,
	    active_attempt_id=NULL, last_outcome_code='POLICY_UPDATED', updated_at=?
WHERE uplink_id=?`, uplinkID, now, uplinkID); err != nil {
		return Policy{}, fmt.Errorf("reset modem recovery runtime after policy update: %w", err)
	}
	if err := appendRecoveryEvent(ctx, transaction, now, "INFO", "MODEM_RECOVERY_POLICY_UPDATED", uplinkID, map[string]any{"policy_generation_changed": true, "enabled": input.Enabled}); err != nil {
		return Policy{}, err
	}
	if err := transaction.Commit(); err != nil {
		return Policy{}, fmt.Errorf("commit modem recovery policy update: %w", err)
	}
	return repository.readPolicy(ctx, repository.Database, uplinkID)
}

// RecoverInterrupted closes attempts left RUNNING by a process crash. It does
// not reset the durable USB budget and therefore cannot manufacture retries.
func (repository *Repository) RecoverInterrupted(ctx context.Context) (int64, error) {
	if repository == nil || repository.Database == nil {
		return 0, errors.New("modem recovery database is required")
	}
	transaction, err := repository.Database.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("begin interrupted modem recovery cleanup: %w", err)
	}
	defer transaction.Rollback()
	now := repository.now().Format(time.RFC3339Nano)
	rows, err := transaction.QueryContext(ctx, `
SELECT id, uplink_id, policy_generation, action, requested_by, reason_code, started_at, details_json
FROM modem_recovery_attempts WHERE status='RUNNING'`)
	if err != nil {
		return 0, fmt.Errorf("read interrupted modem recovery attempts: %w", err)
	}
	var interrupted []Attempt
	for rows.Next() {
		var item Attempt
		var details string
		if err := rows.Scan(&item.ID, &item.UplinkID, &item.PolicyGeneration, &item.Action, &item.RequestedBy, &item.ReasonCode, &item.StartedAt, &details); err != nil {
			rows.Close()
			return 0, fmt.Errorf("scan interrupted modem recovery attempt: %w", err)
		}
		var decoded struct {
			FailureReason string `json:"failure_reason"`
		}
		if json.Unmarshal([]byte(details), &decoded) == nil && validFailure(decoded.FailureReason) {
			item.FailureReason = decoded.FailureReason
		}
		interrupted = append(interrupted, item)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return 0, fmt.Errorf("iterate interrupted modem recovery attempts: %w", err)
	}
	if err := rows.Close(); err != nil {
		return 0, fmt.Errorf("close interrupted modem recovery rows: %w", err)
	}
	result, err := transaction.ExecContext(ctx, `
UPDATE modem_recovery_attempts
SET status='FAILED', reason_code='PROCESS_RESTARTED', finished_at=?
WHERE status='RUNNING'`, now)
	if err != nil {
		return 0, fmt.Errorf("close interrupted modem recovery attempts: %w", err)
	}
	count, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("count interrupted modem recovery attempts: %w", err)
	}
	if _, err := transaction.ExecContext(ctx, `
UPDATE modem_recovery_runtime
SET state='IDLE', active_attempt_id=NULL,
    last_outcome_code=CASE WHEN active_attempt_id IS NULL THEN last_outcome_code ELSE 'PROCESS_RESTARTED' END,
    updated_at=?
WHERE active_attempt_id IS NOT NULL`, now); err != nil {
		return 0, fmt.Errorf("clear interrupted modem recovery runtime: %w", err)
	}
	for _, attempt := range interrupted {
		if err := appendRecoveryEvent(ctx, transaction, now, "WARN", "MODEM_RECOVERY_ATTEMPT_FINISHED", attempt.UplinkID, map[string]any{
			"attempt_id": attempt.ID, "action": attempt.Action, "status": AttemptFailed,
			"outcome_code": "PROCESS_RESTARTED", "failure_reason": attempt.FailureReason,
			"policy_generation": attempt.PolicyGeneration,
		}); err != nil {
			return 0, err
		}
	}
	if err := transaction.Commit(); err != nil {
		return 0, fmt.Errorf("commit interrupted modem recovery cleanup: %w", err)
	}
	return count, nil
}

func (repository *Repository) ObserveHealthy(ctx context.Context, uplinkID string) error {
	if repository == nil || repository.Database == nil || !validID(uplinkID) {
		return errors.New("valid modem recovery repository and uplink id are required")
	}
	now := repository.now().Format(time.RFC3339Nano)
	result, err := repository.Database.ExecContext(ctx, `
UPDATE modem_recovery_runtime
SET state='IDLE', failure_started_at=NULL, cooldown_until=NULL,
    active_attempt_id=NULL, last_outcome_code='PHYSICAL_LINK_HEALTHY', updated_at=?
WHERE uplink_id=? AND active_attempt_id IS NULL`, now, uplinkID)
	if err != nil {
		return fmt.Errorf("record healthy physical modem: %w", err)
	}
	if count, countErr := result.RowsAffected(); countErr != nil || count != 1 {
		return store.ErrNotFound
	}
	return nil
}

// PrepareFailure starts or continues one physical-failure episode. The reason
// is encoded in the bounded runtime state because the deployed schema has no
// free-form failure field.
func (repository *Repository) PrepareFailure(ctx context.Context, uplinkID, reason string) (Snapshot, error) {
	if !validFailure(reason) || !validID(uplinkID) {
		return Snapshot{}, errors.New("valid physical modem failure and uplink id are required")
	}
	transaction, err := repository.Database.BeginTx(ctx, nil)
	if err != nil {
		return Snapshot{}, fmt.Errorf("begin physical modem failure observation: %w", err)
	}
	defer transaction.Rollback()
	policy, err := repository.readPolicy(ctx, transaction, uplinkID)
	if err != nil {
		return Snapshot{}, err
	}
	runtimeState, err := repository.readRuntime(ctx, transaction, uplinkID)
	if err != nil {
		return Snapshot{}, err
	}
	if runtimeState.ActiveAttemptID != "" {
		return Snapshot{Policy: policy, Runtime: runtimeState}, nil
	}
	now := repository.now().Format(time.RFC3339Nano)
	state := failureState(reason)
	failureStartedAt := runtimeState.FailureStartedAt
	if runtimeState.FailureReason != reason || failureStartedAt == "" {
		failureStartedAt = now
	}
	if _, err := transaction.ExecContext(ctx, `
UPDATE modem_recovery_runtime
SET policy_generation=?, state=?, failure_started_at=?, updated_at=?
WHERE uplink_id=? AND active_attempt_id IS NULL`, policy.Generation, state, failureStartedAt, now, uplinkID); err != nil {
		return Snapshot{}, fmt.Errorf("record physical modem failure: %w", err)
	}
	if err := transaction.Commit(); err != nil {
		return Snapshot{}, fmt.Errorf("commit physical modem failure observation: %w", err)
	}
	return repository.Snapshot(ctx, uplinkID, 100)
}

func (repository *Repository) SetWaiting(ctx context.Context, uplinkID, reasonCode string, next time.Time) error {
	if !validID(uplinkID) || !validCode(reasonCode) {
		return errors.New("invalid modem recovery waiting state")
	}
	now := repository.now().Format(time.RFC3339Nano)
	cooldown := any(nil)
	if !next.IsZero() {
		cooldown = next.UTC().Format(time.RFC3339Nano)
	}
	_, err := repository.Database.ExecContext(ctx, `
UPDATE modem_recovery_runtime
SET cooldown_until=?, last_outcome_code=?, updated_at=?
WHERE uplink_id=? AND active_attempt_id IS NULL`, cooldown, reasonCode, now, uplinkID)
	if err != nil {
		return fmt.Errorf("set modem recovery waiting state: %w", err)
	}
	return nil
}

func (repository *Repository) BeginAttempt(ctx context.Context, uplinkID, action, requestedBy, reason string) (Attempt, error) {
	if !validID(uplinkID) || !validAction(action) || !validFailure(reason) || (requestedBy != RequestedBySystem && requestedBy != RequestedByUser) {
		return Attempt{}, errors.New("invalid modem recovery attempt")
	}
	transaction, err := repository.Database.BeginTx(ctx, nil)
	if err != nil {
		return Attempt{}, fmt.Errorf("begin modem recovery attempt: %w", err)
	}
	defer transaction.Rollback()
	policy, err := repository.readPolicy(ctx, transaction, uplinkID)
	if err != nil {
		return Attempt{}, err
	}
	runtimeState, err := repository.readRuntime(ctx, transaction, uplinkID)
	if err != nil {
		return Attempt{}, err
	}
	if runtimeState.ActiveAttemptID != "" {
		return Attempt{}, errors.New("another modem recovery attempt is active")
	}
	if runtimeState.PolicyGeneration != policy.Generation {
		return Attempt{}, ErrStaleGeneration
	}
	if !policy.Enabled {
		return Attempt{}, ErrActionUnsupported
	}
	nowTime := repository.now()
	if until, ok := parseTime(runtimeState.CooldownUntil); ok && nowTime.Before(until) {
		return Attempt{}, ErrBudgetExhausted
	}
	windowStart := runtimeState.BudgetWindowStartedAt
	resetCount := runtimeState.USBResetsInWindow
	if action == ActionUSBDeviceReset {
		parsedWindow, windowOK := parseTime(windowStart)
		if !windowOK || nowTime.Sub(parsedWindow) >= time.Duration(policy.USBResetWindowSeconds)*time.Second {
			windowStart = nowTime.Format(time.RFC3339Nano)
			resetCount = 0
		}
		if policy.MaxUSBResetsPerWindow == 0 || resetCount >= policy.MaxUSBResetsPerWindow {
			return Attempt{}, ErrBudgetExhausted
		}
		resetCount++
	}
	id, err := newAttemptID()
	if err != nil {
		return Attempt{}, err
	}
	now := nowTime.Format(time.RFC3339Nano)
	details, err := json.Marshal(map[string]string{"failure_reason": reason})
	if err != nil {
		return Attempt{}, errors.New("encode modem recovery attempt details failed")
	}
	if _, err := transaction.ExecContext(ctx, `
INSERT INTO modem_recovery_attempts(
    id, uplink_id, policy_generation, action, requested_by, status,
    reason_code, started_at, details_json
) VALUES (?, ?, ?, ?, ?, 'RUNNING', ?, ?, ?)`,
		id, uplinkID, policy.Generation, action, requestedBy, reason, now, string(details)); err != nil {
		return Attempt{}, fmt.Errorf("insert modem recovery attempt: %w", err)
	}
	runtimeResult, err := transaction.ExecContext(ctx, `
UPDATE modem_recovery_runtime
SET state='RUNNING', active_attempt_id=?, budget_window_started_at=?,
    usb_resets_in_window=?, updated_at=?
WHERE uplink_id=? AND policy_generation=? AND active_attempt_id IS NULL`,
		id, nullIfEmpty(windowStart), resetCount, now, uplinkID, policy.Generation)
	if err != nil {
		return Attempt{}, fmt.Errorf("activate modem recovery attempt: %w", err)
	}
	if count, countErr := runtimeResult.RowsAffected(); countErr != nil || count != 1 {
		return Attempt{}, ErrStaleGeneration
	}
	if err := appendRecoveryEvent(ctx, transaction, now, "INFO", "MODEM_RECOVERY_ATTEMPT_STARTED", uplinkID, map[string]any{
		"attempt_id": id, "action": action, "requested_by": requestedBy,
		"failure_reason": reason, "policy_generation": policy.Generation,
	}); err != nil {
		return Attempt{}, err
	}
	if err := transaction.Commit(); err != nil {
		return Attempt{}, fmt.Errorf("commit modem recovery attempt: %w", err)
	}
	return Attempt{ID: id, UplinkID: uplinkID, PolicyGeneration: policy.Generation, Action: action, RequestedBy: requestedBy, Status: AttemptRunning, ReasonCode: reason, FailureReason: reason, StartedAt: now}, nil
}

func (repository *Repository) FinishAttempt(ctx context.Context, attempt Attempt, status, reasonCode string, cooldown time.Duration) error {
	if attempt.ID == "" || !validID(attempt.UplinkID) || !validAttemptStatus(status) || status == AttemptRunning || !validCode(reasonCode) {
		return errors.New("invalid modem recovery completion")
	}
	transaction, err := repository.Database.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin modem recovery completion: %w", err)
	}
	defer transaction.Rollback()
	var activeID string
	var generation int64
	if err := transaction.QueryRowContext(ctx, `
SELECT COALESCE(active_attempt_id, ''), policy_generation
FROM modem_recovery_runtime WHERE uplink_id=?`, attempt.UplinkID).Scan(&activeID, &generation); errors.Is(err, sql.ErrNoRows) {
		return store.ErrNotFound
	} else if err != nil {
		return fmt.Errorf("read active modem recovery attempt: %w", err)
	}
	if activeID != attempt.ID || generation != attempt.PolicyGeneration {
		return ErrStaleGeneration
	}
	nowTime := repository.now()
	now := nowTime.Format(time.RFC3339Nano)
	attemptResult, err := transaction.ExecContext(ctx, `
UPDATE modem_recovery_attempts
SET status=?, reason_code=?, finished_at=?
WHERE id=? AND status='RUNNING'`, status, reasonCode, now, attempt.ID)
	if err != nil {
		return fmt.Errorf("finish modem recovery attempt: %w", err)
	}
	if count, countErr := attemptResult.RowsAffected(); countErr != nil || count != 1 {
		return ErrStaleGeneration
	}
	cooldownValue := any(nil)
	if cooldown > 0 {
		cooldownValue = nowTime.Add(cooldown).Format(time.RFC3339Nano)
	}
	runtimeResult, err := transaction.ExecContext(ctx, `
UPDATE modem_recovery_runtime
SET state=?, active_attempt_id=NULL, cooldown_until=?,
    last_outcome_code=?, updated_at=?
WHERE uplink_id=? AND active_attempt_id=?`,
		failureState(attempt.FailureReason), cooldownValue, reasonCode, now, attempt.UplinkID, attempt.ID)
	if err != nil {
		return fmt.Errorf("finish modem recovery runtime: %w", err)
	}
	if count, countErr := runtimeResult.RowsAffected(); countErr != nil || count != 1 {
		return ErrStaleGeneration
	}
	severity := "INFO"
	if status != AttemptSucceeded {
		severity = "WARN"
	}
	if err := appendRecoveryEvent(ctx, transaction, now, severity, "MODEM_RECOVERY_ATTEMPT_FINISHED", attempt.UplinkID, map[string]any{
		"attempt_id": attempt.ID, "action": attempt.Action, "status": status,
		"outcome_code": reasonCode, "failure_reason": attempt.FailureReason,
		"policy_generation": attempt.PolicyGeneration,
	}); err != nil {
		return err
	}
	if err := transaction.Commit(); err != nil {
		return fmt.Errorf("commit modem recovery completion: %w", err)
	}
	return nil
}

func (repository *Repository) RecordSuppressed(ctx context.Context, uplinkID, action, requestedBy, reason, reasonCode string, cooldown time.Duration) (Attempt, error) {
	attempt, err := repository.BeginAttempt(ctx, uplinkID, action, requestedBy, reason)
	if err != nil {
		return Attempt{}, err
	}
	if err := repository.FinishAttempt(ctx, attempt, AttemptSuppressed, reasonCode, cooldown); err != nil {
		return Attempt{}, err
	}
	attempt.Status, attempt.ReasonCode, attempt.FinishedAt = AttemptSuppressed, reasonCode, repository.now().Format(time.RFC3339Nano)
	return attempt, nil
}

type queryer interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func (repository *Repository) readPolicy(ctx context.Context, source queryer, uplinkID string) (Policy, error) {
	var item Policy
	var enabled, power int
	err := source.QueryRowContext(ctx, `
SELECT p.uplink_id, p.enabled, p.dhcp_retry_after_seconds,
       p.api_retry_after_seconds, p.mobile_session_restart_after_seconds,
       p.usb_rebind_after_seconds, p.usb_reset_after_seconds,
       p.usb_reset_cooldown_seconds, p.max_usb_resets_per_window,
       p.usb_reset_window_seconds, p.allow_hub_port_power_cycle,
       p.policy_generation, p.updated_at
FROM modem_recovery_policy AS p
JOIN hilink_modems AS h ON h.uplink_id=p.uplink_id
WHERE p.uplink_id=?`, uplinkID).Scan(
		&item.UplinkID, &enabled, &item.DHCPRetryAfterSeconds,
		&item.APIRetryAfterSeconds, &item.MobileSessionRestartAfterSeconds,
		&item.USBRebindAfterSeconds, &item.USBResetAfterSeconds,
		&item.USBResetCooldownSeconds, &item.MaxUSBResetsPerWindow,
		&item.USBResetWindowSeconds, &power, &item.Generation, &item.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return Policy{}, store.ErrNotFound
	}
	if err != nil {
		return Policy{}, fmt.Errorf("read modem recovery policy: %w", err)
	}
	item.Enabled, item.AllowHubPortPowerCycle = enabled == 1, power == 1
	return item, nil
}

func (repository *Repository) readRuntime(ctx context.Context, source queryer, uplinkID string) (Runtime, error) {
	var item Runtime
	err := source.QueryRowContext(ctx, `
SELECT uplink_id, policy_generation, state,
       COALESCE(failure_started_at, ''), COALESCE(cooldown_until, ''),
       COALESCE(budget_window_started_at, ''), usb_resets_in_window,
       COALESCE(active_attempt_id, ''), last_outcome_code, updated_at
FROM modem_recovery_runtime WHERE uplink_id=?`, uplinkID).Scan(
		&item.UplinkID, &item.PolicyGeneration, &item.State,
		&item.FailureStartedAt, &item.CooldownUntil,
		&item.BudgetWindowStartedAt, &item.USBResetsInWindow,
		&item.ActiveAttemptID, &item.LastOutcomeCode, &item.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return Runtime{}, store.ErrNotFound
	}
	if err != nil {
		return Runtime{}, fmt.Errorf("read modem recovery runtime: %w", err)
	}
	item.FailureReason = reasonFromState(item.State)
	return item, nil
}

func (repository *Repository) now() time.Time {
	if repository.Now == nil {
		return time.Now().UTC()
	}
	return repository.Now().UTC()
}

func validatePolicyUpdate(input PolicyUpdate) error {
	if input.DHCPRetryAfterSeconds < 5 || input.DHCPRetryAfterSeconds > 3600 ||
		input.APIRetryAfterSeconds < 5 || input.APIRetryAfterSeconds > 3600 ||
		input.MobileSessionRestartAfterSeconds < 10 || input.MobileSessionRestartAfterSeconds > 7200 ||
		input.USBRebindAfterSeconds < 30 || input.USBRebindAfterSeconds > 86400 ||
		input.USBResetAfterSeconds < 60 || input.USBResetAfterSeconds > 86400 ||
		input.USBResetCooldownSeconds < 60 || input.USBResetCooldownSeconds > 86400 ||
		input.MaxUSBResetsPerWindow < 0 || input.MaxUSBResetsPerWindow > 20 ||
		input.USBResetWindowSeconds < 300 || input.USBResetWindowSeconds > 86400 {
		return errors.New("modem recovery policy value is outside the supported range")
	}
	if input.DHCPRetryAfterSeconds > input.USBRebindAfterSeconds ||
		input.APIRetryAfterSeconds > input.MobileSessionRestartAfterSeconds ||
		input.MobileSessionRestartAfterSeconds > input.USBRebindAfterSeconds ||
		input.USBRebindAfterSeconds > input.USBResetAfterSeconds {
		return errors.New("modem recovery ladder delays must progress from safe retries to USB reset")
	}
	return nil
}

func newAttemptID() (string, error) {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		return "", errors.New("generate modem recovery attempt id failed")
	}
	return "modem-recovery-" + hex.EncodeToString(value), nil
}

func failureState(reason string) string { return "OBSERVING_" + reason }

func reasonFromState(state string) string {
	if !strings.HasPrefix(state, "OBSERVING_") {
		return ""
	}
	return strings.TrimPrefix(state, "OBSERVING_")
}

func validFailure(value string) bool {
	return value == FailureDeviceAbsent || value == FailureCarrierDown || value == FailureDHCPLeaseMissing || value == FailureManagementUnreachable
}

func validAction(value string) bool {
	switch value {
	case ActionDHCPRenew, ActionHiLinkAPIReconnect, ActionMobileSessionRestart, ActionUSBDriverRebind, ActionUSBDeviceReset, ActionUSBPortPowerCycle:
		return true
	default:
		return false
	}
}

func validAttemptStatus(value string) bool {
	return value == AttemptRunning || value == AttemptSucceeded || value == AttemptFailed || value == AttemptDeviceRemoved || value == AttemptSuppressed
}

func validID(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > 128 {
		return false
	}
	for _, character := range value {
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || strings.ContainsRune("_.:-", character) {
			continue
		}
		return false
	}
	return true
}

func validCode(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	for _, character := range value {
		if character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || character == '_' {
			continue
		}
		return false
	}
	return true
}

func parseTime(value string) (time.Time, bool) {
	if value == "" {
		return time.Time{}, false
	}
	parsed, err := time.Parse(time.RFC3339Nano, value)
	return parsed, err == nil
}

func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}

func nullIfEmpty(value string) any {
	if value == "" {
		return nil
	}
	return value
}

func appendRecoveryEvent(ctx context.Context, transaction *sql.Tx, now, severity, eventType, uplinkID string, details map[string]any) error {
	content, err := json.Marshal(details)
	if err != nil {
		return errors.New("encode modem recovery event failed")
	}
	if len(content) > 4096 {
		return errors.New("modem recovery event is oversized")
	}
	if _, err := transaction.ExecContext(ctx, `
INSERT INTO events(occurred_at, severity, type, modem_id, uplink_id, details_json)
VALUES (?, ?, ?, ?, ?, ?)`, now, severity, eventType, uplinkID, uplinkID, string(content)); err != nil {
		return fmt.Errorf("append modem recovery event: %w", err)
	}
	return nil
}
