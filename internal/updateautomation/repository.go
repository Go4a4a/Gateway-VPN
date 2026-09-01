package updateautomation

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	updatepkg "gateway-vpn/internal/update"
)

const (
	PhaseIdle            = "IDLE"
	PhaseDisabled        = "DISABLED"
	PhaseChecking        = "CHECKING"
	PhaseCandidate       = "CANDIDATE"
	PhaseDownloading     = "DOWNLOADING"
	PhaseStaged          = "STAGED"
	PhaseWaitingWindow   = "WAITING_WINDOW"
	PhaseApplyIntent     = "APPLY_INTENT"
	PhaseApplyDispatched = "APPLY_DISPATCHED"
	PhaseSucceeded       = "SUCCEEDED"
	PhaseFailed          = "FAILED"
	PhaseSuppressed      = "SUPPRESSED"
	PhaseManualPending   = "MANUAL_PENDING"
	PhaseManualAttention = "MANUAL_ATTENTION"
	PhaseOutcomeUnknown  = "OUTCOME_UNKNOWN"
)

var (
	phaseSet = map[string]struct{}{
		PhaseIdle: {}, PhaseDisabled: {}, PhaseChecking: {}, PhaseCandidate: {},
		PhaseDownloading: {}, PhaseStaged: {}, PhaseWaitingWindow: {},
		PhaseApplyIntent: {}, PhaseApplyDispatched: {}, PhaseSucceeded: {},
		PhaseFailed: {}, PhaseSuppressed: {}, PhaseManualPending: {}, PhaseManualAttention: {}, PhaseOutcomeUnknown: {},
	}
	codePattern     = regexp.MustCompile(`^[A-Z0-9_]{0,64}$`)
	updateIDPattern = regexp.MustCompile(`^update-[0-9]{8}T[0-9]{6}Z-[a-f0-9]{24}$`)
)

// Status is the redacted durable projection exposed to the API. Lease fields
// are deliberately private to the repository and never leave this package.
type Status struct {
	Phase                string `json:"phase"`
	PolicyUpdatedAt      string `json:"policy_updated_at,omitempty"`
	Channel              string `json:"channel"`
	JitterOffsetMinutes  int    `json:"jitter_offset_minutes"`
	NextCheckAt          string `json:"next_check_at,omitempty"`
	NextApplyAt          string `json:"next_apply_at,omitempty"`
	LastAttemptAt        string `json:"last_attempt_at,omitempty"`
	LastCompletedAt      string `json:"last_completed_at,omitempty"`
	LastResultCode       string `json:"last_result_code,omitempty"`
	LastErrorCode        string `json:"last_error_code,omitempty"`
	ConsecutiveFailures  int    `json:"consecutive_failures"`
	CandidateVersion     string `json:"candidate_version,omitempty"`
	CandidateReference   string `json:"candidate_reference,omitempty"`
	CandidatePublishedAt string `json:"candidate_published_at,omitempty"`
	StagedUpdateID       string `json:"staged_update_id,omitempty"`
	StagedVersion        string `json:"staged_version,omitempty"`
	StagedAt             string `json:"staged_at,omitempty"`
	ApplyDeadlineAt      string `json:"apply_deadline_at,omitempty"`
	ApplyIntentAt        string `json:"apply_intent_at,omitempty"`
	ApplyObservedAt      string `json:"apply_observed_at,omitempty"`
	UpdatedAt            string `json:"updated_at"`
	leaseOwner           string
	leaseExpiresAt       string
}

func (status Status) validate() error {
	if _, ok := phaseSet[status.Phase]; !ok || status.Channel != "stable" && status.Channel != "testing" {
		return errors.New("software update scheduler phase or channel is invalid")
	}
	if status.JitterOffsetMinutes < 0 || status.JitterOffsetMinutes > updatepkg.MaximumJitterMinutes || status.ConsecutiveFailures < 0 || status.ConsecutiveFailures > 100 {
		return errors.New("software update scheduler counter is invalid")
	}
	if !codePattern.MatchString(status.LastResultCode) || !codePattern.MatchString(status.LastErrorCode) {
		return errors.New("software update scheduler result code is invalid")
	}
	for _, value := range []string{status.PolicyUpdatedAt, status.NextCheckAt, status.NextApplyAt, status.LastAttemptAt, status.LastCompletedAt, status.CandidatePublishedAt, status.StagedAt, status.ApplyDeadlineAt, status.ApplyIntentAt, status.ApplyObservedAt, status.UpdatedAt, status.leaseExpiresAt} {
		if value == "" {
			continue
		}
		if _, err := time.Parse(time.RFC3339Nano, value); err != nil {
			return errors.New("software update scheduler timestamp is invalid")
		}
	}
	if status.UpdatedAt == "" || (status.leaseOwner == "") != (status.leaseExpiresAt == "") || len(status.leaseOwner) > 64 {
		return errors.New("software update scheduler lease is invalid")
	}
	for _, version := range []string{status.CandidateVersion, status.StagedVersion} {
		if version != "" && updatepkg.ValidateGatewayVersion(version) != nil {
			return errors.New("software update scheduler version is invalid")
		}
	}
	if err := status.validateCandidateOnly(); err != nil {
		return err
	}
	if status.StagedUpdateID == "" != (status.StagedVersion == "") || status.StagedUpdateID != "" && !updateIDPattern.MatchString(status.StagedUpdateID) {
		return errors.New("software update scheduler staged operation is invalid")
	}
	stagingEmpty := status.StagedUpdateID == ""
	if stagingEmpty != (status.StagedAt == "") || stagingEmpty != (status.ApplyDeadlineAt == "") {
		return errors.New("software update scheduler staging deadline evidence is incomplete")
	}
	if status.StagedUpdateID != "" {
		staged, stagedErr := time.Parse(time.RFC3339Nano, status.StagedAt)
		deadline, deadlineErr := time.Parse(time.RFC3339Nano, status.ApplyDeadlineAt)
		if stagedErr != nil || deadlineErr != nil || !deadline.After(staged) {
			return errors.New("software update scheduler staging deadline is invalid")
		}
	}
	if (status.ApplyIntentAt != "" || status.ApplyObservedAt != "") && status.StagedUpdateID == "" {
		return errors.New("software update scheduler apply evidence has no staged operation")
	}
	return nil
}

func (status Status) validateCandidateOnly() error {
	if status.CandidateVersion == "" != (status.CandidateReference == "") || len(status.CandidateReference) > 256 || strings.TrimSpace(status.CandidateReference) != status.CandidateReference || strings.ContainsAny(status.CandidateReference, "?@\r\n\t") {
		return errors.New("software update scheduler candidate reference is invalid")
	}
	if status.CandidateVersion != "" && updatepkg.ValidateGatewayVersion(status.CandidateVersion) != nil {
		return errors.New("software update scheduler candidate version is invalid")
	}
	return nil
}

type Repository struct {
	Database *sql.DB
}

func (repository Repository) Get(ctx context.Context) (Status, error) {
	if repository.Database == nil {
		return Status{}, errors.New("software update scheduler database is required")
	}
	return readStatus(ctx, repository.Database)
}

func (repository Repository) Acquire(ctx context.Context, owner string, now time.Time, duration time.Duration) (Status, bool, error) {
	if repository.Database == nil || !validOwner(owner) || duration < 30*time.Second || duration > 5*time.Minute {
		return Status{}, false, errors.New("software update scheduler lease request is invalid")
	}
	now = now.UTC()
	expires := now.Add(duration).Format(time.RFC3339Nano)
	result, err := repository.Database.ExecContext(ctx, `
UPDATE software_update_scheduler
SET lease_owner=?, lease_expires_at=?, updated_at=?
WHERE singleton_id=1 AND (
    lease_owner='' OR lease_owner=? OR lease_expires_at<=?
)`, owner, expires, now.Format(time.RFC3339Nano), owner, now.Format(time.RFC3339Nano))
	if err != nil {
		return Status{}, false, fmt.Errorf("acquire software update scheduler lease: %w", err)
	}
	count, err := result.RowsAffected()
	if err != nil {
		return Status{}, false, err
	}
	if count == 0 {
		return Status{}, false, nil
	}
	status, err := readStatus(ctx, repository.Database)
	return status, err == nil, err
}

func (repository Repository) Renew(ctx context.Context, owner string, now time.Time, duration time.Duration) error {
	if repository.Database == nil || !validOwner(owner) || duration < 30*time.Second || duration > 5*time.Minute {
		return errors.New("software update scheduler lease renewal is invalid")
	}
	now = now.UTC()
	result, err := repository.Database.ExecContext(ctx, `
UPDATE software_update_scheduler SET lease_expires_at=?, updated_at=?
WHERE singleton_id=1 AND lease_owner=?`, now.Add(duration).Format(time.RFC3339Nano), now.Format(time.RFC3339Nano), owner)
	if err != nil {
		return fmt.Errorf("renew software update scheduler lease: %w", err)
	}
	if count, countErr := result.RowsAffected(); countErr != nil || count != 1 {
		return errors.New("software update scheduler lease was lost")
	}
	return nil
}

func (repository Repository) Release(ctx context.Context, owner string, now time.Time) error {
	if repository.Database == nil || !validOwner(owner) {
		return errors.New("software update scheduler lease release is invalid")
	}
	result, err := repository.Database.ExecContext(ctx, `
UPDATE software_update_scheduler SET lease_owner='', lease_expires_at=NULL, updated_at=?
WHERE singleton_id=1 AND lease_owner=?`, now.UTC().Format(time.RFC3339Nano), owner)
	if err != nil {
		return fmt.Errorf("release software update scheduler lease: %w", err)
	}
	if count, countErr := result.RowsAffected(); countErr != nil || count != 1 {
		return errors.New("software update scheduler lease was lost")
	}
	return nil
}

func (repository Repository) UpdateOwned(ctx context.Context, owner string, mutate func(*Status) error) (Status, error) {
	if repository.Database == nil || !validOwner(owner) || mutate == nil {
		return Status{}, errors.New("owned software update scheduler mutation is invalid")
	}
	transaction, err := repository.Database.BeginTx(ctx, nil)
	if err != nil {
		return Status{}, err
	}
	defer transaction.Rollback()
	status, err := readStatus(ctx, transaction)
	if err != nil {
		return Status{}, err
	}
	if status.leaseOwner != owner {
		return Status{}, errors.New("software update scheduler lease is not owned")
	}
	if err := mutate(&status); err != nil {
		return Status{}, err
	}
	if err := status.validate(); err != nil {
		return Status{}, err
	}
	result, err := transaction.ExecContext(ctx, `
UPDATE software_update_scheduler SET
    phase=?, policy_updated_at=?, channel=?, jitter_offset_minutes=?,
    next_check_at=?, next_apply_at=?, last_attempt_at=?, last_completed_at=?,
    last_result_code=?, last_error_code=?, consecutive_failures=?,
    candidate_version=?, candidate_reference=?, candidate_published_at=?,
	    staged_update_id=?, staged_version=?, staged_at=?, apply_deadline_at=?,
	    apply_intent_at=?, apply_observed_at=?,
    updated_at=?
WHERE singleton_id=1 AND lease_owner=?`,
		status.Phase, status.PolicyUpdatedAt, status.Channel, status.JitterOffsetMinutes,
		nullable(status.NextCheckAt), nullable(status.NextApplyAt), nullable(status.LastAttemptAt), nullable(status.LastCompletedAt),
		status.LastResultCode, status.LastErrorCode, status.ConsecutiveFailures,
		status.CandidateVersion, status.CandidateReference, nullable(status.CandidatePublishedAt),
		status.StagedUpdateID, status.StagedVersion, nullable(status.StagedAt), nullable(status.ApplyDeadlineAt),
		nullable(status.ApplyIntentAt), nullable(status.ApplyObservedAt),
		status.UpdatedAt, owner,
	)
	if err != nil {
		return Status{}, fmt.Errorf("write software update scheduler state: %w", err)
	}
	if count, countErr := result.RowsAffected(); countErr != nil || count != 1 {
		return Status{}, errors.New("software update scheduler state changed concurrently")
	}
	if err := transaction.Commit(); err != nil {
		return Status{}, err
	}
	return status, nil
}

type statusQuery interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func readStatus(ctx context.Context, query statusQuery) (Status, error) {
	var status Status
	var policyUpdatedAt, nextCheckAt, nextApplyAt, lastAttemptAt, lastCompletedAt sql.NullString
	var candidatePublishedAt, stagedAt, applyDeadlineAt, applyIntentAt, applyObservedAt, leaseExpiresAt sql.NullString
	err := query.QueryRowContext(ctx, `
SELECT phase,policy_updated_at,channel,jitter_offset_minutes,
       next_check_at,next_apply_at,last_attempt_at,last_completed_at,
       last_result_code,last_error_code,consecutive_failures,
       candidate_version,candidate_reference,candidate_published_at,
	       staged_update_id,staged_version,staged_at,apply_deadline_at,
	       apply_intent_at,apply_observed_at,
       lease_owner,lease_expires_at,updated_at
FROM software_update_scheduler WHERE singleton_id=1`).Scan(
		&status.Phase, &policyUpdatedAt, &status.Channel, &status.JitterOffsetMinutes,
		&nextCheckAt, &nextApplyAt, &lastAttemptAt, &lastCompletedAt,
		&status.LastResultCode, &status.LastErrorCode, &status.ConsecutiveFailures,
		&status.CandidateVersion, &status.CandidateReference, &candidatePublishedAt,
		&status.StagedUpdateID, &status.StagedVersion, &stagedAt, &applyDeadlineAt,
		&applyIntentAt, &applyObservedAt,
		&status.leaseOwner, &leaseExpiresAt, &status.UpdatedAt,
	)
	if err != nil {
		return Status{}, fmt.Errorf("read software update scheduler state: %w", err)
	}
	status.PolicyUpdatedAt = policyUpdatedAt.String
	status.NextCheckAt = nextCheckAt.String
	status.NextApplyAt = nextApplyAt.String
	status.LastAttemptAt = lastAttemptAt.String
	status.LastCompletedAt = lastCompletedAt.String
	status.CandidatePublishedAt = candidatePublishedAt.String
	status.StagedAt = stagedAt.String
	status.ApplyDeadlineAt = applyDeadlineAt.String
	status.ApplyIntentAt = applyIntentAt.String
	status.ApplyObservedAt = applyObservedAt.String
	status.leaseExpiresAt = leaseExpiresAt.String
	if err := status.validate(); err != nil {
		return Status{}, err
	}
	return status, nil
}

func nullable(value string) any {
	if value == "" {
		return nil
	}
	return value
}

func validOwner(owner string) bool {
	if len(owner) != 32 {
		return false
	}
	for _, character := range owner {
		if (character < 'a' || character > 'f') && (character < '0' || character > '9') {
			return false
		}
	}
	return true
}
