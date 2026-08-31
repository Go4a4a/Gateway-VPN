package update

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gateway-vpn/internal/backup"
	databasepkg "gateway-vpn/internal/db"
)

const DefaultStabilityWindow = 24 * time.Hour

var (
	ErrUpdateStabilizing     = errors.New("the current release is still inside its stability window")
	ErrStabilityWindowActive = errors.New("the release stability window has not elapsed")
	ErrNoFinalizationPending = errors.New("no update transaction awaits finalization")
	ErrUpdateInProgress      = errors.New("another update transaction process is active")
	errInjectedInterruption  = errors.New("injected update interruption")
)

type HostRuntime interface {
	Observe(context.Context) (ManagedRuntimeState, error)
	Quiesce(context.Context) error
	OfflineCheck(context.Context, string, string, string, string, string, int64) (OfflineResult, error)
	StartAndHealth(context.Context, string, string, ManagedRuntimeState) error
}

type ManagedRuntimeState struct {
	MihomoActive  bool `json:"mihomo_active"`
	DNSMasqActive bool `json:"dnsmasq_active"`
}

type Engine struct {
	Stager          *Stager
	RestorePoints   *RestorePointStore
	Store           JournalStore
	Runtime         HostRuntime
	ReleaseRoot     string
	StateDir        string
	DatabasePath    string
	ConfigPath      string
	CurrentVersion  string
	StateUID        int
	StateGID        int
	StabilityWindow time.Duration
	Now             func() time.Time
	AfterState      func(TransactionState) error
	setOwnership    func(string, int, int) error
}

type ApplyResult struct {
	UpdateID          string `json:"update_id"`
	OldVersion        string `json:"old_version"`
	NewVersion        string `json:"new_version"`
	OldSchemaVersion  int64  `json:"old_schema_version"`
	NewSchemaVersion  int64  `json:"new_schema_version"`
	PreUpdateSnapshot string `json:"pre_update_snapshot"`
	RestorePoint      string `json:"restore_point"`
	State             string `json:"state"`
	StabilityDeadline string `json:"stability_deadline"`
	StagingCleaned    bool   `json:"staging_cleaned"`
}

type RestorePointRollbackResult struct {
	UpdateID          string `json:"update_id"`
	RestorePointID    string `json:"restore_point_id"`
	SafetyPointID     string `json:"safety_point_id"`
	OldVersion        string `json:"old_version"`
	TargetVersion     string `json:"target_version"`
	OldSchemaVersion  int64  `json:"old_schema_version"`
	TargetSchema      int64  `json:"target_schema_version"`
	State             string `json:"state"`
	StabilityDeadline string `json:"stability_deadline"`
}

func (engine *Engine) Apply(ctx context.Context, updateID string) (ApplyResult, error) {
	if err := engine.validate(); err != nil {
		return ApplyResult{}, err
	}
	unlock, err := acquireTransactionLock(engine.Store.Root)
	if err != nil {
		return ApplyResult{}, err
	}
	defer unlock()
	active, exists, err := engine.Store.LoadActive()
	if err != nil {
		return ApplyResult{}, err
	}
	if exists {
		switch active.State {
		case StateStabilizing:
			return ApplyResult{}, ErrUpdateStabilizing
		case StateFinalized, StateRolledBack:
			// A terminal transaction remains as the durable last-update record.
		default:
			if _, err := engine.recoverLocked(ctx); err != nil {
				return ApplyResult{}, fmt.Errorf("recover previous update before applying a new one: %w", err)
			}
		}
	}
	stagedRoot, err := engine.Stager.ReleaseRoot(updateID)
	if err != nil {
		return ApplyResult{}, err
	}
	operation, pending, err := engine.Stager.Status()
	if err != nil || !pending || operation.UpdateID != updateID {
		return ApplyResult{}, errors.New("verified staged update metadata changed before apply")
	}
	verified, err := VerifyRelease(stagedRoot, engine.Stager.Policy)
	if err != nil {
		return ApplyResult{}, fmt.Errorf("reverify staged candidate: %w", err)
	}
	oldTarget, oldRelease, err := engine.currentRelease()
	if err != nil {
		return ApplyResult{}, err
	}
	if oldRelease.GatewayVersion != engine.CurrentVersion {
		return ApplyResult{}, errors.New("running binary version does not match the current release target")
	}
	// Boot recovery must never depend on the candidate that is about to become
	// current. Pin a separate recovery entry point to the initiating (old)
	// release before any database or current-symlink mutation.
	if err := engine.switchReleasePointer("recovery", oldTarget, updateID+"-recovery"); err != nil {
		return ApplyResult{}, fmt.Errorf("pin previous release recovery entry point: %w", err)
	}
	newTarget := "releases/v" + verified.Release.GatewayVersion
	installedRoot, err := engine.installRelease(verified)
	if err != nil {
		return ApplyResult{}, err
	}
	managedState, err := engine.Runtime.Observe(ctx)
	if err != nil {
		return ApplyResult{}, fmt.Errorf("observe managed services before update: %w", err)
	}
	now := engine.now()
	journal := Journal{
		FormatVersion: JournalFormatVersion, OperationKind: TransactionSignedUpdate, UpdateID: updateID, State: StatePrepared,
		StartedAt: now.Format(time.RFC3339Nano), UpdatedAt: now.Format(time.RFC3339Nano),
		OldVersion: oldRelease.GatewayVersion, NewVersion: verified.Release.GatewayVersion,
		OldCurrentTarget: oldTarget, NewCurrentTarget: newTarget,
		MihomoWasActive: managedState.MihomoActive, DNSMasqWasActive: managedState.DNSMasqActive,
		SourceKind: operation.SourceKind, SourceChannel: operation.SourceChannel, SourceReference: operation.SourceReference,
	}
	if err := engine.saveState(&journal, StatePrepared); err != nil {
		return ApplyResult{}, err
	}
	failed := func(code string, cause error) (ApplyResult, error) {
		rollbackErr := engine.rollback(ctx, &journal, code)
		if rollbackErr != nil {
			return ApplyResult{}, fmt.Errorf("update failed (%v) and rollback failed: %w", cause, rollbackErr)
		}
		return ApplyResult{}, fmt.Errorf("update rejected and rolled back: %w", cause)
	}
	if err := engine.Runtime.Quiesce(ctx); err != nil {
		return failed("QUIESCE_FAILED", err)
	}
	if err := engine.saveState(&journal, StateQuiesced); err != nil {
		if errors.Is(err, errInjectedInterruption) {
			return ApplyResult{}, err
		}
		return failed("JOURNAL_QUIESCED_FAILED", err)
	}
	snapshot, oldSchema, err := engine.createPreUpdateSnapshot(ctx)
	if err != nil {
		return failed("PRE_UPDATE_SNAPSHOT_FAILED", err)
	}
	restorePoint, err := engine.RestorePoints.CreatePreUpdate(ctx, oldRelease.GatewayVersion, oldSchema, filepath.Join(snapshot.Path, "state.db"))
	if err != nil {
		return failed("RESTORE_POINT_FAILED", err)
	}
	journal.PreUpdateSnapshotID = snapshot.Manifest.SnapshotID
	journal.RestorePointID = restorePoint.Manifest.PointID
	journal.OldSchemaVersion = oldSchema
	if err := engine.saveState(&journal, StateRestorePointReady); err != nil {
		if errors.Is(err, errInjectedInterruption) {
			return ApplyResult{}, err
		}
		return failed("JOURNAL_RESTORE_POINT_FAILED", err)
	}
	candidatePath := engine.candidateDatabasePath(updateID)
	if err := copyExclusiveFile(filepath.Join(snapshot.Path, "state.db"), candidatePath, 0o600, MaximumFileBytes); err != nil {
		return failed("CANDIDATE_DB_COPY_FAILED", err)
	}
	if err := engine.applyOwnership(candidatePath); err != nil {
		return failed("CANDIDATE_DB_OWNERSHIP_FAILED", err)
	}
	candidateBinary := filepath.Join(installedRoot, "bin", "gateway-vpn")
	offline, err := engine.Runtime.OfflineCheck(ctx, candidateBinary, candidatePath, engine.ConfigPath, verified.Release.GatewayVersion, verified.Release.MihomoVersion, verified.Release.DatabaseSchemaMaximum)
	if err != nil {
		return failed("CANDIDATE_OFFLINE_CHECK_FAILED", err)
	}
	if err := verifyOfflineResult(offline, verified.Release.DatabaseSchemaMaximum); err != nil {
		return failed("CANDIDATE_OFFLINE_RESULT_INVALID", err)
	}
	if err := verifyCandidateDatabase(ctx, candidatePath, offline); err != nil {
		return failed("CANDIDATE_DB_REVERIFY_FAILED", err)
	}
	journal.NewSchemaVersion = offline.SchemaVersion
	journal.CandidateDBSHA256 = offline.DatabaseSHA256
	if err := engine.saveState(&journal, StateCandidateReady); err != nil {
		if errors.Is(err, errInjectedInterruption) {
			return ApplyResult{}, err
		}
		return failed("JOURNAL_CANDIDATE_FAILED", err)
	}
	journal.DatabaseReplacementStarted = true
	if err := engine.saveState(&journal, StateDatabaseSwitchPending); err != nil {
		if errors.Is(err, errInjectedInterruption) {
			return ApplyResult{}, err
		}
		return failed("JOURNAL_DB_SWITCH_PENDING_FAILED", err)
	}
	if err := removeDatabaseSidecars(engine.DatabasePath); err != nil {
		return failed("LIVE_DB_SIDECAR_CLEANUP_FAILED", err)
	}
	if err := replaceFile(candidatePath, engine.DatabasePath); err != nil {
		return failed("LIVE_DB_ATOMIC_REPLACE_FAILED", err)
	}
	if err := engine.applyOwnership(engine.DatabasePath); err != nil {
		return failed("LIVE_DB_OWNERSHIP_FAILED", err)
	}
	if err := syncDirectoryPath(filepath.Dir(engine.DatabasePath)); err != nil {
		return failed("LIVE_DB_DIRECTORY_SYNC_FAILED", err)
	}
	if err := engine.saveState(&journal, StateDatabaseSwitched); err != nil {
		if errors.Is(err, errInjectedInterruption) {
			return ApplyResult{}, err
		}
		return failed("JOURNAL_DB_SWITCHED_FAILED", err)
	}
	if err := engine.saveState(&journal, StateReleaseSwitchPending); err != nil {
		if errors.Is(err, errInjectedInterruption) {
			return ApplyResult{}, err
		}
		return failed("JOURNAL_RELEASE_SWITCH_PENDING_FAILED", err)
	}
	if err := engine.switchCurrent(newTarget, updateID); err != nil {
		return failed("CURRENT_ATOMIC_SWITCH_FAILED", err)
	}
	if err := engine.saveState(&journal, StateSwitched); err != nil {
		if errors.Is(err, errInjectedInterruption) {
			return ApplyResult{}, err
		}
		return failed("JOURNAL_SWITCHED_FAILED", err)
	}
	if err := engine.saveState(&journal, StateHealthChecking); err != nil {
		if errors.Is(err, errInjectedInterruption) {
			return ApplyResult{}, err
		}
		return failed("JOURNAL_HEALTH_FAILED", err)
	}
	if err := engine.Runtime.StartAndHealth(ctx, verified.Release.GatewayVersion, engine.DatabasePath, managedState); err != nil {
		return failed("NEW_RELEASE_HEALTH_FAILED", err)
	}
	deadline := engine.now().Add(engine.stabilityWindow())
	journal.StabilityDeadline = deadline.Format(time.RFC3339Nano)
	journal.ErrorCode = ""
	if err := engine.saveState(&journal, StateStabilizing); err != nil {
		if errors.Is(err, errInjectedInterruption) {
			return ApplyResult{}, err
		}
		return failed("JOURNAL_STABILIZING_FAILED", err)
	}
	cleaned := engine.Stager.Discard(context.Background(), updateID) == nil
	return ApplyResult{
		UpdateID: updateID, OldVersion: journal.OldVersion, NewVersion: journal.NewVersion,
		OldSchemaVersion: oldSchema, NewSchemaVersion: offline.SchemaVersion,
		PreUpdateSnapshot: snapshot.Manifest.SnapshotID, RestorePoint: restorePoint.Manifest.PointID, State: string(StateStabilizing),
		StabilityDeadline: journal.StabilityDeadline, StagingCleaned: cleaned,
	}, nil
}

// RollbackToRestorePoint applies one exact, fully verified historical pair.
// Before any live mutation it creates a second complete safety point for the
// currently running pair. The ordinary update boot-recovery journal then has
// enough information to restore that safety point after SIGKILL or reboot.
func (engine *Engine) RollbackToRestorePoint(ctx context.Context, pointID string) (RestorePointRollbackResult, error) {
	if err := engine.validateWithoutStager(); err != nil {
		return RestorePointRollbackResult{}, err
	}
	if ValidateRestorePointID(pointID) != nil {
		return RestorePointRollbackResult{}, errors.New("restore point id is invalid")
	}
	unlock, err := acquireTransactionLock(engine.Store.Root)
	if err != nil {
		return RestorePointRollbackResult{}, err
	}
	defer unlock()
	active, exists, err := engine.Store.LoadActive()
	if err != nil {
		return RestorePointRollbackResult{}, err
	}
	if exists && !terminalState(active.State) {
		return RestorePointRollbackResult{}, ErrUpdateInProgress
	}
	target, err := engine.RestorePoints.Get(ctx, pointID)
	if err != nil {
		return RestorePointRollbackResult{}, err
	}
	if !target.Compatible {
		return RestorePointRollbackResult{}, errors.New("restore point is incompatible with the installed host contract")
	}
	oldTarget, oldRelease, err := engine.currentRelease()
	if err != nil {
		return RestorePointRollbackResult{}, err
	}
	if oldRelease.GatewayVersion != engine.CurrentVersion {
		return RestorePointRollbackResult{}, errors.New("running recovery binary does not match the current release")
	}
	targetRoot := filepath.Join(engine.ReleaseRoot, filepath.FromSlash(target.Manifest.ReleaseTarget))
	targetRelease, err := ReadReleaseMetadata(targetRoot)
	if err != nil || targetRelease.GatewayVersion != target.Manifest.GatewayVersion || targetRelease.DatabaseSchemaMaximum != target.Manifest.SchemaVersion {
		return RestorePointRollbackResult{}, errors.New("restore point release and database pair is inconsistent")
	}
	managedState, err := engine.Runtime.Observe(ctx)
	if err != nil {
		return RestorePointRollbackResult{}, fmt.Errorf("observe managed services before restore point rollback: %w", err)
	}
	transactionID, err := newUpdateID(engine.now())
	if err != nil {
		return RestorePointRollbackResult{}, err
	}
	if err := engine.switchReleasePointer("recovery", oldTarget, transactionID+"-recovery"); err != nil {
		return RestorePointRollbackResult{}, fmt.Errorf("pin current release recovery entry point: %w", err)
	}
	now := engine.now()
	journal := Journal{
		FormatVersion: JournalFormatVersion, OperationKind: TransactionRestorePointRollback,
		UpdateID: transactionID, State: StatePrepared, StartedAt: now.Format(time.RFC3339Nano), UpdatedAt: now.Format(time.RFC3339Nano),
		OldVersion: oldRelease.GatewayVersion, NewVersion: target.Manifest.GatewayVersion,
		OldCurrentTarget: oldTarget, NewCurrentTarget: target.Manifest.ReleaseTarget,
		TargetRestorePointID: pointID, MihomoWasActive: managedState.MihomoActive, DNSMasqWasActive: managedState.DNSMasqActive,
	}
	if err := engine.saveState(&journal, StatePrepared); err != nil {
		return RestorePointRollbackResult{}, err
	}
	failed := func(code string, cause error) (RestorePointRollbackResult, error) {
		rollbackErr := engine.rollback(ctx, &journal, code)
		if rollbackErr != nil {
			return RestorePointRollbackResult{}, fmt.Errorf("restore point rollback failed (%v) and safety recovery failed: %w", cause, rollbackErr)
		}
		return RestorePointRollbackResult{}, fmt.Errorf("restore point was rejected and the safety pair was restored: %w", cause)
	}
	if err := engine.Runtime.Quiesce(ctx); err != nil {
		return failed("RESTORE_QUIESCE_FAILED", err)
	}
	if err := engine.saveState(&journal, StateQuiesced); err != nil {
		if errors.Is(err, errInjectedInterruption) {
			return RestorePointRollbackResult{}, err
		}
		return failed("RESTORE_JOURNAL_QUIESCED_FAILED", err)
	}
	snapshot, oldSchema, err := engine.createPreUpdateSnapshot(ctx)
	if err != nil {
		return failed("RESTORE_SAFETY_SNAPSHOT_FAILED", err)
	}
	safety, err := engine.RestorePoints.CreatePreUpdate(ctx, oldRelease.GatewayVersion, oldSchema, filepath.Join(snapshot.Path, "state.db"))
	if err != nil {
		return failed("RESTORE_SAFETY_POINT_FAILED", err)
	}
	journal.PreUpdateSnapshotID = snapshot.Manifest.SnapshotID
	journal.RestorePointID = safety.Manifest.PointID
	journal.OldSchemaVersion = oldSchema
	if err := engine.saveState(&journal, StateRestorePointReady); err != nil {
		if errors.Is(err, errInjectedInterruption) {
			return RestorePointRollbackResult{}, err
		}
		return failed("RESTORE_SAFETY_JOURNAL_FAILED", err)
	}
	projection, err := engine.prepareRestoreProjection(ctx, pointID, transactionID)
	if err != nil {
		return failed("RESTORE_PROJECTION_PREPARE_FAILED", err)
	}
	defer projection.cleanupCandidates()
	offline, err := engine.Runtime.OfflineCheck(ctx, filepath.Join(targetRoot, "bin", "gateway-vpn"), projection.Database, projection.Configuration, targetRelease.GatewayVersion, targetRelease.MihomoVersion, targetRelease.DatabaseSchemaMaximum)
	if err != nil {
		return failed("RESTORE_OFFLINE_CHECK_FAILED", err)
	}
	if err := verifyOfflineResult(offline, target.Manifest.SchemaVersion); err != nil {
		return failed("RESTORE_OFFLINE_RESULT_INVALID", err)
	}
	if err := verifyCandidateDatabase(ctx, projection.Database, offline); err != nil {
		return failed("RESTORE_DATABASE_REVERIFY_FAILED", err)
	}
	projection.DatabaseSHA256 = offline.DatabaseSHA256
	projection.DatabaseBytes = offline.DatabaseBytes
	journal.NewSchemaVersion = offline.SchemaVersion
	journal.CandidateDBSHA256 = offline.DatabaseSHA256
	if err := engine.saveState(&journal, StateCandidateReady); err != nil {
		if errors.Is(err, errInjectedInterruption) {
			return RestorePointRollbackResult{}, err
		}
		return failed("RESTORE_CANDIDATE_JOURNAL_FAILED", err)
	}
	journal.DatabaseReplacementStarted = true
	if err := engine.saveState(&journal, StateDatabaseSwitchPending); err != nil {
		if errors.Is(err, errInjectedInterruption) {
			return RestorePointRollbackResult{}, err
		}
		return failed("RESTORE_SWITCH_PENDING_JOURNAL_FAILED", err)
	}
	if err := engine.applyRestoreProjection(ctx, projection); err != nil {
		return failed("RESTORE_PROJECTION_APPLY_FAILED", err)
	}
	if err := engine.saveState(&journal, StateDatabaseSwitched); err != nil {
		if errors.Is(err, errInjectedInterruption) {
			return RestorePointRollbackResult{}, err
		}
		return failed("RESTORE_PROJECTION_SWITCHED_JOURNAL_FAILED", err)
	}
	if err := engine.saveState(&journal, StateReleaseSwitchPending); err != nil {
		if errors.Is(err, errInjectedInterruption) {
			return RestorePointRollbackResult{}, err
		}
		return failed("RESTORE_RELEASE_PENDING_JOURNAL_FAILED", err)
	}
	if err := engine.switchCurrent(target.Manifest.ReleaseTarget, transactionID); err != nil {
		return failed("RESTORE_CURRENT_SWITCH_FAILED", err)
	}
	if err := engine.saveState(&journal, StateSwitched); err != nil {
		if errors.Is(err, errInjectedInterruption) {
			return RestorePointRollbackResult{}, err
		}
		return failed("RESTORE_RELEASE_SWITCHED_JOURNAL_FAILED", err)
	}
	if err := engine.saveState(&journal, StateHealthChecking); err != nil {
		if errors.Is(err, errInjectedInterruption) {
			return RestorePointRollbackResult{}, err
		}
		return failed("RESTORE_HEALTH_JOURNAL_FAILED", err)
	}
	if err := engine.Runtime.StartAndHealth(ctx, target.Manifest.GatewayVersion, engine.DatabasePath, managedState); err != nil {
		return failed("RESTORE_TARGET_HEALTH_FAILED", err)
	}
	journal.StabilityDeadline = engine.now().Add(engine.stabilityWindow()).Format(time.RFC3339Nano)
	journal.ErrorCode = ""
	if err := engine.saveState(&journal, StateStabilizing); err != nil {
		if errors.Is(err, errInjectedInterruption) {
			return RestorePointRollbackResult{}, err
		}
		return failed("RESTORE_STABILIZING_JOURNAL_FAILED", err)
	}
	return RestorePointRollbackResult{
		UpdateID: transactionID, RestorePointID: pointID, SafetyPointID: safety.Manifest.PointID,
		OldVersion: oldRelease.GatewayVersion, TargetVersion: target.Manifest.GatewayVersion,
		OldSchemaVersion: oldSchema, TargetSchema: offline.SchemaVersion,
		State: string(StateStabilizing), StabilityDeadline: journal.StabilityDeadline,
	}, nil
}

func (engine *Engine) Recover(ctx context.Context) (bool, error) {
	if err := engine.validateWithoutStager(); err != nil {
		return false, err
	}
	unlock, err := acquireTransactionLock(engine.Store.Root)
	if err != nil {
		return false, err
	}
	defer unlock()
	return engine.recoverLocked(ctx)
}

func (engine *Engine) recoverLocked(ctx context.Context) (bool, error) {
	journal, exists, err := engine.Store.LoadActive()
	if err != nil || !exists {
		return false, err
	}
	switch journal.State {
	case StateStabilizing:
		if err := engine.verifyStabilizing(ctx, journal); err != nil {
			if rollbackErr := engine.rollback(ctx, &journal, "STABILIZING_RECOVERY_HEALTH_FAILED"); rollbackErr != nil {
				return false, rollbackErr
			}
			return true, nil
		}
		return false, nil
	case StateFinalized, StateRolledBack:
		return false, nil
	default:
		if err := engine.rollback(ctx, &journal, "BOOT_OR_PROCESS_RECOVERY"); err != nil {
			return false, err
		}
		return true, nil
	}
}

func (engine *Engine) Finalize(ctx context.Context) (Journal, error) {
	if err := engine.validateWithoutStager(); err != nil {
		return Journal{}, err
	}
	unlock, err := acquireTransactionLock(engine.Store.Root)
	if err != nil {
		return Journal{}, err
	}
	defer unlock()
	journal, exists, err := engine.Store.LoadActive()
	if err != nil {
		return Journal{}, err
	}
	if !exists {
		return Journal{}, ErrNoFinalizationPending
	}
	if journal.State == StateFinalized || journal.State == StateRolledBack {
		return journal, ErrNoFinalizationPending
	}
	if journal.State != StateStabilizing {
		return Journal{}, errors.New("only a stabilizing update may be finalized")
	}
	target, release, err := engine.currentRelease()
	if err != nil || target != journal.NewCurrentTarget || release.GatewayVersion != journal.NewVersion {
		if rollbackErr := engine.rollback(ctx, &journal, "FINALIZE_CURRENT_MISMATCH"); rollbackErr != nil {
			return Journal{}, rollbackErr
		}
		return Journal{}, errors.New("stabilizing current release changed and was rolled back")
	}
	if err := verifyLiveDatabase(ctx, engine.DatabasePath, journal.NewSchemaVersion); err != nil {
		if rollbackErr := engine.rollback(ctx, &journal, "FINALIZE_DATABASE_FAILED"); rollbackErr != nil {
			return Journal{}, rollbackErr
		}
		return Journal{}, errors.New("stabilizing database failed verification and was rolled back")
	}
	if err := engine.Runtime.StartAndHealth(ctx, journal.NewVersion, engine.DatabasePath, journal.managedState()); err != nil {
		if rollbackErr := engine.rollback(ctx, &journal, "FINALIZE_HEALTH_FAILED"); rollbackErr != nil {
			return Journal{}, rollbackErr
		}
		return Journal{}, errors.New("stabilizing release health failed and was rolled back")
	}
	deadline, _ := time.Parse(time.RFC3339Nano, journal.StabilityDeadline)
	if engine.now().Before(deadline) {
		return Journal{}, ErrStabilityWindowActive
	}
	// Only after the complete stability window and a fresh health check may the
	// trusted updater/recovery entry point advance to the new release. This
	// guarantees that the next update is never executed by an older binary that
	// may not understand the current database or signed-release contract.
	if err := engine.switchReleasePointer("recovery", journal.NewCurrentTarget, journal.UpdateID+"-finalize-recovery"); err != nil {
		return Journal{}, errors.New("advance finalized recovery release failed")
	}
	journal.ErrorCode = ""
	if err := engine.saveState(&journal, StateFinalized); err != nil {
		return Journal{}, err
	}
	return journal, nil
}

func (engine *Engine) rollback(ctx context.Context, journal *Journal, code string) error {
	journal.ErrorCode = sanitizedErrorCode(code)
	if err := engine.saveStateNoHook(journal, StateRollingBack); err != nil {
		return err
	}
	if err := engine.Runtime.Quiesce(ctx); err != nil {
		_ = engine.markRollbackFailed(journal, "ROLLBACK_QUIESCE_FAILED")
		return err
	}
	if journal.DatabaseReplacementStarted && journal.transactionKind() == TransactionRestorePointRollback {
		projection, err := engine.prepareRestoreProjection(ctx, journal.RestorePointID, journal.UpdateID)
		if err != nil {
			_ = engine.markRollbackFailed(journal, "ROLLBACK_SAFETY_POINT_INVALID")
			return err
		}
		defer projection.cleanupCandidates()
		if err := engine.applyRestoreProjection(ctx, projection); err != nil {
			_ = engine.markRollbackFailed(journal, "ROLLBACK_SAFETY_POINT_APPLY_FAILED")
			return err
		}
	} else if journal.DatabaseReplacementStarted {
		snapshot, err := engine.verifiedSnapshot(ctx, journal.PreUpdateSnapshotID)
		if err != nil {
			_ = engine.markRollbackFailed(journal, "ROLLBACK_SNAPSHOT_INVALID")
			return err
		}
		candidate := engine.rollbackDatabasePath(journal.UpdateID)
		_ = os.Remove(candidate)
		if err := copyExclusiveFile(filepath.Join(snapshot.Path, "state.db"), candidate, 0o600, MaximumFileBytes); err != nil {
			_ = engine.markRollbackFailed(journal, "ROLLBACK_DB_COPY_FAILED")
			return err
		}
		if err := engine.applyOwnership(candidate); err != nil {
			_ = engine.markRollbackFailed(journal, "ROLLBACK_DB_OWNERSHIP_FAILED")
			return err
		}
		if err := removeDatabaseSidecars(engine.DatabasePath); err != nil {
			_ = engine.markRollbackFailed(journal, "ROLLBACK_DB_SIDECAR_FAILED")
			return err
		}
		if err := replaceFile(candidate, engine.DatabasePath); err != nil {
			_ = engine.markRollbackFailed(journal, "ROLLBACK_DB_REPLACE_FAILED")
			return err
		}
		if err := engine.applyOwnership(engine.DatabasePath); err != nil {
			_ = engine.markRollbackFailed(journal, "ROLLBACK_DB_FINAL_OWNERSHIP_FAILED")
			return err
		}
		if err := syncDirectoryPath(filepath.Dir(engine.DatabasePath)); err != nil {
			_ = engine.markRollbackFailed(journal, "ROLLBACK_DB_SYNC_FAILED")
			return err
		}
	}
	if err := engine.switchCurrent(journal.OldCurrentTarget, journal.UpdateID+"-rollback"); err != nil {
		_ = engine.markRollbackFailed(journal, "ROLLBACK_CURRENT_FAILED")
		return err
	}
	if journal.OldSchemaVersion > 0 {
		if err := verifyLiveDatabase(ctx, engine.DatabasePath, journal.OldSchemaVersion); err != nil {
			_ = engine.markRollbackFailed(journal, "ROLLBACK_DB_VERIFY_FAILED")
			return err
		}
	}
	if err := engine.Runtime.StartAndHealth(ctx, journal.OldVersion, engine.DatabasePath, journal.managedState()); err != nil {
		_ = engine.markRollbackFailed(journal, "ROLLBACK_OLD_HEALTH_FAILED")
		return err
	}
	journal.StabilityDeadline = ""
	if err := engine.saveStateNoHook(journal, StateRolledBack); err != nil {
		return err
	}
	return nil
}

func (engine *Engine) createPreUpdateSnapshot(ctx context.Context) (backup.Snapshot, int64, error) {
	database, err := databasepkg.Open(ctx, databasepkg.OpenOptions{Path: engine.DatabasePath})
	if err != nil {
		return backup.Snapshot{}, 0, err
	}
	defer database.Close()
	if err := databasepkg.QuickCheck(ctx, database); err != nil {
		return backup.Snapshot{}, 0, err
	}
	if err := databasepkg.IntegrityCheck(ctx, database); err != nil {
		return backup.Snapshot{}, 0, err
	}
	if err := databasepkg.ForeignKeyCheck(ctx, database); err != nil {
		return backup.Snapshot{}, 0, err
	}
	schema, err := databasepkg.ReadSchemaVersion(ctx, database)
	if err != nil || schema < 1 {
		return backup.Snapshot{}, 0, errors.New("live database schema is unavailable")
	}
	manager, err := backup.NewManager(database, engine.StateDir, engine.DatabasePath)
	if err != nil {
		return backup.Snapshot{}, 0, err
	}
	manager.Root = engine.updateSnapshotRoot()
	snapshot, err := manager.Create(ctx, backup.KindPreUpdate)
	if err != nil {
		return backup.Snapshot{}, 0, err
	}
	if _, err := database.ExecContext(ctx, "PRAGMA wal_checkpoint(TRUNCATE)"); err != nil {
		return backup.Snapshot{}, 0, errors.New("checkpoint live database before switch failed")
	}
	if err := database.Close(); err != nil {
		return backup.Snapshot{}, 0, err
	}
	if err := removeDatabaseSidecars(engine.DatabasePath); err != nil {
		return backup.Snapshot{}, 0, err
	}
	return snapshot, schema, nil
}

func (engine *Engine) verifiedSnapshot(ctx context.Context, id string) (backup.Snapshot, error) {
	manager, err := backup.NewManager(nil, engine.StateDir, engine.DatabasePath)
	if err != nil {
		return backup.Snapshot{}, err
	}
	manager.Root = engine.updateSnapshotRoot()
	items, err := manager.List(ctx, true)
	if err != nil {
		return backup.Snapshot{}, err
	}
	for _, item := range items {
		if item.Manifest.SnapshotID == id && item.Manifest.Kind == backup.KindPreUpdate {
			return item, nil
		}
	}
	return backup.Snapshot{}, errors.New("verified pre-update snapshot is unavailable")
}

func (engine *Engine) currentRelease() (string, Release, error) {
	current := filepath.Join(engine.ReleaseRoot, "current")
	target, err := readCurrentLink(current)
	if err != nil || filepath.IsAbs(target) {
		return "", Release{}, errors.New("Gateway VPN current symlink target is invalid")
	}
	target = filepath.ToSlash(filepath.Clean(target))
	if !strings.HasPrefix(target, "releases/v") || strings.Contains(strings.TrimPrefix(target, "releases/v"), "/") {
		return "", Release{}, errors.New("Gateway VPN current symlink escapes the release layout")
	}
	release, err := ReadReleaseMetadata(filepath.Join(engine.ReleaseRoot, filepath.FromSlash(target)))
	if err != nil || target != "releases/v"+release.GatewayVersion {
		return "", Release{}, errors.New("current release metadata does not match its target")
	}
	return target, release, nil
}

func (engine *Engine) installRelease(verified VerifiedRelease) (string, error) {
	releasesRoot := filepath.Join(engine.ReleaseRoot, "releases")
	if err := secureRealDirectory(releasesRoot, 0o755); err != nil {
		return "", err
	}
	destination := filepath.Join(releasesRoot, "v"+verified.Release.GatewayVersion)
	if pathExists(destination) {
		existing, err := VerifyRelease(destination, engine.Stager.Policy)
		if err != nil || !sameVerifiedArtifact(existing, verified) {
			return "", errors.New("existing candidate release directory is not the same verified artifact")
		}
		if err := normalizeReleaseDirectoryModes(destination); err != nil {
			return "", fmt.Errorf("normalize existing candidate release directories: %w", err)
		}
		if err := syncTree(destination); err != nil {
			return "", err
		}
		existing, err = VerifyRelease(destination, engine.Stager.Policy)
		if err != nil || !sameVerifiedArtifact(existing, verified) {
			return "", errors.New("existing candidate release changed while normalizing directories")
		}
		return destination, nil
	}
	temporary := filepath.Join(releasesRoot, ".v"+verified.Release.GatewayVersion+"-"+verified.Manifest.ReleaseJSONSHA256[:12])
	if pathExists(temporary) {
		if existing, err := VerifyRelease(temporary, engine.Stager.Policy); err == nil && sameVerifiedArtifact(existing, verified) {
			if err := normalizeReleaseDirectoryModes(temporary); err != nil {
				return "", fmt.Errorf("normalize interrupted candidate release directories: %w", err)
			}
			if err := syncTree(temporary); err != nil {
				return "", err
			}
			existing, err = VerifyRelease(temporary, engine.Stager.Policy)
			if err != nil || !sameVerifiedArtifact(existing, verified) {
				return "", errors.New("interrupted candidate release changed while normalizing directories")
			}
			if err := os.Rename(temporary, destination); err != nil {
				return "", err
			}
			if err := syncDirectoryPath(releasesRoot); err != nil {
				return "", err
			}
			return destination, nil
		}
		if err := removeReleaseTemporary(releasesRoot, temporary); err != nil {
			return "", fmt.Errorf("discard interrupted candidate release copy: %w", err)
		}
	}
	if err := os.Mkdir(temporary, 0o755); err != nil {
		return "", err
	}
	defer func() { _ = removeReleaseTemporary(releasesRoot, temporary) }()
	// gateway-vpn-update.service deliberately runs with UMask=0077. Chmod the
	// root explicitly so the unprivileged runtime can traverse the release after
	// the atomic rename; ownership remains that of the privileged updater.
	if err := os.Chmod(temporary, 0o755); err != nil {
		return "", err
	}
	records := append([]FileRecord(nil), verified.Manifest.Files...)
	for _, name := range []string{ManifestFilename, SignatureFilename} {
		info, err := os.Lstat(filepath.Join(verified.Root, name))
		if err != nil {
			return "", err
		}
		records = append(records, FileRecord{Path: name, Bytes: info.Size(), Executable: false})
	}
	for _, record := range records {
		source := filepath.Join(verified.Root, filepath.FromSlash(record.Path))
		target := filepath.Join(temporary, filepath.FromSlash(record.Path))
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return "", err
		}
		mode := os.FileMode(0o644)
		if record.Executable {
			mode = 0o755
		}
		if err := copyExclusiveFile(source, target, mode, MaximumFileBytes); err != nil {
			return "", err
		}
	}
	// MkdirAll applies the process umask to every newly-created component. Make
	// every real directory in the verified candidate tree exactly traversable;
	// signed file modes are set separately by copyExclusiveFile.
	if err := normalizeReleaseDirectoryModes(temporary); err != nil {
		return "", fmt.Errorf("normalize candidate release directories: %w", err)
	}
	if err := syncTree(temporary); err != nil {
		return "", err
	}
	if _, err := VerifyRelease(temporary, engine.Stager.Policy); err != nil {
		return "", fmt.Errorf("reverify installed candidate release: %w", err)
	}
	if err := os.Rename(temporary, destination); err != nil {
		return "", err
	}
	if err := syncDirectoryPath(releasesRoot); err != nil {
		return "", err
	}
	return destination, nil
}

func normalizeReleaseDirectoryModes(root string) error {
	root, err := safeRoot(root)
	if err != nil {
		return err
	}
	return filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		info, err := os.Lstat(path)
		if err != nil || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("candidate release directory tree is unsafe")
		}
		if !entry.IsDir() {
			return nil
		}
		if path != root {
			relative, err := filepath.Rel(root, path)
			if err != nil || !safeRelativePath(filepath.ToSlash(relative)) {
				return errors.New("candidate release directory path is unsafe")
			}
		}
		if err := os.Chmod(path, 0o755); err != nil {
			return fmt.Errorf("chmod candidate release directory: %w", err)
		}
		return nil
	})
}

func sameVerifiedArtifact(left, right VerifiedRelease) bool {
	return left.Release.GatewayVersion == right.Release.GatewayVersion && left.Fingerprint == right.Fingerprint && left.Manifest.ReleaseJSONSHA256 == right.Manifest.ReleaseJSONSHA256 && equalFileRecords(left.Manifest.Files, right.Manifest.Files)
}

func removeReleaseTemporary(releasesRoot, temporary string) error {
	releasesRoot = filepath.Clean(releasesRoot)
	temporary = filepath.Clean(temporary)
	base := filepath.Base(temporary)
	if filepath.Dir(temporary) != releasesRoot || !strings.HasPrefix(base, ".v") || len(base) > MaximumRelativePath {
		return errors.New("refuse unmanaged release temporary directory")
	}
	info, err := os.Lstat(temporary)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return errors.New("release temporary path is unsafe")
	}
	paths := make([]string, 0, MaximumArchiveEntries+1)
	err = filepath.WalkDir(temporary, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		item, err := os.Lstat(path)
		if err != nil || item.Mode()&os.ModeSymlink != 0 || !item.IsDir() && !item.Mode().IsRegular() {
			return errors.New("release temporary tree contains an unsafe entry")
		}
		if len(paths) >= MaximumArchiveEntries+1 {
			return errors.New("release temporary tree exceeds its entry bound")
		}
		paths = append(paths, path)
		return nil
	})
	if err != nil {
		return err
	}
	for index := len(paths) - 1; index >= 0; index-- {
		if err := os.Remove(paths[index]); err != nil {
			return err
		}
	}
	return syncDirectoryPath(releasesRoot)
}

func (engine *Engine) switchCurrent(target, suffix string) error {
	return engine.switchReleasePointer("current", target, suffix)
}

func (engine *Engine) switchReleasePointer(name, target, suffix string) error {
	if name != "current" && name != "recovery" {
		return errors.New("refuse unmanaged release pointer")
	}
	if target != "releases/v"+strings.TrimPrefix(target, "releases/v") || !versionPattern.MatchString(strings.TrimPrefix(target, "releases/v")) {
		return errors.New("refuse unsafe current release target")
	}
	temporary := filepath.Join(engine.ReleaseRoot, "."+name+"-"+strings.ReplaceAll(suffix, "-rollback", "")+".new")
	_ = os.Remove(temporary)
	if err := createCurrentLink(temporary, filepath.FromSlash(target)); err != nil {
		return err
	}
	if err := replaceFile(temporary, filepath.Join(engine.ReleaseRoot, name)); err != nil {
		_ = os.Remove(temporary)
		return err
	}
	return syncDirectoryPath(engine.ReleaseRoot)
}

func (engine *Engine) verifyStabilizing(ctx context.Context, journal Journal) error {
	target, release, err := engine.currentRelease()
	if err != nil || target != journal.NewCurrentTarget || release.GatewayVersion != journal.NewVersion {
		return errors.New("stabilizing current release does not match the update journal")
	}
	if err := verifyLiveDatabase(ctx, engine.DatabasePath, journal.NewSchemaVersion); err != nil {
		return err
	}
	return engine.Runtime.StartAndHealth(ctx, journal.NewVersion, engine.DatabasePath, journal.managedState())
}

func (engine *Engine) saveState(journal *Journal, state TransactionState) error {
	if err := engine.saveStateNoHook(journal, state); err != nil {
		return err
	}
	if engine.AfterState != nil {
		if err := engine.AfterState(state); err != nil {
			return fmt.Errorf("%w: %v", errInjectedInterruption, err)
		}
	}
	return nil
}

func (engine *Engine) saveStateNoHook(journal *Journal, state TransactionState) error {
	journal.State = state
	journal.UpdatedAt = engine.now().Format(time.RFC3339Nano)
	return engine.Store.Save(*journal)
}

func (engine *Engine) markRollbackFailed(journal *Journal, code string) error {
	journal.ErrorCode = sanitizedErrorCode(code)
	return engine.saveStateNoHook(journal, StateRollbackFailed)
}

func (engine *Engine) validate() error {
	if engine.Stager == nil {
		return errors.New("verified update stager is required")
	}
	if err := engine.validateWithoutStager(); err != nil {
		return err
	}
	if filepath.Clean(engine.Stager.StateDir) != filepath.Clean(engine.StateDir) || engine.Stager.Policy.CurrentGatewayVersion != engine.CurrentVersion {
		return errors.New("update stager is not bound to the current runtime")
	}
	return nil
}

func (engine *Engine) validateWithoutStager() error {
	if engine.Runtime == nil || engine.RestorePoints == nil || !filepath.IsAbs(engine.ReleaseRoot) || !filepath.IsAbs(engine.StateDir) || !filepath.IsAbs(engine.DatabasePath) || !filepath.IsAbs(engine.ConfigPath) || !versionPattern.MatchString(engine.CurrentVersion) || engine.StateUID < 0 || engine.StateGID < 0 {
		return errors.New("complete fixed update engine configuration is required")
	}
	if err := engine.RestorePoints.validate(); err != nil {
		return err
	}
	state := filepath.Clean(engine.StateDir)
	database := filepath.Clean(engine.DatabasePath)
	relative, err := filepath.Rel(state, database)
	transactionRoot := filepath.Clean(engine.Store.Root)
	restoreRoot := filepath.Clean(engine.RestorePoints.Root)
	if err != nil || relative == "." || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) || !filepath.IsAbs(transactionRoot) || filepath.Base(transactionRoot) != "update-transactions" || transactionRoot == state || pathInside(state, transactionRoot) || restoreRoot != filepath.Join(filepath.Dir(transactionRoot), "update-restore-points") || filepath.Clean(engine.RestorePoints.ReleaseRoot) != filepath.Clean(engine.ReleaseRoot) || filepath.Clean(engine.RestorePoints.StateDir) != state || filepath.Clean(engine.RestorePoints.Configuration) != filepath.Clean(engine.ConfigPath) {
		return errors.New("update database must remain inside state while privileged journals remain outside it")
	}
	return nil
}

func (engine *Engine) updateSnapshotRoot() string {
	return filepath.Join(filepath.Dir(filepath.Clean(engine.Store.Root)), "update-snapshots")
}

func (engine *Engine) candidateDatabasePath(updateID string) string {
	return filepath.Join(filepath.Dir(engine.DatabasePath), "."+filepath.Base(engine.DatabasePath)+"."+updateID+".candidate")
}

func (engine *Engine) rollbackDatabasePath(updateID string) string {
	return filepath.Join(filepath.Dir(engine.DatabasePath), "."+filepath.Base(engine.DatabasePath)+"."+updateID+".rollback")
}

func (engine *Engine) now() time.Time {
	if engine.Now != nil {
		return engine.Now().UTC()
	}
	return time.Now().UTC()
}

func (engine *Engine) applyOwnership(path string) error {
	if engine.setOwnership != nil {
		return engine.setOwnership(path, engine.StateUID, engine.StateGID)
	}
	return setFileOwnership(path, engine.StateUID, engine.StateGID)
}

func (engine *Engine) stabilityWindow() time.Duration {
	if engine.StabilityWindow > 0 {
		return engine.StabilityWindow
	}
	return DefaultStabilityWindow
}

func (journal Journal) managedState() ManagedRuntimeState {
	return ManagedRuntimeState{MihomoActive: journal.MihomoWasActive, DNSMasqActive: journal.DNSMasqWasActive}
}

func copyExclusiveFile(source, destination string, mode os.FileMode, maximum int64) error {
	info, err := os.Lstat(source)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maximum {
		return errors.New("update copy source is unsafe or oversized")
	}
	input, err := os.Open(source)
	if err != nil {
		return err
	}
	defer input.Close()
	output, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	written, copyErr := io.Copy(output, io.LimitReader(input, maximum+1))
	syncErr := output.Sync()
	closeErr := output.Close()
	if copyErr != nil || syncErr != nil || closeErr != nil || written != info.Size() || written > maximum {
		_ = os.Remove(destination)
		return errors.New("durable update file copy failed")
	}
	return os.Chmod(destination, mode)
}

func verifyLiveDatabase(ctx context.Context, path string, expectedSchema int64) error {
	database, err := databasepkg.OpenImmutable(ctx, path)
	if err != nil {
		return err
	}
	defer database.Close()
	if err := databasepkg.QuickCheck(ctx, database); err != nil {
		return err
	}
	if err := databasepkg.IntegrityCheck(ctx, database); err != nil {
		return err
	}
	if err := databasepkg.ForeignKeyCheck(ctx, database); err != nil {
		return err
	}
	schema, err := databasepkg.ReadSchemaVersion(ctx, database)
	if err != nil || schema != expectedSchema {
		return errors.New("live database schema does not match the update journal")
	}
	return nil
}
