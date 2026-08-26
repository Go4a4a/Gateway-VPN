package backup

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"gateway-vpn/internal/config"
	databasepkg "gateway-vpn/internal/db"
	"gateway-vpn/internal/state"
)

const restoreApplyJournalVersion = 1

const (
	restoreApplyPrepared  = "PREPARED"
	restoreApplyApplying  = "APPLYING"
	restoreApplyCommitted = "COMMITTED"
)

type RestoreApplyResult struct {
	RestoreID          string `json:"restore_id"`
	SnapshotID         string `json:"snapshot_id"`
	PreRestoreSnapshot string `json:"pre_restore_snapshot_id"`
	SchemaVersion      int64  `json:"schema_version"`
	SessionsRevoked    int64  `json:"sessions_revoked"`
	AppliedAt          string `json:"applied_at"`
	ReconcileRequired  bool   `json:"reconcile_required"`
}

type restoreSwapItem struct {
	Name           string `json:"name"`
	Kind           string `json:"kind"`
	Destination    string `json:"destination"`
	Candidate      string `json:"candidate,omitempty"`
	Rollback       string `json:"rollback"`
	OriginalExists bool   `json:"original_exists"`
}

type restoreApplyJournal struct {
	FormatVersion int                `json:"format_version"`
	RestoreID     string             `json:"restore_id"`
	State         string             `json:"state"`
	AppliedItems  int                `json:"applied_items"`
	Items         []restoreSwapItem  `json:"items"`
	Result        RestoreApplyResult `json:"result"`
}

type RestoreApplier struct {
	Manager         *RestoreManager
	TransactionRoot string
	OwnerUID        int
	OwnerGID        int
	Now             func() time.Time
	AfterActivate   func(int) error
	setOwnership    func(string, int, int) error
	validateOwner   func(os.FileInfo) error
}

func NewRestoreApplier(manager *RestoreManager, transactionRoot string, ownerUID, ownerGID int) (*RestoreApplier, error) {
	if manager == nil || !filepath.IsAbs(transactionRoot) || ownerUID < -1 || ownerGID < -1 {
		return nil, errors.New("restore applier requires a manager, absolute root, and valid ownership")
	}
	return &RestoreApplier{
		Manager: manager, TransactionRoot: filepath.Clean(transactionRoot), OwnerUID: ownerUID, OwnerGID: ownerGID,
		setOwnership: applyOwnership, validateOwner: validateRestoreTransactionOwnership,
	}, nil
}

// Apply performs a fail-closed, durable, all-or-rollback restore. The caller
// must run it only after the control plane, broker, dnsmasq, and Mihomo are
// stopped and the boot PATH_BLOCKED ruleset has been loaded.
func (applier *RestoreApplier) Apply(ctx context.Context) (RestoreApplyResult, error) {
	if err := applier.validate(); err != nil {
		return RestoreApplyResult{}, err
	}
	verified, err := applier.Manager.VerifyPending(ctx)
	if err != nil {
		return RestoreApplyResult{}, err
	}
	items := applier.restoreItems(verified)
	journalPath := applier.journalPath(verified.Operation.RestoreID)
	if _, err := os.Lstat(journalPath); err == nil {
		return applier.resumeInterrupted(ctx, verified, items, journalPath)
	} else if !errors.Is(err, os.ErrNotExist) {
		return RestoreApplyResult{}, errors.New("inspect restore transaction journal failed")
	}

	preRestore, err := applier.createPreRestoreSnapshot(ctx, verified.Operation.RestoreID)
	if err != nil {
		_ = applier.Manager.markApplyFailure(verified.Operation.RestoreID, "PRE_RESTORE_SNAPSHOT_FAILED")
		return RestoreApplyResult{}, err
	}
	result := RestoreApplyResult{
		RestoreID: verified.Operation.RestoreID, SnapshotID: verified.Operation.SnapshotID,
		PreRestoreSnapshot: preRestore.Manifest.SnapshotID, ReconcileRequired: true,
	}
	if err := applier.prepareCandidates(ctx, verified, items, &result); err != nil {
		_ = applier.cleanupCandidates(items)
		_ = applier.Manager.markApplyFailure(verified.Operation.RestoreID, "RESTORE_CANDIDATE_PREPARATION_FAILED")
		return RestoreApplyResult{}, err
	}
	journal := restoreApplyJournal{FormatVersion: restoreApplyJournalVersion, RestoreID: verified.Operation.RestoreID, State: restoreApplyPrepared, Items: items, Result: result}
	if err := applier.writeJournal(journalPath, journal, false); err != nil {
		_ = applier.cleanupCandidates(items)
		_ = applier.Manager.markApplyFailure(verified.Operation.RestoreID, "RESTORE_JOURNAL_CREATE_FAILED")
		return RestoreApplyResult{}, err
	}
	journal.State = restoreApplyApplying
	if err := applier.writeJournal(journalPath, journal, true); err != nil {
		return applier.rollbackFailure(verified.Operation.RestoreID, items, journalPath, err)
	}
	for index := range journal.Items {
		if err := applier.activateItem(journal.Items[index]); err != nil {
			return applier.rollbackFailure(verified.Operation.RestoreID, items, journalPath, err)
		}
		journal.AppliedItems = index + 1
		if err := applier.writeJournal(journalPath, journal, true); err != nil {
			return applier.rollbackFailure(verified.Operation.RestoreID, items, journalPath, err)
		}
		if applier.AfterActivate != nil {
			if err := applier.AfterActivate(index); err != nil {
				return applier.rollbackFailure(verified.Operation.RestoreID, items, journalPath, err)
			}
		}
	}
	if err := applier.verifyActivated(ctx, verified, result); err != nil {
		return applier.rollbackFailure(verified.Operation.RestoreID, items, journalPath, err)
	}
	result.AppliedAt = applier.now().Format(time.RFC3339Nano)
	journal.State = restoreApplyCommitted
	journal.Result = result
	if err := applier.writeJournal(journalPath, journal, true); err != nil {
		return applier.rollbackFailure(verified.Operation.RestoreID, items, journalPath, err)
	}
	return applier.finalizeCommitted(items, journalPath, result)
}

func (applier *RestoreApplier) resumeInterrupted(ctx context.Context, verified VerifiedRestore, items []restoreSwapItem, journalPath string) (RestoreApplyResult, error) {
	journal, err := applier.readJournal(journalPath)
	recoveryItems := items
	if err == nil {
		if validationErr := validateApplyJournal(journal, verified.Operation.RestoreID, items); validationErr != nil {
			err = validationErr
		} else {
			recoveryItems = journal.Items
		}
	}
	if err == nil && journal.State == restoreApplyCommitted {
		if verifyErr := applier.verifyActivated(ctx, verified, journal.Result); verifyErr != nil {
			return applier.rollbackFailure(verified.Operation.RestoreID, recoveryItems, journalPath, verifyErr)
		}
		return applier.finalizeCommitted(recoveryItems, journalPath, journal.Result)
	}
	if rollbackErr := applier.rollbackItems(recoveryItems); rollbackErr != nil {
		_ = applier.Manager.markApplyFailure(verified.Operation.RestoreID, "RESTORE_INTERRUPTED_ROLLBACK_FAILED")
		return RestoreApplyResult{}, errors.Join(errors.New("interrupted restore transaction is unsafe"), err, rollbackErr)
	}
	if removeErr := applier.removeJournal(journalPath); removeErr != nil {
		return RestoreApplyResult{}, removeErr
	}
	_ = applier.Manager.markApplyFailure(verified.Operation.RestoreID, "RESTORE_INTERRUPTED_ROLLED_BACK")
	return RestoreApplyResult{}, errors.New("interrupted restore transaction was rolled back; explicit retry is required")
}

func (applier *RestoreApplier) createPreRestoreSnapshot(ctx context.Context, restoreID string) (Snapshot, error) {
	database, err := databasepkg.Open(ctx, databasepkg.OpenOptions{Path: applier.Manager.DatabasePath})
	if err != nil {
		return Snapshot{}, fmt.Errorf("open live database for pre-restore snapshot: %w", err)
	}
	defer database.Close()
	repository := state.NewRepository(database)
	if _, _, err := repository.Block(ctx, state.GatewayBlocked, "VERIFIED_RESTORE_APPLYING"); err != nil {
		return Snapshot{}, fmt.Errorf("durably block current runtime before restore: %w", err)
	}
	if err := repository.AppendEvent(ctx, state.EventInput{Severity: "WARNING", Type: "RESTORE_ROOT_APPLY_STARTED", Details: map[string]any{"restore_id": restoreID}}); err != nil {
		return Snapshot{}, err
	}
	if err := databasepkg.QuickCheck(ctx, database); err != nil {
		return Snapshot{}, err
	}
	if err := databasepkg.IntegrityCheck(ctx, database); err != nil {
		return Snapshot{}, err
	}
	if err := databasepkg.ForeignKeyCheck(ctx, database); err != nil {
		return Snapshot{}, err
	}
	snapshots, err := NewManager(database, applier.Manager.StateDirectory, applier.Manager.DatabasePath)
	if err != nil {
		return Snapshot{}, err
	}
	snapshot, err := snapshots.Create(ctx, KindPreRestore)
	if err != nil {
		return Snapshot{}, err
	}
	if err := applyPrivateTreeMetadata(snapshot.Path, 0o700, 0o600, applier.OwnerUID, applier.OwnerGID, applier.setOwnership); err != nil {
		return Snapshot{}, err
	}
	return snapshot, nil
}

func (applier *RestoreApplier) prepareCandidates(ctx context.Context, verified VerifiedRestore, items []restoreSwapItem, result *RestoreApplyResult) error {
	if err := applier.cleanupCandidates(items); err != nil {
		return err
	}
	for index := range items {
		item := &items[index]
		exists, err := validateRestoreDestination(item.Destination, item.Kind)
		if err != nil {
			return err
		}
		item.OriginalExists = exists
	}
	if err := copyPrivateFile(ctx, filepath.Join(verified.TreeRoot, "config", "config.yaml"), items[0].Candidate, 0o640, 0, applier.OwnerGID, applier.setOwnership); err != nil {
		return err
	}
	restoredConfiguration, err := config.Load(items[0].Candidate)
	if err != nil || applier.Manager.validateRestoredConfig(restoredConfiguration) != nil {
		return errors.New("prepared restore configuration failed fixed-path validation")
	}
	// Keep the mutable database candidate root-owned until migration and final
	// verification are complete. The hardened restore unit intentionally lacks
	// CAP_FOWNER; ownership is transferred only after the last chmod.
	if err := copyPrivateFile(ctx, filepath.Join(verified.TreeRoot, "database", "state.db"), items[1].Candidate, 0o600, 0, 0, applier.setOwnership); err != nil {
		return err
	}
	schemaVersion, sessionsRevoked, err := applier.prepareDatabase(ctx, items[1].Candidate, verified.Operation, result.PreRestoreSnapshot)
	if err != nil {
		return err
	}
	result.SchemaVersion, result.SessionsRevoked = schemaVersion, sessionsRevoked
	directories := []struct {
		index    int
		source   string
		dirMode  os.FileMode
		fileMode os.FileMode
	}{
		{2, "state/secrets", 0o700, 0o600},
		{3, "state/subscriptions", 0o700, 0o600},
		{4, "state/tls", 0o700, 0o600},
		{5, "state/mihomo/generations", 0o750, 0o640},
		{6, "state/mihomo/state", 0o700, 0o600},
	}
	for _, directory := range directories {
		if err := copyPrivateTree(ctx, filepath.Join(verified.TreeRoot, filepath.FromSlash(directory.source)), items[directory.index].Candidate, directory.dirMode, directory.fileMode, applier.OwnerUID, applier.OwnerGID, applier.setOwnership); err != nil {
			return err
		}
	}
	return nil
}

func (applier *RestoreApplier) prepareDatabase(ctx context.Context, filename string, operation RestoreOperation, preRestoreSnapshot string) (int64, int64, error) {
	database, err := databasepkg.Open(ctx, databasepkg.OpenOptions{Path: filename})
	if err != nil {
		return 0, 0, err
	}
	closeWithError := func(current error) (int64, int64, error) {
		return 0, 0, errors.Join(current, database.Close())
	}
	if err := databasepkg.Migrate(ctx, database); err != nil {
		return closeWithError(fmt.Errorf("migrate restored database: %w", err))
	}
	now := applier.now().Format(time.RFC3339Nano)
	result, err := database.ExecContext(ctx, "UPDATE sessions SET revoked_at=? WHERE revoked_at IS NULL", now)
	if err != nil {
		return closeWithError(fmt.Errorf("revoke restored sessions: %w", err))
	}
	sessionsRevoked, err := result.RowsAffected()
	if err != nil {
		return closeWithError(err)
	}
	if _, err := database.ExecContext(ctx, "DELETE FROM login_attempts"); err != nil {
		return closeWithError(fmt.Errorf("clear restored login attempts: %w", err))
	}
	repository := state.NewRepository(database)
	if _, _, err := repository.Block(ctx, state.GatewayBlocked, "RESTORE_RECONCILIATION_REQUIRED"); err != nil {
		return closeWithError(err)
	}
	if err := repository.AppendEvent(ctx, state.EventInput{Severity: "WARNING", Type: "RESTORE_APPLIED", Details: map[string]any{"restore_id": operation.RestoreID, "snapshot_id": operation.SnapshotID, "pre_restore_snapshot_id": preRestoreSnapshot, "sessions_revoked": sessionsRevoked, "reconciliation_required": true}}); err != nil {
		return closeWithError(err)
	}
	if _, err := database.ExecContext(ctx, "PRAGMA wal_checkpoint(TRUNCATE)"); err != nil {
		return closeWithError(err)
	}
	if err := databasepkg.QuickCheck(ctx, database); err != nil {
		return closeWithError(err)
	}
	if err := databasepkg.IntegrityCheck(ctx, database); err != nil {
		return closeWithError(err)
	}
	if err := databasepkg.ForeignKeyCheck(ctx, database); err != nil {
		return closeWithError(err)
	}
	schemaVersion, err := databasepkg.ReadSchemaVersion(ctx, database)
	if err != nil {
		return closeWithError(err)
	}
	latest, err := databasepkg.LatestSchemaVersion()
	if err != nil || schemaVersion != latest {
		return closeWithError(errors.New("restored database migration did not reach the binary schema"))
	}
	if err := database.Close(); err != nil {
		return 0, 0, err
	}
	if err := removeSQLiteSidecars(filename); err != nil {
		return 0, 0, err
	}
	verification, err := verifyDatabaseFile(ctx, filename, DefaultMaximumDatabaseSize)
	if err != nil || verification.SchemaVersion != schemaVersion {
		return 0, 0, errors.New("prepared restored database failed standalone verification")
	}
	if err := os.Chmod(filename, 0o600); err != nil {
		return 0, 0, err
	}
	if err := applier.setOwnership(filename, applier.OwnerUID, applier.OwnerGID); err != nil {
		return 0, 0, err
	}
	return schemaVersion, sessionsRevoked, nil
}

func (applier *RestoreApplier) activateItem(item restoreSwapItem) error {
	if _, err := os.Lstat(item.Rollback); err == nil {
		return errors.New("restore rollback destination already exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if item.OriginalExists {
		if _, err := os.Lstat(item.Destination); err != nil {
			return errors.New("restore destination disappeared before activation")
		}
		if err := os.Rename(item.Destination, item.Rollback); err != nil {
			return fmt.Errorf("quarantine previous restore destination %s: %w", item.Name, err)
		}
		if err := syncDirectory(filepath.Dir(item.Destination)); err != nil {
			return err
		}
	}
	if item.Candidate != "" {
		if err := os.Rename(item.Candidate, item.Destination); err != nil {
			return fmt.Errorf("activate restored %s: %w", item.Name, err)
		}
		if err := syncDirectory(filepath.Dir(item.Destination)); err != nil {
			return err
		}
	}
	return nil
}

func (applier *RestoreApplier) verifyActivated(ctx context.Context, verified VerifiedRestore, result RestoreApplyResult) error {
	restored, err := config.Load(applier.Manager.ConfigurationPath)
	if err != nil || applier.Manager.validateRestoredConfig(restored) != nil {
		return errors.New("activated restore configuration failed verification")
	}
	database, err := databasepkg.Open(ctx, databasepkg.OpenOptions{Path: applier.Manager.DatabasePath})
	if err != nil {
		return err
	}
	var unrevoked, audit int
	if err := database.QueryRowContext(ctx, "SELECT COUNT(*) FROM sessions WHERE revoked_at IS NULL").Scan(&unrevoked); err != nil {
		database.Close()
		return err
	}
	if err := database.QueryRowContext(ctx, "SELECT COUNT(*) FROM events WHERE type='RESTORE_APPLIED' AND details_json LIKE ?", "%"+verified.Operation.RestoreID+"%").Scan(&audit); err != nil {
		database.Close()
		return err
	}
	runtimeState, err := state.NewRepository(database).Get(ctx)
	if err != nil || runtimeState.GatewayState != state.GatewayBlocked || runtimeState.PathState != state.PathBlocked || runtimeState.ActiveModemID != "" || runtimeState.ActivePathID != "" || runtimeState.ActiveSubscriptionID != "" || runtimeState.ActiveNodeID != "" || unrevoked != 0 || audit != 1 {
		database.Close()
		return errors.New("activated restored database is not fail-closed or session-revoked")
	}
	if err := databasepkg.QuickCheck(ctx, database); err != nil {
		database.Close()
		return err
	}
	if err := databasepkg.IntegrityCheck(ctx, database); err != nil {
		database.Close()
		return err
	}
	if err := databasepkg.ForeignKeyCheck(ctx, database); err != nil {
		database.Close()
		return err
	}
	if _, err := database.ExecContext(ctx, "PRAGMA wal_checkpoint(TRUNCATE)"); err != nil {
		database.Close()
		return err
	}
	if err := database.Close(); err != nil {
		return err
	}
	if err := removeSQLiteSidecars(applier.Manager.DatabasePath); err != nil {
		return err
	}
	verification, err := verifyDatabaseFile(ctx, applier.Manager.DatabasePath, DefaultMaximumDatabaseSize)
	if err != nil || verification.SchemaVersion != result.SchemaVersion {
		return errors.New("activated restored database failed final standalone verification")
	}
	if _, err := os.Lstat(filepath.Join(applier.Manager.StateDirectory, "mihomo", "active")); !errors.Is(err, os.ErrNotExist) {
		return errors.New("stale Mihomo active generation remained after restore")
	}
	return nil
}

func (applier *RestoreApplier) rollbackFailure(restoreID string, items []restoreSwapItem, journalPath string, cause error) (RestoreApplyResult, error) {
	rollbackErr := applier.rollbackItems(items)
	if rollbackErr != nil {
		_ = applier.Manager.markApplyFailure(restoreID, "RESTORE_ROLLBACK_FAILED")
		return RestoreApplyResult{}, errors.Join(cause, rollbackErr)
	}
	removeErr := applier.removeJournal(journalPath)
	markErr := applier.Manager.markApplyFailure(restoreID, "RESTORE_APPLY_FAILED_ROLLED_BACK")
	return RestoreApplyResult{}, errors.Join(cause, removeErr, markErr)
}

func (applier *RestoreApplier) rollbackItems(items []restoreSwapItem) error {
	var failures []error
	for index := len(items) - 1; index >= 0; index-- {
		item := items[index]
		rollbackExists := managedRestorePathExists(item.Rollback)
		candidateExists := item.Candidate != "" && managedRestorePathExists(item.Candidate)
		if rollbackExists {
			if err := removeManagedRestorePath(item.Destination); err != nil {
				failures = append(failures, err)
				continue
			}
			if err := os.Rename(item.Rollback, item.Destination); err != nil {
				failures = append(failures, err)
				continue
			}
		} else if item.Candidate != "" && !candidateExists {
			// The candidate was consumed without a rollback path, so the
			// destination was originally absent and must be removed.
			if err := removeManagedRestorePath(item.Destination); err != nil {
				failures = append(failures, err)
			}
		} else if item.Candidate == "" && !item.OriginalExists {
			// Delete-only destinations that were originally absent may have
			// been recreated by final SQLite verification. Remove them so the
			// rolled-back filesystem exactly matches the pre-restore state.
			if err := removeManagedRestorePath(item.Destination); err != nil {
				failures = append(failures, err)
			}
		}
		if candidateExists {
			if err := removeManagedRestorePath(item.Candidate); err != nil {
				failures = append(failures, err)
			}
		}
		if err := syncDirectory(filepath.Dir(item.Destination)); err != nil {
			failures = append(failures, err)
		}
	}
	return errors.Join(failures...)
}

func (applier *RestoreApplier) finalizeCommitted(items []restoreSwapItem, journalPath string, result RestoreApplyResult) (RestoreApplyResult, error) {
	for _, item := range items {
		if err := removeManagedRestorePath(item.Rollback); err != nil {
			return RestoreApplyResult{}, err
		}
		if item.Candidate != "" {
			if err := removeManagedRestorePath(item.Candidate); err != nil {
				return RestoreApplyResult{}, err
			}
		}
	}
	if err := applier.Manager.complete(result.RestoreID, result.AppliedAt); err != nil {
		return RestoreApplyResult{}, err
	}
	if err := applier.removeJournal(journalPath); err != nil {
		return RestoreApplyResult{}, err
	}
	return result, nil
}

func (applier *RestoreApplier) cleanupCandidates(items []restoreSwapItem) error {
	var failures []error
	for _, item := range items {
		if item.Candidate != "" {
			failures = append(failures, removeManagedRestorePath(item.Candidate))
		}
		failures = append(failures, removeManagedRestorePath(item.Rollback))
	}
	return errors.Join(failures...)
}

func (applier *RestoreApplier) restoreItems(verified VerifiedRestore) []restoreSwapItem {
	id := verified.Operation.RestoreID
	item := func(name, kind, destination string, install bool) restoreSwapItem {
		base := ".gateway-vpn-" + id + "-" + name
		parent := filepath.Dir(destination)
		candidate := ""
		if install {
			candidate = filepath.Join(parent, base+".candidate")
		}
		return restoreSwapItem{Name: name, Kind: kind, Destination: destination, Candidate: candidate, Rollback: filepath.Join(parent, base+".rollback")}
	}
	stateDirectory := applier.Manager.StateDirectory
	return []restoreSwapItem{
		item("config", "file", applier.Manager.ConfigurationPath, true),
		item("database", "file", applier.Manager.DatabasePath, true),
		item("secrets", "directory", filepath.Join(stateDirectory, "secrets"), true),
		item("subscriptions", "directory", filepath.Join(stateDirectory, "subscriptions"), true),
		item("tls", "directory", filepath.Join(stateDirectory, "tls"), true),
		item("mihomo-generations", "directory", filepath.Join(stateDirectory, "mihomo", "generations"), true),
		item("mihomo-state", "directory", filepath.Join(stateDirectory, "mihomo", "state"), true),
		item("mihomo-active", "active", filepath.Join(stateDirectory, "mihomo", "active"), false),
		item("database-wal", "remove", applier.Manager.DatabasePath+"-wal", false),
		item("database-shm", "remove", applier.Manager.DatabasePath+"-shm", false),
	}
}

func (applier *RestoreApplier) validate() error {
	if applier == nil || applier.Manager == nil || !filepath.IsAbs(applier.TransactionRoot) || applier.setOwnership == nil || applier.validateOwner == nil {
		return errors.New("restore applier is not initialized")
	}
	if err := secureRootTransactionDirectory(applier.TransactionRoot, applier.validateOwner); err != nil {
		return err
	}
	for _, directory := range []string{filepath.Dir(applier.Manager.ConfigurationPath), applier.Manager.StateDirectory, filepath.Join(applier.Manager.StateDirectory, "mihomo")} {
		if err := validateRealDirectory(directory); err != nil {
			return err
		}
	}
	return nil
}

func (applier *RestoreApplier) journalPath(restoreID string) string {
	return filepath.Join(applier.TransactionRoot, restoreID+".json")
}

func (applier *RestoreApplier) writeJournal(filename string, journal restoreApplyJournal, replace bool) error {
	if err := validateApplyJournal(journal, journal.RestoreID, journal.Items); err != nil {
		return err
	}
	return writeJSONFile(filename, journal, replace)
}

func (applier *RestoreApplier) readJournal(filename string) (restoreApplyJournal, error) {
	info, err := os.Lstat(filename)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maximumManifestSize {
		return restoreApplyJournal{}, errors.New("restore transaction journal is unsafe")
	}
	content, err := os.ReadFile(filename)
	if err != nil {
		return restoreApplyJournal{}, err
	}
	var journal restoreApplyJournal
	if err := decodeStrictJSON(content, &journal); err != nil {
		return restoreApplyJournal{}, err
	}
	return journal, nil
}

func (applier *RestoreApplier) removeJournal(filename string) error {
	if filepath.Dir(filename) != applier.TransactionRoot || !restoreIDPattern.MatchString(strings.TrimSuffix(filepath.Base(filename), ".json")) {
		return errors.New("refuse to remove unmanaged restore transaction journal")
	}
	if err := os.Remove(filename); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return syncDirectory(applier.TransactionRoot)
}

func validateApplyJournal(journal restoreApplyJournal, restoreID string, expected []restoreSwapItem) error {
	if journal.FormatVersion != restoreApplyJournalVersion || journal.RestoreID != restoreID || !restoreIDPattern.MatchString(restoreID) || journal.AppliedItems < 0 || journal.AppliedItems > len(expected) || len(journal.Items) != len(expected) {
		return errors.New("restore transaction journal contract is invalid")
	}
	switch journal.State {
	case restoreApplyPrepared, restoreApplyApplying, restoreApplyCommitted:
	default:
		return errors.New("restore transaction journal state is invalid")
	}
	for index := range expected {
		actual, wanted := journal.Items[index], expected[index]
		if actual.Name != wanted.Name || actual.Kind != wanted.Kind || actual.Destination != wanted.Destination || actual.Candidate != wanted.Candidate || actual.Rollback != wanted.Rollback {
			return errors.New("restore transaction journal contains an unexpected path")
		}
	}
	if journal.State == restoreApplyCommitted {
		if journal.Result.RestoreID != restoreID || journal.Result.AppliedAt == "" || !journal.Result.ReconcileRequired {
			return errors.New("committed restore journal result is invalid")
		}
		if _, err := time.Parse(time.RFC3339Nano, journal.Result.AppliedAt); err != nil {
			return errors.New("committed restore journal timestamp is invalid")
		}
	}
	return nil
}

func validateRestoreDestination(filename, kind string) (bool, error) {
	if !filepath.IsAbs(filename) {
		return false, errors.New("restore destination must be absolute")
	}
	if err := validateRealDirectory(filepath.Dir(filename)); err != nil {
		return false, err
	}
	info, err := os.Lstat(filename)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, errors.New("restore destination is unsafe")
	}
	switch kind {
	case "file":
		if !info.Mode().IsRegular() {
			return false, errors.New("restore file destination has the wrong type")
		}
	case "directory":
		if !info.IsDir() {
			return false, errors.New("restore directory destination has the wrong type")
		}
	case "remove":
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() && !info.IsDir() {
			return false, errors.New("restore removal destination has an unsafe type")
		}
	case "active":
		if info.Mode()&os.ModeSymlink == 0 && !info.Mode().IsRegular() && !info.IsDir() {
			return false, errors.New("Mihomo active destination has an unsafe type")
		}
	default:
		return false, errors.New("restore destination kind is invalid")
	}
	return true, nil
}

func copyPrivateFile(ctx context.Context, source, destination string, mode os.FileMode, uid, gid int, setOwnership func(string, int, int) error) error {
	info, err := os.Lstat(source)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() < 0 || info.Size() > MaximumPortablePlainBytes {
		return errors.New("restore file source is unsafe")
	}
	if _, err := os.Lstat(destination); err == nil {
		return errors.New("restore candidate already exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	input, err := openStableRegularFile(source, info.Size())
	if err != nil {
		return err
	}
	defer input.Close()
	output, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	written, copyErr := copyWithContext(ctx, output, io.LimitReader(input, info.Size()+1))
	syncErr := output.Sync()
	closeErr := output.Close()
	if copyErr != nil || syncErr != nil || closeErr != nil || written != info.Size() {
		return errors.Join(errors.New("copy restore candidate failed"), copyErr, syncErr, closeErr)
	}
	if err := os.Chmod(destination, mode); err != nil {
		return err
	}
	if err := setOwnership(destination, uid, gid); err != nil {
		return err
	}
	return syncDirectory(filepath.Dir(destination))
}

func copyPrivateTree(ctx context.Context, source, destination string, directoryMode, fileMode os.FileMode, uid, gid int, setOwnership func(string, int, int) error) error {
	info, err := os.Lstat(source)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return errors.New("restore tree source is unsafe")
	}
	if err := os.Mkdir(destination, directoryMode); err != nil {
		return err
	}
	var files int
	var bytesCopied int64
	err = filepath.WalkDir(source, func(current string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if current == source {
			return nil
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		entryInfo, err := os.Lstat(current)
		if err != nil || entryInfo.Mode()&os.ModeSymlink != 0 {
			return errors.New("restore source tree contains an unsafe entry")
		}
		relative, err := filepath.Rel(source, current)
		if err != nil {
			return err
		}
		target := filepath.Join(destination, relative)
		if entryInfo.IsDir() {
			return os.Mkdir(target, directoryMode)
		}
		if !entryInfo.Mode().IsRegular() || entryInfo.Size() < 0 || files >= MaximumPortableFiles || bytesCopied > MaximumPortablePlainBytes-entryInfo.Size() {
			return errors.New("restore source tree exceeds its safety bounds")
		}
		files++
		bytesCopied += entryInfo.Size()
		return copyPrivateFile(ctx, current, target, fileMode, uid, gid, setOwnership)
	})
	if err != nil {
		return err
	}
	return applyPrivateTreeMetadata(destination, directoryMode, fileMode, uid, gid, setOwnership)
}

func applyPrivateTreeMetadata(root string, directoryMode, fileMode os.FileMode, uid, gid int, setOwnership func(string, int, int) error) error {
	paths := []string{}
	if err := filepath.WalkDir(root, func(current string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		info, err := os.Lstat(current)
		if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() && !info.Mode().IsRegular() {
			return errors.New("private restore tree contains an unsafe entry")
		}
		mode := fileMode
		if info.IsDir() {
			mode = directoryMode
		}
		if err := os.Chmod(current, mode); err != nil {
			return err
		}
		if err := setOwnership(current, uid, gid); err != nil {
			return err
		}
		paths = append(paths, current)
		return nil
	}); err != nil {
		return err
	}
	sort.Slice(paths, func(i, j int) bool { return len(paths[i]) > len(paths[j]) })
	for _, current := range paths {
		if info, err := os.Lstat(current); err == nil && info.IsDir() {
			if err := syncDirectory(current); err != nil {
				return err
			}
		}
	}
	return nil
}

func applyOwnership(filename string, uid, gid int) error {
	if runtime.GOOS == "windows" || uid < 0 && gid < 0 {
		return nil
	}
	if err := os.Chown(filename, uid, gid); err != nil {
		return fmt.Errorf("set restore ownership: %w", err)
	}
	return nil
}

func removeManagedRestorePath(filename string) error {
	info, err := os.Lstat(filename)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || info.Mode()&os.ModeSymlink == 0 && !info.IsDir() && !info.Mode().IsRegular() {
		return errors.New("managed restore path is unsafe")
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return os.Remove(filename)
	}
	if info.Mode().IsRegular() {
		return os.Remove(filename)
	}
	paths := []string{}
	err = filepath.WalkDir(filename, func(current string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		entryInfo, err := os.Lstat(current)
		if err != nil || entryInfo.Mode()&os.ModeSymlink != 0 || !entryInfo.IsDir() && !entryInfo.Mode().IsRegular() {
			return errors.New("managed restore tree contains an unsafe entry")
		}
		paths = append(paths, current)
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
	return nil
}

func managedRestorePathExists(filename string) bool {
	info, err := os.Lstat(filename)
	return err == nil && (info.Mode()&os.ModeSymlink != 0 || info.IsDir() || info.Mode().IsRegular())
}

func validateRealDirectory(directory string) error {
	info, err := os.Lstat(directory)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("restore parent directory %s is unsafe", directory)
	}
	return nil
}

func secureRootTransactionDirectory(directory string, validateOwnership func(os.FileInfo) error) error {
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return err
	}
	info, err := os.Lstat(directory)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return errors.New("restore transaction root is unsafe")
	}
	if err := validateOwnership(info); err != nil {
		return err
	}
	return os.Chmod(directory, 0o700)
}

func (applier *RestoreApplier) now() time.Time {
	if applier.Now != nil {
		return applier.Now().UTC()
	}
	return time.Now().UTC()
}
