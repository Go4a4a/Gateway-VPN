package backup

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"time"

	databasepkg "gateway-vpn/internal/db"
	"gateway-vpn/internal/state"
)

var ErrNoVerifiedSnapshot = errors.New("database recovery has no verified snapshot")

type RecoveryState string

const (
	RecoveryFresh    RecoveryState = "FRESH_DATABASE"
	RecoveryHealthy  RecoveryState = "DATABASE_HEALTHY"
	RecoveryRestored RecoveryState = "DATABASE_RESTORED"
	RecoveryBlocked  RecoveryState = "RECOVERY_BLOCKED"
)

type RecoveryResult struct {
	State          RecoveryState `json:"state"`
	SchemaVersion  int64         `json:"schema_version,omitempty"`
	SnapshotID     string        `json:"snapshot_id,omitempty"`
	QuarantineID   string        `json:"quarantine_id,omitempty"`
	PreMigrationID string        `json:"pre_migration_snapshot_id,omitempty"`
}

type recoveryMarker struct {
	FormatVersion int    `json:"format_version"`
	State         string `json:"state"`
	OccurredAt    string `json:"occurred_at"`
	ErrorCode     string `json:"error_code"`
	QuarantineID  string `json:"quarantine_id,omitempty"`
	SnapshotID    string `json:"snapshot_id,omitempty"`
}

type RecoveryManager struct {
	StateDirectory string
	DatabasePath   string
	Snapshots      *Manager
	Now            func() time.Time
}

func NewRecoveryManager(stateDirectory, databasePath string) (*RecoveryManager, error) {
	snapshots, err := NewManager(nil, stateDirectory, databasePath)
	if err != nil {
		return nil, err
	}
	return &RecoveryManager{StateDirectory: filepath.Clean(stateDirectory), DatabasePath: filepath.Clean(databasePath), Snapshots: snapshots}, nil
}

// Prepare verifies the live database before any writable SQLite connection is
// opened. Corrupt DB/WAL/SHM files are moved to a private quarantine and only a
// fully re-verified snapshot may replace them. A durable marker prevents a
// later startup from mistaking a failed recovery for a fresh installation.
func (manager *RecoveryManager) Prepare(ctx context.Context) (RecoveryResult, error) {
	if manager.Snapshots == nil {
		return RecoveryResult{State: RecoveryBlocked}, errors.New("recovery snapshot manager is required")
	}
	if err := manager.prepareRoot(); err != nil {
		return RecoveryResult{State: RecoveryBlocked}, err
	}
	marker, markerExists, markerErr := manager.readMarker()
	if markerErr != nil {
		return RecoveryResult{State: RecoveryBlocked}, markerErr
	}
	info, statErr := os.Lstat(manager.DatabasePath)
	if errors.Is(statErr, os.ErrNotExist) {
		if markerExists {
			return RecoveryResult{State: RecoveryBlocked, SnapshotID: marker.SnapshotID, QuarantineID: marker.QuarantineID}, ErrNoVerifiedSnapshot
		}
		return RecoveryResult{State: RecoveryFresh}, nil
	}
	if statErr != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		_ = manager.writeMarker(recoveryMarker{FormatVersion: 1, State: string(RecoveryBlocked), OccurredAt: manager.now().Format(time.RFC3339Nano), ErrorCode: "DATABASE_FILE_UNSAFE"})
		return RecoveryResult{State: RecoveryBlocked}, errors.New("live database must be a regular non-symlink file")
	}
	schema, verifyErr := verifyLiveDatabase(ctx, manager.DatabasePath)
	if verifyErr == nil {
		if markerExists {
			if err := manager.recordLast(recoveryMarker{FormatVersion: 1, State: string(RecoveryRestored), OccurredAt: manager.now().Format(time.RFC3339Nano), ErrorCode: "RECOVERY_COMPLETED_AFTER_INTERRUPTION", SnapshotID: marker.SnapshotID, QuarantineID: marker.QuarantineID}); err != nil {
				return RecoveryResult{State: RecoveryBlocked}, err
			}
			if err := manager.clearMarker(); err != nil {
				return RecoveryResult{State: RecoveryBlocked}, err
			}
			return RecoveryResult{State: RecoveryRestored, SchemaVersion: schema, SnapshotID: marker.SnapshotID, QuarantineID: marker.QuarantineID}, nil
		}
		return RecoveryResult{State: RecoveryHealthy, SchemaVersion: schema}, nil
	}

	quarantineID, err := manager.quarantineLiveDatabase("DATABASE_INTEGRITY_FAILED")
	if err != nil {
		return RecoveryResult{State: RecoveryBlocked}, err
	}
	result := RecoveryResult{State: RecoveryBlocked, QuarantineID: quarantineID}
	snapshot, err := manager.Snapshots.LatestValid(ctx)
	if err != nil {
		return result, ErrNoVerifiedSnapshot
	}
	result.SnapshotID = snapshot.Manifest.SnapshotID
	if err := manager.updateMarkerSnapshot(quarantineID, snapshot.Manifest.SnapshotID); err != nil {
		return result, err
	}
	if err := manager.restoreSnapshotFile(ctx, snapshot); err != nil {
		return result, err
	}
	restoredSchema, err := verifyLiveDatabase(ctx, manager.DatabasePath)
	if err != nil {
		return result, fmt.Errorf("verify restored live database: %w", err)
	}
	completed := recoveryMarker{
		FormatVersion: 1, State: string(RecoveryRestored), OccurredAt: manager.now().Format(time.RFC3339Nano),
		ErrorCode: "DATABASE_RECOVERED_FROM_VERIFIED_SNAPSHOT", QuarantineID: quarantineID, SnapshotID: snapshot.Manifest.SnapshotID,
	}
	if err := manager.recordLast(completed); err != nil {
		return result, err
	}
	if err := manager.clearMarker(); err != nil {
		return result, err
	}
	result.State, result.SchemaVersion = RecoveryRestored, restoredSchema
	return result, nil
}

type ManagedDatabase struct {
	Database *sql.DB
	Backups  *Manager
	Recovery RecoveryResult
}

// OpenManaged centralizes the startup order used by both the control plane and
// the privileged broker: read-only recovery, pre-migration snapshot, migration,
// then full verification. Callers must close Database on success.
func OpenManaged(ctx context.Context, stateDirectory, databasePath string) (ManagedDatabase, error) {
	recoveryManager, err := NewRecoveryManager(stateDirectory, databasePath)
	if err != nil {
		return ManagedDatabase{}, err
	}
	recovery, err := recoveryManager.Prepare(ctx)
	if err != nil {
		return ManagedDatabase{Recovery: recovery}, err
	}
	database, err := databasepkg.Open(ctx, databasepkg.OpenOptions{Path: databasePath})
	if err != nil {
		return ManagedDatabase{Recovery: recovery}, err
	}
	fail := func(err error) (ManagedDatabase, error) {
		database.Close()
		return ManagedDatabase{Recovery: recovery}, err
	}
	backups, err := NewManager(database, stateDirectory, databasePath)
	if err != nil {
		return fail(err)
	}
	current, err := databasepkg.ReadSchemaVersion(ctx, database)
	if err != nil {
		return fail(err)
	}
	latest, err := databasepkg.LatestSchemaVersion()
	if err != nil {
		return fail(err)
	}
	if current > latest {
		return fail(databasepkg.ErrSchemaTooNew)
	}
	if current > 0 && current < latest {
		snapshot, err := backups.Create(ctx, KindPreMigration)
		if err != nil {
			return fail(fmt.Errorf("create verified pre-migration snapshot: %w", err))
		}
		recovery.PreMigrationID = snapshot.Manifest.SnapshotID
	}
	if err := databasepkg.Migrate(ctx, database); err != nil {
		return fail(err)
	}
	if err := databasepkg.QuickCheck(ctx, database); err != nil {
		return fail(err)
	}
	if err := databasepkg.IntegrityCheck(ctx, database); err != nil {
		return fail(err)
	}
	if err := databasepkg.ForeignKeyCheck(ctx, database); err != nil {
		return fail(err)
	}
	states := state.NewRepository(database)
	if recovery.State == RecoveryRestored {
		if err := states.AppendEvent(ctx, state.EventInput{Severity: "WARNING", Type: "DATABASE_CORRUPTION_RECOVERED", Details: map[string]any{"snapshot_id": recovery.SnapshotID, "quarantine_id": recovery.QuarantineID}}); err != nil {
			return fail(fmt.Errorf("record database corruption recovery: %w", err))
		}
	}
	if recovery.PreMigrationID != "" {
		if err := states.AppendEvent(ctx, state.EventInput{Severity: "INFO", Type: "DATABASE_PRE_MIGRATION_SNAPSHOT_CREATED", Details: map[string]any{"snapshot_id": recovery.PreMigrationID, "from_schema": current, "to_schema": latest}}); err != nil {
			return fail(fmt.Errorf("record pre-migration snapshot: %w", err))
		}
	}
	return ManagedDatabase{Database: database, Backups: backups, Recovery: recovery}, nil
}

func verifyLiveDatabase(ctx context.Context, filename string) (int64, error) {
	database, err := databasepkg.OpenReadOnly(ctx, filename)
	if err != nil {
		return 0, err
	}
	defer database.Close()
	if err := databasepkg.QuickCheck(ctx, database); err != nil {
		return 0, err
	}
	if err := databasepkg.IntegrityCheck(ctx, database); err != nil {
		return 0, err
	}
	if err := databasepkg.ForeignKeyCheck(ctx, database); err != nil {
		return 0, err
	}
	version, err := databasepkg.ReadSchemaVersion(ctx, database)
	if err != nil || version < 1 {
		return 0, errors.New("live database has no supported schema")
	}
	latest, err := databasepkg.LatestSchemaVersion()
	if err != nil || version > latest {
		return 0, databasepkg.ErrSchemaTooNew
	}
	return version, nil
}

func (manager *RecoveryManager) quarantineLiveDatabase(errorCode string) (string, error) {
	quarantineRoot := filepath.Join(manager.StateDirectory, "recovery", "quarantine")
	if err := secureDirectory(quarantineRoot); err != nil {
		return "", err
	}
	id, err := newSnapshotID(manager.now())
	if err != nil {
		return "", err
	}
	marker := recoveryMarker{FormatVersion: 1, State: string(RecoveryBlocked), OccurredAt: manager.now().Format(time.RFC3339Nano), ErrorCode: errorCode, QuarantineID: id}
	if err := manager.writeMarker(marker); err != nil {
		return "", err
	}
	temporary := filepath.Join(quarantineRoot, ".tmp-"+id)
	final := filepath.Join(quarantineRoot, id)
	if err := os.Mkdir(temporary, 0o700); err != nil {
		return "", fmt.Errorf("create corruption quarantine: %w", err)
	}
	moved := []struct{ from, to string }{}
	rollback := func() {
		for index := len(moved) - 1; index >= 0; index-- {
			_ = os.Rename(moved[index].to, moved[index].from)
		}
		_ = os.Remove(temporary)
	}
	for _, suffix := range []string{"", "-wal", "-shm"} {
		source := manager.DatabasePath + suffix
		info, err := os.Lstat(source)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			rollback()
			return "", errors.New("corrupt database or sidecar is unsafe")
		}
		destination := filepath.Join(temporary, "state.db"+suffix)
		if err := os.Rename(source, destination); err != nil {
			rollback()
			return "", fmt.Errorf("move corrupt database into quarantine: %w", err)
		}
		moved = append(moved, struct{ from, to string }{source, destination})
	}
	if len(moved) == 0 {
		rollback()
		return "", errors.New("no corrupt database files were available to quarantine")
	}
	report := recoveryMarker{FormatVersion: 1, State: "QUARANTINED", OccurredAt: manager.now().Format(time.RFC3339Nano), ErrorCode: errorCode, QuarantineID: id}
	if err := writeJSONFile(filepath.Join(temporary, "report.json"), report, false); err != nil {
		rollback()
		return "", err
	}
	if err := syncDirectory(temporary); err != nil {
		rollback()
		return "", err
	}
	if err := os.Rename(temporary, final); err != nil {
		rollback()
		return "", fmt.Errorf("commit corruption quarantine: %w", err)
	}
	if err := syncDirectory(quarantineRoot); err != nil {
		return "", err
	}
	if err := syncDirectory(filepath.Dir(manager.DatabasePath)); err != nil {
		return "", err
	}
	return id, nil
}

func (manager *RecoveryManager) restoreSnapshotFile(ctx context.Context, snapshot Snapshot) error {
	if err := manager.Snapshots.Verify(ctx, snapshot); err != nil {
		return fmt.Errorf("re-verify recovery snapshot: %w", err)
	}
	temporary, err := os.CreateTemp(filepath.Dir(manager.DatabasePath), ".state.db.restore-")
	if err != nil {
		return fmt.Errorf("create recovery database: %w", err)
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return err
	}
	source, err := os.Open(filepath.Join(snapshot.Path, snapshot.Manifest.Database.Name))
	if err != nil {
		temporary.Close()
		return errors.New("open recovery snapshot failed")
	}
	written, copyErr := io.Copy(temporary, io.LimitReader(source, manager.Snapshots.maximumDatabaseBytes()+1))
	sourceCloseErr := source.Close()
	if copyErr != nil || sourceCloseErr != nil || written != snapshot.Manifest.Database.Bytes || written > manager.Snapshots.maximumDatabaseBytes() {
		temporary.Close()
		return errors.New("copy bounded recovery snapshot failed")
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return errors.New("sync recovered database failed")
	}
	if err := temporary.Close(); err != nil {
		return errors.New("close recovered database failed")
	}
	verification, err := verifyDatabaseFile(ctx, temporaryPath, manager.Snapshots.maximumDatabaseBytes())
	if err != nil || verification.SHA256 != snapshot.Manifest.Database.SHA256 {
		return errors.New("staged recovered database failed verification")
	}
	if err := os.Rename(temporaryPath, manager.DatabasePath); err != nil {
		return fmt.Errorf("activate recovered database: %w", err)
	}
	return syncDirectory(filepath.Dir(manager.DatabasePath))
}

func (manager *RecoveryManager) prepareRoot() error {
	if err := secureDirectory(filepath.Join(manager.StateDirectory, "recovery")); err != nil {
		return err
	}
	return manager.Snapshots.prepareRoot()
}

func (manager *RecoveryManager) markerPath() string {
	return filepath.Join(manager.StateDirectory, "recovery", "blocked.json")
}

func (manager *RecoveryManager) readMarker() (recoveryMarker, bool, error) {
	filename := manager.markerPath()
	info, err := os.Lstat(filename)
	if errors.Is(err, os.ErrNotExist) {
		return recoveryMarker{}, false, nil
	}
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maximumManifestSize {
		return recoveryMarker{}, false, errors.New("database recovery marker is unsafe")
	}
	content, err := os.ReadFile(filename)
	if err != nil {
		return recoveryMarker{}, false, errors.New("read database recovery marker failed")
	}
	var marker recoveryMarker
	if err := decodeStrictJSON(content, &marker); err != nil || marker.FormatVersion != 1 || marker.State == "" || marker.ErrorCode == "" {
		return recoveryMarker{}, false, errors.New("database recovery marker is invalid")
	}
	return marker, true, nil
}

func (manager *RecoveryManager) writeMarker(marker recoveryMarker) error {
	return writeJSONFile(manager.markerPath(), marker, true)
}

func (manager *RecoveryManager) updateMarkerSnapshot(quarantineID, snapshotID string) error {
	return manager.writeMarker(recoveryMarker{FormatVersion: 1, State: string(RecoveryBlocked), OccurredAt: manager.now().Format(time.RFC3339Nano), ErrorCode: "DATABASE_RESTORE_PENDING", QuarantineID: quarantineID, SnapshotID: snapshotID})
}

func (manager *RecoveryManager) recordLast(marker recoveryMarker) error {
	return writeJSONFile(filepath.Join(manager.StateDirectory, "recovery", "last.json"), marker, true)
}

func (manager *RecoveryManager) clearMarker() error {
	err := os.Remove(manager.markerPath())
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("clear database recovery marker: %w", err)
	}
	return syncDirectory(filepath.Dir(manager.markerPath()))
}

func writeJSONFile(filename string, value any, replace bool) error {
	content, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return errors.New("encode recovery record failed")
	}
	content = append(content, '\n')
	if int64(len(content)) > maximumManifestSize {
		return errors.New("recovery record exceeds its bound")
	}
	directory := filepath.Dir(filename)
	if err := secureDirectory(directory); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(directory, ".recovery-record-")
	if err != nil {
		return errors.New("create recovery record failed")
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(content); err != nil {
		temporary.Close()
		return errors.New("write recovery record failed")
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return errors.New("sync recovery record failed")
	}
	if err := temporary.Close(); err != nil {
		return errors.New("close recovery record failed")
	}
	if !replace {
		if _, err := os.Lstat(filename); err == nil {
			return errors.New("recovery record already exists")
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	if err := os.Rename(temporaryName, filename); err != nil {
		if runtime.GOOS != "windows" || !replace {
			return err
		}
		if removeErr := os.Remove(filename); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
			return err
		}
		if err := os.Rename(temporaryName, filename); err != nil {
			return err
		}
	}
	return syncDirectory(directory)
}

func (manager *RecoveryManager) now() time.Time {
	if manager.Now != nil {
		return manager.Now().UTC()
	}
	return time.Now().UTC()
}
