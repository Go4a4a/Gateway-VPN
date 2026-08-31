package backup

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	databasepkg "gateway-vpn/internal/db"
	"gateway-vpn/migrations"
)

func TestCorruptMainDatabaseIsQuarantinedAndLatestValidSnapshotRestored(t *testing.T) {
	ctx, database, snapshots := snapshotTestManager(t)
	stateDirectory := filepath.Dir(snapshots.DatabasePath)
	if _, err := database.ExecContext(ctx, `INSERT INTO events(occurred_at,severity,type,details_json) VALUES('2026-08-24T12:00:00Z','INFO','FIRST_SNAPSHOT','{}')`); err != nil {
		t.Fatal(err)
	}
	first, err := snapshots.Create(ctx, KindDaily)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(ctx, `INSERT INTO events(occurred_at,severity,type,details_json) VALUES('2026-08-24T12:01:00Z','INFO','SECOND_SNAPSHOT','{}')`); err != nil {
		t.Fatal(err)
	}
	second, err := snapshots.Create(ctx, KindManual)
	if err != nil {
		t.Fatal(err)
	}
	secondFile, err := os.OpenFile(filepath.Join(second.Path, "state.db"), os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := secondFile.WriteAt([]byte("tampered"), 256); err != nil {
		secondFile.Close()
		t.Fatal(err)
	}
	secondFile.Close()
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
	corrupt := bytes.Repeat([]byte{0xa5}, 8192)
	if err := os.WriteFile(snapshots.DatabasePath, corrupt, 0o600); err != nil {
		t.Fatal(err)
	}
	recovery, err := NewRecoveryManager(stateDirectory, snapshots.DatabasePath)
	if err != nil {
		t.Fatal(err)
	}
	recovery.Now = func() time.Time { return time.Date(2026, 8, 24, 12, 30, 0, 0, time.UTC) }
	result, err := recovery.Prepare(ctx)
	if err != nil {
		t.Fatalf("Prepare() error = %v", err)
	}
	if result.State != RecoveryRestored || result.SnapshotID != first.Manifest.SnapshotID || result.QuarantineID == "" || result.SchemaVersion != 31 {
		t.Fatalf("recovery result = %+v", result)
	}
	preserved, err := os.ReadFile(filepath.Join(stateDirectory, "recovery", "quarantine", result.QuarantineID, "state.db"))
	if err != nil || !bytes.Equal(preserved, corrupt) {
		t.Fatalf("quarantined database mismatch: %d, %v", len(preserved), err)
	}
	restored, err := databasepkg.OpenReadOnly(ctx, snapshots.DatabasePath)
	if err != nil {
		t.Fatal(err)
	}
	defer restored.Close()
	var firstCount, secondCount int
	if err := restored.QueryRowContext(ctx, "SELECT COUNT(*) FROM events WHERE type='FIRST_SNAPSHOT'").Scan(&firstCount); err != nil {
		t.Fatal(err)
	}
	if err := restored.QueryRowContext(ctx, "SELECT COUNT(*) FROM events WHERE type='SECOND_SNAPSHOT'").Scan(&secondCount); err != nil {
		t.Fatal(err)
	}
	if firstCount != 1 || secondCount != 0 {
		t.Fatalf("restored event counts = first:%d second:%d", firstCount, secondCount)
	}
	if _, err := os.Stat(filepath.Join(stateDirectory, "recovery", "blocked.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("recovery marker remains after success: %v", err)
	}
}

func TestCorruptionWithoutVerifiedSnapshotStaysBlockedAcrossStarts(t *testing.T) {
	ctx := context.Background()
	stateDirectory := t.TempDir()
	databasePath := filepath.Join(stateDirectory, "state.db")
	database, err := databasepkg.Open(ctx, databasepkg.OpenOptions{Path: databasePath})
	if err != nil {
		t.Fatal(err)
	}
	if err := databasepkg.Migrate(ctx, database); err != nil {
		database.Close()
		t.Fatal(err)
	}
	database.Close()
	corrupt := bytes.Repeat([]byte{0x7f}, 4096)
	if err := os.WriteFile(databasePath, corrupt, 0o600); err != nil {
		t.Fatal(err)
	}
	recovery, err := NewRecoveryManager(stateDirectory, databasePath)
	if err != nil {
		t.Fatal(err)
	}
	result, err := recovery.Prepare(ctx)
	if !errors.Is(err, ErrNoVerifiedSnapshot) || result.State != RecoveryBlocked || result.QuarantineID == "" {
		t.Fatalf("first Prepare() = %+v, %v", result, err)
	}
	if _, err := os.Stat(databasePath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("corrupt database was left active or replaced: %v", err)
	}
	if _, err := os.Stat(filepath.Join(stateDirectory, "recovery", "blocked.json")); err != nil {
		t.Fatalf("durable recovery marker missing: %v", err)
	}
	result, err = recovery.Prepare(ctx)
	if !errors.Is(err, ErrNoVerifiedSnapshot) || result.State != RecoveryBlocked {
		t.Fatalf("second Prepare() = %+v, %v", result, err)
	}
	if _, err := os.Stat(databasePath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("second start created an empty database: %v", err)
	}
}

func TestHealthyDatabaseCompletesInterruptedRecoveryMarker(t *testing.T) {
	ctx, database, snapshots := snapshotTestManager(t)
	database.Close()
	recovery, err := NewRecoveryManager(filepath.Dir(snapshots.DatabasePath), snapshots.DatabasePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := recovery.prepareRoot(); err != nil {
		t.Fatal(err)
	}
	if err := recovery.writeMarker(recoveryMarker{FormatVersion: 1, State: string(RecoveryBlocked), OccurredAt: time.Now().UTC().Format(time.RFC3339Nano), ErrorCode: "DATABASE_RESTORE_PENDING", SnapshotID: "snapshot-record", QuarantineID: "quarantine-record"}); err != nil {
		t.Fatal(err)
	}
	result, err := recovery.Prepare(ctx)
	if err != nil || result.State != RecoveryRestored || result.SnapshotID != "snapshot-record" {
		t.Fatalf("Prepare() = %+v, %v", result, err)
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(snapshots.DatabasePath), "recovery", "last.json")); err != nil {
		t.Fatalf("last recovery record missing: %v", err)
	}
}

func TestOpenManagedCreatesFreshSchemaWithoutPretendingItWasRecovery(t *testing.T) {
	ctx := context.Background()
	stateDirectory := t.TempDir()
	databasePath := filepath.Join(stateDirectory, "state.db")
	managed, err := OpenManaged(ctx, stateDirectory, databasePath)
	if err != nil {
		t.Fatal(err)
	}
	defer managed.Database.Close()
	if managed.Recovery.State != RecoveryFresh || managed.Recovery.PreMigrationID != "" {
		t.Fatalf("fresh managed recovery = %+v", managed.Recovery)
	}
	version, err := databasepkg.ReadSchemaVersion(ctx, managed.Database)
	if err != nil || version != 31 {
		t.Fatalf("managed schema = %d, %v", version, err)
	}
	if err := databasepkg.IntegrityCheck(ctx, managed.Database); err != nil {
		t.Fatal(err)
	}
}

func TestOpenManagedCreatesVerifiedSnapshotBeforeMigration(t *testing.T) {
	ctx := context.Background()
	stateDirectory := t.TempDir()
	databasePath := filepath.Join(stateDirectory, "state.db")
	database, err := databasepkg.Open(ctx, databasepkg.OpenOptions{Path: databasePath})
	if err != nil {
		t.Fatal(err)
	}
	if err := migrateEmbeddedThrough(ctx, database, 13); err != nil {
		database.Close()
		t.Fatal(err)
	}
	database.Close()

	managed, err := OpenManaged(ctx, stateDirectory, databasePath)
	if err != nil {
		t.Fatal(err)
	}
	defer managed.Database.Close()
	if managed.Recovery.PreMigrationID == "" {
		t.Fatal("pre-migration snapshot id is empty")
	}
	version, err := databasepkg.ReadSchemaVersion(ctx, managed.Database)
	if err != nil || version != 31 {
		t.Fatalf("migrated schema = %d, %v", version, err)
	}
	items, err := managed.Backups.List(ctx, true)
	if err != nil || len(items) != 1 || items[0].Manifest.Kind != KindPreMigration || items[0].Manifest.SchemaVersion != 13 {
		t.Fatalf("pre-migration snapshots = %+v, %v", items, err)
	}
	var audit int
	if err := managed.Database.QueryRowContext(ctx, "SELECT COUNT(*) FROM events WHERE type='DATABASE_PRE_MIGRATION_SNAPSHOT_CREATED'").Scan(&audit); err != nil || audit != 1 {
		t.Fatalf("pre-migration audit count = %d, %v", audit, err)
	}
}

// migrateEmbeddedThrough constructs a real older schema instead of attempting
// lossy reverse DDL against the current schema. It is intentionally test-only.
func migrateEmbeddedThrough(ctx context.Context, database *sql.DB, maximum int64) error {
	if _, err := database.ExecContext(ctx, `CREATE TABLE schema_migrations (
version INTEGER PRIMARY KEY, name TEXT NOT NULL, checksum_sha256 TEXT NOT NULL, applied_at TEXT NOT NULL)`); err != nil {
		return err
	}
	entries, err := fs.ReadDir(migrations.Files, ".")
	if err != nil {
		return err
	}
	names := make([]string, 0, maximum)
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".sql" {
			continue
		}
		parts := strings.SplitN(entry.Name(), "_", 2)
		version, parseErr := strconv.ParseInt(parts[0], 10, 64)
		if parseErr == nil && version <= maximum {
			names = append(names, entry.Name())
		}
	}
	sort.Strings(names)
	for _, name := range names {
		parts := strings.SplitN(strings.TrimSuffix(name, ".sql"), "_", 2)
		version, _ := strconv.ParseInt(parts[0], 10, 64)
		content, readErr := fs.ReadFile(migrations.Files, name)
		if readErr != nil {
			return readErr
		}
		transaction, beginErr := database.BeginTx(ctx, nil)
		if beginErr != nil {
			return beginErr
		}
		digest := sha256.Sum256(content)
		if _, err = transaction.ExecContext(ctx, string(content)); err == nil {
			_, err = transaction.ExecContext(ctx, `INSERT INTO schema_migrations(version,name,checksum_sha256,applied_at) VALUES(?,?,?,?)`,
				version, parts[1], hex.EncodeToString(digest[:]), "2026-08-24T00:00:00Z")
		}
		if err != nil {
			transaction.Rollback()
			return fmt.Errorf("apply test migration %d: %w", version, err)
		}
		if err := transaction.Commit(); err != nil {
			return err
		}
	}
	if int64(len(names)) != maximum {
		return fmt.Errorf("test migration count %d, want %d", len(names), maximum)
	}
	return nil
}
