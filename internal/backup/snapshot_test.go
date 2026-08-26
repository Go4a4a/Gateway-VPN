package backup

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	databasepkg "gateway-vpn/internal/db"
)

func TestOnlineSnapshotIsStandaloneVerifiedAndDailyIsIdempotent(t *testing.T) {
	ctx, database, manager := snapshotTestManager(t)
	if _, err := database.ExecContext(ctx, `INSERT INTO events(occurred_at,severity,type,details_json) VALUES('2026-08-24T10:00:00Z','INFO','BEFORE_BACKUP','{}')`); err != nil {
		t.Fatal(err)
	}
	clock := time.Date(2026, 8, 24, 10, 30, 0, 0, time.UTC)
	manager.Now = func() time.Time { return clock }
	snapshot, created, err := manager.EnsureDaily(ctx)
	if err != nil || !created {
		t.Fatalf("EnsureDaily() = %+v, %v, %v", snapshot, created, err)
	}
	if snapshot.Manifest.Kind != KindDaily || snapshot.Manifest.SchemaVersion != 13 || snapshot.Manifest.Database.Bytes <= 0 || snapshot.Manifest.Database.SHA256 == "" {
		t.Fatalf("snapshot manifest = %+v", snapshot.Manifest)
	}
	if _, err := os.Stat(filepath.Join(snapshot.Path, "state.db-wal")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("standalone snapshot has WAL sidecar: %v", err)
	}
	if info, err := os.Stat(filepath.Join(snapshot.Path, "state.db")); err != nil || runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Fatalf("snapshot database mode = %v, %v", info, err)
	}
	if info, err := os.Stat(snapshot.Path); err != nil || runtime.GOOS != "windows" && info.Mode().Perm() != 0o700 {
		t.Fatalf("snapshot directory mode = %v, %v", info, err)
	}
	if _, err := database.ExecContext(ctx, `INSERT INTO events(occurred_at,severity,type,details_json) VALUES('2026-08-24T10:31:00Z','INFO','AFTER_BACKUP','{}')`); err != nil {
		t.Fatal(err)
	}
	copyDatabase, err := databasepkg.OpenReadOnly(ctx, filepath.Join(snapshot.Path, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer copyDatabase.Close()
	var before, after int
	if err := copyDatabase.QueryRowContext(ctx, "SELECT COUNT(*) FROM events WHERE type='BEFORE_BACKUP'").Scan(&before); err != nil {
		t.Fatal(err)
	}
	if err := copyDatabase.QueryRowContext(ctx, "SELECT COUNT(*) FROM events WHERE type='AFTER_BACKUP'").Scan(&after); err != nil {
		t.Fatal(err)
	}
	if before != 1 || after != 0 {
		t.Fatalf("snapshot event counts = before:%d after:%d", before, after)
	}
	second, created, err := manager.EnsureDaily(ctx)
	if err != nil || created || second.Manifest.SnapshotID != snapshot.Manifest.SnapshotID {
		t.Fatalf("second EnsureDaily() = %+v, %v, %v", second, created, err)
	}
	if err := manager.Verify(ctx, snapshot); err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
}

func TestSnapshotRetentionRunsOnlyAfterAReplacementWasVerified(t *testing.T) {
	ctx, _, manager := snapshotTestManager(t)
	manager.Retention.Manual = 2
	clock := time.Date(2026, 8, 24, 11, 0, 0, 0, time.UTC)
	manager.Now = func() time.Time { return clock }
	created := make([]Snapshot, 0, 3)
	for index := 0; index < 3; index++ {
		item, err := manager.Create(ctx, KindManual)
		if err != nil {
			t.Fatal(err)
		}
		created = append(created, item)
		clock = clock.Add(time.Minute)
	}
	items, err := manager.List(ctx, true)
	if err != nil {
		t.Fatal(err)
	}
	manual := 0
	for _, item := range items {
		if item.Manifest.Kind == KindManual {
			manual++
		}
	}
	if manual != 2 {
		t.Fatalf("retained manual snapshots = %d, want 2", manual)
	}
	if _, err := os.Stat(created[0].Path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("oldest verified snapshot still exists: %v", err)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := manager.Create(cancelled, KindManual); err == nil {
		t.Fatal("cancelled snapshot unexpectedly succeeded")
	}
	items, err = manager.List(ctx, true)
	if err != nil || len(items) != 2 {
		t.Fatalf("failed replacement rotated existing backups: %d, %v", len(items), err)
	}
}

func TestSnapshotHashMismatchAndUnknownManifestFieldsAreRejected(t *testing.T) {
	ctx, _, manager := snapshotTestManager(t)
	snapshot, err := manager.Create(ctx, KindPreMigration)
	if err != nil {
		t.Fatal(err)
	}
	databasePath := filepath.Join(snapshot.Path, "state.db")
	file, err := os.OpenFile(databasePath, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteAt([]byte{0xff}, 128); err != nil {
		file.Close()
		t.Fatal(err)
	}
	file.Close()
	if err := manager.Verify(ctx, snapshot); err == nil {
		t.Fatal("snapshot hash mismatch was accepted")
	}
	items, err := manager.List(ctx, true)
	if err != nil || len(items) != 0 {
		t.Fatalf("corrupt snapshot returned as verified: %d, %v", len(items), err)
	}

	replacement, err := manager.Create(ctx, KindPreMigration)
	if err != nil {
		t.Fatal(err)
	}
	manifestPath := filepath.Join(replacement.Path, "manifest.json")
	content, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	content[len(content)-2] = ','
	content = append(content[:len(content)-1], []byte(`"unknown":"value"}`)...)
	if err := os.WriteFile(manifestPath, content, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := manager.Verify(ctx, replacement); err == nil {
		t.Fatal("manifest with unknown field was accepted")
	}
}

func snapshotTestManager(t *testing.T) (context.Context, *sql.DB, *Manager) {
	t.Helper()
	ctx := context.Background()
	stateDirectory := t.TempDir()
	databasePath := filepath.Join(stateDirectory, "state.db")
	database, err := databasepkg.Open(ctx, databasepkg.OpenOptions{Path: databasePath})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	if err := databasepkg.Migrate(ctx, database); err != nil {
		t.Fatal(err)
	}
	manager, err := NewManager(database, stateDirectory, databasePath)
	if err != nil {
		t.Fatal(err)
	}
	return ctx, database, manager
}
