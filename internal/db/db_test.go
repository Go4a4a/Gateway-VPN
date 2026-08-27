package db

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"testing/fstest"
)

func TestEnsureExactModeSkipsUnneededChmod(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows does not expose verifiable POSIX modes")
	}
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	called := false
	refuseChmod := func(string, os.FileMode) error {
		called = true
		return errors.New("chmod must not run")
	}
	if err := ensureExactMode(directory, 0o700, true, refuseChmod); err != nil || called {
		t.Fatalf("private directory mode convergence = %v, chmod called=%t", err, called)
	}

	file := filepath.Join(directory, "state.db")
	if err := os.WriteFile(file, []byte("fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(file, 0o600); err != nil {
		t.Fatal(err)
	}
	called = false
	if err := ensureExactMode(file, 0o600, false, refuseChmod); err != nil || called {
		t.Fatalf("private file mode convergence = %v, chmod called=%t", err, called)
	}
}

func TestEnsureExactModeCorrectsUnsafeModeAndRejectsUnsafeType(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows does not expose verifiable POSIX modes")
	}
	directory := t.TempDir()
	file := filepath.Join(directory, "state.db")
	if err := os.WriteFile(file, []byte("fixture"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(file, 0o644); err != nil {
		t.Fatal(err)
	}
	called := false
	if err := ensureExactMode(file, 0o600, false, func(path string, mode os.FileMode) error {
		called = true
		return os.Chmod(path, mode)
	}); err != nil || !called {
		t.Fatalf("unsafe file mode convergence = %v, chmod called=%t", err, called)
	}
	if err := ensureExactMode(directory, 0o600, false, os.Chmod); err == nil {
		t.Fatal("directory accepted as database file")
	}
}

func TestOpenConfiguresSafetyPragmas(t *testing.T) {
	ctx := context.Background()
	database, err := Open(ctx, OpenOptions{Path: filepath.Join(t.TempDir(), "state.db")})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer database.Close()

	checks := []struct {
		pragma string
		want   string
	}{
		{"PRAGMA journal_mode", "wal"},
		{"PRAGMA foreign_keys", "1"},
		{"PRAGMA busy_timeout", "5000"},
		{"PRAGMA synchronous", "1"},
	}
	for _, check := range checks {
		var got string
		if err := database.QueryRowContext(ctx, check.pragma).Scan(&got); err != nil {
			t.Fatalf("%s error = %v", check.pragma, err)
		}
		if got != check.want {
			t.Errorf("%s = %q, want %q", check.pragma, got, check.want)
		}
	}
}

func TestOpenReadOnlyCannotCreateOrMutateDatabase(t *testing.T) {
	ctx := context.Background()
	missing := filepath.Join(t.TempDir(), "missing.db")
	if _, err := OpenReadOnly(ctx, missing); err == nil {
		t.Fatal("OpenReadOnly(missing) error = nil")
	}
	path := filepath.Join(t.TempDir(), "state.db")
	writable, err := Open(ctx, OpenOptions{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	if err := Migrate(ctx, writable); err != nil {
		t.Fatal(err)
	}
	writable.Close()
	readOnly, err := OpenReadOnly(ctx, path)
	if err != nil {
		t.Fatalf("OpenReadOnly() error = %v", err)
	}
	defer readOnly.Close()
	if _, err := readOnly.ExecContext(ctx, "UPDATE runtime_state SET gateway_state='ACTIVE'"); err == nil {
		t.Fatal("read-only database accepted UPDATE")
	}
	version, err := ReadSchemaVersion(ctx, readOnly)
	if err != nil || version != 16 {
		t.Fatalf("ReadSchemaVersion(read-only) = %d, %v", version, err)
	}
	if err := ForeignKeyCheck(ctx, readOnly); err != nil {
		t.Fatalf("ForeignKeyCheck(read-only) error = %v", err)
	}
}

func TestReadSchemaVersionDoesNotCreateMigrationTable(t *testing.T) {
	ctx := context.Background()
	database, err := Open(ctx, OpenOptions{Path: filepath.Join(t.TempDir(), "empty.db")})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	version, err := ReadSchemaVersion(ctx, database)
	if err != nil || version != 0 {
		t.Fatalf("ReadSchemaVersion(empty) = %d, %v", version, err)
	}
	var count int
	if err := database.QueryRowContext(ctx, "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='schema_migrations'").Scan(&count); err != nil || count != 0 {
		t.Fatalf("migration table count = %d, %v", count, err)
	}
	latest, err := LatestSchemaVersion()
	if err != nil || latest != 16 {
		t.Fatalf("LatestSchemaVersion() = %d, %v", latest, err)
	}
}

func TestMigrateCreatesInitialSchema(t *testing.T) {
	ctx := context.Background()
	database, err := Open(ctx, OpenOptions{Path: filepath.Join(t.TempDir(), "state.db")})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer database.Close()

	if err := Migrate(ctx, database); err != nil {
		t.Fatalf("Migrate() error = %v", err)
	}
	if err := QuickCheck(ctx, database); err != nil {
		t.Fatalf("QuickCheck() error = %v", err)
	}
	if err := IntegrityCheck(ctx, database); err != nil {
		t.Fatalf("IntegrityCheck() error = %v", err)
	}

	wantTables := []string{
		"bypass_probe_targets",
		"access_methods",
		"access_policy",
		"access_selection_runtime",
		"direct_modem_paths",
		"direct_path_target_results",
		"events",
		"health_samples",
		"modems",
		"node_matchers",
		"operation_steps",
		"operations",
		"nodes",
		"network_apply_transactions",
		"path_node_target_results",
		"path_nodes",
		"path_health_runtime",
		"runtime_state",
		"schema_migrations",
		"sessions",
		"settings",
		"subscription_modem_paths",
		"subscription_node_preferences",
		"subscription_refresh_state",
		"subscription_versions",
		"subscriptions",
		"traffic_daily_totals",
		"users",
		"login_attempts",
		"logging_runtime",
	}
	for _, table := range wantTables {
		var count int
		if err := database.QueryRowContext(ctx, "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?", table).Scan(&count); err != nil {
			t.Fatalf("query table %s: %v", table, err)
		}
		if count != 1 {
			t.Errorf("table %s count = %d, want 1", table, count)
		}
	}

	version, err := SchemaVersion(ctx, database)
	if err != nil {
		t.Fatalf("SchemaVersion() error = %v", err)
	}
	if version != 16 {
		t.Fatalf("SchemaVersion() = %d, want 16", version)
	}
	for _, column := range []string{"service_download_bytes", "service_upload_bytes"} {
		var count int
		if err := database.QueryRowContext(ctx, "SELECT COUNT(*) FROM pragma_table_info('traffic_daily_totals') WHERE name=?", column).Scan(&count); err != nil || count != 1 {
			t.Errorf("traffic service column %s count = %d, %v", column, count, err)
		}
	}
	if _, err := database.ExecContext(ctx, `
INSERT INTO subscriptions (
    id, display_number, name, source_type, enabled, priority, auto_refresh,
    refresh_interval_seconds, fallback_when_named_candidates_fail, status,
    created_at, updated_at
) VALUES ('missing-number', NULL, 'Invalid', 'url', 0, 999, 1, 3600, 0, 'UNKNOWN', 'now', 'now')`); err == nil {
		t.Fatal("migration v5 accepted a subscription without display_number")
	}

	var gatewayState, pathState string
	if err := database.QueryRowContext(ctx, "SELECT gateway_state, path_state FROM runtime_state WHERE singleton_id=1").Scan(&gatewayState, &pathState); err != nil {
		t.Fatalf("read runtime_state: %v", err)
	}
	if gatewayState != "BOOTING" || pathState != "PATH_BLOCKED" {
		t.Errorf("runtime state = %s/%s, want BOOTING/PATH_BLOCKED", gatewayState, pathState)
	}
}

func TestMigrateIsIdempotent(t *testing.T) {
	ctx := context.Background()
	database, err := Open(ctx, OpenOptions{Path: filepath.Join(t.TempDir(), "state.db")})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer database.Close()

	if err := Migrate(ctx, database); err != nil {
		t.Fatalf("first Migrate() error = %v", err)
	}
	if err := Migrate(ctx, database); err != nil {
		t.Fatalf("second Migrate() error = %v", err)
	}
	var count int
	if err := database.QueryRowContext(ctx, "SELECT COUNT(*) FROM schema_migrations").Scan(&count); err != nil {
		t.Fatalf("count migrations: %v", err)
	}
	if count != 16 {
		t.Fatalf("migration count = %d, want 16", count)
	}
}

func TestMigrationRollsBackPartialDDL(t *testing.T) {
	ctx := context.Background()
	database, err := Open(ctx, OpenOptions{Path: filepath.Join(t.TempDir(), "state.db")})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer database.Close()

	broken := fstest.MapFS{
		"000001_broken.sql": &fstest.MapFile{Data: []byte("CREATE TABLE must_rollback (id INTEGER); INVALID SQL;")},
	}
	if err := migrateFS(ctx, database, broken); err == nil {
		t.Fatal("migrateFS() error = nil, want SQL error")
	}
	var count int
	if err := database.QueryRowContext(ctx, "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='must_rollback'").Scan(&count); err != nil {
		t.Fatalf("query rolled back table: %v", err)
	}
	if count != 0 {
		t.Fatalf("must_rollback table count = %d, want 0", count)
	}
}

func TestMigrateRejectsChangedAppliedMigration(t *testing.T) {
	ctx := context.Background()
	database, err := Open(ctx, OpenOptions{Path: filepath.Join(t.TempDir(), "state.db")})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer database.Close()

	original := fstest.MapFS{
		"000001_test.sql": &fstest.MapFile{Data: []byte("CREATE TABLE stable (id INTEGER);")},
	}
	changed := fstest.MapFS{
		"000001_test.sql": &fstest.MapFile{Data: []byte("CREATE TABLE stable (id INTEGER, changed TEXT);")},
	}
	if err := migrateFS(ctx, database, original); err != nil {
		t.Fatalf("first migrateFS() error = %v", err)
	}
	err = migrateFS(ctx, database, changed)
	if !errors.Is(err, ErrMigrationChecksum) {
		t.Fatalf("second migrateFS() error = %v, want ErrMigrationChecksum", err)
	}
}

func TestLoadMigrationsRejectsSequenceGap(t *testing.T) {
	files := fstest.MapFS{
		"000002_gap.sql": &fstest.MapFile{Data: []byte("SELECT 1;")},
	}
	_, err := loadMigrations(files)
	if err == nil {
		t.Fatal("loadMigrations() error = nil, want sequence gap")
	}
}
