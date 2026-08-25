package db

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"gateway-vpn/migrations"
)

var (
	ErrMigrationChecksum = errors.New("migration checksum mismatch")
	ErrSchemaTooNew      = errors.New("database schema is newer than this binary")
)

type migration struct {
	Version  int64
	Name     string
	Checksum string
	SQL      string
}

func Migrate(ctx context.Context, database *sql.DB) error {
	return migrateFS(ctx, database, migrations.Files)
}

// LatestSchemaVersion returns the schema version understood by this binary.
// It reads the embedded migration set and never consults or mutates a database.
func LatestSchemaVersion() (int64, error) {
	available, err := loadMigrations(migrations.Files)
	if err != nil {
		return 0, err
	}
	return available[len(available)-1].Version, nil
}

// ReadSchemaVersion is safe for a query-only connection. A database without a
// migration table is version zero; unlike SchemaVersion it never creates the
// table and is therefore suitable for backup verification and startup checks.
func ReadSchemaVersion(ctx context.Context, database *sql.DB) (int64, error) {
	var exists int
	if err := database.QueryRowContext(ctx, "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='schema_migrations'").Scan(&exists); err != nil {
		return 0, fmt.Errorf("inspect schema migration table: %w", err)
	}
	if exists == 0 {
		return 0, nil
	}
	var version int64
	if err := database.QueryRowContext(ctx, "SELECT COALESCE(MAX(version), 0) FROM schema_migrations").Scan(&version); err != nil {
		return 0, fmt.Errorf("read schema version: %w", err)
	}
	return version, nil
}

func SchemaVersion(ctx context.Context, database *sql.DB) (int64, error) {
	if err := ensureMigrationTable(ctx, database); err != nil {
		return 0, err
	}
	var version int64
	if err := database.QueryRowContext(ctx, "SELECT COALESCE(MAX(version), 0) FROM schema_migrations").Scan(&version); err != nil {
		return 0, fmt.Errorf("read schema version: %w", err)
	}
	return version, nil
}

func migrateFS(ctx context.Context, database *sql.DB, files fs.FS) error {
	available, err := loadMigrations(files)
	if err != nil {
		return err
	}
	if err := ensureMigrationTable(ctx, database); err != nil {
		return err
	}

	applied, err := readAppliedMigrations(ctx, database)
	if err != nil {
		return err
	}
	availableByVersion := make(map[int64]migration, len(available))
	for _, item := range available {
		availableByVersion[item.Version] = item
	}
	for version, checksum := range applied {
		item, exists := availableByVersion[version]
		if !exists {
			return fmt.Errorf("%w: applied version %d is unavailable", ErrSchemaTooNew, version)
		}
		if item.Checksum != checksum {
			return fmt.Errorf("%w: version %d", ErrMigrationChecksum, version)
		}
	}

	for _, item := range available {
		if _, exists := applied[item.Version]; exists {
			continue
		}
		if err := applyMigration(ctx, database, item); err != nil {
			return err
		}
	}
	return nil
}

func ensureMigrationTable(ctx context.Context, database *sql.DB) error {
	const statement = `
CREATE TABLE IF NOT EXISTS schema_migrations (
    version INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    checksum_sha256 TEXT NOT NULL,
    applied_at TEXT NOT NULL
)`
	if _, err := database.ExecContext(ctx, statement); err != nil {
		return fmt.Errorf("create schema_migrations: %w", err)
	}
	return nil
}

func loadMigrations(files fs.FS) ([]migration, error) {
	entries, err := fs.ReadDir(files, ".")
	if err != nil {
		return nil, fmt.Errorf("read migrations: %w", err)
	}
	var result []migration
	seen := make(map[int64]string)
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".sql" {
			continue
		}
		version, name, err := parseMigrationName(entry.Name())
		if err != nil {
			return nil, err
		}
		if previous, exists := seen[version]; exists {
			return nil, fmt.Errorf("duplicate migration version %d: %s and %s", version, previous, entry.Name())
		}
		content, err := fs.ReadFile(files, entry.Name())
		if err != nil {
			return nil, fmt.Errorf("read migration %s: %w", entry.Name(), err)
		}
		digest := sha256.Sum256(content)
		result = append(result, migration{
			Version:  version,
			Name:     name,
			Checksum: hex.EncodeToString(digest[:]),
			SQL:      string(content),
		})
		seen[version] = entry.Name()
	}
	if len(result) == 0 {
		return nil, errors.New("no database migrations found")
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Version < result[j].Version })
	for index, item := range result {
		expected := int64(index + 1)
		if item.Version != expected {
			return nil, fmt.Errorf("migration sequence gap: expected %06d, found %06d", expected, item.Version)
		}
	}
	return result, nil
}

func parseMigrationName(filename string) (int64, string, error) {
	base := strings.TrimSuffix(filename, filepath.Ext(filename))
	parts := strings.SplitN(base, "_", 2)
	if len(parts) != 2 || len(parts[0]) != 6 || parts[1] == "" {
		return 0, "", fmt.Errorf("invalid migration filename %q; expected 000001_name.sql", filename)
	}
	version, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil || version <= 0 {
		return 0, "", fmt.Errorf("invalid migration version in %q", filename)
	}
	return version, parts[1], nil
}

func readAppliedMigrations(ctx context.Context, database *sql.DB) (map[int64]string, error) {
	rows, err := database.QueryContext(ctx, "SELECT version, checksum_sha256 FROM schema_migrations ORDER BY version")
	if err != nil {
		return nil, fmt.Errorf("read applied migrations: %w", err)
	}
	defer rows.Close()
	result := make(map[int64]string)
	for rows.Next() {
		var version int64
		var checksum string
		if err := rows.Scan(&version, &checksum); err != nil {
			return nil, fmt.Errorf("scan applied migration: %w", err)
		}
		result[version] = checksum
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate applied migrations: %w", err)
	}
	return result, nil
}

func applyMigration(ctx context.Context, database *sql.DB, item migration) error {
	transaction, err := database.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin migration %d: %w", item.Version, err)
	}
	defer transaction.Rollback()

	if _, err := transaction.ExecContext(ctx, item.SQL); err != nil {
		return fmt.Errorf("apply migration %d (%s): %w", item.Version, item.Name, err)
	}
	if _, err := transaction.ExecContext(
		ctx,
		"INSERT INTO schema_migrations(version, name, checksum_sha256, applied_at) VALUES (?, ?, ?, ?)",
		item.Version,
		item.Name,
		item.Checksum,
		time.Now().UTC().Format(time.RFC3339Nano),
	); err != nil {
		return fmt.Errorf("record migration %d: %w", item.Version, err)
	}
	if err := transaction.Commit(); err != nil {
		return fmt.Errorf("commit migration %d: %w", item.Version, err)
	}
	return nil
}
