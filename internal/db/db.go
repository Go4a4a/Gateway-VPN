// Package db owns the Gateway VPN SQLite connection, migrations, and integrity
// checks. Domain repositories build on this package rather than opening their
// own connections.
package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	_ "modernc.org/sqlite"
)

const DriverName = "sqlite"

type OpenOptions struct {
	Path string
}

func OpenReadOnly(ctx context.Context, path string) (*sql.DB, error) {
	return openReadOnly(ctx, path, false)
}

// OpenImmutable opens a standalone SQLite image that must not have WAL/SHM
// state. It is intended for committed backup artifacts, never for the live DB.
func OpenImmutable(ctx context.Context, path string) (*sql.DB, error) {
	return openReadOnly(ctx, path, true)
}

func openReadOnly(ctx context.Context, path string, immutable bool) (*sql.DB, error) {
	if path == "" {
		return nil, errors.New("database path is required")
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("resolve read-only database path: %w", err)
	}
	info, err := os.Lstat(absolute)
	if err != nil {
		return nil, fmt.Errorf("inspect read-only database: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, errors.New("read-only database must be a regular non-symlink file")
	}
	dsn := "file:" + filepath.ToSlash(absolute) + "?mode=ro"
	if immutable {
		dsn += "&immutable=1"
	}
	database, err := sql.Open(DriverName, dsn)
	if err != nil {
		return nil, fmt.Errorf("open read-only sqlite: %w", err)
	}
	database.SetMaxOpenConns(1)
	database.SetMaxIdleConns(1)
	for _, statement := range []string{"PRAGMA query_only=ON", "PRAGMA foreign_keys=ON", "PRAGMA busy_timeout=5000"} {
		if _, err := database.ExecContext(ctx, statement); err != nil {
			database.Close()
			return nil, fmt.Errorf("configure read-only sqlite (%s): %w", statement, err)
		}
	}
	if err := database.PingContext(ctx); err != nil {
		database.Close()
		return nil, fmt.Errorf("ping read-only sqlite: %w", err)
	}
	return database, nil
}

func Open(ctx context.Context, options OpenOptions) (*sql.DB, error) {
	if options.Path == "" {
		return nil, errors.New("database path is required")
	}
	fileBacked := options.Path != ":memory:"
	if fileBacked {
		absolute, err := filepath.Abs(options.Path)
		if err != nil {
			return nil, fmt.Errorf("resolve database path: %w", err)
		}
		directory := filepath.Dir(absolute)
		if err := os.MkdirAll(directory, 0o700); err != nil {
			return nil, fmt.Errorf("create database directory: %w", err)
		}
		if err := ensureExactMode(directory, 0o700, true, os.Chmod); err != nil {
			return nil, fmt.Errorf("secure database directory: %w", err)
		}
		if info, err := os.Lstat(absolute); err == nil {
			if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
				return nil, errors.New("database must be a regular non-symlink file")
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("inspect database file: %w", err)
		}
		options.Path = absolute
	}

	database, err := sql.Open(DriverName, options.Path)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}

	// The MVP uses one database connection so connection-local safety PRAGMAs
	// cannot silently differ between pooled connections. WAL still permits other
	// processes such as the Online Backup API helper to read consistently.
	database.SetMaxOpenConns(1)
	database.SetMaxIdleConns(1)

	if err := configure(ctx, database); err != nil {
		database.Close()
		return nil, err
	}
	if fileBacked {
		if err := ensureExactMode(options.Path, 0o600, false, os.Chmod); err != nil {
			database.Close()
			return nil, fmt.Errorf("secure database file: %w", err)
		}
	}
	return database, nil
}

func ensureExactMode(path string, expected os.FileMode, directory bool, chmod func(string, os.FileMode) error) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || directory && !info.IsDir() || !directory && !info.Mode().IsRegular() {
		return errors.New("database path has an unsafe type")
	}
	if runtime.GOOS == "windows" {
		if chmod == nil {
			return errors.New("database path mode requires correction")
		}
		return chmod(path, expected)
	}
	if info.Mode().Perm() == expected.Perm() && info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) == 0 {
		return nil
	}
	if chmod == nil {
		return errors.New("database path mode requires correction")
	}
	if err := chmod(path, expected); err != nil {
		return err
	}
	verified, err := os.Lstat(path)
	if err != nil || verified.Mode()&os.ModeSymlink != 0 || directory && !verified.IsDir() || !directory && !verified.Mode().IsRegular() || verified.Mode().Perm() != expected.Perm() || verified.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
		return errors.New("database path mode correction did not converge")
	}
	return nil
}

func configure(ctx context.Context, database *sql.DB) error {
	pragmas := []string{
		"PRAGMA journal_mode=WAL",
		"PRAGMA foreign_keys=ON",
		"PRAGMA busy_timeout=5000",
		"PRAGMA synchronous=NORMAL",
	}
	for _, statement := range pragmas {
		if _, err := database.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("configure sqlite (%s): %w", statement, err)
		}
	}
	if err := database.PingContext(ctx); err != nil {
		return fmt.Errorf("ping sqlite: %w", err)
	}
	return nil
}

func QuickCheck(ctx context.Context, database *sql.DB) error {
	return checkPragma(ctx, database, "PRAGMA quick_check")
}

func IntegrityCheck(ctx context.Context, database *sql.DB) error {
	return checkPragma(ctx, database, "PRAGMA integrity_check")
}

func ForeignKeyCheck(ctx context.Context, database *sql.DB) error {
	rows, err := database.QueryContext(ctx, "PRAGMA foreign_key_check")
	if err != nil {
		return fmt.Errorf("execute PRAGMA foreign_key_check: %w", err)
	}
	defer rows.Close()
	if rows.Next() {
		return errors.New("PRAGMA foreign_key_check found violations")
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate PRAGMA foreign_key_check: %w", err)
	}
	return nil
}

func checkPragma(ctx context.Context, database *sql.DB, pragma string) error {
	rows, err := database.QueryContext(ctx, pragma)
	if err != nil {
		return fmt.Errorf("execute %s: %w", pragma, err)
	}
	defer rows.Close()

	var problems []string
	for rows.Next() {
		var result string
		if err := rows.Scan(&result); err != nil {
			return fmt.Errorf("scan %s: %w", pragma, err)
		}
		if result != "ok" {
			problems = append(problems, result)
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate %s: %w", pragma, err)
	}
	if len(problems) != 0 {
		return fmt.Errorf("%s failed: %v", pragma, problems)
	}
	return nil
}
