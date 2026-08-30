// Package vpsagent owns the role-specific VPS Hub database. It deliberately
// does not apply Gateway migrations or store Gateway private credentials.
package vpsagent

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"

	databasepkg "gateway-vpn/internal/db"
	"gateway-vpn/internal/wgingress"

	_ "modernc.org/sqlite"
)

const SchemaVersion int64 = 4

type migration struct {
	version int64
	name    string
	sql     string
}

var migrations = []migration{
	{version: 1, name: "initial_vps_hub", sql: schemaV1},
	{version: 2, name: "management_control_plane", sql: schemaV2},
	{version: 3, name: "managed_administrator_config_lifecycle", sql: schemaV3},
	{version: 4, name: "end_to_end_administrator_relay", sql: schemaV4},
}

var (
	vpsIDPattern       = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.:-]{0,127}$`)
	fingerprintPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)
)

type Identity struct {
	VPSID               string `json:"vps_id"`
	DisplayName         string `json:"display_name"`
	IdentityFingerprint string `json:"identity_fingerprint"`
	PublicKey           string `json:"public_key"`
	PrivateKeySecretRef string `json:"-"`
	UpdateIdentityRef   string `json:"-"`
	CreatedAt           string `json:"created_at"`
	UpdatedAt           string `json:"updated_at"`
}

type IdentityInput struct {
	VPSID               string
	DisplayName         string
	IdentityFingerprint string
	PublicKey           string
	PrivateKeySecretRef string
	UpdateIdentityRef   string
}

func Open(ctx context.Context, filename string) (*sql.DB, error) {
	if !filepath.IsAbs(filename) {
		return nil, errors.New("VPS Agent database path must be absolute")
	}
	filename = filepath.Clean(filename)
	if err := secureDirectory(filepath.Dir(filename)); err != nil {
		return nil, err
	}
	if info, err := os.Lstat(filename); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return nil, errors.New("VPS Agent database must be a regular non-symlink file")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("inspect VPS Agent database: %w", err)
	}
	database, err := sql.Open(databasepkg.DriverName, filename)
	if err != nil {
		return nil, fmt.Errorf("open VPS Agent SQLite: %w", err)
	}
	database.SetMaxOpenConns(1)
	database.SetMaxIdleConns(1)
	for _, statement := range []string{"PRAGMA journal_mode=WAL", "PRAGMA foreign_keys=ON", "PRAGMA busy_timeout=5000", "PRAGMA synchronous=NORMAL"} {
		if _, err := database.ExecContext(ctx, statement); err != nil {
			database.Close()
			return nil, fmt.Errorf("configure VPS Agent SQLite: %w", err)
		}
	}
	if err := Migrate(ctx, database); err != nil {
		database.Close()
		return nil, err
	}
	if err := secureFile(filename); err != nil {
		database.Close()
		return nil, err
	}
	return database, nil
}

func Migrate(ctx context.Context, database *sql.DB) error {
	if database == nil {
		return errors.New("VPS Agent database is required")
	}
	if _, err := database.ExecContext(ctx, `
CREATE TABLE IF NOT EXISTS schema_migrations(
    version INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    checksum_sha256 TEXT NOT NULL,
    applied_at TEXT NOT NULL
)`); err != nil {
		return fmt.Errorf("create VPS Agent migration table: %w", err)
	}
	rows, err := database.QueryContext(ctx, "SELECT version,name,checksum_sha256 FROM schema_migrations ORDER BY version")
	if err != nil {
		return fmt.Errorf("read VPS Agent migration history: %w", err)
	}
	var applied int64
	for rows.Next() {
		var version int64
		var name, checksum string
		if err := rows.Scan(&version, &name, &checksum); err != nil {
			rows.Close()
			return fmt.Errorf("scan VPS Agent migration history: %w", err)
		}
		if version != applied+1 || version > SchemaVersion {
			rows.Close()
			return errors.New("VPS Agent migration history is not a supported contiguous prefix")
		}
		expected := migrations[version-1]
		if name != expected.name || checksum != schemaChecksum(expected.sql) {
			rows.Close()
			return errors.New("VPS Agent migration history checksum mismatch")
		}
		applied = version
	}
	if err := rows.Close(); err != nil {
		return fmt.Errorf("close VPS Agent migration history: %w", err)
	}
	for _, item := range migrations[applied:] {
		transaction, err := database.BeginTx(ctx, nil)
		if err != nil {
			return fmt.Errorf("begin VPS Agent migration %d: %w", item.version, err)
		}
		if _, err := transaction.ExecContext(ctx, item.sql); err != nil {
			transaction.Rollback()
			return fmt.Errorf("apply VPS Agent migration %d: %w", item.version, err)
		}
		if _, err := transaction.ExecContext(ctx, `
INSERT INTO schema_migrations(version,name,checksum_sha256,applied_at)
VALUES(?,?,?,?)`, item.version, item.name, schemaChecksum(item.sql), time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
			transaction.Rollback()
			return fmt.Errorf("record VPS Agent migration %d: %w", item.version, err)
		}
		if err := transaction.Commit(); err != nil {
			return fmt.Errorf("commit VPS Agent migration %d: %w", item.version, err)
		}
	}
	return nil
}

func InitializeIdentity(ctx context.Context, database *sql.DB, input IdentityInput, now time.Time) (Identity, error) {
	if database == nil || !vpsIDPattern.MatchString(input.VPSID) || !fingerprintPattern.MatchString(input.IdentityFingerprint) || !wgingress.ValidKey(input.PublicKey) {
		return Identity{}, errors.New("valid immutable VPS identity is required")
	}
	input.DisplayName = strings.TrimSpace(input.DisplayName)
	if input.DisplayName == "" || len(input.DisplayName) > 128 || !validSecretRef(input.PrivateKeySecretRef) || !validSecretRef(input.UpdateIdentityRef) {
		return Identity{}, errors.New("VPS identity name and root-owned secret references are required")
	}
	transaction, err := database.BeginTx(ctx, nil)
	if err != nil {
		return Identity{}, err
	}
	defer transaction.Rollback()
	var existing Identity
	err = scanIdentity(transaction.QueryRowContext(ctx, identitySelect+" WHERE singleton_id=1"), &existing)
	stamp := now.UTC().Format(time.RFC3339Nano)
	if errors.Is(err, sql.ErrNoRows) {
		_, err = transaction.ExecContext(ctx, `
INSERT INTO vps_identity(
    singleton_id,vps_id,display_name,identity_fingerprint,public_key,
    private_key_secret_ref,update_identity_ref,created_at,updated_at
) VALUES(1,?,?,?,?,?,?,?,?)`, input.VPSID, input.DisplayName, input.IdentityFingerprint,
			input.PublicKey, input.PrivateKeySecretRef, input.UpdateIdentityRef, stamp, stamp)
		if err != nil {
			return Identity{}, fmt.Errorf("create VPS identity: %w", err)
		}
	} else if err != nil {
		return Identity{}, err
	} else {
		if existing.VPSID != input.VPSID || existing.IdentityFingerprint != input.IdentityFingerprint || existing.PublicKey != input.PublicKey || existing.PrivateKeySecretRef != input.PrivateKeySecretRef || existing.UpdateIdentityRef != input.UpdateIdentityRef {
			return Identity{}, errors.New("immutable VPS identity already exists with different values")
		}
		if _, err := transaction.ExecContext(ctx, "UPDATE vps_identity SET display_name=?,updated_at=? WHERE singleton_id=1", input.DisplayName, stamp); err != nil {
			return Identity{}, err
		}
	}
	if err := transaction.Commit(); err != nil {
		return Identity{}, err
	}
	return ReadIdentity(ctx, database)
}

func ReadIdentity(ctx context.Context, database *sql.DB) (Identity, error) {
	if database == nil {
		return Identity{}, errors.New("VPS Agent database is required")
	}
	var item Identity
	if err := scanIdentity(database.QueryRowContext(ctx, identitySelect+" WHERE singleton_id=1"), &item); err != nil {
		return Identity{}, err
	}
	return item, nil
}

func Schema(ctx context.Context, database *sql.DB) (int64, error) {
	var version int64
	if database == nil {
		return 0, errors.New("VPS Agent database is required")
	}
	if err := database.QueryRowContext(ctx, "SELECT COALESCE(MAX(version),0) FROM schema_migrations").Scan(&version); err != nil {
		return 0, err
	}
	return version, nil
}

func Verify(ctx context.Context, database *sql.DB) error {
	if database == nil {
		return errors.New("VPS Agent database is required")
	}
	version, err := Schema(ctx, database)
	if err != nil || version != SchemaVersion {
		return errors.New("VPS Agent schema version is invalid")
	}
	for _, item := range migrations {
		var name, checksum string
		if err := database.QueryRowContext(ctx, "SELECT name,checksum_sha256 FROM schema_migrations WHERE version=?", item.version).Scan(&name, &checksum); err != nil || name != item.name || checksum != schemaChecksum(item.sql) {
			return errors.New("VPS Agent migration history is invalid")
		}
	}
	if err := databasepkg.QuickCheck(ctx, database); err != nil {
		return err
	}
	if err := databasepkg.IntegrityCheck(ctx, database); err != nil {
		return err
	}
	var invalidAdminLifecycle int64
	if err := database.QueryRowContext(ctx, `
SELECT COUNT(*)
FROM admin_peers AS peer
LEFT JOIN admin_peers AS source ON source.id=peer.rotation_source_id
WHERE (peer.key_mode='EXTERNAL' AND (peer.private_key_secret_ref IS NOT NULL OR peer.config_state!='NOT_APPLICABLE'))
   OR (peer.key_mode='MANAGED' AND (peer.private_key_secret_ref IS NULL OR peer.config_state='NOT_APPLICABLE'))
   OR (peer.trust_mode='END_TO_END_RELAY' AND peer.key_mode!='EXTERNAL')
   OR (peer.rotation_source_id!='' AND (source.id IS NULL OR source.id=peer.id OR source.key_mode!='MANAGED'))`).Scan(&invalidAdminLifecycle); err != nil {
		return err
	}
	if invalidAdminLifecycle != 0 {
		return errors.New("VPS Agent administrator key lifecycle is invalid")
	}
	return databasepkg.ForeignKeyCheck(ctx, database)
}

func SanitizePortableCopy(ctx context.Context, filename string) error {
	if !filepath.IsAbs(filename) {
		return errors.New("absolute VPS portable database path is required")
	}
	database, err := sql.Open(databasepkg.DriverName, filepath.Clean(filename))
	if err != nil {
		return err
	}
	database.SetMaxOpenConns(1)
	database.SetMaxIdleConns(1)
	defer database.Close()
	for _, statement := range []string{"PRAGMA foreign_keys=ON", "PRAGMA secure_delete=ON", "PRAGMA journal_mode=DELETE", "PRAGMA synchronous=FULL"} {
		if _, err := database.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("prepare VPS portable database sanitization: %w", err)
		}
	}
	transaction, err := database.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	for _, table := range []string{"pairing_invitations", "sessions", "login_attempts", "events", "audit_events", "operations"} {
		if _, err := transaction.ExecContext(ctx, "DELETE FROM "+table); err != nil {
			transaction.Rollback()
			return fmt.Errorf("sanitize VPS portable table %s: %w", table, err)
		}
	}
	if err := transaction.Commit(); err != nil {
		return err
	}
	if _, err := database.ExecContext(ctx, "VACUUM"); err != nil {
		return fmt.Errorf("compact sanitized VPS portable database: %w", err)
	}
	return Verify(ctx, database)
}

// QuarantineRestoredRuntime preserves the durable management configuration of
// a same-VPS restore, but prevents cloned/stale tunnels and publications from
// becoming active until the runtime has reconciled them with their peers.
func QuarantineRestoredRuntime(ctx context.Context, database *sql.DB, now time.Time) error {
	if database == nil {
		return errors.New("VPS Agent database is required")
	}
	transaction, err := database.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer transaction.Rollback()
	stamp := now.UTC().Format(time.RFC3339Nano)
	statements := []string{
		"UPDATE gateway_peers SET state='QUARANTINED',updated_at=? WHERE state!='REVOKED'",
		"UPDATE admin_peers SET state='CONFIGURED',updated_at=? WHERE state!='REVOKED'",
		"UPDATE prefix_allocations SET state='QUARANTINED',updated_at=? WHERE state!='RELEASED'",
		"UPDATE resource_publications SET state='PENDING_RETRY',updated_at=? WHERE state NOT IN ('DISABLED','ROLLED_BACK')",
		"UPDATE admin_relays SET state='CONFIGURED',status_reason='RESTORE_REQUIRES_HOST_APPLY',updated_at=? WHERE enabled=1",
	}
	for _, statement := range statements {
		if _, err := transaction.ExecContext(ctx, statement, stamp); err != nil {
			return fmt.Errorf("quarantine restored VPS runtime: %w", err)
		}
	}
	if err := clearEphemeralTables(ctx, transaction); err != nil {
		return err
	}
	if err := transaction.Commit(); err != nil {
		return err
	}
	return Verify(ctx, database)
}

// ImportPortableAsNew replaces the backed-up VPS identity and removes every
// peer, ACL and prefix allocation tied to the source VPS. Settings are kept;
// all connectivity must be freshly paired and allocated for the new VPS.
func ImportPortableAsNew(ctx context.Context, database *sql.DB, input IdentityInput, now time.Time) (Identity, error) {
	if database == nil || !vpsIDPattern.MatchString(input.VPSID) || !fingerprintPattern.MatchString(input.IdentityFingerprint) || !wgingress.ValidKey(input.PublicKey) {
		return Identity{}, errors.New("valid replacement VPS identity is required")
	}
	input.DisplayName = strings.TrimSpace(input.DisplayName)
	if input.DisplayName == "" || len(input.DisplayName) > 128 || !validSecretRef(input.PrivateKeySecretRef) || !validSecretRef(input.UpdateIdentityRef) {
		return Identity{}, errors.New("replacement VPS identity paths are invalid")
	}
	transaction, err := database.BeginTx(ctx, nil)
	if err != nil {
		return Identity{}, err
	}
	defer transaction.Rollback()
	for _, table := range []string{"acl_grants", "resource_publications", "admin_relays", "gateway_peers", "admin_peers", "prefix_allocations"} {
		if _, err := transaction.ExecContext(ctx, "DELETE FROM "+table); err != nil {
			return Identity{}, fmt.Errorf("clear source VPS table %s: %w", table, err)
		}
	}
	if err := clearEphemeralTables(ctx, transaction); err != nil {
		return Identity{}, err
	}
	stamp := now.UTC().Format(time.RFC3339Nano)
	result, err := transaction.ExecContext(ctx, `
UPDATE vps_identity SET
    vps_id=?,display_name=?,identity_fingerprint=?,public_key=?,
    private_key_secret_ref=?,update_identity_ref=?,created_at=?,updated_at=?
WHERE singleton_id=1`, input.VPSID, input.DisplayName, input.IdentityFingerprint, input.PublicKey,
		input.PrivateKeySecretRef, input.UpdateIdentityRef, stamp, stamp)
	if err != nil {
		return Identity{}, fmt.Errorf("replace portable VPS identity: %w", err)
	}
	if affected, err := result.RowsAffected(); err != nil || affected != 1 {
		return Identity{}, errors.New("portable VPS identity is missing")
	}
	if err := transaction.Commit(); err != nil {
		return Identity{}, err
	}
	if err := Verify(ctx, database); err != nil {
		return Identity{}, err
	}
	return ReadIdentity(ctx, database)
}

type sqlExecutor interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}

func clearEphemeralTables(ctx context.Context, executor sqlExecutor) error {
	for _, table := range []string{"pairing_invitations", "sessions", "login_attempts", "events", "audit_events", "operations"} {
		if _, err := executor.ExecContext(ctx, "DELETE FROM "+table); err != nil {
			return fmt.Errorf("clear ephemeral VPS table %s: %w", table, err)
		}
	}
	return nil
}

const identitySelect = `
SELECT vps_id,display_name,identity_fingerprint,public_key,
       private_key_secret_ref,update_identity_ref,created_at,updated_at
FROM vps_identity`

type scanner interface{ Scan(...any) error }

func scanIdentity(row scanner, item *Identity) error {
	return row.Scan(&item.VPSID, &item.DisplayName, &item.IdentityFingerprint, &item.PublicKey,
		&item.PrivateKeySecretRef, &item.UpdateIdentityRef, &item.CreatedAt, &item.UpdatedAt)
}

func schemaChecksum(content string) string {
	digest := sha256.Sum256([]byte(content))
	return hex.EncodeToString(digest[:])
}

func validSecretRef(value string) bool {
	clean := filepath.ToSlash(filepath.Clean(value))
	return clean == value && strings.HasPrefix(clean, "/var/lib/gateway-vpn-vps/agent/secrets/") && !strings.Contains(clean, "..")
}

func secureDirectory(path string) error {
	if err := os.MkdirAll(path, 0o700); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return errors.New("VPS Agent database directory is unsafe")
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o700 {
		return os.Chmod(path, 0o700)
	}
	return nil
}

func secureFile(path string) error {
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return errors.New("VPS Agent database file is unsafe")
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		return os.Chmod(path, 0o600)
	}
	return nil
}
