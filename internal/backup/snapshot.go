// Package backup owns consistent SQLite snapshots and corruption recovery for
// Gateway VPN. Internal snapshots never contain the separate secret files;
// portable encrypted system backups are built on top of this verified layer.
package backup

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	databasepkg "gateway-vpn/internal/db"
	sqlite "modernc.org/sqlite"
)

const (
	SnapshotFormatVersion      = 1
	DefaultMaximumDatabaseSize = int64(512 << 20)
	maximumManifestSize        = int64(16 << 10)
	backupPageBatch            = int32(128)
)

type Kind string

const (
	KindDaily           Kind = "daily"
	KindManual          Kind = "manual"
	KindPreMigration    Kind = "pre-migration"
	KindPreUpdate       Kind = "pre-update"
	KindPreRestore      Kind = "pre-restore"
	KindPreNetworkApply Kind = "pre-network-apply"
)

var snapshotIDPattern = regexp.MustCompile(`^[0-9]{8}T[0-9]{6}\.[0-9]{9}Z-[a-f0-9]{24}$`)

type FileRecord struct {
	Name   string `json:"name"`
	Bytes  int64  `json:"bytes"`
	SHA256 string `json:"sha256"`
}

type Manifest struct {
	FormatVersion   int        `json:"format_version"`
	SnapshotID      string     `json:"snapshot_id"`
	Kind            Kind       `json:"kind"`
	CreatedAt       string     `json:"created_at"`
	VerifiedAt      string     `json:"verified_at"`
	SchemaVersion   int64      `json:"schema_version"`
	Database        FileRecord `json:"database"`
	QuickCheck      string     `json:"quick_check"`
	IntegrityCheck  string     `json:"integrity_check"`
	ForeignKeyCheck string     `json:"foreign_key_check"`
}

type Snapshot struct {
	Manifest Manifest `json:"manifest"`
	Path     string   `json:"-"`
}

type InventoryItem struct {
	SnapshotID    string `json:"snapshot_id"`
	Kind          Kind   `json:"kind,omitempty"`
	CreatedAt     string `json:"created_at,omitempty"`
	VerifiedAt    string `json:"verified_at,omitempty"`
	SchemaVersion int64  `json:"schema_version,omitempty"`
	Bytes         int64  `json:"bytes,omitempty"`
	SHA256        string `json:"sha256,omitempty"`
	Verified      bool   `json:"verified"`
	ErrorCode     string `json:"error_code,omitempty"`
}

type RetentionPolicy struct {
	Daily           int
	Manual          int
	PreMigration    int
	PreUpdate       int
	PreRestore      int
	PreNetworkApply int
}

func DefaultRetentionPolicy() RetentionPolicy {
	return RetentionPolicy{Daily: 7, Manual: 10, PreMigration: 5, PreUpdate: 5, PreRestore: 5, PreNetworkApply: 5}
}

func (policy RetentionPolicy) limit(kind Kind) int {
	switch kind {
	case KindDaily:
		return policy.Daily
	case KindManual:
		return policy.Manual
	case KindPreMigration:
		return policy.PreMigration
	case KindPreUpdate:
		return policy.PreUpdate
	case KindPreRestore:
		return policy.PreRestore
	case KindPreNetworkApply:
		return policy.PreNetworkApply
	default:
		return 0
	}
}

type Manager struct {
	Database       *sql.DB
	DatabasePath   string
	Root           string
	MaximumDBBytes int64
	Retention      RetentionPolicy
	Now            func() time.Time
	mutex          sync.Mutex
}

func NewManager(database *sql.DB, stateDirectory, databasePath string) (*Manager, error) {
	if !filepath.IsAbs(stateDirectory) || !filepath.IsAbs(databasePath) {
		return nil, errors.New("backup state directory and database path must be absolute")
	}
	stateDirectory = filepath.Clean(stateDirectory)
	databasePath = filepath.Clean(databasePath)
	relative, err := filepath.Rel(stateDirectory, databasePath)
	if err != nil || relative == "." || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return nil, errors.New("backup database must be a file inside the state directory")
	}
	return &Manager{
		Database: database, DatabasePath: databasePath, Root: filepath.Join(stateDirectory, "backups", "snapshots"),
		MaximumDBBytes: DefaultMaximumDatabaseSize, Retention: DefaultRetentionPolicy(),
	}, nil
}

func (manager *Manager) Create(ctx context.Context, kind Kind) (Snapshot, error) {
	manager.mutex.Lock()
	defer manager.mutex.Unlock()
	return manager.createLocked(ctx, kind)
}

func (manager *Manager) createLocked(ctx context.Context, kind Kind) (Snapshot, error) {
	if manager.Database == nil {
		return Snapshot{}, errors.New("online backup requires an open database")
	}
	if !validKind(kind) || manager.Retention.limit(kind) < 1 {
		return Snapshot{}, errors.New("valid backup kind and positive retention are required")
	}
	if err := manager.prepareRoot(); err != nil {
		return Snapshot{}, err
	}
	now := manager.now()
	id, err := newSnapshotID(now)
	if err != nil {
		return Snapshot{}, err
	}
	temporaryDirectory := filepath.Join(manager.Root, ".tmp-"+id)
	finalDirectory := filepath.Join(manager.Root, id)
	if err := os.Mkdir(temporaryDirectory, 0o700); err != nil {
		return Snapshot{}, fmt.Errorf("create backup transaction directory: %w", err)
	}
	defer os.RemoveAll(temporaryDirectory)
	databasePath := filepath.Join(temporaryDirectory, "state.db")
	file, err := os.OpenFile(databasePath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return Snapshot{}, fmt.Errorf("create secure backup destination: %w", err)
	}
	if err := file.Close(); err != nil {
		return Snapshot{}, fmt.Errorf("close backup destination: %w", err)
	}
	if err := onlineBackup(ctx, manager.Database, databasePath); err != nil {
		return Snapshot{}, err
	}
	// The modernc destination connection can leave empty WAL/SHM artifacts
	// after sqlite3_backup_finish. They are never part of a committed snapshot:
	// remove them and verify the main file again as a standalone read-only DB.
	if err := removeSQLiteSidecars(databasePath); err != nil {
		return Snapshot{}, err
	}
	if err := os.Chmod(databasePath, 0o600); err != nil {
		return Snapshot{}, fmt.Errorf("secure completed database snapshot: %w", err)
	}
	verification, err := verifyDatabaseFile(ctx, databasePath, manager.maximumDatabaseBytes())
	if err != nil {
		return Snapshot{}, fmt.Errorf("verify new database snapshot: %w", err)
	}
	manifest := Manifest{
		FormatVersion: SnapshotFormatVersion, SnapshotID: id, Kind: kind,
		CreatedAt: now.Format(time.RFC3339Nano), VerifiedAt: manager.now().Format(time.RFC3339Nano),
		SchemaVersion: verification.SchemaVersion, Database: FileRecord{Name: "state.db", Bytes: verification.Bytes, SHA256: verification.SHA256},
		QuickCheck: "PASS", IntegrityCheck: "PASS", ForeignKeyCheck: "PASS",
	}
	if err := writeManifest(filepath.Join(temporaryDirectory, "manifest.json"), manifest); err != nil {
		return Snapshot{}, err
	}
	if err := syncDirectory(temporaryDirectory); err != nil {
		return Snapshot{}, fmt.Errorf("sync backup transaction directory: %w", err)
	}
	if err := os.Rename(temporaryDirectory, finalDirectory); err != nil {
		return Snapshot{}, fmt.Errorf("commit verified database snapshot: %w", err)
	}
	if err := syncDirectory(manager.Root); err != nil {
		return Snapshot{}, fmt.Errorf("sync snapshot root: %w", err)
	}
	snapshot := Snapshot{Manifest: manifest, Path: finalDirectory}
	if err := manager.pruneLocked(ctx); err != nil {
		return snapshot, fmt.Errorf("snapshot created but retention cleanup failed: %w", err)
	}
	return snapshot, nil
}

func (manager *Manager) EnsureDaily(ctx context.Context) (Snapshot, bool, error) {
	manager.mutex.Lock()
	defer manager.mutex.Unlock()
	today := manager.now().Format("2006-01-02")
	items, err := manager.listLocked(ctx, true)
	if err != nil {
		return Snapshot{}, false, err
	}
	for _, item := range items {
		created, err := time.Parse(time.RFC3339Nano, item.Manifest.CreatedAt)
		if err == nil && item.Manifest.Kind == KindDaily && created.UTC().Format("2006-01-02") == today {
			return item, false, nil
		}
	}
	item, err := manager.createLocked(ctx, KindDaily)
	return item, err == nil, err
}

func (manager *Manager) List(ctx context.Context, verify bool) ([]Snapshot, error) {
	manager.mutex.Lock()
	defer manager.mutex.Unlock()
	return manager.listLocked(ctx, verify)
}

func (manager *Manager) Inventory(ctx context.Context) ([]InventoryItem, error) {
	manager.mutex.Lock()
	defer manager.mutex.Unlock()
	if err := manager.prepareRoot(); err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(manager.Root)
	if err != nil {
		return nil, fmt.Errorf("read snapshot inventory: %w", err)
	}
	items := make([]InventoryItem, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() || !snapshotIDPattern.MatchString(entry.Name()) {
			continue
		}
		item := InventoryItem{SnapshotID: entry.Name()}
		snapshot, err := manager.readSnapshot(ctx, filepath.Join(manager.Root, entry.Name()), false)
		if err != nil {
			item.ErrorCode = "SNAPSHOT_MANIFEST_INVALID"
			items = append(items, item)
			continue
		}
		item.Kind = snapshot.Manifest.Kind
		item.CreatedAt = snapshot.Manifest.CreatedAt
		item.VerifiedAt = snapshot.Manifest.VerifiedAt
		item.SchemaVersion = snapshot.Manifest.SchemaVersion
		item.Bytes = snapshot.Manifest.Database.Bytes
		item.SHA256 = snapshot.Manifest.Database.SHA256
		if _, err := manager.readSnapshot(ctx, snapshot.Path, true); err != nil {
			item.ErrorCode = "SNAPSHOT_VERIFICATION_FAILED"
		} else {
			item.Verified = true
		}
		items = append(items, item)
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].CreatedAt == items[j].CreatedAt {
			return items[i].SnapshotID > items[j].SnapshotID
		}
		return items[i].CreatedAt > items[j].CreatedAt
	})
	return items, nil
}

func (manager *Manager) listLocked(ctx context.Context, verify bool) ([]Snapshot, error) {
	if err := manager.prepareRoot(); err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(manager.Root)
	if err != nil {
		return nil, fmt.Errorf("read snapshot root: %w", err)
	}
	items := make([]Snapshot, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() || !snapshotIDPattern.MatchString(entry.Name()) {
			continue
		}
		item, err := manager.readSnapshot(ctx, filepath.Join(manager.Root, entry.Name()), verify)
		if err != nil {
			continue
		}
		items = append(items, item)
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].Manifest.CreatedAt == items[j].Manifest.CreatedAt {
			return items[i].Manifest.SnapshotID > items[j].Manifest.SnapshotID
		}
		return items[i].Manifest.CreatedAt > items[j].Manifest.CreatedAt
	})
	return items, nil
}

func (manager *Manager) LatestValid(ctx context.Context) (Snapshot, error) {
	items, err := manager.List(ctx, true)
	if err != nil {
		return Snapshot{}, err
	}
	if len(items) == 0 {
		return Snapshot{}, errors.New("no verified database snapshot is available")
	}
	return items[0], nil
}

func (manager *Manager) Verify(ctx context.Context, snapshot Snapshot) error {
	manager.mutex.Lock()
	defer manager.mutex.Unlock()
	if !snapshotIDPattern.MatchString(snapshot.Manifest.SnapshotID) {
		return errors.New("invalid snapshot id")
	}
	_, err := manager.readSnapshot(ctx, filepath.Join(manager.Root, snapshot.Manifest.SnapshotID), true)
	return err
}

func (manager *Manager) readSnapshot(ctx context.Context, directory string, verify bool) (Snapshot, error) {
	name := filepath.Base(directory)
	if !snapshotIDPattern.MatchString(name) || filepath.Dir(directory) != filepath.Clean(manager.Root) {
		return Snapshot{}, errors.New("snapshot directory is outside the managed root")
	}
	info, err := os.Lstat(directory)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return Snapshot{}, errors.New("snapshot directory is unsafe")
	}
	manifestPath := filepath.Join(directory, "manifest.json")
	manifestInfo, err := os.Lstat(manifestPath)
	if err != nil || manifestInfo.Mode()&os.ModeSymlink != 0 || !manifestInfo.Mode().IsRegular() || manifestInfo.Size() <= 0 || manifestInfo.Size() > maximumManifestSize {
		return Snapshot{}, errors.New("snapshot manifest is unsafe")
	}
	content, err := os.ReadFile(manifestPath)
	if err != nil {
		return Snapshot{}, errors.New("read snapshot manifest failed")
	}
	var manifest Manifest
	if err := decodeStrictJSON(content, &manifest); err != nil {
		return Snapshot{}, errors.New("decode snapshot manifest failed")
	}
	if manifest.FormatVersion != SnapshotFormatVersion || manifest.SnapshotID != name || !validKind(manifest.Kind) || manifest.Database.Name != "state.db" || !validDigest(manifest.Database.SHA256) || manifest.Database.Bytes <= 0 || manifest.Database.Bytes > manager.maximumDatabaseBytes() || manifest.QuickCheck != "PASS" || manifest.IntegrityCheck != "PASS" || manifest.ForeignKeyCheck != "PASS" {
		return Snapshot{}, errors.New("snapshot manifest contract is invalid")
	}
	created, createdErr := time.Parse(time.RFC3339Nano, manifest.CreatedAt)
	verified, verifiedErr := time.Parse(time.RFC3339Nano, manifest.VerifiedAt)
	if createdErr != nil || verifiedErr != nil || verified.Before(created) || manifest.SchemaVersion < 1 {
		return Snapshot{}, errors.New("snapshot manifest timestamps or schema are invalid")
	}
	if verify {
		verification, err := verifyDatabaseFile(ctx, filepath.Join(directory, manifest.Database.Name), manager.maximumDatabaseBytes())
		if err != nil {
			return Snapshot{}, err
		}
		if verification.Bytes != manifest.Database.Bytes || verification.SHA256 != manifest.Database.SHA256 || verification.SchemaVersion != manifest.SchemaVersion {
			return Snapshot{}, errors.New("snapshot database does not match its manifest")
		}
	}
	return Snapshot{Manifest: manifest, Path: directory}, nil
}

func (manager *Manager) pruneLocked(ctx context.Context) error {
	items, err := manager.listLocked(ctx, false)
	if err != nil {
		return err
	}
	counts := map[Kind]int{}
	for _, item := range items {
		kind := item.Manifest.Kind
		counts[kind]++
		if counts[kind] <= manager.Retention.limit(kind) {
			continue
		}
		if err := removeSnapshotDirectory(item.Path); err != nil {
			return err
		}
	}
	return syncDirectory(manager.Root)
}

func (manager *Manager) prepareRoot() error {
	if !filepath.IsAbs(manager.Root) || manager.maximumDatabaseBytes() <= 0 {
		return errors.New("absolute snapshot root and positive database bound are required")
	}
	parent := filepath.Dir(manager.Root)
	if err := secureDirectory(parent); err != nil {
		return err
	}
	return secureDirectory(manager.Root)
}

func secureDirectory(directory string) error {
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return fmt.Errorf("create secure backup directory: %w", err)
	}
	info, err := os.Lstat(directory)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return errors.New("backup directory must be a real directory")
	}
	// The control-plane user owns these trees, while privileged restore and
	// recovery helpers intentionally run without CAP_FOWNER. Avoid requiring
	// that capability merely to reapply an already-correct mode.
	if info.Mode().Perm() == 0o700 {
		return nil
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		return fmt.Errorf("secure backup directory: %w", err)
	}
	return nil
}

func onlineBackup(ctx context.Context, database *sql.DB, destination string) error {
	connection, err := database.Conn(ctx)
	if err != nil {
		return fmt.Errorf("reserve SQLite connection for online backup: %w", err)
	}
	defer connection.Close()
	err = connection.Raw(func(raw any) error {
		backuper, ok := raw.(interface {
			NewBackup(string) (*sqlite.Backup, error)
		})
		if !ok {
			return errors.New("SQLite driver does not expose the Online Backup API")
		}
		operation, err := backuper.NewBackup(destination)
		if err != nil {
			return fmt.Errorf("start SQLite online backup: %w", err)
		}
		finished := false
		defer func() {
			if !finished {
				_ = operation.Finish()
			}
		}()
		for {
			if err := ctx.Err(); err != nil {
				return err
			}
			more, err := operation.Step(backupPageBatch)
			if err != nil {
				return fmt.Errorf("copy SQLite online backup pages: %w", err)
			}
			if !more {
				break
			}
		}
		finishErr := operation.Finish()
		finished = true
		if finishErr != nil {
			return fmt.Errorf("finish SQLite online backup: %w", finishErr)
		}
		return nil
	})
	if err != nil {
		return err
	}
	return nil
}

type databaseVerification struct {
	Bytes         int64
	SHA256        string
	SchemaVersion int64
}

func verifyDatabaseFile(ctx context.Context, filename string, maximum int64) (databaseVerification, error) {
	info, err := os.Lstat(filename)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maximum {
		return databaseVerification{}, errors.New("database snapshot must be a bounded regular non-symlink file")
	}
	file, err := os.Open(filename)
	if err != nil {
		return databaseVerification{}, errors.New("open database snapshot for hashing failed")
	}
	hash := sha256.New()
	read, copyErr := io.Copy(hash, io.LimitReader(file, maximum+1))
	closeErr := file.Close()
	if copyErr != nil || closeErr != nil || read != info.Size() || read > maximum {
		return databaseVerification{}, errors.New("hash bounded database snapshot failed")
	}
	database, err := databasepkg.OpenImmutable(ctx, filename)
	if err != nil {
		return databaseVerification{}, fmt.Errorf("open snapshot read-only: %w", err)
	}
	defer database.Close()
	if err := databasepkg.QuickCheck(ctx, database); err != nil {
		return databaseVerification{}, fmt.Errorf("snapshot quick check: %w", err)
	}
	if err := databasepkg.IntegrityCheck(ctx, database); err != nil {
		return databaseVerification{}, fmt.Errorf("snapshot integrity check: %w", err)
	}
	if err := databasepkg.ForeignKeyCheck(ctx, database); err != nil {
		return databaseVerification{}, fmt.Errorf("snapshot foreign key check: %w", err)
	}
	schema, err := databasepkg.ReadSchemaVersion(ctx, database)
	if err != nil || schema < 1 {
		return databaseVerification{}, errors.New("snapshot schema version is unavailable")
	}
	latest, err := databasepkg.LatestSchemaVersion()
	if err != nil || schema > latest {
		return databaseVerification{}, errors.New("snapshot schema is newer than this binary")
	}
	return databaseVerification{Bytes: read, SHA256: hex.EncodeToString(hash.Sum(nil)), SchemaVersion: schema}, nil
}

func writeManifest(filename string, manifest Manifest) error {
	content, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return errors.New("encode snapshot manifest failed")
	}
	content = append(content, '\n')
	if int64(len(content)) > maximumManifestSize {
		return errors.New("snapshot manifest exceeds its bound")
	}
	file, err := os.OpenFile(filename, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("create snapshot manifest: %w", err)
	}
	if _, err := file.Write(content); err != nil {
		file.Close()
		return errors.New("write snapshot manifest failed")
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return errors.New("sync snapshot manifest failed")
	}
	if err := file.Close(); err != nil {
		return errors.New("close snapshot manifest failed")
	}
	return nil
}

func removeSnapshotDirectory(directory string) error {
	if !snapshotIDPattern.MatchString(filepath.Base(directory)) {
		return errors.New("refuse to remove an unmanaged snapshot directory")
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.IsDir() || (entry.Name() != "state.db" && entry.Name() != "manifest.json") {
			return errors.New("refuse to remove snapshot directory with unexpected contents")
		}
		info, err := os.Lstat(filepath.Join(directory, entry.Name()))
		if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return errors.New("refuse to remove unsafe snapshot contents")
		}
	}
	for _, name := range []string{"state.db", "manifest.json"} {
		if err := os.Remove(filepath.Join(directory, name)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return os.Remove(directory)
}

func removeSQLiteSidecars(databasePath string) error {
	for _, suffix := range []string{"-wal", "-shm", "-journal"} {
		filename := databasePath + suffix
		info, err := os.Lstat(filename)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return errors.New("SQLite backup sidecar is unsafe")
		}
		if err := os.Remove(filename); err != nil {
			return fmt.Errorf("remove SQLite backup sidecar: %w", err)
		}
	}
	return syncDirectory(filepath.Dir(databasePath))
}

func validKind(kind Kind) bool {
	switch kind {
	case KindDaily, KindManual, KindPreMigration, KindPreUpdate, KindPreRestore, KindPreNetworkApply:
		return true
	default:
		return false
	}
}

func validDigest(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func newSnapshotID(now time.Time) (string, error) {
	random := make([]byte, 12)
	if _, err := rand.Read(random); err != nil {
		return "", errors.New("generate snapshot id failed")
	}
	return now.UTC().Format("20060102T150405.000000000Z") + "-" + hex.EncodeToString(random), nil
}

func (manager *Manager) now() time.Time {
	if manager.Now != nil {
		return manager.Now().UTC()
	}
	return time.Now().UTC()
}

func (manager *Manager) maximumDatabaseBytes() int64 {
	if manager.MaximumDBBytes > 0 {
		return manager.MaximumDBBytes
	}
	return DefaultMaximumDatabaseSize
}

func syncDirectory(directory string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	file, err := os.Open(directory)
	if err != nil {
		return err
	}
	defer file.Close()
	return file.Sync()
}
