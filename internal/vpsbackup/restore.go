package vpsbackup

import (
	"archive/zip"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"

	"gateway-vpn/internal/backup"
	databasepkg "gateway-vpn/internal/db"
	"gateway-vpn/internal/vpsagent"
)

const (
	RestoreStateStaged         = "STAGED"
	RestoreStateApplyRequested = "APPLY_REQUESTED"
	RestoreStateApplied        = "APPLIED"
	RestoreModeSameVPS         = "SAME_VPS"
	RestoreModeNewVPS          = "IMPORT_AS_NEW"
)

var (
	ErrRestorePending        = errors.New("a VPS restore operation is already pending")
	ErrRestoreNotPending     = errors.New("the VPS restore operation is not pending")
	ErrRestoreUploadTooLarge = errors.New("the encrypted VPS restore upload exceeds its bound")
	vpsRestoreIDPattern      = regexp.MustCompile(`^vps-restore-[a-f0-9]{32}$`)
)

type RestoreOperation struct {
	FormatVersion             int      `json:"format_version"`
	RestoreID                 string   `json:"restore_id"`
	State                     string   `json:"state"`
	CreatedAt                 string   `json:"created_at"`
	BackupID                  string   `json:"backup_id"`
	SourceVPSID               string   `json:"source_vps_id"`
	SourceIdentityFingerprint string   `json:"source_identity_fingerprint"`
	LiveVPSID                 string   `json:"live_vps_id"`
	LiveIdentityFingerprint   string   `json:"live_identity_fingerprint"`
	SchemaVersion             int64    `json:"schema_version"`
	AgentVersion              string   `json:"agent_version"`
	PortableBytes             int64    `json:"portable_bytes"`
	PortableSHA256            string   `json:"portable_sha256"`
	ArchiveBytes              int64    `json:"archive_bytes"`
	PayloadBytes              int64    `json:"payload_bytes"`
	Files                     int      `json:"files"`
	AllowedModes              []string `json:"allowed_modes"`
	IdentityMatches           bool     `json:"identity_matches"`
	CloneQuarantineOnSameVPS  bool     `json:"clone_quarantine_on_same_vps"`
	SelectedMode              string   `json:"selected_mode,omitempty"`
	ApplyAuthorization        string   `json:"apply_authorization,omitempty"`
	ApplyErrorCode            string   `json:"apply_error_code,omitempty"`
	AppliedAt                 string   `json:"applied_at,omitempty"`
}

type VerifiedRestore struct {
	Operation RestoreOperation
	Manifest  Manifest
	TreeRoot  string
	Identity  vpsagent.Identity
}

type ApplyResult struct {
	RestoreID           string `json:"restore_id"`
	Mode                string `json:"mode"`
	VPSID               string `json:"vps_id"`
	IdentityFingerprint string `json:"identity_fingerprint"`
	PreRestoreSnapshot  string `json:"pre_restore_snapshot"`
	AppliedAt           string `json:"applied_at"`
	ReconcileRequired   bool   `json:"reconcile_required"`
	Quarantined         bool   `json:"quarantined"`
}

type RestoreManager struct {
	Database          *sql.DB
	StateDirectory    string
	DatabaseFile      string
	ConfigurationPath string
	Root              string
	Now               func() time.Time
	mutex             sync.Mutex
}

func NewRestoreManager(database *sql.DB, stateDirectory, databasePath, configurationPath string) (*RestoreManager, error) {
	if database == nil || !filepath.IsAbs(stateDirectory) || !filepath.IsAbs(databasePath) || !filepath.IsAbs(configurationPath) {
		return nil, errors.New("VPS restore requires a database and absolute state/database/configuration paths")
	}
	stateDirectory = filepath.Clean(stateDirectory)
	databasePath = filepath.Clean(databasePath)
	relative, err := filepath.Rel(stateDirectory, databasePath)
	if err != nil || relative == "." || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return nil, errors.New("VPS restore database must be inside the role state directory")
	}
	return &RestoreManager{
		Database: database, StateDirectory: stateDirectory, DatabaseFile: databasePath, ConfigurationPath: filepath.Clean(configurationPath),
		Root: filepath.Join(stateDirectory, "recovery", "restores"),
	}, nil
}

// Stage consumes one encrypted .gvpn-vps upload, authenticates it, validates
// its role, manifest, every archive entry and the portable SQLite database,
// then leaves only a durable verified tree. Neither passphrase nor encrypted
// upload nor decrypted ZIP survives a successful staging operation.
func (manager *RestoreManager) Stage(ctx context.Context, encrypted io.Reader, passphrase string) (RestoreOperation, error) {
	manager.mutex.Lock()
	defer manager.mutex.Unlock()
	if encrypted == nil {
		return RestoreOperation{}, errors.New("encrypted VPS restore input is required")
	}
	if err := backup.ValidatePassphrase(passphrase); err != nil {
		return RestoreOperation{}, err
	}
	if err := manager.prepareRoot(); err != nil {
		return RestoreOperation{}, err
	}
	if _, exists, err := manager.readPending(); err != nil {
		return RestoreOperation{}, err
	} else if exists {
		return RestoreOperation{}, ErrRestorePending
	}
	restoreID, err := newVPSRestoreID()
	if err != nil {
		return RestoreOperation{}, err
	}
	temporaryRoot := filepath.Join(manager.Root, ".tmp-"+restoreID)
	finalRoot := filepath.Join(manager.Root, restoreID)
	if err := os.Mkdir(temporaryRoot, 0o700); err != nil {
		return RestoreOperation{}, err
	}
	defer os.RemoveAll(temporaryRoot)
	uploadPath := filepath.Join(temporaryRoot, "upload.gvpn-vps")
	upload, err := os.OpenFile(uploadPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return RestoreOperation{}, errors.New("create bounded VPS restore upload failed")
	}
	digest := sha256.New()
	written, copyErr := copyContext(ctx, io.MultiWriter(upload, digest), io.LimitReader(encrypted, backup.MaximumPortableBackupBytes+1))
	if written > backup.MaximumPortableBackupBytes {
		upload.Close()
		return RestoreOperation{}, ErrRestoreUploadTooLarge
	}
	if copyErr != nil || written <= 0 {
		upload.Close()
		return RestoreOperation{}, errors.New("encrypted VPS restore upload is incomplete")
	}
	if err := upload.Sync(); err != nil {
		upload.Close()
		return RestoreOperation{}, errors.New("sync encrypted VPS restore upload failed")
	}
	if err := upload.Close(); err != nil {
		return RestoreOperation{}, errors.New("close encrypted VPS restore upload failed")
	}
	archivePath := filepath.Join(temporaryRoot, "payload.zip")
	archiveBytes, err := backup.DecryptVPSBackupToZIP(ctx, uploadPath, archivePath, passphrase)
	passphrase = ""
	if err != nil {
		return RestoreOperation{}, errors.New("VPS restore passphrase or backup artifact is invalid")
	}
	manifest, identity, err := manager.extractAndVerify(ctx, archivePath, filepath.Join(temporaryRoot, "tree"))
	if err != nil {
		return RestoreOperation{}, err
	}
	liveIdentity, err := vpsagent.ReadIdentity(ctx, manager.Database)
	if err != nil {
		return RestoreOperation{}, errors.New("read live VPS identity for restore preview failed")
	}
	identityMatches := liveIdentity.VPSID == identity.VPSID && liveIdentity.IdentityFingerprint == identity.IdentityFingerprint && liveIdentity.PublicKey == identity.PublicKey
	allowedModes := []string{RestoreModeNewVPS}
	if identityMatches {
		allowedModes = []string{RestoreModeSameVPS, RestoreModeNewVPS}
	}
	if err := os.Remove(uploadPath); err != nil {
		return RestoreOperation{}, errors.New("remove encrypted VPS restore upload failed")
	}
	if err := os.Remove(archivePath); err != nil {
		return RestoreOperation{}, errors.New("remove decrypted VPS restore ZIP failed")
	}
	operation := RestoreOperation{
		FormatVersion: FormatVersion, RestoreID: restoreID, State: RestoreStateStaged,
		CreatedAt: manager.now().Format(time.RFC3339Nano), BackupID: manifest.BackupID,
		SourceVPSID: identity.VPSID, SourceIdentityFingerprint: identity.IdentityFingerprint,
		LiveVPSID: liveIdentity.VPSID, LiveIdentityFingerprint: liveIdentity.IdentityFingerprint,
		SchemaVersion: manifest.SchemaVersion, AgentVersion: manifest.AgentVersion,
		PortableBytes: written, PortableSHA256: hex.EncodeToString(digest.Sum(nil)), ArchiveBytes: archiveBytes,
		PayloadBytes: manifest.PayloadBytes, Files: len(manifest.Files), AllowedModes: allowedModes,
		IdentityMatches: identityMatches, CloneQuarantineOnSameVPS: true,
	}
	if err := writeJSON(filepath.Join(temporaryRoot, "operation.json"), operation, false); err != nil {
		return RestoreOperation{}, err
	}
	if err := writeJSON(filepath.Join(temporaryRoot, "manifest.json"), manifest, false); err != nil {
		return RestoreOperation{}, err
	}
	if err := syncDirectory(temporaryRoot); err != nil {
		return RestoreOperation{}, err
	}
	if err := os.Rename(temporaryRoot, finalRoot); err != nil {
		return RestoreOperation{}, errors.New("commit VPS restore staging failed")
	}
	if err := syncDirectory(manager.Root); err != nil {
		return RestoreOperation{}, err
	}
	if err := writeJSON(manager.pendingPath(), operation, false); err != nil {
		_ = removeVerifiedTree(finalRoot)
		return RestoreOperation{}, err
	}
	return operation, nil
}

func (manager *RestoreManager) Status() (RestoreOperation, bool, error) {
	manager.mutex.Lock()
	defer manager.mutex.Unlock()
	if err := manager.prepareRoot(); err != nil {
		return RestoreOperation{}, false, err
	}
	return manager.readPending()
}

// AuthorizeApply is a separate durable transition used only after WebUI has
// re-authenticated the administrator and checked the typed confirmation. The
// raw confirmation and password are intentionally not accepted or persisted
// by this storage layer.
func (manager *RestoreManager) AuthorizeApply(restoreID, mode string) (RestoreOperation, error) {
	manager.mutex.Lock()
	defer manager.mutex.Unlock()
	operation, exists, err := manager.readPending()
	if err != nil {
		return RestoreOperation{}, err
	}
	if !exists || operation.RestoreID != restoreID || !vpsRestoreIDPattern.MatchString(restoreID) || !containsMode(operation.AllowedModes, mode) || operation.State != RestoreStateStaged && operation.State != RestoreStateApplyRequested {
		return RestoreOperation{}, ErrRestoreNotPending
	}
	if operation.State == RestoreStateApplyRequested {
		if operation.SelectedMode != mode {
			return RestoreOperation{}, errors.New("VPS restore is already authorized for another mode")
		}
		return operation, nil
	}
	authorization := make([]byte, 32)
	if _, err := rand.Read(authorization); err != nil {
		return RestoreOperation{}, errors.New("generate VPS restore authorization failed")
	}
	operation.State = RestoreStateApplyRequested
	operation.SelectedMode = mode
	operation.ApplyAuthorization = hex.EncodeToString(authorization)
	operation.ApplyErrorCode = ""
	operation.AppliedAt = ""
	root := filepath.Join(manager.Root, operation.RestoreID)
	if err := writeJSON(filepath.Join(root, "operation.json"), operation, true); err != nil {
		return RestoreOperation{}, err
	}
	if err := writeJSON(manager.pendingPath(), operation, true); err != nil {
		return RestoreOperation{}, err
	}
	return operation, nil
}

func (manager *RestoreManager) VerifyPending(ctx context.Context) (VerifiedRestore, error) {
	manager.mutex.Lock()
	defer manager.mutex.Unlock()
	operation, exists, err := manager.readPending()
	if err != nil {
		return VerifiedRestore{}, err
	}
	if !exists {
		return VerifiedRestore{}, ErrRestoreNotPending
	}
	root := filepath.Join(manager.Root, operation.RestoreID)
	stagedOperation, err := readOperation(filepath.Join(root, "operation.json"))
	if err != nil || !equalRestoreOperation(stagedOperation, operation) {
		return VerifiedRestore{}, errors.New("staged VPS restore operation does not match pending marker")
	}
	manifest, err := readManifest(filepath.Join(root, "manifest.json"))
	if err != nil || manifest.BackupID != operation.BackupID || manifest.SourceVPSID != operation.SourceVPSID || manifest.IdentityFingerprint != operation.SourceIdentityFingerprint || manifest.SchemaVersion != operation.SchemaVersion || manifest.PayloadBytes != operation.PayloadBytes || len(manifest.Files) != operation.Files {
		return VerifiedRestore{}, errors.New("staged VPS restore manifest does not match operation")
	}
	identity, err := manager.verifyTree(ctx, filepath.Join(root, "tree"), manifest)
	if err != nil {
		return VerifiedRestore{}, err
	}
	return VerifiedRestore{Operation: operation, Manifest: manifest, TreeRoot: filepath.Join(root, "tree"), Identity: identity}, nil
}

func (manager *RestoreManager) Discard(restoreID string) error {
	manager.mutex.Lock()
	defer manager.mutex.Unlock()
	operation, exists, err := manager.readPending()
	if err != nil {
		return err
	}
	if !exists || operation.RestoreID != restoreID || !vpsRestoreIDPattern.MatchString(restoreID) || operation.State != RestoreStateStaged {
		return ErrRestoreNotPending
	}
	if err := os.Remove(manager.pendingPath()); err != nil {
		return err
	}
	if err := syncDirectory(manager.Root); err != nil {
		return err
	}
	return removeVerifiedTree(filepath.Join(manager.Root, restoreID))
}

func (manager *RestoreManager) markApplyFailure(restoreID, code string) error {
	manager.mutex.Lock()
	defer manager.mutex.Unlock()
	operation, exists, err := manager.readPending()
	if err != nil {
		return err
	}
	if !exists || operation.RestoreID != restoreID || operation.State != RestoreStateApplyRequested || !validErrorCode(code) {
		return ErrRestoreNotPending
	}
	operation.State = RestoreStateStaged
	operation.SelectedMode = ""
	operation.ApplyAuthorization = ""
	operation.ApplyErrorCode = code
	if err := writeJSON(filepath.Join(manager.Root, restoreID, "operation.json"), operation, true); err != nil {
		return err
	}
	return writeJSON(manager.pendingPath(), operation, true)
}

func (manager *RestoreManager) complete(restoreID string, result ApplyResult) error {
	manager.mutex.Lock()
	defer manager.mutex.Unlock()
	operation, exists, err := manager.readPending()
	if err != nil {
		return err
	}
	if !exists || operation.RestoreID != restoreID || operation.State != RestoreStateApplyRequested || result.RestoreID != restoreID {
		return ErrRestoreNotPending
	}
	if _, err := time.Parse(time.RFC3339Nano, result.AppliedAt); err != nil {
		return errors.New("valid VPS restore completion timestamp is required")
	}
	operation.State = RestoreStateApplied
	operation.ApplyAuthorization = ""
	operation.AppliedAt = result.AppliedAt
	operation.ApplyErrorCode = ""
	lastRoot := filepath.Join(manager.StateDirectory, "recovery")
	if err := secureDirectory(lastRoot); err != nil {
		return err
	}
	if err := writeJSON(filepath.Join(lastRoot, "last-vps-restore.json"), operation, true); err != nil {
		return err
	}
	if err := os.Remove(manager.pendingPath()); err != nil {
		return err
	}
	if err := syncDirectory(manager.Root); err != nil {
		return err
	}
	return removeVerifiedTree(filepath.Join(manager.Root, restoreID))
}

func (manager *RestoreManager) extractAndVerify(ctx context.Context, archivePath, treeRoot string) (Manifest, vpsagent.Identity, error) {
	archive, err := zip.OpenReader(archivePath)
	if err != nil {
		return Manifest{}, vpsagent.Identity{}, errors.New("decrypted VPS restore payload is not a ZIP archive")
	}
	defer archive.Close()
	if len(archive.File) < 2 || len(archive.File) > MaximumFiles+1 {
		return Manifest{}, vpsagent.Identity{}, errors.New("VPS restore archive file count is invalid")
	}
	entries := make(map[string]*zip.File, len(archive.File))
	var total uint64
	for _, entry := range archive.File {
		if !safePath(entry.Name) || entry.FileInfo().IsDir() || !entry.Mode().IsRegular() || entry.Mode().Perm()&0o022 != 0 {
			return Manifest{}, vpsagent.Identity{}, errors.New("VPS restore archive contains an unsafe entry")
		}
		if _, exists := entries[entry.Name]; exists || entry.UncompressedSize64 > uint64(backup.MaximumPortablePlainBytes) || total > uint64(backup.MaximumPortablePlainBytes)-entry.UncompressedSize64 {
			return Manifest{}, vpsagent.Identity{}, errors.New("VPS restore archive is duplicated or oversized")
		}
		total += entry.UncompressedSize64
		entries[entry.Name] = entry
	}
	manifestEntry, exists := entries["manifest.json"]
	if !exists || manifestEntry.UncompressedSize64 == 0 || manifestEntry.UncompressedSize64 > uint64(MaximumManifestBytes) {
		return Manifest{}, vpsagent.Identity{}, errors.New("VPS restore manifest is missing or oversized")
	}
	manifestContent, err := readZIPFile(manifestEntry, int64(manifestEntry.UncompressedSize64))
	if err != nil {
		return Manifest{}, vpsagent.Identity{}, err
	}
	var manifest Manifest
	if err := decodeStrict(manifestContent, &manifest); err != nil || !validManifest(manifest) || len(manifest.Files) != len(entries)-1 {
		return Manifest{}, vpsagent.Identity{}, errors.New("VPS restore manifest contract is invalid")
	}
	if err := os.MkdirAll(treeRoot, 0o700); err != nil {
		return Manifest{}, vpsagent.Identity{}, err
	}
	seen := make(map[string]struct{}, len(manifest.Files))
	var payload int64
	for _, record := range manifest.Files {
		if !allowedRestorePath(record.Path) || record.Bytes < 0 || record.Bytes > MaximumFileBytes || !digestPattern.MatchString(record.SHA256) || record.Mode != 0o600 {
			return Manifest{}, vpsagent.Identity{}, errors.New("VPS restore manifest contains an unsafe file")
		}
		if _, exists := seen[record.Path]; exists {
			return Manifest{}, vpsagent.Identity{}, errors.New("VPS restore manifest contains a duplicate file")
		}
		seen[record.Path] = struct{}{}
		entry, exists := entries[record.Path]
		if !exists || int64(entry.UncompressedSize64) != record.Bytes || payload > backup.MaximumPortablePlainBytes-record.Bytes {
			return Manifest{}, vpsagent.Identity{}, errors.New("VPS restore archive does not match manifest")
		}
		payload += record.Bytes
		destination := filepath.Join(treeRoot, filepath.FromSlash(record.Path))
		if err := os.MkdirAll(filepath.Dir(destination), 0o700); err != nil {
			return Manifest{}, vpsagent.Identity{}, err
		}
		reader, err := entry.Open()
		if err != nil {
			return Manifest{}, vpsagent.Identity{}, err
		}
		file, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err != nil {
			reader.Close()
			return Manifest{}, vpsagent.Identity{}, err
		}
		hash := sha256.New()
		written, copyErr := copyContext(ctx, io.MultiWriter(file, hash), io.LimitReader(reader, record.Bytes+1))
		readerErr := reader.Close()
		syncErr := file.Sync()
		closeErr := file.Close()
		if copyErr != nil || readerErr != nil || syncErr != nil || closeErr != nil || written != record.Bytes || hex.EncodeToString(hash.Sum(nil)) != record.SHA256 {
			return Manifest{}, vpsagent.Identity{}, errors.New("VPS restore entry failed verification")
		}
	}
	if payload != manifest.PayloadBytes {
		return Manifest{}, vpsagent.Identity{}, errors.New("VPS restore payload total does not match manifest")
	}
	identity, err := manager.verifyTree(ctx, treeRoot, manifest)
	return manifest, identity, err
}

func (manager *RestoreManager) verifyTree(ctx context.Context, treeRoot string, manifest Manifest) (vpsagent.Identity, error) {
	for _, record := range manifest.Files {
		path := filepath.Join(treeRoot, filepath.FromSlash(record.Path))
		info, err := os.Lstat(path)
		if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() != record.Bytes || runtime.GOOS != "windows" && info.Mode().Perm()&0o022 != 0 {
			return vpsagent.Identity{}, errors.New("staged VPS restore tree contains an unsafe file")
		}
		digest, err := hashPath(ctx, path, record.Bytes)
		if err != nil || digest != record.SHA256 {
			return vpsagent.Identity{}, errors.New("staged VPS restore tree failed hash verification")
		}
	}
	configuration := filepath.Join(treeRoot, "config", "config.yaml")
	if info, err := os.Lstat(configuration); err != nil || !info.Mode().IsRegular() || info.Size() == 0 {
		return vpsagent.Identity{}, errors.New("staged VPS configuration is invalid")
	}
	databasePath := filepath.Join(treeRoot, "database", "state.db")
	database, err := databasepkg.OpenImmutable(ctx, databasePath)
	if err != nil {
		return vpsagent.Identity{}, errors.New("staged VPS database failed verification")
	}
	identity, identityErr := vpsagent.ReadIdentity(ctx, database)
	verifyErr := vpsagent.Verify(ctx, database)
	closeErr := database.Close()
	for _, suffix := range []string{"-wal", "-shm"} {
		_ = os.Remove(databasePath + suffix)
	}
	if identityErr != nil || verifyErr != nil || closeErr != nil || identity.VPSID != manifest.SourceVPSID || identity.IdentityFingerprint != manifest.IdentityFingerprint {
		return vpsagent.Identity{}, errors.New("staged VPS identity or database does not match manifest")
	}
	for _, secretRef := range []string{identity.PrivateKeySecretRef, identity.UpdateIdentityRef} {
		archivePath, err := archivePathForSecretRef(secretRef)
		if err != nil {
			return vpsagent.Identity{}, err
		}
		if _, err := os.Lstat(filepath.Join(treeRoot, filepath.FromSlash(archivePath))); err != nil {
			return vpsagent.Identity{}, errors.New("staged VPS identity secret is missing")
		}
	}
	for _, required := range []string{"state/tls/cert.pem", "state/tls/key.pem"} {
		if _, err := os.Lstat(filepath.Join(treeRoot, filepath.FromSlash(required))); err != nil {
			return vpsagent.Identity{}, errors.New("staged VPS TLS identity is missing")
		}
	}
	return identity, nil
}

func validManifest(manifest Manifest) bool {
	if manifest.FormatVersion != FormatVersion || manifest.Role != "vps" || !backupIDPattern.MatchString(manifest.BackupID) || strings.TrimSpace(manifest.AgentVersion) == "" || manifest.SourceVPSID == "" || !digestPattern.MatchString(manifest.IdentityFingerprint) || manifest.SchemaVersion != vpsagent.SchemaVersion || manifest.PayloadBytes < 0 || manifest.PayloadBytes > backup.MaximumPortablePlainBytes || !manifest.SecretsIncluded || len(manifest.Files) < 4 || len(manifest.Files) > MaximumFiles {
		return false
	}
	_, err := time.Parse(time.RFC3339Nano, manifest.CreatedAt)
	return err == nil
}

func allowedRestorePath(path string) bool {
	if !safePath(path) {
		return false
	}
	return path == "database/state.db" || path == "config/config.yaml" || strings.HasPrefix(path, "state/secrets/") || strings.HasPrefix(path, "state/tls/")
}

func readZIPFile(entry *zip.File, expected int64) ([]byte, error) {
	reader, err := entry.Open()
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	content, err := io.ReadAll(io.LimitReader(reader, expected+1))
	if err != nil || int64(len(content)) != expected {
		return nil, errors.New("read VPS restore ZIP entry failed")
	}
	return content, nil
}

func (manager *RestoreManager) prepareRoot() error {
	return secureDirectory(manager.Root)
}

func (manager *RestoreManager) pendingPath() string {
	return filepath.Join(manager.Root, "pending.json")
}

func (manager *RestoreManager) readPending() (RestoreOperation, bool, error) {
	operation, err := readOperation(manager.pendingPath())
	if errors.Is(err, os.ErrNotExist) {
		return RestoreOperation{}, false, nil
	}
	if err != nil || !validOperation(operation) {
		return RestoreOperation{}, false, errors.New("pending VPS restore marker is invalid")
	}
	return operation, true, nil
}

func readOperation(path string) (RestoreOperation, error) {
	var operation RestoreOperation
	content, err := readSmallJSON(path)
	if err != nil {
		return operation, err
	}
	return operation, decodeStrict(content, &operation)
}

func readManifest(path string) (Manifest, error) {
	var manifest Manifest
	content, err := readSmallJSON(path)
	if err != nil {
		return manifest, err
	}
	if err := decodeStrict(content, &manifest); err != nil || !validManifest(manifest) {
		return Manifest{}, errors.New("staged VPS restore manifest is invalid")
	}
	return manifest, nil
}

func readSmallJSON(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > MaximumManifestBytes {
		return nil, errors.New("VPS restore JSON file is unsafe")
	}
	return os.ReadFile(path)
}

func writeJSON(path string, value any, replace bool) error {
	content, err := json.MarshalIndent(value, "", "  ")
	if err != nil || int64(len(content)) > MaximumManifestBytes {
		return errors.New("encode VPS restore JSON failed")
	}
	content = append(content, '\n')
	temporary, err := os.CreateTemp(filepath.Dir(path), ".restore-json-")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(content); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if !replace {
		if _, err := os.Lstat(path); err == nil {
			return errors.New("VPS restore JSON already exists")
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	if replace && runtime.GOOS == "windows" {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return err
	}
	return syncDirectory(filepath.Dir(path))
}

func decodeStrict(content []byte, destination any) error {
	decoder := json.NewDecoder(strings.NewReader(string(content)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("VPS restore JSON contains trailing data")
	}
	return nil
}

func validOperation(operation RestoreOperation) bool {
	if operation.FormatVersion != FormatVersion || !vpsRestoreIDPattern.MatchString(operation.RestoreID) || !backupIDPattern.MatchString(operation.BackupID) || operation.SourceVPSID == "" || operation.LiveVPSID == "" || !digestPattern.MatchString(operation.SourceIdentityFingerprint) || !digestPattern.MatchString(operation.LiveIdentityFingerprint) || operation.SchemaVersion != vpsagent.SchemaVersion || strings.TrimSpace(operation.AgentVersion) == "" || operation.PortableBytes <= 0 || operation.PortableBytes > backup.MaximumPortableBackupBytes || !digestPattern.MatchString(operation.PortableSHA256) || operation.ArchiveBytes <= 0 || operation.ArchiveBytes > backup.MaximumPortablePlainBytes || operation.PayloadBytes < 0 || operation.PayloadBytes > backup.MaximumPortablePlainBytes || operation.Files < 4 || operation.Files > MaximumFiles {
		return false
	}
	if _, err := time.Parse(time.RFC3339Nano, operation.CreatedAt); err != nil {
		return false
	}
	if operation.IdentityMatches != (operation.SourceVPSID == operation.LiveVPSID && operation.SourceIdentityFingerprint == operation.LiveIdentityFingerprint) {
		return false
	}
	expected := []string{RestoreModeNewVPS}
	if operation.IdentityMatches {
		expected = []string{RestoreModeSameVPS, RestoreModeNewVPS}
	}
	if !equalStrings(operation.AllowedModes, expected) || !operation.CloneQuarantineOnSameVPS {
		return false
	}
	switch operation.State {
	case RestoreStateStaged:
		return operation.SelectedMode == "" && operation.ApplyAuthorization == "" && operation.AppliedAt == "" && (operation.ApplyErrorCode == "" || validErrorCode(operation.ApplyErrorCode))
	case RestoreStateApplyRequested:
		return containsMode(operation.AllowedModes, operation.SelectedMode) && digestPattern.MatchString(operation.ApplyAuthorization) && operation.ApplyErrorCode == "" && operation.AppliedAt == ""
	default:
		return false
	}
}

func containsMode(modes []string, mode string) bool {
	for _, candidate := range modes {
		if candidate == mode {
			return true
		}
	}
	return false
}

func validErrorCode(code string) bool {
	if code == "" || len(code) > 64 {
		return false
	}
	for _, character := range code {
		if character != '_' && (character < 'A' || character > 'Z') && (character < '0' || character > '9') {
			return false
		}
	}
	return true
}

func equalRestoreOperation(left, right RestoreOperation) bool {
	leftModes, rightModes := left.AllowedModes, right.AllowedModes
	left.AllowedModes, right.AllowedModes = nil, nil
	return reflect.DeepEqual(left, right) && equalStrings(leftModes, rightModes)
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func newVPSRestoreID() (string, error) {
	random := make([]byte, 16)
	if _, err := rand.Read(random); err != nil {
		return "", err
	}
	return "vps-restore-" + hex.EncodeToString(random), nil
}

func removeVerifiedTree(root string) error {
	if !vpsRestoreIDPattern.MatchString(filepath.Base(root)) || !strings.Contains(filepath.ToSlash(root), "/recovery/restores/") {
		return errors.New("refuse to remove unmanaged VPS restore tree")
	}
	return removeSafePath(root)
}

func (manager *RestoreManager) now() time.Time {
	if manager.Now != nil {
		return manager.Now().UTC()
	}
	return time.Now().UTC()
}
