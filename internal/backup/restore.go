package backup

import (
	"archive/zip"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"

	"gateway-vpn/internal/config"
)

var (
	ErrRestorePending        = errors.New("a restore operation is already pending")
	ErrRestoreNotPending     = errors.New("the restore operation is not pending")
	ErrRestoreNotAuthorized  = errors.New("restore apply was not explicitly authorized")
	ErrRestoreUploadTooLarge = errors.New("the encrypted restore upload exceeds its bound")
	restoreIDPattern         = regexp.MustCompile(`^restore-[a-f0-9]{32}$`)
)

const (
	RestoreStateStaged         = "STAGED"
	RestoreStateApplyRequested = "APPLY_REQUESTED"
	RestoreStateApplied        = "APPLIED"
)

type RestoreOperation struct {
	FormatVersion      int    `json:"format_version"`
	RestoreID          string `json:"restore_id"`
	State              string `json:"state"`
	CreatedAt          string `json:"created_at"`
	SnapshotID         string `json:"snapshot_id"`
	SchemaVersion      int64  `json:"schema_version"`
	GatewayVersion     string `json:"gateway_version"`
	PortableBytes      int64  `json:"portable_bytes"`
	PortableSHA256     string `json:"portable_sha256"`
	ArchiveBytes       int64  `json:"archive_bytes"`
	PayloadBytes       int64  `json:"payload_bytes"`
	Files              int    `json:"files"`
	ApplyAuthorization string `json:"apply_authorization,omitempty"`
	ApplyErrorCode     string `json:"apply_error_code,omitempty"`
	AppliedAt          string `json:"applied_at,omitempty"`
}

type VerifiedRestore struct {
	Operation RestoreOperation
	Manifest  PortableManifest
	TreeRoot  string
}

type RestoreManager struct {
	StateDirectory         string
	DatabasePath           string
	ConfigurationPath      string
	ExpectedStateDirectory string
	ExpectedDatabasePath   string
	ExpectedMihomoBinary   string
	ExpectedAPISecretPath  string
	ExpectedTLSCertPath    string
	ExpectedTLSKeyPath     string
	Root                   string
	Now                    func() time.Time
	mutex                  sync.Mutex
}

func NewRestoreManager(stateDirectory, databasePath, configurationPath string) (*RestoreManager, error) {
	if !filepath.IsAbs(stateDirectory) || !filepath.IsAbs(databasePath) || !filepath.IsAbs(configurationPath) {
		return nil, errors.New("restore manager requires absolute state, database, and configuration paths")
	}
	stateDirectory = filepath.Clean(stateDirectory)
	databasePath = filepath.Clean(databasePath)
	relative, err := filepath.Rel(stateDirectory, databasePath)
	if err != nil || relative == "." || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return nil, errors.New("restore database must be inside the state directory")
	}
	return &RestoreManager{
		StateDirectory: stateDirectory, DatabasePath: databasePath, ConfigurationPath: filepath.Clean(configurationPath),
		ExpectedStateDirectory: stateDirectory, ExpectedDatabasePath: databasePath,
		ExpectedMihomoBinary:  "/opt/gateway-vpn/current/libexec/mihomo",
		ExpectedAPISecretPath: filepath.Join(stateDirectory, "secrets", "mihomo-api-secret"),
		ExpectedTLSCertPath:   filepath.Join(stateDirectory, "tls", "cert.pem"),
		ExpectedTLSKeyPath:    filepath.Join(stateDirectory, "tls", "key.pem"),
		Root:                  filepath.Join(stateDirectory, "recovery", "restores"),
	}, nil
}

// Stage consumes an encrypted portable artifact, authenticates it with the
// supplied passphrase, validates every ZIP entry against manifest hashes and
// fixed restore roots, and leaves one durable pending operation. No passphrase
// or encrypted upload remains after staging.
func (manager *RestoreManager) Stage(ctx context.Context, encrypted io.Reader, passphrase string) (RestoreOperation, error) {
	manager.mutex.Lock()
	defer manager.mutex.Unlock()
	if encrypted == nil {
		return RestoreOperation{}, errors.New("encrypted restore input is required")
	}
	if err := ValidatePassphrase(passphrase); err != nil {
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
	restoreID, err := newRestoreID()
	if err != nil {
		return RestoreOperation{}, err
	}
	temporaryDirectory := filepath.Join(manager.Root, ".tmp-"+restoreID)
	finalDirectory := filepath.Join(manager.Root, restoreID)
	if err := os.Mkdir(temporaryDirectory, 0o700); err != nil {
		return RestoreOperation{}, fmt.Errorf("create restore staging directory: %w", err)
	}
	defer os.RemoveAll(temporaryDirectory)
	encryptedPath := filepath.Join(temporaryDirectory, "upload.gvpn")
	upload, err := os.OpenFile(encryptedPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return RestoreOperation{}, errors.New("create bounded restore upload failed")
	}
	digest := sha256.New()
	written, copyErr := copyWithContext(ctx, io.MultiWriter(upload, digest), io.LimitReader(encrypted, MaximumPortableBackupBytes+1))
	if written > MaximumPortableBackupBytes {
		upload.Close()
		return RestoreOperation{}, ErrRestoreUploadTooLarge
	}
	if copyErr != nil || written <= 0 {
		upload.Close()
		return RestoreOperation{}, errors.New("encrypted restore upload exceeds its bound or is incomplete")
	}
	if err := upload.Sync(); err != nil {
		upload.Close()
		return RestoreOperation{}, errors.New("sync encrypted restore upload failed")
	}
	if err := upload.Close(); err != nil {
		return RestoreOperation{}, errors.New("close encrypted restore upload failed")
	}
	portableDigest := hex.EncodeToString(digest.Sum(nil))
	zipPath := filepath.Join(temporaryDirectory, "payload.zip")
	plainBytes, err := DecryptToZIP(ctx, encryptedPath, zipPath, passphrase)
	passphrase = ""
	if err != nil {
		return RestoreOperation{}, errors.New("restore passphrase or backup artifact is invalid")
	}
	manifest, err := manager.extractAndVerify(ctx, zipPath, filepath.Join(temporaryDirectory, "tree"))
	if err != nil {
		return RestoreOperation{}, err
	}
	if err := os.Remove(encryptedPath); err != nil {
		return RestoreOperation{}, errors.New("remove encrypted restore staging upload failed")
	}
	if err := os.Remove(zipPath); err != nil {
		return RestoreOperation{}, errors.New("remove decrypted restore staging archive failed")
	}
	operation := RestoreOperation{
		FormatVersion: PortableFormatVersion, RestoreID: restoreID, State: RestoreStateStaged, CreatedAt: manager.now().Format(time.RFC3339Nano),
		SnapshotID: manifest.SnapshotID, SchemaVersion: manifest.SchemaVersion, GatewayVersion: manifest.GatewayVersion,
		PortableBytes: written, PortableSHA256: portableDigest, ArchiveBytes: plainBytes, PayloadBytes: manifest.PayloadBytes, Files: len(manifest.Files),
	}
	if err := writeJSONFile(filepath.Join(temporaryDirectory, "operation.json"), operation, false); err != nil {
		return RestoreOperation{}, err
	}
	if err := writePortableManifest(filepath.Join(temporaryDirectory, "portable-manifest.json"), manifest); err != nil {
		return RestoreOperation{}, err
	}
	if err := syncDirectory(temporaryDirectory); err != nil {
		return RestoreOperation{}, err
	}
	if err := os.Rename(temporaryDirectory, finalDirectory); err != nil {
		return RestoreOperation{}, fmt.Errorf("commit verified restore staging: %w", err)
	}
	if err := syncDirectory(manager.Root); err != nil {
		return RestoreOperation{}, err
	}
	if err := writeJSONFile(manager.pendingPath(), operation, false); err != nil {
		_ = removeRestoreDirectory(finalDirectory)
		return RestoreOperation{}, err
	}
	return operation, nil
}

// AuthorizeApply records the destructive confirmation as a separate durable
// state transition. The pointer-like pending marker is replaced first and the
// authoritative operation record second: after a power loss, readPending
// always returns the operation record, so a torn transition can remain STAGED
// but can never manufacture an APPLY_REQUESTED authorization.
func (manager *RestoreManager) AuthorizeApply(restoreID string) (RestoreOperation, error) {
	manager.mutex.Lock()
	defer manager.mutex.Unlock()
	if !restoreIDPattern.MatchString(restoreID) {
		return RestoreOperation{}, ErrRestoreNotPending
	}
	if err := manager.prepareRoot(); err != nil {
		return RestoreOperation{}, err
	}
	operation, pending, err := manager.readPending()
	if err != nil {
		return RestoreOperation{}, err
	}
	if !pending || operation.RestoreID != restoreID {
		return RestoreOperation{}, ErrRestoreNotPending
	}
	if operation.State != RestoreStateStaged && operation.State != RestoreStateApplyRequested {
		return RestoreOperation{}, ErrRestoreNotPending
	}
	if operation.State == RestoreStateStaged {
		authorization, err := newApplyAuthorization()
		if err != nil {
			return RestoreOperation{}, err
		}
		operation.ApplyAuthorization = authorization
	}
	operation.State = RestoreStateApplyRequested
	operation.ApplyErrorCode = ""
	operation.AppliedAt = ""
	if err := writeJSONFile(manager.pendingPath(), operation, true); err != nil {
		return RestoreOperation{}, err
	}
	if err := writeJSONFile(filepath.Join(manager.Root, restoreID, "operation.json"), operation, true); err != nil {
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

// VerifyPending revalidates the durable marker, the staged operation record,
// the authenticated portable manifest, every extracted file, SQLite, and the
// fixed bootstrap paths. A privileged applier must call this immediately
// before preparing live-file replacements.
func (manager *RestoreManager) VerifyPending(ctx context.Context) (VerifiedRestore, error) {
	manager.mutex.Lock()
	defer manager.mutex.Unlock()
	if err := manager.prepareRoot(); err != nil {
		return VerifiedRestore{}, err
	}
	operation, pending, err := manager.readPending()
	if err != nil {
		return VerifiedRestore{}, err
	}
	if !pending {
		return VerifiedRestore{}, ErrRestoreNotPending
	}
	if operation.State != RestoreStateApplyRequested {
		return VerifiedRestore{}, ErrRestoreNotAuthorized
	}
	operationRoot := filepath.Join(manager.Root, operation.RestoreID)
	stagedOperation, err := readRestoreOperation(filepath.Join(operationRoot, "operation.json"))
	if err != nil || stagedOperation != operation {
		return VerifiedRestore{}, errors.New("staged restore operation does not match its pending marker")
	}
	manifestPath := filepath.Join(operationRoot, "portable-manifest.json")
	manifestInfo, err := os.Lstat(manifestPath)
	if err != nil || manifestInfo.Mode()&os.ModeSymlink != 0 || !manifestInfo.Mode().IsRegular() || manifestInfo.Size() <= 0 || manifestInfo.Size() > maximumPortableManifestBytes {
		return VerifiedRestore{}, errors.New("staged portable manifest is unsafe")
	}
	manifestContent, err := os.ReadFile(manifestPath)
	if err != nil {
		return VerifiedRestore{}, errors.New("read staged portable manifest failed")
	}
	var manifest PortableManifest
	if err := decodeStrictJSON(manifestContent, &manifest); err != nil || !validPortableManifest(manifest) || operation.SnapshotID != manifest.SnapshotID || operation.SchemaVersion != manifest.SchemaVersion || operation.GatewayVersion != manifest.GatewayVersion || operation.PayloadBytes != manifest.PayloadBytes || operation.Files != len(manifest.Files) {
		return VerifiedRestore{}, errors.New("staged portable manifest contract does not match the restore operation")
	}
	treeRoot := filepath.Join(operationRoot, "tree")
	if err := manager.verifyRestoreTree(ctx, treeRoot, manifest); err != nil {
		return VerifiedRestore{}, err
	}
	return VerifiedRestore{Operation: operation, Manifest: manifest, TreeRoot: treeRoot}, nil
}

// Discard removes exactly the identified staged operation. It is used to
// compensate an HTTP upload whose multipart framing proved invalid only after
// the bounded encrypted file had been consumed. It never removes a different
// or already-applying operation.
func (manager *RestoreManager) Discard(_ context.Context, restoreID string) error {
	manager.mutex.Lock()
	defer manager.mutex.Unlock()
	if !restoreIDPattern.MatchString(restoreID) {
		return ErrRestoreNotPending
	}
	operation, pending, err := manager.readPending()
	if err != nil {
		return err
	}
	if !pending || operation.RestoreID != restoreID || operation.State != RestoreStateStaged {
		return ErrRestoreNotPending
	}
	if err := os.Remove(manager.pendingPath()); err != nil {
		return fmt.Errorf("remove pending restore marker: %w", err)
	}
	if err := syncDirectory(filepath.Dir(manager.pendingPath())); err != nil {
		return err
	}
	return removeRestoreDirectory(filepath.Join(manager.Root, restoreID))
}

func (manager *RestoreManager) markApplyFailure(restoreID, code string) error {
	manager.mutex.Lock()
	defer manager.mutex.Unlock()
	if !restoreIDPattern.MatchString(restoreID) || !validRestoreErrorCode(code) {
		return errors.New("valid restore id and apply failure code are required")
	}
	operation, pending, err := manager.readPending()
	if err != nil {
		return err
	}
	if !pending || operation.RestoreID != restoreID || operation.State != RestoreStateApplyRequested {
		return ErrRestoreNotPending
	}
	operation.State = RestoreStateStaged
	operation.ApplyAuthorization = ""
	operation.ApplyErrorCode = code
	if err := writeJSONFile(filepath.Join(manager.Root, restoreID, "operation.json"), operation, true); err != nil {
		return err
	}
	return writeJSONFile(manager.pendingPath(), operation, true)
}

func (manager *RestoreManager) complete(restoreID, appliedAt string) error {
	manager.mutex.Lock()
	defer manager.mutex.Unlock()
	operation, pending, err := manager.readPending()
	if err != nil {
		return err
	}
	if !pending || operation.RestoreID != restoreID || operation.State != RestoreStateApplyRequested {
		return ErrRestoreNotPending
	}
	if _, err := time.Parse(time.RFC3339Nano, appliedAt); err != nil {
		return errors.New("valid restore completion timestamp is required")
	}
	operation.State = RestoreStateApplied
	operation.ApplyAuthorization = ""
	operation.AppliedAt = appliedAt
	operation.ApplyErrorCode = ""
	if err := writeJSONFile(filepath.Join(manager.StateDirectory, "recovery", "last-restore.json"), operation, true); err != nil {
		return err
	}
	if err := os.Remove(manager.pendingPath()); err != nil {
		return fmt.Errorf("remove completed restore marker: %w", err)
	}
	if err := syncDirectory(filepath.Dir(manager.pendingPath())); err != nil {
		return err
	}
	return removeRestoreDirectory(filepath.Join(manager.Root, restoreID))
}

func (manager *RestoreManager) extractAndVerify(ctx context.Context, zipPath, treeRoot string) (PortableManifest, error) {
	archive, err := zip.OpenReader(zipPath)
	if err != nil {
		return PortableManifest{}, errors.New("decrypted restore payload is not a ZIP archive")
	}
	defer archive.Close()
	if len(archive.File) < 2 || len(archive.File) > MaximumPortableFiles+1 {
		return PortableManifest{}, errors.New("restore archive file count is invalid")
	}
	entries := make(map[string]*zip.File, len(archive.File))
	var total uint64
	for _, item := range archive.File {
		if !safePortablePath(item.Name) || item.FileInfo().IsDir() || !item.Mode().IsRegular() || item.Mode().Perm()&0o022 != 0 {
			return PortableManifest{}, errors.New("restore archive contains an unsafe entry")
		}
		if _, exists := entries[item.Name]; exists {
			return PortableManifest{}, errors.New("restore archive contains a duplicate entry")
		}
		if item.UncompressedSize64 > uint64(MaximumPortablePlainBytes) || total > uint64(MaximumPortablePlainBytes)-item.UncompressedSize64 {
			return PortableManifest{}, errors.New("restore archive uncompressed size exceeds its bound")
		}
		total += item.UncompressedSize64
		entries[item.Name] = item
	}
	manifestEntry, exists := entries["manifest.json"]
	if !exists || manifestEntry.UncompressedSize64 == 0 || manifestEntry.UncompressedSize64 > maximumPortableManifestBytes {
		return PortableManifest{}, errors.New("restore archive manifest is missing or oversized")
	}
	manifestContent, err := readZIPEntry(manifestEntry, int64(manifestEntry.UncompressedSize64))
	if err != nil {
		return PortableManifest{}, err
	}
	var manifest PortableManifest
	if err := decodeStrictJSON(manifestContent, &manifest); err != nil || !validPortableManifest(manifest) || len(manifest.Files) != len(entries)-1 {
		return PortableManifest{}, errors.New("restore archive manifest contract is invalid")
	}
	if _, err := time.Parse(time.RFC3339Nano, manifest.CreatedAt); err != nil {
		return PortableManifest{}, errors.New("restore archive manifest timestamp is invalid")
	}
	if err := os.MkdirAll(treeRoot, 0o700); err != nil {
		return PortableManifest{}, errors.New("create verified restore tree failed")
	}
	for _, directory := range []string{"state/secrets", "state/subscriptions", "state/tls", "state/mihomo/generations", "state/mihomo/state"} {
		if err := os.MkdirAll(filepath.Join(treeRoot, filepath.FromSlash(directory)), 0o700); err != nil {
			return PortableManifest{}, errors.New("create fixed restore root failed")
		}
	}
	seen := map[string]struct{}{}
	var payloadBytes int64
	for _, record := range manifest.Files {
		if !allowedPortableRestorePath(record.Path) || record.Bytes < 0 || !validDigest(record.SHA256) || record.Mode&0o022 != 0 {
			return PortableManifest{}, errors.New("restore manifest contains an unsafe file")
		}
		if _, duplicate := seen[record.Path]; duplicate {
			return PortableManifest{}, errors.New("restore manifest contains a duplicate file")
		}
		seen[record.Path] = struct{}{}
		entry, exists := entries[record.Path]
		if !exists || int64(entry.UncompressedSize64) != record.Bytes {
			return PortableManifest{}, errors.New("restore archive does not match its manifest")
		}
		if payloadBytes > MaximumPortablePlainBytes-record.Bytes {
			return PortableManifest{}, errors.New("restore manifest payload exceeds its bound")
		}
		payloadBytes += record.Bytes
		destination := filepath.Join(treeRoot, filepath.FromSlash(record.Path))
		if err := os.MkdirAll(filepath.Dir(destination), 0o700); err != nil {
			return PortableManifest{}, errors.New("create restore entry directory failed")
		}
		content, err := entry.Open()
		if err != nil {
			return PortableManifest{}, errors.New("open restore archive entry failed")
		}
		file, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err != nil {
			content.Close()
			return PortableManifest{}, errors.New("create restore tree entry failed")
		}
		hash := sha256.New()
		written, copyErr := copyWithContext(ctx, io.MultiWriter(file, hash), io.LimitReader(content, record.Bytes+1))
		contentErr := content.Close()
		syncErr := file.Sync()
		closeErr := file.Close()
		if copyErr != nil || contentErr != nil || syncErr != nil || closeErr != nil || written != record.Bytes || hex.EncodeToString(hash.Sum(nil)) != record.SHA256 {
			return PortableManifest{}, errors.New("restore entry failed hash or size verification")
		}
	}
	if payloadBytes != manifest.PayloadBytes {
		return PortableManifest{}, errors.New("restore manifest total does not match verified files")
	}
	databaseVerification, err := verifyDatabaseFile(ctx, filepath.Join(treeRoot, "database", "state.db"), DefaultMaximumDatabaseSize)
	if err != nil || databaseVerification.SchemaVersion != manifest.SchemaVersion {
		return PortableManifest{}, errors.New("restored database failed integrity or schema verification")
	}
	restoredConfigPath := filepath.Join(treeRoot, "config", "config.yaml")
	restoredConfig, err := config.Load(restoredConfigPath)
	if err != nil || manager.validateRestoredConfig(restoredConfig) != nil {
		return PortableManifest{}, errors.New("restored bootstrap configuration is invalid or targets different state paths")
	}
	return manifest, nil
}

func validPortableManifest(manifest PortableManifest) bool {
	if manifest.FormatVersion != PortableFormatVersion || !manifest.SecretsIncluded || manifest.SnapshotID == "" || manifest.SchemaVersion < 1 || len(manifest.Files) < 2 || len(manifest.Files) > MaximumPortableFiles || manifest.PayloadBytes <= 0 || manifest.PayloadBytes > MaximumPortablePlainBytes {
		return false
	}
	if _, err := time.Parse(time.RFC3339Nano, manifest.CreatedAt); err != nil {
		return false
	}
	required := map[string]bool{
		"database/state.db":               false,
		"config/config.yaml":              false,
		"state/secrets/mihomo-api-secret": false,
		"state/tls/cert.pem":              false,
		"state/tls/key.pem":               false,
	}
	for _, record := range manifest.Files {
		if _, exists := required[record.Path]; exists {
			required[record.Path] = true
		}
	}
	for _, present := range required {
		if !present {
			return false
		}
	}
	return true
}

func (manager *RestoreManager) verifyRestoreTree(ctx context.Context, treeRoot string, manifest PortableManifest) error {
	rootInfo, err := os.Lstat(treeRoot)
	if err != nil || rootInfo.Mode()&os.ModeSymlink != 0 || !rootInfo.IsDir() {
		return errors.New("verified restore tree root is unsafe")
	}
	records := make(map[string]PortableFile, len(manifest.Files))
	allowedDirectories := map[string]struct{}{".": {}}
	var expectedBytes int64
	for _, record := range manifest.Files {
		if !allowedPortableRestorePath(record.Path) || record.Bytes < 0 || !validDigest(record.SHA256) || record.Mode&0o022 != 0 {
			return errors.New("staged restore manifest contains an unsafe file")
		}
		if _, duplicate := records[record.Path]; duplicate {
			return errors.New("staged restore manifest contains a duplicate file")
		}
		if expectedBytes > MaximumPortablePlainBytes-record.Bytes {
			return errors.New("staged restore manifest exceeds its payload bound")
		}
		expectedBytes += record.Bytes
		records[record.Path] = record
		for directory := filepath.ToSlash(filepath.Dir(record.Path)); directory != "."; directory = filepath.ToSlash(filepath.Dir(directory)) {
			allowedDirectories[directory] = struct{}{}
		}
	}
	for _, directory := range []string{"database", "config", "state", "state/secrets", "state/subscriptions", "state/tls", "state/mihomo", "state/mihomo/generations", "state/mihomo/state"} {
		allowedDirectories[directory] = struct{}{}
	}
	if expectedBytes != manifest.PayloadBytes {
		return errors.New("staged restore manifest payload total is invalid")
	}
	seen := make(map[string]struct{}, len(records))
	var observedBytes int64
	err = filepath.WalkDir(treeRoot, func(current string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		info, err := os.Lstat(current)
		if err != nil || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("staged restore tree contains an unsafe entry")
		}
		relative, err := filepath.Rel(treeRoot, current)
		if err != nil {
			return err
		}
		relative = filepath.ToSlash(relative)
		if info.IsDir() {
			if _, allowed := allowedDirectories[relative]; !allowed {
				return errors.New("staged restore tree contains an unexpected directory")
			}
			return nil
		}
		if !info.Mode().IsRegular() || runtime.GOOS != "windows" && info.Mode().Perm()&0o022 != 0 {
			return errors.New("staged restore tree contains a non-private file")
		}
		record, exists := records[relative]
		if !exists || info.Size() != record.Bytes {
			return errors.New("staged restore tree does not match its manifest")
		}
		digest, err := hashRegularFile(ctx, current, record.Bytes)
		if err != nil || digest != record.SHA256 {
			return errors.New("staged restore file failed SHA-256 verification")
		}
		if observedBytes > MaximumPortablePlainBytes-record.Bytes {
			return errors.New("staged restore tree exceeds its payload bound")
		}
		observedBytes += record.Bytes
		seen[relative] = struct{}{}
		return nil
	})
	if err != nil {
		return err
	}
	if len(seen) != len(records) || observedBytes != manifest.PayloadBytes {
		return errors.New("staged restore tree is incomplete")
	}
	databaseVerification, err := verifyDatabaseFile(ctx, filepath.Join(treeRoot, "database", "state.db"), DefaultMaximumDatabaseSize)
	if err != nil || databaseVerification.SchemaVersion != manifest.SchemaVersion {
		return errors.New("staged restore database failed repeated integrity verification")
	}
	restoredConfig, err := config.Load(filepath.Join(treeRoot, "config", "config.yaml"))
	if err != nil || manager.validateRestoredConfig(restoredConfig) != nil {
		return errors.New("staged restore configuration failed repeated validation")
	}
	return nil
}

func (manager *RestoreManager) validateRestoredConfig(restored config.Config) error {
	expected := []struct{ actual, required string }{
		{restored.System.StateDir, manager.ExpectedStateDirectory},
		{restored.System.Database, manager.ExpectedDatabasePath},
		{restored.Mihomo.Binary, manager.ExpectedMihomoBinary},
		{restored.Mihomo.APISecretFile, manager.ExpectedAPISecretPath},
		{restored.API.TLSCert, manager.ExpectedTLSCertPath},
		{restored.API.TLSKey, manager.ExpectedTLSKeyPath},
	}
	for _, item := range expected {
		if item.required == "" || filepath.Clean(item.actual) != filepath.Clean(item.required) {
			return errors.New("restored configuration changes a fixed privileged path")
		}
	}
	return nil
}

func writePortableManifest(filename string, manifest PortableManifest) error {
	content, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return errors.New("encode staged portable manifest failed")
	}
	content = append(content, '\n')
	if len(content) == 0 || len(content) > maximumPortableManifestBytes {
		return errors.New("staged portable manifest exceeds its bound")
	}
	directory := filepath.Dir(filename)
	temporary, err := os.CreateTemp(directory, ".portable-manifest-")
	if err != nil {
		return errors.New("create staged portable manifest failed")
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(content); err != nil {
		temporary.Close()
		return errors.New("write staged portable manifest failed")
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return errors.New("sync staged portable manifest failed")
	}
	if err := temporary.Close(); err != nil {
		return errors.New("close staged portable manifest failed")
	}
	if err := os.Rename(temporaryName, filename); err != nil {
		return errors.New("commit staged portable manifest failed")
	}
	return syncDirectory(directory)
}

func (manager *RestoreManager) prepareRoot() error {
	return secureDirectory(manager.Root)
}

func (manager *RestoreManager) pendingPath() string {
	return filepath.Join(manager.StateDirectory, "recovery", "pending-restore.json")
}

func (manager *RestoreManager) readPending() (RestoreOperation, bool, error) {
	filename := manager.pendingPath()
	info, err := os.Lstat(filename)
	if errors.Is(err, os.ErrNotExist) {
		return RestoreOperation{}, false, nil
	}
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maximumManifestSize {
		return RestoreOperation{}, false, errors.New("pending restore marker is unsafe")
	}
	content, err := os.ReadFile(filename)
	if err != nil {
		return RestoreOperation{}, false, errors.New("read pending restore marker failed")
	}
	var operation RestoreOperation
	if err := decodeStrictJSON(content, &operation); err != nil || !validRestoreOperation(operation) {
		return RestoreOperation{}, false, errors.New("pending restore marker is invalid")
	}
	operationPath := filepath.Join(manager.Root, operation.RestoreID, "operation.json")
	storedOperation, err := readRestoreOperation(operationPath)
	if err != nil || !sameRestoreIdentity(operation, storedOperation) {
		return RestoreOperation{}, false, errors.New("pending restore operation record is missing or changed")
	}
	// operation.json is written before the pointer-like pending marker. If a
	// power loss occurs between those two atomic writes, immutable identity must
	// still match and the newer mutable state/error record remains authoritative.
	return storedOperation, true, nil
}

func readRestoreOperation(filename string) (RestoreOperation, error) {
	info, err := os.Lstat(filename)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maximumManifestSize {
		return RestoreOperation{}, errors.New("staged restore operation record is unsafe")
	}
	content, err := os.ReadFile(filename)
	if err != nil {
		return RestoreOperation{}, errors.New("read staged restore operation failed")
	}
	var operation RestoreOperation
	if err := decodeStrictJSON(content, &operation); err != nil || !validRestoreOperation(operation) {
		return RestoreOperation{}, errors.New("staged restore operation record is invalid")
	}
	return operation, nil
}

func validRestoreOperation(operation RestoreOperation) bool {
	if operation.FormatVersion != PortableFormatVersion || !restoreIDPattern.MatchString(operation.RestoreID) || operation.State == "" || operation.SnapshotID == "" || operation.SchemaVersion < 1 || operation.PortableBytes <= 0 || operation.PortableBytes > MaximumPortableBackupBytes || !validDigest(operation.PortableSHA256) || operation.ArchiveBytes <= 0 || operation.ArchiveBytes > MaximumPortablePlainBytes || operation.PayloadBytes <= 0 || operation.PayloadBytes > MaximumPortablePlainBytes || operation.Files < 2 || operation.Files > MaximumPortableFiles {
		return false
	}
	if _, err := time.Parse(time.RFC3339Nano, operation.CreatedAt); err != nil {
		return false
	}
	switch operation.State {
	case RestoreStateStaged:
		return operation.ApplyAuthorization == "" && operation.AppliedAt == "" && (operation.ApplyErrorCode == "" || validRestoreErrorCode(operation.ApplyErrorCode))
	case RestoreStateApplyRequested:
		return validDigest(operation.ApplyAuthorization) && operation.ApplyErrorCode == "" && operation.AppliedAt == ""
	case RestoreStateApplied:
		if operation.ApplyAuthorization != "" || operation.ApplyErrorCode != "" {
			return false
		}
		_, err := time.Parse(time.RFC3339Nano, operation.AppliedAt)
		return err == nil
	default:
		return false
	}
}

func newApplyAuthorization() (string, error) {
	value := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, value); err != nil {
		return "", errors.New("generate restore apply authorization failed")
	}
	return hex.EncodeToString(value), nil
}

func validRestoreErrorCode(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	for _, character := range value {
		if character != '_' && (character < 'A' || character > 'Z') && (character < '0' || character > '9') {
			return false
		}
	}
	return true
}

func sameRestoreIdentity(left, right RestoreOperation) bool {
	return left.FormatVersion == right.FormatVersion && left.RestoreID == right.RestoreID && left.CreatedAt == right.CreatedAt && left.SnapshotID == right.SnapshotID && left.SchemaVersion == right.SchemaVersion && left.GatewayVersion == right.GatewayVersion && left.PortableBytes == right.PortableBytes && left.PortableSHA256 == right.PortableSHA256 && left.ArchiveBytes == right.ArchiveBytes && left.PayloadBytes == right.PayloadBytes && left.Files == right.Files
}

func allowedPortableRestorePath(value string) bool {
	if value == "database/state.db" || value == "config/config.yaml" {
		return true
	}
	for _, prefix := range []string{"state/secrets/", "state/subscriptions/", "state/tls/", "state/mihomo/generations/", "state/mihomo/state/"} {
		if strings.HasPrefix(value, prefix) && len(value) > len(prefix) {
			return safePortablePath(value)
		}
	}
	return false
}

func readZIPEntry(entry *zip.File, expected int64) ([]byte, error) {
	reader, err := entry.Open()
	if err != nil {
		return nil, errors.New("open restore ZIP entry failed")
	}
	defer reader.Close()
	content, err := io.ReadAll(io.LimitReader(reader, expected+1))
	if err != nil || int64(len(content)) != expected {
		return nil, errors.New("read bounded restore ZIP entry failed")
	}
	return content, nil
}

func newRestoreID() (string, error) {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		return "", errors.New("generate restore id failed")
	}
	return "restore-" + hex.EncodeToString(value), nil
}

func removeRestoreDirectory(directory string) error {
	if !restoreIDPattern.MatchString(filepath.Base(directory)) {
		return errors.New("refuse to remove unmanaged restore directory")
	}
	info, err := os.Lstat(directory)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return errors.New("restore directory is unsafe")
	}
	paths := []string{}
	err = filepath.WalkDir(directory, func(current string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		entryInfo, err := os.Lstat(current)
		if err != nil || entryInfo.Mode()&os.ModeSymlink != 0 {
			return errors.New("restore tree contains an unsafe entry")
		}
		if !entryInfo.IsDir() && !entryInfo.Mode().IsRegular() {
			return errors.New("restore tree contains a non-regular entry")
		}
		paths = append(paths, current)
		return nil
	})
	if err != nil {
		return err
	}
	for index := len(paths) - 1; index >= 0; index-- {
		if err := os.Remove(paths[index]); err != nil {
			return fmt.Errorf("remove restore tree entry: %w", err)
		}
	}
	return syncDirectory(filepath.Dir(directory))
}

func (manager *RestoreManager) now() time.Time {
	if manager.Now != nil {
		return manager.Now().UTC()
	}
	return time.Now().UTC()
}
