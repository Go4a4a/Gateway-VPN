// Package vpsbackup implements the role-separated encrypted .gvpn-vps file.
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
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"time"

	"gateway-vpn/internal/backup"
	"gateway-vpn/internal/vpsagent"

	sqlite "modernc.org/sqlite"
)

const (
	FormatVersion        = 1
	MaximumFiles         = 1024
	MaximumManifestBytes = int64(1 << 20)
	MaximumFileBytes     = int64(128 << 20)
	productionStateRoot  = "/var/lib/gateway-vpn-vps/agent"
)

var (
	digestPattern   = regexp.MustCompile(`^[a-f0-9]{64}$`)
	backupIDPattern = regexp.MustCompile(`^vps-backup-[a-f0-9]{32}$`)
	filenamePattern = regexp.MustCompile(`^gateway-vpn-vps-backup-[0-9]{8}T[0-9]{6}Z-[a-f0-9]{24}\.gvpn-vps$`)
)

type FileRecord struct {
	Path   string `json:"path"`
	Bytes  int64  `json:"bytes"`
	SHA256 string `json:"sha256"`
	Mode   uint32 `json:"mode"`
}

type Manifest struct {
	FormatVersion       int          `json:"format_version"`
	Role                string       `json:"role"`
	BackupID            string       `json:"backup_id"`
	CreatedAt           string       `json:"created_at"`
	AgentVersion        string       `json:"agent_version"`
	SourceVPSID         string       `json:"source_vps_id"`
	IdentityFingerprint string       `json:"identity_fingerprint"`
	SchemaVersion       int64        `json:"schema_version"`
	Files               []FileRecord `json:"files"`
	PayloadBytes        int64        `json:"payload_bytes"`
	SecretsIncluded     bool         `json:"secrets_included"`
}

type Artifact struct {
	Filename string   `json:"filename"`
	Path     string   `json:"-"`
	Bytes    int64    `json:"bytes"`
	SHA256   string   `json:"sha256"`
	Manifest Manifest `json:"manifest"`
}

type Manager struct {
	Database          *sql.DB
	StateDirectory    string
	ConfigurationPath string
	AgentVersion      string
	ExportRoot        string
	Now               func() time.Time
}

type sourceFile struct {
	record FileRecord
	path   string
}

func NewManager(database *sql.DB, stateDirectory, configurationPath, agentVersion string) (*Manager, error) {
	if database == nil || !filepath.IsAbs(stateDirectory) || !filepath.IsAbs(configurationPath) || strings.TrimSpace(agentVersion) == "" {
		return nil, errors.New("VPS backup requires database, absolute paths, and Agent version")
	}
	stateDirectory = filepath.Clean(stateDirectory)
	return &Manager{
		Database: database, StateDirectory: stateDirectory, ConfigurationPath: filepath.Clean(configurationPath),
		AgentVersion: strings.TrimSpace(agentVersion), ExportRoot: filepath.Join(stateDirectory, "backups", "exports"),
	}, nil
}

func (manager *Manager) Build(ctx context.Context, passphrase string) (Artifact, error) {
	if err := backup.ValidatePassphrase(passphrase); err != nil {
		return Artifact{}, err
	}
	if err := manager.validate(); err != nil {
		return Artifact{}, err
	}
	if err := secureDirectory(manager.ExportRoot); err != nil {
		return Artifact{}, err
	}
	identity, err := vpsagent.ReadIdentity(ctx, manager.Database)
	if err != nil {
		return Artifact{}, fmt.Errorf("read VPS backup identity: %w", err)
	}
	if err := vpsagent.Verify(ctx, manager.Database); err != nil {
		return Artifact{}, fmt.Errorf("verify live VPS Agent database: %w", err)
	}
	workspace, err := os.MkdirTemp(manager.ExportRoot, ".build-")
	if err != nil {
		return Artifact{}, errors.New("create VPS backup workspace failed")
	}
	defer os.RemoveAll(workspace)
	if err := os.Chmod(workspace, 0o700); err != nil {
		return Artifact{}, err
	}
	databaseCopy := filepath.Join(workspace, "state.db")
	if err := onlineBackup(ctx, manager.Database, databaseCopy); err != nil {
		return Artifact{}, err
	}
	if err := vpsagent.SanitizePortableCopy(ctx, databaseCopy); err != nil {
		return Artifact{}, fmt.Errorf("sanitize portable VPS database: %w", err)
	}
	sources, total, err := manager.collectSources(ctx, databaseCopy, identity)
	if err != nil {
		return Artifact{}, err
	}
	now := manager.now()
	backupID, err := newBackupID()
	if err != nil {
		return Artifact{}, err
	}
	manifest := Manifest{
		FormatVersion: FormatVersion, Role: "vps", BackupID: backupID,
		CreatedAt: now.Format(time.RFC3339Nano), AgentVersion: manager.AgentVersion,
		SourceVPSID: identity.VPSID, IdentityFingerprint: identity.IdentityFingerprint,
		SchemaVersion: vpsagent.SchemaVersion, PayloadBytes: total, SecretsIncluded: true,
		Files: make([]FileRecord, 0, len(sources)),
	}
	for _, source := range sources {
		manifest.Files = append(manifest.Files, source.record)
	}
	manifestContent, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil || int64(len(manifestContent)) > MaximumManifestBytes {
		return Artifact{}, errors.New("encode VPS backup manifest failed")
	}
	manifestContent = append(manifestContent, '\n')
	randomSuffix := strings.TrimPrefix(backupID, "vps-backup-")[:24]
	filename := "gateway-vpn-vps-backup-" + now.Format("20060102T150405Z") + "-" + randomSuffix + ".gvpn-vps"
	temporary, err := os.CreateTemp(manager.ExportRoot, ".encrypted-")
	if err != nil {
		return Artifact{}, errors.New("create VPS encrypted backup failed")
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return Artifact{}, err
	}
	encrypted, err := backup.NewVPSArchiveEncryptWriter(temporary, passphrase)
	passphrase = ""
	if err != nil {
		temporary.Close()
		return Artifact{}, err
	}
	archive := zip.NewWriter(encrypted)
	writeBytes := func(name string, content []byte) error {
		header := &zip.FileHeader{Name: name, Method: zip.Deflate}
		header.SetMode(0o600)
		header.SetModTime(now)
		entry, err := archive.CreateHeader(header)
		if err != nil {
			return err
		}
		_, err = entry.Write(content)
		return err
	}
	if err := writeBytes("manifest.json", manifestContent); err != nil {
		closeBuildWriters(archive, encrypted, temporary)
		return Artifact{}, err
	}
	for _, source := range sources {
		if err := ctx.Err(); err != nil {
			closeBuildWriters(archive, encrypted, temporary)
			return Artifact{}, err
		}
		content, err := readStableFile(ctx, source.path, source.record)
		if err != nil || writeBytes(source.record.Path, content) != nil {
			closeBuildWriters(archive, encrypted, temporary)
			return Artifact{}, errors.New("archive VPS backup source failed")
		}
	}
	if err := archive.Close(); err != nil {
		encrypted.Close()
		temporary.Close()
		return Artifact{}, errors.New("finalize VPS backup ZIP failed")
	}
	if err := encrypted.Close(); err != nil {
		temporary.Close()
		return Artifact{}, err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return Artifact{}, errors.New("sync VPS encrypted backup failed")
	}
	if err := temporary.Close(); err != nil {
		return Artifact{}, err
	}
	bytes, digest, err := hashFile(temporaryPath, backup.MaximumPortableBackupBytes)
	if err != nil {
		return Artifact{}, err
	}
	finalPath := filepath.Join(manager.ExportRoot, filename)
	if err := os.Rename(temporaryPath, finalPath); err != nil {
		return Artifact{}, errors.New("commit VPS encrypted backup failed")
	}
	if err := syncDirectory(manager.ExportRoot); err != nil {
		return Artifact{}, err
	}
	return Artifact{Filename: filename, Path: finalPath, Bytes: bytes, SHA256: digest, Manifest: manifest}, nil
}

func (manager *Manager) Open(artifact Artifact) (io.ReadCloser, error) {
	if !filenamePattern.MatchString(artifact.Filename) || filepath.Base(artifact.Path) != artifact.Filename || filepath.Dir(filepath.Clean(artifact.Path)) != filepath.Clean(manager.ExportRoot) {
		return nil, errors.New("VPS backup artifact is outside the managed export root")
	}
	return openVerifiedArtifact(artifact)
}

func (manager *Manager) Remove(artifact Artifact) error {
	reader, err := manager.Open(artifact)
	if err != nil {
		return err
	}
	file, ok := reader.(*os.File)
	if !ok {
		reader.Close()
		return errors.New("VPS backup artifact handle is invalid")
	}
	openedInfo, err := file.Stat()
	if err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	currentInfo, err := os.Lstat(artifact.Path)
	if err != nil || currentInfo.Mode()&os.ModeSymlink != 0 || !os.SameFile(openedInfo, currentInfo) {
		return errors.New("VPS backup artifact changed before removal")
	}
	if err := os.Remove(artifact.Path); err != nil {
		return err
	}
	return syncDirectory(manager.ExportRoot)
}

func openVerifiedArtifact(artifact Artifact) (*os.File, error) {
	if artifact.Bytes <= 0 || artifact.Bytes > backup.MaximumPortableBackupBytes || !digestPattern.MatchString(artifact.SHA256) {
		return nil, errors.New("VPS backup artifact contract is invalid")
	}
	file, err := openStableFile(artifact.Path, artifact.Bytes)
	if err != nil {
		return nil, errors.New("VPS backup artifact failed final verification")
	}
	hash := sha256.New()
	written, err := io.Copy(hash, io.LimitReader(file, backup.MaximumPortableBackupBytes+1))
	if err != nil || written != artifact.Bytes || hex.EncodeToString(hash.Sum(nil)) != artifact.SHA256 {
		file.Close()
		return nil, errors.New("VPS backup artifact failed final verification")
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		file.Close()
		return nil, errors.New("rewind verified VPS backup artifact failed")
	}
	return file, nil
}

func (manager *Manager) collectSources(ctx context.Context, databaseCopy string, identity vpsagent.Identity) ([]sourceFile, int64, error) {
	sources := make([]sourceFile, 0, 32)
	seen := make(map[string]struct{})
	managedAdministratorFiles := make(map[string]struct{})
	rows, err := manager.Database.QueryContext(ctx, `
SELECT private_key_secret_ref FROM admin_peers
WHERE key_mode='MANAGED' AND state!='REVOKED' AND config_state='AVAILABLE'
ORDER BY id`)
	if err != nil {
		return nil, 0, err
	}
	for rows.Next() {
		var reference string
		if err := rows.Scan(&reference); err != nil {
			rows.Close()
			return nil, 0, err
		}
		archivePath, err := archivePathForSecretRef(reference)
		if err != nil {
			rows.Close()
			return nil, 0, err
		}
		managedAdministratorFiles[archivePath] = struct{}{}
	}
	if err := rows.Close(); err != nil {
		return nil, 0, err
	}
	var total int64
	add := func(archivePath, sourcePath string) error {
		if !safePath(archivePath) {
			return errors.New("VPS backup archive path is unsafe")
		}
		if _, exists := seen[archivePath]; exists || len(sources) >= MaximumFiles {
			return errors.New("VPS backup source is duplicated or file limit is exceeded")
		}
		info, err := os.Lstat(sourcePath)
		if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() < 0 || info.Size() > MaximumFileBytes || runtime.GOOS != "windows" && info.Mode().Perm()&0o022 != 0 {
			return fmt.Errorf("VPS backup source %s is unsafe", archivePath)
		}
		if total > backup.MaximumPortablePlainBytes-info.Size() {
			return errors.New("VPS backup payload exceeds its bound")
		}
		digest, err := hashPath(ctx, sourcePath, info.Size())
		if err != nil {
			return err
		}
		sources = append(sources, sourceFile{record: FileRecord{Path: archivePath, Bytes: info.Size(), SHA256: digest, Mode: 0o600}, path: sourcePath})
		seen[archivePath] = struct{}{}
		total += info.Size()
		return nil
	}
	if err := add("database/state.db", databaseCopy); err != nil {
		return nil, 0, err
	}
	if err := add("config/config.yaml", manager.ConfigurationPath); err != nil {
		return nil, 0, err
	}
	for _, directory := range []string{"secrets", "tls"} {
		root := filepath.Join(manager.StateDirectory, directory)
		info, err := os.Lstat(root)
		if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return nil, 0, fmt.Errorf("required VPS backup root %s is unsafe", directory)
		}
		if err := filepath.WalkDir(root, func(current string, entry os.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if current == root {
				return nil
			}
			info, err := entry.Info()
			if err != nil || info.Mode()&os.ModeSymlink != 0 {
				return errors.New("VPS backup tree contains an unsafe entry")
			}
			if entry.IsDir() {
				return nil
			}
			relative, err := filepath.Rel(manager.StateDirectory, current)
			if err != nil {
				return err
			}
			archivePath := "state/" + filepath.ToSlash(relative)
			if strings.HasPrefix(archivePath, "state/secrets/administrators/") {
				if _, allowed := managedAdministratorFiles[archivePath]; !allowed {
					return nil
				}
			}
			return add(archivePath, current)
		}); err != nil {
			return nil, 0, err
		}
	}
	required := []string{"database/state.db", "config/config.yaml", "state/tls/cert.pem", "state/tls/key.pem"}
	for _, secretRef := range []string{identity.PrivateKeySecretRef, identity.UpdateIdentityRef} {
		archivePath, err := archivePathForSecretRef(secretRef)
		if err != nil {
			return nil, 0, err
		}
		required = append(required, archivePath)
	}
	for archivePath := range managedAdministratorFiles {
		required = append(required, archivePath)
	}
	for _, path := range required {
		if _, exists := seen[path]; !exists {
			return nil, 0, fmt.Errorf("VPS backup is incomplete: %s is missing", path)
		}
	}
	sort.Slice(sources, func(i, j int) bool { return sources[i].record.Path < sources[j].record.Path })
	return sources, total, nil
}

func (manager *Manager) validate() error {
	if manager == nil || manager.Database == nil || !filepath.IsAbs(manager.StateDirectory) || !filepath.IsAbs(manager.ConfigurationPath) || !filepath.IsAbs(manager.ExportRoot) || strings.TrimSpace(manager.AgentVersion) == "" {
		return errors.New("VPS backup manager is incomplete")
	}
	relative, err := filepath.Rel(manager.StateDirectory, manager.ExportRoot)
	if err != nil || relative == "." || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return errors.New("VPS backup export root escapes the role state directory")
	}
	return nil
}

func (manager *Manager) now() time.Time {
	if manager.Now != nil {
		return manager.Now().UTC()
	}
	return time.Now().UTC()
}

// CreateOnlineDatabaseCopy exposes the same SQLite Online Backup primitive to
// the root-owned VPS updater. It copies only the database; configuration and
// secrets remain untouched by a pointer-compatible application update.
func CreateOnlineDatabaseCopy(ctx context.Context, database *sql.DB, destination string) error {
	if database == nil || !filepath.IsAbs(destination) {
		return errors.New("VPS online database copy requires a database and absolute destination")
	}
	return onlineBackup(ctx, database, filepath.Clean(destination))
}

func onlineBackup(ctx context.Context, database *sql.DB, destination string) error {
	file, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return errors.New("create VPS portable database failed")
	}
	if err := file.Close(); err != nil {
		return err
	}
	connection, err := database.Conn(ctx)
	if err != nil {
		return err
	}
	defer connection.Close()
	err = connection.Raw(func(raw any) error {
		backuper, ok := raw.(interface {
			NewBackup(string) (*sqlite.Backup, error)
		})
		if !ok {
			return errors.New("SQLite driver does not expose Online Backup API")
		}
		operation, err := backuper.NewBackup(destination)
		if err != nil {
			return err
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
			more, err := operation.Step(128)
			if err != nil {
				return err
			}
			if !more {
				break
			}
		}
		err = operation.Finish()
		finished = true
		return err
	})
	if err != nil {
		return fmt.Errorf("create VPS SQLite Online Backup: %w", err)
	}
	for _, suffix := range []string{"-wal", "-shm"} {
		if err := os.Remove(destination + suffix); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return os.Chmod(destination, 0o600)
}

func archivePathForSecretRef(ref string) (string, error) {
	ref = filepath.ToSlash(filepath.Clean(ref))
	prefix := productionStateRoot + "/"
	if !strings.HasPrefix(ref, prefix) {
		return "", errors.New("VPS identity secret reference escapes the role state root")
	}
	relative := strings.TrimPrefix(ref, prefix)
	path := "state/" + relative
	if !safePath(path) {
		return "", errors.New("VPS identity secret reference is unsafe")
	}
	return path, nil
}

func newBackupID() (string, error) {
	random := make([]byte, 16)
	if _, err := rand.Read(random); err != nil {
		return "", errors.New("generate VPS backup id failed")
	}
	return "vps-backup-" + hex.EncodeToString(random), nil
}

func closeBuildWriters(archive *zip.Writer, encrypted io.WriteCloser, file *os.File) {
	_ = archive.Close()
	_ = encrypted.Close()
	_ = file.Close()
}

func readStableFile(ctx context.Context, path string, record FileRecord) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() != record.Bytes {
		return nil, errors.New("VPS backup source changed")
	}
	content, err := os.ReadFile(path)
	if err != nil || int64(len(content)) != record.Bytes || sha256Hex(content) != record.SHA256 || ctx.Err() != nil {
		return nil, errors.New("VPS backup source changed during read")
	}
	return content, nil
}

func hashPath(ctx context.Context, path string, expected int64) (string, error) {
	file, err := openStableFile(path, expected)
	if err != nil {
		return "", errors.New("hash VPS backup source failed")
	}
	defer file.Close()
	hash := sha256.New()
	written, err := copyContext(ctx, hash, io.LimitReader(file, expected+1))
	if err != nil || written != expected {
		return "", errors.New("hash VPS backup source failed")
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func hashFile(path string, maximum int64) (int64, string, error) {
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maximum {
		return 0, "", errors.New("VPS backup artifact is unsafe")
	}
	file, err := openStableFile(path, info.Size())
	if err != nil {
		return 0, "", errors.New("read VPS backup artifact failed")
	}
	defer file.Close()
	hash := sha256.New()
	written, err := io.Copy(hash, io.LimitReader(file, maximum+1))
	if err != nil || written != info.Size() {
		return 0, "", errors.New("read VPS backup artifact failed")
	}
	return written, hex.EncodeToString(hash.Sum(nil)), nil
}

func openStableFile(path string, expected int64) (*os.File, error) {
	before, err := os.Lstat(path)
	if err != nil || before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() || before.Size() != expected {
		return nil, errors.New("VPS backup file is not a stable regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	after, err := file.Stat()
	if err != nil || !after.Mode().IsRegular() || after.Size() != expected || !os.SameFile(before, after) {
		file.Close()
		return nil, errors.New("VPS backup file changed during open")
	}
	return file, nil
}

func copyContext(ctx context.Context, destination io.Writer, source io.Reader) (int64, error) {
	buffer := make([]byte, 64<<10)
	var total int64
	for {
		if err := ctx.Err(); err != nil {
			return total, err
		}
		read, readErr := source.Read(buffer)
		if read > 0 {
			written, writeErr := destination.Write(buffer[:read])
			total += int64(written)
			if writeErr != nil {
				return total, writeErr
			}
			if written != read {
				return total, io.ErrShortWrite
			}
		}
		if errors.Is(readErr, io.EOF) {
			return total, nil
		}
		if readErr != nil {
			return total, readErr
		}
	}
}

func sha256Hex(content []byte) string {
	digest := sha256.Sum256(content)
	return hex.EncodeToString(digest[:])
}

func safePath(value string) bool {
	if value == "" || len(value) > 512 || strings.Contains(value, "\\") || strings.HasPrefix(value, "/") {
		return false
	}
	clean := filepath.ToSlash(filepath.Clean(filepath.FromSlash(value)))
	return clean == value && clean != "." && clean != ".." && !strings.HasPrefix(clean, "../")
}

func secureDirectory(path string) error {
	if err := os.MkdirAll(path, 0o700); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return errors.New("VPS backup directory is unsafe")
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o700 {
		return os.Chmod(path, 0o700)
	}
	return nil
}

func syncDirectory(path string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}
