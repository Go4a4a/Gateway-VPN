package backup

import (
	"archive/zip"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
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
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
)

const (
	PortableFormatVersion        = 1
	MaximumPortablePlainBytes    = int64(256 << 20)
	MaximumPortableBackupBytes   = int64(300 << 20)
	MaximumPortableFiles         = 4096
	portableChunkBytes           = 1 << 20
	portableKDFMemoryKiB         = 64 * 1024
	portableKDFIterations        = 3
	portableKDFParallelism       = 2
	minimumBackupPassphraseBytes = 12
	maximumBackupPassphraseBytes = 256
	portableHeaderMaximum        = 8 << 10
	maximumPortableManifestBytes = 2 << 20
)

var (
	portableMagic       = [16]byte{'G', 'A', 'T', 'E', 'W', 'A', 'Y', '-', 'V', 'P', 'N', '-', 'B', 'K', 'P', '1'}
	portableNamePattern = regexp.MustCompile(`^gateway-vpn-backup-[0-9]{8}T[0-9]{6}Z-[a-f0-9]{24}\.gvpn$`)
)

type PortableFile struct {
	Path   string `json:"path"`
	Bytes  int64  `json:"bytes"`
	SHA256 string `json:"sha256"`
	Mode   uint32 `json:"mode"`
}

type PortableManifest struct {
	FormatVersion   int            `json:"format_version"`
	CreatedAt       string         `json:"created_at"`
	GatewayVersion  string         `json:"gateway_version"`
	SnapshotID      string         `json:"snapshot_id"`
	SchemaVersion   int64          `json:"schema_version"`
	Files           []PortableFile `json:"files"`
	PayloadBytes    int64          `json:"payload_bytes"`
	SecretsIncluded bool           `json:"secrets_included"`
}

type PortableArtifact struct {
	Filename   string
	Path       string
	Bytes      int64
	SHA256     string
	SnapshotID string
	Manifest   PortableManifest
}

type PortableManager struct {
	Snapshots         *Manager
	StateDirectory    string
	ConfigurationPath string
	GatewayVersion    string
	ExportRoot        string
	Now               func() time.Time
}

type portableSource struct {
	record PortableFile
	source string
}

type encryptionHeader struct {
	FormatVersion  int    `json:"format_version"`
	PayloadFormat  string `json:"payload_format"`
	Cipher         string `json:"cipher"`
	ChunkBytes     int    `json:"chunk_bytes"`
	KDF            string `json:"kdf"`
	KDFMemoryKiB   uint32 `json:"kdf_memory_kib"`
	KDFIterations  uint32 `json:"kdf_iterations"`
	KDFParallelism uint8  `json:"kdf_parallelism"`
	Salt           string `json:"salt_base64"`
	NoncePrefix    string `json:"nonce_prefix_base64"`
}

func NewPortableManager(snapshots *Manager, stateDirectory, configurationPath, gatewayVersion string) (*PortableManager, error) {
	if snapshots == nil || !filepath.IsAbs(stateDirectory) || !filepath.IsAbs(configurationPath) || strings.TrimSpace(gatewayVersion) == "" {
		return nil, errors.New("portable backup requires snapshots, absolute paths, and a gateway version")
	}
	return &PortableManager{
		Snapshots: snapshots, StateDirectory: filepath.Clean(stateDirectory), ConfigurationPath: filepath.Clean(configurationPath),
		GatewayVersion: strings.TrimSpace(gatewayVersion), ExportRoot: filepath.Join(filepath.Clean(stateDirectory), "backups", "exports"),
	}, nil
}

func (manager *PortableManager) Build(ctx context.Context, passphrase string) (PortableArtifact, error) {
	if err := ValidatePassphrase(passphrase); err != nil {
		return PortableArtifact{}, err
	}
	if err := secureDirectory(manager.ExportRoot); err != nil {
		return PortableArtifact{}, err
	}
	snapshot, err := manager.Snapshots.Create(ctx, KindManual)
	if err != nil {
		return PortableArtifact{}, fmt.Errorf("create portable backup database snapshot: %w", err)
	}
	sources, total, err := manager.collectSources(ctx, snapshot)
	if err != nil {
		return PortableArtifact{}, err
	}
	now := manager.now()
	manifest := PortableManifest{
		FormatVersion: PortableFormatVersion, CreatedAt: now.Format(time.RFC3339Nano), GatewayVersion: manager.GatewayVersion,
		SnapshotID: snapshot.Manifest.SnapshotID, SchemaVersion: snapshot.Manifest.SchemaVersion,
		Files: make([]PortableFile, 0, len(sources)), PayloadBytes: total, SecretsIncluded: true,
	}
	for _, source := range sources {
		manifest.Files = append(manifest.Files, source.record)
	}
	manifestContent, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil || len(manifestContent) > maximumPortableManifestBytes {
		return PortableArtifact{}, errors.New("encode portable backup manifest failed")
	}
	manifestContent = append(manifestContent, '\n')

	randomID, err := newSnapshotID(now)
	if err != nil {
		return PortableArtifact{}, err
	}
	filename := "gateway-vpn-backup-" + now.Format("20060102T150405Z") + "-" + randomID[len(randomID)-24:] + ".gvpn"
	temporary, err := os.CreateTemp(manager.ExportRoot, ".portable-")
	if err != nil {
		return PortableArtifact{}, errors.New("create encrypted backup artifact failed")
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return PortableArtifact{}, err
	}
	encrypted, err := newChunkEncryptWriter(temporary, passphrase)
	if err != nil {
		temporary.Close()
		return PortableArtifact{}, err
	}
	archive := zip.NewWriter(encrypted)
	writeEntry := func(name string, content io.Reader, expected PortableFile) error {
		header := &zip.FileHeader{Name: name, Method: zip.Deflate}
		header.SetMode(0o600)
		header.SetModTime(now)
		entry, err := archive.CreateHeader(header)
		if err != nil {
			return err
		}
		hash := sha256.New()
		written, err := io.Copy(io.MultiWriter(entry, hash), io.LimitReader(content, expected.Bytes+1))
		if err != nil || written != expected.Bytes || hex.EncodeToString(hash.Sum(nil)) != expected.SHA256 {
			return errors.New("portable backup source changed while archiving")
		}
		return nil
	}
	manifestRecord := PortableFile{Path: "manifest.json", Bytes: int64(len(manifestContent)), SHA256: digestBytes(manifestContent), Mode: 0o600}
	if err := writeEntry("manifest.json", strings.NewReader(string(manifestContent)), manifestRecord); err != nil {
		archive.Close()
		encrypted.Close()
		temporary.Close()
		return PortableArtifact{}, err
	}
	for _, source := range sources {
		if err := ctx.Err(); err != nil {
			archive.Close()
			encrypted.Close()
			temporary.Close()
			return PortableArtifact{}, err
		}
		file, err := openStableRegularFile(source.source, source.record.Bytes)
		if err != nil {
			archive.Close()
			encrypted.Close()
			temporary.Close()
			return PortableArtifact{}, err
		}
		writeErr := writeEntry(source.record.Path, file, source.record)
		closeErr := file.Close()
		if writeErr != nil || closeErr != nil {
			archive.Close()
			encrypted.Close()
			temporary.Close()
			return PortableArtifact{}, errors.New("write portable backup entry failed")
		}
	}
	if err := archive.Close(); err != nil {
		encrypted.Close()
		temporary.Close()
		return PortableArtifact{}, errors.New("finalize portable backup archive failed")
	}
	if err := encrypted.Close(); err != nil {
		temporary.Close()
		return PortableArtifact{}, err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return PortableArtifact{}, errors.New("sync encrypted backup artifact failed")
	}
	if err := temporary.Close(); err != nil {
		return PortableArtifact{}, errors.New("close encrypted backup artifact failed")
	}
	verification, err := hashBoundedFile(temporaryPath, MaximumPortableBackupBytes)
	if err != nil {
		return PortableArtifact{}, err
	}
	finalPath := filepath.Join(manager.ExportRoot, filename)
	if err := os.Rename(temporaryPath, finalPath); err != nil {
		return PortableArtifact{}, fmt.Errorf("commit encrypted backup artifact: %w", err)
	}
	if err := syncDirectory(manager.ExportRoot); err != nil {
		return PortableArtifact{}, err
	}
	return PortableArtifact{Filename: filename, Path: finalPath, Bytes: verification.Bytes, SHA256: verification.SHA256, SnapshotID: snapshot.Manifest.SnapshotID, Manifest: manifest}, nil
}

func (manager *PortableManager) Remove(artifact PortableArtifact) error {
	if err := manager.validateArtifactLocation(artifact); err != nil {
		return err
	}
	info, err := os.Lstat(artifact.Path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return errors.New("portable backup artifact is unsafe")
	}
	if err := os.Remove(artifact.Path); err != nil {
		return err
	}
	return syncDirectory(manager.ExportRoot)
}

func (manager *PortableManager) Open(artifact PortableArtifact) (io.ReadCloser, error) {
	if err := manager.validateArtifactLocation(artifact); err != nil {
		return nil, err
	}
	verification, err := hashBoundedFile(artifact.Path, MaximumPortableBackupBytes)
	if err != nil || verification.Bytes != artifact.Bytes || verification.SHA256 != artifact.SHA256 {
		return nil, errors.New("portable backup artifact failed final verification")
	}
	return openStableRegularFile(artifact.Path, artifact.Bytes)
}

func (manager *PortableManager) validateArtifactLocation(artifact PortableArtifact) error {
	if !portableNamePattern.MatchString(artifact.Filename) || filepath.Base(artifact.Path) != artifact.Filename || filepath.Dir(filepath.Clean(artifact.Path)) != filepath.Clean(manager.ExportRoot) {
		return errors.New("refuse to access unmanaged portable backup artifact")
	}
	return nil
}

func (manager *PortableManager) now() time.Time {
	if manager.Now != nil {
		return manager.Now().UTC()
	}
	return time.Now().UTC()
}

func (manager *PortableManager) collectSources(ctx context.Context, snapshot Snapshot) ([]portableSource, int64, error) {
	sources := []portableSource{}
	seen := map[string]struct{}{}
	var total int64
	add := func(archivePath, sourcePath string) error {
		if _, exists := seen[archivePath]; exists || !safePortablePath(archivePath) {
			return errors.New("portable backup path is duplicated or unsafe")
		}
		if len(sources) >= MaximumPortableFiles {
			return errors.New("portable backup file count exceeds its bound")
		}
		info, err := os.Lstat(sourcePath)
		if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() < 0 || runtime.GOOS != "windows" && info.Mode().Perm()&0o022 != 0 {
			return fmt.Errorf("portable backup source %s is unsafe", archivePath)
		}
		if total > MaximumPortablePlainBytes-info.Size() {
			return errors.New("portable backup payload exceeds its bound")
		}
		digest, err := hashRegularFile(ctx, sourcePath, info.Size())
		if err != nil {
			return err
		}
		// Restore always materializes protected regular files as 0600. Source
		// execute bits and platform-specific Windows permission emulation are
		// neither needed nor carried into the portable format.
		record := PortableFile{Path: archivePath, Bytes: info.Size(), SHA256: digest, Mode: 0o600}
		sources = append(sources, portableSource{record: record, source: sourcePath})
		seen[archivePath], total = struct{}{}, total+info.Size()
		return nil
	}
	if err := add("database/state.db", filepath.Join(snapshot.Path, snapshot.Manifest.Database.Name)); err != nil {
		return nil, 0, err
	}
	if err := add("config/config.yaml", manager.ConfigurationPath); err != nil {
		return nil, 0, err
	}
	for _, root := range []struct{ source, target string }{
		{filepath.Join(manager.StateDirectory, "secrets"), "state/secrets"},
		{filepath.Join(manager.StateDirectory, "subscriptions"), "state/subscriptions"},
		{filepath.Join(manager.StateDirectory, "tls"), "state/tls"},
		{filepath.Join(manager.StateDirectory, "mihomo", "generations"), "state/mihomo/generations"},
		{filepath.Join(manager.StateDirectory, "mihomo", "state"), "state/mihomo/state"},
	} {
		info, err := os.Lstat(root.source)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return nil, 0, fmt.Errorf("portable backup root %s is unsafe", root.target)
		}
		err = filepath.WalkDir(root.source, func(current string, entry os.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if err := ctx.Err(); err != nil {
				return err
			}
			if current == root.source {
				return nil
			}
			info, err := entry.Info()
			if err != nil || info.Mode()&os.ModeSymlink != 0 {
				return errors.New("portable backup tree contains an unsafe entry")
			}
			if entry.IsDir() {
				return nil
			}
			if !info.Mode().IsRegular() {
				return errors.New("portable backup tree contains a non-regular file")
			}
			relative, err := filepath.Rel(root.source, current)
			if err != nil {
				return err
			}
			archivePath := filepath.ToSlash(filepath.Join(root.target, relative))
			return add(archivePath, current)
		})
		if err != nil {
			return nil, 0, err
		}
	}
	for _, required := range []string{"database/state.db", "config/config.yaml", "state/secrets/mihomo-api-secret", "state/tls/cert.pem", "state/tls/key.pem"} {
		if _, exists := seen[required]; !exists {
			return nil, 0, fmt.Errorf("portable backup is incomplete: required file %s is missing", required)
		}
	}
	sort.Slice(sources, func(i, j int) bool { return sources[i].record.Path < sources[j].record.Path })
	return sources, total, nil
}

type chunkEncryptWriter struct {
	destination io.Writer
	aead        cipher.AEAD
	noncePrefix [8]byte
	headerHash  [32]byte
	buffer      []byte
	index       uint32
	closed      bool
}

func newChunkEncryptWriter(destination io.Writer, passphrase string) (*chunkEncryptWriter, error) {
	if err := ValidatePassphrase(passphrase); err != nil {
		return nil, err
	}
	salt, noncePrefix := make([]byte, 16), make([]byte, 8)
	if _, err := rand.Read(salt); err != nil {
		return nil, errors.New("generate backup encryption salt failed")
	}
	if _, err := rand.Read(noncePrefix); err != nil {
		return nil, errors.New("generate backup encryption nonce failed")
	}
	key := argon2.IDKey([]byte(passphrase), salt, portableKDFIterations, portableKDFMemoryKiB, portableKDFParallelism, 32)
	block, err := aes.NewCipher(key)
	clear(key)
	if err != nil {
		return nil, errors.New("initialize backup cipher failed")
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, errors.New("initialize backup authentication failed")
	}
	header := encryptionHeader{
		FormatVersion: PortableFormatVersion, PayloadFormat: "zip", Cipher: "AES-256-GCM-CHUNKED", ChunkBytes: portableChunkBytes,
		KDF: "argon2id", KDFMemoryKiB: portableKDFMemoryKiB, KDFIterations: portableKDFIterations, KDFParallelism: portableKDFParallelism,
		Salt: base64.RawStdEncoding.EncodeToString(salt), NoncePrefix: base64.RawStdEncoding.EncodeToString(noncePrefix),
	}
	headerContent, err := json.Marshal(header)
	if err != nil || len(headerContent) > portableHeaderMaximum {
		return nil, errors.New("encode backup encryption header failed")
	}
	prefix := make([]byte, 0, len(portableMagic)+4+len(headerContent))
	prefix = append(prefix, portableMagic[:]...)
	length := make([]byte, 4)
	binary.BigEndian.PutUint32(length, uint32(len(headerContent)))
	prefix = append(prefix, length...)
	prefix = append(prefix, headerContent...)
	if _, err := destination.Write(prefix); err != nil {
		return nil, errors.New("write backup encryption header failed")
	}
	result := &chunkEncryptWriter{destination: destination, aead: aead, buffer: make([]byte, 0, portableChunkBytes), headerHash: sha256.Sum256(prefix)}
	copy(result.noncePrefix[:], noncePrefix)
	return result, nil
}

// DecryptToZIP authenticates every chunk, requires an authenticated final
// record, enforces the fixed KDF/cipher profile, and writes a bounded 0600 ZIP.
// It intentionally reports one generic error for a wrong passphrase or a
// modified/truncated artifact.
func DecryptToZIP(ctx context.Context, encryptedPath, destinationPath, passphrase string) (int64, error) {
	if err := ValidatePassphrase(passphrase); err != nil {
		return 0, err
	}
	info, err := os.Lstat(encryptedPath)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() <= int64(len(portableMagic)+4) || info.Size() > MaximumPortableBackupBytes {
		return 0, errors.New("encrypted backup artifact is invalid")
	}
	source, err := os.Open(encryptedPath)
	if err != nil {
		return 0, errors.New("open encrypted backup artifact failed")
	}
	defer source.Close()
	prefix := make([]byte, len(portableMagic)+4)
	if _, err := io.ReadFull(source, prefix); err != nil || string(prefix[:len(portableMagic)]) != string(portableMagic[:]) {
		return 0, errors.New("backup passphrase or artifact is invalid")
	}
	headerLength := binary.BigEndian.Uint32(prefix[len(portableMagic):])
	if headerLength == 0 || headerLength > portableHeaderMaximum {
		return 0, errors.New("backup passphrase or artifact is invalid")
	}
	headerContent := make([]byte, headerLength)
	if _, err := io.ReadFull(source, headerContent); err != nil {
		return 0, errors.New("backup passphrase or artifact is invalid")
	}
	var header encryptionHeader
	if err := decodeStrictJSON(headerContent, &header); err != nil || header.FormatVersion != PortableFormatVersion || header.PayloadFormat != "zip" || header.Cipher != "AES-256-GCM-CHUNKED" || header.ChunkBytes != portableChunkBytes || header.KDF != "argon2id" || header.KDFMemoryKiB != portableKDFMemoryKiB || header.KDFIterations != portableKDFIterations || header.KDFParallelism != portableKDFParallelism {
		return 0, errors.New("backup passphrase or artifact is invalid")
	}
	salt, saltErr := base64.RawStdEncoding.DecodeString(header.Salt)
	noncePrefix, nonceErr := base64.RawStdEncoding.DecodeString(header.NoncePrefix)
	if saltErr != nil || nonceErr != nil || len(salt) != 16 || len(noncePrefix) != 8 {
		return 0, errors.New("backup passphrase or artifact is invalid")
	}
	key := argon2.IDKey([]byte(passphrase), salt, header.KDFIterations, header.KDFMemoryKiB, header.KDFParallelism, 32)
	block, err := aes.NewCipher(key)
	clear(key)
	if err != nil {
		return 0, errors.New("backup passphrase or artifact is invalid")
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return 0, errors.New("backup passphrase or artifact is invalid")
	}
	destination, err := os.OpenFile(destinationPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return 0, errors.New("create decrypted backup staging file failed")
	}
	succeeded, destinationClosed := false, false
	defer func() {
		if !destinationClosed {
			_ = destination.Close()
		}
		if !succeeded {
			_ = os.Remove(destinationPath)
		}
	}()
	fullPrefix := append(append([]byte(nil), prefix...), headerContent...)
	headerHash := sha256.Sum256(fullPrefix)
	var total int64
	for index := uint32(0); ; index++ {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		recordHeader := make([]byte, 5)
		if _, err := io.ReadFull(source, recordHeader); err != nil {
			return 0, errors.New("backup passphrase or artifact is invalid")
		}
		recordType := recordHeader[0]
		ciphertextLength := binary.BigEndian.Uint32(recordHeader[1:])
		if (recordType != 1 && recordType != 2) || ciphertextLength < uint32(aead.Overhead()) || ciphertextLength > uint32(portableChunkBytes+aead.Overhead()) || recordType == 2 && ciphertextLength != uint32(aead.Overhead()) {
			return 0, errors.New("backup passphrase or artifact is invalid")
		}
		ciphertext := make([]byte, ciphertextLength)
		if _, err := io.ReadFull(source, ciphertext); err != nil {
			return 0, errors.New("backup passphrase or artifact is invalid")
		}
		nonce := make([]byte, 12)
		copy(nonce, noncePrefix)
		binary.BigEndian.PutUint32(nonce[8:], index)
		aad := make([]byte, 0, len(headerHash)+5)
		aad = append(aad, headerHash[:]...)
		aad = append(aad, recordType)
		indexBytes := make([]byte, 4)
		binary.BigEndian.PutUint32(indexBytes, index)
		aad = append(aad, indexBytes...)
		plaintext, err := aead.Open(nil, nonce, ciphertext, aad)
		if err != nil {
			return 0, errors.New("backup passphrase or artifact is invalid")
		}
		if recordType == 2 {
			if len(plaintext) != 0 {
				return 0, errors.New("backup passphrase or artifact is invalid")
			}
			trailing := make([]byte, 1)
			if read, err := source.Read(trailing); read != 0 || !errors.Is(err, io.EOF) {
				return 0, errors.New("backup passphrase or artifact is invalid")
			}
			break
		}
		if len(plaintext) == 0 || total > MaximumPortablePlainBytes-int64(len(plaintext)) {
			return 0, errors.New("decrypted backup payload exceeds its bound")
		}
		written, err := destination.Write(plaintext)
		total += int64(written)
		if err != nil || written != len(plaintext) {
			return 0, errors.New("write decrypted backup payload failed")
		}
		if index == ^uint32(0)-1 {
			return 0, errors.New("backup passphrase or artifact is invalid")
		}
	}
	if total == 0 {
		return 0, errors.New("decrypted backup payload is empty")
	}
	if err := destination.Sync(); err != nil {
		return 0, errors.New("sync decrypted backup payload failed")
	}
	if err := destination.Close(); err != nil {
		return 0, errors.New("close decrypted backup payload failed")
	}
	destinationClosed, succeeded = true, true
	return total, nil
}

func (writer *chunkEncryptWriter) Write(payload []byte) (int, error) {
	if writer.closed {
		return 0, errors.New("encrypted backup writer is closed")
	}
	written := len(payload)
	for len(payload) > 0 {
		available := portableChunkBytes - len(writer.buffer)
		if available > len(payload) {
			available = len(payload)
		}
		writer.buffer = append(writer.buffer, payload[:available]...)
		payload = payload[available:]
		if len(writer.buffer) == portableChunkBytes {
			if err := writer.writeRecord(1, writer.buffer); err != nil {
				return written - len(payload), err
			}
			writer.buffer = writer.buffer[:0]
		}
	}
	return written, nil
}

func (writer *chunkEncryptWriter) Close() error {
	if writer.closed {
		return nil
	}
	writer.closed = true
	if len(writer.buffer) != 0 {
		if err := writer.writeRecord(1, writer.buffer); err != nil {
			return err
		}
	}
	writer.buffer = nil
	return writer.writeRecord(2, nil)
}

func (writer *chunkEncryptWriter) writeRecord(recordType byte, plaintext []byte) error {
	if writer.index == ^uint32(0) {
		return errors.New("encrypted backup has too many chunks")
	}
	nonce := make([]byte, 12)
	copy(nonce, writer.noncePrefix[:])
	binary.BigEndian.PutUint32(nonce[8:], writer.index)
	aad := make([]byte, 0, len(writer.headerHash)+5)
	aad = append(aad, writer.headerHash[:]...)
	aad = append(aad, recordType)
	indexBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(indexBytes, writer.index)
	aad = append(aad, indexBytes...)
	ciphertext := writer.aead.Seal(nil, nonce, plaintext, aad)
	length := make([]byte, 5)
	length[0] = recordType
	binary.BigEndian.PutUint32(length[1:], uint32(len(ciphertext)))
	if _, err := writer.destination.Write(length); err != nil {
		return errors.New("write encrypted backup record header failed")
	}
	if _, err := writer.destination.Write(ciphertext); err != nil {
		return errors.New("write encrypted backup record failed")
	}
	writer.index++
	return nil
}

func ValidatePassphrase(value string) error {
	if !utf8.ValidString(value) || len(value) < minimumBackupPassphraseBytes || len(value) > maximumBackupPassphraseBytes || strings.ContainsRune(value, 0) {
		return fmt.Errorf("backup passphrase must contain %d..%d UTF-8 bytes", minimumBackupPassphraseBytes, maximumBackupPassphraseBytes)
	}
	return nil
}

func safePortablePath(value string) bool {
	if value == "" || len(value) > 512 || strings.Contains(value, "\\") || strings.HasPrefix(value, "/") {
		return false
	}
	clean := filepath.ToSlash(filepath.Clean(filepath.FromSlash(value)))
	return clean == value && clean != "." && clean != ".." && !strings.HasPrefix(clean, "../")
}

func hashRegularFile(ctx context.Context, filename string, expectedBytes int64) (string, error) {
	file, err := openStableRegularFile(filename, expectedBytes)
	if err != nil {
		return "", err
	}
	defer file.Close()
	hash := sha256.New()
	written, err := copyWithContext(ctx, hash, io.LimitReader(file, expectedBytes+1))
	if err != nil || written != expectedBytes {
		return "", errors.New("hash portable backup source failed")
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func openStableRegularFile(filename string, expectedBytes int64) (*os.File, error) {
	before, err := os.Lstat(filename)
	if err != nil || before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() || before.Size() != expectedBytes {
		return nil, errors.New("portable backup source is not a stable regular file")
	}
	file, err := os.Open(filename)
	if err != nil {
		return nil, errors.New("open portable backup source failed")
	}
	after, err := file.Stat()
	if err != nil || !after.Mode().IsRegular() || after.Size() != expectedBytes || !os.SameFile(before, after) {
		file.Close()
		return nil, errors.New("portable backup source changed during open")
	}
	return file, nil
}

func copyWithContext(ctx context.Context, destination io.Writer, source io.Reader) (int64, error) {
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

func hashBoundedFile(filename string, maximum int64) (databaseVerification, error) {
	info, err := os.Lstat(filename)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maximum {
		return databaseVerification{}, errors.New("encrypted backup artifact exceeds its bound or is unsafe")
	}
	file, err := os.Open(filename)
	if err != nil {
		return databaseVerification{}, err
	}
	defer file.Close()
	hash := sha256.New()
	written, err := io.Copy(hash, io.LimitReader(file, maximum+1))
	if err != nil || written != info.Size() {
		return databaseVerification{}, errors.New("hash encrypted backup artifact failed")
	}
	return databaseVerification{Bytes: written, SHA256: hex.EncodeToString(hash.Sum(nil))}, nil
}

func digestBytes(value []byte) string {
	digest := sha256.Sum256(value)
	return hex.EncodeToString(digest[:])
}
