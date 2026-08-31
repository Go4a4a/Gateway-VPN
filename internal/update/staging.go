package update

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"context"
	"crypto/rand"
	"encoding/hex"
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
)

const (
	StagingFormatVersion  = 1
	MaximumArchiveBytes   = int64(768 << 20)
	MaximumArchiveEntries = MaximumFiles * 2
	MaximumArchiveTrailer = int64(1 << 20)
	pendingFilename       = "pending-update.json"
	SourceUpload          = "WEBUI_UPLOAD"
	SourceGitHubChannel   = "GITHUB_CHANNEL"
	SourceExactHTTPS      = "EXACT_HTTPS"
)

var updateIDPattern = regexp.MustCompile(`^update-[0-9]{8}T[0-9]{6}Z-[a-f0-9]{24}$`)

var ErrUpdatePending = errors.New("a verified update is already staged")

type Operation struct {
	FormatVersion     int    `json:"format_version"`
	UpdateID          string `json:"update_id"`
	State             string `json:"state"`
	CreatedAt         string `json:"created_at"`
	GatewayVersion    string `json:"gateway_version"`
	MihomoVersion     string `json:"mihomo_version"`
	SignerKeySHA256   string `json:"signer_key_sha256"`
	ManifestSHA256    string `json:"manifest_sha256"`
	UncompressedBytes int64  `json:"uncompressed_bytes"`
	FileCount         int    `json:"file_count"`
	SourceKind        string `json:"source_kind,omitempty"`
	SourceChannel     string `json:"source_channel,omitempty"`
	SourceReference   string `json:"source_reference,omitempty"`
}

// Source is intentionally safe to persist and display. Reference must never
// contain a URL query, credentials, filesystem path, or bearer token.
type Source struct {
	Kind      string
	Channel   string
	Reference string
}

type Stager struct {
	StateDir string
	Root     string
	Policy   VerificationPolicy
	Now      func() time.Time
	mutex    sync.Mutex
}

func NewStager(stateDirectory, trustedKeyPath string, policy VerificationPolicy) (*Stager, error) {
	if !filepath.IsAbs(stateDirectory) || !filepath.IsAbs(trustedKeyPath) {
		return nil, errors.New("absolute update state and trusted key paths are required")
	}
	stateDirectory = filepath.Clean(stateDirectory)
	key, err := LoadPublicKey(trustedKeyPath)
	if err != nil {
		return nil, err
	}
	policy.PublicKey = key
	return &Stager{StateDir: stateDirectory, Root: filepath.Join(stateDirectory, "update-staging"), Policy: policy}, nil
}

func (stager *Stager) Stage(ctx context.Context, archive io.Reader) (Operation, error) {
	return stager.StageWithSource(ctx, archive, Source{Kind: SourceUpload, Reference: "manual WebUI upload"})
}

func (stager *Stager) StageWithSource(ctx context.Context, archive io.Reader, source Source) (Operation, error) {
	stager.mutex.Lock()
	defer stager.mutex.Unlock()
	if archive == nil {
		return Operation{}, errors.New("release archive reader is required")
	}
	if !validSource(source) {
		return Operation{}, errors.New("update source metadata is invalid or unsafe")
	}
	if err := stager.prepareRoot(); err != nil {
		return Operation{}, err
	}
	if _, exists, err := stager.statusLocked(); err != nil {
		return Operation{}, err
	} else if exists {
		return Operation{}, ErrUpdatePending
	}
	id, err := newUpdateID(stager.now())
	if err != nil {
		return Operation{}, err
	}
	temporary := filepath.Join(stager.Root, ".tmp-"+id)
	final := filepath.Join(stager.Root, id)
	if err := os.Mkdir(temporary, 0o700); err != nil {
		return Operation{}, fmt.Errorf("create update staging transaction: %w", err)
	}
	defer os.RemoveAll(temporary)
	bytesWritten, files, err := extractReleaseArchive(ctx, archive, temporary)
	if err != nil {
		return Operation{}, err
	}
	verified, err := VerifyRelease(temporary, stager.Policy)
	if err != nil {
		return Operation{}, fmt.Errorf("verify staged release: %w", err)
	}
	manifestDigest, _, err := hashFile(filepath.Join(temporary, ManifestFilename), MaximumManifestBytes)
	if err != nil {
		return Operation{}, errors.New("hash verified signed manifest failed")
	}
	if err := syncTree(temporary); err != nil {
		return Operation{}, fmt.Errorf("sync verified update staging: %w", err)
	}
	if err := os.Rename(temporary, final); err != nil {
		return Operation{}, fmt.Errorf("commit verified update staging: %w", err)
	}
	if err := syncDirectoryPath(stager.Root); err != nil {
		return Operation{}, fmt.Errorf("sync update staging root: %w", err)
	}
	operation := Operation{
		FormatVersion: StagingFormatVersion, UpdateID: id, State: "STAGED", CreatedAt: stager.now().Format(time.RFC3339Nano),
		GatewayVersion: verified.Release.GatewayVersion, MihomoVersion: verified.Release.MihomoVersion,
		SignerKeySHA256: verified.Fingerprint, ManifestSHA256: manifestDigest,
		UncompressedBytes: bytesWritten, FileCount: files,
		SourceKind: source.Kind, SourceChannel: source.Channel, SourceReference: source.Reference,
	}
	if err := writePendingOperation(filepath.Join(stager.Root, pendingFilename), operation); err != nil {
		_ = removeStrictTree(final)
		return Operation{}, err
	}
	return operation, nil
}

func (stager *Stager) Status() (Operation, bool, error) {
	stager.mutex.Lock()
	defer stager.mutex.Unlock()
	return stager.statusLocked()
}

func (stager *Stager) statusLocked() (Operation, bool, error) {
	content, err := readBoundedRegular(filepath.Join(stager.Root, pendingFilename), 32<<10)
	if errors.Is(err, os.ErrNotExist) || err != nil && !pathExists(filepath.Join(stager.Root, pendingFilename)) {
		return Operation{}, false, nil
	}
	if err != nil {
		return Operation{}, false, errors.New("pending update metadata is unsafe")
	}
	var operation Operation
	if err := decodeStrict(content, &operation); err != nil || !validOperation(operation) {
		return Operation{}, false, errors.New("pending update metadata is invalid")
	}
	releaseRoot := filepath.Join(stager.Root, operation.UpdateID)
	verified, err := VerifyRelease(releaseRoot, stager.Policy)
	if err != nil {
		return Operation{}, false, fmt.Errorf("pending update no longer verifies: %w", err)
	}
	manifestDigest, _, err := hashFile(filepath.Join(releaseRoot, ManifestFilename), MaximumManifestBytes)
	if err != nil || manifestDigest != operation.ManifestSHA256 || verified.Release.GatewayVersion != operation.GatewayVersion || verified.Release.MihomoVersion != operation.MihomoVersion || verified.Fingerprint != operation.SignerKeySHA256 || len(verified.Manifest.Files)+2 != operation.FileCount {
		return Operation{}, false, errors.New("pending update metadata does not match the verified release")
	}
	return operation, true, nil
}

func (stager *Stager) ReleaseRoot(updateID string) (string, error) {
	if !updateIDPattern.MatchString(updateID) {
		return "", errors.New("valid staged update id is required")
	}
	operation, exists, err := stager.Status()
	if err != nil || !exists || operation.UpdateID != updateID {
		return "", errors.New("requested verified staged update is not pending")
	}
	return filepath.Join(stager.Root, updateID), nil
}

func (stager *Stager) Discard(ctx context.Context, updateID string) error {
	stager.mutex.Lock()
	defer stager.mutex.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	operation, exists, err := stager.statusLocked()
	if err != nil {
		return err
	}
	if !exists || operation.UpdateID != updateID || !updateIDPattern.MatchString(updateID) {
		return errors.New("requested verified staged update is not pending")
	}
	if err := os.Remove(filepath.Join(stager.Root, pendingFilename)); err != nil {
		return fmt.Errorf("remove pending update marker: %w", err)
	}
	if err := syncDirectoryPath(stager.Root); err != nil {
		return err
	}
	if err := removeStrictTree(filepath.Join(stager.Root, updateID)); err != nil {
		return err
	}
	return syncDirectoryPath(stager.Root)
}

func extractReleaseArchive(ctx context.Context, input io.Reader, destination string) (int64, int, error) {
	compressed := &countingReader{Reader: io.LimitReader(input, MaximumArchiveBytes+1)}
	buffered := bufio.NewReader(compressed)
	gzipReader, err := gzip.NewReader(buffered)
	if err != nil {
		return 0, 0, errors.New("release archive is not valid gzip")
	}
	defer gzipReader.Close()
	// A release is exactly one gzip member. This makes truncation, concatenated
	// members and trailing-data smuggling observable after the tar EOF.
	gzipReader.Multistream(false)
	tarReader := tar.NewReader(gzipReader)
	seen := make(map[string]struct{})
	var total int64
	files := 0
	for {
		if err := ctx.Err(); err != nil {
			return 0, 0, err
		}
		header, err := tarReader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return 0, 0, errors.New("read release tar archive failed")
		}
		name := strings.TrimPrefix(header.Name, "./")
		name = strings.TrimSuffix(name, "/")
		if name == "" || !safeRelativePath(name) || header.Linkname != "" || header.Mode&0o7000 != 0 {
			return 0, 0, errors.New("release archive contains an unsafe path, link, or mode")
		}
		if len(seen) >= MaximumArchiveEntries {
			return 0, 0, errors.New("release archive entry count exceeds its bound")
		}
		if _, duplicate := seen[name]; duplicate {
			return 0, 0, errors.New("release archive contains a duplicate path")
		}
		seen[name] = struct{}{}
		target := filepath.Join(destination, filepath.FromSlash(name))
		relative, err := filepath.Rel(destination, target)
		if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			return 0, 0, errors.New("release archive path escapes staging")
		}
		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o755); err != nil {
				return 0, 0, errors.New("create release staging directory failed")
			}
		case tar.TypeReg, tar.TypeRegA:
			files++
			if files > MaximumFiles+2 || header.Size <= 0 || header.Size > MaximumFileBytes || total+header.Size > MaximumArtifactBytes {
				return 0, 0, errors.New("release archive file count or size exceeds its bound")
			}
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return 0, 0, errors.New("create release file parent failed")
			}
			mode := os.FileMode(0o644)
			if header.Mode&0o111 != 0 {
				mode = 0o755
			}
			file, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
			if err != nil {
				return 0, 0, errors.New("create staged release file failed")
			}
			written, copyErr := io.CopyN(file, tarReader, header.Size)
			syncErr := file.Sync()
			closeErr := file.Close()
			if copyErr != nil || syncErr != nil || closeErr != nil || written != header.Size {
				return 0, 0, errors.New("write staged release file failed")
			}
			total += written
		default:
			return 0, 0, errors.New("release archive contains a non-regular entry")
		}
	}
	drained, err := io.Copy(io.Discard, io.LimitReader(gzipReader, MaximumArchiveTrailer+1))
	if err != nil {
		return 0, 0, errors.New("release gzip checksum or trailer is invalid")
	}
	if drained > MaximumArchiveTrailer {
		return 0, 0, errors.New("release tar padding exceeds its bound")
	}
	if closeErr := gzipReader.Close(); closeErr != nil || compressed.Count > MaximumArchiveBytes || files < 7 {
		return 0, 0, errors.New("release archive is truncated, oversized, or incomplete")
	}
	if _, err := buffered.ReadByte(); !errors.Is(err, io.EOF) {
		return 0, 0, errors.New("release archive contains a second member or trailing data")
	}
	return total, files, nil
}

// ExtractReleaseArchive is the bootstrap-facing form of the same strict
// extractor used for runtime update staging. The destination must already be
// an empty, real directory so extraction never merges attacker-controlled
// content with a pre-existing tree.
func ExtractReleaseArchive(ctx context.Context, input io.Reader, destination string) (int64, int, error) {
	if input == nil || !filepath.IsAbs(destination) {
		return 0, 0, errors.New("archive reader and absolute extraction directory are required")
	}
	destination = filepath.Clean(destination)
	info, err := os.Lstat(destination)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return 0, 0, errors.New("extraction destination must be a real directory")
	}
	entries, err := os.ReadDir(destination)
	if err != nil || len(entries) != 0 {
		return 0, 0, errors.New("extraction destination must be empty")
	}
	return extractReleaseArchive(ctx, input, destination)
}

func writePendingOperation(filename string, operation Operation) error {
	content, err := marshalLine(operation)
	if err != nil {
		return errors.New("encode pending update failed")
	}
	temporary := filename + ".tmp"
	if err := os.Remove(temporary); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := writeExclusive(temporary, content, 0o600); err != nil {
		return err
	}
	if err := replaceFile(temporary, filename); err != nil {
		_ = os.Remove(temporary)
		return fmt.Errorf("commit pending update metadata: %w", err)
	}
	return syncDirectoryPath(filepath.Dir(filename))
}

func validOperation(operation Operation) bool {
	created, err := time.Parse(time.RFC3339Nano, operation.CreatedAt)
	sourceValid := operation.SourceKind == "" && operation.SourceChannel == "" && operation.SourceReference == "" || validSource(Source{Kind: operation.SourceKind, Channel: operation.SourceChannel, Reference: operation.SourceReference})
	return operation.FormatVersion == StagingFormatVersion && updateIDPattern.MatchString(operation.UpdateID) && operation.State == "STAGED" && err == nil && !created.IsZero() && versionPattern.MatchString(operation.GatewayVersion) && mihomoVersionPattern.MatchString(operation.MihomoVersion) && digestPattern.MatchString(operation.SignerKeySHA256) && digestPattern.MatchString(operation.ManifestSHA256) && operation.UncompressedBytes > 0 && operation.UncompressedBytes <= MaximumArtifactBytes && operation.FileCount >= 7 && operation.FileCount <= MaximumFiles+2 && sourceValid
}

func validSource(source Source) bool {
	if source.Kind != SourceUpload && source.Kind != SourceGitHubChannel && source.Kind != SourceExactHTTPS {
		return false
	}
	if source.Kind == SourceGitHubChannel {
		if source.Channel != "stable" && source.Channel != "testing" {
			return false
		}
	} else if source.Channel != "" {
		return false
	}
	reference := strings.TrimSpace(source.Reference)
	if reference == "" || len(reference) > 256 || strings.ContainsAny(reference, "\r\n\t") || strings.Contains(reference, "?") || strings.Contains(reference, "@") {
		return false
	}
	return reference == source.Reference
}

func (stager *Stager) prepareRoot() error {
	if !filepath.IsAbs(stager.StateDir) || filepath.Clean(stager.Root) != filepath.Join(filepath.Clean(stager.StateDir), "update-staging") || len(stager.Policy.PublicKey) == 0 {
		return errors.New("update stager paths or trust policy are invalid")
	}
	if err := os.MkdirAll(stager.Root, 0o700); err != nil {
		return fmt.Errorf("create update staging root: %w", err)
	}
	info, err := os.Lstat(stager.Root)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return errors.New("update staging root is unsafe")
	}
	return os.Chmod(stager.Root, 0o700)
}

func removeStrictTree(root string) error {
	info, err := os.Lstat(root)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || !updateIDPattern.MatchString(filepath.Base(root)) {
		return errors.New("refuse to remove unsafe update staging")
	}
	var paths []string
	if err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		item, err := os.Lstat(path)
		if err != nil || item.Mode()&os.ModeSymlink != 0 || !item.IsDir() && !item.Mode().IsRegular() {
			return errors.New("refuse to remove unsafe staged update contents")
		}
		paths = append(paths, path)
		return nil
	}); err != nil {
		return err
	}
	for index := len(paths) - 1; index >= 0; index-- {
		if err := os.Remove(paths[index]); err != nil {
			return err
		}
	}
	return nil
}

func syncTree(root string) error {
	var directories []string
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			directories = append(directories, path)
		}
		return nil
	})
	if err != nil {
		return err
	}
	for index := len(directories) - 1; index >= 0; index-- {
		if err := syncDirectoryPath(directories[index]); err != nil {
			return err
		}
	}
	return nil
}

func syncDirectoryPath(directory string) error {
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

func newUpdateID(now time.Time) (string, error) {
	random := make([]byte, 12)
	if _, err := rand.Read(random); err != nil {
		return "", errors.New("generate update id failed")
	}
	return "update-" + now.UTC().Format("20060102T150405Z") + "-" + hex.EncodeToString(random), nil
}

func (stager *Stager) now() time.Time {
	if stager.Now != nil {
		return stager.Now().UTC()
	}
	return time.Now().UTC()
}

func pathExists(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}

type countingReader struct {
	Reader io.Reader
	Count  int64
}

func (reader *countingReader) Read(buffer []byte) (int, error) {
	read, err := reader.Reader.Read(buffer)
	reader.Count += int64(read)
	return read, err
}
