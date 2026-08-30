// Package vpsupdate implements the independently signed VPS Hub application
// update lifecycle. It never updates the OS, APT packages, foreign services,
// or host-wide firewall state.
package vpsupdate

import (
	"bytes"
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
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	updatepkg "gateway-vpn/internal/update"
	"gateway-vpn/internal/vpsrelease"
)

const (
	StagingFormatVersion = 1
	MaximumArchiveBytes  = int64(192 << 20)
	pendingFilename      = "pending-update.json"
)

var (
	ErrUpdatePending       = errors.New("a verified VPS update is already staged")
	ErrArchiveTooLarge     = errors.New("VPS update archive exceeds its bound")
	ErrHostContractChanged = errors.New("VPS update changes the installed host contract")
	updateIDPattern        = regexp.MustCompile(`^vps-update-[0-9]{8}T[0-9]{6}Z-[a-f0-9]{24}$`)
	digestPattern          = regexp.MustCompile(`^[a-f0-9]{64}$`)
)

type Operation struct {
	FormatVersion      int    `json:"format_version"`
	UpdateID           string `json:"update_id"`
	State              string `json:"state"`
	CreatedAt          string `json:"created_at"`
	CurrentVersion     string `json:"current_version"`
	CandidateVersion   string `json:"candidate_version"`
	CurrentSchema      int64  `json:"current_schema"`
	CandidateSchema    int64  `json:"candidate_schema"`
	SignerKeySHA256    string `json:"signer_key_sha256"`
	ManifestSHA256     string `json:"manifest_sha256"`
	HostContractSHA256 string `json:"host_contract_sha256"`
	UncompressedBytes  int64  `json:"uncompressed_bytes"`
	FileCount          int    `json:"file_count"`
}

type Stager struct {
	StateDirectory string
	ReleaseRoot    string
	TrustedKeyPath string
	CurrentVersion string
	CurrentSchema  int64
	Profile        string
	Now            func() time.Time
	mutex          sync.Mutex
}

func (stager *Stager) Stage(ctx context.Context, archive io.Reader) (Operation, error) {
	stager.mutex.Lock()
	defer stager.mutex.Unlock()
	if archive == nil {
		return Operation{}, errors.New("VPS release archive is required")
	}
	policy, current, err := stager.prepare()
	if err != nil {
		return Operation{}, err
	}
	if _, exists, err := stager.statusLocked(policy); err != nil {
		return Operation{}, err
	} else if exists {
		return Operation{}, ErrUpdatePending
	}
	id, err := newUpdateID(stager.now())
	if err != nil {
		return Operation{}, err
	}
	root := stager.stagingRoot()
	temporary := filepath.Join(root, ".tmp-"+id)
	final := filepath.Join(root, id)
	if err := os.Mkdir(temporary, 0o700); err != nil {
		return Operation{}, fmt.Errorf("create VPS update staging directory: %w", err)
	}
	defer os.RemoveAll(temporary)
	limited := &boundedReader{Reader: archive, Remaining: MaximumArchiveBytes + 1}
	bytesWritten, files, err := updatepkg.ExtractReleaseArchive(ctx, limited, temporary)
	if err != nil {
		return Operation{}, fmt.Errorf("extract strict VPS release archive: %w", err)
	}
	if limited.Exceeded || limited.ReadBytes > MaximumArchiveBytes {
		return Operation{}, ErrArchiveTooLarge
	}
	verified, err := vpsrelease.VerifyRelease(temporary, policy)
	if err != nil {
		return Operation{}, fmt.Errorf("verify staged VPS release: %w", err)
	}
	if compareSemver(verified.Release.Version, stager.CurrentVersion) <= 0 {
		return Operation{}, errors.New("VPS update candidate must be newer than the running release")
	}
	if verified.Release.DatabaseSchemaMaximum < stager.CurrentSchema {
		return Operation{}, errors.New("VPS update candidate cannot read the current database schema")
	}
	currentContract, err := HostContractSHA256(current.Manifest)
	if err != nil {
		return Operation{}, err
	}
	candidateContract, err := HostContractSHA256(verified.Manifest)
	if err != nil {
		return Operation{}, err
	}
	if currentContract != candidateContract {
		return Operation{}, ErrHostContractChanged
	}
	manifestContent, err := readStable(filepath.Join(temporary, vpsrelease.ManifestFilename), vpsrelease.MaximumManifestBytes)
	if err != nil {
		return Operation{}, err
	}
	manifestDigest := sha256.Sum256(manifestContent)
	if err := syncTree(temporary); err != nil {
		return Operation{}, err
	}
	if err := os.Rename(temporary, final); err != nil {
		return Operation{}, fmt.Errorf("commit staged VPS release: %w", err)
	}
	if err := syncDirectory(root); err != nil {
		return Operation{}, err
	}
	operation := Operation{
		FormatVersion: StagingFormatVersion, UpdateID: id, State: "STAGED", CreatedAt: stager.now().Format(time.RFC3339Nano),
		CurrentVersion: stager.CurrentVersion, CandidateVersion: verified.Release.Version,
		CurrentSchema: stager.CurrentSchema, CandidateSchema: verified.Release.DatabaseSchemaMaximum,
		SignerKeySHA256: verified.Fingerprint, ManifestSHA256: hex.EncodeToString(manifestDigest[:]),
		HostContractSHA256: candidateContract, UncompressedBytes: bytesWritten, FileCount: files,
	}
	if err := writeAtomicJSON(filepath.Join(root, pendingFilename), operation, 0o600); err != nil {
		_ = removeStagedTree(final)
		return Operation{}, err
	}
	return operation, nil
}

func (stager *Stager) Status() (Operation, bool, error) {
	stager.mutex.Lock()
	defer stager.mutex.Unlock()
	policy, _, err := stager.prepare()
	if err != nil {
		return Operation{}, false, err
	}
	return stager.statusLocked(policy)
}

func (stager *Stager) statusLocked(policy vpsrelease.VerificationPolicy) (Operation, bool, error) {
	filename := filepath.Join(stager.stagingRoot(), pendingFilename)
	content, err := readStable(filename, 64<<10)
	if errors.Is(err, os.ErrNotExist) {
		return Operation{}, false, nil
	}
	if err != nil {
		return Operation{}, false, errors.New("pending VPS update metadata is unsafe")
	}
	var operation Operation
	if decodeStrict(content, &operation) != nil || !validOperation(operation) || operation.CurrentVersion != stager.CurrentVersion || operation.CurrentSchema != stager.CurrentSchema {
		return Operation{}, false, errors.New("pending VPS update metadata is invalid")
	}
	root := filepath.Join(stager.stagingRoot(), operation.UpdateID)
	verified, err := vpsrelease.VerifyRelease(root, policy)
	if err != nil {
		return Operation{}, false, errors.New("pending VPS update no longer verifies")
	}
	manifestContent, err := readStable(filepath.Join(root, vpsrelease.ManifestFilename), vpsrelease.MaximumManifestBytes)
	digest := sha256.Sum256(manifestContent)
	hostContract, contractErr := HostContractSHA256(verified.Manifest)
	if err != nil || contractErr != nil || verified.Release.Version != operation.CandidateVersion || verified.Release.DatabaseSchemaMaximum != operation.CandidateSchema || verified.Fingerprint != operation.SignerKeySHA256 || hex.EncodeToString(digest[:]) != operation.ManifestSHA256 || hostContract != operation.HostContractSHA256 || len(verified.Manifest.Files)+2 != operation.FileCount {
		return Operation{}, false, errors.New("pending VPS update metadata does not match its signed release")
	}
	return operation, true, nil
}

func (stager *Stager) PendingReleaseRoot(updateID string) (string, error) {
	operation, exists, err := stager.Status()
	if err != nil || !exists || operation.UpdateID != updateID || !updateIDPattern.MatchString(updateID) {
		return "", errors.New("requested verified VPS update is not pending")
	}
	return filepath.Join(stager.stagingRoot(), updateID), nil
}

func (stager *Stager) Discard(updateID string) error {
	stager.mutex.Lock()
	defer stager.mutex.Unlock()
	policy, _, err := stager.prepare()
	if err != nil {
		return err
	}
	operation, exists, err := stager.statusLocked(policy)
	if err != nil || !exists || operation.UpdateID != updateID {
		return errors.New("requested verified VPS update is not pending")
	}
	return stager.discardLocked(updateID)
}

// discardApplied removes an already reverified release after the root updater
// durably records PREPARED. It deliberately does not re-check the current
// pointer: the pointer may already have moved when cleanup is retried after a
// process interruption. All deletion remains confined by the validated ID and
// fixed staging layout.
func (stager *Stager) discardApplied(updateID string) error {
	stager.mutex.Lock()
	defer stager.mutex.Unlock()
	if !filepath.IsAbs(stager.StateDirectory) || !updateIDPattern.MatchString(updateID) {
		return errors.New("VPS update staging cleanup contract is invalid")
	}
	content, err := readStable(filepath.Join(stager.stagingRoot(), pendingFilename), 64<<10)
	if err != nil {
		return errors.New("pending VPS update metadata is unavailable for cleanup")
	}
	var operation Operation
	if decodeStrict(content, &operation) != nil || !validOperation(operation) || operation.UpdateID != updateID {
		return errors.New("pending VPS update metadata is invalid for cleanup")
	}
	return stager.discardLocked(updateID)
}

func (stager *Stager) discardLocked(updateID string) error {
	marker := filepath.Join(stager.stagingRoot(), pendingFilename)
	if err := os.Remove(marker); err != nil {
		return err
	}
	if err := syncDirectory(stager.stagingRoot()); err != nil {
		return err
	}
	if err := removeStagedTree(filepath.Join(stager.stagingRoot(), updateID)); err != nil {
		return err
	}
	return syncDirectory(stager.stagingRoot())
}

func (stager *Stager) prepare() (vpsrelease.VerificationPolicy, vpsrelease.VerifiedRelease, error) {
	if !filepath.IsAbs(stager.StateDirectory) || !filepath.IsAbs(stager.ReleaseRoot) || !filepath.IsAbs(stager.TrustedKeyPath) || updatepkg.ValidateGatewayVersion(stager.CurrentVersion) != nil || stager.CurrentSchema < 1 || !contains(vpsrelease.SupportedProfiles(), stager.Profile) {
		return vpsrelease.VerificationPolicy{}, vpsrelease.VerifiedRelease{}, errors.New("VPS update stager configuration is invalid")
	}
	key, err := updatepkg.LoadPublicKey(stager.TrustedKeyPath)
	if err != nil {
		return vpsrelease.VerificationPolicy{}, vpsrelease.VerifiedRelease{}, err
	}
	policy := vpsrelease.VerificationPolicy{PublicKey: key, ExpectedOS: "linux", ExpectedArch: "amd64", ExpectedProfile: stager.Profile}
	currentRoot, err := currentReleaseRoot(stager.ReleaseRoot)
	if err != nil {
		return vpsrelease.VerificationPolicy{}, vpsrelease.VerifiedRelease{}, err
	}
	currentPolicy := policy
	currentPolicy.ExpectedVersion = stager.CurrentVersion
	current, err := vpsrelease.VerifyRelease(currentRoot, currentPolicy)
	if err != nil || current.Release.DatabaseSchemaMaximum != stager.CurrentSchema {
		return vpsrelease.VerificationPolicy{}, vpsrelease.VerifiedRelease{}, errors.New("running VPS release does not match its signed update contract")
	}
	root := stager.stagingRoot()
	if err := os.MkdirAll(root, 0o700); err != nil {
		return vpsrelease.VerificationPolicy{}, vpsrelease.VerifiedRelease{}, err
	}
	info, err := os.Lstat(root)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return vpsrelease.VerificationPolicy{}, vpsrelease.VerifiedRelease{}, errors.New("VPS update staging root is unsafe")
	}
	if err := os.Chmod(root, 0o700); err != nil {
		return vpsrelease.VerificationPolicy{}, vpsrelease.VerifiedRelease{}, err
	}
	return policy, current, nil
}

func (stager *Stager) stagingRoot() string {
	return filepath.Join(filepath.Clean(stager.StateDirectory), "update-staging")
}
func (stager *Stager) now() time.Time {
	if stager.Now != nil {
		return stager.Now().UTC()
	}
	return time.Now().UTC()
}

// HostContractSHA256 binds pointer-only updates to the exact signed files
// projected by the installer into /etc and systemd. A changed projection must
// use a separate signed installer transaction.
func HostContractSHA256(manifest vpsrelease.Manifest) (string, error) {
	selected := make([]vpsrelease.FileRecord, 0)
	for _, item := range manifest.Files {
		if strings.HasPrefix(item.Path, "packaging/vps/") {
			selected = append(selected, item)
		}
	}
	if len(selected) < 10 {
		return "", errors.New("signed VPS host contract is incomplete")
	}
	sort.Slice(selected, func(i, j int) bool { return selected[i].Path < selected[j].Path })
	hash := sha256.New()
	for _, item := range selected {
		fmt.Fprintf(hash, "%s\x00%d\x00%s\x00%t\n", item.Path, item.Bytes, item.SHA256, item.Executable)
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func currentReleaseRoot(releaseRoot string) (string, error) {
	link := filepath.Join(filepath.Clean(releaseRoot), "current")
	target, err := os.Readlink(link)
	if err != nil || filepath.IsAbs(target) {
		return "", errors.New("VPS current release pointer is invalid")
	}
	target = filepath.ToSlash(filepath.Clean(target))
	if !strings.HasPrefix(target, "releases/v") || strings.Contains(strings.TrimPrefix(target, "releases/v"), "/") {
		return "", errors.New("VPS current release pointer escapes its layout")
	}
	root := filepath.Join(filepath.Clean(releaseRoot), filepath.FromSlash(target))
	info, err := os.Lstat(root)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return "", errors.New("VPS current release directory is invalid")
	}
	return root, nil
}

func validOperation(value Operation) bool {
	created, err := time.Parse(time.RFC3339Nano, value.CreatedAt)
	return value.FormatVersion == StagingFormatVersion && updateIDPattern.MatchString(value.UpdateID) && value.State == "STAGED" && err == nil && !created.IsZero() && updatepkg.ValidateGatewayVersion(value.CurrentVersion) == nil && updatepkg.ValidateGatewayVersion(value.CandidateVersion) == nil && compareSemver(value.CandidateVersion, value.CurrentVersion) > 0 && value.CurrentSchema > 0 && value.CandidateSchema >= value.CurrentSchema && digestPattern.MatchString(value.SignerKeySHA256) && digestPattern.MatchString(value.ManifestSHA256) && digestPattern.MatchString(value.HostContractSHA256) && value.UncompressedBytes > 0 && value.UncompressedBytes <= vpsrelease.MaximumArtifactBytes && value.FileCount >= 10 && value.FileCount <= vpsrelease.MaximumFiles+2
}

func newUpdateID(now time.Time) (string, error) {
	random := make([]byte, 12)
	if _, err := rand.Read(random); err != nil {
		return "", err
	}
	return "vps-update-" + now.UTC().Format("20060102T150405Z") + "-" + hex.EncodeToString(random), nil
}

func writeAtomicJSON(filename string, value any, mode os.FileMode) error {
	content, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	content = append(content, '\n')
	temporary := filename + ".tmp"
	_ = os.Remove(temporary)
	file, err := os.OpenFile(temporary, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	written, writeErr := file.Write(content)
	syncErr, closeErr := file.Sync(), file.Close()
	if writeErr != nil || syncErr != nil || closeErr != nil || written != len(content) {
		_ = os.Remove(temporary)
		return errors.Join(errors.New("write durable VPS update metadata failed"), writeErr, syncErr, closeErr)
	}
	if err := replacePath(temporary, filename); err != nil {
		_ = os.Remove(temporary)
		return err
	}
	return syncDirectory(filepath.Dir(filename))
}

func readStable(filename string, maximum int64) ([]byte, error) {
	info, err := os.Lstat(filename)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maximum || runtime.GOOS != "windows" && info.Mode().Perm()&0o022 != 0 {
		return nil, errors.New("bounded protected regular file is required")
	}
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	opened, statErr := file.Stat()
	content, readErr := io.ReadAll(io.LimitReader(file, maximum+1))
	closeErr := file.Close()
	if statErr != nil || !os.SameFile(info, opened) || readErr != nil || closeErr != nil || int64(len(content)) != info.Size() {
		return nil, errors.New("stable file read failed")
	}
	return content, nil
}

func decodeStrict(content []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("JSON contains trailing data")
	}
	return nil
}

func removeStagedTree(root string) error {
	if !updateIDPattern.MatchString(filepath.Base(root)) {
		return errors.New("unsafe staged VPS update root")
	}
	info, err := os.Lstat(root)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return errors.New("unsafe staged VPS update tree")
	}
	return os.RemoveAll(root)
}

func syncTree(root string) error {
	directories := []string{}
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
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
		if err := syncDirectory(directories[index]); err != nil {
			return err
		}
	}
	return nil
}

func syncDirectory(path string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	return file.Sync()
}

type boundedReader struct {
	Reader               io.Reader
	Remaining, ReadBytes int64
	Exceeded             bool
}

func (reader *boundedReader) Read(buffer []byte) (int, error) {
	if reader.Remaining <= 0 {
		reader.Exceeded = true
		return 0, io.EOF
	}
	if int64(len(buffer)) > reader.Remaining {
		buffer = buffer[:reader.Remaining]
	}
	n, err := reader.Reader.Read(buffer)
	reader.Remaining -= int64(n)
	reader.ReadBytes += int64(n)
	if reader.Remaining == 0 && err == nil {
		reader.Exceeded = true
	}
	return n, err
}

func compareSemver(left, right string) int {
	l := parseSemver(left)
	r := parseSemver(right)
	for i := 0; i < 3; i++ {
		if l.numbers[i] < r.numbers[i] {
			return -1
		}
		if l.numbers[i] > r.numbers[i] {
			return 1
		}
	}
	if l.pre == r.pre {
		return 0
	}
	if l.pre == "" {
		return 1
	}
	if r.pre == "" {
		return -1
	}
	lp, rp := strings.Split(l.pre, "."), strings.Split(r.pre, ".")
	for i := 0; i < len(lp) && i < len(rp); i++ {
		li, le := strconv.ParseUint(lp[i], 10, 64)
		ri, re := strconv.ParseUint(rp[i], 10, 64)
		switch {
		case le == nil && re == nil && li < ri:
			return -1
		case le == nil && re == nil && li > ri:
			return 1
		case le == nil && re != nil:
			return -1
		case le != nil && re == nil:
			return 1
		case lp[i] < rp[i]:
			return -1
		case lp[i] > rp[i]:
			return 1
		}
	}
	if len(lp) < len(rp) {
		return -1
	}
	if len(lp) > len(rp) {
		return 1
	}
	return 0
}

type semver struct {
	numbers [3]uint64
	pre     string
}

func parseSemver(value string) semver {
	core := strings.SplitN(value, "+", 2)[0]
	parts := strings.SplitN(core, "-", 2)
	numbers := strings.Split(parts[0], ".")
	result := semver{}
	for i := range 3 {
		result.numbers[i], _ = strconv.ParseUint(numbers[i], 10, 64)
	}
	if len(parts) == 2 {
		result.pre = parts[1]
	}
	return result
}

func contains(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}
