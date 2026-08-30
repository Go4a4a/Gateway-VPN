// Package vpsrelease defines the independently signed, role-specific VPS
// artifact contract. A VPS archive intentionally does not pretend to be a
// Gateway runtime release and therefore does not require Mihomo or SQLite
// compatibility metadata.
package vpsrelease

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
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

	updatepkg "gateway-vpn/internal/update"
)

const (
	ReleaseFormatVersion  = 1
	ManifestFormatVersion = 1
	ReleaseFilename       = "release.json"
	ManifestFilename      = "manifest.json"
	SignatureFilename     = "release.sig"
	LegacyHashFilename    = "manifest.sha256"
	MaximumReleaseBytes   = int64(64 << 10)
	MaximumManifestBytes  = int64(256 << 10)
	MaximumSignatureBytes = int64(1024)
	MaximumFileBytes      = int64(32 << 20)
	MaximumArtifactBytes  = int64(128 << 20)
	MaximumFiles          = 64
)

var (
	digestPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)
	commitPattern = regexp.MustCompile(`^(?:[a-f0-9]{40}|[a-f0-9]{64})$`)
	pathPart      = regexp.MustCompile(`^[A-Za-z0-9._+@-]+$`)
	profiles      = []string{"debian-12", "ubuntu-20.04", "ubuntu-22.04", "ubuntu-24.04", "ubuntu-26.04"}
)

type Release struct {
	FormatVersion     int      `json:"format_version"`
	Role              string   `json:"role"`
	Version           string   `json:"version"`
	OS                string   `json:"os"`
	Arch              string   `json:"arch"`
	SourceCommit      string   `json:"source_commit"`
	BuildDate         string   `json:"build_date"`
	SupportedProfiles []string `json:"supported_profiles"`
	InterfaceName     string   `json:"interface_name"`
	ManagementSubnet  string   `json:"management_subnet"`
	ListenPort        int      `json:"listen_port"`
}

type FileRecord struct {
	Path       string `json:"path"`
	Bytes      int64  `json:"bytes"`
	SHA256     string `json:"sha256"`
	Executable bool   `json:"executable"`
}

type Manifest struct {
	FormatVersion     int          `json:"format_version"`
	SignerKeySHA256   string       `json:"signer_key_sha256"`
	ReleaseJSONSHA256 string       `json:"release_json_sha256"`
	Files             []FileRecord `json:"files"`
}

type VerificationPolicy struct {
	PublicKey       ed25519.PublicKey
	ExpectedVersion string
	ExpectedOS      string
	ExpectedArch    string
	ExpectedProfile string
}

type VerifiedRelease struct {
	Root        string
	Release     Release
	Manifest    Manifest
	Fingerprint string
}

func SupportedProfiles() []string { return append([]string(nil), profiles...) }

func SignRelease(root string, privateKey ed25519.PrivateKey) (Manifest, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return Manifest{}, errors.New("valid Ed25519 VPS release private key is required")
	}
	root, err := safeRoot(root)
	if err != nil {
		return Manifest{}, err
	}
	for _, name := range []string{ManifestFilename, SignatureFilename} {
		if err := os.Remove(filepath.Join(root, name)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return Manifest{}, errors.New("remove stale VPS release signature metadata failed")
		}
	}
	releaseContent, err := readBoundedRegular(filepath.Join(root, ReleaseFilename), MaximumReleaseBytes)
	if err != nil {
		return Manifest{}, err
	}
	var release Release
	if decodeStrict(releaseContent, &release) != nil || ValidateRelease(release) != nil {
		return Manifest{}, errors.New("VPS release metadata contract is invalid")
	}
	files, err := collectFiles(root)
	if err != nil {
		return Manifest{}, err
	}
	if err := validateRequiredFiles(files); err != nil {
		return Manifest{}, err
	}
	fingerprint, _ := updatepkg.PublicKeyFingerprint(privateKey.Public().(ed25519.PublicKey))
	digest := sha256.Sum256(releaseContent)
	manifest := Manifest{
		FormatVersion: ManifestFormatVersion, SignerKeySHA256: fingerprint,
		ReleaseJSONSHA256: hex.EncodeToString(digest[:]), Files: files,
	}
	if err := validateManifest(manifest, fingerprint); err != nil {
		return Manifest{}, err
	}
	content, err := marshalLine(manifest)
	if err != nil || int64(len(content)) > MaximumManifestBytes {
		return Manifest{}, errors.New("encode bounded VPS release manifest failed")
	}
	signature := []byte(base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, content)) + "\n")
	if err := writeExclusive(filepath.Join(root, ManifestFilename), content, 0o644); err != nil {
		return Manifest{}, err
	}
	if err := writeExclusive(filepath.Join(root, SignatureFilename), signature, 0o644); err != nil {
		_ = os.Remove(filepath.Join(root, ManifestFilename))
		return Manifest{}, err
	}
	return manifest, nil
}

func VerifyRelease(root string, policy VerificationPolicy) (VerifiedRelease, error) {
	root, err := safeRoot(root)
	if err != nil {
		return VerifiedRelease{}, err
	}
	if len(policy.PublicKey) != ed25519.PublicKeySize {
		return VerifiedRelease{}, errors.New("trusted Ed25519 VPS release key is required")
	}
	manifestContent, err := readBoundedRegular(filepath.Join(root, ManifestFilename), MaximumManifestBytes)
	if err != nil {
		return VerifiedRelease{}, err
	}
	signatureContent, err := readBoundedRegular(filepath.Join(root, SignatureFilename), MaximumSignatureBytes)
	if err != nil {
		return VerifiedRelease{}, err
	}
	signature, err := base64.StdEncoding.Strict().DecodeString(strings.TrimSpace(string(signatureContent)))
	if err != nil || len(signature) != ed25519.SignatureSize || !ed25519.Verify(policy.PublicKey, manifestContent, signature) {
		return VerifiedRelease{}, errors.New("VPS release signature verification failed")
	}
	var manifest Manifest
	if err := decodeStrict(manifestContent, &manifest); err != nil {
		return VerifiedRelease{}, errors.New("decode signed VPS release manifest failed")
	}
	fingerprint, _ := updatepkg.PublicKeyFingerprint(policy.PublicKey)
	if err := validateManifest(manifest, fingerprint); err != nil {
		return VerifiedRelease{}, err
	}
	actual, err := collectFiles(root)
	if err != nil || !equalRecords(actual, manifest.Files) {
		return VerifiedRelease{}, errors.New("VPS release files do not exactly match the signed manifest")
	}
	releaseContent, err := readBoundedRegular(filepath.Join(root, ReleaseFilename), MaximumReleaseBytes)
	if err != nil {
		return VerifiedRelease{}, err
	}
	digest := sha256.Sum256(releaseContent)
	if hex.EncodeToString(digest[:]) != manifest.ReleaseJSONSHA256 {
		return VerifiedRelease{}, errors.New("VPS release metadata digest mismatch")
	}
	var release Release
	if err := decodeStrict(releaseContent, &release); err != nil || ValidateRelease(release) != nil {
		return VerifiedRelease{}, errors.New("VPS release metadata contract is invalid")
	}
	if policy.ExpectedVersion != "" && release.Version != policy.ExpectedVersion || policy.ExpectedOS != "" && release.OS != policy.ExpectedOS || policy.ExpectedArch != "" && release.Arch != policy.ExpectedArch || policy.ExpectedProfile != "" && !contains(release.SupportedProfiles, policy.ExpectedProfile) {
		return VerifiedRelease{}, errors.New("VPS release is incompatible with the pinned target")
	}
	if err := validateRequiredFiles(manifest.Files); err != nil {
		return VerifiedRelease{}, err
	}
	return VerifiedRelease{Root: root, Release: release, Manifest: manifest, Fingerprint: fingerprint}, nil
}

func validateRequiredFiles(files []FileRecord) error {
	for _, required := range []struct {
		path       string
		executable bool
	}{
		{"bin/gateway-vpnctl", true},
		{"bin/gateway-vpn-vps-agent", true},
		{"scripts/install-vps.sh", true},
		{"scripts/uninstall-vps.sh", true},
		{"scripts/recover-vps-install.sh", true},
		{"packaging/vps/nftables/gateway-vpn-vps.nft.in", false},
		{"packaging/vps/sysctl.d/90-gateway-vpn-vps.conf", false},
		{"packaging/vps/systemd/gateway-vpn-vps-firewall.service", false},
		{"packaging/vps/systemd/gateway-vpn-vps-install-recovery.service", false},
		{"packaging/vps/systemd/gateway-vpn-vps-agent.service", false},
		{"packaging/vps/systemd/gateway-vpn-vps-restore.service", false},
		{"packaging/vps/systemd/gateway-vpn-vps-restore.path", false},
		{"packaging/vps/systemd/gateway-vpn-vps-restore-recovery.service", false},
		{"packaging/vps/systemd/gateway-vpn-vps-fabric.service", false},
		{"packaging/vps/systemd/gateway-vpn-vps-fabric.path", false},
		{"packaging/vps/systemd/gateway-vpn-vps-fabric-recovery.service", false},
		{"packaging/vps/systemd/gateway-vpn-vps-fabric-watchdog.service", false},
		{"packaging/vps/systemd/gateway-vpn-vps-fabric-watchdog.timer", false},
		{"packaging/vps/config/config.yaml", false},
		{"packaging/vps/systemd/wg-quick@wg-mgmt.service.d/gateway-vpn.conf", false},
		{ReleaseFilename, false},
		{LegacyHashFilename, false},
	} {
		record := findRecord(files, required.path)
		if record == nil || required.executable && !record.Executable {
			return fmt.Errorf("required signed VPS release file is missing or invalid: %s", required.path)
		}
	}
	return nil
}

func ValidateRelease(release Release) error {
	buildDate, dateErr := time.Parse(time.RFC3339, release.BuildDate)
	if release.FormatVersion != ReleaseFormatVersion || release.Role != "vps" || updatepkg.ValidateGatewayVersion(release.Version) != nil || release.OS != "linux" || release.Arch != "amd64" || !commitPattern.MatchString(release.SourceCommit) || dateErr != nil || buildDate.IsZero() || !equalStrings(release.SupportedProfiles, profiles) || release.InterfaceName != "wg-mgmt" || release.ManagementSubnet != "10.80.0.0/24" || release.ListenPort != 51821 {
		return errors.New("VPS release metadata contract is invalid")
	}
	return nil
}

func validateManifest(manifest Manifest, fingerprint string) error {
	if manifest.FormatVersion != ManifestFormatVersion || manifest.SignerKeySHA256 != fingerprint || !digestPattern.MatchString(manifest.ReleaseJSONSHA256) || len(manifest.Files) < 8 || len(manifest.Files) > MaximumFiles {
		return errors.New("signed VPS release manifest contract is invalid")
	}
	previous := ""
	var total int64
	for _, record := range manifest.Files {
		if !safeRelativePath(record.Path) || record.Path == ManifestFilename || record.Path == SignatureFilename || record.Bytes <= 0 || record.Bytes > MaximumFileBytes || !digestPattern.MatchString(record.SHA256) || previous >= record.Path {
			return errors.New("signed VPS release file record is invalid or unsorted")
		}
		previous = record.Path
		total += record.Bytes
		if total > MaximumArtifactBytes {
			return errors.New("signed VPS release exceeds its total size bound")
		}
	}
	return nil
}

func collectFiles(root string) ([]FileRecord, error) {
	records := make([]FileRecord, 0, 32)
	var total int64
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == root {
			return nil
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		relative = filepath.ToSlash(relative)
		info, err := os.Lstat(path)
		if err != nil || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("VPS release contains a symlink or unreadable entry")
		}
		if entry.IsDir() {
			if !safeRelativePath(relative) {
				return errors.New("VPS release contains an unsafe directory")
			}
			return nil
		}
		if !info.Mode().IsRegular() || !safeRelativePath(relative) {
			return errors.New("VPS release contains an unsafe file")
		}
		if relative == ManifestFilename || relative == SignatureFilename {
			return nil
		}
		if len(records) >= MaximumFiles || info.Size() <= 0 || info.Size() > MaximumFileBytes {
			return errors.New("VPS release file count or size exceeds its bound")
		}
		digest, read, err := hashFile(path)
		if err != nil || read != info.Size() {
			return errors.New("hash VPS release file failed")
		}
		total += read
		if total > MaximumArtifactBytes {
			return errors.New("VPS release exceeds its total size bound")
		}
		executable := info.Mode().Perm()&0o111 != 0
		if runtime.GOOS == "windows" && (strings.HasPrefix(relative, "bin/") || strings.HasPrefix(relative, "scripts/")) {
			executable = true
		}
		records = append(records, FileRecord{Path: relative, Bytes: read, SHA256: digest, Executable: executable})
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(records, func(i, j int) bool { return records[i].Path < records[j].Path })
	return records, nil
}

func safeRoot(root string) (string, error) {
	if !filepath.IsAbs(root) {
		return "", errors.New("VPS release root must be absolute")
	}
	root = filepath.Clean(root)
	info, err := os.Lstat(root)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return "", errors.New("VPS release root must be a real directory")
	}
	return root, nil
}

func safeRelativePath(value string) bool {
	if value == "" || len(value) > 512 || strings.Contains(value, "\\") || strings.HasPrefix(value, "/") || filepath.IsAbs(value) || filepath.ToSlash(filepath.Clean(filepath.FromSlash(value))) != value {
		return false
	}
	parts := strings.Split(value, "/")
	if len(parts) > 16 {
		return false
	}
	for _, part := range parts {
		if part == "" || part == "." || part == ".." || len(part) > 128 || !pathPart.MatchString(part) {
			return false
		}
	}
	return true
}

func readBoundedRegular(filename string, maximum int64) ([]byte, error) {
	info, err := os.Lstat(filename)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maximum {
		return nil, errors.New("VPS release file must be bounded regular non-symlink")
	}
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	opened, statErr := file.Stat()
	content, readErr := io.ReadAll(io.LimitReader(file, maximum+1))
	closeErr := file.Close()
	if statErr != nil || !os.SameFile(info, opened) || readErr != nil || closeErr != nil || int64(len(content)) != info.Size() {
		return nil, errors.New("bounded VPS release file read failed")
	}
	return content, nil
}

func hashFile(filename string) (string, int64, error) {
	info, err := os.Lstat(filename)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return "", 0, errors.New("unsafe VPS release file")
	}
	file, err := os.Open(filename)
	if err != nil {
		return "", 0, err
	}
	opened, statErr := file.Stat()
	hash := sha256.New()
	read, copyErr := io.Copy(hash, io.LimitReader(file, MaximumFileBytes+1))
	closeErr := file.Close()
	if statErr != nil || !os.SameFile(info, opened) || copyErr != nil || closeErr != nil || read > MaximumFileBytes {
		return "", 0, errors.New("bounded VPS release file hash failed")
	}
	return hex.EncodeToString(hash.Sum(nil)), read, nil
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

func marshalLine(value any) ([]byte, error) {
	content, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(content, '\n'), nil
}

func writeExclusive(filename string, content []byte, mode os.FileMode) error {
	file, err := os.OpenFile(filename, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	written, writeErr := file.Write(content)
	syncErr := file.Sync()
	closeErr := file.Close()
	if writeErr != nil || syncErr != nil || closeErr != nil || written != len(content) {
		_ = os.Remove(filename)
		return errors.New("durably write VPS release signature metadata failed")
	}
	return os.Chmod(filename, mode)
}

func equalRecords(left, right []FileRecord) bool {
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

func contains(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}

func findRecord(records []FileRecord, path string) *FileRecord {
	index := sort.Search(len(records), func(index int) bool { return records[index].Path >= path })
	if index >= len(records) || records[index].Path != path {
		return nil
	}
	return &records[index]
}
