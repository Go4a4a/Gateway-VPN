// Package update owns the signed Gateway VPN release contract and the
// all-or-rollback host update transaction. Release verification is deliberately
// independent of the candidate binaries: only the already trusted running
// release may authorize execution of a candidate.
package update

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
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
	"time"
)

const (
	ManifestFormatVersion = 1
	ReleaseFormatVersion  = 2
	GatewayAPIContract    = "gateway-vpn-api-v1"
	MihomoAPIContract     = "mihomo-local-v1"
	ManifestFilename      = "manifest.json"
	SignatureFilename     = "release.sig"
	ReleaseFilename       = "release.json"
	LegacyHashFilename    = "manifest.sha256"
	MaximumManifestBytes  = int64(256 << 10)
	MaximumReleaseBytes   = int64(64 << 10)
	maximumHostFileBytes  = int64(256 << 10)
	MaximumSignatureBytes = int64(1024)
	MaximumArtifactBytes  = int64(768 << 20)
	MaximumFileBytes      = int64(512 << 20)
	MaximumFiles          = 128
	MaximumRelativePath   = 512
	MaximumPathParts      = 16
)

var (
	// versionPattern implements the SemVer 2.0.0 grammar relevant to release
	// ordering. In particular, numeric identifiers cannot contain leading
	// zeroes and dot-separated identifiers cannot be empty. Keeping this strict
	// is important because the version is also used as a release directory
	// component and as the durable update identity.
	versionPattern       = regexp.MustCompile(`^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:-(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)(?:\.(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*))*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$`)
	digestPattern        = regexp.MustCompile(`^[a-f0-9]{64}$`)
	pathPart             = regexp.MustCompile(`^[A-Za-z0-9._+@-]+$`)
	mihomoVersionPattern = regexp.MustCompile(`^v?(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$`)
	buildCommitPattern   = regexp.MustCompile(`^(?:[a-f0-9]{40}|[a-f0-9]{64})$`)
)

type Release struct {
	FormatVersion          int    `json:"format_version"`
	GatewayVersion         string `json:"gateway_version"`
	MihomoVersion          string `json:"mihomo_version"`
	OS                     string `json:"os"`
	Arch                   string `json:"arch"`
	MihomoSHA256           string `json:"mihomo_sha256"`
	DatabaseSchemaMinimum  int64  `json:"database_schema_minimum"`
	DatabaseSchemaMaximum  int64  `json:"database_schema_maximum"`
	ConfigSchemaGeneration int    `json:"config_schema_generation"`
	HostContractSHA256     string `json:"host_contract_sha256"`
	GatewayAPIContract     string `json:"gateway_api_contract"`
	MihomoAPIContract      string `json:"mihomo_api_contract"`
	BuildCommit            string `json:"build_commit"`
	BuildDate              string `json:"build_date"`
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
	PublicKey                 ed25519.PublicKey
	ExpectedOS                string
	ExpectedArch              string
	CurrentGatewayVersion     string
	CurrentSchemaVersion      int64
	InitialInstall            bool
	ConfigGeneration          int
	CurrentHostContractSHA256 string
	GatewayAPIContract        string
	MihomoAPIContract         string
	AllowSameVersion          bool
}

type VerifiedRelease struct {
	Root        string
	Release     Release
	Manifest    Manifest
	Fingerprint string
}

func LoadPublicKey(filename string) (ed25519.PublicKey, error) {
	content, err := readBoundedRegular(filename, 16<<10)
	if err != nil {
		return nil, fmt.Errorf("read trusted update key: %w", err)
	}
	block, rest := pem.Decode(content)
	if block == nil || block.Type != "PUBLIC KEY" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("trusted update key must be one PKIX PUBLIC KEY PEM block")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, errors.New("parse trusted update public key failed")
	}
	key, ok := parsed.(ed25519.PublicKey)
	if !ok || len(key) != ed25519.PublicKeySize {
		return nil, errors.New("trusted update key is not Ed25519")
	}
	return append(ed25519.PublicKey(nil), key...), nil
}

func LoadPrivateKey(filename string) (ed25519.PrivateKey, error) {
	filename, err := validatePrivateKeyPath(filename)
	if err != nil {
		return nil, err
	}
	content, err := readBoundedRegular(filename, 32<<10)
	if err != nil {
		return nil, fmt.Errorf("read release signing key: %w", err)
	}
	defer clear(content)
	block, rest := pem.Decode(content)
	if block == nil || block.Type != "PRIVATE KEY" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("release signing key must be one PKCS#8 PRIVATE KEY PEM block")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, errors.New("parse release signing private key failed")
	}
	key, ok := parsed.(ed25519.PrivateKey)
	if !ok || len(key) != ed25519.PrivateKeySize {
		return nil, errors.New("release signing key is not Ed25519")
	}
	return append(ed25519.PrivateKey(nil), key...), nil
}

func PublicKeyFingerprint(key ed25519.PublicKey) (string, error) {
	if len(key) != ed25519.PublicKeySize {
		return "", errors.New("valid Ed25519 public key is required")
	}
	digest := sha256.Sum256(key)
	return hex.EncodeToString(digest[:]), nil
}

func WriteKeyPair(privatePath, publicPath string) (string, error) {
	directory, privatePath, publicPath, err := validateKeyPairDestinationPaths(privatePath, publicPath)
	if err != nil {
		return "", err
	}
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		return "", errors.New("generate Ed25519 update key failed")
	}
	defer clear(privateKey)
	return writeVerifiedKeyPair(directory, privatePath, publicPath, privateKey, publicKey)
}

func VerifyKeyPair(privatePath, publicPath string) (string, error) {
	privatePath, publicPath, err := validateExistingKeyPairPaths(privatePath, publicPath)
	if err != nil {
		return "", err
	}
	privateKey, err := LoadPrivateKey(privatePath)
	if err != nil {
		return "", err
	}
	defer clear(privateKey)
	publicKey, err := LoadPublicKey(publicPath)
	if err != nil {
		return "", err
	}
	if !bytes.Equal(privateKey.Public().(ed25519.PublicKey), publicKey) {
		return "", errors.New("release signing private and public keys do not match")
	}
	return PublicKeyFingerprint(publicKey)
}

func BackupKeyPair(privatePath, publicPath, backupPrivatePath, backupPublicPath string) (string, error) {
	sourcePrivatePath, sourcePublicPath, err := validateExistingKeyPairPaths(privatePath, publicPath)
	if err != nil {
		return "", err
	}
	directory, backupPrivatePath, backupPublicPath, err := validateKeyPairDestinationPaths(backupPrivatePath, backupPublicPath)
	if err != nil {
		return "", err
	}
	if sameFilesystemPath(filepath.Dir(sourcePrivatePath), directory) {
		return "", errors.New("release signing backup must use a different secure directory")
	}
	privateKey, err := LoadPrivateKey(sourcePrivatePath)
	if err != nil {
		return "", err
	}
	defer clear(privateKey)
	publicKey, err := LoadPublicKey(sourcePublicPath)
	if err != nil || !bytes.Equal(privateKey.Public().(ed25519.PublicKey), publicKey) {
		return "", errors.New("source release signing key pair is invalid")
	}
	fingerprint, err := writeVerifiedKeyPair(directory, backupPrivatePath, backupPublicPath, privateKey, publicKey)
	if err != nil {
		return "", err
	}
	if fingerprint == "" {
		return "", errors.New("backup release signing key fingerprint is empty")
	}
	return fingerprint, nil
}

func writeVerifiedKeyPair(directory, privatePath, publicPath string, privateKey ed25519.PrivateKey, publicKey ed25519.PublicKey) (string, error) {
	if len(privateKey) != ed25519.PrivateKeySize || len(publicKey) != ed25519.PublicKeySize || !bytes.Equal(privateKey.Public().(ed25519.PublicKey), publicKey) {
		return "", errors.New("valid matching Ed25519 key pair is required")
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return "", errors.New("encode update private key failed")
	}
	defer clear(privateDER)
	publicDER, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return "", errors.New("encode update public key failed")
	}
	privatePEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER})
	defer clear(privatePEM)
	if err := writeExclusive(privatePath, privatePEM, 0o600); err != nil {
		return "", err
	}
	if err := writeExclusive(publicPath, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER}), 0o644); err != nil {
		_ = os.Remove(privatePath)
		_ = syncDirectory(directory)
		return "", err
	}
	cleanup := func() {
		_ = os.Remove(publicPath)
		_ = os.Remove(privatePath)
		_ = syncDirectory(directory)
	}
	fingerprint, err := VerifyKeyPair(privatePath, publicPath)
	if err != nil {
		cleanup()
		return "", errors.New("verify written release signing key pair failed")
	}
	if err := syncDirectory(directory); err != nil {
		cleanup()
		return "", errors.New("sync generated key directory failed")
	}
	return fingerprint, nil
}

func validateKeyPairDestinationPaths(privatePath, publicPath string) (string, string, string, error) {
	if !filepath.IsAbs(privatePath) || !filepath.IsAbs(publicPath) {
		return "", "", "", errors.New("absolute private and public key paths are required")
	}
	privatePath = filepath.Clean(privatePath)
	publicPath = filepath.Clean(publicPath)
	if sameFilesystemPath(privatePath, publicPath) || !sameFilesystemPath(filepath.Dir(privatePath), filepath.Dir(publicPath)) {
		return "", "", "", errors.New("distinct private and public key paths in one secure directory are required")
	}
	directory := filepath.Dir(privatePath)
	if err := validateSecureKeyDirectory(directory); err != nil {
		return "", "", "", err
	}
	return directory, privatePath, publicPath, nil
}

func validateExistingKeyPairPaths(privatePath, publicPath string) (string, string, error) {
	if !filepath.IsAbs(privatePath) || !filepath.IsAbs(publicPath) {
		return "", "", errors.New("absolute release signing key paths are required")
	}
	privatePath = filepath.Clean(privatePath)
	publicPath = filepath.Clean(publicPath)
	if sameFilesystemPath(privatePath, publicPath) || !sameFilesystemPath(filepath.Dir(privatePath), filepath.Dir(publicPath)) {
		return "", "", errors.New("release signing key pair must use one secure directory")
	}
	if _, err := validatePrivateKeyPath(privatePath); err != nil {
		return "", "", err
	}
	info, err := os.Lstat(publicPath)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return "", "", errors.New("release signing public key must be a regular non-symlink file")
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o022 != 0 {
		return "", "", errors.New("release signing public key must not be writable by group or others")
	}
	return privatePath, publicPath, nil
}

func validatePrivateKeyPath(filename string) (string, error) {
	if !filepath.IsAbs(filename) {
		return "", errors.New("release signing private key path must be absolute")
	}
	filename = filepath.Clean(filename)
	if err := validateSecureKeyDirectory(filepath.Dir(filename)); err != nil {
		return "", err
	}
	info, err := os.Lstat(filename)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("release signing private key must be a regular non-symlink file")
	}
	if runtime.GOOS != "windows" {
		resolved, err := filepath.EvalSymlinks(filename)
		if err != nil || !sameFilesystemPath(filepath.Clean(resolved), filename) {
			return "", errors.New("release signing private key path must not contain symlink components")
		}
		if info.Mode().Perm()&0o077 != 0 {
			return "", errors.New("release signing private key must not be accessible to group or others")
		}
	}
	return filename, nil
}

func validateSecureKeyDirectory(directory string) error {
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("key destination must be an existing real directory")
	}
	if runtime.GOOS != "windows" {
		resolved, err := filepath.EvalSymlinks(directory)
		if err != nil || !sameFilesystemPath(filepath.Clean(resolved), directory) {
			return errors.New("key destination path must not contain symlink components")
		}
		if info.Mode().Perm()&0o077 != 0 {
			return errors.New("key destination directory must not be accessible to group or others")
		}
	}
	for current := directory; ; current = filepath.Dir(current) {
		if _, err := os.Lstat(filepath.Join(current, ".git")); err == nil {
			return errors.New("release signing keys must not be created inside a Git worktree")
		} else if !errors.Is(err, os.ErrNotExist) {
			return errors.New("inspect key destination ancestors failed")
		}
		parent := filepath.Dir(current)
		if parent == current {
			break
		}
	}
	return nil
}

func sameFilesystemPath(left, right string) bool {
	if runtime.GOOS == "windows" {
		return strings.EqualFold(left, right)
	}
	return left == right
}

func clear(content []byte) {
	for index := range content {
		content[index] = 0
	}
}

func SignRelease(root string, privateKey ed25519.PrivateKey) (Manifest, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return Manifest{}, errors.New("valid Ed25519 private key is required")
	}
	root, err := safeRoot(root)
	if err != nil {
		return Manifest{}, err
	}
	for _, name := range []string{ManifestFilename, SignatureFilename} {
		if err := os.Remove(filepath.Join(root, name)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return Manifest{}, fmt.Errorf("remove stale signed metadata: %w", err)
		}
	}
	releaseContent, err := readBoundedRegular(filepath.Join(root, ReleaseFilename), MaximumReleaseBytes)
	if err != nil {
		return Manifest{}, fmt.Errorf("read release metadata: %w", err)
	}
	var release Release
	if err := decodeStrict(releaseContent, &release); err != nil || validateRelease(release) != nil {
		return Manifest{}, errors.New("release metadata contract is invalid")
	}
	hostContract, err := ComputeHostContractSHA256(root)
	if err != nil || hostContract != release.HostContractSHA256 {
		return Manifest{}, errors.New("release host lifecycle contract is invalid")
	}
	files, err := collectFiles(root)
	if err != nil {
		return Manifest{}, err
	}
	publicKey := privateKey.Public().(ed25519.PublicKey)
	fingerprint, _ := PublicKeyFingerprint(publicKey)
	releaseDigest := sha256.Sum256(releaseContent)
	manifest := Manifest{FormatVersion: ManifestFormatVersion, SignerKeySHA256: fingerprint, ReleaseJSONSHA256: hex.EncodeToString(releaseDigest[:]), Files: files}
	content, err := marshalLine(manifest)
	if err != nil || int64(len(content)) > MaximumManifestBytes {
		return Manifest{}, errors.New("encode bounded signed manifest failed")
	}
	signature := ed25519.Sign(privateKey, content)
	if err := writeExclusive(filepath.Join(root, ManifestFilename), content, 0o644); err != nil {
		return Manifest{}, err
	}
	encoded := []byte(base64.StdEncoding.EncodeToString(signature) + "\n")
	if err := writeExclusive(filepath.Join(root, SignatureFilename), encoded, 0o644); err != nil {
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
		return VerifiedRelease{}, errors.New("trusted Ed25519 update key is required")
	}
	manifestContent, err := readBoundedRegular(filepath.Join(root, ManifestFilename), MaximumManifestBytes)
	if err != nil {
		return VerifiedRelease{}, fmt.Errorf("read signed release manifest: %w", err)
	}
	signatureContent, err := readBoundedRegular(filepath.Join(root, SignatureFilename), MaximumSignatureBytes)
	if err != nil {
		return VerifiedRelease{}, fmt.Errorf("read detached release signature: %w", err)
	}
	signature, err := base64.StdEncoding.Strict().DecodeString(strings.TrimSpace(string(signatureContent)))
	if err != nil || len(signature) != ed25519.SignatureSize || !ed25519.Verify(policy.PublicKey, manifestContent, signature) {
		return VerifiedRelease{}, errors.New("release signature verification failed")
	}
	var manifest Manifest
	if err := decodeStrict(manifestContent, &manifest); err != nil {
		return VerifiedRelease{}, errors.New("decode signed release manifest failed")
	}
	fingerprint, _ := PublicKeyFingerprint(policy.PublicKey)
	if err := validateManifest(manifest, fingerprint); err != nil {
		return VerifiedRelease{}, err
	}
	actualFiles, err := collectFiles(root)
	if err != nil {
		return VerifiedRelease{}, err
	}
	if !equalFileRecords(actualFiles, manifest.Files) {
		return VerifiedRelease{}, errors.New("release files do not exactly match the signed manifest")
	}
	releaseContent, err := readBoundedRegular(filepath.Join(root, ReleaseFilename), MaximumReleaseBytes)
	if err != nil {
		return VerifiedRelease{}, errors.New("signed release metadata is unavailable")
	}
	releaseDigest := sha256.Sum256(releaseContent)
	if hex.EncodeToString(releaseDigest[:]) != manifest.ReleaseJSONSHA256 {
		return VerifiedRelease{}, errors.New("release metadata digest does not match the signed manifest")
	}
	var release Release
	if err := decodeStrict(releaseContent, &release); err != nil {
		return VerifiedRelease{}, errors.New("decode release metadata failed")
	}
	hostContract, err := ComputeHostContractSHA256(root)
	if err != nil || hostContract != release.HostContractSHA256 {
		return VerifiedRelease{}, errors.New("signed release host lifecycle contract is invalid")
	}
	if err := validateCompatibility(release, policy); err != nil {
		return VerifiedRelease{}, err
	}
	mihomo := findRecord(manifest.Files, "libexec/mihomo")
	if mihomo == nil || mihomo.SHA256 != release.MihomoSHA256 || !mihomo.Executable {
		return VerifiedRelease{}, errors.New("Mihomo binary does not match signed release metadata")
	}
	for _, required := range []string{"bin/gateway-vpn", "bin/gateway-vpnctl", "libexec/mihomo", ReleaseFilename, LegacyHashFilename} {
		record := findRecord(manifest.Files, required)
		if record == nil || strings.HasPrefix(required, "bin/") && !record.Executable {
			return VerifiedRelease{}, fmt.Errorf("required signed release file is missing or invalid: %s", required)
		}
	}
	return VerifiedRelease{Root: root, Release: release, Manifest: manifest, Fingerprint: fingerprint}, nil
}

func ReadReleaseMetadata(root string) (Release, error) {
	root, err := safeRoot(root)
	if err != nil {
		return Release{}, err
	}
	content, err := readBoundedRegular(filepath.Join(root, ReleaseFilename), MaximumReleaseBytes)
	if err != nil {
		return Release{}, errors.New("release metadata is unavailable")
	}
	var release Release
	if err := decodeStrict(content, &release); err != nil || validateRelease(release) != nil {
		return Release{}, errors.New("release metadata contract is invalid")
	}
	hostContract, err := ComputeHostContractSHA256(root)
	if err != nil || hostContract != release.HostContractSHA256 {
		return Release{}, errors.New("release host lifecycle contract is invalid")
	}
	return release, nil
}

var requiredHostContractFiles = []string{
	"packaging/dnsmasq/dnsmasq.conf.in",
	"packaging/grub/90-gateway-vpn-automatic.cfg",
	"packaging/grub/90-gateway-vpn-menu.cfg",
	"packaging/journald/gateway-vpn.conf",
	"packaging/nftables/boot.nft.in",
	"packaging/sysctl.d/90-gateway-vpn-ipv4-forwarding.conf",
	"packaging/sysctl.d/90-gateway-vpn-ipv6.conf",
	"packaging/systemd/gateway-vpn.service",
	"packaging/systemd/gateway-vpn-watchdog.service",
	"packaging/systemd/gateway-vpn-firewall.service",
	"packaging/systemd/gateway-vpn-firewall-guard.service",
	"packaging/systemd/gateway-vpn-network-broker.socket",
	"packaging/systemd/gateway-vpn-power-cycle@.service",
	"packaging/systemd/gateway-vpn-host-upgrade-recovery.service",
	"packaging/systemd/gateway-vpn-uninstall.service",
	"packaging/systemd/gateway-vpn-update.service",
	"packaging/systemd/gateway-vpn-update-recovery.service",
	"packaging/systemd/gateway-vpn-update-resume.service",
	"packaging/systemd/gateway-vpn-update-finalize.service",
	"packaging/systemd/gateway-vpn-update-finalize.timer",
	"packaging/systemd-networkd/05-gateway-vpn-lan.netdev",
	"packaging/systemd-networkd/05-gateway-vpn-lan.network.in",
	"packaging/systemd-networkd/06-gateway-vpn-lan-member.network.in",
	"packaging/systemd-networkd/80-gateway-vpn-hilink.network",
	"packaging/systemd-wait-online/gateway-vpn.conf",
	"packaging/sysusers.d/gateway-vpn.conf",
	"packaging/tmpfiles.d/gateway-vpn.conf",
	"scripts/install-gateway.sh",
	"scripts/recover-gateway-install.sh",
	"scripts/upgrade-gateway-host.sh",
	"scripts/recover-gateway-host-upgrade.sh",
	"scripts/run-gateway-uninstall-job.sh",
	"scripts/uninstall.sh",
}

var hostContractDirectories = []string{
	"packaging/dnsmasq",
	"packaging/grub",
	"packaging/journald",
	"packaging/nftables",
	"packaging/sysctl.d",
	"packaging/systemd",
	"packaging/systemd-networkd",
	"packaging/systemd-wait-online",
	"packaging/sysusers.d",
	"packaging/tmpfiles.d",
}

var hostContractStandaloneFiles = []string{
	"scripts/install-gateway.sh",
	"scripts/recover-gateway-install.sh",
	"scripts/upgrade-gateway-host.sh",
	"scripts/recover-gateway-host-upgrade.sh",
	"scripts/run-gateway-uninstall-job.sh",
	"scripts/uninstall.sh",
}

type hostContractFile struct {
	path   string
	bytes  int64
	digest string
}

// ComputeHostContractSHA256 binds pointer-only updates to every exact signed
// lifecycle asset copied into root-owned host paths by the first installer.
// Updating any of these assets requires a separate installer transaction;
// silently switching only binaries would create an untested hybrid release.
func ComputeHostContractSHA256(root string) (string, error) {
	root, err := safeRoot(root)
	if err != nil {
		return "", err
	}
	files := make([]hostContractFile, 0, 48)
	seen := make(map[string]bool, 48)
	addFile := func(path string, info os.FileInfo) error {
		if info == nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maximumHostFileBytes {
			return errors.New("release host lifecycle contract contains an invalid file")
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return errors.New("resolve release host lifecycle contract path failed")
		}
		relative = filepath.ToSlash(relative)
		if !safeRelativePath(relative) || seen[relative] {
			return errors.New("release host lifecycle contract path is invalid or duplicated")
		}
		digest, bytesRead, err := hashFile(path, maximumHostFileBytes)
		if err != nil || bytesRead != info.Size() {
			return errors.New("hash release host lifecycle contract file failed")
		}
		seen[relative] = true
		files = append(files, hostContractFile{path: relative, bytes: bytesRead, digest: digest})
		if len(files) > 96 {
			return errors.New("release host lifecycle contract contains too many files")
		}
		return nil
	}
	for _, relativeRoot := range hostContractDirectories {
		contractRoot := filepath.Join(root, filepath.FromSlash(relativeRoot))
		info, err := os.Lstat(contractRoot)
		if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return "", fmt.Errorf("release host lifecycle contract directory is invalid: %s", relativeRoot)
		}
		err = filepath.WalkDir(contractRoot, func(path string, entry os.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if path == contractRoot {
				return nil
			}
			if entry.IsDir() {
				return errors.New("release host lifecycle contract directories must be flat")
			}
			entryInfo, err := entry.Info()
			if err != nil {
				return errors.New("inspect release host lifecycle contract file failed")
			}
			return addFile(path, entryInfo)
		})
		if err != nil {
			return "", err
		}
	}
	for _, relative := range hostContractStandaloneFiles {
		path := filepath.Join(root, filepath.FromSlash(relative))
		info, err := os.Lstat(path)
		if err != nil {
			return "", fmt.Errorf("release host lifecycle contract file is unavailable: %s", relative)
		}
		if err := addFile(path, info); err != nil {
			return "", err
		}
	}
	sort.Slice(files, func(i, j int) bool { return files[i].path < files[j].path })
	present := make(map[string]bool, len(files))
	digest := sha256.New()
	for _, file := range files {
		present[file.path] = true
		_, _ = fmt.Fprintf(digest, "%s\x00%d\x00%s\x00", file.path, file.bytes, file.digest)
	}
	for _, required := range requiredHostContractFiles {
		if !present[required] {
			return "", fmt.Errorf("required host lifecycle file is missing: %s", required)
		}
	}
	return hex.EncodeToString(digest.Sum(nil)), nil
}

func validateCompatibility(release Release, policy VerificationPolicy) error {
	if err := validateRelease(release); err != nil {
		return err
	}
	expectedOS := policy.ExpectedOS
	if expectedOS == "" {
		expectedOS = runtime.GOOS
	}
	expectedArch := policy.ExpectedArch
	if expectedArch == "" {
		expectedArch = runtime.GOARCH
	}
	if release.OS != expectedOS || release.Arch != expectedArch {
		return fmt.Errorf("release platform %s/%s is incompatible with %s/%s", release.OS, release.Arch, expectedOS, expectedArch)
	}
	if policy.InitialInstall {
		if policy.CurrentGatewayVersion != "" || policy.CurrentSchemaVersion != 0 {
			return errors.New("initial-install verification cannot claim an installed version or schema")
		}
	} else if policy.CurrentSchemaVersion < release.DatabaseSchemaMinimum || policy.CurrentSchemaVersion > release.DatabaseSchemaMaximum {
		return errors.New("current database schema is outside the candidate compatibility range")
	}
	if policy.ConfigGeneration > 0 && release.ConfigSchemaGeneration != policy.ConfigGeneration {
		return errors.New("candidate config schema generation is incompatible")
	}
	if policy.CurrentHostContractSHA256 != "" && release.HostContractSHA256 != policy.CurrentHostContractSHA256 {
		return errors.New("candidate host lifecycle contract requires a signed installer upgrade")
	}
	if policy.GatewayAPIContract != "" && release.GatewayAPIContract != policy.GatewayAPIContract {
		return errors.New("candidate Gateway API contract is incompatible")
	}
	if policy.MihomoAPIContract != "" && release.MihomoAPIContract != policy.MihomoAPIContract {
		return errors.New("candidate Mihomo API contract is incompatible")
	}
	if policy.CurrentGatewayVersion != "" {
		comparison, err := compareVersions(release.GatewayVersion, policy.CurrentGatewayVersion)
		if err != nil {
			return errors.New("current or candidate Gateway version is invalid")
		}
		if comparison < 0 || comparison == 0 && !policy.AllowSameVersion {
			return errors.New("release is not a forward Gateway VPN update")
		}
	}
	return nil
}

// ValidateGatewayVersion exposes the exact release-version grammar to channel
// manifests and bootstrap tooling without allowing those trust layers to drift
// to a weaker approximation of the signed release contract.
func ValidateGatewayVersion(value string) error {
	if !versionPattern.MatchString(value) {
		return errors.New("Gateway VPN version is not strict SemVer 2.0.0")
	}
	return nil
}

func validateRelease(release Release) error {
	buildDate, dateErr := time.Parse(time.RFC3339, release.BuildDate)
	if release.FormatVersion != ReleaseFormatVersion || !versionPattern.MatchString(release.GatewayVersion) || !mihomoVersionPattern.MatchString(release.MihomoVersion) || release.OS != "linux" || release.Arch != "amd64" || !digestPattern.MatchString(release.MihomoSHA256) || release.DatabaseSchemaMinimum < 1 || release.DatabaseSchemaMaximum < release.DatabaseSchemaMinimum || release.ConfigSchemaGeneration < 1 || !digestPattern.MatchString(release.HostContractSHA256) || release.GatewayAPIContract != GatewayAPIContract || release.MihomoAPIContract != MihomoAPIContract || !buildCommitPattern.MatchString(release.BuildCommit) || dateErr != nil || buildDate.IsZero() {
		return errors.New("release metadata contract is invalid")
	}
	return nil
}

func validateManifest(manifest Manifest, fingerprint string) error {
	if manifest.FormatVersion != ManifestFormatVersion || manifest.SignerKeySHA256 != fingerprint || !digestPattern.MatchString(manifest.ReleaseJSONSHA256) || len(manifest.Files) < 5 || len(manifest.Files) > MaximumFiles {
		return errors.New("signed release manifest contract is invalid")
	}
	previous := ""
	var total int64
	for _, record := range manifest.Files {
		if !safeRelativePath(record.Path) || record.Path == ManifestFilename || record.Path == SignatureFilename || record.Bytes <= 0 || record.Bytes > MaximumFileBytes || !digestPattern.MatchString(record.SHA256) || previous >= record.Path {
			return errors.New("signed release file record is invalid or unsorted")
		}
		previous = record.Path
		total += record.Bytes
		if total > MaximumArtifactBytes {
			return errors.New("signed release exceeds the maximum artifact size")
		}
	}
	return nil
}

func collectFiles(root string) ([]FileRecord, error) {
	var records []FileRecord
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
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return errors.New("release artifact contains a symlink")
		}
		if entry.IsDir() {
			if !safeRelativePath(relative) {
				return errors.New("release artifact contains an unsafe directory")
			}
			return nil
		}
		if !info.Mode().IsRegular() || !safeRelativePath(relative) {
			return errors.New("release artifact contains an unsafe file")
		}
		if relative == ManifestFilename || relative == SignatureFilename {
			return nil
		}
		if len(records) >= MaximumFiles || info.Size() <= 0 || info.Size() > MaximumFileBytes {
			return errors.New("release artifact file count or size exceeds its bound")
		}
		digest, bytesRead, err := hashFile(path, MaximumFileBytes)
		if err != nil || bytesRead != info.Size() {
			return errors.New("hash release artifact file failed")
		}
		total += bytesRead
		if total > MaximumArtifactBytes {
			return errors.New("release artifact exceeds its total size bound")
		}
		executable := info.Mode().Perm()&0o111 != 0
		if runtime.GOOS == "windows" && (strings.HasPrefix(relative, "bin/") || relative == "libexec/mihomo") {
			executable = true
		}
		records = append(records, FileRecord{Path: relative, Bytes: bytesRead, SHA256: digest, Executable: executable})
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
		return "", errors.New("release root must be absolute")
	}
	root = filepath.Clean(root)
	info, err := os.Lstat(root)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return "", errors.New("release root must be a real directory")
	}
	return root, nil
}

func safeRelativePath(value string) bool {
	if value == "" || len(value) > MaximumRelativePath || strings.Contains(value, "\\") || strings.HasPrefix(value, "/") || filepath.IsAbs(value) || filepath.ToSlash(filepath.Clean(filepath.FromSlash(value))) != value {
		return false
	}
	parts := strings.Split(value, "/")
	if len(parts) > MaximumPathParts {
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
		return nil, errors.New("file must be a bounded regular non-symlink file")
	}
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	content, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || int64(len(content)) != info.Size() || int64(len(content)) > maximum {
		return nil, errors.New("bounded file read failed")
	}
	return content, nil
}

func hashFile(filename string, maximum int64) (string, int64, error) {
	file, err := os.Open(filename)
	if err != nil {
		return "", 0, err
	}
	defer file.Close()
	hash := sha256.New()
	read, err := io.Copy(hash, io.LimitReader(file, maximum+1))
	if err != nil || read > maximum {
		return "", 0, errors.New("bounded file hash failed")
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
		return fmt.Errorf("create %s: %w", filepath.Base(filename), err)
	}
	if _, err := file.Write(content); err != nil {
		file.Close()
		_ = os.Remove(filename)
		return errors.New("write signed release metadata failed")
	}
	if err := file.Chmod(mode); err != nil {
		file.Close()
		_ = os.Remove(filename)
		return errors.New("set signed release metadata permissions failed")
	}
	if err := file.Sync(); err != nil {
		file.Close()
		_ = os.Remove(filename)
		return errors.New("sync signed release metadata failed")
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(filename)
		return errors.New("close signed release metadata failed")
	}
	return nil
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

func equalFileRecords(left, right []FileRecord) bool {
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

func findRecord(records []FileRecord, path string) *FileRecord {
	index := sort.Search(len(records), func(index int) bool { return records[index].Path >= path })
	if index >= len(records) || records[index].Path != path {
		return nil
	}
	return &records[index]
}

type semanticVersion struct {
	major, minor, patch uint64
	pre                 string
}

func compareVersions(left, right string) (int, error) {
	a, err := parseVersion(left)
	if err != nil {
		return 0, err
	}
	b, err := parseVersion(right)
	if err != nil {
		return 0, err
	}
	for _, pair := range [][2]uint64{{a.major, b.major}, {a.minor, b.minor}, {a.patch, b.patch}} {
		if pair[0] < pair[1] {
			return -1, nil
		}
		if pair[0] > pair[1] {
			return 1, nil
		}
	}
	if a.pre == b.pre {
		return 0, nil
	}
	if a.pre == "" {
		return 1, nil
	}
	if b.pre == "" {
		return -1, nil
	}
	return comparePrerelease(a.pre, b.pre), nil
}

func parseVersion(value string) (semanticVersion, error) {
	if !versionPattern.MatchString(value) {
		return semanticVersion{}, errors.New("invalid semantic version")
	}
	withoutBuild := strings.SplitN(value, "+", 2)[0]
	parts := strings.SplitN(withoutBuild, "-", 2)
	numbers := strings.Split(parts[0], ".")
	parsed := semanticVersion{}
	values := []*uint64{&parsed.major, &parsed.minor, &parsed.patch}
	for index, item := range numbers {
		if len(item) > 1 && item[0] == '0' {
			return semanticVersion{}, errors.New("semantic version numeric identifiers may not contain leading zeroes")
		}
		number, err := strconv.ParseUint(item, 10, 64)
		if err != nil {
			return semanticVersion{}, err
		}
		*values[index] = number
	}
	if len(parts) == 2 {
		parsed.pre = parts[1]
	}
	return parsed, nil
}

func comparePrerelease(left, right string) int {
	a, b := strings.Split(left, "."), strings.Split(right, ".")
	for index := 0; index < len(a) && index < len(b); index++ {
		if a[index] == b[index] {
			continue
		}
		an, aerr := strconv.ParseUint(a[index], 10, 64)
		bn, berr := strconv.ParseUint(b[index], 10, 64)
		switch {
		case aerr == nil && berr == nil && an < bn:
			return -1
		case aerr == nil && berr == nil:
			return 1
		case aerr == nil:
			return -1
		case berr == nil:
			return 1
		case a[index] < b[index]:
			return -1
		default:
			return 1
		}
	}
	if len(a) < len(b) {
		return -1
	}
	return 1
}
