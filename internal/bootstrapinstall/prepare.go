package bootstrapinstall

import (
	"context"
	"encoding/hex"
	"errors"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"gateway-vpn/internal/config"
	"gateway-vpn/internal/distribution"
	updatepkg "gateway-vpn/internal/update"
	"gateway-vpn/internal/vpsrelease"
)

type Request struct {
	Role               string
	Channel            string
	Version            string
	SourceCommit       string
	ManifestURL        string
	ManifestSHA256     string
	SignatureURL       string
	PublicKeyURL       string
	SignerKeySHA256    string
	ArtifactBaseURL    string
	OperatingSystem    string
	Architecture       string
	ManifestMaximumAge time.Duration
}

type Bootstrap struct {
	Downloader Downloader
	WorkRoot   string
	Now        func() time.Time
}

type Prepared struct {
	workDir         string
	ReleaseRoot     string
	PublicKeyPath   string
	InstallerPath   string
	Manifest        distribution.Manifest
	Artifact        distribution.Artifact
	VerifiedRelease updatepkg.VerifiedRelease
	VerifiedVPS     vpsrelease.VerifiedRelease
	ManifestSHA256  string
	SignerKeySHA256 string
}

func (bootstrap Bootstrap) Prepare(ctx context.Context, request Request) (Prepared, error) {
	if request.OperatingSystem == "" {
		request.OperatingSystem = runtime.GOOS
	}
	if request.Architecture == "" {
		request.Architecture = runtime.GOARCH
	}
	if err := validateRequest(request); err != nil {
		return Prepared{}, err
	}
	workRoot := bootstrap.WorkRoot
	if workRoot == "" {
		workRoot = os.TempDir()
	}
	workRoot = filepath.Clean(workRoot)
	if !filepath.IsAbs(workRoot) {
		return Prepared{}, errors.New("absolute bootstrap work root is required")
	}
	info, err := os.Lstat(workRoot)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return Prepared{}, errors.New("bootstrap work root must be a real directory")
	}
	workDirectory, err := os.MkdirTemp(workRoot, "gateway-vpn-bootstrap-")
	if err != nil {
		return Prepared{}, errors.New("create bootstrap work directory failed")
	}
	if err := os.Chmod(workDirectory, 0o700); err != nil {
		_ = os.RemoveAll(workDirectory)
		return Prepared{}, errors.New("secure bootstrap work directory failed")
	}
	prepared, err := bootstrap.prepareIn(ctx, request, workDirectory)
	if err != nil {
		_ = os.RemoveAll(workDirectory)
		return Prepared{}, err
	}
	return prepared, nil
}

func (bootstrap Bootstrap) prepareIn(ctx context.Context, request Request, workDirectory string) (Prepared, error) {
	manifestPath := filepath.Join(workDirectory, "channel-manifest.json")
	manifestFetch, err := bootstrap.Downloader.Fetch(ctx, FetchRequest{
		URL: request.ManifestURL, Destination: manifestPath,
		MaximumBytes: distribution.MaximumManifestBytes, ExpectedSHA256: request.ManifestSHA256,
	})
	if err != nil {
		return Prepared{}, errors.New("download pinned channel manifest failed")
	}
	signaturePath := filepath.Join(workDirectory, "channel-manifest.sig")
	if _, err := bootstrap.Downloader.Fetch(ctx, FetchRequest{URL: request.SignatureURL, Destination: signaturePath, MaximumBytes: distribution.MaximumSignatureBytes}); err != nil {
		return Prepared{}, errors.New("download channel signature failed")
	}
	keyPath := filepath.Join(workDirectory, "update-signing.pub")
	if _, err := bootstrap.Downloader.Fetch(ctx, FetchRequest{URL: request.PublicKeyURL, Destination: keyPath, MaximumBytes: MaximumKeyBytes}); err != nil {
		return Prepared{}, errors.New("download trusted update public key failed")
	}
	publicKey, err := updatepkg.LoadPublicKey(keyPath)
	if err != nil {
		return Prepared{}, errors.New("downloaded update public key is invalid")
	}
	fingerprint, _ := updatepkg.PublicKeyFingerprint(publicKey)
	if fingerprint != request.SignerKeySHA256 {
		return Prepared{}, errors.New("downloaded update public key fingerprint mismatch")
	}
	manifestContent, err := readBounded(manifestPath, distribution.MaximumManifestBytes)
	if err != nil {
		return Prepared{}, err
	}
	signatureContent, err := readBounded(signaturePath, distribution.MaximumSignatureBytes)
	if err != nil {
		return Prepared{}, err
	}
	manifest, err := distribution.VerifyManifest(manifestContent, signatureContent, publicKey, distribution.VerificationPolicy{
		ExpectedChannel: request.Channel, ExpectedVersion: request.Version, ExpectedCommit: request.SourceCommit,
		Now: bootstrap.Now, MaximumAge: request.ManifestMaximumAge,
	})
	if err != nil {
		return Prepared{}, errors.New("verify pinned signed channel manifest failed")
	}
	artifact, err := distribution.SelectArtifact(manifest, request.Role, request.OperatingSystem, request.Architecture)
	if err != nil {
		return Prepared{}, err
	}
	if artifact.Bytes > updatepkg.MaximumArchiveBytes {
		return Prepared{}, errors.New("signed role artifact exceeds the strict release archive bound")
	}
	if request.Role == distribution.RoleVPS && artifact.Bytes > vpsrelease.MaximumArtifactBytes {
		return Prepared{}, errors.New("signed VPS artifact exceeds the role-specific archive bound")
	}
	artifactURL, err := joinArtifactURL(request.ArtifactBaseURL, artifact.Filename)
	if err != nil {
		return Prepared{}, err
	}
	archivePath := filepath.Join(workDirectory, "release.tar.gz")
	if _, err := bootstrap.Downloader.Fetch(ctx, FetchRequest{
		URL: artifactURL, Destination: archivePath, MaximumBytes: updatepkg.MaximumArchiveBytes,
		ExpectedBytes: artifact.Bytes, ExpectedSHA256: artifact.SHA256,
	}); err != nil {
		return Prepared{}, errors.New("download signed role artifact failed")
	}
	releaseRoot := filepath.Join(workDirectory, "release")
	if err := os.Mkdir(releaseRoot, 0o700); err != nil {
		return Prepared{}, errors.New("create bootstrap release extraction directory failed")
	}
	archive, err := os.Open(archivePath)
	if err != nil {
		return Prepared{}, errors.New("open downloaded role artifact failed")
	}
	_, _, extractErr := updatepkg.ExtractReleaseArchive(ctx, archive, releaseRoot)
	closeErr := archive.Close()
	if extractErr != nil || closeErr != nil {
		return Prepared{}, errors.New("strict role artifact extraction failed")
	}
	var verified updatepkg.VerifiedRelease
	var verifiedVPS vpsrelease.VerifiedRelease
	switch request.Role {
	case distribution.RoleGateway:
		verified, err = updatepkg.VerifyRelease(releaseRoot, updatepkg.VerificationPolicy{
			PublicKey: publicKey, ExpectedOS: request.OperatingSystem, ExpectedArch: request.Architecture,
			InitialInstall: true, ConfigGeneration: config.CurrentVersion,
			GatewayAPIContract: updatepkg.GatewayAPIContract, MihomoAPIContract: updatepkg.MihomoAPIContract,
		})
		if err != nil || verified.Release.GatewayVersion != request.Version || verified.Fingerprint != request.SignerKeySHA256 {
			return Prepared{}, errors.New("independent signed Gateway release verification failed")
		}
	case distribution.RoleVPS:
		verifiedVPS, err = vpsrelease.VerifyRelease(releaseRoot, vpsrelease.VerificationPolicy{
			PublicKey: publicKey, ExpectedVersion: request.Version, ExpectedOS: request.OperatingSystem, ExpectedArch: request.Architecture,
		})
		if err != nil || verifiedVPS.Release.Version != request.Version || verifiedVPS.Fingerprint != request.SignerKeySHA256 {
			return Prepared{}, errors.New("independent signed VPS release verification failed")
		}
	}
	installerName := "install-" + request.Role + ".sh"
	installerPath := filepath.Join(releaseRoot, "scripts", installerName)
	installerInfo, err := os.Lstat(installerPath)
	if err != nil || installerInfo.Mode()&os.ModeSymlink != 0 || !installerInfo.Mode().IsRegular() || installerInfo.Size() <= 0 || installerInfo.Size() > 1<<20 {
		return Prepared{}, errors.New("signed role installer is missing or unsafe")
	}
	return Prepared{
		workDir: workDirectory, ReleaseRoot: releaseRoot, PublicKeyPath: keyPath, InstallerPath: installerPath,
		Manifest: manifest, Artifact: artifact, VerifiedRelease: verified, VerifiedVPS: verifiedVPS,
		ManifestSHA256: manifestFetch.SHA256, SignerKeySHA256: fingerprint,
	}, nil
}

func (prepared Prepared) Cleanup() error {
	if prepared.workDir == "" || !filepath.IsAbs(prepared.workDir) || !strings.HasPrefix(filepath.Base(prepared.workDir), "gateway-vpn-bootstrap-") {
		return errors.New("refuse to remove an unmanaged bootstrap directory")
	}
	return os.RemoveAll(prepared.workDir)
}

func validateRequest(request Request) error {
	if request.Role != distribution.RoleGateway && request.Role != distribution.RoleVPS {
		return errors.New("bootstrap install role must be gateway or vps")
	}
	if request.Channel == "" || updatepkg.ValidateGatewayVersion(request.Version) != nil || !validDigest(request.ManifestSHA256) || !validDigest(request.SignerKeySHA256) || request.ManifestURL == "" || request.SignatureURL == "" || request.PublicKeyURL == "" || request.ArtifactBaseURL == "" {
		return errors.New("complete pinned bootstrap trust inputs are required")
	}
	if request.OperatingSystem != "linux" || request.Architecture != "amd64" {
		return errors.New("bootstrap release target must be linux/amd64")
	}
	if request.SourceCommit != "" {
		decoded, err := hex.DecodeString(request.SourceCommit)
		if err != nil || len(decoded) != 20 && len(decoded) != 32 || request.SourceCommit != strings.ToLower(request.SourceCommit) {
			return errors.New("pinned source commit must be lowercase Git SHA-1 or SHA-256")
		}
	}
	return nil
}

func joinArtifactURL(base, filename string) (string, error) {
	parsed, err := url.Parse(base)
	if err != nil || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Host == "" || parsed.Path == "" || !strings.HasSuffix(parsed.Path, "/") || strings.Contains(filename, "/") || strings.Contains(filename, "\\") {
		return "", errors.New("artifact base URL or signed filename is invalid")
	}
	parsed.Path += filename
	return parsed.String(), nil
}

func readBounded(filename string, maximum int64) ([]byte, error) {
	info, err := os.Lstat(filename)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maximum {
		return nil, errors.New("bootstrap trust file is unsafe or oversized")
	}
	file, err := os.Open(filename)
	if err != nil {
		return nil, errors.New("open bootstrap trust file failed")
	}
	defer file.Close()
	content, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || int64(len(content)) != info.Size() || int64(len(content)) > maximum {
		return nil, errors.New("read bootstrap trust file failed")
	}
	return content, nil
}
