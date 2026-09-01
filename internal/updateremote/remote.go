// Package updateremote discovers and downloads signed Gateway VPN releases.
// Network metadata is discovery-only: a candidate is trusted only after the
// channel manifest and the release archive pass their independent Ed25519
// verification chains.
package updateremote

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"gateway-vpn/internal/distribution"
	"gateway-vpn/internal/mihomochannel"
	updatepkg "gateway-vpn/internal/update"
)

const (
	DefaultRepository = "Go4a4a/Gateway-VPN"
	defaultAPIBase    = "https://api.github.com"
	maximumAPIBytes   = int64(4 << 20)
	maximumRedirects  = 5
)

var repositoryPattern = regexp.MustCompile(`^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$`)

var nonPublicDestinationPrefixes = []netip.Prefix{
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("2001:db8::/32"),
}

type Available struct {
	Available        bool   `json:"available"`
	Channel          string `json:"channel"`
	CurrentVersion   string `json:"current_version"`
	CandidateVersion string `json:"candidate_version,omitempty"`
	ReleaseTag       string `json:"release_tag,omitempty"`
	PublishedAt      string `json:"published_at,omitempty"`
	ArtifactBytes    int64  `json:"artifact_bytes,omitempty"`
	ArtifactSHA256   string `json:"artifact_sha256,omitempty"`
	SourceReference  string `json:"source_reference,omitempty"`
	SourceCommit     string `json:"source_commit,omitempty"`
}

type MihomoAvailable struct {
	Available               bool   `json:"available"`
	Channel                 string `json:"channel"`
	CurrentGatewayVersion   string `json:"current_gateway_version"`
	CurrentMihomoVersion    string `json:"current_mihomo_version"`
	CandidateGatewayVersion string `json:"candidate_gateway_version,omitempty"`
	CandidateMihomoVersion  string `json:"candidate_mihomo_version,omitempty"`
	ReleaseTag              string `json:"release_tag,omitempty"`
	PublishedAt             string `json:"published_at,omitempty"`
	ArtifactBytes           int64  `json:"artifact_bytes,omitempty"`
	ArtifactSHA256          string `json:"artifact_sha256,omitempty"`
	SourceReference         string `json:"source_reference,omitempty"`
	SourceCommit            string `json:"source_commit,omitempty"`
	Urgency                 string `json:"urgency,omitempty"`
	Summary                 string `json:"summary,omitempty"`
}

type Manager struct {
	Repository           string
	CurrentVersion       string
	CurrentMihomoVersion string
	Stager               *updatepkg.Stager
	Client               *http.Client
	APIBase              string
}

type githubRelease struct {
	TagName     string        `json:"tag_name"`
	Draft       bool          `json:"draft"`
	Prerelease  bool          `json:"prerelease"`
	PublishedAt string        `json:"published_at"`
	Assets      []githubAsset `json:"assets"`
}

type githubAsset struct {
	Name               string `json:"name"`
	Size               int64  `json:"size"`
	BrowserDownloadURL string `json:"browser_download_url"`
}

type resolvedRelease struct {
	Available
	artifactURL string
}

type resolvedMihomoRelease struct {
	MihomoAvailable
	artifactURL string
	manifest    mihomochannel.Manifest
}

func New(repository, currentVersion string, stager *updatepkg.Stager) (*Manager, error) {
	if repository == "" {
		repository = DefaultRepository
	}
	if !repositoryPattern.MatchString(repository) || updatepkg.ValidateGatewayVersion(currentVersion) != nil || stager == nil || len(stager.Policy.PublicKey) == 0 {
		return nil, errors.New("remote updater requires a fixed repository, current version, stager, and trusted key")
	}
	return &Manager{Repository: repository, CurrentVersion: currentVersion, Stager: stager, Client: secureHTTPClient(), APIBase: defaultAPIBase}, nil
}

// UseTransport installs a service-route RoundTripper while preserving the
// updater's fixed timeout and redirect validation. The transport still cannot
// bypass request-level URL, media-type, size, hash or signature checks.
func (manager *Manager) UseTransport(transport http.RoundTripper) error {
	if manager == nil || transport == nil {
		return errors.New("remote updater service transport is required")
	}
	manager.Client = secureHTTPClientWithTransport(transport)
	return nil
}

func (manager *Manager) Check(ctx context.Context, channel string) (Available, error) {
	resolved, err := manager.resolve(ctx, channel)
	return resolved.Available, err
}

func (manager *Manager) CheckMihomo(ctx context.Context, channel string) (MihomoAvailable, error) {
	resolved, err := manager.resolveMihomo(ctx, channel)
	return resolved.MihomoAvailable, err
}

func (manager *Manager) StageChannel(ctx context.Context, channel string) (updatepkg.Operation, error) {
	return manager.stageChannel(ctx, channel, updatepkg.SourceGitHubChannel)
}

func (manager *Manager) StageMihomoChannel(ctx context.Context, channel string) (updatepkg.Operation, error) {
	if _, pending, err := manager.Stager.Status(); err != nil {
		return updatepkg.Operation{}, err
	} else if pending {
		return updatepkg.Operation{}, updatepkg.ErrUpdatePending
	}
	resolved, err := manager.resolveMihomo(ctx, channel)
	if err != nil {
		return updatepkg.Operation{}, err
	}
	if !resolved.Available {
		return updatepkg.Operation{}, errors.New("the selected signed channel has no compatible Mihomo maintenance release")
	}
	operation, err := manager.downloadAndStage(ctx, resolved.artifactURL, resolved.ArtifactBytes, resolved.ArtifactSHA256, updatepkg.Source{
		Kind: updatepkg.SourceMihomoGitHub, Channel: channel, Reference: resolved.SourceReference,
	})
	if err != nil {
		return updatepkg.Operation{}, err
	}
	stagedRoot, stagedRootErr := manager.Stager.ReleaseRoot(operation.UpdateID)
	verified, verifyErr := updatepkg.VerifyRelease(stagedRoot, manager.Stager.Policy)
	identityMismatch := stagedRootErr != nil || verifyErr != nil ||
		operation.GatewayVersion != resolved.CandidateGatewayVersion || operation.MihomoVersion != resolved.CandidateMihomoVersion ||
		verified.Release.GatewayVersion != resolved.manifest.GatewayReleaseVersion ||
		verified.Release.MihomoVersion != resolved.manifest.MihomoVersion ||
		verified.Release.BuildCommit != resolved.manifest.SourceCommit ||
		verified.Release.OS != resolved.manifest.OS || verified.Release.Arch != resolved.manifest.Arch ||
		verified.Release.HostContractSHA256 != resolved.manifest.HostContractSHA256 ||
		verified.Release.GatewayAPIContract != resolved.manifest.GatewayAPIContract ||
		verified.Release.MihomoAPIContract != resolved.manifest.MihomoAPIContract
	if identityMismatch {
		if discardErr := manager.Stager.Discard(context.Background(), operation.UpdateID); discardErr != nil {
			return updatepkg.Operation{}, errors.New("mismatched Mihomo maintenance release could not be removed from staging")
		}
		return updatepkg.Operation{}, errors.New("staged release identity does not match the signed Mihomo channel")
	}
	return operation, nil
}

// StageAutomaticChannel uses the exact same signed discovery, download and
// staging path as a manual channel download, but records scheduler ownership.
// This durable distinction prevents a restart from adopting a user-staged
// release for unattended apply.
func (manager *Manager) StageAutomaticChannel(ctx context.Context, channel string) (updatepkg.Operation, error) {
	return manager.stageChannel(ctx, channel, updatepkg.SourceAutomaticGitHub)
}

func (manager *Manager) stageChannel(ctx context.Context, channel, sourceKind string) (updatepkg.Operation, error) {
	if _, pending, err := manager.Stager.Status(); err != nil {
		return updatepkg.Operation{}, err
	} else if pending {
		return updatepkg.Operation{}, updatepkg.ErrUpdatePending
	}
	resolved, err := manager.resolve(ctx, channel)
	if err != nil {
		return updatepkg.Operation{}, err
	}
	if !resolved.Available.Available {
		return updatepkg.Operation{}, errors.New("the selected signed channel has no newer Gateway release")
	}
	source := updatepkg.Source{Kind: sourceKind, Channel: channel, Reference: resolved.SourceReference}
	return manager.downloadAndStage(ctx, resolved.artifactURL, resolved.ArtifactBytes, resolved.ArtifactSHA256, source)
}

func (manager *Manager) StageExact(ctx context.Context, rawURL string) (updatepkg.Operation, error) {
	if _, pending, err := manager.Stager.Status(); err != nil {
		return updatepkg.Operation{}, err
	} else if pending {
		return updatepkg.Operation{}, updatepkg.ErrUpdatePending
	}
	parsed, err := validateRemoteURL(rawURL)
	if err != nil {
		return updatepkg.Operation{}, err
	}
	reference := exactSourceReference(parsed)
	return manager.downloadAndStage(ctx, parsed.String(), 0, "", updatepkg.Source{Kind: updatepkg.SourceExactHTTPS, Reference: reference})
}

func exactSourceReference(parsed *url.URL) string {
	digest := sha256.Sum256([]byte(parsed.String()))
	return "exact-https#sha256-" + hex.EncodeToString(digest[:8])
}

func (manager *Manager) resolve(ctx context.Context, channel string) (resolvedRelease, error) {
	if channel != "stable" && channel != "testing" {
		return resolvedRelease{}, errors.New("update channel must be stable or testing")
	}
	if err := manager.validate(); err != nil {
		return resolvedRelease{}, err
	}
	releases, err := manager.releaseInventory(ctx)
	if err != nil {
		return resolvedRelease{}, err
	}
	result := resolvedRelease{Available: Available{Channel: channel, CurrentVersion: manager.CurrentVersion}}
	for _, release := range releases {
		candidate, ok := manager.verifyReleaseChannel(ctx, channel, release)
		if !ok {
			continue
		}
		if !result.Available.Available {
			result = candidate
			continue
		}
		order, err := updatepkg.CompareGatewayVersions(candidate.CandidateVersion, result.CandidateVersion)
		if err == nil && order > 0 {
			result = candidate
		}
	}
	return result, nil
}

func (manager *Manager) resolveMihomo(ctx context.Context, channel string) (resolvedMihomoRelease, error) {
	if channel != "stable" && channel != "testing" {
		return resolvedMihomoRelease{}, errors.New("Mihomo update channel must be stable or testing")
	}
	if err := manager.validateMihomo(); err != nil {
		return resolvedMihomoRelease{}, err
	}
	releases, err := manager.releaseInventory(ctx)
	if err != nil {
		return resolvedMihomoRelease{}, err
	}
	result := resolvedMihomoRelease{MihomoAvailable: MihomoAvailable{
		Channel: channel, CurrentGatewayVersion: manager.CurrentVersion, CurrentMihomoVersion: manager.CurrentMihomoVersion,
	}}
	for _, release := range releases {
		candidate, ok := manager.verifyMihomoRelease(ctx, channel, release)
		if !ok {
			continue
		}
		if !result.Available {
			result = candidate
			continue
		}
		order, compareErr := updatepkg.CompareMihomoVersions(candidate.CandidateMihomoVersion, result.CandidateMihomoVersion)
		gatewayOrder := 0
		if compareErr == nil && order == 0 {
			gatewayOrder, compareErr = updatepkg.CompareGatewayVersions(candidate.CandidateGatewayVersion, result.CandidateGatewayVersion)
		}
		if compareErr == nil && (order > 0 || order == 0 && gatewayOrder > 0) {
			result = candidate
		}
	}
	return result, nil
}

func (manager *Manager) releaseInventory(ctx context.Context) ([]githubRelease, error) {
	endpoint := strings.TrimRight(manager.APIBase, "/") + "/repos/" + manager.Repository + "/releases?per_page=50"
	content, err := manager.fetchBytes(ctx, endpoint, maximumAPIBytes, "application/vnd.github+json")
	if err != nil {
		return nil, fmt.Errorf("query GitHub release inventory: %w", err)
	}
	var releases []githubRelease
	// GitHub adds fields over time, so decode into a raw slice first and then
	// strictly decode only the small allowlisted projection per entry.
	var raw []json.RawMessage
	if err := json.Unmarshal(content, &raw); err != nil || len(raw) > 100 {
		return nil, errors.New("GitHub release inventory is invalid or oversized")
	}
	for _, item := range raw {
		var value map[string]json.RawMessage
		if err := json.Unmarshal(item, &value); err != nil {
			continue
		}
		var release githubRelease
		_ = json.Unmarshal(value["tag_name"], &release.TagName)
		_ = json.Unmarshal(value["draft"], &release.Draft)
		_ = json.Unmarshal(value["prerelease"], &release.Prerelease)
		_ = json.Unmarshal(value["published_at"], &release.PublishedAt)
		var assetRaw []map[string]json.RawMessage
		if err := json.Unmarshal(value["assets"], &assetRaw); err != nil || len(assetRaw) > distribution.MaximumArtifacts+12 {
			continue
		}
		for _, rawAsset := range assetRaw {
			var asset githubAsset
			_ = json.Unmarshal(rawAsset["name"], &asset.Name)
			_ = json.Unmarshal(rawAsset["size"], &asset.Size)
			_ = json.Unmarshal(rawAsset["browser_download_url"], &asset.BrowserDownloadURL)
			release.Assets = append(release.Assets, asset)
		}
		releases = append(releases, release)
	}
	return releases, nil
}

func (manager *Manager) verifyReleaseChannel(ctx context.Context, channel string, release githubRelease) (resolvedRelease, bool) {
	if release.Draft || channel == "stable" && release.Prerelease || len(release.Assets) == 0 {
		return resolvedRelease{}, false
	}
	version := strings.TrimPrefix(release.TagName, "v")
	if updatepkg.ValidateGatewayVersion(version) != nil || release.TagName != "v"+version {
		return resolvedRelease{}, false
	}
	order, err := updatepkg.CompareGatewayVersions(version, manager.CurrentVersion)
	if err != nil || order <= 0 {
		return resolvedRelease{}, false
	}
	manifestAsset, manifestOK := findAsset(release.Assets, "channel-"+channel+".json")
	signatureAsset, signatureOK := findAsset(release.Assets, "channel-"+channel+".sig")
	if !manifestOK || !signatureOK || manifestAsset.Size <= 0 || manifestAsset.Size > distribution.MaximumManifestBytes || signatureAsset.Size <= 0 || signatureAsset.Size > distribution.MaximumSignatureBytes {
		return resolvedRelease{}, false
	}
	manifestContent, err := manager.fetchBytes(ctx, manifestAsset.BrowserDownloadURL, distribution.MaximumManifestBytes, "application/json")
	if err != nil {
		return resolvedRelease{}, false
	}
	signatureContent, err := manager.fetchBytes(ctx, signatureAsset.BrowserDownloadURL, distribution.MaximumSignatureBytes, "application/octet-stream")
	if err != nil {
		return resolvedRelease{}, false
	}
	manifest, err := distribution.VerifyManifest(manifestContent, signatureContent, manager.Stager.Policy.PublicKey, distribution.VerificationPolicy{ExpectedChannel: channel, ExpectedVersion: version})
	if err != nil {
		return resolvedRelease{}, false
	}
	artifact, err := distribution.SelectArtifact(manifest, distribution.RoleGateway, "linux", "amd64")
	if err != nil {
		return resolvedRelease{}, false
	}
	asset, ok := findAsset(release.Assets, artifact.Filename)
	if !ok || asset.Size != artifact.Bytes || asset.Size <= 0 || asset.Size > updatepkg.MaximumArchiveBytes {
		return resolvedRelease{}, false
	}
	if _, err := validateRemoteURL(asset.BrowserDownloadURL); err != nil {
		return resolvedRelease{}, false
	}
	if _, err := time.Parse(time.RFC3339, release.PublishedAt); err != nil {
		return resolvedRelease{}, false
	}
	reference := manager.Repository + "#" + release.TagName
	return resolvedRelease{Available: Available{
		Available: true, Channel: channel, CurrentVersion: manager.CurrentVersion,
		CandidateVersion: version, ReleaseTag: release.TagName, PublishedAt: release.PublishedAt,
		ArtifactBytes: artifact.Bytes, ArtifactSHA256: artifact.SHA256,
		SourceReference: reference, SourceCommit: manifest.SourceCommit,
	}, artifactURL: asset.BrowserDownloadURL}, true
}

func (manager *Manager) verifyMihomoRelease(ctx context.Context, channel string, release githubRelease) (resolvedMihomoRelease, bool) {
	if release.Draft || channel == "stable" && release.Prerelease || len(release.Assets) == 0 {
		return resolvedMihomoRelease{}, false
	}
	manifestAsset, manifestOK := findAsset(release.Assets, "mihomo-channel-"+channel+".json")
	signatureAsset, signatureOK := findAsset(release.Assets, "mihomo-channel-"+channel+".sig")
	if !manifestOK || !signatureOK || manifestAsset.Size <= 0 || manifestAsset.Size > mihomochannel.MaximumManifestBytes || signatureAsset.Size <= 0 || signatureAsset.Size > mihomochannel.MaximumSignatureBytes {
		return resolvedMihomoRelease{}, false
	}
	manifestContent, err := manager.fetchBytes(ctx, manifestAsset.BrowserDownloadURL, mihomochannel.MaximumManifestBytes, "application/json")
	if err != nil {
		return resolvedMihomoRelease{}, false
	}
	signatureContent, err := manager.fetchBytes(ctx, signatureAsset.BrowserDownloadURL, mihomochannel.MaximumSignatureBytes, "application/octet-stream")
	if err != nil {
		return resolvedMihomoRelease{}, false
	}
	manifest, err := mihomochannel.VerifyManifest(manifestContent, signatureContent, manager.Stager.Policy.PublicKey, mihomochannel.VerificationPolicy{
		ExpectedChannel: channel, CurrentGatewayVersion: manager.CurrentVersion, CurrentMihomoVersion: manager.CurrentMihomoVersion,
		ExpectedOS: "linux", ExpectedArch: "amd64", ExpectedHostContractSHA256: manager.Stager.Policy.CurrentHostContractSHA256,
		ExpectedGatewayAPIContract: manager.Stager.Policy.GatewayAPIContract, ExpectedMihomoAPIContract: manager.Stager.Policy.MihomoAPIContract,
	})
	if err != nil || release.TagName != "v"+manifest.GatewayReleaseVersion {
		return resolvedMihomoRelease{}, false
	}
	asset, ok := findAsset(release.Assets, manifest.Artifact.Filename)
	if !ok || asset.Size != manifest.Artifact.Bytes || asset.Size <= 0 || asset.Size > updatepkg.MaximumArchiveBytes {
		return resolvedMihomoRelease{}, false
	}
	if _, err := validateRemoteURL(asset.BrowserDownloadURL); err != nil {
		return resolvedMihomoRelease{}, false
	}
	if _, err := time.Parse(time.RFC3339, release.PublishedAt); err != nil {
		return resolvedMihomoRelease{}, false
	}
	reference := manager.Repository + "#" + release.TagName + ":mihomo"
	return resolvedMihomoRelease{MihomoAvailable: MihomoAvailable{
		Available: true, Channel: channel, CurrentGatewayVersion: manager.CurrentVersion, CurrentMihomoVersion: manager.CurrentMihomoVersion,
		CandidateGatewayVersion: manifest.GatewayReleaseVersion, CandidateMihomoVersion: manifest.MihomoVersion,
		ReleaseTag: release.TagName, PublishedAt: release.PublishedAt, ArtifactBytes: manifest.Artifact.Bytes,
		ArtifactSHA256: manifest.Artifact.SHA256, SourceReference: reference, SourceCommit: manifest.SourceCommit,
		Urgency: manifest.Urgency, Summary: manifest.Summary,
	}, artifactURL: asset.BrowserDownloadURL, manifest: manifest}, true
}

func (manager *Manager) downloadAndStage(ctx context.Context, rawURL string, expectedBytes int64, expectedSHA string, source updatepkg.Source) (updatepkg.Operation, error) {
	if err := manager.validate(); err != nil {
		return updatepkg.Operation{}, err
	}
	if _, err := validateRemoteURL(rawURL); err != nil {
		return updatepkg.Operation{}, err
	}
	root := filepath.Join(manager.Stager.StateDir, "update-downloads")
	if err := os.MkdirAll(root, 0o700); err != nil {
		return updatepkg.Operation{}, errors.New("create update download directory failed")
	}
	if info, err := os.Lstat(root); err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return updatepkg.Operation{}, errors.New("update download directory is unsafe")
	}
	if err := os.Chmod(root, 0o700); err != nil {
		return updatepkg.Operation{}, err
	}
	temporary, err := os.CreateTemp(root, ".remote-*.tar.gz")
	if err != nil {
		return updatepkg.Operation{}, errors.New("create private update download failed")
	}
	filename := temporary.Name()
	defer os.Remove(filename)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return updatepkg.Operation{}, err
	}
	response, err := manager.request(ctx, rawURL, "application/gzip")
	if err != nil {
		temporary.Close()
		return updatepkg.Operation{}, err
	}
	defer response.Body.Close()
	if expectedBytes > 0 && response.ContentLength > 0 && response.ContentLength != expectedBytes || response.ContentLength > updatepkg.MaximumArchiveBytes {
		temporary.Close()
		return updatepkg.Operation{}, errors.New("remote release size does not match the signed channel")
	}
	hash := sha256.New()
	written, copyErr := io.Copy(io.MultiWriter(temporary, hash), io.LimitReader(response.Body, updatepkg.MaximumArchiveBytes+1))
	syncErr := temporary.Sync()
	closeErr := temporary.Close()
	if copyErr != nil || syncErr != nil || closeErr != nil || written <= 0 || written > updatepkg.MaximumArchiveBytes || expectedBytes > 0 && written != expectedBytes {
		return updatepkg.Operation{}, errors.New("remote release download is truncated or oversized")
	}
	actualSHA := hex.EncodeToString(hash.Sum(nil))
	if expectedSHA != "" && actualSHA != expectedSHA {
		return updatepkg.Operation{}, errors.New("remote release hash does not match the signed channel")
	}
	archive, err := os.Open(filename)
	if err != nil {
		return updatepkg.Operation{}, err
	}
	defer archive.Close()
	return manager.Stager.StageWithSource(ctx, archive, source)
}

func (manager *Manager) fetchBytes(ctx context.Context, rawURL string, maximum int64, accept string) ([]byte, error) {
	response, err := manager.request(ctx, rawURL, accept)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.ContentLength > maximum {
		return nil, errors.New("remote metadata exceeds its size bound")
	}
	content, err := io.ReadAll(io.LimitReader(response.Body, maximum+1))
	if err != nil || int64(len(content)) == 0 || int64(len(content)) > maximum {
		return nil, errors.New("remote metadata is empty, truncated, or oversized")
	}
	return content, nil
}

func (manager *Manager) request(ctx context.Context, rawURL, accept string) (*http.Response, error) {
	if _, err := validateRemoteURL(rawURL); err != nil {
		return nil, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, errors.New("create bounded update request failed")
	}
	request.Header.Set("Accept", accept)
	request.Header.Set("User-Agent", "Gateway-VPN-update-checker/1")
	response, err := manager.Client.Do(request)
	if err != nil {
		return nil, errors.New("HTTPS update request failed")
	}
	if response.StatusCode != http.StatusOK {
		response.Body.Close()
		return nil, fmt.Errorf("HTTPS update source returned status %d", response.StatusCode)
	}
	if !validResponseMediaType(response.Header.Get("Content-Type"), accept) {
		response.Body.Close()
		return nil, errors.New("HTTPS update source returned an unexpected content type")
	}
	return response, nil
}

func validResponseMediaType(value, requested string) bool {
	mediaType, _, err := mime.ParseMediaType(value)
	if err != nil {
		return false
	}
	switch requested {
	case "application/vnd.github+json":
		return mediaType == "application/vnd.github+json" || mediaType == "application/json"
	case "application/json":
		return mediaType == "application/json" || mediaType == "application/octet-stream"
	case "application/octet-stream":
		return mediaType == "application/octet-stream"
	case "application/gzip":
		return mediaType == "application/gzip" || mediaType == "application/x-gzip" || mediaType == "application/octet-stream"
	default:
		return false
	}
}

func (manager *Manager) validate() error {
	if !repositoryPattern.MatchString(manager.Repository) || updatepkg.ValidateGatewayVersion(manager.CurrentVersion) != nil || manager.Stager == nil || manager.Client == nil {
		return errors.New("remote updater configuration is invalid")
	}
	api, err := validateRemoteURL(strings.TrimRight(manager.APIBase, "/"))
	if err != nil || api.RawQuery != "" {
		return errors.New("remote updater API base is invalid")
	}
	return nil
}

func (manager *Manager) validateMihomo() error {
	if err := manager.validate(); err != nil {
		return err
	}
	if updatepkg.ValidateMihomoVersion(manager.CurrentMihomoVersion) != nil || manager.Stager.Policy.CurrentHostContractSHA256 == "" || manager.Stager.Policy.GatewayAPIContract == "" || manager.Stager.Policy.MihomoAPIContract == "" {
		return errors.New("Mihomo updater compatibility contract is unavailable")
	}
	return nil
}

func findAsset(assets []githubAsset, name string) (githubAsset, bool) {
	var found githubAsset
	count := 0
	for _, asset := range assets {
		if asset.Name == name {
			found = asset
			count++
		}
	}
	return found, count == 1
}

func validateRemoteURL(raw string) (*url.URL, error) {
	if len(raw) == 0 || len(raw) > 2048 || strings.TrimSpace(raw) != raw {
		return nil, errors.New("a bounded exact HTTPS URL is required")
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "https" || parsed.Hostname() == "" || parsed.User != nil || parsed.Fragment != "" {
		return nil, errors.New("update source must be an HTTPS URL without credentials or fragment")
	}
	return parsed, nil
}

func secureHTTPClient() *http.Client {
	dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	transport := &http.Transport{
		Proxy:                 nil,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
		ResponseHeaderTimeout: 20 * time.Second,
		IdleConnTimeout:       30 * time.Second,
		DisableCompression:    true,
	}
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, errors.New("remote update dial address is invalid")
		}
		addresses, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		if err != nil {
			return nil, errors.New("resolve remote update host failed")
		}
		for _, candidate := range addresses {
			address := candidate.Unmap()
			if !publicAddress(address) {
				continue
			}
			connection, err := dialer.DialContext(ctx, network, net.JoinHostPort(address.String(), port))
			if err == nil {
				return connection, nil
			}
		}
		return nil, errors.New("remote update host has no reachable public address")
	}
	return secureHTTPClientWithTransport(transport)
}

func secureHTTPClientWithTransport(transport http.RoundTripper) *http.Client {
	return &http.Client{
		Transport: transport,
		Timeout:   15 * time.Minute,
		CheckRedirect: func(request *http.Request, via []*http.Request) error {
			if len(via) >= maximumRedirects {
				return errors.New("remote update redirect limit exceeded")
			}
			_, err := validateRemoteURL(request.URL.String())
			return err
		},
	}
}

func publicAddress(address netip.Addr) bool {
	address = address.Unmap()
	if !address.IsValid() || !address.IsGlobalUnicast() || address.IsPrivate() || address.IsLoopback() || address.IsLinkLocalUnicast() || address.IsLinkLocalMulticast() || address.IsUnspecified() {
		return false
	}
	for _, prefix := range nonPublicDestinationPrefixes {
		if prefix.Contains(address) {
			return false
		}
	}
	return true
}
