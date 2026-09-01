// Package mihomochannel defines the signed discovery metadata for manually
// approved Mihomo maintenance releases. The referenced artifact remains a full
// immutable Gateway VPN release, so apply, recovery and rollback use the one
// existing privileged update transaction instead of a second mutation path.
package mihomochannel

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	updatepkg "gateway-vpn/internal/update"
)

const (
	FormatVersion         = 1
	Kind                  = "gateway-vpn-mihomo-maintenance-v1"
	MaximumManifestBytes  = int64(64 << 10)
	MaximumSignatureBytes = int64(1024)
	MaximumCompatible     = 32
	MaximumSummaryBytes   = 512

	UrgencyRoutine     = "routine"
	UrgencyRecommended = "recommended"
	UrgencySecurity    = "security"
)

var (
	channelPattern = regexp.MustCompile(`^(?:stable|testing)$`)
	digestPattern  = regexp.MustCompile(`^[a-f0-9]{64}$`)
	commitPattern  = regexp.MustCompile(`^(?:[a-f0-9]{40}|[a-f0-9]{64})$`)
)

type Manifest struct {
	FormatVersion             int      `json:"format_version"`
	Kind                      string   `json:"kind"`
	Channel                   string   `json:"channel"`
	GatewayReleaseVersion     string   `json:"gateway_release_version"`
	MihomoVersion             string   `json:"mihomo_version"`
	CompatibleGatewayVersions []string `json:"compatible_gateway_versions"`
	OS                        string   `json:"os"`
	Arch                      string   `json:"arch"`
	HostContractSHA256        string   `json:"host_contract_sha256"`
	GatewayAPIContract        string   `json:"gateway_api_contract"`
	MihomoAPIContract         string   `json:"mihomo_api_contract"`
	GeneratedAt               string   `json:"generated_at"`
	SourceCommit              string   `json:"source_commit"`
	SignerKeySHA256           string   `json:"signer_key_sha256"`
	Urgency                   string   `json:"urgency"`
	Summary                   string   `json:"summary"`
	Artifact                  Artifact `json:"artifact"`
}

type Artifact struct {
	Filename  string `json:"filename"`
	SHA256    string `json:"sha256"`
	Bytes     int64  `json:"bytes"`
	MediaType string `json:"media_type"`
}

type VerificationPolicy struct {
	ExpectedChannel               string
	ExpectedGatewayReleaseVersion string
	ExpectedSourceCommit          string
	CurrentGatewayVersion         string
	CurrentMihomoVersion          string
	ExpectedOS                    string
	ExpectedArch                  string
	ExpectedHostContractSHA256    string
	ExpectedGatewayAPIContract    string
	ExpectedMihomoAPIContract     string
	Now                           func() time.Time
	MaximumAge                    time.Duration
}

func ArtifactFromFile(filename, gatewayVersion string) (Artifact, error) {
	if updatepkg.ValidateGatewayVersion(gatewayVersion) != nil {
		return Artifact{}, errors.New("Gateway release version is invalid")
	}
	info, err := os.Lstat(filename)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() <= 0 || info.Size() > updatepkg.MaximumArchiveBytes {
		return Artifact{}, errors.New("Mihomo maintenance artifact must be a bounded regular release archive")
	}
	expected := "gateway-vpn-gateway-" + gatewayVersion + "-linux-amd64.tar.gz"
	if filepath.Base(filename) != expected {
		return Artifact{}, errors.New("Mihomo maintenance artifact filename is not canonical")
	}
	file, err := os.Open(filename)
	if err != nil {
		return Artifact{}, err
	}
	defer file.Close()
	hash := sha256.New()
	written, err := io.Copy(hash, io.LimitReader(file, updatepkg.MaximumArchiveBytes+1))
	if err != nil || written != info.Size() {
		return Artifact{}, errors.New("hash Mihomo maintenance release archive failed")
	}
	return Artifact{Filename: expected, SHA256: hex.EncodeToString(hash.Sum(nil)), Bytes: info.Size(), MediaType: "application/gzip"}, nil
}

func SignManifest(manifest Manifest, privateKey ed25519.PrivateKey) ([]byte, []byte, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return nil, nil, errors.New("valid Ed25519 Mihomo channel signing key is required")
	}
	fingerprint, err := updatepkg.PublicKeyFingerprint(privateKey.Public().(ed25519.PublicKey))
	if err != nil {
		return nil, nil, err
	}
	manifest.SignerKeySHA256 = fingerprint
	manifest.CompatibleGatewayVersions = append([]string(nil), manifest.CompatibleGatewayVersions...)
	sort.Strings(manifest.CompatibleGatewayVersions)
	if err := ValidateManifest(manifest); err != nil {
		return nil, nil, err
	}
	content, err := marshalLine(manifest)
	if err != nil || int64(len(content)) > MaximumManifestBytes {
		return nil, nil, errors.New("encode bounded Mihomo channel manifest failed")
	}
	signature := ed25519.Sign(privateKey, content)
	return content, []byte(base64.StdEncoding.EncodeToString(signature) + "\n"), nil
}

func VerifyManifest(content, encodedSignature []byte, publicKey ed25519.PublicKey, policy VerificationPolicy) (Manifest, error) {
	if len(publicKey) != ed25519.PublicKeySize || len(content) == 0 || int64(len(content)) > MaximumManifestBytes || len(encodedSignature) == 0 || int64(len(encodedSignature)) > MaximumSignatureBytes {
		return Manifest{}, errors.New("bounded signed Mihomo channel manifest and trusted key are required")
	}
	signature, err := base64.StdEncoding.Strict().DecodeString(strings.TrimSpace(string(encodedSignature)))
	if err != nil || len(signature) != ed25519.SignatureSize || !ed25519.Verify(publicKey, content, signature) {
		return Manifest{}, errors.New("Mihomo channel manifest signature verification failed")
	}
	var manifest Manifest
	if err := decodeStrict(content, &manifest); err != nil {
		return Manifest{}, errors.New("Mihomo channel manifest JSON contract is invalid")
	}
	fingerprint, _ := updatepkg.PublicKeyFingerprint(publicKey)
	if err := ValidateManifest(manifest); err != nil || manifest.SignerKeySHA256 != fingerprint {
		return Manifest{}, errors.New("Mihomo channel manifest identity or contract is invalid")
	}
	if err := verifyPolicy(manifest, policy); err != nil {
		return Manifest{}, err
	}
	return manifest, nil
}

func ValidateManifest(manifest Manifest) error {
	generated, dateErr := time.Parse(time.RFC3339, manifest.GeneratedAt)
	if manifest.FormatVersion != FormatVersion || manifest.Kind != Kind || !channelPattern.MatchString(manifest.Channel) || updatepkg.ValidateGatewayVersion(manifest.GatewayReleaseVersion) != nil || updatepkg.ValidateMihomoVersion(manifest.MihomoVersion) != nil || manifest.OS != "linux" || manifest.Arch != "amd64" || !digestPattern.MatchString(manifest.HostContractSHA256) || manifest.GatewayAPIContract != updatepkg.GatewayAPIContract || manifest.MihomoAPIContract != updatepkg.MihomoAPIContract || dateErr != nil || generated.IsZero() || !commitPattern.MatchString(manifest.SourceCommit) || !digestPattern.MatchString(manifest.SignerKeySHA256) || !validUrgency(manifest.Urgency) || !validSummary(manifest.Summary) {
		return errors.New("Mihomo channel manifest header is invalid")
	}
	if len(manifest.CompatibleGatewayVersions) == 0 || len(manifest.CompatibleGatewayVersions) > MaximumCompatible {
		return errors.New("Mihomo channel requires a bounded exact compatibility list")
	}
	previous := ""
	for _, version := range manifest.CompatibleGatewayVersions {
		if updatepkg.ValidateGatewayVersion(version) != nil || previous >= version {
			return errors.New("Mihomo channel compatibility versions must be unique and sorted")
		}
		order, err := updatepkg.CompareGatewayVersions(version, manifest.GatewayReleaseVersion)
		if err != nil || order >= 0 {
			return errors.New("compatible Gateway version must precede the maintenance release")
		}
		previous = version
	}
	expected := "gateway-vpn-gateway-" + manifest.GatewayReleaseVersion + "-linux-amd64.tar.gz"
	if manifest.Artifact.Filename != expected || !digestPattern.MatchString(manifest.Artifact.SHA256) || manifest.Artifact.Bytes <= 0 || manifest.Artifact.Bytes > updatepkg.MaximumArchiveBytes || manifest.Artifact.MediaType != "application/gzip" {
		return errors.New("Mihomo channel artifact is invalid")
	}
	return nil
}

func ManifestSHA256(content []byte) (string, error) {
	if len(content) == 0 || int64(len(content)) > MaximumManifestBytes {
		return "", errors.New("bounded Mihomo channel manifest content is required")
	}
	digest := sha256.Sum256(content)
	return hex.EncodeToString(digest[:]), nil
}

func verifyPolicy(manifest Manifest, policy VerificationPolicy) error {
	if policy.ExpectedChannel != "" && manifest.Channel != policy.ExpectedChannel || policy.ExpectedGatewayReleaseVersion != "" && manifest.GatewayReleaseVersion != policy.ExpectedGatewayReleaseVersion || policy.ExpectedSourceCommit != "" && manifest.SourceCommit != policy.ExpectedSourceCommit || policy.ExpectedOS != "" && manifest.OS != policy.ExpectedOS || policy.ExpectedArch != "" && manifest.Arch != policy.ExpectedArch || policy.ExpectedHostContractSHA256 != "" && manifest.HostContractSHA256 != policy.ExpectedHostContractSHA256 || policy.ExpectedGatewayAPIContract != "" && manifest.GatewayAPIContract != policy.ExpectedGatewayAPIContract || policy.ExpectedMihomoAPIContract != "" && manifest.MihomoAPIContract != policy.ExpectedMihomoAPIContract {
		return errors.New("Mihomo channel is incompatible with the current Gateway contract")
	}
	if policy.CurrentGatewayVersion != "" {
		found := false
		for _, version := range manifest.CompatibleGatewayVersions {
			found = found || version == policy.CurrentGatewayVersion
		}
		order, err := updatepkg.CompareGatewayVersions(manifest.GatewayReleaseVersion, policy.CurrentGatewayVersion)
		if !found || err != nil || order <= 0 {
			return errors.New("Mihomo channel does not approve this exact Gateway version")
		}
	}
	if policy.CurrentMihomoVersion != "" {
		order, err := updatepkg.CompareMihomoVersions(manifest.MihomoVersion, policy.CurrentMihomoVersion)
		if err != nil || order <= 0 {
			return errors.New("Mihomo channel is not a forward Mihomo update")
		}
	}
	if policy.MaximumAge > 0 {
		generated, _ := time.Parse(time.RFC3339, manifest.GeneratedAt)
		now := time.Now().UTC()
		if policy.Now != nil {
			now = policy.Now().UTC()
		}
		if generated.After(now.Add(5*time.Minute)) || now.Sub(generated) > policy.MaximumAge {
			return errors.New("Mihomo channel manifest is outside its accepted freshness window")
		}
	}
	return nil
}

func validUrgency(value string) bool {
	return value == UrgencyRoutine || value == UrgencyRecommended || value == UrgencySecurity
}

func validSummary(value string) bool {
	if !utf8.ValidString(value) || strings.TrimSpace(value) != value || len(value) == 0 || len(value) > MaximumSummaryBytes {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
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
