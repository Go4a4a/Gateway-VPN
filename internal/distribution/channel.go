// Package distribution defines the signed, role-aware release channel used by
// the independent first-install bootstrap. It deliberately contains no host
// mutation code.
package distribution

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
	"regexp"
	"sort"
	"strings"
	"time"

	updatepkg "gateway-vpn/internal/update"
)

const (
	ChannelFormatVersion  = 1
	MaximumManifestBytes  = int64(256 << 10)
	MaximumSignatureBytes = int64(1024)
	MaximumArtifacts      = 32
	MaximumArtifactBytes  = int64(1 << 30)

	RoleGateway   = "gateway"
	RoleVPS       = "vps"
	RoleDeploy    = "deploy"
	RoleBootstrap = "bootstrap"
)

var (
	channelPattern  = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)
	filenamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]{0,199}$`)
	digestPattern   = regexp.MustCompile(`^[a-f0-9]{64}$`)
	commitPattern   = regexp.MustCompile(`^(?:[a-f0-9]{40}|[a-f0-9]{64})$`)
)

type Manifest struct {
	FormatVersion   int        `json:"format_version"`
	Channel         string     `json:"channel"`
	ReleaseVersion  string     `json:"release_version"`
	GeneratedAt     string     `json:"generated_at"`
	SourceCommit    string     `json:"source_commit"`
	SignerKeySHA256 string     `json:"signer_key_sha256"`
	Artifacts       []Artifact `json:"artifacts"`
}

type Artifact struct {
	Role      string `json:"role"`
	OS        string `json:"os"`
	Arch      string `json:"arch"`
	Filename  string `json:"filename"`
	SHA256    string `json:"sha256"`
	Bytes     int64  `json:"bytes"`
	MediaType string `json:"media_type"`
}

type VerificationPolicy struct {
	ExpectedChannel string
	ExpectedVersion string
	ExpectedCommit  string
	Now             func() time.Time
	MaximumAge      time.Duration
}

func SignManifest(manifest Manifest, privateKey ed25519.PrivateKey) ([]byte, []byte, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return nil, nil, errors.New("valid Ed25519 channel signing key is required")
	}
	publicKey := privateKey.Public().(ed25519.PublicKey)
	fingerprint, err := updatepkg.PublicKeyFingerprint(publicKey)
	if err != nil {
		return nil, nil, err
	}
	manifest.SignerKeySHA256 = fingerprint
	if err := ValidateManifest(manifest); err != nil {
		return nil, nil, err
	}
	content, err := marshalLine(manifest)
	if err != nil || int64(len(content)) > MaximumManifestBytes {
		return nil, nil, errors.New("encode bounded channel manifest failed")
	}
	signature := ed25519.Sign(privateKey, content)
	encoded := []byte(base64.StdEncoding.EncodeToString(signature) + "\n")
	return content, encoded, nil
}

func VerifyManifest(content, encodedSignature []byte, publicKey ed25519.PublicKey, policy VerificationPolicy) (Manifest, error) {
	if len(publicKey) != ed25519.PublicKeySize || len(content) == 0 || int64(len(content)) > MaximumManifestBytes || len(encodedSignature) == 0 || int64(len(encodedSignature)) > MaximumSignatureBytes {
		return Manifest{}, errors.New("bounded signed channel manifest and trusted Ed25519 key are required")
	}
	signature, err := base64.StdEncoding.Strict().DecodeString(strings.TrimSpace(string(encodedSignature)))
	if err != nil || len(signature) != ed25519.SignatureSize || !ed25519.Verify(publicKey, content, signature) {
		return Manifest{}, errors.New("channel manifest signature verification failed")
	}
	var manifest Manifest
	if err := decodeStrict(content, &manifest); err != nil {
		return Manifest{}, errors.New("channel manifest JSON contract is invalid")
	}
	fingerprint, _ := updatepkg.PublicKeyFingerprint(publicKey)
	if err := ValidateManifest(manifest); err != nil || manifest.SignerKeySHA256 != fingerprint {
		return Manifest{}, errors.New("channel manifest identity or contract is invalid")
	}
	if policy.ExpectedChannel != "" && manifest.Channel != policy.ExpectedChannel {
		return Manifest{}, errors.New("channel manifest does not match the pinned channel")
	}
	if policy.ExpectedVersion != "" && manifest.ReleaseVersion != policy.ExpectedVersion {
		return Manifest{}, errors.New("channel manifest does not match the pinned release version")
	}
	if policy.ExpectedCommit != "" && manifest.SourceCommit != policy.ExpectedCommit {
		return Manifest{}, errors.New("channel manifest does not match the pinned source commit")
	}
	generated, _ := time.Parse(time.RFC3339, manifest.GeneratedAt)
	if policy.MaximumAge > 0 {
		now := time.Now().UTC()
		if policy.Now != nil {
			now = policy.Now().UTC()
		}
		if generated.After(now.Add(5*time.Minute)) || now.Sub(generated) > policy.MaximumAge {
			return Manifest{}, errors.New("channel manifest is outside its accepted freshness window")
		}
	}
	return manifest, nil
}

func ValidateManifest(manifest Manifest) error {
	generated, dateErr := time.Parse(time.RFC3339, manifest.GeneratedAt)
	if manifest.FormatVersion != ChannelFormatVersion || !channelPattern.MatchString(manifest.Channel) || updatepkg.ValidateGatewayVersion(manifest.ReleaseVersion) != nil || dateErr != nil || generated.IsZero() || !commitPattern.MatchString(manifest.SourceCommit) || !digestPattern.MatchString(manifest.SignerKeySHA256) || len(manifest.Artifacts) == 0 || len(manifest.Artifacts) > MaximumArtifacts {
		return errors.New("channel manifest header is invalid")
	}
	previous := ""
	identities := make(map[string]struct{}, len(manifest.Artifacts))
	for _, artifact := range manifest.Artifacts {
		if err := validateArtifact(artifact, manifest.ReleaseVersion); err != nil {
			return err
		}
		order := artifact.Role + "\x00" + artifact.OS + "\x00" + artifact.Arch + "\x00" + artifact.Filename
		if previous >= order {
			return errors.New("channel artifacts must be strictly sorted")
		}
		previous = order
		identity := artifact.Role + "\x00" + artifact.OS + "\x00" + artifact.Arch
		if _, duplicate := identities[identity]; duplicate {
			return errors.New("channel contains more than one artifact for a role and platform")
		}
		identities[identity] = struct{}{}
	}
	return nil
}

func SortArtifacts(artifacts []Artifact) {
	sort.Slice(artifacts, func(i, j int) bool {
		left := artifacts[i].Role + "\x00" + artifacts[i].OS + "\x00" + artifacts[i].Arch + "\x00" + artifacts[i].Filename
		right := artifacts[j].Role + "\x00" + artifacts[j].OS + "\x00" + artifacts[j].Arch + "\x00" + artifacts[j].Filename
		return left < right
	})
}

func SelectArtifact(manifest Manifest, role, operatingSystem, architecture string) (Artifact, error) {
	if err := ValidateManifest(manifest); err != nil {
		return Artifact{}, err
	}
	for _, artifact := range manifest.Artifacts {
		if artifact.Role == role && artifact.OS == operatingSystem && artifact.Arch == architecture {
			return artifact, nil
		}
	}
	return Artifact{}, fmt.Errorf("signed channel has no %s artifact for %s/%s", role, operatingSystem, architecture)
}

func ManifestSHA256(content []byte) (string, error) {
	if len(content) == 0 || int64(len(content)) > MaximumManifestBytes {
		return "", errors.New("bounded channel manifest content is required")
	}
	digest := sha256.Sum256(content)
	return hex.EncodeToString(digest[:]), nil
}

func validateArtifact(artifact Artifact, version string) error {
	if !validRole(artifact.Role) || !validArtifactPlatform(artifact.Role, artifact.OS, artifact.Arch) || !filenamePattern.MatchString(artifact.Filename) || !digestPattern.MatchString(artifact.SHA256) || artifact.Bytes <= 0 || artifact.Bytes > MaximumArtifactBytes {
		return errors.New("channel artifact identity, platform, hash, or size is invalid")
	}
	expectedFilename := fmt.Sprintf("gateway-vpn-%s-%s-%s-%s", artifact.Role, version, artifact.OS, artifact.Arch)
	if artifact.OS == "windows" {
		expectedFilename += ".exe"
	}
	switch artifact.Role {
	case RoleGateway, RoleVPS:
		expectedFilename += ".tar.gz"
		if artifact.MediaType != "application/gzip" || artifact.Filename != expectedFilename {
			return errors.New("role release artifact filename or media type is invalid")
		}
	case RoleDeploy, RoleBootstrap:
		expectedMediaType := "application/octet-stream"
		if artifact.OS == "windows" {
			expectedMediaType = "application/vnd.microsoft.portable-executable"
		}
		if artifact.MediaType != expectedMediaType || artifact.Filename != expectedFilename {
			return errors.New("launcher artifact media type is invalid")
		}
	}
	return nil
}

func validArtifactPlatform(role, operatingSystem, architecture string) bool {
	if architecture != "amd64" {
		return false
	}
	if operatingSystem == "linux" {
		return true
	}
	return role == RoleDeploy && operatingSystem == "windows"
}

func validRole(value string) bool {
	return value == RoleGateway || value == RoleVPS || value == RoleDeploy || value == RoleBootstrap
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
