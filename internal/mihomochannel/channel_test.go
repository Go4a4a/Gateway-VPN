package mihomochannel

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	updatepkg "gateway-vpn/internal/update"
)

func TestSignedManifestApprovesOnlyExactCompatibleForwardVersions(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	manifest := fixtureManifest(t, privateKey)
	content, signature, err := SignManifest(manifest, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	policy := VerificationPolicy{
		ExpectedChannel: "stable", CurrentGatewayVersion: "1.2.0", CurrentMihomoVersion: "v1.19.30",
		ExpectedOS: "linux", ExpectedArch: "amd64", ExpectedHostContractSHA256: strings.Repeat("a", 64),
		ExpectedGatewayAPIContract: updatepkg.GatewayAPIContract, ExpectedMihomoAPIContract: updatepkg.MihomoAPIContract,
		Now: func() time.Time { return time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC) }, MaximumAge: time.Hour,
	}
	verified, err := VerifyManifest(content, signature, publicKey, policy)
	if err != nil || verified.MihomoVersion != "v1.20.0" || verified.GatewayReleaseVersion != "1.2.1" {
		t.Fatalf("VerifyManifest() = %+v,%v", verified, err)
	}
	policy.CurrentGatewayVersion = "1.1.9"
	if _, err := VerifyManifest(content, signature, publicKey, policy); err == nil {
		t.Fatal("unlisted current Gateway version was accepted")
	}
	policy.CurrentGatewayVersion = "1.2.0"
	policy.CurrentMihomoVersion = "v1.20.0"
	if _, err := VerifyManifest(content, signature, publicKey, policy); err == nil {
		t.Fatal("same Mihomo version was accepted as an update")
	}
}

func TestManifestRejectsTamperUnknownFieldsAndUnsafeMetadata(t *testing.T) {
	publicKey, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	manifest := fixtureManifest(t, privateKey)
	content, signature, err := SignManifest(manifest, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	tampered := append([]byte(nil), content...)
	tampered[len(tampered)/2] ^= 1
	if _, err := VerifyManifest(tampered, signature, publicKey, VerificationPolicy{}); err == nil {
		t.Fatal("tampered Mihomo manifest was accepted")
	}
	unknown := append(content[:len(content)-2], []byte(",\n  \"unknown\": true\n}\n")...)
	unknownSignature := ed25519.Sign(privateKey, unknown)
	encodedUnknown := []byte(base64.StdEncoding.EncodeToString(unknownSignature) + "\n")
	if _, err := VerifyManifest(unknown, encodedUnknown, publicKey, VerificationPolicy{}); err == nil {
		t.Fatal("unknown Mihomo manifest field was accepted")
	}
	manifest.Summary = "unsafe\nsummary"
	if _, _, err := SignManifest(manifest, privateKey); err == nil {
		t.Fatal("control character in summary was accepted")
	}
}

func TestArtifactFromFilePinsCanonicalNameSizeAndHash(t *testing.T) {
	root := t.TempDir()
	filename := filepath.Join(root, "gateway-vpn-gateway-1.2.1-linux-amd64.tar.gz")
	if err := os.WriteFile(filename, []byte("signed-full-release"), 0o600); err != nil {
		t.Fatal(err)
	}
	artifact, err := ArtifactFromFile(filename, "1.2.1")
	if err != nil || artifact.Bytes != 19 || len(artifact.SHA256) != 64 || artifact.MediaType != "application/gzip" {
		t.Fatalf("ArtifactFromFile() = %+v,%v", artifact, err)
	}
	if _, err := ArtifactFromFile(filename, "1.2.2"); err == nil {
		t.Fatal("non-canonical artifact filename was accepted")
	}
}

func fixtureManifest(t *testing.T, privateKey ed25519.PrivateKey) Manifest {
	t.Helper()
	fingerprint, err := updatepkg.PublicKeyFingerprint(privateKey.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	return Manifest{
		FormatVersion: FormatVersion, Kind: Kind, Channel: "stable",
		GatewayReleaseVersion: "1.2.1", MihomoVersion: "v1.20.0",
		CompatibleGatewayVersions: []string{"1.0.0", "1.2.0"}, OS: "linux", Arch: "amd64",
		HostContractSHA256: strings.Repeat("a", 64), GatewayAPIContract: updatepkg.GatewayAPIContract,
		MihomoAPIContract: updatepkg.MihomoAPIContract, GeneratedAt: "2026-09-01T11:30:00Z",
		SourceCommit: strings.Repeat("b", 40), SignerKeySHA256: fingerprint,
		Urgency: UrgencyRecommended, Summary: "Исправление совместимости протоколов.",
		Artifact: Artifact{Filename: "gateway-vpn-gateway-1.2.1-linux-amd64.tar.gz", SHA256: strings.Repeat("c", 64), Bytes: 1234, MediaType: "application/gzip"},
	}
}
