package distribution

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestSignedChannelManifestSelectsExactPinnedRoleArtifact(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	manifest := validManifest(t, publicKey)
	content, signature, err := SignManifest(manifest, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := ManifestSHA256(content)
	if err != nil || len(digest) != 64 {
		t.Fatalf("ManifestSHA256() = %q,%v", digest, err)
	}
	verified, err := VerifyManifest(content, signature, publicKey, VerificationPolicy{
		ExpectedChannel: "stable", ExpectedVersion: "1.2.0", ExpectedCommit: strings.Repeat("a", 40),
	})
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := SelectArtifact(verified, RoleGateway, "linux", "amd64")
	if err != nil || artifact.Filename != "gateway-vpn-gateway-1.2.0-linux-amd64.tar.gz" {
		t.Fatalf("SelectArtifact() = %+v,%v", artifact, err)
	}
}

func TestChannelManifestAcceptsOnlyWindowsAMD64DeployArtifact(t *testing.T) {
	manifest := validManifest(t, nil)
	manifest.Artifacts = append(manifest.Artifacts, Artifact{
		Role: RoleDeploy, OS: "windows", Arch: "amd64",
		Filename: "gateway-vpn-deploy-1.2.0-windows-amd64.exe",
		SHA256:   strings.Repeat("4", 64), Bytes: 8192,
		MediaType: "application/vnd.microsoft.portable-executable",
	})
	SortArtifacts(manifest.Artifacts)
	if err := ValidateManifest(manifest); err != nil {
		t.Fatal(err)
	}
	artifact, err := SelectArtifact(manifest, RoleDeploy, "windows", "amd64")
	if err != nil || artifact.Filename != "gateway-vpn-deploy-1.2.0-windows-amd64.exe" {
		t.Fatalf("SelectArtifact(windows) = %+v,%v", artifact, err)
	}
	for _, mutate := range []func(*Artifact){
		func(value *Artifact) { value.Role = RoleBootstrap },
		func(value *Artifact) { value.Arch = "arm64" },
		func(value *Artifact) { value.Filename = "gateway-vpn-deploy-1.2.0-windows-amd64" },
		func(value *Artifact) { value.MediaType = "application/octet-stream" },
	} {
		candidate := manifest
		candidate.Artifacts = append([]Artifact(nil), manifest.Artifacts...)
		for index := range candidate.Artifacts {
			if candidate.Artifacts[index].OS == "windows" {
				mutate(&candidate.Artifacts[index])
				break
			}
		}
		SortArtifacts(candidate.Artifacts)
		if err := ValidateManifest(candidate); err == nil {
			t.Fatal("unsafe Windows channel artifact was accepted")
		}
	}
}

func TestChannelManifestRejectsTamperDowngradeStaleAndUnknownFields(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	manifest := validManifest(t, publicKey)
	content, signature, err := SignManifest(manifest, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	tampered := append([]byte(nil), content...)
	index := strings.Index(string(tampered), "1.2.0")
	if index < 0 {
		t.Fatal("version not found")
	}
	tampered[index+2] = '3'
	if _, err := VerifyManifest(tampered, signature, publicKey, VerificationPolicy{}); err == nil {
		t.Fatal("tampered manifest was accepted")
	}
	if _, err := VerifyManifest(content, signature, publicKey, VerificationPolicy{ExpectedVersion: "1.1.0"}); err == nil {
		t.Fatal("version downgrade/mismatch was accepted")
	}
	if _, err := VerifyManifest(content, signature, publicKey, VerificationPolicy{ExpectedChannel: "beta"}); err == nil {
		t.Fatal("channel mismatch was accepted")
	}
	if _, err := VerifyManifest(content, signature, publicKey, VerificationPolicy{MaximumAge: time.Hour, Now: func() time.Time { return time.Date(2026, 8, 26, 0, 0, 0, 0, time.UTC) }}); err == nil {
		t.Fatal("stale channel manifest was accepted")
	}
	var generic map[string]any
	if err := json.Unmarshal(content, &generic); err != nil {
		t.Fatal(err)
	}
	generic["unknown"] = true
	unknown, _ := json.Marshal(generic)
	unknownSignature := base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, unknown)) + "\n"
	if _, err := VerifyManifest(unknown, []byte(unknownSignature), publicKey, VerificationPolicy{}); err == nil {
		t.Fatal("unknown manifest field was accepted")
	}
}

func TestChannelManifestRejectsUnsafeOrAmbiguousArtifactsAndSemVer(t *testing.T) {
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		mutate func(*Manifest)
	}{
		{name: "leading zero semver", mutate: func(value *Manifest) { value.ReleaseVersion = "01.2.0" }},
		{name: "path traversal", mutate: func(value *Manifest) { value.Artifacts[1].Filename = "../release.tar.gz" }},
		{name: "duplicate role platform", mutate: func(value *Manifest) {
			value.Artifacts = append(value.Artifacts, value.Artifacts[1])
			SortArtifacts(value.Artifacts)
		}},
		{name: "wrong role media", mutate: func(value *Manifest) { value.Artifacts[1].MediaType = "application/octet-stream" }},
		{name: "ambiguous role filename", mutate: func(value *Manifest) { value.Artifacts[1].Filename = "gateway-vpn-copy-1.2.0-linux-amd64.tar.gz" }},
		{name: "unsorted", mutate: func(value *Manifest) { value.Artifacts[0], value.Artifacts[1] = value.Artifacts[1], value.Artifacts[0] }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			manifest := validManifest(t, publicKey)
			test.mutate(&manifest)
			if err := ValidateManifest(manifest); err == nil {
				t.Fatal("invalid channel manifest was accepted")
			}
		})
	}
}

func validManifest(t *testing.T, publicKey ed25519.PublicKey) Manifest {
	t.Helper()
	fingerprint := strings.Repeat("0", 64)
	if len(publicKey) == ed25519.PublicKeySize {
		// SignManifest overwrites this value; direct validation tests only need a
		// syntactically valid placeholder.
		fingerprint = strings.Repeat("f", 64)
	}
	artifacts := []Artifact{
		{Role: RoleBootstrap, OS: "linux", Arch: "amd64", Filename: "gateway-vpn-bootstrap-1.2.0-linux-amd64", SHA256: strings.Repeat("1", 64), Bytes: 1024, MediaType: "application/octet-stream"},
		{Role: RoleGateway, OS: "linux", Arch: "amd64", Filename: "gateway-vpn-gateway-1.2.0-linux-amd64.tar.gz", SHA256: strings.Repeat("2", 64), Bytes: 2048, MediaType: "application/gzip"},
		{Role: RoleVPS, OS: "linux", Arch: "amd64", Filename: "gateway-vpn-vps-1.2.0-linux-amd64.tar.gz", SHA256: strings.Repeat("3", 64), Bytes: 4096, MediaType: "application/gzip"},
	}
	SortArtifacts(artifacts)
	return Manifest{
		FormatVersion: ChannelFormatVersion, Channel: "stable", ReleaseVersion: "1.2.0",
		GeneratedAt: "2026-08-25T00:00:00Z", SourceCommit: strings.Repeat("a", 40), SignerKeySHA256: fingerprint,
		Artifacts: artifacts,
	}
}
