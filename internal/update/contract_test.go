package update

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSignedReleaseVerificationRejectsTamperUnknownFilesAndWrongSigner(t *testing.T) {
	root, publicKey, privateKey := signedReleaseFixture(t, "1.2.0", 11, 12)
	policy := fixturePolicy(publicKey)
	verified, err := VerifyRelease(root, policy)
	if err != nil {
		t.Fatalf("VerifyRelease() error = %v", err)
	}
	if verified.Release.GatewayVersion != "1.2.0" || verified.Fingerprint == "" || len(verified.Manifest.Files) < 5 {
		t.Fatalf("verified release = %+v", verified)
	}

	t.Run("tamper", func(t *testing.T) {
		filename := filepath.Join(root, "bin", "gateway-vpn")
		if err := os.WriteFile(filename, []byte("tampered"), 0o755); err != nil {
			t.Fatal(err)
		}
		if _, err := VerifyRelease(root, policy); err == nil {
			t.Fatal("tampered signed file was accepted")
		}
		if err := os.WriteFile(filename, []byte("gateway-vpn candidate"), 0o755); err != nil {
			t.Fatal(err)
		}
	})

	if _, err := SignRelease(root, privateKey); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "unexpected.txt"), []byte("not signed"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyRelease(root, policy); err == nil {
		t.Fatal("unknown unsigned release file was accepted")
	}
	if err := os.Remove(filepath.Join(root, "unexpected.txt")); err != nil {
		t.Fatal(err)
	}

	otherPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	wrong := policy
	wrong.PublicKey = otherPublic
	if _, err := VerifyRelease(root, wrong); err == nil {
		t.Fatal("release signed by a different identity was accepted")
	}
}

func TestReleaseCompatibilityRejectsDowngradeSchemaPlatformAndContracts(t *testing.T) {
	root, publicKey, _ := signedReleaseFixture(t, "1.2.0", 11, 12)
	base := fixturePolicy(publicKey)
	cases := []struct {
		name   string
		mutate func(*VerificationPolicy)
	}{
		{"same version", func(policy *VerificationPolicy) { policy.CurrentGatewayVersion = "1.2.0" }},
		{"newer current version", func(policy *VerificationPolicy) { policy.CurrentGatewayVersion = "1.3.0" }},
		{"schema too old", func(policy *VerificationPolicy) { policy.CurrentSchemaVersion = 10 }},
		{"schema too new", func(policy *VerificationPolicy) { policy.CurrentSchemaVersion = 13 }},
		{"wrong os", func(policy *VerificationPolicy) { policy.ExpectedOS = "freebsd" }},
		{"wrong arch", func(policy *VerificationPolicy) { policy.ExpectedArch = "arm64" }},
		{"wrong config", func(policy *VerificationPolicy) { policy.ConfigGeneration = 2 }},
		{"wrong host lifecycle", func(policy *VerificationPolicy) { policy.CurrentHostContractSHA256 = strings.Repeat("f", 64) }},
		{"wrong Gateway API", func(policy *VerificationPolicy) { policy.GatewayAPIContract = "gateway-vpn-api-v2" }},
		{"wrong Mihomo API", func(policy *VerificationPolicy) { policy.MihomoAPIContract = "mihomo-local-v2" }},
	}
	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			policy := base
			item.mutate(&policy)
			if _, err := VerifyRelease(root, policy); err == nil {
				t.Fatal("incompatible signed release was accepted")
			}
		})
	}
}

func TestSignerRejectsSymlinksAndStrictMetadata(t *testing.T) {
	root, _, privateKey := unsignedReleaseFixture(t, "1.2.0", 11, 12)
	if err := os.Symlink(filepath.Join(root, "release.json"), filepath.Join(root, "linked.json")); err == nil {
		if _, err := SignRelease(root, privateKey); err == nil {
			t.Fatal("release symlink was signed")
		}
		if err := os.Remove(filepath.Join(root, "linked.json")); err != nil {
			t.Fatal(err)
		}
	}
	content, err := os.ReadFile(filepath.Join(root, ReleaseFilename))
	if err != nil {
		t.Fatal(err)
	}
	content[len(content)-2] = ','
	content = append(content[:len(content)-1], []byte(`"unknown":true}`)...)
	if err := os.WriteFile(filepath.Join(root, ReleaseFilename), content, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := SignRelease(root, privateKey); err == nil {
		t.Fatal("release metadata with unknown fields was signed")
	}
}

func TestSignerRejectsChangedHostLifecycleWithoutMetadataUpdate(t *testing.T) {
	root, _, privateKey := unsignedReleaseFixture(t, "1.2.0", 11, 12)
	unit := filepath.Join(root, filepath.FromSlash(requiredHostContractFiles[0]))
	if err := os.WriteFile(unit, []byte("[Unit]\nDescription=changed lifecycle unit\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := SignRelease(root, privateKey); err == nil {
		t.Fatal("release with stale host lifecycle metadata was signed")
	}
}

func TestSemanticVersionOrdering(t *testing.T) {
	cases := []struct {
		left, right string
		want        int
	}{
		{"1.2.0", "1.1.9", 1},
		{"1.2.0-rc.2", "1.2.0-rc.1", 1},
		{"1.2.0", "1.2.0-rc.9", 1},
		{"2.0.0-alpha", "2.0.0", -1},
		{"1.0.0+build.2", "1.0.0+build.1", 0},
	}
	for _, item := range cases {
		actual, err := compareVersions(item.left, item.right)
		if err != nil || actual != item.want {
			t.Fatalf("compareVersions(%q,%q) = %d,%v want %d", item.left, item.right, actual, err, item.want)
		}
	}
	for _, invalid := range []string{"v1.2.0", "1.02.0", "1.2", "latest", "1.2.0-"} {
		if _, err := compareVersions(invalid, "1.0.0"); err == nil {
			t.Fatalf("invalid version %q was accepted", invalid)
		}
	}
	for _, invalid := range []string{"1.2.0-01", "1.2.0-alpha..1", "1.2.0+build..1", "1.2.0+"} {
		if _, err := compareVersions(invalid, "1.0.0"); err == nil {
			t.Fatalf("non-canonical semantic version %q was accepted", invalid)
		}
	}
}

func TestReleasePathsHaveExplicitDepthAndLengthBounds(t *testing.T) {
	if safeRelativePath(strings.Repeat("a", MaximumRelativePath+1)) {
		t.Fatal("oversized release path was accepted")
	}
	if safeRelativePath(strings.Repeat("a/", MaximumPathParts) + "z") {
		t.Fatal("overly deep release path was accepted")
	}
	if !safeRelativePath("share/doc/OPERATIONS.md") {
		t.Fatal("normal release path was rejected")
	}
	if !safeRelativePath("packaging/systemd/gateway-vpn-network-rollback@.service") {
		t.Fatal("safe systemd template-unit path was rejected")
	}
}

func signedReleaseFixture(t *testing.T, version string, schemaMin, schemaMax int64) (string, ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	root, publicKey, privateKey := unsignedReleaseFixture(t, version, schemaMin, schemaMax)
	if _, err := SignRelease(root, privateKey); err != nil {
		t.Fatal(err)
	}
	return root, publicKey, privateKey
}

func unsignedReleaseFixture(t *testing.T, version string, schemaMin, schemaMax int64) (string, ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	for name, content := range map[string]string{
		"bin/gateway-vpn":    "gateway-vpn candidate",
		"bin/gateway-vpnctl": "gateway-vpnctl candidate",
		"libexec/mihomo":     "mihomo candidate",
		LegacyHashFilename:   strings.Repeat("a", 64) + "  bin/gateway-vpn\n",
	} {
		filename := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(filename), 0o755); err != nil {
			t.Fatal(err)
		}
		mode := os.FileMode(0o644)
		if strings.HasPrefix(name, "bin/") || name == "libexec/mihomo" {
			mode = 0o755
		}
		if err := os.WriteFile(filename, []byte(content), mode); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range requiredHostContractFiles {
		filename := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(filename), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filename, []byte("[Unit]\nDescription=test host lifecycle unit\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	mihomoDigest, _, err := hashFile(filepath.Join(root, "libexec", "mihomo"), MaximumFileBytes)
	if err != nil {
		t.Fatal(err)
	}
	hostContract, err := ComputeHostContractSHA256(root)
	if err != nil {
		t.Fatal(err)
	}
	release := Release{
		FormatVersion: ReleaseFormatVersion, GatewayVersion: version, MihomoVersion: "v1.19.10",
		OS: "linux", Arch: "amd64", MihomoSHA256: mihomoDigest,
		DatabaseSchemaMinimum: schemaMin, DatabaseSchemaMaximum: schemaMax,
		ConfigSchemaGeneration: 1, HostContractSHA256: hostContract,
		GatewayAPIContract: GatewayAPIContract, MihomoAPIContract: MihomoAPIContract,
		BuildCommit: strings.Repeat("a", 40), BuildDate: "2026-08-24T20:00:00Z",
	}
	content, err := json.MarshalIndent(release, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	content = append(content, '\n')
	if err := os.WriteFile(filepath.Join(root, ReleaseFilename), content, 0o644); err != nil {
		t.Fatal(err)
	}
	return root, publicKey, privateKey
}

func fixturePolicy(publicKey ed25519.PublicKey) VerificationPolicy {
	return VerificationPolicy{
		PublicKey: publicKey, ExpectedOS: "linux", ExpectedArch: "amd64",
		CurrentGatewayVersion: "1.1.0", CurrentSchemaVersion: 11,
		ConfigGeneration: 1, GatewayAPIContract: GatewayAPIContract, MihomoAPIContract: MihomoAPIContract,
	}
}
