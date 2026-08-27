package update

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestWriteKeyPairRequiresSecureAbsoluteExclusivePaths(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	privatePath := filepath.Join(directory, "release-signing.pem")
	publicPath := filepath.Join(directory, "update-signing.pub")
	fingerprint, err := WriteKeyPair(privatePath, publicPath)
	if err != nil {
		t.Fatalf("WriteKeyPair() error = %v", err)
	}
	privateKey, err := LoadPrivateKey(privatePath)
	if err != nil {
		t.Fatal(err)
	}
	publicKey, err := LoadPublicKey(publicPath)
	if err != nil {
		t.Fatal(err)
	}
	wantFingerprint, err := PublicKeyFingerprint(publicKey)
	if err != nil || fingerprint != wantFingerprint || !bytes.Equal(privateKey.Public().(ed25519.PublicKey), publicKey) {
		t.Fatalf("generated key pair fingerprint=%q want=%q err=%v", fingerprint, wantFingerprint, err)
	}
	verifiedFingerprint, err := VerifyKeyPair(privatePath, publicPath)
	if err != nil || verifiedFingerprint != fingerprint {
		t.Fatalf("VerifyKeyPair() fingerprint=%q err=%v", verifiedFingerprint, err)
	}
	if runtime.GOOS != "windows" {
		privateInfo, err := os.Stat(privatePath)
		if err != nil {
			t.Fatal(err)
		}
		if privateInfo.Mode().Perm() != 0o600 {
			t.Fatalf("private key mode=%v", privateInfo.Mode().Perm())
		}
		publicInfo, err := os.Stat(publicPath)
		if err != nil {
			t.Fatal(err)
		}
		if publicInfo.Mode().Perm() != 0o644 {
			t.Fatalf("public key mode=%v", publicInfo.Mode().Perm())
		}
	}
	privateBefore, err := os.ReadFile(privatePath)
	if err != nil {
		t.Fatal(err)
	}
	publicBefore, err := os.ReadFile(publicPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := WriteKeyPair(privatePath, publicPath); err == nil {
		t.Fatal("existing signing identity was overwritten")
	}
	privateAfter, _ := os.ReadFile(privatePath)
	publicAfter, _ := os.ReadFile(publicPath)
	if !bytes.Equal(privateBefore, privateAfter) || !bytes.Equal(publicBefore, publicAfter) {
		t.Fatal("failed repeat key generation changed the existing identity")
	}
	if _, err := WriteKeyPair("relative-private.pem", "relative-public.pem"); err == nil {
		t.Fatal("relative key destinations were accepted")
	}
	otherDirectory := t.TempDir()
	if err := os.Chmod(otherDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := WriteKeyPair(filepath.Join(directory, "other-private.pem"), filepath.Join(otherDirectory, "other-public.pem")); err == nil {
		t.Fatal("key destinations in different directories were accepted")
	}
}

func TestBackupKeyPairIsExclusiveAndCryptographicallyVerified(t *testing.T) {
	source := t.TempDir()
	backup := t.TempDir()
	for _, directory := range []string{source, backup} {
		if err := os.Chmod(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	privatePath := filepath.Join(source, "release-signing.pem")
	publicPath := filepath.Join(source, "update-signing.pub")
	fingerprint, err := WriteKeyPair(privatePath, publicPath)
	if err != nil {
		t.Fatal(err)
	}
	backupPrivatePath := filepath.Join(backup, "release-signing.pem")
	backupPublicPath := filepath.Join(backup, "update-signing.pub")
	backupFingerprint, err := BackupKeyPair(privatePath, publicPath, backupPrivatePath, backupPublicPath)
	if err != nil || backupFingerprint != fingerprint {
		t.Fatalf("BackupKeyPair() fingerprint=%q want=%q err=%v", backupFingerprint, fingerprint, err)
	}
	verifiedBackupFingerprint, err := VerifyKeyPair(backupPrivatePath, backupPublicPath)
	if err != nil || verifiedBackupFingerprint != fingerprint {
		t.Fatalf("verify backup fingerprint=%q want=%q err=%v", verifiedBackupFingerprint, fingerprint, err)
	}
	backupPrivateBefore, _ := os.ReadFile(backupPrivatePath)
	backupPublicBefore, _ := os.ReadFile(backupPublicPath)
	if _, err := BackupKeyPair(privatePath, publicPath, backupPrivatePath, backupPublicPath); err == nil {
		t.Fatal("existing release signing backup was overwritten")
	}
	backupPrivateAfter, _ := os.ReadFile(backupPrivatePath)
	backupPublicAfter, _ := os.ReadFile(backupPublicPath)
	if !bytes.Equal(backupPrivateBefore, backupPrivateAfter) || !bytes.Equal(backupPublicBefore, backupPublicAfter) {
		t.Fatal("failed repeat backup changed the existing identity")
	}
	if _, err := BackupKeyPair(privatePath, publicPath, filepath.Join(source, "backup-private.pem"), filepath.Join(source, "backup-public.pem")); err == nil {
		t.Fatal("same-directory backup was accepted")
	}

	other := t.TempDir()
	if err := os.Chmod(other, 0o700); err != nil {
		t.Fatal(err)
	}
	otherPrivate := filepath.Join(other, "other-private.pem")
	otherPublic := filepath.Join(other, "other-public.pem")
	if _, err := WriteKeyPair(otherPrivate, otherPublic); err != nil {
		t.Fatal(err)
	}
	wrongPublic := filepath.Join(source, "wrong-public.pem")
	content, err := os.ReadFile(otherPublic)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(wrongPublic, content, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyKeyPair(privatePath, wrongPublic); err == nil {
		t.Fatal("mismatched release signing pair was accepted")
	}
	mismatchBackup := t.TempDir()
	if err := os.Chmod(mismatchBackup, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := BackupKeyPair(privatePath, wrongPublic, filepath.Join(mismatchBackup, "private.pem"), filepath.Join(mismatchBackup, "public.pem")); err == nil {
		t.Fatal("mismatched source release signing pair was backed up")
	}
	if runtime.GOOS != "windows" {
		if err := os.Chmod(privatePath, 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadPrivateKey(privatePath); err == nil {
			t.Fatal("permission-weakened private key was loaded")
		}
	}
}

func TestWriteKeyPairRejectsUnsafeDestinationAndCleansPartialPair(t *testing.T) {
	insecure := t.TempDir()
	if runtime.GOOS != "windows" {
		if err := os.Chmod(insecure, 0o755); err != nil {
			t.Fatal(err)
		}
		if _, err := WriteKeyPair(filepath.Join(insecure, "private.pem"), filepath.Join(insecure, "public.pem")); err == nil {
			t.Fatal("group-readable key destination was accepted")
		}
	}

	worktree := t.TempDir()
	if err := os.Chmod(worktree, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(worktree, ".git"), 0o700); err != nil {
		t.Fatal(err)
	}
	keys := filepath.Join(worktree, "keys")
	if err := os.Mkdir(keys, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := WriteKeyPair(filepath.Join(keys, "private.pem"), filepath.Join(keys, "public.pem")); err == nil {
		t.Fatal("key destination inside a Git worktree was accepted")
	}

	linkedRoot := t.TempDir()
	if err := os.Chmod(linkedRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	target := t.TempDir()
	if err := os.Chmod(target, 0o700); err != nil {
		t.Fatal(err)
	}
	linkedDirectory := filepath.Join(linkedRoot, "linked")
	if err := os.Symlink(target, linkedDirectory); err == nil {
		if _, err := WriteKeyPair(filepath.Join(linkedDirectory, "private.pem"), filepath.Join(linkedDirectory, "public.pem")); err == nil {
			t.Fatal("symlink key destination was accepted")
		}
	}

	partial := t.TempDir()
	if err := os.Chmod(partial, 0o700); err != nil {
		t.Fatal(err)
	}
	privatePath := filepath.Join(partial, "private.pem")
	publicPath := filepath.Join(partial, "public.pem")
	if err := os.WriteFile(publicPath, []byte("existing public destination"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := WriteKeyPair(privatePath, publicPath); err == nil {
		t.Fatal("existing public destination was overwritten")
	}
	if _, err := os.Lstat(privatePath); !os.IsNotExist(err) {
		t.Fatalf("partial private key was retained: %v", err)
	}
	content, err := os.ReadFile(publicPath)
	if err != nil || string(content) != "existing public destination" {
		t.Fatalf("existing public destination changed: %q err=%v", content, err)
	}
}

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
