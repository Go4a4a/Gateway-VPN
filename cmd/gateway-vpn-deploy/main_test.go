package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"gateway-vpn/internal/buildinfo"
	"gateway-vpn/internal/deploy"
	"gateway-vpn/internal/distribution"
	updatepkg "gateway-vpn/internal/update"
)

func TestVerifyRunningDeployArtifactUsesExactCurrentPlatformIdentity(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(executable)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(content)
	version := "1.2.3"
	commit := strings.Repeat("a", 40)
	originalVersion, originalCommit := buildinfo.Version, buildinfo.Commit
	buildinfo.Version, buildinfo.Commit = version, commit
	defer func() { buildinfo.Version, buildinfo.Commit = originalVersion, originalCommit }()
	filename := "gateway-vpn-deploy-" + version + "-" + runtime.GOOS + "-" + runtime.GOARCH
	mediaType := "application/octet-stream"
	if runtime.GOOS == "windows" {
		filename += ".exe"
		mediaType = "application/vnd.microsoft.portable-executable"
	}
	manifest := distribution.Manifest{
		FormatVersion: distribution.ChannelFormatVersion, Channel: "stable", ReleaseVersion: version,
		GeneratedAt: "2026-09-01T00:00:00Z", SourceCommit: commit, SignerKeySHA256: strings.Repeat("f", 64),
		Artifacts: []distribution.Artifact{{
			Role: distribution.RoleDeploy, OS: runtime.GOOS, Arch: runtime.GOARCH,
			Filename: filename, SHA256: hex.EncodeToString(digest[:]), Bytes: int64(len(content)), MediaType: mediaType,
		}},
	}
	if err := verifyRunningDeployArtifact(manifest); err != nil {
		t.Fatal(err)
	}
	manifest.Artifacts[0].SHA256 = strings.Repeat("0", 64)
	if err := verifyRunningDeployArtifact(manifest); err == nil {
		t.Fatal("running deploy executable accepted a mismatched signed SHA-256")
	}
}

func TestWindowsSignedLauncherReachesPinnedSSHPreflightWithoutHostMutation(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("native Windows launcher smoke")
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(executable)
	if err != nil {
		t.Fatal(err)
	}
	executableDigest := sha256.Sum256(content)
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	version, commit := "1.2.3", strings.Repeat("b", 40)
	originalVersion, originalCommit := buildinfo.Version, buildinfo.Commit
	buildinfo.Version, buildinfo.Commit = version, commit
	defer func() { buildinfo.Version, buildinfo.Commit = originalVersion, originalCommit }()
	artifacts := []distribution.Artifact{
		{Role: distribution.RoleBootstrap, OS: "linux", Arch: "amd64", Filename: "gateway-vpn-bootstrap-1.2.3-linux-amd64", SHA256: strings.Repeat("1", 64), Bytes: 10, MediaType: "application/octet-stream"},
		{Role: distribution.RoleDeploy, OS: "linux", Arch: "amd64", Filename: "gateway-vpn-deploy-1.2.3-linux-amd64", SHA256: strings.Repeat("2", 64), Bytes: 10, MediaType: "application/octet-stream"},
		{Role: distribution.RoleDeploy, OS: "windows", Arch: "amd64", Filename: "gateway-vpn-deploy-1.2.3-windows-amd64.exe", SHA256: hex.EncodeToString(executableDigest[:]), Bytes: int64(len(content)), MediaType: "application/vnd.microsoft.portable-executable"},
		{Role: distribution.RoleGateway, OS: "linux", Arch: "amd64", Filename: "gateway-vpn-gateway-1.2.3-linux-amd64.tar.gz", SHA256: strings.Repeat("3", 64), Bytes: 10, MediaType: "application/gzip"},
		{Role: distribution.RoleVPS, OS: "linux", Arch: "amd64", Filename: "gateway-vpn-vps-1.2.3-linux-amd64.tar.gz", SHA256: strings.Repeat("4", 64), Bytes: 10, MediaType: "application/gzip"},
	}
	distribution.SortArtifacts(artifacts)
	manifestContent, signature, err := distribution.SignManifest(distribution.Manifest{
		FormatVersion: distribution.ChannelFormatVersion, Channel: "stable", ReleaseVersion: version,
		GeneratedAt: "2026-09-01T00:00:00Z", SourceCommit: commit, Artifacts: artifacts,
	}, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	manifestPath := filepath.Join(directory, "channel-stable.json")
	signaturePath := filepath.Join(directory, "channel-stable.sig")
	publicKeyPath := filepath.Join(directory, "update-signing.pub")
	knownHostsPath := filepath.Join(directory, "known hosts")
	identityPath := filepath.Join(directory, "selected identity")
	publicDER, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	for path, value := range map[string][]byte{
		manifestPath: manifestContent, signaturePath: signature,
		publicKeyPath:  pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER}),
		knownHostsPath: {}, identityPath: []byte("not-used-because-port-is-closed\n"),
	} {
		if err := os.WriteFile(path, value, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	manifestDigest, _ := distribution.ManifestSHA256(manifestContent)
	fingerprint, _ := updatepkg.PublicKeyFingerprint(publicKey)
	adminPublicKey := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32))
	code := run([]string{
		"--manifest", manifestPath, "--signature", signaturePath, "--public-key", publicKeyPath,
		"--manifest-sha256", manifestDigest, "--signer-key-sha256", fingerprint,
		"--channel", "stable", "--release-version", version, "--source-commit", commit,
		"--github-repository", "owner/gateway-vpn", "--release-tag", "v1.2.3",
		"--gateway-ssh", "operator@127.0.0.1", "--gateway-port", "1",
		"--vps-ssh", "root@127.0.0.2", "--vps-port", "1",
		"--known-hosts", knownHostsPath, "--gateway-identity", identityPath, "--vps-identity", identityPath,
		"--lan-interface", "enp2s0", "--lan-address", "192.168.200.1/24",
		"--public-endpoint", "1.1.1.1:51821", "--admin-public-key", adminPublicKey,
		"--install-dependencies=false", "--readiness-attempts", "1", "--timeout", "10s", "--apply", "--json",
	})
	if code != 1 {
		t.Fatalf("closed-port signed Windows deploy smoke code=%d, want safe preflight failure 1", code)
	}
}

func TestDeployFailureGuidanceExplainsSSHIdentityWithoutSecrets(t *testing.T) {
	var output bytes.Buffer
	printDeployFailureGuidance(&output, deploy.Report{
		FailurePhase:    "GATEWAY_SSH_PREFLIGHT",
		DiagnosticCodes: []string{"GATEWAY_SSH_PREFLIGHT_FAILED", "IDENTITY_PERMISSIONS"},
	})
	message := output.String()
	if !strings.Contains(message, "Windows") || !strings.Contains(message, "SSH-ключ") || !strings.Contains(message, "установка не началась") {
		t.Fatalf("SSH identity guidance is incomplete: %q", message)
	}
	for _, forbidden := range []string{"private key contents", "-----BEGIN", "passphrase"} {
		if strings.Contains(message, forbidden) {
			t.Fatalf("SSH guidance exposed forbidden material %q: %q", forbidden, message)
		}
	}
}
