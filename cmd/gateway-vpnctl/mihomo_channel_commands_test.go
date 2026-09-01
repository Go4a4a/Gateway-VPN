package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	updatepkg "gateway-vpn/internal/update"
)

func TestWriteMihomoChannelPairIsExclusiveAndCleansPartialOutput(t *testing.T) {
	root := t.TempDir()
	manifestPath, signaturePath, err := writeMihomoChannelPair(root, "stable", []byte("manifest\n"), []byte("signature\n"))
	if err != nil {
		t.Fatal(err)
	}
	manifest, manifestErr := os.ReadFile(manifestPath)
	signature, signatureErr := os.ReadFile(signaturePath)
	if manifestErr != nil || signatureErr != nil || string(manifest) != "manifest\n" || string(signature) != "signature\n" {
		t.Fatalf("written Mihomo channel pair = %q,%q errors=%v,%v", manifest, signature, manifestErr, signatureErr)
	}
	if _, _, err := writeMihomoChannelPair(root, "stable", []byte("replacement"), []byte("replacement")); err == nil {
		t.Fatal("existing Mihomo channel output was replaced")
	}
	manifest, _ = os.ReadFile(manifestPath)
	if string(manifest) != "manifest\n" {
		t.Fatal("exclusive output refusal modified the existing manifest")
	}
}

func TestWriteMihomoChannelPairRejectsSymlinkOutputDirectory(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if _, _, err := writeMihomoChannelPair(link, "stable", []byte("manifest"), []byte("signature")); err == nil {
		t.Fatal("symlink Mihomo channel output directory was accepted")
	}
}

func TestVerifiedMihomoMaintenanceInputsBindArchiveToExactRelease(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	releaseRoot := filepath.Join(t.TempDir(), "release")
	otherRoot := filepath.Join(t.TempDir(), "other")
	createSignedMihomoCommandRelease(t, releaseRoot, privateKey, strings.Repeat("a", 40))
	createSignedMihomoCommandRelease(t, otherRoot, privateKey, strings.Repeat("b", 40))
	archivePath := filepath.Join(t.TempDir(), "gateway-vpn-gateway-1.2.1-linux-amd64.tar.gz")
	if err := os.WriteFile(archivePath, archiveMihomoCommandRelease(t, otherRoot), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := verifiedMihomoMaintenanceInputs(releaseRoot, archivePath, publicKey); err == nil {
		t.Fatal("archive from a different signed release was accepted")
	}
	release, artifact, err := verifiedMihomoMaintenanceInputs(otherRoot, archivePath, publicKey)
	if err != nil || release.BuildCommit != strings.Repeat("b", 40) || artifact.Filename != filepath.Base(archivePath) {
		t.Fatalf("exact signed release/archive pair = %+v,%+v,%v", release, artifact, err)
	}
}

func createSignedMihomoCommandRelease(t *testing.T, root string, privateKey ed25519.PrivateKey, commit string) {
	t.Helper()
	files := map[string][]byte{
		"bin/gateway-vpn":            []byte("gateway-vpn candidate"),
		"bin/gateway-vpnctl":         []byte("gateway-vpnctl candidate"),
		"libexec/mihomo":             []byte("mihomo candidate"),
		updatepkg.LegacyHashFilename: []byte(strings.Repeat("a", 64) + "  bin/gateway-vpn\n"),
	}
	for _, name := range updatepkg.RequiredHostContractFiles() {
		files[name] = []byte("signed host lifecycle fixture\n")
	}
	for name, content := range files {
		filename := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(filename), 0o755); err != nil {
			t.Fatal(err)
		}
		mode := os.FileMode(0o644)
		if strings.HasPrefix(name, "bin/") || name == "libexec/mihomo" || strings.HasPrefix(name, "scripts/") {
			mode = 0o755
		}
		if err := os.WriteFile(filename, content, mode); err != nil {
			t.Fatal(err)
		}
	}
	mihomoDigest := sha256.Sum256(files["libexec/mihomo"])
	hostContract, err := updatepkg.ComputeHostContractSHA256(root)
	if err != nil {
		t.Fatal(err)
	}
	release := updatepkg.Release{
		FormatVersion: updatepkg.ReleaseFormatVersion, GatewayVersion: "1.2.1", MihomoVersion: "v1.20.0",
		OS: "linux", Arch: "amd64", MihomoSHA256: hex.EncodeToString(mihomoDigest[:]),
		DatabaseSchemaMinimum: 1, DatabaseSchemaMaximum: 64, ConfigSchemaGeneration: 1,
		HostContractSHA256: hostContract, GatewayAPIContract: updatepkg.GatewayAPIContract,
		MihomoAPIContract: updatepkg.MihomoAPIContract, BuildCommit: commit, BuildDate: "2026-09-01T01:02:03Z",
	}
	content, err := json.MarshalIndent(release, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, updatepkg.ReleaseFilename), append(content, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := updatepkg.SignRelease(root, privateKey); err != nil {
		t.Fatal(err)
	}
}

func archiveMihomoCommandRelease(t *testing.T, root string) []byte {
	t.Helper()
	var names []string
	if err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.Mode().IsRegular() {
			relative, err := filepath.Rel(root, path)
			if err != nil {
				return err
			}
			names = append(names, filepath.ToSlash(relative))
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	sort.Strings(names)
	var output bytes.Buffer
	gzipWriter := gzip.NewWriter(&output)
	gzipWriter.Header.ModTime = time.Unix(0, 0).UTC()
	tarWriter := tar.NewWriter(gzipWriter)
	for _, name := range names {
		filename := filepath.Join(root, filepath.FromSlash(name))
		content, err := os.ReadFile(filename)
		if err != nil {
			t.Fatal(err)
		}
		info, err := os.Stat(filename)
		if err != nil {
			t.Fatal(err)
		}
		header := &tar.Header{Name: name, Mode: int64(info.Mode().Perm()), Size: int64(len(content)), Typeflag: tar.TypeReg, ModTime: time.Unix(0, 0).UTC()}
		if err := tarWriter.WriteHeader(header); err != nil {
			t.Fatal(err)
		}
		if _, err := tarWriter.Write(content); err != nil {
			t.Fatal(err)
		}
	}
	if err := tarWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gzipWriter.Close(); err != nil {
		t.Fatal(err)
	}
	return output.Bytes()
}
