package packaging_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	updatepkg "gateway-vpn/internal/update"
	"gateway-vpn/internal/vpsrelease"
)

func TestActualGatewayAndVPSSourceTreesFitStrictSignedReleaseContracts(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	repository := repositoryRoot(t)

	t.Run("gateway", func(t *testing.T) {
		root := t.TempDir()
		copyGatewayPackaging(t, filepath.Join(repository, "packaging"), filepath.Join(root, "packaging"))
		copyFile(t, filepath.Join(repository, "scripts", "install-gateway.sh"), filepath.Join(root, "scripts", "install-gateway.sh"), 0o755)
		copyFile(t, filepath.Join(repository, "scripts", "recover-gateway-install.sh"), filepath.Join(root, "scripts", "recover-gateway-install.sh"), 0o755)
		copyFile(t, filepath.Join(repository, "scripts", "recover-gateway-host-upgrade.sh"), filepath.Join(root, "scripts", "recover-gateway-host-upgrade.sh"), 0o755)
		copyFile(t, filepath.Join(repository, "scripts", "upgrade-gateway-host.sh"), filepath.Join(root, "scripts", "upgrade-gateway-host.sh"), 0o755)
		copyFile(t, filepath.Join(repository, "scripts", "run-gateway-uninstall-job.sh"), filepath.Join(root, "scripts", "run-gateway-uninstall-job.sh"), 0o755)
		copyFile(t, filepath.Join(repository, "scripts", "uninstall.sh"), filepath.Join(root, "scripts", "uninstall.sh"), 0o755)
		copyFile(t, filepath.Join(repository, "config.example.yaml"), filepath.Join(root, "config.example.yaml"), 0o644)
		writeSignedTreeFile(t, root, "bin/gateway-vpn", "gateway binary\n", 0o755)
		writeSignedTreeFile(t, root, "bin/gateway-vpnctl", "controller binary\n", 0o755)
		mihomo := []byte("mihomo binary\n")
		writeSignedTreeFile(t, root, "libexec/mihomo", string(mihomo), 0o755)
		writeSignedTreeFile(t, root, "manifest.sha256", strings.Repeat("0", 64)+"  placeholder\n", 0o644)
		writeSignedTreeFile(t, root, "share/supply-chain/sbom.spdx.json", "{}\n", 0o644)
		writeSignedTreeFile(t, root, "share/supply-chain/provenance.intoto.json", "{}\n", 0o644)
		digest := sha256.Sum256(mihomo)
		hostContract, err := updatepkg.ComputeHostContractSHA256(root)
		if err != nil {
			t.Fatal(err)
		}
		writeSignedTreeJSON(t, filepath.Join(root, "release.json"), updatepkg.Release{
			FormatVersion: updatepkg.ReleaseFormatVersion, GatewayVersion: "1.2.0", MihomoVersion: "v1.19.10",
			OS: "linux", Arch: "amd64", MihomoSHA256: hex.EncodeToString(digest[:]),
			DatabaseSchemaMinimum: 1, DatabaseSchemaMaximum: 11, ConfigSchemaGeneration: 1,
			HostContractSHA256: hostContract,
			GatewayAPIContract: updatepkg.GatewayAPIContract, MihomoAPIContract: updatepkg.MihomoAPIContract,
			BuildCommit: strings.Repeat("a", 40), BuildDate: "2026-08-25T00:00:00Z",
		})
		manifest, err := updatepkg.SignRelease(root, privateKey)
		if err != nil {
			t.Fatal(err)
		}
		verified, err := updatepkg.VerifyRelease(root, updatepkg.VerificationPolicy{
			PublicKey: publicKey, ExpectedOS: "linux", ExpectedArch: "amd64", InitialInstall: true,
			ConfigGeneration: 1, GatewayAPIContract: updatepkg.GatewayAPIContract, MihomoAPIContract: updatepkg.MihomoAPIContract,
		})
		if err != nil || len(verified.Manifest.Files) != len(manifest.Files) || len(manifest.Files) < 30 {
			t.Fatalf("actual Gateway signed tree files=%d verified=%v err=%v", len(manifest.Files), verified.Release.GatewayVersion, err)
		}
	})

	t.Run("vps", func(t *testing.T) {
		root := t.TempDir()
		copyTree(t, filepath.Join(repository, "packaging", "vps"), filepath.Join(root, "packaging", "vps"))
		for _, script := range []string{"install-vps.sh", "uninstall-vps.sh", "recover-vps-install.sh"} {
			copyFile(t, filepath.Join(repository, "scripts", script), filepath.Join(root, "scripts", script), 0o755)
		}
		writeSignedTreeFile(t, root, "bin/gateway-vpnctl", "controller binary\n", 0o755)
		writeSignedTreeFile(t, root, "bin/gateway-vpn-vps-agent", "VPS Agent binary\n", 0o755)
		writeSignedTreeFile(t, root, "manifest.sha256", strings.Repeat("0", 64)+"  placeholder\n", 0o644)
		writeSignedTreeFile(t, root, "share/supply-chain/sbom.spdx.json", "{}\n", 0o644)
		writeSignedTreeFile(t, root, "share/supply-chain/provenance.intoto.json", "{}\n", 0o644)
		writeSignedTreeJSON(t, filepath.Join(root, "release.json"), vpsrelease.Release{
			FormatVersion: vpsrelease.ReleaseFormatVersion, Role: "vps", Version: "1.2.0", OS: "linux", Arch: "amd64",
			SourceCommit: strings.Repeat("a", 40), BuildDate: "2026-08-25T00:00:00Z", SupportedProfiles: vpsrelease.SupportedProfiles(),
			InterfaceName: "wg-mgmt", ManagementSubnet: "10.80.0.0/24", ListenPort: 51821,
		})
		manifest, err := vpsrelease.SignRelease(root, privateKey)
		if err != nil {
			t.Fatal(err)
		}
		verified, err := vpsrelease.VerifyRelease(root, vpsrelease.VerificationPolicy{PublicKey: publicKey, ExpectedVersion: "1.2.0", ExpectedOS: "linux", ExpectedArch: "amd64", ExpectedProfile: "debian-12"})
		if err != nil || len(verified.Manifest.Files) != len(manifest.Files) || len(manifest.Files) < 12 {
			t.Fatalf("actual VPS signed tree files=%d verified=%v err=%v", len(manifest.Files), verified.Release.Version, err)
		}
	})
}

func copyTree(t *testing.T, source, destination string) {
	t.Helper()
	err := filepath.WalkDir(source, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative, err := filepath.Rel(source, path)
		if err != nil || relative == "." {
			return err
		}
		target := filepath.Join(destination, relative)
		if entry.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return os.ErrInvalid
		}
		copyFile(t, path, target, 0o644)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func copyGatewayPackaging(t *testing.T, source, destination string) {
	t.Helper()
	err := filepath.WalkDir(source, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == filepath.Join(source, "vps") && entry.IsDir() {
			return filepath.SkipDir
		}
		relative, err := filepath.Rel(source, path)
		if err != nil || relative == "." {
			return err
		}
		target := filepath.Join(destination, relative)
		if entry.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return os.ErrInvalid
		}
		copyFile(t, path, target, 0o644)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func copyFile(t *testing.T, source, destination string, mode os.FileMode) {
	t.Helper()
	content, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(destination), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(destination, content, mode); err != nil {
		t.Fatal(err)
	}
}

func writeSignedTreeFile(t *testing.T, root, relative, content string, mode os.FileMode) {
	t.Helper()
	filename := filepath.Join(root, filepath.FromSlash(relative))
	if err := os.MkdirAll(filepath.Dir(filename), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filename, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
}

func writeSignedTreeJSON(t *testing.T, filename string, value any) {
	t.Helper()
	content, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(filename), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filename, append(content, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
}
