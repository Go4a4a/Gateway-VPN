package vpsrelease

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSignedVPSReleaseAuthenticatesRoleMetadataAndExactTree(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	root := writeValidVPSRelease(t)
	manifest, err := SignRelease(root, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := VerifyRelease(root, VerificationPolicy{
		PublicKey: publicKey, ExpectedVersion: "1.2.0", ExpectedOS: "linux", ExpectedArch: "amd64", ExpectedProfile: "ubuntu-20.04",
	})
	if err != nil {
		t.Fatal(err)
	}
	if verified.Release.Role != "vps" || verified.Release.ListenPort != 51821 || verified.Fingerprint != manifest.SignerKeySHA256 || len(verified.Manifest.Files) < 8 {
		t.Fatalf("verified VPS release = %+v", verified)
	}
	if _, err := VerifyRelease(root, VerificationPolicy{PublicKey: publicKey, ExpectedProfile: "ubuntu-18.04"}); err == nil {
		t.Fatal("unsupported VPS profile was accepted")
	}
	if err := os.WriteFile(filepath.Join(root, "packaging", "vps", "sysctl.d", "90-gateway-vpn-vps.conf"), []byte("tampered\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyRelease(root, VerificationPolicy{PublicKey: publicKey}); err == nil {
		t.Fatal("tampered signed VPS tree was accepted")
	}
}

func TestVPSReleaseRejectsWrongRoleProfilesUnknownMetadataAndMissingInstaller(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	root := writeValidVPSRelease(t)
	releasePath := filepath.Join(root, ReleaseFilename)
	content, err := os.ReadFile(releasePath)
	if err != nil {
		t.Fatal(err)
	}
	var release Release
	if err := json.Unmarshal(content, &release); err != nil {
		t.Fatal(err)
	}
	release.Role = "gateway"
	writeJSON(t, releasePath, release)
	if _, err := SignRelease(root, privateKey); err == nil {
		t.Fatal("wrong VPS role metadata was signed")
	}

	root = writeValidVPSRelease(t)
	content, _ = os.ReadFile(filepath.Join(root, ReleaseFilename))
	content = append(content[:len(content)-2], []byte(",\n  \"unknown\": true\n}\n")...)
	if err := os.WriteFile(filepath.Join(root, ReleaseFilename), content, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := SignRelease(root, privateKey); err == nil {
		t.Fatal("unknown VPS release metadata was signed")
	}

	root = writeValidVPSRelease(t)
	if err := os.Remove(filepath.Join(root, "scripts", "install-vps.sh")); err != nil {
		t.Fatal(err)
	}
	if _, err := SignRelease(root, privateKey); err == nil {
		t.Fatal("VPS release without its installer was signed")
	}
}

func writeValidVPSRelease(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	files := map[string]string{
		"bin/gateway-vpnctl":                                                "controller\n",
		"bin/gateway-vpn-vps-agent":                                         "agent\n",
		"scripts/install-vps.sh":                                            "#!/usr/bin/env bash\nexit 0\n",
		"scripts/uninstall-vps.sh":                                          "#!/usr/bin/env bash\nexit 0\n",
		"scripts/recover-vps-install.sh":                                    "#!/usr/bin/env bash\nexit 0\n",
		"packaging/vps/nftables/gateway-vpn-vps.nft.in":                     "table inet gateway_vpn_vps {}\n",
		"packaging/vps/sysctl.d/90-gateway-vpn-vps.conf":                    "net.ipv4.ip_forward=1\n",
		"packaging/vps/systemd/gateway-vpn-vps-firewall.service":            "[Service]\nType=oneshot\n",
		"packaging/vps/systemd/gateway-vpn-vps-install-recovery.service":    "[Service]\nType=oneshot\n",
		"packaging/vps/systemd/gateway-vpn-vps-agent.service":               "[Service]\nType=simple\n",
		"packaging/vps/systemd/gateway-vpn-vps-restore.service":             "[Service]\nType=oneshot\n",
		"packaging/vps/systemd/gateway-vpn-vps-restore.path":                "[Path]\nPathExists=/var/lib/gateway-vpn-vps/agent/restore.trigger\n",
		"packaging/vps/systemd/gateway-vpn-vps-restore-recovery.service":    "[Service]\nType=oneshot\n",
		"packaging/vps/systemd/gateway-vpn-vps-fabric.service":              "[Service]\nType=oneshot\n",
		"packaging/vps/systemd/gateway-vpn-vps-fabric.path":                 "[Path]\nPathExists=/var/lib/gateway-vpn-vps/agent/fabric.trigger\n",
		"packaging/vps/systemd/gateway-vpn-vps-fabric-recovery.service":     "[Service]\nType=oneshot\n",
		"packaging/vps/systemd/gateway-vpn-vps-fabric-watchdog.service":     "[Service]\nType=oneshot\n",
		"packaging/vps/systemd/gateway-vpn-vps-fabric-watchdog.timer":       "[Timer]\nOnUnitActiveSec=60s\n",
		"packaging/vps/config/config.yaml":                                  "version: 1\n",
		"packaging/vps/systemd/wg-quick@wg-mgmt.service.d/gateway-vpn.conf": "[Unit]\nAfter=gateway-vpn-vps-firewall.service\n",
		LegacyHashFilename:                          strings.Repeat("0", 64) + "  placeholder\n",
		"share/supply-chain/sbom.spdx.json":         "{}\n",
		"share/supply-chain/provenance.intoto.json": "{}\n",
	}
	for relative, content := range files {
		path := filepath.Join(root, filepath.FromSlash(relative))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		mode := os.FileMode(0o644)
		if strings.HasPrefix(relative, "bin/") || strings.HasPrefix(relative, "scripts/") {
			mode = 0o755
		}
		if err := os.WriteFile(path, []byte(content), mode); err != nil {
			t.Fatal(err)
		}
	}
	writeJSON(t, filepath.Join(root, ReleaseFilename), Release{
		FormatVersion: ReleaseFormatVersion, Role: "vps", Version: "1.2.0", OS: "linux", Arch: "amd64",
		SourceCommit: strings.Repeat("a", 40), BuildDate: "2026-08-25T00:00:00Z", SupportedProfiles: SupportedProfiles(),
		InterfaceName: "wg-mgmt", ManagementSubnet: "10.80.0.0/24", ListenPort: 51821,
	})
	return root
}

func writeJSON(t *testing.T, filename string, value any) {
	t.Helper()
	content, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filename, append(content, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
}
