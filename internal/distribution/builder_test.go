package distribution

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	updatepkg "gateway-vpn/internal/update"
)

func TestArtifactFromFileAndGatewayInstallCommandPinCompleteTrustChain(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	version := "1.2.0"
	bootstrapPath := filepath.Join(directory, expectedArtifactFilename(RoleBootstrap, version))
	deployPath := filepath.Join(directory, expectedArtifactFilename(RoleDeploy, version))
	windowsDeployPath := filepath.Join(directory, expectedArtifactFilenameForPlatform(RoleDeploy, version, "windows", "amd64"))
	gatewayPath := filepath.Join(directory, expectedArtifactFilename(RoleGateway, version))
	vpsPath := filepath.Join(directory, expectedArtifactFilename(RoleVPS, version))
	if err := os.WriteFile(bootstrapPath, []byte("bootstrap-v1"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(deployPath, []byte("deploy-v1"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(windowsDeployPath, []byte("deploy-windows-v1"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(gatewayPath, []byte("gateway-release-v1"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(vpsPath, []byte("vps-release-v1"), 0o644); err != nil {
		t.Fatal(err)
	}
	bootstrap, err := ArtifactFromFile(RoleBootstrap, "linux", "amd64", bootstrapPath, version)
	if err != nil {
		t.Fatal(err)
	}
	deploy, err := ArtifactFromFile(RoleDeploy, "linux", "amd64", deployPath, version)
	if err != nil {
		t.Fatal(err)
	}
	windowsDeploy, err := ArtifactFromFile(RoleDeploy, "windows", "amd64", windowsDeployPath, version)
	if err != nil {
		t.Fatal(err)
	}
	gateway, err := ArtifactFromFile(RoleGateway, "linux", "amd64", gatewayPath, version)
	if err != nil {
		t.Fatal(err)
	}
	vps, err := ArtifactFromFile(RoleVPS, "linux", "amd64", vpsPath, version)
	if err != nil {
		t.Fatal(err)
	}
	manifest := Manifest{
		FormatVersion: ChannelFormatVersion, Channel: "stable", ReleaseVersion: version,
		GeneratedAt: "2026-08-25T00:00:00Z", SourceCommit: strings.Repeat("a", 40),
		Artifacts: []Artifact{bootstrap, deploy, windowsDeploy, gateway, vps},
	}
	SortArtifacts(manifest.Artifacts)
	content, signature, err := SignManifest(manifest, privateKey)
	if err != nil || len(signature) == 0 {
		t.Fatal(err)
	}
	manifest, err = VerifyManifest(content, signature, publicKey, VerificationPolicy{ExpectedChannel: "stable", ExpectedVersion: version})
	if err != nil {
		t.Fatal(err)
	}
	manifestDigest, _ := ManifestSHA256(content)
	fingerprint, _ := updatepkg.PublicKeyFingerprint(publicKey)
	command, err := GatewayInstallCommand(manifest, GatewayInstallCommandOptions{
		Repository: "owner/gateway-vpn", ReleaseTag: "v1.2.0", ManifestSHA256: manifestDigest,
		SignerKeySHA256: fingerprint, LANInterface: "enp2s0", LANAddress: "192.168.200.1/24",
		InstallDependencies: true, EnableDHCP: true, DisableSSH: true, Apply: true,
		BootNetworkPolicy: "gateway-nonblocking", GRUBPolicy: "automatic-hidden",
		NonInteractiveRoot: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{bootstrap.SHA256, manifestDigest, fingerprint, "channel-stable.json", "channel-stable.sig", "update-signing.pub", "--source-commit " + manifest.SourceCommit, "--install-dependencies", "--enable-dhcp", "--disable-ssh", "--boot-network-policy gateway-nonblocking", "--grub-policy automatic-hidden", "--apply"} {
		if !strings.Contains(command, required) {
			t.Errorf("generated command missing %q", required)
		}
	}
	if strings.Contains(command, "curl |") || !strings.Contains(command, "command -v wget") || !strings.Contains(command, "run_as_root") || strings.Index(command, "test ") > strings.LastIndex(command, "run_as_root \"$tmp\"") {
		t.Fatal("generated command can execute the bootstrap before its exact hash matches")
	}
	if !strings.Contains(command, "sudo -n") {
		t.Fatal("non-interactive Gateway command can prompt for sudo")
	}
	if !strings.HasPrefix(command, "bash --norc -ceu ") || strings.HasPrefix(command, "bash -ceu ") {
		t.Fatal("Gateway command is vulnerable to SSH remote bashrc/nounset failures")
	}
	interactiveCommand, err := GatewayInstallCommand(manifest, GatewayInstallCommandOptions{
		Repository: "owner/gateway-vpn", ReleaseTag: "v1.2.0", ManifestSHA256: manifestDigest,
		SignerKeySHA256: fingerprint, Interactive: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(interactiveCommand, "--interactive") || !strings.Contains(interactiveCommand, "--management-peer") || !strings.Contains(interactiveCommand, "SSH_CONNECTION") || strings.Contains(interactiveCommand, "--lan-interface") || strings.Contains(interactiveCommand, "--lan-address") || strings.Contains(interactiveCommand, "sudo -n") {
		t.Fatalf("universal interactive command contains target-specific or non-interactive policy: %s", interactiveCommand)
	}
	if _, err := GatewayInstallCommand(manifest, GatewayInstallCommandOptions{
		Repository: "owner/gateway-vpn", ReleaseTag: "v1.2.0", ManifestSHA256: manifestDigest,
		SignerKeySHA256: fingerprint, Interactive: true, LANInterface: "enp2s0",
	}); err == nil {
		t.Fatal("interactive Gateway command accepted a build-time hardware interface")
	}
	if _, err := GatewayInstallCommand(manifest, GatewayInstallCommandOptions{
		Repository: "../bad/repo", ReleaseTag: "v1.2.0", ManifestSHA256: manifestDigest,
		SignerKeySHA256: fingerprint, LANInterface: "enp2s0", LANAddress: "192.168.200.1/24",
	}); err == nil {
		t.Fatal("unsafe GitHub repository was accepted")
	}
	if _, err := GatewayInstallCommand(manifest, GatewayInstallCommandOptions{
		Repository: "owner/gateway-vpn", ReleaseTag: "v1.2.0", ManifestSHA256: manifestDigest,
		SignerKeySHA256: fingerprint, LANInterface: "enp2s0", LANAddress: "8.8.8.8/24",
	}); err == nil {
		t.Fatal("public Gateway LAN was accepted")
	}
	gatewayKey := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))
	adminKey := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{2}, 32))
	vpsCommand, err := VPSInstallCommand(manifest, VPSInstallCommandOptions{
		Repository: "owner/gateway-vpn", ReleaseTag: "v1.2.0", ManifestSHA256: manifestDigest,
		SignerKeySHA256: fingerprint, PublicEndpoint: "1.1.1.1:51821",
		GatewayPublicKey: gatewayKey, AdminPublicKey: adminKey, InstallDependencies: true, AllowGatewaySSH: true, Apply: true,
		NonInteractiveRoot: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{bootstrap.SHA256, manifestDigest, fingerprint, "install-vps", "--public-endpoint 1.1.1.1:51821", gatewayKey, adminKey, "--install-dependencies", "--allow-gateway-ssh", "--apply"} {
		if !strings.Contains(vpsCommand, required) {
			t.Errorf("generated VPS command missing %q", required)
		}
	}
	if !strings.Contains(vpsCommand, "command -v wget") || !strings.Contains(vpsCommand, "run_as_root") || strings.Index(vpsCommand, "test ") > strings.LastIndex(vpsCommand, "run_as_root \"$tmp\"") {
		t.Fatal("generated VPS command elevates before verifying the bootstrap hash")
	}
	if !strings.Contains(vpsCommand, "sudo -n") {
		t.Fatal("non-interactive VPS command can prompt for sudo")
	}
	if !strings.HasPrefix(vpsCommand, "bash --norc -ceu ") || strings.HasPrefix(vpsCommand, "bash -ceu ") {
		t.Fatal("VPS command is vulnerable to SSH remote bashrc/nounset failures")
	}
	deployCommand, err := DeployCommand(manifest, DeployCommandOptions{
		Repository: "owner/gateway-vpn", ReleaseTag: "v1.2.0", ManifestSHA256: manifestDigest,
		SignerKeySHA256: fingerprint, GatewaySSH: "operator@gateway.example", GatewayPort: 22,
		VPSSSH: "root@vps.example", VPSPort: 2222, KnownHosts: "/home/operator/.ssh/known_hosts",
		GatewayIdentity: "/home/operator/.ssh/gateway", VPSIdentity: "/home/operator/.ssh/vps",
		LANInterface: "enp2s0", LANAddress: "192.168.200.1/24", EnableDHCP: true,
		PublicEndpoint: "1.1.1.1:51821", AdminPublicKey: adminKey,
		InstallDependencies: true, AllowGatewaySSH: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{deploy.SHA256, manifestDigest, fingerprint, "gateway-vpn-deploy-1.2.0-linux-amd64", "--gateway-ssh", "operator@gateway.example", "--vps-port", "2222", "--enable-dhcp", "--allow-gateway-ssh", "--apply"} {
		if !strings.Contains(deployCommand, required) {
			t.Errorf("generated deploy command missing %q", required)
		}
	}
	if strings.Contains(deployCommand, "private-key") || strings.Index(deployCommand, "test ") > strings.LastIndex(deployCommand, "\"$tmp/deploy\"") {
		t.Fatal("generated deploy command leaks a private-key argument or executes before exact hash verification")
	}
	if !strings.HasPrefix(deployCommand, "bash --norc -ceu ") || strings.HasPrefix(deployCommand, "bash -ceu ") {
		t.Fatal("deploy command is vulnerable to administrator bashrc/nounset failures")
	}
	if _, err := DeployCommand(manifest, DeployCommandOptions{
		Repository: "owner/gateway-vpn", ReleaseTag: "v1.2.0", ManifestSHA256: manifestDigest,
		SignerKeySHA256: fingerprint, GatewaySSH: "operator@same.example", GatewayPort: 22,
		VPSSSH: "root@same.example", VPSPort: 2222, KnownHosts: "/home/operator/.ssh/known_hosts",
		LANInterface: "enp2s0", LANAddress: "192.168.200.1/24",
		PublicEndpoint: "1.1.1.1:51821", AdminPublicKey: adminKey, InstallDependencies: true,
	}); err == nil {
		t.Fatal("deploy command accepted the same SSH host for both roles")
	}
	windowsCommand, err := WindowsDeployCommand(manifest, WindowsDeployCommandOptions{
		Repository: "owner/gateway-vpn", ReleaseTag: "v1.2.0",
		ManifestSHA256: manifestDigest, SignerKeySHA256: fingerprint,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		windowsDeploy.SHA256, manifestDigest, fingerprint,
		"gateway-vpn-deploy-1.2.0-windows-amd64.exe", "Get-FileHash",
		"--interactive", "$ErrorActionPreference='Stop'", "Remove-Item -LiteralPath $root",
		"$global:LASTEXITCODE=$code", "This PowerShell window remains open for diagnostics",
		"[Net.ServicePointManager]::SecurityProtocol=$previousSecurityProtocol",
	} {
		if !strings.Contains(windowsCommand, required) {
			t.Errorf("Windows deploy command missing %q", required)
		}
	}
	if strings.Contains(strings.ToLower(windowsCommand), "password") || strings.Contains(strings.ToLower(windowsCommand), "private-key") || strings.Index(windowsCommand, "Get-FileHash -LiteralPath $launcher") > strings.Index(windowsCommand, "& $launcher") {
		t.Fatal("Windows deploy command leaks credentials or executes before exact SHA-256 verification")
	}
	if strings.Contains(windowsCommand, "exit $code") || !strings.HasPrefix(windowsCommand, "& { ") {
		t.Fatal("Windows deploy command can close or pollute the administrator PowerShell session")
	}
	adminConfigCommand, err := DeployCommand(manifest, DeployCommandOptions{
		Repository: "owner/gateway-vpn", ReleaseTag: "v1.2.0", ManifestSHA256: manifestDigest,
		SignerKeySHA256: fingerprint, GatewaySSH: "operator@gateway.example", GatewayPort: 22,
		VPSSSH: "root@vps.example", VPSPort: 22, KnownHosts: "/home/operator/.ssh/known_hosts",
		LANInterface: "enp2s0", LANAddress: "192.168.200.1/24", PublicEndpoint: "1.1.1.1:51821",
		AdminConfig: "/home/operator/.config/gateway-vpn/admin.conf", InstallDependencies: true,
	})
	if err != nil || !strings.Contains(adminConfigCommand, "--admin-config") || strings.Contains(adminConfigCommand, "--admin-public-key") {
		t.Fatalf("local administrator config deploy command = %v err=%v", strings.Contains(adminConfigCommand, "--admin-config"), err)
	}
}

func TestArtifactFromFileRejectsWrongRoleFilename(t *testing.T) {
	filename := filepath.Join(t.TempDir(), "release-1.2.0.tar.gz")
	if err := os.WriteFile(filename, []byte("not a role artifact"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ArtifactFromFile(RoleGateway, "linux", "amd64", filename, "1.2.0"); err == nil {
		t.Fatal("ambiguous artifact filename was accepted")
	}
}
