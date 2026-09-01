package main

import (
	"bytes"
	"encoding/base64"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	updatepkg "gateway-vpn/internal/update"
)

func TestChannelCommandsSignVerifyAndGeneratePinnedGatewayCommand(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("private-key CLI operations are intentionally Linux-only")
	}
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	privateKey := filepath.Join(directory, "release-private.pem")
	publicKey := filepath.Join(directory, "update-signing.pub")
	if _, err := updatepkg.WriteKeyPair(privateKey, publicKey); err != nil {
		t.Fatal(err)
	}
	version := "1.2.0"
	bootstrapPath := filepath.Join(directory, "gateway-vpn-bootstrap-1.2.0-linux-amd64")
	deployPath := filepath.Join(directory, "gateway-vpn-deploy-1.2.0-linux-amd64")
	windowsDeployPath := filepath.Join(directory, "gateway-vpn-deploy-1.2.0-windows-amd64.exe")
	gatewayPath := filepath.Join(directory, "gateway-vpn-gateway-1.2.0-linux-amd64.tar.gz")
	vpsPath := filepath.Join(directory, "gateway-vpn-vps-1.2.0-linux-amd64.tar.gz")
	if err := os.WriteFile(bootstrapPath, []byte("trusted bootstrap artifact"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(deployPath, []byte("trusted deploy artifact"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(windowsDeployPath, []byte("trusted Windows deploy artifact"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(gatewayPath, []byte("trusted gateway archive"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(vpsPath, []byte("trusted VPS archive"), 0o644); err != nil {
		t.Fatal(err)
	}
	commit := strings.Repeat("a", 40)
	if code := runChannelSign([]string{
		"--channel", "stable", "--release-version", version, "--source-commit", commit,
		"--generated-at", "2026-08-25T00:00:00Z", "--private-key", privateKey,
		"--output-dir", directory, "--artifact", "bootstrap=" + bootstrapPath,
		"--artifact", "deploy=" + deployPath, "--artifact", "deploy-windows=" + windowsDeployPath,
		"--artifact", "gateway=" + gatewayPath, "--artifact", "vps=" + vpsPath,
	}); code != 0 {
		t.Fatalf("runChannelSign() code = %d", code)
	}
	manifestPath := filepath.Join(directory, "channel-stable.json")
	signaturePath := filepath.Join(directory, "channel-stable.sig")
	if code := runChannelVerify([]string{
		"--manifest", manifestPath, "--signature", signaturePath, "--public-key", publicKey,
		"--channel", "stable", "--release-version", version, "--source-commit", commit,
		"--artifact", "bootstrap=" + bootstrapPath, "--artifact", "deploy=" + deployPath,
		"--artifact", "deploy-windows=" + windowsDeployPath, "--artifact", "gateway=" + gatewayPath, "--artifact", "vps=" + vpsPath,
	}); code != 0 {
		t.Fatalf("runChannelVerify() code = %d", code)
	}
	command, code := captureStdout(t, func() int {
		return runChannelInstallCommand([]string{
			"--manifest", manifestPath, "--signature", signaturePath, "--public-key", publicKey,
			"--channel", "stable", "--release-version", version, "--source-commit", commit,
			"--github-repository", "owner/gateway-vpn", "--release-tag", "v1.2.0",
			"--lan-interface", "enp2s0", "--lan-address", "192.168.200.1/24",
			"--boot-network-policy", "gateway-nonblocking", "--grub-policy", "automatic-hidden",
			"--install-dependencies", "--apply",
		})
	})
	if code != 0 || !strings.Contains(command, "sha256sum --binary") || !strings.Contains(command, "sudo ") || !strings.Contains(command, "--boot-network-policy gateway-nonblocking") || !strings.Contains(command, "--grub-policy automatic-hidden") || !strings.Contains(command, "--install-dependencies") || !strings.Contains(command, "--apply") {
		t.Fatalf("generated command code=%d output=%q", code, command)
	}
	if strings.Index(command, "test ") < 0 || strings.Index(command, "sudo ") < 0 || strings.Index(command, "test ") > strings.Index(command, "sudo ") {
		t.Fatal("generated command elevates before verifying the bootstrap hash")
	}
	interactiveCommand, code := captureStdout(t, func() int {
		return runChannelInstallCommand([]string{
			"--manifest", manifestPath, "--signature", signaturePath, "--public-key", publicKey,
			"--channel", "stable", "--release-version", version, "--source-commit", commit,
			"--github-repository", "owner/gateway-vpn", "--release-tag", "v1.2.0", "--interactive",
		})
	})
	if code != 0 || !strings.Contains(interactiveCommand, "--interactive") || strings.Contains(interactiveCommand, "--lan-interface") || strings.Contains(interactiveCommand, "--lan-address") || strings.Contains(interactiveCommand, "--apply") {
		t.Fatalf("universal command code=%d output=%q", code, interactiveCommand)
	}
	gatewayKey := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))
	adminKey := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{2}, 32))
	vpsCommand, code := captureStdout(t, func() int {
		return runChannelVPSInstallCommand([]string{
			"--manifest", manifestPath, "--signature", signaturePath, "--public-key", publicKey,
			"--channel", "stable", "--release-version", version, "--source-commit", commit,
			"--github-repository", "owner/gateway-vpn", "--release-tag", "v1.2.0",
			"--public-endpoint", "1.1.1.1:51821", "--gateway-public-key", gatewayKey,
			"--admin-public-key", adminKey, "--install-dependencies", "--allow-gateway-ssh", "--apply",
		})
	})
	if code != 0 || !strings.Contains(vpsCommand, "install-vps") || !strings.Contains(vpsCommand, "--install-dependencies") || !strings.Contains(vpsCommand, "--allow-gateway-ssh") || !strings.Contains(vpsCommand, "--apply") {
		t.Fatalf("generated VPS command code=%d output=%q", code, vpsCommand)
	}
	if strings.Index(vpsCommand, "test ") < 0 || strings.Index(vpsCommand, "sudo ") < 0 || strings.Index(vpsCommand, "test ") > strings.Index(vpsCommand, "sudo ") {
		t.Fatal("generated VPS command elevates before verifying the bootstrap hash")
	}
	deployCommand, code := captureStdout(t, func() int {
		return runChannelDeployCommand([]string{
			"--manifest", manifestPath, "--signature", signaturePath, "--public-key", publicKey,
			"--channel", "stable", "--release-version", version, "--source-commit", commit,
			"--github-repository", "owner/gateway-vpn", "--release-tag", "v1.2.0",
			"--gateway-ssh", "operator@gateway.example", "--vps-ssh", "root@vps.example",
			"--known-hosts", "/home/operator/.ssh/gateway-vpn-known_hosts",
			"--gateway-identity", "/home/operator/.ssh/gateway_ed25519",
			"--vps-identity", "/home/operator/.ssh/vps_ed25519",
			"--lan-interface", "enp2s0", "--lan-address", "192.168.200.1/24",
			"--public-endpoint", "1.1.1.1:51821", "--admin-config", "/home/operator/.config/gateway-vpn/admin.conf",
			"--enable-dhcp", "--allow-gateway-ssh",
		})
	})
	if code != 0 || !strings.Contains(deployCommand, "gateway-vpn-deploy-1.2.0-linux-amd64") || !strings.Contains(deployCommand, "--admin-config") || !strings.Contains(deployCommand, "--apply") || strings.Contains(deployCommand, "--admin-public-key") {
		t.Fatalf("generated deploy command code=%d output=%q", code, deployCommand)
	}
	if strings.Index(deployCommand, "test ") < 0 || strings.Index(deployCommand, "test ") > strings.LastIndex(deployCommand, "\"$tmp/deploy\"") {
		t.Fatal("generated deploy command executes its launcher before exact SHA-256 verification")
	}
	windowsCommand, code := captureStdout(t, func() int {
		return runChannelWindowsDeployCommand([]string{
			"--manifest", manifestPath, "--signature", signaturePath, "--public-key", publicKey,
			"--channel", "stable", "--release-version", version, "--source-commit", commit,
			"--github-repository", "owner/gateway-vpn", "--release-tag", "v1.2.0",
		})
	})
	if code != 0 || !strings.Contains(windowsCommand, "gateway-vpn-deploy-1.2.0-windows-amd64.exe") || !strings.Contains(windowsCommand, "Get-FileHash") || !strings.Contains(windowsCommand, "--interactive") {
		t.Fatalf("generated Windows deploy command code=%d output=%q", code, windowsCommand)
	}
	if strings.Index(windowsCommand, "Get-FileHash -LiteralPath $launcher") > strings.Index(windowsCommand, "& $launcher") {
		t.Fatal("generated Windows deploy command executes its launcher before exact SHA-256 verification")
	}
	if err := os.WriteFile(deployPath, []byte("modified deploy artifact"), 0o755); err != nil {
		t.Fatal(err)
	}
	if code := runChannelVerify([]string{
		"--manifest", manifestPath, "--signature", signaturePath, "--public-key", publicKey,
		"--channel", "stable", "--release-version", version, "--source-commit", commit,
		"--artifact", "bootstrap=" + bootstrapPath, "--artifact", "deploy=" + deployPath,
		"--artifact", "deploy-windows=" + windowsDeployPath, "--artifact", "gateway=" + gatewayPath, "--artifact", "vps=" + vpsPath,
	}); code != 1 {
		t.Fatalf("modified local artifact verify code = %d, want 1", code)
	}
}

func captureStdout(t *testing.T, function func() int) (string, int) {
	t.Helper()
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	original := os.Stdout
	os.Stdout = writer
	defer func() { os.Stdout = original }()
	code := function()
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	content, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
	return string(content), code
}
