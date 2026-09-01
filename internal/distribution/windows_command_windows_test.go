//go:build windows

package distribution

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestGeneratedWindowsDeployCommandParsesInSystemPowerShell(t *testing.T) {
	manifest := validManifest(t, nil)
	manifest.Artifacts = append(manifest.Artifacts,
		Artifact{Role: RoleDeploy, OS: "linux", Arch: "amd64", Filename: "gateway-vpn-deploy-1.2.0-linux-amd64", SHA256: strings.Repeat("4", 64), Bytes: 8192, MediaType: "application/octet-stream"},
		Artifact{Role: RoleDeploy, OS: "windows", Arch: "amd64", Filename: "gateway-vpn-deploy-1.2.0-windows-amd64.exe", SHA256: strings.Repeat("5", 64), Bytes: 8192, MediaType: "application/vnd.microsoft.portable-executable"},
	)
	SortArtifacts(manifest.Artifacts)
	command, err := WindowsDeployCommand(manifest, WindowsDeployCommandOptions{
		Repository: "owner/gateway-vpn", ReleaseTag: "v1.2.0",
		ManifestSHA256: strings.Repeat("6", 64), SignerKeySHA256: manifest.SignerKeySHA256,
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(command, "exit $code") || !strings.Contains(command, "$global:LASTEXITCODE=$code") {
		t.Fatal("generated PowerShell command can close the existing terminal or loses the launcher exit code")
	}
	filename := filepath.Join(t.TempDir(), "deploy-command.ps1")
	if err := os.WriteFile(filename, []byte(command+"\r\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	parser := "$tokens=$null; $errors=$null; [void][System.Management.Automation.Language.Parser]::ParseFile('" + strings.ReplaceAll(filename, "'", "''") + "',[ref]$tokens,[ref]$errors); if($errors.Count -ne 0){$errors | ForEach-Object { Write-Error $_.Message }; exit 1}"
	result, err := exec.Command(`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, "-NoProfile", "-NonInteractive", "-Command", parser).CombinedOutput()
	if err != nil {
		t.Fatalf("PowerShell parser rejected generated command: %v\n%s", err, result)
	}
}
