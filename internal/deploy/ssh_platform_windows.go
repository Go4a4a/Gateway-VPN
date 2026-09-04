//go:build windows

package deploy

import (
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
)

func platformSSHExecutable() string {
	return `C:\Windows\System32\OpenSSH\ssh.exe`
}

func platformSSHUnavailableError(executable string) error {
	return fmt.Errorf("Windows OpenSSH Client is missing or unsafe at %s; open PowerShell as Administrator, check it with Get-WindowsCapability -Online | Where-Object Name -like 'OpenSSH.Client*', and install it when State is NotPresent with Add-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0", executable)
}

func platformNullDevice() string { return "NUL" }

// OpenSSH control paths are length-bounded. A short prefix keeps the hashed
// Windows named-pipe/socket path valid even below a normal user TEMP path.
func platformControlDirectoryPrefix() string { return "gvs-" }

func securePlatformControlDirectory(directory string) error {
	current, err := user.Current()
	if err != nil || current.Uid == "" {
		return fmt.Errorf("resolve current Windows user SID: %w", err)
	}
	commands := [][]string{
		{directory, "/inheritance:r"},
		{directory, "/grant:r", "*" + current.Uid + ":(OI)(CI)(F)", "*S-1-5-18:(OI)(CI)(F)", "*S-1-5-32-544:(OI)(CI)(F)"},
	}
	for _, arguments := range commands {
		if output, commandErr := exec.Command(`C:\Windows\System32\icacls.exe`, arguments...).CombinedOutput(); commandErr != nil {
			return fmt.Errorf("restrict Windows SSH directory ACL: %w (%s)", commandErr, strings.TrimSpace(string(output)))
		}
	}
	return os.Chmod(directory, 0o700)
}

func platformSSHEnvironment() []string {
	values := make([]string, 0, 8)
	for _, name := range []string{"SystemRoot", "WINDIR", "SYSTEMDRIVE", "TEMP", "TMP", "USERPROFILE", "USERNAME", "USERDOMAIN", "HOMEDRIVE", "HOMEPATH", "APPDATA", "LOCALAPPDATA", "PROGRAMDATA"} {
		if value := os.Getenv(name); value != "" && !strings.ContainsRune(value, '\x00') {
			values = append(values, name+"="+value)
		}
	}
	values = append(values, `PATH=C:\Windows\System32\OpenSSH;C:\Windows\System32;C:\Windows`)
	return values
}

func platformSSHConfigPath(value string) string {
	return `"` + filepath.ToSlash(value) + `"`
}

func platformSSHRuntimeArguments(_ string) []string {
	return []string{
		"-G", "-F", platformNullDevice(),
		"-o", "BatchMode=yes",
		"-o", "StrictHostKeyChecking=yes",
		"-o", "IdentityAgent=none",
		"gateway-vpn-runtime.invalid",
	}
}

func validatePlatformSSHRuntime(effective string) error {
	for _, required := range []string{"batchmode yes", "stricthostkeychecking true", "identityagent none"} {
		if !strings.Contains(effective, required) {
			return fmt.Errorf("fixed system OpenSSH lacks required option %q", required)
		}
	}
	return nil
}
