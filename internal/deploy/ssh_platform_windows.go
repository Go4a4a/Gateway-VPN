//go:build windows

package deploy

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func platformSSHExecutable() string {
	return `C:\Windows\System32\OpenSSH\ssh.exe`
}

func platformNullDevice() string { return "NUL" }

// OpenSSH control paths are length-bounded. A short prefix keeps the hashed
// Windows named-pipe/socket path valid even below a normal user TEMP path.
func platformControlDirectoryPrefix() string { return "gvs-" }

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
