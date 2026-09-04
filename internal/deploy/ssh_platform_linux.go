//go:build linux

package deploy

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

func platformSSHExecutable() string { return "/usr/bin/ssh" }

func platformSSHUnavailableError(executable string) error {
	return fmt.Errorf("fixed system OpenSSH client is missing or unsafe at %s", executable)
}

func platformNullDevice() string { return "/dev/null" }

func platformControlDirectoryPrefix() string { return "gateway-vpn-ssh-control-" }

func platformSSHEnvironment() []string {
	return []string{"PATH=/usr/bin:/bin", "LANG=C.UTF-8", "LC_ALL=C.UTF-8"}
}

func platformSSHConfigPath(value string) string {
	escaped := strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(value)
	return `"` + escaped + `"`
}

func platformSSHRuntimeArguments(controlPath string) []string {
	return []string{
		"-G", "-F", platformNullDevice(),
		"-o", "ControlMaster=auto",
		"-o", "ControlPersist=" + strconv.Itoa(defaultControlPersistSecond),
		"-o", "ControlPath=" + controlPath,
		"-o", "BatchMode=yes",
		"-o", "StrictHostKeyChecking=yes",
		"-o", "IdentityAgent=none",
		"gateway-vpn-runtime.invalid",
	}
}

func validatePlatformSSHRuntime(effective string) error {
	for _, required := range []string{
		"controlmaster auto",
		"controlpersist " + strconv.Itoa(defaultControlPersistSecond),
		"batchmode yes",
		"stricthostkeychecking true",
		"identityagent none",
	} {
		if !strings.Contains(effective, required) {
			return fmt.Errorf("fixed system OpenSSH lacks required option %q", required)
		}
	}
	if !strings.Contains(effective, "controlpath ") || strings.Contains(effective, "controlpath none") {
		return errors.New("fixed system OpenSSH disabled the persistent control path")
	}
	return nil
}

func newPlatformSSHBackend(*SSHExecutor) sshBackend { return nil }
