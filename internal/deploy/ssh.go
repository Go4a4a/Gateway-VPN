// Package deploy implements the administrative two-host Gateway VPN deploy
// workflow. It never transports private key material.
package deploy

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
)

const (
	DefaultSSHExecutable = "/usr/bin/ssh"
	DefaultOutputLimit   = 256 * 1024
)

var sshUserPattern = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)

type Host struct {
	Destination string
	Port        int
	Identity    string
	KnownHosts  string
}

type RemoteResult struct {
	Stdout   []byte
	Stderr   []byte
	ExitCode int
}

type RemoteExecutor interface {
	Run(context.Context, Host, string) (RemoteResult, error)
}

type SSHExecutor struct {
	Executable  string
	OutputLimit int
}

type RemoteCommandError struct {
	ExitCode int
	Cause    string
}

func (err RemoteCommandError) Error() string {
	if err.ExitCode >= 0 {
		return fmt.Sprintf("remote command failed with exit code %d", err.ExitCode)
	}
	return "remote command failed: " + err.Cause
}

func ValidateHost(host Host) error {
	if !validSSHDestination(host.Destination) || host.Port < 1 || host.Port > 65535 {
		return errors.New("SSH destination or port is invalid")
	}
	if err := validateSSHFile(host.KnownHosts, true); err != nil {
		return errors.New("known-hosts file is unsafe or unavailable")
	}
	if host.Identity != "" {
		if err := validateSSHFile(host.Identity, false); err != nil {
			return errors.New("SSH identity file is unsafe or unavailable")
		}
	}
	return nil
}

func (executor SSHExecutor) Run(ctx context.Context, host Host, remoteCommand string) (RemoteResult, error) {
	if executor.Executable == "" {
		executor.Executable = DefaultSSHExecutable
	}
	if executor.OutputLimit == 0 {
		executor.OutputLimit = DefaultOutputLimit
	}
	if executor.Executable != DefaultSSHExecutable || executor.OutputLimit < 4096 || executor.OutputLimit > 4*1024*1024 {
		return RemoteResult{}, errors.New("fixed SSH executor and bounded output are required")
	}
	if err := ValidateHost(host); err != nil {
		return RemoteResult{}, err
	}
	if remoteCommand == "" || len(remoteCommand) > 128*1024 || strings.ContainsAny(remoteCommand, "\x00\r\n") {
		return RemoteResult{}, errors.New("bounded single-line remote command is required")
	}
	arguments := []string{
		"-F", "/dev/null", "-T",
		"-o", "BatchMode=yes",
		"-o", "PasswordAuthentication=no",
		"-o", "KbdInteractiveAuthentication=no",
		"-o", "StrictHostKeyChecking=yes",
		"-o", "UserKnownHostsFile=" + host.KnownHosts,
		"-o", "GlobalKnownHostsFile=/dev/null",
		"-o", "RequestTTY=no",
		"-o", "ConnectTimeout=15",
		"-o", "ServerAliveInterval=15",
		"-o", "ServerAliveCountMax=2",
		"-p", strconv.Itoa(host.Port),
	}
	if host.Identity != "" {
		arguments = append(arguments, "-o", "IdentitiesOnly=yes", "-i", host.Identity)
	}
	arguments = append(arguments, "--", host.Destination, remoteCommand)
	command := exec.CommandContext(ctx, executor.Executable, arguments...)
	command.Env = []string{"PATH=/usr/bin:/bin", "LANG=C.UTF-8", "LC_ALL=C.UTF-8"}
	var stdout, stderr boundedBuffer
	stdout.maximum = executor.OutputLimit
	stderr.maximum = executor.OutputLimit
	command.Stdout = &stdout
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		result := RemoteResult{Stdout: stdout.Bytes(), Stderr: stderr.Bytes(), ExitCode: -1}
		if stdout.overflow || stderr.overflow {
			return result, RemoteCommandError{ExitCode: -1, Cause: "bounded output limit exceeded"}
		}
		var exitError *exec.ExitError
		if errors.As(err, &exitError) {
			result.ExitCode = exitError.ExitCode()
			return result, RemoteCommandError{ExitCode: result.ExitCode}
		}
		if ctx.Err() != nil {
			return result, ctx.Err()
		}
		return result, RemoteCommandError{ExitCode: -1, Cause: "SSH execution failed"}
	}
	if stdout.overflow || stderr.overflow {
		return RemoteResult{Stdout: stdout.Bytes(), Stderr: stderr.Bytes(), ExitCode: -1}, RemoteCommandError{ExitCode: -1, Cause: "bounded output limit exceeded"}
	}
	return RemoteResult{Stdout: stdout.Bytes(), Stderr: stderr.Bytes(), ExitCode: 0}, nil
}

type boundedBuffer struct {
	buffer   bytes.Buffer
	maximum  int
	overflow bool
}

var errRemoteOutputLimit = errors.New("remote output limit exceeded")

func (buffer *boundedBuffer) Write(content []byte) (int, error) {
	remaining := buffer.maximum - buffer.buffer.Len()
	if remaining <= 0 {
		buffer.overflow = true
		return 0, errRemoteOutputLimit
	}
	if len(content) > remaining {
		_, _ = buffer.buffer.Write(content[:remaining])
		buffer.overflow = true
		return remaining, errRemoteOutputLimit
	}
	_, _ = buffer.buffer.Write(content)
	return len(content), nil
}

func (buffer *boundedBuffer) Bytes() []byte {
	return append([]byte(nil), buffer.buffer.Bytes()...)
}

func validSSHDestination(value string) bool {
	if value == "" || len(value) > 255 || strings.HasPrefix(value, "-") || strings.ContainsAny(value, " \t\r\n/\\:[]") {
		return false
	}
	user, host, hasUser := strings.Cut(value, "@")
	if hasUser {
		if !sshUserPattern.MatchString(user) || strings.Contains(host, "@") {
			return false
		}
	} else {
		host = user
	}
	if address := net.ParseIP(host); address != nil {
		return address.To4() != nil && !address.IsUnspecified() && !address.IsMulticast()
	}
	return validDNSName(host)
}

func validDNSName(value string) bool {
	value = strings.TrimSuffix(strings.ToLower(value), ".")
	if value == "" || len(value) > 253 {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, char := range label {
			if (char >= 'a' && char <= 'z') || (char >= '0' && char <= '9') || char == '-' {
				continue
			}
			return false
		}
	}
	return true
}

func validateSSHFile(filename string, allowEmpty bool) error {
	if !filepath.IsAbs(filename) || strings.ContainsAny(filename, " \t\r\n\x00") {
		return errors.New("absolute SSH file path is required")
	}
	info, err := os.Lstat(filename)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() > 4*1024*1024 || (!allowEmpty && info.Size() == 0) {
		return errors.New("SSH file must be a bounded regular non-symlink file")
	}
	if !allowEmpty && runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return errors.New("SSH identity file permissions are too broad")
	}
	return nil
}
