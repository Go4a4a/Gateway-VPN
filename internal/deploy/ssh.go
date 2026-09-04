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
	"time"
)

const (
	DefaultOutputLimit          = 256 * 1024
	defaultControlPersistSecond = 45 * 60
)

// DefaultSSHExecutable is deliberately fixed per supported administrative
// platform. In particular, Windows never searches PATH for an alternate ssh.
var DefaultSSHExecutable = platformSSHExecutable()

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
	Executable       string
	OutputLimit      int
	controlDirectory string
	backend          sshBackend
}

type sshBackend interface {
	Run(context.Context, Host, string) (RemoteResult, error)
	Close(context.Context, ...Host) error
}

type RemoteCommandError struct {
	ExitCode       int
	Cause          string
	diagnosticCode string
}

func (err RemoteCommandError) Error() string {
	if err.ExitCode >= 0 {
		return fmt.Sprintf("remote command failed with exit code %d", err.ExitCode)
	}
	return "remote command failed: " + err.Cause
}

func (err RemoteCommandError) DiagnosticCode() string {
	if validRemoteDiagnosticCode(err.diagnosticCode) {
		return err.diagnosticCode
	}
	return ""
}

func validRemoteDiagnosticCode(code string) bool {
	switch code {
	case "IDENTITY_PERMISSIONS", "IDENTITY_FORMAT", "HOST_KEY_REJECTED",
		"AUTHENTICATION_REJECTED", "CONNECTION_REFUSED", "CONNECTION_TIMEOUT",
		"UNSUPPORTED_CLIENT_TRANSPORT", "SSH_SESSION_FAILED":
		return true
	default:
		return false
	}
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

// NewSSHExecutor creates a process-owned OpenSSH session directory in the
// platform temporary root. Linux uses ControlMaster; Windows uses one
// long-lived framed ssh.exe process per host. Both implementations reuse the
// already authenticated TCP connection after fail-closed firewalls are applied.
func NewSSHExecutor() (*SSHExecutor, error) {
	return newSSHExecutor("")
}

// NewSSHExecutorAt keeps every ephemeral SSH object below an explicit trusted
// working root. The Windows deploy launcher uses this variant so staged key
// copies and session state never escape its project-local working directory.
func NewSSHExecutorAt(root string) (*SSHExecutor, error) {
	if !filepath.IsAbs(root) || strings.ContainsRune(root, '\x00') {
		return nil, errors.New("absolute SSH working root is required")
	}
	info, err := os.Lstat(root)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return nil, errors.New("SSH working root is unsafe or unavailable")
	}
	return newSSHExecutor(root)
}

func newSSHExecutor(root string) (*SSHExecutor, error) {
	directory, err := os.MkdirTemp(root, platformControlDirectoryPrefix())
	if err != nil {
		return nil, errors.New("create private SSH control directory failed")
	}
	if err := securePlatformControlDirectory(directory); err != nil {
		_ = os.RemoveAll(directory)
		return nil, errors.New("secure SSH control directory failed")
	}
	executor := &SSHExecutor{
		Executable: DefaultSSHExecutable, OutputLimit: DefaultOutputLimit,
		controlDirectory: directory,
	}
	executor.backend = newPlatformSSHBackend(executor)
	if err := executor.validate(); err != nil {
		_ = os.RemoveAll(directory)
		return nil, err
	}
	if err := validateSSHRuntime(executor.Executable, executor.controlPath()); err != nil {
		_ = os.RemoveAll(directory)
		return nil, err
	}
	return executor, nil
}

func (executor *SSHExecutor) Run(ctx context.Context, host Host, remoteCommand string) (RemoteResult, error) {
	if executor != nil && executor.backend != nil {
		return executor.backend.Run(ctx, host, remoteCommand)
	}
	arguments, err := executor.commandArguments(host, remoteCommand)
	if err != nil {
		return RemoteResult{}, err
	}
	command := exec.CommandContext(ctx, executor.Executable, arguments...)
	command.Env = platformSSHEnvironment()
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

func (executor *SSHExecutor) commandArguments(host Host, remoteCommand string) ([]string, error) {
	if err := executor.validate(); err != nil {
		return nil, err
	}
	if err := ValidateHost(host); err != nil {
		return nil, err
	}
	if remoteCommand == "" || len(remoteCommand) > 128*1024 || strings.ContainsAny(remoteCommand, "\x00\r\n") {
		return nil, errors.New("bounded single-line remote command is required")
	}
	arguments := []string{
		"-F", platformNullDevice(), "-T",
		"-o", "ControlMaster=auto",
		"-o", "ControlPersist=" + strconv.Itoa(defaultControlPersistSecond),
		"-o", "ControlPath=" + executor.controlPath(),
		"-o", "BatchMode=yes",
		"-o", "PasswordAuthentication=no",
		"-o", "KbdInteractiveAuthentication=no",
		"-o", "StrictHostKeyChecking=yes",
		"-o", "UserKnownHostsFile=" + platformSSHConfigPath(host.KnownHosts),
		"-o", "GlobalKnownHostsFile=" + platformNullDevice(),
		"-o", "IdentityAgent=none",
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
	return arguments, nil
}

// Close terminates persistent masters and removes their private socket
// directory. Individual -O exit failures are tolerated only if no control
// sockets remain, covering hosts whose first connection never opened.
func (executor *SSHExecutor) Close(ctx context.Context, hosts ...Host) error {
	if executor == nil || executor.controlDirectory == "" {
		return nil
	}
	if executor.backend != nil {
		directory := executor.controlDirectory
		executor.controlDirectory = ""
		backendErr := executor.backend.Close(ctx, hosts...)
		removeErr := os.RemoveAll(directory)
		if backendErr != nil {
			return backendErr
		}
		if removeErr != nil {
			return errors.New("remove private SSH session directory failed")
		}
		return nil
	}
	directory := executor.controlDirectory
	executor.controlDirectory = ""
	defer os.RemoveAll(directory)
	if err := validateControlDirectory(directory); err != nil {
		return err
	}
	controlPath := filepath.Join(directory, "%C")
	for _, host := range hosts {
		if ValidateHost(host) != nil {
			continue
		}
		arguments := []string{
			"-F", platformNullDevice(), "-T",
			"-o", "BatchMode=yes",
			"-o", "ControlPath=" + controlPath,
			"-O", "exit", "-p", strconv.Itoa(host.Port),
			"--", host.Destination,
		}
		command := exec.CommandContext(ctx, executor.Executable, arguments...)
		command.Env = platformSSHEnvironment()
		_ = command.Run()
	}
	for {
		entries, err := os.ReadDir(directory)
		if err != nil {
			return errors.New("inspect SSH control directory during close failed")
		}
		if len(entries) == 0 {
			return nil
		}
		select {
		case <-ctx.Done():
			return errors.New("persistent SSH control connections did not close")
		case <-time.After(50 * time.Millisecond):
		}
	}
}

func (executor *SSHExecutor) validate() error {
	if executor == nil || executor.Executable != DefaultSSHExecutable || executor.OutputLimit < 4096 || executor.OutputLimit > 4*1024*1024 {
		return errors.New("fixed SSH executor and bounded output are required")
	}
	return validateControlDirectory(executor.controlDirectory)
}

func (executor *SSHExecutor) controlPath() string {
	return filepath.Join(executor.controlDirectory, "%C")
}

// validateSSHRuntime proves that the fixed OpenSSH client accepts every
// option needed for connection persistence before either target is contacted.
// ssh -G only expands configuration; it does not open a network connection.
func validateSSHRuntime(executable, controlPath string) error {
	info, err := os.Lstat(executable)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return platformSSHUnavailableError(executable)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	arguments := platformSSHRuntimeArguments(controlPath)
	command := exec.CommandContext(ctx, executable, arguments...)
	command.Env = platformSSHEnvironment()
	var stdout, stderr boundedBuffer
	stdout.maximum = 64 * 1024
	stderr.maximum = 64 * 1024
	command.Stdout = &stdout
	command.Stderr = &stderr
	if err := command.Run(); err != nil || ctx.Err() != nil || stdout.overflow || stderr.overflow {
		return fmt.Errorf("fixed system OpenSSH persistent-session capability check failed: %v", err)
	}
	effective := strings.ToLower(string(stdout.Bytes()) + "\n" + string(stderr.Bytes()))
	return validatePlatformSSHRuntime(effective)
}

func validateControlDirectory(directory string) error {
	expandedPath := filepath.Join(directory, strings.Repeat("0", 40))
	// Linux OpenSSH expands ControlPath into a Unix socket and therefore keeps
	// the full path below the conservative 100-byte limit. Windows uses the
	// long-lived framed ssh.exe backend and never passes ControlPath to
	// OpenSSH; retaining the same limit there would reject normal project-local
	// temporary roots (whose absolute path is often longer than a user TEMP
	// directory). Keep a bounded Windows path as well, but use the platform's
	// safe MAX_PATH-compatible envelope instead of imposing the Unix socket
	// limit on a path that is not used for a socket.
	maximumPath := 100
	if runtime.GOOS == "windows" {
		maximumPath = 240
	}
	if !filepath.IsAbs(directory) || strings.ContainsRune(directory, '\x00') || len(expandedPath) > maximumPath {
		return errors.New("private bounded SSH control directory is required")
	}
	info, err := os.Lstat(directory)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return errors.New("SSH control directory is unsafe or unavailable")
	}
	return nil
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
	if !filepath.IsAbs(filename) || strings.ContainsAny(filename, "\"\t\r\n\x00") {
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
