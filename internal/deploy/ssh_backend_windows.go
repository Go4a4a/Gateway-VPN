//go:build windows

package deploy

import (
	"bufio"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
)

type windowsSSHBackend struct {
	executor *SSHExecutor
	mutex    sync.Mutex
	sessions map[string]*windowsSSHSession
}

type windowsSSHSession struct {
	command    *exec.Cmd
	stdin      io.WriteCloser
	stdout     *bufio.Reader
	waitDone   chan error
	stderrDone chan []byte
	nextID     uint64
	frameLimit int
}

type windowsSSHReadResponse struct {
	line []byte
	err  error
}

func newPlatformSSHBackend(executor *SSHExecutor) sshBackend {
	return &windowsSSHBackend{executor: executor, sessions: make(map[string]*windowsSSHSession)}
}

func (backend *windowsSSHBackend) Run(ctx context.Context, host Host, remoteCommand string) (RemoteResult, error) {
	backend.mutex.Lock()
	defer backend.mutex.Unlock()
	if err := ctx.Err(); err != nil {
		return RemoteResult{}, err
	}
	if err := backend.executor.validate(); err != nil {
		return RemoteResult{}, err
	}
	if err := ValidateHost(host); err != nil || host.Identity == "" {
		return RemoteResult{}, errors.New("Windows SSH requires a validated explicit identity file")
	}
	if remoteCommand == "" || len(remoteCommand) > 128*1024 || strings.ContainsAny(remoteCommand, "\x00\r\n") {
		return RemoteResult{}, errors.New("bounded single-line remote command is required")
	}
	key := windowsSSHSessionKey(host)
	session := backend.sessions[key]
	if session == nil {
		var err error
		session, err = backend.startSession(ctx, host)
		if err != nil {
			return RemoteResult{}, err
		}
		backend.sessions[key] = session
	}
	session.nextID++
	requestID := strconv.FormatUint(session.nextID, 10)
	payload := base64.StdEncoding.EncodeToString([]byte(remoteCommand))
	if _, err := io.WriteString(session.stdin, requestID+"\t"+payload+"\n"); err != nil {
		backend.dropSession(key, session)
		return RemoteResult{}, RemoteCommandError{ExitCode: -1, Cause: "persistent SSH request write failed"}
	}
	responseChannel := make(chan windowsSSHReadResponse, 1)
	go func() {
		line, err := readWindowsSSHFrame(session.stdout, session.frameLimit)
		responseChannel <- windowsSSHReadResponse{line: line, err: err}
	}()
	var responseValue windowsSSHReadResponse
	select {
	case responseValue = <-responseChannel:
	case <-ctx.Done():
		backend.dropSession(key, session)
		return RemoteResult{}, ctx.Err()
	}
	line, err := responseValue.line, responseValue.err
	if err != nil {
		backend.dropSession(key, session)
		if ctx.Err() != nil {
			return RemoteResult{}, ctx.Err()
		}
		return RemoteResult{}, RemoteCommandError{ExitCode: -1, Cause: "persistent SSH response failed"}
	}
	result, err := decodeWindowsSSHResponse(line, requestID, backend.executor.OutputLimit)
	if err != nil {
		backend.dropSession(key, session)
		return RemoteResult{}, err
	}
	if result.ExitCode != 0 {
		return result, RemoteCommandError{ExitCode: result.ExitCode}
	}
	return result, nil
}

func (backend *windowsSSHBackend) startSession(ctx context.Context, host Host) (*windowsSSHSession, error) {
	arguments := []string{
		"-F", platformNullDevice(), "-T",
		"-o", "BatchMode=yes",
		"-o", "PasswordAuthentication=no",
		"-o", "KbdInteractiveAuthentication=no",
		"-o", "StrictHostKeyChecking=yes",
		"-o", "UserKnownHostsFile=" + platformSSHConfigPath(host.KnownHosts),
		"-o", "GlobalKnownHostsFile=" + platformNullDevice(),
		"-o", "IdentityAgent=none",
		"-o", "IdentitiesOnly=yes",
		"-o", "RequestTTY=no",
		"-o", "ConnectTimeout=15",
		"-o", "ConnectionAttempts=1",
		"-o", "ServerAliveInterval=15",
		"-o", "ServerAliveCountMax=2",
		"-i", host.Identity,
		"-p", strconv.Itoa(host.Port),
		"--", host.Destination, windowsSSHBrokerCommand(backend.executor.OutputLimit),
	}
	command := exec.CommandContext(ctx, backend.executor.Executable, arguments...)
	command.Env = platformSSHEnvironment()
	stdin, err := command.StdinPipe()
	if err != nil {
		return nil, errors.New("create persistent SSH stdin failed")
	}
	stdout, err := command.StdoutPipe()
	if err != nil {
		_ = stdin.Close()
		return nil, errors.New("create persistent SSH stdout failed")
	}
	stderr, err := command.StderrPipe()
	if err != nil {
		_ = stdin.Close()
		return nil, errors.New("create persistent SSH stderr failed")
	}
	if err := command.Start(); err != nil {
		_ = stdin.Close()
		return nil, errors.New("start fixed system OpenSSH failed")
	}
	frameLimit := windowsSSHFrameLimit(backend.executor.OutputLimit)
	session := &windowsSSHSession{
		command: command, stdin: stdin, stdout: bufio.NewReaderSize(stdout, frameLimit+1),
		waitDone: make(chan error, 1), stderrDone: make(chan []byte, 1), frameLimit: frameLimit,
	}
	go func() { session.waitDone <- command.Wait() }()
	go func() {
		session.stderrDone <- readBoundedAndDrain(stderr, backend.executor.OutputLimit)
	}()
	handshakeChannel := make(chan windowsSSHReadResponse, 1)
	go func() {
		line, err := readWindowsSSHFrame(session.stdout, 256)
		handshakeChannel <- windowsSSHReadResponse{line: line, err: err}
	}()
	var handshake windowsSSHReadResponse
	select {
	case handshake = <-handshakeChannel:
	case <-ctx.Done():
		_ = stdin.Close()
		_ = command.Process.Kill()
		<-session.waitDone
		<-session.stderrDone
		return nil, ctx.Err()
	}
	line, err := handshake.line, handshake.err
	if err != nil || string(line) != windowsSSHProtocol+"\tREADY\n" {
		_ = stdin.Close()
		_ = command.Process.Kill()
		<-session.waitDone
		stderrOutput := <-session.stderrDone
		return nil, RemoteCommandError{ExitCode: -1, Cause: fmt.Sprintf("persistent SSH broker handshake failed (frame_bytes=%d read_error=%t diagnostic=%s)", len(line), err != nil, classifyWindowsSSHDiagnostic(stderrOutput))}
	}
	return session, nil
}

func (backend *windowsSSHBackend) Close(ctx context.Context, _ ...Host) error {
	backend.mutex.Lock()
	defer backend.mutex.Unlock()
	var closeErr error
	for key, session := range backend.sessions {
		delete(backend.sessions, key)
		if err := session.stdin.Close(); err != nil && closeErr == nil {
			closeErr = errors.New("close persistent SSH request stream failed")
		}
		select {
		case <-session.waitDone:
		case <-ctx.Done():
			_ = session.command.Process.Kill()
			<-session.waitDone
			if closeErr == nil {
				closeErr = errors.New("persistent SSH process did not close")
			}
		}
		<-session.stderrDone
	}
	return closeErr
}

func (backend *windowsSSHBackend) dropSession(key string, session *windowsSSHSession) {
	delete(backend.sessions, key)
	_ = session.stdin.Close()
	_ = session.command.Process.Kill()
	<-session.waitDone
	<-session.stderrDone
}

func windowsSSHSessionKey(host Host) string {
	return strings.ToLower(host.Destination) + "\x00" + strconv.Itoa(host.Port) + "\x00" + filepath.Clean(host.Identity) + "\x00" + filepath.Clean(host.KnownHosts)
}

func readWindowsSSHFrame(reader *bufio.Reader, maximum int) ([]byte, error) {
	line, err := reader.ReadSlice('\n')
	if errors.Is(err, bufio.ErrBufferFull) || len(line) == 0 || len(line) > maximum {
		return nil, errors.New("persistent SSH frame exceeds the bounded limit")
	}
	if err != nil {
		return nil, err
	}
	if len(line) >= 2 && line[len(line)-2] == '\r' {
		line = append(line[:len(line)-2], '\n')
	}
	return append([]byte(nil), line...), nil
}

func decodeWindowsSSHResponse(line []byte, requestID string, outputLimit int) (RemoteResult, error) {
	if len(line) == 0 || line[len(line)-1] != '\n' || bytesContainsCR(line) {
		return RemoteResult{}, RemoteCommandError{ExitCode: -1, Cause: "persistent SSH response framing failed"}
	}
	fields := strings.Split(strings.TrimSuffix(string(line), "\n"), "\t")
	if len(fields) != 5 || fields[0] != windowsSSHProtocol || fields[1] != requestID {
		return RemoteResult{}, RemoteCommandError{ExitCode: -1, Cause: "persistent SSH response identity failed"}
	}
	exitCode, err := strconv.Atoi(fields[2])
	if err != nil || exitCode < 0 || exitCode > 255 {
		return RemoteResult{}, RemoteCommandError{ExitCode: -1, Cause: "persistent SSH exit status failed"}
	}
	stdout, stdoutErr := base64.StdEncoding.Strict().DecodeString(fields[3])
	stderr, stderrErr := base64.StdEncoding.Strict().DecodeString(fields[4])
	if stdoutErr != nil || stderrErr != nil || len(stdout) > outputLimit || len(stderr) > outputLimit {
		return RemoteResult{}, RemoteCommandError{ExitCode: -1, Cause: "persistent SSH bounded output failed"}
	}
	return RemoteResult{Stdout: stdout, Stderr: stderr, ExitCode: exitCode}, nil
}

func bytesContainsCR(value []byte) bool {
	for _, character := range value {
		if character == '\r' {
			return true
		}
	}
	return false
}

func classifyWindowsSSHDiagnostic(content []byte) string {
	value := strings.ToLower(string(content))
	checks := []struct{ fragment, code string }{
		{"bad permissions", "IDENTITY_PERMISSIONS"},
		{"permissions for", "IDENTITY_PERMISSIONS"},
		{"invalid format", "IDENTITY_FORMAT"},
		{"host key verification failed", "HOST_KEY_REJECTED"},
		{"permission denied", "AUTHENTICATION_REJECTED"},
		{"connection refused", "CONNECTION_REFUSED"},
		{"connection timed out", "CONNECTION_TIMEOUT"},
		{"getsockname failed", "UNSUPPORTED_CLIENT_TRANSPORT"},
	}
	for _, check := range checks {
		if strings.Contains(value, check.fragment) {
			return check.code
		}
	}
	return "SSH_SESSION_FAILED"
}

func readBoundedAndDrain(reader io.Reader, maximum int) []byte {
	result := make([]byte, 0, maximum)
	buffer := make([]byte, 32*1024)
	for {
		count, err := reader.Read(buffer)
		if count > 0 && len(result) < maximum {
			keep := count
			if keep > maximum-len(result) {
				keep = maximum - len(result)
			}
			result = append(result, buffer[:keep]...)
		}
		if err != nil {
			return result
		}
	}
}
