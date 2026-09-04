//go:build windows

package deploy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

func TestWindowsOpenSSHLongLivedSessionReusesOneTCPAndClosesIt(t *testing.T) {
	clientPublic, clientPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, hostPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	hostSigner, err := ssh.NewSignerFromKey(hostPrivate)
	if err != nil {
		t.Fatal(err)
	}
	clientSSHKey, err := ssh.NewPublicKey(clientPublic)
	if err != nil {
		t.Fatal(err)
	}
	configuration := &ssh.ServerConfig{
		PublicKeyCallback: func(metadata ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if metadata.User() != "deploy" || !bytes.Equal(key.Marshal(), clientSSHKey.Marshal()) {
				return nil, fmt.Errorf("unexpected test SSH identity")
			}
			return nil, nil
		},
	}
	configuration.AddHostKey(hostSigner)
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	var accepted atomic.Int32
	var authenticated atomic.Bool
	serverDone := make(chan error, 1)
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			serverDone <- acceptErr
			return
		}
		accepted.Add(1)
		_ = listener.Close() // A second TCP connection must now fail.
		serverConnection, channels, requests, handshakeErr := ssh.NewServerConn(connection, configuration)
		if handshakeErr != nil {
			_ = connection.Close()
			serverDone <- handshakeErr
			return
		}
		authenticated.Store(true)
		go func() {
			for request := range requests {
				if request.WantReply {
					_ = request.Reply(false, nil)
				}
			}
		}()
		for newChannel := range channels {
			if newChannel.ChannelType() != "session" {
				_ = newChannel.Reject(ssh.UnknownChannelType, "session required")
				continue
			}
			channel, channelRequests, channelErr := newChannel.Accept()
			if channelErr != nil {
				continue
			}
			go serveWindowsSSHTestSession(channel, channelRequests)
		}
		waitErr := serverConnection.Wait()
		if waitErr != nil {
			message := strings.ToLower(waitErr.Error())
			if strings.Contains(message, "disconnect, reason 11") || strings.Contains(message, "forcibly closed") || strings.Contains(message, "connection reset") {
				waitErr = nil
			}
		}
		serverDone <- waitErr
	}()

	directory := t.TempDir()
	identity := filepath.Join(directory, "selected identity")
	knownHosts := filepath.Join(directory, "known hosts")
	privateBlock, err := ssh.MarshalPrivateKey(clientPrivate, "gateway-vpn-windows-test")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(identity, pem.EncodeToMemory(privateBlock), 0o600); err != nil {
		t.Fatal(err)
	}
	broadenWindowsSSHTestIdentity(t, identity)
	hostPattern := fmt.Sprintf("[127.0.0.1]:%d", port)
	if err := os.WriteFile(knownHosts, []byte(knownhosts.Line([]string{hostPattern}, hostSigner.PublicKey())+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	executor, err := NewSSHExecutorAt(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	controlDirectory := executor.controlDirectory
	host := Host{Destination: "deploy@127.0.0.1", Port: port, Identity: identity, KnownHosts: knownHosts}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	for _, command := range []string{"first", "second"} {
		result, runErr := executor.Run(ctx, host, command)
		if runErr != nil || result.ExitCode != 0 || string(result.Stdout) != "ok:"+command+"\n" || len(result.Stderr) != 0 {
			var serverErr error
			select {
			case serverErr = <-serverDone:
			default:
			}
			t.Fatalf("persistent command %q result=%+v err=%v accepted=%d authenticated=%t server=%v", command, result, runErr, accepted.Load(), authenticated.Load(), serverErr)
		}
	}
	if accepted.Load() != 1 {
		t.Fatalf("OpenSSH opened %d TCP connections, want exactly one", accepted.Load())
	}
	closeCtx, closeCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer closeCancel()
	if err := executor.Close(closeCtx, host); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-serverDone:
		if err != nil && err != io.EOF {
			t.Fatalf("SSH server connection close: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Windows OpenSSH persistent master survived executor.Close")
	}
	if _, err := os.Lstat(controlDirectory); !os.IsNotExist(err) {
		t.Fatal("private Windows OpenSSH control directory survived cleanup")
	}
}

func TestWindowsPersistentSSHRunHonorsContextCancellation(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	controlDirectory, err := os.MkdirTemp("", "gvc-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(controlDirectory)
	executor := &SSHExecutor{Executable: DefaultSSHExecutable, OutputLimit: DefaultOutputLimit, controlDirectory: controlDirectory}
	backend := &windowsSSHBackend{executor: executor, sessions: make(map[string]*windowsSSHSession)}
	server, client := net.Pipe()
	defer server.Close()
	command := exec.Command("cmd.exe", "/c", "ping", "-n", "30", "127.0.0.1", ">nul")
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	stdinReader, stdinWriter := io.Pipe()
	go func() { _, _ = io.Copy(io.Discard, stdinReader) }()
	session := &windowsSSHSession{
		command: command, stdin: stdinWriter, stdout: bufio.NewReader(client),
		waitDone: make(chan error, 1), stderrDone: make(chan []byte, 1), frameLimit: windowsSSHFrameLimit(DefaultOutputLimit),
	}
	go func() { session.waitDone <- command.Wait() }()
	session.stderrDone <- nil
	host := Host{Destination: "deploy@127.0.0.1", Port: listener.Addr().(*net.TCPAddr).Port, Identity: filepath.Join(t.TempDir(), "identity"), KnownHosts: filepath.Join(t.TempDir(), "known_hosts")}
	if err := os.WriteFile(host.Identity, []byte("identity\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(host.KnownHosts, []byte{}, 0o600); err != nil {
		t.Fatal(err)
	}
	backend.sessions[windowsSSHSessionKey(host)] = session
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	_, runErr := backend.Run(ctx, host, "true")
	_ = stdinReader.Close()
	_ = client.Close()
	if !errors.Is(runErr, context.DeadlineExceeded) {
		t.Fatalf("persistent Run cancellation error=%v", runErr)
	}
}

func TestWindowsSSHResponseFramingRejectsSpoofOverflowAndMalformedData(t *testing.T) {
	valid := []byte("GVR1\t7\t3\taGVsbG8=\td2FybmluZw==\n")
	result, err := decodeWindowsSSHResponse(valid, "7", 64)
	if err != nil || result.ExitCode != 3 || string(result.Stdout) != "hello" || string(result.Stderr) != "warning" {
		t.Fatalf("valid nonzero response result=%+v err=%v", result, err)
	}
	for _, invalid := range [][]byte{
		[]byte("GVR1\t8\t0\t\t\n"),
		[]byte("GVR1\t7\t0\t%%%\t\n"),
		[]byte("GVR1\t7\t999\t\t\n"),
		[]byte("GVR1\t7\t0\t" + base64.StdEncoding.EncodeToString(bytes.Repeat([]byte("x"), 65)) + "\t\n"),
		[]byte("GVR1\t7\t0\t\t\r\n"),
	} {
		if _, err := decodeWindowsSSHResponse(invalid, "7", 64); err == nil {
			t.Fatalf("invalid persistent SSH response accepted: %q", invalid)
		}
	}
}

func broadenWindowsSSHTestIdentity(t *testing.T, filename string) {
	t.Helper()
	if output, err := exec.Command(`C:\Windows\System32\icacls.exe`, filename, "/grant", "*S-1-1-0:(R)").CombinedOutput(); err != nil {
		t.Fatalf("broaden Windows SSH test identity to mapped-folder style ACL: %v\n%s", err, output)
	}
}

func serveWindowsSSHTestSession(channel ssh.Channel, requests <-chan *ssh.Request) {
	defer channel.Close()
	for request := range requests {
		if request.Type != "exec" {
			if request.WantReply {
				_ = request.Reply(false, nil)
			}
			continue
		}
		var payload struct{ Command string }
		if err := ssh.Unmarshal(request.Payload, &payload); err != nil {
			if request.WantReply {
				_ = request.Reply(false, nil)
			}
			return
		}
		if request.WantReply {
			_ = request.Reply(true, nil)
		}
		if payload.Command == "" {
			return
		}
		_, _ = io.WriteString(channel, windowsSSHProtocol+"\tREADY\n")
		scanner := bufio.NewScanner(channel)
		scanner.Buffer(make([]byte, 1024), 256*1024)
		for scanner.Scan() {
			fields := strings.Split(scanner.Text(), "\t")
			if len(fields) != 2 {
				return
			}
			command, err := base64.StdEncoding.Strict().DecodeString(fields[1])
			if err != nil {
				return
			}
			stdout := base64.StdEncoding.EncodeToString([]byte("ok:" + string(command) + "\n"))
			_, _ = fmt.Fprintf(channel, "%s\t%s\t0\t%s\t\n", windowsSSHProtocol, fields[0], stdout)
		}
		_, _ = channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
		return
	}
}
