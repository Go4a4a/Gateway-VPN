package deploy

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

func TestValidateHostRejectsOptionInjectionSymlinkAndInsecureIdentity(t *testing.T) {
	directory := t.TempDir()
	knownHosts := filepath.Join(directory, "known_hosts")
	identity := filepath.Join(directory, "identity")
	if err := os.WriteFile(knownHosts, []byte("host key\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(identity, []byte("identity\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	valid := Host{Destination: "deploy@gateway.example", Port: 2222, Identity: identity, KnownHosts: knownHosts}
	if err := ValidateHost(valid); err != nil {
		t.Fatal(err)
	}
	for _, destination := range []string{"-oProxyCommand=bad", "user@host extra", "user@host:22", "bad/user@host", "user@@host"} {
		candidate := valid
		candidate.Destination = destination
		if err := ValidateHost(candidate); err == nil {
			t.Errorf("unsafe destination accepted: %q", destination)
		}
	}
	link := filepath.Join(directory, "known_hosts_link")
	if err := os.Symlink(knownHosts, link); err == nil {
		candidate := valid
		candidate.KnownHosts = link
		if err := ValidateHost(candidate); err == nil {
			t.Fatal("symlink known-hosts file accepted")
		}
	}
	if runtime.GOOS != "windows" {
		if err := os.Chmod(identity, 0o644); err != nil {
			t.Fatal(err)
		}
		if err := ValidateHost(valid); err == nil {
			t.Fatal("overly broad identity permissions accepted")
		}
	}
}

func TestBoundedBufferTruncatesWithoutUnboundedAllocation(t *testing.T) {
	buffer := boundedBuffer{maximum: 8}
	content := strings.Repeat("x", 32)
	written, err := buffer.Write([]byte(content))
	if !errors.Is(err, errRemoteOutputLimit) || written != 8 || len(buffer.Bytes()) != 8 || !buffer.overflow {
		t.Fatalf("unexpected bounded buffer result: written=%d bytes=%d overflow=%v err=%v", written, len(buffer.Bytes()), buffer.overflow, err)
	}
}

func TestSSHExecutorPinsAndPersistsPrivateControlConnection(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("OpenSSH Unix control sockets are Linux-only")
	}
	directory, err := os.MkdirTemp("", "gateway-vpn-ssh-test-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(directory)
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	knownHosts := filepath.Join(directory, "known_hosts")
	identity := filepath.Join(directory, "identity")
	if err := os.WriteFile(knownHosts, []byte("gateway ssh-ed25519 AAAA\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(identity, []byte("identity\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	controlDirectory := filepath.Join(directory, "control")
	if err := os.Mkdir(controlDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	executor := &SSHExecutor{
		Executable: DefaultSSHExecutable, OutputLimit: DefaultOutputLimit,
		controlDirectory: controlDirectory,
	}
	arguments, err := executor.commandArguments(Host{
		Destination: "deploy@gateway.example", Port: 2222,
		Identity: identity, KnownHosts: knownHosts,
	}, "true")
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(arguments, "\x00")
	for _, required := range []string{
		"ControlMaster=auto",
		"ControlPersist=" + strconv.Itoa(defaultControlPersistSecond),
		"ControlPath=" + filepath.Join(controlDirectory, "%C"),
		"StrictHostKeyChecking=yes",
		"UserKnownHostsFile=" + knownHosts,
		"IdentitiesOnly=yes",
	} {
		if !strings.Contains(joined, required) {
			t.Errorf("persistent SSH command missing %q", required)
		}
	}
	if strings.Contains(joined, "ProxyCommand") || strings.Contains(joined, "ControlPath=none") {
		t.Fatal("persistent SSH command contains an unsafe or disabling option")
	}
}

func TestSSHExecutorRejectsInsecureControlDirectory(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows does not enforce Unix control directory permissions")
	}
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o755); err != nil {
		t.Fatal(err)
	}
	executor := &SSHExecutor{
		Executable: DefaultSSHExecutable, OutputLimit: DefaultOutputLimit,
		controlDirectory: directory,
	}
	if err := executor.validate(); err == nil {
		t.Fatal("group/world-accessible SSH control directory accepted")
	}
}
