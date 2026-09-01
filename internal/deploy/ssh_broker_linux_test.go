//go:build linux

package deploy

import (
	"bufio"
	"context"
	"encoding/base64"
	"io"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestWindowsSSHBrokerRunsPhasesAndBoundsOutputOnLinuxTarget(t *testing.T) {
	const outputLimit = 4096
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, "/usr/bin/bash", "--norc", "-c", windowsSSHBrokerCommand(outputLimit))
	command.Env = []string{"PATH=/usr/bin:/bin", "LANG=C.UTF-8", "LC_ALL=C.UTF-8"}
	stdin, err := command.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReaderSize(stdout, windowsSSHFrameLimit(outputLimit)+1)
	ready, err := reader.ReadString('\n')
	if err != nil || ready != windowsSSHProtocol+"\tREADY\n" {
		t.Fatalf("broker readiness=%q err=%v", ready, err)
	}
	assertBrokerPhase(t, stdin, reader, "1", `printf 'hello'; printf 'warning' >&2; exit 7`, 7, "hello", "warning")
	assertBrokerPhase(t, stdin, reader, "2", `head -c 8192 /dev/zero | tr '\0' x`, 125, "", "remote output exceeded bounded limit")
	if err := stdin.Close(); err != nil {
		t.Fatal(err)
	}
	if err := command.Wait(); err != nil {
		t.Fatal(err)
	}
}

func assertBrokerPhase(t *testing.T, stdin io.Writer, reader *bufio.Reader, id, phase string, expectedStatus int, expectedStdout, expectedStderr string) {
	t.Helper()
	payload := base64.StdEncoding.EncodeToString([]byte(phase))
	if _, err := io.WriteString(stdin, id+"\t"+payload+"\n"); err != nil {
		t.Fatal(err)
	}
	line, err := reader.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	fields := strings.Split(strings.TrimSuffix(line, "\n"), "\t")
	if len(fields) != 5 || fields[0] != windowsSSHProtocol || fields[1] != id || fields[2] != strconv.Itoa(expectedStatus) {
		t.Fatalf("broker response header=%q", line)
	}
	stdout, stdoutErr := base64.StdEncoding.Strict().DecodeString(fields[3])
	stderr, stderrErr := base64.StdEncoding.Strict().DecodeString(fields[4])
	if stdoutErr != nil || stderrErr != nil || string(stdout) != expectedStdout || string(stderr) != expectedStderr {
		t.Fatalf("broker response stdout=%q stderr=%q errors=%v,%v", stdout, stderr, stdoutErr, stderrErr)
	}
}
