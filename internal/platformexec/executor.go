// Package platformexec runs fixed binaries directly without a shell.
package platformexec

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"runtime"
)

type Request struct {
	Executable string
	Arguments  []string
	Stdin      []byte
	// MaxOutputBytes bounds stdout and stderr buffers independently. Zero uses
	// the legacy unbounded behavior for callers whose fixed commands already
	// produce strictly bounded output.
	MaxOutputBytes int64
}

type Result struct {
	Stdout   string
	Stderr   string
	ExitCode int
}

type Executor interface {
	Run(context.Context, Request) (Result, error)
}

type OSExecutor struct{}

func (OSExecutor) Run(ctx context.Context, request Request) (Result, error) {
	if runtime.GOOS != "linux" {
		return Result{}, errors.New("platform command execution is supported only on Linux")
	}
	if !filepath.IsAbs(request.Executable) {
		return Result{}, errors.New("platform executable path must be absolute")
	}
	command := exec.CommandContext(ctx, request.Executable, request.Arguments...)
	command.Stdin = bytes.NewReader(request.Stdin)
	stdout := cappedBuffer{maximum: request.MaxOutputBytes}
	stderr := cappedBuffer{maximum: request.MaxOutputBytes}
	command.Stdout = &stdout
	command.Stderr = &stderr
	err := command.Run()
	result := Result{Stdout: stdout.String(), Stderr: stderr.String()}
	if stdout.exceeded || stderr.exceeded {
		return result, errors.New("platform command output exceeded configured limit")
	}
	if err == nil {
		return result, nil
	}
	var exitError *exec.ExitError
	if errors.As(err, &exitError) {
		result.ExitCode = exitError.ExitCode()
		return result, fmt.Errorf("%s exited with code %d: %w", request.Executable, result.ExitCode, err)
	}
	return result, fmt.Errorf("execute %s: %w", request.Executable, err)
}

type cappedBuffer struct {
	buffer   bytes.Buffer
	maximum  int64
	exceeded bool
}

func (buffer *cappedBuffer) Write(content []byte) (int, error) {
	if buffer.maximum <= 0 {
		return buffer.buffer.Write(content)
	}
	remaining := buffer.maximum - int64(buffer.buffer.Len())
	if remaining <= 0 {
		buffer.exceeded = true
		return len(content), nil
	}
	write := content
	if int64(len(write)) > remaining {
		write = write[:int(remaining)]
		buffer.exceeded = true
	}
	_, _ = buffer.buffer.Write(write)
	return len(content), nil
}

func (buffer *cappedBuffer) String() string {
	return buffer.buffer.String()
}
