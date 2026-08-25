package networkapply

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gateway-vpn/internal/platformexec"
)

func TestSystemdRollbackTimerUsesOnlyFixedTemplateUnit(t *testing.T) {
	now := time.Date(2026, 8, 24, 10, 0, 0, 0, time.UTC)
	executor := &recordingExecutor{}
	timer := SystemdRollbackTimer{Executor: executor, Systemctl: filepath.Join(t.TempDir(), "systemctl"), Now: func() time.Time { return now }}
	const id = "apply-0123456789abcdef"
	if err := timer.Arm(context.Background(), id, now.Add(time.Minute)); err != nil {
		t.Fatalf("Arm() error = %v", err)
	}
	if err := timer.Disarm(context.Background(), id); err != nil {
		t.Fatalf("Disarm() error = %v", err)
	}
	if len(executor.requests) != 2 || strings.Join(executor.requests[0].Arguments, " ") != "start gateway-vpn-network-rollback@"+id+".timer" || strings.Join(executor.requests[1].Arguments, " ") != "stop gateway-vpn-network-rollback@"+id+".timer" {
		t.Fatalf("systemctl requests = %+v", executor.requests)
	}
	if err := timer.Arm(context.Background(), "../../evil", now.Add(time.Minute)); err == nil {
		t.Fatal("Arm(unsafe id) error = nil")
	}
	if err := timer.Arm(context.Background(), id, now.Add(30*time.Second)); err == nil {
		t.Fatal("Arm(wrong deadline) error = nil")
	}
}

type recordingExecutor struct {
	requests []platformexec.Request
	err      error
}

func (executor *recordingExecutor) Run(_ context.Context, request platformexec.Request) (platformexec.Result, error) {
	executor.requests = append(executor.requests, request)
	return platformexec.Result{}, executor.err
}
