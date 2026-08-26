package update

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"gateway-vpn/internal/watchdog"
)

func TestUpdateRuntimeRequiresFreshWatchdogAndControlEvidence(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "gateway-vpn-watchdog")
	if err := os.Mkdir(directory, 0o770); err != nil {
		t.Fatal(err)
	}
	statusPath := filepath.Join(directory, "status.json")
	heartbeatPath := filepath.Join(directory, "control.json")
	now := time.Date(2026, 8, 26, 22, 0, 0, 0, time.UTC)
	status := watchdog.Status{
		SchemaVersion: 1, SupervisorStartedAt: now.Add(-time.Hour).Format(time.RFC3339Nano),
		ObservedAt: now.Format(time.RFC3339Nano), OverallState: watchdog.OverallHealthy,
	}
	if err := (watchdog.StatusFile{Path: statusPath}).Write(status); err != nil {
		t.Fatal(err)
	}
	heartbeat := watchdog.ControlHeartbeat{
		SchemaVersion: 1, PID: 42, ProcessStartedAt: now.Add(-time.Hour).Format(time.RFC3339Nano),
		WrittenAt: now.Format(time.RFC3339Nano), DatabaseOK: true, WorkersOK: true,
		ReconcileLastAt: now.Add(-time.Second).Format(time.RFC3339Nano),
	}
	if err := (watchdog.HeartbeatFile{Path: heartbeatPath}).Write(heartbeat); err != nil {
		t.Fatal(err)
	}
	if err := checkWatchdogRuntimeFiles(statusPath, heartbeatPath, now.Add(10*time.Second)); err != nil {
		t.Fatalf("fresh watchdog evidence rejected: %v", err)
	}
	if err := checkWatchdogRuntimeFiles(statusPath, heartbeatPath, now.Add(3*time.Minute)); err == nil {
		t.Fatal("stale watchdog evidence accepted after update")
	}
}
