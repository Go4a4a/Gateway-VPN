package app

import (
	"testing"
	"time"

	"gateway-vpn/internal/watchdog"
)

func TestUpdateAndManagementRuntimeWorkersHaveExplicitWatchdogContracts(t *testing.T) {
	if silence, critical := workerWatchdogSpec(watchdog.WorkerSoftwareUpdate); silence != 3*time.Minute || critical {
		t.Fatalf("software update worker contract = %s critical=%t", silence, critical)
	}
	if silence, critical := workerWatchdogSpec(watchdog.WorkerManagementRuntime); silence != time.Minute || !critical {
		t.Fatalf("management runtime worker contract = %s critical=%t", silence, critical)
	}
	tracker := newWorkerProgressTracker()
	tracker.register(watchdog.WorkerSoftwareUpdate, 3*time.Minute, false)
	tracker.register(watchdog.WorkerManagementRuntime, time.Minute, true)
	progress, healthy := tracker.snapshot(time.Now().UTC())
	if !healthy || len(progress) != 2 || progress[watchdog.WorkerSoftwareUpdate].Critical || !progress[watchdog.WorkerManagementRuntime].Critical {
		t.Fatalf("worker progress projection = %+v healthy=%t", progress, healthy)
	}
}
