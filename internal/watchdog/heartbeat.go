package watchdog

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

const (
	WorkerSubscriptionRefresh = "subscription-refresh"
	WorkerDataPlaneReconcile  = "data-plane-reconcile"
	WorkerModemReconcile      = "modem-reconcile"
	WorkerEthernetReconcile   = "ethernet-reconcile"
	WorkerPathHealth          = "path-health"
	WorkerDirectHealth        = "direct-health"
	WorkerLoggingSync         = "logging-sync"
	WorkerDatabaseBackup      = "database-backup"
	WorkerRetention           = "retention"
	WorkerTrafficAccounting   = "traffic-accounting"
	WorkerSoftwareUpdate      = "software-update"
	WorkerManagementRuntime   = "management-fabric-runtime"
)

var fixedWorkerIDs = map[string]struct{}{
	WorkerSubscriptionRefresh: {}, WorkerDataPlaneReconcile: {},
	WorkerModemReconcile: {}, WorkerEthernetReconcile: {},
	WorkerPathHealth: {}, WorkerDirectHealth: {}, WorkerLoggingSync: {},
	WorkerDatabaseBackup: {}, WorkerRetention: {}, WorkerTrafficAccounting: {}, WorkerSoftwareUpdate: {}, WorkerManagementRuntime: {},
}

type WorkerProgress struct {
	LastProgressAt        string `json:"last_progress_at"`
	MaximumSilenceSeconds int    `json:"maximum_silence_seconds"`
	Critical              bool   `json:"critical"`
}

type ControlHeartbeat struct {
	SchemaVersion    int                       `json:"schema_version"`
	PID              int                       `json:"pid"`
	ProcessStartedAt string                    `json:"process_started_at"`
	WrittenAt        string                    `json:"written_at"`
	DatabaseOK       bool                      `json:"database_ok"`
	WorkersOK        bool                      `json:"workers_ok"`
	APIServing       bool                      `json:"api_serving"`
	ReconcileLastAt  string                    `json:"reconcile_last_at,omitempty"`
	Workers          map[string]WorkerProgress `json:"workers"`
}

type HeartbeatFile struct {
	Path string
}

func (file HeartbeatFile) Write(heartbeat ControlHeartbeat) error {
	if err := validateHeartbeatPath(file.Path); err != nil {
		return err
	}
	if err := heartbeat.Validate(); err != nil {
		return err
	}
	payload, err := json.Marshal(heartbeat)
	if err != nil {
		return fmt.Errorf("encode control heartbeat: %w", err)
	}
	return writeAtomicFile(file.Path, payload, 0o640)
}

func (file HeartbeatFile) Read(now time.Time, maximumAge time.Duration) (ControlHeartbeat, error) {
	if err := validateHeartbeatPath(file.Path); err != nil {
		return ControlHeartbeat{}, err
	}
	info, err := os.Lstat(file.Path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > 64<<10 {
		return ControlHeartbeat{}, errors.New("control heartbeat file is unavailable or unsafe")
	}
	payload, err := os.ReadFile(file.Path)
	if err != nil {
		return ControlHeartbeat{}, errors.New("read control heartbeat failed")
	}
	var heartbeat ControlHeartbeat
	if err := json.Unmarshal(payload, &heartbeat); err != nil || heartbeat.Validate() != nil {
		return ControlHeartbeat{}, errors.New("control heartbeat payload is invalid")
	}
	written, _ := time.Parse(time.RFC3339Nano, heartbeat.WrittenAt)
	if maximumAge <= 0 || now.UTC().Sub(written) < -5*time.Second || now.UTC().Sub(written) > maximumAge {
		return ControlHeartbeat{}, errors.New("control heartbeat is stale")
	}
	return heartbeat, nil
}

func (heartbeat ControlHeartbeat) Validate() error {
	if heartbeat.SchemaVersion != 2 || heartbeat.PID <= 0 {
		return errors.New("control heartbeat identity is invalid")
	}
	started, err := time.Parse(time.RFC3339Nano, heartbeat.ProcessStartedAt)
	if err != nil {
		return errors.New("control process start timestamp is invalid")
	}
	written, err := time.Parse(time.RFC3339Nano, heartbeat.WrittenAt)
	if err != nil || written.Before(started) {
		return errors.New("control heartbeat timestamp is invalid")
	}
	if heartbeat.ReconcileLastAt != "" {
		reconciled, err := time.Parse(time.RFC3339Nano, heartbeat.ReconcileLastAt)
		if err != nil || reconciled.Before(started) || reconciled.After(written.Add(5*time.Second)) {
			return errors.New("control reconciliation timestamp is invalid")
		}
	}
	if len(heartbeat.Workers) == 0 || len(heartbeat.Workers) > len(fixedWorkerIDs) {
		return errors.New("control worker heartbeat set is invalid")
	}
	for id, progress := range heartbeat.Workers {
		if _, exists := fixedWorkerIDs[id]; !exists || progress.MaximumSilenceSeconds < 5 || progress.MaximumSilenceSeconds > 172800 {
			return errors.New("control worker heartbeat contains an invalid worker")
		}
		last, err := time.Parse(time.RFC3339Nano, progress.LastProgressAt)
		if err != nil || last.Before(started) || last.After(written.Add(5*time.Second)) {
			return errors.New("control worker progress timestamp is invalid")
		}
	}
	return nil
}

func validateHeartbeatPath(path string) error {
	if !filepath.IsAbs(path) || filepath.Base(path) != "control.json" || filepath.Base(filepath.Dir(path)) != "gateway-vpn-watchdog" {
		return errors.New("fixed absolute control heartbeat path is required")
	}
	return nil
}
