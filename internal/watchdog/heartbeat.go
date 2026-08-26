package watchdog

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

type ControlHeartbeat struct {
	SchemaVersion    int    `json:"schema_version"`
	PID              int    `json:"pid"`
	ProcessStartedAt string `json:"process_started_at"`
	WrittenAt        string `json:"written_at"`
	DatabaseOK       bool   `json:"database_ok"`
	WorkersOK        bool   `json:"workers_ok"`
	ReconcileLastAt  string `json:"reconcile_last_at,omitempty"`
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
	if heartbeat.SchemaVersion != 1 || heartbeat.PID <= 0 || !heartbeat.DatabaseOK || !heartbeat.WorkersOK {
		return errors.New("complete healthy control heartbeat is required")
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
	return nil
}

func validateHeartbeatPath(path string) error {
	if !filepath.IsAbs(path) || filepath.Base(path) != "control.json" || filepath.Base(filepath.Dir(path)) != "gateway-vpn-watchdog" {
		return errors.New("fixed absolute control heartbeat path is required")
	}
	return nil
}
