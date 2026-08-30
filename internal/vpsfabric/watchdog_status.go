package vpsfabric

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"time"
)

const (
	WatchdogStatusFilename = "fabric-watchdog.json"
	watchdogStatusVersion  = 1
)

var watchdogReasonPattern = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,63}$`)

// WatchdogStatus is display-only telemetry. It never authorizes a host apply;
// the root-owned receipt and transaction journal remain authoritative.
type WatchdogStatus struct {
	FormatVersion      int    `json:"format_version"`
	State              string `json:"state"`
	Healthy            bool   `json:"healthy"`
	ReconcileScheduled bool   `json:"reconcile_scheduled"`
	Reason             string `json:"reason"`
	CheckedAt          string `json:"checked_at"`
}

func NewWatchdogStatus(state, reason string, healthy, scheduled bool, checkedAt time.Time) WatchdogStatus {
	return WatchdogStatus{
		FormatVersion: watchdogStatusVersion, State: state, Healthy: healthy,
		ReconcileScheduled: scheduled, Reason: reason, CheckedAt: checkedAt.UTC().Format(time.RFC3339Nano),
	}
}

func WriteWatchdogStatus(path string, status WatchdogStatus, uid, gid int) error {
	if err := validateWatchdogStatusPath(path); err != nil || uid < 0 || gid < 0 {
		return errors.New("VPS fabric watchdog status destination is invalid")
	}
	if _, err := validateWatchdogStatus(status); err != nil {
		return err
	}
	content, err := json.Marshal(status)
	if err != nil {
		return err
	}
	content = append(content, '\n')
	directory := filepath.Dir(path)
	info, err := os.Lstat(directory)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return errors.New("VPS fabric watchdog status directory is unsafe")
	}
	if current, err := os.Lstat(path); err == nil && (current.Mode()&os.ModeSymlink != 0 || !current.Mode().IsRegular()) {
		return errors.New("VPS fabric watchdog status file is unsafe")
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	temporary, err := os.CreateTemp(directory, ".gateway-vpn-vps-watchdog-")
	if err != nil {
		return err
	}
	name := temporary.Name()
	defer os.Remove(name)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return err
	}
	if runtime.GOOS != "windows" {
		if err := temporary.Chown(uid, gid); err != nil {
			temporary.Close()
			return err
		}
	}
	if _, err := temporary.Write(content); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, path); err != nil {
		return err
	}
	return syncDirectory(directory)
}

func ReadWatchdogStatus(path string, now time.Time, maximumAge time.Duration) (WatchdogStatus, error) {
	if err := validateWatchdogStatusPath(path); err != nil || maximumAge <= 0 || maximumAge > time.Hour {
		return WatchdogStatus{}, errors.New("VPS fabric watchdog status read contract is invalid")
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > 4096 {
		return WatchdogStatus{}, errors.New("VPS fabric watchdog status file is unavailable")
	}
	content, err := os.ReadFile(path)
	if err != nil || int64(len(content)) != info.Size() {
		return WatchdogStatus{}, errors.New("read VPS fabric watchdog status failed")
	}
	var status WatchdogStatus
	if json.Unmarshal(content, &status) != nil {
		return WatchdogStatus{}, errors.New("VPS fabric watchdog status JSON is invalid")
	}
	checkedAt, err := validateWatchdogStatus(status)
	if err != nil || checkedAt.After(now.UTC().Add(30*time.Second)) || now.UTC().Sub(checkedAt) > maximumAge {
		return WatchdogStatus{}, errors.New("VPS fabric watchdog status is stale or invalid")
	}
	return status, nil
}

func validateWatchdogStatusPath(path string) error {
	if !filepath.IsAbs(path) || filepath.Base(path) != WatchdogStatusFilename || filepath.Clean(path) != path {
		return errors.New("canonical absolute VPS fabric watchdog status path is required")
	}
	return nil
}

func validateWatchdogStatus(status WatchdogStatus) (time.Time, error) {
	checkedAt, err := time.Parse(time.RFC3339Nano, status.CheckedAt)
	validState := status.State == "HEALTHY" || status.State == "PENDING" || status.State == "FAILED"
	coherent := status.State == "HEALTHY" && status.Healthy && !status.ReconcileScheduled || status.State != "HEALTHY" && !status.Healthy
	if status.FormatVersion != watchdogStatusVersion || !validState || !coherent || !watchdogReasonPattern.MatchString(status.Reason) || err != nil || status.CheckedAt != checkedAt.UTC().Format(time.RFC3339Nano) {
		return time.Time{}, errors.New("VPS fabric watchdog status content is invalid")
	}
	return checkedAt, nil
}
