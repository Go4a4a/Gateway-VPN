package watchdog

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"time"
)

const durableHistorySchemaVersion = 1

type DurableHistory struct {
	SchemaVersion   int                 `json:"schema_version"`
	RestartAttempts map[string][]string `json:"restart_attempts"`
	RebootAttempts  []string            `json:"reboot_attempts"`
	CriticalSince   map[string]string   `json:"critical_since"`
	PendingRebootAt string              `json:"pending_reboot_at,omitempty"`
}

func NewDurableHistory() DurableHistory {
	return DurableHistory{
		SchemaVersion:   durableHistorySchemaVersion,
		RestartAttempts: make(map[string][]string),
		RebootAttempts:  []string{}, CriticalSince: make(map[string]string),
	}
}

func (history *DurableHistory) normalize() error {
	if history.SchemaVersion != durableHistorySchemaVersion {
		return errors.New("watchdog durable history schema is unsupported")
	}
	if history.RestartAttempts == nil {
		history.RestartAttempts = make(map[string][]string)
	}
	if history.CriticalSince == nil {
		history.CriticalSince = make(map[string]string)
	}
	for id, attempts := range history.RestartAttempts {
		if !validComponentID(id) {
			return errors.New("watchdog durable history contains an unknown component")
		}
		if len(attempts) > 1000 {
			return errors.New("watchdog durable restart history is unbounded")
		}
		for _, value := range attempts {
			if _, err := time.Parse(time.RFC3339Nano, value); err != nil {
				return errors.New("watchdog durable restart timestamp is invalid")
			}
		}
	}
	if len(history.RebootAttempts) > 1000 {
		return errors.New("watchdog durable reboot history is unbounded")
	}
	for _, value := range history.RebootAttempts {
		if _, err := time.Parse(time.RFC3339Nano, value); err != nil {
			return errors.New("watchdog durable reboot timestamp is invalid")
		}
	}
	for id, value := range history.CriticalSince {
		if !validComponentID(id) {
			return errors.New("watchdog durable critical history contains an unknown component")
		}
		if _, err := time.Parse(time.RFC3339Nano, value); err != nil {
			return errors.New("watchdog durable critical timestamp is invalid")
		}
	}
	if history.PendingRebootAt != "" {
		if _, err := time.Parse(time.RFC3339Nano, history.PendingRebootAt); err != nil {
			return errors.New("watchdog pending reboot timestamp is invalid")
		}
	}
	return nil
}

func (history *DurableHistory) Prune(now time.Time, policy Policy) {
	now = now.UTC()
	restartCutoff := now.Add(-policy.RestartWindow())
	for id, attempts := range history.RestartAttempts {
		history.RestartAttempts[id] = recentTimestamps(attempts, restartCutoff)
	}
	history.RebootAttempts = recentTimestamps(history.RebootAttempts, now.Add(-24*time.Hour))
}

func recentTimestamps(values []string, cutoff time.Time) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		parsed, err := time.Parse(time.RFC3339Nano, value)
		if err == nil && !parsed.Before(cutoff) {
			result = append(result, parsed.UTC().Format(time.RFC3339Nano))
		}
	}
	return result
}

func (history *DurableHistory) RestartAllowed(componentID string, policy Policy, now time.Time) (bool, string) {
	if !validComponentID(componentID) {
		return false, "UNKNOWN_COMPONENT"
	}
	history.Prune(now, policy)
	attempts := history.RestartAttempts[componentID]
	if len(attempts) >= policy.MaxRestartsPerComponent {
		return false, "RESTART_BUDGET_EXHAUSTED"
	}
	if len(attempts) != 0 {
		last, _ := time.Parse(time.RFC3339Nano, attempts[len(attempts)-1])
		if now.UTC().Before(last.Add(time.Duration(policy.RestartCooldownSeconds) * time.Second)) {
			return false, "RESTART_COOLDOWN"
		}
	}
	return true, ""
}

func (history *DurableHistory) RecordRestart(componentID string, now time.Time) {
	history.RestartAttempts[componentID] = append(history.RestartAttempts[componentID], now.UTC().Format(time.RFC3339Nano))
}

func (history *DurableHistory) RebootAllowed(policy Policy, now time.Time) (bool, string) {
	history.Prune(now, policy)
	if !policy.HostRebootEnabled {
		return false, "HOST_REBOOT_DISABLED"
	}
	if len(history.RebootAttempts) >= policy.MaxRebootsPer24h {
		return false, "REBOOT_BUDGET_EXHAUSTED"
	}
	return true, ""
}

func (history *DurableHistory) RecordReboot(now time.Time) {
	history.RebootAttempts = append(history.RebootAttempts, now.UTC().Format(time.RFC3339Nano))
	history.PendingRebootAt = ""
}

type HistoryStore struct {
	Root string
}

func (store HistoryStore) Load() (DurableHistory, error) {
	if err := store.validateRoot(); err != nil {
		return DurableHistory{}, err
	}
	filename := filepath.Join(store.Root, "history.json")
	info, err := os.Lstat(filename)
	if errors.Is(err, os.ErrNotExist) {
		return NewDurableHistory(), nil
	}
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > 1<<20 {
		return DurableHistory{}, errors.New("watchdog durable history file is unsafe")
	}
	payload, err := os.ReadFile(filename)
	if err != nil {
		return DurableHistory{}, fmt.Errorf("read watchdog durable history: %w", err)
	}
	var history DurableHistory
	if err := json.Unmarshal(payload, &history); err != nil {
		return DurableHistory{}, errors.New("watchdog durable history is invalid")
	}
	if err := history.normalize(); err != nil {
		return DurableHistory{}, err
	}
	return history, nil
}

func (store HistoryStore) Save(history DurableHistory) error {
	if err := store.validateRoot(); err != nil {
		return err
	}
	if err := history.normalize(); err != nil {
		return err
	}
	payload, err := json.Marshal(history)
	if err != nil {
		return fmt.Errorf("encode watchdog durable history: %w", err)
	}
	if err := writeAtomicFile(filepath.Join(store.Root, "history.json"), payload, 0o600); err != nil {
		return err
	}
	return syncDirectory(store.Root)
}

func syncDirectory(path string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	directory, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open watchdog durable directory: %w", err)
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return fmt.Errorf("sync watchdog durable directory: %w", err)
	}
	return nil
}

func (store HistoryStore) validateRoot() error {
	if !filepath.IsAbs(store.Root) || filepath.Base(filepath.Clean(store.Root)) != "watchdog" {
		return errors.New("fixed absolute watchdog history root is required")
	}
	info, err := os.Lstat(store.Root)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return errors.New("watchdog history root is unsafe")
	}
	return nil
}

func writeAtomicFile(filename string, payload []byte, mode os.FileMode) error {
	directory := filepath.Dir(filename)
	info, err := os.Lstat(directory)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return errors.New("watchdog output directory is unsafe")
	}
	temporary, err := os.CreateTemp(directory, ".watchdog-")
	if err != nil {
		return fmt.Errorf("create watchdog temporary file: %w", err)
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)
	if err := temporary.Chmod(mode); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(payload); err != nil {
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
	if err := os.Rename(temporaryName, filename); err != nil {
		return fmt.Errorf("commit watchdog file: %w", err)
	}
	return nil
}
