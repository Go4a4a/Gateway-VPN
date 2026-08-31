package vpsupdate

import (
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"time"
)

const JournalFormatVersion = 1

type State string

const (
	StatePrepared       State = "PREPARED"
	StateQuiesced       State = "QUIESCED"
	StateCandidateReady State = "CANDIDATE_READY"
	StateDBSwitching    State = "DATABASE_SWITCHING"
	StateDBSwitched     State = "DATABASE_SWITCHED"
	StateReleaseSwitch  State = "RELEASE_SWITCHING"
	StateHealthChecking State = "HEALTH_CHECKING"
	StateStabilizing    State = "STABILIZING"
	StateRollingBack    State = "ROLLING_BACK"
	StateRolledBack     State = "ROLLED_BACK"
	StateFinalized      State = "FINALIZED"
	StateRollbackFailed State = "ROLLBACK_FAILED"
)

var errorCodePattern = regexp.MustCompile(`^(?:|[A-Z][A-Z0-9_]{0,95})$`)

type Journal struct {
	FormatVersion       int    `json:"format_version"`
	UpdateID            string `json:"update_id"`
	State               State  `json:"state"`
	StartedAt           string `json:"started_at"`
	UpdatedAt           string `json:"updated_at"`
	OldVersion          string `json:"old_version"`
	NewVersion          string `json:"new_version"`
	OldSchema           int64  `json:"old_schema"`
	NewSchema           int64  `json:"new_schema"`
	OldCurrentTarget    string `json:"old_current_target"`
	NewCurrentTarget    string `json:"new_current_target"`
	SnapshotSHA256      string `json:"snapshot_sha256,omitempty"`
	CandidateDBSHA256   string `json:"candidate_db_sha256,omitempty"`
	DatabaseSwitchBegun bool   `json:"database_switch_begun"`
	StabilityDeadline   string `json:"stability_deadline,omitempty"`
	ErrorCode           string `json:"error_code,omitempty"`
}

type Status struct {
	FormatVersion     int    `json:"format_version"`
	Available         bool   `json:"available"`
	UpdateID          string `json:"update_id,omitempty"`
	State             State  `json:"state,omitempty"`
	CurrentVersion    string `json:"current_version"`
	PreviousVersion   string `json:"previous_version,omitempty"`
	CandidateVersion  string `json:"candidate_version,omitempty"`
	CurrentSchema     int64  `json:"current_schema"`
	CandidateSchema   int64  `json:"candidate_schema,omitempty"`
	StartedAt         string `json:"started_at,omitempty"`
	UpdatedAt         string `json:"updated_at"`
	StabilityDeadline string `json:"stability_deadline,omitempty"`
	ErrorCode         string `json:"error_code,omitempty"`
	ReconnectRequired bool   `json:"management_reconnect_required"`
}

type JournalStore struct{ Root string }

// InProgress reports whether this journal still requires exclusive ownership
// of the VPS lifecycle. Terminal journals may remain on disk as durable audit
// evidence and must not permanently block reinstall or uninstall.
func (journal Journal) InProgress() bool {
	return journal.State != StateRolledBack && journal.State != StateFinalized
}

func (store JournalStore) Save(journal Journal) error {
	if err := validateJournal(journal); err != nil {
		return err
	}
	if err := store.prepare(); err != nil {
		return err
	}
	directory := filepath.Join(filepath.Clean(store.Root), journal.UpdateID)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return err
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		return err
	}
	if err := writeAtomicJSON(filepath.Join(directory, "journal.json"), journal, 0o600); err != nil {
		return err
	}
	return writeAtomicJSON(filepath.Join(store.Root, "active.json"), journal, 0o600)
}

func (store JournalStore) LoadActive() (Journal, bool, error) {
	exists, err := store.inspectRoot()
	if err != nil || !exists {
		return Journal{}, false, err
	}
	// Inspection is intentionally read-only: lifecycle checks are used by
	// installer dry-runs and uninstall guards and must not create or chmod
	// privileged state merely by observing it.
	if err := store.validateRoot(); err != nil {
		return Journal{}, false, err
	}
	// Save durably writes the per-transaction copy before active.json. Always
	// prefer unfinished transaction evidence, even when active.json still
	// contains a valid terminal journal from the preceding update.
	recoverable, recoverableExists, scanErr := store.scanRecoverableTransaction()
	if scanErr != nil {
		return Journal{}, false, scanErr
	}
	if recoverableExists {
		return recoverable, true, nil
	}
	active, activeExists, activeErr := readJournal(filepath.Join(store.Root, "active.json"))
	if activeErr == nil && activeExists {
		transaction, transactionExists, transactionErr := readJournal(filepath.Join(store.Root, active.UpdateID, "journal.json"))
		if transactionErr == nil && transactionExists && transaction.UpdateID == active.UpdateID {
			activeTime, _ := time.Parse(time.RFC3339Nano, active.UpdatedAt)
			transactionTime, _ := time.Parse(time.RFC3339Nano, transaction.UpdatedAt)
			if transactionTime.After(activeTime) {
				return transaction, true, nil
			}
		}
		// One durable valid copy is sufficient. The next Save repairs both.
		return active, true, nil
	}

	if activeErr != nil && !errors.Is(activeErr, os.ErrNotExist) {
		return Journal{}, false, errors.New("both VPS update journal copies are invalid")
	}
	return Journal{}, false, nil
}

func readJournal(path string) (Journal, bool, error) {
	content, err := readStable(path, 64<<10)
	if errors.Is(err, os.ErrNotExist) {
		return Journal{}, false, err
	}
	if err != nil {
		return Journal{}, false, err
	}
	var journal Journal
	if decodeStrict(content, &journal) != nil || validateJournal(journal) != nil {
		return Journal{}, false, errors.New("VPS update journal is invalid")
	}
	return journal, true, nil
}

func (store JournalStore) scanRecoverableTransaction() (Journal, bool, error) {
	entries, err := os.ReadDir(store.Root)
	if err != nil {
		return Journal{}, false, err
	}
	if len(entries) > 128 {
		return Journal{}, false, errors.New("VPS update transaction root exceeds its bound")
	}
	var candidate Journal
	found := false
	for _, entry := range entries {
		if !entry.IsDir() || !updateIDPattern.MatchString(entry.Name()) {
			continue
		}
		journal, exists, readErr := readJournal(filepath.Join(store.Root, entry.Name(), "journal.json"))
		if readErr != nil || !exists || journal.UpdateID != entry.Name() {
			continue
		}
		if !journal.InProgress() {
			continue
		}
		if found && journal.UpdateID != candidate.UpdateID {
			return Journal{}, false, errors.New("multiple recoverable VPS update transactions exist")
		}
		candidate, found = journal, true
	}
	return candidate, found, nil
}

func (store JournalStore) ClearActive() error {
	filename := filepath.Join(filepath.Clean(store.Root), "active.json")
	if err := os.Remove(filename); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return syncDirectory(filepath.Clean(store.Root))
}

func (store JournalStore) prepare() error {
	if !filepath.IsAbs(store.Root) || filepath.Base(filepath.Clean(store.Root)) != "update-transactions" {
		return errors.New("fixed VPS update transaction root is required")
	}
	if err := os.MkdirAll(store.Root, 0o700); err != nil {
		return err
	}
	if err := store.validateRoot(); err != nil {
		return err
	}
	return os.Chmod(store.Root, 0o700)
}

func (store JournalStore) inspectRoot() (bool, error) {
	if !filepath.IsAbs(store.Root) || filepath.Base(filepath.Clean(store.Root)) != "update-transactions" {
		return false, errors.New("fixed VPS update transaction root is required")
	}
	_, err := os.Lstat(store.Root)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	return err == nil, err
}

func (store JournalStore) validateRoot() error {
	info, err := os.Lstat(store.Root)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return errors.New("VPS update transaction root is unsafe")
	}
	return nil
}

type StatusStore struct {
	Path     string
	UID, GID int
}

func (store StatusStore) Write(status Status) error {
	if err := validateStatus(status); err != nil {
		return err
	}
	if !filepath.IsAbs(store.Path) || filepath.Base(store.Path) != "update-status.json" || store.UID < 0 || store.GID < 0 {
		return errors.New("fixed VPS update status destination is required")
	}
	if err := writeAtomicJSON(store.Path, status, 0o600); err != nil {
		return err
	}
	if err := chownPath(store.Path, store.UID, store.GID); err != nil {
		return err
	}
	return os.Chmod(store.Path, 0o640)
}

func (store StatusStore) Read() (Status, error) {
	if !filepath.IsAbs(store.Path) || filepath.Base(store.Path) != "update-status.json" {
		return Status{}, errors.New("fixed VPS update status path is required")
	}
	content, err := readStable(store.Path, 64<<10)
	if err != nil {
		return Status{}, err
	}
	var status Status
	if decodeStrict(content, &status) != nil || validateStatus(status) != nil {
		return Status{}, errors.New("VPS update status is invalid")
	}
	return status, nil
}

func validateJournal(value Journal) error {
	started, startErr := time.Parse(time.RFC3339Nano, value.StartedAt)
	updated, updateErr := time.Parse(time.RFC3339Nano, value.UpdatedAt)
	if value.FormatVersion != JournalFormatVersion || !updateIDPattern.MatchString(value.UpdateID) || !validState(value.State) || startErr != nil || updateErr != nil || updated.Before(started) || compareSemver(value.NewVersion, value.OldVersion) <= 0 || value.OldSchema < 1 || value.NewSchema < value.OldSchema || value.OldCurrentTarget != "releases/v"+value.OldVersion || value.NewCurrentTarget != "releases/v"+value.NewVersion || !errorCodePattern.MatchString(value.ErrorCode) {
		return errors.New("VPS update journal contract is invalid")
	}
	if value.SnapshotSHA256 != "" && !digestPattern.MatchString(value.SnapshotSHA256) || value.CandidateDBSHA256 != "" && !digestPattern.MatchString(value.CandidateDBSHA256) {
		return errors.New("VPS update journal digest is invalid")
	}
	if value.StabilityDeadline != "" {
		deadline, err := time.Parse(time.RFC3339Nano, value.StabilityDeadline)
		if err != nil || deadline.Before(started) {
			return errors.New("VPS update stability deadline is invalid")
		}
	}
	return nil
}

func validateStatus(value Status) error {
	updated, err := time.Parse(time.RFC3339Nano, value.UpdatedAt)
	if value.FormatVersion != JournalFormatVersion || !value.Available || err != nil || updated.IsZero() || compareSemver(value.CurrentVersion, "0.0.0") <= 0 || value.CurrentSchema < 1 || !errorCodePattern.MatchString(value.ErrorCode) {
		return errors.New("VPS update status contract is invalid")
	}
	if value.UpdateID != "" && (!updateIDPattern.MatchString(value.UpdateID) || !validState(value.State)) {
		return errors.New("VPS update status operation is invalid")
	}
	return nil
}

func validState(value State) bool {
	switch value {
	case StatePrepared, StateQuiesced, StateCandidateReady, StateDBSwitching, StateDBSwitched, StateReleaseSwitch, StateHealthChecking, StateStabilizing, StateRollingBack, StateRolledBack, StateFinalized, StateRollbackFailed:
		return true
	}
	return false
}
