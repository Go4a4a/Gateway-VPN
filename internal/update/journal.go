package update

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

const JournalFormatVersion = 1

type TransactionState string

const (
	StatePrepared              TransactionState = "PREPARED"
	StateQuiesced              TransactionState = "QUIESCED"
	StateCandidateReady        TransactionState = "CANDIDATE_READY"
	StateDatabaseSwitchPending TransactionState = "DATABASE_SWITCH_PENDING"
	StateDatabaseSwitched      TransactionState = "DATABASE_SWITCHED"
	StateReleaseSwitchPending  TransactionState = "RELEASE_SWITCH_PENDING"
	StateSwitched              TransactionState = "SWITCHED"
	StateHealthChecking        TransactionState = "HEALTH_CHECKING"
	StateStabilizing           TransactionState = "STABILIZING"
	StateRollingBack           TransactionState = "ROLLING_BACK"
	StateRolledBack            TransactionState = "ROLLED_BACK"
	StateRollbackFailed        TransactionState = "ROLLBACK_FAILED"
	StateFinalized             TransactionState = "FINALIZED"
)

var errorCodePattern = regexp.MustCompile(`^[A-Z0-9_]{0,64}$`)

type Journal struct {
	FormatVersion              int              `json:"format_version"`
	UpdateID                   string           `json:"update_id"`
	State                      TransactionState `json:"state"`
	StartedAt                  string           `json:"started_at"`
	UpdatedAt                  string           `json:"updated_at"`
	OldVersion                 string           `json:"old_version"`
	NewVersion                 string           `json:"new_version"`
	OldCurrentTarget           string           `json:"old_current_target"`
	NewCurrentTarget           string           `json:"new_current_target"`
	PreUpdateSnapshotID        string           `json:"pre_update_snapshot_id,omitempty"`
	OldSchemaVersion           int64            `json:"old_schema_version,omitempty"`
	NewSchemaVersion           int64            `json:"new_schema_version,omitempty"`
	CandidateDBSHA256          string           `json:"candidate_db_sha256,omitempty"`
	DatabaseReplacementStarted bool             `json:"database_replacement_started"`
	MihomoWasActive            bool             `json:"mihomo_was_active"`
	DNSMasqWasActive           bool             `json:"dnsmasq_was_active"`
	StabilityDeadline          string           `json:"stability_deadline,omitempty"`
	ErrorCode                  string           `json:"error_code,omitempty"`
}

type journalEnvelope struct {
	Journal Journal `json:"journal"`
	SHA256  string  `json:"sha256"`
}

type JournalStore struct {
	Root string
}

func (store JournalStore) Save(journal Journal) error {
	if !filepath.IsAbs(store.Root) || !validJournal(journal) {
		return errors.New("update journal root or contract is invalid")
	}
	if err := secureRealDirectory(store.Root, 0o700); err != nil {
		return err
	}
	transactionDirectory := filepath.Join(store.Root, journal.UpdateID)
	if err := secureRealDirectory(transactionDirectory, 0o700); err != nil {
		return err
	}
	content, err := encodeJournal(journal)
	if err != nil {
		return err
	}
	if err := writeAtomic(filepath.Join(transactionDirectory, "journal.json"), content, 0o600); err != nil {
		return err
	}
	if err := writeAtomic(filepath.Join(store.Root, "active.json"), content, 0o600); err != nil {
		return err
	}
	return syncDirectoryPath(store.Root)
}

func (store JournalStore) LoadActive() (Journal, bool, error) {
	if !filepath.IsAbs(store.Root) {
		return Journal{}, false, errors.New("absolute update journal root is required")
	}
	filename := filepath.Join(filepath.Clean(store.Root), "active.json")
	activeExists := pathExists(filename)
	recoverable, exists, err := store.findRecoverable()
	if err != nil {
		return Journal{}, false, err
	}
	if exists {
		// The per-transaction journal is written and synced before active.json.
		// Prefer it whenever it still describes unfinished work, including when
		// active.json contains the previous transaction or an older state.
		return recoverable, true, nil
	}
	if activeExists {
		active, err := readJournal(filename)
		if err != nil {
			return Journal{}, false, err
		}
		return active, true, nil
	}
	return Journal{}, false, nil
}

func (store JournalStore) findRecoverable() (Journal, bool, error) {
	entries, err := os.ReadDir(store.Root)
	if errors.Is(err, os.ErrNotExist) {
		return Journal{}, false, nil
	}
	if err != nil {
		return Journal{}, false, err
	}
	var candidates []Journal
	for _, entry := range entries {
		if !entry.IsDir() || !updateIDPattern.MatchString(entry.Name()) {
			continue
		}
		journal, err := readJournal(filepath.Join(store.Root, entry.Name(), "journal.json"))
		if err != nil {
			return Journal{}, false, err
		}
		if !terminalState(journal.State) {
			candidates = append(candidates, journal)
		}
	}
	if len(candidates) == 0 {
		return Journal{}, false, nil
	}
	sort.Slice(candidates, func(i, j int) bool { return candidates[i].StartedAt > candidates[j].StartedAt })
	if len(candidates) > 1 {
		return Journal{}, false, errors.New("multiple unfinished update journals require manual forensic recovery")
	}
	return candidates[0], true, nil
}

func encodeJournal(journal Journal) ([]byte, error) {
	plain, err := marshalLine(journal)
	if err != nil {
		return nil, errors.New("encode update journal failed")
	}
	digest := sha256.Sum256(plain)
	envelope := journalEnvelope{Journal: journal, SHA256: hex.EncodeToString(digest[:])}
	return marshalLine(envelope)
}

func readJournal(filename string) (Journal, error) {
	content, err := readBoundedRegular(filename, 64<<10)
	if err != nil {
		return Journal{}, errors.New("update journal is unavailable or unsafe")
	}
	var envelope journalEnvelope
	if err := decodeStrict(content, &envelope); err != nil || !digestPattern.MatchString(envelope.SHA256) || !validJournal(envelope.Journal) {
		return Journal{}, errors.New("update journal contract is invalid")
	}
	plain, err := marshalLine(envelope.Journal)
	if err != nil {
		return Journal{}, errors.New("re-encode update journal failed")
	}
	digest := sha256.Sum256(plain)
	if hex.EncodeToString(digest[:]) != envelope.SHA256 {
		return Journal{}, errors.New("update journal checksum mismatch")
	}
	return envelope.Journal, nil
}

func validJournal(journal Journal) bool {
	started, startErr := time.Parse(time.RFC3339Nano, journal.StartedAt)
	updated, updateErr := time.Parse(time.RFC3339Nano, journal.UpdatedAt)
	if journal.FormatVersion != JournalFormatVersion || !updateIDPattern.MatchString(journal.UpdateID) || !validTransactionState(journal.State) || startErr != nil || updateErr != nil || updated.Before(started) || !versionPattern.MatchString(journal.OldVersion) || !versionPattern.MatchString(journal.NewVersion) || journal.OldVersion == journal.NewVersion || journal.OldCurrentTarget != "releases/v"+journal.OldVersion || journal.NewCurrentTarget != "releases/v"+journal.NewVersion || !errorCodePattern.MatchString(journal.ErrorCode) {
		return false
	}
	if journal.PreUpdateSnapshotID != "" && !snapshotIDPatternForUpdate(journal.PreUpdateSnapshotID) {
		return false
	}
	if journal.OldSchemaVersion < 0 || journal.NewSchemaVersion < 0 || journal.CandidateDBSHA256 != "" && !digestPattern.MatchString(journal.CandidateDBSHA256) {
		return false
	}
	if journal.State == StateCandidateReady || stateMayHaveSwitchedDatabase(journal.State) || journal.DatabaseReplacementStarted {
		if journal.PreUpdateSnapshotID == "" || journal.OldSchemaVersion < 1 || journal.NewSchemaVersion < journal.OldSchemaVersion || !digestPattern.MatchString(journal.CandidateDBSHA256) {
			return false
		}
	}
	if journal.State == StateStabilizing || journal.State == StateFinalized {
		deadline, err := time.Parse(time.RFC3339Nano, journal.StabilityDeadline)
		if err != nil || deadline.Before(updated) && journal.State == StateStabilizing {
			return false
		}
	} else if journal.StabilityDeadline != "" && journal.State != StateRollingBack && journal.State != StateRolledBack && journal.State != StateRollbackFailed {
		return false
	}
	return true
}

func validTransactionState(state TransactionState) bool {
	switch state {
	case StatePrepared, StateQuiesced, StateCandidateReady, StateDatabaseSwitchPending, StateDatabaseSwitched, StateReleaseSwitchPending, StateSwitched, StateHealthChecking, StateStabilizing, StateRollingBack, StateRolledBack, StateRollbackFailed, StateFinalized:
		return true
	default:
		return false
	}
}

func stateMayHaveSwitchedDatabase(state TransactionState) bool {
	switch state {
	case StateDatabaseSwitchPending, StateDatabaseSwitched, StateReleaseSwitchPending, StateSwitched, StateHealthChecking, StateStabilizing, StateFinalized:
		return true
	default:
		return false
	}
}

func terminalState(state TransactionState) bool {
	// STABILIZING still owns the rollback snapshot and must remain recoverable
	// when active.json is lost after an otherwise durable per-transaction write.
	return state == StateRolledBack || state == StateFinalized
}

func snapshotIDPatternForUpdate(value string) bool {
	// Snapshot IDs are generated by internal/backup and deliberately repeated
	// here so a corrupted journal cannot inject a path into recovery.
	matched, _ := regexp.MatchString(`^[0-9]{8}T[0-9]{6}\.[0-9]{9}Z-[a-f0-9]{24}$`, value)
	return matched
}

func secureRealDirectory(directory string, mode os.FileMode) error {
	if err := os.MkdirAll(directory, mode); err != nil {
		return fmt.Errorf("create secure update directory: %w", err)
	}
	info, err := os.Lstat(directory)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return errors.New("update directory must be real and non-symlink")
	}
	return os.Chmod(directory, mode)
}

func writeAtomic(filename string, content []byte, mode os.FileMode) error {
	temporary := filename + ".tmp"
	if err := os.Remove(temporary); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := writeExclusive(temporary, content, mode); err != nil {
		return err
	}
	if err := replaceFile(temporary, filename); err != nil {
		_ = os.Remove(temporary)
		return err
	}
	return syncDirectoryPath(filepath.Dir(filename))
}

func sanitizedErrorCode(value string) string {
	value = strings.ToUpper(value)
	var output strings.Builder
	for _, character := range value {
		if character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || character == '_' {
			output.WriteRune(character)
		}
		if output.Len() == 64 {
			break
		}
	}
	if output.Len() == 0 {
		return "UPDATE_FAILED"
	}
	return output.String()
}
