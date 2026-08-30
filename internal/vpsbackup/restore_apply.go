package vpsbackup

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"gateway-vpn/internal/backup"
	databasepkg "gateway-vpn/internal/db"
	"gateway-vpn/internal/vpsagent"
	"gateway-vpn/internal/wgingress"
)

var ErrRestoreSafelyRolledBack = errors.New("VPS restore failed and was safely rolled back")

const (
	applyJournalVersion = 1
	applyPrepared       = "PREPARED"
	applyApplying       = "APPLYING"
	applyCommitted      = "COMMITTED"
	applyRolledBack     = "ROLLED_BACK"
)

type swapItem struct {
	Name           string `json:"name"`
	Kind           string `json:"kind"`
	Destination    string `json:"destination"`
	Candidate      string `json:"candidate,omitempty"`
	Rollback       string `json:"rollback"`
	OriginalExists bool   `json:"original_exists"`
}

type applyJournal struct {
	FormatVersion      int         `json:"format_version"`
	RestoreID          string      `json:"restore_id"`
	State              string      `json:"state"`
	Mode               string      `json:"mode"`
	ApplyAuthorization string      `json:"apply_authorization"`
	PreRestoreSnapshot string      `json:"pre_restore_snapshot"`
	Items              []swapItem  `json:"items"`
	AppliedItems       int         `json:"applied_items"`
	Result             ApplyResult `json:"result"`
	RollbackErrorCode  string      `json:"rollback_error_code,omitempty"`
}

type snapshotManifest struct {
	FormatVersion int          `json:"format_version"`
	RestoreID     string       `json:"restore_id"`
	CreatedAt     string       `json:"created_at"`
	Files         []FileRecord `json:"files"`
}

type generatedIdentity struct {
	Input          vpsagent.IdentityInput
	WireGuardKey   []byte
	UpdateKey      []byte
	TLSCertificate []byte
	TLSKey         []byte
}

type RestoreApplier struct {
	Manager          *RestoreManager
	TransactionRoot  string
	WireGuardConfig  string
	AgentUID         int
	AgentGID         int
	Now              func() time.Time
	AfterAppliedItem func(int) error
}

func NewRestoreApplier(manager *RestoreManager, transactionRoot string, agentUID, agentGID int) (*RestoreApplier, error) {
	if manager == nil || !filepath.IsAbs(transactionRoot) || agentUID < -1 || agentGID < -1 {
		return nil, errors.New("VPS restore applier requires a manager, absolute transaction root and valid ownership")
	}
	wireGuardConfig := "/etc/wireguard/wg-mgmt.conf"
	if filepath.Clean(manager.StateDirectory) != productionStateRoot {
		wireGuardConfig = filepath.Join(manager.StateDirectory, "wg-mgmt.conf")
	}
	return &RestoreApplier{Manager: manager, TransactionRoot: filepath.Clean(transactionRoot), WireGuardConfig: wireGuardConfig, AgentUID: agentUID, AgentGID: agentGID}, nil
}

func (applier *RestoreApplier) Apply(ctx context.Context) (ApplyResult, error) {
	if err := applier.validate(); err != nil {
		return ApplyResult{}, err
	}
	verified, err := applier.Manager.VerifyPending(ctx)
	if err != nil {
		return ApplyResult{}, err
	}
	operation := verified.Operation
	if operation.State != RestoreStateApplyRequested || !containsMode(operation.AllowedModes, operation.SelectedMode) || !digestPattern.MatchString(operation.ApplyAuthorization) {
		return ApplyResult{}, errors.New("VPS restore apply was not explicitly authorized")
	}
	if operation.SelectedMode == RestoreModeSameVPS && !operation.IdentityMatches {
		return ApplyResult{}, errors.New("same-VPS restore identity does not match the live VPS")
	}
	snapshot, err := applier.createPreRestoreSnapshot(ctx, operation.RestoreID)
	if err != nil {
		_ = applier.Manager.markApplyFailure(operation.RestoreID, "PRE_RESTORE_SNAPSHOT_FAILED")
		return ApplyResult{}, err
	}
	items := applier.restoreItems(operation.RestoreID, operation.SelectedMode)
	identity, err := applier.prepareCandidates(ctx, verified, items)
	if err != nil {
		_ = applier.cleanupItems(items)
		_ = applier.Manager.markApplyFailure(operation.RestoreID, "CANDIDATE_PREPARATION_FAILED")
		return ApplyResult{}, err
	}
	journal := applyJournal{
		FormatVersion: applyJournalVersion, RestoreID: operation.RestoreID, State: applyPrepared,
		Mode: operation.SelectedMode, ApplyAuthorization: operation.ApplyAuthorization,
		PreRestoreSnapshot: snapshot, Items: items,
	}
	journalPath := applier.journalPath(operation.RestoreID)
	if applier.Manager.Database != nil {
		if err := applier.Manager.Database.Close(); err != nil {
			_ = applier.cleanupItems(items)
			_ = applier.Manager.markApplyFailure(operation.RestoreID, "DATABASE_STOP_FAILED")
			return ApplyResult{}, errors.New("close live VPS database before restore failed")
		}
		applier.Manager.Database = nil
	}
	// SQLite may remove WAL/SHM when the final connection closes. Record the
	// exact post-stop filesystem state that the durable journal will govern.
	for index := range journal.Items {
		exists, err := safeDestinationExists(journal.Items[index].Destination, journal.Items[index].Kind)
		if err != nil {
			_ = applier.cleanupItems(journal.Items)
			_ = applier.Manager.markApplyFailure(operation.RestoreID, "DESTINATION_VALIDATION_FAILED")
			return ApplyResult{}, err
		}
		journal.Items[index].OriginalExists = exists
	}
	if err := applier.writeJournal(journalPath, journal, false); err != nil {
		_ = applier.cleanupItems(journal.Items)
		_ = applier.Manager.markApplyFailure(operation.RestoreID, "APPLY_JOURNAL_FAILED")
		return ApplyResult{}, err
	}
	journal.State = applyApplying
	if err := applier.writeJournal(journalPath, journal, true); err != nil {
		return applier.rollbackFailure(operation.RestoreID, journal, journalPath, err)
	}
	for index := range journal.Items {
		if err := ctx.Err(); err != nil {
			return applier.rollbackFailure(operation.RestoreID, journal, journalPath, err)
		}
		if err := applySwapItem(&journal.Items[index]); err != nil {
			return applier.rollbackFailure(operation.RestoreID, journal, journalPath, err)
		}
		journal.AppliedItems = index + 1
		if err := applier.writeJournal(journalPath, journal, true); err != nil {
			return applier.rollbackFailure(operation.RestoreID, journal, journalPath, err)
		}
		if applier.AfterAppliedItem != nil {
			if err := applier.AfterAppliedItem(index + 1); err != nil {
				return applier.rollbackFailure(operation.RestoreID, journal, journalPath, err)
			}
		}
	}
	if err := applier.verifyActivated(ctx, identity, operation.SelectedMode); err != nil {
		return applier.rollbackFailure(operation.RestoreID, journal, journalPath, err)
	}
	result := ApplyResult{
		RestoreID: operation.RestoreID, Mode: operation.SelectedMode, VPSID: identity.VPSID,
		IdentityFingerprint: identity.IdentityFingerprint, PreRestoreSnapshot: snapshot,
		AppliedAt: applier.now().Format(time.RFC3339Nano), ReconcileRequired: true,
		Quarantined: operation.SelectedMode == RestoreModeSameVPS,
	}
	journal.State, journal.Result = applyCommitted, result
	if err := applier.writeJournal(journalPath, journal, true); err != nil {
		return applier.rollbackFailure(operation.RestoreID, journal, journalPath, err)
	}
	return applier.finalizeCommitted(journalPath, journal)
}

// Recover is called by the boot-time privileged unit before VPS Agent starts.
// PREPARED/APPLYING always rolls back; COMMITTED only completes cleanup. Thus
// an interrupted transaction can never be guessed or silently re-applied.
func (applier *RestoreApplier) Recover(_ context.Context) (bool, error) {
	if err := applier.validate(); err != nil {
		return false, err
	}
	entries, err := os.ReadDir(applier.TransactionRoot)
	if err != nil {
		return false, err
	}
	var journals []string
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".json") {
			journals = append(journals, filepath.Join(applier.TransactionRoot, entry.Name()))
		}
	}
	if len(journals) == 0 {
		return false, nil
	}
	if len(journals) != 1 {
		return false, errors.New("multiple VPS restore recovery journals require operator intervention")
	}
	journal, err := applier.readJournal(journals[0])
	if err != nil {
		return false, err
	}
	if applier.Manager.Database != nil {
		if err := applier.Manager.Database.Close(); err != nil {
			return false, err
		}
		applier.Manager.Database = nil
	}
	switch journal.State {
	case applyPrepared, applyApplying:
		if err := applier.rollbackItems(journal.Items); err != nil {
			return false, err
		}
		journal.State, journal.RollbackErrorCode = applyRolledBack, "BOOT_RECOVERY_ROLLBACK"
		if err := applier.writeJournal(journals[0], journal, true); err != nil {
			return false, err
		}
		if err := applier.Manager.markApplyFailure(journal.RestoreID, journal.RollbackErrorCode); err != nil {
			return false, err
		}
		return true, applier.removeJournal(journals[0])
	case applyCommitted:
		_, err := applier.finalizeCommitted(journals[0], journal)
		return true, err
	case applyRolledBack:
		if err := applier.Manager.markApplyFailure(journal.RestoreID, journal.RollbackErrorCode); err != nil && !errors.Is(err, ErrRestoreNotPending) {
			return false, err
		}
		return true, applier.removeJournal(journals[0])
	default:
		return false, errors.New("VPS restore recovery journal state is invalid")
	}
}

func (applier *RestoreApplier) prepareCandidates(ctx context.Context, verified VerifiedRestore, items []swapItem) (vpsagent.Identity, error) {
	sources := map[string]string{
		"config":   filepath.Join(verified.TreeRoot, "config", "config.yaml"),
		"database": filepath.Join(verified.TreeRoot, "database", "state.db"),
		"secrets":  filepath.Join(verified.TreeRoot, "state", "secrets"),
		"tls":      filepath.Join(verified.TreeRoot, "state", "tls"),
	}
	for index := range items {
		item := &items[index]
		exists, err := safeDestinationExists(item.Destination, item.Kind)
		if err != nil {
			return vpsagent.Identity{}, err
		}
		item.OriginalExists = exists
		if item.Candidate == "" {
			continue
		}
		if item.Name == "wireguard" {
			continue
		}
		if err := removeSafePath(item.Candidate); err != nil {
			return vpsagent.Identity{}, err
		}
		source := sources[item.Name]
		if item.Kind == "file" {
			if err := copyProtectedFile(ctx, source, item.Candidate, 0o600); err != nil {
				return vpsagent.Identity{}, err
			}
		} else if err := copyProtectedTree(ctx, source, item.Candidate); err != nil {
			return vpsagent.Identity{}, err
		}
		uid, gid := applier.AgentUID, applier.AgentGID
		if item.Name == "config" {
			uid, gid = 0, applier.AgentGID
			if err := os.Chmod(item.Candidate, 0o640); err != nil {
				return vpsagent.Identity{}, err
			}
		}
		if err := applyOwnershipTree(item.Candidate, uid, gid); err != nil {
			return vpsagent.Identity{}, err
		}
	}
	databaseCandidate := candidateFor(items, "database")
	database, err := vpsagent.Open(ctx, databaseCandidate)
	if err != nil {
		return vpsagent.Identity{}, err
	}
	identity := verified.Identity
	if verified.Operation.SelectedMode == RestoreModeSameVPS {
		err = vpsagent.QuarantineRestoredRuntime(ctx, database, applier.now())
		if err == nil {
			identity, err = vpsagent.ReadIdentity(ctx, database)
		}
	} else {
		generated, generateErr := generateNewIdentity(identity, applier.now())
		if generateErr != nil {
			database.Close()
			return vpsagent.Identity{}, generateErr
		}
		identity, err = vpsagent.ImportPortableAsNew(ctx, database, generated.Input, applier.now())
		if err == nil {
			// Imported administrator identities and peers are deleted from the
			// candidate database. Their not-yet-delivered private keys must be
			// deleted from the candidate tree as well, otherwise the new VPS
			// would retain orphaned credentials owned by the source VPS.
			err = removeSafePath(filepath.Join(candidateFor(items, "secrets"), "administrators"))
		}
		if err == nil {
			err = installGeneratedIdentity(candidateFor(items, "secrets"), candidateFor(items, "tls"), generated)
			if err == nil {
				err = applyOwnershipTree(candidateFor(items, "secrets"), applier.AgentUID, applier.AgentGID)
			}
			if err == nil {
				err = applyOwnershipTree(candidateFor(items, "tls"), applier.AgentUID, applier.AgentGID)
			}
			if err == nil {
				err = installGeneratedWireGuardConfig(candidateFor(items, "wireguard"), generated)
			}
		}
	}
	if err == nil {
		_, err = database.ExecContext(ctx, "PRAGMA wal_checkpoint(TRUNCATE)")
	}
	closeErr := database.Close()
	for _, suffix := range []string{"-wal", "-shm"} {
		if removeErr := os.Remove(databaseCandidate + suffix); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) && err == nil {
			err = removeErr
		}
	}
	if err != nil || closeErr != nil {
		return vpsagent.Identity{}, errors.Join(err, closeErr)
	}
	if err := os.Chmod(databaseCandidate, 0o600); err != nil {
		return vpsagent.Identity{}, err
	}
	if err := applyOwnershipTree(databaseCandidate, applier.AgentUID, applier.AgentGID); err != nil {
		return vpsagent.Identity{}, err
	}
	verifiedDatabase, err := databasepkg.OpenImmutable(ctx, databaseCandidate)
	if err != nil {
		return vpsagent.Identity{}, err
	}
	verifyErr := vpsagent.Verify(ctx, verifiedDatabase)
	actualIdentity, identityErr := vpsagent.ReadIdentity(ctx, verifiedDatabase)
	closeErr = verifiedDatabase.Close()
	if verifyErr != nil || identityErr != nil || closeErr != nil || actualIdentity.VPSID != identity.VPSID || actualIdentity.IdentityFingerprint != identity.IdentityFingerprint {
		return vpsagent.Identity{}, errors.New("prepared VPS restore candidate failed final verification")
	}
	return identity, nil
}

func (applier *RestoreApplier) createPreRestoreSnapshot(ctx context.Context, restoreID string) (string, error) {
	root := filepath.Join(applier.Manager.StateDirectory, "backups", "pre-restore")
	if err := secureDirectory(root); err != nil {
		return "", err
	}
	final := filepath.Join(root, restoreID)
	temporary := filepath.Join(root, ".tmp-"+restoreID)
	if err := os.Mkdir(temporary, 0o700); err != nil {
		return "", err
	}
	defer os.RemoveAll(temporary)
	files := []struct {
		name, source string
		tree         bool
		optional     bool
	}{
		{"config/config.yaml", applier.Manager.ConfigurationPath, false, false},
		{"state/secrets", filepath.Join(applier.Manager.StateDirectory, "secrets"), true, false},
		{"state/tls", filepath.Join(applier.Manager.StateDirectory, "tls"), true, false},
		{"host/wg-mgmt.conf", applier.WireGuardConfig, false, true},
	}
	databaseDestination := filepath.Join(temporary, "database", "state.db")
	if err := os.MkdirAll(filepath.Dir(databaseDestination), 0o700); err != nil {
		return "", err
	}
	if err := onlineBackup(ctx, applier.Manager.Database, databaseDestination); err != nil {
		return "", err
	}
	for _, item := range files {
		destination := filepath.Join(temporary, filepath.FromSlash(item.name))
		if item.optional {
			if _, err := os.Lstat(item.source); errors.Is(err, os.ErrNotExist) {
				continue
			} else if err != nil {
				return "", err
			}
		}
		if item.tree {
			if err := copyProtectedTree(ctx, item.source, destination); err != nil {
				return "", err
			}
		} else if err := copyProtectedFile(ctx, item.source, destination, 0o600); err != nil {
			return "", err
		}
	}
	records, err := recordsForTree(ctx, temporary)
	if err != nil {
		return "", err
	}
	manifest := snapshotManifest{FormatVersion: 1, RestoreID: restoreID, CreatedAt: applier.now().Format(time.RFC3339Nano), Files: records}
	if err := writeJSON(filepath.Join(temporary, "snapshot.json"), manifest, false); err != nil {
		return "", err
	}
	database, err := databasepkg.OpenImmutable(ctx, databaseDestination)
	if err != nil {
		return "", err
	}
	verifyErr := vpsagent.Verify(ctx, database)
	closeErr := database.Close()
	if verifyErr != nil || closeErr != nil {
		return "", errors.Join(verifyErr, closeErr)
	}
	if err := syncDirectory(temporary); err != nil {
		return "", err
	}
	if err := os.Rename(temporary, final); err != nil {
		return "", err
	}
	if err := syncDirectory(root); err != nil {
		return "", err
	}
	return final, nil
}

func (applier *RestoreApplier) verifyActivated(ctx context.Context, expected vpsagent.Identity, mode string) error {
	database, err := databasepkg.OpenImmutable(ctx, applier.Manager.DatabasePath())
	if err != nil {
		return err
	}
	identity, identityErr := vpsagent.ReadIdentity(ctx, database)
	verifyErr := vpsagent.Verify(ctx, database)
	closeErr := database.Close()
	if identityErr != nil || verifyErr != nil || closeErr != nil || identity.VPSID != expected.VPSID || identity.IdentityFingerprint != expected.IdentityFingerprint {
		return errors.New("activated VPS restore database failed verification")
	}
	for _, path := range []string{applier.Manager.ConfigurationPath, filepath.Join(applier.Manager.StateDirectory, "tls", "cert.pem"), filepath.Join(applier.Manager.StateDirectory, "tls", "key.pem")} {
		info, err := os.Lstat(path)
		if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() == 0 {
			return errors.New("activated VPS restore file set is incomplete")
		}
	}
	if mode == RestoreModeNewVPS {
		if err := verifyImportedWireGuardConfig(applier.WireGuardConfig, expected.PublicKey); err != nil {
			return err
		}
	}
	return nil
}

func (manager *RestoreManager) DatabasePath() string {
	return manager.DatabaseFile
}

func (applier *RestoreApplier) restoreItems(restoreID, mode string) []swapItem {
	item := func(name, kind, destination string, install bool) swapItem {
		base := ".gateway-vpn-vps-" + restoreID + "-" + name
		candidate := ""
		if install {
			candidate = filepath.Join(filepath.Dir(destination), base+".candidate")
		}
		return swapItem{Name: name, Kind: kind, Destination: destination, Candidate: candidate, Rollback: filepath.Join(filepath.Dir(destination), base+".rollback")}
	}
	databasePath := applier.Manager.DatabasePath()
	items := []swapItem{
		item("config", "file", applier.Manager.ConfigurationPath, true),
		item("database", "file", databasePath, true),
		item("secrets", "directory", filepath.Join(applier.Manager.StateDirectory, "secrets"), true),
		item("tls", "directory", filepath.Join(applier.Manager.StateDirectory, "tls"), true),
		item("database-wal", "remove", databasePath+"-wal", false),
		item("database-shm", "remove", databasePath+"-shm", false),
	}
	if mode == RestoreModeNewVPS {
		items = append(items, item("wireguard", "file", applier.WireGuardConfig, true))
	}
	return items
}

func (applier *RestoreApplier) rollbackFailure(restoreID string, journal applyJournal, journalPath string, cause error) (ApplyResult, error) {
	if err := applier.rollbackItems(journal.Items); err != nil {
		return ApplyResult{}, errors.Join(cause, err)
	}
	journal.State, journal.RollbackErrorCode = applyRolledBack, "RESTORE_APPLY_FAILED_ROLLED_BACK"
	if err := applier.writeJournal(journalPath, journal, true); err != nil {
		return ApplyResult{}, errors.Join(cause, err)
	}
	markErr := applier.Manager.markApplyFailure(restoreID, journal.RollbackErrorCode)
	removeErr := error(nil)
	if markErr == nil {
		removeErr = applier.removeJournal(journalPath)
	}
	return ApplyResult{}, errors.Join(cause, ErrRestoreSafelyRolledBack, markErr, removeErr)
}

func (applier *RestoreApplier) rollbackItems(items []swapItem) error {
	var failures []error
	for index := len(items) - 1; index >= 0; index-- {
		item := items[index]
		rollbackExists := pathExists(item.Rollback)
		if rollbackExists {
			failures = append(failures, removeSafePath(item.Destination))
			if err := os.Rename(item.Rollback, item.Destination); err != nil {
				failures = append(failures, err)
			}
		} else if !item.OriginalExists {
			failures = append(failures, removeSafePath(item.Destination))
		}
		if item.Candidate != "" {
			failures = append(failures, removeSafePath(item.Candidate))
		}
		failures = append(failures, syncDirectory(filepath.Dir(item.Destination)))
	}
	return errors.Join(failures...)
}

func (applier *RestoreApplier) finalizeCommitted(journalPath string, journal applyJournal) (ApplyResult, error) {
	for _, item := range journal.Items {
		if err := removeSafePath(item.Rollback); err != nil {
			return ApplyResult{}, err
		}
		if item.Candidate != "" {
			if err := removeSafePath(item.Candidate); err != nil {
				return ApplyResult{}, err
			}
		}
	}
	if err := applier.Manager.complete(journal.RestoreID, journal.Result); err != nil {
		return ApplyResult{}, err
	}
	if err := applier.removeJournal(journalPath); err != nil {
		return ApplyResult{}, err
	}
	return journal.Result, nil
}

func applySwapItem(item *swapItem) error {
	if item.OriginalExists {
		if pathExists(item.Rollback) {
			return errors.New("VPS restore rollback destination already exists")
		}
		if err := os.Rename(item.Destination, item.Rollback); err != nil {
			return err
		}
	}
	if item.Candidate != "" {
		if err := os.Rename(item.Candidate, item.Destination); err != nil {
			return err
		}
	}
	return syncDirectory(filepath.Dir(item.Destination))
}

func (applier *RestoreApplier) cleanupItems(items []swapItem) error {
	var failures []error
	for _, item := range items {
		if item.Candidate != "" {
			failures = append(failures, removeSafePath(item.Candidate))
		}
		failures = append(failures, removeSafePath(item.Rollback))
	}
	return errors.Join(failures...)
}

func (applier *RestoreApplier) validate() error {
	if applier == nil || applier.Manager == nil || !filepath.IsAbs(applier.TransactionRoot) || !filepath.IsAbs(applier.WireGuardConfig) || filepath.Base(applier.WireGuardConfig) != "wg-mgmt.conf" {
		return errors.New("VPS restore applier is incomplete")
	}
	if filepath.Clean(applier.Manager.StateDirectory) == productionStateRoot {
		if filepath.Clean(applier.WireGuardConfig) != "/etc/wireguard/wg-mgmt.conf" {
			return errors.New("production VPS WireGuard restore destination is invalid")
		}
	} else if filepath.Dir(filepath.Clean(applier.WireGuardConfig)) != filepath.Clean(applier.Manager.StateDirectory) {
		return errors.New("test VPS WireGuard restore destination escapes its state directory")
	}
	return secureDirectory(applier.TransactionRoot)
}

func (applier *RestoreApplier) journalPath(restoreID string) string {
	return filepath.Join(applier.TransactionRoot, restoreID+".json")
}

func (applier *RestoreApplier) writeJournal(path string, journal applyJournal, replace bool) error {
	if err := applier.validateJournal(journal); err != nil {
		return err
	}
	return writeJSON(path, journal, replace)
}

func (applier *RestoreApplier) readJournal(path string) (applyJournal, error) {
	var journal applyJournal
	content, err := readSmallJSON(path)
	if err != nil {
		return journal, err
	}
	if err := decodeStrict(content, &journal); err != nil || applier.validateJournal(journal) != nil {
		return applyJournal{}, errors.New("VPS restore recovery journal is invalid")
	}
	return journal, nil
}

func (applier *RestoreApplier) validateJournal(journal applyJournal) error {
	if journal.FormatVersion != applyJournalVersion || !vpsRestoreIDPattern.MatchString(journal.RestoreID) || !containsMode([]string{RestoreModeSameVPS, RestoreModeNewVPS}, journal.Mode) || !digestPattern.MatchString(journal.ApplyAuthorization) || journal.AppliedItems < 0 || journal.AppliedItems > len(journal.Items) || journal.PreRestoreSnapshot != filepath.Join(applier.Manager.StateDirectory, "backups", "pre-restore", journal.RestoreID) {
		return errors.New("VPS restore journal contract is invalid")
	}
	expected := applier.restoreItems(journal.RestoreID, journal.Mode)
	if len(expected) != len(journal.Items) {
		return errors.New("VPS restore journal item count is invalid")
	}
	for index := range expected {
		actual, wanted := journal.Items[index], expected[index]
		if actual.Name != wanted.Name || actual.Kind != wanted.Kind || actual.Destination != wanted.Destination || actual.Candidate != wanted.Candidate || actual.Rollback != wanted.Rollback {
			return errors.New("VPS restore journal contains an unexpected path")
		}
	}
	switch journal.State {
	case applyPrepared, applyApplying:
		if journal.Result.RestoreID != "" || journal.RollbackErrorCode != "" {
			return errors.New("unfinished VPS restore journal has a result")
		}
	case applyCommitted:
		if journal.Result.RestoreID != journal.RestoreID || journal.Result.Mode != journal.Mode || journal.Result.AppliedAt == "" || !journal.Result.ReconcileRequired || journal.RollbackErrorCode != "" {
			return errors.New("committed VPS restore journal result is invalid")
		}
	case applyRolledBack:
		if !validErrorCode(journal.RollbackErrorCode) {
			return errors.New("rolled-back VPS restore journal is invalid")
		}
	default:
		return errors.New("VPS restore journal state is invalid")
	}
	return nil
}

func (applier *RestoreApplier) removeJournal(path string) error {
	if filepath.Dir(path) != applier.TransactionRoot || !vpsRestoreIDPattern.MatchString(strings.TrimSuffix(filepath.Base(path), ".json")) {
		return errors.New("refuse to remove unmanaged VPS restore journal")
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return syncDirectory(applier.TransactionRoot)
}

func candidateFor(items []swapItem, name string) string {
	for _, item := range items {
		if item.Name == name {
			return item.Candidate
		}
	}
	return ""
}

func safeDestinationExists(path, kind string) (bool, error) {
	parent, err := os.Lstat(filepath.Dir(path))
	if err != nil || parent.Mode()&os.ModeSymlink != 0 || !parent.IsDir() {
		return false, errors.New("VPS restore destination parent is unsafe")
	}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil || info.Mode()&os.ModeSymlink != 0 {
		return false, errors.New("VPS restore destination is unsafe")
	}
	if kind == "file" && !info.Mode().IsRegular() || kind == "directory" && !info.IsDir() || kind == "remove" && !info.Mode().IsRegular() {
		return false, errors.New("VPS restore destination type is invalid")
	}
	return true, nil
}

func copyProtectedFile(ctx context.Context, source, destination string, mode os.FileMode) error {
	info, err := os.Lstat(source)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() < 0 || info.Size() > MaximumFileBytes {
		return errors.New("VPS restore copy source is unsafe")
	}
	if err := os.MkdirAll(filepath.Dir(destination), 0o700); err != nil {
		return err
	}
	input, err := openStableFile(source, info.Size())
	if err != nil {
		return err
	}
	defer input.Close()
	output, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	written, copyErr := copyContext(ctx, output, input)
	syncErr, closeErr := output.Sync(), output.Close()
	if copyErr != nil || syncErr != nil || closeErr != nil || written != info.Size() {
		return errors.Join(errors.New("copy protected VPS restore file failed"), copyErr, syncErr, closeErr)
	}
	return nil
}

func copyProtectedTree(ctx context.Context, source, destination string) error {
	info, err := os.Lstat(source)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return errors.New("VPS restore tree source is unsafe")
	}
	if err := os.MkdirAll(filepath.Dir(destination), 0o700); err != nil {
		return err
	}
	if err := os.Mkdir(destination, 0o700); err != nil {
		return err
	}
	files, total := 0, int64(0)
	return filepath.WalkDir(source, func(current string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if current == source {
			return nil
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		entryInfo, err := os.Lstat(current)
		if err != nil || entryInfo.Mode()&os.ModeSymlink != 0 {
			return errors.New("VPS restore tree contains an unsafe entry")
		}
		relative, err := filepath.Rel(source, current)
		if err != nil {
			return err
		}
		target := filepath.Join(destination, relative)
		if entryInfo.IsDir() {
			return os.Mkdir(target, 0o700)
		}
		if !entryInfo.Mode().IsRegular() || files >= MaximumFiles || total > backup.MaximumPortablePlainBytes-entryInfo.Size() {
			return errors.New("VPS restore tree exceeds safety bounds")
		}
		files++
		total += entryInfo.Size()
		return copyProtectedFile(ctx, current, target, 0o600)
	})
}

func applyOwnershipTree(root string, uid, gid int) error {
	if runtime.GOOS == "windows" || uid < 0 && gid < 0 {
		return nil
	}
	return filepath.WalkDir(root, func(path string, _ os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		return os.Chown(path, uid, gid)
	})
}

func recordsForTree(ctx context.Context, root string) ([]FileRecord, error) {
	var records []FileRecord
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == root || entry.IsDir() {
			return nil
		}
		info, err := os.Lstat(path)
		if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return errors.New("pre-restore snapshot contains an unsafe file")
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		digest, err := hashPath(ctx, path, info.Size())
		if err != nil {
			return err
		}
		records = append(records, FileRecord{Path: filepath.ToSlash(relative), Bytes: info.Size(), SHA256: digest, Mode: 0o600})
		return nil
	})
	sort.Slice(records, func(i, j int) bool { return records[i].Path < records[j].Path })
	return records, err
}

func generateNewIdentity(source vpsagent.Identity, now time.Time) (generatedIdentity, error) {
	pair, err := wgingress.GenerateKeyPair()
	if err != nil {
		return generatedIdentity{}, err
	}
	randomID, updateKey := make([]byte, 16), make([]byte, 32)
	if _, err := rand.Read(randomID); err != nil {
		return generatedIdentity{}, err
	}
	if _, err := rand.Read(updateKey); err != nil {
		return generatedIdentity{}, err
	}
	fingerprint := sha256.Sum256([]byte(pair.Public))
	vpsID := "vps-" + hex.EncodeToString(randomID)
	certificate, tlsKey, err := generateSelfSignedTLS(vpsID, now)
	if err != nil {
		return generatedIdentity{}, err
	}
	return generatedIdentity{
		Input: vpsagent.IdentityInput{
			VPSID: vpsID, DisplayName: source.DisplayName + " (imported)", IdentityFingerprint: hex.EncodeToString(fingerprint[:]),
			PublicKey: pair.Public, PrivateKeySecretRef: source.PrivateKeySecretRef, UpdateIdentityRef: source.UpdateIdentityRef,
		},
		WireGuardKey: []byte(pair.Private + "\n"), UpdateKey: []byte(hex.EncodeToString(updateKey) + "\n"),
		TLSCertificate: certificate, TLSKey: tlsKey,
	}, nil
}

func installGeneratedIdentity(secretsRoot, tlsRoot string, generated generatedIdentity) error {
	for _, item := range []struct {
		path    string
		content []byte
	}{
		{secretCandidatePath(secretsRoot, generated.Input.PrivateKeySecretRef), generated.WireGuardKey},
		{secretCandidatePath(secretsRoot, generated.Input.UpdateIdentityRef), generated.UpdateKey},
		{filepath.Join(tlsRoot, "cert.pem"), generated.TLSCertificate},
		{filepath.Join(tlsRoot, "key.pem"), generated.TLSKey},
	} {
		if item.path == "" {
			return errors.New("generated VPS identity path is unsafe")
		}
		if err := os.MkdirAll(filepath.Dir(item.path), 0o700); err != nil {
			return err
		}
		if err := os.WriteFile(item.path, item.content, 0o600); err != nil {
			return err
		}
		if err := os.Chmod(item.path, 0o600); err != nil {
			return err
		}
	}
	return nil
}

func installGeneratedWireGuardConfig(path string, generated generatedIdentity) error {
	if !filepath.IsAbs(path) || strings.ContainsRune(string(generated.WireGuardKey), 0) {
		return errors.New("generated VPS WireGuard destination is unsafe")
	}
	privateKey := strings.TrimSpace(string(generated.WireGuardKey))
	if publicKey, err := wgingress.PublicKey(privateKey); err != nil || publicKey != generated.Input.PublicKey {
		return errors.New("generated VPS WireGuard identity is inconsistent")
	}
	content := []byte("[Interface]\nAddress = 10.80.0.1/24\nListenPort = 51821\nPrivateKey = " + privateKey + "\n")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(path, content, 0o600); err != nil {
		return err
	}
	return os.Chmod(path, 0o600)
}

func verifyImportedWireGuardConfig(path, expectedPublicKey string) error {
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > 4096 || runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		return errors.New("activated imported VPS WireGuard config is unsafe")
	}
	content, err := os.ReadFile(path)
	if err != nil || int64(len(content)) != info.Size() {
		return errors.New("read activated imported VPS WireGuard config failed")
	}
	lines := strings.Split(strings.TrimSuffix(string(content), "\n"), "\n")
	if len(lines) != 4 || lines[0] != "[Interface]" || lines[1] != "Address = 10.80.0.1/24" || lines[2] != "ListenPort = 51821" || !strings.HasPrefix(lines[3], "PrivateKey = ") {
		return errors.New("activated imported VPS WireGuard config contract is invalid")
	}
	derived, err := wgingress.PublicKey(strings.TrimPrefix(lines[3], "PrivateKey = "))
	if err != nil || derived != expectedPublicKey {
		return errors.New("activated imported VPS WireGuard key does not match its new identity")
	}
	return nil
}

func secretCandidatePath(root, reference string) string {
	const prefix = "/var/lib/gateway-vpn-vps/agent/secrets/"
	if !strings.HasPrefix(reference, prefix) {
		return ""
	}
	relative := strings.TrimPrefix(reference, prefix)
	if !safePath(relative) {
		return ""
	}
	return filepath.Join(root, filepath.FromSlash(relative))
}

func generateSelfSignedTLS(vpsID string, now time.Time) ([]byte, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return nil, nil, err
	}
	template := x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: "Gateway VPN VPS " + vpsID},
		NotBefore: now.Add(-5 * time.Minute), NotAfter: now.AddDate(1, 0, 0),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true,
		DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("10.80.0.1")},
	}
	certificateDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateDER}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), nil
}

func pathExists(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}

func removeSafePath(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() && !info.IsDir() {
		return errors.New("managed VPS restore path is unsafe")
	}
	if info.Mode().IsRegular() {
		return os.Remove(path)
	}
	var paths []string
	if err := filepath.WalkDir(path, func(current string, _ os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		entryInfo, err := os.Lstat(current)
		if err != nil || entryInfo.Mode()&os.ModeSymlink != 0 || !entryInfo.Mode().IsRegular() && !entryInfo.IsDir() {
			return errors.New("managed VPS restore tree is unsafe")
		}
		paths = append(paths, current)
		return nil
	}); err != nil {
		return err
	}
	for index := len(paths) - 1; index >= 0; index-- {
		if err := os.Remove(paths[index]); err != nil {
			return err
		}
	}
	return nil
}

func (applier *RestoreApplier) now() time.Time {
	if applier.Now != nil {
		return applier.Now().UTC()
	}
	return time.Now().UTC()
}
