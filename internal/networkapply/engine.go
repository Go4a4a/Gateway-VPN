package networkapply

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"gateway-vpn/internal/netutil"
)

type Candidate struct {
	InterfaceName                string
	OldLANCIDR                   string
	NewLANCIDR                   string
	OldURL                       string
	NewURL                       string
	Ethernet                     *EthernetMutation
	Topology                     *TopologyMutation
	ManagementURL                string
	ManagementDestinationIP      string
	RequireWireGuardConfirmation bool
}

type SnapshotBackend interface {
	Snapshot(context.Context, Manifest, string) error
	Apply(context.Context, Manifest, string) error
	Commit(context.Context, Manifest, string) error
	Rollback(context.Context, Manifest, string) error
}

type RollbackTimer interface {
	Arm(context.Context, string, time.Time) error
	Disarm(context.Context, string) error
}

type Engine struct {
	Repository    *Repository
	Store         DiskStore
	Backend       SnapshotBackend
	Timer         RollbackTimer
	RollbackAfter time.Duration
	Now           func() time.Time
	NewSecret     func(int) ([]byte, error)
}

type Prepared struct {
	ApplyID          string    `json:"apply_id"`
	ConfirmToken     string    `json:"confirm_token"`
	OldURL           string    `json:"old_url"`
	NewURL           string    `json:"new_url"`
	RollbackDeadline time.Time `json:"rollback_deadline"`
}

type ConfirmEvidence struct {
	Token              string
	LocalDestinationIP string
	ViaWireGuard       bool
}

type TopologyPreview struct {
	CurrentProfile               string   `json:"current_profile"`
	CandidateProfile             string   `json:"candidate_profile"`
	CurrentDesiredGeneration     int64    `json:"current_desired_generation"`
	CandidateDesiredGeneration   int64    `json:"candidate_desired_generation"`
	OldURL                       string   `json:"old_url"`
	NewURL                       string   `json:"new_url"`
	RequiredPrerequisites        []string `json:"required_prerequisites"`
	MissingPrerequisites         []string `json:"missing_prerequisites"`
	RequireWireGuardConfirmation bool     `json:"require_wireguard_confirmation"`
	ManagementInterfaces         []string `json:"management_interfaces"`
	AffectedInterfaces           []string `json:"affected_interfaces"`
}

type topologyPreviewBackend interface {
	PreviewTopology(context.Context, Manifest) (TopologyPreview, error)
}

func NewEngine(repository *Repository, store DiskStore, backend SnapshotBackend, timer RollbackTimer) *Engine {
	return &Engine{
		Repository:    repository,
		Store:         store,
		Backend:       backend,
		Timer:         timer,
		RollbackAfter: 60 * time.Second,
		Now:           time.Now,
		NewSecret: func(length int) ([]byte, error) {
			value := make([]byte, length)
			_, err := rand.Read(value)
			return value, err
		},
	}
}

// PreviewTopology performs the same protected generation, role, subnet and
// management-safety checks as Stage without creating a transaction, writing a
// snapshot or arming a rollback timer.
func (engine *Engine) PreviewTopology(ctx context.Context, candidate Candidate) (TopologyPreview, error) {
	if err := engine.validate(); err != nil {
		return TopologyPreview{}, err
	}
	backend, ok := engine.Backend.(topologyPreviewBackend)
	if !ok {
		return TopologyPreview{}, errors.New("topology preview backend is unavailable")
	}
	manifest, err := buildManifest(candidate)
	if err != nil {
		return TopologyPreview{}, err
	}
	if manifest.SchemaVersion != TopologyManifestSchema {
		return TopologyPreview{}, errors.New("topology preview requires a topology candidate")
	}
	now := engine.Now().UTC()
	manifest.ID = "preview-topology"
	manifest.CreatedAt = now.Format(time.RFC3339Nano)
	manifest.RollbackDeadline = now.Add(engine.RollbackAfter).Format(time.RFC3339Nano)
	if err := validateManifest(manifest); err != nil {
		return TopologyPreview{}, err
	}
	return backend.PreviewTopology(ctx, manifest)
}

// Prepare is the synchronous convenience operation used by local callers. The
// broker uses Stage followed by a separate Apply request so the one-time token
// can reach the UI before the control-plane address changes.
func (engine *Engine) Prepare(ctx context.Context, candidate Candidate) (Prepared, error) {
	prepared, err := engine.Stage(ctx, candidate)
	if err != nil {
		return Prepared{}, err
	}
	if err := engine.Apply(ctx, prepared.ApplyID); err != nil {
		return Prepared{}, err
	}
	return prepared, nil
}

// Stage snapshots the old state and arms the independent rollback timer. It
// performs no network mutation and returns the confirmation token exactly once.
func (engine *Engine) Stage(ctx context.Context, candidate Candidate) (Prepared, error) {
	if err := engine.validate(); err != nil {
		return Prepared{}, err
	}
	manifest, err := buildManifest(candidate)
	if err != nil {
		return Prepared{}, err
	}
	idBytes, err := engine.NewSecret(16)
	if err != nil {
		return Prepared{}, errors.New("allocate network apply id failed")
	}
	tokenBytes, err := engine.NewSecret(32)
	if err != nil {
		return Prepared{}, errors.New("allocate network apply confirmation token failed")
	}
	applyID := "apply-" + hex.EncodeToString(idBytes)
	confirmToken := hex.EncodeToString(tokenBytes)
	tokenDigest := sha256.Sum256([]byte(confirmToken))
	now := engine.Now().UTC()
	deadline := now.Add(engine.RollbackAfter)
	manifest.ID = applyID
	manifest.RollbackDeadline = deadline.Format(time.RFC3339Nano)
	manifest.CreatedAt = now.Format(time.RFC3339Nano)
	candidateJSON, err := manifestCandidateJSON(manifest)
	if err != nil {
		return Prepared{}, err
	}
	directory, err := engine.Store.Directory(applyID)
	if err != nil {
		return Prepared{}, err
	}
	record := Transaction{
		ID: applyID, State: StatePreparing, ConfirmTokenSHA256: hex.EncodeToString(tokenDigest[:]),
		ManifestSchema: manifest.SchemaVersion, OperationKind: effectiveOperationKind(manifest), CandidateJSON: candidateJSON,
		InterfaceName: candidate.InterfaceName, OldLANCIDR: manifest.OldLANCIDR,
		NewLANCIDR: manifest.NewLANCIDR, OldURL: manifest.OldURL, NewURL: manifest.NewURL,
		NewDestinationIP: manifest.NewDestinationIP, RollbackDeadline: manifest.RollbackDeadline,
		TransactionDir: directory,
	}
	if err := engine.Repository.Create(ctx, record); err != nil {
		return Prepared{}, err
	}
	failBeforeArm := func(code string) (Prepared, error) {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
		defer cancel()
		_ = engine.Repository.Transition(cleanup, applyID, []string{StatePreparing}, StateFailed, code)
		_ = engine.Store.SetPhase(applyID, PhaseFailed)
		return Prepared{}, fmt.Errorf("network apply %s failed (%s)", applyID, code)
	}
	createdDirectory, err := engine.Store.Create(manifest)
	if err != nil {
		return failBeforeArm("SNAPSHOT_DIRECTORY_FAILED")
	}
	if createdDirectory != directory {
		return failBeforeArm("SNAPSHOT_DIRECTORY_MISMATCH")
	}
	if err := engine.Backend.Snapshot(ctx, manifest, directory); err != nil {
		return failBeforeArm("SNAPSHOT_FAILED")
	}
	armTime := engine.Now().UTC()
	deadline = armTime.Add(engine.RollbackAfter)
	manifest.CreatedAt = armTime.Format(time.RFC3339Nano)
	manifest.RollbackDeadline = deadline.Format(time.RFC3339Nano)
	if err := engine.Store.ReplaceManifest(manifest); err != nil {
		return failBeforeArm("ROLLBACK_DEADLINE_STORE_FAILED")
	}
	if err := engine.Repository.UpdateDeadline(ctx, applyID, deadline); err != nil {
		return failBeforeArm("ROLLBACK_DEADLINE_DB_FAILED")
	}
	record.RollbackDeadline = manifest.RollbackDeadline
	if err := engine.Store.SetPhase(applyID, PhaseSnapshot); err != nil {
		return failBeforeArm("SNAPSHOT_STATUS_FAILED")
	}
	if err := engine.Timer.Arm(ctx, applyID, deadline); err != nil {
		return failBeforeArm("ROLLBACK_TIMER_ARM_FAILED")
	}
	rollback := func(code string) (Prepared, error) {
		return Prepared{}, engine.rollback(ctx, record, manifest, directory, code)
	}
	if err := engine.Store.SetPhase(applyID, PhaseArmed); err != nil {
		return rollback("ARMED_STATUS_FAILED")
	}
	if err := engine.Repository.Transition(ctx, applyID, []string{StatePreparing}, StateArmed, ""); err != nil {
		return rollback("ARMED_DB_FAILED")
	}
	return Prepared{ApplyID: applyID, ConfirmToken: confirmToken, OldURL: manifest.OldURL, NewURL: manifest.NewURL, RollbackDeadline: deadline}, nil
}

// Apply changes the network only for a previously armed durable transaction.
func (engine *Engine) Apply(ctx context.Context, applyID string) error {
	if err := engine.validate(); err != nil {
		return err
	}
	transaction, err := engine.Repository.Get(ctx, applyID)
	if err != nil {
		return err
	}
	if transaction.State != StateArmed {
		return ErrApplyState
	}
	manifest, status, err := engine.Store.Load(applyID)
	directory, directoryErr := engine.Store.Directory(applyID)
	if err != nil || directoryErr != nil || status.Phase != PhaseArmed || !manifestMatchesTransaction(manifest, transaction, directory) {
		return errors.New("armed network apply durable state is unavailable")
	}
	deadline, err := time.Parse(time.RFC3339Nano, transaction.RollbackDeadline)
	if err != nil || !deadline.After(engine.Now().UTC()) {
		return engine.rollback(ctx, transaction, manifest, directory, "APPLY_DEADLINE_EXPIRED")
	}
	if err := engine.Backend.Apply(ctx, manifest, directory); err != nil {
		return engine.rollback(ctx, transaction, manifest, directory, "CANDIDATE_APPLY_FAILED")
	}
	persist, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
	defer cancel()
	if err := engine.Store.SetPhase(applyID, PhaseApplied); err != nil {
		return engine.rollback(persist, transaction, manifest, directory, "APPLIED_STATUS_FAILED")
	}
	if err := engine.Repository.Transition(persist, applyID, []string{StateArmed}, StateApplied, ""); err != nil {
		return engine.rollback(persist, transaction, manifest, directory, "APPLIED_DB_FAILED")
	}
	return nil
}

func (engine *Engine) rollback(ctx context.Context, transaction Transaction, manifest Manifest, directory, code string) error {
	cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()
	if err := engine.Backend.Rollback(cleanup, manifest, directory); err != nil {
		_ = engine.Store.SetPhase(transaction.ID, PhaseFailed)
		_ = engine.Repository.Transition(cleanup, transaction.ID, []string{StatePreparing, StateArmed, StateApplied, StateConfirming}, StateFailed, "ROLLBACK_FAILED")
		return fmt.Errorf("network apply %s failed and rollback failed", transaction.ID)
	}
	_ = engine.Store.SetPhase(transaction.ID, PhaseRolledBack)
	_ = engine.Repository.Transition(cleanup, transaction.ID, []string{StatePreparing, StateArmed, StateApplied, StateConfirming}, StateRolledBack, code)
	_ = engine.Timer.Disarm(cleanup, transaction.ID)
	return fmt.Errorf("network apply %s failed and was rolled back (%s)", transaction.ID, code)
}

func (engine *Engine) Confirm(ctx context.Context, applyID string, evidence ConfirmEvidence) error {
	if err := engine.validate(); err != nil {
		return err
	}
	transaction, err := engine.Repository.Get(ctx, applyID)
	if err != nil {
		return err
	}
	if transaction.State != StateApplied {
		return ErrApplyState
	}
	deadline, err := time.Parse(time.RFC3339Nano, transaction.RollbackDeadline)
	if err != nil || !deadline.After(engine.Now().UTC()) {
		return ErrApplyExpired
	}
	provided := sha256.Sum256([]byte(evidence.Token))
	expected, err := hex.DecodeString(transaction.ConfirmTokenSHA256)
	if err != nil || len(expected) != len(provided) || subtle.ConstantTimeCompare(expected, provided[:]) != 1 {
		return ErrConfirmToken
	}
	manifest, status, err := engine.Store.Load(applyID)
	directory, directoryErr := engine.Store.Directory(applyID)
	if err != nil || directoryErr != nil || status.Phase != PhaseApplied || !manifestMatchesTransaction(manifest, transaction, directory) {
		return errors.New("network apply durable state is unavailable")
	}
	if manifest.RequireWireGuardConfirmation && !evidence.ViaWireGuard {
		return ErrConfirmSource
	}
	if !evidence.ViaWireGuard {
		local, parseErr := netip.ParseAddr(evidence.LocalDestinationIP)
		if parseErr != nil || local.Unmap().String() != transaction.NewDestinationIP {
			return ErrConfirmSource
		}
	}
	if err := engine.Store.SetPhase(applyID, PhaseConfirming); err != nil {
		return fmt.Errorf("record network apply confirmation intent: %w", err)
	}
	if err := engine.Repository.Transition(ctx, applyID, []string{StateApplied}, StateConfirming, ""); err != nil {
		return err
	}
	if err := engine.Timer.Disarm(ctx, applyID); err != nil {
		return engine.rollbackConfirmFailure(ctx, transaction, manifest, "ROLLBACK_TIMER_DISARM_FAILED")
	}
	if err := engine.Backend.Commit(ctx, manifest, directory); err != nil {
		return engine.rollbackConfirmFailure(ctx, transaction, manifest, "CANDIDATE_COMMIT_FAILED")
	}
	if err := engine.Store.SetPhase(applyID, PhaseConfirmed); err != nil {
		return fmt.Errorf("record confirmed network apply durable state: %w", err)
	}
	if err := engine.Repository.Transition(ctx, applyID, []string{StateConfirming}, StateConfirmed, ""); err != nil {
		return err
	}
	return nil
}

func (engine *Engine) rollbackConfirmFailure(ctx context.Context, transaction Transaction, manifest Manifest, code string) error {
	cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()
	directory, directoryErr := engine.Store.Directory(transaction.ID)
	if directoryErr != nil || !manifestMatchesTransaction(manifest, transaction, directory) {
		return errors.New("network apply confirmation durable state mismatch")
	}
	if err := engine.Backend.Rollback(cleanup, manifest, directory); err != nil {
		_ = engine.Store.SetPhase(transaction.ID, PhaseFailed)
		_ = engine.Repository.Transition(cleanup, transaction.ID, []string{StateConfirming}, StateFailed, "ROLLBACK_FAILED")
		return errors.New("network apply confirmation failed and rollback failed")
	}
	_ = engine.Store.SetPhase(transaction.ID, PhaseRolledBack)
	_ = engine.Repository.Transition(cleanup, transaction.ID, []string{StateConfirming}, StateRolledBack, code)
	return fmt.Errorf("network apply confirmation failed and was rolled back (%s)", code)
}

// Recover rolls every unconfirmed transaction back on process startup. A
// validated confirmation intent is completed instead, because its request was
// already proven to arrive through the new address or WireGuard.
func (engine *Engine) Recover(ctx context.Context) error {
	if err := engine.validate(); err != nil {
		return err
	}
	items, err := engine.Repository.ListUnfinished(ctx)
	if err != nil {
		return err
	}
	var failures []error
	for _, item := range items {
		manifest, status, loadErr := engine.Store.Load(item.ID)
		directory, directoryErr := engine.Store.Directory(item.ID)
		matches := manifestMatchesTransaction(manifest, item, directory)
		preArmDeadlineMismatch := item.State == StatePreparing && manifestCoreMatchesTransaction(manifest, item, directory)
		if loadErr != nil || directoryErr != nil || (!matches && !preArmDeadlineMismatch) {
			if loadErr == nil {
				loadErr = errors.New("durable manifest and database transaction differ")
			}
			failures = append(failures, fmt.Errorf("recover network apply %s: %w", item.ID, loadErr))
			continue
		}
		switch status.Phase {
		case PhaseConfirmed:
			if err := engine.Repository.Transition(ctx, item.ID, []string{item.State}, StateConfirmed, ""); err != nil {
				failures = append(failures, err)
			}
		case PhaseRolledBack:
			if err := engine.Repository.Transition(ctx, item.ID, []string{item.State}, StateRolledBack, "RECOVERED_ROLLBACK"); err != nil {
				failures = append(failures, err)
			}
		case PhaseConfirming:
			if err := engine.Timer.Disarm(ctx, item.ID); err == nil {
				err = engine.Backend.Commit(ctx, manifest, directory)
			}
			if err == nil {
				err = engine.Store.SetPhase(item.ID, PhaseConfirmed)
			}
			if err == nil {
				err = engine.Repository.Transition(ctx, item.ID, []string{item.State}, StateConfirmed, "")
			}
			if err != nil {
				failures = append(failures, fmt.Errorf("finish confirmed network apply %s: %w", item.ID, err))
			}
		default:
			if err := engine.Backend.Rollback(ctx, manifest, directory); err != nil {
				failures = append(failures, fmt.Errorf("rollback unfinished network apply %s: %w", item.ID, err))
				continue
			}
			_ = engine.Timer.Disarm(ctx, item.ID)
			if err := engine.Store.SetPhase(item.ID, PhaseRolledBack); err != nil {
				failures = append(failures, err)
				continue
			}
			if err := engine.Repository.Transition(ctx, item.ID, []string{item.State}, StateRolledBack, "REBOOT_RECOVERY"); err != nil {
				failures = append(failures, err)
			}
		}
	}
	return errors.Join(failures...)
}

// RollbackFromDisk is the out-of-process helper entry point. It does not open
// SQLite and therefore still works when gateway-vpn is stopped or the DB is
// unavailable.
func RollbackFromDisk(ctx context.Context, store DiskStore, backend SnapshotBackend, applyID string) (bool, error) {
	if backend == nil {
		return false, errors.New("network rollback backend is required")
	}
	manifest, status, err := store.Load(applyID)
	if err != nil {
		return false, err
	}
	if status.Phase == PhaseConfirmed || status.Phase == PhaseConfirming || status.Phase == PhaseRolledBack {
		return false, nil
	}
	directory, err := store.Directory(applyID)
	if err != nil {
		return false, err
	}
	if err := backend.Rollback(ctx, manifest, directory); err != nil {
		_ = store.SetPhase(applyID, PhaseFailed)
		return false, err
	}
	if err := store.SetPhase(applyID, PhaseRolledBack); err != nil {
		return false, err
	}
	return true, nil
}

func (engine *Engine) validate() error {
	if engine == nil || engine.Repository == nil || engine.Backend == nil || engine.Timer == nil || engine.Store.Root == "" || engine.Now == nil || engine.NewSecret == nil {
		return errors.New("network apply engine dependencies are incomplete")
	}
	if engine.RollbackAfter < 30*time.Second || engine.RollbackAfter > 90*time.Second {
		return errors.New("network rollback timeout must be between 30 and 90 seconds")
	}
	return nil
}

func validateCandidate(candidate Candidate) (netip.Prefix, netip.Prefix, error) {
	if !validInterfaceName(candidate.InterfaceName) {
		return netip.Prefix{}, netip.Prefix{}, errors.New("network candidate interface is invalid")
	}
	oldPrefix, err := netip.ParsePrefix(candidate.OldLANCIDR)
	if err != nil {
		return netip.Prefix{}, netip.Prefix{}, errors.New("old LAN CIDR is invalid")
	}
	newPrefix, err := netip.ParsePrefix(candidate.NewLANCIDR)
	if err != nil {
		return netip.Prefix{}, netip.Prefix{}, errors.New("new LAN CIDR is invalid")
	}
	oldNetwork, newNetwork := oldPrefix.Masked(), newPrefix.Masked()
	if !validPrivateIPv4LAN(oldPrefix) || !validPrivateIPv4LAN(newPrefix) || oldNetwork == newNetwork || oldNetwork.Overlaps(newNetwork) {
		return netip.Prefix{}, netip.Prefix{}, errors.New("old and new LAN subnets must be distinct non-overlapping private IPv4 networks")
	}
	if err := validateManagementURL(candidate.OldURL, oldPrefix.Addr()); err != nil {
		return netip.Prefix{}, netip.Prefix{}, fmt.Errorf("old management URL: %w", err)
	}
	if err := validateManagementURL(candidate.NewURL, newPrefix.Addr()); err != nil {
		return netip.Prefix{}, netip.Prefix{}, fmt.Errorf("new management URL: %w", err)
	}
	return oldPrefix, newPrefix, nil
}

func buildManifest(candidate Candidate) (Manifest, error) {
	if candidate.Topology != nil {
		if candidate.Ethernet != nil || candidate.InterfaceName != "" || candidate.OldLANCIDR != "" || candidate.NewLANCIDR != "" {
			return Manifest{}, errors.New("topology candidate cannot contain LAN or Ethernet mutation fields")
		}
		mutation := cloneTopologyMutation(*candidate.Topology)
		if err := validateTopologyMutation(mutation); err != nil {
			return Manifest{}, fmt.Errorf("invalid topology profile candidate: %w", err)
		}
		oldURL, newURL := candidate.OldURL, candidate.NewURL
		if oldURL == "" {
			oldURL = candidate.ManagementURL
		}
		if newURL == "" {
			newURL = candidate.ManagementURL
		}
		destination, err := netip.ParseAddr(candidate.ManagementDestinationIP)
		if err != nil || !destination.Is4() {
			return Manifest{}, errors.New("topology confirmation destination must be an IPv4 address")
		}
		if err := validateManagementURL(newURL, destination); err != nil {
			return Manifest{}, fmt.Errorf("topology management URL: %w", err)
		}
		parsedOld, err := url.Parse(oldURL)
		if err != nil {
			return Manifest{}, errors.New("topology old management URL is invalid")
		}
		oldDestination, err := netip.ParseAddr(strings.Trim(parsedOld.Hostname(), "[]"))
		if err != nil || validateManagementURL(oldURL, oldDestination) != nil {
			return Manifest{}, errors.New("topology old management URL is invalid")
		}
		return Manifest{
			SchemaVersion: TopologyManifestSchema, OperationKind: OperationTopologyProfile,
			OldURL: oldURL, NewURL: newURL,
			NewDestinationIP: destination.String(), Topology: &mutation,
			RequireWireGuardConfirmation: candidate.RequireWireGuardConfirmation,
		}, nil
	}
	if candidate.Ethernet == nil {
		oldPrefix, newPrefix, err := validateCandidate(candidate)
		if err != nil {
			return Manifest{}, err
		}
		return Manifest{
			SchemaVersion: LegacyManifestSchema,
			InterfaceName: candidate.InterfaceName,
			OldLANCIDR:    oldPrefix.String(), NewLANCIDR: newPrefix.String(),
			OldURL: candidate.OldURL, NewURL: candidate.NewURL,
			NewDestinationIP: newPrefix.Addr().String(),
		}, nil
	}
	if candidate.InterfaceName != "" || candidate.OldLANCIDR != "" || candidate.NewLANCIDR != "" || candidate.OldURL != "" || candidate.NewURL != "" {
		return Manifest{}, errors.New("Ethernet candidate cannot contain LAN mutation fields")
	}
	mutation := *candidate.Ethernet
	mutation.UplinkID = strings.TrimSpace(mutation.UplinkID)
	mutation.TargetInterfaceID = strings.TrimSpace(mutation.TargetInterfaceID)
	mutation.Name = strings.TrimSpace(mutation.Name)
	mutation.DNS = append([]string(nil), mutation.DNS...)
	if err := validateEthernetMutation(mutation); err != nil {
		return Manifest{}, fmt.Errorf("invalid Ethernet network candidate: %w", err)
	}
	destination, err := netip.ParseAddr(candidate.ManagementDestinationIP)
	if err != nil || !destination.Is4() {
		return Manifest{}, errors.New("current management destination must be an IPv4 address")
	}
	if err := validateManagementURL(candidate.ManagementURL, destination); err != nil {
		return Manifest{}, fmt.Errorf("current management URL: %w", err)
	}
	manifest := Manifest{
		SchemaVersion: ManifestSchema, OperationKind: OperationEthernetUplink,
		OldURL: candidate.ManagementURL, NewURL: candidate.ManagementURL,
		NewDestinationIP: destination.String(), Ethernet: &mutation,
	}
	return manifest, nil
}

func effectiveOperationKind(manifest Manifest) string {
	if manifest.SchemaVersion == LegacyManifestSchema {
		return OperationLANAddress
	}
	return manifest.OperationKind
}

func manifestCandidateJSON(manifest Manifest) (string, error) {
	if manifest.SchemaVersion == LegacyManifestSchema {
		return "{}", nil
	}
	var candidate any = manifest.Ethernet
	if manifest.SchemaVersion == TopologyManifestSchema {
		candidate = manifest.Topology
	}
	payload, err := json.Marshal(candidate)
	if err != nil {
		return "", errors.New("encode network apply candidate failed")
	}
	return string(payload), nil
}

func validPrivateIPv4LAN(prefix netip.Prefix) bool {
	return prefix.IsValid() && netutil.ValidGatewayLAN(prefix.String())
}

func validateManagementURL(value string, expected netip.Addr) error {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return errors.New("URL must be an HTTPS origin without credentials, path, query, or fragment")
	}
	host, err := netip.ParseAddr(strings.Trim(parsed.Hostname(), "[]"))
	if err != nil || host.Unmap() != expected.Unmap() || parsed.Port() == "" {
		return errors.New("URL host must equal the LAN address and include the API port")
	}
	return nil
}

func manifestMatchesTransaction(manifest Manifest, transaction Transaction, directory string) bool {
	return manifestCoreMatchesTransaction(manifest, transaction, directory) &&
		manifest.RollbackDeadline == transaction.RollbackDeadline
}

func manifestCoreMatchesTransaction(manifest Manifest, transaction Transaction, directory string) bool {
	candidateJSON, err := manifestCandidateJSON(manifest)
	if err != nil {
		return false
	}
	return manifest.ID == transaction.ID &&
		manifest.SchemaVersion == transaction.ManifestSchema &&
		effectiveOperationKind(manifest) == transaction.OperationKind &&
		candidateJSON == transaction.CandidateJSON &&
		manifest.InterfaceName == transaction.InterfaceName &&
		manifest.OldLANCIDR == transaction.OldLANCIDR &&
		manifest.NewLANCIDR == transaction.NewLANCIDR &&
		manifest.OldURL == transaction.OldURL &&
		manifest.NewURL == transaction.NewURL &&
		manifest.NewDestinationIP == transaction.NewDestinationIP &&
		transaction.TransactionDir == directory
}
