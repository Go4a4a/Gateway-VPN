package mihomo

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"

	"gateway-vpn/internal/platformexec"
)

const (
	markerActive  = "active-generation"
	markerLKG     = "lkg-generation"
	markerPending = "pending-generation"
)

type CandidateValidator interface {
	Validate(context.Context, string) error
}

// GenerationRuntime owns the Linux-specific atomic active-directory switch
// and Mihomo reload/restart. Activate must leave traffic fail-closed on error.
type GenerationRuntime interface {
	Activate(context.Context, string, string) error
	Verify(context.Context, string) error
}

// FailClosedRuntime is implemented by runtimes that can explicitly remove an
// active Mihomo data path and leave the host firewall in PATH_BLOCKED. It is
// required when a transaction has no generation to restore.
type FailClosedRuntime interface {
	FailClosed(context.Context) error
}

type TransactionController struct {
	Root      string
	Validator CandidateValidator
	Runtime   GenerationRuntime
	mutex     sync.Mutex
}

type ApplyResult struct {
	Generation         string
	PreviousGeneration string
	RolledBack         bool
}

func (controller *TransactionController) Apply(ctx context.Context, generation string, bundle Bundle) (ApplyResult, error) {
	controller.mutex.Lock()
	defer controller.mutex.Unlock()
	if controller.Root == "" || controller.Validator == nil || controller.Runtime == nil || !safeGenerationID(generation) {
		return ApplyResult{}, errors.New("complete Mihomo transaction controller and safe generation id are required")
	}
	if err := controller.prepareRoot(); err != nil {
		return ApplyResult{}, err
	}
	destination := filepath.Join(controller.Root, "generations", generation)
	if err := WriteCandidate(destination, bundle); err != nil {
		return ApplyResult{}, fmt.Errorf("write Mihomo candidate generation: %w", err)
	}
	if err := controller.Validator.Validate(ctx, destination); err != nil {
		return ApplyResult{Generation: generation}, fmt.Errorf("validate Mihomo candidate generation: %w", err)
	}
	previous, err := readGenerationMarker(controller.Root, markerLKG)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return ApplyResult{Generation: generation}, fmt.Errorf("read Mihomo LKG marker: %w", err)
	}
	result := ApplyResult{Generation: generation, PreviousGeneration: previous}
	if err := writeGenerationMarker(controller.Root, markerPending, generation); err != nil {
		return result, fmt.Errorf("record pending Mihomo generation: %w", err)
	}
	if err := controller.Runtime.Activate(ctx, generation, destination); err != nil {
		return controller.rollback(ctx, result, fmt.Errorf("activate Mihomo candidate generation: %w", err))
	}
	if err := controller.Runtime.Verify(ctx, generation); err != nil {
		return controller.rollback(ctx, result, fmt.Errorf("verify Mihomo candidate generation: %w", err))
	}
	if err := writeGenerationMarker(controller.Root, markerActive, generation); err != nil {
		return controller.rollback(ctx, result, fmt.Errorf("record active Mihomo generation: %w", err))
	}
	if err := writeGenerationMarker(controller.Root, markerLKG, generation); err != nil {
		return controller.rollback(ctx, result, fmt.Errorf("record Mihomo LKG generation: %w", err))
	}
	if err := removeGenerationMarker(controller.Root, markerPending); err != nil {
		return result, fmt.Errorf("clear pending Mihomo generation: %w", err)
	}
	return result, nil
}

// Restore activates a generation that was known before a later successful
// Apply. Candidate qualification uses it for compensation after its temporary
// generation has already passed validation and runtime verification.
//
// An empty generation means that no LKG existed before the candidate. In that
// case the runtime must support FailClosedRuntime; all generation markers are
// removed only after the data path has been blocked.
func (controller *TransactionController) Restore(ctx context.Context, generation string) error {
	controller.mutex.Lock()
	defer controller.mutex.Unlock()
	if controller.Root == "" || controller.Runtime == nil {
		return errors.New("complete Mihomo transaction controller is required")
	}
	if generation != "" && !safeGenerationID(generation) {
		return errors.New("safe Mihomo generation id is required")
	}
	if err := controller.prepareRoot(); err != nil {
		return err
	}
	if generation == "" {
		blocker, ok := controller.Runtime.(FailClosedRuntime)
		if !ok {
			return errors.New("Mihomo runtime cannot restore an empty LKG; PATH_BLOCKED runtime support is required")
		}
		if err := blocker.FailClosed(ctx); err != nil {
			return fmt.Errorf("block Mihomo runtime without previous LKG: %w", err)
		}
		return errors.Join(
			removeGenerationMarker(controller.Root, markerActive),
			removeGenerationMarker(controller.Root, markerLKG),
			removeGenerationMarker(controller.Root, markerPending),
		)
	}
	directory := filepath.Join(controller.Root, "generations", generation)
	info, err := os.Lstat(directory)
	if err != nil {
		return fmt.Errorf("stat Mihomo restore generation: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return errors.New("Mihomo restore generation must be a real directory")
	}
	if err := controller.Runtime.Activate(ctx, generation, directory); err != nil {
		return fmt.Errorf("activate restored Mihomo generation: %w", err)
	}
	if err := controller.Runtime.Verify(ctx, generation); err != nil {
		verificationErr := fmt.Errorf("verify restored Mihomo generation: %w", err)
		if blocker, ok := controller.Runtime.(FailClosedRuntime); ok {
			return errors.Join(verificationErr, blocker.FailClosed(ctx))
		}
		return verificationErr
	}
	if err := writeGenerationMarker(controller.Root, markerActive, generation); err != nil {
		return fmt.Errorf("record restored Mihomo active generation: %w", err)
	}
	if err := writeGenerationMarker(controller.Root, markerLKG, generation); err != nil {
		return fmt.Errorf("record restored Mihomo LKG generation: %w", err)
	}
	if err := removeGenerationMarker(controller.Root, markerPending); err != nil {
		return fmt.Errorf("clear pending Mihomo generation after restore: %w", err)
	}
	return nil
}

// RecoverLKG resolves an interrupted transaction before normal reconciliation.
// A pending generation is never trusted merely because its files exist.
func (controller *TransactionController) RecoverLKG(ctx context.Context) error {
	controller.mutex.Lock()
	defer controller.mutex.Unlock()
	if controller.Root == "" || controller.Runtime == nil {
		return errors.New("complete Mihomo transaction controller is required")
	}
	if _, err := readGenerationMarker(controller.Root, markerPending); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return fmt.Errorf("read pending Mihomo generation: %w", err)
	}
	lkg, err := readGenerationMarker(controller.Root, markerLKG)
	if errors.Is(err, os.ErrNotExist) || lkg == "" {
		blocker, ok := controller.Runtime.(FailClosedRuntime)
		if !ok {
			return errors.New("interrupted Mihomo transaction has no LKG and runtime cannot enforce PATH_BLOCKED")
		}
		if err := blocker.FailClosed(ctx); err != nil {
			return fmt.Errorf("enforce PATH_BLOCKED for interrupted first Mihomo generation: %w", err)
		}
		return removeGenerationMarker(controller.Root, markerPending)
	}
	if err != nil {
		return fmt.Errorf("read Mihomo LKG for recovery: %w", err)
	}
	directory := filepath.Join(controller.Root, "generations", lkg)
	if err := controller.Runtime.Activate(ctx, lkg, directory); err != nil {
		return controller.failClosedRecovery(ctx, fmt.Errorf("restore Mihomo LKG after interrupted transaction: %w", err))
	}
	if err := controller.Runtime.Verify(ctx, lkg); err != nil {
		return controller.failClosedRecovery(ctx, fmt.Errorf("verify recovered Mihomo LKG: %w", err))
	}
	if err := writeGenerationMarker(controller.Root, markerActive, lkg); err != nil {
		return fmt.Errorf("record recovered Mihomo active generation: %w", err)
	}
	return removeGenerationMarker(controller.Root, markerPending)
}

func (controller *TransactionController) failClosedRecovery(ctx context.Context, cause error) error {
	blocker, ok := controller.Runtime.(FailClosedRuntime)
	if !ok {
		return errors.Join(cause, errors.New("runtime cannot enforce PATH_BLOCKED after Mihomo recovery failure"))
	}
	if err := blocker.FailClosed(ctx); err != nil {
		return errors.Join(cause, fmt.Errorf("enforce PATH_BLOCKED after Mihomo recovery failure: %w", err))
	}
	return cause
}

func (controller *TransactionController) rollback(ctx context.Context, result ApplyResult, cause error) (ApplyResult, error) {
	if result.PreviousGeneration == "" {
		blocker, ok := controller.Runtime.(FailClosedRuntime)
		if !ok {
			return result, fmt.Errorf("%w; no previous LKG exists and runtime cannot enforce PATH_BLOCKED", cause)
		}
		if err := blocker.FailClosed(ctx); err != nil {
			return result, errors.Join(cause, fmt.Errorf("enforce PATH_BLOCKED without previous LKG: %w", err))
		}
		result.RolledBack = true
		if err := removeGenerationMarker(controller.Root, markerPending); err != nil {
			return result, errors.Join(cause, fmt.Errorf("clear pending Mihomo generation after PATH_BLOCKED: %w", err))
		}
		return result, cause
	}
	directory := filepath.Join(controller.Root, "generations", result.PreviousGeneration)
	if err := controller.Runtime.Activate(ctx, result.PreviousGeneration, directory); err != nil {
		return controller.failClosedRollback(ctx, result, cause, fmt.Errorf("rollback activation failed: %w", err))
	}
	if err := controller.Runtime.Verify(ctx, result.PreviousGeneration); err != nil {
		return controller.failClosedRollback(ctx, result, cause, fmt.Errorf("rollback verification failed: %w", err))
	}
	result.RolledBack = true
	if err := writeGenerationMarker(controller.Root, markerActive, result.PreviousGeneration); err != nil {
		return result, fmt.Errorf("%w; rollback marker failed: %v", cause, err)
	}
	if err := removeGenerationMarker(controller.Root, markerPending); err != nil {
		return result, fmt.Errorf("%w; pending marker cleanup failed: %v", cause, err)
	}
	return result, cause
}

func (controller *TransactionController) failClosedRollback(ctx context.Context, result ApplyResult, cause, rollbackErr error) (ApplyResult, error) {
	blocker, ok := controller.Runtime.(FailClosedRuntime)
	if !ok {
		return result, errors.Join(cause, rollbackErr, errors.New("runtime cannot enforce PATH_BLOCKED after rollback failure"))
	}
	blockErr := blocker.FailClosed(ctx)
	var cleanupErr error
	if blockErr == nil {
		result.RolledBack = true
		if err := removeGenerationMarker(controller.Root, markerPending); err != nil {
			cleanupErr = fmt.Errorf("clear pending Mihomo generation after rollback failure: %w", err)
		}
	} else {
		blockErr = fmt.Errorf("enforce PATH_BLOCKED after rollback failure: %w", blockErr)
	}
	return result, errors.Join(cause, rollbackErr, blockErr, cleanupErr)
}

func (controller *TransactionController) prepareRoot() error {
	for _, directory := range []struct {
		path string
		mode os.FileMode
	}{
		{path: controller.Root, mode: 0o750},
		{path: filepath.Join(controller.Root, "generations"), mode: 0o750},
		{path: filepath.Join(controller.Root, "state"), mode: 0o700},
	} {
		if err := os.MkdirAll(directory.path, directory.mode); err != nil {
			return fmt.Errorf("create Mihomo transaction directory: %w", err)
		}
		if err := os.Chmod(directory.path, directory.mode); err != nil {
			return fmt.Errorf("secure Mihomo transaction directory: %w", err)
		}
	}
	return nil
}

type BinaryValidator struct {
	Executor   platformexec.Executor
	Executable string
}

func (validator BinaryValidator) Validate(ctx context.Context, generationDirectory string) error {
	if validator.Executor == nil || validator.Executable == "" || !filepath.IsAbs(generationDirectory) {
		return errors.New("Mihomo validator executable, executor, and absolute generation directory are required")
	}
	result, err := validator.Executor.Run(ctx, platformexec.Request{Executable: validator.Executable, Arguments: []string{"-t", "-d", generationDirectory}})
	if err != nil {
		message := strings.TrimSpace(result.Stderr)
		if len(message) > 1024 {
			message = message[:1024]
		}
		if message != "" {
			return fmt.Errorf("%w: %s", err, message)
		}
		return err
	}
	return nil
}

func safeGenerationID(value string) bool {
	if value == "" || len(value) > 128 || value == "." || value == ".." {
		return false
	}
	for _, char := range value {
		if (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') || (char >= '0' && char <= '9') || strings.ContainsRune("._-", char) {
			continue
		}
		return false
	}
	return true
}

func writeGenerationMarker(root, name, generation string) error {
	if !safeGenerationID(generation) {
		return errors.New("unsafe Mihomo generation marker")
	}
	directory := filepath.Join(root, "state")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(directory, ".marker-")
	if err != nil {
		return err
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.WriteString(generation + "\n"); err != nil {
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
	destination := filepath.Join(directory, name)
	if err := os.Rename(temporaryName, destination); err != nil {
		if runtime.GOOS != "windows" {
			return err
		}
		// Windows cannot replace an existing file with os.Rename. Production
		// Linux uses the atomic rename path above.
		if removeErr := os.Remove(destination); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
			return err
		}
		if retryErr := os.Rename(temporaryName, destination); retryErr != nil {
			return retryErr
		}
	}
	return syncMarkerDirectory(directory)
}

func readGenerationMarker(root, name string) (string, error) {
	filename := filepath.Join(root, "state", name)
	info, err := os.Lstat(filename)
	if err != nil {
		return "", err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() > 256 {
		return "", errors.New("invalid Mihomo generation marker file")
	}
	file, err := os.Open(filename)
	if err != nil {
		return "", err
	}
	defer file.Close()
	content, err := io.ReadAll(io.LimitReader(file, 257))
	if err != nil {
		return "", err
	}
	generation := strings.TrimSpace(string(content))
	if !safeGenerationID(generation) {
		return "", errors.New("unsafe Mihomo generation marker content")
	}
	return generation, nil
}

func removeGenerationMarker(root, name string) error {
	err := os.Remove(filepath.Join(root, "state", name))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	return syncMarkerDirectory(filepath.Join(root, "state"))
}

func syncMarkerDirectory(directory string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	file, err := os.Open(directory)
	if err != nil {
		return err
	}
	defer file.Close()
	return file.Sync()
}
