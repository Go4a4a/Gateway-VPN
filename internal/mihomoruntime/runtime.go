// Package mihomoruntime owns the Linux data-plane activation boundary for one
// Mihomo process. It atomically switches immutable generation directories,
// reloads or restarts the fixed service, verifies the pinned API version and
// TUN, and can force the privileged firewall back to PATH_BLOCKED.
package mihomoruntime

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"gateway-vpn/internal/mihomo"
)

const (
	defaultVerifyTimeout  = 15 * time.Second
	defaultVerifyInterval = 250 * time.Millisecond
)

type MihomoAPI interface {
	Reload(context.Context, string) error
	GetVersion(context.Context) (mihomo.Version, error)
}

type PrivilegedBroker interface {
	RestartMihomo(context.Context) error
	FailClosedMihomo(context.Context) error
}

type GenerationSwitcher interface {
	Activate(root, generation, generationDirectory string) error
	Current(root string) (string, error)
	Remove(root string) error
}

type TUNInspector interface {
	RequireReady(context.Context, string) error
}

type LinuxRuntime struct {
	Root            string
	ExpectedVersion string
	TUNName         string
	API             MihomoAPI
	Broker          PrivilegedBroker
	Switcher        GenerationSwitcher
	TUN             TUNInspector
	VerifyTimeout   time.Duration
	VerifyInterval  time.Duration
	Platform        func() string

	mutex               sync.Mutex
	activatedGeneration string
}

func (current *LinuxRuntime) Activate(ctx context.Context, generation, generationDirectory string) error {
	current.mutex.Lock()
	defer current.mutex.Unlock()
	if err := current.validate(); err != nil {
		return err
	}
	if !safeGenerationID(generation) || !filepath.IsAbs(generationDirectory) {
		return current.failActivationLocked(ctx, errors.New("safe generation and absolute generation directory are required"))
	}
	if err := current.Switcher.Activate(current.Root, generation, generationDirectory); err != nil {
		return current.failActivationLocked(ctx, fmt.Errorf("atomically switch Mihomo generation: %w", err))
	}
	reloadErr := current.API.Reload(ctx, "config.yaml")
	if reloadErr != nil {
		if restartErr := current.Broker.RestartMihomo(ctx); restartErr != nil {
			return current.failActivationLocked(ctx, errors.Join(
				fmt.Errorf("reload Mihomo generation: %w", reloadErr),
				fmt.Errorf("restart Mihomo service: %w", restartErr),
			))
		}
	}
	current.activatedGeneration = generation
	return nil
}

func (current *LinuxRuntime) Verify(ctx context.Context, generation string) error {
	current.mutex.Lock()
	defer current.mutex.Unlock()
	if err := current.validate(); err != nil {
		return err
	}
	if !safeGenerationID(generation) || current.activatedGeneration != generation {
		return errors.New("Mihomo generation was not activated by this runtime")
	}
	linked, err := current.Switcher.Current(current.Root)
	if err != nil {
		return fmt.Errorf("read active Mihomo generation: %w", err)
	}
	if linked != generation {
		return fmt.Errorf("active Mihomo generation is %s, expected %s", linked, generation)
	}
	verifyContext, cancel := context.WithTimeout(ctx, current.verifyTimeout())
	defer cancel()
	var lastAPIError, lastTUNError error
	for {
		version, apiErr := current.API.GetVersion(verifyContext)
		if apiErr == nil && version.Version != current.ExpectedVersion {
			return fmt.Errorf("Mihomo API version is %q, pinned release requires %q", version.Version, current.ExpectedVersion)
		}
		tunErr := current.TUN.RequireReady(verifyContext, current.TUNName)
		if apiErr == nil && tunErr == nil {
			return nil
		}
		lastAPIError, lastTUNError = apiErr, tunErr
		timer := time.NewTimer(current.verifyInterval())
		select {
		case <-verifyContext.Done():
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			return errors.Join(
				fmt.Errorf("Mihomo generation verification timed out: %w", verifyContext.Err()),
				lastAPIError,
				lastTUNError,
			)
		case <-timer.C:
		}
	}
}

func (current *LinuxRuntime) FailClosed(ctx context.Context) error {
	current.mutex.Lock()
	defer current.mutex.Unlock()
	if err := current.validate(); err != nil {
		return err
	}
	return current.failClosedLocked(ctx)
}

func (current *LinuxRuntime) failActivationLocked(ctx context.Context, cause error) error {
	return errors.Join(cause, current.failClosedLocked(ctx))
}

func (current *LinuxRuntime) failClosedLocked(ctx context.Context) error {
	blockErr := current.Broker.FailClosedMihomo(ctx)
	removeErr := current.Switcher.Remove(current.Root)
	current.activatedGeneration = ""
	if blockErr != nil {
		blockErr = fmt.Errorf("privileged Mihomo fail-closed operation: %w", blockErr)
	}
	if removeErr != nil {
		removeErr = fmt.Errorf("remove active Mihomo generation link: %w", removeErr)
	}
	return errors.Join(blockErr, removeErr)
}

func (current *LinuxRuntime) validate() error {
	if current == nil || !filepath.IsAbs(current.Root) || strings.TrimSpace(current.ExpectedVersion) == "" || current.ExpectedVersion == "unknown" || !validInterfaceName(current.TUNName) || current.API == nil || current.Broker == nil || current.Switcher == nil || current.TUN == nil {
		return errors.New("complete pinned Mihomo Linux runtime configuration is required")
	}
	platform := runtime.GOOS
	if current.Platform != nil {
		platform = current.Platform()
	}
	if platform != "linux" {
		return errors.New("Mihomo generation activation is supported only on Linux")
	}
	if current.VerifyTimeout < 0 || current.VerifyTimeout > time.Minute || current.VerifyInterval < 0 || current.VerifyInterval > 5*time.Second {
		return errors.New("invalid Mihomo verification timing")
	}
	return nil
}

func (current *LinuxRuntime) verifyTimeout() time.Duration {
	if current.VerifyTimeout > 0 {
		return current.VerifyTimeout
	}
	return defaultVerifyTimeout
}

func (current *LinuxRuntime) verifyInterval() time.Duration {
	if current.VerifyInterval > 0 {
		return current.VerifyInterval
	}
	return defaultVerifyInterval
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

func validInterfaceName(value string) bool {
	if value == "" || len(value) > 15 {
		return false
	}
	for _, char := range value {
		if (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') || (char >= '0' && char <= '9') {
			continue
		}
		switch char {
		case '_', '-', '.', ':':
			continue
		default:
			return false
		}
	}
	return true
}
