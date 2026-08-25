package mihomoruntime

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"gateway-vpn/internal/mihomo"
)

type fakeAPI struct {
	reloadErr     error
	reloads       int
	version       string
	versionErrors int
	versionCalls  int
}

func (api *fakeAPI) Reload(context.Context, string) error {
	api.reloads++
	return api.reloadErr
}

func (api *fakeAPI) GetVersion(context.Context) (mihomo.Version, error) {
	api.versionCalls++
	if api.versionCalls <= api.versionErrors {
		return mihomo.Version{}, errors.New("API not ready")
	}
	return mihomo.Version{Version: api.version}, nil
}

type fakeBroker struct {
	restarts   int
	blocks     int
	restartErr error
	blockErr   error
}

func (broker *fakeBroker) RestartMihomo(context.Context) error {
	broker.restarts++
	return broker.restartErr
}

func (broker *fakeBroker) FailClosedMihomo(context.Context) error {
	broker.blocks++
	return broker.blockErr
}

type fakeSwitcher struct {
	active      string
	activations []string
	removes     int
	activateErr error
}

func (switcher *fakeSwitcher) Activate(_, generation, _ string) error {
	switcher.activations = append(switcher.activations, generation)
	if switcher.activateErr != nil {
		return switcher.activateErr
	}
	switcher.active = generation
	return nil
}

func (switcher *fakeSwitcher) Current(string) (string, error) {
	if switcher.active == "" {
		return "", errors.New("no active link")
	}
	return switcher.active, nil
}

func (switcher *fakeSwitcher) Remove(string) error {
	switcher.removes++
	switcher.active = ""
	return nil
}

type fakeTUN struct {
	failures int
	calls    int
}

func (inspector *fakeTUN) RequireReady(context.Context, string) error {
	inspector.calls++
	if inspector.calls <= inspector.failures {
		return errors.New("TUN not ready")
	}
	return nil
}

func TestLinuxRuntimeReloadsAndVerifiesPinnedVersionAndTUN(t *testing.T) {
	runtime, api, broker, switcher, tun := testLinuxRuntime(t)
	directory := filepath.Join(runtime.Root, "generations", "generation-1")
	if err := runtime.Activate(context.Background(), "generation-1", directory); err != nil {
		t.Fatalf("Activate() error = %v", err)
	}
	if err := runtime.Verify(context.Background(), "generation-1"); err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if api.reloads != 1 || broker.restarts != 0 || broker.blocks != 0 || switcher.active != "generation-1" || tun.calls != 1 {
		t.Fatalf("runtime calls reload/restart/block/active/tun = %d/%d/%d/%s/%d", api.reloads, broker.restarts, broker.blocks, switcher.active, tun.calls)
	}
}

func TestLinuxRuntimeRestartsWhenAPIIsUnavailableAndWaitsForReadiness(t *testing.T) {
	runtime, api, broker, _, tun := testLinuxRuntime(t)
	api.reloadErr = errors.New("connection refused")
	api.versionErrors = 1
	tun.failures = 1
	if err := runtime.Activate(context.Background(), "generation-2", filepath.Join(runtime.Root, "generations", "generation-2")); err != nil {
		t.Fatalf("Activate(restart fallback) error = %v", err)
	}
	if err := runtime.Verify(context.Background(), "generation-2"); err != nil {
		t.Fatalf("Verify(eventual readiness) error = %v", err)
	}
	if broker.restarts != 1 || api.versionCalls < 2 || tun.calls < 2 {
		t.Fatalf("restart/version/tun calls = %d/%d/%d", broker.restarts, api.versionCalls, tun.calls)
	}
}

func TestLinuxRuntimeActivationFailureForcesFailClosedAndRemovesLink(t *testing.T) {
	runtime, api, broker, switcher, _ := testLinuxRuntime(t)
	api.reloadErr = errors.New("reload failed")
	broker.restartErr = errors.New("restart failed")
	if err := runtime.Activate(context.Background(), "generation-3", filepath.Join(runtime.Root, "generations", "generation-3")); err == nil {
		t.Fatal("Activate(unrecoverable) error = nil")
	}
	if broker.blocks != 1 || switcher.removes != 1 || switcher.active != "" {
		t.Fatalf("fail-closed block/remove/active = %d/%d/%s", broker.blocks, switcher.removes, switcher.active)
	}
}

func TestLinuxRuntimeRejectsUnpinnedVersionAndNonLinuxMutation(t *testing.T) {
	runtime, api, broker, switcher, _ := testLinuxRuntime(t)
	api.version = "v9.9.9"
	if err := runtime.Activate(context.Background(), "generation-4", filepath.Join(runtime.Root, "generations", "generation-4")); err != nil {
		t.Fatal(err)
	}
	if err := runtime.Verify(context.Background(), "generation-4"); err == nil {
		t.Fatal("Verify(wrong pinned version) error = nil")
	}
	runtime.Platform = func() string { return "windows" }
	if err := runtime.Activate(context.Background(), "generation-5", filepath.Join(runtime.Root, "generations", "generation-5")); err == nil {
		t.Fatal("Activate(non-Linux) error = nil")
	}
	if broker.blocks != 0 || len(switcher.activations) != 1 {
		t.Fatalf("non-Linux mutation side effects blocks/activations = %d/%v", broker.blocks, switcher.activations)
	}
}

func TestLinuxRuntimeExplicitFailClosedUsesBrokerBeforeRemovingGeneration(t *testing.T) {
	runtime, _, broker, switcher, _ := testLinuxRuntime(t)
	switcher.active = "generation-1"
	if err := runtime.FailClosed(context.Background()); err != nil {
		t.Fatalf("FailClosed() error = %v", err)
	}
	if broker.blocks != 1 || switcher.removes != 1 || switcher.active != "" {
		t.Fatalf("explicit fail-closed = block %d remove %d active %s", broker.blocks, switcher.removes, switcher.active)
	}
}

func testLinuxRuntime(t *testing.T) (*LinuxRuntime, *fakeAPI, *fakeBroker, *fakeSwitcher, *fakeTUN) {
	t.Helper()
	api := &fakeAPI{version: "v1.2.3"}
	broker := &fakeBroker{}
	switcher := &fakeSwitcher{}
	tun := &fakeTUN{}
	runtime := &LinuxRuntime{
		Root:            filepath.Join(t.TempDir(), "mihomo"),
		ExpectedVersion: "v1.2.3",
		TUNName:         "gateway-vpn-tun",
		API:             api,
		Broker:          broker,
		Switcher:        switcher,
		TUN:             tun,
		VerifyTimeout:   time.Second,
		VerifyInterval:  time.Millisecond,
		Platform:        func() string { return "linux" },
	}
	return runtime, api, broker, switcher, tun
}
