package vpsupdate

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"gateway-vpn/internal/platformexec"
)

type runtimeExecutor struct {
	requests    []platformexec.Request
	version     string
	database    string
	failUnit    string
	offline     OfflineResult
	offlineFail bool
}

func (executor *runtimeExecutor) Run(_ context.Context, request platformexec.Request) (platformexec.Result, error) {
	executor.requests = append(executor.requests, request)
	if len(request.Arguments) >= 3 && request.Arguments[0] == "is-active" {
		unit := request.Arguments[len(request.Arguments)-1]
		if unit == executor.failUnit {
			return platformexec.Result{ExitCode: 3}, errors.New("inactive")
		}
		return platformexec.Result{}, nil
	}
	if strings.HasSuffix(request.Executable, filepath.Join("bin", "gateway-vpn-vps-agent")) {
		if reflect.DeepEqual(request.Arguments, []string{"--version"}) {
			return platformexec.Result{Stdout: "gateway-vpn-vps-agent " + executor.version + " (test)\n"}, nil
		}
		if len(request.Arguments) > 0 && request.Arguments[0] == "state-check" {
			return platformexec.Result{}, nil
		}
		if len(request.Arguments) > 0 && request.Arguments[0] == "update-offline-check" {
			if executor.offlineFail {
				return platformexec.Result{}, errors.New("offline candidate rejected")
			}
			content, _ := json.Marshal(executor.offline)
			return platformexec.Result{Stdout: string(content) + "\n"}, nil
		}
	}
	return platformexec.Result{}, nil
}

func TestSystemRuntimeQuiescesOnlyOwnedControlPlaneUnits(t *testing.T) {
	executor := &runtimeExecutor{}
	runtime := SystemRuntime{Executor: executor, Systemctl: filepath.Join(t.TempDir(), "systemctl"), ReleaseRoot: filepath.Join(t.TempDir(), "gateway-vpn-vps")}
	if err := runtime.Quiesce(context.Background()); err != nil {
		t.Fatal(err)
	}
	want := append([]string{"stop"}, managedControlUnits...)
	if len(executor.requests) != 1 || !reflect.DeepEqual(executor.requests[0].Arguments, want) {
		t.Fatalf("Quiesce() requests = %+v", executor.requests)
	}
	for _, request := range executor.requests {
		joined := strings.ToLower(strings.Join(request.Arguments, " "))
		for _, forbidden := range []string{"amnezia", "docker", "ufw", "firewalld"} {
			if strings.Contains(joined, forbidden) {
				t.Fatalf("Quiesce() crossed ownership boundary with %q", forbidden)
			}
		}
	}
}

func TestSystemRuntimeStartsAndRequiresThreeHealthyObservations(t *testing.T) {
	releaseRoot := filepath.Join(t.TempDir(), "gateway-vpn-vps")
	databasePath := filepath.Join(t.TempDir(), "vps-agent.db")
	executor := &runtimeExecutor{version: "1.2.0", database: databasePath}
	runtime := SystemRuntime{Executor: executor, Systemctl: filepath.Join(t.TempDir(), "systemctl"), ReleaseRoot: releaseRoot}
	if err := runtime.StartAndHealth(context.Background(), "1.2.0", databasePath); err != nil {
		t.Fatal(err)
	}
	if len(executor.requests) < 3 || executor.requests[0].Arguments[0] != "reset-failed" || executor.requests[1].Arguments[0] != "start" {
		t.Fatalf("StartAndHealth() ordering = %+v", executor.requests)
	}
	versionChecks := 0
	for _, request := range executor.requests {
		if reflect.DeepEqual(request.Arguments, []string{"--version"}) {
			versionChecks++
		}
	}
	if versionChecks != 3 {
		t.Fatalf("healthy version observations = %d, want 3", versionChecks)
	}
}

func TestSystemRuntimeOfflineCheckRejectsEscapedPathsAndInvalidResult(t *testing.T) {
	releaseRoot := filepath.Join(t.TempDir(), "gateway-vpn-vps")
	candidate := filepath.Join(releaseRoot, "releases", "v1.2.0", "bin", "gateway-vpn-vps-agent")
	database := filepath.Join(t.TempDir(), "candidate.db")
	config := filepath.Join(t.TempDir(), "config.yaml")
	executor := &runtimeExecutor{offline: OfflineResult{Version: "1.2.0", SchemaVersion: 4, DatabaseBytes: 4096, DatabaseSHA256: strings.Repeat("a", 64), QuickCheck: "PASS", IntegrityCheck: "PASS", ForeignKeyCheck: "PASS"}}
	runtime := SystemRuntime{Executor: executor, Systemctl: filepath.Join(t.TempDir(), "systemctl"), ReleaseRoot: releaseRoot}
	if result, err := runtime.OfflineCheck(context.Background(), candidate, database, config, "1.2.0", 4); err != nil || result.Version != "1.2.0" {
		t.Fatalf("OfflineCheck() = %+v,%v", result, err)
	}
	if _, err := runtime.OfflineCheck(context.Background(), filepath.Join(t.TempDir(), "gateway-vpn-vps-agent"), database, config, "1.2.0", 4); err == nil {
		t.Fatal("escaped candidate binary was accepted")
	}
	executor.offline.QuickCheck = "FAIL"
	if _, err := runtime.OfflineCheck(context.Background(), candidate, database, config, "1.2.0", 4); err == nil {
		t.Fatal("invalid candidate result was accepted")
	}
}
