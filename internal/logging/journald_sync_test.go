package logging

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	databasepkg "gateway-vpn/internal/db"
	"gateway-vpn/internal/platformexec"
)

type journaldExecutor struct {
	requests     []platformexec.Request
	failRestarts int
}

func (executor *journaldExecutor) Run(_ context.Context, request platformexec.Request) (platformexec.Result, error) {
	executor.requests = append(executor.requests, request)
	if len(request.Arguments) > 0 && request.Arguments[0] == "restart" && executor.failRestarts > 0 {
		executor.failRestarts--
		return platformexec.Result{}, errors.New("scripted restart failure with private detail")
	}
	return platformexec.Result{}, nil
}

func TestJournaldSynchronizerAppliesDesiredPolicyAndBecomesNoOp(t *testing.T) {
	ctx, settingsRepository, runtimeRepository, paths := journaldFixture(t)
	clock := time.Date(2026, 8, 24, 19, 0, 0, 0, time.UTC)
	settingsRepository.Now = func() time.Time { return clock }
	runtimeRepository.Now = func() time.Time { return clock }
	updated, err := settingsRepository.Update(ctx, UpdateInput{
		GlobalLevel: LevelInfo, RetentionDays: 30, MaxDiskUsageBytes: 512 << 20,
		DiagnosticExcerptBytes: 2 << 20, HealthErrorAggregationSeconds: 60,
	})
	if err != nil {
		t.Fatal(err)
	}
	status, err := runtimeRepository.Get(ctx)
	if err != nil || status.State != RetentionPending || status.DesiredSHA256 != RetentionFingerprint(updated) {
		t.Fatalf("pending retention status = %+v, %v", status, err)
	}
	executor := &journaldExecutor{}
	synchronizer := JournaldSynchronizer{Settings: settingsRepository, Runtime: runtimeRepository, Executor: executor, Paths: paths}
	if err := synchronizer.SyncLogging(ctx); err != nil {
		t.Fatal(err)
	}
	written, err := os.ReadFile(paths.ConfigFile)
	if err != nil {
		t.Fatal(err)
	}
	want, _ := RenderJournaldConfig(updated)
	if string(written) != string(want) {
		t.Fatalf("journald config = %q, want %q", written, want)
	}
	status, err = runtimeRepository.Get(ctx)
	if err != nil || status.State != RetentionApplied || status.AppliedSHA256 != status.DesiredSHA256 || status.AppliedAt == "" || status.LastErrorCode != "" {
		t.Fatalf("applied retention status = %+v, %v", status, err)
	}
	if len(executor.requests) != 2 || executor.requests[0].Arguments[0] != "restart" || executor.requests[1].Arguments[0] != "is-active" {
		t.Fatalf("initial synchronizer commands = %+v", executor.requests)
	}
	if _, err := settingsRepository.Update(ctx, UpdateInput{
		GlobalLevel: LevelWarning, RetentionDays: 30, MaxDiskUsageBytes: 512 << 20,
		DiagnosticExcerptBytes: 2 << 20, HealthErrorAggregationSeconds: 60,
	}); err != nil {
		t.Fatal(err)
	}
	status, err = runtimeRepository.Get(ctx)
	if err != nil || status.State != RetentionApplied {
		t.Fatalf("level-only update retention status = %+v, %v", status, err)
	}
	executor.requests = nil
	if err := synchronizer.SyncLogging(ctx); err != nil {
		t.Fatal(err)
	}
	if len(executor.requests) != 1 || executor.requests[0].Arguments[0] != "is-active" {
		t.Fatalf("no-op synchronizer commands = %+v", executor.requests)
	}
}

func TestJournaldSynchronizerRollsBackFileAndRecordsStableFailure(t *testing.T) {
	ctx, settingsRepository, runtimeRepository, paths := journaldFixture(t)
	previous := []byte("[Journal]\nSystemMaxUse=128M\n")
	if err := os.WriteFile(paths.ConfigFile, previous, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := settingsRepository.Update(ctx, UpdateInput{
		GlobalLevel: LevelInfo, RetentionDays: 7, MaxDiskUsageBytes: 128 << 20,
		DiagnosticExcerptBytes: 1 << 20, HealthErrorAggregationSeconds: 60,
	}); err != nil {
		t.Fatal(err)
	}
	executor := &journaldExecutor{failRestarts: 1}
	synchronizer := JournaldSynchronizer{Settings: settingsRepository, Runtime: runtimeRepository, Executor: executor, Paths: paths}
	if err := synchronizer.SyncLogging(ctx); err == nil || len(executor.requests) != 3 {
		t.Fatalf("SyncLogging(failed) requests=%+v error=%v", executor.requests, err)
	}
	restored, err := os.ReadFile(paths.ConfigFile)
	if err != nil || string(restored) != string(previous) {
		t.Fatalf("restored config = %q, %v", restored, err)
	}
	status, err := runtimeRepository.Get(ctx)
	if err != nil || status.State != RetentionFailed || status.LastErrorCode != "JOURNALD_APPLY_FAILED" || status.AppliedSHA256 != "" {
		t.Fatalf("failed retention status = %+v, %v", status, err)
	}
}

func TestJournaldSynchronizerRejectsSymlinkConfig(t *testing.T) {
	ctx, settingsRepository, runtimeRepository, paths := journaldFixture(t)
	target := filepath.Join(filepath.Dir(paths.ConfigFile), "target")
	if err := os.WriteFile(target, []byte("safe"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, paths.ConfigFile); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	synchronizer := JournaldSynchronizer{Settings: settingsRepository, Runtime: runtimeRepository, Executor: &journaldExecutor{}, Paths: paths}
	if err := synchronizer.SyncLogging(ctx); err == nil {
		t.Fatal("symlink journald config was accepted")
	}
}

func journaldFixture(t *testing.T) (context.Context, Repository, RuntimeRepository, JournaldPaths) {
	t.Helper()
	ctx := context.Background()
	database, err := databasepkg.Open(ctx, databasepkg.OpenOptions{Path: filepath.Join(t.TempDir(), "state.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	if err := databasepkg.Migrate(ctx, database); err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(t.TempDir(), "journald@gateway-vpn.conf.d")
	if err := os.MkdirAll(directory, 0o755); err != nil {
		t.Fatal(err)
	}
	paths := JournaldPaths{
		ConfigFile: filepath.Join(directory, "retention.conf"),
		Systemctl:  filepath.Join(t.TempDir(), "systemctl"), Unit: journaldNamespaceUnit,
	}
	return ctx, Repository{Database: database}, RuntimeRepository{Database: database}, paths
}
