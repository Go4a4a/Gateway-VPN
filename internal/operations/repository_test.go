package operations

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	databasepkg "gateway-vpn/internal/db"
)

func TestOperationLifecyclePersistsRedactedOrderedSteps(t *testing.T) {
	ctx := context.Background()
	database, err := databasepkg.Open(ctx, databasepkg.OpenOptions{Path: filepath.Join(t.TempDir(), "state.db")})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if err := databasepkg.Migrate(ctx, database); err != nil {
		t.Fatal(err)
	}
	repository := NewRepository(database)
	clock := time.Date(2026, 8, 27, 10, 0, 0, 0, time.UTC)
	repository.now = func() time.Time { return clock }
	created, err := repository.Create(ctx, CreateInput{ID: "operation-1", Kind: "SUBSCRIPTION_REFRESH", ScopeType: "SUBSCRIPTION", ScopeID: "sub-a", RequestedBy: "user:1"})
	if err != nil || created.Status != StatusQueued || created.StartedAt != "" || created.FinishedAt != "" {
		t.Fatalf("Create() = %+v, %v", created, err)
	}
	started, err := repository.Start(ctx, created.ID, StepInput{Severity: "INFO", Stage: "ROUTE_SELECTED", Code: "VPN_ROUTE", Message: "using https://user:secret@example.test/token=hidden", Details: map[string]any{"authorization": "Bearer top-secret"}})
	if err != nil || started.Status != StatusRunning || len(started.Steps) != 1 {
		t.Fatalf("Start() = %+v, %v", started, err)
	}
	serialized := started.Steps[0].Message + started.Steps[0].DetailsJSON
	if strings.Contains(serialized, "secret") || strings.Contains(serialized, "hidden") || !strings.Contains(serialized, "REDACTED") {
		t.Fatalf("operation step was not redacted: %q", serialized)
	}
	clock = clock.Add(time.Second)
	if _, err := repository.AppendStep(ctx, created.ID, StepInput{Severity: "INFO", Stage: "HTTP", Code: "HTTP_OK", Message: "source reachable"}); err != nil {
		t.Fatal(err)
	}
	clock = clock.Add(time.Second)
	finished, err := repository.Finish(ctx, created.ID, StatusSucceeded, "REFRESH_COMPLETE", StepInput{Severity: "INFO", Stage: "COMPLETE", Code: "REFRESH_COMPLETE", Message: "subscription updated"})
	if err != nil || finished.Status != StatusSucceeded || finished.FinishedAt == "" || len(finished.Steps) != 3 || finished.Steps[2].Sequence != 3 {
		t.Fatalf("Finish() = %+v, %v", finished, err)
	}
	if _, err := repository.AppendStep(ctx, created.ID, StepInput{Severity: "INFO", Stage: "HTTP", Code: "LATE", Message: "late"}); err == nil {
		t.Fatal("terminal operation accepted another step")
	}
	cleared, err := repository.ClearCompleted(ctx, 10)
	if err != nil || cleared != 1 {
		t.Fatalf("ClearCompleted() = %d, %v", cleared, err)
	}
}

func TestOperationInputAndTerminalTransitionsAreBounded(t *testing.T) {
	ctx := context.Background()
	database, err := databasepkg.Open(ctx, databasepkg.OpenOptions{Path: filepath.Join(t.TempDir(), "state.db")})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if err := databasepkg.Migrate(ctx, database); err != nil {
		t.Fatal(err)
	}
	repository := NewRepository(database)
	if _, err := repository.Create(ctx, CreateInput{ID: "bad", Kind: "lowercase", ScopeType: "SUBSCRIPTION"}); err == nil {
		t.Fatal("invalid operation token accepted")
	}
	if _, err := repository.Create(ctx, CreateInput{ID: "operation-2", Kind: "PROBE", ScopeType: "MODEM"}); err != nil {
		t.Fatal(err)
	}
	if _, err := repository.Finish(ctx, "operation-2", "UNKNOWN", "BAD", StepInput{}); err == nil {
		t.Fatal("invalid terminal status accepted")
	}
}

func TestOperationRejectsStepsBeyondHardBound(t *testing.T) {
	ctx := context.Background()
	database, err := databasepkg.Open(ctx, databasepkg.OpenOptions{Path: filepath.Join(t.TempDir(), "state.db")})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if err := databasepkg.Migrate(ctx, database); err != nil {
		t.Fatal(err)
	}
	repository := NewRepository(database)
	if _, err := repository.Create(ctx, CreateInput{ID: "bounded", Kind: "PROBE", ScopeType: "MODEM"}); err != nil {
		t.Fatal(err)
	}
	if _, err := repository.Start(ctx, "bounded", StepInput{Severity: "INFO", Stage: "QUEUED", Code: "STARTED", Message: "started"}); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(ctx, "UPDATE operation_steps SET sequence=? WHERE operation_id='bounded'", MaximumStepsPerOperation); err != nil {
		t.Fatal(err)
	}
	if _, err := repository.AppendStep(ctx, "bounded", StepInput{Severity: "INFO", Stage: "HTTP", Code: "TOO_MANY", Message: "overflow"}); err == nil {
		t.Fatal("operation accepted a step beyond its hard bound")
	}
}
