package watchdog

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	databasepkg "gateway-vpn/internal/db"
)

func TestRepositoryDefaultsUpdateAndAudit(t *testing.T) {
	ctx := context.Background()
	database, err := databasepkg.Open(ctx, databasepkg.OpenOptions{Path: filepath.Join(t.TempDir(), "state.db")})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if err := databasepkg.Migrate(ctx, database); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC)
	repository := Repository{Database: database, Now: func() time.Time { return now }}
	defaults, err := repository.Get(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !defaults.Enabled || defaults.HostRebootEnabled || defaults.CheckIntervalSeconds != 15 {
		t.Fatalf("unsafe defaults = %+v", defaults)
	}
	updated, err := repository.Update(ctx, UpdateInput{
		Enabled: true, CheckIntervalSeconds: 20, FailureThreshold: 4, SuccessThreshold: 2,
		ReconcileEnabled: true, ComponentRestartEnabled: true, RestartCooldownSeconds: 45,
		MaxRestartsPerComponent: 4, RestartWindowSeconds: 1200,
		HostRebootEnabled: true, RebootAfterCriticalSeconds: 1200,
		MaxRebootsPer24h: 1, RebootGraceSeconds: 90,
	})
	if err != nil {
		t.Fatal(err)
	}
	if updated.UpdatedAt != now.Format(time.RFC3339Nano) || !updated.HostRebootEnabled {
		t.Fatalf("updated policy = %+v", updated)
	}
	var eventType, details string
	if err := database.QueryRowContext(ctx, "SELECT type, details_json FROM events WHERE type='WATCHDOG_SETTINGS_CHANGED'").Scan(&eventType, &details); err != nil {
		t.Fatal(err)
	}
	if eventType != "WATCHDOG_SETTINGS_CHANGED" || details == "" {
		t.Fatalf("audit event = %q %q", eventType, details)
	}
}

func TestPolicyRejectsUnboundedValues(t *testing.T) {
	input := UpdateInput{
		Enabled: true, CheckIntervalSeconds: 15, FailureThreshold: 3, SuccessThreshold: 2,
		ReconcileEnabled: true, ComponentRestartEnabled: true, RestartCooldownSeconds: 30,
		MaxRestartsPerComponent: 5, RestartWindowSeconds: 900,
		RebootAfterCriticalSeconds: 900, MaxRebootsPer24h: 1, RebootGraceSeconds: 60,
	}
	if _, err := NormalizeUpdate(input, time.Now()); err != nil {
		t.Fatalf("safe policy rejected: %v", err)
	}
	input.CheckIntervalSeconds = 1
	if _, err := NormalizeUpdate(input, time.Now()); err == nil {
		t.Fatal("unbounded check interval accepted")
	}
}
