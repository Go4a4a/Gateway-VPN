package update

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	databasepkg "gateway-vpn/internal/db"
)

func TestAutomationPolicyRepositoryDefaultsAndAuditsUpdate(t *testing.T) {
	ctx := context.Background()
	database, err := databasepkg.Open(ctx, databasepkg.OpenOptions{Path: t.TempDir() + "/state.db"})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if err := databasepkg.Migrate(ctx, database); err != nil {
		t.Fatal(err)
	}
	repository := AutomationPolicyRepository{Database: database, Now: func() time.Time { return time.Date(2026, 8, 31, 10, 0, 0, 0, time.UTC) }}
	current, err := repository.Get(ctx)
	if err != nil || current.Channel != "stable" || !current.AutomaticCheckEnabled || current.AutomaticDownloadEnabled || current.AutomaticApplyEnabled || current.RetentionPolicy() != DefaultRestorePointPolicy() {
		t.Fatalf("Get() = %+v,%v", current, err)
	}
	input := AutomationPolicyInput{
		Channel: "testing", AutomaticCheckEnabled: true, AutomaticDownloadEnabled: true,
		AutomaticApplyEnabled: true, CheckIntervalHours: 12, JitterMinutes: 20,
		MaintenanceWindowEnabled: true, MaintenanceStartMinuteUTC: 240, MaintenanceDurationMinutes: 90,
		MaximumApplyDelayHours: 48,
		RetentionMaximumPoints: 6, RetentionMaximumBytes: 12 << 30, RetentionMaximumAgeDays: 730, RetentionMinimumOldPoints: 3,
	}
	next, err := repository.Update(ctx, input)
	if err != nil || next.Channel != "testing" || !next.AutomaticApplyEnabled || next.MaximumApplyDelayHours != 48 || next.UpdatedAt != "2026-08-31T10:00:00Z" {
		t.Fatalf("Update() = %+v,%v", next, err)
	}
	var count int
	if err := database.QueryRowContext(ctx, "SELECT COUNT(*) FROM events WHERE type='SOFTWARE_UPDATE_POLICY_CHANGED'").Scan(&count); err != nil || count != 1 {
		t.Fatalf("audit count = %d,%v", count, err)
	}
}

func TestAutomationPolicyRejectsUnsafeAutomationCombinationsAndUnknownJSON(t *testing.T) {
	policy := DefaultAutomationPolicy()
	policy.AutomaticApplyEnabled = true
	if err := policy.Validate(); err == nil {
		t.Fatal("automatic apply without download/window was accepted")
	}
	policy = DefaultAutomationPolicy()
	policy.JitterMinutes = policy.CheckIntervalHours * 60
	if err := policy.Validate(); err == nil {
		t.Fatal("jitter equal to the full interval was accepted")
	}
	payload, _ := json.Marshal(DefaultAutomationPolicy())
	var object map[string]any
	_ = json.Unmarshal(payload, &object)
	object["unknown"] = true
	unknown, _ := json.Marshal(object)
	ctx := context.Background()
	database, err := databasepkg.Open(ctx, databasepkg.OpenOptions{Path: t.TempDir() + "/state.db"})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if err := databasepkg.Migrate(ctx, database); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(ctx, "UPDATE settings SET value_json=? WHERE key='software_update_policy'", string(unknown)); err != nil {
		t.Fatal(err)
	}
	if _, err := (AutomationPolicyRepository{Database: database}).Get(ctx); err == nil {
		t.Fatal("unknown stored policy field was accepted")
	}
}
