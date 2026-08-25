package logging

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
	"time"

	databasepkg "gateway-vpn/internal/db"
)

func TestRepositoryControllerPersistsTemporaryDebugAndRecoversExpiry(t *testing.T) {
	ctx := context.Background()
	database, err := databasepkg.Open(ctx, databasepkg.OpenOptions{Path: filepath.Join(t.TempDir(), "state.db")})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if err := databasepkg.Migrate(ctx, database); err != nil {
		t.Fatal(err)
	}
	clock := time.Date(2026, 8, 24, 15, 0, 0, 0, time.UTC)
	controller, err := NewController(BootstrapSettings("ERROR"), func() time.Time { return clock })
	if err != nil {
		t.Fatal(err)
	}
	if err := controller.Attach(ctx, database); err != nil {
		t.Fatal(err)
	}
	initial := controller.Snapshot()
	if initial.GlobalLevel != LevelInfo || initial.RetentionDays != 14 || initial.MaxDiskUsageBytes != 256<<20 || initial.DebugComponents == nil {
		t.Fatalf("migration defaults = %+v", initial)
	}
	updated, err := controller.Update(ctx, UpdateInput{
		GlobalLevel:     LevelWarning,
		ComponentLevels: map[string]string{ComponentSubscription: LevelError, ComponentAuthAudit: LevelInfo},
		DebugComponents: []string{ComponentPathHealth}, DebugTTL: MinimumDebugTTL,
		RetentionDays: 30, MaxDiskUsageBytes: 512 << 20,
		DiagnosticExcerptBytes: 2 << 20, HealthErrorAggregationSeconds: 90,
	})
	if err != nil {
		t.Fatal(err)
	}
	if updated.EffectiveLevel(ComponentPathHealth, clock) != LevelDebug || updated.EffectiveLevel(ComponentSystem, clock) != LevelWarning || updated.EffectiveLevel(ComponentAuthAudit, clock) != LevelInfo || controller.DebugRemaining() != MinimumDebugTTL {
		t.Fatalf("updated effective levels = %+v", updated)
	}
	var changedEvents int
	if err := database.QueryRowContext(ctx, "SELECT COUNT(*) FROM events WHERE type='LOGGING_SETTINGS_CHANGED'").Scan(&changedEvents); err != nil || changedEvents != 1 {
		t.Fatalf("settings audit events = %d, %v", changedEvents, err)
	}

	clock = clock.Add(MinimumDebugTTL + time.Second)
	if controller.Enabled(ComponentPathHealth, slog.LevelDebug) {
		t.Fatal("expired debug remained effective before durable cleanup")
	}
	recovered, changed, err := controller.RecoverExpired(ctx)
	if err != nil || !changed || len(recovered.DebugComponents) != 0 || recovered.DebugUntil != "" || recovered.EffectiveLevel(ComponentPathHealth, clock) != LevelWarning {
		t.Fatalf("RecoverExpired() = %+v, %v, %v", recovered, changed, err)
	}
	var expiredEvents int
	if err := database.QueryRowContext(ctx, "SELECT COUNT(*) FROM events WHERE type='LOGGING_DEBUG_EXPIRED'").Scan(&expiredEvents); err != nil || expiredEvents != 1 {
		t.Fatalf("debug expiry events = %d, %v", expiredEvents, err)
	}

	if _, err := controller.Update(ctx, UpdateInput{
		GlobalLevel: LevelInfo, DebugComponents: []string{ComponentAll}, DebugTTL: MinimumDebugTTL,
		RetentionDays: 14, MaxDiskUsageBytes: 256 << 20,
		DiagnosticExcerptBytes: 1 << 20, HealthErrorAggregationSeconds: 60,
	}); err != nil {
		t.Fatal(err)
	}
	clock = clock.Add(MinimumDebugTTL + time.Second)
	restarted, _ := NewController(DefaultSettings(), func() time.Time { return clock })
	if err := restarted.Attach(ctx, database); err != nil {
		t.Fatal(err)
	}
	if snapshot := restarted.Snapshot(); len(snapshot.DebugComponents) != 0 || snapshot.DebugUntil != "" {
		t.Fatalf("restart retained expired debug = %+v", snapshot)
	}
}

func TestLoggingSettingsRejectPermanentDebugAndAuditSuppression(t *testing.T) {
	settings := DefaultSettings()
	settings.GlobalLevel = LevelDebug
	if err := settings.Validate(); err == nil {
		t.Fatal("permanent global debug was accepted")
	}
	settings = DefaultSettings()
	settings.ComponentLevels[ComponentAuthAudit] = LevelError
	if err := settings.Validate(); err == nil {
		t.Fatal("auth/audit suppression was accepted")
	}
	if _, err := normalizeUpdate(UpdateInput{
		GlobalLevel: LevelInfo, DebugComponents: []string{ComponentSystem}, DebugTTL: time.Minute,
		RetentionDays: 14, MaxDiskUsageBytes: 256 << 20,
		DiagnosticExcerptBytes: 1 << 20, HealthErrorAggregationSeconds: 60,
	}, time.Now()); err == nil {
		t.Fatal("debug TTL below five minutes was accepted")
	}
}

func TestControllerRunAutomaticallyExpiresDebugAtDeadline(t *testing.T) {
	ctx := context.Background()
	database, err := databasepkg.Open(ctx, databasepkg.OpenOptions{Path: filepath.Join(t.TempDir(), "state.db")})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if err := databasepkg.Migrate(ctx, database); err != nil {
		t.Fatal(err)
	}
	settings := DefaultSettings()
	settings.DebugComponents = []string{ComponentSystem}
	settings.DebugUntil = time.Now().UTC().Add(100 * time.Millisecond).Format(time.RFC3339Nano)
	settings.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)
	payload, err := json.Marshal(settings)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(ctx, "UPDATE settings SET value_json=?, updated_at=? WHERE key='logging'", string(payload), settings.UpdatedAt); err != nil {
		t.Fatal(err)
	}
	controller, _ := NewController(DefaultSettings(), nil)
	if err := controller.Attach(ctx, database); err != nil {
		t.Fatal(err)
	}
	runContext, cancel := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() { done <- controller.Run(runContext) }()
	deadline := time.Now().Add(2 * time.Second)
	events := 0
	for events == 0 && time.Now().Before(deadline) {
		if err := database.QueryRowContext(ctx, "SELECT COUNT(*) FROM events WHERE type='LOGGING_DEBUG_EXPIRED'").Scan(&events); err != nil {
			cancel()
			t.Fatal(err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	if snapshot := controller.Snapshot(); snapshot.DebugUntil != "" || len(snapshot.DebugComponents) != 0 {
		cancel()
		t.Fatalf("automatic expiry snapshot = %+v", snapshot)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if events != 1 {
		t.Fatalf("automatic expiry events = %d", events)
	}
}

func TestHandlerFiltersPerComponentAndRedactsNestedSecretsBeforeJSON(t *testing.T) {
	clock := time.Date(2026, 8, 24, 16, 0, 0, 0, time.UTC)
	settings := DefaultSettings()
	settings.DebugComponents = []string{ComponentPathHealth}
	settings.DebugUntil = clock.Add(time.Hour).Format(time.RFC3339Nano)
	controller, err := NewController(settings, func() time.Time { return clock })
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	handler, err := NewHandler(slog.NewJSONHandler(&output, &slog.HandlerOptions{Level: slog.LevelDebug}), controller)
	if err != nil {
		t.Fatal(err)
	}
	logger := slog.New(handler)
	logger.With("component", ComponentSystem).Debug("hidden system debug")
	logger.With("component", ComponentPathHealth).Debug("visible health debug", "path_id", "path-a")
	logger.With("component", ComponentSystem, "api_secret", "with-attrs-secret").Info("stored attributes are redacted")
	logger.With("component", ComponentSystem).Info(
		"request https://alice:pass@example.com/check?token=query-secret and Bearer bearer-secret",
		"password", "plain-secret",
		"backup_passphrase", "portable-backup-secret",
		"subscription_url", "https://example.com/private-path?token=url-secret",
		"safe_url", "https://example.net/status?trace=private-query#fragment",
		"identity_hash", strings.Repeat("a", 64),
		"certificate_sha256", strings.Repeat("b", 64),
		"error", errors.New("proxy vless://uuid-secret@example.org:443#node token=error-secret"),
		"details", map[string]any{
			"api_key": "nested-secret", "nested": map[string]any{"response_body": "private body"},
			"endpoint_url": "https://example.org/path?q=private",
		},
	)
	text := output.String()
	for _, secret := range []string{"hidden system debug", "with-attrs-secret", "plain-secret", "portable-backup-secret", "query-secret", "bearer-secret", "private-path", "url-secret", "private-query", "uuid-secret", "error-secret", "nested-secret", "private body", strings.Repeat("a", 64)} {
		if strings.Contains(text, secret) {
			t.Fatalf("log output leaked %q: %s", secret, text)
		}
	}
	for _, expected := range []string{"visible health debug", redactedValue, "https://example.net/", "https://example.org/", strings.Repeat("b", 64), "[REDACTED_PROXY_URI]"} {
		if !strings.Contains(text, expected) {
			t.Fatalf("log output missing %q: %s", expected, text)
		}
	}
}

func TestHandlerKeepsAuditInfoAndAggregatesRepeatedHealthWarnings(t *testing.T) {
	clock := time.Date(2026, 8, 24, 17, 0, 0, 0, time.UTC)
	settings := DefaultSettings()
	settings.GlobalLevel = LevelError
	settings.ComponentLevels[ComponentPathHealth] = LevelWarning
	settings.HealthErrorAggregationSeconds = 60
	controller, _ := NewController(settings, func() time.Time { return clock })
	var output bytes.Buffer
	handler, _ := NewHandler(slog.NewJSONHandler(&output, &slog.HandlerOptions{Level: slog.LevelDebug}), controller)
	logger := slog.New(handler)
	logger.With("component", ComponentSystem).Info("filtered system info")
	logger.With("component", ComponentAuthAudit).Info("mandatory audit info")
	if strings.Contains(output.String(), "filtered system info") || !strings.Contains(output.String(), "mandatory audit info") {
		t.Fatalf("audit floor output = %s", output.String())
	}
	output.Reset()
	for _, at := range []time.Time{clock, clock.Add(10 * time.Second), clock.Add(61 * time.Second)} {
		record := slog.NewRecord(at, slog.LevelWarn, "target probe failed", 0)
		record.AddAttrs(slog.String("component", ComponentPathHealth), slog.String("path_id", "path-a"))
		if err := handler.Handle(context.Background(), record); err != nil {
			t.Fatal(err)
		}
	}
	lines := strings.Split(strings.TrimSpace(output.String()), "\n")
	if len(lines) != 2 || !strings.Contains(lines[1], `"suppressed_repeats":1`) {
		t.Fatalf("aggregated health output = %s", output.String())
	}
}
