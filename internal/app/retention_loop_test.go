package app

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	databasepkg "gateway-vpn/internal/db"
	retentionpkg "gateway-vpn/internal/retention"
)

func TestRetentionLoopConvergesImmediatelyAndStopsWithContext(t *testing.T) {
	ctx := context.Background()
	database, err := databasepkg.Open(ctx, databasepkg.OpenOptions{Path: filepath.Join(t.TempDir(), "state.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	if err := databasepkg.Migrate(ctx, database); err != nil {
		t.Fatal(err)
	}
	payloadRoot := filepath.Join(t.TempDir(), "subscriptions")
	if err := os.MkdirAll(payloadRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	old := time.Now().UTC().AddDate(-1, 0, 0).Format(time.RFC3339Nano)
	for index := 0; index < 2; index++ {
		if _, err := database.ExecContext(ctx, "INSERT INTO health_samples(measured_at,scope_type,state) VALUES(?, 'gateway', 'OK')", old); err != nil {
			t.Fatal(err)
		}
	}
	policy := retentionpkg.DefaultPolicy()
	policy.RowBatch = 1
	runtime := &Runtime{
		Retention:             &retentionpkg.Cleaner{Database: database, PayloadRoot: payloadRoot, Policy: policy},
		logger:                slog.New(slog.NewTextHandler(io.Discard, nil)),
		retentionInterval:     time.Hour,
		retentionBacklogDelay: 5 * time.Millisecond,
	}
	runContext, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- runtime.runRetentionLoop(runContext) }()
	deadline := time.Now().Add(2 * time.Second)
	for {
		var remaining int
		if err := database.QueryRowContext(ctx, "SELECT COUNT(*) FROM health_samples").Scan(&remaining); err != nil {
			cancel()
			t.Fatal(err)
		}
		if remaining == 0 {
			break
		}
		if time.Now().After(deadline) {
			cancel()
			t.Fatalf("retention backlog did not converge; %d rows remain", remaining)
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("runRetentionLoop() error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("retention loop did not stop")
	}
}
