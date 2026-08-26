package traffic

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	databasepkg "gateway-vpn/internal/db"
	"gateway-vpn/internal/mihomo"
)

func TestRunnerKeepsAuthoritativeCheckpointWhenMihomoIsUnavailable(t *testing.T) {
	database := trafficTestDatabase(t)
	defer database.Close()
	runner := Runner{
		Collector:     Collector{Database: database},
		Authoritative: &sequenceTrafficReader{snapshots: []AuthoritativeSnapshot{{Counters: Counters{UploadBytes: 100, DownloadBytes: 200, ServiceUploadBytes: 10, ServiceDownloadBytes: 20}, BootID: testBootID, FirewallGeneration: 5}}},
		Mihomo:        failingMihomoTraffic{}, SessionID: testSessionID,
		SessionStartedAt: time.Date(2026, 8, 26, 9, 0, 0, 0, time.UTC),
		Now:              func() time.Time { return time.Date(2026, 8, 26, 10, 0, 0, 0, time.UTC) },
	}
	result, err := runner.Checkpoint(context.Background())
	if err != nil || result.UploadDelta != 100 || result.DownloadDelta != 200 || result.ServiceUploadDelta != 10 || result.ServiceDownloadDelta != 20 {
		t.Fatalf("Checkpoint() = %+v, %v", result, err)
	}
	current, err := runner.Collector.Current(context.Background(), runner.Now())
	if err != nil || current.MihomoAvailable || current.UploadBytes != 100 || current.ServiceUploadBytes != 10 || current.ServiceDownloadBytes != 20 || current.CurrentUploadBPS != 0 {
		t.Fatalf("Current() = %+v, %v", current, err)
	}
}

func TestRunnerPerformsInitialAndGracefulFinalCheckpoint(t *testing.T) {
	database := trafficTestDatabase(t)
	defer database.Close()
	reader := &sequenceTrafficReader{snapshots: []AuthoritativeSnapshot{
		{Counters: Counters{UploadBytes: 10, DownloadBytes: 20, ServiceUploadBytes: 1, ServiceDownloadBytes: 2}, BootID: testBootID, FirewallGeneration: 5},
		{Counters: Counters{UploadBytes: 30, DownloadBytes: 50, ServiceUploadBytes: 3, ServiceDownloadBytes: 5}, BootID: testBootID, FirewallGeneration: 5},
	}, called: make(chan struct{}, 2)}
	runner := Runner{
		Collector: Collector{Database: database}, Authoritative: reader,
		Mihomo:   fixedMihomoTraffic{snapshot: mihomo.TrafficSnapshot{UploadBPS: 1, DownloadBPS: 2, UploadTotal: 3, DownloadTotal: 4}},
		Interval: time.Hour, SessionID: testSessionID,
		SessionStartedAt: time.Date(2026, 8, 26, 9, 0, 0, 0, time.UTC),
		Now:              func() time.Time { return time.Date(2026, 8, 26, 10, 0, 0, 0, time.UTC) },
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- runner.Run(ctx) }()
	select {
	case <-reader.called:
	case <-time.After(2 * time.Second):
		t.Fatal("initial checkpoint did not run")
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if reader.count() != 2 {
		t.Fatalf("traffic reads = %d, want initial and final", reader.count())
	}
	current, err := runner.Collector.Current(context.Background(), runner.Now())
	if err != nil || current.UploadBytes != 30 || current.DownloadBytes != 50 || current.ServiceUploadBytes != 3 || current.ServiceDownloadBytes != 5 || current.SessionUploadBytes != 30 || current.SessionServiceUploadBytes != 3 || current.SessionServiceDownloadBytes != 5 || !current.MihomoAvailable {
		t.Fatalf("Current() = %+v, %v", current, err)
	}
}

func trafficTestDatabase(t *testing.T) *sql.DB {
	t.Helper()
	ctx := context.Background()
	database, err := databasepkg.Open(ctx, databasepkg.OpenOptions{Path: filepath.Join(t.TempDir(), "state.db")})
	if err != nil {
		t.Fatal(err)
	}
	if err := databasepkg.Migrate(ctx, database); err != nil {
		database.Close()
		t.Fatal(err)
	}
	return database
}

type sequenceTrafficReader struct {
	mutex     sync.Mutex
	snapshots []AuthoritativeSnapshot
	reads     int
	called    chan struct{}
}

func (reader *sequenceTrafficReader) ReadTrafficCounters(context.Context) (AuthoritativeSnapshot, error) {
	reader.mutex.Lock()
	defer reader.mutex.Unlock()
	if reader.reads >= len(reader.snapshots) {
		return AuthoritativeSnapshot{}, errors.New("unexpected traffic read")
	}
	result := reader.snapshots[reader.reads]
	reader.reads++
	if reader.called != nil {
		reader.called <- struct{}{}
	}
	return result, nil
}

func (reader *sequenceTrafficReader) count() int {
	reader.mutex.Lock()
	defer reader.mutex.Unlock()
	return reader.reads
}

type failingMihomoTraffic struct{}

func (failingMihomoTraffic) Traffic(context.Context) (mihomo.TrafficSnapshot, error) {
	return mihomo.TrafficSnapshot{}, errors.New("offline")
}

type fixedMihomoTraffic struct{ snapshot mihomo.TrafficSnapshot }

func (reader fixedMihomoTraffic) Traffic(context.Context) (mihomo.TrafficSnapshot, error) {
	return reader.snapshot, nil
}
