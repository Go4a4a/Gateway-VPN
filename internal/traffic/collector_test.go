package traffic

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	databasepkg "gateway-vpn/internal/db"
	"gateway-vpn/internal/platformexec"
)

const (
	testBootID    = "11111111-2222-3333-4444-555555555555"
	testSessionID = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
)

func TestCheckpointPreservesMonotonicTotalsAcrossCounterReset(t *testing.T) {
	ctx := context.Background()
	database, err := databasepkg.Open(ctx, databasepkg.OpenOptions{Path: filepath.Join(t.TempDir(), "state.db")})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if err := databasepkg.Migrate(ctx, database); err != nil {
		t.Fatal(err)
	}
	collector := Collector{Database: database}
	now := time.Date(2026, 8, 23, 10, 0, 0, 0, time.UTC)
	first, err := collector.Checkpoint(ctx, trafficSample(now, 1, Counters{UploadBytes: 100, DownloadBytes: 200, ServiceUploadBytes: 10, ServiceDownloadBytes: 20}, 90, 180))
	if err != nil || first.UploadDelta != 100 || first.DownloadDelta != 200 || first.ServiceUploadDelta != 10 || first.ServiceDownloadDelta != 20 {
		t.Fatalf("first checkpoint = %+v, %v", first, err)
	}
	second, err := collector.Checkpoint(ctx, trafficSample(now.Add(time.Minute), 1, Counters{UploadBytes: 150, DownloadBytes: 260, ServiceUploadBytes: 15, ServiceDownloadBytes: 30}, 120, 230))
	if err != nil || second.UploadDelta != 50 || second.DownloadDelta != 60 || second.ServiceUploadDelta != 5 || second.ServiceDownloadDelta != 10 || second.NFTReset {
		t.Fatalf("second checkpoint = %+v, %v", second, err)
	}
	reset, err := collector.Checkpoint(ctx, trafficSample(now.Add(2*time.Minute), 1, Counters{UploadBytes: 10, DownloadBytes: 20, ServiceUploadBytes: 2, ServiceDownloadBytes: 3}, 5, 10))
	if err != nil || !reset.NFTReset || !reset.MihomoReset || reset.UploadDelta != 10 || reset.ServiceUploadDelta != 2 || reset.ServiceDownloadDelta != 3 {
		t.Fatalf("reset checkpoint = %+v, %v", reset, err)
	}
	totals, err := collector.Daily(ctx, "2026-08-23", "2026-08-23")
	if err != nil || len(totals) != 1 || totals[0].UploadBytes != 160 || totals[0].DownloadBytes != 280 || totals[0].ServiceUploadBytes != 17 || totals[0].ServiceDownloadBytes != 33 {
		t.Fatalf("daily totals = %+v, %v", totals, err)
	}
}

func TestCheckpointTreatsBootAndNFTTableHandleAsCounterEpoch(t *testing.T) {
	ctx := context.Background()
	database, err := databasepkg.Open(ctx, databasepkg.OpenOptions{Path: filepath.Join(t.TempDir(), "state.db")})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if err := databasepkg.Migrate(ctx, database); err != nil {
		t.Fatal(err)
	}
	collector := Collector{Database: database}
	now := time.Date(2026, 8, 26, 10, 0, 0, 0, time.UTC)
	first, err := collector.Checkpoint(ctx, trafficSample(now, 7, Counters{UploadBytes: 100, DownloadBytes: 200, ServiceUploadBytes: 10, ServiceDownloadBytes: 20}, 50, 60))
	if err != nil || first.NFTReset {
		t.Fatalf("first checkpoint = %+v, %v", first, err)
	}
	second, err := collector.Checkpoint(ctx, trafficSample(now.Add(time.Minute), 7, Counters{UploadBytes: 150, DownloadBytes: 260, ServiceUploadBytes: 15, ServiceDownloadBytes: 30}, 80, 100))
	if err != nil || second.NFTReset || second.UploadDelta != 50 || second.DownloadDelta != 60 || second.ServiceUploadDelta != 5 || second.ServiceDownloadDelta != 10 {
		t.Fatalf("same epoch checkpoint = %+v, %v", second, err)
	}
	recreated, err := collector.Checkpoint(ctx, trafficSample(now.Add(2*time.Minute), 8, Counters{UploadBytes: 300, DownloadBytes: 400, ServiceUploadBytes: 30, ServiceDownloadBytes: 40}, 90, 120))
	if err != nil || !recreated.NFTReset || recreated.UploadDelta != 300 || recreated.DownloadDelta != 400 || recreated.ServiceUploadDelta != 30 || recreated.ServiceDownloadDelta != 40 {
		t.Fatalf("recreated table checkpoint = %+v, %v", recreated, err)
	}
	newBoot := trafficSample(now.Add(3*time.Minute), 1, Counters{UploadBytes: 500, DownloadBytes: 600, ServiceUploadBytes: 50, ServiceDownloadBytes: 60}, 10, 20)
	newBoot.BootID = "66666666-7777-4888-9999-aaaaaaaaaaaa"
	rebooted, err := collector.Checkpoint(ctx, newBoot)
	if err != nil || !rebooted.NFTReset || rebooted.UploadDelta != 500 || rebooted.DownloadDelta != 600 || rebooted.ServiceUploadDelta != 50 || rebooted.ServiceDownloadDelta != 60 {
		t.Fatalf("reboot checkpoint = %+v, %v", rebooted, err)
	}
	current, err := collector.Current(ctx, now.Add(3*time.Minute))
	if err != nil || current.UploadBytes != 950 || current.DownloadBytes != 1260 || current.ServiceUploadBytes != 95 || current.ServiceDownloadBytes != 130 || current.SessionUploadBytes != 950 || current.SessionServiceUploadBytes != 95 || current.SessionServiceDownloadBytes != 130 || current.CurrentUploadBPS != 10 || !current.MihomoAvailable {
		t.Fatalf("Current() = %+v, %v", current, err)
	}
	rows, err := database.QueryContext(ctx, "SELECT key, value_json FROM settings WHERE key LIKE 'traffic_%'")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var key, value string
		if err := rows.Scan(&key, &value); err != nil {
			t.Fatal(err)
		}
		if !json.Valid([]byte(value)) {
			t.Errorf("traffic setting %s is not valid JSON: %q", key, value)
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
}

func TestParseNFTJSONRequiresOwnedNamedCounters(t *testing.T) {
	content := []byte(`{"nftables":[{"metainfo":{"json_schema_version":1}},{"counter":{"family":"inet","name":"user_upload","table":"gateway_vpn","handle":1,"bytes":123,"packets":1}},{"counter":{"family":"inet","name":"user_download","table":"gateway_vpn","handle":2,"bytes":456,"packets":2}},{"counter":{"family":"inet","name":"service_upload","table":"gateway_vpn","handle":3,"bytes":12,"packets":3}},{"counter":{"family":"inet","name":"service_download","table":"gateway_vpn","handle":4,"bytes":34,"packets":4}}]}`)
	counters, err := ParseNFTJSON(content)
	if err != nil || counters.UploadBytes != 123 || counters.DownloadBytes != 456 || counters.ServiceUploadBytes != 12 || counters.ServiceDownloadBytes != 34 {
		t.Fatalf("ParseNFTJSON() = %+v, %v", counters, err)
	}
	if _, err := ParseNFTJSON([]byte(`{"nftables":[]}`)); err == nil {
		t.Fatal("ParseNFTJSON(missing) error = nil")
	}
}

func TestNFTReaderReturnsBootScopedTableGenerationAndCounters(t *testing.T) {
	bootPath := filepath.Join(t.TempDir(), "boot_id")
	if err := os.WriteFile(bootPath, []byte(testBootID+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	executor := &trafficExecutor{outputs: []string{
		`{"nftables":[{"table":{"family":"inet","name":"gateway_vpn","handle":19}}]}`,
		`{"nftables":[{"counter":{"family":"inet","name":"user_upload","table":"gateway_vpn","bytes":123}},{"counter":{"family":"inet","name":"user_download","table":"gateway_vpn","bytes":456}},{"counter":{"family":"inet","name":"service_upload","table":"gateway_vpn","bytes":12}},{"counter":{"family":"inet","name":"service_download","table":"gateway_vpn","bytes":34}}]}`,
	}}
	snapshot, err := (NFTReader{Executor: executor, NFT: "/usr/sbin/nft", BootIDPath: bootPath}).ReadTrafficCounters(context.Background())
	if err != nil || snapshot.BootID != testBootID || snapshot.FirewallGeneration != 19 || snapshot.UploadBytes != 123 || snapshot.DownloadBytes != 456 || snapshot.ServiceUploadBytes != 12 || snapshot.ServiceDownloadBytes != 34 {
		t.Fatalf("ReadTrafficCounters() = %+v, %v", snapshot, err)
	}
	if len(executor.requests) != 2 || executor.requests[0].MaxOutputBytes == 0 || executor.requests[1].MaxOutputBytes == 0 {
		t.Fatalf("bounded nft requests = %+v", executor.requests)
	}
	if _, err := ParseNFTTableGenerationJSON([]byte(`{"nftables":[{"table":{"family":"inet","name":"gateway_vpn","handle":0}}]}`)); err == nil {
		t.Fatal("zero table handle was accepted")
	}
}

func trafficSample(at time.Time, generation uint64, counters Counters, mihomoUpload, mihomoDownload uint64) Sample {
	return Sample{
		MeasuredAt: at, NFT: counters, BootID: testBootID, FirewallGeneration: generation,
		MihomoUploadTotal: mihomoUpload, MihomoDownloadTotal: mihomoDownload,
		CurrentUploadBPS: mihomoUpload, CurrentDownloadBPS: mihomoDownload, MihomoAvailable: true,
		SessionID: testSessionID, SessionStartedAt: time.Date(2026, 8, 26, 9, 0, 0, 0, time.UTC),
	}
}

type trafficExecutor struct {
	requests []platformexec.Request
	outputs  []string
}

func (executor *trafficExecutor) Run(_ context.Context, request platformexec.Request) (platformexec.Result, error) {
	executor.requests = append(executor.requests, request)
	output := executor.outputs[0]
	executor.outputs = executor.outputs[1:]
	return platformexec.Result{Stdout: output}, nil
}
