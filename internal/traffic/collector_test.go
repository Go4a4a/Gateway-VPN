package traffic

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	databasepkg "gateway-vpn/internal/db"
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
	first, err := collector.Checkpoint(ctx, Sample{MeasuredAt: now, NFT: Counters{UploadBytes: 100, DownloadBytes: 200}, MihomoUploadTotal: 90, MihomoDownloadTotal: 180})
	if err != nil || first.UploadDelta != 100 || first.DownloadDelta != 200 {
		t.Fatalf("first checkpoint = %+v, %v", first, err)
	}
	second, err := collector.Checkpoint(ctx, Sample{MeasuredAt: now.Add(time.Minute), NFT: Counters{UploadBytes: 150, DownloadBytes: 260}, MihomoUploadTotal: 120, MihomoDownloadTotal: 230})
	if err != nil || second.UploadDelta != 50 || second.DownloadDelta != 60 || second.NFTReset {
		t.Fatalf("second checkpoint = %+v, %v", second, err)
	}
	reset, err := collector.Checkpoint(ctx, Sample{MeasuredAt: now.Add(2 * time.Minute), NFT: Counters{UploadBytes: 10, DownloadBytes: 20}, MihomoUploadTotal: 5, MihomoDownloadTotal: 10})
	if err != nil || !reset.NFTReset || !reset.MihomoReset || reset.UploadDelta != 10 {
		t.Fatalf("reset checkpoint = %+v, %v", reset, err)
	}
	totals, err := collector.Daily(ctx, "2026-08-23", "2026-08-23")
	if err != nil || len(totals) != 1 || totals[0].UploadBytes != 160 || totals[0].DownloadBytes != 280 {
		t.Fatalf("daily totals = %+v, %v", totals, err)
	}
}

func TestParseNFTJSONRequiresOwnedNamedCounters(t *testing.T) {
	content := []byte(`{"nftables":[{"metainfo":{"json_schema_version":1}},{"counter":{"family":"inet","name":"user_upload","table":"gateway_vpn","bytes":123,"packets":1}},{"counter":{"family":"inet","name":"user_download","table":"gateway_vpn","bytes":456,"packets":2}}]}`)
	counters, err := ParseNFTJSON(content)
	if err != nil || counters.UploadBytes != 123 || counters.DownloadBytes != 456 {
		t.Fatalf("ParseNFTJSON() = %+v, %v", counters, err)
	}
	if _, err := ParseNFTJSON([]byte(`{"nftables":[]}`)); err == nil {
		t.Fatal("ParseNFTJSON(missing) error = nil")
	}
}
