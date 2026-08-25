// Package traffic stores only authoritative total traffic. Per-subscription
// attribution is intentionally absent in the MVP.
package traffic

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	"gateway-vpn/internal/platformexec"
)

const (
	UploadCounterName   = "user_upload"
	DownloadCounterName = "user_download"
)

type Counters struct {
	UploadBytes   uint64
	DownloadBytes uint64
}

type Sample struct {
	MeasuredAt          time.Time
	NFT                 Counters
	MihomoUploadTotal   uint64
	MihomoDownloadTotal uint64
}

type CheckpointResult struct {
	Date          string
	UploadDelta   uint64
	DownloadDelta uint64
	NFTReset      bool
	MihomoReset   bool
}

type DailyTotal struct {
	Date                string
	UploadBytes         uint64
	DownloadBytes       uint64
	MihomoUploadBytes   uint64
	MihomoDownloadBytes uint64
	CheckpointedAt      string
}

type Collector struct {
	Database *sql.DB
}

func (collector Collector) Checkpoint(ctx context.Context, sample Sample) (CheckpointResult, error) {
	if collector.Database == nil || sample.MeasuredAt.IsZero() {
		return CheckpointResult{}, errors.New("traffic database and measurement time are required")
	}
	transaction, err := collector.Database.BeginTx(ctx, nil)
	if err != nil {
		return CheckpointResult{}, fmt.Errorf("begin traffic checkpoint: %w", err)
	}
	defer transaction.Rollback()
	previousUpload, hasUpload, err := readSettingUint(ctx, transaction, "traffic_last_nft_upload")
	if err != nil {
		return CheckpointResult{}, err
	}
	previousDownload, hasDownload, err := readSettingUint(ctx, transaction, "traffic_last_nft_download")
	if err != nil {
		return CheckpointResult{}, err
	}
	previousMihomoUpload, hasMihomoUpload, err := readSettingUint(ctx, transaction, "traffic_last_mihomo_upload")
	if err != nil {
		return CheckpointResult{}, err
	}
	previousMihomoDownload, hasMihomoDownload, err := readSettingUint(ctx, transaction, "traffic_last_mihomo_download")
	if err != nil {
		return CheckpointResult{}, err
	}
	uploadDelta, uploadReset := delta(sample.NFT.UploadBytes, previousUpload, hasUpload)
	downloadDelta, downloadReset := delta(sample.NFT.DownloadBytes, previousDownload, hasDownload)
	mihomoUploadDelta, mihomoUploadReset := delta(sample.MihomoUploadTotal, previousMihomoUpload, hasMihomoUpload)
	mihomoDownloadDelta, mihomoDownloadReset := delta(sample.MihomoDownloadTotal, previousMihomoDownload, hasMihomoDownload)
	now := sample.MeasuredAt.UTC().Format(time.RFC3339Nano)
	date := sample.MeasuredAt.UTC().Format("2006-01-02")
	_, err = transaction.ExecContext(ctx, `
INSERT INTO traffic_daily_totals(
    date, download_bytes, upload_bytes, mihomo_download_bytes,
    mihomo_upload_bytes, checkpointed_at
) VALUES (?, ?, ?, ?, ?, ?)
ON CONFLICT(date) DO UPDATE SET
    download_bytes=download_bytes+excluded.download_bytes,
    upload_bytes=upload_bytes+excluded.upload_bytes,
    mihomo_download_bytes=mihomo_download_bytes+excluded.mihomo_download_bytes,
    mihomo_upload_bytes=mihomo_upload_bytes+excluded.mihomo_upload_bytes,
    checkpointed_at=excluded.checkpointed_at`, date, downloadDelta, uploadDelta, mihomoDownloadDelta, mihomoUploadDelta, now)
	if err != nil {
		return CheckpointResult{}, fmt.Errorf("update daily traffic totals: %w", err)
	}
	for key, value := range map[string]uint64{
		"traffic_last_nft_upload": sample.NFT.UploadBytes, "traffic_last_nft_download": sample.NFT.DownloadBytes,
		"traffic_last_mihomo_upload": sample.MihomoUploadTotal, "traffic_last_mihomo_download": sample.MihomoDownloadTotal,
	} {
		if _, err := transaction.ExecContext(ctx, `
INSERT INTO settings(key, value_json, updated_at) VALUES (?, ?, ?)
ON CONFLICT(key) DO UPDATE SET value_json=excluded.value_json, updated_at=excluded.updated_at`, key, strconv.FormatUint(value, 10), now); err != nil {
			return CheckpointResult{}, fmt.Errorf("save traffic counter checkpoint: %w", err)
		}
	}
	if err := transaction.Commit(); err != nil {
		return CheckpointResult{}, fmt.Errorf("commit traffic checkpoint: %w", err)
	}
	return CheckpointResult{Date: date, UploadDelta: uploadDelta, DownloadDelta: downloadDelta, NFTReset: uploadReset || downloadReset, MihomoReset: mihomoUploadReset || mihomoDownloadReset}, nil
}

func (collector Collector) Daily(ctx context.Context, from, to string) ([]DailyTotal, error) {
	if _, err := time.Parse("2006-01-02", from); err != nil {
		return nil, errors.New("traffic from date must use YYYY-MM-DD")
	}
	if _, err := time.Parse("2006-01-02", to); err != nil || to < from {
		return nil, errors.New("traffic to date must use YYYY-MM-DD and not precede from")
	}
	rows, err := collector.Database.QueryContext(ctx, `
SELECT date, upload_bytes, download_bytes, mihomo_upload_bytes,
       mihomo_download_bytes, checkpointed_at
FROM traffic_daily_totals WHERE date BETWEEN ? AND ? ORDER BY date`, from, to)
	if err != nil {
		return nil, fmt.Errorf("list daily traffic totals: %w", err)
	}
	defer rows.Close()
	var result []DailyTotal
	for rows.Next() {
		var item DailyTotal
		if err := rows.Scan(&item.Date, &item.UploadBytes, &item.DownloadBytes, &item.MihomoUploadBytes, &item.MihomoDownloadBytes, &item.CheckpointedAt); err != nil {
			return nil, fmt.Errorf("scan daily traffic total: %w", err)
		}
		result = append(result, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate daily traffic totals: %w", err)
	}
	return result, nil
}

func ParseNFTJSON(content []byte) (Counters, error) {
	if len(content) == 0 || len(content) > 4<<20 {
		return Counters{}, errors.New("nftables counter JSON is empty or oversized")
	}
	var document struct {
		NFTables []map[string]json.RawMessage `json:"nftables"`
	}
	if err := json.Unmarshal(content, &document); err != nil {
		return Counters{}, fmt.Errorf("decode nftables counters: %w", err)
	}
	values := make(map[string]uint64)
	for _, object := range document.NFTables {
		raw, exists := object["counter"]
		if !exists {
			continue
		}
		var counter struct {
			Family string `json:"family"`
			Table  string `json:"table"`
			Name   string `json:"name"`
			Bytes  uint64 `json:"bytes"`
		}
		if err := json.Unmarshal(raw, &counter); err != nil {
			return Counters{}, fmt.Errorf("decode named nftables counter: %w", err)
		}
		if counter.Family == "inet" && counter.Table == "gateway_vpn" && (counter.Name == UploadCounterName || counter.Name == DownloadCounterName) {
			if _, duplicate := values[counter.Name]; duplicate {
				return Counters{}, fmt.Errorf("duplicate nftables counter %s", counter.Name)
			}
			values[counter.Name] = counter.Bytes
		}
	}
	upload, uploadOK := values[UploadCounterName]
	download, downloadOK := values[DownloadCounterName]
	if !uploadOK || !downloadOK {
		return Counters{}, errors.New("Gateway VPN authoritative nftables counters are missing")
	}
	return Counters{UploadBytes: upload, DownloadBytes: download}, nil
}

func ReadNFTCounters(ctx context.Context, executor platformexec.Executor, nftExecutable string) (Counters, error) {
	result, err := executor.Run(ctx, platformexec.Request{Executable: nftExecutable, Arguments: []string{"--json", "list", "counters", "table", "inet", "gateway_vpn"}})
	if err != nil {
		return Counters{}, fmt.Errorf("read authoritative nftables counters: %w", err)
	}
	return ParseNFTJSON([]byte(result.Stdout))
}

func delta(current, previous uint64, hasPrevious bool) (uint64, bool) {
	if !hasPrevious {
		return current, false
	}
	if current >= previous {
		return current - previous, false
	}
	return current, true
}

func readSettingUint(ctx context.Context, transaction *sql.Tx, key string) (uint64, bool, error) {
	var raw string
	err := transaction.QueryRowContext(ctx, "SELECT value_json FROM settings WHERE key=?", key).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, fmt.Errorf("read traffic checkpoint %s: %w", key, err)
	}
	value, err := strconv.ParseUint(raw, 10, 64)
	if err != nil {
		return 0, false, fmt.Errorf("invalid traffic checkpoint %s", key)
	}
	return value, true, nil
}
