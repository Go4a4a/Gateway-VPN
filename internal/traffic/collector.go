// Package traffic stores only authoritative total traffic. Per-subscription
// attribution is intentionally absent in the MVP.
package traffic

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"gateway-vpn/internal/platformexec"
)

const (
	UploadCounterName          = "user_upload"
	DownloadCounterName        = "user_download"
	ServiceUploadCounterName   = "service_upload"
	ServiceDownloadCounterName = "service_download"
)

type Counters struct {
	UploadBytes          uint64 `json:"upload_bytes"`
	DownloadBytes        uint64 `json:"download_bytes"`
	ServiceUploadBytes   uint64 `json:"service_upload_bytes"`
	ServiceDownloadBytes uint64 `json:"service_download_bytes"`
}

// AuthoritativeSnapshot is produced only by the privileged network broker.
// The boot id and nftables table handle form a counter epoch: the table handle
// changes whenever the owned table is deleted and recreated in one boot, while
// boot id disambiguates handle reuse after reboot.
type AuthoritativeSnapshot struct {
	Counters
	BootID             string `json:"boot_id"`
	FirewallGeneration uint64 `json:"firewall_generation"`
}

type Sample struct {
	MeasuredAt          time.Time
	NFT                 Counters
	BootID              string
	FirewallGeneration  uint64
	MihomoUploadTotal   uint64
	MihomoDownloadTotal uint64
	CurrentUploadBPS    uint64
	CurrentDownloadBPS  uint64
	MihomoAvailable     bool
	SessionID           string
	SessionStartedAt    time.Time
}

type CheckpointResult struct {
	Date                 string
	UploadDelta          uint64
	DownloadDelta        uint64
	ServiceUploadDelta   uint64
	ServiceDownloadDelta uint64
	NFTReset             bool
	MihomoReset          bool
}

type DailyTotal struct {
	Date                 string `json:"date"`
	UploadBytes          uint64 `json:"upload_bytes"`
	DownloadBytes        uint64 `json:"download_bytes"`
	ServiceUploadBytes   uint64 `json:"service_upload_bytes"`
	ServiceDownloadBytes uint64 `json:"service_download_bytes"`
	MihomoUploadBytes    uint64 `json:"mihomo_upload_bytes"`
	MihomoDownloadBytes  uint64 `json:"mihomo_download_bytes"`
	CheckpointedAt       string `json:"checkpointed_at"`
}

type CurrentTotal struct {
	DailyTotal
	CurrentUploadBPS            uint64 `json:"current_upload_bps"`
	CurrentDownloadBPS          uint64 `json:"current_download_bps"`
	SessionUploadBytes          uint64 `json:"session_upload_bytes"`
	SessionDownloadBytes        uint64 `json:"session_download_bytes"`
	SessionServiceUploadBytes   uint64 `json:"session_service_upload_bytes"`
	SessionServiceDownloadBytes uint64 `json:"session_service_download_bytes"`
	SessionStartedAt            string `json:"session_started_at,omitempty"`
	MihomoAvailable             bool   `json:"mihomo_available"`
}

type Collector struct {
	Database *sql.DB
}

func (collector Collector) Checkpoint(ctx context.Context, sample Sample) (CheckpointResult, error) {
	if collector.Database == nil || sample.MeasuredAt.IsZero() || sample.SessionStartedAt.IsZero() || !validBootID(sample.BootID) || sample.FirewallGeneration == 0 || !validSessionID(sample.SessionID) {
		return CheckpointResult{}, errors.New("traffic database, source epoch, session, and measurement time are required")
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
	previousServiceUpload, hasServiceUpload, err := readSettingUint(ctx, transaction, "traffic_last_nft_service_upload")
	if err != nil {
		return CheckpointResult{}, err
	}
	previousServiceDownload, hasServiceDownload, err := readSettingUint(ctx, transaction, "traffic_last_nft_service_download")
	if err != nil {
		return CheckpointResult{}, err
	}
	previousBootID, hasBootID, err := readSettingString(ctx, transaction, "traffic_last_boot_id")
	if err != nil {
		return CheckpointResult{}, err
	}
	previousFirewallGeneration, hasFirewallGeneration, err := readSettingUint(ctx, transaction, "traffic_last_firewall_generation")
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
	sameNFTGeneration := hasUpload && hasDownload && hasServiceUpload && hasServiceDownload && hasBootID && hasFirewallGeneration && previousBootID == sample.BootID && previousFirewallGeneration == sample.FirewallGeneration
	uploadDelta, uploadReset := delta(sample.NFT.UploadBytes, previousUpload, sameNFTGeneration)
	downloadDelta, downloadReset := delta(sample.NFT.DownloadBytes, previousDownload, sameNFTGeneration)
	serviceUploadDelta, serviceUploadReset := delta(sample.NFT.ServiceUploadBytes, previousServiceUpload, sameNFTGeneration)
	serviceDownloadDelta, serviceDownloadReset := delta(sample.NFT.ServiceDownloadBytes, previousServiceDownload, sameNFTGeneration)
	if (hasUpload || hasDownload || hasServiceUpload || hasServiceDownload || hasBootID || hasFirewallGeneration) && !sameNFTGeneration {
		uploadReset, downloadReset, serviceUploadReset, serviceDownloadReset = true, true, true, true
	}
	previousMihomoAvailable, hasMihomoAvailability, err := readSettingUint(ctx, transaction, "traffic_last_mihomo_available")
	if err != nil {
		return CheckpointResult{}, err
	}
	mihomoUploadDelta, mihomoDownloadDelta := uint64(0), uint64(0)
	mihomoUploadReset, mihomoDownloadReset := false, false
	if sample.MihomoAvailable {
		if hasMihomoAvailability && previousMihomoAvailable == 0 {
			// A gap cannot prove how much of the process total belongs to this
			// interval. Establish a new baseline without inventing bytes.
			mihomoUploadReset, mihomoDownloadReset = true, true
		} else {
			mihomoUploadDelta, mihomoUploadReset = delta(sample.MihomoUploadTotal, previousMihomoUpload, hasMihomoUpload)
			mihomoDownloadDelta, mihomoDownloadReset = delta(sample.MihomoDownloadTotal, previousMihomoDownload, hasMihomoDownload)
		}
	}
	previousSessionID, hasSessionID, err := readSettingString(ctx, transaction, "traffic_session_id")
	if err != nil {
		return CheckpointResult{}, err
	}
	sessionUpload, sessionDownload, sessionServiceUpload, sessionServiceDownload := uint64(0), uint64(0), uint64(0), uint64(0)
	if hasSessionID && previousSessionID == sample.SessionID {
		if sessionUpload, _, err = readSettingUint(ctx, transaction, "traffic_session_upload"); err != nil {
			return CheckpointResult{}, err
		}
		if sessionDownload, _, err = readSettingUint(ctx, transaction, "traffic_session_download"); err != nil {
			return CheckpointResult{}, err
		}
		if sessionServiceUpload, _, err = readSettingUint(ctx, transaction, "traffic_session_service_upload"); err != nil {
			return CheckpointResult{}, err
		}
		if sessionServiceDownload, _, err = readSettingUint(ctx, transaction, "traffic_session_service_download"); err != nil {
			return CheckpointResult{}, err
		}
	}
	sessionUpload += uploadDelta
	sessionDownload += downloadDelta
	sessionServiceUpload += serviceUploadDelta
	sessionServiceDownload += serviceDownloadDelta
	now := sample.MeasuredAt.UTC().Format(time.RFC3339Nano)
	date := sample.MeasuredAt.UTC().Format("2006-01-02")
	_, err = transaction.ExecContext(ctx, `
INSERT INTO traffic_daily_totals(
    date, download_bytes, upload_bytes, service_download_bytes,
    service_upload_bytes, mihomo_download_bytes, mihomo_upload_bytes, checkpointed_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(date) DO UPDATE SET
    download_bytes=download_bytes+excluded.download_bytes,
    upload_bytes=upload_bytes+excluded.upload_bytes,
    service_download_bytes=service_download_bytes+excluded.service_download_bytes,
    service_upload_bytes=service_upload_bytes+excluded.service_upload_bytes,
    mihomo_download_bytes=mihomo_download_bytes+excluded.mihomo_download_bytes,
    mihomo_upload_bytes=mihomo_upload_bytes+excluded.mihomo_upload_bytes,
    checkpointed_at=excluded.checkpointed_at`, date, downloadDelta, uploadDelta, serviceDownloadDelta, serviceUploadDelta, mihomoDownloadDelta, mihomoUploadDelta, now)
	if err != nil {
		return CheckpointResult{}, fmt.Errorf("update daily traffic totals: %w", err)
	}
	uintSettings := map[string]uint64{
		"traffic_last_nft_upload": sample.NFT.UploadBytes, "traffic_last_nft_download": sample.NFT.DownloadBytes,
		"traffic_last_nft_service_upload": sample.NFT.ServiceUploadBytes, "traffic_last_nft_service_download": sample.NFT.ServiceDownloadBytes,
		"traffic_last_firewall_generation": sample.FirewallGeneration,
		"traffic_last_mihomo_available":    boolUint(sample.MihomoAvailable),
		"traffic_current_upload_bps":       sample.CurrentUploadBPS, "traffic_current_download_bps": sample.CurrentDownloadBPS,
		"traffic_session_upload": sessionUpload, "traffic_session_download": sessionDownload,
		"traffic_session_service_upload": sessionServiceUpload, "traffic_session_service_download": sessionServiceDownload,
	}
	if sample.MihomoAvailable {
		uintSettings["traffic_last_mihomo_upload"] = sample.MihomoUploadTotal
		uintSettings["traffic_last_mihomo_download"] = sample.MihomoDownloadTotal
	}
	for key, value := range uintSettings {
		if err := upsertSetting(ctx, transaction, key, strconv.FormatUint(value, 10), now); err != nil {
			return CheckpointResult{}, err
		}
	}
	for key, value := range map[string]string{
		"traffic_last_boot_id": sample.BootID, "traffic_session_id": sample.SessionID,
		"traffic_session_started_at": sample.SessionStartedAt.UTC().Format(time.RFC3339Nano), "traffic_last_checkpoint_at": now,
	} {
		encoded, err := json.Marshal(value)
		if err != nil {
			return CheckpointResult{}, fmt.Errorf("encode traffic checkpoint %s: %w", key, err)
		}
		if err := upsertSetting(ctx, transaction, key, string(encoded), now); err != nil {
			return CheckpointResult{}, err
		}
	}
	if err := transaction.Commit(); err != nil {
		return CheckpointResult{}, fmt.Errorf("commit traffic checkpoint: %w", err)
	}
	return CheckpointResult{
		Date: date, UploadDelta: uploadDelta, DownloadDelta: downloadDelta,
		ServiceUploadDelta: serviceUploadDelta, ServiceDownloadDelta: serviceDownloadDelta,
		NFTReset:    uploadReset || downloadReset || serviceUploadReset || serviceDownloadReset,
		MihomoReset: mihomoUploadReset || mihomoDownloadReset,
	}, nil
}

func (collector Collector) Current(ctx context.Context, at time.Time) (CurrentTotal, error) {
	if collector.Database == nil || at.IsZero() {
		return CurrentTotal{}, errors.New("traffic database and current time are required")
	}
	date := at.UTC().Format("2006-01-02")
	transaction, err := collector.Database.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return CurrentTotal{}, err
	}
	defer transaction.Rollback()
	result := CurrentTotal{DailyTotal: DailyTotal{Date: date}}
	err = transaction.QueryRowContext(ctx, `
SELECT date, upload_bytes, download_bytes, service_upload_bytes,
       service_download_bytes, mihomo_upload_bytes, mihomo_download_bytes, checkpointed_at
FROM traffic_daily_totals WHERE date=?`, date).Scan(
		&result.Date, &result.UploadBytes, &result.DownloadBytes, &result.ServiceUploadBytes,
		&result.ServiceDownloadBytes, &result.MihomoUploadBytes, &result.MihomoDownloadBytes, &result.CheckpointedAt,
	)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return CurrentTotal{}, fmt.Errorf("read current daily traffic total: %w", err)
	}
	if result.CurrentUploadBPS, _, err = readSettingUint(ctx, transaction, "traffic_current_upload_bps"); err != nil {
		return CurrentTotal{}, err
	}
	if result.CurrentDownloadBPS, _, err = readSettingUint(ctx, transaction, "traffic_current_download_bps"); err != nil {
		return CurrentTotal{}, err
	}
	if result.SessionUploadBytes, _, err = readSettingUint(ctx, transaction, "traffic_session_upload"); err != nil {
		return CurrentTotal{}, err
	}
	if result.SessionDownloadBytes, _, err = readSettingUint(ctx, transaction, "traffic_session_download"); err != nil {
		return CurrentTotal{}, err
	}
	if result.SessionServiceUploadBytes, _, err = readSettingUint(ctx, transaction, "traffic_session_service_upload"); err != nil {
		return CurrentTotal{}, err
	}
	if result.SessionServiceDownloadBytes, _, err = readSettingUint(ctx, transaction, "traffic_session_service_download"); err != nil {
		return CurrentTotal{}, err
	}
	if result.SessionStartedAt, _, err = readSettingString(ctx, transaction, "traffic_session_started_at"); err != nil {
		return CurrentTotal{}, err
	}
	available, _, err := readSettingUint(ctx, transaction, "traffic_last_mihomo_available")
	if err != nil {
		return CurrentTotal{}, err
	}
	result.MihomoAvailable = available == 1
	if err := transaction.Commit(); err != nil {
		return CurrentTotal{}, fmt.Errorf("complete current traffic snapshot: %w", err)
	}
	return result, nil
}

func (collector Collector) Daily(ctx context.Context, from, to string) ([]DailyTotal, error) {
	if _, err := time.Parse("2006-01-02", from); err != nil {
		return nil, errors.New("traffic from date must use YYYY-MM-DD")
	}
	if _, err := time.Parse("2006-01-02", to); err != nil || to < from {
		return nil, errors.New("traffic to date must use YYYY-MM-DD and not precede from")
	}
	rows, err := collector.Database.QueryContext(ctx, `
SELECT date, upload_bytes, download_bytes, service_upload_bytes,
       service_download_bytes, mihomo_upload_bytes, mihomo_download_bytes, checkpointed_at
FROM traffic_daily_totals WHERE date BETWEEN ? AND ? ORDER BY date`, from, to)
	if err != nil {
		return nil, fmt.Errorf("list daily traffic totals: %w", err)
	}
	defer rows.Close()
	var result []DailyTotal
	for rows.Next() {
		var item DailyTotal
		if err := rows.Scan(&item.Date, &item.UploadBytes, &item.DownloadBytes, &item.ServiceUploadBytes, &item.ServiceDownloadBytes, &item.MihomoUploadBytes, &item.MihomoDownloadBytes, &item.CheckpointedAt); err != nil {
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
		if counter.Family == "inet" && counter.Table == "gateway_vpn" && (counter.Name == UploadCounterName || counter.Name == DownloadCounterName || counter.Name == ServiceUploadCounterName || counter.Name == ServiceDownloadCounterName) {
			if _, duplicate := values[counter.Name]; duplicate {
				return Counters{}, fmt.Errorf("duplicate nftables counter %s", counter.Name)
			}
			values[counter.Name] = counter.Bytes
		}
	}
	upload, uploadOK := values[UploadCounterName]
	download, downloadOK := values[DownloadCounterName]
	serviceUpload, serviceUploadOK := values[ServiceUploadCounterName]
	serviceDownload, serviceDownloadOK := values[ServiceDownloadCounterName]
	if !uploadOK || !downloadOK || !serviceUploadOK || !serviceDownloadOK {
		return Counters{}, errors.New("Gateway VPN authoritative nftables counters are missing")
	}
	return Counters{UploadBytes: upload, DownloadBytes: download, ServiceUploadBytes: serviceUpload, ServiceDownloadBytes: serviceDownload}, nil
}

func ReadNFTCounters(ctx context.Context, executor platformexec.Executor, nftExecutable string) (Counters, error) {
	result, err := executor.Run(ctx, platformexec.Request{Executable: nftExecutable, Arguments: []string{"--json", "list", "counters", "table", "inet", "gateway_vpn"}, MaxOutputBytes: 64 << 10})
	if err != nil {
		return Counters{}, fmt.Errorf("read authoritative nftables counters: %w", err)
	}
	return ParseNFTJSON([]byte(result.Stdout))
}

type NFTReader struct {
	Executor   platformexec.Executor
	NFT        string
	BootIDPath string
}

func (reader NFTReader) ReadTrafficCounters(ctx context.Context) (AuthoritativeSnapshot, error) {
	if reader.Executor == nil || reader.NFT != "/usr/sbin/nft" {
		return AuthoritativeSnapshot{}, errors.New("fixed nftables traffic reader is required")
	}
	bootPath := reader.BootIDPath
	if bootPath == "" {
		bootPath = "/proc/sys/kernel/random/boot_id"
	}
	if bootPath != "/proc/sys/kernel/random/boot_id" && !strings.HasSuffix(bootPath, string(os.PathSeparator)+"boot_id") {
		return AuthoritativeSnapshot{}, errors.New("traffic boot id path is invalid")
	}
	bootContent, err := os.ReadFile(bootPath)
	if err != nil {
		return AuthoritativeSnapshot{}, errors.New("read traffic boot id failed")
	}
	bootID := strings.TrimSpace(string(bootContent))
	if !validBootID(bootID) {
		return AuthoritativeSnapshot{}, errors.New("traffic boot id is invalid")
	}
	tables, err := reader.Executor.Run(ctx, platformexec.Request{Executable: reader.NFT, Arguments: []string{"--json", "list", "tables"}, MaxOutputBytes: 256 << 10})
	if err != nil {
		return AuthoritativeSnapshot{}, fmt.Errorf("read nftables table generation: %w", err)
	}
	generation, err := ParseNFTTableGenerationJSON([]byte(tables.Stdout))
	if err != nil {
		return AuthoritativeSnapshot{}, err
	}
	counters, err := ReadNFTCounters(ctx, reader.Executor, reader.NFT)
	if err != nil {
		return AuthoritativeSnapshot{}, err
	}
	return AuthoritativeSnapshot{Counters: counters, BootID: bootID, FirewallGeneration: generation}, nil
}

func ParseNFTTableGenerationJSON(content []byte) (uint64, error) {
	if len(content) == 0 || len(content) > 256<<10 {
		return 0, errors.New("nftables table JSON is empty or oversized")
	}
	var document struct {
		NFTables []map[string]json.RawMessage `json:"nftables"`
	}
	if err := json.Unmarshal(content, &document); err != nil {
		return 0, errors.New("decode nftables table generation failed")
	}
	var generation uint64
	for _, object := range document.NFTables {
		raw, exists := object["table"]
		if !exists {
			continue
		}
		var table struct {
			Family string `json:"family"`
			Name   string `json:"name"`
			Handle uint64 `json:"handle"`
		}
		if json.Unmarshal(raw, &table) != nil || table.Family != "inet" || table.Name != "gateway_vpn" {
			continue
		}
		if table.Handle == 0 || generation != 0 {
			return 0, errors.New("Gateway VPN nftables table generation is invalid")
		}
		generation = table.Handle
	}
	if generation == 0 {
		return 0, errors.New("Gateway VPN nftables table generation is missing")
	}
	return generation, nil
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
	raw, exists, err := readSettingRaw(ctx, transaction, key)
	if err != nil || !exists {
		return 0, exists, err
	}
	value, err := strconv.ParseUint(raw, 10, 64)
	if err != nil {
		return 0, false, fmt.Errorf("invalid traffic checkpoint %s", key)
	}
	return value, true, nil
}

func readSettingString(ctx context.Context, transaction *sql.Tx, key string) (string, bool, error) {
	raw, exists, err := readSettingRaw(ctx, transaction, key)
	if err != nil || !exists {
		return "", exists, err
	}
	var value string
	if err := json.Unmarshal([]byte(raw), &value); err != nil {
		return "", false, fmt.Errorf("invalid traffic string checkpoint %s", key)
	}
	return value, true, nil
}

func readSettingRaw(ctx context.Context, transaction *sql.Tx, key string) (string, bool, error) {
	var raw string
	err := transaction.QueryRowContext(ctx, "SELECT value_json FROM settings WHERE key=?", key).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("read traffic checkpoint %s: %w", key, err)
	}
	return raw, true, nil
}

func upsertSetting(ctx context.Context, transaction *sql.Tx, key, value, now string) error {
	if _, err := transaction.ExecContext(ctx, `
INSERT INTO settings(key, value_json, updated_at) VALUES (?, ?, ?)
ON CONFLICT(key) DO UPDATE SET value_json=excluded.value_json, updated_at=excluded.updated_at`, key, value, now); err != nil {
		return fmt.Errorf("save traffic checkpoint %s: %w", key, err)
	}
	return nil
}

func boolUint(value bool) uint64 {
	if value {
		return 1
	}
	return 0
}

func validBootID(value string) bool {
	if len(value) != 36 || value[8] != '-' || value[13] != '-' || value[18] != '-' || value[23] != '-' {
		return false
	}
	for index, char := range value {
		if index == 8 || index == 13 || index == 18 || index == 23 {
			continue
		}
		if !((char >= '0' && char <= '9') || (char >= 'a' && char <= 'f')) {
			return false
		}
	}
	return true
}

func validSessionID(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, char := range value {
		if !((char >= '0' && char <= '9') || (char >= 'a' && char <= 'f')) {
			return false
		}
	}
	return true
}
