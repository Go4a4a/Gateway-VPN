package endurance

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	pathpkg "path"
	"strings"
	"time"

	"gateway-vpn/internal/diagnostics"
)

const maximumDiagnosticFiles = 256

type DiagnosticIntegrity struct {
	QuickCheck     string `json:"quick_check"`
	IntegrityCheck string `json:"integrity_check"`
	SchemaVersion  int64  `json:"schema_version"`
}

type RetentionTemporalStats struct {
	Rows       int64  `json:"rows"`
	Oldest     string `json:"oldest,omitempty"`
	MostRecent string `json:"most_recent,omitempty"`
}

type RetentionVersionStats struct {
	Total          int64 `json:"total"`
	LKG            int64 `json:"lkg"`
	Candidate      int64 `json:"candidate"`
	Retained       int64 `json:"retained"`
	Failed         int64 `json:"failed"`
	Other          int64 `json:"other"`
	ActiveLKG      int64 `json:"active_lkg"`
	ActiveNonLKG   int64 `json:"active_non_lkg"`
	RetainedExcess int64 `json:"retained_excess"`
	FailedExcess   int64 `json:"failed_excess"`
}

type RetentionStorageStats struct {
	Available          bool  `json:"available"`
	DatabaseBytes      int64 `json:"database_bytes"`
	WALBytes           int64 `json:"wal_bytes"`
	PageSizeBytes      int64 `json:"page_size_bytes"`
	PageCount          int64 `json:"page_count"`
	FreelistPageCount  int64 `json:"freelist_page_count"`
	AllocatedPageBytes int64 `json:"allocated_page_bytes"`
	LivePageBytes      int64 `json:"live_page_bytes"`
}

type RetentionPolicySnapshot struct {
	HealthDays                 int `json:"health_days"`
	EventDays                  int `json:"event_days"`
	TrafficMonths              int `json:"traffic_months"`
	PreviousSuccessfulVersions int `json:"previous_successful_versions"`
	FailedVersions             int `json:"failed_versions"`
	RowBatch                   int `json:"row_batch"`
	VersionBatch               int `json:"version_batch"`
}

type RetentionSnapshot struct {
	SchemaVersion        int                     `json:"schema_version"`
	CollectedAt          string                  `json:"collected_at"`
	Policy               RetentionPolicySnapshot `json:"policy"`
	HealthSamples        RetentionTemporalStats  `json:"health_samples"`
	Events               RetentionTemporalStats  `json:"events"`
	TrafficDailyTotals   RetentionTemporalStats  `json:"traffic_daily_totals"`
	SubscriptionVersions RetentionVersionStats   `json:"subscription_versions"`
	Storage              RetentionStorageStats   `json:"storage"`
}

type DiagnosticSnapshot struct {
	SHA256    string
	Bytes     int64
	Manifest  diagnostics.Manifest
	Integrity DiagnosticIntegrity
	Retention RetentionSnapshot
}

func InspectDiagnostic(content []byte, expectedSHA256 string) (DiagnosticSnapshot, error) {
	if len(content) == 0 || len(content) > diagnostics.MaximumBundleBytes {
		return DiagnosticSnapshot{}, errors.New("diagnostic archive size is invalid")
	}
	digest := sha256.Sum256(content)
	actualSHA256 := hex.EncodeToString(digest[:])
	if expectedSHA256 != "" && !strings.EqualFold(expectedSHA256, actualSHA256) {
		return DiagnosticSnapshot{}, errors.New("diagnostic archive SHA-256 mismatch")
	}
	reader, err := zip.NewReader(bytes.NewReader(content), int64(len(content)))
	if err != nil || len(reader.File) < 3 || len(reader.File) > maximumDiagnosticFiles {
		return DiagnosticSnapshot{}, errors.New("diagnostic ZIP structure is invalid")
	}
	files := make(map[string][]byte, len(reader.File))
	var total int64
	for _, item := range reader.File {
		name := item.Name
		if name == "" || pathpkg.Clean(name) != name || strings.HasPrefix(name, "/") || strings.Contains(name, "\\") || strings.HasPrefix(name, "../") || item.FileInfo().IsDir() || item.Mode().Perm() != 0o600 {
			return DiagnosticSnapshot{}, errors.New("diagnostic ZIP entry is unsafe")
		}
		if _, exists := files[name]; exists {
			return DiagnosticSnapshot{}, errors.New("diagnostic ZIP entry is duplicated")
		}
		if item.UncompressedSize64 > uint64(diagnostics.MaximumBundleUncompressedBytes) {
			return DiagnosticSnapshot{}, errors.New("diagnostic ZIP entry exceeds size bound")
		}
		handle, err := item.Open()
		if err != nil {
			return DiagnosticSnapshot{}, errors.New("open diagnostic ZIP entry failed")
		}
		payload, readErr := io.ReadAll(io.LimitReader(handle, diagnostics.MaximumBundleUncompressedBytes+1))
		closeErr := handle.Close()
		if readErr != nil || closeErr != nil || int64(len(payload)) > diagnostics.MaximumBundleUncompressedBytes {
			return DiagnosticSnapshot{}, errors.New("read diagnostic ZIP entry failed")
		}
		total += int64(len(payload))
		if total > diagnostics.MaximumBundleUncompressedBytes {
			return DiagnosticSnapshot{}, errors.New("diagnostic ZIP exceeds uncompressed size bound")
		}
		files[name] = payload
	}
	var manifest diagnostics.Manifest
	if err := decodeStrictJSON(files["manifest.json"], &manifest); err != nil || manifest.SchemaVersion != diagnostics.BundleSchemaVersion || !manifest.Complete || manifest.SecretsIncluded || manifest.RedactionPolicy != "gateway-vpn-v1-double-pass" || manifest.GatewayVersion == "" || len(manifest.SectionErrors) != 0 {
		return DiagnosticSnapshot{}, errors.New("diagnostic manifest is incomplete or invalid")
	}
	if len(files) != len(manifest.Files)+1 {
		return DiagnosticSnapshot{}, errors.New("diagnostic manifest file set is incomplete")
	}
	seen := make(map[string]struct{}, len(manifest.Files))
	var payloadBytes int64
	for _, item := range manifest.Files {
		payload, exists := files[item.Path]
		if !exists || item.Path == "manifest.json" || item.ContentType == "" || item.Bytes != int64(len(payload)) || len(item.SHA256) != 64 {
			return DiagnosticSnapshot{}, errors.New("diagnostic manifest record is invalid")
		}
		if _, duplicate := seen[item.Path]; duplicate {
			return DiagnosticSnapshot{}, errors.New("diagnostic manifest record is duplicated")
		}
		seen[item.Path] = struct{}{}
		fileDigest := sha256.Sum256(payload)
		if !strings.EqualFold(item.SHA256, hex.EncodeToString(fileDigest[:])) {
			return DiagnosticSnapshot{}, errors.New("diagnostic manifest file digest mismatch")
		}
		payloadBytes += int64(len(payload))
	}
	if payloadBytes != manifest.PayloadUncompressedSize {
		return DiagnosticSnapshot{}, errors.New("diagnostic manifest payload size mismatch")
	}
	var integrity DiagnosticIntegrity
	if err := decodeStrictJSON(files["database/integrity.json"], &integrity); err != nil || integrity.QuickCheck != "PASS" || integrity.IntegrityCheck != "PASS" || integrity.SchemaVersion < 1 {
		return DiagnosticSnapshot{}, errors.New("diagnostic SQLite integrity check failed")
	}
	var retention RetentionSnapshot
	if err := decodeStrictJSON(files["database/retention.json"], &retention); err != nil {
		return DiagnosticSnapshot{}, errors.New("diagnostic retention snapshot is invalid")
	}
	if err := retention.Validate(); err != nil {
		return DiagnosticSnapshot{}, err
	}
	return DiagnosticSnapshot{SHA256: actualSHA256, Bytes: int64(len(content)), Manifest: manifest, Integrity: integrity, Retention: retention}, nil
}

func (snapshot RetentionSnapshot) Validate() error {
	if snapshot.SchemaVersion != 1 || snapshot.Policy.HealthDays != 7 || snapshot.Policy.EventDays != 30 || snapshot.Policy.TrafficMonths != 24 || snapshot.Policy.PreviousSuccessfulVersions != 2 || snapshot.Policy.FailedVersions != 2 || snapshot.Policy.RowBatch != 500 || snapshot.Policy.VersionBatch != 20 {
		return errors.New("diagnostic retention policy is unexpected")
	}
	if _, err := time.Parse(time.RFC3339Nano, snapshot.CollectedAt); err != nil {
		return errors.New("diagnostic retention timestamp is invalid")
	}
	for _, value := range []int64{
		snapshot.HealthSamples.Rows, snapshot.Events.Rows, snapshot.TrafficDailyTotals.Rows,
		snapshot.SubscriptionVersions.Total, snapshot.SubscriptionVersions.LKG, snapshot.SubscriptionVersions.Candidate,
		snapshot.SubscriptionVersions.Retained, snapshot.SubscriptionVersions.Failed, snapshot.SubscriptionVersions.Other,
		snapshot.SubscriptionVersions.ActiveLKG, snapshot.SubscriptionVersions.ActiveNonLKG,
		snapshot.SubscriptionVersions.RetainedExcess, snapshot.SubscriptionVersions.FailedExcess,
		snapshot.Storage.DatabaseBytes, snapshot.Storage.WALBytes, snapshot.Storage.PageSizeBytes, snapshot.Storage.PageCount,
		snapshot.Storage.FreelistPageCount, snapshot.Storage.AllocatedPageBytes, snapshot.Storage.LivePageBytes,
	} {
		if value < 0 {
			return errors.New("diagnostic retention counters are invalid")
		}
	}
	versions := snapshot.SubscriptionVersions
	if versions.Total != versions.LKG+versions.Candidate+versions.Retained+versions.Failed+versions.Other || versions.ActiveLKG+versions.ActiveNonLKG > versions.Total {
		return errors.New("diagnostic subscription version counts are inconsistent")
	}
	storage := snapshot.Storage
	if !storage.Available || storage.PageSizeBytes <= 0 || storage.PageCount <= 0 || storage.FreelistPageCount > storage.PageCount || storage.PageCount > int64(^uint64(0)>>1)/storage.PageSizeBytes || storage.AllocatedPageBytes != storage.PageSizeBytes*storage.PageCount || storage.LivePageBytes != storage.PageSizeBytes*(storage.PageCount-storage.FreelistPageCount) {
		return errors.New("diagnostic database storage counters are unavailable or inconsistent")
	}
	if !validTemporalStats(snapshot.HealthSamples, time.RFC3339Nano) || !validTemporalStats(snapshot.Events, time.RFC3339Nano) || !validTemporalStats(snapshot.TrafficDailyTotals, "2006-01-02") {
		return errors.New("diagnostic retention time ranges are inconsistent")
	}
	return nil
}

func validTemporalStats(stats RetentionTemporalStats, layout string) bool {
	if stats.Rows == 0 {
		return stats.Oldest == "" && stats.MostRecent == ""
	}
	if stats.Oldest == "" || stats.MostRecent == "" {
		return false
	}
	oldest, oldestErr := time.Parse(layout, stats.Oldest)
	mostRecent, recentErr := time.Parse(layout, stats.MostRecent)
	return oldestErr == nil && recentErr == nil && !mostRecent.Before(oldest)
}

func (snapshot RetentionSnapshot) PolicyFindings(at time.Time) []Finding {
	findings := make([]Finding, 0)
	tolerance := 15 * time.Minute
	if olderThan(snapshot.HealthSamples.Oldest, at.UTC().AddDate(0, 0, -7).Add(-tolerance), false) {
		findings = append(findings, Finding{Code: "HEALTH_RETENTION_NOT_CONVERGED", Metric: "health_samples"})
	}
	if olderThan(snapshot.Events.Oldest, at.UTC().AddDate(0, 0, -30).Add(-tolerance), false) {
		findings = append(findings, Finding{Code: "EVENT_RETENTION_NOT_CONVERGED", Metric: "events"})
	}
	if olderThan(snapshot.TrafficDailyTotals.Oldest, at.UTC().AddDate(0, -24, 0), true) {
		findings = append(findings, Finding{Code: "TRAFFIC_RETENTION_NOT_CONVERGED", Metric: "traffic_daily_totals"})
	}
	versions := snapshot.SubscriptionVersions
	if versions.Other != 0 || versions.ActiveNonLKG != 0 || versions.RetainedExcess != 0 || versions.FailedExcess != 0 {
		findings = append(findings, Finding{Code: "VERSION_RETENTION_NOT_CONVERGED", Metric: "subscription_versions", Detail: fmt.Sprintf("other=%d active_non_lkg=%d retained_excess=%d failed_excess=%d", versions.Other, versions.ActiveNonLKG, versions.RetainedExcess, versions.FailedExcess)})
	}
	return findings
}

func olderThan(value string, cutoff time.Time, dateOnly bool) bool {
	if value == "" {
		return false
	}
	layout := time.RFC3339Nano
	if dateOnly {
		layout = "2006-01-02"
		cutoff, _ = time.Parse(layout, cutoff.Format(layout))
	}
	parsed, err := time.Parse(layout, value)
	return err != nil || parsed.Before(cutoff)
}

func decodeStrictJSON(content []byte, destination any) error {
	if len(content) == 0 || int64(len(content)) > diagnostics.MaximumBundleUncompressedBytes {
		return errors.New("bounded JSON document is required")
	}
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("JSON document contains trailing data")
	}
	return nil
}
