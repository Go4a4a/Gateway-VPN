package endurance

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"

	"gateway-vpn/internal/diagnostics"
)

func TestInspectDiagnosticVerifiesManifestIntegrityAndRetention(t *testing.T) {
	retention := validRetentionSnapshot()
	content := diagnosticFixture(t, retention, false)
	digest := sha256.Sum256(content)
	snapshot, err := InspectDiagnostic(content, hex.EncodeToString(digest[:]))
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Manifest.GatewayVersion != "gateway-vpn test" || snapshot.Integrity.SchemaVersion != 11 || snapshot.Retention.Storage.LivePageBytes != 14*4096 || snapshot.Bytes != int64(len(content)) {
		t.Fatalf("diagnostic snapshot = %+v", snapshot)
	}
	if _, err := InspectDiagnostic(content, string(make([]byte, 64))); err == nil {
		t.Fatal("wrong diagnostic digest accepted")
	}
	if _, err := InspectDiagnostic(diagnosticFixture(t, retention, true), ""); err == nil {
		t.Fatal("unknown retention field accepted")
	}
}

func TestRetentionPolicyFindingsDetectExpiredRowsAndExcessVersions(t *testing.T) {
	now := time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC)
	retention := validRetentionSnapshot()
	retention.HealthSamples.Oldest = now.AddDate(0, 0, -8).Format(time.RFC3339Nano)
	retention.Events.Oldest = now.AddDate(0, 0, -31).Format(time.RFC3339Nano)
	retention.TrafficDailyTotals.Oldest = now.AddDate(0, -25, 0).Format("2006-01-02")
	retention.SubscriptionVersions.RetainedExcess = 1
	findings := retention.PolicyFindings(now)
	for _, code := range []string{"HEALTH_RETENTION_NOT_CONVERGED", "EVENT_RETENTION_NOT_CONVERGED", "TRAFFIC_RETENTION_NOT_CONVERGED", "VERSION_RETENTION_NOT_CONVERGED"} {
		found := false
		for _, finding := range findings {
			if finding.Code == code {
				found = true
			}
		}
		if !found {
			t.Fatalf("retention findings %v missing %s", findings, code)
		}
	}
	retention = validRetentionSnapshot()
	retention.HealthSamples.Oldest = now.AddDate(0, 0, -7).Format(time.RFC3339Nano)
	retention.Events.Oldest = now.AddDate(0, 0, -30).Format(time.RFC3339Nano)
	retention.TrafficDailyTotals.Oldest = now.AddDate(0, -24, 0).Format("2006-01-02")
	if findings := retention.PolicyFindings(now); len(findings) != 0 {
		t.Fatalf("valid retention reported findings: %v", findings)
	}
}

func validRetentionSnapshot() RetentionSnapshot {
	return RetentionSnapshot{
		SchemaVersion: 1, CollectedAt: "2026-08-26T12:00:00Z",
		Policy:               RetentionPolicySnapshot{HealthDays: 7, EventDays: 30, OperationDays: 30, TrafficMonths: 24, PreviousSuccessfulVersions: 2, FailedVersions: 2, RowBatch: 500, VersionBatch: 20},
		HealthSamples:        RetentionTemporalStats{Rows: 10, Oldest: "2026-08-26T11:00:00Z", MostRecent: "2026-08-26T12:00:00Z"},
		Events:               RetentionTemporalStats{Rows: 10, Oldest: "2026-08-26T11:00:00Z", MostRecent: "2026-08-26T12:00:00Z"},
		TrafficDailyTotals:   RetentionTemporalStats{Rows: 1, Oldest: "2026-08-26", MostRecent: "2026-08-26"},
		SubscriptionVersions: RetentionVersionStats{Total: 4, LKG: 1, Candidate: 1, Retained: 1, Failed: 1, ActiveLKG: 1},
		Storage:              RetentionStorageStats{Available: true, DatabaseBytes: 16 * 4096, WALBytes: 4096, PageSizeBytes: 4096, PageCount: 16, FreelistPageCount: 2, AllocatedPageBytes: 16 * 4096, LivePageBytes: 14 * 4096},
	}
}

func diagnosticFixture(t *testing.T, retention RetentionSnapshot, unknownRetentionField bool) []byte {
	t.Helper()
	integrity, err := json.Marshal(DiagnosticIntegrity{QuickCheck: "PASS", IntegrityCheck: "PASS", SchemaVersion: 11})
	if err != nil {
		t.Fatal(err)
	}
	retentionContent, err := json.Marshal(retention)
	if err != nil {
		t.Fatal(err)
	}
	if unknownRetentionField {
		retentionContent = append(retentionContent[:len(retentionContent)-1], []byte(`,"unknown":true}`)...)
	}
	files := map[string][]byte{
		"database/integrity.json": integrity,
		"database/retention.json": retentionContent,
		"meta.json":               []byte(`{"schema_version":1}`),
	}
	manifest := diagnostics.Manifest{
		SchemaVersion: 1, GeneratedAt: "2026-08-26T12:00:00Z", GatewayVersion: "gateway-vpn test", Complete: true,
		SecretsIncluded: false, RedactionPolicy: "gateway-vpn-v1-double-pass", Files: []diagnostics.ManifestFile{},
		SectionErrors: []diagnostics.SectionError{}, SectionWarnings: []diagnostics.SectionError{},
	}
	for _, name := range []string{"database/integrity.json", "database/retention.json", "meta.json"} {
		payload := files[name]
		digest := sha256.Sum256(payload)
		manifest.Files = append(manifest.Files, diagnostics.ManifestFile{Path: name, ContentType: "application/json", Bytes: int64(len(payload)), SHA256: hex.EncodeToString(digest[:])})
		manifest.PayloadUncompressedSize += int64(len(payload))
	}
	manifestContent, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	var buffer bytes.Buffer
	writer := zip.NewWriter(&buffer)
	write := func(name string, payload []byte) {
		header := &zip.FileHeader{Name: name, Method: zip.Deflate}
		header.SetMode(0o600)
		entry, err := writer.CreateHeader(header)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := entry.Write(payload); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"database/integrity.json", "database/retention.json", "meta.json"} {
		write(name, files[name])
	}
	write("manifest.json", manifestContent)
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}
