//go:build linux

package main

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"gateway-vpn/internal/diagnostics"
	endurancepkg "gateway-vpn/internal/endurance"
)

func TestRunEndToEndLinuxSmoke(t *testing.T) {
	now := time.Now().UTC()
	diagnostic := cliDiagnosticFixture(t, now)
	diagnosticDigest := sha256.Sum256(diagnostic)
	var mu sync.Mutex
	sampleNumber := 0
	handler := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/api/v1/auth/login":
			var input map[string]string
			if json.NewDecoder(request.Body).Decode(&input) != nil || input["username"] != "admin" || input["password"] != "correct horse battery staple" {
				http.Error(writer, "invalid", http.StatusUnauthorized)
				return
			}
			http.SetCookie(writer, &http.Cookie{Name: "gateway_vpn_session", Value: "opaque", Path: "/", Secure: true, HttpOnly: true})
			writer.Header().Set("Content-Type", "application/json")
			json.NewEncoder(writer).Encode(map[string]any{
				"user_id": "user-a", "user": "admin", "session_id": strings.Repeat("a", 64), "csrf_token": strings.Repeat("c", 64),
				"must_change_password": false, "expires_at": time.Now().UTC().Add(12 * time.Hour).Format(time.RFC3339Nano),
			})
		case "/api/v1/system/runtime-metrics":
			if _, err := request.Cookie("gateway_vpn_session"); err != nil {
				http.Error(writer, "auth", http.StatusUnauthorized)
				return
			}
			mu.Lock()
			index := sampleNumber
			sampleNumber++
			mu.Unlock()
			rss, descriptors := uint64(64<<20), uint64(12)
			writer.Header().Set("Content-Type", "application/json")
			json.NewEncoder(writer).Encode(endurancepkg.Sample{
				SchemaVersion: 1, CollectedAt: now.Add(time.Duration(index) * 20 * time.Millisecond).Format(time.RFC3339Nano), UptimeSeconds: 3600, Goroutines: 20,
				HeapAllocBytes: 16 << 20, HeapInuseBytes: 20 << 20, StackInuseBytes: 1 << 20, GoRuntimeSysBytes: 32 << 20,
				MallocsTotal: 1000 + uint64(index), FreesTotal: 900 + uint64(index), LiveHeapObjects: 100,
				GCCyclesTotal: 10, GCPauseTotalNanoseconds: 1000, ProcessRSSBytes: &rss, OpenFileDescriptors: &descriptors,
			})
		case "/api/v1/system/diagnostics":
			if request.Header.Get("X-CSRF-Token") != strings.Repeat("c", 64) {
				http.Error(writer, "csrf", http.StatusForbidden)
				return
			}
			writer.Header().Set("Content-Type", "application/zip")
			writer.Header().Set("X-Diagnostic-Complete", "true")
			writer.Header().Set("X-Content-SHA256", hex.EncodeToString(diagnosticDigest[:]))
			writer.Write(diagnostic)
		case "/api/v1/auth/logout":
			writer.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(writer, request)
		}
	})
	server := httptest.NewUnstartedServer(handler)
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13}
	server.StartTLS()
	defer server.Close()
	root := t.TempDir()
	caPath := filepath.Join(root, "gateway-ca.pem")
	if err := os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	passwordPath := filepath.Join(root, "password")
	if err := os.WriteFile(passwordPath, []byte("correct horse battery staple\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	outputParent := filepath.Join(root, "results")
	if err := os.Mkdir(outputParent, 0o700); err != nil {
		t.Fatal(err)
	}
	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()
	os.Args = []string{
		"gateway-vpn-endurance", "--profile", "smoke", "--environment", "developer-linux",
		"--smoke-duration", "200ms", "--smoke-interval", "20ms", "--endpoint", server.URL,
		"--ca-cert", caPath, "--username", "admin", "--password-file", passwordPath, "--output-parent", outputParent,
	}
	if code := run(); code != 0 {
		t.Fatalf("run() exit = %d", code)
	}
	entries, err := os.ReadDir(outputParent)
	if err != nil || len(entries) != 1 {
		t.Fatalf("result directories = %v, %v", entries, err)
	}
	reportContent, err := os.ReadFile(filepath.Join(outputParent, entries[0].Name(), "report.json"))
	if err != nil || !strings.Contains(string(reportContent), `"status": "SMOKE_PASS"`) || !strings.Contains(string(reportContent), `"endurance_gate": false`) {
		t.Fatalf("smoke report = %s, %v", reportContent, err)
	}
}

func cliDiagnosticFixture(t *testing.T, now time.Time) []byte {
	t.Helper()
	retention := endurancepkg.RetentionSnapshot{
		SchemaVersion: 1, CollectedAt: now.Format(time.RFC3339Nano),
		Policy:        endurancepkg.RetentionPolicySnapshot{HealthDays: 7, EventDays: 30, TrafficMonths: 24, PreviousSuccessfulVersions: 2, FailedVersions: 2, RowBatch: 500, VersionBatch: 20},
		HealthSamples: endurancepkg.RetentionTemporalStats{}, Events: endurancepkg.RetentionTemporalStats{}, TrafficDailyTotals: endurancepkg.RetentionTemporalStats{},
		SubscriptionVersions: endurancepkg.RetentionVersionStats{},
		Storage:              endurancepkg.RetentionStorageStats{Available: true, DatabaseBytes: 16 * 4096, WALBytes: 4096, PageSizeBytes: 4096, PageCount: 16, FreelistPageCount: 2, AllocatedPageBytes: 16 * 4096, LivePageBytes: 14 * 4096},
	}
	integrityContent, _ := json.Marshal(endurancepkg.DiagnosticIntegrity{QuickCheck: "PASS", IntegrityCheck: "PASS", SchemaVersion: 11})
	retentionContent, _ := json.Marshal(retention)
	files := map[string][]byte{"database/integrity.json": integrityContent, "database/retention.json": retentionContent, "meta.json": []byte(`{"schema_version":1}`)}
	manifest := diagnostics.Manifest{
		SchemaVersion: 1, GeneratedAt: now.Format(time.RFC3339Nano), GatewayVersion: "gateway-vpn 0.0.0-dev (commit=unknown, built=unknown, mihomo=unknown)", Complete: true,
		SecretsIncluded: false, RedactionPolicy: "gateway-vpn-v1-double-pass", Files: []diagnostics.ManifestFile{}, SectionErrors: []diagnostics.SectionError{}, SectionWarnings: []diagnostics.SectionError{},
	}
	for _, name := range []string{"database/integrity.json", "database/retention.json", "meta.json"} {
		payload := files[name]
		digest := sha256.Sum256(payload)
		manifest.Files = append(manifest.Files, diagnostics.ManifestFile{Path: name, ContentType: "application/json", Bytes: int64(len(payload)), SHA256: hex.EncodeToString(digest[:])})
		manifest.PayloadUncompressedSize += int64(len(payload))
	}
	manifestContent, _ := json.Marshal(manifest)
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
