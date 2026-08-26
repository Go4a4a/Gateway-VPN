package endurance

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestAPIClientUsesTLSMemorySessionRenewsAndVerifiesDiagnostic(t *testing.T) {
	password := "correct horse battery staple"
	diagnostic := diagnosticFixture(t, validRetentionSnapshot(), false)
	diagnosticDigest := sha256.Sum256(diagnostic)
	var mu sync.Mutex
	logins, logouts := 0, 0
	handler := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/api/v1/auth/login":
			var input struct {
				Username string `json:"username"`
				Password string `json:"password"`
			}
			if json.NewDecoder(request.Body).Decode(&input) != nil || input.Username != "admin" || input.Password != password {
				http.Error(writer, "bad login", http.StatusUnauthorized)
				return
			}
			mu.Lock()
			logins++
			mu.Unlock()
			http.SetCookie(writer, &http.Cookie{Name: "gateway_vpn_session", Value: "opaque-session", Path: "/", Secure: true, HttpOnly: true})
			writer.Header().Set("Content-Type", "application/json")
			json.NewEncoder(writer).Encode(map[string]any{
				"user_id": "user-a", "user": "admin", "session_id": strings.Repeat("a", 64), "csrf_token": strings.Repeat("c", 64),
				"must_change_password": false, "expires_at": time.Now().UTC().Add(12 * time.Hour).Format(time.RFC3339Nano),
			})
		case "/api/v1/system/runtime-metrics":
			if _, err := request.Cookie("gateway_vpn_session"); err != nil {
				http.Error(writer, "missing session", http.StatusUnauthorized)
				return
			}
			rss, descriptors := uint64(64<<20), uint64(12)
			writer.Header().Set("Content-Type", "application/json")
			json.NewEncoder(writer).Encode(Sample{
				SchemaVersion: 1, CollectedAt: time.Now().UTC().Format(time.RFC3339Nano), UptimeSeconds: 3600, Goroutines: 20,
				HeapAllocBytes: 16 << 20, HeapInuseBytes: 20 << 20, StackInuseBytes: 1 << 20, GoRuntimeSysBytes: 32 << 20,
				MallocsTotal: 100, FreesTotal: 90, LiveHeapObjects: 10, GCCyclesTotal: 1, GCPauseTotalNanoseconds: 100,
				ProcessRSSBytes: &rss, OpenFileDescriptors: &descriptors,
			})
		case "/api/v1/system/diagnostics":
			if _, err := request.Cookie("gateway_vpn_session"); err != nil || request.Header.Get("X-CSRF-Token") != strings.Repeat("c", 64) {
				http.Error(writer, "missing auth", http.StatusForbidden)
				return
			}
			writer.Header().Set("Content-Type", "application/zip")
			writer.Header().Set("X-Diagnostic-Complete", "true")
			writer.Header().Set("X-Content-SHA256", hex.EncodeToString(diagnosticDigest[:]))
			writer.Write(diagnostic)
		case "/api/v1/auth/logout":
			if request.Header.Get("X-CSRF-Token") != strings.Repeat("c", 64) {
				http.Error(writer, "missing csrf", http.StatusForbidden)
				return
			}
			mu.Lock()
			logouts++
			mu.Unlock()
			writer.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(writer, request)
		}
	})
	server := httptest.NewUnstartedServer(handler)
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13}
	server.StartTLS()
	defer server.Close()
	certificatePEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	client, err := NewAPIClient(server.URL, certificatePEM, "admin", []byte(password))
	if err != nil {
		t.Fatal(err)
	}
	sample, err := client.Sample(t.Context())
	if err != nil || sample.ProcessRSSBytes == nil || *sample.ProcessRSSBytes == 0 {
		t.Fatalf("Sample() = %+v, %v", sample, err)
	}
	client.expires = client.now().Add(5 * time.Minute)
	if _, err := client.Sample(t.Context()); err != nil {
		t.Fatal(err)
	}
	content, digest, err := client.Diagnostic(t.Context())
	if err != nil || digest != hex.EncodeToString(diagnosticDigest[:]) || len(content) != len(diagnostic) {
		t.Fatalf("Diagnostic() = %d %s %v", len(content), digest, err)
	}
	if _, err := InspectDiagnostic(content, digest); err != nil {
		t.Fatal(err)
	}
	if err := client.Close(t.Context()); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if logins != 2 || logouts != 2 || client.password != nil || client.csrf != "" {
		t.Fatalf("session lifecycle logins=%d logouts=%d password=%v csrf=%q", logins, logouts, client.password, client.csrf)
	}
}

func TestAPIClientRejectsUnsafeEndpointAndInvalidCA(t *testing.T) {
	for _, endpoint := range []string{"http://gateway.local", "https://user:pass@gateway.local", "https://gateway.local/api", "https://gateway.local/?secret=1"} {
		if _, err := NewAPIClient(endpoint, []byte("not a certificate"), "admin", []byte("correct horse battery staple")); err == nil {
			t.Fatalf("unsafe endpoint accepted: %s", endpoint)
		}
	}
}
