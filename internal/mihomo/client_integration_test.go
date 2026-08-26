package mihomo

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"testing"
	"time"
)

// This gate is intentionally opt-in: CI/unit runs do not start external
// processes. The release acceptance harness starts the exact pinned Mihomo
// binary with test/fixtures/mihomo/minimal-valid.yaml, then enables this test.
func TestPinnedMihomoAPIContract(t *testing.T) {
	if os.Getenv("GATEWAY_VPN_MIHOMO_API_INTEGRATION") != "1" {
		t.Skip("pinned Mihomo API integration is not enabled")
	}
	client, err := NewClient("http://127.0.0.1:19090", "fixture-secret-not-production", &http.Client{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	version, err := client.GetVersion(ctx)
	if err != nil || !version.Meta || version.Version != "v1.19.30" {
		t.Fatalf("pinned /version = %+v, %v", version, err)
	}
	backend := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = writer.Write(bytes.Repeat([]byte("gateway-vpn-traffic-contract\n"), 4096))
	}))
	defer backend.Close()
	proxyURL, err := url.Parse("http://127.0.0.1:7890")
	if err != nil {
		t.Fatal(err)
	}
	proxyClient := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}, Timeout: 5 * time.Second}
	response, err := proxyClient.Get(backend.URL)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(io.Discard, response.Body); err != nil {
		response.Body.Close()
		t.Fatal(err)
	}
	response.Body.Close()
	connections, err := client.GetConnectionsSummary(ctx)
	if err != nil || connections.Connections == nil {
		t.Fatalf("pinned /connections = %+v, %v", connections, err)
	}
	traffic, err := client.Traffic(ctx)
	if err != nil {
		t.Fatalf("pinned /traffic = %+v, %v", traffic, err)
	}
	if traffic.UploadTotal == 0 || traffic.DownloadTotal == 0 || connections.UploadTotal == 0 || connections.DownloadTotal == 0 {
		t.Fatalf("pinned traffic totals are missing: /traffic=%+v /connections=%+v", traffic, connections)
	}
	if traffic.UploadTotal != connections.UploadTotal || traffic.DownloadTotal != connections.DownloadTotal {
		t.Fatalf("pinned traffic totals disagree: /traffic=%+v /connections=%+v", traffic, connections)
	}
}
