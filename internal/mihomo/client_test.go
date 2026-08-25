package mihomo

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestClientUsesBearerAuthAndOfficialEndpoints(t *testing.T) {
	var requests []string
	server := newLoopbackServer(t, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "Bearer secret" {
			t.Errorf("Authorization = %q", request.Header.Get("Authorization"))
		}
		requests = append(requests, request.Method+" "+request.URL.RequestURI())
		switch request.URL.Path {
		case "/version":
			json.NewEncoder(writer).Encode(Version{Meta: true, Version: "test"})
		case "/configs":
			writer.WriteHeader(http.StatusNoContent)
		case "/proxies/path-a":
			if request.Method == http.MethodGet {
				json.NewEncoder(writer).Encode(ProxyState{Name: "path-a", Type: "Selector", Now: "node-a"})
			} else {
				writer.WriteHeader(http.StatusNoContent)
			}
		case "/proxies/gateway-vpn-active/delay":
			json.NewEncoder(writer).Encode(DelayResult{Delay: 77})
		case "/providers/proxies/provider-a/node-a/healthcheck":
			json.NewEncoder(writer).Encode(DelayResult{Delay: 123})
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()
	client, err := NewClient(server.URL, "secret", server.Client())
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	if version, err := client.GetVersion(context.Background()); err != nil || version.Version != "test" {
		t.Fatalf("GetVersion() = %+v, %v", version, err)
	}
	if err := client.Reload(context.Background(), "generation/config.yaml"); err != nil {
		t.Fatalf("Reload() error = %v", err)
	}
	if err := client.Select(context.Background(), "path-a", "node-a"); err != nil {
		t.Fatalf("Select() error = %v", err)
	}
	if selected, err := client.Selected(context.Background(), "path-a"); err != nil || selected.Now != "node-a" {
		t.Fatalf("Selected() = %+v, %v", selected, err)
	}
	if delay, err := client.ProxyDelay(context.Background(), "gateway-vpn-active", "https://example.com/check", 5*time.Second, "200-399"); err != nil || delay != 77 {
		t.Fatalf("ProxyDelay() = %d, %v", delay, err)
	}
	delay, err := client.ProviderNodeDelay(context.Background(), "provider-a", "node-a", "https://example.com/check", 5*time.Second, "200-399")
	if err != nil || delay != 123 {
		t.Fatalf("ProviderNodeDelay() = %d, %v", delay, err)
	}
	want := []string{
		"GET /version",
		"PUT /configs?force=true",
		"PUT /proxies/path-a",
		"GET /proxies/path-a",
		"GET /proxies/gateway-vpn-active/delay?expected=200-399&timeout=5000&url=https%3A%2F%2Fexample.com%2Fcheck",
		"GET /providers/proxies/provider-a/node-a/healthcheck?expected=200-399&timeout=5000&url=https%3A%2F%2Fexample.com%2Fcheck",
	}
	if strings.Join(requests, "\n") != strings.Join(want, "\n") {
		t.Fatalf("requests:\n%s\nwant:\n%s", strings.Join(requests, "\n"), strings.Join(want, "\n"))
	}
}

func TestClientRejectsNonLoopbackAndUnsafeReloadPath(t *testing.T) {
	if _, err := NewClient("http://192.168.1.1:9090", "secret", nil); err == nil {
		t.Fatal("NewClient(non-loopback) error = nil")
	}
	server := newLoopbackServer(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer server.Close()
	client, err := NewClient(server.URL, "secret", server.Client())
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	if err := client.Reload(context.Background(), "../outside.yaml"); err == nil {
		t.Fatal("Reload(traversal) error = nil")
	}
}

func TestClientLimitsResponseBody(t *testing.T) {
	server := newLoopbackServer(t, http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		io.WriteString(writer, strings.Repeat("x", maxAPIResponseBytes+1))
	}))
	defer server.Close()
	client, err := NewClient(server.URL, "secret", server.Client())
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	if _, err := client.GetVersion(context.Background()); err == nil {
		t.Fatal("GetVersion(oversized) error = nil")
	}
}

func newLoopbackServer(t *testing.T, handler http.Handler) *httptest.Server {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen loopback: %v", err)
	}
	server := httptest.NewUnstartedServer(handler)
	server.Listener = listener
	server.Start()
	return server
}
