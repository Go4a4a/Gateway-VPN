package subscription

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"
)

type fixedResolver struct {
	addresses []netip.Addr
	err       error
}

func (resolver fixedResolver) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	return resolver.addresses, resolver.err
}

func TestFetcherRejectsUnsafeURLsAndDNSAnswersWithoutLeakingSecrets(t *testing.T) {
	fetcher, err := NewFetcher(fixedResolver{addresses: []netip.Addr{
		netip.MustParseAddr("93.184.216.34"),
		netip.MustParseAddr("127.0.0.1"),
	}}, []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")})
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{
		"http://example.com/sub",
		"https://user:pass@example.com/sub",
		"https://router.local/sub",
		"https://192.168.8.1/sub",
		"https://203.0.113.1/sub",
	} {
		if _, err := fetcher.Fetch(context.Background(), value, FetchOptions{}); err == nil {
			t.Errorf("Fetch(%q) error = nil", value)
		}
	}
	const secret = "very-secret-token"
	if _, err := fetcher.Fetch(context.Background(), "https://example.com/sub?token="+secret, FetchOptions{}); err == nil || strings.Contains(err.Error(), secret) {
		t.Fatalf("Fetch(rebinding) error = %v", err)
	}
}

func TestFetcherRejectsResolverFailure(t *testing.T) {
	fetcher, err := NewFetcher(fixedResolver{err: errors.New("resolver detail")}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fetcher.Fetch(context.Background(), "https://example.com/sub?token=secret", FetchOptions{}); err == nil || strings.Contains(err.Error(), "secret") || strings.Contains(err.Error(), "resolver detail") {
		t.Fatalf("Fetch() error = %v", err)
	}
}

func TestFetcherConditionalHTTPSAndResponseHeaders(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Header.Get("If-None-Match") == `"old"` && request.Header.Get("If-Modified-Since") == "yesterday" {
			writer.Header().Set("ETag", `"new"`)
			writer.Header().Set("Last-Modified", "today")
			writer.WriteHeader(http.StatusNotModified)
			return
		}
		writer.Header().Set("ETag", `"one"`)
		writer.Header().Set("Last-Modified", "now")
		_, _ = writer.Write([]byte("vless://11111111-1111-1111-1111-111111111111@one.example:443#one"))
	}))
	defer server.Close()

	fetcher := newLoopbackTLSFetcher(t, server)
	result, err := fetcher.Fetch(context.Background(), server.URL+"/sub", FetchOptions{})
	if err != nil || len(result.Payload) == 0 || result.ETag != `"one"` || result.LastModified != "now" {
		t.Fatalf("initial Fetch() = %+v, %v", result, err)
	}
	result, err = fetcher.Fetch(context.Background(), server.URL+"/sub", FetchOptions{ETag: `"old"`, LastModified: "yesterday"})
	if err != nil || !result.NotModified || result.ETag != `"new"` || result.LastModified != "today" {
		t.Fatalf("conditional Fetch() = %+v, %v", result, err)
	}
}

func TestFetcherLimitsBodyAfterGzipDecompression(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Encoding", "gzip")
		compressed := gzip.NewWriter(writer)
		_, _ = compressed.Write(bytes.Repeat([]byte{'x'}, MaxPayloadBytes+1))
		_ = compressed.Close()
	}))
	defer server.Close()

	fetcher := newLoopbackTLSFetcher(t, server)
	if _, err := fetcher.Fetch(context.Background(), server.URL+"/large", FetchOptions{}); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("oversized Fetch() error = %v", err)
	}
}

func TestFetcherAllowsExactlyConfiguredRedirectCount(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		remaining, _ := strconv.Atoi(request.URL.Query().Get("remaining"))
		if remaining > 0 {
			http.Redirect(writer, request, "/redirect?remaining="+strconv.Itoa(remaining-1), http.StatusFound)
			return
		}
		_, _ = writer.Write([]byte("ok"))
	}))
	defer server.Close()

	fetcher := newLoopbackTLSFetcher(t, server)
	if result, err := fetcher.Fetch(context.Background(), server.URL+"/redirect?remaining=3", FetchOptions{}); err != nil || string(result.Payload) != "ok" {
		t.Fatalf("three redirects = %+v, %v", result, err)
	}
	if _, err := fetcher.Fetch(context.Background(), server.URL+"/redirect?remaining=4", FetchOptions{}); err == nil || !strings.Contains(err.Error(), "HTTPS request failed") {
		t.Fatalf("four redirects error = %v", err)
	}
}

func newLoopbackTLSFetcher(t *testing.T, server *httptest.Server) *Fetcher {
	t.Helper()
	transport, ok := server.Client().Transport.(*http.Transport)
	if !ok || transport.TLSClientConfig == nil {
		t.Fatal("test TLS transport is unavailable")
	}
	return &Fetcher{
		resolver:     fixedResolver{addresses: []netip.Addr{netip.MustParseAddr("127.0.0.1")}},
		timeout:      5 * time.Second,
		maxRedirects: 3,
		ipPolicy: func(address netip.Addr) error {
			if !address.IsLoopback() {
				return errors.New("test endpoint is not loopback")
			}
			return nil
		},
		tlsConfig: transport.TLSClientConfig.Clone(),
	}
}
