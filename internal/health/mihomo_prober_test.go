package health

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"gateway-vpn/internal/mihomo"
)

type bodyProbeSelector struct {
	selections [][2]string
}

func (selector *bodyProbeSelector) Select(_ context.Context, group, target string) error {
	selector.selections = append(selector.selections, [2]string{group, target})
	return nil
}

type bodyProbeDoer func(*http.Request) (*http.Response, error)

func (doer bodyProbeDoer) Do(request *http.Request) (*http.Response, error) { return doer(request) }

func TestMihomoProberUsesPathScopedProviderNode(t *testing.T) {
	var requestPath string
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requestPath = request.URL.RequestURI()
		json.NewEncoder(writer).Encode(mihomo.DelayResult{Delay: 77})
	}))
	server.Listener = listener
	server.Start()
	defer server.Close()
	client, err := mihomo.NewClient(server.URL, "secret", server.Client())
	if err != nil {
		t.Fatal(err)
	}
	prober := MihomoProber{Client: client, TransportURL: "https://transport.example/check", TransportTimeout: 3 * time.Second}
	result := prober.ProbeTransport(context.Background(), Path{ProviderName: "provider-a"}, Candidate{ProviderNodeName: "prefix/node-a"})
	if result.State != ProbePassed || result.LatencyMS != 77 {
		t.Fatalf("ProbeTransport() = %+v", result)
	}
	if requestPath != "/providers/proxies/provider-a/prefix%2Fnode-a/healthcheck?timeout=3000&url=https%3A%2F%2Ftransport.example%2Fcheck" {
		t.Fatalf("request path = %q", requestPath)
	}
}

func TestBodyProbeSelectsIsolatedPathAndChecksStatusBodyAndLimit(t *testing.T) {
	selector := &bodyProbeSelector{}
	gate := make(chan struct{}, 1)
	gate <- struct{}{}
	body := &BodyProbe{
		selector: selector, gate: gate, maxBodyBytes: 32,
		httpClient: bodyProbeDoer(func(request *http.Request) (*http.Response, error) {
			if request.URL.String() != "https://access.example/check" || !request.Close {
				t.Fatalf("body probe request = %+v", request)
			}
			return &http.Response{StatusCode: 302, Body: io.NopCloser(strings.NewReader("prefix access granted suffix")), Header: make(http.Header)}, nil
		}),
	}
	prober := MihomoProber{Client: &mihomo.Client{}, Body: body}
	path := Path{ProbeGroupName: "probe-path-a"}
	candidate := Candidate{ProviderNodeName: "prefix/node-a"}
	target := Target{URL: "https://access.example/check", Timeout: time.Second, ExpectedStatus: "200/302", ExpectedBodySubstring: "access granted"}
	result := prober.ProbeTarget(context.Background(), path, candidate, target)
	if result.State != ProbePassed || result.HTTPStatus != 302 || len(selector.selections) != 2 || selector.selections[0] != [2]string{"probe-path-a", "prefix/node-a"} || selector.selections[1] != [2]string{mihomo.ProbeGroupName, "probe-path-a"} {
		t.Fatalf("body probe result/selections = %+v / %+v", result, selector.selections)
	}

	body.httpClient = bodyProbeDoer(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(strings.Repeat("x", 33))), Header: make(http.Header)}, nil
	})
	result = prober.ProbeTarget(context.Background(), path, candidate, Target{URL: target.URL, Timeout: time.Second, ExpectedBodySubstring: "x"})
	if result.State != ProbeFailed || result.ErrorCode != "BODY_LIMIT_EXCEEDED" {
		t.Fatalf("oversized body result = %+v", result)
	}

	body.httpClient = bodyProbeDoer(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 403, Body: io.NopCloser(strings.NewReader("denied")), Header: make(http.Header)}, nil
	})
	result = prober.ProbeTarget(context.Background(), path, candidate, Target{URL: target.URL, Timeout: time.Second, ExpectedStatus: "200-299", ExpectedBodySubstring: "denied"})
	if result.ErrorCode != "STATUS_MISMATCH" || result.HTTPStatus != 403 {
		t.Fatalf("status mismatch result = %+v", result)
	}
}

func TestNewBodyProbeRejectsNonLoopbackListener(t *testing.T) {
	if _, err := NewBodyProbe(&bodyProbeSelector{}, "0.0.0.0:17890"); err == nil {
		t.Fatal("NewBodyProbe(non-loopback) error = nil")
	}
}

func TestBodyProbeSerializesControlledSelectorAndRequest(t *testing.T) {
	selector := &bodyProbeSelector{}
	gate := make(chan struct{}, 1)
	gate <- struct{}{}
	var inFlight, maxInFlight int32
	body := &BodyProbe{selector: selector, gate: gate, maxBodyBytes: 32}
	body.httpClient = bodyProbeDoer(func(*http.Request) (*http.Response, error) {
		current := atomic.AddInt32(&inFlight, 1)
		for {
			maximum := atomic.LoadInt32(&maxInFlight)
			if current <= maximum || atomic.CompareAndSwapInt32(&maxInFlight, maximum, current) {
				break
			}
		}
		time.Sleep(15 * time.Millisecond)
		atomic.AddInt32(&inFlight, -1)
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("ok")), Header: make(http.Header)}, nil
	})
	prober := MihomoProber{Client: &mihomo.Client{}, Body: body}
	var wait sync.WaitGroup
	for index := 0; index < 2; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			result := prober.ProbeTarget(context.Background(), Path{ProbeGroupName: "probe-path-a"}, Candidate{ProviderNodeName: "node-a"}, Target{URL: "https://example.com/", Timeout: time.Second, ExpectedBodySubstring: "ok"})
			if result.State != ProbePassed {
				t.Errorf("serialized body probe = %+v", result)
			}
		}()
	}
	wait.Wait()
	if maxInFlight != 1 {
		t.Fatalf("max body probes in flight = %d", maxInFlight)
	}
}
