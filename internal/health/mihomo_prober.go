package health

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"gateway-vpn/internal/bypass"
	"gateway-vpn/internal/mihomo"
)

const MaxProbeBodyBytes int64 = 64 << 10

type proxySelector interface {
	Select(context.Context, string, string) error
}

type httpDoer interface {
	Do(*http.Request) (*http.Response, error)
}

// BodyProbe uses a dedicated loopback-only Mihomo mixed listener. Both
// selector changes and the HTTP request are serialized so an observation can
// only belong to the exact path/node that was selected immediately before it.
type BodyProbe struct {
	selector     proxySelector
	httpClient   httpDoer
	gate         chan struct{}
	maxBodyBytes int64
}

type MihomoProber struct {
	Client            *mihomo.Client
	TransportURL      string
	TransportTimeout  time.Duration
	TransportExpected string
	Body              *BodyProbe
}

func NewBodyProbe(selector proxySelector, listenerAddress string) (*BodyProbe, error) {
	address, err := netip.ParseAddrPort(listenerAddress)
	if err != nil || !address.Addr().IsLoopback() || address.Port() == 0 {
		return nil, errors.New("body probe listener must be a numeric loopback address with a port")
	}
	if selector == nil {
		return nil, errors.New("body probe Mihomo selector is required")
	}
	proxyURL, err := url.Parse("http://" + listenerAddress)
	if err != nil {
		return nil, errors.New("body probe proxy URL is invalid")
	}
	dialer := &net.Dialer{Timeout: 5 * time.Second, KeepAlive: -1}
	transport := &http.Transport{
		Proxy:                 http.ProxyURL(proxyURL),
		DialContext:           dialer.DialContext,
		DisableKeepAlives:     true,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 60 * time.Second,
		ForceAttemptHTTP2:     true,
	}
	client := &http.Client{Transport: transport, CheckRedirect: safeProbeRedirect}
	gate := make(chan struct{}, 1)
	gate <- struct{}{}
	return &BodyProbe{selector: selector, httpClient: client, gate: gate, maxBodyBytes: MaxProbeBodyBytes}, nil
}

func (prober MihomoProber) ProbeTransport(ctx context.Context, path Path, candidate Candidate) ProbeResult {
	if prober.Client == nil || prober.TransportURL == "" || prober.TransportTimeout <= 0 {
		return ProbeResult{State: ProbeFailed, ErrorCode: "PROBER_NOT_CONFIGURED"}
	}
	return prober.probe(ctx, path, candidate, prober.TransportURL, prober.TransportTimeout, prober.TransportExpected)
}

func (prober MihomoProber) ProbeTarget(ctx context.Context, path Path, candidate Candidate, target Target) ProbeResult {
	if prober.Client == nil {
		return ProbeResult{State: ProbeFailed, ErrorCode: "PROBER_NOT_CONFIGURED"}
	}
	if target.ExpectedBodySubstring != "" {
		if prober.Body == nil {
			return ProbeResult{State: ProbeFailed, ErrorCode: "BODY_PROBER_NOT_CONFIGURED"}
		}
		return prober.Body.probe(ctx, path, candidate, target)
	}
	return prober.probe(ctx, path, candidate, target.URL, target.Timeout, target.ExpectedStatus)
}

func (prober *BodyProbe) probe(ctx context.Context, path Path, candidate Candidate, target Target) ProbeResult {
	if prober == nil || prober.selector == nil || prober.httpClient == nil || prober.gate == nil || prober.maxBodyBytes <= 0 || path.ProbeGroupName == "" || candidate.ProviderNodeName == "" {
		return ProbeResult{State: ProbeFailed, ErrorCode: "BODY_PROBER_NOT_CONFIGURED"}
	}
	probeCtx, cancel := context.WithTimeout(ctx, target.Timeout)
	defer cancel()
	select {
	case <-prober.gate:
		defer func() { prober.gate <- struct{}{} }()
	case <-probeCtx.Done():
		return ProbeResult{State: ProbeFailed, ErrorCode: classifyProbeError(probeCtx.Err())}
	}
	started := time.Now()
	if err := prober.selector.Select(probeCtx, path.ProbeGroupName, candidate.ProviderNodeName); err != nil {
		return ProbeResult{State: ProbeFailed, ErrorCode: "PROBE_NODE_SELECT_FAILED"}
	}
	if err := prober.selector.Select(probeCtx, mihomo.ProbeGroupName, path.ProbeGroupName); err != nil {
		return ProbeResult{State: ProbeFailed, ErrorCode: "PROBE_PATH_SELECT_FAILED"}
	}
	request, err := http.NewRequestWithContext(probeCtx, http.MethodGet, target.URL, nil)
	if err != nil {
		return ProbeResult{State: ProbeFailed, ErrorCode: "INVALID_TARGET_URL"}
	}
	request.Close = true
	request.Header.Set("Accept", "text/html,application/json,text/plain,*/*")
	request.Header.Set("User-Agent", "Gateway-VPN-Probe/1")
	response, err := prober.httpClient.Do(request)
	if err != nil {
		return ProbeResult{State: ProbeFailed, ErrorCode: classifyBodyProbeError(err)}
	}
	defer response.Body.Close()
	latency := time.Since(started).Milliseconds()
	if target.ExpectedStatus != "" && !bypass.StatusMatches(target.ExpectedStatus, response.StatusCode) {
		return ProbeResult{State: ProbeFailed, LatencyMS: latency, HTTPStatus: response.StatusCode, ErrorCode: "STATUS_MISMATCH"}
	}
	payload, err := io.ReadAll(io.LimitReader(response.Body, prober.maxBodyBytes+1))
	if err != nil {
		return ProbeResult{State: ProbeFailed, LatencyMS: latency, HTTPStatus: response.StatusCode, ErrorCode: "BODY_READ_FAILED"}
	}
	if int64(len(payload)) > prober.maxBodyBytes {
		return ProbeResult{State: ProbeFailed, LatencyMS: latency, HTTPStatus: response.StatusCode, ErrorCode: "BODY_LIMIT_EXCEEDED"}
	}
	if !bytes.Contains(payload, []byte(target.ExpectedBodySubstring)) {
		return ProbeResult{State: ProbeFailed, LatencyMS: latency, HTTPStatus: response.StatusCode, ErrorCode: "BODY_MISMATCH"}
	}
	return ProbeResult{State: ProbePassed, LatencyMS: latency, HTTPStatus: response.StatusCode}
}

func (prober MihomoProber) probe(ctx context.Context, path Path, candidate Candidate, targetURL string, timeout time.Duration, expectedStatus string) ProbeResult {
	delay, err := prober.Client.ProviderNodeDelay(ctx, path.ProviderName, candidate.ProviderNodeName, targetURL, timeout, expectedStatus)
	if err != nil {
		return ProbeResult{State: ProbeFailed, ErrorCode: classifyProbeError(err)}
	}
	return ProbeResult{State: ProbePassed, LatencyMS: int64(delay)}
}

func classifyProbeError(err error) string {
	if err == nil {
		return ""
	}
	switch {
	case errors.Is(err, context.Canceled):
		return "CANCELLED"
	case errors.Is(err, context.DeadlineExceeded):
		return "TIMEOUT"
	}
	message := strings.ToLower(err.Error())
	switch {
	case strings.Contains(message, "timeout"), strings.Contains(message, "deadline"):
		return "TIMEOUT"
	case strings.Contains(message, "connection refused"):
		return "MIHOMO_API_UNAVAILABLE"
	case strings.Contains(message, "http"):
		return "HTTP_FAILURE"
	default:
		return "PROBE_FAILED"
	}
}

func classifyBodyProbeError(err error) string {
	if err == nil {
		return ""
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return classifyProbeError(err)
	}
	message := strings.ToLower(err.Error())
	switch {
	case strings.Contains(message, "certificate"), strings.Contains(message, "tls"):
		return "TLS_FAILURE"
	case strings.Contains(message, "proxyconnect"), strings.Contains(message, "connection refused"):
		return "PROBE_LISTENER_UNAVAILABLE"
	case strings.Contains(message, "redirect"):
		return "REDIRECT_REJECTED"
	default:
		return classifyProbeError(err)
	}
}

func safeProbeRedirect(request *http.Request, via []*http.Request) error {
	if len(via) >= 3 {
		return errors.New("probe redirect limit exceeded")
	}
	if request.URL == nil {
		return errors.New("probe redirect URL is missing")
	}
	if _, err := bypass.NormalizeTarget(bypass.KindURL, request.URL.String()); err != nil {
		return fmt.Errorf("unsafe probe redirect: %w", err)
	}
	return nil
}
