// Package directprobe qualifies direct Internet access through one exact
// uplink routing context without consulting the host default route.
package directprobe

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"gateway-vpn/internal/accesspolicy"
	"gateway-vpn/internal/bypass"
	"gateway-vpn/internal/netbind"
	"gateway-vpn/internal/scheduler"
	"gateway-vpn/internal/uplink"
)

const (
	MaximumResponseBodyBytes  int64 = 64 << 10
	defaultEstimatedBytes           = 4 << 10
	defaultBodyEstimatedBytes       = MaximumResponseBodyBytes + defaultEstimatedBytes
)

var ErrDeferredBudget = errors.New("direct probe deferred by mobile traffic budget")

type RouteAuthorizer interface {
	SyncRouting(context.Context) error
	AuthorizeDirectProbe(context.Context, string, string, []string, uint16) error
}

type Resolver interface {
	LookupNetIP(context.Context, string, string) ([]netip.Addr, error)
}

type DialContextFunc func(context.Context, string, string) (net.Conn, error)
type DialerFactory func(string, uint32) (DialContextFunc, error)
type ResolverFactory func(DialContextFunc, string) Resolver

type HTTPDoer interface {
	Do(*http.Request) (*http.Response, error)
}

type HTTPClientFactory func(DialContextFunc, string, string, []netip.Addr, time.Duration) (HTTPDoer, func(), error)

type Prober struct {
	Uplinks         *uplink.Repository
	Paths           *accesspolicy.DirectPathRepository
	Targets         *bypass.Repository
	Broker          RouteAuthorizer
	Scheduler       *scheduler.Scheduler
	BootstrapDNS    []string
	EvidenceTTL     time.Duration
	DialerFactory   DialerFactory
	ResolverFactory ResolverFactory
	ClientFactory   HTTPClientFactory
	now             func() time.Time
}

func New(uplinks *uplink.Repository, paths *accesspolicy.DirectPathRepository, targets *bypass.Repository, broker RouteAuthorizer, probeScheduler *scheduler.Scheduler, bootstrapDNS []string) (*Prober, error) {
	prober := &Prober{
		Uplinks: uplinks, Paths: paths, Targets: targets, Broker: broker,
		Scheduler: probeScheduler, BootstrapDNS: append([]string(nil), bootstrapDNS...),
		EvidenceTTL: 5 * time.Minute, DialerFactory: defaultDialer,
		ResolverFactory: defaultResolver, ClientFactory: defaultHTTPClient,
		now: time.Now,
	}
	if err := prober.validate(); err != nil {
		return nil, err
	}
	return prober, nil
}

func (prober *Prober) ProbePath(ctx context.Context, pathID, class string) (accesspolicy.DirectResultUpdate, error) {
	if err := prober.validate(); err != nil {
		return accesspolicy.DirectResultUpdate{}, err
	}
	if class == "" {
		class = scheduler.ClassStandby
	}
	path, err := prober.Paths.Get(ctx, pathID)
	if err != nil {
		return accesspolicy.DirectResultUpdate{}, err
	}
	if err := prober.Broker.SyncRouting(ctx); err != nil {
		return accesspolicy.DirectResultUpdate{}, errors.New("direct probe routing synchronization failed")
	}
	currentUplink, err := prober.Uplinks.Get(ctx, path.UplinkID)
	if err != nil || !currentUplink.Enabled || currentUplink.State != "UPLINK_READY" ||
		currentUplink.CurrentIfname == "" || currentUplink.Fwmark <= 0 || currentUplink.Fwmark > 1<<32-1 || currentUplink.RouteGeneration != path.RouteGeneration {
		return accesspolicy.DirectResultUpdate{}, errors.New("direct probe uplink context is unavailable or stale")
	}
	dial, err := prober.DialerFactory(currentUplink.CurrentIfname, uint32(currentUplink.Fwmark))
	if err != nil {
		return accesspolicy.DirectResultUpdate{}, errors.New("direct probe socket binding is unavailable")
	}
	storedTargets, err := prober.Targets.List(ctx)
	if err != nil {
		return accesspolicy.DirectResultUpdate{}, errors.New("read direct probe target policy failed")
	}
	enabledTargets := make([]bypass.Target, 0, len(storedTargets))
	for _, target := range storedTargets {
		if target.Enabled && target.TargetClass != bypass.TargetClassServiceEndpoint {
			enabledTargets = append(enabledTargets, target)
		}
	}
	checkedAt := prober.now().UTC()
	expiresAt := checkedAt.Add(prober.EvidenceTTL)
	update := accesspolicy.DirectResultUpdate{
		PathID: path.ID, ExpectedPolicyGeneration: path.PolicyGeneration,
		ExpectedRouteGeneration: path.RouteGeneration, TransportState: "FAILED",
		QualityClass: accesspolicy.QualityFailed, CheckedAt: checkedAt, ExpiresAt: expiresAt,
	}
	if len(enabledTargets) == 0 {
		update.FailureCode = "NO_ACTIVE_TARGETS"
		if err := ctx.Err(); err != nil {
			return accesspolicy.DirectResultUpdate{}, err
		}
		if err := prober.Paths.Publish(ctx, update); err != nil {
			return accesspolicy.DirectResultUpdate{}, err
		}
		return update, nil
	}

	var responseLatencyTotal int64
	var responses int64
	for _, target := range enabledTargets {
		switch target.TargetClass {
		case bypass.TargetClassGlobalRequired:
			update.RequiredTargetsTotal++
		case bypass.TargetClassGlobalOptional:
			update.OptionalTargetsTotal++
		case bypass.TargetClassWhitelistIndicator:
			update.WhitelistTargetsTotal++
		default:
			return accesspolicy.DirectResultUpdate{}, errors.New("direct probe target class is invalid")
		}
		estimatedBytes := int64(defaultEstimatedBytes)
		if target.ExpectedBodySubstring != "" {
			estimatedBytes = defaultBodyEstimatedBytes
		}
		admission, err := prober.Scheduler.Acquire(ctx, scheduler.Request{
			ModemID: currentUplink.ID, TargetID: target.ID, Class: class, EstimatedBytes: estimatedBytes,
		})
		if err != nil {
			return accesspolicy.DirectResultUpdate{}, err
		}
		if admission.Decision == scheduler.DecisionDeferredBudget || admission.Permit == nil {
			return accesspolicy.DirectResultUpdate{}, ErrDeferredBudget
		}
		result, reachedHTTP, probeErr := prober.probeTarget(ctx, currentUplink, target, dial, checkedAt, expiresAt)
		admission.Permit.Release(estimatedBytes)
		if err := ctx.Err(); err != nil {
			return accesspolicy.DirectResultUpdate{}, err
		}
		if probeErr != nil {
			result = accesspolicy.DirectTargetResult{TargetID: target.ID, TargetClass: target.TargetClass, State: "FAILED", ErrorCode: classifyError(probeErr), CheckedAt: checkedAt, ExpiresAt: expiresAt}
		}
		update.Targets = append(update.Targets, result)
		if reachedHTTP {
			update.TransportState = "PASSED"
			responseLatencyTotal += result.LatencyMS
			responses++
		}
		if result.State == "PASSED" {
			switch target.TargetClass {
			case bypass.TargetClassGlobalRequired:
				update.RequiredTargetsPassed++
			case bypass.TargetClassGlobalOptional:
				update.OptionalTargetsPassed++
			case bypass.TargetClassWhitelistIndicator:
				update.WhitelistTargetsPassed++
			}
		}
	}
	if responses > 0 {
		update.LatencyMS = responseLatencyTotal / responses
	}
	globalScore := update.RequiredTargetsPassed*1000 + update.OptionalTargetsPassed
	update.FunctionalScore = globalScore
	if globalScore == 0 {
		update.FunctionalScore = update.WhitelistTargetsPassed
	}
	switch {
	case update.RequiredTargetsTotal > 0 && update.RequiredTargetsPassed == update.RequiredTargetsTotal:
		update.QualityClass = accesspolicy.QualityFull
		update.FailureCode = ""
	case globalScore > 0:
		update.QualityClass = accesspolicy.QualityLimited
		update.FailureCode = "PARTIAL_TARGET_ACCESS"
	case update.WhitelistTargetsPassed > 0:
		update.QualityClass = accesspolicy.QualityWhitelistOnly
		update.FailureCode = "WHITELIST_ONLY_ACCESS"
	default:
		update.QualityClass = accesspolicy.QualityFailed
		update.FailureCode = "ALL_TARGETS_FAILED"
	}
	if err := ctx.Err(); err != nil {
		return accesspolicy.DirectResultUpdate{}, err
	}
	if err := prober.Paths.Publish(ctx, update); err != nil {
		return accesspolicy.DirectResultUpdate{}, err
	}
	return update, nil
}

func (prober *Prober) probeTarget(ctx context.Context, currentUplink uplink.Uplink, target bypass.Target, dial DialContextFunc, checkedAt, expiresAt time.Time) (accesspolicy.DirectTargetResult, bool, error) {
	parsed, err := url.Parse(target.NormalizedURL)
	if err != nil || parsed.Scheme != "https" || parsed.Hostname() == "" {
		return accesspolicy.DirectTargetResult{}, false, errors.New("stored target URL is invalid")
	}
	timeout := time.Duration(target.TimeoutSeconds) * time.Second
	probeContext, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	port := parsed.Port()
	if port == "" {
		port = "443"
	}
	portNumber, err := strconv.ParseUint(port, 10, 16)
	if err != nil || portNumber == 0 {
		return accesspolicy.DirectTargetResult{}, false, errors.New("stored target port is invalid")
	}
	addresses, err := prober.resolveIPv4(probeContext, dial, parsed.Hostname())
	if err != nil {
		return accesspolicy.DirectTargetResult{}, false, err
	}
	addressStrings := make([]string, 0, len(addresses))
	for _, address := range addresses {
		addressStrings = append(addressStrings, address.String())
	}
	if err := prober.Broker.AuthorizeDirectProbe(probeContext, currentUplink.ID, target.ID, addressStrings, uint16(portNumber)); err != nil {
		return accesspolicy.DirectTargetResult{}, false, errors.New("direct probe firewall authorization failed")
	}
	client, cleanup, err := prober.ClientFactory(dial, parsed.Hostname(), port, addresses, timeout)
	if err != nil {
		return accesspolicy.DirectTargetResult{}, false, errors.New("direct probe HTTPS client creation failed")
	}
	defer cleanup()
	request, err := http.NewRequestWithContext(probeContext, http.MethodGet, parsed.String(), nil)
	if err != nil {
		return accesspolicy.DirectTargetResult{}, false, errors.New("direct probe request creation failed")
	}
	request.Header.Set("Accept", "text/plain,text/html,application/json,*/*;q=0.1")
	request.Header.Set("User-Agent", "Gateway-VPN-Direct-Probe/1")
	started := prober.now()
	response, err := client.Do(request)
	if err != nil {
		return accesspolicy.DirectTargetResult{}, false, err
	}
	defer response.Body.Close()
	latency := prober.now().Sub(started).Milliseconds()
	if latency < 0 {
		latency = 0
	}
	result := accesspolicy.DirectTargetResult{TargetID: target.ID, TargetClass: target.TargetClass, State: "FAILED", LatencyMS: latency, HTTPStatus: response.StatusCode, CheckedAt: checkedAt, ExpiresAt: expiresAt}
	switch target.SuccessMode {
	case bypass.SuccessAnyHTTPResponse:
		result.State = "PASSED"
	case bypass.SuccessExpectedStatus:
		if bypass.StatusMatches(target.ExpectedStatus, response.StatusCode) {
			result.State = "PASSED"
		} else {
			result.ErrorCode = "STATUS_MISMATCH"
		}
	case bypass.SuccessExpectedBody:
		if target.ExpectedStatus != "" && !bypass.StatusMatches(target.ExpectedStatus, response.StatusCode) {
			result.ErrorCode = "STATUS_MISMATCH"
			break
		}
		content, readErr := io.ReadAll(io.LimitReader(response.Body, MaximumResponseBodyBytes+1))
		if readErr != nil {
			result.ErrorCode = "BODY_READ_FAILED"
		} else if int64(len(content)) > MaximumResponseBodyBytes {
			result.ErrorCode = "BODY_LIMIT_EXCEEDED"
		} else if !bytes.Contains(content, []byte(target.ExpectedBodySubstring)) {
			result.ErrorCode = "BODY_MISMATCH"
		} else {
			result.State = "PASSED"
		}
	default:
		return accesspolicy.DirectTargetResult{}, true, errors.New("stored target success policy is invalid")
	}
	return result, true, nil
}

func (prober *Prober) resolveIPv4(ctx context.Context, dial DialContextFunc, host string) ([]netip.Addr, error) {
	if address, err := netip.ParseAddr(host); err == nil {
		address = address.Unmap()
		if !publicIPv4(address) {
			return nil, errors.New("direct probe target IP is not public IPv4")
		}
		return []netip.Addr{address}, nil
	}
	for _, dns := range prober.BootstrapDNS {
		resolver := prober.ResolverFactory(dial, dns)
		if resolver == nil {
			continue
		}
		addresses, err := resolver.LookupNetIP(ctx, "ip4", host)
		if err != nil || len(addresses) == 0 || len(addresses) > 16 {
			continue
		}
		seen := make(map[netip.Addr]struct{}, len(addresses))
		result := make([]netip.Addr, 0, len(addresses))
		valid := true
		for _, address := range addresses {
			address = address.Unmap()
			if !publicIPv4(address) {
				valid = false
				break
			}
			if _, exists := seen[address]; exists {
				continue
			}
			seen[address] = struct{}{}
			result = append(result, address)
		}
		if valid && len(result) != 0 {
			return result, nil
		}
	}
	return nil, errors.New("uplink-bound direct probe DNS failed")
}

func (prober *Prober) validate() error {
	if prober == nil || prober.Uplinks == nil || prober.Paths == nil || prober.Targets == nil || prober.Broker == nil || prober.Scheduler == nil || prober.DialerFactory == nil || prober.ResolverFactory == nil || prober.ClientFactory == nil || prober.now == nil || prober.EvidenceTTL < time.Minute || prober.EvidenceTTL > time.Hour || len(prober.BootstrapDNS) == 0 || len(prober.BootstrapDNS) > 8 {
		return errors.New("direct prober dependencies or evidence policy are invalid")
	}
	for _, raw := range prober.BootstrapDNS {
		address, err := netip.ParseAddr(raw)
		if err != nil || !address.Is4() || address.IsUnspecified() || address.IsMulticast() {
			return errors.New("direct prober requires usable IPv4 bootstrap DNS")
		}
	}
	return nil
}

func defaultDialer(interfaceName string, fwmark uint32) (DialContextFunc, error) {
	configuration := netbind.Config{InterfaceName: interfaceName, Fwmark: fwmark}
	if err := configuration.Validate(); err != nil {
		return nil, err
	}
	dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 15 * time.Second, Control: netbind.SocketControl(configuration)}
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		if network == "tcp" {
			network = "tcp4"
		} else if network == "udp" {
			network = "udp4"
		}
		return dialer.DialContext(ctx, network, address)
	}, nil
}

func defaultResolver(dial DialContextFunc, dns string) Resolver {
	return &net.Resolver{PreferGo: true, StrictErrors: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		if strings.HasPrefix(network, "tcp") {
			network = "tcp4"
		} else {
			network = "udp4"
		}
		return dial(ctx, network, net.JoinHostPort(dns, "53"))
	}}
}

func defaultHTTPClient(dial DialContextFunc, host, port string, addresses []netip.Addr, timeout time.Duration) (HTTPDoer, func(), error) {
	pinned, err := pinnedDialer(dial, host, port, addresses)
	if err != nil {
		return nil, nil, err
	}
	transport := &http.Transport{
		Proxy: nil, DialContext: pinned,
		TLSClientConfig:        &tls.Config{MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout:    minDuration(timeout, 10*time.Second),
		ResponseHeaderTimeout:  timeout,
		MaxResponseHeaderBytes: 32 << 10,
		ForceAttemptHTTP2:      true,
		DisableKeepAlives:      true,
	}
	client := &http.Client{Transport: transport, Timeout: timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return client, transport.CloseIdleConnections, nil
}

func pinnedDialer(dial DialContextFunc, expectedHost, expectedPort string, addresses []netip.Addr) (DialContextFunc, error) {
	if dial == nil || expectedHost == "" || expectedPort == "" || len(addresses) == 0 || len(addresses) > 16 {
		return nil, errors.New("pinned direct probe dialer inputs are invalid")
	}
	validated := make([]netip.Addr, 0, len(addresses))
	for _, address := range addresses {
		address = address.Unmap()
		if !publicIPv4(address) {
			return nil, errors.New("pinned direct probe address is not public IPv4")
		}
		validated = append(validated, address)
	}
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil || !strings.EqualFold(strings.TrimSuffix(host, "."), strings.TrimSuffix(expectedHost, ".")) || port != expectedPort {
			return nil, errors.New("direct probe attempted an unpinned endpoint")
		}
		if network == "tcp" {
			network = "tcp4"
		}
		for _, current := range validated {
			connection, err := dial(ctx, network, net.JoinHostPort(current.String(), expectedPort))
			if err == nil {
				return connection, nil
			}
		}
		return nil, errors.New("direct probe pinned endpoint connection failed")
	}, nil
}

func publicIPv4(address netip.Addr) bool {
	return address.IsValid() && address.Is4() && address.IsGlobalUnicast() && !address.IsPrivate() && !address.IsLoopback() && !address.IsLinkLocalUnicast() && !address.IsMulticast()
}

func classifyError(err error) string {
	if err == nil {
		return ""
	}
	if errors.Is(err, context.Canceled) {
		return "CANCELLED"
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "TIMEOUT"
	}
	message := strings.ToLower(err.Error())
	switch {
	case strings.Contains(message, "dns"):
		return "DNS_FAILED"
	case strings.Contains(message, "authorization"):
		return "FIREWALL_AUTHORIZATION_FAILED"
	case strings.Contains(message, "certificate"), strings.Contains(message, "tls"):
		return "TLS_FAILED"
	case strings.Contains(message, "timeout"), strings.Contains(message, "deadline"):
		return "TIMEOUT"
	default:
		return "HTTPS_FAILED"
	}
}

func minDuration(left, right time.Duration) time.Duration {
	if left < right {
		return left
	}
	return right
}
