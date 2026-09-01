// Package updatenet provides the signed-updater with a service-only route
// ladder. It never changes the active user data path: VPN attempts use the
// isolated Mihomo probe selector and direct attempts use an exact uplink-bound
// socket plus a transient root-owned HTTPS allowlist.
package updatenet

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"gateway-vpn/internal/accesspolicy"
	"gateway-vpn/internal/mihomo"
	"gateway-vpn/internal/netbind"
	"gateway-vpn/internal/subscription"
	"gateway-vpn/internal/subscriptionnet"
	"gateway-vpn/internal/uplink"
)

const (
	maximumVPNAttempts = 128
	maximumDNSAnswers  = 16
	attemptTimeout     = 20 * time.Second
)

var nonPublicIPv4Prefixes = []netip.Prefix{
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"),
}

type selector interface {
	Select(context.Context, string, string) error
}

type serviceBroker interface {
	SyncRouting(context.Context) error
	AuthorizeUpdateService(context.Context, string, []string, uint16) error
}

type Attempt struct {
	RouteKind      string
	UplinkID       string
	SubscriptionID string
	NodeID         string
	ResultCode     string
}

// Ladder is an http.RoundTripper so the existing updater remains the sole
// owner of redirects, media-type checks, size bounds, hashes and signatures.
// Every connection still resolves and validates its destination independently.
type Ladder struct {
	Routes        *subscriptionnet.RouteRepository
	Policy        *accesspolicy.Repository
	Uplinks       *uplink.Repository
	Broker        serviceBroker
	Selector      selector
	ProbeAddress  string
	BootstrapDNS  []string
	OperationLock sync.Locker
	OnAttempt     func(Attempt)
	roundTrip     func(context.Context, *http.Request, subscription.Resolver, subscription.DialContextFunc, subscription.EndpointAuthorizer) (*http.Response, error)
}

func (ladder *Ladder) RoundTrip(request *http.Request) (*http.Response, error) {
	if err := ladder.validate(); err != nil {
		return nil, err
	}
	if err := validateRequest(request); err != nil {
		return nil, err
	}
	routes, routeErr := ladder.Routes.ListServiceVPNRoutes(request.Context())
	if routeErr == nil {
		if len(routes) > maximumVPNAttempts {
			routes = routes[:maximumVPNAttempts]
		}
		for _, route := range routes {
			response, err := ladder.tryVPN(request, route)
			if err == nil && !retryableHTTPStatus(response.StatusCode) {
				return response, nil
			}
			if response != nil && response.Body != nil {
				_ = response.Body.Close()
			}
			if request.Context().Err() != nil {
				return nil, request.Context().Err()
			}
		}
	}
	policy, err := ladder.Policy.GetPolicy(request.Context())
	if err != nil || !policy.DirectServiceRefresh {
		return nil, errors.New("signed update request exhausted every permitted VPN service route")
	}
	if err := ladder.Broker.SyncRouting(request.Context()); err != nil {
		return nil, errors.New("signed update direct service routing is unavailable")
	}
	uplinks, err := ladder.Uplinks.List(request.Context())
	if err != nil {
		return nil, errors.New("signed update uplink inventory is unavailable")
	}
	for _, current := range uplinks {
		if !current.Enabled || current.State != uplink.StateReady {
			continue
		}
		response, attemptErr := ladder.tryDirect(request, current)
		if attemptErr == nil && !retryableHTTPStatus(response.StatusCode) {
			return response, nil
		}
		if response != nil && response.Body != nil {
			_ = response.Body.Close()
		}
		if request.Context().Err() != nil {
			return nil, request.Context().Err()
		}
	}
	return nil, errors.New("signed update request failed through every permitted service route")
}

func (ladder *Ladder) tryVPN(request *http.Request, route subscriptionnet.VPNRoute) (*http.Response, error) {
	ctx, cancel := boundedAttempt(request.Context())
	defer cancel()
	unlock, err := lockContext(ctx, ladder.OperationLock)
	if err != nil {
		return nil, err
	}
	defer unlock()
	// Inventory is advisory. The stable node/uplink identity is authoritative
	// only after the selector lock has been acquired.
	if err := ladder.Routes.ValidateServiceVPNRoute(ctx, route); err != nil {
		ladder.report(Attempt{RouteKind: "VPN", UplinkID: route.ModemID, SubscriptionID: route.SubscriptionID, NodeID: route.NodeID, ResultCode: "ROUTE_STALE"})
		return nil, errors.New("signed update VPN service route became stale")
	}
	if err := ladder.Selector.Select(ctx, route.ProbeGroupName, route.ProviderNodeName); err != nil {
		ladder.report(Attempt{RouteKind: "VPN", UplinkID: route.ModemID, SubscriptionID: route.SubscriptionID, NodeID: route.NodeID, ResultCode: "NODE_SELECT_FAILED"})
		return nil, errors.New("signed update VPN node selection failed")
	}
	if err := ladder.Selector.Select(ctx, mihomo.ProbeGroupName, route.ProbeGroupName); err != nil {
		ladder.report(Attempt{RouteKind: "VPN", UplinkID: route.ModemID, SubscriptionID: route.SubscriptionID, NodeID: route.NodeID, ResultCode: "PATH_SELECT_FAILED"})
		return nil, errors.New("signed update VPN path selection failed")
	}
	dial, err := subscriptionnet.NewSOCKS5Dialer(ladder.ProbeAddress)
	if err != nil {
		return nil, err
	}
	resolver := subscriptionnet.NewProxyResolver(dial, ladder.BootstrapDNS)
	response, err := ladder.roundTripRequest(ctx, request, resolver, dial, nil)
	code := "HTTPS_FAILED"
	if err == nil && retryableHTTPStatus(response.StatusCode) {
		code = "HTTP_RETRYABLE"
	} else if err == nil {
		code = "HTTPS_SUCCEEDED"
	}
	ladder.report(Attempt{RouteKind: "VPN", UplinkID: route.ModemID, SubscriptionID: route.SubscriptionID, NodeID: route.NodeID, ResultCode: code})
	return response, err
}

func (ladder *Ladder) tryDirect(request *http.Request, current uplink.Uplink) (*http.Response, error) {
	ctx, cancel := boundedAttempt(request.Context())
	defer cancel()
	if current.Fwmark <= 0 || current.Fwmark > int64(^uint32(0)) {
		return nil, errors.New("signed update uplink mark is invalid")
	}
	dial, err := boundDialer(current.CurrentIfname, uint32(current.Fwmark))
	if err != nil {
		return nil, err
	}
	resolver := directResolver(dial, ladder.BootstrapDNS)
	authorize := func(authorizeContext context.Context, addresses []netip.Addr, port uint16) error {
		values := make([]string, 0, len(addresses))
		for _, address := range addresses {
			values = append(values, address.Unmap().String())
		}
		return ladder.Broker.AuthorizeUpdateService(authorizeContext, current.ID, values, port)
	}
	response, err := ladder.roundTripRequest(ctx, request, resolver, dial, authorize)
	code := "HTTPS_FAILED"
	if err == nil && retryableHTTPStatus(response.StatusCode) {
		code = "HTTP_RETRYABLE"
	} else if err == nil {
		code = "HTTPS_SUCCEEDED"
	}
	ladder.report(Attempt{RouteKind: "DIRECT", UplinkID: current.ID, ResultCode: code})
	return response, err
}

func (ladder *Ladder) validate() error {
	if ladder == nil || ladder.Routes == nil || ladder.Policy == nil || ladder.Uplinks == nil || ladder.Broker == nil || ladder.Selector == nil || ladder.OperationLock == nil {
		return errors.New("signed update service route ladder is incomplete")
	}
	if len(ladder.BootstrapDNS) == 0 || len(ladder.BootstrapDNS) > 8 {
		return errors.New("signed update bootstrap DNS is invalid")
	}
	for _, value := range ladder.BootstrapDNS {
		address, err := netip.ParseAddr(value)
		if err != nil || !publicIPv4(address.Unmap()) {
			return errors.New("signed update bootstrap DNS must contain public IPv4 addresses")
		}
	}
	if _, err := subscriptionnet.NewSOCKS5Dialer(ladder.ProbeAddress); err != nil {
		return err
	}
	return nil
}

func (ladder *Ladder) report(attempt Attempt) {
	if ladder.OnAttempt != nil {
		ladder.OnAttempt(attempt)
	}
}

func (ladder *Ladder) roundTripRequest(ctx context.Context, request *http.Request, resolver subscription.Resolver, dial subscription.DialContextFunc, authorize subscription.EndpointAuthorizer) (*http.Response, error) {
	if ladder.roundTrip != nil {
		return ladder.roundTrip(ctx, request, resolver, dial, authorize)
	}
	return roundTripThrough(ctx, request, resolver, dial, authorize)
}

func validateRequest(request *http.Request) error {
	if request == nil || request.Method != http.MethodGet || request.Body != nil || request.URL == nil || request.URL.Scheme != "https" || request.URL.Hostname() == "" || request.URL.User != nil || request.URL.Fragment != "" || request.URL.Opaque != "" {
		return errors.New("signed update service request must be a bodyless HTTPS GET")
	}
	if port := request.URL.Port(); port != "" && port != "443" {
		return errors.New("signed update service routes support HTTPS port 443 only")
	}
	host := strings.ToLower(strings.TrimSuffix(request.URL.Hostname(), "."))
	if address, err := netip.ParseAddr(host); err == nil {
		if !publicIPv4(address.Unmap()) {
			return errors.New("signed update destination is not public IPv4")
		}
		return nil
	}
	if !publicHostname(host) {
		return errors.New("signed update destination hostname is invalid or local")
	}
	return nil
}

func roundTripThrough(ctx context.Context, original *http.Request, resolver subscription.Resolver, dial subscription.DialContextFunc, authorize subscription.EndpointAuthorizer) (*http.Response, error) {
	transport := &http.Transport{
		Proxy:                 nil,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 15 * time.Second,
		IdleConnTimeout:       15 * time.Second,
		DisableCompression:    true,
		MaxIdleConns:          1,
	}
	transport.DialContext = func(dialContext context.Context, network, address string) (net.Conn, error) {
		host, rawPort, err := net.SplitHostPort(address)
		if err != nil {
			return nil, errors.New("signed update dial address is invalid")
		}
		port, err := strconv.ParseUint(rawPort, 10, 16)
		if err != nil || port != 443 {
			return nil, errors.New("signed update service dial port is invalid")
		}
		addresses, err := resolver.LookupNetIP(dialContext, "ip4", host)
		if err != nil || len(addresses) == 0 || len(addresses) > maximumDNSAnswers {
			return nil, errors.New("signed update DNS resolution failed")
		}
		validated := make([]netip.Addr, 0, len(addresses))
		for _, candidate := range addresses {
			candidate = candidate.Unmap()
			if !publicIPv4(candidate) {
				return nil, errors.New("signed update DNS returned a non-public address")
			}
			validated = append(validated, candidate)
		}
		if authorize != nil {
			if err := authorize(dialContext, validated, uint16(port)); err != nil {
				return nil, errors.New("signed update endpoint authorization failed")
			}
		}
		for _, candidate := range validated {
			connection, err := dial(dialContext, "tcp4", net.JoinHostPort(candidate.String(), rawPort))
			if err == nil {
				return connection, nil
			}
		}
		return nil, errors.New("signed update endpoint connection failed")
	}
	request := original.Clone(ctx)
	response, err := transport.RoundTrip(request)
	if err != nil {
		transport.CloseIdleConnections()
		return nil, err
	}
	if response == nil || response.Body == nil {
		transport.CloseIdleConnections()
		return nil, errors.New("signed update HTTPS response is invalid")
	}
	response.Body = &transportBody{ReadCloser: response.Body, transport: transport}
	return response, nil
}

type transportBody struct {
	io.ReadCloser
	transport *http.Transport
}

func (body *transportBody) Close() error {
	err := body.ReadCloser.Close()
	body.transport.CloseIdleConnections()
	return err
}

func boundDialer(interfaceName string, fwmark uint32) (subscription.DialContextFunc, error) {
	configuration := netbind.Config{InterfaceName: interfaceName, Fwmark: fwmark}
	if err := configuration.Validate(); err != nil {
		return nil, err
	}
	dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 15 * time.Second, Control: netbind.SocketControl(configuration)}
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		switch network {
		case "tcp":
			network = "tcp4"
		case "udp":
			network = "udp4"
		case "tcp4", "udp4":
		default:
			return nil, errors.New("signed update direct service route supports IPv4 TCP and DNS only")
		}
		return dialer.DialContext(ctx, network, address)
	}, nil
}

func directResolver(dial subscription.DialContextFunc, bootstrapDNS []string) subscription.Resolver {
	return &net.Resolver{PreferGo: true, StrictErrors: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		if strings.HasPrefix(network, "tcp") {
			network = "tcp4"
		} else {
			network = "udp4"
		}
		return dial(ctx, network, net.JoinHostPort(bootstrapDNS[0], "53"))
	}}
}

func boundedAttempt(parent context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(parent, attemptTimeout)
}

func lockContext(ctx context.Context, locker sync.Locker) (func(), error) {
	acquired := make(chan struct{})
	abandoned := make(chan struct{})
	go func() {
		locker.Lock()
		select {
		case acquired <- struct{}{}:
		case <-abandoned:
			locker.Unlock()
		}
	}()
	select {
	case <-ctx.Done():
		close(abandoned)
		return nil, ctx.Err()
	case <-acquired:
		return locker.Unlock, nil
	}
}

func publicIPv4(address netip.Addr) bool {
	address = address.Unmap()
	if !address.Is4() || !address.IsGlobalUnicast() || address.IsPrivate() || address.IsLoopback() || address.IsLinkLocalUnicast() || address.IsLinkLocalMulticast() || address.IsUnspecified() || address.IsMulticast() {
		return false
	}
	for _, prefix := range nonPublicIPv4Prefixes {
		if prefix.Contains(address) {
			return false
		}
	}
	return true
}

func retryableHTTPStatus(status int) bool {
	return status == http.StatusForbidden || status == http.StatusProxyAuthRequired || status == http.StatusRequestTimeout || status == http.StatusTooEarly || status == http.StatusTooManyRequests || status == http.StatusUnavailableForLegalReasons || status >= 500 && status <= 599
}

func publicHostname(host string) bool {
	if host == "" || len(host) > 253 || host == "localhost" || strings.HasSuffix(host, ".localhost") || strings.HasSuffix(host, ".local") || strings.HasSuffix(host, ".lan") || strings.HasSuffix(host, ".internal") {
		return false
	}
	labels := strings.Split(host, ".")
	if len(labels) < 2 {
		return false
	}
	for _, label := range labels {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, character := range label {
			if character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || character == '-' {
				continue
			}
			return false
		}
	}
	return true
}
