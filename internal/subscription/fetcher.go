package subscription

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type Resolver interface {
	LookupNetIP(context.Context, string, string) ([]netip.Addr, error)
}

type DialContextFunc func(context.Context, string, string) (net.Conn, error)

type EndpointAuthorizer func(context.Context, []netip.Addr, uint16) error

type FetchOptions struct {
	ETag         string
	LastModified string
}

type FetchResult struct {
	Payload      []byte
	ETag         string
	LastModified string
	NotModified  bool
}

type Fetcher struct {
	resolver          Resolver
	timeout           time.Duration
	maxRedirects      int
	forbiddenPrefixes []netip.Prefix
	ipPolicy          func(netip.Addr) error
	tlsConfig         *tls.Config
}

func NewFetcher(resolver Resolver, forbiddenPrefixes []netip.Prefix) (*Fetcher, error) {
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	for _, prefix := range forbiddenPrefixes {
		if !prefix.IsValid() {
			return nil, errors.New("invalid forbidden subscription network prefix")
		}
	}
	fetcher := &Fetcher{
		resolver:          resolver,
		timeout:           30 * time.Second,
		maxRedirects:      3,
		forbiddenPrefixes: append([]netip.Prefix(nil), forbiddenPrefixes...),
		tlsConfig:         &tls.Config{MinVersion: tls.VersionTLS12},
	}
	fetcher.ipPolicy = fetcher.validateAddress
	return fetcher, nil
}

// NewFetcherWithRootCAs supports deployments with a private subscription CA
// without weakening hostname verification or the TLS version floor.
func NewFetcherWithRootCAs(resolver Resolver, forbiddenPrefixes []netip.Prefix, roots *x509.CertPool) (*Fetcher, error) {
	if roots == nil {
		return nil, errors.New("subscription TLS root pool is required")
	}
	fetcher, err := NewFetcher(resolver, forbiddenPrefixes)
	if err != nil {
		return nil, err
	}
	fetcher.tlsConfig.RootCAs = roots.Clone()
	return fetcher, nil
}

func (fetcher *Fetcher) Fetch(ctx context.Context, secretURL string, options FetchOptions) (FetchResult, error) {
	return fetcher.fetch(ctx, secretURL, options, fetcher.resolver, nil, nil)
}

// FetchThrough retains all URL, redirect, TLS, response-size, and SSRF checks
// while allowing an internal transport adapter to supply modem-bound DNS,
// dialing, and firewall authorization.
func (fetcher *Fetcher) FetchThrough(ctx context.Context, secretURL string, options FetchOptions, resolver Resolver, dial DialContextFunc, authorize EndpointAuthorizer) (FetchResult, error) {
	return fetcher.fetch(ctx, secretURL, options, resolver, dial, authorize)
}

func (fetcher *Fetcher) fetch(ctx context.Context, secretURL string, options FetchOptions, resolver Resolver, dial DialContextFunc, authorize EndpointAuthorizer) (FetchResult, error) {
	if fetcher == nil || fetcher.resolver == nil || fetcher.ipPolicy == nil || fetcher.tlsConfig == nil {
		return FetchResult{}, errors.New("subscription fetcher is not configured")
	}
	target, err := fetcher.validateURL(secretURL)
	if err != nil {
		return FetchResult{}, err
	}
	tlsConfig := fetcher.tlsConfig.Clone()
	if tlsConfig.MinVersion < tls.VersionTLS12 {
		tlsConfig.MinVersion = tls.VersionTLS12
	}
	transport := &http.Transport{
		Proxy:           nil,
		TLSClientConfig: tlsConfig,
		DialContext: func(dialContext context.Context, network, address string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(address)
			if err != nil {
				return nil, errors.New("subscription endpoint address is invalid")
			}
			addresses, err := resolver.LookupNetIP(dialContext, "ip", host)
			if err != nil || len(addresses) == 0 || len(addresses) > 64 {
				return nil, errors.New("subscription DNS resolution failed")
			}
			validated := make([]netip.Addr, 0, len(addresses))
			for _, candidate := range addresses {
				candidate = candidate.Unmap()
				if err := fetcher.ipPolicy(candidate); err != nil {
					return nil, err
				}
				validated = append(validated, candidate)
			}
			portValue, err := strconv.ParseUint(port, 10, 16)
			if err != nil || portValue == 0 {
				return nil, errors.New("subscription endpoint port is invalid")
			}
			if authorize != nil {
				if err := authorize(dialContext, validated, uint16(portValue)); err != nil {
					return nil, errors.New("subscription endpoint firewall authorization failed")
				}
			}
			if dial == nil {
				dialer := net.Dialer{Timeout: 10 * time.Second, KeepAlive: 15 * time.Second}
				dial = dialer.DialContext
			}
			for _, candidate := range validated {
				connection, err := dial(dialContext, network, net.JoinHostPort(candidate.String(), port))
				if err == nil {
					return connection, nil
				}
			}
			return nil, errors.New("subscription endpoint connection failed")
		},
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 15 * time.Second,
		IdleConnTimeout:       30 * time.Second,
		MaxIdleConns:          2,
	}
	client := &http.Client{Transport: transport, Timeout: fetcher.timeout}
	defer transport.CloseIdleConnections()
	client.CheckRedirect = func(request *http.Request, previous []*http.Request) error {
		// CheckRedirect sees the original request in previous for the first
		// redirect, so > permits exactly maxRedirects hops.
		if len(previous) > fetcher.maxRedirects {
			return errors.New("subscription redirect limit exceeded")
		}
		if _, err := fetcher.validateURL(request.URL.String()); err != nil {
			return errors.New("subscription redirect target is forbidden")
		}
		return nil
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
	if err != nil {
		return FetchResult{}, errors.New("create subscription request failed")
	}
	request.Header.Set("Accept", "application/yaml,text/yaml,text/plain,application/octet-stream")
	request.Header.Set("User-Agent", "Gateway-VPN/1")
	if options.ETag != "" && len(options.ETag) <= 1024 && !strings.ContainsAny(options.ETag, "\r\n") {
		request.Header.Set("If-None-Match", options.ETag)
	}
	if options.LastModified != "" && len(options.LastModified) <= 128 && !strings.ContainsAny(options.LastModified, "\r\n") {
		request.Header.Set("If-Modified-Since", options.LastModified)
	}
	response, err := client.Do(request)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return FetchResult{}, err
		}
		return FetchResult{}, errors.New("subscription HTTPS request failed")
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusNotModified {
		etag := cleanResponseHeader(response.Header.Get("ETag"), 1024)
		if etag == "" {
			etag = options.ETag
		}
		lastModified := cleanResponseHeader(response.Header.Get("Last-Modified"), 128)
		if lastModified == "" {
			lastModified = options.LastModified
		}
		return FetchResult{NotModified: true, ETag: etag, LastModified: lastModified}, nil
	}
	if response.StatusCode != http.StatusOK {
		return FetchResult{}, fmt.Errorf("subscription server returned HTTP %d", response.StatusCode)
	}
	content, err := io.ReadAll(io.LimitReader(response.Body, MaxPayloadBytes+1))
	if err != nil {
		return FetchResult{}, errors.New("read subscription response failed")
	}
	if len(content) > MaxPayloadBytes {
		return FetchResult{}, fmt.Errorf("subscription response exceeds %d bytes", MaxPayloadBytes)
	}
	if len(content) == 0 {
		return FetchResult{}, errors.New("subscription response is empty")
	}
	return FetchResult{Payload: content, ETag: cleanResponseHeader(response.Header.Get("ETag"), 1024), LastModified: cleanResponseHeader(response.Header.Get("Last-Modified"), 128)}, nil
}

func (fetcher *Fetcher) validateURL(value string) (*url.URL, error) {
	if len(value) == 0 || len(value) > 8192 || strings.ContainsAny(value, "\r\n") {
		return nil, errors.New("subscription URL is empty, invalid, or too long")
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" || parsed.Opaque != "" {
		return nil, errors.New("subscription URL must use HTTPS without embedded credentials or fragment")
	}
	if port := parsed.Port(); port != "" {
		value, err := strconv.Atoi(port)
		if err != nil || value < 1 || value > 65535 {
			return nil, errors.New("subscription URL port is invalid")
		}
	}
	host := strings.ToLower(strings.TrimSuffix(parsed.Hostname(), "."))
	if address, err := netip.ParseAddr(host); err == nil {
		if err := fetcher.ipPolicy(address.Unmap()); err != nil {
			return nil, err
		}
	} else if !validSubscriptionHostname(host) {
		return nil, errors.New("subscription hostname is invalid or local")
	}
	return parsed, nil
}

func (fetcher *Fetcher) validateAddress(address netip.Addr) error {
	if err := defaultPublicAddressPolicy(address); err != nil {
		return err
	}
	for _, prefix := range fetcher.forbiddenPrefixes {
		if prefix.Contains(address) {
			return errors.New("subscription endpoint resolves into a protected local network")
		}
	}
	return nil
}

func defaultPublicAddressPolicy(address netip.Addr) error {
	if !address.IsValid() || address.Zone() != "" || !address.IsGlobalUnicast() || address.IsPrivate() || address.IsLoopback() || address.IsLinkLocalUnicast() || address.IsLinkLocalMulticast() || address.IsMulticast() {
		return errors.New("subscription endpoint must resolve only to public global unicast addresses")
	}
	return nil
}

func validSubscriptionHostname(value string) bool {
	if value == "" || len(value) > 253 || value == "localhost" || strings.HasSuffix(value, ".localhost") || strings.HasSuffix(value, ".local") || strings.HasSuffix(value, ".lan") || strings.HasSuffix(value, ".internal") {
		return false
	}
	labels := strings.Split(value, ".")
	if len(labels) < 2 {
		return false
	}
	for _, label := range labels {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, char := range label {
			if (char >= 'a' && char <= 'z') || (char >= '0' && char <= '9') || char == '-' {
				continue
			}
			return false
		}
	}
	return true
}

func cleanResponseHeader(value string, limit int) string {
	if strings.ContainsAny(value, "\r\n") || len(value) > limit {
		return ""
	}
	return strings.TrimSpace(value)
}
