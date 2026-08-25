package mihomo

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"
)

const maxAPIResponseBytes = 1 << 20

type Client struct {
	baseURL    *url.URL
	secret     string
	httpClient *http.Client
}

type Version struct {
	Meta    bool   `json:"meta"`
	Version string `json:"version"`
}

type DelayResult struct {
	Delay uint16 `json:"delay"`
}

type ProxyState struct {
	Name string `json:"name"`
	Type string `json:"type"`
	Now  string `json:"now"`
}

func NewClient(controllerURL, secret string, httpClient *http.Client) (*Client, error) {
	parsed, err := url.Parse(controllerURL)
	if err != nil || parsed.Scheme != "http" || parsed.Host == "" || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, errors.New("Mihomo controller URL must be a plain loopback HTTP origin")
	}
	host := parsed.Hostname()
	address := net.ParseIP(host)
	if address == nil || !address.IsLoopback() {
		return nil, errors.New("Mihomo controller must use a loopback IP address")
	}
	if parsed.Port() == "" {
		return nil, errors.New("Mihomo controller port is required")
	}
	if secret == "" {
		return nil, errors.New("Mihomo API secret is required")
	}
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 10 * time.Second}
	}
	return &Client{baseURL: parsed, secret: secret, httpClient: httpClient}, nil
}

func (client *Client) GetVersion(ctx context.Context) (Version, error) {
	var result Version
	if err := client.doJSON(ctx, http.MethodGet, "/version", nil, http.StatusOK, &result); err != nil {
		return Version{}, err
	}
	if result.Version == "" {
		return Version{}, errors.New("Mihomo version response is empty")
	}
	return result, nil
}

func (client *Client) Reload(ctx context.Context, relativeConfigPath string) error {
	if !safeAPIConfigPath(relativeConfigPath) {
		return errors.New("Mihomo reload path must be a safe relative path below HomeDir")
	}
	endpoint := "/configs?force=true"
	return client.doJSON(ctx, http.MethodPut, endpoint, map[string]string{"path": relativeConfigPath}, http.StatusNoContent, nil)
}

func (client *Client) Select(ctx context.Context, group, target string) error {
	if group == "" || target == "" || strings.ContainsAny(group+target, "\r\n") {
		return errors.New("Mihomo group and target are required")
	}
	endpoint := "/proxies/" + url.PathEscape(group)
	return client.doJSON(ctx, http.MethodPut, endpoint, map[string]string{"name": target}, http.StatusNoContent, nil)
}

func (client *Client) Selected(ctx context.Context, group string) (ProxyState, error) {
	if group == "" || strings.ContainsAny(group, "\r\n") {
		return ProxyState{}, errors.New("Mihomo group is required")
	}
	var state ProxyState
	endpoint := "/proxies/" + url.PathEscape(group)
	if err := client.doJSON(ctx, http.MethodGet, endpoint, nil, http.StatusOK, &state); err != nil {
		return ProxyState{}, err
	}
	if state.Name == "" || state.Now == "" {
		return ProxyState{}, errors.New("Mihomo proxy selection response is incomplete")
	}
	return state, nil
}

func (client *Client) ProxyDelay(ctx context.Context, proxy, targetURL string, timeout time.Duration, expectedStatus string) (uint16, error) {
	if proxy == "" || strings.ContainsAny(proxy, "\r\n") {
		return 0, errors.New("Mihomo proxy delay group is required")
	}
	query, err := delayQuery(targetURL, timeout, expectedStatus)
	if err != nil {
		return 0, err
	}
	endpoint := "/proxies/" + url.PathEscape(proxy) + "/delay?" + query
	var result DelayResult
	if err := client.doJSON(ctx, http.MethodGet, endpoint, nil, http.StatusOK, &result); err != nil {
		return 0, err
	}
	return result.Delay, nil
}

func (client *Client) ProviderNodeDelay(ctx context.Context, provider, node, targetURL string, timeout time.Duration, expectedStatus string) (uint16, error) {
	if provider == "" || node == "" {
		return 0, errors.New("invalid Mihomo provider-node delay request")
	}
	query, err := delayQuery(targetURL, timeout, expectedStatus)
	if err != nil {
		return 0, err
	}
	endpoint := "/providers/proxies/" + url.PathEscape(provider) + "/" + url.PathEscape(node) + "/healthcheck?" + query
	var result DelayResult
	if err := client.doJSON(ctx, http.MethodGet, endpoint, nil, http.StatusOK, &result); err != nil {
		return 0, err
	}
	return result.Delay, nil
}

func delayQuery(targetURL string, timeout time.Duration, expectedStatus string) (string, error) {
	if timeout <= 0 || timeout > 60*time.Second {
		return "", errors.New("invalid Mihomo delay timeout")
	}
	target, err := url.Parse(targetURL)
	if err != nil || target.Scheme != "https" || target.Host == "" || target.User != nil {
		return "", errors.New("Mihomo delay target must be an HTTPS URL without credentials")
	}
	values := url.Values{}
	values.Set("url", target.String())
	values.Set("timeout", strconv.FormatInt(timeout.Milliseconds(), 10))
	if expectedStatus != "" {
		values.Set("expected", expectedStatus)
	}
	return values.Encode(), nil
}

func (client *Client) doJSON(ctx context.Context, method, endpoint string, requestBody any, expectedStatus int, responseBody any) error {
	var body io.Reader
	if requestBody != nil {
		encoded, err := json.Marshal(requestBody)
		if err != nil {
			return fmt.Errorf("encode Mihomo API request: %w", err)
		}
		body = bytes.NewReader(encoded)
	}
	reference, err := url.Parse(endpoint)
	if err != nil || reference.IsAbs() || reference.Host != "" || !strings.HasPrefix(reference.Path, "/") {
		return errors.New("invalid internal Mihomo API endpoint")
	}
	requestURL := client.baseURL.ResolveReference(reference)
	request, err := http.NewRequestWithContext(ctx, method, requestURL.String(), body)
	if err != nil {
		return fmt.Errorf("create Mihomo API request: %w", err)
	}
	request.Header.Set("Authorization", "Bearer "+client.secret)
	request.Header.Set("Accept", "application/json")
	if requestBody != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := client.httpClient.Do(request)
	if err != nil {
		return fmt.Errorf("call Mihomo API: %w", err)
	}
	defer response.Body.Close()
	limited := io.LimitReader(response.Body, maxAPIResponseBytes+1)
	payload, err := io.ReadAll(limited)
	if err != nil {
		return fmt.Errorf("read Mihomo API response: %w", err)
	}
	if len(payload) > maxAPIResponseBytes {
		return errors.New("Mihomo API response exceeds size limit")
	}
	if response.StatusCode != expectedStatus {
		message := strings.TrimSpace(string(payload))
		if len(message) > 256 {
			message = message[:256]
		}
		return fmt.Errorf("Mihomo API returned HTTP %d: %s", response.StatusCode, message)
	}
	if responseBody != nil {
		if err := json.Unmarshal(payload, responseBody); err != nil {
			return fmt.Errorf("decode Mihomo API response: %w", err)
		}
	}
	return nil
}

func safeAPIConfigPath(value string) bool {
	if value == "" || path.IsAbs(value) || strings.Contains(value, "\\") {
		return false
	}
	clean := path.Clean(value)
	return clean != "." && clean != ".." && !strings.HasPrefix(clean, "../") && clean == value
}
