package mihomo

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
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

type TrafficSnapshot struct {
	UploadBPS     uint64 `json:"up"`
	DownloadBPS   uint64 `json:"down"`
	UploadTotal   uint64 `json:"upTotal"`
	DownloadTotal uint64 `json:"downTotal"`
}

type ConnectionsSummary struct {
	DownloadTotal uint64          `json:"downloadTotal"`
	UploadTotal   uint64          `json:"uploadTotal"`
	Connections   json.RawMessage `json:"connections"`
	Memory        uint64          `json:"memory"`
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

func (client *Client) GetConnectionsSummary(ctx context.Context) (ConnectionsSummary, error) {
	var result ConnectionsSummary
	if err := client.doJSON(ctx, http.MethodGet, "/connections", nil, http.StatusOK, &result); err != nil {
		return ConnectionsSummary{}, err
	}
	trimmed := bytes.TrimSpace(result.Connections)
	if !bytes.Equal(trimmed, []byte("null")) && (len(trimmed) < 2 || trimmed[0] != '[' || trimmed[len(trimmed)-1] != ']') {
		return ConnectionsSummary{}, errors.New("Mihomo connections response is invalid")
	}
	return result, nil
}

// Traffic reads exactly one bounded message from Mihomo's official /traffic
// WebSocket. The controller is loopback-only and authenticated by the same
// bearer secret as the other local API operations.
func (client *Client) Traffic(ctx context.Context) (TrafficSnapshot, error) {
	if client == nil || client.baseURL == nil || client.httpClient == nil {
		return TrafficSnapshot{}, errors.New("Mihomo API client is not configured")
	}
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return TrafficSnapshot{}, errors.New("create Mihomo traffic WebSocket nonce failed")
	}
	key := base64.StdEncoding.EncodeToString(nonce)
	endpoint := *client.baseURL
	endpoint.Path = "/traffic"
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return TrafficSnapshot{}, errors.New("create Mihomo traffic request failed")
	}
	request.Header.Set("Authorization", "Bearer "+client.secret)
	request.Header.Set("Connection", "Upgrade")
	request.Header.Set("Upgrade", "websocket")
	request.Header.Set("Sec-WebSocket-Key", key)
	request.Header.Set("Sec-WebSocket-Version", "13")
	response, err := client.httpClient.Do(request)
	if err != nil {
		return TrafficSnapshot{}, errors.New("Mihomo traffic API is unavailable")
	}
	defer response.Body.Close()
	acceptDigest := sha1.Sum([]byte(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
	expectedAccept := base64.StdEncoding.EncodeToString(acceptDigest[:])
	if response.StatusCode != http.StatusSwitchingProtocols || !headerHasToken(response.Header, "Connection", "upgrade") || !headerHasToken(response.Header, "Upgrade", "websocket") || response.Header.Get("Sec-WebSocket-Accept") != expectedAccept {
		return TrafficSnapshot{}, errors.New("Mihomo traffic WebSocket handshake is invalid")
	}
	payload, err := readWebSocketText(response.Body, maxAPIResponseBytes)
	if err != nil {
		return TrafficSnapshot{}, err
	}
	var snapshot TrafficSnapshot
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&snapshot); err != nil {
		return TrafficSnapshot{}, errors.New("Mihomo traffic response is invalid")
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return TrafficSnapshot{}, errors.New("Mihomo traffic response has trailing data")
	}
	return snapshot, nil
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

func headerHasToken(header http.Header, name, expected string) bool {
	for _, value := range header.Values(name) {
		for _, token := range strings.Split(value, ",") {
			if strings.EqualFold(strings.TrimSpace(token), expected) {
				return true
			}
		}
	}
	return false
}

func readWebSocketText(reader io.Reader, maximum int64) ([]byte, error) {
	for frames := 0; frames < 8; frames++ {
		header := make([]byte, 2)
		if _, err := io.ReadFull(reader, header); err != nil {
			return nil, errors.New("read Mihomo traffic WebSocket frame failed")
		}
		if header[0]&0x70 != 0 || header[1]&0x80 != 0 {
			return nil, errors.New("Mihomo traffic WebSocket frame flags are invalid")
		}
		final := header[0]&0x80 != 0
		opcode := header[0] & 0x0f
		length := uint64(header[1] & 0x7f)
		switch length {
		case 126:
			extended := make([]byte, 2)
			if _, err := io.ReadFull(reader, extended); err != nil {
				return nil, errors.New("read Mihomo traffic WebSocket length failed")
			}
			length = uint64(binary.BigEndian.Uint16(extended))
		case 127:
			extended := make([]byte, 8)
			if _, err := io.ReadFull(reader, extended); err != nil {
				return nil, errors.New("read Mihomo traffic WebSocket length failed")
			}
			length = binary.BigEndian.Uint64(extended)
		}
		if length > uint64(maximum) {
			return nil, errors.New("Mihomo traffic WebSocket frame is oversized")
		}
		payload := make([]byte, int(length))
		if _, err := io.ReadFull(reader, payload); err != nil {
			return nil, errors.New("read Mihomo traffic WebSocket payload failed")
		}
		switch opcode {
		case 0x1:
			if !final {
				return nil, errors.New("fragmented Mihomo traffic WebSocket message is unsupported")
			}
			return payload, nil
		case 0x8:
			return nil, errors.New("Mihomo traffic WebSocket closed before a sample")
		case 0x9, 0xa:
			if !final || length > 125 {
				return nil, errors.New("Mihomo traffic WebSocket control frame is invalid")
			}
		default:
			return nil, errors.New("Mihomo traffic WebSocket opcode is unsupported")
		}
	}
	return nil, errors.New("Mihomo traffic WebSocket did not produce a data frame")
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
