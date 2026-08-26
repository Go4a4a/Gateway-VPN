package endurance

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strconv"
	"strings"
	"time"

	"gateway-vpn/internal/diagnostics"
)

const (
	maximumAPIJSONBytes  = int64(32 << 10)
	minimumPasswordBytes = 12
	maximumPasswordBytes = 1024
	sessionRenewalLead   = 15 * time.Minute
)

type APIClient struct {
	baseURL  *url.URL
	http     *http.Client
	username string
	password []byte
	csrf     string
	expires  time.Time
	now      func() time.Time
}

type loginResponse struct {
	UserID             string `json:"user_id"`
	User               string `json:"user"`
	SessionID          string `json:"session_id"`
	CSRFToken          string `json:"csrf_token"`
	MustChangePassword bool   `json:"must_change_password"`
	ExpiresAt          string `json:"expires_at"`
}

func NewAPIClient(endpoint string, caCertificatePEM []byte, username string, password []byte) (*APIClient, error) {
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || (parsed.Path != "" && parsed.Path != "/") || parsed.RawPath != "" {
		return nil, errors.New("endurance endpoint must be an HTTPS origin without credentials, path, query, or fragment")
	}
	if strings.TrimSpace(username) != username || len(username) < 3 || len(username) > 64 || len(password) < minimumPasswordBytes || len(password) > maximumPasswordBytes {
		return nil, errors.New("valid endurance username and password are required")
	}
	roots := x509.NewCertPool()
	if len(caCertificatePEM) == 0 || !roots.AppendCertsFromPEM(caCertificatePEM) {
		return nil, errors.New("Gateway TLS CA certificate is invalid")
	}
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, errors.New("create in-memory session jar failed")
	}
	transport := &http.Transport{
		Proxy:             nil,
		DialContext:       (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		ForceAttemptHTTP2: true, MaxIdleConns: 2, MaxIdleConnsPerHost: 2, IdleConnTimeout: 90 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: 60 * time.Second,
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots},
	}
	parsed.Path = ""
	return &APIClient{
		baseURL: parsed, http: &http.Client{Transport: transport, Jar: jar, Timeout: 2 * time.Minute, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirects are forbidden") }},
		username: username, password: append([]byte(nil), password...), now: func() time.Time { return time.Now().UTC() },
	}, nil
}

func (client *APIClient) Sample(ctx context.Context) (Sample, error) {
	if err := client.ensureSession(ctx); err != nil {
		return Sample{}, err
	}
	response, err := client.request(ctx, http.MethodGet, "/api/v1/system/runtime-metrics", nil, false)
	if err != nil {
		return Sample{}, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || !contentTypeIs(response.Header.Get("Content-Type"), "application/json") {
		return Sample{}, apiStatusError(response)
	}
	sample, err := DecodeSample(io.LimitReader(response.Body, maximumAPIJSONBytes+1))
	if err != nil {
		return Sample{}, err
	}
	return sample, nil
}

func (client *APIClient) Diagnostic(ctx context.Context) ([]byte, string, error) {
	if err := client.ensureSession(ctx); err != nil {
		return nil, "", err
	}
	response, err := client.request(ctx, http.MethodPost, "/api/v1/system/diagnostics", http.NoBody, true)
	if err != nil {
		return nil, "", err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || !contentTypeIs(response.Header.Get("Content-Type"), "application/zip") || response.Header.Get("X-Diagnostic-Complete") != "true" {
		return nil, "", apiStatusError(response)
	}
	content, err := io.ReadAll(io.LimitReader(response.Body, diagnostics.MaximumBundleBytes+1))
	if err != nil || len(content) == 0 || len(content) > diagnostics.MaximumBundleBytes {
		return nil, "", errors.New("read bounded diagnostic archive failed")
	}
	if declared := response.Header.Get("Content-Length"); declared != "" {
		value, parseErr := strconv.ParseInt(declared, 10, 64)
		if parseErr != nil || value != int64(len(content)) {
			return nil, "", errors.New("diagnostic Content-Length mismatch")
		}
	}
	expectedSHA256 := strings.ToLower(response.Header.Get("X-Content-SHA256"))
	if len(expectedSHA256) != 64 {
		return nil, "", errors.New("diagnostic SHA-256 header is invalid")
	}
	digest := sha256.Sum256(content)
	if hex.EncodeToString(digest[:]) != expectedSHA256 {
		return nil, "", errors.New("diagnostic response SHA-256 mismatch")
	}
	return content, expectedSHA256, nil
}

func (client *APIClient) Close(ctx context.Context) error {
	if client == nil {
		return nil
	}
	defer func() {
		for index := range client.password {
			client.password[index] = 0
		}
		client.password = nil
		client.csrf = ""
		if transport, ok := client.http.Transport.(*http.Transport); ok {
			transport.CloseIdleConnections()
		}
	}()
	if client.csrf == "" {
		return nil
	}
	response, err := client.request(ctx, http.MethodPost, "/api/v1/auth/logout", http.NoBody, true)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		return apiStatusError(response)
	}
	return nil
}

func (client *APIClient) ensureSession(ctx context.Context) error {
	if client == nil || client.http == nil || client.baseURL == nil || len(client.password) == 0 {
		return errors.New("endurance API client is closed or incomplete")
	}
	if client.csrf != "" && client.expires.After(client.now().Add(sessionRenewalLead)) {
		return nil
	}
	if client.csrf != "" {
		response, err := client.request(ctx, http.MethodPost, "/api/v1/auth/logout", http.NoBody, true)
		if err != nil {
			return err
		}
		response.Body.Close()
		if response.StatusCode != http.StatusNoContent {
			return apiStatusError(response)
		}
		client.csrf = ""
		client.expires = time.Time{}
	}
	return client.login(ctx)
}

func (client *APIClient) login(ctx context.Context) error {
	payload, err := json.Marshal(map[string]string{"username": client.username, "password": string(client.password)})
	if err != nil {
		return errors.New("encode endurance login failed")
	}
	response, err := client.request(ctx, http.MethodPost, "/api/v1/auth/login", bytes.NewReader(payload), false)
	for index := range payload {
		payload[index] = 0
	}
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || !contentTypeIs(response.Header.Get("Content-Type"), "application/json") {
		return apiStatusError(response)
	}
	content, err := io.ReadAll(io.LimitReader(response.Body, maximumAPIJSONBytes+1))
	if err != nil || int64(len(content)) > maximumAPIJSONBytes {
		return errors.New("read endurance login response failed")
	}
	var session loginResponse
	if err := decodeStrictJSON(content, &session); err != nil {
		return errors.New("decode endurance login response failed")
	}
	expires, err := time.Parse(time.RFC3339Nano, session.ExpiresAt)
	if err != nil || !expires.After(client.now().Add(time.Minute)) || session.User != client.username || session.UserID == "" || len(session.SessionID) != 64 || len(session.CSRFToken) < 32 || session.MustChangePassword {
		return errors.New("endurance login session is invalid or requires password change")
	}
	if len(client.http.Jar.Cookies(client.baseURL)) == 0 {
		return errors.New("endurance login did not establish a secure session cookie")
	}
	client.csrf = session.CSRFToken
	client.expires = expires.UTC()
	return nil
}

func (client *APIClient) request(ctx context.Context, method, path string, body io.Reader, csrf bool) (*http.Response, error) {
	endpoint := *client.baseURL
	endpoint.Path = path
	request, err := http.NewRequestWithContext(ctx, method, endpoint.String(), body)
	if err != nil {
		return nil, errors.New("create endurance API request failed")
	}
	request.Header.Set("User-Agent", "gateway-vpn-endurance/1")
	request.Header.Set("Accept", "application/json")
	if method == http.MethodPost && body != http.NoBody {
		request.Header.Set("Content-Type", "application/json")
	}
	if csrf {
		request.Header.Set("X-CSRF-Token", client.csrf)
	}
	response, err := client.http.Do(request)
	if err != nil {
		return nil, errors.New("Gateway endurance API request failed")
	}
	return response, nil
}

func apiStatusError(response *http.Response) error {
	if response == nil {
		return errors.New("Gateway endurance API response is unavailable")
	}
	var envelope struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	content, _ := io.ReadAll(io.LimitReader(response.Body, maximumAPIJSONBytes+1))
	code := "UNEXPECTED_RESPONSE"
	if int64(len(content)) <= maximumAPIJSONBytes && decodeStrictJSON(content, &envelope) == nil && envelope.Error.Code != "" && len(envelope.Error.Code) <= 64 {
		code = envelope.Error.Code
	}
	return fmt.Errorf("Gateway endurance API returned HTTP %d (%s)", response.StatusCode, code)
}

func contentTypeIs(value, expected string) bool {
	mediaType, _, err := mime.ParseMediaType(value)
	return err == nil && strings.EqualFold(mediaType, expected)
}
