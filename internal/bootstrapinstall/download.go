package bootstrapinstall

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const (
	MaximumRedirects = 5
	MaximumKeyBytes  = int64(16 << 10)
)

type Downloader struct {
	Client        *http.Client
	AllowedHosts  map[string]bool
	AllowHTTPTest bool
}

type FetchRequest struct {
	URL            string
	Destination    string
	MaximumBytes   int64
	ExpectedBytes  int64
	ExpectedSHA256 string
}

type FetchResult struct {
	Bytes  int64
	SHA256 string
}

func NewGitHubDownloader() Downloader {
	allowed := map[string]bool{
		"github.com":                           true,
		"objects.githubusercontent.com":        true,
		"release-assets.githubusercontent.com": true,
	}
	redirectQueryHosts := map[string]bool{
		// GitHub Releases returns a short-lived, signed query string when it
		// redirects an immutable release URL to its asset storage. Query
		// strings remain forbidden on every caller-supplied URL and on
		// redirects to the human-facing github.com origin.
		"objects.githubusercontent.com":        true,
		"release-assets.githubusercontent.com": true,
	}
	transport := &http.Transport{
		Proxy:             nil,
		DialContext:       (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		ForceAttemptHTTP2: true,
		TLSClientConfig:   &tls.Config{MinVersion: tls.VersionTLS12},
		IdleConnTimeout:   30 * time.Second,
	}
	client := &http.Client{Transport: transport, Timeout: 15 * time.Minute}
	client.CheckRedirect = func(request *http.Request, via []*http.Request) error {
		if len(via) >= MaximumRedirects {
			return errors.New("bootstrap download redirect limit exceeded")
		}
		return validateRedirectURL(request.URL, allowed, redirectQueryHosts, false)
	}
	return Downloader{Client: client, AllowedHosts: allowed}
}

func (downloader Downloader) Fetch(ctx context.Context, request FetchRequest) (FetchResult, error) {
	if downloader.Client == nil || request.MaximumBytes <= 0 || request.MaximumBytes > 1<<30 || request.ExpectedBytes < 0 || request.ExpectedBytes > request.MaximumBytes || request.ExpectedSHA256 != "" && !validDigest(request.ExpectedSHA256) || !filepath.IsAbs(request.Destination) {
		return FetchResult{}, errors.New("complete bounded bootstrap download request is required")
	}
	parsed, err := url.Parse(request.URL)
	if err != nil || validateRemoteURL(parsed, downloader.AllowedHosts, downloader.AllowHTTPTest, false) != nil {
		return FetchResult{}, errors.New("bootstrap download URL is outside the allowed origin policy")
	}
	parent := filepath.Dir(filepath.Clean(request.Destination))
	info, err := os.Lstat(parent)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return FetchResult{}, errors.New("bootstrap download destination parent is unsafe")
	}
	if _, err := os.Lstat(request.Destination); !errors.Is(err, os.ErrNotExist) {
		return FetchResult{}, errors.New("bootstrap download destination already exists or is unsafe")
	}
	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodGet, parsed.String(), nil)
	if err != nil {
		return FetchResult{}, errors.New("create bootstrap download request failed")
	}
	httpRequest.Header.Set("Accept", "application/octet-stream, application/json;q=0.9, */*;q=0.1")
	httpRequest.Header.Set("Accept-Encoding", "identity")
	httpRequest.Header.Set("User-Agent", "gateway-vpn-bootstrap/1")
	response, err := downloader.Client.Do(httpRequest)
	if err != nil {
		return FetchResult{}, errors.New("bootstrap download failed")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || response.Uncompressed || response.Header.Get("Content-Encoding") != "" && !strings.EqualFold(response.Header.Get("Content-Encoding"), "identity") {
		return FetchResult{}, errors.New("bootstrap download returned an invalid HTTP response")
	}
	if response.ContentLength > request.MaximumBytes || request.ExpectedBytes > 0 && response.ContentLength >= 0 && response.ContentLength != request.ExpectedBytes {
		return FetchResult{}, errors.New("bootstrap download Content-Length violates the signed bound")
	}
	output, err := os.OpenFile(request.Destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return FetchResult{}, errors.New("create bootstrap download file failed")
	}
	hash := sha256.New()
	written, copyErr := io.Copy(io.MultiWriter(output, hash), io.LimitReader(response.Body, request.MaximumBytes+1))
	syncErr := output.Sync()
	closeErr := output.Close()
	if copyErr != nil || syncErr != nil || closeErr != nil || written <= 0 || written > request.MaximumBytes || request.ExpectedBytes > 0 && written != request.ExpectedBytes {
		_ = os.Remove(request.Destination)
		return FetchResult{}, errors.New("bounded bootstrap download write failed")
	}
	digest := hex.EncodeToString(hash.Sum(nil))
	if request.ExpectedSHA256 != "" && digest != request.ExpectedSHA256 {
		_ = os.Remove(request.Destination)
		return FetchResult{}, errors.New("bootstrap download SHA-256 mismatch")
	}
	if err := syncDirectory(parent); err != nil {
		_ = os.Remove(request.Destination)
		return FetchResult{}, fmt.Errorf("sync bootstrap download directory: %w", err)
	}
	return FetchResult{Bytes: written, SHA256: digest}, nil
}

func validateRemoteURL(value *url.URL, allowedHosts map[string]bool, allowHTTP, allowQuery bool) error {
	if value == nil || value.User != nil || value.ForceQuery || !allowQuery && value.RawQuery != "" || value.Fragment != "" || value.Host == "" || value.Path == "" {
		return errors.New("remote URL has forbidden components")
	}
	scheme := strings.ToLower(value.Scheme)
	if scheme != "https" && !(allowHTTP && scheme == "http") {
		return errors.New("remote URL must use HTTPS")
	}
	host := strings.ToLower(value.Hostname())
	if host == "" || !allowedHosts[host] {
		return errors.New("remote URL host is not allowlisted")
	}
	if !allowHTTP {
		if address := net.ParseIP(host); address != nil || value.Port() != "" && value.Port() != "443" {
			return errors.New("remote URL literal IP or non-HTTPS port is forbidden")
		}
	}
	return nil
}

func validateRedirectURL(value *url.URL, allowedHosts, queryHosts map[string]bool, allowHTTP bool) error {
	if value == nil {
		return errors.New("redirect URL is required")
	}
	host := strings.ToLower(value.Hostname())
	allowQuery := value.RawQuery == "" || queryHosts[host]
	return validateRemoteURL(value, allowedHosts, allowHTTP, allowQuery)
}

func validDigest(value string) bool {
	if len(value) != 64 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil && value == strings.ToLower(value)
}

func syncDirectory(directory string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	file, err := os.Open(directory)
	if err != nil {
		return err
	}
	defer file.Close()
	return file.Sync()
}
