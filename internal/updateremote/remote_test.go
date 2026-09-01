package updateremote

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"

	"gateway-vpn/internal/distribution"
	updatepkg "gateway-vpn/internal/update"
)

type staticTransport map[string][]byte

func (transport staticTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	content, exists := transport[request.URL.String()]
	if !exists {
		return &http.Response{StatusCode: http.StatusNotFound, Body: io.NopCloser(strings.NewReader("missing")), Header: make(http.Header), Request: request}, nil
	}
	mediaType := "application/gzip"
	if strings.Contains(request.URL.Path, "/releases") {
		mediaType = "application/vnd.github+json; charset=utf-8"
	} else if strings.HasSuffix(request.URL.Path, ".json") {
		mediaType = "application/json"
	} else if strings.HasSuffix(request.URL.Path, ".sig") {
		mediaType = "application/octet-stream"
	}
	header := make(http.Header)
	header.Set("Content-Type", mediaType)
	return &http.Response{StatusCode: http.StatusOK, ContentLength: int64(len(content)), Body: io.NopCloser(strings.NewReader(string(content))), Header: header, Request: request}, nil
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (function roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

func TestCheckSelectsNewestValidSignedChannelRelease(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	stager := &updatepkg.Stager{StateDir: t.TempDir(), Policy: updatepkg.VerificationPolicy{PublicKey: publicKey}}
	transport := staticTransport{}
	releases := []map[string]any{
		releaseFixture(t, transport, privateKey, "stable", "v1.1.0", false, false, strings.Repeat("1", 64)),
		releaseFixture(t, transport, privateKey, "stable", "v1.3.0", false, false, strings.Repeat("3", 64)),
		releaseFixture(t, transport, privateKey, "stable", "v9.0.0", false, false, strings.Repeat("9", 64)),
		releaseFixture(t, transport, privateKey, "stable", "v2.0.0-rc.1", false, true, strings.Repeat("2", 64)),
	}
	// A forged higher manifest remains discovery data and is ignored.
	transport["https://downloads.example/v9.0.0/channel-stable.sig"] = []byte("forged\n")
	apiURL := "https://api.example/repos/Go4a4a/Gateway-VPN/releases?per_page=50"
	transport[apiURL], _ = json.Marshal(releases)
	manager, err := New(DefaultRepository, "1.0.0", stager)
	if err != nil {
		t.Fatal(err)
	}
	manager.APIBase = "https://api.example"
	manager.Client = &http.Client{Transport: transport}
	available, err := manager.Check(context.Background(), "stable")
	if err != nil {
		t.Fatal(err)
	}
	if !available.Available || available.CandidateVersion != "1.3.0" || available.ReleaseTag != "v1.3.0" || available.SourceReference != "Go4a4a/Gateway-VPN#v1.3.0" || available.ArtifactSHA256 != strings.Repeat("3", 64) {
		t.Fatalf("available = %+v", available)
	}
}

func TestCheckReturnsNoCandidateAndRejectsUnsafeExactURLs(t *testing.T) {
	publicKey, _, _ := ed25519.GenerateKey(rand.Reader)
	stager := &updatepkg.Stager{StateDir: t.TempDir(), Policy: updatepkg.VerificationPolicy{PublicKey: publicKey}}
	manager, err := New(DefaultRepository, "2.0.0", stager)
	if err != nil {
		t.Fatal(err)
	}
	apiURL := "https://api.example/repos/Go4a4a/Gateway-VPN/releases?per_page=50"
	manager.APIBase = "https://api.example"
	manager.Client = &http.Client{Transport: staticTransport{apiURL: []byte("[]")}}
	available, err := manager.Check(context.Background(), "testing")
	if err != nil || available.Available || available.Channel != "testing" || available.CurrentVersion != "2.0.0" {
		t.Fatalf("available = %+v, %v", available, err)
	}
	for _, raw := range []string{"http://example.com/release.tar.gz", "https://user:secret@example.com/release.tar.gz", "https://example.com/release.tar.gz#fragment", " https://example.com/release.tar.gz"} {
		if _, err := validateRemoteURL(raw); err == nil {
			t.Fatalf("unsafe URL accepted: %s", raw)
		}
	}
}

func TestExactSourceReferenceContainsNoURLComponents(t *testing.T) {
	parsed, err := validateRemoteURL("https://tenant-secret.updates.example/private/path-token/release.tar.gz?bearer=query-token")
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte(parsed.String()))
	reference := exactSourceReference(parsed)
	for _, secret := range []string{"tenant-secret", "path-token", "query-token", "updates.example", "release.tar.gz"} {
		if strings.Contains(reference, secret) {
			t.Fatalf("exact source reference leaked %q: %q", secret, reference)
		}
	}
	if reference != "exact-https#sha256-"+hex.EncodeToString(digest[:8]) {
		t.Fatalf("unexpected exact source reference %q", reference)
	}
}

func TestPublicAddressRejectsLocalAndPrivateRanges(t *testing.T) {
	for _, value := range []string{"127.0.0.1", "10.0.0.1", "192.168.1.1", "169.254.1.1", "100.64.0.1", "198.18.0.1", "203.0.113.10", "::1", "fe80::1", "2001:db8::1"} {
		address, err := netip.ParseAddr(value)
		if err != nil || publicAddress(address) {
			t.Fatalf("non-public address accepted: %s", value)
		}
	}
	address, _ := netip.ParseAddr("8.8.8.8")
	if !publicAddress(address) {
		t.Fatal("public address rejected")
	}
}

func TestRequestRejectsMissingOrUnexpectedContentType(t *testing.T) {
	publicKey, _, _ := ed25519.GenerateKey(rand.Reader)
	stager := &updatepkg.Stager{StateDir: t.TempDir(), Policy: updatepkg.VerificationPolicy{PublicKey: publicKey}}
	manager, err := New(DefaultRepository, "1.0.0", stager)
	if err != nil {
		t.Fatal(err)
	}
	manager.Client = &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader("{}")),
			Header: http.Header{"Content-Type": []string{"text/html"}}, Request: request,
		}, nil
	})}
	if _, err := manager.fetchBytes(context.Background(), "https://updates.example/channel-stable.json", 1024, "application/json"); err == nil {
		t.Fatal("unexpected remote update content type was accepted")
	}
}

func TestUseTransportPreservesTimeoutRedirectAndContentTypeGuards(t *testing.T) {
	publicKey, _, _ := ed25519.GenerateKey(rand.Reader)
	stager := &updatepkg.Stager{StateDir: t.TempDir(), Policy: updatepkg.VerificationPolicy{PublicKey: publicKey}}
	manager, err := New(DefaultRepository, "1.0.0", stager)
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.UseTransport(nil); err == nil {
		t.Fatal("nil service-route transport was accepted")
	}
	called := 0
	transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		called++
		return &http.Response{
			StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader("{}")),
			Header: http.Header{"Content-Type": []string{"text/html"}}, Request: request,
		}, nil
	})
	if err := manager.UseTransport(transport); err != nil {
		t.Fatal(err)
	}
	redirectGuard := manager.Client.CheckRedirect != nil
	if manager.Client.Timeout != 15*time.Minute || !redirectGuard {
		t.Fatalf("service transport weakened client guards: timeout=%s redirect_guard=%t", manager.Client.Timeout, redirectGuard)
	}
	credentialRequest, _ := http.NewRequest(http.MethodGet, "https://user:secret@updates.example/release.tar.gz", nil)
	if err := manager.Client.CheckRedirect(credentialRequest, nil); err == nil {
		t.Fatal("service transport redirect guard accepted URL credentials")
	}
	redirectRequest, _ := http.NewRequest(http.MethodGet, "https://updates.example/release.tar.gz", nil)
	if err := manager.Client.CheckRedirect(redirectRequest, make([]*http.Request, maximumRedirects)); err == nil {
		t.Fatal("service transport redirect guard accepted excessive redirect chain")
	}
	if _, err := manager.fetchBytes(context.Background(), "https://updates.example/channel-stable.json", 1024, "application/json"); err == nil || called != 1 {
		t.Fatalf("service transport bypassed content-type guard: called=%d error=%v", called, err)
	}
}

func releaseFixture(t *testing.T, transport staticTransport, privateKey ed25519.PrivateKey, channel, tag string, draft, prerelease bool, artifactSHA string) map[string]any {
	t.Helper()
	version := strings.TrimPrefix(tag, "v")
	artifactName := "gateway-vpn-gateway-" + version + "-linux-amd64.tar.gz"
	manifest := distribution.Manifest{
		FormatVersion: distribution.ChannelFormatVersion, Channel: channel, ReleaseVersion: version,
		GeneratedAt:  time.Date(2026, 8, 31, 1, 2, 3, 0, time.UTC).Format(time.RFC3339),
		SourceCommit: strings.Repeat("a", 40),
		Artifacts:    []distribution.Artifact{{Role: distribution.RoleGateway, OS: "linux", Arch: "amd64", Filename: artifactName, SHA256: artifactSHA, Bytes: 1234, MediaType: "application/gzip"}},
	}
	content, signature, err := distribution.SignManifest(manifest, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	root := "https://downloads.example/" + tag + "/"
	transport[root+"channel-"+channel+".json"] = content
	transport[root+"channel-"+channel+".sig"] = signature
	return map[string]any{
		"tag_name": tag, "draft": draft, "prerelease": prerelease,
		"published_at": "2026-08-31T01:02:03Z", "ignored_future_field": "safe",
		"assets": []map[string]any{
			{"name": "channel-" + channel + ".json", "size": len(content), "browser_download_url": root + "channel-" + channel + ".json", "ignored": true},
			{"name": "channel-" + channel + ".sig", "size": len(signature), "browser_download_url": root + "channel-" + channel + ".sig"},
			{"name": artifactName, "size": 1234, "browser_download_url": root + artifactName},
		},
	}
}
