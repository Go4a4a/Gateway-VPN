package bootstrapinstall

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"compress/gzip"

	"gateway-vpn/internal/distribution"
	updatepkg "gateway-vpn/internal/update"
	"gateway-vpn/internal/vpsrelease"
)

func TestDownloaderRequiresExactHashSizeAndAllowedOrigin(t *testing.T) {
	payload := []byte("immutable bootstrap payload")
	digest := sha256.Sum256(payload)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/data":
			writer.Write(payload)
		case "/encoded":
			writer.Header().Set("Content-Encoding", "gzip")
			writer.Write(payload)
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()
	downloader := testDownloader(t, server)
	destination := filepath.Join(t.TempDir(), "payload")
	result, err := downloader.Fetch(context.Background(), FetchRequest{
		URL: server.URL + "/data", Destination: destination, MaximumBytes: 1024,
		ExpectedBytes: int64(len(payload)), ExpectedSHA256: hex.EncodeToString(digest[:]),
	})
	if err != nil || result.Bytes != int64(len(payload)) || result.SHA256 != hex.EncodeToString(digest[:]) {
		t.Fatalf("Fetch() = %+v,%v", result, err)
	}
	wrong := filepath.Join(t.TempDir(), "wrong")
	if _, err := downloader.Fetch(context.Background(), FetchRequest{URL: server.URL + "/data", Destination: wrong, MaximumBytes: 1024, ExpectedSHA256: strings.Repeat("0", 64)}); err == nil {
		t.Fatal("wrong download hash was accepted")
	}
	if _, err := os.Lstat(wrong); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("hash-mismatched download was retained")
	}
	if _, err := downloader.Fetch(context.Background(), FetchRequest{URL: server.URL + "/encoded", Destination: filepath.Join(t.TempDir(), "encoded"), MaximumBytes: 1024}); err == nil {
		t.Fatal("encoded HTTP response was accepted")
	}
	if _, err := downloader.Fetch(context.Background(), FetchRequest{URL: "https://example.invalid/release", Destination: filepath.Join(t.TempDir(), "outside"), MaximumBytes: 1024}); err == nil {
		t.Fatal("non-allowlisted download origin was accepted")
	}
}

func TestProductionRemoteURLPolicyRejectsHTTPCredentialsQueryLiteralAndPort(t *testing.T) {
	allowed := map[string]bool{"github.com": true}
	for _, raw := range []string{
		"http://github.com/release",
		"https://user:pass@github.com/release",
		"https://github.com/release?token=secret",
		"https://127.0.0.1/release",
		"https://github.com:8443/release",
		"https://example.com/release",
	} {
		parsed, err := url.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		if err := validateRemoteURL(parsed, allowed, false, false); err == nil {
			t.Fatalf("unsafe remote URL accepted: %s", raw)
		}
	}
	parsed, _ := url.Parse("https://github.com/owner/repo/releases/download/v1.2.0/file")
	if err := validateRemoteURL(parsed, allowed, false, false); err != nil {
		t.Fatalf("valid GitHub URL rejected: %v", err)
	}
}

func TestProductionRedirectURLPolicyAllowsOnlyAssetSignedQueries(t *testing.T) {
	allowed := map[string]bool{
		"github.com":                           true,
		"objects.githubusercontent.com":        true,
		"release-assets.githubusercontent.com": true,
	}
	queryHosts := map[string]bool{
		"objects.githubusercontent.com":        true,
		"release-assets.githubusercontent.com": true,
	}
	for _, raw := range []string{
		"https://release-assets.githubusercontent.com/github-production-release-asset/file?sp=r&sig=signed",
		"https://objects.githubusercontent.com/github-production-release-asset/file?se=expiry&sig=signed",
	} {
		parsed, err := url.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		if err := validateRemoteURL(parsed, allowed, false, false); err == nil {
			t.Fatalf("caller-supplied signed-query URL accepted: %s", raw)
		}
		if err := validateRedirectURL(parsed, allowed, queryHosts, false); err != nil {
			t.Fatalf("valid GitHub asset redirect rejected: %s: %v", raw, err)
		}
	}
	for _, raw := range []string{
		"https://github.com/owner/repo/releases/download/v1.2.0/file?token=forbidden",
		"https://example.com/file?sig=forbidden",
		"https://user@release-assets.githubusercontent.com/file?sig=forbidden",
		"https://release-assets.githubusercontent.com:8443/file?sig=forbidden",
		"https://release-assets.githubusercontent.com/file?",
	} {
		parsed, err := url.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		if err := validateRedirectURL(parsed, allowed, queryHosts, false); err == nil {
			t.Fatalf("unsafe redirect URL accepted: %s", raw)
		}
	}
}

func TestBootstrapAuthenticatesChannelArchiveAndReleaseBeforeInstaller(t *testing.T) {
	fixture := newBootstrapFixture(t)
	defer fixture.server.Close()
	marker := filepath.Join(t.TempDir(), "candidate-executed")
	fixture.installerContent = []byte("#!/usr/bin/env bash\ntouch " + marker + "\n")
	fixture.rebuild(t)
	bootstrap := Bootstrap{Downloader: testDownloader(t, fixture.server), WorkRoot: t.TempDir()}
	prepared, err := bootstrap.Prepare(context.Background(), fixture.request())
	if err != nil {
		t.Fatal(err)
	}
	if prepared.Manifest.ReleaseVersion != fixture.version || prepared.Artifact.Role != distribution.RoleGateway || prepared.VerifiedRelease.Release.GatewayVersion != fixture.version || prepared.SignerKeySHA256 != fixture.fingerprint || prepared.ManifestSHA256 != fixture.manifestSHA256 {
		t.Fatalf("prepared bootstrap = %+v", prepared)
	}
	if _, err := os.Stat(marker); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("candidate installer executed during independent verification")
	}
	workDirectory := prepared.workDir
	if err := prepared.Cleanup(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(workDirectory); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("bootstrap work directory was not removed")
	}
}

func TestBootstrapRejectsArtifactTamperBeforeExtraction(t *testing.T) {
	fixture := newBootstrapFixture(t)
	defer fixture.server.Close()
	fixture.archive = append([]byte(nil), fixture.archive...)
	fixture.archive[len(fixture.archive)/2] ^= 0xff
	bootstrap := Bootstrap{Downloader: testDownloader(t, fixture.server), WorkRoot: t.TempDir()}
	if _, err := bootstrap.Prepare(context.Background(), fixture.request()); err == nil {
		t.Fatal("tampered role artifact was accepted")
	}
}

func TestGatewayInstallerRunsReadOnlyPreflightBeforeApplyWithTypedArguments(t *testing.T) {
	fixture := newBootstrapFixture(t)
	defer fixture.server.Close()
	bootstrap := Bootstrap{Downloader: testDownloader(t, fixture.server), WorkRoot: t.TempDir()}
	prepared, err := bootstrap.Prepare(context.Background(), fixture.request())
	if err != nil {
		t.Fatal(err)
	}
	defer prepared.Cleanup()
	runner := &recordingRunner{}
	result, err := (Installer{Runner: runner, Bash: "/usr/bin/bash"}).InstallGateway(context.Background(), prepared, GatewayOptions{
		LANInterface: "enp2s0", LANAddress: "192.168.200.1/24", InstallDependencies: true, EnableDHCP: true, DisableSSH: true, BootNetworkPolicy: "gateway-nonblocking", GRUBPolicy: "automatic-hidden", Apply: true,
	})
	if err != nil || result.Preflight != "PASSED" || result.Installation != "APPLIED" || len(runner.requests) != 2 {
		t.Fatalf("InstallGateway() = %+v,%v requests=%d", result, err, len(runner.requests))
	}
	first, second := runner.requests[0], runner.requests[1]
	if first.Executable != "/usr/bin/bash" || first.Directory != prepared.ReleaseRoot || contains(first.Arguments, "--apply") || !contains(first.Arguments, "--enable-dhcp") || !contains(first.Arguments, "--disable-ssh") || !contains(first.Arguments, "--install-dependencies") || !contains(first.Arguments, "--dependency-preflight-only") || !contains(first.Arguments, "enp2s0") || !contains(first.Arguments, "192.168.200.1/24") || !contains(first.Arguments, "gateway-nonblocking") || !contains(first.Arguments, "automatic-hidden") || !contains(second.Arguments, "--apply") || contains(second.Arguments, "--dependency-preflight-only") || strings.Join(first.Environment, "\n") != "PATH=/usr/sbin:/usr/bin:/sbin:/bin\nLANG=C.UTF-8\nLC_ALL=C.UTF-8" {
		t.Fatalf("installer requests = %+v", runner.requests)
	}
	runner = &recordingRunner{failAt: 1, failErr: CommandError{ExitCode: 10}}
	result, err = (Installer{Runner: runner, Bash: "/usr/bin/bash"}).InstallGateway(context.Background(), prepared, GatewayOptions{
		LANInterface: "enp2s0", LANAddress: "192.168.200.1/24", InstallDependencies: true, BootNetworkPolicy: "gateway-nonblocking", GRUBPolicy: "keep", Apply: true,
	})
	if err != nil || result.Preflight != "PASSED" || result.Installation != "APPLIED" || len(runner.requests) != 2 {
		t.Fatalf("Gateway APT index refresh continuation = %+v,%v requests=%+v", result, err, runner.requests)
	}
	runner = &recordingRunner{failAt: 1, failErr: CommandError{ExitCode: 20}}
	if _, err := (Installer{Runner: runner, Bash: "/usr/bin/bash"}).InstallGateway(context.Background(), prepared, GatewayOptions{
		LANInterface: "enp2s0", LANAddress: "192.168.200.1/24", InstallDependencies: true, BootNetworkPolicy: "gateway-nonblocking", GRUBPolicy: "keep", Apply: true,
	}); err == nil || len(runner.requests) != 1 {
		t.Fatalf("unsafe Gateway APT plan reached apply: requests=%+v err=%v", runner.requests, err)
	}
	runner = &recordingRunner{failAt: 1, failErr: CommandError{ExitCode: 10}}
	result, err = (Installer{Runner: runner, Bash: "/usr/bin/bash"}).InstallGateway(context.Background(), prepared, GatewayOptions{
		LANInterface: "enp2s0", LANAddress: "192.168.200.1/24", InstallDependencies: true, BootNetworkPolicy: "gateway-nonblocking", GRUBPolicy: "keep", DependencyPreflightOnly: true,
	})
	if err != nil || result.Preflight != "DEPENDENCY_GATE_PASSED_OR_REFRESH_REQUIRED" || result.Installation != "NOT_REQUESTED" || len(runner.requests) != 1 || !contains(runner.requests[0].Arguments, "--dependency-preflight-only") {
		t.Fatalf("orchestrated Gateway dependency gate = %+v,%v requests=%+v", result, err, runner.requests)
	}
	runner = &recordingRunner{failAt: 1}
	if _, err := (Installer{Runner: runner, Bash: "/usr/bin/bash"}).InstallGateway(context.Background(), prepared, GatewayOptions{LANInterface: "enp2s0", LANAddress: "192.168.200.1/24", BootNetworkPolicy: "gateway-nonblocking", GRUBPolicy: "keep", Apply: true}); err == nil || len(runner.requests) != 1 {
		t.Fatalf("failed preflight did not stop apply: requests=%d err=%v", len(runner.requests), err)
	}
	runner = &recordingRunner{}
	if _, err := (Installer{Runner: runner, Bash: "/usr/bin/bash"}).InstallGateway(context.Background(), prepared, GatewayOptions{
		LANInterface: "gateway-vpn-lan", LANMembers: []string{"enp2s0", "enp3s0"}, LANAddress: "192.168.200.1/24", BootNetworkPolicy: "gateway-nonblocking", GRUBPolicy: "keep",
	}); err != nil || len(runner.requests) != 1 || !contains(runner.requests[0].Arguments, "--lan-members") || !contains(runner.requests[0].Arguments, "enp2s0,enp3s0") {
		t.Fatalf("multi-port Gateway arguments = %+v, %v", runner.requests, err)
	}
	if _, err := (Installer{Runner: &recordingRunner{}, Bash: "/usr/bin/bash"}).InstallGateway(context.Background(), prepared, GatewayOptions{
		LANInterface: "enp2s0", LANMembers: []string{"enp2s0", "enp3s0"}, LANAddress: "192.168.200.1/24",
	}); err == nil {
		t.Fatal("LAN bridge members were accepted with a physical LAN interface")
	}
	if _, err := (Installer{Runner: &recordingRunner{}, Bash: "/usr/bin/bash"}).InstallGateway(context.Background(), prepared, GatewayOptions{LANInterface: "../../bad", LANAddress: "192.168.200.1/24"}); err == nil {
		t.Fatal("unsafe LAN interface was accepted")
	}
	if _, err := (Installer{Runner: &recordingRunner{}, Bash: "/usr/bin/bash"}).InstallGateway(context.Background(), prepared, GatewayOptions{LANInterface: "enp2s0", LANAddress: "8.8.8.8/24"}); err == nil {
		t.Fatal("public Gateway LAN was accepted")
	}
}

func TestVPSBootstrapAuthenticatesRoleAndRunsTypedInstaller(t *testing.T) {
	fixture := newVPSBootstrapFixture(t)
	defer fixture.server.Close()
	bootstrap := Bootstrap{Downloader: testDownloader(t, fixture.server), WorkRoot: t.TempDir()}
	prepared, err := bootstrap.Prepare(context.Background(), fixture.request())
	if err != nil {
		t.Fatal(err)
	}
	defer prepared.Cleanup()
	if prepared.VerifiedVPS.Release.Role != "vps" || prepared.VerifiedVPS.Release.Version != fixture.version || prepared.Artifact.Role != distribution.RoleVPS {
		t.Fatalf("prepared VPS bootstrap = %+v", prepared)
	}
	gatewayKey := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))
	adminKey := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{2}, 32))
	runner := &recordingRunner{}
	result, err := (Installer{Runner: runner, Bash: "/usr/bin/bash"}).InstallVPS(context.Background(), prepared, VPSOptions{
		PublicEndpoint: "1.1.1.1:51821", GatewayPublicKey: gatewayKey, AdminPublicKey: adminKey,
		InstallDependencies: true, AllowGatewaySSH: true, Apply: true,
	})
	if err != nil || result.Role != distribution.RoleVPS || result.Preflight != "PASSED" || result.Installation != "APPLIED" || len(runner.requests) != 2 {
		t.Fatalf("InstallVPS() = %+v,%v requests=%d", result, err, len(runner.requests))
	}
	first, second := runner.requests[0], runner.requests[1]
	for _, required := range []string{"--public-endpoint", "1.1.1.1:51821", "--gateway-public-key", gatewayKey, "--admin-public-key", adminKey, "--allow-gateway-ssh", "--install-dependencies", "--dependency-preflight-only"} {
		if !contains(first.Arguments, required) {
			t.Errorf("VPS preflight arguments missing %q", required)
		}
	}
	if contains(first.Arguments, "--apply") || !contains(second.Arguments, "--apply") || contains(second.Arguments, "--dependency-preflight-only") || !contains(second.Arguments, "--install-dependencies") {
		t.Fatal("VPS apply was not separated from read-only preflight")
	}
	runner = &recordingRunner{failAt: 1, failErr: CommandError{ExitCode: 10}}
	result, err = (Installer{Runner: runner, Bash: "/usr/bin/bash"}).InstallVPS(context.Background(), prepared, VPSOptions{
		PublicEndpoint: "1.1.1.1:51821", GatewayPublicKey: gatewayKey, AdminPublicKey: adminKey,
		InstallDependencies: true, Apply: true,
	})
	if err != nil || result.Preflight != "PASSED" || result.Installation != "APPLIED" || len(runner.requests) != 2 {
		t.Fatalf("APT index refresh continuation = %+v,%v requests=%+v", result, err, runner.requests)
	}
	runner = &recordingRunner{failAt: 1, failErr: CommandError{ExitCode: 20}}
	if _, err := (Installer{Runner: runner, Bash: "/usr/bin/bash"}).InstallVPS(context.Background(), prepared, VPSOptions{
		PublicEndpoint: "1.1.1.1:51821", GatewayPublicKey: gatewayKey, AdminPublicKey: adminKey,
		InstallDependencies: true, Apply: true,
	}); err == nil || len(runner.requests) != 1 {
		t.Fatalf("unsafe APT plan was allowed to reach apply: requests=%+v err=%v", runner.requests, err)
	}
	runner = &recordingRunner{failAt: 1, failErr: CommandError{ExitCode: 10}}
	result, err = (Installer{Runner: runner, Bash: "/usr/bin/bash"}).InstallVPS(context.Background(), prepared, VPSOptions{
		PublicEndpoint: "1.1.1.1:51821", GatewayPublicKey: gatewayKey, AdminPublicKey: adminKey,
		InstallDependencies: true, DependencyPreflightOnly: true,
	})
	if err != nil || result.Preflight != "DEPENDENCY_GATE_PASSED_OR_REFRESH_REQUIRED" || result.Installation != "NOT_REQUESTED" || len(runner.requests) != 1 || !contains(runner.requests[0].Arguments, "--dependency-preflight-only") {
		t.Fatalf("orchestrated VPS dependency gate = %+v,%v requests=%+v", result, err, runner.requests)
	}
	runner = &recordingRunner{}
	result, err = (Installer{Runner: runner, Bash: "/usr/bin/bash"}).InstallVPS(context.Background(), prepared, VPSOptions{
		PublicEndpoint: "1.1.1.1:51821", GatewayPublicKey: gatewayKey, AdminPublicKey: adminKey, InstallDependencies: true,
	})
	if err != nil || result.Preflight != "DEPENDENCY_PLAN_VALIDATED" || result.Installation != "NOT_REQUESTED" || len(runner.requests) != 1 || contains(runner.requests[0].Arguments, "--dependency-preflight-only") {
		t.Fatalf("dependency-only VPS preflight = %+v,%v requests=%+v", result, err, runner.requests)
	}
	runner = &recordingRunner{failAt: 1}
	if _, err := (Installer{Runner: runner, Bash: "/usr/bin/bash"}).InstallVPS(context.Background(), prepared, VPSOptions{
		PublicEndpoint: "1.1.1.1:51821", GatewayPublicKey: gatewayKey, AdminPublicKey: adminKey,
		InstallDependencies: true, Apply: true,
	}); err == nil || len(runner.requests) != 1 || !contains(runner.requests[0].Arguments, "--dependency-preflight-only") {
		t.Fatalf("failed VPS dependency preflight did not stop apply: requests=%+v err=%v", runner.requests, err)
	}
	if _, err := (Installer{Runner: &recordingRunner{}, Bash: "/usr/bin/bash"}).InstallVPS(context.Background(), prepared, VPSOptions{PublicEndpoint: "127.0.0.1:51821", GatewayPublicKey: gatewayKey, AdminPublicKey: adminKey}); err == nil {
		t.Fatal("unsafe VPS endpoint was accepted")
	}
}

type recordingRunner struct {
	requests []CommandRequest
	failAt   int
	failErr  error
}

func (runner *recordingRunner) Run(_ context.Context, request CommandRequest) error {
	runner.requests = append(runner.requests, request)
	if runner.failAt > 0 && len(runner.requests) == runner.failAt {
		if runner.failErr != nil {
			return runner.failErr
		}
		return errors.New("synthetic command failure")
	}
	return nil
}

type bootstrapFixture struct {
	server            *httptest.Server
	privateKey        ed25519.PrivateKey
	publicKeyPEM      []byte
	fingerprint       string
	version           string
	commit            string
	installerContent  []byte
	archive           []byte
	manifestContent   []byte
	manifestSignature []byte
	manifestSHA256    string
}

type vpsBootstrapFixture struct {
	server            *httptest.Server
	privateKey        ed25519.PrivateKey
	publicKeyPEM      []byte
	fingerprint       string
	version           string
	commit            string
	archive           []byte
	manifestContent   []byte
	manifestSignature []byte
	manifestSHA256    string
}

func newBootstrapFixture(t *testing.T) *bootstrapFixture {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publicDER, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, _ := updatepkg.PublicKeyFingerprint(publicKey)
	fixture := &bootstrapFixture{
		privateKey: privateKey, publicKeyPEM: pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER}), fingerprint: fingerprint,
		version: "1.2.0", commit: strings.Repeat("a", 40), installerContent: []byte("#!/usr/bin/env bash\nexit 0\n"),
	}
	fixture.server = httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		var content []byte
		switch request.URL.Path {
		case "/channel-stable.json":
			content = fixture.manifestContent
		case "/channel-stable.sig":
			content = fixture.manifestSignature
		case "/update-signing.pub":
			content = fixture.publicKeyPEM
		case "/gateway-vpn-gateway-1.2.0-linux-amd64.tar.gz":
			content = fixture.archive
		default:
			http.NotFound(writer, request)
			return
		}
		writer.Header().Set("Content-Length", fmtInt(len(content)))
		writer.Write(content)
	}))
	fixture.rebuild(t)
	return fixture
}

func newVPSBootstrapFixture(t *testing.T) *vpsBootstrapFixture {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publicDER, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, _ := updatepkg.PublicKeyFingerprint(publicKey)
	fixture := &vpsBootstrapFixture{
		privateKey: privateKey, publicKeyPEM: pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER}),
		fingerprint: fingerprint, version: "1.2.0", commit: strings.Repeat("b", 40),
	}
	releaseRoot := t.TempDir()
	for relative, content := range map[string][]byte{
		"bin/gateway-vpnctl":                                                []byte("synthetic VPS controller"),
		"scripts/install-vps.sh":                                            []byte("#!/usr/bin/env bash\nexit 0\n"),
		"scripts/uninstall-vps.sh":                                          []byte("#!/usr/bin/env bash\nexit 0\n"),
		"scripts/recover-vps-install.sh":                                    []byte("#!/usr/bin/env bash\nexit 0\n"),
		"packaging/vps/nftables/gateway-vpn-vps.nft.in":                     []byte("table inet gateway_vpn_vps {}\n"),
		"packaging/vps/sysctl.d/90-gateway-vpn-vps.conf":                    []byte("net.ipv4.ip_forward=1\n"),
		"packaging/vps/systemd/gateway-vpn-vps-firewall.service":            []byte("[Service]\nType=oneshot\n"),
		"packaging/vps/systemd/gateway-vpn-vps-install-recovery.service":    []byte("[Service]\nType=oneshot\n"),
		"packaging/vps/systemd/wg-quick@wg-mgmt.service.d/gateway-vpn.conf": []byte("[Unit]\nAfter=gateway-vpn-vps-firewall.service\n"),
		"manifest.sha256":                                                   []byte(strings.Repeat("0", 64) + "  placeholder\n"),
		"share/supply-chain/sbom.spdx.json":                                 []byte("{}\n"),
		"share/supply-chain/provenance.intoto.json":                         []byte("{}\n"),
	} {
		writeFixtureFile(t, releaseRoot, relative, content)
	}
	release := vpsrelease.Release{
		FormatVersion: vpsrelease.ReleaseFormatVersion, Role: "vps", Version: fixture.version,
		OS: "linux", Arch: "amd64", SourceCommit: fixture.commit, BuildDate: "2026-08-25T00:00:00Z",
		SupportedProfiles: vpsrelease.SupportedProfiles(), InterfaceName: "wg-mgmt", ManagementSubnet: "10.80.0.0/24", ListenPort: 51821,
	}
	releaseJSON, _ := json.MarshalIndent(release, "", "  ")
	writeFixtureFile(t, releaseRoot, "release.json", append(releaseJSON, '\n'))
	if _, err := vpsrelease.SignRelease(releaseRoot, fixture.privateKey); err != nil {
		t.Fatal(err)
	}
	fixture.archive = archiveFixture(t, releaseRoot)
	archiveDigest := sha256.Sum256(fixture.archive)
	manifest := distribution.Manifest{
		FormatVersion: distribution.ChannelFormatVersion, Channel: "stable", ReleaseVersion: fixture.version,
		GeneratedAt: "2026-08-25T00:00:00Z", SourceCommit: fixture.commit,
		Artifacts: []distribution.Artifact{{
			Role: distribution.RoleVPS, OS: "linux", Arch: "amd64",
			Filename: "gateway-vpn-vps-1.2.0-linux-amd64.tar.gz", SHA256: hex.EncodeToString(archiveDigest[:]), Bytes: int64(len(fixture.archive)), MediaType: "application/gzip",
		}},
	}
	content, signature, err := distribution.SignManifest(manifest, fixture.privateKey)
	if err != nil {
		t.Fatal(err)
	}
	fixture.manifestContent, fixture.manifestSignature = content, signature
	fixture.manifestSHA256, _ = distribution.ManifestSHA256(content)
	fixture.server = httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		var content []byte
		switch request.URL.Path {
		case "/channel-stable.json":
			content = fixture.manifestContent
		case "/channel-stable.sig":
			content = fixture.manifestSignature
		case "/update-signing.pub":
			content = fixture.publicKeyPEM
		case "/gateway-vpn-vps-1.2.0-linux-amd64.tar.gz":
			content = fixture.archive
		default:
			http.NotFound(writer, request)
			return
		}
		writer.Header().Set("Content-Length", fmtInt(len(content)))
		writer.Write(content)
	}))
	return fixture
}

func (fixture *bootstrapFixture) rebuild(t *testing.T) {
	t.Helper()
	releaseRoot := t.TempDir()
	writeFixtureFile(t, releaseRoot, "bin/gateway-vpn", []byte("synthetic gateway binary"))
	writeFixtureFile(t, releaseRoot, "bin/gateway-vpnctl", []byte("synthetic controller binary"))
	mihomo := []byte("synthetic mihomo binary v1.19.10")
	writeFixtureFile(t, releaseRoot, "libexec/mihomo", mihomo)
	writeFixtureFile(t, releaseRoot, "scripts/install-gateway.sh", fixture.installerContent)
	writeFixtureFile(t, releaseRoot, "scripts/recover-gateway-install.sh", []byte("#!/usr/bin/env bash\nexit 0\n"))
	writeFixtureFile(t, releaseRoot, "manifest.sha256", []byte(strings.Repeat("0", 64)+"  placeholder\n"))
	writeFixtureFile(t, releaseRoot, "share/supply-chain/sbom.spdx.json", []byte("{}\n"))
	writeFixtureFile(t, releaseRoot, "share/supply-chain/provenance.intoto.json", []byte("{}\n"))
	for _, name := range []string{
		"gateway-vpn.service", "gateway-vpn-watchdog.service", "gateway-vpn-firewall.service",
		"gateway-vpn-firewall-guard.service", "gateway-vpn-network-broker.socket",
		"gateway-vpn-power-cycle@.service",
		"gateway-vpn-update.service", "gateway-vpn-update-recovery.service", "gateway-vpn-update-resume.service",
		"gateway-vpn-update-finalize.service", "gateway-vpn-update-finalize.timer",
	} {
		writeFixtureFile(t, releaseRoot, "packaging/systemd/"+name, []byte("[Unit]\nDescription=synthetic lifecycle unit\n"))
	}
	for relative, content := range map[string][]byte{
		"packaging/dnsmasq/dnsmasq.conf.in":                               []byte("interface=synthetic\n"),
		"packaging/grub/90-gateway-vpn-automatic.cfg":                     []byte("GRUB_TIMEOUT=1\n"),
		"packaging/grub/90-gateway-vpn-menu.cfg":                          []byte("GRUB_TIMEOUT=5\n"),
		"packaging/journald/gateway-vpn.conf":                             []byte("[Journal]\nStorage=persistent\n"),
		"packaging/nftables/boot.nft.in":                                  []byte("table inet gateway_vpn {}\n"),
		"packaging/sysctl.d/90-gateway-vpn-ipv4-forwarding.conf":          []byte("net.ipv4.ip_forward=1\n"),
		"packaging/sysctl.d/90-gateway-vpn-ipv6.conf":                     []byte("net.ipv6.conf.all.disable_ipv6=1\n"),
		"packaging/systemd-networkd/05-gateway-vpn-lan.netdev":            []byte("[NetDev]\nName=gateway-vpn-lan\n"),
		"packaging/systemd-networkd/05-gateway-vpn-lan.network.in":        []byte("[Match]\nName=__LAN_INTERFACE__\n"),
		"packaging/systemd-networkd/06-gateway-vpn-lan-member.network.in": []byte("[Match]\nName=__LAN_MEMBER__\n"),
		"packaging/systemd-networkd/80-gateway-vpn-hilink.network":        []byte("[Match]\nType=ether\n"),
		"packaging/systemd-wait-online/gateway-vpn.conf":                  []byte("[Service]\nExecStart=/usr/bin/true\n"),
		"packaging/sysusers.d/gateway-vpn.conf":                           []byte("u gateway-vpn - - - -\n"),
		"packaging/tmpfiles.d/gateway-vpn.conf":                           []byte("d /run/gateway-vpn 0750 root root -\n"),
	} {
		writeFixtureFile(t, releaseRoot, relative, content)
	}
	mihomoDigest := sha256.Sum256(mihomo)
	hostContract, err := updatepkg.ComputeHostContractSHA256(releaseRoot)
	if err != nil {
		t.Fatal(err)
	}
	release := updatepkg.Release{
		FormatVersion: updatepkg.ReleaseFormatVersion, GatewayVersion: fixture.version, MihomoVersion: "v1.19.10",
		OS: "linux", Arch: "amd64", MihomoSHA256: hex.EncodeToString(mihomoDigest[:]),
		DatabaseSchemaMinimum: 1, DatabaseSchemaMaximum: 11, ConfigSchemaGeneration: 1,
		HostContractSHA256: hostContract,
		GatewayAPIContract: updatepkg.GatewayAPIContract, MihomoAPIContract: updatepkg.MihomoAPIContract,
		BuildCommit: fixture.commit, BuildDate: "2026-08-25T00:00:00Z",
	}
	releaseJSON, _ := json.MarshalIndent(release, "", "  ")
	writeFixtureFile(t, releaseRoot, "release.json", append(releaseJSON, '\n'))
	if _, err := updatepkg.SignRelease(releaseRoot, fixture.privateKey); err != nil {
		t.Fatal(err)
	}
	fixture.archive = archiveFixture(t, releaseRoot)
	archiveDigest := sha256.Sum256(fixture.archive)
	manifest := distribution.Manifest{
		FormatVersion: distribution.ChannelFormatVersion, Channel: "stable", ReleaseVersion: fixture.version,
		GeneratedAt: "2026-08-25T00:00:00Z", SourceCommit: fixture.commit,
		Artifacts: []distribution.Artifact{{
			Role: distribution.RoleGateway, OS: "linux", Arch: "amd64",
			Filename: "gateway-vpn-gateway-1.2.0-linux-amd64.tar.gz", SHA256: hex.EncodeToString(archiveDigest[:]), Bytes: int64(len(fixture.archive)), MediaType: "application/gzip",
		}},
	}
	content, signature, err := distribution.SignManifest(manifest, fixture.privateKey)
	if err != nil {
		t.Fatal(err)
	}
	fixture.manifestContent, fixture.manifestSignature = content, signature
	fixture.manifestSHA256, _ = distribution.ManifestSHA256(content)
}

func (fixture *bootstrapFixture) request() Request {
	return Request{
		Role: distribution.RoleGateway, Channel: "stable", Version: fixture.version, SourceCommit: fixture.commit,
		ManifestURL: fixture.server.URL + "/channel-stable.json", ManifestSHA256: fixture.manifestSHA256,
		SignatureURL: fixture.server.URL + "/channel-stable.sig", PublicKeyURL: fixture.server.URL + "/update-signing.pub",
		SignerKeySHA256: fixture.fingerprint, ArtifactBaseURL: fixture.server.URL + "/",
		OperatingSystem: "linux", Architecture: "amd64",
	}
}

func (fixture *vpsBootstrapFixture) request() Request {
	return Request{
		Role: distribution.RoleVPS, Channel: "stable", Version: fixture.version, SourceCommit: fixture.commit,
		ManifestURL: fixture.server.URL + "/channel-stable.json", ManifestSHA256: fixture.manifestSHA256,
		SignatureURL: fixture.server.URL + "/channel-stable.sig", PublicKeyURL: fixture.server.URL + "/update-signing.pub",
		SignerKeySHA256: fixture.fingerprint, ArtifactBaseURL: fixture.server.URL + "/",
		OperatingSystem: "linux", Architecture: "amd64",
	}
}

func testDownloader(t *testing.T, server *httptest.Server) Downloader {
	t.Helper()
	parsed, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	return Downloader{Client: server.Client(), AllowedHosts: map[string]bool{parsed.Hostname(): true}, AllowHTTPTest: true}
}

func writeFixtureFile(t *testing.T, root, relative string, content []byte) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(relative))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	mode := os.FileMode(0o644)
	if strings.HasPrefix(relative, "bin/") || relative == "libexec/mihomo" || strings.HasPrefix(relative, "scripts/") {
		mode = 0o755
	}
	if err := os.WriteFile(path, content, mode); err != nil {
		t.Fatal(err)
	}
}

func archiveFixture(t *testing.T, root string) []byte {
	t.Helper()
	var output bytes.Buffer
	gzipWriter := gzip.NewWriter(&output)
	tarWriter := tar.NewWriter(gzipWriter)
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == root {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		header, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return err
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		header.Name = filepath.ToSlash(relative)
		if entry.IsDir() {
			header.Name += "/"
		}
		if err := tarWriter.WriteHeader(header); err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		file, err := os.Open(path)
		if err != nil {
			return err
		}
		_, copyErr := io.Copy(tarWriter, file)
		closeErr := file.Close()
		if copyErr != nil {
			return copyErr
		}
		return closeErr
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := tarWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gzipWriter.Close(); err != nil {
		t.Fatal(err)
	}
	return output.Bytes()
}

func contains(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}

func fmtInt(value int) string {
	if value == 0 {
		return "0"
	}
	buffer := make([]byte, 0, 20)
	for value > 0 {
		buffer = append(buffer, byte('0'+value%10))
		value /= 10
	}
	for left, right := 0, len(buffer)-1; left < right; left, right = left+1, right-1 {
		buffer[left], buffer[right] = buffer[right], buffer[left]
	}
	return string(buffer)
}
