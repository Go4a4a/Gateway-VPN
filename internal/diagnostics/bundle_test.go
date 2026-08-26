package diagnostics

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gateway-vpn/internal/bypass"
	"gateway-vpn/internal/config"
	databasepkg "gateway-vpn/internal/db"
	loggingpkg "gateway-vpn/internal/logging"
	"gateway-vpn/internal/modem"
	"gateway-vpn/internal/state"
	"gateway-vpn/internal/subscription"
	wireguardpkg "gateway-vpn/internal/wireguard"
)

type fakeHostProvider struct {
	snapshot HostSnapshot
	err      error
}

func (provider fakeHostProvider) Collect(context.Context) (HostSnapshot, error) {
	return provider.snapshot, provider.err
}

type fakeJournalProvider struct {
	pages []loggingpkg.JournalPage
	err   error
	calls int
}

func (provider *fakeJournalProvider) QueryLogs(_ context.Context, query loggingpkg.JournalQuery) (loggingpkg.JournalPage, error) {
	if query.Limit != loggingpkg.MaximumJournalPageSize || query.Since == "" || query.Until == "" {
		return loggingpkg.JournalPage{}, errors.New("unexpected diagnostic journal query")
	}
	provider.calls++
	if provider.err != nil {
		return loggingpkg.JournalPage{}, provider.err
	}
	if len(provider.pages) == 0 {
		return loggingpkg.JournalPage{Items: []loggingpkg.JournalEntry{}}, nil
	}
	page := provider.pages[0]
	provider.pages = provider.pages[1:]
	return page, nil
}

func TestDiagnosticBundleContainsManifestRequiredSectionsAndNoSecrets(t *testing.T) {
	ctx, database := diagnosticDatabase(t)
	configuration := config.Default()
	modems := modem.NewRepository(database, configuration.Modems.RoutingTableStart, configuration.Modems.FwmarkStart)
	digest := sha256.Sum256([]byte("identity-super-secret"))
	if _, err := modems.Adopt(ctx, modem.AdoptInput{ID: "modem-a", Name: "Primary LTE", OperatorLabel: "Operator", IdentityKind: "usb_serial_hash", IdentityHash: hex.EncodeToString(digest[:]), MaskedSerial: "***1234"}); err != nil {
		t.Fatal(err)
	}
	if _, err := modems.ApplyLease(ctx, "modem-a", modem.LeaseInput{InterfaceName: "enxmodem", ManagementCIDR: "192.168.8.0/24", Gateway: "192.168.8.1", DNS: []string{"1.1.1.1"}, MTU: 1500, State: modem.StateReady}); err != nil {
		t.Fatal(err)
	}
	subscriptions := subscription.NewRepository(database)
	created, err := subscriptions.Create(ctx, subscription.CreateInput{ID: "sub-a", Name: "Whitelist subscription", SourceType: "url", SourceSecretRef: "/var/lib/source-secret-ref", RefreshInterval: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	versions := subscription.NewVersionRepository(database)
	proxyCredential := "11111111-1111-1111-1111-111111111111"
	staged, err := versions.Stage(ctx, subscription.StageInput{VersionID: "version-a", SubscriptionID: created.ID, Payload: []byte("vless://" + proxyCredential + "@proxy.example:443#LTE-node")})
	if err != nil {
		t.Fatal(err)
	}
	if err := versions.Activate(ctx, staged.Version.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := bypass.NewRepository(database).Create(ctx, bypass.CreateInput{ID: "target-a", Name: "Required target", Kind: bypass.KindURL, Value: "https://example.com/private?token=target-secret", Required: true, Timeout: 5 * time.Second, SuccessMode: bypass.SuccessExpectedBody, ExpectedBodySubstring: "body-secret"}); err != nil {
		t.Fatal(err)
	}
	if err := state.NewRepository(database).AppendEvent(ctx, state.EventInput{Severity: "ERROR", Type: "TEST_SECRET_EVENT", Details: map[string]any{"password": "event-password", "url": "https://event.example/private?token=event-token", "safe": "visible"}}); err != nil {
		t.Fatal(err)
	}
	if err := (wireguardpkg.RuntimeStore{Database: database}).Put(ctx, wireguardpkg.RuntimeState{CurrentModemID: "modem-a", LastHandshakeAt: "2026-08-24T17:59:00Z", ConfigSHA256: strings.Repeat("b", 64)}, time.Now()); err != nil {
		t.Fatal(err)
	}
	mihomoRoot := filepath.Join(t.TempDir(), "mihomo")
	if err := os.MkdirAll(filepath.Join(mihomoRoot, "state"), 0o700); err != nil {
		t.Fatal(err)
	}
	for name, value := range map[string]string{"active-generation": "active-1\n", "lkg-generation": "lkg-1\n"} {
		if err := os.WriteFile(filepath.Join(mihomoRoot, "state", name), []byte(value), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	now := time.Date(2026, 8, 24, 18, 0, 0, 0, time.UTC)
	host := HostSnapshot{
		SchemaVersion: HostSnapshotSchemaVersion, CollectedAt: now.Format(time.RFC3339Nano),
		OS: OperatingSystem{ID: "ubuntu", VersionID: "24.04", PrettyName: "Ubuntu 24.04 LTS"}, Kernel: "6.8.0",
		Interfaces:  []InterfaceSummary{{Name: "enp2s0", State: "UP", MTU: 1500, Addresses: []InterfaceAddress{{Family: "inet", Local: "192.168.200.1", PrefixLen: 24}}}},
		OwnedRoutes: []byte(`[{"protocol":186,"table":1101}]`), OwnedRules: []byte(`[{"protocol":186,"table":1101}]`),
		Nftables:      []byte(`{"nftables":[{"counter":{"packets":10,"bytes":2048},"comment":"password=host-nft-secret"}]}`),
		WireGuard:     WireGuardSummary{Available: true, ListenPort: 51821, Peers: []WireGuardPeerSummary{{Index: 1, Endpoint: "203.0.113.50:51821", LatestHandshakeAt: "2026-08-24T17:59:00Z"}}},
		MihomoVersion: "Mihomo Meta test token=host-version-secret", SectionErrors: []SectionError{},
	}
	journal := &fakeJournalProvider{pages: []loggingpkg.JournalPage{{Items: []loggingpkg.JournalEntry{{Cursor: "s=one", OccurredAt: now.Format(time.RFC3339Nano), Severity: loggingpkg.LevelError, Component: loggingpkg.ComponentSystem, Unit: "gateway-vpn.service", Message: "password=journal-secret URL https://journal.example/private?token=journal-token"}}}}}
	builder := Builder{
		Database: database, Configuration: configuration, Host: fakeHostProvider{snapshot: host}, Journal: journal,
		GatewayVersion: "gateway-vpn test", ExpectedMihomoVersion: "test", TLSFingerprint: strings.Repeat("a", 64),
		MihomoRoot: mihomoRoot, Now: func() time.Time { return now },
	}
	bundle, err := builder.Build(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if bundle.Filename != "gateway-vpn-diagnostics-20260824T180000Z.zip" || len(bundle.Content) == 0 || len(bundle.Content) > MaximumBundleBytes || !bundle.Manifest.Complete || bundle.Manifest.SecretsIncluded {
		t.Fatalf("bundle metadata = %+v bytes=%d", bundle, len(bundle.Content))
	}
	archiveFiles, modes, total := unzipBundle(t, bundle.Content)
	if total != bundle.UncompressedSize {
		t.Fatalf("uncompressed size = %d, want %d", bundle.UncompressedSize, total)
	}
	for _, name := range []string{
		"manifest.json", "meta.json", "config/sanitized.json", "runtime/gateway-state.json",
		"runtime/modems.json", "runtime/subscriptions.json", "runtime/path-matrix.json", "runtime/nodes.json",
		"runtime/probe-targets.json", "runtime/mihomo-sanitized.json", "runtime/wireguard.json",
		"host/snapshot.json", "events/events.jsonl", "logs/journal.jsonl", "database/integrity.json", "database/retention.json",
	} {
		if _, exists := archiveFiles[name]; !exists {
			t.Fatalf("archive is missing %s", name)
		}
		if modes[name] != 0o600 {
			t.Fatalf("archive mode for %s = %o", name, modes[name])
		}
	}
	var manifest Manifest
	if err := json.Unmarshal(archiveFiles["manifest.json"], &manifest); err != nil {
		t.Fatal(err)
	}
	if !manifest.Complete || manifest.SecretsIncluded || len(manifest.SectionErrors) != 0 || manifest.PayloadUncompressedSize <= 0 {
		t.Fatalf("manifest = %+v", manifest)
	}
	var payloadBytes int64
	for _, item := range manifest.Files {
		content, exists := archiveFiles[item.Path]
		if !exists || int64(len(content)) != item.Bytes {
			t.Fatalf("manifest file %s size mismatch", item.Path)
		}
		digest := sha256.Sum256(content)
		if hex.EncodeToString(digest[:]) != item.SHA256 {
			t.Fatalf("manifest file %s digest mismatch", item.Path)
		}
		payloadBytes += item.Bytes
	}
	if payloadBytes != manifest.PayloadUncompressedSize {
		t.Fatalf("manifest payload bytes = %d, want %d", manifest.PayloadUncompressedSize, payloadBytes)
	}
	archiveDigest := sha256.Sum256(bundle.Content)
	if bundle.SHA256 != hex.EncodeToString(archiveDigest[:]) {
		t.Fatal("bundle SHA-256 mismatch")
	}
	combined := ""
	for _, content := range archiveFiles {
		combined += string(content)
	}
	for _, forbidden := range []string{"identity-super-secret", hex.EncodeToString(digest[:]), "/var/lib/source-secret-ref", proxyCredential, "target-secret", "body-secret", "event-password", "event-token", "journal-secret", "journal-token", "host-nft-secret", "host-version-secret", "203.0.113.50", "api-secret-file", "private_key"} {
		if strings.Contains(combined, forbidden) {
			t.Fatalf("diagnostic bundle leaked %q", forbidden)
		}
	}
	for _, expected := range []string{"***1234", "Whitelist subscription", "visible", "https://event.example/", "https://journal.example/", `"integrity_check": "PASS"`, `"schema_version": 11`, `"health_days": 7`, `"traffic_months": 24`} {
		if !strings.Contains(combined, expected) {
			t.Fatalf("diagnostic bundle missing %q", expected)
		}
	}
	description, err := builder.Describe(ctx)
	if err != nil || !description.Available || description.SecretsIncluded || description.ConfiguredJournalExcerptBytes != 1<<20 {
		t.Fatalf("Describe() = %+v, %v", description, err)
	}
}

func TestDiagnosticBundleSurvivesUnavailableHostAndJournalWithStableCodes(t *testing.T) {
	ctx, database := diagnosticDatabase(t)
	mihomoRoot := filepath.Join(t.TempDir(), "mihomo")
	journal := &fakeJournalProvider{err: errors.New("private journal token=secret")}
	builder := Builder{
		Database: database, Configuration: config.Default(), Host: fakeHostProvider{err: errors.New("private root output /root/secret")}, Journal: journal,
		GatewayVersion: "test", MihomoRoot: mihomoRoot,
	}
	bundle, err := builder.Build(ctx)
	if err != nil {
		t.Fatal(err)
	}
	files, _, _ := unzipBundle(t, bundle.Content)
	if bundle.Manifest.Complete || len(bundle.Manifest.SectionErrors) < 2 || !bytes.Contains(files["host/snapshot.json"], []byte("HOST_DIAGNOSTICS_UNAVAILABLE")) || !bytes.Contains(files["logs/status.json"], []byte("JOURNAL_EXCERPT_UNAVAILABLE")) {
		t.Fatalf("partial bundle manifest/files = %+v %v", bundle.Manifest, files)
	}
	combined := string(files["manifest.json"]) + string(files["host/snapshot.json"]) + string(files["logs/status.json"])
	if strings.Contains(combined, "/root/secret") || strings.Contains(combined, "private journal") || strings.Contains(combined, "token=secret") {
		t.Fatalf("partial bundle leaked backend errors: %s", combined)
	}
}

func TestArchiveRejectsUnsafeOrDuplicatePaths(t *testing.T) {
	now := time.Now().UTC()
	manifest := Manifest{SchemaVersion: BundleSchemaVersion, Complete: true, Files: []ManifestFile{}, SectionErrors: []SectionError{}, SectionWarnings: []SectionError{}}
	for _, files := range [][]archiveFile{
		{{name: "../secret", contentType: "text/plain", content: []byte("x")}},
		{{name: "same", contentType: "text/plain", content: []byte("x")}, {name: "same", contentType: "text/plain", content: []byte("y")}},
		{{name: "manifest.json", contentType: "application/json", content: []byte("{}")}},
	} {
		if _, err := buildZIP(files, manifest, now); err == nil {
			t.Fatalf("unsafe archive files accepted: %+v", files)
		}
	}
}

func diagnosticDatabase(t *testing.T) (context.Context, *sql.DB) {
	t.Helper()
	ctx := context.Background()
	database, err := databasepkg.Open(ctx, databasepkg.OpenOptions{Path: filepath.Join(t.TempDir(), "state.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	if err := databasepkg.Migrate(ctx, database); err != nil {
		t.Fatal(err)
	}
	return ctx, database
}

func unzipBundle(t *testing.T, content []byte) (map[string][]byte, map[string]os.FileMode, int64) {
	t.Helper()
	reader, err := zip.NewReader(bytes.NewReader(content), int64(len(content)))
	if err != nil {
		t.Fatal(err)
	}
	files := make(map[string][]byte, len(reader.File))
	modes := make(map[string]os.FileMode, len(reader.File))
	var total int64
	for _, item := range reader.File {
		if strings.HasPrefix(item.Name, "/") || strings.Contains(item.Name, "\\") || strings.Contains(item.Name, "..") {
			t.Fatalf("unsafe ZIP entry %q", item.Name)
		}
		handle, err := item.Open()
		if err != nil {
			t.Fatal(err)
		}
		payload, err := io.ReadAll(io.LimitReader(handle, MaximumBundleUncompressedBytes+1))
		handle.Close()
		if err != nil || int64(len(payload)) > MaximumBundleUncompressedBytes {
			t.Fatalf("read ZIP entry %q: %v", item.Name, err)
		}
		files[item.Name] = payload
		modes[item.Name] = item.Mode().Perm()
		total += int64(len(payload))
	}
	return files, modes, total
}
