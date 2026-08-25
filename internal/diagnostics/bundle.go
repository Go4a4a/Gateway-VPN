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
	"fmt"
	"net/netip"
	"os"
	pathpkg "path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"gateway-vpn/internal/bypass"
	"gateway-vpn/internal/config"
	"gateway-vpn/internal/db"
	loggingpkg "gateway-vpn/internal/logging"
	"gateway-vpn/internal/modem"
	"gateway-vpn/internal/pathmatrix"
	"gateway-vpn/internal/state"
	"gateway-vpn/internal/subscription"
	wireguardpkg "gateway-vpn/internal/wireguard"
)

const (
	BundleSchemaVersion            = 1
	MaximumBundleUncompressedBytes = int64(24 << 20)
	MaximumBundleBytes             = 32 << 20
	maximumEventExcerptBytes       = 2 << 20
	maximumJournalPages            = 256
	maximumNodeSummaries           = 5000
)

var safeGeneration = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)

type HostProvider interface {
	Collect(context.Context) (HostSnapshot, error)
}

type JournalProvider interface {
	QueryLogs(context.Context, loggingpkg.JournalQuery) (loggingpkg.JournalPage, error)
}

type Builder struct {
	Database              *sql.DB
	Configuration         config.Config
	Host                  HostProvider
	Journal               JournalProvider
	GatewayVersion        string
	ExpectedMihomoVersion string
	TLSFingerprint        string
	MihomoRoot            string
	Now                   func() time.Time
}

type Bundle struct {
	Filename         string
	Content          []byte
	SHA256           string
	UncompressedSize int64
	Manifest         Manifest
}

type Description struct {
	Available                     bool     `json:"available"`
	Format                        string   `json:"format"`
	SchemaVersion                 int      `json:"schema_version"`
	DownloadEndpoint              string   `json:"download_endpoint"`
	SecretsIncluded               bool     `json:"secrets_included"`
	MaximumArchiveBytes           int      `json:"maximum_archive_bytes"`
	MaximumUncompressedBytes      int64    `json:"maximum_uncompressed_bytes"`
	ConfiguredJournalExcerptBytes int64    `json:"configured_journal_excerpt_bytes"`
	Sections                      []string `json:"sections"`
}

type Manifest struct {
	SchemaVersion           int            `json:"schema_version"`
	GeneratedAt             string         `json:"generated_at"`
	GatewayVersion          string         `json:"gateway_version"`
	Complete                bool           `json:"complete"`
	SecretsIncluded         bool           `json:"secrets_included"`
	RedactionPolicy         string         `json:"redaction_policy"`
	PayloadUncompressedSize int64          `json:"payload_uncompressed_size"`
	Files                   []ManifestFile `json:"files"`
	SectionErrors           []SectionError `json:"section_errors"`
	SectionWarnings         []SectionError `json:"section_warnings"`
}

type ManifestFile struct {
	Path        string `json:"path"`
	ContentType string `json:"content_type"`
	Bytes       int64  `json:"bytes"`
	SHA256      string `json:"sha256"`
}

type archiveFile struct {
	name        string
	contentType string
	content     []byte
}

func (builder Builder) Describe(ctx context.Context) (Description, error) {
	if err := builder.validate(); err != nil {
		return Description{}, err
	}
	settings, err := (loggingpkg.Repository{Database: builder.Database}).Get(ctx)
	if err != nil {
		return Description{}, err
	}
	return Description{
		Available: true, Format: "zip", SchemaVersion: BundleSchemaVersion,
		DownloadEndpoint: "/api/v1/system/diagnostics", SecretsIncluded: false,
		MaximumArchiveBytes: MaximumBundleBytes, MaximumUncompressedBytes: MaximumBundleUncompressedBytes,
		ConfiguredJournalExcerptBytes: settings.DiagnosticExcerptBytes,
		Sections:                      []string{"versions", "sanitized_config", "host_network", "owned_nftables", "modems_subscriptions_paths", "mihomo", "wireguard", "events", "journal", "sqlite_integrity"},
	}, nil
}

func (builder Builder) Build(ctx context.Context) (Bundle, error) {
	if err := builder.validate(); err != nil {
		return Bundle{}, err
	}
	now := builder.now()
	manifest := Manifest{
		SchemaVersion: BundleSchemaVersion, GeneratedAt: now.Format(time.RFC3339Nano),
		GatewayVersion: boundedText(loggingpkg.SanitizeText(builder.GatewayVersion), 256),
		Complete:       true, SecretsIncluded: false, RedactionPolicy: "gateway-vpn-v1-double-pass",
		Files: []ManifestFile{}, SectionErrors: []SectionError{}, SectionWarnings: []SectionError{},
	}
	files := make([]archiveFile, 0, 16)
	seenErrors := map[string]struct{}{}
	seenWarnings := map[string]struct{}{}
	addError := func(section, code string) {
		key := section + "\x00" + code
		if _, exists := seenErrors[key]; exists {
			return
		}
		seenErrors[key] = struct{}{}
		manifest.Complete = false
		manifest.SectionErrors = append(manifest.SectionErrors, SectionError{Section: section, Code: code})
	}
	addWarning := func(section, code string) {
		key := section + "\x00" + code
		if _, exists := seenWarnings[key]; exists {
			return
		}
		seenWarnings[key] = struct{}{}
		manifest.SectionWarnings = append(manifest.SectionWarnings, SectionError{Section: section, Code: code})
	}
	addJSON := func(name string, value any) error {
		content, err := marshalDiagnosticJSON(value)
		if err != nil {
			return err
		}
		files = append(files, archiveFile{name: name, contentType: "application/json", content: content})
		return nil
	}
	addStatus := func(name, code string) error {
		return addJSON(name, map[string]any{"available": false, "error_code": code})
	}

	settings, err := (loggingpkg.Repository{Database: builder.Database}).Get(ctx)
	if err != nil {
		settings = loggingpkg.DefaultSettings()
		addError("logging_settings", "LOGGING_SETTINGS_UNAVAILABLE")
	}
	if err := addJSON("meta.json", map[string]any{
		"schema_version": BundleSchemaVersion, "generated_at": now.Format(time.RFC3339Nano),
		"gateway_version": manifest.GatewayVersion, "expected_mihomo_version": boundedText(loggingpkg.SanitizeText(builder.ExpectedMihomoVersion), 256),
		"tls_certificate_sha256": safeFingerprint(builder.TLSFingerprint), "secrets_included": false,
	}); err != nil {
		return Bundle{}, err
	}
	if err := addJSON("config/sanitized.json", sanitizedConfig(builder.Configuration)); err != nil {
		return Bundle{}, err
	}

	states := state.NewRepository(builder.Database)
	if snapshot, readErr := states.Get(ctx); readErr == nil {
		if err := addJSON("runtime/gateway-state.json", snapshot); err != nil {
			return Bundle{}, err
		}
	} else {
		addError("gateway_state", "GATEWAY_STATE_UNAVAILABLE")
		if err := addStatus("runtime/gateway-state.json", "GATEWAY_STATE_UNAVAILABLE"); err != nil {
			return Bundle{}, err
		}
	}

	modems := modem.NewRepository(builder.Database, builder.Configuration.Modems.RoutingTableStart, builder.Configuration.Modems.FwmarkStart)
	storedModems, modemErr := modems.List(ctx)
	if modemErr == nil {
		if err := addJSON("runtime/modems.json", sanitizeModems(storedModems)); err != nil {
			return Bundle{}, err
		}
	} else {
		addError("modems", "MODEM_INVENTORY_UNAVAILABLE")
		if err := addStatus("runtime/modems.json", "MODEM_INVENTORY_UNAVAILABLE"); err != nil {
			return Bundle{}, err
		}
	}

	subscriptions := subscription.NewRepository(builder.Database)
	storedSubscriptions, subscriptionErr := subscriptions.List(ctx)
	if subscriptionErr == nil {
		if err := addJSON("runtime/subscriptions.json", sanitizeSubscriptions(storedSubscriptions)); err != nil {
			return Bundle{}, err
		}
	} else {
		addError("subscriptions", "SUBSCRIPTION_INVENTORY_UNAVAILABLE")
		if err := addStatus("runtime/subscriptions.json", "SUBSCRIPTION_INVENTORY_UNAVAILABLE"); err != nil {
			return Bundle{}, err
		}
	}

	paths := pathmatrix.NewRepository(builder.Database)
	storedPaths, pathErr := paths.List(ctx)
	if pathErr == nil {
		if err := addJSON("runtime/path-matrix.json", sanitizePaths(storedPaths)); err != nil {
			return Bundle{}, err
		}
	} else {
		addError("path_matrix", "PATH_MATRIX_UNAVAILABLE")
		if err := addStatus("runtime/path-matrix.json", "PATH_MATRIX_UNAVAILABLE"); err != nil {
			return Bundle{}, err
		}
	}

	targets := bypass.NewRepository(builder.Database)
	storedTargets, targetErr := targets.List(ctx)
	if targetErr == nil {
		if err := addJSON("runtime/probe-targets.json", sanitizeTargets(storedTargets)); err != nil {
			return Bundle{}, err
		}
	} else {
		addError("probe_targets", "PROBE_TARGETS_UNAVAILABLE")
		if err := addStatus("runtime/probe-targets.json", "PROBE_TARGETS_UNAVAILABLE"); err != nil {
			return Bundle{}, err
		}
	}

	nodeSummaries, nodesTruncated, nodeErr := readNodeSummaries(ctx, builder.Database)
	if nodeErr == nil {
		if nodesTruncated {
			addWarning("nodes", "NODE_SUMMARY_TRUNCATED")
		}
		if err := addJSON("runtime/nodes.json", map[string]any{"items": nodeSummaries, "truncated": nodesTruncated}); err != nil {
			return Bundle{}, err
		}
	} else {
		addError("nodes", "NODE_SUMMARY_UNAVAILABLE")
		if err := addStatus("runtime/nodes.json", "NODE_SUMMARY_UNAVAILABLE"); err != nil {
			return Bundle{}, err
		}
	}

	wireGuardState, wireGuardErr := (wireguardpkg.RuntimeStore{Database: builder.Database}).Get(ctx)
	if wireGuardErr == nil {
		if err := addJSON("runtime/wireguard.json", wireGuardState); err != nil {
			return Bundle{}, err
		}
	} else {
		addError("wireguard_runtime", "WIREGUARD_RUNTIME_UNAVAILABLE")
		if err := addStatus("runtime/wireguard.json", "WIREGUARD_RUNTIME_UNAVAILABLE"); err != nil {
			return Bundle{}, err
		}
	}

	mihomoSummary, markerErrors := sanitizedMihomoSummary(builder.Configuration, builder.MihomoRoot)
	for _, item := range markerErrors {
		addError(item.Section, item.Code)
	}
	if err := addJSON("runtime/mihomo-sanitized.json", mihomoSummary); err != nil {
		return Bundle{}, err
	}

	if builder.Host != nil {
		host, hostErr := builder.Host.Collect(ctx)
		if hostErr == nil {
			host, hostErr = sanitizeHostSnapshot(host)
		}
		if hostErr == nil {
			for _, item := range host.SectionErrors {
				addError("host/"+item.Section, item.Code)
			}
			content, marshalErr := json.MarshalIndent(host, "", "  ")
			if marshalErr != nil || len(content) > MaximumHostSnapshotBytes {
				return Bundle{}, errors.New("encode bounded host diagnostics failed")
			}
			content = append(content, '\n')
			files = append(files, archiveFile{name: "host/snapshot.json", contentType: "application/json", content: content})
		} else {
			addError("host", "HOST_DIAGNOSTICS_UNAVAILABLE")
			if err := addStatus("host/snapshot.json", "HOST_DIAGNOSTICS_UNAVAILABLE"); err != nil {
				return Bundle{}, err
			}
		}
	} else {
		addError("host", "HOST_DIAGNOSTICS_NOT_CONFIGURED")
		if err := addStatus("host/snapshot.json", "HOST_DIAGNOSTICS_NOT_CONFIGURED"); err != nil {
			return Bundle{}, err
		}
	}

	eventsContent, eventsTruncated, eventErr := collectEvents(ctx, states)
	if eventErr == nil {
		if eventsTruncated {
			addWarning("events", "EVENT_EXCERPT_TRUNCATED")
		}
		files = append(files, archiveFile{name: "events/events.jsonl", contentType: "application/x-ndjson", content: eventsContent})
	} else {
		addError("events", "EVENT_EXCERPT_UNAVAILABLE")
		if err := addStatus("events/status.json", "EVENT_EXCERPT_UNAVAILABLE"); err != nil {
			return Bundle{}, err
		}
	}

	journalContent, journalTruncated, journalErr := collectJournal(ctx, builder.Journal, settings.DiagnosticExcerptBytes, now)
	if journalErr == nil {
		if journalTruncated {
			addWarning("journal", "JOURNAL_EXCERPT_TRUNCATED")
		}
		files = append(files, archiveFile{name: "logs/journal.jsonl", contentType: "application/x-ndjson", content: journalContent})
	} else {
		addError("journal", "JOURNAL_EXCERPT_UNAVAILABLE")
		if err := addStatus("logs/status.json", "JOURNAL_EXCERPT_UNAVAILABLE"); err != nil {
			return Bundle{}, err
		}
	}

	integrity := integrityReport(ctx, builder.Database)
	if integrity.QuickCheck != "PASS" || integrity.IntegrityCheck != "PASS" {
		addError("sqlite_integrity", "SQLITE_INTEGRITY_FAILED")
	}
	if err := addJSON("database/integrity.json", integrity); err != nil {
		return Bundle{}, err
	}

	return buildZIP(files, manifest, now)
}

func sanitizeHostSnapshot(input HostSnapshot) (HostSnapshot, error) {
	if input.SchemaVersion != HostSnapshotSchemaVersion {
		return HostSnapshot{}, errors.New("host diagnostic schema is unsupported")
	}
	output := input
	output.CollectedAt = boundedText(loggingpkg.SanitizeText(input.CollectedAt), 64)
	output.OS.ID = boundedText(loggingpkg.SanitizeText(input.OS.ID), 64)
	output.OS.VersionID = boundedText(loggingpkg.SanitizeText(input.OS.VersionID), 64)
	output.OS.PrettyName = boundedText(loggingpkg.SanitizeText(input.OS.PrettyName), 256)
	output.Kernel = boundedText(loggingpkg.SanitizeText(input.Kernel), 256)
	output.MihomoVersion = boundedText(loggingpkg.SanitizeText(input.MihomoVersion), 512)
	output.Interfaces = make([]InterfaceSummary, 0, min(len(input.Interfaces), maximumInterfaces))
	for _, item := range input.Interfaces {
		if len(output.Interfaces) == maximumInterfaces || !safeInterfaceName.MatchString(item.Name) {
			break
		}
		mtu := item.MTU
		if mtu < 0 || mtu > 1<<20 {
			mtu = 0
		}
		current := InterfaceSummary{Name: item.Name, State: boundedText(loggingpkg.SanitizeText(item.State), 32), MTU: mtu, Addresses: []InterfaceAddress{}}
		for _, address := range item.Addresses {
			parsed, err := netip.ParseAddr(address.Local)
			if err != nil || !parsed.Is4() || address.PrefixLen < 0 || address.PrefixLen > 32 || len(current.Addresses) >= maximumInterfaceAddresses {
				continue
			}
			current.Addresses = append(current.Addresses, InterfaceAddress{Family: "inet", Local: parsed.String(), PrefixLen: address.PrefixLen, Scope: boundedText(loggingpkg.SanitizeText(address.Scope), 32)})
		}
		output.Interfaces = append(output.Interfaces, current)
	}
	var err error
	if output.OwnedRoutes, err = sanitizeJSONArray(input.OwnedRoutes); err != nil {
		return HostSnapshot{}, errors.New("host route summary is invalid")
	}
	if output.OwnedRules, err = sanitizeOwnedRules(input.OwnedRules); err != nil {
		return HostSnapshot{}, errors.New("host rule summary is invalid")
	}
	if output.Nftables, err = sanitizeJSONObject(input.Nftables); err != nil {
		return HostSnapshot{}, errors.New("host nftables summary is invalid")
	}
	output.WireGuard.Peers = make([]WireGuardPeerSummary, 0, min(len(input.WireGuard.Peers), 128))
	for _, peer := range input.WireGuard.Peers {
		if len(output.WireGuard.Peers) == 128 {
			break
		}
		peer.Endpoint = maskEndpoint(peer.Endpoint)
		peer.AllowedIPs = safeAllowedIPs(strings.Join(peer.AllowedIPs, ","))
		peer.LatestHandshakeAt = boundedText(loggingpkg.SanitizeText(peer.LatestHandshakeAt), 64)
		if peer.Index < 1 || peer.PersistentKeepalive < 0 || peer.PersistentKeepalive > 65535 {
			continue
		}
		output.WireGuard.Peers = append(output.WireGuard.Peers, peer)
	}
	if output.WireGuard.ListenPort < 0 || output.WireGuard.ListenPort > 65535 {
		output.WireGuard.ListenPort = 0
	}
	output.WireGuard.Fwmark = boundedText(loggingpkg.SanitizeText(input.WireGuard.Fwmark), 32)
	output.SectionErrors = make([]SectionError, 0, len(input.SectionErrors))
	for _, item := range input.SectionErrors {
		if safeDiagnosticSection(item.Section) && safeDiagnosticCode(item.Code) {
			output.SectionErrors = append(output.SectionErrors, item)
		}
	}
	content, err := json.Marshal(output)
	if err != nil || len(content) > MaximumHostSnapshotBytes {
		return HostSnapshot{}, errors.New("sanitized host diagnostics exceed their bound")
	}
	return output, nil
}

func safeDiagnosticSection(value string) bool {
	if value == "" || len(value) > 64 {
		return false
	}
	for _, character := range value {
		if (character >= 'a' && character <= 'z') || (character >= '0' && character <= '9') || character == '_' || character == '/' {
			continue
		}
		return false
	}
	return true
}

func safeDiagnosticCode(value string) bool {
	if value == "" || len(value) > 64 {
		return false
	}
	for index, character := range value {
		if (character >= 'A' && character <= 'Z') || (index > 0 && character >= '0' && character <= '9') || (index > 0 && character == '_') {
			continue
		}
		return false
	}
	return true
}

func (builder Builder) validate() error {
	if builder.Database == nil || builder.Host == nil || builder.Journal == nil {
		return errors.New("diagnostic builder database, host collector, and journal reader are required")
	}
	if err := builder.Configuration.Validate(); err != nil {
		return fmt.Errorf("validate diagnostic bootstrap config: %w", err)
	}
	if builder.GatewayVersion == "" || !absolutePath(builder.MihomoRoot) {
		return errors.New("diagnostic builder versions and Mihomo root are required")
	}
	return nil
}

func (builder Builder) now() time.Time {
	if builder.Now != nil {
		return builder.Now().UTC()
	}
	return time.Now().UTC()
}

func buildZIP(files []archiveFile, manifest Manifest, now time.Time) (Bundle, error) {
	sort.Slice(files, func(i, j int) bool { return files[i].name < files[j].name })
	seen := make(map[string]struct{}, len(files)+1)
	var uncompressed int64
	for _, file := range files {
		if err := validateArchiveFile(file, seen); err != nil {
			return Bundle{}, err
		}
		uncompressed += int64(len(file.content))
		if uncompressed > MaximumBundleUncompressedBytes {
			return Bundle{}, errors.New("diagnostic bundle exceeds its uncompressed bound")
		}
		digest := sha256.Sum256(file.content)
		manifest.Files = append(manifest.Files, ManifestFile{Path: file.name, ContentType: file.contentType, Bytes: int64(len(file.content)), SHA256: hex.EncodeToString(digest[:])})
	}
	manifest.PayloadUncompressedSize = uncompressed
	manifestContent, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return Bundle{}, errors.New("encode diagnostic manifest failed")
	}
	manifestContent = append(manifestContent, '\n')
	if uncompressed+int64(len(manifestContent)) > MaximumBundleUncompressedBytes {
		return Bundle{}, errors.New("diagnostic manifest exceeds the archive bound")
	}
	totalUncompressed := uncompressed + int64(len(manifestContent))

	var buffer bytes.Buffer
	archive := zip.NewWriter(&buffer)
	write := func(name string, content []byte) error {
		header := &zip.FileHeader{Name: name, Method: zip.Deflate}
		header.SetMode(0o600)
		header.SetModTime(now)
		entry, err := archive.CreateHeader(header)
		if err != nil {
			return err
		}
		_, err = entry.Write(content)
		return err
	}
	for _, file := range files {
		if err := write(file.name, file.content); err != nil {
			_ = archive.Close()
			return Bundle{}, errors.New("write diagnostic archive entry failed")
		}
	}
	if err := write("manifest.json", manifestContent); err != nil {
		_ = archive.Close()
		return Bundle{}, errors.New("write diagnostic manifest failed")
	}
	if err := archive.Close(); err != nil {
		return Bundle{}, errors.New("finalize diagnostic archive failed")
	}
	if buffer.Len() > MaximumBundleBytes {
		return Bundle{}, errors.New("compressed diagnostic bundle exceeds its fixed bound")
	}
	content := append([]byte(nil), buffer.Bytes()...)
	digest := sha256.Sum256(content)
	return Bundle{
		Filename: "gateway-vpn-diagnostics-" + now.Format("20060102T150405Z") + ".zip",
		Content:  content, SHA256: hex.EncodeToString(digest[:]), UncompressedSize: totalUncompressed, Manifest: manifest,
	}, nil
}

func validateArchiveFile(file archiveFile, seen map[string]struct{}) error {
	clean := pathpkg.Clean(file.name)
	if file.name == "" || clean != file.name || strings.HasPrefix(clean, "/") || strings.Contains(file.name, "\\") || clean == "manifest.json" || strings.HasPrefix(clean, "../") {
		return errors.New("diagnostic archive path is unsafe")
	}
	if _, exists := seen[clean]; exists {
		return errors.New("diagnostic archive path is duplicated")
	}
	seen[clean] = struct{}{}
	if file.contentType == "" || int64(len(file.content)) > MaximumBundleUncompressedBytes {
		return errors.New("diagnostic archive entry is invalid")
	}
	return nil
}

func marshalDiagnosticJSON(value any) ([]byte, error) {
	content, err := json.MarshalIndent(loggingpkg.SanitizeValue(value), "", "  ")
	if err != nil {
		return nil, errors.New("encode sanitized diagnostic JSON failed")
	}
	return append(content, '\n'), nil
}

func absolutePath(value string) bool {
	return filepath.IsAbs(value) || pathpkg.IsAbs(value)
}

type sanitizedBootstrapConfig struct {
	Version int `json:"version"`
	System  struct {
		StateDir string `json:"state_dir"`
		Database string `json:"database"`
		LogLevel string `json:"log_level"`
	} `json:"system"`
	Network config.NetworkConfig        `json:"network"`
	Modems  config.ModemDiscoveryConfig `json:"modems"`
	Mihomo  struct {
		Binary                       string   `json:"binary"`
		TUNName                      string   `json:"tun_name"`
		Stack                        string   `json:"stack"`
		APIAddress                   string   `json:"api_address"`
		ProbeAddress                 string   `json:"probe_address"`
		BootstrapDNS                 []string `json:"bootstrap_dns"`
		TransportProbeOrigin         string   `json:"transport_probe_origin"`
		TransportProbeTimeoutSeconds int      `json:"transport_probe_timeout_seconds"`
		TransportExpectedStatus      string   `json:"transport_expected_status"`
	} `json:"mihomo"`
	API struct {
		Listen  []string `json:"listen"`
		TLSCert string   `json:"tls_cert"`
	} `json:"api"`
}

func sanitizedConfig(input config.Config) sanitizedBootstrapConfig {
	var output sanitizedBootstrapConfig
	output.Version = input.Version
	output.System.StateDir, output.System.Database, output.System.LogLevel = input.System.StateDir, input.System.Database, input.System.LogLevel
	output.Network, output.Modems = input.Network, input.Modems
	output.Mihomo.Binary, output.Mihomo.TUNName, output.Mihomo.Stack = input.Mihomo.Binary, input.Mihomo.TunName, input.Mihomo.Stack
	output.Mihomo.APIAddress, output.Mihomo.ProbeAddress = input.Mihomo.APIAddress, input.Mihomo.ProbeAddress
	output.Mihomo.BootstrapDNS = append([]string(nil), input.Mihomo.BootstrapDNS...)
	output.Mihomo.TransportProbeOrigin = loggingpkg.SanitizeText(input.Mihomo.TransportProbeURL)
	output.Mihomo.TransportProbeTimeoutSeconds, output.Mihomo.TransportExpectedStatus = input.Mihomo.TransportProbeTimeoutSeconds, input.Mihomo.TransportExpectedStatus
	output.API.Listen, output.API.TLSCert = append([]string(nil), input.API.Listen...), input.API.TLSCert
	return output
}

type modemSummary struct {
	ID                          string   `json:"id"`
	Number                      int64    `json:"number"`
	Name                        string   `json:"name"`
	ConfiguredOperator          string   `json:"configured_operator,omitempty"`
	ObservedOperator            string   `json:"observed_operator,omitempty"`
	IdentityKind                string   `json:"identity_kind"`
	MaskedIdentity              string   `json:"masked_identity,omitempty"`
	Enabled                     bool     `json:"enabled"`
	Priority                    int64    `json:"priority"`
	InterfaceName               string   `json:"interface_name,omitempty"`
	ManagementCIDR              string   `json:"management_cidr,omitempty"`
	Gateway                     string   `json:"gateway,omitempty"`
	DNS                         []string `json:"dns"`
	MTU                         int64    `json:"mtu,omitempty"`
	RoutingTableID              uint32   `json:"routing_table_id"`
	Fwmark                      uint32   `json:"fwmark"`
	State                       string   `json:"state"`
	TelemetryState              string   `json:"telemetry_state"`
	ManagementReachabilityState string   `json:"management_reachability_state"`
	LastSeenAt                  string   `json:"last_seen_at,omitempty"`
}

func sanitizeModems(items []modem.Modem) []modemSummary {
	result := make([]modemSummary, 0, len(items))
	for _, item := range items {
		var dns []string
		_ = json.Unmarshal([]byte(item.DNSJSON), &dns)
		if dns == nil {
			dns = []string{}
		}
		masked := item.MaskedSerial
		if masked != "" && !strings.Contains(masked, "*") {
			masked = "[MASKED]"
		}
		result = append(result, modemSummary{
			ID: item.ID, Number: item.DisplayNumber, Name: item.Name, ConfiguredOperator: item.OperatorLabel,
			ObservedOperator: item.ObservedOperator, IdentityKind: item.IdentityKind, MaskedIdentity: masked,
			Enabled: item.Enabled, Priority: item.Priority, InterfaceName: item.InterfaceName,
			ManagementCIDR: item.ManagementCIDR, Gateway: item.Gateway, DNS: dns, MTU: item.MTU,
			RoutingTableID: item.RoutingTableID, Fwmark: item.Fwmark, State: item.State,
			TelemetryState: item.TelemetryState, ManagementReachabilityState: item.ManagementReachabilityState, LastSeenAt: item.LastSeenAt,
		})
	}
	return result
}

type subscriptionSummary struct {
	ID                              string `json:"id"`
	Number                          int64  `json:"number"`
	Name                            string `json:"name"`
	SourceType                      string `json:"source_type"`
	Enabled                         bool   `json:"enabled"`
	Priority                        int64  `json:"priority"`
	AutoRefresh                     bool   `json:"auto_refresh"`
	RefreshIntervalSeconds          int64  `json:"refresh_interval_seconds"`
	FallbackWhenNamedCandidatesFail bool   `json:"fallback_when_named_candidates_fail"`
	Status                          string `json:"status"`
	ActiveVersionID                 string `json:"active_version_id,omitempty"`
	LastRefreshAt                   string `json:"last_refresh_at,omitempty"`
	LastSuccessAt                   string `json:"last_success_at,omitempty"`
}

func sanitizeSubscriptions(items []subscription.Subscription) []subscriptionSummary {
	result := make([]subscriptionSummary, 0, len(items))
	for _, item := range items {
		result = append(result, subscriptionSummary{
			ID: item.ID, Number: item.DisplayNumber, Name: item.Name, SourceType: item.SourceType,
			Enabled: item.Enabled, Priority: item.Priority, AutoRefresh: item.AutoRefresh,
			RefreshIntervalSeconds: item.RefreshIntervalSeconds, FallbackWhenNamedCandidatesFail: item.FallbackWhenNamedCandidatesFail,
			Status: item.Status, ActiveVersionID: item.ActiveVersionID, LastRefreshAt: item.LastRefreshAt, LastSuccessAt: item.LastSuccessAt,
		})
	}
	return result
}

func sanitizePaths(items []pathmatrix.Cell) []pathmatrix.Cell {
	return append([]pathmatrix.Cell(nil), items...)
}

type targetSummary struct {
	ID             string `json:"id"`
	Name           string `json:"name"`
	Kind           string `json:"kind"`
	Origin         string `json:"origin"`
	Enabled        bool   `json:"enabled"`
	Required       bool   `json:"required"`
	Priority       int64  `json:"priority"`
	TimeoutSeconds int64  `json:"timeout_seconds"`
	SuccessMode    string `json:"success_mode"`
	ExpectedStatus string `json:"expected_status,omitempty"`
	State          string `json:"state"`
}

func sanitizeTargets(items []bypass.Target) []targetSummary {
	result := make([]targetSummary, 0, len(items))
	for _, item := range items {
		result = append(result, targetSummary{ID: item.ID, Name: item.Name, Kind: item.Kind, Origin: loggingpkg.SanitizeText(item.NormalizedURL), Enabled: item.Enabled, Required: item.Required, Priority: item.Priority, TimeoutSeconds: item.TimeoutSeconds, SuccessMode: item.SuccessMode, ExpectedStatus: item.ExpectedStatus, State: item.State})
	}
	return result
}

type nodeSummary struct {
	ID                string `json:"id"`
	VersionID         string `json:"version_id"`
	SubscriptionID    string `json:"subscription_id"`
	ExternalName      string `json:"external_name"`
	ProxyType         string `json:"proxy_type"`
	Enabled           bool   `json:"enabled"`
	SelectionOverride string `json:"selection_override"`
	CandidateSource   string `json:"candidate_source"`
	MatchedMatcherID  string `json:"matched_matcher_id,omitempty"`
}

func readNodeSummaries(ctx context.Context, database *sql.DB) ([]nodeSummary, bool, error) {
	rows, err := database.QueryContext(ctx, `
SELECT n.id, n.version_id, s.id, n.external_name, n.proxy_type, n.enabled,
       n.selection_override, n.candidate_source, COALESCE(n.matched_matcher_id, '')
FROM subscriptions AS s
JOIN nodes AS n ON n.version_id=s.active_version_id
ORDER BY s.priority, s.display_number, n.normalized_name, n.id
LIMIT ?`, maximumNodeSummaries+1)
	if err != nil {
		return nil, false, err
	}
	defer rows.Close()
	result := make([]nodeSummary, 0)
	for rows.Next() {
		var item nodeSummary
		var enabled int
		if err := rows.Scan(&item.ID, &item.VersionID, &item.SubscriptionID, &item.ExternalName, &item.ProxyType, &enabled, &item.SelectionOverride, &item.CandidateSource, &item.MatchedMatcherID); err != nil {
			return nil, false, err
		}
		item.Enabled = enabled != 0
		item.ExternalName = boundedText(loggingpkg.SanitizeText(item.ExternalName), 256)
		result = append(result, item)
	}
	if err := rows.Err(); err != nil {
		return nil, false, err
	}
	truncated := len(result) > maximumNodeSummaries
	if truncated {
		result = result[:maximumNodeSummaries]
	}
	return result, truncated, nil
}

type mihomoSummary struct {
	TUNName                 string   `json:"tun_name"`
	Stack                   string   `json:"stack"`
	APIAddress              string   `json:"api_address"`
	ProbeAddress            string   `json:"probe_address"`
	BootstrapDNS            []string `json:"bootstrap_dns"`
	TransportProbeOrigin    string   `json:"transport_probe_origin"`
	ActiveGeneration        string   `json:"active_generation,omitempty"`
	LastKnownGoodGeneration string   `json:"last_known_good_generation,omitempty"`
	PendingGeneration       string   `json:"pending_generation,omitempty"`
}

func sanitizedMihomoSummary(configuration config.Config, root string) (mihomoSummary, []SectionError) {
	result := mihomoSummary{
		TUNName: configuration.Mihomo.TunName, Stack: configuration.Mihomo.Stack,
		APIAddress: configuration.Mihomo.APIAddress, ProbeAddress: configuration.Mihomo.ProbeAddress,
		BootstrapDNS:         append([]string(nil), configuration.Mihomo.BootstrapDNS...),
		TransportProbeOrigin: loggingpkg.SanitizeText(configuration.Mihomo.TransportProbeURL),
	}
	errorsFound := []SectionError{}
	markers := []struct {
		name string
		set  func(string)
	}{
		{"active-generation", func(value string) { result.ActiveGeneration = value }},
		{"lkg-generation", func(value string) { result.LastKnownGoodGeneration = value }},
		{"pending-generation", func(value string) { result.PendingGeneration = value }},
	}
	for _, marker := range markers {
		value, exists, err := readGenerationMarker(root, marker.name)
		if err != nil {
			errorsFound = append(errorsFound, SectionError{Section: "mihomo", Code: "MIHOMO_MARKER_INVALID"})
			continue
		}
		if exists {
			marker.set(value)
		}
	}
	return result, errorsFound
}

func readGenerationMarker(root, name string) (string, bool, error) {
	if !absolutePath(root) || !safeGeneration.MatchString(name) {
		return "", false, errors.New("invalid marker location")
	}
	filename := filepath.Join(root, "state", name)
	info, err := os.Lstat(filename)
	if errors.Is(err, os.ErrNotExist) {
		return "", false, nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() <= 0 || info.Size() > 256 {
		return "", false, errors.New("invalid generation marker")
	}
	content, err := os.ReadFile(filename)
	if err != nil {
		return "", false, errors.New("read generation marker failed")
	}
	value := strings.TrimSpace(string(content))
	if !safeGeneration.MatchString(value) || value == "." || value == ".." {
		return "", false, errors.New("unsafe generation marker")
	}
	return value, true, nil
}

func collectEvents(ctx context.Context, repository *state.Repository) ([]byte, bool, error) {
	events, err := repository.ListEvents(ctx, 500, 0)
	if err != nil {
		return nil, false, err
	}
	var buffer bytes.Buffer
	truncated := false
	for _, event := range events {
		var details any
		decoder := json.NewDecoder(strings.NewReader(event.DetailsJSON))
		decoder.UseNumber()
		if err := decoder.Decode(&details); err != nil {
			details = "[INVALID_REDACTED_DETAILS]"
		}
		entry := map[string]any{
			"id": event.ID, "occurred_at": event.OccurredAt, "severity": event.Severity, "type": event.Type,
			"modem_id": event.ModemID, "subscription_id": event.SubscriptionID, "path_id": event.PathID,
			"details": loggingpkg.SanitizeValue(details),
		}
		line, err := json.Marshal(entry)
		if err != nil {
			return nil, false, err
		}
		if buffer.Len()+len(line)+1 > maximumEventExcerptBytes {
			truncated = true
			break
		}
		buffer.Write(line)
		buffer.WriteByte('\n')
	}
	return buffer.Bytes(), truncated, nil
}

func collectJournal(ctx context.Context, provider JournalProvider, maximumBytes int64, now time.Time) ([]byte, bool, error) {
	if provider == nil || maximumBytes < loggingpkg.MinimumExcerptBytes || maximumBytes > loggingpkg.MaximumExcerptBytes {
		return nil, false, errors.New("diagnostic journal reader or limit is invalid")
	}
	var buffer bytes.Buffer
	cursor := ""
	seen := map[string]struct{}{}
	truncated := false
	for pageNumber := 0; pageNumber < maximumJournalPages; pageNumber++ {
		page, err := provider.QueryLogs(ctx, loggingpkg.JournalQuery{Limit: loggingpkg.MaximumJournalPageSize, Cursor: cursor, Since: now.Add(-31 * 24 * time.Hour).Format(time.RFC3339Nano), Until: now.Format(time.RFC3339Nano)})
		if err != nil {
			return nil, false, err
		}
		for _, item := range page.Items {
			line, err := json.Marshal(loggingpkg.SanitizeValue(item))
			if err != nil {
				return nil, false, err
			}
			if int64(buffer.Len()+len(line)+1) > maximumBytes {
				return buffer.Bytes(), true, nil
			}
			buffer.Write(line)
			buffer.WriteByte('\n')
		}
		if !page.HasMore {
			return buffer.Bytes(), truncated, nil
		}
		if page.NextCursor == "" || page.NextCursor == cursor {
			return nil, false, errors.New("journal pagination did not advance")
		}
		if _, exists := seen[page.NextCursor]; exists {
			return nil, false, errors.New("journal pagination cursor repeated")
		}
		seen[page.NextCursor] = struct{}{}
		cursor = page.NextCursor
	}
	truncated = true
	return buffer.Bytes(), truncated, nil
}

type sqliteIntegrityReport struct {
	QuickCheck     string `json:"quick_check"`
	IntegrityCheck string `json:"integrity_check"`
	SchemaVersion  int64  `json:"schema_version"`
}

func integrityReport(ctx context.Context, database *sql.DB) sqliteIntegrityReport {
	report := sqliteIntegrityReport{QuickCheck: "FAIL", IntegrityCheck: "FAIL"}
	if db.QuickCheck(ctx, database) == nil {
		report.QuickCheck = "PASS"
	}
	if db.IntegrityCheck(ctx, database) == nil {
		report.IntegrityCheck = "PASS"
	}
	_ = database.QueryRowContext(ctx, "SELECT COALESCE(MAX(version), 0) FROM schema_migrations").Scan(&report.SchemaVersion)
	return report
}

func safeFingerprint(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if len(value) == 64 {
		if _, err := hex.DecodeString(value); err == nil {
			return value
		}
	}
	return ""
}
