package vpsops

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
	"io"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	loggingpkg "gateway-vpn/internal/logging"
)

const (
	BundleSchemaVersion    = 1
	MaximumBundleBytes     = 12 << 20
	maximumBundlePlaintext = int64(8 << 20)
	MaximumQueryLimit      = 200
)

type ConfigSummary struct {
	Listen         []string `json:"listen"`
	AdminPrefixes  []string `json:"admin_prefixes"`
	StateDirectory string   `json:"state_directory"`
}

type Service struct {
	Database         *sql.DB
	SnapshotPath     string
	FabricStatusPath string
	Config           ConfigSummary
	AgentVersion     string
	Now              func() time.Time
}

type LogQuery struct {
	Category string
	Search   string
	Limit    int
}

type LogPage struct {
	Categories  []string   `json:"categories"`
	Selected    string     `json:"selected_category"`
	Items       []LogEntry `json:"items"`
	SnapshotAt  string     `json:"snapshot_at,omitempty"`
	SnapshotAge int64      `json:"snapshot_age_seconds,omitempty"`
	State       string     `json:"state"`
	Reason      string     `json:"reason,omitempty"`
}

func (service *Service) Logs(ctx context.Context, query LogQuery) (LogPage, error) {
	if service == nil || service.Database == nil {
		return LogPage{}, errors.New("VPS operations service is unavailable")
	}
	query.Category = strings.ToLower(strings.TrimSpace(query.Category))
	if query.Category == "" {
		query.Category = CategoryAll
	}
	query.Search = strings.TrimSpace(query.Search)
	if !ValidCategory(query.Category) || query.Limit < 1 || query.Limit > MaximumQueryLimit || len(query.Search) > 128 || !utf8.ValidString(query.Search) || strings.ContainsAny(query.Search, "\r\n\x00") {
		return LogPage{}, errors.New("VPS log query is invalid")
	}
	page := LogPage{Categories: Categories(), Selected: query.Category, Items: []LogEntry{}, State: "HEALTHY"}
	snapshot, snapshotErr := (Store{Path: service.SnapshotPath}).Read()
	if snapshotErr == nil {
		page.SnapshotAt = snapshot.CollectedAt
		if collected, err := time.Parse(time.RFC3339Nano, snapshot.CollectedAt); err == nil {
			page.SnapshotAge = max(0, int64(service.now().Sub(collected).Seconds()))
		}
		page.Items = append(page.Items, snapshot.Entries...)
		if snapshot.State != "HEALTHY" {
			page.State, page.Reason = "DEGRADED", "ROOT_SNAPSHOT_PARTIAL"
		}
	} else {
		page.State, page.Reason = "DEGRADED", "ROOT_SNAPSHOT_UNAVAILABLE"
	}
	audit, err := service.auditLogs(ctx, 250)
	if err != nil {
		return LogPage{}, err
	}
	page.Items = append(page.Items, audit...)
	sortLogs(page.Items)
	filtered := make([]LogEntry, 0, min(query.Limit, len(page.Items)))
	needle := strings.ToLower(query.Search)
	for _, item := range page.Items {
		if query.Category != CategoryAll && item.Category != query.Category && !(query.Category == CategorySecurity && item.Source == "security-audit") {
			continue
		}
		if needle != "" && !strings.Contains(strings.ToLower(item.Message+" "+item.Unit+" "+item.Source), needle) {
			continue
		}
		filtered = append(filtered, item)
		if len(filtered) == query.Limit {
			break
		}
	}
	page.Items = filtered
	return page, nil
}

func (service *Service) Snapshot() (Snapshot, error) {
	if service == nil {
		return Snapshot{}, errors.New("VPS operations service is unavailable")
	}
	return (Store{Path: service.SnapshotPath}).Read()
}

func (service *Service) auditLogs(ctx context.Context, limit int) ([]LogEntry, error) {
	rows, err := service.Database.QueryContext(ctx, `
SELECT id,occurred_at,severity,event_type,details_json
FROM audit_events ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]LogEntry, 0, limit)
	for rows.Next() {
		var id int64
		var occurred, severity, eventType, details string
		if err := rows.Scan(&id, &occurred, &severity, &eventType, &details); err != nil {
			return nil, err
		}
		var value any
		if json.Unmarshal([]byte(details), &value) != nil {
			value = map[string]any{}
		}
		safeDetails, _ := json.Marshal(loggingpkg.SanitizeValue(value))
		message := strings.TrimSpace(eventType)
		if len(safeDetails) > 2 {
			message += " " + string(safeDetails)
		}
		result = append(result, LogEntry{Cursor: fmt.Sprintf("audit:%d", id), OccurredAt: occurred, Severity: normalizeSeverity(severity), Category: categoryForEvent(eventType), Source: "security-audit", Message: bounded(message, 2048)})
	}
	return result, rows.Err()
}

func categoryForEvent(event string) string {
	value := strings.ToUpper(event)
	switch {
	case strings.Contains(value, "PAIRING"), strings.Contains(value, "GATEWAY"):
		return CategoryPairing
	case strings.Contains(value, "ADMIN"), strings.Contains(value, "RELAY"):
		return CategoryAdmins
	case strings.Contains(value, "RESOURCE"), strings.Contains(value, "ACL"):
		return CategoryResources
	case strings.Contains(value, "FABRIC"):
		return CategoryFabric
	case strings.Contains(value, "BACKUP"), strings.Contains(value, "RESTORE"), strings.Contains(value, "UPDATE"):
		return CategoryLifecycle
	case strings.Contains(value, "LOGIN"), strings.Contains(value, "AUTH"), strings.Contains(value, "PASSWORD"):
		return CategorySecurity
	default:
		return CategorySecurity
	}
}

func normalizeSeverity(value string) string {
	switch strings.ToUpper(strings.TrimSpace(value)) {
	case "CRITICAL":
		return "critical"
	case "ERROR":
		return "error"
	case "WARNING", "WARN":
		return "warning"
	case "DEBUG":
		return "debug"
	default:
		return "info"
	}
}

type Bundle struct {
	Filename string
	Content  []byte
	SHA256   string
	Bytes    int64
	Manifest BundleManifest
}

type BundleManifest struct {
	SchemaVersion   int                  `json:"schema_version"`
	GeneratedAt     string               `json:"generated_at"`
	AgentVersion    string               `json:"agent_version"`
	Complete        bool                 `json:"complete"`
	SecretsIncluded bool                 `json:"secrets_included"`
	RedactionPolicy string               `json:"redaction_policy"`
	Files           []BundleManifestFile `json:"files"`
	SectionErrors   []string             `json:"section_errors"`
}

type BundleManifestFile struct {
	Path   string `json:"path"`
	Bytes  int64  `json:"bytes"`
	SHA256 string `json:"sha256"`
}

type bundleFile struct {
	name    string
	content []byte
}

func (service *Service) BuildBundle(ctx context.Context) (Bundle, error) {
	if service == nil || service.Database == nil {
		return Bundle{}, errors.New("VPS diagnostic builder is unavailable")
	}
	now := service.now()
	manifest := BundleManifest{SchemaVersion: BundleSchemaVersion, GeneratedAt: now.Format(time.RFC3339Nano), AgentVersion: bounded(service.AgentVersion, 256), Complete: true, SecretsIncluded: false, RedactionPolicy: "gateway-vpn-vps-v1-double-pass", Files: []BundleManifestFile{}, SectionErrors: []string{}}
	files := []bundleFile{}
	addJSON := func(name string, value any) {
		value = loggingpkg.SanitizeValue(value)
		content, err := json.MarshalIndent(value, "", "  ")
		if err != nil {
			manifest.Complete = false
			manifest.SectionErrors = append(manifest.SectionErrors, strings.ToUpper(strings.ReplaceAll(name, "/", "_"))+"_ENCODE_FAILED")
			return
		}
		files = append(files, bundleFile{name: name, content: append(content, '\n')})
	}
	addJSON("configuration/summary.json", service.Config)
	if snapshot, err := service.Snapshot(); err == nil {
		addJSON("operations/snapshot.json", snapshot)
	} else {
		manifest.Complete = false
		manifest.SectionErrors = append(manifest.SectionErrors, "ROOT_SNAPSHOT_UNAVAILABLE")
	}
	if logs, err := service.Logs(ctx, LogQuery{Category: CategoryAll, Limit: MaximumQueryLimit}); err == nil {
		var output bytes.Buffer
		for _, item := range logs.Items {
			line, _ := json.Marshal(loggingpkg.SanitizeValue(item))
			output.Write(line)
			output.WriteByte('\n')
		}
		files = append(files, bundleFile{name: "logs/recent.jsonl", content: output.Bytes()})
	} else {
		manifest.Complete = false
		manifest.SectionErrors = append(manifest.SectionErrors, "LOGS_UNAVAILABLE")
	}
	if report, err := service.databaseReport(ctx); err == nil {
		addJSON("database/report.json", report)
	} else {
		manifest.Complete = false
		manifest.SectionErrors = append(manifest.SectionErrors, "DATABASE_REPORT_UNAVAILABLE")
	}
	if raw, err := readBoundedJSON(service.FabricStatusPath, 256<<10); err == nil {
		var value any
		_ = json.Unmarshal(raw, &value)
		addJSON("fabric/watchdog.json", value)
	} else {
		manifest.Complete = false
		manifest.SectionErrors = append(manifest.SectionErrors, "FABRIC_STATUS_UNAVAILABLE")
	}
	sort.Slice(files, func(i, j int) bool { return files[i].name < files[j].name })
	var plain int64
	for _, file := range files {
		plain += int64(len(file.content))
		digest := sha256.Sum256(file.content)
		manifest.Files = append(manifest.Files, BundleManifestFile{Path: file.name, Bytes: int64(len(file.content)), SHA256: hex.EncodeToString(digest[:])})
	}
	if plain > maximumBundlePlaintext {
		return Bundle{}, errors.New("VPS diagnostic plaintext exceeds its fixed bound")
	}
	manifestContent, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return Bundle{}, err
	}
	manifestContent = append(manifestContent, '\n')
	var output bytes.Buffer
	archive := zip.NewWriter(&output)
	for _, file := range append(files, bundleFile{name: "manifest.json", content: manifestContent}) {
		header := &zip.FileHeader{Name: file.name, Method: zip.Deflate}
		header.SetMode(0o600)
		header.Modified = time.Unix(0, 0).UTC()
		writer, err := archive.CreateHeader(header)
		if err != nil {
			return Bundle{}, err
		}
		if _, err := writer.Write(file.content); err != nil {
			return Bundle{}, err
		}
	}
	if err := archive.Close(); err != nil {
		return Bundle{}, err
	}
	if output.Len() <= 0 || output.Len() > MaximumBundleBytes {
		return Bundle{}, errors.New("VPS diagnostic archive exceeds its fixed bound")
	}
	digest := sha256.Sum256(output.Bytes())
	stamp := now.Format("20060102T150405Z")
	return Bundle{Filename: "gateway-vpn-vps-diagnostics-" + stamp + ".zip", Content: output.Bytes(), SHA256: hex.EncodeToString(digest[:]), Bytes: int64(output.Len()), Manifest: manifest}, nil
}

func (service *Service) databaseReport(ctx context.Context) (map[string]any, error) {
	report := map[string]any{"schema_version": int64(0), "quick_check": "FAIL", "foreign_keys": "FAIL", "table_counts": map[string]int64{}}
	var schemaVersion int64
	if err := service.Database.QueryRowContext(ctx, "SELECT COALESCE(MAX(version),0) FROM schema_migrations").Scan(&schemaVersion); err != nil {
		return nil, err
	}
	report["schema_version"] = schemaVersion
	var quick string
	if err := service.Database.QueryRowContext(ctx, "PRAGMA quick_check").Scan(&quick); err == nil && quick == "ok" {
		report["quick_check"] = "PASS"
	}
	var foreign int64
	if err := service.Database.QueryRowContext(ctx, "SELECT COUNT(*) FROM pragma_foreign_key_check").Scan(&foreign); err == nil && foreign == 0 {
		report["foreign_keys"] = "PASS"
	}
	counts := report["table_counts"].(map[string]int64)
	for _, table := range []string{"gateway_peers", "admin_peers", "admin_relays", "resource_publications", "acl_grants", "pairing_invitations", "audit_events", "operations"} {
		var count int64
		if err := service.Database.QueryRowContext(ctx, "SELECT COUNT(*) FROM "+table).Scan(&count); err != nil {
			return nil, err
		}
		counts[table] = count
	}
	return report, nil
}

func (service *Service) now() time.Time {
	if service.Now != nil {
		return service.Now().UTC()
	}
	return time.Now().UTC()
}

func VerifyBundle(content []byte) (BundleManifest, error) {
	if len(content) <= 0 || len(content) > MaximumBundleBytes {
		return BundleManifest{}, errors.New("bounded VPS diagnostic archive is required")
	}
	reader, err := zip.NewReader(bytes.NewReader(content), int64(len(content)))
	if err != nil {
		return BundleManifest{}, err
	}
	files := map[string][]byte{}
	seen := map[string]struct{}{}
	var total int64
	for _, item := range reader.File {
		if item.FileInfo().IsDir() || item.UncompressedSize64 > uint64(maximumBundlePlaintext) || !validBundlePath(item.Name) {
			return BundleManifest{}, errors.New("invalid VPS diagnostic member")
		}
		handle, err := item.Open()
		if err != nil {
			return BundleManifest{}, err
		}
		payload, readErr := io.ReadAll(io.LimitReader(handle, maximumBundlePlaintext+1))
		closeErr := handle.Close()
		if readErr != nil || closeErr != nil {
			return BundleManifest{}, errors.New("read VPS diagnostic member failed")
		}
		total += int64(len(payload))
		if _, duplicate := seen[item.Name]; total > maximumBundlePlaintext || duplicate {
			return BundleManifest{}, errors.New("VPS diagnostic members exceed bounds")
		}
		seen[item.Name] = struct{}{}
		files[item.Name] = payload
	}
	var manifest BundleManifest
	if json.Unmarshal(files["manifest.json"], &manifest) != nil || manifest.SchemaVersion != BundleSchemaVersion || manifest.SecretsIncluded || manifest.RedactionPolicy != "gateway-vpn-vps-v1-double-pass" {
		return BundleManifest{}, errors.New("VPS diagnostic manifest is invalid")
	}
	if len(files) != len(manifest.Files)+1 {
		return BundleManifest{}, errors.New("VPS diagnostic archive has unlisted members")
	}
	listed := map[string]struct{}{}
	for _, record := range manifest.Files {
		if !validBundlePath(record.Path) || record.Path == "manifest.json" {
			return BundleManifest{}, errors.New("VPS diagnostic manifest path is invalid")
		}
		if _, duplicate := listed[record.Path]; duplicate {
			return BundleManifest{}, errors.New("VPS diagnostic manifest path is duplicated")
		}
		listed[record.Path] = struct{}{}
		content := files[record.Path]
		digest := sha256.Sum256(content)
		if int64(len(content)) != record.Bytes || hex.EncodeToString(digest[:]) != record.SHA256 {
			return BundleManifest{}, errors.New("VPS diagnostic member digest mismatch")
		}
	}
	return manifest, nil
}

func validBundlePath(value string) bool {
	switch value {
	case "manifest.json", "configuration/summary.json", "operations/snapshot.json", "logs/recent.jsonl", "database/report.json", "fabric/watchdog.json":
		return true
	default:
		return false
	}
}
