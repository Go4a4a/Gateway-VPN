// Package vpsops provides the bounded, display-only operational view used by
// the VPS Hub. Privileged collection is parameter-free from the Web API: a
// root-owned timer writes one sanitized snapshot and the unprivileged Agent
// can only read that file.
package vpsops

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	loggingpkg "gateway-vpn/internal/logging"
	"gateway-vpn/internal/platformexec"
)

const (
	SnapshotSchemaVersion = 1
	MaximumSnapshotBytes  = int64(4 << 20)
	maximumJournalBytes   = int64(3 << 20)
	maximumCommandBytes   = int64(256 << 10)
	maximumEntries        = 512
)

const (
	CategoryAll       = "all"
	CategoryAgent     = "agent-control"
	CategoryPairing   = "pairing-gateways"
	CategoryAdmins    = "administrators-relays"
	CategoryResources = "resources-acl"
	CategoryFabric    = "management-fabric"
	CategoryWatchdog  = "watchdog-recovery"
	CategoryLifecycle = "backup-restore-update"
	CategorySecurity  = "security-audit"
)

var (
	categoryOrder  = []string{CategoryAll, CategoryAgent, CategoryPairing, CategoryAdmins, CategoryResources, CategoryFabric, CategoryWatchdog, CategoryLifecycle, CategorySecurity}
	safeUnit       = regexp.MustCompile(`^[A-Za-z0-9@_.:-]{1,128}$`)
	safeCursor     = regexp.MustCompile(`^[A-Za-z0-9;:_=+./-]{1,256}$`)
	looseAuth      = regexp.MustCompile(`(?i)\b(?:bearer|basic)\s+[A-Za-z0-9._~+/=-]{4,}`)
	authAssignment = regexp.MustCompile(`(?i)\bauthorization\s*[:=]\s*[^\s]+(?:\s+[^\s]+)?`)
	units          = []string{
		"gateway-vpn-vps-agent.service",
		"gateway-vpn-vps-firewall.service",
		"gateway-vpn-vps-fabric.service",
		"gateway-vpn-vps-fabric-recovery.service",
		"gateway-vpn-vps-fabric-watchdog.service",
		"gateway-vpn-vps-restore.service",
		"gateway-vpn-vps-restore-recovery.service",
		"gateway-vpn-vps-install-recovery.service",
		"gateway-vpn-vps-operations.service",
		"wg-quick@wg-mgmt.service",
	}
)

type LogEntry struct {
	Cursor     string `json:"cursor"`
	OccurredAt string `json:"occurred_at"`
	Severity   string `json:"severity"`
	Category   string `json:"category"`
	Source     string `json:"source"`
	Unit       string `json:"unit,omitempty"`
	Message    string `json:"message"`
}

type UnitStatus struct {
	Unit        string `json:"unit"`
	LoadState   string `json:"load_state"`
	ActiveState string `json:"active_state"`
	SubState    string `json:"sub_state"`
	Restarts    uint64 `json:"restarts"`
}

type InterfaceStatus struct {
	Name      string   `json:"name"`
	State     string   `json:"state,omitempty"`
	Addresses []string `json:"addresses"`
}

type WireGuardStatus struct {
	Available         bool   `json:"available"`
	ListenPort        int    `json:"listen_port,omitempty"`
	Peers             int    `json:"peers"`
	LatestHandshakeAt string `json:"latest_handshake_at,omitempty"`
	RXBytes           uint64 `json:"rx_bytes"`
	TXBytes           uint64 `json:"tx_bytes"`
}

type HostStatus struct {
	Kernel      string            `json:"kernel,omitempty"`
	Interfaces  []InterfaceStatus `json:"interfaces"`
	OwnedRoutes json.RawMessage   `json:"owned_routes"`
	OwnedNFT    json.RawMessage   `json:"owned_nftables"`
	WireGuard   WireGuardStatus   `json:"wireguard"`
}

type Snapshot struct {
	SchemaVersion int             `json:"schema_version"`
	CollectedAt   string          `json:"collected_at"`
	State         string          `json:"state"`
	Units         []UnitStatus    `json:"units"`
	Host          HostStatus      `json:"host"`
	FabricStatus  json.RawMessage `json:"fabric_status"`
	Entries       []LogEntry      `json:"entries"`
	SectionErrors []string        `json:"section_errors"`
}

type Paths struct {
	Output       string
	FabricStatus string
	Journalctl   string
	Systemctl    string
	IP           string
	NFT          string
	WG           string
	Uname        string
}

func DefaultPaths() Paths {
	return Paths{
		Output:       "/var/lib/gateway-vpn-vps-privileged/operations/snapshot.json",
		FabricStatus: "/var/lib/gateway-vpn-vps/agent/fabric-watchdog.json",
		Journalctl:   "/usr/bin/journalctl", Systemctl: "/usr/bin/systemctl",
		IP: "/usr/sbin/ip", NFT: "/usr/sbin/nft", WG: "/usr/bin/wg", Uname: "/usr/bin/uname",
	}
}

func Categories() []string { return append([]string(nil), categoryOrder...) }

func ValidCategory(value string) bool {
	for _, item := range categoryOrder {
		if value == item {
			return true
		}
	}
	return false
}

type Collector struct {
	Executor platformexec.Executor
	Paths    Paths
	AgentGID int
	Now      func() time.Time
}

func (collector Collector) Collect(ctx context.Context) (Snapshot, error) {
	if err := collector.validate(); err != nil {
		return Snapshot{}, err
	}
	snapshot := Snapshot{
		SchemaVersion: SnapshotSchemaVersion, CollectedAt: collector.now().Format(time.RFC3339Nano), State: "HEALTHY",
		Units: []UnitStatus{}, Host: HostStatus{Interfaces: []InterfaceStatus{}, OwnedRoutes: json.RawMessage("[]"), OwnedNFT: json.RawMessage("{}")},
		FabricStatus: json.RawMessage("{}"), Entries: []LogEntry{}, SectionErrors: []string{},
	}
	failed := func(section string) {
		snapshot.SectionErrors = append(snapshot.SectionErrors, section)
		snapshot.State = "DEGRADED"
	}
	if value, err := collector.collectUnits(ctx); err == nil {
		snapshot.Units = value
	} else {
		failed("SYSTEMD_STATUS_UNAVAILABLE")
	}
	if value, err := collector.collectJournal(ctx); err == nil {
		snapshot.Entries = value
	} else {
		failed("JOURNAL_UNAVAILABLE")
	}
	if value, err := collector.command(ctx, collector.Paths.Uname, []string{"-r"}, 4096); err == nil {
		snapshot.Host.Kernel = bounded(value, 256)
	} else {
		failed("KERNEL_UNAVAILABLE")
	}
	if value, err := collector.command(ctx, collector.Paths.IP, []string{"-json", "-4", "address", "show"}, maximumCommandBytes); err == nil {
		if snapshot.Host.Interfaces, err = decodeInterfaces([]byte(value)); err != nil {
			failed("INTERFACES_INVALID")
		}
	} else {
		failed("INTERFACES_UNAVAILABLE")
	}
	if value, err := collector.command(ctx, collector.Paths.IP, []string{"-json", "-4", "route", "show", "dev", "wg-mgmt", "protocol", "186"}, maximumCommandBytes); err == nil {
		if snapshot.Host.OwnedRoutes, err = sanitizeJSON([]byte(value), true); err != nil {
			failed("OWNED_ROUTES_INVALID")
		}
	} else {
		failed("OWNED_ROUTES_UNAVAILABLE")
	}
	if value, err := collector.command(ctx, collector.Paths.NFT, []string{"-j", "list", "table", "inet", "gateway_vpn_vps"}, maximumCommandBytes); err == nil {
		if snapshot.Host.OwnedNFT, err = sanitizeJSON([]byte(value), false); err != nil {
			failed("OWNED_NFT_INVALID")
		}
	} else {
		failed("OWNED_NFT_UNAVAILABLE")
	}
	if value, err := collector.command(ctx, collector.Paths.WG, []string{"show", "wg-mgmt", "dump"}, maximumCommandBytes); err == nil {
		if snapshot.Host.WireGuard, err = decodeWireGuard(value); err != nil {
			failed("WIREGUARD_INVALID")
		}
	} else {
		failed("WIREGUARD_UNAVAILABLE")
	}
	if value, err := readBoundedJSON(collector.Paths.FabricStatus, 256<<10); err == nil {
		snapshot.FabricStatus = value
	} else {
		failed("FABRIC_STATUS_UNAVAILABLE")
	}
	if err := ValidateSnapshot(snapshot); err != nil {
		return Snapshot{}, err
	}
	return snapshot, nil
}

func (collector Collector) CollectAndWrite(ctx context.Context) (Snapshot, error) {
	snapshot, err := collector.Collect(ctx)
	if err != nil {
		return Snapshot{}, err
	}
	content, err := json.MarshalIndent(snapshot, "", "  ")
	if err != nil || int64(len(content)) > MaximumSnapshotBytes {
		return Snapshot{}, errors.New("VPS operations snapshot is oversized")
	}
	content = append(content, '\n')
	// The root-owned timer is the only writer. The Agent receives read access
	// through its group; it must never own this privileged snapshot.
	if err := atomicWrite(collector.Paths.Output, content, 0, collector.AgentGID); err != nil {
		return Snapshot{}, err
	}
	return snapshot, nil
}

func (collector Collector) validate() error {
	if collector.Executor == nil || collector.AgentGID < 0 {
		return errors.New("complete VPS operations collector identity is required")
	}
	for _, value := range []string{collector.Paths.Output, collector.Paths.FabricStatus, collector.Paths.Journalctl, collector.Paths.Systemctl, collector.Paths.IP, collector.Paths.NFT, collector.Paths.WG, collector.Paths.Uname} {
		if !filepath.IsAbs(value) {
			return errors.New("VPS operations paths must be absolute")
		}
	}
	if filepath.Base(filepath.Dir(collector.Paths.Output)) != "operations" || filepath.Base(collector.Paths.Output) != "snapshot.json" {
		return errors.New("fixed VPS operations output path is required")
	}
	return nil
}

func (collector Collector) collectUnits(ctx context.Context) ([]UnitStatus, error) {
	arguments := []string{"show", "--property=Id", "--property=LoadState", "--property=ActiveState", "--property=SubState", "--property=NRestarts"}
	arguments = append(arguments, units...)
	output, err := collector.command(ctx, collector.Paths.Systemctl, arguments, maximumCommandBytes)
	if err != nil {
		return nil, err
	}
	blocks := strings.Split(strings.TrimSpace(output), "\n\n")
	result := make([]UnitStatus, 0, len(blocks))
	for _, block := range blocks {
		values := map[string]string{}
		for _, line := range strings.Split(block, "\n") {
			key, value, ok := strings.Cut(line, "=")
			if ok {
				values[key] = strings.TrimSpace(value)
			}
		}
		if !safeUnit.MatchString(values["Id"]) {
			continue
		}
		restarts, _ := strconv.ParseUint(values["NRestarts"], 10, 64)
		result = append(result, UnitStatus{Unit: values["Id"], LoadState: bounded(values["LoadState"], 32), ActiveState: bounded(values["ActiveState"], 32), SubState: bounded(values["SubState"], 32), Restarts: restarts})
	}
	if len(result) == 0 || len(result) > len(units) {
		return nil, errors.New("systemd status is empty or oversized")
	}
	return result, nil
}

func (collector Collector) collectJournal(ctx context.Context) ([]LogEntry, error) {
	arguments := []string{"--no-pager", "--quiet", "--output=json", "--reverse", "--truncate-newline", "--lines=512", "--output-fields=__CURSOR,__REALTIME_TIMESTAMP,PRIORITY,_SYSTEMD_UNIT,MESSAGE"}
	for _, unit := range units {
		arguments = append(arguments, "--unit="+unit)
	}
	output, err := collector.command(ctx, collector.Paths.Journalctl, arguments, maximumJournalBytes)
	if err != nil {
		return nil, err
	}
	result := make([]LogEntry, 0, maximumEntries)
	for _, line := range strings.Split(output, "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var raw map[string]any
		if json.Unmarshal([]byte(line), &raw) != nil {
			return nil, errors.New("decode VPS journal line failed")
		}
		if entry, ok := journalEntry(raw); ok {
			result = append(result, entry)
		}
		if len(result) == maximumEntries {
			break
		}
	}
	return result, nil
}

func journalEntry(raw map[string]any) (LogEntry, bool) {
	cursor, timestamp, priority := field(raw, "__CURSOR"), field(raw, "__REALTIME_TIMESTAMP"), field(raw, "PRIORITY")
	unit, message := field(raw, "_SYSTEMD_UNIT"), field(raw, "MESSAGE")
	if !safeCursor.MatchString(cursor) || !safeUnit.MatchString(unit) || len(message) > 256<<10 {
		return LogEntry{}, false
	}
	micros, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil || micros < 0 {
		return LogEntry{}, false
	}
	severity := map[string]string{"0": "critical", "1": "critical", "2": "critical", "3": "error", "4": "warning", "5": "info", "6": "info", "7": "debug"}[priority]
	if severity == "" {
		severity = "info"
	}
	sanitized := loggingpkg.SanitizeText(message)
	sanitized = authAssignment.ReplaceAllString(sanitized, "authorization=[REDACTED]")
	sanitized = looseAuth.ReplaceAllString(sanitized, "[REDACTED_AUTHORIZATION]")
	return LogEntry{Cursor: cursor, OccurredAt: time.Unix(0, micros*1000).UTC().Format(time.RFC3339Nano), Severity: severity, Category: categoryForUnit(unit), Source: "systemd-journald", Unit: unit, Message: bounded(sanitized, 2048)}, true
}

func categoryForUnit(unit string) string {
	value := strings.ToLower(unit)
	switch {
	case strings.Contains(value, "watchdog"), strings.Contains(value, "recovery"):
		return CategoryWatchdog
	case strings.Contains(value, "restore"), strings.Contains(value, "install"):
		return CategoryLifecycle
	case strings.Contains(value, "fabric"), strings.Contains(value, "firewall"), strings.Contains(value, "wg-mgmt"):
		return CategoryFabric
	default:
		return CategoryAgent
	}
}

func (collector Collector) command(ctx context.Context, executable string, arguments []string, maximum int64) (string, error) {
	result, err := collector.Executor.Run(ctx, platformexec.Request{Executable: executable, Arguments: append([]string(nil), arguments...), MaxOutputBytes: maximum})
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(result.Stdout), nil
}

func (collector Collector) now() time.Time {
	if collector.Now != nil {
		return collector.Now().UTC()
	}
	return time.Now().UTC()
}

func decodeInterfaces(payload []byte) ([]InterfaceStatus, error) {
	var raw []struct {
		Name      string `json:"ifname"`
		State     string `json:"operstate"`
		Addresses []struct {
			Family string `json:"family"`
			Local  string `json:"local"`
			Prefix int    `json:"prefixlen"`
		} `json:"addr_info"`
	}
	if json.Unmarshal(payload, &raw) != nil || len(raw) > 128 {
		return nil, errors.New("invalid interface inventory")
	}
	result := make([]InterfaceStatus, 0, len(raw))
	for _, item := range raw {
		if !safeUnit.MatchString(item.Name) {
			continue
		}
		entry := InterfaceStatus{Name: item.Name, State: bounded(item.State, 32), Addresses: []string{}}
		for _, address := range item.Addresses {
			if address.Family == "inet" && address.Prefix >= 0 && address.Prefix <= 32 && len(entry.Addresses) < 32 {
				entry.Addresses = append(entry.Addresses, bounded(address.Local, 64)+"/"+strconv.Itoa(address.Prefix))
			}
		}
		result = append(result, entry)
	}
	return result, nil
}

func decodeWireGuard(output string) (WireGuardStatus, error) {
	lines := strings.Split(strings.TrimSpace(output), "\n")
	if len(lines) == 0 || strings.TrimSpace(lines[0]) == "" {
		return WireGuardStatus{}, errors.New("empty WireGuard dump")
	}
	fields := strings.Split(lines[0], "\t")
	if len(fields) != 4 {
		return WireGuardStatus{}, errors.New("invalid WireGuard interface")
	}
	port, err := strconv.Atoi(fields[2])
	if err != nil || port < 0 || port > 65535 {
		return WireGuardStatus{}, errors.New("invalid WireGuard port")
	}
	result := WireGuardStatus{Available: true, ListenPort: port}
	var latest int64
	for _, line := range lines[1:] {
		fields := strings.Split(line, "\t")
		if len(fields) != 8 || result.Peers >= 256 {
			return WireGuardStatus{}, errors.New("invalid WireGuard peer")
		}
		handshake, err1 := strconv.ParseInt(fields[4], 10, 64)
		rx, err2 := strconv.ParseUint(fields[5], 10, 64)
		tx, err3 := strconv.ParseUint(fields[6], 10, 64)
		if err1 != nil || err2 != nil || err3 != nil || handshake < 0 {
			return WireGuardStatus{}, errors.New("invalid WireGuard counters")
		}
		result.Peers++
		result.RXBytes += rx
		result.TXBytes += tx
		if handshake > latest {
			latest = handshake
		}
	}
	if latest > 0 {
		result.LatestHandshakeAt = time.Unix(latest, 0).UTC().Format(time.RFC3339Nano)
	}
	return result, nil
}

func sanitizeJSON(payload []byte, array bool) (json.RawMessage, error) {
	var value any
	if array {
		var decoded []any
		decoder := json.NewDecoder(bytes.NewReader(payload))
		decoder.UseNumber()
		if err := decoder.Decode(&decoded); err != nil {
			return nil, err
		}
		if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
			return nil, errors.New("JSON has trailing data")
		}
		value = decoded
	} else {
		var decoded map[string]any
		decoder := json.NewDecoder(bytes.NewReader(payload))
		decoder.UseNumber()
		if err := decoder.Decode(&decoded); err != nil {
			return nil, err
		}
		if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
			return nil, errors.New("JSON has trailing data")
		}
		value = decoded
	}
	content, err := json.Marshal(loggingpkg.SanitizeValue(value))
	if err != nil || int64(len(content)) > maximumCommandBytes {
		return nil, errors.New("sanitized JSON is oversized")
	}
	return content, nil
}

func readBoundedJSON(filename string, maximum int64) (json.RawMessage, error) {
	content, err := readRegular(filename, maximum)
	if err != nil {
		return nil, err
	}
	var value any
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.UseNumber()
	if decoder.Decode(&value) != nil {
		return nil, errors.New("invalid JSON")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return nil, errors.New("JSON has trailing data")
	}
	sanitized, err := json.Marshal(loggingpkg.SanitizeValue(value))
	if err != nil {
		return nil, err
	}
	return sanitized, nil
}

func ValidateSnapshot(snapshot Snapshot) error {
	if snapshot.SchemaVersion != SnapshotSchemaVersion || (snapshot.State != "HEALTHY" && snapshot.State != "DEGRADED") || len(snapshot.Units) > len(units) || len(snapshot.Entries) > maximumEntries || len(snapshot.SectionErrors) > 32 {
		return errors.New("VPS operations snapshot contract is invalid")
	}
	if _, err := time.Parse(time.RFC3339Nano, snapshot.CollectedAt); err != nil {
		return errors.New("VPS operations timestamp is invalid")
	}
	for _, entry := range snapshot.Entries {
		if !safeCursor.MatchString(entry.Cursor) || !ValidCategory(entry.Category) || entry.Category == CategoryAll || !safeUnit.MatchString(entry.Unit) || len(entry.Message) > 2048 || !utf8.ValidString(entry.Message) {
			return errors.New("VPS operations entry is invalid")
		}
	}
	return nil
}

type Store struct{ Path string }

func (store Store) Read() (Snapshot, error) {
	if !filepath.IsAbs(store.Path) || filepath.Base(filepath.Dir(store.Path)) != "operations" || filepath.Base(store.Path) != "snapshot.json" {
		return Snapshot{}, errors.New("fixed VPS operations snapshot path is required")
	}
	content, err := readRegular(store.Path, MaximumSnapshotBytes)
	if err != nil {
		return Snapshot{}, err
	}
	var snapshot Snapshot
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&snapshot); err != nil {
		return Snapshot{}, errors.New("decode VPS operations snapshot failed")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return Snapshot{}, errors.New("VPS operations snapshot has trailing data")
	}
	if err := ValidateSnapshot(snapshot); err != nil {
		return Snapshot{}, err
	}
	return snapshot, nil
}

func readRegular(filename string, maximum int64) ([]byte, error) {
	info, err := os.Lstat(filename)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maximum || runtime.GOOS != "windows" && info.Mode().Perm()&0o022 != 0 {
		return nil, errors.New("bounded protected regular VPS operations file is required")
	}
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	opened, statErr := file.Stat()
	content, readErr := io.ReadAll(io.LimitReader(file, maximum+1))
	closeErr := file.Close()
	if statErr != nil || !os.SameFile(info, opened) || readErr != nil || closeErr != nil || int64(len(content)) != info.Size() {
		return nil, errors.New("stable VPS operations read failed")
	}
	return content, nil
}

func atomicWrite(filename string, content []byte, uid, gid int) error {
	directory := filepath.Dir(filename)
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || runtime.GOOS != "windows" && info.Mode().Perm()&0o022 != 0 {
		return errors.New("VPS operations directory is unsafe")
	}
	temporary, err := os.CreateTemp(directory, ".snapshot-*")
	if err != nil {
		return err
	}
	name := temporary.Name()
	defer os.Remove(name)
	fail := func(cause error) error { _ = temporary.Close(); return cause }
	if err := temporary.Chmod(0o640); err != nil {
		return fail(err)
	}
	if err := chownFile(temporary, uid, gid); err != nil {
		return fail(err)
	}
	if written, err := temporary.Write(content); err != nil || written != len(content) {
		return fail(errors.New("write VPS operations snapshot failed"))
	}
	if err := temporary.Sync(); err != nil {
		return fail(err)
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, filename); err != nil {
		return fmt.Errorf("replace VPS operations snapshot: %w", err)
	}
	return syncDirectory(directory)
}

func syncDirectory(directory string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	handle, err := os.Open(directory)
	if err != nil {
		return err
	}
	defer handle.Close()
	return handle.Sync()
}

func bounded(value string, maximum int) string {
	value = strings.TrimSpace(value)
	if len(value) <= maximum {
		return value
	}
	value = value[:maximum]
	for !utf8.ValidString(value) {
		value = value[:len(value)-1]
	}
	return value
}

func field(raw map[string]any, key string) string {
	if value, ok := raw[key].(string); ok {
		return value
	}
	return ""
}

func sortLogs(entries []LogEntry) {
	sort.SliceStable(entries, func(i, j int) bool { return entries[i].OccurredAt > entries[j].OccurredAt })
}
