package logging

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"gateway-vpn/internal/platformexec"
)

const (
	MaximumJournalPageSize = 25
	journalScanLimit       = 128
	journalOutputLimit     = int64(2 << 20)
	journalMessageBytes    = 768
)

var (
	safeJournalCursor = regexp.MustCompile(`^[A-Za-z0-9;:_=+./-]{1,256}$`)
	safeJournalID     = regexp.MustCompile(`^[A-Za-z0-9:._-]{1,128}$`)
)

type JournalQuery struct {
	Limit          int      `json:"limit"`
	Cursor         string   `json:"cursor,omitempty"`
	Since          string   `json:"since,omitempty"`
	Until          string   `json:"until,omitempty"`
	Levels         []string `json:"levels,omitempty"`
	Component      string   `json:"component,omitempty"`
	ModemID        string   `json:"modem_id,omitempty"`
	SubscriptionID string   `json:"subscription_id,omitempty"`
	PathID         string   `json:"path_id,omitempty"`
	CorrelationID  string   `json:"correlation_id,omitempty"`
	Search         string   `json:"search,omitempty"`
}

type JournalEntry struct {
	Cursor         string `json:"cursor"`
	OccurredAt     string `json:"occurred_at"`
	Severity       string `json:"severity"`
	Component      string `json:"component"`
	Unit           string `json:"unit"`
	Message        string `json:"message"`
	ModemID        string `json:"modem_id,omitempty"`
	SubscriptionID string `json:"subscription_id,omitempty"`
	PathID         string `json:"path_id,omitempty"`
	CorrelationID  string `json:"correlation_id,omitempty"`
	Suppressed     int64  `json:"suppressed_repeats,omitempty"`
}

type JournalPage struct {
	Items      []JournalEntry `json:"items"`
	NextCursor string         `json:"next_cursor,omitempty"`
	HasMore    bool           `json:"has_more"`
}

type JournalReader struct {
	Executor   platformexec.Executor
	Journalctl string
	Now        func() time.Time
}

func (reader JournalReader) QueryLogs(ctx context.Context, query JournalQuery) (JournalPage, error) {
	if reader.Executor == nil || reader.Journalctl == "" || reader.Journalctl[0] != '/' {
		return JournalPage{}, errors.New("fixed journal reader dependencies are required")
	}
	normalized, err := NormalizeJournalQuery(query, reader.now())
	if err != nil {
		return JournalPage{}, err
	}
	arguments := []string{
		"--namespace=gateway-vpn", "--no-pager", "--quiet", "--output=json",
		"--output-fields=__CURSOR,__REALTIME_TIMESTAMP,PRIORITY,_SYSTEMD_UNIT,MESSAGE",
		"--reverse", "--truncate-newline", "--lines=" + strconv.Itoa(journalScanLimit+1),
	}
	if normalized.Cursor != "" {
		arguments = append(arguments, "--cursor="+normalized.Cursor)
	}
	if normalized.Since != "" {
		arguments = append(arguments, "--since="+normalized.Since)
	}
	if normalized.Until != "" {
		arguments = append(arguments, "--until="+normalized.Until)
	}
	result, err := reader.Executor.Run(ctx, platformexec.Request{Executable: reader.Journalctl, Arguments: arguments, MaxOutputBytes: journalOutputLimit})
	if err != nil || int64(len(result.Stdout)) > journalOutputLimit {
		return JournalPage{}, errors.New("bounded namespaced journal query failed")
	}
	return parseJournalPage(result.Stdout, normalized)
}

func NormalizeJournalQuery(query JournalQuery, now time.Time) (JournalQuery, error) {
	if query.Limit <= 0 || query.Limit > MaximumJournalPageSize {
		return JournalQuery{}, fmt.Errorf("journal page limit must be 1..%d", MaximumJournalPageSize)
	}
	query.Cursor = strings.TrimSpace(query.Cursor)
	if query.Cursor != "" && !safeJournalCursor.MatchString(query.Cursor) {
		return JournalQuery{}, errors.New("journal cursor is invalid")
	}
	var since, until time.Time
	var err error
	if strings.TrimSpace(query.Since) != "" {
		since, err = time.Parse(time.RFC3339Nano, strings.TrimSpace(query.Since))
		if err != nil {
			return JournalQuery{}, errors.New("journal since timestamp is invalid")
		}
		query.Since = since.UTC().Format(time.RFC3339Nano)
	}
	if strings.TrimSpace(query.Until) != "" {
		until, err = time.Parse(time.RFC3339Nano, strings.TrimSpace(query.Until))
		if err != nil {
			return JournalQuery{}, errors.New("journal until timestamp is invalid")
		}
		query.Until = until.UTC().Format(time.RFC3339Nano)
	} else {
		until = now.UTC()
	}
	if !since.IsZero() && (!until.After(since) || until.Sub(since) > 31*24*time.Hour) {
		return JournalQuery{}, errors.New("journal time range must be positive and no longer than 31 days")
	}
	seenLevels := make(map[string]struct{})
	levels := make([]string, 0, len(query.Levels))
	for _, raw := range query.Levels {
		level := strings.ToLower(strings.TrimSpace(raw))
		if level == "warn" {
			level = LevelWarning
		}
		if level != LevelError && level != LevelWarning && level != LevelInfo && level != LevelDebug {
			return JournalQuery{}, fmt.Errorf("unknown journal level %q", raw)
		}
		if _, exists := seenLevels[level]; exists {
			return JournalQuery{}, errors.New("journal levels contain a duplicate")
		}
		seenLevels[level] = struct{}{}
		levels = append(levels, level)
	}
	query.Levels = levels
	query.Component = strings.ToLower(strings.TrimSpace(query.Component))
	if query.Component != "" && !validComponent(query.Component) {
		return JournalQuery{}, errors.New("journal component is invalid")
	}
	for _, item := range []struct {
		name  string
		value *string
	}{{"modem", &query.ModemID}, {"subscription", &query.SubscriptionID}, {"path", &query.PathID}, {"correlation", &query.CorrelationID}} {
		*item.value = strings.TrimSpace(*item.value)
		if *item.value != "" && !safeJournalID.MatchString(*item.value) {
			return JournalQuery{}, fmt.Errorf("journal %s filter is invalid", item.name)
		}
	}
	query.Search = strings.TrimSpace(query.Search)
	if len(query.Search) > 128 || !utf8.ValidString(query.Search) || strings.ContainsAny(query.Search, "\r\n\x00") {
		return JournalQuery{}, errors.New("journal search is invalid")
	}
	return query, nil
}

func parseJournalPage(output string, query JournalQuery) (JournalPage, error) {
	page := JournalPage{Items: []JournalEntry{}}
	scanner := bufio.NewScanner(strings.NewReader(output))
	scanner.Buffer(make([]byte, 4096), 256<<10)
	rawSeen := 0
	lastScannedCursor := ""
	for scanner.Scan() {
		entry, err := parseJournalEntry(scanner.Bytes())
		if err != nil {
			return JournalPage{}, err
		}
		if query.Cursor != "" && entry.Cursor == query.Cursor {
			continue
		}
		rawSeen++
		if rawSeen > journalScanLimit {
			page.HasMore = true
			page.NextCursor = lastScannedCursor
			break
		}
		lastScannedCursor = entry.Cursor
		if !journalEntryMatches(entry, query) {
			continue
		}
		if len(page.Items) == query.Limit {
			page.HasMore = true
			page.NextCursor = page.Items[len(page.Items)-1].Cursor
			break
		}
		page.Items = append(page.Items, entry)
	}
	if err := scanner.Err(); err != nil {
		return JournalPage{}, errors.New("namespaced journal output is invalid or oversized")
	}
	if page.HasMore && page.NextCursor == "" {
		return JournalPage{}, errors.New("journal pagination cursor is unavailable")
	}
	return page, nil
}

func parseJournalEntry(payload []byte) (JournalEntry, error) {
	var raw map[string]any
	if err := json.Unmarshal(payload, &raw); err != nil {
		return JournalEntry{}, errors.New("decode namespaced journal entry failed")
	}
	cursor := journalField(raw, "__CURSOR")
	timestamp := journalField(raw, "__REALTIME_TIMESTAMP")
	priority := journalField(raw, "PRIORITY")
	unit := journalField(raw, "_SYSTEMD_UNIT")
	message := journalField(raw, "MESSAGE")
	if cursor == "" || !safeJournalCursor.MatchString(cursor) || timestamp == "" || len(message) > 256<<10 {
		return JournalEntry{}, errors.New("namespaced journal entry is incomplete")
	}
	microseconds, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil || microseconds < 0 || microseconds > math.MaxInt64/1000 {
		return JournalEntry{}, errors.New("namespaced journal timestamp is invalid")
	}
	entry := JournalEntry{
		Cursor: cursor, OccurredAt: time.Unix(0, microseconds*1000).UTC().Format(time.RFC3339Nano),
		Severity: journalSeverity(priority), Unit: truncateUTF8Bytes(SanitizeText(unit), 128), Component: componentForUnit(unit),
	}
	var structured map[string]any
	if json.Unmarshal([]byte(message), &structured) == nil {
		if level := stringValue(structured["level"]); level != "" {
			entry.Severity = normalizeJournalSeverity(level)
		}
		if component := strings.ToLower(stringValue(structured["component"])); validComponent(component) {
			entry.Component = component
		}
		entry.Message = truncateUTF8Bytes(SanitizeText(stringValue(structured["msg"])), journalMessageBytes)
		entry.ModemID = safeReturnedID(stringValue(structured["modem_id"]))
		entry.SubscriptionID = safeReturnedID(stringValue(structured["subscription_id"]))
		entry.PathID = safeReturnedID(stringValue(structured["path_id"]))
		entry.CorrelationID = safeReturnedID(stringValue(structured["correlation_id"]))
		entry.Suppressed = int64Value(structured["suppressed_repeats"])
	} else {
		entry.Message = truncateUTF8Bytes(SanitizeText(message), journalMessageBytes)
	}
	if entry.Message == "" {
		entry.Message = "(empty journal message)"
	}
	return entry, nil
}

func journalEntryMatches(entry JournalEntry, query JournalQuery) bool {
	if len(query.Levels) != 0 {
		matched := false
		for _, level := range query.Levels {
			if entry.Severity == level {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	if query.Component != "" && entry.Component != query.Component ||
		query.ModemID != "" && entry.ModemID != query.ModemID ||
		query.SubscriptionID != "" && entry.SubscriptionID != query.SubscriptionID ||
		query.PathID != "" && entry.PathID != query.PathID ||
		query.CorrelationID != "" && entry.CorrelationID != query.CorrelationID {
		return false
	}
	return query.Search == "" || strings.Contains(strings.ToLower(entry.Message), strings.ToLower(query.Search))
}

func journalField(raw map[string]any, key string) string {
	value := raw[key]
	switch current := value.(type) {
	case string:
		return current
	case []any:
		if len(current) != 0 {
			return stringValue(current[0])
		}
	}
	return ""
}

func stringValue(value any) string {
	if value == nil {
		return ""
	}
	if text, ok := value.(string); ok {
		return text
	}
	return fmt.Sprint(value)
}

func int64Value(value any) int64 {
	switch current := value.(type) {
	case float64:
		return int64(current)
	case json.Number:
		result, _ := current.Int64()
		return result
	case string:
		result, _ := strconv.ParseInt(current, 10, 64)
		return result
	default:
		return 0
	}
}

func journalSeverity(priority string) string {
	value, err := strconv.Atoi(priority)
	if err != nil {
		return LevelInfo
	}
	switch {
	case value <= 3:
		return LevelError
	case value == 4:
		return LevelWarning
	case value == 7:
		return LevelDebug
	default:
		return LevelInfo
	}
}

func normalizeJournalSeverity(level string) string {
	switch strings.ToUpper(strings.TrimSpace(level)) {
	case "DEBUG":
		return LevelDebug
	case "WARN", "WARNING":
		return LevelWarning
	case "ERROR":
		return LevelError
	default:
		return LevelInfo
	}
}

func componentForUnit(unit string) string {
	switch {
	case strings.Contains(unit, "mihomo"):
		return ComponentMihomo
	case strings.Contains(unit, "firewall"), strings.Contains(unit, "network-broker"), strings.Contains(unit, "network-recovery"), strings.Contains(unit, "network-rollback"):
		return ComponentRoutingFirewall
	default:
		return ComponentSystem
	}
}

func safeReturnedID(value string) string {
	value = strings.TrimSpace(value)
	if value != "" && safeJournalID.MatchString(value) {
		return value
	}
	return ""
}

func truncateUTF8Bytes(value string, maximum int) string {
	if len(value) <= maximum {
		return value
	}
	cut := maximum
	for cut > 0 && !utf8.ValidString(value[:cut]) {
		cut--
	}
	return value[:cut] + "…"
}

func (reader JournalReader) now() time.Time {
	if reader.Now != nil {
		return reader.Now().UTC()
	}
	return time.Now().UTC()
}
