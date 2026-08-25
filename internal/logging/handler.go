package logging

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
)

const redactedValue = "[REDACTED]"

var (
	httpURLPattern          = regexp.MustCompile(`(?i)https?://[^\s"'<>]+`)
	proxyURIPattern         = regexp.MustCompile(`(?i)\b(?:vless|vmess|trojan|ss|ssr|socks5?)://[^\s"'<>]+`)
	authorizationPattern    = regexp.MustCompile(`(?i)\b(?:bearer|basic)\s+[A-Za-z0-9._~+/=-]+`)
	secretAssignmentPattern = regexp.MustCompile(`(?i)\b(token|password|passwd|passphrase|secret|api[_-]?key|private[_-]?key)=([^&\s]+)`)
)

type Handler struct {
	inner      slog.Handler
	controller *Controller
	attributes []slog.Attr
	deduper    *recordDeduper
}

type recordDeduper struct {
	mutex   sync.Mutex
	entries map[string]dedupeEntry
}

type dedupeEntry struct {
	last       time.Time
	suppressed int64
}

func NewHandler(inner slog.Handler, controller *Controller) (slog.Handler, error) {
	if inner == nil || controller == nil {
		return nil, errors.New("logging inner handler and controller are required")
	}
	return &Handler{inner: inner, controller: controller, deduper: &recordDeduper{entries: make(map[string]dedupeEntry)}}, nil
}

func (handler *Handler) Enabled(ctx context.Context, level slog.Level) bool {
	return handler != nil && level >= handler.controller.MinimumThreshold() && handler.inner.Enabled(ctx, level)
}

func (handler *Handler) Handle(ctx context.Context, record slog.Record) error {
	if handler == nil {
		return errors.New("logging handler is nil")
	}
	component := componentFromAttrs(handler.attributes)
	record.Attrs(func(attribute slog.Attr) bool {
		if current := componentFromAttr(attribute); current != "" {
			component = current
		}
		return true
	})
	if component == "" {
		component = ComponentSystem
	}
	if !handler.controller.Enabled(component, record.Level) {
		return nil
	}
	sanitized := slog.NewRecord(record.Time, record.Level, sanitizeString(record.Message), record.PC)
	record.Attrs(func(attribute slog.Attr) bool {
		sanitized.AddAttrs(redactAttr(attribute))
		return true
	})
	if component == ComponentPathHealth && record.Level >= slog.LevelWarn {
		at := sanitized.Time
		if at.IsZero() {
			at = handler.controller.nowUTC()
		}
		emit, suppressed := handler.deduper.allow(recordFingerprint(sanitized, component), at, handler.controller.AggregationWindow())
		if !emit {
			return nil
		}
		if suppressed > 0 {
			sanitized.AddAttrs(slog.Int64("suppressed_repeats", suppressed))
		}
	}
	return handler.inner.Handle(ctx, sanitized)
}

func (handler *Handler) WithAttrs(attributes []slog.Attr) slog.Handler {
	sanitized := make([]slog.Attr, 0, len(attributes))
	for _, attribute := range attributes {
		sanitized = append(sanitized, redactAttr(attribute))
	}
	all := append([]slog.Attr(nil), handler.attributes...)
	all = append(all, sanitized...)
	return &Handler{inner: handler.inner.WithAttrs(sanitized), controller: handler.controller, attributes: all, deduper: handler.deduper}
}

func (handler *Handler) WithGroup(name string) slog.Handler {
	return &Handler{inner: handler.inner.WithGroup(name), controller: handler.controller, attributes: append([]slog.Attr(nil), handler.attributes...), deduper: handler.deduper}
}

func (deduper *recordDeduper) allow(key string, at time.Time, window time.Duration) (bool, int64) {
	if deduper == nil || window <= 0 {
		return true, 0
	}
	deduper.mutex.Lock()
	defer deduper.mutex.Unlock()
	entry, exists := deduper.entries[key]
	if exists && at.Sub(entry.last) >= 0 && at.Sub(entry.last) < window {
		entry.suppressed++
		deduper.entries[key] = entry
		return false, 0
	}
	suppressed := entry.suppressed
	deduper.entries[key] = dedupeEntry{last: at}
	if len(deduper.entries) > 1024 {
		cutoff := at.Add(-2 * window)
		for currentKey, current := range deduper.entries {
			if current.last.Before(cutoff) {
				delete(deduper.entries, currentKey)
			}
		}
		if len(deduper.entries) > 1024 {
			for currentKey := range deduper.entries {
				if currentKey != key {
					delete(deduper.entries, currentKey)
					break
				}
			}
		}
	}
	return true, suppressed
}

func componentFromAttrs(attributes []slog.Attr) string {
	component := ""
	for _, attribute := range attributes {
		if current := componentFromAttr(attribute); current != "" {
			component = current
		}
	}
	return component
}

func componentFromAttr(attribute slog.Attr) string {
	attribute.Value = attribute.Value.Resolve()
	if strings.EqualFold(attribute.Key, "component") && attribute.Value.Kind() == slog.KindString {
		value := strings.ToLower(strings.TrimSpace(attribute.Value.String()))
		if validComponent(value) {
			return value
		}
	}
	if attribute.Value.Kind() == slog.KindGroup {
		return componentFromAttrs(attribute.Value.Group())
	}
	return ""
}

func redactAttr(attribute slog.Attr) slog.Attr {
	if attribute.Equal(slog.Attr{}) {
		return attribute
	}
	if sensitiveKey(attribute.Key) {
		return slog.String(attribute.Key, redactedValue)
	}
	value := attribute.Value.Resolve()
	switch value.Kind() {
	case slog.KindString:
		text := value.String()
		if URLKey(attribute.Key) {
			text = sanitizeURL(text)
		} else {
			text = sanitizeString(text)
		}
		attribute.Value = slog.StringValue(text)
	case slog.KindGroup:
		group := value.Group()
		redacted := make([]slog.Attr, 0, len(group))
		for _, child := range group {
			redacted = append(redacted, redactAttr(child))
		}
		attribute.Value = slog.GroupValue(redacted...)
	case slog.KindAny:
		attribute.Value = slog.AnyValue(sanitizeAny(value.Any()))
	default:
		attribute.Value = value
	}
	return attribute
}

func sanitizeAny(value any) any {
	switch current := value.(type) {
	case nil:
		return nil
	case error:
		return errors.New(sanitizeString(current.Error()))
	case fmt.Stringer:
		return sanitizeString(current.String())
	case []byte:
		return "[REDACTED_BINARY]"
	case string:
		return sanitizeString(current)
	}
	payload, err := json.Marshal(value)
	if err != nil || len(payload) > 1<<20 {
		return "[REDACTED_UNSUPPORTED_VALUE]"
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.UseNumber()
	var decoded any
	if err := decoder.Decode(&decoded); err != nil {
		return "[REDACTED_UNSUPPORTED_VALUE]"
	}
	return sanitizeTree(decoded)
}

func sanitizeTree(value any) any {
	switch current := value.(type) {
	case map[string]any:
		result := make(map[string]any, len(current))
		for key, child := range current {
			if sensitiveKey(key) {
				result[key] = redactedValue
			} else if text, ok := child.(string); ok && URLKey(key) {
				result[key] = sanitizeURL(text)
			} else {
				result[key] = sanitizeTree(child)
			}
		}
		return result
	case []any:
		result := make([]any, len(current))
		for index, child := range current {
			result[index] = sanitizeTree(child)
		}
		return result
	case string:
		return sanitizeString(current)
	default:
		return current
	}
}

func sensitiveKey(key string) bool {
	normalized := normalizeKey(key)
	for _, marker := range []string{
		"password", "passwd", "passphrase", "token", "secret", "credential", "authorization", "cookie",
		"private_key", "api_key", "proxy_uri", "proxy_url", "subscription_url", "source_url",
		"source_secret_ref", "api_secret_ref", "identity_hash", "serial", "imei", "imsi", "iccid",
		"response_body", "expected_body", "payload", "packet", "mihomo_config", "subscription_config",
	} {
		if strings.Contains(normalized, marker) {
			return true
		}
	}
	return false
}

func URLKey(key string) bool {
	normalized := normalizeKey(key)
	return normalized == "url" || strings.HasSuffix(normalized, "_url") || strings.Contains(normalized, "endpoint_url")
}

func normalizeKey(key string) string {
	value := strings.ToLower(strings.TrimSpace(key))
	replacer := strings.NewReplacer("-", "_", ".", "_", " ", "_")
	return replacer.Replace(value)
}

func sanitizeString(value string) string {
	value = proxyURIPattern.ReplaceAllString(value, "[REDACTED_PROXY_URI]")
	value = authorizationPattern.ReplaceAllString(value, "[REDACTED_AUTHORIZATION]")
	value = secretAssignmentPattern.ReplaceAllString(value, "$1=[REDACTED]")
	value = httpURLPattern.ReplaceAllStringFunc(value, sanitizeURL)
	return value
}

// SanitizeText applies the same pre-logger string policy to data read back
// from journald. It is intentionally idempotent.
func SanitizeText(value string) string {
	return sanitizeString(value)
}

// SanitizeValue applies the recursive pre-logger policy to structured data
// before it crosses another output boundary such as a diagnostic archive.
// The returned value contains only JSON-compatible types.
func SanitizeValue(value any) any {
	return sanitizeAny(value)
}

func sanitizeURL(value string) string {
	parsed, err := url.Parse(value)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
		return "[REDACTED_URL]"
	}
	parsed.User = nil
	parsed.Path = "/"
	parsed.RawPath = ""
	parsed.RawQuery = ""
	parsed.ForceQuery = false
	parsed.Fragment = ""
	return parsed.String()
}

func recordFingerprint(record slog.Record, component string) string {
	digest := sha256.New()
	_, _ = digest.Write([]byte(component))
	_, _ = digest.Write([]byte{0})
	_, _ = digest.Write([]byte(record.Level.String()))
	_, _ = digest.Write([]byte{0})
	_, _ = digest.Write([]byte(record.Message))
	record.Attrs(func(attribute slog.Attr) bool {
		_, _ = digest.Write([]byte{0})
		_, _ = digest.Write([]byte(attribute.Key))
		_, _ = digest.Write([]byte("=" + fmt.Sprint(attribute.Value.Any())))
		return true
	})
	return hex.EncodeToString(digest.Sum(nil))
}
