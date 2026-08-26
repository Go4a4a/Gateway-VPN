// Package logging owns Gateway VPN's dynamic structured logging policy and
// performs secret redaction before records reach the process output handler.
package logging

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	ComponentAll             = "all"
	ComponentSystem          = "system"
	ComponentModem           = "modem"
	ComponentPathHealth      = "path_health"
	ComponentSubscription    = "subscription"
	ComponentMihomo          = "mihomo"
	ComponentRoutingFirewall = "routing_firewall"
	ComponentWireGuard       = "wireguard"
	ComponentTraffic         = "traffic"
	ComponentAuthAudit       = "auth_audit"

	LevelError   = "error"
	LevelWarning = "warning"
	LevelInfo    = "info"
	LevelDebug   = "debug"

	MinimumDebugTTL = 5 * time.Minute
	MaximumDebugTTL = 24 * time.Hour

	MinimumRetentionDays  = 1
	MaximumRetentionDays  = 365
	MinimumDiskUsageBytes = int64(64 << 20)
	MaximumDiskUsageBytes = int64(4 << 30)
	MinimumExcerptBytes   = int64(64 << 10)
	MaximumExcerptBytes   = int64(16 << 20)
)

var componentOrder = []string{
	ComponentSystem,
	ComponentModem,
	ComponentPathHealth,
	ComponentSubscription,
	ComponentMihomo,
	ComponentRoutingFirewall,
	ComponentWireGuard,
	ComponentTraffic,
	ComponentAuthAudit,
}

type Settings struct {
	SchemaVersion                 int               `json:"schema_version"`
	GlobalLevel                   string            `json:"global_level"`
	ComponentLevels               map[string]string `json:"component_levels"`
	DebugComponents               []string          `json:"debug_components"`
	DebugUntil                    string            `json:"debug_until"`
	RetentionDays                 int               `json:"retention_days"`
	MaxDiskUsageBytes             int64             `json:"max_disk_usage_bytes"`
	DiagnosticExcerptBytes        int64             `json:"diagnostic_excerpt_bytes"`
	HealthErrorAggregationSeconds int               `json:"health_error_aggregation_seconds"`
	UpdatedAt                     string            `json:"updated_at"`
}

type UpdateInput struct {
	GlobalLevel                   string
	ComponentLevels               map[string]string
	DebugComponents               []string
	DebugTTL                      time.Duration
	RetentionDays                 int
	MaxDiskUsageBytes             int64
	DiagnosticExcerptBytes        int64
	HealthErrorAggregationSeconds int
}

func Components() []string {
	return append([]string(nil), componentOrder...)
}

func DefaultSettings() Settings {
	return Settings{
		SchemaVersion: 1, GlobalLevel: LevelInfo, ComponentLevels: map[string]string{},
		DebugComponents: []string{}, RetentionDays: 14,
		MaxDiskUsageBytes: 256 << 20, DiagnosticExcerptBytes: 1 << 20,
		HealthErrorAggregationSeconds: 60,
	}
}

func BootstrapSettings(level string) Settings {
	settings := DefaultSettings()
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "error":
		settings.GlobalLevel = LevelError
	case "warn", "warning":
		settings.GlobalLevel = LevelWarning
	default:
		settings.GlobalLevel = LevelInfo
	}
	return settings
}

func (settings Settings) Validate() error {
	if settings.SchemaVersion != 1 {
		return errors.New("logging settings schema version must be 1")
	}
	if !validBaseLevel(settings.GlobalLevel) {
		return errors.New("global logging level must be error, warning, or info")
	}
	for component, level := range settings.ComponentLevels {
		if !validComponent(component) || !validBaseLevel(level) {
			return fmt.Errorf("invalid logging level override for %q", component)
		}
		if component == ComponentAuthAudit && level != LevelInfo {
			return errors.New("auth/audit logging cannot be reduced below info")
		}
	}
	if err := validateDebug(settings.DebugComponents, settings.DebugUntil); err != nil {
		return err
	}
	if settings.RetentionDays < MinimumRetentionDays || settings.RetentionDays > MaximumRetentionDays {
		return fmt.Errorf("logging retention must be %d..%d days", MinimumRetentionDays, MaximumRetentionDays)
	}
	if settings.MaxDiskUsageBytes < MinimumDiskUsageBytes || settings.MaxDiskUsageBytes > MaximumDiskUsageBytes {
		return errors.New("logging disk limit is outside the supported range")
	}
	if settings.DiagnosticExcerptBytes < MinimumExcerptBytes || settings.DiagnosticExcerptBytes > MaximumExcerptBytes || settings.DiagnosticExcerptBytes > settings.MaxDiskUsageBytes {
		return errors.New("diagnostic excerpt limit is outside the supported range")
	}
	if settings.HealthErrorAggregationSeconds < 1 || settings.HealthErrorAggregationSeconds > 3600 {
		return errors.New("health error aggregation window must be 1..3600 seconds")
	}
	if settings.UpdatedAt != "" {
		if _, err := time.Parse(time.RFC3339Nano, settings.UpdatedAt); err != nil {
			return errors.New("logging settings update timestamp is invalid")
		}
	}
	return nil
}

func normalizeUpdate(input UpdateInput, now time.Time) (Settings, error) {
	settings := Settings{
		SchemaVersion:   1,
		GlobalLevel:     strings.ToLower(strings.TrimSpace(input.GlobalLevel)),
		ComponentLevels: make(map[string]string),
		RetentionDays:   input.RetentionDays, MaxDiskUsageBytes: input.MaxDiskUsageBytes,
		DiagnosticExcerptBytes:        input.DiagnosticExcerptBytes,
		HealthErrorAggregationSeconds: input.HealthErrorAggregationSeconds,
		UpdatedAt:                     now.UTC().Format(time.RFC3339Nano),
	}
	for rawComponent, rawLevel := range input.ComponentLevels {
		component := strings.ToLower(strings.TrimSpace(rawComponent))
		level := strings.ToLower(strings.TrimSpace(rawLevel))
		if level == "" || level == "inherit" {
			continue
		}
		if level == "warn" {
			level = LevelWarning
		}
		settings.ComponentLevels[component] = level
	}
	seen := make(map[string]struct{})
	for _, raw := range input.DebugComponents {
		component := strings.ToLower(strings.TrimSpace(raw))
		if component == "" {
			continue
		}
		if _, exists := seen[component]; exists {
			return Settings{}, errors.New("debug component list contains a duplicate")
		}
		seen[component] = struct{}{}
		settings.DebugComponents = append(settings.DebugComponents, component)
	}
	sort.Strings(settings.DebugComponents)
	if len(settings.DebugComponents) == 0 {
		if input.DebugTTL != 0 {
			return Settings{}, errors.New("debug TTL requires at least one debug component")
		}
	} else {
		if input.DebugTTL < MinimumDebugTTL || input.DebugTTL > MaximumDebugTTL {
			return Settings{}, errors.New("debug TTL must be between 5 minutes and 24 hours")
		}
		settings.DebugUntil = now.UTC().Add(input.DebugTTL).Format(time.RFC3339Nano)
	}
	if settings.GlobalLevel == "warn" {
		settings.GlobalLevel = LevelWarning
	}
	if err := settings.Validate(); err != nil {
		return Settings{}, err
	}
	return settings, nil
}

func (settings Settings) Threshold(component string, now time.Time) slog.Level {
	component = strings.ToLower(strings.TrimSpace(component))
	if !validComponent(component) {
		component = ComponentSystem
	}
	if settings.debugEnabled(component, now) {
		return slog.LevelDebug
	}
	level := settings.GlobalLevel
	if override := settings.ComponentLevels[component]; override != "" {
		level = override
	}
	threshold := slogLevel(level)
	if component == ComponentAuthAudit && threshold > slog.LevelInfo {
		return slog.LevelInfo
	}
	return threshold
}

func (settings Settings) EffectiveLevel(component string, now time.Time) string {
	return levelName(settings.Threshold(component, now))
}

func (settings Settings) MinimumThreshold(now time.Time) slog.Level {
	minimum := settings.Threshold(ComponentSystem, now)
	for _, component := range componentOrder {
		if current := settings.Threshold(component, now); current < minimum {
			minimum = current
		}
	}
	return minimum
}

func (settings Settings) AggregationWindow() time.Duration {
	return time.Duration(settings.HealthErrorAggregationSeconds) * time.Second
}

func (settings Settings) debugEnabled(component string, now time.Time) bool {
	if settings.DebugUntil == "" || len(settings.DebugComponents) == 0 {
		return false
	}
	deadline, err := time.Parse(time.RFC3339Nano, settings.DebugUntil)
	if err != nil || !deadline.After(now.UTC()) {
		return false
	}
	for _, current := range settings.DebugComponents {
		if current == ComponentAll || current == component {
			return true
		}
	}
	return false
}

func validateDebug(components []string, deadline string) error {
	if len(components) == 0 {
		if deadline != "" {
			return errors.New("debug deadline requires a debug component")
		}
		return nil
	}
	if deadline == "" {
		return errors.New("debug component requires a deadline")
	}
	if _, err := time.Parse(time.RFC3339Nano, deadline); err != nil {
		return errors.New("debug deadline is invalid")
	}
	seen := make(map[string]struct{})
	for _, component := range components {
		if component != ComponentAll && !validComponent(component) {
			return fmt.Errorf("unknown debug component %q", component)
		}
		if _, exists := seen[component]; exists {
			return errors.New("debug component list contains a duplicate")
		}
		seen[component] = struct{}{}
	}
	if _, all := seen[ComponentAll]; all && len(seen) != 1 {
		return errors.New("debug component all cannot be combined with individual components")
	}
	return nil
}

func validBaseLevel(level string) bool {
	return level == LevelError || level == LevelWarning || level == LevelInfo
}

func validComponent(component string) bool {
	for _, current := range componentOrder {
		if current == component {
			return true
		}
	}
	return false
}

func slogLevel(level string) slog.Level {
	switch level {
	case LevelError:
		return slog.LevelError
	case LevelWarning:
		return slog.LevelWarn
	case LevelDebug:
		return slog.LevelDebug
	default:
		return slog.LevelInfo
	}
}

func levelName(level slog.Level) string {
	switch {
	case level <= slog.LevelDebug:
		return LevelDebug
	case level >= slog.LevelError:
		return LevelError
	case level >= slog.LevelWarn:
		return LevelWarning
	default:
		return LevelInfo
	}
}

func cloneSettings(settings Settings) Settings {
	result := settings
	result.ComponentLevels = make(map[string]string, len(settings.ComponentLevels))
	for key, value := range settings.ComponentLevels {
		result.ComponentLevels[key] = value
	}
	result.DebugComponents = make([]string, len(settings.DebugComponents))
	copy(result.DebugComponents, settings.DebugComponents)
	return result
}

func RetentionFingerprint(settings Settings) string {
	digest := sha256.Sum256([]byte("journald-retention-v1\x00" + strconv.Itoa(settings.RetentionDays) + "\x00" + strconv.FormatInt(settings.MaxDiskUsageBytes, 10)))
	return hex.EncodeToString(digest[:])
}
