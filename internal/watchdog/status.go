package watchdog

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const (
	ComponentControl         = "control_plane"
	ComponentSQLite          = "sqlite"
	ComponentFirewallGuard   = "firewall_guard"
	ComponentFirewallRuleset = "firewall_ruleset"
	ComponentNetworkBroker   = "network_broker"
	ComponentDNSMasq         = "dnsmasq"
	ComponentMihomo          = "mihomo"
	ComponentResources       = "resources"

	ComponentHealthy       = "HEALTHY"
	ComponentDegraded      = "DEGRADED"
	ComponentFailed        = "FAILED"
	ComponentNotApplicable = "NOT_APPLICABLE"

	OverallHealthy            = "HEALTHY"
	OverallDegraded           = "DEGRADED"
	OverallCriticalLocal      = "CRITICAL_LOCAL"
	OverallRecoverySuppressed = "RECOVERY_SUPPRESSED"

	ClassificationLocal       = "LOCAL_COMPONENT_FAILURE"
	ClassificationExternal    = "EXTERNAL_CONNECTIVITY_FAILURE"
	ClassificationMaintenance = "MAINTENANCE_TRANSACTION"
)

type ComponentSpec struct {
	ID             string
	Label          string
	Restartable    bool
	RebootEligible bool
}

var fixedComponentSpecs = []ComponentSpec{
	{ID: ComponentControl, Label: "Control plane", Restartable: true, RebootEligible: true},
	{ID: ComponentSQLite, Label: "SQLite", Restartable: true, RebootEligible: false},
	{ID: ComponentFirewallGuard, Label: "Firewall guard", Restartable: true, RebootEligible: true},
	{ID: ComponentFirewallRuleset, Label: "Firewall ruleset", Restartable: true, RebootEligible: true},
	{ID: ComponentNetworkBroker, Label: "Network broker", Restartable: true, RebootEligible: true},
	{ID: ComponentDNSMasq, Label: "LAN DNS/DHCP", Restartable: true, RebootEligible: true},
	{ID: ComponentMihomo, Label: "Mihomo/TUN", Restartable: true, RebootEligible: true},
	{ID: ComponentResources, Label: "Host resources", Restartable: false, RebootEligible: false},
}

func ComponentSpecs() []ComponentSpec {
	return append([]ComponentSpec(nil), fixedComponentSpecs...)
}

func validComponentID(id string) bool {
	for _, spec := range fixedComponentSpecs {
		if spec.ID == id {
			return true
		}
	}
	return false
}

type Observation struct {
	ComponentID string
	Applicable  bool
	Healthy     bool
	ErrorCode   string
	Details     map[string]any
}

type ProbeSnapshot struct {
	ObservedAt      time.Time
	Maintenance     bool
	MaintenanceCode string
	Connectivity    string
	Components      []Observation
}

type ComponentStatus struct {
	ID                   string         `json:"id"`
	Label                string         `json:"label"`
	State                string         `json:"state"`
	Applicable           bool           `json:"applicable"`
	Classification       string         `json:"classification,omitempty"`
	ErrorCode            string         `json:"error_code,omitempty"`
	Details              map[string]any `json:"details,omitempty"`
	ConsecutiveFailures  int            `json:"consecutive_failures"`
	ConsecutiveSuccesses int            `json:"consecutive_successes"`
	RestartsInWindow     int            `json:"restarts_in_window"`
	LastSuccessAt        string         `json:"last_success_at,omitempty"`
	LastFailureAt        string         `json:"last_failure_at,omitempty"`
	LastRecoveryAt       string         `json:"last_recovery_at,omitempty"`
	LastRecoveryAction   string         `json:"last_recovery_action,omitempty"`
	RecoverySuppressed   bool           `json:"recovery_suppressed"`
	SuppressionReason    string         `json:"suppression_reason,omitempty"`
}

type Status struct {
	SchemaVersion       int               `json:"schema_version"`
	SupervisorStartedAt string            `json:"supervisor_started_at"`
	ObservedAt          string            `json:"observed_at"`
	OverallState        string            `json:"overall_state"`
	ConnectivityState   string            `json:"connectivity_state"`
	ConnectivityClass   string            `json:"connectivity_class,omitempty"`
	Maintenance         bool              `json:"maintenance"`
	MaintenanceCode     string            `json:"maintenance_code,omitempty"`
	PolicySource        string            `json:"policy_source"`
	PolicyErrorCode     string            `json:"policy_error_code,omitempty"`
	HostReboots24h      int               `json:"host_reboots_24h"`
	PendingRebootAt     string            `json:"pending_reboot_at,omitempty"`
	Components          []ComponentStatus `json:"components"`
}

type StatusFile struct {
	Path string
}

func (file StatusFile) Write(status Status) error {
	if !filepath.IsAbs(file.Path) || filepath.Base(file.Path) != "status.json" {
		return errors.New("fixed absolute watchdog status path is required")
	}
	payload, err := json.Marshal(status)
	if err != nil {
		return fmt.Errorf("encode watchdog status: %w", err)
	}
	return writeAtomicFile(file.Path, payload, 0o640)
}

func (file StatusFile) Read() (Status, error) {
	if !filepath.IsAbs(file.Path) || filepath.Base(file.Path) != "status.json" {
		return Status{}, errors.New("fixed absolute watchdog status path is required")
	}
	info, err := os.Lstat(file.Path)
	if err != nil {
		return Status{}, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > 1<<20 {
		return Status{}, errors.New("watchdog status file is unsafe")
	}
	payload, err := os.ReadFile(file.Path)
	if err != nil {
		return Status{}, err
	}
	var status Status
	if err := json.Unmarshal(payload, &status); err != nil || status.SchemaVersion != 1 || status.ObservedAt == "" {
		return Status{}, errors.New("watchdog status payload is invalid")
	}
	return status, nil
}

// ValidateFresh prevents a dead supervisor from remaining green in the Web UI
// merely because its last sanitized status file still exists in /run.
func (status Status) ValidateFresh(now time.Time, maximumAge time.Duration) error {
	if maximumAge <= 0 {
		return errors.New("positive watchdog status age is required")
	}
	started, startErr := time.Parse(time.RFC3339Nano, status.SupervisorStartedAt)
	observed, observedErr := time.Parse(time.RFC3339Nano, status.ObservedAt)
	if startErr != nil || observedErr != nil || observed.Before(started) {
		return errors.New("watchdog status timestamps are invalid")
	}
	age := now.UTC().Sub(observed)
	if age < -5*time.Second || age > maximumAge {
		return errors.New("watchdog status is stale")
	}
	return nil
}

func MaximumStatusAge(policy Policy) time.Duration {
	if err := policy.Validate(); err != nil {
		policy = DefaultPolicy()
	}
	return 2*policy.CheckInterval() + time.Minute
}

func sortComponentStatuses(items []ComponentStatus) {
	order := make(map[string]int, len(fixedComponentSpecs))
	for index, spec := range fixedComponentSpecs {
		order[spec.ID] = index
	}
	sort.SliceStable(items, func(left, right int) bool { return order[items[left].ID] < order[items[right].ID] })
}

func safeCode(value string) string {
	value = strings.ToUpper(strings.TrimSpace(value))
	if value == "" || len(value) > 64 {
		return "UNKNOWN"
	}
	for _, character := range value {
		if character != '_' && (character < 'A' || character > 'Z') && (character < '0' || character > '9') {
			return "UNKNOWN"
		}
	}
	return value
}
