package watchdog

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"time"
)

type PolicyReader interface {
	Get(context.Context) (Policy, error)
}

type Prober interface {
	Snapshot(context.Context) (ProbeSnapshot, error)
	Reconcile(context.Context, string) error
	FailClosed(context.Context) error
	Restart(context.Context, string) error
	Reboot(context.Context) error
}

type HistoryPersistence interface {
	Load() (DurableHistory, error)
	Save(DurableHistory) error
}

type StatusWriter interface {
	Write(Status) error
}

type componentRuntime struct {
	failures, successes int
	reconciled          bool
	lastSuccess         string
	lastFailure         string
	lastRecovery        string
	lastAction          string
}

type Supervisor struct {
	Policies PolicyReader
	Probe    Prober
	History  HistoryPersistence
	Status   StatusWriter
	Logger   *slog.Logger
	Now      func() time.Time
	OnReady  func() error

	startedAt         time.Time
	policy            Policy
	durable           DurableHistory
	runtime           map[string]*componentRuntime
	loaded            bool
	lastStatusWritten bool
}

func (supervisor *Supervisor) Run(ctx context.Context) error {
	if err := supervisor.initialize(); err != nil {
		return err
	}
	ready := false
	for {
		interval, err := supervisor.Tick(ctx)
		if err != nil && ctx.Err() == nil {
			supervisor.logger().Warn("watchdog cycle failed", "error", err)
		}
		if !ready && supervisor.lastStatusWritten {
			if supervisor.OnReady != nil {
				if err := supervisor.OnReady(); err != nil {
					return fmt.Errorf("notify watchdog readiness: %w", err)
				}
			}
			ready = true
		}
		timer := time.NewTimer(jitterInterval(interval))
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return nil
		case <-timer.C:
		}
	}
}

func (supervisor *Supervisor) initialize() error {
	if supervisor.Policies == nil || supervisor.Probe == nil || supervisor.History == nil || supervisor.Status == nil {
		return errors.New("complete watchdog supervisor dependencies are required")
	}
	if supervisor.loaded {
		return nil
	}
	supervisor.startedAt = supervisor.now()
	supervisor.policy = DefaultPolicy()
	supervisor.policy.HostRebootEnabled = false
	history, err := supervisor.History.Load()
	if err != nil {
		return fmt.Errorf("load watchdog durable history: %w", err)
	}
	supervisor.durable = history
	supervisor.runtime = make(map[string]*componentRuntime, len(fixedComponentSpecs))
	for _, spec := range fixedComponentSpecs {
		supervisor.runtime[spec.ID] = &componentRuntime{}
	}
	supervisor.loaded = true
	return nil
}

func (supervisor *Supervisor) Tick(ctx context.Context) (time.Duration, error) {
	supervisor.lastStatusWritten = false
	if err := supervisor.initialize(); err != nil {
		return DefaultPolicy().CheckInterval(), err
	}
	now := supervisor.now()
	policySource, policyError := "SQLITE", ""
	if policy, err := supervisor.Policies.Get(ctx); err == nil {
		supervisor.policy = policy
	} else {
		policySource = "LAST_KNOWN_GOOD"
		policyError = "POLICY_READ_FAILED"
		supervisor.logger().Warn("watchdog policy read failed; retaining last-known safe policy", "error", err)
	}
	supervisor.durable.Prune(now, supervisor.policy)
	snapshot, probeErr := supervisor.Probe.Snapshot(ctx)
	if probeErr != nil {
		policyError = mergeCode(policyError, "LOCAL_PROBE_FAILED")
		snapshot = missingProbeSnapshot(now)
	}
	if snapshot.ObservedAt.IsZero() {
		snapshot.ObservedAt = now
	}
	observed := make(map[string]Observation, len(snapshot.Components))
	for _, item := range snapshot.Components {
		if validComponentID(item.ComponentID) {
			observed[item.ComponentID] = item
		}
	}
	statuses := make([]ComponentStatus, 0, len(fixedComponentSpecs))
	criticalEligible := make([]string, 0)
	historyChanged := false
	for _, spec := range fixedComponentSpecs {
		observation, exists := observed[spec.ID]
		if !exists {
			observation = Observation{ComponentID: spec.ID, Applicable: true, Healthy: false, ErrorCode: "PROBE_RESULT_MISSING"}
		}
		status, changed := supervisor.evaluateComponent(ctx, spec, observation, snapshot, now)
		historyChanged = historyChanged || changed
		statuses = append(statuses, status)
		if status.State == ComponentFailed && spec.RebootEligible {
			criticalEligible = append(criticalEligible, spec.ID)
		}
	}
	if snapshot.Maintenance && supervisor.durable.PendingRebootAt != "" {
		supervisor.durable.PendingRebootAt = ""
		historyChanged = true
	}
	rebootChanged, rebootErr := supervisor.evaluateReboot(ctx, criticalEligible, snapshot, now, statuses)
	historyChanged = historyChanged || rebootChanged
	if rebootErr != nil {
		policyError = mergeCode(policyError, "HOST_REBOOT_FAILED")
	}
	if historyChanged {
		if err := supervisor.History.Save(supervisor.durable); err != nil {
			return supervisor.policy.CheckInterval(), fmt.Errorf("save watchdog durable history: %w", err)
		}
	}
	status := Status{
		SchemaVersion: 1, SupervisorStartedAt: supervisor.startedAt.Format(time.RFC3339Nano),
		ObservedAt:   snapshot.ObservedAt.UTC().Format(time.RFC3339Nano),
		OverallState: deriveOverall(statuses), ConnectivityState: snapshot.Connectivity,
		Maintenance: snapshot.Maintenance, MaintenanceCode: safeOptionalCode(snapshot.MaintenanceCode),
		PolicySource: policySource, PolicyErrorCode: policyError,
		HostReboots24h: len(supervisor.durable.RebootAttempts), PendingRebootAt: supervisor.durable.PendingRebootAt,
		Components: statuses,
	}
	if status.ConnectivityState == "" {
		status.ConnectivityState = "UNKNOWN"
	}
	if status.ConnectivityState != "AVAILABLE" {
		status.ConnectivityClass = ClassificationExternal
	}
	if err := supervisor.Status.Write(status); err != nil {
		return supervisor.policy.CheckInterval(), fmt.Errorf("write watchdog status: %w", err)
	}
	supervisor.lastStatusWritten = true
	return supervisor.policy.CheckInterval(), errors.Join(probeErr, rebootErr)
}

func (supervisor *Supervisor) evaluateComponent(ctx context.Context, spec ComponentSpec, observation Observation, snapshot ProbeSnapshot, now time.Time) (ComponentStatus, bool) {
	runtimeState := supervisor.runtime[spec.ID]
	status := ComponentStatus{ID: spec.ID, Label: spec.Label, Applicable: observation.Applicable, Details: observation.Details}
	changed := false
	if !observation.Applicable {
		runtimeState.failures, runtimeState.successes, runtimeState.reconciled = 0, 0, false
		if _, exists := supervisor.durable.CriticalSince[spec.ID]; exists {
			delete(supervisor.durable.CriticalSince, spec.ID)
			changed = true
		}
		status.State = ComponentNotApplicable
		return status, changed
	}
	if observation.Healthy {
		_, wasCritical := supervisor.durable.CriticalSince[spec.ID]
		wasRecovering := runtimeState.failures > 0 || runtimeState.reconciled || wasCritical
		runtimeState.successes++
		runtimeState.failures = 0
		runtimeState.lastSuccess = now.Format(time.RFC3339Nano)
		if runtimeState.successes >= supervisor.policy.SuccessThreshold {
			runtimeState.reconciled = false
			if _, exists := supervisor.durable.CriticalSince[spec.ID]; exists {
				delete(supervisor.durable.CriticalSince, spec.ID)
				changed = true
			}
		}
		if wasRecovering && runtimeState.successes < supervisor.policy.SuccessThreshold {
			status.State = ComponentDegraded
			status.Classification = ClassificationLocal
			return supervisor.componentStatus(status, runtimeState, now), changed
		}
		status.State = ComponentHealthy
		return supervisor.componentStatus(status, runtimeState, now), changed
	}
	runtimeState.failures++
	runtimeState.successes = 0
	runtimeState.lastFailure = now.Format(time.RFC3339Nano)
	status.ErrorCode = safeCode(observation.ErrorCode)
	status.Classification = ClassificationLocal
	if runtimeState.failures < supervisor.policy.FailureThreshold {
		status.State = ComponentDegraded
		return supervisor.componentStatus(status, runtimeState, now), changed
	}
	status.State = ComponentFailed
	if _, exists := supervisor.durable.CriticalSince[spec.ID]; !exists {
		supervisor.durable.CriticalSince[spec.ID] = now.Format(time.RFC3339Nano)
		changed = true
	}
	if snapshot.Maintenance {
		status.RecoverySuppressed, status.SuppressionReason = true, ClassificationMaintenance
		return supervisor.componentStatus(status, runtimeState, now), changed
	}
	if !supervisor.policy.Enabled {
		status.RecoverySuppressed, status.SuppressionReason = true, "WATCHDOG_DISABLED"
		return supervisor.componentStatus(status, runtimeState, now), changed
	}
	if supervisor.policy.ReconcileEnabled && !runtimeState.reconciled {
		runtimeState.reconciled = true
		runtimeState.lastAction = "RECONCILE"
		runtimeState.lastRecovery = now.Format(time.RFC3339Nano)
		supervisor.logger().Info("watchdog recovery action", "component_id", spec.ID, "action", "RECONCILE")
		if err := supervisor.Probe.Reconcile(ctx, spec.ID); err != nil {
			status.ErrorCode = "RECONCILE_FAILED"
			supervisor.logger().Warn("watchdog reconciliation request failed", "component_id", spec.ID, "error", err)
		}
		return supervisor.componentStatus(status, runtimeState, now), changed
	}
	if !spec.Restartable || !supervisor.policy.ComponentRestartEnabled {
		status.RecoverySuppressed = true
		if !spec.Restartable {
			status.SuppressionReason = "COMPONENT_NOT_RESTARTABLE"
		} else {
			status.SuppressionReason = "COMPONENT_RESTART_DISABLED"
		}
		return supervisor.componentStatus(status, runtimeState, now), changed
	}
	allowed, reason := supervisor.durable.RestartAllowed(spec.ID, supervisor.policy, now)
	if !allowed {
		status.RecoverySuppressed, status.SuppressionReason = true, reason
		return supervisor.componentStatus(status, runtimeState, now), changed
	}
	if err := supervisor.Probe.FailClosed(ctx); err != nil {
		status.RecoverySuppressed, status.SuppressionReason = true, "FAIL_CLOSED_FAILED"
		status.ErrorCode = "FAIL_CLOSED_FAILED"
		supervisor.logger().Error("watchdog refused unsafe restart because fail-closed failed", "component_id", spec.ID, "error", err)
		return supervisor.componentStatus(status, runtimeState, now), changed
	}
	supervisor.durable.RecordRestart(spec.ID, now)
	changed = true
	// Persist the attempt before invoking systemd. A watchdog crash or power
	// loss during restart must consume budget rather than create a restart loop.
	if err := supervisor.History.Save(supervisor.durable); err != nil {
		status.RecoverySuppressed, status.SuppressionReason = true, "HISTORY_PERSIST_FAILED"
		status.ErrorCode = "HISTORY_PERSIST_FAILED"
		supervisor.logger().Error("watchdog refused component restart because durable budget could not be committed", "component_id", spec.ID, "error", err)
		return supervisor.componentStatus(status, runtimeState, now), changed
	}
	runtimeState.lastAction = "COMPONENT_RESTART"
	runtimeState.lastRecovery = now.Format(time.RFC3339Nano)
	supervisor.logger().Warn("watchdog recovery action", "component_id", spec.ID, "action", "COMPONENT_RESTART", "attempts_in_window", len(supervisor.durable.RestartAttempts[spec.ID]))
	if err := supervisor.Probe.Restart(ctx, spec.ID); err != nil {
		status.ErrorCode = "COMPONENT_RESTART_FAILED"
		supervisor.logger().Error("watchdog component restart failed", "component_id", spec.ID, "error", err)
	}
	return supervisor.componentStatus(status, runtimeState, now), changed
}

func (supervisor *Supervisor) componentStatus(status ComponentStatus, runtimeState *componentRuntime, now time.Time) ComponentStatus {
	status.ConsecutiveFailures = runtimeState.failures
	status.ConsecutiveSuccesses = runtimeState.successes
	status.LastSuccessAt = runtimeState.lastSuccess
	status.LastFailureAt = runtimeState.lastFailure
	status.LastRecoveryAt = runtimeState.lastRecovery
	status.LastRecoveryAction = runtimeState.lastAction
	status.RestartsInWindow = len(supervisor.durable.RestartAttempts[status.ID])
	return status
}

func (supervisor *Supervisor) evaluateReboot(ctx context.Context, critical []string, snapshot ProbeSnapshot, now time.Time, statuses []ComponentStatus) (bool, error) {
	if len(critical) == 0 || snapshot.Maintenance || !supervisor.policy.Enabled {
		if supervisor.durable.PendingRebootAt != "" {
			supervisor.durable.PendingRebootAt = ""
			return true, nil
		}
		return false, nil
	}
	if !supervisor.policy.HostRebootEnabled {
		changed := false
		if supervisor.durable.PendingRebootAt != "" {
			supervisor.durable.PendingRebootAt = ""
			changed = true
		}
		for index := range statuses {
			if contains(critical, statuses[index].ID) && !statuses[index].RecoverySuppressed {
				statuses[index].RecoverySuppressed = true
				statuses[index].SuppressionReason = "HOST_REBOOT_DISABLED"
			}
		}
		return changed, nil
	}
	oldest := now
	for _, id := range critical {
		value, exists := supervisor.durable.CriticalSince[id]
		parsed, err := time.Parse(time.RFC3339Nano, value)
		if exists && err == nil && parsed.Before(oldest) {
			oldest = parsed
		}
	}
	if now.Before(oldest.Add(time.Duration(supervisor.policy.RebootAfterCriticalSeconds) * time.Second)) {
		return false, nil
	}
	allowed, reason := supervisor.durable.RebootAllowed(supervisor.policy, now)
	if !allowed {
		for index := range statuses {
			if contains(critical, statuses[index].ID) {
				statuses[index].RecoverySuppressed = true
				statuses[index].SuppressionReason = reason
			}
		}
		return false, nil
	}
	if supervisor.durable.PendingRebootAt == "" {
		supervisor.durable.PendingRebootAt = now.Add(time.Duration(supervisor.policy.RebootGraceSeconds) * time.Second).Format(time.RFC3339Nano)
		supervisor.logger().Error("watchdog scheduled bounded host reboot", "critical_components", critical, "reboot_at", supervisor.durable.PendingRebootAt)
		return true, nil
	}
	deadline, err := time.Parse(time.RFC3339Nano, supervisor.durable.PendingRebootAt)
	if err != nil || now.Before(deadline) {
		return false, nil
	}
	// Persist the attempt before invoking systemd so a process or host crash
	// cannot erase the budget and create a reboot loop.
	supervisor.durable.RecordReboot(now)
	if err := supervisor.History.Save(supervisor.durable); err != nil {
		return false, err
	}
	if err := supervisor.Probe.FailClosed(ctx); err != nil {
		supervisor.logger().Error("watchdog host reboot cancelled because fail-closed failed", "error", err)
		return false, err
	}
	supervisor.logger().Error("watchdog executing bounded host reboot", "critical_components", critical, "reboots_24h", len(supervisor.durable.RebootAttempts))
	if err := supervisor.Probe.Reboot(ctx); err != nil {
		return false, err
	}
	return false, nil
}

func missingProbeSnapshot(now time.Time) ProbeSnapshot {
	items := make([]Observation, 0, len(fixedComponentSpecs))
	for _, spec := range fixedComponentSpecs {
		items = append(items, Observation{ComponentID: spec.ID, Applicable: true, Healthy: false, ErrorCode: "LOCAL_PROBE_FAILED"})
	}
	return ProbeSnapshot{ObservedAt: now, Connectivity: "UNKNOWN", Components: items}
}

func deriveOverall(statuses []ComponentStatus) string {
	result := OverallHealthy
	for _, status := range statuses {
		if status.RecoverySuppressed && status.State == ComponentFailed {
			return OverallRecoverySuppressed
		}
		if status.State == ComponentFailed {
			result = OverallCriticalLocal
		} else if status.State == ComponentDegraded && result == OverallHealthy {
			result = OverallDegraded
		}
	}
	return result
}

func contains(items []string, expected string) bool {
	for _, item := range items {
		if item == expected {
			return true
		}
	}
	return false
}

func mergeCode(left, right string) string {
	if left == "" {
		return right
	}
	return left + "+" + right
}

func jitterInterval(interval time.Duration) time.Duration {
	if interval <= 0 {
		return time.Second
	}
	span := interval / 10
	if span <= 0 {
		return interval
	}
	return interval - span + time.Duration(rand.Int64N(int64(2*span)+1))
}

func safeOptionalCode(value string) string {
	if value == "" {
		return ""
	}
	return safeCode(value)
}

func (supervisor *Supervisor) now() time.Time {
	if supervisor.Now != nil {
		return supervisor.Now().UTC()
	}
	return time.Now().UTC()
}

func (supervisor *Supervisor) logger() *slog.Logger {
	if supervisor.Logger != nil {
		return supervisor.Logger
	}
	return slog.Default()
}
