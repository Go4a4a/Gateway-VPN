package health

import (
	"context"
	"errors"

	"gateway-vpn/internal/scheduler"
)

// ScheduledProber applies the global/per-modem concurrency, request-rate and
// mobile-traffic budget before delegating each transport or target request.
// Candidate promotion normally uses ClassFailover so its reserved critical
// budget can exceed the soft limit with accounting, but never bypasses hard
// concurrency or rate limits.
type ScheduledProber struct {
	Inner              Prober
	Scheduler          *scheduler.Scheduler
	Class              string
	EstimatedBytes     int64
	BodyEstimatedBytes int64
}

func (prober ScheduledProber) ProbeTransport(ctx context.Context, path Path, candidate Candidate) ProbeResult {
	return prober.probe(ctx, path, "transport", prober.EstimatedBytes, func() ProbeResult {
		return prober.Inner.ProbeTransport(ctx, path, candidate)
	})
}

func (prober ScheduledProber) ProbeTarget(ctx context.Context, path Path, candidate Candidate, target Target) ProbeResult {
	estimatedBytes := prober.EstimatedBytes
	if target.ExpectedBodySubstring != "" && prober.BodyEstimatedBytes > 0 {
		estimatedBytes = prober.BodyEstimatedBytes
	}
	return prober.probe(ctx, path, target.ID, estimatedBytes, func() ProbeResult {
		return prober.Inner.ProbeTarget(ctx, path, candidate, target)
	})
}

func (prober ScheduledProber) probe(ctx context.Context, path Path, targetID string, estimatedBytes int64, operation func() ProbeResult) ProbeResult {
	if prober.Inner == nil || prober.Scheduler == nil || estimatedBytes <= 0 || operation == nil {
		return ProbeResult{State: ProbeFailed, ErrorCode: "SCHEDULER_NOT_CONFIGURED"}
	}
	class := prober.Class
	if class == "" {
		class = scheduler.ClassStandby
	}
	admission, err := prober.Scheduler.Acquire(ctx, scheduler.Request{ModemID: path.ModemID, TargetID: targetID, Class: class, EstimatedBytes: estimatedBytes})
	if err != nil {
		if errors.Is(err, context.Canceled) {
			return ProbeResult{State: ProbeFailed, ErrorCode: "CANCELLED"}
		}
		if errors.Is(err, context.DeadlineExceeded) {
			return ProbeResult{State: ProbeFailed, ErrorCode: "TIMEOUT"}
		}
		return ProbeResult{State: ProbeFailed, ErrorCode: "SCHEDULER_REJECTED"}
	}
	if admission.Decision == scheduler.DecisionDeferredBudget || admission.Permit == nil {
		return ProbeResult{State: ProbeFailed, ErrorCode: scheduler.DecisionDeferredBudget}
	}
	defer admission.Permit.Release(estimatedBytes)
	return operation()
}
