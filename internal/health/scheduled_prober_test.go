package health

import (
	"context"
	"testing"
	"time"

	"gateway-vpn/internal/scheduler"
)

type countingProber struct {
	calls int
}

func (prober *countingProber) ProbeTransport(context.Context, Path, Candidate) ProbeResult {
	prober.calls++
	return ProbeResult{State: ProbePassed}
}

func (prober *countingProber) ProbeTarget(context.Context, Path, Candidate, Target) ProbeResult {
	prober.calls++
	return ProbeResult{State: ProbePassed}
}

func TestScheduledProberAccountsAdmittedRequestAndDefersStandbyBudget(t *testing.T) {
	scheduled, err := scheduler.New(scheduler.Config{
		MaxConcurrency: 1, MaxConcurrencyPerModem: 1, MaxRequestsPerWindow: 10,
		RequestWindow: time.Second, DailySoftLimitBytes: 100, ActiveFailoverReservePercent: 50,
	})
	if err != nil {
		t.Fatal(err)
	}
	inner := &countingProber{}
	prober := ScheduledProber{Inner: inner, Scheduler: scheduled, Class: scheduler.ClassStandby, EstimatedBytes: 40}
	path := Path{ModemID: "modem-a"}
	if result := prober.ProbeTransport(context.Background(), path, Candidate{}); result.State != ProbePassed {
		t.Fatalf("first probe = %+v", result)
	}
	result := prober.ProbeTarget(context.Background(), path, Candidate{}, Target{ID: "target-a"})
	if result.ErrorCode != scheduler.DecisionDeferredBudget || inner.calls != 1 {
		t.Fatalf("deferred probe = %+v, inner calls=%d", result, inner.calls)
	}
	usage := scheduled.Snapshot("modem-a")
	if usage.Requests != 1 || usage.ObservedBytes != 40 || usage.ReservedBytes != 0 {
		t.Fatalf("scheduler usage = %+v", usage)
	}
}
