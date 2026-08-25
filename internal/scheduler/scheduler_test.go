package scheduler

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestStandbyUsesOnlyNonReservedBudgetAndCriticalCanOverrun(t *testing.T) {
	scheduler, err := New(Config{MaxConcurrency: 2, MaxConcurrencyPerModem: 1, MaxRequestsPerWindow: 100, RequestWindow: time.Minute, DailySoftLimitBytes: 1000, ActiveFailoverReservePercent: 30})
	if err != nil {
		t.Fatal(err)
	}
	standby, err := scheduler.Acquire(context.Background(), Request{ModemID: "m1", TargetID: "t1", Class: ClassStandby, EstimatedBytes: 700})
	if err != nil || standby.Decision != DecisionAdmitted {
		t.Fatalf("standby admission = %+v, %v", standby, err)
	}
	standby.Permit.Release(700)
	deferred, err := scheduler.Acquire(context.Background(), Request{ModemID: "m1", TargetID: "t2", Class: ClassStandby, EstimatedBytes: 1})
	if err != nil || deferred.Decision != DecisionDeferredBudget {
		t.Fatalf("deferred admission = %+v, %v", deferred, err)
	}
	critical, err := scheduler.Acquire(context.Background(), Request{ModemID: "m1", TargetID: "t3", Class: ClassFailover, EstimatedBytes: 400})
	if err != nil || critical.Decision != DecisionAdmitted || !critical.Overage {
		t.Fatalf("critical admission = %+v, %v", critical, err)
	}
	critical.Permit.Release(400)
	usage := scheduler.Snapshot("m1")
	if usage.ObservedBytes != 1100 || usage.OverageBytes != 100 {
		t.Fatalf("usage = %+v", usage)
	}
}

func TestPerModemConcurrencyBlocksUntilRelease(t *testing.T) {
	scheduler, err := New(Config{MaxConcurrency: 2, MaxConcurrencyPerModem: 1, MaxRequestsPerWindow: 100, RequestWindow: time.Minute, DailySoftLimitBytes: 1000})
	if err != nil {
		t.Fatal(err)
	}
	first, err := scheduler.Acquire(context.Background(), Request{ModemID: "m1", TargetID: "t1", Class: ClassActive, EstimatedBytes: 1})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	_, err = scheduler.Acquire(ctx, Request{ModemID: "m1", TargetID: "t2", Class: ClassActive, EstimatedBytes: 1})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("second Acquire() error = %v", err)
	}
	first.Permit.Release(1)
	third, err := scheduler.Acquire(context.Background(), Request{ModemID: "m1", TargetID: "t3", Class: ClassActive, EstimatedBytes: 1})
	if err != nil || third.Permit == nil {
		t.Fatalf("third Acquire() = %+v, %v", third, err)
	}
	third.Permit.Release(1)
}

func TestHardRateLimitHonorsContext(t *testing.T) {
	scheduler, err := New(Config{MaxConcurrency: 1, MaxConcurrencyPerModem: 1, MaxRequestsPerWindow: 1, RequestWindow: time.Second, DailySoftLimitBytes: 1000})
	if err != nil {
		t.Fatal(err)
	}
	first, err := scheduler.Acquire(context.Background(), Request{ModemID: "m1", TargetID: "t1", Class: ClassActive})
	if err != nil {
		t.Fatal(err)
	}
	first.Permit.Release(0)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	_, err = scheduler.Acquire(ctx, Request{ModemID: "m2", TargetID: "t2", Class: ClassActive})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("rate-limited Acquire() error = %v", err)
	}
}

func TestSchedulerReportsImmutableOperationalLimits(t *testing.T) {
	configuration := DefaultConfig()
	scheduler, err := New(configuration)
	if err != nil {
		t.Fatal(err)
	}
	limits := scheduler.Limits()
	if limits.DailySoftLimitBytes != configuration.DailySoftLimitBytes ||
		limits.StandbyLimitBytes != configuration.DailySoftLimitBytes*int64(100-configuration.ActiveFailoverReservePercent)/100 ||
		limits.ActiveFailoverReservePercent != configuration.ActiveFailoverReservePercent ||
		limits.MaxConcurrency != configuration.MaxConcurrency ||
		limits.MaxConcurrencyPerModem != configuration.MaxConcurrencyPerModem ||
		limits.MaxRequestsPerWindow != configuration.MaxRequestsPerWindow ||
		limits.RequestWindow != configuration.RequestWindow || limits.MinTargetInterval != configuration.MinTargetInterval {
		t.Fatalf("Limits() = %+v", limits)
	}
	if limits := (*Scheduler)(nil).Limits(); limits != (Limits{}) {
		t.Fatalf("nil Limits() = %+v", limits)
	}
}
