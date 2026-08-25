// Package scheduler enforces probe concurrency, rate, and per-modem soft
// traffic budgets.
package scheduler

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

const (
	ClassStandby  = "STANDBY"
	ClassActive   = "ACTIVE"
	ClassFailover = "FAILOVER"

	DecisionAdmitted       = "ADMITTED"
	DecisionDeferredBudget = "DEFERRED_BUDGET"
)

type Config struct {
	MaxConcurrency               int
	MaxConcurrencyPerModem       int
	MaxRequestsPerWindow         int
	RequestWindow                time.Duration
	MinTargetInterval            time.Duration
	DailySoftLimitBytes          int64
	ActiveFailoverReservePercent int
}

type Request struct {
	ModemID        string
	TargetID       string
	Class          string
	EstimatedBytes int64
}

type Admission struct {
	Decision string
	Overage  bool
	Permit   *Permit
}

type ModemUsage struct {
	Day           string
	ObservedBytes int64
	ReservedBytes int64
	Requests      int64
	OverageBytes  int64
}

type Limits struct {
	DailySoftLimitBytes          int64
	StandbyLimitBytes            int64
	ActiveFailoverReservePercent int
	MaxConcurrency               int
	MaxConcurrencyPerModem       int
	MaxRequestsPerWindow         int
	RequestWindow                time.Duration
	MinTargetInterval            time.Duration
}

type Scheduler struct {
	config Config
	now    func() time.Time
	global chan struct{}

	mutex        sync.Mutex
	perModem     map[string]chan struct{}
	requestTimes []time.Time
	lastTarget   map[string]time.Time
	usage        map[string]*ModemUsage
}

type Permit struct {
	scheduler *Scheduler
	request   Request
	once      sync.Once
}

func New(config Config) (*Scheduler, error) {
	if config.MaxConcurrency <= 0 || config.MaxConcurrencyPerModem <= 0 || config.MaxConcurrencyPerModem > config.MaxConcurrency {
		return nil, errors.New("invalid probe concurrency limits")
	}
	if config.MaxRequestsPerWindow <= 0 {
		return nil, errors.New("probe request rate limit must be positive")
	}
	if config.RequestWindow <= 0 {
		config.RequestWindow = time.Minute
	}
	if config.MinTargetInterval < 0 || config.DailySoftLimitBytes <= 0 || config.ActiveFailoverReservePercent < 0 || config.ActiveFailoverReservePercent > 100 {
		return nil, errors.New("invalid probe target interval or traffic budget")
	}
	return &Scheduler{
		config:     config,
		now:        time.Now,
		global:     make(chan struct{}, config.MaxConcurrency),
		perModem:   make(map[string]chan struct{}),
		lastTarget: make(map[string]time.Time),
		usage:      make(map[string]*ModemUsage),
	}, nil
}

func (scheduler *Scheduler) Acquire(ctx context.Context, request Request) (Admission, error) {
	if request.ModemID == "" || request.TargetID == "" || request.EstimatedBytes < 0 || !validClass(request.Class) {
		return Admission{}, errors.New("invalid probe scheduling request")
	}
	overage, deferred := scheduler.reserveBudget(request)
	if deferred {
		return Admission{Decision: DecisionDeferredBudget}, nil
	}
	select {
	case scheduler.global <- struct{}{}:
	case <-ctx.Done():
		scheduler.unreserveBudget(request)
		return Admission{}, ctx.Err()
	}
	modemSemaphore := scheduler.modemSemaphore(request.ModemID)
	select {
	case modemSemaphore <- struct{}{}:
	case <-ctx.Done():
		<-scheduler.global
		scheduler.unreserveBudget(request)
		return Admission{}, ctx.Err()
	}
	if err := scheduler.acquireRate(ctx, request.TargetID); err != nil {
		<-modemSemaphore
		<-scheduler.global
		scheduler.unreserveBudget(request)
		return Admission{}, err
	}
	scheduler.mutex.Lock()
	usage := scheduler.currentUsageLocked(request.ModemID)
	usage.Requests++
	scheduler.mutex.Unlock()
	return Admission{Decision: DecisionAdmitted, Overage: overage, Permit: &Permit{scheduler: scheduler, request: request}}, nil
}

// Release records observed response bytes and releases both concurrency slots.
// It is safe to call more than once; only the first call has an effect.
func (permit *Permit) Release(observedBytes int64) {
	if permit == nil || permit.scheduler == nil {
		return
	}
	permit.once.Do(func() {
		if observedBytes < 0 {
			observedBytes = 0
		}
		scheduler := permit.scheduler
		scheduler.mutex.Lock()
		usage := scheduler.currentUsageLocked(permit.request.ModemID)
		usage.ReservedBytes -= permit.request.EstimatedBytes
		if usage.ReservedBytes < 0 {
			usage.ReservedBytes = 0
		}
		usage.ObservedBytes += observedBytes
		if usage.ObservedBytes > scheduler.config.DailySoftLimitBytes {
			usage.OverageBytes = usage.ObservedBytes - scheduler.config.DailySoftLimitBytes
		}
		modemSemaphore := scheduler.perModem[permit.request.ModemID]
		scheduler.mutex.Unlock()
		<-modemSemaphore
		<-scheduler.global
	})
}

func (scheduler *Scheduler) Snapshot(modemID string) ModemUsage {
	scheduler.mutex.Lock()
	defer scheduler.mutex.Unlock()
	usage := scheduler.currentUsageLocked(modemID)
	return *usage
}

// Limits returns the immutable scheduler policy in a form suitable for a
// redacted operational status API. It contains no request history or secrets.
func (scheduler *Scheduler) Limits() Limits {
	if scheduler == nil {
		return Limits{}
	}
	config := scheduler.config
	return Limits{
		DailySoftLimitBytes:          config.DailySoftLimitBytes,
		StandbyLimitBytes:            config.DailySoftLimitBytes * int64(100-config.ActiveFailoverReservePercent) / 100,
		ActiveFailoverReservePercent: config.ActiveFailoverReservePercent,
		MaxConcurrency:               config.MaxConcurrency,
		MaxConcurrencyPerModem:       config.MaxConcurrencyPerModem,
		MaxRequestsPerWindow:         config.MaxRequestsPerWindow,
		RequestWindow:                config.RequestWindow,
		MinTargetInterval:            config.MinTargetInterval,
	}
}

func (scheduler *Scheduler) reserveBudget(request Request) (bool, bool) {
	scheduler.mutex.Lock()
	defer scheduler.mutex.Unlock()
	usage := scheduler.currentUsageLocked(request.ModemID)
	projected := usage.ObservedBytes + usage.ReservedBytes + request.EstimatedBytes
	standbyLimit := scheduler.config.DailySoftLimitBytes * int64(100-scheduler.config.ActiveFailoverReservePercent) / 100
	if request.Class == ClassStandby && projected > standbyLimit {
		return false, true
	}
	usage.ReservedBytes += request.EstimatedBytes
	return projected > scheduler.config.DailySoftLimitBytes, false
}

func (scheduler *Scheduler) unreserveBudget(request Request) {
	scheduler.mutex.Lock()
	defer scheduler.mutex.Unlock()
	usage := scheduler.currentUsageLocked(request.ModemID)
	usage.ReservedBytes -= request.EstimatedBytes
	if usage.ReservedBytes < 0 {
		usage.ReservedBytes = 0
	}
}

func (scheduler *Scheduler) acquireRate(ctx context.Context, targetID string) error {
	for {
		now := scheduler.now()
		scheduler.mutex.Lock()
		cutoff := now.Add(-scheduler.config.RequestWindow)
		firstValid := 0
		for firstValid < len(scheduler.requestTimes) && !scheduler.requestTimes[firstValid].After(cutoff) {
			firstValid++
		}
		if firstValid > 0 {
			scheduler.requestTimes = append([]time.Time(nil), scheduler.requestTimes[firstValid:]...)
		}
		waitUntil := now
		if len(scheduler.requestTimes) >= scheduler.config.MaxRequestsPerWindow {
			waitUntil = scheduler.requestTimes[0].Add(scheduler.config.RequestWindow)
		}
		if previous := scheduler.lastTarget[targetID]; scheduler.config.MinTargetInterval > 0 && previous.Add(scheduler.config.MinTargetInterval).After(waitUntil) {
			waitUntil = previous.Add(scheduler.config.MinTargetInterval)
		}
		if !waitUntil.After(now) {
			scheduler.requestTimes = append(scheduler.requestTimes, now)
			scheduler.lastTarget[targetID] = now
			scheduler.mutex.Unlock()
			return nil
		}
		scheduler.mutex.Unlock()
		timer := time.NewTimer(time.Until(waitUntil))
		select {
		case <-timer.C:
		case <-ctx.Done():
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			return ctx.Err()
		}
	}
}

func (scheduler *Scheduler) modemSemaphore(modemID string) chan struct{} {
	scheduler.mutex.Lock()
	defer scheduler.mutex.Unlock()
	semaphore := scheduler.perModem[modemID]
	if semaphore == nil {
		semaphore = make(chan struct{}, scheduler.config.MaxConcurrencyPerModem)
		scheduler.perModem[modemID] = semaphore
	}
	return semaphore
}

func (scheduler *Scheduler) currentUsageLocked(modemID string) *ModemUsage {
	day := scheduler.now().UTC().Format("2006-01-02")
	usage := scheduler.usage[modemID]
	if usage == nil || usage.Day != day {
		usage = &ModemUsage{Day: day}
		scheduler.usage[modemID] = usage
	}
	return usage
}

func validClass(value string) bool {
	switch value {
	case ClassStandby, ClassActive, ClassFailover:
		return true
	default:
		return false
	}
}

func DefaultConfig() Config {
	return Config{
		MaxConcurrency: 4, MaxConcurrencyPerModem: 2,
		MaxRequestsPerWindow: 30, RequestWindow: time.Minute,
		MinTargetInterval:            time.Second,
		DailySoftLimitBytes:          25 * 1024 * 1024,
		ActiveFailoverReservePercent: 30,
	}
}

func (usage ModemUsage) String() string {
	return fmt.Sprintf("day=%s requests=%d observed=%d reserved=%d overage=%d", usage.Day, usage.Requests, usage.ObservedBytes, usage.ReservedBytes, usage.OverageBytes)
}
