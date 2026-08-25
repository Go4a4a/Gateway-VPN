package webapi

import (
	"sync"
	"time"
)

const (
	diagnosticBundleLimit  = 3
	diagnosticBundleWindow = 10 * time.Minute
)

type diagnosticRateLimiter struct {
	mutex   sync.Mutex
	clients map[string]diagnosticRateState
}

type diagnosticRateState struct {
	windowStart time.Time
	requests    int
}

func newDiagnosticRateLimiter() *diagnosticRateLimiter {
	return &diagnosticRateLimiter{clients: make(map[string]diagnosticRateState)}
}

func (limiter *diagnosticRateLimiter) allow(key string, now time.Time) (bool, time.Duration) {
	if limiter == nil || key == "" {
		return false, diagnosticBundleWindow
	}
	limiter.mutex.Lock()
	defer limiter.mutex.Unlock()
	current := limiter.clients[key]
	if current.windowStart.IsZero() || !now.Before(current.windowStart.Add(diagnosticBundleWindow)) {
		limiter.clients[key] = diagnosticRateState{windowStart: now, requests: 1}
		limiter.cleanup(now)
		return true, 0
	}
	if current.requests >= diagnosticBundleLimit {
		return false, current.windowStart.Add(diagnosticBundleWindow).Sub(now)
	}
	current.requests++
	limiter.clients[key] = current
	return true, 0
}

func (limiter *diagnosticRateLimiter) cleanup(now time.Time) {
	if len(limiter.clients) <= 1024 {
		return
	}
	cutoff := now.Add(-2 * diagnosticBundleWindow)
	for key, current := range limiter.clients {
		if current.windowStart.Before(cutoff) {
			delete(limiter.clients, key)
		}
	}
}
