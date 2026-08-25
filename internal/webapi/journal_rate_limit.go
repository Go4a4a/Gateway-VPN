package webapi

import (
	"sync"
	"time"
)

const (
	journalQueryLimit  = 20
	journalQueryWindow = time.Minute
)

type journalRateLimiter struct {
	mutex   sync.Mutex
	clients map[string]journalRateState
}

type journalRateState struct {
	windowStart time.Time
	requests    int
}

func newJournalRateLimiter() *journalRateLimiter {
	return &journalRateLimiter{clients: make(map[string]journalRateState)}
}

func (limiter *journalRateLimiter) allow(key string, now time.Time) (bool, time.Duration) {
	if limiter == nil || key == "" {
		return false, journalQueryWindow
	}
	limiter.mutex.Lock()
	defer limiter.mutex.Unlock()
	state := limiter.clients[key]
	if state.windowStart.IsZero() || !now.Before(state.windowStart.Add(journalQueryWindow)) {
		state = journalRateState{windowStart: now, requests: 1}
		limiter.clients[key] = state
		limiter.cleanup(now)
		return true, 0
	}
	if state.requests >= journalQueryLimit {
		return false, state.windowStart.Add(journalQueryWindow).Sub(now)
	}
	state.requests++
	limiter.clients[key] = state
	return true, 0
}

func (limiter *journalRateLimiter) cleanup(now time.Time) {
	if len(limiter.clients) <= 1024 {
		return
	}
	cutoff := now.Add(-2 * journalQueryWindow)
	for key, state := range limiter.clients {
		if state.windowStart.Before(cutoff) {
			delete(limiter.clients, key)
		}
	}
}
