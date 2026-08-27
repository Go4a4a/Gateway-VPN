package subscription

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const maximumRetryAfter = 24 * time.Hour

type retryAfterError struct {
	err   error
	delay time.Duration
}

func (current *retryAfterError) Error() string { return current.err.Error() }
func (current *retryAfterError) Unwrap() error { return current.err }

// WithRetryAfter preserves a safe underlying error while carrying a bounded
// server-requested delay through route fallbacks into the durable scheduler.
func WithRetryAfter(err error, delay time.Duration) error {
	if err == nil || delay <= 0 {
		return err
	}
	if delay > maximumRetryAfter {
		delay = maximumRetryAfter
	}
	return &retryAfterError{err: err, delay: delay}
}

func FetchRetryAfter(err error) (time.Duration, bool) {
	var current *retryAfterError
	if !errors.As(err, &current) || current.delay <= 0 {
		return 0, false
	}
	return current.delay, true
}

func parseRetryAfter(value string, now time.Time) time.Duration {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > 128 || strings.ContainsAny(value, "\r\n") {
		return 0
	}
	if seconds, err := strconv.ParseInt(value, 10, 64); err == nil {
		if seconds <= 0 {
			return 0
		}
		delay := time.Duration(seconds) * time.Second
		if delay > maximumRetryAfter || delay < 0 {
			return maximumRetryAfter
		}
		return delay
	}
	requested, err := http.ParseTime(value)
	if err != nil || !requested.After(now) {
		return 0
	}
	delay := requested.Sub(now)
	if delay > maximumRetryAfter {
		return maximumRetryAfter
	}
	return delay
}
