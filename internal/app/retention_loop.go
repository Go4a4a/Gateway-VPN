package app

import (
	"context"
	"errors"
	"time"

	"gateway-vpn/internal/watchdog"
)

const (
	defaultRetentionInterval     = 10 * time.Minute
	defaultRetentionBacklogDelay = 250 * time.Millisecond
)

// runRetentionLoop immediately applies one bounded cleanup pass. A known
// backlog is drained through additional small transactions, while errors use
// the normal interval so a persistent filesystem or database fault cannot
// create a tight retry loop.
func (application *Runtime) runRetentionLoop(ctx context.Context) error {
	if application == nil || application.Retention == nil || application.logger == nil {
		return errors.New("database retention cleaner and logger are required")
	}
	idleInterval := application.retentionInterval
	if idleInterval <= 0 {
		idleInterval = defaultRetentionInterval
	}
	backlogDelay := application.retentionBacklogDelay
	if backlogDelay <= 0 {
		backlogDelay = defaultRetentionBacklogDelay
	}
	for {
		result, err := application.Retention.CleanBatch(ctx)
		application.workerProgress.mark(watchdog.WorkerRetention)
		if ctx.Err() != nil {
			return nil
		}
		if err != nil {
			application.logger.Warn("database retention pass failed",
				"health_samples_deleted", result.HealthSamplesDeleted,
				"events_deleted", result.EventsDeleted,
				"traffic_days_deleted", result.TrafficDaysDeleted,
				"subscription_versions_deleted", result.SubscriptionVersionsDeleted,
				"payload_directories_deleted", result.PayloadDirectoriesDeleted,
				"error", err)
		} else if result.TotalDeleted() != 0 {
			application.logger.Info("database retention pass completed",
				"health_samples_deleted", result.HealthSamplesDeleted,
				"events_deleted", result.EventsDeleted,
				"traffic_days_deleted", result.TrafficDaysDeleted,
				"subscription_versions_deleted", result.SubscriptionVersionsDeleted,
				"payload_directories_deleted", result.PayloadDirectoriesDeleted,
				"backlog", result.HasMore)
		}
		delay := idleInterval
		if err == nil && result.HasMore {
			delay = backlogDelay
		}
		timer := time.NewTimer(delay)
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
