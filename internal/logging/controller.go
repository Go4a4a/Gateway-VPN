package logging

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"sync"
	"time"
)

type Controller struct {
	mutex      sync.RWMutex
	updateLock sync.Mutex
	repository *Repository
	settings   Settings
	now        func() time.Time
	wake       chan struct{}

	OnError func(error)
}

func NewController(initial Settings, now func() time.Time) (*Controller, error) {
	if err := initial.Validate(); err != nil {
		return nil, err
	}
	if now == nil {
		now = time.Now
	}
	return &Controller{settings: cloneSettings(initial), now: now, wake: make(chan struct{}, 1)}, nil
}

func (controller *Controller) Attach(ctx context.Context, database *sql.DB) error {
	if controller == nil || database == nil {
		return errors.New("logging controller and database are required")
	}
	controller.updateLock.Lock()
	defer controller.updateLock.Unlock()
	repository := &Repository{Database: database, Now: controller.nowUTC}
	settings, _, err := repository.ExpireDebug(ctx)
	if err != nil {
		return err
	}
	controller.mutex.Lock()
	controller.repository = repository
	controller.settings = cloneSettings(settings)
	controller.mutex.Unlock()
	controller.signal()
	return nil
}

func (controller *Controller) Update(ctx context.Context, input UpdateInput) (Settings, error) {
	if controller == nil {
		return Settings{}, errors.New("logging controller is required")
	}
	controller.updateLock.Lock()
	defer controller.updateLock.Unlock()
	controller.mutex.RLock()
	repository := controller.repository
	controller.mutex.RUnlock()
	if repository == nil {
		return Settings{}, errors.New("logging controller is not attached")
	}
	settings, err := repository.Update(ctx, input)
	if err != nil {
		return Settings{}, err
	}
	controller.publish(settings)
	return controller.Snapshot(), nil
}

func (controller *Controller) RecoverExpired(ctx context.Context) (Settings, bool, error) {
	if controller == nil {
		return Settings{}, false, errors.New("logging controller is required")
	}
	controller.updateLock.Lock()
	defer controller.updateLock.Unlock()
	controller.mutex.RLock()
	repository := controller.repository
	controller.mutex.RUnlock()
	if repository == nil {
		return Settings{}, false, errors.New("logging controller is not attached")
	}
	settings, changed, err := repository.ExpireDebug(ctx)
	if err != nil {
		return Settings{}, false, err
	}
	controller.publish(settings)
	return controller.Snapshot(), changed, nil
}

func (controller *Controller) Snapshot() Settings {
	if controller == nil {
		return DefaultSettings()
	}
	controller.mutex.RLock()
	settings := cloneSettings(controller.settings)
	controller.mutex.RUnlock()
	if settings.DebugUntil != "" {
		deadline, err := time.Parse(time.RFC3339Nano, settings.DebugUntil)
		if err != nil || !deadline.After(controller.nowUTC()) {
			settings.DebugComponents = []string{}
			settings.DebugUntil = ""
		}
	}
	return settings
}

func (controller *Controller) Enabled(component string, level slog.Level) bool {
	settings := controller.Snapshot()
	return level >= settings.Threshold(component, controller.nowUTC())
}

func (controller *Controller) MinimumThreshold() slog.Level {
	settings := controller.Snapshot()
	return settings.MinimumThreshold(controller.nowUTC())
}

func (controller *Controller) AggregationWindow() time.Duration {
	return controller.Snapshot().AggregationWindow()
}

func (controller *Controller) DebugRemaining() time.Duration {
	settings := controller.Snapshot()
	if settings.DebugUntil == "" {
		return 0
	}
	deadline, err := time.Parse(time.RFC3339Nano, settings.DebugUntil)
	if err != nil {
		return 0
	}
	remaining := deadline.Sub(controller.nowUTC())
	if remaining < 0 {
		return 0
	}
	return remaining
}

func (controller *Controller) Run(ctx context.Context) error {
	if controller == nil {
		return errors.New("logging controller is required")
	}
	controller.mutex.RLock()
	attached := controller.repository != nil
	controller.mutex.RUnlock()
	if !attached {
		return errors.New("logging controller is not attached")
	}
	for {
		settings := controller.rawSnapshot()
		wait := time.Duration(-1)
		if settings.DebugUntil != "" {
			if deadline, err := time.Parse(time.RFC3339Nano, settings.DebugUntil); err == nil {
				wait = deadline.Sub(controller.nowUTC())
			} else {
				wait = 0
			}
		}
		if wait <= 0 && wait != -1 {
			if _, _, err := controller.RecoverExpired(ctx); err != nil && ctx.Err() == nil {
				if controller.OnError != nil {
					controller.OnError(err)
				}
				wait = 5 * time.Second
			} else {
				continue
			}
		}
		var timer *time.Timer
		var timerChannel <-chan time.Time
		if wait >= 0 {
			timer = time.NewTimer(wait)
			timerChannel = timer.C
		}
		select {
		case <-ctx.Done():
			if timer != nil {
				timer.Stop()
			}
			return nil
		case <-controller.wake:
			if timer != nil {
				timer.Stop()
			}
		case <-timerChannel:
		}
	}
}

func (controller *Controller) rawSnapshot() Settings {
	controller.mutex.RLock()
	defer controller.mutex.RUnlock()
	return cloneSettings(controller.settings)
}

func (controller *Controller) publish(settings Settings) {
	controller.mutex.Lock()
	controller.settings = cloneSettings(settings)
	controller.mutex.Unlock()
	controller.signal()
}

func (controller *Controller) signal() {
	select {
	case controller.wake <- struct{}{}:
	default:
	}
}

func (controller *Controller) nowUTC() time.Time {
	return controller.now().UTC()
}
