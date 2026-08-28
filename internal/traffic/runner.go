package traffic

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"time"

	"gateway-vpn/internal/mihomo"
)

const DefaultCheckpointInterval = 30 * time.Second

type AuthoritativeReader interface {
	ReadTrafficCounters(context.Context) (AuthoritativeSnapshot, error)
}

type MihomoReader interface {
	Traffic(context.Context) (mihomo.TrafficSnapshot, error)
}

type Runner struct {
	Collector        Collector
	Authoritative    AuthoritativeReader
	Mihomo           MihomoReader
	Interval         time.Duration
	SessionID        string
	SessionStartedAt time.Time
	Now              func() time.Time
	OnError          func(error)
	OnCheckpoint     func()
}

func NewSessionID() (string, error) {
	content := make([]byte, 32)
	if _, err := rand.Read(content); err != nil {
		return "", errors.New("create traffic session id failed")
	}
	return hex.EncodeToString(content), nil
}

func (runner *Runner) Run(ctx context.Context) error {
	if err := runner.validate(); err != nil {
		return err
	}
	interval := runner.Interval
	if interval == 0 {
		interval = DefaultCheckpointInterval
	}
	run := func(checkpointContext context.Context) {
		if _, err := runner.Checkpoint(checkpointContext); err != nil && checkpointContext.Err() == nil && runner.OnError != nil {
			runner.OnError(err)
		}
		if runner.OnCheckpoint != nil {
			runner.OnCheckpoint()
		}
	}
	run(ctx)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			// The control process is still alive during worker shutdown. Use a
			// fresh bounded context for the promised graceful final checkpoint.
			finalContext, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			run(finalContext)
			cancel()
			return nil
		case <-ticker.C:
			run(ctx)
		}
	}
}

func (runner *Runner) Checkpoint(ctx context.Context) (CheckpointResult, error) {
	if err := runner.validate(); err != nil {
		return CheckpointResult{}, err
	}
	authoritative, err := runner.Authoritative.ReadTrafficCounters(ctx)
	if err != nil {
		return CheckpointResult{}, err
	}
	sample := Sample{
		MeasuredAt: runner.now(), NFT: authoritative.Counters,
		BootID: authoritative.BootID, FirewallGeneration: authoritative.FirewallGeneration,
		SessionID: runner.SessionID, SessionStartedAt: runner.SessionStartedAt,
	}
	if runner.Mihomo != nil {
		mihomoSample, mihomoErr := runner.Mihomo.Traffic(ctx)
		if mihomoErr == nil {
			sample.MihomoAvailable = true
			sample.MihomoUploadTotal = mihomoSample.UploadTotal
			sample.MihomoDownloadTotal = mihomoSample.DownloadTotal
			sample.CurrentUploadBPS = mihomoSample.UploadBPS
			sample.CurrentDownloadBPS = mihomoSample.DownloadBPS
		}
	}
	return runner.Collector.Checkpoint(ctx, sample)
}

func (runner *Runner) validate() error {
	if runner == nil || runner.Collector.Database == nil || runner.Authoritative == nil || !validSessionID(runner.SessionID) || runner.SessionStartedAt.IsZero() || runner.Interval < 0 {
		return errors.New("complete traffic checkpoint runner configuration is required")
	}
	return nil
}

func (runner *Runner) now() time.Time {
	if runner.Now != nil {
		return runner.Now().UTC()
	}
	return time.Now().UTC()
}
