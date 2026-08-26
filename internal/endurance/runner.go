package endurance

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

type GatewayClient interface {
	Sample(context.Context) (Sample, error)
	Diagnostic(context.Context) ([]byte, string, error)
	Close(context.Context) error
}

type DiagnosticSummary struct {
	SHA256               string `json:"sha256"`
	Bytes                int64  `json:"bytes"`
	GatewayVersion       string `json:"gateway_version"`
	SchemaVersion        int64  `json:"database_schema_version"`
	DatabaseBytes        int64  `json:"database_bytes"`
	WALBytes             int64  `json:"wal_bytes"`
	LivePageBytes        int64  `json:"live_page_bytes"`
	HealthSampleRows     int64  `json:"health_sample_rows"`
	EventRows            int64  `json:"event_rows"`
	TrafficDailyRows     int64  `json:"traffic_daily_rows"`
	SubscriptionVersions int64  `json:"subscription_versions"`
}

type RunReport struct {
	SchemaVersion   int               `json:"schema_version"`
	Status          string            `json:"status"`
	Environment     Environment       `json:"environment"`
	HarnessRevision string            `json:"harness_revision"`
	HarnessModified bool              `json:"harness_modified"`
	Evaluation      Evaluation        `json:"evaluation"`
	StartDiagnostic DiagnosticSummary `json:"start_diagnostic"`
	EndDiagnostic   DiagnosticSummary `json:"end_diagnostic"`
}

type runState struct {
	SchemaVersion   int         `json:"schema_version"`
	Profile         Profile     `json:"profile"`
	Environment     Environment `json:"environment"`
	HarnessRevision string      `json:"harness_revision"`
	HarnessModified bool        `json:"harness_modified"`
	Status          string      `json:"status"`
	StartedAt       string      `json:"started_at"`
	ExpectedEndAt   string      `json:"expected_end_at"`
	CompletedAt     string      `json:"completed_at,omitempty"`
	Samples         int         `json:"samples"`
	ErrorCode       string      `json:"error_code,omitempty"`
}

type Runner struct {
	Client          GatewayClient
	Policy          EvaluationPolicy
	Environment     Environment
	HarnessRevision string
	HarnessModified bool
	OutputDirectory string
	Now             func() time.Time
}

type Environment string

const (
	EnvironmentDeveloperLinux  Environment = "developer-linux"
	EnvironmentHardwareGateway Environment = "hardware-gateway"
)

func CreateRunDirectory(parent string, profile Profile, now time.Time) (string, error) {
	if !filepath.IsAbs(parent) || profile == "" {
		return "", errors.New("absolute endurance output parent and profile are required")
	}
	info, err := os.Lstat(parent)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || (runtime.GOOS != "windows" && info.Mode().Perm()&0o022 != 0) {
		return "", errors.New("endurance output parent is unsafe")
	}
	prefix := "gateway-vpn-endurance-" + strings.ReplaceAll(string(profile), "-", "_") + "-" + now.UTC().Format("20060102T150405Z") + "-"
	directory, err := os.MkdirTemp(parent, prefix)
	if err != nil {
		return "", errors.New("create endurance output directory failed")
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		os.RemoveAll(directory)
		return "", errors.New("protect endurance output directory failed")
	}
	if err := syncEnduranceDirectory(parent); err != nil {
		os.RemoveAll(directory)
		return "", err
	}
	return directory, nil
}

func (runner Runner) Run(ctx context.Context) (report RunReport, err error) {
	if runner.Client == nil || !filepath.IsAbs(runner.OutputDirectory) {
		return RunReport{}, errors.New("endurance client and absolute output directory are required")
	}
	if err := runner.Policy.Validate(); err != nil {
		return RunReport{}, err
	}
	if runner.Environment != EnvironmentDeveloperLinux && runner.Environment != EnvironmentHardwareGateway {
		return RunReport{}, errors.New("endurance environment is invalid")
	}
	if runner.Policy.Profile == ProfileRelease && runner.Environment != EnvironmentHardwareGateway {
		return RunReport{}, errors.New("release endurance requires an explicitly attested hardware Gateway environment")
	}
	if runner.Policy.Profile != ProfileSmoke && (!validRevision(runner.HarnessRevision) || runner.HarnessModified) {
		return RunReport{}, errors.New("developer/release endurance requires a clean revision-identified harness binary")
	}
	if err := validateRunDirectory(runner.OutputDirectory); err != nil {
		return RunReport{}, err
	}
	now := runner.Now
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	started := now().UTC()
	state := runState{SchemaVersion: 1, Profile: runner.Policy.Profile, Environment: runner.Environment, HarnessRevision: runner.HarnessRevision, HarnessModified: runner.HarnessModified, Status: "RUNNING", StartedAt: started.Format(time.RFC3339Nano), ExpectedEndAt: started.Add(runner.Policy.Duration).Format(time.RFC3339Nano)}
	if err := writeRunJSON(runner.OutputDirectory, "run-state.json", state); err != nil {
		return RunReport{}, err
	}
	defer func() {
		closeContext, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if closeErr := runner.Client.Close(closeContext); closeErr != nil && err == nil {
			err = closeErr
		}
		if err != nil {
			state.Status = "FAILED"
			state.CompletedAt = now().UTC().Format(time.RFC3339Nano)
			state.ErrorCode = "ENDURANCE_RUN_FAILED"
			_ = writeRunJSON(runner.OutputDirectory, "run-state.json", state)
		}
	}()

	startContent, startSHA256, err := runner.Client.Diagnostic(ctx)
	if err != nil {
		return RunReport{}, err
	}
	startDiagnostic, err := InspectDiagnostic(startContent, startSHA256)
	if err != nil {
		return RunReport{}, err
	}
	if err := writeRunFile(runner.OutputDirectory, "diagnostic-start.zip", startContent); err != nil {
		return RunReport{}, err
	}

	sampleFile, err := os.OpenFile(filepath.Join(runner.OutputDirectory, "samples.ndjson"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return RunReport{}, errors.New("create endurance samples file failed")
	}
	writer := bufio.NewWriterSize(sampleFile, 64<<10)
	closeSamples := func() error {
		if err := writer.Flush(); err != nil {
			sampleFile.Close()
			return errors.New("flush endurance samples failed")
		}
		if err := sampleFile.Sync(); err != nil {
			sampleFile.Close()
			return errors.New("sync endurance samples failed")
		}
		if err := sampleFile.Close(); err != nil {
			return errors.New("close endurance samples failed")
		}
		return nil
	}
	samples := make([]Sample, 0, int(runner.Policy.Duration/runner.Policy.Interval)+1)
	collect := func() error {
		sample, err := runner.Client.Sample(ctx)
		if err != nil {
			return err
		}
		encoded, err := json.Marshal(sample)
		if err != nil {
			return errors.New("encode endurance sample failed")
		}
		if _, err := writer.Write(encoded); err != nil {
			return errors.New("write endurance sample failed")
		}
		if err := writer.WriteByte('\n'); err != nil {
			return errors.New("write endurance sample delimiter failed")
		}
		if err := writer.Flush(); err != nil {
			return errors.New("flush endurance sample failed")
		}
		if err := sampleFile.Sync(); err != nil {
			return errors.New("sync endurance sample failed")
		}
		samples = append(samples, sample)
		state.Samples = len(samples)
		if err := writeRunJSON(runner.OutputDirectory, "run-state.json", state); err != nil {
			return err
		}
		return nil
	}
	if err := collect(); err != nil {
		_ = closeSamples()
		return RunReport{}, err
	}
	deadline := started.Add(runner.Policy.Duration)
	for next := started.Add(runner.Policy.Interval); !next.After(deadline); next = next.Add(runner.Policy.Interval) {
		delay := time.Until(next)
		if runner.Now != nil {
			delay = next.Sub(now())
		}
		if delay < 0 {
			delay = 0
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			_ = closeSamples()
			return RunReport{}, ctx.Err()
		case <-timer.C:
		}
		if err := collect(); err != nil {
			_ = closeSamples()
			return RunReport{}, err
		}
	}
	if err := closeSamples(); err != nil {
		return RunReport{}, err
	}
	if err := syncEnduranceDirectory(runner.OutputDirectory); err != nil {
		return RunReport{}, err
	}

	endContent, endSHA256, err := runner.Client.Diagnostic(ctx)
	if err != nil {
		return RunReport{}, err
	}
	endDiagnostic, err := InspectDiagnostic(endContent, endSHA256)
	if err != nil {
		return RunReport{}, err
	}
	if err := writeRunFile(runner.OutputDirectory, "diagnostic-end.zip", endContent); err != nil {
		return RunReport{}, err
	}
	firstTime, _ := samples[0].Time()
	lastTime, _ := samples[len(samples)-1].Time()
	evaluation, err := Evaluate(samples, firstTime, lastTime, runner.Policy)
	if err != nil {
		return RunReport{}, err
	}
	if startDiagnostic.Manifest.GatewayVersion != endDiagnostic.Manifest.GatewayVersion || startDiagnostic.Integrity.SchemaVersion != endDiagnostic.Integrity.SchemaVersion {
		evaluation.addFinding("BUILD_OR_SCHEMA_CHANGED", "", "diagnostic build identity changed during run")
	}
	if evaluation.EnduranceGate && (strings.Contains(startDiagnostic.Manifest.GatewayVersion, "commit=unknown") || strings.Contains(startDiagnostic.Manifest.GatewayVersion, " 0.0.0-dev ")) {
		evaluation.addFinding("UNVERSIONED_GATEWAY_BUILD", "", "Gateway diagnostic identity is not an exact release build")
	}
	for _, finding := range endDiagnostic.Retention.PolicyFindings(lastTime) {
		evaluation.addFinding(finding.Code, finding.Metric, finding.Detail)
	}
	startLive, endLive := startDiagnostic.Retention.Storage.LivePageBytes, endDiagnostic.Retention.Storage.LivePageBytes
	if startLive > 0 && endLive > startLive {
		delta := endLive - startLive
		if delta > 32<<20 && float64(endLive) > float64(startLive)*1.10 {
			evaluation.addFinding("DATABASE_LIVE_PAGE_GROWTH", "database_live_page_bytes", fmt.Sprintf("start=%d end=%d", startLive, endLive))
		}
	}
	status := "FAILED"
	if evaluation.Passed {
		status = "SMOKE_PASS"
		if evaluation.EnduranceGate {
			status = "PASS"
		}
	}
	report = RunReport{
		SchemaVersion: 1, Status: status, Environment: runner.Environment, HarnessRevision: runner.HarnessRevision, HarnessModified: runner.HarnessModified, Evaluation: evaluation,
		StartDiagnostic: summarizeDiagnostic(startDiagnostic), EndDiagnostic: summarizeDiagnostic(endDiagnostic),
	}
	if err := writeRunJSON(runner.OutputDirectory, "report.json", report); err != nil {
		return RunReport{}, err
	}
	state.Status = status
	state.CompletedAt = now().UTC().Format(time.RFC3339Nano)
	state.ErrorCode = ""
	if err := writeRunJSON(runner.OutputDirectory, "run-state.json", state); err != nil {
		return RunReport{}, err
	}
	return report, nil
}

func validRevision(value string) bool {
	if len(value) != 40 && len(value) != 64 {
		return false
	}
	for _, character := range value {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

func summarizeDiagnostic(snapshot DiagnosticSnapshot) DiagnosticSummary {
	retention := snapshot.Retention
	return DiagnosticSummary{
		SHA256: snapshot.SHA256, Bytes: snapshot.Bytes, GatewayVersion: snapshot.Manifest.GatewayVersion, SchemaVersion: snapshot.Integrity.SchemaVersion,
		DatabaseBytes: retention.Storage.DatabaseBytes, WALBytes: retention.Storage.WALBytes, LivePageBytes: retention.Storage.LivePageBytes,
		HealthSampleRows: retention.HealthSamples.Rows, EventRows: retention.Events.Rows, TrafficDailyRows: retention.TrafficDailyTotals.Rows,
		SubscriptionVersions: retention.SubscriptionVersions.Total,
	}
}

func validateRunDirectory(directory string) error {
	info, err := os.Lstat(directory)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || (runtime.GOOS != "windows" && info.Mode().Perm() != 0o700) {
		return errors.New("endurance output directory is unsafe")
	}
	entries, err := os.ReadDir(directory)
	if err != nil || len(entries) != 0 {
		return errors.New("endurance output directory must be empty")
	}
	return nil
}

func writeRunFile(directory, name string, content []byte) error {
	if filepath.Base(name) != name || name == "." || name == ".." || len(content) == 0 {
		return errors.New("endurance artifact name or content is invalid")
	}
	file, err := os.OpenFile(filepath.Join(directory, name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return errors.New("create endurance artifact failed")
	}
	if _, err := file.Write(content); err != nil {
		file.Close()
		return errors.New("write endurance artifact failed")
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return errors.New("sync endurance artifact failed")
	}
	if err := file.Close(); err != nil {
		return errors.New("close endurance artifact failed")
	}
	return syncEnduranceDirectory(directory)
}

func writeRunJSON(directory, name string, value any) error {
	content, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return errors.New("encode endurance state failed")
	}
	content = append(content, '\n')
	temporary, err := os.CreateTemp(directory, ".endurance-state-*.tmp")
	if err != nil {
		return errors.New("create endurance state temporary file failed")
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return errors.New("protect endurance state temporary file failed")
	}
	if _, err := temporary.Write(content); err != nil {
		temporary.Close()
		return errors.New("write endurance state failed")
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return errors.New("sync endurance state failed")
	}
	if err := temporary.Close(); err != nil {
		return errors.New("close endurance state failed")
	}
	destination := filepath.Join(directory, name)
	if info, err := os.Lstat(destination); err == nil && (info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular()) {
		return errors.New("endurance state destination is unsafe")
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return errors.New("inspect endurance state destination failed")
	}
	if err := replaceEnduranceFile(temporaryPath, destination); err != nil {
		return errors.New("publish endurance state failed")
	}
	return syncEnduranceDirectory(directory)
}

func syncEnduranceDirectory(directory string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	handle, err := os.Open(directory)
	if err != nil {
		return errors.New("open endurance directory for sync failed")
	}
	defer handle.Close()
	if err := handle.Sync(); err != nil {
		return errors.New("sync endurance directory failed")
	}
	return nil
}
