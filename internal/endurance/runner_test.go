package endurance

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

type fakeRunnerClient struct {
	start      time.Time
	interval   time.Duration
	diagnostic []byte
	samples    int
	closed     bool
	sampleErr  error
}

func (client *fakeRunnerClient) Sample(context.Context) (Sample, error) {
	if client.sampleErr != nil {
		return Sample{}, client.sampleErr
	}
	stamp := client.start.Add(time.Duration(client.samples) * client.interval)
	rss, descriptors := uint64(64<<20), uint64(12)
	sample := Sample{
		SchemaVersion: 1, CollectedAt: stamp.Format(time.RFC3339Nano), UptimeSeconds: 3600 + int64(stamp.Sub(client.start)/time.Second), Goroutines: 20,
		HeapAllocBytes: 16 << 20, HeapInuseBytes: 20 << 20, StackInuseBytes: 1 << 20, GoRuntimeSysBytes: 32 << 20,
		MallocsTotal: 1000 + uint64(client.samples), FreesTotal: 900 + uint64(client.samples), LiveHeapObjects: 100,
		GCCyclesTotal: 10, GCPauseTotalNanoseconds: 1000, ProcessRSSBytes: &rss, OpenFileDescriptors: &descriptors,
	}
	client.samples++
	return sample, nil
}

func (client *fakeRunnerClient) Diagnostic(context.Context) ([]byte, string, error) {
	digest := sha256.Sum256(client.diagnostic)
	return append([]byte(nil), client.diagnostic...), hex.EncodeToString(digest[:]), nil
}

func (client *fakeRunnerClient) Close(context.Context) error {
	client.closed = true
	return nil
}

func TestRunnerWritesDurableSmokeArtifactsWithoutClaimingEndurance(t *testing.T) {
	policy := EvaluationPolicy{Profile: ProfileSmoke, Duration: 320 * time.Millisecond, Interval: 20 * time.Millisecond, Warmup: 40 * time.Millisecond, Window: 40 * time.Millisecond}
	parent := t.TempDir()
	directory, err := CreateRunDirectory(parent, policy.Profile, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	client := &fakeRunnerClient{start: time.Now().UTC(), interval: policy.Interval, diagnostic: diagnosticFixture(t, validRetentionSnapshot(), false)}
	report, err := (Runner{Client: client, Policy: policy, Environment: EnvironmentDeveloperLinux, OutputDirectory: directory}).Run(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if report.Status != "SMOKE_PASS" || !report.Evaluation.Passed || report.Evaluation.EnduranceGate || report.Evaluation.Samples != 17 || !client.closed {
		t.Fatalf("runner report = %+v closed=%t", report, client.closed)
	}
	for _, name := range []string{"run-state.json", "samples.ndjson", "diagnostic-start.zip", "diagnostic-end.zip", "report.json"} {
		info, err := os.Lstat(filepath.Join(directory, name))
		if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || (runtime.GOOS != "windows" && info.Mode().Perm() != 0o600) {
			t.Fatalf("artifact %s = %v %v", name, info, err)
		}
	}
	file, err := os.Open(filepath.Join(directory, "samples.ndjson"))
	if err != nil {
		t.Fatal(err)
	}
	scanner := bufio.NewScanner(file)
	lines := 0
	for scanner.Scan() {
		var sample Sample
		if json.Unmarshal(scanner.Bytes(), &sample) != nil || sample.SchemaVersion != 1 {
			t.Fatalf("invalid sample line: %s", scanner.Bytes())
		}
		lines++
	}
	file.Close()
	if scanner.Err() != nil || lines != 17 {
		t.Fatalf("sample lines = %d, %v", lines, scanner.Err())
	}
	stateContent, err := os.ReadFile(filepath.Join(directory, "run-state.json"))
	if err != nil || !strings.Contains(string(stateContent), `"status": "SMOKE_PASS"`) || strings.Contains(string(stateContent), "csrf") {
		t.Fatalf("run state = %s, %v", stateContent, err)
	}
}

func TestRunnerFailureStateDoesNotPersistBackendError(t *testing.T) {
	policy := EvaluationPolicy{Profile: ProfileSmoke, Duration: 200 * time.Millisecond, Interval: 20 * time.Millisecond, Warmup: 40 * time.Millisecond, Window: 40 * time.Millisecond}
	directory, err := CreateRunDirectory(t.TempDir(), policy.Profile, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	client := &fakeRunnerClient{start: time.Now().UTC(), interval: policy.Interval, diagnostic: diagnosticFixture(t, validRetentionSnapshot(), false), sampleErr: errors.New("password=backend-secret /root/private")}
	if _, err := (Runner{Client: client, Policy: policy, Environment: EnvironmentDeveloperLinux, OutputDirectory: directory}).Run(t.Context()); err == nil {
		t.Fatal("runner failure returned nil")
	}
	stateContent, err := os.ReadFile(filepath.Join(directory, "run-state.json"))
	if err != nil || !strings.Contains(string(stateContent), `"status": "FAILED"`) || !strings.Contains(string(stateContent), `"error_code": "ENDURANCE_RUN_FAILED"`) || strings.Contains(string(stateContent), "backend-secret") || strings.Contains(string(stateContent), "/root/private") {
		t.Fatalf("failed run state = %s, %v", stateContent, err)
	}
	if !client.closed {
		t.Fatal("failed runner did not close client")
	}
}

func TestRunnerRejectsReleaseOnNonHardwareOrUnstampedHarness(t *testing.T) {
	client := &fakeRunnerClient{}
	directory := filepath.Join(t.TempDir(), "not-created")
	if _, err := (Runner{Client: client, Policy: ReleasePolicy(), Environment: EnvironmentDeveloperLinux, HarnessRevision: strings.Repeat("a", 40), OutputDirectory: directory}).Run(t.Context()); err == nil {
		t.Fatal("release endurance accepted non-hardware environment")
	}
	if _, err := (Runner{Client: client, Policy: DeveloperPolicy(), Environment: EnvironmentDeveloperLinux, HarnessRevision: "unknown", OutputDirectory: directory}).Run(t.Context()); err == nil {
		t.Fatal("developer endurance accepted unstamped harness")
	}
}
