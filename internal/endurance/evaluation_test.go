package endurance

import (
	"testing"
	"time"
)

func TestEvaluateStableSmokeRunPassesWithoutClaimingEnduranceGate(t *testing.T) {
	start := time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC)
	policy := EvaluationPolicy{Profile: ProfileSmoke, Duration: 20 * time.Second, Interval: 100 * time.Millisecond, Warmup: 2 * time.Second, Window: 2 * time.Second}
	samples := syntheticSamples(start, policy, func(_ int, sample *Sample) {})
	evaluation, err := Evaluate(samples, start, start.Add(policy.Duration), policy)
	if err != nil {
		t.Fatal(err)
	}
	if !evaluation.Passed || evaluation.EnduranceGate || len(evaluation.Findings) != 0 || evaluation.EvaluatedSamples == 0 || len(evaluation.Metrics) != 5 {
		t.Fatalf("stable evaluation = %+v", evaluation)
	}
}

func TestEvaluateDetectsDiscreteAndByteGrowth(t *testing.T) {
	start := time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC)
	policy := EvaluationPolicy{Profile: ProfileSmoke, Duration: 24 * time.Second, Interval: 100 * time.Millisecond, Warmup: 2 * time.Second, Window: 2 * time.Second}
	samples := syntheticSamples(start, policy, func(index int, sample *Sample) {
		elapsedWindow := int(time.Duration(index) * policy.Interval / policy.Window)
		sample.Goroutines += uint64(elapsedWindow)
		fd := *sample.OpenFileDescriptors + uint64(elapsedWindow)
		sample.OpenFileDescriptors = &fd
		rss := *sample.ProcessRSSBytes + uint64(elapsedWindow)*(8<<20)
		sample.ProcessRSSBytes = &rss
		sample.HeapAllocBytes += uint64(elapsedWindow) * (8 << 20)
		sample.MallocsTotal += uint64(elapsedWindow * 2000)
		sample.LiveHeapObjects = sample.MallocsTotal - sample.FreesTotal
	})
	evaluation, err := Evaluate(samples, start, start.Add(policy.Duration), policy)
	if err != nil {
		t.Fatal(err)
	}
	if evaluation.Passed || !hasFinding(evaluation, "UNBOUNDED_DISCRETE_GROWTH", "goroutines") || !hasFinding(evaluation, "UNBOUNDED_DISCRETE_GROWTH", "open_file_descriptors") || !hasFinding(evaluation, "SUSTAINED_RESOURCE_GROWTH", "process_rss_bytes") || !hasFinding(evaluation, "SUSTAINED_RESOURCE_GROWTH", "heap_alloc_bytes") || !hasFinding(evaluation, "SUSTAINED_RESOURCE_GROWTH", "live_heap_objects") {
		t.Fatalf("growth evaluation = %+v", evaluation)
	}
}

func TestEvaluateDetectsRestartAndGap(t *testing.T) {
	start := time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC)
	policy := EvaluationPolicy{Profile: ProfileSmoke, Duration: 20 * time.Second, Interval: 100 * time.Millisecond, Warmup: 2 * time.Second, Window: 2 * time.Second}
	samples := syntheticSamples(start, policy, func(_ int, sample *Sample) {})
	middle := len(samples) / 2
	samples[middle].UptimeSeconds = 1
	for index := middle + 1; index < len(samples); index++ {
		samples[index].CollectedAt = samples[index].TimeOrPanic().Add(300 * time.Millisecond).Format(time.RFC3339Nano)
	}
	evaluation, err := Evaluate(samples, start, start.Add(policy.Duration+300*time.Millisecond), policy)
	if err != nil {
		t.Fatal(err)
	}
	if evaluation.Passed || !hasFinding(evaluation, "PROCESS_RESTARTED", "uptime_seconds") || !hasFinding(evaluation, "SAMPLE_GAP", "") {
		t.Fatalf("restart evaluation = %+v", evaluation)
	}
}

func TestDeveloperAndReleasePoliciesCannotBeShortened(t *testing.T) {
	policy := DeveloperPolicy()
	policy.Duration--
	if err := policy.Validate(); err == nil {
		t.Fatal("shortened developer policy accepted")
	}
	policy = ReleasePolicy()
	policy.Interval += time.Second
	if err := policy.Validate(); err == nil {
		t.Fatal("modified release policy accepted")
	}
}

func syntheticSamples(start time.Time, policy EvaluationPolicy, mutate func(int, *Sample)) []Sample {
	count := int(policy.Duration/policy.Interval) + 1
	result := make([]Sample, 0, count)
	for index := 0; index < count; index++ {
		stamp := start.Add(time.Duration(index) * policy.Interval)
		rss, descriptors := uint64(64<<20), uint64(12)
		sample := Sample{
			SchemaVersion: SampleSchemaVersion, CollectedAt: stamp.Format(time.RFC3339Nano), UptimeSeconds: 3600 + int64(stamp.Sub(start)/time.Second),
			Goroutines: 20, HeapAllocBytes: 16 << 20, HeapInuseBytes: 20 << 20, StackInuseBytes: 1 << 20, GoRuntimeSysBytes: 32 << 20,
			MallocsTotal: 100000, FreesTotal: 90000, LiveHeapObjects: 10000, GCCyclesTotal: 10, GCPauseTotalNanoseconds: 1000,
			ProcessRSSBytes: &rss, OpenFileDescriptors: &descriptors,
		}
		mutate(index, &sample)
		result = append(result, sample)
	}
	return result
}

func (sample Sample) TimeOrPanic() time.Time {
	stamp, err := sample.Time()
	if err != nil {
		panic(err)
	}
	return stamp
}

func hasFinding(evaluation Evaluation, code, metric string) bool {
	for _, finding := range evaluation.Findings {
		if finding.Code == code && finding.Metric == metric {
			return true
		}
	}
	return false
}
