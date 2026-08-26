package endurance

import (
	"errors"
	"math"
	"sort"
	"time"
)

const (
	DeveloperDuration = 24 * time.Hour
	ReleaseDuration   = 72 * time.Hour
	SampleInterval    = time.Minute
	WarmupDuration    = 30 * time.Minute
	WindowDuration    = 30 * time.Minute
	byteGrowthFloor   = float64(32 << 20)
)

type Profile string

const (
	ProfileDeveloper Profile = "developer-24h"
	ProfileRelease   Profile = "release-72h"
	ProfileSmoke     Profile = "smoke"
)

type EvaluationPolicy struct {
	Profile  Profile       `json:"profile"`
	Duration time.Duration `json:"-"`
	Interval time.Duration `json:"-"`
	Warmup   time.Duration `json:"-"`
	Window   time.Duration `json:"-"`
}

func DeveloperPolicy() EvaluationPolicy {
	return EvaluationPolicy{Profile: ProfileDeveloper, Duration: DeveloperDuration, Interval: SampleInterval, Warmup: WarmupDuration, Window: WindowDuration}
}

func ReleasePolicy() EvaluationPolicy {
	return EvaluationPolicy{Profile: ProfileRelease, Duration: ReleaseDuration, Interval: SampleInterval, Warmup: WarmupDuration, Window: WindowDuration}
}

func SmokePolicy(duration, interval time.Duration) EvaluationPolicy {
	warmup := duration / 5
	window := duration / 5
	if warmup < interval {
		warmup = interval
	}
	if window < interval {
		window = interval
	}
	return EvaluationPolicy{Profile: ProfileSmoke, Duration: duration, Interval: interval, Warmup: warmup, Window: window}
}

func (policy EvaluationPolicy) Validate() error {
	if policy.Duration <= 0 || policy.Interval <= 0 || policy.Warmup < 0 || policy.Window <= 0 || policy.Warmup >= policy.Duration || policy.Window > policy.Duration-policy.Warmup {
		return errors.New("endurance evaluation policy is invalid")
	}
	if policy.Duration/policy.Interval > 10000 || (policy.Duration-policy.Warmup)/policy.Window < 2 {
		return errors.New("endurance evaluation sample or window count is outside bounds")
	}
	switch policy.Profile {
	case ProfileDeveloper:
		if policy != DeveloperPolicy() {
			return errors.New("developer endurance policy cannot be shortened")
		}
	case ProfileRelease:
		if policy != ReleasePolicy() {
			return errors.New("release endurance policy cannot be shortened")
		}
	case ProfileSmoke:
		if policy.Duration > time.Hour || policy.Interval < 10*time.Millisecond {
			return errors.New("smoke endurance policy is outside test bounds")
		}
	default:
		return errors.New("endurance profile is invalid")
	}
	return nil
}

type Finding struct {
	Code   string `json:"code"`
	Metric string `json:"metric,omitempty"`
	Detail string `json:"detail,omitempty"`
}

type MetricSummary struct {
	FirstWindowMedian float64 `json:"first_window_median"`
	LastWindowMedian  float64 `json:"last_window_median"`
	Minimum           float64 `json:"minimum"`
	Maximum           float64 `json:"maximum"`
	SlopePerHour      float64 `json:"slope_per_hour"`
	Windows           int     `json:"windows"`
}

type Evaluation struct {
	Profile          Profile                  `json:"profile"`
	Passed           bool                     `json:"passed"`
	EnduranceGate    bool                     `json:"endurance_gate"`
	Samples          int                      `json:"samples"`
	EvaluatedSamples int                      `json:"evaluated_samples"`
	StartedAt        string                   `json:"started_at"`
	EndedAt          string                   `json:"ended_at"`
	Metrics          map[string]MetricSummary `json:"metrics"`
	Findings         []Finding                `json:"findings"`
}

type metricDefinition struct {
	name      string
	value     func(Sample) (float64, bool)
	bounded   bool
	byteValue bool
}

func Evaluate(samples []Sample, startedAt, endedAt time.Time, policy EvaluationPolicy) (Evaluation, error) {
	if err := policy.Validate(); err != nil {
		return Evaluation{}, err
	}
	startedAt, endedAt = startedAt.UTC(), endedAt.UTC()
	if !endedAt.After(startedAt) || endedAt.Sub(startedAt) < policy.Duration-policy.Interval {
		return Evaluation{}, errors.New("endurance observation duration is incomplete")
	}
	evaluation := Evaluation{
		Profile: policy.Profile, Passed: true, EnduranceGate: policy.Profile != ProfileSmoke,
		Samples: len(samples), StartedAt: startedAt.Format(time.RFC3339Nano), EndedAt: endedAt.Format(time.RFC3339Nano),
		Metrics: map[string]MetricSummary{}, Findings: []Finding{},
	}
	if len(samples) < 2 {
		return Evaluation{}, errors.New("endurance samples are incomplete")
	}
	times := make([]time.Time, len(samples))
	for index, sample := range samples {
		if err := sample.Validate(policy.Profile != ProfileSmoke); err != nil {
			return Evaluation{}, err
		}
		stamp, _ := sample.Time()
		times[index] = stamp
		if stamp.Before(startedAt.Add(-policy.Interval)) || stamp.After(endedAt.Add(policy.Interval)) || (index > 0 && !stamp.After(times[index-1])) {
			return Evaluation{}, errors.New("endurance sample timestamps are invalid")
		}
		if index > 0 {
			if stamp.Sub(times[index-1]) > 2*policy.Interval {
				evaluation.addFinding("SAMPLE_GAP", "", stamp.Sub(times[index-1]).String())
			}
			if sample.UptimeSeconds < samples[index-1].UptimeSeconds {
				evaluation.addFinding("PROCESS_RESTARTED", "uptime_seconds", "uptime decreased")
			}
		}
	}
	evaluatedStart := startedAt.Add(policy.Warmup)
	first := sort.Search(len(times), func(index int) bool { return !times[index].Before(evaluatedStart) })
	if first >= len(samples) {
		return Evaluation{}, errors.New("no endurance samples remain after warm-up")
	}
	evaluated := samples[first:]
	evaluatedTimes := times[first:]
	evaluation.EvaluatedSamples = len(evaluated)
	definitions := []metricDefinition{
		{name: "goroutines", value: func(sample Sample) (float64, bool) { return float64(sample.Goroutines), true }, bounded: true},
		{name: "open_file_descriptors", value: func(sample Sample) (float64, bool) {
			if sample.OpenFileDescriptors == nil {
				return 0, false
			}
			return float64(*sample.OpenFileDescriptors), true
		}, bounded: true},
		{name: "process_rss_bytes", value: func(sample Sample) (float64, bool) {
			if sample.ProcessRSSBytes == nil {
				return 0, false
			}
			return float64(*sample.ProcessRSSBytes), true
		}, byteValue: true},
		{name: "heap_alloc_bytes", value: func(sample Sample) (float64, bool) { return float64(sample.HeapAllocBytes), true }, byteValue: true},
		{name: "live_heap_objects", value: func(sample Sample) (float64, bool) { return float64(sample.LiveHeapObjects), true }},
	}
	for _, definition := range definitions {
		windows, err := metricWindows(evaluated, evaluatedTimes, evaluatedStart, policy.Window, definition.value)
		if err != nil {
			return Evaluation{}, err
		}
		summary := summarizeWindows(windows, policy.Window)
		evaluation.Metrics[definition.name] = summary
		if definition.bounded && unreturnedSixWindowGrowth(windows) {
			evaluation.addFinding("UNBOUNDED_DISCRETE_GROWTH", definition.name, "six increasing windows and no return within +5")
		}
		if !definition.bounded && sustainedLeak(windows, definition.byteValue) {
			evaluation.addFinding("SUSTAINED_RESOURCE_GROWTH", definition.name, "positive slope and last-hour median exceeds first-hour median")
		}
	}
	return evaluation, nil
}

func (evaluation *Evaluation) addFinding(code, metric, detail string) {
	evaluation.Passed = false
	evaluation.Findings = append(evaluation.Findings, Finding{Code: code, Metric: metric, Detail: detail})
}

func metricWindows(samples []Sample, times []time.Time, origin time.Time, window time.Duration, value func(Sample) (float64, bool)) ([][]float64, error) {
	if len(samples) != len(times) {
		return nil, errors.New("endurance sample timestamps mismatch")
	}
	windows := make([][]float64, 0)
	for index, sample := range samples {
		current, ok := value(sample)
		if !ok {
			return nil, errors.New("required endurance metric is unavailable")
		}
		bucket := int(times[index].Sub(origin) / window)
		if bucket < 0 || bucket > 10000 {
			return nil, errors.New("endurance metric window is invalid")
		}
		for len(windows) <= bucket {
			windows = append(windows, nil)
		}
		windows[bucket] = append(windows[bucket], current)
	}
	compacted := make([][]float64, 0, len(windows))
	for _, values := range windows {
		if len(values) != 0 {
			compacted = append(compacted, values)
		}
	}
	if len(compacted) < 2 {
		return nil, errors.New("insufficient endurance metric windows")
	}
	return compacted, nil
}

func summarizeWindows(windows [][]float64, window time.Duration) MetricSummary {
	medians := windowMedians(windows)
	minimum, maximum := medians[0], medians[0]
	for _, value := range medians[1:] {
		minimum = math.Min(minimum, value)
		maximum = math.Max(maximum, value)
	}
	return MetricSummary{
		FirstWindowMedian: medians[0], LastWindowMedian: medians[len(medians)-1], Minimum: minimum, Maximum: maximum,
		SlopePerHour: linearSlope(medians) * float64(time.Hour) / float64(window), Windows: len(medians),
	}
}

func windowMedians(windows [][]float64) []float64 {
	result := make([]float64, 0, len(windows))
	for _, values := range windows {
		copyValues := append([]float64(nil), values...)
		sort.Float64s(copyValues)
		middle := len(copyValues) / 2
		if len(copyValues)%2 == 0 {
			result = append(result, (copyValues[middle-1]+copyValues[middle])/2)
		} else {
			result = append(result, copyValues[middle])
		}
	}
	return result
}

func unreturnedSixWindowGrowth(windows [][]float64) bool {
	medians := windowMedians(windows)
	for start := 0; start+6 < len(medians); start++ {
		increasing := true
		for index := start + 1; index <= start+6; index++ {
			if medians[index] <= medians[index-1] {
				increasing = false
				break
			}
		}
		if increasing && medians[len(medians)-1] > medians[start]+5 {
			return true
		}
	}
	return false
}

func sustainedLeak(windows [][]float64, byteValue bool) bool {
	medians := windowMedians(windows)
	if len(medians) < 4 || linearSlope(medians) <= 0 {
		return false
	}
	firstHour := medianSlice(medians[:min(2, len(medians))])
	lastHour := medianSlice(medians[max(0, len(medians)-2):])
	delta := lastHour - firstHour
	if firstHour <= 0 || lastHour <= firstHour*1.10 || (byteValue && delta < byteGrowthFloor) {
		return false
	}
	nonnegative := 0
	for index := 1; index < len(medians); index++ {
		if medians[index] >= medians[index-1] {
			nonnegative++
		}
	}
	return float64(nonnegative)/float64(len(medians)-1) >= 0.70
}

func medianSlice(values []float64) float64 {
	copyValues := append([]float64(nil), values...)
	sort.Float64s(copyValues)
	middle := len(copyValues) / 2
	if len(copyValues)%2 == 0 {
		return (copyValues[middle-1] + copyValues[middle]) / 2
	}
	return copyValues[middle]
}

func linearSlope(values []float64) float64 {
	if len(values) < 2 {
		return 0
	}
	meanX := float64(len(values)-1) / 2
	var meanY float64
	for _, value := range values {
		meanY += value
	}
	meanY /= float64(len(values))
	var numerator, denominator float64
	for index, value := range values {
		x := float64(index) - meanX
		numerator += x * (value - meanY)
		denominator += x * x
	}
	if denominator == 0 {
		return 0
	}
	return numerator / denominator
}
