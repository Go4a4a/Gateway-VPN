// Package endurance contains the reproducible developer/release endurance
// collector and evaluator. It consumes only the authenticated, secret-free
// Gateway VPN API and never records credentials or session material.
package endurance

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"time"
)

const SampleSchemaVersion = 1

type Sample struct {
	SchemaVersion           int     `json:"schema_version"`
	CollectedAt             string  `json:"collected_at"`
	UptimeSeconds           int64   `json:"uptime_seconds"`
	Goroutines              uint64  `json:"goroutines"`
	HeapAllocBytes          uint64  `json:"heap_alloc_bytes"`
	HeapInuseBytes          uint64  `json:"heap_inuse_bytes"`
	StackInuseBytes         uint64  `json:"stack_inuse_bytes"`
	GoRuntimeSysBytes       uint64  `json:"go_runtime_sys_bytes"`
	MallocsTotal            uint64  `json:"mallocs_total"`
	FreesTotal              uint64  `json:"frees_total"`
	LiveHeapObjects         uint64  `json:"live_heap_objects"`
	GCCyclesTotal           uint64  `json:"gc_cycles_total"`
	GCPauseTotalNanoseconds uint64  `json:"gc_pause_total_nanoseconds"`
	ProcessRSSBytes         *uint64 `json:"process_rss_bytes,omitempty"`
	OpenFileDescriptors     *uint64 `json:"open_file_descriptors,omitempty"`
}

func DecodeSample(reader io.Reader) (Sample, error) {
	content, err := io.ReadAll(io.LimitReader(reader, maximumAPIJSONBytes+1))
	if err != nil || int64(len(content)) > maximumAPIJSONBytes {
		return Sample{}, errors.New("runtime metrics exceed their size bound")
	}
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	var sample Sample
	if err := decoder.Decode(&sample); err != nil {
		return Sample{}, errors.New("decode runtime metrics failed")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return Sample{}, errors.New("runtime metrics contain trailing data")
	}
	if err := sample.Validate(false); err != nil {
		return Sample{}, err
	}
	return sample, nil
}

func (sample Sample) Time() (time.Time, error) {
	return time.Parse(time.RFC3339Nano, sample.CollectedAt)
}

func (sample Sample) Validate(requireLinux bool) error {
	if sample.SchemaVersion != SampleSchemaVersion || sample.UptimeSeconds < 0 || sample.Goroutines < 1 {
		return errors.New("runtime metrics schema or counters are invalid")
	}
	stamp, err := sample.Time()
	if err != nil || stamp.Location() != time.UTC {
		return errors.New("runtime metrics timestamp is invalid")
	}
	if sample.FreesTotal > sample.MallocsTotal || sample.LiveHeapObjects != sample.MallocsTotal-sample.FreesTotal {
		return errors.New("runtime allocation counters are inconsistent")
	}
	if requireLinux && (sample.ProcessRSSBytes == nil || sample.OpenFileDescriptors == nil) {
		return errors.New("Linux runtime metrics are required")
	}
	return nil
}
