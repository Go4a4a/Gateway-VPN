package main

import (
	"bytes"
	"testing"
)

func TestStageVPSUpdateRequiresReleaseGateBoundary(t *testing.T) {
	arguments := []string{"--archive", "/tmp/candidate.tar.gz", "--current-version", "1.0.0", "--current-schema", "4", "--profile", "ubuntu-24.04", "--release-gate-only"}
	for name, getenv := range map[string]func(string) string{
		"missing environment": func(string) string { return "" },
		"wrong environment":   func(string) string { return "0" },
	} {
		t.Run(name, func(t *testing.T) {
			if code := run(arguments, getenv, &bytes.Buffer{}, &bytes.Buffer{}); code != 1 {
				t.Fatalf("run() code = %d, want 1", code)
			}
		})
	}
}
