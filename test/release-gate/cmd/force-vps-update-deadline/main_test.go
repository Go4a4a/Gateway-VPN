package main

import (
	"bytes"
	"testing"
	"time"
)

func TestForceVPSUpdateDeadlineRequiresReleaseGateBoundary(t *testing.T) {
	if code := run([]string{"--expected-update-id", "vps-update-test", "--release-gate-only"}, func(string) string { return "" }, time.Now, &bytes.Buffer{}, &bytes.Buffer{}); code != 1 {
		t.Fatalf("run() code = %d, want 1", code)
	}
}
