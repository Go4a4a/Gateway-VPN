package main

import (
	"testing"
	"time"

	"gateway-vpn/internal/endurance"
)

func TestSelectPolicyKeepsDeveloperAndReleaseDurationsFixed(t *testing.T) {
	developer, err := selectPolicy("developer", time.Second, time.Millisecond)
	if err != nil || developer != endurance.DeveloperPolicy() {
		t.Fatalf("developer policy = %+v, %v", developer, err)
	}
	release, err := selectPolicy("release", time.Second, time.Millisecond)
	if err != nil || release != endurance.ReleasePolicy() {
		t.Fatalf("release policy = %+v, %v", release, err)
	}
	smoke, err := selectPolicy("smoke", 10*time.Second, 100*time.Millisecond)
	if err != nil || smoke.Profile != endurance.ProfileSmoke || smoke.Duration != 10*time.Second || smoke.Interval != 100*time.Millisecond {
		t.Fatalf("smoke policy = %+v, %v", smoke, err)
	}
	if _, err := selectPolicy("short-release", time.Second, time.Millisecond); err == nil {
		t.Fatal("unknown policy accepted")
	}
}

func TestTrimCredentialNewlinePreservesPasswordBytes(t *testing.T) {
	if got := string(trimCredentialNewline([]byte("  secret password  \r\n"))); got != "  secret password  " {
		t.Fatalf("trimCredentialNewline() = %q", got)
	}
	if got := trimCredentialNewline([]byte("secret\ninside")); got != nil {
		t.Fatalf("embedded newline accepted: %q", got)
	}
}
