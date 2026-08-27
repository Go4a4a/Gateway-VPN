package main

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunRequiresBothReleaseGateConfirmations(t *testing.T) {
	base := []string{
		"--archive", filepath.Join(t.TempDir(), "candidate.tar.gz"),
		"--config", filepath.Join(t.TempDir(), "config.yaml"),
		"--trusted-key", filepath.Join(t.TempDir(), "update-signing.pub"),
		"--current-release-root", filepath.Join(t.TempDir(), "v0.1.0-old"),
		"--current-version", "0.1.0-old",
	}
	for _, test := range []struct {
		name      string
		env       string
		confirmed bool
	}{
		{name: "neither"},
		{name: "environment only", env: "1"},
		{name: "flag only", confirmed: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			arguments := append([]string(nil), base...)
			if test.confirmed {
				arguments = append(arguments, "--release-gate-only")
			}
			var stderr bytes.Buffer
			code := run(arguments, func(string) string { return test.env }, &bytes.Buffer{}, &stderr)
			if code != 1 || !strings.Contains(stderr.String(), "environment and explicit confirmation") {
				t.Fatalf("run() = %d, %q", code, stderr.String())
			}
		})
	}
}

func TestRunRejectsNonAbsolutePathsBeforeMutation(t *testing.T) {
	var stderr bytes.Buffer
	code := run([]string{
		"--archive", "candidate.tar.gz",
		"--config", filepath.Join(t.TempDir(), "config.yaml"),
		"--trusted-key", filepath.Join(t.TempDir(), "update-signing.pub"),
		"--current-release-root", filepath.Join(t.TempDir(), "v0.1.0-old"),
		"--current-version", "0.1.0-old",
		"--release-gate-only",
	}, func(string) string { return "1" }, &bytes.Buffer{}, &stderr)
	if code != 1 || !strings.Contains(stderr.String(), "archive must be an absolute path") {
		t.Fatalf("run() = %d, %q", code, stderr.String())
	}
}

func TestRunRejectsMismatchedCurrentIdentityBeforeMutation(t *testing.T) {
	var stderr bytes.Buffer
	code := run([]string{
		"--archive", filepath.Join(t.TempDir(), "candidate.tar.gz"),
		"--config", filepath.Join(t.TempDir(), "config.yaml"),
		"--trusted-key", filepath.Join(t.TempDir(), "update-signing.pub"),
		"--current-release-root", filepath.Join(t.TempDir(), "v0.1.0-other"),
		"--current-version", "0.1.0-old",
		"--release-gate-only",
	}, func(string) string { return "1" }, &bytes.Buffer{}, &stderr)
	if code != 1 || !strings.Contains(stderr.String(), "version and release root do not match") {
		t.Fatalf("run() = %d, %q", code, stderr.String())
	}
}
