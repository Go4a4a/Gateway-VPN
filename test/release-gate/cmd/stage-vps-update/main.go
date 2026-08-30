package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"gateway-vpn/internal/vpsrelease"
	"gateway-vpn/internal/vpsupdate"
)

const releaseGateEnvironment = "GATEWAY_VPN_RELEASE_GATE"

func main() {
	os.Exit(run(os.Args[1:], os.Getenv, os.Stdout, os.Stderr))
}

func run(arguments []string, getenv func(string) string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("stage-vps-update", flag.ContinueOnError)
	flags.SetOutput(stderr)
	archivePath := flags.String("archive", "", "absolute signed VPS release archive")
	currentVersion := flags.String("current-version", "", "exact installed VPS version")
	currentSchema := flags.Int64("current-schema", 0, "exact installed VPS schema")
	profile := flags.String("profile", "", "exact supported VPS host profile")
	confirmed := flags.Bool("release-gate-only", false, "confirm isolated release-gate use")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 {
		return 2
	}
	if getenv(releaseGateEnvironment) != "1" || !*confirmed {
		return fail(stderr, "release-gate environment and explicit confirmation are required")
	}
	if !filepath.IsAbs(*archivePath) || *currentVersion == "" || *currentSchema < 1 || !contains(vpsrelease.SupportedProfiles(), *profile) {
		return fail(stderr, "absolute archive, current version/schema, and supported profile are required")
	}
	archive, err := os.Open(*archivePath)
	if err != nil {
		return fail(stderr, "open signed VPS archive: %v", err)
	}
	defer archive.Close()
	stager := &vpsupdate.Stager{
		StateDirectory: "/var/lib/gateway-vpn-vps/agent",
		ReleaseRoot:    "/opt/gateway-vpn-vps",
		TrustedKeyPath: "/etc/gateway-vpn-vps/update-signing.pub",
		CurrentVersion: *currentVersion,
		CurrentSchema:  *currentSchema,
		Profile:        *profile,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	operation, err := stager.Stage(ctx, archive)
	if err != nil {
		return fail(stderr, "stage signed VPS archive: %v", err)
	}
	fmt.Fprintf(stdout, "%s\n", operation.UpdateID)
	return 0
}

func contains(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}

func fail(stderr io.Writer, format string, arguments ...any) int {
	fmt.Fprintf(stderr, format+"\n", arguments...)
	return 1
}
