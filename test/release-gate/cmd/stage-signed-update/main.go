package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"gateway-vpn/internal/config"
	databasepkg "gateway-vpn/internal/db"
	updatepkg "gateway-vpn/internal/update"
)

const releaseGateEnvironment = "GATEWAY_VPN_RELEASE_GATE"

func main() {
	os.Exit(run(os.Args[1:], os.Getenv, os.Stdout, os.Stderr))
}

func run(arguments []string, getenv func(string) string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("stage-signed-update", flag.ContinueOnError)
	flags.SetOutput(stderr)
	archivePath := flags.String("archive", "", "signed gateway release .tar.gz")
	configPath := flags.String("config", "", "absolute strict production config path")
	trustedKey := flags.String("trusted-key", "", "absolute trusted Ed25519 public key path")
	releaseRoot := flags.String("current-release-root", "", "absolute trusted current release directory")
	current := flags.String("current-version", "", "exact trusted current Gateway version")
	confirmed := flags.Bool("release-gate-only", false, "confirm isolated release-gate use")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 {
		return 2
	}

	if getenv(releaseGateEnvironment) != "1" || !*confirmed {
		return fail(stderr, "release-gate environment and explicit confirmation are required")
	}
	for name, value := range map[string]string{
		"archive": *archivePath, "config": *configPath, "trusted key": *trustedKey,
		"current release root": *releaseRoot,
	} {
		if !filepath.IsAbs(value) {
			return fail(stderr, "%s must be an absolute path", name)
		}
	}
	if *current == "" || filepath.Base(filepath.Clean(*releaseRoot)) != "v"+*current {
		return fail(stderr, "current version and release root do not match")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	configuration, err := config.Load(*configPath)
	if err != nil {
		return fail(stderr, "load strict production config: %v", err)
	}
	database, err := databasepkg.OpenReadOnly(ctx, configuration.System.Database)
	if err != nil {
		return fail(stderr, "open live database: %v", err)
	}
	schema, schemaErr := databasepkg.ReadSchemaVersion(ctx, database)
	closeErr := database.Close()
	if schemaErr != nil || closeErr != nil || schema < 1 {
		return fail(stderr, "read live schema: schema=%d read=%v close=%v", schema, schemaErr, closeErr)
	}
	release, err := updatepkg.ReadReleaseMetadata(*releaseRoot)
	if err != nil || release.GatewayVersion != *current {
		return fail(stderr, "read trusted current release: %v", err)
	}
	stager, err := updatepkg.NewStager(configuration.System.StateDir, *trustedKey, updatepkg.VerificationPolicy{
		ExpectedOS: runtime.GOOS, ExpectedArch: runtime.GOARCH,
		CurrentGatewayVersion: *current, CurrentSchemaVersion: schema,
		ConfigGeneration:          config.CurrentVersion,
		CurrentHostContractSHA256: release.HostContractSHA256,
		GatewayAPIContract:        updatepkg.GatewayAPIContract,
		MihomoAPIContract:         updatepkg.MihomoAPIContract,
	})
	if err != nil {
		return fail(stderr, "create trusted stager: %v", err)
	}
	archive, err := os.Open(*archivePath)
	if err != nil {
		return fail(stderr, "open signed archive: %v", err)
	}
	operation, stageErr := stager.Stage(ctx, archive)
	closeErr = archive.Close()
	if stageErr != nil || closeErr != nil {
		return fail(stderr, "stage signed archive: stage=%v close=%v", stageErr, closeErr)
	}
	fmt.Fprintf(stdout, "staged %s as %s from schema %d\n", operation.GatewayVersion, operation.UpdateID, schema)
	return 0
}

func fail(stderr io.Writer, format string, arguments ...any) int {
	fmt.Fprintf(stderr, format+"\n", arguments...)
	return 1
}
