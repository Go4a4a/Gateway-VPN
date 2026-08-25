package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"
	"time"

	"gateway-vpn/internal/buildinfo"
	"gateway-vpn/internal/config"
	databasepkg "gateway-vpn/internal/db"
	"gateway-vpn/internal/platformexec"
	updatepkg "gateway-vpn/internal/update"
)

const (
	defaultReleaseRoot      = "/opt/gateway-vpn"
	defaultTrustedUpdateKey = "/etc/gateway-vpn/update-signing.pub"
	defaultPrivilegedRoot   = "/var/lib/gateway-vpn-privileged"
)

func runUpdateOfflineCheck(args []string) int {
	flags := flag.NewFlagSet("gateway-vpn update-offline-check", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	databasePath := flags.String("database", "", "candidate SQLite copy")
	configPath := flags.String("config", "", "strict bootstrap YAML path")
	expectedVersion := flags.String("expected-version", "", "signed candidate Gateway version")
	expectedMihomo := flags.String("expected-mihomo-version", "", "signed candidate Mihomo version")
	expectedSchema := flags.Int64("expected-schema", 0, "signed candidate maximum DB schema")
	jsonOutput := flags.Bool("json", false, "emit a bounded JSON result")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 || *databasePath == "" || *configPath == "" || *expectedVersion == "" || *expectedMihomo == "" || *expectedSchema < 1 || !*jsonOutput {
		return 2
	}
	if os.Getenv("GATEWAY_VPN_UPDATE_UNIT") != "1" {
		fmt.Fprintln(os.Stderr, "candidate offline check may run only inside the fixed systemd update unit")
		return 1
	}
	if buildinfo.Version != *expectedVersion || buildinfo.MihomoVersion != *expectedMihomo {
		fmt.Fprintln(os.Stderr, "candidate embedded version does not match signed update metadata")
		return 1
	}
	executable, err := os.Executable()
	if err != nil {
		fmt.Fprintln(os.Stderr, "resolve candidate executable failed")
		return 1
	}
	releaseRoot := filepath.Dir(filepath.Dir(executable))
	release, err := updatepkg.ReadReleaseMetadata(releaseRoot)
	if err != nil || release.GatewayVersion != *expectedVersion || release.MihomoVersion != *expectedMihomo || release.DatabaseSchemaMaximum != *expectedSchema {
		fmt.Fprintln(os.Stderr, "candidate release metadata does not match offline check arguments")
		return 1
	}
	configuration, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "candidate bootstrap configuration is incompatible")
		return 1
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	if err := updatepkg.CheckCandidateComponents(ctx, platformexec.OSExecutor{}, releaseRoot, configuration.System.StateDir, *expectedVersion, *expectedMihomo, *expectedSchema); err != nil {
		fmt.Fprintln(os.Stderr, "candidate Mihomo compatibility check failed")
		return 1
	}
	result, err := updatepkg.CheckCandidateDatabase(ctx, *databasePath, *configPath, *expectedSchema)
	if err != nil {
		fmt.Fprintln(os.Stderr, "candidate database migration or integrity check failed")
		return 1
	}
	if err := json.NewEncoder(os.Stdout).Encode(result); err != nil {
		fmt.Fprintln(os.Stderr, "encode candidate offline result failed")
		return 1
	}
	return 0
}

func runUpdateApply(args []string) int {
	flags := flag.NewFlagSet("gateway-vpn update-apply", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	updateID := flags.String("id", "", "verified staged update id")
	configPath := flags.String("config", "/etc/gateway-vpn/config.yaml", "strict bootstrap YAML path")
	apply := flags.Bool("apply", false, "apply the verified signed update")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		return 2
	}
	if err := requireUpdateUnit("GATEWAY_VPN_UPDATE_UNIT", *apply); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	engine, err := productionUpdateEngine(ctx, *configPath, true)
	if err != nil {
		fmt.Fprintln(os.Stderr, "initialize signed update transaction failed")
		return 1
	}
	if *updateID == "" {
		operation, exists, statusErr := engine.Stager.Status()
		if statusErr != nil || !exists {
			fmt.Fprintln(os.Stderr, "no verified signed update is pending")
			return 1
		}
		*updateID = operation.UpdateID
	}
	result, err := engine.Apply(ctx, *updateID)
	if err != nil {
		fmt.Fprintln(os.Stderr, "signed update failed; the old pair was restored or boot recovery remains armed")
		return 1
	}
	if err := json.NewEncoder(os.Stdout).Encode(result); err != nil {
		return 1
	}
	return 0
}

func runUpdateRecover(args []string) int {
	flags := flag.NewFlagSet("gateway-vpn update-recover", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	configPath := flags.String("config", "/etc/gateway-vpn/config.yaml", "strict bootstrap YAML path")
	apply := flags.Bool("apply", false, "recover the fixed unfinished update transaction")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		return 2
	}
	if err := requireUpdateUnit("GATEWAY_VPN_UPDATE_RECOVERY_UNIT", *apply); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	engine, err := productionUpdateEngine(ctx, *configPath, false)
	if err != nil {
		fmt.Fprintln(os.Stderr, "initialize update recovery failed")
		return 1
	}
	if systemRuntime, ok := engine.Runtime.(updatepkg.SystemRuntime); ok {
		systemRuntime.RecoveryOnly = true
		engine.Runtime = systemRuntime
	}
	recovered, err := engine.Recover(ctx)
	if err != nil {
		fmt.Fprintln(os.Stderr, "update recovery failed; Gateway VPN remains fail-closed")
		return 1
	}
	fmt.Printf("Gateway VPN update recovery completed; rolled_back=%t\n", recovered)
	return 0
}

func runUpdateFinalize(args []string) int {
	flags := flag.NewFlagSet("gateway-vpn update-finalize", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	configPath := flags.String("config", "/etc/gateway-vpn/config.yaml", "strict bootstrap YAML path")
	apply := flags.Bool("apply", false, "finalize the stable update or roll it back on failure")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		return 2
	}
	if err := requireUpdateUnit("GATEWAY_VPN_UPDATE_FINALIZE_UNIT", *apply); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	engine, err := productionUpdateEngine(ctx, *configPath, false)
	if err != nil {
		fmt.Fprintln(os.Stderr, "initialize update finalization failed")
		return 1
	}
	journal, err := engine.Finalize(ctx)
	if errors.Is(err, updatepkg.ErrStabilityWindowActive) {
		fmt.Fprintln(os.Stderr, "release stability window is still active")
		return 0
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "update finalization failed; rollback was attempted")
		return 1
	}
	fmt.Printf("Gateway VPN update %s finalized at version %s\n", journal.UpdateID, journal.NewVersion)
	return 0
}

func productionUpdateEngine(ctx context.Context, configPath string, withStager bool) (*updatepkg.Engine, error) {
	configuration, err := config.Load(configPath)
	if err != nil {
		return nil, err
	}
	uid, gid, err := gatewayVPNIdentity()
	if err != nil {
		return nil, err
	}
	engine := &updatepkg.Engine{
		Store:       updatepkg.JournalStore{Root: filepath.Join(defaultPrivilegedRoot, "update-transactions")},
		Runtime:     updatepkg.SystemRuntime{Executor: platformexec.OSExecutor{}, Systemctl: "/usr/bin/systemctl", ReleaseRoot: defaultReleaseRoot},
		ReleaseRoot: defaultReleaseRoot, StateDir: configuration.System.StateDir, DatabasePath: configuration.System.Database,
		ConfigPath: configPath, CurrentVersion: buildinfo.Version, StateUID: int(uid), StateGID: int(gid),
	}
	if !withStager {
		return engine, nil
	}
	database, err := databasepkg.OpenReadOnly(ctx, configuration.System.Database)
	if err != nil {
		return nil, err
	}
	schema, schemaErr := databasepkg.ReadSchemaVersion(ctx, database)
	closeErr := database.Close()
	if schemaErr != nil || closeErr != nil || schema < 1 {
		return nil, errors.New("read current schema for update compatibility failed")
	}
	stager, err := updatepkg.NewStager(configuration.System.StateDir, defaultTrustedUpdateKey, updatepkg.VerificationPolicy{
		ExpectedOS: "linux", ExpectedArch: "amd64", CurrentGatewayVersion: buildinfo.Version,
		CurrentSchemaVersion: schema, ConfigGeneration: config.CurrentVersion,
		GatewayAPIContract: updatepkg.GatewayAPIContract, MihomoAPIContract: updatepkg.MihomoAPIContract,
	})
	if err != nil {
		return nil, err
	}
	engine.Stager = stager
	return engine, nil
}

func requireUpdateUnit(variable string, apply bool) error {
	if !apply {
		return errors.New("update mutation requires --apply")
	}
	if runtime.GOOS != "linux" || os.Geteuid() != 0 {
		return errors.New("update mutation requires Linux root")
	}
	if os.Getenv(variable) != "1" {
		return errors.New("update mutation may run only inside its fixed systemd unit")
	}
	return nil
}
