package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"gateway-vpn/internal/auth"
	"gateway-vpn/internal/buildinfo"
	"gateway-vpn/internal/platformexec"
	"gateway-vpn/internal/vpsagent"
	"gateway-vpn/internal/vpsbackup"
	"gateway-vpn/internal/vpsconfig"
	"gateway-vpn/internal/vpsfabric"
	"gateway-vpn/internal/vpsops"
	"gateway-vpn/internal/vpsrelease"
	"gateway-vpn/internal/vpsupdate"
	"gateway-vpn/internal/vpswebapi"
	"gateway-vpn/internal/wgingress"
)

const defaultConfigPath = "/etc/gateway-vpn-vps/config.yaml"

func main() { os.Exit(run(os.Args[1:])) }

func run(args []string) int {
	if len(args) > 0 {
		switch args[0] {
		case "serve":
			return runServe(args[1:])
		case "identity-init":
			return runIdentityInit(args[1:])
		case "init-admin":
			return runInitAdmin(args[1:])
		case "state-check":
			return runStateCheck(args[1:])
		case "restore-apply":
			return runRestoreApply(args[1:], false)
		case "restore-recover":
			return runRestoreApply(args[1:], true)
		case "legacy-adopt":
			return runLegacyAdopt(args[1:])
		case "fabric-apply":
			return runFabricApply(args[1:], false)
		case "fabric-recover":
			return runFabricApply(args[1:], true)
		case "fabric-restore-prepare":
			return runFabricRestore(args[1:], true)
		case "fabric-restore-reset":
			return runFabricRestore(args[1:], false)
		case "fabric-watchdog":
			return runFabricWatchdog(args[1:])
		case "operations-collect":
			return runOperationsCollect(args[1:])
		case "update-offline-check":
			return runUpdateOfflineCheck(args[1:])
		case "update-lifecycle-check":
			return runVPSUpdateLifecycleCheck(args[1:])
		case "update-apply":
			return runVPSUpdateApply(args[1:])
		case "update-recover":
			return runVPSUpdateRecover(args[1:])
		case "update-finalize":
			return runVPSUpdateFinalize(args[1:])
		}
	}
	flags := flag.NewFlagSet("gateway-vpn-vps-agent", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	showVersion := flags.Bool("version", false, "print build version")
	showSchema := flags.Bool("schema-version", false, "print VPS Agent database schema version")
	checkConfig := flags.String("check-config", "", "strictly validate a VPS Agent YAML file")
	checkPassword := flags.String("check-password-file", "", "validate a protected VPS Hub bootstrap password file")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	switch {
	case *showVersion:
		fmt.Println(buildinfo.String("gateway-vpn-vps-agent"))
		return 0
	case *showSchema:
		fmt.Println(vpsagent.SchemaVersion)
		return 0
	case *checkConfig != "":
		if _, err := vpsconfig.Load(*checkConfig); err != nil {
			fmt.Fprintf(os.Stderr, "VPS Agent config is invalid: %v\n", err)
			return 1
		}
		fmt.Println("VPS Agent config is valid")
		return 0
	case *checkPassword != "":
		password, err := readProtectedPassword(*checkPassword)
		if err != nil || password == "" {
			fmt.Fprintf(os.Stderr, "VPS Hub password file is invalid: %v\n", err)
			return 1
		}
		password = ""
		fmt.Println("VPS Hub password file is valid")
		return 0
	default:
		fmt.Fprintln(os.Stderr, "usage: gateway-vpn-vps-agent [--version|--schema-version|--check-config PATH|--check-password-file PATH|serve|identity-init|init-admin|state-check|restore-apply|restore-recover|legacy-adopt|fabric-apply|fabric-recover|fabric-restore-prepare|fabric-restore-reset|fabric-watchdog|operations-collect|update-offline-check|update-lifecycle-check|update-apply|update-recover|update-finalize]")
		return 2
	}
}

func runVPSUpdateLifecycleCheck(args []string) int {
	if len(args) != 0 {
		fmt.Fprintln(os.Stderr, "usage: gateway-vpn-vps-agent update-lifecycle-check")
		return 2
	}
	if os.Geteuid() != 0 {
		fmt.Fprintln(os.Stderr, "VPS update lifecycle inspection requires root")
		return 1
	}
	journal, exists, err := inspectVPSUpdateLifecycle(filepath.Join("/var/lib/gateway-vpn-vps-privileged", "update-transactions"))
	if err != nil {
		fmt.Fprintln(os.Stderr, "Gateway VPN VPS update lifecycle is unavailable or unsafe")
		return 1
	}
	if exists && journal.InProgress() {
		fmt.Fprintln(os.Stderr, "Gateway VPN VPS update lifecycle is active")
		return 1
	}
	fmt.Println("Gateway VPN VPS update lifecycle is idle")
	return 0
}

func inspectVPSUpdateLifecycle(root string) (vpsupdate.Journal, bool, error) {
	return (vpsupdate.JournalStore{Root: root}).LoadActive()
}

func runUpdateOfflineCheck(args []string) int {
	flags := flag.NewFlagSet("gateway-vpn-vps-agent update-offline-check", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	databasePath := flags.String("database", "", "fixed root transaction candidate database")
	configPath := flags.String("config", defaultConfigPath, "absolute VPS Agent YAML config")
	expectedVersion := flags.String("expected-version", "", "signed candidate version")
	expectedSchema := flags.Int64("expected-schema", 0, "signed candidate schema")
	jsonOutput := flags.Bool("json", false, "write strict JSON result")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 || !*jsonOutput || *configPath != defaultConfigPath || !validVPSUpdateCandidatePath(*databasePath) || *expectedVersion != buildinfo.Version || *expectedSchema != vpsagent.SchemaVersion {
		return 2
	}
	if _, err := vpsconfig.Load(*configPath); err != nil {
		fmt.Fprintln(os.Stderr, "candidate VPS configuration is invalid")
		return 1
	}
	database, err := vpsagent.Open(context.Background(), *databasePath)
	if err != nil || vpsagent.Verify(context.Background(), database) != nil {
		if database != nil {
			_ = database.Close()
		}
		fmt.Fprintln(os.Stderr, "candidate VPS database migration or verification failed")
		return 1
	}
	if _, err := database.ExecContext(context.Background(), "PRAGMA wal_checkpoint(TRUNCATE)"); err != nil {
		_ = database.Close()
		fmt.Fprintln(os.Stderr, "candidate VPS database checkpoint failed")
		return 1
	}
	if _, err := database.ExecContext(context.Background(), "PRAGMA journal_mode=DELETE"); err != nil {
		_ = database.Close()
		fmt.Fprintln(os.Stderr, "candidate VPS database journal finalization failed")
		return 1
	}
	if err := database.Close(); err != nil {
		fmt.Fprintln(os.Stderr, "candidate VPS database close failed")
		return 1
	}
	for _, suffix := range []string{"-wal", "-shm"} {
		if err := os.Remove(*databasePath + suffix); err != nil && !errors.Is(err, os.ErrNotExist) {
			fmt.Fprintln(os.Stderr, "candidate VPS database sidecar cleanup failed")
			return 1
		}
	}
	file, err := os.Open(*databasePath)
	if err != nil {
		return 1
	}
	info, statErr := file.Stat()
	hash := sha256.New()
	written, copyErr := io.Copy(hash, io.LimitReader(file, vpsbackup.MaximumFileBytes+1))
	closeErr := file.Close()
	if statErr != nil || copyErr != nil || closeErr != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > vpsbackup.MaximumFileBytes || written != info.Size() {
		fmt.Fprintln(os.Stderr, "candidate VPS database hash failed")
		return 1
	}
	result := vpsupdate.OfflineResult{Version: buildinfo.Version, SchemaVersion: vpsagent.SchemaVersion, DatabaseBytes: written, DatabaseSHA256: hex.EncodeToString(hash.Sum(nil)), QuickCheck: "PASS", IntegrityCheck: "PASS", ForeignKeyCheck: "PASS"}
	if err := json.NewEncoder(os.Stdout).Encode(result); err != nil {
		return 1
	}
	return 0
}

func validVPSUpdateCandidatePath(path string) bool {
	if !filepath.IsAbs(path) || filepath.Base(path) != "candidate.db" {
		return false
	}
	transaction := filepath.Dir(filepath.Clean(path))
	return strings.HasPrefix(filepath.Base(transaction), "vps-update-") && filepath.Base(filepath.Dir(transaction)) == "update-transactions" && filepath.Base(filepath.Dir(filepath.Dir(transaction))) == "gateway-vpn-vps-privileged"
}

func runServe(args []string) int {
	flags := flag.NewFlagSet("gateway-vpn-vps-agent serve", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	configPath := flags.String("config", defaultConfigPath, "absolute VPS Agent YAML config")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		return 2
	}
	configuration, database, err := openConfigured(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "open VPS Agent state failed: %v\n", err)
		return 1
	}
	defer database.Close()
	if _, err := vpsagent.ReadIdentity(context.Background(), database); err != nil {
		fmt.Fprintln(os.Stderr, "VPS Agent identity is not initialized")
		return 1
	}
	authService := auth.Service{Database: database}
	if hasUsers, err := authService.HasUsers(context.Background()); err != nil || !hasUsers {
		fmt.Fprintln(os.Stderr, "VPS Agent administrator is not initialized")
		return 1
	}
	backups, err := vpsbackup.NewManager(database, configuration.System.StateDirectory, *configPath, buildinfo.String("gateway-vpn-vps-agent"))
	if err != nil {
		fmt.Fprintf(os.Stderr, "initialize VPS backups failed: %v\n", err)
		return 1
	}
	restores, err := vpsbackup.NewRestoreManager(database, configuration.System.StateDirectory, configuration.System.Database, *configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "initialize VPS restore failed: %v\n", err)
		return 1
	}
	adminKeys, err := vpsagent.NewAdminKeyManager(database, configuration.System.StateDirectory, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "initialize managed VPS administrator keys failed: %v\n", err)
		return 1
	}
	if err := adminKeys.CleanupConsumed(context.Background()); err != nil {
		fmt.Fprintf(os.Stderr, "clean consumed VPS administrator keys failed: %v\n", err)
		return 1
	}
	profile, err := vpsHostProfile()
	if err != nil {
		fmt.Fprintf(os.Stderr, "identify VPS update profile failed: %v\n", err)
		return 1
	}
	updates := &vpsupdate.Service{
		Stager:     &vpsupdate.Stager{StateDirectory: configuration.System.StateDirectory, ReleaseRoot: "/opt/gateway-vpn-vps", TrustedKeyPath: "/etc/gateway-vpn-vps/update-signing.pub", CurrentVersion: buildinfo.Version, CurrentSchema: vpsagent.SchemaVersion, Profile: profile},
		StatusPath: filepath.Join(configuration.System.StateDirectory, "update-status.json"), CurrentVersion: buildinfo.Version, CurrentSchema: vpsagent.SchemaVersion, ApplyAvailable: true,
	}
	if err := updates.EnsureInitialStatus(); err != nil {
		fmt.Fprintf(os.Stderr, "initialize VPS update status failed: %v\n", err)
		return 1
	}
	web, err := vpswebapi.New(vpswebapi.Dependencies{
		Database: database, Auth: authService, Backups: backups, Restores: restores,
		AdminKeys:        &adminKeys,
		RestoreApply:     systemdRestoreTrigger{path: filepath.Join(configuration.System.StateDirectory, "restore.trigger")},
		FabricApply:      systemdFabricTrigger{path: filepath.Join(configuration.System.StateDirectory, "fabric.trigger")},
		FabricStatusPath: filepath.Join(configuration.System.StateDirectory, vpsfabric.WatchdogStatusFilename),
		Updates:          updates, UpdateApply: systemdUpdateTrigger{path: filepath.Join(configuration.System.StateDirectory, "update.trigger")},
		Operations: &vpsops.Service{
			Database: database, SnapshotPath: vpsops.DefaultPaths().Output,
			FabricStatusPath: filepath.Join(configuration.System.StateDirectory, vpsfabric.WatchdogStatusFilename),
			Config:           vpsops.ConfigSummary{Listen: append([]string(nil), configuration.Listen...), AdminPrefixes: append([]string(nil), configuration.AdminPrefixes...), StateDirectory: configuration.System.StateDirectory},
			AgentVersion:     buildinfo.String("gateway-vpn-vps-agent"),
		},
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "initialize VPS Hub WebUI failed: %v\n", err)
		return 1
	}
	pair, err := tls.LoadX509KeyPair(configuration.TLS.Certificate, configuration.TLS.PrivateKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load VPS Hub TLS identity failed: %v\n", err)
		return 1
	}
	tlsConfiguration := &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{pair}}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	servers := make([]*http.Server, 0, len(configuration.Listen))
	errorChannel := make(chan error, len(configuration.Listen))
	for _, endpoint := range configuration.Listen {
		listener, err := net.Listen("tcp4", endpoint)
		if err != nil {
			fmt.Fprintf(os.Stderr, "bind VPS Hub %s failed: %v\n", endpoint, err)
			return 1
		}
		server := &http.Server{
			Handler: web.Handler(), ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 5 * time.Minute,
			WriteTimeout: 5 * time.Minute, IdleTimeout: 90 * time.Second, MaxHeaderBytes: 32 << 10,
		}
		servers = append(servers, server)
		go func(server *http.Server, listener net.Listener) {
			err := server.Serve(tls.NewListener(listener, tlsConfiguration.Clone()))
			if err != nil && !errors.Is(err, http.ErrServerClosed) {
				errorChannel <- err
				return
			}
			errorChannel <- nil
		}(server, listener)
	}
	select {
	case <-ctx.Done():
	case err := <-errorChannel:
		if err != nil {
			fmt.Fprintf(os.Stderr, "VPS Hub server failed: %v\n", err)
		}
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	for _, server := range servers {
		_ = server.Shutdown(shutdown)
	}
	return 0
}

func runVPSUpdateApply(args []string) int {
	flags := flag.NewFlagSet("gateway-vpn-vps-agent update-apply", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	configPath := flags.String("config", defaultConfigPath, "absolute VPS Agent YAML config")
	apply := flags.Bool("apply", false, "apply the fixed staged VPS update")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 || !*apply || os.Getenv("GATEWAY_VPN_VPS_UPDATE_UNIT") != "1" || os.Geteuid() != 0 {
		return 2
	}
	unlockLifecycle, err := acquireVPSUpdateRootLifecycle(false)
	if err != nil {
		fmt.Fprintln(os.Stderr, "VPS update is blocked by another Gateway VPN VPS lifecycle transaction")
		return 1
	}
	defer unlockLifecycle()
	removeLiveMarker, err := createVPSUpdateLiveMarker()
	if err != nil {
		fmt.Fprintln(os.Stderr, "create VPS update live marker failed")
		return 1
	}
	defer removeLiveMarker()
	engine, err := productionVPSUpdateEngine(*configPath, true)
	if err != nil {
		fmt.Fprintln(os.Stderr, "initialize VPS update transaction failed")
		return 1
	}
	result, err := engine.Apply(context.Background())
	if err != nil {
		fmt.Fprintln(os.Stderr, "VPS update failed; rollback completed or boot recovery remains armed")
		return 1
	}
	_ = json.NewEncoder(os.Stdout).Encode(result)
	return 0
}

func runVPSUpdateRecover(args []string) int {
	flags := flag.NewFlagSet("gateway-vpn-vps-agent update-recover", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	configPath := flags.String("config", defaultConfigPath, "absolute VPS Agent YAML config")
	apply := flags.Bool("apply", false, "recover the fixed VPS update transaction")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 || !*apply || os.Getenv("GATEWAY_VPN_VPS_UPDATE_RECOVERY_UNIT") != "1" || os.Geteuid() != 0 {
		return 2
	}
	// During first install the installer owns the common lock while
	// synchronously starting this recovery unit. Permit that one verified
	// owner only while both root-owned install markers are present.
	unlockLifecycle, err := acquireVPSUpdateRootLifecycle(true)
	if err != nil {
		fmt.Fprintln(os.Stderr, "VPS update recovery is blocked by another Gateway VPN VPS lifecycle transaction")
		return 1
	}
	defer unlockLifecycle()
	engine, err := productionVPSUpdateEngine(*configPath, false)
	if err != nil {
		fmt.Fprintln(os.Stderr, "initialize VPS update recovery failed")
		return 1
	}
	recovered, err := engine.Recover(context.Background())
	if err != nil {
		fmt.Fprintln(os.Stderr, "VPS update recovery failed; management remains stopped for another recovery attempt")
		return 1
	}
	fmt.Printf("VPS update recovery completed; rolled_back=%t\n", recovered)
	return 0
}

func runVPSUpdateFinalize(args []string) int {
	flags := flag.NewFlagSet("gateway-vpn-vps-agent update-finalize", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	configPath := flags.String("config", defaultConfigPath, "absolute VPS Agent YAML config")
	apply := flags.Bool("apply", false, "finalize the fixed stable VPS update")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 || !*apply || os.Getenv("GATEWAY_VPN_VPS_UPDATE_FINALIZE_UNIT") != "1" || os.Geteuid() != 0 {
		return 2
	}
	unlockLifecycle, err := acquireVPSUpdateRootLifecycle(false)
	if err != nil {
		fmt.Fprintln(os.Stderr, "VPS update finalization is blocked by another Gateway VPN VPS lifecycle transaction")
		return 1
	}
	defer unlockLifecycle()
	removeLiveMarker, err := createVPSUpdateLiveMarker()
	if err != nil {
		fmt.Fprintln(os.Stderr, "create VPS update live marker failed")
		return 1
	}
	defer removeLiveMarker()
	engine, err := productionVPSUpdateEngine(*configPath, false)
	if err != nil {
		return 1
	}
	journal, err := engine.Finalize(context.Background())
	if errors.Is(err, vpsupdate.ErrNoFinalizationPending) || errors.Is(err, vpsupdate.ErrStabilityWindowActive) {
		return 0
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "VPS update finalization failed; rollback completed or recovery remains armed")
		return 1
	}
	fmt.Printf("VPS update %s finalized at version %s\n", journal.UpdateID, journal.NewVersion)
	return 0
}

func productionVPSUpdateEngine(configPath string, withStager bool) (*vpsupdate.Engine, error) {
	configuration, err := vpsconfig.Load(configPath)
	if err != nil {
		return nil, err
	}
	uid, gid, err := resolveAccount("gateway-vpn-vps")
	if err != nil {
		return nil, err
	}
	profile, err := vpsHostProfile()
	if err != nil {
		return nil, err
	}
	engine := &vpsupdate.Engine{
		Store:       vpsupdate.JournalStore{Root: "/var/lib/gateway-vpn-vps-privileged/update-transactions"},
		Status:      vpsupdate.StatusStore{Path: filepath.Join(configuration.System.StateDirectory, "update-status.json"), UID: uid, GID: gid},
		Runtime:     vpsupdate.SystemRuntime{Executor: platformexec.OSExecutor{}, Systemctl: "/usr/bin/systemctl", ReleaseRoot: "/opt/gateway-vpn-vps"},
		ReleaseRoot: "/opt/gateway-vpn-vps", StateDirectory: configuration.System.StateDirectory, DatabasePath: configuration.System.Database, ConfigPath: configPath,
		TrustedKeyPath: "/etc/gateway-vpn-vps/update-signing.pub", Profile: profile, RunningVersion: buildinfo.Version, RunningSchema: vpsagent.SchemaVersion, AgentUID: uid, AgentGID: gid,
	}
	if withStager {
		engine.Stager = &vpsupdate.Stager{StateDirectory: configuration.System.StateDirectory, ReleaseRoot: engine.ReleaseRoot, TrustedKeyPath: engine.TrustedKeyPath, CurrentVersion: engine.RunningVersion, CurrentSchema: engine.RunningSchema, Profile: profile}
	}
	return engine, nil
}

func vpsHostProfile() (string, error) {
	content, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return "", err
	}
	values := map[string]string{}
	for _, line := range strings.Split(string(content), "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		values[key] = strings.Trim(strings.TrimSpace(value), `"`)
	}
	profile := values["ID"] + "-" + values["VERSION_ID"]
	for _, supported := range vpsrelease.SupportedProfiles() {
		if profile == supported {
			return profile, nil
		}
	}
	return "", errors.New("unsupported VPS OS profile")
}

func runLegacyAdopt(args []string) int {
	flags := flag.NewFlagSet("gateway-vpn-vps-agent legacy-adopt", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	configPath := flags.String("config", defaultConfigPath, "absolute VPS Agent YAML config")
	gatewayKey := flags.String("gateway-public-key", "", "legacy Gateway public key")
	adminKey := flags.String("admin-public-key", "", "legacy administrator public key")
	endpoint := flags.String("endpoint", "", "legacy VPS endpoint")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		return 2
	}
	_, database, err := openConfigured(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "open VPS Agent state failed: %v\n", err)
		return 1
	}
	defer database.Close()
	result, err := (vpsagent.HubRepository{Database: database}).AdoptLegacyInstallerPeers(context.Background(), vpsagent.LegacyAdoptionInput{
		GatewayPublicKey: *gatewayKey, AdminPublicKey: *adminKey, Endpoint: *endpoint,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "adopt exact legacy VPS peers failed: %v\n", err)
		return 1
	}
	_ = json.NewEncoder(os.Stdout).Encode(result)
	return 0
}

func runFabricApply(args []string, recover bool) int {
	flags := flag.NewFlagSet("gateway-vpn-vps-agent fabric-apply", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	configPath := flags.String("config", defaultConfigPath, "absolute VPS Agent YAML config")
	agentUser := flags.String("agent-user", "gateway-vpn-vps", "VPS Agent service account")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		return 2
	}
	configuration, database, err := openConfigured(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "open VPS Agent state failed: %v\n", err)
		return 1
	}
	uid, gid, err := resolveAccount(*agentUser)
	if err != nil {
		database.Close()
		fmt.Fprintf(os.Stderr, "resolve VPS Agent ownership failed: %v\n", err)
		return 1
	}
	identity, err := vpsagent.ReadIdentity(context.Background(), database)
	if err != nil {
		database.Close()
		fmt.Fprintf(os.Stderr, "read VPS identity failed: %v\n", err)
		return 1
	}
	paths := vpsfabric.DefaultPaths(identity.PrivateKeySecretRef)
	paths.TransactionRoot = filepath.Join(filepath.Dir(configuration.System.TransactionRoot), "fabric")
	applier := &vpsfabric.Applier{
		Repository: vpsagent.HubRepository{Database: database, HostApplyAvailable: true},
		Executor:   platformexec.OSExecutor{}, Paths: paths,
	}
	if recover {
		recovered, applyErr := applier.Recover(context.Background())
		reset, resetErr := applier.ResetAfterRestore(context.Background())
		pending, pendingErr := applier.RestoreReconciliationPending()
		triggerErr := error(nil)
		if pending {
			triggerErr = (systemdFabricTrigger{path: filepath.Join(configuration.System.StateDirectory, "fabric.trigger")}).ApplyVPSFabric(context.Background())
		}
		closeErr := database.Close()
		ownershipErr := restoreDatabaseOwnership(configuration.System.Database, uid, gid)
		if err := errors.Join(applyErr, resetErr, pendingErr, triggerErr, closeErr, ownershipErr); err != nil {
			fmt.Fprintf(os.Stderr, "recover interrupted VPS fabric failed: %v\n", err)
			return 1
		}
		fmt.Printf("VPS fabric recovery checked; recovered=%t restore_reset=%t\n", recovered, reset)
		return 0
	}
	applyErr := applier.Apply(context.Background())
	closeErr := database.Close()
	ownershipErr := restoreDatabaseOwnership(configuration.System.Database, uid, gid)
	if err := errors.Join(applyErr, closeErr, ownershipErr); err != nil {
		fmt.Fprintf(os.Stderr, "apply VPS fabric failed: %v\n", err)
		return 1
	}
	fmt.Println("VPS fabric applied")
	return 0
}

// runOperationsCollect is called only by the fixed root-owned systemd unit.
// HTTP never supplies paths, executables, units, or command arguments.
func runOperationsCollect(args []string) int {
	flags := flag.NewFlagSet("gateway-vpn-vps-agent operations-collect", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	configPath := flags.String("config", defaultConfigPath, "absolute VPS Agent YAML config")
	agentUser := flags.String("agent-user", "gateway-vpn-vps", "VPS Agent service account")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		return 2
	}
	configuration, err := vpsconfig.Load(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load VPS Agent config for operations snapshot failed: %v\n", err)
		return 1
	}
	_, gid, err := resolveAccount(*agentUser)
	if err != nil {
		fmt.Fprintf(os.Stderr, "resolve VPS Agent ownership failed: %v\n", err)
		return 1
	}
	paths := vpsops.DefaultPaths()
	paths.FabricStatus = filepath.Join(configuration.System.StateDirectory, vpsfabric.WatchdogStatusFilename)
	collector := vpsops.Collector{Executor: platformexec.OSExecutor{}, Paths: paths, AgentGID: gid}
	snapshot, err := collector.CollectAndWrite(context.Background())
	if err != nil {
		fmt.Fprintf(os.Stderr, "collect bounded VPS operations snapshot failed: %v\n", err)
		return 1
	}
	fmt.Printf("VPS operations snapshot %s: %s (%d log entries)\n", snapshot.CollectedAt, snapshot.State, len(snapshot.Entries))
	return 0
}

func runFabricRestore(args []string, prepare bool) int {
	name := "fabric-restore-reset"
	if prepare {
		name = "fabric-restore-prepare"
	}
	flags := flag.NewFlagSet("gateway-vpn-vps-agent "+name, flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	configPath := flags.String("config", defaultConfigPath, "absolute VPS Agent YAML config")
	agentUser := flags.String("agent-user", "gateway-vpn-vps", "VPS Agent service account")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		return 2
	}
	configuration, database, err := openConfigured(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "open VPS fabric restore state failed: %v\n", err)
		return 1
	}
	uid, gid, err := resolveAccount(*agentUser)
	if err != nil {
		database.Close()
		fmt.Fprintf(os.Stderr, "resolve VPS Agent ownership failed: %v\n", err)
		return 1
	}
	identity, err := vpsagent.ReadIdentity(context.Background(), database)
	if err != nil {
		database.Close()
		fmt.Fprintf(os.Stderr, "read VPS identity failed: %v\n", err)
		return 1
	}
	paths := vpsfabric.DefaultPaths(identity.PrivateKeySecretRef)
	paths.TransactionRoot = filepath.Join(filepath.Dir(configuration.System.TransactionRoot), "fabric")
	applier := &vpsfabric.Applier{Repository: vpsagent.HubRepository{Database: database, HostApplyAvailable: true}, Executor: platformexec.OSExecutor{}, Paths: paths}
	operationErr := error(nil)
	changed := false
	if prepare {
		restores, managerErr := vpsbackup.NewRestoreManager(database, configuration.System.StateDirectory, configuration.System.Database, *configPath)
		if managerErr != nil {
			operationErr = managerErr
		} else if operation, exists, statusErr := restores.Status(); statusErr != nil {
			operationErr = statusErr
		} else if !exists || operation.State != vpsbackup.RestoreStateApplyRequested || operation.ApplyAuthorization == "" {
			operationErr = errors.New("explicitly authorized VPS restore is required")
		} else {
			operationErr = applier.PrepareRestore(context.Background(), operation.RestoreID)
			changed = operationErr == nil
		}
	} else {
		changed, operationErr = applier.ResetAfterRestore(context.Background())
		if operationErr == nil && changed {
			operationErr = (systemdFabricTrigger{path: filepath.Join(configuration.System.StateDirectory, "fabric.trigger")}).ApplyVPSFabric(context.Background())
		}
	}
	closeErr := database.Close()
	ownershipErr := restoreDatabaseOwnership(configuration.System.Database, uid, gid)
	if err := errors.Join(operationErr, closeErr, ownershipErr); err != nil {
		fmt.Fprintf(os.Stderr, "%s failed: %v\n", name, err)
		return 1
	}
	fmt.Printf("VPS fabric restore transition complete; operation=%s changed=%t\n", name, changed)
	return 0
}

func runFabricWatchdog(args []string) int {
	flags := flag.NewFlagSet("gateway-vpn-vps-agent fabric-watchdog", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	configPath := flags.String("config", defaultConfigPath, "absolute VPS Agent YAML config")
	agentUser := flags.String("agent-user", "gateway-vpn-vps", "VPS Agent service account")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		return 2
	}
	configuration, database, err := openConfigured(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "open VPS fabric watchdog state failed: %v\n", err)
		return 1
	}
	uid, gid, err := resolveAccount(*agentUser)
	if err != nil {
		database.Close()
		fmt.Fprintf(os.Stderr, "resolve VPS Agent ownership failed: %v\n", err)
		return 1
	}
	identity, err := vpsagent.ReadIdentity(context.Background(), database)
	if err != nil {
		database.Close()
		fmt.Fprintf(os.Stderr, "read VPS identity failed: %v\n", err)
		return 1
	}
	paths := vpsfabric.DefaultPaths(identity.PrivateKeySecretRef)
	paths.TransactionRoot = filepath.Join(filepath.Dir(configuration.System.TransactionRoot), "fabric")
	applier := &vpsfabric.Applier{Repository: vpsagent.HubRepository{Database: database, HostApplyAvailable: true}, Executor: platformexec.OSExecutor{}, Paths: paths}
	needed, reason, checkErr := applier.NeedsApply(context.Background())
	telemetry, telemetryErr := applier.ReadWatchdogTelemetry(context.Background())
	if checkErr == nil && !needed && telemetryErr != nil {
		checkErr = telemetryErr
	}
	triggerErr := error(nil)
	if checkErr == nil && needed {
		triggerErr = (systemdFabricTrigger{path: filepath.Join(configuration.System.StateDirectory, "fabric.trigger")}).ApplyVPSFabric(context.Background())
	}
	closeErr := database.Close()
	ownershipErr := restoreDatabaseOwnership(configuration.System.Database, uid, gid)
	state, healthy, scheduled, statusReason := "HEALTHY", true, false, reason
	operationErr := errors.Join(checkErr, triggerErr, closeErr, ownershipErr)
	if checkErr != nil {
		state, healthy = "FAILED", false
	} else if triggerErr != nil {
		state, healthy, statusReason = "FAILED", false, "RECONCILE_SCHEDULE_FAILED"
	} else if closeErr != nil || ownershipErr != nil {
		state, healthy, statusReason = "FAILED", false, "WATCHDOG_MAINTENANCE_FAILED"
	} else if needed {
		state, healthy, scheduled = "PENDING", false, true
	}
	status := vpsfabric.NewWatchdogStatus(state, statusReason, healthy, scheduled, time.Now().UTC())
	status.DesiredGeneration = telemetry.DesiredGeneration
	status.AppliedGeneration = telemetry.AppliedGeneration
	status.RelayCount = telemetry.RelayCount
	status.RelayRuleCount = telemetry.RelayRuleCount
	status.RelayPackets = telemetry.RelayPackets
	status.RelayBytes = telemetry.RelayBytes
	statusErr := vpsfabric.WriteWatchdogStatus(filepath.Join(configuration.System.StateDirectory, vpsfabric.WatchdogStatusFilename), status, uid, gid)
	if err := errors.Join(operationErr, statusErr); err != nil {
		fmt.Fprintf(os.Stderr, "VPS fabric watchdog failed (%s): %v\n", reason, err)
		return 1
	}
	_ = json.NewEncoder(os.Stdout).Encode(status)
	return 0
}

func restoreDatabaseOwnership(databasePath string, uid, gid int) error {
	var failures []error
	for _, path := range []string{databasePath, databasePath + "-wal", databasePath + "-shm"} {
		if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
			continue
		} else if err != nil {
			failures = append(failures, err)
			continue
		}
		failures = append(failures, os.Chown(path, uid, gid))
	}
	return errors.Join(failures...)
}

func runIdentityInit(args []string) int {
	flags := flag.NewFlagSet("gateway-vpn-vps-agent identity-init", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	configPath := flags.String("config", defaultConfigPath, "absolute VPS Agent YAML config")
	vpsID := flags.String("vps-id", "", "immutable VPS id")
	displayName := flags.String("display-name", "", "VPS display name")
	publicKey := flags.String("public-key", "", "VPS WireGuard public key")
	privateRef := flags.String("private-key-secret-ref", "/var/lib/gateway-vpn-vps/agent/secrets/wireguard/server.key", "protected WireGuard private-key reference")
	updateRef := flags.String("update-identity-ref", "/var/lib/gateway-vpn-vps/agent/secrets/update/identity.key", "protected update identity reference")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		return 2
	}
	_, database, err := openConfigured(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "open VPS Agent state failed: %v\n", err)
		return 1
	}
	defer database.Close()
	digest := sha256.Sum256([]byte(strings.TrimSpace(*publicKey)))
	identity, err := vpsagent.InitializeIdentity(context.Background(), database, vpsagent.IdentityInput{
		VPSID: strings.TrimSpace(*vpsID), DisplayName: strings.TrimSpace(*displayName),
		IdentityFingerprint: hex.EncodeToString(digest[:]), PublicKey: strings.TrimSpace(*publicKey),
		PrivateKeySecretRef: *privateRef, UpdateIdentityRef: *updateRef,
	}, time.Now())
	if err != nil {
		fmt.Fprintf(os.Stderr, "initialize immutable VPS identity failed: %v\n", err)
		return 1
	}
	_ = json.NewEncoder(os.Stdout).Encode(identity)
	return 0
}

func runInitAdmin(args []string) int {
	flags := flag.NewFlagSet("gateway-vpn-vps-agent init-admin", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	configPath := flags.String("config", defaultConfigPath, "absolute VPS Agent YAML config")
	passwordFile := flags.String("password-file", "", "protected file containing the bootstrap password")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 || *passwordFile == "" {
		return 2
	}
	password, err := readProtectedPassword(*passwordFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read VPS administrator password failed: %v\n", err)
		return 1
	}
	_, database, err := openConfigured(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "open VPS Agent state failed: %v\n", err)
		return 1
	}
	defer database.Close()
	created, err := (auth.Service{Database: database}).CreateBootstrapAdmin(context.Background(), password)
	password = ""
	if err != nil || !created {
		fmt.Fprintln(os.Stderr, "VPS administrator already exists or could not be created")
		return 1
	}
	fmt.Println("VPS Hub bootstrap administrator created; password change is required at first login")
	return 0
}

func runStateCheck(args []string) int {
	flags := flag.NewFlagSet("gateway-vpn-vps-agent state-check", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	configPath := flags.String("config", defaultConfigPath, "absolute VPS Agent YAML config")
	expectedPublicKey := flags.String("expected-public-key", "", "expected VPS WireGuard public key")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		return 2
	}
	configuration, database, err := openConfigured(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "open VPS Agent state failed: %v\n", err)
		return 1
	}
	defer database.Close()
	identity, err := vpsagent.ReadIdentity(context.Background(), database)
	if strings.TrimSpace(*expectedPublicKey) == "" && err == nil {
		*expectedPublicKey = identity.PublicKey
	}
	if err != nil || vpsagent.Verify(context.Background(), database) != nil || identity.PublicKey != strings.TrimSpace(*expectedPublicKey) {
		fmt.Fprintln(os.Stderr, "VPS Agent database identity does not match the expected WireGuard identity")
		return 1
	}
	if identity.PrivateKeySecretRef != "/var/lib/gateway-vpn-vps/agent/secrets/wireguard/server.key" || identity.UpdateIdentityRef != "/var/lib/gateway-vpn-vps/agent/secrets/update/identity.key" {
		fmt.Fprintln(os.Stderr, "VPS Agent identity secret references are not canonical")
		return 1
	}
	privateKey, err := readProtectedSecret(identity.PrivateKeySecretRef, 256)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read VPS WireGuard identity failed: %v\n", err)
		return 1
	}
	derived, err := wgingress.PublicKey(strings.TrimSpace(privateKey))
	privateKey = ""
	if err != nil || derived != identity.PublicKey {
		fmt.Fprintln(os.Stderr, "VPS WireGuard private key does not match the immutable identity")
		return 1
	}
	updateIdentity, err := readProtectedSecret(identity.UpdateIdentityRef, 256)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read VPS update identity failed: %v\n", err)
		return 1
	}
	updateIdentity = strings.TrimSpace(updateIdentity)
	decodedUpdate, decodeErr := hex.DecodeString(updateIdentity)
	updateIdentity = ""
	if decodeErr != nil || len(decodedUpdate) != 32 {
		fmt.Fprintln(os.Stderr, "VPS update identity is invalid")
		return 1
	}
	for index := range decodedUpdate {
		decodedUpdate[index] = 0
	}
	if _, err := tls.LoadX509KeyPair(configuration.TLS.Certificate, configuration.TLS.PrivateKey); err != nil {
		fmt.Fprintln(os.Stderr, "VPS Hub TLS identity is invalid")
		return 1
	}
	if hasUsers, err := (auth.Service{Database: database}).HasUsers(context.Background()); err != nil || !hasUsers {
		fmt.Fprintln(os.Stderr, "VPS Hub administrator is not initialized")
		return 1
	}
	fmt.Println("VPS Agent identity, secrets, TLS, database, and administrator state are valid")
	return 0
}

func runRestoreApply(args []string, recover bool) int {
	name := "restore-apply"
	if recover {
		name = "restore-recover"
	}
	flags := flag.NewFlagSet("gateway-vpn-vps-agent "+name, flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	configPath := flags.String("config", defaultConfigPath, "absolute VPS Agent YAML config")
	agentUID := flags.Int("agent-uid", -1, "VPS Agent service uid")
	agentGID := flags.Int("agent-gid", -1, "VPS Agent service gid")
	agentUser := flags.String("agent-user", "gateway-vpn-vps", "VPS Agent service account used when numeric ownership is omitted")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		return 2
	}
	configuration, database, err := openConfigured(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "open VPS restore state failed: %v\n", err)
		return 1
	}
	restores, err := vpsbackup.NewRestoreManager(database, configuration.System.StateDirectory, configuration.System.Database, *configPath)
	if err != nil {
		database.Close()
		fmt.Fprintf(os.Stderr, "initialize VPS restore state failed: %v\n", err)
		return 1
	}
	if *agentUID < 0 || *agentGID < 0 {
		resolvedUID, resolvedGID, err := resolveAccount(*agentUser)
		if err != nil {
			database.Close()
			fmt.Fprintf(os.Stderr, "resolve VPS Agent ownership failed: %v\n", err)
			return 1
		}
		*agentUID, *agentGID = resolvedUID, resolvedGID
	}
	applier, err := vpsbackup.NewRestoreApplier(restores, configuration.System.TransactionRoot, *agentUID, *agentGID)
	if err != nil {
		database.Close()
		fmt.Fprintf(os.Stderr, "initialize privileged VPS restore failed: %v\n", err)
		return 1
	}
	if recover {
		recovered, err := applier.Recover(context.Background())
		if err != nil {
			fmt.Fprintf(os.Stderr, "recover interrupted VPS restore failed: %v\n", err)
			return 1
		}
		fmt.Printf("VPS restore recovery checked; recovered=%t\n", recovered)
		return 0
	}
	result, err := applier.Apply(context.Background())
	if err != nil {
		fmt.Fprintf(os.Stderr, "apply VPS restore failed: %v\n", err)
		return 1
	}
	_ = json.NewEncoder(os.Stdout).Encode(result)
	return 0
}

func resolveAccount(name string) (int, int, error) {
	account, err := user.Lookup(name)
	if err != nil {
		return 0, 0, err
	}
	uid, uidErr := strconv.Atoi(account.Uid)
	gid, gidErr := strconv.Atoi(account.Gid)
	if uidErr != nil || gidErr != nil || uid < 0 || gid < 0 {
		return 0, 0, errors.New("VPS Agent account has invalid numeric ownership")
	}
	return uid, gid, nil
}

func openConfigured(configPath string) (vpsconfig.Config, *sql.DB, error) {
	configuration, err := vpsconfig.Load(configPath)
	if err != nil {
		return vpsconfig.Config{}, nil, err
	}
	database, err := vpsagent.Open(context.Background(), configuration.System.Database)
	return configuration, database, err
}

func readProtectedPassword(path string) (string, error) {
	return readProtectedSecret(path, 1026)
}

func readProtectedSecret(path string, maximum int64) (string, error) {
	if !filepath.IsAbs(path) {
		return "", errors.New("absolute protected file path is required")
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maximum || runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return "", errors.New("file must be a protected bounded regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	content, err := io.ReadAll(io.LimitReader(file, maximum+1))
	closeErr := file.Close()
	if err != nil || closeErr != nil || int64(len(content)) != info.Size() {
		return "", errors.New("read password file failed")
	}
	value := strings.TrimSuffix(strings.TrimSuffix(string(content), "\n"), "\r")
	if maximum > 1024 && (len(value) < 12 || len(value) > 1024) || strings.ContainsRune(value, 0) {
		return "", errors.New("password must contain 12..1024 bytes")
	}
	return value, nil
}

type systemdRestoreTrigger struct{ path string }

type systemdFabricTrigger struct{ path string }
type systemdUpdateTrigger struct{ path string }

func (trigger systemdFabricTrigger) ApplyVPSFabric(ctx context.Context) error {
	return createSystemdTrigger(ctx, trigger.path, "fabric.trigger")
}

func (trigger systemdRestoreTrigger) ApplyPendingVPSRestore(ctx context.Context) error {
	return createSystemdTrigger(ctx, trigger.path, "restore.trigger")
}

func (trigger systemdUpdateTrigger) ApplyPendingVPSUpdate(ctx context.Context) error {
	return createSystemdTrigger(ctx, trigger.path, "update.trigger")
}

func createSystemdTrigger(ctx context.Context, path, expectedBase string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !filepath.IsAbs(path) || filepath.Base(path) != expectedBase || expectedBase != "restore.trigger" && expectedBase != "fabric.trigger" && expectedBase != "update.trigger" {
		return errors.New("VPS systemd trigger path is invalid")
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if errors.Is(err, os.ErrExist) {
		info, statErr := os.Lstat(path)
		content, readErr := os.ReadFile(path)
		if statErr != nil || readErr != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || string(content) != "apply\n" || runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
			return errors.New("existing VPS systemd trigger is unsafe")
		}
		return nil
	}
	if err != nil {
		return err
	}
	written, writeErr := file.WriteString("apply\n")
	syncErr, closeErr := file.Sync(), file.Close()
	if writeErr != nil || syncErr != nil || closeErr != nil || written != len("apply\n") {
		_ = os.Remove(path)
		return errors.Join(errors.New("durably create VPS systemd trigger failed"), writeErr, syncErr, closeErr)
	}
	if runtime.GOOS == "windows" {
		return nil
	}
	directory, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	err = directory.Sync()
	closeErr = directory.Close()
	return errors.Join(err, closeErr)
}
