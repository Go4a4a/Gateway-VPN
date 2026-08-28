// Package app wires the unprivileged Gateway VPN management runtime. Network
// mutation remains owned by separately validated Linux controllers.
package app

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sync/atomic"
	"time"

	"gateway-vpn/internal/accesspolicy"
	"gateway-vpn/internal/auth"
	"gateway-vpn/internal/backup"
	"gateway-vpn/internal/bootstrap"
	"gateway-vpn/internal/buildinfo"
	"gateway-vpn/internal/bypass"
	"gateway-vpn/internal/candidateruntime"
	"gateway-vpn/internal/config"
	databasepkg "gateway-vpn/internal/db"
	"gateway-vpn/internal/diagnostics"
	"gateway-vpn/internal/directprobe"
	"gateway-vpn/internal/hilink"
	"gateway-vpn/internal/hostboot"
	loggingpkg "gateway-vpn/internal/logging"
	"gateway-vpn/internal/mihomo"
	"gateway-vpn/internal/modem"
	"gateway-vpn/internal/modemrecovery"
	"gateway-vpn/internal/networkapply"
	"gateway-vpn/internal/operations"
	"gateway-vpn/internal/pathmatrix"
	"gateway-vpn/internal/reconcile"
	retentionpkg "gateway-vpn/internal/retention"
	"gateway-vpn/internal/state"
	"gateway-vpn/internal/store"
	"gateway-vpn/internal/subscription"
	"gateway-vpn/internal/tlsbootstrap"
	"gateway-vpn/internal/traffic"
	updatepkg "gateway-vpn/internal/update"
	"gateway-vpn/internal/watchdog"
	"gateway-vpn/internal/webapi"
	wireguardpkg "gateway-vpn/internal/wireguard"
)

type Runtime struct {
	Config                config.Config
	Database              *sql.DB
	API                   *webapi.Server
	Admin                 bootstrap.AdminResult
	TLS                   tlsbootstrap.Result
	Refresh               *subscription.RefreshCoordinator
	RefreshWorker         *subscription.RefreshWorker
	RefreshDispatch       *subscription.RefreshDispatcher
	Mihomo                *mihomo.TransactionController
	Reconciler            *reconcile.Reconciler
	Routing               interface{ SyncRouting(context.Context) error }
	WireGuard             interface{ SyncWireGuard(context.Context) error }
	ModemRunner           *hilink.Runner
	ModemRecovery         *modemrecovery.Runner
	HealthRunner          *candidateruntime.PeriodicRunner
	DirectRunner          *directprobe.Runner
	Logging               *loggingpkg.Controller
	LoggingSync           webapi.LoggingSynchronizer
	Backups               *backup.Manager
	Retention             *retentionpkg.Cleaner
	TrafficRunner         *traffic.Runner
	Updates               *updatepkg.Stager
	States                *state.Repository
	logger                *slog.Logger
	routingLogger         *slog.Logger
	wireGuardLogger       *slog.Logger
	trafficLogger         *slog.Logger
	retentionInterval     time.Duration
	retentionBacklogDelay time.Duration
	reconcileNow          chan struct{}
	processStartedAt      time.Time
	lastReconcileUnixNano atomic.Int64
}

type brokerHostDiagnostics struct {
	client *networkapply.BrokerClient
}

type runtimeWorkerExit struct {
	name string
	err  error
}

func (provider brokerHostDiagnostics) Collect(ctx context.Context) (diagnostics.HostSnapshot, error) {
	return provider.client.CollectHostDiagnostics(ctx)
}

func Initialize(ctx context.Context, configuration config.Config, configurationPath string, logger *slog.Logger, loggingController *loggingpkg.Controller) (*Runtime, error) {
	if err := configuration.Validate(); err != nil {
		return nil, err
	}
	if logger == nil || loggingController == nil || !filepath.IsAbs(configurationPath) {
		return nil, errors.New("safe logger and logging controller are required")
	}
	managedDatabase, err := backup.OpenManaged(ctx, configuration.System.StateDir, configuration.System.Database)
	if err != nil {
		return nil, err
	}
	database := managedDatabase.Database
	fail := func(err error) (*Runtime, error) {
		database.Close()
		return nil, err
	}
	if err := loggingController.Attach(ctx, database); err != nil {
		return fail(fmt.Errorf("initialize logging settings: %w", err))
	}
	matchers := subscription.NewMatcherRepository(database)
	if _, err := matchers.EnsureDefaults(ctx); err != nil {
		return fail(err)
	}
	authService := auth.Service{Database: database}
	admin, err := bootstrap.EnsureAdmin(ctx, authService, configuration.System.StateDir)
	if err != nil {
		return fail(err)
	}
	hosts := make([]string, 0, len(configuration.API.Listen))
	for _, address := range configuration.API.Listen {
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			return fail(fmt.Errorf("read API TLS host: %w", err))
		}
		hosts = append(hosts, host)
	}
	tlsResult, err := tlsbootstrap.Ensure(configuration.API.TLSCert, configuration.API.TLSKey, hosts)
	if err != nil {
		return fail(err)
	}
	states := state.NewRepository(database)
	bootID, err := hostboot.Read("")
	if err != nil {
		return fail(fmt.Errorf("read Linux boot identity: %w", err))
	}
	startupRecovery, err := initializeStartupPolicy(ctx, database, states, bootID)
	if err != nil {
		return fail(err)
	}
	modems := modem.NewRepository(database, configuration.Modems.RoutingTableStart, configuration.Modems.FwmarkStart)
	subscriptions := subscription.NewRepository(database)
	nodes := subscription.NewNodeRepository(database)
	paths := pathmatrix.NewRepository(database)
	targets := bypass.NewRepository(database)
	networkBroker, err := networkapply.NewBrokerClient("/run/gateway-vpn/network-broker.sock")
	if err != nil {
		return fail(err)
	}
	dataPlane, err := initializeDataPlane(ctx, database, configuration, subscriptions, modems, paths, targets, matchers, states, networkBroker)
	if err != nil {
		return fail(err)
	}
	dataPlane.Reconciler.StartupRecovery = startupRecovery
	systemLogger := logger.With("component", loggingpkg.ComponentSystem)
	subscriptionLogger := logger.With("component", loggingpkg.ComponentSubscription)
	modemLogger := logger.With("component", loggingpkg.ComponentModem)
	recoveryController := &modemrecovery.Controller{Repository: modemrecovery.NewRepository(database), Executor: networkBroker}
	recoveryRunner := modemrecovery.NewRunner(recoveryController)
	recoveryRunner.OnError = func(err error) {
		modemLogger.Warn("bounded physical modem recovery failed", "error", err)
	}
	healthLogger := logger.With("component", loggingpkg.ComponentPathHealth)
	routingLogger := logger.With("component", loggingpkg.ComponentRoutingFirewall)
	wireGuardLogger := logger.With("component", loggingpkg.ComponentWireGuard)
	trafficLogger := logger.With("component", loggingpkg.ComponentTraffic)
	dataPlane.RefreshWorker.OnError = func(subscriptionID string, err error) {
		subscriptionLogger.Warn("scheduled subscription refresh failed", "subscription_id", subscriptionID, "error", err)
	}
	dataPlane.ModemRunner.OnCycle = func(result hilink.CycleResult) {
		dataPlane.Discoveries.Replace(result.Matches)
		recoveryRunner.Submit(modemrecovery.ObservationBatch{Healthy: append([]string(nil), result.PhysicallyHealthyModems...), Failures: cloneStringMap(result.PhysicalFailures)})
		if len(result.ReadyModems) != 0 || len(result.OfflineModems) != 0 || len(result.ConflictModems) != 0 || len(result.Errors) != 0 {
			modemLogger.Info("HiLink modem inventory reconciled", "ready", result.ReadyModems, "offline", result.OfflineModems, "conflicts", len(result.ConflictModems), "errors", len(result.Errors))
		}
	}
	dataPlane.ModemRunner.OnError = func(err error) {
		modemLogger.Warn("HiLink modem reconciliation failed", "error", err)
	}
	dataPlane.HealthRunner.OnCycle = func(result candidateruntime.PeriodicCycleResult) {
		if result.Probed != 0 || result.Deferred != 0 || result.Published != 0 || len(result.Errors) != 0 {
			healthLogger.Info("periodic path health cycle completed", "due", result.Due, "probed", result.Probed, "deferred", result.Deferred, "published", result.Published, "outage_suppressed", result.OutageSuppressed, "errors", len(result.Errors))
		}
	}
	dataPlane.HealthRunner.OnError = func(err error) {
		healthLogger.Warn("periodic path health cycle failed", "error", err)
	}
	dataPlane.DirectRunner.OnCycle = func(result directprobe.CycleResult) {
		if result.Probed != 0 || result.Deferred != 0 || result.Published != 0 || len(result.Errors) != 0 {
			healthLogger.Info("periodic direct Internet health cycle completed", "due", result.Due, "probed", result.Probed, "deferred", result.Deferred, "published", result.Published, "errors", len(result.Errors))
		}
	}
	dataPlane.DirectRunner.OnError = func(err error) {
		healthLogger.Warn("periodic direct Internet health cycle failed", "error", err)
	}
	trafficSessionID, err := traffic.NewSessionID()
	if err != nil {
		return fail(err)
	}
	trafficRunner := &traffic.Runner{
		Collector: traffic.Collector{Database: database}, Authoritative: networkBroker, Mihomo: dataPlane.MihomoClient,
		Interval: traffic.DefaultCheckpointInterval, SessionID: trafficSessionID, SessionStartedAt: time.Now().UTC(),
		OnError: func(err error) { trafficLogger.Warn("authoritative traffic checkpoint failed", "error", err) },
	}
	loggingController.OnError = func(err error) {
		systemLogger.Warn("logging debug expiry persistence failed", "error", err)
	}
	diagnosticBuilder := &diagnostics.Builder{
		Database: database, Configuration: configuration, Host: brokerHostDiagnostics{client: networkBroker}, Journal: networkBroker,
		GatewayVersion: buildinfo.String("gateway-vpn"), ExpectedMihomoVersion: buildinfo.MihomoVersion,
		TLSFingerprint: tlsResult.Fingerprint, MihomoRoot: filepath.Join(configuration.System.StateDir, "mihomo"),
		WatchdogStatus: watchdog.StatusFile{Path: "/run/gateway-vpn-watchdog/status.json"},
	}
	portableBackups, err := backup.NewPortableManager(managedDatabase.Backups, configuration.System.StateDir, configurationPath, buildinfo.String("gateway-vpn"))
	if err != nil {
		return fail(err)
	}
	restores, err := backup.NewRestoreManager(configuration.System.StateDir, configuration.System.Database, configurationPath)
	if err != nil {
		return fail(err)
	}
	restores.ExpectedMihomoBinary = configuration.Mihomo.Binary
	restores.ExpectedAPISecretPath = configuration.Mihomo.APISecretFile
	restores.ExpectedTLSCertPath = configuration.API.TLSCert
	restores.ExpectedTLSKeyPath = configuration.API.TLSKey
	var updates *updatepkg.Stager
	trustedUpdateKey := "/etc/gateway-vpn/update-signing.pub"
	if info, keyErr := os.Lstat(trustedUpdateKey); keyErr == nil && info.Mode()&os.ModeSymlink == 0 && info.Mode().IsRegular() {
		schema, schemaErr := databasepkg.ReadSchemaVersion(ctx, database)
		if schemaErr != nil {
			return fail(schemaErr)
		}
		updates, keyErr = updatepkg.NewStager(configuration.System.StateDir, trustedUpdateKey, updatepkg.VerificationPolicy{
			ExpectedOS: "linux", ExpectedArch: "amd64", CurrentGatewayVersion: buildinfo.Version,
			CurrentSchemaVersion: schema, ConfigGeneration: config.CurrentVersion,
			GatewayAPIContract: updatepkg.GatewayAPIContract, MihomoAPIContract: updatepkg.MihomoAPIContract,
		})
		if keyErr != nil {
			systemLogger.Error("signed update trust configuration is invalid", "error", keyErr)
		}
	} else if keyErr == nil || !errors.Is(keyErr, os.ErrNotExist) {
		systemLogger.Error("signed update trust key is unsafe or unavailable")
	}
	api, err := webapi.New(webapi.Dependencies{
		Database: database, Auth: authService, State: states,
		Modems: modems, Uplinks: dataPlane.Uplinks, Subscriptions: subscriptions, Nodes: nodes,
		Paths: paths, Targets: targets,
		Matchers: matchers, NetworkBroker: networkBroker,
		Discoveries:         dataPlane.Discoveries,
		WireGuardRuntime:    &wireguardpkg.RuntimeStore{Database: database},
		WireGuardConfigPath: filepath.Join(configuration.System.StateDir, "secrets", "wireguard.yaml"),
		WireGuardSync:       networkBroker,
		ModemRuntime:        networkBroker,
		ModemRecovery:       recoveryController,
		ModemReconcile: func(ctx context.Context) (hilink.CycleResult, error) {
			return dataPlane.ModemRunner.Manager.Reconcile(ctx)
		},
		ModemPathProbe:       dataPlane.PathProbe,
		DirectPathProbe:      dataPlane.DirectRunner,
		PathOperations:       dataPlane.PathProbe,
		PathActivator:        dataPlane.Reconciler,
		SubscriptionRefresh:  dataPlane.Refresh,
		SubscriptionDispatch: dataPlane.RefreshDispatch,
		AccessPolicy:         accesspolicy.NewRepository(database),
		Operations:           operations.NewRepository(database),
		BootIDReader: func() (string, error) {
			return hostboot.Read("")
		},
		SubscriptionSecretRoot:  filepath.Join(configuration.System.StateDir, "secrets", "subscriptions"),
		SubscriptionPayloadRoot: filepath.Join(configuration.System.StateDir, "subscriptions"),
		Reconcile: func(ctx context.Context) (any, error) {
			return dataPlane.Reconciler.Reconcile(ctx)
		},
		PeriodicHealth:       &dataPlane.HealthRunner.Schedules,
		PeriodicHealthConfig: dataPlane.HealthRunner.Config,
		ProbeBudget:          dataPlane.ProbeScheduler,
		Logging:              loggingController,
		LoggingSync:          networkBroker,
		Journal:              networkBroker,
		Diagnostics:          diagnosticBuilder,
		Backups:              managedDatabase.Backups,
		PortableBackups:      portableBackups,
		Restores:             restores,
		RestoreApply:         networkBroker,
		Updates:              updates,
		UpdateApply:          networkBroker,
		Watchdog:             &watchdog.Repository{Database: database},
		WatchdogStatus:       watchdog.StatusFile{Path: "/run/gateway-vpn-watchdog/status.json"},
		NetworkCandidate:     networkCandidateBuilder(configuration, database),
		NetworkInterface:     configuration.Network.LANInterface,
		NetworkLANAddress:    configuration.Network.LANAddress,
	})
	if err != nil {
		return fail(err)
	}
	return &Runtime{Config: configuration, Database: database, API: api, Admin: admin, TLS: tlsResult, Refresh: dataPlane.Refresh, RefreshWorker: dataPlane.RefreshWorker, RefreshDispatch: dataPlane.RefreshDispatch, Mihomo: dataPlane.Transactions, Reconciler: dataPlane.Reconciler, Routing: dataPlane.Routing, WireGuard: dataPlane.WireGuard, ModemRunner: dataPlane.ModemRunner, ModemRecovery: recoveryRunner, HealthRunner: dataPlane.HealthRunner, DirectRunner: dataPlane.DirectRunner, Logging: loggingController, LoggingSync: networkBroker, Backups: managedDatabase.Backups, Retention: &retentionpkg.Cleaner{Database: database, PayloadRoot: filepath.Join(configuration.System.StateDir, "subscriptions"), Policy: retentionpkg.DefaultPolicy()}, TrafficRunner: trafficRunner, Updates: updates, States: states, logger: systemLogger, routingLogger: routingLogger, wireGuardLogger: wireGuardLogger, trafficLogger: trafficLogger, reconcileNow: make(chan struct{}, 1), processStartedAt: time.Now().UTC()}, nil
}

func cloneStringMap(input map[string]string) map[string]string {
	result := make(map[string]string, len(input))
	for key, value := range input {
		result[key] = value
	}
	return result
}

func initializeStartupPolicy(ctx context.Context, database *sql.DB, states *state.Repository, bootID string) (bool, error) {
	if database == nil || states == nil {
		return false, errors.New("startup policy repositories are required")
	}
	boot, err := accesspolicy.NewRepository(database).ReconcileBoot(ctx, bootID)
	if err != nil {
		return false, fmt.Errorf("reconcile host boot policy: %w", err)
	}
	recoveredPolicy, err := states.RecoverPolicyTransition(ctx)
	if err != nil {
		return false, fmt.Errorf("recover interrupted policy verification: %w", err)
	}
	if recoveredPolicy {
		return false, nil
	}
	snapshot, err := states.Get(ctx)
	if err != nil {
		return false, fmt.Errorf("read startup runtime state: %w", err)
	}
	if !boot.NewBoot {
		// A process restart must not manufacture a host reboot. Preserve an
		// active/verifying tuple so the observer can compare it with nftables;
		// all blocked states are already fail-closed.
		if snapshot.PathState == state.PathActive || snapshot.PathState == state.PathVerifying || snapshot.PathState == state.PathBlocked && snapshot.GatewayState != state.GatewayBooting {
			return false, nil
		}
		if _, _, err := states.Block(ctx, state.GatewayBlocked, "DATA_PLANE_NOT_YET_OBSERVED"); err != nil {
			return false, fmt.Errorf("record same-boot startup quarantine: %w", err)
		}
		return false, nil
	}
	if boot.StartupBlockUntilQualified {
		if _, _, err := states.Block(ctx, state.GatewayBlocked, "STARTUP_QUALIFICATION_REQUIRED"); err != nil {
			return false, fmt.Errorf("record startup qualification quarantine: %w", err)
		}
		return false, nil
	}
	_, prepared, err := states.PrepareStartupRecovery(ctx)
	if errors.Is(err, store.ErrNotFound) {
		if _, _, blockErr := states.Block(ctx, state.GatewayBlocked, "STARTUP_RECOVERY_UNAVAILABLE"); blockErr != nil {
			return false, errors.Join(err, blockErr)
		}
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("prepare minimal startup recovery: %w", err)
	}
	return prepared, nil
}

// RequestReconcile coalesces fixed SIGHUP requests from the privileged
// watchdog. It does not accept a component, unit, command or desired state.
func (application *Runtime) RequestReconcile() {
	if application == nil || application.reconcileNow == nil {
		return
	}
	select {
	case application.reconcileNow <- struct{}{}:
	default:
	}
}

func (application *Runtime) Serve(ctx context.Context) error {
	if runtime.GOOS != "linux" {
		return errors.New("Gateway VPN production runtime requires Ubuntu/Linux")
	}
	if application == nil || application.API == nil || application.Database == nil {
		return errors.New("Gateway VPN runtime is not initialized")
	}
	if application.Admin.Created {
		application.logger.Warn("bootstrap admin created; read the one-time password locally and change it", "password_file", application.Admin.PasswordFile)
	}
	application.logger.Info("management TLS ready", "certificate_sha256", application.TLS.Fingerprint)
	workerContext, stopWorker := context.WithCancel(ctx)
	defer stopWorker()
	workerDone := make(chan runtimeWorkerExit, 16)
	workers := 0
	startWorker := func(name string, run func(context.Context) error) {
		workers++
		go func() { workerDone <- runtimeWorkerExit{name: name, err: run(workerContext)} }()
	}
	if application.RefreshWorker != nil {
		startWorker("subscription-refresh", application.RefreshWorker.Run)
	}
	if application.RefreshDispatch != nil {
		startWorker("manual-subscription-refresh", application.RefreshDispatch.Run)
		if err := application.RefreshDispatch.WaitReady(workerContext); err != nil {
			stopWorker()
			return fmt.Errorf("start manual subscription refresh dispatcher: %w", err)
		}
	}
	if application.Reconciler != nil {
		startWorker("data-plane-reconcile", application.runReconcileLoop)
	}
	if application.ModemRunner != nil {
		startWorker("modem-reconcile", application.ModemRunner.Run)
	}
	if application.ModemRecovery != nil {
		startWorker("modem-recovery", application.ModemRecovery.Run)
	}
	if application.HealthRunner != nil {
		startWorker("path-health", application.HealthRunner.Run)
	}
	if application.DirectRunner != nil {
		startWorker("direct-health", application.DirectRunner.Run)
	}
	if application.Logging != nil {
		startWorker("logging", application.Logging.Run)
	}
	if application.LoggingSync != nil {
		startWorker("logging-sync", application.runLoggingSyncLoop)
	}
	if application.Backups != nil && application.States != nil {
		startWorker("database-backup", application.runBackupLoop)
	}
	if application.Retention != nil {
		startWorker("retention", application.runRetentionLoop)
	}
	if application.TrafficRunner != nil {
		startWorker("traffic-accounting", application.TrafficRunner.Run)
	}
	startWorker("control-heartbeat", application.runWatchdogHeartbeatLoop)
	serveDone := make(chan error, 1)
	go func() {
		serveDone <- serveHTTPS(workerContext, application.Config.API.Listen, application.Config.API.TLSCert, application.Config.API.TLSKey, application.API, application.logger, func() {
			_ = watchdog.NotifySystemd("READY=1")
		})
	}()
	backgroundErrors := []error{}
	serveCollected := false
	remainingWorkers := workers
	select {
	case <-ctx.Done():
	case serveErr := <-serveDone:
		serveCollected = true
		if serveErr != nil {
			backgroundErrors = append(backgroundErrors, serveErr)
		}
	case exit := <-workerDone:
		remainingWorkers--
		if ctx.Err() == nil {
			if exit.err == nil {
				exit.err = errors.New("worker exited without cancellation")
			}
			backgroundErrors = append(backgroundErrors, fmt.Errorf("critical runtime worker %s stopped: %w", exit.name, exit.err))
		}
	}
	stopWorker()
	_ = watchdog.NotifySystemd("STOPPING=1")
	if !serveCollected {
		if serveErr := <-serveDone; serveErr != nil {
			backgroundErrors = append(backgroundErrors, serveErr)
		}
	}
	for remainingWorkers > 0 {
		exit := <-workerDone
		remainingWorkers--
		if exit.err != nil && !errors.Is(exit.err, context.Canceled) {
			backgroundErrors = append(backgroundErrors, fmt.Errorf("runtime worker %s shutdown: %w", exit.name, exit.err))
		}
	}
	return errors.Join(backgroundErrors...)
}

func (application *Runtime) runBackupLoop(ctx context.Context) error {
	ticker := time.NewTicker(6 * time.Hour)
	defer ticker.Stop()
	for {
		snapshot, created, err := application.Backups.EnsureDaily(ctx)
		if err != nil && ctx.Err() == nil {
			application.logger.Warn("daily verified database snapshot failed", "error", err)
		} else if created {
			application.logger.Info("daily verified database snapshot created", "snapshot_id", snapshot.Manifest.SnapshotID, "bytes", snapshot.Manifest.Database.Bytes)
			if err := application.States.AppendEvent(ctx, state.EventInput{Severity: "INFO", Type: "DATABASE_DAILY_SNAPSHOT_CREATED", Details: map[string]any{"snapshot_id": snapshot.Manifest.SnapshotID, "bytes": snapshot.Manifest.Database.Bytes, "schema_version": snapshot.Manifest.SchemaVersion}}); err != nil && ctx.Err() == nil {
				application.logger.Warn("record daily database snapshot event failed", "error", err)
			}
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

func (application *Runtime) runLoggingSyncLoop(ctx context.Context) error {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		if err := application.LoggingSync.SyncLogging(ctx); err != nil && ctx.Err() == nil {
			application.logger.Warn("journald retention synchronization failed", "error", err)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

func (application *Runtime) runReconcileLoop(ctx context.Context) error {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		if application.Routing != nil {
			if err := application.Routing.SyncRouting(ctx); err != nil && ctx.Err() == nil {
				application.routingLogger.Warn("modem routing synchronization failed", "error", err)
			}
		}
		if application.WireGuard != nil {
			if err := application.WireGuard.SyncWireGuard(ctx); err != nil && ctx.Err() == nil {
				application.wireGuardLogger.Warn("WireGuard management synchronization failed", "error", err)
			}
		}
		if _, err := application.Reconciler.Reconcile(ctx); err != nil && ctx.Err() == nil {
			application.logger.Warn("data-plane reconciliation failed", "error", err)
		}
		application.lastReconcileUnixNano.Store(time.Now().UTC().UnixNano())
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		case <-application.reconcileNow:
		}
	}
}

func (application *Runtime) runWatchdogHeartbeatLoop(ctx context.Context) error {
	file := watchdog.HeartbeatFile{Path: "/run/gateway-vpn-watchdog/control.json"}
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		now := time.Now().UTC()
		pingContext, cancel := context.WithTimeout(ctx, 3*time.Second)
		databaseOK := application.Database.PingContext(pingContext) == nil
		cancel()
		lastReconcileNano := application.lastReconcileUnixNano.Load()
		workersOK := lastReconcileNano > 0 && now.Sub(time.Unix(0, lastReconcileNano)) <= 90*time.Second
		if databaseOK && workersOK {
			heartbeat := watchdog.ControlHeartbeat{
				SchemaVersion: 1, PID: os.Getpid(), ProcessStartedAt: application.processStartedAt.Format(time.RFC3339Nano),
				WrittenAt: now.Format(time.RFC3339Nano), DatabaseOK: true, WorkersOK: true,
				ReconcileLastAt: time.Unix(0, lastReconcileNano).UTC().Format(time.RFC3339Nano),
			}
			if err := file.Write(heartbeat); err != nil && ctx.Err() == nil {
				application.logger.Warn("publish control watchdog heartbeat failed", "error", err)
			}
			_ = watchdog.NotifySystemd("WATCHDOG=1")
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

func (application *Runtime) Close() error {
	if application == nil || application.Database == nil {
		return nil
	}
	return application.Database.Close()
}
