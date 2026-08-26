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
	"time"

	"gateway-vpn/internal/auth"
	"gateway-vpn/internal/backup"
	"gateway-vpn/internal/bootstrap"
	"gateway-vpn/internal/buildinfo"
	"gateway-vpn/internal/bypass"
	"gateway-vpn/internal/candidateruntime"
	"gateway-vpn/internal/config"
	databasepkg "gateway-vpn/internal/db"
	"gateway-vpn/internal/diagnostics"
	"gateway-vpn/internal/hilink"
	loggingpkg "gateway-vpn/internal/logging"
	"gateway-vpn/internal/mihomo"
	"gateway-vpn/internal/modem"
	"gateway-vpn/internal/networkapply"
	"gateway-vpn/internal/pathmatrix"
	"gateway-vpn/internal/reconcile"
	retentionpkg "gateway-vpn/internal/retention"
	"gateway-vpn/internal/state"
	"gateway-vpn/internal/subscription"
	"gateway-vpn/internal/tlsbootstrap"
	updatepkg "gateway-vpn/internal/update"
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
	Mihomo                *mihomo.TransactionController
	Reconciler            *reconcile.Reconciler
	Routing               interface{ SyncRouting(context.Context) error }
	WireGuard             interface{ SyncWireGuard(context.Context) error }
	ModemRunner           *hilink.Runner
	HealthRunner          *candidateruntime.PeriodicRunner
	Logging               *loggingpkg.Controller
	LoggingSync           webapi.LoggingSynchronizer
	Backups               *backup.Manager
	Retention             *retentionpkg.Cleaner
	Updates               *updatepkg.Stager
	States                *state.Repository
	logger                *slog.Logger
	routingLogger         *slog.Logger
	wireGuardLogger       *slog.Logger
	retentionInterval     time.Duration
	retentionBacklogDelay time.Duration
}

type brokerHostDiagnostics struct {
	client *networkapply.BrokerClient
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
	recoveredPolicy, err := states.RecoverPolicyTransition(ctx)
	if err != nil {
		return fail(fmt.Errorf("recover interrupted policy verification: %w", err))
	}
	if !recoveredPolicy {
		_, _, _ = states.Block(ctx, state.GatewayBlocked, "DATA_PLANE_NOT_YET_OBSERVED")
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
	systemLogger := logger.With("component", loggingpkg.ComponentSystem)
	subscriptionLogger := logger.With("component", loggingpkg.ComponentSubscription)
	modemLogger := logger.With("component", loggingpkg.ComponentModem)
	healthLogger := logger.With("component", loggingpkg.ComponentPathHealth)
	routingLogger := logger.With("component", loggingpkg.ComponentRoutingFirewall)
	wireGuardLogger := logger.With("component", loggingpkg.ComponentWireGuard)
	dataPlane.RefreshWorker.OnError = func(subscriptionID string, err error) {
		subscriptionLogger.Warn("scheduled subscription refresh failed", "subscription_id", subscriptionID, "error", err)
	}
	dataPlane.ModemRunner.OnCycle = func(result hilink.CycleResult) {
		dataPlane.Discoveries.Replace(result.Matches)
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
	loggingController.OnError = func(err error) {
		systemLogger.Warn("logging debug expiry persistence failed", "error", err)
	}
	diagnosticBuilder := &diagnostics.Builder{
		Database: database, Configuration: configuration, Host: brokerHostDiagnostics{client: networkBroker}, Journal: networkBroker,
		GatewayVersion: buildinfo.String("gateway-vpn"), ExpectedMihomoVersion: buildinfo.MihomoVersion,
		TLSFingerprint: tlsResult.Fingerprint, MihomoRoot: filepath.Join(configuration.System.StateDir, "mihomo"),
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
		Modems: modems, Subscriptions: subscriptions, Nodes: nodes,
		Paths: paths, Targets: targets,
		Matchers: matchers, NetworkBroker: networkBroker,
		Discoveries:         dataPlane.Discoveries,
		WireGuardRuntime:    &wireguardpkg.RuntimeStore{Database: database},
		WireGuardConfigPath: filepath.Join(configuration.System.StateDir, "secrets", "wireguard.yaml"),
		WireGuardSync:       networkBroker,
		ModemRuntime:        networkBroker,
		ModemReconcile: func(ctx context.Context) (hilink.CycleResult, error) {
			return dataPlane.ModemRunner.Manager.Reconcile(ctx)
		},
		ModemPathProbe:          dataPlane.PathProbe,
		PathOperations:          dataPlane.PathProbe,
		PathActivator:           dataPlane.Reconciler,
		SubscriptionRefresh:     dataPlane.Refresh,
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
		NetworkCandidate:     networkCandidateBuilder(configuration, database),
		NetworkInterface:     configuration.Network.LANInterface,
		NetworkLANAddress:    configuration.Network.LANAddress,
	})
	if err != nil {
		return fail(err)
	}
	return &Runtime{Config: configuration, Database: database, API: api, Admin: admin, TLS: tlsResult, Refresh: dataPlane.Refresh, RefreshWorker: dataPlane.RefreshWorker, Mihomo: dataPlane.Transactions, Reconciler: dataPlane.Reconciler, Routing: dataPlane.Routing, WireGuard: dataPlane.WireGuard, ModemRunner: dataPlane.ModemRunner, HealthRunner: dataPlane.HealthRunner, Logging: loggingController, LoggingSync: networkBroker, Backups: managedDatabase.Backups, Retention: &retentionpkg.Cleaner{Database: database, PayloadRoot: filepath.Join(configuration.System.StateDir, "subscriptions"), Policy: retentionpkg.DefaultPolicy()}, Updates: updates, States: states, logger: systemLogger, routingLogger: routingLogger, wireGuardLogger: wireGuardLogger}, nil
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
	workerDone := make(chan error, 8)
	workers := 0
	if application.RefreshWorker != nil {
		workers++
		go func() { workerDone <- application.RefreshWorker.Run(workerContext) }()
	}
	if application.Reconciler != nil {
		workers++
		go func() { workerDone <- application.runReconcileLoop(workerContext) }()
	}
	if application.ModemRunner != nil {
		workers++
		go func() { workerDone <- application.ModemRunner.Run(workerContext) }()
	}
	if application.HealthRunner != nil {
		workers++
		go func() { workerDone <- application.HealthRunner.Run(workerContext) }()
	}
	if application.Logging != nil {
		workers++
		go func() { workerDone <- application.Logging.Run(workerContext) }()
	}
	if application.LoggingSync != nil {
		workers++
		go func() { workerDone <- application.runLoggingSyncLoop(workerContext) }()
	}
	if application.Backups != nil && application.States != nil {
		workers++
		go func() { workerDone <- application.runBackupLoop(workerContext) }()
	}
	if application.Retention != nil {
		workers++
		go func() { workerDone <- application.runRetentionLoop(workerContext) }()
	}
	serveErr := ServeHTTPS(ctx, application.Config.API.Listen, application.Config.API.TLSCert, application.Config.API.TLSKey, application.API, application.logger)
	stopWorker()
	backgroundErrors := []error{serveErr}
	for index := 0; index < workers; index++ {
		backgroundErrors = append(backgroundErrors, <-workerDone)
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
