package app

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"gateway-vpn/internal/accesspolicy"
	"gateway-vpn/internal/bootstrap"
	"gateway-vpn/internal/buildinfo"
	"gateway-vpn/internal/bypass"
	"gateway-vpn/internal/candidateruntime"
	"gateway-vpn/internal/config"
	"gateway-vpn/internal/directprobe"
	"gateway-vpn/internal/health"
	"gateway-vpn/internal/hilink"
	"gateway-vpn/internal/mihomo"
	"gateway-vpn/internal/mihomoruntime"
	"gateway-vpn/internal/modem"
	"gateway-vpn/internal/networkapply"
	"gateway-vpn/internal/operations"
	"gateway-vpn/internal/pathmatrix"
	"gateway-vpn/internal/pathruntime"
	"gateway-vpn/internal/platformexec"
	"gateway-vpn/internal/reconcile"
	"gateway-vpn/internal/scheduler"
	"gateway-vpn/internal/state"
	"gateway-vpn/internal/subscription"
	"gateway-vpn/internal/subscriptionnet"
)

type dataPlaneComponents struct {
	Refresh         *subscription.RefreshCoordinator
	RefreshWorker   *subscription.RefreshWorker
	RefreshDispatch *subscription.RefreshDispatcher
	Transactions    *mihomo.TransactionController
	Reconciler      *reconcile.Reconciler
	Routing         candidateruntime.RoutingSynchronizer
	WireGuard       interface{ SyncWireGuard(context.Context) error }
	PathProbe       *candidateruntime.Runtime
	HealthRunner    *candidateruntime.PeriodicRunner
	DirectRunner    *directprobe.Runner
	ProbeScheduler  *scheduler.Scheduler
	ModemRunner     *hilink.Runner
	Discoveries     *hilink.DiscoveryRegistry
	MihomoClient    *mihomo.Client
}

func initializeDataPlane(ctx context.Context, database *sql.DB, configuration config.Config, subscriptions *subscription.Repository, modems *modem.Repository, paths *pathmatrix.Repository, targets *bypass.Repository, matchers *subscription.MatcherRepository, states *state.Repository, broker *networkapply.BrokerClient) (dataPlaneComponents, error) {
	if database == nil || subscriptions == nil || modems == nil || paths == nil || targets == nil || matchers == nil || states == nil || broker == nil {
		return dataPlaneComponents{}, errors.New("data-plane repositories and privileged broker are required")
	}
	secret, err := readBoundedSecret(configuration.Mihomo.APISecretFile, 4096)
	if err != nil {
		return dataPlaneComponents{}, fmt.Errorf("read Mihomo API secret: %w", err)
	}
	client, err := mihomo.NewClient("http://"+configuration.Mihomo.APIAddress, secret, &http.Client{Timeout: 15 * time.Second})
	if err != nil {
		return dataPlaneComponents{}, err
	}
	executor := platformexec.OSExecutor{}
	tunInspector := mihomoruntime.IPLinkInspector{Executor: executor, IP: "/usr/sbin/ip"}
	operationLock := &sync.Mutex{}
	linuxRuntime := &mihomoruntime.LinuxRuntime{
		Root:            filepath.Join(configuration.System.StateDir, "mihomo"),
		ExpectedVersion: buildinfo.MihomoVersion,
		TUNName:         configuration.Mihomo.TunName,
		API:             client,
		Broker:          broker,
		Switcher:        mihomoruntime.AtomicSymlinkSwitcher{},
		TUN:             tunInspector,
	}
	transactions := &mihomo.TransactionController{
		Root: filepath.Join(configuration.System.StateDir, "mihomo"),
		Validator: mihomo.BinaryValidator{
			Executor: executor, Executable: configuration.Mihomo.Binary,
		},
		Runtime: linuxRuntime,
	}
	if err := transactions.RecoverLKG(ctx); err != nil {
		return dataPlaneComponents{}, fmt.Errorf("recover interrupted Mihomo generation: %w", err)
	}
	probeScheduler, err := scheduler.New(scheduler.DefaultConfig())
	if err != nil {
		return dataPlaneComponents{}, err
	}
	directPaths := accesspolicy.NewDirectPathRepository(database)
	accessPolicies := accesspolicy.NewRepository(database)
	directProber, err := directprobe.New(modems, directPaths, targets, broker, probeScheduler, configuration.Mihomo.BootstrapDNS)
	if err != nil {
		return dataPlaneComponents{}, fmt.Errorf("initialize direct Internet prober: %w", err)
	}
	directRunner, err := directprobe.NewRunner(directProber, directprobe.DefaultRunnerConfig())
	if err != nil {
		return dataPlaneComponents{}, fmt.Errorf("initialize direct Internet probe runner: %w", err)
	}
	baseProber := health.MihomoProber{
		Client:            client,
		TransportURL:      configuration.Mihomo.TransportProbeURL,
		TransportTimeout:  time.Duration(configuration.Mihomo.TransportProbeTimeoutSeconds) * time.Second,
		TransportExpected: configuration.Mihomo.TransportExpectedStatus,
	}
	bodyProbe, err := health.NewBodyProbe(client, configuration.Mihomo.ProbeAddress)
	if err != nil {
		return dataPlaneComponents{}, fmt.Errorf("initialize Mihomo body probe: %w", err)
	}
	baseProber.Body = bodyProbe
	proberForClass := func(class string) health.Prober {
		return health.ScheduledProber{
			Inner: baseProber, Scheduler: probeScheduler,
			Class: class, EstimatedBytes: 4 * 1024,
			BodyEstimatedBytes: health.MaxProbeBodyBytes + 4*1024,
		}
	}
	scheduledProber := proberForClass(scheduler.ClassFailover)
	versions := subscription.NewVersionRepository(database)
	candidateRuntime := &candidateruntime.Runtime{
		Subscriptions:  subscriptions,
		Versions:       versions,
		Modems:         modems,
		Targets:        targets,
		Paths:          paths,
		State:          states,
		TargetStates:   &health.TargetOutageEvaluator{Database: database, Config: health.DefaultTargetOutageConfig()},
		Controller:     transactions,
		Selector:       client,
		Routing:        broker,
		EndpointAccess: broker,
		Prober:         scheduledProber,
		ProberForClass: proberForClass,
		Qualifier:      health.Qualifier{MaxConcurrency: 2, ContinueAfterRequiredFailure: true},
		PayloadRoot:    filepath.Join(configuration.System.StateDir, "subscriptions"),
		BaseInput: mihomo.Input{
			ExternalController: configuration.Mihomo.APIAddress,
			ProbeListener:      configuration.Mihomo.ProbeAddress,
			APISecret:          secret,
			TUNName:            configuration.Mihomo.TunName,
			TUNStack:           configuration.Mihomo.Stack,
			LANInterface:       configuration.Network.LANInterface,
			ProviderDirectory:  "providers",
			BootstrapDNS:       append([]string(nil), configuration.Mihomo.BootstrapDNS...),
		},
		EvidenceTTL:   5 * time.Minute,
		OperationLock: operationLock,
	}
	fetcher, err := subscription.NewFetcher(nil, nil)
	if err != nil {
		return dataPlaneComponents{}, err
	}
	modemFetcher, err := subscriptionnet.NewModemBoundFetcher(fetcher, modems, broker, configuration.Mihomo.BootstrapDNS)
	if err != nil {
		return dataPlaneComponents{}, err
	}
	operationRepository := operations.NewRepository(database)
	ladderFetcher, err := subscriptionnet.NewRouteLadderFetcher(
		fetcher,
		subscriptionnet.NewRouteRepository(database),
		accessPolicies,
		modemFetcher,
		client,
		configuration.Mihomo.ProbeAddress,
		configuration.Mihomo.BootstrapDNS,
		operationLock,
		operationRepository,
	)
	if err != nil {
		return dataPlaneComponents{}, fmt.Errorf("initialize resilient subscription fetcher: %w", err)
	}
	refresh := subscription.NewRefreshCoordinator(
		subscriptions,
		versions,
		matchers,
		subscription.NewRefreshRepository(database),
		ladderFetcher,
		subscription.FileSourceURLReader{Root: filepath.Join(configuration.System.StateDir, "secrets", "subscriptions")},
		candidateRuntime,
		filepath.Join(configuration.System.StateDir, "subscriptions"),
	)
	refresh.Operations = operationRepository
	refreshDispatch, err := subscription.NewRefreshDispatcher(refresh, 2, 64)
	if err != nil {
		return dataPlaneComponents{}, fmt.Errorf("initialize manual refresh dispatcher: %w", err)
	}
	worker := &subscription.RefreshWorker{Coordinator: refresh, Subscriptions: subscriptions}
	identitySalt, err := bootstrap.EnsureModemIdentitySalt(configuration.System.StateDir)
	if err != nil {
		return dataPlaneComponents{}, fmt.Errorf("initialize modem identity salt: %w", err)
	}
	modemManager := &hilink.Manager{
		Probe: hilink.HostProbe(), LeaseReader: hilink.NetworkdLeaseReader{},
		Routes: hilink.AuthoritativeRoutes{Broker: broker}, Modems: modems,
		IdentitySalt: identitySalt, LANPrefix: configuration.Network.LANAddress,
		WireGuardPrefix: "10.80.0.0/24",
	}
	discoveries := hilink.NewDiscoveryRegistry(modems)
	modemRunner := &hilink.Runner{Manager: modemManager, Watcher: hilink.HostLinkWatcher(), ReconcileInterval: 5 * time.Second}
	pathActuator := &pathruntime.Actuator{
		Database: database, Targets: targets, Broker: broker, Mihomo: client,
		BodyProber: scheduledProber, OperationLock: operationLock,
		StartupProbeURL:      configuration.Mihomo.TransportProbeURL,
		StartupProbeTimeout:  time.Duration(configuration.Mihomo.TransportProbeTimeoutSeconds) * time.Second,
		StartupProbeExpected: configuration.Mihomo.TransportExpectedStatus,
	}
	pathObserver := pathruntime.Observer{Database: database, Broker: broker, Mihomo: client, TUN: tunInspector, State: states, TUNName: configuration.Mihomo.TunName, ExpectedVersion: buildinfo.MihomoVersion, OperationLock: operationLock}
	reconciler := &reconcile.Reconciler{
		Observer: pathObserver, Inventory: reconcile.SQLiteInventory{Database: database},
		State: states, Actuator: pathActuator,
		AccessPaths: directPaths, AccessPolicy: accessPolicies,
	}
	healthRunner := &candidateruntime.PeriodicRunner{
		Runtime: candidateRuntime,
		Schedules: health.PeriodicRepository{
			Database: database,
		},
		Paths: paths, State: states,
		Reconcile: func(ctx context.Context) (any, error) {
			return reconciler.Reconcile(ctx)
		},
		Config: candidateruntime.DefaultPeriodicConfig(),
	}
	return dataPlaneComponents{Refresh: refresh, RefreshWorker: worker, RefreshDispatch: refreshDispatch, Transactions: transactions, Reconciler: reconciler, Routing: broker, WireGuard: broker, PathProbe: candidateRuntime, HealthRunner: healthRunner, DirectRunner: directRunner, ProbeScheduler: probeScheduler, ModemRunner: modemRunner, Discoveries: discoveries, MihomoClient: client}, nil
}

func readBoundedSecret(filename string, maximum int64) (string, error) {
	if !filepath.IsAbs(filename) || maximum <= 0 {
		return "", errors.New("absolute secret path and positive size limit are required")
	}
	info, err := os.Lstat(filename)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maximum {
		return "", errors.New("secret must be a bounded regular non-symlink file")
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return "", errors.New("secret permissions are too broad")
	}
	file, err := os.Open(filename)
	if err != nil {
		return "", errors.New("open secret failed")
	}
	defer file.Close()
	content, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || int64(len(content)) > maximum {
		return "", errors.New("read bounded secret failed")
	}
	value := strings.TrimSpace(string(content))
	if value == "" || strings.ContainsAny(value, "\r\n\x00") {
		return "", errors.New("secret content is empty or invalid")
	}
	return value, nil
}
