package main

import (
	"context"
	"database/sql"
	"errors"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"os/signal"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"syscall"
	"time"

	"gateway-vpn/internal/accesspolicy"
	"gateway-vpn/internal/backup"
	"gateway-vpn/internal/buildinfo"
	"gateway-vpn/internal/bypass"
	"gateway-vpn/internal/config"
	"gateway-vpn/internal/dataplane"
	"gateway-vpn/internal/diagnostics"
	"gateway-vpn/internal/gatewayfabric"
	loggingpkg "gateway-vpn/internal/logging"
	"gateway-vpn/internal/managementfabric"
	"gateway-vpn/internal/mihomoruntime"
	"gateway-vpn/internal/modem"
	"gateway-vpn/internal/modemrecovery"
	"gateway-vpn/internal/networkapply"
	"gateway-vpn/internal/platformexec"
	"gateway-vpn/internal/power"
	"gateway-vpn/internal/removal"
	"gateway-vpn/internal/state"
	"gateway-vpn/internal/subscription"
	"gateway-vpn/internal/traffic"
	updatepkg "gateway-vpn/internal/update"
	"gateway-vpn/internal/uplink"
	"gateway-vpn/internal/wgingress"
	wireguardpkg "gateway-vpn/internal/wireguard"
)

const defaultNetworkTransactionRoot = "/var/lib/gateway-vpn-privileged/network-transactions"

type topologyRuntimeContext struct {
	firewall *dataplane.FirewallBackend
	routing  *dataplane.RoutingBackend
	ingress  *wgingress.Backend
}

func (runtime topologyRuntimeContext) SetTopologyNetwork(interfaceName, lanCIDR string) error {
	if runtime.firewall == nil || runtime.routing == nil || runtime.ingress == nil || len(interfaceName) == 0 || len(interfaceName) > 15 {
		return errors.New("topology runtime context is incomplete")
	}
	prefix, err := netip.ParsePrefix(lanCIDR)
	if err != nil || !prefix.Addr().Is4() {
		return errors.New("topology runtime LAN prefix is invalid")
	}
	runtime.firewall.LANName = interfaceName
	runtime.routing.LANPrefix = prefix.String()
	if interfaceName == wgingress.DefaultInterfaceName {
		runtime.ingress.Repository.ReservedPrefixes = nil
	} else {
		runtime.ingress.Repository.ReservedPrefixes = []netip.Prefix{prefix.Masked()}
	}
	return nil
}

func runNetworkBroker(args []string) int {
	flags := flag.NewFlagSet("gateway-vpn network-broker", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	configPath := flags.String("config", "/etc/gateway-vpn/config.yaml", "strict bootstrap YAML path")
	transactionRoot := flags.String("transaction-root", defaultNetworkTransactionRoot, "root-owned transaction directory")
	apply := flags.Bool("apply", false, "enable the privileged broker")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		return 2
	}
	if err := requireNetworkPrivilege(*apply); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if err := validateSystemdActivation(); err != nil {
		fmt.Fprintf(os.Stderr, "validate broker socket activation: %v\n", err)
		return 1
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	engine, database, err := productionNetworkEngine(ctx, *configPath, *transactionRoot)
	if err != nil {
		fmt.Fprintf(os.Stderr, "initialize network broker: %v\n", err)
		return 1
	}
	defer database.Close()
	configuration, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load data-plane broker configuration: %v\n", err)
		return 1
	}
	if err := engine.Recover(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "recover unfinished network apply: %v\n", err)
		return 1
	}
	lanPrefix, err := netip.ParsePrefix(configuration.Network.LANAddress)
	if err != nil {
		fmt.Fprintf(os.Stderr, "parse LAN prefix for Management Fabric: %v\n", err)
		return 1
	}
	fabricRepository := managementfabric.NewRepository(database, []managementfabric.ReservedPrefix{{Owner: "gateway-lan", CIDR: lanPrefix.Masked().String()}})
	fabricPaths := gatewayfabric.DefaultPaths()
	fabricPaths.TransactionRoot = filepath.Join(filepath.Dir(*transactionRoot), "management-fabric")
	fabricPaths.SecretRoot = filepath.Join(configuration.System.StateDir, "secrets", "management")
	fabricApplier := &gatewayfabric.Applier{Repository: fabricRepository, Executor: platformexec.OSExecutor{}, Paths: fabricPaths}
	if recovered, err := fabricApplier.Recover(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "recover unfinished Gateway Management Fabric transaction: %v\n", err)
		return 1
	} else if recovered {
		fmt.Fprintln(os.Stdout, "Recovered unfinished Gateway Management Fabric transaction")
	}
	uid, _, err := gatewayVPNIdentity()
	if err != nil {
		fmt.Fprintf(os.Stderr, "resolve broker peer identity: %v\n", err)
		return 1
	}
	listener, err := networkapply.ListenerFromSystemdFD(3, uid)
	if err != nil {
		fmt.Fprintf(os.Stderr, "open network broker socket: %v\n", err)
		return 1
	}
	defer listener.Close()
	executor := platformexec.OSExecutor{}
	modemRepository := modem.NewRepository(database, configuration.Modems.RoutingTableStart, configuration.Modems.FwmarkStart)
	uplinkRepository := uplink.NewRepository(database, configuration.Modems.RoutingTableStart, configuration.Modems.FwmarkStart)
	firewallBackend := &dataplane.FirewallBackend{
		Database: database, Uplinks: uplinkRepository, Executor: executor, NFT: "/usr/sbin/nft",
		TUNName: configuration.Mihomo.TunName, LANName: configuration.Network.LANInterface,
	}
	routingBackend := dataplane.RoutingBackend{
		Uplinks:           uplinkRepository,
		Executor:          executor,
		IP:                "/usr/sbin/ip",
		LANPrefix:         configuration.Network.LANAddress,
		WireGuardPrefix:   "10.80.0.0/24",
		BootstrapDNS:      append([]string(nil), configuration.Mihomo.BootstrapDNS...),
		RoutingTableStart: configuration.Modems.RoutingTableStart,
		FwmarkStart:       configuration.Modems.FwmarkStart,
		Gate:              firewallBackend,
	}
	firewallBackend.Routing = &routingBackend
	serviceBackend := dataplane.ServiceFirewallBackend{
		Routing:       routingBackend,
		Modems:        modemRepository,
		Subscriptions: subscription.NewRepository(database),
		Targets:       bypass.NewRepository(database),
		Executor:      executor,
		NFT:           "/usr/sbin/nft",
		BootstrapDNS:  append([]string(nil), configuration.Mihomo.BootstrapDNS...),
		Versions:      subscription.NewVersionRepository(database),
		PayloadRoot:   filepath.Join(configuration.System.StateDir, "subscriptions"),
		AccessPolicy:  accesspolicy.NewRepository(database),
	}
	wireGuardBackend := &dataplane.WireGuardBackend{
		Modems: modemRepository, States: state.NewRepository(database),
		Runtime: wireguardpkg.RuntimeStore{Database: database}, Endpoints: &serviceBackend,
		Executor: executor, IP: "/usr/sbin/ip", WG: "/usr/bin/wg",
		ConfigPath: filepath.Join(configuration.System.StateDir, "secrets", "wireguard.yaml"),
	}
	loggingExporter := &loggingpkg.Exporter{
		Repository: loggingpkg.ExportRepository{Database: database},
		Executor:   executor,
		Paths:      loggingpkg.DefaultExportPaths(),
	}
	loggingBackend := loggingpkg.JournaldSynchronizer{
		Settings: loggingpkg.Repository{Database: database},
		Runtime:  loggingpkg.RuntimeRepository{Database: database},
		Executor: executor, Paths: loggingpkg.DefaultJournaldPaths(),
		Exporter: loggingExporter,
	}
	journalReader := loggingpkg.JournalReader{Executor: executor, Journalctl: "/usr/bin/journalctl"}
	hostDiagnostics := diagnostics.HostCollector{
		Executor: executor, IP: "/usr/sbin/ip", NFT: "/usr/sbin/nft", WG: "/usr/bin/wg",
		Uname: "/usr/bin/uname", MihomoBinary: "/opt/gateway-vpn/current/libexec/mihomo", OSReleaseFile: "/etc/os-release",
	}
	updateAdmin := networkapply.SystemdUpdateAdmin{
		Executor: executor, Systemctl: "/usr/bin/systemctl",
		JournalRoot: filepath.Join(defaultPrivilegedRoot, "update-transactions"),
	}
	if trustedKey, keyErr := updatepkg.LoadPublicKey(defaultTrustedUpdateKey); keyErr == nil {
		currentRelease, releaseErr := updatepkg.ReadReleaseMetadata(filepath.Join(defaultReleaseRoot, "releases", "v"+buildinfo.Version))
		if releaseErr == nil && currentRelease.GatewayVersion == buildinfo.Version {
			store := &updatepkg.RestorePointStore{
				Root: filepath.Join(defaultPrivilegedRoot, "update-restore-points"), ReleaseRoot: defaultReleaseRoot,
				StateDir: configuration.System.StateDir, Configuration: *configPath,
				Verification: updatepkg.VerificationPolicy{
					PublicKey: trustedKey, ExpectedOS: "linux", ExpectedArch: "amd64", ConfigGeneration: config.CurrentVersion,
					CurrentHostContractSHA256: currentRelease.HostContractSHA256,
					GatewayAPIContract:        updatepkg.GatewayAPIContract, MihomoAPIContract: updatepkg.MihomoAPIContract,
				},
			}
			updateAdmin.RestorePoints = &updatepkg.RestorePointController{
				Store: store, Journals: updatepkg.JournalStore{Root: updateAdmin.JournalRoot},
				Requests: updatepkg.RollbackRequestStore{Root: filepath.Join(defaultPrivilegedRoot, "update-rollback")}, ReleaseRoot: defaultReleaseRoot,
			}
		}
	}
	server, err := networkapply.NewBrokerServerWithFullRuntime(
		engine,
		mihomoruntime.SystemdAdmin{Executor: executor, Systemctl: "/usr/bin/systemctl"},
		firewallBackend,
		&serviceBackend,
		&serviceBackend,
		wireGuardBackend,
		loggingBackend,
		journalReader,
		hostDiagnostics,
		networkapply.SystemdRestoreAdmin{Executor: executor, Systemctl: "/usr/bin/systemctl"},
		updateAdmin,
		traffic.NFTReader{Executor: executor, NFT: "/usr/sbin/nft"},
		modemrecovery.LinuxBackend{Database: database, Executor: executor, Networkctl: "/usr/bin/networkctl"},
	)
	if err != nil {
		fmt.Fprintf(os.Stderr, "create network broker: %v\n", err)
		return 1
	}
	ingressSecretRoot := filepath.Join(configuration.System.StateDir, "secrets", "wireguard-ingress")
	server.Ingress = &wgingress.Backend{
		Repository: wgingress.Repository{
			Database: database, SecretRoot: ingressSecretRoot,
			ReservedPrefixes: []netip.Prefix{lanPrefix.Masked()},
		},
		Keys:     wgingress.KeyStore{Root: ingressSecretRoot},
		Executor: executor, IP: "/usr/sbin/ip", WG: "/usr/bin/wg", NFT: "/usr/sbin/nft", Mutate: *apply,
	}
	server.Power = power.DefaultLinuxBackend(database, executor)
	server.Removal = removal.DefaultLinuxBackend(database, executor)
	server.ManagementFabric = fabricApplier
	privilegedBackupRoot := filepath.Join(defaultPrivilegedRoot, "backup-exports")
	privilegedSnapshots, err := backup.NewManager(database, configuration.System.StateDir, configuration.System.Database)
	if err != nil {
		fmt.Fprintf(os.Stderr, "initialize privileged portable backup snapshots: %v\n", err)
		return 1
	}
	privilegedSnapshots.Root = filepath.Join(privilegedBackupRoot, "snapshots")
	privilegedPortableBackups, err := backup.NewPortableManager(privilegedSnapshots, configuration.System.StateDir, *configPath, buildinfo.String("gateway-vpn"))
	if err != nil {
		fmt.Fprintf(os.Stderr, "initialize privileged portable backup exporter: %v\n", err)
		return 1
	}
	privilegedPortableBackups.ExportRoot = filepath.Join(privilegedBackupRoot, "artifacts")
	privilegedPortableBackups.TransientSnapshot = true
	server.PortableBackup = privilegedPortableBackups
	if err := networkapply.ServeBroker(ctx, listener, server); err != nil {
		fmt.Fprintf(os.Stderr, "network broker stopped: %v\n", err)
		return 1
	}
	return 0
}

func runNetworkRollback(args []string) int {
	flags := flag.NewFlagSet("gateway-vpn network-rollback", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	applyID := flags.String("id", "", "safe network apply id")
	configPath := flags.String("config", "/etc/gateway-vpn/config.yaml", "strict bootstrap YAML path")
	transactionRoot := flags.String("transaction-root", defaultNetworkTransactionRoot, "root-owned transaction directory")
	apply := flags.Bool("apply", false, "perform the rollback")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 || *applyID == "" {
		return 2
	}
	if err := requireNetworkPrivilege(*apply); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	_, gid, err := gatewayVPNIdentity()
	if err != nil {
		fmt.Fprintf(os.Stderr, "resolve managed file group: %v\n", err)
		return 1
	}
	paths := networkapply.DefaultUbuntuPaths()
	paths.ConfigFile = *configPath
	paths.ConfigGID = int(gid)
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	store := networkapply.DiskStore{Root: *transactionRoot}
	manifest, _, err := store.Load(*applyID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load network rollback transaction: %v\n", err)
		return 1
	}
	var backend networkapply.SnapshotBackend = networkapply.UbuntuBackend{Executor: platformexec.OSExecutor{}, Paths: paths}
	var rollbackEngine *networkapply.Engine
	var database *sql.DB
	engine, opened, initErr := productionNetworkEngine(ctx, *configPath, *transactionRoot)
	if initErr == nil {
		rollbackEngine = engine
		database = opened
		defer database.Close()
		backend = engine.Backend
	} else if manifest.SchemaVersion != networkapply.LegacyManifestSchema {
		fmt.Fprintf(os.Stderr, "initialize Ethernet network rollback: %v\n", initErr)
		return 1
	}
	changed, err := networkapply.RollbackFromDisk(ctx, store, backend, *applyID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "network rollback failed: %v\n", err)
		return 1
	}
	if changed {
		if rollbackEngine != nil {
			transaction, stateErr := rollbackEngine.Repository.Get(ctx, *applyID)
			if stateErr == nil && (transaction.State == networkapply.StatePreparing || transaction.State == networkapply.StateArmed || transaction.State == networkapply.StateApplied || transaction.State == networkapply.StateConfirming) {
				stateErr = rollbackEngine.Repository.Transition(ctx, transaction.ID, []string{transaction.State}, networkapply.StateRolledBack, "ROLLBACK_TIMER")
			}
			if stateErr != nil {
				fmt.Fprintf(os.Stderr, "network rollback restored host state but could not finalize SQLite status: %v\n", stateErr)
				return 1
			}
		}
		fmt.Println("Gateway VPN network transaction rolled back")
	} else {
		fmt.Println("Gateway VPN network transaction already terminal")
	}
	return 0
}

func runNetworkRecover(args []string) int {
	flags := flag.NewFlagSet("gateway-vpn network-recover", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	configPath := flags.String("config", "/etc/gateway-vpn/config.yaml", "strict bootstrap YAML path")
	transactionRoot := flags.String("transaction-root", defaultNetworkTransactionRoot, "root-owned transaction directory")
	apply := flags.Bool("apply", false, "recover or roll back unfinished transactions")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		return 2
	}
	if err := requireNetworkPrivilege(*apply); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	engine, database, err := productionNetworkEngine(ctx, *configPath, *transactionRoot)
	if err != nil {
		fmt.Fprintf(os.Stderr, "initialize network recovery: %v\n", err)
		return 1
	}
	defer database.Close()
	if err := engine.Recover(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "network recovery failed: %v\n", err)
		return 1
	}
	fmt.Println("Gateway VPN network recovery complete")
	return 0
}

func productionNetworkEngine(ctx context.Context, configPath, transactionRoot string) (*networkapply.Engine, *sql.DB, error) {
	configuration, err := config.Load(configPath)
	if err != nil {
		return nil, nil, err
	}
	managedDatabase, err := backup.OpenManaged(ctx, configuration.System.StateDir, configuration.System.Database)
	if err != nil {
		return nil, nil, err
	}
	database := managedDatabase.Database
	fail := func(err error) (*networkapply.Engine, *sql.DB, error) {
		database.Close()
		return nil, nil, err
	}
	_, gid, err := gatewayVPNIdentity()
	if err != nil {
		return fail(err)
	}
	paths := networkapply.DefaultUbuntuPaths()
	paths.ConfigFile = configPath
	paths.ConfigGID = int(gid)
	executor := platformexec.OSExecutor{}
	uplinkRepository := uplink.NewRepository(database, configuration.Modems.RoutingTableStart, configuration.Modems.FwmarkStart)
	topologyFirewall := &dataplane.FirewallBackend{
		Database: database, Uplinks: uplinkRepository, Executor: executor, NFT: paths.NFT,
		TUNName: configuration.Mihomo.TunName, LANName: configuration.Network.LANInterface,
	}
	topologyRouting := &dataplane.RoutingBackend{
		Uplinks: uplinkRepository, Executor: executor, IP: paths.IP,
		LANPrefix: configuration.Network.LANAddress, WireGuardPrefix: "10.80.0.0/24",
		BootstrapDNS:      append([]string(nil), configuration.Mihomo.BootstrapDNS...),
		RoutingTableStart: configuration.Modems.RoutingTableStart,
		FwmarkStart:       configuration.Modems.FwmarkStart, Gate: topologyFirewall,
	}
	topologyFirewall.Routing = topologyRouting
	lanPrefix, err := netip.ParsePrefix(configuration.Network.LANAddress)
	if err != nil {
		return fail(err)
	}
	ingressSecretRoot := filepath.Join(configuration.System.StateDir, "secrets", "wireguard-ingress")
	topologyIngress := &wgingress.Backend{
		Repository: wgingress.Repository{Database: database, SecretRoot: ingressSecretRoot, ReservedPrefixes: []netip.Prefix{lanPrefix.Masked()}},
		Keys:       wgingress.KeyStore{Root: ingressSecretRoot}, Executor: executor,
		IP: paths.IP, WG: "/usr/bin/wg", NFT: paths.NFT, Mutate: true,
	}
	backend := networkapply.UbuntuBackend{
		Executor: executor, Paths: paths, Database: database,
		RoutingTableStart: configuration.Modems.RoutingTableStart,
		FwmarkStart:       configuration.Modems.FwmarkStart,
		TopologyGate:      topologyFirewall, TopologyRouting: topologyRouting,
		TopologyIngress: topologyIngress,
		TopologyContext: topologyRuntimeContext{firewall: topologyFirewall, routing: topologyRouting, ingress: topologyIngress},
	}
	timer := networkapply.SystemdRollbackTimer{Executor: executor, Systemctl: paths.Systemctl}
	engine := networkapply.NewEngine(networkapply.NewRepository(database), networkapply.DiskStore{Root: transactionRoot}, backend, timer)
	return engine, database, nil
}

func gatewayVPNIdentity() (uint32, uint32, error) {
	account, err := user.Lookup("gateway-vpn")
	if err != nil {
		return 0, 0, err
	}
	uid, err := strconv.ParseUint(account.Uid, 10, 32)
	if err != nil {
		return 0, 0, err
	}
	group, err := user.LookupGroup("gateway-vpn")
	if err != nil {
		return 0, 0, err
	}
	gid, err := strconv.ParseUint(group.Gid, 10, 32)
	if err != nil {
		return 0, 0, err
	}
	return uint32(uid), uint32(gid), nil
}

func requireNetworkPrivilege(apply bool) error {
	if !apply {
		return errors.New("privileged network operation requires explicit --apply")
	}
	if runtime.GOOS != "linux" {
		return errors.New("privileged network operation requires Ubuntu/Linux")
	}
	if os.Geteuid() != 0 {
		return errors.New("privileged network operation requires root")
	}
	return nil
}

func validateSystemdActivation() error {
	pid, err := strconv.Atoi(os.Getenv("LISTEN_PID"))
	if err != nil || pid != os.Getpid() {
		return errors.New("LISTEN_PID does not match broker process")
	}
	fds, err := strconv.Atoi(os.Getenv("LISTEN_FDS"))
	if err != nil || fds != 1 {
		return errors.New("exactly one systemd socket is required")
	}
	return nil
}
