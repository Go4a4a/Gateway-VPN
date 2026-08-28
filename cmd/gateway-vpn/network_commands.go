package main

import (
	"context"
	"database/sql"
	"errors"
	"flag"
	"fmt"
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
	"gateway-vpn/internal/bypass"
	"gateway-vpn/internal/config"
	"gateway-vpn/internal/dataplane"
	"gateway-vpn/internal/diagnostics"
	loggingpkg "gateway-vpn/internal/logging"
	"gateway-vpn/internal/mihomoruntime"
	"gateway-vpn/internal/modem"
	"gateway-vpn/internal/modemrecovery"
	"gateway-vpn/internal/networkapply"
	"gateway-vpn/internal/platformexec"
	"gateway-vpn/internal/state"
	"gateway-vpn/internal/subscription"
	"gateway-vpn/internal/traffic"
	"gateway-vpn/internal/uplink"
	wireguardpkg "gateway-vpn/internal/wireguard"
)

const defaultNetworkTransactionRoot = "/var/lib/gateway-vpn-privileged/network-transactions"

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
	loggingBackend := loggingpkg.JournaldSynchronizer{
		Settings: loggingpkg.Repository{Database: database},
		Runtime:  loggingpkg.RuntimeRepository{Database: database},
		Executor: executor, Paths: loggingpkg.DefaultJournaldPaths(),
	}
	journalReader := loggingpkg.JournalReader{Executor: executor, Journalctl: "/usr/bin/journalctl"}
	hostDiagnostics := diagnostics.HostCollector{
		Executor: executor, IP: "/usr/sbin/ip", NFT: "/usr/sbin/nft", WG: "/usr/bin/wg",
		Uname: "/usr/bin/uname", MihomoBinary: "/opt/gateway-vpn/current/libexec/mihomo", OSReleaseFile: "/etc/os-release",
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
		networkapply.SystemdUpdateAdmin{
			Executor: executor, Systemctl: "/usr/bin/systemctl",
			JournalRoot: filepath.Join(defaultPrivilegedRoot, "update-transactions"),
		},
		traffic.NFTReader{Executor: executor, NFT: "/usr/sbin/nft"},
		modemrecovery.LinuxBackend{Database: database, Executor: executor, Networkctl: "/usr/bin/networkctl"},
	)
	if err != nil {
		fmt.Fprintf(os.Stderr, "create network broker: %v\n", err)
		return 1
	}
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
	paths.ConfigGID = int(gid)
	backend := networkapply.UbuntuBackend{Executor: platformexec.OSExecutor{}, Paths: paths}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	changed, err := networkapply.RollbackFromDisk(ctx, networkapply.DiskStore{Root: *transactionRoot}, backend, *applyID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "network rollback failed: %v\n", err)
		return 1
	}
	if changed {
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
	backend := networkapply.UbuntuBackend{Executor: executor, Paths: paths}
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
