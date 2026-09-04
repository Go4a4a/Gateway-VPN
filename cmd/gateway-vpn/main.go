package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"gateway-vpn/internal/app"
	"gateway-vpn/internal/buildinfo"
	"gateway-vpn/internal/config"
	"gateway-vpn/internal/firewall"
	loggingpkg "gateway-vpn/internal/logging"
	"gateway-vpn/internal/platformexec"
	"gateway-vpn/internal/preflight"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	if len(args) > 0 && args[0] == "serve" {
		return runServe(args[1:])
	}
	if len(args) > 0 && args[0] == "firewall-boot" {
		return runFirewallBoot(args[1:])
	}
	if len(args) > 0 && args[0] == "firewall-guard" {
		return runFirewallGuard(args[1:])
	}
	if len(args) > 0 && args[0] == "network-broker" {
		return runNetworkBroker(args[1:])
	}
	if len(args) > 0 && args[0] == "wireguard-ingress-bootstrap" {
		return runWireGuardIngressBootstrap(args[1:])
	}
	if len(args) > 0 && args[0] == "initial-topology-check" {
		return runInitialTopologyCheck(args[1:])
	}
	if len(args) > 0 && args[0] == "initial-topology-apply" {
		return runInitialTopologyApply(args[1:])
	}
	if len(args) > 0 && args[0] == "watchdog" {
		return runWatchdog(args[1:])
	}
	if len(args) > 0 && args[0] == "network-rollback" {
		return runNetworkRollback(args[1:])
	}
	if len(args) > 0 && args[0] == "network-recover" {
		return runNetworkRecover(args[1:])
	}
	if len(args) > 0 && args[0] == "database-restore" {
		return runDatabaseRestore(args[1:])
	}
	if len(args) > 0 && args[0] == "update-offline-check" {
		return runUpdateOfflineCheck(args[1:])
	}
	if len(args) > 0 && args[0] == "update-lifecycle-check" {
		return runUpdateLifecycleCheck(args[1:])
	}
	if len(args) > 0 && args[0] == "update-apply" {
		return runUpdateApply(args[1:])
	}
	if len(args) > 0 && args[0] == "update-recover" {
		return runUpdateRecover(args[1:])
	}
	if len(args) > 0 && args[0] == "update-rollback" {
		return runUpdateRollback(args[1:])
	}
	if len(args) > 0 && args[0] == "update-finalize" {
		return runUpdateFinalize(args[1:])
	}
	flags := flag.NewFlagSet("gateway-vpn", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	showVersion := flags.Bool("version", false, "print build version")
	checkDefaults := flags.Bool("check-defaults", false, "validate compiled bootstrap defaults")
	checkConfig := flags.String("check-config", "", "strictly validate a bootstrap YAML file")
	if err := flags.Parse(args); err != nil {
		return 2
	}

	switch {
	case *showVersion:
		fmt.Println(buildinfo.String("gateway-vpn"))
		return 0
	case *checkDefaults:
		if err := config.Default().Validate(); err != nil {
			fmt.Fprintf(os.Stderr, "bootstrap defaults are invalid: %v\n", err)
			return 1
		}
		fmt.Println("bootstrap defaults are valid")
		return 0
	case *checkConfig != "":
		if _, err := config.Load(*checkConfig); err != nil {
			fmt.Fprintf(os.Stderr, "bootstrap config is invalid: %v\n", err)
			return 1
		}
		fmt.Println("bootstrap config is valid")
		return 0
	case flags.NArg() == 1 && flags.Arg(0) == "preflight":
		report := preflight.RunHost()
		fmt.Println(report.String())
		if report.Ready() {
			return 0
		}
		return 1
	default:
		fmt.Fprintln(os.Stderr, "usage: gateway-vpn [--version|--check-defaults|--check-config PATH|preflight|firewall-boot|firewall-guard|network-broker|wireguard-ingress-bootstrap|initial-topology-check|initial-topology-apply|watchdog|network-rollback|network-recover|database-restore|update-offline-check|update-lifecycle-check|update-apply|update-recover|update-rollback|update-finalize|serve]")
		fmt.Fprintln(os.Stderr, "no network changes were made")
		return 2
	}
}

func runFirewallGuard(args []string) int {
	flags := flag.NewFlagSet("gateway-vpn firewall-guard", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	configPath := flags.String("config", "/etc/gateway-vpn/config.yaml", "strict bootstrap YAML path")
	markerPath := flags.String("marker-path", "/run/gateway-vpn-firewall-guard/quarantine", "root-owned quarantine marker path")
	apply := flags.Bool("apply", false, "run the privileged firewall integrity guard")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		return 2
	}
	if err := requireNetworkPrivilege(*apply); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	configuration, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load Gateway VPN configuration: %v\n", err)
		return 1
	}
	_, portText, err := net.SplitHostPort(configuration.API.Listen[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "read Gateway VPN API port: %v\n", err)
		return 1
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || port == 0 {
		fmt.Fprintln(os.Stderr, "Gateway VPN API port is invalid")
		return 1
	}
	ruleset, err := firewall.RenderBootBlocked(firewall.BootConfig{
		LANInterface: configuration.Network.LANInterface, TUNInterface: configuration.Mihomo.TunName,
		ManagementInterfaces: configuration.Network.ManagementInterfaces,
		WireGuardInterface:   "wg-mgmt", APIPort: uint16(port), WireGuardListenPort: 51821,
		DisableSSHManagement: configuration.Network.DisableSSHManagement,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "render guarded firewall: %v\n", err)
		return 1
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	guard := &firewall.Guard{
		Executor: platformexec.OSExecutor{}, NFT: "/usr/sbin/nft", IP: "/usr/sbin/ip",
		LANInterface: configuration.Network.LANInterface, Ruleset: ruleset,
		MarkerPath: *markerPath,
	}
	runner := &firewall.GuardRunner{
		Guard: guard, Monitor: firewall.NFTMonitor{Executable: "/usr/sbin/nft"},
		OnResult: func(result firewall.GuardResult) {
			fmt.Fprintf(os.Stdout, "Gateway VPN firewall guard recovered=%t quarantined=%t lan_restored=%t cause=%q\n", result.Recovered, result.Quarantined, result.LANRestored, result.FailureCause)
		},
		OnError: func(err error) { fmt.Fprintf(os.Stderr, "Gateway VPN firewall guard warning: %v\n", err) },
	}
	if err := runner.Run(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "Gateway VPN firewall guard stopped: %v\n", err)
		return 1
	}
	return 0
}

func runFirewallBoot(args []string) int {
	flags := flag.NewFlagSet("gateway-vpn firewall-boot", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	configPath := flags.String("config", "/etc/gateway-vpn/config.yaml", "strict bootstrap YAML path")
	apply := flags.Bool("apply", false, "apply the checked owned nftables table")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		return 2
	}
	configuration, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load Gateway VPN configuration: %v\n", err)
		return 1
	}
	_, portText, err := net.SplitHostPort(configuration.API.Listen[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "read Gateway VPN API port: %v\n", err)
		return 1
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || port == 0 {
		fmt.Fprintln(os.Stderr, "Gateway VPN API port is invalid")
		return 1
	}
	ruleset, err := firewall.RenderBootBlocked(firewall.BootConfig{
		LANInterface: configuration.Network.LANInterface, TUNInterface: configuration.Mihomo.TunName,
		ManagementInterfaces: configuration.Network.ManagementInterfaces,
		WireGuardInterface:   "wg-mgmt", APIPort: uint16(port), WireGuardListenPort: 51821,
		DisableSSHManagement: configuration.Network.DisableSSHManagement,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "render boot firewall: %v\n", err)
		return 1
	}
	if err := firewall.ValidateAndLoad(context.Background(), platformexec.OSExecutor{}, ruleset, firewall.LoadOptions{NFTExecutable: "/usr/sbin/nft", Mutate: *apply}); err != nil {
		fmt.Fprintf(os.Stderr, "apply boot firewall: %v\n", err)
		return 1
	}
	if *apply {
		fmt.Printf("Gateway VPN PATH_BLOCKED firewall loaded (sha256=%s)\n", ruleset.SHA256)
	} else {
		fmt.Printf("Gateway VPN PATH_BLOCKED firewall dry-run is valid (sha256=%s)\n", ruleset.SHA256)
	}
	return 0
}

func runServe(args []string) int {
	flags := flag.NewFlagSet("gateway-vpn serve", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	configPath := flags.String("config", "/etc/gateway-vpn/config.yaml", "strict bootstrap YAML path")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		return 2
	}
	configuration, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load Gateway VPN configuration: %v\n", err)
		return 1
	}
	loggingController, err := loggingpkg.NewController(loggingpkg.BootstrapSettings(configuration.System.LogLevel), nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, "initialize safe logging policy failed")
		return 1
	}
	handler, err := loggingpkg.NewHandler(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}), loggingController)
	if err != nil {
		fmt.Fprintln(os.Stderr, "initialize safe logging handler failed")
		return 1
	}
	logger := slog.New(handler)
	systemLogger := logger.With("component", loggingpkg.ComponentSystem)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	runtime, err := app.Initialize(ctx, configuration, *configPath, logger, loggingController)
	if err != nil {
		systemLogger.Error("Gateway VPN initialization failed", "error", err)
		return 1
	}
	defer runtime.Close()
	reconcileSignal := make(chan os.Signal, 1)
	signal.Notify(reconcileSignal, syscall.SIGHUP)
	defer signal.Stop(reconcileSignal)
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-reconcileSignal:
				runtime.RequestReconcile()
			}
		}
	}()
	if err := runtime.Serve(ctx); err != nil {
		systemLogger.Error("Gateway VPN runtime stopped", "error", err)
		return 1
	}
	systemLogger.Info("Gateway VPN stopped cleanly")
	return 0
}
