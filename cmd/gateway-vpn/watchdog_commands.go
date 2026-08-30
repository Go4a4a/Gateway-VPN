package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"gateway-vpn/internal/config"
	"gateway-vpn/internal/networkapply"
	"gateway-vpn/internal/platformexec"
	"gateway-vpn/internal/watchdog"
)

const (
	defaultWatchdogHistoryRoot = "/var/lib/gateway-vpn-privileged/watchdog"
	defaultWatchdogStatusPath  = "/run/gateway-vpn-watchdog/status.json"
	defaultControlHeartbeat    = "/run/gateway-vpn-watchdog/control.json"
)

type notifyingWatchdogStatus struct{ file watchdog.StatusFile }

type watchdogManagementFabricClient struct{ client *networkapply.BrokerClient }

func (client watchdogManagementFabricClient) ManagementFabricStatus(ctx context.Context) (watchdog.ManagementFabricStatus, error) {
	status, err := client.client.ManagementFabricStatus(ctx)
	return watchdog.ManagementFabricStatus{NeedsApply: status.NeedsApply, Reason: status.Reason}, err
}

func (client watchdogManagementFabricClient) SyncManagementFabric(ctx context.Context) error {
	return client.client.SyncManagementFabric(ctx)
}

func (writer notifyingWatchdogStatus) Write(status watchdog.Status) error {
	if err := writer.file.Write(status); err != nil {
		return err
	}
	return watchdog.NotifySystemd("WATCHDOG=1")
}

func runWatchdog(args []string) int {
	flags := flag.NewFlagSet("gateway-vpn watchdog", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	configPath := flags.String("config", "/etc/gateway-vpn/config.yaml", "strict bootstrap YAML path")
	historyRoot := flags.String("history-root", defaultWatchdogHistoryRoot, "root-owned durable watchdog history root")
	statusPath := flags.String("status-path", defaultWatchdogStatusPath, "sanitized runtime status path")
	apply := flags.Bool("apply", false, "enable fixed privileged watchdog recovery actions")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		return 2
	}
	if err := requireNetworkPrivilege(*apply); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if *configPath != "/etc/gateway-vpn/config.yaml" || *historyRoot != defaultWatchdogHistoryRoot || *statusPath != defaultWatchdogStatusPath {
		fmt.Fprintln(os.Stderr, "watchdog privileged paths are fixed by the signed release")
		return 1
	}
	configuration, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load Gateway VPN configuration: %v\n", err)
		return 1
	}
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo})).With("component", "watchdog")
	managementFabric, err := networkapply.NewBrokerClient("/run/gateway-vpn/network-broker.sock")
	if err != nil {
		fmt.Fprintf(os.Stderr, "create fixed management fabric broker client: %v\n", err)
		return 1
	}
	probe := &watchdog.SystemProbe{
		Executor: platformexec.OSExecutor{}, Systemctl: "/usr/bin/systemctl", NFT: "/usr/sbin/nft", IP: "/usr/sbin/ip", WG: "/usr/bin/wg",
		SSHD: "/usr/sbin/sshd", SS: "/usr/bin/ss",
		GatewayBinary: "/opt/gateway-vpn/current/bin/gateway-vpn", ConfigPath: *configPath,
		DatabasePath: configuration.System.Database, HeartbeatPath: defaultControlHeartbeat,
		MihomoConfigPath: "/var/lib/gateway-vpn/mihomo/active/config.yaml", MihomoTUN: configuration.Mihomo.TunName,
		LogExportRoot:       "/var/log/gateway-vpn",
		WireGuardConfigPath: "/etc/gateway-vpn/wireguard.yaml",
		LANPrefix:           configuration.Network.LANAddress, WireGuardPrefix: "10.80.0.0/24",
		BootstrapDNS:      configuration.Mihomo.BootstrapDNS,
		RoutingTableStart: configuration.Modems.RoutingTableStart, FwmarkStart: configuration.Modems.FwmarkStart,
		InstallMarkerPath: "/var/lib/gateway-vpn-privileged/install-transactions/active",
		ManagementFabric:  watchdogManagementFabricClient{client: managementFabric},
	}
	supervisor := &watchdog.Supervisor{
		Policies: watchdog.LivePolicySource{DatabasePath: configuration.System.Database},
		Probe:    probe, History: watchdog.HistoryStore{Root: *historyRoot},
		Status: notifyingWatchdogStatus{file: watchdog.StatusFile{Path: *statusPath}}, Logger: logger,
		OnReady: func() error { return watchdog.NotifySystemd("READY=1") },
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	logger.Info("Gateway VPN bounded watchdog starting", "host_reboot_default", false)
	defer watchdog.NotifySystemd("STOPPING=1")
	if err := supervisor.Run(ctx); err != nil {
		logger.Error("Gateway VPN watchdog stopped", "error", err)
		return 1
	}
	logger.Info("Gateway VPN watchdog stopped cleanly")
	return 0
}
