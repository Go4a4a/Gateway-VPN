package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"gateway-vpn/internal/backup"
	"gateway-vpn/internal/config"
)

const defaultRestoreTransactionRoot = "/var/lib/gateway-vpn-privileged/restore-transactions"

func runDatabaseRestore(args []string) int {
	flags := flag.NewFlagSet("gateway-vpn database-restore", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	configPath := flags.String("config", "/etc/gateway-vpn/config.yaml", "strict bootstrap YAML path")
	transactionRoot := flags.String("transaction-root", defaultRestoreTransactionRoot, "root-owned restore transaction directory")
	apply := flags.Bool("apply", false, "apply the one verified pending restore")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		return 2
	}
	if err := requireNetworkPrivilege(*apply); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if os.Getenv("GATEWAY_VPN_DATABASE_RESTORE_UNIT") != "1" {
		fmt.Fprintln(os.Stderr, "database restore may run only inside the fixed systemd restore unit")
		return 1
	}
	configuration, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "load current Gateway VPN configuration failed")
		return 1
	}
	uid, gid, err := gatewayVPNIdentity()
	if err != nil {
		fmt.Fprintln(os.Stderr, "resolve Gateway VPN state ownership failed")
		return 1
	}
	manager, err := backup.NewRestoreManager(configuration.System.StateDir, configuration.System.Database, *configPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "initialize pending restore manager failed")
		return 1
	}
	manager.ExpectedMihomoBinary = configuration.Mihomo.Binary
	manager.ExpectedAPISecretPath = configuration.Mihomo.APISecretFile
	manager.ExpectedTLSCertPath = configuration.API.TLSCert
	manager.ExpectedTLSKeyPath = configuration.API.TLSKey
	applier, err := backup.NewRestoreApplier(manager, *transactionRoot, int(uid), int(gid))
	if err != nil {
		fmt.Fprintln(os.Stderr, "initialize root restore transaction failed")
		return 1
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	result, err := applier.Apply(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "verified database restore failed and remains fail-closed: %v\n", err)
		return 1
	}
	fmt.Printf("Gateway VPN restore %s applied from snapshot %s; pre-restore snapshot %s; reconciliation required\n", result.RestoreID, result.SnapshotID, result.PreRestoreSnapshot)
	return 0
}
