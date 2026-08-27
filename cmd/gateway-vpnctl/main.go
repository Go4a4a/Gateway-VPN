package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"gateway-vpn/internal/buildinfo"
	"gateway-vpn/internal/db"
	"gateway-vpn/internal/pathmatrix"
	"gateway-vpn/internal/state"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	if len(args) > 0 && args[0] == "status" {
		return runStatus(args[1:])
	}
	if len(args) > 0 && args[0] == "release-keygen" {
		return runReleaseKeygen(args[1:])
	}
	if len(args) > 0 && args[0] == "release-key-verify" {
		return runReleaseKeyVerify(args[1:])
	}
	if len(args) > 0 && args[0] == "release-key-backup" {
		return runReleaseKeyBackup(args[1:])
	}
	if len(args) > 0 && args[0] == "release-keyfile-create" {
		return runReleaseKeyfileCreate(args[1:])
	}
	if len(args) > 0 && args[0] == "release-keyfile-verify" {
		return runReleaseKeyfileVerify(args[1:])
	}
	if len(args) > 0 && args[0] == "release-keyfile-backup" {
		return runReleaseKeyfileBackup(args[1:])
	}
	if len(args) > 0 && args[0] == "release-keyfile-unlock" {
		return runReleaseKeyfileUnlock(args[1:])
	}
	if len(args) > 0 && args[0] == "release-sign" {
		return runReleaseSign(args[1:])
	}
	if len(args) > 0 && args[0] == "release-host-contract" {
		return runReleaseHostContract(args[1:])
	}
	if len(args) > 0 && args[0] == "release-verify" {
		return runReleaseVerify(args[1:])
	}
	if len(args) > 0 && args[0] == "vps-release-sign" {
		return runVPSReleaseSign(args[1:])
	}
	if len(args) > 0 && args[0] == "vps-release-verify" {
		return runVPSReleaseVerify(args[1:])
	}
	if len(args) > 0 && args[0] == "channel-sign" {
		return runChannelSign(args[1:])
	}
	if len(args) > 0 && args[0] == "channel-verify" {
		return runChannelVerify(args[1:])
	}
	if len(args) > 0 && args[0] == "channel-install-command" {
		return runChannelInstallCommand(args[1:])
	}
	if len(args) > 0 && args[0] == "channel-vps-install-command" {
		return runChannelVPSInstallCommand(args[1:])
	}
	if len(args) > 0 && args[0] == "channel-deploy-command" {
		return runChannelDeployCommand(args[1:])
	}
	if len(args) > 0 && args[0] == "gateway-install-preflight" {
		return runGatewayInstallPreflight(args[1:])
	}
	if len(args) > 0 && args[0] == "deploy-wireguard-prepare" {
		return runDeployWireGuardPrepare(args[1:])
	}
	if len(args) > 0 && args[0] == "deploy-wireguard-inspect" {
		return runDeployWireGuardInspect(args[1:])
	}
	if len(args) > 0 && args[0] == "deploy-wireguard-finalize" {
		return runDeployWireGuardFinalize(args[1:])
	}
	flags := flag.NewFlagSet("gateway-vpnctl", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	showVersion := flags.Bool("version", false, "print build version")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *showVersion {
		fmt.Println(buildinfo.String("gateway-vpnctl"))
		return 0
	}

	fmt.Fprintln(os.Stderr, "usage: gateway-vpnctl [--version|status|release-keygen|release-key-verify|release-key-backup|release-keyfile-create|release-keyfile-verify|release-keyfile-backup|release-keyfile-unlock|release-host-contract|release-sign|release-verify|vps-release-sign|vps-release-verify|channel-sign|channel-verify|channel-install-command|channel-vps-install-command|channel-deploy-command|gateway-install-preflight|deploy-wireguard-inspect|deploy-wireguard-prepare|deploy-wireguard-finalize]")
	return 2
}

func runStatus(args []string) int {
	flags := flag.NewFlagSet("gateway-vpnctl status", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	databasePath := flags.String("database", "/var/lib/gateway-vpn/state.db", "existing Gateway VPN SQLite path")
	jsonOutput := flags.Bool("json", false, "emit JSON")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		return 2
	}
	ctx := context.Background()
	database, err := db.OpenReadOnly(ctx, *databasePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "open Gateway VPN state: %v\n", err)
		return 1
	}
	defer database.Close()
	snapshot, err := state.NewRepository(database).Get(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read Gateway VPN state: %v\n", err)
		return 1
	}
	paths, err := pathmatrix.NewRepository(database).List(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read Gateway VPN path matrix: %v\n", err)
		return 1
	}
	if *jsonOutput {
		if err := json.NewEncoder(os.Stdout).Encode(map[string]any{"runtime": snapshot, "paths": paths}); err != nil {
			fmt.Fprintf(os.Stderr, "encode Gateway VPN status: %v\n", err)
			return 1
		}
		return 0
	}
	fmt.Printf("Gateway: %s\nPath: %s\n", snapshot.GatewayState, snapshot.PathState)
	if snapshot.ActivePathID != "" {
		fmt.Printf("Active: modem=%s subscription=%s node=%s path=%s\n", snapshot.ActiveModemID, snapshot.ActiveSubscriptionID, snapshot.ActiveNodeID, snapshot.ActivePathID)
	} else {
		fmt.Println("Active: none")
	}
	fmt.Printf("Matrix cells: %d\n", len(paths))
	return 0
}
