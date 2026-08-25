package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"runtime"

	wireguardpkg "gateway-vpn/internal/wireguard"
)

const (
	deployWireGuardConfigPath  = "/var/lib/gateway-vpn/secrets/wireguard.yaml"
	deployWireGuardPendingPath = "/var/lib/gateway-vpn/secrets/.deploy-wireguard.key"
)

func runDeployWireGuardPrepare(args []string) int {
	flags := flag.NewFlagSet("gateway-vpnctl deploy-wireguard-prepare", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	jsonOutput := flags.Bool("json", false, "emit bounded machine-readable public-key state")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		return 2
	}
	if runtime.GOOS == "linux" && os.Geteuid() == 0 {
		fmt.Fprintln(os.Stderr, "deploy WireGuard key preparation must run as the installed gateway-vpn service user, not root")
		return 1
	}
	result, err := wireguardpkg.PrepareDeployKey(deployWireGuardConfigPath, deployWireGuardPendingPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "prepare local Gateway WireGuard key: %v\n", err)
		return 1
	}
	return printDeployWireGuardState(result, *jsonOutput)
}

func runDeployWireGuardInspect(args []string) int {
	flags := flag.NewFlagSet("gateway-vpnctl deploy-wireguard-inspect", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	jsonOutput := flags.Bool("json", false, "emit bounded machine-readable public-key state")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		return 2
	}
	result, err := wireguardpkg.InspectDeployKey(deployWireGuardConfigPath, deployWireGuardPendingPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "inspect local Gateway WireGuard key: %v\n", err)
		return 1
	}
	return printDeployWireGuardState(result, *jsonOutput)
}

func runDeployWireGuardFinalize(args []string) int {
	flags := flag.NewFlagSet("gateway-vpnctl deploy-wireguard-finalize", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	peerPublicKey := flags.String("peer-public-key", "", "VPS WireGuard public key")
	endpoint := flags.String("endpoint", "", "public VPS HOST:51821 endpoint")
	keepalive := flags.Int("persistent-keepalive", 25, "persistent keepalive in seconds")
	handshake := flags.Int("handshake-timeout", 45, "handshake timeout in seconds")
	jsonOutput := flags.Bool("json", false, "emit bounded machine-readable public-key state")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 || *peerPublicKey == "" || *endpoint == "" {
		return 2
	}
	if runtime.GOOS == "linux" && os.Geteuid() == 0 {
		fmt.Fprintln(os.Stderr, "deploy WireGuard key finalization must run as the installed gateway-vpn service user, not root")
		return 1
	}
	result, err := wireguardpkg.FinalizeDeployKey(wireguardpkg.DeployFinalizeOptions{
		ConfigPath: deployWireGuardConfigPath, PendingKeyPath: deployWireGuardPendingPath,
		PeerPublicKey: *peerPublicKey, Endpoint: *endpoint,
		KeepaliveSeconds: *keepalive, HandshakeSeconds: *handshake,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "finalize local Gateway WireGuard config: %v\n", err)
		return 1
	}
	return printDeployWireGuardState(result, *jsonOutput)
}

func printDeployWireGuardState(result wireguardpkg.DeployKeyState, jsonOutput bool) int {
	if jsonOutput {
		if err := json.NewEncoder(os.Stdout).Encode(result); err != nil {
			return 1
		}
		return 0
	}
	fmt.Printf("Gateway WireGuard key state=%s public_key=%s\n", result.State, result.PublicKey)
	return 0
}
