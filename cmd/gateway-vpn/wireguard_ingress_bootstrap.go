package main

import (
	"context"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"

	"gateway-vpn/internal/config"
	databasepkg "gateway-vpn/internal/db"
	"gateway-vpn/internal/platformexec"
	"gateway-vpn/internal/uplink"
	"gateway-vpn/internal/wgingress"
)

// runWireGuardIngressBootstrap applies only the first-install, standard
// ROUTED listener. Advanced ONE_ARM and interface-role assignments remain a
// WebUI safe-apply operation after the complete hardware inventory is visible.
func runWireGuardIngressBootstrap(args []string) int {
	flags := flag.NewFlagSet("gateway-vpn wireguard-ingress-bootstrap", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	configPath := flags.String("config", "/etc/gateway-vpn/config.yaml", "strict bootstrap YAML path")
	endpointHost := flags.String("endpoint-host", "", "public IPv4 or DNS hostname without port")
	subnet := flags.String("subnet", wgingress.DefaultSubnet, "private canonical WireGuard ingress subnet")
	listenPort := flags.Int("listen-port", wgingress.DefaultListenPort, "WireGuard ingress UDP port")
	dnsText := flags.String("dns", "", "comma-separated external client IPv4 DNS addresses")
	apply := flags.Bool("apply", false, "persist and converge the initial WireGuard ingress server")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		return 2
	}
	dns := splitIngressDNS(*dnsText)
	if err := wgingress.ValidateInitialServerOptions(*endpointHost, *subnet, *listenPort, dns); err != nil {
		fmt.Fprintf(os.Stderr, "validate initial WireGuard ingress options: %v\n", err)
		return 2
	}
	if !*apply {
		fmt.Println("initial WireGuard ingress options are valid; no changes were made")
		return 0
	}
	if err := requireNetworkPrivilege(true); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	configuration, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load Gateway VPN configuration: %v\n", err)
		return 1
	}
	lanPrefix, err := netip.ParsePrefix(configuration.Network.LANAddress)
	if err != nil {
		fmt.Fprintf(os.Stderr, "parse managed LAN prefix: %v\n", err)
		return 1
	}
	ingressPrefix, _ := netip.ParsePrefix(*subnet)
	if ingressPrefix.Overlaps(lanPrefix.Masked()) {
		fmt.Fprintln(os.Stderr, "WireGuard ingress subnet overlaps the managed LAN")
		return 1
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	database, err := databasepkg.Open(ctx, databasepkg.OpenOptions{Path: configuration.System.Database})
	if err != nil {
		fmt.Fprintf(os.Stderr, "open installed Gateway database: %v\n", err)
		return 1
	}
	defer database.Close()
	current, err := databasepkg.ReadSchemaVersion(ctx, database)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read installed Gateway schema: %v\n", err)
		return 1
	}
	latest, err := databasepkg.LatestSchemaVersion()
	if err != nil || current != latest {
		fmt.Fprintf(os.Stderr, "installed Gateway schema is not ready for WireGuard ingress: current=%d latest=%d\n", current, latest)
		return 1
	}
	uplinks := uplink.NewRepository(database, configuration.Modems.RoutingTableStart, configuration.Modems.FwmarkStart)
	if _, err := uplinks.EnsureManagedLANInterface(ctx, configuration.Network.LANInterface, configuration.Network.LANAddress); err != nil {
		fmt.Fprintf(os.Stderr, "publish managed LAN listener: %v\n", err)
		return 1
	}
	secretRoot := configuration.System.StateDir + "/secrets/wireguard-ingress"
	backend := &wgingress.Backend{
		Repository: wgingress.Repository{Database: database, SecretRoot: secretRoot, ReservedPrefixes: []netip.Prefix{lanPrefix.Masked()}},
		Keys:       wgingress.KeyStore{Root: secretRoot}, Executor: platformexec.OSExecutor{},
		IP: "/usr/sbin/ip", WG: "/usr/bin/wg", NFT: "/usr/sbin/nft", Mutate: true,
	}
	server, err := backend.UpdateServer(ctx, wgingress.ServerUpdate{
		Enabled: true, Name: "WireGuard для клиентов", SubnetCIDR: ingressPrefix.String(),
		ListenPort: *listenPort, EndpointHost: strings.TrimSpace(*endpointHost), MTU: wgingress.DefaultMTU,
		TopologyMode: "ROUTED", DNS: dns,
		ListenInterfaces: []wgingress.ListenInterface{{NetworkInterfaceID: uplink.ManagedLANInterfaceID, ExposureMode: "LOCAL", Priority: 1}},
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "apply initial WireGuard ingress server: %v\n", err)
		return 1
	}
	if server.State != "ACTIVE" || server.AppliedGeneration != server.DesiredGeneration {
		fmt.Fprintf(os.Stderr, "initial WireGuard ingress convergence is incomplete: state=%s applied=%d desired=%d\n", server.State, server.AppliedGeneration, server.DesiredGeneration)
		return 1
	}
	fmt.Printf("WireGuard ingress ready: interface=%s address=%s endpoint=%s:%s\n", server.InterfaceName, server.ServerAddress, server.EndpointHost, strconv.Itoa(server.ListenPort))
	return 0
}

func splitIngressDNS(value string) []string {
	parts := strings.Split(value, ",")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		if item := strings.TrimSpace(part); item != "" {
			result = append(result, item)
		}
	}
	return result
}
