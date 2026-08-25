package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"gateway-vpn/internal/installpreflight"
	"gateway-vpn/internal/platformexec"
)

func runGatewayInstallPreflight(args []string) int {
	flags := flag.NewFlagSet("gateway-vpnctl gateway-install-preflight", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	lanInterface := flags.String("lan-interface", "", "explicit Gateway transit LAN interface")
	lanAddress := flags.String("lan-address", "", "explicit private Gateway transit LAN host CIDR")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		return 2
	}
	err := installpreflight.CheckGatewayLAN(context.Background(), platformexec.OSExecutor{}, installpreflight.LANOptions{
		Interface: *lanInterface, CIDR: *lanAddress, IPPath: "/usr/sbin/ip",
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Gateway LAN host preflight failed: %v\n", err)
		return 1
	}
	fmt.Println("Gateway LAN host preflight: PASS")
	return 0
}
