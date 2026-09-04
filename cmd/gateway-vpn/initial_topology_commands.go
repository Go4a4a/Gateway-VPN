package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"gateway-vpn/internal/installtopology"
)

// runInitialTopologyCheck is intentionally read-only. The independently
// verified release uses it to reject malformed or role-conflicting installer
// handoff before any host mutation. Rich profiles are accepted only when the
// caller explicitly opts into the post-install safe-apply stage.
func runInitialTopologyCheck(args []string) int {
	flags := flag.NewFlagSet("gateway-vpn initial-topology-check", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	token := flags.String("token", "", "bounded non-secret initial topology token")
	lanInterface := flags.String("lan-interface", "", "installer LAN interface to bind to the topology")
	lanMembers := flags.String("lan-members", "", "optional comma-separated physical LAN bridge members")
	allowNonDefault := flags.Bool("allow-nondefault", false, "allow a profile applied by the post-install rollback transaction")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 || *token == "" {
		return 2
	}
	plan, err := installtopology.DecodeToken(*token)
	if err != nil {
		fmt.Fprintf(os.Stderr, "initial topology is invalid: %v\n", err)
		return 1
	}
	members := splitTopologyCommaValues(*lanMembers)
	if *lanInterface != "" {
		if err := installtopology.ValidateInstallerBinding(plan, *lanInterface, members); err != nil {
			fmt.Fprintf(os.Stderr, "initial topology does not match the supported installer action: %v\n", err)
			return 1
		}
		if !*allowNonDefault && plan.Profile != installtopology.ProfileEthernetHiLink {
			fmt.Fprintln(os.Stderr, "non-default initial topology requires the post-install safe-apply stage")
			return 1
		}
	} else if *lanMembers != "" {
		fmt.Fprintln(os.Stderr, "--lan-members requires --lan-interface")
		return 2
	}
	fmt.Printf("initial topology is valid: profile=%s lan_ports=%d ethernet_uplinks=%d one_arm=%t\n", plan.Profile, len(plan.LANMembers), len(plan.EthernetUplinks), plan.UsesOneArmIngress())
	return 0
}

func splitTopologyCommaValues(value string) []string {
	if value == "" {
		return nil
	}
	return strings.Split(value, ",")
}
