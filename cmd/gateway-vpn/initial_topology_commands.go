package main

import (
	"context"
	"database/sql"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"gateway-vpn/internal/config"
	"gateway-vpn/internal/db"
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

type currentTopologyState struct {
	Profile           string
	DesiredGeneration int64
	AppliedGeneration int64
	State             string
	LANInterface      string
	LANAddress        string
	DHCPDNS           bool
}

// runTopologyState is a read-only bridge between the durable runtime topology
// and the signed shell lifecycle. It prevents a reinstall or host-contract
// upgrade from mistaking the immutable first-install handoff for the topology
// that may have since been changed through WebUI safe apply.
func runTopologyState(args []string) int {
	flags := flag.NewFlagSet("gateway-vpn topology-state", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	configPath := flags.String("config", "/etc/gateway-vpn/config.yaml", "strict Gateway configuration")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		return 2
	}
	configuration, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load Gateway VPN configuration: %v\n", err)
		return 1
	}
	database, err := db.OpenReadOnly(context.Background(), configuration.System.Database)
	if err != nil {
		fmt.Fprintf(os.Stderr, "open Gateway VPN topology state: %v\n", err)
		return 1
	}
	defer database.Close()
	state, err := readConvergedTopologyState(context.Background(), database, configuration)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read Gateway VPN topology state: %v\n", err)
		return 1
	}
	fmt.Printf("topology state: profile=%s desired_generation=%d applied_generation=%d state=%s lan_interface=%s lan_address=%s dhcp_dns=%t\n",
		state.Profile, state.DesiredGeneration, state.AppliedGeneration, state.State, state.LANInterface, state.LANAddress, state.DHCPDNS)
	return 0
}

func readConvergedTopologyState(ctx context.Context, database *sql.DB, configuration config.Config) (currentTopologyState, error) {
	if database == nil {
		return currentTopologyState{}, errors.New("topology database is unavailable")
	}
	state := currentTopologyState{LANInterface: configuration.Network.LANInterface, LANAddress: configuration.Network.LANAddress, DHCPDNS: configuration.Network.LANServiceMode == "dhcp_dns"}
	if err := database.QueryRowContext(ctx, `
SELECT active_profile,desired_generation,applied_generation,state
FROM topology_profile_state WHERE singleton_id=1`).Scan(&state.Profile, &state.DesiredGeneration, &state.AppliedGeneration, &state.State); err != nil {
		return currentTopologyState{}, err
	}
	if !validTopologyStateProfile(state.Profile) || state.DesiredGeneration < 1 || state.AppliedGeneration < 1 || state.DesiredGeneration != state.AppliedGeneration || state.State != "ACTIVE" {
		return currentTopologyState{}, errors.New("topology is not a converged active profile")
	}
	return state, nil
}

func validTopologyStateProfile(value string) bool {
	switch installtopology.Profile(value) {
	case installtopology.ProfileEthernetHiLink, installtopology.ProfileEthernetEthernet, installtopology.ProfileOneArmWireGuard, installtopology.ProfileMixed:
		return true
	default:
		return false
	}
}
