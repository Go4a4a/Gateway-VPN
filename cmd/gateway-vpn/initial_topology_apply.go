package main

// The first-install topology handoff is deliberately a separate command. The
// shell installer establishes a minimal, reachable management baseline first;
// this command then provisions any signed Ethernet uplinks and changes the
// profile through the normal durable snapshot/apply/confirm transaction. If
// the process, service, or network path fails, the existing network recovery
// timer restores the baseline and the shell install marker removes the new
// state.

import (
	"bufio"
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"gateway-vpn/internal/config"
	"gateway-vpn/internal/installtopology"
	"gateway-vpn/internal/networkapply"
	"gateway-vpn/internal/uplink"
	"gateway-vpn/internal/wgingress"
)

func runInitialTopologyApply(args []string) int {
	flags := flag.NewFlagSet("gateway-vpn initial-topology-apply", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	configPath := flags.String("config", "/etc/gateway-vpn/config.yaml", "strict Gateway configuration")
	token := flags.String("token", "", "bounded non-secret initial topology token")
	lanInterface := flags.String("lan-interface", "", "temporary installer LAN interface")
	lanMembers := flags.String("lan-members", "", "comma-separated temporary physical LAN members")
	lanAddress := flags.String("lan-address", "", "temporary installer LAN IPv4 CIDR")
	enableIngress := flags.Bool("enable-wireguard-ingress", false, "use the initialized WireGuard ingress listener")
	confirmationMode := flags.String("confirmation-mode", "automatic", "automatic, external-wireguard, or local-console")
	apply := flags.Bool("apply", false, "perform the rollback-protected profile transaction")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 || *token == "" {
		return 2
	}
	plan, err := installtopology.DecodeToken(*token)
	if err != nil {
		fmt.Fprintf(os.Stderr, "decode initial topology: %v\n", err)
		return 1
	}
	members := splitTopologyCommaValues(*lanMembers)
	if err := installtopology.ValidateInstallerBinding(plan, *lanInterface, members); err != nil {
		fmt.Fprintf(os.Stderr, "initial topology does not match installer LAN binding: %v\n", err)
		return 1
	}
	if plan.Profile == installtopology.ProfileEthernetHiLink {
		fmt.Println("initial HiLink topology already matches the installer baseline; no profile transaction was needed")
		return 0
	}
	if *confirmationMode != "automatic" && *confirmationMode != "external-wireguard" && *confirmationMode != "local-console" {
		fmt.Fprintln(os.Stderr, "initial topology confirmation mode must be automatic, external-wireguard, or local-console")
		return 2
	}
	if !*apply {
		fmt.Println("initial non-default topology is valid; re-run with --apply to use the rollback-protected transaction")
		return 0
	}
	if err := requireNetworkPrivilege(true); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	configuration, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load Gateway VPN configuration: %v\n", err)
		return 1
	}
	if strings.TrimSpace(*lanAddress) == "" {
		*lanAddress = configuration.Network.LANAddress
	}
	if _, err := netip.ParsePrefix(*lanAddress); err != nil {
		fmt.Fprintf(os.Stderr, "temporary installer LAN address is invalid: %v\n", err)
		return 1
	}
	engine, database, err := productionNetworkEngine(ctx, *configPath, defaultNetworkTransactionRoot)
	if err != nil {
		fmt.Fprintf(os.Stderr, "initialize topology safe-apply engine: %v\n", err)
		return 1
	}
	defer database.Close()
	repository := uplink.NewRepository(database, configuration.Modems.RoutingTableStart, configuration.Modems.FwmarkStart)
	interfaces, err := repository.ListInterfaces(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read observed Ethernet inventory: %v\n", err)
		return 1
	}
	byName := make(map[string]string)
	for _, item := range interfaces {
		if item.ID == uplink.ManagedLANInterfaceID || item.CurrentIfname == "" {
			continue
		}
		if previous, exists := byName[item.CurrentIfname]; exists && previous != item.ID {
			fmt.Fprintf(os.Stderr, "interface inventory has duplicate stable identity for %s\n", item.CurrentIfname)
			return 1
		}
		byName[item.CurrentIfname] = item.ID
	}
	resolve := func(ifname string) (string, error) {
		id := byName[strings.TrimSpace(ifname)]
		if id == "" {
			return "", fmt.Errorf("selected interface %s is not present in the protected inventory; wait for Ethernet reconciliation and retry", ifname)
		}
		return id, nil
	}
	lanIDs := make([]string, 0, len(plan.LANMembers))
	for _, ifname := range plan.LANMembers {
		id, resolveErr := resolve(ifname)
		if resolveErr != nil {
			fmt.Fprintln(os.Stderr, resolveErr)
			return 1
		}
		lanIDs = append(lanIDs, id)
	}
	sharedID := ""
	if plan.SharedOneArmInterface != "" {
		sharedID, err = resolve(plan.SharedOneArmInterface)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
	}
	if plan.Profile == installtopology.ProfileOneArmWireGuard && !*enableIngress {
		fmt.Fprintln(os.Stderr, "ONE_ARM_WIREGUARD requires the initialized WireGuard ingress listener")
		return 1
	}
	if plan.Profile == installtopology.ProfileMixed && sharedID != "" && !*enableIngress {
		fmt.Fprintln(os.Stderr, "MIXED with a shared one-arm interface requires the initialized WireGuard ingress listener")
		return 1
	}
	// Resolve all Ethernet intent to stable interface IDs before staging. The
	// actual uplink records and networkd files are created only by the backend
	// after the transaction snapshot has been durably written and the path is
	// blocked. This keeps first-install apply crash-safe and rollback-owned.
	ethernetInterfaceIDs := make(map[string]string, len(plan.EthernetUplinks))
	for _, item := range plan.EthernetUplinks {
		interfaceID, resolveErr := resolve(item.InterfaceName)
		if resolveErr != nil {
			fmt.Fprintln(os.Stderr, resolveErr)
			return 1
		}
		ethernetInterfaceIDs[item.InterfaceName] = interfaceID
	}
	mutation, oldURL, newURL, destination, err := buildInitialTopologyMutation(ctx, database, configuration, plan, lanIDs, sharedID, ethernetInterfaceIDs, *lanAddress, *enableIngress)
	if err != nil {
		fmt.Fprintf(os.Stderr, "build initial topology candidate: %v\n", err)
		return 1
	}
	// A first-install command may confirm automatically only while retaining
	// the exact management origin used by the installer. ONE_ARM/shared-only
	// profiles move management to wg-ingress and must later be confirmed by a
	// real request through that new path (or by an explicitly proven local
	// console workflow); treating this local root process as that request would
	// defeat rollback protection.
	autoConfirm := initialTopologyAutoConfirmAllowed(oldURL, newURL)
	if !autoConfirm && *confirmationMode != "external-wireguard" && *confirmationMode != "local-console" {
		fmt.Fprintf(os.Stderr, "initial topology moves management from %s to %s and requires external new-path confirmation; no network changes were staged\n", oldURL, newURL)
		return 1
	}
	if autoConfirm && *confirmationMode != "automatic" {
		fmt.Fprintln(os.Stderr, "local-console confirmation is unnecessary while the exact management origin is retained")
		return 2
	}
	if *confirmationMode == "local-console" {
		if _, err := requireIndependentLocalConsole(os.Stdin); err != nil {
			fmt.Fprintf(os.Stderr, "local-console confirmation is unavailable: %v; no network changes were staged\n", err)
			return 1
		}
	}
	prepared, err := engine.Stage(ctx, networkapply.Candidate{
		Topology:                      &mutation,
		OldURL:                        oldURL,
		NewURL:                        newURL,
		ManagementDestinationIP:       destination,
		RequireWireGuardConfirmation:  !autoConfirm,
		AllowLocalConsoleConfirmation: *confirmationMode == "local-console",
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "stage initial topology safe apply: %v\n", err)
		return 1
	}
	if *confirmationMode == "external-wireguard" {
		fmt.Println("The topology transaction is staged but has not changed the network yet.")
		fmt.Printf("After apply, open this one-time URL through the configured WireGuard path before %s:\n%s/#network-confirm=%s.%s\n",
			prepared.RollbackDeadline.UTC().Format(time.RFC3339), prepared.NewURL, prepared.ApplyID, prepared.ConfirmToken)
		fmt.Println("The fragment is not sent in an HTTP request; the WebUI uses it once to confirm the new path.")
		_ = os.Stdout.Sync()
	}
	if err := engine.Apply(ctx, prepared.ApplyID); err != nil {
		fmt.Fprintf(os.Stderr, "apply initial topology safe apply: %v\n", err)
		return 1
	}
	evidence := networkapply.ConfirmEvidence{Token: prepared.ConfirmToken, LocalDestinationIP: destination}
	if *confirmationMode == "external-wireguard" {
		if err := waitForExternalTopologyConfirmation(ctx, networkapply.NewRepository(database), prepared.ApplyID, prepared.RollbackDeadline); err != nil {
			fmt.Fprintf(os.Stderr, "external WireGuard confirmation did not complete: %v\n", err)
			return 1
		}
		fmt.Printf("initial topology profile applied and externally confirmed: profile=%s destination=%s ethernet_uplinks=%d\n", plan.Profile, destination, len(plan.EthernetUplinks))
		return 0
	}
	if *confirmationMode == "local-console" {
		phrase := initialTopologyConsolePhrase(prepared.ApplyID)
		fmt.Printf("Topology is temporarily active and will roll back at %s unless confirmed.\n", prepared.RollbackDeadline.UTC().Format(time.RFC3339))
		fmt.Printf("From this same independent console, type exactly %q: ", phrase)
		line, readErr := readBoundedConsoleLine(os.Stdin)
		if readErr != nil || line != phrase {
			fmt.Fprintln(os.Stderr, "\nlocal-console confirmation did not match; automatic rollback remains armed")
			return 1
		}
		evidence.LocalDestinationIP = ""
		evidence.ViaLocalConsole = true
	}
	if err := engine.Confirm(ctx, prepared.ApplyID, evidence); err != nil {
		fmt.Fprintf(os.Stderr, "confirm initial topology safe apply: %v\n", err)
		return 1
	}
	fmt.Printf("initial topology profile applied and confirmed: profile=%s destination=%s ethernet_uplinks=%d\n", plan.Profile, destination, len(plan.EthernetUplinks))
	return 0
}

func initialTopologyAutoConfirmAllowed(oldURL, newURL string) bool {
	return oldURL != "" && oldURL == newURL
}

var independentConsolePattern = regexp.MustCompile(`^/dev/(tty([1-9]|[1-5][0-9]|6[0-3])|ttyS[0-9]+|ttyAMA[0-9]+|hvc[0-9]+)$`)

// requireIndependentLocalConsole distinguishes a physical Linux VT or an
// out-of-band serial console from SSH, terminal multiplexers and pipes. It is
// evaluated before Stage so a remote caller cannot weaken first-install
// rollback protection by merely passing --confirmation-mode local-console.
func requireIndependentLocalConsole(input *os.File) (string, error) {
	if runtime.GOOS != "linux" || input == nil {
		return "", errors.New("an independent Linux console is required")
	}
	target, err := os.Readlink(filepath.Join("/proc/self/fd", strconv.FormatUint(uint64(input.Fd()), 10)))
	if err != nil || !isIndependentConsolePath(target) {
		return "", errors.New("stdin is not /dev/console, a Linux virtual terminal, or a serial console")
	}
	return target, nil
}

func isIndependentConsolePath(value string) bool {
	return value == "/dev/console" || independentConsolePattern.MatchString(value)
}

func initialTopologyConsolePhrase(applyID string) string {
	return "CONFIRM " + applyID
}

func readBoundedConsoleLine(input io.Reader) (string, error) {
	reader := bufio.NewReader(io.LimitReader(input, 258))
	line, err := reader.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	if len(line) > 257 || !strings.HasSuffix(line, "\n") {
		return "", errors.New("console confirmation must be one bounded line")
	}
	return strings.TrimSuffix(strings.TrimSuffix(line, "\n"), "\r"), nil
}

func waitForExternalTopologyConfirmation(ctx context.Context, repository *networkapply.Repository, applyID string, deadline time.Time) error {
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for {
		transaction, err := repository.Get(ctx, applyID)
		if err != nil {
			return err
		}
		switch transaction.State {
		case networkapply.StateConfirmed:
			return nil
		case networkapply.StateRolledBack:
			return errors.New("the unconfirmed topology was rolled back")
		case networkapply.StateFailed:
			return errors.New("the topology transaction failed")
		}
		if !time.Now().UTC().Before(deadline) {
			return networkapply.ErrApplyExpired
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func buildInitialTopologyMutation(ctx context.Context, database *sql.DB, configuration config.Config, plan installtopology.Plan, lanIDs []string, sharedID string, ethernetInterfaceIDs map[string]string, installerLANAddress string, enableIngress bool) (networkapply.TopologyMutation, string, string, string, error) {
	var profile string
	var desired, applied int64
	var state string
	if err := database.QueryRowContext(ctx, `SELECT active_profile,desired_generation,applied_generation,state FROM topology_profile_state WHERE singleton_id=1`).Scan(&profile, &desired, &applied, &state); err != nil {
		return networkapply.TopologyMutation{}, "", "", "", err
	}
	if desired != applied || state != "ACTIVE" {
		return networkapply.TopologyMutation{}, "", "", "", errors.New("initial topology generation is not converged")
	}
	oldPrefix, err := netip.ParsePrefix(configuration.Network.LANAddress)
	if err != nil {
		return networkapply.TopologyMutation{}, "", "", "", errors.New("configured LAN address is invalid")
	}
	oldPort := "8443"
	for _, listen := range configuration.API.Listen {
		if _, port, splitErr := net.SplitHostPort(listen); splitErr == nil && port != "" {
			oldPort = port
			break
		}
	}
	oldURL := "https://" + netip.AddrPortFrom(oldPrefix.Addr(), mustPort(oldPort)).String()
	mutation := networkapply.TopologyMutation{ExpectedDesiredGeneration: desired, Profile: string(plan.Profile), LANInterfaceIDs: append([]string(nil), lanIDs...), IngressTopologyMode: "ROUTED", AcknowledgedPrerequisites: []string{"ACCEPT_TEMPORARY_DISCONNECT", "MOVE_LAN_CABLES", "CONFIGURE_KEENETIC_WAN_DHCP"}}
	for _, item := range plan.EthernetUplinks {
		interfaceID := ethernetInterfaceIDs[item.InterfaceName]
		if interfaceID == "" {
			return networkapply.TopologyMutation{}, "", "", "", fmt.Errorf("initial Ethernet interface %s was not resolved", item.InterfaceName)
		}
		digest := sha256.Sum256([]byte("gateway-vpn:initial-ethernet:" + interfaceID))
		mutation.EthernetUplinks = append(mutation.EthernetUplinks, networkapply.TopologyEthernetUplink{
			ID: "initial-ethernet-" + fmt.Sprintf("%x", digest[:8]), Name: "Ethernet " + item.InterfaceName,
			NetworkInterfaceID: interfaceID, AddressMode: item.AddressMode, IPv4CIDR: item.IPv4CIDR,
			Gateway: item.Gateway, DNS: append([]string(nil), item.DNS...), MTU: item.MTU,
		})
	}
	mutation.ManagementInterfaceIDs = append([]string(nil), lanIDs...)
	mutation.SharedOneArmInterfaceID = sharedID
	if sharedID != "" {
		mutation.ManagementInterfaceIDs = append(mutation.ManagementInterfaceIDs, sharedID)
	}
	for _, id := range mutation.ManagementInterfaceIDs {
		if id == "" {
			return networkapply.TopologyMutation{}, "", "", "", errors.New("initial topology contains an empty management interface")
		}
	}
	if plan.Profile == installtopology.ProfileOneArmWireGuard || plan.Profile == installtopology.ProfileMixed && sharedID != "" && len(lanIDs) == 0 {
		if !enableIngress {
			return networkapply.TopologyMutation{}, "", "", "", errors.New("one-arm initial profile requires WireGuard ingress")
		}
		server, serverErr := (wgingress.Repository{Database: database}).GetServer(ctx)
		if serverErr != nil || !server.Enabled || server.ServerAddress == "" {
			return networkapply.TopologyMutation{}, "", "", "", errors.New("initialized WireGuard ingress server is unavailable")
		}
		mutation.LANInterfaceName = "wg-ingress"
		mutation.LANAddress = server.ServerAddress
		mutation.DHCPDNSEnabled = false
		mutation.IngressEnabled = true
		mutation.IngressTopologyMode = "ONE_ARM"
		mutation.IngressListenInterfaces = []networkapply.TopologyListenInterface{{NetworkInterfaceID: sharedID, ExposureMode: "PUBLIC", Priority: 1}}
		mutation.AcknowledgedPrerequisites = append(mutation.AcknowledgedPrerequisites, "CONFIGURE_KEENETIC_WIREGUARD", "VERIFY_UPSTREAM_RETURN_PATH")
	} else {
		mutation.LANInterfaceName = "gateway-vpn-lan"
		mutation.LANAddress = installerLANAddress
		mutation.DHCPDNSEnabled = true
		if enableIngress {
			mutation.IngressEnabled = true
			mutation.IngressListenInterfaces = []networkapply.TopologyListenInterface{{NetworkInterfaceID: uplink.ManagedLANInterfaceID, ExposureMode: "LOCAL", Priority: 1}}
		}
	}
	if mutation.IngressEnabled && mutation.IngressTopologyMode == "ROUTED" {
		mutation.IngressListenInterfaces = []networkapply.TopologyListenInterface{{NetworkInterfaceID: uplink.ManagedLANInterfaceID, ExposureMode: "LOCAL", Priority: 1}}
	}
	destinationPrefix, err := netip.ParsePrefix(mutation.LANAddress)
	if err != nil {
		return networkapply.TopologyMutation{}, "", "", "", errors.New("initial topology management address is invalid")
	}
	destination := destinationPrefix.Addr().String()
	newURL := "https://" + netip.AddrPortFrom(destinationPrefix.Addr(), mustPort(oldPort)).String()
	if profile == mutation.Profile && desired == 1 {
		return networkapply.TopologyMutation{}, "", "", "", errors.New("initial topology is already active; refusing a duplicate apply")
	}
	return mutation, oldURL, newURL, destination, nil
}

func mustPort(value string) uint16 {
	parsed, err := strconv.ParseUint(value, 10, 16)
	if err != nil || parsed == 0 {
		return 8443
	}
	return uint16(parsed)
}
