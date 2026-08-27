// Package installwizard implements the read-only, target-side Gateway setup
// dialogue used by the independently verified bootstrap binary.
package installwizard

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"sort"
	"strconv"
	"strings"

	"gateway-vpn/internal/installpreflight"
	"gateway-vpn/internal/netutil"
	"gateway-vpn/internal/platformexec"
)

const inventoryLimit = 4 << 20

const LANInterface = "gateway-vpn-lan"

var ErrCancelled = errors.New("interactive Gateway installation cancelled")

type Selection struct {
	LANInterface        string
	LANMembers          []string
	LANAddress          string
	EnableDHCP          bool
	InstallDependencies bool
}

type Session struct {
	executor       platformexec.Executor
	scanner        *bufio.Scanner
	output         io.Writer
	ipPath         string
	udevPath       string
	managementPeer string
}

type linkObservation struct {
	Index     int      `json:"ifindex"`
	Name      string   `json:"ifname"`
	Flags     []string `json:"flags"`
	OperState string   `json:"operstate"`
	LinkType  string   `json:"link_type"`
}

type addressObservation struct {
	Name      string `json:"ifname"`
	Addresses []struct {
		Family    string `json:"family"`
		Local     string `json:"local"`
		PrefixLen int    `json:"prefixlen"`
	} `json:"addr_info"`
}

type routeObservation struct {
	Destination string `json:"dst"`
	Device      string `json:"dev"`
	Gateway     string `json:"gateway"`
}

type interfaceChoice struct {
	index           int
	name            string
	linkType        string
	operState       string
	carrier         bool
	loopback        bool
	defaultRoute    bool
	managementRoute bool
	hilinkRisk      bool
	addresses       []string
}

// ProtectManagementPeer additionally blocks the interface used to reach an
// active SSH client when that information survived privilege elevation.
func (session *Session) ProtectManagementPeer(value string) bool {
	address, err := netip.ParseAddr(value)
	if err != nil || !address.Is4() || address.IsUnspecified() || address.IsMulticast() {
		return false
	}
	session.managementPeer = address.String()
	return true
}

func NewSession(executor platformexec.Executor, input io.Reader, output io.Writer) (*Session, error) {
	if executor == nil || input == nil || output == nil {
		return nil, errors.New("interactive installer requires an executor and terminal streams")
	}
	scanner := bufio.NewScanner(input)
	scanner.Buffer(make([]byte, 256), 4096)
	return &Session{executor: executor, scanner: scanner, output: output, ipPath: "/usr/sbin/ip", udevPath: "/usr/bin/udevadm"}, nil
}

// Select performs only observations and validation. It never changes links,
// addresses, routes, packages, files, services, or firewall state.
func (session *Session) Select(ctx context.Context) (Selection, error) {
	choices, err := session.inventory(ctx)
	if err != nil {
		return Selection{}, err
	}
	fmt.Fprintln(session.output, "Gateway VPN interactive installation")
	fmt.Fprintln(session.output, "Read-only network inventory (nothing has been changed):")
	for number, choice := range choices {
		fmt.Fprintf(session.output, "  [%d] %s\n", number+1, describeChoice(choice))
	}
	selected, err := session.chooseInterfaces(choices)
	if err != nil {
		return Selection{}, err
	}
	enableDHCP, err := session.yesNo("Enable Gateway DHCP for the Keenetic WAN connection?", true)
	if err != nil {
		return Selection{}, err
	}
	installDependencies, err := session.yesNo("Allow installation of missing signed-profile Ubuntu packages after safe APT simulation?", true)
	if err != nil {
		return Selection{}, err
	}
	lanAddress, err := session.chooseLAN(ctx, LANInterface, enableDHCP)
	if err != nil {
		return Selection{}, err
	}
	return Selection{
		LANInterface: LANInterface, LANMembers: interfaceNames(selected), LANAddress: lanAddress,
		EnableDHCP: enableDHCP, InstallDependencies: installDependencies,
	}, nil
}

// ConfirmApply is called only after the verified release's read-only preflight
// has completed. Requiring an exact token prevents an accidental Enter from
// authorizing package, network, firewall, or service changes.
func (session *Session) ConfirmApply(version, preflight string, selection Selection) (bool, error) {
	fmt.Fprintln(session.output)
	fmt.Fprintln(session.output, "Verified installation summary:")
	fmt.Fprintf(session.output, "  release:              %s\n", version)
	fmt.Fprintf(session.output, "  Keenetic WAN link:    %s\n", selection.LANInterface)
	fmt.Fprintf(session.output, "  physical LAN ports:   %s\n", strings.Join(selection.LANMembers, ", "))
	fmt.Fprintf(session.output, "  Gateway LAN address:  %s\n", selection.LANAddress)
	fmt.Fprintf(session.output, "  Gateway DHCP:         %s\n", yesNoText(selection.EnableDHCP))
	fmt.Fprintf(session.output, "  missing dependencies: %s\n", allowDenyText(selection.InstallDependencies))
	fmt.Fprintf(session.output, "  read-only preflight:  %s\n", preflight)
	fmt.Fprintln(session.output, "No persistent host changes have been requested yet.")
	fmt.Fprint(session.output, "Type INSTALL to apply, or q to cancel: ")
	answer, err := session.readLine()
	if err != nil {
		return false, err
	}
	switch strings.TrimSpace(answer) {
	case "INSTALL":
		return true, nil
	case "q", "Q", "quit", "cancel", "":
		return false, nil
	default:
		fmt.Fprintln(session.output, "Confirmation did not match INSTALL; installation cancelled.")
		return false, nil
	}
}

func (session *Session) inventory(ctx context.Context) ([]interfaceChoice, error) {
	linksResult, err := session.executor.Run(ctx, platformexec.Request{
		Executable: session.ipPath, Arguments: []string{"-json", "-details", "link", "show"}, MaxOutputBytes: inventoryLimit,
	})
	if err != nil {
		return nil, fmt.Errorf("observe network interfaces with fixed iproute2 command: %w", err)
	}
	addressesResult, err := session.executor.Run(ctx, platformexec.Request{
		Executable: session.ipPath, Arguments: []string{"-json", "-4", "address", "show"}, MaxOutputBytes: inventoryLimit,
	})
	if err != nil {
		return nil, fmt.Errorf("observe interface IPv4 addresses: %w", err)
	}
	routesResult, err := session.executor.Run(ctx, platformexec.Request{
		Executable: session.ipPath, Arguments: []string{"-json", "-4", "route", "show", "table", "all"}, MaxOutputBytes: inventoryLimit,
	})
	if err != nil {
		return nil, fmt.Errorf("observe host IPv4 routes: %w", err)
	}
	var links []linkObservation
	var addresses []addressObservation
	var routes []routeObservation
	if json.Unmarshal([]byte(linksResult.Stdout), &links) != nil || json.Unmarshal([]byte(addressesResult.Stdout), &addresses) != nil || json.Unmarshal([]byte(routesResult.Stdout), &routes) != nil {
		return nil, errors.New("decode bounded iproute2 network inventory")
	}
	byName := make(map[string]*interfaceChoice, len(links))
	choices := make([]interfaceChoice, 0, len(links))
	for _, link := range links {
		if !validInterfaceName(link.Name) || link.Index <= 0 {
			return nil, errors.New("network inventory contains an invalid interface identity")
		}
		choice := interfaceChoice{
			index: link.Index, name: link.Name, linkType: safeLabel(link.LinkType), operState: safeLabel(link.OperState),
			carrier: contains(link.Flags, "LOWER_UP"), loopback: link.Name == "lo" || link.LinkType == "loopback" || contains(link.Flags, "LOOPBACK"),
		}
		choices = append(choices, choice)
		byName[link.Name] = &choices[len(choices)-1]
	}
	// Map pointers must be rebuilt after append growth.
	for index := range choices {
		byName[choices[index].name] = &choices[index]
		if choices[index].linkType == "ether" {
			properties, err := session.executor.Run(ctx, platformexec.Request{
				Executable: session.udevPath, Arguments: []string{"info", "--query=property", "--path", "/sys/class/net/" + choices[index].name}, MaxOutputBytes: 64 << 10,
			})
			if err != nil {
				return nil, fmt.Errorf("observe interface device metadata for %s: %w", choices[index].name, err)
			}
			choices[index].hilinkRisk = huaweiUSBNetwork(properties.Stdout)
		}
	}
	for _, observed := range addresses {
		choice := byName[observed.Name]
		if choice == nil {
			return nil, errors.New("address inventory refers to an unknown interface")
		}
		for _, address := range observed.Addresses {
			if address.Family != "inet" {
				continue
			}
			parsed, err := netip.ParseAddr(address.Local)
			if err != nil || !parsed.Is4() || address.PrefixLen < 0 || address.PrefixLen > 32 {
				return nil, errors.New("network inventory contains an invalid IPv4 address")
			}
			choice.addresses = append(choice.addresses, netip.PrefixFrom(parsed, address.PrefixLen).String())
		}
	}
	for _, route := range routes {
		if route.Destination != "default" && route.Destination != "0.0.0.0/0" {
			continue
		}
		choice := byName[route.Device]
		if choice != nil {
			choice.defaultRoute = true
		}
	}
	if session.managementPeer != "" {
		managementResult, err := session.executor.Run(ctx, platformexec.Request{
			Executable: session.ipPath, Arguments: []string{"-json", "-4", "route", "get", session.managementPeer}, MaxOutputBytes: inventoryLimit,
		})
		if err != nil {
			return nil, fmt.Errorf("observe active management route: %w", err)
		}
		var managementRoutes []routeObservation
		if json.Unmarshal([]byte(managementResult.Stdout), &managementRoutes) != nil || len(managementRoutes) != 1 {
			return nil, errors.New("decode active management route observation")
		}
		choice := byName[managementRoutes[0].Device]
		if choice == nil {
			return nil, errors.New("active management route refers to an unknown interface")
		}
		choice.managementRoute = true
	}
	sort.Slice(choices, func(left, right int) bool {
		if choices[left].index != choices[right].index {
			return choices[left].index < choices[right].index
		}
		return choices[left].name < choices[right].name
	})
	if len(choices) == 0 {
		return nil, errors.New("no network interfaces were discovered")
	}
	return choices, nil
}

func (session *Session) chooseInterfaces(choices []interfaceChoice) ([]interfaceChoice, error) {
	selectable := 0
	defaultNumbers := make([]string, 0, len(choices))
	for _, choice := range choices {
		if selectableChoice(choice) {
			selectable++
		}
	}
	for index, choice := range choices {
		if selectableChoice(choice) {
			defaultNumbers = append(defaultNumbers, strconv.Itoa(index+1))
		}
	}
	if selectable == 0 {
		return nil, errors.New("no unused safe Ethernet interface is available: loopback/non-Ethernet, Huawei HiLink, configured IPv4, current default-route, and active management interfaces cannot become the Keenetic WAN link")
	}
	for {
		fmt.Fprintf(session.output, "Select one or more dedicated LAN/management Ethernet ports (comma-separated) [%s = all safe] (q cancels): ", strings.Join(defaultNumbers, ","))
		answer, err := session.readLine()
		if err != nil {
			return nil, err
		}
		answer = strings.TrimSpace(answer)
		if answer == "q" || answer == "Q" || answer == "quit" || answer == "cancel" {
			return nil, ErrCancelled
		}
		if answer == "" || strings.EqualFold(answer, "all") {
			answer = strings.Join(defaultNumbers, ",")
		}
		parts := strings.Split(answer, ",")
		selected := make([]interfaceChoice, 0, len(parts))
		seen := make(map[int]bool, len(parts))
		invalid := false
		for _, part := range parts {
			number, parseErr := strconv.Atoi(strings.TrimSpace(part))
			if parseErr != nil || number < 1 || number > len(choices) || seen[number] {
				invalid = true
				break
			}
			seen[number] = true
			choice := choices[number-1]
			if !selectableChoice(choice) {
				fmt.Fprintf(session.output, "Interface %s is not safe for the LAN bridge: %s.\n", choice.name, blockedReason(choice))
				invalid = true
				break
			}
			selected = append(selected, choice)
		}
		if invalid || len(selected) == 0 {
			fmt.Fprintln(session.output, "Enter unique comma-separated numbers of selectable Ethernet ports.")
			continue
		}
		return selected, nil
	}
}

func (session *Session) chooseLAN(ctx context.Context, interfaceName string, dhcp bool) (string, error) {
	candidates := []string{"192.168.200.1/24", "192.168.201.1/24", "192.168.210.1/24", "10.200.0.1/24", "172.31.200.1/24"}
	proposed := ""
	for _, candidate := range candidates {
		if err := installpreflight.CheckGatewayLAN(ctx, session.executor, installpreflight.LANOptions{Interface: interfaceName, CIDR: candidate, IPPath: session.ipPath}); err == nil {
			proposed = candidate
			break
		}
	}
	for {
		if proposed == "" {
			fmt.Fprint(session.output, "Enter a non-conflicting private Gateway host CIDR (/16../30): ")
		} else {
			fmt.Fprintf(session.output, "Gateway host CIDR [%s]: ", proposed)
		}
		answer, err := session.readLine()
		if err != nil {
			return "", err
		}
		answer = strings.TrimSpace(answer)
		if answer == "q" || answer == "Q" || answer == "quit" || answer == "cancel" {
			return "", ErrCancelled
		}
		if answer == "" {
			answer = proposed
		}
		prefix, ok := netutil.ParseGatewayLAN(answer)
		if !ok {
			fmt.Fprintln(session.output, "Use a canonical RFC1918 host CIDR (/16../30), not a network/broadcast address and not 10.80.0.0/24.")
			continue
		}
		if dhcp && prefix.Bits() != 24 {
			fmt.Fprintln(session.output, "Built-in automatic DHCP currently requires a /24 Gateway LAN; enter a /24 or restart and decline DHCP.")
			continue
		}
		if err := installpreflight.CheckGatewayLAN(ctx, session.executor, installpreflight.LANOptions{Interface: interfaceName, CIDR: answer, IPPath: session.ipPath}); err != nil {
			fmt.Fprintf(session.output, "CIDR conflict: %v\n", err)
			continue
		}
		return answer, nil
	}
}

func (session *Session) yesNo(prompt string, defaultYes bool) (bool, error) {
	suffix := " [Y/n]: "
	if !defaultYes {
		suffix = " [y/N]: "
	}
	for {
		fmt.Fprint(session.output, prompt+suffix)
		answer, err := session.readLine()
		if err != nil {
			return false, err
		}
		switch strings.ToLower(strings.TrimSpace(answer)) {
		case "":
			return defaultYes, nil
		case "y", "yes":
			return true, nil
		case "n", "no":
			return false, nil
		case "q", "quit", "cancel":
			return false, ErrCancelled
		default:
			fmt.Fprintln(session.output, "Answer y or n (q cancels).")
		}
	}
}

func (session *Session) readLine() (string, error) {
	if !session.scanner.Scan() {
		if err := session.scanner.Err(); err != nil {
			return "", fmt.Errorf("read interactive terminal input: %w", err)
		}
		return "", ErrCancelled
	}
	return session.scanner.Text(), nil
}

func describeChoice(choice interfaceChoice) string {
	linkType := choice.linkType
	if linkType == "" {
		linkType = "unknown"
	}
	state := choice.operState
	if state == "" {
		state = "UNKNOWN"
	}
	addresses := "none"
	if len(choice.addresses) > 0 {
		addresses = strings.Join(choice.addresses, ",")
	}
	availability := "selectable"
	if choice.loopback {
		availability = "blocked: loopback"
	} else if choice.linkType != "ether" {
		availability = "blocked: not an Ethernet-type link"
	} else if choice.defaultRoute {
		availability = "blocked: current default route"
	} else if choice.managementRoute {
		availability = "blocked: active SSH management route"
	} else if choice.hilinkRisk {
		availability = "blocked: Huawei USB/HiLink device"
	} else if len(choice.addresses) > 0 {
		availability = "blocked: existing IPv4 (management/uplink/modem risk)"
	}
	return fmt.Sprintf("%s type=%s state=%s carrier=%s ipv4=%s — %s", choice.name, linkType, state, yesNoText(choice.carrier), addresses, availability)
}

func selectableChoice(choice interfaceChoice) bool {
	return !choice.loopback && choice.linkType == "ether" && !choice.defaultRoute && !choice.managementRoute && !choice.hilinkRisk && len(choice.addresses) == 0
}

func blockedReason(choice interfaceChoice) string {
	switch {
	case choice.loopback:
		return "loopback"
	case choice.linkType != "ether":
		return "not an Ethernet-type link"
	case choice.defaultRoute:
		return "current default route"
	case choice.managementRoute:
		return "active SSH management route"
	case choice.hilinkRisk:
		return "Huawei USB network device (HiLink modem risk)"
	case len(choice.addresses) > 0:
		return "existing IPv4 configuration (management/uplink/modem risk)"
	default:
		return "unknown safety state"
	}
}

func huaweiUSBNetwork(output string) bool {
	vendor, bus := "", ""
	for _, line := range strings.Split(output, "\n") {
		key, value, found := strings.Cut(strings.TrimSpace(line), "=")
		if !found || len(value) > 128 {
			continue
		}
		switch key {
		case "ID_VENDOR_ID":
			vendor = strings.ToLower(value)
		case "ID_BUS":
			bus = strings.ToLower(value)
		}
	}
	return bus == "usb" && vendor == "12d1"
}

func interfaceNames(choices []interfaceChoice) []string {
	result := make([]string, len(choices))
	for index, choice := range choices {
		result[index] = choice.name
	}
	return result
}

func validInterfaceName(value string) bool {
	if value == "" || len(value) > 15 {
		return false
	}
	for _, character := range value {
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') || (character >= '0' && character <= '9') || strings.ContainsRune("_.:-", character) {
			continue
		}
		return false
	}
	return true
}

func safeLabel(value string) string {
	if len(value) > 32 {
		return "invalid"
	}
	for _, character := range value {
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') || (character >= '0' && character <= '9') || strings.ContainsRune("_.:-", character) {
			continue
		}
		return "invalid"
	}
	return value
}

func contains(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func yesNoText(value bool) string {
	if value {
		return "yes"
	}
	return "no"
}

func allowDenyText(value bool) string {
	if value {
		return "allowed after validation"
	}
	return "not allowed"
}
