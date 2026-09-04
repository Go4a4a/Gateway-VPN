package installwizard

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"gateway-vpn/internal/platformexec"
)

func TestInteractiveSelectionListsMultipleInterfacesBlocksDefaultAndFindsFreeCIDR(t *testing.T) {
	executor := &wizardExecutor{
		links: `[
			{"ifindex":1,"ifname":"lo","flags":["LOOPBACK","UP"],"operstate":"UNKNOWN","link_type":"loopback"},
			{"ifindex":2,"ifname":"eno1","flags":["BROADCAST","UP","LOWER_UP"],"operstate":"UP","link_type":"ether"},
			{"ifindex":3,"ifname":"enp2s0","flags":["BROADCAST"],"operstate":"DOWN","link_type":"ether"},
			{"ifindex":4,"ifname":"enxhilink","flags":["BROADCAST","UP","LOWER_UP"],"operstate":"UP","link_type":"ether"},
			{"ifindex":5,"ifname":"enp3s0","flags":["BROADCAST"],"operstate":"DOWN","link_type":"ether"},
			{"ifindex":6,"ifname":"enxhilink2","flags":["BROADCAST"],"operstate":"DOWN","link_type":"ether"}
		]`,
		addresses: `[
			{"ifname":"lo","addr_info":[{"family":"inet","local":"127.0.0.1","prefixlen":8}]},
			{"ifname":"eno1","addr_info":[{"family":"inet","local":"192.168.1.20","prefixlen":24}]},
			{"ifname":"enp2s0","addr_info":[]},
			{"ifname":"enxhilink","addr_info":[{"family":"inet","local":"192.168.200.2","prefixlen":24}]},
			{"ifname":"enp3s0","addr_info":[]},
			{"ifname":"enxhilink2","addr_info":[]}
		]`,
		routes: `[
			{"dst":"default","gateway":"192.168.1.1","dev":"eno1"},
			{"dst":"192.168.1.0/24","dev":"eno1"},
			{"dst":"192.168.200.0/24","dev":"enxhilink"}
		]`,
		udev: map[string]string{"enxhilink": "ID_BUS=usb\nID_VENDOR_ID=12d1\n", "enxhilink2": "ID_BUS=usb\nID_VENDOR_ID=12d1\n"},
	}
	// First select the addressed HiLink and the default-route NIC, then the
	// unused Ethernet intended for Keenetic WAN.
	input := strings.NewReader("4\n2\n\n\n\n\n\n\n\n\n\n")
	output := new(bytes.Buffer)
	session, err := NewSession(executor, input, output)
	if err != nil {
		t.Fatal(err)
	}
	session.inspectBoot = configurableGRUB
	selection, err := session.Select(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if selection.Topology.Profile != "ETHERNET_HILINK" || selection.LANInterface != LANInterface || strings.Join(selection.LANMembers, ",") != "enp2s0,enp3s0" || selection.LANAddress != "192.168.201.1/24" || !selection.EnableDHCP || !selection.EnableSSH || !selection.InstallDependencies || selection.BootNetworkPolicy != BootNetworkNonBlocking || selection.GRUBPolicy != GRUBAutomatic {
		t.Fatalf("selection = %+v", selection)
	}
	for _, expected := range []string{"eno1", "enp2s0", "enp3s0", "enxhilink", "enxhilink2", "текущий выход Ubuntu", "Huawei USB/HiLink", "НУЖНО ВЫБРАТЬ СЕЙЧАС", "БУДЕТ НАСТРОЕНО АВТОМАТИЧЕСКИ", "МОЖНО ИЗМЕНИТЬ ПОСЛЕ УСТАНОВКИ", "без Ethernet carrier"} {
		if !strings.Contains(output.String(), expected) {
			t.Errorf("wizard output missing %q: %s", expected, output.String())
		}
	}
	if executor.mutationObserved {
		t.Fatal("interactive selection executed a mutating command")
	}
}

func TestInteractiveSelectionValidatesCustomCIDRAndDHCPPrefix(t *testing.T) {
	executor := cleanWizardExecutor()
	input := strings.NewReader("2\n\n10.42.0.1/16\n10.42.0.1/24\nno\nno\nno\n2\n3\n")
	output := new(bytes.Buffer)
	session, _ := NewSession(executor, input, output)
	session.inspectBoot = configurableGRUB
	selection, err := session.Select(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if selection.Topology.Profile != "ETHERNET_HILINK" || selection.LANInterface != LANInterface || strings.Join(selection.LANMembers, ",") != "enp2s0" || selection.LANAddress != "10.42.0.1/24" || selection.InstallDependencies || selection.EnableSSH || !selection.EnableDHCP || selection.BootNetworkPolicy != BootNetworkKeep || selection.GRUBPolicy != GRUBKeep {
		t.Fatalf("selection = %+v", selection)
	}
	if !strings.Contains(output.String(), "требует подсеть /24") {
		t.Fatalf("missing DHCP prefix explanation: %s", output.String())
	}
}

func TestInteractiveSelectionBlocksActiveManagementRoute(t *testing.T) {
	executor := cleanWizardExecutor()
	executor.managementRoute = `[{"dst":"203.0.113.10","dev":"enp2s0","prefsrc":"192.0.2.20"}]`
	session, _ := NewSession(executor, strings.NewReader(""), new(bytes.Buffer))
	if !session.ProtectManagementPeer("203.0.113.10") {
		t.Fatal("valid management peer was rejected")
	}
	if _, err := session.Select(context.Background()); err == nil || !strings.Contains(err.Error(), "нет свободного безопасного Ethernet") {
		t.Fatalf("management interface was selectable: %v", err)
	}
}

func TestInteractiveCancellationAndExactFinalConfirmation(t *testing.T) {
	session, _ := NewSession(cleanWizardExecutor(), strings.NewReader("q\n"), new(bytes.Buffer))
	if _, err := session.Select(context.Background()); !errors.Is(err, ErrCancelled) {
		t.Fatalf("cancel error = %v", err)
	}

	output := new(bytes.Buffer)
	session, _ = NewSession(cleanWizardExecutor(), strings.NewReader("yes\n"), output)
	confirmed, err := session.ConfirmApply("1.2.0", "PASSED", Selection{LANInterface: "enp2s0", LANAddress: "192.168.200.1/24"})
	if err != nil || confirmed {
		t.Fatalf("non-exact confirmation = %v,%v", confirmed, err)
	}
	if !strings.Contains(output.String(), "отменена") {
		t.Fatalf("cancellation not reported: %s", output.String())
	}

	session, _ = NewSession(cleanWizardExecutor(), strings.NewReader("INSTALL\n"), new(bytes.Buffer))
	confirmed, err = session.ConfirmApply("1.2.0", "PASSED", Selection{})
	if err != nil || !confirmed {
		t.Fatalf("exact confirmation = %v,%v", confirmed, err)
	}
}

func TestUnknownBootloaderIsPreservedWithoutUnsafePrompt(t *testing.T) {
	session, _ := NewSession(cleanWizardExecutor(), strings.NewReader("2\n\n\n\n\n\n\n\n"), new(bytes.Buffer))
	session.inspectBoot = func() bootObservation {
		return bootObservation{bootloader: "неизвестный", firmware: "UEFI", detail: "нет подтверждённого GRUB"}
	}
	selection, err := session.Select(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if selection.GRUBPolicy != GRUBKeep || selection.BootNetworkPolicy != BootNetworkNonBlocking {
		t.Fatalf("unsafe boot policy selection = %+v", selection)
	}
}

func TestWindowsBootEntryMakesVisibleBoundedMenuTheRecommendation(t *testing.T) {
	output := new(bytes.Buffer)
	session, _ := NewSession(cleanWizardExecutor(), strings.NewReader("2\n\n\n\n\n\n\n\n"), output)
	session.inspectBoot = func() bootObservation {
		return bootObservation{bootloader: "GRUB", configurable: true, firmware: "UEFI", detail: "Windows detected", windowsEntry: true}
	}
	selection, err := session.Select(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if selection.GRUBPolicy != GRUBMenu {
		t.Fatalf("Windows-safe GRUB selection = %+v", selection)
	}
	for _, expected := range []string{"Обнаружена Windows", "Показывать меню выбора 5 секунд — рекомендуется"} {
		if !strings.Contains(output.String(), expected) {
			t.Fatalf("Windows-safe explanation missing %q: %s", expected, output.String())
		}
	}
}

func TestInteractiveSelectionCanEnableInitialWireGuardIngress(t *testing.T) {
	input := strings.NewReader("2\n\n\n\n\nyes\nvpn.example.org\n\n\n\n\n\n")
	output := new(bytes.Buffer)
	session, _ := NewSession(cleanWizardExecutor(), input, output)
	session.inspectBoot = configurableGRUB
	selection, err := session.Select(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !selection.EnableWGIngress || selection.WGEndpointHost != "vpn.example.org" || selection.WGSubnetCIDR != "10.90.0.0/24" || selection.WGListenPort != 51820 || strings.Join(selection.WGClientDNS, ",") != "1.1.1.1,9.9.9.9" {
		t.Fatalf("WireGuard selection = %+v", selection)
	}
	if !strings.Contains(output.String(), "проброс") || !strings.Contains(output.String(), "10.90.0.1 не заявляется DNS") {
		t.Fatalf("WireGuard explanation missing: %s", output.String())
	}
}

func TestInteractiveEOFAndMalformedInventoryFailClosed(t *testing.T) {
	session, _ := NewSession(cleanWizardExecutor(), strings.NewReader(""), new(bytes.Buffer))
	if _, err := session.Select(context.Background()); !errors.Is(err, ErrCancelled) {
		t.Fatalf("EOF error = %v", err)
	}
	executor := cleanWizardExecutor()
	executor.links = `{`
	session, _ = NewSession(executor, strings.NewReader(""), new(bytes.Buffer))
	if _, err := session.Select(context.Background()); err == nil || !strings.Contains(err.Error(), "decode") {
		t.Fatalf("malformed inventory error = %v", err)
	}
}

func cleanWizardExecutor() *wizardExecutor {
	return &wizardExecutor{
		links:     `[{"ifindex":1,"ifname":"lo","flags":["LOOPBACK"],"operstate":"UNKNOWN","link_type":"loopback"},{"ifindex":2,"ifname":"enp2s0","flags":["BROADCAST"],"operstate":"DOWN","link_type":"ether"}]`,
		addresses: `[{"ifname":"lo","addr_info":[{"family":"inet","local":"127.0.0.1","prefixlen":8}]},{"ifname":"enp2s0","addr_info":[]}]`,
		routes:    `[]`,
	}
}

func configurableGRUB() bootObservation {
	return bootObservation{bootloader: "GRUB", configurable: true, firmware: "UEFI", detail: "valid configuration"}
}

type wizardExecutor struct {
	links            string
	addresses        string
	routes           string
	managementRoute  string
	udev             map[string]string
	mutationObserved bool
}

func (executor *wizardExecutor) Run(_ context.Context, request platformexec.Request) (platformexec.Result, error) {
	if request.Executable == "/usr/bin/udevadm" && len(request.Arguments) == 4 && request.Arguments[0] == "info" && request.Arguments[1] == "--query=property" && request.Arguments[2] == "--path" && strings.HasPrefix(request.Arguments[3], "/sys/class/net/") {
		name := strings.TrimPrefix(request.Arguments[3], "/sys/class/net/")
		return platformexec.Result{Stdout: executor.udev[name]}, nil
	}
	if request.Executable != "/usr/sbin/ip" {
		executor.mutationObserved = true
		return platformexec.Result{}, errors.New("unexpected executable")
	}
	switch strings.Join(request.Arguments, " ") {
	case "-json -details link show":
		return platformexec.Result{Stdout: executor.links}, nil
	case "-json -4 address show":
		return platformexec.Result{Stdout: executor.addresses}, nil
	case "-json -4 route show table all":
		return platformexec.Result{Stdout: executor.routes}, nil
	case "-json -4 route get 203.0.113.10":
		return platformexec.Result{Stdout: executor.managementRoute}, nil
	default:
		executor.mutationObserved = true
		return platformexec.Result{}, errors.New("unexpected or mutating command")
	}
}
