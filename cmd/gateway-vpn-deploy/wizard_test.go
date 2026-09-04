package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestInteractiveDeployWizardCollectsExplicitTrustAndRequiresInstall(t *testing.T) {
	gatewaySSH, vpsSSH, knownHosts := "", "", ""
	gatewayPort, vpsPort := 22, 22
	gatewayIdentity, vpsIdentity := "", ""
	lanInterface, lanAddress := "", "192.168.200.1/24"
	enableDHCP, installDependencies, allowGatewaySSH := false, true, false
	publicEndpoint, adminPublicKey, adminConfig := "", "", `C:\Users\Operator\Gateway VPN\admin.conf`
	options := interactiveDeployOptions{
		GatewaySSH: &gatewaySSH, GatewayPort: &gatewayPort,
		VPSSSH: &vpsSSH, VPSPort: &vpsPort, KnownHosts: &knownHosts,
		GatewayIdentity: &gatewayIdentity, VPSIdentity: &vpsIdentity,
		LANInterface: &lanInterface, LANAddress: &lanAddress, EnableDHCP: &enableDHCP,
		PublicEndpoint: &publicEndpoint, AdminPublicKey: &adminPublicKey, AdminConfig: &adminConfig,
		InstallDependencies: &installDependencies, AllowGatewaySSH: &allowGatewaySSH,
	}
	answers := strings.Join([]string{
		"operator@gateway.example", "", "root@vps.example", "2222",
		`C:\Users\Operator\ssh\known hosts`, `C:\Users\Operator\ssh\gateway key`, `C:\Users\Operator\ssh\vps key`,
		"enp2s0", "", "yes", "vpn.example.net:51821", "", "no", "INSTALL", "",
	}, "\n")
	var output bytes.Buffer
	if err := runInteractiveDeployWizard(strings.NewReader(answers), &output, options); err != nil {
		t.Fatalf("%v; output=%q", err, output.String())
	}
	if gatewaySSH != "operator@gateway.example" || gatewayPort != 22 || vpsSSH != "root@vps.example" || vpsPort != 2222 || !enableDHCP || installDependencies != true || allowGatewaySSH {
		t.Fatalf("unexpected wizard result: gateway=%s:%d vps=%s:%d dhcp=%t deps=%t ssh=%t", gatewaySSH, gatewayPort, vpsSSH, vpsPort, enableDHCP, installDependencies, allowGatewaySSH)
	}
	for _, required := range []string{"pinned host keys", "read-only preflight", "Только точное слово INSTALL"} {
		if !strings.Contains(output.String(), required) {
			t.Errorf("wizard output missing %q", required)
		}
	}
}

func TestInteractiveDeployWizardDoesNotApplyWithoutExactConfirmation(t *testing.T) {
	gatewaySSH, vpsSSH := "operator@gateway.example", "root@vps.example"
	knownHosts, gatewayIdentity, vpsIdentity := "/safe/known_hosts", "/safe/gateway", "/safe/vps"
	gatewayPort, vpsPort := 22, 22
	lanInterface, lanAddress := "enp2s0", "192.168.200.1/24"
	enableDHCP, installDependencies, allowGatewaySSH := false, true, false
	publicEndpoint, adminPublicKey, adminConfig := "1.1.1.1:51821", "external-public-key", ""
	options := interactiveDeployOptions{
		GatewaySSH: &gatewaySSH, GatewayPort: &gatewayPort,
		VPSSSH: &vpsSSH, VPSPort: &vpsPort, KnownHosts: &knownHosts,
		GatewayIdentity: &gatewayIdentity, VPSIdentity: &vpsIdentity,
		LANInterface: &lanInterface, LANAddress: &lanAddress, EnableDHCP: &enableDHCP,
		PublicEndpoint: &publicEndpoint, AdminPublicKey: &adminPublicKey, AdminConfig: &adminConfig,
		InstallDependencies: &installDependencies, AllowGatewaySSH: &allowGatewaySSH,
	}
	// Accept every displayed default, then decline the exact final phrase.
	answers := strings.Repeat("\n", 13) + "install\n"
	if err := runInteractiveDeployWizard(strings.NewReader(answers), &bytes.Buffer{}, options); err == nil {
		t.Fatal("wizard accepted a non-exact installation confirmation")
	}
}

func TestInteractiveDeployWizardSupportsBackAndSingleStepEdit(t *testing.T) {
	gatewaySSH, vpsSSH := "operator@gateway.example", "root@old-vps.example"
	knownHosts, gatewayIdentity, vpsIdentity := "/safe/known_hosts", "/safe/gateway", "/safe/vps"
	gatewayPort, vpsPort := 22, 22
	lanInterface, lanAddress := "enp2s0", "192.168.200.1/24"
	enableDHCP, installDependencies, allowGatewaySSH := false, true, false
	publicEndpoint, adminPublicKey, adminConfig := "1.1.1.1:51821", "external-public-key", ""
	options := interactiveDeployOptions{
		GatewaySSH: &gatewaySSH, GatewayPort: &gatewayPort,
		VPSSSH: &vpsSSH, VPSPort: &vpsPort, KnownHosts: &knownHosts,
		GatewayIdentity: &gatewayIdentity, VPSIdentity: &vpsIdentity,
		LANInterface: &lanInterface, LANAddress: &lanAddress, EnableDHCP: &enableDHCP,
		PublicEndpoint: &publicEndpoint, AdminPublicKey: &adminPublicKey, AdminConfig: &adminConfig,
		InstallDependencies: &installDependencies, AllowGatewaySSH: &allowGatewaySSH,
	}
	answers := []string{
		"", "", "", "НАЗАД", "root@new-vps.example", "2202",
	}
	answers = append(answers, make([]string, 9)...)
	answers = append(answers, "ИЗМЕНИТЬ", "2", "2222", "INSTALL", "")
	var output bytes.Buffer
	if err := runInteractiveDeployWizard(strings.NewReader(strings.Join(answers, "\n")), &output, options); err != nil {
		t.Fatalf("back/edit wizard failed: %v; output=%q", err, output.String())
	}
	if gatewayPort != 2222 || vpsSSH != "root@new-vps.example" || vpsPort != 2202 {
		t.Fatalf("back/edit values not retained: gateway_port=%d vps=%s:%d", gatewayPort, vpsSSH, vpsPort)
	}
	for _, required := range []string{"На любом шаге можно ввести НАЗАД", "Проверка перед установкой", "Номер шага для изменения"} {
		if !strings.Contains(output.String(), required) {
			t.Errorf("back/edit output missing %q", required)
		}
	}
}

func TestInteractiveDeployWizardRejectsBareSSHHostAndExplainsUserAtHost(t *testing.T) {
	gatewaySSH, vpsSSH := "", ""
	gatewayPort, vpsPort := 22, 22
	knownHosts, gatewayIdentity, vpsIdentity := "", "", ""
	lanInterface, lanAddress := "", "192.168.200.1/24"
	enableDHCP, installDependencies, allowGatewaySSH := false, true, false
	publicEndpoint, adminPublicKey, adminConfig := "", "", `C:\Users\Operator\Gateway VPN\admin.conf`
	options := interactiveDeployOptions{
		GatewaySSH: &gatewaySSH, GatewayPort: &gatewayPort,
		VPSSSH: &vpsSSH, VPSPort: &vpsPort, KnownHosts: &knownHosts,
		GatewayIdentity: &gatewayIdentity, VPSIdentity: &vpsIdentity,
		LANInterface: &lanInterface, LANAddress: &lanAddress, EnableDHCP: &enableDHCP,
		PublicEndpoint: &publicEndpoint, AdminPublicKey: &adminPublicKey, AdminConfig: &adminConfig,
		InstallDependencies: &installDependencies, AllowGatewaySSH: &allowGatewaySSH,
	}
	answers := strings.Join([]string{
		"operator@gateway.example", "", "172.18.224.1", "root@vps.example", "2222",
		`C:\Users\Operator\ssh\known hosts`, `C:\Users\Operator\ssh\gateway key`, `C:\Users\Operator\ssh\vps key`,
		"enp2s0", "", "no", "vpn.example.net:51821", "no", "no", "INSTALL",
	}, "\n")
	var output bytes.Buffer
	if err := runInteractiveDeployWizard(strings.NewReader(answers), &output, options); err != nil {
		t.Fatalf("%v; output=%q", err, output.String())
	}
	if vpsSSH != "root@vps.example" || vpsPort != 2222 {
		t.Fatalf("wizard did not recover from bare host: vps=%s:%d", vpsSSH, vpsPort)
	}
	if !strings.Contains(output.String(), "USER@HOST") {
		t.Fatal("wizard did not explain USER@HOST after a bare host")
	}
}
