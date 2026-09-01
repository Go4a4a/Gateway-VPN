package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
)

type interactiveDeployOptions struct {
	GatewaySSH          *string
	GatewayPort         *int
	VPSSSH              *string
	VPSPort             *int
	KnownHosts          *string
	GatewayIdentity     *string
	VPSIdentity         *string
	LANInterface        *string
	LANAddress          *string
	EnableDHCP          *bool
	PublicEndpoint      *string
	AdminPublicKey      *string
	AdminConfig         *string
	InstallDependencies *bool
	AllowGatewaySSH     *bool
}

func runInteractiveDeployWizard(input io.Reader, output io.Writer, options interactiveDeployOptions) error {
	reader := bufio.NewScanner(input)
	reader.Buffer(make([]byte, 1024), 4096)
	fmt.Fprintln(output, "Gateway VPN — безопасная установка Gateway и VPS")
	fmt.Fprintln(output, "Мастер использует pinned host keys и выбранные SSH key files. Пароли и содержимое private keys не сохраняются.")

	var err error
	if *options.GatewaySSH, err = promptRequired(reader, output, "Gateway SSH (USER@HOST)", *options.GatewaySSH); err != nil {
		return err
	}
	if *options.GatewayPort, err = promptPort(reader, output, "Gateway SSH port", *options.GatewayPort); err != nil {
		return err
	}
	if *options.VPSSSH, err = promptRequired(reader, output, "VPS SSH (USER@HOST)", *options.VPSSSH); err != nil {
		return err
	}
	if *options.VPSPort, err = promptPort(reader, output, "VPS SSH port", *options.VPSPort); err != nil {
		return err
	}
	if *options.KnownHosts, err = promptRequired(reader, output, "Absolute pinned known_hosts file", *options.KnownHosts); err != nil {
		return err
	}
	if *options.GatewayIdentity, err = promptRequired(reader, output, "Gateway SSH private-key file", *options.GatewayIdentity); err != nil {
		return err
	}
	if *options.VPSIdentity, err = promptRequired(reader, output, "VPS SSH private-key file", *options.VPSIdentity); err != nil {
		return err
	}
	if *options.LANInterface, err = promptRequired(reader, output, "Gateway Ethernet interface connected to Keenetic WAN", *options.LANInterface); err != nil {
		return err
	}
	if *options.LANAddress, err = promptRequired(reader, output, "Gateway transit LAN CIDR", defaultString(*options.LANAddress, "192.168.200.1/24")); err != nil {
		return err
	}
	if *options.EnableDHCP, err = promptYesNo(reader, output, "Enable validated DHCP on the transit LAN", *options.EnableDHCP); err != nil {
		return err
	}
	if *options.PublicEndpoint, err = promptRequired(reader, output, "Public VPS endpoint (HOST:51821)", *options.PublicEndpoint); err != nil {
		return err
	}
	if *options.AdminPublicKey == "" && *options.AdminConfig == "" {
		if *options.AdminConfig, err = promptRequired(reader, output, "Local administrator WireGuard config to create", defaultAdminConfigPath()); err != nil {
			return err
		}
	}
	if (*options.AdminPublicKey == "") == (*options.AdminConfig == "") {
		return errors.New("choose exactly one administrator config or public key")
	}
	if *options.InstallDependencies, err = promptYesNoDefault(reader, output, "Install validated missing dependencies", *options.InstallDependencies, true); err != nil {
		return err
	}
	if *options.AllowGatewaySSH, err = promptYesNo(reader, output, "Allow administrator SSH forwarding to Gateway through VPS", *options.AllowGatewaySSH); err != nil {
		return err
	}

	fmt.Fprintln(output, "\nПроверка перед установкой:")
	fmt.Fprintf(output, "  Gateway: %s:%d\n  VPS: %s:%d\n", *options.GatewaySSH, *options.GatewayPort, *options.VPSSSH, *options.VPSPort)
	fmt.Fprintf(output, "  pinned known_hosts: %s\n  Gateway SSH key: %s\n  VPS SSH key: %s\n", *options.KnownHosts, *options.GatewayIdentity, *options.VPSIdentity)
	fmt.Fprintf(output, "  transit: %s %s; DHCP=%t\n  VPS endpoint: %s\n", *options.LANInterface, *options.LANAddress, *options.EnableDHCP, *options.PublicEndpoint)
	if *options.AdminConfig != "" {
		fmt.Fprintf(output, "  administrator WireGuard config: %s\n", *options.AdminConfig)
	} else {
		fmt.Fprintln(output, "  administrator WireGuard key: external public key (private key is not handled)")
	}
	fmt.Fprintf(output, "  install dependencies=%t; Gateway SSH via VPS=%t\n", *options.InstallDependencies, *options.AllowGatewaySSH)
	fmt.Fprintln(output, "Сначала обе машины пройдут read-only preflight. Изменения начнутся только после успешных проверок.")
	fmt.Fprint(output, "Для продолжения введите INSTALL: ")
	if !reader.Scan() {
		return inputError(reader)
	}
	if strings.TrimSpace(reader.Text()) != "INSTALL" {
		return errors.New("exact INSTALL confirmation was not entered")
	}
	return nil
}

func promptRequired(reader *bufio.Scanner, output io.Writer, label, current string) (string, error) {
	for attempt := 0; attempt < 3; attempt++ {
		if current == "" {
			fmt.Fprintf(output, "%s: ", label)
		} else {
			fmt.Fprintf(output, "%s [%s]: ", label, current)
		}
		if !reader.Scan() {
			return "", inputError(reader)
		}
		value := strings.TrimSpace(reader.Text())
		if value == "" {
			value = current
		}
		if value != "" && !strings.ContainsAny(value, "\x00\r\n\t") {
			return value, nil
		}
		fmt.Fprintln(output, "Значение обязательно и должно быть одной строкой.")
	}
	return "", errors.New("too many invalid answers")
}

func promptPort(reader *bufio.Scanner, output io.Writer, label string, current int) (int, error) {
	if current == 0 {
		current = 22
	}
	for attempt := 0; attempt < 3; attempt++ {
		value, err := promptRequired(reader, output, label, strconv.Itoa(current))
		if err != nil {
			return 0, err
		}
		port, parseErr := strconv.Atoi(value)
		if parseErr == nil && port >= 1 && port <= 65535 {
			return port, nil
		}
		fmt.Fprintln(output, "Порт должен быть числом от 1 до 65535.")
		current = 0
	}
	return 0, errors.New("too many invalid port answers")
}

func promptYesNo(reader *bufio.Scanner, output io.Writer, label string, current bool) (bool, error) {
	return promptYesNoDefault(reader, output, label, current, current)
}

func promptYesNoDefault(reader *bufio.Scanner, output io.Writer, label string, current, defaultValue bool) (bool, error) {
	if current {
		defaultValue = true
	}
	defaultText := "n"
	if defaultValue {
		defaultText = "y"
	}
	for attempt := 0; attempt < 3; attempt++ {
		fmt.Fprintf(output, "%s [y/n, default %s]: ", label, defaultText)
		if !reader.Scan() {
			return false, inputError(reader)
		}
		switch strings.ToLower(strings.TrimSpace(reader.Text())) {
		case "":
			return defaultValue, nil
		case "y", "yes", "да", "д":
			return true, nil
		case "n", "no", "нет", "н":
			return false, nil
		default:
			fmt.Fprintln(output, "Введите y/yes/да или n/no/нет.")
		}
	}
	return false, errors.New("too many invalid yes/no answers")
}

func inputError(reader *bufio.Scanner) error {
	if err := reader.Err(); err != nil {
		return errors.New("read interactive answer failed")
	}
	return errors.New("interactive input ended")
}

func defaultAdminConfigPath() string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return ""
	}
	if runtime.GOOS == "windows" {
		return filepath.Join(home, "Gateway VPN", "admin-wireguard.conf")
	}
	return filepath.Join(home, ".config", "gateway-vpn", "admin.conf")
}

func defaultString(value, fallback string) string {
	if value != "" {
		return value
	}
	return fallback
}
