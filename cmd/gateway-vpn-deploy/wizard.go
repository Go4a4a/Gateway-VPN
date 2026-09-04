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

var (
	errWizardBack      = errors.New("return to the previous wizard step")
	errWizardCancelled = errors.New("interactive deployment cancelled by user")
)

type interactiveWizardStep struct {
	title   string
	hints   []string
	prompt  func(*bufio.Scanner, io.Writer) error
	summary func() string
}

func runInteractiveDeployWizard(input io.Reader, output io.Writer, options interactiveDeployOptions) error {
	reader := bufio.NewScanner(input)
	reader.Buffer(make([]byte, 1024), 4096)
	fmt.Fprintln(output, "Gateway VPN — безопасная установка Gateway и VPS")
	fmt.Fprintln(output, "Мастер использует pinned host keys и выбранные SSH key files. Пароли и содержимое private keys не попадают в конфигурацию или отчёт; защищённая временная Windows-копия ключа удаляется после SSH-сессии.")
	fmt.Fprintln(output, "Ниже мастер объясняет каждое поле. При первом запуске указываются две Linux-машины: Gateway и VPS; после установки эти значения повторно вводить не нужно.")
	fmt.Fprintln(output, "На любом шаге можно ввести НАЗАД для возврата или ОТМЕНА для безопасного выхода. Изменения на Linux-машинах начнутся только после финального INSTALL.")

	steps := buildInteractiveWizardSteps(options)
	if len(steps) == 0 {
		return errors.New("interactive wizard has no steps")
	}
	stepIndex := 0
	singleEdit := false
	for {
		for stepIndex < len(steps) {
			step := steps[stepIndex]
			fmt.Fprintf(output, "\nШаг %d из %d.\n", stepIndex+1, len(steps))
			writeHint(output, step.title, step.hints...)
			err := step.prompt(reader, output)
			if errors.Is(err, errWizardBack) {
				if stepIndex == 0 {
					fmt.Fprintln(output, "Это первый шаг; вернуться дальше назад нельзя.")
				} else {
					stepIndex--
					singleEdit = false
				}
				continue
			}
			if err != nil {
				return err
			}
			if singleEdit {
				stepIndex = len(steps)
				singleEdit = false
			} else {
				stepIndex++
			}
		}

		if (*options.AdminPublicKey == "") == (*options.AdminConfig == "") {
			return errors.New("choose exactly one administrator config or public key")
		}
		fmt.Fprintln(output, "\nПроверка перед установкой:")
		for index, step := range steps {
			fmt.Fprintf(output, "  %2d. %-36s %s\n", index+1, step.title+":", step.summary())
		}
		fmt.Fprintln(output, "Сначала обе машины пройдут read-only preflight. Изменения начнутся только после успешных проверок.")
		writeHint(output, "Финальная проверка", "До этого момента выполняются только локальные действия и read-only проверки; Linux-машины ещё не менялись.", "Введите ИЗМЕНИТЬ, чтобы выбрать номер одного шага, НАЗАД — чтобы вернуться к последнему шагу, или ОТМЕНА — чтобы выйти.", "Только точное слово INSTALL большими латинскими буквами разрешает начать установку.")
		fmt.Fprint(output, "Действие [INSTALL / ИЗМЕНИТЬ / НАЗАД / ОТМЕНА]: ")
		if !reader.Scan() {
			return inputError(reader)
		}
		action := strings.TrimSpace(reader.Text())
		if action == "INSTALL" {
			return nil
		}
		switch strings.ToUpper(action) {
		case "НАЗАД", "BACK":
			stepIndex = len(steps) - 1
		case "ОТМЕНА", "CANCEL", "QUIT", "ВЫХОД":
			return errWizardCancelled
		case "ИЗМЕНИТЬ", "EDIT", "CHANGE":
			selected, err := promptWizardStepNumber(reader, output, len(steps))
			if errors.Is(err, errWizardBack) {
				continue
			}
			if err != nil {
				return err
			}
			stepIndex = selected
			singleEdit = true
		default:
			fmt.Fprintln(output, "Неизвестное действие. Установка не началась; выберите один из указанных вариантов.")
		}
	}
}

func buildInteractiveWizardSteps(options interactiveDeployOptions) []interactiveWizardStep {
	steps := []interactiveWizardStep{
		{
			title: "Gateway SSH",
			hints: []string{"Это адрес Linux-компьютера, который станет Gateway VPN.", "Введите имя пользователя и адрес через @: USER@HOST. Обычно это root@IP или ваш администраторский пользователь.", "Адрес и имя пользователя берутся из данных вашей Ubuntu-машины; пример: root@192.0.2.10."},
			prompt: func(reader *bufio.Scanner, output io.Writer) error {
				value, err := promptSSHDestination(reader, output, "Gateway SSH (USER@HOST)", *options.GatewaySSH)
				if err == nil {
					*options.GatewaySSH = value
				}
				return err
			},
			summary: func() string { return *options.GatewaySSH },
		},
		{
			title: "Порт SSH Gateway",
			hints: []string{"Это TCP-порт, через который на Gateway работает SSH.", "Обычно используется 22; если провайдер или ваш администратор назначил другой порт, введите его.", "В тестовом стенде порт указан в файле SANDBOX-STEPS.txt."},
			prompt: func(reader *bufio.Scanner, output io.Writer) error {
				value, err := promptPort(reader, output, "Gateway SSH port", *options.GatewayPort)
				if err == nil {
					*options.GatewayPort = value
				}
				return err
			},
			summary: func() string { return strconv.Itoa(*options.GatewayPort) },
		},
		{
			title: "VPS SSH",
			hints: []string{"Это адрес отдельного VPS, который будет использоваться для управления и резервного канала.", "Формат такой же: USER@HOST. Не вводите только IP-адрес — укажите имя пользователя перед @.", "Публичный адрес VPS и имя пользователя берутся у VPS-провайдера; пример: root@203.0.113.20."},
			prompt: func(reader *bufio.Scanner, output io.Writer) error {
				value, err := promptSSHDestination(reader, output, "VPS SSH (USER@HOST)", *options.VPSSSH)
				if err == nil {
					*options.VPSSSH = value
				}
				return err
			},
			summary: func() string { return *options.VPSSSH },
		},
		{
			title: "Порт SSH VPS",
			hints: []string{"Это TCP-порт SSH на VPS.", "Обычно 22. В тестовом стенде Gateway и VPS могут иметь один IP, но разные порты — это нормально.", "Порт берётся из настроек VPS или из подготовленной инструкции тестового стенда."},
			prompt: func(reader *bufio.Scanner, output io.Writer) error {
				value, err := promptPort(reader, output, "VPS SSH port", *options.VPSPort)
				if err == nil {
					*options.VPSPort = value
				}
				return err
			},
			summary: func() string { return strconv.Itoa(*options.VPSPort) },
		},
		{
			title: "Pinned known_hosts",
			hints: []string{"Это файл с заранее проверенными отпечатками SSH-серверов Gateway и VPS.", "Введите полный путь к существующему файлу, а не его содержимое.", "Файл выдаёт администратор или его создаёт подготовительный мастер после проверки отпечатков; пример: C:\\GatewayVPNGate\\targets-evidence\\known_hosts."},
			prompt: func(reader *bufio.Scanner, output io.Writer) error {
				value, err := promptRequired(reader, output, "Absolute pinned known_hosts file", *options.KnownHosts)
				if err == nil {
					*options.KnownHosts = value
				}
				return err
			},
			summary: func() string { return *options.KnownHosts },
		},
		{
			title: "SSH-ключ Gateway",
			hints: []string{"Это выбранный private key-файл для входа на Gateway без пароля.", "Укажите полный путь к файлу ключа; не вставляйте сам ключ в окно мастера.", "Выберите тот же ключ, которым вы обычно подключаетесь к Gateway через OpenSSH."},
			prompt: func(reader *bufio.Scanner, output io.Writer) error {
				value, err := promptRequired(reader, output, "Gateway SSH private-key file", *options.GatewayIdentity)
				if err == nil {
					*options.GatewayIdentity = value
				}
				return err
			},
			summary: func() string { return *options.GatewayIdentity },
		},
		{
			title: "SSH-ключ VPS",
			hints: []string{"Это private key-файл для входа на VPS.", "Можно выбрать тот же административный ключ, если он разрешён на обеих машинах, либо отдельный ключ VPS.", "Введите полный путь к файлу; содержимое ключа не сохраняется и не передаётся в отчёт."},
			prompt: func(reader *bufio.Scanner, output io.Writer) error {
				value, err := promptRequired(reader, output, "VPS SSH private-key file", *options.VPSIdentity)
				if err == nil {
					*options.VPSIdentity = value
				}
				return err
			},
			summary: func() string { return *options.VPSIdentity },
		},
		{
			title: "Ethernet Gateway → Keenetic",
			hints: []string{"Выберите физический Ethernet-интерфейс Gateway, к которому подключён WAN-порт Keenetic.", "Нужно имя интерфейса Linux, например lan0 или enp2s0, а не название сетевой карты в Windows.", "На самом Gateway список можно посмотреть командой `ip -br link`; не выбирайте интерфейс текущей SSH-сессии или модем Huawei."},
			prompt: func(reader *bufio.Scanner, output io.Writer) error {
				value, err := promptRequired(reader, output, "Gateway Ethernet interface connected to Keenetic WAN", *options.LANInterface)
				if err == nil {
					*options.LANInterface = value
				}
				return err
			},
			summary: func() string { return *options.LANInterface },
		},
		{
			title: "Transit LAN CIDR",
			hints: []string{"Это отдельная локальная подсеть между Gateway и WAN-портом Keenetic.", "Введите адрес Gateway с маской, например 192.168.200.1/24; эта сеть не должна совпадать с домашней LAN, VPN или подсетью модема.", "Если не знаете подходящую сеть, оставьте предложенное значение и проверьте, что оно не используется в вашей сети."},
			prompt: func(reader *bufio.Scanner, output io.Writer) error {
				value, err := promptRequired(reader, output, "Gateway transit LAN CIDR", defaultString(*options.LANAddress, "192.168.200.1/24"))
				if err == nil {
					*options.LANAddress = value
				}
				return err
			},
			summary: func() string { return *options.LANAddress },
		},
		{
			title: "DHCP на transit LAN",
			hints: []string{"При включении Gateway будет автоматически выдавать адреса устройствам за Keenetic.", "Выберите yes только если DHCP на этом сегменте должен работать на Gateway; при DHCP Keenetic оставьте no.", "В тестовом стенде обычно выбирается no, чтобы не вмешиваться в чужой DHCP."},
			prompt: func(reader *bufio.Scanner, output io.Writer) error {
				value, err := promptYesNo(reader, output, "Enable validated DHCP on the transit LAN", *options.EnableDHCP)
				if err == nil {
					*options.EnableDHCP = value
				}
				return err
			},
			summary: func() string { return yesNoSummary(*options.EnableDHCP) },
		},
		{
			title: "Публичный адрес VPS",
			hints: []string{"Это внешний адрес и UDP-порт VPS, куда Gateway установит WireGuard-соединение.", "Введите HOST:PORT, например 203.0.113.20:51821. Не используйте внутренний Docker/домашний адрес и не добавляйте http://.", "Адрес берётся из панели VPS и его firewall; UDP-порт должен быть разрешён у провайдера."},
			prompt: func(reader *bufio.Scanner, output io.Writer) error {
				value, err := promptRequired(reader, output, "Public VPS endpoint (HOST:51821)", *options.PublicEndpoint)
				if err == nil {
					*options.PublicEndpoint = value
				}
				return err
			},
			summary: func() string { return *options.PublicEndpoint },
		},
	}
	if *options.AdminPublicKey == "" && *options.AdminConfig == "" {
		steps = append(steps, interactiveWizardStep{
			title: "Локальный WireGuard-конфиг администратора",
			hints: []string{"Мастер создаст здесь конфигурацию для подключения администратора к Gateway через VPS.", "Введите полный путь к новому файлу либо нажмите Enter для предложенного пути.", "Это путь на компьютере, где запущен мастер; сам private key будет создан локально и не попадёт на VPS."},
			prompt: func(reader *bufio.Scanner, output io.Writer) error {
				value, err := promptRequired(reader, output, "Local administrator WireGuard config to create", defaultString(*options.AdminConfig, defaultAdminConfigPath()))
				if err == nil {
					*options.AdminConfig = value
				}
				return err
			},
			summary: func() string { return *options.AdminConfig },
		})
	}
	steps = append(steps,
		interactiveWizardStep{
			title: "Установка недостающих зависимостей",
			hints: []string{"Мастер проверит пакеты, которые нужны Gateway и VPS, и установит только разрешённые отсутствующие зависимости.", "Рекомендуется yes. Уже установленные пакеты не удаляются и не обновляются без необходимости.", "Выберите no только если вы заранее установили зависимости вручную."},
			prompt: func(reader *bufio.Scanner, output io.Writer) error {
				value, err := promptYesNoDefault(reader, output, "Install validated missing dependencies", *options.InstallDependencies, true)
				if err == nil {
					*options.InstallDependencies = value
				}
				return err
			},
			summary: func() string { return yesNoSummary(*options.InstallDependencies) },
		},
		interactiveWizardStep{
			title: "SSH-доступ администратора через VPS",
			hints: []string{"При yes мастер разрешит администраторский SSH-доступ к Gateway через защищённый канал VPS.", "Это удобно, когда Gateway не имеет внешнего IP; при no такой forwarding не включается.", "Выбирайте yes только если хотите управлять Gateway через VPS."},
			prompt: func(reader *bufio.Scanner, output io.Writer) error {
				value, err := promptYesNo(reader, output, "Allow administrator SSH forwarding to Gateway through VPS", *options.AllowGatewaySSH)
				if err == nil {
					*options.AllowGatewaySSH = value
				}
				return err
			},
			summary: func() string { return yesNoSummary(*options.AllowGatewaySSH) },
		},
	)
	return steps
}

func promptWizardStepNumber(reader *bufio.Scanner, output io.Writer, maximum int) (int, error) {
	for attempt := 0; attempt < 3; attempt++ {
		fmt.Fprintf(output, "Номер шага для изменения [1-%d]: ", maximum)
		if !reader.Scan() {
			return 0, inputError(reader)
		}
		value := strings.TrimSpace(reader.Text())
		if err := wizardNavigationError(value); err != nil {
			return 0, err
		}
		number, err := strconv.Atoi(value)
		if err == nil && number >= 1 && number <= maximum {
			return number - 1, nil
		}
		fmt.Fprintln(output, "Введите номер шага из указанного диапазона.")
	}
	return 0, errors.New("too many invalid wizard step numbers")
}

func yesNoSummary(value bool) string {
	if value {
		return "да"
	}
	return "нет"
}

func writeHint(output io.Writer, title string, lines ...string) {
	fmt.Fprintf(output, "\n[%s]\n", title)
	for _, line := range lines {
		fmt.Fprintf(output, "  %s\n", line)
	}
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
		if err := wizardNavigationError(value); err != nil {
			return "", err
		}
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

func promptSSHDestination(reader *bufio.Scanner, output io.Writer, label, current string) (string, error) {
	for attempt := 0; attempt < 3; attempt++ {
		value, err := promptRequired(reader, output, label, current)
		if err != nil {
			return "", err
		}
		user, host, found := strings.Cut(value, "@")
		if found && user != "" && host != "" && !strings.Contains(host, "@") {
			return value, nil
		}
		fmt.Fprintln(output, "Введите SSH-адрес в формате USER@HOST, например root@192.0.2.10.")
		current = ""
	}
	return "", errors.New("too many invalid SSH destinations")
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
		value := strings.TrimSpace(reader.Text())
		if err := wizardNavigationError(value); err != nil {
			return false, err
		}
		switch strings.ToLower(value) {
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

func wizardNavigationError(value string) error {
	switch strings.ToUpper(strings.TrimSpace(value)) {
	case "НАЗАД", "BACK":
		return errWizardBack
	case "ОТМЕНА", "CANCEL", "QUIT", "ВЫХОД":
		return errWizardCancelled
	default:
		return nil
	}
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
