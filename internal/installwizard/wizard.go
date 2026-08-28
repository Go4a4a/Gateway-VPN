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
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"gateway-vpn/internal/installpreflight"
	"gateway-vpn/internal/netutil"
	"gateway-vpn/internal/platformexec"
)

const inventoryLimit = 4 << 20

const LANInterface = "gateway-vpn-lan"

type BootNetworkPolicy string

const (
	BootNetworkNonBlocking BootNetworkPolicy = "gateway-nonblocking"
	BootNetworkKeep        BootNetworkPolicy = "keep"
)

type GRUBPolicy string

const (
	GRUBAutomatic GRUBPolicy = "automatic-hidden"
	GRUBMenu      GRUBPolicy = "menu-5s"
	GRUBKeep      GRUBPolicy = "keep"
)

var (
	ErrCancelled       = errors.New("interactive Gateway installation cancelled")
	windowsGRUBPattern = regexp.MustCompile(`(?im)(menuentry[^\n]*windows|--class[ \t]+windows)`)
)

type Selection struct {
	LANInterface        string
	LANMembers          []string
	LANAddress          string
	EnableDHCP          bool
	InstallDependencies bool
	BootNetworkPolicy   BootNetworkPolicy
	GRUBPolicy          GRUBPolicy
}

type Session struct {
	executor       platformexec.Executor
	scanner        *bufio.Scanner
	output         io.Writer
	ipPath         string
	udevPath       string
	managementPeer string
	inspectBoot    func() bootObservation
}

type bootObservation struct {
	bootloader   string
	configurable bool
	firmware     string
	detail       string
	windowsEntry bool
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
	return &Session{
		executor: executor, scanner: scanner, output: output, ipPath: "/usr/sbin/ip", udevPath: "/usr/bin/udevadm",
		inspectBoot: inspectBootEnvironment,
	}, nil
}

// Select performs only observations and validation. It never changes links,
// addresses, routes, packages, files, services, or firewall state.
func (session *Session) Select(ctx context.Context) (Selection, error) {
	choices, err := session.inventory(ctx)
	if err != nil {
		return Selection{}, err
	}
	boot := session.inspectBoot()
	fmt.Fprintln(session.output, "Gateway VPN — понятная установка одной командой")
	fmt.Fprintln(session.output, "Сейчас выполняется только чтение настроек. До итогового слова INSTALL компьютер не изменяется.")
	fmt.Fprintln(session.output)
	fmt.Fprintln(session.output, "НУЖНО ВЫБРАТЬ СЕЙЧАС")
	fmt.Fprintln(session.output, "Каждый пункт показывает рекомендуемый вариант и объясняет последствия выбора.")
	fmt.Fprintln(session.output)
	fmt.Fprintln(session.output, "1. Физические сетевые порты для Keenetic и управления")
	fmt.Fprintln(session.output, "Gateway объединит выбранные Ethernet-порты в один безопасный LAN-мост. WebUI и SSH будут доступны через любой из них.")
	fmt.Fprintln(session.output, "Все выбранные порты станут одной локальной сетью. Не выбирайте порт модема, действующей внешней сети или второй кабель к тому же коммутатору, если не уверены в топологии.")
	fmt.Fprintln(session.output, "Обнаруженные интерфейсы:")
	for number, choice := range choices {
		fmt.Fprintf(session.output, "  [%d] %s\n", number+1, describeChoice(choice))
	}
	selected, err := session.chooseInterfaces(choices)
	if err != nil {
		return Selection{}, err
	}
	fmt.Fprintln(session.output)
	fmt.Fprintln(session.output, "2. Автоматическая настройка WAN-порта Keenetic (DHCP)")
	fmt.Fprintln(session.output, "Если включить, Keenetic сам получит адрес, шлюз и DNS от Gateway. Это рекомендуемый и самый простой вариант.")
	fmt.Fprintln(session.output, "Если выключить, адрес WAN придётся вручную настраивать в Keenetic; ошибочная настройка лишит клиентов связи.")
	enableDHCP, err := session.yesNo("Включить DHCP для WAN Keenetic?", true)
	if err != nil {
		return Selection{}, err
	}
	fmt.Fprintln(session.output)
	fmt.Fprintln(session.output, "3. Служебная подсеть между Gateway и Keenetic")
	fmt.Fprintln(session.output, "Установщик предложит свободную частную подсеть и проверит, что она не пересекается с существующими сетями, модемами и WireGuard.")
	lanAddress, err := session.chooseLAN(ctx, LANInterface, enableDHCP)
	if err != nil {
		return Selection{}, err
	}
	fmt.Fprintln(session.output)
	fmt.Fprintln(session.output, "4. Недостающие системные компоненты Ubuntu")
	fmt.Fprintln(session.output, "Рекомендуется разрешить установку только точного списка необходимых пакетов. Перед этим APT выполнит безопасную симуляцию без удаления и обновления уже установленных пакетов.")
	fmt.Fprintln(session.output, "Если запретить и хотя бы одного компонента нет, установка остановится до изменений.")
	installDependencies, err := session.yesNo("Разрешить установить недостающие компоненты после проверки плана APT?", true)
	if err != nil {
		return Selection{}, err
	}
	fmt.Fprintln(session.output)
	fmt.Fprintln(session.output, "5. Ожидание сети при загрузке Ubuntu")
	fmt.Fprintln(session.output, "HiLink и Ethernet могут быть отключены, медленно запускаться или временно зависнуть. Gateway должен загрузиться и открыть управление независимо от них.")
	bootNetworkPolicy, err := session.chooseBootNetworkPolicy()
	if err != nil {
		return Selection{}, err
	}
	fmt.Fprintln(session.output)
	fmt.Fprintln(session.output, "6. Меню загрузчика GRUB")
	fmt.Fprintf(session.output, "Обнаружено: %s; режим прошивки: %s. %s\n", boot.bootloader, boot.firmware, boot.detail)
	grubPolicy, err := session.chooseGRUBPolicy(boot)
	if err != nil {
		return Selection{}, err
	}
	session.printAutomaticPolicy()
	return Selection{
		LANInterface: LANInterface, LANMembers: interfaceNames(selected), LANAddress: lanAddress,
		EnableDHCP: enableDHCP, InstallDependencies: installDependencies,
		BootNetworkPolicy: bootNetworkPolicy, GRUBPolicy: grubPolicy,
	}, nil
}

// ConfirmApply is called only after the verified release's read-only preflight
// has completed. Requiring an exact token prevents an accidental Enter from
// authorizing package, network, firewall, or service changes.
func (session *Session) ConfirmApply(version, preflight string, selection Selection) (bool, error) {
	fmt.Fprintln(session.output)
	fmt.Fprintln(session.output, "ИТОГОВЫЙ ПЛАН УСТАНОВКИ")
	fmt.Fprintf(session.output, "  Проверенный release:             %s\n", version)
	fmt.Fprintf(session.output, "  Логический LAN Gateway:          %s\n", selection.LANInterface)
	fmt.Fprintf(session.output, "  Физические Ethernet-порты:       %s\n", strings.Join(selection.LANMembers, ", "))
	fmt.Fprintf(session.output, "  Адрес Gateway для Keenetic:      %s\n", selection.LANAddress)
	fmt.Fprintf(session.output, "  Автонастройка Keenetic (DHCP):   %s\n", yesNoText(selection.EnableDHCP))
	fmt.Fprintf(session.output, "  Недостающие пакеты:              %s\n", allowDenyText(selection.InstallDependencies))
	fmt.Fprintf(session.output, "  Ожидание внешней сети при boot:  %s\n", bootNetworkPolicyText(selection.BootNetworkPolicy))
	fmt.Fprintf(session.output, "  Меню GRUB:                       %s\n", grubPolicyText(selection.GRUBPolicy))
	fmt.Fprintf(session.output, "  Read-only preflight:             %s\n", preflight)
	fmt.Fprintln(session.output)
	fmt.Fprintln(session.output, "Автоматически будут настроены: fail-closed firewall, IPv4 forwarding, блокировка IPv6, SSH/WebUI только через LAN, systemd/watchdog, журналирование, recovery и rollback.")
	fmt.Fprintln(session.output, "Других скрытых аппаратных или сетевых решений нет: выбранные выше пункты и этот автоматический список составляют полный first-install contract.")
	fmt.Fprintln(session.output)
	fmt.Fprintln(session.output, "ЧТО ИМЕННО ИЗМЕНИТСЯ ПОСЛЕ INSTALL")
	fmt.Fprintln(session.output, "  • Программа: новая неизменяемая версия в /opt/gateway-vpn/releases/ и проверенный указатель current.")
	fmt.Fprintln(session.output, "  • Сеть: только owned файлы 05-/06-/80-gateway-vpn-* в /etc/systemd/network; Netplan пользователя не перезаписывается.")
	fmt.Fprintln(session.output, "  • Защита: owned nftables/sysctl, systemd units, журнал, watchdog и recovery helper; чужой firewall не очищается молча.")
	fmt.Fprintln(session.output, "  • Настройки и состояние: /etc/gateway-vpn, /var/lib/gateway-vpn и закрытый root-only recovery marker/snapshot.")
	if selection.BootNetworkPolicy == BootNetworkNonBlocking {
		fmt.Fprintln(session.output, "  • Загрузка сети: owned systemd wait-online drop-in; его удалит rollback/uninstall.")
	} else {
		fmt.Fprintln(session.output, "  • Загрузка сети: штатные wait-online настройки Ubuntu не изменяются.")
	}
	if selection.GRUBPolicy == GRUBKeep {
		fmt.Fprintln(session.output, "  • GRUB: текущая настройка не изменяется.")
	} else {
		fmt.Fprintln(session.output, "  • GRUB: только /etc/default/grub.d/90-gateway-vpn.cfg и заново проверенный /boot/grub/grub.cfg; основной /etc/default/grub не переписывается.")
	}
	fmt.Fprintln(session.output, "  • Диск не переразмечается, ОС не обновляется целиком и автоматическая перезагрузка после установки не выполняется.")
	fmt.Fprintln(session.output, "Во время применения выбранные LAN-порты кратковременно изменят сетевое состояние. При ошибке установщик восстановит прежние настройки.")
	fmt.Fprintln(session.output, "До этого момента постоянные настройки компьютера не изменялись.")
	fmt.Fprint(session.output, "Введите INSTALL для применения или q для отмены: ")
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
		fmt.Fprintln(session.output, "Подтверждение не совпало с INSTALL; установка отменена.")
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
		return nil, errors.New("нет свободного безопасного Ethernet-порта: loopback/non-Ethernet, Huawei HiLink, интерфейс с IPv4/default route или активная SSH-сессия не могут стать LAN-портом Gateway")
	}
	for {
		fmt.Fprintf(session.output, "Выберите один или несколько LAN-портов через запятую [%s = все безопасные] (q — отмена): ", strings.Join(defaultNumbers, ","))
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
				fmt.Fprintf(session.output, "Интерфейс %s нельзя безопасно включить в LAN-мост: %s.\n", choice.name, blockedReason(choice))
				invalid = true
				break
			}
			selected = append(selected, choice)
		}
		if invalid || len(selected) == 0 {
			fmt.Fprintln(session.output, "Введите неповторяющиеся номера разрешённых Ethernet-портов через запятую.")
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
			fmt.Fprint(session.output, "Введите свободный частный адрес Gateway с префиксом /16…/30: ")
		} else {
			fmt.Fprintf(session.output, "Адрес Gateway [%s — рекомендуется]: ", proposed)
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
			fmt.Fprintln(session.output, "Нужен частный IPv4-адрес RFC1918 с /16…/30; нельзя использовать адрес сети/broadcast или служебную сеть 10.80.0.0/24.")
			continue
		}
		if dhcp && prefix.Bits() != 24 {
			fmt.Fprintln(session.output, "Автоматический DHCP требует подсеть /24. Введите /24 либо перезапустите мастер и отключите DHCP.")
			continue
		}
		if err := installpreflight.CheckGatewayLAN(ctx, session.executor, installpreflight.LANOptions{Interface: interfaceName, CIDR: answer, IPPath: session.ipPath}); err != nil {
			fmt.Fprintf(session.output, "Эта подсеть конфликтует с существующей сетью: %v\n", err)
			continue
		}
		return answer, nil
	}
}

func (session *Session) chooseBootNetworkPolicy() (BootNetworkPolicy, error) {
	fmt.Fprintln(session.output, "  [1] Не ждать внешнюю сеть — рекомендуется")
	fmt.Fprintln(session.output, "      Ubuntu, WebUI и SSH запускаются без Ethernet carrier, DHCP модема и доступа в интернет.")
	fmt.Fprintln(session.output, "      HiLink обнаруживаются в фоне; штатный wait-online завершается сразу и не добавляет задержку загрузки.")
	fmt.Fprintln(session.output, "  [2] Сохранить стандартную политику Ubuntu")
	fmt.Fprintln(session.output, "      Другой сервис может ожидать обязательный Ethernet/HiLink около 90–120 секунд.")
	answer, err := session.numberedChoice("Выбор [1]: ", 1, 2)
	if err != nil {
		return "", err
	}
	if answer == 2 {
		return BootNetworkKeep, nil
	}
	return BootNetworkNonBlocking, nil
}

func (session *Session) chooseGRUBPolicy(boot bootObservation) (GRUBPolicy, error) {
	if !boot.configurable {
		fmt.Fprintln(session.output, "  Автоматическое изменение недоступно: безопасно сохраняется текущий загрузчик.")
		return GRUBKeep, nil
	}
	if boot.windowsEntry {
		fmt.Fprintln(session.output, "  Обнаружена Windows или другая Windows boot entry: скрывать меню небезопасно.")
		fmt.Fprintln(session.output, "  [1] Показывать меню выбора 5 секунд — рекомендуется")
		fmt.Fprintln(session.output, "      Ubuntu загрузится автоматически, но останется понятный выбор Windows и recovery.")
		fmt.Fprintln(session.output, "  [2] Сохранить текущую настройку GRUB")
		fmt.Fprintln(session.output, "      Установщик не меняет видимость или timeout существующего меню.")
		answer, err := session.numberedChoice("Выбор [1]: ", 1, 2)
		if err != nil {
			return "", err
		}
		if answer == 2 {
			return GRUBKeep, nil
		}
		return GRUBMenu, nil
	}
	fmt.Fprintln(session.output, "  [1] Автоматически загружать Ubuntu — рекомендуется")
	fmt.Fprintln(session.output, "      Меню скрыто, остаётся короткое окно Esc/Shift для ручного восстановления; recordfail не останавливает unattended boot.")
	fmt.Fprintln(session.output, "  [2] Показывать recovery-меню 5 секунд")
	fmt.Fprintln(session.output, "      Удобнее для ручной диагностики, но каждая загрузка будет дольше.")
	fmt.Fprintln(session.output, "  [3] Сохранить текущую настройку GRUB")
	fmt.Fprintln(session.output, "      Установщик не меняет видимость или timeout меню; существующая задержка может остаться.")
	answer, err := session.numberedChoice("Выбор [1]: ", 1, 3)
	if err != nil {
		return "", err
	}
	switch answer {
	case 2:
		return GRUBMenu, nil
	case 3:
		return GRUBKeep, nil
	default:
		return GRUBAutomatic, nil
	}
}

func (session *Session) numberedChoice(prompt string, defaultChoice, maximum int) (int, error) {
	for {
		fmt.Fprint(session.output, prompt)
		answer, err := session.readLine()
		if err != nil {
			return 0, err
		}
		answer = strings.TrimSpace(answer)
		if answer == "" {
			return defaultChoice, nil
		}
		if strings.EqualFold(answer, "q") || strings.EqualFold(answer, "quit") || strings.EqualFold(answer, "cancel") {
			return 0, ErrCancelled
		}
		number, parseErr := strconv.Atoi(answer)
		if parseErr == nil && number >= 1 && number <= maximum {
			return number, nil
		}
		fmt.Fprintf(session.output, "Введите номер от 1 до %d или q для отмены.\n", maximum)
	}
}

func (session *Session) printAutomaticPolicy() {
	fmt.Fprintln(session.output)
	fmt.Fprintln(session.output, "БУДЕТ НАСТРОЕНО АВТОМАТИЧЕСКИ ДЛЯ БЕЗОПАСНОСТИ")
	fmt.Fprintln(session.output, "  • Подлинность: подписанный release, версия и каждый файл проверяются до запуска установщика.")
	fmt.Fprintln(session.output, "  • Совместимость: Ubuntu, процессор, память, диск, время, TUN, WireGuard, nftables и systemd проходят read-only проверку.")
	fmt.Fprintln(session.output, "  • Firewall: сначала включается безопасная стартовая блокировка; рабочий путь открывается только после проверки выбранного способа доступа.")
	fmt.Fprintln(session.output, "  • Маршрутизация: IPv4 forwarding включается; IPv6 forwarding и возможный обход через IPv6 блокируются.")
	fmt.Fprintln(session.output, "  • Управление: SSH и WebUI доступны через общий LAN-мост, но закрыты со стороны HiLink и других внешних интерфейсов.")
	fmt.Fprintln(session.output, "  • Модемы: от одного до нескольких HiLink обнаруживаются в фоне; их отсутствие, отключение или долгая регистрация не задерживают Ubuntu.")
	fmt.Fprintln(session.output, "  • Службы: systemd запускает control plane, firewall guard, watchdog, DNS/DHCP (если выбран), журнал и recovery в безопасном порядке.")
	fmt.Fprintln(session.output, "  • Восстановление: до изменений создаётся durable marker и снимок; ошибка, обрыв процесса или reboot запускают rollback только owned-настроек.")
	fmt.Fprintln(session.output)
	fmt.Fprintln(session.output, "МОЖНО ИЗМЕНИТЬ ПОСЛЕ УСТАНОВКИ В WEBUI")
	fmt.Fprintln(session.output, "  • Модемы, их номера/приоритеты и подписки — вкладки «Модемы» и «Подписки».")
	fmt.Fprintln(session.output, "  • Серверы проверки, выбор VPN-нод и порядок доступа — соответствующие сетевые вкладки.")
	fmt.Fprintln(session.output, "  • Startup blocking, watchdog/reboot budgets, логирование и обновления — «Система и безопасность».")
	fmt.Fprintln(session.output, "  • Эти runtime-настройки не нужно придумывать во время первой установки: мастер создаст безопасную основу, затем WebUI объяснит каждое изменение.")
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
		case "y", "yes", "д", "да":
			return true, nil
		case "n", "no", "н", "нет":
			return false, nil
		case "q", "quit", "cancel":
			return false, ErrCancelled
		default:
			fmt.Fprintln(session.output, "Ответьте y/да или n/нет; q отменяет установку.")
		}
	}
}

func inspectBootEnvironment() bootObservation {
	firmware := "Legacy BIOS"
	if pathIsDirectory("/sys/firmware/efi") {
		firmware = "UEFI"
	}
	if pathIsRegular("/usr/sbin/update-grub") && pathIsRegular("/boot/grub/grub.cfg") && pathIsRegular("/etc/default/grub") {
		windowsEntry := containsWindowsGRUBEntry("/boot/grub/grub.cfg")
		detail := "доступен безопасный owned drop-in и проверка generated grub.cfg"
		if windowsEntry {
			detail += "; обнаружена Windows boot entry"
		}
		return bootObservation{bootloader: "GRUB", configurable: true, firmware: firmware, detail: detail, windowsEntry: windowsEntry}
	}
	return bootObservation{bootloader: "GRUB не подтверждён", firmware: firmware, detail: "необходимые штатные GRUB-файлы не найдены; настройки загрузчика останутся без изменений"}
}

func containsWindowsGRUBEntry(path string) bool {
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > inventoryLimit {
		return false
	}
	content, err := os.ReadFile(path)
	return err == nil && windowsGRUBPattern.Match(content)
}

func pathIsRegular(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.Mode().IsRegular()
}

func pathIsDirectory(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
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
	addresses := "нет"
	if len(choice.addresses) > 0 {
		addresses = strings.Join(choice.addresses, ",")
	}
	availability := "можно выбрать"
	if choice.loopback {
		availability = "заблокирован: внутренний loopback"
	} else if choice.linkType != "ether" {
		availability = "заблокирован: не Ethernet"
	} else if choice.defaultRoute {
		availability = "заблокирован: текущий выход Ubuntu в сеть"
	} else if choice.managementRoute {
		availability = "заблокирован: через него открыта текущая SSH-сессия"
	} else if choice.hilinkRisk {
		availability = "заблокирован: Huawei USB/HiLink модем"
	} else if len(choice.addresses) > 0 {
		availability = "заблокирован: уже имеет IPv4 и может быть management/uplink/modem"
	}
	return fmt.Sprintf("%s тип=%s состояние=%s кабель/link=%s IPv4=%s — %s", choice.name, linkType, state, yesNoText(choice.carrier), addresses, availability)
}

func selectableChoice(choice interfaceChoice) bool {
	return !choice.loopback && choice.linkType == "ether" && !choice.defaultRoute && !choice.managementRoute && !choice.hilinkRisk && len(choice.addresses) == 0
}

func blockedReason(choice interfaceChoice) string {
	switch {
	case choice.loopback:
		return "это внутренний loopback"
	case choice.linkType != "ether":
		return "это не Ethernet-интерфейс"
	case choice.defaultRoute:
		return "через него проходит текущий default route Ubuntu"
	case choice.managementRoute:
		return "через него открыта активная SSH-сессия"
	case choice.hilinkRisk:
		return "это Huawei USB/HiLink модем"
	case len(choice.addresses) > 0:
		return "он уже имеет IPv4 и может использоваться для управления или uplink"
	default:
		return "состояние безопасности не определено"
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
		return "да"
	}
	return "нет"
}

func allowDenyText(value bool) string {
	if value {
		return "разрешена только после безопасной симуляции"
	}
	return "запрещена; при отсутствии пакета установка остановится"
}

func bootNetworkPolicyText(value BootNetworkPolicy) string {
	if value == BootNetworkNonBlocking {
		return "не ждать Ethernet/HiLink/Internet (рекомендуется)"
	}
	return "сохранить стандартную политику Ubuntu"
}

func grubPolicyText(value GRUBPolicy) string {
	switch value {
	case GRUBAutomatic:
		return "скрытое меню и автоматическая загрузка Ubuntu"
	case GRUBMenu:
		return "показывать recovery-меню 5 секунд"
	default:
		return "не изменять текущую настройку"
	}
}
