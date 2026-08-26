# Gateway VPN — план реализации

**Версия:** 1.1  
**Дата:** 2026-08-23  
**Статус:** готов к началу технического этапа 0  
**Целевая платформа Gateway:** Ubuntu Server 24.04 LTS, x86_64  
**Целевая платформа VPS:** Ubuntu Server LTS 20.04 и выше, x86_64; Debian 12+ как отдельный support profile  
**Проверяемые Ubuntu VPS profiles:** 20.04, 22.04, 24.04 и 26.04 LTS; 20.04 допускается только с активным Ubuntu Pro/ESM и актуальными security updates
**Поправка 2026-08-26:** добавлен обязательный contract круглосуточного самоконтроля и bounded recovery (§9.8); остальные ранее зафиксированные решения версии 1.1 не переписаны

---

## Оглавление

1. Назначение и границы проекта
2. Предпосылки и обязательные проверки
3. Архитектура
4. Сетевая топология
5. HiLink Modem Manager
6. Mihomo data plane
7. Subscription Manager
8. Firewall и fail-closed
9. Health, failover и reconciliation
10. WireGuard management plane
11. Конфигурация и источник истины
12. База данных
13. Traffic accounting
14. API и Web UI
15. Безопасность
16. Логи, события и диагностика
17. Установка и эксплуатация
18. Тестирование
19. Этапы реализации
20. Definition of Done проекта
21. Данные, которые нужно зафиксировать на этапе 0

---

## 1. Назначение и границы проекта

### 1.1 Назначение

Gateway VPN — домашний IPv4-шлюз, который:

- получает один или несколько uplink от HiLink-модемов, включая Huawei E3372h-325;
- направляет пользовательский трафик через один процесс Mihomo в режиме TUN;
- загружает HAPP-совместимые VPN-подписки и хранит последнюю рабочую версию;
- отбирает внутри подписок только узлы, пригодные для обхода заданных ресурсов;
- автоматически выбирает подтверждённый путь `модем → подписка → bypass-узел` и переключает его при отказе;
- исключает прямой выход пользовательского трафика через мобильного оператора;
- предоставляет локальный Web UI и API;
- сохраняет управление через независимый WireGuard-туннель Gateway → VPS;
- собирает состояние, события и статистику трафика.

### 1.2 Что входит в MVP

- несколько одновременно подключённых HiLink USB-Ethernet модемов с приоритетами;
- hot-plug/hot-unplug, сохранение offline-модемов в конфигурации и автоматическое возвращение после reconnect;
- независимая проверка каждой пары `модем × подписка`;
- IPv4 data plane;
- Keenetic, подключённый WAN-портом к Gateway;
- один процесс Mihomo;
- Mihomo TUN с прозрачной обработкой TCP, UDP и DNS;
- несколько подписок с приоритетами;
- поиск bypass-кандидатов по настраиваемым признакам имени с fallback-проверкой всех узлов;
- произвольное количество приоритетных probe targets, управляемых через Web UI;
- last known good для подписок и конфигурации Mihomo;
- автоматический failover и failback с hysteresis;
- fail-closed nftables;
- DHCP и DNS на транзитной сети Gateway → Keenetic;
- HTTPS Web UI, REST API и CLI;
- удалённый доступ к самому Gateway через VPS WireGuard;
- SQLite, структурированные события и учёт трафика;
- idempotent install/update/uninstall scripts;
- backup, restore и diagnostic bundle.
- круглосуточный self-health supervisor с настраиваемой через Web UI безопасной лестницей восстановления и защитой от restart/reboot loop.

Рабочая топология — `1..N` adopted HiLink-модемов. Один модем является полностью поддерживаемой штатной конфигурацией: список modem priority состоит из одного элемента, межмодемный failover не выполняется, а при disconnect единственного uplink Gateway остаётся `PATH_BLOCKED` до его стабильного reconnect либо добавления другого модема. При двух, пяти или большем числе модемов используется та же модель без специального «двухмодемного» режима; каждый модем имеет собственные identity, priority, management subnet, route table, fwmark, health и ячейки `modem × subscription`. Web UI не задаёт искусственный предел количества записей, но фактический hard limit определяется уникальностью подсетей, USB-питанием и hardware-profile limits для размера Mihomo config и probe matrix. Требование иметь минимум два модема относится только к стендовой проверке multi-modem failover и не является минимальным требованием для обычной установки.

### 1.3 Что не входит в MVP

- собственный VPN-протокол;
- поддержка QMI, MBIM, PPP и Stick-прошивок модемов;
- автоматическая перепрошивка Huawei;
- IPv6-транзит;
- балансировка одной пользовательской сессии между подписками;
- полноценный многопользовательский RBAC;
- доступ через VPS к домашней сети `192.168.50.0/24` за Keenetic;
- QMI/MBIM/PPP, Ethernet WAN и другие не-HiLink типы uplink;
- одновременная работа HiLink-модемов с пересекающимися management-подсетями;
- агрегация пропускной способности или распределение одной пользовательской сессии между модемами;
- мобильное приложение;
- облачный управляющий сервис.

### 1.4 Основные принципы

1. **Fail-closed:** LAN никогда не выходит напрямую через HiLink.
2. **Разделение плоскостей:** пользовательский трафик, управление Gateway и служебный bootstrap имеют разные правила.
3. **Один владелец состояния:** приложение поддерживает желаемое состояние через reconciliation loop.
4. **Last known good:** ошибочное обновление не разрушает работающий путь.
5. **Минимальные привилегии:** Web/API не работают от root; секреты не попадают в БД, API и логи.
6. **Проверяемость:** каждый этап заканчивается автоматизируемыми критериями готовности.
7. **Безопасное изменение сети:** рискованные настройки применяются с подтверждением или rollback.
8. **Unattended recovery:** локальные программные сбои обнаруживаются и исправляются автоматически, но внешний outage не маскируется опасным циклом перезагрузок.

---

## 2. Предпосылки и обязательные проверки

### 2.1 Аппаратные предпосылки

- Gateway имеет отдельный Ethernet-порт для Keenetic;
- каждый HiLink-модем подключён к USB-порту/хабу с достаточным индивидуальным питанием;
- каждый HiLink выдаёт Gateway адрес по DHCP и имеет собственный Web UI;
- management-подсети всех одновременно enabled модемов уникальны и не пересекаются с Gateway LAN, Home LAN и WireGuard;
- Gateway включается раньше либо одновременно с Keenetic;
- на Gateway корректно работают TUN, nftables и kernel WireGuard.

### 2.2 Матрица прямой достижимости

До начала основной реализации таблица заполняется отдельно для каждого модема/оператора:

| Ресурс | Нужен напрямую через HiLink | Результат стенда |
|---|---:|---|
| Web UI/API HiLink | да | TBD |
| DNS для имён VPN-нод | да, если ноды заданы доменами | TBD |
| VPN-ноды подписок | да | TBD |
| URL первого импорта подписки | да или локальный импорт | TBD |
| URL обновления подписок | желательно; после запуска допускается через активный VPN | TBD |
| VPS WireGuard endpoint | да | TBD |
| NTP endpoint | желательно | TBD |
| Репозиторий обновлений Gateway | не обязательно в runtime | TBD |

Если VPN-ноды или VPS отсутствуют в whitelist конкретного оператора, соответствующая комбинация через этот модем технически невозможна независимо от реализации Gateway. Это не делает автоматически неисправными другие модемы.

### 2.3 Зафиксированные сетевые ограничения MVP

- пользовательский data plane — только IPv4;
- IPv6 на транзитной сети блокируется;
- каждый модем работает как независимый NAT-router, входящие подключения к Gateway через операторов не используются;
- WireGuard всегда инициируется с Gateway на VPS;
- домашняя сеть за Keenetic остаётся отдельным NAT-доменом.

---

## 3. Архитектура

### 3.1 Компоненты Gateway

```text
┌───────────────────────────────────────────────────────────────┐
│                         GATEWAY                               │
│                                                               │
│  ┌───────────────────── gateway-vpn ───────────────────────┐ │
│  │ Config / DB / migrations                               │ │
│  │ HiLink Modem Manager (1..N)                            │ │
│  │ Subscription Manager + Node Classifier + LKG           │ │
│  │ Probe Target Manager / Health / Failover               │ │
│  │ Multi-Uplink Routing Controller                         │ │
│  │ Mihomo Controller                                      │ │
│  │ Firewall Controller                                    │ │
│  │ Traffic / Events / Diagnostics                         │ │
│  │ HTTPS API + embedded Web UI                            │ │
│  └─────────────────────────────────────────────────────────┘ │
│              │                  │                 │           │
│       ┌──────▼──────┐    ┌──────▼──────┐   ┌─────▼──────┐   │
│       │ one Mihomo  │    │  nftables   │   │ WireGuard │   │
│       │ process/TUN │    │ fail-closed │   │ mgmt peer │   │
│       └─────────────┘    └─────────────┘   └────────────┘   │
│                                                               │
│  ┌──────────┐ ┌──────────┐              ┌────────────────┐    │
│  │HiLink #1 │ │HiLink #N │              │ LAN to        │    │
│  │USB Eth   │ │USB Eth   │              │ Keenetic WAN  │    │
│  └──────────┘ └──────────┘              └────────────────┘    │
└───────────────────────────────────────────────────────────────┘
```

### 3.2 Разделение плоскостей

#### Data plane

```text
Home device
  → Keenetic NAT
  → Gateway LAN
  → Mihomo TUN
  → выбранная пара subscription/node
  → выбранный HiLink modem
  → HiLink NAT
  → mobile network
  → Internet
```

Ни один nftables route/accept не должен создавать путь `Gateway LAN → любой HiLink` в обход Mihomo.

#### Control plane

```text
Web UI / CLI
  → gateway-vpn
  → desired state in SQLite
  → reconciler
  → Mihomo / nftables / WireGuard / dnsmasq
```

#### Management plane

```text
Admin device
  → WireGuard
  → VPS
  → WireGuard
  → Gateway HTTPS/SSH
```

Management plane имеет отдельное исключение в firewall и не зависит от работоспособности VPN-подписок.

### 3.3 Модель процессов

- `gateway-vpn.service` — непривилегированное Go-приложение;
- `mihomo.service` — один процесс под отдельным системным пользователем;
- `dnsmasq.service` — DHCP/DNS только на интерфейсе к Keenetic;
- `wg-quick@wg-mgmt.service` либо нативное управление `wg`/`ip`;
- `nftables.service` загружает boot-time fail-closed ruleset до запуска data plane.

Привилегированные операции выполняются через строго ограниченный helper либо через выделенные systemd units. REST API не получает произвольный shell-доступ.

---

## 4. Сетевая топология

### 4.1 Адресация

| Сегмент | Адреса | Назначение |
|---|---|---|
| HiLink modem #1 | определяется DHCP; например `192.168.8.0/24` | Operator A ↔ Gateway |
| HiLink modem #2 | определяется DHCP; например `192.168.9.0/24` | Operator B ↔ Gateway |
| HiLink modem #N | отдельная уникальная подсеть | Operator N ↔ Gateway |
| Gateway transit LAN | `192.168.200.0/24` | Gateway ↔ Keenetic WAN |
| Gateway transit IP | `192.168.200.1/24` | DHCP gateway и DNS |
| Keenetic WAN | DHCP reservation, например `192.168.200.2` | WAN Keenetic |
| Home LAN | `192.168.50.0/24` | устройства за Keenetic |
| WireGuard management | `10.80.0.0/24` | VPS, Gateway, администраторы |
| VPS WireGuard | `10.80.0.1/24` | management router |
| Gateway WireGuard | `10.80.0.2/32` | удалённое управление |
| Admin peers | `10.80.0.10/32` и далее | ПК/телефон администратора |

Подсети не должны пересекаться. Адрес и subnet каждого HiLink считаются обнаруживаемыми параметрами, а не константами. Совпадающие management-подсети не исправляются метриками или priority: конфликтующий модем помещается в quarantine до изменения его подсети.

### 4.2 Логические имена интерфейсов

Приложение хранит роли, а не полагается на случайные имена `eth0`, `usb0` или `enx...`:

| Роль | Пример | Определение |
|---|---|---|
| `uplink_hilink_<id>` | `enx001e...` | stable modem ID + USB parent + DHCP gateway |
| `lan_keenetic` | `enp2s0` | явная настройка установщика |
| `tun_mihomo` | `gateway-vpn-tun` | фиксированное имя в Mihomo |
| `wg_management` | `wg-mgmt` | фиксированное имя |

### 4.3 Multi-uplink policy routing

Каждый enabled modem получает независимый routing context:

```text
modem priority 10 → fwmark 0x1101 → table 1101 → default via modem_1 gateway
modem priority 20 → fwmark 0x1102 → table 1102 → default via modem_2 gateway
modem priority 30 → fwmark 0x1103 → table 1103 → default via modem_3 gateway
```

Правила:

- DHCP lease каждого модема не устанавливает default route в main table;
- Modem Manager создаёт link route и default route только в выделенной table;
- table ID и fwmark стабильны для `modem_id`, а не для текущего имени интерфейса;
- исходящие proxy sockets получают `interface-name` и `routing-mark` нужного модема;
- DNS bootstrap для proxy hostname выполняется в контексте того же модема;
- приложение проверяет `ip route get <proxy-ip> mark <modem-mark>` до квалификации path;
- ECMP, bonding и load balancing между модемами не используются;
- в каждый момент пользовательский трафик имеет один активный path tuple;
- subnet conflict с другим модемом/LAN/WireGuard переводит модем в `MODEM_SUBNET_CONFLICT`;
- одинаковые management-подсети через per-modem network namespaces рассматриваются после MVP.

Default ranking путей лексикографический: сначала `modem.priority`, затем `subscription.priority`, затем стабильность/latency node. Следовательно, сначала проверяются другие qualified nodes и subscriptions на предпочтительном модеме, затем следующий модем. В будущем допускается альтернативная policy `subscription-first`, но она не входит в MVP.

### 4.4 Keenetic

- WAN Keenetic подключён к `lan_keenetic` Gateway;
- WAN mode: DHCP client;
- WAN IP желательно закрепить по MAC;
- gateway и DNS: `192.168.200.1`;
- домашняя LAN: `192.168.50.0/24`;
- NAT Keenetic остаётся включённым;
- IPv6 Internet/WAN для этого подключения выключен в MVP;
- другие активные WAN/default routes на Keenetic запрещены, иначе они создадут обход fail-closed Gateway.

Gateway видит пользовательский трафик как трафик WAN-адреса Keenetic. Учёт по отдельным домашним устройствам в MVP невозможен и не заявляется.

Keenetic может оставить link-local IPv6 или ULA внутри домашней LAN, если они не дают глобального IPv6 default route. Критерий безопасности — отсутствие глобального IPv6 prefix и выхода в интернет, а не обязательное исчезновение локального IPv6 со всех домашних устройств.

---

## 5. HiLink Modem Manager

### 5.1 Обязанности

- обнаруживать любое количество поддерживаемых HiLink USB-Ethernet устройств;
- сопоставлять hot-plug interface с сохранённым `modem_id`;
- хранить offline-модемы, пользовательское имя, оператора, enabled и priority;
- получать отдельные DHCP lease, gateway, DNS и MTU;
- назначать каждому модему стабильные fwmark/routing table;
- определять Web UI/API address по конкретному lease;
- проверять USB carrier, DHCP, management API и whitelist transport отдельно для каждого модема;
- опционально получать SIM status, registration, operator, signal и network type;
- обнаруживать пересечение management subnet до установки routes;
- выполнять независимый recovery с per-modem cooldown;
- публиковать observed state, не выбирая active path самостоятельно.

### 5.2 Устойчивая идентичность и adoption

Linux interface name не является идентификатором модема. Сопоставление выполняется в порядке надёжности:

1. serial устройства из HiLink API, сохранённый как salted hash и masked display;
2. USB serial (`ID_SERIAL_SHORT`);
3. стабильный MAC USB-Ethernet interface;
4. USB topology path как последний fallback.

Первое неизвестное устройство получает discovery ID и появляется во вкладке **Модемы** как `UNADOPTED`. При adoption ему назначаются постоянные `modem_id` и человекочитаемый `display_number` (`Модем 1`, `Модем 2`, …), который не зависит от USB port и priority и автоматически не переиспользуется. Администратор задаёт имя, подпись оператора и priority. Фактический operator из HiLink telemetry хранится отдельно и может отличаться при замене SIM. Если identity неоднозначна, устройство не перехватывает настройки отсутствующего модема автоматически. Операции:

- **Adopt** — добавить обнаруженный modem в конфигурацию;
- **Disable** — сохранить modem, но не использовать routes/probes;
- **Forget** — удалить только offline modem после подтверждения;
- **Replace identity** — привязать новое устройство к старому logical modem с audit event.

### 5.3 Состояния одного модема

```text
MODEM_UNADOPTED
MODEM_CONFIGURED_OFFLINE
  → MODEM_DISCOVERED
  → MODEM_LINK_UP
  → MODEM_CONFIGURING
  → MODEM_REGISTERING
  → MODEM_RESTRICTED
  → MODEM_READY

Любое состояние → MODEM_RECOVERING → MODEM_CONFIGURING
Любое состояние → MODEM_SUBNET_CONFLICT
Любое состояние → MODEM_ERROR
Любое состояние → MODEM_DISABLED
```

`MODEM_READY` означает, что через этот uplink доступны служебные endpoints хотя бы для начала path qualification. Доступность глобального интернета определяется не самим modem state, а ячейкой `модем × подписка`.

### 5.4 Hot-plug и recovery

При disconnect:

1. udev/link event немедленно помечает modem offline;
2. routes/table этого modem удаляются или переводятся в unreachable;
3. все связанные path cells получают `MODEM_OFFLINE`;
4. если modem был активным, failover выбирает уже квалифицированный path другого modem;
5. сохранённая конфигурация, priority и history не удаляются.

При reconnect identity сопоставляется с `modem_id`, DHCP и routes восстанавливаются, но modem не становится eligible немедленно. Изменение interface/lease/gateway/table увеличивает `route_generation`, поэтому результаты прежнего подключения становятся `STALE`. Modem обязан пройти success threshold и фоновую requalification приоритетных подписок. Автоматический failback разрешён только после `modem_stable_seconds`.

Recovery ladder выполняется независимо для каждого модема:

1. перечитать carrier и route;
2. обновить DHCP lease;
3. повторить запрос HiLink API;
4. переподключить mobile session через API, если операция поддерживается прошивкой;
5. выполнить controlled USB rebind/reset;
6. перейти в `MODEM_ERROR` и прекратить частые перезапуски.

Для шагов 4–5 обязательны cooldown, event log и ручная кнопка восстановления.

### 5.5 Конфигурация

```yaml
modems:
  auto_discover: true
  require_unique_management_subnets: true
  routing_table_start: 1101
  fwmark_start: 0x1101
  modem_stable_seconds: 180
  reconnect_failback_seconds: 300

  supported_usb:
    - vendor_id: "12d1"
      product_ids: []

  recovery_defaults:
    dhcp_renew_after_seconds: 30
    reconnect_after_seconds: 90
    usb_reset_after_seconds: 300
    usb_reset_cooldown_seconds: 900
```

Mutable modem records, priorities, operator labels, identity и secret refs находятся в SQLite. HiLink password каждого модема хранится отдельным secret file. HiLink API является firmware-dependent: отказ API не останавливает конкретный uplink, если DHCP и transport исправны.

UI показывает для каждого модема три независимых уровня:

- **Connectivity:** USB carrier, DHCP lease, gateway и доступность VPN transport;
- **Telemetry:** доступность HiLink API, SIM/operator/signal/network type.
- **Paths:** состояния всех `subscription × modem` combinations.

Например, при неработающем API и исправном uplink отображается `Connected; telemetry unavailable`, а не `Modem failed`. `MODEM_READY` не требует работоспособности telemetry API.

---

## 6. Mihomo data plane

### 6.1 Базовое решение

- ровно один процесс Mihomo;
- один TUN `gateway-vpn-tun`;
- для каждой enabled пары `subscription × modem` генерируется локальный provider path;
- proxy definitions пары получают modem-specific `interface-name` и `routing-mark`;
- provider path хранит все нормализованные candidate nodes подписки с уникальным modem prefix;
- выбор узла выполняется управляемой `select`-группой на path;
- одна верхнеуровневая группа определяет активный path `(modem, subscription, node)`;
- контроллер использует только локальный Mihomo API;
- внешний controller bind — только `127.0.0.1` и с secret.

### 6.2 Схема групп

```text
subscription A normalized nodes
  ├─→ provider_A_M1 [interface=M1, mark=M1] ─→ path_A_M1 (select)
  ├─→ provider_A_M2 [interface=M2, mark=M2] ─→ path_A_M2 (select)
  └─→ provider_A_MN [interface=MN, mark=MN] ─→ path_A_MN (select)

subscription B normalized nodes
  ├─→ provider_B_M1 [interface=M1, mark=M1] ─→ path_B_M1 (select)
  └─→ provider_B_M2 [interface=M2, mark=M2] ─→ path_B_M2 (select)

group_gateway_active:
  controlled select over all enabled path groups
```

Mihomo поддерживает `interface-name` и `routing-mark` на proxy node; provider override используется для привязки одной подписки к разным модемам. Имена имеют формат, не раскрывающий secrets: `m_<short-id>/s_<short-id>/<normalized-node>`.

Размер generated config растёт примерно как `enabled modems × enabled subscriptions × candidate nodes`. До apply генератор считает количество proxy instances и ожидаемый размер config; превышение hardware-profile soft limit выдаёт предупреждение, hard limit отклоняет transaction до изменения LKG. Конкретные limits фиксируются load test на этапе 0/3. Offline, но enabled modem сохраняет path state в БД, однако его provider может быть исключён из runtime config до reconnect и добавлен одной полной конфигурационной transaction.

Приоритеты modem/subscription и список квалифицированных path nodes хранит приложение. Встроенный `url-test` с одним URL не определяет пригодность для обхода. Gateway выбирает в path group только node со свежим `BYPASS_QUALIFIED` именно для этого modem, переключает path через локальный API Mihomo и подтверждает end-to-end probe. Квалификация того же node через другой modem является независимым результатом. До явного выбора контроллера `PATH_ACTIVE` не устанавливается.

### 6.3 TUN requirements

Минимальные свойства генерируемой конфигурации:

```yaml
ipv6: false
mode: rule
allow-lan: false
log-level: warning

external-controller: 127.0.0.1:9090
secret: "${MIHOMO_API_SECRET}"

tun:
  enable: true
  device: gateway-vpn-tun
  stack: mixed
  auto-route: true
  auto-redirect: true
  strict-route: true
  auto-detect-interface: false
  include-interface:
    - "${LAN_INTERFACE}"
  dns-hijack:
    - any:53
    - tcp://any:53
```

Точный рабочий конфиг фиксируется только после этапа 0. Нельзя считать наличие `port` или `socks-port` прозрачной маршрутизацией.

`stack: mixed` является выбранным значением по умолчанию, но не слепой константой. На этапе 0 он должен пройти TCP, UDP, QUIC, DNS, MTU и endurance smoke tests. `system` используется как fallback при проблемах с UDP/gVisor или лишнем расходе памяти; полный `gvisor` рассматривается только при обоснованной потребности в дополнительной userspace-изоляции. Принятый stack записывается в hardware profile стенда.

### 6.4 DNS

- `dnsmasq` слушает `192.168.200.1:53` и обслуживает DHCP;
- пользовательские DNS-запросы передаются во внутренний DNS Mihomo;
- DNS upstream для пользователей идёт через активную VPN-группу;
- bootstrap DNS для имён VPN-нод выполняется через DNS и routing context конкретного проверяемого модема;
- запросы LAN к стороннему TCP/UDP 53 перехватываются или блокируются;
- IPv6 DNS и DoT direct блокируются в MVP;
- политика DoH внутри пользовательского HTTPS-трафика определяется VPN и не считается leak.

### 6.5 Конфигурационный transaction

1. скачать подписку во временный файл;
2. проверить размер, формат и ограничения безопасности;
3. преобразовать в нормализованный subscription payload;
4. сгенерировать provider/group для каждой enabled пары subscription × modem;
5. применить per-modem interface/mark overrides и проверить уникальность proxy names;
6. выполнить `mihomo -t`;
7. атомарно сохранить candidate и предыдущий LKG;
8. reload/restart Mihomo;
9. проверить локальный API, TUN и route mark каждого online modem;
10. квалифицировать path matrix в фоне, сохраняя текущий LKG path;
11. при ошибке восстановить LKG;
12. только после успешной проверки отметить generation активной.

### 6.6 Systemd и права

- отдельный пользователь `gateway-vpn-mihomo`;
- только необходимые capabilities для TUN/network setup;
- `NoNewPrivileges=true`;
- `ProtectSystem=strict`;
- `ProtectHome=true`;
- writable paths ограничены каталогом Mihomo;
- memory/CPU limits являются защитой от аварии, а не способом штатного управления;
- бинарник и версия Mihomo фиксируются release manifest.

### 6.7 Политика версий Mihomo

- каждый release Gateway закрепляет одну точную версию Mihomo и SHA-256 бинарника;
- диапазон версий и автоматическое использование `latest` не поддерживаются;
- встроенный Mihomo `/upgrade` отключён и не выставляется в Web UI;
- manifest содержит версию core, платформу, hash, config schema generation и ожидаемый API contract;
- перед обновлением выполняются `mihomo -t`, `/version`, `/connections`, `/traffic`, provider health-check и TUN smoke tests;
- breaking change конфигурации или API блокирует обновление до появления адаптера и migration tests;
- предыдущий проверенный binary сохраняется для rollback.

---

## 7. Subscription Manager

### 7.1 Поддерживаемые входы

MVP должен иметь проверенную compatibility matrix:

- Clash/Mihomo YAML с массивом `proxies`;
- Base64 subscription со списком URI;
- plain text URI list;
- локальная загрузка файла для bootstrap;
- конкретные протоколы и поля подтверждаются реальными образцами HAPP-подписок.

Полный удалённый Mihomo config не исполняется. Из него извлекаются только разрешённые proxy definitions.

### 7.2 Модель подписки

```yaml
subscription:
  id: uuid
  name: VUSH Mobile
  source_type: url       # url | upload
  source_url: secret-ref
  enabled: true
  priority: 10
  auto_refresh: true
  refresh_interval: 3600
  status: healthy        # unknown | healthy | degraded | failed | disabled
  active_version_id: uuid
  nodes_total: 15
  nodes_candidates: 3
  modem_paths_total: 2
  modem_paths_qualified: 1
  policy_generation: 7
```

`subscription.status` — только агрегат для списка: `healthy`, если существует свежая qualified cell; `degraded`, если часть ready-модемов failed/stale; `failed`, если ни одна cell через ready-модем не qualified; `unavailable`, если нет ready-модемов. Решение о переключении всегда принимает path matrix, а не этот агрегат.

### 7.3 Безопасность загрузки

- HTTPS по умолчанию;
- запрет `file:`, `ftp:` и произвольных схем;
- redirects ограничены;
- request timeout и response size limit;
- защита от DNS rebinding и SSRF к loopback, link-local, management и home subnets;
- приватные URL разрешаются только явной настройкой;
- URL и токены маскируются в API, UI и логах;
- credentials хранятся в secret files с mode `0600`;
- provider/node names получают prefix subscription ID для исключения коллизий;
- неизвестные или опасные поля отклоняются;
- обновление никогда не удаляет текущий LKG до подтверждения нового.

### 7.4 Refresh policy

- interval + random jitter;
- conditional HTTP requests через ETag/Last-Modified;
- exponential backoff;
- ручной refresh не запускает второй параллельный refresh;
- после появления активного VPN обновление может идти через него;
- истечение подписки и ошибка сети являются разными событиями.

### 7.5 Отбор bypass-кандидатов по имени

Имя узла используется только для формирования пула кандидатов, но не считается доказательством работоспособности. Перед сравнением применяется Unicode NFKC normalization, trim и case-insensitive matching.

Начальный набор matchers:

```yaml
node_matchers:
  - pattern: "обход"
    type: substring
    priority: 10
  - pattern: "lte"
    type: substring
    priority: 20
  - pattern: "white list"
    type: substring
    priority: 30
  - pattern: "whitelist"
    type: substring
    priority: 40
  - pattern: "белый список"
    type: substring
    priority: 50
  - pattern: "белые списки"
    type: substring
    priority: 60
```

Match-политика и порядок:

1. исключить disabled и вручную запрещённые узлы;
2. применить ручные include/exclude overrides;
3. найти узлы, совпавшие хотя бы с одним enabled matcher;
4. если совпадения есть — candidate pool состоит только из совпавших и manual-include узлов;
5. если совпадений нет — candidate pool состоит из всех оставшихся узлов подписки;
6. каждый candidate обязан пройти bypass target probes;
7. узлы вне candidate pool получают состояние `NAME_FILTERED`, но сохраняются в inventory.

Если совпавшие по имени узлы существуют, но ни один не прошёл проверки, автоматический fallback к остальным узлам по умолчанию не выполняется. Опциональная настройка подписки `fallback_when_named_candidates_fail` может разрешить второй полный проход, но выключена по умолчанию. UI показывает preview совпадений до сохранения. Manual override переносится на новую версию подписки только при совпадении стабильного node fingerprint; неоднозначные совпадения требуют повторного подтверждения.

Regex mode использует Go `regexp` с RE2-семантикой и линейным временем выполнения, а не backtracking engine. Разрешены anchors (`^`, `$`), character classes, alternation и bounded/unbounded repetition. Lookahead, lookbehind и backreferences не поддерживаются самим движком. Дополнительные ограничения MVP:

- pattern не длиннее 256 UTF-8 bytes;
- normalized node name не длиннее 512 UTF-8 bytes;
- не более 32 enabled regex matchers; остальные matchers могут быть substring;
- pattern компилируется при сохранении, invalid expression отклоняется;
- regex применяется только к имени node, не к полному proxy config;
- preview обязателен перед сохранением regex из Web UI.

### 7.6 Probe targets для проверки обхода

Пользователь может через Web UI добавить, изменить, выключить, удалить и переупорядочить любое практическое количество сайтов/доменов. Малый фиксированный лимит бизнес-логикой не задаётся; scheduler ограничивает только параллелизм и частоту запросов.

```yaml
probe_target:
  id: uuid
  name: YouTube
  kind: domain              # domain | url
  value: youtube.com
  normalized_url: https://youtube.com/
  enabled: true
  required: true
  priority: 10
  timeout_seconds: 8
  success_mode: any_http_response
  expected_status: ""       # optional: 200-399, 204, 200/302
  expected_body_substring: "" # optional
```

Правила:

- domain нормализуется в HTTPS URL; для стабильной проверки предпочтителен явный URL;
- priority уникален среди enabled targets и определяет порядок проверки, как у подписок; он не отменяет требование пройти каждый `required=true` target;
- все `required=true` targets должны пройти для состояния `BYPASS_QUALIFIED`;
- optional target failure отображается в UI, но не дисквалифицирует узел;
- проверка `any_http_response` успешна при завершённых DNS/TCP/TLS и валидном HTTP response, включая `403`, который доказывает сетевую достижимость;
- при заданных `expected_status` или content marker применяется строгая проверка;
- должен существовать хотя бы один enabled required target; иначе состояние `NO_BYPASS_TARGETS`, автоматическая активация запрещена;
- URL targets проходят ту же нормализацию, timeout, size limit и SSRF-защиту, что subscription URLs;
- credentials в probe URL запрещены.

### 7.7 Квалификация и выбор узла

```text
Subscription refresh
  → normalize all nodes
  → build candidate pool by name matchers
  → for each enabled/online modem create a path context
  → probe each (modem, candidate node) against required targets
  → BYPASS_QUALIFIED / BYPASS_FAILED / UNTESTED per path node
  → select best qualified (modem, subscription, node)
  → verify active path
```

- сначала выполняется дешёвый transport probe, затем bypass targets в порядке priority;
- required failure прекращает оставшиеся probes этого узла по fail-fast policy;
- probes идут через конкретный node и конкретный modem routing context, а не просто через active subscription group;
- preferred backend — адресный Mihomo provider-node health-check с произвольным URL;
- на этапе 0 проверяется, достаточно ли API закреплённой версии для `expected_status/content`; если нет, используется выделенный loopback probe inbound и сериализованная controlled select-группа;
- concurrency, per-modem/per-host rate, jitter и cache TTL ограничивают матрицу `modems × subscriptions × candidate nodes × targets`;
- при равном результате выбирается узел с меньшей latency и более длинной непрерывной успешной историей;
- active path node проверяется чаще standby path nodes;
- обновлённая подписка не заменяет LKG, пока хотя бы одна enabled modem combination не получила `BYPASS_QUALIFIED`;
- ручной выбор не позволяет активировать `BYPASS_FAILED` или stale node без отдельного аварийного override с предупреждением и event log.

`BYPASS_QUALIFIED` всегда имеет scope `(modem_id, subscription_id, node_id, policy_generation, route_generation)`. Успех node через Operator A ничего не говорит о доступности того же node через Operator B; смена DHCP gateway/interface того же модема также требует подтверждения нового routing context.

---

## 8. Firewall и fail-closed

### 8.1 Общая политика

Boot-time ruleset загружается независимо от `gateway-vpn` и Mihomo:

- `input`: drop;
- `forward`: drop;
- `output`: drop с явными служебными исключениями;
- одна таблица семейства `inet` применяется к IPv4 и IPv6 filter paths; отдельная `ip6`-таблица для тех же filter hooks не требуется;
- IPv6 отключается на всех `uplink_hilink_<id>`, `lan_keenetic` и по умолчанию для новых интерфейсов через sysctl;
- `net.ipv6.conf.all.forwarding=0`, Router Advertisements и DHCPv6 не создают маршрут через Gateway;
- nftables остаётся вторым уровнем защиты и отбрасывает IPv6 в `input`, `forward` и `output` даже при ошибке sysctl;
- UFW/firewalld и сторонние ruleset managers обнаруживаются как конфликт установки.

Базовый IPv6 sysctl profile MVP:

```ini
net.ipv6.conf.all.disable_ipv6=1
net.ipv6.conf.default.disable_ipv6=1
net.ipv6.conf.all.forwarding=0
```

Installer применяет профиль до поднятия LAN services и проверяет фактические значения для уже существующих и вновь появившихся интерфейсов.

### 8.2 Разрешённые пути

| Источник | Назначение | Условие |
|---|---|---|
| LAN | DHCP/DNS Gateway | только `lan_keenetic` |
| LAN | Mihomo TUN | только подтверждённый transparent path |
| LAN/WG | HTTPS API | только management CIDR/interface |
| WG | SSH Gateway | опционально и только admin peers |
| Gateway | HiLink Web/API | только management address конкретного modem/interface |
| Mihomo | proxy endpoints | modem-specific interface + fwmark + route table |
| WireGuard | VPS endpoint UDP | через выбранный management modem, независимо от VPN path |
| Gateway | subscription/bootstrap endpoints | выбранный modem context или active VPN path |
| Gateway | NTP/bootstrap DNS | только настроенные endpoints и modem context |

Явно запрещено:

```text
lan_keenetic → uplink_hilink_* direct
lan_keenetic → wg_management
Internet/любой HiLink → Gateway input
LAN → Mihomo controller port
LAN → arbitrary DNS through любой HiLink
```

### 8.3 Dynamic nftables sets

Контроллер атомарно поддерживает:

- `hilink_interfaces`;
- `hilink_management_v4` с привязкой к `modem_id/interface`;
- `mihomo_endpoint_v4` с modem-specific marks;
- `wireguard_endpoint_v4` с candidate management-modem marks;
- `bootstrap_dns_v4`;
- `bootstrap_http_v4`;
- `admin_wg_v4`.

Обновление sets не заменяет весь ruleset и не создаёт временное окно direct access.

### 8.4 PATH_STATE

```text
PATH_BLOCKED
  Пользовательский forward запрещён.
  HiLink management и WireGuard bootstrap разрешены.

PATH_VERIFYING
  Mihomo поднят; разрешён только внутренний probe.

PATH_ACTIVE
  LAN направляется в подтверждённый TUN path.

PATH_DEGRADED
  Существующий путь работает частично; идёт проверка кандидата.
```

Приложение не устанавливает `PATH_ACTIVE`, пока end-to-end probe через выбранный tuple `(modem, subscription, node)` не успешен.

### 8.5 Инварианты

- остановка `gateway-vpn` не удаляет firewall;
- падение Mihomo прекращает новый пользовательский трафик;
- reboot сначала загружает `PATH_BLOCKED`;
- отсутствие SQLite или ошибочная миграция не открывает direct path;
- management exception каждого modem не включает всю его подсеть без необходимости;
- удаление/падение одного modem не меняет routes и marks остальных модемов;
- forwarded LAN packet без выбранного TUN path никогда не попадает в main/default route любого modem.

### 8.6 Контроль целостности firewall

- небольшой привилегированный `gateway-vpn-firewall-guard.service` проверяет наличие таблицы, chains, generation marker и критических drop rules;
- guard использует `nft monitor` плюс периодическую сверку, не полагаясь только на основной Go-процесс;
- при исчезновении owned ruleset guard сначала переводит `lan_keenetic` в quarantine/link-down, затем восстанавливает проверенный ruleset;
- LAN возвращается только после повторной проверки TUN path;
- удаление owned Gateway VPN table и случайный `nft flush ruleset` входят в integration tests;
- злоумышленник с root-доступом находится вне threat model: root способен отключить и nftables, и guard. Защита предназначена от сбоя, конфликтующего сервиса и административной ошибки.

---

## 9. Health, failover и reconciliation

### 9.1 Уровни здоровья

| Уровень | Пример проверки | Влияние |
|---|---|---|
| Modem USB link | interface/carrier конкретного modem | recovery этого modem |
| Modem HiLink | DHCP, gateway, Web/API, registration | modem state |
| Modem whitelist transport | разрешённые endpoints через modem mark/table | eligibility modem paths |
| Mihomo process | PID, API, TUN, config version | restart/rollback |
| Path node transport | конкретный proxy через конкретный modem | path-node eligibility |
| Path node bypass | modem × subscription × node × required targets | `BYPASS_QUALIFIED` |
| Modem/subscription cell | хотя бы один qualified path node | path matrix status |
| Probe target | результат через независимые modems/subscriptions | target outage suppression |
| Global VPN | required targets через active path | PATH_ACTIVE |
| Management | latest WireGuard handshake | alert only |

ICMP ping не является основной проверкой proxy node. Совпадение имени с `обход`/`lte`/whitelist также не является health result: такой узел обязан пройти configured required targets.

### 9.2 Probe policy

- отдельный лёгкий transport endpoint плюс минимум один пользовательский required bypass target;
- targets выполняются в пользовательском порядке priority;
- ожидаемый HTTP status/body применяется, если настроен; иначе достаточно валидного HTTP response;
- timeout и latency записываются отдельно;
- probes выполняются строго через конкретный proxy и modem mark/table;
- direct probe используется только для диагностики whitelist transport;
- интервалы имеют jitter;
- standby checks выполняются реже и с ограничением concurrency;
- scheduler ограничивает concurrency, per-target rate и общий probe traffic budget;
- результаты имеют TTL; stale result не используется для нового переключения;
- health-check не должен создавать заметный мобильный трафик.

Начальные значения budget, уточняемые на этапе 0:

```yaml
probe_budget:
  max_concurrency: 4
  max_concurrency_per_modem: 2
  max_requests_per_minute: 30
  active_target_interval_seconds: 60
  standby_target_ttl_seconds: 900
  max_response_body_bytes: 65536
  daily_soft_limit_mb_per_modem: 25
  active_and_failover_reserve_percent: 30
```

При исчерпании soft budget конкретного модема откладываются его standby requalification probes и получают состояние `DEFERRED_BUDGET`, а не `FAILED`. Проверки active path и кандидата на failover используют зарезервированную долю; после её исчерпания critical probes могут превысить soft limit с отдельным warning event, потому что budget не должен отключать контроль active path. `max_requests_per_minute`, global/per-modem concurrency и response-size limit остаются hard limits. UI показывает requests/bytes отдельно по модемам, overage, отложенные probes и прогноз времени полной матрицы. Изменение budget не меняет прошлые health results.

Если один required target одновременно перестал работать через текущий path и несколько независимых комбинаций разных модемов/подписок, он получает `TARGET_SUSPECT`. Такой общий сбой не запускает бесконечное переключение paths: текущий путь остаётся `DEGRADED_TARGET`, остальные targets продолжают проверяться, а UI показывает отдельную проблему сайта. Target автоматически возвращается в normal policy только после success threshold либо ручного подтверждения. Если независимых путей недостаточно, применяется строгая политика и target не подавляется автоматически.

### 9.3 Матрица modem × subscription

Каждая ячейка является одной сущностью и содержит:

```yaml
path_cell:
  modem_id: modem-a
  subscription_id: sub-1
  state: qualified
  transport_state: passed
  candidate_nodes: 3
  qualified_nodes: 2
  selected_node_id: node-x
  required_targets_passed: 3
  required_targets_total: 3
  latency_ms: 148
  last_checked_at: 2026-08-23T10:00:00Z
  expires_at: 2026-08-23T10:15:00Z
  policy_generation: 7
  route_generation: 12
```

Состояния ячейки:

```text
MODEM_OFFLINE
MODEM_DISABLED
SUBNET_CONFLICT
SUBSCRIPTION_DISABLED
UNTESTED
PROBING
QUALIFIED
DEGRADED
FAILED
STALE
DEFERRED_BUDGET
```

Семантика результата:

- `QUALIFIED` — хотя бы одна candidate node через этот modem прошла proxy transport и все enabled `required` targets текущей policy generation;
- `DEGRADED` — активный transport ещё работает, но часть optional checks failed либо идёт подтверждение подозрительного общего target outage;
- `FAILED` — проверка завершена и ни одна candidate node не удовлетворяет required policy;
- `STALE` — исторический успех существует, но TTL/policy/route generation изменились; для нового переключения он запрещён;
- offline/disabled/conflict states не запускают probes и не превращаются в subscription failure.

Конечный список probes не может доказать доступность буквально всего Интернета. Поэтому UI использует точную формулировку **«Доступ подтверждён: N/N обязательных ресурсов»**, отдельно показывает transport state и не пишет «весь Интернет работает». Именно этот операционный статус отображается для каждой подписки через каждый модем и для каждого модема через каждую подписку.

Матрица показывается в двух представлениях без дублирования данных:

- **Subscriptions → Modems:** для выбранной подписки видны статусы через каждый modem;
- **Modems → Subscriptions:** для выбранного modem видны статусы каждой подписки;
- **Path Matrix:** общая таблица, фильтры и принудительная перепроверка ячейки.

### 9.4 Состояние Gateway

```text
BOOTING
  → ALL_MODEMS_OFFLINE
  → NO_BYPASS_TARGETS
  → NO_WORKING_SUBSCRIPTION
  → VERIFYING
  → ACTIVE
  → VERIFYING_POLICY
  → DEGRADED_TARGET
  → DEGRADED
  → SWITCHING
  → ACTIVE

Любое состояние → BLOCKED
```

Desired state хранится в SQLite. Observed state восстанавливается при старте из ОС, nftables, Mihomo и WireGuard. Reconciler идемпотентно сближает observed state с desired state.

### 9.5 Разделение причин отказа

- `ACTIVE_MODEM_DOWN`: немедленно исключить все его paths и выбрать qualified path другого modem;
- `MODEM_DOWN`: не переключать подписки внутри offline modem; восстанавливать только этот HiLink;
- `ALL_MODEMS_OFFLINE`: PATH_BLOCKED, но desired state и priorities сохраняются;
- `MIHOMO_DOWN`: перезапустить Mihomo с LKG;
- `ACTIVE_NODE_DOWN`: выбрать другой qualified node той же modem/subscription cell;
- `ACTIVE_CELL_DOWN`: выбрать следующую subscription на том же modem, затем следующий modem;
- `ACTIVE_SUBSCRIPTION_DOWN`: агрегированный UI status; решение принимается по path cells, а не глобально;
- `REQUIRED_TARGET_DOWN`: подтвердить через другие узлы; различить node failure и `TARGET_SUSPECT`;
- `NO_BYPASS_TARGETS`: оставить PATH_BLOCKED и запросить настройку targets;
- `GLOBAL_PROBE_DOWN` при здоровом node transport: пометить degraded и выполнить target matrix confirmation;
- `NO_SUBSCRIPTIONS`: оставить PATH_BLOCKED, сохранить WireGuard и показать причину.

### 9.6 Failover sequence

1. подтвердить отказ несколькими последовательными probes;
2. определить, исправен ли active modem;
3. выбрать другой qualified node текущей modem/subscription cell;
4. если его нет — выбрать следующую subscription по priority на текущем modem;
5. если qualified cell на нём нет — выбрать следующий online modem по priority;
6. перепроверить candidate tuple по required targets без открытия LAN path;
7. атомарно выбрать path group и применить соответствующие mark/table;
8. повторить end-to-end probe;
9. разрешить новые LAN flows;
10. записать event с modem/subscription/node before/after;
11. при ошибке попробовать следующий tuple;
12. если кандидатов нет — `PATH_BLOCKED`.

30-секундный drain перед переключением не используется. TCP-соединения не мигрируют между VPN-нодами. Старые соединения либо завершаются естественно, либо удаляются по отдельной аварийной политике.

### 9.7 Hysteresis

```yaml
health:
  failure_threshold: 3
  success_threshold: 2
  active_interval_seconds: 10
  standby_interval_seconds: 60
  timeout_seconds: 5
  jitter_percent: 20

failover:
  cooldown_seconds: 60
  failback_stable_seconds: 300
  failback_cooldown_seconds: 900
  modem_reconnect_stable_seconds: 180
```

Failback разрешён только после непрерывной стабильности всей preferred path cell. Вернувшийся modem сначала проходит `modem_reconnect_stable_seconds` и приоритетную requalification; одно его появление в USB не вызывает переключение.

### 9.8 Круглосуточный самоконтроль и bounded recovery

Эксплуатационная цель — `24/7 unattended operation` и максимально достижимая доступность. Формулировка «100% uptime» не является технической гарантией: программно невозможно устранить отключение питания, физический отказ Gateway/USB-хаба, одновременную недоступность всех операторов/VPS или повреждение оборудования. Любое заявленное uptime измеряется по журналу и monitoring interval, а не предполагается по наличию active systemd unit.

Самоконтроль разделяет три класса состояния:

- `LOCAL_COMPONENT_FAILURE`: процесс, event loop, SQLite, firewall generation, broker, Mihomo/TUN, dnsmasq, disk/memory/FD pressure или внутренняя reconciliation loop неисправны;
- `EXTERNAL_CONNECTIVITY_FAILURE`: все модемы offline, mobile registration отсутствует, подписки/узлы/targets либо VPS недоступны при исправном локальном control plane;
- `MAINTENANCE_TRANSACTION`: install/update/restore/safe network apply выполняется или восстанавливается.

Лестница автоматического восстановления строго ограничена и журналируется:

1. повторить локальную проверку с failure threshold и jitter;
2. выполнить idempotent reconcile;
3. перевести data plane в `PATH_BLOCKED` до опасной мутации;
4. перезапустить только неисправный component в dependency order и проверить его readiness;
5. для Mihomo/config/update использовать LKG/transaction rollback;
6. если локальный критический дефект сохраняется, зафиксировать `CRITICAL_LOCAL` и оставить management plane доступным;
7. optional host reboot разрешён только явной настройкой, после непрерывного локального critical interval, вне любой maintenance transaction и в пределах durable reboot budget;
8. после исчерпания restart/reboot budget перейти в `RECOVERY_SUPPRESSED`, сохранить fail-closed и требовать operator action.

Обычная потеря глобального Интернета, `ALL_MODEMS_OFFLINE`, отсутствие working subscription/target или недоступность VPS **никогда сами по себе не перезагружают Gateway**: reboot не исправляет внешний outage и может создать destructive loop. Firewall guard и базовый systemd liveness watchdog не отключаются из Web UI. Hardware watchdog (`/dev/watchdog`) является отдельной optional advanced функцией и включается только после hardware preflight.

Изменяемая policy хранится в SQLite, валидируется server-side, имеет safe defaults, bounded ranges и audit history. Минимальный набор настроек:

```yaml
watchdog:
  enabled: true
  check_interval_seconds: 15
  failure_threshold: 3
  success_threshold: 2
  reconcile_enabled: true
  component_restart_enabled: true
  restart_cooldown_seconds: 30
  max_restarts_per_component: 5
  restart_window_seconds: 900
  host_reboot_enabled: false
  reboot_after_critical_seconds: 900
  max_reboots_per_24h: 1
  reboot_grace_seconds: 60
```

Настройка не разрешает arbitrary unit/command. Список компонентов, порядок restart, fixed executable/systemd unit names и признаки critical failure зашиты в signed release. Изменение policy не сбрасывает durable restart/reboot history. Web UI показывает effective policy, состояние каждого компонента, last success/failure/recovery, число попыток и причину suppression. Все автоматические actions попадают в events/journald и diagnostic bundle без secrets.

---

## 10. WireGuard management plane

### 10.1 Границы MVP

WireGuard предоставляет удалённый доступ к:

- Web UI/API Gateway на `10.80.0.2`;
- SSH Gateway, если функция включена;
- диагностике Gateway.

Маршрут в `192.168.200.0/24` или `192.168.50.0/24` на Gateway peer в MVP не добавляется.

### 10.2 Gateway

```ini
[Interface]
Address = 10.80.0.2/32
PrivateKey = <gateway-private-key>

[Peer]
PublicKey = <vps-public-key>
Endpoint = <vps-ip>:51821
AllowedIPs = 10.80.0.0/24
PersistentKeepalive = 25
```

WireGuard management использует собственный выбор uplink и не привязан к active VPN path. Для каждого online modem отдельно хранится `management_reachability_state`: `UNTESTED`, `PROBING`, `REACHABLE`, `BLOCKED` или `STALE`. По умолчанию выбирается modem с наименьшим значением priority среди `MODEM_READY`, для которых VPS endpoint подтверждён; если подтверждённых ещё нет, candidates пробуются последовательно по priority. Для IP-адреса VPS создаётся modem-specific host route в table выбранного модема; endpoint исключается из Mihomo TUN и пользовательского traffic accounting.

При disconnect management-модема контроллер:

1. сохраняет WireGuard interface и peer configuration;
2. атомарно переносит endpoint host route/rule на следующий `MODEM_READY` по priority;
3. удаляет старый route только после установки нового либо переводит его в `unreachable`;
4. ожидает восстановления handshake за счёт `PersistentKeepalive = 25`;
5. если handshake не восстановился за configured threshold, помечает candidate `BLOCKED` и пробует следующий modem;
6. пишет событие с previous/new `modem_id` и временем восстановления.

Отсутствие qualified subscription path не мешает выбору management-модема: для WireGuard достаточно доступности endpoint VPS через прямой служебный маршрут. При возвращении более приоритетного модема обратное переключение выполняется только после `modem_reconnect_stable_seconds`, чтобы не создавать flap. Если VPS endpoint задан hostname, DNS resolution выполняется отдельно через каждый eligible modem, а старый подтверждённый IP хранится до TTL/ошибки соединения.

### 10.3 VPS

```ini
[Interface]
Address = 10.80.0.1/24
ListenPort = 51821
PrivateKey = <vps-private-key>

[Peer]
# Gateway
PublicKey = <gateway-public-key>
AllowedIPs = 10.80.0.2/32

[Peer]
# Admin device
PublicKey = <admin-public-key>
AllowedIPs = 10.80.0.10/32
```

На VPS включается IPv4 forwarding только для management subnet и firewall rule `admin peers → 10.80.0.2` на разрешённые management ports.

`Address = 10.80.0.1/24` создаёт на VPS connected route `10.80.0.0/24 dev wg-mgmt`; отдельный статический маршрут для этой сети не нужен. `AllowedIPs = 10.80.0.2/32` и `10.80.0.10/32` выбирают конкретного peer и одновременно ограничивают допустимые source addresses. После поднятия интерфейса installer обязательно проверяет `ip route get 10.80.0.2`, `ip route get 10.80.0.10` и двусторонний forwarding.

### 10.4 Admin device

```ini
[Interface]
Address = 10.80.0.10/32
PrivateKey = <admin-private-key>

[Peer]
PublicKey = <vps-public-key>
Endpoint = <vps-ip>:51821
AllowedIPs = 10.80.0.1/32, 10.80.0.2/32
PersistentKeepalive = 25
```

### 10.5 Будущий доступ к Home LAN

Добавление `192.168.50.0/24` требует отдельного design/acceptance этапа:

- статический маршрут и firewall на Keenetic либо WireGuard peer на Keenetic;
- соответствующий `AllowedIPs` только у Gateway peer на VPS;
- правила forwarding без доступа к data plane;
- проверка обратного маршрута и отсутствия конфликтов подсетей.

---

## 11. Конфигурация и источник истины

### 11.1 Разделение хранения

| Данные | Хранилище |
|---|---|
| bootstrap paths, LAN bind interface, modem discovery defaults, DB path | `/etc/gateway-vpn/config.yaml` |
| изменяемые настройки | SQLite |
| пароли, токены, private keys | `/var/lib/gateway-vpn/secrets/*` |
| provider payloads и LKG | `/var/lib/gateway-vpn/subscriptions/*` |
| Mihomo configs и LKG | `/var/lib/gateway-vpn/mihomo/*` |
| события runtime | SQLite + journald |

YAML не дублирует изменяемые настройки Web UI. При конфликте bootstrap YAML определяет только способ открыть БД и базовые интерфейсы.

### 11.2 Bootstrap config

```yaml
version: 1

system:
  state_dir: /var/lib/gateway-vpn
  database: /var/lib/gateway-vpn/state.db
  log_level: INFO

network:
  lan_interface: enp2s0
  lan_address: 192.168.200.1/24
  ipv6_mode: disabled

modems:
  type: hilink
  auto_discover: true
  require_adoption: true
  require_unique_management_subnets: true
  routing_table_start: 1101
  fwmark_start: 0x1101

mihomo:
  binary: /opt/gateway-vpn/current/libexec/mihomo
  tun_name: gateway-vpn-tun
  api_address: 127.0.0.1:9090
  api_secret_file: /var/lib/gateway-vpn/secrets/mihomo-api-secret

api:
  listen:
    - 192.168.200.1:8443
    - 10.80.0.2:8443
  tls_cert: /var/lib/gateway-vpn/tls/cert.pem
  tls_key: /var/lib/gateway-vpn/tls/key.pem
```

---

## 12. База данных

### 12.1 SQLite policy

При каждом соединении:

```sql
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;
PRAGMA busy_timeout=5000;
PRAGMA synchronous=NORMAL;
```

Все изменения схемы выполняются versioned migrations в транзакции. Перед несовместимой миграцией создаётся backup.

### 12.2 Основные таблицы

```sql
CREATE TABLE subscriptions (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    source_type TEXT NOT NULL,
    source_secret_ref TEXT,
    enabled INTEGER NOT NULL DEFAULT 1,
    priority INTEGER NOT NULL,
    auto_refresh INTEGER NOT NULL DEFAULT 1,
    refresh_interval_seconds INTEGER NOT NULL DEFAULT 3600,
    fallback_when_named_candidates_fail INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'unknown',
    active_version_id TEXT,
    last_refresh_at TEXT,
    last_success_at TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE UNIQUE INDEX subscriptions_priority_enabled
ON subscriptions(priority) WHERE enabled = 1;

CREATE TABLE modems (
    id TEXT PRIMARY KEY,
    display_number INTEGER NOT NULL UNIQUE,
    name TEXT NOT NULL,
    operator_label TEXT,
    observed_operator TEXT,
    identity_kind TEXT NOT NULL,
    identity_hash TEXT NOT NULL,
    masked_serial TEXT,
    enabled INTEGER NOT NULL DEFAULT 1,
    priority INTEGER NOT NULL,
    interface_name TEXT,
    management_cidr TEXT,
    gateway TEXT,
    dns_json TEXT,
    mtu INTEGER,
    routing_table_id INTEGER NOT NULL UNIQUE,
    fwmark INTEGER NOT NULL UNIQUE,
    state TEXT NOT NULL DEFAULT 'configured_offline',
    telemetry_state TEXT NOT NULL DEFAULT 'unknown',
    management_reachability_state TEXT NOT NULL DEFAULT 'untested',
    last_seen_at TEXT,
    stable_since TEXT,
    api_secret_ref TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE UNIQUE INDEX modems_identity
ON modems(identity_kind, identity_hash);

CREATE UNIQUE INDEX modems_priority_enabled
ON modems(priority) WHERE enabled = 1;

CREATE TABLE subscription_versions (
    id TEXT PRIMARY KEY,
    subscription_id TEXT NOT NULL,
    content_sha256 TEXT NOT NULL,
    nodes_total INTEGER NOT NULL,
    state TEXT NOT NULL,
    error TEXT,
    created_at TEXT NOT NULL,
    activated_at TEXT,
    FOREIGN KEY(subscription_id) REFERENCES subscriptions(id) ON DELETE CASCADE
);

CREATE TABLE nodes (
    id TEXT PRIMARY KEY,
    version_id TEXT NOT NULL,
    external_name TEXT NOT NULL,
    normalized_name TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    proxy_type TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    selection_override TEXT NOT NULL DEFAULT 'auto', -- auto | include | exclude
    candidate_source TEXT NOT NULL DEFAULT 'unclassified',
    FOREIGN KEY(version_id) REFERENCES subscription_versions(id) ON DELETE CASCADE
);

CREATE UNIQUE INDEX nodes_version_fingerprint
ON nodes(version_id, fingerprint);

CREATE UNIQUE INDEX nodes_version_normalized_name
ON nodes(version_id, normalized_name);

CREATE TABLE node_matchers (
    id TEXT PRIMARY KEY,
    pattern TEXT NOT NULL,
    match_type TEXT NOT NULL,       -- substring | regex
    enabled INTEGER NOT NULL DEFAULT 1,
    priority INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE UNIQUE INDEX node_matchers_priority_enabled
ON node_matchers(priority) WHERE enabled = 1;

CREATE TABLE bypass_probe_targets (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    target_kind TEXT NOT NULL,      -- domain | url
    target_value TEXT NOT NULL,
    normalized_url TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    required INTEGER NOT NULL DEFAULT 1,
    priority INTEGER NOT NULL,
    timeout_seconds INTEGER NOT NULL DEFAULT 8,
    success_mode TEXT NOT NULL DEFAULT 'any_http_response',
    expected_status TEXT,
    expected_body_substring TEXT,
    state TEXT NOT NULL DEFAULT 'unknown',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE UNIQUE INDEX bypass_probe_targets_priority_enabled
ON bypass_probe_targets(priority) WHERE enabled = 1;

CREATE TABLE subscription_modem_paths (
    id TEXT PRIMARY KEY,
    modem_id TEXT NOT NULL,
    subscription_id TEXT NOT NULL,
    state TEXT NOT NULL DEFAULT 'untested',
    transport_state TEXT NOT NULL DEFAULT 'unknown',
    selected_node_id TEXT,
    candidate_nodes INTEGER NOT NULL DEFAULT 0,
    qualified_nodes INTEGER NOT NULL DEFAULT 0,
    required_targets_passed INTEGER NOT NULL DEFAULT 0,
    required_targets_total INTEGER NOT NULL DEFAULT 0,
    latency_ms INTEGER,
    policy_generation INTEGER NOT NULL DEFAULT 0,
    route_generation INTEGER NOT NULL DEFAULT 0,
    last_checked_at TEXT,
    expires_at TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(modem_id, subscription_id),
    FOREIGN KEY(modem_id) REFERENCES modems(id) ON DELETE CASCADE,
    FOREIGN KEY(subscription_id) REFERENCES subscriptions(id) ON DELETE CASCADE,
    FOREIGN KEY(selected_node_id) REFERENCES nodes(id) ON DELETE SET NULL
);

CREATE INDEX subscription_modem_paths_ranking
ON subscription_modem_paths(modem_id, subscription_id, state);

CREATE TABLE path_nodes (
    path_id TEXT NOT NULL,
    node_id TEXT NOT NULL,
    qualification_state TEXT NOT NULL DEFAULT 'untested',
    qualification_generation INTEGER NOT NULL DEFAULT 0,
    route_generation INTEGER NOT NULL DEFAULT 0,
    qualification_expires_at TEXT,
    latency_ms INTEGER,
    last_success_at TEXT,
    last_failure_at TEXT,
    failure_code TEXT,
    PRIMARY KEY(path_id, node_id),
    FOREIGN KEY(path_id) REFERENCES subscription_modem_paths(id) ON DELETE CASCADE,
    FOREIGN KEY(node_id) REFERENCES nodes(id) ON DELETE CASCADE
);

CREATE TABLE path_node_target_results (
    path_id TEXT NOT NULL,
    node_id TEXT NOT NULL,
    target_id TEXT NOT NULL,
    state TEXT NOT NULL,
    latency_ms INTEGER,
    http_status INTEGER,
    error_code TEXT,
    checked_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    policy_generation INTEGER NOT NULL,
    route_generation INTEGER NOT NULL,
    PRIMARY KEY(path_id, node_id, target_id),
    FOREIGN KEY(path_id, node_id) REFERENCES path_nodes(path_id, node_id) ON DELETE CASCADE,
    FOREIGN KEY(target_id) REFERENCES bypass_probe_targets(id) ON DELETE CASCADE
);

CREATE INDEX path_node_target_results_freshness
ON path_node_target_results(path_id, policy_generation, route_generation, expires_at);

CREATE TABLE runtime_state (
    singleton_id INTEGER PRIMARY KEY CHECK(singleton_id = 1),
    gateway_state TEXT NOT NULL,
    path_state TEXT NOT NULL,
    active_modem_id TEXT,
    active_path_id TEXT,
    management_modem_id TEXT,
    active_subscription_id TEXT,
    active_node_id TEXT,
    config_generation INTEGER NOT NULL DEFAULT 0,
    updated_at TEXT NOT NULL,
    FOREIGN KEY(active_modem_id) REFERENCES modems(id) ON DELETE SET NULL,
    FOREIGN KEY(active_path_id) REFERENCES subscription_modem_paths(id) ON DELETE SET NULL,
    FOREIGN KEY(management_modem_id) REFERENCES modems(id) ON DELETE SET NULL,
    FOREIGN KEY(active_subscription_id) REFERENCES subscriptions(id) ON DELETE SET NULL,
    FOREIGN KEY(active_node_id) REFERENCES nodes(id) ON DELETE SET NULL
);

CREATE TABLE events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    occurred_at TEXT NOT NULL,
    severity TEXT NOT NULL,
    type TEXT NOT NULL,
    modem_id TEXT,
    subscription_id TEXT,
    path_id TEXT,
    details_json TEXT NOT NULL
);

CREATE TABLE health_samples (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    measured_at TEXT NOT NULL,
    scope_type TEXT NOT NULL,
    scope_id TEXT,
    state TEXT NOT NULL,
    latency_ms INTEGER,
    error_code TEXT
);

CREATE TABLE traffic_daily_totals (
    date TEXT PRIMARY KEY,
    download_bytes INTEGER NOT NULL DEFAULT 0,
    upload_bytes INTEGER NOT NULL DEFAULT 0,
    mihomo_download_bytes INTEGER NOT NULL DEFAULT 0,
    mihomo_upload_bytes INTEGER NOT NULL DEFAULT 0,
    checkpointed_at TEXT NOT NULL
);

CREATE TABLE settings (
    key TEXT PRIMARY KEY,
    value_json TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
```

`nodes` хранит только subscription-level identity и классификацию кандидата. Health/latency/qualification не хранятся глобально в `nodes`: они принадлежат `path_nodes`, потому что одна node может быть доступна через modem A и недоступна через modem B. Аналогично target result всегда привязан к `path_id + node_id + target_id`.

`subscription_modem_paths` — единственный источник текущего состояния матрицы для API и всех UI-представлений. Приложение дополнительно валидирует, что `selected_node_id` относится к active version соответствующей subscription. Все foreign keys и индексы проверяются migration tests; удаление modem/subscription каскадно удаляет только производные path results, но операция Forget/Delete до commit создаёт audit event и требует подтверждения.

### 12.3 Retention

- raw health samples: 7 дней по умолчанию;
- events: 30 дней;
- daily traffic: 24 месяца либо без ограничения до ручной настройки;
- subscription versions: active LKG + предыдущие 2 успешные + последние 2 ошибочные;
- cleanup выполняется малыми транзакциями;
- `VACUUM` запускается только вручную или в maintenance window.

### 12.4 Power-loss и corruption recovery

- при каждом старте выполняется `PRAGMA quick_check`, а полный `integrity_check` — по расписанию и перед release update;
- WAL checkpoint выполняется периодически; принудительный `TRUNCATE` допускается только в maintenance operation;
- ежедневный backup создаётся через SQLite Online Backup API и проверяется перед ротацией предыдущего;
- перед migration, network apply и restore создаётся отдельный verified snapshot;
- при обнаружении corruption приложение прекращает запись, сохраняет повреждённые DB/WAL/SHM для диагностики и переводит data plane в безопасное состояние;
- затем автоматически пробуется последний backup, прошедший integrity check;
- если backup отсутствует или также повреждён, создаётся diagnostic event и остаётся `PATH_BLOCKED`; пустая БД автоматически поверх повреждённой не создаётся;
- после восстановления reconciler заново сверяет SQLite, Mihomo, nftables и observed network state до `PATH_ACTIVE`.

---

## 13. Traffic accounting

### 13.1 Метрики

- общий пользовательский RX/TX через VPN;
- текущая общая скорость;
- daily/monthly aggregation общего трафика;
- общий traffic за active session;
- служебный direct-трафик отдельно от пользовательского.

**Зафиксированное решение MVP — Option A:** per-subscription и per-proxy traffic attribution не предоставляется. UI и API не показывают приблизительные значения по подпискам. Такая детализация может быть добавлена после MVP отдельным этапом без изменения data plane.

### 13.2 Источники

- nftables counters в выбранной на этапе 0 точке LAN/TUN — authoritative общий пользовательский объём;
- Mihomo API `/traffic` — текущая скорость, process-scoped `upTotal/downTotal` и cross-check;
- WireGuard и HiLink management traffic не включаются в пользовательскую статистику.

Приложение периодически сохраняет delta nftables counters вместе с `boot_id` и `firewall_generation`. Сброс counter после reboot или замены ruleset начинает новую generation и никогда не вычитается из накопленного итога. Graceful shutdown выполняет финальный checkpoint; crash допускает только ограниченную потерю внутри последнего checkpoint interval.

Traffic spike на этапе 0 остаётся обязательным, но больше не выбирает между Option A/B. Он определяет точную точку подсчёта, исключение DHCP/DNS/management traffic, checkpoint interval, поведение counters при reload/reboot и допустимое расхождение nftables с Mihomo `/traffic`.

---

## 14. API и Web UI

### 14.1 API conventions

- prefix `/api/v1`;
- JSON error envelope с machine-readable code;
- OpenAPI specification хранится в репозитории;
- pagination для history/events/logs;
- timestamps — UTC RFC3339;
- destructive operations требуют подтверждения;
- асинхронные refresh/apply/restart возвращают operation ID;
- secrets никогда не возвращаются обратно клиенту.

### 14.2 Основные endpoints

```text
POST   /api/v1/auth/login
POST   /api/v1/auth/logout
GET    /api/v1/auth/session

GET    /api/v1/gateway/status
GET    /api/v1/gateway/diagnostics
POST   /api/v1/gateway/reconcile

GET    /api/v1/modems
GET    /api/v1/modems/discovered
POST   /api/v1/modems/{discovery_id}/adopt
GET    /api/v1/modems/{id}
PATCH  /api/v1/modems/{id}
DELETE /api/v1/modems/{id}
PUT    /api/v1/modems/priorities
POST   /api/v1/modems/{id}/recover
POST   /api/v1/modems/{id}/probe
POST   /api/v1/modems/{id}/replace-identity

GET    /api/v1/subscriptions
POST   /api/v1/subscriptions
GET    /api/v1/subscriptions/{id}
PATCH  /api/v1/subscriptions/{id}
DELETE /api/v1/subscriptions/{id}
POST   /api/v1/subscriptions/{id}/refresh
POST   /api/v1/subscriptions/{id}/probe
PUT    /api/v1/subscriptions/priorities

GET    /api/v1/nodes
PATCH  /api/v1/nodes/{id}
POST   /api/v1/nodes/{id}/probe       # modem_id обязателен в body
POST   /api/v1/nodes/{id}/qualify     # modem_id обязателен в body

GET    /api/v1/paths
GET    /api/v1/paths/matrix
GET    /api/v1/paths/{modem_id}/{subscription_id}
POST   /api/v1/paths/{modem_id}/{subscription_id}/probe
POST   /api/v1/paths/{modem_id}/{subscription_id}/activate

GET    /api/v1/node-matchers
POST   /api/v1/node-matchers
PATCH  /api/v1/node-matchers/{id}
DELETE /api/v1/node-matchers/{id}
PUT    /api/v1/node-matchers/priorities
POST   /api/v1/node-matchers/preview

GET    /api/v1/bypass-targets
POST   /api/v1/bypass-targets
GET    /api/v1/bypass-targets/{id}
PATCH  /api/v1/bypass-targets/{id}
DELETE /api/v1/bypass-targets/{id}
PUT    /api/v1/bypass-targets/priorities
POST   /api/v1/bypass-targets/{id}/probe

GET    /api/v1/health
GET    /api/v1/health/history
GET    /api/v1/health/supervisor
POST   /api/v1/health/supervisor/recover
GET    /api/v1/events

GET    /api/v1/traffic/current
GET    /api/v1/traffic/daily
GET    /api/v1/traffic/monthly
GET    /api/v1/traffic/export.csv

GET    /api/v1/settings
PATCH  /api/v1/settings
GET    /api/v1/settings/watchdog
PUT    /api/v1/settings/watchdog
POST   /api/v1/settings/network/apply
POST   /api/v1/settings/network/apply/{id}/confirm

GET    /api/v1/wireguard/status
POST   /api/v1/wireguard/configure

POST   /api/v1/system/backup
POST   /api/v1/system/restore
POST   /api/v1/system/reboot
```

`GET /paths/matrix` является каноническим read model для Dashboard, **Модемы**, **Подписки** и **Матрица путей**. Ответ содержит одну запись на пару `modem_id × subscription_id`, выбранную node, свежесть результата и объяснимый reason code. Frontend не вычисляет health самостоятельно.

Ручная активация path разрешена только при свежем `QUALIFIED` в текущих `policy_generation` и `route_generation`. Emergency override является отдельной привилегированной операцией с предупреждением, TTL, audit event и не разрешает direct path. Reorder modem/subscription priorities атомарен: сервер принимает полный упорядоченный список IDs и проверяет его на дубликаты/пропуски. Изменение порядка обновляет ranking generation, но не инвалидирует свежие probe results и не обрывает текущий path; новый порядок применяется при следующем failover, явной активации или штатном failback после hysteresis.

### 14.3 Web UI

Web UI разделяется по предметным областям; одна настройка имеет одного владельца и не дублируется на нескольких страницах:

1. **Обзор:** Gateway state, active tuple `модем → подписка → node`, причина последнего переключения, WireGuard, traffic и основные предупреждения.
2. **Модемы:** discovery/adoption, CRUD, enable, номер/priority, operator, hot-plug state, recovery и статусы всех подписок через выбранный модем.
3. **Подписки:** CRUD, номер/priority, refresh/LKG, masked URL, candidate counts и статусы подписки через каждый модем.
4. **Матрица путей:** полная таблица `модем × подписка`, фильтры, freshness, выбранная node, latency, reason code, manual probe/activate.
5. **Серверы проверки доступа:** ordered bypass targets (domain/URL) с CRUD, enable/required, timeout, условием успеха и приоритетом.
6. **Правила отбора серверов:** ordered node-name matchers, preview по подпискам, manual include/exclude и fallback policy.
7. **VPN-серверы:** исходное имя, подписка, candidate source, matched rule и раскрываемая матрица результатов по модемам/targets.
8. **Состояние и события:** modem/path/target health, timeline, target outages, probe budget и объяснение failover.
9. **Трафик:** current/daily/monthly total и CSV без ложной per-subscription детализации.
10. **Удалённый доступ:** VPS peer, выбранный management-модем, handshake и admin peers.
11. **Сеть:** transit LAN, DHCP/DNS, обнаруженные интерфейсы, routing tables/marks read-only и safe apply.
12. **Система и безопасность:** версии, update, backup/restore, users/sessions, TLS, diagnostic bundle и отдельная карточка **Самоконтроль 24/7** с component health, recovery history, bounded watchdog settings и предупреждением для optional reboot.

Вкладка **Модемы** использует такой же управляемый список, как **Подписки**: стабильный номер/имя, enabled и явный priority; priority не выводится из USB port или порядка обнаружения. Строка модема показывает configured/observed operator, interface, management subnet/gateway/DNS, routing table/fwmark, signal/registration, telemetry state, WireGuard endpoint reachability, `last_seen_at`, subnet conflict и компактные badges по всем subscriptions. Доступны Adopt, Disable/Enable, Probe, Recover, Replace identity и Forget; Forget разрешён только для offline-модема с подтверждением.

Вкладка **Подписки** показывает для каждой подписки отдельный status badge/колонку каждого модема: `QUALIFIED`, `FAILED`, `PROBING`, `MODEM_OFFLINE`, `STALE` и другие состояния ячейки. При большом числе модемов используется горизонтальная прокрутка/compact cards, а не скрытие колонок. Вкладка **Модемы** показывает ту же матрицу в обратной ориентации. Обе страницы получают данные из `subscription_modem_paths`; разные результаты между ними считаются ошибкой.

Матрица должна масштабироваться: server-side фильтры и pagination/virtualization для деталей nodes, lazy load target results, ограниченный fan-out ручной проверки и прогноз времени проверки очереди. Цвет никогда не является единственным признаком состояния — используются текст, icon и reason code. Offline-модем остаётся видимым вместе с конфигурацией и последними результатами, но просроченные результаты помечаются `STALE` и не используются для переключения.

Изменение matcher или target policy создаёт новую policy generation, сбрасывает затронутые qualification results в `UNTESTED` и запускает фоновую переоценку. Оно не обрывает текущий `PATH_ACTIVE` мгновенно:

1. Gateway переходит в `VERIFYING_POLICY`, сохраняя текущий node на grace period 120 секунд;
2. active node проверяется первым по новой policy generation;
3. если он проходит — результат закрепляется и `PATH_ACTIVE` продолжается без переключения;
4. если он не проходит — выбирается другой qualified candidate сначала в той же modem/subscription cell, затем в следующей subscription на этом modem, затем на следующем modem;
5. если до конца grace period подходящего узла нет — Gateway переходит в `PATH_BLOCKED`;
6. reboot во время незавершённой requalification начинает с `PATH_BLOCKED`, а не со старой policy generation.

Удаление последнего required target требует явного подтверждения и после grace period переводит автоматическую активацию в `NO_BYPASS_TARGETS`.

### 14.4 Safe network apply

1. API валидирует candidate и возвращает `apply_id`, одноразовый `confirm_token`, `old_url`, `new_url` и `rollback_deadline`;
2. предыдущая сеть, DHCP и firewall сохраняются в durable transaction directory;
3. независимый от основного процесса `gateway-vpn-network-rollback@<id>.timer` запускается до изменения сети;
4. новый адрес добавляется, а старый временно сохраняется как secondary address на grace period;
5. dnsmasq, API bind и firewall применяются в candidate generation;
6. UI предлагает открыть одноразовую confirmation page на `new_url`; альтернативно подтверждение принимается через `wg_management`;
7. `POST /api/v1/settings/network/apply/{id}/confirm` принимается только если запрос пришёл на новый local destination address либо через WireGuard;
8. после подтверждения старый адрес удаляется, transaction фиксируется, timer отменяется;
9. при timeout, падении `gateway-vpn` или reboot незавершённая transaction откатывается отдельным helper до штатного запуска DHCP/API.

Запрос через старый адрес не доказывает работоспособность новой сети и не подтверждает apply. При смене transit subnet Keenetic должен получить новый DHCP lease; пользователь вручную открывает `new_url`, поскольку browser security и self-signed TLS не позволяют надёжно выполнить cross-origin reconnect из старой страницы.

---

## 15. Безопасность

### 15.1 Аутентификация

- при установке генерируется случайный одноразовый bootstrap password;
- `admin/admin` запрещён;
- пароль хранится как Argon2id hash;
- браузер получает `Secure`, `HttpOnly`, `SameSite=Strict` session cookie;
- state-changing requests защищаются от CSRF;
- login имеет rate limit и progressive delay;
- сессии можно отозвать;
- неаутентифицированный status endpoint отсутствует по умолчанию.

### 15.2 TLS и bind

- API слушает только LAN и WireGuard addresses;
- порт по умолчанию `8443`;
- TLS обязателен;
- при первом запуске генерируется self-signed certificate с отображением fingerprint;
- позднее допускается пользовательский certificate;
- Mihomo controller слушает только loopback.

### 15.3 Секреты

- mode `0600`, владелец соответствующего service user;
- subscription URLs, WireGuard keys, passwords и API tokens не пишутся в логи;
- backup с секретами шифруется пользовательской passphrase;
- diagnostic bundle по умолчанию исключает secrets и полные subscription payloads;
- фиксированные service credentials по возможности передаются через systemd `LoadCredential=`/`LoadCredentialEncrypted=` и читаются из `$CREDENTIALS_DIRECTORY`;
- динамические subscription/HiLink secrets хранятся отдельными файлами и заменяются по схеме write → fsync → chmod/chown → atomic rename;
- ротация имеет validate/apply/rollback и не удаляет предыдущий secret до успешной проверки;
- приложение перечитывает динамический secret по `SIGHUP`/внутренней reload operation;
- WireGuard keys применяются через `wg syncconf`, а Mihomo API secret — согласованным reload контроллера и core;
- если конкретный credential загружается systemd только при старте unit, допускается controlled restart владельца: nftables и отдельный Mihomo data plane продолжают обеспечивать fail-closed.

### 15.4 Supply chain

- версии Gateway, Mihomo и Web UI фиксированы;
- release artifacts имеют SHA-256 и подпись/release provenance;
- installer не скачивает `latest` без manifest;
- обновление сначала загружается и проверяется, затем устанавливается атомарно;
- хранится предыдущая рабочая версия для rollback;
- `curl | bash` допускается только как bootstrap скачивания подписанного installer artifact, не как непрозрачный поток команд.

### 15.5 Threat model

Минимально рассматриваются:

- утечка direct-трафика при падении Mihomo;
- SSRF через subscription URL;
- вредоносный provider payload;
- захват Web UI из LAN;
- кража токена подписки из логов/backup;
- подмена binary/update;
- DNS leak и IPv6 leak;
- подмена/неоднозначное сопоставление modem identity после hot-plug;
- пересечение management subnets и route injection через DHCP модема;
- lockout при ошибке сетевых настроек;
- компрометация VPS management peer.

---

## 16. Логи, события и диагностика

### 16.1 Логирование

- приложение пишет structured logs в journald;
- типы: `system`, `modem`, `path`, `subscription`, `mihomo`, `health`, `failover`, `firewall`, `wireguard`, `auth`;
- повторяющиеся health failures агрегируются;
- ни одно поле не содержит credentials или полный URL подписки;
- log level изменяется без рестарта;
- journal retention настраивается установщиком.

Настройки находятся в **Система и безопасность → Логирование** и имеют одного владельца в SQLite:

- общий уровень и отдельный уровень для `system`, `modem`, `path/health`, `subscription`, `mihomo`, `routing/firewall`, `wireguard`, `auth/audit`;
- значения `error`, `warning`, `info`, `debug`; production default — `info`;
- debug включается только с TTL от 5 минут до 24 часов и автоматически возвращается к предыдущему уровню после deadline/reboot recovery;
- настраиваются retention days, максимальный journal disk usage, максимальный размер diagnostic excerpt и агрегация одинаковых health errors;
- audit событий входа, изменения settings/policy, manual activation, update/restore и destructive actions не отключается и не понижается ниже `info`;
- secret redaction выполняется до передачи записи logger-у: subscription URL query/token, passwords, private/API keys, proxy credentials, modem serial/identity hash и response body никогда не допускаются даже при `debug`;
- payload подписки, полный Mihomo config и packet contents не являются debug-логами; они доступны только через отдельные уже sanitized diagnostics;
- изменение logging settings создаёт audit event с old/new metadata без секретов и применяется без restart;
- Web UI предоставляет фильтры по времени, severity, category, modem/subscription/path и correlation ID, но читает journald через ограниченный server-side API с pagination/rate limit, а не произвольный journal query.

### 16.2 События

Пользовательские события хранятся отдельно от технических логов:

```json
{
  "type": "path_failover",
  "severity": "warning",
  "occurred_at": "2026-08-23T10:00:00Z",
  "details": {
    "from": {
      "modem_id": "modem-a",
      "subscription_id": "subscription-a",
      "node_id": "node-a"
    },
    "to": {
      "modem_id": "modem-b",
      "subscription_id": "subscription-b",
      "node_id": "node-b"
    },
    "reason": "active_path_probe_failed",
    "detection_ms": 24100,
    "switch_ms": 1800
  }
}
```

### 16.3 Diagnostic bundle

Содержит:

- версии ОС, kernel, Gateway и Mihomo;
- sanitized config;
- interface/address/route/rule summary;
- masked modem identities, states и path matrix без serial/API secrets;
- sanitized nftables ruleset и counters;
- Mihomo config без proxy credentials;
- последние события и ограниченный journal;
- WireGuard handshake metadata без keys;
- SQLite integrity check result.

---

## 17. Установка и эксплуатация

### 17.1 Структура репозитория

```text
gateway-vpn/
├── cmd/
│   ├── gateway-vpn/
│   └── gateway-vpnctl/
├── internal/
│   ├── api/
│   ├── auth/
│   ├── bypass/
│   ├── config/
│   ├── db/
│   ├── diagnostics/
│   ├── events/
│   ├── firewall/
│   ├── health/
│   ├── hilink/
│   ├── mihomo/
│   ├── path/
│   ├── reconcile/
│   ├── routing/
│   ├── subscription/
│   ├── traffic/
│   └── wireguard/
├── web/
├── migrations/
├── packaging/
│   ├── systemd/
│   ├── nftables/
│   └── tmpfiles.d/
├── scripts/
│   ├── install-gateway.sh
│   ├── install-vps.sh
│   ├── update.sh
│   └── uninstall.sh
├── test/
│   ├── integration/
│   ├── netns/
│   └── hardware/
├── docs/
│   ├── PLAN_v1.1.md
│   ├── NETWORKING.md
│   ├── SECURITY.md
│   ├── OPERATIONS.md
│   └── API.md
├── go.mod
├── Makefile
└── README.md
```

Точная последовательность отключения IPv6 Internet/WAN на Keenetic документируется в `docs/OPERATIONS.md` после фиксации модели и версии KeeneticOS на этапе 0. Архитектурный критерий остаётся неизменным: на WAN Keenetic нет global IPv6 prefix/default route, а проверка `curl -6` с домашнего клиента не устанавливает интернет-соединение.

### 17.2 Installer requirements

- проверяет ОС, kernel features, TUN, nftables, WireGuard и свободные подсети;
- обнаруживает конфликт UFW/firewalld/NetworkManager configuration;
- не делает безусловный full system upgrade;
- идемпотентен;
- создаёт service users, directories и permissions;
- устанавливает boot-time blocked ruleset;
- генерирует secrets и показывает bootstrap password один раз;
- проверяет подписанные artifacts;
- до включения DHCP требует явного выбора LAN interface;
- сохраняет pre-install network/firewall snapshot;
- умеет dry-run;
- при ошибке выполняет rollback.

### 17.3 Обновление

Версии не перезаписываются на месте:

```text
/opt/gateway-vpn/
├── releases/
│   ├── v1.1.0/
│   │   ├── bin/gateway-vpn
│   │   ├── bin/gateway-vpnctl
│   │   ├── libexec/mihomo
│   │   ├── web/
│   │   └── manifest.json
│   └── v1.2.0/
└── current -> releases/v1.1.0
```

Systemd запускает `/opt/gateway-vpn/current/bin/gateway-vpn`. Новый symlink создаётся под временным именем в том же каталоге и заменяет `current` атомарным `rename`. Хранятся минимум текущий и предыдущий проверенный release; более старые версии удаляются только после stability window и при наличии отдельного DB backup.

1. backup DB/config/secrets metadata;
2. скачать versioned artifact;
3. проверить signature/hash;
4. проверить совместимость migrations;
5. установить новую версию рядом со старой и сохранить atomic symlink target;
6. создать отдельную копию БД для migration, не мигрируя единственный экземпляр in-place;
7. выполнить migration, `PRAGMA integrity_check` и offline compatibility checks на копии;
8. остановить control plane, атомарно переключить binary symlink и migrated DB;
9. выполнить startup и health checks;
10. при неуспехе остановить новый binary, вернуть старый symlink и исходную DB как согласованную пару;
11. удалить rollback copy только после завершения заданного stability window.

Down-migration новой БД старым binary не используется: rollback всегда восстанавливает snapshot до migration.

### 17.4 GitHub zero-to-ready deployment

Официальный способ первого развёртывания — versioned Gateway VPN release из GitHub Releases. Репозиторий исходного кода сам по себе не считается установочным artifact. Release содержит отдельные пакеты ролей `gateway`, `vps` и административный deploy launcher, signed channel manifest с точными версиями, SHA-256, SBOM и provenance.

Поддерживаются три одинаково воспроизводимых режима:

1. одна сгенерированная release-команда на чистом Gateway с ролью `gateway`;
2. одна сгенерированная release-команда на чистом VPS с ролью `vps`;
3. одна команда `gateway-vpn-deploy` с административного компьютера, которая по SSH выполняет preflight обеих машин, устанавливает обе роли, обменивает только WireGuard public keys и запускает end-to-end verification.

Команда содержит явную release version и ожидаемый hash bootstrap artifact. `curl | sudo bash`, непроверенный `latest` и исполнение загруженного файла до проверки hash/signature запрещены. Удобный канал `stable` допустим только как подписанный manifest, разрешающийся в конкретную immutable version; в installation report всегда записываются resolved version, hashes и signer identity.

До первой host mutation выполняется полный read-only preflight и формируется машинно-читаемый отчёт. Проверяются:

- на Gateway — Ubuntu Server `24.04` LTS `x86_64`; на VPS — объявленный release manifest Ubuntu Server LTS profile `20.04+` либо Debian 12+; дополнительно проверяются systemd, время/DNS, свободное место/RAM и поддерживаемое ядро;
- Ubuntu 20.04 VPS принимается только при активном ESM/security coverage и отсутствии ожидающих обязательных security updates; installer не подключает платную подписку и не делает full distribution upgrade самостоятельно;
- TUN, nftables, policy routing, WireGuard, необходимые sysctl/capabilities и отсутствие конфликтующих firewall/network managers;
- на Gateway — явно выбранный Ethernet `lan_keenetic`, непересекающаяся transit subnet, USB/networkd support и отсутствие опасного default-route takeover;
- на VPS — публичный IPv4 либо явно заданный достижимый endpoint, свободный UDP `51821`, IP forwarding и возможность установить owned firewall rules;
- SSH/sudo prerequisites orchestration-режима, доступность immutable GitHub artifacts и валидность всех signatures/hashes;
- все обязательные пользовательские входы: LAN interface/CIDR, VPS endpoint, SSH destinations и политика включения DHCP. Неоднозначный интерфейс не выбирается автоматически.

Если любой обязательный preflight не пройден, обе машины остаются неизменёнными. После начала установки каждая роль использует собственный pre-install snapshot и rollback; ошибка второй роли откатывает только изменения текущей transaction и оставляет первую роль в безопасном диагностируемом состоянии. Повторный запуск идемпотентен и умеет продолжить либо согласованно откатить незавершённую deployment transaction.

Zero-to-ready workflow обязан:

1. установить закреплённые binaries, Mihomo, systemd units, users, permissions и boot-time fail-closed rules;
2. создать SQLite, TLS и локальные secrets на соответствующих hosts, не передавая private keys через GitHub или command line;
3. настроить transit DHCP/DNS, management WireGuard Gateway↔VPS и VPS firewall;
4. запустить services в безопасном порядке и дождаться readiness, а не только состояния `active (running)`;
5. проверить локальный Web UI, WireGuard handshake, endpoint route, nftables ownership, reboot persistence и отсутствие API bind на HiLink interfaces;
6. вывести Web UI URLs, TLS fingerprint, одноразовый bootstrap password location и итоговый redacted installation report;
7. завершиться кодом `0` только при статусе `READY`. Если модемы/подписка ещё не добавлены, допустим только явно обозначенный `INSTALLED_NOT_READY`, без утверждения, что интернет-путь готов.

Термин «любой Gateway/VPS» означает любой хост, удовлетворяющий опубликованной support matrix. Для VPS версия `20.04 и выше` означает поддерживаемые LTS profiles, явно перечисленные и протестированные release manifest; неизвестный будущий release сначала проходит CI/integration qualification и не принимается только по числовому сравнению версии. Произвольная ОС/архитектура, устройство без отдельного Ethernet-порта к Keenetic, пересекающиеся HiLink-подсети, VPS за недоступным CGNAT или закрытый UDP-порт не маскируются автоматическими обходами и завершаются понятным preflight failure.

### 17.5 Uninstall

- сначала переводит Gateway в `PATH_BLOCKED`;
- останавливает services;
- удаляет только rules/tables, принадлежащие Gateway VPN;
- не выполняет глобальный `flush ruleset`;
- сохраняет backup по умолчанию;
- не удаляет пользовательские WireGuard keys без отдельного подтверждения.

---

## 18. Тестирование

### 18.1 Unit tests

- config validation;
- subscription format detection и normalization;
- sanitizer/SSRF policy;
- modem/subscription priority ordering и стабильный tie-break;
- modem identity matching, ambiguous adoption и subnet-conflict detection;
- ranking tuple `modem priority → subscription priority → node quality`;
- Unicode/case-insensitive node-name matching и regex limits;
- RE2 regex validation: anchors/repetition работают, lookaround/backreference/oversized patterns отклоняются;
- candidate-pool policy: matched-only, no-match fallback-all, manual overrides;
- bypass target required/optional semantics и policy generation invalidation;
- target outage suppression;
- probe budget accounting, active reserve и `DEFERRED_BUDGET`;
- state machine;
- hysteresis/backoff;
- migrations;
- log redaction;
- API auth и permissions.
- parser/verification signed channel manifest и защита от version/hash downgrade;
- zero-to-ready preflight не изменяет host при любой failed prerequisite;
- идемпотентность и transaction resume/rollback deploy launcher.

### 18.2 Integration tests

Linux network namespaces моделируют:

- Keenetic/client side;
- Gateway LAN;
- не менее двух fake HiLink routers с разными management subnets и операторами;
- несколько proxy candidates;
- VPS WireGuard peer;
- DNS и probe endpoints.
- чистая Ubuntu 24.04 Gateway и отдельные чистые VPS fixtures Ubuntu 20.04/22.04/24.04/26.04 LTS для GitHub zero-to-ready deployment; 20.04 fixture проверяет ESM/security gate.

Обязательные проверки:

- TCP и UDP через TUN;
- DNS hijack и packet capture на HiLink, подтверждающий отсутствие пользовательского direct DNS;
- отсутствие IPv4 direct path;
- IPv6 RA/DHCPv6 injection, `curl -6` и отсутствие global IPv6 route;
- graceful stop, SIGTERM, `kill -9` и restart storm Mihomo;
- reload/rollback Mihomo с восстановлением LKG;
- atomic nft sets update;
- удаление owned nftables table и случайный `nft flush ruleset` с quarantine/recovery;
- failover/failback;
- два модема одновременно получают DHCP lease, но ни один не устанавливает default route в main table;
- одинаковая subscription/node комбинация проходит required targets через modem A и не проходит через modem B;
- modem A отключается во время active path: новые direct flows не появляются, выбирается qualified path modem B;
- modem A подключается обратно: identity/routes восстанавливаются, а failback ждёт stable requalification;
- USB interface rename/replug сохраняет `modem_id`, priority и routing table/fwmark;
- неоднозначная identity не присваивает новому устройству конфигурацию отсутствующего модема;
- пересечение HiLink subnets помещает только конфликтующий modem в `MODEM_SUBNET_CONFLICT`;
- reorder modem/subscription priority меняет ranking, но не инвалидирует fresh qualification и не обрывает active path вне правил failback/manual activation;
- packet capture на каждом modem подтверждает соответствие `interface-name`, fwmark и routing table выбранной path cell;
- подписка с `обход`/`LTE`/whitelist names: проверяются только совпавшие candidates;
- подписка без совпадений: проверяются все enabled nodes;
- named candidates существуют, но failed: остальные не используются при default policy;
- required target matrix: node qualified только после всех required successes;
- изменение priority/required/URL target инвалидирует старые results и запускает requalification;
- новая policy generation сохраняет active path на grace period, проверяет active node первым и блокирует путь при истечении grace без кандидата;
- reboot во время `VERIFYING_POLICY` начинает с PATH_BLOCKED;
- target недоступен только через один modem: failed получают только его path results, другие modem cells остаются qualified;
- общий target outage через разные модемы/подписки создаёт `TARGET_SUSPECT` без failover loop;
- scheduler выдерживает большую матрицу `modems × subscriptions × nodes × targets` при заданных global/per-modem concurrency/rate budgets;
- исчерпание soft probe budget откладывает standby probes, но не помечает nodes как failed;
- management WireGuard переносит endpoint route на следующий modem и восстанавливает handshake независимо от subscription matrix;
- первый по priority modem не пропускает VPS UDP: selector помечает его management path `BLOCKED` и устанавливает handshake через следующий modem;
- reboot with PATH_BLOCKED;
- truncated/invalid-checksum WAL после power cut: SQLite отбрасывает неподтверждённый tail, `quick_check` проходит, Gateway начинает с verification;
- page corruption/partial write в основном DB-файле: `integrity_check` падает, запись прекращается, выполняется restore verified backup либо остаётся `PATH_BLOCKED`;
- upgrade A→B с успешной migration и rollback B→A через pre-migration DB snapshot;
- atomic switch `/opt/gateway-vpn/current` и rollback на предыдущий release directory;
- safe network apply rollback.

### 18.3 Hardware-in-the-loop

- не менее двух реальных HiLink-модемов, включая Huawei E3372h-325, желательно с SIM разных операторов;
- реальный Keenetic;
- реальная HAPP-подписка каждого поддерживаемого формата;
- USB unplug/replug каждого модема по отдельности и в разном порядке;
- одновременная работа разных management subnets без default-route race;
- потеря mobile registration;
- зависание WebUI/API при сохранении DHCP path;
- исчерпание/обновление DHCP lease;
- power loss Gateway;
- смена IP VPS/DNS response;
- длительный UDP/QUIC traffic;
- MTU/fragmentation test.

### 18.4 Failure matrix

| Сбой | Ожидаемое действие | Direct leak |
|---|---|---:|
| Падение gateway-vpn | firewall остаётся, data path зависит от LKG policy | нет |
| Падение Mihomo | PATH_BLOCKED/нет нового LAN traffic | нет |
| Ошибка новой подписки | продолжить LKG | нет |
| Все ноды active path cell недоступны | следующая subscription на том же modem, затем следующий modem | нет |
| Active node потерял required target | другой qualified node той же cell, затем subscription/modem по ranking | нет |
| Named candidates есть, но все failed | не использовать unmarked nodes без разрешённого full fallback | нет |
| Ни один node name не совпал | проверить все enabled nodes подписки | нет |
| Required target недоступен только через один modem | failed только его path results; проверить другой modem | нет |
| Required target недоступен через независимые modems/subscriptions | TARGET_SUSPECT/DEGRADED_TARGET без failover loop | нет |
| Нет enabled required targets | NO_BYPASS_TARGETS и PATH_BLOCKED | нет |
| Probe soft budget исчерпан | standby probes DEFERRED_BUDGET, active/failover используют reserve | нет |
| Policy generation изменена | active node работает только в grace, затем requalified/switch/blocked | нет |
| Reboot во время VERIFYING_POLICY | старт с PATH_BLOCKED и проверка новой generation | нет |
| Все modem/subscription cells недоступны | PATH_BLOCKED, management доступен | нет |
| Неактивный HiLink unplug | только его cells → MODEM_OFFLINE; active path не меняется | нет |
| Активный HiLink unplug | немедленно закрыть его routes, failover на qualified cell другого modem | нет |
| HiLink reconnect | восстановить identity/routes, requalify, delayed failback | нет |
| Два modem получили DHCP одновременно | defaults остаются только в modem-specific tables | нет |
| HiLink subnets пересеклись | конфликтующий modem quarantined, остальные продолжают работу | нет |
| WireGuard management modem unplug | endpoint route переходит на следующий ready modem | нет |
| Priority modem не достигает VPS endpoint | следующий management-reachable modem без влияния на data path | нет |
| VPS/WireGuard недоступен | data plane продолжает работать | нет |
| SQLite недоступна | blocked или последний подтверждённый runtime без изменений | нет |
| SQLite WAL оборван/имеет неверную checksum | отбросить неподтверждённый tail, quick check, затем verification | нет |
| SQLite main DB page повреждена/частично записана | не открывать БД на запись; integrity event; restore backup либо PATH_BLOCKED | нет |
| Mihomo SIGKILL/restart storm | ограниченный restart, LKG, затем PATH_BLOCKED | нет |
| Control loop завис, но PID жив | systemd liveness watchdog завершает process; bounded restart; reconcile observed state | нет |
| Broker/dnsmasq/firewall guard завершился | перезапуск только компонента, readiness check и audit event | нет |
| Внешний Internet/modems/VPS недоступны длительно | failover либо PATH_BLOCKED; host reboot не выполняется | нет |
| Локальный critical failure пережил restart budget | RECOVERY_SUPPRESSED; optional bounded reboot только по explicit policy | нет |
| Reboot budget исчерпан | запрет следующих reboot до durable window expiry; operator alert | нет |
| Update/restore/network transaction активна | watchdog не вмешивается; штатный transaction recovery имеет приоритет | нет |
| Gateway VPN nftables table удалена | LAN quarantine, восстановление guard, повторная verification | нет |
| Reboot | старт с blocked ruleset, затем verification | нет |
| IPv6 router advertisement | ignored/dropped | нет |

### 18.5 Обязательные fixtures

```text
test/fixtures/
├── mihomo/
│   ├── minimal-valid.yaml
│   ├── invalid.yaml
│   └── expected-api-schema.json
├── subscriptions/
│   ├── clash-minimal.yaml
│   ├── uri-list.txt
│   ├── base64-subscription.txt
│   ├── node-names-bypass-cyrillic.yaml
│   ├── node-names-lte-whitelist.yaml
│   ├── node-names-no-match.yaml
│   └── malicious-and-oversized-cases/
├── bypass-targets/
│   ├── required-and-optional.json
│   ├── target-outage-matrix.json
│   └── invalid-and-ssrf-cases.json
├── modems/
│   ├── two-distinct-subnets.json
│   ├── identity-replug-events.json
│   ├── ambiguous-identity.json
│   └── subnet-conflict.json
├── path-matrix/
│   ├── mixed-qualified-failed.json
│   ├── active-modem-unplug.json
│   ├── reconnect-delayed-failback.json
│   └── large-scheduler-matrix.json
├── nftables/
│   ├── boot-blocked.nft
│   ├── two-modems-policy-routing.nft
│   ├── path-active-modem-a.nft
│   ├── path-active-modem-b.nft
│   └── expected-ruleset.json
├── netns/
│   ├── topology.md
│   └── addresses.env
└── database/
    ├── clean-v1.db
    ├── wal-truncated-recoverable/
    ├── wal-invalid-checksum-recoverable/
    ├── page-corrupted.db
    └── partial-main-write.db
```

Fixtures не содержат production credentials, настоящие subscription tokens или private keys.

---

## 19. Этапы реализации

### Этап 0. Проверка архитектурных предпосылок

**Цель:** доказать основной packet path на реальном оборудовании до разработки приложения.

Этап 0 обязателен и имеет собственный gate. Его можно выполнять параллельно с созданием каркаса репозитория, но разработка firewall controller, failover и traffic accounting не начинается до успешного прохождения его exit criteria. Netns-набор автоматизируется начиная с этапа 1; этап 0 остаётся воспроизводимым hardware spike.

- [ ] подключить не менее двух HiLink-модемов, включая Huawei E3372h-325, по возможности с SIM разных операторов;
- [ ] зафиксировать USB IDs, identity sources, interface drivers, DHCP leases и уникальные subnets всех модемов;
- [ ] заполнить матрицу whitelist reachability отдельно для каждого модема/оператора;
- [ ] проверить VPS WireGuard напрямую через каждый HiLink;
- [ ] доказать одновременную policy routing через отдельные fwmark/tables без default route в main table;
- [ ] выполнить unplug/replug активного и резервного модема, проверить сохранение identity и отсутствие direct leak;
- [ ] поднять один Mihomo TUN вручную;
- [ ] проверить `mixed`, при необходимости сравнить `system`, и зафиксировать TUN stack;
- [ ] закрепить точную версию/SHA-256 Mihomo и сохранить API schema `/version`, `/traffic`, `/connections`;
- [ ] проверить адресный provider-node health-check на реальном bypass URL и зафиксировать семантику HTTP errors/status;
- [ ] собрать обезличенный набор реальных имён nodes с bypass/LTE/whitelist markers и без них;
- [ ] провести TCP, UDP, DNS и QUIC через TUN;
- [ ] заблокировать direct LAN → HiLink;
- [ ] проверить остановку Mihomo, reboot и IPv6 leak;
- [ ] провести total traffic-accounting spike: выбрать nftables measurement point, checkpoint interval и измерить расхождение с `/traffic`;
- [ ] измерить MTU и базовую производительность;
- [ ] сохранить эталонные nftables/Mihomo configs в `test/fixtures`;
- [ ] проверить реальные образцы всех подписок.

**Критерий готовности:** оба модема одновременно маршрутизируют test sockets только через собственные fwmark/tables; одна subscription проверена через каждого оператора; клиент за Keenetic имеет глобальный интернет через закреплённый Mihomo; после `kill -9 mihomo` или unplug active modem прямой интернет немедленно отсутствует, а qualified резервный path может быть выбран без route leak; WireGuard management восстанавливается через резервный modem; общий traffic counter сохраняет монотонность после reload/reboot в пределах принятого checkpoint interval.

### Этап 1. Bootstrap Gateway

- [ ] структура Go-проекта;
- [ ] config validation;
- [ ] SQLite migrations;
- [ ] system users/directories;
- [ ] journald logging;
- [ ] systemd units;
- [ ] boot-time nftables PATH_BLOCKED;
- [ ] dnsmasq DHCP/DNS;
- [ ] multi-modem discovery, adoption и stable identity;
- [ ] modem CRUD, enabled/priority и offline persistence;
- [ ] per-modem DHCP без default route в main table;
- [ ] policy tables/fwmarks, subnet-conflict quarantine и hot-plug state machine;
- [ ] базовый `gateway-vpnctl status`.

**Критерий готовности:** чистая установка, 10 последовательных reboot и replug в обратном USB-порядке безопасно восстанавливают как минимум два `modem_id`, их priority и отдельные route tables; конфликт/отсутствие одного модема не повреждает routes другого; data path не открывается без подтверждённого VPN; SQLite каждый раз проходит integrity check.

### Этап 2. Subscription Manager и один Mihomo

- [ ] URL/upload import;
- [ ] parsers и sanitizer;
- [ ] provider/group generation для каждой enabled пары `subscription × modem`;
- [ ] node name normalization;
- [ ] node matcher engine и default matcher seed;
- [ ] candidate pool classification и manual include/exclude;
- [ ] LKG versioning;
- [ ] Mihomo config generator;
- [ ] modem-specific `interface-name`/`routing-mark` overrides и globally unique group names;
- [ ] controlled `select` group per path cell и верхнеуровневая active-path group;
- [ ] validation/reload/rollback transaction;
- [ ] local Mihomo API client;
- [ ] ручная активация qualified tuple `modem × subscription × node` без автоматического failover.

**Критерий готовности:** корректная подписка независимо активируется через каждый стендовый modem на закреплённой версии Mihomo; capture подтверждает выбранный физический интерфейс и mark; полный Mihomo config всех пар проходит transaction/LKG; набор valid/invalid/empty/oversized/malicious fixtures проходит; при наличии bypass-name matches candidate pool не содержит обычные узлы, а при отсутствии matches содержит все enabled nodes; ошибочный import не меняет LKG path.

### Этап 3. Reconciler, health и failover

- [ ] desired/observed reconciliation;
- [ ] layered health model;
- [ ] bypass target model, priorities и policy generation;
- [ ] path matrix `modem × subscription` и path-scoped result storage;
- [ ] адресные `modem × subscription × node × target` probes;
- [ ] qualification scheduler с global/per-modem concurrency/rate budgets;
- [ ] path-node/cell/global probes;
- [ ] target outage suppression;
- [ ] failure cause classification;
- [ ] modem-first lexicographic ranking и failover `node → subscription → modem`;
- [ ] failback hysteresis;
- [ ] dynamic nftables sets;
- [ ] event history;
- [ ] restart/crash recovery.

**Критерий готовности:** failure matrix проходит автоматически; каждая enabled modem/subscription cell имеет независимый статус; активируется только node, прошедший все enabled required targets через конкретный modem в текущих policy/route generations; scheduler соблюдает global/per-modem budgets; failover выполняется `node → subscription на текущем modem → следующий modem` не более чем за 45 секунд после подтверждённого отказа; общий target outage не создаёт loop; direct leak отсутствует; восстановленный preferred modem не вызывает failback до stable interval и cooldown.

### Этап 4. Безопасный API и Web UI

- [ ] HTTPS listener;
- [ ] bootstrap password и Argon2id;
- [ ] secure sessions, CSRF и rate limiting;
- [ ] `/api/v1` + OpenAPI;
- [ ] Dashboard с явным active path tuple;
- [ ] логические вкладки Modems, Subscriptions, Path Matrix, Check Servers, Matchers и Nodes;
- [ ] modem discovery/adoption/CRUD, enable и atomic priority reorder;
- [ ] subscriptions/nodes с двусторонним представлением path matrix;
- [ ] bypass target CRUD, enable/required и atomic priority reorder;
- [ ] node matcher CRUD/preview и policy requalification status;
- [ ] health/events;
- [ ] settings с safe apply;
- [ ] secret redaction;
- [ ] diagnostics download.

**Критерий готовности:** все privileged операции требуют auth; API не раскрывает secrets; пользователь может добавить/отключить/переименовать/переупорядочить modem и subscription, а их страницы показывают согласованные статусы всех пар из одного read model; пользователь может CRUD/reorder targets/matchers; UI показывает target matrix, probe budget и reason code каждого node/path; offline modem не исчезает, stale results не выглядят рабочими; смена policy generation проходит через 120-секундный grace; ошибочная LAN-настройка откатывается out-of-process helper не позднее 90 секунд.

### Этап 5. WireGuard management

- [ ] VPS installer;
- [ ] Gateway peer generation;
- [ ] admin peer management;
- [ ] modem-independent management-uplink selector;
- [ ] modem-specific endpoint host routes и atomic failover;
- [ ] VPS forwarding/firewall;
- [ ] status/handshake UI;
- [ ] management survival tests.

**Критерий готовности:** Web UI доступен через VPS при неработающем Mihomo и отсутствии рабочих подписок; unplug текущего management-модема переносит endpoint route на следующий ready modem и восстанавливает handshake без ручной настройки.

### Этап 6. Traffic, backup и эксплуатация

- [ ] реализовать общий authoritative traffic accounting без per-subscription attribution;
- [ ] retention/aggregation;
- [ ] CSV export;
- [ ] backup/restore;
- [ ] diagnostic bundle;
- [ ] signed update/rollback;
- [ ] idempotent install/uninstall;
- [ ] signed GitHub Releases для ролей Gateway/VPS и generated one-command install;
- [ ] `gateway-vpn-deploy` для одной SSH-orchestrated zero-to-ready установки обеих ролей;
- [ ] совместный preflight/report, transaction resume/rollback и end-to-end readiness gate;
- [ ] operations documentation.

**Критерий готовности:** power-loss, atomic symlink update rollback и backup/restore проходят без повреждения состояния и утечки трафика; systemd всегда запускает согласованный `current` release; generated GitHub command устанавливает каждую роль на чистую поддерживаемую Ubuntu, а `gateway-vpn-deploy` с одной команды доводит чистые Gateway+VPS до подтверждённого WireGuard/WebUI readiness либо откатывается без ложного успеха; 24-часовой developer endurance test и 72-часовой release endurance test не показывают монотонного роста RSS/FD/goroutines после warm-up, SQLite проходит integrity check, а размер БД соответствует retention policy.

---

## 20. Definition of Done проекта

Проект считается готовым к домашней эксплуатации, когда одновременно выполнены условия:

1. этап 0 воспроизводим минимум с двумя HiLink-модемами, включая Huawei E3372h-325, и целевым Keenetic;
2. все тесты failure matrix проходят;
3. подтверждено отсутствие direct IPv4, DNS и IPv6 leak;
4. invalid subscription/config/update автоматически откатываются к LKG;
5. после reboot Gateway стартует fail-closed и восстанавливает рабочий путь без ручного вмешательства;
6. WireGuard management доступен независимо от состояния Mihomo и переключает modem uplink при disconnect;
7. API не слушает HiLink uplink и требует аутентификацию;
8. секреты отсутствуют в API responses, logs и diagnostic bundle;
9. installer, update, rollback, backup, restore и uninstall проверены на чистой системе;
10. документация содержит topology, recovery runbook и список поддерживаемых subscription formats;
11. версия и SHA-256 Mihomo закреплены, а API contract сохранён fixture;
12. общий traffic counter является authoritative; per-subscription значения отсутствуют в MVP API и UI;
13. активным становится только tuple `modem × subscription × node` с актуальным `BYPASS_QUALIFIED` для всех required targets через этот modem;
14. name matcher fallback и target priority/CRUD проходят fixtures и integration tests;
15. общий outage одного target не вызывает бесконечное переключение nodes/subscriptions/modems;
16. все adopted модемы сохраняют identity, номер, priority и history после unplug/replug и reboot;
17. Web UI показывает одинаковое состояние каждой `modem × subscription` cell во вкладках Modems, Subscriptions и Path Matrix;
18. потеря active modem не создаёт direct route, а переключение выполняется на qualified cell по порядку `node → subscription → modem`;
19. вернувшийся preferred modem активируется только после stable requalification, без flap;
20. DHCP, DNS bootstrap, proxy sockets и WireGuard endpoint routes каждого модема изолированы его fwmark/routing table.
21. versioned signed artifacts из GitHub устанавливают чистые поддерживаемые Gateway и VPS воспроизводимо; одна SSH-orchestrated команда либо подтверждает полный `READY`, либо выдаёт проверяемый `INSTALLED_NOT_READY`/failure и безопасный rollback без ложного заявления о готовности.
22. PID-alive hang, component crash и restart storm автоматически обнаруживаются; восстановление bounded, dependency-aware, fail-closed и полностью отражено в UI/events/diagnostics.
23. длительная внешняя потеря Internet/modems/VPS не вызывает host reboot; optional reboot локального critical failure имеет durable budget и не выполняется во время install/update/restore/network transaction.
24. 24- и 72-часовые endurance результаты содержат supervisor/recovery counters и не имеют скрытого restart/reboot loop.

---

## 21. Данные, которые нужно зафиксировать на этапе 0

Эти значения не меняют архитектуру, но необходимы для production config:

- фактические USB vendor/product IDs всех стендовых модемов, включая Huawei E3372h-325;
- доступные источники stable identity и поведение MAC/interface name после replug каждого модема;
- имена kernel drivers и сетевых интерфейсов;
- фактические HiLink IP/subnet, DHCP leases и WebUI versions каждого модема;
- подтверждение уникальности management subnets и процедура их изменения через WebUI HiLink;
- поддерживаемые HiLink API endpoints и необходимость аутентификации по моделям/прошивкам;
- адреса/домены, разрешённые whitelist каждого оператора;
- измеренное время обнаружения disconnect/reconnect и восстановления mobile registration;
- формат и обезличенные fixtures каждой HAPP-подписки;
- реальные варианты имён bypass/LTE/whitelist nodes и отсутствие таких меток в части подписок;
- начальный список required/optional probe targets и ожидаемая семантика их ответа;
- допустимые global/per-modem concurrency, cache TTL и mobile traffic budget для полной path matrix;
- публичный IP/hostname и порт VPS;
- точная модель и версия KeeneticOS;
- измеренная MTU и требуемая пропускная способность;
- допустимое время failover и объём health-check traffic;
- checkpoint interval и допустимое расхождение nftables total с Mihomo `/traffic`;
- закреплённые Mihomo version/hash, TUN stack и API schema fixture.

После заполнения этого раздела и успешного этапа 0 архитектурные решения MVP считаются закрытыми.
