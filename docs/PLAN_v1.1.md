# Gateway VPN — план реализации

**Версия:** 1.1  
**Дата:** 2026-08-23  
**Статус:** готов к началу технического этапа 0  
**Целевая платформа Gateway:** Ubuntu Server 24.04 LTS, x86_64  
**Целевая платформа VPS:** Ubuntu Server LTS 20.04 и выше, x86_64; Debian 12+ как отдельный support profile  
**Проверяемые Ubuntu VPS profiles:** 20.04, 22.04, 24.04 и 26.04 LTS; 20.04 допускается только с активным Ubuntu Pro/ESM и актуальными security updates
**Поправка 2026-08-26:** добавлен обязательный contract круглосуточного самоконтроля и bounded recovery (§9.8); остальные ранее зафиксированные решения версии 1.1 не переписаны
**Поправка 2026-08-27:** прямой Интернет стал штатным проверяемым методом доступа в едином priority list с подписками; добавлены server stickiness/overrides, resilient subscription refresh, FULL/LIMITED ranking, временный direct-only mode и настраиваемая стартовая блокировка
**Поправка 2026-08-29:** watchdog расширен до фиксированного контура из 17 компонентов, включая отдельный `logging_pipeline`, с per-component recovery mode и классификацией внешних отказов; first-install SSH/SFTP стал рекомендуемым интерактивным default с явным opt-out; для Gateway закреплён owned management route `10.80.0.0/24 dev wg-mgmt protocol 186`
**Поправка 2026-08-30:** односерверный `wg-mgmt` расширяется в successor до many-to-many Management Fabric `1..N Gateway ↔ 1..N VPS`; добавлены независимые одновременно активные management links, optional end-to-end `wg-admin` через VPS UDP relay, публикация Gateway/Keenetic/local resources с ACL и alias-prefix для пересекающихся домашних подсетей, несколько способов доступа в LAN без обязательной замены обычного WAN Keenetic, безопасное переключение topology profiles после установки и сгруппированная навигация WebUI

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
- выбирает лучший подтверждённый метод доступа: прямой Интернет через конкретный модем либо подписку через один процесс Mihomo в режиме TUN;
- загружает HAPP-совместимые VPN-подписки и хранит последнюю рабочую версию;
- отбирает внутри подписок только узлы, пригодные для обхода заданных ресурсов;
- автоматически выбирает подтверждённый путь `метод → модем → [VPN-узел]` и переключает его при отказе или появлении более функционального пути;
- не допускает неуправляемый прямой выход: direct разрешается только как явно включённый и проверенный метод через выбранный модем;
- предоставляет локальный Web UI и API;
- сохраняет управление через один или несколько независимых WireGuard-туннелей Gateway → VPS;
- собирает состояние, события и статистику трафика.

### 1.2 Что входит в поддерживаемый MVP/successor scope

- несколько одновременно подключённых HiLink USB-Ethernet модемов с приоритетами;
- один или несколько Ethernet-uplink в дополнение к HiLink либо вместо них; DHCP и статический IPv4 поддерживаются, PPPoE не входит в проект;
- hot-plug/hot-unplug, сохранение offline-модемов в конфигурации и автоматическое возвращение после reconnect;
- независимая проверка каждой пары `uplink × способ доступа`, где uplink имеет тип `HILINK` или `ETHERNET`;
- IPv4 data plane;
- Keenetic, подключённый WAN-портом к Gateway;
- один процесс Mihomo;
- Mihomo TUN с прозрачной обработкой TCP, UDP и DNS;
- несколько подписок с приоритетами;
- единый список приоритетов, содержащий неудаляемый пункт `Прямой интернет` и подписки;
- поиск bypass-кандидатов по настраиваемым признакам имени с fallback-проверкой всех узлов;
- произвольное количество приоритетных probe targets, управляемых через Web UI;
- last known good для подписок и конфигурации Mihomo;
- автоматический failover и failback с hysteresis;
- fail-safe nftables с атомарным открытием только выбранного direct- или TUN-пути;
- DHCP и DNS на транзитной сети Gateway → Keenetic;
- HTTPS Web UI, REST API и CLI;
- удалённый доступ к самому Gateway через один или несколько VPS WireGuard;
- successor Management Fabric для нескольких Gateway на одном VPS и одного Gateway на нескольких VPS, с явной публикацией разрешённых локальных ресурсов;
- SQLite, структурированные события и учёт трафика;
- idempotent install/update/uninstall scripts;
- backup, restore и diagnostic bundle.
- круглосуточный self-health supervisor с настраиваемой через Web UI безопасной лестницей восстановления и защитой от restart/reboot loop.
- отдельные direct-only индикаторы белых списков, не смешиваемые с проверкой полноценного Internet через VPN;
- опциональный входящий WireGuard-сервер `wg-ingress` с полным управлением peers/клиентами через Web UI, включая однокарточную схему через Keenetic;
- тематические представления журналов в Web UI и redacted plain-text exports для скачивания штатным OpenSSH/SFTP.

Рабочая топология — `1..N` adopted HiLink-модемов. Один модем является полностью поддерживаемой штатной конфигурацией: список modem priority состоит из одного элемента, межмодемный failover не выполняется, а при disconnect единственного uplink Gateway остаётся `PATH_BLOCKED` до его стабильного reconnect либо добавления другого модема. При двух, пяти или большем числе модемов используется та же модель без специального «двухмодемного» режима; каждый модем имеет собственные identity, priority, management subnet, route table, fwmark, health и ячейки `modem × subscription`. Web UI не задаёт искусственный предел количества записей, но фактический hard limit определяется уникальностью подсетей, USB-питанием и hardware-profile limits для размера Mihomo config и probe matrix. Требование иметь минимум два модема относится только к стендовой проверке multi-modem failover и не является минимальным требованием для обычной установки.

Successor-модель обобщает это правило до `1..N` enabled uplinks. HiLink остаётся специализированным uplink с USB identity, telemetry и recovery, Ethernet — uplink со stable NIC identity, DHCP/static IPv4 и собственным gateway. Наличие только одного uplink само по себе ничего не блокирует: Gateway перебирает через него direct и все разрешённые VPN-методы, использует лучший `FULL`, а при его отсутствии — лучший разрешённый `LIMITED/WHITELIST_ONLY`. Пользовательский Internet отсутствует только когда через единственный физический uplink не осталось ни одного пригодного пути; Web UI/SSH/SFTP и recovery продолжают работать через management/LAN.

### 1.3 Что не входит в поддерживаемый scope

- собственный VPN-протокол;
- поддержка QMI, MBIM, PPP и Stick-прошивок модемов;
- автоматическая перепрошивка Huawei;
- IPv6-транзит;
- балансировка одной пользовательской сессии между подписками;
- полноценный многопользовательский RBAC;
- неограниченный неаудируемый доступ через VPS ко всем локальным сетям; successor допускает только явно опубликованные ресурсы/подсети через ACL и проверенный return path;
- QMI/MBIM/PPP/PPPoE и другие типы uplink, кроме поддерживаемых `HILINK` и обычного IPv4 `ETHERNET` DHCP/static;
- одновременная работа HiLink-модемов с пересекающимися management-подсетями;
- агрегация пропускной способности или распределение одной пользовательской сессии между модемами;
- мобильное приложение;
- облачный управляющий сервис.

### 1.4 Основные принципы

1. **Проверяемый data path:** LAN проходит только через текущий выбранный метод. Direct разрешается исключительно как штатный пункт policy и только через квалифицированный modem path; при отсутствии допустимого пути используется quarantine.
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
| Ethernet uplink #N | DHCP или static IPv4; отдельная непересекающаяся подсеть | upstream router/ONT ↔ Gateway |
| Gateway transit LAN | `192.168.200.0/24` | Gateway ↔ Keenetic WAN |
| Gateway transit IP | `192.168.200.1/24` | DHCP gateway и DNS |
| Keenetic WAN | DHCP reservation, например `192.168.200.2` | WAN Keenetic |
| Home LAN | `192.168.50.0/24` | устройства за Keenetic |
| WireGuard management link #1 | `10.80.0.0/24` по умолчанию | первый VPS, Gateway, администраторы |
| Дополнительный management link #N | отдельная выбранная непересекающаяся subnet | независимый VPS link |
| VPS WireGuard #1 | `10.80.0.1/24` | management router первого link |
| Gateway WireGuard #1 | `10.80.0.2/32` | удалённое управление через первый VPS |
| Admin peers #1 | `10.80.0.10/32` и далее | ПК/телефон администратора на первом VPS |
| Published resource pools | выбираемые conflict-free private prefixes | уникальные alias сетей/ресурсов разных Gateway |
| WireGuard ingress | выбираемая private IPv4 subnet, например `10.90.0.0/24` | Keenetic/clients → Gateway data plane |

Подсети не должны пересекаться. Адрес и subnet каждого HiLink считаются обнаруживаемыми параметрами, а не константами. Совпадающие management-подсети не исправляются метриками или priority: конфликтующий модем помещается в quarantine до изменения его подсети.

### 4.2 Логические имена интерфейсов

Приложение хранит роли, а не полагается на случайные имена `eth0`, `usb0` или `enx...`:

| Роль | Пример | Определение |
|---|---|---|
| `uplink_hilink_<id>` | `enx001e...` | stable modem ID + USB parent + DHCP gateway |
| `uplink_ethernet_<id>` | `enp3s0` | stable NIC identity + explicit adopted uplink record |
| `lan_keenetic` | `gateway-vpn-lan` | owned Linux bridge; один или несколько явно подтверждённых физических Ethernet members |
| `tun_mihomo` | `gateway-vpn-tun` | фиксированное имя в Mihomo |
| `wg_management_<link_id>` | `wg-mgmt` для совместимого первого link, затем bounded `gvm<N>` | отдельный management link к конкретному VPS; имя стабильно по link slot и укладывается в Linux IFNAMSIZ |
| `wg_admin` | `wg-admin` | optional end-to-end administrator tunnel, доставляемый через VPS UDP relay без расшифровки admin traffic на VPS |
| `wg_ingress` | `wg-ingress` | отдельный optional server для пользовательского/роутерного трафика |

### 4.3 Multi-uplink policy routing

Каждый enabled uplink получает независимый routing context:

```text
uplink priority 10 → fwmark 0x1101 → table 1101 → default via Ethernet/router
uplink priority 20 → fwmark 0x1102 → table 1102 → default via HiLink modem_1
uplink priority 30 → fwmark 0x1103 → table 1103 → default via HiLink modem_2
```

Правила:

- DHCP lease каждого uplink не устанавливает default route в main table;
- Uplink Manager создаёт link route и default route только в выделенной table;
- table ID и fwmark стабильны для `uplink_id`, а не для текущего имени интерфейса;
- исходящие proxy sockets получают `interface-name` и `routing-mark` нужного uplink;
- DNS bootstrap для proxy hostname выполняется в контексте того же uplink;
- приложение проверяет `ip route get <proxy-ip> mark <uplink-mark>` до квалификации path;
- ECMP, bonding и load balancing между uplinks не используются;
- в каждый момент пользовательский трафик имеет один активный path tuple;
- subnet conflict с другим uplink/LAN/WireGuard переводит запись в `UPLINK_SUBNET_CONFLICT`; HiLink дополнительно показывает `MODEM_SUBNET_CONFLICT` в специализированном представлении;
- одинаковые management-подсети через per-modem network namespaces рассматриваются после MVP.

Default ranking путей сначала сравнивает функциональность `FULL > LIMITED/WHITELIST_ONLY > FAILED`, затем `access_method.priority`, `uplink.priority`, preferred node rank, стабильность и latency. Поэтому `FULL` всегда выигрывает у ограниченного пути независимо от priority, а среди одинаково функциональных вариантов действует явно заданный пользователем порядок.

### 4.4 Keenetic

- WAN Keenetic подключён к `lan_keenetic` Gateway;
- при нескольких Ethernet-портах все выбранные dedicated LAN/management ports входят в один bridge `gateway-vpn-lan` с единственным transit IPv4; поэтому Keenetic WAN, локальный WebUI и SSH доступны через любой выбранный порт без дублирования одной подсети на независимых L3 interfaces;
- Huawei/USB-HiLink, current default-route, active SSH management route, non-Ethernet и интерфейсы с существующим IPv4 не включаются в bridge; STP включён для защиты от случайной L2-петли, но два LAN-порта не следует намеренно соединять с одним внешним switch без необходимости;
- WAN mode: DHCP client;
- WAN IP желательно закрепить по MAC;
- gateway и DNS: `192.168.200.1`;
- домашняя LAN: `192.168.50.0/24`;
- NAT Keenetic остаётся включённым;
- IPv6 Internet/WAN для этого подключения выключен в MVP;
- другие активные WAN/default routes на Keenetic запрещены, иначе они создадут обход fail-closed Gateway.

Gateway видит пользовательский трафик как трафик WAN-адреса Keenetic. Учёт по отдельным домашним устройствам в MVP невозможен и не заявляется.

Keenetic может оставить link-local IPv6 или ULA внутри домашней LAN, если они не дают глобального IPv6 default route. Критерий безопасности — отсутствие глобального IPv6 prefix и выхода в интернет, а не обязательное исчезновение локального IPv6 со всех домашних устройств.

### 4.5 Поддерживаемые ingress/uplink-профили

Установщик и Web UI используют роли, а не предполагают одну фиксированную разводку:

1. **Ethernet LAN → HiLink uplink:** Keenetic WAN получает DHCP от `gateway-vpn-lan`, пользовательский трафик приходит обычной маршрутизацией, Internet предоставляет один или несколько HiLink.
2. **Ethernet LAN → Ethernet uplink:** одна или несколько карт образуют LAN/management bridge, отдельная карта получает DHCP/static IPv4 от upstream router и служит transport для direct/VPN.
3. **Однокарточный WireGuard:** одна Ethernet-карта одновременно предоставляет management, принимает outer UDP `wg-ingress` от Keenetic и выпускает direct/VPN outer connections обратно через тот же Keenetic. Пользовательский ingress при этом является виртуальным `wg-ingress`, а не неразличимым plain-LAN hairpin.
4. **Смешанный:** `wg-ingress` или Ethernet LAN принимает трафик, а набор uplinks включает Ethernet и любое поддерживаемое количество HiLink.

Обычная physical NIC не назначается одновременно member-ом LAN bridge и Ethernet uplink. Исключение — однокарточный WireGuard-профиль: физическая карта имеет shared `MANAGEMENT + WG_ENDPOINT + ETHERNET_UPLINK` role, а пользовательский plaintext входит только через `wg-ingress`. Сам Gateway, UDP endpoint, proxy/DNS/subscription/VPS service flows обязательно исключаются из возвращающей политики Keenetic; preflight проверяет маршрут к upstream gateway, отдельные marks и отсутствие route recursion.

Все четыре topology profiles являются изменяемыми после установки через WebUI, а не одноразовым выбором мастера. Переход создаёт один durable safe-apply transaction для roles, networkd, DHCP/DNS, firewall, policy routing, `wg-ingress` и API bind; старый management address/path сохраняется на grace period, новый path требует подтверждения, timeout/process crash/reboot выполняют out-of-process rollback. Если candidate затрагивает единственный доступный management path и нет подтверждённого `wg-mgmt`, другого LAN-порта либо локальной консоли, apply блокируется до появления альтернативного пути. Физическое перемещение кабеля и внешняя настройка Keenetic показываются как явные prerequisites и не объявляются автоматически выполненными.

### 4.6 Stable identity, назначение и замена сетевой карты

Physical NIC inventory хранит permanent MAC, PCI/USB topology, driver, model/vendor, текущий ifname, carrier и addresses. Пользователь назначает роли через мастер/Web UI; случайное Linux-имя не является durable identity. Исчезнувшая карта остаётся `CONFIGURED_OFFLINE`, а операция **«Заменить сетевую карту»** атомарно переносит роль и настройки на явно выбранную unused NIC.

Перед replacement/apply отображаются точные последствия, выполняются conflict/loop/management reachability checks и создаётся LKG snapshot. Изменение подтверждается из нового management path; без подтверждения отдельный root helper откатывает persistent/runtime network state. SSH/SFTP никогда не открываются на dedicated uplink, но разрешены на выбранных management/LAN ports и, отдельной policy, через `wg-mgmt`.

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

Recovery не запускается из-за недоступности глобальных targets, VPN nodes либо HiLink telemetry при исправных carrier/DHCP/gateway. Состояние `WHITELIST_ONLY` является свойством direct path и означает ограничение оператора, а не аппаратную неисправность модема.

Physical-failure classifier использует только `DEVICE_ABSENT`, `CARRIER_DOWN`, `DHCP_LEASE_MISSING` и отдельно подтверждённый `HILINK_MANAGEMENT_UNREACHABLE`. Полученный carrier + валидный DHCP lease завершает hardware-recovery episode даже при subnet conflict, ошибке policy routing или отсутствии глобального доступа: эти причины исправляются своими контроллерами. Ручная кнопка сначала заново обнаруживает устройство/carrier/lease и не выполняет reset физически исправного модема только потому, что Internet или VPN недоступны.

Каждый автоматический recovery step получает durable per-modem attempt budget, minimum failure duration, deadline, cooldown и generation. Выполнение сериализуется с hot-plug/replacement; disconnect во время действия завершает его как `DEVICE_REMOVED`, а новый USB identity никогда не наследует reset старого modem без явного match. После DHCP/API/mobile-session/USB действия маршруты остаются закрытыми до нового lease, увеличения `route_generation` и fresh path qualification.

Controlled USB recovery выполняется только параметрическим root broker по сохранённой и повторно сверенной sysfs identity: сначала driver unbind/bind, затем поддерживаемый USBDEVFS reset, а реальный port power-cycle — только если обнаружен hub с индивидуальным управлением портом и policy явно разрешена. Произвольный sysfs path из Web/API root broker не принимает. При исчерпании budget модем становится `MODEM_ERROR/RECOVERY_SUPPRESSED`, остальные uplinks продолжают работу, а полный host reboot не запускается из-за одного внешнего modem outage.

Каждый signed hardware profile явно перечисляет фактически разрешённые recovery actions. Ступень, ещё не прошедшая реальный gate на данном modem/driver/hub, завершается `SUPPRESSED/HARDWARE_ACTION_NOT_AVAILABLE`, а не пробует generic sysfs mutation. WebUI показывает отдельные policy, текущую физическую причину, durable budget/cooldown и очищенную историю; изменение policy generation не обнуляет уже использованный USB budget.

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
    max_usb_resets_per_window: 3
    usb_reset_window_seconds: 3600
    allow_hub_port_power_cycle: false
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
- auto-refresh не зависит от разрешения подписки для пользовательского трафика: выключенная подписка продолжает обновляться при `auto_refresh=true`;
- прямое служебное обновление разрешено по умолчанию и не зависит от включения `Прямого интернета` как пользовательского метода;
- fetch выполняется последовательно через active node этой подписки, другие разрешённые nodes этой подписки, разрешённые nodes других подписок и direct через ready-модемы по priority;
- служебная попытка fetch имеет отдельный routing context и никогда не переключает пользовательский data path;
- global default interval может быть переопределён на подписке; retry учитывает bounded exponential backoff, jitter и HTTP `Retry-After`;
- один URL/subscription refresh имеет single-flight lease; ручной запуск либо присоединяется к текущей operation, либо получает её ID, но не создаёт второй fetch;
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

Targets разделены на непересекающиеся классы:

- `GLOBAL_REQUIRED` и `GLOBAL_OPTIONAL` проверяют полноценность direct и каждого exact VPN path;
- `WHITELIST_INDICATOR` проверяется **только напрямую** через конкретный uplink и никогда не входит в VPN qualification;
- `SERVICE_ENDPOINT` создаётся системой для subscription source, proxy endpoint, VPS/update и отображает служебную достижимость, но не объявляет пользовательский Internet полным.

Успех одного `WHITELIST_INDICATOR` не означает полный Internet. Direct path получает `WHITELIST_ONLY`, только когда stable threshold подтверждает настоящий HTTPS response хотя бы одного enabled indicator, а несколько независимых global required targets не проходят. Если часть global targets проходит, используется общее состояние `LIMITED`; если global required policy полностью выполнена — `FULL` независимо от indicator results. Captive portal/операторский redirect отклоняется strict expected status/body/certificate-host validation.

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
  class: global_required      # global_required | global_optional | whitelist_indicator
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
- whitelist indicator не отправляется через VPN node даже при ручной проверке; UI явно показывает `Проверяется только напрямую`;
- изменение class/priority/URL/expected response повышает policy generation и делает старые direct/VPN results stale;
- состояние `WHITELIST_ONLY` разрешается как временный пользовательский direct path только когда immutable direct method включён; его отключение не запрещает отдельный service-refresh fallback.

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

### 7.8 Управление VPN-серверами и устойчивость обновления подписки

Каждая подписка раскрывает полный inventory узлов активной LKG-версии. Для узла доступны три явные политики:

- `AUTO` — использовать результат matchers и fallback policy;
- `INCLUDE` / **Использовать** — включать в candidate pool независимо от имени;
- `EXCLUDE` / **Не использовать** — никогда не использовать для probes, user traffic или subscription fetch fallback.

Пользователь может назначить основной узел и упорядочить резервные узлы. При равном классе доступности этот порядок важнее latency. Активный узел sticky: небольшое улучшение latency другого узла не вызывает переключения. Переключение выполняется только при подтверждённом ухудшении, ручном выборе либо после stable interval, если появился более функциональный или более приоритетный путь.

После refresh узлы новой immutable version получают новые version-scoped IDs, но решения переносятся по стабильному fingerprint. Для совпавшего fingerprint сохраняются `AUTO/INCLUDE/EXCLUDE`, preferred rank и пользовательская метка. Новый fingerprint получает `AUTO`; исчезнувший fingerprint сохраняется в bounded history, чтобы кратковременное исчезновение и возвращение узла не теряло решение. Неоднозначная identity не переносится автоматически и отображается как требующая подтверждения.

Новая версия подписки проходит import, policy classification, Mihomo validation и qualification до LKG activation. Ошибка любого шага оставляет прежнюю LKG и её node policy рабочими. В UI доступны отдельные операции **Проверить сервер**, **Проверить через выбранный/каждый модем**, **Проверить подписку**, **Проверить источник**, **Обновить сейчас** и **Обновить все**.

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
| LAN | Direct modem path | только когда выбран квалифицированный метод `Прямой интернет`; один конкретный interface/table и SNAT generation |
| LAN/WG | HTTPS API | только management CIDR/interface |
| LAN | SSH Gateway | TCP/22 на owned `gateway-vpn-lan`; аутентификация штатного OpenSSH |
| WG | SSH Gateway | опционально и только admin peers |
| Gateway | HiLink Web/API | только management address конкретного modem/interface |
| Mihomo | proxy endpoints | modem-specific interface + fwmark + route table |
| WireGuard | VPS endpoint UDP | через выбранный management modem, независимо от VPN path |
| Gateway | subscription/bootstrap endpoints | выбранный modem context или active VPN path |
| Gateway | NTP/bootstrap DNS | только настроенные endpoints и modem context |

Явно запрещено вне активной direct generation:

```text
lan_keenetic → любой невыбранный uplink_hilink_* direct
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
- `active_direct_interfaces` и `active_direct_marks` с cardinality `0` либо `1`;
- отдельную generation активного метода, исключающую одновременное открытие TUN и direct.

Обновление sets не заменяет весь ruleset и не создаёт временное окно direct access.

### 8.4 PATH_STATE

```text
PATH_BLOCKED
  Пользовательский forward запрещён.
  HiLink management и WireGuard bootstrap разрешены.

PATH_VERIFYING
  Mihomo поднят; разрешён только внутренний probe.

PATH_ACTIVE
  LAN направляется ровно в один подтверждённый TUN или direct path.

PATH_DEGRADED
  Существующий путь работает частично; идёт проверка кандидата.
```

Приложение не устанавливает `PATH_ACTIVE`, пока end-to-end probe через выбранный tuple `(method, modem, optional subscription/node)` не успешен. `PATH_BLOCKED` — внутреннее quarantine-состояние, а UI показывает понятную причину: например, **«Интернет временно заблокирован: ни один проверенный способ доступа не работает»**.

Настройка **«Блокировать интернет до завершения стартовой проверки»** управляет только стартовой стратегией:

- `ON` — boot firewall остаётся в quarantine до fresh full qualification;
- `OFF` — после минимальной проверки link/DHCP/route/NAT восстанавливается последний допустимый LKG-метод либо временный direct path, а полная qualification продолжается в фоне;
- настройка не отключает firewall и не разрешает произвольный uplink;
- повреждение state, отсутствие минимально безопасного route/NAT или отсутствие всех uplink всё равно оставляет quarantine независимо от настройки.

### 8.5 Инварианты

- остановка `gateway-vpn` не удаляет firewall;
- падение Mihomo прекращает новый пользовательский трафик только для активного VPN-метода и запускает выбор другого qualified метода, включая direct;
- reboot сначала загружает `PATH_BLOCKED`;
- отсутствие SQLite или ошибочная миграция не открывает direct path;
- management exception каждого modem не включает всю его подсеть без необходимости;
- удаление/падение одного modem не меняет routes и marks остальных модемов;
- forwarded LAN packet без выбранного TUN/direct generation никогда не попадает в main/default route любого modem;
- TUN и direct user gates не могут быть активны одновременно;
- direct SNAT привязан к выбранному modem interface и его generation, а не к wildcard uplink set.

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
| Physical uplink | interface/carrier конкретного uplink | eligibility и recovery этого uplink |
| Modem HiLink | USB identity, DHCP, gateway, Web/API, registration | специализированный modem state |
| Direct whitelist transport | indicators напрямую через uplink mark/table | `WHITELIST_ONLY` evidence |
| Mihomo process | PID, API, TUN, config version | restart/rollback |
| Path node transport | конкретный proxy через конкретный uplink | path-node eligibility |
| Path node bypass | uplink × subscription × node × required targets | `BYPASS_QUALIFIED` |
| Uplink/subscription cell | хотя бы один qualified path node | path matrix status |
| Probe target | результат через независимые uplinks/subscriptions | target outage suppression |
| Direct uplink path | required/optional targets напрямую через uplink mark/table | FULL/LIMITED/WHITELIST_ONLY/FAILED |
| Global access | required/optional targets через active method | PATH_ACTIVE/FULL/LIMITED |
| Management | latest WireGuard handshake | alert only |

ICMP ping не является основной проверкой proxy node. Совпадение имени с `обход`/`lte`/whitelist также не является health result: такой узел обязан пройти configured required targets.

### 9.2 Probe policy

- отдельный лёгкий transport endpoint плюс минимум один пользовательский required bypass target;
- targets выполняются в пользовательском порядке priority;
- ожидаемый HTTP status/body применяется, если настроен; иначе достаточно валидного HTTP response;
- timeout и latency записываются отдельно;
- VPN probes выполняются строго через конкретный proxy и uplink mark/table;
- direct probes выполняются как полноценная qualification отдельно через каждый uplink mark/table;
- интервалы имеют jitter;
- standby checks выполняются реже и с ограничением concurrency;
- scheduler ограничивает concurrency, per-target rate и общий probe traffic budget;
- результаты имеют TTL; stale result не используется для нового переключения;
- health-check не должен создавать заметный мобильный трафик.

Начальные значения budget, уточняемые на этапе 0:

```yaml
probe_budget:
  max_concurrency: 4
  max_concurrency_per_uplink: 2
  max_requests_per_minute: 30
  active_target_interval_seconds: 60
  standby_target_ttl_seconds: 900
  max_response_body_bytes: 65536
  daily_soft_limit_mb_per_uplink: 25
  active_and_failover_reserve_percent: 30
```

При исчерпании soft budget конкретного uplink откладываются его standby requalification probes и получают состояние `DEFERRED_BUDGET`, а не `FAILED`. Проверки active path и кандидата на failover используют зарезервированную долю; после её исчерпания critical probes могут превысить soft limit с отдельным warning event, потому что budget не должен отключать контроль active path. `max_requests_per_minute`, global/per-uplink concurrency и response-size limit остаются hard limits. UI показывает requests/bytes отдельно по uplinks, overage, отложенные probes и прогноз времени полной матрицы. Изменение budget не меняет прошлые health results.

Если один required target одновременно перестал работать через текущий path и несколько независимых комбинаций разных uplinks/подписок, он получает `TARGET_SUSPECT`. Такой общий сбой не запускает бесконечное переключение paths: текущий путь остаётся `DEGRADED_TARGET`, остальные targets продолжают проверяться, а UI показывает отдельную проблему сайта. Target автоматически возвращается в normal policy только после success threshold либо ручного подтверждения. Если независимых путей недостаточно, применяется строгая политика и target не подавляется автоматически.

### 9.3 Матрица uplink × subscription

Каждая ячейка является одной сущностью и содержит:

```yaml
path_cell:
  uplink_id: uplink-a
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
UPLINK_OFFLINE
UPLINK_DISABLED
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

- `QUALIFIED` — хотя бы одна candidate node через этот uplink прошла proxy transport и все enabled `required` targets текущей policy generation;
- `DEGRADED` — активный transport ещё работает, но часть optional checks failed либо идёт подтверждение подозрительного общего target outage;
- `FAILED` — проверка завершена и ни одна candidate node не удовлетворяет required policy;
- `STALE` — исторический успех существует, но TTL/policy/route generation изменились; для нового переключения он запрещён;
- offline/disabled/conflict states не запускают probes и не превращаются в subscription failure.

Конечный список probes не может доказать доступность буквально всего Интернета. Поэтому UI использует точную формулировку **«Доступ подтверждён: N/N обязательных ресурсов»**, отдельно показывает transport state и не пишет «весь Интернет работает». Именно этот операционный статус отображается для каждой подписки через каждый модем и для каждого модема через каждую подписку.

Матрица показывается в двух представлениях без дублирования данных:

- **Subscriptions → Uplinks:** для выбранной подписки видны статусы через каждый uplink, а HiLink показывает дополнительные modem telemetry/recovery fields;
- **Uplinks/Modems → Subscriptions:** для выбранного uplink видны статусы каждой подписки;
- **Path Matrix:** общая таблица, фильтры и принудительная перепроверка ячейки.

Для `Прямого интернета` существует параллельная строка uplink paths с теми же policy/route generation, freshness и target results, но без subscription/node. Поэтому статус direct независим для каждого физического выхода: один uplink может быть `FULL`, другой `LIMITED/WHITELIST_ONLY`, третий `FAILED`.

### 9.3.1 Единый список методов и ranking

`Прямой интернет` автоматически создаётся при первой установке, по умолчанию включён и имеет первый priority. Его можно выключить или переместить, но нельзя удалить. Каждая подписка является следующим элементом того же ordered access-method list. Отключение элемента запрещает только user routing через него и не отменяет разрешённые служебные refresh attempts.

Каждый конкретный candidate получает quality:

- `FULL` — все enabled required targets успешны;
- `LIMITED` — transport работает и успешна только часть target policy; хранится объяснимый functional score;
- `FAILED/STALE/UNTESTED` — для активации непригоден.

Выбор выполняется детерминированно:

```text
FULL
→ среди LIMITED максимальный functional score
→ priority метода
→ priority uplink
→ preferred rank VPN-сервера
→ сохранить текущий путь при полном равенстве
```

Любой `FULL` предпочтительнее любого `LIMITED` независимо от места в priority list. Среди нескольких `FULL` побеждает priority. `LIMITED` используется, если `FULL` отсутствует; более функциональный LIMITED важнее priority, а при равном score применяется priority. Functional score строится из количества/веса доступных required и optional targets и versioned вместе с target policy; frontend его не вычисляет.

Временная операция **«Только прямой интернет»** ограничивает user routing direct-кандидатами, показывает яркий banner и автоматически сбрасывается после reboot или вручную. Она не меняет постоянный ordered list и не останавливает обновления подписок.

### 9.4 Состояние Gateway

```text
BOOTING
  → ALL_UPLINKS_OFFLINE
  → NO_BYPASS_TARGETS
  → NO_WORKING_ACCESS_METHOD
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

- `ACTIVE_UPLINK_DOWN`: немедленно исключить все его paths и выбрать qualified path другого uplink;
- `UPLINK_DOWN`: не переключать подписки внутри offline uplink; для HiLink запускать только bounded recovery этого модема;
- `ALL_UPLINKS_OFFLINE`: PATH_BLOCKED, но desired state и priorities сохраняются;
- `MIHOMO_DOWN`: перезапустить Mihomo с LKG;
- `ACTIVE_DIRECT_DOWN`: выбрать другой FULL/LIMITED/WHITELIST_ONLY direct uplink либо qualified VPN method;
- `ACTIVE_NODE_DOWN`: выбрать другой qualified node той же uplink/subscription cell;
- `ACTIVE_CELL_DOWN`: выбрать следующую subscription на том же uplink, затем следующий uplink;
- `ACTIVE_SUBSCRIPTION_DOWN`: агрегированный UI status; решение принимается по path cells, а не глобально;
- `REQUIRED_TARGET_DOWN`: подтвердить через другие узлы; различить node failure и `TARGET_SUSPECT`;
- `NO_BYPASS_TARGETS`: оставить PATH_BLOCKED и запросить настройку targets;
- `GLOBAL_PROBE_DOWN` при здоровом node transport: пометить degraded и выполнить target matrix confirmation;
- `NO_SUBSCRIPTIONS`: продолжить direct qualification; блокировать только если direct также недоступен/выключен;
- `NO_WORKING_ACCESS_METHOD`: quarantine, сохранить management и продолжать background discovery/qualification.

### 9.6 Failover sequence

1. подтвердить отказ несколькими последовательными probes; hard link/DHCP/route loss подтверждения не ждёт;
2. построить snapshot всех fresh direct и VPN candidates;
3. выбрать лучший quality class, затем применить method/uplink/node priorities;
4. для VPN сохранить текущий healthy node, если новый candidate не лучше по quality/priority после hysteresis;
5. перепроверить candidate tuple без открытия пользовательского LAN path;
6. атомарно закрыть прежнюю generation и применить TUN selection либо direct mark/interface/SNAT;
7. повторить end-to-end probe через фактический активный метод;
8. разрешить новые LAN flows только для этой generation;
9. записать event с method/uplink/subscription/node before/after и объяснением ranking;
10. при ошибке исключить candidate на текущий retry cycle и попробовать следующий;
11. если кандидатов нет — quarantine `PATH_BLOCKED`, не создавая неуправляемый direct route.

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
  failure_hold_seconds: 30
  cooldown_seconds: 60
  recovery_stable_seconds: 120
  failback_stable_seconds: 300
  failback_cooldown_seconds: 900
  modem_reconnect_stable_seconds: 180
```

Failback или переход на восстановившийся более качественный/приоритетный метод разрешён только после `recovery_stable_seconds`, непрерывной стабильности всей preferred path cell и cooldown. Вернувшийся modem сначала проходит `modem_reconnect_stable_seconds` и приоритетную requalification; одно его появление в USB не вызывает переключение. Потеря carrier/DHCP/default route и disappearance USB являются hard failures и используют быстрый путь без `failure_hold_seconds`.

### 9.8 Круглосуточный самоконтроль и bounded recovery

Эксплуатационная цель — `24/7 unattended operation` и максимально достижимая доступность. Формулировка «100% uptime» не является технической гарантией: программно невозможно устранить отключение питания, физический отказ Gateway/USB-хаба, одновременную недоступность всех операторов/VPS или повреждение оборудования. Любое заявленное uptime измеряется по журналу и monitoring interval, а не предполагается по наличию active systemd unit.

Самоконтроль разделяет три класса состояния:

- `LOCAL_COMPONENT_FAILURE`: процесс, event loop, SQLite, firewall generation, broker, Mihomo/TUN, dnsmasq, disk/memory/FD pressure или внутренняя reconciliation loop неисправны;
- `EXTERNAL_CONNECTIVITY_FAILURE`: все модемы offline, mobile registration отсутствует, подписки/узлы/targets либо VPS недоступны при исправном локальном control plane;
- `MAINTENANCE_TRANSACTION`: install/update/restore/safe network apply выполняется или восстанавливается.

Фиксированный signed contour включает: WebUI/API и control plane; SQLite; firewall guard и целостность owned ruleset; privileged network broker; `systemd-networkd`; LAN DNS/DHCP; OpenSSH/SFTP, если он включён; Mihomo/TUN; WireGuard management; optional WireGuard ingress; policy routing; критические фоновые workers; convergence desired/observed generations; verified SQLite backup и WAL; disk/memory/file-descriptor resources; logging export pipeline. Successor добавляет два отдельных компонента: восемнадцатый `management_fabric_routes`, который сверяет per-VPS links, published-resource routes/alias mappings и обе ACL projections, и девятнадцатый `wireguard_admin`, который проверяет optional end-to-end admin interface/relay/peers без объединения их с outer link liveness. Для WireGuard проверяются interface/address/peer/fwmark, owned management и endpoint routes, generation state и свежесть handshake. Старый handshake при исправном локальном интерфейсе/маршрутах является `EXTERNAL_CONNECTIVITY_FAILURE`, а не основанием для restart.

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
  worker_stale_seconds: 120
  wireguard_handshake_stale_seconds: 180
  backup_max_age_hours: 36
  database_wal_max_bytes: 268435456
  minimum_disk_free_bytes: 536870912
  minimum_disk_free_percent: 5
  minimum_memory_available_bytes: 134217728
  minimum_memory_available_percent: 5
  component_recovery_modes:
    control_plane: RESTART
    sqlite: RESTART
    firewall_guard: RESTART
    firewall_ruleset: RESTART
    network_broker: RESTART
    systemd_networkd: RESTART
    dnsmasq: RESTART
    openssh_sftp: RESTART
    mihomo: RESTART
    wireguard_management: RESTART
    wireguard_admin: RESTART
    wireguard_ingress: RESTART
    policy_routing: RESTART
    management_fabric_routes: RECONCILE
    worker_runtime: RESTART
    configuration_convergence: RESTART
    database_backup: RESTART
    logging_pipeline: RESTART
    resources: MONITOR_ONLY
  host_reboot_enabled: false
  reboot_after_critical_seconds: 900
  max_reboots_per_24h: 1
  reboot_grace_seconds: 60
```

Для каждого из девятнадцати компонентов successor выбирается только один поддерживаемый режим: `MONITOR_ONLY`, `RECONCILE` или `RESTART`; WebUI не может добавить unit, executable, interface, route либо command. Список компонентов, допустимые для каждого режима действия, порядок restart, fixed executable/systemd unit names и признаки critical failure зашиты в signed release. Изменение policy не сбрасывает durable restart/reboot history. Web UI показывает effective policy, состояние каждого компонента, last success/failure/recovery, число попыток и причину suppression. Все автоматические actions попадают в events/journald и diagnostic bundle без secrets.

---

## 10. WireGuard management plane

### 10.1 Базовый совместимый профиль и граница successor

Базовый односерверный профиль WireGuard предоставляет удалённый доступ к:

- Web UI/API Gateway на `10.80.0.2`;
- SSH Gateway, если функция включена;
- диагностике Gateway.

Маршрут в `192.168.200.0/24` или `192.168.50.0/24` на Gateway peer автоматически не добавляется. Доступ к Keenetic и локальным сетям является отдельной default-off публикацией ресурса по §§10.8–10.10, а не расширением любых `AllowedIPs` без ACL.

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

Поскольку Gateway имеет `Address = 10.80.0.2/32`, controller отдельно и идемпотентно владеет маршрутом `10.80.0.0/24 dev wg-mgmt protocol 186` для совместимого первого link. Watchdog требует его точного наличия; route не выводится через active subscription или modem table и удаляется вместе с managed WireGuard contour. Каждый дополнительный link получает такой же owned route только к собственной непересекающейся management subnet через свой `gvm<N>`; общий wildcard route ко всем private networks запрещён.

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

### 10.5 Доступ к Keenetic и Home LAN

Обычный режим остаётся неизменным: Keenetic получает Internet через свой WAN от Gateway. Удалённый management path не заменяет WAN, DHCP/NAT или default route Keenetic. Доступ через VPS к локальным ресурсам выключен по умолчанию и включается для каждого ресурса одним из проверяемых профилей:

1. `GATEWAY_ONLY` — только WebUI/API/SSH/SFTP самого Gateway;
2. `KEENETIC_WAN` — только явно разрешённые management ports транзитного WAN-адреса Keenetic; требуется подтверждённое разрешение сервиса/firewall Keenetic;
3. `VIA_KEENETIC_WAN_ROUTED` — Gateway маршрутизирует разрешённые host/subnet destinations через WAN-адрес Keenetic; Keenetic должен иметь явное WAN→LAN firewall rule и проверенный обратный путь;
4. `VIA_WG_ROUTER` — отдельный Keenetic/router peer типа `ROUTER_ROUTED` объявляет behind-subnets; обычный Internet Keenetic по-прежнему идёт через WAN, а WireGuard переносит только заданные management/local prefixes без `0.0.0.0/0`;
5. `VIA_DEDICATED_LAN` — отдельный Ethernet/VLAN Gateway подключён к LAN-side Keenetic/switch как management-only interface без default route и DHCP server.

`VIA_WG_ROUTER` может использовать существующий отдельный `wg-ingress` peer, но только через новое строгое правило `разрешённый wg-mgmt admin → разрешённый ROUTER_ROUTED peer/resource`; management и ingress keys/interfaces не объединяются. `VIA_KEENETIC_WAN_ROUTED` и `KEENETIC_WAN` не считаются готовыми только из-за ping: проверяются нужный TCP/UDP port, forward policy и return traffic. Gateway не пытается тайно изменить Keenetic; WebUI показывает точные внешние шаги и оставляет resource в `WAITING_EXTERNAL_CONFIGURATION`, пока fresh probe не подтвердит путь.

### 10.6 Входящий WireGuard `wg-ingress`

`wg-ingress` является отдельным optional data-plane server и не переиспользует keys, subnet, port или policy management-интерфейса `wg-mgmt`. Он принимает пользовательский трафик от Keenetic, отдельного router peer либо device peers и передаёт его в тот же unified selector `uplink × access method`.

Поддерживаются профили peer:

- `DEVICE` — один tunnel IPv4 и full/split-tunnel client configuration;
- `ROUTER_NAT` — несколько устройств за роутером представлены одним tunnel address;
- `ROUTER_ROUTED` — за peer объявлены явные непересекающиеся IPv4 subnets, а Gateway сохраняет исходные client addresses.

Web UI имеет отдельную вкладку **«WireGuard-клиенты»**: server enable/listen interface/UDP port/subnet/MTU/DNS/endpoint, server public key и rotation; client add/edit/enable/disable/revoke/delete, stable address allocation, public key, AllowedIPs/behind-subnets, keepalive, last handshake, masked endpoint, RX/TX, health, audit и фильтр журнала. Готовый standard `.conf`, QR и copyable fields доступны для managed client; пользователь также может добавить собственный public key.

В режиме managed keypair client private key хранится только отдельным root-owned `0600` secret file, никогда не в SQLite/log/diagnostic bundle, и повторная выдача требует свежей password re-authentication и audit event. В режиме external key Gateway хранит только public key и не может повторно выдать private-key-ready config. Revoke удаляет peer из active generation до ответа API; key rotation атомарно заменяет peer и отзывает прежний public key.

Peer по умолчанию получает policy **«Автоматический общий путь»**. Дополнительно разрешены bounded profiles: только выбранные access methods, VPN-only без direct fallback, разрешение/запрет `WHITELIST_ONLY`, либо block при отсутствии подходящего пути. Arbitrary nft/ip commands и произвольные marks из Web UI не принимаются.

Однокарточный режим официально поддерживается: outer `wg-ingress` UDP приходит через shared Ethernet, decapsulated traffic классифицируется по `iifname=wg-ingress`, а Mihomo proxy sockets/direct SNAT выходят через тот же physical uplink с другим mark/conntrack generation. Firewall принимает listen port только на явно выбранных interfaces; по умолчанию это local Ethernet, публичная WAN exposure является отдельной default-off policy. Endpoint, собственный address Gateway и service/proxy flows обязаны обходить возвращающую WireGuard policy Keenetic. Apply отклоняется при route recursion, overlapping peer AllowedIPs, duplicate address/public key, management subnet overlap или отсутствии гарантированного return path.

### 10.7 Many-to-many Management Fabric

Successor поддерживает одновременно:

- `1 VPS → N Gateway`: один VPS имеет уникальный peer `/32`, immutable `site_id` и public key для каждого Gateway;
- `1 Gateway → N VPS`: Gateway хранит несколько независимых `management_link`, каждый со своим VPS endpoint, WireGuard keypair, interface slot, непересекающейся subnet/address и route generation;
- `N Gateway ↔ N VPS`: один Gateway может быть зарегистрирован на нескольких VPS, а один VPS — обслуживать несколько Gateway без общей private key или общей writable policy.

Все enabled management links поддерживаются активными одновременно. Priority не выключает резервный туннель: он влияет только на preferred URL/config и порядок выбора при явно управляемом admin-side failover. Каждый link независимо выбирает physical uplink по policy `AUTO`, `PINNED_WITH_FALLBACK` либо `PINNED_ONLY`, создаёт endpoint host route в его table и не зависит от active user subscription path. Отказ одного VPS/link не изменяет data plane и не перезапускает другие links.

Первый существующий `wg-mgmt` является совместимым link slot 0. Новые links получают bounded Linux-safe names `gvm1`, `gvm2`, …; slot не переиспользуется автоматически после удаления. Одинаковые management subnet, Gateway/admin addresses или перекрывающиеся `AllowedIPs` разных peers отклоняются до apply. Пример `10.80.0.0/24` остаётся только default первого link, а мастер предлагает свободные непересекающиеся ranges после проверки всех host/uplink/transit/ingress/local routes.

Gateway не требует внешнего IP или port forwarding: каждый link сам инициирует UDP к VPS и использует `PersistentKeepalive`. VPS endpoint может иметь несколько заранее подтверждённых IP/port candidates; DNS разрешается отдельно через каждый eligible uplink, последний успешный IP сохраняется до bounded expiry. Автоматический management-over-Mihomo не включается: он создаёт зависимость от data plane и допускается только как будущий отдельный profile после доказанного loop-free UDP path.

### 10.8 Идентичность, pairing и ключи

- каждый Gateway имеет immutable random `site_id` и изменяемое понятное имя;
- каждый `Gateway ↔ VPS` link имеет отдельную WireGuard keypair; private key не покидает создавшую её сторону и хранится только root-owned secret file;
- VPS создаёт одноразовый bounded pairing bundle/token с endpoint, VPS public key, назначенными addresses/prefixes, expiry и fingerprint; Gateway показывает fingerprint до подтверждения и возвращает только свой public key;
- повторное использование, истёкший token, subnet collision или несовпадающий fingerprint отклоняются без частично активного peer;
- rotation выполняется make-before-break: новый peer/link обязан получить handshake и пройти management probe до отзыва старого;
- один admin device получает отдельный key/address на каждом VPS, shared administrator configs запрещены; revoke удаляет peer и ACL generation до успешного ответа.

Restore на заменяющее железо имеет два разных режима. **«Восстановить тот же Gateway»** сохраняет `site_id`, но требует отозвать/заменить прежние link keys до снятия quarantine; одновременно active старый и восстановленный экземпляры с одной identity запрещены и обнаруживаются как endpoint flap. **«Создать новый Gateway из настроек»** всегда генерирует новый `site_id`, все management/admin keys и pairing, не копируя сетевую identity исходного site.

VPS не хранит пароль WebUI Gateway, subscription URLs, proxy credentials либо Gateway private keys. Optional VPS Hub показывает зарегистрированные Gateway, links/resources и открывает их собственные HTTPS WebUI, но не подменяет их аутентификацию.

### 10.9 Публикуемые локальные ресурсы

Management Fabric маршрутизирует не произвольную LAN, а typed сущности `management_resource`:

- `GATEWAY_SERVICE` — WebUI/API/SSH/SFTP Gateway;
- `KEENETIC_SERVICE` — конкретный host/protocol/port Keenetic;
- `LOCAL_HOST` — один локальный IPv4 и разрешённые protocols/ports;
- `LOCAL_SUBNET` — целая явно подтверждённая IPv4 subnet;
- `CUSTOM_SERVICE` — один host/port с проверяемым health probe.

Resource хранит local destination, access profile из §10.5, enabled, health, local route generation и список допущенных administrators/groups. Отдельная `resource publication` для каждого VPS link хранит собственный published alias address/prefix и applied ACL generation. `LOCAL_SUBNET` является advanced destructive-scope permission с отдельным impact preview; default — минимальные host/port resources. L2 bridging, broadcast discovery, mDNS/SSDP relay и Internet forwarding через management fabric по умолчанию отсутствуют.

### 10.10 Пересекающиеся локальные подсети

Несколько Gateway часто имеют одинаковые `192.168.50.0/24` или `192.168.1.0/24`; VPS не может назначить один destination prefix разным WireGuard peers. Поэтому каждой комбинации `site × resource × VPS link` выделяется уникальный непересекающийся published alias prefix из resource pool соответствующего VPS. Например, локальные `192.168.50.0/24` двух Gateway на VPS-A могут публиковаться как `10.96.1.0/24` и `10.96.2.0/24`; публикация первого Gateway через VPS-B получает ещё один отличный prefix из pool VPS-B.

Gateway выполняет только owned typed L3 alias translation `published prefix ↔ local prefix` и при необходимости source translation на подтверждённый return-path address; nftables/conntrack generation применяется атомарно вместе с route и ACL. Alias не меняет адреса устройств и никогда не используется data plane. Pool/alias проверяются против всех connected/static/policy/WireGuard/uplink subnets на Gateway, VPS и admin profile; конфликт блокирует apply.

Portable baseline выдаёт администратору отдельный конфиг/management address и отдельные resource aliases для каждого VPS, поэтому оба tunnels могут быть подняты с непересекающимися routes. UI показывает оба адреса одного logical resource как **«через VPS-A»** и **«через VPS-B»**. Один WireGuard interface с двумя peers и одинаковыми `AllowedIPs` запрещён: стандартный WireGuard не выполняет health-based peer selection. Полностью прозрачный failover одного и того же alias через несколько VPS требует отдельного управляемого admin client/OS route metrics и не заявляется без такого компонента.

### 10.11 Двухсторонние ACL и изоляция

VPS и Gateway независимо применяют одну versioned access generation:

- `admin peer → разрешённые site/resource alias prefixes → разрешённые protocols/ports`;
- Gateway↔Gateway, admin↔admin, management→user Internet и доступ к непубликованной LAN запрещены;
- source address проверяется WireGuard `AllowedIPs`, затем VPS firewall и повторно Gateway firewall;
- произвольные route, nft expression, interface или command из WebUI/API не принимаются;
- изменение ACL/resources выполняется make-before-break, требует acknowledgement всех required VPS и откатывается при несовпадении generation;
- partial VPS outage не удаляет рабочую предыдущую ACL generation на остальных VPS; UI показывает `APPLIED`, `PARTIAL`, `PENDING_RETRY` либо `ROLLED_BACK` по каждому link.

#### 10.11.1 Trust modes и end-to-end administrator tunnel

Базовый `ROUTED_HUB` заканчивает admin WireGuard на VPS и затем маршрутизирует трафик в outer Gateway link. Он прост и достаточен для HTTPS WebUI/SSH/SFTP, которые имеют собственное шифрование и аутентификацию, но полностью скомпрометированный VPS технически способен видеть network metadata и имитировать source address admin peer внутри доверенного management link. Double ACL защищает от ошибки/обычного чужого peer, но не выдаётся за криптографическую защиту от владельца VPS private key.

Для доступа к Keenetic/local resources рекомендован `END_TO_END_RELAY`:

1. Gateway поднимает отдельный `wg-admin` с administrator peers и root-only keys;
2. VPS выделяет этому site allowlisted public UDP relay port и пересылает только зашифрованные WireGuard datagrams через outer management link на `wg-admin` listen port Gateway;
3. inner tunnel завершается на Gateway, поэтому VPS не имеет admin private/session key, не расшифровывает payload и не может создать валидный admin packet;
4. Gateway ACL связывает resource grants с authenticated inner admin peer/address; outer VPS peer получает только health/pairing/relay permissions и не получает прямой local-resource forwarding;
5. компрометированный VPS всё ещё может блокировать/replay старые UDP datagrams или создать DoS, но не расшифровать сессию и не имитировать новый authenticated admin traffic.

Каждый relay имеет bounded fixed port allocation, rate limit, source-independent WireGuard authentication и отдельную operation generation. Portable config использует конкретный VPS relay endpoint; резервный VPS выдаёт второй config/endpoint. Автоматически помещать один и тот же `AllowedIPs` двум peer endpoints нельзя. `ROUTED_HUB` для raw local resources допускается только отдельным предупреждаемым opt-in; WebUI/SSH всё равно сохраняют собственную authentication независимо от trust mode.

### 10.12 Состояния, watchdog и восстановление

Каждый management link имеет состояния `DISABLED`, `CONFIGURED`, `CONNECTING`, `REACHABLE`, `DEGRADED`, `ENDPOINT_UNREACHABLE`, `AUTH_FAILED`, `ROUTE_CONFLICT` и `STALE`. Наблюдаются interface/key/address, endpoint DNS/IP, selected uplink/table/fwmark, latest handshake, RX/TX progress, RTT, VPS acknowledgement, resource route/ACL generation и freshness probes.

Recovery выполняется только для неисправного link: re-resolve endpoint → сменить eligible uplink → idempotent route reconcile → `wg syncconf` → recreate конкретного interface после budget. Недоступность внешнего VPS классифицируется как external outage, не вызывает restart других links или reboot host. Corrupt local key/config, исчезнувший owned route либо generation mismatch являются local failure и проходят bounded recovery. Watchdog отдельно подтверждает, что management paths не попали в Mihomo/user traffic accounting и не создали main-table default route.

### 10.13 WebUI и VPS Hub

Gateway WebUI получает отдельную предметную группу **«Удалённый доступ»** с подстраницами **«VPS и каналы»**, **«Администраторы»**, **«Локальные ресурсы»** и **«Матрица доступа»**. На ней видны все links одновременно, selected uplink, endpoint/handshake/RTT, pairing/rotation, `ROUTED_HUB`/`END_TO_END_RELAY`, relay port/inner peer health, resource access profile, external prerequisites, alias, ACL generation и точная причина недоступности.

VPS Hub является минимальным отдельным WebUI/API VPS-роли, доступным только через admin WireGuard либо localhost. Он управляет Gateway public peers, admin peers, assigned prefixes и ACL, показывает handshake/last seen и ссылки на WebUI каждого Gateway. Он не является публичным reverse proxy и не хранит Gateway passwords/secrets. Pairing и любое route/ACL изменение имеют operation ID, durable stages, audit, retry и terminal receipt.

Для удобства VPS Hub может выдавать только внутри admin tunnel локальные DNS-имена Gateway/resources в отдельной выбранной private zone; IP/alias всегда остаются видимыми и пригодными как fallback. Имена нормализуются, не публикуются в public DNS и не являются identity/ACL key. WebUI показывает для одного logical resource все варианты **«через VPS …»**, копируемый адрес/имя и кнопку проверки именно этого пути.

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

`nodes` хранит только subscription-level identity и классификацию кандидата. Health/latency/qualification не хранятся глобально в `nodes`: в исходной схеме они принадлежат `path_nodes`, потому что одна node может быть доступна через uplink A и недоступна через uplink B. Аналогично target result всегда привязан к `path_id + node_id + target_id`.

До successor migration `subscription_modem_paths` является единственным источником текущего состояния матрицы. После атомарного переноса единственным writable source становится `subscription_uplink_paths`; legacy modem-specific таблицы остаются read-only только на ограниченное окно совместимости и затем удаляются отдельной проверенной migration. Приложение дополнительно валидирует, что `selected_node_id` относится к active version соответствующей subscription. Все foreign keys и индексы проверяются migration tests; удаление uplink/subscription каскадно удаляет только производные path results, но операция Forget/Delete до commit создаёт audit event и требует подтверждения.

### 12.2.1 Расширение для unified access policy

Историческая базовая схема выше расширяется только последовательными migration, без переписывания применённых файлов:

- `access_methods` — единый ordered list: immutable `DIRECT` и одна `SUBSCRIPTION`-строка на подписку; `enabled/priority` относятся к user routing, а не к auto-refresh;
- `direct_modem_paths` — историческая до-successor таблица независимой qualification direct modem path; successor переносит её в `direct_uplink_paths` с сохранением path ID;
- `direct_path_target_results` — target evidence для direct без фиктивной subscription/node;
- `subscription_node_preferences` — durable `AUTO/INCLUDE/EXCLUDE`, preferred rank и пользовательская метка по `(subscription_id, fingerprint)`, переживающие смену immutable version;
- `access_policy` — singleton с startup gate, failure/recovery/cooldown intervals, ranking generation и разрешением service direct refresh;
- `access_selection_runtime` — restart-safe hysteresis evidence, last switch и boot-scoped temporary direct-only mode;
- `operations` и `operation_steps` — bounded redacted журнал ручных/автоматических refresh, probe, qualification и switch operations.

`runtime_state` получает `active_method_id`, `active_method_kind` и `active_quality_class`. Для VPN прежние subscription/node fields заполнены; для direct они `NULL`. Compatibility code не трактует `NULL` subscription как разрешение direct: method kind, modem, route generation и firewall generation проверяются вместе.

Functional score и selection explanation являются server-side данными одной policy generation. `FULL` не кодируется искусственным максимальным latency; quality class сравнивается до score. Старые direct/VPN результаты после target, route или ranking policy change становятся `STALE` и не используются для новой активации.

### 12.2.2 Successor migration: generic uplinks и WireGuard ingress

Новая миграция не переименовывает существующие таблицы «на месте» с потерей доказуемости. Она создаёт generic source of truth и атомарно переносит каждый `modems.id` в `uplinks.id` типа `HILINK`. На ограниченное migration window database-owned compatibility bridge принимает только записи ещё не перенесённых HiLink-компонентов и в той же SQLite transaction проецирует их в generic tables; отдельного legacy UI/API и обратной синхронизации generic→legacy нет. После переноса всех readers/writers bridge и legacy tables удаляются следующей проверенной migration.

- `network_interfaces` — stable hardware identity, observed ifname/model/driver/carrier/address и replacement history;
- `interface_role_assignments` — `LAN_MEMBER`, `MANAGEMENT`, `ETHERNET_UPLINK`, `WG_ENDPOINT`, explicit shared one-arm profile и desired/observed generation;
- `uplinks` — type `HILINK|ETHERNET`, display number/name, enabled/priority, NIC/modem reference, DHCP/static config, route table/fwmark, state/generations;
- `hilink_modems` — USB/API/operator/telemetry/recovery fields по FK `uplink_id`, без дублирования priority/routes;
- `subscription_uplink_paths` и `direct_uplink_paths` принимают все новые writes вместо modem-specific path tables; связанные generic node/target evidence tables также переносятся с сохранением прежних path IDs;
- target results содержат class и exact `uplink_id/path/node/policy_generation/route_generation` evidence;
- `wireguard_ingress_servers`, `wireguard_ingress_peers`, `wireguard_ingress_peer_routes` и `wireguard_ingress_runtime` хранят только non-secret configuration/status; private keys находятся в secret files;
- `modem_recovery_policy`, `modem_recovery_runtime` и `modem_recovery_attempts` сохраняют cooldown/budget/generation/outcome независимо от process restart;
- `log_export_policy` хранит retention/rotation/category enable state, но не произвольные filesystem paths.

Runtime active tuple получает `active_uplink_id`; legacy `active_modem_id` читается только при migration и затем не является источником выбора. Существующие path IDs сохраняются без изменения, а отдельная migration map фиксирует соответствие legacy modem ID и нового uplink ID, чтобы events/history и LKG не стали указывать на другую комбинацию. Перед migration создаётся SQLite Online Backup; downgrade использует pre-migration snapshot, а не обратное преобразование generic schema.

### 12.2.3 Successor migration: Management Fabric

Management Fabric добавляется новой gap-free migration без изменения существующего link до проверки новой проекции:

- `gateway_sites` — singleton immutable `site_id`, display name и current identity generation;
- `vps_nodes` — endpoint candidates, verified fingerprint/public key, enabled и metadata без private credentials;
- `management_links` — VPS, stable interface slot, local/remote addresses, management subnet, secret refs, uplink policy, desired/applied route generation и state;
- `management_link_endpoints` — resolved/probed IP/port/uplink candidates, freshness и redacted failure code;
- `management_admins` и `management_admin_vps_peers` — administrator identity, per-VPS public peer/address, revoke state и config grant metadata;
- `management_admin_tunnels` и `management_admin_relays` — optional Gateway-terminated `wg-admin` peers, per-VPS UDP relay allocation, desired/applied generation и trust mode;
- `management_resources` — type, local destination, access profile, protocols/ports, health и external prerequisite state;
- `management_resource_publications` — resource×VPS-link alias address/prefix, desired/applied route/ACL generations и publication state;
- `management_resource_acl` — explicit administrator/group→resource grants;
- `management_fabric_generations` и `management_fabric_operations` — desired/per-VPS applied generations, retry/rollback stages и terminal receipts.

WireGuard private keys/PSK, reusable pairing secrets и downloadable admin private configs в SQLite не хранятся. Существующий `wg-mgmt` импортируется как link slot 0 только после проверки exact interface/address/route/peer; при неоднозначности migration оставляет прежний runtime неизменным и требует ручного adoption. VPS-role database использует те же IDs/generations для public peers, relay allocation и ACL projection, но не получает Gateway application DB или credentials.

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

- общий пользовательский RX/TX через активный VPN- или direct-метод;
- текущая общая скорость;
- daily/monthly aggregation общего трафика;
- общий traffic за active session с раздельным dimension `VPN/DIRECT`, но без ложной per-subscription attribution;
- служебный direct-трафик отдельно от пользовательского.

**Зафиксированное решение MVP — Option A:** per-subscription и per-proxy traffic attribution не предоставляется. UI и API не показывают приблизительные значения по подпискам. Такая детализация может быть добавлена после MVP отдельным этапом без изменения data plane.

### 13.2 Источники

- nftables counters после LAN policy gate — authoritative общий пользовательский объём и для TUN, и для выбранного direct path;
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
GET    /api/v1/access-methods
PUT    /api/v1/access-methods/priorities
PATCH  /api/v1/access-methods/{id}
POST   /api/v1/access-methods/direct-only
DELETE /api/v1/access-methods/direct-only

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

GET    /api/v1/network/interfaces
GET    /api/v1/uplinks
POST   /api/v1/uplinks/ethernet
GET    /api/v1/uplinks/{id}
PATCH  /api/v1/uplinks/{id}
DELETE /api/v1/uplinks/{id}
PUT    /api/v1/uplinks/priorities
POST   /api/v1/uplinks/{id}/probe
POST   /api/v1/uplinks/{id}/replace-interface
PUT    /api/v1/uplinks/{id}/network
POST   /api/v1/network/roles/preview

GET    /api/v1/subscriptions
POST   /api/v1/subscriptions
GET    /api/v1/subscriptions/{id}
PATCH  /api/v1/subscriptions/{id}
DELETE /api/v1/subscriptions/{id}
POST   /api/v1/subscriptions/{id}/refresh
POST   /api/v1/subscriptions/refresh
POST   /api/v1/subscriptions/{id}/probe
POST   /api/v1/subscriptions/{id}/source/probe
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

GET    /api/v1/wireguard-ingress
PUT    /api/v1/wireguard-ingress
GET    /api/v1/wireguard-ingress/peers
POST   /api/v1/wireguard-ingress/peers
PATCH  /api/v1/wireguard-ingress/peers/{id}
DELETE /api/v1/wireguard-ingress/peers/{id}
POST   /api/v1/wireguard-ingress/peers/{id}/rotate
POST   /api/v1/wireguard-ingress/peers/{id}/probe
POST   /api/v1/wireguard-ingress/peers/{id}/reauth
GET    /api/v1/wireguard-ingress/peers/{id}/config
GET    /api/v1/wireguard-ingress/peers/{id}/qrcode

GET    /api/v1/health
GET    /api/v1/health/history
GET    /api/v1/health/supervisor
POST   /api/v1/health/supervisor/recover
GET    /api/v1/events
GET    /api/v1/logs
GET    /api/v1/logs/export
GET    /api/v1/operations
GET    /api/v1/operations/{id}
DELETE /api/v1/operations/completed

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

GET    /api/v1/management/vps
POST   /api/v1/management/vps/pair
POST   /api/v1/management/vps/{id}/rotate
DELETE /api/v1/management/vps/{id}
GET    /api/v1/management/admins
POST   /api/v1/management/admins
POST   /api/v1/management/admins/{id}/revoke
GET    /api/v1/management/resources
POST   /api/v1/management/resources
PUT    /api/v1/management/resources/{id}
DELETE /api/v1/management/resources/{id}
GET    /api/v1/management/access-matrix
POST   /api/v1/management/apply

POST   /api/v1/system/backup
POST   /api/v1/system/restore
GET    /api/v1/system/power/capabilities
POST   /api/v1/system/reboot
POST   /api/v1/system/shutdown
POST   /api/v1/system/power-cycle
```

`GET /paths/matrix` является каноническим read model для Dashboard, **Выходы в интернет**, **Модемы**, **Подписки** и **Матрица путей**. Ответ содержит direct uplink paths и одну запись на пару `uplink_id × subscription_id`, выбранную node, quality/functional score, свежесть результата и объяснимый reason code. Frontend не вычисляет health или ranking самостоятельно. Legacy modem routes являются alias на HiLink uplink и не образуют вторую матрицу.

Ручная активация path разрешена только при свежем `QUALIFIED` в текущих `policy_generation` и `route_generation`. Emergency override является отдельной привилегированной операцией с предупреждением, TTL, audit event и не разрешает direct path. Reorder modem/subscription priorities атомарен: сервер принимает полный упорядоченный список IDs и проверяет его на дубликаты/пропуски. Изменение порядка обновляет ranking generation, но не инвалидирует свежие probe results и не обрывает текущий path; новый порядок применяется при следующем failover, явной активации или штатном failback после hysteresis.

### 14.3 Web UI

Web UI разделяется по предметным областям; одна настройка имеет одного владельца и не дублируется на нескольких страницах. Sidebar не является плоским списком из десятков пунктов: он показывает шесть понятных групп, внутри которых открываются самостоятельные вкладки/подвкладки. Последняя выбранная подстраница и фильтры сохраняются локально, breadcrumbs и deep links ведут к конкретному объекту, а mobile navigation использует тот же порядок в drawer.

1. **Обзор**
   - **Состояние Gateway:** active tuple `метод → uplink → [подписка → node]`, quality, причина переключения, management links, traffic и критические предупреждения.
   - **Состояние и операции:** persistent operation panel, stages/timeline, outages, probe budget и объяснение failover.

2. **Интернет и VPN**
   - **Способы доступа:** ordered list `Прямой интернет + подписки`, enable/priority, FULL/LIMITED, startup gate и temporary direct-only.
   - **Выходы в интернет:** Ethernet/HiLink uplinks, priority, DHCP/static IPv4, direct/VPN summary, replacement и причина выбора.
   - **Модемы:** HiLink discovery/adoption, operator/telemetry, hot-plug, recovery и статусы методов.
   - **Подписки:** refresh/LKG, masked URL, candidate counts, server policies и статусы через каждый uplink.
   - **VPN-серверы:** `AUTO/INCLUDE/EXCLUDE`, preferred rank и per-uplink/target results.
   - **Матрица путей:** canonical `uplink × access method` с quality/freshness/reason/manual probe.
   - **Серверы проверки доступа** и **Правила отбора серверов:** target classes, CRUD/priority и matcher preview остаются разными вкладками, потому что решают разные задачи.

3. **Сеть**
   - **Топология и интерфейсы:** physical inventory, ingress/management/uplink roles, topology profile, replacement и safe apply.
   - **Локальная сеть Gateway:** transit LAN, DHCP/DNS, Keenetic WAN reservation и read-only advanced routes/marks.
   - **Входящие WireGuard-клиенты:** отдельный `wg-ingress`, peers, keys/config/QR, policies, handshake/RX/TX; эта страница не смешивается со служебным `wg-mgmt`.

4. **Удалённый доступ**
   - **VPS и каналы:** `1..N` links, pairing/rotation, selected uplink, endpoint/handshake/RTT и independent health.
   - **Администраторы:** отдельные peers/configs, `ROUTED_HUB`/`END_TO_END_RELAY`, revoke и разрешённые sites/resources.
   - **Локальные ресурсы:** Gateway/Keenetic/hosts/subnets, access profile, local destination, published alias, ports, health и external prerequisites.
   - **Матрица доступа:** `administrator × VPS × Gateway × resource`, effective ACL/generation и объяснение `почему доступно/недоступно`.

5. **Наблюдение**
   - **Журнал:** один canonical stream с тематическими вкладками и object deep links.
   - **Трафик:** current/daily/monthly total и CSV без ложной per-subscription детализации.
   - **Самоконтроль 24/7:** девятнадцать fixed components successor, effective recovery policy, history и suppression reasons.

6. **Система**
   - **Обновление и обслуживание:** version, update, backup/restore, diagnostic bundle и uninstall.
   - **Безопасность:** users/sessions, TLS, SSH/SFTP, audit и key rotations.
   - **Питание:** manual reboot/shutdown и capability-gated RTC power-cycle.

Overview показывает только сводку и ссылки **«Открыть подробности»**; CRUD/advanced forms в него не копируются. Страница объекта использует один compact status header и локальные секции, а длинные tables получают server-side pagination/virtualization. Advanced network/CIDR/AllowedIPs/NAT details скрыты за **«Дополнительными сведениями»**, но ошибки всегда формулируются понятным языком и указывают точную вкладку исправления.

Каждая настройка имеет видимое понятное название, короткое inline-объяснение и help trigger. На desktop подсказка появляется после bounded hover delay, при keyboard focus — немедленно, на touch — по нажатию `?`; hover не является единственным способом получить описание. Help сообщает назначение, рекомендуемое значение и причину, prerequisites, точные последствия, возможность потери управления/Internet, restart/requalification, rollback и пример. Обычный режим скрывает CIDR/fwmark/table/AllowedIPs за **«Дополнительными сведениями»**, advanced mode всё равно принимает только typed validated values, а не arbitrary commands.

Перед сохранением risky settings Web UI показывает mutation/impact preview: какие роли/addresses/firewall/routes/services изменятся, ожидаемое краткое прерывание, confirmation path и deadline rollback. Dashboard и каждая detail card имеют **«Почему выбран этот путь»**, **«Открыть журнал объекта»** и конкретный recovery next step. Термин `PATH_BLOCKED` остаётся внутренним; пользователь видит **«Нет доступного интернет-канала»** с причиной и состоянием продолжающейся диагностики.

Operation panel показывает стадии `QUEUED → ROUTE_SELECTED → DNS → TLS → HTTP → IMPORT → VALIDATE → QUALIFY → ACTIVATE → COMPLETE/FAILED`, timestamps и безопасные reason codes. Backend error text, URL credentials и proxy secrets не отображаются. Ручная кнопка немедленно возвращает operation ID; обновление страницы не теряет статус.

Карточка **Питание** не смешивает ручные действия пользователя с автоматической recovery policy. `Перезагрузить` и `Выключить` требуют свежей password re-authentication, отдельного typed confirmation и короткого отменяемого countdown. `Выключить и включить через N секунд` доступно только после server-side проверки RTC device, `rtcwake` и поддержки wake-from-S5 конкретной системой; допустимый интервал bounded и по умолчанию равен 30 секундам. Таймер считается от отправки команды, а Web UI явно предупреждает, что фактическое время в состоянии S5 короче на длительность корректного shutdown. Если UEFI/RTC не подтверждены, Web UI показывает функцию как недоступную и не обещает автоматическое включение. Все power actions имеют operation ID и audit event и отклоняются во время install/update/restore, network safe apply, backup mutation или другой power operation. Root broker принимает только enum `REBOOT`, `SHUTDOWN`, `RTC_POWER_CYCLE` и bounded delay, никогда не принимает command, unit или path из API/SQLite.

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

- API слушает только owned LAN/management bridge addresses и local addresses всех enabled `wg_management_<link_id>`; dedicated Ethernet/HiLink uplinks и public VPS interface никогда не являются bind targets;
- порт по умолчанию `8443`;
- TLS обязателен;
- при первом запуске генерируется локальная Gateway CA и leaf certificate со stable site hostname/current management SAN; пользователю показывается CA fingerprint, а добавление management link выполняет leaf rotation без молчаливой смены доверенной CA;
- позднее допускается пользовательский certificate;
- пользовательский certificate перед apply проверяется на key match, expiry и покрытие stable hostname; отсутствие нового IP SAN не блокирует hostname access, но показывается как понятное предупреждение;
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
- подмена admin source полностью скомпрометированным routed-hub VPS и abuse публичного UDP relay;
- повторное использование pairing token или подмена VPS fingerprint;
- route/AllowedIPs injection, пересечение alias pool и доступ не к тому Gateway при одинаковых Home LAN;
- lateral movement Gateway↔Gateway либо admin↔admin через общий VPS;
- рассинхронизация ACL generations между Gateway и несколькими VPS;

---

## 16. Логи, события и диагностика

### 16.1 Логирование

- приложение пишет structured logs в journald;
- типы: `system`, `uplink`, `modem`, `path/access`, `subscription/node`, `mihomo`, `network/firewall/dns/dhcp`, `wireguard-management`, `management-fabric/resource-acl`, `wireguard-ingress`, `watchdog/recovery`, `update/backup`, `auth/audit`;
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

Web UI показывает один canonical stream в тематических вкладках **Все**, **Модемы**, **Подписки и VPN-серверы**, **Доступ и переключения**, **VPN/Mihomo**, **Сеть**, **Удалённый доступ/VPS/ресурсы**, **WireGuard-клиенты**, **Watchdog**, **Обновления/backup** и **Безопасность/audit**. Фильтр конкретного uplink/modem/subscription/node/VPS/link/admin/resource/peer/operation доступен как deep link из соответствующей карточки. Очистка UI-селекции не удаляет audit; удаление eligible operational history подчиняется retention и отдельному подтверждению.

Journald остаётся единственным authoritative журналом. Bounded exporter создаёт redacted human-readable snapshots/rotated archives только по фиксированному owned пути:

```text
/var/log/gateway-vpn/
├── current/
│   ├── all.log
│   ├── modems.log
│   ├── subscriptions.log
│   ├── access.log
│   ├── vpn-mihomo.log
│   ├── network.log
│   ├── wireguard-vps.log
│   ├── watchdog.log
│   ├── updates.log
│   └── security-audit.log
├── archive/
└── diagnostics/
```

Files создаются atomic rename, имеют bounded size/age/disk budget и независимо проходят второй redaction pass. Они не являются новым источником recovery или UI state. Стандартный OpenSSH/SFTP остаётся без отдельного SFTP daemon/account: пользователь входит тем же Ubuntu SSH account через management/LAN либо разрешённый `wg-mgmt` и скачивает эти файлы. Installer проверяет, что выбранный административный account имеет read-only group access; WebUI password с Linux/SFTP password не объединяется. TCP/22 и SFTP никогда не открываются на dedicated uplink/HiLink.

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
- redacted Management Fabric links, published aliases, effective ACL generations и resource health без private/pairing material;
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
│   ├── recover-gateway-install.sh
│   ├── upgrade-gateway-host.sh
│   ├── recover-gateway-host-upgrade.sh
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

- официальный first-install entrypoint остаётся одной одинаковой version-pinned командой; после cryptographic bootstrap она запускает последовательный интерактивный мастер на целевой машине, а не требует предварительно редактировать Netplan, GRUB, systemd или файлы проекта;
- мастер использует единый human-readable contract для **каждого** компонента установки: показывает обнаруженное состояние, понятное назначение компонента, рекомендуемый вариант с причиной, остальные безопасные варианты, последствия каждого выбора, возможность позднего изменения и точный список будущих host mutations; термин без расшифровки (`CIDR`, `DHCP`, `GRUB`, `PATH_BLOCKED`, `wait-online`, `fwmark` и т. п.) не может быть единственным объяснением;
- все компоненты делятся на три явно названные группы: **«Нужно выбрать сейчас»**, **«Будет настроено автоматически для безопасности»** и **«Можно изменить после установки в WebUI»**. Обязательные security invariants не маскируются как пользовательский выбор, но мастер объясняет, что и зачем будет сделано; необязательные policy decisions всегда имеют `Рекомендуется`, `Сохранить текущую настройку` и безопасную отмену;
- Enter принимает только показанный рекомендуемый вариант; номер/значение проверяется повторно, `q` отменяет установку без persistent mutation. Перед apply мастер печатает исчерпывающую сводку, предупреждает о временной потере сети/перезагрузке, если применимо, и требует точный token `INSTALL`;
- первоначально мастер обязан одинаково покрывать: проверку release/signature, support matrix ОС/CPU/bootloader/filesystem, зависимости, понятный topology profile, назначение одного или нескольких LAN/management ports, Ethernet uplinks либо HiLink-only выход, shared one-card WireGuard profile, transit/uplink/WireGuard subnets, DHCP/static IPv4, DHCP/DNS для WAN Keenetic, SSH/SFTP через management, IPv4 forwarding/IPv6 block, boot firewall/startup policy, динамические HiLink-модемы, optional `wg-ingress`, `networkd-wait-online`, GRUB, systemd services/watchdog/log exports, backup/rollback и итоговую readiness-проверку; параметры, которые меняются только после установки, перечисляются с путём к соответствующей вкладке WebUI;
- проверяет ОС, kernel features, TUN, nftables, WireGuard и свободные подсети;
- обнаруживает конфликт UFW/firewalld/NetworkManager configuration;
- не делает безусловный full system upgrade;
- идемпотентен;
- создаёт service users, directories и permissions;
- устанавливает boot-time blocked ruleset;
- генерирует secrets и показывает bootstrap password один раз;
- проверяет подписанные artifacts;
- release-команда не содержит имя интерфейса или подсеть конкретного компьютера;
- в интерактивном режиме на целевом Gateway показывает все обнаруженные интерфейсы с номером, типом, link/carrier state, IPv4-адресами и признаком default route, после чего требует явного подтверждения одного или нескольких физических LAN/management Ethernet ports;
- отдельным шагом показывает роли `Приём пользовательского трафика`, `Управление`, `Выход в интернет`, `Общий Ethernet для однокарточного WireGuard`, `HiLink` и `Не использовать`; для каждой роли объясняет направление пакета и рекомендуемый вариант по выбранной topology;
- Ethernet uplink выбирается только из safe unused NIC, затем мастер предлагает DHCP либо static IPv4/gateway/DNS; PPPoE отсутствует во всех prompts/config/API;
- one-card WireGuard выбирается явно, печатает обязательное исключение самого Gateway из возвращающей Keenetic policy и до apply выполняет route-recursion preview;
- выбранные порты объединяются в owned bridge `gateway-vpn-lan`; один адрес, DHCP/DNS, WebUI, SSH и routed LAN policy назначаются bridge, а не повторяются на каждом порту;
- loopback, non-Ethernet, Huawei USB/HiLink по udev metadata, интерфейс с уже настроенным IPv4 (management/uplink/modem risk), интерфейс текущего default route и доступный из `SSH_CONNECTION` интерфейс активной management-сессии не могут быть выбраны; мастер предлагает все оставшиеся safe Ethernet ports, но пользователь подтверждает или меняет набор; повторная установка использует verified update/idempotent automation path, а не clean-host wizard;
- отдельный интерактивный шаг показывает текущие состояния package/`ssh.service`, объясняет назначение SSH/SFTP и рекомендует включение; `Enter` принимает `Да`, оператор может явно выбрать `Нет`, а automation сохраняет безопасный default-on и имеет явный `--disable-ssh` opt-out;
- при включённом выборе `openssh-server` проверяется как managed dependency; если его нет, package загружается до firewall mutation, но устанавливается/запускается только после durable marker и `PATH_BLOCKED`; installer выполняет `sshd -t`, `systemctl enable --now ssh.service`, требует enabled/active и IPv4 wildcard TCP/22, после чего nftables разрешает TCP/22 только через owned management bridge/LAN; при opt-out package/service не меняются, правило TCP/22 отсутствует, config/report сохраняют выбор, а rollback/uninstall восстанавливает прежние enabled/active states (установленный OS package, как и прочие dependencies, не удаляется);
- предлагает первый свободный private transit CIDR, разрешает ввести другой `/16../30` и до установки проверяет его против всех host addresses/routes, HiLink management networks и `10.80.0.0/24`;
- отдельно спрашивает про DHCP и установку отсутствующих зависимостей; DHCP требует `/24`;
- предлагает boot-network policy: рекомендуемый appliance-вариант не ждёт carrier, DHCP или Internet ни от одного Ethernet/HiLink uplink, заменяет запуск штатного `systemd-networkd-wait-online` owned success-no-wait drop-in и запускает Gateway control plane независимо от `network-online.target`; вариант `Сохранить Ubuntu` не меняет host wait-online policy и явно предупреждает о возможной задержке 90–120 секунд;
- HiLink, выбранные физические LAN members и сам owned bridge имеют явный `RequiredForOnline=no`; отсутствие/зависание одного или всех модемов отображается runtime state machine и никогда не задерживает boot ОС;
- предлагает GRUB policy только после read-only определения фактического GRUB/UEFI/Legacy состояния: при единственной Ubuntu рекомендуемый `Автоматическая Ubuntu` скрывает меню, оставляет короткое окно вызова `Esc/Shift` и не останавливается на menu после `recordfail`; при найденной Windows boot entry скрытый вариант недоступен и рекомендуется видимое меню на 5 секунд; альтернативой всегда остаётся полное сохранение текущей policy. Неизвестный/не-GRUB bootloader никогда не изменяется автоматически;
- GRUB настраивается отдельным owned `/etc/default/grub.d/` drop-in без перезаписи vendor/user файла, затем `update-grub` и generated-config validation; boot-network policy использует отдельный owned systemd drop-in. Оба файла, их отсутствие до установки и regenerated state входят в first-install snapshot/recovery/rollback и удаляются при uninstall;
- после read-only preflight показывает итоговую сводку и требует отдельного точного подтверждения до первой разрешённой host mutation;
- при отсутствии настоящего TTY интерактивный режим завершается fail-closed; для CI/deploy сохраняется отдельный automation mode с обязательными явными `LAN interface/CIDR` и policy flags;
- сохраняет pre-install network/firewall snapshot;
- умеет dry-run;
- при ошибке выполняет rollback.

Одна команда не означает опасную установку без вопросов. Она означает отсутствие ручной подготовки: все hardware-dependent решения принимает человек в одном понятном мастере после автоматического read-only обследования. Если состояние неоднозначно (несколько ОС, неизвестный bootloader, активная management-сессия на изменяемом порту, чужой firewall/network ownership, повреждённый filesystem/GRUB или неподдерживаемая ОС), мастер объясняет конкретный конфликт и завершается до первой mutation вместо догадки.

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

Pointer-only update дополнительно принимает candidate только при точном совпадении подписанного `host_contract_sha256`, вычисленного по полному набору root-owned lifecycle assets: systemd units, networkd policy, boot wait-online, GRUB, nftables, sysctl, journald, dnsmasq, sysusers/tmpfiles и first-install recovery helper. Изменение этих файлов нельзя молча проигнорировать при переключении binaries: такой artifact отклоняется до host mutation и требует отдельной подписанной installer-upgrade transaction. После успешного stability window и повторной health-проверки `recovery` symlink атомарно переводится на новый проверенный release; до этого момента он остаётся на старом release для rollback. Поэтому следующую update-транзакцию всегда выполняет последний finalized trusted updater, а не произвольно давний binary.

Signed installer-upgrade для изменившегося host contract является отдельной root-транзакцией, а не ослабленным pointer-update:

1. разрешён только из finalized состояния, где `current` и `recovery` указывают на один старый release, отсутствуют pending install/update/restore/network transactions, а LAN/DHCP/SSH/SFTP/`wg-ingress`/boot/GRUB параметры точно совпадают с действующим installation report;
2. старое дерево проверяется verifier-ом старого подписанного release, candidate — verifier-ом candidate; `release.json.gateway_version`, запрошенная version и фактический `gateway-vpn --version` обязаны совпасть;
3. до mutation проверяется точная gap-free migration history старой SQLite, затем data path переводится в `PATH_BLOCKED`, control/data services останавливаются и создаётся cold root-only snapshot старого `/opt`, `/etc`, SQLite с WAL/SHM, privileged transaction state, Gateway-owned systemd/networkd/sysctl/GRUB/journald/tmpfiles/sysusers files и экспортированных логов;
4. recovery helper и его boot unit устанавливаются до durable active marker. Snapshot восстанавливается только по фиксированному allowlist Gateway-owned destinations; копирование synthetic snapshot root поверх `/` запрещено;
5. candidate installer наследует уже захваченный `flock`, не может освободить внешний lock либо удалить внешний recovery helper и сохраняет persistent config/secrets. После запуска candidate проверяются exact schema/history, services, watchdog и blocked firewall;
6. новый completed-install marker объединяется со старым так, чтобы будущий uninstall по-прежнему восстанавливал известные исходные до самой первой установки sysctl/link/SSH/group/boot значения, а не состояние непосредственно перед upgrade. Отсутствующее в legacy marker состояние `ssh.socket` не угадывается по post-install host: legacy merge остаётся форматом 18 и uninstaller не меняет socket без pre-install evidence;
7. любая ошибка или reboot/SIGKILL при живом marker запускает независимое восстановление старого signed tree, исходной DB/config/secrets/host projection и только после постановки старых service jobs переводит marker в terminal rollback. При ошибке самого rollback marker сохраняется, а data path остаётся закрыт.

Down-migration новой БД старым binary не используется: rollback всегда восстанавливает snapshot до migration.

### 17.4 GitHub zero-to-ready deployment

Официальный способ первого развёртывания — versioned Gateway VPN release из GitHub Releases. Репозиторий исходного кода сам по себе не считается установочным artifact. Release содержит отдельные пакеты ролей `gateway`, `vps` и административный deploy launcher, signed channel manifest с точными версиями, SHA-256, SBOM и provenance.

Поддерживаются три одинаково воспроизводимых режима:

1. одна сгенерированная release-команда на чистом Gateway с ролью `gateway`;
2. одна сгенерированная release-команда на чистом VPS с ролью `vps`;
3. одна команда `gateway-vpn-deploy` с административного компьютера, которая по SSH выполняет preflight обеих машин, устанавливает обе роли, обменивает только WireGuard public keys и запускает end-to-end verification.

Первый deploy создаёт один management link, но не закрепляет односерверную топологию навсегда. После установки Gateway WebUI может pair дополнительный VPS, а VPS Hub — дополнительный Gateway без переустановки любой роли. Installer VPS предлагает conflict-free management/admin/resource pools, проверяет их против host routes и существующих peers и никогда не перенумеровывает уже выданные site/link/admin prefixes автоматически. Повторный deploy существующей роли использует authenticated pairing/update transaction и не запускает clean-host wizard.

VPS Hub после first install слушает только localhost и admin WireGuard address; публичный HTTPS bind является запрещённым default и не включается pairing bundle. Итоговая readiness проверка для management fabric отдельно подтверждает Gateway→каждый VPS handshake, admin→Gateway HTTPS, ACL deny между sites и отсутствие management prefixes в user Internet/NAT path.

Команда содержит явную release version и ожидаемый hash bootstrap artifact. `curl | sudo bash`, непроверенный `latest` и исполнение загруженного файла до проверки hash/signature запрещены. Удобный канал `stable` допустим только как подписанный manifest, разрешающийся в конкретную immutable version; в installation report всегда записываются resolved version, hashes и signer identity.

До первой host mutation выполняется полный read-only preflight и формируется машинно-читаемый отчёт. Проверяются:

- на Gateway — Ubuntu Server `24.04` LTS `x86_64`; на VPS — объявленный release manifest Ubuntu Server LTS profile `20.04+` либо Debian 12+; дополнительно проверяются systemd, время/DNS, свободное место/RAM и поддерживаемое ядро;
- Ubuntu 20.04 VPS принимается только при активном ESM/security coverage и отсутствии ожидающих обязательных security updates; installer не подключает платную подписку и не делает full distribution upgrade самостоятельно;
- TUN, nftables, policy routing, WireGuard, необходимые sysctl/capabilities и отсутствие конфликтующих firewall/network managers;
- на Gateway — явно выбранный Ethernet `lan_keenetic`, непересекающаяся transit subnet, USB/networkd support и отсутствие опасного default-route takeover;
- на VPS — публичный IPv4 либо явно заданный достижимый endpoint, свободный UDP `51821`, IP forwarding и возможность установить owned firewall rules;
- SSH/sudo prerequisites orchestration-режима, доступность immutable GitHub artifacts и валидность всех signatures/hashes;
- все обязательные пользовательские входы: LAN interface/CIDR, VPS endpoint, SSH destinations и политика включения DHCP. Обычная Gateway release-команда собирает LAN/DHCP/dependency choices интерактивно уже на целевом компьютере и потому остаётся одинаковой для всех поддерживаемых Gateway; SSH-orchestrated automation принимает те же значения явно. Неоднозначный интерфейс не выбирается автоматически.

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
- восстанавливает записанные перед первой установкой forwarding/IPv6, LAN bridge/member/link, SSH service/socket, log-reader membership, boot/network и GRUB состояния только для owned/snapshotted изменений Gateway VPN;
- режим `Сохранить данные` удаляет программу, units и `/etc/gateway-vpn`, но сохраняет `/var/lib/gateway-vpn` для повторной установки; режим `Полное удаление` после отдельного подтверждения удаляет также DB, secrets, keys, backups и log exports, предварительно предлагая оператору явный экспорт;
- установленные OS packages по умолчанию не удаляются: после установки они могли стать общими зависимостями другого ПО. Optional dependency cleanup является отдельным expert-действием, допускается только после APT simulation и запрещается при любом removal постороннего пакета;
- WebUI использует password re-auth, точную русскую фразу, предварительный impact report и отдельный фиксированный root-owned systemd job. После принятия job WebUI закономерно становится недоступен; terminal receipt сохраняется вне удаляемого application tree;
- перед удалённым apply явно предупреждает, что восстановление прежнего LAN/SSH состояния может оборвать текущую сессию;
- не обещает factory reset или побайтовое состояние всей Ubuntu: изменения пользователя, других программ, package security updates и не-owned host state не откатываются.

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
- unified ranking `FULL → best LIMITED score → method → modem → node rank → sticky tie`;
- hysteresis/backoff и hard-failure fast path;
- direct immutable access-method lifecycle и boot-scoped direct-only mode;
- node preference transfer/history по stable fingerprint;
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
- минимум два независимых VPS WireGuard peers и два Gateway site peers, включая одинаковые local subnets за разными sites;
- DNS и probe endpoints.
- чистая Ubuntu 24.04 Gateway и отдельные чистые VPS fixtures Ubuntu 20.04/22.04/24.04/26.04 LTS для GitHub zero-to-ready deployment; 20.04 fixture проверяет ESM/security gate.

Обязательные проверки:

- TCP и UDP через TUN;
- DNS hijack и packet capture на HiLink, подтверждающий отсутствие пользовательского direct DNS;
- отсутствие неуправляемого IPv4 direct path при VPN/quarantine и наличие ровно одного modem-scoped SNAT path при выбранном direct;
- IPv6 RA/DHCPv6 injection, `curl -6` и отсутствие global IPv6 route;
- graceful stop, SIGTERM, `kill -9` и restart storm Mihomo;
- reload/rollback Mihomo с восстановлением LKG;
- atomic nft sets update;
- удаление owned nftables table и случайный `nft flush ruleset` с quarantine/recovery;
- failover/failback;
- direct FULL выигрывает у VPN LIMITED, а VPN FULL выигрывает у direct LIMITED независимо от priority;
- direct `WHITELIST_ONLY` определяется только direct-only indicators при failed independent global targets; indicators никогда не отправляются через VPN и не вызывают modem recovery;
- при отсутствии FULL лучший разрешённый LIMITED/WHITELIST_ONLY продолжает user service, а background probes находят FULL без изменения active path во время проверки;
- при двух одинаково функциональных candidates применяются method/modem/node priorities, затем sticky tie;
- direct qualification выполняется независимо через каждый ready modem и не использует main-table default route;
- temporary direct-only mode исключает VPN из user ranking, сохраняет service refresh и сбрасывается после нового boot ID;
- startup gate ON начинает с quarantine, OFF открывает только минимально проверенный LKG/direct generation и продолжает qualification в фоне;
- два модема одновременно получают DHCP lease, но ни один не устанавливает default route в main table;
- одинаковая subscription/node комбинация проходит required targets через modem A и не проходит через modem B;
- modem A отключается во время active path: новые direct flows не появляются, выбирается qualified path modem B;
- modem A подключается обратно: identity/routes восстанавливаются, а failback ждёт stable requalification;
- USB interface rename/replug сохраняет `modem_id`, priority и routing table/fwmark;
- неоднозначная identity не присваивает новому устройству конфигурацию отсутствующего модема;
- пересечение HiLink subnets помещает только конфликтующий modem в `MODEM_SUBNET_CONFLICT`;
- reorder modem/subscription priority меняет ranking, но не инвалидирует fresh qualification и не обрывает active path вне правил failback/manual activation;
- packet capture на каждом modem подтверждает соответствие `interface-name`, fwmark и routing table выбранной path cell;
- mixed Ethernet/HiLink uplinks имеют независимые DHCP/static routes, fwmarks/tables и ranking; Ethernet lease также не создаёт main-table default;
- safe NIC replacement переносит role/LKG на новую stable identity, а timeout/reboot откатывает прежний persistent/runtime state;
- single-NIC `wg-ingress` fixture доказывает `Keenetic → WG → TUN/direct → та же NIC → upstream` без route recursion и plaintext leak;
- WireGuard ingress peer CRUD/disable/revoke/key rotation/config/QR, duplicate AllowedIPs/subnet/key rejection и reboot persistence проходят с реальным `wg` parser;
- managed client private key отсутствует в DB/log/API list/diagnostics и возвращается только после re-auth; external-key peer никогда не выдаёт private key;
- modem recovery ladder различает external whitelist/VPN outage и carrier/DHCP/device hang, соблюдает durable budgets/cooldown и принимает только повторно verified fixed sysfs identity;
- log tabs возвращают одну canonical event identity, а SFTP exports совпадают по фильтру, проходят redaction, rotation/disk budget и не открывают TCP/22 на uplinks;
- keyboard/touch/hover help и impact preview существуют для всех mutable network/WireGuard/watchdog/logging settings; color не является единственным индикатором;
- подписка с `обход`/`LTE`/whitelist names: проверяются только совпавшие candidates;
- подписка без совпадений: проверяются все enabled nodes;
- named candidates существуют, но failed: остальные не используются при default policy;
- `AUTO/INCLUDE/EXCLUDE` и preferred rank переживают refresh по fingerprint; новый node получает AUTO, исчезнувшая preference сохраняется bounded history;
- disabled user-routing subscription с `auto_refresh=true` обновляется, а direct service fallback работает даже при выключенном direct user method;
- refresh route ladder пробует current subscription nodes, other subscription nodes и direct modems без переключения user path;
- parallel manual/automatic refresh одного source объединяется durable lease/single-flight operation;
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
- один VPS одновременно маршрутизирует нескольких Gateway peers с уникальными `/32`/site prefixes и запрещает Gateway↔Gateway forwarding;
- один Gateway одновременно удерживает handshakes с двумя VPS через независимые interfaces/keys/subnets; остановка одного VPS не меняет второй link и data plane;
- pairing token одноразов, fingerprint/subnet проверяются, а make-before-break key rotation сохраняет хотя бы один проверенный management path;
- `END_TO_END_RELAY` доставляет реальный nested WireGuard handshake admin→Gateway через VPS UDP relay; packet capture на VPS не содержит inner plaintext, а пакет, сгенерированный только VPS без admin private key, не проходит `wg-admin`/resource ACL;
- restore-as-same-site требует key replacement и не допускает одновременно active cloned identity; restore-as-new-site получает новые `site_id`/keys/prefixes;
- одинаковые `192.168.50.0/24` за двумя Gateway доступны только через разные published alias prefixes; попытка overlapping alias/AllowedIPs отклоняется до mutation;
- ACL разрешает конкретному admin только назначенные site/resource ports и одинаково блокирует нарушение на VPS и Gateway; Gateway↔Gateway, admin↔admin и management→Internet запрещены;
- `GATEWAY_ONLY`, `KEENETIC_WAN`, `VIA_KEENETIC_WAN_ROUTED`, `VIA_WG_ROUTER` и `VIA_DEDICATED_LAN` имеют отдельные fixtures; отсутствие внешнего Keenetic firewall/return path оставляет resource `WAITING_EXTERNAL_CONFIGURATION`, не создавая широкого fallback;
- topology profiles переключаются после установки одной durable safe-apply transaction; подтверждение только со старого management address не фиксирует candidate, timeout/process kill/reboot возвращают LKG topology;
- grouped WebUI navigation сохраняет единственного владельца каждой настройки, breadcrumbs/deep links и доступность keyboard/touch при desktop/mobile layouts;
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
- Ethernet uplink DHCP/static, link loss/replacement и mixed failover с HiLink;
- однокарточный `wg-ingress` с реальным Keenetic policy и packet capture обоих направлений;
- driver unbind/bind и USB reset Huawei с проверкой cooldown/budget; hub port power-cycle тестируется только на фактически поддерживающем per-port power оборудовании;

### 18.4 Failure matrix

| Сбой | Ожидаемое действие | Неуправляемый direct leak |
|---|---|---:|
| Падение gateway-vpn | firewall остаётся, data path зависит от LKG policy | нет |
| Падение Mihomo при active VPN | выбрать другой FULL/LIMITED метод, включая qualified direct; иначе quarantine | нет |
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
| Все VPN cells недоступны, direct FULL/LIMITED доступен | выбрать direct по quality/priority | нет |
| Direct недоступен, VPN FULL/LIMITED доступен | выбрать VPN по quality/priority | нет |
| Все direct/VPN paths недоступны | PATH_BLOCKED, management доступен | нет |
| Direct user method выключен | direct исключён из user ranking, service refresh fallback остаётся разрешён | нет |
| Временный direct-only mode | user traffic только через qualified direct; после reboot обычный ranking | нет |
| Startup blocking выключен | открыть только minimally verified LKG/direct generation; background qualification может безопасно переключить | нет |
| Неактивный HiLink unplug | только его cells → MODEM_OFFLINE; active path не меняется | нет |
| Активный HiLink unplug | немедленно закрыть его routes, failover на qualified cell другого modem | нет |
| HiLink reconnect | восстановить identity/routes, requalify, delayed failback | нет |
| Два modem получили DHCP одновременно | defaults остаются только в modem-specific tables | нет |
| HiLink subnets пересеклись | конфликтующий modem quarantined, остальные продолжают работу | нет |
| WireGuard management modem unplug | endpoint route переходит на следующий ready modem | нет |
| Priority modem не достигает VPS endpoint | следующий management-reachable modem без влияния на data path | нет |
| VPS/WireGuard недоступен | data plane продолжает работать | нет |
| Один из нескольких VPS недоступен | остальные management links продолжают работать; только этот link получает external outage | нет |
| VPS relay скомпрометирован/пытается spoof admin | `END_TO_END_RELAY` не принимает пакет без inner admin key; WebUI/SSH auth сохраняется | нет |
| Один VPS обслуживает несколько Gateway с одинаковой Home LAN | unique alias prefixes выбирают правильный site; межсайтовый forwarding закрыт | нет |
| ACL generation применена только на части VPS | рабочая предыдущая generation сохраняется; status PARTIAL/PENDING_RETRY либо полный rollback | нет |
| Keenetic продолжает Internet через WAN без management WireGuard | Gateway остаётся доступен; непроверенная Home LAN не публикуется | нет |
| Keenetic WAN→LAN firewall/return path отсутствует | resource WAITING_EXTERNAL_CONFIGURATION; другие resources/links продолжают работу | нет |
| Reboot/kill во время topology profile switch | отдельный helper восстанавливает LKG network/firewall/API bind | нет |
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
| Reboot/SIGKILL во время signed host-contract upgrade | boot recovery восстанавливает старые signed release + DB + owned host projection; marker сохраняется до успешного rollback | нет |
| Ошибка либо разрыв WebUI во время uninstall | root job продолжает по durable marker; при незавершённом restore исходных owned состояний повторяет recovery и не выдаёт ложный success | нет |

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
- [ ] capability-gated power management с re-authentication, audit и блокировкой во время критических транзакций;
- [ ] secret redaction;
- [ ] diagnostics download.

**Критерий готовности:** все privileged операции требуют auth; API не раскрывает secrets; пользователь может добавить/отключить/переименовать/переупорядочить modem и subscription, а их страницы показывают согласованные статусы всех пар из одного read model; пользователь может CRUD/reorder targets/matchers; UI показывает target matrix, probe budget и reason code каждого node/path; offline modem не исчезает, stale results не выглядят рабочими; смена policy generation проходит через 120-секундный grace; ошибочная LAN-настройка откатывается out-of-process helper не позднее 90 секунд.

### Этап 5. WireGuard management

- [ ] VPS installer;
- [ ] durable entities для `site`, `vps_node`, `management_link`, `admin_peer`, `management_resource`, ACL/route generations и operation receipts;
- [ ] несколько Gateway peers на одном VPS и несколько одновременно active VPS links на одном Gateway;
- [ ] per-link keypair, one-time pairing, fingerprint verification и make-before-break rotation;
- [ ] optional Gateway-terminated `wg-admin` и per-site VPS UDP relay для end-to-end administrator mode;
- [ ] admin peer management и отдельные portable configs для каждого VPS без overlapping `AllowedIPs`;
- [ ] uplink-independent endpoint selector каждого link, host routes и bounded recovery;
- [ ] VPS forwarding/firewall с двойной Gateway-side ACL и default deny между sites/admins;
- [ ] local-resource profiles через Gateway-only, Keenetic WAN/routed, router WireGuard и dedicated LAN;
- [ ] unique published alias pool и typed translation для overlapping Home LAN;
- [ ] Gateway **«Удалённый доступ»** tabs и restricted VPS Hub;
- [ ] topology profile switching после установки через durable safe apply;
- [ ] management/resource watchdog, logs, diagnostics и survival tests.

**Критерий готовности:** Web UI доступен через любой enabled reachable VPS при неработающем Mihomo и отсутствии рабочих подписок; один VPS безопасно обслуживает минимум два Gateway, один Gateway одновременно удерживает минимум два VPS links, а отказ VPS/uplink не разрушает остальные links. Администратор получает только разрешённые Gateway/Keenetic/local resources, одинаковые Home LAN различаются alias prefixes, отсутствие Keenetic return path не расширяет firewall, и post-install topology switch либо подтверждается через новый management path, либо автоматически возвращает LKG.

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
3. подтверждено отсутствие неразрешённого direct IPv4/DNS и IPv6 leak; когда активен direct, capture доказывает ровно выбранный modem/interface/table/SNAT generation;
4. invalid subscription/config/update автоматически откатываются к LKG;
5. после reboot Gateway применяет настроенную startup policy, никогда не открывает произвольный uplink и восстанавливает рабочий FULL/LIMITED путь без ручного вмешательства;
6. WireGuard management доступен независимо от состояния Mihomo и переключает modem uplink при disconnect;
7. API не слушает HiLink uplink и требует аутентификацию;
8. секреты отсутствуют в API responses, logs и diagnostic bundle;
9. installer, update, rollback, backup, restore и uninstall проверены на чистой системе;
10. документация содержит topology, recovery runbook и список поддерживаемых subscription formats;
11. версия и SHA-256 Mihomo закреплены, а API contract сохранён fixture;
12. общий traffic counter является authoritative; per-subscription значения отсутствуют в MVP API и UI;
13. активным становится только fresh tuple `method × modem × optional subscription/node`; FULL имеет все required targets, LIMITED имеет объяснимый score и используется только при отсутствии FULL;
14. name matcher fallback и target priority/CRUD проходят fixtures и integration tests;
15. общий outage одного target не вызывает бесконечное переключение nodes/subscriptions/modems;
16. все adopted модемы сохраняют identity, номер, priority и history после unplug/replug и reboot;
17. Web UI показывает одинаковое состояние direct и каждой `modem × subscription` cell во вкладках Modems, Subscriptions и Path Matrix;
18. потеря active modem не создаёт wildcard/main-table route, а переключение выполняется по quality, method/modem/node priority и hysteresis;
19. вернувшийся preferred modem активируется только после stable requalification, без flap;
20. DHCP, DNS bootstrap, proxy sockets и WireGuard endpoint routes каждого модема изолированы его fwmark/routing table.
21. versioned signed artifacts из GitHub устанавливают чистые поддерживаемые Gateway и VPS воспроизводимо; одна SSH-orchestrated команда либо подтверждает полный `READY`, либо выдаёт проверяемый `INSTALLED_NOT_READY`/failure и безопасный rollback без ложного заявления о готовности.
22. PID-alive hang, component crash и restart storm автоматически обнаруживаются; восстановление bounded, dependency-aware, fail-closed и полностью отражено в UI/events/diagnostics.
23. длительная внешняя потеря Internet/modems/VPS не вызывает host reboot; optional reboot локального critical failure имеет durable budget и не выполняется во время install/update/restore/network transaction.
24. 24- и 72-часовые endurance результаты содержат supervisor/recovery counters и не имеют скрытого restart/reboot loop.
25. immutable direct access method создаётся автоматически, может быть выключен/переупорядочен, не удаляется и не управляет service refresh permission.
26. `AUTO/INCLUDE/EXCLUDE`, preferred node order и sticky selection переживают subscription refresh по stable fingerprint; EXCLUDE никогда не используется.
27. scheduled/manual refresh имеет durable operation status, single-flight, retry/backoff/Retry-After и route fallback до direct без изменения пользовательского active path.
28. startup blocking ON/OFF и boot-scoped direct-only mode проходят reboot/netns tests; ни один вариант не отключает firewall или quarantine при повреждённом state.
29. HiLink и Ethernet являются равноправными uplinks: matrix, priorities, routing generations, mixed failover/failback и interface replacement используют один canonical read/write model без modem-only fallback.
30. direct-only whitelist indicators создают объяснимый `WHITELIST_ONLY`, никогда не квалифицируют VPN и не превращают operator restriction в modem hardware recovery.
31. реальный modem recovery выполняет bounded DHCP/API/mobile-session/USB ladder, переживает restart, прекращается после budget и не перезагружает host из-за внешнего outage.
32. `wg-ingress` полностью управляется через authenticated Web UI/API; managed/external peers, config/QR, revoke/rotation, one-card mode, per-peer policy и leak/loop tests проходят.
33. Web UI имеет понятные роли, help для mouse/keyboard/touch, impact preview и safe rollback; технические термины не являются единственным объяснением mutable setting.
34. canonical journald stream имеет тематические Web UI tabs и bounded redacted `/var/log/gateway-vpn` exports, доступные штатным SFTP только через management paths.
35. ручные reboot/shutdown требуют re-authentication и typed confirmation; RTC power-cycle доступен только при доказанной поддержке железом, а любая power action блокируется во время критической durable transaction и полностью отражается в audit/operation status.
36. все поддерживаемые topology profiles и interface roles можно изменить после установки через WebUI; risky apply имеет preview, alternative management prerequisite, out-of-process timeout/reboot rollback и подтверждается только через новый path.
37. Management Fabric поддерживает `1..N Gateway ↔ 1..N VPS`: links имеют отдельные keys/subnets/interfaces/generations, остаются одновременно active и восстанавливаются независимо от user data plane.
38. VPS/Gateway применяют одинаковую versioned ACL; Gateway↔Gateway, admin↔admin, management→Internet и непубликованные local networks закрыты, а key pairing/rotation/revoke не оставляют промежуточного широкого доступа.
39. Gateway, Keenetic и local host/subnet resources публикуются только явно через один из проверенных profiles; обычный WAN Internet Keenetic не зависит от наличия management WireGuard, а отсутствующий firewall/return path отображается как внешний prerequisite.
40. одинаковые private Home LAN нескольких Gateway доступны через уникальные conflict-checked aliases для каждой `site × resource × VPS link` publication без изменения адресов локальных устройств и без route ambiguity на VPS/admin.
41. WebUI использует сгруппированную предметную навигацию, отдельные вкладки VPS/администраторов/локальных ресурсов/матрицы доступа, единственного владельца каждой настройки и canonical backend state без дублирующих форм/вычислений.
42. Для local-resource access доступен Gateway-terminated `END_TO_END_RELAY`: VPS пересылает только зашифрованные inner WireGuard datagrams, не может подделать admin peer, а `ROUTED_HUB` остаётся явно обозначенным более доверительным opt-in.

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
