# Gateway VPN — сетевые инварианты

## Каноническая схема

```text
Keenetic WAN / обычный LAN-клиент / WireGuard peer
  → gateway-vpn-lan либо wg-ingress
  → выбранный проверенный access method: direct или subscription
  → direct gate либо единый gateway-vpn-tun / Mihomo node
  → выбранный HiLink или Ethernet uplink
  → uplink-specific fwmark + routing table + optional SNAT
  → оператор / внешний роутер / ONT
```

Gateway поддерживает `1..N` uplinks в любой разумной комбинации: один HiLink, несколько HiLink, один или несколько Ethernet uplinks либо смешанный набор. Количество само по себе не меняет policy: сначала выбирается наиболее функциональный fresh path (`FULL`, затем разрешённый `LIMITED/WHITELIST_ONLY`), а среди одинаковых — порядок access method, uplink и node.

## Интерфейсы и роли

- Один или несколько выделенных Ethernet LAN-портов объединяются в owned bridge `gateway-vpn-lan` с единственным transit IPv4. WebUI, DHCP/DNS и OpenSSH/SFTP относятся к bridge, поэтому доступны через любой его member.
- Отдельный Ethernet uplink получает роль `UPLINK`; его DHCP/static gateway/DNS хранятся раздельно от observed lease и никогда не создают неуправляемый default route в `main`.
- HiLink является USB-Ethernet uplink с собственной management subnet/NAT, stable device identity, telemetry и bounded recovery. Huawei/USB NIC никогда не включается в LAN bridge.
- `SHARED_ONE_ARM` допускает один физический Ethernet к существующему роутеру: входящий пользовательский трафик приходит по `wg-ingress`, а отмеченный uplink возвращает обработанный трафик через тот же L2 interface. Обычный незашифрованный LAN transit на shared interface не принимается.
- Replacement привязывает логическую роль к новой stable NIC identity через safe apply. Текущее Linux ifname не считается постоянным идентификатором.
- Все topology profiles и роли изменяются после установки через WebUI. Candidate одновременно покрывает networkd, DHCP/DNS, firewall, policy routing, `wg-ingress` и API bind; LKG/old management path сохраняются до подтверждения через новый path, а timeout/process crash/reboot выполняют out-of-process rollback.
- Loopback, non-Ethernet, current default-route/active SSH path, интерфейс с чужим IPv4 и HiLink risk не могут молча стать LAN member. Любая неоднозначность требует явного выбора пользователя.

## Uplink isolation

- Каждый adopted uplink получает стабильный `uplink_id`, display number, priority, routing table, fwmark и route generation; выданные значения не переиспользуются после удаления.
- Root reconciler владеет только routes/rules protocol `186`, закрывает direct/TUN gate перед изменением и проверяет каждый context через `ip route get … mark …`.
- DHCP, bootstrap DNS/HTTPS, subscription refresh, Mihomo proxy sockets, direct probes и WireGuard endpoint используют только точный tuple `interface × fwmark × routing table × destination`.
- Ни один HiLink/Ethernet uplink default route не добавляется в `main`; смена interface/gateway очищает прежние service/endpoint generations.
- Management subnet каждого HiLink/Ethernet uplink обязана быть уникальной и не пересекаться с transit LAN, `wg-mgmt`, `wg-ingress`, behind-peer networks и другими uplinks.
- Uplink без carrier/lease/gateway может быть временно offline и возвращается в candidate pool только после fresh observation/requalification. Наличие одного uplink не блокирует Gateway само по себе.

## Методы доступа и квалификация

- Direct и каждая подписка являются элементами одного ordered access-method list. Immutable direct method создаётся автоматически, может быть выключен и переупорядочен, но не удаляется.
- Одинаковая subscription node квалифицируется независимо через каждый uplink. Scope результата: `(uplink, access_method, optional subscription/node, policy_generation, route_generation)`.
- `FULL` означает успех всех обязательных global targets. `LIMITED` хранит точное частичное evidence. `WHITELIST_ONLY` создаётся только direct-проверкой специальных operator whitelist indicators и никогда не квалифицирует VPN node.
- Active path требует свежие target results и точную selected node/direct identity. Ручной override не обходит qualification или firewall transaction.
- Пока существует `FULL`, LIMITED/WHITELIST_ONLY не выбирается. Среди одинакового качества применяются пользовательские priorities и hysteresis; вернувшийся preferred path обязан пройти stable requalification.
- При operator/global outage исправный modem/uplink не классифицируется как hardware failure. Bounded physical recovery запускается только по отсутствию устройства, carrier, lease или management API/mobile-session evidence.

## Firewall и fail-closed

- Owned table — только `inet gateway_vpn`; текущая firewall schema generation — `4`. Controller никогда не вызывает `nft flush ruleset` и не изменяет таблицы других приложений.
- Direct и TUN gate взаимно исключаются. Direct открывается только для точного fresh `uplink + generation`; при active subscription прямой пользовательский выход закрыт.
- Настройка startup blocking управляет только поведением до первого доказанного path. Она не отключает firewall integrity/quarantine: повреждённое или неизвестное состояние всегда закрывается.
- IPv6 отключён sysctl и блокируется owned `inet` ruleset; IPv6 forwarding равен `0`.
- SSH/SFTP TCP/22 разрешается только с `gateway-vpn-lan` (и отдельной management policy через `wg-mgmt`), никогда с HiLink/Ethernet uplink.
- `wg-ingress` UDP принимается только на server-configured listener interfaces из `wireguard_ingress_listeners`. Disabled/failed server не оставляет интерфейс или wildcard listener.
- Firewall guard проверяет base drop chains, generation 4, четыре traffic counters и ingress listener set. При flush/corruption он сначала quarantines transit LAN, восстанавливает только owned blocked ruleset и возвращает link после повторной проверки.

## WireGuard и Management Fabric

- Совместимый первый `wg-mgmt` (`10.80.0.0/24`) обслуживает независимое управление через VPS. Gateway address `10.80.0.2/32` дополняется owned route `10.80.0.0/24 dev wg-mgmt protocol 186`; VPS address `10.80.0.1/24` создаёт обратный connected route.
- Successor допускает `1..N Gateway ↔ 1..N VPS`. Дополнительные links используют отдельные `gvm<N>`, keypair, непересекающуюся management subnet/address и route/ACL generation; все enabled links остаются active одновременно и независимо выбирают physical uplink. Один VPS назначает уникальные Gateway `/32`, запрещает Gateway↔Gateway/admin↔admin forwarding и не создаёт общий private wildcard route.
- Endpoint `wg-mgmt` получает uplink-specific host route и failover независимо от Mihomo/user path. Старый handshake при совпавшем локальном contour является внешней ошибкой, а не поводом restart/reboot.
- Optional `wg-admin` завершает administrator tunnel непосредственно на Gateway. В рекомендуемом `END_TO_END_RELAY` VPS пересылает allowlisted public UDP port через outer management link, но не имеет inner key и не расшифровывает admin payload; `ROUTED_HUB` остаётся явным более доверительным режимом.
- `wg-ingress` (по умолчанию `10.90.0.0/24`, UDP/51820) принимает трафик клиентов/роутеров. Его keys, peers, AllowedIPs, behind routes и access policies независимы от management tunnel.
- Для managed ingress peer private key/PSK остаются root-only; revoke удаляет peer из kernel. Peer traffic проходит ту же FULL/LIMITED/direct/VPN policy, а не получает собственный неконтролируемый NAT.
- Forwarding обычного LAN в outer `wg-mgmt` запрещён. Локальные ресурсы публикуются default-off как typed Gateway/Keenetic/host/subnet services через `GATEWAY_ONLY`, Keenetic WAN/routed, router WireGuard либо dedicated LAN profile и explicit administrator ACL.
- Для каждой публикации `site × resource × VPS link` выделяется уникальный alias prefix. Это позволяет безопасно различать одинаковые `192.168.1.0/24`/`192.168.50.0/24` разных Gateway и одновременно держать admin tunnels к нескольким VPS без duplicate `AllowedIPs`.
- Обычный Internet Keenetic продолжает идти через WAN. Management WireGuard на Keenetic не обязателен; без него Home LAN требует явного WAN→LAN firewall/return path либо dedicated LAN link и остаётся `WAITING_EXTERNAL_CONFIGURATION`, пока fresh probe не подтвердит доступ.

## VPS coexistence с AmneziaVPN и чужими сетевыми owners

- VPS-роли принадлежат только bounded interfaces `gvm<N>`/`gva<N>`, непересекающимся management/admin/alias prefixes, собственным ports, fwmarks/tables и routes protocol `186`. Preflight сверяет их со всеми observed addresses/routes/rules/listeners, WireGuard/Amnezia/Docker interfaces и отклоняет конфликт до mutation.
- `inet gateway_vpn_vps` не использует blanket base-chain `policy drop` для всего host traffic: unowned interfaces/addresses/ports получают ранний `return`/policy accept, а deny применяется только внутри owned contour. `flush ruleset`, disable UFW/firewalld, удаление foreign nft/iptables rules и изменение чужих WireGuard peers запрещены.
- Gateway VPN не создаёт default route VPS и не меняет AmneziaVPN, Docker bridge, NAT или policy marks. Watchdog читает чужой state только для conflict/drift classification и никогда не restart/reload чужой unit/interface либо весь VPS.
- Если IPv4 forwarding уже включён, Gateway VPN не считает его своим. Если его включила Gateway VPN, uninstall возвращает `0` только при доказанном отсутствии нового foreign forwarding owner; иначе удаляет owned sysctl projection, сохраняет безопасное `1` и выдаёт явный residual-state warning, чтобы не оборвать позднее установленную AmneziaVPN.
- Пересечения LAN/uplink/management/admin/ingress/peer/resource prefixes и duplicate peer routes отклоняются до apply. Management→Internet, непубликованная LAN и inter-site traffic всегда default deny.

Конкретные addresses, interfaces, USB IDs и routing values стенда записываются после hardware discovery, а не предполагаются из порядка PCI/USB-портов.
