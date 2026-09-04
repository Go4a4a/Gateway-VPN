# Gateway VPN Linux network-namespace tests

Эти сценарии требуют root, Linux network namespaces, nftables и iproute2. Они намеренно не запускаются и не считаются `PASS` в Windows cross-build.

Для локального disposable Docker gate используется pinned Ubuntu 24.04 image:

```bash
docker build -t gateway-vpn-netns:ubuntu24 -f test/netns/Dockerfile.ubuntu24 .
```

```bash
CGO_ENABLED=0 go build -o /tmp/gateway-vpn-netns ./cmd/gateway-vpn
CGO_ENABLED=0 go test -c -o /tmp/gateway-vpn-dataplane-test ./internal/dataplane
CGO_ENABLED=0 go test -c -o /tmp/gateway-vpn-app-test ./internal/app
CGO_ENABLED=0 go test -c -o /tmp/gateway-vpn-wgingress-test ./internal/wgingress
CGO_ENABLED=0 go test -c -o /tmp/gateway-vpn-networkapply-test ./internal/networkapply
CGO_ENABLED=0 go test -c -o /tmp/gateway-vpn-updatenet-test ./internal/updatenet
CGO_ENABLED=0 go test -c -o /tmp/gateway-vpn-gatewayfabric-test ./internal/gatewayfabric
CGO_ENABLED=0 go build -o /tmp/gateway-vpn-mihomo-peer ./test/netns/cmd/mihomo-peer
sudo bash ./test/netns/firewall_guard.sh /tmp/gateway-vpn-netns /tmp/gateway-vpn-dataplane-test
sudo bash ./test/netns/startup_policy.sh /tmp/gateway-vpn-netns /tmp/gateway-vpn-app-test
sudo bash ./test/netns/lan_bridge_ssh.sh /tmp/gateway-vpn-netns
sudo bash ./test/netns/wireguard_ingress.sh /tmp/gateway-vpn-wgingress-test
sudo bash ./test/netns/initial_topology_preflight.sh /tmp/gateway-vpn-netns /tmp/gateway-vpn-networkapply-test
sudo bash ./test/netns/topology_profiles.sh /tmp/gateway-vpn-netns /tmp/gateway-vpn-networkapply-test
sudo bash ./test/netns/update_service_routes.sh /tmp/gateway-vpn-dataplane-test /tmp/gateway-vpn-updatenet-test
sudo bash ./test/netns/management_resources.sh /tmp/gateway-vpn-gatewayfabric-test
sudo bash ./test/netns/mihomo_tun.sh /absolute/path/to/pinned/mihomo \
  /tmp/gateway-vpn-mihomo-peer v1.19.30 PINNED_LOWERCASE_SHA256 \
  /new/absolute/evidence-directory
```

`firewall_guard.sh` создаёт только namespace с уникальным PID suffix, не меняет host ruleset и удаляет namespace через trap. Сценарий проверяет policy routing без unmarked default route, route-aware TCP MSS `1240` при direct MTU `1280` и `1260` при TUN MTU `1300` реальным packet capture, удаление `table inet gateway_vpn`, полный `nft flush ruleset`, durable LAN quarantine, восстановление schema generation и возврат только в `PATH_BLOCKED`. Direct firewall gate одинаков для HiLink и Ethernet uplink; тип физического выхода не расширяет его scope.

`startup_policy.sh` использует отдельные namespace и временные SQLite-файлы. Четыре запуска production startup logic доказывают новый boot с включённой блокировкой, минимальное exact-LKG восстановление при выключенной блокировке, сохранение active tuple при restart процесса в том же boot, сброс временного direct-only и возврат kernel firewall в `PATH_BLOCKED` на следующем boot. Ни один сценарий не добавляет unmarked default route.

`lan_bridge_ssh.sh` проверяет один management bridge с двумя физическими LAN-портами: TCP/22 доступен через оба, недоступен через отдельный uplink, а `disable_ssh_management: true` атомарно удаляет правило TCP/22 и блокирует оба LAN-пути даже при живом wildcard listener.

`wireguard_ingress.sh` запускает отдельный kernel integration binary в disposable root namespace. Он создаёт настоящий server/client WireGuard contour, выполняет handshake без внешнего Интернета, проверяет LAN-scoped UDP listener, адрес/peer в ядре, удаление revoked peer и полное fail-closed удаление интерфейса при выключении сервера.

`initial_topology_preflight.sh` выполняет release binary в отдельном network namespace и проверяет direct/bridge handoff, отказ при несовпадающем интерфейсе, unknown field и пока неподдерживаемом first-install backend. До и после каждого запуска сравнивается полный link/address/route/rule snapshot. Дополнительно fixture проверяет, что первый topology check расположен до WireGuard preflight и apply boundary установщика, и повторяет durable apply/commit/rollback tests. Evidence сохраняется только в project-local `.cache/netns`; bare-metal установку этот gate не заменяет.

`topology_profiles.sh` связывает durable topology apply/commit/rollback contract с реальным kernel nftables ONE_ARM-контуром. Неподтверждённый либо spoofed `wg-ingress` source блокируется, exact peer allowlist проходит через выбранный direct uplink, а mark map не содержит дубликатов.

`update_service_routes.sh` создаёт отдельные HiLink- и Ethernet-пары, применяет production root backend и доказывает реальные marked TCP packets только для exact public-IP/443 tuple и UID `gateway-vpn`. Root UID, неразрешённый destination и unmarked route остаются заблокированы; Ethernet не получает HiLink management exception.

`management_resources.sh` создаёт disposable Gateway/Keenetic/WireGuard/dedicated-LAN namespaces и реальные TCP-службы. Он доказывает пять access profiles, `SO_BINDTODEVICE`, обязательный host внутри `LOCAL_SUBNET`, отсутствие публикации при недоступном transport/return path и запрет dedicated-management интерфейса с default route.

`mihomo_tun.sh` требует отдельно переданные exact version/SHA-256 pinned Mihomo и test-only Go peer. В трёх namespace он поднимает второй экземпляр того же Mihomo как локальный SOCKS5 endpoint и полностью локальные HTTP/UDP/DNS services. Gateway instance использует `stack: mixed`, `auto-route`, `auto-redirect`, `strict-route`, DNS hijack и SOCKS node с `interface-name`/`routing-mark`; прямой `LAN → uplink` блокируется независимым nft rule. Gate доказывает TCP, UDP и DNS через TUN, loopback-only API, отсутствие unmarked route, отсутствие direct leak после `SIGKILL` и повторный запуск после пропущенного userspace cleanup. Последний optional argument — новый absolute evidence directory; при его наличии configs/logs не удаляются после завершения или ошибки. Этот тест не заменяет реальную HAPP-подписку, Huawei/Keenetic capture, mobile operator path или hardware endurance.
