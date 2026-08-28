# Gateway VPN Linux network-namespace tests

Эти сценарии требуют root, Linux network namespaces, nftables и iproute2. Они намеренно не запускаются и не считаются `PASS` в Windows cross-build.

```bash
CGO_ENABLED=0 go build -o /tmp/gateway-vpn-netns ./cmd/gateway-vpn
CGO_ENABLED=0 go test -c -o /tmp/gateway-vpn-dataplane-test ./internal/dataplane
CGO_ENABLED=0 go test -c -o /tmp/gateway-vpn-app-test ./internal/app
sudo bash ./test/netns/firewall_guard.sh /tmp/gateway-vpn-netns /tmp/gateway-vpn-dataplane-test
sudo bash ./test/netns/startup_policy.sh /tmp/gateway-vpn-netns /tmp/gateway-vpn-app-test
```

`firewall_guard.sh` создаёт только namespace с уникальным PID suffix, не меняет host ruleset и удаляет namespace через trap. Сценарий проверяет policy routing без unmarked default route, удаление `table inet gateway_vpn`, полный `nft flush ruleset`, durable LAN quarantine, восстановление schema generation и возврат только в `PATH_BLOCKED`.

`startup_policy.sh` использует отдельные namespace и временные SQLite-файлы. Четыре запуска production startup logic доказывают новый boot с включённой блокировкой, минимальное exact-LKG восстановление при выключенной блокировке, сохранение active tuple при restart процесса в том же boot, сброс временного direct-only и возврат kernel firewall в `PATH_BLOCKED` на следующем boot. Ни один сценарий не добавляет unmarked default route.
