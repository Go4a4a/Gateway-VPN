# Gateway VPN Linux network-namespace tests

Эти сценарии требуют root, Linux network namespaces, nftables и iproute2. Они намеренно не запускаются и не считаются `PASS` в Windows cross-build.

```bash
CGO_ENABLED=0 go build -o /tmp/gateway-vpn-netns ./cmd/gateway-vpn
sudo bash ./test/netns/firewall_guard.sh /tmp/gateway-vpn-netns
```

`firewall_guard.sh` создаёт только namespace с уникальным PID suffix, не меняет host ruleset и удаляет namespace через trap. Сценарий проверяет policy routing без unmarked default route, удаление `table inet gateway_vpn`, полный `nft flush ruleset`, durable LAN quarantine, восстановление schema generation и возврат только в `PATH_BLOCKED`.
