# Gateway VPN — сетевые инварианты

```text
Keenetic transit LAN
  → gateway-vpn-tun
  → выбранный Mihomo node
  → modem-specific interface + fwmark
  → modem-specific routing table
  → HiLink NAT
```

- Ни один HiLink default route не добавляется в `main`.
- Root reconciler владеет только base routes/rules protocol `186`, атомарно закрывает TUN gate перед изменением и проверяет каждый context через `ip route get … mark …`.
- Каждый adopted modem получает стабильные `modem_id`, display number, routing table и fwmark; значения не переиспользуются.
- Huawei USB NIC получает только DHCP address/lease через networkd; `UseRoutes=no` и `UseGateway=no` запрещают автоматический main-table default route.
- Management subnet каждого модема обязан быть уникальным и не пересекаться с transit LAN/WireGuard/другими модемами.
- Одинаковая subscription node квалифицируется независимо через каждый modem. Scope результата: `(modem, subscription, node, policy_generation, route_generation)`.
- Path activation требует свежую `QUALIFIED` cell и свежий `BYPASS_QUALIFIED` selected node.
- Приоритет failover: другой node той же cell → следующая subscription на текущем modem → следующий modem.
- Forwarding LAN → HiLink direct и LAN → WireGuard management запрещён.
- Direct DNS/subscription/Mihomo sockets разрешаются только точными modem-scoped nft tuples; смена interface/gateway очищает старые service/endpoint generations.
- WireGuard endpoint получает modem-specific host route и не зависит от active VPN path.
- IPv6 отключён на host и блокируется owned `inet` ruleset; IPv6 forwarding равен `0`.

Конкретные addresses/interfaces таблицы стенда записываются после hardware discovery, а не предполагаются из USB port order.
