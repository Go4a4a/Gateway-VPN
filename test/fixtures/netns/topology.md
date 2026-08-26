# Gateway VPN netns fixture

`client-fixture` connects to `gateway-fixture` through the transit LAN. Two
independent modem namespaces expose different management subnets. The gateway
main table has no modem default route; marked lookups use table 1101 or 1102.

```text
client-fixture -- 192.168.200.0/24 -- gateway-fixture
                                      | mark 0x1101 -> modem-a-fixture 192.168.8.0/24
                                      ` mark 0x1102 -> modem-b-fixture 192.168.9.0/24
```

The fixture is disposable and contains no production interface, SIM, MAC,
subscription, VPS, or key material.
