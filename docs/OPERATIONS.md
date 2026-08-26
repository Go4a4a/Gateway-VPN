# Gateway VPN — эксплуатация Gateway и VPS

## Поддерживаемая платформа

Gateway устанавливается на Ubuntu Server 24.04 LTS x86_64. VPS role поддерживает перечисленные release manifest профили Ubuntu Server 20.04/22.04/24.04/26.04 LTS x86_64 и Debian 12+; Ubuntu 20.04 принимается только при активном Ubuntu Pro/ESM и актуальных security updates. Windows используется только как среда разработки. Production runtime ожидает systemd, nftables, iproute2 и WireGuard tools; dnsmasq и `/dev/net/tun` обязательны только для Gateway role.

До аппаратного gate запрещено считать Gateway готовым к домашнему трафику. Рабочая установка поддерживает `1..N` HiLink-модемов и не требует резервного uplink; при disconnect единственного модема data path остаётся `PATH_BLOCKED` до его возврата. Стенд должен включать Keenetic и минимум два HiLink-модема с разными management-подсетями, чтобы отдельно доказать multi-modem failover; результаты фиксируются в `PROJECT_STATUS.md`.

## Сборка release

Release закрепляет конкретный Mihomo binary и его SHA-256. Ed25519 identity создаётся один раз на изолированном trusted builder; private key не помещается в репозиторий или GitHub Release:

```bash
./bin/gateway-vpnctl release-keygen \
  --private-key /secure/release-signing.pem \
  --public-key /secure/update-signing.pub

./scripts/build-release.sh \
  0.1.0 vX.Y.Z /path/to/mihomo <64-hex-sha256> \
  /secure/release-signing.pem

./scripts/build-vps-release.sh 0.1.0 /secure/release-signing.pem
./scripts/build-deploy.sh 0.1.0
```

Builder требует clean committed Git tree и создаёт:

- `dist/gateway-vpn-gateway-<version>-linux-amd64/` — полный подписанный tree;
- `dist/gateway-vpn-gateway-<version>-linux-amd64.tar.gz` — Gateway role artifact;
- `dist/gateway-vpn-bootstrap-<version>-linux-amd64` — независимый bootstrap binary;
- `dist/gateway-vpn-deploy-<version>-linux-amd64` и его SBOM/provenance — административный SSH launcher;
- SHA-256 role archives, bootstrap и deploy launcher в stdout trusted build.

Все четыре роли и signed channel можно собрать и повторно проверить одной командой на trusted Ubuntu builder. `dist/` перед запуском обязан отсутствовать, private key должен быть regular non-symlink file без group/other permissions, а tag — точно `vVERSION`:

```bash
./scripts/fetch-mihomo-release.sh \
  vX.Y.Z <SHA-256-официального-linux-amd64-v1-gz> \
  /secure/build-input/mihomo

./scripts/build-release-bundle.sh \
  0.1.0 test vX.Y.Z /secure/build-input/mihomo \
  /secure/release-signing.pem /secure/update-signing.pub \
  OWNER/REPOSITORY v0.1.0 \
  enp2s0 192.168.200.1/24 --enable-dhcp
```

Fetcher принимает только официальный compatible `mihomo-linux-amd64-v1-vX.Y.Z.gz` с GitHub MetaCubeX, ограничивает download/decompression, сначала проверяет опубликованный archive SHA-256 и только затем запускает bounded version probe. Bundle builder вычисляет и закрепляет SHA-256 распакованного binary, а build/channel timestamp канонически берётся из commit time. Поэтому повторная сборка exact commit с теми же Go/Mihomo inputs не зависит от времени запуска.

Подписанный Gateway tree включает binaries, закреплённый Mihomo, `scripts/install-gateway.sh`, `scripts/uninstall.sh`, `config.example.yaml`, весь regular-file `packaging/`, документацию, SBOM/provenance, `release.json`, полный manifest и detached signature. Установленная `/opt/gateway-vpn/releases/v<version>` является точной копией этого дерева и снова проходит `release-verify`; выборочная копия файлов недопустима.

### Signed channel и точная команда GitHub

После сборки role artifacts создаётся version-pinned channel. Для двухмашинной установки публикуются все четыре роли `gateway`, `vps`, `bootstrap`, `deploy`:

```bash
./scripts/build-channel.sh \
  0.1.0 stable \
  /secure/release-signing.pem /secure/update-signing.pub \
  OWNER/REPOSITORY v0.1.0 \
  enp2s0 192.168.200.1/24 \
  bootstrap=dist/gateway-vpn-bootstrap-0.1.0-linux-amd64 \
  deploy=dist/gateway-vpn-deploy-0.1.0-linux-amd64 \
  gateway=dist/gateway-vpn-gateway-0.1.0-linux-amd64.tar.gz \
  vps=dist/gateway-vpn-vps-0.1.0-linux-amd64.tar.gz
```

Builder тем же trusted key создаёт и тут же перепроверяет `channel-stable.json` и `channel-stable.sig`, копирует публичный `update-signing.pub` и пишет `install-gateway-0.1.0.command.txt`. В GitHub Release с точным tag `v0.1.0` загружаются role artifacts, bootstrap, оба channel-файла и public key без переименования. `latest`, branch archive и mutable URL не используются.

### GitHub CI и immutable draft

`.github/workflows/ci.yml` не получает release secrets. На закреплённых full-SHA official Actions и Ubuntu 24.04 он выполняет race suite, vet, четыре CGO-free builds, JS/shell checks, а отдельный root netns job реально проверяет восстановление owned nftables table после delete/`nft flush ruleset` и отсутствие direct route. Dependabot может предложить обновление Action SHA отдельным PR; такое изменение проходит обычный review и не применяется автоматически.

Долгоживущий Ed25519 private key не помещается в GitHub Actions secrets: production signing остаётся на изолированном trusted Linux builder. После успешного bundle gate builder с локально настроенным `GH_TOKEN` создаёт только GitHub draft:

```bash
./scripts/create-github-release-draft.sh \
  0.1.0 test OWNER/REPOSITORY v0.1.0
```

Publisher сверяет clean HEAD, local/remote exact tag, отсутствие существующего release и полный фиксированный список assets, затем вызывает только `gh release create --draft --verify-tag`. Он никогда не публикует draft автоматически. До ручной публикации в GitHub repository settings обязательно включается [**Enable release immutability**](https://docs.github.com/en/code-security/how-tos/secure-your-supply-chain/establish-provenance-and-integrity/prevent-release-changes): настройка действует только для будущих публикаций. Сначала к draft прикрепляются все assets, затем draft просматривается и публикуется вручную; после публикации tag и assets должны отображаться как immutable.

Содержимое `install-gateway-0.1.0.command.txt` является одной точной командой для выбранных при build LAN interface/CIDR. Она скачивает bootstrap только по HTTPS (`curl`, fallback на GNU `wget`), сверяет закреплённый SHA-256, затем запускает его напрямую из root-shell либо через `sudo`. Bootstrap отдельно закрепляет channel/version/commit/raw-manifest hash/signer fingerprint, допускает GitHub signed query string только на проверенном asset redirect и до installer проверяет archive hash/size, Ed25519 release signature и точный полный tree. Если нужен другой LAN interface, команда генерируется заново из того же уже проверенного channel manifest:

```bash
./dist/gateway-vpn-gateway-0.1.0-linux-amd64/bin/gateway-vpnctl \
  channel-install-command \
  --manifest dist/channel-stable.json \
  --signature dist/channel-stable.sig \
  --public-key dist/update-signing.pub \
  --channel stable --release-version 0.1.0 --source-commit <exact-commit> \
  --github-repository OWNER/REPOSITORY --release-tag v0.1.0 \
  --lan-interface enp2s0 --lan-address 192.168.200.1/24 --apply
```

Факт наличия generated command ещё не является Linux installation PASS: первый production release должен пройти реальную загрузку GitHub redirect, dry-run/apply, forced recovery и reboot на Ubuntu 24.04.

Gateway command может включать `--install-dependencies`. До mutation installer проверяет signed release, Ubuntu 24.04/x86_64, NTP/DNS/RAM/disk и целостность APT/dpkg, затем симулирует только отсутствующие `iproute2`, `nftables`, `wireguard-tools`, `kmod`, `procps`, `dnsmasq` с `--no-install-recommends --no-remove --no-upgrade`. После `apt-get update` simulation повторяется; OS packages при application rollback/uninstall не удаляются.

После появления required commands выполняется полный read-only Gateway preflight: TUN/kernel sysctls/systemd-networkd, выбранный LAN interface, отсутствие default route на нём, UFW/firewalld и конфликтующих owned paths. Transit CIDR обязан быть usable RFC1918 host address с `/16../30`, не network/broadcast, не пересекать `10.80.0.0/24`, другие host interface networks или non-default routes; автоматический DHCP дополнительно требует `/24`. Проверка route/address выполняется `gateway-vpnctl gateway-install-preflight` по bounded JSON `ip` output.

First-install transaction сериализована `/run/lock/gateway-vpn-install.lock` и имеет durable active marker под `/var/lib/gateway-vpn-privileged/install-transactions/`. До поднятия LAN и `net.ipv4.ip_forward=1` installer применяет signed boot ruleset `PATH_BLOCKED`. Старые IPv4/IPv6 sysctl, наличие LAN address, административное состояние link и существующий state root входят в marker; boot/manual recovery удаляет только owned table/files/units/address, восстанавливает прежние sysctl/link и архивирует marker лишь после verification. Ephemeral root-owned `/run/gateway-vpn-install-authorized` разрешает start units только самому живому installer; после reboot он исчезает, поэтому при active/broken marker control/data-plane units не запускаются до recovery. Успешная transaction отключает recovery unit, но сохраняет подписанный helper/unit для проверки idempotency.

### VPS role и clean-host dependency provisioning

VPS artifact собирается на том же trusted Linux builder и подписывается тем же release key:

```bash
./scripts/build-vps-release.sh 0.1.0 /secure/release-signing.pem
```

Builder требует clean committed worktree и создаёт `dist/gateway-vpn-vps-0.1.0-linux-amd64/` и одноимённый `.tar.gz`. Release metadata фиксирует только профили `ubuntu-20.04`, `ubuntu-22.04`, `ubuntu-24.04`, `ubuntu-26.04`, `debian-12`, interface `wg-mgmt`, subnet `10.80.0.0/24` и UDP port `51821`.

После загрузки VPS artifact, bootstrap, signed channel files и `update-signing.pub` в тот же immutable GitHub Release точная VPS-команда создаётся так:

```bash
./scripts/generate-vps-install-command.sh \
  0.1.0 stable dist/update-signing.pub OWNER/REPOSITORY v0.1.0 \
  vpn.example.net:51821 \
  '<Gateway-WireGuard-public-key>' \
  '<Admin-WireGuard-public-key>'
```

Generated command всегда включает `--install-dependencies --apply`; forwarding SSH `10.80.0.10 → 10.80.0.2:22` добавляется только необязательным `--allow-gateway-ssh`. До запуска команды нужны базовые `bash`, `mktemp`, `rm`, `chmod`, `sha256sum`, `id` и один HTTPS downloader: `curl` либо GNU `wget`. Для непривилегированной shell дополнительно нужен `sudo`; в root-shell он не требуется. Эти инструменты образуют внешний bootstrap minimum, потому что candidate ещё не может безопасно устанавливать код до проверки собственного hash. Команда не использует download-to-shell: bootstrap сохраняется во временный файл, проверяется exact SHA-256 и только затем получает root.

VPS installer имеет два разных non-mutating результата:

- без `--install-dependencies` отсутствие требуемого пакета является ошибкой;
- с `--install-dependencies`, но без `--apply`, проверяются signed release, exact OS/architecture, NTP, DNS, RAM/disk, целостность APT/dpkg и simulation точного набора пакетов; если пакетов нет, полный nft/WireGuard/port preflight получает статус `NOT_RUN`, а не ложный PASS.

При `--install-dependencies --apply` последовательность фиксирована:

1. bootstrap выполняет внешнюю non-mutating фазу; только exit code `10` от APT simulation классифицируется как необходимость refresh indexes и допускает переход к apply, removal/empty/прочие ошибки блокируют установку;
2. installer обновляет только настроенные администратором APT indexes;
3. повторно выполняет `apt-get -s install --no-install-recommends --no-remove --no-upgrade` и отклоняет любой план с удалением или обновлением уже установленного пакета;
4. устанавливает только отсутствующие top-level packages `iproute2`, `nftables`, `wireguard-tools`, `kmod`, `procps`, `python3-minimal`;
5. проверяет `dpkg` status и `apt-get check`, затем выполняет полный kernel/nft/WireGuard/systemd/port/path/conflict preflight;
6. только после полного PASS создаёт VPS private key локально, устанавливает signed tree и запускает owned services.

Installer никогда не вызывает `upgrade`, `full-upgrade`, `dist-upgrade`, `autoremove` и не меняет APT sources; install plan также не может обновлять уже установленный пакет. Установленные OS packages не удаляются при application rollback или uninstall: они могут использоваться другими сервисами. Если более поздний preflight не прошёл, Gateway VPN state не создаётся, но уже успешно установленные пакеты остаются на хосте.

Install, boot recovery и uninstall сериализуются общим root-owned lock `/run/lock/gateway-vpn-vps-install.lock`. Active marker и orphan `.active.tmp`/WireGuard temp/`.current.new` проверяются до managed package mutation; безопасный root-owned `.active.tmp`, возникший до начала transaction, удаляется только apply-фазой, а неизвестное частичное состояние не перезаписывается. Незавершённая transaction сохраняет active marker до доказанного удаления owned table/units/files и восстановления прежних forwarding sysctl. Обычный uninstall без `--purge-keys` оставляет строгий `root:root 0600` `wg-mgmt.conf`; повторная установка принимает его только при точном совпадении обоих peers и адресов, поэтому VPS public key сохраняется. Для смены peer contract требуется явная reconfiguration либо uninstall с `--purge-keys`.

Ubuntu 20.04 до managed dependency provisioning требует уже установленные `ubuntu-advantage-tools` и `python3-minimal`, attached и неистёкший Ubuntu Pro, `esm-infra=enabled`, `esm-apps=enabled` и отсутствие pending upgrades после актуального APT cache. Pro attach/исправление устаревшей ОС требует решения администратора и намеренно не выполняется installer-ом. VPS cloud/provider firewall должен разрешать входящий UDP/51821. Домашняя/transit LAN на VPS не маршрутизируется: Gateway peer получает только `10.80.0.2/32`, Admin peer — `10.80.0.10/32`.

Успешная установка намеренно завершается состоянием `INSTALLED_NOT_READY` и выводит VPS public key. Готовность подтверждается только после настройки обоих peers и свежего WireGuard handshake; наличие файлов или active unit не заменяет handshake.

### Одна команда для Gateway и VPS

`gateway-vpn-deploy` запускается с отдельного административного Linux/amd64 компьютера. Нужны `/usr/bin/ssh`, HTTPS downloader, `sha256sum`, два заранее проверенных SSH host keys в одном absolute `known_hosts`, passwordless `sudo -n` на обеих machines и отдельные SSH destinations. Launcher запускает OpenSSH с `-F /dev/null`, `BatchMode=yes`, `StrictHostKeyChecking=yes`, запрещёнными password/keyboard-interactive/TTY и bounded output; произвольные SSH options, ProxyCommand и shell fragments из пользовательских полей не принимаются. Первый pinned SSH check создаёт отдельные ControlMaster connections в новом private `0700` temporary directory. Все последующие команды используют те же established TCP sessions после включения fail-closed firewall; TCP/22 ради installer не открывается. В конце launcher посылает обоим masters `-O exit`, проверяет исчезновение control sockets и удаляет temporary directory.

Точная команда создаётся после signed channel. Вариант ниже сам создаёт admin private key локально и после получения VPS public key атомарно формирует `/home/operator/.config/gateway-vpn/admin.conf` с mode `0600`; каталог должен существовать и иметь mode `0700`:

```bash
./scripts/generate-deploy-command.sh \
  0.1.0 stable dist/update-signing.pub OWNER/REPOSITORY v0.1.0 \
  operator@gateway.example root@vps.example \
  /home/operator/.ssh/gateway-vpn-known_hosts \
  enp2s0 192.168.200.1/24 vpn.example.net:51821 - \
  --gateway-identity /home/operator/.ssh/gateway_ed25519 \
  --vps-identity /home/operator/.ssh/vps_ed25519 \
  --admin-config /home/operator/.config/gateway-vpn/admin.conf \
  --enable-dhcp
```

Содержимое `dist/deploy-gateway-vps-0.1.0.command.txt` скачивает exact deploy binary и проверяет его опубликованный SHA-256 до запуска. Launcher затем повторно проверяет raw manifest hash, Ed25519 signature/signer, собственные size/hash/version/commit и наличие всех четырёх exact role artifacts.

Workflow фиксирован:

1. SSH/sudo checks и signed role dry-run выполняются на обеих machines до первого role apply; если APT index требует refresh, отчёт использует консервативный `DEPENDENCY_GATE_PASSED_OR_REFRESH_REQUIRED`, а refresh остаётся только apply-фазе;
2. Gateway role устанавливается в `PATH_BLOCKED`; helper от пользователя `gateway-vpn` создаёт/resume pending private key в `/var/lib/gateway-vpn/secrets/` и возвращает только public key;
3. VPS exact preflight повторяется с реальным Gateway public key, затем VPS installer локально создаёт либо строго проверяет VPS private key;
4. только VPS public key читается из bounded install report; Gateway атомарно создаёт `wireguard.yaml`, а admin machine — optional `wg-quick` config;
5. readiness проверяет owned nft tables, services, локальный HTTPS WebUI, свежий handshake с ожидаемым VPS peer и `PATH_ACTIVE`.

Приватные Gateway/VPS/admin keys не попадают в argv, SSH, stdout, JSON report или GitHub. Повторный запуск читает только public identity существующего Gateway key и сохраняет pending admin/Gateway identity после interruption. Raw public keys в итоговом report заменяются SHA-256 fingerprints.

Exit code `0` выдаётся только для `READY`. Если обе роли установлены, но модем/подписка ещё не настроены либо handshake не появился, launcher возвращает code `3`, state `INSTALLED_NOT_READY` и diagnostic codes без ложного успеха. Любая ошибка после установки первой роли оставляет её fail-closed и указывает точную phase; rollback второй role transaction не удаляет уже безопасно установленный Gateway.

## Проверка установки без изменений

```bash
sudo ./scripts/install-gateway.sh \
  --release-dir ./dist/gateway-vpn-gateway-0.1.0-linux-amd64 \
  --trusted-update-key /secure/update-signing.pub \
  --version 0.1.0 \
  --lan-interface enp2s0 \
  --lan-address 192.168.200.1/24 \
  --install-dependencies
```

Без `--apply` выполняется только validation/dependency simulation. Для реальной установки добавляется `--apply`; DHCP включается только отдельным `--enable-dhcp` и в автоматическом режиме требует `/24` transit subnet.

Перед `--apply` installer проверяет Ubuntu 24.04/x86_64, TUN, nft/ip/wg/systemd/dnsmasq, private usable LAN CIDR и host overlap, Ed25519 release/legacy SHA manifests, conflict UFW/firewalld и неизвестный partial state. Снимок address/route/rule/nft state сохраняется в root-owned `/var/lib/gateway-vpn-privileged/install-transactions/`. Успех означает `INSTALLED_NOT_READY`: fail-closed firewall, IPv4 forwarding, persistent LAN, control service и HTTPS listener проверены, но рабочий VPN path ещё должен быть доказан обычной qualification.

## Первый запуск

Boot order:

1. если остался durable first-install marker, `gateway-vpn-install-recovery.service` восстанавливает прежнее host state; application units имеют отдельный marker gate;
2. `gateway-vpn-firewall.service` загружает owned `PATH_BLOCKED` table;
3. `gateway-vpn-network-recovery.service` до DHCP/API откатывает каждую незавершённую сетевую транзакцию либо завершает уже доказанный confirmation intent;
4. `gateway-vpn.service` открывает SQLite, применяет migrations и проверяет integrity; systemd-networkd сохраняет transit LAN и выдаёт Huawei HiLink только DHCP lease без routes/DNS/NTP;
5. при отсутствии users создаётся `admin` и одноразовый пароль в `/var/lib/gateway-vpn/secrets/bootstrap-admin-password` с mode `0600`;
6. self-signed TLS certificate создаётся в `/var/lib/gateway-vpn/tls/`, fingerprint пишется в journald;
7. HTTPS API начинает слушать LAN address; WireGuard bind подключается после появления адреса;
8. root broker активируется только через `/run/gateway-vpn/network-broker.sock`, доступный owner `gateway-vpn` с mode `0600`;
9. Mihomo и DHCP остаются выключены, пока их конфигурации не проверены.

```bash
sudo cat /var/lib/gateway-vpn/secrets/bootstrap-admin-password
sudo journalctl -u gateway-vpn.service -u gateway-vpn-firewall.service
networkctl status
sudo /opt/gateway-vpn/current/bin/gateway-vpnctl status
```

Пароль необходимо сменить при первом входе. Не передавайте его в issue, diagnostic bundle или журнал разработки.

## Локальные пользователи и сессии

До замены одноразового bootstrap-пароля API разрешает только просмотр текущей сессии, смену собственного пароля и logout. Web UI скрывает остальные вкладки и показывает обязательную форму. Успешная смена сохраняет текущую сессию, отзывает все остальные сессии этого пользователя и очищает флаг `must_change_password`.

Вкладка **Система и безопасность → Пользователи и активные сессии** позволяет:

- создавать локального пользователя с временным паролем;
- переименовывать, включать и отключать пользователя;
- сбрасывать чужой пароль с отзывом всех его сессий и обязательной заменой при следующем входе;
- просматривать активные, ещё не истёкшие сессии и отзывать любую из них;
- удалить пользователя только после отключения и отдельного destructive confirmation.

В MVP все включённые локальные пользователи имеют одинаковые административные права; полноценный RBAC не заявляется. Имена регистронезависимы, содержат 3–64 ASCII-символа и ограничены буквами, цифрами, `.`, `_`, `-`. Текущего пользователя нельзя отключить или удалить, а сервер не позволяет оставить систему без включённого администратора. Отключение пользователя немедленно отзывает его сессии. Session ID в UI является SHA-256 digest случайного bearer token и сам не предоставляет доступ.

Полный versioned контракт фактически зарегистрированного API находится в `docs/openapi.yaml`. Contract test требует документацию каждого `/api/v1` method, уникальный `operationId`, CSRF для всех mutations, cookie security scheme и разрешимые локальные `$ref`.

## Safe apply сетевого адреса

Изменение transit LAN выполняется только во вкладке **Сеть**:

1. control plane проверяет конфликт нового CIDR с WireGuard и сохранёнными modem networks;
2. root broker повторно сверяет CIDR со всеми фактически назначенными IPv4 networks host;
3. старые config, dnsmasq, persistent `70-gateway-vpn-lan.network` и runtime firewall сохраняются в root-owned `/var/lib/gateway-vpn-privileged/network-transactions/<apply-id>/`;
4. `gateway-vpn-network-rollback@<apply-id>.timer` вооружается на 60 секунд до изменения адреса;
5. старый адрес остаётся secondary, а API возвращает одноразовую ссылку на `new_url`; token находится только во fragment `#network-confirm=...` и не отправляется HTTP-серверу при открытии страницы;
6. на новом адресе нужно снова войти и нажать **Подтвердить сетевые настройки**; подтверждение через старый destination отклоняется. Альтернатива — API через `wg-mgmt`;
7. candidate networkd policy атомарно устанавливается и перед подтверждением только reload-ится без destructive reconfigure; без подтверждения отдельный root helper восстанавливает persistent/runtime snapshot без зависимости от SQLite или процесса `gateway-vpn`.

Диагностика незавершённой операции:

```bash
systemctl list-timers 'gateway-vpn-network-rollback@*'
sudo journalctl -u gateway-vpn-network-recovery.service -u gateway-vpn-network-broker.service
sudo find /var/lib/gateway-vpn-privileged/network-transactions -maxdepth 2 -type f -printf '%m %u:%g %p\n'
```

Не запускайте instance rollback timer вручную с придуманным ID. Production-ready статус safe apply требует отдельного netns-теста timeout/reboot и затем проверки на Ubuntu 24.04; Windows unit tests этого не доказывают.

## Изменение политики проверки доступа

Любое изменение targets, matchers или manual node override выделяет новую `policy_generation`. Если пользовательский путь уже активен, Gateway не обрывает его немедленно:

1. SQLite атомарно фиксирует `VERIFYING_POLICY`, новую generation, время начала и deadline через 120 секунд;
2. текущий active node остаётся в Mihomo provider как grace-only transport и проверяется первым, но не возвращается в новый candidate pool, если новая политика его исключила;
3. свежий успех того же node завершает transition без reload/firewall switch;
4. его отказ активирует уже qualified replacement сначала в той же cell, затем по обычному subscription/modem ranking;
5. пока результата нет, Web UI показывает оставшееся время; после deadline Gateway закрывает TUN gate;
6. restart/crash во время transition никогда не продолжает старый путь: boot firewall уже blocked, SQLite transition очищается в `PATH_BLOCKED`, а событие `POLICY_VERIFICATION_INTERRUPTED` сохраняет причину.

Удаление последнего enabled required target требует отдельного подтверждения. После него старый путь живёт только до указанного deadline, затем состояние становится `NO_BYPASS_TARGETS`; это не отключает fail-closed.

Для диагностики используйте вкладки **Обзор**, **Матрица путей** и **Состояние и события**. События `POLICY_VERIFICATION_STARTED`, `POLICY_VERIFIED`, `PATH_ACTIVATION_STARTED`, `POLICY_VERIFICATION_INTERRUPTED` и `PATH_BLOCKED` показывают полный переход. Не изменяйте transition columns SQLite вручную: migration v7 защищает целостность полей trigger-ами.

Во вкладке **Матрица путей** действие **Узлы и проверки** открывает server-side paginated inventory конкретной пары `modem × subscription`:

- **Probe** проверяет точный node через точный modem, возвращает transport/target details и не изменяет authoritative evidence или active path;
- **Квалифицировать** записывает результат только этого node, сохраняя свежие результаты его соседей и пересчитывая aggregate cell;
- **Проверить весь путь** атомарно заменяет evidence всей cell после bounded qualification candidate pool;
- **Ресурсы** лениво загружает current/stale target evidence keyset-страницами, поэтому большой набор targets не раздувает основную matrix response;
- **Активировать** доступно только при свежем `BYPASS_QUALIFIED` в текущих `policy_generation` и `route_generation`. Failed/stale node API отклоняет с `NODE_NOT_FRESH`; прямого Mihomo selector bypass нет.

Ручная активация использует штатный `BeginNodeActivation → fail-closed Actuator → FinishNodeActivation`, повторно проверяет все required targets через выбранный active group и лишь затем открывает TUN gate. События `MANUAL_NODE_PROBED`, `MANUAL_NODE_QUALIFIED`, `MANUAL_PATH_QUALIFIED` и `MANUAL_PATH_ACTIVATION_REQUESTED` дают audit trail.

## Логирование и audit

Production default — structured JSON уровня `info` в отдельном journald namespace `gateway-vpn` и пользовательские/audit events в SQLite. Installer создаёт `/etc/systemd/journald@gateway-vpn.conf.d/retention.conf` с исходным лимитом 256 MiB и retention 14 дней; текущий технический журнал читается командой `journalctl --namespace=gateway-vpn`.

Во вкладке **Система и безопасность → Логирование** настраиваются общий и component-specific уровни, временный debug, retention/дисковый лимит, размер diagnostic excerpt и окно агрегации одинаковых health errors. Уровни применяются без restart. Debug разрешён только на 5 минут–24 часа, хранится отдельным overlay с deadline, автоматически выключается в работающем процессе и очищается после reboot, если deadline истёк. Любое изменение и автоматическое истечение создаёт `LOGGING_SETTINGS_CHANGED`/`LOGGING_DEBUG_EXPIRED` в обязательном audit.

Retention policy имеет отдельный durable state `UNKNOWN/PENDING/APPLYING/APPLIED/FAILED`. После изменения control plane сохраняет settings и вызывает parameter-free root broker: broker сам перечитывает значения из SQLite, атомарно заменяет только фиксированный `retention.conf`, перезапускает `systemd-journald@gateway-vpn.service` и проверяет `is-active`. При ошибке прежний drop-in восстанавливается, WebUI показывает стабильный failure code, а минутный worker повторяет синхронизацию. Изменение только уровней/TTL не перезапускает journald, если retention fingerprint не изменился.

Там же доступен **Технический журнал** только из namespace `gateway-vpn`: страницы до 25 записей, период не более 31 дня и фильтры по уровню, component, modem/subscription/path, correlation ID и тексту. API ограничен 20 запросами в минуту на session. Reader всегда запускает фиксированный `/usr/bin/journalctl` с фиксированными namespace/JSON/reverse flags, считывает не более 129 записей/2 MiB за вызов, ограничивает cursor/поля/сообщение и повторно применяет secret redaction. Control plane не добавляется в широкую группу чтения host journal; доступ выполняется через тот же UID-bound root broker. Недоступность журнала не скрывает logging settings и отображается отдельной ошибкой блока.

Audit входов, policy/settings mutations, manual activation, update/restore и destructive actions не отключается и имеет жёсткий minimum `info`, даже если global level равен `warning` или `error`. Pre-logger handler удаляет subscription URL/token, passwords, private/API keys, proxy credentials, modem serial/identity hash, response body, полный subscription payload и несаницированный Mihomo config также из вложенных map/struct/error. Journal reader и diagnostic builder выполняют независимый второй redaction pass и не полагаются на текущий log level.

## Диагностический архив

Во вкладке **Система и безопасность → Диагностический архив** authenticated администратор может создать ZIP кнопкой **Создать и скачать**. Операция требует CSRF, не принимает параметры или request body, ограничена тремя архивами за 10 минут на session и создаёт обязательное событие `DIAGNOSTIC_BUNDLE_CREATED`. Ответ содержит attachment filename, `Content-Length`, `X-Content-SHA256` и `X-Diagnostic-Complete`.

Архив создаётся только в памяти и не сохраняется на диске Gateway. `manifest.json` показывает schema, `complete`, section errors/warnings, размер и SHA-256 каждого payload-файла. Ошибка host/journal/отдельного read model не отменяет download: архив становится частичным, а manifest содержит стабильный error code без внутренних command/path details. Максимум — 24 MiB несжатых данных и 32 MiB ZIP; journal excerpt отдельно задаётся в Logging в диапазоне 64 KiB–16 MiB.

Архив не содержит private/API keys, session/CSRF tokens, subscription URL/payload/secret refs, proxy credentials/config, target expected body, modem identity/serial/MAC или реальный WireGuard endpoint host. В него входят только redacted config/state/inventory, owned protocol-186 routes/rules, owned `inet gateway_vpn` table, masked WireGuard counters, versions, bounded events/journal и SQLite integrity result. Перед отправкой все host/log/event values проходят дополнительную sanitization. Даже для поддержки не следует прикладывать архив публично без проверки локальной политикой организации.

## Резервное копирование и восстановление

Во вкладке **Система и безопасность → Резервные снимки и восстановление** доступны два разных вида копий:

- локальный SQLite snapshot содержит только БД и хранится на самом Gateway; он создаётся SQLite Online Backup API и проходит `quick_check`, полный `integrity_check`, `foreign_key_check` и SHA-256;
- переносимый `.gvpn` дополнительно содержит strict bootstrap config, Mihomo API secret, TLS cert/key, subscription secrets/payloads и Mihomo generations/state только внутри chunked AES-256-GCM. Ключ выводится Argon2id из passphrase 12–256 UTF-8 байт; passphrase не сохраняется и не восстанавливается.

Переносимую копию следует скачать на внешний носитель и хранить отдельно от passphrase. Файл без обязательных DB/config/Mihomo API secret/TLS cert+key не создаётся и не принимается restore. Лимиты одного artifact: 300 MiB encrypted, 256 MiB plaintext payload и 4096 файлов.

Восстановление выполняется в два шага:

1. выбрать `.gvpn` и ввести passphrase; control plane потоково принимает файл, проверяет AEAD/final record, ZIP paths/types/count/size, manifest SHA-256, SQLite integrity/schema/FK и fixed config paths; upload, passphrase и plaintext ZIP удаляются, live-состояние не меняется;
2. проверить displayed restore/snapshot/schema/size/SHA-256, ввести `ВОССТАНОВИТЬ` и отдельно подтвердить destructive apply. Неверный staging можно удалить кнопкой **Удалить staging** без изменения live-файлов.

После загрузки операция имеет состояние `STAGED` и не является разрешением на замену live-файлов. После Apply Web/API сначала закрывает data path, сохраняет blocked runtime и audit, затем отдельной power-loss-safe записью переводит именно выбранную операцию в `APPLY_REQUESTED` и связывает её с одноразовым 256-bit authorization nonce. Nonce остаётся только в root/apply records и не возвращается API. Только после этого root broker принимает пустой fixed request и ставит в очередь `gateway-vpn-database-restore-dispatch.service`. Fixed dispatcher ждёт одну секунду, чтобы ответ `202 Accepted` гарантированно ушёл через broker socket, и только затем запускает конфликтующий с management plane `gateway-vpn-database-restore.service`. Restore unit:

1. останавливает control plane, broker/socket, Mihomo и dnsmasq;
2. повторно загружает boot `PATH_BLOCKED` ruleset;
3. создаёт verified `pre-restore` SQLite snapshot прежнего состояния;
4. повторно проверяет staging, мигрирует candidate DB до схемы текущего binary, отзывает все sessions и очищает login attempts;
5. через same-filesystem candidates и root-owned journal заменяет `/etc/gateway-vpn/config.yaml`, DB, secrets, subscriptions, TLS и Mihomo generation/state;
6. удаляет stale `mihomo/active`, проверяет live config/SQLite и оставляет runtime `PATH_BLOCKED`;
7. возвращает broker socket и control plane. Mihomo не запускается resume unit: обычный reconciler должен заново доказать текущий tuple `modem × subscription × node` до `PATH_ACTIVE`.

Boot recovery отделён от runtime destructive apply. Только бесконфликтный `gateway-vpn-database-restore-boot.service` включён в `multi-user.target`; при наличии `pending-restore.json` он после update recovery и boot firewall проверяет durable state до network recovery, broker socket и control plane. Обычный `STAGED` является успешным no-op и никогда не применяется из-за перезагрузки. Только `APPLY_REQUESTED` разрешает начать подтверждённую транзакцию либо восстановить journal с тем же nonce. Успешный rollback сначала фиксируется journal-state `ROLLED_BACK`, затем отзывает authorization и возвращает операцию в `STAGED`; повторный boot поэтому может только идемпотентно завершить rollback, но не повторить destructive apply. Новый WebUI Apply получает новый nonce и может безопасно удалить stale `ROLLED_BACK` journal предыдущей попытки. Runtime `gateway-vpn-database-restore.service` не включается ни в один boot target и запускается исключительно fixed-командой root broker после подтверждения в WebUI.

Браузерная сессия после успешного restore намеренно недействительна — требуется войти снова. Если процесс/питание прервались между rename-операциями, root-owned `/var/lib/gateway-vpn-privileged/restore-transactions/` позволяет на следующем запуске вернуть прежние destinations в обратном порядке. Pending marker очищается только после полной проверки committed состояния; любой failed/interrupted transaction после успешного rollback остаётся `STAGED` с `apply_error_code` и требует нового явного Apply.

Диагностика:

```bash
sudo systemctl status gateway-vpn-database-restore.service
sudo systemctl status gateway-vpn-database-restore-dispatch.service
sudo systemctl status gateway-vpn-database-restore-boot.service
sudo systemctl status gateway-vpn-database-restore-resume.service
sudo journalctl --namespace=gateway-vpn -u gateway-vpn-database-restore.service
sudo journalctl --namespace=gateway-vpn -u gateway-vpn-database-restore-boot.service
sudo ls -la /var/lib/gateway-vpn/recovery/
sudo ls -la /var/lib/gateway-vpn-privileged/restore-transactions/
sudo nft list table inet gateway_vpn
```

`gateway-vpn database-restore` не запускается вручную: binary требует fixed systemd-unit environment, а unit обеспечивает остановку процессов и повторную загрузку fail-closed firewall. Если restore unit завершился ошибкой, не удаляйте `pending-restore.json`, operation tree, root transaction journal или rollback paths вручную; сохраните diagnostic bundle, проверьте `last-restore.json`/`operation.apply_error_code` в WebUI и повторяйте Apply только после выяснения причины. Простая перезагрузка не считается повторным Apply. Этот contract проверяется unit/integration tests; реальный bare-metal power-cut остаётся отдельным hardware gate.

## Подписанное обновление и atomic rollback

Во вкладке **Система и безопасность → Подписанное обновление** принимается только versioned `.tar.gz`, подписанный доверенным Ed25519-ключом `/etc/gateway-vpn/update-signing.pub`. До изменения live-системы staging ограничивает archive/entry/path/depth/size, запрещает symlink, hardlink, device, sparse и concatenated/trailing gzip data, проверяет signature, signer SHA-256, полный file manifest, SHA-256 каждого файла, строгий SemVer, Git commit/build date, OS/arch, DB/config и Gateway/Mihomo API contracts. Один verified staging не доказывает установку и может быть безопасно удалён.

После typed `ОБНОВИТЬ` и отдельного confirmation Web/API сначала закрывает data path, сохраняет blocked state и вызывает parameter-free root broker. `gateway-vpn-update.service` повторно загружает fixed `PATH_BLOCKED` firewall, повторно проверяет staging и выполняет одну root transaction:

1. закрепляет `/opt/gateway-vpn/recovery` на старом проверенном release до любых live mutation;
2. устанавливает immutable candidate в `/opt/gateway-vpn/releases/v<version>` и запрещает переиспользовать каталог той же версии для другого signed artifact;
3. останавливает control/broker/Mihomo/dnsmasq, создаёт verified pre-update SQLite snapshot в `/var/lib/gateway-vpn-privileged/update-snapshots/` и мигрирует отдельную candidate DB;
4. запускает candidate binary в offline compatibility mode, проверяет закреплённый Mihomo и действующий Mihomo LKG;
5. атомарно заменяет DB, затем symlink `current`, запускает прежний набор managed services и требует три последовательных health observations;
6. оставляет root journal в `STABILIZING` на 24 часа. Каждые 15 минут finalize timer повторяет binary/DB/service health; после deadline состояние становится `FINALIZED`.

Любая ошибка после подготовки вызывает rollback согласованной пары: прежняя SQLite восстанавливается из verified snapshot, `current` возвращается на старый release, затем проверяется старая версия и запускается прежний набор services. Незавершённые состояния восстанавливает `gateway-vpn-update-recovery.service` до broker/control/data plane. `OnFailure` запускает `gateway-vpn-update-resume.service`, который сначала принудительно повторяет recovery и только после его успеха возвращает management socket/control plane. Межпроцессный Linux `flock` не допускает одновременные Apply/Recover/Finalize.

Блок **Последняя root-транзакция обновления** отдельно от staging показывает только sanitized поля root-owned журнала: update ID, старую/новую версии, `PREPARED…STABILIZING/FINALIZED/ROLLED_BACK/ROLLBACK_FAILED`, timestamps, stability deadline и стабильный error code. Пути, snapshot ID, DB hashes и systemd diagnostics через broker не выдаются. `ROLLED_BACK` означает, что старая пара восстановлена; `ROLLBACK_FAILED` является критическим состоянием и требует сохранить fail-closed режим до диагностики.

Диагностика:

```bash
sudo systemctl status gateway-vpn-update.service
sudo systemctl status gateway-vpn-update-recovery.service
sudo systemctl status gateway-vpn-update-finalize.timer
sudo systemctl status gateway-vpn-update-resume.service
sudo journalctl --namespace=gateway-vpn -u gateway-vpn-update.service -u gateway-vpn-update-recovery.service
sudo readlink /opt/gateway-vpn/current
sudo readlink /opt/gateway-vpn/recovery
sudo ls -la /var/lib/gateway-vpn-privileged/update-transactions/
sudo nft list table inet gateway_vpn
```

Не удаляйте staging, root journal, snapshot, `current` или `recovery` вручную во время `PREPARED…STABILIZING/ROLLING_BACK/ROLLBACK_FAILED`. Update helper-ы нельзя запускать напрямую: они требуют fixed systemd environment и ordering. До реального Ubuntu root/systemd/power-cut теста механизм имеет статус `CODE_PASS / LINUX_NOT_RUN`, а не production acceptance.

## Удалённый доступ WireGuard

Management-туннель настраивается во вкладке **Удалённый доступ**. Для первой настройки нужны private key Gateway, public key VPS и endpoint VPS с фиксированным UDP-портом `51821`. Gateway использует `10.80.0.2/32`, а `AllowedIPs` в MVP фиксирован как `10.80.0.0/24`. Начальное ожидание нового handshake — 45 секунд; Web UI допускает диапазон 30–180 секунд.

Конфигурация атомарно сохраняется в `/var/lib/gateway-vpn/secrets/wireguard.yaml` с mode `0600`. Private key не возвращается API и не подставляется обратно в форму: пустое поле при последующем изменении сохраняет действующий ключ. После сохранения root broker получает только безаргументную команду reconciliation, самостоятельно читает защищённый файл и SQLite, разрешает точный endpoint tuple и пробует модемы по priority.

Для каждого `MODEM_READY` Web UI показывает `UNTESTED`, `PROBING`, `REACHABLE`, `BLOCKED` либо `STALE`. Кандидат становится активным только после handshake новее начала пробы. При unplug маршрут VPS переносится на следующий модем; при hostname последний рабочий IPv4 сохраняется во время кратковременной ошибки DNS. Устаревший handshake показывается как предупреждение и сам по себе не влияет на пользовательский VPN path.

На VPS peer Gateway должен иметь `AllowedIPs = 10.80.0.2/32`; `Address = 10.80.0.1/24` создаёт connected route автоматически. До признания этапа выполненным обязательны `wg show wg-mgmt latest-handshakes`, `ip route get 10.80.0.2` на VPS и фактический вход в Web UI через `https://10.80.0.2:8443` при остановленном Mihomo.

## Проверки fail-closed

На Linux-стенде обязательны:

```bash
sudo nft list table inet gateway_vpn
ip -json -4 rule show
ip -json -4 route show table all protocol 186
ip -json -4 route get 1.1.1.1 mark 0x1101   # mark/table заменить observed значениями модема
curl -6 --max-time 5 https://example.com   # должен завершиться ошибкой
sudo systemctl kill -s SIGKILL gateway-vpn-mihomo.service
```

После остановки Mihomo новый LAN traffic не должен попасть в HiLink напрямую. `nft flush ruleset`, reboot, unplug/replug обоих модемов и обратный USB-порядок входят в integration/hardware matrix и не заменяются unit-тестами.

`gateway-vpn-firewall-guard.service` независимо от control plane слушает `nft monitor ruleset` и каждые две секунды проверяет owned table, три base chain с `policy drop`, schema generation `1` и критические rules. При исчезновении/повреждении table guard сохраняет root-only marker в `/run/gateway-vpn-firewall-guard/`, переводит transit LAN interface administratively down, атомарно загружает только `table inet gateway_vpn` в `PATH_BLOCKED`, повторно проверяет её и лишь затем возвращает link up. Если восстановление не прошло, marker и quarantine сохраняются через restart guard-процесса.

Диагностика guard:

```bash
systemctl status gateway-vpn-firewall-guard.service
journalctl -u gateway-vpn-firewall-guard.service
cat /run/gateway-vpn-firewall-guard/quarantine 2>/dev/null || true
```

Guard никогда не выполняет `nft flush ruleset` и не восстанавливает таблицы других приложений. Подготовленный Linux-сценарий `test/netns/firewall_guard.sh` создаёт изолированные namespace и проверяет delete owned table/полный flush, но результат считается `PASS` только после фактического root-запуска на Linux.

## Keenetic и IPv6

Архитектурное требование: на WAN Keenetic отсутствуют global IPv6 prefix/default route; на Gateway IPv6 отключён sysctl и блокируется nftables. Точная последовательность меню KeeneticOS будет добавлена после фиксации модели Keenetic и версии прошивки на аппаратном этапе 0. Критерий проверки неизменен: `curl -6` с домашнего клиента не устанавливает интернет-соединение.

## Удаление

`./scripts/uninstall.sh` по умолчанию является dry-run. `--apply` удаляет units/program/config, но сохраняет `/var/lib/gateway-vpn`. `--purge-data --apply` сначала сохраняет копию SQLite в `/root`, затем удаляет runtime data. Host firewall/network после удаления восстанавливаются только явной административной операцией.
