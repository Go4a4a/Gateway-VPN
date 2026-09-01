# Gateway VPN — эксплуатация Gateway и VPS

## Поддерживаемая платформа

Gateway устанавливается на Ubuntu Server 24.04 LTS x86_64. VPS role поддерживает перечисленные release manifest профили Ubuntu Server 20.04/22.04/24.04/26.04 LTS x86_64 и Debian 12+; Ubuntu 20.04 принимается только при активном Ubuntu Pro/ESM и актуальных security updates. Gateway/VPS runtime на Windows не поддерживается; Windows 10/11 x64 используется только как административный компьютер для portable `gateway-vpn-deploy.exe`. Production Linux runtime ожидает systemd, nftables, iproute2 и WireGuard tools; dnsmasq и `/dev/net/tun` обязательны только для Gateway role.

До аппаратного gate запрещено считать Gateway готовым к домашнему трафику. Рабочая установка поддерживает `1..N` HiLink-модемов и не требует резервного uplink; при disconnect единственного модема data path остаётся `PATH_BLOCKED` до его возврата. Стенд должен включать Keenetic и минимум два HiLink-модема с разными management-подсетями, чтобы отдельно доказать multi-modem failover; результаты фиксируются в `PROJECT_STATUS.md`.

## Сборка release

Release закрепляет конкретный Mihomo binary и его SHA-256. Ed25519 identity создаётся один раз на trusted Linux builder; private key не помещается в репозиторий, GitHub, Gateway или VPS.

Каждый полный Gateway VPN release уже несёт одну проверенную Mihomo внутри `libexec/mihomo`. Обычный release может оставить прежнюю Mihomo либо обновить её; установленный Gateway не скачивает core из отдельной папки и не заменяет binary на месте.

Штатный production-вариант — один переносимый файл `gateway-vpn-production.gvkey`. Внутри него private/public Ed25519 и fingerprint целиком зашифрованы AES-256-GCM; ключ шифрования выводится Argon2id (`64 MiB`, 3 iteration, parallelism 2) из passphrase длиной не менее 10 Unicode-символов и не более 256 UTF-8 байт. Header аутентифицирован, неизвестный format/KDF/cipher отклоняется до использования заявленных файлом KDF-параметров. Файл создаётся exclusive, `fsync`-ится, тут же расшифровывается и cryptographically self-verifies; existing destination никогда не перезаписывается. Для production рекомендуется запоминаемая фраза длиной 14 и более символов.

Для постоянного хранения не требуется Linux-раздел или специальная флешка: `.gvkey` можно хранить как обычный файл вне Git worktree, в том числе на Windows. Нужна byte-identical verified backup-копия в независимом месте и отдельно сохранённая сильная passphrase. Потеря и primary, и backup лишит проект возможности выпускать доверенные обновления; потеря passphrase эквивалентна потере ключа. Passphrase нельзя помещать рядом с `.gvkey`, в shell history, argv, environment, GitHub Secrets этого репозитория или журнал.

Создание primary и backup выполняется одной Linux-командой. Скрипт локально и без echo спрашивает passphrase дважды; временный passphrase-файл существует только в `/dev/shm` tmpfs:

```bash
./scripts/create-release-key-file.sh \
  /publisher-primary/gateway-vpn-production.gvkey \
  /publisher-backup/gateway-vpn-production.gvkey
```

При сборке encrypted wrapper спрашивает passphrase один раз, проверяет `.gvkey`, раскрывает пару только в отдельный `0700` каталог настоящего `/dev/shm`, вызывает обычный reproducible builder и удаляет временную pair через `trap` при success/error/signal:

```bash
./scripts/build-release-bundle-encrypted.sh \
  0.1.0-rc.1 candidate v1.19.30 /opt/mihomo \
  /publisher-primary/gateway-vpn-production.gvkey \
  OWNER/REPOSITORY v0.1.0-rc.1
```

Public key автоматически извлекается из `.gvkey` во временное хранилище и входит в подписанный release как `update-signing.pub`; для установки/обновления passphrase и private key не требуются. Low-level `release-keyfile-create`, `release-keyfile-verify`, `release-keyfile-backup` и `release-keyfile-unlock` принимают passphrase только из абсолютного private `0600` файла в закрытом каталоге или bounded stdin (`--passphrase-file -`). Постоянный plaintext PEM workflow ниже сохраняется только как низкоуровневый compatibility/test contract и требует зашифрованной файловой системы:

```bash
install -d -m 0700 /secure/primary
./bin/gateway-vpnctl release-keygen \
  --private-key /secure/primary/release-signing.pem \
  --public-key /secure/primary/update-signing.pub

./scripts/build-release.sh \
  0.1.0 vX.Y.Z /path/to/mihomo <64-hex-sha256> \
  /secure/primary/release-signing.pem

./scripts/build-vps-release.sh 0.1.0 /secure/primary/release-signing.pem
./scripts/build-deploy.sh 0.1.0
```

Builder требует clean committed Git tree и создаёт:

- `dist/gateway-vpn-gateway-<version>-linux-amd64/` — полный подписанный tree;
- `dist/gateway-vpn-gateway-<version>-linux-amd64.tar.gz` — Gateway role artifact;
- `dist/gateway-vpn-bootstrap-<version>-linux-amd64` — независимый bootstrap binary;
- `dist/gateway-vpn-deploy-<version>-linux-amd64` и `dist/gateway-vpn-deploy-<version>-windows-amd64.exe`, каждый со своим SBOM/provenance, — административные SSH launchers;
- SHA-256 role archives, bootstrap и deploy launcher в stdout trusted build.

Все четыре роли и signed channel можно собрать и повторно проверить одной командой на trusted Ubuntu builder. `dist/` перед запуском обязан отсутствовать, private key должен быть regular non-symlink file без group/other permissions, а tag — точно `vVERSION`:

```bash
./scripts/fetch-mihomo-release.sh \
  vX.Y.Z <SHA-256-официального-linux-amd64-v1-gz> \
  /secure/build-input/mihomo

./scripts/build-release-bundle.sh \
  0.1.0 test vX.Y.Z /secure/build-input/mihomo \
  /secure/primary/release-signing.pem /secure/primary/update-signing.pub \
  OWNER/REPOSITORY v0.1.0
```

Если полный release выпускается прежде всего ради новой проверенной Mihomo, к той же сборке явно добавляется maintenance channel. Например, `1.0.1` с Mihomo `v1.20.0`, проверенная как обновление exact установленной версии `1.0.0`:

```bash
./scripts/build-release-bundle-encrypted.sh \
  1.0.1 stable v1.20.0 /secure/build-input/mihomo \
  /publisher-primary/gateway-vpn-production.gvkey \
  OWNER/REPOSITORY v1.0.1 \
  --mihomo-maintenance \
  --mihomo-channel stable \
  --mihomo-urgency recommended \
  --mihomo-summary 'Проверенное обновление совместимости Mihomo.' \
  --compatible-gateway-version 1.0.0
```

`--compatible-gateway-version` повторяется для каждой **точной** версии Gateway, с которой реально проверялся переход; диапазон и предположение «совместимо со всеми старыми» запрещены. Сборка создаёт полный `gateway-vpn-gateway-1.0.1-linux-amd64.tar.gz` и дополнительную пару `mihomo-channel-stable.json/.sig`, которая указывает именно на этот archive. В исходники репозитория или отдельную GitHub-папку Mihomo binary не добавляется.

Fetcher принимает только официальный compatible `mihomo-linux-amd64-v1-vX.Y.Z.gz` с GitHub MetaCubeX, ограничивает download/decompression, сначала проверяет опубликованный archive SHA-256 и только затем запускает bounded version probe. Bundle builder вычисляет и закрепляет SHA-256 распакованного binary, а build/channel timestamp канонически берётся из commit time. Поэтому повторная сборка exact commit с теми же Go/Mihomo inputs не зависит от времени запуска.

Подписанный Gateway tree включает binaries, закреплённый Mihomo, `scripts/install-gateway.sh`, `scripts/uninstall.sh`, `config.example.yaml`, весь regular-file `packaging/`, документацию, SBOM/provenance, `release.json`, полный manifest и detached signature. Установленная `/opt/gateway-vpn/releases/v<version>` является точной копией этого дерева и снова проходит `release-verify`; выборочная копия файлов недопустима.

### Signed channel и точная команда GitHub

После сборки role artifacts создаётся version-pinned channel. Для двухмашинной установки публикуются все четыре роли `gateway`, `vps`, `bootstrap`, `deploy`:

```bash
./scripts/build-channel.sh \
  0.1.0 stable \
  /secure/primary/release-signing.pem /secure/primary/update-signing.pub \
  OWNER/REPOSITORY v0.1.0 \
  bootstrap=dist/gateway-vpn-bootstrap-0.1.0-linux-amd64 \
  deploy=dist/gateway-vpn-deploy-0.1.0-linux-amd64 \
  deploy-windows=dist/gateway-vpn-deploy-0.1.0-windows-amd64.exe \
  gateway=dist/gateway-vpn-gateway-0.1.0-linux-amd64.tar.gz \
  vps=dist/gateway-vpn-vps-0.1.0-linux-amd64.tar.gz
```

Builder тем же trusted key создаёт и тут же перепроверяет `channel-stable.json` и `channel-stable.sig`, копирует публичный `update-signing.pub` и пишет `install-gateway-0.1.0.command.txt`. В GitHub Release с точным tag `v0.1.0` загружаются role artifacts, bootstrap, оба channel-файла и public key без переименования. `latest`, branch archive и mutable URL не используются.

Если сборка содержит Mihomo maintenance channel, publisher автоматически находит только полные безопасные пары `mihomo-channel-stable/testing.json + .sig`, повторно проверяет signature, exact commit, сопровождающий Gateway tree и archive и добавляет пару в тот же draft. Наличие только manifest либо только signature блокирует публикацию.

### GitHub CI и immutable draft

`.github/workflows/ci.yml` не получает release secrets. На закреплённых full-SHA official Actions и Ubuntu 24.04 он выполняет race suite, vet, четыре CGO-free builds, JS/shell checks, а отдельный root netns job реально проверяет восстановление owned nftables table после delete/`nft flush ruleset` и отсутствие direct route. Dependabot может предложить обновление Action SHA отдельным PR; такое изменение проходит обычный review и не применяется автоматически.

Долгоживущий Ed25519 private key не помещается в GitHub Actions secrets: production signing остаётся на изолированном trusted Linux builder. После успешного bundle gate builder с локально настроенным `GH_TOKEN` создаёт только GitHub draft:

```bash
./scripts/create-github-release-draft.sh \
  0.1.0 test OWNER/REPOSITORY v0.1.0
```

Publisher сверяет clean HEAD, local/remote exact tag, отсутствие существующего release и полный фиксированный список assets, затем вызывает только `gh release create --draft --verify-tag`. Он никогда не публикует draft автоматически. До ручной публикации в GitHub repository settings обязательно включается [**Enable release immutability**](https://docs.github.com/en/code-security/how-tos/secure-your-supply-chain/establish-provenance-and-integrity/prevent-release-changes): настройка действует только для будущих публикаций. Сначала к draft прикрепляются все assets, затем draft просматривается и публикуется вручную; после публикации tag и assets должны отображаться как immutable.

Содержимое `install-gateway-0.1.0.command.txt` является одной универсальной точной командой и не содержит имени интерфейса, CIDR или DHCP-политики конкретного компьютера. Она скачивает bootstrap только по HTTPS (`curl`, fallback на GNU `wget`), сверяет закреплённый SHA-256, затем запускает его напрямую из root-shell либо через `sudo`. Bootstrap отдельно закрепляет channel/version/commit/raw-manifest hash/signer fingerprint, допускает GitHub signed query string только на проверенном asset redirect и до installer проверяет archive hash/size, Ed25519 release signature и точный полный tree.

После проверки bootstrap интерактивный мастер на самом Gateway:

1. требует настоящий terminal и выполняет только read-only `iproute2` inventory;
2. показывает все найденные интерфейсы с номером, типом, состоянием carrier/link, IPv4, udev Huawei/USB risk и default-route status;
3. предлагает включить все безопасные Ethernet-порты либо позволяет ввести несколько номеров через запятую; пользователь явно подтверждает набор;
4. объединяет выбранные порты в owned bridge `gateway-vpn-lan` с одним transit address, поэтому WebUI и SSH доступны через любой из этих портов, а Keenetic WAN можно подключить к любому из них;
5. запрещает loopback, non-Ethernet, Huawei USB/HiLink, интерфейс с уже настроенным IPv4, интерфейс текущего default route и обнаруженный интерфейс активной SSH management-сессии;
6. спрашивает, нужен ли DHCP для WAN Keenetic/прямых management clients и можно ли установить отсутствующие managed dependencies;
7. предлагает первый свободный `/24` из безопасного набора либо принимает другой private host CIDR `/16../30`; при DHCP разрешён только `/24`;
8. проверяет CIDR против всех IPv4 addresses/non-default routes хоста и фиксированной WireGuard management subnet;
9. отдельно предлагает штатный OpenSSH/SFTP (рекомендуется) и optional входящий WireGuard для телефонов, ПК или роутеров; для WireGuard проверяет public endpoint, отдельную private subnet, UDP port и DNS;
10. предлагает не ждать внешнюю сеть при boot (рекомендуется для Gateway) либо сохранить штатную Ubuntu policy; в рекомендуемом режиме Ethernet, HiLink, DHCP и Интернет не задерживают загрузку ОС;
11. определяет GRUB и UEFI/Legacy, затем предлагает скрытую автоматическую загрузку Ubuntu, видимое меню на 5 секунд либо сохранение текущей policy; если найдена Windows boot entry, скрытый вариант не предлагается, а неизвестный загрузчик всегда сохраняется;
12. отдельно показывает полный список обязательных автоматических настроек и runtime-параметров, которые позднее меняются в WebUI;
13. запускает signed read-only preflight, показывает итоговую сводку и применяет изменения только после точного ввода `INSTALL`.

Каждый пункт мастера объясняет назначение простыми словами, показывает обнаруженное состояние, явно помечает рекомендацию и последствия остальных вариантов. `Enter` принимает только видимую рекомендацию, `q` завершает работу без persistent mutation. Security invariants (проверка подписи, firewall, IPv6 block, ownership, recovery) не изображаются как отключаемые вопросы: они перечисляются отдельным блоком до итогового `INSTALL`.

Appliance-вариант boot-network устанавливает только owned drop-in `/etc/systemd/system/systemd-networkd-wait-online.service.d/gateway-vpn.conf`, который успешно завершает штатное ожидание сразу. Сам `systemd-networkd` продолжает работать и динамически настраивает появившиеся интерфейсы; Gateway control plane не зависит от `network-online.target`. Вариант `Сохранить Ubuntu` не создаёт drop-in.

GRUB policy хранится только в owned `/etc/default/grub.d/90-gateway-vpn.cfg`; `/etc/default/grub` не перезаписывается. После изменения выполняются `update-grub` и `grub-script-check`. Recovery/uninstall удаляют owned drop-in и заново генерируют валидный `grub.cfg`. Даже при скрытом меню остаётся короткое окно `Esc` (UEFI) либо `Shift` (Legacy BIOS) для ручного recovery.

OpenSSH/SFTP — отдельный понятный шаг interactive wizard. Мастер показывает, установлен ли `openssh-server`, включён и запущен ли `ssh.service`, объясняет, что SFTP является частью OpenSSH, и рекомендует **Да**. `Enter` принимает рекомендацию; **Нет** означает, что installer не устанавливает/не включает OpenSSH и не создаёт TCP/22 rule. Automation также использует default-on; явный отказ передаётся только `--disable-ssh` и сохраняется как `network.disable_ssh_management: true` плюс `lan_ssh_enabled: false` в install report.

При включённом выборе OpenSSH входит в managed dependency plan. Если пакет отсутствует, его bytes скачиваются до включения fail-closed firewall без запуска daemon; установка и `ssh.service` activation происходят только после durable rollback marker и `PATH_BLOCKED`. До изменения service выполняется `sshd -t`, затем `systemctl enable --now ssh.service`, повторная проверка enabled/active и IPv4 wildcard listener TCP/22. nftables принимает новые SSH connections только через точный set `local_management_interfaces`: initially это выбранный LAN/bridge, а подтверждённый topology profile может добавить несколько явно назначенных management Ethernet-портов. Обычный dedicated Ethernet uplink и HiLink туда не попадают; исключение — сознательно выбранная общая карта `SHARED_ONE_ARM`. Existing SSH users/keys/password policy сохраняются; Gateway VPN не включает root login и не создаёт общий пароль SSH. При отключённом DHCP прямому management-компьютеру потребуется статический адрес из выбранной transit subnet.

После установки используйте Ubuntu account, уже разрешённый политикой OpenSSH:

```bash
ssh <ubuntu-user>@<LAN-IP-Gateway>
sftp <ubuntu-user>@<LAN-IP-Gateway>
sudo sshd -t
sudo systemctl is-enabled ssh.service
sudo systemctl is-active ssh.service
sudo ss -H -ltn 'sport = :22'
sudo nft list chain inet gateway_vpn input
```

Ожидается ровно одно owned разрешение вида `iifname @local_management_interfaces tcp dport 22 accept`; сами разрешённые интерфейсы перечислены в одноимённом set. Попадание обычного dedicated uplink в этот set является security defect. Если SSH/SFTP сознательно выключен, TCP/22 rule не должно быть вовсе, а watchdog показывает компонент как `NOT_APPLICABLE`.

Owned LAN networkd policies используют точные ранние имена `05-gateway-vpn-lan.*` и `06-gateway-vpn-lan-<port>.network`, чтобы выбранные interfaces не были перехвачены более поздними generated `10-netplan-*` matches после reboot. Installer не удаляет и не переписывает netplan; только явно выбранные dedicated ports получают более точную owned policy.

Чтобы включить **все** физические Ethernet-порты, первый interactive install следует запускать с локальной консоли. Порт текущей SSH-сессии намеренно исключается: удалённое преобразование несущего session link в bridge с другим IP может оборвать installer до rollback. При локальном запуске все свободные ports предлагаются по умолчанию. STP включён, но не следует одновременно подключать несколько bridge ports к одному switch без осознанной топологии.

EOF, отмена, отсутствие TTY, конфликт подсети или неуспешный preflight завершаются без persistent Gateway VPN changes. Если для preflight не хватает managed packages, до подтверждения проверяется безопасный APT plan; после `INSTALL` ставятся только подтверждённые отсутствующие packages, затем полный host preflight повторяется до создания Gateway-owned state.

Такая же universal command может быть сгенерирована вручную из уже проверенного channel manifest:

```bash
./dist/gateway-vpn-gateway-0.1.0-linux-amd64/bin/gateway-vpnctl \
  channel-install-command \
  --manifest dist/channel-stable.json \
  --signature dist/channel-stable.sig \
  --public-key dist/update-signing.pub \
  --channel stable --release-version 0.1.0 --source-commit <exact-commit> \
  --github-repository OWNER/REPOSITORY --release-tag v0.1.0 \
  --interactive
```

Для CI, заранее подготовленного provisioning и `gateway-vpn-deploy` сохраняется неинтерактивный automation mode: там `--lan-interface`, `--lan-address`, dependency/DHCP policy, `--boot-network-policy`, `--grub-policy` и `--apply` задаются явно. Он намеренно не угадывает hardware inputs.

Факт наличия generated command ещё не является Linux installation PASS: первый production release должен пройти реальную загрузку GitHub redirect, dry-run/apply, forced recovery и reboot на Ubuntu 24.04.

Gateway command может включать `--install-dependencies`. До mutation installer проверяет signed release, Ubuntu 24.04/x86_64, NTP/DNS/RAM/disk и целостность APT/dpkg, затем симулирует только отсутствующие `iproute2`, `nftables`, `wireguard-tools`, `kmod`, `procps`, `dnsmasq-base`, `openssh-server` с `--no-install-recommends --no-remove --no-upgrade`. Fresh install и внешний bootstrap/download требуют NTP; при обновлении уже установленного fail-closed Gateway локальный signed artifact может проверяться без NTP/DNS, после чего host-upgrade transaction отдельно аутентифицирует старый release и DB до первого изменения. Используется именно binary-only `dnsmasq-base`, чтобы installer не запускал конкурирующий общий DNS daemon; при `--enable-dhcp` существующий wildcard либо LAN listener TCP/UDP 53 блокирует apply до mutation. Managed dnsmasq запускается сразу как `gateway-vpn-dns:gateway-vpn`, а lease хранит в отдельном systemd-owned `/var/lib/gateway-vpn-dnsmasq` mode `0700`; общий `/var/lib/gateway-vpn` он не может перечислять или изменять. После `apt-get update` simulation повторяется; OS packages при application rollback/uninstall не удаляются.

После появления required commands выполняется полный read-only Gateway preflight: TUN/kernel sysctls/systemd-networkd, выбранный LAN interface, отсутствие default route на нём, UFW/firewalld и конфликтующих owned paths. Transit CIDR обязан быть usable RFC1918 host address с `/16../30`, не network/broadcast, не пересекать `10.80.0.0/24`, другие host interface networks или non-default routes; автоматический DHCP дополнительно требует `/24`. Проверка route/address выполняется `gateway-vpnctl gateway-install-preflight` по bounded JSON `ip` output.

First-install transaction сериализована `/run/lock/gateway-vpn-install.lock` и имеет durable active marker под `/var/lib/gateway-vpn-privileged/install-transactions/`. До поднятия LAN и `net.ipv4.ip_forward=1` installer применяет signed boot ruleset `PATH_BLOCKED`. Старые IPv4/IPv6 sysctl, наличие LAN address, административное состояние link и существующий state root входят в marker; boot/manual recovery удаляет только owned table/files/units/address, восстанавливает прежние sysctl/link и архивирует marker лишь после verification. Ephemeral root-owned `/run/gateway-vpn-install-authorized` разрешает start units только самому живому installer; после reboot он исчезает, поэтому при active/broken marker control/data-plane units не запускаются до recovery. Успешная transaction отключает recovery unit, но сохраняет подписанный helper/unit для проверки idempotency.

### VPS role и clean-host dependency provisioning

VPS artifact собирается на том же trusted Linux builder и подписывается тем же release key:

```bash
./scripts/build-vps-release.sh 0.1.0 /secure/primary/release-signing.pem
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
4. устанавливает только отсутствующие top-level packages `iproute2`, `nftables`, `wireguard-tools`, `kmod`, `procps`, `python3`, `openssl` и `passwd`; полный пакет `python3`, а не только `python3-minimal`, требуется для строгого JSON-разбора host preflight и recovery gates;
5. проверяет `dpkg` status и `apt-get check`, затем выполняет полный kernel/nft/WireGuard/systemd/port/path/conflict preflight;
6. только после полного PASS запрашивает bootstrap-пароль VPS Hub (либо принимает защищённый root-only password file для automation), создаёт локальные VPS/WireGuard/update/TLS identities, отдельного system user `gateway-vpn-vps`, Agent DB и администратора с обязательной сменой пароля при первом входе;
7. устанавливает signed tree, ограничивает VPS Hub адресами `127.0.0.1:9443` и `10.80.0.1:9443`, открывает второй адрес только Admin peer `10.80.0.10` и запускает owned services.

Installer никогда не вызывает `upgrade`, `full-upgrade`, `dist-upgrade`, `autoremove` и не меняет APT sources; install plan также не может обновлять уже установленный пакет. Установленные OS packages не удаляются при application rollback или uninstall: они могут использоваться другими сервисами. Если более поздний preflight не прошёл, Gateway VPN state не создаётся, но уже успешно установленные пакеты остаются на хосте.

Install, boot recovery и uninstall сериализуются общим root-owned lock `/run/lock/gateway-vpn-vps-install.lock`. Root-only install transactions остаются в `/var/lib/gateway-vpn-vps/install-transactions`, а непривилегированный Agent владеет только `/var/lib/gateway-vpn-vps/agent`; он не может читать/менять install journal. Active marker и orphan `.active.tmp`/WireGuard temp/`.current.new` проверяются до managed package mutation; безопасный root-owned `.active.tmp`, возникший до начала transaction, удаляется только apply-фазой, а неизвестное частичное состояние не перезаписывается. Незавершённая transaction сохраняет active marker до доказанного удаления owned table/units/files/account и восстановления прежних forwarding sysctl.

Обычный uninstall без `--purge-keys` сохраняет `wg-mgmt.conf`, VPS Agent DB, настройки, администратора, TLS/update/WireGuard identity и скачанные backups. Повторная установка принимает их только после строгой проверки user/group/modes, SQLite/schema/auth/TLS, secret references и совпадения Agent public key с `wg-mgmt`; смешанное либо частичное состояние отклоняется. `--purge-keys` удаляет и эти данные вместе с service account. Для смены peer contract требуется явная reconfiguration либо purge.

Ubuntu 20.04 до managed dependency provisioning требует уже установленные `ubuntu-advantage-tools` и полный пакет `python3`, attached и неистёкший Ubuntu Pro, `esm-infra=enabled`, `esm-apps=enabled` и отсутствие pending upgrades после актуального APT cache. Pro attach/исправление устаревшей ОС требует решения администратора и намеренно не выполняется installer-ом. VPS cloud/provider firewall должен разрешать входящий UDP/51821. Домашняя/transit LAN на VPS не маршрутизируется: Gateway peer получает только `10.80.0.2/32`, Admin peer — `10.80.0.10/32`.

Успешная установка запускает restricted VPS Hub, но внешний management link намеренно остаётся `INSTALLED_NOT_READY` и выводит VPS public key. WebUI доступен локально или через уже настроенный Admin peer; полная готовность канала подтверждается только после настройки peers и свежего WireGuard handshake. Наличие файлов либо active unit не заменяет handshake.

Successor добавляет один лёгкий `gateway-vpn-vps` Go Agent с embedded WebUI/CLI/SQLite. Он слушает только localhost и admin WireGuard, а SSH port forwarding остаётся аварийным способом доступа; публичный bind запрещён по умолчанию. WebUI показывает Gateway/links/admin/resources/ACL, ownership-scoped watchdog, тематические logs, diagnostics и отдельную signed update page. Agent не предоставляет shell, generic systemd manager, APT upgrade либо power control VPS.

Текущая VPS Agent schema 4 предоставляет рабочие вкладки **Обзор**, **Gateway**, **Каналы**, **Администраторы**, **End-to-end relay**, **Локальные ресурсы**, **Матрица доступа**, **Watchdog**, **Журналы**, **Backup/восстановление** и **Диагностика**. Pairing invitation резервирует отдельную canonical private `/30`, содержит endpoint/VPS public identity и случайный 256-bit token; в SQLite сохраняется только SHA-256 токена. Raw token возвращается один раз, удаляется из DOM/памяти WebUI при уходе со страницы, имеет срок 5 минут–24 часа и общий budget восемь неверных попыток. Consume одной SQLite transaction создаёт peer, переносит prefix reservation и закрывает invitation; replay, duplicate site/key, пересечение prefix и неверный fingerprint/token не оставляют частичный Gateway.

`gateway-vpn-vps-operations.timer` раз в минуту запускает fixed root-owned collector. WebUI не передаёт ему unit, путь, executable или аргументы: helper читает только allowlisted Gateway VPN units, краткий `wg-mgmt` summary без ключей/endpoints, owned route protocol `186`, owned nftables table `inet gateway_vpn_vps`, интерфейсную IPv4-сводку и последний Management Fabric watchdog status. Результат проходит второй redaction pass и атомарно заменяет `/var/lib/gateway-vpn-vps-privileged/operations/snapshot.json` с доступом Agent только на чтение. Parent позволяет service group только traversal (`0710`), operations имеет `0750`, snapshot `0640`, а соседние restore/fabric каталоги остаются `root:root 0700`; Agent не может их перечислять, читать или менять. Отсутствующий либо частичный snapshot отображается как `DEGRADED`; audit events SQLite остаются доступны и не подменяются telemetry.

Вкладка **Журналы** разделяет bounded view на общий лог, Agent/control plane, pairing/Gateway, administrators/relay, resources/ACL, Management Fabric, watchdog/recovery, backup/restore/update и security audit. Кнопка **Очистить окно** очищает только DOM браузера и никогда не удаляет journald/audit. Вкладка **Диагностика** собирает ZIP только в памяти с manifest и SHA-256: sanitized config summary, SQLite schema/integrity/counts, root operations snapshot, последние очищенные logs и fabric watchdog telemetry. Private keys, PSK, raw endpoints WireGuard, passwords, tokens, session cookies и portable backup payload не включаются; недоступная секция записывается в manifest и делает `complete=false`, но не заставляет WebUI запускать host command.

#### Подписанное обновление VPS Hub

Вкладка **Обновление VPS Hub** принимает только versioned signed VPS `.tar.gz`. Upload выполняет непривилегированный Agent в закрытый `update-staging`, проверяет strict archive layout, Ed25519 signature, полный manifest/hash, OS/arch/profile, более новую SemVer и совместимость schema. Если hash полного `packaging/vps/*` host contract отличается, pointer-update возвращает `UPDATE_REQUIRES_INSTALLER` до изменения хоста: обычное обновление не заменяет systemd/nft/sysctl/WireGuard installation contract.

После password re-authentication и точной фразы `ОБНОВИТЬ VPS HUB` WebUI создаёт только mode-`0600` trigger в Agent state. Fixed `.path` запускает root updater без HTTP-пути, unit name или command arguments. До создания live-marker root-команда атомарно получает общий VPS lifecycle lock `/run/lock/gateway-vpn-vps-install.lock`, поэтому update/finalize не пересекаются с install/recovery/uninstall; отдельный update lock сериализует только журналы updater. Root повторно проверяет staging и current signed tree, закрепляет старый `recovery`, устанавливает candidate в immutable release directory, quiesce-ит только owned control-plane units, создаёт SQLite Online Backup, мигрирует/проверяет копию и атомарно переключает DB с `current`.

Candidate обязан три последовательных раза пройти version/state и owned-unit health. После этого WebUI показывает `STABILIZING`: `current` уже новый, но `recovery` остаётся старым 24 часа. Fixed finalize timer повторяет health check и только после deadline переводит `recovery` на candidate. SIGKILL, service failure либо boot с незавершённым journal запускает independent recovery из старого pointer; потерянный `active.json` восстанавливается по второй transaction-local journal copy. Marker `/run/gateway-vpn-vps-update-live` подавляет boot recovery только пока реально работает apply/finalize и исчезает после process death/reboot.

Состояния `PREPARED…STABILIZING/FINALIZED/ROLLED_BACK/ROLLBACK_FAILED`, версии, timestamps и безопасный error code доступны в WebUI. Привилегированные paths, DB/snapshot hashes и systemd stderr не публикуются. При `ROLLED_BACK` старая release+DB пара снова активна; `ROLLBACK_FAILED` требует не удалять transaction directory и сначала собрать diagnostic bundle/журнал. Незавершённый либо повреждённый journal блокирует reinstall/uninstall до recovery; оставшийся после сбоя terminal `FINALIZED`/`ROLLED_BACK` journal является безопасной audit-записью и не блокирует lifecycle навсегда. Uninstaller удерживает тот же общий lock, останавливает Agent и повторяет semantic transaction check до удаления первого owned файла. Updater не меняет APT, AmneziaVPN, Docker, UFW, foreign WireGuard/routes/firewall и не вызывает reboot VPS.

Администратор может использовать `EXTERNAL`, при котором VPS получает только public key и отдельный private `/32`, либо `MANAGED`, при котором отдельный private key существует в закрытом state только до однократной re-authenticated выдачи готового `.conf`. Повторное скачивание запрещено; rotation создаёт replacement peer и не отзывает прежний автоматически. QR остаётся незаявленным до отдельной реализации. Ресурс имеет immutable `Gateway peer × resource_id`, typed kind/access profile, local destination и уникальный alias. `LOCAL_SUBNET` требует отдельного acknowledgement, а TCP/UDP ACL запрещает port 0/wildcard; ICMP не имеет port fields. Удаление администратора одной transaction удаляет все его ACL, revoke Gateway выключает его публикации. UI всегда показывает `desired/applied generation`; до следующего privileged этапа сервер честно возвращает `host_apply_available=false`, `AWAITING_HOST_APPLY`/`PENDING`, а не ложный working handshake.

Endpoint завершения pairing принимает только bounded invitation ID/token, immutable `site_id`, Gateway public key и optional HTTPS origin; пароль VPS/Gateway и private key через него не передаются. Он имеет invitation-local attempt/expiry budget и не открывается в public firewall текущего installation profile: TCP/9443 остаётся доступен только localhost и admin peer. Отдельный pre-pairing listener/transport будет включён лишь вместе с root renderer и явным firewall contract.

На VPS с AmneziaVPN или другим VPN preflight сначала снимет bounded inventory interfaces/addresses/routes/rules/fwmarks/listeners/nftables/iptables/UFW/Docker bridges и выберет только свободные Gateway VPN values. Owned firewall не имеет blanket drop для unowned traffic, не вызывает `flush ruleset` и не disable/reload foreign services. Watchdog работает только с `gateway-vpn-vps*`, `gvm<N>`/`gva<N>`, owned protocol-186 routes и `inet gateway_vpn_vps`. Перед production acceptance обязательны install → pairing → watchdog recovery → signed update → uninstall с побайтным/семантическим сравнением foreign Amnezia/Docker/UFW state и реальной проверкой его connectivity.

### Одна команда для Gateway и VPS

Первый `gateway-vpn-deploy` запускается с отдельного административного Linux/amd64 компьютера. Нужны `/usr/bin/ssh`, HTTPS downloader, `sha256sum`, два заранее проверенных SSH host keys в одном absolute `known_hosts`, passwordless `sudo -n` на обеих machines и отдельные SSH destinations. Launcher запускает OpenSSH с `-F /dev/null`, `BatchMode=yes`, `StrictHostKeyChecking=yes`, запрещёнными password/keyboard-interactive/TTY и bounded output; произвольные SSH options, ProxyCommand и shell fragments из пользовательских полей не принимаются. Первый pinned SSH check создаёт отдельные ControlMaster connections в новом private `0700` temporary directory. Все последующие команды используют те же established TCP sessions после включения fail-closed firewall; TCP/22 ради installer не открывается. В конце launcher посылает обоим masters `-O exit`, проверяет исчезновение control sockets и удаляет temporary directory.

Windows 10/11 x64 launcher выпускается как один подписанный channel manifest-ом portable `gateway-vpn-deploy.exe` без установки. Он использует только точный системный `C:\Windows\System32\OpenSSH\ssh.exe`, проверяет обязательные client options до сети, требует pinned `known_hosts` и явно выбранные SSH key files для обеих машин; password/private key не сохраняются и не попадают в report. Так как официальный Win32-OpenSSH не поддерживает Client `ControlMaster`, launcher держит по одному `ssh.exe`/TCP на Gateway и VPS и передаёт последовательные фазы через bounded framed stdin/stdout protocol к фиксированному `/usr/bin/bash --norc`; новые TCP connections после firewall apply не создаются. Clean Windows VM должна пройти тот же signed-channel, dry-run, READY/INSTALLED_NOT_READY и interruption diagnostics contract до объявления конкретного release Windows-supported.

Signed release дополнительно содержит `install-deploy-windows-<version>.command.txt`. Его содержимое копируется в уже открытый PowerShell — файл `.ps1` запускать и менять ExecutionPolicy не требуется. Команда выполняется в отдельном PowerShell scope, создаёт случайный temporary directory, через HTTPS загружает exact Windows EXE, raw manifest, detached signature и public signing key, сверяет опубликованные SHA-256 EXE и manifest **до запуска**, затем открывает русскоязычный `--interactive` wizard и гарантированно удаляет temporary files. После успеха или ошибки исходное окно не закрывается: команда показывает результат, сохраняет точный launcher code в `$LASTEXITCODE`, восстанавливает изменённую на время загрузки TLS-настройку и возвращает обычный prompt для диагностики. Перед использованием администратор независимо сверяет signer fingerprint и SSH host-key fingerprints с доверенным источником.

Мастер запрашивает только:

- `USER@HOST` и SSH port Gateway/VPS;
- absolute pinned `known_hosts` и явный private-key **file path** для каждой машины;
- удалённый Gateway Ethernet interface, transit CIDR, DHCP policy и VPS `HOST:51821`;
- local path для создаваемого administrator WireGuard config либо заранее переданный public key;
- dependency и Gateway-through-VPS SSH policies.

Содержимое SSH/WireGuard private keys и пароли не читаются мастером как ответы, не помещаются в argv/report и не сохраняются в wizard state. После сводки требуется точный ввод `INSTALL`. Code `0` означает только `READY`, code `3` — безопасный `INSTALLED_NOT_READY`, остальные коды означают остановку с redacted phase/diagnostic codes.

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
  --trusted-update-key /secure/primary/update-signing.pub \
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
3. update recovery, условный restore recovery и `gateway-vpn-network-recovery.service` последовательно завершают или откатывают незавершённые root-транзакции до DHCP/API;
4. `gateway-vpn-watchdog.service` создаёт общий runtime heartbeat-каталог и переходит в safe-default policy; во время install/recovery он только наблюдает и не выполняет recovery actions;
5. `gateway-vpn.service` открывает SQLite, применяет migrations и проверяет integrity; systemd-networkd сохраняет transit LAN и выдаёт Huawei HiLink только DHCP lease без routes/DNS/NTP;
6. при отсутствии users создаётся `admin` и одноразовый пароль в `/var/lib/gateway-vpn/secrets/bootstrap-admin-password` с mode `0600`;
7. self-signed TLS certificate создаётся в `/var/lib/gateway-vpn/tls/`, fingerprint пишется в journald;
8. HTTPS API начинает слушать LAN address; WireGuard bind подключается после появления адреса;
9. root broker активируется только через `/run/gateway-vpn/network-broker.sock` с owner/group `gateway-vpn` и mode `0660`; dedicated-группа нужна root-watchdog в его ограниченном systemd sandbox, а `SO_PEERCRED` до разбора HTTP дополнительно допускает только UID `gateway-vpn` либо root;
10. Mihomo остаётся condition-inactive до проверенной LKG; dnsmasq запускается только для установки с явно включённым DHCP.

```bash
sudo cat /var/lib/gateway-vpn/secrets/bootstrap-admin-password
sudo journalctl -u gateway-vpn.service -u gateway-vpn-firewall.service
networkctl status
sudo /opt/gateway-vpn/current/bin/gateway-vpnctl status
```

Пароль необходимо сменить при первом входе. Не передавайте его в issue, diagnostic bundle или журнал разработки.

## Первый аппаратный acceptance

Этот gate начинается только с versioned immutable GitHub Release, production/hardware-test signing identity и generated exact command. Локальный disposable acceptance artifact нельзя переносить на физический Gateway как production release. До начала зафиксируйте tag, source commit, signer fingerprint, SHA-256 Gateway/VPS/bootstrap/deploy и фактические модели Ubuntu, KeeneticOS и HiLink firmware.

Проверка разделена на два уровня:

- **H1 — первая установка:** физический Ubuntu 24.04 Gateway, отдельная LAN NIC в WAN Keenetic, один HiLink и реальный VPS. H1 доказывает clean install, один рабочий path, fail-closed, management WireGuard и unplug/replug единственного модема;
- **H2 — полный hardware/production gate:** тот же стенд и минимум два HiLink с разными management subnets, желательно разных операторов. H2 дополнительно доказывает modem-first failover/failback, раздельные policy tables, reverse USB order и management-uplink switch. Поддержка `1..N` не означает, что для обычной работы обязательно иметь два модема, но Definition of Done multi-modem функции без H2 не закрывается.

### 1. Топология и безопасное окно

Физическая схема H1/H2:

```text
домашний test client → LAN Keenetic
WAN Keenetic          → отдельная LAN NIC Gateway
USB Gateway           → HiLink 1 [→ HiLink 2 для H2]
Gateway               → WireGuard через выбранный HiLink → VPS
```

На первом прогоне не переводите основной домашний трафик на Gateway. Используйте отдельный test client/SSID/VLAN и окно обслуживания. HiLink interfaces нельзя добавлять в bridge с transit LAN. На WAN Keenetic отключаются global IPv6 prefix/default route; точные пункты меню и версия KeeneticOS записываются в локальное evidence.

Создайте root-only каталог доказательств. Он может содержать MAC, USB serial, public IP, DNS names и packet payload, поэтому не прикладывается целиком к issue или `PROJECT_STATUS.md`:

```bash
sudo install -d -m 0700 /root/gateway-vpn-acceptance
sudo sh -c 'umask 077; date -u +%FT%TZ > /root/gateway-vpn-acceptance/started-at.txt'
```

До установки локально сохраните `uname -a`, `/etc/os-release`, `timedatectl`, `ip -json link/address/route`, `networkctl list`, `lsusb`, выбранную LAN NIC и фактические HiLink subnets. USB serial и полные MAC не переносятся в публичный журнал; в `PROJECT_STATUS.md` используются salted identity/fingerprint и обезличенные interface labels.

### 2. Clean install и exact identity

Запустите только exact generated GitHub command. Его bootstrap SHA-256 должен совпадать с опубликованным channel manifest. Ожидаемый первый результат без настроенных subscriptions — `INSTALLED_NOT_READY`, а не ложный `READY`.

Сразу после установки:

```bash
sudo systemctl is-system-running
sudo systemctl --failed --no-legend --plain
sudo readlink /opt/gateway-vpn/current
sudo readlink /opt/gateway-vpn/recovery
release=$(sudo readlink -f /opt/gateway-vpn/current)
sudo "$release/bin/gateway-vpn" --version
sudo "$release/bin/gateway-vpnctl" release-verify \
  --release-dir "$release" \
  --public-key /etc/gateway-vpn/update-signing.pub \
  --current-version 0.0.0 --current-schema 1 --json
sudo "$release/bin/gateway-vpnctl" status
sudo nft list table inet gateway_vpn
ip -json -4 rule show
ip -json -4 route show table all
```

Verifier намеренно требует canonical real release directory; передавать ему symlink `/opt/gateway-vpn/current` нельзя. До qualification ожидаются `PATH_BLOCKED`, пустой TUN gate, отсутствие modem default routes в `main` и пустой `systemctl --failed`. WebUI должен открываться с test client за Keenetic по transit address, но не через HiLink management address.

После первого входа смените bootstrap password, создайте diagnostic bundle и сохраните его SHA-256 локально. Не копируйте password, session cookie, subscription URL, WireGuard private key или raw diagnostic ZIP в журнал разработки.

### 3. Модемы, подписки и path matrix

Для каждого физического модема отдельно:

1. принять найденный modem в WebUI, задать номер, имя, enabled и priority;
2. сверить interface/driver/DHCP lease/management subnet и убедиться, что другой modem не использует ту же subnet;
3. добавить subscriptions, targets и matchers; полные URL/tokens остаются только в secrets storage;
4. подтвердить candidate-pool правило: при наличии `обход`/`lte`/whitelist marker проверяются только matched nodes, без markers — все enabled nodes подписки;
5. выполнить qualification точного `modem × subscription × node` по всем required targets;
6. сравнить одну и ту же cell во вкладках **Модемы**, **Подписки** и **Матрица путей**;
7. активировать только свежий `BYPASS_QUALIFIED` tuple и записать route/policy generations, node fingerprint и время.

H1 выполняется с одной cell и проверяет disconnect/reconnect без direct fallback. H2 заполняет полную матрицу минимум `2 modems × 1 subscription`, включая случай без name-marker fallback, и подтверждает independent status через каждого оператора.

### 4. Packet capture и leak gate

`tcpdump` является отдельным инструментом стенда и намеренно не устанавливается Gateway installer-ом. Если он нужен, установку пакета выполняет администратор до gate. PCAP хранится только в `/root/gateway-vpn-acceptance` и считается чувствительным.

В трёх терминалах запустите bounded capture на фактических интерфейсах:

```bash
read -r -p 'LAN interface: ' LAN_IF
read -r -p 'HiLink interface: ' HILINK_IF
ip link show dev "$LAN_IF"
ip link show dev "$HILINK_IF"
sudo timeout --signal=INT 180 tcpdump -ni "$LAN_IF" -s 0 \
  -w /root/gateway-vpn-acceptance/lan.pcap
sudo timeout --signal=INT 180 tcpdump -ni "$HILINK_IF" -s 0 \
  -w /root/gateway-vpn-acceptance/hilink-1.pcap
sudo timeout --signal=INT 180 tcpdump -ni gateway-vpn-tun -s 0 \
  -w /root/gateway-vpn-acceptance/tun.pcap
```

Для H2 одновременно пишется отдельный capture второго HiLink. С test client выполните TCP/HTTPS, UDP/QUIC, обычный DNS lookup, known-size download и `curl -6 --max-time 5 https://example.com`. Capture и nft counters должны доказать:

- пользовательский IPv4 появляется LAN↔TUN и не идёт LAN→HiLink напрямую;
- выбранный proxy socket выходит только через HiLink конкретной cell/mark;
- client DNS не уходит прямым UDP/TCP 53 в обход DNS hijack;
- IPv6 global route/connection отсутствует;
- `user_*` изменяются known-size transfer, `service_*` считаются отдельно;
- отсутствие direct traffic сохраняется после reload, guard recovery и reboot.

### Bounded recovery физического HiLink

Во вкладке **Модемы → Самовосстановление модемов** отдельно показаны physical failure, recovery runtime, last outcome, cooldown, durable USB budget и последние попытки. Кнопка **Проверить и восстановить** сначала повторяет discovery/carrier/DHCP observation. При исправном carrier/lease она возвращает `NO_PHYSICAL_FAILURE` и не пытается перезапустить модем из-за `WHITELIST_ONLY`, недоступных global targets, VPN nodes, subscription endpoint или routing/subnet ошибки.

На текущем непроверенном hardware profile автоматически исполняется только фиксированный networkd DHCP renew. HiLink mobile reconnect, driver rebind, USBDEVFS reset и hub port power-cycle должны отображаться как `HARDWARE_ACTION_NOT_AVAILABLE`; это ожидаемая защита, а не повод запускать команды вручную. Разрешать эти ступени можно только после H1/H2 проверки точного Huawei E3372h/driver identity, disconnect во время действия, cooldown/budget и отсутствия воздействия на соседний USB modem. Изменение WebUI policy не обнуляет уже использованный budget; процессный restart закрывает незавершённую попытку кодом `PROCESS_RESTARTED`.

Для диагностики используйте тематический журнал `modems`/`watchdog-recovery` и API/WebUI history. В журнале допустимы только uplink display identity, action, generation и redacted outcome; serial, identity hash, sysfs path и HiLink credentials не экспортируются.

Любой подтверждённый direct IPv4/DNS/IPv6 packet является немедленным `FAIL`: оставьте `PATH_BLOCKED`, сохраните diagnostics/pcap и не подключайте основной домашний трафик.

### 5. Failure matrix H1/H2

Для каждой операции фиксируйте UTC start/detection/recovery timestamps, active tuple до/после, reason code, `systemctl --failed`, nft generation и relevant packet-capture interval.

Обязательные H1 проверки:

- `SIGKILL` Mihomo: новый пользовательский трафик прекращается, direct fallback отсутствует;
- unplug единственного HiLink: modem остаётся в UI offline, `PATH_BLOCKED`; после replug возвращается тот же identity/number/priority и выполняется новая qualification;
- reboot Gateway: boot начинает с `PATH_BLOCKED`, SQLite integrity проходит, рабочий path возвращается только после fresh evidence;
- остановленный Mihomo/нерабочая subscription не лишают доступа к WebUI через `wg-mgmt`;
- `curl -6` и DNS sentinel не дают leak;
- corrupt import/config/update отклоняются без потери LKG.

Дополнительные H2 проверки:

- unplug active modem переключает `node → subscription на текущем modem → следующий modem` не позднее 45 секунд после подтверждённого failure;
- WireGuard endpoint route и fresh handshake переходят на резервный modem;
- preferred modem после возврата не активируется до stable requalification/cooldown;
- десять reboot и replug в обратном USB-порядке сохраняют оба identities/priorities и раздельные route tables;
- общий outage required target не создаёт node/subscription/modem switching loop;
- subnet conflict одного модема помещает только его в quarantine и не повреждает routes другого.

`nft flush ruleset` выполняется только в изолированном окне H2. Guard обязан опустить transit link, восстановить owned table строго в `PATH_BLOCKED`, проверить schema/counters и только затем вернуть link; чужие nft tables он не восстанавливает.

### 6. VPS/WireGuard, traffic и длительные gates

На реальном VPS provider firewall разрешает UDP/51821. Для каждого ready modem получите свежий handshake, затем при остановленном Mihomo откройте `https://10.80.0.2:8443` с admin peer. Сохраните локально:

```bash
sudo wg show wg-mgmt latest-handshakes transfer endpoints
ip route get 10.80.0.2
sudo nft list table inet gateway_vpn_vps
```

На Gateway сверяются modem-specific endpoint route/mark и WebUI statuses `REACHABLE/STALE/BLOCKED`. Private keys и raw public keys в `PROJECT_STATUS.md` не записываются; допустим только SHA-256 fingerprint public identity.

Traffic spike выполняется known-size transfer до/после Mihomo reload и reboot. Запишите checkpoint interval, user/service delta, Mihomo cross-check delta и процент расхождения; per-subscription attribution не добавляется. После функционального H1/H2 запускаются несокращаемые 24h developer и 72h hardware release profiles из раздела **Endurance-наблюдение**.

### 7. Фиксация результата

Для каждой попытки в `PROJECT_STATUS.md` добавляется отдельная сессия с таблицей:

| Gate | Результат | Обезличенное доказательство | Ограничение/следующий шаг |
|---|---|---|---|
| Release identity/install | `PASS/FAIL/NOT_RUN` | version, commit, signer/hash fingerprints |  |
| H1 one-modem path/fail-closed | `PASS/FAIL/NOT_RUN` | modem label, timestamps, event/reason IDs |  |
| H2 multi-modem failover | `PASS/FAIL/NOT_RUN` | modem labels, failover/failback seconds |  |
| IPv4/DNS/IPv6 leak | `PASS/FAIL/NOT_RUN` | local PCAP SHA-256 и анализ без публикации PCAP |  |
| VPS/WireGuard | `PASS/FAIL/NOT_RUN` | endpoint label, handshake age, public-key fingerprints |  |
| Traffic accounting | `PASS/FAIL/NOT_RUN` | known bytes, four deltas, mismatch percent |  |
| Reboot/replug/update/restore | `PASS/FAIL/NOT_RUN` | counts, terminal states, failed-unit count |  |
| 24h/72h endurance | `PASS/FAIL/NOT_RUN` | report SHA-256, sample count, restart/gap totals |  |

`PASS` ставится только после просмотра исходного локального evidence. Отсутствие ошибки в UI, unit test, Docker или устное наблюдение не заменяет packet capture, handshake, reboot/replug и endurance доказательства соответствующего масштаба.

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

## Safe apply сети и topology profile

Изменение transit LAN выполняется только во вкладке **Сеть → Топология и интерфейсы**:

1. WebUI собирает один exact candidate и выполняет **Проверить профиль без применения**; любое последующее изменение формы инвалидирует Preview;
2. control plane проверяет protected generation, комбинацию ролей и конфликт нового CIDR с WireGuard и сохранёнными uplink networks;
3. root broker повторно сверяет candidate с фактическим inventory, current roles, fresh management path и обязательными внешними подтверждениями;
4. старые config, bridge/member networkd, dnsmasq, `wg-ingress`, роли, routing и runtime firewall сохраняются в root-owned `/var/lib/gateway-vpn-privileged/network-transactions/<apply-id>/`;
5. `gateway-vpn-network-rollback@<apply-id>.timer` вооружается на 60 секунд до изменения адреса;
6. старый management path сохраняется, candidate применяется и reconfigure-ится только для точного affected-interface set; API возвращает одноразовую ссылку на `new_url`, а token находится только во fragment `#network-confirm=...`;
7. на новом адресе нужно снова войти и нажать **Подтвердить сетевые настройки**; подтверждение через старый destination отклоняется. Альтернатива — свежий `wg-mgmt`, если candidate требует WireGuard-only confirmation;
8. без подтверждения отдельный root helper восстанавливает весь persistent/runtime LKG snapshot без зависимости от живого процесса `gateway-vpn`; active firewall открывается только после полного успешного возврата network/routing/ingress/services.

Диагностика незавершённой операции:

```bash
systemctl list-timers 'gateway-vpn-network-rollback@*'
sudo journalctl -u gateway-vpn-network-recovery.service -u gateway-vpn-network-broker.service
sudo find /var/lib/gateway-vpn-privileged/network-transactions -maxdepth 2 -type f -printf '%m %u:%g %p\n'
```

Не запускайте instance rollback timer вручную с придуманным ID. Production-ready статус safe apply требует отдельного netns-теста timeout/reboot и затем проверки на Ubuntu 24.04; Windows unit tests этого не доказывают.

Schema 30 применяет тем же durable механизмом не только CIDR, но и переход между `ETHERNET_HILINK`, `ETHERNET_ETHERNET`, `ONE_ARM_WIREGUARD` и `MIXED`. Candidate включает roles/networkd/DHCP/DNS/firewall/policy routing/`wg-ingress`/API bind одной generation. Обычные Ethernet-LAN profiles используют owned bridge `gateway-vpn-lan`; one-arm принимает plaintext user traffic только через `wg-ingress`, а общая physical карта остаётся Ethernet uplink/явным management endpoint. Если удаляется последний локальный management path без свежего `wg-mgmt` либо нового проверяемого destination, Apply блокируется. Старый management address/path остаётся до подтверждения; reboot/process loss/timeout возвращают весь LKG profile, а не только IP.

Full-profile contract реализован в текущем source tree, но его production-ready статус отмечается только в `PROJECT_STATUS.md` после Linux netns/systemd gate; физические кабели, настройки Keenetic и hardware-проверка остаются внешними действиями.

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

WebUI делит этот же поток на десять вкладок: **Все**, **Модемы**, **Подписки и VPN-серверы**, **Доступ и переключения**, **VPN / Mihomo**, **Сеть**, **WireGuard / VPS**, **Watchdog**, **Обновления / backup**, **Безопасность / audit**. Категория является server-side allowlisted filter, а не отдельным источником; одна запись сохраняет тот же cursor/timestamp/correlation identity при просмотре через общий и тематический фильтр.

Для удобного скачивания exporter создаёт только очищенные текстовые копии в `/var/log/gateway-vpn/current/<category>.log`, а при смене суток переносит прежние bounded files в `/var/log/gateway-vpn/archive/`. Исходным журналом остаётся journald. По умолчанию включены все десять категорий, максимум одного файла 10 MiB, общий budget 256 MiB, 14 archive files и 14 дней; WebUI показывает desired/applied generation и ошибку convergence. Запись выполняется atomic rename, повторным redaction pass и отклоняет symlink/non-regular/неверно принадлежащий tree.

Installer создаёт группу `gateway-vpn-log-readers`, добавляет только явно выбранный обычный Ubuntu account и устанавливает каталоги `root:gateway-vpn-log-readers 2750`, файлы `0640`. После первой установки войдите заново, чтобы новая supplementary group применилась. Стандартный SFTP использует тот же TCP/22 и account, отдельного daemon/password нет:

```bash
id -nG <ubuntu-user>
sftp <ubuntu-user>@<LAN-IP-Gateway>
sftp> ls /var/log/gateway-vpn/current
sftp> get /var/log/gateway-vpn/current/modems.log
sudo find /var/log/gateway-vpn -maxdepth 2 -printf '%u:%g %m %p\n'
sudo journalctl --namespace=gateway-vpn --since=-15min
```

Если SSH отключён, WebUI-журнал и exporter продолжают работать, но SFTP недоступен. Watchdog component `logging_pipeline` отдельно проверяет journald, generation, freshness, размеры и permissions exports; он не заменяет authoritative journal из экспортированных файлов.

Audit входов, policy/settings mutations, manual activation, update/restore и destructive actions не отключается и имеет жёсткий minimum `info`, даже если global level равен `warning` или `error`. Pre-logger handler удаляет subscription URL/token, passwords, private/API keys, proxy credentials, modem serial/identity hash, response body, полный subscription payload и несаницированный Mihomo config также из вложенных map/struct/error. Journal reader и diagnostic builder выполняют независимый второй redaction pass и не полагаются на текущий log level.

## Учёт трафика

Вкладка **Трафик** разделяет два не пересекающихся класса:

- `user_upload` / `user_download` — только пользовательский IPv4-трафик между transit LAN и подтверждённым Mihomo TUN. Это authoritative общий VPN total без приблизительной разбивки по подпискам или proxy nodes;
- `service_upload` / `service_download` — прямой служебный трафик самого Gateway через HiLink: DHCP модема, HiLink management, WireGuard endpoint, bootstrap DNS/HTTPS и разрешённые Mihomo DNS/proxy endpoints. Он показывается отдельно и никогда не прибавляется к пользовательскому total.

Named counters принадлежат только таблице `inet gateway_vpn`. Control plane не получает `CAP_NET_ADMIN`: каждые 30 секунд он вызывает parameter-free UID-bound root broker, который читает только четыре фиксированных имени counters, `boot_id` и handle owned table. Пара `boot_id + table handle` образует epoch. После reboot, firewall recovery или замены ruleset первый checkpoint новой epoch начинает новую delta-базу и не вычитает старое значение. Потеря при аварийном завершении ограничена последним checkpoint interval; штатное завершение делает отдельный bounded финальный checkpoint.

`Mihomo /traffic` читается как authenticated WebSocket и используется только для текущей общей скорости, process totals и cross-check. Недоступность Mihomo API не останавливает authoritative nftables checkpoints: UI показывает API как недоступный, а user/service totals продолжают сохраняться. Active-session totals начинаются при старте текущего control process и также разделены на user/service. Daily rows сохраняются в SQLite, monthly endpoint агрегирует их без отдельной приблизительной атрибуции, CSV содержит оба класса и Mihomo cross-check columns.

Authenticated read-only endpoints:

```text
GET /api/v1/traffic/current
GET /api/v1/traffic/daily?from=YYYY-MM-DD&to=YYYY-MM-DD
GET /api/v1/traffic/monthly?from=YYYY-MM-DD&to=YYYY-MM-DD
GET /api/v1/traffic/export.csv?from=YYYY-MM-DD&to=YYYY-MM-DD
```

Диагностика источника без изменения counters:

```bash
sudo nft list counters table inet gateway_vpn
sudo nft --json list tables
sudo cat /proc/sys/kernel/random/boot_id
sudo journalctl --namespace=gateway-vpn -u gateway-vpn.service --since=-15min
```

Отсутствие любого из четырёх counters является нарушением firewall schema: guard/watchdog оставляют data path fail-closed и восстанавливают полный owned ruleset. Signed update и rollback сначала quiesce-ят data plane, затем одной systemd-транзакцией перезапускают `gateway-vpn-firewall.service` и `gateway-vpn-firewall-guard.service` из уже выбранного release. Update/recovery units используют `Wants/After`, а не `Requires` для этой пары, чтобы собственный restart не завершил transaction process сигналом `SIGTERM`.

До реального hardware traffic spike нельзя утверждать точное расхождение nftables и Mihomo, фактическую стоимость служебных probes или отсутствие packet-classification особенностей конкретного HiLink/оператора. Эти значения фиксируются на физическом Gateway; Docker/netns доказывают синтаксис, fail-closed, epoch/parser и kernel counters, но не заменяют packet capture на Huawei/Keenetic.

## Самоконтроль 24/7

Во вкладке **Система и безопасность → Самоконтроль 24/7** отдельно показываются локальное состояние процессов/SQLite/firewall, доступность глобального Интернета, active maintenance и durable restart/reboot budgets. Потеря модемов, операторов, подписок, targets, VPS или всего внешнего Интернета отображается как connectivity outage и сама по себе никогда не запускает restart либо reboot.

Safe-default policy проверяет фиксированный allowlist из 17 компонентов каждые 15 секунд: WebUI/API/control, SQLite, firewall guard/ruleset, broker/networkd, DNS/DHCP, optional SSH/SFTP, Mihomo/TUN, WireGuard management/ingress, policy routing, background workers, desired/observed convergence, verified backup/WAL, host resources и logging/export pipeline. Она требует три последовательные ошибки и два успеха, сначала вызывает idempotent reconcile, затем закрывает data path и только после этого может перезапустить фиксированный unit. По умолчанию разрешено не более пяти restart одного компонента за 15 минут с cooldown 30 секунд. Отключение automatic recovery не отключает read-only monitoring, systemd crash restart, fail-closed firewall guard и audit.

Во вкладке **Система и безопасность → Самоконтроль 24/7** для каждого fixed component выбирается только допустимый `Только наблюдать`, `Reconcile без restart` или `Reconcile и bounded restart`. WebUI не принимает имя unit, executable, interface, route или command. Отдельно настраиваются worker-stale, WireGuard-handshake, backup-age, SQLite-WAL, disk и memory thresholds. Resource pressure отображается, но не делает host reboot допустимым. Старый WireGuard handshake при корректных interface/address/peer/fwmark/routes классифицируется как внешний outage и подавляет локальные recovery/reboot действия.

Host reboot по умолчанию выключен. Его включение требует отдельного подтверждения в WebUI; даже после включения нужны непрерывный локальный critical failure не менее 15 минут, исчерпанная безопасная локальная recovery ladder, повторный `PATH_BLOCKED`, 60-секундный grace и свободный durable budget (по умолчанию один reboot за 24 часа). История записывается и fsync-ится до privileged action, не очищается restart-ом supervisor или изменением settings и блокирует reboot loop. Disk/memory/FD pressure, maintenance transaction и внешний outage не являются reboot-eligible причинами.

### Ручное управление питанием

Во вкладке **Система и безопасность → Питание** доступны отдельные от watchdog операции **Перезагрузить** и **Выключить**. Каждая требует текущий пароль, точную русскую фразу подтверждения и имеет отменяемый пятисекундный отсчёт до отправки. После передачи команды systemd WebUI показывает operation ID; разрыв HTTPS после этого является ожидаемым и не означает, что команда не принята. Install/update/restore, safe network apply, backup mutation и другая power operation блокируют ручное действие.

**Выключить и включить по таймеру** не включается только по наличию `/dev/rtc0` или `rtcwake`: firmware может не поддерживать wake-from-S5. Сначала оператор отдельно проверяет конкретный Gateway на тестовом интервале и только после успешного физического включения создаёт root-owned regular marker `/var/lib/gateway-vpn-privileged/rtc-wake-from-s5.verified` с mode `0600` и точным содержимым `RTC_WAKE_FROM_S5_VERIFIED_V1`. До этого WebUI показывает RTC как **обнаружен, но не проверен**, а кнопка заблокирована. RTC alarm отсчитывается от отправки команды, поэтому фактическое время в полностью выключенном состоянии короче на время корректного завершения Ubuntu. Реальный hardware acceptance этой функции выполняется только на физическом Gateway; Docker и VM не доказывают S5 wake.

Control и supervisor используют systemd watchdog heartbeats. Runtime status считается доступным только при свежих root status и control heartbeat с правильными owner/mode; старый файл после смерти процесса не отображается как healthy. `gateway-vpn.service` следует lifecycle supervisor, а его heartbeat-каталог сохраняется при restart обоих units, поэтому control не продолжает работу в отдельном устаревшем mount namespace.

Диагностика:

```bash
sudo systemctl status gateway-vpn-watchdog.service gateway-vpn.service
sudo systemctl show gateway-vpn-watchdog.service gateway-vpn.service -p ActiveState -p SubState -p NRestarts -p WatchdogUSec
sudo stat -c '%U:%G:%a %y %n' /run/gateway-vpn-watchdog/status.json /run/gateway-vpn-watchdog/control.json
sudo journalctl --namespace=gateway-vpn -u gateway-vpn-watchdog.service -u gateway-vpn.service
sudo nft list table inet gateway_vpn
sudo ip -N -json -4 route show 10.80.0.0/24
sudo wg show wg-mgmt fwmark
```

При настроенном management WireGuard первый route должен содержать `dst=10.80.0.0/24`, `dev=wg-mgmt`, numeric protocol `186`. Ubuntu 24.04 `ip -N -json` может кодировать protocol/table как JSON-строки; это штатная форма и текущий watchdog принимает её строго как decimal integer. Route mismatch является локальной ошибкой; отсутствие свежего handshake при совпавшем локальном contour — внешней.

Не удаляйте вручную `/var/lib/gateway-vpn-privileged/watchdog`: там находится root-only история budget. Перед плановым обслуживанием используйте штатные install/update/restore/network-apply units; supervisor распознаёт их как maintenance и не конкурирует с транзакцией.

## Диагностический архив

Во вкладке **Система и безопасность → Диагностический архив** authenticated администратор может создать ZIP кнопкой **Создать и скачать**. Операция требует CSRF, не принимает параметры или request body, ограничена тремя архивами за 10 минут на session и создаёт обязательное событие `DIAGNOSTIC_BUNDLE_CREATED`. Ответ содержит attachment filename, `Content-Length`, `X-Content-SHA256` и `X-Diagnostic-Complete`.

Архив создаётся только в памяти и не сохраняется на диске Gateway. `manifest.json` показывает schema, `complete`, section errors/warnings, размер и SHA-256 каждого payload-файла. Ошибка host/journal/отдельного read model не отменяет download: архив становится частичным, а manifest содержит стабильный error code без внутренних command/path details. Максимум — 24 MiB несжатых данных и 32 MiB ZIP; journal excerpt отдельно задаётся в Logging в диапазоне 64 KiB–16 MiB.

Архив не содержит private/API keys, session/CSRF tokens, subscription URL/payload/secret refs, proxy credentials/config, target expected body, modem identity/serial/MAC или реальный WireGuard endpoint host. В него входят только redacted config/state/inventory, owned protocol-186 routes/rules, owned `inet gateway_vpn` table, masked WireGuard counters, versions, bounded events/journal, SQLite integrity и fixed `database/retention.json`. Последний содержит только policy, counts/ranges таблиц, DB/WAL bytes и SQLite page/freelist totals — путь к БД не выдаётся. Перед отправкой все host/log/event values проходят дополнительную sanitization. Даже для поддержки не следует прикладывать архив публично без проверки локальной политикой организации.

## Endurance-наблюдение

Authenticated read-only `GET /api/v1/system/runtime-metrics` возвращает только bounded process counters: uptime, число goroutines, Go heap/stack/system bytes, allocations/frees/live objects и GC totals. На Linux дополнительно возвращаются RSS и число открытых file descriptors из `/proc/self`. Endpoint не возвращает argv, environment, filesystem paths, network endpoints, IDs, config или secrets; обычная session authentication обязательна. Отдельный per-session limit — 20 запросов в минуту (`429` + `Retry-After` при превышении).

После входа API-клиент может сохранять samples с интервалом 60 секунд, используя root-only cookie jar и установленный Gateway TLS certificate:

```bash
umask 077
curl --fail --silent --show-error \
  --cacert /var/lib/gateway-vpn/tls/server.crt \
  --cookie /root/gateway-vpn-endurance.cookies \
  https://192.168.200.1:8443/api/v1/system/runtime-metrics
```

Cookie jar создаётся штатным login API-клиентом и имеет mode `0600`; bearer token нельзя помещать в командную строку, журнал или итоговый CSV. Сессия живёт 12 часов, поэтому 24/72-часовой harness должен повторно аутентифицироваться до expiry, удерживая введённый пароль только в памяти процесса либо используя отдельный защищённый credential provider. Увеличивать lifetime production-сессии ради теста нельзя.

Reference harness находится в `test/endurance` и запускается с отдельного Linux admin host либо из изолированного Linux container. Он требует TLS 1.3 и явно указанный CA certificate, запрещает redirect/proxy, хранит cookie/CSRF только в памяти, обновляет сессию до expiry и отзывает её при завершении. Пароль читается только из absolute single-link файла текущего пользователя с mode `0600`; содержимое password нельзя передавать через argv/environment. Артефакты создаются в новом `0700` directory, а `samples.ndjson`, start/end ZIP, `run-state.json` и `report.json` имеют mode `0600` и fsync. `run-state.json` обновляет число samples после каждой минуты, поэтому interrupted run не выглядит завершённым.

Harness необходимо собирать из clean exact revision без `-buildvcs=false`; 24/72-часовой профиль откажется стартовать, если binary не содержит VCS revision либо был собран из modified worktree. Точно так же итоговый PASS запрещён для Gateway diagnostic identity `0.0.0-dev`/`commit=unknown` или если Gateway version/schema изменились во время run:

```bash
git status --porcelain
CGO_ENABLED=0 go build -trimpath -buildvcs=true \
  -o ./gateway-vpn-endurance ./test/endurance
sudo install -m 0755 ./gateway-vpn-endurance /root/gateway-vpn-endurance
rm -f ./gateway-vpn-endurance
sudo install -d -m 0700 /root/gateway-vpn-endurance-results
sudo install -m 0600 /dev/null /root/gateway-vpn-endurance.password
sudoedit /root/gateway-vpn-endurance.password
```

Сначала выполняется короткая проверка самого harness. Она может вернуть только `SMOKE_PASS` и никогда не засчитывается как endurance:

```bash
sudo /root/gateway-vpn-endurance \
  --profile smoke \
  --environment developer-linux \
  --smoke-duration 2m \
  --smoke-interval 10s \
  --endpoint https://192.168.200.1:8443 \
  --ca-cert /var/lib/gateway-vpn/tls/cert.pem \
  --username admin \
  --password-file /root/gateway-vpn-endurance.password \
  --output-parent /root/gateway-vpn-endurance-results
```

После успешного smoke запускается несокращаемый developer profile; duration/interval/warm-up/window в нём фиксированы как 24h/1m/30m/30m:

```bash
sudo /root/gateway-vpn-endurance \
  --profile developer \
  --environment developer-linux \
  --endpoint https://192.168.200.1:8443 \
  --ca-cert /var/lib/gateway-vpn/tls/cert.pem \
  --username admin \
  --password-file /root/gateway-vpn-endurance.password \
  --output-parent /root/gateway-vpn-endurance-results
```

Release profile фиксирован на 72 часа и дополнительно требует `--environment hardware-gateway --release-hardware-confirmation REAL_GATEWAY_MODEMS_KEENETIC_VPS`. Это явная operator attestation, а не автоматическое доказательство оборудования: release gate всё равно засчитывается только вместе с журналом реального Gateway, минимум одного HiLink, Keenetic, VPS handshake/packet capture и отсутствия direct/IPv6/DNS leak. Docker run с release flags не заменяет hardware gate.

Developer gate длится 24 часа, release gate — 72 часа. Warm-up первые 30 минут не участвует в оценке. Harness сохраняет минутные samples и 30-минутные медианы. Gate считается неуспешным, если после warm-up:

- goroutines или FD растут в шести последовательных окнах и не возвращаются к первой медиане + 5;
- RSS, heap allocation или live objects имеют положительный устойчивый slope, а медиана последнего часа превышает медиану первого часа более чем на 10% и минимум на 32 MiB для byte metrics;
- процесс, broker/firewall guard либо WebUI недоступны, появляется direct leak или SQLite/retention check не проходит.

`mallocs_total`, `frees_total`, `gc_cycles_total` и `gc_pause_total_nanoseconds` являются накопительными и сами по себе не означают leak. Перед warm-up и после последнего sample создаются diagnostic bundles; harness проверяет ZIP paths/modes/bounds, SHA-256 каждого manifest entry, `complete=true`, неизменность Gateway build/schema и оба SQLite integrity result. Финальный retention snapshot обязан не иметь строк старше 7/30 дней и 24 месяцев (для worker допускается 15-минутное окно), лишних `RETAINED/FAILED`, неизвестных states либо active non-LKG. Рост live SQLite pages более 10% и 32 MiB также завершает gate ошибкой. Docker developer endurance не заменяет 72-часовой release endurance на реальном Gateway с модемами, Keenetic и VPS.

## Резервное копирование и восстановление

Во вкладке **Система и безопасность → Резервные снимки и восстановление** доступны два разных вида копий:

- локальный SQLite snapshot содержит только БД и хранится на самом Gateway; он создаётся SQLite Online Backup API и проходит `quick_check`, полный `integrity_check`, `foreign_key_check` и SHA-256;
- переносимый `.gvpn` дополнительно содержит strict bootstrap config, Mihomo API secret, TLS cert/key, subscription secrets/payloads, Mihomo generations/state, `wg-ingress` и Management Fabric private keys только внутри chunked AES-256-GCM. Ключ выводится Argon2id из passphrase 12–256 UTF-8 байт; passphrase не сохраняется и не восстанавливается.

Перед созданием `.gvpn` WebUI требует текущий пароль администратора и две совпадающие passphrase. Обычный `gateway-vpn` process не имеет доступа к root-owned `/var/lib/gateway-vpn/secrets/management`: он передаёт passphrase только по UID-restricted Unix socket. Root broker независимо создаёт verified transient SQLite snapshot, читает фиксированные config/state trees и потоково шифрует artifact в `/var/lib/gateway-vpn-privileged/backup-exports` (`root:root 0700`). Через границу возвращаются только path-free metadata и уже зашифрованные bytes; root path, plaintext ZIP и private keys не передаются WebUI. Control plane повторно проверяет size/SHA-256 и сохраняет только краткоживущий encrypted `.gvpn` до окончания HTTP download. Passphrase отсутствует в argv, environment, SQLite, systemd trigger и journal.

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

Boot recovery отделён от runtime destructive apply. Только бесконфликтный `gateway-vpn-database-restore-boot.service` включён в `multi-user.target`; при наличии `pending-restore.json` он после update recovery и boot firewall выполняет один recovery pass (`RemainAfterExit=yes`) до network recovery, broker socket и control plane. Перед чтением journal удаляются только строго распознанные root-owned `0600` atomic temp-файлы `.recovery-record-<digits>`; неожиданный тип, mode, owner или имя блокирует recovery. Обычный `STAGED` является успешным no-op и никогда не применяется из-за перезагрузки. Только `APPLY_REQUESTED` разрешает начать подтверждённую транзакцию либо восстановить journal с тем же nonce. Успешный rollback сначала фиксируется journal-state `ROLLED_BACK`, затем отзывает authorization и возвращает операцию в `STAGED`; повторный boot поэтому может только идемпотентно завершить rollback, но не повторить destructive apply. Новый WebUI Apply получает новый nonce и может безопасно удалить stale `ROLLED_BACK` journal предыдущей попытки. Runtime `gateway-vpn-database-restore.service` не включается ни в один boot target и запускается исключительно fixed-командой root broker после подтверждения в WebUI.

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

### Backup и восстановление VPS Hub

Во вкладке VPS Hub **Backup/обновление/восстановление** кнопка **Скачать backup** создаёт encrypted `.gvpn-vps`. Файл содержит только состояние VPS-роли: Agent DB/config/TLS, VPS-owned WireGuard/relay keys, ещё не скачанные managed administrator keys, public peers, prefix allocations, resources/ACL и update identity. Уже выданные/отозванные и orphan administrator keys, Gateway private keys, Gateway application DB, Web-сессии, login attempts, logs/diagnostics и временные либо уже использованные pairing invitations исключены. Gateway `.gvpn` и VPS `.gvpn-vps` имеют разные authenticated role и не принимаются чужим restore endpoint.

WebUI требует свежую password re-authentication и введённую пользователем passphrase, показывает version/schema/VPS identity, состав и конфликты до Apply и никогда не сохраняет passphrase/plaintext archive. Доступны два явных режима:

- **Восстановить тот же VPS** — сохраняет `vps_id`, keys, links и allocations только после подтверждения замены; старый экземпляр должен быть выключен/отозван, duplicate active identity остаётся quarantined;
- **Импортировать настройки как новый VPS** — переносит разрешённые policy/settings, но создаёт новый `vps_id`, WireGuard/update/TLS identities, очищает source peers/prefixes/ACL/pairing и физически удаляет source administrator secret tree, атомарно заменяет `wg-mgmt.conf` конфигурацией без старых peers и требует заново pair Gateway/admin. После успешной root transaction `wg-quick@wg-mgmt` перезапускается с новой identity.

Перед Apply создаётся verified local pre-restore snapshot. Root transaction использует fixed destinations, durable journal и reboot recovery; при SIGKILL/power loss возвращает прежний exact VPS state. После commit fabric остаётся default-deny до свежих peer handshakes, route/ACL reconciliation и acknowledgement. Restore VPS не меняет AmneziaVPN/Docker/UFW/foreign VPN state; conflict до mutation показывается в preview и блокирует Apply.

## Подписанное обновление и atomic rollback

Во вкладке **Система и безопасность → Подписанное обновление** принимается только versioned `.tar.gz`, подписанный доверенным Ed25519-ключом `/etc/gateway-vpn/update-signing.pub`. Источником может быть официальный signed GitHub Release выбранного канала `Stable`/`Testing`, ручная загрузка файла либо advanced exact immutable HTTPS URL. `main`, branch/commit URL, `latest`, `git pull`, URL credentials и private/link-local/loopback destination не поддерживаются. Redirect, DNS resolution, content type, download size, signed channel hash и конечный artifact повторно проверяются; URL/query не попадают в audit.

Карточка **Обновление Mihomo** является отдельным понятным представлением того же безопасного механизма. Кнопка **Проверить обновление Mihomo** скачивает только небольшой подписанный maintenance manifest и показывает установленную Mihomo, candidate Mihomo, сопровождающую Gateway version, важность и описание. **Загрузить и проверить Mihomo** скачивает полный Gateway archive; установленная система ещё не меняется. Обычное обновление всего Gateway точно так же уже содержит нужную для него Mihomo — никаких последующих загрузок core из отдельной папки не требуется.

Maintenance manifest принимается только при точном включении текущей Gateway version в compatibility list, более новой Mihomo, совпадении Linux/amd64, host contract и Gateway/Mihomo API contracts. После скачивания archive обычный release verifier повторно сверяет signature, tree, commit, обе версии и contracts. Несовпадение удаляется из staging. Установка, snapshot, 24-часовая стабилизация и rollback полностью общие с Gateway update; второй updater отсутствует. Ручное Mihomo staging automatic worker не применяет.

До изменения live-системы staging ограничивает archive/entry/path/depth/size, запрещает symlink, hardlink, device, sparse и concatenated/trailing gzip data, проверяет signature, signer SHA-256, полный file manifest, SHA-256 каждого файла, строгий SemVer, Git commit/build date, OS/arch, DB/config и Gateway/Mihomo API contracts. Дополнительно candidate `host_contract_sha256`, вычисленный по всем packaged systemd unit/socket/timer files, обязан совпасть с текущим release: WebUI pointer-update не оставляет на host несовместимые старые units. Несовпадение безопасно отклоняется до mutation и означает, что нужен отдельный signed installer-upgrade artifact. Один verified staging не доказывает установку и может быть безопасно удалён.

Карточка **Версии и восстановление** хранит отдельно channel, автоматическую проверку, автоматическую загрузку, автоматическое применение, ежедневное окно обслуживания в UTC и максимальную задержку Apply от `1` до `720` часов (по умолчанию `72`). Durable automatic check/download/apply worker сохраняет restart-safe состояние, впервые введённое в schema 33, и использует только подписанный channel staging и fixed root apply; ручной staged release никогда не присваивается автоматике.

По умолчанию автоматические проверка, загрузка и применение выключены; ручная проверка и ручное подписанное обновление остаются доступны. Каждая ступень автоматики включается отдельно, а автоматическое применение дополнительно требует включённого UTC maintenance window. Состояние worker отображается после перезагрузки WebUI и не зависит от живого HTTP-запроса: `IDLE/DISABLED`, `CHECKING`, `CANDIDATE`, `DOWNLOADING`, `STAGED/WAITING_WINDOW`, `APPLY_INTENT/APPLY_DISPATCHED`, `SUCCEEDED/FAILED/SUPPRESSED`, `MANUAL_PENDING`, `MANUAL_ATTENTION` либо `OUTCOME_UNKNOWN`. Lease owner и его expiry являются внутренними полями SQLite и не возвращаются API. Для automatic staging сохраняется immutable `staged_at + apply_deadline_at`; изменение policy пересчитывает deadline только от исходного `staged_at`, а не продлевает его от текущего момента. Истечение deadline никогда не принуждает unsafe Apply: candidate остаётся проверенным staging, automation переходит в `MANUAL_ATTENTION`, фиксирует audit и ждёт решения администратора.

Check и download используют отдельную service-only лестницу, не переключающую активный пользовательский путь:

1. текущий active VPN node, если его access method всё ещё включён;
2. остальные разрешённые nodes включённых подписок по access-method/node/uplink priority и свежему evidence;
3. если policy **«Разрешить служебное обновление через прямой интернет»** включена — каждый ready uplink по приоритету.

VPN-попытка выполняется через изолированный Mihomo probe selector/SOCKS listener и перед выбором повторно проверяет stable node, `EXCLUDE`, enabled subscription и ready uplink уже под общим Mihomo operation lock. Direct fallback сначала сверяет owned policy routing, затем root-authorizes только точный `Gateway UID × interface × fwmark × resolved public IPv4 × TCP/443`; DNS и socket также привязаны к тому же uplink. CGNAT/private/link-local/documentation/benchmark/reserved адреса, другой UID/interface/mark/port и Ethernet-доступ к HiLink management subnet остаются закрыты. Отключённая подписка не может переносить generic Gateway update, но сохраняет отдельный self-refresh своей LKG через service-only selector.

Перед unattended Apply worker повторно читает последнюю policy generation и требует одновременно:

- отсутствие install/update/restore/network/uninstall/power maintenance operation либо неизвестного root maintenance state;
- активный fresh `FULL` пользовательский путь со всеми обязательными targets;
- хотя бы один fresh `REACHABLE` Management Fabric/WireGuard management handshake;
- попадание в заданное окно обслуживания UTC.

После этих проверок control plane сначала закрывает пользовательский путь, атомарно сохраняет `APPLY_INTENT` и лишь затем вызывает parameter-free root Apply. Потеря ответа после intent не приводит к повторному запуску: состояние становится `OUTCOME_UNKNOWN` до появления authoritative root journal. После restart automatic worker может принять только собственный `AUTOMATIC_GITHUB_CHANNEL` staging с тем же update ID/channel; ручная загрузка, manual GitHub staging и exact HTTPS остаются `MANUAL_PENDING`. Изменение policy до Apply не наследует прежнее автоматическое разрешение.

Состояние можно проверить без доступа к secret/root paths:

```bash
curl --cacert /var/lib/gateway-vpn/tls/cert.pem \
  https://127.0.0.1:8443/api/v1/system/update/automation
sudo journalctl --namespace=gateway-vpn --since=-30min | grep -i 'automatic signed update'
```

API требует обычную authenticated WebUI session; пример `curl` показывает только адрес endpoint и без session ожидаемо вернёт `401`. Если root broker или observation недоступны, worker сохраняет фиксированный sanitized reason code, ничего не применяет и повторяет проверку позже. Ручной verified staging и Apply продолжают работать независимо от automatic worker.

После typed `ОБНОВИТЬ` и отдельного confirmation Web/API сначала закрывает data path, сохраняет blocked state и вызывает parameter-free root broker. `gateway-vpn-update.service` повторно загружает fixed `PATH_BLOCKED` firewall, повторно проверяет staging и выполняет одну root transaction:

1. закрепляет `/opt/gateway-vpn/recovery` на старом проверенном release до любых live mutation;
2. устанавливает immutable candidate в `/opt/gateway-vpn/releases/v<version>` и запрещает переиспользовать каталог той же версии для другого signed artifact;
3. останавливает control/broker/Mihomo/dnsmasq, создаёт verified pre-update SQLite snapshot в `/var/lib/gateway-vpn-privileged/update-snapshots/` и мигрирует отдельную candidate DB;
4. запускает candidate binary в offline compatibility mode, проверяет закреплённый Mihomo и действующий Mihomo LKG;
5. атомарно заменяет DB, затем symlink `current`, запускает прежний набор managed services и требует три последовательных health observations;
6. оставляет root journal в `STABILIZING` на 24 часа. Каждые 15 минут finalize timer повторяет binary/DB/service health; после deadline состояние становится `FINALIZED`, а `recovery` атомарно переводится на новый проверенный release.

Любая ошибка после подготовки вызывает rollback согласованной пары: прежняя SQLite восстанавливается из verified snapshot, `current` возвращается на старый release, затем проверяется старая версия и запускается прежний набор services. Незавершённые состояния восстанавливает `gateway-vpn-update-recovery.service` до broker/control/data plane. `OnFailure` запускает `gateway-vpn-update-resume.service`, который сначала принудительно повторяет recovery, возвращает management socket/control plane и очищает ожидаемый failed-state исходных update/finalize units. Межпроцессный Linux `flock` не допускает одновременные Apply/Recover/Finalize. `recovery` остаётся на старом release весь stability window; последующие timer ticks для `FINALIZED`/`ROLLED_BACK` являются успешным no-op и не оставляют host в `systemctl --failed`.

Блок **Последняя root-транзакция обновления** отдельно от staging показывает только sanitized поля root-owned журнала: update ID, старую/новую версии, `PREPARED…STABILIZING/FINALIZED/ROLLED_BACK/ROLLBACK_FAILED`, timestamps, stability deadline и стабильный error code. Пути, snapshot ID, DB hashes и systemd diagnostics через broker не выдаются. `ROLLED_BACK` означает, что старая пара восстановлена; `ROLLBACK_FAILED` является критическим состоянием и требует сохранить fail-closed режим до диагностики.

### Версии и complete restore points

Таблица **Проверенные точки восстановления** показывает полный retained point: identity подписанного release, SQLite, config, secrets, subscriptions, TLS, Mihomo generations/state и проверочные hashes. Роли `CURRENT`, `RECOVERY` и `ACTIVE_TRANSACTION` вычисляются root-контроллером из реальных pointers/journal и защищают point от ручного удаления и retention. Кнопка **Очистить по сохранённой политике** применяет count/size/age limits только к eligible history; превышение лимита protected points не является разрешением удалить их.

Ручной rollback доступен только для point с тем же host contract. Он требует текущего пароля, `ROLLBACK_TO_RESTORE_POINT` и отдельного destructive confirmation. После повторной проверки совместимости control plane переводит пользовательский data path в `PATH_BLOCKED`, пишет audit и передаёт root только выбранный verified point ID через durable `/var/lib/gateway-vpn-privileged/update-rollback/pending.json`. Fixed `gateway-vpn-update-rollback.service` создаёт complete safety-point текущего состояния, восстанавливает historical release+DB/config/secrets/subscriptions/TLS/Mihomo pair и запускает обычные health/stability gates. Новые после выбранной точки настройки и данные намеренно заменяются. Ошибка, `SIGKILL` или reboot возвращает safety-point; вручную удалять pending request, safety-point или journal нельзя.

Диагностика:

```bash
sudo systemctl status gateway-vpn-update.service
sudo systemctl status gateway-vpn-update-rollback.service
sudo systemctl status gateway-vpn-update-recovery.service
sudo systemctl status gateway-vpn-update-finalize.timer
sudo systemctl status gateway-vpn-update-resume.service
sudo journalctl --namespace=gateway-vpn -u gateway-vpn-update.service -u gateway-vpn-update-recovery.service
sudo readlink /opt/gateway-vpn/current
sudo readlink /opt/gateway-vpn/recovery
sudo ls -la /var/lib/gateway-vpn-privileged/update-transactions/
sudo ls -la /var/lib/gateway-vpn-privileged/update-restore-points/
sudo ls -la /var/lib/gateway-vpn-privileged/update-rollback/
sudo nft list table inet gateway_vpn
```

Не удаляйте staging, root journal, snapshot, restore point, rollback request, `current` или `recovery` вручную во время `PREPARED…STABILIZING/ROLLING_BACK/ROLLBACK_FAILED/RELEASE_SWITCH_PENDING`. Update helper-ы нельзя запускать напрямую: они требуют fixed systemd environment и ordering.

Disposable privileged Ubuntu 24.04 Docker/systemd gate с тестовым signer подтвердил manual historical rollback, ownership всех восстановленных namespaces, сохранение foreign nft/interface, `SIGKILL` в `RELEASE_SWITCH_PENDING` и automatic safety-point recovery после настоящего нового PID 1. Terminal markers: `GATEWAY_RESTORE_POINT_SYSTEMD_PASS` и `GATEWAY_RESTORE_POINT_REBOOT_RECOVERY_PASS`. Это не заменяет bare-metal power-cut, физические modem/network paths и 24/72h hardware endurance; они остаются обязательными до production acceptance.

### Подписанное обновление host contract

Если `host_contract_sha256` candidate отличается, обычный WebUI pointer-update правильно отклоняет artifact до mutation. Обновление выполняется той же version-pinned bootstrap/installer командой новой версии: candidate installer обнаруживает finalized старую установку и передаёт работу `scripts/upgrade-gateway-host.sh`. Helper напрямую вручную не запускается.

Host-upgrade не совмещается с перенастройкой LAN, DHCP, SSH/SFTP, log-reader, `wg-ingress`, wait-online или GRUB. Сначала примените/откатите отдельную safe configuration transaction, затем повторите upgrade с параметрами действующего installation report. Старый release проверяет собственный signed tree своим verifier-ом; новый verifier проверяет candidate и точную gap-free migration history DB.

После `PATH_BLOCKED` и остановки runtime создаётся cold root-only snapshot под `/var/lib/gateway-vpn-host-upgrade/transactions/<id>/snapshot`. В него входят старые release pointers/tree, SQLite/WAL/SHM, config/secrets, privileged state и только фиксированные Gateway-owned host files. Synthetic snapshot parents никогда не копируются поверх `/etc`, `/usr`, `/var` или `/boot`; recovery восстанавливает отдельный allowlist destinations. Candidate first-install rollback наследует внешний FD lock и не имеет права удалить host-upgrade recovery helper.

Durable marker `/var/lib/gateway-vpn-host-upgrade/active` существует от готового snapshot до полной проверки candidate. Ошибка, SIGKILL либо новый boot вызывает `gateway-vpn-host-upgrade-recovery.service`, который возвращает старую signed release+DB pair, LAN/policies/services и оставляет firewall в `PATH_BLOCKED`. Старый pre-first-install marker переносится в новый completed marker, поэтому последующий uninstall восстанавливает состояние ОС до самой первой установки, а не до последнего upgrade.

Диагностика:

```bash
sudo systemctl status gateway-vpn-host-upgrade-recovery.service
sudo journalctl --namespace=gateway-vpn -u gateway-vpn-host-upgrade-recovery.service
sudo ls -la /var/lib/gateway-vpn-host-upgrade/
sudo readlink /opt/gateway-vpn/current
sudo readlink /opt/gateway-vpn/recovery
sudo nft list chain inet gateway_vpn forward
```

Не удаляйте `active`, transaction/tooling/snapshot или recovery unit вручную. Если recovery завершился ошибкой, marker намеренно остаётся и следующий boot может повторить идемпотентное восстановление. Exact success/failure/new-PID1 matrix относится только к тому candidate, для которого сохранено evidence; bare-metal power cut остаётся отдельным gate.

## Входящий WireGuard для клиентов

Вкладка **WireGuard-клиенты** управляет отдельным интерфейсом `wg-ingress`; он не является служебным `wg-mgmt`. Сервер можно включить при первой интерактивной установке либо позднее в WebUI. Standard routed profile использует отдельную private subnet (по умолчанию `10.90.0.0/24`), UDP port и public endpoint для готовых клиентских профилей. Если Gateway находится за Keenetic/другим NAT, этот UDP port нужно пробросить на LAN-адрес Gateway. Firewall принимает его только на выбранных listener interfaces; disabled или failed apply полностью удаляет `wg-ingress` из kernel.

`ROUTED` принимает traffic с выделенного LAN/listener. `SHARED_ONE_ARM` предназначен для схемы, где один Ethernet-интерфейс одновременно принимает WireGuard от существующего роутера и является явно назначенным uplink обратно к нему; выбранная карта обязана иметь роль `SHARED_ONE_ARM` и enabled uplink. Gateway всё равно применяет fwmark/owned routes и не создаёт wildcard/main-table fallback. Переход topology/subnet/listener проходит conflict validation до generation apply.

Поддерживаются два типа ключей клиента:

- **Managed** — Gateway создаёт private key и PSK в root-only `/var/lib/gateway-vpn/secrets/wireguard-ingress/`; готовый `.conf` и QR доступны только после повторного ввода текущего WebUI-пароля через одноразовый 90-секундный grant;
- **External** — пользователь вводит только public key; скачиваемый файл является шаблоном с `<INSERT_PRIVATE_KEY>`, QR намеренно недоступен.

Для каждого peer задаются адрес, device/router kind, optional подсети за удалённым роутером, client AllowedIPs, keepalive, DNS и разрешённые access methods. Режим `AUTO` следует общей priority/quality policy; direct-only/VPN-only и точный список методов ограничивают peer дополнительно. Рекомендуемая `Блокировать при неподходящем пути` не позволяет трафику peer выйти через незаявленный fallback. Handshake показывает только локальную WireGuard-связь и не заменяет FULL/LIMITED проверку Интернета.

**Отключить** сохраняет peer и номер, но удаляет его из kernel. **Отозвать** необратимо запрещает старый профиль и сохраняет audit row; только после этого доступно удаление root-only client secrets. **Повернуть ключ** для managed peer немедленно делает старый `.conf` недействительным. Server key rotation отзывает все ранее выданные client endpoint profiles и требует осознанного повторного экспорта.

Диагностика без вывода private keys:

```bash
sudo wg show wg-ingress
sudo ip -N -json -4 address show dev wg-ingress
sudo ip -N -json -4 route show dev wg-ingress protocol 186
sudo nft list set inet gateway_vpn wireguard_ingress_listeners
sudo journalctl --namespace=gateway-vpn --since=-15min | grep -i wireguard
```

Portable backup включает server key, managed peer keys и PSK только внутри encrypted `.gvpn`; plaintext secrets не появляются в manifest/API/logs. До hardware acceptance требуется клиентский handshake через реальный Keenetic, capture входящего UDP и выходного direct/VPN path, revoke/reconnect test и отдельная проверка one-arm loop isolation.

## Удалённый доступ WireGuard — совместимый первый link

Management-туннель настраивается во вкладке **Удалённый доступ**. Для первой настройки нужны private key Gateway, public key VPS и endpoint VPS с фиксированным UDP-портом `51821`. Gateway использует `10.80.0.2/32`, а `AllowedIPs` в MVP фиксирован как `10.80.0.0/24`. Начальное ожидание нового handshake — 45 секунд; Web UI допускает диапазон 30–180 секунд.

Конфигурация атомарно сохраняется в `/var/lib/gateway-vpn/secrets/wireguard.yaml` с mode `0600`. Private key не возвращается API и не подставляется обратно в форму: пустое поле при последующем изменении сохраняет действующий ключ. После сохранения root broker получает только безаргументную команду reconciliation, самостоятельно читает защищённый файл и SQLite, разрешает точный endpoint tuple и пробует модемы по priority.

Для каждого `MODEM_READY` Web UI показывает `UNTESTED`, `PROBING`, `REACHABLE`, `BLOCKED` либо `STALE`. Кандидат становится активным только после handshake новее начала пробы. При unplug маршрут VPS переносится на следующий модем; при hostname последний рабочий IPv4 сохраняется во время кратковременной ошибки DNS. Устаревший handshake показывается как предупреждение и сам по себе не влияет на пользовательский VPN path.

На VPS peer Gateway должен иметь `AllowedIPs = 10.80.0.2/32`; `Address = 10.80.0.1/24` создаёт connected route автоматически. До признания этапа выполненным обязательны `wg show wg-mgmt latest-handshakes`, `ip route get 10.80.0.2` на VPS и фактический вход в Web UI через `https://10.80.0.2:8443` при остановленном Mihomo.

## Successor Management Fabric и локальные ресурсы

Этот раздел фиксирует эксплуатационный contract расширения 2026-08-30. Текущий schema-25 release поддерживает только совместимый первый link выше; нельзя считать перечисленные ниже функции доступными, пока `PROJECT_STATUS.md` не покажет реализованные migrations/runtime/netns/systemd/browser gates.

В Gateway WebUI группа **Удалённый доступ** разделена на четыре страницы:

1. **VPS и каналы** — добавить/pair `1..N` VPS, увидеть отдельные key/subnet/interface, выбранный uplink, endpoint, handshake/RTT, generation и rotation;
2. **Администраторы** — отдельные peers/configs/revoke и выбор `ROUTED_HUB` либо рекомендуемого `END_TO_END_RELAY`;
3. **Локальные ресурсы** — явно опубликовать Gateway service, Keenetic service, host или subnet и выбрать способ `GATEWAY_ONLY`, `KEENETIC_WAN`, `VIA_KEENETIC_WAN_ROUTED`, `VIA_WG_ROUTER` либо `VIA_DEDICATED_LAN`;
4. **Матрица доступа** — проверить effective `administrator × VPS × Gateway × resource`, обе ACL generations и причину недоступности.

Все enabled VPS links остаются подняты одновременно; отказ одного не выключает остальные и не влияет на user data plane. Gateway всегда инициирует outer WireGuard, поэтому внешний IP/port forwarding на Gateway не нужен. У каждого link отдельные keypair, management subnet/interface и endpoint-uplink selector. Первый `wg-mgmt` остаётся slot 0; дополнительные links используют `gvm<N>` и не получают overlapping `AllowedIPs`.

Во вкладке **Администраторы** доступны два режима. **Внешний ключ** хранит private key только на устройстве пользователя. **Готовый конфиг** создаёт отдельный managed peer и требует текущий пароль плюс точную фразу; `.conf` скачивается один раз, после чего private key удаляется с VPS и состояние становится `CONSUMED`. Конфиг содержит private address этого peer, public key/endpoint VPS и routes ко всем опубликованным aliases данного VPS; наличие route не является разрешением — versioned ACL остаётся default-deny. Повторное скачивание невозможно. **Начать смену ключа** создаёт replacement peer с другим адресом; прежний peer следует отозвать только после скачивания нового конфига, host apply и fresh handshake.

Обычный Internet Keenetic продолжает идти через WAN Gateway. WireGuard на Keenetic не обязателен. Без него доступ к Home LAN требует явно настроенных WAN→LAN firewall/return route на Keenetic либо отдельного management-only Ethernet/VLAN; пока fresh service/return probe не прошёл, ресурс остаётся `WAITING_EXTERNAL_CONFIGURATION`. `VIA_WG_ROUTER` использует только management/local prefixes без `0.0.0.0/0` и не заменяет default route Keenetic.

Для одинаковых private LAN каждой публикации `site × resource × VPS link` назначается свой alias prefix. Поэтому один логический ресурс может иметь разные адреса **через VPS-A** и **через VPS-B**; оба portable admin tunnels остаются без duplicate routes. Адреса устройств не меняются, а arbitrary NAT/route expressions из WebUI не принимаются.

`ROUTED_HUB` расшифровывает admin WireGuard на доверенном VPS и подходит для HTTPS/SSH/SFTP, но полностью скомпрометированный VPS способен spoof source внутри outer link. В `END_TO_END_RELAY` VPS лишь пересылает allowlisted public UDP port через outer tunnel на отдельный `wg-admin` Gateway: inner session завершается на Gateway, VPS не имеет inner key и не может сформировать authenticated admin packet. Для raw Keenetic/local-resource access это рекомендуемый default; compromised relay всё ещё может вызвать DoS, но не прочитать payload.

Удаление administrator/VPS выполняется как revoke с durable tombstone и per-link acknowledgement. Restore **того же Gateway** сохраняет `site_id`, но требует key replacement и исключения старого экземпляра; restore **как нового Gateway** генерирует новый `site_id`, links/keys/prefixes. Одновременно active clone с одной identity должен переводиться в quarantine как endpoint flap.

WebUI не смешивает эти страницы с **Входящими WireGuard-клиентами** (`wg-ingress`), подписками/модемами или topology forms. Overview показывает только summary и deep links. Watchdog successor имеет отдельные `management_fabric_routes` и `wireguard_admin`; внешний outage одного VPS не запускает host reboot или restart других links.

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

`gateway-vpn-firewall-guard.service` независимо от control plane слушает `nft monitor ruleset` и каждые две секунды проверяет owned table, три base chain с `policy drop`, текущую schema generation `7`, exact conntrack mark preserve/restore rules, точный набор локальных management-интерфейсов, четыре named traffic counters, WireGuard-ingress listener set, Management Fabric sets/chains/jumps и критические rules. Boot/recovery ruleset оставляет Management Fabric dynamic chains и generation пустыми, поэтому ни старые ACL, ни старые VPS links после восстановления автоматически не открываются. При исчезновении/повреждении table guard сохраняет root-only marker в `/run/gateway-vpn-firewall-guard/`, переводит transit LAN interface administratively down, атомарно загружает только `table inet gateway_vpn` в `PATH_BLOCKED`, повторно проверяет её и лишь затем возвращает link up. Если восстановление не прошло, marker и quarantine сохраняются через restart guard-процесса.

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

`./scripts/uninstall.sh` по умолчанию является dry-run. `--apply` сначала атомарно загружает signed boot ruleset и проверяет `PATH_BLOCKED`, затем удаляет units/program/config и owned nftables/networkd/sysctl/journald/GRUB projection, восстанавливает сохранённые перед первой установкой forwarding/IPv6 и `src_valid_mark` (если это значение известно marker текущего поколения), LAN link/bridge members, SSH service/socket и log-reader membership, но сохраняет `/var/lib/gateway-vpn` для повторной установки. `--purge-data --apply` дополнительно и без скрытой копии удаляет application DB/secrets/keys/backups и `/var/log/gateway-vpn`; нужный portable backup/diagnostic export следует скачать до команды.

Удаление не является factory reset Ubuntu. Установленные системные packages не удаляются автоматически, чужие firewall/network rules не изменяются, а изменения, сделанные оператором или другим ПО после установки, не угадываются и не откатываются. После удаления owned firewall table оператор обязан убедиться, что обычная host firewall policy соответствует его требованиям. Восстановление прежней сети либо отключение SSH, который до установки был выключен, может оборвать текущую сессию.

WebUI в **Система и безопасность → Удаление Gateway VPN** сначала показывает фактический bounded impact report. Apply требует текущий пароль, точную фразу `УДАЛИТЬ GATEWAY VPN`, подтверждение разрыва management-сессии и границ восстановления ОС; `Полное удаление` дополнительно требует подтвердить потерю данных и то, что нужный экспорт уже сохранён либо осознанно не нужен. HTTP передаёт root только typed `operation_id + PRESERVE_DATA|PURGE_DATA`.

Root broker создаёт `root:root 0600` `/var/lib/gateway-vpn-uninstall/active` и запускает только `gateway-vpn-uninstall.service`. Helper до mutation повторно проверяет signed current release, копирует проверенные verifier/uninstaller/key в root-only tooling вне `/opt/gateway-vpn`, применяет `PATH_BLOCKED` и использует общий lifecycle lock. Поэтому SIGKILL или reboot после удаления `/opt` не лишает следующий boot uninstaller: enabled guardian с `ConditionPathExists` повторяет idempotent operation. Успех сначала fsync-сохраняет `completed-uninstall-…` receipt в `/var/lib/gateway-vpn-uninstall/`, затем удаляет active marker и guardian. Receipt является authoritative terminal evidence, особенно если SQLite была удалена либо WebUI отключился до ответа.

Проверка после удаления:

```bash
sudo ls -l /var/lib/gateway-vpn-uninstall/completed-uninstall-*
sudo systemctl status gateway-vpn-uninstall.service
sudo nft list table inet gateway_vpn   # ожидается отсутствие owned table после успешного завершения
```
