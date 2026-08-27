# Gateway VPN

Fail-closed IPv4-шлюз для одного или нескольких HiLink-модемов, HAPP-совместимых подписок и одного Mihomo TUN.

Архитектурный источник истины: [`docs/PLAN_v1.1.md`](docs/PLAN_v1.1.md). Текущий ход разработки, проверки, проблемы и принятые решения: [`docs/PROJECT_STATUS.md`](docs/PROJECT_STATUS.md).

Linux CI определён в `.github/workflows/ci.yml` и не имеет release secrets. Полный подписанный Gateway/VPS/bootstrap/deploy bundle собирается на отдельном trusted Linux builder через `scripts/build-release-bundle.sh`; `scripts/create-github-release-draft.sh` создаёт только проверяемый GitHub draft для последующей ручной immutable-публикации.

## Текущее состояние

Реализованы и покрыты unit/integration-level тестами strict config, SQLite migrations/repositories, multi-modem path matrix, subscription sanitizer/LKG, Mihomo generator/API transaction, qualification scheduler, runtime reconciler, защищённый Web API, verified backup/restore и Ed25519 signed update с согласованным rollback binary+SQLite. Production signing identity хранится одним portable `.gvkey` файлом под Argon2id + AES-256-GCM; verified backup является byte-identical encrypted copy, а release wrapper раскрывает PEM только во временный Linux tmpfs. Gateway clean-host installer валидирует private transit LAN и пересечения host routes, безопасно устанавливает только отсутствующие зависимости, загружает `PATH_BLOCKED` до IPv4 forwarding/LAN, сохраняет persistent systemd-networkd policy и имеет durable first-install recovery. Отдельный подписанный VPS role имеет exact profiles Ubuntu Server 20.04/22.04/24.04/26.04 LTS и Debian 12, локальную генерацию WireGuard key, owned firewall/recovery и тот же opt-in принцип dependency provisioning; Ubuntu 20.04 принимается только с актуальным Pro/ESM. Typed `gateway-vpn-deploy` проверяет две SSH-машины до apply, устанавливает exact signed roles, обменивает только WireGuard public keys, локально создаёт optional admin `wg-quick` config и выдаёт redacted `READY`/`INSTALLED_NOT_READY` report.

Контракт management API хранится в [`docs/openapi.yaml`](docs/openapi.yaml). Он автоматически сверяется со всеми зарегистрированными `/api/v1` маршрутами. Локальные пользователи MVP имеют одинаковые административные права; обязательная смена bootstrap-пароля, управление пользователями и отзыв активных сессий доступны во вкладке **Система и безопасность**.

Автоматизированные Linux/netns и privileged Ubuntu 24.04 Docker/systemd gates пройдены, включая exact install/reboot и signed update/rollback/finalize. Физический Gateway, HiLink/Keenetic, реальный VPS/provider UDP и 24/72-часовой endurance ещё не пройдены, поэтому проект нельзя считать production-ready для домашнего трафика. Точный статус и ограничения находятся в `docs/PROJECT_STATUS.md`; порядок первой проверки на железе — в разделе **Первый аппаратный acceptance** документа `docs/OPERATIONS.md`.

## Команды разработчика

Требуется Go 1.26.7 или совместимый toolchain:

```bash
make check
make build
./bin/gateway-vpn --version
./bin/gateway-vpn --check-defaults
./bin/gateway-vpn preflight
./bin/gateway-vpn firewall-boot --config config.example.yaml
./bin/gateway-vpnctl --version
./bin/gateway-vpn-deploy --version
```

Production distribution использует отдельно распространяемые `gateway-vpn-bootstrap` и `gateway-vpn-deploy`. Generated one-command сверяет заранее опубликованный SHA-256 launcher до исполнения; launcher затем повторно проверяет собственный hash/size/build identity по подписанному channel manifest. SSH работает без password/TTY, только с pinned `known_hosts`, `StrictHostKeyChecking=yes` и non-interactive `sudo -n`. Gateway/VPS private keys создаются только соответствующими hosts, а optional admin private key — только в защищённом локальном файле административной машины. Полный порядок публикации и one-command запуска описан в `docs/OPERATIONS.md`.

Hardware-проверки этапа 0 выполняются только на отдельном Gateway-стенде по `docs/OPERATIONS.md`; обезличенный результат каждой попытки записывается в `docs/PROJECT_STATUS.md`.
