# Gateway VPN — статус и журнал разработки

**Последнее обновление:** 2026-08-25  
**Общее состояние:** `IN_PROGRESS`  
**Текущий этап:** GitHub zero-to-ready distribution: clean local source baseline `dd60f31`, independent bootstrap, Gateway/VPS/deploy artifacts, signed channel, typed two-host SSH orchestration, local-only WireGuard key lifecycle и durable role recovery готовы; trusted Linux build, первый immutable GitHub release и реальные Linux/VPS gates впереди

**Оценка прогресса:** около `93%` программной реализации и около `65%` полной production-готовности. Вторая оценка намеренно ниже: она включает ещё не выполненные GitHub install, Ubuntu/systemd/nftables/Mihomo/WireGuard/VPS/hardware gates и обязательный 72-часовой endurance, которые нельзя заменить unit-тестами или cross-build.

Этот файл является отдельным оперативным журналом проекта. Архитектурные требования находятся в `PLAN_v1.1.md` и без отдельного решения не переписываются задним числом.

## Правила ведения

- верхняя часть файла показывает актуальное состояние;
- журнал сессий ведётся в обратном хронологическом порядке;
- для каждой сессии фиксируются сделанное, результат проверки, проблемы, изменения решений и следующий шаг;
- неуспешные эксперименты не удаляются;
- секреты, полные subscription URLs, private keys, SIM identifiers и серийные номера сюда не записываются;
- выполненным считается только проверенный результат; созданный, но не запущенный код отмечается отдельно.

## Режим работы Codex

- штатный уровень мышления для разработки — `High / Высокий`;
- обязательный протокол повышения и возврата уровня хранится в корневом `AGENTS.md`;
- перед блоком, которому существенно нужен `xhigh / Очень высокий`, `max / Макс` или `ultra / Ультра`, Codex обязан сообщить пользователю уровень и причину и дождаться подтверждения переключения;
- `Ultra / Ультра` запрашивается только для особо сложной работы, которая действительно выигрывает от нескольких независимых параллельных потоков;
- после завершения такого блока Codex обязан сразу сообщить, что можно вернуться на `High / Высокий`;
- уровень мышления не заменяет автоматические тесты и реальные Linux/VPS/hardware проверки.

## Текущий срез

| Область | Состояние | Комментарий |
|---|---|---|
| Архитектурный план | `DONE` | Зафиксирован `PLAN_v1.1.md` |
| Репозиторий | `LOCAL_COMMIT_PASS / REMOTE_NOT_RUN` | Первый clean local commit `dd60f31` создан после полного pre-commit gate; remote GitHub repository/release ещё не проверялись |
| Этап 0: hardware spike | `NOT_RUN` | Нужен Linux Gateway, Keenetic и минимум два HiLink-модема |
| Этап 1: bootstrap | `CODE_PASS / LINUX_NOT_RUN` | Config, SQLite/bootstrap lifecycle, HTTPS runtime, clean-host dependencies, private LAN/host-overlap preflight, fail-closed first-install recovery и persistent networkd policy готовы; Linux host validation ещё не выполнена |
| Data plane / Mihomo | `CODE_PASS / LINUX_NOT_RUN` | Atomic Linux symlink runtime, pinned API/TUN verify, broker restart/fail-closed и transaction recovery покрыты tests/compile; реальный Mihomo/Linux apply не запускался |
| Firewall / routing | `CODE_PASS / LINUX_NOT_RUN` | Dynamic TUN gate, protocol-186 routes, modem-scoped endpoint sets и независимый nft monitor/poll guard с LAN quarantine подключены; реальный nft/ip/netns apply не запускался |
| Modem Manager | `CODE_PASS / LINUX_NOT_RUN` | Netlink+poll runner, sysfs identity, networkd DHCP leases без default route, disconnect/replug sync и WebUI adoption подключены; реальные USB/networkd events не запускались |
| WireGuard management | `CODE_PASS / LINUX_NOT_RUN` | Protected WebUI config, parameter-free root sync, modem-priority handshake selector, exact nft endpoint tuple и hot-unplug/failback state machine покрыты tests; реальные wg/ip/nft/VPS не запускались |
| Subscription Manager | `CODE_PASS / LINUX_NOT_RUN` | Stable-number CRUD, protected URL secrets, priority/enable/delete lifecycle и modem×subscription status WebUI подключены; реальный mobile fetch/qualification не запускался |
| Qualification / scheduler | `CODE_PASS / LINUX_NOT_RUN` | Durable ACTIVE/STANDBY schedule, restart-safe hysteresis, scheduler budget deferral, independent target-outage confirmation и exact `DEGRADED_TARGET` recovery подключены; реальный Mihomo listener и mobile traffic budget ещё не проверены |
| SQLite | `PASS` | Migrations v1–v11, checksum/version guard, case-insensitive local-user identity, durable policy/health/logging settings и retention convergence state, monotonic numbers, WAL/PRAGMAs и integrity tests готовы |
| Safe network apply | `CODE_PASS / LINUX_NOT_RUN` | UID-bound root broker, typed Ubuntu backend, persistent networkd snapshot/apply/rollback+reload, 60-секундный systemd rollback, destination-bound confirm и reboot recovery покрыты tests; реальные nft/ip/systemd не запускались |
| API / Web UI | `CODE_PASS / LINUX_TLS_NOT_RUN` | 78 `/api/v1` routes покрыты contract-tested OpenAPI; обязательная смена bootstrap password, case-insensitive local admins, user/session lifecycle, Argon2id/session/CSRF, lifecycle tabs, logging/diagnostics/restore UI проходят Go/browser tests; реальный Ubuntu HTTPS/bind ещё не запускался |
| Logging / audit | `CODE_PASS / JOURNALD_NOT_RUN` | Dynamic levels/TTL, auth floor, aggregation, double redaction, parameter-free retention sync и bounded namespaced journal reader/API/UI покрыты tests; реальный journald ещё не запускался |
| Diagnostic bundle | `CODE_PASS / LINUX_HOST_NOT_RUN` | Memory-only bounded ZIP, manifest/SHA-256, partial section codes, privileged fixed-command host snapshot, audit/rate limit и WebUI download покрыты adversarial tests; реальные `ip/nft/wg/journalctl` данные Ubuntu ещё не собирались |
| Backup / restore | `CODE_PASS / LINUX_SYSTEMD_NOT_RUN` | SQLite Online Backup snapshots, corruption recovery, Argon2id+AES-GCM `.gvpn`, strict staging, root-owned journal, pre-restore snapshot, migration/session revoke, all-path rollback и WebUI покрыты success/adversarial/power-loss simulation tests; реальный root/systemd restore на Ubuntu ещё не запускался |
| Signed update | `CODE_PASS / LINUX_SYSTEMD_NOT_RUN` | Ed25519 release/staging, strict archive/metadata contracts, offline candidate+DB migration, atomic `current`/independent `recovery`, paired DB rollback, root journal/lock, 24h finalize, OnFailure resume и sanitized WebUI status покрыты synthetic tests; реальный Ubuntu root/reboot/power-cut update не запускался |
| Packaging | `GATEWAY_VPS_DEPLOY_CODE_PASS / GITHUB_LINUX_NOT_RUN` | Hash-pinned bootstrap/deploy, exact Gateway/VPS roles, signed channel, two-host preflight/apply, local-only keys, generated one-command и redacted readiness покрыты tests/syntax; реальный release/GitHub/SSH/install не запускался |
| Traffic accounting | `FOUNDATION_PASS` | Option A: общий authoritative total и Mihomo cross-check доступны в repository/API/UI; реальные nft counters ещё не считывались |
| Автоматические тесты | `PASS` | `go test ./...`, `go vet ./...`, shell/JS syntax и `linux/amd64 CGO_ENABLED=0` builds `gateway-vpn`, `gateway-vpnctl`, `gateway-vpn-bootstrap`, `gateway-vpn-deploy` прошли на Go 1.26.7 |

## Ближайший следующий инкремент

Следующий инкремент: получить clean checkout exact commit `dd60f31` на trusted Linux builder, собрать и подписать test release, опубликовать immutable GitHub assets и выполнить реальную двухмашинную dry-run/apply/resume/reboot matrix. Найденные integration defects исправляются до перехода к nft/netns, update/restore/recovery и hardware gates. Bootstrap/channel/deploy уже готовы только на synthetic уровне; GitHub redirects, OpenSSH, sudo, systemd, nftables, WireGuard handshake и WebUI bind фактически не запускались.

## Критический путь до release

При неизменном scope основной оставшийся путь — release/integration acceptance и найденные при ней исправления. После первого GitHub/Ubuntu deploy отдельно требуются update/restore/recovery acceptance, VPS reboot, Keenetic/HiLink packet-capture matrix и не сокращаемый 72-часовой endurance.

Если целевые Linux Gateway, VPS и модемы доступны без пауз, оптимистичный календарный ориентир до проверенного release — `4–8 дней`: примерно `1–3` интенсивных дня на оставшийся код и интеграционные исправления, затем минимум `72 часа` endurance. Это не обещанная дата: отсутствие стенда, найденные routing/hardware defects либо расширение scope сдвигают срок. Без фактического доступа к Linux/VPS/оборудованию можно завершить код и synthetic tests, но нельзя честно поставить production status `DONE`.

## Известные ограничения и блокеры

1. Текущая среда — Windows, команды `nft`, `ip` и `sqlite3` отсутствуют.
2. WSL установлен, но доступ к списку дистрибутивов завершился `E_ACCESSDENIED`.
3. Docker CLI установлен, однако Docker Engine не запущен; локальные образы недоступны.
4. Системный Go отсутствует. Официальный portable Go 1.26.7 загружен только в gitignored-каталог `.tools`, SHA-256 проверен; production/CI всё равно потребуют воспроизводимую Linux toolchain setup.
5. Обычная установка поддерживает `1..N` модемов и полностью работоспособна с одним. Этап 0 для multi-modem feature нельзя считать пройденным без реального packet capture минимум через два модема с разными management-подсетями; это стендовое требование, а не минимум для эксплуатации.
6. Clean local source baseline `dd60f31` создан. Remote GitHub repository/release credentials и trusted Linux builder в текущей среде не предоставлены; synthetic channel smoke не заменяет реальный GitHub Release.
7. Gateway installer/recovery/dependency/networkd code не запускался на Ubuntu 24.04: реальное поведение APT, systemd conditions, nftables ordering, sysctl, HTTPS bind, recovery/reboot и uninstall остаётся `NOT_RUN`.
8. VPS installer/recovery/dependency code не запускался на Ubuntu/Debian: реальное поведение APT, systemd, nftables, WireGuard, reboot и provider firewall остаётся `NOT_RUN`.

## Реестр решений реализации

| ID | Дата | Решение | Причина |
|---|---|---|---|
| DEV-001 | 2026-08-23 | `PLAN_v1.1.md` считать зафиксированным, ход работ вести здесь | Не смешивать требования и фактическую историю |
| DEV-002 | 2026-08-23 | Начать с fail-safe каркаса: runtime по умолчанию завершается без изменения сети | До firewall guard и проверок нельзя имитировать рабочий Gateway |
| DEV-003 | 2026-08-23 | На старте не добавлять внешние Go-зависимости | Позволяет проверить базовую модель стандартной библиотекой и уменьшает supply-chain поверхность |
| DEV-004 | 2026-08-23 | Использовать Go 1.26.7 как зрелый поддерживаемый toolchain | Go 1.27 вышел 2026-08-19; предыдущая ветка 1.26 остаётся поддерживаемой и имеет актуальный patch release |
| DEV-005 | 2026-08-23 | Официальное имя проекта — `Gateway VPN`; executable/service — `gateway-vpn`; admin CLI — `gateway-vpnctl` | Пользователь уточнил название после первого технического инкремента; `HAPP` обозначает только совместимые подписки |
| DEV-006 | 2026-08-23 | Зафиксировать `modernc.org/sqlite v1.56.0` | Pure-Go `database/sql` driver даёт одинаковые tests/build без CGO на Windows и Ubuntu; version и transitive hashes закреплены в `go.mod`/`go.sum` |
| DEV-007 | 2026-08-23 | На этапе foundation использовать один SQLite connection | Все connection-local PRAGMA гарантированно применяются; расширение pool возможно после отдельного concurrency test |
| DEV-008 | 2026-08-23 | Bootstrap YAML читать через `go.yaml.in/yaml/v3 v3.0.5` в strict mode | Поддерживаемая security-fix ветка; v4 на текущую дату остаётся release candidate |
| DEV-009 | 2026-08-23 | Любой network applicator по умолчанию работает как dry-run | До Linux nft validation, snapshot/rollback и firewall guard нельзя разрешать host mutation обычным запуском |
| DEV-010 | 2026-08-23 | Нормализованные proxy payloads хранить immutable-файлами `0600`, а в SQLite — identity/classification | Таблица `nodes` по плану не содержит credentials/config; секретный payload нужен для воспроизводимой генерации Mihomo после restart |
| DEV-011 | 2026-08-23 | Любая мутация target/matcher увеличивает `policy_generation` в той же DB transaction | Старый успешный probe не должен пережить изменение критериев проверки |
| DEV-012 | 2026-08-23 | Mihomo candidate не становится LKG до runtime verification | Успешный `mihomo -t` доказывает синтаксис, но не end-to-end работоспособность TUN/path |
| DEV-013 | 2026-08-23 | Auth schema вынесена в migration v2; password KDF — Argon2id из закреплённого `golang.org/x/crypto v0.47.0` | Парольный KDF нельзя заменять собственным алгоритмом; users/sessions должны переживать restart |
| DEV-014 | 2026-08-23 | API возвращает отдельные DTO, а не DB structs | `identity_hash`, secret refs и внутренние поля не должны случайно появиться в JSON при расширении repositories |
| DEV-015 | 2026-08-24 | Production target — только Ubuntu Server 24.04 LTS x86_64; Windows остаётся dev-средой | Cross-build доказывает компиляцию, но не заменяет systemd/nft/ip/netns и hardware verification |
| DEV-016 | 2026-08-24 | HTTP cache/backoff и single-refresh lease хранить durable в SQLite migration v3 | Manual/scheduled refresh не должны дублировать мобильный трафик или терять schedule после restart |
| DEV-017 | 2026-08-24 | Subscription LKG продвигается только после runtime qualification хотя бы одной пары modem × node; при DB activation error требуется compensating runtime rollback | HTTP 200 и `mihomo -t` недостаточны для доказательства обходного пути, а старая LKG не должна разрушаться |
| DEV-018 | 2026-08-24 | Safe network apply использует одновременно SQLite state и отдельный checksummed disk manifest; timeout helper не зависит от SQLite | Повреждение/lock БД или падение control plane не должны лишать систему rollback |
| DEV-019 | 2026-08-24 | Подтверждение принимается только по одноразовому token и local destination нового LAN IP либо через WireGuard | Запрос через старый адрес не доказывает доступность новой сети |
| DEV-020 | 2026-08-24 | Привилегированный network broker активируется Unix socket owner `gateway-vpn:gateway-vpn` mode `0600` и повторно проверяет peer через `SO_PEERCRED` | Web/API не получает `CAP_NET_ADMIN`, а другой service user той же группы не получает broker access |
| DEV-021 | 2026-08-24 | Safe apply разделён на `Stage` и `Apply` | UI должен получить одноразовый token и `new_url` до перезапуска API на новом адресе; timer уже вооружён, но сеть на стадии Stage ещё не изменена |
| DEV-022 | 2026-08-24 | Новая версия подписки сначала добавляется в Mihomo как qualification-only shadow provider с отдельным runtime key | Candidate можно проверять через каждый modem, но он не попадает в `gateway-vpn-active` до SQLite LKG activation |
| DEV-023 | 2026-08-24 | DB-компенсация activation выполняется даже если runtime rollback сообщил ошибку | Runtime restore обязан оставить путь восстановленным или fail-closed; кандидатная SQLite LKG и частичное evidence не должны оставаться authoritative |
| DEV-024 | 2026-08-24 | Privileged broker принимает только две дополнительные data-plane операции без параметров: restart фиксированного Mihomo unit и fail-closed фиксированных firewall/Mihomo units | Control plane не получает `CAP_NET_ADMIN`, произвольный unit name или shell; UID/socket boundary остаётся единым |
| DEV-025 | 2026-08-24 | Release требует явную Mihomo version и hash; version встраивается linker flag и записывается в checksummed `release.json` | Успешный `/version` считается только при точном совпадении с закреплённым core, а `latest` не может попасть в runtime |
| DEV-026 | 2026-08-24 | Mihomo service enabled, но имеет `ConditionPathExists=.../active/config.yaml`; отдельный persistent `.path` watcher не используется | После reboot LKG стартует автоматически, первый generation запускает broker; watcher мог бы повторно поднять service между fail-closed stop и удалением active link |
| DEV-027 | 2026-08-24 | Policy routing синхронизируется parameter-free root endpoint из authoritative SQLite inventory; control plane не передаёт `ip` arguments | Stale/offline modem routes удаляются без global flush, а привилегированная поверхность не превращается в command proxy |
| DEV-028 | 2026-08-24 | Direct service firewall использует tuples `interface × fwmark × IPv4 × port`; subscription IP разрешается на 2 минуты, Mihomo endpoints полностью заменяются для конкретного набора protected version IDs | Одинаковые IP/hostname через разных операторов остаются независимыми contexts; arbitrary Gateway/LAN direct traffic не открывается |
| DEV-029 | 2026-08-24 | `gateway-vpn.service` получает только `CAP_NET_RAW`, но не `CAP_NET_ADMIN`; capability нужна исключительно для `SO_BINDTODEVICE`/`SO_MARK`, а nft output ограничивает UID и root-authorized tuples | Modem-bound DNS/HTTPS нельзя корректно реализовать обычным unmarked socket при отсутствии default route в main table |
| DEV-030 | 2026-08-24 | Huawei HiLink interfaces получают DHCP через отдельный systemd-networkd profile `ID_BUS=usb + ID_VENDOR_ID=12d1`, но `UseRoutes/UseGateway/UseDNS/UseNTP=no` | DHCP lease нужен приложению, однако networkd не должен создать main-table default route или изменить host DNS/NTP |
| DEV-031 | 2026-08-24 | Modem Manager сначала фиксирует `READY/OFFLINE/CONFLICT` в SQLite и только затем вызывает parameter-free root sync | Root broker строит authoritative plan из DB; противоположный порядок сохранял бы route отключённого модема или не видел бы новый lease |
| DEV-032 | 2026-08-24 | Текущие discovery matches хранятся в thread-safe ephemeral registry, а постоянным объектом становятся только после CSRF-protected adoption | Исчезнувший USB device не должен оставаться конфигурацией, identity hash не должен попадать в Web/API, а adopted modem/priority должны переживать restart |
| DEV-033 | 2026-08-24 | WireGuard root broker принимает только пустой `sync`; config/keys/endpoint/modem route context читает из protected file и SQLite | Web/API не должен передавать root произвольный endpoint, interface, fwmark, route table или key material |
| DEV-034 | 2026-08-24 | Подтверждённый management modem и владелец фактического endpoint route хранятся раздельно; любой switch сначала остаётся `PROBING` до нового handshake | Неуспешный failback обязан удалить candidate route и восстановить прежний modem, не выдавая неподтверждённый путь за active |
| DEV-035 | 2026-08-24 | WireGuard hostname имеет пятиминутный runtime cache и минутный retry с сохранением последнего подтверждённого IP; config fingerprint принудительно запускает re-probe | Временная DNS-ошибка не должна уничтожать рабочий management route, а смена endpoint/key не должна ошибочно стать `NO_CHANGE` |
| DEV-036 | 2026-08-24 | Firewall guard перед recovery сохраняет root-only marker и administratively выключает только transit LAN; link возвращается после schema/drop verification, а старый active generation не восстанавливается | После удаления owned table нельзя полагаться на основной Go-процесс или открывать прежний TUN path без новой end-to-end проверки; marker должен пережить crash guard |
| DEV-037 | 2026-08-24 | Каждая path activation повторно авторизует endpoint активной immutable subscription version до Mihomo selection/probe | Boot ruleset после guard recovery очищает dynamic sets; без rehydration qualified LKG не смогла бы снова соединиться и открыть проверенный TUN gate |
| DEV-038 | 2026-08-24 | Подписки получают монотонный непереиспользуемый `display_number`; URL остаётся только в atomic secret file, а локальный WebUI preview использует synthetic server-side session только на numeric loopback | Приоритет и UUID не являются человекочитаемым постоянным номером; браузерные smoke-tests не должны ослаблять production `Secure` cookie или запускать network workers |
| DEV-039 | 2026-08-24 | Matcher и manual node override переклассифицируют active-version node inventory в той же SQLite transaction, что и `policy_generation`; regex mutation требует HMAC-bound preview текущего inventory | Новый UI-policy не должен сосуществовать со старым Mihomo candidate pool; preview должен устаревать при изменении matcher/inventory context и не быть обходом синтаксической проверки |
| DEV-040 | 2026-08-24 | `expected_body` проверяется через отдельный `127.0.0.1` Mihomo mixed listener, global probe selector и отдельную probe-группу каждой path; controlled select + HTTPS request сериализованы | Body API нельзя доказать delay endpoint-ом, а переключение обычной path group во время проверки могло бы затронуть живой пользовательский трафик |
| DEV-041 | 2026-08-24 | HTTP-status expression канонизируется до записи, а удаление/disable/demotion последнего enabled required target требует подтверждения внутри той же SQLite transaction | Runtime и Mihomo должны видеть один однозначный status contract; предварительный API count не защищает от конкурентных мутаций и может оставить систему без обязательной проверки без осознанного решения |
| DEV-042 | 2026-08-24 | Policy mutation активного tuple в той же transaction сохраняет generation/start/deadline и переводит Gateway в `VERIFYING_POLICY`; schema v7 trigger запрещает partial transition, а restart всегда очищает его в `PATH_BLOCKED` | Grace должен переживать control-plane сбой как однозначное durable состояние, но старое evidence нельзя автоматически возобновлять после reboot |
| DEV-043 | 2026-08-24 | Текущий active node проверяется синхронно первым; если новая policy исключила его, node остаётся первым только в grace provider payload, но отсутствует в candidate pool/evidence новой generation | Mihomo reload не должен незаметно переключить живой трафик до проверки replacement, а запрещённый новой policy узел не должен получить ложный qualified status |
| DEV-044 | 2026-08-24 | После каждого сохранённого qualification snapshot запускается aggregate target evaluator; `UNKNOWN/NORMAL/TARGET_SUSPECT` и state-change events опираются только на свежие generation-scoped независимые modem/subscription combinations | UI и будущая suppression policy должны различать отказ path/node и вероятный общий outage проверяемого ресурса |
| DEV-045 | 2026-08-24 | Первый production deploy поставляется как signed/versioned GitHub Release для ролей Gateway/VPS; дополнительно создаётся SSH-orchestrator `gateway-vpn-deploy`, доводящий обе чистые поддерживаемые Ubuntu-машины одной командой до проверенного `READY` либо безопасного явного failure | Удобство «с нуля» не должно превращаться в `curl | sudo bash`, скрывать несовместимое железо или считать `systemd active` доказательством готовности data/management plane |
| DEV-046 | 2026-08-24 | DEV-015 ограничивает Ubuntu 24.04 только ролью Gateway; VPS получает отдельные Ubuntu LTS profiles 20.04/22.04/24.04/26.04 и Debian 12+, причём 20.04 требует активного ESM/security coverage | Фактический VPS пользователя работает на Ubuntu 20.04; публичный management endpoint нельзя считать поддержанным без security maintenance после окончания standard support |
| DEV-047 | 2026-08-24 | Exact diagnostic probe восстанавливает предыдущую Mihomo generation и не пишет evidence; exact qualification upsert-ит только выбранный node и атомарно пересчитывает cell из всех свежих peers | Диагностика не должна незаметно менять failover ranking, а проверка одного сервера не должна удалять свежие результаты других серверов подписки |
| DEV-048 | 2026-08-24 | Ручная активация принимает exact fresh node, проходит через штатные state/actuator transitions и остаётся активной при следующем reconcile; Web API выдаёт node/target details keyset-страницами | Прямой selector обошёл бы generation/expiry и fail-closed проверки, а eager matrix response не масштабируется с большим числом серверов и targets |
| DEV-049 | 2026-08-24 | Logging settings становятся отдельным System/Security read model: per-component levels, bounded journald retention и debug только с TTL; обязательный audit и pre-logger secret redaction пользователь отключить не может | Подробная диагностика нужна для эксплуатации, но постоянный debug расходует диск/мобильный трафик и не должен превращаться в канал утечки subscription/proxy/modem secrets |
| DEV-050 | 2026-08-24 | Migration v8 хранит ACTIVE/STANDBY schedule и success/failure streak каждого path; смена роли обнуляет streak и делает path немедленно due, а `DEFERRED_BUDGET` переносит следующую попытку без изменения authoritative evidence, streak или `last_probe_at` | Hysteresis должен переживать restart, failover должен немедленно переклассифицировать cadence, а исчерпание мобильного бюджета не является сетевым отказом |
| DEV-051 | 2026-08-24 | Required-target failure подавляет failover только после exhaustive confirmation через достаточные независимые modem/subscription combinations; exact active tuple остаётся `PATH_ACTIVE` в `DEGRADED_TARGET` без смены firewall generation и восстанавливается тем же reconciler без повторной активации | Общий outage проверяемого сайта не должен вызвать бессмысленное переключение модемов/подписок, но при недостатке независимых evidence политика обязана оставаться строгой |
| DEV-052 | 2026-08-24 | Health WebUI читает redacted periodic schedule и in-memory per-modem probe usage через отдельный authenticated status API; scheduler публикует только immutable limits и агрегированные bytes/requests | Оператору нужны причины отсрочки и расход мобильного бюджета, но API не должен раскрывать target payloads, credentials или произвольный scheduler state |
| DEV-053 | 2026-08-24 | Durable logging policy хранит только base levels `error/warning/info`; temporary debug является отдельным component-scoped overlay с TTL 5 минут–24 часа и автоматически очищается worker-ом/reboot recovery | Возврат к прежнему уровню не должен зависеть от сохранённой копии settings, а permanent debug в bootstrap config противоречит ограниченному diagnostic режиму |
| DEV-054 | 2026-08-24 | Единственный `slog.Handler` фильтрует по component, агрегирует повторные path/health warnings и рекурсивно redacts key/value/group/map/struct/error до передачи JSON handler-у; `auth_audit` всегда имеет effective threshold не выше `info` | Redaction после journald уже поздняя, вложенные values/WithAttrs иначе обходят простой DTO filter, а global `error` не должен выключать обязательный audit |
| DEV-055 | 2026-08-24 | Все Gateway VPN service units получают `LogNamespace=gateway-vpn`; installer задаёт безопасные bootstrap defaults 14 дней/256 MiB, а UI показывает отдельный runtime state до первого подтверждённого root sync | Общий host journal нельзя бесконтрольно занимать сервисными логами; software status не должен ложно утверждать, что непривилегированный процесс уже переписал root journald config |
| DEV-056 | 2026-08-24 | Bootstrap admin, invalid/rate-limited/successful login и logout пишутся в SQLite audit в той же transaction, что соответствующее auth state change; failed username хранится только как SHA-256, пароль не попадает в details | Обязательный login audit нельзя реализовывать best-effort callback после выдачи session, иначе crash оставит успешный вход без события |
| DEV-057 | 2026-08-24 | Migration v10 хранит desired/applied retention fingerprints и state `UNKNOWN/PENDING/APPLYING/APPLIED/FAILED`; parameter-free root sync перечитывает settings из SQLite, атомарно применяет fixed journald drop-in и откатывает его при неуспешном restart/verify | HTTP не должен передавать root retention values или путь, а UI обязан отличать durable desired policy от фактически подтверждённой конфигурации journald |
| DEV-058 | 2026-08-24 | Технический журнал читается через root broker фиксированным `/usr/bin/journalctl` только из namespace `gateway-vpn`; control plane не получает broad `systemd-journal` membership | Доступ ко всему host journal чрезмерен для Web/API и нарушает разделение привилегий |
| DEV-059 | 2026-08-24 | Journal query принимает только allowlisted typed filters и bounded keyset pagination: 25 returned/129 scanned records, 31 день, 2 MiB subprocess output, 64 KiB broker response и 20 запросов/минуту на session | Текстовый поиск и cursor не должны превращаться в arbitrary `journalctl` arguments, неограниченное чтение памяти или канал DoS |
| DEV-060 | 2026-08-24 | Journal reader повторно redacts каждое сообщение и structured field после чтения, ограничивает UTF-8 message/unit/IDs и не доверяет даже записям собственного namespace | Pre-logger redaction является основной защитой, но imported/legacy/non-JSON journal records требуют независимой защиты на границе выдачи API |
| DEV-061 | 2026-08-24 | Diagnostic bundle строится только в памяти как fixed-entry ZIP с per-file manifest, SHA-256, лимитами 24 MiB uncompressed/32 MiB archive и mode `0600` для каждой записи | Support artifact не должен оставлять секретный временный файл, допускать traversal/duplicates или неограниченно занимать память |
| DEV-062 | 2026-08-24 | Privileged host diagnostics является parameter-free операцией root broker и запускает только фиксированные absolute `uname/ip/nft/wg/mihomo` команды и чтение `/etc/os-release` | Web/API не должен превращать диагностику в command/path proxy или позволять выбрать чужую nft table, interface либо journal namespace |
| DEV-063 | 2026-08-24 | Ошибка отдельной diagnostic section не отменяет архив: manifest получает `complete=false` и стабильный code без backend details; данные проходят повторную sanitization/redaction перед ZIP | Частичная диагностика полезнее полного отказа, но оператор обязан видеть неполноту, а тексты root/journal ошибок не должны раскрывать секреты |
| DEV-064 | 2026-08-24 | Создание архива требует authenticated session + CSRF, не принимает body/options, ограничено тремя архивами за 10 минут на session и до download пишет `DIAGNOSTIC_BUNDLE_CREATED` | Параметр `include_secrets` недопустим даже как опция, а ресурсоёмкая support operation должна иметь rate limit и audit trail |
| DEV-065 | 2026-08-24 | Runtime topology явно определена как `1..N`: один модем — штатный режим без межмодемного failover, а минимум два требуется только для проверки multi-modem feature | Установка не должна требовать резервный uplink; при disconnect единственного модема Gateway обязан остаться `PATH_BLOCKED`, а не искать несуществующий modem |
| DEV-066 | 2026-08-24 | SQLite snapshots создаются только Online Backup API, полностью проверяются до ротации и разделяются на daily/manual/pre-migration/pre-restore/pre-network-apply | Копирование live WAL-файла или обычный file copy не гарантирует согласованную backup image и не даёт пригодного corruption recovery evidence |
| DEV-067 | 2026-08-24 | Полный portable backup имеет `.gvpn`, chunked AES-256-GCM и Argon2id; обязательны DB/config/Mihomo API secret/TLS cert+key, а passphrase и plaintext ZIP не сохраняются | Незашифрованный ZIP раскрывал бы все VPN/subscription/TLS secrets, а формально успешная копия без bootstrap secrets не может восстановить запускаемую систему |
| DEV-068 | 2026-08-24 | Restore разделён на unprivileged authenticated staging и отдельный root apply: перед каждым apply повторно проверяются manifest/files/SQLite/config, создаётся `pre-restore` snapshot, candidates находятся рядом с destinations, а root-owned journal обеспечивает reverse rollback и recovery после power loss | Один rename невозможен между `/etc` и `/var`; последовательная замена без durable journal оставляла бы смешанное DB/config/secrets состояние после сбоя |
| DEV-069 | 2026-08-24 | После restore все sessions отзываются, runtime принудительно остаётся `PATH_BLOCKED`, stale Mihomo active link удаляется, а reconciler обязан заново доказать path до `PATH_ACTIVE` | Состояние из backup не является свежим доказательством текущего modem/subscription/network path и не должно автоматически открыть пользовательский трафик |
| DEV-070 | 2026-08-24 | Root broker принимает только пустой `/v1/restore/apply` и запускает один fixed systemd unit; bootstrap Mihomo executable и secret/TLS paths теперь фиксированы управляемыми путями | Restore API не должен передавать root restore id/path/unit/command, а восстановленный YAML не должен превращать root diagnostics или services в arbitrary executable/path proxy |
| DEV-071 | 2026-08-24 | В MVP каждый enabled local user является администратором; username ограничен conservative ASCII и защищён case-insensitive unique index migration v11 | Полный RBAC явно исключён планом, но неоднозначные регистром учётные записи и возможность потерять последнего администратора недопустимы |
| DEV-072 | 2026-08-24 | Bootstrap password блокирует весь API кроме session/password/logout; собственная смена сохраняет только current session, reset/disable отзывают все target sessions | Одного UI-предупреждения недостаточно: временный пароль нельзя использовать для обычного управления, а смена credentials должна немедленно сокращать поверхность активных сессий |
| DEV-073 | 2026-08-24 | `docs/openapi.yaml` описывает все 78 реально зарегистрированных `/api/v1` method; contract test проверяет route parity, уникальные operation IDs, CSRF, cookie auth, path params и локальные `$ref` | Ручная спецификация без автоматической сверки быстро расходится с handler и создаёт ложный контракт для installer/UI/CLI |
| DEV-074 | 2026-08-25 | Update artifact является immutable versioned Ed25519-signed tree со строгими SemVer/Git/build metadata, полным manifest и compatibility contract; та же версия не может быть переиспользована для другого signed artifact | SHA-256 без доверенного signer не аутентифицирует release, а mutable version directory ломает audit и rollback identity |
| DEV-075 | 2026-08-25 | Update переключает SQLite и release как журналируемую пару, заранее закрепляет отдельный `recovery` pointer на старом release и сохраняет rollback snapshot/lock вне writable state parent минимум до завершения 24h stability window | Candidate binary/current pointer не должен быть единственной программой восстановления, а новая schema со старым binary или наоборот является недопустимым mixed state |
| DEV-076 | 2026-08-25 | Apply/Recover/Finalize выполняются только fixed systemd units после повторного `PATH_BLOCKED`; failure resume возвращает broker/control лишь после успешного recovery | Запуск update из Web/API не должен передавать root параметры или оставлять management/data plane в неопределённом состоянии после остановки service |
| DEV-077 | 2026-08-25 | WebUI читает результат последней root update transaction отдельным parameter-free broker request и получает только versions/state/timestamps/error code | Staging не доказывает исход установки, но filesystem paths, snapshot IDs, DB hashes и systemd diagnostics не должны пересекать privilege boundary |
| DEV-078 | 2026-08-25 | Первый install доверяет только отдельно распространяемому bootstrap, чей SHA-256 встроен в generated command; candidate verifier не является корнем доверия | Проверка release бинарником из того же непроверенного archive была бы циклическим доверием |
| DEV-079 | 2026-08-25 | Caller URL всегда запрещает query; signed query разрешён только проверенному GitHub asset redirect на allowlisted storage hosts | GitHub Releases реально использует краткоживущий query, но разрешать токены в исходных пользовательских URL или на любом redirect нельзя |
| DEV-080 | 2026-08-25 | Channel manifest Ed25519-подписывает exact version/commit и строго именованные role artifacts с hash/size; Gateway archive содержит полный installer/config/packaging tree и устанавливается без потери подписанных файлов | Одна команда должна аутентифицировать bootstrap и весь install payload, а установленный release обязан повторно совпадать с тем же полным manifest |
| DEV-081 | 2026-08-25 | Штатный reasoning effort проекта — `High`; перед существенно более сложным блоком Codex останавливается, просит переключить на `xhigh`/`max`/`ultra`, а после блока сообщает о возврате на `High`; `Ultra` применяется только при реальной пользе независимых параллельных потоков; постоянное правило хранится в `AGENTS.md` | Сохранять качество на критических блоках без постоянного расхода повышенного reasoning budget и не полагаться на память отдельной сессии |
| DEV-082 | 2026-08-25 | VPS поставляется отдельным подписанным role artifact для exact profiles `debian-12`, `ubuntu-20.04/22.04/24.04/26.04`; первая установка создаёт `wg-mgmt` локально и заканчивается только `INSTALLED_NOT_READY` до реального handshake | Наличие active units не доказывает доступность management path, а VPS private key нельзя передавать через GitHub или command line |
| DEV-083 | 2026-08-25 | VPS dependency provisioning является opt-in `--install-dependencies`; APT plan дважды симулируется с `--no-remove --no-upgrade`, разрешает только фиксированные missing top-level packages и никогда не откатывает успешно установленные host packages application rollback-ом | Автоматизация чистого VPS не должна удалять/обновлять чужие пакеты, а удаление общих OS dependencies при rollback опаснее их сохранения |
| DEV-084 | 2026-08-25 | Ubuntu 20.04 до managed package mutation требует уже установленные Pro client/Python, attached non-expired Pro, enabled `esm-infra`/`esm-apps` и отсутствие pending updates; maintenance gate повторяется после `apt-get update` | Installer не имеет права автоматически подключать платную подписку или объявлять EOL-систему поддерживаемой по устаревшему APT cache |
| DEV-085 | 2026-08-25 | Install/recovery/uninstall VPS используют один root-owned non-blocking lock и durable marker; recovery удаляет только owned state, не архивирует marker до полной проверки и сохраняет валидный `wg-mgmt.conf` при обычном uninstall/reinstall | Одновременные root operations, power loss и потеря VPS private key не должны создавать смешанное либо необратимое состояние |
| DEV-086 | 2026-08-25 | Generated one-command использует HTTPS-only `curl` с GNU `wget` fallback, проверяет внешний bootstrap SHA-256 до root и работает напрямую в root-shell либо через `sudo` | На Debian VPS `sudo` может отсутствовать, а downloader может различаться; удобство не должно ослаблять bootstrap trust chain |
| DEV-087 | 2026-08-25 | Exit code `10` dependency preflight означает только невозможность построить plan до refresh и допускается bootstrap-ом исключительно между read-only/apply фазами; removal, upgrade, empty и прочие plans остаются фатальными | Устаревшие APT indexes не должны блокировать one-command apply, но непроверенный plan нельзя ошибочно назвать `DEPENDENCY_PLAN_VALIDATED` |
| DEV-088 | 2026-08-25 | Gateway clean-host dependency provisioning использует тот же opt-in/double-simulation/no-remove/no-upgrade contract и не удаляет успешно установленные OS packages при rollback | Установка одной командой на чистую Ubuntu 24.04 не должна требовать ручного поиска пакетов и одновременно не должна менять постороннее host state |
| DEV-089 | 2026-08-25 | Внешний Gateway LAN contract един для config/bootstrap/channel/safe-apply: usable RFC1918 `/16../30`, без network/broadcast, WireGuard overlap и пересечений с observed host addresses/non-default routes | Публичный или пересекающийся transit CIDR может открыть API не там, сломать маршрутизацию либо сделать rollback недостижимым |
| DEV-090 | 2026-08-25 | First-install durable marker сохраняет IPv4/IPv6 sysctl и LAN/link state; signed `PATH_BLOCKED` применяется до LAN/IPv4 forwarding, а application units при active marker запускаются только с ephemeral root-owned `/run` authorization живого installer | Установка не должна иметь direct-forwarding окно, а crash/reboot не должен запускать частично установленный control/data plane |
| DEV-091 | 2026-08-25 | Transit LAN записывается в owned systemd-networkd file; safe apply snapshot/apply/rollback включает этот файл и выполняет только reload до explicit confirmation | Назначенный только runtime адрес исчез бы после reboot, а destructive networkd reconfigure до подтверждения нарушил бы доступность rollback |
| DEV-092 | 2026-08-25 | `gateway-vpn-deploy` использует только fixed `/usr/bin/ssh`, `-F /dev/null`, strict pinned known_hosts, BatchMode/no-password/no-TTY, validated destinations/ports/paths и bounded output | Удобство SSH orchestration не должно принимать ProxyCommand/options из пользовательского ввода, зависеть от interactive password prompt или превращать remote output в memory/log secret leak |
| DEV-093 | 2026-08-25 | Оба signed role dry-run выполняются до первого apply; actual Gateway public key создаётся локально после них, а VPS получает повторный exact-key preflight перед apply | VPS installer требует Gateway public key, но private key нельзя создавать заранее либо передавать через admin/GitHub; placeholder допустим только в non-mutating clean-host preflight |
| DEV-094 | 2026-08-25 | Gateway/VPS/admin private keys создаются только на соответствующих hosts; resume читает только public identity, pending key удаляется после atomic config+fsync, raw public keys в report заменяются fingerprints | Interruption не должен заставлять менять уже записанный VPS peer, а one-command install не должен передавать private key через argv/SSH/stdout или молча ротировать existing config |
| DEV-095 | 2026-08-25 | Deploy exit code `0` разрешён только при свежем expected WireGuard handshake и `PATH_ACTIVE`; безопасно установленные роли без модема/подписки возвращают code `3` и `INSTALLED_NOT_READY` | Active systemd units и наличие файлов не доказывают management/data readiness, но отсутствие пользовательской конфигурации после clean install не является rollback-worthy corruption |
| DEV-096 | 2026-08-25 | Внешний orchestrated dependency dry-run использует отдельный `DEPENDENCY_GATE_PASSED_OR_REFRESH_REQUIRED`; APT refresh остаётся только apply-фазе с повторной simulation | Устаревший package index не должен блокировать clean-host one-command до разрешённой apply, но невозможность полного preflight при отсутствующих packages нельзя называть обычным `PASSED` |
| DEV-097 | 2026-08-25 | Первый release разрешено строить только из exact clean commit; локальный baseline `dd60f31` фиксирует проверенную source identity, но сам по себе не считается trusted Linux/GitHub release | Untracked workspace нельзя воспроизводимо связать с build metadata, SBOM, provenance и immutable artifacts |

## Журнал разработки

### Сессия 032 — первый clean commit и перевод на Linux release gate — 2026-08-25

**Сделано:**

- весь ранее untracked workspace проверен перед staging: реальные private keys/tokens/runtime databases не найдены; совпадения secret scan оказались намеренными фальшивыми значениями redaction-тестов;
- локальные binaries/caches остаются вне source tree через `.gitignore`; добавлен `.gitattributes` с repository-wide LF, чтобы shell/systemd assets не получали CRLF при работе из Windows;
- staged snapshot проверен на случайные крупные/secret artifacts и line-ending contract;
- создан первый локальный root commit `dd60f31` (`feat: implement Gateway VPN foundation and deployment`), содержащий 349 source/documentation/packaging files;
- commit identity задан только для одной команды как `Codex <codex@local.invalid>`; global Git config пользователя не изменялся.

**Проверено перед commit:**

- `go test ./... -count=1` — PASS;
- `go vet ./...` — PASS;
- Linux/amd64 `CGO_ENABLED=0` builds `gateway-vpn`, `gateway-vpnctl`, `gateway-vpn-bootstrap`, `gateway-vpn-deploy` — PASS;
- `node --check internal/webapi/static/app.js` — PASS;
- Git Bash `bash -n scripts/*.sh test/netns/*.sh` — PASS;
- Git index содержит LF, реальные secrets и tracked build artifacts не обнаружены.

**Не выполнено и не считается PASS:**

- commit ещё не получен clean Linux checkout-ом и не собран trusted Linux builder-ом;
- GitHub repository/release, signed immutable assets и реальные Gateway/VPS hosts в текущей среде недоступны;
- локальный Windows cross-build не меняет общий runtime status `LINUX_NOT_RUN`.

**Следующий шаг:** clean checkout exact commit `dd60f31` на trusted Linux builder, signed test release и реальная двухмашинная acceptance matrix.

### Сессия 031 — typed SSH deploy, local-only keys и redacted readiness — 2026-08-25

**Сделано:**

- добавлен Linux/amd64 `gateway-vpn-deploy`, который локально проверяет raw channel hash, Ed25519 signature/signer, exact version/commit, собственные signed size/SHA-256/build identity и наличие всех `gateway/vps/bootstrap/deploy` artifacts;
- SSH executor принимает только validated `USER@HOST`, numeric port, regular non-symlink known-hosts/identity files, запускает fixed `/usr/bin/ssh -F /dev/null` с `BatchMode`, `StrictHostKeyChecking`, no password/keyboard-interactive/TTY и bounded stdout/stderr;
- orchestrator выполняет SSH prerequisites и обе signed role dry-run фазы до первого apply; ошибки обеих preflight собираются до возврата и не начинают installation;
- clean-host VPS dry-run использует только syntactically valid placeholder Gateway public key; после Gateway apply local helper от service UID создаёт pending private key, возвращает public key и запускает повторный exact-key VPS preflight;
- `gateway-vpnctl deploy-wireguard-inspect/prepare/finalize` реализуют read-only resume, exclusive pending key mode `0600`, X25519 public derivation, exact existing-config check, atomic `wireguard.yaml` и directory fsync без вывода private key;
- VPS public key читается только из strict bounded install report; итоговый JSON содержит SHA-256 fingerprints keys, phase/status/diagnostic codes и не сериализует raw public keys либо remote stdout/stderr;
- optional `--admin-config` создаёт/resume admin private key только на административной машине и после VPS install атомарно формирует exact `10.80.0.10/32` wg-quick config; альтернативный `--admin-public-key` сохраняет внешний key lifecycle;
- readiness проверяет обе owned nft tables/services, локальный Gateway HTTPS, свежий handshake именно ожидаемого VPS peer и runtime `PATH_ACTIVE`; результат без modem/subscription/handshake — code `3`/`INSTALLED_NOT_READY`, а не false success;
- outer clean-host preflight получил typed `--dependency-preflight-only`: безопасный code-10 APT refresh defer не блокирует переход к apply, но report использует консервативный `DEPENDENCY_GATE_PASSED_OR_REFRESH_REQUIRED`;
- добавлены `scripts/build-deploy.sh`, SBOM/provenance launcher, `channel-deploy-command`, exact hash-before-exec download command и `scripts/generate-deploy-command.sh`;
- README, Operations и Security синхронизированы с one-command, resume, exit-code и key-boundary contracts.

**Найдено и исправлено:**

- запуск key helper как root создавал бы `root:root 0600` secret, который основной `gateway-vpn` service не может читать; remote helper запускается строго через `sudo -u gateway-vpn`, а CLI отвергает root prepare/finalize;
- placeholder preflight ломал бы idempotent resume уже установленной пары; добавлен отдельный read-only inspect существующего/pending Gateway key до обеих role preflight;
- первый outer dry-run не принимал безопасный code-10 stale APT index, хотя последующий signed apply умеет refresh+re-simulation; введена отдельная честно именованная orchestrated dependency gate;
- разные SSH usernames позволяли указать один physical host для обеих ролей; host identity теперь сравнивается независимо от user и trailing dot;
- bounded writer первоначально продолжал бы бесконечно отбрасывать output после лимита; overflow теперь закрывает pipe ошибкой и останавливает command;
- заранее обязательный Admin public key не соответствовал zero-from-scratch; добавлен локальный pending/final admin config lifecycle без передачи private material.

**Проверено:**

- targeted tests покрывают обе preflight до apply, partial failure после Gateway, exact-key resume, `READY` и `INSTALLED_NOT_READY`, raw-key JSON redaction, same-host/option/symlink rejection, output limit, local admin key resume/idempotency и incompatible config refusal;
- bootstrap/distribution tests покрывают orchestrated code-10 continuation, non-interactive sudo, exact deploy hash-before-exec и оба admin modes;
- packaging tests проверяют deploy builder, SBOM/provenance, generated command и отсутствие private-key arguments;
- `go test ./... -count=1` — PASS для всех packages;
- `go vet ./...` — PASS;
- Linux/amd64 `CGO_ENABLED=0` builds `gateway-vpn`, `gateway-vpnctl`, `gateway-vpn-bootstrap`, `gateway-vpn-deploy` — PASS;
- `node --check internal/webapi/static/app.js` и Git Bash `bash -n scripts/*.sh test/netns/*.sh` — PASS;
- CLI test подписал synthetic channel с четырьмя roles и сгенерировал exact admin-config deploy command, в которой hash check предшествует launcher execution;
- любые Linux runtime пункты остаются отдельным `NOT_RUN`.

**Не выполнено и не считается PASS:**

- deploy binary ещё не собирался clean committed Linux builder-ом, channel не публиковался в GitHub, exact command не запускался на реальном административном Linux host;
- OpenSSH known-host enforcement, remote `sudo -n`, APT refresh/install, two-host interruption/resume и код `3` не проверялись с настоящими Gateway/VPS;
- WireGuard public derivation/config compatibility не сверялись реальным `wg`, handshake через HiLink не выполнялся, admin config не поднимался `wg-quick`;
- репозиторий по-прежнему без первого commit, поэтому production builder gates намеренно не обходились.

**Следующий шаг:** создать первый clean committed test release на Linux, загрузить immutable GitHub assets и выполнить двухмашинную preflight/apply/interruption/resume/reboot matrix; затем исправить фактические integration defects и перейти к nft/netns/hardware/endurance acceptance.

### Сессия 030 — Gateway clean-host install, persistent LAN и first-install recovery — 2026-08-25

**Сделано:**

- Gateway installer получил opt-in `--install-dependencies` с фиксированным allowlist `iproute2/nftables/wireguard-tools/kmod/procps/dnsmasq`, simulation `--no-install-recommends --no-remove --no-upgrade`, code-10 refresh continuation и повторный full preflight после package install;
- dependency flag проведён через `gateway-vpn-bootstrap`, `gateway-vpnctl channel-install-command` и channel builder;
- добавлен единый typed LAN validator для config/bootstrap/distribution/safe apply: private usable host CIDR `/16../30`, запрет public/CGNAT, network/broadcast и fixed WireGuard `10.80.0.0/24` overlap;
- новый read-only `gateway-vpnctl gateway-install-preflight` разбирает bounded JSON `ip address/route`, отклоняет пересечение requested transit LAN с любым другим host interface network или non-default route и допускает только exact kernel routes уже назначенного idempotent LAN;
- first-install использует общий root-owned lock, durable marker с десятью exact fields, root snapshots address/route/rule/nft и boot recovery helper/unit; broken symlink active marker не трактуется как отсутствие transaction;
- marker сохраняет прежние `net.ipv4.ip_forward`, IPv6 disable/forwarding, наличие LAN address, administrative link state и существование state root; recovery удаляет только owned table/files/units/release/address и архивирует marker после повторной проверки восстановленного state;
- добавлена persistent `/etc/systemd/network/70-gateway-vpn-lan.network`; initial install и safe network apply сохраняют requested CIDR после reboot, а safe apply snapshot/rollback включает networkd file и `networkctl reload`;
- installer загружает signed owned `PATH_BLOCKED` nft table до назначения LAN и включения IPv4 forwarding, затем проверяет active firewall/guard/control, nft table, exact LAN address, `ip_forward=1`, HTTPS listen и optional DHCP до `INSTALLED_NOT_READY`;
- systemd Gateway/VPS units при active или broken first-install marker допускают запуск только при ephemeral `root:root 0600` authorization живого installer; authorization удаляется recovery/uninstall и отсутствует после reboot;
- успешная transaction durable архивирует marker и обязательно отключает first-install recovery unit; при failure disable marker возвращается в active и обычный rollback остаётся возможен;
- idempotent Gateway install повторно проверяет signed release/config/firewall, exact persistent networkd/sysctl policy, trusted key, report, runtime services/table/API и disabled recovery unit;
- Gateway uninstall до mutation строго валидирует owner/mode/size/schema/unique fields/value completed marker, восстанавливает прежние forwarding/IPv6/LAN/link значения и удаляет report/networkd/WireGuard interface/owned nft table;
- Gateway/VPS installer и recovery получили дополнительные orphan/broken-marker/ephemeral-authorization checks; recovery helpers больше не скрываются systemd `ConditionPathExists`, которое могло не заметить broken symlink.

**Найдено и исправлено:**

- template config заменял только IP и сохранял `/24` при другом разрешённом prefix; теперь сначала заменяется полный CIDR;
- public, network/broadcast и management-overlapping LAN CIDR проходили часть bootstrap chain; validation унифицирована и покрыта negative tests;
- installer проверял выбранный interface, но не пересечение его новой подсети с другими host routes/interfaces; добавлен typed JSON preflight;
- transit LAN назначался только runtime-командой и исчезал после reboot; добавлен owned systemd-networkd policy и rollback persistence;
- Gateway не закреплял `net.ipv4.ip_forward=1`, поэтому router-mode не мог гарантированно пересылать Keenetic traffic; sysctl добавлен с сохранением/restore прежнего значения;
- первое включение forwarding происходило бы до загрузки fail-closed firewall; порядок изменён на `nft PATH_BLOCKED → LAN/sysctl → services`;
- Gateway installer/uninstaller не задавали `umask 077`, из-за чего новый transaction lock мог получить mode `0644` и тут же провалить собственную проверку `0600`;
- broken symlink active marker обходил install gate и systemd recovery condition; проверки используют одновременно `-e/-L`, recovery unit запускается без path condition, а application units имеют отдельный transaction gate;
- добавленный marker gate первоначально блокировал бы и самого живого installer; введён ephemeral authorization, который является trigger-alternative только во время текущей root transaction;
- completed marker uninstall ранее читался без exact schema/ownership/size checks; validation перенесена до destructive steps;
- first-install recovery unit оставался enabled после успеха; теперь disable является частью завершения, а его failure возвращает active marker и запускает rollback.

**Проверено:**

- `go test ./... -count=1` — PASS для всех packages;
- `go vet ./...` — PASS;
- Linux/amd64 `CGO_ENABLED=0` builds `gateway-vpn`, `gateway-vpnctl`, `gateway-vpn-bootstrap` — PASS;
- `node --check internal/webapi/static/app.js` — PASS;
- Git Bash `bash -n` всех 11 `scripts/*.sh`/`test/netns/*.sh` — PASS;
- targeted shell smoke до host access отклонил `8.8.8.8/24`, network/broadcast, `10.80.0.0/24` overlap и prefix `/15` с exit code `2`;
- package tests покрывают public/unsafe LAN rejection, address/route overlap, exact current kernel-route exception, networkd persistence/reload/rollback и transaction systemd gates.

**Не выполнено и не считается PASS:**

- installer/recovery/uninstall не запускались root на Ubuntu 24.04; syntax/unit tests не доказывают реальный APT, `ip -json`, systemd trigger conditions, networkd reload, nft syntax/apply, sysctl restore или reboot ordering;
- HTTPS readiness wait, first-install SIGKILL/power-loss recovery, DHCP, idempotent reinstall и uninstall restore не проверялись на Linux;
- новый IPv4 forwarding contract не заменяет packet-capture leak test: до hardware/netns gate статус остаётся `CODE_PASS / LINUX_NOT_RUN`;
- репозиторий всё ещё без первого commit, поэтому clean-tree release builders и реальный GitHub one-command не запускались.

**Следующий шаг:** реализовать typed SSH `gateway-vpn-deploy` с двухмашинным read-only preflight, signed role installation, локальным созданием private keys/public-key exchange и единым redacted readiness report; затем сделать первый commit/test release и выполнить реальные Ubuntu/VPS recovery/reboot gates.

### Сессия 029 — signed VPS role, safe dependencies и durable recovery — 2026-08-25

**Сделано:**

- добавлен отдельный signed VPS release contract/builder для exact `debian-12`, `ubuntu-20.04/22.04/24.04/26.04`, Linux/amd64, `wg-mgmt`, `10.80.0.0/24` и UDP/51821;
- `gateway-vpn-bootstrap`, `gateway-vpnctl`, channel manifest и command generator получили VPS role с обязательными endpoint, Gateway/Admin WireGuard public keys и опциональной политикой SSH forwarding;
- generated command сохраняет bootstrap во временный файл, скачивает его через HTTPS-only `curl` либо GNU `wget`, сверяет exact SHA-256 и лишь затем запускает напрямую как root либо через `sudo`;
- `install-vps.sh` выполняет signed-tree/profile/time/DNS/RAM/disk/dpkg preflight, проверяет public endpoint, kernel WireGuard, nft syntax, forwarding sysctls, UDP/51821, UFW/firewalld и конфликтующие owned paths;
- opt-in `--install-dependencies` определяет только отсутствующие `iproute2/nftables/wireguard-tools/kmod/procps/python3-minimal`, симулирует APT с `--no-install-recommends --no-remove --no-upgrade`, запрещает removal/upgrade/empty plans, обновляет indexes и повторяет simulation перед exact install;
- bootstrap различает полный `PASSED`, консервативный `DEPENDENCY_PLAN_VALIDATED` и специальный exit code `10`, разрешающий refresh только внутри apply-транзакции;
- Ubuntu 20.04 до package mutation требует установленный `ubuntu-advantage-tools`/`python3-minimal`, attached non-expired Pro, `esm-infra`/`esm-apps` и отсутствие pending updates; после refresh maintenance gate повторяется;
- VPS private key создаётся только локально после полного preflight; firewall разрешает только Admin `10.80.0.10 → Gateway 10.80.0.2` на 8443 и опционально 22, остальные peer-to-peer forwarding requests отклоняются;
- install/recovery/uninstall сериализованы `/run/lock/gateway-vpn-vps-install.lock`; durable marker хранит прежние forwarding sysctls и key-preservation flag, а boot recovery удаляет только owned table/units/files и проверяет восстановленное состояние до archival marker;
- обычный uninstall сохраняет `root:root 0600` `wg-mgmt.conf`; reinstall принимает ключ только после строгой проверки exact interface/address/port/peers/AllowedIPs/private-key canonicality;
- harmless root-owned `.active.tmp` до начала transaction классифицируется и удаляется только apply-фазой; WireGuard temp/`.current.new` без active marker считаются неизвестным partial state и не перезаписываются;
- idempotent existing install повторно проверяет signed release, immutable configs, active services, runtime public key/peers/AllowedIPs, routes и наличие owned nft table; завершение остаётся `INSTALLED_NOT_READY` до peer configuration и handshake;
- README, `OPERATIONS.md`, `SECURITY.md` и packaging/bootstrap/distribution tests синхронизированы с фактическим VPS contract.

**Найдено и исправлено:**

- изначально uninstall сохранял WireGuard key, но reinstall считал тот же файл конфликтом; добавлена строгая preserved-key ветка и recovery flag;
- recovery мог потерять active marker либо отключить собственный boot unit до завершения rollback; marker теперь переименовывается durable только после verified cleanup, self-disable выполняется последним;
- install/recovery/uninstall не имели общего transaction lock; добавлен один проверяемый `root:root 0600` non-blocking `flock`;
- Ubuntu 20.04 Pro gate первоначально выполнялся после managed package provisioning; перенесён до mutation и повторяется после index refresh;
- скрытая dependency-preflight фаза могла вернуть code 0 при невозможности построить APT plan и вызвать ложный `DEPENDENCY_PLAN_VALIDATED`; введён typed exit code `10`, остальные unsafe results блокируют apply;
- APT install plan запрещал removal, но мог обновить уже установленную dependency; добавлены `--no-upgrade` и явная проверка upgrade actions;
- generated VPS command безусловно требовал `curl`, `awk` и `sudo`, поэтому не работал в минимальной Debian root-shell; добавлены downloader fallback, hash extraction без `awk` и root-aware invocation;
- повторный запуск доверял `systemd active` без проверки фактических runtime peers/routes/table; добавлены read-only idempotency checks;
- recovery marker допускал лишние поля; добавлены size, exact field count, unique-key/schema и value checks.

**Проверено:**

- `go test ./... -count=1` — PASS для всех packages;
- `go vet ./...` — PASS;
- Linux/amd64 `CGO_ENABLED=0` builds `gateway-vpn`, `gateway-vpnctl`, `gateway-vpn-bootstrap` — PASS;
- `node --check internal/webapi/static/app.js` — PASS;
- Git Bash `bash -n` для всех `scripts/*.sh` и `test/netns/*.sh` — PASS;
- targeted bootstrap/distribution/CLI/packaging tests подтверждают split read-only/apply phases, code-10 continuation, rejection code-20 unsafe plan, dependency flag propagation, root/wget command contract, exact profiles, key preservation, owned recovery и transaction lock.

**Не выполнено и не считается PASS:**

- VPS release не собирался trusted Linux builder-ом и не публиковался в реальном GitHub Release, потому что репозиторий не имеет первого commit;
- installer, APT plan/install, Pro status parser, recovery/uninstall, systemd units, nft ruleset, WireGuard key/interface/route и reboot не запускались на Ubuntu/Debian;
- cloud/provider firewall UDP/51821, Gateway/Admin peer configuration, handshake и Web UI через `10.80.0.2:8443` не проверялись;
- package rollback намеренно отсутствует: успешно установленные OS packages остаются host state, даже если последующий application preflight завершится ошибкой;
- synthetic tests и cross-build дают статус `CODE_PASS / LINUX_NOT_RUN`, а не поддержку конкретного VPS provider.

**Следующий шаг:** реализовать typed SSH `gateway-vpn-deploy` с двухмашинным preflight, signed role installation, public-key exchange и end-to-end readiness report; затем перейти к первому committed GitHub test release и реальным Ubuntu/VPS gates.

### Сессия 028 — independent bootstrap, signed channel и installable Gateway artifact — 2026-08-25

**Сделано:**

- добавлен отдельно собираемый `gateway-vpn-bootstrap`, который не использует candidate binary для принятия решения о доверии;
- bootstrap закрепляет exact channel/version/source commit, raw manifest SHA-256 и Ed25519 public-key fingerprint, выбирает только exact role/platform artifact, сверяет signed bytes/hash/size и выполняет строгую extraction/release verification до installer;
- production downloader запрещает proxy, HTTP, credentials, fragments, literal IP/non-443, unlisted hosts и query в caller URL; GitHub signed query разрешён только внутри redirect на `objects.githubusercontent.com` или `release-assets.githubusercontent.com`;
- `build-release.sh` теперь создаёт `gateway-vpn-gateway-<version>-linux-amd64.tar.gz` и отдельный bootstrap, выводит SHA-256 обоих, а подписанный Gateway tree включает installer/uninstaller, config example, полный regular-file `packaging/`, docs и supply-chain metadata;
- initial installer копирует в `/opt/gateway-vpn/releases/v<version>` весь подписанный regular-file tree с executable modes и повторно выполняет `release-verify`, а не создаёт неполную выборку файлов;
- добавлены строгие channel manifest/roles `gateway`, `vps`, `deploy`, `bootstrap`, sorted uniqueness, exact filenames, OS/arch, media type, size/hash bounds и Ed25519 sign/verify;
- `gateway-vpnctl` получил `channel-sign`, `channel-verify` и `channel-install-command`; локальные artifact sources должны быть regular non-symlink files и хешируются с change-during-read guard;
- `scripts/build-channel.sh` требует clean committed tree, подписывает/проверяет channel public key и генерирует `install-gateway-<version>.command.txt` для exact immutable GitHub tag;
- generated command использует HTTPS-only `curl`, не pipe-to-shell, сверяет внешний bootstrap SHA-256 и только затем вызывает `sudo`; bootstrap получает все pin-ы и запускает сначала read-only installer preflight, затем отдельный `--apply`;
- README, Operations и Security синхронизированы с новым trust/distribution contract и фактическими именами artifacts.

**Найдено и исправлено:**

- исходная URL policy применяла запрет query также к GitHub Release redirect, поэтому настоящая загрузка с `release-assets.githubusercontent.com?...` не могла работать;
- старый release archive не содержал `scripts/install-gateway.sh`, `config.example.yaml` и `packaging/`, хотя bootstrap ожидал installer внутри authenticated tree;
- после добавления этих файлов старый installer продолжал копировать только binaries/docs, из-за чего installed tree не совпал бы с подписанным manifest; заменено exact full-tree copy;
- role validation принимала любое имя, лишь содержащее version; теперь каждому role соответствует единственное точное filename;
- generated command требовал разорвать bootstrap chicken-and-egg: hash bootstrap берётся только из уже локально проверенного signed channel и встраивается до публикации команды.

**Проверено:**

- `go test ./... -count=1` — PASS, включая bootstrap tamper/origin/query, signed channel, exact artifact, CLI sign/verify/command и packaging tests;
- `go vet ./...` — PASS;
- Linux/amd64 `CGO_ENABLED=0` builds `gateway-vpn`, `gateway-vpnctl` и `gateway-vpn-bootstrap` — PASS;
- `node --check internal/webapi/static/app.js` — PASS;
- Git Bash `bash -n` для build/install/uninstall/channel и netns scripts — PASS;
- отдельный CLI smoke создал временную Ed25519 identity, два synthetic role artifacts, подписал/проверил stable channel и сгенерировал 1228-символьную command; Git Bash принял её синтаксис (`PASS`), private key остался только в gitignored `.tools`;
- тест подтверждает, что caller-supplied asset URL с query отклоняется, а тот же query принимается только как allowlisted asset redirect; unsafe host/credentials/port/empty query отклоняются.

**Не выполнено и не считается PASS:**

- production `build-release.sh`/`build-channel.sh` не запускались из-за отсутствия первого commit и Linux trusted builder; synthetic `.tar.gz` в CLI syntax smoke не проверялся как release archive;
- реальная GitHub Release загрузка, redirect chain, CA/TLS, public asset upload и one-command dry-run/apply не выполнялись;
- clean Ubuntu 24.04 dependency installation пока не автоматизирована: generated command требует локальные `bash`, `curl`, `sha256sum`, `sudo`, а candidate installer пока только проверяет, но не устанавливает `ip/nft/wg/dnsmasq`;
- VPS role/archive/installer, Ubuntu 20.04+ и Debian profiles, WireGuard server configuration и SSH `gateway-vpn-deploy` отсутствуют;
- systemd/nft/ip/Mihomo/USB/Keenetic/hardware/endurance gates остаются `NOT_RUN`; host network текущей Windows-среды не изменялся.

**Следующий шаг:** реализовать VPS role artifact и `install-vps.sh` с exact OS profiles/rollback, затем dependency provisioning для чистых Gateway/VPS и typed SSH orchestrator. После этого выпустить первый immutable GitHub test release из committed Linux builder и выполнить реальный Ubuntu install/reboot/reject matrix.

### Сессия 027 — signed update, independent recovery и root transaction status — 2026-08-25

**Сделано:**

- реализован строгий release contract: SemVer 2.0.0 без leading-zero/empty identifiers, точная Mihomo version/hash, OS/arch, current/max DB schema, config и Gateway/Mihomo API contracts, Git SHA-1/SHA-256 commit и RFC3339 build date;
- `build-release.sh` требует существующий commit и чистый worktree, создаёт полный SHA-256 manifest и Ed25519 signature; staging проверяет trusted public key/fingerprint и immutable operation до изменения live state;
- tar.gz parser принимает ровно один gzip member с корректным footer/checksum, ограничивает archive/artifact/entry/path/depth/padding и запрещает traversal, duplicate, link/device и trailing/concatenated data;
- Web API получил bounded/rate-limited multipart upload, CSRF/audit, отдельные Stage/Apply/Discard и typed destructive confirmation; Apply сначала закрывает data path и фиксирует durable blocked state;
- root update повторно проверяет signed staging, запрещает переиспользование `releases/v<version>` другим artifact, запускает candidate offline compatibility check и миграцию копии SQLite;
- переключение DB и `/opt/gateway-vpn/current` оформлено durable state machine с verified pre-update snapshot, atomic rename/symlink, paired rollback и boot recovery каждого промежуточного состояния;
- до mutation создаётся независимый `/opt/gateway-vpn/recovery` на старый release; recovery/finalize units не зависят от candidate `current`;
- Linux update transaction защищена non-blocking `flock`; synthetic non-Linux lock покрывает concurrent tests;
- root journals, snapshots, lock и install/restore/network transactions перенесены под `/var/lib/gateway-vpn-privileged/*`, чтобы service UID не мог подменить journal через writable parent;
- после успешного health-check release остаётся `STABILIZING` 24 часа; periodic finalize проверяет здоровье также до deadline, затем фиксирует `FINALIZED`, а failure возвращает старую binary+DB pair;
- добавлен `gateway-vpn-update-resume.service`: `OnFailure` сначала перезапускает recovery unit и лишь затем возвращает broker socket/control plane; update unit перед mutation повторно загружает fixed boot firewall;
- update journal больше не считает `STABILIZING` terminal, предпочитает durable per-transaction copy stale `active.json` и восстанавливает одну повреждённую копию по второй для незавершённой транзакции;
- parameter-free root broker получил sanitized status read без path/snapshot/hash/systemd output; WebUI отдельно показывает staging и фактический `STABILIZING/FINALIZED/ROLLED_BACK/ROLLBACK_FAILED` outcome;
- installer/uninstaller, tmpfiles и packaging tests подключили update/recovery/finalize/resume units и отдельные privileged paths; OpenAPI, README, Operations и Security обновлены под фактический contract.

**Найдено и исправлено:**

- исходный recovery запускался через `current`, поэтому повреждённый candidate мог лишить систему самой программы rollback; введён отдельный old-release `recovery` pointer;
- `STABILIZING` ошибочно считался terminal, из-за чего потеря `active.json` могла скрыть живую rollback transaction;
- существующий version directory мог молча использоваться повторно без доказательства identical signed artifact;
- update apply/recovery/finalize могли стартовать одновременно из разных systemd процессов; добавлен межпроцессный lock;
- OnFailure первоначально мог вернуть management без гарантированного повторного recovery; resume теперь имеет строгий recovery-first ordering;
- update status в WebUI показывал только verified staging и после reconnect не сообщал реальный root outcome; добавлен независимый root-owned transaction status;
- первая локальная команда `gofmt` использовала устаревший путь `.tools/go/bin`; фактический pinned toolchain найден в `.tools/go1.26.7/go/bin`, после чего форматирование выполнено для 243 Go-файлов;
- старые preview-процессы занимали 18081/18082; новый build проверен на отдельном numeric loopback `127.0.0.1:18084` и остановлен после smoke test.

**Проверено:**

- `go test ./... -count=1` — PASS после update/recovery wiring; отдельный targeted gate `internal/networkapply`, `internal/webapi`, `test/webui-preview` — PASS после root transaction status;
- `go vet ./...` — PASS;
- Linux/amd64 `CGO_ENABLED=0` builds `gateway-vpn` и `gateway-vpnctl` — PASS;
- `node --check internal/webapi/static/app.js` — PASS;
- packaging tests подтверждают установку и ordering fixed update/recovery/finalize/resume units, boot firewall precondition и privileged tmpfiles paths;
- update tests покрывают signature/manifest/metadata/archive adversarial cases, staging, identical-artifact rule, lock, interruption каждого journal state, paired rollback, unhealthy stabilizing recovery и finalize health;
- in-app browser smoke с synthetic pending update и предыдущим `FINALIZED`: обе панели отображаются независимо, versions/state/timestamps видимы, console warnings/errors отсутствуют; destructive Apply/Discard не нажимались.

**Не выполнено и не считается PASS:**

- реальный Ubuntu 24.04 root запуск update/recovery/finalize/resume units, `systemd-analyze verify`, ownership/chown, update с фактическим Mihomo и reboot/power-cut interruption;
- реальный release не собирался: текущий репозиторий ещё не имеет первого commit и весь worktree untracked, тогда как builder намеренно требует clean committed Git state;
- первичная установка из GitHub пока не имеет независимого hash-verified bootstrap verifier: verifier внутри candidate artifact нельзя считать самостоятельным корнем доверия;
- VPS artifact/installer Ubuntu 20.04+, SSH orchestrator, nft/netns, WireGuard, Keenetic/HiLink, hardware и endurance gates остаются `NOT_RUN`.

**Следующий шаг:** независимый минимальный bootstrap verifier и signed GitHub role artifacts, затем one-command Gateway/VPS installers и SSH orchestrator. На первом доступном Ubuntu-стенде обязательно выполнить success/reject/rollback/reboot/power-cut update matrix до production-заявлений.

### Сессия 026 — mandatory bootstrap password, users/sessions и OpenAPI contract — 2026-08-24

**Сделано:**

- migration v11 добавила case-insensitive unique index для local usernames; login теперь выполняет `COLLATE NOCASE`, но возвращает каноническое сохранённое имя;
- реализован secret-free lifecycle локальных администраторов: list/create/rename/enable/disable/delete, Argon2id temporary passwords, запрет self-disable/self-delete, запрет отключения последнего enabled user и удаление только после disable + explicit confirmation;
- собственная смена пароля требует текущий пароль, запрещает повторное значение, снимает `must_change_password`, сохраняет только current session и отзывает остальные; administrative reset отзывает все target sessions и снова требует обязательной замены;
- active session API показывает только SHA-256 token digest, username и timestamps; любую сессию можно отозвать, включая текущую с очисткой browser cookie;
- middleware теперь серверно блокирует весь API временного bootstrap user, кроме `GET auth/session`, `PUT auth/password` и logout; это нельзя обойти прямым запросом вне WebUI;
- вкладка **Система и безопасность** получила формы создания пользователя, safe actions, password reset dialog, own-password form и таблицу активных сессий; обязательная bootstrap scene скрывает навигацию до успешной смены;
- добавлен `docs/openapi.yaml` OpenAPI 3.1 для всех 78 зарегистрированных methods, cookie/CSRF security, path/query/destructive parameters, auth schemas, backup/restore media types и единый error envelope;
- OpenAPI contract test извлекает реальные ServeMux registrations и требует точное совпадение методов/paths, уникальные `operationId`, documented CSRF для каждой mutation, разрешимые internal `$ref`, объявленные path parameters и корректные cookie/error components;
- `OPERATIONS.md`, `SECURITY.md` и README дополнены фактической моделью local admin/session и ссылкой на API contract.

**Найдено и исправлено:**

- `must_change_password` ранее был только информационным флагом: bootstrap user мог сразу вызвать любой защищённый endpoint;
- username uniqueness была case-sensitive, а login — exact-case, что позволяло неоднозначные `admin`/`Admin` identities при будущем CRUD;
- в API отсутствовали безопасные user/session identifiers и операции revoke/reset, хотя вкладка плана требовала users/sessions;
- после смены собственного пароля WebUI мог показывать уже отозванные другие sessions до ручного обновления; теперь security panel перечитывается;
- новая migration первоначально обнаружила жёсткие schema v10 ожидания в DB/backup/recovery/diagnostics tests; fixtures переведены на v11, а pre-migration test теперь реально моделирует v10 → v11.

**Проверено:**

- `go test ./... -count=1` — PASS;
- `go vet ./...` — PASS;
- Linux/amd64 `CGO_ENABLED=0` builds `gateway-vpn` и `gateway-vpnctl` — PASS;
- targeted `auth`, `webapi`, `db`, `backup`, `diagnostics` tests — PASS;
- OpenAPI route contract — PASS для 78 зарегистрированных methods;
- `node --check internal/webapi/static/app.js` — PASS;
- in-app browser normal synthetic scene — PASS: users/session tables, current-user destructive controls disabled, own password form и console без warnings/errors;
- in-app browser `--must-change-password` scene — PASS: navigation отсутствует, доступны только mandatory form/logout, console без warnings/errors; account creation и final password submit в browser не выполнялись, соответствующие mutations проверены API tests.

**Не выполнено и не считается PASS:**

- OpenAPI не запускался через внешний full semantic validator/code generator; собственный contract test проверяет структуру, security invariants, references и точный route parity, но generic schemas остальных domain endpoints ещё могут детализироваться;
- реальный Ubuntu 24.04 TLS bind, secure cookie в браузере по HTTPS, session persistence/revoke после service restart и filesystem-backed migration v10 → v11 не запускались;
- `systemd-analyze verify`, shell `bash -n`, nft/netns, Mihomo, WireGuard, VPS, Keenetic/HiLink и hardware/endurance gates остаются `NOT_RUN`.

**Следующий шаг:** signed update/atomic release rollback с pre-migration snapshot, DB/config/API-contract compatibility gate и автоматическим возвратом согласованной пары binary + DB; затем GitHub release installers и SSH zero-to-ready orchestrator.

### Сессия 025 — verified backup, corruption recovery и all-or-rollback restore — 2026-08-24

**Сделано:**

- реализован реальный SQLite Online Backup API со standalone DB без WAL/SHM, `quick_check`, полным `integrity_check`, `foreign_key_check`, schema/SHA-256 manifest и retention daily 7/manual 10/pre-* 5;
- startup выполняет read-only проверку live DB до writable open, quarantine повреждённых DB/WAL/SHM, durable blocked marker и восстановление только из самого нового повторно verified snapshot; без backup пустая DB не создаётся;
- `OpenManaged` централизует recovery, `pre-migration` snapshot, migration и final integrity, а шестичасовой worker создаёт не более одного daily snapshot за UTC-день;
- portable `.gvpn` включает verified DB, strict config, secrets, subscription payloads, TLS и Mihomo generation/state; применяется chunked AES-256-GCM с Argon2id `64 MiB / t=3 / p=2`, authenticated header/chunk index/final record и лимитами 256 MiB plaintext, 300 MiB artifact, 4096 файлов;
- restore upload потоковый и bounded: строгий multipart order, CSRF, passphrase 12–256 UTF-8 bytes, ZIP traversal/symlink/duplicate/size checks, manifest SHA-256, повторная SQLite/config verification, один durable pending и отсутствие upload/passphrase/plain ZIP после staging;
- trailing multipart после успешного consume компенсируется exact discard до audit; добавлен отдельный audited `DELETE` staged restore, чтобы неверно выбранный backup не создавал тупик;
- root `RestoreApplier` закрывает старый runtime, создаёт verified `pre-restore` snapshot, мигрирует candidate DB до schema binary, отзывает sessions, очищает login attempts, фиксирует `RESTORE_APPLIED`, заменяет config/DB/secrets/subscriptions/TLS/Mihomo state через same-filesystem candidates и удаляет stale Mihomo active;
- root-owned transaction journal и фиксированные candidate/rollback paths поддерживают reverse rollback при любой ошибке и recovery после имитированного power loss; pending очищается только после final config/SQLite/fail-closed verification;
- broker получил parameter-free `/v1/restore/apply`; fixed `gateway-vpn-database-restore.service` останавливает control/broker/socket/Mihomo/dnsmasq, повторно загружает boot `PATH_BLOCKED`, а resume unit возвращает только broker socket/control plane — Mihomo запускается лишь после reconciliation;
- WebUI показывает upload/passphrase form, verified pending metadata, полный SHA-256, typed `ВОССТАНОВИТЬ`, отдельные Apply/Discard, reconnect message и объяснение session revoke/reconciliation;
- bootstrap validation фиксирует Mihomo binary `/opt/gateway-vpn/current/libexec/mihomo` и secret/TLS paths внутри state directory; root host diagnostics больше не берёт executable из YAML.

**Найдено и исправлено:**

- исходный multipart handler не компилировался из-за неверной обработки `MultipartReader()` и мог оставить pending после запрещённой третьей части;
- mutable pending marker и `operation.json` могли разойтись при power loss между двумя atomic writes; immutable identity теперь сверяется, а более новый operation record остаётся authoritative;
- initial rollback reconstruction терял `OriginalExists` из journal и удалял ещё не затронутый `mihomo/active`; recovery теперь использует validated journal items;
- rollback после final SQLite verification мог оставить новые WAL/SHM рядом с возвращённой старой DB; delete-only originally-absent sidecars теперь удаляются;
- portable backup ранее мог создаться без Mihomo API secret/TLS cert/key и восстановить формально целую, но незапускаемую систему;
- restore config позволял произвольный absolute Mihomo executable, который root diagnostics мог выполнить.

**Проверено:**

- `go test ./... -count=1` — PASS;
- `go vet ./...` — PASS;
- `GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go test -c -o .tools/linux-tests/ ./...` — PASS;
- Linux/amd64 builds `gateway-vpn` и `gateway-vpnctl` — PASS;
- restore/stage/VerifyPending critical tests `-count=5` — PASS (`28.844s`);
- `node --check internal/webapi/static/app.js` — PASS;
- in-app browser smoke на disposable loopback preview — PASS для empty upload и synthetic verified pending scenes; DOM controls/layout/console проверены, реальные файлы не загружались и destructive buttons не нажимались;
- попытка `bash -n` через установленный WSL launcher — `NOT_RUN`: WSL вернул `E_ACCESSDENIED`, как и ранее.

**Не выполнено и не считается PASS:**

- реальный Ubuntu 24.04 root запуск restore/resume systemd units, ownership/chown, nft boot reload и restart ordering;
- restore на чистой установленной Gateway с фактическими `/etc` и `/var`, реальный reboot/power cut и проверка recovery journal после него;
- `systemd-analyze verify`, shell `bash -n`, nft/netns, Mihomo, WireGuard, VPS, Keenetic/HiLink и hardware/endurance gates.

**Следующий шаг:** OpenAPI/users и signed update/atomic release rollback; затем generated GitHub installers и SSH zero-to-ready orchestrator. При появлении Ubuntu-стенда первым integration gate выполнить restore success/failure/power-cut matrix до любых production-заявлений.

### Сессия 024 — bounded diagnostic bundle и топология 1..N — 2026-08-24

**Сделано:**

- добавлен `internal/diagnostics`: memory-only ZIP с фиксированными отсортированными entries, mode `0600`, запретом traversal/duplicates, лимитами 24 MiB uncompressed и 32 MiB archive;
- `manifest.json` содержит schema, полноту, redaction policy, section errors/warnings и SHA-256/размер каждого payload-файла; partial collection остаётся доступной со стабильными безопасными кодами;
- архив включает redacted config, gateway state, modems, subscriptions, nodes, path matrix, probe targets, Mihomo/WireGuard runtime, bounded events/journal, SQLite `quick_check`/`integrity_check` и host snapshot;
- root broker получил parameter-free `POST /v1/diagnostics/host`; collector запускает только фиксированные absolute команды, выбирает только owned routes/rules/nft table и исключает MAC, WireGuard keys и endpoint host;
- subscription payloads/URLs/secret refs, proxy credentials, target expected body, identity hashes, private/API keys и реальные WireGuard endpoints не читаются либо повторно redacts перед архивом;
- authenticated `GET /api/v1/gateway/diagnostics` описывает возможности, а CSRF-protected `POST /api/v1/system/diagnostics` без body создаёт attachment, ограничивает session тремя архивами за 10 минут и пишет audit event;
- WebUI во вкладке **Система и безопасность** показывает лимиты/секции и скачивает полный либо явно частичный архив с размером и SHA-256;
- план и operations уточнены для `1..N` модемов: один является штатной конфигурацией; при его отключении остаётся `PATH_BLOCKED`, два и более используют ту же модель priorities/matrix без отдельного режима; минимум два нужен только для стендовой проверки failover.

**Найдено и исправлено:**

- manifest section errors/warnings дедуплицированы по `section + code`, чтобы одна privileged ошибка не повторялась из нескольких слоёв;
- privileged/backend error text заменён стабильными кодами и не попадает ни в partial status entry, ни в manifest;
- host snapshot повторно валидирует typed IPv4/interface/WireGuard fields и повторно sanitizes owned route/rule/nft JSON, даже если root boundary уже выполнила фильтрацию;
- browser-инструмент не зарегистрировал synthetic blob download через `waitForEvent("download")`, но authenticated API вернул валидный attachment, а UI показал успешное создание; attachment headers/body отдельно покрыты unit test.

**Проверки:**

- `go test ./... -count=1` — PASS;
- `go vet ./...` — PASS;
- `GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build ./...` — PASS;
- `go test -count=5` для `diagnostics`, `logging`, `networkapply`, `webapi`, `app`, `platformexec`, `candidateruntime`, `db`, `config`, `test/packaging` — PASS;
- `node --check internal/webapi/static/app.js` — PASS;
- targeted tests `diagnostics`, `networkapply`, `webapi`, `app`, `test/webui-preview` — PASS;
- adversarial bundle test подтверждает отсутствие modem identity, subscription/proxy/target/event/journal/host secrets, реального WireGuard endpoint, API secret/private key; manifest size/digests и ZIP modes совпадают;
- API tests подтверждают auth/CSRF, запрет body `include_secrets`, attachment headers, audit, redacted backend error и rate limit `3/10min`;
- browser smoke показал diagnostic card, успешный API/UI result `Полный диагностический архив создан`, размер/SHA-256 и отсутствие console warnings/errors.

**Что не проверено и не считается готовым:**

- Windows WSL снова завершил `bash -n scripts/*.sh` ошибкой `Wsl/Service/CreateInstance/E_ACCESSDENIED`; shell syntax остаётся `NOT_RUN` до Linux/CI;
- реальные `/usr/sbin/ip`, `/usr/sbin/nft`, `/usr/bin/wg`, `/usr/bin/journalctl`, Ubuntu permissions/SO_PEERCRED и bounded host snapshot не запускались;
- архив ещё не проверен seeded canary secrets в реальном namespaced journal и host output;
- backup/restore/corruption recovery, OpenAPI, update rollback и signed zero-to-ready installers остаются следующими программными инкрементами;
- hardware/Mihomo/nftables/WireGuard/mobile traffic и 72-часовой endurance gates не изменились.

**Следующий шаг:** SQLite Online Backup API, verified daily/pre-migration snapshots и restore/corruption recovery; затем OpenAPI/update/release packaging и реальные Linux/hardware gates.

### Сессия 023 — retention convergence и bounded journal viewer — 2026-08-24

**Сделано:**

- migration v10 добавила singleton `logging_runtime` с desired/applied SHA-256 fingerprints, состояниями `UNKNOWN/PENDING/APPLYING/APPLIED/FAILED`, applied timestamp и стабильным безопасным error code;
- изменение logging settings атомарно переводит retention в `PENDING`, но сохраняет подтверждённый `APPLIED`, когда меняются только уровни, debug TTL, excerpt или aggregation и retention fingerprint остаётся прежним;
- root broker получил parameter-free `/v1/logging/sync`: значения не принимаются из HTTP/broker request, а повторно читаются root-процессом из SQLite;
- `JournaldSynchronizer` владеет только `/etc/systemd/journald@gateway-vpn.conf.d/retention.conf` и fixed unit `systemd-journald@gateway-vpn.service`; применяет файл atomic write + file/directory fsync, выполняет restart/`is-active`, а при failure восстанавливает прежний файл и повторно запускает namespace unit;
- control plane выполняет sync сразу после успешного PUT и отдельным минутным retry worker-ом для durable convergence после временной ошибки или reboot;
- broker получил typed `/v1/logging/query`, а production wiring использует только fixed `/usr/bin/journalctl`; произвольные executable, unit, namespace, output format и `journalctl` arguments не принимаются;
- journal reader всегда выбирает namespace `gateway-vpn`, JSON и newest-first ordering; page ограничена 25 результатами, scan — 129 records, subprocess output — 2 MiB, broker response — 64 KiB, time range — 31 днём, cursor — 256 safe chars;
- server-side allowlist поддерживает severity/component/modem/subscription/path/correlation/search; поля ID/unit/message дополнительно ограничены, malformed output отклоняется, а каждое сообщение повторно проходит redaction;
- authenticated `GET /api/v1/logs` отклоняет unknown query fields и ограничен 20 запросами в минуту на session с `Retry-After`;
- вкладка **Система и безопасность** показывает фактический retention state и технический журнал с time/severity/component/scope/correlation/text filters и keyset-загрузкой более старых страниц; ошибка journal reader не скрывает logging settings;
- packaging разрешает root broker писать только фиксированный journald drop-in и требует `journalctl`; synthetic preview получил две безопасные journal records для браузерной проверки.

**Найдено и исправлено:**

- URL redaction ранее удалял userinfo/query/fragment, но сохранял потенциально секретный path; теперь наружу остаётся только origin;
- общий process executor получил bounded stdout/stderr collector, который продолжает читать child pipes после достижения лимита и не создаёт deadlock на большом выводе;
- unsafe/symlink journald config directory теперь даёт stable failed state, а не оставляет неоднозначный runtime status;
- полный suite выявил календарно-зависимую fixture в `candidateruntime`: evidence было навсегда прибито к `2026-08-24 12:00 UTC` и после этого времени становилось stale; fixture переведена на текущие часы, два затронутых теста проходят 20 повторов.

**Проверки:**

- `go test ./...` — PASS;
- `go vet ./...` — PASS;
- `GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build ./...` — PASS;
- `go test -count=5` для `logging`, `networkapply`, `webapi`, `app`, `platformexec`, `candidateruntime`, `db`, `config`, `test/packaging` — PASS;
- два календарно-зависимых `candidateruntime` regression tests с `-count=20` — PASS;
- `gateway-vpn --check-defaults`, `--check-config config.example.yaml` и `node --check internal/webapi/static/app.js` — PASS;
- browser smoke на disposable numeric loopback показал retention cards/editor, две journal records, ровно одну строку после component filter `path_health` и отсутствие console warnings/errors;
- tests подтверждают apply/no-op/rollback/symlink rejection synchronizer-а, state preservation при level-only update, немедленный app retry, typed broker contracts, oversized output/response rejection и journal validation/pagination/redaction.

**Что не проверено и не считается готовым:**

- Windows `bash` снова перенаправлен в WSL и завершился `Bash/Service/CreateInstance/E_ACCESSDENIED`; `bash -n scripts/*.sh` остаётся `NOT_RUN` до Linux/CI;
- реальный `systemd-journald@gateway-vpn`, restart, persistent storage, rotation и disk/retention enforcement на Ubuntu не запускались; статус остаётся `JOURNALD_NOT_RUN`;
- release gate с canary secrets и фактическим чтением/redaction namespaced journal не выполнен;
- diagnostic bundle, OpenAPI и backup/restore ещё не реализованы; hardware/Mihomo/nftables/WireGuard/mobile traffic gates не изменились.

**Следующий шаг:** bounded redacted diagnostic bundle с manifest и audit, затем OpenAPI/backup/restore и signed GitHub zero-to-ready Gateway/VPS packaging; параллельно при появлении Linux-стенда выполнить journald canary gate.

### Сессия 022 — dynamic logging, pre-logger redaction и audit — 2026-08-24

**Сделано:**

- migration v9 добавила versioned default logging policy в единственный SQLite `settings` owner: global/component base levels, debug scope/deadline, retention, disk/excerpt limits и health error aggregation window;
- реализованы typed `logging.Repository` и `Controller`: strict JSON, диапазоны значений, unknown component rejection, atomic update + `LOGGING_SETTINGS_CHANGED`, debug recovery + `LOGGING_DEBUG_EXPIRED` и in-memory apply без process restart;
- permanent `DEBUG` удалён из bootstrap config contract; bootstrap допускает `INFO/WARN/ERROR`, а production debug включается только отдельным overlay на 5 минут–24 часа;
- controller запускается пятым cancellable worker, ждёт точного deadline, выключает debug в памяти даже при DB error и retry-ит durable cleanup; expired deadline очищается также при startup attach;
- централизованный `slog.Handler` выполняет component-aware filtering для `system`, `modem`, `path_health`, `subscription`, `mihomo`, `routing_firewall`, `wireguard`, `auth_audit`; audit floor остаётся `info` при любом global level;
- redaction выполняется до JSON/journald handler и покрывает record attrs, `WithAttrs`, groups, вложенные map/struct/slice, errors, URL userinfo/query/fragment, bearer/basic authorization, proxy URI, password/token/private/API keys, modem serial/identity hash, response body, payload/packet и полные sensitive configs;
- одинаковые warning/error записи `path_health` агрегируются в bounded in-memory map и следующая выпущенная запись получает `suppressed_repeats`;
- app callbacks размечены component logger-ами; startup logger использует тот же redacting handler до SQLite attach, затем controller атомарно подхватывает durable policy;
- authenticated `GET/PUT /api/v1/settings/logging` возвращает base/effective levels, доступные components, remaining debug TTL, retention/excerpt/aggregation и применяет изменения только с session+CSRF;
- вкладка **Система и безопасность** получила полный logging editor: общий/восемь component levels, auth floor, debug scopes+TTL, retention/disk/excerpt и aggregation;
- `CreateBootstrapAdmin`, invalid/rate-limited/successful `Login` и `Revoke` теперь пишут обязательные SQLite auth events в той же transaction; failed username представлен digest-ом, password отсутствует;
- все восемь service units помещены в `LogNamespace=gateway-vpn`; installer устанавливает persistent/compressed/sealed namespace default 14 дней, 256 MiB system/64 MiB runtime и удаляет drop-in при uninstall;
- `OPERATIONS.md`, `SECURITY.md` и example config обновлены под фактический contract и честный pending state privileged retention sync/journal reader.

**Найдено и исправлено:**

- первый browser smoke открыл fallback placeholder с `Cannot read properties of null (reading 'includes')`: clone пустого `debug_components` превращал non-nil `[]` в JSON `null`; clone теперь всегда сохраняет array contract, добавлен regression assertion;
- первая формулировка могла создать впечатление, что WebUI уже применяет root journald limits. На тот момент API/UI явно возвращали `DESIRED_STORED_INSTALLER_DEFAULT_ACTIVE`, а privileged runtime sync оставался следующим инкрементом; текущий state contract заменён сессией 023;
- `bash -n` installer scripts снова не запустился: Windows перенаправил `bash` в WSL и получил `Bash/Service/CreateInstance/E_ACCESSDENIED`. Это записано как непроверенный Linux gate, а не скрыто успешными string tests.

**Проверки:**

- `go test ./...` — PASS;
- `go vet ./...` — PASS;
- `GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build ./...` — PASS;
- `node --check internal/webapi/static/app.js` — PASS;
- `gateway-vpn --check-defaults` и `--check-config config.example.yaml` — PASS;
- `go test -count=5` для `logging`, `auth`, `webapi`, `app`, `db`, `config`, `test/packaging` — PASS;
- redaction tests проверяют отсутствие plain/nested/WithAttrs passwords, subscription/query tokens, bearer secret, proxy URI credentials, modem identity, response body и сохранение безопасного certificate SHA-256;
- controller tests подтверждают TTL range, component isolation, audit floor, автоматическое expiry timer-ом, restart recovery и два обязательных settings events;
- auth tests подтверждают transaction-bound bootstrap/login/rate-limit/logout events и отсутствие test passwords в `details_json`;
- API tests подтверждают authentication, CSRF, effective debug только выбранного component, 300-секундный TTL, audit event и отказ permanent debug;
- packaging tests подтверждают namespace и bounded defaults во всех service units;
- повторный browser smoke на disposable numeric loopback показал logging cards/form, восемь scopes, auth select только `inherit/info`, TTL 5–1440 минут и отсутствие console warnings/errors.

**Что не проверено и не считается готовым:**

- `systemd` не разбирал units, `systemd-journald@gateway-vpn` не запускался, реальный JSON output/retention/disk rotation не наблюдался; статус остаётся `JOURNALD_NOT_RUN`;
- на момент завершения этой сессии WebUI retention был только durable desired setting и действовал installer default 14 дней/256 MiB; parameter-free root sync добавлен следующей сессией 023;
- на момент завершения этой сессии bounded `journalctl` reader и server-side filters/keyset pagination/rate limit отсутствовали; они добавлены сессией 023, diagnostic bundle всё ещё отсутствует;
- redaction доказан adversarial unit tests, но release gate дополнительно требует реальный journal scan на Ubuntu с seeded canary secrets;
- hardware, Mihomo, nftables, WireGuard и mobile traffic gates этой сессией не затрагивались.

**Следующий шаг на тот момент:** restricted root retention sync и bounded namespaced journal reader/API/UI filters; выполнено сессией 023. Canary integration test, diagnostic bundle/OpenAPI/backup остаются впереди.

### Сессия 021 — periodic health, hysteresis и target-outage suppression — 2026-08-24

**Сделано:**

- migration v8 добавила `path_health_runtime` с durable `ACTIVE/STANDBY`, next/last probe, последним результатом, success/failure streak и причиной budget deferral; schedule каскадно удаляется вместе с path;
- `PeriodicRepository` создаёт расписания для всей матрицы, немедленно переклассифицирует path после смены active tuple, выдаёт due paths с ACTIVE-first ordering и сохраняет streak между process restarts;
- `DEFERRED_BUDGET` теперь не пишет `last_probe_at`, не увеличивает failure streak и не меняет authoritative path/node/target evidence; operation errors также переносятся как явная отсрочка, а не ложный сетевой failure;
- qualifier получил отдельный exhaustive mode, позволяющий outage-confirmation проверить остальные required targets после первого отказа, не меняя обычный fail-fast contract;
- `PeriodicRunner` выполняет дешёвые diagnostic active probes, публикует evidence только после настраиваемого success/failure hysteresis, использует отдельные ACTIVE/STANDBY/FAILOVER scheduler classes и считает confirmation probes/deferred attempts;
- active transport/node failure после threshold запускает обычную authoritative qualification и reconciliation; failed/stale path не активируется обходным путём;
- required-target failure сначала квалифицирует bounded набор standby combinations; `TargetOutageEvaluator.EvaluateWithObservation` добавляет ещё не опубликованное exact active observation и разрешает suppression только после независимых modem/subscription thresholds;
- при подтверждённом общем outage exact active node сохраняется в path state `DEGRADED`, Gateway переходит в `DEGRADED_TARGET`, firewall/Mihomo tuple не меняется; fresh success того же exact node возвращает `ACTIVE` через reconciler без повторной actuator activation;
- production runtime запускает periodic runner как четвёртый cancellable worker рядом с refresh, modem и reconcile loops; cycle/error summaries передаются structured logger-у;
- добавлен authenticated `GET /api/v1/health/periodic`: redacted path schedule, cadence/hysteresis config, immutable scheduler limits и агрегированный дневной расход bytes/requests по каждому модему;
- вкладка **Состояние и события** показывает active/standby cadence, thresholds, `DEFERRED_BUDGET`, следующую попытку, per-modem probe budget и прежний audit/event stream; synthetic preview содержит PASSED, UNKNOWN и DEFERRED расписания.

**Найдено и исправлено тестами:**

- migration suite ещё ожидал schema v7; ожидание обновлено до v8 и повторная migration подтверждает ровно восемь checksummed записей;
- первая версия budget deferral ошибочно обновляла `last_probe_at`, хотя scheduler не выполнил сетевой probe; поле теперь сохраняет время последней фактической попытки;
- первые cycle counters не включали outage-confirmation probes; runner теперь отдельно учитывает все выполненные и отложенные confirmation operations;
- suppression без `TARGET_SUSPECT` специально отклоняется path repository; отдельный reconciler test подтверждает строгий режим при недостатке независимых observations.

**Проверки:**

- `go test ./...` — PASS;
- `go vet ./...` — PASS;
- `GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build ./...` — PASS;
- `node --check internal/webapi/static/app.js` — PASS;
- `go test -count=5` для `health`, `candidateruntime`, `pathmatrix`, `state`, `reconcile`, `scheduler`, `webapi`, `app`, `db` — PASS;
- repository tests подтверждают restart-safe streak, ACTIVE/STANDBY role reset, availability filtering, cascade cleanup и budget deferral без ложной попытки;
- runner tests подтверждают success/failure thresholds, restart между failures, неизменность standby evidence при budget exhaustion, normal transport failover и target-wide suppression по четырём независимым combinations;
- reconciler test подтверждает strict rejection до target classification, стабильный exact `DEGRADED_TARGET` и recovery без второй actuator activation;
- browser smoke на disposable numeric-loopback preview подтвердил четыре path schedules, разные cadence, один `DEFERRED_BUDGET`, budget usage двух модемов и отсутствие console warnings/errors.

**Что не проверено и не считается готовым:**

- tests используют fake Mihomo/controller/routing и synthetic target responses; фактические scheduler bytes, mobile operator rate/latency, real target outage и live failover не измерялись;
- Linux worker lifecycle, systemd cancellation, real Mihomo listener, nft gate, marked sockets, DNS/IPv6 leak и packet capture остаются `LINUX_NOT_RUN`;
- hardware gate с двумя HiLink-модемами разных подсетей и операторов не запускался; cross-build не повышает его статус;
- UI/API показывают runtime health, но production logging settings, journald reader, diagnostic bundle и OpenAPI ещё не реализованы.

**Следующий шаг:** production logging foundation по `DEV-049` — централизованный redacting handler, per-component dynamic levels/debug TTL, durable settings/audit API и WebUI; затем bounded journald reader/diagnostic bundle и OpenAPI.

### Сессия 020 — exact path operations, lazy evidence и deployment requirements — 2026-08-24

**Сделано:**

- добавлены synchronous manual operations `ProbeNode`, `QualifyNode` и `QualifyPath`, которые всегда rebuild/apply полного active-LKG Mihomo bundle и проверяют точный modem routing context;
- диагностический node probe после проверки восстанавливает предыдущую generation и сохраняет только audit event, не меняя `path_nodes`, aggregate cell или active tuple;
- `StoreNodeQualification` атомарно upsert-ит один node/его target evidence, сохраняет свежих peers текущей generation и пересчитывает best node/counters/expiry без искусственного продления чужого evidence;
- state repository получил exact-node activation methods; actuator больше не требует, чтобы ручной node совпадал с автоматическим `selected_node_id`, но по-прежнему требует active LKG, enabled candidate, current generations и future expiry;
- reconciler сериализует automatic/manual activation, валидирует exact active node и не возвращает ручной выбор к aggregate-best на следующем цикле;
- добавлены authenticated API для path qualification, exact node probe/qualification/activation, node pages и lazy target pages; failed/stale activation возвращает `NODE_NOT_FRESH` до data-plane mutation;
- read models помечают evidence `STALE` при policy/route mismatch либо expiry; target keyset следует priority+ID, node keyset — stable node ID, page limit ограничен `1..200`;
- вкладки **Матрица путей** и **VPN-серверы** получили exact operations, paginated dialog и ленивые target details; synthetic preview содержит реальное current-generation evidence;
- по новому требованию пользователя план расширен signed GitHub zero-to-ready deployment: отдельные role artifacts, one-command local installs и единый SSH orchestrator для Gateway+VPS с full preflight/readiness/rollback;
- Gateway target остаётся Ubuntu 24.04; VPS support matrix расширена на Ubuntu LTS 20.04/22.04/24.04/26.04 и Debian 12+, причём Ubuntu 20.04 требует активного ESM/security coverage.

**Проверки:**

- `go test ./...` — PASS;
- `go vet ./...` — PASS;
- `GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build ./...` — PASS;
- `node --check internal/webapi/static/app.js` — PASS;
- `go test -count=5` для `state`, `reconcile`, `pathmatrix`, `candidateruntime`, `pathruntime`, `webapi` — PASS;
- browser smoke на disposable loopback preview подтвердил Matrix dialog, свежий `BYPASS_QUALIFIED`, lazy target rows, exact diagnostic response и отсутствие console warnings/errors.

**Что не проверено и не считается готовым:**

- операции выполнялись через fake Mihomo/controller/routing adapters и synthetic browser runtime; реальный Linux TUN, nftables, marked sockets и mobile targets остаются `LINUX_NOT_RUN`;
- GitHub Release pipeline, VPS installer, ESM detection, joint SSH deploy, reboot/end-to-end readiness и rollback ещё не реализованы; они только стали обязательным зафиксированным scope;
- Ubuntu 20.04/22.04/24.04/26.04 VPS fixtures и Ubuntu 24.04 Gateway не запускались; support status пока не может быть `PASS`;
- emergency override для failed/stale node намеренно отсутствует; обычная ручная активация остаётся строго fresh-qualified.

**Следующий шаг:** periodic health orchestration с active reserve/standby cadence и target-outage suppression в failover decision, затем OpenAPI/diagnostics/backup и zero-to-ready release tooling.

### Сессия 019 — durable VERIFYING_POLICY grace и target-state orchestration — 2026-08-24

**Сделано:**

- migration v7 добавила в singleton `runtime_state` durable `policy_transition_generation`, `started_at` и `deadline`; insert/update triggers допускают только полностью пустой transition либо полный `VERIFYING_POLICY + PATH_ACTIVE + active tuple` с положительной generation и возрастающим deadline;
- `InvalidatePathPolicy` теперь в той же transaction выделяет generation, начинает или перезапускает 120-секундный grace для активного tuple, сохраняет `POLICY_VERIFICATION_STARTED` и затем инвалидирует path evidence; для blocked/boot состояния transition не создаётся;
- state repository получил `FinishPolicyVerification`: тот же active node завершает transition только при свежем `BYPASS_QUALIFIED` evidence новой generation и неизменном route context, без изменения firewall/config generation;
- `RecoverPolicyTransition` на startup очищает active tuple, увеличивает config generation и записывает `POLICY_VERIFICATION_INTERRUPTED`; приложение выполняет recovery до обычного `DATA_PLANE_NOT_YET_OBSERVED`, поэтому restart не продолжает старую policy;
- observer теперь проверяет не только active path group, но и точное имя выбранного active node из текущей LKG; несовпадение становится `MihomoReady=false`, а не принимается как рабочий путь;
- qualifier получил `PreferredNodeID`: active node проверяется отдельно первым; его успех немедленно закрепляет cell без проверки более быстрых standby nodes, а failure открывает bounded parallel pass оставшихся candidates;
- если matcher/manual override исключил active node, runtime сохраняет его первым в normal provider payload только на grace, но `loadActive`/qualification оставляют candidate pool пустым или состоящим только из разрешённых replacements; active traffic поэтому не меняется скрыто при bundle reload;
- reconciler различает `POLICY_VERIFICATION_PENDING`, `POLICY_VERIFIED`, replacement activation и expiry: тот же node не реактивируется, replacement проходит обычный block/select/reverify/open flow, отсутствие результата либо required targets закрывает путь после deadline;
- удаление последнего required target теперь действительно использует подтверждённый grace, затем становится `NO_BYPASS_TARGETS`; modem/Mihomo/TUN/observed tuple failures по-прежнему блокируют немедленно и не ждут policy deadline;
- Web API requalification проверяет active modem первым, после probes немедленно вызывает reconciliation и возвращает `VERIFYING_POLICY`, если transition ещё продолжается; dashboard API/UI показывает generation, deadline и оставшиеся секунды;
- `TargetOutageEvaluator` запускается после сохранения qualification evidence, переводит первый доказанный observation из `UNKNOWN` в `NORMAL`, определяет `TARGET_SUSPECT` только по независимым modem/subscription combinations и пишет `TARGET_STATE_NORMAL`, `TARGET_OUTAGE_SUSPECTED`, `TARGET_OUTAGE_RECOVERED`;
- `OPERATIONS.md` и `SECURITY.md` получили runbook policy grace, restart semantics и разделение active/probe/grace-only selectors.

**Проверено:**

- migration suite подтверждает schema version 7, idempotence/checksums и отклонение partial runtime transition trigger-ом;
- state test подтверждает ровно 120 секунд между start/deadline, отказ commit на stale evidence, успешный same-node commit без новой config generation и restart recovery с очищенным tuple/event;
- reconciler tests подтверждают pending без actuator calls, same-node `POLICY_VERIFIED` без reactivation, verified replacement activation и grace→`NO_BYPASS_TARGETS` после удаления последнего required target;
- runtime test подтверждает, что manual-excluded единственный active node остаётся в generated provider bundle, но cell получает `CandidateNodes=0`, `FAILED` и transition не завершается преждевременно;
- qualifier tests подтверждают preferred-node short circuit и fallback на оставшиеся candidates после его failure;
- target evaluator tests подтверждают initial `NORMAL`, cross-modem/subscription `TARGET_SUSPECT`, recovery и три соответствующих event types; CandidateRuntime test подтверждает реальный post-qualification вызов evaluator;
- core state/reconcile/runtime/health suites выполнены с `-count=5` — PASS;
- полный `go test ./...` — PASS;
- полный `go vet ./...` — PASS;
- `GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build ./...` — PASS;
- `node --check internal/webapi/static/app.js` — PASS.

**Не реализовано / не проверено:**

- реальный Mihomo reload должен подтвердить сохранение exact selector и отсутствие краткого переключения на первый provider node; текущие generator/runtime tests не заменяют `mihomo -t`, API observation и packet capture;
- 120-секундный deadline контролируется пятисекундным reconciliation loop, поэтому фактическое закрытие ожидается не позже следующего cycle; systemd restart/reboot recovery пока проверен repository/app wiring, но не реальной Ubuntu загрузкой;
- migration v7 не применялась к сохранённой production v6 DB на Ubuntu и её triggers не проходили power-cut/checkpoint test;
- aggregate target classifier и events подключены, но полная outage suppression для уже активного path и periodic health scheduler ещё не завершена; `TARGET_SUSPECT` пока не разрешает использовать failed evidence как qualified;
- адресные node/path probe/qualify/activate, lazy target-result matrix и pagination/virtualization остаются следующими пунктами;
- Ubuntu/systemd/Mihomo/netns/два HiLink/Keenetic gates не запускались и остаются `NOT_RUN`.

**Следующий шаг:** адресные node/path operations и lazy target evidence API/UI, затем periodic active/standby health с полной target-outage suppression; при появлении Ubuntu host выполнить migration v6→v7, Mihomo reload/selector observation и packet capture.

### Сессия 018 — строгая target policy, isolated body probe и полный WebUI lifecycle — 2026-08-24

**Сделано:**

- добавлен единый target-policy validator для create/update: name/URL/timeout, допустимые success modes, UTF-8 body marker до 256 bytes и согласованность полей; `any_http_response` больше не сохраняет stale expectations;
- status expressions принимают одиночные коды, диапазоны и списки с `/` или `,`, проверяют границы `100..599`, порядок/пересечения и сохраняются канонически, например `302, 200-299` → `200-299/302`;
- bootstrap config получил `mihomo.probe_address` с безопасным default `127.0.0.1:17890`; generator создаёт loopback-only mixed listener `gateway-vpn-probe-in`, global selector `gateway-vpn-probe` и отдельную `probe-path-*` selector group на каждый normal/shadow path;
- probe-группы используют тот же provider с modem-specific `interface-name`/`routing-mark`, но не совпадают с группами active data path; body check поэтому не меняет selection живого пользовательского пути;
- реализован сериализованный `BodyProbe`: exact node select → exact probe path select → новый HTTPS request через фиксированный local proxy; proxy environment не используется, keep-alive отключён, TLS verification остаётся штатной, redirects ограничены тремя и повторно проходят public-target validation;
- тело ответа ограничено 64 KiB, фактический HTTP status сохраняется в evidence, а failures различают `STATUS_MISMATCH`, `BODY_MISMATCH`, `BODY_LIMIT_EXCEEDED`, TLS/listener/selector/read errors;
- qualification runtime теперь принимает `expected_body`, передаёт isolated group identity и body marker; scheduler резервирует увеличенный traffic estimate для content probes; path activation повторно проверяет required body target при закрытом TUN gate до `ActivatePath`;
- repository атомарно запрещает update, disable или delete последнего enabled required target без explicit confirmation; rejected transaction не меняет объект или policy generation;
- все target mutations — create/update/enable/disable/delete/reorder — инвалидируют generation и запускают requalification ready-модемов; добавлен `POST /api/v1/bypass-targets/{id}/probe` с честным scope `ALL_ELIGIBLE_PATHS`;
- вкладка **Серверы проверки доступа** получила полный create/edit, enable, required, timeout, `any/status/body` fields, priority ↑/↓, manual probe и подтверждённое удаление; условие успеха показывается в списке без потери канонического status;
- browser smoke обнаружил пустой API list как `null`; repository теперь гарантирует `items: []`, поэтому empty state стабилен.

**Проверено:**

- status parser tests: canonical ordering, single/range/list matching, invalid/overlap/duplicate/reversed/out-of-range rejection;
- repository tests: одинаковая create/update validation, optional status + required body, rejected stale fields, atomic last-required confirmation и non-nil empty list;
- body-probe tests: точные selector calls, status+body success, status mismatch, 64 KiB limit, non-loopback listener rejection и maximum concurrency `1`;
- generator tests: отдельные active/probe groups для normal и qualification-shadow paths, probe listener `127.0.0.1:17890`, shadow отсутствует в active selector и присутствует в probe selector;
- pathruntime test подтверждает required `expected_body` recheck через `StablePathNames.ProbeGroupName` до открытия firewall и отсутствие fallback к обычному delay check;
- Web API lifecycle test подтверждает canonical response, CSRF, requalification после каждой успешной mutation/manual probe и `409 CONFIRM_LAST_REQUIRED_TARGET` без подтверждения;
- disposable browser smoke-test подтвердил empty state, создание `expected_body`, поля editor, отображение `HTTP 200-299/302 + body`, manual probe и отсутствие console errors; destructive accept проверен API-тестом, нативное browser confirm в smoke было только открыто и не применялось;
- полный `go test ./...` — PASS;
- полный `go vet ./...` — PASS;
- `GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build ./...` — PASS;
- `node --check internal/webapi/static/app.js` — PASS.

**Не реализовано / не проверено:**

- generated listener/groups не проходили `mihomo -t` на закреплённом production binary и реальный CONNECT/HTTPS request через два modem marks; configuration/API semantics остаются `LINUX_NOT_RUN` до этапа 0;
- packet capture пока не доказывает отсутствие direct path, DNS leak и принадлежность body response точному modem/operator; unit tests доказывают selection contract, но не внешний runtime;
- существующий `TargetOutageEvaluator` ещё не запускается как обязательный post-qualification orchestration step, поэтому aggregate target state может оставаться `UNKNOWN`; lazy matrix `target × modem × subscription × node` также ещё не выведена в UI;
- manual target probe сейчас безопасно перепроверяет полную enabled policy на всех eligible paths; отдельный bounded single-target diagnostic с сохранением non-authoritative результата ещё не реализован;
- durable 120-секундный `VERIFYING_POLICY` grace, reboot recovery этой generation и адресные node/path probe/qualify/activate остаются следующими обязательными пунктами;
- Ubuntu/systemd/Mihomo/netns/два HiLink/Keenetic gates не запускались и не считаются выполненными.

**Следующий шаг:** durable policy grace и target-outage orchestration, затем адресные node/path operations и lazy target-result UI; после появления Ubuntu host обязательно выполнить Mihomo config validation, netns firewall suite и hardware packet capture.

### Сессия 017 — active node inventory, matcher preview и manual overrides — 2026-08-24

**Сделано:**

- migration v6 добавила `nodes.matched_matcher_id`, поэтому inventory объясняет не только `NAME_MATCH`, но и конкретное правило, определившее candidate;
- создан active-node repository: возвращает только узлы текущих LKG, subscription identity, proxy type, candidate source, manual override и status узла через каждый modem; fingerprint и proxy config/credentials не выходят в API;
- matcher create/update/delete/reorder теперь внутри одной transaction переклассифицируют все active-version nodes, обновляют `enabled/candidate_source/matched_matcher_id`, затем выделяют новую global policy generation и инвалидируют старые evidence;
- full prospective matcher set компилируется до commit: лимит 32 enabled regex проверяется на совокупности, а invalid RE2 отклоняется даже у disabled matcher;
- добавлен read-only `POST /api/v1/node-matchers/preview`: показывает candidate/filtered/excluded counts и каждую node по активным подпискам;
- regex create/update без актуального preview token возвращает `MATCHER_PREVIEW_REQUIRED`; token HMAC-привязан к предложению, текущим matchers и preview активного inventory, а server secret существует только в памяти процесса;
- `GET /api/v1/nodes` и CSRF-protected `PATCH /api/v1/nodes/{id}` реализуют redacted inventory и `auto/include/exclude`; override переносится по fingerprint при следующем refresh, создаёт audit event и запускает requalification ready-модемов;
- policy-only `ReclassifyOne` больше не скачивает подписку через мобильный uplink: он читает локальный immutable LKG payload, выполняет обычный staging/qualification/LKG flow и сохраняет ETag/Last-Modified;
- WebUI вкладка **Правила отбора серверов** получила CRUD, enable, reorder, обязательный preview dialog по подпискам и expandable node list; вкладка **VPN-серверы** показывает candidate decision, matched rule, manual override и статусы через модемы.

**Проверено:**

- repository test подтверждает read-only preview, atomic смену candidate pool после matcher update, matched matcher attribution, manual include и `NODE_OVERRIDE_CHANGED` audit;
- API test подтверждает redaction node inventory, отказ regex без preview, выдачу/применение token, requalification call и manual exclude;
- reclassification test подтверждает отсутствие дополнительного HTTP/mobile fetch и сохранение conditional-cache metadata;
- disposable browser smoke-test показал четыре active nodes для двух подписок, противоположные `NAME_MATCH/NAME_FILTERED` decisions, modem statuses и regex preview `2 candidates / 0 filtered` после объединения действующего LTE matcher с предлагаемым ordinary regex; console errors отсутствовали;
- полный `go test ./...` — PASS;
- полный `go vet ./...` — PASS;
- `GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build ./...` — PASS;
- `node --check internal/webapi/static/app.js` — PASS.

**Не реализовано / не проверено:**

- предусмотренный планом 120-секундный `VERIFYING_POLICY` grace как durable state machine ещё не реализован; mutation инвалидирует evidence и синхронно пытается перепроверить ready-модемы, поэтому этот пункт не считается закрытым;
- адресные `POST /nodes/{id}/probe|qualify`, lazy target-result details, pagination/virtualization и path manual operations ещё отсутствуют;
- реальный Mihomo bundle rebuild и probes после matcher/override mutation не запускались на Ubuntu/модемах; browser preview использовал synthetic runtime;
- migration v6 не проверялась на сохранённой production v5 DB под Ubuntu; Linux/hardware status остаётся `NOT_RUN`.

**Следующий шаг:** завершить target success policy (`expected_status`, bounded `expected_body_substring`, update/enable/reorder/manual probe), затем вернуться к durable policy grace и адресным node/path operations.

### Сессия 016 — полный lifecycle подписок и браузерная проверка WebUI — 2026-08-24

**Сделано:**

- добавлена migration v5: существующим подпискам назначаются постоянные монотонные `display_number`, counter продолжает последовательность после удаления, unique index и insert/update triggers запрещают `NULL`;
- repository подписок получил audit-backed update, enable/disable, exact-set priority reorder и delete только для disabled/non-active объекта; порядок выдачи детерминирован номером;
- Web API получил CSRF-protected create/update/enable/disable/reorder/delete endpoints; URL сохраняется atomic secret file и никогда не возвращается DTO, normalized payload tree удаляется вместе с подтверждённо отключённой подпиской;
- validation выполняется до записи нового URL, поэтому некорректный PATCH не оставляет частично применённый secret;
- смена fallback-policy без нового URL запускает `ReclassifyOne`, смена URL запускает полный forced refresh, enable с LKG запускает проверку через все ready-модемы;
- отключение активной подписки или модема сначала закрывает root TUN gate, затем немедленно очищает active tuple в SQLite и только после этого меняет enabled state; `state.Block` теперь также восстанавливает half-cleared blocked tuple;
- вкладка **Подписки** получила создание, редактирование без раскрытия текущего URL, auto-refresh/fallback settings, стабильный номер, приоритеты ↑/↓, enable/disable, refresh и подтверждённое delete;
- для каждой подписки показано состояние через каждый настроенный модем, включая offline/stale/failed cells; те же modem×subscription данные остаются каноническими для вкладок **Модемы** и **Матрица путей**;
- добавлен loopback-only disposable `test/webui-preview`: он использует synthetic data/session, не запускает production workers и не меняет host network;
- визуальная проверка обнаружила, что `.login-shell { display:grid }` переопределяет HTML `hidden`; добавлено `[hidden]{display:none!important}`, после чего login view имеет нулевую высоту, а приложение и modal editor отображаются без наложения.

**Проверено:**

- полный lifecycle `httptest`: create вызывает refresh, API не раскрывает URL/path, invalid PATCH не меняет secret, fallback update вызывает reclassification, active disable блокирует путь до DB mutation, delete требует disabled+confirmation и удаляет secret/payload;
- migration v5 отклоняет запись без номера; repository test подтверждает, что номер удалённой подписки не переиспользуется;
- browser smoke-test на disposable loopback preview подтвердил вкладку, две подписки × два модема, disabled priority/delete controls, create form и modal editor; computed layout после исправления: hidden login `display:none`, height `0`;
- полный `go test ./...` — PASS;
- полный `go vet ./...` — PASS;
- `GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build ./...` — PASS;
- `node --check internal/webapi/static/app.js` — PASS.

**Не реализовано / не проверено:**

- Unix mode `0600` проверяется кодом и Linux-условной assertion, но Windows filesystem не доказывает production permission semantics; реальная Ubuntu-проверка остаётся `LINUX_NOT_RUN`;
- browser preview не выполнял реальные subscription download/Mihomo qualification и не является hardware test;
- реальные Ubuntu 24.04 SQLite migration на сохранённой v4 DB, systemd service user ownership и power-loss recovery требуют Linux gate;
- node list/manual include-exclude/preview, target `expected_body`, OpenAPI, backup/update/diagnostics и telemetry gaps остаются впереди.

**Следующий шаг:** реализовать node operations и matcher preview/manual override со сквозной requalification, затем закрыть target expected-body и operational API gaps; при появлении Ubuntu host выполнить уже подготовленный netns firewall gate.

### Сессия 015 — независимый firewall integrity guard и netns harness — 2026-08-24

**Сделано:**

- boot ruleset получил immutable `firewall_schema_generation = 1`; runtime backends также требуют этот marker и критические owned sets до мутации;
- реализован отдельный privileged `firewall.Guard`: проверяет owned table, schema generation, `input/forward/output policy drop`, `PATH_BLOCKED`, TUN и WireGuard critical rules;
- при потере/повреждении table guard сначала определяет исходный administrative state transit LAN, атомарно сохраняет root-only quarantine marker, выполняет `ip link ... down`, затем загружает через `nft --check` только `table inet gateway_vpn` в boot `PATH_BLOCKED`;
- LAN поднимается только после повторной text+JSON verification schema generation; если recovery падает, link остаётся down и marker позволяет новому guard process продолжить восстановление после restart; изначально administratively down link guard не поднимает;
- добавлен `NFTMonitor`, читающий `/usr/sbin/nft monitor ruleset`, и двухсекундный polling fallback; monitor restart имеет bounded backoff, а guard остаётся работоспособным при падении monitor subprocess;
- создан `gateway-vpn-firewall-guard.service` с root, `CAP_NET_ADMIN`, `RuntimeDirectory=... 0700`, systemd hardening и ordering до recovery/broker/control/Mihomo/dnsmasq; все data-plane units теперь требуют guard;
- installer устанавливает/enable/restart guard, uninstaller останавливает и удаляет unit;
- path activation перед выбором node повторно просит root собрать Mihomo endpoint allowlist из конкретной active immutable version; это восстанавливает очищенные boot sets после guard recovery до end-to-end probe;
- подготовлен `test/netns/firewall_guard.sh`: уникальные gateway/client/modem namespaces, marked table без unmarked default, удаление owned table, полный `nft flush ruleset`, schema/PATH_BLOCKED recovery и проверка отсутствия автоматического возврата active generation;
- `OPERATIONS.md` и `SECURITY.md` описывают quarantine marker, диагностику, ownership и ограничение, что чужие nft tables guard не восстанавливает.

**Проверено:**

- healthy guard не меняет LAN и выполняет только integrity reads;
- missing table и wrong schema: link down → checked owned load → text/JSON verify → link up; payload не содержит `flush ruleset`;
- load failure сохраняет link down и marker; новая Guard instance после устранения ошибки восстанавливает table и только затем link;
- исходный admin-down state сохраняется без marker/самовольного link up;
- runner реагирует и на monitor event, и на silent periodic loss;
- packaging tests проверяют unit capabilities/ordering/installer и наличие двух destructive scenarios в netns harness;
- pathruntime test фиксирует порядок `block gate → authorize active version endpoints → select → required probes → activate gate`;
- полный `go test ./...` — PASS;
- полный `go vet ./...` — PASS;
- `GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build ./...` — PASS;
- WebUI `node --check` — PASS.

**Не реализовано / не проверено:**

- netns script подготовлен, но в текущей Windows-среде фактически не запускался; `nft monitor`, real link quarantine, schema JSON shape и atomic table replacement остаются `LINUX_NOT_RUN`;
- `systemd-analyze verify`, boot ordering, RuntimeDirectory ownership, capability bounding и crash/restart marker recovery требуют Ubuntu 24.04;
- monitor-to-quarantine имеет ненулевую реакцию; отсутствие глобального direct leak опирается также на production invariant без unmarked modem default route, который должен быть проверен packet capture в netns/hardware;
- случайный полный `nft flush ruleset` удаляет и чужие tables: guard восстанавливает только Gateway VPN table, как требует ownership model;
- фактический rehydrate proxy endpoint sets через real DNS/Mihomo после guard reset не запускался.

**Следующий шаг:** modem operation API/WebUI и audit events, затем subscription CRUD; параллельно при появлении Linux host выполнить подготовленный netns guard gate.

### Сессия 014 — production WireGuard management selector и WebUI — 2026-08-24

**Сделано:**

- добавлен strict protected WireGuard config loader/writer: абсолютный regular non-symlink file, bounded YAML с known fields, atomic temp+fsync+rename, mode `0600`; MVP фиксирует `wg-mgmt`, `10.80.0.2/32`, `AllowedIPs=10.80.0.0/24` и UDP/51821;
- Web API получил CSRF-protected `GET/PUT /api/v1/settings/wireguard` и redacted `GET /api/v1/wireguard/status`; private key принимается при первой настройке/ротации, никогда не возвращается и при пустом update сохраняется прежним;
- вкладка **Удалённый доступ** показывает active/candidate/route modem, endpoint/handshake и reachability каждого модема, а также сохраняет endpoint, VPS public key, keepalive и configured handshake threshold 30–180 секунд;
- root broker получил строго безаргументный `POST /v1/wireguard/sync`; production backend самостоятельно читает `/var/lib/gateway-vpn/secrets/wireguard.yaml`, modem inventory и runtime state;
- application reconciliation loop после authoritative routing sync каждые пять секунд вызывает management sync независимо от состояния Mihomo/subscription path;
- service firewall разрешает единственный WireGuard tuple `interface × fwmark × public endpoint IPv4` с отдельной two-part generation; повторная проверка корректного tuple не переписывает nft set;
- WireGuard controller создаёт/синхронизирует interface через `wg syncconf`, назначает `10.80.0.2/32`, ставит endpoint host route в modem table, меняет fwmark и только затем удаляет старый endpoint route;
- persistent runtime раздельно хранит confirmed `CurrentModemID` и фактический `RouteModemID`; новый/возвращённый modem остаётся `PROBING` и становится `REACHABLE` только после handshake новее `ProbeStartedAt`;
- timeout помечает candidate `BLOCKED` и пробует следующий modem; unplug/lease-context change кандидата сбрасывает ожидание немедленно; неуспешный failback возвращает route на прежний confirmed modem и повторно подтверждает handshake;
- config SHA заставляет применить новые key/peer/endpoint даже при неизменном modem; при смене endpoint IP старый `/32` route удаляется также на том же modem;
- hostname разрешается modem-bound root DNS socket через его interface/fwmark; runtime cache составляет пять минут, а временная DNS-ошибка сохраняет и повторно авторизует последний confirmed IPv4 с минутным retry;
- root broker unit получил `CAP_NET_RAW` вместе с `CAP_NET_ADMIN` для modem-bound DNS и explicit read-only WireGuard secret path; control plane по-прежнему не получает `CAP_NET_ADMIN`;
- `OPERATIONS.md` и `SECURITY.md` дополнены настройкой VPS/Gateway, redaction/rotation contract и обязательными hardware gates.

**Проверено:**

- WireGuard state-machine tests: первая проба, commit только по новому handshake, timeout на следующий modem, candidate unplug без ожидания, active unplug, failback hysteresis, failed failback route restore, concurrent sync serialization и missing-config no-op;
- config/DNS tests: strict/atomic protected round trip, фиксированный MVP port/interface/subnet, bounded configurable handshake timeout, config-change re-probe, удаление старого endpoint route, hostname resolution через candidate modem и сохранение cached IP при DNS failure;
- firewall/broker tests: точный endpoint tuple и generation no-op, parameter-free strict JSON, unknown parameter rejection и redaction privileged error;
- Web API tests: settings требуют session/CSRF, private key сохраняется и не возвращается, update без private key сохраняет действующий secret, status не раскрывает config fingerprint;
- полный `go test ./...` — PASS;
- полный `go vet ./...` — PASS;
- `GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build ./...` — PASS;
- `node --check internal/webapi/static/app.js` — PASS.

**Не реализовано / не проверено:**

- фактические `wg syncconf`, `wg show latest-handshakes`, protocol-186 host routes, nft concatenated set и systemd capability/sandbox не запускались на Ubuntu 24.04; статус остаётся `LINUX_NOT_RUN`;
- `SO_BINDTODEVICE`/`SO_MARK` root DNS, hostname TTL на реальном DNS, UDP/51821 packet capture и переключение между двумя операторами не проверялись;
- VPS peer/firewall/forwarding, вход в Web UI через `10.80.0.2:8443`, unplug Huawei и работа при остановленном Mihomo требуют реального стенда;
- active handshake age выводится как alert-only по плану и сам по себе не переключает modem; switch запускают initial/config/failback/unplug transitions;
- внешний вид новой вкладки проверен только через embedded asset/API contract и JS syntax, не через реальный браузер;
- firewall guard, netns recovery после удаления owned table и reboot/systemd integration впереди.

**Следующий шаг:** firewall guard с quarantine/reload/verification и Linux netns harness, затем реальные Ubuntu 24.04/VPS/два HiLink gates.

### Сессия 013 — production HiLink hot-plug loop и WebUI adoption — 2026-08-24

**Сделано:**

- добавлен Linux `NETLINK_ROUTE/RTMGRP_LINK` watcher с bounded receive timeout; runner выполняет immediate reconcile, coalesced link-event reconcile и пятisekундный polling fallback, а ошибка watcher не отключает polling;
- production `app.Serve` запускает Modem Runner как отдельный lifecycle worker и корректно останавливает его общим context;
- sysfs probe перечисляет только USB network devices, извлекает vendor/product/serial/MAC/topology/driver/carrier; identity salt создаётся один раз atomic secret `0600` и стабильно переживает restart;
- systemd service разрешён read-only `AF_NETLINK`, но не получил `CAP_NET_ADMIN`; modem-bound socket capability остаётся только `CAP_NET_RAW`;
- добавлен systemd-networkd profile для USB Huawei `12d1`: IPv4 DHCP, RA/link-local отключены, `UseRoutes/UseGateway/UseDNS/UseNTP=no`; installer требует активный networkd, устанавливает profile и выполняет `networkctl reload`;
- preflight теперь проверяет `networkctl`; service ordering требует `systemd-networkd.service`;
- HiLink Manager переведён на порядок `observed SQLite state → authoritative root sync`: новый lease становится `MODEM_READY` до parameter-free sync, disconnect сначала становится offline, затем удаляет route; empty plan также запускает cleanup;
- route-sync failure переводит затронутые ready modem records в `MODEM_ERROR` и повторно вызывает cleanup, при этом TUN gate уже остаётся закрытым root backend;
- добавлен `AuthoritativeRoutes`: plan служит только ownership proof, route/interface/mark arguments не пересылаются broker;
- создан thread-safe discovery registry; наружу возвращаются interface, USB IDs, masked serial/topology, carrier и reason, но не salted identity hash;
- Web API реализовал предусмотренные планом `GET /api/v1/modems/discovered` и CSRF-protected `POST /api/v1/modems/{discovery_id}/adopt`; adoption выдаёт постоянный UUID-like ID, display number/table/fwmark и создаёт path-matrix cells;
- вкладка **Модемы** показывает отдельную секцию найденных устройств и позволяет задать имя/оператора перед adoption; неоднозначный identity остаётся read-only с reason.

**Проверено:**

- Runner tests: immediate+link-event reconcile, watcher failure reporting и продолжение polling;
- Manager ordering test: root route adapter видит DB `MODEM_READY` при add и `MODEM_CONFIGURED_OFFLINE` при remove;
- conflict test по-прежнему изолирует два пересекающихся modem subnet и оставляет независимый третий ready;
- registry test: identity hash отсутствует в DTO, adoption использует сохранённый hash и удаляет ephemeral discovery;
- Web API test: discovery list требует session, adoption требует CSRF, создаёт второй modem и вторую matrix cell;
- packaging tests: networkd match/DHCP/no-route policy, `AF_NETLINK` и service dependency;
- полный `go test ./...`, `go vet ./...`, `GOOS=linux GOARCH=amd64` builds обоих binaries — PASS.

**Не реализовано / не проверено:**

- реальный netlink event, `/sys` metadata Huawei E3372h-325, udev properties `ID_BUS/ID_VENDOR_ID`, networkd lease format и `networkctl reload` не запускались на Ubuntu; всё остаётся `LINUX_NOT_RUN`;
- статический networkd profile пока покрывает только заявленный Huawei vendor `12d1`; расширение vendor/product allowlist потребует generated root-owned profiles и Linux tests;
- HiLink API serial пока не повышает уже выбранную USB identity автоматически; API telemetry foundation не включена в runner cycle;
- adoption audit event, modem PATCH/enable/priority/delete/recover/probe/replace-identity endpoints ещё отсутствуют;
- networkd reconfigure уже подключённого до установки interface и поведение конкурирующих netplan files требуют реального installer test;
- WireGuard management selector/set, firewall guard и netns/hardware gates впереди.

**Следующий шаг:** WireGuard management selector с modem-priority reachability и atomic endpoint tuple, затем firewall guard/netns suite.

### Сессия 012 — dynamic path gate, modem routing и fail-closed bootstrap — 2026-08-24

**Сделано:**

- boot nftables table расширена atomic sets `active_tun_interfaces`, `active_path_generation`, modem-scoped service sets и отдельными Mihomo TCP/UDP endpoint sets; forward разрешает только IPv4 `LAN → verified TUN`, прямого правила `LAN → HiLink` нет;
- root `FirewallBackend` атомарно меняет только owned path sets, выполняет `nft --check`, apply и JSON observation; half-active/wrong-TUN state отклоняется;
- broker получил strict parameter-bounded path operations; production `pathruntime.Actuator` выбирает qualified node/path через Mihomo API, повторно проверяет все required targets и только после этого открывает TUN gate; ошибка выбирает `REJECT` и оставляет gate закрытым;
- `BeginActivation` generation передаётся в nft без второго increment; CandidateRuntime, path actuator и observer используют общий operation lock; production запускает пятisekундный reconciliation loop;
- реализован root-backed authoritative modem routing sync: enabled `MODEM_READY` читаются из SQLite, для каждого строятся management/default routes и fwmark rule в отдельной table с protocol `186`; state вне main table сверяется через `ip -json`, stale base routes/rules удаляются без `flush`, WireGuard host routes сохраняются;
- перед любой route mutation закрывается TUN gate; partial apply компенсируется удалением owned base state; после apply каждый bootstrap DNS проверяется через `ip route get <ip> mark <fwmark>` с ожидаемыми table/interface/gateway;
- root broker публикует только parameter-free `POST /v1/routing/sync`; routing sync выполняется до candidate qualification и перед каждым periodic reconcile;
- firewall output policy получила modem tuples `ifname × mark × IPv4` для DNS и `ifname × mark × IPv4 × port` для subscription/Mihomo endpoints; управление sets сериализовано внутри root backend и имеет собственные two-part generations;
- создан Linux socket binding layer: control-plane DNS/HTTPS использует `SO_BINDTODEVICE` + `SO_MARK`; `gateway-vpn.service` получает только `CAP_NET_RAW`, без `CAP_NET_ADMIN`;
- production subscription fetch вынесен в отдельный adapter `internal/subscriptionnet`: он синхронизирует routing, пробует `MODEM_READY` по priority, выполняет IPv4 DNS и HTTPS в одном modem context, запрашивает двухминутный root-authorized firewall tuple и переходит к следующему оператору при ошибке;
- root Mihomo endpoint authorization принимает только список существующих candidate/LKG/retained version IDs, сам читает immutable `0600` payloads и enabled node fingerprints, разрешает hostnames отдельно через каждый ready modem и полностью заменяет точные TCP/UDP endpoint sets до shadow/final apply;
- rollback CandidateRuntime восстанавливает endpoint allowlist предыдущих version IDs вместе с предыдущей Mihomo generation; произвольные IP/port для Mihomo через broker не принимаются;
- исправлено направление package dependencies: modem-aware transport вынесен из доменного `subscription`, поэтому domain packages снова не образуют import cycle.

**Проверено:**

- route sync tests: stale modem rule/default/link route удаляются, WireGuard host route protocol `186` не затрагивается, main table/global flush отсутствуют, no-op не закрывает gate, неверный marked lookup закрывает gate;
- service firewall tests: context generation и точные HiLink/DNS tuples, краткоживущий HTTPS tuple, public IPv4/HTTPS validation, Mihomo endpoint generation из protected candidate payload;
- subscription adapter test: Operator A не соединяется, Operator B используется следующим по priority; оба получают отдельную authorization attempt с modem ID, mark context, exact IPv4 и port `443`;
- broker tests: routing sync не принимает параметры, bootstrap/Mihomo requests имеют strict DTO, unknown fields и backend details не проходят boundary;
- полный `go test ./...` — PASS;
- полный `go vet ./...` — PASS;
- `GOOS=linux GOARCH=amd64` builds `gateway-vpn` и `gateway-vpnctl` — PASS.

**Не реализовано / не проверено:**

- все команды выполнялись в Windows dev-среде с fake executors; фактические `nft --check`, concat-set syntax, `meta skuid`, timeout/destroy element semantics и JSON `iproute2` Ubuntu 24.04 остаются `LINUX_NOT_RUN`;
- `SO_BINDTODEVICE`/`SO_MARK` с systemd `CAP_NET_RAW`, реальные marked DNS/HTTPS sockets, proxy hostname resolution через два оператора и packet capture не запускались;
- реальный Mihomo binary, provider override, API selection, TUN, reload/rollback и endpoint TCP/UDP traffic не запускались;
- WireGuard endpoint set/selector, NTP allowlist, udev/networkd event loop и automatic modem adoption/replug lifecycle ещё не подключены;
- firewall guard и netns recovery после удаления table/`nft flush ruleset` отсутствуют;
- proxy DNS resolution сейчас synchronous и без persistent TTL cache; load/budget policy для тысяч уникальных endpoint hostnames должна быть подтверждена stage 0/3;
- `expected_body` target остаётся намеренно неподдержанным текущим delay API;
- Ubuntu/hardware gate остаётся `NOT_RUN`; cross-build не является runtime validation.

**Следующий шаг:** production udev/networkd Modem Manager loop и WireGuard management selector, затем firewall guard и Linux netns suite с фактическими nft/ip/marked-socket/Mihomo проверками.

### Сессия 011 — Linux Mihomo GenerationRuntime и production refresh wiring — 2026-08-24

**Сделано:**

- добавлен `internal/mihomoruntime.LinuxRuntime`, реализующий `mihomo.GenerationRuntime` и `FailClosedRuntime`;
- activation принимает только safe generation ID и ожидаемый absolute generation directory, атомарно переключает `mihomo/active`, затем вызывает loopback Mihomo API reload; при недоступном API запрашивает synchronous restart фиксированного systemd unit через privileged broker;
- Verify сверяет active generation link, точную закреплённую Mihomo `/version` и наличие `UP` TUN через фиксированный `/usr/sbin/ip -json link show dev`; API/TUN readiness опрашивается с bounded timeout;
- Linux-only `AtomicSymlinkSwitcher` проверяет, что root/generations/generation — реальные каталоги, `config.yaml` — regular non-symlink, active target относительный и не выходит из `generations`; публикация выполняется одним symlink rename + directory fsync;
- non-Linux switcher всегда отклоняет mutation; Windows tests используют injected switcher/platform и не имитируют Linux filesystem PASS;
- network broker получил только `POST /v1/mihomo/restart` и `POST /v1/mihomo/fail-closed` с пустым strict JSON; ошибки редактируются до reason code, endpoint по-прежнему защищён socket `0600` + `SO_PEERCRED` UID;
- root `SystemdAdmin` выполняет исключительно `restart gateway-vpn-mihomo.service` либо последовательность `reload gateway-vpn-firewall.service → stop gateway-vpn-mihomo.service`; unit names не приходят от клиента;
- при любой необратимой activation error runtime просит broker восстановить boot `PATH_BLOCKED`, остановить Mihomo и удаляет active link;
- `TransactionController` теперь реально вызывает fail-closed при verification failure первого generation, при failed rollback предыдущего LKG и при boot recovery pending generation без LKG; pending marker очищается после доказанного blocked recovery;
- исправлены права Mihomo generations: root/generations `0750`, generation/provider directories `0750`, config/provider files `0640`, private state markers `0700/0600`; Mihomo service видит generation tree read-only и не может менять proxy credentials/config;
- Mihomo service устанавливается enabled, но запускается только при `ConditionPathExists=/var/lib/gateway-vpn/mihomo/active/config.yaml`; первый generation запускает broker, последующие reboot поднимают сохранённый LKG;
- рассмотренный `.path` watcher удалён: постоянный `PathExists` мог повторно запустить service между fail-closed stop и удалением active link;
- release builder теперь требует `MIHOMO_VERSION` и SHA-256, встраивает version в `buildinfo`, создаёт checksummed `release.json` с OS/arch/config schema/API contract; installer сверяет Gateway binary version и создаёт Mihomo API secret `0600`;
- bootstrap config получил явные `mihomo.stack`, `bootstrap_dns`, transport probe URL/timeout/expected status с strict validation;
- добавлен `ScheduledProber`: каждый transport/target request проходит global/per-modem concurrency, hard rate и mobile soft-budget accounting; CandidateRuntime использует critical failover reserve;
- добавлен durable scheduled refresh worker: каждые 30 секунд он вызывает non-forced refresh только для enabled auto-refresh URL subscriptions, а SQLite due time/lease остаются authoritative;
- production `app.Initialize` теперь собирает Mihomo client, BinaryValidator, LinuxRuntime, transaction recovery, scheduler, CandidateRuntime, secure fetch/source reader, manual coordinator и scheduled worker;
- Web API получил CSRF-protected `POST /api/v1/subscriptions/{id}/refresh`, а вкладка **Подписки** — кнопку «Обновить и проверить»; LKG меняется только после полного двухфазного runtime flow.

**Проверено:**

- LinuxRuntime tests: API reload без restart, restart fallback, eventual API/TUN readiness, exact-version mismatch, non-Linux rejection и fail-closed при двойной reload/restart ошибке;
- fixed SystemdAdmin tests: точный executable/arguments/order и stop attempt даже после firewall reload error;
- broker tests: обе parameter-free operations, вызовы backend и отсутствие privileged error detail в client error;
- transaction tests: first-generation Verify failure вызывает FailClosed и очищает pending; interrupted first generation на boot восстанавливается в blocked state;
- scheduler wrapper test: admitted request учитывает bytes, следующий standby request получает `DEFERRED_BUDGET` без вызова prober;
- scheduled worker tests: due refresh, durable next attempt, clean context stop, real failure reporting и silent not-due handling;
- API test: manual refresh требует session+CSRF, передаёт force=true и возвращает conflict для concurrent lease;
- app construction test собирает coordinator/worker/transactions с защищённым secret; symlink и embedded-newline secrets отклоняются;
- packaging tests проверяют read-only generations, conditional service, generated API secret, pinned release metadata и непривилегированный control plane;
- Git Bash `bash -n scripts/build-release.sh scripts/install-gateway.sh scripts/uninstall.sh` — PASS;
- полный `go test ./...`, `go vet ./...` и `GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build ./...` — PASS;
- Linux-tagged `internal/mihomoruntime` tests, включая реальный `os.Symlink → os.Rename → fsync` test, успешно скомпилированы через `go test -c` в ELF binary, но не запускались.

**Не реализовано / не проверено:**

- Linux-only atomic symlink test не исполнялся; фактические rename/fsync permissions и ownership на ext4 остаются `LINUX_NOT_RUN`;
- root broker не вызывал реальный `systemctl`; systemd authorization/sandbox, firewall reload, service stop/restart и boot Condition требуют Ubuntu 24.04;
- реальный Mihomo `-t`, API reload, pinned `/version`, provider override, TUN creation и `ip -json` не запускались;
- bootstrap DNS/subscription HTTPS пока не привязаны к конкретному modem fwmark/table и boot firewall ещё не содержит рабочие dynamic `bootstrap_dns_v4/bootstrap_http_v4` flows; поэтому реальный fail-closed bootstrap refresh не заявляется;
- dynamic firewall/path actuator и reconciler production wiring отсутствуют, поэтому LAN path остаётся blocked даже после qualification;
- synchronous manual refresh handler может жить дольше обычного HTTP request на большой подписке; durable asynchronous operations API/status остаётся обязательным;
- `expected_body` target всё ещё требует отдельный controlled probe transport; Mihomo delay API adapter доказывает только transport/status;
- scheduled budget пока учитывает conservative estimated bytes, а не фактический response size из Mihomo API;
- real systemd-analyze, nft/ip/netns, Ubuntu reboot и HiLink hardware gates не выполнялись.

**Следующий шаг:** реализовать root-backed atomic nft set/path activation, per-modem bootstrap routing и production reconciler actuator; затем подключить udev/networkd Modem Manager loop и перенести весь data plane в netns/Ubuntu integration tests.

### Сессия 010 — двухфазный CandidateRuntime и multi-modem evidence commit — 2026-08-24

**Сделано:**

- Mihomo generator получил `QualificationOnly`, отдельный `RuntimeKey`, стабильную logical subscription identity и path metadata с node prefix; shadow provider/group создаётся, но исключается из `gateway-vpn-active`;
- generator запрещает два обычных active entry одной logical subscription, при этом допускает её active LKG и изолированный candidate shadow одновременно;
- `TransactionController.Restore` восстанавливает явно указанное ранее успешное поколение после уже завершившегося `Apply`, обновляет active/LKG markers и очищает pending marker;
- для случая без предыдущего поколения введён `FailClosedRuntime`: runtime сначала переводится в `PATH_BLOCKED`, затем active/LKG/pending markers удаляются; не прошедший Verify restore также вызывает fail-closed, если backend поддерживает контракт;
- реализован `internal/candidateruntime`: он сериализует promotions, загружает immutable payloads всех enabled active LKG subscriptions, фильтрует nodes по сохранённой classification/fingerprint и добавляет кандидат только как shadow;
- для каждого enabled `MODEM_READY` строится отдельный provider с interface/fwmark; candidate paths квалифицируются в памяти через все enabled targets, и promotion отклоняется, если ни один modem path не получил `BYPASS_QUALIFIED`;
- до `subscription_versions.Activate` в path matrix не записывается candidate evidence; promotion handle сохраняет возможность отката через SQLite activation;
- `Commit` повторно строит финальный bundle уже по authoritative SQLite LKG, применяет отдельное active generation, выбирает qualified node внутри каждого прошедшего path group и только после этого атомарно сохраняет path/node/target evidence;
- добавлена компенсация частичного evidence commit: candidate-version rows удаляются, затронутые cells становятся `STALE`, остальные modem/subscription cells не меняются;
- refresh coordinator теперь всегда пытается выполнить `AbortActivation` после runtime rollback, включая случай, когда rollback сам сообщил ошибку; это не оставляет failed candidate как SQLite LKG;
- `ReconcileCells` исправлен: новые modem × subscription cells наследуют текущую global `policy_generation`, а не всегда generation `0`;
- runtime generation lock удерживается от shadow apply до terminal `Commit`/`Rollback`, поэтому две refresh operations не могут перемешать временные и финальные Mihomo generations.

**Проверено:**

- generator test: одна active и одна shadow version одной subscription создают два provider/group, имеют разные prefixes, а active group содержит `REJECT` и только normal group;
- transaction tests: restore к предыдущему successful generation, restore без LKG через fail-closed и verification failure с принудительным fail-closed;
- multi-modem CandidateRuntime test: один и тот же candidate через modem A становится `QUALIFIED`, через modem B — `FAILED`; до SQLite activation evidence отсутствует, после commit обе cell получают независимые результаты;
- partial commit test: route generation modem B меняется между qualification и commit, evidence modem A успевает записаться, stale error останавливает commit, rollback возвращает `base-generation`, удаляет candidate evidence и после DB compensation восстанавливается прежняя subscription LKG;
- no-qualified-path test: temporary shadow generation откатывается и candidate не публикуется;
- coordinator test: даже сообщённая ошибка runtime rollback не мешает восстановить прежнюю SQLite LKG и пометить candidate `FAILED`;
- новый path cell после ранее выполненной policy invalidation получает актуальную generation;
- полный `go test ./...`, `go vet ./...`, `GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build ./cmd/gateway-vpn ./cmd/gateway-vpnctl` и отдельный Linux build новых internal packages — PASS.

**Не реализовано / не проверено:**

- CandidateRuntime пока не подключён к production API/scheduled refresh construction; тесты используют fake generation controller, selector и path-scoped prober;
- реальный Linux `GenerationRuntime` с atomic active directory/symlink, Mihomo process reload/restart, API Verify, TUN smoke и firewall `PATH_BLOCKED` ещё отсутствует;
- `expected_body` target намеренно отклоняется CandidateRuntime, потому что текущий Mihomo delay API доказывает transport/status, но не возвращает body; нужен отдельный безопасный body-probe transport либо подтверждённый Mihomo API mechanism;
- существующий concurrency/rate/traffic-budget scheduler не подключён к вызовам CandidateRuntime prober;
- не проверялись реальный Mihomo binary/API, TUN, provider override, selection retention при reload, packet capture, `nftables`, `systemd`, netns или HiLink hardware;
- Linux/Ubuntu статус остаётся `NOT_RUN`: cross-build не является runtime validation.

**Следующий шаг:** реализовать fail-closed Linux `GenerationRuntime`, подключить его вместе с CandidateRuntime к manual/scheduled subscription refresh operations, затем выполнить netns tests с реальным Mihomo и проверить systemd units на Ubuntu 24.04.

### Сессия 009 — privileged safe-apply broker, Ubuntu backend и WebUI flow — 2026-08-24

**Сделано:**

- safe-apply engine разделён на `Stage` и `Apply`: `Stage` создаёт snapshot/manifest, пересчитывает deadline непосредственно перед arm, запускает timer и возвращает token без сетевой мутации; отдельный `Apply` меняет сеть;
- сохранён synchronous `Prepare` как безопасная обёртка `Stage → Apply` для внутренних тестов;
- добавлен bounded strict-JSON broker protocol по Unix socket: stage/apply/confirm/recover; privileged errors редактируются до stable reason code и не раскрывают filesystem/command details;
- broker client отключает proxy/compression, использует только абсолютный Unix socket и ограничивает response size;
- добавлен `PeerAuthorizingListener`: filesystem mode `0600` является первым boundary, Linux `SO_PEERCRED` UID — вторым; неверный peer закрывается до HTTP parsing;
- реализован typed `UbuntuBackend`: strict current/candidate config, проверка фактического old CIDR через `ip -json`, authoritative overlap check по всем observed host IPv4 networks, root snapshot текущего config/dnsmasq/persistent и runtime nftables;
- backend генерирует только известные Gateway VPN assets, валидирует candidate через config loader, `nft --check` и `dnsmasq --test`, вызывает фиксированные absolute `ip`/`nft`/`dnsmasq`/`systemctl` без shell;
- apply сохраняет old address как secondary, ставит новый address, блокирующий nft generation, config/dnsmasq и заказывает non-blocking restart API; persistence после restart request использует cancellation-independent context;
- commit удаляет старый address только после подтверждения; rollback сначала возвращает старый address/config/firewall/dnsmasq/API, затем удаляет candidate address;
- добавлен `SystemdRollbackTimer`, который допускает только safe apply ID и строго 60-секундный template deadline;
- добавлены CLI `network-broker`, `network-rollback`, `network-recover`; mutation требует одновременно Ubuntu/Linux, root и явный `--apply`;
- добавлены systemd broker socket/service, pre-API recovery service и rollback service/timer templates; transaction root создаётся `root:root 0700`;
- `gateway-vpn.service` остаётся без capabilities и зависит от recovery; broker/root helpers ограничены `CAP_NET_ADMIN`, `CAP_DAC_OVERRIDE`, `CAP_CHOWN`, fixed writable paths и systemd sandbox;
- installer/uninstaller устанавливает и обслуживает новые units;
- Web API получил safe apply stage/status/confirm endpoints; candidate заранее проверяется против WireGuard и modem management networks;
- async Apply запускается только после записи и flush HTTP 202 с `apply_id`, token, old/new URL и deadline;
- confirm определяет источник только через `http.LocalAddrContextKey`; `Host` и proxy headers не являются evidence;
- вкладка **Сеть** показывает current interface/CIDR, форму safe apply и одноразовую confirmation page. Token помещается в URL fragment, который browser не отправляет HTTP server; на новом origin пользователь входит снова и подтверждает apply;
- `OPERATIONS.md` и `SECURITY.md` дополнены boot order, runbook и privilege boundary.

**Проверено:**

- broker tests: stage/apply/confirm round-trip, strict unknown-field rejection, privileged error redaction;
- peer listener test: wrong UID connection закрывается, allowed UID принимается;
- Ubuntu backend tests: snapshot, generated config/dnsmasq, typed command set, apply, commit, rollback, missing old address и overlap неизвестного host interface;
- timer tests: только fixed systemd instance, unsafe ID и неверный deadline отклоняются;
- API tests: token возвращается до async Apply, `Host` spoof без LocalAddr отклоняется, реальный new local destination передаётся broker;
- app candidate builder tests: modem и WireGuard overlap отклоняются;
- packaging tests подтверждают control plane без `CAP_NET_ADMIN`, socket mode `0600`, root-owned store, pre-start recovery и independent timer/helper;
- встроенный Browser выполнил login, открыл вкладку **Сеть** и отобразил LAN `enp2s0 / 192.168.200.1/24`; URL с валидным confirmation fragment показал отдельную кнопку подтверждения. Screenshot API завершился ошибкой, поэтому визуальный screenshot не заявляется как PASS;
- полный `go test ./...`, `go vet ./...`, Linux/amd64 cross-build и compile-only Linux-tagged `internal/networkapply` — PASS.

**Неуспешные / ограниченные проверки:**

- первая команда после Linux cross-build попыталась запустить Linux test binaries на Windows и закономерно получила `%1 is not a valid Win32 application`; повтор выполнен корректно как compile-only через `-exec`;
- встроенный Browser не смог снять full-page screenshot, хотя DOM snapshots и интерактивные переходы прошли;
- `systemd-analyze verify`, реальные `SO_PEERCRED`, `nft --check`, `dnsmasq --test`, `ip address`, timer timeout, reboot recovery и API restart на новом адресе не запускались: для них нужен Linux/netns/Ubuntu;
- Web UI preview использовал fake broker и не менял host network.

**Следующий шаг:** двухфазный CandidateRuntime `Mihomo generation → in-memory path qualification → SQLite active version → evidence commit`, затем Linux netns harness и фактическая проверка новых systemd units.

### Сессия 008 — durable safe network apply state machine — 2026-08-24

**Сделано:**

- добавлена migration v4 `network_apply_transactions` с единственной незавершённой apply transaction, hashed confirmation token, old/new endpoints, rollback deadline и terminal timestamps;
- реализован safe-apply engine: DB record → checksummed durable manifest → snapshot backend → независимый timer → candidate apply; timer всегда вооружается до первой сетевой мутации;
- rollback timeout ограничен диапазоном 30–90 секунд, default — 60 секунд;
- старый и новый LAN должны быть разными непересекающимися private IPv4 subnet, management URLs обязаны быть HTTPS origins на соответствующих address/port;
- confirmation token хранится только как SHA-256 и сравнивается constant-time; raw token возвращается один раз в `Prepared`;
- подтверждение через LAN требует, чтобы фактический local destination socket совпал с новым LAN IP; WireGuard является отдельным разрешённым evidence path;
- confirmation intent сначала записывается на диск, затем timer снимается и backend commit удаляет старую сеть; reboot между этими шагами завершает уже доказанное подтверждение;
- все остальные незавершённые состояния при reboot откатываются немедленно, даже если timeout ещё не истёк;
- `RollbackFromDisk` не открывает SQLite и предназначен для отдельного timer/helper process;
- disk store создаёт каталоги `0700`, manifest/status `0600`, использует fsync + atomic rename, strict JSON, schema version и SHA-256 manifest; symlink/non-regular/oversized/tampered файлы отклоняются;
- manifest повторно проходит полную typed validation, а DB/disk identity сверяется перед commit/recovery, чтобы путь из изменённой DB не стал privileged input;
- refresh CandidateRuntime уточнён до двухфазного `Promote → SQLite Activate → Commit evidence`; commit failure вызывает runtime rollback и восстановление прежней LKG.

**Проверено:**

- operation-order test доказывает `snapshot → arm → apply` и `confirm intent → disarm → commit`;
- неверный token и запрос через старый destination отклоняются без side effects; новый destination и WireGuard принимаются;
- apply failure после отмены caller context использует независимый cleanup context, откатывается и снимает timer;
- DB-independent rollback меняет disk phase без доступа к repository, а следующий recovery согласует SQLite;
- reboot recovery откатывает unconfirmed apply и завершает durable confirmation intent;
- parallel apply, overlapping/public LAN, неверный interface/URL и tampered manifest отклоняются;
- migration v4, полный `go test ./...`, `go vet ./...` и Linux/amd64 cross-build — PASS.

**Не реализовано / не проверено:**

- `SnapshotBackend` и `RollbackTimer` пока являются привилегированными контрактами: Ubuntu broker, root-owned transaction root, systemd socket/timer units и реальное восстановление address/dnsmasq/firewall ещё не подключены;
- API endpoint не включается, пока broker отсутствует — Web/API процесс не получает `CAP_NET_ADMIN`;
- ни одна сеть Windows host не изменялась; netns/Ubuntu safe-apply timeout test остаётся обязательным gate.

**Следующий шаг:** root broker через ограниченный Unix socket, systemd rollback helper и typed Ubuntu backend; затем dynamic dual API listener и end-to-end confirmation test.

### Сессия 007 — Ubuntu packaging, multi-modem runtime foundations и безопасный refresh — 2026-08-24

**Сделано:**

- добавлены Ubuntu 24.04/x86_64 release builder, SHA-256 manifest, dry-run-by-default installer, systemd units, operations/security/networking runbooks и read-only `gateway-vpnctl status`;
- production management runtime подключает SQLite/bootstrap admin, TLS certificate lifecycle и HTTPS listeners; `gateway-vpn.service` остаётся непривилегированным, а firewall/Mihomo разделены по units;
- реализованы HiLink discovery, salted stable identity, DHCP lease parser, networkd config с `UseRoutes=no`, `UseGateway=no`, `UseDNS=no`, lease/offline state handling, route-generation invalidation, XML telemetry и subnet-conflict quarantine abstractions;
- реализованы WireGuard config/controller и management-uplink hysteresis; switch сначала устанавливает новый endpoint host route, затем меняет `wg fwmark` и только после этого удаляет старый route;
- реализован общий traffic accounting Option A с nft/Mihomo delta/reset handling, daily/monthly API, CSV и WebUI без ложной per-subscription attribution;
- добавлен HTTPS-only subscription fetcher: normal TLS verification с минимум TLS 1.2, proxy environment отключён, redirect limit, DNS pinning, запрет mixed public/private answers, loopback/private/link-local/protected prefixes и literal-IP bypass;
- ошибки fetcher не включают secret URL/token; conditional `ETag`/`Last-Modified` сохраняется, размер ограничивается после прозрачной gzip-декомпрессии;
- migration v3 хранит conditional cache, consecutive failures, next attempt и expiring owner lease; ручной refresh не обходит active lease, а crash не блокирует подписку навсегда;
- URL подписки читается только из confined secret root: traversal, symlink components, нерегулярные/oversized файлы и широкие Unix permissions отклоняются;
- реализован refresh coordinator: source → conditional fetch → matcher/override classification → immutable DB version → protected payload → runtime promotion/qualification → SQLite LKG;
- одинаковое тело без `304` определяется по SHA-256 и не создаёт новую версию/reload; manual include/exclude переносится только по stable fingerprint;
- runtime error сохраняется как безопасный reason code, предыдущая LKG остаётся активной; если runtime уже продвинул кандидат, но SQLite activation не завершилась, вызывается compensating rollback и DB compensation умеет восстановить предыдущую LKG даже после неопределённого commit result;
- refresh interval и exponential failure backoff используют bounded jitter; lease и failure cleanup выполняются с cancellation-independent timeout.

**Проверено:**

- fetcher tests подтверждают SSRF/mixed-DNS rejection, protected literal IP, отсутствие token/error-detail leakage, resolver failure, `304`, response headers, лимит после gzip и ровно три redirect;
- refresh repository tests подтверждают запрет параллельного запуска, forced/manual semantics, expiry crashed lease, due schedule, success reset и failure backoff state;
- coordinator tests подтверждают LKG promotion, conditional refresh, identical-body short circuit, runtime failure без замены LKG, safe reason code и rollback при отменённой DB activation;
- migration v3, idempotence и полный schema test — PASS;
- полный `go test ./...`, `go vet ./...` и `GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build ./cmd/gateway-vpn ./cmd/gateway-vpnctl` — PASS.

**Что не получилось / не проверено:**

- `CandidateRuntime.Promote` пока является строгим контрактом, а не подключённым Linux adapter: реальный bundle generation, `mihomo -t`, reload, TUN smoke и path qualification этим инкрементом не запускались;
- packaging assets не прошли реальные `systemd-analyze verify`, `nft --check`, `bash -n` и `dnsmasq --test` на Ubuntu;
- udev hot-plug, networkd lease lifecycle, HiLink XML конкретной firmware, WireGuard handshake, два модема и Keenetic не проверялись на hardware;
- никакие host routes/firewall rules в Windows не изменялись.

**Следующий шаг:** durable safe network apply/out-of-process rollback, затем Linux CandidateRuntime и API operation wiring; после этого netns suite и обязательный Ubuntu/hardware gate.

### Сессия 006 — runtime state, reconciler и защищённый Web API — 2026-08-23

**Сделано:**

- добавлен runtime state repository с двухфазной активацией `PATH_BLOCKED → PATH_VERIFYING → PATH_ACTIVE`, config generation и атомарными audit events;
- `BeginActivation` и `FinishActivation` независимо требуют fresh `QUALIFIED` cell, выбранный `BYPASS_QUALIFIED` node, совпадающие policy/route generations, active subscription version, `MODEM_READY` и неистёкший TTL;
- idempotent `Block` очищает весь active tuple и не создаёт повторные events при неизменном blocked reason;
- добавлен reconciler foundation: проверяет firewall/Mihomo/TUN observation, наличие required targets/ready modems, возобновляет прерванную verification, выбирает modem-first fresh candidate и вызывает только abstract fail-closed actuator;
- добавлен target outage evaluator: `TARGET_SUSPECT` возникает только при порогах по независимым комбинациям, разным modem и subscription; восстановление требует successes через разные модемы; dynamic state не меняет policy generation и не создаёт failover-loop;
- добавлена migration v2 для `users`, `sessions`, `login_attempts` и expiry indexes;
- реализованы Argon2id PHC hashes, одноразовый bootstrap admin, persistent hashed session/CSRF tokens, session revocation и progressive login delay;
- создан authenticated `/api/v1` foundation: login/logout/session, gateway status, modems, subscriptions, canonical path matrix, bypass targets, node matchers и paginated events;
- state-changing endpoints требуют CSRF; cookie имеет `Secure`, `HttpOnly`, `SameSite=Strict`; security headers включают CSP, frame denial, no-sniff, no-store и restrictive permissions policy;
- modem/subscription API использует явные redacted DTO и не выдаёт identity hash, API secret ref или subscription secret ref;
- target/matcher CRUD и atomic reorder подключены к policy generation; удаление последнего enabled required target требует отдельного destructive confirmation;
- Web UI разделён на 12 логических вкладок из плана; Обзор, Модемы, Подписки, Матрица, Серверы проверки, Matchers и Events используют один API/read model;
- добавлен server-side effective state: истёкший сохранённый `QUALIFIED` возвращается UI как `STALE` с `RESULT_EXPIRED`.

**Проверено:**

- migration v2, Argon2id verify, bootstrap uniqueness, login/session/CSRF/revoke и progressive block — PASS;
- `httptest` подтверждает 401 без session, 403 без CSRF, Secure cookie attributes, successful protected mutation и отсутствие secret/identity fields;
- встроенный браузер открыл локальный preview, выполнил login и отобразил четыре modem × subscription cells с offline/stale состояниями;
- browser smoke test нашёл несовпадение `GatewayState`/`gateway_state`: badge показывал `UNKNOWN`. API переведён на явный snake_case DTO, повторная проверка показала `NO_WORKING_SUBSCRIPTION / PATH_BLOCKED`;
- полный `go test ./...`, `go vet ./...` и `linux/amd64 CGO_ENABLED=0 go build` — PASS.

**Не проверено:** production HTTPS bind на Ubuntu, certificate generation/rotation, systemd sandbox, Linux observer/actuator и реальное переключение path. Preview слушал только loopback и не менял host network.

**Следующий шаг:** production TLS/bootstrap runtime и Ubuntu systemd/install assets, затем Linux observer/guard/netns tests.

### Сессия 005 — Subscription Manager, qualification и Mihomo LKG foundation — 2026-08-23

**Сделано:**

- реализован безопасный импорт Clash YAML, plain URI list и whole-base64 subscriptions для `vless`, `vmess`, `trojan`, `ss`, `hysteria2` и `tuic`;
- неизвестные/controller-owned proxy fields, private/local endpoints, некорректные credentials, oversized payloads и дубликаты отклоняются до изменения LKG;
- имена нормализуются через Unicode NFKC + case folding; fingerprint SHA-256 не зависит от display name;
- matcher policy поддерживает substring и Go RE2 regex, manual include/exclude, начальные маркеры «обход»/LTE/whitelist и fallback ко всем nodes только при отсутствии name matches;
- добавлен matcher repository с однократным default seed, CRUD/reorder и атомарной инвалидацией `policy_generation`;
- добавлены immutable `subscription_versions`, node identity/classification, staging, FAILED и LKG/RETAINED activation с сохранением прежней рабочей версии;
- нормализованные proxy configs сохраняются отдельно от SQLite в защищённом immutable payload tree (`0700` directories, `0600` file), повторно валидируются при чтении и не принимают symlink/traversal;
- реализован single-process Mihomo generator: provider/group для каждой online пары modem × subscription, modem-specific `interface-name`/`routing-mark`, один TUN и верхняя группа, начинающаяся с `REJECT`;
- реализован loopback-only Mihomo API client для version/reload/select/provider-node health-check;
- реализован path-scoped qualifier: дешёвый transport probe, required targets по priority с fail-fast, optional evidence и выбор lowest-latency qualified node;
- реализована атомарная запись `path_nodes` + `path_node_target_results` + aggregate cell; foreign subscription node и устаревшие policy/route generations отклоняются без частичной записи;
- bypass target repository получил SSRF-safe normalization, CRUD/reorder и transaction-bound policy invalidation;
- реализован probe scheduler с global/per-modem concurrency, hard request rate, per-target interval, per-modem soft traffic budget, 30% active/failover reserve, `DEFERRED_BUDGET` и overage accounting;
- реализован Mihomo configuration transaction: immutable candidate, внешний `mihomo -t` validator contract, pending marker, runtime activation/verification, LKG promotion, rollback и boot recovery незавершённой операции.

**Найдено и исправлено тестами:**

- URI subscription первоначально могла ошибочно приниматься за malformed YAML; YAML parser теперь запускается только при root key `proxies:`;
- prefixed provider node содержит `/`; прежняя сборка API URL могла дважды экранировать `%2F`, из-за чего адресный health-check обращался к несуществующему node. Endpoint теперь разбирается как relative URL и сохраняет escaped path segment;
- SQLite `INSERT … SELECT … ON CONFLICT` требует disambiguating `WHERE`; исправление из сессии 003 продолжает покрываться matrix tests.

**Проверено:** package-level tests для subscription, bypass, pathmatrix, Mihomo, health и scheduler проходят. Protected payload round-trip, LKG preservation, stale-generation rejection, budget deferral/critical overage, config rollback и interrupted-transaction recovery покрыты отдельными тестами.

**Не проверено:** реальный формат конкретной HAPP-подписки, закреплённый Mihomo binary/API, `mihomo -t`, TUN, provider override, systemd activation, policy routing и packet capture. Эти пункты остаются открытыми до Linux/hardware gate; `GenerationRuntime` пока является безопасным интерфейсом без подключённого host mutation.

**Следующий шаг:** runtime state/events/reconciler, затем API/auth/WebUI read model; после этого Linux packaging, guard и netns suite.

### Сессия 004 — strict config и безопасный network foundation — 2026-08-23

**Сделано:**

- добавлен strict YAML loader с `KnownFields`, запретом duplicate/unknown keys, второго YAML document, symlink и файлов больше 1 MiB;
- config file на Linux не может быть writable для group/others; environment interpolation отсутствует;
- добавлена CLI-проверка `gateway-vpn --check-config <path>`;
- `config.example.yaml` проходит реальный strict decode и validation;
- реализован read-only Linux preflight для TUN, sysctl paths, systemd и `ip/nft/wg/systemctl`;
- реализована typed policy-routing модель для нескольких модемов;
- overlaps management/LAN/WireGuard, duplicate interface/table/fwmark и reserved/main tables отклоняются до renderer;
- renderer создаёт только modem-specific routes и rules с owned protocol `186`, никогда не вызывает global flush;
- добавлен прямой process executor без shell, доступный только на Linux и только с absolute executable path;
- создан boot-time nftables `PATH_BLOCKED` renderer с owned table `inet gateway_vpn`, policy drop для input/forward/output и минимальными DHCP/API/WireGuard management exceptions;
- nft loader по умолчанию dry-run, при явном mutation сначала выполняет `nft --check`, а существующая owned table заменяется в одной nft transaction без `flush ruleset`.

**Проверено:** полный `go test ./...`, `go vet ./...`, strict example config check и `linux/amd64 CGO_ENABLED=0` cross-build — PASS. Windows preflight корректно возвращает `NOT_READY` и не запускает сетевые команды.

**Не проверено:** синтаксис ruleset реальным `nft`, применение `ip rule/route`, rollback и firewall guard — для этого нужен Linux namespace/стенд. Поэтому mutation API не подключён к runtime.

**Следующий шаг:** безопасный Subscription Manager foundation и затем Mihomo config generator, чтобы получить первый сквозной, но ещё netns-only data-plane candidate.

### Сессия 003 — SQLite, repositories и Linux preflight — 2026-08-23

**Сделано:**

- добавлена embedded migration `000001_initial.sql` с таблицами из архитектурного плана;
- реализован migration runner с последовательностью версий, SHA-256 applied migration, защитой от изменённой/слишком новой схемы и transaction rollback;
- при открытии БД применяются WAL, foreign keys, busy timeout и `synchronous=NORMAL`, права каталога/файла ограничиваются `0700/0600`;
- добавлены `quick_check` и `integrity_check`;
- реализованы repositories модемов и подписок с atomic priority reorder;
- display number, routing table и fwmark модема выделяются монотонными counters и не переиспользуются после удаления ранее принятого устройства;
- реализован канонический repository матрицы `modem × subscription`;
- stale probe result блокируется после смены route/policy generation;
- отключение модема/подписки переопределяет старый `QUALIFIED` и очищает selected node;
- добавлена чистая typed-модель policy routes/rules с проверкой subnet/table/mark/interface conflicts;
- добавлен read-only `gateway-vpn preflight` для Linux capabilities.

**Что проверено:**

- `go test ./...` — PASS для config, db, modem, subscription, pathmatrix, networkplan и preflight;
- `go vet ./...` — PASS;
- Windows build — PASS;
- `linux/amd64`, `CGO_ENABLED=0` cross-build — PASS;
- SQLite `quick_check` и `integrity_check` после migration — PASS;
- повторное применение migration не создаёт вторую запись;
- частично выполнившаяся ошибочная migration полностью откатывается;
- изменение уже применённого SQL определяется по checksum;
- Windows preflight ожидаемо завершился code 1 с `NOT_READY`, не выполняя сетевых команд.

**Найдено и исправлено тестами:** первый вариант matrix reconciliation использовал неоднозначный для SQLite синтаксис `INSERT … SELECT … ON CONFLICT` без `WHERE`; тест получил syntax error около `DO`. Добавлен явный `WHERE 1=1`, после чего полный suite прошёл.

**Ограничение проверки:** `go test -race` в текущей Windows-среде не запустился, потому что race detector требует CGO/C compiler. Race suite переносится в обязательный Linux CI; обычные tests/vet и CGO-free cross-build прошли.

**Следующий шаг:** ownership-aware dry-run/apply слой для `ip rule/route` и boot-time fail-closed nftables template с тестами отсутствия main-table/direct-LAN route.

### Сессия 002 — официальное переименование — 2026-08-23

**Причина:** пользователь уточнил, что название проекта — `Gateway VPN`, а предварительные имена `happ-gateway` и `happctl` использовать нельзя.

**Принятый naming contract:**

- display name: `Gateway VPN`;
- Go module: `gateway-vpn`;
- основной executable и systemd service: `gateway-vpn` / `gateway-vpn.service`;
- административная CLI: `gateway-vpnctl`;
- TUN interface: `gateway-vpn-tun`;
- системные каталоги: `/etc/gateway-vpn`, `/var/lib/gateway-vpn`, `/opt/gateway-vpn`;
- service helpers используют prefix `gateway-vpn-`;
- слово `HAPP` сохраняется только для обозначения форматов/источников VPN-подписок.

**Изменено:** module/import paths, каталоги `cmd`, Makefile outputs, build metadata, bootstrap defaults, example config, README и naming references в архитектурном плане. Архитектура и порядок этапов не изменялись.

**Результат проверки:**

- `gofmt`, `go test ./...` и `go vet ./...` прошли;
- собраны `bin/gateway-vpn.exe` и `bin/gateway-vpnctl.exe`;
- `gateway-vpn --version`, `gateway-vpn --check-defaults` и `gateway-vpnctl --version` завершились с code 0;
- безопасный запуск `gateway-vpn` без команды завершился с code 2 без сетевых изменений;
- старые generated binaries удалены, старые source/module/config identifiers отсутствуют;
- изменение является только переименованием; hardware/Linux gate не выполнялся.

### Сессия 001 — инициализация проекта — 2026-08-23

**Цель:** превратить архитектурный документ в репозиторий и создать первый безопасный проверяемый инкремент.

**Сделано:**

- проверено исходное содержимое workspace: присутствовал только `docs/PLAN_v1.1.md`;
- создан локальный Git-репозиторий с веткой `main`;
- добавлены `.gitignore`, `.editorconfig`, `README.md`, `Makefile` и `go.mod`;
- добавлен `config.example.yaml`, соответствующий bootstrap-разделу плана;
- созданы первые точки входа; их предварительные имена позднее заменены по решению `DEV-005`;
- добавлена build metadata package;
- реализована модель bootstrap-конфигурации и fail-fast validation без внешних библиотек;
- добавлены unit tests для безопасных bind addresses, IPv6 policy, modem adoption, путей secret files и накопления нескольких validation errors;
- основной runtime намеренно оставлен закрытым и возвращает ошибку без сетевых изменений.

**Что получилось:**

- структура исходного кода создана;
- bootstrap defaults и негативные тестовые сценарии описаны кодом;
- сетевые команды, сервисы и маршруты не изменялись.
- официальный архив `go1.26.7.windows-amd64.zip` проверен по SHA-256 `f4f534a486e4bc3387fa18f08208f2f854b7aaea8a08f2a2d829a914a05abb11` и распакован в `.tools` без системной установки;
- `gofmt` выполнен;
- `go test ./...` прошёл: package `internal/config` — `ok`, остальные packages пока не имеют tests;
- `go vet ./...` прошёл;
- первоначальные бинарники и CLI smoke checks прошли; их предварительные имена позднее заменены по решению `DEV-005`;
- запуск Gateway без разрешённой команды завершился с code 2 и сообщением `no network changes were made`.

**Что не получилось / не проверено:**

- hardware spike, nftables, policy routing, USB discovery и Mihomo не проверялись в Windows-среде;
- Docker fallback недоступен, потому что Docker Engine не запущен;
- WSL fallback недоступен из-за `E_ACCESSDENIED`.

**Неуспешный промежуточный запуск:** сразу после распаковки три параллельные команды с раздельными новыми Go cache сообщили, что часть стандартной библиотеки не найдена. Архив имел правильный checksum, нужные файлы присутствовали. Последовательный запуск с одним локальным cache успешно выполнил test/vet/build. До повторения причины этот эпизод считается особенностью локальной Windows-среды, а CI-команды должны выполняться последовательно.

**Следующий шаг:** установить или предоставить Go toolchain, выполнить format/vet/test/build, затем добавить первую SQLite migration и migration runner с тестом применения к пустой БД.
