# Gateway VPN — статус и журнал разработки

**Последнее обновление:** 2026-09-05
**Общее состояние:** `INITIAL_TOPOLOGY_PRECHECK_ORDERING_FIX_CI_PASS / PROFILE_SAFE_APPLY_BACKEND_NEXT / NEW_IMMUTABLE_CANDIDATE_PENDING / HARDWARE_AND_ENDURANCE_GATES_PENDING`
**Текущий этап:** immutable testing release `v0.1.1-testing.f300b25` остаётся опубликованным и неизменным, а stable/latest остаётся `v0.1.0-successor.5723940`. В current source typed initial-topology token теперь проверяется сразу после проверки подписанного релиза, до WireGuard/SSH/пакетных host probes и apply boundary; перед дальнейшим apply сохранена defence-in-depth повторная проверка. Linux netns fixture для direct/bridge handoff, mismatched/unknown/unsupported токенов, snapshots link/address/route/rule без изменения namespace и backend rollback tests прошёл в GitHub Actions run `33924870349` (Linux job `101195028597`, все jobs success). Новый immutable candidate ещё не собирался и current clean Windows two-target gate не засчитан. Следующий software-блок — завершить и отдельно проверить first-install/profile safe-apply backend для `ETHERNET_ETHERNET`, `ONE_ARM_WIREGUARD` и `MIXED`; затем остаются физические Ubuntu Gateway/VPS, HiLink/Keenetic и 24/72-часовые endurance gates.

**Оценка прогресса:** относительно прежнего schema-25 scope программная реализация остаётся примерно `98%`; относительно текущего расширенного обязательного scope программная часть ориентировочно `98%`. Готовность к первой установке на физический стенд — примерно `97%`, полная production-готовность — примерно `84%`. Durable signed-update scheduler, service-route ladder, отдельный signed Mihomo maintenance discovery поверх полного immutable Gateway release, signed Gateway/VPS foundations, complete Gateway restore-point rollback, live Management Fabric observations, exact schema-34 lifecycle matrix и Windows portable delivery source имеют local evidence. Первый clean Windows guest выявил и точно локализовал mapped-key ACL defect без изменения targets; source fix локально проверен, но требует нового immutable candidate и повторения guest gate. Privileged Docker и local Windows 10 не заменяют физические Ubuntu Gateway/VPS, Mihomo/WireGuard/HiLink/Keenetic captures, hardware-validated firmware/USB recovery и RTC S5, а также несокращаемые 24/72-часовые endurance.

Этот файл является отдельным оперативным журналом проекта. Архитектурные требования находятся в `PLAN_v1.1.md` и без отдельного решения не переписываются задним числом.

### Сессия 2026-09-05 — Linux initial-topology preflight fixture и ранняя проверка до mutation

**Сделано:**

- установщик `scripts/install-gateway.sh` теперь декодирует и сверяет typed initial-topology token сразу после проверки подписанного release metadata; это происходит до read-only WireGuard preflight, `systemd`/SSH runtime preparation, APT refresh и apply transaction;
- прежняя проверка возле полного LAN preflight сохранена как defence-in-depth recheck непосредственно перед дальнейшим переходом установки;
- добавлен `test/netns/initial_topology_preflight.sh`: в disposable Linux network namespace он проверяет direct и bridge handoff, mismatch интерфейса, unknown JSON field и отказ для профиля без first-install backend; для каждого запуска сравниваются JSON snapshots link/address/route/rule до и после;
- fixture дополнительно проверяет source-order установщика и запускает четыре durable topology apply/commit/rollback теста; evidence сохраняется в project-local `.cache/netns` и не удаляется автоматически;
- CI и `test/netns/README.md` включают новый fixture.

**Проверено локально:** `go test` для install topology/wizard, Gateway command, distribution, bootstrap/deploy и packaging — PASS; `go vet ./...` для текущего source — PASS; `bash -n` нового fixture и установщика в установленном Git Bash — PASS; `git diff --check` — PASS. Сам root/netns fixture в Windows не запускался: системный WSL shim недоступен (`E_ACCESSDENIED`), Docker daemon также недоступен. Полный Linux fixture должен быть выполнен GitHub CI; hardware/bare-metal evidence этим не заменяется.

**Проверено внешним CI:** GitHub Actions run `33924870349` для commit `3f24c15` завершился `success`. `Repository secret history gate`, `Windows portable deploy contract`, `Go, packaging and syntax gates` и `Linux nftables fail-closed gate` прошли; в Linux job шаг `Prove initial topology handoff is read-only and precedes apply` завершён успешно вместе с полным набором privileged/systemd checks.

**Следующий шаг:** перейти к first-install/profile safe-apply backend для `ETHERNET_ETHERNET`, `ONE_ARM_WIREGUARD` и `MIXED`, сохраняя двухфазное подтверждение и rollback. После source validation, только при отдельном разрешении пользователя, собрать новый production-signed testing candidate и повторить clean Windows two-target gate. Stable/latest, production key и опубликованный `f300b25` в этой сессии не затрагивались.

### Сессия 2026-09-05 — typed initial topology handoff (локальный этап)

**Сделано:**

- добавлен bounded canonical `installtopology.Plan` для четырёх согласованных профилей; до появления backend safe-apply реально разрешён только `ETHERNET_HILINK`;
- интерактивный target wizard теперь возвращает выбранный topology plan;
- topology token проходит через deploy request, signed distribution command, bootstrap и `install-gateway.sh`;
- перед изменениями shell-установщик повторно вызывает read-only `gateway-vpn initial-topology-check` и сверяет token с `--lan-interface/--lan-members`;
- добавлены строгие проверки unknown fields, trailing data, размера token, конфликтов ролей и несовпадения токена с применяемым LAN;
- сохранена обратная совместимость API bootstrap-тестов: если token не передан в библиотечный вызов, он выводится только из уже валидированных LAN-аргументов; сгенерированные команды всегда передают token явно.

**Проверено:** project-local `gofmt`, `go test` для `installtopology`, `installwizard`, `distribution`, `bootstrapinstall`, `deploy`, обоих bootstrap/deploy command packages — PASS; `git diff --check` — PASS. Windows `bash.exe` shim не смог создать WSL-процесс (`E_ACCESSDENIED`), поэтому shell syntax gate перенесён в Linux CI и не засчитан локально.

**Ограничение:** safe-apply backend для `ETHERNET_ETHERNET`, `ONE_ARM_WIREGUARD` и `MIXED` ещё не подключён, поэтому эти профили не предлагаются первой установкой и fail-closed отклоняются от текущего installer action. Token передаётся в текущую install/upgrade transaction, но пока не добавляется в публичный install report, чтобы не менять его schema без отдельной миграции; legacy upgrade без token остаётся совместимым только с сохранением прежней LAN-схемы.

**Следующий шаг:** добавить Linux-side integration fixture для shell preflight/apply ordering и затем выполнить release-level validation перед новым immutable testing candidate. Stable channel и production key не затрагивались.

## Правила ведения

- верхняя часть файла показывает актуальное состояние;
- журнал сессий ведётся в обратном хронологическом порядке;
- для каждой сессии фиксируются сделанное, результат проверки, проблемы, изменения решений и следующий шаг;
- неуспешные эксперименты не удаляются;
- секреты, полные subscription URLs, private keys, SIM identifiers и серийные номера сюда не записываются;
- выполненным считается только проверенный результат; созданный, но не запущенный код отмечается отдельно.

## Режим работы Codex

- штатный уровень мышления для разработки — `High / Высокий`;
- текущий явно подтверждённый пользователем уровень — `xhigh / Очень высокий`; пользователь подтвердил повышение перед новым signed candidate и clean-Windows two-target gate;
- обязательный протокол повышения и возврата уровня хранится в корневом `AGENTS.md`;
- сообщение Codex о рекомендуемом уровне не является переключением;
- перед любым повышением или понижением Codex обязан остановить проектную работу, сообщить уровень и причину и дождаться явного подтверждения переключения;
- перед блоком, которому существенно нужен `xhigh / Очень высокий`, `max / Макс` или `ultra / Ультра`, применяется тот же обязательный stop-and-confirm протокол;
- `Ultra / Ультра` запрашивается только для особо сложной работы, которая действительно выигрывает от нескольких независимых параллельных потоков;
- после завершения такого блока Codex предлагает возврат на `High / Высокий`, останавливается и продолжает только после явного подтверждения; без подтверждения фактический повышенный уровень сохраняется;
- уровень мышления не заменяет автоматические тесты и реальные Linux/VPS/hardware проверки.

## Текущий срез

| Область | Состояние | Комментарий |
|---|---|---|
| Архитектурный план | `DONE / COMPLETE_RESTORE_POINT_ROLLBACK_AMENDED_2026-08-31` | Закреплены generic uplinks/topology/Management Fabric, remote signed sources, independent recovery, two-stage acceptance и complete restore-point retention/manual safety rollback |
| Репозиторий | `IMPLEMENTATION_F300B25_TAGGED / MAIN_DOCS_AHEAD_SYNCED / FULL_CI_RUN_33908523656_PASS / PUBLISHED_IMMUTABLE_PRERELEASE / PUBLIC_BASE_IMMUTABLE` | Exact implementation tag `v0.1.1-testing.f300b25` указывает на `f300b251…`; `origin/main` содержит поверх него только последующие documentation-only записи журнала. Новый Release опубликован как immutable testing prerelease; public stable/latest `v0.1.0-successor.5723940` и Release `378316577` неизменны |
| Этап 0: hardware spike | `NOT_RUN` | Нужны Linux Gateway, Keenetic и хотя бы один HiLink; для отдельной проверки multi-modem failover нужны минимум два модема с разными management-подсетями |
| Этап 1: bootstrap | `UNIVERSAL_WIZARD_V3_SSH_WG_INGRESS_LOCAL_PASS / INPUT_GUIDANCE_SOURCE_PASS / F9A2CB2_FRESH_REINSTALL_UNINSTALL_PASS / G2203D0B_FRESH_REINSTALL_UNINSTALL_PASS / F300B25_PUBLISHED_AND_NATIVE_PASS / CLEAN_WINDOWS_MAPPED_KEY_ROOT_CAUSE_AND_SOURCE_FIX_PASS / REPEAT_CANDIDATE_GATE_PENDING / HARDWARE_PENDING` | Мастер объясняет текущие поля, но zero-to-ready Windows UX ещё должен получить initial topology selection и Back/Edit navigation. Первый `f300b25` guest gate доказал mapped-key ACL defect без target mutation; current source автоматически stages identity в private project-local ACL scope, не меняет original key и показывает actionable reason. Новый candidate и повторный gate pending. Candidate `g2203d0b.crypto5` ранее прошёл signed Gateway/VPS fresh apply и same-version reinstall; Gateway preserve-uninstall восстановил SSH socket/service, LAN, sysctl/firewall и сохранил schema-34 DB |
| Data plane / Mihomo | `F9A2CB2_EXACT_V1.19.30_MIXED_TUN_NETNS_SYSTEMD_PASS / HARDWARE_PENDING` | Exact SHA-256-pinned Mihomo `v1.19.30` фактически прошёл `stack: mixed`, TCP/UDP/DNS hijack, marked SOCKS path, loopback API, SIGKILL fail-closed/restart и production systemd unit финального candidate под отдельным пользователем. SQLite сохраняет traverse-only root `0710`, DB `0600` и secrets `0700`; физический HiLink/Keenetic/mobile path остаётся обязательным |
| Firewall / routing | `SCHEMA_V8_MSS_ROUTE_AWARE_DYNAMIC_MANAGEMENT_AND_TOPOLOGY_NETNS_PASS / HARDWARE_PENDING` | Schema `8` сохраняет counters, TUN/direct и Management Fabric gates, проецирует exact set локальных management-интерфейсов и peer-scoped one-arm rules. Отдельная owned `forward_mss` chain меняет только TCP SYN пользовательского трафика по фактическому route MTU; локальный packet capture подтвердил MSS 1240 при MTU 1280 (direct/Ethernet-путь) и MSS 1260 при MTU 1300 (TUN-путь). Privileged netns подтвердил startup/flush recovery, multi-LAN SSH, `wg-ingress`, topology rollback, единственный direct mark для `wg-ingress`, allowlisted peer и блокировку spoofed source; физический capture остаётся обязательным |
| Modem Manager | `BOUNDED_RECOVERY_LOCAL_PASS / HARDWARE_PENDING` | Physical classifier, durable attempts/cooldown/budget, process-restart cleanup, manual API/WebUI/history и typed root DHCP renew подключены. Firmware API/mobile-session/USB identity actions намеренно suppressed до Huawei E3372h gate |
| WireGuard management | `VPS_MULTI_PEER_WG_MGMT_PRIVILEGED_PASS / GATEWAY_MANY_TO_MANY_PRIVILEGED_PASS / HARDWARE_PENDING` | VPS Hub применяет несколько Gateway/admin peers на fixed `wg-mgmt`. Gateway schema 28 применяет независимые `gvm<N>`; реальный kernel gate доказал два simultaneous handshakes, отдельные fwmark/tables и сохранение ifindex второго link при удалении первого |
| Management Fabric / VPS Hub | `BOTH_ROLES_PRIVILEGED_APPLY_AND_COEXISTENCE_PASS / GATEWAY_RUNTIME_OBSERVATION_PRIVILEGED_PASS / E2E_RELAY_PACKET_3X_PASS / OPERATIONS_DIAGNOSTICS_LOCAL_PASS / VPS_UPDATE_SYSTEMD_GATE_PASS / VPS_LIFECYCLE_GUARD_PASS` | Обе роли имеют parameter-free root apply/recovery. Gateway root observer читает только expected peer каждого applied typed link, control plane атомарно принимает полный generation-bound redacted snapshot и переводит просроченный `REACHABLE` в `STALE`; реальный двух-link kernel gate подтвердил observations и selective removal. VPS update lifecycle сохраняет прежние privileged evidence |
| Удалённые локальные ресурсы | `FIVE_PROFILE_QUALIFICATION_NETNS_PASS / GATEWAY_PREFIX_DNAT_ACL_RETURN_PATH_NETNS_PASS / E2E_ADMIN_RELAY_PACKET_ANTI_SPOOF_PASS` | Typed resources/publications/ACL применяются на VPS и Gateway. Отдельный kernel gate доказывает `GATEWAY_ONLY`, `KEENETIC_WAN`, `VIA_KEENETIC_WAN_ROUTED`, `VIA_WG_ROUTER`, `VIA_DEDICATED_LAN`, exact owned route, `SO_BINDTODEVICE`, declared TCP transport и fail-closed external prerequisites. E2E gate разрешает только exact admin/resource/port и не хранит inner private key на VPS |
| WireGuard ingress | `FULL_LOCAL_KERNEL_LIFECYCLE_PASS / HOST_NOT_RUN` | Schema 23, root-only atomic keys/PSK, managed/external peers, address/subnet conflict checks, one-arm/routed topology, listener allowlist, per-peer access policy, API/WebUI, one-use re-authenticated config/QR, counters/handshake и revoke/delete/rotation реализованы. Privileged Ubuntu netns доказал server/client handshake и удаление revoked peer из kernel; реальный Keenetic/client/Internet path ещё не запускался |
| Subscription Manager | `RESILIENT_REFRESH_LADDER_LOCAL_PASS / LINUX_NOT_RUN` | Active target node → other allowed target nodes → allowed nodes других subscriptions → policy-enabled direct ready-модемы подключены через отдельный Mihomo probe listener; EXCLUDE повторно проверяется под operation lock. Disabled user method обновляет service-only LKG без публикации user path; `Retry-After`, lease, redacted stages и bounded retention покрыты tests |
| Qualification / scheduler | `UNIFIED_FULL_LIMITED_LOCAL_PASS / LINUX_NOT_RUN` | Direct и VPN qualification создают generation-scoped `FULL/LIMITED/FAILED`; LIMITED VPN хранит точный частично доступный node и перед activation повторно проверяет только fresh passed targets. Ranking, hysteresis и direct probes покрыты tests |
| Unified access methods | `SIGNED_FRESH_INSTALL_PASS / HARDWARE_PENDING` | Direct + subscriptions имеют один authenticated ordered list и один server-side read model. Каждый modem показывает direct и все VPN methods; каждая subscription — все modem paths; matrix содержит оба kind. Exact signed candidate прошёл fresh systemd/PID1 и kernel startup acceptance без немедленного обрыва active path |
| Self-health / watchdog | `GATEWAY_19_PLUS_UPDATE_AND_MANAGEMENT_RUNTIME_WORKERS_LOCAL_PASS / VPS_RELAY_ROOT_WATCHDOG_PASS / MANAGEMENT_FABRIC_KERNEL_PROJECTION_PASS` | Базовый фиксированный контур из 19 компонентов не переименован; heartbeat дополнительно имеет явные contracts для automatic update worker и critical-silence Management Fabric observer. Observation failure не вызывает внешний host reboot, а зависший worker обнаруживается. Hardware recovery остаётся внешним gate |
| SQLite | `GATEWAY_V34_AND_VPS_AGENT_V4_EXACT_LIFECYCLE_PASS` | Gateway schema 34 добавляет Management Resource health/probe evidence поверх schema-33 automatic update scheduler; internal lease fields не выдаются API. Contiguous VPS Agent schema 4 хранит public relay allocation и external administrator trust mode без inner private key. v1→current migration, integrity/FK/lifecycle и оба encrypted backup/restore round-trip проходят; disposable exact schema-34/v4 Gateway и VPS installs подтвердили schema/integrity/lifecycle на systemd PID 1 |
| Safe network apply | `FULL_TOPOLOGY_PROFILE_TRANSACTION_PRIVILEGED_PASS / REAL_BARE_METAL_NETWORKD_NOT_RUN` | LAN/Ethernet CRUD/replacement и четыре post-install topology profiles используют один durable broker/LKG snapshot. Transaction координирует stable+legacy networkd paths, interface roles, LAN/DHCP/DNS, firewall, policy routing и `wg-ingress`; impact preview, new-path/WireGuard confirmation, timeout/reboot rollback, strict snapshot hash/pair validation и tamper rejection покрыты tests и privileged Ubuntu gate |
| API / Web UI | `GROUPED_GATEWAY_AND_VPS_LOCAL_PASS / UPDATE_RETENTION_BROWSER_PASS / VPS_DEFENSE_IN_DEPTH_HEADER_FIXED` | Обе роли прошли предметные вкладки при 320×720. Gateway «Система и безопасность» показывает separate update policy, signed sources, complete restore-point history и re-authenticated destructive rollback. Desktop/mobile browser gate не выявил document overflow, clipped actions или console errors. Exact VPS HTTPS gate дополнительно обнаружил отсутствие legacy defense-in-depth `X-Frame-Options`; CSP уже имел `frame-ancestors 'none'`, а header `DENY` добавлен в общий middleware с static/API regression |
| Logging / audit | `GATEWAY_AND_VPS_THEMATIC_LOCAL_PASS / UTC_ONLY_UI / VPS_ROOT_SNAPSHOT_BOUNDARY_PASS / BARE_METAL_PENDING` | Gateway logging contract сохраняет один UTC timeline без timezone setting; filter ввод/подсказка интерпретируются как UTC. VPS Hub применяет второй redaction pass к URL credentials/query, authorization, WireGuard keys/PSK и structured secrets. Реальные VPS retention/journald и Gateway OpenSSH/SFTP ещё не проверены на железе |
| Diagnostic bundle | `GATEWAY_AND_VPS_CODE_PASS / VPS_OWNERSHIP_PRIVILEGED_PASS / REAL_HOST_PENDING` | Обе роли формируют memory-only bounded ZIP с manifest/SHA-256 и partial section codes. VPS bundle включает sanitized configuration, SQLite schema/integrity/counts, recent logs, root operations snapshot и Fabric watchdog; maximum 12 MiB archive/8 MiB plaintext, secrets исключены. Реальные production-host `ip/nft/wg/journalctl` данные ещё не собирались |
| Backup / restore | `MANDATORY_ROLE_SEPARATED_WEBUI_PASS / SCHEMA29_4_RELAY_ROUNDTRIP_PASS / GATEWAY_EXACT_SIGNED_RECOVERY_PASS / VPS_SIGKILL_RECOVERY_PASS / BARE_METAL_PENDING` | Gateway `.gvpn` сохраняет exact `wg-admin` key/contour/relay/tunnel/trust mode; VPS `.gvpn-vps` сохраняет paired Gateway/external E2E admin/relay association, port/rate/burst без inner key. Decrypted DB, staged tree, same-VPS apply и rollback assertions проходят. Cross-role restore запрещён; bare-metal VPS power cut ещё не выполнялся |
| Signed update | `MIHOMO_MAINTENANCE_LOCAL_BROWSER_PASS / AUTOMATIC_SERVICE_ROUTE_MAX_DELAY_LOCAL_PASS / GATEWAY_COMPLETE_RESTORE_SYSTEMD_PASS / VPS_TRANSACTION_SYSTEMD_SIGKILL_ROLLBACK_PASS / BOTH_ROLES_SHARED_LIFECYCLE_LOCK_PASS / EXACT_SCHEMA33_LIFECYCLE_MATRIX_PASS / HARDWARE_POWER_CUT_PENDING` | Отдельный signed Mihomo manifest разрешает только exact-compatible forward core в полном immutable Gateway release; staging повторно связывает archive с commit/host/API contracts и остаётся manual-only. Schema-33 worker имеет durable lease/deadlines/jitter, separate check/download/apply, bounded maximum apply delay без unsafe forced Apply, отдельную VPN/direct service-route ladder, UTC window, manual/automatic ownership, maintenance suppression, fresh FULL+management readiness и ambiguous-intent no-redispatch. Exact fresh/reinstall/uninstall/recovery/host-contract upgrade matrix прошла; real bare-metal power-cut остаётся pending |
| Packaging | `PRODUCTION_GVKEY_SIGNED_TESTING_F300B25 / PUBLISHED_IMMUTABLE_PRERELEASE / PUBLIC_REMOTE_14_OF_14_SHA256_PASS / NATIVE_WINDOWS_9_OF_9_PASS / PUBLIC_5723940_LATEST_IMMUTABLE` | Production signer `fceb4a54…eda60c` подписал exact `0.1.1-testing.f300b25`: Gateway `57`, VPS `35`, channel `5` artifacts. Publisher проверил подписи и exact tag до публикации. Fresh unauthenticated download `14/14` совпал по SHA-256; channel signature и five-artifact identity повторно проверены. Windows EXE прошёл positive/negative native trust и PS5.1 contract. Release immutable/prerelease; stable/latest не изменён |
| Uninstall | `WEBUI_DURABLE_GUARDIAN_EXACT_NEW_PID1_PASS / VPS_UNINSTALL_LIFECYCLE_SYSTEMD_PASS / HARDWARE_POWER_CUT_PENDING` | Gateway exact `ga7a783b` прошёл guardian/new-PID1 recovery с побайтным сохранением данных. Текущий VPS uninstaller под реальным systemd PID 1 доказанно блокируется общим lock, nonterminal и corrupt journal до mutation, принимает terminal audit journal и сохраняет Hub state плюс `wg-mgmt.conf` |
| Endurance | `HARNESS_LINUX_SMOKE_PASS / 24H_72H_NOT_STARTED` | Linux-only CLI требует TLS 1.3/explicit CA и 0600 password file, держит session secrets в памяти, сохраняет minute samples и verified start/end diagnostics, автоматически оценивает restart/gaps/goroutines/FD/RSS/heap/live objects/SQLite retention. Smoke end-to-end прошёл, но не является gate; 24h developer и 72h hardware release ещё не запускались |
| Traffic accounting | `EXACT_INSTALL_UPDATE_PASS / HARDWARE_PENDING` | Option A реализован: authoritative `user_upload/user_download/service_upload/service_download`, reset/epoch, session/daily/monthly totals, Mihomo cross-check, API/CSV/UI. Schema-v2 counters прошли fresh boot и signed update; мобильный hardware budget/cross-check ещё `NOT_RUN` |
| Автоматические тесты | `F300B25_FULL_CI_33908523656_PASS / CURRENT_FULL_LINUX_GO_TEST_AND_VET_PASS / CURRENT_WINDOWS_BROAD_ACL_INTEGRATION_PASS / UBUNTU24_SYSTEMD_PASS / GATEWAY_RESTORE_POINT_REBOOT_GATE_PASS / EXACT_VPS_UPDATE_GATE_PASS` | Previous exact release source `f300b25` имеет полный зелёный GitHub CI. Current mapped-key fix прошёл полный `go test ./...` и `go vet ./...` в существующем Linux builder, Windows integration с намеренно broad source ACL и изменённые Windows package tests; remote CI для нового source ещё pending. Privileged Gateway/VPS recovery evidence не изменено |

## Матрица доказательств Definition of Done

Статусы ниже относятся к каждому точному пункту §20 `PLAN_v1.1.md`: `PASS_LOCAL` означает, что требование доказано текущими автоматическими/privileged Docker gates; `IN_PROGRESS_LOCAL` — новое требование реализовано только частично; `PARTIAL_EXTERNAL` — локальная часть прошла, а обязательное физическое или публичное evidence отсутствует; `NOT_RUN_EXTERNAL` — требуемый длительный или hardware gate не запускался. Архитектурные чекбоксы в `PLAN_v1.1.md` не используются как изменяемый журнал.

| DoD | Статус | Авторитетное evidence и остающийся gate |
|---:|---|---|
| 1 | `NOT_RUN_EXTERNAL` | H2 требует минимум два реальных HiLink, включая Huawei E3372h-325, и целевой Keenetic; runbook готов, hardware evidence отсутствует |
| 2 | `PARTIAL_EXTERNAL` | Unit/integration/netns failure matrix и точечные systemd recovery gates проходят; полная H1/H2 matrix на физическом packet path не запускалась |
| 3 | `PARTIAL_EXTERNAL` | Kernel/netns fail-closed и IPv6 policy проверены; обязательные IPv4/DNS/IPv6 captures за Keenetic и через реальные HiLink отсутствуют |
| 4 | `PASS_LOCAL` | Invalid subscription/config сохраняют LKG; exact signed format-2 candidate имеет доказанные migration `13 → 16`, controlled rollback и boot/process recovery `16 → 13`, finalization/reboot и terminal no-op |
| 5 | `PARTIAL_EXTERNAL` | ON/OFF startup policy подключена к Linux boot ID, runtime и firewall actuator. Exact remote netns gate доказал invalidation при ON, одно exact direct LKG recovery при OFF, same-boot restart, next-boot direct-only reset и kernel quarantine; реальный reboot на физическом Gateway ещё не выполнен |
| 6 | `PARTIAL_EXTERNAL` | Production broker и synthetic WireGuard handshake/failover прошли; реальный VPS/provider UDP и переключение между physical modem uplinks не проверены |
| 7 | `PASS_LOCAL` | Exact Ubuntu/systemd install слушает HTTPS только на management LAN; auth/bootstrap/session/CSRF/rate-limit и bind allowlist покрыты tests |
| 8 | `PASS_LOCAL` | Logging, API serializers и diagnostic bundle используют fixed allowlists/redaction; adversarial tests не допускают secrets/paths/backend text |
| 9 | `PARTIAL_EXTERNAL` | Installer/update/rollback/backup/restore/uninstall прошли clean disposable systemd и power-cut gates; произвольный bare-metal clean host и real VPS provider остаются внешними |
| 10 | `PASS_LOCAL` | README/NETWORKING/OPERATIONS/H1/H2, Management Fabric/topology/local-resource contract и фактический safe-apply lifecycle входят в exact reproducible signed schema-34 validation tree; production publication остаётся отдельным внешним gate |
| 11 | `PASS_LOCAL` | Mihomo `v1.19.30` и SHA-256 находятся в signed metadata; `test/fixtures/mihomo/expected-api-schema.json` сохраняет API contract |
| 12 | `PASS_LOCAL` | Firewall schema `6`, storage/API/CSV/UI реализуют только authoritative total user/service counters; per-subscription traffic отсутствует |
| 13 | `PARTIAL_EXTERNAL` | Unified repository, selector и mutually-exclusive direct/TUN actuator отклоняют stale policy/route generations, ранжируют FULL/LIMITED и сохраняют точную runtime identity; физический multi-operator gate отсутствует |
| 14 | `PASS_LOCAL` | Matcher fallback, manual include/exclude, target CRUD/priority и malicious/empty/name fixtures покрыты integration tests |
| 15 | `PASS_LOCAL` | Independent target-outage confirmation и `DEGRADED_TARGET` recovery не запускают node/subscription/modem loop; scheduler/reconciler tests проходят |
| 16 | `PARTIAL_EXTERNAL` | Stable identity, priority/history и reverse-order event fixtures проходят; реальные USB identity sources, десять reboot/replug и H2 не запускались |
| 17 | `PASS_LOCAL` | Канонический server-side modem×access-method DTO содержит direct и VPN, quality/evidence/freshness/active reason; Modems, Subscriptions и Path Matrix используют одни path IDs без frontend health synthesis |
| 18 | `PARTIAL_EXTERNAL` | Quality/method/modem/node ranker, route generations, direct firewall generation и TUN/direct mutual exclusion покрыты unit/integration и exact remote kernel netns run `33128823746`; physical loss/capture ещё отсутствуют |
| 19 | `PARTIAL_EXTERNAL` | Restart-safe stable interval/cooldown/failback hysteresis покрыты durable tests; реальный recovered preferred modem не проверен |
| 20 | `PARTIAL_EXTERNAL` | Per-modem fwmark/table, DHCP, DNS, proxy и WireGuard route isolation проходят render/kernel/netns gates; реальные operator subnets/interfaces не зафиксированы |
| 21 | `PARTIAL_EXTERNAL` | Исправленный successor `0.1.1-testing.f300b25` production-signed и опубликован immutable prerelease из exact tag. Fresh unauthenticated download, SHA-256 `14/14`, channel/five-role signature и native Windows `9/9` прошли. Clean Windows two-target gate запущен, но итог ещё не получен; real two-host `READY` отсутствует |
| 22 | `PASS_LOCAL` | Exact signed systemd watchdog обнаруживает hang/crash/restart storm, имеет bounded dependency-aware recovery и публикует UI/events/diagnostics evidence |
| 23 | `PASS_LOCAL` | External outage отделён от local failure; default host reboot выключен, optional action имеет durable budget и transaction suppression |
| 24 | `NOT_RUN_EXTERNAL` | Exact endurance harness и smoke готовы, но обязательные непрерывные 24- и 72-часовые runs не запускались |
| 25 | `PASS_LOCAL` | Immutable direct method автоматически создаётся, не удаляется, enable/reorder работает через единый API/UI, а independent service-refresh permission изменяется отдельно |
| 26 | `PASS_LOCAL` | AUTO/INCLUDE/EXCLUDE и partial preferred order управляются UI/API, сохраняются по fingerprint, переносятся на новый version-scoped node ID и реально определяют первый FULL/equal LIMITED node; active policy transition имеет sticky-first и reorder не обрывает путь |
| 27 | `PASS_LOCAL` | Scheduled/manual refresh имеет durable lease/status, bounded retry/route ladder и single-flight. Manual API сразу возвращает существующий/новый operation ID; GET/list/clear API и persistent redacted WebUI timeline покрыты tests |
| 28 | `PASS_LOCAL` | Domain tests и exact remote Linux integration используют persistent SQLite и production nft/ip backends: gate ON остаётся blocked, gate OFF открывает только exact LKG `wan0+fwmark`, same-boot restart сохраняет tuple, следующий boot сбрасывает direct-only и возвращает `PATH_BLOCKED` без unmarked route |
| 29 | `PASS_LOCAL` | Canonical uplink model используется matrix/selector/Mihomo/firewall/routing и WebUI для HiLink и Ethernet. Ethernet create/replace/address/delete проходят durable safe apply, timeout/reboot rollback, stable NIC identity и runtime reconciliation; modem-only write fallback отсутствует |
| 30 | `PASS_LOCAL` | Direct-only whitelist targets выполняются только через direct runner, создают generation-scoped `WHITELIST_ONLY`, не квалифицируют VPN и не запускают physical modem recovery; classifier, manual probe и ranking покрыты tests |
| 31 | `PARTIAL_EXTERNAL` | Durable controller/runner, physical-only classifier, process-restart cleanup, typed root broker DHCP renew, API/WebUI policy/history и suppression tests проходят. Firmware mobile reconnect, verified driver rebind/USB reset/hub action требуют реального Huawei E3372h hardware gate |
| 32 | `PASS_LOCAL` | Authenticated API/WebUI управляет server и managed/external peers; root-only keys/PSK, config/QR re-auth, revoke/rotation/delete, per-peer policy, one-arm validation и listener firewall реализованы. Privileged netns доказал реальный handshake и удаление revoked peer из kernel |
| 33 | `PASS_LOCAL` | Generic network roles, impact previews и safe apply/rollback подключены. Mutable controls имеют точные русские descriptions, native `title`, `aria-label` и открываемую кнопку `?` для mouse/keyboard/touch; destructive actions отдельно подтверждаются |
| 34 | `PASS_LOCAL` | Один canonical namespaced journald stream фильтруется десятью WebUI tabs. Bounded redacted current/archive exports, rotation/retention/disk budget, root/group modes и read-only SFTP membership проверены локально; TCP/22 остаётся только management-scoped |
| 35 | `PASS_LOCAL` | Reboot/shutdown используют password re-auth, typed phrase, countdown, durable operation/audit и transaction exclusion. RTC power-cycle скрыт до root-owned hardware verification marker; Docker/VM не считаются доказательством S5 wake |
| 36 | `PASS_LOCAL` | Четыре topology profiles переключаются одной durable transaction с impact preview, full-contour LKG snapshot, strict hash/path-pair validation, coordinated roles/networkd/DHCP-DNS/firewall/policy routing/`wg-ingress`, new-path либо fresh WireGuard confirmation и timeout/reboot rollback. Privileged Ubuntu gate доказал apply/commit/rollback и отклонение tampered snapshot до mutation |
| 37 | `PASS_LOCAL` | Обе роли имеют parameter-free root apply, simultaneous Gateway `gvm<N>` и multi-peer VPS `wg-mgmt`. Privileged gates доказали реальные handshakes, per-uplink fwmark/table, receipt/rollback и selective removal без reset неизменённого link; hardware/provider failover остаётся внешним общим gate |
| 38 | `PASS_LOCAL` | Durable resource/ACL generations применяются двойным VPS+Gateway firewall. Packet gates доказывают default deny, точный admin/resource ACL, cross-link denial, prefix DNAT, return path и coexistence с foreign UFW/Docker/Amnezia objects |
| 39 | `PASS_LOCAL` | Typed resource/publication/ACL CRUD, generation-bound health, unified API/WebUI и пять access profiles реализованы. Privileged Ubuntu netns gate доказал exact kernel route/interface/transport для Gateway, Keenetic WAN/routed, ROUTER_ROUTED WireGuard и dedicated LAN; недоступный return path и management-interface default route не публикуются |
| 40 | `PASS_LOCAL` | Per-`site × resource × VPS link` aliases, strict overlap validation и typed equal-prefix translation реализованы. Двух-VPS kernel gate доказал независимые `/24` aliases, точное prefix DNAT и отсутствие cross-link доступа |
| 41 | `PASS_LOCAL` | Gateway и VPS Hub имеют сгруппированные предметные разделы, отдельный Management Fabric contour, thematic logs и accessible contextual help. Responsive browser gate на 320×720 подтвердил компактный mobile selector, отсутствие page overflow и необрезанные controls; desktop navigation и active-state sync сохранены |
| 42 | `PASS_LOCAL` | Gateway-terminated `wg-admin`, fixed UDP/51822, external inner peers и allowlisted/rate-limited VPS relay реализованы в schema 29/4 API/WebUI/root plans/watchdogs. Privileged Ubuntu gate трижды доказал реальный inner handshake, allow/deny/wrong-port/plaintext/spoofed-source matrix, counters и отсутствие inner key/peer на VPS; обе backup-роли сохраняют topology без нарушения trust boundary |
| 43 | `PASS_LOCAL` | Lightweight Go Agent/Hub, Management Fabric, backup, logs/diagnostics и signed pointer-update transaction реализованы. Privileged update/finalize/SIGKILL recovery, semantic terminal/corrupt journal, shared lifecycle lock и real systemd uninstall gates проходят; portable Windows delivery учитывается отдельно в пункте 45 |
| 44 | `PASS_LOCAL` | VPS владеет отдельной nft table, Gateway — только schema-5 owned chains/sets; обе стороны не делают global flush. Privileged apply/rollback/selective-removal gates сохраняют UFW/Docker/Amnezia-like tables, а Gateway дополнительно сохраняет foreign interfaces |
| 45 | `PARTIAL_EXTERNAL` | Linux SSH orchestrator, Windows OpenSSH adapter и current production-signed `.exe` `f300b25` прошли native version/commit, channel/signer/self-identity, wrong hash/signer, tampered signature/PE и PS5.1 hash-before-exec/project-local-finally-cleanup. USER@HOST/host+port/staging defects исправлены. Новый clean Windows Sandbox two-target deploy запущен и ожидает интерактивного завершения; результат ещё не засчитан |
| 46 | `PASS_LOCAL` | Gateway `.gvpn` и VPS `.gvpn-vps` имеют раздельные authenticated roles, WebUI download/preview/re-auth/typed apply, corruption/cross-role rejection, same-device quarantine, import-as-new key rotation и journalled rollback; VPS test имитирует SIGKILL/fresh-boot recovery |
| 47 | `PARTIAL_EXTERNAL` | Signed GitHub Stable/Testing manual check/download, exact HTTPS/upload, two-stage pointer transaction, complete restore-point retention/UI и privileged manual rollback/reboot recovery прошли. Current `f300b25` опубликован immutable prerelease и проверен fresh public `14/14` SHA-256/signature; stable/latest остался `v0.1.0-successor.5723940`. Bare-metal power-cut остаётся внешним gate |

**Итог аудита:** `31 PASS_LOCAL`, `0 IN_PROGRESS_LOCAL`, `14 PARTIAL_EXTERNAL`, `2 NOT_RUN_EXTERNAL`. Полный Definition of Done не достигнут: обе backup-роли, information architecture, privileged Gateway/VPS Management Fabric, five-profile local-resource qualification, end-to-end administrator relay, единая topology transaction, Hub operations/diagnostics, exact Gateway/VPS lifecycle и automatic remote Gateway update core закрыты локально. Исправленный current testing prerelease опубликован immutable и независимо проверен; clean Windows VM gate запущен, но ещё не завершён. Затем остаются H1/H2/VPS/RTC и реальные 24/72h evidence.

## Ближайший следующий инкремент

Следующий локальный инкремент — завершить уже запущенный clean Windows 10/11 x64 two-target workflow для immutable `v0.1.1-testing.f300b25`, сохранить redacted report и проверить обе установленные роли снаружи Sandbox. Ожидаемый изолированный итог — `INSTALLED_NOT_READY`/exit `3`, поскольку endpoint `198.51.100.1` является TEST-NET; это допустимо только при полном успешном apply обеих ролей и явных pending external-path diagnostics. Production `.gvkey` повторно не открывать и candidate не пересобирать; stable/latest не менять.

## Критический путь до release

Расширенный universal-installer successor локально реализует data-plane, refresh, generic uplinks, direct/VPN read model, node preferences, startup policy, SSH/OpenSSH, входящий WireGuard, тематические SFTP/Hub-логи, bounded diagnostics, privileged many-to-many Management Fabric с live observations, проверенный inner `wg-admin` relay с role backup round-trip, единую post-install смену topology, signed VPS update и Gateway automatic scheduler/service-route core с complete restore-point recovery. Exact post-fix schema-34/4 Gateway+VPS lifecycle, Windows delivery source, dependency hardening, production-signed immutable publication, public hash/signature и native Windows trust закрыты для `f300b251…`. Clean Windows VM сейчас выполняется; затем остаются внешние physical/endurance gates. Production key существует отдельно и повторно для этого candidate не открывается; stable/latest не меняются.

После закрытого local Management Resources contour отдельный путь до production release включает реальные multi-Gateway/multi-VPS/Keenetic/HiLink проверки, найденные исправления, 24-часовой developer и несокращаемый 72-часовой release endurance. Прежний ориентир `4–8 дней` относился к старому single-VPS scope и больше не используется как обещание. Без фактического доступа к Linux/VPS/оборудованию можно передать install-ready candidate, но нельзя честно поставить production status `DONE`.

## Известные ограничения и блокеры

1. Текущая host-среда — Windows, команды `nft`, `ip` и `sqlite3` на host отсутствуют; Linux gates доступны внутри Docker Desktop.
2. WSL 2 доступен; Ubuntu 24.04 сейчас остановлен, а Docker Desktop использует отдельный running `docker-desktop` distro. Основные Linux/systemd gates выполняются в одноразовых Docker-контейнерах.
3. Docker Desktop privileged execution явно разрешён пользователем. Exact `g2203d0b.crypto5` дважды воспроизводимо собран, прошёл signed verification, native Windows PE smoke, fresh apply/idempotency обеих Ubuntu 24 systemd-ролей и Gateway preserve-uninstall. Предыдущие exact gates отдельно доказали new-PID1 и forced rollback. Docker в любом случае не заменяет реальный systemd host reboot, USB HiLink и двухмашинный VPS gate.
4. Системный Go отсутствует. После очистки заново получен официальный portable Go `1.26.7`, SHA-256 `f4f534a486e4bc3387fa18f08208f2f854b7aaea8a08f2a2d829a914a05abb11`, путь `.tools/go1.26.7/go/bin/go.exe`; локальные module/build caches воспроизводимы и могут удаляться только между test-блоками. Production/CI по-прежнему требуют воспроизводимую Linux toolchain setup.
5. Обычная установка поддерживает `1..N` модемов и полностью работоспособна с одним. Этап 0 для multi-modem feature нельзя считать пройденным без реального packet capture минимум через два модема с разными management-подсетями; это стендовое требование, а не минимум для эксплуатации.
6. Публичный remote и GitHub CI работают; GitHub release immutability включена. Exact run `33175739792` для `1b90ffcb99b25f79954cbc1b4bde7bcc0140175d` завершён `success`, включая оба jobs. CI не получает release secrets. Permanent encrypted production key и byte-identical backup готовы; новый tag/Release для `1b90ffc` не создавался.
7. Disposable-signed candidate `0.1.0-successor.g2203d0b.crypto5` дважды воспроизводимо собран из source `2203d0b223f5de2fb4620c3b11039b193a63d80c`; Gateway/VPS/channel verification, native Windows PE smoke, fresh/reinstall systemd lifecycle обеих ролей и Gateway preserve-uninstall прошли для этой exact source identity. Это не заменяет bare-metal reboot/power cut, произвольный физический NIC topology или USB hotplug.
8. VPS signed installer прошёл privileged Docker systemd acceptance на Ubuntu 22.04/24.04/26.04; current uninstaller дополнительно прошёл preserve/reinstall/purge на Ubuntu 24.04. Vanilla Ubuntu 20.04 доказанно отклоняется без Pro/ESM до mutation. Положительный 20.04, Debian 12, реальный VPS reboot/provider firewall и внешний UDP handshake остаются `NOT_RUN`.
9. Schema 34 Gateway / schema 4 VPS Agent, обязательные role backups, topology safe apply, remote update/complete restore points, Management Resource health, `x/crypto v0.55.0` и privileged Gateway/VPS runtimes прошли current exact disposable lifecycle для `g2203d0b.crypto5`. Опубликованный production-signed release по-прежнему относится к прежнему scope; clean Windows VM и новый production successor не закрыты.

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
| DEV-098 | 2026-08-25 | Signed role/channel metadata использует canonical commit timestamp; bundle повторно проверяет Gateway/VPS signatures и re-hash всех четырёх local channel artifacts | Invocation time не должен менять signed identity, а валидная подпись старого manifest не доказывает, что локальный upload file после build не был заменён |
| DEV-099 | 2026-08-25 | GitHub CI не получает release secrets, использует official Actions только по full commit SHA и отдельно запускает race suite и root netns fail-closed gate на Ubuntu 24.04 | PR/CI automation не должна иметь путь к long-lived signing key; Windows cross-build не заменяет реальный nft/netns run |
| DEV-100 | 2026-08-25 | Long-lived Ed25519 key остаётся только на trusted builder; GitHub publisher создаёт exact draft и никогда не публикует его автоматически | GitHub Actions secret расширил бы signing trust boundary, а release immutability применяется только при публикации и требует прикрепить все assets к draft заранее |
| DEV-101 | 2026-08-25 | Все shell entrypoints и netns harness фиксируются в Git как executable `100755` | Документированные `./scripts/...` и CI `./test/netns/...` иначе ломаются сразу после clean Linux checkout |
| DEV-102 | 2026-08-25 | Root ownership/chown остаются обязательными production gates, а non-root unit fixtures используют только package-private injected ownership operations; Linux test отдельно доказывает отказ non-root transaction root | GitHub race suite обязан работать без запуска всего test job от root, но тестовая изоляция не должна ослаблять реальную privilege boundary |
| DEV-103 | 2026-08-25 | Все scalar generation sets в runtime и install nftables templates используют поддерживаемый Ubuntu 24.04 datatype `mark`; standalone netns gate создаёт точные production service users до загрузки symbolic `skuid` | nftables 1.0.9 отвергает unqualified `type integer`, а symbolic UID разрешается во время parsing ruleset |
| DEV-104 | 2026-08-25 | Netns assertions под `set -o pipefail` не используют early-exit `grep -q` на выводе `nft`/`ip`, а JSON-проверки допускают whitespace | SIGPIPE upstream-процесса и различия JSON formatting не должны превращать успешное fail-closed recovery в ложный CI failure |
| DEV-105 | 2026-08-25 | Production bundle до draft обязан повторяться дважды из одного exact clean commit, одинаковых pinned inputs и одного signer; `dist/` сравнивается byte-for-byte | Успешная signature verification доказывает целостность конкретного artifact, но не воспроизводимость сборки либо отсутствие invocation-time state |
| DEV-106 | 2026-08-25 | Первый rehearsal pin — официальный Mihomo `v1.19.30` `linux-amd64-v1`, archive SHA-256 `cbe553d0319a414bd3a372c5976a252155b2c4882b66bce88a4d6bba9571a553`, binary SHA-256 `20ba567571d9ca642bedecbb01f8092cab0f1679100087ef1a4a2efac0ed5494`; production promotion требует повторной official metadata и runtime/API проверки | Нельзя подменять exact release input mutable `latest`; version probe и archive hash сами по себе ещё не доказывают совместимость data plane |
| DEV-107 | 2026-08-25 | Runtime destructive restore unit с `Conflicts=` не включается в boot target; отдельный бесконфликтный boot restore unit завершает pending transaction до network recovery/socket/control | Condition-false conflict unit в общей boot transaction может вытеснить management jobs ещё до вычисления condition; runtime stop/resume и boot ordering являются разными задачами |
| DEV-108 | 2026-08-25 | Повтор signed Gateway installer допускает отсутствие direct DNS только при точном root-owned completed report и совпадающих immutable `current`/`recovery` pointers, после чего всё равно выполняет полный existing-install audit | Собственный fail-closed firewall обязан блокировать direct DNS, поэтому без строго ограниченного исключения корректная повторная команда не была идемпотентной |
| DEV-109 | 2026-08-25 | Все generated bootstrap/deploy shell commands запускают Bash как `bash --norc -ceu` | `sshd` remote command может заставить Bash читать стандартный Ubuntu `.bashrc`; при `nounset` обращение `/etc/bash.bashrc` к unset `PS1` останавливало signed preflight до mutation. Доверенный workflow не должен зависеть от dotfiles удалённого пользователя |
| DEV-110 | 2026-08-25 | Gateway/VPS release archives перечисляют явные top-level entries и никогда не включают отдельную tar-запись `.`/`./` | Bootstrap и runtime update используют один strict extractor, который отвергает standalone archive root entry. Старый `tar ... .` создавал structurally invalid artifact, хотя проверка уже распакованного signed tree проходила |
| DEV-111 | 2026-08-26 | Two-host deploy создаёт private `0700` OpenSSH ControlMaster directory и переиспользует заранее pinned established sessions через Gateway/VPS firewall apply; в конце masters закрываются через `-O exit`, sockets проверяются и directory удаляется | Каждый прежний `SSHExecutor.Run` открывал новый TCP connection. Gateway installer правильно закрыл TCP/22, поэтому следующий key-preparation phase был недостижим. Открывать SSH hole в fail-closed firewall нельзя; multiplexing сохраняет существующую authenticated connection без ослабления ruleset |
| DEV-112 | 2026-08-26 | Policy-rule observer запускает `ip -N -json`, а decoder filtered owned routes допускает отсутствующее поле `protocol`, проверяя его строго при наличии | Ubuntu iproute2 выводит protocol 186 как symbolic `bgp`; при `route show ... protocol 186` kernel-side filter работает, но JSON вообще опускает поле protocol. Прежний decoder не видел только что применённые owned rule/routes и ошибочно завершал verification |
| DEV-113 | 2026-08-26 | `gateway-vpn-deploy` сам создаёт отсутствующие компоненты parent directory для локального admin WireGuard config с mode `0700`; каждый существующий component проверяется через `Lstat`, symlink запрещён, а первая missing boundary не может находиться непосредственно под group/other-writable parent | Сгенерированная «одна команда» на clean admin host завершалась до SSH, если `~/.config/gateway-vpn` ещё не существовал. Ручной `mkdir` противоречит zero-from-scratch contract; обычный `MkdirAll` мог бы пройти через symlink/shared writable path |
| DEV-114 | 2026-08-26 | Root update/restore helpers не делают `chmod` уже корректных Gateway-owned DB path; unsafe type/symlink по-прежнему отклоняется, а capabilities не расширяются `CAP_FOWNER` | Hardened snapshot unit с `CAP_DAC_OVERRIDE` не мог chmod уже правильный `0600` файл другого owner; повторная мутация прав не нужна и неоправданно расширяла бы root boundary |
| DEV-115 | 2026-08-26 | Updater после создания и перед atomic rename нормализует каждый real candidate release directory в `root:root 0755`, а signed files — строго `0755/0644`; tree повторно signature-verify | `UMask=0077` создавал root-only `0700` directories, из-за чего unprivileged control service не мог исполнить новый binary, хотя file mode был правильным |
| DEV-116 | 2026-08-26 | Installer активирует finalize timer через `enable --now`, readiness проверяет его active state, а successful update имеет fixed `ExecStartPost` для того же timer | Простое `enable` после уже активного `timers.target` оставляло 24h transaction в `STABILIZING` до следующего reboot |
| DEV-117 | 2026-08-26 | Successful boot update recovery ставит fixed broker socket/control start jobs через `systemctl start --no-block`; failed recovery не выполняет post-step | Rollback quiesce отменял ожидавшие boot jobs управления; synchronous start создал бы dependency cycle с network recovery, а no-block сохраняет systemd ordering и fail-closed failure semantics |
| DEV-118 | 2026-08-26 | Portable restore после upload остаётся только `STAGED`; WebUI Apply атомарно создаёт `APPLY_REQUESTED` с одноразовым 256-bit nonce, который не возвращается API | `pending-restore.json` раньше не отличал проверенный upload от подтверждённого destructive action, поэтому обычный reboot мог применить backup без согласия пользователя |
| DEV-119 | 2026-08-26 | Успешный restore rollback сначала фиксирует root journal `ROLLED_BACK`, затем отзывает nonce и возвращает operation в `STAGED`; повторный rollback идемпотентен, а новый Apply получает другой nonce | Power cut после rollback, но до marker update мог повторно удалить уже возвращённые original destinations либо автоматически повторить destructive apply |
| DEV-120 | 2026-08-26 | Boot restore unit имеет `RemainAfterExit=yes` и удаляет только root-owned regular `0600` `.recovery-record-<digits>` перед state decision | Несколько `Wants=` повторно запускали helper в одном boot, а SIGKILL оставлял безопасный, но неограниченно накапливающийся atomic temp record |
| DEV-121 | 2026-08-26 | Endurance использует authenticated `/api/v1/system/runtime-metrics`: только bounded Go/process counters, Linux RSS/FD и отдельный per-session rate limit 20/min | RSS/FD доступны через `/proc`, но число goroutines иначе нельзя достоверно измерять снаружи; endpoint не должен раскрывать argv/environment/config/IDs/secrets или позволять hammering `runtime.ReadMemStats` |
| DEV-122 | 2026-08-26 | DB retention запускается немедленно и каждые 10 минут, удаляет максимум 500 time-series rows и 20 versions за транзакционный pass, а известный backlog повторяет через 250 ms; DB row удаляется до payload directory, orphan scan идемпотентен, `.payload-*` не трогается, автоматический `VACUUM` запрещён | Размер SQLite должен сходиться к PLAN §12.3 без длинной write lock; power loss между DB commit и filesystem delete не должен навсегда сохранять proxy payload либо затронуть текущий refresh |
| DEV-123 | 2026-08-26 | Каждый diagnostic bundle содержит fixed `database/retention.json`: policy, table counts/time ranges, aggregate version states/excess и DB/WAL/page/freelist bytes без DB path или IDs | Endurance обязан доказать SQLite integrity и соответствие retention, а одной process-memory telemetry для этого недостаточно |
| DEV-124 | 2026-08-26 | Reference endurance CLI имеет только `smoke`, fixed 24h developer и fixed 72h release profiles; developer/release требуют clean VCS-stamped harness и versioned Gateway, release — отдельные hardware environment+typed confirmation | Короткий тест, modified binary или Docker нельзя случайно представить как production endurance; credentials/session material не должны попадать в argv, environment или artifacts |
| DEV-125 | 2026-08-26 | Фактический reasoning effort меняется только после явного подтверждения пользователя; при любом предлагаемом повышении или понижении Codex останавливает работу до подтверждения. Текущий подтверждённый уровень — `xhigh` | Ранее уведомление о допустимом возврате на `High` было ошибочно воспринято как состоявшееся переключение, хотя пользователь уровень не менял |
| DEV-126 | 2026-08-26 | Shared state root имеет mode `0710 gateway-vpn:gateway-vpn`; изолированные data-plane units запускаются systemd с `Group=gateway-vpn` только для traverse, а secrets и остальные private children сохраняют `0700` | Exact signed DHCP install обнаружил, что прежний parent `0700` делает service-owned child недостижимым. `0710` разрешает только проход к известному child и не разрешает group list/read/write root |
| DEV-127 | 2026-08-26 | Добавить обязательный 24/7 self-health supervisor с bounded recovery ladder и гибкой audited policy в WebUI; host reboot default-off и никогда не запускается только из-за внешней потери Internet/modems/subscriptions/VPS | 100% uptime физически не гарантируется, но локальный crash/hang должен автоматически обнаруживаться и восстанавливаться без direct leak, destructive reboot loop или вмешательства в активную maintenance transaction |
| DEV-128 | 2026-08-26 | dnsmasq запускается systemd сразу как `gateway-vpn-dns:gateway-vpn`; config не выполняет второй privilege drop, unit не имеет `CAP_SETUID/CAP_SETGID`. Clean-host dependency — `dnsmasq-base`; wildcard/LAN TCP/UDP 53 listener блокирует DHCP install до mutation | Второй exact apply и isolated transient-unit test разделили Unix path permissions и runtime drop: systemd-owned identity стабильно стартует. Полный пакет `dnsmasq` дополнительно включает общий daemon, который занимает `0.0.0.0/[::]:53` и не должен автоматически устанавливаться либо останавливаться Gateway installer-ом |
| DEV-129 | 2026-08-26 | Preflight получает DNS listeners двумя явными командами `ss -ltn` и `ss -lun`, затем проверяет wildcard и LAN address | На Ubuntu 24.04 combined `ss -lntu` в focused acceptance не вернул активный TCP/53 listener, поэтому ложный dry-run PASS был обнаружен до mutation; раздельные queries доказанно возвращают и блокируют конфликт |
| DEV-130 | 2026-08-26 | Lease/state dnsmasq вынесен в отдельный systemd `StateDirectory=gateway-vpn-dnsmasq` mode `0700`; service UID не получает write/list к общему `/var/lib/gateway-vpn`, legacy child больше не создаётся tmpfiles | Даже корректные UID/GID и systemd-owned process не должны зависеть от записи lease внутрь закрытого application tree. Изолированный transient test доказал запуск, lease creation и DHCP bind с отдельным top-level state root |
| DEV-131 | 2026-08-26 | Port-53 conflict gate выполняется только после доказанной fresh-install classification; exact existing install вместо этого сверяет signed release, generated dnsmasq config, active service и state/lease identity. Lease обязан быть `gateway-vpn-dns:gateway-vpn 0644` внутри parent `0700` | Успешно работающий managed dnsmasq закономерно слушает LAN:53, поэтому общий preflight ломал идемпотентность. dnsmasq явно создаёт lease `0644`, но закрытый parent `0700` сохраняет confidentiality; ожидание `0600` противоречило фактическому daemon contract |
| DEV-132 | 2026-08-26 | Root watchdog имеет только fixed signed paths/actions, читает live SQLite через новый `mode=ro/query_only` handle на каждый цикл, сохраняет restart/reboot budget и fsync directory **до** privileged action; внешний outage и resource pressure не reboot-eligible, host reboot default-off | Supervisor не должен стать command proxy, создавать root-owned WAL, терять budget при kill/power loss либо превращать недоступность оператора/VPS в destructive reboot loop |
| DEV-133 | 2026-08-26 | Control plane использует `Type=notify`, systemd `WatchdogSec=120s`, пятисекундный DB/reconcile heartbeat и fatal exit любого critical worker; root supervisor стартует только после update/restore/network recovery, требует fresh status/control evidence и всегда применяет `PATH_BLOCKED` перед component restart/reboot | Наличие PID/active unit не доказывает живой event loop. Recovery не должен гоняться с destructive transaction, а signed update не считается healthy без работающего нового watchdog и control heartbeat |
| DEV-134 | 2026-08-26 | Traffic Option A использует четыре authoritative named nftables counters: пользовательские upload/download и отдельные service upload/download; epoch определяется boot ID и kernel nft table handle, а Mihomo служит cross-check, не источником истины | Служебные probes/subscription/update/WireGuard/HiLink операции расходуют мобильный трафик, но не должны смешиваться с пользовательским total или ошибочно атрибутироваться подписке |
| DEV-135 | 2026-08-26 | Update/recovery/resume units используют `Wants/After`, а не `Requires` для firewall/guard, которые update runtime сам перезапускает одной systemd transaction до и после pointer switch | Реальный transient systemd probe доказал, что unit с `Requires=` при собственном restart required-unit получает `SIGTERM` и входит в restart loop; weak activation сохраняет ordering без self-termination |
| DEV-136 | 2026-08-26 | Database fixtures обязаны воспроизводиться побайтно: migration-generated timestamps фиксируются, WAL salts канонизируются с полным пересчётом rolling checksums, а malformed WAL создаются только после канонизации валидного образа | Случайные fixture bytes ломают exact build reproducibility и скрывают непреднамерённые изменения corruption-моделей; простая подмена salt без frame checksum сделала бы WAL невалидным по другой причине |
| DEV-137 | 2026-08-26 | Pointer-only signed update разрешён только при равном вычисленном `host_contract_sha256` всех packaged systemd unit/socket/timer files; Gateway release metadata format повышен до `2` | Release archive может содержать новые root-owned units, но существующий updater атомарно переключает только immutable release/DB. Молчаливое сохранение старых units создаёт непроверенный hybrid host; несовместимость должна отклоняться ещё при unprivileged staging до mutation |
| DEV-138 | 2026-08-26 | `recovery` остаётся на старом release до конца stability window и атомарно переводится на новый только successful finalization; `FINALIZED`/`ROLLED_BACK` timer tick является code-0 no-op, а resume после recovery очищает failed-state update/finalize units | Иначе следующую update-транзакцию выполняет произвольно старый binary, который может не понимать текущую DB/release metadata, а ожидаемый rollback оставляет 24/7 host в ложном `systemctl --failed` |
| DEV-139 | 2026-08-27 | Exact `0.1.0-traffic.3c13b09` считать локально готовым к первой установке на физическое железо; production-ready статус не присваивать до publish, real hardware/VPS и 24/72h gates | Reproducible build, fresh install, schema migration/rollback/finalize и новый PID 1 доказаны, но Docker/disposable signer не подтверждают USB, mobile network, provider VPS и длительную эксплуатацию |
| DEV-140 | 2026-08-27 | Разделить первый hardware gate на H1 с одним модемом и полный H2 минимум с двумя модемами; только H2 закрывает multi-modem часть этапа 0 и Definition of Done | Рабочая установка обязана поддерживать `1..N` и не требовать резервного modem, но failover/reverse-order/раздельные operator routes невозможно доказать на одном устройстве |
| DEV-141 | 2026-08-27 | `0.1.0-validation.47297a7` считать локальным docs-complete successor для hardware handoff; будущая публичная сборка получает новую version и не переиспользует обе локальные validation identities | Signed OPERATIONS входит в immutable release tree, поэтому исправленный H1/H2 runbook нужно доказать внутри exact artifact, но disposable acceptance key и локальная version не должны превращаться в production identity задним числом |
| DEV-142 | 2026-08-27 | Вести явную 24-пунктную DoD evidence matrix в `PROJECT_STATUS.md`, не отмечая архитектурные чекбоксы `PLAN_v1.1.md` задним числом | Локальный test PASS, обязательный physical/public gate и полный project DONE имеют разную доказательную силу; одна статусная строка не должна смешивать эти уровни |
| DEV-143 | 2026-08-27 | После явного разрешения отправить только `main`, проверить exact remote SHA и дождаться terminal GitHub Actions result; tag/release/key оставить отдельным полномочием | Push исходников и создание production trust identity имеют разный риск и не должны объединяться одним подразумеваемым разрешением |
| DEV-144 | 2026-08-27 | Production release key генерируется только CLI на trusted Linux builder в заранее созданном `0700` absolute same-directory storage вне Git worktree; pair создаётся exclusive, fsync-ится и перечитывается для cryptographic match | Ошибочный относительный путь, shared directory, symlink component или повторный запуск не должны создать/заменить долговременную trust identity; выбор backup storage остаётся операторским security-решением |
| DEV-145 | 2026-08-27 | Первый public hardware candidate должен использовать новую pre-release SemVer (предпочтительно `0.1.0-rc.1`), а stable `0.1.0` не резервировать до успешных H1/H2 | Public namespace пуст, но production-ready stable version до physical/endurance gates создала бы ложное обещание качества; tag/version создаются только отдельной авторизованной transaction |
| DEV-146 | 2026-08-27 | Private release key при каждом verify/backup/sign повторно проходит absolute-path, secure-directory, no-symlink, regular-file и permission checks; все CLI-команды, использующие private key, работают только на trusted Linux builder | Проверка только во время keygen не обнаруживает последующее перемещение key, ослабление mode или запуск signing operation на неподходящем host |
| DEV-147 | 2026-08-27 | Primary и backup keypair проверяются cryptographically private→public; backup создаётся exclusive в другом заранее созданном secure directory, fsync-ится, перечитывается и не перезаписывается | Обычное копирование без self-verification может сохранить повреждённую или mismatched пару; CLI доказывает целостность копии, но encryption и физическую независимость носителя обязан обеспечить оператор |
| DEV-148 | 2026-08-27 | Изменение release-key lifecycle считается локально принятым только после exact clean-commit double-build с одним disposable verified primary/backup signer, byte-for-byte сравнением полного `dist` и canonical verification через backup public key | Unit/CLI tests не доказывают, что ранний pair gate совместим со всеми четырьмя role artifacts, что signing остаётся воспроизводимым и что private material не попадает в bundle |
| DEV-149 | 2026-08-27 | Штатный permanent signing secret хранить как один переносимый encrypted `gateway-vpn-production.gvkey`; рядом с проектом, на Gateway или VPS его не размещать. Специальная флешка/LUKS не обязательна; требуется byte-identical backup в другом каталоге и отдельно известная только владельцу passphrase | Пользователю нужен простой file-based lifecycle, а безопасность at-rest уже обеспечивает authenticated Argon2id + AES-256-GCM container; Gateway для проверки обновлений получает только public key |
| DEV-150 | 2026-08-27 | Passphrase `.gvkey` принимает минимум 10 Unicode-символов и максимум 256 UTF-8 байт; ведущие/концевые пробелы, CR/LF/NUL и invalid UTF-8 запрещены, 14+ символов остаются рекомендацией | Пользователь явно выбрал минимум 10 символов; rune count не позволяет короткому кириллическому паролю пройти только из-за многобайтового UTF-8 представления |
| DEV-151 | 2026-08-27 | Plaintext PEM и временный интерактивный passphrase-файл существуют только в проверенном `0700` `/dev/shm`; несекретный helper собирается отдельно в `/tmp`, поскольку `/dev/shm` допустимо и желательно монтировать `noexec`; оба каталога удаляются trap при success/error/signal | Production workflow не должен требовать executable secret tmpfs и не должен оставлять private material после неуспешной сборки; реальный `noexec /dev/shm` smoke доказал разделение |
| DEV-152 | 2026-08-27 | Созданный пользователем permanent `.gvkey` считать production signing identity; не раскрывать/копировать его в repo, Gateway, VPS, logs или release assets. До отдельного разрешения не создавать tag/Release и не подписывать публичную RC | Hidden workflow завершил create+backup+verify, внешний audit подтвердил format/byte identity; полномочие создать key не является полномочием публиковать release |
| DEV-153 | 2026-08-27 | Generated Gateway release command является universal interactive command и не содержит build-time NIC/CIDR/DHCP policy. Target-side wizard показывает все links, разрешает только unused Ethernet без IPv4/default/active SSH route, проверяет выбранный private CIDR и требует post-preflight token `INSTALL`; explicit mode остаётся для CI/SSH automation | Release не должен пересобираться под конкретный компьютер. Молчаливый выбор среди нескольких NIC, использование modem/management uplink или subnet overlap может оборвать управление либо создать неверный LAN path; до финального подтверждения persistent host mutation запрещена |
| DEV-154 | 2026-08-27 | Один или несколько подтверждённых safe Ethernet ports объединяются в owned bridge `gateway-vpn-lan`; единственный transit IPv4, WebUI, DHCP/DNS и OpenSSH относятся к bridge. nftables разрешает новый TCP/22 только через bridge, не через HiLink/uplink. Первый install с включением всех свободных ports выполняется с локальной консоли, потому что несущий активную SSH-сессию интерфейс fail-closed исключается | Одна IPv4-подсеть не должна назначаться нескольким независимым L3 interfaces. Bridge даёт один стабильный адрес независимо от физического порта, а исключение uplink/HiLink не превращает удобство SSH в внешнюю management exposure или риск обрыва installer |
| DEV-155 | 2026-08-27 | `Прямой интернет` и подписки являются единым ordered access-method list. Выбор выполняется как `FULL → best LIMITED score → method priority → modem priority → preferred node rank → sticky tie`; direct создаётся автоматически, не удаляется и может быть отключён для user routing | Gateway должен искать самый функциональный глобальный доступ через одного или нескольких операторов, сохраняя управляемый priority и не превращая direct в случайную утечку мимо выбранного метода |
| DEV-156 | 2026-08-27 | Node policy хранится по stable fingerprint как `AUTO/INCLUDE/EXCLUDE` и optional preferred rank; missing nodes сохраняются исторически и восстанавливают решение после возвращения. Обновление disabled user method продолжается независимо от routing enable | Refresh меняет version/node IDs и имена, но не должен терять ручной выбор, неожиданно включать EXCLUDE или лишать выключенную подписку возможности снова стать пригодной |
| DEV-157 | 2026-08-27 | Startup block становится явной ON/OFF policy, но OFF не отключает nftables: до полной qualification разрешается только минимально проверенный LKG/direct generation. Boot-scoped direct-only override сбрасывается после reboot; служебный direct refresh регулируется отдельно | Пользователь может выбрать более быстрый старт без неконтролируемого forwarding, а диагностический direct-only режим не должен незаметно стать постоянной политикой или отключить обновление подписок |
| DEV-158 | 2026-08-27 | Active direct path хранить отдельным `runtime_state.active_direct_path_id` с FK на `direct_modem_paths`; VPN сохраняет `active_path_id`. Firewall schema v3 открывает TUN и direct только взаимоисключающе, а LIMITED VPN перед открытием gate повторно проверяет все ранее прошедшие fresh targets | Полиморфный FK либо modem-only direct identity не позволяют доказать точный путь при recovery. LIMITED нельзя считать безопасно активированным только по aggregate score без node/target evidence и post-selection recheck |
| DEV-159 | 2026-08-27 | Subscription refresh использует отдельный service-only Mihomo probe selector и последовательность `active target node → другие allowed target nodes → allowed nodes других subscriptions → direct ready-modems`, не изменяя `gateway-vpn-active`/runtime/firewall user gate. Disabled user method сохраняет LKG как qualification-only provider; EXCLUDE повторно проверяется после получения общего operation lock. Одна operation ограничена 5 минутами, 20 секундами на route, 1024 VPN attempts и 32768 redacted steps | Общий selector без сериализации смешивает маршруты конкурентных probes; выключение user method не должно лишать auto-refresh или случайно разрешать user path. Явные bounds не позволяют большой/враждебной подписке бесконечно удерживать worker и раздувать SQLite, а limit фиксируется в operation status до direct fallback |
| DEV-160 | 2026-08-27 | Linux boot ID хранится отдельно от process lifetime. Gate ON на каждом новом boot атомарно инвалидирует qualification evidence; gate OFF разрешает ровно одно восстановление только прежнего exact enabled LKG/direct tuple, после bounded transport/routing checks, и немедленно планирует полную qualification. Firewall/quarantine не отключаются. Same-boot restart сохраняет tuple; temporary direct-only сбрасывается только при новом boot | Настройка быстрого старта не должна превращаться в общий bypass либо считать process restart перезагрузкой. Exact boot identity, одноразовое разрешение и generation checks ограничивают окно восстановления прежним известным путём, а stale/corrupt state остаётся fail-closed |
| DEV-161 | 2026-08-27 | Manual subscription refresh сначала атомарно получает durable lease и создаёт `QUEUED` operation, затем передаётся в bounded dispatcher `2 workers / 64 capacity`; HTTP request context после ответа не используется. Повторный manual/scheduled request возвращает owner ID действующего lease. На process restart старые leases освобождаются, а QUEUED/RUNNING operations терминализируются `PROCESS_RESTART` | UI должен немедленно получить стабильный ID без второго fetch, goroutine/queue не могут расти без границ, а crash не должен оставлять ложное вечное RUNNING или блокировать refresh до 30-минутного lease timeout |
| DEV-162 | 2026-08-28 | Единственный Web/API read model является `modem × access method` и содержит как immutable direct row каждого модема, так и VPN row каждой subscription; effective freshness, quality, evidence, active identity и reason вычисляются только backend. Modems и Subscriptions получают проекции тех же typed rows, а не пересчитывают health | Три логические вкладки не должны показывать разные состояния одного пути. Frontend aggregation скрывала direct path и могла считать просроченный LIMITED результат рабочим |
| DEV-163 | 2026-08-28 | Preferred node API принимает active version node IDs, но durable порядок хранит по fingerprint. Runtime переводит fingerprint в новый version-scoped ID, последовательно проверяет preferred nodes до первого FULL, использует rank раньше latency при равном LIMITED score и ставит active transition node первым. Reorder не закрывает текущий путь и применяется при следующей qualification/failover | Пользователю нужны постоянный основной сервер и упорядоченный резерв без потери выбора после refresh. Одновременное переключение при редактировании порядка создало бы flap; хранение node ID не пережило бы immutable version update |
| DEV-164 | 2026-08-28 | Перед повторными update health/rollback/recovery starts сбрасывать start-limit только у фиксированного набора owned firewall/guard/runtime units после установки `PATH_BLOCKED`; реальные start/health ошибки не маскировать | Systemd считает даже успешные oneshot starts: несколько штатных quiesce/activation/rollback cycles блокировали firewall, затем network-recovery, хотя сами команды были корректны. Scoped `reset-failed` не открывает data path и не касается чужих units |
| DEV-165 | 2026-08-28 | Сокращение 24-часового update stability window допускается только source-only release-gate helper с двойным подтверждением, exact update ID и состоянием `STABILIZING`; результат доказывает finalizer mechanics, но никогда не доказывает реальную 24-часовую стабильность | Ожидание суток не нужно для проверки atomic recovery pointer/checksum/terminal state, однако искусственное время нельзя смешивать с endurance evidence или production acceptance |
| DEV-166 | 2026-08-28 | Startup-policy integration выполняется четырьмя отдельными process phases над persistent SQLite и одним isolated kernel namespace; production `firewall-boot`, `FirewallBackend` и `RoutingBackend` являются actuator-ами, а изменяемый boot ID моделирует host boundary | Domain tests не доказывают соответствие DB intent фактическим nft sets/policy route. Раздельные процессы выявляют ложное manufacture-reboot, а новый boot обязан закрыть kernel до control recovery и не создавать unmarked default route |
| DEV-167 | 2026-08-28 | Все проверки побайтного равенства owned host-policy файлов в installer выполнять через `cmp -s --`, а не через `[[ value == $(cat file) ]]`; наличие `cmp` входит в ранний host preflight | Правая часть `==` внутри Bash `[[ ]]` без кавычек является glob pattern. Поэтому корректный systemd drop-in, начинающийся с `[Service]`, и bridge netdev с `[NetDev]` ложно отвергались после успешной установки и вызывали безопасный rollback |
| DEV-168 | 2026-08-28 | Transit LAN static address должен применяться `systemd-networkd` с `ConfigureWithoutCarrier=yes`; `RequiredForOnline=no` сохраняется отдельно | Non-blocking wait-online сам по себе только убирает задержку boot. Без carrier networkd создавал bridge, но оставлял его `configuring` без LAN IP, из-за чего required management bind перезапускался до подключения кабеля вместо работоспособного offline control plane |
| DEV-169 | 2026-08-28 | Физический выход обобщается до canonical `uplink` типов `HILINK` и `ETHERNET`; существующий `modems.id` атомарно становится `uplinks.id` того же значения, а path/node/target IDs сохраняются | Параллельные modem-only и generic writable модели дали бы расходящиеся ranking, generations и runtime identity; сохранение ID удерживает audit/LKG/history однозначными |
| DEV-170 | 2026-08-28 | NIC хранится по stable hardware identity отдельно от current ifname; Ethernet uplink создаётся только на интерфейсе без активной роли, а replacement требует expected generation, переводит uplink в configuring и инвалидирует только его paths | Linux ifname может измениться либо карта может быть заменена. Простая замена строки без optimistic generation/safe apply могла бы перенести route на уже занятую карту и лишить управления |
| DEV-171 | 2026-08-28 | Probe target получает один из классов `GLOBAL_REQUIRED`, `GLOBAL_OPTIONAL`, `WHITELIST_INDICATOR`, `SERVICE_ENDPOINT`; whitelist indicator выполняется только direct и не участвует в VPN qualification или modem hardware recovery | Доступность Яндекса/операторского белого списка при недоступном глобальном Internet доказывает ограничение оператора, а не исправность VPN и не зависание USB-модема |
| DEV-172 | 2026-08-28 | `wg-ingress` имеет отдельные server/peer/route/runtime сущности и secret-file key lifecycle, не смешивается с `wg-mgmt`; managed peer private key допустим только как secret ref, external peer не имеет private key | Входящий пользовательский трафик и удалённое управление имеют разные trust/routing boundaries. Хранение private key в SQLite/API/list/diagnostics нарушило бы контракт секретов |
| DEV-173 | 2026-08-28 | Modem recovery получает durable policy/runtime/attempt budget и выполняет только последовательность DHCP→HiLink API→mobile session→verified USB actions; whitelist/VPN/global target outage не запускает hardware reset | Неограниченные resets/reboots ухудшают 24/7 работу и могут циклически отключать исправный модем при операторской фильтрации |
| DEV-174 | 2026-08-28 | Journald остаётся authoritative; тематические WebUI вкладки являются фильтрами одного stream, а `/var/log/gateway-vpn` содержит только bounded redacted exports для штатного OpenSSH/SFTP через management paths | Несколько независимых журналов расходились бы по событиям и retention; отдельный SFTP daemon/account не нужен и расширил бы поверхность атаки |
| DEV-175 | 2026-08-28 | Ручная проверка `GLOBAL_*` target выполняет fresh direct requalification всех eligible uplinks и VPN requalification; `WHITELIST_INDICATOR` выполняет только fresh direct requalification, а `SERVICE_ENDPOINT` не допускается в user-access probe | Старое fresh evidence не должно скрывать изменение операторского фильтра. Whitelist probe через VPN дал бы ложную диагностику, а service endpoint не может объявить пользовательский Internet рабочим |
| DEV-176 | 2026-08-28 | Modem recovery принимает только четыре физические причины; ручная кнопка заново проверяет discovery/carrier/lease. Root broker принимает только `uplink_id + enum action + policy_generation`, повторно читает active attempt/interface из SQLite и пока исполняет только fixed networkd DHCP renew | Global/whitelist/VPN/subscription/routing outage не должен перезапускать исправный USB. Непроверенные firmware/sysfs actions безопаснее явно подавить до E3372h hardware identity gate |
| DEV-177 | 2026-08-28 | Ethernet create, replacement и DHCP/static mutation выполняются тем же durable safe-apply engine по stable NIC ID, expected generation и typed manifest v2; root повторно разрешает current ifname и сохраняет только owned networkd state до explicit confirmation | Ifname и карта могут измениться, а прямой CRUD из WebUI мог бы оборвать management, создать overlap либо оставить DB/networkd в смешанном состоянии после timeout/reboot |
| DEV-178 | 2026-08-28 | Ручное питание отделено от watchdog: password re-auth + точная фраза + отменяемый countdown, durable operation/audit и root allowlist из трёх enum. RTC power-cycle доступен только при executable `rtcwake`, wakealarm, signed template unit и root-owned marker успешного физического S5 test | HTTP не должен быть command/systemd proxy. Само наличие RTC не доказывает включение из S5, поэтому непроверенное железо не получает кнопку с ложной гарантией, а update/restore/network/install транзакции нельзя прерывать ручным power action |
| DEV-179 | 2026-08-28 | Ethernet persistent configuration и observed DHCP state хранятся раздельно; stable identity использует MAC только при Linux `addr_assign_type=0`, а удаление disabled uplink является durable safe-apply с сохранением canonical row до confirmation | Runtime DHCP lease не должен стирать пользовательский DNS/заменяемую конфигурацию; randomized MAC не является hardware identity; немедленный SQL DELETE лишил бы rollback path history и owned networkd snapshot |
| DEV-180 | 2026-08-29 | Watchdog policy v2 имеет фиксированные 16 компонентов, typed thresholds и per-component `MONITOR_ONLY/RECONCILE/RESTART`; внешний connectivity outage подавляет local recovery/reboot, но не мониторинг | Один общий restart toggle не позволяет безопасно отделить наблюдение от автоматического вмешательства. Произвольный unit/command из WebUI нарушил бы signed root boundary |
| DEV-181 | 2026-08-29 | First-install SSH/SFTP рекомендуется и включён по умолчанию, но является явным интерактивным выбором; automation opt-out только `--disable-ssh`. При включении OpenSSH обязан пройти config/service/listener checks, а TCP/22 разрешается только через owned LAN bridge; при opt-out rule отсутствует | SSH нужен для администрирования/SFTP, но установка на любой host не должна молча навязывать daemon. Wildcard listener обеспечивает все выбранные LAN ports, а interface-scoped firewall исключает exposure через uplink/HiLink |
| DEV-182 | 2026-08-29 | Gateway controller отдельно владеет `10.80.0.0/24 dev wg-mgmt protocol 186`; watchdog строго принимает числовые JSON-поля `ip -N -json` как number либо decimal string и отдельно классифицирует route mismatch и stale handshake | `/32` address не создаёт management `/24` route. Ubuntu 24.04 выдаёт protocol/table как строки; parser только числовых JSON literals ложно объявлял исправный contour сломанным и мог запустить лишний recovery |
| DEV-183 | 2026-08-29 | Desktop sidebar является flex-column: navigation прокручивается в отдельной области, logout остаётся отдельным нижним action без absolute overlay | При 720px viewport абсолютный logout перекрывал «Система и безопасность» и точный клик фактически отзывал session. DOM-only smoke не обнаруживал этот usability/security defect |
| DEV-184 | 2026-08-29 | `wg-ingress` отделён от служебного `wg-mgmt`; server и peers имеют durable desired/applied generation, managed либо external key mode, routed/one-arm topology и fixed interface `wg-ingress` | Входящий пользовательский трафик и управление Gateway имеют разные trust/policy/lifecycle; объединение интерфейсов создало бы loop и расширило AllowedIPs управления |
| DEV-185 | 2026-08-29 | Managed peer private keys и PSK хранятся только root-only файлами, не в SQLite; `.conf`/QR выдаются только после свежего пароля одноразовым 90-second grant. Revoke удаляет peer из kernel, delete разрешён только после revoke, rotation отзывает старый профиль | Обычный list API, backup metadata, журнал и diagnostic bundle не должны становиться каналом утечки client private key; повторное скачивание требует явного доказательства текущей сессии |
| DEV-186 | 2026-08-29 | Firewall schema 4 содержит отдельный allowlisted set входящих WireGuard listeners; пустой/невалидный listener, apply error либо disabled server полностью удаляет `wg-ingress` из kernel. One-arm egress обязан ссылаться на явно назначенный enabled uplink | Wildcard UDP listener и частично применённый peer contour могли открыть незапланированный внешний интерфейс либо оставить обход policy routing |
| DEV-187 | 2026-08-29 | Journald namespace остаётся единственным authoritative источником, WebUI использует десять allowlisted тематических фильтров, а SFTP получает только bounded redacted current/archive exports через группу `gateway-vpn-log-readers` | Независимые журналы расходились бы; прямой доступ Ubuntu-account к application state либо широкому system journal нарушил бы least privilege |
| DEV-188 | 2026-08-29 | Watchdog contour расширен до 17 fixed components: `logging_pipeline` проверяет journald service, desired/applied export generation, безопасные directory/file modes, freshness и size budget. Recovery не принимает path/unit из WebUI | SFTP-файлы являются эксплуатационной функцией 24/7 и не должны незаметно переставать обновляться либо бесконтрольно заполнять диск |
| DEV-189 | 2026-08-29 | Contextual help сохраняет точные ручные descriptions и добавляет каждому mutable control `title`, `aria-label` и нативно открываемую кнопку `?`; она доступна мышью, клавиатурой и касанием | Один hover-only tooltip не работает на сенсорных устройствах и плохо доступен с клавиатуры/screen reader, а техническое имя поля не является объяснением последствия |
| DEV-190 | 2026-08-29 | Перед каждым installer-side `sshd -t` используется только фиксированный `/run/sshd`: `/run` и существующий directory обязаны быть real `root:root 0755`; отсутствующий directory создаётся без configurable path, а preflight-вариант удаляет только созданный им пустой runtime directory | На чистой Ubuntu пакет `openssh-server` устанавливается до первого запуска `ssh.service`; systemd ещё не создал `RuntimeDirectory=sshd`, поэтому прямой `sshd -t` ложно отклонял исправную конфигурацию. Symlink/unsafe permissions нельзя исправлять или принимать автоматически |
| DEV-191 | 2026-08-29 | Root network broker получает write-доступ только к точному `/var/lib/gateway-vpn/secrets/wireguard-ingress`, тогда как весь parent secrets tree остаётся read-only; каталог заранее создаётся `root:root 0700`. Underlying broker error пишется только в bounded privileged journal, клиент получает стабильный redacted code | Общий `ReadOnlyPaths=/var/lib/gateway-vpn/secrets` заблокировал initial server-key creation. Расширять write boundary на все секреты либо возвращать filesystem root cause через Web/API нельзя |
| DEV-192 | 2026-08-29 | First-install marker v20 отдельно фиксирует enabled/active состояния `ssh.service` и `ssh.socket`, а recovery/uninstall точно восстанавливают оба и идемпотентно возвращают log-reader membership. Маркеры 14/16/18 остаются читаемыми; неизвестное legacy socket-state не угадывается. Официальный active `ssh.socket` принимается preflight как штатный владелец TCP/22 | Ubuntu 24.04 package install может активировать socket unit независимо от service. Прежний rollback оставлял TCP/22 занятым, блокировал retry и мог менять исходную socket-activation policy; старый marker не содержит данных для безопасного ретроспективного предположения |
| DEV-193 | 2026-08-29 | Installer readiness проверяет supervisor `status.json` schema v1 и control-plane `control.json` schema v2 как два независимых versioned контракта | Worker-level heartbeat расширил control payload до v2, но статический installer probe остался на v1 и ложно отклонил полностью поднятый management contour |
| DEV-194 | 2026-08-29 | Recovery helper восстановления systemd state всегда возвращает success после учёта результата через `record_failure`; ожидаемые отрицательные `is-enabled`/`is-active` probes не могут завершить весь script через `set -e` | Успешно остановленный `ssh.socket` давал exit 1 проверке «ещё active?»; этот корректный отрицательный ответ вытекал как status функции, сохранял active marker и прерывал дальнейшее восстановление |
| DEV-195 | 2026-08-29 | WebUI removal запускается только после password re-auth, точной фразы и выбора `preserve data` либо `purge data`; завершение выполняет отдельный фиксированный root-owned systemd job после остановки WebUI. Установленные системные пакеты по умолчанию не удаляются, optional dependency cleanup обязан быть отдельным явно опасным выбором | Процесс не может надёжно удалить самого себя в HTTP request. Exact pre-install state восстанавливается только для owned/snapshotted настроек; автоматический `apt autoremove` способен удалить пакеты, уже используемые другим ПО, и не равен побайтовому rollback ОС |
| DEV-196 | 2026-08-29 | Идемпотентный `gateway-vpn-network-recovery.service` сохраняет rerun-on-demand семантику, но отключает systemd start-rate limit через `StartLimitIntervalSec=0`; реальные failures по-прежнему блокируют dependents | First install последовательно поднимает broker/watchdog/control/DHCP, каждый из которых требует либо хочет inactive oneshot recovery. Пять корректных runs исчерпывали default burst, а шестой post-`wg-ingress` restart получал ложный dependency failure. `RemainAfterExit` изменил бы process-restart recovery contract, а локальный reset только в installer не защитил бы другие штатные быстрые restarts |
| DEV-197 | 2026-08-29 | Release/systemd gates используют только canonical generic-uplink runtime states; retired modem-only `ALL_MODEMS_OFFLINE` запрещён отдельным packaging regression. Steady-state validator допускается считать стабильным только после серии последовательных запусков над одним неизменённым installed root | Schema/runtime уже обобщены с модемов на `HILINK/ETHERNET`, поэтому старое имя в acceptance script ложно отклоняло корректный runtime. Один повтор после стартового timeout не отделяет transient readiness от воспроизводимой systemd гонки |
| DEV-198 | 2026-08-29 | Изменение signed `host_contract_sha256` выполняется отдельной cold-snapshot installer transaction: старый/новый release проверяются совместимыми собственными verifier-ами, candidate verifier требует exact gap-free DB history, nested install наследует внешний lock, boot helper восстанавливает только allowlisted Gateway paths, а completion marker сохраняет исходное до первой установки состояние ОС | Pointer-only update намеренно не меняет root lifecycle. Новый verifier не может ретроспективно вычислить старый host contract, synthetic snapshot parents нельзя накладывать на `/`, а marker внутреннего reinstall иначе подменил бы pre-install sysctl/LAN/SSH evidence состоянием перед upgrade |
| DEV-199 | 2026-08-29 | Host-upgrade recovery guardian unit/helper/enable symlink исключаются из destructive restore и остаются активны до durable `rolled-back-*`; прежняя guardian projection возвращается только после terminal receipt и `sync` | SIGKILL первой recovery не должен удалить единственный boot helper при всё ещё активном `APPLYING` marker; следующий boot обязан иметь возможность безопасно повторить rollback |
| DEV-200 | 2026-08-29 | Boot recovery namespace считает `/boot/grub` optional и открывает для exact replacement owned root directories их parents `/opt`, `/var/lib`, `/var/log`; helper остаётся fixed signed без пользовательских параметров и проверяет marker/snapshot до mutation | Required missing `/boot/grub` давал `226/NAMESPACE`, а отдельные bind mounts самих `/opt/gateway-vpn`/`/var/lib/gateway-vpn` запрещали `rm -rf` root directory как read-only mount point |
| DEV-201 | 2026-08-29 | Durable WebUI uninstall публикует exclusive root-owned marker, копирует hash-bound signed tooling вне удаляемого release tree, удерживает общий lifecycle FD9 lock и удаляет active marker только после fsync terminal receipt. Повторная установка принимает оставшиеся guardian unit/helper только при строгой root-owned receipt schema; GRUB rollback повторяется по durable install marker даже после уже удалённого drop-in | HTTP-процесс и `/opt/gateway-vpn` исчезают во время операции, SIGKILL/reboot может произойти между любыми cleanup steps, а filename-похожая либо неполная receipt не должна давать исключение из fresh-install conflict checks |
| DEV-202 | 2026-08-30 | Заменить односерверное допущение successor Management Fabric моделью `1..N Gateway ↔ 1..N VPS`: каждый link имеет отдельные keypair/interface slot/subnet/generation и остаётся active одновременно с остальными | Один VPS должен принимать несколько Gateway без внешних IP, а один Gateway — переживать отказ отдельного VPS. Одинаковые AllowedIPs нескольким peers и один global active link не дают корректного many-to-many/failover |
| DEV-203 | 2026-08-30 | Обычный Internet Keenetic продолжает идти через WAN; remote LAN access является отдельным default-off resource profile `GATEWAY_ONLY`, `KEENETIC_WAN`, `VIA_KEENETIC_WAN_ROUTED`, `VIA_WG_ROUTER` либо `VIA_DEDICATED_LAN` | WireGuard на Keenetic не является обязательным и не должен незаметно заменять его WAN/default route. Без явного Keenetic firewall/return path домашняя LAN недоступна и должна отображаться как внешний prerequisite, а не открываться широким NAT |
| DEV-204 | 2026-08-30 | Каждой публикации `site × resource × VPS link` назначать unique conflict-checked alias prefix; VPS и Gateway применяют одну versioned double ACL, default deny между Gateway/admin и запрет management→Internet | У нескольких объектов почти неизбежно совпадут `192.168.1.0/24`/`192.168.50.0/24`, а один resource через два VPS также не может иметь duplicate portable routes. Alias без двойной ACL либо arbitrary user NAT расширил бы lateral movement и root command boundary |
| DEV-205 | 2026-08-30 | WebUI перейти с длинного плоского меню на шесть предметных групп; удалённый контур имеет отдельные вкладки `VPS и каналы`, `Администраторы`, `Локальные ресурсы`, `Матрица доступа`, а `wg-ingress` остаётся в отдельной странице входящих клиентов | Новые many-to-many/resources настройки нельзя смешивать с подписками, сетевыми картами или user WireGuard. Один владелец настройки, canonical read model, breadcrumbs/deep links и progressive disclosure предотвращают расхождение и нагромождение |
| DEV-206 | 2026-08-30 | Все поддерживаемые topology profiles/roles должны переключаться после установки через WebUI одной durable safe-apply transaction с LKG, impact preview, альтернативным management prerequisite, подтверждением через новый path и reboot/timeout rollback | Установочный выбор не должен навсегда привязывать Gateway к конкретной карте/схеме, но изменение единственного management path без независимого подтверждения создаёт необратимый lockout |
| DEV-207 | 2026-08-30 | Watchdog successor расширить до 18 fixed components отдельным `management_fabric_routes`; per-link external VPS outage не перезапускает другие links/host, а local route/ACL/key/generation defect проходит bounded reconcile только затронутого link | WireGuard handshake liveness и правильность опубликованных alias/routes/ACL — разные признаки. Общий restart всех tunnels при отказе одного VPS ухудшил бы доступность и создал бы recovery loop |
| DEV-208 | 2026-08-30 | Для local-resource access рекомендовать Gateway-terminated `wg-admin` через allowlisted VPS UDP relay; `ROUTED_HUB` оставить явным trusted opt-in. Watchdog successor получает отдельный девятнадцатый component `wireguard_admin` | Hop-by-hop WireGuard на VPS шифрует линии, но полностью скомпрометированный VPS может spoof admin source. Nested end-to-end tunnel оставляет VPS только возможность relay/DoS и не даёт расшифровать либо сгенерировать authenticated admin packet |
| DEV-209 | 2026-08-30 | После удаления owned networkd policy uninstall/first-install recovery вызывает `networkctl reload` только если `systemd-networkd.service` уже active; daemon не запускается и unavailable/inactive state не считается cleanup failure, а ошибка reload активного daemon остаётся фатальной/записанной | Cleanup не должен активировать чужой network manager или зависеть от D-Bus activation после нового PID1. Удалённые файлы гарантированно отсутствуют к следующему boot, но работающий daemon обязан немедленно перечитать live policy |
| DEV-210 | 2026-08-30 | VPS management реализовать одним lightweight Go Agent с embedded restricted WebUI/CLI/SQLite; signed one-command installer выдаёт bounded invitation, Gateway импортирует код/файл и не получает VPS login/password/private key. Agent после pairing доступен только через localhost/admin WireGuard | Удобство не требует публичного тяжёлого control panel либо хранения root credentials на Gateway; invitation сохраняет zero-to-ready onboarding и закрывается после success/expiry |
| DEV-211 | 2026-08-30 | AmneziaVPN/foreign VPN coexistence является обязательным release gate: VPS firewall scope-only без global drop/flush, уникальные interfaces/ports/subnets/tables/marks, watchdog и lifecycle меняют только owned objects, а forwarding `0` возвращается лишь без нового foreign owner | Отдельное имя nft table само по себе не предотвращает блокировку чужого трафика base-chain policy. Удаление или recovery Gateway VPN не должно оборвать Amnezia/Docker/UFW либо другой сервис того же VPS |
| DEV-212 | 2026-08-30 | Windows 10/11 x64 получает signed portable `gateway-vpn-deploy.exe` последним delivery layer после стабилизации VPS Agent/pairing API; он использует verified system OpenSSH, pinned host identity и не сохраняет credentials | Ранний Windows wizard пришлось бы переделывать вместе с pairing. Поздний thin client сохраняет один security/readiness contract с Linux launcher и не замедляет core runtime |
| DEV-213 | 2026-08-30 | Gateway и VPS имеют раздельные encrypted WebUI backup files `.gvpn`/`.gvpn-vps`, preview и durable restore; same-device сохраняет identity только с replacement/quarantine, import-as-new генерирует новые IDs/keys/prefixes/pairing | Удобное файловое восстановление обязательно для обеих ролей, но смешивание private keys либо незаметное клонирование active site/VPS создаёт duplicate identity и широкий management access |
| DEV-214 | 2026-08-30 | Root install journal VPS остаётся в `/var/lib/gateway-vpn-vps/install-transactions`, а unprivileged Agent получает только `/var/lib/gateway-vpn-vps/agent`; WebUI создаёт mode-0600 `restore.trigger`, который fixed systemd `.path` передаёт parameter-free root restore unit | Передача Agent права вызывать произвольный `systemctl` либо traverse root install state расширила бы privilege boundary. Узкий durable trigger переживает разрыв HTTP и не принимает path/unit/argument от пользователя |
| DEV-215 | 2026-08-30 | `IMPORT_AS_NEW` генерирует новую VPS identity/WireGuard/update/TLS, удаляет source peers/prefix/ACL/pairing и одной journalled transaction заменяет `wg-mgmt.conf` interface-only конфигурацией; после commit wg-quick перезапускается | Новая Agent identity не должна расходиться с фактическим WireGuard private key, а stale source peers в host config иначе обошли бы очищенную DB и clone quarantine |
| DEV-216 | 2026-08-30 | Обычный VPS uninstall сохраняет Agent DB/settings/admin/backups/TLS/update/WireGuard account state; reinstall принимает его только после exact ownership/schema/identity checks. `--purge-keys` удаляет state и service account | Файловый backup не отменяет удобный reinstall, но частично сохранённый либо подменённый service state нельзя молча принять как действующий Hub |
| DEV-217 | 2026-08-30 | Наблюдатель owned route использует kernel-filtered `ip -json ... protocol 186` и принимает только эквивалентные Ubuntu representations: numeric `186`, symbolic `bgp` либо отсутствующее уже отфильтрованное поле; bare private IPv4 canonicalize в `/32`, а отсутствующий после `dev wg-mgmt` filtered field допустим | Реальный iproute2 может опускать отфильтрованные `protocol`/`dev`, печатать протокол символически и host route без `/32`. Строгий parser обязан учитывать эти формы, но по-прежнему отвергать public/default/foreign routes |
| DEV-218 | 2026-08-30 | `fabric-watchdog.json` является только atomic bounded display-status для WebUI; право root apply определяется исключительно root-owned receipt/journal и authenticated desired generation | Writable Agent/UI telemetry нельзя превращать в authorization либо recovery source. Потеря или подмена display-файла даёт stale/unavailable UI state, но не разрешает host mutation |
| DEV-219 | 2026-08-30 | Privileged multi-peer fixture использует отдельный point-to-point `/30` veth underlay для каждого WireGuard peer, а не общий synthetic Linux bridge | Docker Desktop bridge при четырёх peers иногда терял data packets до nftables при исправных handshakes; изолированный underlay убирает недетерминизм harness и сохраняет проверяемую ACL-топологию |
| DEV-220 | 2026-08-30 | Любая новая durable настройка Gateway или VPS считается завершённой только вместе с role-specific encrypted file backup/restore round-trip; `.gvpn` и `.gvpn-vps` остаются обязательными WebUI функциями и никогда не принимаются другой ролью | Пользователь требует переносимого восстановления с нуля без ручного собирания файлов. Расширение Management Fabric не должно создавать настройки, которые теряются при backup либо обходят preview/re-auth/pre-restore snapshot/rollback |
| DEV-221 | 2026-08-30 | Адаптивность является общим WebUI-контрактом обеих ролей: controls не имеют фиксированной высоты, длинные локализованные подписи переносятся, grid использует `minmax(0,1fr)`, формы/карточки не расширяют viewport, широкие таблицы прокручиваются только внутри своего контейнера, а мобильная навигация остаётся читаемой горизонтальной лентой | Точечное сокращение текста скрывает дефект и ломается при следующем переводе или новой функции. Общие layout-ограничения и browser regression защищают все текущие и будущие страницы |
| DEV-222 | 2026-08-30 | Gateway Management Fabric private keys и transaction state принимаются только при exact `root:root 0600/0700`; WebUI export пересекает root boundary исключительно как уже зашифрованный bounded stream после re-authentication | Непривилегированный control process не должен читать long-lived management identities, но portable backup обязан сохранять их для полного восстановления |
| DEV-223 | 2026-08-30 | Apply вычисляет delta интерфейсов и не перезапускает byte-identical `gvm<N>`; удаление одного VPS сохраняет ifindex/handshake остальных, а изменённый link обрабатывается как remove+apply | Полная пересборка всех WireGuard links при любой policy/ACL generation создаёт ненужный management outage и противоречит many-to-many отказоустойчивости |
| DEV-224 | 2026-08-30 | Gateway Management Fabric разрешает `established,related` в обоих направлениях только при `iifname`/`oifname` owned interface set; первый пакет каждого нового доступа по-прежнему проходит exact `ct state new` ACL | Packet gate доказал, что одностороннее reply-rule пропускает SYN/SYN-ACK, но блокирует дальнейшие client→resource packets; symmetric scoped state rule завершает разрешённое соединение без расширения new-flow ACL |
| DEV-225 | 2026-08-30 | Кнопки действий внутри широких таблиц сохраняют естественную однострочную ширину; переполнение принимает только ограниченный `.table-wrap`, а не сама кнопка или весь документ | Flex-shrink сжимал столбец действий примерно до 66 px даже на desktop и до 30 px на mobile: русские подписи занимали до восьми строк. Общий table-action contract исправляет все текущие и будущие таблицы без сокращения текста |
| DEV-226 | 2026-08-30 | Строка checkbox с contextual-help всегда строится grid `auto minmax(0,1fr) auto`; текст занимает сжимаемую среднюю колонку, а checkbox и `?` сохраняют размер внутри контейнера | Flex-вариант на 320 px выпускал кнопку справки за правый край на 4 px при длинной русской подписи, хотя document overflow эвристика этого не показывала |
| DEV-227 | 2026-08-30 | Ротация `wg-admin` создаёт в одной DB transaction opaque exact rollback snapshot; при host failure старый private key и snapshot восстанавливаются до journal recovery, без compensating generation | Повторный обычный rotate к старому public key увеличивал generation и мог оставить существующий `wg-admin` без identity после частично проваленного apply. Exact snapshot не перетирает конкурентные изменения и возвращает прежнюю generation/runtime |
| DEV-228 | 2026-08-30 | На узком экране предметные вкладки Gateway и VPS Hub выбираются из полного сгруппированного selector; desktop navigation остаётся исходной, а обе поверхности синхронизируют active page | Горизонтальная лента технически не обрезала саму кнопку, но скрывала большинство длинных русских названий за прокруткой и выглядела как незавершённая разметка. Selector показывает выбранный раздел целиком и не увеличивает ширину документа |
| DEV-229 | 2026-08-30 | Post-install topology хранится как отдельный schema-30 profile/generation state и меняется только operation `TOPOLOGY_PROFILE` внутри существующей durable network safe-apply transaction; snapshot охватывает роли интерфейсов, stable+legacy networkd paths, LAN/DHCP-DNS, firewall, routing и `wg-ingress` | Независимые изменения компонентов могут оставить half-applied профиль и закрыть WebUI/SSH. Один LKG contour позволяет атомарно подтвердить новый management path либо полностью вернуть прежнюю схему после timeout, reboot или process failure |
| DEV-230 | 2026-08-30 | Installer-selected physical LAN roles импортируются ровно один раз после первого kernel observation, только при untouched topology generation `1/1 ACTIVE`; direct ifname имеет приоритет над bridge members, managed virtual LAN и уже назначенные uplink запрещены | После миграции старой установки stable physical inventory не знает, какой порт был LAN, но повторное угадывание после пользовательского safe apply перетрёт осознанный выбор и может назначить uplink как management port |
| DEV-231 | 2026-08-30 | Topology rollback принимает snapshot только с allowlisted profile/roles, bounded unique members, SHA-256 и обязательной парой stable+legacy path для каждого candidate/current интерфейса; malformed/tampered snapshot отклоняется до data-path mutation | Root recovery читает durable disk state после crash/reboot. Частичный либо подменённый manifest не должен удалять один вариант networkd identity, назначать неизвестную роль или создавать неполный rollback contour |
| DEV-232 | 2026-08-30 | Firewall schema 6 разрешает WebUI/SSH через exact named set `local_management_interfaces`; one-arm source допускается только от allowlisted `wg-ingress` peer и получает direct mark ровно один раз | Один захардкоженный LAN ifname противоречит сменяемым multi-port profiles. Широкое разрешение физической shared-карты позволило бы plaintext/spoofed traffic обойти WireGuard policy |
| DEV-233 | 2026-08-31 | VPS operational snapshot создаётся только fixed root timer как `root:gateway-vpn-vps 0640`; parent имеет `0710`, operations directory `0750`, а sibling restore/fabric state остаётся `root:root 0700` | Agent должен читать только уже очищенное display-only состояние. Владение snapshot пользователем Agent либо групповое открытие всего privileged root расширяет последствия компрометации WebUI |
| DEV-234 | 2026-08-31 | VPS installer требует полный пакет `python3`, а не `python3-minimal` | Строгие JSON host/recovery gates используют стандартный модуль `json`; минимальный Ubuntu package предоставляет интерпретатор, но не гарантирует полную стандартную библиотеку, что доказал локальный чистый образ |
| DEV-235 | 2026-08-31 | Remote Gateway update принимает только signed immutable GitHub Release, signed WebUI upload либо exact HTTPS artifact; Gateway владеет одной locked transaction, boot recovery независим от WebUI/VPS, acceptance имеет initial gate и 24h stability, retention хранит complete release+DB+owned-metadata restore points | Удалённый Gateway нельзя оставлять без безопасного обновления, но удобная кнопка не должна устанавливать `main`, ослаблять подпись, принимать внешний outage за regression либо лишать рабочей recovery-пары после migration |
| DEV-236 | 2026-08-31 | Official channel resolver принимает только exact `v<version>` releases с signed `channel-stable/testing` manifest, role/OS/arch artifact и public HTTPS destination; direct URL запрещает credentials/fragment/private DNS result, bounded redirects и повторно проходит полный release verifier | GitHub metadata и HTTPS сами по себе не являются доверием. SSRF, redirect на локальный адрес, oversized/truncated download и несовпадающий channel hash должны завершиться до staging/live mutation |
| DEV-237 | 2026-08-31 | Restore point является complete immutable pair: retained signed release identity, SQLite, config, secrets, subscriptions, TLS, Mihomo state и host contract; `CURRENT`, `RECOVERY`, `ACTIVE_TRANSACTION` выводятся root-контроллером и всегда защищены от delete/prune | Отдельный старый binary без соответствующих данных не восстанавливает рабочее состояние, а writable/UI-supplied protected flag позволил бы удалить единственный recovery contour |
| DEV-238 | 2026-08-31 | Manual historical rollback требует password re-authentication, exact phrase и destructive header, сначала закрывает data path и создаёт complete safety point, затем запускает только fixed rollback unit; restored pair проходит новый stability window, а SIGKILL/reboot возвращает safety point | Rollback намеренно уничтожает более новые active данные. Простого клика или down-migration недостаточно для защиты от ошибки администратора и частичного переключения release/state |
| DEV-239 | 2026-08-31 | Restore projection сохраняет namespace-specific ownership: root-only Management Fabric/WireGuard secrets `root:root 0600/0700`, TLS certificate `gateway-vpn:gateway-vpn 0644`; mode устанавливается до `chown`, partial candidates всегда очищаются, `/etc/gateway-vpn` writable только fixed rollback/recovery units | Привилегированное восстановление не должно раскрыть private keys application UID, потерять читаемость TLS certificate или оставить наполовину собранный candidate после permission failure |
| DEV-240 | 2026-08-31 | Время Gateway VPN хранится, передаётся, фильтруется и показывается только в UTC; пользовательская настройка timezone/UTC+3 не вводится | Один UTC timeline устраняет неоднозначность recovery/update/log audit между Gateway, несколькими VPS и браузерами; локальное отображение могло бы сдвинуть filter boundary без изменения сохранённых событий |
| DEV-241 | 2026-08-31 | Gateway и VPS update/recovery/finalize входят в общий root lifecycle lock соответствующей роли; install-time recovery получает bypass только при двух безопасных root markers. Reinstall/uninstall используют semantic journal state, а не существование `active.json`; root mutation в systemd `ExecStartPre` запрещена | Terminal audit journal не должен навсегда блокировать обслуживание, но nonterminal/corrupt state обязан fail-safe. Общий lock и повторная проверка после остановки control plane закрывают TOCTOU с install/host-upgrade/uninstall |
| DEV-242 | 2026-09-01 | Automatic Gateway update получает отдельный durable singleton state и lease, принимает после restart только собственный signed `AUTOMATIC_GITHUB_CHANNEL` staging и никогда не повторяет Apply после durable intent без authoritative root outcome | Ручной staged artifact не должен стать unattended update. Потеря HTTP/systemd ответа после начала root mutation делает повторный dispatch опасным; `OUTCOME_UNKNOWN` сохраняет fail-safe до чтения root journal |
| DEV-243 | 2026-09-01 | Unattended Apply требует latest policy, отсутствие/известное состояние maintenance, fresh `FULL` access tuple и fresh management handshake; control path закрывается до durable intent. Ошибка readiness только откладывает Apply и не отменяет подпись/LKG/root checks | Далёкий Gateway нельзя автоматически менять при ограниченном Интернете либо без подтверждённого пути управления. Недоступность root status не является доказательством безопасности и должна suppress mutation |
| DEV-244 | 2026-09-01 | Gateway Management Fabric runtime observation выполняет только root applier по applied typed host plan; unprivileged caller не передаёт interface/peer/key/path. Control plane принимает только полный redacted snapshot одной current generation и самостоятельно превращает просроченный `REACHABLE` в `STALE` | UI/readiness не должны доверять произвольному peer либо вечному старому handshake. Полнота и generation binding исключают частичное обновление состояния при concurrent link mutation |
| DEV-245 | 2026-09-01 | Решение DEV-020 уточнено: broker socket использует owner/group `gateway-vpn`, mode `0660` и обязательный `SO_PEERCRED`; допускаются только UID `gateway-vpn` либо root, клиент не сохраняет keep-alive между typed запросами | Ограниченный root-watchdog не имеет `CAP_DAC_OVERRIDE`, но должен выполнять parameter-free recovery. Group write даёт доступ к socket без широкой capability, UID-проверка отсекает другого участника группы, а новое соединение исключает stale peer после systemd restart |
| DEV-246 | 2026-09-01 | Signed channel сохраняет role `deploy`, но различает точные platform identities `linux/amd64` и `windows/amd64`; Windows artifact имеет immutable `.exe` filename и PE media type, а channel builder требует ровно пять labels: `bootstrap/deploy/deploy-windows/gateway/vps` | Отдельная неподписанная Windows загрузка создала бы второй trust contour. Одна signature должна аутентифицировать обе launcher-платформы, exact size/SHA-256/version/commit и общий набор Linux role artifacts |
| DEV-247 | 2026-09-01 | Windows launcher использует только system `ssh.exe`, но не `ControlMaster`: один долгоживущий process/TCP на host выполняет фиксированный bounded framed Bash protocol с pinned `known_hosts`, explicit identity, no agent/password/TTY и context cancellation | Реальный Windows 10/OpenSSH 9.5 gate получил `getsockname failed: Not a socket`; официальный Win32-OpenSSH scope исключает Client ControlMaster. Новые TCP connections после Gateway fail-closed apply недопустимы, поэтому отдельные `ssh.exe` на каждую фазу не являются безопасной заменой |
| DEV-248 | 2026-09-01 | Windows release публикует copy/paste PowerShell command, а не `.ps1`: exact EXE и raw manifest скачиваются во временный GUID directory и оба сверяются по externally pinned SHA-256 до запуска signed interactive wizard; ExecutionPolicy не меняется | Пользователь уже столкнулся с запрещённым execution policy и исчезающими `.ps1` окнами. Copy/paste в открытый PowerShell остаётся одной командой, не сохраняет credentials и гарантированно удаляет downloaded trust inputs |
| DEV-249 | 2026-09-01 | Обновить `golang.org/x/crypto` с `v0.47.0` до `v0.55.0`, сохранив уже совместимые `x/sys v0.47.0` и `x/text v0.41.0`; единственный module-only `GO-2026-5932` принять как недостижимый, пока проект не импортирует unmaintained `openpgp`, а `govulncheck` подтверждает 0 symbol/package vulnerabilities | `v0.55.0` закрывает все version-fixable advisories прежнего module graph. У `GO-2026-5932` нет fixed version; отказ от всего `x/crypto` лишил бы проект Argon2id и SSH/knownhosts, тогда как call-graph scanner доказывает отсутствие affected package в сборке |
| DEV-250 | 2026-09-01 | Одноразовые Docker resources, project `.cache`, validation bundles и lifecycle-стенды после тестов автоматически не удалять и Docker VHDX не сжимать; cleanup выполнять только по отдельному явному запросу пользователя. `open-webui`, его image и volume сохранять всегда без противоположного прямого указания | Пользователь самостоятельно следит за дисковым местом и хочет повторно использовать уже полученные images/caches/evidence; автоматический prune создаёт лишние повторные загрузки и длительные пересборки |
| DEV-251 | 2026-09-01 | Новая установка Gateway VPN по умолчанию имеет выключенные automatic check, download и apply; ручная проверка, signed staging и ручное применение с rollback остаются доступны | Пользователь не планирует включать автоматику; даже harmless manifest check не должен молча выполняться без явного opt-in |
| DEV-252 | 2026-09-01 | Отдельное ручное обновление Mihomo использует signed domain-bound maintenance manifest, но всегда устанавливает полный immutable Gateway release через единственный существующий update/snapshot/stability/rollback contour; второй privileged updater, mutable binary и upstream `latest` запрещены | Обычный Gateway release уже обязан содержать проверенную Mihomo. Отдельная карточка нужна для удобства и compatibility discovery, но отдельная мутация core удвоила бы root/recovery paths и могла оставить несогласованные binary/config/API/DB состояния |
| DEV-253 | 2026-09-02 | Родитель live SQLite сохраняет два безопасных exact режима: обычный private `0700` и заранее установленный production state-root `0710`; любой иной mode нормализуется к `0700`. `0710` даёт только traverse группе `gateway-vpn`, тогда как DB остаётся `0600`, state root нельзя читать/листать/изменять, а root-only secrets сохраняют независимые `0700/0600` и ownership | Изолированный `gateway-vpn-mihomo` входит в service group и должен пройти через `/var/lib/gateway-vpn` к собственному `mihomo/active`. Принудительный `db.Open → chmod 0700` отменял tmpfiles contract после старта control plane и приводил production Mihomo unit к `status=200/CHDIR`; расширять group permissions до read/write нельзя |
| DEV-254 | 2026-09-02 | Обязательная отрицательная lifecycle-проверка в Bash не может быть записана как standalone `! command` с надеждой на `set -e`; используется явный `if command; then error; exit/return 1; fi`, а packaging regression запрещает известные опасные формы | Bash освобождает commands внутри `!` от обычного errexit-поведения. Старый release-gate поэтому продолжал работу при активном Mihomo и заполненном fail-closed set, а uninstall мог замаскировать ошибку восстановления enabled-state последующей успешной проверкой active-state |
| DEV-255 | 2026-09-02 | Production root ownership остаётся безусловным; non-root portable/race fixtures используют текущие UID/GID через private same-package test seam, а проверки, смысл которых состоит именно в exact `root:root`, выполняются только в root-capable gate и явно skip на непривилегированном runner | Общий GitHub race job не имеет `CAP_CHOWN`. Требование сменить временный test-файл на UID 0 ложно роняло CI либо маскировалось локальным root Docker, но ослаблять реальные ownership boundaries ради переносимости тестов нельзя |
| DEV-256 | 2026-09-02 | Каждый отслеживаемый shell entrypoint обязан иметь Git mode `100755`; GitHub syntax step проверяет mode всего tracked `.sh` набора до `bash -n`, а не только перечисленные старые файлы | Исправный LF/shebang не помогает при прямом `sudo ./script.sh`, если checkout восстановил mode `100644`. Ручной перечень не защищает будущие netns/release helpers от того же пропуска |
| DEV-257 | 2026-09-02 | Smoke/unit fixture с retention и sample timestamps использует одну явную фиксированную diagnostic timeline; текущие часы допускаются только там, где тестируется именно wall-clock поведение. Production retention policy и её пределы не меняются ради теста | Иначе корректный fixture неизбежно становится старше собственного семидневного окна и начинает ронять CI в календарную дату, не связанную ни с кодом, ни с production retention |
| DEV-258 | 2026-09-02 | При `read-only filesystem`/Docker `502` вместе с host storage events `disk 51`, `Ntfs 50/140` либо `stornvme 129/11` development workload немедленно останавливается; запрещены factory reset, `wsl --unregister`, удаление VHDX и дальнейшая нагрузка до проверки host disk. Cleanup/compact выполняются только после detached VHDX backup и отдельного явного запроса; `open-webui` сохраняется | Docker-level сообщение может быть следствием исчезновения физического NVMe. Продолжение тестов или reset уничтожили бы диагностические данные и могли бы повредить единственную копию volumes; verified backup и host-first recovery ограничивают последствия |
| DEV-259 | 2026-09-04 | GitHub Draft Release любого signed channel, кроме `stable`, создаётся сразу с `prerelease=true`; publication остаётся отдельным ручным действием | Один только подписанный `channel-testing` не управляет GitHub `latest`. Non-stable draft без prerelease-флага при последующей публикации мог выглядеть обычным release и заменить stable/latest metadata |
| DEV-260 | 2026-09-04 | Route-aware TCP MSS clamping является общей пользовательской сетевой функцией, а не modem-only настройкой: owned chain ограничивается активным verified direct/TUN egress, динамическими LAN/WireGuard ingress и TCP SYN; при MTU 1500 значение остаётся штатным | Узкий modem-only workaround оставил бы те же MTU-проблемы на Ethernet, TUN и разрешённом `wg-ingress`. Ограничение по owned interfaces/egress сохраняет SSH, WebUI, Management Fabric, служебный output и UDP/QUIC вне правила |
| DEV-261 | 2026-09-04 | Deploy endpoint в интерактивном мастере всегда вводится как `USER@HOST`; локальная валидация сравнивает полный SSH endpoint `host+port`, запрещает только одинаковый endpoint и разрешает один host с разными портами для изолированных Gateway/VPS targets | Bare host приводит к неясной ошибке удалённого шага, а запрет одного IP ломает легитимный clean-gate с двумя опубликованными SSH-портами на одном Docker host |
| DEV-262 | 2026-09-04 | Перед каждым полем Windows/Linux deploy wizard печатает короткое русское объяснение назначения, допустимого формата, источника значения и безопасного примера; private keys/passwords не принимаются как текстовые значения | Мастер должен быть понятен пользователю без опыта администрирования и не заставлять угадывать, где взять адрес, порт, интерфейс, CIDR или путь к ключу |
| DEV-263 | 2026-09-04 | Windows one-command staging хранится в скрытой случайной подпапке текущей project-local рабочей директории; системные `%TEMP%`, profile temp и глобальные кэши не используются, cleanup выполняется в `finally` | Ограничение project-local ресурсов предотвращает неконтролируемый рост системного диска и оставляет все одноразовые download inputs в видимой пользователю рабочей области |
| DEV-264 | 2026-09-04 | Netns MSS capture сначала дожидается создания pcap-файла `tcpdump`, затем отправляет ровно один SYN; capture timeout увеличен с 5 до 10 секунд и остаётся bounded | GitHub CI выявил exit `124` из-за гонки запуска capture на загруженном runner; ожидание готовности устраняет false negative, а верхний предел времени сохраняет защиту от зависания release gate |
| DEV-265 | 2026-09-04 | После source/harness fixes обязательный CI run `33899645155` должен быть полностью зелёным до любого нового signed candidate; при этом старый immutable testing release и stable/latest не переиспользуются и не изменяются | Clean-Windows повтор невозможен на старом immutable bundle: он содержит исправленный wizard/validator только в source, поэтому release delivery должен получить новый явно разрешённый signed candidate |
| DEV-266 | 2026-09-04 | Clean Windows Sandbox использует два mapped каталога: read-only `C:\GatewayVPNGate` для подписанных входов/evidence и writable project-local `C:\GatewayVPNRuntime` для one-command staging; PowerShell стартует во втором | Generated launcher теперь намеренно пишет относительно текущего каталога и не должен получать read-only mapped folder или системный `%TEMP%`; отдельный writable mapping сохраняет trust inputs неизменными |
| DEV-267 | 2026-09-04 | Локальная проверка секретов включается только явно через `core.hooksPath=.githooks`; hook сканирует staged snapshot с pinned-политикой Gitleaks, включая fixtures, а обязательный server-side full-history scan остаётся границей доверия | Ранний pre-commit feedback снижает риск случайно добавить production secret, но не должен блокировать обычные checkout-ы без установленного инструмента и не может заменять проверку всей истории в CI |

## Журнал разработки

### Сессия 188 — production-signed successor f300b25 и проверенный GitHub Draft prerelease — 2026-09-04

**Сделано:**

- подтверждено, что `origin/main` и локальный `HEAD` совпадают на `f300b2513558c883e1960a775ba820abdda7565c`, а exact annotated tag `v0.1.1-testing.f300b25` указывает ровно на этот commit и уже отправлен в GitHub;
- подтверждён полностью успешный GitHub Actions run `33908523656` для current commit: secret-history, Go/race/vet/fuzz/packaging/syntax, Windows portable contract и Linux nftables/netns;
- production `.gvkey` был открыт пользователем только вводом passphrase в отдельном launcher; plaintext identity существовала только во временном Linux tmpfs и была удалена после сборки;
- trusted builder собрал `0.1.1-testing.f300b25`: Gateway/VPS архивы, bootstrap, Linux/Windows deploy, SPDX/in-toto, testing channel, signing public key и две exact copy/paste commands — всего 16 локальных объектов в `dist`;
- локальные verifiers подтвердили signer `fceb4a543d90aabbbe11a42d2c210c1565c235d017da7adc6c5b9d95c8eda60c`, Gateway `57` файлов, VPS `35` файлов и testing channel `5` artifacts;
- прежний `dist` не удалён и сохранён внутри проекта в `.cache/release-builder/previous-dist-0.1.1-testing.3bb466b-20260904`;
- GitHub CLI внутри builder получил отдельную device authorization как `Go4a4a`; браузерная сессия GitHub сама по себе не передавалась контейнеру и production key для этого не использовался;
- первая попытка publisher безопасно остановилась до внешней записи с `Missing publisher command: go`; повторный запуск получил явный `PATH=/opt/go1.26.7/bin:$PATH` и не пересобирал release;
- publisher из clean exact tag повторно проверил Gateway/VPS/channel signatures, соответствие remote tag текущему commit и отсутствие существующего Release, затем создал только GitHub Draft Release;
- GitHub metadata подтверждает `isDraft=true`, `isPrerelease=true`, exact tag `v0.1.1-testing.f300b25` и ровно `14/14` ожидаемых assets с совпадающими именами и размерами;
- stable/latest, прежний published testing release и public channel не изменялись.
- после exact tag в `origin/main` отправлена только documentation-only запись этой сессии; release source и подписанные bytes остаются привязаны к `f300b251…`.

**Не получилось / ограничение:**

- fresh download 14 draft assets в project-local `.cache/release-builder/draft-verification-0.1.1-testing.f300b25` был начат только после создания draft, но Docker Desktop Engine остановился до скачивания; каталог остался пустым, дубликаты не созданы;
- Docker logs доказывают нормальный запуск Engine и контейнера перед остановкой и не показывают повреждения project/Docker data, но причина завершения Desktop в этой сессии не доказана; повторные слепые перезапуски не выполнялись;
- на этом промежуточном шаге remote SHA-256 и повторная проверка подписей скачанных draft bytes оставались `PENDING`, а draft ещё не был опубликован; оба пункта закрыты продолжением той же сессии ниже.

**Продолжение и закрытие publication gate:** Docker Desktop был устойчиво запущен через Windows shell; существующий builder продолжен без пересоздания. Все 14 draft assets скачаны обратно в project-local `.cache/release-builder/draft-verification-0.1.1-testing.f300b25`, каждый SHA-256 совпал с локальным `dist`, а скачанные channel signature и пять role artifacts повторно прошли cryptographic verification. Current Windows EXE непосредственно на host вернул exact version/commit, принял доверенный channel/self-identity и безопасно остановился до SSH/apply; wrong manifest hash, wrong signer, tampered signature и tampered PE дали ожидаемый code 1. Generated PowerShell прошёл Windows PowerShell 5.1 AST, hash-before-exec, project-local staging и cleanup в `finally`: суммарно `9/9 PASS`.

После подтверждения repository setting `immutable-releases.enabled=true` Draft опубликован с явными `--prerelease --latest=false`. Remote API доказал `draft=false`, `prerelease=true`, `immutable=true`, `assets_count=14`; GitHub latest остался stable `v0.1.0-successor.5723940`. Новая fresh public download без `GH_TOKEN` повторно получила 14/14 assets в `.cache/release-publication-0.1.1-testing.f300b25/published-assets`; все SHA-256 и signature/five-artifact identity совпали. Временный GitHub CLI credential удалён, последующий `gh auth status` подтвердил отсутствие login.

Два ранее созданных disposable targets не пересоздавались: их container ID, prepared image ID, exact port bindings, active SSH, pinned Win32 OpenSSH и отсутствие всех Gateway/VPS application paths заново проверены. Новый project-local gate каталог использует NTFS hard links на тот же disposable SSH test key без второй secret copy, новый immutable signed command, read-only inputs и отдельный writable runtime. `.wsb`, XML и PowerShell AST проверены; Windows Sandbox PID `33960/13068` запущена и сейчас ожидает интерактивное выполнение мастера. Сам clean guest gate ещё не засчитан.

**Следующий шаг:** получить итог мастера, сохранить redacted report и с host проверить обе установленные роли. Ожидаемый isolated result — `INSTALLED_NOT_READY`/exit `3`, а не `READY`, из-за TEST-NET endpoint `198.51.100.1`. Реальные Ubuntu/HiLink/Keenetic и 24/72-часовые gates остаются внешними.

**UX-дефекты, обнаруженные при фактическом интерактивном запуске:** current deploy wizard последовательно спрашивает только `Ethernet Gateway → WAN Keenetic` и transit CIDR, хотя §18.2/§20 плана требуют понятный первоначальный выбор `ETHERNET_HILINK`, `ETHERNET_ETHERNET`, `ONE_ARM_WIREGUARD` либо `MIXED` и только релевантные роли/поля. Кроме того, после перехода к следующему prompt нельзя вернуться и исправить ошибочно выбранный файл `known_hosts` без отмены всего процесса. Current release остаётся неизменяемым и этот WAN gate продолжается как запланированный; до следующего candidate мастер должен получить memory-only step state, обязательную валидацию до перехода, действия **«Назад»**, **«Продолжить»**, **«Изменить»**, безопасную отмену без mutation и итоговый review с переходом к любому шагу. На Windows PowerShell остаётся только проверяемым bootstrap/download launcher; сам интерактивный мастер выполняет portable `gateway-vpn-deploy.exe`. Полноценный графический Windows frontend с кнопками и системным выбором файлов намеренно отложен до самого конца проекта, чтобы не задерживать core: перед началом этого финального delivery-этапа Codex обязан отдельно напомнить о нём пользователю и спросить подтверждение. Оценка production-quality GUI остаётся `2–3 рабочих дня`; он не заменяет CLI/fail-safe contract.

**Продолжение UX source:** консольный Windows deploy wizard переведён на memory-only step state. Каждый prompt показывает номер шага и принимает `НАЗАД`/`BACK` либо `ОТМЕНА`/`CANCEL`; итоговый review нумерует все значения и поддерживает `ИЗМЕНИТЬ`/`EDIT` с возвратом к одному выбранному шагу, `НАЗАД`, безопасную отмену и только exact uppercase `INSTALL`. Изменение отдельного шага возвращает к review, остальные уже проверенные ответы не приходится вводить повторно. Unit test доказал возврат с VPS port к VPS address, сохранение исправленного адреса/порта, отдельное изменение Gateway port из review и запрет lowercase confirmation. Initial four-topology selection остаётся отдельным backend-coupled этапом: мастер не будет показывать неработающий декоративный выбор до фактической передачи interface roles/WireGuard/uplink parameters installer-у.

**Фактический результат первого clean Windows запуска и доказанная причина:** пользователь ввёл все значения и подтвердил `INSTALL`, после чего orchestration безопасно остановилась в `GATEWAY_SSH_PREFLIGHT` с `GATEWAY_SSH_PREFLIGHT_FAILED`; `gateway_preflight`, `vps_preflight` и обе installation phases остались `NOT_RUN`, поэтому никакой target не изменён. Публичная загрузка, SHA-256/signature/self-identity и interactive input завершились до ошибки успешно. Оба прежних Docker-target продолжают работать на `172.18.224.1:42022/42023` с теми же container ID. Project-local diagnostic доказал `CONNECTED` к обоим портам, exact pinned host-key match и принятие public key сервером; Windows OpenSSH отверг только read-only mapped source с `UNPROTECTED PRIVATE KEY FILE`, потому что ACL содержит SID host-пользователя. Уничтожаемая Sandbox-local копия тех же `444` bytes с ACL текущего WDAG user вошла успешно (`exit 0`), а temporary identity была удалена. Source fix теперь на Windows создаёт process-owned project-local directory с inheritance removed и allowlist текущего SID/`SYSTEM`/Administrators, копирует выбранный bounded regular identity только туда, использует staged path в persistent SSH и удаляет его при handshake failure, session drop, normal close либо outer cleanup; исходный файл/ACL не меняются. Generated PowerShell явно передаёт private `$root` через `--ssh-working-root`, поэтому `%TEMP%` не используется. Low-level allowlisted SSH diagnostic добавляется в redacted report и получает понятное русское пояснение. Windows tests с намеренно broad source ACL и package tests `internal/deploy`, `internal/distribution`, `cmd/gateway-vpn-deploy` проходят. Полный `go test ./...` в существующем Linux builder-контейнере также полностью зелёный; Windows-host suite прошёл все пакеты кроме четырёх ожидаемо self-rejecting signing-key tests, которым специально запрещён заданный project-local `GOTMPDIR` внутри Git worktree. Внешний Windows `%TEMP%` для обхода этого security contract не использовался. Новый immutable candidate ещё не создавался.

### Сессия 187 — current secret-guard source прошёл полный GitHub CI — 2026-09-04

**Remote evidence:** GitHub Actions run `33904761787` для exact commit `48433fc9a8614e7e80f64a20c5e58b4ae233f908` завершился `Success` за `19m57s`. Все четыре jobs зелёные: Repository secret history gate `9s`; Go, packaging and syntax gates `17m47s`; Windows portable deploy contract `1m19s`; Linux nftables fail-closed gate `1m50s`. Основной job выполнил полный `go test -race ./...`, vet, четыре bounded fuzz-smoke, все release builds и syntax check нового `.githooks/pre-commit`/scanner. Secret-history job отдельно подтвердил отсутствие leaks во всей истории.

**Текущее состояние:** `origin/main` содержит current source `48433fc`; рабочее дерево до этой journal-only записи было чистым. Опубликованный `v0.1.1-testing.3bb466b` остаётся immutable и намеренно не изменяется, но не содержит новых deploy fixes/secret guard. Production key не открывался, новый bundle/tag/Release не создавался, stable/latest не менялся. Docker/cache/evidence не очищались.

**Следующий шаг:** получить отдельное явное разрешение пользователя на production key, новый testing build, exact tag и testing prerelease. Затем обновить writable Sandbox gate и повторить полный two-target deploy; реальные Ubuntu Gateway/VPS, HiLink/Keenetic/RTC и 24/72h endurance остаются внешними обязательными gates.

### Сессия 186 — добавлен opt-in pre-commit secret guard и завершён review коллеги — 2026-09-04

**Что внедрено:** добавлены `.githooks/pre-commit` и `scripts/pre-commit-secret-scan.sh`. После явного `git config core.hooksPath .githooks` hook перед коммитом запускает `gitleaks protect --staged --redact --no-banner`, поэтому проверяется именно staged snapshot, включая `test/fixtures`; целые каталоги и Git history не исключаются. При отсутствии Gitleaks hook останавливается с понятным сообщением, а отключение локального hook не меняет обязательный GitHub full-history secret-history gate. Packaging regression test проверяет контракт hook/scanner, а CI проверяет shell syntax обоих файлов.

**Результат аудита замечаний:** TODO/FIXME/XXX/HACK в рабочем source нет; migration inventory непрерывен `000001`…`000034`, поэтому отдельное пояснение о якобы пропущенной `000024` не требуется (файл `000024_watchdog_logging_pipeline.sql` присутствует). Go `1.26.7` и `CGO_ENABLED=0` оставлены намеренно как зафиксированный reproducible toolchain/portable pure-Go SQLite contract. Bounded fuzz smoke уже выполняется в CI для subscription import, bypass target normalization, Mihomo generation и release archive extraction. Windows portable job и endurance harness имеют отдельные контракты и runbook; расширять их без нового требования не нужно. OpenSSH readiness, modem-subnet diagnostics и route-aware MSS clamping уже закреплены в source/PLAN/OPERATIONS, включая отдельные direct/Ethernet/TUN/WireGuard scopes.

**Проверки:** focused packaging/deploy/distribution tests и полный serial `go test ./... -count=1 -p 1`, `go vet ./...`, `git diff --check` — PASS. `go test -race` на текущем Windows host по-прежнему не запускается без C compiler; авторитетный race gate остаётся GitHub Ubuntu CI. Production key, tag, release, Docker resources и project caches не открывались и не удалялись.

**Следующий шаг:** закоммитить этот source/doc increment, отправить в `origin/main` обычной синхронизацией и дождаться CI. Новый production-signed candidate, exact tag и publication по-прежнему требуют отдельного явного разрешения пользователя; hardware/VPS/endurance gates остаются внешними.

### Сессия 185 — подготовлен writable Sandbox template для повторного deploy — 2026-09-04

**Причина:** source fix перевёл Windows one-command staging с системного `%TEMP%` в текущую project-local рабочую директорию. Существующий `Gateway-VPN-Clean-Gate.wsb` монтирует весь gate folder как read-only `C:\GatewayVPNGate`; запуск исправленного launcher из этого каталога был бы корректно отклонён отсутствием записи.

**Подготовка:** в сохранённом project-local evidence каталоге создана пустая `runtime` и проверен XML-шаблон `Gateway-VPN-Clean-Gate-Writable-Template.wsb`. Он оставляет подписанные inputs/evidence read-only в `C:\GatewayVPNGate`, монтирует отдельную writable project-local папку как `C:\GatewayVPNRuntime` и запускает PowerShell сразу из неё. Это не запускает Sandbox, не меняет targets и не трогает старый read-only `.wsb`.

**Проверка:** `[xml]` parsing шаблона прошёл (`WSB_XML_PASS`); старые Windows Sandbox процессы и два clean target-контейнера сохранены без mutation. Шаблон будет применён только после появления нового signed candidate; старый immutable `3bb466b` повторно запускать не следует.

**Следующий шаг:** дождаться отдельного journal-only CI run, затем получить явное разрешение на production-signed testing candidate. После его публикации обновить signed inputs/steps в новом writable gate, закрыть старый Sandbox и запустить новый только вручную пользователем.

### Сессия 184 — все CI gates зелёные после исправлений deploy и MSS harness — 2026-09-04

**CI:** для commit `007b6fe53cd92d43a1e89ccf34bcf40d80d3e0de` GitHub Actions run `33899645155` завершился `success`. Успешны все jobs: `Repository secret history gate`, `Go, packaging and syntax gates` (включая полный `go test -race ./...`, `go vet`, fuzz smoke и release builds), `Windows portable deploy contract` и `Linux nftables fail-closed gate` (включая direct/TUN MSS capture, startup, LAN, WireGuard, topology, Management Resource, VPS boundary и systemd steps).

**Что это подтверждает:** исправление project-local Windows staging, `USER@HOST` wizard и host+port endpoint validation прошло полный автоматический и packaging contract. Стабилизация `tcpdump` устранила подтверждённую race-причину предыдущего timeout `124`; Linux netns gate теперь получает готовый pcap до SYN и завершает bounded capture без false negative. `origin/main` содержит ровно этот commit, рабочее дерево чистое.

**Граница:** опубликованный `v0.1.1-testing.3bb466b` immutable и содержит старое поведение, поэтому повторять его в Sandbox не следует. Для проверки исправленного поведения нужен новый production-signed testing candidate: отдельное разрешение пользователя на открытие production key, сборку, exact tag и prerelease. Stable/latest не изменялись; Docker targets, `.cache` и evidence сохраняются.

**Следующий шаг:** после явного разрешения собрать и подписать новый testing candidate из `007b6fe`, создать prerelease (stable/latest не менять), затем повторить clean Windows Sandbox two-target deploy с `root@172.18.224.1` и портами `42022/42023`. Если новый guest gate пройдёт, остаются только физические Ubuntu Gateway/VPS/HiLink/Keenetic и 24/72-часовые endurance gates.

### Сессия 183 — устранена нестабильность Linux MSS release-gate — 2026-09-04

**CI result:** GitHub Actions run `33896874277` для нового source commit выполнил secret-history, Go/packaging/syntax и Windows portable jobs успешно. Linux nftables job остановился только на шаге `Prove owned firewall recovery and no direct route` с annotation `Process completed with exit code 124`; job logs закрыты GitHub API для обычного пользователя, но step inventory и timeout code однозначно указывают на bounded `tcpdump` MSS capture.

**Диагноз:** product source (wizard, deploy endpoint validator и Windows downloader) не участвует в этом netns script. В `firewall_guard.sh` capture запускался, затем клиентский SYN отправлялся после фиксированного `sleep 0.1`; на загруженном runner `tcpdump` мог ещё не открыть pcap, поэтому `timeout 5` завершался с кодом `124` до получения пакета. Это false negative release harness, а не обход fail-closed или неверный MSS.

**Исправление:** оба direct/TUN capture теперь используют bounded `timeout 10` и перед отправкой SYN ждут появления соответствующего pcap-файла (до 2 секунд), с понятной ошибкой и журналом, если `tcpdump` не готов. После readiness сохраняется короткая стабилизационная пауза; правило по-прежнему принимает ровно один SYN и проверяет точный MSS `1240`/`1260`.

**Проверки:** после изменения прошли `git diff --check` и полный serial `go test ./... -count=1 -p 1`; `go vet ./...` также прошёл. Локальный `go test -race` на Windows не запускается без `gcc` при `CGO_ENABLED=1`; это отдельно от Linux CI, где race и netns выполняются на Ubuntu. Новый source commit ещё требует CI rerun; production key, published immutable `3bb466b` и stable/latest не изменялись.

**Следующий шаг:** закоммитить harness fix вместе с предыдущими source/journal changes и отправить в `origin/main`, дождаться зелёного CI, затем получить отдельное явное разрешение на новый production-signed testing candidate и повторить clean-Windows deploy с корректными `USER@HOST` ответами. Старые targets/evidence и одноразовые Docker resources не удалять.

### Сессия 182 — clean Windows deploy безопасно остановлен на local validation, source fixes подготовлены — 2026-09-04

**Фактический запуск:** пользователь запустил опубликованный immutable `v0.1.1-testing.3bb466b` в Windows Sandbox. Мастер дошёл до локальной валидации и вернул `state=FAILED`, `failure_phase=LOCAL_VALIDATION`, `diagnostic_codes=["DEPLOY_INPUT_INVALID"]`. Ни Gateway, ни VPS не изменялись; application trees на обоих target-контейнерах по-прежнему отсутствуют, поэтому rollback не требовался.

**Причины остановки:** в поле VPS SSH был введён bare host `172.18.224.1`, хотя мастер требует `USER@HOST` (например, `root@172.18.224.1`). Кроме того, опубликованный validator сравнивал только host и ошибочно запрещал один IP для Gateway и VPS даже при разных SSH-портах `42022` и `42023`; это легитимная изоляция двух disposable targets, а не один и тот же SSH endpoint.

**Исправления в source:** локальная проверка теперь сравнивает полные `host+port`, блокирует только совпадающий endpoint и разрешает один host с разными портами. Интерактивный мастер отклоняет bare host до mutation и печатает понятный пример формата. Перед каждым параметром добавлены русские подсказки: назначение, допустимый формат, откуда взять значение и безопасный пример. Windows generated one-command больше не использует системный TEMP: staging создаётся в скрытой project-local подпапке текущей рабочей директории и удаляется в `finally`; этот контракт отражён в `OPERATIONS.md` и regression test.

**Проверки:** focused `go test ./cmd/gateway-vpn-deploy ./internal/deploy ./internal/distribution -count=1 -p 1` и полный serial `go test ./... -count=1 -p 1` прошли. `git diff --check` также прошёл. Новый signed candidate ещё не собирался, production key и GitHub stable/latest не затрагивались.

**Следующий шаг:** зафиксировать source и этот журнал обычным коммитом, отправить в `origin/main`, дождаться CI и только после отдельного явного разрешения пользователя собрать/подписать новый testing candidate. Затем повторить clean Windows two-target deploy с `root@host` для обеих целей и разными портами; старый immutable candidate повторно запускать не нужно. Docker resources, project `.cache`, targets и evidence сохраняются согласно проектным правилам.

### Сессия 181 — Windows Sandbox запущена, интерактивный deploy ожидает пользователя — 2026-09-04

**Запуск guest:** после публикации prerelease и повторного target precheck открыт project-local `Gateway-VPN-Clean-Gate.wsb`. Windows процессы `WindowsSandbox` и `WindowsSandboxClient` существуют с `2026-09-04 19:02:53/19:02:57`, отвечают и не перезапускались. Guest получает только read-only mapped gate directory; vGPU, audio/video input и printer redirection отключены согласно сохранённой конфигурации.

**Повторная проверка ожидания:** оба target-контейнера остаются `systemd=running`, `ssh=active`. На Gateway отсутствуют `/opt/gateway-vpn`, `/etc/gateway-vpn`, `/var/lib/gateway-vpn`; на VPS отсутствуют соответствующие `gateway-vpn-vps` trees. Следовательно, пользователь ещё не запускал portable deploy и никакой частичной установки либо network mutation на targets нет.

**Обязательная ручная граница:** Windows automation safety запрещает Codex вводить команды в PowerShell или автоматизировать terminal UI. Пользователю нужно вручную скопировать единственную строку из `C:\GatewayVPNGate\signed-windows-command.txt` в уже открытый PowerShell и ответить мастеру по `C:\GatewayVPNGate\SANDBOX-STEPS.txt`, после чего оставить окно открытым и передать финальный вывод. Sandbox и targets намеренно сохраняются; запуск заново, cleanup или изменение host security не выполняются.

**Следующий шаг:** получить финальный вывод portable deploy и независимо проверить обе установленные роли, signatures, reports, systemd units, WireGuard config и допустимые pending diagnostics. Ожидаемый итог изолированного TEST-NET gate — `INSTALLED_NOT_READY`/code `3`, а не `READY`.

### Сессия 180 — публикация immutable testing prerelease 3bb466b — 2026-09-04

**Разрешённая публикация:** пользователь отдельно разрешил опубликовать только testing prerelease `v0.1.1-testing.3bb466b`; rebuild, повторное открытие production key, новый tag, новый Draft и изменение stable channel не выполнялись. Одноразовый GitHub device login был создан только внутри существующего `gateway-vpn-release-builder-20260902`.

**Preflight и publication:** authenticated API нашёл единственный exact Draft Release ID `382816272` с `prerelease=true` и `14` assets. Annotated tag разыменован в exact commit `3bb466b6a418298c46d13073edeee5cff505ab1c`; перед публикацией latest оставался `v0.1.0-successor.5723940`. Exact Draft опубликован `2026-09-04T15:50:42Z` с явными `draft=false`, `prerelease=true`, `make_latest=false`; GitHub после публикации вернул `immutable=true`. Public URL: `https://github.com/Go4a4a/Gateway-VPN/releases/tag/v0.1.1-testing.3bb466b`.

**Независимая post-publication проверка:** все `14/14` assets заново скачаны из опубликованного Release в project-local `.cache/release-publication-0.1.1-testing.3bb466b-20260904T155042Z/published-assets`; каждый файл совпал с `dist` по exact имени и SHA-256. Повторная `channel-verify` подтвердила signer `fceb4a543d90aabbbe11a42d2c210c1565c235d017da7adc6c5b9d95c8eda60c`, manifest `9a47665d23fc8e250d2269545d8b07a6c75e11ff235c1f7f6a92917299c1c9f4` и все пять role artifacts. После logout подтверждено отсутствие `gh` credential, `GH_TOKEN` и `GITHUB_TOKEN`; manifest повторно скачан по публичному Release URL без авторизации и дал тот же SHA-256. Финальный API read подтвердил exact tag/commit, `14` assets, `draft=false`, `prerelease=true`, `immutable=true`; stable/latest остался `v0.1.0-successor.5723940`.

**Неуспешные безопасные попытки:** первая объединённая read-only команда разыменования tag остановилась на ошибке кавычек `--jq`; публикация ещё не выполнялась. Первая post-publication `channel-verify` использовала неверные сокращённые флаги `--version/--commit` и завершилась до проверки; исправленный вызов с `--release-version/--source-commit` прошёл. GitHub CLI `2.23.0` не поддержал `auth logout --user`; штатный logout единственной записи `github.com` затем успешно удалил credential. Эти ошибки не меняли release assets, tag, stable channel или локальный bundle.

**Post-publication handoff precheck:** оба fresh target-контейнера повторно подтверждены `running`; внутри Gateway и VPS `systemd=running`, `ssh=active`, список failed units пуст, application trees ещё отсутствуют. Отдельный Gateway `lan0` существует, остаётся `DOWN` без адреса и готов для выбора мастером; никакая установка либо network mutation этим precheck не выполнялась.

**Следующий шаг:** выполнить опубликованную hash-before-exec one-command в clean Windows Sandbox против уже подготовленных fresh Gateway/VPS targets, ожидая честный `INSTALLED_NOT_READY`/code `3` для изолированного TEST-NET endpoint; после этого переходить к физическим Ubuntu Gateway/VPS, HiLink/Keenetic/RTC и 24/72-часовым gates. Docker/cache/evidence не удалять автоматически.

### Сессия 179 — аудит оставшегося локального scope перед публикацией — 2026-09-04

**Проверено:** current `main` чист и синхронизирован с `origin/main`. Повторный requirement scan текущего source исключил `.git`, `.cache`, `.tools`, `dist` и этот исторический журнал и не нашёл ни одного `TODO`, `FIXME`, `XXX` или `HACK`. Migration inventory непрерывен от `000001_initial.sql` до `000034_management_resource_health.sql`; ранее обсуждавшийся пропуск `000024` в текущем source отсутствует. DoD matrix содержит ровно `47` требований: `31 PASS_LOCAL`, `0 IN_PROGRESS_LOCAL`, `14 PARTIAL_EXTERNAL`, `2 NOT_RUN_EXTERNAL`.

**Уточнение evidence без повышения статуса:** DoD 21, 45 и 47 больше не ссылаются на устаревшие disposable candidates. В них записаны фактические production-signed `0.1.1-testing.3bb466b`, exact tag/verified hidden Draft, native Windows trust smoke, fresh Default Switch targets и готовый `.wsb`. Статусы сохранены `PARTIAL_EXTERNAL`, потому что testing prerelease ещё не опубликован, clean Windows guest не выполнила full deploy, а реальные hosts/hardware/power-cut не проверены.

**Вывод:** доступного незавершённого локального product-code scope аудит не обнаружил. Следующие доказательства являются внешними: отдельное разрешение на GitHub publication; интерактивный запуск one-command в clean Windows Sandbox; затем физические Gateway/VPS/HiLink/Keenetic/RTC и 24/72-hour runs. Эти gates не подменяются дополнительными unit/netns/Docker прогонами.

### Сессия 178 — fresh Ubuntu targets для clean Windows two-host gate — 2026-09-04

**Host safety preflight:** Docker Desktop `4.89.0`/Engine `29.7.2` исправен, `open-webui` остаётся `healthy`, Windows Sandbox component `Containers-DisposableClientVM` включён. До создания ресурсов свободно `34,98 GiB` на `C:`, `97,01 GiB` на Docker-диске `D:` и `115,61 GiB` на backup-диске `E:`. Никакой cleanup, prune, VHDX compact, удаление cache/containers/images или изменение `open-webui` не выполнялись.

**Восстановление test prerequisite:** прежний systemd rehearsal image был удалён по отдельному запросу очистки и закономерно отсутствовал. Из tracked `test/systemd/Dockerfile.ubuntu24` повторно собран exact local image `gateway-vpn-systemd-rehearsal:ubuntu24-751669c` от pinned Ubuntu digest `33ceb719…`; получен immutable image ID `sha256:5b6814dd995cad897b32033dc962635f0467404a1cbc58fc734d8967ee126db2`, размер Docker content около `49,4 MB`. Image включает Ubuntu 24.04, systemd, OpenSSH, nftables, WireGuard tools, dnsmasq-base и production dependency set; pull mutable Ubuntu tag не использовался.

**Подготовка:** внутри project-local `.cache/windows-clean-gate-0.1.1-testing.3bb466b` создан отдельный unencrypted Ed25519 identity только для disposable release gate и собран source-only `prepare-windows-targets.exe`. Helper SHA-256 `0e7a173270053f9719281bcfbea6a50e3417947e88e8793f8a7d35570a89c322`. Первый dry-run без `--apply` подтвердил exact image, системные Docker/OpenSSH executables, назначенный Default Switch address `172.18.224.1`, свободные distinct ports `42022/42023`, уникальные resource names и новое evidence directory; состояние `READY_TO_APPLY`.

**Apply result:** guarded helper с обязательными `GATEWAY_VPN_RELEASE_GATE=1`, `--release-gate-only` и `--apply` создал каждую роль через отдельный SSH-hardening stage, unique host key и exact committed image ID. Активны только final targets `gateway-vpn-win-gate-3bb466b-20260904-gateway` и `…-vps`; staging containers завершены и сохранены. Gateway target ID `7cf0d8c7…`, prepared image `321c2e0a…`, exact bind `172.18.224.1:42022→22`; VPS target ID `c9a827b0…`, prepared image `917d4eb3…`, exact bind `172.18.224.1:42023→22`. Оба final containers privileged только для disposable systemd release gate, используют private cgroup namespace и tmpfs `/run`.

**Проверено:** source-only helper сам сформировал pinned `known_hosts` и успешно выполнил key-only fixed Win32 OpenSSH authentication. Независимый повтор подтвердил TCP reachability обоих портов и pinned SSH. Внутри обеих ролей: `Ubuntu 24.04`, `systemctl is-system-running=running`, `ssh.service=active`, `systemctl --failed` пуст, отсутствуют `/opt`/`/etc`/`/var/lib` trees Gateway и VPS. Public evidence находится в `targets-evidence/targets.json`; disposable private identity не копировался в evidence.

**Sandbox handoff:** Gateway management/SSH остаётся на Docker `eth0`; отдельный test-only dummy NIC `lan0` создан в disposable Gateway target как аналог незанятой физической LAN-карты. Он не имеет IPv4/default route и не затрагивает host network; installer получит его как transit LAN, не разрывая management session. Project-local `Gateway-VPN-Clean-Gate.wsb` прошёл XML validation, включает networking и отображает только gate folder read-only в `C:\GatewayVPNGate`; vGPU, audio/video input и printer redirection отключены. Точная signed one-command скопирована без изменения как `signed-windows-command.txt`, SHA-256 `6ed67428b4979b9ee366af87364c366a8e53db2ec3315cf1e1aab6d70444a618`; `SANDBOX-STEPS.txt` содержит все ответы мастера. Изолированный public endpoint использует TEST-NET `198.51.100.1:51821`, поэтому ожидаемый итог Docker delivery gate — честный `INSTALLED_NOT_READY`/code `3`, а не ложный `READY` без реального VPS/modem path.

**Ошибки без скрытого повторного mutation:** первая сборка helper использовала неверный путь к сохранённому Go (`.tools/go1.26.7/bin` вместо `.tools/go1.26.7/go/bin`) и остановилась до создания binary/containers. Следующая сборка корректно отказалась из-за Git ownership; применён только process-local `GIT_CONFIG_COUNT`/`safe.directory`, глобальный Git config не менялся. После успешного единственного `--apply` внешняя диагностическая команда ожидала неверное имя `evidence.json`; фактический `targets.json` и оба targets уже были корректны, `--apply` повторно не запускался. Первый ручной SSH probe не заключил путь `known_hosts` с пробелом во внутренние quotes и был отвергнут до authentication; точный формат helper прошёл без изменений targets.

**Граница:** targets готовы, но clean Windows Sandbox ещё не выполнила portable deploy. Hidden Draft недоступен обычной download-команде до публикации, а publication требует отдельного явного разрешения. Никакой hardware/Linux production gate этим Docker evidence не закрывается.

**Следующий шаг:** после явного разрешения опубликовать testing prerelease `v0.1.1-testing.3bb466b`, проверить immutable remote state и удалить GitHub credential. Затем запустить clean Windows Sandbox и выполнить опубликованную hash-before-exec one-command против `172.18.224.1:42022/42023`, используя pinned `known_hosts` и disposable identity.

### Сессия 177 — production-signed candidate 3bb466b, verified Draft и native Windows trust smoke — 2026-09-04

**Exact candidate:** production `.gvkey` успешно открыт пользователем через скрытый prompt только на время сборки; пароль не передавался через chat, argv, environment или файл. Exact source `3bb466b6a418298c46d13073edeee5cff505ab1c`, version `0.1.1-testing.3bb466b`, pinned Mihomo `v1.19.30`, signer fingerprint `fceb4a543d90aabbbe11a42d2c210c1565c235d017da7adc6c5b9d95c8eda60c`. Temporary plaintext identity существовал только в container tmpfs и был удалён; encrypted key остался at rest.

**Signed artifacts:** Gateway release содержит `57` файлов, VPS release — `35`, testing channel — `5` artifacts. SHA-256: Gateway archive `68f2598affddd0f406c5010cb2b1d859eb06b02a071f89dcaf6ebc93811899f7`, VPS archive `541eaf2fff99a7b8b95a117e2ceca0e928a684206154ac5d005afbc9209efeca`, bootstrap `57eba5458de626163c6a2e4b78728ce3a68bfca17a09c563158365ae4195755e`, Linux deploy `7c864337b1b5e9841f829bf7efe66a718c91eeb9e47ec84f80f5a8503f7d7748`, Windows deploy `569137023eeaf4fb8ffdcb84a8781d3c874257b2edab43310b6c86a696a4c789`, channel manifest `9a47665d23fc8e250d2269545d8b07a6c75e11ff235c1f7f6a92917299c1c9f4`. Полный Gateway/VPS/channel bundle повторно проверен после сборки.

**GitHub delivery state:** annotated exact tag `v0.1.1-testing.3bb466b` отправлен в `origin`. Создан скрытый Draft Release `https://github.com/Go4a4a/Gateway-VPN/releases/tag/untagged-6082e40f650cb1b69d2d`, сразу классифицированный как prerelease. Repository release immutability включена; `14/14` скачанных обратно assets совпали с локальными по имени, размеру и SHA-256. GitHub device credential после проверки удалён. Draft не опубликован, public stable/latest остаётся `v0.1.0-successor.5723940`.

**Windows launcher defect и исправление:** прежний project-local signing launcher падал в Windows PowerShell 5.1 на parser error около `&&` и повреждённой UTF-8 строки. Launcher переведён на ASCII-only и безопасную single-quoted format string; настоящий Windows PowerShell 5.1 принял его, после чего пользователь получил полный успешный signed build до `Press Enter to close this window`.

**Native Windows artifact smoke:** текущий exact `.exe` фактически запущен на Windows. `--version` вернул exact version/commit. Валидные manifest/signature/public key, manifest hash, signer, channel, version и commit прошли cryptographic и running-self-identity verification; запуск намеренно остановлен до SSH/apply с ожидаемым code `2`. Отдельные cases ожидаемо отвергли wrong manifest hash, wrong signer, tampered signature и изменённый PE. Generated one-command прошёл Windows PowerShell 5.1 AST parser; статически доказаны hash-before-exec, восстановление `SecurityProtocol` и удаление download directory в `finally`. Итог `9/9 PASS`; evidence сохранено только внутри `.cache/release-builder/windows-native-smoke-0.1.1-testing.3bb466b`.

**Граница:** это подтверждает signed Windows trust boundary, но не является clean Windows 10/11 guest и не выполняет двухцелевой SSH deploy. Draft нельзя публиковать без отдельного явного разрешения. Физические Ubuntu Gateway/VPS, HiLink/Keenetic/provider paths, USB/power/RTC и 24/72-часовые endurance не засчитывались.

**Следующий шаг:** после отдельного разрешения опубликовать именно testing prerelease, повторно проверить immutable tag/assets и неизменность stable/latest, удалить одноразовый GitHub credential; затем подготовить fresh два systemd/SSH target и выполнить clean Windows guest two-target deploy опубликованной one-command.

### Сессия 176 — возобновление critical delivery gate на xhigh — 2026-09-04

**Подтверждение режима:** пользователь явно переключил уровень с `High` на `xhigh` и разрешил продолжить работу. Следующий блок остаётся сквозным release-delivery/zero-to-ready gate; уровень не будет понижен без обязательной остановки и отдельного подтверждения.

**Уточнённый management-инвариант:** обсуждение локального доступа через Keenetic не изменило архитектуру. WebUI/API остаются независимы от пользовательского Internet path и доступны через назначенный LAN/management bridge либо явно разрешённый management address профиля `SHARED_ONE_ARM`; `PATH_BLOCKED`, отказ модема, Mihomo или подписок их не закрывают. Dedicated uplink/HiLink не становятся management bind target. Safe network apply сохраняет старый путь до подтверждения нового и откатывается при timeout/reboot. Guest Wi-Fi/VLAN isolation либо внешний firewall Keenetic остаются явным внешним prerequisite, а не поводом расширять Gateway firewall.

**Проверено перед candidate:** `main` чист и синхронизирован на `a52fbdd`; CI #86 для неизменившегося code tree завершён `Success`. Предыдущий production-signed testing bundle относится к tag `v0.1.1-testing.645500a` и не переиспользуется как current candidate.

**Следующий шаг:** после отдельного явного разрешения использовать production `.gvkey`, собрать воспроизводимый testing bundle из exact clean HEAD, создать новый immutable testing tag и GitHub Draft Release. Публикация prerelease остаётся отдельным действием после проверки draft/asset hashes и release-immutability policy.

### Сессия 175 — полный CI текущего source и локальная повторная проверка — 2026-09-04

**Авторитетный внешний результат:** GitHub Actions CI #86, run `33863273880`, для current code commit `58fff86` завершился `Success`. Успешны все четыре jobs: repository secret-history gate; Windows portable deploy contract; Go race/vet/bounded fuzz/Linux builds/JavaScript и shell syntax; privileged Ubuntu nftables fail-closed/systemd gate.

**Локальная проверка:**

- `go vet ./...` прошёл с `GOCACHE`, `GOMODCACHE`, `TEMP`, `TMP` и `GOTMPDIR` внутри project `.cache`;
- последовательный `go test -count=1 -p 1 ./...` с теми же project-local paths прошёл для всех пакетов, кроме четырёх `internal/update` security-тестов: они ожидаемо отказались создавать release-signing keys внутри Git worktree;
- попытка повторить только `internal/update` во внешнем системном `%TEMP%` была остановлена средой до запуска, поскольку отдельного разрешения пользователя на внешний временный путь нет. Защита не ослаблялась и не обходилась; те же тесты успешно выполнены race-suite CI #86 во внешнем ephemeral runner temp;
- `git diff --check` прошёл; рабочее дерево до этого journal update было чистым.

**Граница:** CI и локальные проверки не заменяют clean Windows guest, physical Gateway/VPS, реальные HiLink/Keenetic/provider paths, USB/power/RTC recovery и 24/72-часовые endurance. Production key, Docker resources, теги, Draft и stable release не изменялись.

**Следующий шаг:** выполнить clean Windows 10/11 x64 full signed two-target deploy. Это сквозной zero-to-ready/release-delivery gate; до его начала по проектному протоколу требуется явно подтверждённый `xhigh`, а новый candidate/signing/tag/Release — отдельное разрешение пользователя.

### Сессия 174 — подтверждение текущего уровня и CI после journal commit — 2026-09-04

**Сделано:**

- зафиксирован явно подтверждённый пользователем рабочий уровень `High / Высокий`; запись о прежнем `xhigh` удалена из актуального среза;
- после документальных commit GitHub автоматически отменяет устаревшие проверки и запускает актуальный CI для последнего commit; secret-history и Windows jobs текущего CI уже завершились успешно, основной Go/packaging job ещё выполняется.

**Граница:**

- это только актуализация статуса и контроль автоматической проверки; код, конфигурация, Docker-ресурсы, production key, теги и релизы не изменялись;
- clean Windows guest, физические Linux/hardware/VPS gates и endurance остаются обязательными внешними проверками.

**Следующий шаг:** дождаться полного результата CI #84 и внести его в журнал. Для любого нового signed candidate или GitHub Release потребуется отдельное подтверждение пользователя.

### Сессия 173 — фиксация Windows portability и контроль CI — 2026-09-04

**Сделано:**

- подтверждено, что изменения Windows portability из сессии 172 зафиксированы коммитом `f508ec9` и отправлены в `origin/main`;
- исправлена устаревшая запись о том, что CI #82 ещё выполняется и код не отправлен: CI #82 (`33859374962`) завершился успешно, а новый код уже находится в remote;
- новый CI #83 (`33861843233`, commit `f508ec9`) запущен GitHub Actions; до его завершения release/tag и новые privileged-действия не выполняются.

**Граница:**

- локальная Windows-среда и CI не заменяют clean Windows guest, физический Ubuntu Gateway/VPS, HiLink/Keenetic, реальные Ethernet/TUN/WireGuard/provider packet captures, USB/power/RTC recovery и 24/72-часовые endurance;
- production key, testing/stable tag и GitHub Release не открывались и не изменялись.

**Следующий шаг:** после завершения CI #83 зафиксировать его итог в журнале и перейти к clean Windows two-target deploy либо к подготовке hardware handoff; для нового подписанного candidate/release потребуется отдельное разрешение пользователя.

### Сессия 172 — Windows portability и project-local test temp — 2026-09-04

**Сделано:**

- Windows `internal/vpsupdate` lifecycle fixtures теперь сначала проверяют наличие права на создание symlink. При обычном Windows-процессе без Developer Mode/`SeCreateSymbolicLinkPrivilege` пропускаются только symlink-зависимые VPS lifecycle-тесты с явным объяснением; Linux CI по-прежнему выполняет их полностью.
- `internal/deploy` получил платформенный предел каталога persistent SSH: Linux сохраняет строгий 100-байтный предел для Unix `ControlPath`, Windows framed `ssh.exe` backend допускает bounded 240-байтный абсолютный путь. Это позволяет безопасно использовать project-local `.cache/tmp`, не включая Unix socket limit для пути, который Windows backend не передаёт OpenSSH.

**Проверено:**

- `go test -count=1 -v ./internal/vpsupdate` с `TEMP/TMP` внутри `.cache/tmp` — PASS; symlink-only tests корректно `SKIP`, остальные journal/status/runtime tests PASS.
- `go test -count=1 -v ./internal/deploy` с project-local temp — PASS, включая Windows system OpenSSH readiness, persistent one-TCP session, cancellation и framing.
- `go test -count=1 ./internal/update` — PASS с внешним системным temp только для security-тестов, которые намеренно требуют отказа при размещении signing key внутри Git worktree; ключи не сохраняются, `t.TempDir` удаляется после тестов.
- Все остальные пакеты `go test -count=1` с project-local `TEMP/TMP/TMPDIR`, а также `go vet ./...` и `git diff --check` — PASS. Никакие Docker-ресурсы, project cache, теги или релизы не удалялись/не создавались.

**Граница:** локальная Windows-среда не заменяет clean Windows guest, Linux/VPS/hardware и 24/72-часовые gates. На момент этой сессии CI #82 и отправка нового коммита ещё не были завершены; итог зафиксирован в сессии 173.

**Следующий шаг:** зафиксировать эти изменения отдельным обычным коммитом, отправить его в `origin/main` и проверить новый CI; затем вернуться к clean Windows two-target deploy/hardware handoff. Production key, tag и Release не открывать/не менять без отдельного разрешения.

### Сессия 171 — полный CI gate после MSS/security инкремента — 2026-09-04

**Внешний результат:** GitHub Actions run `33857428928` (`#81`) для `74573d804436a694ab50409b9b70562ad642b79c` завершился `Success` за `20m 40s`.

**Закрытые jobs:**

- `Repository secret history gate` — `success`, summary `No leaks detected`;
- `Go, packaging and syntax gates` — `success` за `17m 28s`, включая `go test -race ./...`, vet, четыре bounded fuzz smoke, Linux/Windows builds и JS/shell syntax;
- `Windows portable deploy contract` — `success` за `1m 14s`;
- `Linux nftables fail-closed gate` — `success` за `1m 50s`, включая route-aware MSS packet capture, firewall recovery, startup policy, multi-port LAN, WireGuard ingress, topology, service routes, five Management Resource profiles, VPS ownership boundary и Ubuntu 24 systemd verification.

**Граница:** этот CI подтверждает воспроизводимость source и privileged Ubuntu namespace/systemd gates, но не заменяет clean Windows guest, физический Ubuntu Gateway/VPS, реальные HiLink/Keenetic/provider paths, USB/power/RTC recovery и 24/72-часовой endurance. Testing Draft не публиковался и stable/latest не изменялся.

### Сессия 170 — route-aware MSS, secret-history gate и полезные рекомендации — 2026-09-04

**Сделано:**

- route-aware TCP MSS clamping закреплён в firewall schema `8` и packaging template для всех пользовательских verified путей: HiLink, Ethernet, Mihomo TUN и разрешённый `wg-ingress`; наличие модема не является условием. Отдельная `forward_mss` chain работает только для TCP SYN, а значение вычисляется ядром по route MTU (`rt mtu`).
- CI получил обязательный полный-history secret scan с pinned action/engine, а четыре критичных формата получили bounded fuzz smoke. В `.gitleaksignore` оставлены только шесть разобранных исторических false-positive fingerprint; целые `test`/`fixtures` не исключаются.
- Windows portable deploy теперь заранее проверяет именно `C:\Windows\System32\OpenSSH\ssh.exe` и выводит точные команды диагностики/установки OpenSSH Client, не меняя Windows молча.
- диагностика `MODEM_SUBNET_CONFLICT` стала структурированной: WebUI/API показывают CIDR, конфликтующие номера/интерфейсы, доступный management URL и универсальную инструкцию без предположений о производителе модема.
- генератор fixture перенесён на проектную рабочую папку; системный `%TEMP%` для Gateway VPN не использовался.

**Проверено:**

- полный последовательный `go test ./... -count=1 -p 1` выполнен с project-local `GOCACHE/GOTMPDIR`; все остальные пакеты прошли. Четыре `internal/update` key-file теста ожидаемо отклонили project-local temp как Git worktree, а Windows `internal/vpsupdate` symlink-тесты требуют отдельного `SeCreateSymbolicLinkPrivilege`; security invariants не ослаблялись.
- `go vet ./...` — PASS; `gofmt` для всех Go-файлов, `node --check`, Git Bash `bash -n` для shell entrypoints и `git diff --check` — PASS.
- ранее сохранённый privileged packet gate фактически подтвердил MSS 1240 при route MTU 1280 для direct/Ethernet и MSS 1260 при MTU 1300 для TUN-подобного пути; management/UDP/неактивный egress в правило не попадают.
- изменения зафиксированы коммитом `693f70e` (`security: add route-aware MSS and validation gates`) и отправлены в `origin/main`; новый tag/Release не создавался, текущий testing Draft и stable/latest не изменялись.

**Ограничения:**

- gitleaks-контейнеры и validation resources не удалялись. Docker API в текущем Windows-сеансе вернул `Access denied`, поэтому inventory-only проверка контейнеров отложена без mutation.
- реальный Ubuntu Gateway/VPS, модемы, Keenetic, физический Ethernet/TUN/WireGuard capture и 24/72-часовой endurance по-прежнему не выполнены. Поэтому MSS и весь продукт не переводятся в `production-ready` только на основании локального gate.
- после успешного push локальный `git ls-remote` не смог получить credential через Windows Schannel (`SEC_E_NO_CREDENTIALS`); удалённый CI для `693f70e` нужно проверить через GitHub Actions после появления run.

**Следующий шаг:** использовать зелёный CI run `#81` как базу для clean Windows guest и физических hardware/VPS gates; testing Draft не публиковать без отдельного разрешения.

### Сессия 169 — production-signed testing draft и защита stable/latest — 2026-09-04

**Разрешённая release-операция:** пользователь явно разрешил использовать production `.gvkey`, собрать и подписать новый testing release и создать только GitHub Draft Release, не меняя stable channel; уровень `xhigh` подтверждён. В одном сохранённом Linux builder использованы официальный Go `1.26.7` с SHA-256 `ffb5f8de10c62550dfddab66b36b57030721e0a44a3218e9e1181d7b59f121ca` и официальный Mihomo `v1.19.30` archive SHA-256 `cbe553d0319a414bd3a372c5976a252155b2c4882b66bce88a4d6bba9571a553`; распакованный Mihomo совпал с закреплённым SHA-256 `20ba567571d9ca642bedecbb01f8092cab0f1679100087ef1a4a2efac0ed5494`. Все caches/inputs/evidence находятся только в project-local `.cache/release-builder`; `%TEMP%` не использовался.

**Exact identity и подпись:** annotated tag `v0.1.1-testing.645500a` указывает ровно на clean commit `645500a2645ff4fdcde88c28d024e4d30f8d0400` и отправлен в `origin`. Primary key был подключён read-only; passphrase введена пользователем в отдельном скрытом prompt и не попала в чат, argv, environment, файл или журнал. Encrypted wrapper раскрыл identity только в `/dev/shm`; после завершения `KEY_UNLOCK_DIRS=0`. Независимый verifier из exact source подтвердил Gateway `57` файлов, VPS `35` файлов и `channel-testing` с `5` artifacts, единый signer `fceb4a543d90aabbbe11a42d2c210c1565c235d017da7adc6c5b9d95c8eda60c` и channel manifest SHA-256 `7fafca63ee2ee602020c4bdf2ec4b540c1b7eb91a0a6282211831f1d04bc9263`.

**Draft и remote evidence:** после GitHub device authorization штатный `create-github-release-draft.sh` ещё раз проверил exact tag, обе роли и channel и создал скрытый Draft Release. Read-back обнаружил `isPrerelease=false`: draft не публиковался, metadata немедленно исправлена до `isDraft=true / isPrerelease=true`. Все `14` remote assets скачаны обратно в `.cache/release-builder/remote-draft-0.1.1-testing.645500a`; число файлов `14/14`, SHA-256 каждого совпал с локальным `dist`. Опубликованный `v0.1.0-successor.5723940` остаётся `stable/latest`, не draft и не prerelease. GitHub CLI credential после проверки удалён из builder.

**Исправление повторения:** publisher теперь добавляет `--prerelease` для любого `CHANNEL != stable`; packaging regression и `OPERATIONS.md` фиксируют это как `DEV-259`. Focused `go test ./test/packaging -count=1`, `bash -n scripts/create-github-release-draft.sh` и `git diff --check` — PASS. Первая невидимая PTY попытка signing prompt была прервана до `dist`; первый GitHub device code истёк после закрытия страницы, второй завершился успешно. Ни одна из этих попыток не создала partial release и не изменила stable channel.

**Сохранённые ресурсы:** `dist`, builder, project-local Go/Mihomo caches и remote verification bundle намеренно не удаляются. `open-webui` не изменялся. Новый Docker/project backup не создавался.

**Следующий шаг:** зафиксировать и отправить prerelease-guard/journal в `main`, дождаться exact CI. Testing draft не публиковать без отдельного явного разрешения и проверки repository release immutability; после разрешённой публикации выполнить clean Windows delivery и первую физическую установку Gateway/VPS по hardware runbook.

### Сессия 168 — полный GitHub CI после исправления endurance fixture — 2026-09-02

**Внешний gate:** GitHub Actions run `33636614345` для commit `5aad23b1a94762592fa4b82c1767927de31c96f7` завершён со статусом `success`. Все три job прошли: `Go, packaging and syntax gates` (включая `go test -race ./...`, vet, Linux/Windows builds и JS/shell syntax), `Windows portable deploy contract` и `Linux nftables fail-closed gate`.

**Root netns/systemd evidence:** успешно выполнены firewall recovery/startup policy, multi-port LAN SSH, WireGuard ingress handshake, topology rollback, signed-update service-route ladder, пять Management Resource profiles, VPS operations ownership boundary и pinned Ubuntu 24.04 Gateway/VPS systemd verification. Это первый полный CI run после `9028869` без calendar-dependent endurance failure.

**Ограничение:** production signing key/tag/Release не использовались; clean Windows VM, physical Ubuntu Gateway/VPS, HiLink/Keenetic/WireGuard captures и обязательные 24/72-hour endurance остаются внешними gates.

**Следующий шаг:** подготовить следующий разрешённый release/hardware gate; production publication выполнять только после отдельного разрешения пользователя. Новые Docker/project backups не создавать без отдельного запроса.

### Сессия 167 — локализация временных Go-кэшей — 2026-09-02

**Замечание пользователя и исправление процесса:** focused `go test` первоначально не смог создать стандартный cache в профиле Windows (`Access denied`), поэтому для единичного прогона были временно назначены `%TEMP%\gateway-vpn-go-build` и `%TEMP%\gateway-vpn-go-mod`. Тест `internal/endurance -count=20` прошёл, после чего оба созданных каталога удалены (`17 553` файлов, освобождено около `1.17 GiB`); вне project tree этих ресурсов больше нет.

**Новое правило:** в `AGENTS.md` закреплено, что кэши, временные файлы и результаты Gateway VPN хранятся внутри папки проекта; системные `%TEMP%`/профили пользователя не используются без отдельного согласования и обязательной записи назначения/удаления в журнале. В дальнейшем тестовые кэши будут направляться в явно созданный project-local каталог и не будут автоматически чиститься без отдельного запроса.

**Следующий шаг:** продолжить полный GitHub CI после push commit `9a900a3`; Docker backup и project backup не пересоздавать без отдельного запроса.

### Сессия 166 — согласованная очистка host и единичные backups — 2026-09-02

**Сделано по отдельному запросу пользователя:**

- из рабочей папки проекта удалён только disposable `.cache` (`10 217` файлов, освобождено около `0.49 GiB`); исходники, `.git`, документы, fixtures и закреплённый `.tools/go1.26.7` сохранены;
- Docker Desktop корректно остановлен на время snapshot, актуальные `D:\Docker\DockerDesktopWSL\disk\docker_data.vhdx` и `main\ext4.vhdx` скопированы на `E:`; новая копия проверена по размеру/сравнению `robocopy`, старый backup удалён только после успешной проверки;
- на `E:` оставлена единственная Docker-копия `E:\Gateway-VPN-recovery\2026-09-02-post-cleanup-recovery` (`docker_data.vhdx` `11 978 932 224` bytes + `ext4.vhdx` `100 663 296` bytes, всего около `11.25 GiB`); временная `.rebuild` удалена;
- в ту же папку добавлена одна копия проекта `...\project`; после синхронизации журнала `16 088` файлов и `258 002 882` bytes совпадают с источником, `robocopy /L` не выявил расхождений;
- Docker Desktop снова запущен, `open-webui` сохранил container/image/volume и после запуска перешёл в `healthy`; новые копии Docker без отдельного явного запроса пользователя создаваться не будут.

**Ограничение:** backup проекта отражает текущую рабочую копию на момент сессии и не заменяет GitHub remote; production signing key и runtime secrets в backup не добавлялись.

**Следующий шаг:** вернуться к незавершённому CI-фокусу из сессий 164–165; новые disposable targets создавать только непосредственно перед соответствующим gate.

### Сессия 165 — восстановление NVMe/Docker и согласованная очистка development host — 2026-09-02

**Инцидент и признанная ошибка процесса:** после локальных длительных Docker/race прогонов Linux storage ранее перешёл в `read-only filesystem`, затем API вернул `502`. Работа должна была быть сразу остановлена, но Windows Sandbox осталась запущенной, а host storage не был немедленно проверен. Позднее Docker Desktop показал `Wsl/Service/RegisterDistro/MountDisk/HNS/0x800701b1` для `D:\Docker\DockerDesktopWSL\main\ext4.vhdx`. Ничего не удалялось, однако System log доказал не Docker-only fault: `3506` событий `disk 51`, `Ntfs 50/140`, три reset `stornvme 129` и controller error `11`; `NE-512` исчез из `Get-Disk`, возвращал size `0`, а Windows фиксировала lost delayed writes в `$Mft`, `$UsnJrnl`, BlueStacks и Docker VHDX. Docker был полностью остановлен, Sandbox закрыта вместе с её `vmwp`; factory reset, unregister, reinstall и VHDX deletion не выполнялись.

**Host-first recovery:** после полного power cycle `NE-512` вернулся как online 512-GB disk, `D:` снова имел NTFS/MFT и partition mapping. Оба NVMe сообщают одинаковый аппаратный EUI `eui.0100000000000000`, поэтому Windows пишет `disk 158`; официальный Microsoft contract считает это warning без client functionality/performance impact, и identifiers не менялись. `chkdsk /scan` в текущем elevated execution context дважды ошибочно сообщил `RAW`, тогда как `Get-Volume`, `fsutil volumeinfo/ntfsinfo`, MFT metadata и последующее непрерывное чтение подтвердили NTFS; никакие repair flags не применялись. Отсоединённые Docker VHDX были скопированы на `E:`: `63,321,407,488` bytes, zero failed/mismatch; source/backup одинаково прошли `Get-VHD`, а за 17 минут чтения не появилось новых storage events.

**Явно разрешённая очистка:** после успешного старта Docker инвентаризация нашла `73` остановленных `gateway-vpn-*` containers, `10` связанных image IDs, один disposable project volume и `194.9 MB` build cache; один staged race container занимал `19.4 GB`. Удалён только этот project-scoped набор. `open-webui` container/image/volume сохранены, его restart policy `always`, health `healthy`, HTTP loopback — `200`; неизвестный старый `node:24.14.0-bookworm-slim` сохранён как не принадлежащий доказанно проекту. После штатного Docker shutdown detached `docker_data.vhdx` прошёл read-only mount + `Optimize-VHD -Mode Full` + guaranteed dismount: размер уменьшился с `63,489,179,648` до `11,968,446,464` bytes, возвращено `51,520,733,184` bytes. Docker/WSL повторно запустились, `open-webui` остался healthy, новых NVMe/NTFS errors нет.

**Backup и project cache:** актуальный остановленный Docker state повторно скопирован и проверен как `E:\Gateway-VPN-recovery\2026-09-02-post-cleanup-recovery` (`12,079,595,520` bytes, zero failed/mismatch, оба VHDX structurally readable); только после этого прежний 63-GB backup удалён. По отдельному запросу пользователя project `.cache` уменьшен с `16.70 GiB`/`158,308` files до `0.495 GiB`: удалены старые validation/release bundles, duplicated build/GOPATH caches и disposable binaries; сохранены `gomod-final`, `go-build-final`, `.tools/go1.26.7`, `.git`, source/docs и текущие непушенные изменения. После завершения свободно примерно `C: 49.35 GiB`, `D: 57.36 GiB`, `E: 115.92 GiB`. Production `.gvkey` не открывался и не находился в очищаемом дереве.

**Граница:** восстановление development host не является Linux/hardware evidence Gateway VPN. NVMe reset/lost-write остаётся host hardware/firmware/driver risk и при повторении требует немедленного stop по `DEV-258`; отсутствие новых событий после power cycle/backup/compact не доказывает долговременную исправность накопителя.

**Следующий шаг:** зафиксировать календарный fixture как `DEV-257`/сессию 164, повторить focused test, отправить code+journal в `origin/main` и дождаться полного GitHub CI. Disposable clean-Windows targets после cleanup создавать заново только перед фактическим gate, а не заранее.

### Сессия 164 — устранение calendar-dependent endurance smoke fixture — 2026-09-02

**Внешний gate:** GitHub Actions run `33625094372` для `70fbfdbe90b599890eef9531ae35d7ef07571fd6` повторно завершил `Windows portable deploy contract` и прошёл весь non-root Linux race/vet/build/syntax набор до последнего Go package. Единственным failure стал `internal/endurance`: smoke runner передавал `time.Now()` как sample timeline, но diagnostic fixture имел immutable `CollectedAt=2026-08-26T12:00:00Z`; после 2026-09-02 11:15 UTC sample evaluation пересекла собственный предел `7 days + 15 minutes`. Зависимый root netns job корректно не запускался, поэтому исправленные service-route/Management Resources/VPS ownership/systemd gates всё ещё требуют первого фактического CI выполнения.

**Исправление без изменения production:** runner fixture теперь использует `sampleStart=2026-08-26T12:00:00Z`, то есть ту же явную timeline, что diagnostic retention snapshot. Production evaluator, retention days, tolerance и runtime timestamps не менялись. Контракт закреплён как `DEV-257`, code identity — commit `9028869e0a704b81aa5726c00346005613516ddf`.

**Локальная проверка:** точный ранее падавший test прошёл `20×`; весь `internal/endurance` завершился PASS. Исправление затрагивает только четыре строки test fixture и комментарий, production code не изменён.

**Следующий шаг:** commit журнала, push code+journal в `origin/main`, затем дождаться нового полного GitHub run и проверить все три jobs. Production signing key/tag/Release до зелёного результата не использовать.

### Сессия 163 — Git executable mode gate для всех shell entrypoints — 2026-09-02

**Неуспешный root gate:** повторный GitHub run `33622765978` для `b68675190664726c3b073b69728102dbff575892` завершил `Windows portable deploy contract` и весь `Go, packaging and syntax gates` job со статусом `success`; тем самым non-root ownership исправление подтверждено на чистом Ubuntu runner. Зависимый root job прошёл owned firewall recovery, startup policy, multi-port LAN SSH, WireGuard ingress и topology rollback, но остановился до выполнения service-route кода. Авторизованный GitHub Actions UI показал точную строку: `sudo: ./test/netns/update_service_routes.sh: command not found`.

**Причина:** у `update_service_routes.sh` был корректный `#!/usr/bin/env bash` и LF, но Git index mode `100644`. Полная проверка индекса нашла ещё пять таких entrypoints: Gateway uninstall helper, `management_resources.sh`, `mihomo_tun.sh`, `vps_operations_boundary.sh` и lifecycle validator. Локальный `bash -n` не выявлял дефект, потому что проверяет содержимое и не требует прямого исполнения файла.

**Исправление и защита от повтора:** все шесть файлов переведены только Git mode change в `100755`, без изменения содержимого. `.github/workflows/ci.yml` теперь вычисляет полный tracked `.sh` набор из Git index и завершает job ошибкой при любом mode, отличном от `100755`, до JavaScript/`bash -n`. Локальная проверка подтвердила: `42` shell-файла, zero non-executable tracked entries, `bash -n` PASS. Изменение зафиксировано commit `dc0c8d6326777ab9a89d4125f1ab2d24d8a81fb4`.

**Следующий шаг:** отправить mode fix и журнал в `origin/main`, дождаться нового полного GitHub run. Обязательный результат — success всех трёх jobs, включая ещё не выполненные в run `33622765978` service-route, Management Resources, VPS ownership и pinned Ubuntu systemd gates. Production signing/tag/Release до этого не выполнять.

### Сессия 162 — исправление non-root ownership fixtures после GitHub CI — 2026-09-02

**Неуспешный внешний gate:** GitHub Actions run `33609038214` для commit `be99f1fb87d023445f2f40df04388bb21142dc6d` успешно завершил `Windows portable deploy contract`, но job `Go, packaging and syntax gates` упал в `go test -race ./...`. Зависимый `Linux nftables fail-closed gate` поэтому был корректно пропущен. Точный log показал не preview-timeout, а попытки непривилегированного runner выполнить `chown` временных файлов на root либо чужой GID в `vpsbackup`, `vpsops`, `vpsupdate` и `vpswebapi`. После ранней ownership-ошибки один VPS update test дополнительно индексировал пустой `runtime.started` и паниковал вместо полезной диагностики.

**Исправлено без ослабления production:** VPS restore/config и Gateway restore projection получили private package-level root-owner identity с production default `0`; только same-package tests заменяют её на текущий UID/GID. VPS operations snapshot теперь сохраняет UID создавшего его root-процесса через `chown(-1, agentGID)` и меняет только группу, что точнее production-контракта. VPS updater/status/watchdog fixtures используют текущую process identity. Rollback test сначала проверяет непустой runtime trace. Exact root-only uninstall marker test явно пропускается без root и продолжает выполняться в root-capable suite.

**Дополнительная проверка:** focused race packages `vpsbackup`, `vpsops`, `vpsupdate`, `vpswebapi`, затем `removal` и `update` прошли от UID/GID `65534`. Первый полный parallel non-root race выявил те же оставшиеся hardcoded ownership fixtures; после их исправления следующий parallel run дошёл до конца основных packages, а два SQLite recovery tests единично дали ресурсную флуктуацию и отдельно сразу прошли. Для однозначности весь suite повторён последовательно с `-race -p 1`: пакеты до `subscription` прошли; после закрытия часового служебного контейнера отдельный точный хвост от `subscriptionnet` через все VPS/WebUI/fixtures/packaging packages завершился PASS. Обычный `go test ./... -count=1`, `go vet ./...` и `bash -n` всех shell entrypoints — PASS.

**Локальное ограничение среды:** два сохранённых fixture-файла старый root-container оставил на NTFS с отображением `0600`; поэтому clean-like race выполнялся из внутренней staged-копии с обычными read permissions, не меняя рабочие fixtures. После длительных прогонов Docker Linux storage перешёл в `read-only file system`, затем API вернул `502`; host Windows сохранял около 36 GiB свободного места. Никакие containers/images/volumes/cache/evidence не удалялись. После удаления только неиспользуемого helper и добавления комментария точный финальный diff дополнительно прошёл Windows Go 1.26.7 tests для `internal/update` и `internal/vpsbackup`.

**Результат:** исправление зафиксировано code commit `6a91c6dd49769415fe9a2d484be64bbc44462341`. Production signing key не открывался. Следующий обязательный шаг — отправить commit и этот журнал в `origin/main`, дождаться всех трёх GitHub jobs, включая netns/systemd, и только после зелёного CI отдельно согласовывать production signing/tag/draft Release.

### Сессия 158 — запуск Windows Sandbox и подготовка clean-gate targets — 2026-09-02

**Sandbox:** после разрешения пользователя и перезагрузки `Containers-DisposableClientVM` подтверждён как `Enabled`, `WindowsSandbox.exe` и отдельный `vmwp` process работают, pending reboot marker отсутствует. Попытка получить визуальное окно через Windows Computer Use вернула системное ограничение `SetIsBorderRequired … E_NOINTERFACE`; неподтверждённые координаты и обход этого ограничения не использовались.

**Fresh targets:** из сохранённого exact Ubuntu 24.04 rehearsal image созданы два новых, не переиспользующих старые, target-контейнера на Windows Docker Desktop host. Они опубликованы только на Hyper-V Default Switch address `172.28.64.1`, TCP ports `23001` (Gateway) и `23002` (VPS), с отдельным disposable ED25519 identity. Read-only preflight и apply helper завершились PASS; evidence содержит только public host-key fingerprints, image/container IDs, hashes и pinned `known_hosts`, private identity в evidence не копировалась.

**Ограничение текущего запуска:** candidate `0.1.0-successor.g2203d0b.crypto5` не опубликован в GitHub Release, а production signing/tag/Release не разрешены, поэтому его generated GitHub download command нельзя выполнять в Sandbox как полноценный delivery test. Windows Computer Use также запрещает автоматизацию PowerShell/терминала внутри Sandbox. Таким образом, запуск Sandbox и подготовка fresh targets закрыты, но clean Windows two-target deploy остаётся pending и может быть выполнен после публикации candidate либо вручную пользователем внутри Sandbox по согласованной команде.

**Следующий шаг:** отдельное разрешение на production signing/tag/GitHub draft Release (если нужен именно текущий candidate) либо предоставленная пользователем clean Windows VM/ручной запуск команды в Sandbox. После этого проверить hash-before-exec, единый persistent Win32 OpenSSH transport, оба fresh target, `INSTALLED_NOT_READY`/`READY` report и interruption diagnostics. Containers, evidence, cache и Sandbox не удалять автоматически.

### Сессия 159 — исправление ошибки Windows Sandbox `0x800706D9` — 2026-09-02

**Диагностика:** повторный запуск после перезагрузки показал `CmService` в `STOPPED` с `WIN32_EXIT_CODE=1068`. Его обязательная зависимость `hvhost` («Служба узла HV») была ошибочно переведена в `Disabled`; `RpcSs`, `RpcEptMapper`, BFE, Windows Firewall, `hns`, `vmcompute` и `vmms` при этом были исправны. Все требуемые Windows Features (`Containers-DisposableClientVM`, `VirtualMachinePlatform`, `Microsoft-Hyper-V-All`) уже имели состояние `Enabled`.

**Исправление:** с отдельного разрешения пользователя `hvhost` возвращён в штатный триггерный `Manual` режим и запущен; затем запущен `CmService`. После этого `hvhost` и `CmService` находятся в `Running`, повторный `WindowsSandbox.exe` создал живые `WindowsSandbox` и новый `vmwp`, свежих системных ошибок не появилось. Изменение обратимо и относится только к служебной конфигурации Windows host.

**Граница:** это закрывает host-side ошибку запуска Sandbox, но не заменяет pending clean Windows two-target deploy: текущий candidate `0.1.0-successor.g2203d0b.crypto5` по-прежнему не опубликован в GitHub Release. Containers, Sandbox, cache и evidence сохраняются по контракту.

### Сессия 160 — полный offline Go test/vet текущего commit — 2026-09-02

**Проверка:** в сохранённых Docker-контейнерах на pinned Go `1.26.7`, с `GOPROXY=off`, `GOSUMDB=off`, `CGO_ENABLED=0` и локальным module/build cache выполнены `go test ./... -count=1` и `go vet ./...` для clean commit `9f93a39c290b4e08afa5ed7c9281b02642ec2dd6`. Все пакеты, включая release-gate, WebUI, watchdog, routing, WireGuard, backup/restore и оба role-control plane, завершились `PASS`; оба контейнера завершились с exit code `0`.

**Среда/evidence:** сохранены контейнеры `gateway-vpn-test-9f93a39-20260902` и `gateway-vpn-vet-9f93a39-20260902`; первый неудачный probe с ошибочным вложенным shell quoting также сохранён как диагностическое evidence. Production key не монтировался, GitHub и host state не изменялись.

**Граница:** offline unit/integration suite не заменяет clean Windows two-target deploy, production signed publication и физические Ubuntu/HiLink/Keenetic/WireGuard/endurance gates.

### Сессия 161 — shell syntax gate текущего commit — 2026-09-02

**Проверка:** в отдельном сохранённом Linux-контейнере на pinned toolchain выполнен `bash -n` для всех `scripts/*.sh`, `test/release-gate/*.sh`, `test/systemd/*.sh`, `test/fixtures/*.sh` и `test/netns/*.sh`; контейнер завершился с exit code `0`.

**Граница:** синтаксическая проверка не запускает privileged systemd/nftables/netns/USB/Mihomo paths и не заменяет clean Windows deploy, production release или hardware gates.

### Сессия 157 — доступность clean Windows guest — 2026-09-02

**Read-only host discovery (до перезагрузки):** текущая ОС — Windows 10 Pro x64 `10.0.19045`. Hyper-V и `VirtualMachinePlatform` включены, `vmcompute`/`vmms` работают, Default Switch существует. Готовых Hyper-V VM нет; в пользовательских Downloads/Documents/Desktop не найдено локальных `.iso`, `.vhd`, `.vhdx`, `.wim` либо `.esd`. На момент этой исторической проверки Windows Sandbox component `Containers-DisposableClientVM` был выключен, `WindowsSandbox.exe` отсутствовал; после отдельного разрешения и перезагрузки актуальное состояние зафиксировано в сессии 158.

**Граница на момент сессии:** включение Windows Sandbox изменяло optional components текущей ОС и требовало restart, поэтому оно не выполнялось без отдельного согласования. Загрузка многогигабайтного Windows ISO и создание VM также не подменялись неявным действием. Production key, GitHub и candidate containers не затрагивались. Разрешение и перезагрузка выполнены позже; результат описан в сессии 158.

**Следующий шаг (исторический):** после явного разрешения включить Windows Sandbox без автоматической перезагрузки, сообщить фактический `RestartNeeded`, а после доступного reboot подготовить ephemeral `.wsb` и выполнить полный signed Windows two-target deploy. Этот host-side prerequisite закрыт в сессии 158; остаётся сам signed two-target deploy. Альтернатива — предоставленная пользователем clean Windows 10/11 VM.

### Сессия 156 — exact Gateway/VPS systemd lifecycle и Gateway preserve-uninstall — 2026-09-02

**Gateway exact fresh/reinstall:** сохранённый disposable Ubuntu 24.04 container с real systemd PID 1 повторил signed lifecycle candidate `0.1.0-successor.g2203d0b.crypto5`. Fresh apply с LAN `lan0`, `192.168.200.1/24`, DHCP и SSH/SFTP прошёл полный tracked validator: `GATEWAY_SYSTEMD_RELEASE_GATE_PASS`, schema `34`, firewall generation `7`, state root `0710`, DB `0600`, secrets `0700`. Same-version reinstall сохранил config/report/secrets/completed marker/current+recovery pointers и unit start-times (`GATEWAY_SAME_VERSION_REINSTALL_PASS`). Это exact evidence source identity `2203d0b`, а не перенос результата предыдущего code-equivalent candidate.

**VPS dependency preflight:** первоначальный заранее сохранённый VPS container имел `--network none`; installer правильно обнаружил отсутствующий пакет `python3`, а Docker не допускает подключение bridge к container с private `none` network. Он сохранён как отрицательное evidence. Отдельный fresh Ubuntu 24.04 systemd container с обычной сетью воспроизвёл clean-host contract. Первый `--install-dependencies` dry-run честно сообщил, что пустые APT indexes ещё не могут найти `python3`, и не создал managed state. Apply выполнил `apt-get update`, повторил mandatory simulation и установил ровно `13` новых dependency packages: `0 upgraded`, `0 removed`, `16 not upgraded`. Документационный endpoint `203.0.113.10:51821` затем был правильно отклонён как не globally routable; до managed mutation installer не дошёл. Повтор использовал только синтаксически глобальный test endpoint и не устанавливал с ним сетевое соединение.

**VPS exact fresh/reinstall:** signed install прошёл с schema `4`, двумя exact `wg-mgmt` peers, `10.80.0.1/24`, UDP `51821`, единственной owned nftables table, неизменными default route и DNS, обоими Hub HTTPS listeners, active recovery/update/fabric paths и timers. DB integrity/FK, state-root/DB/secrets permissions, zero owned restarts/failures, current/recovery pointers и `INSTALLED_NOT_READY` без реального Gateway/admin handshake подтверждены сохранённым read-only validator: `VPS_FRESH_SYSTEMD_RELEASE_GATE_PASS`. Same-version reinstall побайтно сохранил config, WireGuard private config, TLS, DB, install report, completed marker, package set, current/recovery pointers и start-times всех основных services/paths/timers: `VPS_SAME_VERSION_REINSTALL_PASS`.

**Gateway production preserve-uninstall:** операция запускалась не прямым обходом, а штатным production contour WebUI: bounded `/v1/uninstall/impact`, затем typed broker request `PRESERVE_DATA` и durable `gateway-vpn-uninstall.service`. Первая orchestration-попытка использовала ошибочно короткий 31-hex operation ID; broker отверг её без marker/mutation. Корректный 32-hex request завершился authenticated terminal receipt с `result=SUCCEEDED` и `packages_removed=0`. Строгий post-validator подтвердил: owned `/opt`/`/etc`/systemd/nftables удалены; исходные `ssh.socket=enabled/active` и `ssh.service=disabled/inactive` восстановлены; `lan0` снова поднят без managed `192.168.200.1/24`; исходные forwarding, `src_valid_mark` и IPv6 sysctl восстановлены. Сохранённая `/var/lib/gateway-vpn/state.db` имеет schema `34`, `integrity_check=ok`, пустой `foreign_key_check`, mode `0600`; результат `GATEWAY_PRESERVE_UNINSTALL_SYSTEMD_PASS`.

**Граница и ресурсы:** production `.gvkey` не открывался; использован прежний disposable candidate signer, private часть которого уже удалена. Push, tag, GitHub Release, clean Windows guest, physical Ubuntu Gateway/VPS, Huawei E3372h/Keenetic/mobile path и 24/72-hour endurance не выполнялись. Оба исходных containers, новый VPS networked container, caches, validators и evidence сохранены по `DEV-250`.

**Следующий шаг:** программный candidate снова готов к внешнему delivery gate. Нужен настоящий clean Windows 10/11 x64 guest с полным two-target deploy; production signing/tag/GitHub Release допустимы только после нового явного разрешения пользователя. После публикации — установка на физический Ubuntu Gateway/VPS и отдельные HiLink/Keenetic/USB/power/endurance gates.

### Сессия 155 — устранение stale operational snapshots и exact reproducible candidate — 2026-09-02

**Найденный defect документации:** аудит текущего дерева обнаружил устаревшие утверждения в release-facing docs: README называл watchdog `17-component` и schema-v24 rehearsal «ещё выполняющимся», `docs/OPERATIONS.md` повторял retired `17`-component и schema-25 ограничения, а `docs/SECURITY.md` содержал тот же retired numeric snapshot. Это не меняло runtime, но могло ввести оператора в заблуждение и попадало в Gateway documentation tree.

**Исправление и regression:** README теперь описывает HiLink/Ethernet uplinks, bounded component watchdog и завершённый exact disposable rehearsal; OPERATIONS фиксирует текущий Gateway schema 34/VPS Agent schema 4 contract; SECURITY больше не зашивает изменяемое число компонентов. Добавлены packaging regressions, запрещающие эти устаревшие snapshots. Focused packaging tests — PASS; `go vet -buildvcs=false ./...` — PASS; `git diff --check` — PASS.

**Новый exact build:** source `2203d0b223f5de2fb4620c3b11039b193a63d80c` дважды независимо собран offline в clone-a/clone-b с pinned Go `1.26.7`, `--network none`, `GOPROXY=off`, раздельными build caches и одним disposable signer fingerprint `2be9a3333e5d45bab7a12c45b427db067f114dde3cb7f8e57216b074ae877408`. Candidate: `0.1.0-successor.g2203d0b.crypto5`, Mihomo `v1.19.30`, SHA-256 Mihomo `20ba567571d9ca642bedecbb01f8092cab0f1679100087ef1a4a2efac0ed5494`. Обе `dist` содержат по `110` файлов; paths, sizes и SHA-256 совпали (`REPRODUCIBLE_DIST_PASS`). Основные SHA-256 clone-a: Gateway archive `fdbf2ed4fe7037cad8912b9edd260f69f897f81ef5021429e97457d28af4632c`, VPS archive `b528bdfd28475dd8b34b720921c7e11a288baa5d1ef04eade1ae7abd107a64cc`, bootstrap `a965ec9aeb05e749f1d6bc0581ccb840a840bb1ddca652c129477fcd641c8afe`, Linux deploy `03bcf484c34ff344372f3fa3538b779e564c907e2044895a4dc8e409f40b87ec`, Windows deploy `19d393b60a1eef5ef6e20c49502c3984fc729c7ecd0bc05d7a3f8fff52a5a1d8`, channel manifest `2109f3a6e912a8b78b996779ceb4aefed40371167339360e6c22f826f8c972fa`, channel signature `d6ee75dc51c9ca23a8bedf8831c1cde8876322e90b530811f0bbf77131494f9c`, public key `ba10aea0f7cc5216657ba40fc87e84f1f4640980bbe0985cdaaf12cdf16d7bd0`.

**Native Windows delivery:** new PE `--version`/signed channel positive path and the four required negative paths passed: wrong manifest hash, wrong signer fingerprint, tampered signature and tampered PE all stopped before SSH/target mutation. Results: `WINDOWS_EXACT_NATIVE_PE_SMOKE_PASS` with `WINDOWS_EXACT_VERSION_PASS`, `WINDOWS_SIGNED_CHANNEL_AND_SELF_IDENTITY_PASS`, `WINDOWS_REJECTS_MANIFEST_HASH_PASS`, `WINDOWS_REJECTS_SIGNER_PASS`, `WINDOWS_REJECTS_TAMPERED_SIGNATURE_PASS`, `WINDOWS_REJECTS_TAMPERED_PE_PASS`.

**Полный suite и ограничение среды:** full `go test -buildvcs=false ./... -count=1 -p 1` прошёл для всех пакетов, кроме `internal/vpsupdate`, где Windows-профиль без `SeCreateSymbolicLinkPrivilege` ожидаемо отверг тестовые symlink (`A required privilege is not held by the client`). Это известное ограничение Windows runner; Linux privileged lifecycle и ранее elevated/native gate для этой области проходят. Ошибка не связана с изменёнными docs/regression. Disposable private key после сборки удалён; public key и dist/evidence сохранены.

**Граница:** новый candidate имеет exact build/signature/native-PE evidence, но fresh/reinstall systemd lifecycle для source identity `g2203d0b.crypto5` ещё не повторён; сохраняется evidence предыдущего code-equivalent `gf9a2cb2.crypto4`. Production `.gvkey`, push/tag/GitHub Release, clean Windows VM, physical Gateway/VPS/HiLink/Keenetic и 24/72-hour endurance не выполнялись.

**Следующий шаг:** повторить exact Gateway/VPS fresh/reinstall/restore/uninstall systemd lifecycle для `g2203d0b.crypto5` в disposable Ubuntu environment; затем при отдельном разрешении пользователя выполнить production signing/tag/Release. Не удалять candidate, caches или Docker resources автоматически.

### Сессия 154 — exact native Windows PE и PowerShell delivery smoke — 2026-09-02

**Exact native PE:** финальный `gateway-vpn-deploy-windows-amd64.exe` candidate `0.1.0-successor.gf9a2cb2.crypto4` запущен непосредственно на Windows. `--version` вернул `gateway-vpn-deploy 0.1.0-successor.gf9a2cb2.crypto4` и exact source commit `f9a2cb2730717243304e6523bbb8f5c2df1f2aec`. Позитивный smoke проверил raw manifest, signature, trusted signer и собственные size/SHA-256/version/commit, после чего ожидаемо остановился с usage/code `2` до `--apply`; SSH, сеть и target hosts не затрагивались. Результаты: `WINDOWS_EXACT_VERSION_PASS` и `WINDOWS_SIGNED_CHANNEL_AND_SELF_IDENTITY_PASS`.

**Обязательные отрицательные проверки:** отдельные копии inputs доказанно отвергли неверный manifest hash, подменённый trusted signer, повреждённую channel signature и изменённый PE. Получены `WINDOWS_REJECTS_MANIFEST_HASH_PASS`, `WINDOWS_REJECTS_SIGNER_PASS`, `WINDOWS_REJECTS_TAMPERED_SIGNATURE_PASS` и `WINDOWS_REJECTS_TAMPERED_PE_PASS`; ни один отрицательный сценарий не дошёл до SSH либо target mutation.

**PowerShell hash-before-exec:** сгенерированная copy/paste-команда имеет `3098` bytes, `315` tokens, `18` commands и ровно `4` downloads. PowerShell AST не содержит parser errors; подтверждены четыре exact immutable GitHub URLs, проверка SHA-256 launcher и manifest до `& $launcher`, cleanup временного каталога в `finally`, отсутствие `Invoke-Expression`, `Start-Process`, изменения ExecutionPolicy, password/private-key literals и `.gvkey`. Это закрывает local/native input gate, но не подменяет выполнение команды из отдельного clean Windows guest.

**Архитектурная граница:** обсуждённые пользовательские режимы HAPP (`sing-box`, Xray, tun2proxy и смешанный proxy mode) не добавляются. Gateway VPN сохраняет один Mihomo data plane с зафиксированным mixed TUN: отдельные пользовательские движки не нужны и создали бы несовместимые routing/firewall/recovery paths.

**Ресурсы и ограничения:** test artifacts сохранены в `.cache/validation-f9a2cb2/windows-native-smoke`. Production `.gvkey` не открывался; push/tag/GitHub Release, Windows component/reboot, cleanup и hardware/endurance не выполнялись. Настоящий clean Windows 10/11 x64 guest с полным signed two-target deploy остаётся внешним gate.

**Следующий шаг:** journal commit зафиксировать локально. Далее без новой внешней среды или отдельного разрешения на production signing/publication остаются только уже перечисленные внешние gates: clean Windows guest, физические Ubuntu Gateway/VPS, Huawei E3372h/Keenetic/mobile path и 24/72-часовой endurance.

### Сессия 153 — финальный traversal successor, явные отрицательные assertions и обе systemd-роли — 2026-09-02

**Обнаружение и исправление gate:** первый exact successor `0.1.0-successor.g5180374.crypto3` воспроизводимо собрался и прошёл Gateway/VPS lifecycle, но финальная adversarial проверка показала, что tracked `validate_gateway_systemd.sh` использовал standalone `! command`. В Bash `set -e` не делает такую форму обязательным assertion: validator мог продолжить работу с активным Mihomo или непустыми `active_*` sets. Та же ошибка присутствовала в marker/restore-point gates; production `uninstall.sh` мог замаскировать не восстановленный enabled-state последующей проверкой active-state. Все обязательные отрицательные проверки переведены на явные `if ...; then error; exit/return 1; fi`; добавлен packaging regression. Исправленный validator фактически отверг активный Mihomo и искусственно заполненный `active_path_generation`, затем прошёл после возврата чистого состояния. Решение закреплено как `DEV-254`, source commit — `f9a2cb2730717243304e6523bbb8f5c2df1f2aec`.

**Финальная воспроизводимая identity:** два independent detached clone commit `f9a2cb2` с раздельными build caches, pinned Go image `sha256:e8c859f5632d…`, `--network none`, `GOPROXY=off`, `GOSUMDB=off`, read-only module cache и disposable signer `2c734b06f87a5d4724a0110d83d700ebe92fb54b3ddc9df091da27ed74e96a6a` побайтно собрали `0.1.0-successor.gf9a2cb2.crypto4`. Одинаковы paths/types/modes/sizes/hashes всех `110` файлов и `31` каталогов. SHA-256: Gateway `9e41c47e71efd95441a045a1f86c7244e5908e339071034815e97a73935c0491`, VPS `3c930b065c7b8e4f77e4b16e36163208f86c8e78e54983018fe6a74dbd14aa84`, bootstrap `e1f4d37daeb35209016edb29bfe0ae27684e5e8a1694876646dbba1925bd9e36`, Linux deploy `3a69b369eacbd0bff4e4b3d361336382f0ab6e6c214bc649dfa1e99aa1566a30`, Windows deploy `e8ba2c84267c697e9daee219e6252cc022298300a992b9944e41fd69b24fa9ba`, stable channel `7d7058adbe6d091ba49f4265e63074a1cc7a4c8356d9daad80da036ea463c004`. Все role signatures/channel/artifacts повторно verified внутри обеих сборок.

**Gateway exact lifecycle:** clean Ubuntu 24 systemd host прошёл signed dry-run без mutation и fresh apply для `lan0`, `192.168.200.1/24`, DHCP и SSH/SFTP. После штатной Management Fabric convergence строгий gate подтвердил schema `34`, firewall generation `7`, `HEALTHY`, HTTPS/SSH/DNS/DHCP, IPv6 block, `PATH_BLOCKED`, zero restarts и пустые fail-closed sets. Production state root сохранил `gateway-vpn:gateway-vpn 0710`, DB — `0600`, secrets — `0700`. Same-version reinstall сохранил report/config/key/marker/pointers и control start-time. Exact bundled Mihomo `v1.19.30`, SHA-256 `20ba567571d9ca642bedecbb01f8092cab0f1679100087ef1a4a2efac0ed5494`, запустился из этого release, поднял mixed TUN и authenticated loopback API с `NRestarts=0`; validator обязан был отклонить этот test-only active generation. Stop удалил TUN, generation удалена, финальный validator снова прошёл.

**Gateway uninstall:** exact candidate `uninstall.sh --apply` загрузил `PATH_BLOCKED`, удалил owned program/config/units/firewall/address и восстановил исходные `ssh.socket=enabled/active`, `ssh.service=disabled/inactive`, членство log-reader и состояние dummy LAN. `/var/lib/gateway-vpn/state.db` сохранена; schema `34`, quick/integrity/FK — PASS. Первое post-check сравнило hash только live main DB и остановилось после нормального WAL checkpoint при shutdown; это некорректная fixture-модель, а не потеря данных. Проверка заменена на логическую SQLite integrity и завершилась `FINAL_GATEWAY_UNINSTALL_PRESERVE_PASS`.

**VPS exact lifecycle:** отдельный clean Ubuntu 24 host установил ровно 13 недостающих Python packages после повторной APT simulation, `0 upgraded`, `0 removed`, затем прошёл signed install. Schema `4`, два exact `wg-mgmt` peer, scoped nftables, default route/DNS, recovery/update/fabric paths и timers, Hub HTTPS headers/listeners и `INSTALLED_NOT_READY` подтверждены. Единственным external failed unit минимального image был прежний `systemd-networkd-wait-online`; после test-only mask systemd стал `running`, все owned units имели zero failures/restarts. Дополнительные explicit negative assertions подтвердили disabled/inactive install-recovery unit. Same-version reinstall побайтно сохранил config/firewall/trust key/WireGuard/TLS/DB/report/marker и времена запуска Agent/WireGuard.

**Regression и неуспешные harness-шаги:** focused Windows packaging test прошёл. Первый full Linux run с `--cap-drop ALL` завершил только ownership-changing tests ошибкой `operation not permitted`; повтор с минимальными `CHOWN/DAC_OVERRIDE/FOWNER/SETUID/SETGID`, без сети и без network capabilities, прошёл полный `go test ./...`, `go vet ./...`, шесть CGO-free linux/amd64 builds и Bash syntax. Более ранний Mihomo API вызов без bearer header получил ожидаемый `401`, исправленный authenticated вызов прошёл; один marker path и несколько shell-quoting попыток были ошибками orchestration до product assertions. Initial Gateway validator был запущен до Management Fabric receipt и честно увидел `CRITICAL_LOCAL`; после штатного reconcile без изменения продукта стал `HEALTHY`.

**Граница и ресурсы:** production `.gvkey` не открывался; использован только прежний disposable validation signer. Push/tag/GitHub Release, Windows component/reboot, cleanup и hardware/endurance не выполнялись. Build/candidate/systemd containers, exact dist trees, caches и evidence сохранены по `DEV-250`.

**Следующий шаг:** программный candidate готов к внешнему delivery gate. Для полного zero-to-ready доказательства нужен настоящий clean Windows 10/11 x64 guest с two-target deploy. Для первой физической установки нужны отдельное разрешение на production signing/tag/Release и затем Ubuntu Gateway/VPS, Huawei E3372h/Keenetic/mobile path; после запуска остаются hardware recovery и реальные 24/72-hour endurance.

### Сессия 152 — exact Mihomo mixed-TUN gate и исправление production systemd traversal — 2026-09-02

**Новый exact gate:** добавлены test-only Go peer `test/netns/cmd/mihomo-peer` и root netns harness `test/netns/mihomo_tun.sh`. Harness принимает только absolute regular executables, exact semver и lowercase SHA-256, работает без внешней сети в трёх namespaces и сохраняет evidence только в явно новом absolute directory. Для Gateway instance он фактически проверяет `stack: mixed`, `auto-route`, `auto-redirect`, `strict-route`, UDP/TCP DNS hijack, один SOCKS5 node с `interface-name=wan0` и `routing-mark=101`, loopback API `/version`/`/proxies`/`/connections`, отсутствие unmarked endpoint route и независимый nft direct-forward drop.

**Exact runtime result:** pinned Mihomo `v1.19.30`, SHA-256 `20ba567571d9ca642bedecbb01f8092cab0f1679100087ef1a4a2efac0ed5494`, прошёл TCP, UDP и DNS через TUN. После `SIGKILL` API и TUN исчезли, временно предоставленный direct route не дал HTTP/UDP leak и увеличил только independent drop counter; тот же config затем повторно поднялся после пропущенного userspace cleanup. Evidence сохранён в `.cache/gate/mihomo-tun-20260901/evidence-final-1`, container `gateway-vpn-mihomo-tun-20260901` не удалялся.

**Ошибки стенда до успешного прогона:** первый вариант пересёк uplink с Mihomo TUN range `198.18.0.0/30`; второй добавил target-specific route в `main`, из-за чего UDP закономерно обходил TUN. Uplink перенесён в отдельную test subnet, unmarked route удалён, marked table сохранён. Оба случая были дефектами topology fixture до product assertions, а не Mihomo/Gateway runtime.

**Найденный production blocker:** настоящий installed `gateway-vpn-mihomo.service` в Ubuntu 24 systemd container циклически завершался `status=200/CHDIR`. Tmpfiles и generation tree имели правильные `0710/0750`, но запущенный control plane через `internal/db.Open` повторно менял `/var/lib/gateway-vpn` на `0700`; отдельный пользователь `gateway-vpn-mihomo` терял traverse до `mihomo/active`. `db.Open` теперь сохраняет только exact безопасный `0710`, оставляет обычный default `0700`, исправляет group-readable `0750` обратно в `0700` и не ослабляет DB/secrets. Update restore regression согласован с production traverse-only contract и продолжает проверять root-only ownership/modes.

**Production-unit evidence:** в сохранённом `gateway-vpn-mihomo-systemd-20260901` exact installed unit запущен как `User=gateway-vpn-mihomo`, `Group=gateway-vpn` на read-only generation. С исправленным текущим control-plane binary одновременно были `active/running` оба сервиса, root оставался `0710`, Mihomo имел `NRestarts=0`, TUN существовал, authenticated API вернул `v1.19.30`; stop удалил TUN, generation не получил `cache.db`. После gate исходный signed test binary `751669c…` восстановлен, unit-ы остановлены, TUN отсутствует. Это отдельный systemd runtime proof, а не изменение immutable candidate.

**Regression:** Linux tests нового DB/packaging contract прошли; traversal/root-only restore focused test — `10×`. Финальный offline Linux `go test -buildvcs=false ./... -count=1 -p 1`, `go vet ./...`, gofmt и сборка шести linux/amd64 CGO-free targets — PASS. Bash всех scripts, 12 JavaScript files и `git diff --check` — PASS. Первый full run правильно обнаружил stale assertion `0700`; после обновления весь test suite прошёл. Два последующих non-product exit были ошибками orchestration: PowerShell разобрал shell substitutions до `docker create`, а затем build harness указал несуществующий `./cmd/gateway-vpn-endurance` вместо `./test/endurance`; исправленный final build container завершился exit `0`. Все successful/failed named containers и build caches сохранены согласно `DEV-250`.

**Граница доказательства:** тест использует локальный SOCKS endpoint, а не настоящую HAPP-подписку/сервер обхода. Huawei E3372h, Keenetic WAN, mobile operator whitelist, USB recovery, физические Ethernet roles, VPS из Интернета и 24/72-hour endurance не запускались и остаются hardware gates. Production key не читался; push/tag/GitHub Release и cleanup не выполнялись.

**Следующий шаг:** сохранить source-only gate отдельным локальным commit; затем прежний внешний delivery gate не меняется — clean Windows 10/11 x64 two-target deploy требует отдельной VM/Sandbox и явного разрешения на её включение/reboot. После него собрать новый exact reproducible candidate уже с исправлением traversal и передать пользователю для первой физической установки; hardware/endurance результаты фиксировать только после запуска на железе.

### Сессия 151 — guarded preparation двух fresh targets для clean-Windows deploy — 2026-09-01

**Реализовано:** добавлен source-only `test/release-gate/cmd/prepare-windows-targets`. Он запускается на Windows Docker Desktop host и требует одновременно `GATEWAY_VPN_RELEASE_GATE=1`, `--release-gate-only` и отдельный `--apply`. Dry-run проверяет fixed Docker/Win32 OpenSSH paths, existing exact local image без pull, exact assigned non-wildcard IPv4, два свободных разных unprivileged ports, dedicated unencrypted Ed25519 key, новый evidence directory и отсутствие всех derived container/image names. Apply использует уже проверенный immutable image ID, сначала без опубликованного порта создаёт отдельный stage каждой роли, генерирует unique host key, включает key-only root SSH, проверяет отсутствие Gateway/VPS application trees, commit-ит отдельный test image и final container создаёт уже по exact committed image ID. Затем проверяются exact port projection, pinned `known_hosts` и реальный вход fixed системным Win32 OpenSSH. Private key не копируется в target/evidence; автоматический pull/reuse/remove отсутствует, при ошибке started resources только останавливаются и сохраняются для диагностики.

**Фактический lifecycle:** read-only run `dryrun-20260901` вернул `READY_TO_APPLY` для base image `sha256:fb5fb28f53e52d0f49b5d5ff63e2b244d5a518f36d8552972f4ebbc64a4bbf58`, loopback ports `22991/22992`, fixed Docker и Win32 OpenSSH. Первый apply `applytest-20260901` безопасно остановил staging до публикации порта: минимальный image не имел ephemeral `/run/sshd`, и строгий `sshd -t` завершился `Missing privilege separation directory`. Helper дополнен exact `root:root 0755 /run/sshd`; неудачный resource сохранён и после диагностики остановлен, не удалён.

**Успешные повторы:** `applytest2-20260901` впервые закрыл полный lifecycle и no-silent-reuse. Последующий audit устранил TOCTOU локального retag: stage теперь создаётся по уже проверенному immutable base image ID, final — по exact committed image ID. Финальный current-source run `applytest3-20260901` создал fresh Gateway/VPS containers `d557e8f6…`/`b676d2ef…`, разные prepared image IDs `2b36c686…`/`952cdde2…`, разные host-key fingerprints и exact loopback mappings `127.0.0.1:22999/23000 → 22/tcp`. Оба fixed Win32 OpenSSH logins с pinned host keys прошли. `known_hosts` hash повторно совпал с `targets.json`; в evidence найдено `0` private-key filenames. Dry-run с уже использованным run ID и другими свободными ports отказался на существующем stage name. Final и диагностические Docker resources сохранены согласно `DEV-250`; внешние/LAN ports не открывались.

**Regression:** полный Windows `go test -buildvcs=false ./... -count=1 -p 1` и `go vet -buildvcs=false ./...` под основным пользователем — PASS. После exact-image-ID hardening focused Windows test/vet/build и полный privileged apply текущего helper — PASS; Linux/amd64 cross-build helper — PASS. Предшествующий sandbox-user run прошёл все пакеты, кроме `internal/vpsupdate`: Windows отказал тестовым symlink из-за отсутствующего `SeCreateSymbolicLinkPrivilege`; тот же suite под штатным пользователем прошёл, поэтому это сохранённое ограничение sandbox runner, не product defect.

**Граница evidence:** same-host loopback lifecycle доказывает preparation/freshness/host-key/Win32 OpenSSH contour, но не доступ из отдельной clean Windows guest и не выполнение portable deploy. Windows Sandbox/VM не включалась; Windows component/reboot, production `.gvkey`, push/tag/Release, cleanup и hardware/endurance не выполнялись.

**Следующий шаг:** после отдельного разрешения включить Windows Sandbox либо использовать другую clean Windows 10/11 x64 VM; определить доступный guest→host exact address, создать новые targets на нём и выполнить внешне закреплённую hash-before-exec PowerShell-команду полного signed two-target deploy. Exact GitHub candidate publication требует отдельного разрешения непосредственно перед signing/tag/Release.

### Сессия 150 — инвентаризация reusable targets для clean-Windows gate — 2026-09-01

**Проверено без mutation:** Docker Desktop сохраняет оба exact `gef7712f.crypto2` Ubuntu 24 systemd targets и их базовый rehearsal image. `gateway-vpn-ef7712f-gateway-fresh` и `gateway-vpn-ef7712f-vps-fresh` работают privileged с private cgroup namespace; installed pointers ведут на exact version `v0.1.0-successor.gef7712f.crypto2`. На обеих машинах установлен Ubuntu OpenSSH Server `1:9.6p1-3ubuntu13.18`; Gateway SSH active, VPS package присутствует, но service inactive.

**Граница повторного использования:** у сохранённых containers нет опубликованных host SSH ports, и обе роли уже установлены. Поэтому их нельзя использовать как доказательство fresh clean-Windows two-target deployment: это подменило бы fresh install на same-version reinstall и не позволило бы Sandbox подключиться. Existing evidence targets не изменялись и не очищались.

**Минимальная подготовка после разрешения:** reusable base image уже есть; для gate нужны два новых disposable clean systemd containers из него с key-only OpenSSH и явно опубликованными разными TCP ports, доступными только test administration path. Затем clean Windows запускает внешне закреплённую PowerShell-команду и один persistent Win32 OpenSSH TCP на роль. Создание этих targets откладывается до появления Windows Sandbox/VM, чтобы не держать лишние экспонированные listeners.

**Не выполнялось:** container create/start/stop/remove, package install, port publication, Sandbox enable/reboot, signing/push/tag/Release и cleanup.

**Следующий шаг:** прежний внешний gate не изменился — отдельное разрешение на Windows Sandbox/reboot или другая clean Windows VM; после этого подготовить два fresh SSH target, отдельно авторизовать production signed GitHub candidate и выполнить end-to-end deploy.

### Сессия 149 — повторная проверка сохранённого candidate и граница clean-Windows gate — 2026-09-01

**Контракт Mihomo без изменения архитектуры:** подтверждено, что обычное полное обновление Gateway VPN уже несёт одну закреплённую и проверенную версию Mihomo. Если core менять не требуется, следующий Gateway release сохраняет прежнюю версию; если требуется — включает новую. Отдельный maintenance manifest является только ручным discovery/compatibility представлением того же полного immutable Gateway release, а не указателем на изменяемую GitHub-папку или произвольный upstream `latest`. Это уже соответствует `DEV-252`, PLAN и OPERATIONS; новый updater либо новое решение не вводились.

**Повторная проверка evidence:** после journal commit `9882d6aaef1a80fe4e5f960ca8ff9d450064702b` рабочее дерево оставалось чистым. В обеих сохранённых независимых сборках `clone-a` и `clone-b` повторно вычислены SHA-256 шести delivery inputs candidate `0.1.0-successor.gef7712f.crypto2`: Gateway, VPS, bootstrap, Linux deploy, Windows deploy и `channel-stable.json`. Все 12 сравнений совпали с hashes сессии 148; rebuild, production key и сеть не использовались.

**Clean Windows readiness:** локальный Windows host по-прежнему имеет работающий Hyper-V compute service, но Windows Sandbox отсутствует (`WindowsSandbox.exe` отсутствует; optional feature не обнаружена текущим read-only inventory), а отдельной clean Windows VM/ISO/VHD нет. Поэтому существующий Windows 10 native source/Win32 OpenSSH gate нельзя честно переименовать в clean-VM end-to-end. Включение Sandbox изменяет компонент Windows и требует reboot; полный two-target command дополнительно загружает exact role artifacts из immutable GitHub Release, которого для этого candidate ещё нет.

**Не выполнялось:** Windows component enable/reboot, production `.gvkey`, push, tag, GitHub Release, cleanup и физические/hardware/endurance проверки.

**Следующий шаг:** получить отдельное разрешение на включение Windows Sandbox с перезагрузкой либо предоставить другую clean Windows 10/11 x64 VM; для полного GitHub delivery gate отдельно разрешить exact production signing/tag/Release candidate `gef7712f.crypto2`. После этого выполнить hash-before-exec PowerShell и настоящий two-target Windows deploy; без этих разрешений перейти можно только к физической установке пользователем, не закрывая clean-VM gate заранее.

### Сессия 148 — post-fix reproducible exact candidate и обе systemd-роли — 2026-09-01

**Source/artifacts:** exact source `ef7712f75189ef9646eb2acab7006f2eeda9d9dd`, version `0.1.0-successor.gef7712f.crypto2`, Mihomo `v1.19.30`, прежний disposable signer `2c734b06f87a5d4724a0110d83d700ebe92fb54b3ddc9df091da27ed74e96a6a`. Два independent offline clean clone с раздельными caches дали одинаковые paths/types/Unix modes/sizes/SHA-256 всех `110` файлов и `31` подкаталога. SHA-256: Gateway `1acdafe696d078bbef2965aec3d5a2d79a0e4ee6b5f105c668862c26d4ab5ec6`, VPS `809aeaac790c989a9a9fd8ab77e7b4fa46bf0a233fb3eefba5368ebbec2a93ee`, bootstrap `2a63d1db2c669094e99f48b371ebc54c62b4cb809c195d0b405abce0a00317a9`, Linux deploy `73c8d69f53532d0290289252305a4b2a507981d80f675d4c715b4b6919210e66`, Windows deploy `3bb4e42537ed3d5c3638aa0d17d315df79b384e04f3814436a5d83fb2bca8727`, stable channel manifest `33e19b3baa381cfd19811b1736cc5b4d9176a72629cf9f1e2a4768ab807eaada`. Gateway 57 files, VPS 35 files, five channel artifacts и exact commit повторно verified offline.

**Gateway exact gate:** clean Ubuntu 24 systemd host прошёл signed dry-run/fresh apply с `lan0`, `192.168.200.1/24`, DHCP и SSH/SFTP. Full release gate подтвердил schema `34`, SQLite quick/integrity/FK, firewall generation `7`, `HEALTHY` watchdog, workers, HTTPS/SSH/DNS/DHCP, IPv6 block, `PATH_BLOCKED`, pointers и zero restarts. Same-version reinstall побайтно сохранил config/report/key/marker/pointers и unit start-times.

**VPS exact gate:** отдельный clean Ubuntu 24 host установил ровно 13 недостающих Python packages без upgrades/removals, затем прошёл signature/profile, schema `4`, SQLite quick/integrity/FK, exact two-peer `wg-mgmt`, scoped accept-policy nftables, preserved default route/DNS, state/lifecycle checks, timers/paths и оба HTTPS listeners. Строгий response gate теперь получил CSP, `X-Frame-Options: DENY`, `nosniff`, `no-referrer`, `no-store`; итог `VPS_EXACT_SYSTEMD_GATE_PASS`, systemd `running`, readiness ожидаемо `INSTALLED_NOT_READY` без реальных peer handshakes. Same-version reinstall сохранил Hub DB/config/firewall/WireGuard/TLS/report/marker/pointers и unit start-times.

**Harness:** первая Gateway preparation попытка использовала недопустимо длинное test-only interface name `wg-install-probe`; kernel отверг его до создания, повтор с `wgprobe` прошёл. Первый SQLite wrapper не создал destination directory и имел nested-shell quoting error; продукт не затронут, corrected wrapper прошёл. В VPS image заранее замаскирован только известный внешний `systemd-networkd-wait-online.service`, чтобы не повторять доказанный 120-second Docker artifact; installer и все Gateway VPN units не изменялись. Первая dist hash-команда после успешного полного сравнения завершилась code `1` только из-за неверного wildcard имени channel-файла; подпись/hash `channel-stable.json` затем проверены правильным exact path.

**Не проверено:** clean Windows VM, production signer/publication, physical Gateway/VPS/Mihomo/TUN/HiLink/Keenetic и 24/72-hour endurance. Production `.gvkey` не открывался; push/tag/Release и cleanup не выполнялись.

**Следующий шаг:** clean Windows VM readiness, затем по отдельному разрешению production signing/publication либо сразу physical install-candidate test; hardware/endurance по-прежнему нельзя объявлять выполненными заранее.

### Сессия 147 — exact Mihomo successor lifecycle и VPS security-header finding — 2026-09-01

**Reproducible candidate:** source `751669c36fcb2574a859a1a6ffe1998f679b78b6`, version `0.1.0-successor.g751669c.crypto1`, Mihomo `v1.19.30`, disposable signer `2c734b06f87a5d4724a0110d83d700ebe92fb54b3ddc9df091da27ed74e96a6a`. Два независимых offline clean clone с раздельными build caches получили одинаковые `110` файлов и `31` каталог. SHA-256: Gateway `463c989c03e030e78f855c6a6a1a8f690447e8a1124c144b67f2a26e9cf4544e`, VPS `baa210bf116c35dacba5268d6479357f0e8e93729bd6503a2e3bcd144cff1cbb`, bootstrap `987b94bafb6764053af553eea7af1e1733274fa7afd7f07f25584713683300ab`, Linux deploy `f70ab64adb50b96ffc42b4e753a65b1751743d065ad8d42d9a1e221afc690ca7`, Windows deploy `8eda71ed8d8a7e08605a4b90fdb743317633a2ba1d2625bb01386d12b6c40dbf`, channel manifest `20f004c3041d1d19f86037141d4ad40ec96a968fa7f6bf7844b845d3925ff19f`. Stable upstream Mihomo не новее pinned `v1.19.30`, поэтому фиктивный maintenance manifest не создавался.

**Gateway exact lifecycle:** signed dry-run/fresh apply на Ubuntu 24 systemd PID 1, LAN `lan0`, `192.168.200.1/24`, DHCP и SSH/SFTP — PASS. Full release gate подтвердил signature, schema `34`, SQLite quick/integrity/FK, firewall generation `7`, HTTPS headers/bind, SSH/DNS/DHCP, IPv6 block, `PATH_BLOCKED`, `HEALTHY` watchdog, 12 live workers и нулевые restart counters. Same-version reinstall повторно проверил 57 signed files и побайтно сохранил config/report/key/completed marker, `current/recovery`, transaction tree и времена запуска units. Snapshot установленного host запущен новым systemd PID 1; после штатной hysteresis/NTP convergence тот же full gate прошёл повторно.

**VPS exact lifecycle:** clean dry-run безопасно остановился на отсутствующем `python3`; dependency-only phase вернул ожидаемый code `10` при пустых APT indexes. Apply обновил indexes и установил ровно 13 новых packages без upgrades/removals. Signature, profile Ubuntu 24, schema `4`, SQLite quick/integrity/FK, `wg-mgmt` с двумя exact peers, scoped nft `policy accept`, preserved default route/DNS, root/`10.80.0.1` HTTPS, paths/timers/recovery, state-check/update-lifecycle и `INSTALLED_NOT_READY` прошли. Same-version reinstall побайтно сохранил config/firewall/key/report/marker, Hub TLS/secrets, WireGuard config, pointers и unit start-times. Production uninstall удалил program/interface/owned firewall, вернул sysctls и побайтно сохранил Hub DB/settings/backups/account/TLS/secrets, completed marker и `/etc/wireguard/wg-mgmt.conf`; сохранённая schema `4` повторно прошла integrity/FK.

**Найдено строгим gate:** VPS WebUI имел достаточную современную CSP `frame-ancestors 'none'`, но не имел совместимого defense-in-depth header `X-Frame-Options: DENY`, который уже выдавал Gateway WebUI. Поэтому `g751669c.crypto1` не считается полностью прошедшим VPS release gate и не продвигается. Общий VPS security middleware дополнен `DENY`; regression требует CSP, `X-Frame-Options`, `nosniff`, `no-referrer` и `no-store` одновременно для static и API responses.

**Post-fix source gates:** полный Windows `go test ./... -count=1 -p 1`, `go vet ./...`, пять builds и focused regression — PASS. Pinned Linux Go `1.26.7`, no-network/read-only root+source, минимальные capabilities: полный `go test -race ./... -count=1 -p 1`, `go vet ./...` и пять builds — PASS. Windows elevated build сначала не получил VCS status от Git и был честно повторён с `-buildvcs=false`; exact VCS identity остаётся обязательной для следующей clean-clone release build. Две ошибочные промежуточные poll-команды имели только JavaScript quoting/syntax error и не затронули живой Linux test container.

**Harness observations:** Gateway не смог установить `sqlite3` после apply именно потому, что рабочий fail-closed firewall закрыл прямой DNS/Internet; release gate использовал отдельный локально собранный read-only helper на том же `modernc.org/sqlite`. На VPS минимальный Docker image держал внешний `systemd-networkd-wait-online` до 120-second timeout; installer продолжил и все owned units прошли, единственным failed unit остался внешний image artifact. Первый VPS harness завершился на `set -e`, читая допустимое `degraded`; исправленный read-only gate явно разрешил только exact `systemd-networkd-wait-online.service`.

**Не проверено:** новый post-fix exact reproducible bundle/lifecycle, clean Windows VM, physical Gateway/VPS/Mihomo/TUN/HiLink/Keenetic, production signer/publication и endurance. Production `.gvkey` не открывался, push/tag/Release не выполнялись, validation resources не очищались.

**Следующий шаг:** зафиксировать header fix чистым локальным commit, дважды offline собрать новую exact identity и повторить достаточный Gateway/VPS systemd lifecycle; только этот successor может рассматриваться как production candidate.

### Сессия 146 — signed Mihomo maintenance channel — 2026-09-01

**Принято и реализовано:** каждый обычный Gateway release по-прежнему содержит одну точную Mihomo. Для релиза, выпускаемого преимущественно ради core, добавлен отдельный domain-bound `gateway-vpn-mihomo-maintenance-v1` manifest с channel, сопровождающей Gateway/Mihomo versions, exact compatibility list, OS/arch, host/Gateway API/Mihomo API contracts, commit, archive hash/size, urgency и bounded summary. Manifest подписывается тем же Ed25519 production identity и указывает на полный Gateway archive, а не на отдельный binary.

**Runtime/API/WebUI:** remote resolver игнорирует draft, stable prerelease, forged signature, неподходящую точную Gateway version, непередовую Mihomo, чужой host/API contract, unsafe URL/size и несовпадающий tag. Staging имеет отдельный `MIHOMO_GITHUB_CHANNEL`, скачивает полный archive через существующую service-route transport, прогоняет общий release verifier и затем повторно связывает release с exact commit/host/API identity maintenance manifest; mismatch удаляется из staging. Durable automatic scheduler классифицирует этот source как ручной и никогда не применяет его без пользователя. В `Система и безопасность` добавлена карточка с текущей/candidate Mihomo, сопровождающей Gateway version, urgency, summary и отдельными ручными Check/Stage.

**Сборка и публикация:** добавлены `mihomo-channel-sign/verify`, deterministic `scripts/build-mihomo-channel.sh`, opt-in flags обычного и encrypted bundle builders. GitHub draft publisher принимает zero, stable и/или testing pair, запрещает неполную пару, повторно проверяет её из clean tagged source и добавляет в тот же draft. Binary Mihomo не копируется в исходники либо отдельную GitHub-папку: он уже находится в полном Gateway archive.

**Финальный review и усиление:** signer теперь не доверяет отдельно лежащему распакованному release при вычислении только внешнего SHA-256 архива. Архив копируется в private `0700/0600` staging, повторно хешируется, извлекается общим strict release extractor и проверяется production public key; его полный signed `Release` обязан совпасть с указанным release directory. CLI sign также требует, чтобы `--source-commit` совпадал с signed `release.json`. Добавлен regression, где два отдельно валидных signed release/archive с разными commit отвергаются как несогласованная пара. Смена stable/testing в WebUI инвалидирует прежний результат Check и скрывает Stage до новой проверки.

**Проверено:** focused `mihomochannel`, `updateremote`, `update`, `updateautomation`, `webapi`, `app`, CLI, packaging и preview tests — PASS; forged/incompatible/prerelease manifests, exact staged identity mismatch с cleanup, manual-scheduler isolation, archive/release binding и exclusive output покрыты. Полный Windows `go test ./... -count=1 -p 1` прошёл; обычный sandbox ожидаемо не дал существующим `vpsupdate` tests создать symlink, повтор того же suite с Windows privilege прошёл полностью. Полный Linux `go test -race ./... -count=1 -p 1` в Go `1.26.7` no-network/read-only-source container — PASS, включая root-owned backup secret ownership test с минимальными capabilities. `go vet`, Windows/Linux CGO-free build matrix, `node --check`, secret scan, `git diff --check` и Linux `bash -n` в read-only/no-network container — PASS. Browser preview на `320×720` и `1440×900` подтвердил отсутствие horizontal overflow/clipped buttons и console warnings/errors после показа длинного maintenance status.

**Неудачные проверки/harness:** Windows `bash.exe` недоступен из sandbox (`E_ACCESSDENIED`), поэтому shell syntax проверен Linux container. Первая Linux race-команда ошибочно смонтировала Go temp с `noexec`; вторая намеренно сняла это ограничение, но слишком строгий `--cap-drop ALL` не позволил существующему privileged backup ownership test выполнить `chown`. При финальном review первый новый container использовал login `bash -lc`, который заменил image `PATH` и не нашёл установленный Go; повтор с exact `/usr/local/go/bin/go` прошёл. Это harness restrictions, не product failures; authoritative run использовал минимальные `CHOWN/SETUID/SETGID/DAC_OVERRIDE/FOWNER` capabilities и завершился полностью.

**Не проверено:** реальная публикация maintenance release, production key, Linux systemd lifecycle exact нового commit, physical Mihomo/TUN/HiLink/Keenetic path и 24-часовое stability window. Эти gates не объявляются выполненными.

**Следующий шаг:** завершить финальный security/syntax scan, создать clean local commit, затем дважды offline собрать exact candidate и продолжить Ubuntu 24 lifecycle без production push/tag/Release.

### Сессия 145 — exact reproducibility и manual-only update defaults — 2026-09-01

**Exact build evidence до policy fix:** commit `822c2dd6591dc79e2fcc57c7fd118ca394049423`, version `0.1.0-successor.g822c2dd.crypto1` и disposable signer `2c734b06f87a5d4724a0110d83d700ebe92fb54b3ddc9df091da27ed74e96a6a` дважды независимо собраны offline. Обе сборки дали одинаковые SHA-256 Gateway `e7bbf76c63f42ac68f8df03fea07b23da8dab6d167f441d317d544004b87fdff`, VPS `8ace2311886a94beb07e7da43ccebbbcba49617bb784e2d98447951a15076765`, bootstrap `a04f3962b714dc6e80eb4bbb7d962ad8b2311ab14ba330abfe578295c69d4593`, Linux deploy `20f781ad8d464c08023a5365424c11f9b466e803bd61d729bd0d58885a158a52`, Windows deploy `6fb7752f54ae5344989dc51821acc13679599cc04b84ad7cb2ff380ddefe5041` и channel manifest `f86f7518e75ea3dbf161efca0576352365476bc3ae5540b70b8a9a3a5d097bb6`. Рекурсивное сравнение `dist` подтвердило одинаковые paths/types/sizes/SHA-256 всех `141` entries. Production `.gvkey` не открывался.

**Найдено до lifecycle:** migration `000031` и runtime default включали automatic manifest check раз в `24` часа, хотя download/apply были выключены. После явного решения пользователя fresh-install default и `DefaultAutomationPolicy` изменены на три `false`; WebAPI regression и PLAN/OPERATIONS приведены к тому же contract. Намеренно включённые на существующей установке settings не перетираются migration-ом.

**Проверено:** focused `internal/update`, `internal/webapi`, `internal/updateautomation` и `internal/db` tests прошли после правки. Первые два Windows запуска завершились до tests: сначала default build/module cache был недоступен sandbox, затем старый module cache оказался пуст. Pinned modules загружены в новый project-local cache, после чего authoritative run с `GOPROXY=off` дал PASS. Это harness/cache setup, а не product defect.

**Следствие:** policy fix изменяет source identity, поэтому два совпавших bundle `g822c2dd.crypto1` остаются reproducibility evidence, но не продвигаются в lifecycle/production. Новый exact candidate будет создан только из следующего clean commit. Validation bundles, caches, signer volume и Docker resources не удалялись.

**Следующий шаг:** закрепить manual-only default локальным commit. Отдельный Mihomo maintenance channel остаётся архитектурным обсуждением до явного принятия; arbitrary upstream `latest` в любом случае не допускается.

### Сессия 144 — запрет автоматической очистки одноразовых ресурсов — 2026-09-01

**Решение пользователя:** после тестов сохранять Docker containers/images/volumes/build cache, `.cache`, validation bundles и lifecycle-стенды. Размер можно контролировать и сообщать, но удаление/prune/compaction выполняются только после отдельной команды пользователя. Правило добавлено в корневой `AGENTS.md`; `open-webui` остаётся безусловно защищённым ресурсом. Уже созданные module caches, pinned Go/Node images и Mihomo validation input сохранены.

**Следующий шаг:** зафиксировать эту workflow-инструкцию отдельным локальным commit и собирать окончательный dependency-hardened exact candidate уже из новой clean source identity; автоматическую cleanup после gate не выполнять.

### Сессия 143 — dependency hardening `x/crypto v0.55.0` и полный source/security gate — 2026-09-01

**Изменение:** официальный `proxy.golang.org` подтвердил latest `golang.org/x/crypto v0.55.0` с минимум Go 1.25 и требованиями `x/sys v0.47.0`, `x/text v0.41.0`, `x/term v0.45.0`. Проект использует Go `1.26.7`; `x/sys`/`x/text` уже совпадали. `go get`/`go mod tidy` изменили только direct `x/crypto v0.47.0 → v0.55.0`, его checksums, обязательный `x/term v0.45.0` checksum и lexical ordering direct require; `go mod verify` и `go mod tidy -diff` проходят.

**Windows gate:** focused `auth/backup/update/deploy` tests прошли. Полный Windows запуск ожидаемо не смог выполнить только Linux-semantic `internal/vpsupdate`, потому что создание symlink требует отсутствующей Windows privilege; затем authoritative supported matrix из 86 packages без `internal/vpsupdate`, полный `go vet ./...` и сборка пяти `.exe` прошли. Тот же `internal/vpsupdate` отдельно прошёл в полном Linux race suite.

**Linux gate:** pinned official `golang:1.26.7-bookworm@sha256:e8c859f5632dcfde7b32d2012b4351728f6437930887c2f6a91ea242459e5514`, `--network none`, isolated project cache, `go mod verify`, полный `go test -race ./... -count=1 -p 1`, `go vet ./...` и сборка пяти Linux entrypoints — PASS. Первый harness-вызов с `bash -lc` остановился до тестов, потому что login shell перезаписал PATH; неизменённый source прошёл с absolute `/usr/local/go/bin/go`.

**Security/syntax audit:** официальный `govulncheck v1.7.0` по актуальной `vuln.go.dev` проверил 87 root packages, 13 modules и standard library Go 1.26.7. Symbol vulnerabilities `0`, imported-package vulnerabilities `0`; остался один module-only `GO-2026-5932` для неимпортируемого `golang.org/x/crypto/openpgp`, fixed version отсутствует. Все 40 Bash scripts и 12 JavaScript files прошли syntax check в offline pinned containers; 561 tracked Go files прошли `gofmt -l`; diff hygiene, отсутствие private-key headers/token-like values/key-like tracked files/реальных WireGuard private-key values и tracked build artifacts подтверждены. Две ранние secret-scan эвристики ложно приняли code templates `PrivateKey = %s` и checksum `modernc.org/token` за secrets; уточнённый value-format scan прошёл без ослабления проверки фактических ключей.

**Следующий шаг:** создать чистый локальный commit и новую immutable validation identity, выполнить reproducible signed build disposable signer-ом и достаточный exact Gateway/VPS lifecycle. Production `.gvkey`, push/tag/GitHub Release не использовать.

### Сессия 142 — exact schema-34 lifecycle, security audit и финальная очистка стенда — 2026-09-01

**Immutable validation identity:** source commit `429810f63fae3e03a494bbe55cb1678bdba32fe7`, tree `53b956a8fe1a38c7668c96a851d447d4c16cab3f`, version `0.1.0-successor.g429810f.lifecycle1`, disposable signer fingerprint `56cf6c2f97d6019a45857b0089ca613d6ead05e348abd434863765c0bd842374`. Production `.gvkey` не открывался. Offline build после предварительного module/Mihomo prefetch повторно сверил exact commit и signer. SHA-256: Gateway `dc22ccc0dd3dd8a857d73fe68a24b33f2793e54e24c0ec4f4a8dd409edb822fc`, VPS `b54c5fcafcae601bb007170d9035e4078ec27a7d7d09bde79bad50f9765ee1c9`, bootstrap `55a122234158d28b73f716602f2f49a640bb6d606267593471295c812494fd05`, Linux deploy `14114364cf87ca41e6c0e605bf639b2f4e817bd691f90fc0a02996c79f67e010`, Windows deploy `8c7018d8ac9abe34431f63e9bcf9d1312b0540ac364421f4ed3f498269b33aa1`, channel manifest `49abd299617282fcd9af9664ac0e4cf0bdc9446d0174a9fd24ddf1f25b0d67e6`.

**Gateway exact lifecycle:** на Ubuntu 24.04 с real systemd PID 1 signed dry-run и fresh apply прошли; получены SQLite schema `34` и firewall generation `7`. Полный `validate_gateway_systemd.sh`, строгий same-version reinstall и independent new-PID1 clone — PASS. Reinstall не изменил report/config/marker hashes, pointers или число markers. Recovery matrix для marker formats `14/16/18/20/21` и uninstall matrix `14/16/18/20` плюс normal `21` прошли; legacy markers не выдумывают прежний `src_valid_mark`, current 21-field marker восстанавливает исходный `0`. Первый dry-run ожидаемо не увидел module metadata Docker/WSL, но реальный `ip link add wg-probe type wireguard` и `wg show` доказали доступность kernel WireGuard; неизменённый installer после этого прошёл.

**VPS exact lifecycle:** на отдельном Ubuntu 24.04 systemd host clean dependency-preflight вернул ожидаемый code `10`; apply обновил APT indexes и установил ровно 13 новых пакетов без upgrades/removals. Signed VPS release, SQLite schema `4`, quick/integrity, firewall, `wg-mgmt`, Agent, update/restore/fabric paths и timers — PASS. HTTPS root на `127.0.0.1:9443` прошёл; итоговый readiness `INSTALLED_NOT_READY` корректен без реальных peers/handshake. Same-version reinstall побайтно сохранил report/config/`wg-mgmt.conf`/marker/pointers; production uninstall побайтно сохранил Hub DB и WireGuard config. Единственный failed unit был внешний `systemd-networkd-wait-online.service` disposable image без cloud NIC `.network`; Gateway VPN units не падали.

**Source/security audit:** на Linux прошли `go test -race ./... -count=1 -p 1`, `gofmt`, `go vet ./...`, сборка всех Linux entrypoints и Windows deploy с `vcs.modified=false`, 12 JavaScript syntax checks, все Bash syntax checks, Ubuntu systemd units и GRUB policies. Tracked-tree secret scan не нашёл private key headers, tokens или key-like files; credential URLs присутствуют только в adversarial tests/fixtures, `PrivateKey =` — только placeholders. `govulncheck v1.7.0` по актуальной Go vulnerability DB не нашёл уязвимостей в достижимом code или imported packages. Module `golang.org/x/crypto v0.47.0` всё ещё связан с 15 module-level advisories без достижимых vulnerable symbols; перед production candidate требуется отдельное совместимое обновление минимум до версии, закрывающей их, и повтор audit/lifecycle.

**Неуспешные/уточняющие harness-шаги:** прежний UID 1000 стенда был занят; две вспомогательные evidence wait-команды имели quoting errors; VPS image начинал с пустыми APT indexes; запрос к неверному `/api/v1/session` дал `404`, authoritative endpoint — `/api/v1/auth/session`, а HTTPS root прошёл. Эти эпизоды сохранены как ограничения/ошибки стенда и не маскируются PASS-результатами.

**Очистка по запросу пользователя:** удалён точный gitignored `C:\Users\Igor\Documents\ChatGPT\Gateway VPN\.cache\lifecycle` размером `571,69 MiB`; workspace уменьшен до `237,83 MiB`, `.tools` (`224,98 MiB`), исходники, `.git`, документация и рабочее изменение этого журнала сохранены. Удалены три одноразовых containers `gateway-vpn-schema34-vps-fresh`, `gateway-vpn-schema34-lifecycle-reboot`, `gateway-vpn-schema34-lifecycle-fresh`; images `gateway-vpn-schema34-installed:lifecycle1`, `gateway-vpn-systemd-rehearsal:ubuntu24`, `golang:1.26.7-bookworm`, `node:24.14.0-bookworm-slim`; disposable signer volume и `194,9 MB` build cache. После cleanup Docker содержит только healthy `open-webui`, его используемый image и volume; reclaimable space равно `0 B`.

**Физическое освобождение диска:** Docker Desktop использует custom storage `D:\Docker\DockerDesktopWSL`. После штатной остановки Docker/WSL `docker_data.vhdx` сжат `Optimize-VHD -Mode Full` с `13,117` до `10,563 GiB`, освобождено `2,554 GiB`; свободное место D: выросло с `49,86` до `52,42 GiB`. Docker запущен обратно, `open-webui` вернулся в `running/healthy`; его image и volume `open-webui` (`1,194 GB`) сохранены. На C: очистка workspace увеличила свободное место примерно с `56,76` до `57,30 GiB`.

**Следующий шаг:** dependency hardening `x/crypto` с полным повтором race/vet/build/`govulncheck`; при изменении source создать новую immutable validation identity и повторить достаточный exact lifecycle. Production key/publication не использовать без отдельного разрешения; hardware/clean Windows/endurance gates не считать выполненными.

### Сессия 141 — exact schema-34 validation bundle и безопасная очистка диска — 2026-09-01

**Exact source и воспроизводимость:** schema-34 source зафиксирован локальным commit `429810f63fae3e03a494bbe55cb1678bdba32fe7`, tree `53b956a8fe1a38c7668c96a851d447d4c16cab3f`; ветка `main` стала на 21 commit впереди `origin/main`, push/tag/GitHub Release не выполнялись. В pinned builder `golang:1.26.7-bookworm@sha256:e8c859f5632dcfde7b32d2012b4351728f6437930887c2f6a91ea242459e5514` два clean clone этого commit независимо собрали validation candidate `0.1.0-successor.g429810f` с `--network none`, `GOPROXY=off`, `GOSUMDB=off` и раздельными ephemeral build caches. Сравнение 110 файлов и 32 каталогов подтвердило одинаковые relative paths, Unix modes и SHA-256 содержимого.

**Validation artifacts:** Gateway archive имел SHA-256 `138eff0b76018191a71a66aa33900be4a01eb9a2938f205808c7690d5919083a`, VPS archive — `7d5cb066da3ea197d9f0a87665138c5a09bb1a2e3007fd72275b320b01fc553a`, bootstrap — `168198bb8f8f978e4349fb83ac409fbff6427a9e2acbc8dc65e14a76c663be53`, Linux deploy — `47af137d268a79f3e2de9894837e5d25085034f921c54d0d24311157dad0e576`, Windows deploy `.exe` — `3d85846727d331226402411240cfcf35470b1cf61047e0da76fd72a5c691a78d`, channel manifest — `6535e37b7bbc8193fceb2ed751f25797455c12e201511d37895b53455efa0f7a`. Использовался только disposable validation signer fingerprint `fd9a8ffb609ecb66dc039a0ef673912dcc4aab2099914329b17f2e1139216d3c`; production `.gvkey` не открывался.

**Неуспешные harness-шаги:** первая генерация disposable signer штатно отказалась в корне volume с mode `0755`; после переноса в каталог `0700` private key получил mode `0600` и bundle был собран. Fresh Ubuntu 24.04 systemd rehearsal остановился до Gateway install на harness-команде `useradd --uid 1000 admin`, потому что UID 1000 уже занят базовым image. Поэтому fresh install/reinstall/marker lifecycle для этого exact candidate не считается выполненным; production-дефект этим запуском не обнаружен.

**Запрошенная очистка workspace:** удалён только gitignored воспроизводимый `.cache` размером `735,05 MiB`: module cache `323,65 MiB`, две build trees по `181,38 MiB` и release input `48,64 MiB`. Resolved target был проверен как точный `C:\Users\Igor\Documents\ChatGPT\Gateway VPN\.cache`. Workspace уменьшен до `237,83 MiB`; portable Go `1.26.7` в `.tools` (`224,98 MiB`), исходники, документация и `.git` сохранены.

**Запрошенная очистка Docker Desktop:** удалены одноразовый `gateway-vpn-schema34-fresh`, image `gateway-vpn-systemd-rehearsal:ubuntu24` (`194,3 MB`), неиспользуемый `golang:1.26.7-bookworm` (`1,236 GB`), disposable volume `gateway-vpn-schema34-signer` и `194,9 MB` build cache. После prune остались только healthy `open-webui`, его используемый image и volume; reclaimable Docker space равно `0 B`. Для физического возврата места Docker Desktop штатно остановлен, WSL завершён, отключённый `D:\Docker\DockerDesktopWSL\disk\docker_data.vhdx` сжат `Optimize-VHD -Mode Full`, затем Docker запущен обратно. VHDX уменьшился с `12,140 GiB` до `10,520 GiB`, физически освобождено `1 651 MiB`; свободное место `D:` выросло с `50,84` до `52,46 GiB`. `open-webui` автоматически вернулся в `healthy`, его volume `open-webui` (`1,194 GB`) сохранён.

**Следующий шаг:** пересоздать disposable exact schema-34 candidate и fresh systemd harness с незанятым UID, затем завершить install/reinstall/marker lifecycle gate. Это воспроизводимая работа; cleaned validation artifacts не являлись production release.

### Сессия 140 — five-profile Management Resources kernel gate и полный platform audit — 2026-09-01

**Реализованный gate:** добавлены Linux integration test `TestResourceProbeAgainstKernelRoutes`, disposable `test/netns/management_resources.sh`, README contract и CI wiring. Gate создаёт отдельные Gateway, Keenetic, ROUTER_ROUTED WireGuard и dedicated-management namespaces, реальные routes/interfaces и TCP listeners. Он проверяет `GATEWAY_ONLY`, `KEENETIC_WAN`, `VIA_KEENETIC_WAN_ROUTED`, `VIA_WG_ROUTER`, `VIA_DEDICATED_LAN`, `SO_BINDTODEVICE`, exact `health_probe_address` внутри `LOCAL_SUBNET`, недоступный external return path и запрет default route на dedicated-management интерфейсе.

**Найдено первым реальным запуском:** первый privileged gate fail-closed отклонил `VIA_WG_ROUTER` с `WG_ROUTER_ROUTE_NOT_CONFIRMED`. Причина оказалась production-дефектом evidence, а не слабой фикстурой: `ip -json route get` в реальном iproute2 возвращает effective device/gateway, но не сохраняет protocol исходной route; unit fake ошибочно добавлял `protocol: 186`, поэтому code path нельзя было пройти на Linux. Дополнительно resource query и fixtures не ограничивали route направлением `INGRESS`, хотя repository/WebUI создают behind-subnets именно с этим направлением.

**Исправление:** effective path по-прежнему проверяется через bounded `route get`, а ownership `VIA_WG_ROUTER` теперь независимо доказывается fixed root-owned командой `route show table main exact <expected-prefix> dev wg-ingress protocol 186` и строгим JSON projection. Отсутствующий/wrong-protocol route оставляет resource в `WAITING_EXTERNAL_CONFIGURATION` и не запускает transport probe. `wireGuardResourcePrefix` принимает только enabled `ROUTER_ROUTED` `INGRESS` prefixes; unit/kernel fixtures приведены к реальному storage contract.

**Проверки:** focused Management Fabric/Gateway Fabric tests и vet — PASS; packaging test разобрал GitHub workflow YAML — PASS; `node --check` и `git diff --check` — PASS. Новый privileged Ubuntu 24.04 gate после исправления — PASS. В одном disposable privileged container также прошли CI-equivalent `firewall_guard`, `startup_policy`, multi-LAN SSH, реальный WireGuard ingress handshake, topology rollback/ONE_ARM anti-spoof, exact update service routes, Management Resources и VPS operations root-boundary gates.

**Полный platform audit:** официальный `go1.26.7.linux-amd64.tar.gz` загружен с `go.dev` и проверен по SHA-256 `ffb5f8de10c62550dfddab66b36b57030721e0a44a3218e9e1181d7b59f121ca`. В Ubuntu 24.04 без сети прошли `go mod verify`, полный `go test ./... -count=1` и `go vet ./...`, включая реальные Linux symlink semantics `internal/vpsupdate`. На Windows прошли все пакеты кроме доказанно Linux-only `internal/vpsupdate`, затем полный `go vet ./...`; Windows-specific portable deploy tests включены. Это software/kernel evidence, а не физический Keenetic/HiLink/hardware gate.

**Очистка после gate:** удалены `1 404,72 MiB` воспроизводимых Windows/Linux Go caches, test binaries и проверенный temporary Linux toolchain archive; workspace возвращён к `239,76 MiB`. Удалены одноразовый `gateway-vpn-netns:ubuntu24` и `184,4 MB` его layers/build cache. В Docker сохранены только healthy `open-webui`, его используемый image и volume; reclaimable space снова `0 B`.

**Следующий шаг:** начать финальный requirement/security/release audit current schema-34 source. Production `.gvkey`, push/tag/Release не использовать без отдельного разрешения.

### Сессия 139 — очистка workspace и полный Docker prune — 2026-09-01

**Workspace:** повторный аудит показал, что тесты снова создали только два воспроизводимых gitignored-кэша: `.cache/go-build` — `342,73 MiB` и `.cache/go-path` — `323,55 MiB`. После проверки resolved absolute path удалён исключительно `C:\Users\Igor\Documents\ChatGPT\Gateway VPN\.cache`, освобождено `666,27 MiB`. Workspace уменьшен примерно до `239,75 MiB`; из него `224,98 MiB` занимает сохранённый portable Go `1.26.7` в `.tools`. Исходники, `.git`, весь большой tracked/untracked schema-34 worktree и production key не удалялись и не открывались.

**Docker Desktop:** с явного разрешения пользователя выполнены `docker system prune --all --force --volumes`, дополнительный prune всех неиспользуемых named volumes и полный builder prune. Все операции вернули `0 B`: остановленных контейнеров, лишних images, volumes, networks и build cache нет. Сохранены работающий healthy `open-webui`, его используемый image `ghcr.io/open-webui/open-webui:main` (`6,729 GB`), writable layer (`54,9 MB`) и связанный volume `open-webui` (`1,194 GB`).

**Физический диск Docker:** storage находится в `D:\Docker\DockerDesktopWSL`; `docker_data.vhdx` занимает `10,51 GiB`, весь каталог — около `10,60 GiB`. Повторная compaction не выполнялась: prune не высвободил ни одного блока, а предыдущая штатная compaction уже показала, что оставшийся объём занят активным Open WebUI. Его дальнейшее уменьшение потребовало бы удалить используемый image или пользовательский volume и поэтому не относится к безопасной очистке.

**Границы:** очистка не меняет следующий software-шаг: отформатировать и запустить новый privileged Linux/netns gate пяти Management Resource profiles, затем продолжить финальный requirement/security/release audit. После следующего Go test-блока `.cache` снова можно безопасно удалить.

### Сессия 138 — повторная очистка воспроизводимого кэша после тестов — 2026-09-01

**Workspace:** перед удалением повторно проверены `git status`, top-level размеры и dry-run `git clean -ndX`. Удалён только заново созданный тестами gitignored `.cache`: `go-path` — `323,55 MiB`, `go-build` — `241,82 MiB`, всего около `565,37 MiB`. Весь tracked/untracked resource/schema-34 worktree, `.git`, исходники и необходимая portable Go toolchain `1.26.7` в `.tools` сохранены. После очистки workspace занимает около `239,70 MiB`; единственный оставшийся ignored-каталог — требуемая `.tools` (`224,98 MiB`).

**Docker Desktop:** фактический inventory вне sandbox подтверждает отсутствие неиспользуемых контейнеров, images, volumes и build cache. Сохранены только запущенный healthy `open-webui`, используемый им image `ghcr.io/open-webui/open-webui:main` (`6,73 GB`), writable layer (`54,9 MB`) и связанный volume `open-webui` (`1,194 GB`). Их удаление остановило бы Open WebUI и могло бы уничтожить его пользовательские данные, поэтому Docker prune не запускался: освобождаемый объём равен `0 B`.

**Границы:** production `.gvkey`, Git push/tag/Release и пользовательские данные не открывались и не изменялись. Очистка не меняет незавершённый software-шаг: завершить `health_probe_address` и resource contour DoD 39, затем повторить focused/full verification.

### Сессия 137 — удаление повторно созданного build cache и контроль Docker — 2026-09-01

**Workspace:** перед удалением повторно проверены `git status`, ignored-файлы и размеры top-level каталогов. Удалён только gitignored воспроизводимый `.cache` размером `498,94 MiB`, повторно созданный текущим Go test-блоком. Весь tracked/untracked schema-33/Windows delivery worktree, `.git`, исходники и проверенный portable Go `1.26.7` в `.tools` сохранены. Workspace уменьшен примерно с `738,54 MiB` до `239,60 MiB`; из оставшегося объёма `224,98 MiB` занимает нужная локальная Go toolchain. Tracked deletions отсутствуют, `git diff --check` — PASS.

**Docker Desktop:** с разрешением пользователя выполнены container/image/volume/network/build-cache prune и полный inventory до/после. Все операции вернули `0 B`: неиспользуемых Docker-ресурсов уже нет. Сохранены только запущенный healthy `open-webui`, используемый им image `ghcr.io/open-webui/open-webui:main` (`6,73 GB`), writable layer (`54,9 MB`) и связанный volume `open-webui` (`1,194 GB`). Это рабочие данные Open WebUI, а не одноразовые ресурсы Gateway VPN; их удаление остановило бы Open WebUI и удалило бы его данные.

**Диск:** повторная compaction не выполнялась, потому что Docker не освободил ни одного блока. `docker_data.vhdx` остаётся `10,511 GiB`, что соответствует используемому Open WebUI; свободно `57,56 GiB` на `C:` и `52,47 GiB` на `D:`. Production `.gvkey`, Git push/tag/Release и пользовательские данные не открывались и не изменялись. Следующий software-шаг остаётся прежним: завершить resource contour для DoD 39 и финальный requirement/security/release audit.

### Сессия 136 — повторная безопасная очистка Docker Desktop и workspace — 2026-09-01

**Инвентаризация до удаления:** Git worktree проверен до любых операций: `main` остаётся на `20` commits впереди `origin/main`, весь большой незакоммиченный schema-33/Windows delivery блок сохранён. Workspace занимал `251 235 243` bytes (`239,60 MiB`); из них `235 905 597` bytes (`224,98 MiB`) — единственный проверенный portable Go `1.26.7` в `.tools`. Gitignored `.cache` и `dist` отсутствовали, а `git clean -ndX` показывал только нужную `.tools`; поэтому из workspace ничего не удалено. Исходники, новые migration/scripts, `.git` и production `.gvkey` не читались и не изменялись.

**Docker cleanup:** `docker system df -v`, containers/images/volumes inventory и `docker system prune --all --force --volumes` подтвердили, что неиспользуемых ресурсов и build cache уже нет (`Total reclaimed space: 0B`). Сохранены только healthy `open-webui`, его единственный image `7f1b0a1a50cf`, контейнерный writable layer `54,9 MB` и связанный volume `open-webui` `1,194 GB`. У контейнера действует `RestartPolicy=always`; лишних project-test containers/images/volumes нет.

**VHDX:** Docker Desktop использует custom storage `D:\\Docker\\DockerDesktopWSL`; `docker_data.vhdx` до compaction имел `11 331 960 832` bytes (`10,55 GiB`), при этом ext4 содержал около `8,9 GiB` фактических данных. После `fstrim`, штатной остановки Docker/WSL и `Optimize-VHD -Mode Full` файл уменьшился до `11 285 823 488` bytes (`10,511 GiB`), то есть освобождено `46 137 344` bytes (`44,0 MiB`). Малый результат ожидаем: свободные блоки уже были корректно разрежены, а оставшийся объём занят используемым Open WebUI. Docker снова запущен; `open-webui` автоматически вернулся в `running/healthy`, volume и image сохранились, build cache остаётся `0 B`.

**Контроль после очистки:** workspace по-прежнему `239,60 MiB`; `git diff --check` — PASS, `git status` не получил новых удалений. На момент измерения свободно `57,59 GiB` на `C:` и `52,47 GiB` на `D:`. Следующий software-шаг не изменён: финальный requirement/security/release audit текущего scope; release writes по-прежнему требуют отдельного разрешения пользователя.

### Сессия 135 — Windows portable deploy, реальный persistent SSH transport и signed channel — 2026-09-01

**Portable launcher и мастер:** `gateway-vpn-deploy` теперь собирается для `linux/amd64` и `windows/amd64`; Windows 10/11 x64 больше не отклоняется platform gate. После локальной проверки raw manifest signature/hash и собственного exact artifact identity `--interactive` запрашивает Gateway/VPS `USER@HOST`/ports, pinned `known_hosts`, явно выбранные SSH identity files, Gateway LAN interface/CIDR/DHCP, VPS endpoint, administrator WireGuard config/public key и две понятные policy. Мастер показывает impact summary и требует точный `INSTALL`; password и содержимое private key не запрашиваются и не попадают в report/state.

**Критическое обнаружение и исправление:** системный Windows 10 OpenSSH `9.5p1` синтаксически показывал `ControlMaster=auto` через `ssh -G`, но реальный первый session завершился `getsockname failed: Not a socket`. Это соответствует официальному [Win32-OpenSSH Project Scope](https://github.com/PowerShell/Win32-OpenSSH/wiki/Project-Scope), где Client ControlMaster указан как unsupported, и открытому [issue #1328](https://github.com/PowerShell/Win32-OpenSSH/issues/1328). Windows backend заменён на один long-lived fixed `C:\Windows\System32\OpenSSH\ssh.exe`/TCP на Gateway и VPS. Последовательные remote phases передаются через base64 framed protocol к `/usr/bin/bash --norc`; response содержит request ID, exit code и раздельные bounded stdout/stderr. Identity agent/password/keyboard-interactive/TTY/user config выключены, host key pinned, output/command/frame ограничены, context cancellation убивает session, а cleanup ждёт закрытия process/connection и удаляет private directory.

**Нативное доказательство Windows:** тестовый SSH server принимает ровно одно TCP-соединение и тут же закрывает listener; две последовательные commands успешно проходят по уже установленному соединению, затем `Close` терминально закрывает server side и удаляет session directory. Этот lifecycle вместе с cancellation прошёл `20×`. Отдельный signed-launcher smoke на локальном Windows 10 Pro build `19045.6456` проверил exact manifest/signature/signer, собственный Windows EXE hash/size/version/commit и безопасно дошёл до ожидаемого `GATEWAY_SSH_PREFLIGHT` failure на закрытом локальном port без host mutation. Response spoof/wrong ID, malformed base64, oversized output, invalid status и CRLF ambiguity отклоняются.

**Target Ubuntu broker:** exact framed Bash broker реально запущен `3×` внутри Debian 12 Linux container; он вернул отдельные stdout/stderr и exit `7`, после чего oversized output детерминированно преобразовал в bounded exit `125`. Linux launcher сохранил прежний private `ControlMaster` contract; его полный изменённый package suite прошёл отдельно в Linux runtime container.

**Signed distribution:** manifest contract допускает Windows только для role `deploy` на `amd64`, требует filename `gateway-vpn-deploy-<version>-windows-amd64.exe` и PE media type. `build-deploy.sh` из clean disposable committed tree создал оба binaries и отдельные SBOM/provenance; финальный disposable build `9.9.9-final` дал Linux SHA-256 `a6eb24c03f20a5619bc2cbb1f7dedac9057c2d7497a795bd5cf32c956e779f25` (`8 822 946` bytes) и Windows SHA-256 `b39d5b88433009174de1b9db30fed42018cad13b84ac05332522c134f2e381e9` (`9 106 944` bytes), совпавшие с обеими metadata. Это воспроизводимый test build, не production release identity.

**Channel/PowerShell:** disposable Ed25519 signer в container tmpfs подписал exact five-artifact channel с manifest SHA-256 `96702191917f3290180eaf7b0f958c72d9aa79afa79edd3da0ff12554d9cfd71`; повторный verifier перехешировал все пять files. Builder создал `install-deploy-windows-9.9.9-channel.command.txt`; штатный Windows PowerShell parser принял `2 275` UTF-8 bytes, а проверка подтвердила exact EXE/manifest hashes до `--interactive`, guaranteed temporary cleanup и отсутствие `password`, `private-key`, `.gvkey`. После добавления bytes к Windows artifact повторный channel verify завершился code `1`. Disposable signer/artifacts полностью удалены; production `.gvkey` не читался.

**Regression:** все Windows packages кроме известного `internal/vpsupdate` прошли одним `go test ... -count=1`; исключённый пакет требует отсутствующую у текущего account `SeCreateSymbolicLinkPrivilege` и ранее прошёл полный Linux suite. Изменённые `cmd/gateway-vpn-deploy`, `cmd/gateway-vpnctl`, `internal/deploy`, `internal/distribution`, `test/packaging` прошли нативные Windows tests/vet и Linux runtime tests; Windows persistent lifecycle дополнительно `20×`. `go vet ./...`, gofmt, все Bash syntax checks, 12 JavaScript syntax checks и `git diff --check` — PASS. CI добавляет отдельный `windows-2025` job с system OpenSSH и portable build; он ещё не запускался, поскольку push не выполнялся.

**Ограничения и cleanup:** clean Windows 10/11 VM с двумя настоящими supported Linux hosts, end-to-end `READY/INSTALLED_NOT_READY`, interruption после реального firewall apply и отсутствие credential residue ещё не доказаны; current Windows host не считается clean VM. Git push/tag/Release не выполнялись. Все disposable source/channel/test binaries и containers удалены; Docker содержит только healthy `open-webui`, его image/volume и `0 B` build cache/reclaimable. Следующий шаг — финальный requirement/security/release audit текущего расширенного scope, затем exact signed successor candidate только с отдельным разрешением на release writes.

### Сессия 134 — exact schema-33 lifecycle matrix, time-expiry regression и финальный Linux audit — 2026-09-01

**Exact fresh install:** disposable source identity `d43363f4aec6aa30cef7167d345a46e49381d0ee`, signer fingerprint `1bfd6904b995ab2a16b52dda56754f0a7d0ae0b86f6036fef9c542cfe6d316bf`. Release C archive повторно совпал с SHA-256 `ed51078fadde210f5eaff9abb669042de6af8d03d012a9c66e0c25c9b91368bb`, release D — `7da930819622c4b38146abfceaaf18557b9e45f874ff2523beff17552e027439`. Clean Ubuntu 24.04 systemd PID-1 host с исходным `net.ipv4.conf.all.src_valid_mark=0` прошёл signed dry-run и apply C для `lan0 / 192.168.200.1/24`, DHCP, SSH/SFTP user `ubuntu`, `gateway-nonblocking` и GRUB `keep`. Marker validator подтвердил 21 поле и исходный source mark `0`; полный validator подтвердил SQLite schema `33`, firewall generation `7`, `PATH_BLOCKED`, HTTPS/DNS/DHCP/SSH, watchdog `HEALTHY`, отсутствие failed/restarted managed units и immutable release pointers.

**Offline same-version reinstall:** реальный installed nft output policy заблокировал внешний TCP DNS и direct HTTPS (`timeout`); marker/report/config SHA-256, число markers и current/recovery pointers сняты до повтора. Docker systemd после `timedatectl set-ntp false` оставлял kernel-wide `NTPSynchronized=yes`, поэтому только чтение этого свойства было test-only подменено bounded wrapper-ом на `no`; wrapper гарантированно удалён сразу после команды. Installer явно прошёл ветви `NTP/DNS ... installed fail-closed policy`, повторно проверил подпись, release и весь existing-host contract и вернул `already installed`. Все сохранённые hashes/pointers и единственный marker остались побайтно неизменны; NTP service возвращён, полный validator повторно PASS. Это доказательство offline branch/idempotency в контейнере, но не bare-metal loss-of-clock gate.

**Uninstall/recovery compatibility:** обычный production uninstall 21-польного marker сначала загрузил `PATH_BLOCKED`, сохранил SQLite, удалил owned runtime и восстановил исходный source mark `0`. На независимых immutable PID-1 clones recovery markers `14/16/18/20` корректно не придумывали отсутствующее прежнее значение и оставили текущий source mark `1`; 21-польный recovery восстановил записанное `0`. Completed-marker uninstall `14/16/18/20` сохранил SQLite и неизвестный source mark `1`. Все сценарии прошли `validate_gateway_install_marker_lifecycle.sh`; успешные clones сразу удалялись.

**Signed host-contract upgrade:** C и D имеют одинаковый host contract `52d2d15cb301ccf3958f57745496d9e6e1d4cae7594a5c270618dbf9ad65f6e7`; production host-upgrader правильно отказал до mutation с `Use pointer-only signed update when host lifecycle contracts are equal`, сохранив оба C pointers и отсутствие active transaction. Для реального merge gate создан только disposable signed D fixture с безвредным systemd-comment, новым contract `4b29d87a79b46cd3e81d8425e50e4a968af72ab8b720c397cb900a0c8e672420` и archive SHA-256 `af30e135765967b3df2142d76d312cecb5203c7edc106a216fd15e7024cbedc3`. Upgrade `21→21` сохранил исходный mark `0`; `20→21` зафиксировал наблюдаемое install-time значение `1`; `18/16/14→18` не добавил отсутствующие source-mark/SSH-socket сведения. Каждый D host upgrade завершил full schema-33/firewall-7/systemd validator и сохранил rollback snapshot до удаления clone.

**Найденный test defect:** первый полный Linux suite обнаружил, что `TestSQLiteApplyReadinessRequiresFreshFullPathAndManagementHandshake` использовал абсолютное `2026-09-01 04:00 UTC` и qualification expiry `05:00`; запуск в `05:02` воспроизвёл `ErrStaleGeneration` 10 из 10 раз. Это не production generation defect: test reference time заменён на current UTC, сохранив относительный one-hour TTL и все management/FULL/stale assertions. Исправленный regression прошёл `50×`. Полный pinned Linux Go `1.26.7` `go test ./... -count=1` и `go vet ./...` — PASS; gofmt, все Bash scripts, 12 JavaScript syntax checks и `git diff --check` — PASS. Windows suite до этого прошёл все packages кроме прежних `internal/vpsupdate` symlink tests без `SeCreateSymbolicLinkPrivilege`; Linux тот же package PASS.

**Ограничения:** после Docker Desktop restart реальный host WireGuard module был загружен и стал виден installer preflight, но создание test interface вернуло WSL/Docker kernel error `Attribute failed policy validation`; WireGuard runtime этим gate не засчитывается. Не запускались физические Ubuntu Gateway/VPS, HiLink/Keenetic/USB recovery, bare-metal reboot/power-cut, RTC S5 и 24/72h endurance. Production `.gvkey`, Git push/tag/Release не выполнялись.

**Финальная очистка:** удалены завершённый lifecycle container, installed/rehearsal/Go images, release-gate и два Go cache volumes, disposable signed fixtures/snapshots и весь воспроизводимый `.cache` (`841,69 MiB`). Docker снова содержит только healthy `open-webui`, его image и volume; build cache `0 B`. После `fstrim` и `Optimize-VHD -Mode Full` `docker_data.vhdx` уменьшился с `13,14` до `10,55 GiB`, на `D:` возвращено около `2,58 GiB`; `open-webui` после restart подтверждён как `running/healthy`. Следующий software-шаг — Windows deploy delivery, затем финальный release/security audit с отдельным разрешением на любые push/tag/Release.

### Сессия 133 — целевая очистка текущего lifecycle-стенда и Docker VHDX — 2026-09-01

**Docker Desktop:** до удаления выполнен полный inventory контейнеров, images, volumes и build cache. По точным именам удалены только заменённый диагностический контейнер `gateway-vpn-schema33-base` (`166 MB` writable layer), отвязанный volume `gateway-vpn-schema33-build-cache` (`754,7 MB`) и неиспользуемый build image `golang:1.26.7-bookworm` (`1,24 GB`). Сохранены healthy `open-webui`, его image и volume `open-webui` (`1,194 GB`), а также текущий clean `gateway-vpn-schema33-c-fresh`, используемый им rehearsal image и минимальный release-gate volume. Default Docker networks не изменялись; build cache после очистки равен `0 B`.

**Фактическое освобождение диска:** после `fstrim` Docker Desktop штатно остановлен, WSL завершён, а `D:\Docker\DockerDesktopWSL\disk\docker_data.vhdx` уплотнён `Optimize-VHD -Mode Full`. VHDX уменьшился с `13,420` до `10,890 GiB`; свободное место `D:` выросло с `49,560` до `52,100 GiB`, то есть возвращено около `2,53 GiB`. Docker запущен обратно; `open-webui` подтверждён как `running/healthy`, сохранённый lifecycle host — как `running` с `systemd=running`.

**Workspace:** каталог проекта перед очисткой занимал около `803 MiB`. Удалены четыре распакованные копии releases A/B/C/D (`312,64 MiB`), которые полностью воспроизводятся из оставленных подписанных `.tar.gz`, и заменённый промежуточный `.cache/schema33-gate` (`77,48 MiB`). После очистки workspace занимает около `421 MiB`: сохранены `.tools` (`224,98 MiB`), exact source и подписанные lifecycle archives/bootstrap (`.cache` всего `182,04 MiB`), base image tar, страхующий worktree patch, `.git`, все tracked/untracked исходники и пользовательские изменения. Хэши текущих C/D archives повторно совпали с зафиксированными `ed51078f...68bb` и `7da93081...e027439`.

**Ограничения и следующий шаг:** очистка не является software gate и не заменяет Linux/hardware tests. Production `.gvkey`, Git push/tag/Release и данные пользователя не читались и не изменялись. Следующий шаг не изменён: завершить exact schema-33 fresh/offline-reinstall/uninstall/legacy-marker/upgrade lifecycle matrix на сохранённом `gateway-vpn-schema33-c-fresh`, затем выполнить финальный suite/audit и удалить оставшиеся disposable ресурсы.

### Сессия 132 — безопасная очистка и schema-33 watchdog/systemd recovery gate — 2026-09-01

**Очистка:** Docker inventory подтвердил отсутствие остановленных контейнеров, старых project images и бесхозных volumes. Сохранены healthy `open-webui` с его image/volume и активный `gateway-vpn-schema33-base` с exact release evidence. Удалены только `.cache/go-build` и `.cache/go-path` (`498,54 MiB`) и Docker build cache (`194,9 MB`); временная hotfix-сборка после gate также удалена. Workspace уменьшен с `833,23` до `334,69 MiB` в `.cache`, диск `C:` получил около `0,50 GiB`; `.tools`, `.git`, source, exact schema-33 artifacts и production/user data не затронуты.

**Найденные дефекты:** full systemd validator выявил ложный `SSH_FIREWALL_SCOPE_INVALID`: watchdog ожидал legacy direct-interface rule, хотя firewall schema 7 правильно использует `@local_management_interfaces`. Второй дефект оставлял fresh zero-link Management Fabric в `1/0 PENDING`: root-watchdog не мог открыть socket `0600 gateway-vpn:gateway-vpn` без `CAP_DAC_OVERRIDE`, а persistent HTTP transport мог повторно использовать соединение к прежнему broker process после restart.

**Исправления:** SSH check теперь требует ровно одно set-based правило и JSON-состав nft-set, точно равный LAN плюс configured management interfaces; лишний uplink и legacy rule отклоняются. Broker listener явно допускает root только по `SO_PEERCRED`; socket mode изменён на `0660` для dedicated group, а local Unix client использует новое соединение для каждого bounded typed request. OPERATIONS и packaging contract обновлены.

**Проверки:** focused `internal/watchdog`, `internal/networkapply`, `test/packaging`, полный Linux `go test ./...`, Bash syntax и `git diff --check` — PASS. В real systemd PID-1/nftables container подписанный control plane оставался byte-original, hotfix broker/watchdog имели отдельный SHA. SSH перешёл в `HEALTHY`; искусственный zero-link drift `desired=2/applied=1/PENDING` watchdog самостоятельно восстановил в `2/2/APPLIED`, после чего общий status стал `HEALTHY`, а Management Fabric — `NOT_APPLICABLE` при нуле links.

**Ограничения и следующий шаг:** это runtime evidence текущего source, но не новый signed artifact. Exact source/release A до исправления прошёл fresh install, schema 33 и firewall generation 7 marker gate; теперь нужно закрыть offline same-version idempotent preflight, пересобрать disposable exact releases и повторить полный lifecycle/legacy-marker/upgrade matrix. Активный schema-33 контейнер и необходимые image/volumes пока сохранены именно для этого незавершённого gate; `open-webui` не изменялся. Production `.gvkey`, Git push/tag/Release не выполнялись.

### Сессия 131 — удаление disposable schema-33 стенда и фактическое освобождение Docker VHDX — 2026-09-01

**Workspace:** перед удалением сверены top-level размеры, `git status` и dry-run `git clean`. Удалён только gitignored воспроизводимый `.cache` размером `523 883 788` bytes (`499,6 MiB`), состоявший из `go-path` и `go-build`. Сохранены `.tools` с локальным Go `1.26.7`, `.git`, весь tracked/untracked schema-33 source и незакоммиченные изменения. `git clean` не применялся, поэтому новые исходники `internal/updatenet`, migration `000033` и новые Linux/release-gate scripts не затронуты.

**Docker Desktop:** по точным именам остановлены и удалены восемь одноразовых systemd-контейнеров `gateway-vpn-schema33-*`, test images `gateway-vpn-schema33-installed:a`, `gateway-vpn-systemd-rehearsal:ubuntu24`, build-only `golang:1.26.7-bookworm`, volume `gateway-vpn-schema33-release-gate` (`108,8 MB`) и весь воспроизводимый build cache (`194,9 MB`). После очистки `docker system df` содержит только active `open-webui`: один используемый image, один healthy container и один linked volume; reclaimable data и build cache равны `0 B`. Default networks сохранены.

**Фактическое освобождение диска:** Docker storage location подтверждён из локальной настройки как `D:\Docker\DockerDesktopWSL`. После `fstrim`, контролируемой остановки Docker/WSL и `Optimize-VHD -Mode Full` файл `docker_data.vhdx` уменьшился с `12,699` до `10,513 GiB`, то есть на `2,187 GiB`; после штатного запуска его рабочий размер составил `10,544 GiB`, а свободное место `D:` выросло с `50,29` до `52,44 GiB`. Docker Desktop запущен обратно, `open-webui` подтверждён как `running/healthy`; его данные не изменялись.

**Ограничения и следующий шаг:** удалены только воспроизводимые ресурсы, поэтому следующий privileged Ubuntu gate потребует заново собрать disposable image/release artifacts. Production `.gvkey`, Git tag/Release/push и пользовательские данные не открывались и не изменялись. Незавершённый software-шаг остаётся прежним: исправить различение active install и terminal-uninstall remnants в `scripts/install-gateway.sh`, добавить packaging regressions и затем повторить schema-33 lifecycle/upgrade matrix.

### Сессия 130 — очистка воспроизводимых schema-33 ресурсов и сжатие Docker VHDX — 2026-09-01

**Workspace:** перед удалением проверены Git worktree и размеры всех top-level каталогов. Удалён только gitignored воспроизводимый `.cache` размером `2 140 981 412` bytes (`2041,8 MiB`): Windows/Linux Go module/build caches и временные Linux test binaries. Сохранены весь незакоммиченный schema-33 worktree, `.git`, исходники, документация и `.tools` с проверенным Go `1.26.7` (`225,0 MiB`). После очистки workspace занимает `239,5 MiB`; `.cache` отсутствует.

**Docker Desktop:** inventory до удаления показал два неиспользуемых project-test image — `gateway-vpn-netns:ubuntu24` (`184 MB`) и `golang:1.26.7-bookworm` (`1,24 GB`) — и `184,4 MB` build cache. Они удалены по точным именам, build cache очищен до `0 B`. Широкий volume/container prune не применялся: единственные container/image/volume принадлежат работающему `open-webui` и сохранены. После очистки `docker system df` показывает один active image, один active container, один linked volume и `0 B` reclaimable/build cache.

**Фактическое освобождение Windows-диска:** Docker data root обнаружен по локальной настройке в `D:\Docker\DockerDesktopWSL`. После контролируемой остановки Docker/WSL выполнен `Optimize-VHD -Mode Full`; `docker_data.vhdx` уменьшился с `12,818 GiB` до `10,512 GiB`, диск `D:` получил обратно `2,307 GiB` (`50,14` → `52,47 GiB` free). Первая попытка безопасно завершилась до compaction, потому что установленный `Optimize-VHD` не поддерживает параметр `-LiteralPath`; повтор выполнен с корректным `-Path`. Docker Desktop запущен обратно, `open-webui` автоматически восстановился и подтверждён как `healthy`; его image и volume около `1,194 GB` не изменялись.

**Следующий шаг:** очистка не является software gate и не меняет архитектурный критический путь. Для незавершённого disposable Ubuntu 24 systemd/root lifecycle gate schema-33 локальные caches и test images будут воспроизведены по необходимости; production `.gvkey`, tag, Release и push не затрагивались.

### Сессия 129 — целевая очистка workspace и Docker Desktop — 2026-09-01

**Сделано:** перед удалением повторно проверены Git worktree, размеры top-level каталогов, Docker containers/images/volumes и build cache. Из workspace удалён только воспроизводимый `.cache` размером `1037,5 MiB` (Windows/Linux Go module/build caches и два временных Linux test binary). Сохранены `.tools` с проверенным Go `1.26.7`, `.git`, весь исходный код и незакоммиченный schema-33 worktree. По точным именам удалены неиспользуемые project-test images `gateway-vpn-netns:ubuntu24` и `golang:1.26.7-bookworm`; отдельно очищены `184,4 MB` относящегося к их сборке Docker build cache.

**Проверено:** после очистки workspace занимает `239,5 MiB`, из которых `225 MiB` — сохранённый portable Go toolchain; на диске `C:` доступно `59,59 GiB`. Единственный Docker container `open-webui` остаётся `healthy`, его image сохранён, единственный volume `open-webui` размером около `1,194 GB` подключён и не изменён. Других volumes и build cache не осталось. `git status` до и после очистки содержит тот же незакоммиченный schema-33 набор; пользовательские/production данные не удалялись.

**Ограничение и следующий шаг:** очистка не является новым software gate. Для продолжения незавершённого schema-33 update-service-route блока локальные Go caches, Linux test binaries и disposable Ubuntu netns image будут воспроизведены перед обязательным повторным privileged gate; архитектурный следующий шаг не изменён.

### Сессия 128 — повторная безопасная очистка workspace и Docker inventory — 2026-09-01

**Workspace:** перед удалением проверен `git status`; все незакоммиченные изменения schema-33/service-route блока и migration `000033` сохранены. Удалён только gitignored воспроизводимый каталог `.cache` (`go-path` 323,5 MiB и `go-build` 264,8 MiB, всего около 588,3 MiB). Локальный проверенный Go toolchain `.tools` 225,0 MiB оставлен, поскольку он нужен для продолжения разработки. Размер workspace уменьшен примерно с 827,8 MiB до 239,5 MiB; tracked deletions отсутствуют, production `.gvkey` не читался и не изменялся.

**Docker:** полный inventory подтвердил отсутствие неиспользуемых контейнеров, images, volumes и build cache. Остались только активный healthy `open-webui`, используемый им image `ghcr.io/open-webui/open-webui:main` (6,73 GB) и связанный volume `open-webui` (1,194 GB); это не ресурсы Gateway VPN, поэтому они сохранены. Default-сети `bridge/host/none` также сохранены. Широкий prune не выполнен: reclaimable объём равен `0 B`, а удаление активных/чужих данных недопустимо. Docker VHD `D:\Docker\DockerDesktopWSL\disk\docker_data.vhdx` занимает 12,84 GiB и соответствует оставшимся рабочим данным; повторная остановка/компактизация без освобождённых blocks не выполнялась.

**Следующий шаг:** восстановить локальные Go caches только при запуске следующего test-блока, завершить security/race review service-route ladder (включая исключение disabled access methods), выполнить полный audit и после него снова удалить воспроизводимый cache. Production key, tag, Release и push в этой сессии не затрагивались.

### Сессия 127 — schema-32 automatic scheduler core, live Management Fabric observations и полный Linux audit — 2026-09-01

**Automatic update core:** migration `000032` добавляет singleton restart-safe state/lease с bounded phases, deadlines, candidate/staging identity, apply intent/outcome и sanitized result codes. Worker разделяет check/download/apply policy, deterministic jitter и UTC maintenance window, принимает после restart только свой signed `AUTOMATIC_GITHUB_CHANNEL`, не присваивает ручной staging, подавляется при другой/неизвестной maintenance operation и перед Apply повторно требует latest policy, fresh `FULL` access tuple и fresh management handshake. Data path закрывается до durable `APPLY_INTENT`; неоднозначный dispatch становится `OUTCOME_UNKNOWN` и не выполняется повторно без authoritative root journal. API/WebUI показывают redacted durable status и не выдают lease fields/backend paths/secrets.

**Management Fabric runtime:** root `gatewayfabric.Applier` наблюдает `wg show <fixed applied interface> latest-handshakes` только для expected peer из typed host plan. Broker возвращает полный redacted projection `CONNECTING/REACHABLE/DEGRADED/STALE`; unprivileged runner атомарно принимает его только для совпадающих desired/applied generation и полного набора links. Старый `REACHABLE` автоматически становится `STALE`, даже если broker недоступен. Runtime и scheduler имеют отдельные worker heartbeat contracts; внешний outage не превращается в host reboot.

**Найдено и исправлено race-аудитом:** первый Linux `-race` прогон выявил одновременную запись тестового `leaseRenewInterval` и чтение из renewal goroutine. `RunOnce` теперь передаёт goroutine immutable interval snapshot, отменяет её и обязательно ждёт `leaseStopped` до чтения authoritative renewal error/release. Это также исключает утечку старого renew worker между циклами. Targeted и полный повторные race-suite прошли.

**Проверки:** `gofmt` 541 project Go files, Node syntax 12 JavaScript files, Bash syntax, `git diff --check`, `go vet ./...`, targeted race и полный Linux `go test -race ./... -count=1 -p 1` — PASS. Собраны все Linux entrypoints: Gateway, bootstrap, deploy, VPS Agent, CLI и endurance. OpenAPI route parity, schema v1→32 migration/integrity, WebAPI redaction и responsive 1440/390/320 px fixture прошли. Windows обычный suite прошёл кроме прежних `internal/vpsupdate` symlink tests без `SeCreateSymbolicLinkPrivilege`; тот же package прошёл полный Linux race. Попытка Windows `-race` ожидаемо остановилась до tests из-за отсутствия CGO compiler; первая объединённая Docker-команда с login shell остановилась до Go из-за сброшенного PATH, исправленный non-login запуск прошёл.

**Privileged Ubuntu 24 evidence:** одноразовый privileged container повторно доказал firewall delete/`nft flush ruleset` recovery только в `PATH_BLOCKED`, startup ON/OFF exact-LKG semantics, multi-port LAN SSH/uplink isolation, реальный `wg-ingress`, topology rollback и ONE_ARM anti-spoof, VPS operations root boundary и Ubuntu 24 systemd/GRUB graph. Усиленный Gateway Fabric kernel test вызвал новый production observer после двух реальных handshakes и получил две `REACHABLE` observations; после selective removal получил ровно surviving link, сохранив foreign objects и неизменённый interface.

**Очистка и ограничения:** перед аудитом остановлен только временный WebUI preview; удалены воспроизводимый `.cache` 578,14 MiB, preview temp 15,34 MiB, неиспользуемый Docker Scout module 187,94 MiB и 29,99 MiB rotated Docker logs. Активный `open-webui`, его image/volume и единственный локальный Go `.tools` сохранены. Production `.gvkey` не читался; tag, Release и push не выполнялись. Hardware HiLink/Keenetic/USB/RTC, bare-metal power-cut и 24/72h endurance не засчитывались. Аудит §17.3.1 выявил два ещё не закрытых требования: bounded maximum apply delay и service-route ladder для signed check/download; поэтому scheduler отмечен как core local pass, а не полный production completion. Следующий шаг — реализовать именно эти два пункта, затем Windows deploy delivery.

### Сессия 126 — общий Gateway/VPS lifecycle lock и semantic terminal-journal recovery — 2026-08-31

**Причина аудита:** cross-lifecycle просмотр update/rollback/host-upgrade/uninstall обнаружил, что простой факт существования `update-transactions/active.json` навсегда блокировал обслуживание после сбоя между записью terminal `FINALIZED`/`ROLLED_BACK` и удалением pointer. Одновременно Gateway/VPS update units могли выполнить root mutation в `ExecStartPre` до общего install/uninstall lock. На VPS те же дефекты оставались в reinstall/uninstall, а Agent update engine имел только частный `update.lock`.

**Gateway boundary:** добавлена команда `gateway-vpn update-lifecycle-check`, где только проверенный nonterminal journal считается активным; corrupt/ambiguous state fail-safe. Apply, recovery, restore-point rollback и finalize получают `/run/lock/gateway-vpn-install.lock` через `openat(O_NOFOLLOW)` с проверкой owner/type/mode/nlink и nonblocking `flock`. Install/host-upgrade recovery допускает единственный narrow bypass только при одновременных безопасных root-owned install active и authorization markers. Update unit больше не вызывает `firewall-boot` до lock; host-upgrade и guardian uninstall используют semantic checker и повторяют проверку после lock/остановки control plane.

**VPS boundary:** `Journal.InProgress()` отделяет terminal audit evidence от незавершённой операции; `LoadActive()` выполняет read-only inspection, предпочитает новую recoverable transaction-local copy старому terminal pointer и блокирует multiple/corrupt evidence. Boot recovery очищает оставшийся terminal pointer без rollback. Добавлена root-only команда `gateway-vpn-vps-agent update-lifecycle-check`. Apply/recovery/finalize входят в `/run/lock/gateway-vpn-vps-install.lock`; apply/finalize только после lock создают exclusive symlink-safe live marker, а update/finalize units объявлены взаимно конфликтующими и не имеют root-mutating `ExecStartPre`. Reinstall сначала аутентифицирует установленное дерево подписанным source verifier и затем запускает semantic checker. Uninstaller под общим lock останавливает Agent, повторяет полный transaction check и лишь потом удаляет первый owned объект.

**Новые regression gates:** добавлены Linux inode/flock/marker tests, terminal/recoverable journal tests, packaging запреты raw `active.json`/root-mutating `ExecStartPre`, privileged `VPS_LIFECYCLE_GUARD_PASS` и real PID-1 `VPS_UNINSTALL_LIFECYCLE_SYSTEMD_PASS`. Последний доказал: занятый lock, nonterminal и corrupt journal блокируют uninstall до mutation; terminal journal разрешает штатное удаление; Hub state и `/etc/wireguard/wg-mgmt.conf` сохранены. Ubuntu 24 `systemd-analyze verify` и GRUB policy прошли.

**Полная проверка:** native Linux offline `go test ./... -count=1 -p 1` и `go vet ./...` прошли; focused Linux race для обоих CLI, `internal/update`, `internal/vpsupdate`, `internal/removal` и packaging прошёл. Bash syntax всех `scripts/test *.sh`, Go formatting и `git diff --check` прошли. Windows полный suite прошёл во всех пакетах кроме прежних VPS symlink pointer tests: host не имеет `SeCreateSymbolicLinkPrivilege`; тот же полный suite, включая `internal/vpsupdate`, прошёл на Linux. Первая объединённая Linux команда ошибочно использовала login shell, потеряла `/usr/local/go/bin` и остановилась до Go tests; повтор с absolute Go path прошёл. Первый privileged lifecycle fixture удалял собственный `$TMP` во время начального cleanup и не создавал parent transaction root; исправленный fixture прошёл без ослабления product checks.

**Ограничения и cleanup:** production key не читался; tag, GitHub Release и push не выполнялись. Docker здесь доказывает Linux/systemd lifecycle, но не заменяет bare-metal power-cut или реальный VPS provider. После gate удалены test container, volume, temporary systemd image, Go/Ubuntu base images и весь build cache; `docker system df` снова показывает только используемый Open WebUI, который остался `healthy`. Следующий программный блок остаётся прежним: durable automatic Gateway update scheduler, затем Windows deploy delivery и exact release/security audit.

### Сессия 125 — безопасная очистка Windows/Docker build-среды — 2026-08-31

**Удалено:** все контейнеры, volumes и images тестов Gateway VPN (`gateway-vpn-*`, `gvpn-*`, `gvp-*`), явно использованные ими Go/Node/Ubuntu base images, dangling прежний Open WebUI image и весь неиспользуемый Docker build cache. Из workspace удалены только gitignored воспроизводимые `.cache`, `.tools` и `dist`; удерживавшие Go cache тестовые `go.exe`/`webui-preview.exe` корректно остановлены.

**Сохранено и проверено:** рабочий `open-webui`, его текущий image и volume данных; после перезапуска контейнер вернулся в `healthy`. Production `.gvkey` и backup находятся в отдельном соседнем каталоге и не открывались/не удалялись. `git status` сохранил все tracked/untracked изменения schema-31 блока, tracked deletions отсутствуют, branch остаётся `main` и `ahead 18`.

**Освобождённое место:** workspace уменьшен примерно с 12,2 GB до 13,2 MB, на `C:` возвращено около 12,11 GB. После `fstrim`, штатной остановки Docker Desktop и `Optimize-VHD` файл `D:\Docker\DockerDesktopWSL\disk\docker_data.vhdx` уменьшен с `61 620 617 216` до `11 303 649 280` bytes; на `D:` возвращено `50 316 967 936` bytes. Итоговый Docker inventory: один active `open-webui`, один его image, один volume, build cache `0 B`.

**Ограничение и следующий шаг:** удалённые toolchain/images/caches воспроизводимы, но следующий Linux/Go gate сначала заново скачает либо пересоберёт их. После восстановления проверенной среды продолжить незавершённый lifecycle audit: semantic terminal/nonterminal update journal, общий install lock и TOCTOU-проверки host-upgrade/uninstall; затем выполнить regressions и вернуться к durable automatic update scheduler. Push, tag и GitHub Release не выполнялись.

### Сессия 124 — remote Gateway update и complete restore-point rollback — 2026-08-31

**Signed remote source и policy:** schema 31 хранит независимые gates check/download/apply, Stable/Testing channel, bounded jitter, UTC maintenance window и count/size/age retention. Manual WebUI/API умеет проверить signed GitHub manifest, скачать exact role/OS/arch artifact в verified staging либо принять advanced immutable HTTPS URL. Remote client запрещает credentials/fragment/private/link-local/loopback destinations, повторно проверяет каждый redirect/DNS result, size/SHA-256/content type и не пишет URL/query в audit. Автоматический scheduler ещё не подключён: сохранённая policy не объявляется исполненной сама по себе.

**Complete restore points:** retained point включает signed release identity, SQLite, config, secrets, subscriptions, TLS, Mihomo generations/state и host-contract hashes. Root-контроллер вычисляет `CURRENT`, `RECOVERY`, `ACTIVE_TRANSACTION`, защищает их от delete/prune и сериализует retention с update lifecycle. Ручной historical rollback теперь требует password re-authentication, destructive header и `ROLLBACK_TO_RESTORE_POINT`, переводит data path в `PATH_BLOCKED`, создаёт complete safety point и запускает отдельный fixed `gateway-vpn-update-rollback.service`. Pending request и recovery переживают разрыв WebUI, crash и reboot.

**Privileged Linux/systemd evidence:** disposable Ubuntu 24.04 systemd container использовал только test versions `0.1.0-restoregate.1/.2/.3` и disposable signer `b09d69f7a0f6b4774cf6ed27d7bb532351a9184bae425eb747936faaea671a0e`; production `.gvkey` не открывался. Полный gate завершился `GATEWAY_RESTORE_POINT_SYSTEMD_PASS rollback=update-20260831T131551Z-06016ebec1cd61ed3accb59e crash_state=RELEASE_SWITCH_PENDING safety=point-20260831T131612Z-aadc126a1c634c0690cb1171`. После настоящего `docker restart` и нового PID 1 получен `GATEWAY_RESTORE_POINT_REBOOT_RECOVERY_PASS rollback=update-20260831T131611Z-d3dd1ab65e4ae54a69b41aed safety=point-20260831T131612Z-aadc126a1c634c0690cb1171`. Доказаны historical DB/config/secrets/subscriptions/TLS/Mihomo state, ownership, сохранение foreign nft table/interface, cleanup pending request и resume management/DHCP.

**Найдено и исправлено privileged gate:** rollback unit не передавал historical compatibility marker; boot recovery не мог атомарно вернуть `/etc/gateway-vpn/config.yaml`; restored Management Fabric/WireGuard secrets и TLS certificate требовали разных owner/mode; partial candidate мог остаться после permission failure. Добавлены отдельные update/rollback markers, минимальный `/etc/gateway-vpn` `ReadWritePaths` только rollback/recovery units, namespace-aware ownership с mode-before-chown и unconditional candidate cleanup. Unix mode assertions вынесены в Linux-specific implementation, чтобы Windows tests не имитировали недостоверные permission bits.

**Неуспешные проверки сохранены:** Linux race-попытки до product tests выявили только ошибки окружения: release-builder image не содержал GCC, а `.tools/gomodcache-linux` оказался неполным и не содержал `go-qrcode`. Корректный `golang:1.26.7-bookworm` запуск с полным `.tools/gomodcache`, `GOPROXY/GOSUMDB=off` и `--network none` прошёл `go test -race ./... -count=1 -p 1`. Первая прямая `systemd-analyze verify` не имела inert VPS executable placeholders; после их добавления полный Gateway/VPS graph прошёл с exit 0. Первая JS loop ошибочно захватила pprof template из `.tools`; повтор только для tracked и untracked project JavaScript прошёл. Bulk `gofmt` в PowerShell наткнулся на `StandardOutputEncoding`; независимая per-file проверка прошла с пустым выводом. `go vet ./...`, Bash syntax и `git diff --check` также прошли. Windows full suite затрагивает старое ограничение `internal/vpsupdate` на создание symlink без privilege; новый Gateway update/restore code проходит, а тот же VPS package проходит native Linux race suite.

**WebUI и UTC:** «Система и безопасность» проверена при 1280×720 и 320×720. Update policy, signed source, horizontally contained restore table и destructive rollback dialog помещаются, русский текст переносится, document overflow и console errors отсутствуют. Выявленная подсказка журнала «местное время» исправлена: label, initial filter и query boundary используют UTC, timezone setting не добавляется.

**Состояние:** manual remote source и complete restore-point lifecycle имеют local/privileged evidence. Hardware/bare-metal power-cut, physical HiLink/Keenetic paths и 24/72h endurance не выполнялись. Следующий блок — durable automatic update scheduler, затем Windows deploy delivery и exact production release/security audit. Tag, GitHub Release и push не выполнялись.

### Сессия 123 — privileged VPS update/finalize/SIGKILL rollback gate — 2026-08-31

**Реальный lifecycle gate:** в disposable privileged Ubuntu 24 container установлены три локально подписанные тестовые версии VPS Agent. Выполнены успешное обновление с baseline на candidate, вход в `STABILIZING`, guarded finalization, запуск следующего обновления, принудительный `SIGKILL` root updater во время `HEALTH_CHECKING` и автоматическое восстановление предыдущей согласованной пары release+SQLite. После recovery Agent вернулся в `active`, `current` и `recovery` указывали на прежнюю LKG, а чужие nftables table и dummy interface остались побайтно/структурно неизменными.

**Найдено и исправлено:** gate выявил четыре реальных дефекта. Installer проверял HTTPS listener раньше готовности Agent; итоговая запись install report закрывала service user traversal к его state directory; прямой DB `rename()` между двумя systemd bind mounts возвращал `EXDEV`; recovery unit синхронно запускал зависимый Agent и попадал в systemd dependency deadlock. Добавлены bounded listener wait, сохранение `root:gateway-vpn-vps 0710`, verified same-directory atomic DB switch и asynchronous `systemctl start --no-block` после offline recovery. Gate script получил диагностический `ERR` trap, защищённую паузу synthetic deadline и bounded ожидание Agent после asynchronous rollback.

**Доказательство:** `VPS_UPDATE_SYSTEMD_GATE_PASS`; successful transaction `vps-update-20260830T233019Z-e9153cbff598f1bde99deb0c`, interrupted transaction `vps-update-20260830T233031Z-9bd904b20794ee210654e516`, rollback version `0.2.0-vpsgate.14`. Использован только disposable test signer fingerprint `091ba1b6012a17e4451203ef25497a9dd44c21c85a1be8f544a10dd9870a28d1`; production `.gvkey`, tag и GitHub Release не затрагивались.

**WebUI:** страница VPS «Обновление» проверена при 1280×720 и 320×720. На mobile navigation заменяется полным selector, document horizontal overflow отсутствует, карточки/file picker/actions помещаются. Desktop navigation сохраняет предусмотренную горизонтально прокручиваемую ленту, сама страница и кнопки не обрезаются; gate принят с этим известным layout contract.

**Regression:** текущий worktree повторно прошёл полный offline Linux `go test ./... -count=1 -p 1`, `go vet ./...`, `gofmt -l`, JavaScript `node --check`, Bash syntax всех tracked scripts, `git diff --check` и Ubuntu 24 `systemd-analyze verify`/GRUB policy gate. Первая повторная Linux-попытка ошибочно использовала неполный read-only module cache без `go-qrcode` и завершилась setup failure до product tests; повтор с полным локальным cache и `GOPROXY/GOSUMDB=off` прошёл. Это исправление test-run environment, а не product defect.

**Состояние:** VPS signed updater закрыт как `SYSTEMD_SIGKILL_ROLLBACK_PASS`. Архитектурная схема удалённого Gateway update уже обязательна в `PLAN_v1.1.md`, но её полный GitHub/WebUI delivery, complete restore-point retention и UI lifecycle ещё не реализованы и не объявляются готовыми.

**Следующий шаг:** реализовать remote Gateway update и complete restore-point lifecycle: Stable/Testing channel metadata, signed upload/exact URL, locked preflight/apply, initial health gate, 24h stabilization/finalization, rollback и protected retention. Затем Windows deploy delivery и финальный exact release/security audit.

### Сессия 122 — signed VPS updater source, redundant recovery и exact gate preparation — 2026-08-31

**Реализовано:** VPS Hub получил strict signed `.tar.gz` staging, WebUI/API status/stage/apply/discard, fixed unprivileged trigger и root systemd apply. Engine закрепляет старый recovery pointer, устанавливает immutable candidate под restrictive `UMask=0077` с нормализованными directory modes, создаёт SQLite Online Backup, мигрирует/проверяет копию, атомарно переключает DB+current, требует три последовательных health observations и сохраняет 24-часовой `STABILIZING` до finalization. Status для Agent содержит только версии/state/timestamps/error code без privileged paths/hashes.

**Crash/recovery:** root journal хранится двумя atomic copies. Найдена и исправлена systemd-гонка: код умел восстановить отсутствующий `active.json` из transaction-local journal, но прежний `ConditionPathExists=active.json` вообще не запускал boot recovery. Recovery теперь всегда выполняет bounded no-op/scan перед Agent, кроме живого apply/finalize marker; повреждение обеих copies останавливает recovery вместо догадки. Tests отдельно покрывают потерю active pointer, обе corrupted copies, restrictive umask, SystemRuntime ordering и sanitized status.

**Lifecycle/packaging:** VPS signed host contract включает пять update units; installer активирует recovery/path/finalize timer, readiness проверяет timer active, first-install recovery/uninstall удаляют staging/status/units/pointers в правильном ownership scope. Обычный updater не меняет APT, foreign services/firewall/WireGuard либо host contract; несовпадение возвращает installer-required до mutation. Добавлены guarded release-gate helpers и repeatable systemd script для success/finalize и SIGKILL rollback с foreign nft/interface sentinel.

**Проверено:** полный `go test ./... -count=1 -p 1`, `go vet ./...`, Go formatting, все shell/JavaScript syntax, `git diff --check` и Ubuntu 24 `systemd-analyze`/GRUB gate — PASS. Exact signed VPS artifacts и privileged update script ещё не запускались, поэтому блок остаётся `IN_PROGRESS_LOCAL`.

**Следующий шаг:** создать exact local commit, собрать только disposable test-signed `baseline/success/interrupted` VPS releases и выполнить privileged systemd gate. Production key/tag/Release не затрагивать.

### Сессия 121 — контракт отказоустойчивого удалённого обновления Gateway — 2026-08-31

**Зафиксировано в архитектуре:** отдельная WebUI-группа «Обслуживание» с вкладками обновления, версий/восстановления, backup и диагностики; источники Stable/Testing signed GitHub Releases, signed `.tar.gz` upload и advanced exact HTTPS URL; запрет `main`/branch/commit/`git pull`; независимые check/download/apply settings, maintenance window и jitter.

**Transaction/recovery contract:** Gateway является единственным владельцем locked operation даже при нескольких VPS. До mutation выполняются signature/platform/schema/disk/offline checks и записывается рабочий baseline. Candidate переключается согласованной парой release+DB; fixed boot recovery не зависит от candidate, WebUI, браузера или VPS. Software-caused потеря ранее рабочего path/channel вызывает rollback, внешний modem/operator/VPS outage получает отдельную классификацию.

**Acceptance/retention:** initial gate `5..10` минут предшествует 24-часовому stability window. До finalization `recovery` остаётся на прежней LKG. Хранятся complete restore points `signed release + SQLite snapshot + owned metadata + hashes`; default — current, обязательный recovery и две старые точки, защищённые версии не удаляются. Pointer-only update не меняет OS, AmneziaVPN, Docker, UFW или foreign services; изменившийся host contract требует signed installer-upgrade.

**Состояние реализации:** это обязательный согласованный контракт, а не заявление о готовой функции. Базовые Gateway signed staging/pointer rollback и host-contract recovery уже существуют, но GitHub channel automation, полный restore-point retention/WebUI и новые interruption/stability gates ещё не реализованы. Текущие незакоммиченные изменения VPS updater сохранены без перезаписи.

**Следующий шаг:** закончить и проверить текущий VPS updater, затем реализовать Gateway remote update contract. Production key не открывать, tag/Release не создавать без отдельного разрешения.

### Сессия 120 — VPS operational logs, bounded diagnostics и root snapshot boundary — 2026-08-31

**VPS operations plane:** добавлен отдельный пакет `internal/vpsops`. Fixed root-owned `gateway-vpn-vps-operations.service/.timer` без параметров от HTTP собирает только allowlisted systemd units, IPv4 interfaces, protocol-186 routes, owned nft table, безопасную сводку `wg-mgmt`, Fabric watchdog и bounded journald. Snapshot записывается атомарно в `/var/lib/gateway-vpn-vps-privileged/operations/snapshot.json`; второй redaction pass удаляет WireGuard keys/PSK, URL credentials/query, Authorization/Bearer и structured password/token/private-key fields.

**API и WebUI:** добавлены `GET /api/v1/vps/logs`, `GET /api/v1/vps/diagnostics/status` и `POST /api/v1/vps/diagnostics/download`. Вкладка «Журналы» имеет тематические категории, поиск, limit 50/100/200, локально прокручиваемое окно и очистку только DOM. Диагностический ZIP собирается в памяти, ограничен 12 MiB archive/8 MiB plaintext, содержит manifest и SHA-256 каждого allowlisted файла, sanitized config, SQLite schema/integrity/counts, recent logs, operations snapshot и Fabric watchdog; отсутствующая секция даёт `complete=false`, secrets не включаются. Desktop 1280×720 и mobile 320×720 browser gate прошли без horizontal overflow/clipped actions, console warnings/errors отсутствуют.

**Privilege boundary:** первый privileged gate нашёл product defect: atomic writer назначал snapshot владельцем Agent, хотя installer ожидал root. Writer исправлен на `root:<agent-group> 0640`; Linux gate доказал, что Agent читает snapshot, но не sibling `/restore-transactions/secret`. Parent `/var/lib/gateway-vpn-vps-privileged` использует `root:gateway-vpn-vps 0710`, operations — `0750`, restore/fabric остаются `root:root 0700`.

**Dependency defect:** после исправления ownership гейт остановился в test-only JSON validation: образ с `python3-minimal` имел `/usr/bin/python3`, но не модуль `json`. Это выявило реальный zero-to-ready риск, потому что VPS installer сам выполняет строгий JSON parse. Installer/Dockerfile/docs/source gate переведены на полный `python3`; пересобранный Ubuntu 24 образ прошёл весь ownership/JSON gate.

**Проверки:** `go test ./... -count=1 -p 1`, `go vet ./...`, Node `--check`, `bash -n`, `git diff --check` — PASS. Ubuntu 24 privileged ownership gate — PASS. Повторный Ubuntu 24 systemd/GRUB unit graph — PASS. Hardware/реальный VPS не запускались и остаются pending.

**Следующий шаг:** signed VPS update transaction с offline candidate/schema verification, crash-safe DB+release pointer switch, boot recovery и rollback; затем Windows deploy delivery. Production key не открывать, tag/Release не создавать без отдельного разрешения.

### Сессия 119 — schema 30 topology profiles, initial LAN import и one-arm gate — 2026-08-30

**Durable topology transaction:** migration 30 добавила отдельное состояние active profile и generation, а network safe-apply получил operation `TOPOLOGY_PROFILE`. WebUI/API переключают четыре поддерживаемых профиля: `Ethernet LAN → HiLink`, `Ethernet LAN → Ethernet Internet`, `one-arm WireGuard` и mixed HiLink+Ethernet. Один candidate координирует physical roles, логический LAN/address, networkd stable+legacy files, DHCP/DNS, firewall, policy routing и `wg-ingress`; Preview показывает prerequisites/affected interfaces, Apply требует повторно неизменившийся payload, а Confirm принимается только через новый local destination либо требуемый management WireGuard.

**Rollback security:** topology snapshot проверяет schema/profile/generation/state/time/LAN CIDR, allowlisted roles, bounds, уникальные role/interface pairs, SHA-256 и полный stable+legacy path pair каждого current/candidate member. Unknown path kind, duplicate member и отсутствующая половина path pair отклоняются до изменения data plane. Timeout/reboot/process recovery возвращают весь contour, а не отдельный IP-адрес.

**Первоначальный LAN:** первый physical observation теперь читает kernel master из sysfs и транзакционно импортирует installer-selected direct LAN либо physical bridge members как `LAN_MEMBER` + `MANAGEMENT`. Импорт разрешён только на untouched generation `1/1 ACTIVE`, блокируется при уже существующих физических topology roles, не принимает synthetic `netif:managed:lan` и не переназначает Ethernet/HiLink uplink. Событие хранит только interface IDs без MAC/identity hash.

**Firewall и privileged evidence:** schema 6 использует dynamic `@local_management_interfaces` для WebUI/SSH. Новый Ubuntu 24 privileged gate выполнил topology apply/commit/rollback, проверил строгий tamper rejection, реальный nftables ruleset и one-arm policy: непроверенный `wg-ingress` source заблокирован, exact allowlisted peer проходит, spoofed source блокируется, direct mark существует ровно один раз. Обновлённый two-member LAN bridge gate подтверждает SSH через set и недоступность TCP/22 с uplink. Firewall guard startup/LKG/owned-table deletion/`nft flush ruleset`, WireGuard ingress handshake и Ubuntu 24 systemd/GRUB gates также прошли.

**WebUI browser gate:** disposable preview получил безопасный synthetic broker и три физических интерфейса, поэтому вкладка «Сеть» теперь проверяет production read model без host mutation. На desktop и `320×720` подтверждены четыре profile, one-arm normalization, prerequisite Preview, отсутствие document overflow/clipped buttons и локальная прокрутка role matrix/table; console warning/error пуст. Исправлен сброс вертикальной прокрутки после полной отрисовки новой вкладки, чтобы её заголовок не оставался выше viewport. Добавлен smoke-тест network settings/topology read API; mutation Preview дополнительно выполнен browser gate.

**Regression:** `go test ./... -count=1 -p 1`, `go vet ./...`, Node syntax всех JS, `bash -n` всех shell scripts и `git diff --check` — PASS. Полный suite обнаружил и исправил один устаревший packaging assertion: он искал старое `iifname "gateway-vpn-lan"`, хотя schema 6 намеренно использует `@local_management_interfaces`.

**Не проверено:** фактическая смена сетевых карт/кабелей на bare-metal Ubuntu, реальный networkd restart/reboot, Keenetic WAN/one-arm WireGuard, HiLink/Ethernet uplinks, сохранение management access через физический topology switch и hardware power cut. Новый schema-30 source ещё не собран production key, не тегирован и не опубликован.

**Следующий шаг:** VPS Hub logs/update/diagnostics, затем Windows deploy delivery и exact privileged release/security audit.

### Сессия 118 — privileged end-to-end relay, schema 29/4 backup и мобильная навигация — 2026-08-30

**VPS API contract:** добавлен отдельный OpenAPI 3.1 документ всех 35 Hub routes. Contract test проверяет точное совпадение method/path с handler, уникальность `operationId`, cookie identity, CSRF для защищённых mutation, path parameters и локальные `$ref`. Relay DTO фиксирует `destination_port=51822`, `private_keys_on_vps=false` и не содержит полей приватного ключа.

**Literal privileged packet gate:** Ubuntu 24 контейнер без внешней сети поднимает внешний relay path и внутренний WireGuard между администратором и Gateway. Доказаны реальный handshake, разрешённый TCP/8443, запрещённый TCP/8444, отказ wrong public UDP port, отказ plaintext injection и spoofed inner-admin source `10.83.0.10` с VPS. В owned nft table ровно пять relay rules с ненулевыми packet/byte counters; inner peer/key на VPS отсутствует, foreign UFW/Docker/Amnezia-like tables сохраняются. Gate выполнен три раза подряд — PASS.

**Role-specific backup/restore:** Gateway `.gvpn` schema 29 теперь явно проверяет exact `wg-admin.key`, `management_admin_contour`, relay, tunnel и `END_TO_END_RELAY` peer; decrypted DB, successful restore и rollback к прежнему key/topology проходят. VPS `.gvpn-vps` schema 4 проверяет paired Gateway, external E2E administrator, relay association, public/bind/destination ports, rate/burst и generations. Decrypted DB, staged tree и same-VPS restore сохраняют эти данные; quarantine переводит runtime state в `CONFIGURED` как предусмотрено. Ни backup, ни staging, ни live VPS не получают inner `wg-admin` private key.

**WebUI visual:** длинные кнопки используют auto-height, balanced wrapping и устойчивое выравнивание. На ширине до breakpoint горизонтальная лента заменена полным selector с логическими группами; выбор синхронизирует скрытую desktop-вкладку. Browser gate открыл все 16 Gateway sections и все 9 доступных VPS Hub sections при `320×720`: button overflow отсутствует, ширина документа не превышает viewport. На `1024×768` selector скрыт и обычная desktop navigation сохранена.

**Regression:** `go test ./internal/backup ./internal/vpsbackup ./internal/vpsagent ./internal/managementfabric -count=1`, handler tests обеих WebUI, Node syntax, `git diff --check` и полный `go test ./... -count=1` — PASS.

**Не проверено:** физические VPS/Gateway/Keenetic/HiLink paths, provider UDP/firewall, bare-metal reboot/power cut и 24/72h endurance. Новый exact signed schema-29/4 artifact ещё не собирался и не публиковался.

**Следующий шаг:** единая post-install topology-profile transaction с WebUI safe apply/confirm/rollback; затем VPS Hub logs/update/diagnostics и повтор exact privileged systemd/coexistence/release gate.

### Сессия 117 — полный 320 px WebUI gate и атомарный rollback `wg-admin` — 2026-08-30

**WebUI:** общий responsive-контракт повторно проверен на актуальных Gateway schema 29 и VPS Agent schema 4 fixtures. Все навигационные вкладки обеих ролей открыты при `320×720`; видимые buttons/labels/headings/status не имеют clipped scroll area, элементы не выходят за viewport вне собственных table/nav scroll-контейнеров, `document.scrollWidth == clientWidth`, console warning/error пуст. Дополнительно исправлена реальная геометрия checkbox + contextual-help: grid `auto minmax(0,1fr) auto` не выпускает `?` за край длинной строки. Preview-процессы остановлены, viewport сброшен, временные tabs закрыты.

**Найденный rollback defect:** новый injected failure test смены `wg-admin` identity доказал, что прежний код возвращал key file и DB public identity, но мог оставить runtime-интерфейс без public identity, firewall в закрытом промежуточном состоянии и journal recovery pending. Root applier теперь повторно применяет fixed identity/address/listen port даже при совпадающем durable contour, а rotation сохраняет opaque exact pre-rotation snapshot в той же DB transaction. При failure сначала возвращаются прежние private/public identity и desired/applied metadata, затем восстанавливается host journal/receipt; compensating generation не создаётся. Rollback отказывается перетирать конкурентно изменённое desired state.

**Regression:** тест проверяет старый private key, durable public identity, прежнюю receipt generation, byte-equivalent runtime contour/firewall, отсутствие candidate identity в runtime/DB и отсутствие key/path в error. Целевые пакеты, затем полный `go test ./... -count=1`, Node syntax двух изменённых WebUI bundles, `gofmt` и `git diff --check` — PASS.

**Следующий шаг:** добавить VPS OpenAPI route contract для Hub/relay, literal privileged UDP relay + inner WireGuard packet/anti-spoof gate и role-specific backup/restore round-trip schema 29/4; затем единая topology-profile transaction и Hub logs/update/diagnostics.

### Сессия 116 — читаемые действия в адаптивном WebUI — 2026-08-30

**Исправлено:** отдельный browser-аудит всех Gateway-вкладок обнаружил, что прежняя общая переносимость текста скрывала другую проблему: flex-контейнер действий в таблице сжимался до ширины столбца. Кнопки `Обновить и проверить`, `Заменить identity`, `Сбросить пароль` занимали 3–5 строк, а `Отозвать` на 320 px становилась почти вертикальной. Теперь только table action groups получают intrinsic `max-content` width, их кнопки не shrink-ятся и остаются однострочными; широкая таблица по-прежнему прокручивается только внутри `.table-wrap`. На мобильной горизонтальной навигации скрыты неинтерактивные заголовки групп, чтобы они не появлялись обрезанными фрагментами между вкладками.

**Regression:** stylesheet handler test закрепляет table-action layout contract. `go test ./internal/webapi ./internal/vpswebapi -count=1`, Node syntax и `git diff --check` — PASS. Встроенный browser прошёл все Gateway-вкладки на 320×720: эвристика чрезмерно узких/многострочных кнопок вернула пустой результат. Повтор всех вкладок на 1280×900 не обнаружил document overflow или переполнения видимых кнопок, карточек и форм; console warn/error пуст.

**Следующий шаг:** продолжить с end-to-end inner `wg-admin` relay/anti-spoof contour; затем реализовать единую topology-profile transaction и Hub logs/update/diagnostics. Hardware/bare-metal и endurance gates остаются не выполнены.

### Сессия 115 — privileged Gateway Management Fabric и root secret boundary — 2026-08-30

**Root boundary и backup:** production `DefaultPaths` требует exact `root:root 0700` для transaction/management-secret roots и `root:root 0600` для каждого непосредственного private-key файла; symlink, nested reference, другой owner либо ослабленный mode отклоняются до первого host command. Linux cross-UID gate отдельно доказал, что control UID читает обычный service secret, но не management key; fixed root broker собирает encrypted `.gvpn`, WebUI получает только bounded ciphertext/path-free metadata, а расшифрованный round-trip содержит ключ. Перед WebUI-export требуется повторный текущий пароль администратора.

**Gateway runtime и найденные product defects:** root applier получил strict stale-object removal/inventory и сохраняет неизменённые `gvm<N>` при ACL-only apply либо удалении другого VPS. Первый реальный Ubuntu gate обнаружил фактическую форму `ip -json`: host route печатается без `/32`; parser теперь канонизирует bare IPv4 в `/32`, сохраняя exact destination/gateway/table проверки. Следующий packet run показал, что SYN проходил exact `ct state new` ACL, но последующие разрешённые client→resource packets попадали в `PATH_BLOCKED`; добавлено строго scoped `iifname @management_fabric_interfaces ct state established,related`, симметричное существующему reply rule. Новые соединения по-прежнему требуют точного source/interface/alias/protocol/port ACL.

**Privileged evidence:** disposable Ubuntu 24 container без сети создал два независимых VPS namespaces/uplink `/30`, два `gvm<N>` и настоящий WireGuard handshake для каждого. Проверены `ip -json route get endpoint mark`, отдельные tables/marks, exact protocol-186 endpoint `/32`, management/interface routes, nft endpoint/interface/generation sets, prefix DNAT `/24`, `ct state new`, разрешённый двусторонний TCP к локальному resource, запрет cross-link и неразрешённого порта. После disable первого link исчезли только `gvm1` и его endpoint route/set tuple; `gvm2` сохранил прежний ifindex, handshake и разрешённый ресурс. Foreign UFW/Docker/Amnezia-like nft tables и Docker/Amnezia-like interfaces остались byte-identical. Финальный gate прошёл три последовательных раза; полный Linux package binary также прошёл ownership, rollback, stale deletion, renderer и kernel tests.

**Regression:** Windows `go test ./... -count=1 -p 1`, `go vet ./...`, все 11 JS `node --check`, 30 shell scripts `bash -n`, `git diff --check` — PASS. Read-only `golang:1.26.7-bookworm`, `--network none`, `GOPROXY/GOSUMDB=off` выполнил полный Linux test/vet и собрал пять binaries — PASS. Disposable Ubuntu 24 offline image повторно прошёл полный Gateway/VPS `systemd-analyze verify` и nft schema-5 parser. Full GRUB gate не повторён: netns image попытался установить отсутствующие пакеты без сети, а локальный systemd image не содержит GRUB packages; ранее проверенный GRUB result сохраняется историческим evidence и должен быть повторён перед exact signed release.

**Следующий шаг:** реализовать end-to-end inner `wg-admin` relay/anti-spoof contour; затем единую topology-profile transaction и Hub logs/update/diagnostics. Hardware/bare-metal и endurance gates остаются не выполнены.

### Сессия 114 — адаптивный Gateway и VPS WebUI — 2026-08-30

**Исправлено:** общий responsive-контракт применён к обоим интерфейсам. Кнопки и action links теперь растут по высоте, переносят длинные русские подписи и не выходят за родительский блок. Inputs/selects/textarea, карточки, формы и flex/grid children получили безопасные `min-width: 0`/`max-width: 100%`; основной Gateway grid использует `minmax(0,1fr)`. Широкие таблицы остаются в собственных scroll-контейнерах. На узком экране action groups перестраиваются в полноширинные строки, а навигация Gateway/VPS остаётся горизонтальной лентой с естественной шириной пунктов вместо сжатия текста в вертикальные буквы.

**Regression:** static handler tests обеих ролей закрепляют обязательные responsive declarations. `go test ./internal/webapi ./internal/vpswebapi -count=1` — PASS.

**Browser evidence:** disposable loopback previews Gateway и VPS Hub проверены на viewport 390×844. Для Gateway Overview и Management Fabric, а также VPS Administrators и Backup/restore получено `document.scrollWidth == document.clientWidth`; среди видимых кнопок и основных card/form/action containers нет элементов с `scrollWidth > clientWidth` либо `scrollHeight > clientHeight`. Console warn/error обеих страниц пуст. Preview-процессы и временные browser tabs после проверки остановлены.

**Следующий шаг:** вернуться к security review Gateway Management Fabric: закрыть root-owned management-key backup boundary без выдачи plaintext WebUI-процессу, затем проверить stale-link removal/rollback и privileged `gvm<N>` nftables/policy-routing/WireGuard projection.

### Сессия 113 — privileged VPS Management Fabric, rollback и root watchdog — 2026-08-30

**Legacy adoption и host transaction:** VPS Agent получил явное принятие существующего `wg-mgmt` без смены прежней топологии. Hub сохраняет `10.80.0.1/24`; `10.80.0.0/24` зарезервирован для legacy/Hub и не выделяется новым объектам. Parameter-free `fabric.trigger` запускает fixed root unit, который повторно строит typed plan из Agent DB, атомарно применяет `wg-mgmt.conf`, owned protocol-186 routes и `table inet gateway_vpn_vps`, затем проверяет фактические peers/addresses/routes/rules и только после этого фиксирует applied generation/receipt.

**Rollback, recovery и restore:** до mutation сохраняются exact persistent/runtime snapshots. Ошибка после candidate firewall/routes возвращает старые WireGuard peers, routes, nftables, files, receipt и applied generation; journal остаётся авторитетным для boot recovery. VPS restore получил single-use fabric reconciliation authorization: после успешной замены role state host projection остаётся default-deny/pending, пока reconciler не применит и не проверит restored generation. Restore systemd sandbox получил только необходимый write boundary `/etc/wireguard`.

**Watchdog и WebUI:** fixed `.path`, apply/recovery services и periodic watchdog timer включены в installer/recovery/uninstaller и полный systemd graph. Root watchdog сравнивает desired plan с receipt и реальными WireGuard/routes/nftables, ставит reconciliation в очередь при локальном расхождении и пишет atomic bounded `fabric-watchdog.json`. Этот файл только отображает состояние: WebUI не может использовать его как root authorization. На страницах Overview, Access Matrix и Watchdog доступны понятные кнопки применения/reconciliation и видны desired/applied generation, результат root-проверки, reason и queued state.

**ACL и coexistence evidence:** privileged Linux fixture с двумя Gateway и двумя administrator peers установила четыре настоящих WireGuard handshake. Проверены разрешённые Hub SSH/9443/ping, Gateway SSH/индивидуальный WebUI и published resource ACL; unauthorized resource, admin↔admin, Gateway↔Gateway и Gateway→Hub forwarding остаются blocked. Foreign UFW, Docker и AmneziaVPN nftables tables до/после apply/rollback совпадают и не flush-ятся.

**Обязательные файловые backups:** повторно закреплено пользовательское требование: настройки Gateway и VPS обязаны сохраняться и восстанавливаться удобным файлом через WebUI. Реализация остаётся раздельной (`.gvpn`/`.gvpn-vps`), encrypted, с verified preview, password re-authentication, pre-restore snapshot, durable journal/reboot recovery и cross-role rejection. Management Fabric/settings находятся в role DB/config и включены в соответствующий round-trip; каждый будущий durable раздел обязан добавлять regression такого восстановления.

**Проверено:** focused Go tests затронутых пакетов, полный Windows `go test ./... -count=1 -p 1` и `go vet ./...`, offline Linux test/vet и CGO-free builds пяти binaries, `gofmt`, Node syntax, Bash syntax, `git diff --check`, Ubuntu 24 `systemd-analyze verify` и GRUB gate — PASS. Финальный privileged VPS suite трижды подряд подтвердил nft parser/coexistence, four-peer ACL, actual rollback и atomic watchdog status.

**Неудачные harness-попытки:** общий synthetic bridge в Docker Desktop был flaky: второй peer иногда терял data packets до nftables при успешном handshake. Fixture переведён на независимый point-to-point `/30` underlay для каждого peer, после чего десять последовательных прогонов прошли. Первая offline Linux попытка использовала неполный read-only `.tools/gomodcache-linux` без `github.com/skip2/go-qrcode`; повтор с полным локальным module cache и `--network none` прошёл. Финальный Windows вызов alias `bash` снова попал в недоступный WSL (`E_ACCESSDENIED`); те же exact scripts прошли `bash -n` через Git Bash. Это ограничения test harness/cache, а не найденные product defects.

**Следующий шаг:** реализовать Gateway-side simultaneous `gvm<N>` links и согласованное применение published resources/ACL, затем end-to-end `wg-admin` relay. После этого закрыть Hub logs/update/diagnostics, grouped Gateway WebUI и выполнить exact signed Gateway↔VPS systemd/browser gates. Hardware/bare-metal и endurance остаются отдельными обязательными внешними проверками.

### Сессия 112 — managed administrator one-use config и typed VPS host-plan — 2026-08-30

**Schema 3 и managed keys:** VPS Agent получил gap-free checksum migration с `config_state`, `config_downloaded_at` и `rotation_source_id`. Внешний режим по-прежнему принимает только public key. Managed create требует password re-authentication и фразу `СОЗДАТЬ УПРАВЛЯЕМЫЙ КЛЮЧ`, генерирует отдельную X25519 pair и пишет private key atomic `0600` только под Agent state; DB/DTO/audit не содержат private material. `.conf` требует вторую re-authentication и per-peer phrase, строит exact endpoint/assigned address/VPS public key/allowed management+alias routes, переводит `AVAILABLE → CONSUMED` и удаляет key до HTTP response. Concurrent/repeated download получает conflict. Cleanup failure не выдаёт content и остаётся `CLEANUP_REQUIRED` до startup cleanup.

**Make-before-break rotation:** отдельная операция создаёт replacement managed peer с новым address и `rotation_source_id`, не меняя и не отзывая прежний peer. WebUI явно требует скачать новый config, дождаться будущего host apply/fresh handshake и лишь затем отозвать source. Revoke удаляет ACL/prefix generation и недоставленный private key. Shared key/config между несколькими VPS не создаётся.

**Backup/restore:** `.gvpn-vps` включает managed private file только пока соответствующий peer `AVAILABLE`; consumed, revoked и orphan files пропускаются. Отсутствие обязательного AVAILABLE secret делает backup ошибкой, а не тихо неполной копией. `IMPORT_AS_NEW` теперь после очистки peer topology физически удаляет candidate `secrets/administrators`, поэтому новый VPS не сохраняет source credentials; same-VPS остаётся способен восстановить ещё не скачанный config.

**Read-only host projection:** добавлен deterministic `VPSHostPlan` с fixed `wg-mgmt`, UDP/51821 и route protocol 186. Он выводит canonical per-link VPS addresses, Gateway/admin peers с exact `/32`/published alias AllowedIPs, owned alias routes, Hub admin sources и bounded TCP/UDP/ICMP ACL. Private key/ref, arbitrary command/executable/path/interface и default route отсутствуют. Corrupt key/generation, dangling publication/ACL и unsafe prefix отклоняются. Это вход будущего root reconciler, не applied host state; `host_apply_available` остаётся false.

**WebUI/API:** вкладка Administrators теперь имеет отдельные формы external/managed, видимый config lifecycle, one-use download, rotation и revoke. Download использует `Cache-Control: no-store`, attachment-only response и очищает введённые password/confirmation/endpoint variables. Routes ко всем alias позволяют в дальнейшем добавлять ACL без повторной передачи private key; сам route не выдаёт доступ — двойной firewall остаётся default-deny.

**Проверено сейчас:** focused и полный Windows `go test ./... -count=1 -p 1`, полный Windows `go vet ./...`, полный offline Linux test/vet и builds Gateway/bootstrap/ctl/VPS Agent/deploy — PASS. `node --check`, gofmt всех Go-файлов и `git diff --check` — PASS до финальной записи журнала. Unit/integration coverage включает one-use/repeated download, unsafe endpoint, external-key non-rotation, make-before-break source preservation, secret removal, AVAILABLE-only backup, orphan exclusion, import-as-new physical purge, deterministic host-plan и corruption negatives. In-app browser smoke подтвердил login, managed-create, видимый `AVAILABLE` lifecycle и отдельную полную страницу **Backup / восстановление** с password/passphrase download и verified upload формами; console warning/error отсутствуют, preview server остановлен.

**Неудачные harness/test попытки:** первый focused Go run не дошёл до compile, потому что стандартный Windows `GOCACHE` недоступен sandbox; повтор с project-local caches прошёл. Первый compile после schema 3 выявил устаревшее имя/ожидание теста `v1 → v2`; production migration правильно дошла до version 3, test заменён на `v1 → current` с проверкой обеих migration columns. Первая offline Linux попытка задала отдельный `GOPATH`, но не явный `GOMODCACHE`, поэтому при `GOPROXY=off` не нашла смонтированные modules; повтор с `GOMODCACHE=/go/pkg/mod` прошёл. Browser automation остановилась на native confirm/prompt, а повторная попытка не распознала программный `a.download` как download event; endpoint one-use/consumed/removal/repeated-conflict доказан integration tests, а визуальный create/backup smoke повторён без console errors. Product defect не обнаружен.

**Следующий шаг:** сначала parameter-free fabric trigger и legacy `wg-mgmt` adoption/preflight, затем journalled root WireGuard/route/double-ACL apply/rollback с AmneziaVPN/Docker/UFW non-interference fixtures.

### Сессия 111 — VPS Hub management control plane и обязательный role backup contract — 2026-08-30

**VPS Agent schema 2:** добавлены contiguous checksum-verified migration и durable поля для pairing payload/consumed peer, состояния Gateway endpoint/WebUI/handshake/counters, administrator key mode/health, typed resource display/access/acknowledgement/health и desired/applied fabric generations. Raw pairing token не хранится: сохраняется SHA-256 digest; invitation имеет expiry от 5 минут до 24 часов, durable budget восемь попыток, атомарно резервирует `/30`, consumes ровно один Gateway public key и отклоняет replay. Cross-role duplicate WireGuard public keys, пересекающиеся prefixes/aliases и небезопасные значения отклоняются до mutation.

**Control plane и WebUI:** authenticated Hub API и функциональные страницы реализуют Overview, invitations/Gateway list/revoke, external-key administrators, typed resources с отдельным acknowledgement для `LOCAL_SUBNET`, bounded TCP/UDP/ICMP ACL, canonical access matrix и ownership-only watchdog read model. Destructive revoke требует password re-authentication и точную фразу. Managed private admin configs пока намеренно не выдаются; UI честно поддерживает только `EXTERNAL` public keys. Logs и Diagnostics видимо заблокированы до реализации, а health сообщает `PENDING/HOST_APPLY_NOT_IMPLEMENTED`, не имитируя root runtime.

**Security boundary:** HTTP не принимает VPS login/password, private key, arbitrary command, unit, interface, route либо nft expression. Public pairing completion получает только bounded token и Gateway public data; current TCP/9443 firewall остаётся localhost/admin-only, поэтому отдельный безопасный pre-pairing transport является частью следующего privileged инкремента. Raw invitation очищается из DOM и памяти JavaScript при уходе со страницы Gateway.

**Обязательные backup/restore:** подтверждено требование пользователя, что Gateway и VPS должны иметь удобное файловое сохранение и восстановление настроек через WebUI. Реализация уже закрывает его раздельными encrypted `.gvpn` и `.gvpn-vps`: download, upload, verified preview, passphrase/password re-authentication, typed Apply, cross-role rejection, pre-restore snapshot и durable rollback/recovery. PLAN уточнён: это обязательная, а не рекомендательная функция; CLI для обычного сценария не требуется.

**Проверено:** focused `vpsagent`, `vpswebapi`, `vpsbackup` и VPS command tests, полный Windows `go test ./... -count=1 -p 1` и `go vet ./...`, полный offline Linux test/vet и builds Gateway/bootstrap/ctl/VPS Agent/deploy — PASS. `node --check`, gofmt и `git diff --check` — PASS до финальной правки журнала. In-app browser smoke прошёл login, Overview, invitation/Gateway, Channels, Administrators, Resources, ACL matrix и ownership-only Watchdog без console warning/error; preview server остановлен, browser tab закрыт.

**Неудачная harness-попытка:** первый offline Linux Docker run использовал login shell `sh -lc`, не сохранивший Go в `PATH`; повтор с exact `/usr/local/go/bin/go` прошёл полностью. Это ошибка запуска стенда, а не дефект продукта.

**Следующий шаг:** managed administrator key/config lifecycle и узкий parameter-free privileged apply trigger; затем many-to-many WireGuard/route/double-ACL renderer/apply и обязательные AmneziaVPN/Docker/UFW coexistence gates.

### Сессия 110 — VPS Hub WebUI backup/restore и аварийное восстановление — 2026-08-30

**Отдельная роль VPS:** реализован самостоятельный authenticated формат `.gvpn-vps` с Argon2id и chunked AES-256-GCM. Manifest фиксирует role/schema/source VPS identity и SHA-256 каждого разрешённого файла; Gateway `.gvpn` и VPS `.gvpn-vps` взаимно не принимаются. Portable snapshot включает только VPS Agent DB/config/TLS, VPS-owned identities/peers/prefixes/resources/ACL/update state и исключает sessions, login attempts, operation/log history и ephemeral/used pairing material.

**VPS Hub WebUI:** lightweight Go Agent получил restricted TLS WebUI с первым обязательным изменением bootstrap-пароля, login/session/CSRF protection и отдельной страницей backup. Оператор может скачать файл, загрузить его для read-only preview, увидеть role/version/schema/source identity/состав/конфликты, выбрать `Восстановить тот же VPS` либо `Импортировать как новый`, повторно ввести текущий пароль администратора и точную фразу подтверждения. Staged upload и passphrase удаляются после terminal result/discard; cross-role, неверный пароль, повреждённый envelope/manifest и несовместимая schema отклоняются до live mutation.

**Безопасное восстановление:** same-VPS режим сохраняет identity только в quarantine до подтверждённой замены прежнего узла. `IMPORT_AS_NEW` генерирует новые `vps_id`, WireGuard/update/TLS identities, очищает source peers/prefixes/resources/ACL/pairing и создаёт `wg-mgmt.conf` только с новым interface/private key без stale peers. До fresh reconciliation Hub остаётся default-deny. Root transaction создаёт verified pre-restore snapshot, заменяет только фиксированный набор DB/config/secrets/TLS/WireGuard destinations, ведёт fsync-журнал и возвращает точное прежнее состояние при обычной ошибке, SIGKILL либо следующей загрузке после частичного swap.

**Privilege boundary и host lifecycle:** непривилегированный `gateway-vpn-vps` владеет только `/var/lib/gateway-vpn-vps/agent` и не может читать root install journals. WebUI создаёт mode-0600 `restore.trigger`; fixed `gateway-vpn-vps-restore.path` запускает parameter-free root restore unit без права Agent вызывать произвольный `systemctl`. Installer создаёт account/DB/config/secrets/TLS/bootstrap admin и Agent/restore/recovery units, открывая TCP/9443 только для admin WireGuard peer `10.80.0.10`. Reinstall принимает сохранённый Agent state лишь после exact ownership/schema/auth/TLS/key consistency checks. Обычный uninstall сохраняет настройки/администратора/backups/identities, а `--purge-keys` удаляет их и service account. Root install, Agent и privileged restore state разведены по трём непересекающимся каталогам.

**Проверено:** полные Windows и offline Linux `go test ./... -count=1 -p 1`, `go vet ./...`, Linux builds, `node --check`, shell syntax и `git diff --check` — PASS. Unit/integration coverage проверяет crypto bounds/corruption/wrong role, sanitization, preview/re-auth/typed confirmation, same-VPS quarantine, import-as-new identity и реальный `wg-mgmt` consistency, handled rollback и имитацию SIGKILL/fresh-boot recovery. Ubuntu 24 `systemd-analyze verify` и privileged disposable load/delete собственной `table inet gateway_vpn_vps` — PASS; global nftables flush не используется. Реальный VPS provider, Amnezia/Docker/UFW coexistence lifecycle и bare-metal power loss остаются внешними gates.

**Неудачные проверки harness:** первый host-вызов `gofmt/go` использовал отсутствующий системный PATH; после явного выбора portable `.tools/go1.26.7` product checks прошли. WSL `bash` вернул `E_ACCESSDENIED`, поэтому shell syntax проверен Git Bash. Обычный Ubuntu image не содержал `systemd-analyze`, использован локальный Ubuntu systemd test image. Unprivileged nft netlink ожидаемо получил отказ, тот же exact ruleset успешно загружен privileged disposable container. Первый offline Linux run указал на неполный `gomodcache-linux`; повтор с полным локальным `.tools/gomodcache` прошёл. Эти случаи не являются product defects и сохранены для воспроизводимости стенда.

**Следующий шаг:** реализовать VPS pairing/links/administrators/resources/ACL API и ownership-scoped watchdog поверх готового Agent; затем privileged many-to-many WireGuard/route/double-ACL apply и coexistence gate с AmneziaVPN/Docker/UFW.

### Сессия 109 — schema 26 Management Fabric, bounded pairing и read-only renderer — 2026-08-30

**Durable data model:** добавлена migration `000026_management_fabric.sql` для local sites, VPS identities, независимых links/endpoints, digest-only pairing, make-before-break key rotations, administrators/VPS peers, typed resources/ports/publications/ACL и fabric operations/generations. Отдельный singleton counter монотонно выделяет VPS display numbers и link slots; удалённый slot автоматически не переиспользуется. Slot 0 остаётся только explicit legacy `wg-mgmt` adoption, новые links получают `gvm1..gvm4095`. Schema запрещает default route, non-SHA-256 token digest и произвольные/private-key values вместо `/var/lib/gateway-vpn/secrets/*.key` references.

**Repository и validation:** реализованы immutable local `site_id`, create/list/get для VPS и links, несколько одновременно сохранённых VPS/links, canonical private IPv4/address/endpoint validation, collision checks со всеми management/admin/alias/ingress/modem/uplink/reserved prefixes, verified fingerprint/public-key pinning и generation increment. `LOCAL_SUBNET` требует explicit acknowledgement; publications обязаны принадлежать тому же site, ACL — конкретному administrator/VPS/resource publication и только TCP/UDP/ICMP с bounded ports. JSON/read model не выдаёт private-key secret ref.

**Pairing:** импорт принимает raw bounded token только на API boundary и сохраняет SHA-256. VPS identity временно создаётся в той же SQLite transaction; prefix/identity conflict откатывает и identity, и counters. Fingerprint confirmation использует constant-time comparison, общий attempt budget 8 и expiry до 24 часов. Consume одной transaction создаёт link, endpoint и generation, переводит invitation в `CONSUMED`; replay не создаёт второй link. Неверный consume proof также расходует budget, а SIGKILL/process failure до commit по SQLite semantics не оставляет частичный link.

**Read-only renderer:** deterministic typed projection создаёт только owned route protocol `186`, конкретные management/resource-alias destinations, Linux-safe per-slot interfaces, `/32` WireGuard AllowedSources, alias translation и точные ACL rules. `0.0.0.0/0`, arbitrary interface/protocol/ports, cross-site binding, overlap и duplicate key/slot/interface отклоняются до будущей root boundary. Renderer не исполняет `ip`, `wg`, `nft` и не меняет host.

**Проверено:** fresh/idempotent schema 26, table/check/FK contour, два VPS + два links, monotonic slot after delete, duplicate fingerprint/public key, reserved/subnet/alias collision, secret-reference redaction, pairing digest/confirmation/expiry/budgets/exactly-once/replay/atomic rollback и renderer negative fixtures — PASS. После обновления exact schema expectations backup/recovery/update также проходят. Полные offline `go test ./... -count=1` и `go vet ./...` — PASS. Privileged Linux/multi-VPS/Amnezia runtime не запускался; exact signed host evidence остаётся schema 25.

**Следующий шаг:** отдельный VPS Agent role foundation и реальный `.gvpn-vps` encrypted backup/preview/restore поверх role-specific DB/config/secrets; затем Gateway/VPS API и privileged coexistence renderer.

### Сессия 108 — exact `a7a783b`, reproducible build и new-PID1 uninstall recovery — 2026-08-30

**Exact source и build:** документы VPS Agent/Hub, invitation pairing, Amnezia coexistence, role backups и Windows deploy зафиксированы commit `a7a783bbc7c48f9aad84afc766b05f74f55cad72`; он включает parent fix conditional networkd cleanup. Две tracked-only copies собраны одним disposable signer `8231e4d382968a21611e59310a315f5b2f8f9010783abae17fe9cdd0dcf22af0`, с отдельными writable module/build caches, `--network none`, `GOPROXY=off` и `GOSUMDB=off`. Полные `dist` совпали побайтно и по Unix modes: 87 files/31 dirs. SHA-256: Gateway `af632ddde25430ac11cc44e8bff2a7d1133772df7150b2aefb12c0d9aa777e50`, VPS `c15eb94b7d1425a2926f6b4d84bd34ebfde3131b646a2dfc7f2faa6c66c4caee`, bootstrap `d140e467fd04c120da8c0372d1f7b7e37800e0d8ffb47e6f3c180f911253654b`, deploy `b558ab6b25974f924ad91839d2b68f181f037b3a7c24161628bf7257d8225440`, channel `26399bf58c88c514c7975bb38e22d233cffa3606b6e4a15902b0b3f8becc3fce`.

**Exact lifecycle:** public schema-16 baseline прошёл signed dry-run и host-contract apply до `0.1.0-successor.ga7a783b`, schema 25, active control/watchdog/firewall guard и `PATH_BLOCKED`. Настоящий WebUI/API с login, обязательной заменой bootstrap password, CSRF, re-authentication и точной фразой дважды завершил `PRESERVE_DATA` штатными root-only receipts; оба раза последующая reinstall прошла. Финальный запрос `uninstall-97818e78faacf85360589e87e7366c15` получил SIGKILL fixed guardian сразу после durable `active`/`tooling-ready`; helper modes остались `0700/0700/0600`, marker modes `0600`, terminal receipt отсутствовал.

**New PID 1:** весь контейнер получил SIGKILL, stopped filesystem сохранён, новый PID 1 стартовал с очищенным `/run`. Первый recovery полностью завершился, но disabled networkd socket оказался статически triggered стендом и активировал daemon после receipt, поэтому узкий критерий inactive daemon не был ему присвоен. Повтор из того же pre-recovery image с явно unavailable/masked `systemd-networkd.service` и `.socket` доказал правильную ветку: daemon ни разу не стартовал, guardian создал `root:root 0600` receipt `SUCCEEDED`, `packages_removed=0`, удалил active/tooling и весь Gateway-owned host projection, не оставил failed units.

**Сохранность и reinstall:** SHA-256 семи файлов — `state.db`, WAL, SHM и всех четырёх обычных secret files — совпали до power-loss и после recovery. Database verify дал schema 25, `quick_check/integrity_check/foreign_key_check/migration_history=ok`. После явного возврата networkd external prerequisite в рабочее состояние тот же signed artifact переустановился; secrets остались побайтно прежними, mandatory services active, `PATH_BLOCKED`, failed units отсутствуют. Это authoritative privileged Docker/systemd gate; bare-metal отключение питания и physical Ubuntu всё ещё внешние gates.

**Неуспешные harness-попытки:** прежняя пара build commit `c0c547a` остановилась до artifacts на read-only module cache. Первая пара `a7a783b` остановилась до artifacts из-за `noexec /tmp`; повтор с executable tmpfs прошёл. Первый kill watcher исчерпал timeout до dispatch, второй остановился на попытке передать secret directories в `sha256sum`; продукт в обоих случаях штатно завершил uninstall и receipt. Исправленный watcher использовал только recursively enumerated regular files и получил требуемый SIGKILL. Production `.gvkey` не открывался, tag/GitHub Release не создавались; исходный дефектный container `gvpn-uninstall-recovery-0d28010` сохранён.

**Следующий шаг:** schema 26 Management Fabric data/storage/validation foundation без host mutation, затем pairing state machine/read-only renderer и VPS Agent/coexistence skeleton.

### Сессия 107 — утверждённый VPS Agent, coexistence, Windows deploy и role backups — 2026-08-30

**Пользователь утвердил:** VPS устанавливается одной signed командой и добавляется в Gateway WebUI одноразовым invitation без передачи VPS login/password; серверное управление выполняет один лёгкий Go Agent с embedded WebUI/CLI/SQLite. Hub доступен только через localhost/admin WireGuard, имеет предметные вкладки Gateway/links/admin/resources/ACL/watchdog/log/update/backup/diagnostics и не предоставляет arbitrary shell/OS manager. Watchdog меняет только Gateway VPN-owned objects и не reboot VPS.

**Совместимость:** AmneziaVPN либо другой VPN/Docker/UFW на том же VPS является обязательным, а не best-effort сценарием. Зафиксированы collision preflight, отдельные interfaces/ports/prefixes/tables/marks, scope-only firewall без blanket drop/flush, запрет управления foreign units/rules и conditional restoration global forwarding. Требуется отдельный install/pair/watchdog/update/uninstall coexistence gate с неизменностью чужого runtime и connectivity.

**Delivery и backup:** Windows 10/11 x64 получит portable signed `gateway-vpn-deploy.exe` после заморозки core VPS/pairing API; Linux launcher остаётся первым. Gateway `.gvpn` сохраняет действующий доказанный WebUI restore contract, VPS Hub получает отдельный `.gvpn-vps` с preview, passphrase, durable power-loss rollback и same-device/import-as-new modes. Cross-role restore, ephemeral pairing/session/log data и silent duplicate identity запрещены.

**Граница evidence:** изменения пока только в `PLAN_v1.1.md`, `NETWORKING.md`, `OPERATIONS.md`, `SECURITY.md` и этом журнале. Текущая schema 25 не содержит VPS Agent DB/API/Hub, coexistence renderer/test, VPS backup или Windows adapter; статусы добавлены как `IN_PROGRESS_LOCAL`, а не PASS.

**Проверка документации:** все 46 пунктов DoD имеют ровно одну строку evidence; автоматический подсчёт матрицы совпадает с итогом `20 PASS_LOCAL / 12 IN_PROGRESS_LOCAL / 12 PARTIAL_EXTERNAL / 2 NOT_RUN_EXTERNAL`. Проверены границы pairing/public bind, раздельные backup roles, identity-aware restore и запрет вмешательства в Amnezia/Docker/UFW. `git diff --check` и focused `go test ./test/packaging -count=1` с локальными offline Go caches — PASS; первый запуск без переназначенных caches ожидаемо получил отказ sandbox на запись в пользовательские `GOCACHE/GOMODCACHE` и не является product failure.

**Build harness observation:** первая пара offline сборок commit `c0c547a` безопасно завершилась до создания artifacts: read-only module cache не содержал writable `cache/download`, Go попытался создать его и получил `read-only file system`. Source и signer не изменились. Следующая exact сборка использует отдельные writable per-build module/cache volumes, предварительно заполненные из verified offline cache, и снова работает с `--network none`/`GOPROXY=off`.

**Следующий шаг:** зафиксировать новый exact docs+recovery commit, повторить две offline сборки с исправленным harness и выполнить new-PID1 uninstall recovery gate.

### Сессия 106 — new-PID1 uninstall regression и conditional networkd cleanup — 2026-08-30

**Фактический результат прежнего exact candidate:** сохранённый disposable `gvpn-uninstall-recovery-0d28010` был запущен новым PID 1 с boot ID `014de467-19da-4b0a-a634-6d964b332b95`. Guardian повторно нашёл `PRESERVE_DATA` marker и проверенное root-only tooling, дошёл до финальной очистки, но `networkctl reload` увидел неработающий networkd, попытался D-Bus-активировать `org.freedesktop.network1` и через 25 секунд завершился timeout. Unit остался failed; active marker и `tooling-ready` сохранены, terminal receipt не создан. Контейнер сохранён как evidence и не считается PASS.

**Исправлено:** `uninstall.sh` и first-install recovery используют один явный contract: уже active `systemd-networkd` обязан успешно выполнить live reload; inactive/unavailable daemon не запускается и безопасно пропускается после удаления всех Gateway-owned `.network` files. Это не маскирует failure работающего daemon и не меняет чужую host network policy. Добавлен packaging regression, запрещающий bare/duplicate `networkctl reload` вне active-state gate.

**Проверено на source:** focused packaging test, полный `go test ./... -count=1`, `go vet ./...`, Linux/amd64 CGO-free build четырёх commands, Bash `-n` исправленных scripts в pinned Ubuntu 24.04 container и `git diff --check` — PASS. Production key не открывался, tag/Release не создавались.

**Остаётся:** новый clean exact disposable artifact должен повторить preserve → guardian SIGKILL → новый PID1 с фактически inactive networkd и доказать terminal receipt, сохранённую schema-25 DB/secrets, отсутствие owned host projection и возможность reinstall. Только после этого regression gate закрывается.

**Следующий шаг:** commit точного source, offline disposable build и повторный systemd recovery gate без ручной подмены hash-bound tooling.

### Сессия 105 — Management Fabric, удалённые локальные ресурсы и WebUI information architecture — 2026-08-30

**Уточнённый пользовательский сценарий:** все topology profiles должны изменяться через WebUI после установки; один VPS может обслуживать несколько Gateway, один Gateway — несколько VPS; Gateway не имеет внешнего IP и сам инициирует management tunnels. Через VPS нужен управляемый доступ к самому Gateway, при явном разрешении — к Keenetic и локальным host/subnet. Keenetic может продолжать получать Internet обычным WAN без WireGuard.

**Архитектурно зафиксировано:** many-to-many links с отдельными keys/subnets/interfaces и одновременно active состоянием; per-link uplink selector; one-time pairing/fingerprint/make-before-break rotation; restricted VPS Hub; portable per-VPS admin configs без overlapping AllowedIPs; recommended Gateway-terminated `wg-admin` through allowlisted VPS UDP relay; typed resources и пять access profiles; отдельные aliases для каждой `site × resource × VPS link` publication; double ACL на VPS/Gateway; explicit external prerequisites и отсутствие Gateway↔Gateway/admin↔admin/management→Internet forwarding. Текущий один `wg-mgmt` становится совместимым slot 0, не молча превращается в broad route.

**WebUI contract:** sidebar сгруппирован в шесть областей, а удалённый доступ имеет отдельные страницы VPS/каналов, администраторов, локальных ресурсов и матрицы доступа. `wg-ingress` clients, topology/interfaces, subscriptions/modems и logs остаются отдельными владельцами своих настроек; Overview содержит только summary/deep links. Добавлены API outline, DB migration entities, два watchdog components, integration/failure gates и Definition of Done 36–42.

**Граница evidence:** изменены только архитектурные/эксплуатационные документы `PLAN_v1.1.md`, `NETWORKING.md`, `OPERATIONS.md` и `PROJECT_STATUS.md`. Schema 25/runtime/firewall/VPS installer/WebUI не реализуют новый Management Fabric; никаких PASS или production/hardware статусов ему не присвоено. Прежний single-VPS contour и current 17-component watchdog остаются фактической реализацией.

**Следующий шаг:** проверить непротиворечивость документации, затем вернуться к незавершённому exact schema-25 new-PID1 uninstall recovery gate после отдельного разрешения на повторный старт disposable container. После закрытия gate начать schema 26 Management Fabric foundation: typed data model/migration, validation и read-only plan renderer без host mutation.

### Сессия 104 — schema 25 и durable WebUI uninstall contour — 2026-08-29

**Реализовано:** добавлены `internal/removal` и migration 25 с partial unique invariant одной активной `SYSTEM_UNINSTALL`. Web/API требует authenticated session, CSRF, текущий пароль, точную фразу `УДАЛИТЬ GATEWAY VPN`, явные acknowledgement и выбор `PRESERVE_DATA`/`PURGE_DATA`; purge отдельно требует подтвердить потерю данных и сохранённый либо осознанно ненужный export. Через Unix broker проходит только typed operation ID/mode. Fixed root backend проверяет отсутствие lifecycle maintenance, fsync-публикует `/var/lib/gateway-vpn-uninstall/active` и запускает только `gateway-vpn-uninstall.service`.

**Recovery contract:** guardian удерживает общий lifecycle FD9 lock, проверяет signed current release и собственные installed unit/helper, создаёт hash-bound root-only tooling вне `/opt`, применяет и подтверждает `PATH_BLOCKED`, затем запускает существующий idempotent uninstaller. Успех сначала fsync-сохраняет six-field `completed-uninstall-<id>`, затем удаляет active marker/tooling и собственную projection. При SIGKILL/reboot enabled unit повторяет operation даже после удаления `/opt`. Fresh installer разрешает заменить два terminal guardian remnants только при строгой `root:root 0600` receipt с совпадающим filename/operation ID, allowlisted mode, `SUCCEEDED`, UTC timestamp и `packages_removed=0`; любой другой remnant остаётся конфликтом. GRUB regeneration при recovery/uninstall определяется durable install marker и повторяется, даже если предыдущая попытка уже удалила drop-in.

**Поведение удаления:** обе ветви сначала закрывают пользовательский data path. Preserve оставляет application data для reinstall; purge удаляет DB/secrets/keys/backups и log exports без скрытой копии в `/root`. Ubuntu packages и чужие host settings намеренно не удаляются. Installer/recovery/host-upgrade, signed host contract, release builder, systemd unit graph, OpenAPI, Operations/Security runbooks и WebUI panel интегрированы с новым guardian.

**Проверено:** полный serial `go test ./... -count=1 -p 1`, `go vet ./...`, Linux/amd64 CGO-free cross-build четырёх commands, Bash syntax семи lifecycle scripts, JavaScript syntax `app.js`/`power.js`/`uninstall.js`, `git diff --check` и direct offline Ubuntu 24 `systemd-analyze verify` полного Gateway/VPS unit graph — PASS. Packaging regressions отдельно закрепляют GRUB retry после удалённого drop-in, строгую terminal receipt и узкое исключение только для двух guardian remnants.

**Неуспешные промежуточные проверки:** первый полный Windows suite выявил, что Unix directory mode и directory `fsync` нельзя достоверно исполнять на Windows. Durability/mode helpers разделены build tags: Linux по-прежнему требует точные `0700/0600`, root owner и реальный directory fsync; non-Linux существует только для source tests и не ослабляет production build. Первая попытка полного `verify_units.sh` в network-disabled базовом image остановилась из-за отсутствующего `grub-common`; unit graph затем проверен direct offline `systemd-analyze`, а ранее пройденный GRUB gate не изменялся этим increment.

**Остаётся:** exact committed candidate ещё не собран и не проходил WebUI/API preserve, reinstall, purge, guardian SIGKILL и новый PID1 retry. Никакой tag/Release не создавался, production signing key не использовался, physical Ubuntu/hardware gates не объявляются пройденными.

**Следующий шаг:** commit/push schema-25 source increment, две offline reproducible builds disposable signer-ом и exact immutable schema-16 baseline → schema-25 host-contract/uninstall/recovery matrix.

### Сессия 103 — exact schema 16→24 и повторяемый new-PID1 rollback — 2026-08-29

**Exact candidate:** commit `c6328682541a220b33b7b40ca3df3fe6be30dd54` дважды собран offline из двух clean tracked-only copies с `GOPROXY=off`, разными build cache и одним disposable signer. Все 85 файлов двух `dist` побайтно совпали. Signer fingerprint `8231e4d382968a21611e59310a315f5b2f8f9010783abae17fe9cdd0dcf22af0`; SHA-256: Gateway `1c071b9a79b9360623e52c018027f7d7be4d77aafbc5eedd153c6c90c19da6ad`, VPS `24b0802e98ee8c6e898347e78082def545c85741a40e73f03fc689d1828a56c0`, bootstrap `a4b2fba885d081f3c023b77b2e90f1e5d31e7aa26b05f6953331736b577f1602`, deploy `33ee971042e19df06cfe2041bad0cf2aa7faa94c03c58d744f86036c6f467762`, channel `87aced35bdd976262a9820b9e5b25a159c8c32bfba01d51a29e44946476a0d21`. Production key, tag и GitHub Release не использовались.

**Success/failure matrix:** clean clone immutable public `0.1.0-successor.5723940` (schema 16, legacy 14-field marker) успешно перешёл на `0.1.0-successor.gc632868` с exact gap-free schema/history 24. `current`/`recovery`, config, все прежние secrets, преобразованный 18-field marker, mandatory services, watchdog `HEALTHY`, пустой `systemctl --failed` и `PATH_BLOCKED` проверены. В отдельном container candidate control намеренно остановлен после activation; transaction вернула оба pointers, exact schema/history 16, исходные config/secrets/report и побайтно тот же 14-field marker, создала root-only `rolled-back-*`, восстановила services/watchdog и не открыла direct path.

**Двойное interruption evidence:** upgrade запущен как PID1-owned transient cgroup и получил SIGKILL только после durable `APPLYING` marker и candidate pointer. Первая recovery запущена штатным systemd unit и получила отдельный SIGKILL после удаления обычного `gateway-vpn.service`, то есть внутри destructive restore. После второго interruption guardian helper `root:root 0700`, unit `0644`, enable symlink, active marker и `PATH_BLOCKED` оставались на месте, terminal receipt отсутствовал. `/run` очищен как volatile tmpfs, container перезапущен с новым PID 1; boot автоматически повторил recovery и завершил rollback. Итог: baseline pointers/schema/history 16, config/secrets/report/legacy marker восстановлены, active marker отсутствует, root-only receipt присутствует, прежняя отсутствующая guardian projection возвращена, mandatory services active, watchdog `HEALTHY`, failed units пусты, `PATH_BLOCKED`.

**Найдено exact rehearsal и исправлено:** первая версия recovery удаляла собственные unit/helper до terminal receipt, поэтому повторный boot уже не имел guardian. Двухфазное удаление закреплено commit `c2312c4`. Следующий exact rehearsal обнаружил `226/NAMESPACE` на хосте без `/boot/grub`; путь сделан optional (`781968b`). После этого systemd unit дошёл до mutation и показал, что отдельные `ReadWritePaths=/opt/gateway-vpn ...` являются read-only mount points при удалении самих directory roots. Namespace ограниченно переведён на parents `/opt`, `/var/lib`, `/var/log` (`c632868`), в то время как fixed signed helper сохраняет строгий allowlist и pre-mutation validation. Candidates `gc2312c4` и `g781968b` признаны superseded и не публикуются.

**Source gates:** после каждого исправления полный serial `go test ./... -count=1 -p 1` и `go vet ./...` проходили в network-disabled Linux builder; packaging regressions закрепляют guardian ordering, optional GRUB и parent mount semantics. Реальный Ubuntu 24 systemd mount namespace с отсутствующим `/boot/grub` отдельно запустил probe успешно. WSL/Git-Bash Windows-wide `bash -n` попытка не выполнялась из-за локального `E_ACCESSDENIED`; authoritative Linux release builds повторно проверили и подписали все четыре lifecycle shell files.

**Следующий шаг:** реализовать DEV-195 WebUI uninstall orchestration с re-auth, точной фразой, preserve/purge, fixed root-owned durable job и terminal receipt; затем clean SSH/WG OFF и финальный source/systemd/security audit перед разрешённым push. Bare-metal power cut остаётся hardware gate.

### Сессия 102 — signed host-contract transaction и local recovery audit — 2026-08-29

**Реализовано:** новый `scripts/upgrade-gateway-host.sh` отделяет lifecycle upgrade от pointer-only update, проверяет совпадение requested/signed/binary versions, запрещает одновременно менять LAN/DHCP/SSH/SFTP/`wg-ingress`/boot/GRUB, закрывает data path, создаёт cold root-only snapshot и запускает candidate installer с наследуемым FD9 lock. Новый `gateway-vpn-host-upgrade-recovery.service` восстанавливает старую release+DB pair, config/secrets, LAN/sysctl/units и запускается до control/data plane при живом durable marker. `gateway-vpnctl database-verify` проверяет exact schema, gap-free checksummed migration prefix, quick/integrity/foreign-key checks. Host contract теперь подписывает installer, upgrader, оба recovery helpers и uninstaller; размер отдельного lifecycle file ограничен 256 KiB.

**Найдено review и исправлено:** первоначальный recovery выполнял `cp -a snapshot/rootfs/. /`; synthetic parents были созданы `0700`, поэтому merge мог изменить permissions системных `/etc`, `/usr`, `/var` и `/boot`. Восстановление заменено строгим allowlist отдельных Gateway destinations, regression запрещает whole-root merge. Второй дефект: новый verifier не может проверить immutable старый release, не содержащий новых required host files. Transaction теперь сохраняет проверенный old verifier отдельно: он проверяет старую signature/manifest/host contract, новый verifier — старую DB migration history; restored old verifier дополнительно обязан побайтно совпасть с snapshot.

**Проверено:** `gofmt`; focused и полный serial `go test ./... -count=1 -p 1`; `go vet ./...`; `git diff --check`; Git Bash syntax новых/изменённых lifecycle scripts — PASS. Отдельный Linux Go 1.26.7 container повторно выполнил focused source gate. Privileged Ubuntu 24.04 container повторно выполнил `systemd-analyze verify` всего Gateway/VPS unit graph и реальный GRUB generate/validate/owned-drop-in rollback — PASS. Production key, tag и GitHub Release не использовались.

**Неуспешный промежуточный тест:** после выделения отдельной validated `TOOLING` directory packaging regression ещё искал прежние literal paths `$TRANSACTION/tooling/...` и дал два ожидаемых string-mismatch. Проверка обновлена на `$TOOLING/...`; повторный focused suite прошёл, runtime contract не ослаблялся.

**Exact baseline discovery:** новый clean Ubuntu container установил неизменяемый public `0.1.0-successor.5723940` со schema 16 и показал marker format 14: исходное состояние `ssh.service` записано, `ssh.socket` ещё отсутствует. Первоначальный merge ошибочно подставлял socket state из post-install candidate marker. До запуска upgrade merge изменён: marker v20 сохраняет старые socket fields только при их реальном наличии; legacy 14/16/18 становится форматом 18, поэтому uninstaller не угадывает неизвестное pre-install состояние socket.

**Superseded exact build:** commit `3a84a522568ece08d7d28dda91fa46a02d903c0d` дважды offline собрал 85 побайтно одинаковых files как `0.1.0-successor.g3a84a52` (Gateway SHA-256 `f1572d5507f6381b0ab080aaebce0a4893317bfb104efcc212b2c84655867088`). Artifact не запускался как upgrade и сразу признан superseded после обнаружения legacy socket-marker defect; tag/Release не создавались. Следующий exact candidate обязан включать исправленный merge.

**Первый apply-gate исправленного marker:** exact `d44456f` воспроизводимо собран, а dry-run public schema `16 → 24` прошёл. Apply создал cold snapshot/marker, затем inner installer безопасно остановился на `Gateway DNS resolution failed`: внешний dispatch выполнялся до DNS/resources/APT/kernel/network preflight, а inner повторял DNS уже после преднамеренного `PATH_BLOCKED`. Recovery полностью вернул public release+schema 16, active marker отсутствует, firewall blocked и control active. Порядок изменён: весь host preflight выполняется до dispatch; inner после quiesce допускает отсутствие DNS только при exact inherited FD9 + active root marker и повторяет все локальные invariants.

**Не проверено:** candidate ещё не собран как exact committed disposable-signed artifact; public baseline schema 16 не обновлялся до schema 24. Success, injected failure, process interruption и новый PID 1 с пустым `/run` пока не являются доказанными. Bare-metal power cut остаётся отдельным hardware gate.

**Следующий шаг:** commit/push текущего increment, exact offline candidate build и privileged Ubuntu 24.04 public-baseline `16 → 24` success/rollback/new-PID1 recovery matrix. После стабилизации реализовать DEV-195 WebUI uninstall job и расширить CLI purge до полного bounded cleanup/receipt.

### Сессия 101 — exact `0858294`, fresh/idempotency PASS и canonical release gate — 2026-08-29

**Exact build:** commit `0858294aa308a0b4a8d3fb641bd31eaba1ac5cf9` отправлен в `origin/main` и дважды offline собран как `0.1.0-successor.g0858294`; все 82 файла совпали побайтно. Disposable signer `8231e4d382968a21611e59310a315f5b2f8f9010783abae17fe9cdd0dcf22af0`; SHA-256: Gateway `70e679f8b1189a5faa88bf4485b278c41b0155dc624ee2773822a569a6b14315`, VPS `e7ea3f3b158fd7c9d75a594f38fc45cef5821853ab87eddd46999c02429cd84b`, bootstrap `ff88263c7e93d594391369a2baae4ac0b7a9733cb83cb5984e5f2fcdb2a9028b`, deploy `0976dcaed85fc00f0e52da079b26dcb14ad8a3296f4d3a61dbbff58cd3a7565c`, channel `baa378c62f7f64305cec2ab759111250215cf917fd3028d72911cd06db4e2a76`. Production key, tag и Release не использовались.

**Fresh acceptance:** clean Ubuntu 24.04 без заранее установленного OpenSSH успешно получил LAN bridge `gateway-vpn-lan` с `lan0,lan1`, адрес `192.168.210.1/24`, DHCP, OpenSSH/SFTP, тематические log exports, fail-closed firewall schema 4, control/watchdog с 17 компонентами и `wg-ingress` `10.90.0.1/24` на UDP/51822. Без реального uplink runtime ожидаемо находится в `ALL_UPLINKS_OFFLINE / PATH_BLOCKED`; все 17 компонентов watchdog — `HEALTHY`. Повтор exact installer завершился идемпотентно и сохранил готовый contour.

**Release-gate drift:** tracked validator всё ещё ожидал retired `ALL_MODEMS_OFFLINE`. Проверка заменена на canonical `ALL_UPLINKS_OFFLINE`, а packaging test запрещает возврат старого modem-only состояния. Над тем же неизменённым installed root десять последовательных non-trace validator runs завершились `GATEWAY_SYSTEMD_RELEASE_GATE_PASS`; failed units, restart counters и запрещённые journal signatures отсутствуют.

**Source/static gates:** полный serial `go test ./... -count=1 -p 1`, `go vet ./...`, синтаксис четырёх production WebUI JavaScript-файлов, Bash syntax всех tracked installer/netns/systemd/release-gate scripts, Ubuntu 24.04 `systemd-analyze verify`, GRUB policy gate и `git diff --check` — PASS.

**Ограничение:** текущий container сохраняет PID 1 и `/run` с момента установки; это ещё не доказательство настоящего reboot boundary. Отдельные clean SSH/WG OFF, schema update/rollback и WebUI uninstall gates пока не выполнены.

**Следующий шаг:** зафиксировать test/status increment, сохранить installed rootfs и выполнить новый PID 1 с пустым `/run` и test-only persistent `lan0/lan1`; затем clean SSH/WG OFF и schema update/rollback acceptance.

### Сессия 100 — exact `3c20f2a` и bounded systemd start-limit defect — 2026-08-29

**Exact build:** commit `3c20f2ad2af8d28f1f803fe4a65e8e7f5b9910a4` отправлен в `origin/main` и дважды offline собран как `0.1.0-successor.3c20f2a`; все 82 файла совпали побайтно. Disposable signer `8231e4d382968a21611e59310a315f5b2f8f9010783abae17fe9cdd0dcf22af0`; SHA-256: Gateway `c3e23cda370678061ccb9c259676b29485e6deb5719c3476cc882447a2b2fd38`, VPS `4c2932cbc581b45bee04d362194538dd6b8afe00e96509166ac7d6a863be622b`, bootstrap `f334044a75edd0021769396255a215d3839f52f76d7bc8690cd710a3f4024628`, deploy `b8dc8a3aa0290a5503dba3ac4eeeeebded71300a1687b31dd373556bb87f2f76`, channel `644b570b02856709418d124a9c9022d2c0a7bb85fd637ef4bdfb5885cb536c2e`. Первые две build-попытки безопасно остановились до артефактов из-за неполного/readonly Go module cache; успешный build использовал полный workspace-local cache с `GOPROXY=off`. Production key, tag и Release не использовались.

**Fresh acceptance:** clean Ubuntu 24.04 без OpenSSH успешно прошёл signature/preflight, безопасную установку семи пакетов без upgrade/removal, `/run/sshd`, `sshd -t`, LAN bridge `lan0,lan1`, `192.168.210.1:8443`, DHCP, firewall, broker, watchdog/control v2 readiness и тематический log export. Initial ingress bootstrap создал `wg-ingress` на `10.90.0.1/24`, UDP/51822. Следующий совместный restart control/watchdog получил dependency failure: `gateway-vpn-network-recovery.service` ранее пять раз успешно завершился для последовательных dependents и шестым запуском попал в systemd `start-limit-hit`.

**Исправление:** recovery остаётся inactive oneshot и продолжает запускаться перед каждым новым dependent process start, но его unit отключает start-rate limiting. Это не маскирует command failure и не превращает recovery в постоянно active unit; зависимые сервисы всё равно не стартуют при реальной ошибке recovery. Packaging regression закрепляет property, Ubuntu 24.04 `systemd-analyze verify` всего unit graph проходит.

**Rollback evidence:** automatic first-install recovery exact `3c20f2a` завершился без ручного вмешательства: active marker отсутствует, создан root-only `rolled-back-*`, config/release/state/log roots удалены, LAN-карты снова `UP`, оба OpenSSH unit возвращены в исходный `disabled/inactive`. Полные serial `go test ./... -count=1 -p 1`, `go vet ./...` и `git diff --check` после unit fix — PASS.

**Следующий шаг:** commit/push unit fix, новый exact double-build и третий SSH/WG ON fresh acceptance; затем SSH/WG OFF, idempotent reinstall, new-PID1/reboot и schema update/rollback gates.

### Сессия 099 — readiness schema drift и завершение first-install recovery — 2026-08-29

**Exact evidence:** source `d4efd0fe7cd9300111278923870bd0803dbe7bf9` дважды offline собран как `0.1.0-successor.d4efd0f`; все 82 файла совпали побайтно. Disposable signer fingerprint `8231e4d382968a21611e59310a315f5b2f8f9010783abae17fe9cdd0dcf22af0`; SHA-256: Gateway `9654655cf140e701906069ff566581511fe16f19eaecdb50e8fa78211cb88fcf`, VPS `4e3fba3fcde4e5244c7eaf337f012d3e05eb7beab10e362948bde6914504d513`, bootstrap `95a3256f2ea13c3d2102cd61e12e5f9cf69f6e4c7575ea078ede1e45016b7e40`, deploy `60da9364a642da09a6a854141d2f07ef0232c23bd6b8708b517bc455ebff6f1d`, channel `f0ff01cb578635b46bdceee27c67d837db1f081e8c00a4a151fd71cf43793521`. Production key, tag и Release не использовались.

**Fresh rehearsal:** на clean Ubuntu 24.04 без `openssh-server` installer успешно установил пакет, подготовил `/run/sshd`, прошёл `sshd -t`, включил wildcard TCP/22, создал `gateway-vpn-lan` с `lan0,lan1`, поднял `192.168.210.1:8443`, DHCP и owned fail-closed firewall. Namespaced journal подтвердил healthy management startup. Readiness всё же истёк: installer искал `schema_version:1` в control heartbeat, тогда как runtime и validator используют schema v2.

**Recovery defect и исправление:** automatic recovery остановил owned units/table/bridge, но оставил active marker. `bash -x` доказал остановку на корректном отрицательном `systemctl is-active ssh.socket`: последний status helper-функции вытекал под `set -e`. Helper теперь явно возвращает 0 после сохранения любых реальных ошибок через `record_failure`. Исправленный script повторно выполнен в том же systemd container: active marker исчез, создан root-only `rolled-back-*`, LAN bridge/config/state/release pointers удалены, обе LAN-карты возвращены в исходный `UP`, `ssh.service` и `ssh.socket` — в исходный `disabled/inactive`.

**Проверено после правок:** focused packaging regressions, полный serial `go test ./... -count=1 -p 1`, `go vet ./...`, JavaScript syntax 8 файлов, Ubuntu Bash syntax 27 tracked scripts и `git diff --check` — PASS. Старый exact `d4efd0f` остаётся acceptance evidence, но не является install-ready artifact.

**Новый запрос по удалению:** принято разделение WebUI на «удалить приложение с сохранением данных» и explicit purge; операция требует re-auth/точной фразы и завершается отдельным root-owned job. Побайтовый возврат всей Ubuntu без disk snapshot не заявляется; dependency packages по умолчанию сохраняются.

**Следующий шаг:** commit/push исправлений, новый exact double-build и повтор SSH/WG ON fresh install; затем SSH/WG OFF, idempotent reinstall, new-PID1/reboot и schema update/rollback gates. После стабилизации exact install lifecycle реализовать принятый WebUI uninstall orchestration.

### Сессия 098 — WireGuard secret sandbox и точный OpenSSH rollback — 2026-08-29

**Exact evidence до исправления:** source `b02d3a9b3d1c080846ce50d780990f0ac3ec8d0e` дважды offline собран как `0.1.0-successor.b02d3a9`; все 82 файла совпали побайтно. Disposable signer fingerprint `8231e4d382968a21611e59310a315f5b2f8f9010783abae17fe9cdd0dcf22af0`; SHA-256: Gateway `fc80d0d51d734aafb05bb59e1f110449d805fbce54f33579a31dc3905a466c73`, VPS `904dbf3ab69a7929a111d6947b692666123d088dadba2f8452343c0928ce421f`, bootstrap `ab25551053da304dcf0ed4e439710f11e245575ceca44f62fa1416e712245d87`, deploy `7d8330dbf2497887ea274171350a529c6b09d885bb9fd5aaaa47121e3221d27c`, channel `a12c8bfeeacdda2ee41453060f844d7d715a698b59dc4f3037e267d31240a399`. Production key, tag и Release не использовались.

**Что доказал fresh rehearsal:** clean-host OpenSSH package установился, фиксированный `/run/sshd` прошёл проверку, `sshd -t` и запуск `ssh.service` успешны. Requested UDP/51821 был корректно отклонён как занятый `wg-mgmt`, после явного выбора 51822 preflight продолжился. Затем broker не смог создать начальный `wg-ingress` key: unit одновременно имел read-only `/var/lib/gateway-vpn/secrets` и обязан был писать в его child. Изолированный systemd test доказал `BASELINE_READ_ONLY_PASS` и `NARROW_OVERRIDE_PASS`. Failed-install recovery восстановил `ssh.service`, но прежний 18-field marker не хранил состояние `ssh.socket`; socket остался enabled/active и занял TCP/22. Дополнительно обнаружено, что uninstaller принимал только 14/16-field marker и не возвращал новое log-reader membership.

**Исправлено:** tmpfiles заранее создаёт root-only ingress secret root, broker получает единственный более специфичный `ReadWritePaths` override; install проверяет type/owner/mode. Привилегированные ingress failures сохраняют operation и внутреннюю причину в journal без typed input/secret values, а API-код остаётся redacted. Новый 20-field marker сохраняет service/socket enabled+active, recovery и uninstall читают 14/16/18/20, точно восстанавливают известные состояния, допускают отсутствующий unit только для desired disabled/inactive, удаляют `wg-ingress` и возвращают добавленное членство `gateway-vpn-log-readers`. Active штатный `ssh.socket` теперь распознаётся preflight и не считается чужим TCP/22 listener.

**Проверено:** новые packaging regressions покрывают marker compatibility, service/socket restore contract, absent-unit branch, log-reader rollback, `wg-ingress` cleanup и narrow systemd boundary. Отдельный broker test подтверждает: private root cause присутствует в privileged log и отсутствует в public response. Полные serial `go test ./... -count=1 -p 1`, `go vet ./...`, Go format, JavaScript syntax для 8 файлов, Ubuntu shell syntax всех scripts/tests и `git diff --check` — PASS.

**Следующий шаг:** зафиксировать и отправить новый exact source, дважды воспроизводимо собрать disposable-signed bundle и повторить SSH/WG ON clean Ubuntu acceptance; затем выполнить SSH/WG OFF, idempotent reinstall, new-PID1/reboot и schema update/rollback gates. `b02d3a9` не является install-ready artifact.

### Сессия 097 — clean-host OpenSSH runtime regression — 2026-08-29

**Найдено на exact rehearsal:** две независимые offline-сборки `0.1.0-successor.4b97c7e` совпали побайтно, но первая fresh Ubuntu 24.04 установка с отсутствующим `openssh-server` остановилась после безопасного включения `PATH_BLOCKED` и установки пакета: `sshd -t` сообщил `Missing privilege separation directory: /run/sshd`. Поэтому этот exact artifact сразу исключён из install-ready candidates; production key, tag и GitHub Release не использовались.

**Проверка отказа и rollback:** Ubuntu unit содержит `RuntimeDirectory=sshd`/`RuntimeDirectoryMode=0755`, а пакет не поставляет отдельный tmpfiles rule. До первого запуска service каталог ожидаемо отсутствовал. Durable recovery удалил `/opt`, `/etc`, `/var/lib` и `/var/log` Gateway VPN и owned nftables table; установленный системный OpenSSH package намеренно сохранился, service остался disabled/inactive.

**Исправлено:** installer получил единый helper безопасной подготовки фиксированного `/run/sshd`; он проверяет real directory, root ownership и exact `0755`, не принимает путь из аргумента/конфига и используется всеми четырьмя config validation points. Preflight создаёт каталог только временно и удаляет только созданный им пустой directory, сохраняя исходное состояние host; apply оставляет runtime systemd service.

**Проверено:** focused test доказал clean-host temporary/persistent paths и успешный реальный `sshd -t`; symlink на `/tmp` и directory mode `0777` были отклонены. Packaging regression, полный serial `go test ./... -count=1 -p 1`, `go vet ./...`, Go format, JavaScript/shell syntax и diff check — PASS. Disposable failed container после сохранения evidence удалён; `open-webui` и build volumes не затронуты.

**Следующий шаг:** зафиксировать и отправить исправленный source commit, собрать два побайтно сравнимых disposable-signed bundles и повторить SSH/WG ON fresh systemd acceptance, затем отдельный SSH/WG OFF, idempotency, new-PID1/reboot и update/rollback gates.

### Сессия 096 — входящий WireGuard, тематические SFTP-логи и доступные подсказки — 2026-08-29

**Сделано:**

- migrations 23–24 добавили полный `wg-ingress` lifecycle и 17-й watchdog component `logging_pipeline`; schema текущего successor — 24;
- server/peer repository хранит immutable display numbers, assigned addresses, behind-subnets, client AllowedIPs, разрешённые access methods, runtime generation/handshake/counters и audit events; duplicate key/address/subnet/route conflicts отклоняются транзакционно;
- managed server/peer keys и PSK создаются атомарно в `/var/lib/gateway-vpn/secrets/wireguard-ingress`, имеют root-only contract и не попадают в SQLite/API/logs/diagnostics; external peer сохраняет только public key;
- root network broker создаёт `wg-ingress`, применяет `wg syncconf`, address/owned routes/listener set и fail-closes полуприменённый contour. Поддержаны ROUTED и SHARED_ONE_ARM, per-peer access policy, enable/disable, probe, revoke/delete и key rotation;
- authenticated WebUI/API получили отдельную вкладку WireGuard-клиентов: server/listener/topology settings, managed/external peers, policies, handshake/counters, готовый `.conf` и QR. Managed export требует текущий пароль и single-use grant; secret response имеет `no-store`;
- interactive first-install wizard предлагает optional входящий WireGuard, проверяет endpoint/subnet/listen port/DNS и передаёт typed flags install transaction; report и idempotency сохраняют выбор;
- canonical logging viewer разделён на десять allowlisted тематических tabs. Exporter делает второй redaction pass, atomic current files, daily archive, retention/file/total budget и безопасно отклоняет symlink/non-regular tree;
- installer создаёт `/var/log/gateway-vpn/{current,archive,diagnostics}` как `root:gateway-vpn-log-readers`, выдаёт выбранному обычному Ubuntu account только read-only group access и проверяет rollback/idempotency; отдельный SFTP daemon не добавлен;
- watchdog проверяет journald/export pipeline как 17-й fixed component; backup/restore отдельно доказывает наличие server key, managed peer key/PSK и отсутствие plaintext secrets в `.gvpn`;
- единый contextual-help слой сохраняет точные descriptions, заполняет старые формы, добавляет `aria-label` и нативную кнопку `?` для mouse/keyboard/touch.

**Проверено:**

- focused repository/backend/WebAPI/installwizard/bootstrap/logging/watchdog/backup/restore/firewall tests — PASS;
- полный Windows serial `go test ./... -count=1 -p 1`, `go vet ./...`, `gofmt -l`, JavaScript syntax и `git diff --check` — PASS после всех product/documentation изменений;
- privileged Ubuntu 24.04 netns: firewall guard/global flush recovery, startup policy, multi-LAN SSH/uplink isolation и настоящий server/client WireGuard handshake — PASS; revoke удалил peer из kernel, disable удалил `wg-ingress`;
- kernel gate нашёл и исправил product defect: `wg show <iface> dump` без peers содержит четыре interface fields, а не пять; добавлен regression path;
- Ubuntu 24.04 `systemd-analyze verify`, GRUB generation/check и полный Gateway/VPS unit graph — PASS;
- browser preview показал WireGuard UI, десять log tabs, category switching и ноль console warnings/errors. Последний gate дополнительно доказал: все 32 WireGuard controls имеют help; у всех mutable controls проверенной формы есть `title`/`aria-label`/кнопка `?`; справка открывается мышью и Enter, закрывается Space.

**Не проверено / открытые gates:** текущий schema-v24/firewall-v4 successor ещё не проходил exact disposable-signed fresh install/update/rollback/new-PID1 acceptance. Реальные OpenSSH/SFTP, WireGuard ingress client через Keenetic, one-card traffic loop/capture, physical Ethernet/HiLink, VPS/provider UDP, firmware/USB recovery, RTC S5 и 24/72h endurance остаются внешними gates.

**Следующий шаг:** source commit/push, затем disposable-signed Ubuntu 24.04 systemd rehearsal без production key/tag/Release.

### Сессия 095 — watchdog contour v2 и интерактивный SSH/SFTP installer — 2026-08-29

**Сделано:**

- migration 22 перевела watchdog policy на schema 2, сохранила прежние operator choices и добавила thresholds для workers, WireGuard handshake, backup/WAL, disk/memory и recovery modes всех 16 fixed components;
- root supervisor проверяет WebUI/API/control heartbeat, SQLite, firewall guard/ruleset, broker/networkd, DNS/DHCP, optional OpenSSH/SFTP, Mihomo/TUN, WireGuard management/ingress, policy routing, critical workers, configuration convergence, verified backup/WAL и resources;
- worker heartbeat получил typed per-worker progress/freshness; recovery ladder поддерживает `MONITOR_ONLY`, `RECONCILE`, `RESTART`, не принимает unit/command/path из DB/API и подавляет restart/reboot при `EXTERNAL_CONNECTIVITY_FAILURE`;
- WireGuard management health проверяет interface/address/peer/fwmark, `10.80.0.0/24 dev wg-mgmt protocol 186`, endpoint route и handshake. Controller исправлен: обязательный management route теперь создаётся идемпотентно;
- реальный Ubuntu 24.04 output выявил второй defect: `ip -N -json` кодирует protocol/table строками. Parser исправлен на строгую поддержку JSON number либо decimal string, добавлен regression test;
- interactive wizard получил отдельный default-on вопрос SSH/SFTP с показом текущих package/enabled/active состояний и понятным объяснением; automation default-on имеет явный `--disable-ssh` opt-out;
- при включении dependency plan добавляет `openssh-server`, installer выполняет `sshd -t`, `systemctl enable --now ssh.service`, enabled/active и IPv4 wildcard listener checks. Firewall открывает TCP/22 только через `gateway-vpn-lan`; config/install report сохраняют policy. При opt-out daemon/package не меняются, rule отсутствует, watchdog возвращает `NOT_APPLICABLE`;
- WebUI получил полный watchdog v2 editor/status. Browser preview расширен synthetic 16-component status и исправлен stale direct target fixture;
- визуальный gate обнаружил реальный overlap: absolute logout перекрывал кнопку «Система и безопасность» и отзывал session. Sidebar переведён на отдельный scrollable navigation + non-overlapping logout; длинный `RECOVERY_SUPPRESSED` больше не обрезается.

**Проверено:**

- focused watchdog/WebAPI/config/firewall/installwizard/bootstrap/distribution/backup/update/WireGuard tests — PASS;
- Linux schema `21 → 22`, clean schema 22 и migration idempotency — PASS;
- реальный privileged Ubuntu 24.04 WireGuard/dummy contour подтвердил фактические link/address/route/fwmark/marked-route JSON формы; parser regression — PASS;
- privileged offline netns: TCP/22 доступен через оба LAN bridge members, блокируется через uplink, а `disable_ssh_management: true` удаляет rule и блокирует все три пути при живом wildcard listener — PASS;
- Ubuntu 24.04 `systemd-analyze verify` полного Gateway/VPS graph и GRUB generation/check — PASS;
- локальный browser preview: все 16 компонентов, external WireGuard suppression, thresholds/modes/help titles, scrollable navigation и исправленный summary layout отображаются; console warning/error — 0;
- финальный полный offline Linux `go test ./... -count=1` и `go vet ./...`, format всех tracked Go-файлов, syntax всех WebUI JavaScript и project shell scripts, `git diff --check` — PASS.

Первая Linux-сборка netns binary ошибочно использовала пустой module cache при `--network none`; повтор с существующим project cache прошёл. Первый netns image не имел test-only Python listener; одноразовый слой с `python3-minimal` был создан для offline kernel gate. Оба эпизода не дошли до product assertions и классифицированы как test-environment defects. Первый реальный `ip -N -json` gate, напротив, нашёл product parser defect и привёл к исправлению до commit.

**Не проверено / открытые gates:** новый schema-v22 successor ещё не проходил exact signed fresh install/update/rollback/new-PID1 kill/hang acceptance; OpenSSH enable/opt-out не выполнялись на bare-metal Ubuntu с реальными LAN NIC; management WireGuard не проверен через реальный VPS/provider/HiLink. Полный `wg-ingress`, thematic log exports/tabs, оставшийся contextual help и 24/72h endurance остаются впереди.

**Следующий шаг:** зафиксировать и отправить schema-v22 increment; затем реализовать полный `wg-ingress` key/client/config/QR lifecycle и one-card routing gate. Tag/Release не создавать.

### Сессия 094 — Ethernet runtime, readiness и полный safe lifecycle — 2026-08-28

**Сделано:**

- migration 21 разделила persistent `configured_*` и фактические runtime address/gateway/DNS, добавила `readiness_reason` и совместимые HiLink triggers;
- Linux Ethernet observer использует stable salted permanent-MAC/topology identity, отслеживает hot-plug/hot-unplug, carrier, DHCP lease/static addressing, subnet conflicts и readiness;
- randomized/assigned MAC больше не считается постоянной identity: Linux `addr_assign_type` обязан быть `0`, иначе применяется topology path;
- authoritative routing reconciliation учитывает ready Ethernet и HiLink в общей priority модели, не оставляет прямой fallback route и инвалидирует только затронутую generation;
- DHCP observation сохраняет заданные пользователем DNS; WebUI раздельно показывает полученный адрес и редактирует persistent configuration;
- Ethernet enable/disable, priority, impact preview и safe `DELETE` подключены к API/WebUI. Удалить можно только disabled неактивный uplink; canonical DB row сохраняется до confirmation, timeout/reboot rollback восстанавливает owned networkd file, commit идемпотентен.

**Проверено:**

- `node --check` обоих Ethernet/app scripts, `git diff --check`, полный Windows `go test ./... -count=1` и `go vet ./...` — PASS;
- targeted Linux/amd64 tests через Docker `--network none` с локальным module cache — PASS для Ethernet, networkapply, uplink, DB и modem;
- Linux gate обнаружил и до commit исправил Linux-only compile defect в обработке `net.ParseCIDR`; повторный targeted run, включая permanent/randomized MAC test, прошёл;
- migration/backup/restore/update fixtures используют schema 21 и проходят; HiLink readiness triggers, configured/runtime DNS, mixed priority, safe-delete confirmation/rollback/commit и stale generation покрыты tests.

Первая offline Linux-попытка не дошла до compilation из-за отсутствия новых modules в image cache. Повтор использовал локальный проверенный `go.sum` cache при `--network none`; это ограничение disposable builder cache, не product failure.

**Не проверено / открытые gates:** реальные networkd DHCP/static lease, physical carrier/hotplug, замена NIC, route convergence и rollback на Ubuntu Gateway; signed schema 13→21 install/update/recovery; hardware HiLink/Keenetic path.

**Следующий шаг:** расширить root watchdog на WireGuard management, policy routing, worker freshness, configuration convergence и bounded storage checks; внешний Internet/VPS outage не должен запускать restart/reboot.

### Сессия 093 — safe Ethernet apply v2 и ручное управление питанием — 2026-08-28

**Сделано:**

- migration 19 расширила safe network transaction versioned manifest, operation kind и typed candidate metadata; legacy LAN apply backfill остаётся однозначным;
- Ethernet `CREATE`, `REPLACE_INTERFACE` и `UPDATE_ADDRESS` принимают stable `network_interface_id`, не доверяют ifname из HTTP/root socket, требуют свободную роль/expected generation и проверяют DHCP/static/CIDR/gateway/DNS/MTU/subnet conflicts;
- root backend сохраняет и восстанавливает только принадлежащие Gateway networkd files, применяет candidate через existing 60-second safe apply, после confirmation атомарно обновляет uplink/role generations и инвалидирует только затронутые paths;
- WebUI получил понятные формы создания Ethernet-выхода, переназначения карты и смены IP-режима со status/confirm/rollback flow;
- migration 20 и `internal/power` добавили durable `SYSTEM_POWER` operations, reboot/shutdown и optional RTC power-cycle с интервалом 30..3600 секунд;
- WebUI-карточка **Система и безопасность → Питание** показывает capabilities, требует текущий пароль, точную русскую фразу и даёт пять секунд на отмену; последняя операция и reconnect notice сохраняются;
- root broker принимает только `REBOOT`, `SHUTDOWN`, `RTC_POWER_CYCLE` и bounded delay; command, executable, unit и path через HTTP/SQLite не передаются;
- install/update/restore/network apply markers и transitional systemd units блокируют power. Завершённые `RemainAfterExit=yes` recovery units не блокируют питание навсегда; это закреплено регрессионным тестом;
- RTC-кнопка требует `rtcwake`, wakealarm, installed signed template и marker с точным содержимым после успешного физического wake-from-S5; mere detection отображается как **обнаружен, не проверен**;
- installer, recovery, uninstall и signed host contract включают `gateway-vpn-power-cycle@.service`; broker capability set расширен только `CAP_SYS_BOOT`.

**Проверено:**

- full Windows Go 1.26.7 и Linux/amd64 builder `go test ./... -count=1`/`go vet ./...` — PASS;
- power tests подтверждают typed bounds, unverified RTC suppression, fixed systemd dispatch, redacted executor errors, interrupted operation recovery, audit, mutual exclusion и отсутствие permanent block от completed recovery unit — PASS;
- Ethernet safe-apply tests подтверждают stable identity boundary, generation/role/subnet validation, snapshot/apply/rollback и API rejection переданного `interface_name` — PASS;
- `node --check` для `app.js`, `power.js`, `ethernet-network.js`, `modem-recovery.js`, `git diff --check` и полный OpenAPI/packaging suite — PASS;
- disposable Ubuntu 24.04 `bash -n` всех project shell scripts и `systemd-analyze verify` полного Gateway/VPS unit graph — PASS.

Первая Linux-попытка с `--network none` завершилась setup failure до compilation: используемый builder image не содержал обновлённый module cache. Повтор того же source с разрешённой загрузкой зафиксированных `go.sum` dependencies прошёл полностью; это test-environment cache miss, а не product failure.

**Не проверено / открытые gates:**

- реальные networkd DHCP/static lease, carrier loss, gateway/DNS observation, route/firewall convergence и rollback после reboot на Ubuntu host не запускались;
- RTC alarm и включение из S5 не проверялись на физическом Gateway, marker не создавался; Docker/VM этот hardware gate не закрывают;
- новый signed schema 13→20 update/rollback/install candidate не создавался, production key/tag/Release не использовались.

**Следующий шаг:** подключить generic Ethernet runtime observer и routing/firewall reconciliation, затем закрыть enable/disable/priority/delete и impact preview. После этого перейти к `wg-ingress`, тематическим логам/SFTP exports и contextual help.

### Сессия 092 — bounded physical modem recovery vertical slice — 2026-08-28

**Сделано:**

- добавлен самостоятельный `internal/modemrecovery`: durable policy/runtime/attempt repository, physical-only controller, coalescing runner, hysteresis, cooldown, USB reset window budget, policy generation и restart cleanup;
- HiLink reconcile теперь явно публикует только `DEVICE_ABSENT`, `CARRIER_DOWN` и `DHCP_LEASE_MISSING`; carrier + валидный DHCP lease считается физически здоровым даже при subnet/routing/global/VPN ошибке;
- отсутствие уже offline модема продолжает наблюдаться на каждом цикле, поэтому recovery timer не замерзает после первого disconnect; при reconnect физический episode сбрасывается;
- старый `SetRecovering`, который только менял legacy state и инвалидировал paths, удалён из production surface;
- root broker получил strict typed request `uplink_id + action + policy_generation`; backend повторно читает active attempt, HiLink/enabled/address mode/current ifname/carrier из SQLite и исполняет только `/usr/bin/networkctl renew <derived-ifname>`;
- произвольный interface/sysfs path/executable не принимается. HiLink API/mobile-session/driver rebind/USB reset/hub power-cycle возвращают `HARDWARE_ACTION_NOT_AVAILABLE` до реального E3372h profile gate;
- `GET/PUT /api/v1/modems/{id}/recovery`, расширенный modem DTO и отдельная WebUI-карточка показывают physical reason, policy, runtime, cooldown, durable budget и очищенную историю; ручная кнопка ничего не сбрасывает у физически исправного модема;
- каждая начатая/завершённая попытка и policy mutation создаёт redacted event; незавершённая попытка после process restart закрывается как `PROCESS_RESTARTED`, не обнуляя USB budget.

**Проверено:**

- non-physical `GLOBAL_TARGETS_FAILED` отклоняется recovery controller; healthy и absent-without-safe-action не создают reset attempt — PASS;
- DHCP hysteresis/manual action, exact broker tuple, rejection extra `interface`, stale generation, device/identity boundary и unsupported hardware suppression — PASS;
- interrupted RUNNING attempt, durable USB cooldown/window counter и recovery history после restart — PASS;
- authenticated recovery API, policy generation, modem DTO, WebUI JavaScript syntax и OpenAPI route parity — PASS;
- полный `go test ./...`, `go vet ./...`, targeted package suites, оба `node --check` и `git diff --check` — PASS; реальные Linux `networkctl`, Huawei firmware API и USB actions не запускались.

**Следующий шаг:** зафиксировать exact source commit и реализовать safe Ethernet mutation manifest v2 с snapshot/apply/confirm/rollback. Production key/tag/Release не использовать.

### Сессия 091 — canonical runtime, whitelist classifier и generic uplink WebUI — 2026-08-28

**Сделано:**

- migration 18 завершила generic runtime foreign-key boundary: `runtime_state`, periodic health и events используют authoritative uplink/path identity; legacy modem columns остаются только bounded read-only projection;
- path matrix, selector, state transitions, reconciliation, routing/firewall activation и events переведены на `UplinkID`; legacy modem fields заполняются только для `HILINK`;
- single Mihomo bundle строится из canonical `uplinks`: Ethernet получает настоящий interface/fwmark и квалифицируется без создания фиктивной строки `modems`;
- target policy разделена на `GLOBAL_REQUIRED`, `GLOBAL_OPTIONAL`, `WHITELIST_INDICATOR`, `SERVICE_ENDPOINT`; VPN не проверяет whitelist/service, direct хранит отдельные whitelist counters и классифицирует `WHITELIST_ONLY`;
- `FULL` ранжируется выше `LIMITED/WHITELIST_ONLY`; операторская whitelist-only доступность не запускает hardware recovery и не может быть выдана за полноценный Internet;
- добавлены authenticated `GET /api/v1/uplinks` и `GET /api/v1/network/interfaces`, explicit OpenAPI routes и новая вкладка «Физические выходы»; UI показывает HiLink/Ethernet, NIC roles, carrier/address/generations и общий path read model;
- API не выдаёт stable identity hashes, полный MAC, HiLink API secret ref или subscription secrets; Ethernet не проецируется как fake modem;
- ручная target-проверка принудительно обновляет direct evidence даже при ещё свежем старом результате; global targets дополнительно проверяют VPN, whitelist targets — только direct, service targets отклоняются из user-access scope;
- вкладка подписок использует generic uplink labels и показывает global/whitelist direct evidence для каждого физического выхода.

**Проверено:**

- Ethernet VPN path создаётся/квалифицируется Mihomo и активирует firewall по своему interface/fwmark; `active_modem_id` при этом остаётся пустым — PASS;
- whitelist/service target exclusion, `FULL > WHITELIST_ONLY`, repository persistence и manual direct-only trigger — PASS;
- uplink/NIC API authentication, OpenAPI route parity и adversarial redaction identity hash/full MAC/secret fields — PASS;
- fresh-evidence manual direct re-probe и взаимное исключение с periodic runner — PASS;
- `node --check internal/webapi/static/app.js`, полный `go test ./...`, `go vet ./...`, `git diff --check` и targeted generic runtime/API suites — PASS.

**Не завершено:** Ethernet create/replace/address changes намеренно не имеют прямых mutation endpoints: они должны войти в существующую safe network transaction с confirm/rollback. Node/periodic-health/WireGuard management projections ещё содержат modem-oriented compatibility labels. Bounded modem recovery, `wg-ingress`, thematic log UI/SFTP exports и полный contextual help остаются последующими vertical slices.

**Следующий шаг:** полный test/vet/diff audit и фиксация exact source; затем safe Ethernet mutation transaction либо, если её host plan требует отдельного redesign, bounded modem recovery vertical slice. Production key/tag/Release не использовать.

### Сессия 090 — расширенный successor и schema v17 generic uplinks — 2026-08-28

**Причина:** пользователь завершил обсуждение универсальных топологий и разрешил внести все согласованные изменения: Ethernet/HiLink uplinks, роли и замена NIC, direct-only whitelist indicators, bounded recovery, входящий WireGuard, тематические логи/SFTP и понятный contextual help.

**Сделано:**

- `PLAN_v1.1.md` приведён к единой терминологии `uplink × access method`; `FULL > LIMITED/WHITELIST_ONLY > FAILED`, uplink priority и отсутствие аппаратного recovery из-за операторских ограничений закреплены без modem-only противоречий;
- добавлена migration 17: `network_interfaces`, `interface_role_assignments`, `uplinks`, `hilink_modems`, generic subscription/direct path evidence, `active_uplink_id`, non-secret `wg-ingress` schema, durable modem recovery и bounded log-export policy;
- migration переносит каждый существующий HiLink в uplink того же ID, сохраняет прежние path/node/target IDs и runtime active/management identity; отдельная map фиксирует legacy modem→uplink;
- добавлен canonical `internal/uplink` repository: stable interface observation, создание DHCP/static Ethernet только на unused NIC, чтение общего списка и специализированного HiLink projection;
- replacement Ethernet NIC использует expected desired generation, переносит роль, повышает route generation, переводит uplink в `UPLINK_CONFIGURING` и делает только принадлежащие ему generic VPN/direct evidence `STALE`; метод явно требует внешней safe-apply transaction.
- добавлен временный database-owned compatibility bridge: legacy HiLink/modem/path/node/target/runtime writes атомарно отражаются в generic schema; generic Ethernet writes не копируются назад, а старые таблицы не получают отдельного UI/API;
- generic и legacy monotonic allocation counters взаимно поднимают безопасный floor, поэтому добавление Ethernet не создаёт будущий collision display number/routing table/fwmark при adoption нового HiLink.

**Проверено:**

- migration 16→17 с существующими HiLink, VPN/direct paths, node/target evidence и active runtime tuple — PASS;
- `PRAGMA foreign_key_check` после переноса — PASS;
- schema 17 fresh/idempotent/rollback tests — PASS;
- Ethernet create, collision/role/static-gateway rejection, HiLink projection и stale-generation NIC replacement — PASS;
- legacy insert/update/reorder/delete, path-state и runtime identity compatibility projection — PASS;
- targeted `internal/db`, `internal/uplink`, `internal/backup`, `internal/diagnostics` и `internal/update` suites — PASS после обновления schema contract 16→17.
- полный `go test ./...`, `go vet ./...` и `git diff --check` после compatibility bridge — PASS.

**Не завершено:** текущие selector/pathmatrix/reconciler/API всё ещё пишут legacy modem-specific таблицы. До их переноса generic schema не объявляется runtime source of truth, commit не становится install candidate и новый tag/Release не создаётся.

**Следующий шаг:** перевести modem compatibility adapter и path matrix writes на `uplinks`/generic paths, затем selector/runtime/API; после стабилизации реализовать whitelist classifier, recovery broker и `wg-ingress` вертикальными проверяемыми срезами.

### Сессия 089 — exact universal-installer successor достиг INSTALL_READY — 2026-08-28

**Точный candidate:**

- source commit: `1b90ffcb99b25f79954cbc1b4bde7bcc0140175d`;
- version: `0.1.0-successor.1b90ffc`;
- disposable signer SHA-256: `8231e4d382968a21611e59310a315f5b2f8f9010783abae17fe9cdd0dcf22af0`;
- Gateway archive: `3ca04ade0429a23e3bd4e18de7619164ada2eebaec6a63da339d49bd5fffb8e9`;
- VPS archive: `f91a305fcfd314b7c11b74c28a21e2ae0c5d09d84111bb9ec0f75c87087334f7`;
- bootstrap: `2ab6cd2c1249a2e740167076f7c16c51422055185909be7432d5b60ec692ebf2`;
- deploy: `570cec02ebbf9711fd69e2e61cd658f651789f807937f0b3b98ac75cc5833910`;
- channel manifest: `743a640904302d7ea095129831fd4dfcbcdfca26c5f446380692b03d4a39d788`.

**Reproducibility и remote gate:** две независимые clean/offline сборки с одинаковыми pinned inputs и одним disposable signer совпали побайтно. Exact source находится в `origin/main`; GitHub Actions run `33175739792` завершил `Go, packaging and syntax gates` и `Linux nftables fail-closed gate` со статусом `success`. Production `.gvkey` при сборке и acceptance не открывался, не перемещался и не подключался.

**Fresh Ubuntu 24.04 acceptance:** installer выбрал два LAN-порта `lan0,lan1`, создал owned bridge `gateway-vpn-lan` с `192.168.200.1/24`, включил DHCP, применил рекомендуемые non-blocking boot-network и hidden GRUB policies. Fresh apply завершил schema `16`, firewall schema `3`, `PATH_BLOCKED`, HTTPS/DNS/DHCP/SSH и control/watchdog readiness. Все проверенные managed services имели `NRestarts=0`; повтор exact команды завершился штатным idempotent success.

**No-network/new-PID1 gate:** отдельный boot не имел Docker network и физических `lan0/lan1`. `ConfigureWithoutCarrier=yes` перевёл bridge в `no-carrier (configured)`, сохранил management address и поднял control plane без ожидания кабеля, HiLink, DHCP или Internet. Owned wait-online policy выполнилась через `/usr/bin/true`; измеренный start — `167 ms`. Hidden GRUB timeout `1` сохранился, failed managed units и restart loops отсутствовали. Первая validator-выборка через 12 секунд штатно попала в окно watchdog hysteresis; после стабилизации полный validator прошёл, control всё время имел `NRestarts=0`.

**Forced rollback:** test-only watcher после начала install transaction подменил owned wait-online policy. Installer обнаружил несоответствие и завершился отказом; GRUB восстановлен побайтно, bridge/member policies удалены, SSH возвращён в исходное `disabled/inactive`, sysctl/firewall восстановлены, active marker отсутствует, failed units отсутствуют. Итоговый маркер проверки: `FINAL_FORCED_INSTALL_GRUB_MULTIPORT_ROLLBACK_PASS`.

**Итог:** требование «одна команда, понятный выбор для каждого компонента и безопасная отмена/rollback» внесено в §17.2 плана, реализовано и доказано exact remote/systemd acceptance. Local successor имеет статус `INSTALL_READY`. Public production successor ещё не создан; immutable `v0.1.0-successor.5723940` не изменялся.

**Следующий шаг:** только после отдельного разрешения использовать production key, подписать exact `1b90ffc`, создать новый immutable tag/GitHub Release и проверить published attestation. Затем — физическая установка Gateway/VPS и аппаратные H1/H2/endurance gates.

### Сессия 088 — единый понятный installer, GRUB и загрузка без ожидания сети — 2026-08-28

**Причина:** пользователь потребовал сохранить одну универсальную команду, но сделать понятный интерактивный выбор для каждого компонента установки. Отдельно требовалось убрать самопроизвольное GRUB-меню и исключить задержку Ubuntu из-за отсутствующего Ethernet, медленного/зависшего HiLink или недоступного Internet.

**Реализовано локально:**

- §17.2 `PLAN_v1.1.md` закрепляет единый human-readable contract: обнаруженное состояние, объяснение простыми словами, рекомендация с причиной, последствия альтернатив, позднее изменение, `q` без mutation и exact `INSTALL` после полного mutation plan;
- мастер разделён на «Нужно выбрать сейчас», «Будет настроено автоматически для безопасности» и «Можно изменить после установки в WebUI»; hardware/policy choices покрывают несколько LAN ports, DHCP, свободный CIDR, dependencies, boot-network и GRUB;
- wizard определяет GRUB/UEFI/Legacy; для одной Ubuntu рекомендует hidden timeout, при Windows boot entry скрытый вариант не предлагает и рекомендует меню 5 секунд, неизвестный загрузчик сохраняет без изменений;
- owned GRUB drop-in задаёт Ubuntu default, hidden timeout `1s`/recordfail `0` либо visible menu `5s`; installer проверяет existing/generated `grub.cfg`, отказывается скрывать Windows, а recovery/uninstall удаляют только owned drop-in и повторно выполняют `update-grub`/`grub-script-check`;
- Gateway control plane и Mihomo больше не зависят от `network-online.target`; LAN bridge/members и HiLink имеют `RequiredForOnline=no`;
- рекомендуемая boot policy заменяет `systemd-networkd-wait-online` на owned immediate-success drop-in `/usr/bin/true`; `systemd-networkd` продолжает в фоне принимать hotplug и DHCP. Альтернатива `keep` не меняет Ubuntu wait-online;
- automation mode получил обязательные typed `--boot-network-policy` и `--grub-policy`; deploy передаёт no-wait + GRUB keep явно;
- install report и durable marker расширены двумя policy fields; recovery/uninstall сохраняют совместимость со старыми 14-field markers и новыми 16-field markers;
- `host_contract_sha256` теперь связывает pointer-only update не только с systemd, но со всеми root-owned lifecycle assets: networkd, wait-online, GRUB, nftables, sysctl, journald, dnsmasq, sysusers/tmpfiles и recovery helper.

**Найдено и исправлено проверкой:** первоначальный `systemd-networkd-wait-online --interface=gateway-vpn-lan:off --timeout=10` на настоящем Ubuntu 24.04 PID 1 без сети ждал ровно 10 секунд и завершался failure, поскольку bridge оставался `configuring/no-carrier`. Этот вариант удалён. Owned `ExecStart=/usr/bin/true` повторно завершил service как `active/success` за `19 ms`, хотя bridge оставался без carrier; именно это требуемая appliance-семантика.

**Проверено:** full `go test ./... -count=1`, `go vet ./...`, четыре CGO-free Linux/amd64 builds, Node/shell syntax и `git diff --check` — PASS. Disposable Ubuntu 24.04 `systemd-analyze verify` принял все Gateway/VPS units и no-wait drop-in. Штатные `update-grub` и `grub-script-check` успешно сгенерировали/проверили hidden, menu и rollback конфигурации; из-за Docker overlay storage использован детерминированный test-only `grub-probe`, поэтому реальный disk/UEFI NVRAM остаётся bare-metal gate.

**Первый exact CI и исправление:** GitHub Actions run `33170851364` для `fc8f542` прошёл format, но Linux-only `TestChannelCommandsSignVerifyAndGeneratePinnedGatewayCommand` обнаружил, что `gateway-vpnctl channel-install-command` ещё не объявлял/передавал два новых обязательных automation flags. Windows suite не мог увидеть этот тест, потому что release private-key CLI намеренно Linux-only. CLI получил typed flags, early validation и передачу в generator; точный упавший test, полный `go test -race ./...` и `go vet ./...` прошли в disposable `golang:1.26.7-bookworm`. Первый run сохраняется как failed evidence.

**Exact CI исправления:** commit `6b1b51bb4b4be568e50139926903f952856cfaad` отправлен в `origin/main`; GitHub Actions run `33171987634` завершился `success`. Отдельно прошли `Go, packaging and syntax gates` и `Linux nftables fail-closed gate`. Это подтверждает полный контракт мастера установки, обязательную передачу boot/GRUB policies и неизменность fail-closed data plane.

**Journal CI:** следующий docs-only commit `678420ce8177912839af821d520198a25ba55db9` также прошёл exact GitHub Actions run `33172397680`: Go/packaging и Linux nftables jobs завершились `success`.

**Signed fresh-install defect и исправление:** exact `678420c` дважды offline собран с disposable signer `8231e4d382968a21611e59310a315f5b2f8f9010783abae17fe9cdd0dcf22af0`; все файлы двух `dist` совпали побайтно. Fresh Ubuntu 24.04 dry-run и dependency plan не сделали mutation, apply установил dependencies, PATH_BLOCKED, GRUB policy и management runtime, но финальная проверка ложно отвергла побайтно одинаковый wait-online drop-in. Transaction штатно откатила release, services, owned policy и GRUB. Причина — Bash glob semantics у `[[ left == $(cat right) ]]` для `[Service]`; тем же дефектом была затронута idempotency-проверка `[NetDev]`. Все file-to-file проверки заменены на `cmp -s --`, `cmp` добавлен в preflight, а packaging test запрещает прежний класс сравнения. Focused и full Linux `go test -race`, `go vet`, shell syntax и `git diff --check` прошли.

**Второй exact gate и no-carrier defect:** fix commit `653650fca9d238aa765ffb15371695c89a404d1f` прошёл GitHub Actions `33174026324`. Его signed bundle дважды совпал побайтно; fresh Ubuntu multi-port install `lan0,lan1 → gateway-vpn-lan`, full systemd validator и exact idempotency прошли. Новый PID 1 без Docker network создал bridge и не задержал `systemd running`, но networkd оставил статический LAN IP неназначенным до carrier; required HTTPS bind перезапускался. Это не wait-online defect, а отсутствие `ConfigureWithoutCarrier=yes` в LAN `.network`. Test-only применение обновлённого шаблона немедленно перевело bridge в `no-carrier (configured)`, назначило `192.168.200.1/24` и подняло control plane. Политика и packaging regression обновлены; candidate `653650f` не продвигается. Full Linux `go test -race`, `go vet`, shell syntax и `git diff --check` прошли.

**Release boundary:** immutable public `v0.1.0-successor.5723940` не менялся и не содержит эту доработку. Successor зафиксирован и exact-CI проверен, но ещё не подписан production key и не опубликован отдельным tag/Release.

**Следующий шаг:** commit/push no-carrier policy fix, дождаться exact CI, собрать новый disposable-signed successor и с нуля повторить Ubuntu 24.04/systemd install, no-network boot, idempotency, forced rollback, GRUB apply/rollback и reboot. Новый production tag/Release требует отдельного разрешения пользователя.

### Сессия 087 — immutable public Release и GitHub attestation — 2026-08-28

**Разрешение и publish transaction:** пользователь отдельно разрешил публикацию уже проверенного GitHub draft. Перед единственной publish transaction повторно сверены exact tag, source commit, полный список из `10` assets, их GitHub `sha256:` digests и включённая repository release immutability. Draft `RE_kwDOUEBVKs4WjKch` опубликован как Release ID `378316577`, `draft=false`, `immutable=true`, latest; время публикации `2026-08-28T07:31:19Z`. Public URL: `https://github.com/Go4a4a/Gateway-VPN/releases/tag/v0.1.0-successor.5723940`. GitHub UI явно показывает `Immutable release`; изменяемыми остаются только title и notes.

**Public post-publish audit:** public REST metadata соответствует repository, exact tag и Release ID. Remote dereferenced tag остаётся строго `57239401732c18822729499656801b994d627477`. Ровно `10` публичных assets повторно скачаны и сопоставлены с signed build1: суммарно `52934269` байт, каждое имя, size и SHA-256 совпали, итог `PUBLIC_DOWNLOAD_BYTE_IDENTICAL_PASS`. Ключевые digests: Gateway `c4ff94175081de8f6869d14ce3e001faab9517e096eb6fd37651cbb7e9794093`, VPS `58c337301c267725b6bdde1efdd53700245c97a6ab24b730474601f0aa0be809`, bootstrap `aa76dccb62719cea4b4fbf33ecd7f4c3b6cfd9cacf14e82c49cb99bf50b47deb`, deploy `4e91bba7fd32c6c3efec8de1f2f902786c05d6814cf667a6fec92265998dd134`, channel `b978f1973866be6f07ebfc32f6ff2089e987cdc75116700165e54b31467dcd00`.

**GitHub cryptographic attestation:** официальный portable `gh v2.98.0` повторно загружен и проверен по SHA-256 `c28c7b3b584967a05b74d9eaf7481bff24ddc34930bf2d6e442c148236561eb1`. После самостоятельно подтверждённого пользователем device login команда `gh release verify` подтвердила in-toto release predicate для `Go4a4a/Gateway-VPN`, tag `v0.1.0-successor.5723940` и database ID `378316577`; certificate SAN — `https://dotcom.releases.github.com`, verified TSA timestamp — `2026-08-28T07:31:20Z`. Каждый из `10` заново скачанных файлов отдельно прошёл `gh release verify-asset`; локальный SHA-256 каждого файла равен attested subject digest. Итог — `RELEASE_ATTESTATION_ALL_ASSETS_PASS`.

**Диагностика и очистка:** первый canary официального CLI корректно остановился до verification с требованием `gh auth login`; это отсутствие локальной CLI-сессии после предыдущей очистки, а не ошибка Release. После нового device login token не выводился и использовался только из изолированного CLI credential context. По завершении выполнен `gh auth logout`, unauthenticated status подтверждён, portable CLI, скачанные public assets и временный auth/config каталог удалены. Production `.gvkey` не читался, не перемещался, не удалялся и не монтировался; сохранённые signed build/signer/module-cache volumes не изменялись.

**External evidence:** release-attestation journal commit `c776f04290160feb23761a2d06888064709d3822` отправлен в `origin/main` и прошёл exact GitHub Actions run `33152806661` со статусом `success`. Go/packaging/race/vet, Linux nftables fail-closed, startup-policy, multi-port LAN SSH и Ubuntu 24.04 systemd gates завершились успешно. Immutable tag и Release assets не изменялись.

**Следующий шаг:** перейти к интерактивной one-command установке на физический Ubuntu 24.04 Gateway и реальный VPS Ubuntu 20.04+ по `docs/OPERATIONS.md`; hardware, реальный HiLink/Keenetic packet path и 24/72-часовые endurance остаются обязательными внешними gates и пока не считаются выполненными.

### Сессия 086 — exact tag и verified GitHub draft — 2026-08-28

**Разрешение и граница:** пользователь отдельно разрешил создание/push exact tag и GitHub draft Release. Публикация draft, изменение visibility и изменение repository security settings не разрешались и не выполнялись. Production `.gvkey` не читался, не расшифровывался и не монтировался.

**Tag transaction:** перед записью local tag/release и remote tag/release endpoints возвращали отсутствие. Создан annotated tag `v0.1.0-successor.5723940`; dereferenced local и remote tag равен только `57239401732c18822729499656801b994d627477`, а не docs-only `main`. Первая попытка push не выполнила remote write: PowerShell исказил составной refspec до `refs/tags//tags/...`; повтор через literal `git push origin tag v0.1.0-successor.5723940` успешно создал remote tag.

**Publisher authentication:** официальный portable GitHub CLI `v2.98.0` загружен из GitHub Release. Windows archive проверен по SHA-256 `c28c7b3b584967a05b74d9eaf7481bff24ddc34930bf2d6e442c148236561eb1`, Linux archive — `3b8ac6b30336802fc1a858d7c084e11cdf24ac1a761ca90b68022d7d729208de`. Пользователь самостоятельно завершил GitHub device login как `Go4a4a`; token не выводился и не записывался в проект. После проверки draft CLI OAuth-сессия удалена, portable cache очищен.

**Clean publisher:** canonical build1 имеет ровно `10` top-level asset files и `2` уже распакованных signed release trees. Финальный publisher volume содержал clean detached checkout exact tag, byte-identical build1 и проверенный Linux `gh`; staging выполнялся без сети и с dropped capabilities. External publisher container имел read-only checkout/assets/root/module cache, `GOPROXY=off`, disposable RAM-only Go cache/workspace, no-new-privileges и эфемерный `GH_TOKEN`. Штатный `scripts/create-github-release-draft.sh` заново собрал verifier из exact source и подтвердил Gateway `47` файлов, VPS `17` файлов и channel `validation` с `4` artifacts; signer везде `8231e4d382968a21611e59310a315f5b2f8f9010783abae17fe9cdd0dcf22af0`.

**Draft result:** создан только GitHub draft `RE_kwDOUEBVKs4WjKch`, title `Gateway VPN 0.1.0-successor.5723940`, tag `v0.1.0-successor.5723940`, `publishedAt=null`. Draft содержит ровно `10` assets; независимый post-upload audit сопоставил каждое имя, size, `uploaded` state и GitHub `sha256:` digest с локальным signed build — `POST_UPLOAD_ASSET_DIGEST_AUDIT_PASS`. Notes содержат полный exact source commit. Authenticated endpoint `GET /repos/Go4a4a/Gateway-VPN/immutable-releases` с API `2026-03-10` вернул `200 {"enabled":true,"enforced_by_owner":false}`. После будущей публикации tag/assets будут защищены immutability; сейчас draft остаётся изменяемым и скрытым.

**Неуспешные диагностические шаги:** первый staging volume остановился при распаковке Linux `gh`, потому что archive uid/gid требовали запрещённый `chown`; `--no-same-owner` исправил environment issue. Затем выяснилось, что build1 уже содержит распакованные release trees: повторная распаковка добавила пять top-level файлов, поэтому polluted volume был отвергнут и заменён новым clean volume. Первый publisher container остановился до verifier из-за отсутствующего RAM `GOTMPDIR`; исправленный запуск создал каталоги заранее и явно передал Docker exit code PowerShell. REST lookup draft по tag вернул `404`; `gh release view`/GraphQL, используемый publisher-ом, корректно показал hidden draft и asset digests. Ни один из этих запусков до успешного publisher не создавал partial Release или не менял signed assets.

**Очистка:** удалены только два временных publisher volumes и portable `gh` cache. Сохранены `gvpn-xhigh-dist-5723940`, `gvpn-xhigh-signer-66d0d09`, `gvpn-xhigh-gomod-66d0d09`, release Go caches и production `.gvkey`.

**Следующий шаг:** требуется отдельное явное разрешение пользователя на публикацию уже проверенного draft. Перед publish повторно read-only сверить exact tag/draft/10 digests/immutability, затем выполнить одну publish transaction, проверить public URLs и immutable attestation. Только после immutable public Release запускать one-command установку на физический Ubuntu 24.04 Gateway и реальный VPS Ubuntu 20.04+ по `docs/OPERATIONS.md`.

### Сессия 085 — exact-source offline publisher verification — 2026-08-28

**Граница полномочий:** отдельного разрешения на создание/push release tag и GitHub draft ещё нет, поэтому GitHub и локальные tags не изменялись. Проверка выполнялась только над существующим signed candidate; production `.gvkey` не читался и не монтировался.

**Повторная custody-проверка:** рабочее дерево чистое; diff от signed source commit `57239401732c18822729499656801b994d627477` до текущего `main` содержит только `docs/PROJECT_STATUS.md`. В read-only volume две независимые сборки по-прежнему имеют одинаковые `artifacts.sha256`, `artifacts.meta` и побайтно одинаковый `dist`; build1 содержит ровно `10` publisher assets. Повторно подтверждены SHA-256: Gateway `c4ff94175081de8f6869d14ce3e001faab9517e096eb6fd37651cbb7e9794093`, VPS `58c337301c267725b6bdde1efdd53700245c97a6ab24b730474601f0aa0be809`, bootstrap `aa76dccb62719cea4b4fbf33ecd7f4c3b6cfd9cacf14e82c49cb99bf50b47deb`, deploy `4e91bba7fd32c6c3efec8de1f2f902786c05d6814cf667a6fec92265998dd134`, channel `b978f1973866be6f07ebfc32f6ff2089e987cdc75116700165e54b31467dcd00`.

**Exact-source gate:** отдельный container работал с `--network none`, read-only root/source/signed bundle/module cache, без capabilities и с `no-new-privileges`. Source получен через `git archive` exact commit, verifier собран один раз в disposable RAM-only workspace и затем независимо проверил: Gateway release `47` файлов, VPS release `17` файлов и channel `validation` с `4` artifacts. Во всех трёх результатах signer равен `8231e4d382968a21611e59310a315f5b2f8f9010783abae17fe9cdd0dcf22af0`; итог — `EXACT_SOURCE_OFFLINE_VERIFIER_PASS`.

**Неуспешные диагностические запуски:** первая bundle-команда была перехвачена PowerShell из-за `$(...)` внутри double-quoted Linux command и не выполнила assertions; повтор с literal quoting прошёл. Первые три exact-source containers остановились до product verification из-за неверного default `GOPATH` при read-only root, недостаточного 64 MiB Go work directory и Docker tmpfs `noexec`. Финальный запуск использовал явные `GOPATH`, `GOTMPDIR`, 2 GiB RAM workspace и `exec`; ни один промежуточный запуск не изменял source, bundle или host network.

**Следующий шаг:** требуется отдельное явное разрешение пользователя на создание и push exact tag `v0.1.0-successor.5723940` и GitHub draft Release. Draft не публиковать автоматически; после создания повторно сверить remote tag, полный asset list, hashes/signatures и repository immutability перед ручной публикацией.

### Сессия 084 — High mode и read-only pre-publication audit — 2026-08-28

**Режим:** пользователь явно подтвердил возврат `xhigh → High` после завершения signed fresh-install/kernel gate; работа продолжена с install-ready состояния без повторения уже пройденных Docker checks.

**GitHub namespace:** публичный `Go4a4a/Gateway-VPN` активен, default branch — `main`; exact tag `v0.1.0-successor.5723940` и соответствующий GitHub Release/draft отсутствуют. Никаких внешних записей, tag, draft или asset upload в этой сессии не выполнялось.

**Fixed asset gate:** read-only build1 содержит ровно все `10` обязательных publisher assets как regular non-symlink files: Gateway/VPS archives, bootstrap, deploy, deploy SPDX/in-toto, `channel-validation.json/.sig`, `update-signing.pub` и universal interactive Gateway command. Published hashes повторно совпали: Gateway `c4ff9417…`, VPS `58c33730…`, bootstrap `aa76dccb…`, deploy `4e91bba7…`, channel `b978f197…`; command закрепляет signer `8231e4d3…`, source `57239401732c18822729499656801b994d627477` и не содержит конкретного NIC/CIDR/DHCP выбора.

**Важный publication contract:** immutable release tag обязан указывать ровно на signed source commit `57239401732c18822729499656801b994d627477`, а не на более новый docs-only `main` commit. `create-github-release-draft.sh` должен запускаться из отдельного clean checkout exact tag, повторно verify Gateway/VPS/channel и только затем создавать `--draft --verify-tag`. Текущая Windows shell не содержит `gh`/`GH_TOKEN`; browser login не считается неинтерактивным publisher credential и не извлекается автоматически.

**Hardware handoff:** `docs/OPERATIONS.md` уже содержит обязательные H1/H2 topology, exact identity/install, modem/subscription matrix, bounded sensitive PCAP, IPv4/DNS/IPv6 leak gate, failure matrix, VPS/WireGuard, traffic accounting, 24h/72h и обезличенную таблицу результата. Gate начинается только после versioned immutable GitHub Release; локальный disposable bundle на физический Gateway не переносится.

**Следующий шаг:** требуется отдельное явное разрешение пользователя на создание и push exact tag и GitHub draft Release. Публикация draft остаётся отдельным ручным действием после проверки repository release immutability и полного списка assets.

### Сессия 083 — exact signed fresh install, новый PID 1 и kernel acceptance — 2026-08-28

**Exact scope:** read-only build1 `0.1.0-successor.5723940` из volume `gvpn-xhigh-dist-5723940`; source commit `57239401732c18822729499656801b994d627477`, signer `8231e4d382968a21611e59310a315f5b2f8f9010783abae17fe9cdd0dcf22af0`. Production `.gvkey` не читался и не монтировался. Текущий evidence commit `0dd18dd736a8e716d5bdc6ae66a1acd111471869` отличается от source candidate только `docs/PROJECT_STATUS.md`; exact CI `33130137658` для него — `success`.

**Очистка перед gate:** после read-only фиксации прежних успешных systemd параметров удалены только устаревшие ресурсы Gateway VPN: `104` containers, `12` volumes, `2` networks и `38` image tags. Сохранены candidate/signer/module-cache volumes, release Go caches, pinned builder и Ubuntu 24.04 dnsmasq base. `open-webui`, `practical_margulis` и прочие чужие ресурсы не изменялись.

**Fresh install:** новый privileged Ubuntu 24.04 systemd container имел только dummy `lan0`, read-only candidate mount, private cgroup namespace и tmpfs `/run`. Первый dry-run корректно остановился из-за отсутствующего `openssh-server` без изменений. Dependency-preflight попал в предусмотренный empty-index/code-10 путь; apply сам выполнил `apt-get update`, повторно доказал план `7 new / 0 upgrades / 0 removals`, скачал OpenSSH до активации firewall, затем установил late packages уже после `PATH_BLOCKED`. Install завершил schema `16`, firewall schema `3`, HTTPS/SSH/DNS/DHCP, watchdog и broker; Mihomo остался выключен без validated active generation.

**Idempotency и reboot:** повтор exact installer command с теми же LAN/DHCP параметрами завершился `already installed with the requested immutable release and LAN policy`. Tracked `test/release-gate/validate_gateway_systemd.sh` дважды выдал `GATEWAY_SYSTEMD_RELEASE_GATE_PASS`: сразу после apply и в новом PID 1 fixture из committed installed rootfs `sha256:4bf205d1efd47245f7fee563661d64c51ba0ddb38ee65c4e4fa4400939450a5e`. На новом boot systemd — `running`, failed units отсутствуют, `NRestarts=0` для control/watchdog/firewall-guard/broker/dnsmasq, SQLite `quick_check`/`integrity_check` — `ok`, foreign-key violations отсутствуют, runtime — `ALL_MODEMS_OFFLINE / PATH_BLOCKED`.

**Kernel/netns:** exact signed production binary SHA-256 `d4f12ac7e74b3db645f87cc5db91a2b831686666b10605743d9f3ee0bfc55f2b`; test-only dataplane/app binaries — `845491574407eb2c4c3de710bf650da92fdb16a0f02db62ddeaba59d3293d49f` и `161325c982724914f63cd5455d5bb77cb22f648111c40f7d9384124f02a5d6e6`. Firewall recovery/no-direct-route, startup gate/exact-LKG/same-boot/next-boot и multi-port LAN SSH/uplink isolation — PASS в отдельном privileged `--network none` container.

**Неуспешные/диагностические шаги:** первый netns запуск в установленном host остановился до product assertions с `RTNETLINK ... File exists`, потому что harness временно создаёт собственный `lan0`; тест перенесён в чистый root namespace без изменения working Gateway. Test-only `ping/python3` не входят в production dependencies: попытка APT после boot получила DNS failure из-за работающего `PATH_BLOCKED`, после чего пакеты были доставлены offline из отдельного helper container. Это не меняет production dependency contract.

**Итог:** exact reproducible signed successor достиг локального `INSTALL_READY`. Public tag/GitHub Release, физический Gateway, реальный VPS/provider UDP, HiLink/Keenetic packet capture, USB hotplug/failover и 24/72h endurance не выполнялись и не считаются завершёнными.

**Следующий шаг:** только после отдельного разрешения создать immutable Git tag/GitHub Release для exact candidate; затем выполнить интерактивную установку на физический Ubuntu 24.04 Gateway и реальный VPS по hardware runbook.

### Сессия 082 — reproducible signed successor 5723940 — 2026-08-28

**Exact candidate:**

- source commit: `57239401732c18822729499656801b994d627477`;
- version: `0.1.0-successor.5723940`, Mihomo `v1.19.30`, schema `1..16`;
- signer SHA-256: `8231e4d382968a21611e59310a315f5b2f8f9010783abae17fe9cdd0dcf22af0`;
- host contract: `db8de3d29a520938f98f2a24baa304b75875ba3606d7fd3c0bb0b267f5eeaa41`;
- Gateway archive: `c4ff94175081de8f6869d14ce3e001faab9517e096eb6fd37651cbb7e9794093`;
- VPS archive: `58c337301c267725b6bdde1efdd53700245c97a6ab24b730474601f0aa0be809`;
- bootstrap: `aa76dccb62719cea4b4fbf33ecd7f4c3b6cfd9cacf14e82c49cb99bf50b47deb`;
- deploy: `4e91bba7fd32c6c3efec8de1f2f902786c05d6814cf667a6fec92265998dd134`;
- channel manifest: `b978f1973866be6f07ebfc32f6ff2089e987cdc75116700165e54b31467dcd00`.

**Сборка и custody:** две отдельные containers клонировали clean read-only worktree в разные writable layers, имели `--network none`, `GOPROXY=off`, read-only pinned module cache и read-only disposable signer volume. Production encrypted `.gvkey` не открывался, не перемещался и не подключался. Результаты сохранены раздельно в `gvpn-xhigh-dist-5723940/build1` и `build2`; signer volume пока не удаляется.

**Проверено:** `artifacts.sha256`, `artifacts.meta` и recursive tree сравнение совпали для всех `78` файлов. Canonical `release-verify`, `vps-release-verify` и `channel-verify` повторно прошли из read-only build1; release trees не содержат symlink/device/FIFO/socket, полный dist не содержит PEM private-key marker, generated one-command не кодирует интерфейс/CIDR конкретного Gateway.

**Не заявляется:** candidate ещё не установлен на fresh Ubuntu systemd host, strict idempotency и новый PID 1 не проверены. Двойная сборка и signature verification не заменяют installer/runtime acceptance.

**Следующий шаг:** после явного разрешения privileged Docker — fresh dry-run/apply/idempotency, tracked `validate_gateway_systemd.sh`, новый PID 1/reboot и kernel gate; после PASS удалить старые containers/images/volumes и тяжёлые `.tools`, сохранив production `.gvkey` и необходимый signer до завершения gates.

### Сессия 081 — remote kernel startup-policy gate и завершение локального DoD — 2026-08-28

**Реализовано:**

- Linux-only `internal/app` integration test использует реальную schema-16 SQLite fixture и production `dataplane.FirewallBackend`/`RoutingBackend` с фиксированными `/usr/sbin/nft` и `/usr/sbin/ip`;
- `test/netns/startup_policy.sh` создаёт отдельные Gateway/client/modem namespaces, `lan0`, `wan0` и dummy TUN, не меняет host ruleset и удаляет всё через trap;
- четыре process phase доказывают: gate ON инвалидирует старое evidence и оставляет DB/kernel blocked; gate OFF допускает только прежний exact direct LKG, создаёт только marked modem table и открывает `wan0+0x1101`; restart в том же boot сохраняет exact active tuple и temporary direct-only; следующий boot снова применяет boot firewall, сбрасывает direct-only и возвращает `PATH_BLOCKED`;
- CI собирает отдельный `internal/app` test binary и запускает новый сценарий после прежнего firewall guard; packaging test и netns README фиксируют обязательный contract.

**Проверки:** full Windows `go test ./... -count=1`, `go vet ./...`, Linux/amd64 app-test cross-compile и vet, `gofmt`, Git Bash `bash -n`, `git diff --check` — PASS. Commit `3ada2ae7fec1699b21234505f7a01c4100b3c212` опубликован в `main`.

**Неуспешный запуск:** exact run `33128409761` прошёл race/build и прежний firewall gate, но новый файл имел Git mode `100644`, поэтому runner завершил шаг до выполнения с `sudo: ... command not found`. Runtime и kernel assertions в этом run не запускались. Mode-only commit `e5b5e7c456f0c40adba23f242dc3ed31d16b70fa` установил `100755`.

**Авторитетный результат:** exact run `33128823746` завершён `success`: race suite, vet, release builds, shell syntax, firewall delete/global-flush recovery, новый startup-policy boot/process gate, multi-port LAN SSH isolation и pinned Ubuntu systemd verification прошли. DoD 28 повышен в `PASS_LOCAL`; исправлен старый арифметический итог матрицы на `15 PASS_LOCAL / 0 IN_PROGRESS_LOCAL / 11 PARTIAL_EXTERNAL / 2 NOT_RUN_EXTERNAL`.

**Следующий шаг:** новый signed candidate exact текущего clean tree → fresh Ubuntu 24.04 apply/idempotency/new-PID1 validator/kernel acceptance. Этот шаг требует отдельно разрешённого privileged Docker запуска; tag/GitHub Release не создавать.

### Сессия 080 — xhigh signed successor, update recovery и test harness — 2026-08-28

**Точный candidate:**

- product commit: `9301e0581b879bfb2ecf05af9e4e1e40142f23af`;
- version: `0.1.0-successor.9301e05`, Mihomo `v1.19.30`, schema `1..16`;
- signer SHA-256: `8231e4d382968a21611e59310a315f5b2f8f9010783abae17fe9cdd0dcf22af0`;
- host contract: `db8de3d29a520938f98f2a24baa304b75875ba3606d7fd3c0bb0b267f5eeaa41`;
- Gateway archive: `cfa72be651ea0fd03e108052128598fb29c902821110b996407bea21ccdf87e7`;
- VPS archive: `afaa286c1ec77f014ab6948f28765511bbc1ac13f10c903b879fd008f0b712e8`;
- bootstrap: `4c1acf859a30f03cddf9a782a0703e93f2bbcc853c1fe704d1779eb421b7b0a9`;
- deploy: `ddee5835b3080e62fcaef2a14a06d6182af50e00c4f3e1f7b13c6a6564c46eba`;
- channel: `92238a368b0eeb517d190a94cd93916a4bf2244cac8732b9bbc481c2d59e2bfd`;
- две независимые clean/offline Linux-сборки совпали по SHA-256, Unix mode и size всех `78` файлов.

**Найдено и исправлено xhigh gates:**

- candidate `4038525` доказал, что повторные штатные fail-closed firewall/guard restarts могут накопить systemd `start-limit-hit`; commit `35d2d06` добавил scoped reset только этих owned units непосредственно перед atomic restart;
- повторный candidate `35d2d06` дошёл дальше и выявил тот же счётчик у `gateway-vpn-network-recovery.service` и managed runtime dependencies; commit `9301e05` после уже установленного `PATH_BLOCKED` сбрасывает только fixed owned runtime set, затем по-прежнему требует настоящий start и три health observations;
- fresh installer с пустыми APT indexes и Windows admin-key path через symlink-parent были исправлены ранее в `4038525`; ни один rejected candidate не назначен install-ready.

**Exact update/rollback evidence:**

- честная test-only schema-13 baseline `0.1.0-baseline.13.fixed9301e05` построена из исторического schema-13 дерева с backport только двух updater start-limit fixes; это fixture, не release;
- controlled candidate-health rejection завершился `ROLLED_BACK / NEW_RELEASE_HEALTH_FAILED`: `current`/`recovery` на baseline, live schema `13`, `quick_check=ok`, foreign-key rows `0`, staging очищен, `PATH_BLOCKED`, managed services active, `NRestarts=0`, failed units отсутствуют;
- successful transaction `update-20260827T231151Z-61402155e4441acce26a5395` мигрировала `13 → 16`, сохранила `16` migration records, `quick_check=ok`, foreign-key rows `0`, candidate current и baseline recovery в `STABILIZING`;
- ранний exact `gateway-vpn-update-finalize.service` завершился code `0` с `release stability window is still active`, не изменив journal/recovery;
- source-only helper изменил deadline только exact `STABILIZING` journal через production `JournalStore`; wrong ID и отсутствие двойного gate-confirmation завершались отказом. После этого exact production finalizer записал `FINALIZED`, перевёл обе ссылки на candidate и оставил `PATH_BLOCKED`; это проверка mechanics, не реальные 24 часа;
- новый systemd PID 1 после finalized rootfs сохранил candidate current/recovery, schema 16, terminal journal, active managed services, `NRestarts=0`, пустой `systemctl --failed` и `PATH_BLOCKED`.

**Interrupted-update recovery:**

- signed candidate штатно staged production verifier-ом на чистой schema-13 baseline;
- exact `gateway-vpn-update.service` наблюдался в `PREPARED → QUIESCED → HEALTH_CHECKING`; в durable `HEALTH_CHECKING`, уже после DB/current switch, весь container был завершён `SIGKILL` до `OnFailure`;
- новый PID 1 использовал закреплённый recovery binary и записал `ROLLED_BACK / BOOT_OR_PROCESS_RECOVERY`; обе ссылки вернулись на baseline, migration count/max `13`, `quick_check=ok`, foreign-key rows `0`, failed units отсутствуют, firewall остался `PATH_BLOCKED`;
- management/broker/dnsmasq завершили boot ordering примерно за `1.6s` monotonic time с `NRestarts=0`. Первая выборка попала между достижением target и завершением jobs; wall-clock Docker совершил скачок, но `systemd-analyze critical-chain`, journal и последующая active-проверка подтвердили bounded normal boot, а не 47-секундный product stall.

**Версионируемый harness и проверки:**

- добавлены source-only `test/release-gate/cmd/force-update-deadline` и `stage-signed-update`; они не входят в allowlist release builder и требуют environment + explicit flag + absolute paths + exact identity/state;
- staging helper теперь выводит state/DB только из strict production config, а deadline helper запрещает регрессию journal timestamps и reread-проверяет checksummed copies;
- read-only `validate_gateway_systemd.sh` сводит exact release/schema/SQLite, canonical blocked runtime, watchdog/systemd/restarts, HTTPS/SSH/DNS/DHCP, IPv6, nft gates, install report и current-boot failure signatures в один повторяемый fresh/reboot acceptance; CI теперь проверяет его shell syntax;
- focused helper tests/vet, full `go test ./... -count=1`, full `go vet ./...`, четыре CGO-free Linux/amd64 builds, `node --check`, shell `bash -n` и `git diff --check` — PASS.

**Неуспешные/непродуктовые запуски:** первая offline helper-сборка использовала builder без mounted Go module cache и ожидаемо отказалась обращаться в сеть; повтор с read-only pinned cache прошёл. Попытка создать новый privileged fresh-install container не стартовала из-за `502 auth_unavailable` approval-сервиса Codex, поэтому не является product failure и не засчитывается как fresh gate.

**Остаётся:** после явного разрешения privileged Docker выполнить clean exact fresh install, strict idempotency, новый PID 1 и kernel/netns gates; затем обновить journal, commit/push `main`, дождаться exact GitHub CI и очистить временные Docker/.tools ресурсы, не удаляя production `.gvkey`.

### Сессия 079 — публикация unified read model и remote CI — 2026-08-28

**Сделано:**

- функциональный блок direct/VPN read model и preferred nodes зафиксирован exact commit `f5f4de9b5980d0324164b0ef9888e33bc4b68944` и опубликован в `origin/main`;
- public GitHub Actions run `33117118977` сопоставлен с полным SHA через REST API; tag и GitHub Release не создавались.

**Проверено удалённо:**

- `Go, packaging and syntax gates` — `success`, 2m25s;
- `Linux nftables fail-closed gate` — `success`, 1m14s;
- весь run — `success`, 3m46s.

**Следующий шаг:** собрать новый disposable signed successor candidate и повторить exact fresh Ubuntu systemd/netns install, schema migration, update/rollback/finalize и reboot recovery gates без public tag/Release. До этого блока требуется подтверждённое переключение с High на xhigh по протоколу проекта.

### Сессия 078 — канонический direct/VPN read model и preferred nodes — 2026-08-28

**Сделано локально:**

- добавлен typed `pathReadItem` для всех user access paths: direct и subscription rows имеют одинаковые method/modem identity, `FULL/LIMITED`, functional score, required/optional evidence, latency, generations, freshness, reason и active flag;
- `/api/v1/paths/matrix` стал канонической `modem × access method` матрицей; `/modems` и `/subscriptions` возвращают проекции тех же rows, включая direct status каждого из `1..N` модемов и VPN status каждой subscription через каждый модем;
- effective state переводит `QUALIFIED/DEGRADED` без корректного будущего expiry в `STALE`; UI не вычисляет пригодность самостоятельно;
- WebUI «Модемы», «Подписки», «Матрица путей» и Dashboard показывают общий method name, state, quality, evidence и active identity; disposable preview создал 2 direct + 4 VPN rows для двух модемов и двух подписок, а counts совпали во всех API;
- `subscription_node_preferences` подключён к node read model и новому `PUT /subscriptions/{id}/nodes/priorities`; UI раскрывает отдельную таблицу каждой подписки, позволяет добавить/переместить/убрать preferred node и отдельно управляет AUTO/INCLUDE/EXCLUDE;
- API переводит active node IDs в fingerprints и отклоняет duplicate, чужой, отключённый, EXCLUDE или missing-subscription input; repository повторяет проверки независимо от handler;
- runtime переносит order/sticky identity на новую immutable version по fingerprint, последовательно проверяет preferred nodes и сохраняет active node первым во время policy transition. Изменение порядка не мутирует active tuple.

**Проверено локально:**

- focused accesspolicy/health/candidateruntime/subscription/webapi/app tests — PASS, включая реальный runtime `QualifyPath`, fingerprint transfer, first preferred FULL, equal-score LIMITED rank, сохранение active direct tuple и invalid API inputs;
- полный `go test ./... -count=1`, `go vet ./...`, CGO-free Linux amd64 build, OpenAPI route contract для 98 methods, `node --check` и `git diff --check` — PASS;
- disposable Windows preview реально стартовал на loopback: matrix `6` rows (`2 DIRECT + 4 SUBSCRIPTION`), каждый modem получил `3` path rows, каждая subscription — `2` modem rows, node preference fields присутствуют;
- Windows `go test -race` не стартовал, потому что portable toolchain имеет `CGO_ENABLED=0` и C compiler отсутствует. Это environment limitation до компиляции; обязательный Linux race выполняется remote CI после push.

**Не проверено:** visual browser smoke остаётся недоступен из изолированного in-app browser; реальный Linux/Mihomo/HiLink multi-modem path и signed systemd candidate ещё не запускались.

**Следующий шаг:** commit/push и exact remote race/netns CI; затем новый disposable signed candidate и полный fresh Ubuntu install/update/rollback/reboot gate без tag/Release.

### Сессия 077 — unified access API/WebUI и асинхронный operation panel — 2026-08-27

**Сделано локально:**

- добавлены authenticated API для единого списка `Прямой интернет + подписки`, полного reorder, enable/disable, startup block, direct service refresh, failure/recovery/cooldown hysteresis и boot-scoped temporary direct-only;
- отключение активного method и включение direct-only сначала закрывают data path через root boundary и очищают authoritative active tuple; произвольный boot ID из WebUI не принимается — backend читает Linux boot identity самостоятельно;
- manual refresh переведён на bounded runtime dispatcher: API немедленно возвращает operation ID, повторный запрос присоединяется к тому же durable owner, а worker живёт от process context, не от завершившегося HTTP request;
- startup recovery dispatcher освобождает leases предыдущего процесса и переводит незавершённые refresh/reclassify operations в terminal `FAILED / PROCESS_RESTART`; queue shutdown оставляет явный `CANCELLED`, а не вечный `QUEUED`;
- добавлены bulk refresh, list/detail/clear completed operations API; detail декодирует только уже bounded/redacted structured steps, completed cleanup не затрагивает RUNNING/QUEUED;
- OpenAPI расширен для access methods, access policy, direct-only, bulk refresh и operations; contract покрывает 97 зарегистрированных method routes;
- WebUI получил отдельную вкладку «Способы доступа»: единый priority, active method/quality, понятные startup/direct-only формулировки, service refresh и hysteresis settings;
- вкладка «Подписки» больше не содержит отдельный конфликтующий reorder: enable идёт через unified method repository, manual/bulk refresh показывает ID и открывает persistent scrolling timeline; обновление подписки разрешено независимо от участия в user ranking;
- disposable WebUI preview получил синтетический operation dispatcher, поэтому диалог стадий можно проверять без сетевых mutation.

**Проверено:**

- `go test -race ./... -count=1` — PASS для всех packages, включая parallel single-flight, один source fetch, durable requester identity и restart recovery;
- `go vet ./...` и CGO-free `GOOS=linux GOARCH=amd64 go build ./...` — PASS;
- OpenAPI route contract, API auth/CSRF/access-policy/direct-only/operations tests, `node --check`, Linux `bash -n` и `git diff --check` — PASS;
- loopback preview на Windows вернул HTTP 200 и production security headers.

**Не получилось / не проверено:** встроенный браузер работает в изолированной network-среде и не достиг host loopback preview; подключённого Chrome browser surface не было. Поэтому новый экран не объявляется visual browser-smoke PASS: остаются API/DOM-independent tests и JS syntax. Реальный signed Ubuntu browser, physical boot, HiLink/Keenetic capture и USB failover не выполнялись.

**Remote acceptance:** exact commit `22709f9dd38b85ab516c7ec2920774ae04e65861`, GitHub Actions run `33114255191`, terminal status `success`, total 3m33s; обе обязательные jobs завершены успешно.

**Следующий шаг:** включить direct-per-modem health в общий read model трёх вкладок и завершить preferred-node order/sticky UI.

### Сессия 076 — boot-scoped startup policy и retention CI fix — 2026-08-27

**Причина:** после публикации refresh ladder GitHub Actions run `33105093173` упал в Linux race suite, а незавершённым архитектурным пунктом оставалось точное поведение настройки «Блокировать доступ до проверки после запуска» при reboot и обычном restart процесса.

**Сделано:**

- исправлена CI-регрессия: `test/endurance` теперь передаёт `OperationDays: 30`; diagnostic retention считает только завершённые operations по `finished_at`, валидирует их temporal range и выдаёт `OPERATION_RETENTION_NOT_CONVERGED`;
- добавлена migration v16 с `access_selection_runtime.observed_boot_id` и безопасный reader канонического UUID из `/proc/sys/kernel/random/boot_id`; symlink, relative path, oversized и некорректный UUID отклоняются;
- boot reconciliation одной SQLite transaction различает host reboot и restart процесса, очищает pending switch и сбрасывает temporary direct-only только на новом boot;
- при включённой startup block policy новый boot атомарно переводит VPN/direct qualification в `STALE`, удаляет target evidence, сбрасывает periodic schedules и оставляет runtime в `PATH_BLOCKED` до новой полной qualification;
- при выключенной policy разрешается только прежний точный active tuple: subscription должен ссылаться на текущую enabled LKG version и разрешённый node, direct/VPN method и modem должны быть enabled, modem — `MODEM_READY`, route/policy generations — текущими;
- startup recovery переводит tuple в `PATH_VERIFYING`, увеличивает config generation и немедленно планирует полную фоновую qualification; VPN до открытия TUN gate проходит один bounded HTTPS transport probe, а обычная activation по-прежнему повторно проверяет configured required targets;
- разрешение startup recovery одноразовое: block, ошибка, policy transition или выбор другого более функционального/приоритетного candidate его потребляет; после этого действует только обычная полная процедура;
- process restart в том же boot не уничтожает действующий tuple и не имитирует reboot. Повреждённый, неполный или отсутствующий LKG/runtime tuple остаётся blocked; firewall/quarantine никогда не отключаются независимо от пользовательской настройки;
- schema-v16 ожидания проведены через migration, backup/recovery, diagnostics и update tests.

**Найдено и исправлено:**

- исходный targeted suite обнаружил, что pre-migration backup fixture после появления v16 откатывался только до v15, хотя ожидал v13; fixture теперь удаляет обе migrations v16/v15 и снова проверяет настоящий `13 → 16` путь;
- первая попытка privileged netns gate в Debian container не дошла до теста: APT mirror был недоступен и packages отсутствовали. Запуск перенесён на pinned Ubuntu 24.04 image;
- первый multi-LAN запуск в минимальном Ubuntu image остановился до теста из-за отсутствующего `python3`; зависимость добавлена только в одноразовый test container, повторный сценарий прошёл.

**Проверено:**

- `go test -race ./... -count=1` — PASS для всех packages;
- `go vet ./...`, CGO-free Linux/amd64 `go build ./...`, `node --check`, `bash -n` и `git diff --check` — PASS;
- pinned Ubuntu 24.04 `systemd-analyze verify` — PASS для Gateway/VPS units, timers, sockets и WireGuard drop-in;
- privileged Ubuntu netns `firewall_guard.sh` — PASS: LAN quarantine, восстановление owned `PATH_BLOCKED` после удаления table/flush и отсутствие direct route;
- privileged Ubuntu netns `lan_bridge_ssh.sh` — PASS: один bridge IPv4, TCP/22 через оба LAN member и блокировка uplink;
- отдельные tests доказывают ON/OFF/first boot/same-boot restart/no-LKG, атомарную инвалидацию evidence, exact direct/VPN preparation, one-shot reconciler permit и использование startup transport probe вместо required target loop.

**Не проверено:** настоящий reboot физического Ubuntu Gateway, сохранение/восстановление nftables через PID 1 на железе, HiLink/Keenetic packet capture, USB hotplug/failover и полный фоновой probe cycle с реальным Mihomo. Эти gates остаются аппаратными, а не считаются выполненными по Docker/netns.

**Remote acceptance:** exact commit `de5f7edc368c2789d12192823d9b872981ff5278`, GitHub Actions run `33109704378`, terminal status `success`, total 3m37s; обе обязательные jobs завершены успешно.

**Следующий шаг:** API/OpenAPI для access methods, startup policy, temporary direct-only и operations; затем asynchronous manual subscription refresh с operation ID и WebUI «Способы доступа»/operation panel.

### Сессия 075 — resilient subscription refresh ladder — 2026-08-27

**Цель:** сделать scheduled/manual update подписок максимально устойчивым к блокировке provider domain на отдельном VPN-сервере или операторе, не переключая и не ослабляя текущий пользовательский маршрут.

**Реализовано локально:**

- production fetcher теперь перебирает exact service routes в порядке: текущий active node целевой подписки, остальные allowed nodes этой подписки, allowed nodes других подписок, затем direct через ready-модемы по priority, только если `direct_service_refresh_enabled=true`;
- VPN DNS и HTTPS идут через SOCKS5 на существующий numeric loopback-only mixed listener `gateway-vpn-probe-in`; selection `probe-path → gateway-vpn-probe` и весь DNS/TLS/HTTP fetch выполняются под общим Mihomo operation lock, поэтому параллельный probe/reload не может подменить route внутри одной попытки;
- перед select под уже захваченным lock повторно проверяются active version, modem READY, stable node identity и `AUTO/INCLUDE` policy. Node, ставшая `EXCLUDE` либо исчезнувшая после построения inventory, получает `VPN_ROUTE_STALE` и не используется;
- disabled user-routing subscription больше не удаляется из Mihomo целиком: её LKG остаётся только в qualification-only probe groups, не входит в `gateway-vpn-active`; refresh новой disabled LKG квалифицирует candidate, но не публикует `QUALIFIED` user path;
- direct adapter по-прежнему использует `SO_BINDTODEVICE + SO_MARK`, а root backend дополнительно перечитывает `direct_service_refresh_enabled` перед transient endpoint authorization. Выключенный direct user method не мешает service refresh; выключенная отдельная service policy запрещает root authorization;
- каждая route attempt записывает redacted durable стадии `ROUTE_SELECTED → DNS → TLS → HTTP`; URL, query token, response body и backend text в operation не попадают. Refresh добавляет `SOURCE → IMPORT → VALIDATE → QUALIFY → ACTIVATE → COMPLETE/FAILED`;
- HTTP `Retry-After` переносится как typed bounded delay через все fallbacks и увеличивает durable exponential backoff не более configured 6 часов; response headers/body details не раскрываются;
- один route ограничен 20 секундами, вся ladder — 5 минутами, одна operation — 1024 VPN attempts и 32768 steps; применение route limit явно появляется в журнале, после чего direct fallback всё равно выполняется;
- завершённые operations автоматически удаляются малыми batches через 30 дней; retention/diagnostic/endurance snapshots отражают operation policy и counts.

**Проверено:**

- route repository test подтверждает точный active-first order, target-subscription before others, service use routing-disabled subscription и отсутствие EXCLUDE; отдельная revalidation отвергает node, исключённую после inventory;
- integration test подтверждает, что общий operation lock удерживается через selector и HTTPS dial, первый route может отказать, следующий succeeds, а `runtime_state` user tuple остаётся byte-equivalent;
- SOCKS/direct route attempts, root direct policy gate, disabled-subscription LKG promotion без user evidence, durable stage order, URL redaction, bounded `Retry-After`, operation hard bound и 30-day cleanup покрыты tests;
- полный `go test ./... -count=1` — PASS;
- полный `go vet ./...` — PASS;
- `GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build ./...` — PASS;
- `git diff --check` — PASS;
- предыдущий exact GitHub Actions run `33101289685` для `5f2e521` завершён `success`; jobs `Go, packaging and syntax gates` и `Linux nftables fail-closed gate` — PASS.

**Ограничения:** реальный Mihomo mixed/SOCKS DNS+TLS fetch, provider redirects через разные nodes/operators, Linux marked direct sockets и mobile traffic budget ещё не проверены на hardware. Manual API пока выполняет refresh синхронно и не возвращает operation ID; GET/DELETE operations API, OpenAPI и WebUI panel остаются отдельным следующим interface block.

**Следующий шаг:** commit/push exact refresh-ladder block и получить terminal remote CI; затем подключить startup gate OFF с минимально проверенным LKG/direct recovery и boot-ID lifecycle временного direct-only режима.

### Сессия 074 — firewall schema v3 и unified runtime selector — 2026-08-27

**Цель:** связать уже опубликованные direct probes и unified ranking с реальным fail-closed data plane, не допуская одновременного TUN/direct forwarding, stale modem route либо зависимости прямого доступа от работоспособности Mihomo.

**Реализовано локально:**

- firewall schema v3 добавляет bounded sets/maps `active_tun_interfaces`, `active_direct_interfaces`, exact `interface . fwmark`, `LAN → fwmark`, path generation и direct route generation; каждая transaction сначала закрывает оба user gates, после чего открывает не более одного метода;
- direct forward и MASQUERADE требуют одновременно выбранный modem interface и точный mark; LAN packet в direct получает mark только при активной map. `PATH_BLOCKED` не пропускает его даже к connected modem subnet;
- root broker принимает для direct activation только `modem_id + route_generation`, перечитывает runtime intent, fresh evidence, interface/fwmark и routing state из SQLite и после apply сверяет точную nft JSON map;
- migration v15 добавляет отдельный FK `active_direct_path_id`; VPN и direct runtime tuples больше не используют неоднозначный общий path ID. Begin/Finish/Block/recovery атомарно ведут method, quality и все identity fields;
- production reconciler подключён к unified candidates и durable transition runtime: `FULL` всегда выше `LIMITED`, затем действуют functional score и method/modem/node priorities; normal failover/failback ждёт hold/stable/cooldown, потеря точного data-plane context и незавершённая activation используют hard-failure fast path;
- direct activation не требует Mihomo/TUN; при рабочем direct падение Mihomo не блокирует Интернет. VPN activation по-прежнему требует exact Mihomo selector, end-to-end recheck и TUN gate;
- VPN qualification теперь сохраняет `BYPASS_LIMITED`, выбирает лучший частично функциональный node только если FULL отсутствует и считает score как `required_passed × 1000 + optional_passed`; перед activation повторно проверяются все fresh targets, которые прошли в сохранённом LIMITED evidence;
- policy transition умеет подтвердить остающийся FULL либо LIMITED VPN node или немедленно перейти на лучший unified replacement, включая direct; startup/recovery state сохраняет точный method kind и quality;
- gateway status API дополнен `active_direct_path_id`, `active_method_id/kind` и `active_quality_class`; backup/update/diagnostics expectations переведены на schema v15.

**Проверено:**

- focused state/accesspolicy/health/pathmatrix/reconcile/pathruntime/dataplane/app/webapi tests — PASS;
- полный `go test ./... -count=1` — PASS;
- полный `go vet ./...` — PASS;
- `GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build ./...` — PASS;
- `git diff --check` — PASS;
- production nft renderer/decoder добавлен в Linux CI/netns gate с последовательностью TUN → DIRECT → BLOCKED → TUN; exact remote kernel result будет получен после commit/push.

**Не проверено:** Windows не может выполнить nftables/netns; реальный Ubuntu 24.04 Gateway, HiLink packet path, USB disconnect/replug и physical multi-operator failover остаются внешними gates. Startup gate OFF, resilient subscription refresh route ladder и access-method/API/OpenAPI/WebUI/operation panel ещё не реализованы.

**Следующий шаг:** commit/push exact schema-v3 selector block и дождаться terminal GitHub Actions; затем реализовать resilient refresh ladder, чтобы subscription update перебирал active method, другие qualified VPN paths и разрешённый service-direct путь с подробным operation status.

### Сессия 073 — modem-bound direct Internet qualification — 2026-08-27

**Цель:** превратить persistent direct modem paths из migration v14 в фактические проверки полноценности Интернета через каждый отдельный HiLink/uplink без fallback в host main/default route и без открытия пользовательского forwarding.

**Реализовано локально:**

- новый `internal/directprobe` для каждого due direct path повторно синхронизирует owned policy routing, сверяет authoritative modem `route_generation` и создаёт DNS/HTTPS sockets с одним `SO_BINDTODEVICE + SO_MARK` контекстом;
- DNS последовательно использует настроенный bounded bootstrap list, принимает только `1..16` IPv4 global-unicast ответов без private/IPv6 примеси; HTTPS подключается только к полученному pinned IP, сохраняет исходный hostname для TLS/SNI, не следует redirect, ограничивает headers/body и поддерживает `any_http_response`, `expected_status`, `expected_body`;
- root broker получил typed `POST /v1/direct-probe/authorize`: caller передаёт только modem ID, target ID, до 16 public IPv4 и HTTPS port; root перечитывает modem interface/fwmark и текущую enabled target policy из SQLite, проверяет port и добавляет exact tuple в существующий service set с timeout 2 минуты;
- общий scheduler применяет concurrency/rate/mobile-byte budget. Budget deferral не стирает прежнее evidence; `FULL` требует прохождения всех обязательных целей, optional-only success даёт `LIMITED`, пустая policy явно публикует `FAILED/NO_ACTIVE_TARGETS`;
- periodic runner подключён как критический `direct-health` worker и только записывает qualification evidence. Он не активирует direct NAT/TUN и не может открыть пользовательский трафик;
- runner получил round-robin cursor: постоянная ошибка первых priority-модемов больше не лишает проверки последующие модемы при `DueLimit < modem count`;
- disabled для user routing URL-подписка по-прежнему допускается root bootstrap authorization для background/manual refresh; upload source и неизвестная подписка не допускаются.

**Safety review и найденные проблемы:**

- добавлена проверка смены modem route generation именно во время root routing sync: stale context не создаёт socket, firewall tuple или новое evidence;
- policy mutation защищена двумя уровнями: root отвергает уже disabled target/изменённый port, а publication transaction отвергает старую global policy generation и неполный target set;
- caller cancellation теперь всегда прекращает весь cycle без перезаписи предыдущего результата; локальный timeout отдельной цели остаётся нормальным `TIMEOUT` evidence и не останавливает проверку остальных целей;
- private literal, смешанный public+private DNS answer и IPv6 answer отвергаются; redirect и dial к hostname/IP вне pinned origin невозможны;
- подтверждено, что `direct-health` только вызывает repository publication и transient service allowlist, а существующий user gate остаётся неизменным.

**Проверено:** focused directprobe/dataplane/networkapply/accesspolicy/app tests; полный `go test ./... -count=1`; `go vet ./...`; четыре `linux/amd64 CGO_ENABLED=0` cross-build (`gateway-vpn`, `gateway-vpnctl`, `gateway-vpn-bootstrap`, `gateway-vpn-deploy`); `git diff --check` — PASS. Linux capabilities, реальный marked DNS/HTTPS, nft timeout и packet capture ещё не запускались.

**Следующий шаг:** реализовать unified runtime selector и direct actuator с root endpoint только `modem_id + route_generation`, firewall schema v3, взаимным исключением direct NAT и TUN gate, atomic rollback/quarantine; затем resilient subscription refresh ladder и API/WebUI.

### Сессия 072 — unified direct/VPN access policy foundation — 2026-08-27

**Причина:** после обсуждения пользователь утвердил расширенную модель с прямым Интернетом в общем priority list, выбором самого функционального пути через `1..N` модемов, durable server preferences, отказоустойчивым обновлением и понятной настраиваемой стартовой блокировкой.

**Реализовано локально:**

- `PLAN_v1.1.md` дополнен единым access-method contract, `FULL/LIMITED` ranking, direct qualification, startup modes, temporary direct-only, server preferences, resilient refresh ladder, persistent operation panel, API/WebUI/test/DoD требованиями;
- migration v14 добавляет `access_methods`, `access_policy`, direct modem/target evidence, durable node preferences, selection runtime, bounded operations и quality/route-generation поля;
- новый `internal/accesspolicy` реализует immutable direct method, synchronization подписок, exact ranking, stable/cooldown/hard-failure transitions, boot-scoped direct-only, preferred rank и unified direct/VPN candidate inventory;
- новый `internal/operations` сохраняет redacted ordered stages, terminal state и bounded cleanup;
- subscription refresh больше не зависит от user-routing enable; preferences и overrides переносятся между versions по fingerprint, исчезнувшие nodes сохраняют history;
- modem lease/interface/gateway/enable/offline transitions монотонно меняют authoritative `route_generation` и в одной transaction инвалидируют VPN и direct evidence;
- direct result publication проверяет global policy generation, authoritative modem generation и соответствие evidence текущему required/optional target policy; candidate inventory дополнительно фильтрует stale/expired rows.

**Найдено и исправлено тестами:** искусственно изменённый authoritative modem generation показал, что проверка только generation строки path допускает короткое окно для старого probe-result. `Publish` теперь повторно сверяет поколение самого модема внутри transaction. `Reconcile` не переносит старый success на новое route/policy generation, а сбрасывает quality/evidence в `STALE`.

**Проверено:** `gofmt`; полный `go test ./... -count=1`; `go vet ./...`; CGO-free Linux/amd64 cross-build для `gateway-vpn`, `gateway-vpnctl`, `gateway-vpn-bootstrap` и `gateway-vpn-deploy` — PASS. Direct tests покрывают один и несколько ready/offline модемов, FULL/LIMITED evidence, disabled direct method, stale route/policy rejection и совместный direct/VPN ranking.

**Не реализовано пока:** modem-bound direct DNS/HTTPS prober, unified runtime selector/actuator, privileged broker и nftables direct generation, resilient refresh route ladder, API/OpenAPI/WebUI/operation panel. Migration v14 ещё не прошла signed update/rollback и Linux systemd/netns gates.

**Следующий шаг:** реализовать direct prober на существующем `netbind.SocketControl`, который для каждого ready modem использует его authoritative interface/fwmark, записывает required/optional results и functional score без main-table/default-route fallback.

### Сессия 071 — multi-port LAN bridge и SSH с любого выбранного Ethernet — 2026-08-27

**Причина:** пользователь уточнил, что Gateway может иметь несколько Ethernet-интерфейсов и SSH должен быть доступен независимо от того, в какой LAN-порт подключён кабель.

**Реализовано локально:**

- wizard принимает несколько уникальных номеров через запятую, по умолчанию выбирает все safe Ethernet ports и передаёт их installer как bounded typed `LANMembers`;
- Huawei USB network links дополнительно распознаются по fixed `udevadm` metadata `ID_BUS=usb` + `ID_VENDOR_ID=12d1`, поэтому даже ещё не получивший IPv4 HiLink не может случайно стать LAN member;
- выбранные ports объединяются в owned bridge `gateway-vpn-lan`; systemd-networkd получает persistent `.netdev`, отдельный exact member policy и один address на bridge, STP включён; ранние owned `05-/06-` filenames имеют приоритет над Ubuntu `10-netplan-*` после reboot;
- OpenSSH добавлен в managed dependency plan: отсутствующий package скачивается до firewall mutation без запуска daemon, но устанавливается и запускается только после durable recovery marker и `PATH_BLOCKED`;
- installer требует active `ssh.service` и IPv4 wildcard listener TCP/22; boot nftables разрешает новые SSH connections только с `gateway-vpn-lan`, а не с HiLink/uplink;
- install marker расширен до 14 strict fields. Recovery/uninstall отсоединяют members, удаляют только owned bridge/networkd files, возвращают прежние administrative link states и прежние enabled/active states OpenSSH;
- install report фиксирует physical `lan_members` и `lan_ssh_enabled`; PLAN, OPERATIONS и README объясняют один адрес для всех выбранных ports, DHCP/static-client requirement и local-console boundary.

**Проверено:** `gofmt`; focused tests; полный `go test ./... -count=1`; `go vet ./...`; deterministic regeneration и hash-check nftables fixtures; `bash -n scripts/*.sh`; CGO-free Linux/amd64 builds `gateway-vpn`, `gateway-vpnctl`, `gateway-vpn-bootstrap`, `gateway-vpn-deploy`; `git diff --check` — PASS. Первый full suite правильно обнаружил stale `boot-blocked.nft`; fixture и его canonical SHA-256 регенерированы, повторный full suite прошёл. В CI добавлен root netns gate с двумя bridge members, единственным bridge IPv4, STP forwarding, двумя успешными TCP/22 probes и запрещённым TCP/22 через отдельный uplink; его фактический Linux result ещё ожидает push.

**Не проверено пока:** реальное создание bridge/member links, nft input semantics на bridge, доступ TCP/22 через каждый member, networkd reboot persistence и rollback на Linux kernel. Docker Desktop/Engine в текущей Windows session не запущен, поэтому эти пункты не объявляются PASS до exact remote Linux CI и disposable signed systemd/netns rehearsal.

**Следующий шаг:** commit/push текущего successor, дождаться terminal exact GitHub CI, затем выполнить clean disposable-signed full-bundle Linux rehearsal; production tag/Release остаются отдельным разрешением.

### Сессия 070 — universal interactive Gateway installer — 2026-08-27

**Причина:** пользователь отклонил требование заранее сообщить `enp2s0`: установка должна запускаться одной и той же GitHub-командой на любом поддерживаемом PC, сама показывать несколько Ethernet-интерфейсов и позволять выбрать непересекающуюся подсеть WAN Keenetic.

**Реализовано локально:**

- новый target-side `installwizard` делает только bounded `ip -json` observations и показывает numbered inventory: link type, state/carrier, IPv4 и safety reason;
- loopback, non-Ethernet, любой link с IPv4, current default-route и доступный из `SSH_CONNECTION` active management link заблокированы; HiLink с выданным management IPv4 поэтому нельзя случайно выбрать как LAN;
- пользователь явно выбирает unused Ethernet, DHCP policy и разрешение на безопасную установку отсутствующих managed packages;
- wizard ищет первый свободный CIDR из безопасного набора, принимает custom canonical RFC1918 host CIDR `/16../30`, требует `/24` для DHCP и использует существующий typed overlap preflight против всех addresses/routes и `10.80.0.0/24`;
- после проверки exact signed Gateway artifact выполняется отдельный read-only installer preflight; apply начинается только после exact token `INSTALL`; cancel/EOF/нет TTY/preflight failure не запрашивают persistent changes;
- `GatewayInstallCommand` и `channel-install-command` получили mutually-exclusive interactive/explicit modes; build-channel и оба bundle builders теперь всегда выпускают generic interactive Gateway command без hardware inputs;
- automation/CI/deploy contract с явными `--lan-interface/--lan-address` сохранён без изменения.

**Проверено:** focused wizard/distribution/bootstrap/channel/packaging tests PASS; полный Windows `go test ./... -count=1` и `go vet ./...` PASS; Git Bash `bash -n scripts/*.sh` PASS; CGO-free Linux/amd64 bootstrap cross-build PASS; `git diff --check` PASS. Tests покрывают multiple NIC, default-route и configured/HiLink rejection, active SSH route, conflict-free default selection, invalid/custom CIDR, DHCP `/24`, cancel/EOF, exact final token, отсутствие mutating commands в selection и regression explicit automation.

**Не проверено пока:** реальный target TTY/iproute2 inventory на Ubuntu, clean disposable signed full bundle с новым builder CLI, exact remote CI и физический install. Docker API из текущей restricted Windows session недоступен; это не заменяется локальным unit PASS.

**Изменение прежнего handoff:** реальный LAN interface больше не является входом release build/publish и не нужен для подготовки RC. Он выбирается и повторно проверяется непосредственно на целевом Gateway. Исторические записи с прежним требованием сохраняются как ход разработки, но DEV-153 их отменяет.

**Следующий шаг:** commit/push, дождаться exact GitHub CI, затем выполнить clean disposable-signed full-bundle/Linux interactive rehearsal до production RC.

### Сессия 069 — permanent encrypted production key — 2026-08-27

**Пользовательское действие:** владелец самостоятельно выполнил исправленный PowerShell launcher с process-scoped `ExecutionPolicy Bypass`, ввёл passphrase два раза в hidden terminal prompt и получил `DONE: primary encrypted key file and verified backup were created.` Пароль не передавался в чат, argv, environment, Git, journal или Codex tool input/output.

**Создано:** primary `gateway-vpn-production.gvkey` и backup с тем же именем в ранее выбранных отдельных каталогах `C:\Users\Igor\Documents\Gateway VPN Keys\primary` и `...\backup`. Низкоуровневый Linux workflow последовательно выполнил exclusive create, Argon2id/AES-GCM encrypt, decrypt/self-verify, byte-identical backup, повторный decrypt/verify primary и backup; только после всех success-команд напечатан `DONE`.

**Независимая read-only проверка без пароля:** оба файла существуют, каждый имеет 574 bytes и fixed magic `GATEWAY-VPN-KEY1`; полное byte comparison и SHA-256 совпадают. Содержимое не расшифровывалось, passphrase не запрашивалась. In-memory ciphertext buffers после проверки очищены.

**Durability boundary:** текущая backup-копия находится в отдельном каталоге, но на том же пользовательском storage namespace; она защищает от случайного удаления/повреждения одного файла, но не доказывает независимость физического диска или account-wide loss. Флешка не обязательна: при желании byte-identical backup позднее можно скопировать на другой диск или в отдельно защищённое облачное хранилище, сохраняя passphrase отдельно.

**External state:** exact published journal commit `eece377` прошёл GitHub Actions run `33053762746` со всеми Go/packaging/syntax и Linux nft/netns/systemd jobs. Production tag, draft/public GitHub Release и production-signed RC artifacts не создавались. Hardware H1/H2, real VPS/provider и 24/72h endurance evidence не изменялось.

**Следующий шаг:** определить фактическое имя выделенного LAN interface на будущем Ubuntu Gateway (не modem USB interfaces), затем подготовить из нового clean commit production-signed `0.1.0-rc.1`. Создание/push tag и GitHub draft Release остаются отдельной внешней transaction и требуют явного разрешения пользователя.

### Сессия 068 — portable `.gvkey` и пользовательский пароль — 2026-08-27

**Причина:** пользователь отказался от обязательных флешек/отдельных encrypted Linux storage и выбрал простой файл ключа с самостоятельно задаваемым паролем. Release signing всё равно сохраняет Ed25519 trust boundary: private key нужен только издателю обновления, а Gateway/VPS получают исключительно public key.

**Реализовано:** добавлен bounded format `GATEWAY-VPN-KEY1`: strict authenticated header, Argon2id `64 MiB/3/p2`, AES-256-GCM, encrypted PKCS#8 private/public payload и fingerprint self-verification. CLI получил Linux-only create/verify/backup/unlock; destination обязан быть absolute real `.gvkey` вне Git worktree, existing file не перезаписывается, backup создаётся byte-identical в другом каталоге. Passphrase поступает только через bounded stdin или private `0600` file, очищаются полный input buffer, decoded private DER, private/public key copies и ciphertext buffer. Скрипт creation спрашивает пароль дважды без echo; release wrapper спрашивает один раз, раскрывает PEM только в RAM и всегда удаляет его trap.

**Упрощённый контракт:** постоянный encrypted файл разрешено хранить на Windows как обычный файл; специальная флешка не требуется. Primary выбран как `C:\Users\Igor\Documents\Gateway VPN Keys\primary\gateway-vpn-production.gvkey`, copy — как соседний backup-каталог вне Git. После отдельного указания пользователя минимум изменён с 20 байт на 10 Unicode-символов (max 256 UTF-8 bytes), с тестами точной ASCII/кириллической границы.

**Проверено:** full Windows `go test ./... -count=1`/`go vet ./...`, shell syntax, Markdown fences и `git diff --check` — PASS. Native offline Linux focused tests/vet — PASS. Disposable lifecycle на специально `noexec /dev/shm` создал 574-byte primary/byte-identical backup, проверил wrong-path/cleanup и не оставил PEM marker. Exact clean `08b7c5c` собрал и canonical re-verified полный signed version `0.1.0-keyfile.08b7c5c`; итог `ENCRYPTED_KEY_CLEAN_COMMIT_BUNDLE_PASS`. Remote runs `33052162474` для `08b7c5c` и `33053389413` для 10-character successor `cbd8bf7` завершились `success`.

**Найдено и исправлено:** первый static packaging test не видел magic, поскольку он был записан byte-array literal; magic закреплён immutable string. Passphrase reader раньше очищал только trimmed slice, теперь очищает полный original buffer. Первые wrappers собирали helper внутри потенциально `noexec /dev/shm`; helper перенесён в отдельный cleanup-scoped `/tmp`. Clean clone обнаружил отсутствующий executable-bit новых scripts; commit `08b7c5c` закрепил mode `100755` и повторная full сборка прошла.

**Неуспешные operator UI попытки:** Codex terminal panel был queued и не показался пользователю; первый отдельный PowerShell получил неправильно разобранный path с пробелом, второй показал parse error временного UTF-8 launcher. Оба процесса завершились до password input/create. Launcher переписан ASCII-only и Windows PowerShell parser возвращает `PARSE_OK`; production primary/backup каталоги повторно проверены и остаются пустыми. Эти failures относятся к локальному способу показа prompt, не к `.gvkey`/Docker/crypto implementation.

**Граница результата:** production key, tag и GitHub Release не созданы. Disposable test identities и bundle уничтожены вместе с `--rm` containers. Hardware H1/H2, real VPS/provider и 24/72h endurance статусы не изменялись.

**Следующий шаг:** пользователь запускает в уже видимом PowerShell `& ".\.cache\start-production-key-prompt.ps1"`, самостоятельно вводит passphrase два раза и сообщает `DONE`. После этого проверить existence/size/byte-identical SHA-256 без чтения passphrase; cryptographic create+backup+verify уже выполняются внутри одной команды. Затем создать новую immutable RC только отдельной release transaction; tag/draft Release по-прежнему требуют отдельного разрешения.

### Сессия 067 — exact reproducible key-lifecycle bundle — 2026-08-27

**Причина продолжения:** после remote CI новый use-time custody contract был доказан library/CLI tests, но полный `build-release-bundle.sh` с ранним `release-key-verify`, четырьмя role artifacts и verified backup ещё не запускался из exact clean commit. Это был последний локально закрываемый release gap без production key или hardware.

**Exact rehearsal identity:** source `4ab16686bbbee0194b2f09eb9562c90b7a44d1f2`, local-only immutable version `0.1.0-keylife.4ab1668`, pinned Mihomo `v1.19.30`. Один disposable Ed25519 signer был создан в container tmpfs, cryptographically verified, скопирован новым exclusive backup workflow в другой `0700` tmpfs directory и после завершения уничтожен вместе с `--rm` container. Production identity не создавалась.

**Negative gate:** отдельный clean clone получил primary private key и public key другой freshly generated identity. Full bundle command завершился на раннем pair verification до создания `dist`; дорогая build/sign phase не запускалась.

**Reproducibility и verification:** два независимых clean clone текущего commit использовали раздельные пустые Go build caches, read-only module cache и `--network none`. Оба собрали Gateway/VPS/bootstrap/deploy/channel одним signer. Полное сравнение entry type/mode/path и каждого файла дало 105 одинаковых tree entries, 76 byte-identical files. Gateway release, VPS release и signed channel повторно прошли canonical verifier с public key из backup, а recursive scan не нашёл `BEGIN PRIVATE KEY` в `dist`. Итоговый marker — `FULL_OFFLINE_RELEASE_KEYLIFE_REPRO_PASS`.

**Artifact evidence:** Gateway archive `21d33c377fa79acd3baa723357c6b0433aa338d5394a7c9eb4ee3abbafe4af7f`; VPS archive `b3e5956983ba8952fe335092c006b0a547efe45349cc92b5eabc4c947ce8d6d9`; bootstrap `d8f1d03f500a1185b0c1ba4818d6e41a80e4f28fcb9cc510feacf5380874f7f9`; deploy `9876d6375b6e853029012237043bc424527576341cc8b9d49326bb743f2a2cf4`; channel manifest `23c117d0ac127c3cd41c51f6e0c20a6d2ca00037939b88c0e5541b94e8524946`. Эти artifacts были disposable rehearsal output и не публикуются.

**Public namespace и граница evidence:** read-only `git ls-remote --tags origin` вернул пустой список, GitHub Releases API — `release_count=0`. Hardware H1/H2, real VPS/provider path и 24/72h endurance не запускались и не повышались. Requirement audit не выявил нового недописанного локального runtime scope; оставшиеся `PARTIAL_EXTERNAL`/`NOT_RUN_EXTERNAL` действительно требуют production publish, физических hosts/modems/Keenetic или времени.

**Следующий шаг:** получить два абсолютных Linux-visible encrypted storage path и явное разрешение `Разрешаю создать production signing key`; затем проверить storage и создать primary+verified independent backup. Tag/draft Release остаются отдельным последующим разрешением.

### Сессия 066 — remote CI use-time key lifecycle — 2026-08-27

**Exact public identity:** проверенный security increment зафиксирован commit `00f7e293074644dca560b232ecbf077d868bdd5c` и отправлен в явно разрешённую ветку `main`; `git ls-remote` подтвердил тот же SHA в `refs/heads/main`.

**Remote evidence:** GitHub Actions workflow `Gateway VPN CI`, run `33028034972`, завершился `completed/success` для exact `00f7e29`. Job `Go, packaging and syntax gates` прошла exact checkout, pinned Go toolchain, formatting, race-enabled full suite, vet, сборку всех Linux release entrypoints и JavaScript/shell syntax. Job `Linux nftables fail-closed gate` прошла native Linux build, реальное fail-closed/no-direct-route nftables evidence и Gateway/VPS systemd verification на Ubuntu 24.04.

**Граница результата:** production signing key, tag, GitHub Release и assets не создавались. Hardware H1/H2, реальный VPS/provider path и 24/72h endurance не повышались и остаются внешними gates.

**Следующий шаг:** пользователь должен выбрать два абсолютных Linux-visible пути: primary encrypted/offline storage и независимый encrypted backup, затем отдельно написать `Разрешаю создать production signing key`. Только после проверки mounts/ownership/modes/free space допускается keygen/verify/backup; `0.1.0-rc.1` tag и draft Release потребуют отдельного последующего разрешения.

### Сессия 065 — use-time key custody и verified backup — 2026-08-27

**Закрытый lifecycle gap:** прежний hardening надёжно создавал keypair, но после генерации private key загружался без повторной проверки абсолютного secure path/mode, отсутствовала явная команда проверки пары и проверяемый backup workflow. Signing-команды также могли быть вызваны на non-Linux host, хотя production identity разрешено использовать только на trusted Linux builder.

**Исправлено:** `LoadPrivateKey` теперь при каждом использовании требует absolute real path, secure directory вне Git worktree, regular non-symlink file и закрытые Linux permissions. Добавлены Linux-only `release-key-verify` и `release-key-backup`; обе команды сверяют public key с public component private key и возвращают bounded fingerprint. Backup допускается только в другом заранее созданном secure directory, создаёт оба файла exclusive с `fsync`, перечитывает копию, сохраняет exact `0600/0644` и не перезаписывает existing destinations. `release-sign`, `vps-release-sign` и `channel-sign` также стали Linux-only. Full bundle builder выполняет pair verification до дорогих сборок Gateway/VPS/deploy/channel. OPERATIONS/SECURITY описывают primary/independent-backup процедуру и честную границу: CLI не может доказать encryption или физическую независимость storage.

**Проверено:** targeted и полный Windows Go 1.26.7 `go test ./... -count=1`/`go vet ./...` — PASS. Native offline Linux в pinned builder с `--network none`, read-only source/module cache и отдельными writable build caches — полный test/vet PASS. Disposable tmpfs CLI smoke получил `FULL_OFFLINE_LINUX_KEY_VERIFY_BACKUP_PASS`: explicit verify, exact primary/backup fingerprint, modes `0600/0644`, byte-identical pair, repeat no-overwrite, mismatched public rejection, symlink-path rejection и permission-weakened private rejection. Test identity существовала только внутри удалённого container tmpfs. Offline `bash -n` всех project scripts, Markdown fence balance и `git diff --check` — PASS.

**Неуспешные harness-попытки:** первые Windows commands не задали workspace-local module cache и были остановлены sandbox до компиляции; повтор с локальными cache прошёл. Первые Docker команды неверно экранировали Windows bind path с пробелом и завершились до запуска контейнера; исправленная PowerShell argument form прошла. Это ошибки test-run environment, не product failures.

**Граница полномочий:** production key, tag и GitHub Release не создавались. Hardware/VPS/endurance evidence не изменено. Разрешение пользователя относится к `git push origin main`.

**Следующий шаг:** зафиксировать проверенный increment, отправить exact commit в разрешённый `main` и дождаться terminal GitHub Actions result. После green CI по-прежнему нужны два абсолютных Linux-visible encrypted storage path и отдельная фраза `Разрешаю создать production signing key`.

### Сессия 064 — remote CI hardened key custody — 2026-08-27

**Exact public identity:** security increment зафиксирован commit `7f36928f439cd645e17367be8423281ca996a30e` и отправлен в разрешённую ветку `main`; `git ls-remote` подтвердил тот же SHA. Production key/tag/release не создавались.

**Remote evidence:** GitHub Actions workflow `Gateway VPN CI`, run `33026304197`, завершился `completed/success` для exact `7f36928`. Первая job прошла formatting, race-enabled full suite, vet, четыре Linux entrypoint builds и JS/shell syntax. Вторая job прошла native nftables fail-closed/no-direct-route gate и Gateway/VPS systemd verification на Ubuntu 24.04.

**Текущий внешний blocker:** keygen contract теперь готов, но production/hardware-test identity нельзя безопасно создать без двух заранее выбранных storage locations: primary encrypted/offline Linux-visible directory и независимый encrypted backup. Также требуется отдельное явное разрешение именно на генерацию key; прежнее разрешение относилось только к `git push origin main`.

**Следующий шаг:** получить два абсолютных пути и подтверждение `Разрешаю создать production signing key`. Затем на trusted Linux builder проверить mounts/ownership/modes/free space, создать pair только в primary, независимо проверить fingerprint, скопировать private/public backup с verification и только потом строить новую immutable `0.1.0-rc.1` candidate. Tag/draft Release остаются последующей отдельной transaction.

### Сессия 063 — keyless release preflight и hardening key custody — 2026-08-27

**Keyless public preflight:** exact `main`/`origin/main` начинали с `3e973bc`; public GitHub API показал `TAG_COUNT=0`, `RELEASE_COUNT=0`. `gh` CLI на Windows host отсутствует, а `git ls-remote --tags` один раз не получил Windows Schannel credentials; публичный REST API дал авторитетный read-only namespace result. Никакой tag/draft/version не создавались. Для первого hardware package выбрана policy pre-release, предпочтительно `0.1.0-rc.1`; stable `0.1.0` остаётся свободной до physical gates.

**Найденный security gap:** прежний `release-keygen` использовал exclusive files и private mode `0600`, но принимал relative/different-directory paths и не проверял secure parent, Git worktree или symlink components. Это позволяло оператору случайно создать permanent key в repository/shared storage, хотя publisher документация требовала isolated builder.

**Исправлено:** production CLI теперь запускает keygen только на Linux. Library принимает только два разных absolute paths в одном существующем real directory; Linux directory обязан быть mode `0700`/без group-other access, весь destination path — без symlink components, ancestor chain — без `.git`. Existing destinations никогда не перезаписываются. Private DER/PEM и in-memory key buffers очищаются; private/public files создаются exclusive, mode выставляется до file fsync, directory fsync выполняется после пары. Затем оба PEM перечитываются, public key выводится из private и сравнивается с сохранённым public/fingerprint; partial failure удаляет только созданные файлы и fsync-ит cleanup. Backup намеренно не создаётся автоматически.

**Проверено:** полный Windows `go test ./... -count=1` и `go vet ./...` — PASS. Полный offline native Linux `go test ./... -count=1`/`go vet ./...` из read-only source и module cache — `FULL_OFFLINE_LINUX_KEY_CUSTODY_PASS`. Отдельный disposable Linux CLI smoke в tmpfs доказал success в `0700`, exact modes `0600/0644`, repeat no-overwrite, rejection relative/`0755` destinations — `LINUX_RELEASE_KEYGEN_CLI_PASS`; test key исчез с container. Первые Linux harness попытки отдельно зафиксировали не продуктовые ограничения: отсутствующий writable module cache, затем `noexec /tmp`, затем старый channel test не задавал `0700`; harness/test fixture исправлены, production state не затрагивался.

**Что не сделано:** production/hardware-test key не создан; пути основного и backup encrypted storage не получены. Tag, draft Release и assets отсутствуют. Hardware/VPS/endurance статусы не изменены.

**Следующий шаг:** commit/push/remote CI этого hardening increment. После green CI остановиться до двух абсолютных storage paths и явного разрешения на production key generation; затем создать новую RC version из exact clean commit, а не переиспользовать validation artifacts.

### Сессия 062 — public main и exact remote CI — 2026-08-27

**Разрешение и push:** пользователь явно написал `Разрешаю git push origin main`. Выполнен только push branch `main`; GitHub принял диапазон `8fe6f1b..5d86e14`. `git ls-remote` подтвердил `refs/heads/main = 5d86e14ab648309d84052d005c3732b3b2198783`, local tracking branch синхронизировалась. Tags, Releases и signing keys не затрагивались.

**Remote CI:** поскольку `gh` CLI на host отсутствует, состояние читалось через публичный GitHub Actions REST API по exact `head_sha`. Workflow `Gateway VPN CI`, run `33024593573`, event `push`, завершился `success` для `5d86e14`.

**Job evidence:** `Go, packaging and syntax gates` прошёл checkout exact revision, pinned Go toolchain, formatting, race-enabled suite, vet, сборку всех Linux release entrypoints и JavaScript/shell syntax. `Linux nftables fail-closed gate` прошёл native Linux build, реальное восстановление owned firewall без direct route и `systemd-analyze` verification Gateway/VPS units на pinned Ubuntu 24.04. Обе jobs и все их steps имеют terminal `completed/success`.

**Что изменилось в DoD:** remote CI часть пункта 21 теперь доказана, но сам пункт остаётся `PARTIAL_EXTERNAL`: production-signed immutable GitHub version/assets и real Gateway+VPS `READY` ещё отсутствуют. Остальные H1/H2/VPS/endurance статусы не повышались.

**Следующий шаг:** выбрать безопасное место создания и резервного хранения production/hardware-test Ed25519 private key, отдельно подтвердить полномочие на key generation и затем создать новую immutable version/tag/draft Release. Без этого не создавать долгоживущий key и не переиспользовать disposable validation versions.

### Сессия 061 — requirement-by-requirement completion audit — 2026-08-27

**Причина:** продолжение цели не является явным разрешением на внешнее `git push`. Вместо изменения remote выполнен новый read-only/локальный аудит всех 24 пунктов Definition of Done, этапов 0–6, fixtures, workflows, release evidence и незакрытых gates.

**Результат аудита:** локальная реализация этапов 1–6 присутствует и покрыта 475 Go test functions, fixtures, kernel/netns, disposable systemd и signed lifecycle rehearsals. Создана отдельная DoD evidence matrix: 12 пунктов имеют `PASS_LOCAL`, 10 требуют внешнего продолжения после локального PASS, 2 (`H2 hardware` и `24/72h endurance`) не запускались. Полный проект намеренно не помечен `DONE`.

**Повторная проверка текущего HEAD:** portable Go `1.26.7` выполнил последовательные `go test ./... -count=1` и `go vet ./...` — PASS для всех packages; `git diff --check` — PASS. Первые два вызова focused packaging test использовали ошибочные PowerShell paths к portable Go и завершились до запуска Go; корректный путь `.tools/go1.26.7/go/bin/go.exe` затем дал PASS, файлы не менялись.

**Граница полномочий:** `git push`, tag, GitHub Release и production signing key не создавались. Следующий внешний шаг остаётся прежним: только после явного разрешения пользователя push `main`, затем remote CI; signing identity/version и hardware installation — отдельные решения.

**Следующий шаг:** зафиксировать audit локальным коммитом и сохранить clean worktree. Если явного push permission по-прежнему нет, не изменять GitHub и продолжить только с теми локальными проверками, которые дают новое evidence.

### Сессия 060 — docs-complete reproducible successor и fresh reboot — 2026-08-27

**Exact identity:** clean commit `47297a72488b0cbe6e0c8416e4cd511a6d7f0628`, version `0.1.0-validation.47297a7`, Mihomo `v1.19.30`, disposable signer `f6c6eb142b2a2aa004a480431632c6f816e2b255a91ee463282db3bb89081842`, host contract `db8de3d29a520938f98f2a24baa304b75875ba3606d7fd3c0bb0b267f5eeaa41`. Release metadata содержит DB schema range `1..13` и config generation `1`.

**Reproducible build:** две независимые Linux-сборки `.tools/dist-47297a7-build1` и `build2` содержат по 76 файлов; сравнение каждого relative path, length и SHA-256 дало `DIFF_COUNT=0`. SHA-256: Gateway `cfab176afe7c4367e01c8708b7d47e7131286ee4571e559135537e4c06c9c262`, bootstrap `e278c2a6ab05545fa9f835dd43ca48a084b1edc9b2bd330fcd3d6566ce6fdab2`, VPS `6ba8559f06e152050dc32fd3242a1486b443d9d8cd81830483b2ccc9586b349a`, deploy `a215c80097c5e5eec274e714c5a03b9746bd24d4a2a073e0efcac9c348ef8350`, channel manifest `cc68f990c2f64a7ad4b3d918c92a5b5e4743509ae969be98a27cc2bcf2d0103c`. Оба builder-а независимо проверили Gateway/VPS/channel signatures.

**Signed documentation:** packaged `share/doc/OPERATIONS.md` имеет SHA-256 `28f55a9ef493b60bec074fe5b8d6a6765527af7293ffdc53343c16236c03ebbb`, побайтно совпадает с source и содержит H1 one-modem, H2 multi-modem, topology, leak stop-conditions, failure matrix и evidence table. Installed immutable tree повторно прошёл canonical `release-verify`; manifest содержит 45 signed payload files.

**Fresh Ubuntu 24.04/systemd:** новый privileged container `gateway-vpn-validation-47297a7` создан непосредственно из `gateway-vpn-systemd-rehearsal:ubuntu24-dnsmasq-base` с private cgroup namespace, tmpfs `/run`/`/run/lock`, read-only `/input`, persistent dummy `lan0` и успешно созданным/удалённым `wg-probe`. Installer dry-run и apply проверили release signature, OS/arch/NTP/DNS/resources/dependencies и host preflight. Runtime получил schema `13`, firewall generation `2`, четыре zeroed counters, HTTPS/DNS/DHCP, active management services, inactive Mihomo без active path, `PATH_BLOCKED`, `NRestarts=0` и пустой `systemctl --failed`.

**Idempotency и новый PID 1:** повторный installer вернул exact already-installed no-op; hashes управляемых файлов, inode DB, transaction count, service restart counters и `current/recovery` pointers не изменились. Rootfs сохранён как disposable image `gateway-vpn-validation-installed:47297a7-reboot1`, после чего новый container `gateway-vpn-validation-reboot-47297a7` самостоятельно поднял persistent LAN, firewall/guard, update recovery/timer, broker, watchdog, control и dnsmasq. После штатной watchdog hysteresis состояние стало `HEALTHY`, `policy_source=SQLITE`; `FRESH_SCHEMA_V2_RUNTIME_PASS`, `NEW_PID1_SCHEMA_V2_LIFECYCLE_PASS` и `VALIDATION_NEW_PID1_SIGNED_REBOOT_PASS` получены без failed units.

**Harness-уточнения:** первый дополнительный tail assertion остановился на Windows→Docker quoting шаблона `grep`; предшествующие runtime/signature проверки уже прошли, а исправленный read-only tail завершился success. Первый lifecycle-helper был запущен до завершения watchdog hysteresis и увидел ожидаемый стартовый `DEGRADED` при `consecutive_successes=1`; snapshot показал active services, fresh heartbeats, `NRestarts=0` и пустой failed list. После следующих штатных cycles тот же helper прошёл; production retry/state не менялись.

**Что не заявляется:** GitHub push/tag/release, production key, real Gateway/VPS, APT fetch на произвольном clean host, HiLink/Keenetic/mobile packet capture, USB hotplug/multi-modem failover и 24/72h endurance остаются `NOT_RUN`. Ни один hardware status не повышен.

**Следующий шаг:** локально зафиксировать этот журнал и оставить clean worktree; затем остановиться до явного разрешения пользователя на push `main`. После push — remote CI и отдельное решение по production/hardware-test key storage и новой immutable public version.

### Сессия 059 — completion audit и аппаратный runbook — 2026-08-27

**Обнаруженный пробел:** requirement-by-requirement просмотр текущих документов нашёл устаревшее заявление README и OPERATIONS, будто Linux/netns и signed root/systemd update ещё не выполнялись. После exact session 058 это противоречило фактическому evidence и могло заставить оператора либо повторять уже закрытый Docker gate, либо неверно смешивать его с bare-metal acceptance.

**Исправлено:** README теперь различает пройденные Linux/netns/privileged Docker-systemd gates и незакрытые physical/VPS/provider/endurance gates. В OPERATIONS добавлен полный раздел **Первый аппаратный acceptance**: H1 для реально допустимой конфигурации с одним модемом и H2 минимум с двумя модемами для multi-modem Definition of Done; topology/safe window, immutable release identity, canonical verifier path, WebUI path matrix, bounded sensitive PCAP, IPv4/DNS/IPv6 leak criteria, H1/H2 failure matrix, VPS/WireGuard, traffic spike, 24/72h profiles и обезличенная evidence table. Любой direct packet является stop-condition, а H1 явно не повышает этап 0/H2 до PASS.

**Проверено:** `git diff --check`, баланс Markdown fences и локальные README links — PASS; `go test ./test/packaging -count=1` — PASS. Названия TUN `gateway-vpn-tun`, VPS nft table `gateway_vpn_vps` и release verifier canonical-directory contract сверены с source/packaging. Hardware команды не запускались и никакой physical status не изменён.

**Release identity:** behavioural candidate `3c13b09` и его хеши не изменялись. Поскольку OPERATIONS входит в signed Gateway tree, будущая публичная сборка обязана иметь новую immutable version из актуального clean commit; повторно публиковать `0.1.0-traffic.3c13b09` с другим archive/signature запрещено.

**Следующий шаг:** после явного разрешения пользователя push main → remote CI → отдельное решение по production/hardware-test key storage → новая signed publish version → H1/H2 по runbook.

### Сессия 058 — финальный format-2 lifecycle acceptance — 2026-08-27

**Exact identity:** clean commit `3c13b093718e9e0ac2b38da9617baf05039ba732`, version `0.1.0-traffic.3c13b09`, Mihomo `v1.19.30`, disposable signer `f6c6eb142b2a2aa004a480431632c6f816e2b255a91ee463282db3bb89081842`, host contract `db8de3d29a520938f98f2a24baa304b75875ba3606d7fd3c0bb0b267f5eeaa41`. Две независимые Linux-сборки содержат по 76 файлов и совпадают побайтно. SHA-256: Gateway `f6825c042780ccf72328b6dbf989c4ae65315a4a752fa32509cc16a3d7388ff4`, bootstrap `8ad82bb914c09a39ba666b064b4e867b14475f78b91f5f1b15ff0580f2a5d481`, VPS `f3260966ae5d5589a21d7e1d72a28414e0a880d3562a2182cbfe915210dea4a7`, deploy `19c7c156becc035b6f44747ee9480b30d6e2e9520087eca7d6672a8ef81142e7`, channel manifest `273ad5b0ea8431d4f9e8681916469bcd9ea2affe00b49fe96913c993186b2c9d`.

**Fresh/reboot acceptance:** ранее установленный exact candidate после нового systemd PID 1 повторно дал `FRESH_SCHEMA_V2_RUNTIME_PASS` и `NEW_PID1_SCHEMA_V2_LIFECYCLE_PASS`: schema `13`, firewall generation `2`, четыре nft counters, обязательные services active, Mihomo закрыт без active path, `PATH_BLOCKED`, failed units отсутствуют. Первый helper, помещённый в `/tmp`, был штатно удалён boot-time tmpfiles cleanup; helper перенесён в persistent test path, production state при этом не менялся.

**Совместимый baseline:** создан отдельный test-only commit `baf9823888120b43fcafd8de65716278bece25e6`, version `0.1.0-schema1.baf9823`. Он оставляет SQLite schema `12` и firewall generation `1`, но использует побайтно одинаковые с `3c13b09` production updater code, packaged systemd units и format-2 host contract. Baseline прошёл полный Windows `go test ./... -count=1`/`go vet ./...`, собран и подписан тем же disposable signer; archive SHA-256 `d90e9589f2f26d1e79ec6f036cebc09a1b0c0f9a2ca4c50262dec171471cc0c4`. Metadata baseline/candidate доказанно различается schema maximum `12/13`, но имеет одинаковый `host_contract_sha256`.

**Update/rollback/finalize:** fresh Ubuntu 24.04 systemd rootfs установил baseline через dry-run/apply и получил `SCHEMA1_FORMAT2_INSTALL_PASS`. WebUI staged candidate, signed update мигрировал `12 → 13`, заменил firewall `1 → 2`, оставил `recovery` на baseline и завершил update unit `success/0`. Controlled removal execute bit у candidate `gateway-vpnctl` вызвал `ROLLED_BACK / STABILIZING_RECOVERY_HEALTH_FAILED`: current/recovery вернулись на baseline, DB `12`, firewall `1`, только user counters, `PATH_BLOCKED`; resume поднял management и очистил failed-state. Candidate repaired и повторно прошёл Ed25519 verification. Следующий finalize tick завершился `success/0` и не изменил terminal rollback.

Повторный staging/update снова мигрировал `12 → 13`. Test-only helper через production `JournalStore` безопасно сдвинул только stability deadline, не обходя health/DB/release checks. Finalize перевёл journal в `FINALIZED`, атомарно передвинул `recovery` на `releases/v0.1.0-traffic.3c13b09`; повторный terminal tick остался `success/0`. Сохранённый finalized rootfs стартовал новым PID 1 и дал `FINALIZED_NEW_PID1_HOST2_PASS`: current/recovery указывают на candidate, schema `13`, firewall `2`, четыре counters, management active, Mihomo inactive, `PATH_BLOCKED`, failed units пусты.

**Неуспешные/уточняющие моменты harness:** первые монолитные validation вызовы завершились без итогового marker; read-only snapshot показал уже завершённые update/rollback и корректный durable journal, а после settling те же assertions и отдельный tail-helper прошли. Причина локализована в timing проверочного harness, а не в durable production state; production retry/state не менялись, checker разделён на durable-state и post-settle части. Попытка final audit через `/opt/gateway-vpn/current` была ожидаемо отклонена verifier-ом, который требует canonical real directory; canonical immutable release path прошёл.

**Финальный audit:** root worktree до обновления этого журнала был clean, `git diff --check`/`git fsck` прошли, tracked private-key/generated artifact files и private-key markers отсутствуют. Release tree повторно проверен Ed25519 verifier-ом; Unix modes, отсутствие binary xattrs/file capabilities, shell syntax, installed systemd graph и пустой `systemctl --failed` подтверждены. SBOM subjects, SLSA-style provenance digests, channel artifacts, exact one-command metadata и все ожидаемые SHA-256 согласованы. Gateway binaries собраны Go `1.26.7`, `CGO_ENABLED=0`, `trimpath`; pinned Mihomo имеет Go `1.26.6`, version/hash дополнительно закреплены signed metadata.

**Что не заявляется:** private acceptance key не является production key; GitHub push/tag/release не выполнялись. Real Gateway, конкретный LAN NIC, APT clean-host fetch, HiLink/Keenetic, mobile packet capture, реальный VPS/provider UDP, USB hotplug/multi-modem failover и 24/72h endurance остаются `NOT_RUN`. Текущий результат — локально install-ready candidate для начала этих проверок, а не production `DONE`.

**Следующий шаг:** после явного разрешения пользователя выполнить production signing/publish transaction и запустить exact one-command install на физическом Gateway и VPS; найденные hardware отклонения фиксировать следующей сессией.

### Сессия 057 — exact schema-v2 acceptance и host lifecycle contract — 2026-08-26

**Exact candidate до найденного defect:** clean commit `818007269d233088231f380c151f9ffde00618ca`, version `0.1.0-traffic.8180072`, Mihomo `v1.19.30`, disposable signer `f6c6eb142b2a2aa004a480431632c6f816e2b255a91ee463282db3bb89081842`. Fresh Ubuntu 24.04 install получил schema `13`, firewall generation `2` и четыре authoritative counters; повторный installer был строгим no-op. Новый systemd PID 1 самостоятельно поднял persistent LAN, firewall/guard, update recovery, broker, watchdog, control и dnsmasq; HTTPS/DNS/DHCP и `PATH_BLOCKED` проверены. Результаты: `FRESH_SCHEMA_V2_RUNTIME_PASS`, `IDEMPOTENT_INSTALL_SCHEMA_V2_PASS`, `NEW_PID1_REBOOT_SCHEMA_V2_PASS`.

**Signed update/rollback:** отдельный test-only schema-1 baseline `0.1.0-schema1.b788570` сохранил current trusted updater/systemd lifecycle при DB schema `12` и firewall generation `1`. Signed update `1 → 2` мигрировал SQLite `12 → 13`, переключил current на `.8180072`, оставил recovery на schema-1 и завершил unit `Result=success/ExecMainStatus=0`. Controlled removal execute bit у нового `gateway-vpnctl` заставил recovery выполнить автоматический rollback: current/recovery вернулись на schema-1, journal получил `ROLLED_BACK/STABILIZING_RECOVERY_HEALTH_FAILED`, DB `12`, firewall generation `1`, только user counters. После explicit resume реальные `gateway-vpn.service`, broker socket/service, watchdog, dnsmasq, firewall и guard стали active; HTTPS/CLI отвечали.

**Найденный lifecycle defect:** следующий finalize timer использовал terminal `ROLLED_BACK` journal как ошибку, завершал `gateway-vpn-update-finalize.service` code `1` и через `OnFailure` снова запускал idempotent recovery/resume. Data path оставался закрыт и management восстанавливался, но `systemctl --failed` содержал finalize unit — недопустимый ложный degraded-state для 24/7 supervisor. Отдельный аудит обнаружил более общий инвариант: после successful finalization `recovery` не переводился на новый release, а packaged systemd unit changes не применялись pointer-only updater-ом и не блокировали update.

**Исправление:** terminal states и отсутствие transaction стали typed successful no-op; resume после успешного recovery выполняет `systemctl reset-failed` только для fixed update/finalize units. Finalize после deadline и повторной DB/runtime health-проверки атомарно переводит `recovery` на new current target до фиксации `FINALIZED`. Gateway release metadata format `2` содержит `host_contract_sha256`: digest вычисляется отдельной fixed CLI по bounded flat `packaging/systemd`, повторно вычисляется signer/verifier-ом и сравнивается с current release при staging. Изменённые units теперь отклоняются до mutation как требующие отдельной signed installer-upgrade transaction.

**Reboot/диагностика старого fixture:** во время tail harness Docker передал PID 1 `SIGRTMIN+3`; container завершился `137/OOMKilled=false`. Gateway namespace не содержит watchdog recovery/reboot action, systemd выполнил штатный halt. Новый PID 1 сохранил schema-1 rollback pair, загрузил `PATH_BLOCKED`, поднял все обязательные services без failed units; через несколько cycles watchdog вернул `HEALTHY`, `policy_source=SQLITE`, оба watchdog timestamps ненулевые, `NRestarts=0`. Тестово повреждённый execute bit восстановлен, schema-v2 release снова прошёл полную Ed25519 verification.

**Проверки worktree:** focused update/bootstrap/packaging tests, полный Windows Go 1.26.7 `go test ./... -count=1`/`go vet ./...`, полный offline Linux/amd64 test/vet и Ubuntu 24.04 `systemd-analyze verify` — PASS. Windows bind-mount mode warnings и отсутствующие `/opt` executables в verify image ожидаемы; production release tree modes проверяются exact build. Новый release ещё не собран, поэтому исправление пока не получает install-ready status.

**Следующий шаг:** clean commit → schema-1 compatible baseline с тем же host/updater contract → новый format-2 double-build → fresh install/reboot и signed update/rollback/finalize acceptance без failed units.

### Сессия 056 — полный traffic accounting, firewall schema v2 и update dependency gate — 2026-08-26

**Закрытый пробел PLAN §13.1:** предыдущий runtime публиковал только пользовательские nft totals и Mihomo cross-check, но не сохранял отдельный служебный расход. Firewall schema повышена до `2`; renderer и packaged template создают `user_upload`, `user_download`, `service_upload`, `service_download`. Service rules учитывают modem DHCP, HiLink management, WireGuard endpoint, bootstrap DNS/HTTPS, root DNS, Mihomo DNS/proxy endpoints и established replies через modem interfaces. Пользовательский LAN↔TUN трафик остаётся в отдельной паре counters.

**Runtime и storage:** periodic collector читает четыре kernel counter, использует authoritative epoch `boot_id + nft table handle`, корректно обрабатывает reset/reboot/ruleset replacement и сохраняет session/daily deltas. Migration `000013_traffic_service_counters.sql` добавляет service totals; API current/daily/monthly, CSV и WebUI разделяют пользовательский и служебный расход. Authenticated Mihomo `/traffic` WebSocket и `/connections` остаются диагностическим cross-check; per-subscription attribution в MVP не заявляется.

**Update/rollback firewall schema:** `Quiesce` сначала останавливает control/broker/Mihomo/dnsmasq, затем одной systemd transaction перезапускает firewall+guard из выбранного release. `StartAndHealth`, включая recovery, повторяет transaction после выбора current pointer. Отдельный privileged Ubuntu/systemd probe обнаружил критическую зависимость: transient update unit с `Requires=firewall/guard`, сам выполняющий их restart, был остановлен `SIGTERM` и вошёл в start-limit loop. После замены lifecycle edge на `Wants/After` тот же probe завершился `result=success`; packaging/unit contract теперь запрещает self-terminating `Requires` для этой пары.

**Fixtures:** добавлены минимальные subscriptions, bypass targets, modem discovery/network topology, nftables rulesets и реальные SQLite corruption-модели: page corruption, partial main write, truncated WAL и invalid-checksum WAL. Первичная проверка reproducibility выявила current-time в schema-v1 runtime row и случайные WAL salts/checksums. Timestamp зафиксирован; валидный WAL теперь получает постоянную salt-пару и полный SQLite rolling checksum заголовка и каждого frame. Regression-test дважды генерирует независимые деревья; дополнительный прямой запуск подтвердил `DATABASE_FIXTURES_BYTE_IDENTICAL count=7`.

**Проверено:** текущий worktree прошёл Windows Go 1.26.7 `go test ./... -count=1` и `go vet ./...`; native Linux/amd64 в pinned builder — полный `go test ./... -count=1` и `go vet ./...`; WebUI `node --check`, shell syntax и fixture parser/migration suite — PASS. Реальный Ubuntu kernel nftables fixture загрузился; production traffic reader получил `user_upload=12345`, `user_download=67890`, `service_upload=111`, `service_download=222`. Privileged netns guard восстановил удалённый/flushed owned table только в `PATH_BLOCKED` и не создал direct route.

**Что ещё не заявляется:** hardware traffic spike, фактический расход probes, Mihomo/nft расхождение на мобильном uplink, real HiLink/Keenetic/VPS и endurance остаются `NOT_RUN`. Exact signed candidate `618d617` предшествует schema `2` и не должен выдаваться как текущая сборка.

**Следующий шаг:** итоговый diff/security audit → clean local commit → новый exact reproducible signed candidate → fresh Ubuntu 24.04 install/reboot и обязательный signed update/rollback acceptance со сменой firewall schema `1 ↔ 2`.

### Сессия 055 — финальный локальный install-ready candidate — 2026-08-26

**Exact identity:** commit `618d6177812727afc6289d5c0ec8d295bc8368bc`, version `0.1.0-endurance.618d617`, Mihomo `v1.19.30`, disposable acceptance signer `f6c6eb142b2a2aa004a480431632c6f816e2b255a91ee463282db3bb89081842`. SHA-256: Gateway archive `8b17a6fc3d759dcf513f2b3838e752df159b47aba06cd4df6e6d625e3020b0ce`, bootstrap `060af139bc900e283955a7cc91561906e00bdab5a33dd3a5ba1eff72a2c9a0d9`, VPS archive `14f07aaa9f8fc57613f58b40d00fde20645bd6643981b9268d303d35d259cc78`, deploy `4524b96adba8b6c7548d8b6b8db1a47fb39fdf751874fc899e29bba6154e5d90`, channel manifest `289c1948391ad68731f3a7906fb9e5f16d9a8abc2f5408ed57aaf28ebd5082cc`.

**Build gate:** две независимые offline сборки из clean detached clone на Linux filesystem, с одним Mihomo/key/toolchain/cache input, прошли self-verification всех четырёх roles/channel. Рекурсивные path/size/SHA-256 всех `76` файлов совпали. Host `dist/` содержит вторую каноническую сборку; первая сохранена gitignored как evidence.

**Fresh install:** новый Ubuntu 24.04/systemd rootfs имел `is-system-running=running`, NTP `yes`, test-only `lan0`. Archive dry-run, signature/full-tree/LAN preflight, fresh DHCP apply и strict idempotent повтор завершились code 0. После нескольких полных cycles supervisor показал `overall_state=HEALTHY`, `policy_source=SQLITE`; отсутствие модемов/Mihomo классифицировано `EXTERNAL_CONNECTIVITY_FAILURE`/`NOT_APPLICABLE`, firewall остаётся `PATH_BLOCKED`. HTTPS, DNS TCP/UDP, DHCP, owners/modes и completion marker подтверждены; `NRestarts=0`, forbidden systemd events и `data-plane reconciliation failed` отсутствуют.

**New PID 1:** rootfs после graceful shutdown сохранён только как disposable local image и запущен новым systemd PID 1 с test-only persistent dummy `lan0`; signed release tree не менялся. Boot firewall, guard, update/network recovery, broker, watchdog, control, dnsmasq, timer, exact current/recovery pointers, fresh root/control heartbeat, SQLite/dnsmasq ownership, LAN, HTTPS security headers, DNS/DHCP sockets и отсутствие active install marker проверены. `gateway-vpn-watchdog.service` и `gateway-vpn.service` имеют ненулевые `WatchdogTimestampMonotonic`, `NRestarts=0`, status/control age `12s/3s`; rejected notification, namespace error, start-limit и false data-plane warnings отсутствуют. Итог: `FINAL_NEW_PID1_ACCEPTANCE_PASS`.

**Harness-only false negative:** первая финальная combined boot command зависела от порядка строк `ss` (`8443` ожидался перед `53`) и завершилась exit 1 при полностью корректных values. Order-independent повтор прошёл; product state не изменялся.

**Ограничение handoff:** bundle подписан disposable acceptance key и channel с test interface `lan0`; GitHub tag/release не существует, commits не push-ились. До публичной одной команды нужно получить фактический LAN interface, решить permanent backed-up signing identity и получить явное разрешение пользователя на push/tag/release. Hardware/VPS/endurance gates остаются `NOT_RUN`.

**Следующий шаг:** release distribution decision → immutable GitHub draft/publish/verify → физическая установка и hardware test plan.

### Сессия 054 — reproducibility PASS, exact install rejection и systemd lifecycle fix — 2026-08-26

**Reproducibility:** exact bundle `0.1.0-endurance.aa15477` из commit `aa154774ac0e4a7745a58c5142534ba861a96b7b`, Mihomo `v1.19.30` и disposable signer `f6c6eb142b2a2aa004a480431632c6f816e2b255a91ee463282db3bb89081842` собран дважды без сети. Канонические SHA-256 совпали: Gateway `dc233f01ac50d4bb66c6345e08b3c4e3fbbec67a1ad18bae2de5ecb54c5e9084`, bootstrap `b31a0d9ca350b5d3b12f4a29da1fdfd586e8411c50e3bdc7d6546d54964e7b0e`, VPS `462340cd71c9658fb384f9f57e950ee246aaff8c3773536af4c51387ead78606`, deploy `d91b321b735e47568ae9a800ea253b0aabd9cb6c3a63b82c77662a805c0d4317`, channel `5970cfbb33239768fcaa09fed1b246e0ac32177fc15dfda321c0000c17c820ac`. Рекурсивное сравнение `76` файлов по path/size/SHA-256 — PASS.

**Неуспешные build-environment попытки:** Windows bind mount сначала представил private key с широким Unix mode, и builder штатно отказал до создания release. Следующий offline run был ошибочно запущен без сохранённого module cache и остановился на запрещённой сетевой загрузке. Ещё одна валидно подписанная сборка использовала унаследованный `umask 077`: release-tree bytes совпали, но tar modes отличались от канонических `0755/0644`, поэтому archives/channel были отклонены. Повтор с одноразовым key `0600`, затем `umask 022` воспроизвёл первый bundle побайтно; неуспешные outputs сохранены только в gitignored `.tools` и не считаются кандидатами.

**Exact Ubuntu rejection:** новый privileged Ubuntu 24.04/systemd rootfs сообщил `running`, NTP `yes`; exact archive dry-run и signature/tree/LAN preflight прошли. Fresh apply не объявил успех и штатно откатил first-install transaction. Default journal доказал ранний асинхронный start control из `gateway-vpn-update-recovery.service`, последующий restart ordered `network-recovery`, остановку watchdog и удаление его `RuntimeDirectory`; control получил `status=226/NAMESPACE` на отсутствующем `/run/gateway-vpn-watchdog`, а повторные recovery jobs достигли `start-limit-hit`. Namespaced journal отдельно зафиксировал rejection notification от Go runtime thread при `NotifyAccess=main`. После failure release/config/units были удалены rollback-ом, active marker архивирован как `rolled-back-*`; прямой путь не открывался.

**Исправление:** update recovery больше не самозапускает broker/control; resume unit и installer остаются явными владельцами возобновления. Installer regression фиксирует последовательность `update recovery → network recovery → broker → watchdog → control`. Control теперь `Requires/PartOf` watchdog, watchdog сохраняет shared runtime directory через restart, а оба Go notify services используют `NotifyAccess=all`, ограниченный собственным service cgroup. Operations/Security дополнены boot order, bounded recovery policy, external-outage/maintenance suppression, default-off durable-budget reboot и командами диагностики.

**Проверено для fix worktree:** focused packaging test — PASS; полный Windows Go 1.26.7 `go test ./... -count=1` и `go vet ./...` — PASS; полный offline native Linux/amd64 `go test ./... -count=1` и `go vet ./...` — PASS; Ubuntu 24.04 `systemd-analyze verify` исправленного graph завершился code 0. Windows bind-mount warnings о mode unit-файлов и отсутствующих `/opt` executables относятся к read-only source mount; предыдущий staged exact tree verify проверял production modes/paths. Новый exact signed candidate и PID 1 apply/idempotency/reboot smoke ещё не выполнены.

**Первый исправленный signed candidate:** clean commit `b2ea2fec8978ba5934c6475b15a3fd80aae80219`, version `0.1.0-endurance.b2ea2fe`, signer `f6c6eb142b2a2aa004a480431632c6f816e2b255a91ee463282db3bb89081842`; Gateway archive `7184765087f65def3622822e59718246a8839f33b9dcf488397be8942801727d`, bootstrap `3c10882686b0d151a42d71470993cb6ea54b7b9dcf73ff962a46e142fad9ee87`, VPS archive `3bac66151c7657276b18ef045976a897d260252545d44de45e13991383e10d1f`, deploy `f4f55506f2af4f4f585f579e00c22f6cae42fecca018ba3801d7bf157a987609`, channel `af0e0d0cf3ed07c992fc524027e4aeeae779cef1188e21727f7aebb93638e86f`. Две независимые offline сборки на clean Linux filesystem совпали для всех `76` файлов. Fresh Ubuntu 24.04 dry-run/apply и strict idempotent reinstall завершились code 0. До reboot supervisor показал `HEALTHY`, внешний outage отдельно, все long-running `NRestarts=0`, `PATH_BLOCKED`, HTTPS/DNS/DHCP/ownership PASS; journal не содержит rejected notify, start-limit или namespace failure.

**Новый PID 1:** установленный rootfs после graceful shutdown загружен новым systemd PID 1 с test-only dummy `lan0`; release tree не менялся. Firewall/guard/update+network recovery/broker/watchdog/control/dnsmasq/timer, fresh heartbeats, SQLite mode, completion marker, LAN, `PATH_BLOCKED`, HTTPS security headers, DNS/DHCP sockets и `NRestarts=0` подтверждены. Первая объединённая проверка дважды дала harness-only false negative: successful oneshot `network-recovery` ожидался active вместо `inactive/result=success`, затем `pipefail + grep -q` преобразовал нормальный producer `SIGPIPE` в exit 1; отдельный values dump доказал PASS соответствующих assertions.

**Quality defect после boot:** при отсутствии первой Mihomo generation authoritative nft gate уже был закрыт, но best-effort selector `REJECT` возвращал ошибку недоступного API каждые пять секунд. Leak/restart отсутствовали и watchdog оставался `HEALTHY`, однако журнал рос без полезного сигнала. Worktree теперь подавляет только secondary selector error после доказанного успешного firewall block; ошибка authoritative block по-прежнему вызывает emergency fail-closed и возвращает обе причины. Два focused regression-теста, повторные полные Windows и native Linux `go test ./... -count=1`/`go vet ./...` — PASS; clean commit и последний signed smoke ещё требуются.

**Следующий шаг:** clean commit → последний unique signed double-build → abbreviated fresh install/new-PID1 и отсутствие повторных data-plane warnings. `aa15477` и `b2ea2fe` не устанавливать как финальный кандидат.

### Сессия 053 — bounded self-health supervisor и полный локальный gate — 2026-08-26

**Реализовано:** migration v12 добавила safe-default watchdog policy. Новый `internal/watchdog` содержит server-side bounded ranges, audited repository, query-only live policy source, fixed component allowlist, jittered checks, failure/success hysteresis, durable restart/reboot windows, maintenance и external-connectivity classification, sanitized runtime status и root system probe. Watchdog проверяет control/reconcile heartbeat, SQLite quick-check, firewall guard/ruleset, broker, optional dnsmasq, Mihomo/TUN и disk/memory/FD pressure. SQLite failure восстанавливается только через fail-closed и fixed control restart; resource pressure и внешний outage не reboot-eligible.

**Privilege/recovery boundary:** новый `gateway-vpn-watchdog.service` работает root с primary group `gateway-vpn`, fixed executable/paths и только `CAP_NET_ADMIN`, `CAP_SYS_BOOT`, `CAP_DAC_READ_SEARCH`; arbitrary unit/command/path из SQLite/API отсутствуют. Restart/reboot attempt атомарно сохраняется и fsync-ится до `systemctl`; `PATH_BLOCKED` обязателен перед любой опасной recovery action. `host_reboot_enabled=false` по умолчанию, выключение отменяет pending reboot, durable 24h budget переживает supervisor restart и блокирует reboot loop. Installer, interrupted-install recovery, update health/rollback и uninstall включают новый unit/status/history lifecycle.

**Control/API/UI:** control service переведён на `Type=notify` и `WatchdogSec=120s`; SIGHUP запускает coalesced reconcile, пятисекундный heartbeat публикуется только при доступной DB и свежем completed reconcile. Неожиданный выход любого critical background worker завершает process для bounded systemd recovery. Добавлены `GET/PUT /api/v1/settings/watchdog`, `GET /api/v1/system/watchdog`, OpenAPI, CSRF/strict JSON/audit, карточка «Самоконтроль 24/7» с component status, budgets и отдельным подтверждением host reboot. Diagnostic bundle включает redacted policy/status; stale runtime file не показывается как healthy.

**Synthetic failure matrix:** покрыты external outage без recovery/reboot, maintenance suppression, threshold → reconcile → fail-closed → fixed restart, все restartable components, отказ fail-closed, durable-history write failure, restart budget после process restart, default-off reboot, continuous critical delay/grace, pending cancellation, non-reboot-eligible failures, reboot budget/loop suppression, success hysteresis, readiness только после первого status и fixed privileged command matrix.

**Найдено и исправлено во время gate:** migration v12 обнаружила старые schema-11 expectations в diagnostic/update/backup fixtures; pre-migration fixture сохранён семантически как v11→v12, а compatibility checks не ослаблены. Lifecycle audit нашёл отсутствующий `CAP_DAC_READ_SEARCH` для root process с урезанным capability set и `state.db 0600`; capability добавлена без `CAP_DAC_OVERRIDE`. Boot graph сначала позволял supervisor гоняться с update/restore/network recovery — добавлен строгий `Before/After`. Restart budget первоначально сохранялся после `systemctl restart`; commit перенесён до privileged action. Старый status file первоначально мог выглядеть healthy после смерти supervisor; API/diagnostics/update/installer теперь требуют freshness.

**Проверки текущего worktree:** полный Windows `go test ./... -count=1` и `go vet ./...` — PASS; native Linux/amd64 Go 1.26.7 `go test ./... -count=1` и `go vet ./...` из read-only source/module cache — PASS; `node --check`, `git diff --check`, Ubuntu 24.04 `bash -n` всех scripts/netns/systemd scripts — PASS; Ubuntu 24.04 `systemd-analyze verify` всего Gateway/VPS unit/socket/timer graph — PASS; privileged netns текущего Linux binary восстановил удалённый/flushed owned nftables ruleset только в `PATH_BLOCKED`, quarantined LAN и не создал direct route — PASS. Первая offline Linux попытка с ошибочно выбранным пустым `/go/pkg/mod` и `GOPROXY=off` завершилась setup failure; повтор с сохранённым `gomodcache-linux` прошёл полностью, поэтому эпизод классифицирован как неверный test-run environment, не product failure.

**Что ещё не заявляется:** новый watchdog ещё не запускался из exact signed tree под новым Ubuntu PID 1; kill/hang/reboot-loop systemd acceptance, fresh install/idempotency/reboot, hardware HiLink/Keenetic/VPS и 24/72h endurance остаются `NOT_RUN`.

**Следующий шаг:** clean commit → exact signed bundle → clean Ubuntu 24.04 archive dry-run/apply/idempotency/new-PID1 watchdog smoke. После PASS подготовить однострочную команду первой физической установки.

### Сессия 052 — отдельный systemd state root для dnsmasq — 2026-08-26

**Четвёртая signed candidate:** exact clean commit `b8d192fad5775ec0a4644f36acbfd0b6f5b89b51`, version `0.1.0-endurance.b8d192f`, Gateway archive SHA-256 `6f729cd10017c91fd5e5f19540d57268eabd326c49eeeb3663a815c76928d3b3`; full build/signature/channel и fresh Ubuntu dry-run PASS. Apply снова fail-closed откатился на `dnsmasq: cannot open or create lease file ... Permission denied`.

**Доказанная причина и реализация:** transient systemd unit стабильно работает с отдельным `/var/lib/gateway-vpn-dnsmasq`, owner `gateway-vpn-dns:gateway-vpn`, mode `0700`: dnsmasq остаётся active, создаёт lease и привязывает DHCP sockets к `lan0`. Lease path изменён одновременно в packaged template и safe-apply renderer; unit получил `StateDirectory`/`StateDirectoryMode`; sysusers home, network rollback sandbox, installer conflict/existing/post-apply validation, interrupted-install recovery и uninstall синхронизированы. Старый tmpfiles child удалён, dnsmasq больше не пишет lease в общий application state root.

**Проверено для текущего diff:** полный Linux/amd64 `go test ./... -count=1`, `go vet ./...`, `bash -n` install/recovery/uninstall scripts, `git diff --check` и Ubuntu 24.04 `systemd-analyze verify` — PASS. Системный Go в текущем desktop runtime отсутствовал, поэтому актуальный Windows suite не запускался; предыдущий exact commit проходил Windows suite.

**Пятая signed candidate:** clean commit `89c6a8d6b2dc149aeeb5a0ab6218c2e4ec26fa30`, version `0.1.0-endurance.89c6a8d`, signer `e1da4f2da556de241086378873243a3e4bbfe4cbb3503864c875270bd4509517`, Gateway archive SHA-256 `b86d808793b98259e15d9e7588868588c576ac1619ce7996daf3c0a9b795e968`, channel manifest SHA-256 `1084918daf24fbf72a8c020d72fda598696e28a09eca3444ba6f035349440b8e`; full bundle verify и archive-based dry-run PASS. Fresh apply завершился code 0: control/firewall guard/broker/dnsmasq active, Mihomo condition-inactive, state root `gateway-vpn-dns:gateway-vpn 0700`, DNS TCP/UDP 53, DHCP UDP/67 и HTTPS/8443 sockets, API HTTP 200, `PATH_BLOCKED`, LAN CIDR/pointer/report и `NRestarts=0` доказаны.

**Найдено обязательной idempotency проверкой:** повторная команда сначала отклонила собственный LAN:53 listener. После inspection также зафиксировано, что dnsmasq создаёт lease `0644`, не `0600`; закрытый parent `0700` не позволяет другим UID прочитать файл. Port gate перенесён только в fresh branch; existing branch теперь сравнивает exact generated config и фактические owner/group/modes. Focused packaging/networkapply, затем полный Linux `go test ./... -count=1`, `go vet ./...`, shell syntax и `git diff --check` — PASS.

**Следующий шаг:** commit idempotency fix, новый шестой exact signed candidate, fresh apply + повторная команда + новый PID 1/reboot. Только после полного installer PASS начинается реализация self-health supervisor PLAN §9.8.

**Шестая signed acceptance:** clean commit `d471c12594f7279882c3a5eb8703eec67768da3b`, version `0.1.0-endurance.d471c12`, signer `e1da4f2da556de241086378873243a3e4bbfe4cbb3503864c875270bd4509517`, Gateway archive SHA-256 `29e267419cfbf49771f0fdc79e429e196d25f005145b42ea4b09403bee0dd4ed`, channel manifest SHA-256 `97e6e37267634f958fd2cde2f9a78e17a399b7a77839a2343642d803644a9376`; full four-role/channel verification PASS. На новом clean Ubuntu 24.04 rootfs archive dry-run, apply и повторный strict existing-install audit завершились code 0.

**Boot acceptance:** установленный rootfs запущен новым container/PID 1. Первый diagnostic boot намеренно не имел физического LAN до `multi-user.target`: control fail-closed завершился без direct leak, firewall/dnsmasq остались безопасны. Финальный disposable fixture добавил только test-only systemd `.netdev`, чтобы моделировать существующий до network-online физический `lan0`; signed release tree не менялся. Automatic boot получил `192.168.200.1/24`, active control/firewall guard/broker/dnsmasq/update timer, condition-inactive Mihomo, DNS TCP/UDP 53, DHCP UDP/67, HTTPS/8443 с HTTP 200, `PATH_BLOCKED`, state root `0700`, lease `0644`, отсутствующие active install/authorization artifacts и `NRestarts=0` всех long-running units. Это `DOCKER_SYSTEMD_PASS`, не замена bare-metal reboot.

**Следующий шаг:** реализовать принятый self-health supervisor PLAN §9.8; installer defect закрыт.

### Сессия 051 — точный stop-and-confirm протокол уровня мышления — 2026-08-26

**Уточнение пользователя:** текущий уровень всё время оставался `xhigh`; уведомление Codex о возможности вернуться на `High` не являлось подтверждением переключения.

**Зафиксировано:** любое последующее повышение или понижение требует полной остановки проектной работы до явного подтверждения пользователя. До такого подтверждения сохраняется последний подтверждённый уровень. Текущий подтверждённый уровень — `xhigh`, продолжение критического signed/systemd/endurance блока разрешено.

**Signed acceptance:** disposable signer-ом собран и повторно проверен полный bundle `0.1.0-endurance.43a4bd0` из exact clean commit `43a4bd088c003e6b09b5943e39140d009cc6af53`, Mihomo `v1.19.30`; Gateway archive SHA-256 `cfce8420207c55b836e8863cd316d2b8db3ea8f030a0dac9cab159f638cf1744`. Ubuntu 24.04/systemd dry-run прошёл. Apply дошёл до management readiness, но завершился `Installed Gateway DHCP service is not active`; first-install transaction штатно откатила units, nftables, pointers и LAN state.

**Найдено:** namespaced journal доказал `dnsmasq: cannot open or create lease file ... Permission denied`. `/var/lib/gateway-vpn` имел `0700 gateway-vpn:gateway-vpn`, поэтому service UID не мог traverse к собственному child. Первый fix `0710` с private children `0700` прошёл полный Windows и network-disabled Linux test/vet. Из него собран второй exact bundle `0.1.0-endurance.f6023b9`, archive SHA-256 `cbac5a7a88126f4e7cd877ceffd1955da0114408110fa8b2f359d666d069c4d8`; dry-run PASS, apply снова штатно откатился с тем же lease error.

**Уточнённая причина:** фактические mode и supplementary group корректны, `setpriv` и exact systemd filesystem sandbox создают файлы. Transient unit стабильно запустил dnsmasq, когда systemd сразу назначил dedicated UID/GID и config не выполнял повторный privilege drop. Отдельно выявлен общий `dnsmasq.service` rehearsal image на wildcard port 53. Fix переносит identity в systemd, удаляет `CAP_SETUID/GID`, заменяет clean dependency на `dnsmasq-base` и добавляет pre-mutation port conflict gate. Полный Windows/Linux test/vet, Linux shell syntax и Ubuntu 24.04 `systemd-analyze verify` — PASS; third signed acceptance ещё не выполнена.

**Третья signed candidate:** exact clean commit `3c528237fecae2d1a0384516fca84385fc6ae860`, version `0.1.0-endurance.3c52823`, Gateway archive SHA-256 `606a6019a779392910108579b9e7018e6fff9955ebc2e80ea0cc85464b0b7a0e`; full bundle/signature/channel PASS. Fresh Ubuntu image содержит `dnsmasq-base`, не содержит package/unit `dnsmasq` и не имеет wildcard listener. Негативный test с временным TCP/53 listener сначала выявил ложный PASS combined `ss -lntu`; исправленные отдельные `ss -ltn`/`ss -lun` дали точный pre-mutation отказ, install marker/current/config отсутствовали. Focused package test и offline Bash syntax PASS.

**Новый scope:** пользователь потребовал круглосуточный самоконтроль, автоматическое восстановление и гибкие watchdog settings. PLAN §9.8 теперь фиксирует bounded ladder, component states, default-off durable-budget host reboot, запрет reboot из-за внешнего outage, API/WebUI/audit/diagnostic и crash/hang/reboot-loop gates. Реализация ещё не начата и не считается `PASS`.

**Следующий шаг:** commit port-listener fix, четвёртая unique signed dry-run/apply/reboot/readiness на clean `dnsmasq-base` image; затем реализация supervisor до harness smoke и 24-часового developer endurance.

### Сессия 050 — воспроизводимый endurance harness и DB evidence — 2026-08-26

**Реализация:**

- diagnostic bundle получил fixed `database/retention.json` со schema generation 1: точная active policy 7/30 дней, 24 месяца, version limits, rows/oldest/latest для health/events/traffic, aggregate LKG/CANDIDATE/RETAINED/FAILED/other, active non-LKG и over-retention counts;
- storage evidence содержит только DB/WAL bytes, page size/count, freelist и live-page bytes; реальный database path не сериализуется, недоступный/несогласованный storage делает diagnostic section incomplete;
- `internal/endurance` реализует TLS 1.3 API client без proxy/redirect, in-memory secure cookie/CSRF, automatic pre-expiry logout/login, bounded strict runtime JSON и diagnostic ZIP verification по Content-Length/header SHA-256/manifest file SHA-256/path/mode/size;
- evaluator фиксирует minute sampling, 30-minute warm-up/windows, restart и sample gaps, шесть растущих окон goroutines/FD, устойчивый RSS/heap/live-object slope, 10%+32 MiB byte threshold, SQLite cutoffs/version excess и live-page growth;
- runner пишет новый `0700` run directory, minute-fsynced `0600` NDJSON, start/end ZIP, progress state и final report; backend error text, credentials, cookie/CSRF и endpoint в artifacts не записываются;
- `test/endurance` читает пароль только из absolute current-user single-link `0600` file, очищает caller buffer после client construction и не принимает password через argv/environment; exact developer/release profiles нельзя изменить flags;
- `smoke` всегда возвращает только `SMOKE_PASS`/`endurance_gate=false`; release требует `hardware-gateway` и exact typed confirmation, но документация отдельно запрещает считать эту attestation автоматическим доказательством hardware;
- CI дополнительно собирает Linux/amd64 VCS-stamped harness, а Operations/Security получили точные команды, artifacts и threat-boundary.

**Проверки:**

- adversarial/unit tests покрывают strict metrics JSON, inconsistent counters, ZIP/path/mode/hash/unknown fields, retention cutoffs, restart/gap и все resource-growth classifiers, fixed profile validation, durable success/failure state и отсутствие backend secret text;
- полный Windows `go test ./... -count=1` и `go vet ./...` — PASS;
- полный offline Linux/amd64 `go test ./... -count=1`, `go vet ./...` и `go build -trimpath -buildvcs=true ./test/endurance` — PASS;
- отдельный Linux end-to-end CLI smoke реально выполнил TLS login, secure cookie+CSRF, 11 samples, два verified diagnostic downloads, logout и создал `SMOKE_PASS` report за 200 ms;
- post-commit offline Linux build из clean `58b9cea46907eaa8f6e7e7f5955a5c005e3bdae6` подтверждён через `go version -m`: `GOOS=linux`, `GOARCH=amd64`, exact `vcs.revision`, `vcs.modified=false`;
- `git diff --check` — PASS. Ни 24-часовой, ни 72-часовой run не выполнялся и не засчитывается.

**Следующий шаг:** зафиксировать harness clean commit, затем на повышенном уровне провести exact signed/versioned Ubuntu systemd candidate build/install и запустить 24-часовой developer endurance. Hardware/release gates остаются `NOT_RUN`.

### Сессия 049 — bounded DB retention и production lifecycle — 2026-08-26

**Реализация:**

- добавлен отдельный `internal/retention` с валидируемой policy: raw health 7 дней, events 30 дней, daily traffic 24 месяца (`0` оставляет traffic unlimited), active LKG и все `CANDIDATE` защищены, для каждой подписки сохраняются два последних `RETAINED` и два последних `FAILED`;
- каждая категория удаляется отдельным bounded SQL statement/transaction; один pass ограничен 500 time-series rows и 20 version rows, `VACUUM` worker не вызывает;
- version row и зависимые nodes сначала атомарно удаляются из SQLite, затем удаляется только проверенный non-symlink payload directory `0700`; interruption между операциями исправляет следующий orphan scan;
- orphan inventory просматривается полностью в пределах общего portable-backup bound 4096, поэтому поздний orphan не блокируется большим числом ранних referenced payload; временные `.payload-*` текущего refresh никогда не удаляются;
- production `Runtime` получил восьмой cancellable worker: первый pass выполняется сразу, известный backlog повторяется через 250 ms малыми batch, стабильное состояние проверяется каждые 10 минут, постоянная ошибка не создаёт tight loop;
- журналирование содержит только bounded counts и sanitized error, без subscription/version IDs или содержимого payload.

**Проверки:**

- targeted Windows tests `internal/subscription`, `internal/retention`, `internal/app` — PASS; проверены точные retention boundaries, protected states, batch convergence, unlimited traffic, idempotent delete, orphan после referenced payload, сохранение in-flight directory, immediate worker и context stop;
- полный Windows `go test ./...` и `go vet ./...` — PASS;
- полный offline Linux/amd64 `go test ./...` и `go vet ./...` без сети — PASS;
- первый холодный параллельный Linux run один раз превысил прежний односекундный test-only timeout polling firewall guard; isolated Linux test затем прошёл 20/20, timeout harness увеличен до 3 секунд, повторный полный Linux test+vet прошёл;
- `git diff --check` — PASS. Реальные 24/72-часовые endurance runs не запускались и не считаются выполненными.

**Следующий шаг:** подготовить exact-build endurance harness, выполнить 24-часовой developer run и оценить RSS/FD/goroutines/heap/live objects вместе с SQLite integrity, WAL/DB size и фактической сходимостью retention. Реальные Gateway/VPS/HiLink/Keenetic и production release gates не изменились.

### Сессия 048 — измеримая endurance telemetry и completion-аудит retention — 2026-08-26

**Реализация:**

- добавлен authenticated read-only `GET /api/v1/system/runtime-metrics` со schema generation `1`, timestamp/uptime, goroutines, Go heap/stack/system, mallocs/frees/live objects и GC totals;
- Linux implementation безопасно читает только `/proc/self/statm` и `/proc/self/fd`, возвращая RSS и steady-state FD count; на других development OS Linux-only поля отсутствуют;
- response строится из фиксированного allowlist и не содержит argv, environment, filesystem paths, network endpoints, config, identities или secrets;
- отдельный session limiter разрешает 20 samples в минуту и возвращает стабильный `RUNTIME_METRICS_RATE_LIMITED`/`Retry-After`, поэтому частые `runtime.ReadMemStats` нельзя использовать как простой authenticated DoS;
- OpenAPI содержит exact response schema, а Operations — минутный sampling, 30-минутный warm-up/medians, 24h developer и 72h release gates, leak thresholds, 12h session reauthentication без увеличения production lifetime и обязательные start/end SQLite diagnostics.

**Проверки:**

- полный Windows `go test ./...` и `go vet ./...` — PASS;
- полный offline Linux/amd64 `go test ./...` и `go vet ./...` — PASS; Linux handler test фактически получил положительные RSS/FD из `/proc`;
- auth test подтверждает `401` без session, фиксированный набор полей, положительные counters, RFC3339Nano timestamp и `429` на 21-м запросе одного окна;
- OpenAPI route/reference/security contract и packaging tests — PASS.

**Обнаруженный незакрытый критерий:**

- completion-аудит разделов 12.3/19/20 показал, что schema содержит `health_samples`, `events`, `traffic_daily_totals` и immutable subscription versions, но production worker удаления по срокам/количеству ещё отсутствует;
- поэтому 24h endurance пока не запускается: отсутствие монотонного роста RSS/FD/goroutines не докажет критерий «размер БД соответствует retention policy»;
- следующий локальный шаг — bounded small-transaction retention с cleanup защищённых payload directories, затем unit/runtime tests. Hardware/release gates остаются внешними и не считаются выполненными.

### Сессия 047 — Gateway/VPS uninstall, preserve, reinstall и purge — 2026-08-26

**Gateway exact signed `.27`:**

- использован завершивший restore/reboot disposable Ubuntu 24.04 container с exact signed `0.1.0-systemd.27`; dry-run явно сообщил, что runtime data сохраняются без `--purge-data`;
- обычный uninstall остановил/удалил все owned units, nft table, `wg-mgmt`, persistent LAN config, program/config tree и install report, восстановил прежние forwarding/IPv6 sysctl, удалил добавленный `192.168.200.1/24` и сохранил исходный up-state `lan0`;
- `/var/lib/gateway-vpn/state.db`, subscriptions и marker сохранились; новый boot не восстановил ни один owned artifact, а embedded `gateway-vpnctl status` открыл сохранённую БД read-only и вернул `PATH_BLOCKED`;
- raw SHA main SQLite-файла, ошибочно снятый до graceful service stop, ожидаемо изменился после WAL checkpoint и дал false negative; acceptance исправлен на logical/read-only open и последующий application startup integrity gate;
- signed installer dry-run/apply поверх сохранённого state прошёл, management вернулся, marker сохранился, startup integrity завершился успешно и path остался `BLOCKED`;
- повторный uninstall с `--purge-data` удалил оба state roots, но сначала создал `/root/gateway-vpn-state-<UTC>.db` как `root:root 0600`; backup открылся embedded CLI до и после reboot, owned state не восстановился.

**VPS current uninstaller:**

- установленный signed VPS `0.1.0-systemd.8` имеет `scripts/uninstall-vps.sh` SHA-256 `da091a9bb1f9adf86a87e143cc3aa8e84d2bcfbd775455baac1defb60ad14991`, byte-for-byte совпадающий с current source;
- обычный uninstall сохранил byte-identical `root:root 0600` `/etc/wireguard/wg-mgmt.conf` и `/var/lib/gateway-vpn-vps`, удалил owned nft/interface/units/program/config и восстановил прежние IPv4/IPv6 forwarding values; reboot не запустил recovery;
- signed dry-run/apply строго распознал preserved private key и requested peers, переустановил VPS без смены config, поднял owned firewall и `wg-mgmt` с ожидаемыми `/32` AllowedIPs;
- только явный `--purge-keys` удалил WireGuard config и state root; reboot подтвердил отсутствие key, interface, nft table, units и recovery.

**Итог и границы доказательства:**

- runtime uninstall requirement закрыт для privileged Docker/systemd, включая безопасные defaults и destructive confirmations;
- bare-metal cleanup, произвольный package set и current full VPS release rebuild не подменяются этим тестом; последний допустим как current-uninstaller acceptance именно из-за доказанного byte identity.

### Сессия 046 — exact signed `.27` destructive restore/recovery acceptance — 2026-08-26

**Reproducible signed fixture:**

- локальный journal commit `18be89f` зафиксировал предыдущую unsigned acceptance; исполняемый release намеренно собран из clean code commit `ddcc407d72971299b5bbec5ec986105fb34a2695`;
- `0.1.0-systemd.27` собран с `--network none`, read-only source/module mounts и read-only rootfs; build/work cache находились в tmpfs, private Ed25519 key — только в `noexec` tmpfs и был уничтожен до успешного выхода builder;
- signer fingerprint `cf88bcabd71d83539bb191e6146e576ca31192a0cdf12d9d35210511c2020163`, archive SHA-256 `b7fa2172400496fb0fe90b8d747f8c4b94f97859e761b67d16b126abac5093f8`, public-key file SHA-256 `99b4d61fb2151d90c59abdca5832cb42f593fb2f8876b2e709cabdbe9a6b339f`; all 44 manifest files прошли detached Ed25519 verification;
- disposable key не является будущим production identity; его public key и fixture предназначены только для acceptance.

**Clean install, staging и success:**

- первый контейнер создан прямо из `gateway-vpn-systemd-rehearsal:ubuntu24-reboot`, а не через `docker commit` установленного Gateway; clean release verify, installer dry-run и apply — PASS, report `INSTALLED_NOT_READY`, Mihomo inactive;
- Web API: обязательная смена bootstrap password, encrypted portable backup, size/SHA header verification, truncated/corrupt upload rejection, live-state mutation и verified `STAGED` — PASS;
- после нескольких reboot `STAGED` сохранил byte-identical config/secret/marker, не создал root journal/`last-restore`, вернул management и не включил Mihomo;
- explicit Apply восстановил DB/config/secrets/subscriptions, отозвал старую сессию, удалил временного пользователя, создал verified pre-restore snapshot и оставил пустой TUN gate/`PATH_BLOCKED`; следующий reboot сохранил `last-restore=APPLIED` и работающий HTTPS management.

**Host-side power cut и retry:**

- второй контейнер также установлен в новом clean rootfs; watcher дождался durable `APPLYING`, остановил helper после `applied_items=3`, затем host выполнил `SIGKILL`; Docker подтвердил exit `137`;
- новый boot выполнил rollback к mutation state, оставил operation `STAGED / RESTORE_INTERRUPTED_ROLLED_BACK`, отозвал authorization nonce, удалил root journal и orphan `.recovery-record-*`, вернул broker/WebUI и сохранил Mihomo/TUN закрытыми;
- hash state за отдельные пять секунд не изменился: автоматического повторного Apply нет;
- новое explicit Apply после rollback было принято и завершилось success; финальный reboot сохранил `APPLIED`, отсутствие pending/journal/temp, active management и `PATH_BLOCKED`.

**Проблемы стенда и итог:**

- две ранние staging-reboot команды дали false negative из-за ошибочного ожидания отсутствующего `reason_code` и Windows/`bash` quoting в диагностическом `grep`; состояние продукта было прочитано отдельно, ожидание исправлено, после чего полный hash-based reboot прошёл. Эти ошибки не меняли live restore state;
- exact-signed Docker restore/recovery gate закрыт. Уровень мышления можно вернуть с `xhigh` на `High`; следующий блок — реальный Gateway/VPS/HiLink/Keenetic и production release/endurance.

### Сессия 045 — destructive restore, найденный auto-retry и boot-safe recovery — 2026-08-26

**Exact signed baseline и обнаруженный дефект:**

- exact signed `0.1.0-systemd.26` собран из `9235e42afcea6ba79bb46cdf25830e05e7d987b1`, signer fingerprint `6670666c1a1f61c3d0e1d441241e25c605d79b390ab9ce9633589d151d200ecf`, archive SHA-256 `ec41158bff049dbb39aef63028cfcc0cc821e616a23c951a678758bcb984569a`; private key существовал только в `noexec` tmpfs и уничтожен;
- clean Ubuntu 24.04/systemd install, mandatory bootstrap password change, portable encrypted backup, corrupt/truncated rejection, verified staging without live mutation, API `202 APPLY_SCHEDULED`, root restore DB/config/secrets/subscriptions, session revocation, pre-restore snapshot, management resume, empty TUN gate и clean reboot — PASS;
- host-side `docker kill --signal SIGKILL` после durable `APPLYING`, `applied_items=3`, exit `137`: первый boot правильно выполнил rollback, но второй dependency-start применил backup автоматически. Дополнительно доказано, что простой `STAGED` upload также мог примениться после reboot.

**Исправления:**

- `0725413` добавил `APPLY_REQUESTED`, power-loss-safe `AuthorizeApply`, WebUI authorization до broker trigger, `--boot-recovery`, запрет `VerifyPending` для обычного `STAGED` и обязательную новую авторизацию после failure;
- `dd56903` связал operation/root journal одноразовым nonce, добавил durable `ROLLED_BACK`, отказ от чужого active journal, идемпотентный повтор rollback и безопасное продолжение только после нового explicit Apply;
- `ddcc407` очищает строго распознанные root-owned atomic temp records после SIGKILL и оставляет boot helper active/exited через `RemainAfterExit=yes`, поэтому несколько `Wants=` не создают второй recovery pass;
- Web API никогда не возвращает authorization nonce; failed rollback не переводится в `STAGED`, пока filesystem rollback реально не завершён.

**Проверки актуального `ddcc407`:**

- полный Windows и offline Linux/amd64 `go test ./...` + `go vet ./...` — PASS; весь unit graph — `systemd-analyze verify` PASS;
- disposable Ubuntu/systemd, production Web API и current binary: обычный `STAGED` reboot сохранил одинаковые config/secret/last-restore SHA-256 и mutation marker, management вернулся, root journal не создан;
- success path восстановил marker/config/secrets, удалил pending/journal, оставил Mihomo inactive и TUN gate пустым. Первая попытка в клонированном image получила ожидаемый Docker OverlayFS lower-layer `EXDEV`; после verified upper-layer copy-up тех же disposable каталогов production restore прошёл. Это artifact метода `docker commit`, а не production restore defect;
- power-cut clone остановлен в `APPLYING` после трёх replacements и уничтожен host-side с exit `137`; boot вернул mutation DB/config/secrets, записал `STAGED / RESTORE_INTERRUPTED_ROLLED_BACK`, удалил nonce/journal/temp, сохранил прежний `last-restore`, поднял broker/WebUI и за пять секунд не выполнил auto-retry;
- следующий staged reboot с latest cleanup binary дал ровно один новый `remains STAGED`, `Result=success`, `ActiveState=active`, пустой transaction root и работающее management.

**Ограничение и следующий шаг:**

- latest matrix пока `unsigned behavioral acceptance`: попытка exact-signed `.27` не стартовала, потому что среда автоматически отклонила Docker approval до запуска builder. Нужен явный пользовательский allow для offline builder с read-only source/module mounts и одноразовым ключом в tmpfs;
- после exact signed `.27` retest можно завершить xhigh restore/recovery block и вернуться на High; hardware/VPS/endurance gates останутся отдельным production path.

### Сессия 044 — exact signed update, finalize, rollback и power-cut recovery — 2026-08-26

**Цель:** выполнить не synthetic, а root-owned systemd update transaction на clean signed Gateway и довести success/failure/reboot/interruption paths до проверенного состояния.

**Неуспешные acceptance-попытки и исправления:**

- `.13 → .14`: staging прошёл, но snapshot завершился `PRE_UPDATE_SNAPSHOT_FAILED`; rollback вернул `.13`, управление и fail-closed firewall. Transient hardened-unit probe доказал `chmod /var/lib/gateway-vpn: operation not permitted`: DB helper безусловно chmod уже правильные Gateway-owned `0700/0600` paths, а unit намеренно не имел `CAP_FOWNER`. Commit `0f08b99` делает chmod только при неверном mode и не расширяет capability set;
- `.15 → .16`: snapshot, candidate DB и release switch дошли дальше, но control получил `Permission denied` на новом binary; rollback вернул `.15`+DB. Причина — `UMask=0077` превращал создаваемые updater-каталоги в `0700 root:root`. Commit `17a011f` явно нормализует все real release directories в `0755`, сохраняет files `0755/0644` и повторно проверяет signed tree;
- `.17 → .18`: core update впервые дошёл до `STABILIZING`, но post-check нашёл enabled/inactive finalize timer. Installer активировал его только через `enable` после запуска `timers.target`. Commit `ef44363` использует `enable --now`, проверяет timer в install readiness и запускает fixed timer после successful update;
- `.19 → .20`: clean update, finalize, forced health rollback и finalized reboot прошли. Настоящий host-side power cut в durable `HEALTH_CHECKING` восстановил `.19`+DB, но broker/control остались inactive: rollback quiesce отменил их ожидавшие boot jobs. Commit `e5b8934` после successful recovery ставит fixed services обратно в очередь через dependency-safe `systemctl start --no-block`;
- первые два disposable watcher запуска не считаются power-cut evidence: 12-секундное окно закончилось до старта update unit, затем `SIGKILL` PID 1 из того же PID namespace был проигнорирован Linux init semantics. Финальная методика сначала `SIGSTOP` updater после durable journal, затем host-side `docker kill --signal SIGKILL` всего container namespace.

**Финальный exact signed gate:**

- source commit `e5b8934b8cd700970d2e80be1f442ec7577c20ec`; disposable versions `.21/.22`; signer fingerprint `41e0f3acd01f7e6d9fc0db3703bb4ccfdc78dd4497d44abc3f34f70b1a633b0b`;
- baseline/candidate archive SHA-256: `0b4417183091c0d2f5e5d4572615bf45a718352f149747931abda298e0aba817` / `386da20c827d3cc63093495b97b8b8828e95ab9d13a9a172cba173c821285be6`;
- build был offline с read-only module cache; private Ed25519 key находился только в `noexec` tmpfs, не экспортировался и уничтожен после container exit;
- clean Ubuntu 24.04/systemd `.21` install проверил full signed manifest, preflight, fail-closed nftables, persistent LAN, management HTTPS и сразу active finalize timer;
- Web API login потребовал сменить bootstrap password; multipart staging прошёл с CSRF и доказанно не изменил `current`, DB либо `/opt/.../.22`;
- `.21 → .22` завершился `STABILIZING`: `current=.22`, `recovery=.21`, verified pre-update SQLite snapshot, `root:root 0755` directories, files `0755/0644`, `.22` реально исполнился от `gateway-vpn`, staging очищен, timer active, TUN gate пуст;
- production finalize unit после test-only валидного ускорения deadline завершил transaction как `FINALIZED`; forced candidate health дал `ROLLED_BACK / NEW_RELEASE_HEALTH_FAILED`; current mismatch дал `ROLLED_BACK / FINALIZE_CURRENT_MISMATCH`; finalized reboot оставил `.20` current и `rolled_back=false`;
- финальный exact power cut: updater остановлен в durable `HEALTH_CHECKING`, Docker host уничтожил namespace с exit `137`, затем тот же rootfs загрузился новым PID 1 и аппаратоподобным `lan0`. Recovery journal стал `ROLLED_BACK / BOOT_OR_PROCESS_RECOVERY`, `current/recovery=.21`, DB status прошёл, broker/control/firewall/timer active, TUN gate пуст, namespaced journal сообщил `rolled_back=true`.

**Регрессия и ограничения:**

- после каждого исправления полный Windows и offline native Linux `go test ./...` и `go vet ./...` — PASS; отдельный Linux umask test доказал directories `0755`, executable files `0755`, остальные `0644` и повторный `VerifyRelease`;
- systemd units прошли `systemd-analyze verify`; transient proof на реально сломанном boot стенде подтвердил автоматическое возобновление broker/control;
- local `main` содержит commits сверх `origin/main`; push не выполнялся без отдельного разрешения пользователя;
- disposable Docker/systemd gate не заменяет bare-metal power cut, permanent signing identity, public immutable GitHub release и реальное оборудование.

**Следующий шаг:** destructive restore success/failure/reboot/power-cut acceptance на exact signed Ubuntu 24.04, затем реальные Gateway/VPS/HiLink/Keenetic gates и endurance.

### Сессия 043 — exact signed `.13`, clean one-command и WireGuard acceptance — 2026-08-26

**Воспроизводимый signed bundle:**

- exact source commit — `b6e0610056e72938d7d00f768882a0f2f0565567`, version — `0.1.0-systemd.13`, Mihomo — pinned `v1.19.30`;
- две независимые offline-сборки с `GOPROXY=off` и read-only local module cache совпали byte-for-byte; disposable Ed25519 private key находился только в `noexec` tmpfs, не экспортировался и уничтожен;
- signer — `31c8040b71d979a9531912beb54f7035c0e29f53c89d539eb526542e115fc422`, channel manifest SHA-256 — `ae9a6af65f644b9add9b17683c04f162f15e0f9f3249046950f6618085e499a2`;
- Gateway/VPS archive SHA-256 — `03eb82539b2899fe88b571bcdf32e5ab02d0fe6688c16c231b070d215126df93` / `62855cb9a1966705b0c818717aa6f2d98bfb3b7e427267428f3b60a7faf86a99`; bootstrap/deploy — `dc41fe3aefd10389af75c8baf846bf1cfa31f8c676d10157ecc552bc5308b5f6` / `4b8b4311f401703ac7e07ff519b800862d3396f6ffd47bfbf4e0ac6b8016419c`.

**Полностью clean one-command acceptance:**

- новый s013 stand стартовал без `/root/.config/gateway-vpn` на admin host и без managed paths на Gateway/VPS; CA/channel hash и pinned SSH host fingerprints совпали до запуска;
- exact launcher сам создал `/root/.config` и `/root/.config/gateway-vpn` с mode `0700`, а `admin.conf` — `0600`; `.pending`, ControlMaster sockets/directories и живые mux processes после завершения отсутствовали;
- Gateway и VPS роли применились, WireGuard config был сформирован без вывода private material. Итог ожидаемо был `INSTALLED_NOT_READY`: `wireguard_configured=true`, но до synthetic modem отсутствовали handshake и internet path; единственные diagnostics — `WIREGUARD_HANDSHAKE_PENDING` и `MODEM_SUBSCRIPTION_PATH_PENDING`;
- оба installed artifacts сообщили exact version/commit `.13`/`b6e0610`; Gateway WebUI локально возвращал HTTP 200, VPS firewall и `wg-quick@wg-mgmt` были active;
- новый TCP/22 к Gateway получил timeout. Следовательно, workflow сохранил доступ через заранее установленный pinned ControlMaster, но не открыл SSH hole в nftables;
- `gateway-vpn-dnsmasq.service` остался inactive, потому что custom two-host fixture намеренно не передал `--enable-dhcp`; DHCP policy по контракту является явным install choice, поэтому это не дефект роли.

**Exact installed-binary synthetic acceptance:**

- helper собран текущим portable Go 1.26.7 из current source с `GOPROXY=off`, `CGO_ENABLED=0`, `-mod=readonly` и `-trimpath`; SHA-256 внутри/снаружи контейнера совпал: `5d035744ddeb634f6d44f932efb67768eaac77525ad6fe99db27fef09ef8e359`;
- остановлен только непривилегированный `gateway-vpn.service`, чтобы Docker `eth1` не был возвращён Modem Manager в offline; production broker/socket, boot firewall и firewall guard оставались active, installed signed binaries не заменялись;
- helper от UID `gateway-vpn` через штатные SQLite repository и root broker создал `synthetic-modem-a`: `eth1`, `8.8.8.0/24`, gateway/DNS `8.8.8.1`, table `1101`, fwmark `0x1101`, `MODEM_READY`, management state `REACHABLE`;
- numeric rule observer увидел priority/table `1101`, fwmark `0x1101`, protocol `186`; table 1101 содержала default, link и exact endpoint route через `eth1`, а marked lookups для `1.1.1.1` и `8.8.8.8` выбрали table 1101, gateway `8.8.8.1`, source `8.8.8.2`. Owned protocol-186 routes в main table отсутствовали;
- nftables set содержал только exact tuple `"eth1" . 0x00001101 . 8.8.8.8`; `active_tun_interfaces` оставался пустым, поэтому без subscription/Mihomo internet path не открылся;
- Gateway `wg-mgmt` получил `10.80.0.2/32`, endpoint `8.8.8.8:51821`, fwmark `0x1101`, fresh handshake и snapshot transfer `92 B received / 360 B sent`;
- VPS `10.80.0.1/24` видел peer endpoint `8.8.8.2:54393`, allowed IP `10.80.0.2/32`, fresh handshake и snapshot transfer `244 B received / 92 B sent`; `ip route get 10.80.0.2` выбрал `wg-mgmt`. Второй admin peer `10.80.0.10/32` ожидаемо оставался без handshake;
- после apply production broker/socket, firewall и guard сохранили `active`.

**Стендовые особенности, не являющиеся production-дефектами:**

- системного Go в Windows `PATH` нет; helper успешно пересобран зафиксированным portable toolchain из `.tools`;
- первый `docker cp` с Windows-style relative path сообщил code 0, но не создал ожидаемый `/run` file; повтор с POSIX-style path в `/tmp` с последующей проверкой SHA-256 сработал;
- четыре zombie `ssh` process не имели sockets/resources: fixture admin PID 1 — `sleep infinity`, который не reaps children. Живых SSH master processes не было.

**Не считается выполненным:** synthetic Docker network не заменяет реальный HiLink/operator/public VPS UDP и packet capture; пустой TUN gate не доказывает internet path через Mihomo/subscription; update, restore/power-cut и production GitHub release ещё не прошли фактический acceptance.

**Следующий шаг:** exact signed update acceptance на systemd стенде, затем restore/recovery и interruption/power-loss simulations.

### Сессия 042 — signed `.12` и clean-admin zero-to-ready boundary — 2026-08-26

**Reproducible signed `.12`:**

- source commit — `d591be08bd3edf522791b3ab5a9fa22df37e4e10`, version — `0.1.0-systemd.12`, Mihomo — прежний pinned `v1.19.30` из trusted local builder image;
- builder работал с `GOPROXY=off`, read-only local module cache и двумя независимыми clone из verified Git bundle; один disposable Ed25519 key находился только в `noexec` tmpfs;
- две полные Gateway/VPS/bootstrap/deploy/channel сборки совпали byte-for-byte; private key не экспортирован и уничтожен вместе с контейнером;
- signer — `5097b0e8694d282e75d7129bc61dede1d03e2721805ee1a484fca53ad32e4a10`, channel manifest SHA-256 — `60d25b7569aa9aa591fca07427bcb4050b6ae6aa919b1d59802054527aeb7f1e`;
- Gateway/VPS archive SHA-256 — `5eb663d61f68d978610792f0c18b902fa610afb1bd9309fb4a42aeeff75e8c26` / `022da96da38667d8de122e7d4fb9ff3623b7b7c46166f3c2e449cece5125a0d6`; bootstrap/deploy — `3670290d8635929b7b804a15549d60afaac0a69f328facfddf812f9cf33a452b` / `072659c4c40e764ac607ae17dc4ea9897cd7bf70d2560fbae3f0adb3eabefb61`.

**Неуспешные builder попытки сохранены как evidence:**

- первый offline run показал, что image не содержит module cache; второй mount указывал в `/go/pkg/mod`, тогда как фактический `GOMODCACHE` — `/root/go/pkg/mod`;
- следующая попытка не смогла запустить helper из намеренно `noexec` key tmpfs; после переноса helper внутрь clone clean-worktree gate закономерно отверг untracked binary;
- финальная схема оставила key tmpfs `noexec`, helper поместила в ephemeral `/tmp`, source clones сохранила clean и успешно завершила double-build. Ни один ранний отказ не создал public artifact или сохранившийся private key.

**Clean s012 выявил следующий дефект:**

- старый s011 удалён; созданы новые isolated admin/modem networks и clean Ubuntu 24.04 Gateway/VPS/admin containers. Обе роли подтвердили отсутствие всех managed paths до запуска;
- HTTPS mirror вернул exact `.12` manifest hash, SSH ED25519 fingerprints совпали с pinned Gateway/VPS значениями, generated command прошёл `bash -n`;
- exact one-command deploy завершился до SSH и до любой role mutation с `administrator config directory must be a protected real directory`: на действительно clean admin отсутствовал `/root/.config/gateway-vpn`;
- это классифицировано как дефект one-command-from-zero, а не operator prerequisite; ручной `mkdir` не применялся, Gateway/VPS остались clean.

**Исправлено и проверено:**

- `PrepareAdminIdentity` теперь создаёт недостающую directory chain по одному component с mode `0700`, проверяет каждый существующий component через `Lstat`, не следует symlink и не начинает создание непосредственно под group/other-writable parent;
- существующий final directory по-прежнему обязан быть real и без group/other permissions; existing config/pending identity остаются idempotent и никогда молча не заменяются;
- добавлены tests nested clean creation, exact `0700`, world-writable boundary, non-private final directory и symlink component без mutation target;
- полный Windows `go test ./...`, `go vet ./...` и нативный Linux `internal/deploy` suite — PASS.

**Следующий шаг:** commit, signed `.13`, новый clean admin/Gateway/VPS run без подготовленного config directory; затем exact signed synthetic WireGuard handshake.

### Сессия 041 — signed `.11`, реальный iproute2 defect и synthetic WireGuard handshake — 2026-08-26

**Clean signed orchestration завершён:**

- из commit `d3c0cf0090b9a2ec743e7390ff4e7dfd5e2c4c14` собран disposable bundle `0.1.0-systemd.11`; signer — `8a893b99b382f8fda4a78a9d03b54368b7a7faa111ebf8665ef0fc54e779e4ed0`, channel manifest SHA-256 — `54928e57ac53817fd18259db1a027478033c1ae53ed18c272d67f5bab9df90d4`;
- Gateway/VPS archive SHA-256 — `d22fa99b0cce4013d910390495c3932430881d4fbf0092a2c16f46d8445af655` / `415e2a3e6cb2826117de5e6adb1f6569b7abb492216905ccdc2d54b80f887863`; bootstrap/deploy SHA-256 — `c97c2a0fd89041681ea81913d56a92f0a3210d045dd3099e16458c4847c3fa79` / `3827bca59bb272266937f0ce96f3141be814923d8d8793ffee7ef91b1ff91b12`;
- exact deploy на полностью новых s011 Gateway/VPS прошёл оба preflight, применил обе роли, создал/обменял ключи без вывода private material и настроил WireGuard; итог ожидаемо вернул code 3 и `INSTALLED_NOT_READY`, потому что реальный модем и subscription/path отсутствовали;
- readiness report: Gateway/VPS `APPLIED`, `wireguard_configured=true`, `wireguard_handshake=false`, `internet_path_active=false`, admin config `CONFIGURED`; diagnostic codes — только `WIREGUARD_HANDSHAKE_PENDING` и `MODEM_SUBSCRIPTION_PATH_PENDING`;
- private ControlMaster sockets/directories и mux processes после workflow отсутствовали; новый TCP/22 на Gateway по-прежнему получал timeout, то есть continuity исправлена без firewall hole;
- Gateway admin/secret files и VPS `wg-mgmt.conf` имели ожидаемых владельцев и mode `0600`; install reports не содержали private keys.

**Synthetic modem gate и найденный дефект:**

- ignored helper, собранный из текущего source, открыл production SQLite API от пользователя `gateway-vpn`, вызвал `modem.Repository.Adopt`/`ApplyLease` и создал одну запись: `eth1`, `8.8.8.0/24`, gateway `8.8.8.1`, table `1101`, fwmark `4353`, `MODEM_READY`;
- обычный Modem Manager правильно вернул эту запись в offline, поскольку Docker `eth1` не является USB/HiLink discovery device. Для изолированного backend gate остановлен только непривилегированный `gateway-vpn.service`; root broker, socket, nft guard и fail-closed firewall оставались active;
- helper от штатного UID вызвал production broker `SyncRouting`; backend создал правильные route/rule, но вернул `ROUTING_SYNC_FAILED`. Фактический `ip -json -4 rule show` показал `protocol:"bgp"`, а `ip -json -4 route show table all protocol 186` вернул уже отфильтрованные owned routes без поля `protocol`;
- observer переведён на numeric rule output `ip -N -json`; filtered route decoder принимает отсутствующее поле protocol как контракт kernel-side filter, но при наличии по-прежнему принимает только exact 186. Unit fixtures теперь содержат фактическую Ubuntu JSON форму.

**Фактическая проверка исправления:**

- временный Linux/amd64 бинарник с fix заменил только broker binary в disposable s011; это проверка кандидата, а не signed acceptance;
- повторный helper завершился с `management_reachability_state=REACHABLE`;
- Gateway имел rule `fwmark 0x1101 lookup 1101 proto bgp`, table 1101 с default/link/endpoint routes через `eth1`, а `ip route get` для `1.1.1.1` и endpoint с mark `0x1101` выбрал table 1101 и source `8.8.8.2`;
- nft set содержал exact tuple `"eth1" . 0x00001101 . 8.8.8.8`; `wg-mgmt` получил `10.80.0.2/32`, endpoint `8.8.8.8:51821`, fwmark `0x1101`, свежий handshake и ненулевой двусторонний transfer;
- VPS видел тот же Gateway peer с endpoint `8.8.8.2:<ephemeral>`, fresh handshake, `10.80.0.2/32` и route через `wg-mgmt`; второй admin peer оставался без handshake, как и ожидается для не поднятого fixture;
- Windows `go test ./...`, `go vet ./...` и нативный Ubuntu/Linux `internal/dataplane` test binary — PASS.

**Не считается выполненным:** exact signed `.12` ещё не собран; synthetic `eth1` и временная остановка Modem Manager не заменяют реальные USB hot-plug/HiLink/operator/VPS/provider-firewall gates. Internet path остаётся blocked без подписки и квалифицированного Mihomo node.

**Следующий шаг:** commit fix, signed `.12`, новый clean orchestration и повтор synthetic handshake уже на неизменённом signed installed binary; затем update/restore/recovery acceptance.

### Сессия 040 — post-firewall SSH continuity и private ControlMaster lifecycle — 2026-08-26

**Strict bootstrap fix подтверждён:**

- из commit `def1c7f97df88ee09a03f1f6e243c923ecd09662` собран disposable bundle `0.1.0-systemd.10`; signer — `a6def8a6616e72e5906d2a731aea144bbb175bb6746c51585879878f8ec618ec`, channel manifest SHA-256 — `7109d40c4d9418471b9ecac188ee6f312ac159b9316f5ec0252bd4e7b49e2f42`;
- Gateway archive начинается с `bin/` и содержит 60 actual entries, VPS — с `bin/` и 30 entries; отдельные `.`/`./` отсутствуют, public output hashes совпали, disposable private signing key уничтожен;
- полностью новый s010 Gateway/VPS/admin/HTTPS стенд подтвердил clean managed state, fixture CA/channel hash и прежние pinned ED25519 host keys;
- exact Gateway bootstrap по pinned SSH прошёл strict extraction, verification всех 43 файлов, Ubuntu/LAN host preflight и вернул `DEPENDENCY_PLAN_VALIDATED` без mutation.

**Следующий production defect воспроизведён и классифицирован:**

- полный exact deploy прошёл Gateway/VPS external preflight, применил Gateway и остановился в `GATEWAY_KEY_PREPARE`; report: Gateway `APPLIED`, VPS `NOT_RUN`;
- Gateway остался безопасно `INSTALLED_NOT_READY`, firewall/broker/control active, SSH daemon продолжал слушать TCP/22, pending WireGuard deploy key отсутствовал, VPS managed state отсутствовал;
- owned nft input chain имел policy drop и только `ct state established,related` для существующих connections; новый pinned SSH connect с admin `172.30.8.4` получил timeout. Тем самым доказана transport continuity причина, а не installer/key defect.

**Исправлено в source:**

- `gateway-vpn-deploy` создаёт новый private bounded `0700` OpenSSH control directory; первый pinned command включает `ControlMaster=auto`, а последующие фазы используют тот же authenticated established TCP session после firewall apply;
- ControlPersist ограничен общим 45-минутным deploy window. После orchestration launcher посылает обоим hosts `-O exit`, ждёт удаления sockets, удаляет directory и при cleanup failure возвращает отдельный redacted diagnostic вместо ложного успеха;
- TCP/22 в Gateway/VPS firewall не открывается и пользовательские SSH options/ProxyCommand по-прежнему не принимаются;
- добавлены tests обязательных ControlMaster/ControlPersist/ControlPath/host-key/identity options и отказа insecure control directory; OPERATIONS описывает lifecycle.

**Проверки и стендовые ошибки:**

- Windows: deploy package tests, полный `go test ./...`, `go vet ./...`, `git diff --check` — PASS;
- первая Linux test-container попытка имела fixture `/tmp` с `noexec`, поэтому Go test binaries не запускались; повтор с executable tmpfs раскрыл слишком длинный test-only `t.TempDir` для консервативного Unix socket bound;
- test fixture переведён на короткий private `os.MkdirTemp`; финальные Linux `go test ./internal/deploy ./cmd/gateway-vpn-deploy ./test/packaging` — PASS. Production socket path из `/tmp/gateway-vpn-ssh-control-*` оставался в bound.
- реальный fixture OpenSSH создал master socket после первой команды к clean VPS, `-O check` подтвердил master PID, `-O exit` удалил socket, private directory стал пустым и был удалён — PASS.

**Следующий шаг:** commit, signed `.11`, полностью clean orchestration rerun; затем WireGuard handshake/modem fixture и проверка удаления SSH control sockets.

### Сессия 039 — настоящий bootstrap обнаружил несовместимый root tar entry — 2026-08-25

**Новый disposable artifact и чистый стенд:**

- Docker Desktop подтверждён как Linux/x86_64 Engine `29.7.2`; локальная sandbox boundary потребовала отдельного разрешения на Docker API, но не изменения production code;
- из clean commit `11ec459fd6af5d96eac6cbf17d3f39cfea099fc3` собран и повторно verified bundle `0.1.0-systemd.9`; итоговый disposable signer — `62a88df4fd086c5da2568e44f842f86e4fb673b486cf6179d9ebb69129d678c3`, channel manifest SHA-256 — `963caac852004eddffd24eeb68e427d7e64dd4a0a3049f00e87732c5504b7f7c`;
- первый build успешно завершился, но публичный output находился в `/work` tmpfs и после остановки container закономерно исчез до `docker cp`; private key при этом был уничтожен. Повторный build экспортировал только public artifacts через отдельный bind mount, после чего builder удалён; все 10 top-level SHA-256 совпали, private-key-like output отсутствует;
- старые containers/networks удалены, созданы clean Gateway/VPS/admin/HTTPS containers и новые bridge networks; fixture CA, HTTPS manifest hash и заранее известные ED25519 SSH host fingerprints подтверждены на всех трёх машинах, managed state до запуска отсутствовал.

**Результат exact orchestration:**

- новый outer launcher реально начинается с `bash --norc -ceu`; прежняя `/etc/bash.bashrc: PS1: unbound variable` больше не воспроизводится;
- orchestration безопасно остановилась в `GATEWAY_ROLE_PREFLIGHT` до managed mutation с `independent bootstrap verification failed`;
- отдельный pinned SSH dry-run получил ту же ошибку. Все скачанные manifest/signature/public key/Gateway archive имели точные size и SHA-256; channel signature и обычная verification распакованного signed tree прошли;
- read-only diagnostic на том же source установил точную границу: `ExtractReleaseArchive` вернул `release archive contains an unsafe path, link, or mode` до первого файла;
- tar inspection показал причину: оба builders выполняли `tar ... .`, добавляя отдельную запись `./`. Strict extractor после нормализации намеренно отклоняет пустой root path; ранее systemd harness предварительно распаковывал archive и потому не проверял этот bootstrap boundary.

**Исправлено в source:**

- `build-release.sh` и `build-vps-release.sh` теперь собирают отсортированный массив реальных top-level entries и передают tar только его, без `.`/`./`;
- packaging regression требует explicit top-level enumeration и запрещает старый root-archiving pattern;
- `go test ./test/packaging`, полный `go test ./...` и `git diff --check` — PASS.

**Следующий шаг:** commit, новый clean disposable signed bundle, clean orchestration rerun и только после успешного bootstrap — проверка post-firewall SSH continuity и Gateway↔VPS WireGuard handshake.

### Сессия 038 — первый exact SSH orchestrator run и remote bashrc regression — 2026-08-25

**Стенд:** отдельные admin/Gateway/VPS Linux containers, strict key-only SSH с заранее сверенными ED25519 host fingerprints, краткоживущее локальное TLS-зеркало exact signed `.8` assets и отдельная изолированная сеть будущего WireGuard endpoint. Private SSH/TLS fixture keys находятся только в ignored `.tools`; GitHub Release не создавался.

**Результат первого запуска:**

- signed channel сгенерировал одну exact deploy command; admin проверил deploy SHA-256, channel signature/signer и HTTPS trust;
- SSH prerequisite phase прошла на двух разных pinned destinations;
- первая Gateway role preflight остановилась до создания `/etc/gateway-vpn`, `/opt/gateway-vpn`, state, nft table или interface;
- ручной повтор той же signed preflight раскрыл точную ошибку: `/etc/bash.bashrc: line 7: PS1: unbound variable`;
- причина — Bash, запущенный через `sshd` remote command, может читать `.bashrc` даже для non-interactive command; generated `bash -ceu` включает `nounset` до чтения Ubuntu bashrc.

**Исправлено:**

- Gateway, VPS и outer deploy commands теперь начинаются с `bash --norc -ceu` и не зависят от пользовательских/system-wide remote dotfiles;
- добавлены assertions для всех трёх generated command classes;
- package tests `internal/distribution`, `internal/deploy` и полный `go test ./...` — PASS.

**Следующий шаг:** commit/push, новый clean disposable signed bundle и полный повтор orchestration с clean Gateway/VPS; после него проверить post-firewall SSH continuity и реальный WireGuard handshake.

### Сессия 037 — signed VPS Ubuntu matrix, idempotency и fresh boot — 2026-08-25

**Цель:** реально проверить подписанный VPS role на поддерживаемых Ubuntu systemd profiles, сохранив отдельными Docker и real-host acceptance boundaries.

**Проверено на Ubuntu 22.04, 24.04 и 26.04:**

- official Ubuntu base images закреплены по digest; systemd/NTP, nftables, WireGuard tools и clean rootfs запускались в отдельных privileged containers;
- signed VPS archive `0.1.0-systemd.8` из commit `9eca9bb` прошёл legacy SHA-256 и strict Ed25519 exact-tree verification;
- dry-run проверил OS/profile, NTP, DNS, RAM/disk, packages, public endpoint, WireGuard kernel/tools, nft syntax, UDP/51821, sysctl и path conflicts без mutation;
- apply локально создал VPS private key, immutable release pointer, `root:root 0600` `wg-mgmt.conf`, два exact peers `10.80.0.2/32` и `10.80.0.10/32`, owned nft table и `INSTALLED_NOT_READY` report;
- `net.ipv4.ip_forward=1`, IPv6 forwarding выключен, connected routes обоих peers идут через `wg-mgmt`, firewall и WireGuard units active/enabled, first-install recovery disabled после completed marker;
- точный повтор исходной apply-команды вернул already-installed с теми же peer contract/key identity; restart firewall/WireGuard сохранил key, routes и ruleset;
- installed rootfs каждой версии запущена новым контейнером с новым PID 1 и пустым `/run`: firewall и `wg-mgmt` поднялись автоматически без ручного запуска, marker/ephemeral authorization отсутствовали;
- единственный failed unit после fresh boot — стандартный `systemd-networkd-wait-online.service`, поскольку Docker `eth0` не управляется networkd; application units полностью active и acceptance PASS, поэтому этот Docker-only degraded state не приравнен к VPS host defect.

**Ubuntu 20.04:**

- vanilla official image с актуальным Pro client прошёл signed release/NTP/host prerequisites, затем ожидаемо остановился сообщением `Ubuntu 20.04 is not attached to Ubuntu Pro`;
- после отказа отсутствовали `/var/lib/gateway-vpn-vps`, managed config, `wg-mgmt` и owned nft table — mutation не началась;
- положительный 20.04 gate требует предоставленного Pro-attached, non-expired VPS с enabled `esm-infra`/`esm-apps` и без pending updates; Docker не подменяет это внешнее право/состояние.

**Неуспешные стендовые попытки:**

- прямой `docker cp` signed directory с Windows NTFS выставил всем файлам executable bit; strict exact-tree verifier правильно отказал, поэтому acceptance использовал production `.tar.gz`, сохраняющий Unix executable contract;
- первые 24.04/26.04 fixtures положили archive/public key внутрь release root; verifier правильно отклонил два лишних файла до mutation. После размещения bootstrap inputs вне signed tree оба dry-run прошли без изменения production code.

**Не проверено:** реальный cloud VPS/provider firewall/reboot, внешний UDP/51821, Gateway↔VPS handshake, Debian 12 и положительный Ubuntu 20.04 Pro gate.

**Следующий шаг:** SSH orchestrator на двух Linux-машинах и реальный WireGuard handshake через изолированную Docker network; затем journal/commit/push и возврат с `xhigh` на `High`, если acceptance не выявит критических дефектов.

### Сессия 036 — signed Gateway systemd install, idempotency и fresh boot — 2026-08-25

**Цель:** реально выполнить Gateway installer/recovery boundaries в Ubuntu 24.04 systemd, не выдавая Docker за bare-metal/hardware acceptance.

**Сделано и опубликовано:**

- `552da76` добавил pinned reproducible Ubuntu 24.04 systemd rehearsal image; `5dd557a` устранил перезапись release version через `/etc/os-release`;
- `0173533` разрешил SQLite recovery state в hardened units и включил реальную NTP-синхронизацию fixture; `ed3df70` добавил минимальный `CAP_FOWNER`;
- `464c42f` обеспечил automatic rollback на любом nonzero `EXIT` Gateway/VPS installers и возврат managed DB ownership после root network recovery;
- `583debb` заставил installer явно запускать broker socket, ждать socket+service+Unix path и генерировать runtime `lan_interface: lan0` вместо оставшегося example `enp2s0`;
- `a6aeaa1` сделал повторную установку совместимой с собственным fail-closed DNS, не ослабляя fresh-install preflight;
- fresh-systemd boot обнаружил конфликт runtime restore unit с boot transaction; `9eca9bb` разделил boot recovery и runtime destructive restore, перенёс broker socket в упорядоченный `multi-user.target`, расширил first-install ordering и убрал ложные WAL/SHM `chown` errors.

**Финальный disposable signed artifact этого блока:**

- source commit: `9eca9bbc45f98db42681aa77a282034581ccded7`;
- version: `0.1.0-systemd.8`; Gateway signed tree: 43 files;
- signer fingerprint: `7b98a51ea20bdffe3db8831ca9bfa550b45bc221d2ceb493758c75e6215887d3`;
- Gateway archive SHA-256: `fb9525c12b2b9b699bc027f806be9597cc2a4e7519d998e668ceec6dd0a1cf5d`;
- bootstrap SHA-256: `776e843aad49122a241cce0fd15d332e0296fa9223ddc8e479508a2300049346`;
- VPS archive SHA-256: `deea0cd85806dceb0500f875c2f47028b62a5f2c78f08fedb7072233528dc31e`;
- channel manifest SHA-256: `d837d4c3fec372c6da82271142fae095da03836f96f9008437b51eda3a80cad0`;
- private key существовал только в container tmpfs и уничтожен; это не production identity.

**Проверено:**

- полный local `go test ./...`, Linux `bash -n` для scripts/netns/systemd и Ubuntu 24.04 `systemd-analyze verify` всего Gateway/VPS unit graph — PASS;
- clean signed `.8` dry-run проверил NTP, release signature/manifest, 43 files, Ubuntu/kernel/TUN/LAN/packages и ничего не изменил;
- apply создал users/state/secrets/TLS/config/networkd/sysctl/units, загрузил `PATH_BLOCKED`, поднял guard, broker socket/service и control plane и завершил durable marker;
- `lan0` получил `192.168.200.1/24`; runtime config и nftables используют `lan0`, `enp2s0` отсутствует; IPv4 forwarding включён, IPv6 disabled/не forwardится;
- HTTPS реально слушает `192.168.200.1:8443`, возвращает 200, CSP, Permissions-Policy и no-sniff; DB `gateway-vpn:gateway-vpn 0600`, config `root:gateway-vpn 0640`;
- runtime restore unit disabled, boot restore/socket enabled; install recovery disabled после completed marker; Mihomo ожидаемо inactive без validated generation;
- точный повтор того же signed installer под заблокированным direct DNS вернул already-installed без mutation; restart `gateway-vpn.service` повторно прошёл acceptance;
- installed rootfs запущена в новом контейнере с новым пустым `/run`, новым PID 1 и `lan0` до systemd: firewall/guard/update/boot restore/network recovery/socket/broker/control поднялись автоматически без ручного `systemctl start`, полный acceptance — PASS;
- network recovery с отсутствующими WAL/SHM завершился чисто без ложных `chown: cannot access`; сообщений `network broker is unavailable` нет.

**Неуспешные промежуточные проверки и найденные причины:**

- `.5` сначала оставляла broker socket inactive и runtime firewall на `enp2s0`; оба дефекта воспроизведены, исправлены и закрыты `.6`;
- первый exact repeat `.6` завершился `Gateway DNS resolution failed`, потому что корректный `PATH_BLOCKED` блокировал direct DNS; исключение ограничено строгим completed-install hint и подтверждено `.7/.8`;
- обычный `docker restart` сохранил Docker tmpfs `/run` и не переиграл newly enabled target dependencies, поэтому не засчитан как reboot; проверка заменена installed-rootfs snapshot + новый контейнер/PID 1/пустой `/run`;
- более честный fresh boot `.7` выявил, что enabled runtime restore `Conflicts=` вытесняет socket/control из общей transaction. После разделения units candidate и signed `.8` boot прошли автоматически.

**Не проверено:** реальный Ubuntu host reboot/power cut, package installation на произвольном clean host, uninstall, pending database restore success/failure/power-cut, signed update apply/rollback, Mihomo validated generation/TUN, USB HiLink/Keenetic и любой реальный mobile/VPS packet flow.

**Следующий шаг:** signed VPS installer/systemd/recovery matrix на Ubuntu 20.04, 22.04 и 24.04, затем SSH orchestrator и двухмашинный WireGuard handshake.

### Сессия 035 — reproducible signed release rehearsal — 2026-08-25

**Цель:** проверить весь trusted-builder signing/bundle pipeline до создания permanent key, Git tag или GitHub draft.

**Pinned inputs:**

- source commit: `434d58c83075b3c6fee541a1d6fe94b2bf90a048`, clean clone без локальных tags;
- builder: `ubuntu@sha256:33ceb71981b602c1a7443a53469e4dba065f7503eab3078a2d7a57a2ab987517`;
- Go: official `go1.26.7.linux-amd64.tar.gz`, SHA-256 `ffb5f8de10c62550dfddab66b36b57030721e0a44a3218e9e1181d7b59f121ca` с `go.dev`;
- Mihomo: official MetaCubeX `v1.19.30`, asset `mihomo-linux-amd64-v1-v1.19.30.gz`, GitHub digest `cbe553d0319a414bd3a372c5976a252155b2c4882b66bce88a4d6bba9571a553`, verified binary SHA-256 `20ba567571d9ca642bedecbb01f8092cab0f1679100087ef1a4a2efac0ed5494`;
- rehearsal version/tag: local-only `0.1.0-rehearsal.1` / `v0.1.0-rehearsal.1`;
- Ed25519 key: создан только в container tmpfs, fingerprint `9ec8eb243c3ec8e96dfd87e2482ff7a94226af448eac3b8b0fcacbd2f91c7d94`, после container exit уничтожен и для production не используется.

**Выполнено:**

- официальный Go archive проверен до extraction, официальный Mihomo archive — до decompression/version probe;
- два независимых clean clone одного commit получили один local rehearsal tag, одинаковые pinned inputs и один disposable signer;
- `build-release-bundle.sh` дважды собрал Gateway role, VPS role, bootstrap, deploy launcher, SBOM/provenance, signed channel, public key и generated one-command;
- каждый проход повторно выполнил `release-verify --initial-install`, `vps-release-verify` и complete local `channel-verify --artifact`;
- весь `dist/` двух сборок сравнен `diff -qr` и оказался byte-for-byte идентичным;
- generated `install-gateway-0.1.0-rehearsal.1.command.txt` прошёл `bash -n`.

**Детерминированные результаты обоих проходов:**

- Gateway archive SHA-256: `72ebc791387d5075ee18c1e8074ac639a436275c0027a9f72adf0cbef0576120`;
- VPS archive SHA-256: `efedd10b7e3132c3373161697d15ec97ef556e17b65033316cbd20bb7ae9eda9`;
- bootstrap SHA-256: `8ec5dbc7a32c9c9001dd78cdcabe58413989144fa0b887f27b571695acb18e1e`;
- deploy SHA-256: `8368e74a62639372166edba61e6372798fcf9592f5a49fb4b91c47776cb5f416`;
- signed channel manifest SHA-256: `e08d51a308a1b11a475e57b9736efd667a4bdf538b8ee688fdbcea3eb674e6ee`.

**Очистка и ограничения:**

- disposable container удалён; rehearsal tag, `dist/` и private key не появились в host repository; secret/fingerprint scan workspace пуст;
- release immutability всё ещё выключена, поэтому tag/draft/publish намеренно не выполнялись;
- rehearsal не доказывает GitHub asset redirect/bootstrap install, реальный Mihomo TUN/API, systemd/reboot, SSH/VPS или hardware paths.

**Следующий шаг:** после включения immutability создать и отдельно backed-up permanent signing identity, повторить exact production double-build, создать draft и перейти к реальным installation gates.

### Сессия 034 — первый public GitHub CI и Ubuntu nftables/netns acceptance — 2026-08-25

**Сделано:**

- публичный репозиторий `https://github.com/Go4a4a/Gateway-VPN` проверен как пустой, добавлен как `origin`, ветка `main` опубликована без конфликта истории;
- Docker Desktop проверен от Windows user context: `4.87.0`, Engine `29.7.2`, Linux/amd64 `desktop-linux` — READY;
- первый remote GitHub race run выявил настоящую гонку в firewall guard test executor и неверное требование выполнять restore/update unit fixtures от root;
- commit `fd1549e` синхронизировал test executor и ввёл package-private ownership operations только для fixtures; production root ownership/chown остались неизменными, добавлен Linux-specific отказ non-root transaction root;
- первый root netns run выявил несовместимый с Ubuntu 24.04 nftables `type integer` и отсутствие service users при standalone boot ruleset load;
- commit `3afc425` перевёл все generation sets runtime/install templates на `type mark`, добавил regression checks и воспроизвёл production `gateway-vpn`/`gateway-vpn-mihomo` account prerequisite в harness;
- Docker trace выявил два ложных harness failure: upstream SIGPIPE от `grep -q` под `pipefail` и жёсткое ожидание JSON без пробелов;
- commit `cf7fa75` сделал stream assertions pipefail-safe, JSON whitespace-tolerant и добавил timeout diagnostics/regression test.

**Проверено:**

- локально после каждого исправления: `go test ./... -count=1`, `go vet ./...`, четыре Linux/amd64 CGO-free build, JS/shell syntax и `git diff --check` — PASS;
- одноразовый privileged Docker `ubuntu:24.04` выполнил полный `test/netns/firewall_guard.sh`: owned table delete, LAN quarantine, PATH_BLOCKED recovery, global `nft flush ruleset`, повторное recovery и отсутствие unmarked direct route — PASS;
- GitHub Actions run `32877860357` на exact code baseline `cf7fa75`: `Go, packaging and syntax gates` — success; `Linux nftables fail-closed gate` — success;
- GitHub Actions остаётся secret-free; long-lived signing key не передавался GitHub.

**Что не считается проверенным:**

- Docker/netns не проверяет systemd ordering, reboot/power-loss recovery, реальный USB HiLink, Keenetic packet capture, VPS firewall/WireGuard handshake или WebUI bind;
- release immutability, trusted signing key, signed GitHub draft/release и one-command install с GitHub assets ещё не выполнялись.

**Следующий шаг:** включить release immutability, подготовить trusted signing key/builder, получить зелёный CI для status-only head и перейти к exact tag → signed bundle → draft → manual publish, затем к двухмашинному Gateway/VPS acceptance.

### Сессия 033 — deterministic release bundle, secret-free Linux CI и immutable draft — 2026-08-25

**Сделано:**

- добавлен `.github/workflows/ci.yml`: Ubuntu 24.04, `go test -race`, vet, gofmt, четыре Linux/amd64 CGO-free builds, JS/shell syntax и отдельный root nft/netns failure-recovery job;
- `actions/checkout v7.0.1` и `actions/setup-go v7.0.0` закреплены полными official commit SHA; workflow имеет только `contents: read`, не использует `pull_request_target` и не читает secrets;
- добавлен review-only Dependabot feed для GitHub Action pins;
- build timestamps Gateway/VPS/deploy/channel теперь канонически выводятся из commit timestamp, а не wall-clock invocation time;
- `channel-verify` получил optional complete `--artifact ROLE=FILE` gate: каждый из четырёх signed artifacts повторно проверяется по exact filename/size/SHA-256, duplicate/missing/modified file блокируется;
- `release-verify --initial-install` позволяет trusted builder повторно проверить signed Gateway tree без выдуманной already-installed версии/схемы;
- добавлен `fetch-mihomo-release.sh`: только official MetaCubeX compatible amd64-v1 asset, HTTPS-only redirect, 64 MiB download и 128 MiB decompression bounds, archive SHA-256 до decompression/version probe;
- добавлен `build-release-bundle.sh`, который одной командой собирает Gateway/VPS/bootstrap/deploy/channel, закрепляет binary Mihomo SHA-256 и повторно проверяет все signatures/artifacts;
- добавлен `create-github-release-draft.sh`: перед external write verifier пересобирается из clean tagged source, local/remote tag и exact assets сверяются, затем создаётся только draft через `gh release create --draft --verify-tag`;
- все существующие и новые shell entrypoints, включая netns harness, переведены из ошибочного Git mode `100644` в `100755`;
- Operations/README дополнены точным trusted-builder → draft → manual immutable publish workflow.

**Найдено и исправлено:**

- прежние примеры `./scripts/...` не работали бы после clean Linux checkout из-за mode `100644`;
- одна лишь проверка channel signature не замечала замену локального artifact между build и upload; добавлен complete local re-hash и негативный тест подмены deploy binary;
- wall-clock build/channel dates делали exact-commit bundle зависимым от времени запуска; metadata привязана к commit time;
- перенос long-lived release key в GitHub Actions был отвергнут как расширение trust boundary: CI полностью secret-free, signing остаётся на отдельном builder;
- автоматическая публикация была отвергнута: GitHub immutability действует только для будущей публикации, поэтому publisher останавливается на полностью наполненном draft.

**Проверено:**

- targeted `cmd/gateway-vpnctl` и packaging tests, включая modified local artifact rejection — PASS;
- `go test ./... -count=1` — PASS;
- `go vet ./...` — PASS;
- Linux/amd64 `CGO_ENABLED=0` builds четырёх entrypoints — PASS;
- `node --check internal/webapi/static/app.js` и Git Bash `bash -n scripts/*.sh test/netns/*.sh` — PASS;
- workflow YAML parsing, full-SHA Action count, no-secrets/no-`pull_request_target`, fixed permissions и netns command проверяются packaging tests;
- release/CI code зафиксирован commit `28ad0c7`.

**Не выполнено и не считается PASS:**

- GitHub workflow ещё не запускался; `go test -race` и root nft/netns остаются `GITHUB_CI_NOT_RUN`;
- strict Mihomo fetch, signed bundle и `gh` draft не запускались на Linux trusted builder;
- release immutability не включалась и GitHub release не создан;
- реальные Gateway/VPS install, SSH, reboot и hardware gates не изменили статус `NOT_RUN`.

**Следующий шаг:** push `28ad0c7`, добиться зелёного GitHub CI, затем exact-tag trusted build/draft/immutable publish и двухмашинная acceptance matrix.

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
