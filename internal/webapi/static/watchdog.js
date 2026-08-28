/* global api, badge, card, notice, renderSystemWithDiagnostics, table, watchdogPanel */

watchdogPanel = async function watchdogPanelExpanded() {
  const [settings, runtime] = await Promise.all([
    api('/api/v1/settings/watchdog'),
    api('/api/v1/system/watchdog'),
  ]);
  const policy = settings.policy;
  const limits = settings.limits || {};
  const components = settings.components || [];
  const current = runtime.status || {};
  const box = document.createElement('section');
  box.className = 'card watchdog-panel';

  const heading = document.createElement('h2');
  heading.textContent = 'Самоконтроль 24/7';
  const intro = document.createElement('p');
  intro.className = 'muted';
  intro.textContent = 'Проверяются WebUI/API, SQLite, firewall, systemd-networkd, DNS/DHCP, SSH/SFTP, Mihomo, оба WireGuard-контура, policy routing, фоновые циклы, согласование настроек, резервные копии и ресурсы. Внешний отказ оператора, VPS, подписки или сайта не запускает локальный restart/reboot.';
  const summary = document.createElement('div');
  summary.className = 'grid watchdog-summary';
  summary.append(
    card('Локальное состояние', runtime.runtime_state === 'AVAILABLE' ? current.overall_state : 'UNAVAILABLE', 'Сервисы, ядро, настройки и ресурсы'),
    card('Глобальный доступ', runtime.runtime_state === 'AVAILABLE' ? current.connectivity_state : 'UNKNOWN', current.connectivity_class || 'Отдельно от local recovery'),
    card('Обслуживание', current.maintenance ? 'ACTIVE' : 'INACTIVE', current.maintenance_code || 'Recovery не вмешивается в транзакции'),
    card('Перезагрузки за 24 часа', `${current.host_reboots_24h || 0} / ${policy.max_reboots_per_24h}`, current.pending_reboot_at ? `Ожидает: ${current.pending_reboot_at}` : 'Нет ожидающей перезагрузки'),
  );
  box.append(heading, intro, summary);

  if (runtime.runtime_state !== 'AVAILABLE') {
    const warning = document.createElement('p');
    warning.className = 'restore-warning';
    warning.textContent = 'Свежий runtime-отчёт supervisor недоступен. Fail-closed firewall и systemd restart остаются независимыми; проверьте gateway-vpn-watchdog.service.';
    box.append(warning);
  } else {
    const rows = (runtime.components || []).map(component => ({
      ...component,
      stateBadge: badge(component.state),
      classificationText: component.classification || 'LOCAL/OK',
      errorText: component.error_code || '—',
      lastRecovery: component.last_recovery_at ? `${component.last_recovery_action || 'RECOVERY'} · ${component.last_recovery_at}` : '—',
      suppression: component.recovery_suppressed ? (component.suppression_reason || 'SUPPRESSED') : '—',
    }));
    box.append(table([
      { label: 'Компонент', key: 'label' },
      { label: 'Состояние', render: item => item.stateBadge },
      { label: 'Класс', key: 'classificationText' },
      { label: 'Код', key: 'errorText' },
      { label: 'Ошибок подряд', key: 'consecutive_failures' },
      { label: 'Restart / окно', key: 'restarts_in_window' },
      { label: 'Последнее восстановление', key: 'lastRecovery' },
      { label: 'Почему не восстанавливается', key: 'suppression' },
    ], rows));
  }

  const form = document.createElement('form');
  form.className = 'settings-form watchdog-editor';
  const title = document.createElement('h3');
  title.textContent = 'Политика наблюдения и восстановления';
  form.append(title);

  const checkbox = (labelText, name, value, help) => {
    const label = document.createElement('label');
    label.className = 'check';
    label.title = help;
    const input = document.createElement('input');
    input.type = 'checkbox';
    input.name = name;
    input.checked = Boolean(value);
    label.append(input, document.createTextNode(labelText));
    form.append(label);
    return input;
  };
  const numeric = (parent, labelText, name, value, min, max, help) => {
    const label = document.createElement('label');
    label.textContent = labelText;
    label.title = help;
    const input = document.createElement('input');
    input.type = 'number';
    input.name = name;
    input.value = value;
    input.min = min;
    input.max = max;
    input.required = true;
    label.append(input);
    parent.append(label);
    return input;
  };

  checkbox('Включить автоматическое bounded recovery', 'enabled', policy.enabled, 'Мониторинг и отображение состояний продолжаются всегда. Этот переключатель разрешает автоматические reconcile/restart действия.');
  checkbox('Разрешить idempotent reconcile', 'reconcile_enabled', policy.reconcile_enabled, 'Первый безопасный шаг: попросить control plane повторно согласовать настройки с фактическим состоянием.');
  checkbox('Разрешить restart только фиксированных компонентов', 'component_restart_enabled', policy.component_restart_enabled, 'Restart выполняется только для зашитого в подписанном коде списка systemd units и только после fail-closed.');
  numeric(form, 'Интервал проверки, секунд', 'check_interval_seconds', policy.check_interval_seconds, limits.check_interval_seconds_min || 5, limits.check_interval_seconds_max || 300, 'Как часто root supervisor выполняет полный read-only health snapshot.');
  numeric(form, 'Ошибок подряд до recovery', 'failure_threshold', policy.failure_threshold, limits.failure_threshold_min || 1, limits.failure_threshold_max || 10, 'Защищает от единичных кратковременных сбоев.');
  numeric(form, 'Успехов подряд до HEALTHY', 'success_threshold', policy.success_threshold, limits.success_threshold_min || 1, limits.success_threshold_max || 10, 'Hysteresis после восстановления.');
  numeric(form, 'Cooldown restart, секунд', 'restart_cooldown_seconds', policy.restart_cooldown_seconds, limits.restart_cooldown_seconds_min || 5, limits.restart_cooldown_seconds_max || 3600, 'Минимальная пауза между restart одного компонента.');
  numeric(form, 'Restart одного компонента за окно', 'max_restarts_per_component', policy.max_restarts_per_component, limits.max_restarts_per_component_min || 1, limits.max_restarts_per_component_max || 20, 'Durable budget переживает restart процесса и изменение настроек.');
  numeric(form, 'Окно restart budget, секунд', 'restart_window_seconds', policy.restart_window_seconds, limits.restart_window_seconds_min || 60, limits.restart_window_seconds_max || 86400, 'Период, внутри которого считаются попытки restart.');

  const thresholds = document.createElement('fieldset');
  thresholds.className = 'settings-group watchdog-thresholds';
  const thresholdsLegend = document.createElement('legend');
  thresholdsLegend.textContent = 'Пороги локального здоровья';
  thresholds.append(thresholdsLegend);
  numeric(thresholds, 'Зависание критического worker, секунд', 'worker_stale_seconds', policy.worker_stale_seconds, limits.worker_stale_seconds_min || 30, limits.worker_stale_seconds_max || 900, 'Минимально допустимая пауза между progress heartbeat фоновых циклов. Длинные задачи имеют собственные большие безопасные интервалы.');
  numeric(thresholds, 'WireGuard handshake считается старым через, секунд', 'wireguard_handshake_stale_seconds', policy.wireguard_handshake_stale_seconds, limits.wireguard_handshake_stale_seconds_min || 60, limits.wireguard_handshake_stale_seconds_max || 3600, 'Старый handshake при исправном интерфейсе и маршрутах классифицируется как внешний отказ VPS/сети и не вызывает restart.');
  numeric(thresholds, 'Максимальный возраст daily backup, часов', 'backup_max_age_hours', policy.backup_max_age_hours, limits.backup_max_age_hours_min || 24, limits.backup_max_age_hours_max || 168, 'После этого отсутствие свежей структурно проверенной SQLite-копии считается локальной проблемой.');
  numeric(thresholds, 'Максимальный SQLite WAL, МиБ', 'database_wal_max_mib', Math.round(policy.database_wal_max_bytes / 1048576), Math.round((limits.database_wal_max_bytes_min || 67108864) / 1048576), Math.round((limits.database_wal_max_bytes_max || 4294967296) / 1048576), 'Большой WAL может указывать на зависший checkpoint или нехватку диска.');
  numeric(thresholds, 'Свободно на диске минимум, МиБ', 'minimum_disk_free_mib', Math.round(policy.minimum_disk_free_bytes / 1048576), Math.round((limits.minimum_disk_free_bytes_min || 134217728) / 1048576), Math.round((limits.minimum_disk_free_bytes_max || 17179869184) / 1048576), 'Одновременно применяется и процентный порог; срабатывает более строгий.');
  numeric(thresholds, 'Свободно на диске минимум, %', 'minimum_disk_free_percent', policy.minimum_disk_free_percent, limits.minimum_resource_percent_min || 1, limits.minimum_resource_percent_max || 25, 'Resource pressure отображается, но не является причиной host reboot.');
  numeric(thresholds, 'Доступно памяти минимум, МиБ', 'minimum_memory_available_mib', Math.round(policy.minimum_memory_available_bytes / 1048576), Math.round((limits.minimum_memory_available_bytes_min || 67108864) / 1048576), Math.round((limits.minimum_memory_available_bytes_max || 8589934592) / 1048576), 'Используется MemAvailable, а не только полностью свободная память.');
  numeric(thresholds, 'Доступно памяти минимум, %', 'minimum_memory_available_percent', policy.minimum_memory_available_percent, limits.minimum_resource_percent_min || 1, limits.minimum_resource_percent_max || 25, 'Resource pressure никогда не превращается в автоматический reboot.');
  form.append(thresholds);

  const modes = document.createElement('fieldset');
  modes.className = 'settings-group watchdog-components';
  const modesLegend = document.createElement('legend');
  modesLegend.textContent = 'Реакция по компонентам';
  modes.append(modesLegend);
  const modeLabels = { MONITOR_ONLY: 'Только наблюдать', RECONCILE: 'Reconcile без restart', RESTART: 'Reconcile и bounded restart' };
  const modeInputs = new Map();
  components.forEach(component => {
    const label = document.createElement('label');
    label.textContent = component.label;
    label.title = component.reboot_eligible ? 'Компонент может участвовать в аварийном host reboot только если общий reboot отдельно включён и исчерпан длительный local recovery.' : 'Этот компонент никогда сам по себе не разрешает host reboot.';
    const select = document.createElement('select');
    (component.allowed_recovery_modes || ['MONITOR_ONLY']).forEach(mode => {
      const option = document.createElement('option');
      option.value = mode;
      option.textContent = modeLabels[mode] || mode;
      select.append(option);
    });
    select.value = policy.component_recovery_modes[component.id] || 'MONITOR_ONLY';
    modeInputs.set(component.id, select);
    label.append(select);
    modes.append(label);
  });
  const modesNote = document.createElement('p');
  modesNote.className = 'muted';
  modesNote.textContent = 'Мониторинг отключить нельзя. Из WebUI нельзя задать unit, команду, interface, маршрут или путь — выбирается только уровень реакции для фиксированного компонента.';
  modes.append(modesNote);
  form.append(modes);

  const advanced = document.createElement('fieldset');
  advanced.className = 'settings-group watchdog-reboot';
  const advancedLegend = document.createElement('legend');
  advancedLegend.textContent = 'Аварийная перезагрузка host — advanced';
  advanced.append(advancedLegend);
  const rebootLabel = document.createElement('label');
  rebootLabel.className = 'check';
  rebootLabel.title = 'По умолчанию выключено. Доступно только для code-defined критических локальных компонентов после fail-closed и durable budget.';
  const reboot = document.createElement('input');
  reboot.type = 'checkbox';
  reboot.name = 'host_reboot_enabled';
  reboot.checked = Boolean(policy.host_reboot_enabled);
  rebootLabel.append(reboot, document.createTextNode('Разрешить host reboot при устойчивой локальной критической поломке'));
  advanced.append(rebootLabel);
  numeric(advanced, 'Непрерывный local critical до reboot, секунд', 'reboot_after_critical_seconds', policy.reboot_after_critical_seconds, limits.reboot_after_critical_seconds_min || 300, limits.reboot_after_critical_seconds_max || 86400, 'Таймер начинается только после локальной ошибки, не после пропажи Интернета/VPS.');
  numeric(advanced, 'Максимум reboot за 24 часа', 'max_reboots_per_24h', policy.max_reboots_per_24h, limits.max_reboots_per_24h_min || 1, limits.max_reboots_per_24h_max || 3, 'Durable ограничение предотвращает цикл перезагрузок.');
  numeric(advanced, 'Grace перед reboot, секунд', 'reboot_grace_seconds', policy.reboot_grace_seconds, limits.reboot_grace_seconds_min || 10, limits.reboot_grace_seconds_max || 600, 'Дополнительное окно, в котором восстановление отменяет запланированный reboot.');
  const rebootWarning = document.createElement('p');
  rebootWarning.className = 'restore-warning';
  rebootWarning.textContent = 'Внешний outage, старый WireGuard handshake, отказ подписки и давление диска/памяти не являются причиной host reboot.';
  advanced.append(rebootWarning);
  form.append(advanced);

  const submit = document.createElement('button');
  submit.type = 'submit';
  submit.textContent = 'Сохранить политику watchdog';
  form.append(submit);
  form.addEventListener('submit', async event => {
    event.preventDefault();
    if (reboot.checked && !policy.host_reboot_enabled && !confirm('Включить аварийный reboot host? Он сработает только после устойчивой локальной critical failure, fail-closed и в пределах durable budget.')) return;
    const number = name => Number(form.elements[name].value);
    const componentRecoveryModes = {};
    modeInputs.forEach((input, id) => { componentRecoveryModes[id] = input.value; });
    const payload = {
      enabled: form.elements.enabled.checked,
      check_interval_seconds: number('check_interval_seconds'),
      failure_threshold: number('failure_threshold'),
      success_threshold: number('success_threshold'),
      reconcile_enabled: form.elements.reconcile_enabled.checked,
      component_restart_enabled: form.elements.component_restart_enabled.checked,
      restart_cooldown_seconds: number('restart_cooldown_seconds'),
      max_restarts_per_component: number('max_restarts_per_component'),
      restart_window_seconds: number('restart_window_seconds'),
      worker_stale_seconds: number('worker_stale_seconds'),
      wireguard_handshake_stale_seconds: number('wireguard_handshake_stale_seconds'),
      backup_max_age_hours: number('backup_max_age_hours'),
      database_wal_max_bytes: number('database_wal_max_mib') * 1048576,
      minimum_disk_free_bytes: number('minimum_disk_free_mib') * 1048576,
      minimum_disk_free_percent: number('minimum_disk_free_percent'),
      minimum_memory_available_bytes: number('minimum_memory_available_mib') * 1048576,
      minimum_memory_available_percent: number('minimum_memory_available_percent'),
      component_recovery_modes: componentRecoveryModes,
      host_reboot_enabled: reboot.checked,
      reboot_after_critical_seconds: number('reboot_after_critical_seconds'),
      max_reboots_per_24h: number('max_reboots_per_24h'),
      reboot_grace_seconds: number('reboot_grace_seconds'),
    };
    submit.disabled = true;
    try {
      await api('/api/v1/settings/watchdog', { method: 'PUT', body: JSON.stringify(payload) });
      notice('Watchdog policy сохранена; мониторинг продолжен, durable budgets не сброшены');
      await renderSystemWithDiagnostics();
    } catch (error) {
      notice(error.message);
      submit.disabled = false;
    }
  });
  box.append(form);
  return box;
};
