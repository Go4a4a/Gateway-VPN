'use strict';

const modemRecoveryLabels = {
  DEVICE_ABSENT: 'USB-модем не обнаружен',
  CARRIER_DOWN: 'USB-сеть обнаружена, link отсутствует',
  DHCP_LEASE_MISSING: 'Не получен DHCP-адрес HiLink',
  HILINK_MANAGEMENT_UNREACHABLE: 'Web/API HiLink недоступен',
  PHYSICAL_LINK_HEALTHY: 'Физический канал исправен',
  ACTION_COMPLETED: 'Действие выполнено',
  HARDWARE_ACTION_NOT_AVAILABLE: 'Действие ждёт аппаратной проверки',
  DEVICE_ABSENT_NO_SAFE_ACTION: 'Ожидание подключения модема',
  RECOVERY_LADDER_EXHAUSTED: 'Безопасные действия исчерпаны',
  PROCESS_RESTARTED: 'Прерванная попытка закрыта после restart',
};

function modemRecoveryText(value) {
  return modemRecoveryLabels[value] || value || '—';
}

function modemRecoveryField(form, labelText, name, value, min, max, help) {
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
  form.append(label);
}

async function openModemRecoveryDialog(modem) {
  const snapshot = await api(`/api/v1/modems/${encodeURIComponent(modem.id)}/recovery?limit=50`);
  const dialog = document.createElement('dialog');
  dialog.className = 'editor-dialog';
  const heading = document.createElement('h2');
  heading.textContent = `Восстановление: #${modem.number} ${modem.name}`;
  const intro = document.createElement('p');
  intro.className = 'muted';
  intro.textContent = 'Recovery запускается только при физическом отказе модема. Блокировки сайтов, отсутствие полного Интернета, отказ VPN-сервера или подписки не перезапускают USB.';
  const summary = document.createElement('div');
  summary.className = 'grid';
  summary.append(
    card('Состояние', snapshot.runtime.state, modemRecoveryText(snapshot.runtime.failure_reason)),
    card('Последний результат', modemRecoveryText(snapshot.runtime.last_outcome_code), snapshot.runtime.updated_at || '—'),
    card('USB reset budget', `${snapshot.runtime.usb_resets_in_window} / ${snapshot.policy.max_usb_resets_per_window}`, snapshot.runtime.budget_window_started_at || 'Окно ещё не начато'),
    card('Cooldown', snapshot.runtime.cooldown_until || 'Нет', `Policy generation ${snapshot.policy.policy_generation}`),
  );

  const form = document.createElement('form');
  form.className = 'card settings-form';
  const formTitle = document.createElement('h3');
  formTitle.textContent = 'Ограничения автоматического восстановления';
  form.append(formTitle);
  const enabledLabel = document.createElement('label');
  enabledLabel.className = 'check';
  const enabled = document.createElement('input');
  enabled.type = 'checkbox';
  enabled.name = 'enabled';
  enabled.checked = snapshot.policy.enabled;
  enabledLabel.append(enabled, document.createTextNode(' Включить автоматический bounded recovery этого модема'));
  enabledLabel.title = 'Отключение не выключает сам модем: Gateway продолжит обнаружение и обычную работу, но не будет запускать recovery actions.';
  form.append(enabledLabel);
  modemRecoveryField(form, 'DHCP renew после, секунд', 'dhcp', snapshot.policy.dhcp_retry_after_seconds, 5, 3600, 'Сколько непрерывно ждать lease, прежде чем один раз запросить networkd renew.');
  modemRecoveryField(form, 'Повтор HiLink API после, секунд', 'api', snapshot.policy.api_retry_after_seconds, 5, 3600, 'Применяется только к подтверждённой недоступности локального Web/API модема.');
  modemRecoveryField(form, 'Перезапуск mobile session после, секунд', 'mobile', snapshot.policy.mobile_session_restart_after_seconds, 10, 7200, 'Firmware-specific действие. До аппаратной проверки будет безопасно подавлено.');
  modemRecoveryField(form, 'USB driver rebind после, секунд', 'rebind', snapshot.policy.usb_rebind_after_seconds, 30, 86400, 'Более сильная ступень. До проверки identity на реальном E3372h не исполняется.');
  modemRecoveryField(form, 'USB reset после, секунд', 'reset', snapshot.policy.usb_reset_after_seconds, 60, 86400, 'Аппаратная ступень с отдельным cooldown и durable budget.');
  modemRecoveryField(form, 'Cooldown USB reset, секунд', 'reset_cooldown', snapshot.policy.usb_reset_cooldown_seconds, 60, 86400, 'Минимальное время до следующего USB reset, сохраняется после restart.');
  modemRecoveryField(form, 'USB reset за окно', 'reset_max', snapshot.policy.max_usb_resets_per_window, 0, 20, '0 полностью запрещает USB reset; изменение настроек не обнуляет уже использованный budget.');
  modemRecoveryField(form, 'Окно USB budget, секунд', 'reset_window', snapshot.policy.usb_reset_window_seconds, 300, 86400, 'Период подсчёта аппаратных reset.');
  const powerLabel = document.createElement('label');
  powerLabel.className = 'check';
  const power = document.createElement('input');
  power.type = 'checkbox';
  power.name = 'power';
  power.checked = snapshot.policy.allow_hub_port_power_cycle;
  power.disabled = true;
  powerLabel.append(power, document.createTextNode(' Power cycle USB-hub port (недоступно до hardware profile)'));
  powerLabel.title = 'Эта функция требует подтверждённого управляемого USB-hub и точной привязки порта. Сейчас она намеренно недоступна.';
  form.append(powerLabel);
  const warning = document.createElement('p');
  warning.className = 'restore-warning';
  warning.textContent = 'Сейчас автоматически исполняется только безопасный DHCP renew. Firmware/USB действия фиксируются как подавленные, пока не пройдут реальные тесты Huawei E3372h; это защищает соседние USB-устройства и работающие модемы.';
  const save = document.createElement('button');
  save.type = 'submit';
  save.textContent = 'Сохранить recovery policy';
  form.append(warning, save);
  form.addEventListener('submit', async event => {
    event.preventDefault();
    save.disabled = true;
    const number = name => Number(form.elements[name].value);
    try {
      await api(`/api/v1/modems/${encodeURIComponent(modem.id)}/recovery`, {
        method: 'PUT',
        body: JSON.stringify({
          enabled: enabled.checked,
          dhcp_retry_after_seconds: number('dhcp'),
          api_retry_after_seconds: number('api'),
          mobile_session_restart_after_seconds: number('mobile'),
          usb_rebind_after_seconds: number('rebind'),
          usb_reset_after_seconds: number('reset'),
          usb_reset_cooldown_seconds: number('reset_cooldown'),
          max_usb_resets_per_window: number('reset_max'),
          usb_reset_window_seconds: number('reset_window'),
          allow_hub_port_power_cycle: snapshot.policy.allow_hub_port_power_cycle,
        }),
      });
      notice('Политика восстановления модема сохранена; USB budget не сброшен');
      dialog.close();
      await renderers.modems();
    } catch (error) {
      notice(error.message);
      save.disabled = false;
    }
  });

  const historyTitle = document.createElement('h3');
  historyTitle.textContent = 'Последние попытки';
  const history = table([
    {label: 'Начало', render: item => item.started_at || '—'},
    {label: 'Действие', key: 'action'},
    {label: 'Источник', render: item => item.requested_by === 'USER' ? 'Кнопка WebUI' : 'Автоматически'},
    {label: 'Физическая причина', render: item => modemRecoveryText(item.failure_reason)},
    {label: 'Статус', render: item => badge(item.status)},
    {label: 'Результат', render: item => modemRecoveryText(item.reason_code)},
    {label: 'Завершение', render: item => item.finished_at || '—'},
  ], snapshot.attempts || []);
  const close = actionButton('Закрыть', () => dialog.close());
  dialog.append(heading, intro, summary, form, historyTitle, history, close);
  dialog.addEventListener('close', () => dialog.remove());
  document.body.append(dialog);
  dialog.showModal();
}

const baseRenderModems = renderers.modems;
renderers.modems = async function renderModemsWithRecovery() {
  await baseRenderModems();
  const response = await api('/api/v1/modems');
  const box = document.createElement('section');
  box.className = 'card modem-recovery-panel';
  const heading = document.createElement('h2');
  heading.textContent = 'Самовосстановление модемов';
  const note = document.createElement('p');
  note.className = 'muted';
  note.textContent = 'Отдельно от проверки Интернета. DEVICE_ABSENT означает ожидание подключения, а не остановку Gateway; WebUI/SSH и остальные рабочие выходы продолжают работать.';
  const rows = response.items.map(item => ({
    ...item,
    recoveryActions: actionGroup(
      actionButton('Проверить и восстановить', async () => {
        const result = await api(`/api/v1/modems/${encodeURIComponent(item.id)}/recover`, {method: 'POST'});
        const recovery = result.recovery || {};
        notice(recovery.reason_code ? modemRecoveryText(recovery.reason_code) : 'Физическое состояние модема перепроверено');
        await renderers.modems();
      }, false, !item.enabled),
      actionButton('История и настройки', () => openModemRecoveryDialog(item)),
    ),
  }));
  box.append(heading, note, table([
    {label: 'Модем', render: item => `#${item.number} ${item.name}`},
    {label: 'Физическая причина', render: item => modemRecoveryText(item.physical_failure)},
    {label: 'Recovery state', render: item => badge(item.recovery_state)},
    {label: 'Последний результат', render: item => modemRecoveryText(item.recovery_reason)},
    {label: 'Действия', render: item => item.recoveryActions},
  ], rows));
  $('content').append(box);
};
