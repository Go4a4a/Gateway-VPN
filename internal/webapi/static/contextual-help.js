'use strict';

(function installContextualHelp() {
  const descriptions = {
    name: 'Понятное локальное название. Оно используется только в WebUI и журналах и не меняет сетевой адрес.',
    enabled: 'Включает или исключает этот объект из автоматической работы. Сохранённая конфигурация при выключении не удаляется.',
    priority: 'Меньшее число означает более высокий приоритет среди одинаково работоспособных вариантов.',
    url: 'Адрес источника. Секретная часть хранится отдельно и не выводится в журналах или диагностике.',
    source_url: 'HTTPS-адрес подписки. Gateway хранит его как защищённый secret и использует отказоустойчивую цепочку обновления.',
    refresh_interval_seconds: 'Период автоматического обновления. Ручная кнопка обновления доступна независимо от этого интервала.',
    timeout: 'Максимальное время одной проверки до признания попытки неуспешной.',
    timeout_seconds: 'Максимальное время одной проверки до признания попытки неуспешной.',
    target_class: 'Обязательные цели определяют FULL; дополнительные дают диагностику; индикаторы белого списка проверяются только напрямую.',
    success_mode: 'Определяет, какой HTTP-ответ доказывает доступность цели: любой ответ, заданный статус или маркер в теле.',
    expected_status: 'Допустимый HTTP-статус или диапазон статусов, например 200-399.',
    expected_body: 'Короткий точный фрагмент, который должен встретиться в ограниченной начальной части ответа.',
    current_password: 'Текущий пароль проверяется сервером и не сохраняется в форме, журнале или диагностике.',
    new_password: 'Новый пароль учётной записи. После замены остальные её сессии будут отозваны.',
    password_confirmation: 'Повтор нового пароля защищает от опечатки.',
    since: 'Показывать записи, созданные не раньше выбранного местного времени.',
    level: 'Минимальная тематическая выборка по уровню события. Фильтр не меняет сохранённый журнал.',
    component: 'Ограничивает просмотр выбранным внутренним компонентом Gateway VPN.',
    modem_id: 'Необязательный точный идентификатор модема для диагностики его событий.',
    subscription_id: 'Необязательный точный идентификатор подписки для диагностики её событий.',
    path_id: 'Необязательный идентификатор конкретного сочетания uplink и способа доступа.',
    correlation_id: 'Связывает сообщения одной операции между несколькими компонентами.',
    search: 'Ищет текст только в уже очищенных сообщениях выбранной страницы журнала.',
    check_interval_seconds: 'Как часто watchdog перечитывает локальное состояние фиксированных компонентов.',
    failure_threshold: 'Сколько последовательных ошибок требуется до разрешённого recovery-действия.',
    success_threshold: 'Сколько последовательных успешных проверок подтверждают восстановление.',
    restart_cooldown_seconds: 'Минимальная пауза между restart одного компонента.',
    max_restarts_per_component: 'Жёсткий лимит restart одного компонента внутри временного окна.',
    restart_window_seconds: 'Размер durable окна, в котором считается restart budget.',
    reboot_after_critical_seconds: 'Минимальная длительность непрерывного локального critical failure до планирования reboot.',
    max_reboots_per_24h: 'Жёсткий durable лимит автоматических перезагрузок за скользящие 24 часа.',
    reboot_grace_seconds: 'Пауза перед перезагрузкой, позволяющая отменить действие и завершить запись состояния.',
    lan_address: 'Адрес и подсеть management LAN. Изменение применяется через safe apply с подтверждением и rollback.',
    address_mode: 'DHCP получает параметры автоматически; STATIC использует явно заданные адрес, шлюз и DNS.',
    ipv4_cidr: 'IPv4-адрес интерфейса с длиной префикса, например 192.168.50.2/24.',
    gateway: 'IPv4-шлюз именно этого uplink. Он не становится неконтролируемым общим default route.',
    dns: 'Список DNS-адресов. Запросы привязываются к выбранному проверенному маршруту.',
    mtu: 'Максимальный размер пакета. Меняйте значение только при подтверждённой фрагментации или требовании провайдера.',
    interface_id: 'Стабильная обнаруженная сетевая карта. При замене оборудования её можно безопасно переназначить.',
    network_interface_id: 'Стабильная обнаруженная сетевая карта. Имя Linux-интерфейса может измениться после перезагрузки.',
    confirmation: 'Точная фраза подтверждает осознанное выполнение необратимого или потенциально прерывающего действия.',
  };

  function directLabelText(label) {
    const text = Array.from(label.childNodes)
      .filter(node => node.nodeType === Node.TEXT_NODE)
      .map(node => node.textContent.trim())
      .filter(Boolean)
      .join(' ');
    return text || label.querySelector('legend')?.textContent?.trim() || 'эта настройка';
  }

  function defaultControlHelp(control, labelText) {
    const kind = control.tagName === 'SELECT' ? 'Выберите значение' :
      control.type === 'checkbox' ? 'Установите или снимите флажок' :
      control.type === 'password' ? 'Введите значение' : 'Укажите значение';
    return `${kind} для настройки «${labelText}». Изменение применяется только после сохранения формы; сервер повторно проверит допустимость и конфликты.`;
  }

  function decorate(root) {
    root.querySelectorAll('label').forEach(label => {
      const control = label.querySelector('input, select, textarea');
      if (!control) return;
      const labelText = directLabelText(label);
      const description = control.title || descriptions[control.name] || defaultControlHelp(control, labelText);
      if (!control.title) control.title = description;
      if (!label.title) label.title = description;
      if (!control.getAttribute('aria-label')) control.setAttribute('aria-label', labelText);
      if (!label.querySelector('details.contextual-help')) {
        const details = document.createElement('details');
        details.className = 'contextual-help';
        const summary = document.createElement('summary');
        summary.textContent = '?';
        summary.title = description;
        summary.setAttribute('aria-label', `Справка: ${labelText}`);
        const popup = document.createElement('span');
        popup.className = 'contextual-help-popup';
        popup.textContent = description;
        details.append(summary, popup);
        details.addEventListener('toggle', () => {
          if (!details.open) return;
          root.querySelectorAll('details.contextual-help[open]').forEach(other => {
            if (other !== details) other.open = false;
          });
        });
        summary.addEventListener('click', event => event.stopPropagation());
        summary.addEventListener('keydown', event => {
          event.stopPropagation();
          if (event.key !== 'Enter' && event.key !== ' ') return;
          event.preventDefault();
          details.open = !details.open;
        });
        label.append(details);
      }
    });
    root.querySelectorAll('fieldset > legend').forEach(legend => {
      if (!legend.title) legend.title = `Группа связанных настроек «${legend.textContent.trim()}».`;
    });
    root.querySelectorAll('button').forEach(button => {
      if (!button.textContent.trim()) return;
      const warning = button.classList.contains('danger') ? ' Действие может отозвать доступ или удалить сохранённые данные и потребует подтверждения.' : '';
      if (!button.title) button.title = `Действие «${button.textContent.trim()}».${warning}`;
      if (!button.getAttribute('aria-label')) button.setAttribute('aria-label', button.textContent.trim());
    });
  }

  const content = document.getElementById('content');
  if (!content) return;
  let scheduled = false;
  const schedule = () => {
    if (scheduled) return;
    scheduled = true;
    queueMicrotask(() => { scheduled = false; decorate(content); });
  };
  new MutationObserver(schedule).observe(content, { childList: true, subtree: true });
  schedule();
})();
