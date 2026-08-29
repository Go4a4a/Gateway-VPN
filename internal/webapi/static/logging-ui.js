'use strict';

const loggingCategoryLabels = {
  all: 'Все',
  modems: 'Модемы',
  subscriptions: 'Подписки и VPN-серверы',
  access: 'Доступ и переключения',
  'vpn-mihomo': 'VPN / Mihomo',
  network: 'Сеть',
  'wireguard-vps': 'WireGuard / VPS',
  watchdog: 'Watchdog',
  updates: 'Обновления / backup',
  'security-audit': 'Безопасность / audit',
};

// app.js intentionally owns the canonical viewer entry point. This script is
// loaded immediately after it and replaces only that UI renderer; all queries
// still cross the authenticated, allowlisted and rate-limited server API.
loggingJournalViewer = async function categorizedLoggingJournalViewer(components) {
  const box = document.createElement('div');
  box.className = 'card journal-viewer';

  const heading = document.createElement('h2');
  heading.textContent = 'Технический журнал';
  const note = document.createElement('p');
  note.className = 'muted';
  note.textContent = 'Один достоверный журнал Gateway VPN разделён на удобные тематические вкладки. Фильтры проверяются сервером, секреты повторно скрываются, страницы ограничены 25 записями.';
  const exportInfo = document.createElement('p');
  exportInfo.className = 'muted journal-export-info';
  try {
    const settings = await api('/api/v1/settings/logging');
    const convergence = settings.log_export_applied_generation === settings.log_export_desired_generation;
    exportInfo.textContent = settings.log_export_enabled
      ? `SFTP-копии: ${settings.log_export_sftp_path} · ${settings.log_export_state}${convergence ? '' : ' · ожидается синхронизация'}. Это только удобная redacted-выгрузка; исходным журналом остаётся journald.`
      : 'SFTP-копии логов отключены; исходный журнал journald продолжает работать.';
  } catch {
    exportInfo.textContent = 'Состояние SFTP-копий временно недоступно; просмотр canonical journald остаётся независимым.';
  }

  const categories = document.createElement('div');
  categories.className = 'journal-category-tabs';
  categories.setAttribute('role', 'tablist');
  categories.setAttribute('aria-label', 'Категории технического журнала');
  let activeCategory = 'all';

  const form = document.createElement('form');
  form.className = 'toolbar journal-filters';
  form.innerHTML = '<label>От<input name="since" type="datetime-local"></label><label>Уровень<select name="level"><option value="">Все</option><option value="error">Error</option><option value="warning">Warning</option><option value="info">Info</option><option value="debug">Debug</option></select></label><label>Компонент<select name="component"><option value="">Все</option></select></label><label>Модем<input name="modem_id" maxlength="128" placeholder="modem-id"></label><label>Подписка<input name="subscription_id" maxlength="128" placeholder="subscription-id"></label><label>Путь<input name="path_id" maxlength="128" placeholder="path-id"></label><label>Correlation ID<input name="correlation_id" maxlength="128"></label><label>Текст<input name="search" maxlength="128"></label><button>Применить</button>';
  components.forEach((component) => {
    const option = document.createElement('option');
    option.value = component;
    option.textContent = loggingComponentLabels[component] || component;
    form.elements.component.append(option);
  });
  const initial = new Date(Date.now() - 24 * 60 * 60 * 1000);
  form.elements.since.value = new Date(initial.getTime() - initial.getTimezoneOffset() * 60000).toISOString().slice(0, 16);

  const pages = document.createElement('div');
  pages.className = 'journal-pages';
  const controls = document.createElement('div');
  controls.className = 'actions';
  let cursor = '';

  const load = async (reset = true) => {
    if (reset) cursor = '';
    const params = new URLSearchParams({limit: '25', category: activeCategory});
    const since = form.elements.since.value;
    if (since) params.set('since', new Date(since).toISOString());
    for (const name of ['level', 'component', 'modem_id', 'subscription_id', 'path_id', 'correlation_id', 'search']) {
      const value = form.elements[name].value.trim();
      if (value) params.append(name, value);
    }
    if (!reset && cursor) params.set('cursor', cursor);
    const page = await api('/api/v1/logs?' + params.toString());
    const rows = page.items.map((item) => ({
      ...item,
      severityBadge: badge(item.severity),
      scope: [item.modem_id, item.subscription_id, item.path_id].filter(Boolean).join(' · ') || '—',
    }));
    const current = table([
      {label: 'Время', key: 'occurred_at'},
      {label: 'Уровень', render: (item) => item.severityBadge},
      {label: 'Компонент', render: (item) => loggingComponentLabels[item.component] || item.component},
      {label: 'Unit', key: 'unit'},
      {label: 'Scope', key: 'scope'},
      {label: 'Correlation', key: 'correlation_id'},
      {label: 'Сообщение', key: 'message'},
      {label: 'Повторы', key: 'suppressed_repeats'},
    ], rows);
    pages.className = 'journal-pages';
    if (reset) pages.replaceChildren(current);
    else pages.append(current);
    cursor = page.next_cursor || '';
    controls.replaceChildren();
    if (page.has_more && cursor) controls.append(actionButton('Загрузить более старые', () => load(false)));
  };

  Object.entries(loggingCategoryLabels).forEach(([category, label]) => {
    const button = document.createElement('button');
    button.type = 'button';
    button.className = category === activeCategory ? 'active' : '';
    button.setAttribute('role', 'tab');
    button.setAttribute('aria-selected', category === activeCategory ? 'true' : 'false');
    button.textContent = label;
    button.addEventListener('click', async () => {
      if (category === activeCategory) return;
      activeCategory = category;
      categories.querySelectorAll('button').forEach((current) => {
        const selected = current === button;
        current.classList.toggle('active', selected);
        current.setAttribute('aria-selected', selected ? 'true' : 'false');
      });
      pages.className = 'empty';
      pages.textContent = 'Загрузка…';
      try {
        await load(true);
      } catch (err) {
        pages.className = 'empty';
        pages.textContent = err.message;
      }
    });
    categories.append(button);
  });

  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    try {
      await load(true);
    } catch (err) {
      notice(err.message);
    }
  });
  box.append(heading, note, exportInfo, categories, form, pages, controls);
  try {
    await load(true);
  } catch (err) {
    pages.className = 'empty';
    pages.textContent = err.message;
  }
  return box;
};
