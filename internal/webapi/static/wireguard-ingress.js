/* global api, actionButton, actionGroup, badge, card, notice, setContent */

let wireGuardIngressPanel = async () => { throw new Error('Модуль WireGuard-клиентов не загружен'); };

(function installWireGuardIngressPanel() {
  const list = value => value.split(/[\s,;]+/).map(item => item.trim()).filter(Boolean);
  const shortKey = value => value ? `${value.slice(0, 8)}…${value.slice(-6)}` : '—';
  const bytes = value => {
    value = Number(value || 0);
    if (value < 1024) return `${value} Б`;
    if (value < 1048576) return `${(value / 1024).toFixed(1)} КиБ`;
    if (value < 1073741824) return `${(value / 1048576).toFixed(1)} МиБ`;
    return `${(value / 1073741824).toFixed(1)} ГиБ`;
  };
  const help = (element, text) => { element.title = text; return element; };

  function field(text, name, value, title, options = {}) {
    const label = document.createElement('label');
    label.textContent = text;
    label.title = title;
    let input;
    if (options.choices) {
      input = document.createElement('select');
      options.choices.forEach(item => {
        const option = document.createElement('option');
        option.value = item.value;
        option.textContent = item.label;
        input.append(option);
      });
    } else if (options.multiline) {
      input = document.createElement('textarea');
      input.rows = 2;
    } else {
      input = document.createElement('input');
      input.type = options.type || 'text';
      if (options.min !== undefined) input.min = options.min;
      if (options.max !== undefined) input.max = options.max;
    }
    input.name = name;
    input.value = value ?? '';
    input.required = Boolean(options.required);
    input.placeholder = options.placeholder || '';
    input.title = title;
    label.append(input);
    return { label, input };
  }

  function check(text, name, checked, title) {
    const label = document.createElement('label');
    label.className = 'check';
    label.title = title;
    const input = document.createElement('input');
    input.type = 'checkbox';
    input.name = name;
    input.checked = Boolean(checked);
    input.title = title;
    label.append(input, document.createTextNode(text));
    return { label, input };
  }

  function passwordDialog(title, description) {
    return new Promise(resolve => {
      const dialog = document.createElement('dialog');
      dialog.className = 'modal';
      const form = document.createElement('form');
      form.className = 'settings-form';
      const heading = document.createElement('h2');
      heading.textContent = title;
      const note = document.createElement('p');
      note.className = 'muted';
      note.textContent = description;
      const password = field('Текущий пароль', 'password', '', 'Используется только для повторной проверки текущей сессии и не сохраняется.', { type: 'password', required: true });
      password.input.autocomplete = 'current-password';
      const buttons = document.createElement('div');
      buttons.className = 'actions';
      const cancel = document.createElement('button');
      cancel.type = 'button';
      cancel.textContent = 'Отмена';
      const submit = document.createElement('button');
      submit.type = 'submit';
      submit.textContent = 'Подтвердить';
      buttons.append(cancel, submit);
      form.append(heading, note, password.label, buttons);
      dialog.append(form);
      document.body.append(dialog);
      const finish = result => { dialog.close(); dialog.remove(); resolve(result); };
      cancel.addEventListener('click', () => finish(null));
      dialog.addEventListener('cancel', event => { event.preventDefault(); finish(null); });
      form.addEventListener('submit', event => { event.preventDefault(); finish(password.input.value); });
      dialog.showModal();
      password.input.focus();
    });
  }

  async function reauth(peer) {
    const password = await passwordDialog('Повторное подтверждение', 'Private-key профиль открывается одноразово на 90 секунд. Grant сгорает сразу после скачивания.');
    if (password === null) return null;
    return api(`/api/v1/wireguard-ingress/peers/${encodeURIComponent(peer.id)}/reauth`, {
      method: 'POST', body: JSON.stringify({ password_confirmation: password }),
    });
  }

  async function rawProfile(peer, type) {
    let token = '';
    if (peer.key_mode === 'MANAGED') {
      const grant = await reauth(peer);
      if (!grant) return null;
      token = grant.reauth_token;
    }
    const headers = token ? { 'X-Reauth-Token': token } : {};
    const response = await fetch(`/api/v1/wireguard-ingress/peers/${encodeURIComponent(peer.id)}/${type}`, { credentials: 'same-origin', headers });
    if (!response.ok) {
      let message = `HTTP ${response.status}`;
      try { message = (await response.json()).message || message; } catch (_) { /* binary response */ }
      throw new Error(message);
    }
    return response;
  }

  async function downloadConfig(peer) {
    const response = await rawProfile(peer, 'config');
    if (!response) return;
    const blob = await response.blob();
    const match = (response.headers.get('Content-Disposition') || '').match(/filename="?([^";]+)"?/i);
    const link = document.createElement('a');
    link.href = URL.createObjectURL(blob);
    link.download = match ? match[1] : `wireguard-client-${peer.number}.conf`;
    document.body.append(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(link.href);
    notice(peer.key_mode === 'MANAGED' ? 'Одноразовый профиль скачан' : 'Скачан шаблон без private key');
  }

  async function showQR(peer) {
    const response = await rawProfile(peer, 'qrcode');
    if (!response) return;
    const url = URL.createObjectURL(await response.blob());
    const dialog = document.createElement('dialog');
    dialog.className = 'modal qr-modal';
    const title = document.createElement('h2');
    title.textContent = `QR: ${peer.name}`;
    const warning = document.createElement('p');
    warning.className = 'restore-warning';
    warning.textContent = 'QR содержит private key. Закройте окно сразу после импорта.';
    const image = document.createElement('img');
    image.src = url;
    image.alt = `WireGuard QR для ${peer.name}`;
    const close = document.createElement('button');
    close.textContent = 'Закрыть и удалить из памяти';
    close.addEventListener('click', () => dialog.close());
    dialog.append(title, warning, image, close);
    dialog.addEventListener('close', () => { URL.revokeObjectURL(url); dialog.remove(); });
    document.body.append(dialog);
    dialog.showModal();
  }

  function methodSelector(methods, selected) {
    const box = document.createElement('fieldset');
    const legend = document.createElement('legend');
    legend.textContent = 'Разрешённые способы доступа';
    legend.title = 'Пустой список означает любой подходящий способ. Иначе клиент допускается только при активном отмеченном пункте.';
    box.append(legend);
    const controls = new Map();
    methods.forEach(method => {
      const item = check(`${method.name}${method.enabled ? '' : ' (отключён)'}`, method.id, selected.includes(method.id), `Разрешить клиенту способ «${method.name}».`);
      item.input.disabled = !method.enabled && !selected.includes(method.id);
      controls.set(method.id, item.input);
      box.append(item.label);
    });
    return { box, values: () => Array.from(controls).filter(([, input]) => input.checked).map(([id]) => id) };
  }

  function peerCard(peer, methods, rerender) {
    const details = document.createElement('details');
    details.className = 'card wireguard-peer';
    const summary = document.createElement('summary');
    const peerState = peer.revoked_at ? 'REVOKED' : (peer.enabled ? peer.runtime_state : 'DISABLED');
    summary.append(document.createTextNode(`#${peer.number} · ${peer.name} · `), badge(peerState), document.createTextNode(` · ${peer.assigned_address}`));
    details.append(summary);
    const status = document.createElement('div');
    status.className = 'grid';
    status.append(
      card('Тип', peer.peer_kind, peer.key_mode === 'MANAGED' ? 'Ключ хранится root-only' : 'Только внешний public key'),
      card('Handshake', peer.last_handshake_at || 'Ещё не было', peer.observed_endpoint || 'Endpoint не наблюдался'),
      card('Получено', bytes(peer.rx_bytes), 'Kernel WireGuard counter'),
      card('Отправлено', bytes(peer.tx_bytes), 'Kernel WireGuard counter'),
    );
    details.append(status);

    const form = document.createElement('form');
    form.className = 'settings-form wireguard-peer-editor';
    const name = field('Название', 'name', peer.name, 'Понятное имя устройства или удалённого роутера.', { required: true });
    const enabled = check('Клиент включён', 'enabled', peer.enabled, 'Выключение удаляет peer из kernel, но сохраняет номер и настройки.');
    const keepalive = field('Persistent keepalive, секунд', 'keepalive', peer.persistent_keepalive, 'Обычно 25 для клиента за NAT; 0 отключает keepalive.', { type: 'number', min: 0, max: 65535, required: true });
    const mode = field('Тип выхода', 'mode', peer.access_policy_mode, 'AUTO допускает direct и VPN. Остальные варианты жёстко ограничивают способ.', { choices: [
      { value: 'AUTO', label: 'Автоматически' }, { value: 'DIRECT_ONLY', label: 'Только прямой Internet' }, { value: 'VPN_ONLY', label: 'Только VPN' },
    ] });
    const whitelist = check('Разрешать режим только белых списков', 'whitelist', peer.allow_whitelist_only, 'Если выключено, peer блокируется при активном WHITELIST_ONLY direct-пути.');
    const block = check('Блокировать при неподходящем пути', 'block', peer.block_when_unqualified, 'Рекомендуется. Если выключено, разрешён любой глобально проверенный путь как аварийный fallback.');
    const dns = check('Передавать DNS клиенту', 'dns', peer.client_dns_enabled, 'Добавляет явно заданные внешние DNS-адреса в скачиваемый конфиг. Пустой список не меняет DNS на клиенте.');
    const endpoint = field('Endpoint peer — необязательно', 'endpoint', peer.endpoint_override || '', 'Только для site-to-site peer со стабильным адресом, формат host:port.');
    const behind = field('Подсети за роутером', 'behind', (peer.behind_subnets || []).join(', '), 'Для ROUTER_ROUTED. Не должны пересекаться с LAN, tunnel, management и другими peers.', { multiline: true });
    const allowed = field('AllowedIPs клиента', 'allowed', (peer.client_allowed_ips || []).join(', '), 'Какие назначения клиент отправляет в Gateway; 0.0.0.0/0 — весь IPv4.', { multiline: true, required: true });
    const method = methodSelector(methods, peer.allowed_access_method_ids || []);
    const save = document.createElement('button');
    save.type = 'submit';
    save.textContent = 'Сохранить клиента';
    save.disabled = Boolean(peer.revoked_at);
    form.append(name.label, enabled.label, keepalive.label, mode.label, whitelist.label, block.label, dns.label, endpoint.label, behind.label, allowed.label, method.box, save);
    form.addEventListener('submit', async event => {
      event.preventDefault();
      await api(`/api/v1/wireguard-ingress/peers/${encodeURIComponent(peer.id)}`, { method: 'PATCH', body: JSON.stringify({
        name: name.input.value.trim(), enabled: enabled.input.checked,
        endpoint_override: endpoint.input.value.trim(), persistent_keepalive: Number(keepalive.input.value),
        access_policy_mode: mode.input.value, allow_whitelist_only: whitelist.input.checked,
        block_when_unqualified: block.input.checked, client_dns_enabled: dns.input.checked,
        behind_subnets: list(behind.input.value), client_allowed_ips: list(allowed.input.value),
        allowed_access_method_ids: method.values(),
      }) });
      notice('WireGuard-клиент сохранён и применён');
      await rerender();
    });
    details.append(form);

    const actions = actionGroup(
      help(actionButton('Проверить', async () => { await api(`/api/v1/wireguard-ingress/peers/${encodeURIComponent(peer.id)}/probe`, { method: 'POST' }); notice('Handshake и счётчики перечитаны'); await rerender(); }, false, Boolean(peer.revoked_at)), 'Читает kernel state без генерации пользовательского трафика.'),
      help(actionButton('Скачать .conf', () => downloadConfig(peer), false, Boolean(peer.revoked_at)), 'Managed-профиль требует текущий пароль и выдаётся одноразово.'),
      help(actionButton('QR', () => showQR(peer), false, peer.key_mode !== 'MANAGED' || Boolean(peer.revoked_at)), 'Показывает managed private profile после повторного ввода пароля.'),
      help(actionButton('Сменить ключ', async () => {
        const password = await passwordDialog('Смена ключа клиента', 'Старый профиль немедленно перестанет работать. После операции скачайте новый.');
        if (password === null || !confirm('Заменить keypair и PSK клиента?')) return;
        await api(`/api/v1/wireguard-ingress/peers/${encodeURIComponent(peer.id)}/rotate`, { method: 'POST', body: JSON.stringify({ password_confirmation: password, confirmation: 'ROTATE_WIREGUARD_CLIENT_KEY' }) });
        notice('Ключ заменён; скачайте новый профиль');
        await rerender();
      }, true, peer.key_mode !== 'MANAGED' || Boolean(peer.revoked_at)), 'Только managed key; старый профиль отзывается.'),
      help(actionButton('Отозвать', async () => {
        if (!confirm(`Немедленно отозвать «${peer.name}»?`)) return;
        await api(`/api/v1/wireguard-ingress/peers/${encodeURIComponent(peer.id)}/revoke`, { method: 'POST', headers: { 'X-Confirm-Destructive': 'revoke-wireguard-peer' } });
        notice('Клиент отозван и удалён из kernel');
        await rerender();
      }, true, Boolean(peer.revoked_at)), 'Сохраняет запись для аудита, но запрещает подключение.'),
      help(actionButton('Удалить запись', async () => {
        if (!confirm(`Удалить отозванного клиента #${peer.number} и managed key files?`)) return;
        await api(`/api/v1/wireguard-ingress/peers/${encodeURIComponent(peer.id)}`, { method: 'DELETE', headers: { 'X-Confirm-Destructive': 'delete-revoked-wireguard-peer' } });
        notice('Отозванный клиент удалён; номер не переиспользуется');
        await rerender();
      }, true, !peer.revoked_at), 'Доступно только после отзыва и необратимо.'),
    );
    details.append(actions);
    return details;
  }

  wireGuardIngressPanel = async function renderWireGuardIngress() {
    const [serverResponse, peerResponse, interfaceResponse, methodResponse] = await Promise.all([
      api('/api/v1/wireguard-ingress'), api('/api/v1/wireguard-ingress/peers'),
      api('/api/v1/network/interfaces'), api('/api/v1/access-methods'),
    ]);
    const server = serverResponse.server;
    const peers = peerResponse.items || [];
    const interfaces = (interfaceResponse.items || []).filter(item => item.carrier_state !== 'ABSENT');
    const methods = methodResponse.items || [];
    const rerender = () => wireGuardIngressPanel();

    const summary = document.createElement('div');
    summary.className = 'grid';
    summary.append(
      card('WireGuard-сервер', server.enabled ? server.state : 'DISABLED', `${server.interface_name} · ${server.server_address}`),
      card('Включено клиентов', peers.filter(peer => peer.enabled && !peer.revoked_at).length, `${peers.length} записей всего`),
      card('Свежий handshake', peers.filter(peer => peer.runtime_state === 'HEALTHY').length, 'Не равен проверке глобального Internet'),
      card('Public key сервера', shortKey(server.public_key), `UDP/${server.listen_port}`),
    );
    const intro = document.createElement('section');
    intro.className = 'card';
    intro.innerHTML = '<h2>Входящий WireGuard</h2><p class="muted">Принимает трафик устройств и роутеров и отделён от служебного <code>wg-mgmt</code>. Клиент проходит только через разрешённый проверенный direct/VPN-путь. Private keys не попадают в SQLite, обычный API, логи и диагностику.</p>';

    const serverForm = document.createElement('form');
    serverForm.className = 'card settings-form wireguard-server-editor';
    const serverTitle = document.createElement('h2');
    serverTitle.textContent = 'Настройки сервера';
    const enabled = check('Включить входящий WireGuard', 'enabled', server.enabled, 'При ошибке применения wg-ingress полностью удаляется из kernel — fail-closed.');
    const name = field('Название', 'name', server.name, 'Понятное локальное имя сервера.', { required: true });
    const subnet = field('Подсеть клиентов', 'subnet', server.subnet_cidr, 'Приватная IPv4 /16…/29 без пересечений с LAN, uplinks и 10.80.0.0/24.', { required: true });
    const port = field('UDP-порт', 'port', server.listen_port, '51821 зарезервирован служебным wg-mgmt.', { type: 'number', min: 1, max: 65535, required: true });
    const endpoint = field('Публичный IP или DNS-имя', 'endpoint', server.endpoint_host, 'Адрес, который будет записан в клиентские профили.', { required: true });
    const mtu = field('MTU', 'mtu', server.mtu, 'Обычно 1420; меняйте при доказанной фрагментации.', { type: 'number', min: 576, max: 9000, required: true });
    const topology = field('Топология', 'topology', server.topology_mode, 'ONE_ARM принимает и возвращает трафик через одну карту с ролью SHARED_ONE_ARM.', { choices: [
      { value: 'ROUTED', label: 'Обычная маршрутизация' }, { value: 'ONE_ARM', label: 'Одна карта (one-arm)' },
    ] });
    const interfaceChoices = [{ value: '', label: 'Автоматически по активному пути' }, ...interfaces.map(item => ({
      value: item.id, label: `${item.interface_name || 'без имени'} · ${(item.roles || []).map(role => role.role).join(', ') || 'без роли'}`,
    }))];
    const egress = field('Карта транспорта', 'egress', server.network_interface_id || '', 'Для ONE_ARM обязательна карта с enabled uplink; она задаёт fwmark UDP WireGuard.', { choices: interfaceChoices });
    const dns = field('DNS для клиентов (необязательно)', 'dns', (server.dns || []).join(', '), 'Внешние IPv4 DNS, например 1.1.1.1 или 9.9.9.9. Они идут через текущий проверенный маршрут. 10.90.0.1 не является DNS-сервером.', {});
    const listeners = document.createElement('fieldset');
    const listenerTitle = document.createElement('legend');
    listenerTitle.textContent = 'Интерфейсы приёма UDP';
    listenerTitle.title = 'Firewall открывает только отмеченные exact interface/port tuples. PUBLIC требует WG_ENDPOINT или SHARED_ONE_ARM.';
    listeners.append(listenerTitle);
    const configured = new Map((server.listen_interfaces || []).map(item => [item.network_interface_id, item]));
    const listenerControls = [];
    interfaces.forEach(item => {
      const row = document.createElement('div');
      row.className = 'wireguard-listener-row';
      const selected = check(`${item.interface_name || 'без имени'} · ${(item.roles || []).map(role => role.role).join(', ') || 'без роли'}`, item.id, configured.has(item.id), 'Принимать WireGuard UDP на этом интерфейсе.');
      const exposure = document.createElement('select');
      exposure.title = 'LOCAL — из доверенной сети; PUBLIC — внешний интерфейс со специальной ролью.';
      exposure.innerHTML = '<option value="LOCAL">Локальная сеть</option><option value="PUBLIC">Публичный интерфейс</option>';
      exposure.value = configured.get(item.id)?.exposure_mode || 'LOCAL';
      row.append(selected.label, exposure);
      listeners.append(row);
      listenerControls.push({ id: item.id, selected: selected.input, exposure });
    });
    if (!listenerControls.length) {
      const warning = document.createElement('p');
      warning.className = 'restore-warning';
      warning.textContent = 'Нет доступных интерфейсов. Сначала назначьте карту во вкладке «Сеть».';
      listeners.append(warning);
    }
    const saveServer = document.createElement('button');
    saveServer.type = 'submit';
    saveServer.textContent = 'Сохранить и применить';
    serverForm.append(serverTitle, enabled.label, name.label, subnet.label, port.label, endpoint.label, mtu.label, topology.label, egress.label, dns.label, listeners, saveServer);
    serverForm.addEventListener('submit', async event => {
      event.preventDefault();
      const selected = listenerControls.filter(item => item.selected.checked).map((item, index) => ({ network_interface_id: item.id, exposure_mode: item.exposure.value, priority: index + 1 }));
      await api('/api/v1/wireguard-ingress', { method: 'PUT', body: JSON.stringify({
        enabled: enabled.input.checked, name: name.input.value.trim(), subnet_cidr: subnet.input.value.trim(),
        listen_port: Number(port.input.value), endpoint_host: endpoint.input.value.trim(), mtu: Number(mtu.input.value),
        topology_mode: topology.input.value, network_interface_id: egress.input.value,
        dns: list(dns.input.value), listen_interfaces: selected,
      }) });
      notice('WireGuard-сервер применён и проверен');
      await rerender();
    });
    serverForm.append(actionGroup(
      help(actionButton('Копировать public key', async () => { await navigator.clipboard.writeText(server.public_key); notice('Public key скопирован'); }), 'Public key не является секретом.'),
      help(actionButton('Сменить ключ сервера', async () => {
        const password = await passwordDialog('Смена ключа сервера', 'Все старые клиентские профили перестанут подключаться.');
        if (password === null || !confirm('Заменить ключ сервера?')) return;
        await api('/api/v1/wireguard-ingress/rotate', { method: 'POST', body: JSON.stringify({ password_confirmation: password, confirmation: 'ROTATE_WIREGUARD_SERVER_KEY' }) });
        notice('Ключ сервера заменён; обновите клиентские профили');
        await rerender();
      }, true), 'Необратимо отзывает прежний public key сервера.'),
    ));

    const create = document.createElement('form');
    create.className = 'card settings-form wireguard-peer-create';
    const createTitle = document.createElement('h2');
    createTitle.textContent = 'Добавить клиента';
    const peerName = field('Название', 'name', '', 'Например «Телефон Игоря» или «Keenetic филиала».', { required: true });
    const kind = field('Тип', 'kind', 'DEVICE', 'DEVICE — устройство; ROUTER_NAT — роутер с NAT; ROUTER_ROUTED — маршрутизируемые подсети.', { choices: [
      { value: 'DEVICE', label: 'Одно устройство' }, { value: 'ROUTER_NAT', label: 'Роутер с NAT' }, { value: 'ROUTER_ROUTED', label: 'Роутер с routed-подсетями' },
    ] });
    const keyMode = field('Ключ', 'key_mode', 'MANAGED', 'MANAGED создаёт root-only key и одноразовый .conf/QR; EXTERNAL хранит только public key.', { choices: [
      { value: 'MANAGED', label: 'Создать на Gateway' }, { value: 'EXTERNAL', label: 'Внешний public key' },
    ] });
    const publicKey = field('Public key клиента', 'public_key', '', 'WireGuard public key в base64; только для EXTERNAL.');
    const address = field('Желаемый адрес — необязательно', 'address', '', 'Пустое поле выбирает первый свободный адрес.');
    const behind = field('Подсети за роутером', 'behind', '', 'Только ROUTER_ROUTED, через запятую.', { multiline: true });
    const allowed = field('AllowedIPs клиента', 'allowed', '0.0.0.0/0', '0.0.0.0/0 отправляет через Gateway весь IPv4.', { multiline: true, required: true });
    const createButton = document.createElement('button');
    createButton.type = 'submit';
    createButton.textContent = 'Создать клиента';
    create.append(createTitle, peerName.label, kind.label, keyMode.label, publicKey.label, address.label, behind.label, allowed.label, createButton);
    const syncMode = () => { publicKey.label.hidden = keyMode.input.value !== 'EXTERNAL'; publicKey.input.required = keyMode.input.value === 'EXTERNAL'; };
    keyMode.input.addEventListener('change', syncMode);
    syncMode();
    create.addEventListener('submit', async event => {
      event.preventDefault();
      const result = await api('/api/v1/wireguard-ingress/peers', { method: 'POST', body: JSON.stringify({
        name: peerName.input.value.trim(), peer_kind: kind.input.value, key_mode: keyMode.input.value,
        public_key: keyMode.input.value === 'EXTERNAL' ? publicKey.input.value.trim() : '', assigned_address: address.input.value.trim(),
        persistent_keepalive: 25, access_policy_mode: 'AUTO', allow_whitelist_only: true,
        block_when_unqualified: true, client_dns_enabled: true, behind_subnets: list(behind.input.value),
        client_allowed_ips: list(allowed.input.value), allowed_access_method_ids: [],
      }) });
      notice(`Клиент #${result.peer.number} создан${result.peer.key_mode === 'MANAGED' ? '; скачайте профиль' : ''}`);
      await rerender();
    });

    const peersTitle = document.createElement('h2');
    peersTitle.textContent = 'Клиенты';
    const peersHelp = document.createElement('p');
    peersHelp.className = 'muted';
    peersHelp.textContent = 'Разверните клиента, чтобы изменить policy или выполнить действие. Handshake показывает связь с peer, а доступность Internet определяется отдельной проверкой активного пути.';
    const peerNodes = peers.map(peer => peerCard(peer, methods, rerender));
    if (!peerNodes.length) {
      const empty = document.createElement('section');
      empty.className = 'card muted';
      empty.textContent = 'Клиенты ещё не созданы.';
      peerNodes.push(empty);
    }
    setContent(summary, intro, serverForm, create, peersTitle, peersHelp, ...peerNodes);
  };
})();
