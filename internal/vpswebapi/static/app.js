'use strict';

const $=id=>document.getElementById(id);
const ui={csrf:'',page:'overview',invitation:null,gateways:[],admins:[],resources:[],logCategory:'all'};

async function api(path,options={}){
  const headers={...(options.headers||{})};
  if(options.body&&!(options.body instanceof FormData))headers['Content-Type']='application/json';
  if(options.method&&options.method!=='GET')headers['X-CSRF-Token']=ui.csrf;
  const response=await fetch(path,{credentials:'same-origin',...options,headers});
  if(!response.ok){let message=`HTTP ${response.status}`;try{message=(await response.json()).error.message}catch{}throw new Error(message)}
  if(response.status===204)return null;
  return response.json();
}

function notice(message){$('notice').textContent=message||''}
function clear(root){root.replaceChildren()}
function textElement(tag,value,className=''){const node=document.createElement(tag);node.textContent=String(value??'—');if(className)node.className=className;return node}
function status(value){return textElement('span',value||'UNKNOWN',`status ${value||'UNKNOWN'}`)}
function empty(root,message){clear(root);root.append(textElement('div',message,'empty'))}
function summary(rows){const list=document.createElement('dl');list.className='summary';for(const [label,value] of rows){list.append(textElement('dt',label),textElement('dd',value))}return list}
function objectCard(title,rows,stateValue,actions=[]){const card=document.createElement('article');card.className='card object';const heading=document.createElement('div');heading.className='row';const titleNode=textElement('h3',title);heading.append(titleNode,status(stateValue));card.append(heading,summary(rows));if(actions.length){const bar=document.createElement('div');bar.className='actions';for(const action of actions)bar.append(action);card.append(bar)}return card}
function actionButton(label,handler,danger=false){const button=textElement('button',label,danger?'danger':'secondary');button.type='button';button.addEventListener('click',handler);return button}
function setOptions(select,items,label){clear(select);for(const item of items){const option=document.createElement('option');option.value=item.id;option.textContent=label(item);select.append(option)}select.disabled=items.length===0}
function countStates(values){return Object.entries(values||{}).map(([key,value])=>`${key}: ${value}`).join(', ')||'нет'}

function showApp(session){
  ui.csrf=session.csrf_token;$('login').hidden=true;$('app').hidden=false;
  const required=Boolean(session.must_change_password);$('password-card').hidden=!required;$('navigation').hidden=required;$('mobile-navigation').hidden=required;
  document.querySelectorAll('[data-page-panel]').forEach(panel=>panel.hidden=required||panel.dataset.pagePanel!==ui.page);
  if(required){notice('Задайте собственный пароль VPS Hub перед продолжением.');return}
  const saved=localStorage.getItem('gateway-vpn-vps-page');
  navigate(document.querySelector(`[data-page="${saved}"]`)?saved:'overview');
}
function showLogin(){$('app').hidden=true;$('login').hidden=false}
async function navigate(page){
  if(ui.page==='gateways'&&page!=='gateways'&&ui.invitation){ui.invitation=null;$('pairing-bundle').textContent='';$('pairing-once').hidden=true}
  ui.page=page;localStorage.setItem('gateway-vpn-vps-page',page);
  $('mobile-navigation-select').value=page;
  document.querySelectorAll('[data-page-panel]').forEach(panel=>panel.hidden=panel.dataset.pagePanel!==page);
  document.querySelectorAll('[data-page]').forEach(button=>button.classList.toggle('active',button.dataset.page===page));
  notice('');
  try{await loadPage(page)}catch(error){notice(error.message)}
}
async function loadPage(page){
  if(page==='overview')return loadOverview();
  if(page==='gateways')return loadGateways();
  if(page==='channels')return loadChannels();
  if(page==='admins')return loadAdmins();
  if(page==='relays')return loadRelays();
  if(page==='resources')return loadResources();
  if(page==='matrix')return loadMatrix();
  if(page==='watchdog')return loadWatchdog();
  if(page==='logs')return loadLogs();
  if(page==='backup')return refreshBackupStatus();
  if(page==='update')return loadUpdate();
  if(page==='diagnostics')return loadDiagnostics();
}

async function loadOverview(){
  const item=await api('/api/v1/hub/overview');const root=$('overview-content');clear(root);
  const hostPending=item.desired_generation!==item.applied_generation,hostActions=[];
  if(item.host_apply_available&&hostPending)hostActions.push(actionButton('Применить изменения сейчас',()=>applyFabricNow('overview')));
  root.append(
    objectCard(item.identity.display_name,[['VPS ID',item.identity.vps_id],['Fingerprint',item.identity.identity_fingerprint],['Schema',item.schema_version]],'ACTIVE'),
    objectCard('Gateway',[['Состояния',countStates(item.gateways)],['Открытых приглашений',item.open_invitations]],item.open_invitations?'PENDING':'HEALTHY'),
    objectCard('Доступ',[['Администраторы',countStates(item.administrators)],['Ресурсы',countStates(item.resources)],['ACL правил',item.acl_grants]],item.fabric_state),
    objectCard('Применение на host',[['Desired generation',item.desired_generation],['Applied generation',item.applied_generation],['Привилегированный reconciler',item.host_apply_available?'Доступен':'Недоступен']],item.host_apply_available?(hostPending?'PENDING':'HEALTHY'):'FAILED',hostActions)
  );
}

async function applyFabricNow(refreshPage=ui.page){
  if(!confirm('Поставить безопасное применение Management Fabric в очередь? При ошибке предыдущая конфигурация будет восстановлена.'))return;
  try{const result=await api('/api/v1/hub/fabric/apply',{method:'POST',body:'{}'});notice(result.state==='ALREADY_APPLIED'?'Management Fabric уже соответствует настройкам.':`Применение generation ${result.generation} поставлено в очередь.`);setTimeout(()=>loadPage(refreshPage).catch(error=>notice(error.message)),1000)}catch(error){notice(error.message)}
}

async function loadGateways(){
  const [pairings,gateways]=await Promise.all([api('/api/v1/hub/pairing-invitations'),api('/api/v1/hub/gateways')]);
  ui.gateways=gateways.items||[];renderPairings(pairings.items||[]);renderGateways($('gateway-list'),ui.gateways,true);
}
function renderPairings(items){
  const root=$('pairing-list');if(!items.length){empty(root,'Приглашений ещё нет.');return}clear(root);
  for(const item of items){const actions=[];if(item.state==='OPEN')actions.push(actionButton('Отозвать',async()=>{if(!confirm('Отозвать это одноразовое приглашение?'))return;try{await api(`/api/v1/hub/pairing-invitations/${encodeURIComponent(item.invitation_id)}`,{method:'DELETE',headers:{'X-Confirm-Destructive':'reject-pairing-invitation'}});notice('Приглашение отозвано');await loadGateways()}catch(error){notice(error.message)}},true));root.append(objectCard(item.gateway_name||item.invitation_id,[['ID',item.invitation_id],['Подсеть',item.assigned_subnet],['Endpoint',item.endpoint],['Истекает',item.expires_at],['Попыток',item.attempt_count]],item.state,actions))}
}
function renderGateways(root,items,destructive){
  if(!items.length){empty(root,'Ни один Gateway ещё не связан с этим VPS.');return}clear(root);
  for(const item of items){const actions=[];if(item.webui_url)actions.push(actionButton('Открыть WebUI',()=>window.open(item.webui_url,'_blank','noopener')));if(destructive&&item.state!=='REVOKED')actions.push(actionButton('Отозвать Gateway',()=>revokeGateway(item),true));root.append(objectCard(item.display_name,[['Site ID',item.site_id],['Peer ID',item.id],['Подсеть',item.assigned_subnet],['Gateway / VPS',`${item.assigned_address} / ${item.remote_address}`],['Endpoint',item.endpoint],['Handshake',item.latest_handshake_at||'ещё не наблюдался'],['Generation',`${item.applied_generation} / ${item.desired_generation}`],['Причина',item.status_reason||'—']],item.state,actions))}
}
async function revokeGateway(item){
  const phrase=`ОТОЗВАТЬ GATEWAY ${item.id}`;if(!confirm(`Будут закрыты канал и все публикации этого Gateway. Продолжить?`))return;
  const password=prompt('Введите текущий пароль VPS Hub');if(password===null)return;const confirmation=prompt(`Введите точную фразу:\n${phrase}`);if(confirmation===null)return;
  try{await api(`/api/v1/hub/gateways/${encodeURIComponent(item.id)}/revoke`,{method:'POST',body:JSON.stringify({password,confirmation})});notice('Gateway отозван; host generation ожидает применения');await loadGateways()}catch(error){notice(error.message)}
}
async function loadChannels(){const gateways=await api('/api/v1/hub/gateways');ui.gateways=gateways.items||[];renderGateways($('channel-list'),ui.gateways,false)}

async function loadAdmins(){
  const response=await api('/api/v1/hub/admins');ui.admins=response.items||[];const root=$('admin-list');
	$('managed-admin-card').hidden=!response.managed_key_creation_available;
  if(!ui.admins.length){empty(root,'Администраторы ещё не добавлены.');return}clear(root);
	  for(const item of ui.admins){const actions=[];if(item.key_mode==='MANAGED'&&item.config_state==='AVAILABLE')actions.push(actionButton('Скачать конфиг один раз',()=>downloadAdminConfig(item)));if(item.key_mode==='MANAGED'&&item.state!=='REVOKED')actions.push(actionButton('Начать смену ключа',()=>rotateAdmin(item)));if(item.key_mode==='EXTERNAL'&&item.state!=='REVOKED'){const next=item.trust_mode==='END_TO_END_RELAY'?'ROUTED_HUB':'END_TO_END_RELAY';actions.push(actionButton(next==='END_TO_END_RELAY'?'Включить end-to-end':'Перевести через VPS Hub',()=>changeAdminTrustMode(item,next)))}if(item.state!=='REVOKED')actions.push(actionButton('Отозвать',()=>revokeAdmin(item),true));root.append(objectCard(item.name,[['ID',item.id],['Адрес',item.assigned_address],['Режим ключа',item.key_mode],['Режим доверия',item.trust_mode||'ROUTED_HUB'],['Готовый конфиг',item.config_state],['Скачан',item.config_downloaded_at||'нет'],['Сменяет ключ',item.rotation_source_id||'—'],['Handshake',item.latest_handshake_at||'ещё не наблюдался'],['Generation',`${item.applied_generation} / ${item.desired_generation}`],['Причина',item.status_reason||'—']],item.state,actions))}
}
async function changeAdminTrustMode(item,trust_mode){
  const explanation=trust_mode==='END_TO_END_RELAY'?'Внутренний private key должен оставаться только у администратора и на Gateway. VPS будет выполнять лишь UDP relay.':'Сессия администратора будет завершаться на VPS Hub и проходить по его ACL.';
  if(!confirm(`${explanation}\n\nИзменить режим для «${item.name}»?`))return;
  try{await api(`/api/v1/hub/admins/${encodeURIComponent(item.id)}/trust-mode`,{method:'PUT',body:JSON.stringify({trust_mode})});notice(`Режим доверия изменён на ${trust_mode}; host generation ожидает применения`);await loadAdmins()}catch(error){notice(error.message)}
}
async function downloadAdminConfig(item){
  if(!confirm('Конфигурацию можно скачать только один раз. После ответа приватный ключ будет удалён с VPS. Продолжить?'))return;
  let endpoint=prompt('Публичный WireGuard endpoint этого VPS в формате host:port',ui.gateways.find(gateway=>gateway.state!=='REVOKED')?.endpoint||'');if(endpoint===null)return;
  let password=prompt('Введите текущий пароль VPS Hub');if(password===null)return;let confirmation=prompt(`Введите точную фразу:\nСКАЧАТЬ КОНФИГУРАЦИЮ ${item.id}`);if(confirmation===null)return;
  try{const response=await fetch(`/api/v1/hub/admins/${encodeURIComponent(item.id)}/config`,{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json','X-CSRF-Token':ui.csrf},body:JSON.stringify({endpoint,password,confirmation})});endpoint=password=confirmation='';if(!response.ok){const body=await response.json();throw new Error(body.error.message)}const blob=await response.blob(),name=(response.headers.get('Content-Disposition')||'').match(/filename="([^"]+)"/)?.[1]||'gateway-vpn-administrator.conf',link=document.createElement('a');link.href=URL.createObjectURL(blob);link.download=name;link.click();setTimeout(()=>URL.revokeObjectURL(link.href),1000);notice(`Конфигурация ${name} выдана один раз; приватный ключ удалён с VPS`);await loadAdmins()}catch(error){endpoint=password=confirmation='';notice(error.message)}
}
async function rotateAdmin(item){
  const assigned_address=prompt('Новый уникальный Private IPv4 для сменного peer');if(assigned_address===null)return;const name=prompt('Название сменного устройства/ключа',`${item.name} — сменный ключ`);if(name===null)return;let password=prompt('Введите текущий пароль VPS Hub');if(password===null)return;let confirmation=prompt(`Введите точную фразу:\nНАЧАТЬ СМЕНУ КЛЮЧА ${item.id}`);if(confirmation===null)return;
  try{await api(`/api/v1/hub/admins/${encodeURIComponent(item.id)}/rotate`,{method:'POST',body:JSON.stringify({name,assigned_address,password,confirmation})});password=confirmation='';notice('Сменный peer создан. Скачайте его конфиг, дождитесь handshake и только затем отзывайте прежний peer.');await loadAdmins()}catch(error){password=confirmation='';notice(error.message)}
}
async function revokeAdmin(item){
  const phrase=`ОТОЗВАТЬ АДМИНИСТРАТОРА ${item.id}`;if(!confirm('Будут немедленно удалены все ACL этого администратора. Продолжить?'))return;
  const password=prompt('Введите текущий пароль VPS Hub');if(password===null)return;const confirmation=prompt(`Введите точную фразу:\n${phrase}`);if(confirmation===null)return;
  try{await api(`/api/v1/hub/admins/${encodeURIComponent(item.id)}/revoke`,{method:'POST',body:JSON.stringify({password,confirmation})});notice('Администратор и его ACL отозваны');await loadAdmins()}catch(error){notice(error.message)}
}

async function loadRelays(){
  const [gateways,response]=await Promise.all([api('/api/v1/hub/gateways'),api('/api/v1/hub/admin-relays')]);ui.gateways=(gateways.items||[]).filter(item=>item.state!=='REVOKED');setOptions($('relay-form').elements.gateway_peer_id,ui.gateways,item=>`${item.display_name} — ${item.assigned_address}`);
  const root=$('relay-list'),items=response.items||[];if(!items.length){empty(root,'End-to-end relay ещё не настроены.');return}clear(root);const gatewayNames=new Map(ui.gateways.map(item=>[item.id,item.display_name]));
  for(const item of items){const actions=[actionButton(item.enabled?'Отключить relay':'Включить relay',async()=>{try{await api(`/api/v1/hub/admin-relays/${encodeURIComponent(item.id)}/enabled`,{method:'PUT',body:JSON.stringify({enabled:!item.enabled})});notice(item.enabled?'Relay отключён; правила будут безопасно удалены':'Relay включён; правила ожидают безопасного применения');await loadRelays()}catch(error){notice(error.message)}})];if(!item.enabled)actions.push(actionButton('Удалить relay',async()=>{if(!confirm('Удалить отключённый relay? Его внешний UDP-порт перестанет быть частью конфигурации Gateway VPN.'))return;try{await api(`/api/v1/hub/admin-relays/${encodeURIComponent(item.id)}`,{method:'DELETE',headers:{'X-Confirm-Destructive':'delete-disabled-admin-relay'}});notice('Отключённый relay удалён');await loadRelays()}catch(error){notice(error.message)}},true));root.append(objectCard(`${gatewayNames.get(item.gateway_peer_id)||item.gateway_peer_id} — UDP ${item.public_udp_port}`,[['Relay ID',item.id],['Gateway peer',item.gateway_peer_id],['Публичный endpoint',`${item.public_endpoint_host}:${item.public_udp_port}/UDP`],['Bind на VPS',item.public_bind_address],['Назначение на Gateway',`UDP ${item.destination_port||response.destination_port}`],['Rate / burst',`${item.rate_limit_per_second} / ${item.burst_packets} пакетов`],['Приватные ключи на VPS',response.private_keys_on_vps?'ОШИБКА: обнаружены':'Нет'],['Generation',`${item.applied_generation} / ${item.desired_generation}`],['Причина',item.status_reason||'—']],item.state,actions))}
}

async function loadResources(){
  const [gateways,resources]=await Promise.all([api('/api/v1/hub/gateways'),api('/api/v1/hub/resources')]);ui.gateways=(gateways.items||[]).filter(item=>item.state!=='REVOKED');ui.resources=resources.items||[];
  setOptions($('resource-form').elements.gateway_peer_id,ui.gateways,item=>`${item.display_name} — ${item.assigned_address}`);
  const root=$('resource-list');if(!ui.resources.length){empty(root,'Локальные ресурсы ещё не опубликованы.');return}clear(root);
  for(const item of ui.resources){const actions=[actionButton('Удалить публикацию',async()=>{if(!confirm(`Удалить публикацию «${item.display_name}» и связанные ACL?`))return;try{await api(`/api/v1/hub/resources/${encodeURIComponent(item.id)}`,{method:'DELETE',headers:{'X-Confirm-Destructive':'delete-resource-publication'}});notice('Публикация удалена');await loadResources()}catch(error){notice(error.message)}},true)];root.append(objectCard(item.display_name,[['ID ресурса',item.resource_id],['Gateway peer',item.gateway_peer_id],['Тип / профиль',`${item.resource_kind} / ${item.access_profile}`],['Локально → alias',`${item.local_destination} → ${item.published_alias}`],['Health',item.health],['Generation',`${item.applied_generation} / ${item.desired_generation}`],['Причина',item.status_reason||'—']],item.state,actions))}
}

async function loadMatrix(){
  const matrix=await api('/api/v1/hub/access-matrix');ui.admins=(matrix.administrators||[]).filter(item=>item.state!=='REVOKED');ui.resources=(matrix.resources||[]).filter(item=>item.enabled&&item.state!=='DISABLED');
  setOptions($('acl-form').elements.admin_peer_id,ui.admins,item=>`${item.name} — ${item.assigned_address}`);setOptions($('acl-form').elements.publication_id,ui.resources,item=>`${item.display_name} — ${item.published_alias}`);
  const generation=$('matrix-generation');clear(generation);for(const [label,value] of [['Состояние',matrix.state],['Desired',matrix.desired_generation],['Applied',matrix.applied_generation],['Host apply',matrix.host_apply_available?'Доступен':'Недоступен']])generation.append(textElement('dt',label),textElement('dd',value));const generationCard=generation.closest('.card');generationCard.querySelector('.fabric-apply-action')?.remove();if(matrix.host_apply_available&&matrix.desired_generation!==matrix.applied_generation){const apply=actionButton('Применить generation',()=>applyFabricNow('matrix'));apply.classList.add('fabric-apply-action');generationCard.append(apply)}
  const root=$('acl-list'),grants=matrix.grants||[];if(!grants.length){empty(root,'Явных разрешений пока нет — действует default deny.');return}clear(root);
  const admins=new Map((matrix.administrators||[]).map(item=>[item.id,item]));const resources=new Map((matrix.resources||[]).map(item=>[item.id,item]));
  for(const item of grants){const admin=admins.get(item.admin_peer_id),resource=resources.get(item.publication_id);const ports=item.protocol==='ICMP'?'ICMP':`${item.port_start}–${item.port_end}`;const remove=actionButton('Удалить правило',async()=>{if(!confirm('Удалить это разрешение?'))return;try{await api(`/api/v1/hub/acl/${encodeURIComponent(item.id)}`,{method:'DELETE',headers:{'X-Confirm-Destructive':'delete-acl-grant'}});notice('ACL удалён; новая generation ожидает применения');await loadMatrix()}catch(error){notice(error.message)}},true);root.append(objectCard(`${admin?.name||item.admin_peer_id} → ${resource?.display_name||item.publication_id}`,[['Протокол / порты',`${item.protocol} ${ports}`],['Alias',resource?.published_alias||'—'],['Generation',item.generation],['ACL ID',item.id]],'PENDING',[remove]))}
}

async function loadWatchdog(){
  const [report,overview]=await Promise.all([api('/api/v1/hub/watchdog'),api('/api/v1/hub/overview')]);const root=$('watchdog-content');clear(root);root.append(objectCard('Общее состояние',[['Проверено',report.checked_at],['Граница', 'Только owned Gateway VPN objects']],report.state));
  const host=report.host_fabric||{},hostActions=[];if(overview.host_apply_available&&(overview.desired_generation!==overview.applied_generation||host.state!=='HEALTHY'))hostActions.push(actionButton('Запустить reconciliation',()=>applyFabricNow('watchdog')));root.append(objectCard('Management Fabric host watchdog',[['Статус получен',host.available?'Да':'Нет'],['Последняя root-проверка',host.checked_at||'ещё не выполнялась'],['Причина',host.reason||'STATUS_UNAVAILABLE'],['Reconciliation поставлен',host.reconcile_scheduled?'Да':'Нет'],['Generation',`${host.applied_generation??overview.applied_generation} / ${host.desired_generation??overview.desired_generation}`],['Relay / owned rules',`${host.relay_count??0} / ${host.relay_rule_count??0}`],['Relay counters',`${host.relay_packets??0} пакетов / ${host.relay_bytes??0} байт`]],host.state||'UNKNOWN',hostActions));
  for(const item of report.components||[])root.append(objectCard(item.name,[['Причина',item.reason],['Owned only',item.owned_only?'Да':'Нет']],item.state));
}

const logCategoryLabels={
  'all':'Общий лог','agent-control':'Agent / управление','pairing-gateways':'Pairing / Gateway',
  'administrators-relays':'Администраторы / relay','resources-acl':'Ресурсы / ACL',
  'management-fabric':'Management Fabric','watchdog-recovery':'Watchdog / recovery',
  'backup-restore-update':'Backup / restore / update','security-audit':'Безопасность / audit'
};
async function loadLogs(){
  const form=$('log-filter'),search=form.elements.search.value.trim(),limit=Number(form.elements.limit.value)||100;
  const query=new URLSearchParams({category:ui.logCategory,limit:String(limit)});if(search)query.set('search',search);
  const page=await api(`/api/v1/vps/logs?${query}`);renderLogCategories(page.categories||[]);const state=$('log-state');clear(state);
  for(const [label,value] of [['Состояние',page.state],['Снимок root',page.snapshot_at||'ещё не получен'],['Возраст снимка',page.snapshot_at?`${page.snapshot_age_seconds} сек.`:'—'],['Причина',page.reason||'—'],['Показано',(page.items||[]).length]])state.append(textElement('dt',label),textElement('dd',value));
  const root=$('log-window');clear(root);if(!(page.items||[]).length){root.append(textElement('div','Для выбранной категории записей нет.','empty'));return}
  for(const item of page.items){const row=document.createElement('article');row.className='log-entry';const head=document.createElement('div');head.className='log-entry-head';head.append(textElement('time',item.occurred_at),status(String(item.severity||'info').toUpperCase()),textElement('span',logCategoryLabels[item.category]||item.category,'muted'));const source=textElement('div',[item.source,item.unit].filter(Boolean).join(' · '),'muted');const message=textElement('pre',item.message);row.append(head,source,message);root.append(row)}
}
function renderLogCategories(categories){const root=$('log-categories');clear(root);for(const category of categories){const button=actionButton(logCategoryLabels[category]||category,async()=>{ui.logCategory=category;await loadLogs()});button.classList.toggle('active',category===ui.logCategory);button.setAttribute('role','tab');button.setAttribute('aria-selected',String(category===ui.logCategory));root.append(button)}}

async function loadDiagnostics(){
  const item=await api('/api/v1/vps/diagnostics/status'),root=$('diagnostic-status');clear(root);
  root.append(summary([['Доступно',item.available?'Да':'Нет'],['Формат',item.format||'—'],['Приватные данные',item.secrets_included?'ОШИБКА: включены':'Не включаются'],['Root-снимок',item.snapshot_state||item.reason||'—'],['Собран',item.snapshot_collected_at||'—'],['Лимит архива',item.maximum_archive_bytes?`${Math.round(item.maximum_archive_bytes/1048576)} МиБ`:'—'],['Разделы',(item.sections||[]).join(', ')||'—'],['Неполные секции',(item.snapshot_section_errors||[]).join(', ')||'нет']]))
}

async function loadUpdate(){
  const view=await api('/api/v1/vps/update/status'),root=$('update-status');clear(root);
  const transaction=view.transaction||{};
  root.append(summary([
    ['Доступно',view.available?'Да':'Нет'],['Текущая версия',view.current_version||'—'],['Schema',view.current_schema??'—'],
    ['Root updater',view.apply_available?'Подключён':'Недоступен'],['Состояние транзакции',transaction.state||'Нет активной'],
    ['Предыдущая версия',transaction.previous_version||'—'],['Кандидат',transaction.candidate_version||'—'],
    ['Stability deadline',transaction.stability_deadline||'—'],['Последняя ошибка',transaction.error_code||'нет']
  ]));
  const candidateRoot=$('update-candidate');clear(candidateRoot);
  if(view.staged&&view.operation){renderUpdateCandidate(view.operation,view.confirmation_phrase);}
  else empty(candidateRoot,transaction.state==='STABILIZING'?'Новая версия работает в окне стабильности; старая версия сохранена для автоматического rollback.':'Проверенный release пока не загружен.');
  const pending=sessionStorage.getItem('vps-update-pending');
  if(pending){notice(pending);sessionStorage.removeItem('vps-update-pending')}
}

function renderUpdateCandidate(operation,confirmationPhrase){
  const root=$('update-candidate'),card=document.createElement('article');card.className='card object';
  card.append(textElement('h3',`Проверенный кандидат ${operation.candidate_version}`),summary([
    ['Update ID',operation.update_id],['Текущая версия',operation.current_version],['Версия кандидата',operation.candidate_version],
    ['Schema сейчас / максимум кандидата',`${operation.current_schema} / ${operation.candidate_schema}`],['Файлов',operation.file_count],
    ['Распаковано',`${Math.round(operation.uncompressed_bytes/1024)} КиБ`],['Проверен',operation.created_at]
  ]));
  const form=document.createElement('form'),password=document.createElement('input'),confirmation=document.createElement('input');
  password.type='password';password.autocomplete='current-password';password.required=true;
  confirmation.autocomplete='off';confirmation.required=true;
  const passwordLabel=textElement('label','Текущий пароль VPS Hub');passwordLabel.append(password);
  const confirmationLabel=textElement('label',`Введите: ${confirmationPhrase}`);confirmationLabel.append(confirmation);
  const apply=actionButton('Обновить с автоматическим rollback',async()=>{
    if(!confirm('VPS Agent временно перезапустится. При ошибке release и база данных будут автоматически возвращены. Продолжить?'))return;
    apply.disabled=true;
    try{await api('/api/v1/vps/update/apply',{method:'POST',body:JSON.stringify({update_id:operation.update_id,password:password.value,confirmation:confirmation.value})});password.value='';confirmation.value='';sessionStorage.setItem('vps-update-pending','Обновление запущено. Если соединение прервалось, переподключитесь: boot recovery завершит apply или rollback.');notice('Root updater запущен; VPS Hub может кратковременно переподключиться.')}catch(error){notice(error.message);apply.disabled=false}
  },true);
  const discard=actionButton('Удалить проверенный кандидат',async()=>{
    if(!confirm('Удалить только staged release без изменения работающей версии?'))return;
    try{await api('/api/v1/vps/update',{method:'DELETE',headers:{'X-Confirm-Destructive':'discard-staged-vps-update'}});notice('Staged VPS release удалён; работающая версия не менялась.');await loadUpdate()}catch(error){notice(error.message)}
  });
  form.append(passwordLabel,confirmationLabel,apply,discard);card.append(form);root.append(card);
}

$('login-form').addEventListener('submit',async event=>{event.preventDefault();const data=new FormData(event.target);try{showApp(await api('/api/v1/auth/login',{method:'POST',body:JSON.stringify({username:data.get('username'),password:data.get('password')})}))}catch(error){$('login-error').textContent=error.message}});
$('logout').addEventListener('click',async()=>{try{await api('/api/v1/auth/logout',{method:'POST'})}finally{ui.csrf='';showLogin()}});
$('password-form').addEventListener('submit',async event=>{event.preventDefault();const form=event.target,data=new FormData(form);if(data.get('new_password')!==data.get('password_confirmation')){notice('Новый пароль и подтверждение не совпадают');return}try{await api('/api/v1/auth/password',{method:'PUT',body:JSON.stringify({current_password:data.get('current_password'),new_password:data.get('new_password'),password_confirmation:data.get('password_confirmation')})});form.reset();showApp(await api('/api/v1/auth/session'));notice('Пароль VPS Hub изменён')}catch(error){notice(error.message)}});
document.querySelectorAll('[data-page]').forEach(button=>button.addEventListener('click',()=>navigate(button.dataset.page)));
$('mobile-navigation-select').addEventListener('change',event=>navigate(event.target.value));
document.querySelectorAll('[data-refresh]').forEach(button=>button.addEventListener('click',()=>loadPage(button.dataset.refresh).catch(error=>notice(error.message))));
$('log-filter').addEventListener('submit',event=>{event.preventDefault();loadLogs().catch(error=>notice(error.message))});
$('clear-log-view').addEventListener('click',()=>{empty($('log-window'),'Окно очищено только в этом браузере. Системный журнал и audit trail сохранены.');notice('Отображение очищено; записи на VPS не удалялись.')});
$('download-diagnostics').addEventListener('click',async event=>{const button=event.currentTarget;button.disabled=true;try{const response=await fetch('/api/v1/vps/diagnostics/download',{method:'POST',credentials:'same-origin',headers:{'X-CSRF-Token':ui.csrf}});if(!response.ok){const body=await response.json();throw new Error(body.error.message)}const blob=await response.blob(),name=(response.headers.get('Content-Disposition')||'').match(/filename="([^"]+)"/)?.[1]||'gateway-vpn-vps-diagnostics.zip',digest=response.headers.get('X-Content-SHA256')||'не указан',link=document.createElement('a');link.href=URL.createObjectURL(blob);link.download=name;link.click();setTimeout(()=>URL.revokeObjectURL(link.href),1000);notice(`Диагностика ${name} скачана; SHA-256 ${digest}`)}catch(error){notice(error.message)}finally{button.disabled=false}});
$('update-stage-form').addEventListener('submit',async event=>{event.preventDefault();const form=event.target,data=new FormData(form),upload=new FormData(),button=form.querySelector('button');upload.append('release',data.get('release'));button.disabled=true;try{const result=await api('/api/v1/vps/update/stage',{method:'POST',body:upload});form.reset();notice(`Release ${result.operation.candidate_version} подписан и совместим. Применение ещё не началось.`);await loadUpdate()}catch(error){notice(error.message)}finally{button.disabled=false}});

$('pairing-form').addEventListener('submit',async event=>{event.preventDefault();const form=event.target,data=new FormData(form);try{const result=await api('/api/v1/hub/pairing-invitations',{method:'POST',body:JSON.stringify({gateway_name:data.get('gateway_name'),endpoint:data.get('endpoint'),assigned_subnet:data.get('assigned_subnet'),expiry_seconds:Number(data.get('expiry_minutes'))*60})});ui.invitation=result.invitation;$('pairing-bundle').textContent=JSON.stringify(result.invitation,null,2);$('pairing-once').hidden=false;notice('Приглашение создано. Токен больше не будет показан после ухода со страницы.');await loadGateways()}catch(error){notice(error.message)}});
$('download-pairing').addEventListener('click',()=>{if(!ui.invitation)return;const blob=new Blob([JSON.stringify(ui.invitation,null,2)+'\n'],{type:'application/json'}),link=document.createElement('a');link.href=URL.createObjectURL(blob);link.download=`gateway-vpn-pairing-${ui.invitation.invitation_id}.json`;link.click();setTimeout(()=>URL.revokeObjectURL(link.href),1000)});
$('admin-form').addEventListener('submit',async event=>{event.preventDefault();const form=event.target,data=new FormData(form);try{await api('/api/v1/hub/admins',{method:'POST',body:JSON.stringify({name:data.get('name'),public_key:data.get('public_key'),assigned_address:data.get('assigned_address'),key_mode:'EXTERNAL',trust_mode:data.get('trust_mode')})});form.reset();notice('Администратор добавлен; host generation ожидает применения');await loadAdmins()}catch(error){notice(error.message)}});
$('managed-admin-form').addEventListener('submit',async event=>{event.preventDefault();const form=event.target,data=new FormData(form);try{await api('/api/v1/hub/admins',{method:'POST',body:JSON.stringify({name:data.get('name'),assigned_address:data.get('assigned_address'),key_mode:'MANAGED',password:data.get('password'),confirmation:data.get('confirmation')})});form.reset();notice('Управляемый ключ создан. Скачайте готовый конфиг ровно один раз.');await loadAdmins()}catch(error){notice(error.message)}});
$('relay-form').addEventListener('submit',async event=>{event.preventDefault();const form=event.target,data=new FormData(form);try{await api('/api/v1/hub/admin-relays',{method:'POST',body:JSON.stringify({gateway_peer_id:data.get('gateway_peer_id'),public_endpoint_host:data.get('public_endpoint_host'),public_bind_address:data.get('public_bind_address'),public_udp_port:Number(data.get('public_udp_port')),destination_port:51822,rate_limit_per_second:Number(data.get('rate_limit_per_second')),burst_packets:Number(data.get('burst_packets'))})});notice('End-to-end relay создан и ожидает безопасного применения');await loadRelays()}catch(error){notice(error.message)}});
$('resource-form').addEventListener('submit',async event=>{event.preventDefault();const form=event.target,data=new FormData(form);try{await api('/api/v1/hub/resources',{method:'POST',body:JSON.stringify({gateway_peer_id:data.get('gateway_peer_id'),resource_id:data.get('resource_id'),display_name:data.get('display_name'),resource_kind:data.get('resource_kind'),local_destination:data.get('local_destination'),published_alias:data.get('published_alias'),access_profile:data.get('access_profile'),enabled:data.get('enabled')==='on',advanced_scope_acknowledged:data.get('advanced_scope_acknowledged')==='on'})});form.reset();form.elements.enabled.checked=true;notice('Публикация сохранена; без ACL доступ остаётся закрыт');await loadResources()}catch(error){notice(error.message)}});
$('acl-form').addEventListener('submit',async event=>{event.preventDefault();const form=event.target,data=new FormData(form),protocol=data.get('protocol');try{await api('/api/v1/hub/acl',{method:'POST',body:JSON.stringify({admin_peer_id:data.get('admin_peer_id'),publication_id:data.get('publication_id'),protocol,port_start:protocol==='ICMP'?0:Number(data.get('port_start')),port_end:protocol==='ICMP'?0:Number(data.get('port_end'))})});notice('ACL сохранён; host generation ожидает применения');await loadMatrix()}catch(error){notice(error.message)}});
$('acl-form').elements.protocol.addEventListener('change',event=>{const icmp=event.target.value==='ICMP';$('acl-form').elements.port_start.disabled=icmp;$('acl-form').elements.port_end.disabled=icmp});

$('backup-form').addEventListener('submit',async event=>{event.preventDefault();const form=event.target,data=new FormData(form),button=form.querySelector('button');button.disabled=true;try{const response=await fetch('/api/v1/vps/backup/download',{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json','X-CSRF-Token':ui.csrf},body:JSON.stringify({password:data.get('password'),passphrase:data.get('passphrase'),passphrase_confirmation:data.get('passphrase_confirmation')})});if(!response.ok){const body=await response.json();throw new Error(body.error.message)}const blob=await response.blob(),name=(response.headers.get('Content-Disposition')||'').match(/filename="([^"]+)"/)?.[1]||'gateway-vpn-vps-backup.gvpn-vps',link=document.createElement('a');link.href=URL.createObjectURL(blob);link.download=name;link.click();setTimeout(()=>URL.revokeObjectURL(link.href),1000);form.reset();notice(`Backup ${name} создан, проверен и скачан`)}catch(error){notice(error.message)}finally{button.disabled=false}});
$('restore-form').addEventListener('submit',async event=>{event.preventDefault();const form=event.target,data=new FormData(form),upload=new FormData();upload.append('passphrase',data.get('passphrase'));upload.append('backup',data.get('backup'));try{const result=await api('/api/v1/vps/restore/stage',{method:'POST',body:upload});form.reset();renderPreview(result.operation,result.confirmation_phrases);notice('Файл проверен. Текущие настройки ещё не изменены.')}catch(error){notice(error.message)}});
function renderPreview(operation,phrases){const root=$('restore-preview');clear(root);if(!operation||!operation.restore_id)return;root.append(summary([['Роль','VPS Hub'],['Источник',operation.source_vps_id],['Текущий VPS',operation.live_vps_id],['Версия Agent',operation.agent_version],['Schema',operation.schema_version],['Файлов',operation.files],['Identity совпадает',operation.identity_matches?'Да':'Нет']]));const form=document.createElement('form'),mode=document.createElement('select'),password=document.createElement('input'),confirmation=document.createElement('input');password.type='password';password.autocomplete='current-password';password.required=true;confirmation.required=true;for(const allowed of operation.allowed_modes||[]){const option=document.createElement('option');option.value=allowed;option.textContent=allowed==='SAME_VPS'?'Восстановить этот VPS':'Импортировать как новый VPS';mode.append(option)}const modeLabel=textElement('label','Режим');modeLabel.append(mode);const passwordLabel=textElement('label','Текущий пароль VPS Hub');passwordLabel.append(password);const confirmationLabel=textElement('label','');confirmationLabel.append(confirmation);const update=()=>{confirmationLabel.firstChild.textContent=`Введите: ${phrases[mode.value]||''}`};mode.addEventListener('change',update);update();const apply=actionButton('Применить с безопасным rollback',async()=>{if(!confirm('Начать подтверждённое восстановление VPS Hub? Управление временно прервётся.'))return;try{await api('/api/v1/vps/restore/apply',{method:'POST',body:JSON.stringify({restore_id:operation.restore_id,mode:mode.value,password:password.value,confirmation:confirmation.value})});sessionStorage.setItem('vps-restore-pending','Restore запущен; переподключитесь после перезапуска VPS Agent.');notice('Restore запланирован. VPS Agent перезапустится.')}catch(error){notice(error.message)}},true);const discard=actionButton('Отменить staged restore',async()=>{if(!confirm('Удалить проверенный staged restore без изменения текущих настроек?'))return;try{await api('/api/v1/vps/restore',{method:'DELETE',headers:{'X-Confirm-Destructive':'discard-staged-vps-restore'}});clear(root);notice('Staged restore удалён')}catch(error){notice(error.message)}});form.append(modeLabel,passwordLabel,confirmationLabel,apply,discard);root.append(form)}
async function refreshBackupStatus(){const state=await api('/api/v1/vps/backup/status');if(state.pending)renderPreview(state.operation,state.confirmation_phrases||{});const pending=sessionStorage.getItem('vps-restore-pending');if(pending){notice(pending);sessionStorage.removeItem('vps-restore-pending')}}

(async()=>{try{showApp(await api('/api/v1/auth/session'))}catch{showLogin()}})();
