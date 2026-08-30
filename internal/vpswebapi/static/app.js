'use strict';

const $=id=>document.getElementById(id);
const ui={csrf:'',page:'overview',invitation:null,gateways:[],admins:[],resources:[]};

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
  const required=Boolean(session.must_change_password);$('password-card').hidden=!required;$('navigation').hidden=required;
  document.querySelectorAll('[data-page-panel]').forEach(panel=>panel.hidden=required||panel.dataset.pagePanel!==ui.page);
  if(required){notice('Задайте собственный пароль VPS Hub перед продолжением.');return}
  const saved=localStorage.getItem('gateway-vpn-vps-page');
  navigate(document.querySelector(`[data-page="${saved}"]`)?saved:'overview');
}
function showLogin(){$('app').hidden=true;$('login').hidden=false}
async function navigate(page){
  if(ui.page==='gateways'&&page!=='gateways'&&ui.invitation){ui.invitation=null;$('pairing-bundle').textContent='';$('pairing-once').hidden=true}
  ui.page=page;localStorage.setItem('gateway-vpn-vps-page',page);
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
  if(page==='resources')return loadResources();
  if(page==='matrix')return loadMatrix();
  if(page==='watchdog')return loadWatchdog();
  if(page==='backup')return refreshBackupStatus();
}

async function loadOverview(){
  const item=await api('/api/v1/hub/overview');const root=$('overview-content');clear(root);
  root.append(
    objectCard(item.identity.display_name,[['VPS ID',item.identity.vps_id],['Fingerprint',item.identity.identity_fingerprint],['Schema',item.schema_version]],'ACTIVE'),
    objectCard('Gateway',[['Состояния',countStates(item.gateways)],['Открытых приглашений',item.open_invitations]],item.open_invitations?'PENDING':'HEALTHY'),
    objectCard('Доступ',[['Администраторы',countStates(item.administrators)],['Ресурсы',countStates(item.resources)],['ACL правил',item.acl_grants]],item.fabric_state),
    objectCard('Применение на host',[['Desired generation',item.desired_generation],['Applied generation',item.applied_generation],['Root apply доступен',item.host_apply_available?'Да':'Нет, следующий этап']],item.host_apply_available?'HEALTHY':'PENDING')
  );
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
  for(const item of ui.admins){const actions=[];if(item.key_mode==='MANAGED'&&item.config_state==='AVAILABLE')actions.push(actionButton('Скачать конфиг один раз',()=>downloadAdminConfig(item)));if(item.key_mode==='MANAGED'&&item.state!=='REVOKED')actions.push(actionButton('Начать смену ключа',()=>rotateAdmin(item)));if(item.state!=='REVOKED')actions.push(actionButton('Отозвать',()=>revokeAdmin(item),true));root.append(objectCard(item.name,[['ID',item.id],['Адрес',item.assigned_address],['Режим ключа',item.key_mode],['Готовый конфиг',item.config_state],['Скачан',item.config_downloaded_at||'нет'],['Сменяет ключ',item.rotation_source_id||'—'],['Handshake',item.latest_handshake_at||'ещё не наблюдался'],['Generation',`${item.applied_generation} / ${item.desired_generation}`],['Причина',item.status_reason||'—']],item.state,actions))}
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

async function loadResources(){
  const [gateways,resources]=await Promise.all([api('/api/v1/hub/gateways'),api('/api/v1/hub/resources')]);ui.gateways=(gateways.items||[]).filter(item=>item.state!=='REVOKED');ui.resources=resources.items||[];
  setOptions($('resource-form').elements.gateway_peer_id,ui.gateways,item=>`${item.display_name} — ${item.assigned_address}`);
  const root=$('resource-list');if(!ui.resources.length){empty(root,'Локальные ресурсы ещё не опубликованы.');return}clear(root);
  for(const item of ui.resources){const actions=[actionButton('Удалить публикацию',async()=>{if(!confirm(`Удалить публикацию «${item.display_name}» и связанные ACL?`))return;try{await api(`/api/v1/hub/resources/${encodeURIComponent(item.id)}`,{method:'DELETE',headers:{'X-Confirm-Destructive':'delete-resource-publication'}});notice('Публикация удалена');await loadResources()}catch(error){notice(error.message)}},true)];root.append(objectCard(item.display_name,[['ID ресурса',item.resource_id],['Gateway peer',item.gateway_peer_id],['Тип / профиль',`${item.resource_kind} / ${item.access_profile}`],['Локально → alias',`${item.local_destination} → ${item.published_alias}`],['Health',item.health],['Generation',`${item.applied_generation} / ${item.desired_generation}`],['Причина',item.status_reason||'—']],item.state,actions))}
}

async function loadMatrix(){
  const matrix=await api('/api/v1/hub/access-matrix');ui.admins=(matrix.administrators||[]).filter(item=>item.state!=='REVOKED');ui.resources=(matrix.resources||[]).filter(item=>item.enabled&&item.state!=='DISABLED');
  setOptions($('acl-form').elements.admin_peer_id,ui.admins,item=>`${item.name} — ${item.assigned_address}`);setOptions($('acl-form').elements.publication_id,ui.resources,item=>`${item.display_name} — ${item.published_alias}`);
  const generation=$('matrix-generation');clear(generation);for(const [label,value] of [['Состояние',matrix.state],['Desired',matrix.desired_generation],['Applied',matrix.applied_generation],['Host apply',matrix.host_apply_available?'Доступен':'Ещё не подключён']])generation.append(textElement('dt',label),textElement('dd',value));
  const root=$('acl-list'),grants=matrix.grants||[];if(!grants.length){empty(root,'Явных разрешений пока нет — действует default deny.');return}clear(root);
  const admins=new Map((matrix.administrators||[]).map(item=>[item.id,item]));const resources=new Map((matrix.resources||[]).map(item=>[item.id,item]));
  for(const item of grants){const admin=admins.get(item.admin_peer_id),resource=resources.get(item.publication_id);const ports=item.protocol==='ICMP'?'ICMP':`${item.port_start}–${item.port_end}`;const remove=actionButton('Удалить правило',async()=>{if(!confirm('Удалить это разрешение?'))return;try{await api(`/api/v1/hub/acl/${encodeURIComponent(item.id)}`,{method:'DELETE',headers:{'X-Confirm-Destructive':'delete-acl-grant'}});notice('ACL удалён; новая generation ожидает применения');await loadMatrix()}catch(error){notice(error.message)}},true);root.append(objectCard(`${admin?.name||item.admin_peer_id} → ${resource?.display_name||item.publication_id}`,[['Протокол / порты',`${item.protocol} ${ports}`],['Alias',resource?.published_alias||'—'],['Generation',item.generation],['ACL ID',item.id]],'PENDING',[remove]))}
}

async function loadWatchdog(){
  const report=await api('/api/v1/hub/watchdog');const root=$('watchdog-content');clear(root);root.append(objectCard('Общее состояние',[['Проверено',report.checked_at],['Граница', 'Только owned Gateway VPN objects']],report.state));
  for(const item of report.components||[])root.append(objectCard(item.name,[['Причина',item.reason],['Owned only',item.owned_only?'Да':'Нет']],item.state));
}

$('login-form').addEventListener('submit',async event=>{event.preventDefault();const data=new FormData(event.target);try{showApp(await api('/api/v1/auth/login',{method:'POST',body:JSON.stringify({username:data.get('username'),password:data.get('password')})}))}catch(error){$('login-error').textContent=error.message}});
$('logout').addEventListener('click',async()=>{try{await api('/api/v1/auth/logout',{method:'POST'})}finally{ui.csrf='';showLogin()}});
$('password-form').addEventListener('submit',async event=>{event.preventDefault();const form=event.target,data=new FormData(form);if(data.get('new_password')!==data.get('password_confirmation')){notice('Новый пароль и подтверждение не совпадают');return}try{await api('/api/v1/auth/password',{method:'PUT',body:JSON.stringify({current_password:data.get('current_password'),new_password:data.get('new_password'),password_confirmation:data.get('password_confirmation')})});form.reset();showApp(await api('/api/v1/auth/session'));notice('Пароль VPS Hub изменён')}catch(error){notice(error.message)}});
document.querySelectorAll('[data-page]').forEach(button=>button.addEventListener('click',()=>navigate(button.dataset.page)));
document.querySelectorAll('[data-refresh]').forEach(button=>button.addEventListener('click',()=>loadPage(button.dataset.refresh).catch(error=>notice(error.message))));

$('pairing-form').addEventListener('submit',async event=>{event.preventDefault();const form=event.target,data=new FormData(form);try{const result=await api('/api/v1/hub/pairing-invitations',{method:'POST',body:JSON.stringify({gateway_name:data.get('gateway_name'),endpoint:data.get('endpoint'),assigned_subnet:data.get('assigned_subnet'),expiry_seconds:Number(data.get('expiry_minutes'))*60})});ui.invitation=result.invitation;$('pairing-bundle').textContent=JSON.stringify(result.invitation,null,2);$('pairing-once').hidden=false;notice('Приглашение создано. Токен больше не будет показан после ухода со страницы.');await loadGateways()}catch(error){notice(error.message)}});
$('download-pairing').addEventListener('click',()=>{if(!ui.invitation)return;const blob=new Blob([JSON.stringify(ui.invitation,null,2)+'\n'],{type:'application/json'}),link=document.createElement('a');link.href=URL.createObjectURL(blob);link.download=`gateway-vpn-pairing-${ui.invitation.invitation_id}.json`;link.click();setTimeout(()=>URL.revokeObjectURL(link.href),1000)});
$('admin-form').addEventListener('submit',async event=>{event.preventDefault();const form=event.target,data=new FormData(form);try{await api('/api/v1/hub/admins',{method:'POST',body:JSON.stringify({name:data.get('name'),public_key:data.get('public_key'),assigned_address:data.get('assigned_address'),key_mode:'EXTERNAL'})});form.reset();notice('Администратор добавлен; host generation ожидает применения');await loadAdmins()}catch(error){notice(error.message)}});
$('managed-admin-form').addEventListener('submit',async event=>{event.preventDefault();const form=event.target,data=new FormData(form);try{await api('/api/v1/hub/admins',{method:'POST',body:JSON.stringify({name:data.get('name'),assigned_address:data.get('assigned_address'),key_mode:'MANAGED',password:data.get('password'),confirmation:data.get('confirmation')})});form.reset();notice('Управляемый ключ создан. Скачайте готовый конфиг ровно один раз.');await loadAdmins()}catch(error){notice(error.message)}});
$('resource-form').addEventListener('submit',async event=>{event.preventDefault();const form=event.target,data=new FormData(form);try{await api('/api/v1/hub/resources',{method:'POST',body:JSON.stringify({gateway_peer_id:data.get('gateway_peer_id'),resource_id:data.get('resource_id'),display_name:data.get('display_name'),resource_kind:data.get('resource_kind'),local_destination:data.get('local_destination'),published_alias:data.get('published_alias'),access_profile:data.get('access_profile'),enabled:data.get('enabled')==='on',advanced_scope_acknowledged:data.get('advanced_scope_acknowledged')==='on'})});form.reset();form.elements.enabled.checked=true;notice('Публикация сохранена; без ACL доступ остаётся закрыт');await loadResources()}catch(error){notice(error.message)}});
$('acl-form').addEventListener('submit',async event=>{event.preventDefault();const form=event.target,data=new FormData(form),protocol=data.get('protocol');try{await api('/api/v1/hub/acl',{method:'POST',body:JSON.stringify({admin_peer_id:data.get('admin_peer_id'),publication_id:data.get('publication_id'),protocol,port_start:protocol==='ICMP'?0:Number(data.get('port_start')),port_end:protocol==='ICMP'?0:Number(data.get('port_end'))})});notice('ACL сохранён; host generation ожидает применения');await loadMatrix()}catch(error){notice(error.message)}});
$('acl-form').elements.protocol.addEventListener('change',event=>{const icmp=event.target.value==='ICMP';$('acl-form').elements.port_start.disabled=icmp;$('acl-form').elements.port_end.disabled=icmp});

$('backup-form').addEventListener('submit',async event=>{event.preventDefault();const form=event.target,data=new FormData(form),button=form.querySelector('button');button.disabled=true;try{const response=await fetch('/api/v1/vps/backup/download',{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json','X-CSRF-Token':ui.csrf},body:JSON.stringify({password:data.get('password'),passphrase:data.get('passphrase'),passphrase_confirmation:data.get('passphrase_confirmation')})});if(!response.ok){const body=await response.json();throw new Error(body.error.message)}const blob=await response.blob(),name=(response.headers.get('Content-Disposition')||'').match(/filename="([^"]+)"/)?.[1]||'gateway-vpn-vps-backup.gvpn-vps',link=document.createElement('a');link.href=URL.createObjectURL(blob);link.download=name;link.click();setTimeout(()=>URL.revokeObjectURL(link.href),1000);form.reset();notice(`Backup ${name} создан, проверен и скачан`)}catch(error){notice(error.message)}finally{button.disabled=false}});
$('restore-form').addEventListener('submit',async event=>{event.preventDefault();const form=event.target,data=new FormData(form),upload=new FormData();upload.append('passphrase',data.get('passphrase'));upload.append('backup',data.get('backup'));try{const result=await api('/api/v1/vps/restore/stage',{method:'POST',body:upload});form.reset();renderPreview(result.operation,result.confirmation_phrases);notice('Файл проверен. Текущие настройки ещё не изменены.')}catch(error){notice(error.message)}});
function renderPreview(operation,phrases){const root=$('restore-preview');clear(root);if(!operation||!operation.restore_id)return;root.append(summary([['Роль','VPS Hub'],['Источник',operation.source_vps_id],['Текущий VPS',operation.live_vps_id],['Версия Agent',operation.agent_version],['Schema',operation.schema_version],['Файлов',operation.files],['Identity совпадает',operation.identity_matches?'Да':'Нет']]));const form=document.createElement('form'),mode=document.createElement('select'),password=document.createElement('input'),confirmation=document.createElement('input');password.type='password';password.autocomplete='current-password';password.required=true;confirmation.required=true;for(const allowed of operation.allowed_modes||[]){const option=document.createElement('option');option.value=allowed;option.textContent=allowed==='SAME_VPS'?'Восстановить этот VPS':'Импортировать как новый VPS';mode.append(option)}const modeLabel=textElement('label','Режим');modeLabel.append(mode);const passwordLabel=textElement('label','Текущий пароль VPS Hub');passwordLabel.append(password);const confirmationLabel=textElement('label','');confirmationLabel.append(confirmation);const update=()=>{confirmationLabel.firstChild.textContent=`Введите: ${phrases[mode.value]||''}`};mode.addEventListener('change',update);update();const apply=actionButton('Применить с безопасным rollback',async()=>{if(!confirm('Начать подтверждённое восстановление VPS Hub? Управление временно прервётся.'))return;try{await api('/api/v1/vps/restore/apply',{method:'POST',body:JSON.stringify({restore_id:operation.restore_id,mode:mode.value,password:password.value,confirmation:confirmation.value})});sessionStorage.setItem('vps-restore-pending','Restore запущен; переподключитесь после перезапуска VPS Agent.');notice('Restore запланирован. VPS Agent перезапустится.')}catch(error){notice(error.message)}},true);const discard=actionButton('Отменить staged restore',async()=>{if(!confirm('Удалить проверенный staged restore без изменения текущих настроек?'))return;try{await api('/api/v1/vps/restore',{method:'DELETE',headers:{'X-Confirm-Destructive':'discard-staged-vps-restore'}});clear(root);notice('Staged restore удалён')}catch(error){notice(error.message)}});form.append(modeLabel,passwordLabel,confirmationLabel,apply,discard);root.append(form)}
async function refreshBackupStatus(){const state=await api('/api/v1/vps/backup/status');if(state.pending)renderPreview(state.operation,state.confirmation_phrases||{});const pending=sessionStorage.getItem('vps-restore-pending');if(pending){notice(pending);sessionStorage.removeItem('vps-restore-pending')}}

(async()=>{try{showApp(await api('/api/v1/auth/session'))}catch{showLogin()}})();
