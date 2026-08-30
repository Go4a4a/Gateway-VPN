'use strict';

const topologyApplyStorageKey='gateway-vpn-topology-apply';

const topologyProfileLabels={
  ETHERNET_HILINK:'Ethernet LAN → HiLink-модемы',
  ETHERNET_ETHERNET:'Ethernet LAN → Ethernet Internet',
  ONE_ARM_WIREGUARD:'Одна Ethernet-карта через WireGuard',
  MIXED:'Смешанный: HiLink + Ethernet'
};

const topologyPrerequisiteLabels={
  ACCEPT_TEMPORARY_DISCONNECT:'Я понимаю, что соединение может кратковременно прерваться, а без подтверждения произойдёт откат.',
  MOVE_LAN_CABLES:'Я подключу LAN-кабели к выбранным портам и не считаю это автоматическим действием Gateway.',
  CONFIGURE_KEENETIC_WAN_DHCP:'WAN Keenetic/роутера настроен на получение адреса от Gateway по DHCP.',
  CONFIGURE_KEENETIC_WIREGUARD:'На Keenetic/роутере настроен входящий WireGuard peer к wg-ingress Gateway.',
  VERIFY_UPSTREAM_RETURN_PATH:'Проверены исключения Gateway/service traffic и возврат через общий Ethernet без route recursion.'
};

function topologyHasRole(item,role){return (item.roles||[]).some(value=>value.role===role)}
function topologyInterfaceCaption(item){return `${item.interface_name||'Интерфейс отсутствует'} · ${item.vendor||item.model||item.driver||item.id} · ${item.carrier_state}`}

async function topologyIngressState(){
  try{return (await api('/api/v1/wireguard-ingress')).server||null}catch{return null}
}

function topologyPayload(form,interfaces){
  const selected=selector=>Array.from(form.querySelectorAll(selector)).filter(control=>control.checked).map(control=>control.value);
  const shared=form.querySelector('input[name="shared_one_arm_interface_id"]:checked')?.value||'';
  const listeners=[];
  form.querySelectorAll('[data-listener-row]').forEach(row=>{
    const enabled=row.querySelector('[data-listener]');if(!enabled.checked)return;
    listeners.push({network_interface_id:enabled.value,exposure_mode:row.querySelector('[data-listener-exposure]').value,priority:listeners.length+1});
  });
  return {
    expected_desired_generation:Number(form.dataset.generation),profile:form.elements.profile.value,
    lan_interface_ids:selected('[data-role="lan"]'),management_interface_ids:selected('[data-role="management"]'),
    wg_endpoint_interface_ids:selected('[data-role="endpoint"]'),shared_one_arm_interface_id:shared,
    lan_interface_name:form.elements.lan_interface_name.value.trim(),lan_address:form.elements.lan_address.value.trim(),
    dhcp_dns_enabled:form.elements.dhcp_dns_enabled.checked,ingress_enabled:form.elements.ingress_enabled.checked,
    ingress_topology_mode:form.elements.ingress_topology_mode.value,ingress_listen_interfaces:listeners,
    acknowledged_prerequisites:selected('[data-prerequisite]'),
    require_wireguard_confirmation:form.elements.require_wireguard_confirmation.checked
  };
}

function normalizeTopologyProfile(form){
  const oneArm=form.elements.profile.value==='ONE_ARM_WIREGUARD';
  form.elements.dhcp_dns_enabled.checked=!oneArm;
  form.elements.ingress_topology_mode.value=oneArm?'ONE_ARM':'ROUTED';
  if(!oneArm)return;
  const shared=form.querySelector('input[name="shared_one_arm_interface_id"]:checked');
  if(!shared)return;
  form.querySelectorAll('[data-role="lan"]').forEach(control=>{control.checked=false});
  form.querySelectorAll('[data-role="management"]').forEach(control=>{control.checked=control.value===shared.value});
  form.elements.ingress_enabled.checked=true;
  form.querySelectorAll('[data-listener-row]').forEach(row=>{
    const listener=row.querySelector('[data-listener]');listener.checked=listener.value===shared.value;
    if(listener.checked)row.querySelector('[data-listener-exposure]').value='PUBLIC';
  });
}

function topologyRoleMatrix(interfaces,ingress){
  const listeners=new Map((ingress?.listen_interfaces||[]).map(item=>[item.network_interface_id,item]));
  const wrapper=document.createElement('div');wrapper.className='topology-role-matrix';
  const none=document.createElement('label');none.className='checkbox topology-shared-none';none.title='Обычные профили не используют общую one-arm карту.';const noneInput=document.createElement('input');noneInput.type='radio';noneInput.name='shared_one_arm_interface_id';noneInput.value='';noneInput.checked=!interfaces.some(item=>topologyHasRole(item,'SHARED_ONE_ARM'));none.append(noneInput,document.createTextNode(' Не использовать общую one-arm карту'));wrapper.append(none);
  const heading=document.createElement('div');heading.className='topology-role-row topology-role-heading';
  ['Сетевая карта','LAN','Управление','WG endpoint','Общая карта','WG слушает'].forEach(label=>{const cell=document.createElement('strong');cell.textContent=label;heading.append(cell)});wrapper.append(heading);
  interfaces.forEach(item=>{
    const row=document.createElement('div');row.className='topology-role-row';row.dataset.interfaceId=item.id;
    const caption=document.createElement('span');caption.textContent=topologyInterfaceCaption(item);caption.title='Роль сохраняется по стабильной identity карты, а не по меняющемуся Linux ifname.';row.append(caption);
    const checkbox=(role,title)=>{const label=document.createElement('label');label.className='topology-role-choice';label.title=title;const input=document.createElement('input');input.type='checkbox';input.value=item.id;input.dataset.role=role;const storedRole={lan:'LAN_MEMBER',management:'MANAGEMENT',endpoint:'WG_ENDPOINT'}[role];input.checked=topologyHasRole(item,storedRole);label.append(input);return label};
    row.append(checkbox('lan','Принимать обычный LAN-трафик от WAN роутера и включить порт в управляемый LAN.'),checkbox('management','Разрешить WebUI и SSH через эту карту.'),checkbox('endpoint','Разрешить слушать входящий WireGuard на этой карте.'));
    const sharedLabel=document.createElement('label');sharedLabel.className='topology-role-choice';sharedLabel.title='Только для однокарточной схемы: plaintext transit запрещён, пользовательский трафик приходит по WireGuard.';const shared=document.createElement('input');shared.type='radio';shared.name='shared_one_arm_interface_id';shared.value=item.id;shared.checked=topologyHasRole(item,'SHARED_ONE_ARM');sharedLabel.append(shared);row.append(sharedLabel);
    const listenerCell=document.createElement('span');listenerCell.className='topology-listener-choice';listenerCell.dataset.listenerRow='';const listen=document.createElement('input');listen.type='checkbox';listen.dataset.listener='';listen.value=item.id;listen.checked=listeners.has(item.id);const exposure=document.createElement('select');exposure.dataset.listenerExposure='';exposure.innerHTML='<option value="LOCAL">Только LAN</option><option value="PUBLIC">Внешний</option>';exposure.value=listeners.get(item.id)?.exposure_mode||'LOCAL';listenerCell.append(listen,exposure);row.append(listenerCell);wrapper.append(row);
  });
  const managedListener=listeners.get('netif:managed:lan');const managedRow=document.createElement('div');managedRow.className='topology-role-row topology-managed-listener';managedRow.dataset.listenerRow='';const managedCaption=document.createElement('span');managedCaption.textContent='Логический управляемый LAN';managedCaption.title='Слушать wg-ingress на LAN Gateway независимо от конкретного физического member-порта.';managedRow.append(managedCaption,document.createElement('span'),document.createElement('span'),document.createElement('span'),document.createElement('span'));const managedCell=document.createElement('span');managedCell.className='topology-listener-choice';const managedCheck=document.createElement('input');managedCheck.type='checkbox';managedCheck.dataset.listener='';managedCheck.value='netif:managed:lan';managedCheck.checked=Boolean(managedListener);const managedExposure=document.createElement('select');managedExposure.dataset.listenerExposure='';managedExposure.innerHTML='<option value="LOCAL">Только LAN</option>';managedCell.append(managedCheck,managedExposure);managedRow.append(managedCell);wrapper.append(managedRow);
  return wrapper;
}

function topologyPendingPanel(){
  let pending;try{pending=JSON.parse(sessionStorage.getItem(topologyApplyStorageKey)||'null')}catch{return null}if(!pending)return null;
  const box=document.createElement('section');box.className='card topology-pending';const heading=document.createElement('h3');heading.textContent='Topology profile ожидает подтверждения';
  const warning=document.createElement('p');warning.className='restore-warning';warning.textContent=`Если новый management path не подтвердить до ${pending.deadline}, весь прежний сетевой профиль восстановится автоматически.`;
  const actions=document.createElement('div');actions.className='actions';
  const current=actionButton('Подтвердить через текущий WireGuard',async()=>{await api(`/api/v1/settings/network/apply/${encodeURIComponent(pending.id)}/confirm`,{method:'POST',body:JSON.stringify({confirm_token:pending.token})});sessionStorage.removeItem(topologyApplyStorageKey);notice('Новый topology profile подтверждён');await renderNetwork()});current.title='Сработает только если эта WebUI-сессия действительно пришла через защищённый wg-mgmt.';
  const link=document.createElement('a');link.className='button-link';link.textContent='Открыть новый LAN-адрес и подтвердить';try{const destination=new URL(pending.new_url);destination.hash=`network-confirm=${pending.id}.${pending.token}`;link.href=destination.toString()}catch{link.removeAttribute('href')}
  actions.append(current,link);box.append(heading,warning,actions);return box;
}

async function topologyProfilePanel(){
  const [topology,interfaceData,ingress]=await Promise.all([api('/api/v1/network/topology'),api('/api/v1/network/interfaces'),topologyIngressState()]);
  const interfaces=(interfaceData.items||[]).filter(item=>item.id!=='netif:managed:lan'&&item.carrier_state!=='ABSENT');
  const section=document.createElement('section');section.className='card topology-profile';const heading=document.createElement('h2');heading.textContent='Топология и роли интерфейсов';
  const intro=document.createElement('p');intro.className='muted';intro.textContent='Профиль можно менять после установки. Preview ничего не применяет; Apply одной транзакцией меняет роли, networkd, DHCP/DNS, firewall, policy routing, wg-ingress и адрес WebUI. Без подтверждения возвращается весь предыдущий профиль.';section.append(heading,intro);
  const pending=topologyPendingPanel();if(pending)section.append(pending);
  const form=document.createElement('form');form.className='settings-form topology-form';form.dataset.generation=topology.desired_generation;
  form.innerHTML=`<div class="form-grid">
    <label title="Выбирает направление входящего пользовательского трафика и допустимые типы Internet-uplink.">Профиль<select name="profile">${(topology.profiles||[]).map(value=>`<option value="${escapeAttribute(value)}" ${value===topology.active_profile?'selected':''}>${escapeHTML(topologyProfileLabels[value]||value)}</option>`).join('')}</select></label>
    <label title="Gateway использует собственный bridge gateway-vpn-lan; в one-arm его роль выполняет wg-ingress.">Логический LAN-интерфейс<input name="lan_interface_name" maxlength="15" value="${topology.active_profile==='ONE_ARM_WIREGUARD'?'wg-ingress':'gateway-vpn-lan'}" readonly required></label>
    <label title="Адрес Gateway и подсеть, выдаваемая WAN Keenetic. Не должна пересекаться с uplink, HiLink или WireGuard.">LAN IPv4 CIDR<input name="lan_address" value="${escapeAttribute(topology.lan_address)}" required></label>
    <label class="checkbox"><input name="dhcp_dns_enabled" type="checkbox" ${topology.active_profile==='ONE_ARM_WIREGUARD'?'':'checked'}> DHCP/DNS для WAN роутера</label>
    <label class="checkbox"><input name="ingress_enabled" type="checkbox" ${ingress?.enabled?'checked':''}> Включить wg-ingress</label>
    <label title="ROUTED — обычный отдельный ingress; ONE_ARM — трафик приходит и возвращается через одну физическую карту.">Режим wg-ingress<select name="ingress_topology_mode"><option value="ROUTED">Обычный routed</option><option value="ONE_ARM">Одна карта</option></select></label>
    <label class="checkbox" title="Обязательно, если удаляется последний локальный management path. Подтверждение будет принято только через свежий wg-mgmt."><input name="require_wireguard_confirmation" type="checkbox"> Подтверждать только через management WireGuard</label>
  </div>`;
  form.elements.ingress_topology_mode.value=ingress?.topology_mode||'ROUTED';
  form.append(topologyRoleMatrix(interfaces,ingress));
  const prerequisites=document.createElement('fieldset');prerequisites.className='topology-prerequisites';const legend=document.createElement('legend');legend.textContent='Внешние действия и риск';prerequisites.append(legend);
  Object.entries(topologyPrerequisiteLabels).forEach(([value,labelText])=>{const label=document.createElement('label');label.className='checkbox';label.title='Gateway проверит этот флажок ещё раз перед созданием snapshot.';const input=document.createElement('input');input.type='checkbox';input.value=value;input.dataset.prerequisite='';label.append(input,document.createTextNode(' '+labelText));prerequisites.append(label)});form.append(prerequisites);
  const result=document.createElement('div');result.className='topology-preview-result muted';result.textContent='Сначала выполните безопасную предварительную проверку.';
  const previewButton=document.createElement('button');previewButton.type='button';previewButton.textContent='Проверить профиль без применения';
  const applyButton=document.createElement('button');applyButton.type='button';applyButton.textContent='Применить на 60 секунд';applyButton.disabled=true;applyButton.className='danger';let acceptedPayload='';
  const invalidate=()=>{acceptedPayload='';applyButton.disabled=true};form.addEventListener('input',invalidate);
  form.elements.profile.addEventListener('change',()=>{normalizeTopologyProfile(form);if(form.elements.profile.value==='ONE_ARM_WIREGUARD'){form.elements.lan_interface_name.value='wg-ingress';if(ingress?.server_address)form.elements.lan_address.value=ingress.server_address}else if(form.elements.lan_interface_name.value==='wg-ingress'){form.elements.lan_interface_name.value='gateway-vpn-lan'}invalidate()});
  form.querySelectorAll('input[name="shared_one_arm_interface_id"]').forEach(control=>control.addEventListener('change',()=>{if(form.elements.profile.value==='ONE_ARM_WIREGUARD')normalizeTopologyProfile(form)}));
  previewButton.addEventListener('click',async()=>{previewButton.disabled=true;try{const payload=topologyPayload(form,interfaces),preview=await api('/api/v1/network/topology/preview',{method:'POST',body:JSON.stringify(payload)});const missing=preview.missing_prerequisites||[];result.className=missing.length?'topology-preview-result restore-warning':'topology-preview-result success';result.textContent=missing.length?`Нужно подтвердить: ${missing.map(value=>topologyPrerequisiteLabels[value]||value).join(' ')}`:`Проверка пройдена. Будут затронуты: ${(preview.affected_interfaces||[]).join(', ')||'только логические интерфейсы'}. Новый адрес: ${preview.new_url}`;acceptedPayload=missing.length?'':JSON.stringify(payload);applyButton.disabled=!acceptedPayload}catch(err){result.className='topology-preview-result restore-warning';result.textContent=err.message;invalidate()}finally{previewButton.disabled=false}});
  applyButton.addEventListener('click',async()=>{const payload=topologyPayload(form,interfaces);if(!acceptedPayload||JSON.stringify(payload)!==acceptedPayload){notice('После последней проверки настройки изменились; выполните Preview ещё раз');invalidate();return}if(!confirm('Применить весь сетевой профиль? При потере связи он автоматически откатится.'))return;applyButton.disabled=true;try{const prepared=await api('/api/v1/network/topology/apply',{method:'POST',body:JSON.stringify(payload)});sessionStorage.setItem(topologyApplyStorageKey,JSON.stringify({id:prepared.apply_id,token:prepared.confirm_token,deadline:prepared.rollback_deadline,new_url:prepared.new_url}));notice('Topology profile применён временно; подтвердите новый management path');await renderNetwork()}catch(err){notice(err.message);applyButton.disabled=false}});
  const actions=document.createElement('div');actions.className='actions';actions.append(previewButton,applyButton);form.append(result,actions);section.append(form);return section;
}
