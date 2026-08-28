'use strict';

const ethernetApplyStorageKey='gateway-vpn-ethernet-apply';

function ethernetFreeInterfaces(interfaces){
  return interfaces.filter(item=>item.carrier_state!=='ABSENT'&&(item.roles||[]).every(role=>role.role==='UNUSED'||role.role==='SHARED_ONE_ARM'));
}

function ethernetInterfaceOptions(items,selected=''){
  return items.map(item=>`<option value="${escapeAttribute(item.id)}" ${item.id===selected?'selected':''}>${escapeHTML(item.interface_name||'Без имени')} · ${escapeHTML(item.vendor||item.model||item.driver||item.id)} · ${escapeHTML(item.carrier_state)}</option>`).join('');
}

function escapeHTML(value){
  return String(value??'').replace(/[&<>"']/g,character=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[character]));
}

function escapeAttribute(value){return escapeHTML(value)}

function ethernetNetworkFields(values={}){
  const mode=values.address_mode||'DHCP';
  return `<label title="DHCP получает IPv4, шлюз и обычно DNS автоматически от роутера, ONT или другого Ethernet-провайдера.">Получение адреса
    <select name="address_mode"><option value="DHCP" ${mode==='DHCP'?'selected':''}>Автоматически (DHCP)</option><option value="STATIC" ${mode==='STATIC'?'selected':''}>Статический IPv4</option></select>
  </label>
  <label data-static title="Адрес этой карты вместе с префиксом, например 172.20.1.2/24. Подсеть не должна совпадать с LAN, WireGuard или другим выходом.">IPv4 CIDR<input name="ipv4_cidr" value="${escapeAttribute(values.ipv4_cidr||'')}" placeholder="172.20.1.2/24"></label>
  <label data-static title="Шлюз должен находиться в той же подсети, но отличаться от адреса Gateway.">Шлюз<input name="gateway" value="${escapeAttribute(values.gateway||'')}" placeholder="172.20.1.1"></label>
  <label title="Необязательно. Несколько IPv4 DNS вводятся через запятую. В DHCP пустое поле означает использовать DNS, полученный автоматически.">DNS<input name="dns" value="${escapeAttribute((values.dns||[]).join(', '))}" placeholder="1.1.1.1, 9.9.9.9"></label>
  <label title="Оставьте 0 для системного значения. Допустимо 576–9216; обычно используется 1500.">MTU<input name="mtu" type="number" min="0" max="9216" value="${Number(values.mtu||0)}"></label>`;
}

function bindEthernetMode(form){
  const refresh=()=>{const isStatic=form.elements.address_mode.value==='STATIC';form.querySelectorAll('[data-static]').forEach(label=>{label.hidden=!isStatic;label.querySelector('input').required=isStatic})};
  form.elements.address_mode.addEventListener('change',refresh);refresh();
}

function ethernetPayload(form){
  const mode=form.elements.address_mode.value;
  return {address_mode:mode,ipv4_cidr:mode==='STATIC'?form.elements.ipv4_cidr.value.trim():'',gateway:mode==='STATIC'?form.elements.gateway.value.trim():'',dns:form.elements.dns.value.split(',').map(value=>value.trim()).filter(Boolean),mtu:Number(form.elements.mtu.value||0)};
}

function rememberEthernetApply(result,label){
  sessionStorage.setItem(ethernetApplyStorageKey,JSON.stringify({id:result.apply_id,token:result.confirm_token,deadline:result.rollback_deadline,label}));
}

function readEthernetApply(){
  try{return JSON.parse(sessionStorage.getItem(ethernetApplyStorageKey)||'null')}catch{return null}
}

async function ethernetPendingPanel(){
  const pending=readEthernetApply();if(!pending)return null;
  const box=document.createElement('section');box.className='card ethernet-confirm';
  const heading=document.createElement('h3');heading.textContent='Ожидает подтверждения: '+(pending.label||'Ethernet-настройка');
  const status=document.createElement('p');status.className='restore-warning';status.textContent=`Если не подтвердить до ${pending.deadline}, предыдущая карта и конфигурация восстановятся автоматически.`;
  let transaction;
  try{transaction=await api(`/api/v1/settings/network/apply/${encodeURIComponent(pending.id)}`)}catch(err){status.textContent=err.message}
  const stateLine=document.createElement('p');stateLine.textContent=`Состояние: ${transaction?.state||'проверяется'}`;
  const confirmButton=actionButton('Подтвердить применённую Ethernet-настройку',async()=>{
    await api(`/api/v1/settings/network/apply/${encodeURIComponent(pending.id)}/confirm`,{method:'POST',body:JSON.stringify({confirm_token:pending.token})});
    sessionStorage.removeItem(ethernetApplyStorageKey);notice('Ethernet-настройка подтверждена; rollback timer отменён');await renderNetwork();
  },false,transaction?.state!=='APPLIED');
  confirmButton.title='Подтверждение означает, что WebUI всё ещё доступен и выбранная конфигурация должна стать постоянной.';
  if(['CONFIRMED','ROLLED_BACK','FAILED'].includes(transaction?.state)){confirmButton.disabled=true;sessionStorage.removeItem(ethernetApplyStorageKey)}
  box.append(heading,status,stateLine,confirmButton);return box;
}

function openEthernetDialog(title,body,submitLabel,onSubmit){
  const dialog=document.createElement('dialog');dialog.className='editor-dialog';
  const form=document.createElement('form');form.className='settings-form';form.method='dialog';form.innerHTML=`<h2>${escapeHTML(title)}</h2>${body}<div class="actions"><button type="submit">${escapeHTML(submitLabel)}</button><button type="button" data-cancel>Отмена</button></div>`;
  form.querySelector('[data-cancel]').addEventListener('click',()=>dialog.close());
  form.addEventListener('submit',async event=>{event.preventDefault();const submit=form.querySelector('button[type=submit]');submit.disabled=true;try{await onSubmit(form);dialog.close();await renderNetwork()}catch(err){notice(err.message);submit.disabled=false}});
  dialog.addEventListener('close',()=>dialog.remove());dialog.append(form);document.body.append(dialog);dialog.showModal();return form;
}

async function ethernetSafeApplyPanel(){
  const [uplinkData,interfaceData]=await Promise.all([api('/api/v1/uplinks'),api('/api/v1/network/interfaces')]);
  const ethernet=(uplinkData.items||[]).filter(item=>item.type==='ETHERNET'),interfaces=interfaceData.items||[],free=ethernetFreeInterfaces(interfaces);
  const section=document.createElement('section');section.className='card ethernet-safe-apply';
  const heading=document.createElement('h2');heading.textContent='Ethernet-выходы в Internet';
  const intro=document.createElement('p');intro.className='muted';intro.textContent='Здесь карта получает Internet по DHCP или статическому IPv4. Все изменения сначала применяются на 60 секунд и автоматически откатываются, если их не подтвердить.';
  section.append(heading,intro);
  const pending=await ethernetPendingPanel();if(pending)section.append(pending);

  const create=document.createElement('form');create.className='settings-form';create.innerHTML=`<h3>Добавить Ethernet-выход</h3><label title="Показывается в списке приоритетов и журналах.">Понятное название<input name="name" maxlength="128" required placeholder="Домашний провайдер"></label><label title="Можно выбрать только обнаруженную свободную карту без LAN, management, HiLink или другой uplink-роли.">Сетевая карта<select name="network_interface_id" required><option value="">Выберите свободную карту</option>${ethernetInterfaceOptions(free)}</select></label>${ethernetNetworkFields()}<button type="submit" ${free.length?'':'disabled'}>Проверить и применить на 60 секунд</button>`;
  bindEthernetMode(create);
  if(!free.length){const warning=document.createElement('p');warning.className='muted';warning.textContent='Свободных обнаруженных Ethernet-карт сейчас нет. Подключите карту или освободите её роль.';create.append(warning)}
  create.addEventListener('submit',async event=>{event.preventDefault();if(!confirm('Создать Ethernet-выход и временно применить networkd-конфигурацию? Без подтверждения всё откатится.'))return;const payload={name:create.elements.name.value.trim(),network_interface_id:create.elements.network_interface_id.value,...ethernetPayload(create)};const result=await api('/api/v1/uplinks/ethernet',{method:'POST',body:JSON.stringify(payload)});rememberEthernetApply(result,payload.name);notice('Candidate применён или применяется; дождитесь состояния APPLIED и подтвердите');await renderNetwork()});
  section.append(create);

  const dnsFor=item=>{try{return JSON.parse(item.dns_json||'[]')||[]}catch{return[]}};
  const rows=ethernet.map(item=>({...item,address:item.address_mode==='STATIC'?`${item.ipv4_cidr} → ${item.gateway}`:'Автоматически (DHCP)',actions:actionGroup(
    actionButton('IP, DNS и MTU',()=>{const form=openEthernetDialog(`Настройки «${item.name}»`,ethernetNetworkFields({...item,dns:dnsFor(item)}),'Применить на 60 секунд',async form=>{if(!confirm('Временно применить новые IP-настройки?'))return;const result=await api(`/api/v1/uplinks/${encodeURIComponent(item.id)}/network`,{method:'PUT',body:JSON.stringify({expected_desired_generation:item.desired_generation,...ethernetPayload(form)})});rememberEthernetApply(result,`${item.name}: IP-настройки`)});bindEthernetMode(form)}),
    actionButton('Заменить карту',()=>{const choices=free.filter(candidate=>candidate.id!==item.network_interface_id);openEthernetDialog(`Заменить карту «${item.name}»`,`<p class="restore-warning">Старая карта освободится только внутри подтверждаемой транзакции. При timeout назначение вернётся назад.</p><label>Новая свободная карта<select name="network_interface_id" required><option value="">Выберите карту</option>${ethernetInterfaceOptions(choices)}</select></label>`,'Заменить на 60 секунд',async form=>{if(!confirm('Временно переназначить этот выход на другую физическую карту?'))return;const result=await api(`/api/v1/uplinks/${encodeURIComponent(item.id)}/replace-interface`,{method:'POST',body:JSON.stringify({network_interface_id:form.elements.network_interface_id.value,expected_desired_generation:item.desired_generation})});rememberEthernetApply(result,`${item.name}: замена карты`)})},false,!free.some(candidate=>candidate.id!==item.network_interface_id))
  )}));
  section.append(table([{label:'Выход',key:'name'},{label:'Карта',render:item=>item.interface_name||item.network_interface_id},{label:'Адрес',key:'address'},{label:'Состояние',render:item=>badge(item.state)},{label:'Generation',render:item=>`${item.observed_generation}/${item.desired_generation}`},{label:'Действия',render:item=>item.actions}],rows));
  return section;
}
