'use strict';

function shortFingerprint(value){const text=String(value||'');return text?`${text.slice(0,12)}…${text.slice(-8)}`:'—'}

function fabricTabs(sections){
  const tabs=document.createElement('div');tabs.className='fabric-subtabs';
  const select=id=>{for(const [key,section] of Object.entries(sections)){section.hidden=key!==id}tabs.querySelectorAll('button').forEach(button=>button.classList.toggle('active',button.dataset.section===id))};
  for(const [id,section] of Object.entries(sections)){const button=document.createElement('button');button.type='button';button.dataset.section=id;button.textContent=section.dataset.label;button.addEventListener('click',()=>select(id));tabs.append(button)}
  select(Object.keys(sections)[0]);return tabs;
}

function fabricSection(label,...children){const section=document.createElement('section');section.className='fabric-section';section.dataset.label=label;section.append(...children);return section}

async function renderManagementFabric(){
  const [response,uplinkResponse]=await Promise.all([api('/api/v1/management-fabric'),api('/api/v1/uplinks')]);
  const fabric=response.fabric,uplinks=uplinkResponse.items||[];
  fabric.vps=fabric.vps||[];fabric.links=fabric.links||[];fabric.admins=fabric.admins||[];fabric.resources=fabric.resources||[];fabric.publications=fabric.publications||[];fabric.acl=fabric.acl||[];
  const enabledVPS=fabric.vps.filter(item=>item.enabled);
  const statusGrid=document.createElement('div');statusGrid.className='grid';
  const converged=fabric.desired_generation===fabric.applied_generation&&!response.host_status.needs_apply;
  statusGrid.append(
    card('Management Fabric',converged?'СОГЛАСОВАН':'ОЖИДАЕТ ПРИМЕНЕНИЯ',`generation ${fabric.applied_generation} / ${fabric.desired_generation}`),
    card('VPS',String(enabledVPS.length),`Настроено: ${fabric.vps.length}`),
    card('Одновременные каналы',String(fabric.links.filter(item=>item.enabled).length),'Все включённые связи работают параллельно'),
    card('Root status',response.host_status_query_state,response.host_status.reason||fabric.last_error_code||'Ошибок применения нет')
  );
  const controls=document.createElement('div');controls.className='card actions';
  controls.append(
    actionButton('Проверить и применить сейчас',async()=>{await api('/api/v1/management-fabric/sync',{method:'POST'});notice('Management Fabric проверен и применён');await renderManagementFabric()},false,!response.apply_available),
    actionButton('Отключить все VPS-каналы',async()=>{if(!enabledVPS.length||!confirm('Отключить все VPS-каналы удалённого управления? Локальный WebUI и пользовательский интернет останутся работать.'))return;for(const item of enabledVPS){await api(`/api/v1/management-fabric/vps/${encodeURIComponent(item.id)}`,{method:'PATCH',body:JSON.stringify({name:item.name,enabled:false})})}notice('Все VPS-каналы отключены');await renderManagementFabric()},true,!enabledVPS.length)
  );
  controls.title='Применение выполняет только фиксированный root broker. WebUI не передаёт команды, маршруты, nftables-выражения или пути ключей.';

  const overview=fabricSection('Обзор',statusGrid,controls);
  const reorder=async(id,direction)=>{const items=fabric.vps.filter(item=>item.enabled),index=items.findIndex(item=>item.id===id),target=index+direction;if(index<0||target<0||target>=items.length)return;[items[index],items[target]]=[items[target],items[index]];await api('/api/v1/management-fabric/vps/priorities',{method:'PUT',body:JSON.stringify({ids:items.map(item=>item.id)})});await renderManagementFabric()};
  const vpsRows=fabric.vps.map(item=>({...item,actions:actionGroup(
    actionButton('Выше',()=>reorder(item.id,-1),false,!item.enabled||enabledVPS[0]?.id===item.id),
    actionButton('Ниже',()=>reorder(item.id,1),false,!item.enabled||enabledVPS.at(-1)?.id===item.id),
    actionButton('Переименовать',async()=>{const name=prompt('Понятное имя VPS',item.name);if(!name)return;await api(`/api/v1/management-fabric/vps/${encodeURIComponent(item.id)}`,{method:'PATCH',body:JSON.stringify({name,enabled:item.enabled})});await renderManagementFabric()}),
    actionButton(item.enabled?'Отключить':'Включить',async()=>{if(item.enabled&&!confirm(`Отключить каналы через ${item.name}?`))return;const result=await api(`/api/v1/management-fabric/vps/${encodeURIComponent(item.id)}`,{method:'PATCH',body:JSON.stringify({name:item.name,enabled:!item.enabled})});notice(result.sync_state==='RETRY_PENDING'?'Настройка сохранена; watchdog повторит применение':'Настройка применена');await renderManagementFabric()},item.enabled)
  )}));
  const vpsIntro=document.createElement('div');vpsIntro.className='card';vpsIntro.innerHTML='<h2>VPS</h2><p class="muted">Приоритет определяет предпочтение между одинаково доступными управляющими VPS. Включённые links остаются подняты одновременно; отказ одного VPS не отключает остальные.</p>';
  const vpsSection=fabricSection('VPS',vpsIntro,table([
    {label:'№',key:'number'},{label:'Приоритет',key:'priority'},{label:'Имя',key:'name'},{label:'Включён',render:item=>item.enabled?'Да':'Нет'},
    {label:'Состояние',render:item=>badge(item.state)},{label:'Management pool',key:'admin_address_pool'},{label:'Alias pool',key:'resource_alias_pool'},
    {label:'Проверенный fingerprint',render:item=>{const value=document.createElement('span');value.className='fingerprint';value.title=item.verified_fingerprint;value.textContent=shortFingerprint(item.verified_fingerprint);return value}},
    {label:'Действия',render:item=>item.actions}
  ],vpsRows));

  const linkNodes=[];
  for(const item of fabric.links){
    const details=document.createElement('details');details.className='card fabric-link-editor';
    const summary=document.createElement('summary');summary.append(document.createTextNode(`${item.interface_name} · ${item.vps_id} · `),badge(item.state));
    const info=document.createElement('p');info.className='muted';info.textContent=`${item.local_address} ↔ ${item.remote_address} · subnet ${item.management_subnet} · uplink ${item.selected_uplink_id||'ещё не выбран'} · route ${item.applied_route_generation}/${item.desired_route_generation} · ACL ${item.applied_acl_generation}/${item.desired_acl_generation}`;
    const form=document.createElement('form');form.className='settings-form';
    form.innerHTML='<label class="check" title="Отключение сохраняет настройки, но удаляет interface/routes/ACL из host runtime после применения."><input name="enabled" type="checkbox">Канал включён</label><label title="AUTO выбирает готовый физический выход по общему приоритету. PINNED_WITH_FALLBACK предпочитает выбранный, но допускает резерв. PINNED_ONLY запрещает другой uplink.">Политика физического выхода<select name="policy"><option value="AUTO">Автоматически</option><option value="PINNED_WITH_FALLBACK">Закреплённый с резервом</option><option value="PINNED_ONLY">Только закреплённый</option></select></label><label title="Используется для двух закреплённых режимов. В AUTO поле игнорируется.">Закреплённый uplink<select name="pinned"><option value="">Не выбран</option></select></label><label title="Период служебного пакета WireGuard, который поддерживает NAT-сопоставление модема/роутера.">Persistent keepalive, секунд<input name="keepalive" type="number" min="10" max="60" required></label><button>Сохранить канал</button>';
    form.elements.enabled.checked=item.enabled;form.elements.policy.value=item.uplink_policy;form.elements.keepalive.value=item.persistent_keepalive;
    for(const uplink of uplinks){const option=document.createElement('option');option.value=uplink.id;option.textContent=`#${uplink.number} ${uplink.name} (${uplink.type}, ${uplink.state})`;option.selected=uplink.id===item.pinned_uplink_id;form.elements.pinned.append(option)}
    form.addEventListener('submit',async event=>{event.preventDefault();const policy=form.elements.policy.value,pinned=policy==='AUTO'?'':form.elements.pinned.value;if(policy!=='AUTO'&&!pinned){notice('Для закреплённой политики выберите uplink');return}const result=await api(`/api/v1/management-fabric/links/${encodeURIComponent(item.id)}`,{method:'PATCH',body:JSON.stringify({enabled:form.elements.enabled.checked,uplink_policy:policy,pinned_uplink_id:pinned,persistent_keepalive:Number(form.elements.keepalive.value)})});notice(result.sync_state==='RETRY_PENDING'?'Канал сохранён; watchdog повторит применение':'Канал сохранён и применён');await renderManagementFabric()});
    details.append(summary,info,form);linkNodes.push(details);
  }
  if(!linkNodes.length){const empty=document.createElement('div');empty.className='card empty';empty.textContent='Связи с VPS ещё не добавлены';linkNodes.push(empty)}
  const linksSection=fabricSection('Каналы',...linkNodes);

  const adminsSection=fabricSection('Администраторы',table([
    {label:'Имя',key:'name'},{label:'Тип',key:'kind'},{label:'VPS',key:'vps_id'},{label:'Адрес',key:'assigned_address'},
    {label:'Состояние',render:item=>badge(item.peer_state||item.state)},{label:'Generation',render:item=>`${item.applied_generation}/${item.desired_generation}`},
    {label:'Fingerprint',render:item=>shortFingerprint(item.public_key_fingerprint)}
  ],fabric.admins||[]));
  const resourcesSection=fabricSection('Ресурсы',table([
    {label:'Имя',key:'name'},{label:'Тип',key:'kind'},{label:'Профиль доступа',key:'access_profile'},{label:'Локальный адрес',key:'local_destination'},
    {label:'Включён',render:item=>item.enabled?'Да':'Нет'},{label:'Health',render:item=>badge(item.health_state)},{label:'Route generation',render:item=>`${item.applied_route_generation}/${item.desired_route_generation}`},
    {label:'Порты',render:item=>(item.ports||[]).map(port=>port.protocol==='ICMP'?'ICMP':`${port.protocol} ${port.port_start}${port.port_end!==port.port_start?`-${port.port_end}`:''}`).join(', ')||'—'}
  ],fabric.resources||[]));
  const accessSection=fabricSection('Матрица доступа',
    table([{label:'Администратор',key:'admin_id'},{label:'Ресурс',key:'resource_id'},{label:'Протокол',key:'protocol'},{label:'Порты',render:item=>item.protocol==='ICMP'?'—':`${item.port_start}${item.port_end!==item.port_start?`-${item.port_end}`:''}`},{label:'Включено',render:item=>item.enabled?'Да':'Нет'},{label:'Generation',key:'generation'}],fabric.acl||[]),
    table([{label:'Ресурс',key:'resource_id'},{label:'Канал',key:'link_id'},{label:'Публикуемый alias',key:'published_alias'},{label:'Состояние',render:item=>badge(item.state)},{label:'Route',render:item=>`${item.applied_route_generation}/${item.desired_route_generation}`},{label:'ACL',render:item=>`${item.applied_acl_generation}/${item.desired_acl_generation}`}],fabric.publications||[])
  );
  const sections={overview,vps:vpsSection,links:linksSection,admins:adminsSection,resources:resourcesSection,access:accessSection};
  setContent(fabricTabs(sections),...Object.values(sections));
}

titles['management-fabric']='VPS и удалённое управление';
renderers['management-fabric']=renderManagementFabric;
