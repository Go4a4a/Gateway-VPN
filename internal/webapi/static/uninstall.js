'use strict';

function openUninstallDialog(impact){
  const phrase=impact.required_confirmation_phrase||'УДАЛИТЬ GATEWAY VPN',dialog=document.createElement('dialog');
  dialog.className='editor-dialog uninstall-dialog';
  const form=document.createElement('form');form.className='card settings-form uninstall-form';
  form.innerHTML=`<h2>Удалить Gateway VPN</h2><p class="restore-warning"><strong>Это не заводской сброс Ubuntu.</strong> WebUI, SSH/SFTP и пользовательский Internet могут сразу стать недоступны. Пакеты Ubuntu и изменения других программ не удаляются.</p><label title="Сохранение данных оставляет /var/lib/gateway-vpn для повторной установки. Полное удаление уничтожает базу, секреты, ключи, резервные копии и экспорты журналов.">Режим<select name="mode"><option value="PRESERVE_DATA">Сохранить данные Gateway VPN</option><option value="PURGE_DATA">Полное удаление данных</option></select></label><p class="muted" data-mode-description></p><label class="check"><input name="ack_session" type="checkbox" required><span>Понимаю, что текущие WebUI, SSH и SFTP соединения могут оборваться</span></label><label class="check"><input name="ack_not_factory" type="checkbox" required><span>Понимаю, что это удаление Gateway VPN, а не восстановление всей Ubuntu к исходному состоянию</span></label><div data-purge-acks hidden><label class="check"><input name="ack_export" type="checkbox"><span>Я скачал нужный backup/диагностику или осознанно продолжаю без экспорта</span></label><label class="check"><input name="ack_purge" type="checkbox"><span>Безвозвратно удалить базу, подписки, секреты, ключи, backups и экспорты журналов</span></label></div><label title="Повторная проверка подтверждает текущего администратора.">Текущий пароль<input name="password" type="password" autocomplete="current-password" maxlength="1024" required></label><label title="Защита от случайного запуска: фраза должна совпасть полностью.">Введите: ${phrase}<input name="confirmation" autocomplete="off" spellcheck="false" maxlength="64" required></label><p class="muted" data-countdown>После подтверждения будет 8 секунд на отмену.</p><div class="actions"><button type="submit" class="action danger">Продолжить</button><button type="button" class="action" data-cancel>Отмена</button></div>`;
  const mode=form.elements.mode,modeDescription=form.querySelector('[data-mode-description]'),purgeAcks=form.querySelector('[data-purge-acks]'),submit=form.querySelector('button[type=submit]'),cancel=form.querySelector('[data-cancel]'),countdown=form.querySelector('[data-countdown]');
  const updateMode=()=>{const purge=mode.value==='PURGE_DATA';purgeAcks.hidden=!purge;form.elements.ack_export.required=purge;form.elements.ack_purge.required=purge;modeDescription.textContent=purge?impact.purge_data_description:impact.preserve_data_description};
  mode.addEventListener('change',updateMode);updateMode();
  let timer=null,remaining=0,dispatching=false;
  const stopCountdown=()=>{if(timer)clearInterval(timer);timer=null;remaining=0;submit.disabled=false;submit.textContent='Продолжить';countdown.textContent='Операция отменена до передачи root guardian.'};
  cancel.addEventListener('click',()=>{if(dispatching)return;if(timer){stopCountdown();return}dialog.close()});
  form.addEventListener('submit',event=>{
    event.preventDefault();if(timer||dispatching)return;
    if(form.elements.confirmation.value!==phrase){notice(`Введите «${phrase}» точно, как показано`);return}
    remaining=8;submit.disabled=true;submit.textContent=`Удаление через ${remaining}…`;countdown.textContent='До передачи root guardian можно нажать «Отмена».';
    timer=setInterval(async()=>{
      remaining--;submit.textContent=remaining>0?`Удаление через ${remaining}…`:'Передача guardian…';
      if(remaining>0)return;
      clearInterval(timer);timer=null;dispatching=true;cancel.disabled=true;
      const purge=mode.value==='PURGE_DATA',payload={mode:mode.value,password:form.elements.password.value,confirmation:phrase,acknowledge_session_loss:form.elements.ack_session.checked,acknowledge_not_factory_reset:form.elements.ack_not_factory.checked,acknowledge_purge_data_loss:purge&&form.elements.ack_purge.checked,acknowledge_export_handled:purge&&form.elements.ack_export.checked};
      form.elements.password.value='';
      try{
        const result=await api('/api/v1/system/uninstall',{method:'POST',body:JSON.stringify(payload)});
        sessionStorage.setItem('gateway-vpn-uninstall',`Удаление передано root guardian: ${result.operation_id||result.id||'операция создана'}. Итоговый receipt останется в /var/lib/gateway-vpn-uninstall/.`);
        notice('Root guardian принял удаление. Соединение сейчас прервётся; не выключайте питание без необходимости.');dialog.close();
      }catch(err){notice(err.message);dispatching=false;cancel.disabled=false;submit.disabled=false;submit.textContent='Продолжить';countdown.textContent='Удаление не подтверждено. Проверьте состояние Gateway перед повтором.'}
    },1000);
  });
  dialog.addEventListener('close',()=>{if(timer)clearInterval(timer);form.elements.password.value='';dialog.remove()});
  dialog.append(form);document.body.append(dialog);dialog.showModal();
}

async function uninstallPanel(){
  const box=document.createElement('section');box.className='card uninstall-panel';
  box.innerHTML='<h2>Удаление Gateway VPN</h2><p class="muted">Безопасно закрывает пользовательский путь, восстанавливает только записанные установщиком изменения и удаляет принадлежащие Gateway VPN файлы. Пакеты Ubuntu не удаляются.</p>';
  let data;
  try{data=await api('/api/v1/system/uninstall/impact')}catch(err){const warning=document.createElement('p');warning.className='restore-warning';warning.textContent=`Impact report недоступен: ${err.message}`;box.append(warning);return box}
  const impact=data.impact||{},summary=document.createElement('dl');summary.className='restore-summary';
  summary.innerHTML=`<dt>Запись исходного состояния</dt><dd>${impact.installed_state_recorded?'есть — owned изменения будут восстановлены':'не найдена — удаление остановится либо не будет угадывать состояние ОС'}</dd><dt>Данные приложения</dt><dd>${impact.application_data_present?'обнаружены':'не обнаружены'}</dd><dt>Пакеты Ubuntu</dt><dd>${impact.os_packages_retained?'останутся установленными':'неизвестно'}</dd><dt>Текущая операция</dt><dd>${impact.active?'УДАЛЕНИЕ УЖЕ ВЫПОЛНЯЕТСЯ':'нет'}</dd>`;
  box.append(summary);
  const details=document.createElement('details');details.innerHTML='<summary>Что изменится и что не откатывается</summary>';
  const effects=document.createElement('ul');for(const item of impact.common_effects||[])effects.append(Object.assign(document.createElement('li'),{textContent:item}));
  const excluded=document.createElement('p');excluded.className='muted';excluded.textContent=`Не восстанавливается автоматически: ${(impact.not_restored_automatically||[]).join('; ')}.`;details.append(effects,excluded);box.append(details);
  const actions=document.createElement('div');actions.className='actions';const button=actionButton('Открыть безопасное удаление',()=>openUninstallDialog(impact),true,!impact.available||impact.active);button.classList.add('danger');button.title='Требуются password re-auth, точная фраза, подтверждение impact report и отменяемый отсчёт.';actions.append(button);box.append(actions);
  if(data.latest_operation){const latest=document.createElement('p');latest.className='muted';latest.textContent=`Последний запрос: ${data.latest_operation.scope_id} · ${data.latest_operation.status} · ${data.latest_operation.summary_code||'без результата'} · ${data.latest_operation.updated_at}`;box.append(latest)}
  return box;
}
