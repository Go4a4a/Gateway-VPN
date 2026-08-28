'use strict';

const powerActions={
  REBOOT:{label:'Перезагрузить',endpoint:'/api/v1/system/reboot',confirmation:'ПЕРЕЗАГРУЗИТЬ',description:'Корректно завершает сервисы и перезагружает Gateway. Доступ и Internet временно пропадут.'},
  SHUTDOWN:{label:'Выключить',endpoint:'/api/v1/system/shutdown',confirmation:'ВЫКЛЮЧИТЬ',description:'Корректно выключает Gateway. Для повторного запуска потребуется физически включить компьютер.'},
  RTC_POWER_CYCLE:{label:'Выключить и включить по таймеру',endpoint:'/api/v1/system/power-cycle',confirmation:'ВЫКЛЮЧИТЬ И ВКЛЮЧИТЬ',description:'Ставит проверенный RTC wake alarm и выключает Gateway. Доступно только после аппаратного подтверждения wake-from-S5.'}
};

function openPowerDialog(action,capabilities){
  const definition=powerActions[action],rtc=action==='RTC_POWER_CYCLE',dialog=document.createElement('dialog');
  dialog.className='editor-dialog power-dialog';
  const form=document.createElement('form');form.className='card settings-form';
  const min=capabilities.minimum_rtc_delay_seconds||30,max=capabilities.maximum_rtc_delay_seconds||3600,delay=capabilities.default_rtc_delay_seconds||30;
  form.innerHTML=`<h2>${definition.label}</h2><p class="restore-warning">${definition.description}</p>${rtc?`<label title="RTC-таймер считается от отправки команды. Фактическое время в полностью выключенном состоянии будет короче на время корректного завершения Ubuntu; автозапуск также зависит от UEFI.">Запланировать включение через, секунд<input name="delay_seconds" type="number" min="${min}" max="${max}" value="${delay}" required></label>`:''}<label title="Повторная проверка подтверждает, что опасное действие выполняет текущий администратор.">Текущий пароль<input name="password" type="password" autocomplete="current-password" maxlength="1024" required></label><label title="Защита от случайного нажатия: фразу нужно ввести точно, как показано.">Введите: ${definition.confirmation}<input name="confirmation" autocomplete="off" spellcheck="false" maxlength="64" required></label><p class="muted" data-countdown>После подтверждения будет 5 секунд на отмену.</p><div class="actions"><button type="submit" class="action danger">Продолжить</button><button type="button" class="action" data-cancel>Отмена</button></div>`;
  const submit=form.querySelector('button[type=submit]'),cancel=form.querySelector('[data-cancel]'),countdown=form.querySelector('[data-countdown]');
  let timer=null,remaining=0,dispatching=false;
  const stopCountdown=()=>{if(timer)clearInterval(timer);timer=null;remaining=0;submit.disabled=false;submit.textContent='Продолжить';countdown.textContent='Операция отменена до отправки команды.'};
  cancel.addEventListener('click',()=>{if(dispatching)return;if(timer){stopCountdown();return}dialog.close()});
  form.addEventListener('submit',event=>{
    event.preventDefault();if(timer||dispatching)return;
    if(form.elements.confirmation.value!==definition.confirmation){notice(`Введите «${definition.confirmation}» точно, как показано`);return}
    remaining=5;submit.disabled=true;submit.textContent=`Отправка через ${remaining}…`;countdown.textContent='До отправки команды можно нажать «Отмена».';
    timer=setInterval(async()=>{
      remaining--;submit.textContent=remaining>0?`Отправка через ${remaining}…`:'Отправка…';
      if(remaining>0)return;
      clearInterval(timer);timer=null;dispatching=true;cancel.disabled=true;
      const payload={password:form.elements.password.value,confirmation:definition.confirmation,delay_seconds:rtc?Number(form.elements.delay_seconds.value):0};
      form.elements.password.value='';
      try{
        const result=await api(definition.endpoint,{method:'POST',body:JSON.stringify(payload)});
        sessionStorage.setItem('gateway-vpn-power-action',`${definition.label}: команда отправлена, operation ${result.operation_id||result.id||'создана'}.`);
        notice(`${definition.label}: команда отправлена. Соединение с Gateway сейчас прервётся.`);dialog.close();
      }catch(err){
        notice(err.message);dispatching=false;cancel.disabled=false;submit.disabled=false;submit.textContent='Продолжить';countdown.textContent='Команда не подтверждена. Проверьте состояние Gateway перед повтором.';
      }
    },1000);
  });
  dialog.addEventListener('close',()=>{if(timer)clearInterval(timer);form.elements.password.value='';dialog.remove()});
  dialog.append(form);document.body.append(dialog);dialog.showModal();
}

async function powerPanel(){
  const box=document.createElement('section');box.className='card power-panel';
  const heading=document.createElement('h2');heading.textContent='Питание';
  const intro=document.createElement('p');intro.className='muted';intro.textContent='Ручные действия не связаны с автоматическим watchdog. Требуются текущий пароль, точная фраза и отменяемый 5-секундный отсчёт. Во время install/update/restore или safe network apply команды блокируются.';
  box.append(heading,intro);
  let data;
  try{data=await api('/api/v1/system/power/capabilities')}catch(err){const warning=document.createElement('p');warning.className='restore-warning';warning.textContent=`Управление питанием недоступно: ${err.message}`;box.append(warning);return box}
  const capabilities=data.capabilities||{},rtc=capabilities.rtc_power_cycle||{};
  const summary=document.createElement('div');summary.className='grid power-summary';
  summary.append(card('Перезагрузка',capabilities.reboot?.available?'ДОСТУПНА':'НЕДОСТУПНА','Корректный systemd reboot'),card('Выключение',capabilities.shutdown?.available?'ДОСТУПНО':'НЕДОСТУПНО','Повторное включение вручную'),card('RTC-автозапуск',rtc.available?'ПОДТВЕРЖДЁН':rtc.detected?'ОБНАРУЖЕН, НЕ ПРОВЕРЕН':'НЕДОСТУПЕН',rtc.available?'Wake-from-S5 подтверждён на этом Gateway':rtc.reason_code||'RTC/UEFI не обнаружены'));
  box.append(summary);
  if(rtc.detected&&!rtc.verified){const warning=document.createElement('p');warning.className='restore-warning';warning.textContent='RTC и helper обнаружены, но включение после полного выключения ещё не подтверждено на этом компьютере. Кнопка заблокирована до аппаратного теста — обычные reboot и shutdown работают независимо.';box.append(warning)}
  const actions=document.createElement('div');actions.className='actions power-actions';
  for(const [action,capability] of [['REBOOT',capabilities.reboot],['SHUTDOWN',capabilities.shutdown],['RTC_POWER_CYCLE',rtc]]){
    const button=actionButton(powerActions[action].label,()=>openPowerDialog(action,capabilities),true,!capability?.available);
    button.title=capability?.available?powerActions[action].description:`Недоступно: ${capability?.reason_code||'возможность не обнаружена'}`;actions.append(button);
  }
  box.append(actions);
  if(data.latest_operation){const latest=document.createElement('p');latest.className='muted';latest.textContent=`Последняя операция: ${data.latest_operation.scope_id} · ${data.latest_operation.status} · ${data.latest_operation.summary_code||'без результата'} · ${data.latest_operation.updated_at}`;box.append(latest)}
  return box;
}
