const routeTitles = {
  dashboard:'概览', devices:'设备', sharing:'共享', policy:'访问', ops:'问题与维护', system:'系统维护', networks:'所有网络', network:'网络设置'
};

let taskContext=null;
function renderTaskContext(){
  const bar=document.getElementById('policyTaskContext');if(!bar)return;
  if(!taskContext){bar.hidden=true;bar.innerHTML='';return;}
  const isDevice=taskContext.type==='device';
  bar.hidden=false;
  bar.innerHTML=`<div><small>${isDevice?'来自设备详情':'来自共享详情'}</small><strong>${esc(taskContext.name)}</strong><p>${isDevice?'访问结果已保持这台设备作为当前来源。':'访问页已保持这个共享作为当前检查对象。'}</p></div><button class="secondary-btn small" id="returnTaskContext">${isDevice?'返回设备详情':'返回共享详情'}</button>`;
  document.getElementById('returnTaskContext')?.addEventListener('click',()=>{
    const ctx=taskContext;taskContext=null;
    if(ctx.type==='device'){showRoute('devices');openDrawer(ctx.name,'network');}
    else {showRoute('sharing');openServiceDrawer(ctx.name,'overview');}
  });
}
function showRoute(route,context=null){
  if(!routeTitles[route]) route='dashboard';
  taskContext=route==='policy'?context:null;
  if(route==='policy' && context?.type==='device') window.__policyContextSource=context.name;
  if(route!=='policy') window.__policyContextSource='';
  document.querySelectorAll('.page').forEach(p=>p.classList.toggle('active', p.dataset.page===route));
  document.querySelectorAll('.nav-item').forEach(a=>a.classList.toggle('active', a.dataset.route===route));
  const crumb=document.getElementById('crumbTitle');if(crumb)crumb.textContent=routeTitles[route];
  history.replaceState(null,'','#'+route);
  if(window.__networkWorkspaceReady) renderNetworkScopedPage(route);
  renderTaskContext();
  if(route==='policy' && context?.type==='device'){
    const picker=document.getElementById('policySourcePicker');
    if(picker && [...picker.options].some(o=>o.value===context.name)){picker.value=context.name;picker.dispatchEvent(new Event('change'));}
  }
  window.scrollTo({top:0,behavior:'instant'});
}

document.querySelectorAll('[data-route]').forEach(a=>a.addEventListener('click',e=>{
  const r=a.dataset.route;
  if(routeTitles[r]){e.preventDefault();showRoute(r)}
}));
document.querySelectorAll('[data-route-button]').forEach(b=>b.addEventListener('click',()=>showRoute(b.dataset.routeButton)));
showRoute(location.hash.replace('#','')||'dashboard');
window.addEventListener('hashchange',()=>showRoute(location.hash.replace('#','')||'dashboard'));

document.getElementById('themeBtn').addEventListener('click',()=>document.body.classList.toggle('dark'));

function esc(v=''){
  return String(v).replace(/[&<>'"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[c]));
}
function field(id){const el=document.getElementById(id);return el?el.value:'';}
function copyText(text, message='已复制'){
  if(navigator.clipboard && window.isSecureContext){
    navigator.clipboard.writeText(text).then(()=>toast(message)).catch(()=>fallbackCopy(text,message));
  }else fallbackCopy(text,message);
}
function fallbackCopy(text,message){
  const ta=document.createElement('textarea');ta.value=text;ta.style.position='fixed';ta.style.opacity='0';document.body.appendChild(ta);ta.select();
  try{document.execCommand('copy');toast(message)}catch(_){toast('请手动复制')}
  ta.remove();
}
function downloadText(filename,text){
  const blob=new Blob([text],{type:'text/plain;charset=utf-8'});
  const url=URL.createObjectURL(blob);const a=document.createElement('a');a.href=url;a.download=filename;document.body.appendChild(a);a.click();a.remove();URL.revokeObjectURL(url);
  toast('配置文件已生成');
}

/* ---------------- Device data & drawer ---------------- */
const devices = {
  '办公笔记本':{
    icon:'▰',status:'online',address:'10.18.0.12',platform:'Linux',location:'',last:'刚刚',version:'1.8.2',
    peerId:'peer_7f4c…91a2',groups:['家庭成员','受管设备'],credential:'正常',credentialExpiry:'2026-10-12',credentialSerial:'cred_a17c…8d2f',route:'直连优先 · 中继备用',
    access:[['家庭 NAS 文件服务','TCP 445'],['家庭 Dashboard','HTTPS 443'],['开发环境 SSH','TCP 22']],shares:[],
    activity:[['刚刚','与中继服务建立备用连接'],['8 分钟前','访问家庭 Dashboard'],['35 分钟前','设备身份验证成功']]
  },
  'Android 手机':{
    icon:'▯',status:'online',address:'10.18.0.21',platform:'Android',location:'',last:'1 分钟前',version:'1.8.2',
    peerId:'peer_52bd…0e19',groups:['家庭成员'],credential:'正常',credentialExpiry:'2026-10-07',credentialSerial:'cred_c803…7ab1',route:'中继',
    access:[['家庭 NAS 文件服务','TCP 445'],['家庭 Dashboard','HTTPS 443']],shares:[],
    activity:[['1 分钟前','保持在线'],['20 分钟前','访问家庭 NAS 文件服务']]
  },
  '家用 NAS':{
    icon:'▤',status:'online',address:'10.18.0.30',platform:'Linux',location:'',last:'3 分钟前',version:'1.8.1',
    peerId:'peer_81aa…33fd',groups:['基础设施'],credential:'正常',credentialExpiry:'2026-11-01',credentialSerial:'cred_73b0…4c11',route:'直连',
    access:[['家庭 Dashboard','HTTPS 443']],shares:[['家庭 NAS 文件服务','TCP 445'],['家庭 Dashboard','HTTPS 443']],
    activity:[['3 分钟前','共享服务健康检查通过'],['18 分钟前','家庭 NAS 文件服务被访问'],['1 小时前','设备身份验证成功']]
  },
  '家庭网关':{
    icon:'◇',status:'online',address:'10.18.0.18',platform:'Linux',location:'',last:'8 分钟前',version:'1.8.2',
    peerId:'peer_gw19…7dd2',groups:['基础设施'],credential:'正常',credentialExpiry:'2026-11-18',credentialSerial:'cred_gw90…18bb',route:'直连优先 · 中继备用',
    access:[['家庭 Dashboard','HTTPS 443']],shares:[],
    activity:[['8 分钟前','网关连接保持在线'],['35 分钟前','路径检查通过']]
  },
  '开发服务器':{
    icon:'▤',status:'online',address:'10.18.0.40',platform:'Linux',location:'',last:'12 分钟前',version:'1.8.0',
    peerId:'peer_5c8e…741a',groups:['开发设备'],credential:'正常',credentialExpiry:'2026-09-30',credentialSerial:'cred_bf16…0a0d',route:'直连',
    access:[['家庭 Dashboard','HTTPS 443']],shares:[['开发环境 SSH','TCP 22']],
    activity:[['12 分钟前','保持在线'],['42 分钟前','开发环境 SSH 健康检查通过']]
  },
  '测试主机':{
    icon:'▰',status:'offline',address:'10.18.0.66',platform:'Linux',location:'',last:'2 小时前',version:'1.7.9',
    peerId:'peer_a742…018c',groups:['开发设备'],credential:'正常',credentialExpiry:'2026-09-25',credentialSerial:'cred_e7d2…8f90',route:'未知',
    access:[],shares:[],activity:[['2 小时前','设备离线'],['3 小时前','最后一次设备身份验证成功']]
  }
};

const drawer=document.getElementById('deviceDrawer');
const drawerBg=document.getElementById('drawerBackdrop');
const drawerSummary=document.getElementById('drawerSummary');
const drawerTabContent=document.getElementById('drawerTabContent');
let currentDeviceName='办公笔记本';
let currentDrawerTab='overview';

function statusPill(device){
  return device.status==='online'
    ? '<span class="status-pill good">● 在线</span>'
    : '<span class="status-pill neutral">● 离线</span>';
}
function renderDrawerSummary(){
  const d=devices[currentDeviceName]||devices['办公笔记本'];
  drawerSummary.innerHTML=`
    <div class="device-hero upgraded">
      <div class="device-big-icon">${esc(d.icon)}</div>
      <div class="device-hero-copy">${statusPill(d)}<p>${esc(d.platform)} · ${esc((d.groups||[]).join('、')||'未分组')} · 最近连接 ${esc(d.last)}</p></div>
      <button class="secondary-btn small" id="testDeviceBtn">测试连接</button>
    </div>
    <div class="device-health ${d.status==='online'?'healthy':'offline'}">
      <span>${d.status==='online'?'✓':'!'}</span><div><strong>${d.status==='online'?'设备工作正常':'设备当前离线'}</strong><p>${d.status==='online'?'设备身份有效，可以按访问规则使用共享。':'最后一次连接为 '+esc(d.last)+'。离线不会自动取消已有访问规则。'}</p></div>
    </div>`;
  document.getElementById('testDeviceBtn')?.addEventListener('click',()=>toast(d.status==='online'?'连接测试成功 · 延迟 18 ms':'暂时无法连接到该设备'));
}

function renderDrawerTab(){
  const d=devices[currentDeviceName]||devices['办公笔记本'];
  document.querySelectorAll('#drawerTabs .drawer-tab').forEach(b=>b.classList.toggle('active',b.dataset.drawerTab===currentDrawerTab));
  if(currentDrawerTab==='overview'){
    drawerTabContent.innerHTML=`
      <div class="detail-grid round4-primary-facts">
        <div><small>虚拟地址</small><strong>${esc(d.address)}</strong></div>
        <div><small>系统</small><strong>${esc(d.platform)}</strong></div>
        <div><small>位置说明</small><strong>${esc(d.location||'未设置')}</strong></div>
      </div>
      <div class="round8-inline-action"><button class="secondary-btn small" data-open-tab="basic">修改名称或位置</button></div>
      <details class="round4-technical"><summary>技术详情</summary><div class="detail-grid detail-grid-six">
        <div><small>设备 ID</small><strong>${esc(d.peerId)}</strong></div><div><small>客户端版本</small><strong>${esc(d.version)}</strong></div>
        <div><small>连接方式</small><strong>${esc(d.route)}</strong></div><div><small>设备凭据</small><strong>${esc(d.credential)}</strong></div>
      </div><button class="secondary-btn small" id="copyAddressBtn">复制虚拟地址</button></details>`;
    document.getElementById('copyAddressBtn')?.addEventListener('click',()=>copyText(d.address,'设备地址已复制'));
  }else if(currentDrawerTab==='basic'){
    drawerTabContent.innerHTML=`
      <section class="drawer-section no-top round4-settings-card"><div class="drawer-section-head"><div><h3>基本信息</h3><p>这里只修改控制台里看到的名称和位置说明，不改变设备身份、虚拟地址或现有访问权限。</p></div></div>
        <label>设备名称<input id="basicDeviceName" value="${esc(currentDeviceName)}"></label>
        <label>位置说明<input id="basicDeviceLocation" value="${esc(d.location||'')}" placeholder="例如：书房、工作电脑"></label>
        <button class="primary-btn" id="saveDeviceBasicsBtn">保存基本信息</button>
      </section>`;
    document.getElementById('saveDeviceBasicsBtn')?.addEventListener('click',()=>{
      const nextName=(document.getElementById('basicDeviceName')?.value||'').trim()||currentDeviceName;
      const nextLocation=(document.getElementById('basicDeviceLocation')?.value||'').trim()||'未设置';
      d.location=nextLocation;
      if(nextName!==currentDeviceName && !devices[nextName]){
        const oldName=currentDeviceName;devices[nextName]=d;delete devices[oldName];
        Object.values(services).forEach(svc=>{if(svc.host===oldName)svc.host=nextName;});
        currentDeviceName=nextName;document.getElementById('drawerTitle').textContent=nextName;
      }
      renderDrawerSummary();toast('设备基本信息已保存（原型）');
    });
  }else if(currentDrawerTab==='network'){
    drawerTabContent.innerHTML=`
      <section class="drawer-section no-top"><div class="drawer-section-head"><div><h3>可以访问</h3><p>${d.access.length?`当前规则允许这台设备访问 ${d.access.length} 个共享。`:'当前没有允许访问的共享。'}</p></div><button class="link-btn" id="manageRulesBtn">调整访问</button></div>
        ${d.access.length?d.access.map(r=>`<div class="resource-chip"><span>${esc(r[0])}</span><b>${esc(r[1])}</b></div>`).join(''):'<div class="empty-mini">没有允许访问的资源</div>'}
      </section>
      <section class="drawer-section"><div class="drawer-section-head"><div><h3>这台设备对外共享</h3><p>别人能否使用这些共享，仍由访问规则决定。</p></div></div>
        ${d.shares.length?d.shares.map(r=>`<div class="resource-chip share"><span>${esc(r[0])}</span><b>${esc(r[1])}</b></div>`).join(''):'<div class="empty-mini">这台设备没有提供共享</div>'}
      </section>
      <div class="security-note"><span>✓</span><p><strong>默认拒绝仍然生效。</strong>设备加入网络不代表自动获得全部共享的访问权限。</p></div>`;
    document.getElementById('manageRulesBtn')?.addEventListener('click',()=>{const name=currentDeviceName;closeDrawer();showRoute('policy',{type:'device',name})});
  }else if(currentDrawerTab==='maintenance'){
    drawerTabContent.innerHTML=`
      <div class="subtle-note round4-maintenance-intro"><strong>正常设备通常不需要日常维护</strong><p>只有设备身份即将到期、设备准备退出网络或排查身份问题时才需要这里。</p></div>
      <section class="credential-card">
        <div class="credential-head"><span class="credential-icon">✓</span><div><strong>设备身份有效</strong><p>${esc(currentDeviceName)} 当前可以正常证明自己的身份。</p></div><span class="status-pill good">正常</span></div>
        <div class="credential-facts"><div><small>有效期至</small><strong>${esc(d.credentialExpiry)}</strong></div></div>
        <details class="round4-technical"><summary>凭据技术信息</summary><div class="detail-grid"><div><small>凭据序列</small><strong>${esc(d.credentialSerial)}</strong></div></div></details>
      </section>
      <section class="drawer-section"><h3>设备身份维护</h3><div class="credential-actions"><button class="secondary-btn" id="rotateCredentialBtn">请求设备更新身份</button><button class="danger-outline-btn" id="revokeCredentialBtn">撤销设备凭据</button></div><p class="field-help spaced">更新请求由在线设备自行完成；撤销会让设备失去身份，需要重新加入网络。</p></section>
      <details class="drawer-section round8-activity"><summary><strong>查看设备操作记录</strong></summary><div class="activity-stream">${d.activity.map((a,i)=>`<div class="activity-row"><span class="activity-dot ${i===0?'active':''}"></span><time>${esc(a[0])}</time><div><strong>${esc(a[1])}</strong><small>${esc(currentDeviceName)}</small></div></div>`).join('')}</div></details>
      <section class="drawer-section round4-danger-zone"><h3>停用设备</h3><p>设备不再使用当前网络时再执行。操作记录和设备信息仍会保留。</p><button class="danger-outline-btn" id="disableDeviceInMaintenanceBtn">停用这台设备</button></section>`;
    document.getElementById('rotateCredentialBtn')?.addEventListener('click',()=>toast('原型：已请求设备自行更新身份'));
    document.getElementById('revokeCredentialBtn')?.addEventListener('click',()=>toast('原型：撤销属于高风险操作，正式版需要二次确认'));
    document.getElementById('disableDeviceInMaintenanceBtn')?.addEventListener('click',()=>document.getElementById('disableDeviceBtn')?.click());
  }else{
    currentDrawerTab='overview';renderDrawerTab();return;
  }
  drawerTabContent.querySelectorAll('[data-open-tab]').forEach(b=>b.addEventListener('click',()=>{currentDrawerTab=b.dataset.openTab;renderDrawerTab()}));
}

function openDrawer(name,tab='overview'){
  if(!devices[name]) return;
  currentDeviceName=name;currentDrawerTab=tab;
  document.getElementById('drawerTitle').textContent=name;
  renderDrawerSummary();renderDrawerTab();
  drawer.classList.add('open');drawer.setAttribute('aria-hidden','false');drawerBg.hidden=false;
}
function closeDrawer(){drawer.classList.remove('open');drawer.setAttribute('aria-hidden','true');drawerBg.hidden=true;}

document.getElementById('drawerTabs').addEventListener('click',e=>{
  const btn=e.target.closest('[data-drawer-tab]');if(!btn)return;currentDrawerTab=btn.dataset.drawerTab;renderDrawerTab();
});
document.querySelector('.device-table').addEventListener('click',e=>{
  const row=e.target.closest('.device-row');if(!row)return;
  if(!e.target.closest('.row-more'))row.focus();
  openDrawer(row.dataset.device);
});
document.querySelector('.device-table').addEventListener('keydown',e=>{
  const row=e.target.closest('.device-row');if(!row || e.target.closest('.row-more') || !['Enter',' '].includes(e.key))return;
  e.preventDefault();row.focus();openDrawer(row.dataset.device);
});
document.getElementById('closeDrawer').addEventListener('click',closeDrawer);
drawerBg.addEventListener('click',closeDrawer);
document.getElementById('editDeviceBtn').addEventListener('click',()=>toast('原型：打开设备名称、用途与分组编辑'));
document.getElementById('disableDeviceBtn').addEventListener('click',()=>toast('原型：停用设备前会要求二次确认'));

/* ---------------- Shared services & unified access drawer ---------------- */
const services = {
  '家庭 NAS 文件服务':{
    icon:'N',iconClass:'',host:'家用 NAS',hostAddress:'10.18.0.30',protocol:'TCP',port:'445',dns:'nas.home',status:'healthy',lastCheck:'2 分钟前',
    scopes:[
      {name:'家庭成员',kind:'设备组',count:3,rule:'规则 #1'},
      {name:'办公笔记本',kind:'单台设备',count:1,rule:'规则 #6'}
    ],
    activity:[
      {time:'2 分钟前',result:'allow',device:'办公笔记本',detail:'成功访问 · TCP 445'},
      {time:'20 分钟前',result:'allow',device:'Android 手机',detail:'成功访问 · TCP 445'},
      {time:'昨天 22:14',result:'deny',device:'测试主机',detail:'被访问规则阻止'}
    ]
  },
  '家庭 Dashboard':{
    icon:'W',iconClass:'purple',host:'家用 NAS',hostAddress:'10.18.0.30',protocol:'HTTPS',port:'443',dns:'dashboard.home',status:'healthy',lastCheck:'5 分钟前',
    scopes:[{name:'所有受管设备',kind:'设备组',count:2,rule:'规则 #2'}],
    activity:[
      {time:'8 分钟前',result:'allow',device:'办公笔记本',detail:'成功访问 · HTTPS 443'},
      {time:'29 分钟前',result:'allow',device:'Android 手机',detail:'成功访问 · HTTPS 443'}
    ]
  },
  '开发环境 SSH':{
    icon:'D',iconClass:'green',host:'开发服务器',hostAddress:'10.18.0.40',protocol:'TCP',port:'22',dns:'',status:'healthy',lastCheck:'7 分钟前',
    scopes:[{name:'开发设备',kind:'设备组',count:2,rule:'规则 #3'}],
    activity:[
      {time:'42 分钟前',result:'allow',device:'办公笔记本',detail:'成功访问 · TCP 22'},
      {time:'2 小时前',result:'deny',device:'Android 手机',detail:'不在“开发设备”访问范围内'}
    ]
  }
};

const serviceList=document.getElementById('serviceList');
const serviceDrawer=document.getElementById('serviceDrawer');
const serviceDrawerBg=document.getElementById('serviceDrawerBackdrop');
const serviceDrawerSummary=document.getElementById('serviceDrawerSummary');
const serviceDrawerTabContent=document.getElementById('serviceDrawerTabContent');
let currentServiceName='家庭 NAS 文件服务';
let currentServiceTab='overview';

function serviceEndpoint(svc){
  if(svc.protocol==='HTTPS') return `https://${svc.dns||svc.hostAddress}${svc.port==='443'?'':':'+svc.port}`;
  if(svc.protocol==='HTTP') return `http://${svc.dns||svc.hostAddress}${svc.port==='80'?'':':'+svc.port}`;
  return `${svc.dns||svc.hostAddress}:${svc.port}`;
}
function serviceStatusPill(svc){
  if(svc.status==='healthy') return '<span class="status-pill good">● 可用</span>';
  if(svc.status==='paused') return '<span class="status-pill neutral">Ⅱ 已暂停</span>';
  return '<span class="status-pill warn">! 需检查</span>';
}
function serviceScopeTags(svc){
  if(!svc.scopes.length) return '<span class="tag muted-tag">当前无人可访问</span>';
  return svc.scopes.slice(0,3).map(x=>`<span class="tag">${esc(x.name)}</span>`).join('') + (svc.scopes.length>3?`<span class="tag">+${svc.scopes.length-3}</span>`:'');
}
function renderServices(filter=''){
  if(!serviceList) return;
  const query=filter.trim().toLowerCase();
  const entries=Object.entries(services).filter(([name,svc])=>!query || [name,svc.host,svc.dns,svc.protocol,svc.port].join(' ').toLowerCase().includes(query));
  serviceList.innerHTML=entries.length?entries.map(([name,svc])=>`
    <article class="service-card service-card-v4" data-service="${esc(name)}" tabindex="0">
      <div class="service-icon ${esc(svc.iconClass)}">${esc(svc.icon)}</div>
      <div class="service-info">
        <div class="service-title-line"><strong>${esc(name)}</strong>${svc.status==='paused'?'<span class="tiny-state">已暂停</span>':''}</div>
        <p>${esc(svc.host)} · ${esc(svc.protocol)} ${esc(svc.port)}${svc.dns?' · '+esc(svc.dns):''}</p>
        <div class="service-tags">${serviceScopeTags(svc)}</div>
      </div>
      <div class="service-endpoint"><small>访问地址</small><code>${esc(serviceEndpoint(svc))}</code></div>
      <div class="service-state">${serviceStatusPill(svc)}<small>${esc(svc.lastCheck)}验证</small></div>
      <button class="secondary-btn small service-manage-btn" data-manage-service="${esc(name)}">查看详情</button>
    </article>`).join(''):'<div class="empty-list-state"><strong>没有找到共享</strong><p>换一个关键词，或新建一个共享服务。</p></div>';
  const count=Object.keys(services).length;
  const healthy=Object.values(services).filter(x=>x.status==='healthy').length;
  const set=(id,value)=>{const el=document.getElementById(id);if(el)el.textContent=String(value);};
  set('shareListCount',count);set('shareStatCount',count);set('shareStatHealthy',healthy);
  const navBadge=document.querySelector('.nav-item[data-route="sharing"] .badge');if(navBadge)navBadge.textContent=String(count);
}

function renderServiceSummary(){
  const svc=services[currentServiceName];if(!svc)return;
  serviceDrawerSummary.innerHTML=`
    <div class="service-hero">
      <div class="service-big-icon ${esc(svc.iconClass)}">${esc(svc.icon)}</div>
      <div class="service-hero-copy">${serviceStatusPill(svc)}<p>${esc(svc.host)} · ${esc(svc.protocol)} ${esc(svc.port)}${svc.dns?' · '+esc(svc.dns):''}</p></div>
      <button class="secondary-btn small" id="testServiceBtn">测试共享</button>
    </div>
    <div class="service-health ${svc.status==='healthy'?'healthy':svc.status==='paused'?'paused':'warning'}">
      <span>${svc.status==='healthy'?'✓':svc.status==='paused'?'Ⅱ':'!'}</span>
      <div><strong>${svc.status==='healthy'?'共享工作正常':svc.status==='paused'?'共享已暂停':'共享需要检查'}</strong><p>${svc.status==='healthy'?`最近一次健康检查：${esc(svc.lastCheck)}。当前有 ${svc.scopes.length} 个访问范围。`:svc.status==='paused'?'服务定义仍保留，但所有访问会被临时阻止。':'请检查服务所在设备和端口是否可用。'}</p></div>
    </div>`;
  document.getElementById('testServiceBtn')?.addEventListener('click',()=>{
    if(svc.status==='paused') toast('共享已暂停，请先恢复后再测试');
    else {svc.lastCheck='刚刚';toast('共享测试成功 · 服务可达');renderServiceSummary();renderServices(document.getElementById('shareSearchInput')?.value||'');}
  });
}

function accessCountLabel(scope){
  if(scope.kind==='单台设备') return '1 台设备';
  return `${scope.count} 台设备`;
}
function renderServiceTab(){
  const svc=services[currentServiceName];if(!svc)return;
  const pathTab=document.querySelector('#serviceDrawerTabs [data-service-tab="path"]');if(pathTab)pathTab.hidden=true;
  if(currentServiceTab==='path')currentServiceTab='overview';
  document.querySelectorAll('#serviceDrawerTabs .drawer-tab').forEach(b=>b.classList.toggle('active',b.dataset.serviceTab===currentServiceTab));
  if(currentServiceTab==='overview'){
    serviceDrawerTabContent.innerHTML=`
      <section class="drawer-section"><div class="drawer-section-head"><div><h3>日常操作</h3><p>状态正常时通常不需要修改资源配置。</p></div></div><div class="drawer-action-grid round4-action-grid"><button class="action-tile" id="checkServiceAccessBtn"><b>检查访问</b><small>${svc.scopes.length} 个允许范围</small></button><button class="action-tile" data-service-open-tab="settings"><b>修改设置</b><small>名称、协议、端口或暂停状态</small></button><button class="action-tile" id="openHostDeviceBtn"><b>查看提供设备</b><small>${esc(svc.host)}</small></button></div></section>
      <section class="drawer-section connection-card"><div class="drawer-section-head"><div><h3>访问地址</h3><p>地址不是密码；是否可以使用仍由访问规则决定。</p></div></div><div class="endpoint-copy-row"><code>${esc(serviceEndpoint(svc))}</code><button class="secondary-btn small" id="copyServiceEndpointBtn">复制</button></div></section>
      <details class="round4-technical"><summary>技术详情</summary><div class="detail-grid detail-grid-six"><div><small>提供设备地址</small><strong>${esc(svc.hostAddress)}</strong></div><div><small>协议</small><strong>${esc(svc.protocol)}</strong></div><div><small>端口</small><strong>${esc(svc.port)}</strong></div><div><small>DNS</small><strong>${esc(svc.dns||'未设置')}</strong></div></div></details>`;
    document.getElementById('copyServiceEndpointBtn')?.addEventListener('click',()=>copyText(serviceEndpoint(svc),'共享访问地址已复制'));
    document.getElementById('checkServiceAccessBtn')?.addEventListener('click',()=>{const name=currentServiceName;closeServiceDrawer();showRoute('policy',{type:'share',name})});
    document.getElementById('openHostDeviceBtn')?.addEventListener('click',()=>{closeServiceDrawer();openDrawer(svc.host,'overview')});
  }else if(currentServiceTab==='settings'){
    serviceDrawerTabContent.innerHTML=`
      <section class="drawer-section no-top round4-settings-card"><div class="drawer-section-head"><div><h3>常用设置</h3><p>只调整共享本身，不会自动改变谁能访问。</p></div></div>
        <label>协议<select id="round4ServiceProtocol"><option ${svc.protocol==='TCP'?'selected':''}>TCP</option><option ${svc.protocol==='UDP'?'selected':''}>UDP</option><option ${svc.protocol==='HTTP'?'selected':''}>HTTP</option><option ${svc.protocol==='HTTPS'?'selected':''}>HTTPS</option></select></label>
        <label>端口<input id="round4ServicePort" value="${esc(svc.port)}"></label>
        <details class="round4-inline-advanced"><summary>更多设置</summary><label>DNS 名称（可选）<input id="round4ServiceDns" value="${esc(svc.dns||'')}"></label></details>
        <button class="primary-btn" id="saveRound4ServiceSettings">保存设置</button>
      </section>
      <section class="drawer-section round4-danger-zone"><h3>${svc.status==='paused'?'恢复共享':'暂停共享'}</h3><p>${svc.status==='paused'?'恢复后，已有访问规则会继续生效。':'暂停会立即阻止使用，但保留共享设置和已有访问规则。'}</p><button class="${svc.status==='paused'?'secondary-btn':'danger-outline-btn'}" id="pauseResourceInSettingsBtn">${svc.status==='paused'?'恢复共享':'暂停共享'}</button></section>`;
    document.getElementById('saveRound4ServiceSettings')?.addEventListener('click',()=>{svc.protocol=document.getElementById('round4ServiceProtocol')?.value||svc.protocol;svc.port=(document.getElementById('round4ServicePort')?.value||svc.port).trim();svc.dns=(document.getElementById('round4ServiceDns')?.value||svc.dns||'').trim();renderServiceSummary();renderServices(field('shareSearchInput'));toast('共享设置已保存（原型）');});
    document.getElementById('pauseResourceInSettingsBtn')?.addEventListener('click',()=>document.getElementById('pauseShareBtn')?.click());
  }else{
    currentServiceTab='overview';renderServiceTab();return;
  }
  serviceDrawerTabContent.querySelectorAll('[data-service-open-tab]').forEach(b=>b.addEventListener('click',()=>{currentServiceTab=b.dataset.serviceOpenTab;renderServiceTab();}));
}

function openServiceDrawer(name,tab='overview'){
  if(!services[name])return;
  currentServiceName=name;currentServiceTab=tab;
  document.getElementById('serviceDrawerTitle').textContent=name;
  renderServiceSummary();renderServiceTab();
  serviceDrawer.classList.add('open');serviceDrawer.setAttribute('aria-hidden','false');serviceDrawerBg.hidden=false;
  const pauseBtn=document.getElementById('pauseShareBtn');pauseBtn.textContent=services[name].status==='paused'?'恢复共享':'暂停共享';
}
function closeServiceDrawer(){serviceDrawer.classList.remove('open');serviceDrawer.setAttribute('aria-hidden','true');serviceDrawerBg.hidden=true;}

document.getElementById('serviceDrawerTabs')?.addEventListener('click',e=>{const btn=e.target.closest('[data-service-tab]');if(!btn)return;currentServiceTab=btn.dataset.serviceTab;renderServiceTab();});
document.getElementById('closeServiceDrawer')?.addEventListener('click',closeServiceDrawer);
serviceDrawerBg?.addEventListener('click',closeServiceDrawer);
serviceList?.addEventListener('click',e=>{const card=e.target.closest('[data-service]');if(!card)return;openServiceDrawer(card.dataset.service);});
serviceList?.addEventListener('keydown',e=>{if((e.key==='Enter'||e.key===' ')&&e.target.closest('[data-service]')){e.preventDefault();openServiceDrawer(e.target.closest('[data-service]').dataset.service);}});
document.getElementById('editShareBtn')?.addEventListener('click',()=>toast('原型：打开共享名称、路径与目标编辑'));
document.getElementById('pauseShareBtn')?.addEventListener('click',()=>{
  const svc=services[currentServiceName];if(!svc)return;svc.status=svc.status==='paused'?'healthy':'paused';toast(svc.status==='paused'?'共享已暂停':'共享已恢复');openServiceDrawer(currentServiceName,currentServiceTab);renderServices(document.getElementById('shareSearchInput')?.value||'');
});
document.getElementById('shareSearchInput')?.addEventListener('input',e=>renderServices(e.target.value));
document.getElementById('refreshShareStatusBtn')?.addEventListener('click',()=>{Object.values(services).forEach(svc=>{if(svc.status==='healthy')svc.lastCheck='刚刚'});renderServices(document.getElementById('shareSearchInput')?.value||'');toast('共享状态已刷新');});
document.getElementById('testAllSharesBtn')?.addEventListener('click',()=>{Object.values(services).forEach(svc=>{if(svc.status==='healthy')svc.lastCheck='刚刚'});renderServices(document.getElementById('shareSearchInput')?.value||'');toast('检查完成：所有启用的共享连接可达');});
document.getElementById('openPolicyFromSharing')?.addEventListener('click',()=>showRoute('policy'));
renderServices();

/* ---------------- v5: permission matrix, plain-language explanations & simulator ---------------- */
let policyView='devices';
let selectedPolicyCell=null;
let policySelectedSource='';

function groupMembers(groupName){
  return Object.entries(devices).filter(([name,d])=>{
    if(groupName==='所有受管设备') return d.groups?.includes('受管设备') || d.groups?.includes(groupName);
    if(groupName==='指定设备') return ['办公笔记本'].includes(name);
    return d.groups?.includes(groupName);
  }).map(([name])=>name);
}
function policyGroupNames(){
  const names=new Set(['家庭成员','所有受管设备','开发设备']);
  Object.values(services).forEach(svc=>svc.scopes.forEach(scope=>{if(!devices[scope.name]) names.add(scope.name)}));
  return [...names].filter(name=>groupMembers(name).length || Object.values(services).some(s=>s.scopes.some(x=>x.name===name)));
}
function policySubjects(view=policyView){
  if(view==='groups') return policyGroupNames().map(name=>({name,kind:'设备组',members:groupMembers(name)}));
  return Object.entries(devices).map(([name,d])=>({name,kind:'设备',device:d}));
}
function renderPolicySourcePicker(){
  const picker=document.getElementById('policySourcePicker');if(!picker)return;
  const deviceOptions=Object.keys(devices).map(name=>`<option value="${esc(name)}">设备 · ${esc(name)}</option>`).join('');
  const groupOptions=policyGroupNames().map(name=>`<option value="${esc(name)}">设备组 · ${esc(name)}</option>`).join('');
  const preferred=window.__policyContextSource||policySelectedSource;
  picker.innerHTML=`<option value="">选择设备或设备组…</option>${deviceOptions}${groupOptions}`;
  if(preferred && [...picker.options].some(o=>o.value===preferred)){policySelectedSource=preferred;picker.value=preferred;}
  else if(policySelectedSource && ![...picker.options].some(o=>o.value===policySelectedSource)){policySelectedSource='';}
}
function matchingScopeForDevice(deviceName,svc){
  const exact=svc.scopes.find(scope=>scope.name===deviceName);
  if(exact) return {scope:exact,inherited:false};
  const d=devices[deviceName];
  if(!d) return null;
  const inherited=svc.scopes.find(scope=>!devices[scope.name] && groupMembers(scope.name).includes(deviceName));
  return inherited?{scope:inherited,inherited:true}:null;
}
function evaluateAccess(source,target){
  const svc=services[target];
  const d=devices[source];
  if(!svc) return {policyAllowed:false,effectiveNow:false,reason:'共享不存在',match:null};
  let match=null;
  if(d) match=matchingScopeForDevice(source,svc);
  else {
    const exact=svc.scopes.find(scope=>scope.name===source);
    if(exact) match={scope:exact,inherited:false};
  }
  const policyAllowed=!!match;
  const sourceOnline=d?d.status==='online':true;
  const serviceReady=svc.status==='healthy';
  const effectiveNow=policyAllowed && sourceOnline && serviceReady;
  let currentIssue='';
  if(policyAllowed && !sourceOnline) currentIssue='设备当前离线';
  else if(policyAllowed && !serviceReady) currentIssue=svc.status==='paused'?'资源当前已暂停':'资源当前不可达';
  return {policyAllowed,effectiveNow,sourceOnline,serviceReady,currentIssue,match,svc,device:d};
}
function matrixCellState(result){
  if(result.policyAllowed && !result.effectiveNow) return 'attention';
  return result.policyAllowed?'allow':'deny';
}
function matrixCellLabel(result){
  if(result.policyAllowed && !result.effectiveNow) return '!';
  return result.policyAllowed?'✓':'–';
}
function scopeRuleLabel(match){
  if(!match) return '没有匹配到允许规则';
  const rule=match.scope.rule||'允许规则';
  return match.inherited?`${rule} · 继承自“${match.scope.name}”`:`${rule} · 直接授权`;
}
function countGrantRelationships(){
  return Object.values(services).reduce((n,svc)=>n+svc.scopes.length,0);
}
function subjectMeta(subject){
  if(subject.kind==='设备组'){
    const offline=subject.members.filter(name=>devices[name]?.status!=='online').length;
    return `${subject.members.length} 台设备${offline?` · ${offline} 台离线`:''}`;
  }
  const d=subject.device;
  return `${d.platform} · ${d.status==='online'?'在线':'离线'}`;
}
function renderPermissionMatrix(){
  const wrap=document.getElementById('permissionMatrix');if(!wrap)return;
  if(!policySelectedSource){wrap.innerHTML='<div class="policy-detail-empty round8-source-empty"><span>↑</span><strong>先选择访问来源</strong><p>选中一台设备或设备组后，这里只显示它对共享的最终访问结果。</p></div>';return;}
  const all=[...policySubjects('devices'),...policySubjects('groups')];
  const subjects=all.filter(subject=>subject.name===policySelectedSource);
  const targets=Object.keys(services);
  const header=targets.map(name=>{const svc=services[name];return `<div class="matrix-service-head"><strong>${esc(name)}</strong><small>${esc(svc.protocol)} ${esc(svc.port)}</small></div>`}).join('');
  const rows=subjects.map(subject=>{
    const cells=targets.map(target=>{
      const result=evaluateAccess(subject.name,target);const state=matrixCellState(result);
      const selected=selectedPolicyCell?.source===subject.name&&selectedPolicyCell?.target===target;
      const title=result.policyAllowed?(result.effectiveNow?'允许访问':`权限允许，但${result.currentIssue}`):'未授权，默认阻止';
      return `<button class="matrix-cell ${state}${selected?' selected':''}" data-policy-source="${esc(subject.name)}" data-policy-target="${esc(target)}" title="${esc(title)}" aria-label="${esc(subject.name)} 到 ${esc(target)}：${esc(title)}"><span>${matrixCellLabel(result)}</span><small>${state==='allow'?'允许':state==='attention'?'需注意':'阻止'}</small></button>`;
    }).join('');
    const statusClass=subject.kind==='设备'&&subject.device.status!=='online'?' offline':'';
    return `<div class="matrix-row"><div class="matrix-subject${statusClass}"><span class="subject-kind">${subject.kind==='设备组'?'组':'设备'}</span><strong>${esc(subject.name)}</strong><small>${esc(subjectMeta(subject))}</small></div>${cells}</div>`;
  }).join('');
  wrap.innerHTML=`<div class="permission-matrix" style="--service-count:${Math.max(targets.length,1)}"><div class="matrix-row matrix-header"><div class="matrix-corner"><strong>当前来源</strong><small>点击结果查看原因</small></div>${header}</div>${rows}</div>`;
}
function renderAdvancedRules(){
  const el=document.getElementById('advancedRuleList');if(!el)return;
  const rules=[];
  Object.entries(services).forEach(([target,svc])=>svc.scopes.forEach(scope=>rules.push({source:scope.name,target,svc,scope})));
  el.innerHTML=rules.length?rules.map((r,i)=>{
    const members=devices[r.source]?[r.source]:groupMembers(r.source);
    const offline=members.filter(name=>devices[name]?.status!=='online').length;
    return `<article class="rule-card ${offline?'attention':''}" data-advanced-rule-source="${esc(r.source)}" data-advanced-rule-target="${esc(r.target)}"><div class="rule-num">${i+1}</div><div class="rule-body"><strong>${esc(r.source)} → ${esc(r.target)}</strong><p><span>${esc(r.source)}</span><b>可以访问</b><span>${esc(r.target)}</span></p><small>${esc(r.svc.protocol)} ${esc(r.svc.port)} · ${esc(r.scope.rule||'允许规则')}${offline?` · ${offline} 台相关设备离线`:''}</small></div><span class="status-pill ${offline?'warn':'good'}">${offline?'需注意':'启用'}</span><button class="row-more" aria-label="查看此规则">›</button></article>`;
  }).join(''):'<div class="empty-mini">当前没有允许规则，所有访问都会被默认拒绝。</div>';
}
function renderPolicySummary(){
  const grants=countGrantRelationships();
  const g=document.getElementById('policyGrantCount');if(g)g.textContent=String(grants);
  const svc=document.getElementById('policyServiceCount');if(svc)svc.textContent=String(Object.keys(services).length);
  const dash=document.getElementById('dashboardGrantCount');if(dash)dash.textContent=String(grants);
}
function renderPolicyDetail(source,target){
  const el=document.getElementById('policyDetail');const ctx=document.getElementById('policyDetailContext');if(!el||!ctx)return;
  selectedPolicyCell={source,target};
  const result=evaluateAccess(source,target);const svc=services[target];const isDevice=!!devices[source];
  const state=result.policyAllowed?(result.effectiveNow?'allow':'attention'):'deny';
  const title=state==='allow'?'当前可以访问':state==='attention'?'权限允许，但当前无法连接':'当前会被阻止';
  let sentence='';
  if(result.policyAllowed){
    if(result.match.inherited) sentence=`“${source}”属于“${result.match.scope.name}”，该设备组已被允许访问“${target}”。`;
    else sentence=`“${source}”已经被直接允许访问“${target}”。`;
  }else sentence=`没有任何允许规则覆盖“${source} → ${target}”，因此 Peerward 会执行默认拒绝。`;
  ctx.textContent=`${source} → ${target}`;
  el.className='policy-detail-content';
  el.innerHTML=`
    <div class="policy-result-banner ${state}"><span>${state==='allow'?'✓':state==='attention'?'!':'×'}</span><div><strong>${title}</strong><p>${esc(sentence)}</p></div></div>
    <div class="policy-fact-grid">
      <div><small>访问来源</small><strong>${esc(source)}</strong><span>${isDevice?esc(`${devices[source].platform} · ${devices[source].status==='online'?'在线':'离线'}`):esc(`${groupMembers(source).length} 台设备`)}</span></div>
      <div><small>目标共享</small><strong>${esc(target)}</strong><span>${esc(`${svc.protocol} ${svc.port} · ${svc.status==='healthy'?'可用':svc.status==='paused'?'已暂停':'需检查'}`)}</span></div>
      <div><small>命中规则</small><strong>${esc(scopeRuleLabel(result.match))}</strong><span>${result.match?.inherited?'设备组授权会自动应用到组内设备':'直接针对当前来源'}</span></div>
      <div><small>访问地址</small><strong class="mono-strong">${esc(serviceEndpoint(svc))}</strong><span>地址本身不是密码</span></div>
    </div>
    ${result.currentIssue?`<div class="policy-inline-warning"><span>!</span><p><strong>权限配置没有问题，但当前连接仍会失败。</strong>${esc(result.currentIssue)}。恢复设备或共享后，无需重新授权。</p></div>`:''}
    <div class="policy-detail-actions">
      <button class="secondary-btn" id="detailSimulateBtn">用模拟器检查</button>
      ${result.policyAllowed?(result.match?.inherited?`<button class="primary-btn" id="detailOpenSourceRuleBtn">管理“${esc(result.match.scope.name)}”授权</button>`:`<button class="danger-outline-btn" id="detailRevokeBtn">撤销此授权</button>`):`<button class="primary-btn" id="detailAllowBtn">允许访问</button>`}
    </div>`;
  renderPermissionMatrix();
  document.getElementById('detailSimulateBtn')?.addEventListener('click',()=>{
    const ss=document.getElementById('simSource'),st=document.getElementById('simTarget');if(ss&&[...ss.options].some(o=>o.value===source))ss.value=source;if(st)st.value=target;runSimulation();document.getElementById('policySimulatorPanel')?.scrollIntoView({behavior:'smooth',block:'center'});
  });
  document.getElementById('detailAllowBtn')?.addEventListener('click',()=>openModal('rule',{source,target}));
  document.getElementById('detailOpenSourceRuleBtn')?.addEventListener('click',()=>openServiceDrawer(target,'overview'));
  document.getElementById('detailRevokeBtn')?.addEventListener('click',()=>{
    const idx=svc.scopes.findIndex(scope=>scope.name===source);if(idx<0)return;svc.scopes.splice(idx,1);toast(`已撤销“${source}”访问“${target}”的权限`);selectedPolicyCell=null;renderPolicyUI();renderPolicyDetail(source,target);renderServices(document.getElementById('shareSearchInput')?.value||'');
  });
}
function fillSimulatorOptions(){
  const source=document.getElementById('simSource'),target=document.getElementById('simTarget');if(!source||!target)return;
  const oldSource=source.value||'Android 手机',oldTarget=target.value||'开发环境 SSH';
  source.innerHTML=`<optgroup label="设备">${Object.keys(devices).map(name=>`<option value="${esc(name)}">${esc(name)}</option>`).join('')}</optgroup><optgroup label="设备组">${policyGroupNames().map(name=>`<option value="${esc(name)}">${esc(name)}（组）</option>`).join('')}</optgroup>`;
  target.innerHTML=Object.keys(services).map(name=>`<option value="${esc(name)}">${esc(name)}</option>`).join('');
  if([...source.options].some(o=>o.value===oldSource))source.value=oldSource;else if([...source.options].some(o=>o.value==='Android 手机'))source.value='Android 手机';
  if([...target.options].some(o=>o.value===oldTarget))target.value=oldTarget;else target.selectedIndex=0;
}
function runSimulation(){
  const source=document.getElementById('simSource')?.value,target=document.getElementById('simTarget')?.value,out=document.getElementById('simulationResult');if(!source||!target||!out)return;
  const result=evaluateAccess(source,target);const svc=services[target];
  const state=result.policyAllowed?(result.effectiveNow?'allow':'attention'):'deny';
  const heading=state==='allow'?'模拟结果：允许访问':state==='attention'?'模拟结果：权限允许，但当前不可连接':'模拟结果：访问会被阻止';
  const step1=devices[source]?`设备状态：${devices[source].status==='online'?'在线':'离线'}`:`设备组：${groupMembers(source).length} 台设备`;
  const step2=result.match?`权限规则：${scopeRuleLabel(result.match)}`:'权限规则：没有匹配的允许规则';
  const step3=`共享状态：${svc.status==='healthy'?'可用':svc.status==='paused'?'已暂停':'需检查'} · ${svc.protocol} ${svc.port}`;
  out.className=`simulation-result ${state}`;
  out.innerHTML=`<span class="sim-result-icon">${state==='allow'?'✓':state==='attention'?'!':'×'}</span><div class="sim-result-copy"><strong>${heading}</strong><p>${state==='allow'?`“${esc(source)}”现在可以连接“${esc(target)}”。`:state==='attention'?`访问规则允许，但${esc(result.currentIssue)}。`:`没有允许规则，因此默认拒绝。`}</p><ol><li>${esc(step1)}</li><li>${esc(step2)}</li><li>${esc(step3)}</li></ol></div><button class="link-btn" id="simulationExplainBtn">查看权限说明</button>`;
  document.getElementById('simulationExplainBtn')?.addEventListener('click',()=>{renderPolicyDetail(source,target);document.getElementById('policyDetailPanel')?.scrollIntoView({behavior:'smooth',block:'center'});});
}
function renderPolicyUI(){
  renderPolicySummary();renderPolicySourcePicker();renderPermissionMatrix();renderAdvancedRules();fillSimulatorOptions();
  document.querySelectorAll('#policyViewSwitch [data-policy-view]').forEach(btn=>btn.classList.toggle('active',btn.dataset.policyView===policyView));
}

document.getElementById('policyViewSwitch')?.addEventListener('click',e=>{const btn=e.target.closest('[data-policy-view]');if(!btn)return;policyView=btn.dataset.policyView;selectedPolicyCell=null;renderPermissionMatrix();document.getElementById('policyDetailContext').textContent='尚未选择';document.getElementById('policyDetail').className='policy-detail-empty';document.getElementById('policyDetail').innerHTML='<span>↖</span><strong>点击权限矩阵中的任意格子</strong><p>你会看到“为什么允许 / 为什么阻止”、命中的规则以及可以采取的操作。</p>';document.querySelectorAll('#policyViewSwitch [data-policy-view]').forEach(b=>b.classList.toggle('active',b===btn));});
document.getElementById('policySourcePicker')?.addEventListener('change',e=>{policySelectedSource=e.target.value;window.__policyContextSource=policySelectedSource;selectedPolicyCell=null;renderPermissionMatrix();const ctx=document.getElementById('policyDetailContext'),detail=document.getElementById('policyDetail');if(ctx)ctx.textContent='尚未选择';if(detail){detail.className='policy-detail-empty';detail.innerHTML='<span>↖</span><strong>选择一个访问结果</strong><p>这里会显示最终决定、命中的授权和当前路径状态。</p>';}});
document.getElementById('permissionMatrix')?.addEventListener('click',e=>{const cell=e.target.closest('[data-policy-source][data-policy-target]');if(!cell)return;renderPolicyDetail(cell.dataset.policySource,cell.dataset.policyTarget);document.getElementById('policyDetailPanel')?.scrollIntoView({behavior:'smooth',block:'nearest'});});
document.getElementById('advancedRuleList')?.addEventListener('click',e=>{const card=e.target.closest('[data-advanced-rule-source]');if(!card)return;renderPolicyDetail(card.dataset.advancedRuleSource,card.dataset.advancedRuleTarget);document.getElementById('advancedPolicyDetails').open=false;document.getElementById('policyDetailPanel')?.scrollIntoView({behavior:'smooth',block:'center'});});
document.getElementById('runSimulationBtn')?.addEventListener('click',runSimulation);
document.getElementById('simulateBtn')?.addEventListener('click',()=>{document.getElementById('policySimulatorPanel')?.scrollIntoView({behavior:'smooth',block:'center'});document.getElementById('simSource')?.focus();});
renderPolicyUI();

/* ---------------- Guided wizards ---------------- */
const modal=document.getElementById('modalBackdrop');
const modalTitle=document.getElementById('modalTitle');
const modalBody=document.getElementById('modalBody');
const modalNext=document.getElementById('modalNext');
const modalBack=document.getElementById('modalBack');
const modalStepper=document.getElementById('modalStepper');
let modalType='device';
let modalStep=1;
let wizardState={};

const wizardConfig={
  device:{title:'添加设备',steps:['设备信息','接入方式','等待上线','完成']},
  share:{title:'新建共享',steps:['共享内容','谁可以访问','确认创建']},
  rule:{title:'添加访问权限',steps:['选择设备或组','选择共享','确认授权']}
};

function syncStepper(){
  const cfg=wizardConfig[modalType];
  modalStepper.style.setProperty('--step-count',cfg.steps.length);
  modalStepper.innerHTML=cfg.steps.map((label,i)=>`<div class="step ${i===modalStep-1?'active':''} ${i<modalStep-1?'done':''}"><span>${i+1}</span><strong>${esc(label)}</strong></div>`).join('');
  modalBack.hidden=modalStep===1;
}
function joinTicket(){return wizardState.ticket||'pw_join_7G2k9mQ4_xY8pL2';}
function joinCommand(){return `peerward join --control https://control.peerward.local --ticket ${joinTicket()}`;}
function joinConfig(){return `# Peerward device join configuration\ncontrol = "https://control.peerward.local"\njoin_ticket = "${joinTicket()}"\ndevice_name = "${wizardState.name||'new-device'}"\n`;}

function attachDeviceStepEvents(){
  modalBody.querySelectorAll('[data-method]').forEach(btn=>btn.addEventListener('click',()=>{
    wizardState.ttl=field('joinTtl')||wizardState.ttl||'15 分钟';wizardState.connectMethod=btn.dataset.method;renderDeviceStep();
  }));
  document.getElementById('copyJoinCommand')?.addEventListener('click',()=>copyText(joinCommand(),'接入命令已复制'));
  document.getElementById('copyJoinTicket')?.addEventListener('click',()=>copyText(joinTicket(),'加入凭据已复制'));
  document.getElementById('downloadJoinConfig')?.addEventListener('click',()=>downloadText('peerward-join.conf',joinConfig()));
  document.getElementById('showSecurityExplain')?.addEventListener('click',()=>toast('加入凭据只用于首次接入；设备上线后会自动换成设备凭据'));
}

function renderEnrollmentGroupAccess(){
  const target=document.getElementById('enrollmentGroupAccess');if(!target)return;
  const groups=wizardState.groups||[];
  if(!groups.length){target.innerHTML='<p class="field-help">默认不分组，加入后仍可修改。</p>';return;}
  target.innerHTML=`<div class="enrollment-group-access"><strong>所选组的当前授权</strong>${groups.map(name=>{
    const grants=Object.entries(services).filter(([,svc])=>svc.scopes.some(scope=>scope.name===name));
    return `<div><b>${esc(name)}</b>${grants.length?`<ul>${grants.map(([title,svc])=>`<li>${esc(title)} · ${esc(svc.protocol||'按访问规则')}${svc.port?' '+esc(svc.port):''}</li>`).join('')}</ul>`:'<p>该组暂无已启用的共享授权。</p>'}</div>`;
  }).join('')}<p class="field-help">入网成功后自动加入所选组，并适用届时的访问规则。这里展示现有允许规则，实际访问仍受附加条件、拒绝规则和共享状态限制。</p></div>`;
}

function renderDeviceStep(){
  if(modalStep===1){
    modalBody.innerHTML=`
      <div class="subtle-note"><strong>先告诉 Peerward 这是什么设备</strong><p>这里只创建管理记录，不会立即改变新设备上的任何设置。</p></div>
      <label>设备名称<input id="deviceNameInput" value="${esc(wizardState.name||'')}" placeholder="例如：小明的笔记本" /></label>
      <label>设备平台<select id="devicePlatformInput"><option>Linux</option><option>Android</option></select></label>
      <fieldset class="enrollment-groups"><legend>设备组（可选，可多选）</legend>
        <div class="enrollment-group-options">${policyGroupNames().map(name=>`<label><input type="checkbox" name="device_groups" value="${esc(name)}" ${(wizardState.groups||[]).includes(name)?'checked':''}><span>${esc(name)}</span></label>`).join('')}</div>
        <div id="enrollmentGroupAccess"></div>
      </fieldset>`;
    const updateGroups=()=>{wizardState.groups=[...modalBody.querySelectorAll('[name="device_groups"]:checked')].map(el=>el.value);renderEnrollmentGroupAccess();};
    modalBody.querySelectorAll('[name="device_groups"]').forEach(el=>el.addEventListener('change',updateGroups));
    renderEnrollmentGroupAccess();
    if(wizardState.platform) document.getElementById('devicePlatformInput').value=wizardState.platform;
    modalNext.textContent='下一步';
  }else if(modalStep===2){
    wizardState.ticket=wizardState.ticket||'pw_join_7G2k9mQ4_xY8pL2';
    const method=wizardState.connectMethod||'command';
    modalBody.innerHTML=`
      <div class="success-card"><span class="success-mark">✓</span><div><strong>一次性加入凭据已准备好</strong><p>只把它用于 <b>${esc(wizardState.name||'这台设备')}</b> 的首次接入。设备成功上线后会自动获得自己的设备凭据。</p></div></div>
      <label>加入凭据有效期<select id="joinTtl"><option>15 分钟</option><option>1 小时</option><option>24 小时</option></select></label>
      <div class="method-tabs" role="tablist"><button class="method-tab ${method==='command'?'active':''}" data-method="command">复制命令</button><button class="method-tab ${method==='qr'?'active':''}" data-method="qr">扫码加入</button><button class="method-tab ${method==='manual'?'active':''}" data-method="manual">手动输入</button></div>
      ${method==='command'?`
        <div class="join-method-panel"><div class="method-title"><span>⌘</span><div><strong>在新设备的终端运行</strong><p>适合 Linux 设备。Android 建议使用扫码或手动输入。</p></div></div><pre class="command-box"><code>${esc(joinCommand())}</code></pre><div class="inline-actions method-actions"><button class="primary-btn" type="button" id="copyJoinCommand">复制命令</button><button class="secondary-btn" type="button" id="downloadJoinConfig">下载配置文件</button></div></div>`:''}
      ${method==='qr'?`
        <div class="join-method-panel qr-panel"><img src="join-qr.png" alt="设备加入二维码" width="180" height="180"><div><strong>在 Peerward 客户端中扫码</strong><p>二维码包含控制服务地址和一次性加入凭据。</p><small>适合手机或带摄像头的设备。</small></div></div>`:''}
      ${method==='manual'?`
        <div class="join-method-panel"><div class="method-title"><span>⌨</span><div><strong>手动输入加入凭据</strong><p>在新设备的 Peerward 客户端选择“加入已有网络”。</p></div></div><div class="ticket-box"><code>${esc(joinTicket())}</code><button class="secondary-btn small" id="copyJoinTicket">复制</button></div><div class="manual-facts"><div><small>控制服务</small><strong>https://control.peerward.local</strong></div><div><small>网络</small><strong>家庭网络</strong></div></div></div>`:''}
      <div class="join-security-line"><span>🔒</span><p>加入凭据不是共享密码，也不是设备日常使用的长期身份。</p><button class="link-btn" type="button" id="showSecurityExplain">了解区别</button></div>`;
    document.getElementById('joinTtl').value=wizardState.ttl||'15 分钟';
    modalNext.textContent='我已在设备上操作';attachDeviceStepEvents();
  }else if(modalStep===3){
    const online=!!wizardState.online;
    modalBody.innerHTML=`
      <div class="waiting-card ${online?'complete':''}">
        <span class="waiting-mark">${online?'✓':'↻'}</span>
        <div><strong>${online?'设备已上线':'等待 '+esc(wizardState.name||'新设备')+' 连接'}</strong><p>${online?'控制服务已经验证新设备，并签发了设备凭据。':'请在新设备上完成刚才的扫码、命令或手动输入。完成后点击“检查连接”。'}</p></div>
      </div>
      <div class="onboarding-checklist">
        <div class="check-item done"><span>✓</span><div><strong>一次性加入凭据已创建</strong><small>有效期 ${esc(wizardState.ttl||'15 分钟')}</small></div></div>
        <div class="check-item ${online?'done':'current'}"><span>${online?'✓':'2'}</span><div><strong>新设备提交自己的设备密钥</strong><small>${online?'已收到并验证':'等待设备连接'}</small></div></div>
        <div class="check-item ${online?'done':''}"><span>${online?'✓':'3'}</span><div><strong>签发设备凭据</strong><small>${online?'已完成':'上线后自动完成'}</small></div></div>
      </div>
      ${online?`<div class="confirm-card device-confirm"><div class="confirm-row"><span>设备地址</span><strong>${esc(wizardState.address||'10.18.0.72')}</strong></div><div class="confirm-row"><span>设备身份</span><strong>已签发</strong></div><div class="confirm-row"><span>设备组</span><strong>${esc((wizardState.groups||[]).join("、")||"未分组")}</strong></div></div>`:`<details class="trouble-box"><summary>设备一直没有上线？</summary><p>确认设备能访问控制服务，并检查加入凭据是否过期。加入凭据过期后只需重新生成，不影响其他设备。</p><div class="inline-actions"><button class="secondary-btn small" id="copyAgainBtn">再次复制命令</button><button class="secondary-btn small" id="downloadAgainBtn">下载配置</button></div></details>`}
      `;
    if(!online){
      document.getElementById('copyAgainBtn')?.addEventListener('click',()=>copyText(joinCommand(),'接入命令已复制'));
      document.getElementById('downloadAgainBtn')?.addEventListener('click',()=>downloadText('peerward-join.conf',joinConfig()));
    }
    modalNext.textContent=online?'下一步':'检查连接';
  }else{
    modalBody.innerHTML=`
      <div class="device-finish-hero"><span>✓</span><div><strong>${esc(wizardState.name||'新设备')} 已加入家庭网络</strong><p>以后这台设备会使用自己的设备凭据连接，不再需要刚才的一次性加入凭据。</p></div></div>
      <div class="confirm-card">
        <div class="confirm-row"><span>状态</span><strong class="good-text">● 在线</strong></div>
        <div class="confirm-row"><span>虚拟地址</span><strong>${esc(wizardState.address||'10.18.0.72')}</strong></div>
        <div class="confirm-row"><span>设备凭据</span><strong>正常 · 有效至 ${esc(wizardState.credentialExpiry||'2026-10-16')}</strong></div>
        <div class="confirm-row"><span>访问权限</span><strong>按现有访问规则</strong></div>
      </div>
      <div class="next-actions-card"><strong>接下来可以做什么？</strong><button type="button" id="finishOpenDevice"><span>查看设备详情</span><b>›</b></button><button type="button" id="finishOpenPolicy"><span>为设备设置访问权限</span><b>›</b></button></div>`;
    document.getElementById('finishOpenDevice')?.addEventListener('click',()=>{finalizeDevice(false);modal.hidden=true;openDrawer(wizardState.name,'overview')});
    document.getElementById('finishOpenPolicy')?.addEventListener('click',()=>{finalizeDevice(false);modal.hidden=true;showRoute('policy')});
    modalNext.textContent='完成';
  }
}

function renderShareStep(){
  if(modalStep===1){
    modalBody.innerHTML=`
      <div class="subtle-note"><strong>这一步只定义“共享什么”</strong><p>共享本身不会创建新的共享密码或共享凭据。</p></div>
      <label>共享名称<input id="shareName" value="${esc(wizardState.name||'')}" placeholder="例如：家庭 NAS 文件服务" /></label>
      <label>服务所在设备<select id="shareDevice"><option>家用 NAS</option><option>开发服务器</option><option>办公笔记本</option></select></label>
      <div class="form-grid two"><label>协议<select id="shareProtocol"><option>TCP</option><option>UDP</option><option>HTTP</option><option>HTTPS</option></select></label><label>端口<input id="sharePort" inputmode="numeric" value="${esc(wizardState.port||'445')}" /></label></div>
      <label>DNS 名称（可选）<input id="shareDns" value="${esc(wizardState.dns||'')}" placeholder="例如：nas.home" /></label>
      <p class="field-help">Peerward 会用“服务所在设备”的设备身份发布这个服务。</p>`;
    if(wizardState.device) document.getElementById('shareDevice').value=wizardState.device;
    if(wizardState.protocol) document.getElementById('shareProtocol').value=wizardState.protocol;
    modalNext.textContent='下一步';
  }else if(modalStep===2){
    modalBody.innerHTML=`
      <div class="subtle-note"><strong>再决定“谁可以访问”</strong><p>保存后系统会创建对应的访问规则；你也可以选择暂不开放。</p></div>
      <div class="choice-list">
        <label class="choice-card"><input type="radio" name="shareScope" value="家庭成员" ${!wizardState.scope||wizardState.scope==='家庭成员'?'checked':''}><span><strong>家庭成员</strong><small>当前设备组中的所有家庭设备</small></span></label>
        <label class="choice-card"><input type="radio" name="shareScope" value="所有受管设备" ${wizardState.scope==='所有受管设备'?'checked':''}><span><strong>所有受管设备</strong><small>适合 Dashboard、监控等通用服务</small></span></label>
        <label class="choice-card"><input type="radio" name="shareScope" value="指定设备" ${wizardState.scope==='指定设备'?'checked':''}><span><strong>指定设备</strong><small>只开放给你选择的单台设备</small></span></label>
        <label class="choice-card"><input type="radio" name="shareScope" value="暂不开放" ${wizardState.scope==='暂不开放'?'checked':''}><span><strong>暂不开放</strong><small>先创建服务，稍后再到访问规则中授权</small></span></label>
      </div>
      <div class="security-note"><span>✓</span><p><strong>默认拒绝仍然生效。</strong>没有访问规则的其他设备不能访问这个共享。</p></div>`;
    modalNext.textContent='下一步';
  }else{
    const scope=wizardState.scope||'家庭成员';
    const willRule=scope!=='暂不开放';
    modalBody.innerHTML=`
      <div class="confirm-card">
        <div class="confirm-row"><span>共享名称</span><strong>${esc(wizardState.name||'未命名共享')}</strong></div>
        <div class="confirm-row"><span>服务位置</span><strong>${esc(wizardState.device||'家用 NAS')} · ${esc(wizardState.protocol||'TCP')} ${esc(wizardState.port||'445')}</strong></div>
        ${wizardState.dns?`<div class="confirm-row"><span>DNS 名称</span><strong>${esc(wizardState.dns)}</strong></div>`:''}
        <div class="confirm-row"><span>访问范围</span><strong>${esc(scope)}</strong></div>
      </div>
      <div class="info-banner compact"><span>i</span><div><strong>${willRule?'将同时创建访问规则':'不会创建访问规则'}</strong><p>${willRule?'系统会为“'+esc(scope)+' → '+esc(wizardState.name||'该共享')+'”创建允许规则。':'共享会先保持不可访问，直到你手动创建访问规则。'}</p></div></div>
      <div class="subtle-note"><strong>不会生成共享凭据</strong><p>设备身份负责证明“谁在发布”，访问规则负责决定“谁能访问”。</p></div>`;
    modalNext.textContent='创建共享';
  }
}

function renderRuleStep(){
  if(modalStep===1){
    const groups=policyGroupNames().map(name=>`<option value="${esc(name)}">${esc(name)}</option>`).join('');
    const deviceOptions=Object.keys(devices).map(name=>`<option value="${esc(name)}">${esc(name)}</option>`).join('');
    modalBody.innerHTML=`<label>谁可以访问<select id="ruleSource"><optgroup label="设备组">${groups}</optgroup><optgroup label="单台设备">${deviceOptions}</optgroup></select></label><p class="field-help">优先给设备组授权，日后新增组内设备会自动获得相同权限；也可以只允许一台设备。</p>`;
    if(wizardState.source && [...document.getElementById('ruleSource').options].some(o=>o.value===wizardState.source)) document.getElementById('ruleSource').value=wizardState.source;modalNext.textContent='下一步';
  }else if(modalStep===2){
    const targets=Object.entries(services).map(([name,svc])=>`<option value="${esc(name)}">${esc(name)} · ${esc(svc.protocol)} ${esc(svc.port)}</option>`).join('');
    modalBody.innerHTML=`<label>访问什么<select id="ruleTarget">${targets}</select></label><div class="info-banner compact"><span>i</span><div><strong>协议与端口由共享服务提供</strong><p>不需要再次填写 TCP/UDP 和端口，减少配置错误。</p></div></div>`;
    if(wizardState.target && [...document.getElementById('ruleTarget').options].some(o=>o.value===wizardState.target)) document.getElementById('ruleTarget').value=wizardState.target;modalNext.textContent='下一步';
  }else{
    modalBody.innerHTML=`<div class="confirm-card"><div class="rule-sentence"><span>${esc(wizardState.source||'家庭成员')}</span><b>可以访问</b><span>${esc(wizardState.target||'家庭 NAS 文件服务')}</span></div></div><div class="security-note"><span>✓</span><p><strong>默认拒绝仍然生效。</strong>这条权限只开放上面明确选择的访问；其他共享不会受到影响。</p></div>`;
    modalNext.textContent='创建访问权限';
  }
}

function renderModal(){
  syncStepper();
  if(modalType==='device') renderDeviceStep();
  else if(modalType==='share') renderShareStep();
  else renderRuleStep();
}

function openModal(type='device',preset={}){
  modalType=type;modalStep=1;wizardState={...preset};modalTitle.textContent=wizardConfig[type].title;modal.hidden=false;renderModal();
}

function saveCurrentStep(){
  if(modalType==='device'){
    if(modalStep===1){wizardState.name=field('deviceNameInput')||'新设备';wizardState.groups=[...modalBody.querySelectorAll('[name="device_groups"]:checked')].map(el=>el.value);wizardState.platform=field('devicePlatformInput')||'Linux';}
    if(modalStep===2){wizardState.ttl=field('joinTtl')||wizardState.ttl||'15 分钟';}
  }else if(modalType==='share'){
    if(modalStep===1){wizardState.name=field('shareName')||'未命名共享';wizardState.device=field('shareDevice');wizardState.protocol=field('shareProtocol');wizardState.port=field('sharePort')||'443';wizardState.dns=field('shareDns');}
    if(modalStep===2){wizardState.scope=document.querySelector('input[name="shareScope"]:checked')?.value||'家庭成员';}
  }else{
    if(modalStep===1) wizardState.source=field('ruleSource');
    if(modalStep===2) wizardState.target=field('ruleTarget');
  }
}

function finalizeDevice(showToast=true){
  const name=wizardState.name||'新设备';
  if(!devices[name]){
    devices[name]={icon:wizardState.platform==='Android'?'▯':'▰',status:'online',address:wizardState.address||'10.18.0.72',platform:wizardState.platform||'Linux',location:'',last:'刚刚',version:'1.8.2',peerId:'peer_new…72af',groups:[...(wizardState.groups||[])],credential:'正常',credentialExpiry:wizardState.credentialExpiry||'2026-10-16',credentialSerial:'cred_new…91b7',route:'中继',access:[],shares:[],activity:[['刚刚','设备首次加入网络'],['刚刚','设备凭据签发成功']]};
    const table=document.querySelector('.device-table');
    const row=document.createElement('div');row.className='table-row device-row';row.dataset.device=name;
    row.innerHTML=`<div class="device-cell"><span class="device-icon">${esc(devices[name].icon)}</span><span><strong>${esc(name)}</strong><small>${esc(devices[name].platform)} · ${esc((devices[name].groups||[]).join('、')||'未分组')}</small></span></div><div><span class="status-pill good">● 在线</span></div><div><code>${esc(devices[name].address)}</code></div><div>刚刚</div><div>按现有规则</div><div><button class="row-more" aria-label="查看${esc(name)}详情">•••</button></div>`;
    table.appendChild(row);
    const count=document.querySelector('.table-head-row h2 span');if(count) count.textContent=String(Object.keys(devices).length);
    const badge=document.querySelector('.nav-item[data-route="devices"] .badge');if(badge) badge.textContent=String(Object.keys(devices).length);
  }
  renderPolicyUI();
  if(showToast) toast(`${name} 已加入网络`);
}

function finalizeShare(){
  const name=wizardState.name||'未命名共享';
  const scope=wizardState.scope||'家庭成员';
  const protocol=wizardState.protocol||'TCP';
  const host=wizardState.device||'家用 NAS';
  const hostDevice=devices[host];
  const iconClass=protocol==='HTTPS'||protocol==='HTTP'?'purple':protocol==='TCP'&&String(wizardState.port)==='22'?'green':'';
  const scopeInfo=scope==='暂不开放'?[]:[{name:scope,kind:scope==='指定设备'?'设备集合':'设备组',count:scope==='指定设备'?2:scope==='所有受管设备'?2:3,rule:'新建规则'}];
  services[name]={icon:(name.trim()[0]||'S').toUpperCase(),iconClass,host,hostAddress:hostDevice?.address||'10.18.0.30',protocol,port:wizardState.port||'443',dns:wizardState.dns||'',status:'healthy',lastCheck:'刚刚',scopes:scopeInfo,activity:[]};
  if(hostDevice && !hostDevice.shares.some(x=>x[0]===name)) hostDevice.shares.push([name,`${protocol} ${wizardState.port||'443'}`]);
  renderServices(document.getElementById('shareSearchInput')?.value||'');
  renderPolicyUI();
}
function finalizeRule(){
  const target=wizardState.target||'家庭 NAS 文件服务';
  const source=wizardState.source||'家庭成员';
  const svc=services[target];
  if(svc && !svc.scopes.some(x=>x.name===source)){
    const single=!!devices[source];
    svc.scopes.push({name:source,kind:single?'单台设备':'设备组',count:single?1:source==='所有受管设备'?2:source==='开发设备'?2:3,rule:'新建规则'});
    renderServices(document.getElementById('shareSearchInput')?.value||'');
    renderPolicyUI();
    selectedPolicyCell={source,target};
  }
}

modalNext.addEventListener('click',()=>{
  saveCurrentStep();
  const max=wizardConfig[modalType].steps.length;
  if(modalType==='device' && modalStep===3 && !wizardState.online){
    wizardState.online=true;wizardState.address='10.18.0.72';wizardState.credentialExpiry='2026-10-16';renderModal();toast('已检测到设备上线，并签发设备凭据');return;
  }
  if(modalStep<max){modalStep++;renderModal();return;}
  modal.hidden=true;
  if(modalType==='device') finalizeDevice(true);
  if(modalType==='share'){finalizeShare();toast(wizardState.scope==='暂不开放'?'资源已创建，当前未授权访问':'资源和访问规则已创建');}
  if(modalType==='rule'){finalizeRule();toast('访问权限已创建');renderPolicyUI();if(wizardState.source&&wizardState.target)renderPolicyDetail(wizardState.source,wizardState.target);}
});
modalBack.addEventListener('click',()=>{if(modalStep>1){modalStep--;renderModal();}});

document.getElementById('addDeviceBtn').addEventListener('click',()=>openModal('device'));
document.getElementById('addShareBtn').addEventListener('click',()=>openModal('share'));
document.getElementById('addRuleBtn').addEventListener('click',()=>openModal('rule'));
document.querySelectorAll('.close-modal').forEach(b=>b.addEventListener('click',()=>modal.hidden=true));
modal.addEventListener('click',e=>{if(e.target===modal) modal.hidden=true});
document.addEventListener('keydown',e=>{if(e.key==='Escape'){if(!modal.hidden)modal.hidden=true;else if(serviceDrawer?.classList.contains('open'))closeServiceDrawer();else if(drawer.classList.contains('open'))closeDrawer();}});

function toast(msg){
  const t=document.getElementById('toast');t.textContent=msg;t.hidden=false;clearTimeout(window.__toast);window.__toast=setTimeout(()=>t.hidden=true,2400);
}



/* ---------------- v6: actionable health / operations center ---------------- */
const DEMO_TODAY = new Date('2026-09-16T00:00:00+08:00');
const opsIssueOverrides = Object.create(null);
let opsIssueFilterValue = 'open';
let opsLastCheckedIssueIds = null;

function demoDaysUntil(dateText){
  const d=new Date(dateText+'T00:00:00+08:00');
  return Math.ceil((d-DEMO_TODAY)/86400000);
}
function expiringCredentialDevices(){
  return Object.entries(devices).filter(([,d])=>demoDaysUntil(d.credentialExpiry)<=14);
}
function buildOpsIssues(){
  const issues=[];
  Object.entries(devices).forEach(([name,d])=>{
    if(d.status!=='online') issues.push({
      id:'offline:'+name,type:'device',severity:'warning',title:`${name} 已离线 ${d.last}`,
      summary:'如果这台设备本来就不需要常在线，可以标记为“已知”；否则建议先检查电源、网络和 Peerward 客户端。',
      impact:'仅影响该设备',impactClass:'low',device:name,guidance:'先确认设备是否应该在线。离线不会影响其他设备，也不会自动删除已有访问权限。'
    });
  });
  const expiring=expiringCredentialDevices();
  if(expiring.length){
    const earliest=Math.min(...expiring.map(([,d])=>demoDaysUntil(d.credentialExpiry)));
    issues.push({
      id:'credential:expiring',type:'credential',severity:'warning',title:`${expiring.length} 台设备的凭据将在 14 天内到期`,
      summary:`最早还有 ${earliest} 天到期。正常轮换不会改变设备名称、地址或访问权限。`,
      impact:'暂不影响使用',impactClass:'low',devices:expiring.map(([name])=>name),guidance:'建议在到期前请求设备更新身份，避免身份到期后需要重新接入。'
    });
  }
  Object.entries(services).forEach(([name,svc])=>{
    if(svc.status!=='healthy' && svc.status!=='paused') issues.push({
      id:'service:'+name,type:'service',severity:'critical',title:`${name} 当前不可达`,summary:'共享健康检查失败，请检查提供设备是否在线以及服务端口是否仍在监听。',impact:'影响此共享',impactClass:'',service:name,guidance:'先测试提供设备，再确认协议和端口。不要先修改访问权限。'
    });
  });
  return issues.map(i=>({...i,state:opsIssueOverrides[i.id]||'open'}));
}
function activeIssues(){return buildOpsIssues().filter(i=>i.state==='open');}
function knownIssues(){return buildOpsIssues().filter(i=>i.state==='known');}
function criticalIssues(){return activeIssues().filter(i=>i.severity==='critical');}

function openDeviceFromOps(name){ openDrawer(name,'overview'); }
function openServiceFromOps(name){ openServiceDrawer(name,'overview'); }
function issuePrimaryAction(issue){
  if(issue.type==='device') return `<button class="secondary-btn small" data-issue-action="device" data-issue-id="${esc(issue.id)}">查看设备</button>`;
  if(issue.type==='credential') return `<button class="primary-btn small-primary" data-issue-action="rotate" data-issue-id="${esc(issue.id)}">请求更新</button>`;
  if(issue.type==='service') return `<button class="secondary-btn small" data-issue-action="service" data-issue-id="${esc(issue.id)}">查看共享</button>`;
  return '';
}
function dashboardIssueHtml(issue){
  return `<div class="dashboard-action-item">
    <span class="dashboard-action-icon ${issue.severity==='critical'?'':'info'}">${issue.severity==='critical'?'!':'!'}</span>
    <div class="dashboard-action-copy"><strong>${esc(issue.title)}</strong><small>${esc(issue.summary)}</small></div>
    <div class="dashboard-action-meta"><span class="impact-pill ${esc(issue.impactClass||'')}">${esc(issue.impact)}</span><button class="link-btn" data-dashboard-issue="${esc(issue.id)}">处理 ›</button></div>
  </div>`;
}
function renderDashboardHealth(){
  const issues=activeIssues(), critical=criticalIssues();
  const online=Object.values(devices).filter(d=>d.status==='online').length,total=Object.keys(devices).length;
  const healthyShares=Object.values(services).filter(s=>s.status==='healthy').length,shareTotal=Object.keys(services).length;
  const expiring=expiringCredentialDevices().length;
  const banner=document.getElementById('dashboardHealthBanner');
  if(banner){
    banner.classList.remove('attention','healthy','critical');
    banner.classList.add(critical.length?'critical':issues.length?'attention':'healthy');
    document.getElementById('dashboardHealthIcon').textContent=critical.length?'!':issues.length?'!':'✓';
    document.getElementById('dashboardHealthTitle').textContent=critical.length?`有 ${critical.length} 个问题正在影响使用`:issues.length?`网络整体可用，有 ${issues.length} 件事建议处理`:'网络运行正常，没有待处理事项';
    document.getElementById('dashboardHealthText').textContent=critical.length?'请优先处理下方标为“影响使用”的事项。':issues.length?'控制服务、中继和 DNS 工作正常；这些事项目前不会阻断其他在线设备。':'关键组件、在线设备与共享服务均未发现需要人工处理的问题。';
  }
  const set=(id,val)=>{const e=document.getElementById(id);if(e)e.textContent=val};
  set('dashboardIssueCount',issues.length);set('dashboardIssueFoot',critical.length?`${critical.length} 个正在影响使用`:issues.length?'均非严重故障':'无需处理');
  set('dashboardOnlineCount',online);set('dashboardDeviceTotal',`/ ${total} 在线`);set('dashboardDeviceFoot',online===total?'全部设备在线':`${total-online} 台设备离线`);
  set('dashboardShareHealthy',healthyShares);set('dashboardShareTotal',`/ ${shareTotal} 可用`);set('dashboardShareFoot',healthyShares===shareTotal?'全部通过健康检查':`${shareTotal-healthyShares} 个共享需检查`);
  set('dashboardCredentialHealth',expiring);set('dashboardCredentialFoot',expiring?'建议在 14 天内请求设备更新':'近期无需更新');
  const list=document.getElementById('dashboardActionList');
  if(list) list.innerHTML=issues.length?issues.slice(0,3).map(dashboardIssueHtml).join(''):`<div class="dashboard-action-empty"><div><strong>当前没有需要你处理的事项</strong><span>系统事件仍会记录在问题与维护，但不会因为正常的“默认拒绝”打扰你。</span></div></div>`;
  const badge=document.getElementById('navOpsBadge');if(badge){badge.textContent=String(issues.length);badge.hidden=!issues.length;}
}
function issueCardHtml(issue){
  const stateLabel=issue.state==='known'?'<span class="issue-tag neutral">已知</span>':'';
  return `<article class="ops-issue-card ${esc(issue.state)}" data-issue-card="${esc(issue.id)}">
    <span class="ops-issue-icon ${issue.severity==='critical'?'':'info'}">!</span>
    <div class="ops-issue-main">
      <div class="ops-issue-top"><strong>${esc(issue.title)}</strong><div class="ops-issue-tags"><span class="issue-tag">${esc(issue.impact)}</span>${stateLabel}</div></div>
      <p class="issue-what"><small>发生了什么</small>${esc(issue.summary)}</p>
      <div class="issue-guidance"><span>→</span><div><strong>建议下一步</strong><p>${esc(issue.guidance)}</p></div></div>
      <div class="issue-actions">${issuePrimaryAction(issue)}<button class="link-btn" data-issue-action="${issue.state==='known'?'reopen':'known'}" data-issue-id="${esc(issue.id)}">${issue.state==='known'?'重新列为待处理':'标记为已知'}</button></div>
    </div>
  </article>`;
}
function renderOpsCenter(){
  const all=buildOpsIssues(),open=all.filter(i=>i.state==='open'),known=all.filter(i=>i.state==='known'),crit=open.filter(i=>i.severity==='critical');
  const set=(id,val)=>{const e=document.getElementById(id);if(e)e.textContent=val};
  set('opsOpenCount',open.length);set('opsKnownCount',known.length);set('opsAllCount',all.length);set('opsCriticalCount',crit.length);
  let visible=opsIssueFilterValue==='open'?open:opsIssueFilterValue==='known'?known:all;
  const q=document.getElementById('opsIssueQueue');
  if(q)q.innerHTML=visible.length?visible.map(issueCardHtml).join(''):`<div class="empty-issue-state"><div><span>✓</span><strong>${opsIssueFilterValue==='known'?'没有已知事项':'当前没有待处理事项'}</strong><p>${opsIssueFilterValue==='known'?'你标记为已知的事项会出现在这里。':'正常的访问拒绝和系统事件不会被当作故障。'}</p></div></div>`;
  document.querySelectorAll('#opsIssueFilter [data-issue-filter]').forEach(b=>b.classList.toggle('active',b.dataset.issueFilter===opsIssueFilterValue));
  renderDashboardHealth();
}
function rotateExpiringCredentials(){
  const targets=expiringCredentialDevices();
  targets.forEach(([,d])=>{d.credentialExpiry='2026-12-15';d.credential='正常';});
  delete opsIssueOverrides['credential:expiring'];
  if(currentDeviceName && devices[currentDeviceName]){renderDrawerSummary();renderDrawerTab();}
  renderOpsCenter();
  toast(`已为 ${targets.length} 台设备模拟自行更新身份`);
}
function runHealthCheck(source='ops'){
  const btn=document.getElementById(source==='dashboard'?'dashboardRunCheckBtn':source==='full'?'opsRunFullCheckBtn':'opsRefreshBtn');
  const before=opsLastCheckedIssueIds||new Set(buildOpsIssues().map(i=>i.id));
  if(btn){
    const old=btn.textContent;btn.disabled=true;btn.textContent='检查中…';
    setTimeout(()=>{
      const current=buildOpsIssues();const currentIds=new Set(current.map(i=>i.id));
      const removed=[...before].filter(id=>!currentIds.has(id));const open=current.filter(i=>i.state==='open');
      opsLastCheckedIssueIds=currentIds;
      btn.disabled=false;btn.textContent=old;renderOpsCenter();
      const box=document.getElementById('opsRecheckResult');
      if(box && source==='ops'){
        box.hidden=false;box.classList.toggle('recovered',open.length===0||removed.length>0);
        const title=open.length===0?'重新检查完成：当前证据已恢复':removed.length?'重新检查完成：先前有事项已不再出现':'重新检查完成：仍有事项需要处理';
        const detail=open.length===0?'当前没有待处理事项。Peerward 根据重新读取的当前证据确认状态，而不是根据你是否点击过修复按钮。':removed.length?`有 ${removed.length} 个先前事项已不再满足提醒条件；仍有 ${open.length} 项需要处理。`:`当前证据仍满足 ${open.length} 项提醒条件，请继续按建议下一步处理。`;
        box.innerHTML=`<span>${open.length===0?'✓':'↻'}</span><div><strong>${title}</strong><p>${detail}</p><small>检查完成于 · 刚刚</small></div>`;
      }
      const label='刚刚';['dashboardLastCheck','opsLastCheck'].forEach(id=>{const e=document.getElementById(id);if(e)e.textContent=label});
      toast(open.length?'重新检查完成':'重新检查完成：当前没有待处理事项');
    },650);
  }else{renderOpsCenter();}
}

document.getElementById('dashboardReviewBtn')?.addEventListener('click',()=>showRoute('ops'));
document.getElementById('dashboardRunCheckBtn')?.addEventListener('click',()=>runHealthCheck('dashboard'));
document.getElementById('opsRefreshBtn')?.addEventListener('click',()=>runHealthCheck('ops'));
document.getElementById('opsRunFullCheckBtn')?.addEventListener('click',()=>runHealthCheck('full'));
document.getElementById('opsExportBtn')?.addEventListener('click',()=>downloadText('peerward-diagnostics.txt','Peerward diagnostics demo\nControl: OK\nRelay: OK\nDNS: OK\nDatabase: OK\nOpen issues: '+activeIssues().length));
document.getElementById('opsIssueFilter')?.addEventListener('click',e=>{const b=e.target.closest('[data-issue-filter]');if(!b)return;opsIssueFilterValue=b.dataset.issueFilter;renderOpsCenter();});
document.getElementById('dashboardActionList')?.addEventListener('click',e=>{const b=e.target.closest('[data-dashboard-issue]');if(!b)return;showRoute('ops');setTimeout(()=>{const card=document.querySelector(`[data-issue-card="${CSS.escape(b.dataset.dashboardIssue)}"]`);card?.scrollIntoView({behavior:'smooth',block:'center'});},50);});
document.getElementById('opsIssueQueue')?.addEventListener('click',e=>{
  const b=e.target.closest('[data-issue-action]');if(!b)return;
  const id=b.dataset.issueId;const issue=buildOpsIssues().find(x=>x.id===id);if(!issue)return;
  const action=b.dataset.issueAction;
  if(action==='device'){openDeviceFromOps(issue.device);return;}
  if(action==='service'){openServiceFromOps(issue.service);return;}
  if(action==='rotate'){rotateExpiringCredentials();return;}
  if(action==='known'){opsIssueOverrides[id]='known';toast('已标记为已知，之后可重新列为待处理');renderOpsCenter();return;}
  if(action==='reopen'){delete opsIssueOverrides[id];toast('已重新列为待处理');renderOpsCenter();return;}
});

renderOpsCenter();
opsLastCheckedIssueIds=new Set(buildOpsIssues().map(i=>i.id));

/* ---------------- v7: first-run / empty-state experience ---------------- */
let firstRunMode=false;
const firstRunState={network:false,device:false,share:false,access:false,deviceTicketReady:false,networkName:'家庭网络',networkId:'home-mesh',deviceName:'我的笔记本',platform:'Linux',shareName:'我的第一个共享',protocol:'TCP',port:'445'};
const firstRunOriginal={networkName:'家庭网络',networkLink:'网络设置'};

function firstRunCompletedCount(){return ['network','device','share','access'].filter(k=>firstRunState[k]).length;}
function firstRunNextStep(){return !firstRunState.network?'network':!firstRunState.device?'device':!firstRunState.share?'share':!firstRunState.access?'access':'done';}
function frStepCard(key,num,title,desc,route){
  const done=!!firstRunState[key],next=firstRunNextStep(),current=key===next,locked=!done&&!current;
  const stateClass=done?'done':current?'current':'locked';
  const action=done?`<span class="setup-step-state">已完成</span>`:current?`<button class="${key==='network'?'primary-btn':'secondary-btn'}" data-first-action="go-${route}">${key==='network'?'开始设置':'继续'}</button>`:`<span class="setup-step-state locked">等待上一步</span>`;
  return `<div class="setup-step-card ${stateClass}"><span class="setup-step-num">${done?'✓':num}</span><div class="setup-step-copy"><strong>${title}</strong><small>${desc}</small></div>${action}</div>`;
}
function renderFirstRunDashboard(){
  const el=document.getElementById('firstRunDashboard'); if(!el)return;
  const count=firstRunCompletedCount(),pct=count*25,next=firstRunNextStep();
  if(next==='done'){
    el.innerHTML=`<div class="first-run-shell"><div class="first-run-head"><div><div class="eyebrow">首次使用</div><h1>你的 Peerward 基础设置已经完成</h1><p>现在已经具备“网络、设备、共享、访问权限”四个基本要素。日常使用时，只需要处理真正出现的待办。</p></div><span class="first-run-mode-pill">首次使用预览</span></div><section class="first-run-complete"><span class="first-run-complete-mark">✓</span><h2>可以开始使用了</h2><p>这套引导的目标是让第一次使用的人不用理解 Mesh、Policy、Credential 等底层术语，也能安全完成基础配置。</p><div class="first-run-summary"><div><small>网络</small><strong>${esc(firstRunState.networkName)}</strong></div><div><small>第一台设备</small><strong>${esc(firstRunState.deviceName)}</strong></div><div><small>第一个共享</small><strong>${esc(firstRunState.shareName)}</strong></div><div><small>访问权限</small><strong>${esc(firstRunState.deviceName)} 可以访问</strong></div></div><div class="first-run-complete-actions"><button class="primary-btn" data-first-action="finish-preview">结束预览，返回演示网络</button><button class="secondary-btn" data-first-action="reset-preview">重新体验引导</button></div></section></div>`; return;
  }
  el.innerHTML=`<div class="first-run-shell"><div class="first-run-head"><div><div class="eyebrow">欢迎使用 Peerward</div><h1>先完成 4 件事，就可以开始使用</h1><p>第一次进入时不展示一堆空指标，而是按真实任务一步步带你建立网络。每一步都说明“为什么需要”和“完成后会发生什么”。</p></div><span class="first-run-mode-pill">首次使用预览</span></div><section class="setup-hero"><div><div class="eyebrow">约 3 分钟</div><h2>把第一台设备安全地接入你的网络</h2><p>Peerward 会先建立一个网络空间，再让设备获得自己的身份。共享和访问权限都建立在设备身份之上。</p></div><div class="setup-hero-art"><div class="setup-network-visual"><span class="setup-node">▰</span><i class="setup-line"></i><span class="setup-node control">P</span></div></div></section><section class="setup-progress-card"><div class="setup-progress-head"><strong>设置进度</strong><span>${count} / 4 已完成</span></div><div class="setup-progress-track"><i style="width:${pct}%"></i></div><div class="setup-step-list">${frStepCard('network',1,'创建网络','给设备和共享一个共同的安全空间。','network')}${frStepCard('device',2,'添加第一台设备','生成一次性加入方式，设备上线后获得自己的长期身份。','devices')}${frStepCard('share',3,'创建第一个共享','选择这台设备上要开放的服务，不会生成额外“共享凭据”。','sharing')}${frStepCard('access',4,'设置谁可以访问','明确授权后才可以连接；没有授权时默认阻止。','policy')}</div></section><div class="first-run-tip-grid"><div class="first-run-tip"><span>1</span><strong>一次只做一件事</strong><small>后续步骤在前置条件完成前会保持锁定，减少误配置。</small></div><div class="first-run-tip"><span>✓</span><strong>默认安全</strong><small>设备加入不等于能访问所有资源；没有明确权限就默认阻止。</small></div><div class="first-run-tip"><span>?</span><strong>不要求懂专业术语</strong><small>底层 Mesh、Policy、Credential 保留在高级区域，不挡住日常操作。</small></div></div></div>`;
}
function lockedWorkspace(title,desc,needed,action){return `<div class="first-run-shell"><div class="first-run-head"><div><div class="eyebrow">首次使用</div><h1>${title}</h1><p>${desc}</p></div><span class="first-run-mode-pill">首次使用预览</span></div><section class="empty-workspace locked"><div class="empty-workspace-top"><span class="empty-workspace-icon locked">⌁</span><div><h2>还不能进行这一步</h2><p>${needed}</p></div></div><div class="locked-prereq"><span>→</span><div>先完成前置步骤，Peerward 会自动把你带回这里。</div></div><div class="empty-form-actions"><button class="primary-btn" data-first-action="${action}">去完成前置步骤</button></div></section></div>`;}
function renderFirstRunNetwork(){
 const el=document.getElementById('firstRunNetwork');if(!el)return;
 if(firstRunState.network){el.innerHTML=`<div class="first-run-shell"><div class="first-run-head"><div><div class="eyebrow">第 1 步 · 已完成</div><h1>网络已创建</h1><p>接下来添加第一台设备。网络标识会保持稳定，日常一般不需要修改。</p></div><span class="first-run-mode-pill">首次使用预览</span></div><section class="empty-workspace"><div class="empty-workspace-top"><span class="empty-workspace-icon success">✓</span><div><h2>${esc(firstRunState.networkName)}</h2><p>网络标识：${esc(firstRunState.networkId)} · 托管 DNS 与资源访问已使用推荐默认值。</p></div></div><div class="first-run-success"><strong>默认设置已经足够开始</strong><p>地址范围、设备凭据参数等高级设置暂时不需要调整。</p></div><div class="empty-form-actions"><button class="primary-btn" data-first-action="go-devices">添加第一台设备</button><button class="secondary-btn" data-first-action="go-dashboard">返回设置进度</button></div></section></div>`;return;}
 el.innerHTML=`<div class="first-run-shell"><div class="first-run-head"><div><div class="eyebrow">第 1 步 · 创建网络</div><h1>给你的设备创建一个网络空间</h1><p>只需要起一个容易识别的名字。其他网络参数使用安全默认值，之后有需要再到高级设置调整。</p></div><span class="first-run-mode-pill">首次使用预览</span></div><section class="empty-workspace"><div class="empty-workspace-top"><span class="empty-workspace-icon">⌂</span><div><h2>创建第一个网络</h2><p>这不会改变任何现有路由器或局域网设置；它只是 Peerward 用来组织设备和权限的逻辑网络。</p></div></div><div class="empty-form"><label>网络名称<input id="firstNetworkName" value="${esc(firstRunState.networkName)}" placeholder="例如：家庭网络"></label><label>网络标识<input id="firstNetworkId" value="${esc(firstRunState.networkId)}" placeholder="例如：home-mesh"></label><p class="empty-form-help">网络标识建议使用小写字母、数字和连字符，创建后一般不再修改。</p><div class="empty-form-actions"><button class="primary-btn" data-first-action="create-network">创建网络并继续</button><button class="secondary-btn" data-first-action="go-dashboard">稍后再做</button></div></div></section></div>`;
}
function renderFirstRunDevices(){
 const el=document.getElementById('firstRunDevices');if(!el)return;
 if(!firstRunState.network){el.innerHTML=lockedWorkspace('设备','第一台设备加入后，Peerward 才有一个可以被识别和授权的真实端点。','请先创建网络。','go-network');return;}
 if(firstRunState.device){el.innerHTML=`<div class="first-run-shell"><div class="first-run-head"><div><div class="eyebrow">第 2 步 · 已完成</div><h1>第一台设备已经上线</h1><p>一次性加入凭据已经完成使命；日常连接会使用设备自己的长期身份。</p></div><span class="first-run-mode-pill">首次使用预览</span></div><section class="empty-workspace"><div class="empty-workspace-top"><span class="empty-workspace-icon success">✓</span><div><h2>${esc(firstRunState.deviceName)}</h2><p>${esc(firstRunState.platform)} · 在线 · 已签发设备凭据</p></div></div><div class="first-run-success"><strong>这台设备现在“有身份”了</strong><p>但它还没有自动获得任何共享访问权。下一步创建一个可以被访问的服务。</p></div><div class="empty-form-actions"><button class="primary-btn" data-first-action="go-sharing">创建第一个共享</button><button class="secondary-btn" data-first-action="go-dashboard">返回设置进度</button></div></section></div>`;return;}
 if(firstRunState.deviceTicketReady){const cmd=`peerward join --control https://control.peerward.local --ticket pw_join_FIRST_${firstRunState.networkId}`;el.innerHTML=`<div class="first-run-shell"><div class="first-run-head"><div><div class="eyebrow">第 2 步 · 接入设备</div><h1>在 ${esc(firstRunState.deviceName)} 上完成一次接入</h1><p>下面的加入凭据只用于这一次接入。设备上线后会自动换成自己的设备凭据。</p></div><span class="first-run-mode-pill">首次使用预览</span></div><section class="empty-workspace"><div class="first-run-success"><strong>一次性加入方式已准备好</strong><p>有效期 15 分钟。不要把它当成共享密码长期保存。</p></div><div class="first-join-box"><div class="first-join-method"><strong>方式 A · 复制命令</strong><small>在新设备的终端运行</small><div class="first-join-command">${esc(cmd)}</div><div class="empty-form-actions"><button class="secondary-btn" data-first-action="copy-first-command">复制命令</button><button class="primary-btn" data-first-action="simulate-device-online">我已操作，检查设备上线</button></div></div><div class="first-join-qr"><img src="join-qr.png" alt="设备加入二维码"><small>也可以在 Peerward 客户端扫码</small></div></div></section></div>`;return;}
 el.innerHTML=`<div class="first-run-shell"><div class="first-run-head"><div><div class="eyebrow">第 2 步 · 添加设备</div><h1>先添加你正在使用的这台设备</h1><p>只需要名称和平台。Peerward 随后会生成一次性接入方式，并等待设备上线。</p></div><span class="first-run-mode-pill">首次使用预览</span></div><section class="empty-workspace"><div class="empty-workspace-top"><span class="empty-workspace-icon">▰</span><div><h2>添加第一台设备</h2><p>设备名称只用于管理界面，建议写成你一眼能认出的名字。</p></div></div><div class="empty-form"><label>设备名称<input id="firstDeviceName" value="${esc(firstRunState.deviceName)}"></label><label>平台<select id="firstDevicePlatform"><option>Linux</option><option>Android</option></select></label><p class="empty-form-help">添加设备不会自动开放任何共享访问权限。</p><div class="empty-form-actions"><button class="primary-btn" data-first-action="prepare-first-device">生成加入方式</button><button class="secondary-btn" data-first-action="go-dashboard">返回设置进度</button></div></div></section></div>`;
 setTimeout(()=>{const p=document.getElementById('firstDevicePlatform');if(p)p.value=firstRunState.platform;},0);
}
function renderFirstRunSharing(){
 const el=document.getElementById('firstRunSharing');if(!el)return;
 if(!firstRunState.device){el.innerHTML=lockedWorkspace('共享','共享必须由一台已经加入网络并拥有设备身份的设备提供。','请先添加第一台设备并确认它上线。','go-devices');return;}
 if(firstRunState.share){el.innerHTML=`<div class="first-run-shell"><div class="first-run-head"><div><div class="eyebrow">第 3 步 · 已完成</div><h1>第一个共享已经创建</h1><p>共享定义了“提供什么服务”，但目前仍然没有自动给任何设备访问权。</p></div><span class="first-run-mode-pill">首次使用预览</span></div><section class="empty-workspace"><div class="empty-workspace-top"><span class="empty-workspace-icon success">✓</span><div><h2>${esc(firstRunState.shareName)}</h2><p>${esc(firstRunState.deviceName)} · ${esc(firstRunState.protocol)} ${esc(firstRunState.port)}</p></div></div><div class="first-run-success"><strong>没有生成“共享凭据”</strong><p>${esc(firstRunState.deviceName)} 的设备身份负责证明服务来自哪里；下一步访问权限负责决定谁可以使用。</p></div><div class="empty-form-actions"><button class="primary-btn" data-first-action="go-policy">设置访问权限</button><button class="secondary-btn" data-first-action="go-dashboard">返回设置进度</button></div></section></div>`;return;}
 el.innerHTML=`<div class="first-run-shell"><div class="first-run-head"><div><div class="eyebrow">第 3 步 · 创建共享</div><h1>选择这台设备上要开放的服务</h1><p>这里定义“什么服务从哪里提供”。不会再创建一个新的共享密码或共享凭据。</p></div><span class="first-run-mode-pill">首次使用预览</span></div><section class="empty-workspace"><div class="empty-workspace-top"><span class="empty-workspace-icon">⇄</span><div><h2>创建第一个共享</h2><p>服务所在设备已经确定为 ${esc(firstRunState.deviceName)}。</p></div></div><div class="empty-form"><label>共享名称<input id="firstShareName" value="${esc(firstRunState.shareName)}"></label><div class="form-grid"><label>协议<select id="firstShareProtocol"><option>TCP</option><option>UDP</option><option>HTTP</option><option>HTTPS</option></select></label><label>端口<input id="firstSharePort" value="${esc(firstRunState.port)}" inputmode="numeric"></label></div><p class="empty-form-help">例如：SMB 文件服务通常使用 TCP 445，SSH 通常使用 TCP 22。</p><div class="first-run-success"><strong>这里不需要“共享凭据”</strong><p>Peerward 会使用提供设备已有的设备身份发布服务。</p></div><div class="empty-form-actions"><button class="primary-btn" data-first-action="create-first-share">创建共享并继续</button><button class="secondary-btn" data-first-action="go-dashboard">返回设置进度</button></div></div></section></div>`;
 setTimeout(()=>{const p=document.getElementById('firstShareProtocol');if(p)p.value=firstRunState.protocol;},0);
}
function renderFirstRunPolicy(){
 const el=document.getElementById('firstRunPolicy');if(!el)return;
 if(!firstRunState.share){el.innerHTML=lockedWorkspace('访问权限','访问权限需要一个明确的访问者和一个已经存在的共享服务。','请先创建第一个共享。','go-sharing');return;}
 if(firstRunState.access){el.innerHTML=`<div class="first-run-shell"><div class="first-run-head"><div><div class="eyebrow">第 4 步 · 已完成</div><h1>访问权限已经生效</h1><p>现在基础设置已经完整：设备有身份、共享有来源、访问者有明确授权。</p></div><span class="first-run-mode-pill">首次使用预览</span></div><section class="empty-workspace"><div class="empty-workspace-top"><span class="empty-workspace-icon success">✓</span><div><h2>权限已创建</h2><p>没有被明确授权的其他设备仍然会按默认拒绝策略被阻止。</p></div></div><div class="natural-rule-preview"><span>${esc(firstRunState.deviceName)}</span><b>可以访问</b><span>${esc(firstRunState.shareName)}</span></div><div class="empty-form-actions"><button class="primary-btn" data-first-action="go-dashboard">完成首次设置</button></div></section></div>`;return;}
 el.innerHTML=`<div class="first-run-shell"><div class="first-run-head"><div><div class="eyebrow">第 4 步 · 设置访问权限</div><h1>最后决定：谁可以使用这个共享</h1><p>Peerward 默认拒绝没有明确授权的访问。第一次设置时，先只允许刚添加的这台设备最容易理解。</p></div><span class="first-run-mode-pill">首次使用预览</span></div><section class="empty-workspace"><div class="empty-workspace-top"><span class="empty-workspace-icon">✓</span><div><h2>创建第一条访问权限</h2><p>以后可以改成设备组，让多台设备继承相同权限。</p></div></div><div class="natural-rule-preview"><span>${esc(firstRunState.deviceName)}</span><b>可以访问</b><span>${esc(firstRunState.shareName)}</span></div><div class="first-run-success"><strong>默认拒绝继续生效</strong><p>这条授权只开放上面这一项，不会让设备自动获得其他共享的访问权。</p></div><div class="empty-form-actions"><button class="primary-btn" data-first-action="create-first-access">创建访问权限</button><button class="secondary-btn" data-first-action="go-dashboard">返回设置进度</button></div></section></div>`;
}
function renderFirstRunOps(){
 const el=document.getElementById('firstRunOps');if(!el)return;
 const count=firstRunCompletedCount();
 el.innerHTML=`<div class="first-run-shell"><div class="first-run-head"><div><div class="eyebrow">首次使用 · 运维</div><h1>${count<4?'还没有需要处理的运维事项':'首次设置完成，当前没有异常'}</h1><p>${count<4?'刚开始时问题与维护不会用空告警和技术指标打扰你。完成基础设置后，这里只出现真正需要决定或操作的问题。':'设备上线、共享可用、访问权限明确；正常被规则阻止的访问也不会被误报成故障。'}</p></div><span class="first-run-mode-pill">首次使用预览</span></div><section class="empty-workspace"><div class="empty-workspace-top"><span class="empty-workspace-icon ${count===4?'success':''}">${count===4?'✓':'i'}</span><div><h2>${count===4?'当前没有待处理事项':'先完成首次设置'}</h2><p>控制服务、中继和 DNS 等底层组件仍会自动检查，但只有需要人工介入时才会出现在“待处理”。</p></div></div><div class="first-run-ops-grid"><div class="first-run-ops-card"><strong>正常阻止 ≠ 故障</strong><small>默认拒绝或访问规则拦截会记录为安全事件，不进入告警队列。</small></div><div class="first-run-ops-card"><strong>出现问题时直接给下一步</strong><small>例如设备离线会建议先检查电源和客户端，而不是只展示错误码。</small></div></div><div class="empty-form-actions"><button class="primary-btn" data-first-action="go-dashboard">查看首次设置进度</button></div></section></div>`;
}
function renderFirstRunUI(){
 renderFirstRunDashboard();renderFirstRunNetwork();renderFirstRunDevices();renderFirstRunSharing();renderFirstRunPolicy();renderFirstRunOps();updateFirstRunChrome();
}
function updateFirstRunChrome(){
 const name=document.getElementById('sidebarNetworkName'),status=document.getElementById('sidebarNetworkStatus'),link=document.getElementById('sidebarNetworkLink');
 if(firstRunMode){
   if(name)name.textContent=firstRunState.network?firstRunState.networkName:'尚未创建网络';
   if(status)status.innerHTML=firstRunState.network?'<i class="dot ok"></i> 首次设置中':'<i class="dot"></i> 等待设置';
   if(link)link.textContent=firstRunState.network?'网络设置':'开始设置';
   const devBadge=document.querySelector('.nav-item[data-route="devices"] .badge');if(devBadge)devBadge.textContent=firstRunState.device?'1':'0';
   const shareBadge=document.querySelector('.nav-item[data-route="sharing"] .badge');if(shareBadge)shareBadge.textContent=firstRunState.share?'1':'0';
   const opsBadge=document.getElementById('navOpsBadge');if(opsBadge)opsBadge.hidden=true;
 }else{
   if(window.__networkWorkspaceReady){applyNetworkChrome();renderNetworkScopedPage(location.hash.replace('#','')||'dashboard');}
   else{
     if(name)name.textContent=firstRunOriginal.networkName;if(status)status.innerHTML='<i class="dot ok"></i> 运行正常';if(link)link.textContent=firstRunOriginal.networkLink;
     const devBadge=document.querySelector('.nav-item[data-route="devices"] .badge');if(devBadge)devBadge.textContent=String(Object.keys(devices).length);
     const shareBadge=document.querySelector('.nav-item[data-route="sharing"] .badge');if(shareBadge)shareBadge.textContent=String(Object.keys(services).length);
     renderDashboardHealth();
   }
 }
}
function setFirstRunMode(value,reset=false){
 firstRunMode=!!value;document.body.classList.toggle('first-run-mode',firstRunMode);
 const btn=document.getElementById('firstRunPreviewBtn');if(btn)btn.textContent=firstRunMode?'退出首次设置体验':'体验首次设置';
 if(reset)Object.assign(firstRunState,{network:false,device:false,share:false,access:false,deviceTicketReady:false,networkName:'家庭网络',networkId:'home-mesh',deviceName:'我的笔记本',platform:'Linux',shareName:'我的第一个共享',protocol:'TCP',port:'445'});
 renderFirstRunUI();showRoute('dashboard');
}
function firstRunGo(route){showRoute(route);renderFirstRunUI();}

document.getElementById('firstRunPreviewBtn')?.addEventListener('click',()=>setFirstRunMode(!firstRunMode,!firstRunMode));
document.addEventListener('click',e=>{
 const b=e.target.closest('[data-first-action]');if(!b)return;const action=b.dataset.firstAction;
 if(action==='go-dashboard')return firstRunGo('dashboard');if(action==='go-network')return firstRunGo('network');if(action==='go-devices')return firstRunGo('devices');if(action==='go-sharing')return firstRunGo('sharing');if(action==='go-policy')return firstRunGo('policy');
 if(action==='create-network'){
   firstRunState.networkName=field('firstNetworkName')||'家庭网络';firstRunState.networkId=(field('firstNetworkId')||'home-mesh').trim();firstRunState.network=true;toast('网络已创建，接下来添加第一台设备');renderFirstRunUI();return firstRunGo('devices');
 }
 if(action==='prepare-first-device'){
   firstRunState.deviceName=field('firstDeviceName')||'我的笔记本';firstRunState.platform=field('firstDevicePlatform')||'Linux';firstRunState.deviceTicketReady=true;renderFirstRunUI();return;
 }
 if(action==='copy-first-command')return copyText(`peerward join --control https://control.peerward.local --ticket pw_join_FIRST_${firstRunState.networkId}`,'接入命令已复制');
 if(action==='simulate-device-online'){firstRunState.device=true;firstRunState.deviceTicketReady=false;toast('设备已上线，并获得自己的设备凭据');renderFirstRunUI();setTimeout(()=>firstRunGo('sharing'),260);return;}
 if(action==='create-first-share'){
   firstRunState.shareName=field('firstShareName')||'我的第一个共享';firstRunState.protocol=field('firstShareProtocol')||'TCP';firstRunState.port=field('firstSharePort')||'445';firstRunState.share=true;toast('共享已创建；没有生成共享凭据');renderFirstRunUI();setTimeout(()=>firstRunGo('policy'),260);return;
 }
 if(action==='create-first-access'){firstRunState.access=true;toast('访问权限已创建，默认拒绝仍然生效');renderFirstRunUI();setTimeout(()=>firstRunGo('dashboard'),260);return;}
 if(action==='reset-preview'){setFirstRunMode(true,true);toast('首次设置体验已重置');return;}
 if(action==='finish-preview'){setFirstRunMode(false,false);toast('已返回已配置的演示网络');return;}
});
renderFirstRunUI();

/* ---------------- v8: multi-network workspace ---------------- */
const networkProfiles = {
  'home-mesh':{
    id:'home-mesh',name:'家庭网络',icon:'⌂',avatarClass:'home',status:'healthy',statusText:'运行正常',role:'管理员',
    deviceTotal:6,online:5,shareTotal:3,shareHealthy:3,issues:2,lastActivity:'刚刚',range:'10.18.0.0/16',dns:true,
    description:'家庭设备、NAS 与个人服务',
    devices:[],shares:[],grants:[],issueList:[]
  },
  'work-lab':{
    id:'work-lab',name:'工作实验室',icon:'◇',avatarClass:'work',status:'attention',statusText:'1 项待处理',role:'管理员',
    deviceTotal:4,online:4,shareTotal:2,shareHealthy:1,issues:1,lastActivity:'6 分钟前',range:'10.42.0.0/16',dns:true,
    description:'开发、演示和内部测试资源',
    devices:[
      {name:'工作站',icon:'▰',platform:'Linux',address:'10.42.0.12',state:'online',meta:'受管设备 · 刚刚'},
      {name:'演示平板',icon:'▯',platform:'Android',address:'10.42.0.18',state:'online',meta:'个人设备 · 3 分钟前'},
      {name:'Staging API',icon:'▤',platform:'Linux',address:'10.42.0.31',state:'online',meta:'服务设备 · 6 分钟前'},
      {name:'CI Runner',icon:'▤',platform:'Linux',address:'10.42.0.44',state:'online',meta:'自动化设备 · 4 分钟前'}
    ],
    shares:[
      {name:'Staging Dashboard',host:'Staging API',endpoint:'https://staging.lab',state:'healthy',access:'开发设备组'},
      {name:'内部 API',host:'Staging API',endpoint:'api.lab:8443',state:'warning',access:'工作站、CI Runner'}
    ],
    grants:[
      {source:'开发设备组',target:'Staging Dashboard'},
      {source:'工作站',target:'内部 API'},
      {source:'CI Runner',target:'内部 API'}
    ],
    issueList:[{title:'内部 API 健康检查失败',summary:'服务设备在线，但 TCP 8443 最近一次检查超时。',action:'检查 Staging API 上的服务进程'}]
  },
  'test-sandbox':{
    id:'test-sandbox',name:'测试沙箱',icon:'□',avatarClass:'test',status:'idle',statusText:'空闲',role:'管理员',
    deviceTotal:1,online:0,shareTotal:0,shareHealthy:0,issues:0,lastActivity:'昨天',range:'10.77.0.0/16',dns:false,
    description:'临时验证配置，不影响其他网络',
    devices:[{name:'临时测试机',icon:'▰',platform:'Linux',address:'10.77.0.10',state:'offline',meta:'测试设备 · 昨天'}],
    shares:[],grants:[],issueList:[]
  }
};
let currentNetworkId='home-mesh';
let networkMenuOpen=false;

function currentNetwork(){return networkProfiles[currentNetworkId]||networkProfiles['home-mesh'];}
function networkDotClass(profile){return profile.status==='healthy'?'ok':profile.status==='attention'?'warn':'';}
function networkStatusHtml(profile){const cls=profile.status==='healthy'?'ok':profile.status==='attention'?'warn':'';return `<i class="dot ${cls}"></i> ${esc(profile.statusText)}`;}
function currentRoute(){return location.hash.replace('#','')||'dashboard';}

function ensureAlternateContainers(){
  ['dashboard','devices','sharing','policy','ops','network'].forEach(route=>{
    const page=document.querySelector(`.page[data-page="${route}"]`);if(!page||page.querySelector('.alternate-network-only'))return;
    const div=document.createElement('div');div.className='alternate-network-only';div.dataset.altPage=route;
    const first=page.querySelector('.first-run-only');if(first)first.insertAdjacentElement('afterend',div);else page.prepend(div);
  });
}
function networkAvatar(profile,size=''){return `<span class="network-avatar ${esc(profile.avatarClass||'home')} ${size}">${esc(profile.icon||'⌂')}</span>`;}
function networkContextStrip(profile){return `<section class="network-context-strip">${networkAvatar(profile)}<div class="network-context-copy"><strong>你正在操作：${esc(profile.name)}</strong><small>${esc(profile.id)} · ${esc(profile.description)}。这里的改动不会影响其他网络。</small></div><span class="network-scope-lock">独立安全边界</span><button class="secondary-btn small" data-open-network-menu="1">切换网络</button></section>`;}
function altPageHead(profile,title,desc,actions=''){return `<div class="alt-page-head"><div><div class="eyebrow">${esc(profile.name)}</div><h1>${title}</h1><p>${desc}</p></div>${actions?`<div class="head-actions">${actions}</div>`:''}</div>`;}
function altStats(profile){return `<div class="alt-stats-grid"><article class="alt-stat"><small>设备</small><strong>${profile.online}/${profile.deviceTotal}</strong><span>当前在线</span></article><article class="alt-stat"><small>共享</small><strong>${profile.shareHealthy}/${profile.shareTotal}</strong><span>当前可用</span></article><article class="alt-stat"><small>待处理</small><strong>${profile.issues}</strong><span>${profile.issues?'需要你的操作':'当前无事项'}</span></article><article class="alt-stat"><small>最近活动</small><strong style="font-size:16px">${esc(profile.lastActivity)}</strong><span>此网络范围内</span></article></div>`;}
function altDeviceRows(profile){
  if(!profile.devices.length)return `<div class="alt-empty"><span>▰</span><strong>这个网络还没有设备</strong><p>添加设备后，它只会出现在 ${esc(profile.name)}，不会自动加入其他网络。</p><button class="primary-btn" data-alt-action="add-device">＋ 添加第一台设备</button></div>`;
  return `<div class="alt-list">${profile.devices.map(d=>`<div class="alt-row"><span class="alt-row-icon">${esc(d.icon)}</span><div class="alt-row-copy"><strong>${esc(d.name)}</strong><small>${esc(d.platform)} · ${esc(d.address)}</small></div><div class="alt-row-meta"><span class="status-pill ${d.state==='online'?'good':'neutral'}">● ${d.state==='online'?'在线':'离线'}</span><small>${esc(d.meta.split(' · ').pop())}</small></div></div>`).join('')}</div>`;
}
function altShareRows(profile){
  if(!profile.shares.length)return `<div class="alt-empty"><span>⇄</span><strong>这个网络还没有共享</strong><p>共享只能使用本网络中的设备作为服务来源，访问权限也不会跨网络生效。</p><button class="primary-btn" data-alt-action="add-share" ${profile.online?'':'disabled'}>＋ 新建共享</button></div>`;
  return `<div class="alt-list">${profile.shares.map(s=>`<div class="alt-row"><span class="alt-row-icon">⇄</span><div class="alt-row-copy"><strong>${esc(s.name)}</strong><small>${esc(s.host)} · ${esc(s.endpoint)} · ${esc(s.access)}</small></div><div class="alt-row-meta"><span class="status-pill ${s.state==='healthy'?'good':'warn'}">${s.state==='healthy'?'● 可用':'! 需检查'}</span></div></div>`).join('')}</div>`;
}
function altGrantRows(profile){
  if(!profile.grants.length)return `<div class="alt-empty"><span>✓</span><strong>还没有访问授权</strong><p>默认拒绝已经生效。创建权限前，没有设备可以访问此网络中的共享。</p><button class="primary-btn" data-alt-action="add-access" ${profile.shareTotal?'':'disabled'}>＋ 添加访问权限</button></div>`;
  return `<div class="alt-list">${profile.grants.map(g=>`<div class="alt-grant"><span>${esc(g.source)}</span><b>可以访问</b><span>${esc(g.target)}</span></div>`).join('')}</div>`;
}
function altIssueRows(profile){
  if(!profile.issueList.length)return `<div class="alt-empty"><span>✓</span><strong>当前没有需要处理的事项</strong><p>健康检查和安全事件只在 ${esc(profile.name)} 范围内计算，不会把其他网络的问题混进来。</p></div>`;
  return `<div class="alt-list">${profile.issueList.map(i=>`<div class="alt-issue"><span>!</span><div><strong>${esc(i.title)}</strong><small>${esc(i.summary)}</small></div><button class="secondary-btn small" data-alt-action="issue">处理</button></div>`).join('')}</div>`;
}
function renderAlternateNetworkPage(route){
  const profile=currentNetwork();const box=document.querySelector(`.alternate-network-only[data-alt-page="${route}"]`);if(!box)return;
  let html=`<div class="alternate-network-shell">${networkContextStrip(profile)}`;
  if(route==='dashboard'){
    html+=altPageHead(profile,'仪表盘','这里只汇总当前网络的设备、共享和待处理事项。',`<button class="secondary-btn" data-alt-action="health">运行健康检查</button><button class="primary-btn" data-alt-route="ops">查看待处理</button>`)+altStats(profile)+`<div class="alt-grid"><section class="alt-section"><div class="alt-section-head"><div><h2>设备概况</h2><p>当前网络中的设备，不会混入其他网络。</p></div><button class="link-btn" data-alt-route="devices">查看全部 ›</button></div>${altDeviceRows({...profile,devices:profile.devices.slice(0,3)})}</section><section class="alt-section"><div class="alt-section-head"><div><h2>${profile.issues?'需要你处理':'共享状态'}</h2><p>${profile.issues?'按影响范围给出下一步。':'当前网络中的共享状态。'}</p></div><button class="link-btn" data-alt-route="${profile.issues?'ops':'sharing'}">查看 ›</button></div>${profile.issues?altIssueRows(profile):altShareRows(profile)}</section></div>`;
  }else if(route==='devices'){
    html+=altPageHead(profile,'设备','每台设备只属于它加入的网络。切换网络不会移动设备。',`<button class="primary-btn" data-alt-action="add-device">＋ 添加设备</button>`)+`<section class="alt-section"><div class="alt-section-head"><div><h2>全部设备 · ${profile.deviceTotal}</h2><p>${profile.online} 台在线</p></div></div>${altDeviceRows(profile)}</section>`;
  }else if(route==='sharing'){
    html+=altPageHead(profile,'共享','共享只能引用当前网络里的设备；访问范围也只在这个网络里生效。',`<button class="primary-btn" data-alt-action="add-share">＋ 新建共享</button>`)+`<section class="alt-section"><div class="alt-section-head"><div><h2>已共享服务 · ${profile.shareTotal}</h2><p>${profile.shareHealthy} 个当前可用</p></div></div>${altShareRows(profile)}</section>`;
  }else if(route==='policy'){
    html+=altPageHead(profile,'访问权限','用自然语言查看“谁可以访问什么”。没有明确授权时默认阻止。',`<button class="primary-btn" data-alt-action="add-access">＋ 添加访问权限</button>`)+`<section class="alt-section"><div class="alt-section-head"><div><h2>当前授权关系</h2><p>这些权限只属于 ${esc(profile.name)}。</p></div><span class="status-pill good">✓ 默认拒绝开启</span></div>${altGrantRows(profile)}</section>`;
  }else if(route==='ops'){
    html+=altPageHead(profile,'问题与维护','告警、健康检查和已知事项都按网络隔离，避免把不同环境的问题混在一起。',`<button class="secondary-btn" data-alt-action="health">刷新检查</button>`)+altStats(profile)+`<section class="alt-section"><div class="alt-section-head"><div><h2>需要你处理</h2><p>${profile.issues} 项来自当前网络</p></div></div>${altIssueRows(profile)}</section>`;
  }else if(route==='network'){
    html+=altPageHead(profile,'网络设置','先确认顶部网络名称，再修改配置。危险操作会明确标出影响的网络。',`<button class="primary-btn" data-alt-action="save-settings">保存更改</button>`)+`<div class="alt-settings-grid"><section class="alt-setting-card"><h2>基本信息</h2><div class="alt-setting-fact"><span>网络名称</span><strong>${esc(profile.name)}</strong></div><div class="alt-setting-fact"><span>网络标识</span><code>${esc(profile.id)}</code></div><div class="alt-setting-fact"><span>管理方式</span><strong>单管理员</strong></div></section><section class="alt-setting-card"><h2>网络功能</h2><div class="alt-setting-fact"><span>托管 DNS</span><strong>${profile.dns?'已开启':'已关闭'}</strong></div><div class="alt-setting-fact"><span>内部地址范围</span><code>${esc(profile.range)}</code></div><div class="alt-setting-fact"><span>资源访问</span><strong>已开启</strong></div></section><section class="alt-setting-card"><h2>当前规模</h2><div class="alt-setting-fact"><span>设备</span><strong>${profile.deviceTotal}</strong></div><div class="alt-setting-fact"><span>共享</span><strong>${profile.shareTotal}</strong></div><div class="alt-setting-fact"><span>待处理</span><strong>${profile.issues}</strong></div></section><section class="alt-setting-card alt-danger"><h2>危险操作 · ${esc(profile.name)}</h2><p class="field-help">删除只会影响这个网络，但其中设备会失去连接，已有共享和权限也会一起删除。</p><button class="danger-btn" data-alt-action="delete-network">删除 ${esc(profile.name)}</button></section></div>`;
  }
  html+='</div>';box.innerHTML=html;
}
function renderNetworkScopedPage(route=currentRoute()){
  ensureAlternateContainers();
  const isAlt=currentNetworkId!=='home-mesh'&&!firstRunMode;
  document.body.classList.toggle('alternate-network-mode',isAlt);
  if(isAlt&&route!=='networks')renderAlternateNetworkPage(route);
  if(route==='networks')renderNetworksPortfolio();
}
function renderNetworkMenu(filter=''){
  const list=document.getElementById('networkMenuList');if(!list)return;
  const q=filter.trim().toLowerCase();const items=Object.values(networkProfiles).filter(p=>!q||`${p.name} ${p.id} ${p.description}`.toLowerCase().includes(q));
  list.innerHTML=items.length?items.map(p=>`<button class="network-option ${p.id===currentNetworkId?'active':''}" data-network-id="${esc(p.id)}" role="option" aria-selected="${p.id===currentNetworkId}">${networkAvatar(p)}<span class="network-option-copy"><strong>${esc(p.name)}</strong><small>${esc(p.id)} · ${esc(p.description)}</small></span><span class="network-option-meta"><b>${p.deviceTotal} 台设备</b><small>${p.issues?`${p.issues} 项待处理`:p.statusText}</small></span></button>`).join(''):`<div class="alt-empty" style="padding:18px"><strong>没有找到网络</strong></div>`;
}
function renderNetworksPortfolio(){
  const el=document.getElementById('networkPortfolio');if(!el)return;
  el.innerHTML=Object.values(networkProfiles).map(p=>`<article class="network-portfolio-card ${p.id===currentNetworkId?'current':''}"><div class="network-portfolio-head">${networkAvatar(p)}<div class="network-portfolio-title"><strong>${esc(p.name)}</strong><small>${esc(p.id)}</small></div>${p.id===currentNetworkId?'<span class="current-network-pill">当前网络</span>':''}</div><div class="network-health-line"><i class="dot ${networkDotClass(p)}"></i><strong>${esc(p.statusText)}</strong><span>· 最近活动 ${esc(p.lastActivity)}</span></div><div class="network-card-stats"><div><small>设备</small><strong>${p.online}/${p.deviceTotal}</strong></div><div><small>共享</small><strong>${p.shareHealthy}/${p.shareTotal}</strong></div><div><small>待处理</small><strong>${p.issues}</strong></div></div><div class="network-card-attention ${p.issues?'':'ok'}">${p.issues?`有 ${p.issues} 项需要在这个网络里处理。`:'当前没有需要人工处理的事项。'}</div><div class="network-card-actions"><button class="${p.id===currentNetworkId?'secondary-btn':'primary-btn'} small" data-network-card-action="switch" data-network-id="${esc(p.id)}">${p.id===currentNetworkId?'正在使用':'切换到此网络'}</button><button class="secondary-btn small" data-network-card-action="settings" data-network-id="${esc(p.id)}">网络设置</button></div></article>`).join('');
}
function applyNetworkChrome(){
  if(firstRunMode)return;const p=currentNetwork();
  const name=document.getElementById('sidebarNetworkName');if(name)name.textContent=p.name;
  const status=document.getElementById('sidebarNetworkStatus');if(status)status.innerHTML=networkStatusHtml(p);
  const avatar=document.getElementById('sidebarNetworkAvatar');if(avatar){avatar.className=`network-avatar ${p.avatarClass}`;avatar.textContent=p.icon;}
  const topName=document.getElementById('topNetworkChipName');if(topName)topName.textContent=p.name;
  const topIcon=document.getElementById('topNetworkChipIcon');if(topIcon)topIcon.textContent=p.icon;
  const topDot=document.getElementById('topNetworkChipDot');if(topDot)topDot.className=`dot ${networkDotClass(p)}`;
  const scopeText=document.getElementById('topbarScopeText');if(scopeText)scopeText.textContent=`${p.name} · ${p.statusText||'正常'}`;
  const dashboardNetworkTitle=document.getElementById('dashboardNetworkTitle');if(dashboardNetworkTitle)dashboardNetworkTitle.textContent=p.name;
  document.querySelectorAll('.page-head .eyebrow').forEach(el=>{if(!el.closest('[data-page="networks"]'))el.textContent=p.name;});
  const devBadge=document.querySelector('.nav-item[data-route="devices"] .badge');if(devBadge)devBadge.textContent=String(p.deviceTotal);
  const shareBadge=document.querySelector('.nav-item[data-route="sharing"] .badge');if(shareBadge)shareBadge.textContent=String(p.shareTotal);
  const opsBadge=document.getElementById('navOpsBadge');if(opsBadge){opsBadge.textContent=String(p.issues);opsBadge.hidden=!p.issues;}
  renderNetworkMenu(document.getElementById('networkMenuSearch')?.value||'');renderNetworksPortfolio();
}
function closeNetworkMenu(){const menu=document.getElementById('networkMenu'),btn=document.getElementById('networkSwitch');if(menu)menu.hidden=true;if(btn)btn.setAttribute('aria-expanded','false');networkMenuOpen=false;}
function openNetworkMenu(){if(firstRunMode)return;const menu=document.getElementById('networkMenu'),btn=document.getElementById('networkSwitch');if(menu)menu.hidden=false;if(btn)btn.setAttribute('aria-expanded','true');renderNetworkMenu();networkMenuOpen=true;setTimeout(()=>document.getElementById('networkMenuSearch')?.focus(),0);}
function toggleNetworkMenu(){networkMenuOpen?closeNetworkMenu():openNetworkMenu();}
function switchNetwork(id,route=null){
  if(!networkProfiles[id]||id===currentNetworkId){closeNetworkMenu();if(route)showRoute(route);return;}
  if(typeof closeDrawer==='function')closeDrawer();if(typeof closeServiceDrawer==='function')closeServiceDrawer();
  currentNetworkId=id;closeNetworkMenu();applyNetworkChrome();renderNetworkScopedPage(route||currentRoute());
  if(route)showRoute(route);toast(`已切换到 ${networkProfiles[id].name} · 后续操作只影响此网络`);
}
function openNetworkCreate(){closeNetworkMenu();const b=document.getElementById('networkCreateBackdrop');if(b)b.hidden=false;setTimeout(()=>document.getElementById('newNetworkName')?.focus(),0);}
function closeNetworkCreate(){const b=document.getElementById('networkCreateBackdrop');if(b)b.hidden=true;}
function createNetworkFromModal(){
  const name=field('newNetworkName').trim()||'新网络';let id=field('newNetworkId').trim().toLowerCase().replace(/[^a-z0-9-]+/g,'-').replace(/^-|-$/g,'');if(!id)id='network-'+Date.now();
  if(networkProfiles[id]){toast('这个网络标识已经存在');return;}
  networkProfiles[id]={id,name,icon:'＋',avatarClass:'new',status:'healthy',statusText:'刚创建',role:'管理员',deviceTotal:0,online:0,shareTotal:0,shareHealthy:0,issues:0,lastActivity:'刚刚',range:'自动分配',dns:true,description:'新创建的独立网络',devices:[],shares:[],grants:[],issueList:[]};
  closeNetworkCreate();renderNetworksPortfolio();switchNetwork(id,'dashboard');toast(`${name} 已创建 · 现在可以添加第一台设备`);
}

document.getElementById('networkSwitch')?.addEventListener('click',e=>{e.stopPropagation();toggleNetworkMenu();});
document.getElementById('topNetworkChip')?.addEventListener('click',e=>{e.stopPropagation();toggleNetworkMenu();});
document.getElementById('networkMenu')?.addEventListener('click',e=>e.stopPropagation());
document.getElementById('networkMenuList')?.addEventListener('click',e=>{const b=e.target.closest('[data-network-id]');if(b)switchNetwork(b.dataset.networkId);});
document.getElementById('networkMenuSearch')?.addEventListener('input',e=>renderNetworkMenu(e.target.value));
document.getElementById('manageNetworksBtn')?.addEventListener('click',()=>{closeNetworkMenu();showRoute('networks');});
document.getElementById('newNetworkQuickBtn')?.addEventListener('click',openNetworkCreate);
document.getElementById('createNetworkBtn')?.addEventListener('click',openNetworkCreate);
document.getElementById('closeNetworkCreate')?.addEventListener('click',closeNetworkCreate);
document.getElementById('cancelNetworkCreate')?.addEventListener('click',closeNetworkCreate);
document.getElementById('networkCreateBackdrop')?.addEventListener('click',e=>{if(e.target.id==='networkCreateBackdrop')closeNetworkCreate();});
document.getElementById('confirmNetworkCreate')?.addEventListener('click',createNetworkFromModal);
document.getElementById('networkPortfolio')?.addEventListener('click',e=>{const b=e.target.closest('[data-network-card-action]');if(!b)return;const id=b.dataset.networkId;if(b.dataset.networkCardAction==='switch')switchNetwork(id);else switchNetwork(id,'network');});
document.addEventListener('click',e=>{if(networkMenuOpen&&!e.target.closest('#networkCard')&&!e.target.closest('#topNetworkChip'))closeNetworkMenu();});
document.addEventListener('click',e=>{
  const open=e.target.closest('[data-open-network-menu]');if(open){openNetworkMenu();return;}
  const nav=e.target.closest('[data-alt-route]');if(nav){showRoute(nav.dataset.altRoute);return;}
  const action=e.target.closest('[data-alt-action]');if(!action)return;const p=currentNetwork();
  if(action.dataset.altAction==='health'){toast(`${p.name} 健康检查完成 · ${p.issues?p.issues+' 项仍需处理':'当前正常'}`);return;}
  if(action.dataset.altAction==='save-settings'){toast(`${p.name} 的设置已保存（原型）`);return;}
  if(action.dataset.altAction==='add-device'){toast(`将在 ${p.name} 中创建设备加入凭据，不会影响其他网络`);return;}
  if(action.dataset.altAction==='add-share'){toast(`将在 ${p.name} 中创建共享；只能选择此网络的设备`);return;}
  if(action.dataset.altAction==='add-access'){toast(`将在 ${p.name} 中添加访问权限；默认拒绝继续生效`);return;}
  if(action.dataset.altAction==='issue'){toast(`已打开 ${p.name} 的问题处理流程（原型）`);return;}
  if(action.dataset.altAction==='delete-network'){if(confirm(`确认删除“${p.name}”？\n\n只会删除这个网络，但其中设备、共享和访问权限都会失效。`))toast('原型：正式版会要求再次输入网络名称确认');return;}
});

ensureAlternateContainers();
window.__networkWorkspaceReady=true;
applyNetworkChrome();
renderNetworkScopedPage(currentRoute());

/* ---------------- v10: single-admin audit & guarded high-risk actions ---------------- */
routeTitles.audit='操作记录';
Object.values(networkProfiles).forEach(p=>{p.role='管理员';p.userRole='admin';});

function actorName(){return '管理员';}

const auditEvents=[
  {id:1,networkId:'home-mesh',date:'今天',time:'08:05',action:'更新访问权限',detail:'家庭成员 → 家庭 NAS 文件服务',actor:'管理员',actorRole:'单人管理',target:'访问权限',risk:'normal',result:'成功',reason:'新增家庭设备访问范围'},
  {id:2,networkId:'home-mesh',date:'今天',time:'07:46',action:'请求设备更新身份',detail:'开发服务器 · cred_bf16…0a0d',actor:'管理员',actorRole:'单人管理',target:'开发服务器',risk:'normal',result:'成功',reason:'设备身份即将到期'},
  {id:3,networkId:'home-mesh',date:'今天',time:'07:20',action:'暂停共享',detail:'家庭 Dashboard · HTTPS 443',actor:'管理员',actorRole:'单人管理',target:'家庭 Dashboard',risk:'high',result:'成功',reason:'短时维护'},
  {id:4,networkId:'work-lab',date:'今天',time:'08:31',action:'创建共享',detail:'内部 API · TCP 8443',actor:'管理员',actorRole:'单人管理',target:'内部 API',risk:'normal',result:'成功',reason:''},
  {id:5,networkId:'test-sandbox',date:'昨天',time:'16:40',action:'运行健康检查',detail:'测试沙箱全量检查',actor:'系统',actorRole:'自动任务',target:'网络',risk:'normal',result:'成功',reason:''}
];
function nowHM(){return new Intl.DateTimeFormat('zh-CN',{hour:'2-digit',minute:'2-digit',hour12:false}).format(new Date());}
function addAuditEvent({action,detail='',target='',risk='normal',result='成功',reason='',networkId=currentNetworkId,actor=actorName(),actorRole='单人管理'}){
  auditEvents.unshift({id:Date.now()+Math.random(),networkId,date:'今天',time:nowHM(),action,detail,actor,actorRole,target,risk,result,reason});
  if(currentRoute()==='audit')renderAuditUI();
}
function auditNetworkSelection(){return document.getElementById('auditNetworkFilter')?.value||'current';}
function filteredAuditEvents(){
  const q=(document.getElementById('auditSearch')?.value||'').trim().toLowerCase();
  const net=auditNetworkSelection();
  const risk=document.getElementById('auditRiskFilter')?.value||'all';
  return auditEvents.filter(e=>(net==='all'||e.networkId===currentNetworkId)&&(risk==='all'||(risk==='high'?e.risk==='high':e.risk!=='high'))&&(!q||`${e.action} ${e.detail} ${e.actor} ${e.target} ${e.reason}`.toLowerCase().includes(q)));
}
function renderAuditUI(){
  const p=currentNetwork();
  const eye=document.getElementById('auditEyebrow');if(eye)eye.textContent=p.name;
  const net=document.getElementById('auditNetworkFilter');if(net&&net.options[0])net.options[0].textContent=`当前网络 · ${p.name}`;
  const base=auditEvents.filter(e=>auditNetworkSelection()==='all'||e.networkId===currentNetworkId);
  const tc=document.getElementById('auditTodayCount');if(tc)tc.textContent=String(base.filter(e=>e.date==='今天').length);
  const hc=document.getElementById('auditHighCount');if(hc)hc.textContent=String(base.filter(e=>e.risk==='high').length);
  const dc=document.getElementById('auditDeniedCount');if(dc)dc.textContent=String(base.filter(e=>e.result!=='成功').length);
  const list=document.getElementById('auditList');if(!list)return;
  const events=filteredAuditEvents();
  list.innerHTML=events.length?events.map(e=>{
    const netName=networkProfiles[e.networkId]?.name||e.networkId;
    const icon=e.result==='成功'?(e.risk==='high'?'!':'✓'):'×';
    return `<div class="audit-row"><time class="audit-time">${esc(e.date)}<br>${esc(e.time)}</time><span class="audit-icon ${e.risk==='high'?'high':''}">${icon}</span><div class="audit-copy"><strong>${esc(e.action)}</strong><small>${esc(e.detail)}${e.reason?` · 原因：${esc(e.reason)}`:''}</small></div><div class="audit-actor"><strong>${esc(e.actor)}</strong><small>${esc(e.actorRole)}</small></div><div class="audit-target"><strong>${esc(e.target||'—')}</strong><small>${esc(netName)}</small></div><span class="audit-risk ${e.risk==='high'?'high':''}">${e.risk==='high'?'高风险':e.result!=='成功'?'失败':'普通'}</span></div>`;
  }).join(''):`<div class="audit-empty">没有匹配的操作记录。</div>`;
}

let pendingRiskAction=null;
function openRiskAction({title,summary,target,impact,risk='high',confirmText='',confirmLabel='确认操作',onConfirm}){
  pendingRiskAction={onConfirm,confirmText};const back=document.getElementById('riskBackdrop');if(!back)return;
  document.getElementById('riskEyebrow').textContent=risk==='high'?'高风险操作':'需要确认';
  document.getElementById('riskTitle').textContent=title;
  document.getElementById('riskSummary').textContent=summary;
  document.getElementById('riskFacts').innerHTML=`<div class="risk-fact"><small>当前网络</small><strong>${esc(currentNetwork().name)} · ${esc(currentNetworkId)}</strong></div><div class="risk-fact"><small>影响对象</small><strong>${esc(target||'当前对象')}</strong></div><div class="risk-fact"><small>影响</small><strong>${esc(impact||'配置会立即生效')}</strong></div><div class="risk-fact"><small>执行身份</small><strong>${esc(actorName())} · 单人管理</strong></div>`;
  const phrase=document.getElementById('riskConfirmPhrase'),label=document.getElementById('riskPhraseLabel'),input=document.getElementById('riskPhraseInput'),btn=document.getElementById('confirmRiskAction');
  document.getElementById('riskReason').value='';
  phrase.hidden=!confirmText;label.textContent=confirmText;input.value='';btn.textContent=confirmLabel;btn.disabled=!!confirmText;back.hidden=false;
  setTimeout(()=>confirmText?input.focus():document.getElementById('riskReason').focus(),0);
}
function closeRiskAction(){const b=document.getElementById('riskBackdrop');if(b)b.hidden=true;pendingRiskAction=null;}
function confirmRiskAction(){if(!pendingRiskAction)return;const reason=document.getElementById('riskReason').value.trim();const fn=pendingRiskAction.onConfirm;closeRiskAction();fn?.(reason);}

// Replace one-click destructive operations with a consistent confirmation flow.
document.addEventListener('click',e=>{
  const btn=e.target.closest('button,[data-alt-action],[data-remove-scope]');if(!btn)return;const id=btn.id;
  if(id==='revokeCredentialBtn'){
    e.preventDefault();e.stopImmediatePropagation();const d=devices[currentDeviceName];
    openRiskAction({title:`撤销 ${currentDeviceName} 的设备凭据`,summary:'撤销后，这台设备会立即失去 Peerward 身份，现有连接会中断；要再次使用必须重新加入网络。',target:currentDeviceName,impact:'设备离线，需重新加入',confirmText:currentDeviceName,confirmLabel:'撤销设备凭据',onConfirm:(reason)=>{d.credential='已撤销';d.status='offline';addAuditEvent({action:'撤销设备凭据',detail:d.credentialSerial,target:currentDeviceName,risk:'high',reason});renderDrawerSummary();renderDrawerTab();toast(`${currentDeviceName} 的设备凭据已撤销（原型）`);}});return;
  }
  if(id==='disableDeviceBtn'){
    e.preventDefault();e.stopImmediatePropagation();const d=devices[currentDeviceName];
    openRiskAction({title:`停用 ${currentDeviceName}`,summary:'停用会阻断这台设备继续连接当前网络，但保留操作记录和设备信息，便于之后核查。',target:currentDeviceName,impact:'设备连接将被阻断',confirmLabel:'确认停用设备',onConfirm:(reason)=>{d.status='offline';d.disabled=true;addAuditEvent({action:'停用设备',detail:d.address,target:currentDeviceName,risk:'high',reason});renderDrawerSummary();toast(`${currentDeviceName} 已停用（原型）`);}});return;
  }
  if(id==='pauseShareBtn'){
    const svc=services[currentServiceName];if(!svc)return;if(svc.status==='paused'){addAuditEvent({action:'恢复共享',detail:`${svc.protocol} ${svc.port}`,target:currentServiceName,risk:'normal'});return;}
    e.preventDefault();e.stopImmediatePropagation();openRiskAction({title:`暂停 ${currentServiceName}`,summary:'暂停后，已经获得访问权限的设备也会暂时无法使用这个资源；已有访问规则会保留。',target:currentServiceName,impact:'资源立即不可达，权限规则保留',confirmLabel:'暂停资源',onConfirm:(reason)=>{svc.status='paused';addAuditEvent({action:'暂停资源',detail:`${svc.protocol} ${svc.port}`,target:currentServiceName,risk:'high',reason});openServiceDrawer(currentServiceName,currentServiceTab);renderServices(document.getElementById('shareSearchInput')?.value||'');toast('资源已暂停');}});return;
  }
  if(id==='detailRevokeBtn'){
    e.preventDefault();e.stopImmediatePropagation();if(!selectedPolicyCell)return;const {source,target}=selectedPolicyCell;const svc=services[target];if(!svc)return;
    openRiskAction({title:`撤销 ${source} 的访问权限`,summary:`撤销后，“${source}”将不再能访问“${target}”。如果权限来自设备组，请在设备组授权中修改。`,target:`${source} → ${target}`,impact:'访问会按默认拒绝策略阻止',confirmLabel:'撤销访问权限',onConfirm:(reason)=>{const idx=svc.scopes.findIndex(scope=>scope.name===source);if(idx>=0)svc.scopes.splice(idx,1);addAuditEvent({action:'撤销访问权限',detail:`${source} → ${target}`,target:'访问权限',risk:'high',reason});selectedPolicyCell=null;renderPolicyUI();renderPolicyDetail(source,target);renderServices(document.getElementById('shareSearchInput')?.value||'');toast('访问权限已撤销');}});return;
  }
  if(btn.hasAttribute('data-remove-scope')){
    e.preventDefault();e.stopImmediatePropagation();const svc=services[currentServiceName],idx=Number(btn.dataset.removeScope),scope=svc?.scopes?.[idx];if(!svc||!scope)return;
    openRiskAction({title:`移除 ${scope.name} 的访问范围`,summary:`“${scope.name}”将不能继续访问“${currentServiceName}”，其他访问范围不受影响。`,target:`${scope.name} → ${currentServiceName}`,impact:'该来源的访问将被阻止',confirmLabel:'移除访问权限',onConfirm:(reason)=>{svc.scopes.splice(idx,1);addAuditEvent({action:'移除共享访问范围',detail:`${scope.name} → ${currentServiceName}`,target:currentServiceName,risk:'high',reason});renderServiceTab();renderServiceSummary();renderServices(document.getElementById('shareSearchInput')?.value||'');renderPolicyUI();toast(`已移除“${scope.name}”的访问权限`);}});return;
  }
  if(id==='deleteNetworkBtn'||btn.dataset.altAction==='delete-network'){
    e.preventDefault();e.stopImmediatePropagation();const p=currentNetwork(),deleteId=currentNetworkId;
    openRiskAction({title:`删除 ${p.name}`,summary:'这是网络级不可撤销操作。这个网络里的设备会失去连接，共享、访问权限和网络配置都会一起删除。',target:p.name,impact:`${p.deviceTotal} 台设备、${p.shareTotal} 个共享`,confirmText:p.name,confirmLabel:'永久删除网络',onConfirm:(reason)=>{addAuditEvent({action:'删除网络',detail:`${p.name} · ${p.id}`,target:p.name,risk:'high',reason,networkId:deleteId});if(deleteId==='home-mesh'){toast('原型：已完成完整确认流程；为保留主演示数据，没有实际删除家庭网络');return;}delete networkProfiles[deleteId];switchNetwork('home-mesh','networks');renderNetworksPortfolio();toast(`${p.name} 已删除（原型）`);}});return;
  }
},true);

// Risk modal controls.
document.getElementById('closeRiskModal')?.addEventListener('click',closeRiskAction);
document.getElementById('cancelRiskModal')?.addEventListener('click',closeRiskAction);
document.getElementById('riskBackdrop')?.addEventListener('click',e=>{if(e.target.id==='riskBackdrop')closeRiskAction();});
document.getElementById('riskPhraseInput')?.addEventListener('input',e=>{const btn=document.getElementById('confirmRiskAction');if(btn)btn.disabled=e.target.value.trim()!==(pendingRiskAction?.confirmText||'');});
document.getElementById('confirmRiskAction')?.addEventListener('click',confirmRiskAction);

// Audit filtering / export.
['auditSearch','auditNetworkFilter','auditRiskFilter'].forEach(id=>document.getElementById(id)?.addEventListener(id==='auditSearch'?'input':'change',renderAuditUI));
document.getElementById('exportAuditBtn')?.addEventListener('click',()=>{
  const lines=filteredAuditEvents().map(e=>`${e.date} ${e.time}\t${networkProfiles[e.networkId]?.name||e.networkId}\t${e.actor}(${e.actorRole})\t${e.action}\t${e.target}\t${e.result}\t${e.reason||''}`).join('\n');
  downloadText(`peerward-operations-${currentNetworkId}.tsv`,`时间\t网络\t操作者\t操作\t对象\t结果\t原因\n${lines}`);
});

// Normal changes also enter the operation log.
document.addEventListener('click',e=>{
  if(e.target.closest('#saveNetworkSettingsBtn')){addAuditEvent({action:'保存网络设置',detail:currentNetwork().id,target:'网络设置',risk:'normal'});toast('网络设置已保存（原型）');}
  if(e.target.closest('#rotateCredentialBtn'))addAuditEvent({action:'请求设备更新身份',detail:devices[currentDeviceName]?.credentialSerial||'',target:currentDeviceName,risk:'normal'});
},false);
document.addEventListener('click',e=>{if(e.target.id!=='modalNext')return;const max=wizardConfig[modalType]?.steps?.length||0;if(modalStep<max)return;const type=modalType,s={...wizardState};setTimeout(()=>{if(type==='device')addAuditEvent({action:'添加设备',detail:s.name||'新设备',target:s.name||'设备',risk:'normal'});if(type==='share')addAuditEvent({action:'创建共享',detail:`${s.protocol||''} ${s.port||''}`.trim(),target:s.name||'共享',risk:'normal'});if(type==='rule')addAuditEvent({action:'添加访问权限',detail:`${s.source||''} → ${s.target||''}`,target:'访问权限',risk:'normal'});},0);},true);

// The operation-log page stays global even while another network's scoped renderer is active.
const v10BaseRenderNetworkScopedPage=renderNetworkScopedPage;
renderNetworkScopedPage=function(route=currentRoute()){
  if(route==='audit'){document.body.classList.remove('alternate-network-mode');renderAuditUI();return;}
  v10BaseRenderNetworkScopedPage(route);
};
const v10BaseShowRoute=showRoute;
showRoute=function(route,context=null){if(route==='team')route='dashboard';v10BaseShowRoute(route,context);if(route==='audit')renderAuditUI();};
const v10BaseSwitchNetwork=switchNetwork;
switchNetwork=function(id,route=null){if(networkProfiles[id]){networkProfiles[id].role='管理员';networkProfiles[id].userRole='admin';}v10BaseSwitchNetwork(id,route);if(currentRoute()==='audit')renderAuditUI();};

renderAuditUI();
const v10InitialRoute=location.hash.replace('#','');if(v10InitialRoute==='team')showRoute('dashboard');else if(v10InitialRoute==='audit')showRoute('audit');

/* ---------------- v12: global search / notifications / single-admin session ---------------- */
const v12NotificationRead = new Set();
let v12NotificationScope = 'all';
let v12CommandItems = [];
let v12CommandActive = 0;

function v12NetworkName(id){ return networkProfiles[id]?.name || id || '当前网络'; }
function v12CurrentObjectDevices(){
  if(currentNetworkId==='home-mesh') return Object.entries(devices).map(([name,d])=>({name,meta:`${d.platform} · ${d.address} · ${d.status==='online'?'在线':'离线'}`}));
  return (currentNetwork().devices||[]).map(d=>({name:d.name,meta:`${d.platform} · ${d.address} · ${d.state==='online'?'在线':'离线'}`}));
}
function v12CurrentObjectShares(){
  if(currentNetworkId==='home-mesh') return Object.entries(services).map(([name,s])=>({name,meta:`${s.device} · ${s.protocol} ${s.port}`,state:s.status}));
  return (currentNetwork().shares||[]).map(s=>({name:s.name,meta:`${s.host} · ${s.endpoint}`,state:s.state}));
}

function v12SearchItems(){
  const items=[];
  const pages=[
    ['dashboard','仪表盘','查看当前网络概况和需要处理的事项','⌂'],['devices','设备','管理设备、状态和设备身份','▣'],['sharing','共享','管理 NAS、网站、SSH 等共享服务','⇄'],['policy','访问权限','决定谁可以使用哪个共享','✓'],['ops','运维','健康检查、告警和处理队列','≋'],['networks','所有网络','查看并切换多个独立网络','◇'],['network','网络设置','修改当前网络的基础设置','⚙'],['audit','操作记录','查看管理员和系统的配置变更','≡']
  ];
  pages.forEach(([route,title,desc,icon])=>items.push({type:'page',group:'功能',title,desc,icon,meta:'打开页面',route}));
  v12CurrentObjectDevices().forEach(d=>items.push({type:'device',group:'当前网络设备',title:d.name,desc:d.meta,icon:'▣',meta:v12NetworkName(currentNetworkId),networkId:currentNetworkId}));
  v12CurrentObjectShares().forEach(s=>items.push({type:'share',group:'当前共享',title:s.name,desc:s.meta,icon:'⇄',meta:v12NetworkName(currentNetworkId),networkId:currentNetworkId}));
  Object.values(networkProfiles).forEach(p=>items.push({type:'network',group:'网络',title:p.name,desc:`${p.deviceTotal} 台设备 · ${p.shareTotal} 个共享 · ${p.statusText}`,icon:p.icon||'◇',meta:p.id,networkId:p.id}));
  items.push(
    {type:'action',group:'快捷操作',title:'添加设备',desc:'生成一次性加入方式并等待设备上线',icon:'＋',meta:'快捷操作',action:'add-device'},
    {type:'action',group:'快捷操作',title:'新建共享',desc:'选择提供设备、协议、端口和访问范围',icon:'⇄',meta:'快捷操作',action:'add-share'},
    {type:'action',group:'快捷操作',title:'添加访问权限',desc:'选择“谁可以访问哪个共享”',icon:'✓',meta:'快捷操作',action:'add-rule'},
    {type:'action',group:'快捷操作',title:'运行健康检查',desc:'检查当前网络的设备、共享和关键组件',icon:'↻',meta:'快捷操作',action:'health'}
  );
  return items;
}
function v12CommandMatches(item,q){
  if(!q) return true;
  const hay=`${item.title} ${item.desc} ${item.meta} ${item.group}`.toLowerCase();
  return q.toLowerCase().split(/\s+/).filter(Boolean).every(k=>hay.includes(k));
}
function v12RenderCommandResults(query=''){
  const box=document.getElementById('commandResults'); if(!box)return;
  const q=query.trim();
  let results=v12SearchItems().filter(x=>v12CommandMatches(x,q));
  if(!q){
    const preferred=['action','device','share','network','page'];
    results=results.sort((a,b)=>preferred.indexOf(a.type)-preferred.indexOf(b.type)).slice(0,12);
  }else results=results.slice(0,24);
  v12CommandItems=results; v12CommandActive=Math.min(v12CommandActive,Math.max(0,results.length-1));
  if(!results.length){box.innerHTML='<div class="command-empty"><div><strong>没有找到匹配结果</strong><span>可以搜索设备名、共享名、网络名，或输入“健康检查”“访问权限”等功能名称。</span></div></div>';return;}
  const groups=[];
  results.forEach((it,idx)=>{let g=groups.find(x=>x.name===it.group);if(!g){g={name:it.group,items:[]};groups.push(g)}g.items.push([it,idx])});
  box.innerHTML=groups.map(g=>`<div class="command-group"><div class="command-group-label">${esc(g.name)}</div>${g.items.map(([it,idx])=>`<button class="command-result ${idx===v12CommandActive?'active':''}" data-command-index="${idx}" role="option" aria-selected="${idx===v12CommandActive}"><span class="command-result-icon">${esc(it.icon)}</span><span class="command-result-copy"><strong>${esc(it.title)}</strong><small>${esc(it.desc)}</small></span><span class="command-result-meta">${esc(it.meta)}</span></button>`).join('')}</div>`).join('');
  box.querySelector('.command-result.active')?.scrollIntoView({block:'nearest'});
}
function v12UpdateCommandContext(){
  const el=document.getElementById('commandContext');if(!el)return;
  el.innerHTML=`<span class="context-dot"></span><strong>当前网络：${esc(currentNetwork().name)}</strong><small>搜索会优先显示当前网络对象，也可以直接切换网络。</small>`;
}
function v12OpenCommand(){
  const back=document.getElementById('commandBackdrop');if(!back)return;
  closeNetworkMenu?.(); v12CloseAdminMenu(); v12CloseNotifications();
  back.hidden=false;v12CommandActive=0;v12UpdateCommandContext();
  const input=document.getElementById('globalSearchInput');input.value='';v12RenderCommandResults('');setTimeout(()=>input.focus(),0);
}
function v12CloseCommand(){const b=document.getElementById('commandBackdrop');if(b)b.hidden=true;}
function v12RunCommand(item){
  if(!item)return;v12CloseCommand();
  if(item.type==='page'){showRoute(item.route);return;}
  if(item.type==='network'){switchNetwork(item.networkId,'dashboard');return;}
  if(item.type==='device'){
    if(item.networkId!==currentNetworkId)switchNetwork(item.networkId,'devices');else showRoute('devices');
    if(item.networkId==='home-mesh')setTimeout(()=>openDrawer(item.title,'overview'),40);return;
  }
  if(item.type==='share'){
    if(item.networkId!==currentNetworkId)switchNetwork(item.networkId,'sharing');else showRoute('sharing');
    if(item.networkId==='home-mesh')setTimeout(()=>openServiceDrawer(item.title,'overview'),40);return;
  }
  if(item.type==='action'){
    if(item.action==='add-device'){showRoute('devices');setTimeout(()=>openModal('device'),40)}
    if(item.action==='add-share'){showRoute('sharing');setTimeout(()=>openModal('share'),40)}
    if(item.action==='add-rule'){showRoute('policy');setTimeout(()=>openModal('rule'),40)}
    if(item.action==='health'){showRoute('ops');setTimeout(()=>runHealthCheck('ops'),80)}
  }
}

document.getElementById('searchBtn')?.addEventListener('click',v12OpenCommand);
document.getElementById('commandBackdrop')?.addEventListener('click',e=>{if(e.target.id==='commandBackdrop')v12CloseCommand()});
document.getElementById('globalSearchInput')?.addEventListener('input',e=>{v12CommandActive=0;v12RenderCommandResults(e.target.value)});
document.getElementById('commandResults')?.addEventListener('click',e=>{const b=e.target.closest('[data-command-index]');if(b)v12RunCommand(v12CommandItems[Number(b.dataset.commandIndex)])});
document.addEventListener('keydown',e=>{
  if((e.ctrlKey||e.metaKey)&&e.key.toLowerCase()==='k'){e.preventDefault();v12OpenCommand();return;}
  const back=document.getElementById('commandBackdrop');if(!back||back.hidden)return;
  if(e.key==='Escape'){e.preventDefault();v12CloseCommand();return;}
  if(e.key==='ArrowDown'){e.preventDefault();v12CommandActive=Math.min(v12CommandItems.length-1,v12CommandActive+1);v12RenderCommandResults(field('globalSearchInput'));}
  if(e.key==='ArrowUp'){e.preventDefault();v12CommandActive=Math.max(0,v12CommandActive-1);v12RenderCommandResults(field('globalSearchInput'));}
  if(e.key==='Enter'){e.preventDefault();v12RunCommand(v12CommandItems[v12CommandActive]);}
});

function v12BuildNotifications(){
  const out=[];
  buildOpsIssues().filter(i=>i.state==='open').forEach(i=>{
    out.push({id:`home:${i.id}`,networkId:'home-mesh',kind:'action',severity:i.severity,title:i.title,summary:i.summary,time:'刚刚',actionLabel:'处理',source:i});
  });
  Object.values(networkProfiles).filter(p=>p.id!=='home-mesh').forEach(p=>{
    (p.issueList||[]).forEach((i,idx)=>out.push({id:`${p.id}:issue:${idx}`,networkId:p.id,kind:'action',severity:p.status==='attention'?'warning':'info',title:i.title,summary:i.summary,time:p.lastActivity,actionLabel:'查看',source:i}));
  });
  out.push(
    {id:'home:blocked-ssh',networkId:'home-mesh',kind:'info',severity:'info',title:'Android 手机访问 SSH 已按规则阻止',summary:'设备不属于“开发设备”访问范围。这是正常的默认拒绝，不需要处理。',time:'2 小时前',actionLabel:'查看权限'},
    {id:'home:health-ok',networkId:'home-mesh',kind:'info',severity:'info',title:'关键组件健康检查通过',summary:'控制服务、中继、托管 DNS 和数据库均正常。',time:'今天 09:36',actionLabel:'查看状态'},
    {id:'test:idle',networkId:'test-sandbox',kind:'info',severity:'info',title:'测试沙箱已空闲 1 天',summary:'临时测试机离线，但该网络没有共享和待处理事项。',time:'昨天',actionLabel:'查看网络'}
  );
  return out;
}
function v12UnreadCount(){return v12BuildNotifications().filter(n=>!v12NotificationRead.has(n.id)).length;}
function v12RenderNotificationBadge(){
  const b=document.getElementById('notificationBadge');if(!b)return;const n=v12UnreadCount();b.textContent=n>9?'9+':String(n);b.hidden=!n;
}
function v12NotificationIcon(n){if(n.severity==='critical')return ['critical','!'];if(n.kind==='info')return ['info','i'];return ['','!'];}
function v12RenderNotifications(){
  const box=document.getElementById('notificationList');if(!box)return;
  const all=v12BuildNotifications().filter(n=>v12NotificationScope==='all'||n.networkId===currentNetworkId);
  const actionable=all.filter(n=>n.kind==='action'), infos=all.filter(n=>n.kind==='info');
  const section=(label,items)=>items.length?`<div class="notification-section-label"><span>${label}</span><span>${items.length}</span></div>${items.map(n=>{const [cls,icon]=v12NotificationIcon(n);const unread=!v12NotificationRead.has(n.id);return `<article class="notification-item ${unread?'unread':''}" data-notification-id="${esc(n.id)}"><span class="notification-icon ${cls}">${icon}</span><div class="notification-copy"><strong>${esc(n.title)}</strong><p>${esc(n.summary)}</p><div class="notification-meta"><span class="notification-network">${esc(v12NetworkName(n.networkId))}</span><span>${esc(n.time)}</span><span class="notification-action">${esc(n.actionLabel)} ›</span></div></div></article>`}).join('')}`:'';
  box.innerHTML=(section('需要处理',actionable)+section('信息',infos))||'<div class="notification-empty"><div><span>✓</span><strong>这里暂时没有通知</strong><p>真正需要处理的事项会出现在这里。</p></div></div>';
  document.querySelectorAll('#notificationScope [data-notification-scope]').forEach(b=>b.classList.toggle('active',b.dataset.notificationScope===v12NotificationScope));
  v12RenderNotificationBadge();
}
function v12OpenNotifications(){
  v12CloseCommand();v12CloseAdminMenu();
  const d=document.getElementById('notificationDrawer'),bg=document.getElementById('notificationBackdrop');if(!d||!bg)return;
  bg.hidden=false;requestAnimationFrame(()=>d.classList.add('open'));d.setAttribute('aria-hidden','false');v12RenderNotifications();
}
function v12CloseNotifications(){
  const d=document.getElementById('notificationDrawer'),bg=document.getElementById('notificationBackdrop');if(!d||!bg)return;
  d.classList.remove('open');d.setAttribute('aria-hidden','true');setTimeout(()=>{if(!d.classList.contains('open'))bg.hidden=true},180);
}
function v12OpenNotificationItem(id){
  const n=v12BuildNotifications().find(x=>x.id===id);if(!n)return;v12NotificationRead.add(id);v12RenderNotificationBadge();v12CloseNotifications();
  if(n.networkId!==currentNetworkId)switchNetwork(n.networkId,n.kind==='action'?'ops':'dashboard');
  if(n.networkId==='home-mesh' && n.source){
    if(n.source.type==='device'){showRoute('ops');setTimeout(()=>openDeviceFromOps(n.source.device),50);return;}
    if(n.source.type==='credential'){showRoute('ops');return;}
    if(n.source.type==='service'){showRoute('ops');setTimeout(()=>openServiceFromOps(n.source.service),50);return;}
  }
  if(n.id==='home:blocked-ssh'){showRoute('policy');return;}
  if(n.id==='home:health-ok'){showRoute('ops');return;}
  if(n.id==='test:idle'){switchNetwork('test-sandbox','dashboard');return;}
  showRoute(n.kind==='action'?'ops':'dashboard');
}

document.getElementById('notificationBtn')?.addEventListener('click',v12OpenNotifications);
document.getElementById('closeNotificationBtn')?.addEventListener('click',v12CloseNotifications);
document.getElementById('notificationBackdrop')?.addEventListener('click',v12CloseNotifications);
document.getElementById('notificationScope')?.addEventListener('click',e=>{const b=e.target.closest('[data-notification-scope]');if(!b)return;v12NotificationScope=b.dataset.notificationScope;v12RenderNotifications();});
document.getElementById('markAllNotificationsRead')?.addEventListener('click',()=>{v12BuildNotifications().forEach(n=>{if(v12NotificationScope==='all'||n.networkId===currentNetworkId)v12NotificationRead.add(n.id)});v12RenderNotifications();toast('当前范围的通知已标为已读');});
document.getElementById('notificationList')?.addEventListener('click',e=>{const n=e.target.closest('[data-notification-id]');if(n)v12OpenNotificationItem(n.dataset.notificationId)});
document.getElementById('openOpsFromNotifications')?.addEventListener('click',()=>{v12CloseNotifications();showRoute('ops')});

function v12OpenAdminMenu(){
  v12CloseCommand();v12CloseNotifications();const m=document.getElementById('adminMenu'),b=document.getElementById('oidcLoginBtn');if(!m||!b)return;
  m.hidden=false;b.setAttribute('aria-expanded','true');
}
function v12CloseAdminMenu(){const m=document.getElementById('adminMenu'),b=document.getElementById('oidcLoginBtn');if(m)m.hidden=true;if(b)b.setAttribute('aria-expanded','false');}
function v12ToggleAdminMenu(){const m=document.getElementById('adminMenu');if(!m)return;m.hidden?v12OpenAdminMenu():v12CloseAdminMenu();}
function v12LockConsole(){v12CloseAdminMenu();const l=document.getElementById('lockScreen');if(l){l.hidden=false;l.style.display='grid';}}
function v12UnlockConsole(){const l=document.getElementById('lockScreen');if(l){l.hidden=true;l.style.display='none';}toast('OIDC 管理会话已恢复（原型）');}

document.getElementById('oidcLoginBtn')?.addEventListener('click',e=>{e.stopPropagation();v12ToggleAdminMenu()});
document.getElementById('adminIdentityCard')?.addEventListener('click',e=>{e.stopPropagation();v12ToggleAdminMenu()});
document.getElementById('reauthAdminBtn')?.addEventListener('click',()=>{v12CloseAdminMenu();toast('正式版将跳转到 OIDC 身份提供方重新验证')});
document.getElementById('lockConsoleBtn')?.addEventListener('click',v12LockConsole);
document.getElementById('unlockConsoleBtn')?.addEventListener('click',v12UnlockConsole);
document.addEventListener('click',e=>{if(!e.target.closest('#adminMenu')&&!e.target.closest('#oidcLoginBtn')&&!e.target.closest('#adminIdentityCard'))v12CloseAdminMenu()});
document.addEventListener('keydown',e=>{if(e.key==='Escape'){v12CloseAdminMenu();v12CloseNotifications();}});

// Keep v12 surfaces synchronized when the active network changes or issue state changes.
const v12BaseSwitchNetwork=switchNetwork;
switchNetwork=function(id,route=null){v12BaseSwitchNetwork(id,route);v12UpdateCommandContext();v12RenderNotifications();};
const v12BaseRenderOpsCenter=renderOpsCenter;
renderOpsCenter=function(){v12BaseRenderOpsCenter();v12RenderNotificationBadge();};

v12UpdateCommandContext();
v12RenderNotificationBadge();

/* ---------------- v14: mesh-native resource model ---------------- */
(function(){
  const RESOURCE_TYPE = {
    service:{label:'设备服务',short:'服务',icon:'▤',className:'service',technical:'Service'},
    lan:{label:'局域网资源',short:'局域网',icon:'⌂',className:'lan',technical:'NetworkResource · GatewayBinding'},
    exit:{label:'互联网出口',short:'出口',icon:'↗',className:'exit',technical:'Exit'}
  };

  // v1.0 demo data only uses currently supported Peer platforms.
  devices['家庭网关']={
    icon:'◇',status:'online',address:'10.18.0.18',platform:'Linux',location:'',last:'8 分钟前',version:'1.8.2',
    peerId:'peer_gw19…7dd2',groups:['基础设施'],credential:'正常',credentialExpiry:'2026-11-18',credentialSerial:'cred_gw90…18bb',route:'直连优先 · 中继备用',
    access:[['家庭 Dashboard','HTTPS 443']],shares:[['客厅打印机','局域网资源'],['家庭互联网出口','互联网出口']],
    activity:[['8 分钟前','网关连接保持在线'],['18 分钟前','局域网资源路径检查通过'],['35 分钟前','互联网出口探测通过']]
  };
  if(devices['办公笔记本']){
    devices['办公笔记本'].access=[['家庭 NAS 文件服务','TCP 445'],['家庭 Dashboard','HTTPS 443'],['开发环境 SSH','TCP 22'],['客厅打印机','TCP 631'],['家庭互联网出口','默认出口']];
  }
  if(devices['Android 手机']) devices['Android 手机'].access=[['家庭 NAS 文件服务','TCP 445'],['家庭 Dashboard','HTTPS 443'],['客厅打印机','TCP 631']];

  // Existing Service examples become explicit resource types.
  Object.entries(services).forEach(([,r])=>{
    r.kind='service';
    r.configured=true;
    r.pathState='online';
    r.reachable=r.status==='healthy';
  });
  if(services['家庭 Dashboard']){
    services['家庭 Dashboard'].activity=[
      {time:'8 分钟前',result:'allow',device:'办公笔记本',detail:'成功访问 · HTTPS 443'},
      {time:'29 分钟前',result:'allow',device:'Android 手机',detail:'成功访问 · HTTPS 443'}
    ];
  }
  services['客厅打印机']={
    kind:'lan',icon:'P',iconClass:'green',host:'家庭网关',hostAddress:'10.18.0.18',target:'192.168.1.50/32',protocol:'TCP',port:'631',dns:'printer.home',status:'healthy',lastCheck:'4 分钟前',configured:true,pathState:'online',reachable:true,
    scopes:[{name:'家庭成员',kind:'设备组',count:2,rule:'规则 #4'}],
    activity:[
      {time:'12 分钟前',result:'allow',device:'办公笔记本',detail:'经家庭网关访问 · TCP 631'},
      {time:'1 小时前',result:'allow',device:'Android 手机',detail:'经家庭网关访问 · TCP 631'}
    ]
  };
  services['家庭互联网出口']={
    kind:'exit',icon:'↗',iconClass:'purple',host:'家庭网关',hostAddress:'10.18.0.18',target:'0.0.0.0/0',protocol:'IP',port:'—',dns:'',status:'healthy',lastCheck:'3 分钟前',configured:true,pathState:'online',reachable:true,
    scopes:[
      {name:'所有受管设备',kind:'设备组',count:1,rule:'规则 #5'},
      {name:'Android 手机',kind:'单台设备',count:1,rule:'规则 #7'}
    ],
    activity:[
      {time:'6 分钟前',result:'allow',device:'办公笔记本',detail:'经家庭网关访问互联网 · SNAT'},
      {time:'33 分钟前',result:'allow',device:'Android 手机',detail:'经家庭网关访问互联网 · SNAT'}
    ]
  };

  if(typeof networkProfiles!=='undefined' && networkProfiles['home-mesh']){
    Object.assign(networkProfiles['home-mesh'],{deviceTotal:6,online:5,shareTotal:5,shareHealthy:5,description:'家庭设备、局域网资源与互联网出口'});
  }

  function typeInfo(r){return RESOURCE_TYPE[r?.kind]||RESOURCE_TYPE.service;}
  function resourceTransport(r){
    if(r.kind==='exit') return '默认路由 · SNAT';
    return `${r.protocol} ${r.port}`;
  }
  function resourceEndpoint(r){
    if(r.kind==='exit') return `默认互联网出口 · ${r.target||'0.0.0.0/0'}`;
    if(r.kind==='lan') return `${r.dns||String(r.target||'').replace('/32','')}${r.port&&r.port!=='—'?':'+r.port:''}`;
    if(r.protocol==='HTTPS') return `https://${r.dns||r.hostAddress}${r.port==='443'?'':':'+r.port}`;
    if(r.protocol==='HTTP') return `http://${r.dns||r.hostAddress}${r.port==='80'?'':':'+r.port}`;
    return `${r.dns||r.hostAddress}:${r.port}`;
  }
  function resourceDescriptor(r){
    if(r.kind==='lan') return `${r.target} · 经 ${r.host}`;
    if(r.kind==='exit') return `${r.target||'0.0.0.0/0'} · 经 ${r.host}`;
    return `${r.host} · ${resourceTransport(r)}${r.dns?' · '+r.dns:''}`;
  }
  function resourcePathLabel(r){
    const d=devices[r.host];
    if(r.kind==='service') return d?.status==='online'?'提供设备在线':'提供设备离线';
    return d?.status==='online'?'网关在线':'网关离线';
  }
  function resourceReachabilityLabel(r){
    if(r.status==='paused') return '已暂停';
    if(r.status!=='healthy' || r.reachable===false) return '目标不可达';
    if(r.kind==='exit') return '外网探测正常';
    if(r.kind==='lan') return '目标端口可达';
    return '服务端口可达';
  }
  function resourceStatusPill(r){
    if(r.status==='paused') return '<span class="status-pill neutral">Ⅱ 已暂停</span>';
    if(r.status==='healthy' && r.reachable!==false) return '<span class="status-pill good">● 可达</span>';
    return '<span class="status-pill warn">! 需检查</span>';
  }
  function resourceScopeTags(r){
    if(!r.scopes.length) return '<span class="tag muted-tag">尚未授权</span>';
    return r.scopes.slice(0,3).map(x=>`<span class="tag">${esc(x.name)}</span>`).join('') + (r.scopes.length>3?`<span class="tag">+${r.scopes.length-3}</span>`:'');
  }
  function healthyResource(r){return r.status==='healthy' && r.pathState!=='offline' && r.reachable!==false;}
  function grantCount(){return Object.values(services).reduce((n,r)=>n+r.scopes.length,0);}

  // Keep older policy code working while changing the user-facing semantics.
  serviceEndpoint=resourceEndpoint;
  serviceStatusPill=resourceStatusPill;
  serviceScopeTags=resourceScopeTags;

  let v14ResourceFilter='all';
  renderServices=function(filter=''){
    if(!serviceList)return;
    const q=filter.trim().toLowerCase();
    const entries=Object.entries(services).filter(([name,r])=>{
      if(v14ResourceFilter!=='all' && r.kind!==v14ResourceFilter)return false;
      const hay=[name,r.host,r.dns,r.protocol,r.port,r.target,typeInfo(r).label,typeInfo(r).technical].join(' ').toLowerCase();
      return !q||hay.includes(q);
    });
    serviceList.innerHTML=entries.length?entries.map(([name,r])=>{
      const t=typeInfo(r);
      return `<article class="service-card service-card-v4 mesh-resource-card" data-service="${esc(name)}" tabindex="0">
        <div class="resource-kind-icon ${esc(t.className)}">${esc(t.icon)}</div>
        <div class="service-info resource-main">
          <div class="service-title-line"><strong>${esc(name)}</strong><span class="resource-type-chip ${esc(t.className)}">${esc(t.label)}</span>${r.status==='paused'?'<span class="tiny-state">已暂停</span>':''}</div>
          <p>${esc(resourceDescriptor(r))}</p>
          <div class="service-tags">${resourceScopeTags(r)}</div>
        </div>
        <div class="resource-path-mini"><small>路径</small><strong>${esc(resourcePathLabel(r))}</strong><span>${esc(resourceReachabilityLabel(r))}</span></div>
        <div class="service-state">${resourceStatusPill(r)}<small>${esc(r.lastCheck)}检查</small></div>
        <button class="secondary-btn small service-manage-btn" data-manage-service="${esc(name)}">查看详情</button>
      </article>`;
    }).join(''):'<div class="empty-list-state"><strong>没有找到匹配的共享</strong><p>换一个关键词或共享类型，或添加一个新共享。</p></div>';
    const total=Object.keys(services).length;
    const healthy=Object.values(services).filter(healthyResource).length;
    const set=(id,val)=>{const e=document.getElementById(id);if(e)e.textContent=String(val)};
    set('shareListCount',total);set('shareStatCount',total);set('shareStatHealthy',healthy);set('shareStatAttention',total-healthy);set('shareStatGrantCount',grantCount());
    const navBadge=document.querySelector('.nav-item[data-route="sharing"] .badge');if(navBadge)navBadge.textContent=String(total);
  };

  function resourceHealthSteps(r){
    const pathOk=devices[r.host]?.status==='online' && r.pathState!=='offline';
    const reachOk=healthyResource(r);
    return `<div class="resource-health-steps">
      <div class="resource-health-step ok"><span>✓</span><small>配置</small><strong>${r.configured===false?'未完成':'已保存'}</strong></div>
      <div class="resource-health-step ${r.scopes.length?'ok':'idle'}"><span>${r.scopes.length?'✓':'–'}</span><small>授权</small><strong>${r.scopes.length?`${r.scopes.length} 个范围`:'尚未授权'}</strong></div>
      <div class="resource-health-step ${pathOk?'ok':'warn'}"><span>${pathOk?'✓':'!'}</span><small>路径</small><strong>${esc(resourcePathLabel(r))}</strong></div>
      <div class="resource-health-step ${reachOk?'ok':'warn'}"><span>${reachOk?'✓':'!'}</span><small>可达性</small><strong>${esc(resourceReachabilityLabel(r))}</strong></div>
    </div>`;
  }

  renderServiceSummary=function(){
    const r=services[currentServiceName];if(!r)return;
    const t=typeInfo(r);
    const eyebrow=document.getElementById('serviceDrawerEyebrow');if(eyebrow)eyebrow.textContent=`共享详情 · ${t.label}`;
    serviceDrawerSummary.innerHTML=`
      <div class="service-hero resource-hero">
        <div class="resource-kind-icon large ${esc(t.className)}">${esc(t.icon)}</div>
        <div class="service-hero-copy">${resourceStatusPill(r)}<p>${esc(resourceDescriptor(r))}</p><small>${esc(t.technical)}</small></div>
        <button class="secondary-btn small" id="testServiceBtn">检查资源</button>
      </div>
      ${resourceHealthSteps(r)}
      <div class="resource-state-explain"><span>i</span><p><strong>“已配置”不等于“现在可访问”。</strong>Peerward 会分别判断访问授权、Mesh 路径和目标可达性。</p></div>`;
    document.getElementById('testServiceBtn')?.addEventListener('click',()=>{
      if(r.status==='paused'){toast('资源已暂停，请先恢复后再检查');return;}
      r.lastCheck='刚刚';r.pathState=devices[r.host]?.status==='online'?'online':'offline';r.reachable=r.pathState==='online';r.status=r.reachable?'healthy':'warning';
      toast(r.reachable?'检查完成：路径和目标均可达':'检查完成：当前路径不可达');renderServiceSummary();renderServices(field('shareSearchInput'));
    });
  };

  renderServiceTab=function(){
    const r=services[currentServiceName];if(!r)return;
    const t=typeInfo(r);
    const pathTab=document.querySelector('#serviceDrawerTabs [data-service-tab="path"]');if(pathTab)pathTab.hidden=r.kind==='service';
    if(r.kind==='service' && currentServiceTab==='path')currentServiceTab='overview';
    document.querySelectorAll('#serviceDrawerTabs .drawer-tab').forEach(b=>b.classList.toggle('active',b.dataset.serviceTab===currentServiceTab));
    if(currentServiceTab==='overview'){
      const target=r.kind==='service'?resourceEndpoint(r):(r.kind==='lan'?r.target:(r.target||'0.0.0.0/0'));
      const raw=JSON.stringify({kind:r.kind,provider:r.host,provider_address:r.hostAddress,target:r.target||null,protocol:r.protocol,port:r.port,dns:r.dns||null,configured:r.configured,path_state:r.pathState,reachable:r.reachable},null,2);
      serviceDrawerTabContent.innerHTML=`
        <section class="drawer-section"><div class="drawer-section-head"><div><h3>日常操作</h3><p>先看状态，需要改变行为时再进入对应页面。</p></div></div><div class="drawer-action-grid round4-action-grid"><button class="action-tile" id="checkServiceAccessBtn"><b>检查访问</b><small>${r.scopes.length} 个允许范围</small></button><button class="action-tile" data-service-open-tab="settings"><b>修改设置</b><small>共享目标与暂停状态</small></button><button class="action-tile" id="openHostDeviceBtn"><b>${r.kind==='service'?'查看提供设备':'查看网关设备'}</b><small>${esc(r.host)}</small></button></div></section>
        <section class="drawer-section connection-card"><div class="drawer-section-head"><div><h3>${r.kind==='service'?'访问地址':'当前路径'}</h3><p>${r.kind==='service'?'地址不是密码；授权和当前状态仍需同时满足。':'流量会先进入 Mesh，再由网关转发到目标。'}</p></div></div><div class="endpoint-copy-row"><code>${esc(resourceEndpoint(r))}</code><button class="secondary-btn small" id="copyServiceEndpointBtn">复制</button></div></section>
        <details class="round4-technical"><summary>技术详情</summary><div class="detail-grid detail-grid-six"><div><small>底层类型</small><strong>${esc(t.technical)}</strong></div><div><small>提供者地址</small><strong>${esc(r.hostAddress)}</strong></div><div><small>传输</small><strong>${esc(resourceTransport(r))}</strong></div><div><small>端点</small><strong>${esc(target)}</strong></div></div><details class="round4-raw-details"><summary>查看原始资源数据</summary><pre>${esc(raw)}</pre></details></details>`;
      document.getElementById('copyServiceEndpointBtn')?.addEventListener('click',()=>copyText(resourceEndpoint(r),'资源地址已复制'));
      document.getElementById('checkServiceAccessBtn')?.addEventListener('click',()=>{const name=currentServiceName;closeServiceDrawer();showRoute('policy',{type:'share',name})});
      document.getElementById('openHostDeviceBtn')?.addEventListener('click',()=>{closeServiceDrawer();openDrawer(r.host,'overview')});
    }else if(currentServiceTab==='settings'){
      const targetField=r.kind==='service'?'':`<label>${r.kind==='lan'?'局域网目标':'路由范围'}<input id="round4ResourceTarget" value="${esc(r.target||'')}"></label>`;
      const transportFields=r.kind==='exit'?'':`<div class="form-grid two"><label>协议<select id="round4ResourceProtocol"><option ${r.protocol==='TCP'?'selected':''}>TCP</option><option ${r.protocol==='UDP'?'selected':''}>UDP</option><option ${r.protocol==='HTTP'?'selected':''}>HTTP</option><option ${r.protocol==='HTTPS'?'selected':''}>HTTPS</option></select></label><label>端口<input id="round4ResourcePort" value="${esc(r.port)}"></label></div>`;
      serviceDrawerTabContent.innerHTML=`
        <section class="drawer-section no-top round4-settings-card"><div class="drawer-section-head"><div><h3>常用设置</h3><p>修改共享本身不会自动改变访问授权。</p></div></div>${targetField}${transportFields}
          <details class="round4-inline-advanced"><summary>更多设置</summary><label>DNS 名称（可选）<input id="round4ResourceDns" value="${esc(r.dns||'')}"></label></details>
          <button class="primary-btn" id="saveRound4ResourceSettings">保存设置</button>
        </section>
        <section class="drawer-section round4-danger-zone"><h3>${r.status==='paused'?'恢复共享':'暂停共享'}</h3><p>${r.status==='paused'?'恢复后，已有访问规则会继续生效。':'暂停会立即阻止使用，但保留共享设置和访问规则。'}</p><button class="${r.status==='paused'?'secondary-btn':'danger-outline-btn'}" id="pauseResourceInSettingsBtn">${r.status==='paused'?'恢复共享':'暂停共享'}</button></section>`;
      document.getElementById('saveRound4ResourceSettings')?.addEventListener('click',()=>{
        if(document.getElementById('round4ResourceTarget'))r.target=(document.getElementById('round4ResourceTarget').value||r.target).trim();
        if(document.getElementById('round4ResourceProtocol'))r.protocol=document.getElementById('round4ResourceProtocol').value||r.protocol;
        if(document.getElementById('round4ResourcePort'))r.port=(document.getElementById('round4ResourcePort').value||r.port).trim();
        if(document.getElementById('round4ResourceDns'))r.dns=(document.getElementById('round4ResourceDns').value||'').trim();
        renderServiceSummary();renderServices(field('shareSearchInput'));toast('资源设置已保存（原型）');
      });
      document.getElementById('pauseResourceInSettingsBtn')?.addEventListener('click',()=>document.getElementById('pauseShareBtn')?.click());
    }else if(currentServiceTab==='path'){
      serviceDrawerTabContent.innerHTML=`
        <div class="subtle-note round4-path-intro"><strong>只有局域网资源和互联网出口需要网关路径</strong><p>普通设备服务直接由提供设备监听，不需要额外网关批准。</p></div>
        <section class="drawer-section no-top"><div class="drawer-section-head"><div><h3>当前网关路径</h3><p>先确认网关在线，再检查目标是否可达。</p></div><button class="secondary-btn small" id="round4RecheckPathBtn">重新检查</button></div><div class="detail-grid round4-primary-facts"><div><small>网关设备</small><strong>${esc(r.host)}</strong></div><div><small>网关 Mesh 地址</small><strong>${esc(r.hostAddress)}</strong></div><div><small>目标</small><strong>${esc(r.target||'0.0.0.0/0')}</strong></div><div><small>路径状态</small><strong>${esc(resourcePathLabel(r))}</strong></div><div><small>目标状态</small><strong>${esc(resourceReachabilityLabel(r))}</strong></div></div></section>`;
      document.getElementById('round4RecheckPathBtn')?.addEventListener('click',()=>document.getElementById('testServiceBtn')?.click());
    }else{
      currentServiceTab='overview';renderServiceTab();return;
    }
    serviceDrawerTabContent.querySelectorAll('[data-service-open-tab]').forEach(b=>b.addEventListener('click',()=>{currentServiceTab=b.dataset.serviceOpenTab;renderServiceTab();}));
  };

  const v14BaseOpenServiceDrawer=openServiceDrawer;
  openServiceDrawer=function(name,tab='overview'){
    if(!services[name])return;
    v14BaseOpenServiceDrawer(name,tab);
    const t=typeInfo(services[name]);const e=document.getElementById('serviceDrawerEyebrow');if(e)e.textContent=`共享详情 · ${t.label}`;
    const pause=document.getElementById('pauseShareBtn');if(pause)pause.textContent=services[name].status==='paused'?'恢复资源':'暂停资源';
  };

  groupMembers=function(groupName){
    return Object.entries(devices).filter(([name,d])=>{
      if(groupName==='所有受管设备')return d.groups?.includes('受管设备')||d.groups?.includes(groupName);
      return d.groups?.includes(groupName);
    }).map(([name])=>name);
  };

  evaluateAccess=function(source,target){
    const r=services[target],d=devices[source];
    if(!r)return {policyAllowed:false,effectiveNow:false,reason:'资源不存在',match:null};
    let match=null;
    if(d)match=matchingScopeForDevice(source,r);else{const exact=r.scopes.find(scope=>scope.name===source);if(exact)match={scope:exact,inherited:false};}
    const policyAllowed=!!match;
    const sourceOnline=d?d.status==='online':true;
    const pathOnline=devices[r.host]?.status==='online' && r.pathState!=='offline';
    const resourceReady=r.status==='healthy' && r.reachable!==false && pathOnline;
    const effectiveNow=policyAllowed&&sourceOnline&&resourceReady;
    let currentIssue='';
    if(policyAllowed&&!sourceOnline)currentIssue='访问设备当前离线';
    else if(policyAllowed&&r.status==='paused')currentIssue='资源当前已暂停';
    else if(policyAllowed&&!pathOnline)currentIssue=r.kind==='service'?'提供设备当前离线':'网关设备当前离线';
    else if(policyAllowed&&!resourceReady)currentIssue='目标当前不可达';
    return {policyAllowed,effectiveNow,sourceOnline,serviceReady:resourceReady,currentIssue,match,svc:r,device:d,pathOnline};
  };

  renderPermissionMatrix=function(){
    const wrap=document.getElementById('permissionMatrix');if(!wrap)return;
    if(!policySelectedSource){wrap.innerHTML='<div class="policy-detail-empty round8-source-empty"><span>↑</span><strong>先选择访问来源</strong><p>选中一台设备或设备组后，这里只显示它对共享的最终访问结果。</p></div>';return;}
    const all=[...policySubjects('devices'),...policySubjects('groups')],subjects=all.filter(subject=>subject.name===policySelectedSource),targets=Object.keys(services);
    const header=targets.map(name=>{const r=services[name],t=typeInfo(r);return `<div class="matrix-service-head"><span class="matrix-resource-type">${esc(t.short)}</span><strong>${esc(name)}</strong><small>${esc(resourceTransport(r))}</small></div>`}).join('');
    const rows=subjects.map(subject=>{
      const cells=targets.map(target=>{const result=evaluateAccess(subject.name,target),state=matrixCellState(result),selected=selectedPolicyCell?.source===subject.name&&selectedPolicyCell?.target===target,title=result.policyAllowed?(result.effectiveNow?'允许访问':`权限允许，但${result.currentIssue}`):'未授权，默认阻止';return `<button class="matrix-cell ${state}${selected?' selected':''}" data-policy-source="${esc(subject.name)}" data-policy-target="${esc(target)}" title="${esc(title)}"><span>${matrixCellLabel(result)}</span><small>${state==='allow'?'允许':state==='attention'?'需注意':'阻止'}</small></button>`}).join('');
      const statusClass=subject.kind==='设备'&&subject.device.status!=='online'?' offline':'';
      return `<div class="matrix-row"><div class="matrix-subject${statusClass}"><span class="subject-kind">${subject.kind==='设备组'?'组':'设备'}</span><strong>${esc(subject.name)}</strong><small>${esc(subjectMeta(subject))}</small></div>${cells}</div>`;
    }).join('');
    wrap.innerHTML=`<div class="permission-matrix" style="--service-count:${Math.max(targets.length,1)}"><div class="matrix-row matrix-header"><div class="matrix-corner"><strong>当前来源</strong><small>点击结果查看原因</small></div>${header}</div>${rows}</div>`;
  };

  renderPolicyDetail=function(source,target){
    const el=document.getElementById('policyDetail'),ctx=document.getElementById('policyDetailContext');if(!el||!ctx)return;
    policySelectedSource=source;const picker=document.getElementById('policySourcePicker');if(picker&&[...picker.options].some(o=>o.value===source))picker.value=source;
    selectedPolicyCell={source,target};const result=evaluateAccess(source,target),r=services[target],t=typeInfo(r),isDevice=!!devices[source];
    const state=result.policyAllowed?(result.effectiveNow?'allow':'attention'):'deny',title=state==='allow'?'当前可以访问':state==='attention'?'权限允许，但当前无法连接':'当前会被阻止';
    let sentence='';if(result.policyAllowed)sentence=result.match.inherited?`“${source}”属于“${result.match.scope.name}”，该设备组已被允许访问“${target}”。`:`“${source}”已经被直接允许访问“${target}”。`;else sentence=`没有任何允许规则覆盖“${source} → ${target}”，因此 Peerward 会执行默认拒绝。`;
    ctx.textContent=`${source} → ${target}`;el.className='policy-detail-content';
    el.innerHTML=`<div class="policy-result-banner ${state}"><span>${state==='allow'?'✓':state==='attention'?'!':'×'}</span><div><strong>${title}</strong><p>${esc(sentence)}</p></div></div>
      <div class="policy-fact-grid">
        <div><small>访问来源</small><strong>${esc(source)}</strong><span>${isDevice?esc(`${devices[source].platform} · ${devices[source].status==='online'?'在线':'离线'}`):esc(`${groupMembers(source).length} 台设备`)}</span></div>
        <div><small>目标资源</small><strong>${esc(target)}</strong><span>${esc(`${t.label} · ${resourceTransport(r)}`)}</span></div>
        <div><small>命中规则</small><strong>${esc(scopeRuleLabel(result.match))}</strong><span>${result.match?.inherited?'设备组授权会自动应用到组内设备':'直接针对当前来源'}</span></div>
        <div><small>当前路径</small><strong>${esc(resourcePathLabel(r))}</strong><span>${esc(resourceReachabilityLabel(r))}</span></div>
      </div>
      ${result.currentIssue?`<div class="policy-inline-warning"><span>!</span><p><strong>权限配置没有问题，但当前连接仍会失败。</strong>${esc(result.currentIssue)}。恢复路径或资源后，无需重新授权。</p></div>`:''}
      <div class="policy-detail-actions"><button class="secondary-btn" id="detailSimulateBtn">用模拟器检查</button>${result.policyAllowed?(result.match?.inherited?`<button class="primary-btn" id="detailOpenSourceRuleBtn">管理“${esc(result.match.scope.name)}”授权</button>`:`<button class="danger-outline-btn" id="detailRevokeBtn">撤销此授权</button>`):`<button class="primary-btn" id="detailAllowBtn">允许访问</button>`}</div>`;
    renderPermissionMatrix();
    document.getElementById('detailSimulateBtn')?.addEventListener('click',()=>{const ss=document.getElementById('simSource'),st=document.getElementById('simTarget');if(ss&&[...ss.options].some(o=>o.value===source))ss.value=source;if(st)st.value=target;runSimulation();document.getElementById('policySimulatorPanel')?.scrollIntoView({behavior:'smooth',block:'center'});});
    document.getElementById('detailAllowBtn')?.addEventListener('click',()=>openModal('rule',{source,target}));
    document.getElementById('detailOpenSourceRuleBtn')?.addEventListener('click',()=>openServiceDrawer(target,'overview'));
    document.getElementById('detailRevokeBtn')?.addEventListener('click',()=>{const idx=r.scopes.findIndex(scope=>scope.name===source);if(idx<0)return;r.scopes.splice(idx,1);toast(`已撤销“${source}”访问“${target}”的权限`);selectedPolicyCell=null;renderPolicyUI();renderPolicyDetail(source,target);renderServices(field('shareSearchInput'));});
  };

  runSimulation=function(){
    const source=document.getElementById('simSource')?.value,target=document.getElementById('simTarget')?.value,out=document.getElementById('simulationResult');if(!source||!target||!out)return;
    const result=evaluateAccess(source,target),r=services[target],t=typeInfo(r),state=result.policyAllowed?(result.effectiveNow?'allow':'attention'):'deny';
    const heading=state==='allow'?'模拟结果：允许访问':state==='attention'?'模拟结果：权限允许，但当前不可连接':'模拟结果：访问会被阻止';
    const step1=devices[source]?`设备状态：${devices[source].status==='online'?'在线':'离线'}`:`设备组：${groupMembers(source).length} 台设备`,step2=result.match?`权限规则：${scopeRuleLabel(result.match)}`:'权限规则：没有匹配的允许规则',step3=`资源路径：${t.label} · ${resourcePathLabel(r)} · ${resourceReachabilityLabel(r)}`;
    out.className=`simulation-result ${state}`;out.innerHTML=`<span class="sim-result-icon">${state==='allow'?'✓':state==='attention'?'!':'×'}</span><div class="sim-result-copy"><strong>${heading}</strong><p>${state==='allow'?`“${esc(source)}”现在可以使用“${esc(target)}”。`:state==='attention'?`访问规则允许，但${esc(result.currentIssue)}。`:'没有允许规则，因此默认拒绝。'}</p><ol><li>${esc(step1)}</li><li>${esc(step2)}</li><li>${esc(step3)}</li></ol></div><button class="link-btn" id="simulationExplainBtn">查看权限说明</button>`;
    document.getElementById('simulationExplainBtn')?.addEventListener('click',()=>{renderPolicyDetail(source,target);document.getElementById('policyDetailPanel')?.scrollIntoView({behavior:'smooth',block:'center'});});
  };

  // Resource creation wizard: first choose the real mesh resource kind.
  wizardConfig.share.title='添加共享';
  wizardConfig.share.steps=['共享类型','共享信息','谁可以访问','确认创建'];
  renderShareStep=function(){
    const kind=wizardState.kind||'service';
    if(modalStep===1){
      modalBody.innerHTML=`<div class="subtle-note"><strong>先选择共享类型</strong><p>不同共享会使用不同连接路径；普通操作不需要先理解底层资源模型。</p></div><div class="resource-kind-choice">
        <label class="resource-kind-choice-card ${kind==='service'?'selected':''}"><input type="radio" name="resourceKind" value="service" ${kind==='service'?'checked':''}><span class="resource-kind-icon service">▤</span><span><strong>设备服务</strong><small>共享某台设备上的 TCP / UDP / HTTP 服务</small></span></label>
        <label class="resource-kind-choice-card ${kind==='lan'?'selected':''}"><input type="radio" name="resourceKind" value="lan" ${kind==='lan'?'checked':''}><span class="resource-kind-icon lan">⌂</span><span><strong>局域网资源</strong><small>通过一台网关设备访问打印机、摄像头或网段</small></span></label>
        <label class="resource-kind-choice-card ${kind==='exit'?'selected':''}"><input type="radio" name="resourceKind" value="exit" ${kind==='exit'?'checked':''}><span class="resource-kind-icon exit">↗</span><span><strong>互联网出口</strong><small>通过网关设备提供受控的互联网出口</small></span></label></div><div class="security-note"><span>✓</span><p>无论哪种类型，都不会生成“共享凭据”；设备身份和访问策略仍然分离。</p></div>`;
      modalNext.textContent='下一步';
    }else if(modalStep===2){
      if(kind==='service')modalBody.innerHTML=`<div class="subtle-note"><strong>设备服务</strong><p>服务直接运行在加入 Mesh 的设备上。</p></div><label>共享名称<input id="shareName" value="${esc(wizardState.name||'')}" placeholder="例如：家庭 NAS 文件服务"></label><label>提供设备<select id="shareDevice"><option>家用 NAS</option><option>开发服务器</option><option>办公笔记本</option><option>家庭网关</option></select></label><div class="form-grid two"><label>协议<select id="shareProtocol"><option>TCP</option><option>UDP</option><option>HTTP</option><option>HTTPS</option></select></label><label>端口<input id="sharePort" inputmode="numeric" value="${esc(wizardState.port||'445')}"></label></div><label>DNS 名称（可选）<input id="shareDns" value="${esc(wizardState.dns||'')}" placeholder="例如：nas.home"></label><p class="field-help">路径：访问设备 → 提供设备。</p>`;
      else if(kind==='lan')modalBody.innerHTML=`<div class="subtle-note"><strong>局域网资源</strong><p>目标本身不需要安装 Peerward，由网关设备负责转发。</p></div><label>共享名称<input id="shareName" value="${esc(wizardState.name||'')}" placeholder="例如：客厅打印机"></label><label>网关设备<select id="shareDevice"><option>家庭网关</option><option>家用 NAS</option></select></label><label>局域网目标<input id="shareTarget" value="${esc(wizardState.target||'192.168.1.50/32')}" placeholder="IP 或 CIDR，例如 192.168.1.50/32"></label><div class="form-grid two"><label>协议<select id="shareProtocol"><option>TCP</option><option>UDP</option></select></label><label>端口<input id="sharePort" inputmode="numeric" value="${esc(wizardState.port||'631')}"></label></div><label>DNS 名称（可选）<input id="shareDns" value="${esc(wizardState.dns||'')}" placeholder="例如：printer.home"></label><p class="field-help">路径：访问设备 → 网关设备 → 局域网目标。</p>`;
      else modalBody.innerHTML=`<div class="subtle-note"><strong>互联网出口</strong><p>出口由网关设备提供，并使用 SNAT 对外访问；不会自动开放公网入站。</p></div><label>共享名称<input id="shareName" value="${esc(wizardState.name||'家庭互联网出口')}"></label><label>出口网关<select id="shareDevice"><option>家庭网关</option><option>家用 NAS</option></select></label><label>路由范围<input id="shareTarget" value="${esc(wizardState.target||'0.0.0.0/0')}" disabled></label><div class="info-banner compact"><span>i</span><div><strong>默认出口只用于出站</strong><p>Peerward 会保留设备身份和访问规则；这里不创建公网入站规则。</p></div></div>`;
      if(document.getElementById('shareDevice')&&wizardState.device)document.getElementById('shareDevice').value=wizardState.device;if(document.getElementById('shareProtocol')&&wizardState.protocol)document.getElementById('shareProtocol').value=wizardState.protocol;modalNext.textContent='下一步';
    }else if(modalStep===3){
      modalBody.innerHTML=`<div class="subtle-note"><strong>再决定“谁可以访问”</strong><p>访问授权和共享类型是两件事；没有明确授权时默认阻止。</p></div><div class="choice-list">
        <label class="choice-card"><input type="radio" name="shareScope" value="家庭成员" ${!wizardState.scope||wizardState.scope==='家庭成员'?'checked':''}><span><strong>家庭成员</strong><small>当前设备组中的家庭设备</small></span></label>
        <label class="choice-card"><input type="radio" name="shareScope" value="所有受管设备" ${wizardState.scope==='所有受管设备'?'checked':''}><span><strong>所有受管设备</strong><small>适合 Dashboard 或互联网出口</small></span></label>
        <label class="choice-card"><input type="radio" name="shareScope" value="办公笔记本" ${wizardState.scope==='办公笔记本'?'checked':''}><span><strong>仅办公笔记本</strong><small>直接授权给一台设备</small></span></label>
        <label class="choice-card"><input type="radio" name="shareScope" value="暂不开放" ${wizardState.scope==='暂不开放'?'checked':''}><span><strong>暂不开放</strong><small>先保存资源，稍后再授权</small></span></label></div><div class="security-note"><span>✓</span><p><strong>默认拒绝仍然生效。</strong>共享创建成功不代表所有设备自动获得访问权。</p></div>`;
      modalNext.textContent='下一步';
    }else{
      const scope=wizardState.scope||'家庭成员',t=RESOURCE_TYPE[kind],willRule=scope!=='暂不开放';
      const location=kind==='service'?`${wizardState.device||'家用 NAS'} · ${wizardState.protocol||'TCP'} ${wizardState.port||'445'}`:kind==='lan'?`${wizardState.target||'192.168.1.50/32'} · 经 ${wizardState.device||'家庭网关'}`:`${wizardState.target||'0.0.0.0/0'} · 经 ${wizardState.device||'家庭网关'}`;
      modalBody.innerHTML=`<div class="confirm-card"><div class="confirm-row"><span>共享类型</span><strong>${esc(t.label)}</strong></div><div class="confirm-row"><span>共享名称</span><strong>${esc(wizardState.name||'未命名共享')}</strong></div><div class="confirm-row"><span>路径</span><strong>${esc(location)}</strong></div>${wizardState.dns?`<div class="confirm-row"><span>DNS 名称</span><strong>${esc(wizardState.dns)}</strong></div>`:''}<div class="confirm-row"><span>访问范围</span><strong>${esc(scope)}</strong></div></div><div class="info-banner compact"><span>i</span><div><strong>${willRule?'将同时创建允许规则':'不会创建允许规则'}</strong><p>${willRule?'系统会把授权和共享设置分别保存。':'共享会保存，但默认拒绝会阻止所有访问。'}</p></div></div><div class="subtle-note"><strong>安全边界保持分离</strong><p>共享设置、设备身份、访问规则和当前路径状态分别管理，任何一项都不会被另一项静默替代。</p></div>`;
      modalNext.textContent='创建共享';
    }
  };

  const v14BaseSaveCurrentStep=saveCurrentStep;
  saveCurrentStep=function(){
    if(modalType!=='share'){v14BaseSaveCurrentStep();return;}
    if(modalStep===1)wizardState.kind=document.querySelector('input[name="resourceKind"]:checked')?.value||wizardState.kind||'service';
    if(modalStep===2){wizardState.name=field('shareName')||'未命名共享';wizardState.device=field('shareDevice')||'家庭网关';wizardState.target=field('shareTarget')||wizardState.target||'';wizardState.protocol=field('shareProtocol')||wizardState.protocol||(wizardState.kind==='exit'?'IP':'TCP');wizardState.port=field('sharePort')||wizardState.port||(wizardState.kind==='exit'?'—':'443');wizardState.dns=field('shareDns')||wizardState.dns||'';}
    if(modalStep===3)wizardState.scope=document.querySelector('input[name="shareScope"]:checked')?.value||'家庭成员';
  };

  finalizeShare=function(){
    const kind=wizardState.kind||'service',name=wizardState.name||'未命名共享',scope=wizardState.scope||'家庭成员',host=wizardState.device||(kind==='service'?'家用 NAS':'家庭网关'),hostDevice=devices[host];
    const protocol=kind==='exit'?'IP':wizardState.protocol||'TCP',port=kind==='exit'?'—':wizardState.port||'443';
    const scopeInfo=scope==='暂不开放'?[]:[{name:scope,kind:devices[scope]?'单台设备':'设备组',count:devices[scope]?1:groupMembers(scope).length||1,rule:'新建规则'}];
    services[name]={kind,icon:(name.trim()[0]||'R').toUpperCase(),iconClass:kind==='exit'?'purple':kind==='lan'?'green':'',host,hostAddress:hostDevice?.address||'10.18.0.18',target:kind==='exit'?'0.0.0.0/0':kind==='lan'?(wizardState.target||'192.168.1.50/32'):'',protocol,port,dns:wizardState.dns||'',status:'healthy',lastCheck:'刚刚',configured:true,pathState:hostDevice?.status==='online'?'online':'offline',reachable:hostDevice?.status==='online',scopes:scopeInfo,activity:[]};
    if(hostDevice&&!hostDevice.shares.some(x=>x[0]===name))hostDevice.shares.push([name,typeInfo(services[name]).label]);
    if(networkProfiles?.['home-mesh']){networkProfiles['home-mesh'].shareTotal=Object.keys(services).length;networkProfiles['home-mesh'].shareHealthy=Object.values(services).filter(healthyResource).length;}
    renderServices(field('shareSearchInput'));renderPolicyUI();renderDashboardHealth();
  };

  // Rule wizard describes generic resources instead of assuming a TCP service.
  const v14BaseRenderRuleStep=renderRuleStep;
  renderRuleStep=function(){
    if(modalStep!==2){v14BaseRenderRuleStep();return;}
    const targets=Object.entries(services).map(([name,r])=>`<option value="${esc(name)}">${esc(name)} · ${esc(typeInfo(r).label)} · ${esc(resourceTransport(r))}</option>`).join('');
    modalBody.innerHTML=`<label>访问什么<select id="ruleTarget">${targets}</select></label><div class="info-banner compact"><span>i</span><div><strong>目标可以是服务、局域网资源或出口</strong><p>资源已经定义自己的协议、目标和路径，这里只创建访问授权。</p></div></div>`;
    if(wizardState.target&&[...document.getElementById('ruleTarget').options].some(o=>o.value===wizardState.target))document.getElementById('ruleTarget').value=wizardState.target;modalNext.textContent='下一步';
  };

  // Credential renewal is device-initiated; the console only requests it.
  const v14BaseRenderDrawerTab=renderDrawerTab;
  renderDrawerTab=function(){
    if(currentDrawerTab!=='maintenance'){v14BaseRenderDrawerTab();return;}
    const d=devices[currentDeviceName]||devices['办公笔记本'];
    document.querySelectorAll('#drawerTabs .drawer-tab').forEach(b=>b.classList.toggle('active',b.dataset.drawerTab===currentDrawerTab));
    drawerTabContent.innerHTML=`<div class="subtle-note round4-maintenance-intro"><strong>正常设备通常不需要日常维护</strong><p>设备身份即将到期、设备准备退出网络或需要排查身份问题时，再使用下面的操作。</p></div><section class="credential-card"><div class="credential-head"><span class="credential-icon">✓</span><div><strong>设备身份有效</strong><p>${esc(currentDeviceName)} 当前可以正常证明自己的身份。</p></div><span class="status-pill good">正常</span></div><div class="credential-facts"><div><small>有效期至</small><strong>${esc(d.credentialExpiry)}</strong></div></div><details class="round4-technical"><summary>凭据技术信息</summary><div class="detail-grid"><div><small>凭据序列</small><strong>${esc(d.credentialSerial)}</strong></div></div></details></section><div class="subtle-note credential-explain"><strong>设备自己更新身份材料</strong><p>控制台只发送更新请求，不替设备生成或保存私钥。一次性加入凭据也不会被重复使用。</p></div><section class="drawer-section"><h3>设备身份维护</h3><div class="credential-actions"><button class="secondary-btn" id="rotateCredentialBtn">请求设备更新身份</button><button class="danger-outline-btn" id="revokeCredentialBtn">撤销设备凭据</button></div><p class="field-help spaced">更新身份属于正常维护；撤销凭据会让设备失去身份，需要重新加入网络。</p></section><details class="drawer-section round8-activity"><summary><strong>查看设备操作记录</strong></summary><div class="activity-stream">${d.activity.map((a,i)=>`<div class="activity-row"><span class="activity-dot ${i===0?'active':''}"></span><time>${esc(a[0])}</time><div><strong>${esc(a[1])}</strong><small>${esc(currentDeviceName)}</small></div></div>`).join('')}</div></details><section class="drawer-section round4-danger-zone"><h3>停用设备</h3><p>确认这台设备不再使用当前网络时再执行。操作记录和设备信息仍会保留。</p><button class="danger-outline-btn" id="disableDeviceInMaintenanceBtn">停用这台设备</button></section>`;
    document.getElementById('rotateCredentialBtn')?.addEventListener('click',()=>requestDeviceCredentialUpdate(currentDeviceName));
    document.getElementById('revokeCredentialBtn')?.addEventListener('click',()=>toast('撤销属于高风险操作，正式版需要二次确认'));
    document.getElementById('disableDeviceInMaintenanceBtn')?.addEventListener('click',()=>document.getElementById('disableDeviceBtn')?.click());
  };
  function requestDeviceCredentialUpdate(name){
    const d=devices[name];if(!d)return;
    if(d.status!=='online'){toast(`${name} 当前离线，更新请求将在设备恢复在线后才能完成`);return;}
    d.credentialExpiry='2026-12-15';d.activity.unshift(['刚刚','设备收到更新请求并自行更新身份']);
    addAuditEvent?.({action:'请求设备更新身份',detail:d.credentialSerial||'',target:name,risk:'normal'});
    renderDrawerSummary();renderDrawerTab();renderOpsCenter();toast(`${name} 已自行完成身份更新（原型）`);
  }

  buildOpsIssues=function(){
    const issues=[];
    Object.entries(devices).forEach(([name,d])=>{if(d.status!=='online')issues.push({id:'offline:'+name,type:'device',severity:'warning',title:`${name} 已离线 ${d.last}`,summary:'如果这台设备本来就不需要常在线，可以标记为“已知”；否则建议先检查电源、网络和 Peerward 客户端。',impact:'仅影响该设备',impactClass:'low',device:name,guidance:'先确认设备是否应该在线。离线不会影响其他设备，也不会自动删除已有访问权限。'});});
    const expiring=expiringCredentialDevices();if(expiring.length){const earliest=Math.min(...expiring.map(([,d])=>demoDaysUntil(d.credentialExpiry)));issues.push({id:'credential:expiring',type:'credential',severity:'warning',title:`${expiring.length} 台设备身份将在 14 天内到期`,summary:`最早还有 ${earliest} 天到期。控制台只发送更新请求；在线设备会自行生成并提交新的身份材料。`,impact:'暂不影响使用',impactClass:'low',devices:expiring.map(([name])=>name),guidance:'先请求在线设备更新身份；离线设备恢复连接后再完成更新。控制台不会替设备生成私钥。'});}
    Object.entries(services).forEach(([name,r])=>{if(!healthyResource(r)&&r.status!=='paused'){issues.push({id:'service:'+name,type:'service',severity:'critical',title:`${name} 当前不可达`,summary:`${typeInfo(r).label}的路径或目标检查失败。`,impact:'影响这个共享',impactClass:'',service:name,guidance:r.kind==='service'?'先确认提供设备在线，再检查服务端口。':'先确认网关设备在线，再检查局域网目标或出口。'});}});
    return issues.map(i=>({...i,state:opsIssueOverrides[i.id]||'open'}));
  };
  issuePrimaryAction=function(issue){
    if(issue.type==='device')return `<button class="secondary-btn small" data-issue-action="device" data-issue-id="${esc(issue.id)}">查看设备</button>`;
    if(issue.type==='credential')return `<button class="primary-btn small-primary" data-issue-action="rotate" data-issue-id="${esc(issue.id)}">更新设备身份</button>`;
    if(issue.type==='service')return `<button class="secondary-btn small" data-issue-action="service" data-issue-id="${esc(issue.id)}">查看共享</button>`;
    return '';
  };
  rotateExpiringCredentials=function(){
    const targets=expiringCredentialDevices(),online=targets.filter(([,d])=>d.status==='online'),offline=targets.filter(([,d])=>d.status!=='online');
    online.forEach(([,d])=>{d.credentialExpiry='2026-12-15';d.activity.unshift(['刚刚','设备收到更新请求并自行更新身份']);});
    renderOpsCenter();
    if(offline.length)toast(`${online.length} 台在线设备已自行更新身份；${offline.length} 台离线设备的身份仍待更新`);else toast(`${online.length} 台设备已自行完成身份更新`);
  };

  renderDashboardHealth=function(){
    const issues=activeIssues(),critical=criticalIssues(),online=Object.values(devices).filter(d=>d.status==='online').length,total=Object.keys(devices).length,healthy=Object.values(services).filter(healthyResource).length,resTotal=Object.keys(services).length,expiring=expiringCredentialDevices().length;
    const banner=document.getElementById('dashboardHealthBanner');if(banner){banner.classList.remove('attention','healthy','critical');banner.classList.add(critical.length?'critical':issues.length?'attention':'healthy');document.getElementById('dashboardHealthIcon').textContent=critical.length||issues.length?'!':'✓';document.getElementById('dashboardHealthTitle').textContent=critical.length?`有 ${critical.length} 个问题正在影响使用`:issues.length?`网络整体可用，有 ${issues.length} 件事建议处理`:'网络运行正常，没有待处理事项';document.getElementById('dashboardHealthText').textContent=critical.length?'请优先处理下方标为“影响使用”的事项。':`当前 ${online}/${total} 台设备在线，${healthy}/${resTotal} 个共享连接可达；共享基础设施当前正常。`;}
    const set=(id,val)=>{const e=document.getElementById(id);if(e)e.textContent=val};set('dashboardIssueCount',issues.length);set('dashboardIssueFoot',critical.length?`${critical.length} 个正在影响使用`:issues.length?'均非严重故障':'无需处理');set('dashboardOnlineCount',online);set('dashboardDeviceTotal',`/ ${total} 在线`);set('dashboardDeviceFoot',online===total?'全部设备在线':`${total-online} 台设备离线`);set('dashboardShareHealthy',healthy);set('dashboardShareTotal',`/ ${resTotal} 路径可达`);set('dashboardShareFoot',healthy===resTotal?'全部资源路径正常':`${resTotal-healthy} 个资源需检查`);set('dashboardCredentialHealth',expiring);set('dashboardCredentialFoot',expiring?'等待设备自行更新身份':'近期无需处理');
    const list=document.getElementById('dashboardActionList');if(list)list.innerHTML=issues.length?issues.slice(0,3).map(dashboardIssueHtml).join(''):`<div class="dashboard-action-empty"><div><strong>当前没有需要你处理的事项</strong><span>正常安全阻止和动态路径变化不会被误报成故障。</span></div></div>`;const badge=document.getElementById('navOpsBadge');if(badge){badge.textContent=String(issues.length);badge.hidden=!issues.length;}
  };

  // Resource type filter.
  document.getElementById('resourceTypeFilter')?.addEventListener('click',e=>{const b=e.target.closest('[data-resource-filter]');if(!b)return;v14ResourceFilter=b.dataset.resourceFilter;document.querySelectorAll('#resourceTypeFilter [data-resource-filter]').forEach(x=>x.classList.toggle('active',x===b));renderServices(field('shareSearchInput'));});

  // Update search semantics and current network resource summary.
  if(typeof v12CurrentObjectShares==='function')v12CurrentObjectShares=function(){if(currentNetworkId==='home-mesh')return Object.entries(services).map(([name,r])=>({name,meta:`${typeInfo(r).label} · ${resourceDescriptor(r)}`,state:r.status}));return (currentNetwork().shares||[]).map(s=>({name:s.name,meta:`资源 · ${s.host} · ${s.endpoint}`,state:s.state}));};

  // Refresh data-dependent surfaces after the mesh-native migration.
  renderServices('');
  renderPolicyUI();
  renderOpsCenter();
  renderDashboardHealth();
  if(typeof renderNetworksPortfolio==='function')renderNetworksPortfolio();
  if(typeof v12RenderNotificationBadge==='function')v12RenderNotificationBadge();
})();

/* Round 12: prototype keyboard and screen-reader parity with the production console. */
function round12SyncPrototypeTabs(){
  const sync=(selector,dataKey,current,panel)=>{
    const normalized=current==='basic'?'overview':current;
    let active=null;
    document.querySelectorAll(selector).forEach(btn=>{
      const selected=!btn.hidden && btn.dataset[dataKey]===normalized;
      btn.classList.toggle('active',selected);
      btn.setAttribute('aria-selected',String(selected));
      btn.tabIndex=selected?0:-1;
      if(selected)active=btn;
    });
    if(active&&panel)panel.setAttribute('aria-labelledby',active.id);
  };
  sync('#drawerTabs [role="tab"]','drawerTab',currentDrawerTab,drawerTabContent);
  sync('#serviceDrawerTabs [role="tab"]','serviceTab',currentServiceTab,serviceDrawerTabContent);
}

const round12DialogSelector='[role="dialog"][aria-modal="true"],[role="alertdialog"][aria-modal="true"]';
const round12DialogHistory=new Map();
const round12DialogVisible=dialog=>dialog?.isConnected&&dialog.getClientRects().length>0&&dialog.getAttribute('aria-hidden')!=='true';
const round12Focusable=dialog=>[...dialog.querySelectorAll('button:not(:disabled),a[href],input:not(:disabled),select:not(:disabled),textarea:not(:disabled),summary,[tabindex]')].filter(node=>node.tabIndex>=0&&node.getClientRects().length&&!node.closest('[inert]'));
function round12SyncPrototypeDialogs(){
  round12SyncPrototypeTabs();
  const visible=[...document.querySelectorAll(round12DialogSelector)].filter(round12DialogVisible);
  const restore=[];
  for(const [dialog,previous] of round12DialogHistory){
    if(!visible.includes(dialog)){round12DialogHistory.delete(dialog);restore.push(previous);}
  }
  visible.forEach(dialog=>{if(!round12DialogHistory.has(dialog))round12DialogHistory.set(dialog,document.activeElement);});
  const previous=restore.reverse().find(node=>node?.isConnected);
  if(previous instanceof HTMLElement)previous.focus();
  const active=visible.at(-1);
  if(active&&!active.contains(document.activeElement)){
    (active.querySelector('[autofocus]')??round12Focusable(active)[0]??active).focus();
  }
}
new MutationObserver(round12SyncPrototypeDialogs).observe(document.body,{subtree:true,childList:true,attributes:true,attributeFilter:['class','hidden','aria-hidden']});
round12SyncPrototypeDialogs();

document.addEventListener('keydown',event=>{
  const target=event.target instanceof Element?event.target:null;
  const tab=target?.closest('[role="tab"]');
  const tablist=tab?.closest('[role="tablist"]');
  if(tab&&tablist&&['ArrowRight','ArrowLeft','ArrowDown','ArrowUp','Home','End'].includes(event.key)){
    const tabs=[...tablist.querySelectorAll('[role="tab"]')].filter(node=>!node.hidden&&!node.disabled&&node.getClientRects().length);
    const current=Math.max(0,tabs.indexOf(tab));
    let next=current;
    if(event.key==='ArrowRight'||event.key==='ArrowDown')next=(current+1)%tabs.length;
    else if(event.key==='ArrowLeft'||event.key==='ArrowUp')next=(current-1+tabs.length)%tabs.length;
    else if(event.key==='Home')next=0;
    else if(event.key==='End')next=tabs.length-1;
    event.preventDefault();tabs[next]?.click();tabs[next]?.focus();return;
  }
  if(event.key!=='Tab')return;
  const dialog=[...round12DialogHistory.keys()].filter(round12DialogVisible).at(-1);if(!dialog)return;
  const nodes=round12Focusable(dialog);if(!nodes.length){event.preventDefault();dialog.focus();return;}
  if(event.shiftKey&&(document.activeElement===nodes[0]||!dialog.contains(document.activeElement))){event.preventDefault();nodes.at(-1).focus();}
  else if(!event.shiftKey&&(document.activeElement===nodes.at(-1)||!dialog.contains(document.activeElement))){event.preventDefault();nodes[0].focus();}
},true);
