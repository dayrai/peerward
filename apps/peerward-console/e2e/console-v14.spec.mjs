import { expect, test } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';
import { mkdir } from 'node:fs/promises';
import { randomUUID } from 'node:crypto';
import path from 'node:path';
const origin=process.env.PEERWARD_CONSOLE_E2E_URL;
test.use({viewport:{width:1440,height:1000},serviceWorkers:'block'});
test.skip(process.env.PEERWARD_CONSOLE_V14_E2E!=='1','isolated console fixture required');
const evidence=process.env.PEERWARD_EVIDENCE_SCREENSHOT_DIR;
async function screenshot(page,name){if(evidence){await mkdir(evidence,{recursive:true});await page.screenshot({path:path.join(evidence,name+'.png'),fullPage:true,animations:'disabled'});}}
async function meshes(page){return (await(await page.request.get(`${origin}/api/v1/meshes`)).json()).items;}
async function accessible(page){const r=await new AxeBuilder({page}).withTags(['wcag2a','wcag2aa']).analyze();expect(r.violations.filter(v=>['serious','critical'].includes(v.impact))).toEqual([]);}
async function createShare(page,base,draft){const preview=await(await page.request.post(base+'/console/sharing/preview',{data:draft})).json();expect(preview.digest,JSON.stringify(preview)).toBeTruthy();expect((await page.request.post(base+'/console/sharing/apply',{headers:{'If-Match':`"${preview.version}"`},data:{draft,preview_digest:preview.digest}})).ok()).toBe(true);}

test('Chinese default, five routes, responsive themes, search and keyboard drawer',async({page})=>{
 const list=await meshes(page),mesh=list[0];await page.setViewportSize({width:1440,height:1000});
 const errors=[];page.on('pageerror',e=>errors.push(e.message));
 for(const [route,title] of [['','概览'],['peers','设备'],['services','共享'],['policy','访问'],['operations','问题与维护']]){
  await page.goto(`${origin}/${route}?mesh=${mesh.id}`);await expect(page.locator('main')).toHaveAttribute('data-console-ready','true');await expect(page.locator('#pw-language')).toHaveValue('zh-CN');await expect(page.getByRole('heading',{level:1,name:title,exact:true})).toBeVisible();
  await expect(page.locator('body')).not.toContainText('missing-translation');await page.waitForTimeout(400);await accessible(page);await screenshot(page,`desktop-${route||'overview'}-zh`);
 }
 await page.keyboard.press('Control+k');const dialog=page.getByRole('dialog');await expect(dialog).toBeVisible();await dialog.getByRole('textbox').fill('home-nas');const searchResult=dialog.locator('.search-result').first();await expect(searchResult).toBeVisible();await expect(searchResult).toContainText('设备');await expect(searchResult).not.toContainText(/ · device\b/i);await page.keyboard.press('Escape');await expect(dialog).toHaveCount(0);
 await page.locator('details.account-menu > summary').click();await expect(page.locator('#pw-language')).toBeVisible();await page.locator('#pw-theme').selectOption('dark');await page.locator('#pw-language').selectOption('en-US');await page.locator('details.account-menu > summary').click();await page.reload();await expect(page.locator('#pw-theme')).toHaveValue('dark');await expect(page.locator('#pw-language')).toHaveValue('en-US');await screenshot(page,'desktop-operations-en-dark');
 await page.setViewportSize({width:390,height:844});await page.goto(`${origin}/peers?mesh=${mesh.id}`);await page.locator('details.account-menu > summary').click();await expect(page.locator('#pw-language')).toBeVisible();await page.locator('details.account-menu > summary').click();await accessible(page);expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth)).toBe(true);await screenshot(page,'mobile-devices-en-dark');
 await page.locator('details.account-menu > summary').click();await page.locator('#pw-language').selectOption('zh-CN');await page.locator('#pw-theme').selectOption('light');await page.locator('details.account-menu > summary').click();await screenshot(page,'mobile-devices-zh-light');expect(errors).toEqual([]);
});

test('three sharing kinds, real preview, permissions, pause and persistent issue state',async({page})=>{
 test.setTimeout(120000);const [mesh]=await meshes(page);const base=`/api/v1/meshes/${mesh.id}`;
 const peers=(await(await page.request.get(origin+base+'/peers')).json()).items;const provider=peers.find(p=>p.name==='home-nas'),consumer=peers.find(p=>p.name==='test-consumer');expect(provider&&consumer).toBeTruthy();
 const resources=[];
 for(const [kind,suffix] of [['service','文件服务'],['lan','打印机'],['internet','互联网出口']]){
  const name=`${suffix}-${randomUUID().slice(0,6)}`;await page.goto(`${origin}/services?mesh=${mesh.id}`);await expect(page.locator('main')).toHaveAttribute('data-console-ready','true');await page.getByRole('button',{name:'＋ 添加共享',exact:true}).click();const d=page.getByRole('dialog');
  await d.getByRole('radio',{name:({service:'设备服务',lan:'局域网资源',internet:'互联网出口'})[kind],exact:true}).check();await d.getByRole('button',{name:'下一步',exact:true}).click();await screenshot(page,`sharing-prototype-${kind}-details`);await d.locator('#share-name').fill(name);await d.locator('#share-provider').selectOption(provider.id);
  if(kind==='lan'){await d.locator('#share-prefix').fill('192.168.211.10/32');await d.locator('#share-dns').fill(`printer-${randomUUID().slice(0,6)}.console.test`);}
  await d.getByRole('button',{name:'下一步',exact:true}).click();await d.locator(`input[name=share-source][value="peer:${consumer.id}"]`).check();
  await screenshot(page,`wizard-${kind}-zh`);await d.getByRole('button',{name:'下一步',exact:true}).click();await expect(d.locator('.sharing-review')).toBeVisible();
  if(kind!=='service'){await expect(d.getByRole('button',{name:'创建共享',exact:true})).toBeDisabled();await d.locator('#share-gateway-approval').check();}
  await d.getByRole('button',{name:'创建共享',exact:true}).click();await expect(d.getByText('共享已创建',{exact:true})).toBeVisible();await expect(d.getByRole('link',{name:'继续检查访问',exact:true})).toHaveAttribute('href',new RegExp(`source=peer%3A${consumer.id}`));await d.getByRole('button',{name:'Close / 关闭'}).click();
  const shares=(await(await page.request.get(origin+base+'/console/sharing')).json()).items;const resource=shares.find(r=>r.name===name);expect(resource).toBeTruthy();expect(resource.reachability.state).toBe('unknown');resources.push(resource);
 }
 await page.goto(`${origin}/services?mesh=${mesh.id}`);await expect(page.locator('main')).toHaveAttribute('data-console-ready','true');await page.locator('#sharing-search').fill(resources[0].name);await page.locator('.sharing-row').filter({hasText:resources[0].name}).getByRole('button',{name:'查看详情',exact:true}).click();await expect(page).toHaveURL(new RegExp(`resource=${resources[0].id}`));await page.goBack();await expect(page.getByRole('dialog')).toHaveCount(0);await expect(page.locator('#sharing-search')).toHaveValue(resources[0].name);
 await page.goto(`${origin}/services?mesh=${mesh.id}&resource=${resources[0].id}`);const d=page.getByRole('dialog');await expect(d.getByText('未知 / 未检查',{exact:true}).first()).toBeVisible();await accessible(page);await screenshot(page,'sharing-detail-zh');
 await d.getByRole('tab',{name:'共享信息',exact:true}).click();await d.getByRole('button',{name:'暂停共享',exact:true}).click();await d.locator('#state-share-confirm').fill(resources[0].name);await d.locator('#state-share-reason').fill('测试维护');await d.getByRole('button',{name:'确认暂停共享',exact:true}).click();await d.getByRole('button',{name:'查看状态',exact:true}).click();await d.getByRole('tab',{name:'共享信息',exact:true}).click();await expect(d.getByRole('button',{name:'恢复共享',exact:true})).toBeVisible();
 const simulate=()=>page.request.post(origin+base+'/policy/simulate',{data:{source_peer_id:consumer.id,target_service_id:resources[0].id,protocol:'tcp'}});expect((await(await simulate()).json()).allowed).toBe(false);
 await d.getByRole('button',{name:'恢复共享',exact:true}).click();await d.locator('#state-share-confirm').fill(resources[0].name);await d.locator('#state-share-reason').fill('测试完成');await d.getByRole('button',{name:'确认恢复共享',exact:true}).click();await expect.poll(async()=>(await(await simulate()).json()).allowed).toBe(true);
 await d.getByRole('link',{name:'检查访问',exact:true}).click();await expect(page).toHaveURL(new RegExp(`policy\\?mesh=${mesh.id}.*resource=${resources[0].id}`));await expect(page.locator('.access-focus-banner')).toContainText(resources[0].name);await page.locator('#access-source').selectOption(`peer:${consumer.id}`);await expect(page).toHaveURL(/source=peer/);await page.reload();await expect(page.locator('#access-source')).toHaveValue(`peer:${consumer.id}`);await expect(page.locator('.access-context-banner')).toContainText(consumer.display_name||consumer.name);await expect(page.getByRole('link',{name:'查看设备详情',exact:true})).toHaveAttribute('href',new RegExp(`resource=${consumer.id}`));await expect(page.locator('.access-focus-banner').filter({hasText:resources[0].name})).toBeVisible();await expect(page.locator('.access-matrix-cell.allowed')).toBeVisible();await screenshot(page,'access-results-zh');
 await page.setViewportSize({width:390,height:844});await expect(page.locator('.access-permission-matrix')).toBeVisible();expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth)).toBe(true);await accessible(page);await screenshot(page,'mobile-access-results-zh');await page.setViewportSize({width:1440,height:1000});
 const access=page.getByRole('region',{name:'访问详情'});await page.getByRole('button',{name:new RegExp(resources[0].name+'.*查看原因')}).click();await access.getByRole('button',{name:'撤销此授权'}).click();await access.locator('#grant-state-reason').fill('测试撤销');await access.getByRole('checkbox').check();await access.getByRole('button',{name:'确认提交',exact:true}).click();await expect.poll(async()=>(await(await simulate()).json()).allowed).toBe(false);
 await page.goto(`${origin}/operations?mesh=${mesh.id}`);await expect(page.getByText('修复后如何确认',{exact:true})).toBeVisible();const issuesPanel=page.locator('.issues-panel');await issuesPanel.getByRole('button',{name:'重新检查',exact:true}).click();await expect(issuesPanel.getByText(/重新检查完成/)).toBeVisible();const issue=page.locator('.issue-card').first();await expect(issue.locator('.issue-next-step')).toContainText('建议下一步');await expect(issue.locator('.issue-impact')).toBeVisible();await expect(issue.locator('.issue-primary-action')).toHaveAttribute('href',new RegExp(`mesh=${mesh.id}`));const acknowledgement=page.waitForResponse(response=>response.request().method()==='PATCH'&&new URL(response.url()).pathname.endsWith('/console/notices'));await issue.getByRole('button',{name:'标记已知'}).click();expect((await acknowledgement).ok()).toBe(true);await page.reload();await page.getByRole('button',{name:/^已知 \d+$/,exact:true}).click();await expect(page.locator('.issue-card')).not.toHaveCount(0);
});

test('device drawer edits persist and unsaved changes block switching network',async({page})=>{
 const [mesh,other]=await meshes(page);await page.goto(`${origin}/peers?mesh=${mesh.id}`);await expect(page.locator('main')).toHaveAttribute('data-console-ready','true');await page.getByRole('button',{name:'家庭记忆库',exact:true}).click();await expect(page).toHaveURL(/resource=/);const d=page.getByRole('dialog');await d.getByRole('button',{name:'修改基本信息',exact:true}).click();await d.locator('#drawer-device-location').fill('书房 · 验收');
 page.once('dialog',dialog=>dialog.dismiss());await d.getByRole('button',{name:'Close / 关闭'}).click();await expect(d).toBeVisible();await d.getByRole('button',{name:'保存更改'}).click();await expect.poll(async()=> (await(await page.request.get(`${origin}/api/v1/meshes/${mesh.id}/peers`)).json()).items.find(p=>p.name==='home-nas').location).toBe('书房 · 验收');
 await expect(d.getByRole('status').filter({hasText:/^已保存$/})).toHaveText('已保存');await screenshot(page,'device-detail-zh');await d.getByRole('button',{name:'Close / 关闭'}).click();await expect(page).not.toHaveURL(/resource=/);await page.locator('.network-switcher summary').click();await page.locator('.network-menu a').filter({hasText:other.name}).click();await expect(page).toHaveURL(new RegExp(other.id));await expect(page.getByRole('button',{name:'家庭记忆库',exact:true})).toHaveCount(0);
});

test('search opens another detail on the current route and immutable network fields stay read only',async({page})=>{
 const [mesh]=await meshes(page);await page.goto(`${origin}/peers?mesh=${mesh.id}`);await expect(page.locator('main')).toHaveAttribute('data-console-ready','true');
 for(const query of ['test-consumer','home-nas']){
  await page.getByRole('button',{name:'全局搜索',exact:true}).click();let dialog=page.getByRole('dialog');await dialog.getByRole('textbox').fill(query);
  await dialog.getByRole('link').first().click();dialog=page.getByRole('dialog',{name:'设备详情',exact:true});await expect(dialog).toBeVisible();await expect(dialog).toContainText(query);await dialog.getByRole('button',{name:'Close / 关闭'}).click();
 }
 await page.getByRole('button',{name:'家庭记忆库',exact:true}).click();const detail=page.getByRole('dialog',{name:'设备详情',exact:true});
 await detail.getByRole('tab',{name:'共享与访问',exact:true}).click();await expect(detail.getByRole('link').filter({hasText:'文件服务'}).first()).toBeVisible();await expect(detail.locator('#access-source')).toHaveCount(0);await expect(detail.locator('#access-source-search')).toHaveCount(0);await expect(detail.getByRole('heading',{name:'可以访问',exact:true})).toBeVisible();await expect(detail.getByRole('heading',{name:'这台设备对外共享',exact:true})).toBeVisible();await expect(detail.getByRole('link',{name:'调整访问',exact:true})).toHaveAttribute('href',/source=peer/);await screenshot(page,'device-sharing-access-zh');
 await detail.getByRole('tab',{name:'维护',exact:true}).click();await detail.getByText('查看设备操作记录',{exact:true}).click();await expect(detail).toContainText('设备 · 修改');await expect(detail).not.toContainText('peer.update');await screenshot(page,'device-activity-zh');await detail.getByRole('button',{name:'Close / 关闭'}).click();
 await page.goto(`${origin}/meshes?mesh=${mesh.id}`);await expect(page.locator('main')).toHaveAttribute('data-console-ready','true');
 await expect(page.locator('#network-identity')).toHaveAttribute('readonly', /^(true)?$/);
 await page.locator('#network-advanced > summary').click();
 await expect(page.locator('#network-advanced .readonly-value').filter({hasText:mesh.address_cidr})).toBeVisible();
 await expect(page.locator('#network-advanced .readonly-value').filter({hasText:mesh.id})).toBeVisible();
 await expect(page.getByLabel('DNS 后缀',{exact:true})).toBeEnabled();
});

test('LAN target editing previews withdrawal, preserves grants and reapproves the exact gateway',async({page})=>{
 test.setTimeout(90000);const [mesh]=await meshes(page),base=`${origin}/api/v1/meshes/${mesh.id}`;
 const peers=(await(await page.request.get(base+'/peers')).json()).items,provider=peers.find(p=>p.name==='home-nas');
 const id=randomUUID(),name='地址变更验收-'+id.slice(0,6),draft={request_id:id,name,provider:provider.id,target:{kind:'network',definition:{name,target:{kind:'subnet',prefix:'192.168.217.10/32',site_id:randomUUID()}},dns_name:null,dns_address:null},source:{kind:'none'},protocol:6,port:443,reason:'Isolated browser verification'};
 const creation=await(await page.request.post(base+'/console/sharing/preview',{data:draft})).json();expect(creation.digest).toBeTruthy();
 expect((await page.request.post(base+'/console/sharing/apply',{headers:{'If-Match':`"${creation.version}"`},data:{draft,preview_digest:creation.digest}})).ok()).toBe(true);
 await page.goto(`${origin}/services?mesh=${mesh.id}&resource=${id}`);const d=page.getByRole('dialog');await d.getByRole('tab',{name:'共享信息',exact:true}).click();await d.getByRole('button',{name:'修改目标',exact:true}).click();
 await d.getByLabel('目标地址或网段',{exact:true}).fill('192.168.217.11/32');await d.getByLabel('变更原因',{exact:true}).fill('打印机地址已调整');await d.getByRole('button',{name:'预览变更影响',exact:true}).click();
 await expect(d.getByText(/1 个网关需要重新批准/)).toBeVisible();await d.getByLabel('输入原共享名称确认',{exact:true}).fill(name);await screenshot(page,'network-edit-preview-zh');await d.getByRole('button',{name:'确认提交变更',exact:true}).click();
 await expect.poll(async()=>(await(await page.request.get(base+`/network-resources/${id}`)).json()).definition.target.prefix).toBe('192.168.217.11/32');await expect(d.getByRole('button',{name:'查看状态',exact:true})).toBeVisible();await d.getByRole('button',{name:'查看状态',exact:true}).click();await expect(d.getByRole('tab',{name:'状态',exact:true})).toHaveClass(/active/);
 await d.getByRole('tab',{name:'网关路径',exact:true}).click();await expect(d.getByText(/未批准/)).toBeVisible();await d.getByRole('button',{name:'管理此网关',exact:true}).click();await d.getByLabel('网关优先级',{exact:true}).fill('25');await d.getByLabel('批准此网关提供当前目标',{exact:true}).check();await d.getByLabel('网关变更原因',{exact:true}).fill('核对新的打印机目标');await d.getByRole('button',{name:'预览网关变更',exact:true}).click();
 const gateway=(await(await page.request.get(base+`/console/network-resources/${id}/gateways`)).json()).items[0];await d.getByLabel('输入网关名称确认',{exact:true}).fill(gateway.peer_name);await screenshot(page,'gateway-approval-preview-zh');await d.getByRole('button',{name:'确认网关变更',exact:true}).click();
 await expect.poll(async()=>(await(await page.request.get(base+`/console/network-resources/${id}/gateways`)).json()).items[0].binding.approved).toBe(true);await accessible(page);
});

test('sharing evidence refresh preserves dirty drafts and rejects stale writes',async({page})=>{
 const [mesh]=await meshes(page),base=`${origin}/api/v1/meshes/${mesh.id}`;
 const peers=(await(await page.request.get(base+'/peers')).json()).items,provider=peers.find(p=>p.name==='home-nas');
 const id=randomUUID(),name='并发编辑-'+id.slice(0,6),draft={request_id:id,name,provider:provider.id,target:{kind:'service',protocols:['tcp'],port:18444,alias:null},source:{kind:'none'},protocol:6,port:18444,reason:'Isolated concurrent edit test'};
 const preview=await(await page.request.post(base+'/console/sharing/preview',{data:draft})).json();expect(preview.digest).toBeTruthy();expect((await page.request.post(base+'/console/sharing/apply',{headers:{'If-Match':`"${preview.version}"`},data:{draft,preview_digest:preview.digest}})).ok()).toBe(true);
 await page.goto(`${origin}/services?mesh=${mesh.id}&resource=${id}`);const d=page.getByRole('dialog');await d.getByRole('tab',{name:'共享信息',exact:true}).click();await d.locator('#edit-share-name').fill('尚未提交的名称');
 const current=await(await page.request.get(base+`/services/${id}`)).json();expect((await page.request.patch(base+`/console/services/${id}`,{headers:{'If-Match':`"${current.version}"`},data:{display_name:'其他会话已保存',alias:null,protocols:['tcp'],listen_port:18444,paused:false,reason:'Concurrent writer'}})).ok()).toBe(true);
 await d.getByRole('button',{name:'重新检查',exact:true}).click();await expect(d.getByText(/资源已在别处更新/)).toBeVisible();await expect(d.locator('#edit-share-name')).toHaveValue('尚未提交的名称');await d.getByRole('button',{name:'保存设置',exact:true}).click();await expect(d.getByRole('alert')).toContainText(/version|版本|changed/);await expect(d.locator('#edit-share-name')).toHaveValue('尚未提交的名称');await screenshot(page,'sharing-conflict-draft-zh');
 page.once('dialog',dialog=>dialog.accept());await d.getByRole('button',{name:'Close / 关闭'}).click();
});

test('LAN and exit grants revoke and restore from access details',async({page})=>{
 test.setTimeout(90000);const [mesh]=await meshes(page),base=`${origin}/api/v1/meshes/${mesh.id}`;
 const peers=(await(await page.request.get(base+'/peers')).json()).items,provider=peers.find(p=>p.name==='home-nas'),source=peers.find(p=>p.name==='test-consumer');
 for(const kind of ['lan','internet']){
  const id=randomUUID(),name=`授权闭环-${kind}-${id.slice(0,5)}`,target=kind==='lan'?{kind:'subnet',prefix:'192.168.233.10/32',site_id:randomUUID()}:{kind:'internet',ipv4:true,ipv6:false};
  await createShare(page,base,{request_id:id,name,provider:kind==='internet'?source.id:provider.id,target:{kind:'network',definition:{name,target},dns_name:null,dns_address:null},source:{kind:'peer',id:source.id},protocol:17,port:5353,reason:'Browser grant lifecycle'});
  await page.goto(`${origin}/policy?mesh=${mesh.id}`);await page.locator('#access-source').selectOption(`peer:${source.id}`);await page.locator('#access-resource-search').fill(name);await page.getByRole('button',{name:new RegExp(name+'.*查看原因')}).click();const d=page.getByRole('region',{name:'访问详情'});
  const grants=base+`/console/network-resources/${id}/grants`;
  for(const enabled of [false,true]){
   await d.getByRole('button',{name:enabled?'恢复此授权':'撤销此授权',exact:true}).click();await d.locator('#grant-state-reason').fill(enabled?'恢复已核对的来源':'撤销不再需要的访问');await d.getByRole('checkbox').check();await screenshot(page,`grant-${kind}-${enabled?'restore':'revoke'}-zh`);await d.getByRole('button',{name:'确认提交',exact:true}).click();await expect.poll(async()=>(await(await page.request.get(grants)).json()).items[0].enabled).toBe(enabled);
  }
  if(kind==='lan'){
   const policy=await(await page.request.get(base+'/resource-policy')).json();
   const wildcard=structuredClone(policy.document.rules.find(rule=>rule.resources.includes(id)));
   wildcard.id=randomUUID();wildcard.source={peers:[],labels:{},cidrs:[]};wildcard.source_collections=[];
   expect((await page.request.put(base+'/resource-policy',{headers:{'If-Match':`"${policy.version}"`},data:{...policy.document,rules:[...policy.document.rules,wildcard]}})).ok()).toBe(true);
   const advanced=d.locator('.managed-grant').filter({hasText:'按高级规则匹配来源'});
   await expect(advanced.getByRole('link',{name:'查看高级规则'})).toBeVisible();
   await expect(advanced.getByRole('button',{name:'撤销此授权'})).toHaveCount(0);
  }
  await accessible(page);
 }
});

test('top bar waits for WASM hydration and the first search click works',async({page})=>{
 const [mesh]=await meshes(page);
 let release;
 const ready=new Promise(resolve=>{release=resolve;});
 let intercepted=false;
 await page.route('**/assets/peerward-console-web_bg.wasm*',async route=>{
  intercepted=true;await ready;await route.continue();
 });
 try{
  await page.goto(`${origin}/policy?mesh=${mesh.id}`,{waitUntil:'commit'});
  await expect.poll(()=>intercepted).toBe(true);
  await expect(page.locator('main')).toHaveAttribute('data-console-ready','false');
  await expect(page.locator('header.topbar')).toHaveJSProperty('inert',true);
  await expect(page.locator('main')).toHaveJSProperty('inert',true);
  await expect(page.getByRole('button',{name:'全局搜索',exact:true,includeHidden:true})).toBeDisabled();
  await expect(page.getByRole('button',{name:'通知中心',exact:true,includeHidden:true})).toBeDisabled();
  await expect(page.locator('button.mobile-menu')).toBeDisabled();
 }finally{release();}
 await expect(page.locator('main')).toHaveAttribute('data-console-ready','true');
 await expect(page.locator('header.topbar')).toHaveJSProperty('inert',false);
 await expect(page.locator('main')).toHaveJSProperty('inert',false);
 await page.getByRole('button',{name:'全局搜索',exact:true}).click();
 await expect(page.getByRole('dialog').getByRole('textbox')).toBeVisible();
});

test('group search selects the matching matrix source on the same route',async({page})=>{
 const errors=[];page.on('pageerror',error=>errors.push(error.message));
 const [mesh]=await meshes(page),base=`${origin}/api/v1/meshes/${mesh.id}`;
 const peers=(await(await page.request.get(base+'/peers')).json()).items,source=peers.find(p=>p.name==='test-consumer');
 for(const name of ['搜索定位甲','搜索定位乙']){
  const id=randomUUID();expect((await page.request.post(base+'/collections',{data:{id,definition:{name,kind:'devices',members:[source.id],labels:{}}}})).ok()).toBe(true);
  if(name==='搜索定位甲'){await page.goto(`${origin}/policy?mesh=${mesh.id}`);await expect(page.locator('main')).toHaveAttribute('data-console-ready','true');}
  await page.getByRole('button',{name:'全局搜索',exact:true}).click();const search=page.getByRole('dialog');await search.getByRole('textbox').fill(name);await search.getByRole('link').filter({hasText:name}).click();await expect(page).toHaveURL(/source=group/);await expect(page.locator('#access-source')).toHaveValue(`group:${id}`);await expect(page.locator('#access-source option:checked')).toContainText(name);
 }
 await screenshot(page,'group-search-access-zh');await accessible(page);expect(errors).toEqual([]);
});

test('service simulation distinguishes configured transports and validates publisher address',async({page})=>{
 const [mesh]=await meshes(page),base=`${origin}/api/v1/meshes/${mesh.id}`;
 const peers=(await(await page.request.get(base+'/peers')).json()).items,provider=peers.find(p=>p.name==='home-nas'),source=peers.find(p=>p.name==='test-consumer');
 const id=randomUUID(),name='协议条件验收-'+id.slice(0,6);
 await createShare(page,base,{request_id:id,name,provider:provider.id,target:{kind:'service',protocols:['tcp','udp'],port:19999,alias:null},source:{kind:'peer',id:source.id},protocol:6,port:19999,reason:'Transport simulation'});
 const policy=await(await page.request.get(base+'/policy')).json();
 const deny={id:randomUUID(),priority:0,action:'deny',enabled:true,log:false,source:{peer_ids:[source.id],labels:{},cidrs:[]},destination:{peer_ids:[provider.id],labels:{},cidrs:[]},protocol:'udp',destination_ports:[{first:19999,last:19999}]};
 expect((await page.request.put(base+'/policy',{headers:{'If-Match':`"${policy.revision}"`},data:{...policy,revision:Number(policy.revision)+1,rules:[...policy.rules,deny]}})).ok()).toBe(true);
 await page.goto(`${origin}/policy?mesh=${mesh.id}`);await page.locator('#access-source').selectOption(`peer:${source.id}`);await page.locator('#access-resource-search').fill(name);const cell=page.getByRole('button',{name:new RegExp(name+'.*查看原因')});await expect(cell).toContainText('部分允许');await cell.click();const d=page.locator('.access-simulator-panel');await d.getByText('高级：模拟具体条件',{exact:true}).click();
 for(const [protocol,outcome] of [['6','允许'],['17','拒绝']]){await d.locator('#simulate-service-protocol').selectOption(protocol);await d.getByRole('button',{name:'模拟访问',exact:true}).click();await expect(d.getByRole('heading',{name:outcome,exact:true})).toBeVisible();}
 await screenshot(page,'service-conditional-simulation-zh');await d.locator('#simulate-service-address').fill('203.0.113.77');await d.getByRole('button',{name:'模拟访问',exact:true}).click();await expect(d.getByRole('alert')).toContainText('该地址不属于提供此服务的设备');await accessible(page);
});

test('dialog focus returns, detail tabs use keyboard semantics, and busy submit is single-shot',async({page})=>{
 const [mesh]=await meshes(page);const base=`${origin}/api/v1/meshes/${mesh.id}`;
 await page.goto(`${origin}/peers?mesh=${mesh.id}`);await expect(page.locator('main')).toHaveAttribute('data-console-ready','true');
 const deviceTrigger=page.locator('.device-name').first();await deviceTrigger.focus();await deviceTrigger.click();
 const deviceDialog=page.getByRole('dialog',{name:'设备详情'});await expect(deviceDialog).toBeVisible();
 await expect(page.locator('#console-sidebar')).toHaveAttribute('inert','');
 const statusTab=deviceDialog.getByRole('tab',{name:'状态',exact:true});const networkTab=deviceDialog.getByRole('tab',{name:'共享与访问',exact:true});const maintenanceTab=deviceDialog.getByRole('tab',{name:'维护',exact:true});
 let releaseMatrix;let matrixHeld=false;const matrixGate=new Promise(resolve=>{releaseMatrix=resolve;});
 await page.route('**/console/matrix',async route=>{matrixHeld=true;await matrixGate;await route.continue();});
 try {
 await expect(statusTab).toHaveAttribute('aria-selected','true');await statusTab.focus();await page.keyboard.press('ArrowRight');
 await expect.poll(()=>matrixHeld).toBe(true);
 await expect(networkTab).toBeFocused();await expect(networkTab).toHaveAttribute('aria-selected','true');await expect(deviceDialog.getByRole('tabpanel')).toHaveAttribute('aria-labelledby','device-detail-tab-network');
 await page.keyboard.press('End');await expect(maintenanceTab).toBeFocused();await expect(maintenanceTab).toHaveAttribute('aria-selected','true');
 await page.keyboard.press('Home');await expect(statusTab).toBeFocused();await expect(statusTab).toHaveAttribute('aria-selected','true');
 } finally { releaseMatrix();await page.unrouteAll({behavior:'wait'}); }
 await deviceDialog.getByRole('button',{name:'Close / 关闭'}).click();
 await expect(deviceDialog).toHaveCount(0);await expect(deviceTrigger).toBeFocused();await expect(page.locator('#console-sidebar')).not.toHaveAttribute('inert','');

 const searchButton=page.getByRole('button',{name:'全局搜索',exact:true});await searchButton.focus();await searchButton.click();const searchDialog=page.getByRole('dialog',{name:'全局搜索'});await expect(searchDialog.getByRole('textbox')).toBeFocused();await page.keyboard.press('Escape');await expect(searchDialog).toHaveCount(0);await expect(searchButton).toBeFocused();

 const peers=(await(await page.request.get(base+'/peers')).json()).items;const provider=peers.find(p=>p.name==='home-nas')??peers[0];expect(provider).toBeTruthy();
 await page.goto(`${origin}/services?mesh=${mesh.id}`);await page.getByRole('button',{name:'＋ 添加共享',exact:true}).click();const shareDialog=page.getByRole('dialog',{name:'添加共享'});
 await shareDialog.getByRole('button',{name:'下一步',exact:true}).click();await shareDialog.locator('#share-name').fill(`防重复-${randomUUID().slice(0,6)}`);await shareDialog.locator('#share-provider').selectOption(provider.id);await shareDialog.getByRole('button',{name:'下一步',exact:true}).click();
 let previewCalls=0;await page.route('**/console/sharing/preview',async route=>{previewCalls+=1;await new Promise(resolve=>setTimeout(resolve,500));await route.continue();});
 const previewButton=shareDialog.getByRole('button',{name:'下一步',exact:true});await previewButton.focus();await page.keyboard.press('Enter');await page.keyboard.press('Escape');await expect(shareDialog).toBeVisible();await page.keyboard.press('Enter');
 await expect.poll(()=>previewCalls).toBe(1);await expect(shareDialog.locator('.sharing-review')).toBeVisible();
 let discardPrompt='';page.once('dialog',async dialog=>{discardPrompt=dialog.message();await dialog.accept();});await shareDialog.getByRole('button',{name:'Close / 关闭'}).click();await expect.poll(()=>discardPrompt).toContain('未保存');await accessible(page);
});

test('sharing choices recover from failed reads and preview explains an empty group grant', async ({page}) => {
 const [mesh] = await meshes(page), base = `${origin}/api/v1/meshes/${mesh.id}`;
 const peers = (await (await page.request.get(base+'/peers')).json()).items;
 const provider = peers.find(peer=>peer.name==='home-nas');
 const group = randomUUID(), groupName = `empty-${group.slice(0,8)}`;
 expect((await page.request.post(base+'/collections',{data:{id:group,definition:{name:groupName,kind:'devices',members:[],labels:{}}}})).ok()).toBe(true);
 await page.addInitScript(() => {
   window.allowChoiceRetry = false;
   document.addEventListener('click', event => {
     if (event.target.closest('button')?.textContent.trim() === '重试读取候选项') window.allowChoiceRetry = true;
   }, true);
 });
 await page.route('**/console/devices?**',async route=>(await page.evaluate(()=>window.allowChoiceRetry)) ? route.continue() : route.abort());
 await page.goto(`${origin}/services?mesh=${mesh.id}`);
 await page.getByRole('button',{name:'＋ 添加共享',exact:true}).click();
 const dialog = page.getByRole('dialog');
 await dialog.getByRole('button',{name:'下一步',exact:true}).click();
 await expect(dialog.getByRole('alert')).toBeVisible();
 await dialog.getByRole('button',{name:'重试读取候选项',exact:true}).click();
 await expect(dialog.getByRole('alert')).toHaveCount(0);
 await dialog.locator('#share-name').fill('empty-group-preview');
 await dialog.locator('#share-provider').selectOption(provider.id);
 await dialog.getByRole('button',{name:'下一步',exact:true}).click();
 if (await dialog.getByRole('button',{name:'重试读取候选项',exact:true}).isVisible()) await dialog.getByRole('button',{name:'重试读取候选项',exact:true}).click();
 await dialog.locator(`input[name=share-source][value="group:${group}"]`).check();
 await dialog.getByRole('button',{name:'下一步',exact:true}).click();
 await expect(dialog.locator('.sharing-review')).toContainText(groupName);
 await expect(dialog.locator('.sharing-review')).toContainText(provider.display_name);
 await expect(dialog.locator('.sharing-preview-warnings')).toContainText('所选设备组没有有效成员');
 await expect(dialog.locator('.sharing-preview-warnings')).toContainText('权限检查不代表目标当前可达');
 await screenshot(page,'sharing-review-empty-group-zh');
 await accessible(page);
});
