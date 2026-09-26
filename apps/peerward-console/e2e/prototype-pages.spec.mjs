import {expect,test} from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';
import {mkdir} from 'node:fs/promises';
import path from 'node:path';
import {randomUUID} from 'node:crypto';
const origin=process.env.PEERWARD_CONSOLE_E2E_URL;
test.skip(process.env.PEERWARD_CONSOLE_V14_E2E!=='1','isolated fixture required');
test.use({viewport:{width:1440,height:1000},serviceWorkers:"block"});
async function capture(page,name){const dir=process.env.PEERWARD_EVIDENCE_SCREENSHOT_DIR;if(dir){await mkdir(dir,{recursive:true});await page.screenshot({path:path.join(dir,name+'.png'),fullPage:!name.startsWith('network-create'),animations:'disabled'});}}
async function preference(page,kind,value){await page.locator('.account-menu > summary').click();await page.locator('#pw-'+kind).selectOption(value);await page.locator('.account-menu > summary').click();}
async function meshes(page){return(await(await page.request.get(origin+'/api/v1/meshes')).json()).items;}
async function open(page,route,mesh){await page.goto(`${origin}/${route}${mesh?'?mesh='+mesh:''}`);await expect(page.locator('main')).toHaveAttribute('data-console-ready','true');}
async function accessible(page){const r=await new AxeBuilder({page}).withTags(['wcag2a','wcag2aa']).analyze();expect(r.violations.filter(v=>['critical','serious'].includes(v.impact))).toEqual([]);}
async function patch(page,id,data){const url=`${origin}/api/v1/meshes/${id}`,old=await(await page.request.get(url)).json();const r=await page.request.patch(url,{headers:{'If-Match':`"${old.version}"`},data});expect(r.ok(),await r.text()).toBe(true);return r.json();}

test('portfolio preserves scope and creates through a centered modal',async({page})=>{
 const errors=[];page.on('pageerror',e=>errors.push(e.message));page.on('console',m=>{if(m.type()==='error')errors.push(m.text());});
 const [mesh]=await meshes(page);await open(page,'networks',mesh.id);await expect(page.getByRole('heading',{level:1})).toHaveText('所有网络');const current=page.locator('.portfolio-card').filter({hasText:mesh.name});await expect(current).toHaveClass(/current/);await expect(current.getByText('在线设备',{exact:true})).toBeVisible();await expect(page.locator('.action-panel')).toHaveCount(0);await accessible(page);await capture(page,'portfolio-zh');
 await page.getByRole('button',{name:'＋ 新建网络',exact:true}).click();const d=page.getByRole('dialog');await expect(d.locator('#new-network-name')).toBeFocused();await d.locator('#new-network-name').fill('办公室网络');await d.locator('#new-network-identifier').fill('office-mesh');await expect(d.locator('input')).toHaveCount(2);
 const box=await d.boundingBox();expect(box.width).toBe(560);expect(Math.abs(box.x+box.width/2-720)).toBeLessThan(2);expect(Math.abs(box.y+box.height/2-500)).toBeLessThan(2);await d.locator('#new-network-name').focus();await accessible(page);await capture(page,'network-create-zh');expect(errors).toEqual([]);
 page.once('dialog',d=>d.dismiss());await page.keyboard.press('Escape');await expect(d).toBeVisible();page.once('dialog',d=>d.accept());await page.keyboard.press('Escape');await expect(d).toHaveCount(0);
 await current.getByRole('link',{name:'网络设置'}).click();await expect(page.locator('#network-name')).toHaveValue(mesh.name);
});

test('settings save real versioned changes without changing immutable fields',async({page})=>{
 const [mesh]=await meshes(page);await open(page,'meshes',mesh.id);await expect(page.locator('#network-name')).toHaveValue(mesh.name);await expect(page.locator('#network-advanced')).not.toHaveAttribute('open','');await expect(page.locator('#network-identity')).toHaveAttribute('readonly',/^(true)?$/);
 const sizes=await page.locator('.device-conditions input[type=checkbox]').evaluateAll(ns=>ns.filter(n=>n.getClientRects().length).map(n=>({w:n.getBoundingClientRect().width,h:n.getBoundingClientRect().height})));expect(sizes.length).toBeGreaterThan(1);expect(sizes.every(s=>s.w<=38&&s.h<=22)).toBe(true);await accessible(page);await capture(page,'network-settings-zh');
 await page.locator('#network-name').fill(mesh.name+'-已修改');await page.getByRole('button',{name:'保存网络设置',exact:true}).click();await expect(page.locator('.settings-basics [role=status]')).toContainText('网络设置已保存');await expect(page.locator('[data-console-dirty="true"]')).toHaveCount(0);await page.reload();await expect(page.locator('#network-name')).toHaveValue(mesh.name+'-已修改');
 const saved=await(await page.request.get(`${origin}/api/v1/meshes/${mesh.id}`)).json();for(const k of ['address_cidr','secondary_cidr','gateway','mtu'])expect(saved[k]).toEqual(mesh[k]);await patch(page,mesh.id,{name:mesh.name});
});

test('settings conflicts retain drafts and switching requires explicit discard',async({page})=>{
 const [mesh,other]=await meshes(page);await open(page,'meshes',mesh.id);await expect(page.locator('#network-name')).toHaveValue(mesh.name);await page.locator('#network-name').fill('未提交草稿');await patch(page,mesh.id,{name:mesh.name+'-外部修改'});await page.getByRole('button',{name:'保存网络设置',exact:true}).click();await expect(page.locator('.settings-basics [role=alert]')).toBeVisible();await expect(page.locator('#network-name')).toHaveValue('未提交草稿');await page.getByRole('button',{name:'重新读取最新设置',exact:true}).click();await expect(page.locator('#network-name')).toHaveValue(mesh.name+'-外部修改');await page.locator('#network-name').fill('再次编辑');
 page.once('dialog',d=>d.dismiss());await page.locator('.network-switcher summary').click();await page.locator('.network-menu').getByRole('link',{name:'管理所有网络',exact:true}).click();await expect(page.getByRole('heading',{level:1})).toHaveText('网络设置');page.once('dialog',d=>d.accept());if(!await page.locator('.network-switcher').evaluate(node=>node.open))await page.locator('.network-switcher summary').click();await page.locator('.network-menu').getByRole('link',{name:'管理所有网络',exact:true}).click();await expect(page.getByRole('heading',{level:1})).toHaveText('所有网络');await page.locator('.portfolio-card').filter({hasText:other.name}).getByRole('link',{name:'网络设置'}).click();await expect(page.locator('#network-name')).toHaveValue(other.name);await patch(page,mesh.id,{name:mesh.name});
});

test('device condition editing preserves advanced scope',async({page})=>{
 const [mesh]=await meshes(page),url=`${origin}/api/v1/meshes/${mesh.id}/device-conditions`,old=await(await page.request.get(url)).json();await open(page,'meshes',mesh.id);const panel=page.getByRole('region',{name:'设备条件',exact:true});await expect(panel.locator('#condition-minimum-version')).toBeEnabled();await panel.locator('#condition-minimum-version').fill('1.0.0');await panel.getByRole('checkbox',{name:/已核对影响/}).check();await panel.getByRole('button',{name:'保存设备条件',exact:true}).click();await expect(panel.getByRole('status')).toContainText('已保存');const saved=await(await page.request.get(url)).json();expect(saved.definition.minimum_version).toBe('1.0.0');expect(saved.definition.scope).toEqual(old.definition.scope);expect(saved.definition.required_capabilities).toEqual(old.definition.required_capabilities);expect((await page.request.put(url,{headers:{'If-Match':`"${saved.version}"`},data:old.definition})).ok()).toBe(true);
});

test('access results evaluate the selected source and open its explanation',async({page})=>{
 let evaluations=0;page.on('request',r=>{if(new URL(r.url()).pathname.endsWith('/console/matrix'))evaluations++;});
 const [mesh]=await meshes(page),base=`${origin}/api/v1/meshes/${mesh.id}`;const peers=(await(await page.request.get(base+'/peers')).json()).items;const draft={request_id:randomUUID(),name:'访问结果验收服务',provider:peers[0].id,target:{kind:'service',protocols:['tcp'],port:8443,alias:null},source:{kind:'peer',id:peers[1].id},protocol:6,port:8443,reason:'Access results browser acceptance'};const preview=await(await page.request.post(base+'/console/sharing/preview',{data:draft})).json();expect(preview.digest).toBeTruthy();expect((await page.request.post(base+'/console/sharing/apply',{headers:{'If-Match':`"${preview.version}"`},data:{draft,preview_digest:preview.digest}})).ok()).toBe(true);await open(page,'policy',mesh.id);await expect(page.locator('.access-empty-selection')).toBeVisible();const source=peers.find(p=>p.administrative_state==='enabled');expect(source).toBeTruthy();const previous=evaluations;await page.locator('#access-source').selectOption(`peer:${source.id}`);await expect.poll(()=>evaluations).toBeGreaterThan(previous);await expect(page.locator('.matrix-scroll tbody tr').first()).toBeVisible();await page.locator('#access-resource-search').fill('访问结果验收服务');const cell=page.getByRole('button',{name:/访问结果验收服务.*查看原因/});await cell.click();await expect(page.getByRole('region',{name:'访问详情'})).toContainText('访问结果验收服务');await expect(page.getByRole('dialog')).toHaveCount(0);await page.locator('#access-source').selectOption('');await expect(page.locator('.access-empty-selection')).toBeVisible();await capture(page,'access-results-zh');await accessible(page);
});

test('activity shows readable records and exports only the filtered page',async({page})=>{
 const [mesh]=await meshes(page);await open(page,'audit',mesh.id);await expect(page.locator('.activity-row').first()).toBeVisible();await page.locator('#activity-result').selectOption('success');const href=await page.getByRole('link',{name:'导出当前页'}).getAttribute('href'),rows=JSON.parse(Buffer.from(href.split(',')[1],'base64').toString());expect(rows.length).toBeGreaterThan(0);expect(rows.length).toBeLessThanOrEqual(50);expect(rows.every(r=>r.result==='success')).toBe(true);await page.locator('#activity-search').fill('no-such-action-abcdef');await expect(page.locator('.activity-row')).toHaveCount(0);await page.locator('#activity-search').fill('');await capture(page,'activity-log-zh');await accessible(page);
});

test('all pages fit mobile screens and pass accessibility in both themes',async({page})=>{
 test.setTimeout(150000);
 const [mesh]=await meshes(page),errors=[];
 page.on('pageerror',e=>errors.push(e.message));
 for(const route of ['','peers','services','policy','operations','networks','meshes','relays','authorities','webhooks','audit','join-tickets']) {
   await open(page,route,mesh.id);
   await capture(page,`support-${route}-zh`);
   await accessible(page);
   // The invitation route intentionally opens a modal. Set shell preferences
   // on the portfolio, then revisit the route to test the modal in that theme.
   await open(page,'networks',mesh.id);
   await page.setViewportSize({width:390,height:844});
   await preference(page,'theme','dark');
   await preference(page,'language','en-US');
   await open(page,route,mesh.id);
   expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth)).toBe(true);
   await capture(page,`support-${route}-mobile-en-dark`);
   await accessible(page);
   await open(page,'networks',mesh.id);
   await page.locator('.mobile-menu').click();
   await expect(page.locator('.sidebar')).toHaveClass(/mobile-open/);
   await page.keyboard.press('Escape');
   await expect(page.locator('.sidebar')).not.toHaveClass(/mobile-open/);
   await page.setViewportSize({width:1440,height:1000});
   await preference(page,'theme','light');
   await preference(page,'language','zh-CN');
 }
 expect(errors).toEqual([]);
});

test('empty network scope guides selection instead of exposing unusable forms',async({page})=>{
 await open(page,'');await expect(page.getByRole('heading',{name:'先选择一个网络',exact:true})).toBeVisible();await expect(page.getByRole('link',{name:'查看所有网络',exact:true})).toBeVisible();
 for(const route of ['peers','services','policy','join-tickets','authorities','webhooks']){await open(page,route);await expect(page.getByRole('heading',{name:'先选择一个网络',exact:true})).toBeVisible();await expect(page.locator('main form')).toHaveCount(0);await expect(page.getByRole('link',{name:'查看所有网络',exact:true})).toBeVisible();}
});

test('creation retries the same request after a rejected submission',async({page})=>{
 const requests=[];await page.route('**/api/v1/mesh-provisioning',async route=>{if(route.request().method()!=='POST')return route.continue();requests.push(route.request().postDataJSON());await route.fulfill({status:503,json:{error:{code:'temporarily_unavailable',message:'Executor unavailable',request_id:'fixture',retryable:true,field_errors:{}}}});});
 await open(page,'networks');await page.getByRole('button',{name:'＋ 新建网络',exact:true}).click();const d=page.getByRole('dialog');await d.locator('#new-network-name').fill('重试网络');await d.locator('#new-network-identifier').fill('retry-network');for(let n=1;n<=2;n++){await d.getByRole('button',{name:'创建并切换',exact:true}).click();await expect(d.getByRole('alert')).toBeVisible();expect(requests.length).toBe(n);}expect(requests[0]).toEqual(requests[1]);expect(requests[0].name).toBe('重试网络');expect(requests[0].network_identifier).toBe('retry-network');
});

test('network deletion requires the saved name and reports submitted progress',async({page})=>{
 const [mesh]=await meshes(page);let request;await page.route(`**/api/v1/meshes/${mesh.id}`,async route=>{if(route.request().method()!=='DELETE')return route.continue();request={body:route.request().postDataJSON(),version:route.request().headers()['if-match']};await route.fulfill({status:202,json:{mesh_id:mesh.id,job_id:randomUUID()}});});
 await open(page,'meshes',mesh.id);await expect(page.locator('#network-name')).toHaveValue(mesh.name);await page.locator('.settings-danger').getByRole('button',{name:'删除网络',exact:true}).click();const d=page.getByRole('dialog'),button=d.getByRole('button',{name:'确认删除',exact:true});await expect(button).toBeDisabled();await d.locator('#delete-network-confirm').fill(mesh.name+' ');await expect(button).toBeDisabled();await d.locator('#delete-network-confirm').fill(mesh.name);await capture(page,'delete-network-confirm-zh');await button.click();await expect(d).toHaveCount(0);expect(request).toEqual({body:{confirmation_name:mesh.name},version:`"${mesh.version}"`});await expect(page.locator('.settings-danger [role=status]')).toContainText('删除请求已提交');await expect(page.locator('.settings-danger').getByRole('button',{name:'删除网络',exact:true})).toBeDisabled();
});

// Model only the executor transition; never claim that the fixture ran a Relay.
test('network creation waits for executor completion before navigating', async ({page}) => {
  const [mesh] = await meshes(page);
  let job;
  let polls = 0;
  let retries = 0;
  let submissions = 0;
  await page.route(url => url.pathname.startsWith('/api/v1/mesh-provisioning'), async route => {
    if (route.request().method() === 'POST' && route.request().url().endsWith('/retry')) {
      expect(route.request().url()).toContain('/'+job.id+'/retry');retries++;job={...job,status:'running',error_code:null};await route.fulfill({json:job});
    } else if (route.request().method() === 'POST') {
      submissions++;
      const request = route.request().postDataJSON();
      job = {id: request.request_id, mesh_id: mesh.id, name: request.name,
        operation: 'create', existing_mesh: false, status: 'running', stage: 'signer',
        error_code: null, relay_endpoint: null,
        created_at: '2026-09-20T00:00:00Z', updated_at: '2026-09-20T00:00:00Z'};
      await route.fulfill({json: job});
    } else {
      if (job) polls++;
      await route.fulfill({json: new URL(route.request().url()).pathname.endsWith('/mesh-provisioning') ? {items: job ? [job] : [], next_cursor: null} : job});
    }
  });
  await open(page, 'networks');
  await page.getByRole('button', {name: '＋ 新建网络', exact: true}).click();
  const drawer = page.getByRole('dialog');
  await drawer.locator('#new-network-name').fill('等待执行的网络');
  await drawer.locator('#new-network-identifier').fill('waiting-network');
  await drawer.getByRole('button', {name: '创建并切换', exact: true}).click();
  await expect.poll(() => polls).toBeGreaterThan(1);
  await expect(drawer).toBeVisible();
  await expect(page).toHaveURL(url => url.origin === origin && url.pathname === '/networks' && !url.search);
  job = {...job,status:'failed',error_code:'relay_unhealthy'};
  await expect(drawer.getByRole('button',{name:'重试初始化',exact:true})).toBeEnabled();
  await drawer.getByRole('button',{name:'重试初始化',exact:true}).click();
  await expect.poll(()=>retries).toBe(1);expect(submissions).toBe(1);
  job = {...job, status: 'succeeded', stage: 'complete'};
  await expect(drawer).toHaveCount(0);
  await expect(page).toHaveURL(origin + '/?mesh=' + mesh.id);
  await expect(page.getByRole('heading',{level:1})).toHaveText('概览');
});

test('create modal validates identifiers and supports mobile dark keyboard dismissal',async({page})=>{
 await open(page,'networks');await preference(page,'theme','dark');await preference(page,'language','en-US');await page.setViewportSize({width:390,height:844});
 await page.getByRole('button',{name:'＋ New network',exact:true}).click();const d=page.getByRole('dialog');await d.locator('#new-network-name').fill('Office network');const submit=d.getByRole('button',{name:'Create and switch',exact:true});await expect(submit).toBeDisabled();
 for(const value of ['-start','end-','with spaces','网络']){await d.locator('#new-network-identifier').fill(value);await expect(submit).toBeDisabled();await expect(d.locator('#new-network-identifier')).toHaveAttribute('aria-invalid','true');await expect(d.locator('#network-identifier-error')).toContainText('Invalid identifier');}
 await d.locator('#new-network-identifier').fill('office-mesh');await d.locator('#new-network-name').fill('界'.repeat(43));await expect(submit).toBeDisabled();await expect(d.getByRole('alert')).toContainText('name is too long');await d.locator('#new-network-name').fill('Office network');await expect(submit).toBeEnabled();expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth)).toBe(true);await accessible(page);await capture(page,'network-create-mobile-en-dark');
 await submit.focus();await page.keyboard.press('Tab');await expect(d.getByRole('button',{name:'Close / 关闭'})).toBeFocused();
 page.once('dialog',dialog=>dialog.dismiss());await d.getByRole('button',{name:'Cancel',exact:true}).click();await expect(d).toBeVisible();page.once('dialog',dialog=>dialog.accept());await d.getByRole('button',{name:'Cancel',exact:true}).click();await expect(d).toHaveCount(0);await expect(page.getByRole('button',{name:'＋ New network',exact:true})).toBeFocused();
});

test('create modal persists identifier and closes without cancelling the durable task',async({page})=>{
 const identifier='browser-'+randomUUID().slice(0,8);await open(page,'networks');await page.getByRole('button',{name:'＋ 新建网络',exact:true}).click();const d=page.getByRole('dialog');await d.locator('#new-network-name').fill('真实创建验收');await d.locator('#new-network-identifier').fill(identifier.toUpperCase());
 const response=page.waitForResponse(r=>new URL(r.url()).pathname==='/api/v1/mesh-provisioning'&&r.request().method()==='POST');await d.getByRole('button',{name:'创建并切换',exact:true}).click();const result=await response;expect(result.status(),await result.text()).toBe(202);const job=await result.json();await expect(d.locator('.network-create-progress')).toBeVisible();await expect(d.locator('#new-network-identifier')).toBeDisabled();await expect(d.getByRole('button',{name:'正在创建…',exact:true})).toBeDisabled();await d.getByRole('button',{name:'关闭',exact:true}).click();await expect(d).toHaveCount(0);
 await page.reload();const card=page.locator('.portfolio-card').filter({hasText:identifier});await expect(card).toBeVisible();await card.getByRole('link',{name:'网络设置'}).click();await expect(page.locator('#network-identity')).toHaveValue(identifier);
 const saved=await(await page.request.get(`${origin}/api/v1/meshes/${job.mesh_id}`)).json();expect(saved.network_identifier).toBe(identifier);expect(saved.lifecycle).toBe('creating');
 await open(page,'networks');await page.getByRole('button',{name:'＋ 新建网络',exact:true}).click();await d.locator('#new-network-name').fill('重复标识');await d.locator('#new-network-identifier').fill(identifier);await d.getByRole('button',{name:'创建并切换',exact:true}).click();await expect(d.getByRole('alert')).toContainText('这个网络标识已经存在');await expect(d.locator('#new-network-identifier')).toBeEnabled();
});

// The screenshot regression: OPC is a display name; OPC-mesh must not disable creation.
test('create modal accepts uppercase identifiers and submits their lowercase form',async({page})=>{
 const requests=[];await page.route('**/api/v1/mesh-provisioning',async route=>{
  if(route.request().method()!=='POST')return route.continue();
  requests.push(route.request().postDataJSON());await route.fulfill({status:503,json:{error:{code:'temporarily_unavailable',message:'Executor unavailable',request_id:'fixture',retryable:true}}});
 });
 await open(page,'meshes');await page.getByRole('button',{name:'＋ 新建网络',exact:true}).click();const d=page.getByRole('dialog'),identifier=d.locator('#new-network-identifier'),submit=d.getByRole('button',{name:'创建并切换',exact:true});
 await d.locator('#new-network-name').fill('OPC');await identifier.fill('OPC-mesh');await expect(submit).toBeEnabled();await expect(identifier).toHaveAttribute('aria-invalid','false');await expect(d.getByRole('status')).toContainText('opc-mesh');await capture(page,'network-create-uppercase-zh');
 // Keyboard and mouse submission both normalize; typing never moves the button.
 await identifier.press('Enter');await expect(d.getByRole('alert')).toBeVisible();expect(requests).toHaveLength(1);expect(requests[0].network_identifier).toBe('opc-mesh');expect(requests[0].name).toBe('OPC');
 await identifier.fill('OPC-mesh');await submit.click();await expect.poll(()=>requests.length).toBe(2);await expect(identifier).toHaveValue('opc-mesh');expect(requests[1]).toEqual(requests[0]);
 // Re-entering uppercase after normalization still works and keeps the same request ID.
 await identifier.fill('OPC-MESH');await submit.click();await expect.poll(()=>requests.length).toBe(3);await expect(identifier).toHaveValue('opc-mesh');expect(requests[2]).toEqual(requests[0]);
});

test('invitation bulk cancellation belongs to history and is absent without records',async({page})=>{
 const [mesh,empty]=await meshes(page);await open(page,'join-tickets',empty.id);await expect(page.locator('.bulk-actions')).toHaveCount(0);await capture(page,'invite-empty-without-bulk-zh');await open(page,'join-tickets',mesh.id);
 const before=(await(await page.request.get(`${origin}/api/v1/meshes/${mesh.id}/peers`)).json()).items;
 const tickets=[];for(let n=0;n<2;n++){const response=await page.request.post(`${origin}/api/v1/meshes/${mesh.id}/join-tickets`,{data:{expires_in_seconds:300,settings:{name:'bulk-invitation-'+n}}});expect(response.ok(),await response.text()).toBe(true);tickets.push(await response.json());}
 await page.reload();await expect(page.locator('main')).toHaveAttribute('data-console-ready','true');const advanced=page.locator('details').filter({has:page.locator('summary').filter({hasText:'邀请记录与高级选项'})}),bulk=advanced.locator('.bulk-actions');await expect(bulk).toHaveCount(1);await expect(bulk).toBeHidden();await page.getByRole('dialog',{name:'添加设备',exact:true}).getByRole('button',{name:'Close / 关闭',exact:true}).click();await advanced.locator(':scope > summary').click();await expect(bulk).toBeVisible();await expect(bulk.locator('legend')).toHaveText('批量取消邀请');await expect(bulk).toContainText('不影响已加入的设备');
 for(let n=0;n<2;n++)await bulk.getByRole('checkbox',{name:'bulk-invitation-'+n,exact:true}).check();await bulk.getByRole('button',{name:'预览取消邀请',exact:true}).click();await expect(bulk.locator('.bulk-preview li')).toHaveCount(2);await expect(bulk.getByRole('button',{name:'确认取消所选邀请',exact:true})).toBeVisible();await bulk.getByLabel('输入 Mesh 名称',{exact:true}).fill(mesh.name);await bulk.getByLabel('输入所选项目数量',{exact:true}).fill('2');await capture(page,'invite-bulk-cancellation-zh');await bulk.getByRole('button',{name:'确认取消所选邀请',exact:true}).click();await expect(advanced.getByRole('status').filter({hasText:'批量操作已提交: 2'})).toBeVisible();
 for(const ticket of tickets){const saved=await(await page.request.get(`${origin}/api/v1/meshes/${mesh.id}/join-tickets/${ticket.id}`)).json();expect(saved.status).toBe('cancelled');}
 expect((await(await page.request.get(`${origin}/api/v1/meshes/${mesh.id}/peers`)).json()).items).toEqual(before);
});

test('invitation device information preserves Unicode and is validated before submit',async({page})=>{
 const [mesh]=await meshes(page),requests=[];
 page.on('request',r=>{if(r.method()==='POST'&&new URL(r.url()).pathname.endsWith('/join-tickets'))requests.push(r.postDataJSON());});
 await open(page,'join-tickets',mesh.id);
 const name=page.locator('#invite-device-name'),submit=page.getByRole('button',{name:'下一步',exact:true});
 await name.fill('bad\u0001name');
 await expect(submit).toBeDisabled();await expect(name).toHaveAttribute('aria-invalid','true');
 await expect(page.locator('#invite-name-error')).toContainText('控制字符');expect(requests).toHaveLength(0);
 await name.fill('  小明的 Alienware 笔记本  ');
 await expect(submit).toBeEnabled();await expect(page.locator('#invite-name-error')).toHaveCount(0);
 await expect(page.getByLabel('设备用途',{exact:true})).toHaveCount(0);
 await page.getByLabel('设备平台',{exact:true}).selectOption('android');
 await accessible(page);await capture(page,'invitation-device-information-zh');
 const response=page.waitForResponse(r=>r.request().method()==='POST'&&new URL(r.url()).pathname.endsWith('/join-tickets'));
 await submit.click();const result=await response;expect(result.status()).toBe(201);const ticket=await result.json();
 await expect(page.getByRole('tab',{name:'扫码加入',exact:true})).toHaveAttribute('aria-selected','true');
 expect(requests).toHaveLength(1);expect(requests[0].settings.name).toBeNull();
 const saved=await(await page.request.get(`${origin}/api/v1/meshes/${mesh.id}/join-tickets/${ticket.id}`)).json();
 expect(saved.settings).toMatchObject({display_name:'小明的 Alienware 笔记本',device_groups:[],platform_hint:'android',mode:{kind:'approval'},labels:{}});
 await page.getByRole('button',{name:'上一步',exact:true}).click();
 await expect(name).toHaveValue('小明的 Alienware 笔记本');
 await expect(page.locator('input[name=device_groups]:checked')).toHaveCount(0);
 await expect(page.getByLabel('设备平台',{exact:true})).toHaveValue('android');
 await submit.click();expect(requests).toHaveLength(1);
 await page.locator('.enrollment-restart summary').click();await page.getByRole('button',{name:'邀请下一台设备',exact:true}).click();
 await expect(name).toHaveValue('');await expect(page.locator('input[name=device_groups]:checked')).toHaveCount(0);
 await expect(page.getByLabel('设备平台',{exact:true})).toHaveValue('linux');
 const optionalResponse=page.waitForResponse(r=>r.request().method()==='POST'&&new URL(r.url()).pathname.endsWith('/join-tickets'));
 await submit.click();expect((await optionalResponse).status()).toBe(201);expect(requests[1].settings.display_name).toBe('新设备');
});

test('invitation device name rejection is explained and clears when editing',async({page})=>{
 const [mesh]=await meshes(page);let attempts=0;
 await page.route('**/api/v1/meshes/*/join-tickets',async route=>{if(route.request().method()!=='POST')return route.continue();attempts++;await route.fulfill({status:400,json:{error:{code:'invalid_network_configuration',message:'invitation.display_name',request_id:'fixture',retryable:false}}});});
 await open(page,'join-tickets',mesh.id);await page.locator('#invite-device-name').fill('小明的笔记本');
 await page.getByRole('button',{name:'下一步',exact:true}).click();
 await expect(page.getByRole('alert')).toContainText('设备名称最多 128 个字符');
 await expect(page.getByRole('alert')).not.toContainText('invitation.display_name');
 await expect(page.locator('#invite-device-name')).toHaveValue('小明的笔记本');expect(attempts).toBe(1);
 await page.locator('#invite-device-name').fill('新笔记本');await expect(page.getByRole('alert')).toHaveCount(0);
});
