import {expect,test} from '@playwright/test';
const origin=process.env.PEERWARD_CONSOLE_E2E_URL;
test.skip(process.env.PEERWARD_CONSOLE_LOCK_E2E!=='1','isolated OIDC fixture required');
test('lock revokes the server session and fresh OIDC authentication restores the network and page',async({page,playwright})=>{
 await page.goto(`${origin}/api/v1/auth/login`);await expect(page).toHaveURL(origin+'/');
 const session=await page.evaluate(async()=>await(await fetch('/auth/session')).json());expect(session.role).toBe('admin');expect(session.csrf_token).toBeTruthy();
 expect(await page.evaluate(async()=>(await fetch('/auth/logout',{method:'POST',headers:{'content-type':'application/json'},body:'{}'})).status)).toBe(403);
 const {items}=await page.evaluate(async()=>await(await fetch('/api/v1/meshes')).json());const destination=`/services?mesh=${items[0].id}`;
 await page.goto(origin+destination);await expect(page.locator('main')).toHaveAttribute('data-console-ready','true');
 const stale=await playwright.request.newContext({extraHTTPHeaders:{cookie:(await page.context().cookies()).map(c=>`${c.name}=${c.value}`).join('; ')}} );
 try {
  await page.locator('.account-menu summary').click();await page.getByRole('button',{name:'锁定控制台',exact:true}).click();
  await expect(page.getByRole('heading',{name:'控制台已锁定'})).toBeVisible();expect((await stale.get(origin+'/auth/session')).status()).toBe(401);
  expect((await page.request.get(origin+'/auth/session')).status()).toBe(401);
  await page.getByRole('link',{name:'重新验证身份 / Sign in again'}).click();await expect(page).toHaveURL(origin+destination);
  await expect(page.locator('main')).toHaveAttribute('data-console-ready','true');expect((await page.evaluate(async()=>await(await fetch('/auth/session')).json())).authenticated).toBe(true);
  const provider=await(await page.request.get(process.env.PEERWARD_OIDC_PROVIDER_URL+'debug')).json();expect(provider.reauthentications).toBe(1);expect(provider.pkce_validations).toBe(2);expect(provider.unused_codes).toBe(0);
 } finally {await stale.dispose();}
});

test('real viewer login hides guided mutations and Control rejects approval and sharing writes', async ({ page, browser }) => {
 const provider = process.env.PEERWARD_OIDC_PROVIDER_URL;
 // Chromium sends Secure loopback cookies; use the browser's real session for API checks.
 const api = async (tab, path, method = 'GET', body, headers = {}) => tab.evaluate(async ({path, method, body, headers}) => {
  const response = await fetch(path, {method, headers: {'Content-Type':'application/json', ...headers}, body:body === undefined ? undefined : JSON.stringify(body)});
  return {status:response.status, body:await response.json()};
 }, {path, method, body, headers});
 await page.goto(`${origin}/api/v1/auth/login`);
 await expect(page).toHaveURL(origin+'/');
 const admin = (await api(page, '/auth/session')).body;
 expect(admin.role).toBe('admin');
 const {items} = (await api(page, '/api/v1/meshes')).body;
 const mesh = items.find(item => item.name !== 'second-console-network').id;
 const base = `/api/v1/meshes/${mesh}`;
 const invite = await api(page, base + '/join-tickets', 'POST', {expires_in_seconds:300,settings:{mode:{kind:'approval'}}}, {'X-CSRF-Token':admin.csrf_token});
 expect(invite.status).toBe(201);
 const ticket = invite.body;
 const { signedClaim } = await import('./join-claim.mjs');
 const claim = signedClaim(ticket.token);
 const pending = await page.request.post(`${origin}/api/v1/join/${ticket.token}/claim`,{data:claim.body});
 expect(pending.status()).toBe(202);
 const application = (await pending.json()).application;
 expect((await page.request.post(provider + 'test-role', {data:'viewer'})).ok()).toBe(true);
 const context = await browser.newContext();
 try {
  const viewer = await context.newPage();
  await viewer.goto(`${origin}/api/v1/auth/login`);
  await expect(viewer).toHaveURL(origin+'/');
  const session = (await api(viewer, '/auth/session')).body;
  expect(session.role).toBe('viewer');
  expect(session.capabilities).not.toContain('resource_write');
  await viewer.goto(`${origin}/join-tickets?mesh=${mesh}`);
  await expect(viewer.locator('main')).toHaveAttribute('data-console-ready','true');
  await expect(viewer.getByRole('button',{name:'生成一次性邀请',exact:true})).toHaveCount(0);
  await expect(viewer.locator('#join-confirm-fingerprint')).toHaveCount(0);
  await expect(viewer.getByRole('button',{name:'身份一致，批准设备',exact:true})).toHaveCount(0);
  const headers = {'X-CSRF-Token':session.csrf_token,'If-Match':`"${application.version}"`};
  expect((await api(viewer, `${base}/join-applications/${application.id}/approve`, 'POST', {identity_fingerprint:claim.fingerprint}, headers)).status).toBe(403);
  expect((await api(viewer, base+'/join-tickets', 'POST', {expires_in_seconds:300}, headers)).status).toBe(403);
  const peers = (await api(page, base+'/peers')).body.items;
  const draft = {request_id:crypto.randomUUID(),name:'denied-share',provider:peers[0].id,target:{kind:'service',protocols:['tcp'],port:443,alias:null},source:{kind:'none'},protocol:6,port:443,reason:''};
  expect((await api(viewer, base+'/console/sharing/preview', 'POST', draft, headers)).status).toBe(403);
  expect((await api(viewer, base+'/console/sharing/apply', 'POST', {draft,preview_digest:'forged'}, headers)).status).toBe(403);
  for (const route of ['peers','services','policy']) {
   await viewer.goto(`${origin}/${route}?mesh=${mesh}`);
   await expect(viewer.locator('main')).toHaveAttribute('data-console-ready','true');
   await expect(viewer.getByText('只读模式',{exact:true})).toBeVisible();
   await expect(viewer.getByRole('button',{name:'＋ 添加共享',exact:true})).toHaveCount(0);
   await expect(viewer.getByRole('link',{name:'添加设备',exact:true})).toHaveCount(0);
  }
  await viewer.goto(`${origin}/peers?mesh=${mesh}`);
  await viewer.getByRole('button',{name:'设备组',exact:true}).click();
  const groups = viewer.getByRole('dialog',{name:'设备组',exact:true});
  await expect(groups.getByRole('button',{name:'新建设备组',exact:true})).toHaveCount(0);
  await expect(groups.getByRole('button',{name:'保存设备组',exact:true})).toBeDisabled();
  await expect(groups.getByLabel('设备组名称',{exact:true})).toBeDisabled();
  expect((await api(viewer,base+'/collections','POST',{id:crypto.randomUUID(),definition:{name:'denied-group',kind:'devices',members:[],labels:{}}},headers)).status).toBe(403);
  await viewer.goto(`${origin}/peers?mesh=${mesh}&resource=${peers[0].id}`);
  const device = viewer.getByRole('dialog',{name:'设备详情',exact:true});
  await expect(device.locator('.device-primary-facts')).toBeVisible();
  await expect(device.getByRole('button',{name:'修改基本信息',exact:true})).toHaveCount(0);
  await device.getByRole('tab',{name:'共享与访问',exact:true}).click();
  await expect(device.getByRole('link',{name:'查看访问',exact:true})).toHaveAttribute('href',`/policy?mesh=${mesh}&source=peer%3A${peers[0].id}`);
  await expect(device.getByRole('link',{name:'调整访问',exact:true})).toHaveCount(0);
  await device.getByRole('tab',{name:'维护',exact:true}).click();
  await expect(device.getByRole('button',{name:'停用这台设备',exact:true})).toHaveCount(0);
  expect((await api(viewer, `${base}/peers/${peers[0].id}`, 'PATCH', {display_name:'forbidden'}, {'X-CSRF-Token':session.csrf_token,'If-Match':`"${peers[0].version}"`})).status).toBe(403);
  const readableDraft = {...draft, request_id:crypto.randomUUID(), name:'只读验证共享'};
  const adminHeaders = {'X-CSRF-Token':admin.csrf_token};
  const preview = await api(page, base + '/console/sharing/preview', 'POST', readableDraft, adminHeaders);
  expect(preview.status).toBe(200);
  const created = await api(page, base + '/console/sharing/apply', 'POST', {draft:readableDraft, preview_digest:preview.body.digest}, {...adminHeaders,'If-Match':`"${preview.body.version}"`});
  expect(created.status).toBeLessThan(300);
  const shares = (await api(page, base + '/console/sharing')).body.items;
  expect(shares.length).toBeGreaterThan(0);
  await viewer.goto(`${origin}/services?mesh=${mesh}&resource=${shares[0].id}`);
  const sharing = viewer.getByRole('dialog', {name:'共享详情',exact:true});
  await expect(sharing.getByRole('tab', {name:'共享信息',exact:true})).toHaveCount(0);
  await sharing.getByRole('tab', {name:'谁可以访问',exact:true}).click();
  await expect(sharing.getByRole('heading', {name:'此资源的授权',exact:true})).toBeVisible();
  await expect(sharing.locator('#sharing-access-source')).toHaveCount(0);
  await expect(sharing.getByRole('button', {name:/撤销此授权|恢复此授权|确认授权/})).toHaveCount(0);
  expect((await api(page, base+'/join-applications/'+application.id)).body.status).toBe('pending');
 } finally {
  await context.close();
  await page.request.post(provider + 'test-role', {data:'admin'});
 }
});
