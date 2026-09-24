import { expect, test } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';
import { mkdir, readFile } from 'node:fs/promises';
import path from 'node:path';
import { randomUUID } from 'node:crypto';
import { signedClaim } from './join-claim.mjs';

const origin = process.env.PEERWARD_CONSOLE_E2E_URL;
test.skip(process.env.PEERWARD_CONSOLE_V14_E2E !== '1', 'isolated fixture required');
test.use({ viewport: { width: 1440, height: 1000 }, serviceWorkers: 'block' });

async function capture(page, name) {
  const directory = process.env.PEERWARD_EVIDENCE_SCREENSHOT_DIR;
  if (!directory) return;
  await mkdir(directory, { recursive: true });
  await page.screenshot({ path: path.join(directory, `${name}.png`), animations: 'disabled' });
}

for (const width of [1440, 390]) {
  test(`enrollment prototype: four real steps, connection tabs and keyboard at ${width}px`, async ({ page, context }) => {
    await page.setViewportSize({ width, height: 1000 });
    await context.grantPermissions(['clipboard-read', 'clipboard-write']);
    const [mesh] = (await (await page.request.get(`${origin}/api/v1/meshes`)).json()).items;
    const base = `${origin}/api/v1/meshes/${mesh.id}`;
    const groups = [];
    for (const prefix of ['家庭设备','工作设备']) {
      const response = await page.request.post(`${base}/collections`, {data:{id:randomUUID(),definition:{name:prefix+'-'+randomUUID().slice(0,8),kind:'devices',members:[],labels:{}}}});
      expect(response.status(), await response.text()).toBe(201); groups.push(await response.json());
    }
    if (width === 1440) {
      const provider = (await (await page.request.get(`${base}/peers`)).json()).items.find(peer=>peer.name==='home-nas');
      const draft = {request_id:randomUUID(),name:'入网组授权 NAS',provider:provider.id,
        target:{kind:'service',protocols:['tcp'],port:18546,alias:null},source:{kind:'collection',id:groups[0].id},protocol:6,port:18546,reason:'Isolated enrollment group fixture'};
      const previewResponse=await page.request.post(`${base}/console/sharing/preview`,{data:draft});
      expect(previewResponse.ok(),await previewResponse.text()).toBe(true);
      const preview=await previewResponse.json();
      expect((await page.request.post(`${base}/console/sharing/apply`,{headers:{'If-Match':`"${preview.version}"`},data:{draft,preview_digest:preview.digest}})).ok()).toBe(true);
    }
    await page.goto(`${origin}/peers?mesh=${mesh.id}`);
    await expect(page.locator('main')).toHaveAttribute('data-console-ready', 'true');
    await page.getByRole('link', { name: '＋ 添加设备', exact: true }).click();
    const dialog = page.getByRole('dialog', { name: '添加设备', exact: true });
    await expect(dialog.locator('.enrollment-progress li')).toHaveText(['1设备信息','2接入方式','3等待上线','4完成']);
    await expect(dialog.locator('#join-review')).toHaveCount(0);
    // Closing a server-rendered modal must restore the header after hydration.
    await dialog.getByRole('button',{name:'取消',exact:true}).click();
    await page.locator('.account-menu > summary').click();
    await expect(page.locator('#pw-language')).toBeVisible();
    await page.locator('.account-menu > summary').click();
    await page.getByRole('button',{name:'＋ 添加设备',exact:true}).click();
    await expect(dialog).toBeVisible();
    await capture(page, `enrollment-info-${width}`);
    const displayName = `小明的笔记本-${randomUUID().slice(0,8)}`;
    await dialog.getByLabel('设备名称',{exact:true}).fill(displayName);
    await expect(dialog.getByText('设备用途',{exact:true})).toHaveCount(0);
    for (const group of groups) {
      const choice = dialog.getByRole('checkbox',{name:group.definition.name,exact:true});
      await expect(choice).not.toBeChecked(); await choice.check();
    }
    await expect(dialog.locator('.enrollment-group-access')).toContainText('该组暂无已启用的共享授权');
    if(width===1440) await expect(dialog.locator('.enrollment-group-access')).toContainText('入网组授权 NAS · TCP 18546');
    await capture(page, `enrollment-groups-${width}`);
    const formAudit = await new AxeBuilder({page}).withTags(['wcag2a','wcag2aa']).analyze();
    expect(formAudit.violations.filter(v=>['serious','critical'].includes(v.impact))).toEqual([]);
    let ticketWrites = 0;
    page.on('request', request => { if (request.method() === 'POST' && request.url().endsWith('/join-tickets')) ticketWrites++; });
    const response = page.waitForResponse(r => r.request().method() === 'POST' && r.url().endsWith('/join-tickets'));
    await dialog.getByRole('button', { name: '下一步', exact: true }).click();
    const ticket = await (await response).json();
    await expect(dialog.locator('[aria-current=step]')).toHaveText('2接入方式');
    await expect(dialog.locator('#join-review')).toBeHidden();
    const box = await dialog.boundingBox();
    expect(box.width).toBe(width === 1440 ? 680 : 370);
    expect(Math.abs(box.x + box.width / 2 - width / 2)).toBeLessThan(2);
    const invitation = await dialog.locator('#enrollment-link').inputValue();
    await dialog.getByRole('button', { name: '复制命令', exact: true }).click();
    expect(await page.evaluate(() => navigator.clipboard.readText())).toBe('peerward join accept --bundle-file - --output-dir ./peerward-device');
    const downloadPromise = page.waitForEvent('download');
    await dialog.getByRole('link', { name: '下载加入文件', exact: true }).click();
    const download = await downloadPromise;
    expect(await readFile(await download.path(), 'utf8')).toBe(invitation);
    const copyButton = dialog.getByRole('button', {name:'复制命令', exact:false});
    expect((await copyButton.boundingBox()).width).toBeGreaterThan(70);
    await capture(page, `enrollment-command-${width}`);
    await dialog.getByRole('tab', { name: '复制命令', exact: true }).focus();
    await page.keyboard.press('ArrowRight');
    await expect(dialog.getByRole('tab', { name: '扫码加入', exact: true })).toHaveAttribute('aria-selected', 'true');
    await expect(dialog.locator('.join-qr svg')).toBeVisible();
    await capture(page, `enrollment-qr-${width}`);
    await page.keyboard.press('ArrowRight');
    await expect(dialog.locator('#enrollment-link')).toHaveValue(invitation);
    await dialog.getByRole('button', { name: '复制邀请链接', exact: true }).click();
    expect(await page.evaluate(() => navigator.clipboard.readText())).toBe(invitation);
    await dialog.getByRole('button', { name: '上一步', exact: true }).click();
    await expect(dialog.locator('#invite-device-name')).toBeDisabled();
    for (const group of groups) {
      const choice = dialog.getByRole('checkbox',{name:group.definition.name,exact:true});
      await expect(choice).toBeChecked(); await expect(choice).toBeDisabled();
      expect((await (await page.request.get(`${base}/collections/${group.id}`)).json()).definition.members).toEqual([]);
    }
    await dialog.getByRole('button', { name: '下一步', exact: true }).click();
    expect(ticketWrites).toBe(1);
    await dialog.getByRole('button', { name: '我已在设备上操作', exact: true }).click();
    await expect(dialog.locator('[aria-current=step]')).toHaveText('3等待上线');
    await expect(dialog.getByText('正在等待新设备', { exact: true })).toBeVisible();
    await capture(page, `enrollment-waiting-${width}`);
    const claim = signedClaim(ticket.token);
    expect((await page.request.post(`${origin}/api/v1/join/${ticket.token}/claim`, {data:claim.body})).status()).toBe(202);
    await dialog.getByRole('button', { name: '检查连接', exact: true }).click();
    await dialog.locator('#join-confirm-fingerprint').fill(claim.fingerprint);
    await dialog.getByRole('button', { name: '身份一致，批准设备', exact: true }).click();
    await expect(dialog.locator('[aria-current=step]')).toHaveText('4完成');
    await expect(dialog.getByText('设备已加入网络', { exact: true })).toBeVisible();
    await capture(page, `enrollment-complete-${width}`);
    const freshTicket = await (await page.request.get(`${origin}/api/v1/meshes/${mesh.id}/join-tickets/${ticket.id}`)).json();
    const peer = await (await page.request.get(`${origin}/api/v1/meshes/${mesh.id}/peers/${freshTicket.claimed_peer_id}`)).json();
    expect(peer.display_name).toBe(displayName);expect(peer).not.toHaveProperty('purpose');
    for (const group of groups) {
      expect((await (await page.request.get(`${base}/collections/${group.id}`)).json()).definition.members).toEqual([peer.id]);
    }
    expect(peer.labels).not.toHaveProperty('purpose');
    expect(peer.labels).not.toHaveProperty('platform_hint');
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
    const audit = await new AxeBuilder({ page }).withTags(['wcag2a','wcag2aa']).analyze();
    expect(audit.violations.filter(v => ['serious','critical'].includes(v.impact))).toEqual([]);
    if (width === 1440) {
      await dialog.getByRole('link',{name:'查看这台设备',exact:true}).click();
      const details = page.getByRole('dialog',{name:'设备详情',exact:true});
      await details.getByRole('button',{name:'修改基本信息',exact:true}).click();
      await expect(details.getByLabel('设备用途',{exact:true})).toHaveCount(0);
      await details.getByLabel('位置说明',{exact:true}).fill('书房');
      const patched = page.waitForResponse(r=>r.request().method()==='PATCH' && r.url().endsWith('/peers/'+peer.id));
      await details.getByRole('button',{name:'保存更改',exact:true}).click();
      expect((await patched).status()).toBe(200);
      await page.reload();
      await details.getByRole('button',{name:'修改基本信息',exact:true}).click();
      await expect(details.getByLabel('位置说明',{exact:true})).toHaveValue('书房');
      const saved = await (await page.request.get(`${origin}/api/v1/meshes/${mesh.id}/peers/${peer.id}`)).json();
      expect(saved.labels).toEqual(peer.labels);expect(saved.name).toBe(peer.name);
    }
  });
}

test('device groups: create, retry failed edit, reload members and select group for access', async ({ page }) => {
  const [mesh] = (await (await page.request.get(`${origin}/api/v1/meshes`)).json()).items;
  const base = `${origin}/api/v1/meshes/${mesh.id}`;
  const name = `家庭设备-${randomUUID().slice(0,8)}`;
  const peers = (await (await page.request.get(base + '/peers')).json()).items;
  const member = peers.find(peer => peer.administrative_state === 'enabled');
  expect(member).toBeTruthy();
  const memberName = member.display_name || member.name;
  await page.goto(`${origin}/peers?mesh=${mesh.id}`);
  await expect(page.locator('main')).toHaveAttribute('data-console-ready','true');
  await page.getByRole('button', {name:'设备组',exact:true}).click();
  const dialog = page.getByRole('dialog',{name:'设备组',exact:true});
  await dialog.getByRole('button',{name:'新建设备组',exact:true}).click();
  await dialog.getByLabel('设备组名称',{exact:true}).fill(name);
  await dialog.getByRole('checkbox',{name:memberName,exact:true}).check();
  let warned = false;
  page.once('dialog', async prompt => { warned = true; await prompt.dismiss(); });
  await dialog.getByRole('button',{name:'新建设备组',exact:true}).click();
  expect(warned).toBe(true);
  await expect(dialog.getByLabel('设备组名称',{exact:true})).toHaveValue(name);
  const created = page.waitForResponse(r => r.request().method()==='POST' && r.url()===`${base}/collections`);
  await dialog.getByRole('button',{name:'保存设备组',exact:true}).click();
  const group = await (await created).json();
  await expect(dialog.getByRole('button',{name,exact:true})).toBeEnabled();
  await dialog.locator('.drawer-body').evaluate(node => { node.scrollTop = 0; });
  await capture(page, 'device-group-created');
  await dialog.getByLabel('设备组名称',{exact:true}).fill(name+'更新');
  await page.route(`**/collections/${group.id}`, route => route.request().method()==='PUT'
    ? route.fulfill({status:503,json:{error:{code:'unavailable',message:'try again',field_errors:{}}}})
    : route.continue());
  await dialog.getByRole('button',{name:'保存设备组',exact:true}).click();
  await expect(dialog.getByRole('alert')).toBeVisible();
  await expect(dialog.getByLabel('设备组名称',{exact:true})).toHaveValue(name+'更新');
  await page.unroute(`**/collections/${group.id}`);
  await dialog.getByRole('button',{name:'保存设备组',exact:true}).click();
  await expect(dialog.getByRole('button',{name:name+'更新',exact:true})).toBeEnabled();
  await page.reload();
  await page.getByRole('button',{name:'设备组',exact:true}).click();
  await dialog.getByRole('button',{name:name+'更新',exact:true}).click();
  await expect(dialog.getByRole('checkbox',{name:memberName,exact:true})).toBeChecked();
  await page.setViewportSize({width:390,height:844});
  await capture(page,'device-group-mobile');
  expect(await page.evaluate(() => document.documentElement.scrollWidth<=innerWidth)).toBe(true);
  const audit = await new AxeBuilder({page}).withTags(['wcag2a','wcag2aa']).analyze();
  expect(audit.violations.filter(v=>['serious','critical'].includes(v.impact))).toEqual([]);
  await page.goto(`${origin}/policy?mesh=${mesh.id}&source=group:${group.id}`);
  await expect(page.locator('#access-source')).toHaveValue(`group:${group.id}`);
  const fresh = await (await page.request.get(`${base}/collections/${group.id}`)).json();
  expect(fresh.definition.members).toEqual(group.definition.members);
  expect(fresh.definition.members).toEqual([member.id]);
  expect((await page.request.delete(`${base}/collections/${group.id}`,{headers:{'If-Match':`"${fresh.version}"`}})).ok()).toBe(true);
});
