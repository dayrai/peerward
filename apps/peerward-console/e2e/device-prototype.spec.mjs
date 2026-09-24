import { expect, test } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';
import { mkdir } from 'node:fs/promises';
import path from 'node:path';
import { randomUUID } from 'node:crypto';

const origin = process.env.PEERWARD_CONSOLE_E2E_URL;
test.skip(process.env.PEERWARD_CONSOLE_V14_E2E !== '1', 'isolated console fixture required');
test.use({ viewport: { width: 1920, height: 1130 }, serviceWorkers: 'block' });

async function capture(page, name) {
  const directory = process.env.PEERWARD_EVIDENCE_SCREENSHOT_DIR;
  if (directory) {
    await mkdir(directory, { recursive: true });
    await page.screenshot({ path: path.join(directory, `${name}.png`), animations: 'disabled' });
  }
}

test('device prototype layout uses real scoped facts, search, menu and completion routes', async ({ page }) => {
  const errors = [];
  page.on('pageerror', error => errors.push(error.message));
  const mesh = (await (await page.request.get(`${origin}/api/v1/meshes`)).json()).items[0];
  const base = `${origin}/api/v1/meshes/${mesh.id}`;
  let initial = await (await page.request.get(`${base}/console/devices`)).json();
  const peer = initial.items.find(item => item.name === 'home-nas');
  expect(peer).toBeTruthy();
  const previousCount = initial.summaries[peer.id].provided_services;
  const draft = { request_id: randomUUID(), name: '设备列表服务计数', provider: peer.id,
    target: { kind: 'service', protocols: ['tcp'], port: 19443, alias: null },
    source: { kind: 'none' }, protocol: 6, port: 19443, reason: 'Device inventory verification' };
  const preview = await (await page.request.post(`${base}/console/sharing/preview`, { data: draft })).json();
  expect(preview.digest).toBeTruthy();
  expect((await page.request.post(`${base}/console/sharing/apply`, {
    headers: { 'If-Match': `"${preview.version}"` }, data: { draft, preview_digest: preview.digest },
  })).ok()).toBe(true);
  initial = await (await page.request.get(`${base}/console/devices`)).json();
  expect(initial.summaries[peer.id].provided_services).toBe(previousCount + 1);
  // No invented "last active" timestamp from creation or configuration edits.
  expect(initial.summaries[peer.id].last_connected_at).toBeNull();
  expect(initial.summaries[peer.id].runtime_observed_at).toBeNull();
  expect(initial.summaries[peer.id].diagnostics).toEqual([{
    code: 'device_offline', observed_at: expect.any(Number), retry_hint: 'check_network',
  }]);
  await page.goto(`${origin}/peers?mesh=${mesh.id}`);
  await expect(page.locator('main')).toHaveAttribute('data-console-ready', 'true');
  const table = page.getByRole('table', { name: '设备', exact: true });
  await expect(table.getByRole('columnheader')).toHaveText(['设备', '状态', '地址', '最近连接', '访问范围', '操作']);
  await expect(page.locator('.device-table-head h2')).toHaveText(`全部设备${initial.total}`);
  await expect(page.locator('.device-join-guide')).toContainText('添加设备只需要一次接入');
  await expect(page.locator('.guide-flow li')).toHaveCount(3);
  await expect(page.locator('.device-more-menu')).toBeHidden();
  await expect(page.locator('#advanced-device-management')).toHaveCount(0);
  const row = page.locator(`[data-peer="${peer.id}"]`);
  await expect(row).toContainText('暂无记录');
  await expect(row.getByRole('link')).toHaveAttribute('href', `/policy?mesh=${mesh.id}&source=peer%3A${peer.id}`);
  await capture(page, 'devices-prototype-desktop');
  for (const query of [peer.mesh_addresses[0], peer.labels.platform]) {
    await page.locator('#device-search').fill(query);
    await expect(row).toBeVisible();
    await expect(page.locator('.device-table-head h2')).toContainText('筛选结果');
    const result = await (await page.request.get(`${base}/console/devices?q=${encodeURIComponent(query)}`)).json();
    expect(result.items.some(item => item.id === peer.id)).toBe(true);
    await page.locator('.device-more > summary').click();
    const exportLink = page.getByRole('link', { name: '导出当前结果' });
    const csv = await (await page.request.get(new URL(await exportLink.getAttribute('href'), origin).href)).text();
    expect(csv).toContain(peer.id);
    await page.keyboard.press('Escape');
    await expect(page.locator('.device-more-menu')).toBeHidden();
  }
  await page.locator('#device-search').fill('no-such-prototype-device');
  await expect(page.getByRole('status')).toContainText('没有匹配的设备');
  await page.locator('#device-search').fill('');
  await row.getByRole('button', { name: `查看${peer.display_name || peer.name}详情` }).click();
  await expect(page).toHaveURL(new RegExp(`resource=${peer.id}`));
  await expect(page.getByRole('dialog')).toBeVisible();
  await page.keyboard.press('Escape');
  await expect(page.getByRole('dialog')).toHaveCount(0);
  await row.focus();
  await page.keyboard.press('Enter');
  await expect(page.getByRole('dialog')).toBeVisible();
  await page.keyboard.press('Escape');
  await expect(row).toBeFocused();
  await row.getByRole('link').click();
  await expect(page.locator('#access-source')).toHaveValue(`peer:${peer.id}`);
  await page.goto(`${origin}/peers?mesh=${mesh.id}`);
  await page.getByRole('link', { name: '＋ 添加设备', exact: true }).click();
  await expect(page.locator('#invite-device-name')).toBeVisible();
  await page.goto(`${origin}/peers?mesh=${mesh.id}`);
  await page.setViewportSize({ width: 390, height: 844 });
  await expect(row).toBeVisible();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  await capture(page, 'devices-prototype-mobile');
  const result = await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa']).analyze();
  expect(result.violations.filter(item => ['serious', 'critical'].includes(item.impact))).toEqual([]);
  expect(errors).toEqual([]);
});

test('device detail content follows prototype and checks real connection records', async ({page, context}) => {
  const mesh = (await (await page.request.get(`${origin}/api/v1/meshes`)).json()).items[0];
  const base = `${origin}/api/v1/meshes/${mesh.id}`;
  const peer = (await (await page.request.get(`${base}/peers`)).json()).items.find(item => item.name === 'home-nas');
  await page.goto(`${origin}/peers?mesh=${mesh.id}&resource=${peer.id}`);
  await expect(page.locator('main')).toHaveAttribute('data-console-ready','true');
  const drawer = page.getByRole('dialog',{name:'设备详情',exact:true});
  await expect(drawer.getByRole('heading',{name:peer.display_name || peer.name,exact:true})).toBeVisible();
  await expect(drawer.locator('.device-hero-copy')).toContainText('最近连接');
  await expect(drawer.locator('.device-health')).toContainText('设备当前离线');
  await expect(drawer.locator('.device-runtime-diagnostics')).toContainText('设备离线');
  await expect(drawer.locator('.device-runtime-diagnostics')).toContainText('检查设备网络和中继地址');
  await expect(drawer.locator('.device-runtime-diagnostics')).toContainText('证据时间');
  await expect(drawer.locator('.device-primary-facts')).toContainText('虚拟地址');
  await expect(drawer.locator('.device-primary-facts')).toContainText('位置说明');
  await expect(drawer.locator('.device-primary-facts')).toContainText('Linux');
  const copy = drawer.locator('.device-primary-facts .copy-value');
  await expect(copy).toHaveCount(1);
  await expect(copy).toHaveAttribute('title','复制');
  await expect(copy.locator('svg').first()).toBeVisible();
  expect((await copy.boundingBox()).width).toBe(24);
  expect((await copy.locator('svg').first().boundingBox()).width).toBe(14);
  await context.grantPermissions(['clipboard-read','clipboard-write']);
  await copy.click();
  await expect(copy).toHaveAttribute('data-copy-state','done');
  expect(await page.evaluate(()=>navigator.clipboard.readText())).toBe(peer.mesh_addresses[0]);
  await page.evaluate(()=>Object.defineProperty(navigator,'clipboard',{configurable:true,value:{writeText:async()=>{throw new Error('permission denied');}}}));
  await copy.click();
  await expect(copy).toHaveAttribute('data-copy-state','error');
  await expect(copy.locator('.copy-feedback')).toContainText('复制失败');
  await page.evaluate(()=>delete navigator.clipboard);
  await copy.click();
  await expect(copy).toHaveAttribute('data-copy-state','done');
  await expect(drawer.locator('.device-detail-technical')).not.toHaveAttribute('open');
  const box=await drawer.boundingBox();expect(box.width).toBe(520);
  const hero=await drawer.locator('.device-detail-hero').boundingBox();
  const health=await drawer.locator('.device-health').boundingBox();
  const tabs=await drawer.getByRole('tablist').boundingBox();
  expect(hero.y).toBeLessThan(health.y);expect(health.y).toBeLessThan(tabs.y);
  await capture(page,'device-drawer-desktop');
  const connection=page.waitForResponse(response=>response.url()===`${base}/peers/${peer.id}` && response.request().method()==='GET');
  await drawer.getByRole('button',{name:'检查连接',exact:true}).click();
  expect((await connection).ok()).toBe(true);
  await expect(drawer.locator('.device-connection-result')).toContainText('没有有效连接');
  await expect(drawer.locator('.device-connection-result')).not.toContainText('18 ms');
  await page.route(`${base}/peers/${peer.id}`,route=>route.fulfill({status:503,json:{error:{code:'unavailable',message:'temporarily unavailable'}}}));
  await drawer.getByRole('button',{name:'检查连接',exact:true}).click();
  await expect(drawer.locator('.device-connection-result')).toHaveAttribute('role','alert');
  await expect(drawer.locator('.device-connection-result')).not.toHaveText('');
  await page.unroute(`${base}/peers/${peer.id}`);
  await drawer.getByRole('tab',{name:'共享与访问',exact:true}).click();
  await expect(drawer.getByRole('heading',{name:'可以访问',exact:true})).toBeVisible();
  await expect(drawer.getByRole('heading',{name:'这台设备对外共享',exact:true})).toBeVisible();
  await expect(drawer.getByRole('link',{name:'调整访问',exact:true})).toHaveAttribute('href',`/policy?mesh=${mesh.id}&source=peer%3A${peer.id}`);
  await expect(drawer.getByText('默认拒绝仍然生效。',{exact:true})).toBeVisible();
  await drawer.getByRole('tab',{name:'维护',exact:true}).click();
  await expect(drawer.getByText('查看设备操作记录',{exact:true})).toBeVisible();
  await drawer.getByRole('tab',{name:'状态',exact:true}).click();
  await drawer.locator('.device-detail-technical > summary').click();
  await expect(drawer.locator('.device-detail-technical')).toContainText(peer.id);
  await expect(drawer.locator('.device-detail-technical')).toContainText(peer.mesh_addresses[0]);
  await page.setViewportSize({width:390,height:844});
  expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth)).toBe(true);
  const a11y=await new AxeBuilder({page}).withTags(['wcag2a','wcag2aa']).analyze();
  expect(a11y.violations.filter(issue=>['serious','critical'].includes(issue.impact))).toEqual([]);
  await capture(page,'device-drawer-mobile');
});
