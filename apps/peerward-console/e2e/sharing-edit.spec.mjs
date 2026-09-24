import { expect, test } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';
import { randomUUID } from 'node:crypto';
import { mkdir } from 'node:fs/promises';
import path from 'node:path';

const origin = process.env.PEERWARD_CONSOLE_E2E_URL;
test.skip(process.env.PEERWARD_CONSOLE_V14_E2E !== '1', 'isolated console fixture required');
test.use({ viewport: { width: 1440, height: 1000 }, serviceWorkers: 'block' });

async function fixture(page, kind = 'service') {
  const [mesh] = (await (await page.request.get(`${origin}/api/v1/meshes`)).json()).items;
  const base = `${origin}/api/v1/meshes/${mesh.id}`;
  const peers = (await (await page.request.get(`${base}/peers`)).json()).items;
  const provider = peers.find(p => p.name === 'home-nas');
  const source = peers.find(p => p.name === 'test-consumer');
  if (kind === 'internet') {
    // The shared fixture permits one exit per provider. Reuse its disposable
    // exit if an earlier workflow test already created one.
    const existing = (await (await page.request.get(`${base}/console/sharing`)).json()).items.find(r => r.kind === 'internet');
    if (existing) {
      await page.goto(`${origin}/services?mesh=${mesh.id}&resource=${existing.id}`);
      await expect(page.locator('main')).toHaveAttribute('data-console-ready', 'true');
      return { mesh, base, id: existing.id, name: existing.name, provider, source, dialog: page.getByRole('dialog', { name: '共享详情', exact: true }) };
    }
  }
  const id = randomUUID(), name = `共享编辑-${id.slice(0, 6)}`;
  const target = kind === 'service' ? { kind, protocols: ['tcp'], port: 18444, alias: null }
    : { kind: 'network', definition: { name, target: kind === 'lan'
      ? { kind: 'subnet', prefix: '192.168.231.19/32', site_id: randomUUID() }
      : { kind: 'internet', ipv4: true, ipv6: false } }, dns_name: null, dns_address: null };
  const draft = { request_id: id, name, provider: provider.id, target, source: { kind: 'none' }, protocol: 6, port: 18444, reason: 'Isolated share edit fixture' };
  const preview = await (await page.request.post(`${base}/console/sharing/preview`, { data: draft })).json();
  expect(preview.digest, JSON.stringify(preview)).toBeTruthy();
  expect((await page.request.post(`${base}/console/sharing/apply`, { headers: { 'If-Match': `"${preview.version}"` }, data: { draft, preview_digest: preview.digest } })).ok()).toBe(true);
  await page.goto(`${origin}/services?mesh=${mesh.id}&resource=${id}`);
  await expect(page.locator('main')).toHaveAttribute('data-console-ready', 'true');
  const dialog = page.getByRole('dialog', { name: '共享详情', exact: true });
  return { mesh, base, id, name, provider, source, dialog };
}

async function capture(page, name) {
  const directory = process.env.PEERWARD_EVIDENCE_SCREENSHOT_DIR;
  if (!directory) return;
  await mkdir(directory, { recursive: true });
  await page.screenshot({ path: path.join(directory, `${name}.png`), animations: 'disabled' });
}

test('sharing edit: saves parameters and manages grants entirely within the same detail', async ({ page }) => {
  test.setTimeout(90_000);
  const { mesh, base, id, name, provider, source, dialog: d } = await fixture(page);
  await d.getByRole('tab', { name: '共享信息', exact: true }).click();
  await expect(d.getByLabel('共享名称', { exact: true })).toHaveValue(name);
  await expect(d.getByLabel('提供设备', { exact: true })).toHaveAttribute('readonly', /^(true)?$/);
  await expect(d.getByLabel('DNS 名称（可选）', { exact: true })).toBeVisible();
  expect((await d.locator('#edit-share-protocol').boundingBox()).y).toBe((await d.locator('#edit-share-port').boundingBox()).y);
  await d.locator('#edit-share-name').fill('修改后的共享');
  const protocol = d.locator('#edit-share-protocol');
  const box = await protocol.boundingBox();
  await page.mouse.move(box.x + box.width - 12, box.y + box.height / 2);
  await page.mouse.down();
  expect(await protocol.evaluate(select => select.matches(':open'))).toBe(false);
  await page.mouse.up();
  expect(await protocol.evaluate(select => select.matches(':open'))).toBe(true);
  await page.keyboard.press('ArrowDown');
  await page.keyboard.press('Enter');
  await expect(protocol).toHaveValue('udp');
  await d.locator('#edit-share-port').fill('18445');
  const alias = `edited-${id.slice(0, 6)}`;
  await d.locator('#edit-share-alias').fill(alias);
  page.once('dialog', prompt => prompt.dismiss());
  await d.getByRole('tab', { name: '谁可以访问', exact: true }).click();
  await expect(d.getByRole('tab', { name: '共享信息', exact: true })).toHaveAttribute('aria-selected', 'true');
  await expect(d.locator('#edit-share-name')).toHaveValue('修改后的共享');
  await capture(page, 'sharing-edit-parameters');
  await d.getByRole('button', { name: '保存设置', exact: true }).click();
  await expect(d.getByRole('status')).toContainText('配置已经保存');
  const saved = await (await page.request.get(`${base}/services/${id}`)).json();
  expect(saved).toMatchObject({ alias, protocols: ['udp'], listen_port: 18445 });
  expect((await (await page.request.get(`${base}/console/sharing?resource=${id}`)).json()).items[0].name).toBe('修改后的共享');
  const grantsUrl = `${base}/console/services/${id}/grants`;
  expect((await (await page.request.get(grantsUrl)).json()).items).toHaveLength(0);
  await d.getByRole('tab', { name: '谁可以访问', exact: true }).click();
  await expect(d.getByText('尚无简易授权；高级规则仍可能允许访问。', { exact: true })).toBeVisible();
  const chooser = d.locator('#sharing-access-source');
  await chooser.selectOption(`peer:${source.id}`);
  await d.locator('#grant-reason').fill('允许这台设备访问');
  page.once('dialog', prompt => prompt.dismiss());
  await chooser.selectOption(`peer:${provider.id}`);
  await expect(chooser).toHaveValue(`peer:${source.id}`);
  await expect(d.locator('#grant-reason')).toHaveValue('允许这台设备访问');
  await d.locator('#sharing-access-search').fill('no-matching-device');
  await expect(chooser).toHaveValue(`peer:${source.id}`);
  await expect(d.locator('#grant-reason')).toHaveValue('允许这台设备访问');
  await d.locator('#sharing-access-search').fill('');
  await d.getByRole('button', { name: '预览授权影响', exact: true }).click();
  await d.getByRole('button', { name: '确认授权', exact: true }).click();
  await expect(d.getByRole('button', { name: '撤销此授权', exact: true })).toBeVisible();
  const simulate = async () => (await (await page.request.post(`${base}/policy/simulate`, { data: { source_peer_id: source.id, target_service_id: id, protocol: 'udp' } })).json()).allowed;
  await expect.poll(simulate).toBe(true);
  await capture(page, 'sharing-edit-access');
  for (const enabled of [false, true]) {
    await d.getByRole('button', { name: enabled ? '恢复此授权' : '撤销此授权', exact: true }).click();
    await d.locator('#grant-state-reason').fill(enabled ? '恢复访问' : '撤销访问');
    await d.getByRole('checkbox').check();
    await d.getByRole('button', { name: '确认提交', exact: true }).click();
    await expect.poll(simulate).toBe(enabled);
    await expect.poll(async () => (await (await page.request.get(grantsUrl)).json()).items[0].enabled).toBe(enabled);
  }
  await expect(page).toHaveURL(`${origin}/services?mesh=${mesh.id}&resource=${id}`);
  await d.getByRole('tab', { name: '共享信息', exact: true }).click();
  await expect(d.locator('#edit-share-name')).toHaveValue('修改后的共享');
  await expect(d.locator('#edit-share-alias')).toHaveValue(alias);
  await expect(d.locator('#edit-share-protocol')).toHaveValue('udp');
  const audit = await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa']).analyze();
  expect(audit.violations.filter(v => ['serious', 'critical'].includes(v.impact))).toEqual([]);
  await page.setViewportSize({ width: 390, height: 844 });
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  await capture(page, 'sharing-edit-mobile-parameters');
  await d.getByRole('tab', { name: '谁可以访问', exact: true }).click();
  await expect(d.getByRole('button', { name: '撤销此授权', exact: true })).toBeVisible();
  await capture(page, 'sharing-edit-mobile-access');
  const mobileAudit = await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa']).analyze();
  expect(mobileAudit.violations.filter(v => ['serious', 'critical'].includes(v.impact))).toEqual([]);
});

test('sharing edit: LAN and exit access grants are available in sharing details', async ({ page }) => {
  test.setTimeout(90_000);
  for (const kind of ['lan', 'internet']) {
    const { base, id, source, dialog: d } = await fixture(page, kind);
    await d.getByRole('tab', { name: '谁可以访问', exact: true }).click();
    await d.locator('#sharing-access-source').selectOption(`peer:${source.id}`);
    await d.locator('#grant-protocol').selectOption('17');
    await d.locator('#grant-port').fill('5353');
    await d.locator('#grant-reason').fill('确认局域网或出口授权');
    await d.getByRole('button', { name: '预览授权影响', exact: true }).click();
    await d.getByRole('button', { name: '确认授权', exact: true }).click();
    await expect(d.getByRole('button', { name: '撤销此授权', exact: true }).last()).toBeVisible();
    const grants = (await (await page.request.get(`${base}/console/network-resources/${id}/grants`)).json()).items;
    expect(grants.some(grant => grant.enabled && grant.protocol === 17)).toBe(true);
    await expect(d.getByRole('tab', { name: '网关路径', exact: true })).toBeVisible();
  }
});
