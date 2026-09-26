import { expect, test } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';
import { mkdir } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { randomUUID } from 'node:crypto';

const origin = process.env.PEERWARD_CONSOLE_E2E_URL;
test.skip(process.env.PEERWARD_CONSOLE_V14_E2E !== '1', 'isolated console fixture required');
test.use({ viewport: { width: 1920, height: 1130 }, serviceWorkers: 'block' });
async function capture(page, name) {
  const directory = process.env.PEERWARD_EVIDENCE_SCREENSHOT_DIR;
  if (!directory) return;
  await mkdir(directory, { recursive: true });
  await page.screenshot({ path: path.join(directory, `${name}.png`), animations: 'disabled', fullPage: true });
}
async function fixture(page) {
  const mesh = (await (await page.request.get(`${origin}/api/v1/meshes`)).json()).items[0];
  const base = `${origin}/api/v1/meshes/${mesh.id}`;
  const peers = (await (await page.request.get(`${base}/peers`)).json()).items;
  return { mesh, base, provider: peers.find(p => p.name === 'home-nas'), source: peers.find(p => p.name === 'test-consumer') };
}
async function createShare(page, base, provider, source, port = 20988) {
  const draft = { request_id: randomUUID(), name: '访问原型服务-' + randomUUID().slice(0, 6), provider: provider.id,
    target: { kind: 'service', protocols: ['tcp'], port, alias: null },
    source: source ? { kind: 'peer', id: source.id } : { kind: 'none' }, protocol: 6, port, reason: 'Access prototype regression' };
  const preview = await (await page.request.post(base + '/console/sharing/preview', { data: draft })).json();
  expect(preview.digest).toBeTruthy();
  expect((await page.request.post(base + '/console/sharing/apply', {
    headers: { 'If-Match': `"${preview.version}"` }, data: { draft, preview_digest: preview.digest },
  })).ok()).toBe(true);
  return (await (await page.request.get(base + '/console/sharing?q=' + encodeURIComponent(draft.name))).json()).items[0];
}

test('access prototype keeps the matrix, details, simulation and grant flow together', async ({ page, context }) => {
  test.setTimeout(120000);
  const errors = [];
  page.on('pageerror', error => errors.push(error.message));
  const { mesh, base, provider, source } = await fixture(page);
  const share = await createShare(page, base, provider);
  for (const port of [20989, 20990, 20991, 20992]) await createShare(page, base, provider, source, port);
  await page.goto(`${origin}/policy?mesh=${mesh.id}`);
  await expect(page.locator('main')).toHaveAttribute('data-console-ready', 'true');
  await expect(page.locator('.access-default')).toContainText('默认拒绝已开启');
  await expect(page.getByRole('button', { name: '＋ 添加授权', exact: true })).toBeVisible();
  await expect(page.locator('.access-empty-selection')).toBeVisible();
  const detail = page.getByRole('region', { name: '访问详情', exact: true });
  await expect(detail).toContainText('选择一个访问结果');
  await expect(page.locator('#advanced-access')).not.toHaveAttribute('open');
  const detailBox = await detail.boundingBox(), simulatorBox = await page.locator('.access-simulator-panel').boundingBox();
  expect(Math.abs(detailBox.y - simulatorBox.y)).toBeLessThan(2);
  expect(simulatorBox.x).toBeGreaterThan(detailBox.x + detailBox.width);
  await capture(page, 'access-prototype-empty-desktop');

  // Capture the source with the same viewport and interaction states.
  const reference = await context.newPage();
  await reference.goto(pathToFileURL(path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../../docs/peerward-web-ui/index.html')).href + '#policy');
  await reference.locator('#policySourcePicker').selectOption('');
  await capture(reference, 'access-reference-empty-desktop');
  await reference.locator('#policySourcePicker').selectOption({ label: '设备 · 办公笔记本' });
  await capture(reference, 'access-reference-selected-desktop');
  await reference.close();

  await page.locator('#access-source').selectOption(`peer:${source.id}`);
  await expect(page.locator('.access-permission-matrix tbody tr')).toHaveCount(1);
  await expect(page.locator('.access-matrix-cell')).toHaveCount(5);
  await expect(page.locator('.access-matrix-cell.allowed')).toHaveCount(4);
  await expect(page.locator('.access-matrix-cell.denied')).toHaveCount(1);
  await capture(page, 'access-prototype-selected-desktop');
  await page.locator('#access-resource-search').fill(share.name);
  const cell = page.getByRole('button', { name: new RegExp(share.name + '.*查看原因') });
  await expect(cell).toContainText('拒绝');
  await cell.focus();
  await page.keyboard.press('Enter');
  await expect(cell).toHaveAttribute('aria-pressed', 'true');
  await expect(detail).toContainText(share.name);
  await expect(page.getByRole('dialog')).toHaveCount(0);
  await page.locator('#access-source-search').fill('no matching candidate');
  await expect(page.locator('#access-source')).toHaveValue(`peer:${source.id}`);
  await expect(detail).toContainText(share.name);
  await page.locator('#access-source-search').fill('');

  // The main action reuses real preview/apply and the current source/share.
  await page.getByRole('button', { name: '＋ 添加授权', exact: true }).click();
  const grant = page.getByRole('dialog', { name: '添加授权', exact: true });
  await expect(grant.locator('#grant-share')).toHaveValue(share.id);
  await expect(grant.locator('#sharing-access-source')).toHaveValue(`peer:${source.id}`);
  await grant.locator('#grant-reason').fill('授权页面原型验收');
  await grant.getByRole('button', { name: '预览授权影响', exact: true }).click();
  await grant.getByRole('button', { name: '确认授权', exact: true }).click();
  await expect(grant.getByRole('status').filter({ hasText: '授权已提交' })).toContainText('授权已提交');
  await grant.getByRole('button', { name: 'Close / 关闭' }).click();
  await expect(cell).toContainText('允许');
  await expect(detail.locator('.access-explanation')).toContainText('允许');
  await capture(page, 'access-prototype-detail-desktop');

  await page.locator('#access-source').selectOption('');
  await expect(detail).toContainText('选择一个访问结果');
  await expect(page.locator('.access-empty-selection')).toBeVisible();
  await page.locator('#access-source').selectOption(`peer:${source.id}`);
  await cell.click();
  await page.locator('.access-detail-panel details').filter({ hasText: '为此来源添加授权' }).locator('summary').click();
  await detail.locator('#grant-reason').fill('未提交的授权');
  await page.locator('#access-source').focus();
  page.once('dialog', dialog => dialog.dismiss());
  await page.locator('#access-source').selectOption(`peer:${provider.id}`);
  await expect(page.locator('#access-source')).toHaveValue(`peer:${source.id}`);
  await expect(detail.locator('#grant-reason')).toHaveValue('未提交的授权');
  page.once('dialog', dialog => dialog.accept());
  await page.locator('#access-source').selectOption(`peer:${provider.id}`);
  await expect(detail).toContainText('选择一个访问结果');

  await page.setViewportSize({ width: 390, height: 844 });
  await cell.click();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  await capture(page, 'access-prototype-mobile');
  const audit = await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa']).analyze();
  expect(audit.violations.filter(v => ['serious', 'critical'].includes(v.impact))).toEqual([]);
  expect(errors).toEqual([]);
});

test('access prototype reports evaluation failures and reflects the actual default policy', async ({ page }) => {
  const { mesh, source } = await fixture(page);
  await page.route('**/policy', async route => {
    const response = await route.fetch();
    const body = await response.json();
    await route.fulfill({ response, json: { ...body, default_action: 'allow' } });
  });
  await page.goto(`${origin}/policy?mesh=${mesh.id}`);
  await expect(page.locator('.access-default')).toContainText('设备通信的默认策略为允许');
  await expect(page.locator('.access-default')).not.toContainText('默认拒绝已开启');
  await page.route('**/console/matrix', route => route.fulfill({ status: 503, json: { error: { code: 'unavailable', message: 'temporarily unavailable' } } }));
  await page.locator('#access-source').selectOption(`peer:${source.id}`);
  const error = page.locator('.access-workspace [role=alert]');
  await expect(error).toContainText('暂时无法计算访问结果');
  await page.unroute('**/console/matrix');
  await error.getByRole('button', { name: '重试', exact: true }).click();
  await expect(page.locator('.access-matrix-cell').first()).toBeVisible();
  await expect(error).toHaveCount(0);
});
