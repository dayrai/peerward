import { expect, test } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';
import { mkdir } from 'node:fs/promises';
import path from 'node:path';
import { randomUUID } from 'node:crypto';

const origin = process.env.PEERWARD_CONSOLE_E2E_URL;
test.use({ viewport: { width: 1440, height: 1000 }, serviceWorkers: 'block' });
test.skip(process.env.PEERWARD_CONSOLE_V14_E2E !== '1', 'isolated console fixture required');
let base, original, devices;

async function current(page) {
  const response = await page.request.get(`${base}/policy`);
  expect(response.ok()).toBe(true);
  return response.json();
}
async function open(page) {
  const mesh = base.split('/').at(-1);
  await page.goto(`${origin}/policy?mesh=${mesh}`);
  await expect(page.locator('main')).toHaveAttribute('data-console-ready', 'true');
  await page.getByRole('button', { name: '配置设备互通', exact: true }).click();
  await expect(page.getByRole('dialog', { name: '访问规则', exact: true })).toBeVisible();
  await expect(page.locator('.policy-savebar')).toContainText('所有规则已保存');
}
async function addPing(page) {
  await page.getByLabel('发起设备', { exact: true }).selectOption(devices[0].id);
  await page.getByLabel('目标设备', { exact: true }).selectOption(devices[1].id);
  await expect(page.getByRole('combobox', { name: '允许的通信', exact: true })).toHaveValue('ping');
  await expect(page.getByRole('combobox', { name: '通信方向', exact: true })).toHaveValue('both');
  await page.getByRole('button', { name: '加入待保存规则', exact: true }).click();
}
async function capture(page, name) {
  const folder = process.env.PEERWARD_EVIDENCE_SCREENSHOT_DIR;
  if (!folder) return;
  await mkdir(folder, { recursive: true });
  await page.screenshot({ path: path.join(folder, `${name}.png`), fullPage: false });
}

test.beforeEach(async ({ page }) => {
  const meshes = await (await page.request.get(`${origin}/api/v1/meshes`)).json();
  base = `${origin}/api/v1/meshes/${meshes.items[0].id}`;
  original = await current(page);
  devices = (await (await page.request.get(`${base}/peers?limit=100`)).json()).items
    .filter(p => p.administrative_state === 'enabled');
  expect(devices.length).toBeGreaterThanOrEqual(2);
});
test.afterEach(async ({ page }) => {
  // Only the disposable fixture: restore the pre-test rules, with a new revision.
  const latest = await current(page);
  if (latest.revision !== original.revision) {
    const response = await page.request.put(`${base}/policy`, { data: { ...original, revision: latest.revision + 1 } });
    expect(response.ok()).toBe(true);
  }
});

test('policy editor selects two devices, validates without saving, saves both directions and preserves existing rules', async ({ page }) => {
  const preserved = {
    id: randomUUID(), priority: 10, action: 'deny', enabled: true, log: true,
    source: { peer_ids: [], labels: { scope: 'protected' }, cidrs: [] },
    destination: { peer_ids: [], labels: {}, cidrs: ['192.168.19.0/24'] },
    protocol: 'tcp', destination_ports: [{ first: 8000, last: 8090 }],
  };
  expect((await page.request.put(`${base}/policy`, { data: { ...original, revision: original.revision + 1, rules: [...original.rules, preserved] } })).ok()).toBe(true);
  const baseline = await current(page);
  await open(page);
  await expect(page.getByRole('button', { name: '保存规则', exact: true })).toBeDisabled();
  await capture(page, 'policy-editor-loaded-zh');
  await addPing(page);
  await capture(page, 'policy-editor-draft-zh');
  await expect(page.locator('.policy-summary-row')).toHaveCount(baseline.rules.length + 2);
  await page.getByRole('button', { name: '仅校验', exact: true }).click();
  await expect(page.locator('.policy-savebar')).toContainText('校验通过，尚未保存');
  expect(await current(page)).toEqual(baseline);
  await page.getByRole('button', { name: '保存规则', exact: true }).click();
  await expect(page.locator('.policy-savebar')).toContainText('规则已保存');
  const saved = await current(page);
  expect(saved.revision).toBe(baseline.revision + 1);
  for (const rule of baseline.rules) expect(saved.rules).toContainEqual(rule);
  expect(saved.default_action).toBe(baseline.default_action);
  for (const [source, target] of [[devices[0], devices[1]], [devices[1], devices[0]]]) {
    expect(saved.rules).toContainEqual(expect.objectContaining({
      action: 'allow', enabled: true, protocol: 'icmp', destination_ports: [],
      source: { peer_ids: [source.id], cidrs: [], labels: {} },
      destination: { peer_ids: [target.id], cidrs: [], labels: {} },
    }));
  }
  await capture(page, 'policy-editor-saved-zh');
  await expect(page.getByRole('button', { name: '保存规则', exact: true })).toBeDisabled();
  await page.reload();
  await page.getByRole('button', { name: '配置设备互通', exact: true }).click();
  await expect(page.locator('.policy-summary-row')).toHaveCount(saved.rules.length);
  await expect(page.getByRole('button', { name: '保存规则', exact: true })).toBeDisabled();
});

test('policy editor protects unsaved rules and keeps save visible on mobile', async ({ page }) => {
  await open(page);
  await page.getByLabel('发起设备', { exact: true }).selectOption(devices[0].id);
  await page.getByLabel('目标设备', { exact: true }).selectOption(devices[0].id);
  await expect(page.getByText('请选择两台不同的设备。', { exact: true })).toBeVisible();
  await expect(page.getByRole('button', { name: '加入待保存规则', exact: true })).toBeDisabled();
  await page.getByLabel('目标设备', { exact: true }).selectOption(devices[1].id);
  await page.getByRole('button', { name: '加入待保存规则', exact: true }).click();
  page.once('dialog', dialog => dialog.dismiss());
  await page.getByRole('button', { name: 'Close / 关闭', exact: true }).click();
  await expect(page.getByRole('dialog', { name: '访问规则', exact: true })).toBeVisible();
  await page.setViewportSize({ width: 390, height: 844 });
  await page.locator('.policy-advanced > summary').click();
  for (const scrollTo of [0, 1e6]) {
    await page.locator('.policy-scroll').evaluate((el, position) => { el.scrollTop = position; }, scrollTo);
    await expect(page.getByRole('button', { name: '保存规则', exact: true })).toBeInViewport();
  }
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  await capture(page, 'policy-editor-mobile-zh');
  const result = await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa']).analyze();
  expect(result.violations.filter(v => ['serious', 'critical'].includes(v.impact))).toEqual([]);
  await page.locator('.policy-scroll').evaluate(el => { el.scrollTop = 0; });
  await page.getByRole('button', { name: '保存规则', exact: true }).click();
  await expect(page.locator('.policy-savebar')).toContainText('规则已保存');
});

test('policy editor saves a selected device pair directly without a staging step', async ({ page }) => {
  await open(page);
  await page.getByLabel('发起设备', { exact: true }).selectOption(devices[0].id);
  await page.getByLabel('目标设备', { exact: true }).selectOption(devices[1].id);
  await expect(page.getByRole('button', { name: '保存规则', exact: true })).toBeEnabled();
  await capture(page, 'policy-editor-ping-ready-zh');
  await page.getByRole('button', { name: '保存规则', exact: true }).click();
  await expect(page.locator('.policy-savebar')).toContainText('规则已保存');
  expect((await current(page)).rules).toHaveLength(original.rules.length + 2);
  await expect(page.getByLabel('发起设备', { exact: true })).toHaveValue('');
  await expect(page.getByRole('button', { name: '保存规则', exact: true })).toBeDisabled();
});

test('policy editor retains draft on concurrent update and cannot overwrite newer policy', async ({ page }) => {
  await open(page);
  await addPing(page);
  const external = { ...original, revision: original.revision + 1 };
  expect((await page.request.put(`${base}/policy`, { data: external })).ok()).toBe(true);
  await page.getByRole('button', { name: '保存规则', exact: true }).click();
  await expect(page.locator('.policy-savebar')).toContainText('草稿已保留');
  expect((await current(page)).revision).toBe(external.revision);
  expect((await current(page)).rules).toEqual(external.rules);
  await expect(page.locator('.policy-summary-row')).toHaveCount(original.rules.length + 2);
  await expect(page.getByRole('button', { name: '保存规则', exact: true })).toBeDisabled();
  await capture(page, 'policy-editor-conflict-zh');
  await page.getByRole('button', { name: '重新加载', exact: true }).click();
  await page.getByRole('button', { name: '继续编辑', exact: true }).click();
  await expect(page.locator('.policy-summary-row')).toHaveCount(original.rules.length + 2);
  await page.getByRole('button', { name: '重新加载', exact: true }).click();
  await page.getByRole('button', { name: '放弃并重新加载', exact: true }).click();
  await expect(page.locator('.policy-summary-row')).toHaveCount(original.rules.length);
});

test('policy editor reports failed validation and transport failure without clearing the draft', async ({ page }) => {
  await open(page); await addPing(page);
  await page.route('**/policy/validate', route => route.fulfill({ json: { valid: false, field_errors: { 'rules.0': 'invalid' }, warnings: [] } }));
  await page.getByRole('button', { name: '保存规则', exact: true }).click();
  await expect(page.locator('.policy-savebar')).toContainText('规则未通过校验，尚未保存');
  expect(await current(page)).toEqual(original);
  await page.unroute('**/policy/validate');
  await page.route('**/policy', route => route.request().method() === 'PUT' ? route.abort('failed') : route.continue());
  await page.getByRole('button', { name: '保存规则', exact: true }).click();
  await expect(page.locator('.policy-savebar [role=alert]')).toBeVisible();
  await expect(page.locator('.policy-summary-row')).toHaveCount(original.rules.length + 2);
  expect(await current(page)).toEqual(original);
});
