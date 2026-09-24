import { expect, test } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';
import { mkdir } from 'node:fs/promises';
import path from 'node:path';

const origin = process.env.PEERWARD_CONSOLE_E2E_URL;
test.skip(process.env.PEERWARD_CONSOLE_V14_E2E !== '1', 'isolated console fixture required');
test.use({ viewport: { width: 1440, height: 1000 }, serviceWorkers: 'block' });

async function openWizard(page) {
  const [mesh] = (await (await page.request.get(`${origin}/api/v1/meshes`)).json()).items;
  await page.goto(`${origin}/services?mesh=${mesh.id}`);
  await expect(page.locator('main')).toHaveAttribute('data-console-ready', 'true');
  await page.getByRole('button', { name: '＋ 添加共享', exact: true }).click();
  const dialog = page.getByRole('dialog', { name: '添加共享', exact: true });
  await expect(dialog).toBeVisible();
  return { mesh, dialog };
}

async function capture(page, name) {
  const directory = process.env.PEERWARD_EVIDENCE_SCREENSHOT_DIR;
  if (directory) {
    await expect(page.getByRole('dialog')).not.toContainText('正在读取候选项…');
    await mkdir(directory, { recursive: true });
    await page.screenshot({ path: path.join(directory, `${name}.png`), animations: 'disabled' });
  }
}

for (const width of [1440, 390]) {
  test(`sharing prototype: centered four-step modal at ${width}px`, async ({ page }) => {
    await page.setViewportSize({ width, height: 1000 });
    const { dialog } = await openWizard(page);
    await expect(dialog.locator('.sharing-wizard-progress li')).toHaveText([
      '1共享类型', '2共享信息', '3谁可以访问', '4确认创建',
    ]);
    await expect(dialog.getByRole('radio')).toHaveCount(3);
    await expect(dialog.getByRole('radio', { name: '设备服务', exact: true })).toBeChecked();
    await expect(dialog.locator('#share-name')).toHaveCount(0);
    await expect(dialog.locator('#share-provider')).toHaveCount(0);
    const box = await dialog.boundingBox();
    expect(box.width).toBe(width === 1440 ? 680 : 370);
    expect(Math.abs(box.x + box.width / 2 - width / 2)).toBeLessThan(2);
    expect(Math.abs(box.y + box.height / 2 - 500)).toBeLessThan(2);
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
    const audit = await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa']).analyze();
    expect(audit.violations.filter(v => ['serious', 'critical'].includes(v.impact))).toEqual([]);
    await capture(page, `sharing-prototype-type-${width}`);
    await dialog.getByRole('button', { name: '下一步', exact: true }).click();
    await expect(dialog.locator('.sharing-wizard-progress li').first()).toHaveText('✓共享类型');
    await expect(dialog.getByLabel('共享名称', { exact: true })).toBeVisible();
    await expect(dialog.getByRole('combobox', { name: '提供设备', exact: true })).toBeVisible();
    await expect(dialog.locator('#share-provider-query')).toHaveCount(0);
    await expect(dialog.getByRole('button', { name: '更多设置', exact: true })).toHaveCount(0);
    await expect(dialog.locator('#share-dns')).toBeVisible();
    await expect(dialog.locator('#share-port')).toHaveValue('445');
    const protocol = await dialog.locator('#share-protocol').boundingBox();
    const port = await dialog.locator('#share-port').boundingBox();
    if (width === 1440) {
      expect(protocol.y).toBe(port.y);
      expect(port.x - protocol.x - protocol.width).toBe(12);
      expect((await dialog.boundingBox()).height).toBeLessThan(660);
    } else {
      expect(port.y).toBeGreaterThan(protocol.y);
      expect(protocol.x).toBe(port.x);
    }
    const detailsAudit = await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa']).analyze();
    expect(detailsAudit.violations.filter(v => ['serious', 'critical'].includes(v.impact))).toEqual([]);
    await capture(page, `sharing-prototype-service-details-${width}`);
    await dialog.getByRole('button', { name: '取消', exact: true }).click();
    await expect(dialog).toHaveCount(0);
    await expect(page.getByRole('button', { name: '＋ 添加共享', exact: true })).toBeFocused();
  });
}

test('sharing prototype: keyboard selection, validation, back navigation and guarded cancellation', async ({ page }) => {
  const { mesh, dialog } = await openWizard(page);
  const writes = [];
  page.on('request', request => {
    if (request.method() === 'POST' && /\/console\/sharing\/(preview|apply)$/.test(new URL(request.url()).pathname)) writes.push(request.url());
  });
  await dialog.getByRole('radio', { name: '设备服务', exact: true }).focus();
  await page.keyboard.press('ArrowDown');
  await expect(dialog.getByRole('radio', { name: '局域网资源', exact: true })).toBeChecked();
  await dialog.getByRole('button', { name: '下一步', exact: true }).click();
  await expect(dialog.locator('[aria-current="step"]')).toHaveText('2共享信息');
  await dialog.getByRole('button', { name: '下一步', exact: true }).click();
  await expect(dialog.locator('[aria-current="step"]')).toHaveText('2共享信息');
  const peers = (await (await page.request.get(`${origin}/api/v1/meshes/${mesh.id}/peers`)).json()).items;
  const provider = peers.find(peer => peer.name === 'home-nas');
  const consumer = peers.find(peer => peer.name === 'test-consumer');
  await dialog.locator('#share-name').fill('保留的局域网草稿');
  await dialog.locator('#share-provider').selectOption(provider.id);
  await dialog.locator('#share-prefix').fill('192.168.214.10/32');
  await dialog.locator('#share-protocol').selectOption('all');
  await dialog.getByRole('button', { name: '下一步', exact: true }).click();
  await expect(dialog.locator('[aria-current="step"]')).toHaveText('3谁可以访问');
  await dialog.locator(`input[name=share-source][value="peer:${consumer.id}"]`).check();
  await dialog.getByRole('button', { name: '上一步', exact: true }).click();
  await expect(dialog.locator('#share-name')).toHaveValue('保留的局域网草稿');
  await expect(dialog.locator('#share-prefix')).toHaveValue('192.168.214.10/32');
  await expect(dialog.locator('#share-provider')).toHaveValue(provider.id);
  await dialog.getByRole('button', { name: '上一步', exact: true }).click();
  await expect(dialog.getByRole('radio', { name: '局域网资源', exact: true })).toBeChecked();
  await dialog.getByRole('button', { name: '下一步', exact: true }).click();
  await expect(dialog.locator('#share-name')).toHaveValue('保留的局域网草稿');
  await expect(dialog.locator('#share-provider')).toHaveValue(provider.id);
  await expect(dialog.locator('#share-protocol')).toHaveValue('all');
  await capture(page, 'sharing-prototype-details');
  await dialog.getByRole('button', { name: '下一步', exact: true }).click();
  await expect(dialog.locator(`input[name=share-source][value="peer:${consumer.id}"]`)).toBeChecked();
  await capture(page, 'sharing-prototype-access');
  let prompts = 0;
  page.once('dialog', async prompt => { prompts += 1; expect(prompt.message()).toContain('未保存'); await prompt.dismiss(); });
  await dialog.getByRole('button', { name: '取消', exact: true }).click();
  await expect(dialog).toBeVisible();
  expect(prompts).toBe(1);
  page.once('dialog', async prompt => { prompts += 1; await prompt.accept(); });
  await dialog.getByRole('button', { name: '取消', exact: true }).click();
  await expect(dialog).toHaveCount(0);
  expect(prompts).toBe(2);
  expect(writes).toEqual([]);
});

test('sharing prototype: native protocol picker stays open across candidate refresh', async ({ page }) => {
  await page.clock.install();
  const { dialog } = await openWizard(page);
  await dialog.getByRole('button', { name: '下一步', exact: true }).click();
  await expect(dialog.locator('#share-provider option')).not.toHaveCount(1);
  await expect(dialog).not.toContainText('正在读取候选项…');
  let release;
  let intercepted = false;
  const gate = new Promise(resolve => { release = resolve; });
  await page.route('**/console/devices?**', async route => {
    intercepted = true;
    await gate;
    await route.continue();
  });
  const protocol = dialog.locator('#share-protocol');
  try {
    const box = await protocol.boundingBox();
    await page.mouse.move(box.x + box.width - 14, box.y + box.height / 2);
    await page.mouse.down();
    expect(await protocol.evaluate(select => select.matches(':open'))).toBe(false);
    await page.mouse.up();
    await expect(protocol).toHaveJSProperty('value', 'tcp');
    expect(await protocol.evaluate(select => select.matches(':open'))).toBe(true);
    await page.clock.fastForward(30_000);
    await expect.poll(() => intercepted).toBe(true);
    await expect(dialog).toContainText('正在读取候选项…');
    expect(await protocol.evaluate(select => select.matches(':open'))).toBe(true);
    release();
    await expect(dialog).not.toContainText('正在读取候选项…');
    expect(await protocol.boundingBox()).toEqual(box);
    await page.waitForTimeout(300);
    expect(await protocol.evaluate(select => select.matches(':open'))).toBe(true);
    await page.keyboard.press('ArrowDown');
    await page.keyboard.press('Enter');
    await expect(protocol).toHaveValue('udp');
    await expect(dialog).toBeVisible();
    await expect(page.locator('#console-sidebar')).toHaveAttribute('inert', '');
    // Reopening requires an ordinary click, never holding the mouse button.
    await protocol.click();
    expect(await protocol.evaluate(select => select.matches(':open'))).toBe(true);
    await page.keyboard.press('ArrowDown');
    await page.keyboard.press('Enter');
    await expect(protocol).toHaveValue('http');
    await expect(dialog.locator('#share-port')).toHaveValue('80');
  } finally {
    release();
    await page.unrouteAll({ behavior: 'wait' });
  }
  page.once('dialog', prompt => prompt.accept());
  await dialog.getByRole('button', { name: '取消', exact: true }).click();
  await expect(dialog).toHaveCount(0);
  await expect(page.locator('#console-sidebar')).not.toHaveAttribute('inert', '');
  await expect(page.getByRole('button', { name: '＋ 添加共享', exact: true })).toBeFocused();
});

test('sharing prototype: protocol opens after release at the text and arrow, with keyboard support', async ({ page }) => {
  const { dialog } = await openWizard(page);
  await dialog.getByRole('button', { name: '下一步', exact: true }).click();
  await expect(dialog).not.toContainText('正在读取候选项…');
  const protocol = dialog.locator('#share-protocol');
  await protocol.selectOption('http');
  let unexpectedPrompts = 0;
  const dismissPrompt = async prompt => { unexpectedPrompts += 1; await prompt.dismiss(); };
  page.on('dialog', dismissPrompt);
  for (const [position, duration] of [['text', 30], ['arrow', 30], ['text', 200], ['arrow', 350]]) {
    const box = await protocol.boundingBox();
    await page.mouse.move(box.x + (position === 'text' ? box.width / 2 : box.width - 14), box.y + box.height / 2);
    await page.mouse.down();
    await page.waitForTimeout(duration);
    expect(await protocol.evaluate(select => select.matches(':open'))).toBe(false);
    await page.mouse.up();
    await page.waitForTimeout(500);
    expect(await protocol.evaluate(select => select.matches(':open'))).toBe(true);
    await page.keyboard.press('Escape');
    expect(await protocol.evaluate(select => select.matches(':open'))).toBe(false);
    await expect(protocol).toHaveValue('http');
    await expect(dialog).toBeVisible();
  }
  await protocol.focus();
  await page.keyboard.press('Space');
  expect(await protocol.evaluate(select => select.matches(':open'))).toBe(true);
  await page.keyboard.press('ArrowDown');
  await page.keyboard.press('Enter');
  await expect(protocol).toHaveValue('https');
  await expect(dialog.locator('#share-port')).toHaveValue('443');
  expect(unexpectedPrompts).toBe(0);
  page.off('dialog', dismissPrompt);
  page.once('dialog', prompt => prompt.accept());
  await dialog.getByRole('button', { name: '取消', exact: true }).click();
  await expect(dialog).toHaveCount(0);
});

test('sharing prototype: HTTP presets, DNS validation and real review preserve settings', async ({ page }) => {
  const { mesh, dialog } = await openWizard(page);
  const peers = (await (await page.request.get(`${origin}/api/v1/meshes/${mesh.id}/peers`)).json()).items;
  const provider = peers.find(peer => peer.name === 'home-nas');
  await dialog.getByRole('button', { name: '下一步', exact: true }).click();
  await dialog.locator('#share-name').fill('网页服务验收');
  await dialog.locator('#share-provider').selectOption(provider.id);
  await dialog.locator('#share-protocol').selectOption('http');
  await expect(dialog.locator('#share-port')).toHaveValue('80');
  await dialog.locator('#share-protocol').selectOption('https');
  await expect(dialog.locator('#share-port')).toHaveValue('443');
  await dialog.locator('#share-port').fill('443');
  await dialog.locator('#share-protocol').selectOption('http');
  await expect(dialog.locator('#share-port')).toHaveValue('443');
  await dialog.locator('#share-port').fill('18443');
  await dialog.locator('#share-protocol').selectOption('http');
  await expect(dialog.locator('#share-port')).toHaveValue('18443');
  await dialog.locator('#share-protocol').selectOption('https');
  await dialog.locator('#share-dns').fill('nas.home');
  await dialog.getByRole('button', { name: '下一步', exact: true }).click();
  await expect(dialog.getByRole('alert')).toContainText('不要填写完整域名');
  await dialog.locator('#share-dns').fill('web-proof');
  await dialog.getByRole('button', { name: '下一步', exact: true }).click();
  await expect(dialog.getByRole('radio', { name: '暂不新增授权', exact: true })).toBeChecked();
  await capture(page, 'sharing-prototype-service-access');
  const preview = page.waitForResponse(r => new URL(r.url()).pathname.endsWith('/console/sharing/preview') && r.request().method() === 'POST');
  await dialog.getByRole('button', { name: '下一步', exact: true }).click();
  const response = await preview;
  expect(response.ok()).toBe(true);
  const draft = response.request().postDataJSON();
  expect(draft.target).toEqual({ kind: 'service', protocols: ['tcp'], port: 18443, alias: 'web-proof' });
  expect(draft.source).toEqual({ kind: 'none' });
  await expect(dialog.locator('.sharing-review')).toContainText('HTTPS 18443');
  await expect(dialog.locator('.sharing-review')).toContainText('web-proof');
  await expect(dialog.locator('[aria-current=step]')).toHaveText('4确认创建');
  const audit = await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa']).analyze();
  expect(audit.violations.filter(v => ['serious', 'critical'].includes(v.impact))).toEqual([]);
  await capture(page, 'sharing-prototype-service-review');
  await dialog.getByRole('button', { name: '上一步', exact: true }).click();
  await dialog.getByRole('button', { name: '上一步', exact: true }).click();
  await expect(dialog.locator('#share-protocol')).toHaveValue('https');
  await expect(dialog.locator('#share-port')).toHaveValue('18443');
  await expect(dialog.locator('#share-dns')).toHaveValue('web-proof');
  page.once('dialog', prompt => prompt.accept());
  await dialog.getByRole('button', { name: '取消', exact: true }).click();
});
