// Launched only by the disposable Android runner after the real device is ready.
// It receives public identifiers; the Console keeps administrative credentials.
import { chromium, expect } from '@playwright/test';
import { writeFile } from 'node:fs/promises';
import path from 'node:path';

const [origin, mesh, peer, output] = process.argv.slice(2);
if (!/^http:\/\/127\.0\.0\.1:\d+$/.test(origin) ||
    ![mesh, peer].every(value => /^[0-9a-f-]{36}$/.test(value))) {
  throw new Error('Disposable loopback console and device identifiers required');
}
const report = { passed: false, scope: 'Browser Console → real Android device → authenticated completion', peer_id: peer };
const browser = await chromium.launch({ headless: true });
const page = await browser.newPage({ viewport: { width: 1440, height: 1000 }, locale: 'zh-CN' });
page.setDefaultTimeout(20_000);
try {
  await page.goto(`${origin}/peers?mesh=${mesh}&resource=${peer}`);
  await expect(page.locator('main')).toHaveAttribute('data-console-ready', 'true');
  const drawer = page.getByRole('dialog', { name: '设备详情', exact: true });
  await drawer.getByRole('tab', { name: '维护', exact: true }).click();
  await drawer.getByText('发起更新请求', { exact: true }).click();
  await drawer.locator('#renewal-deadline').selectOption('3600');
  await drawer.locator('#renewal-reason').fill('Android 控制台联动验收');
  await drawer.getByRole('checkbox').check();
  await page.screenshot({ path: path.join(output, 'console-renewal-before.png'), fullPage: true });
  const endpoint = `/api/v1/meshes/${mesh}/console/devices/${peer}/renewals`;
  const pending = page.waitForResponse(response => response.url().endsWith(endpoint) && response.request().method() === 'POST');
  await drawer.getByRole('button', { name: '提交更新请求', exact: true }).click();
  const response = await pending;
  if (response.status() !== 200) throw new Error(`Renewal rejected (${response.status()})`);
  const renewal = await response.json();
  report.request_id = renewal.id;
  const retry = await page.request.post(origin + endpoint, {
    headers: { 'If-Match': response.request().headers()['if-match'] },
    data: response.request().postDataJSON(),
  });
  expect(retry.status()).toBe(200);
  expect((await retry.json()).id).toBe(renewal.id);
  report.idempotent_retry = true;
  await expect.poll(async () => {
    const current = await page.request.get(origin + endpoint);
    expect(current.status()).toBe(200);
    const item = (await current.json()).items.find(item => item.id === renewal.id);
    report.state = item?.state;
    return report.state;
  }, { timeout: 110_000 }).toBe('completed');
  await drawer.getByRole('button', { name: '刷新进度', exact: true }).click();
  await expect(drawer.getByText('已完成，新身份已重新认证', { exact: true })).toBeVisible();
  const updated = await page.request.get(`${origin}/api/v1/meshes/${mesh}/peers/${peer}`);
  expect(updated.status()).toBe(200);
  const activeSerial = (await updated.json()).credentials.active.serial;
  expect(activeSerial).not.toBe(response.request().postDataJSON().current_serial);
  const credentialDetails = drawer.locator('details').filter({
    has: page.locator('summary', { hasText: '凭据技术信息' }),
  });
  await credentialDetails.locator('summary').click();
  await expect(credentialDetails.locator('code')).toHaveText(activeSerial);
  await expect(drawer.getByText('已提交，等待投递', { exact: true })).toHaveCount(0);
  report.active_credential_refreshed = true;
  await page.screenshot({ path: path.join(output, 'console-renewal-completed.png'), fullPage: true });
  await page.reload();
  await page.getByRole('dialog').getByRole('tab', { name: '维护', exact: true }).click();
  await expect(page.getByRole('dialog').getByText('已完成，新身份已重新认证', { exact: true })).toBeVisible();
  report.survives_reload = true;
  report.passed = true;
} catch (error) {
  // Keep diagnostic locations and public UI only, never raw request headers.
  report.error = error.name;
  await page.screenshot({ path: path.join(output, 'console-renewal-failed.png'), fullPage: true }).catch(() => {});
  throw error;
} finally {
  await writeFile(path.join(output, 'console-browser-renewal.json'), JSON.stringify(report, null, 2) + '\n');
  await browser.close();
}
