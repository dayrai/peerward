import { expect, test } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';
import { randomUUID } from 'node:crypto';
import { signedClaim } from './join-claim.mjs';

test.skip(process.env.PEERWARD_CONSOLE_V14_E2E !== '1', 'isolated backend fixture required');
const origin = process.env.PEERWARD_CONSOLE_E2E_URL;
test.use({serviceWorkers:'block'});

async function openEnrollment(page) {
  const { items } = await (await page.request.get(`${origin}/api/v1/meshes`)).json();
  const mesh = items.find(item => item.name !== 'second-console-network').id;
  await page.goto(`${origin}/join-tickets?mesh=${mesh}`);
  await expect(page.locator('main')).toHaveAttribute('data-console-ready', 'true');
  await page.locator('#invite-device-name').fill(`guided-${randomUUID().slice(0, 8)}`);
  const created = page.waitForResponse(r => r.request().method() === 'POST' && r.url().endsWith('/join-tickets'));
  await page.getByRole('button', { name: '下一步', exact: true }).click();
  const ticket = await (await created).json();
  await page.getByRole('button', { name: '我已在设备上操作', exact: true }).click();
  const claim = signedClaim(ticket.token);
  return { mesh, ticket, claim, path: `${origin}/api/v1/join/${ticket.token}/claim` };
}

async function submitClaim(page, path, claim, status) {
  const response = await page.request.post(path, { data: claim.body });
  expect(response.status(), await response.text()).toBe(status);
  return await response.json();
}

const review = page => page.locator('#join-review');
const check = page => review(page).getByRole('button', { name: '检查连接', exact: true });

test('guided enrollment binds approval to its invitation and retains committed success after a read failure', async ({ page }) => {
  const first = await openEnrollment(page);
  await submitClaim(page, first.path, first.claim, 202);
  const current = await openEnrollment(page);
  await check(page).click();
  await expect(review(page).getByText('正在等待新设备', { exact: true })).toBeVisible();
  await expect(review(page).getByText(first.claim.fingerprint, { exact: true })).toHaveCount(0);
  const pending = await submitClaim(page, current.path, current.claim, 202);
  // Filter is applied by Control before pagination, not against the first history page in the browser.
  const filtered = await page.request.get(`${origin}/api/v1/meshes/${current.mesh}/join-applications?ticket=${current.ticket.id}&limit=1`);
  expect(filtered.ok()).toBe(true);
  expect((await filtered.json()).items.map(item => item.id)).toEqual([pending.application.id]);
  await check(page).click();
  await expect(review(page).getByText(current.claim.fingerprint, { exact: true })).toBeVisible();
  const approve = review(page).getByRole('button', { name: '身份一致，批准设备', exact: true });
  await expect(approve).toBeDisabled();
  await page.locator('#join-confirm-fingerprint').fill(first.claim.fingerprint);
  await expect(approve).toBeDisabled();
  await page.locator('#join-confirm-fingerprint').fill(current.claim.fingerprint);
  let approvals = 0;
  let failRead = false;
  await page.route('**/join-applications**', async route => {
    const request = route.request();
    if (request.method() === 'POST' && new URL(request.url()).pathname.endsWith('/approve')) {
      approvals++;
      const response = await route.fetch();
      expect(response.ok()).toBe(true);
      failRead = true;
      await route.fulfill({ response });
    } else if (failRead && request.method() === 'GET') {
      await route.fulfill({ status: 503, json: { error: { code: 'control_unavailable', message: 'read interrupted', field_errors: {} } } });
    } else await route.continue();
  });
  await approve.click();
  await expect(review(page).getByRole('status').filter({ hasText: '设备已加入网络' })).toBeVisible();
  await expect(review(page).getByRole('alert')).toBeVisible();
  await expect(approve).toHaveCount(0);
  expect(approvals).toBe(1);
  failRead = false;
  await check(page).click();
  await expect(review(page).getByRole('alert')).toHaveCount(0);
  const ticket = await (await page.request.get(`${origin}/api/v1/meshes/${current.mesh}/join-tickets/${current.ticket.id}`)).json();
  await expect(review(page).getByRole('link', { name: '设置访问权限', exact: true })).toHaveAttribute('href', `/policy?mesh=${current.mesh}&source=peer:${ticket.claimed_peer_id}`);
  await expect(page.locator('.enrollment-progress li.done')).toHaveCount(3);
  const accessibility = await new AxeBuilder({ page }).include('#join-review').analyze();
  expect(accessibility.violations).toEqual([]);
  await review(page).getByRole('link', { name: '查看这台设备', exact: true }).click();
  await expect(page).toHaveURL(new RegExp(`resource=${ticket.claimed_peer_id}`));
  await expect(page.getByRole('dialog', { name: '设备详情', exact: true })).toBeVisible();
  const other = await (await page.request.get(`${origin}/api/v1/meshes/${first.mesh}/join-tickets/${first.ticket.id}`)).json();
  expect(other.status).toBe('pending');
});

test('advanced bearer enrollment preserves device information and the access source', async ({ page }) => {
  const {items:[mesh]} = await (await page.request.get(`${origin}/api/v1/meshes`)).json();
  // Bearer invitations remain an advanced API/editor option; the guided flow uses approval.
  const response = await page.request.post(`${origin}/api/v1/meshes/${mesh.id}/join-tickets`, {data:{expires_in_seconds:900,settings:{display_name:'无需审批的笔记本',platform_hint:'linux',mode:{kind:'bearer'}}}});
  expect(response.status()).toBe(201);
  const ticket = await response.json();
  const joined = await submitClaim(page, `${origin}/api/v1/join/${ticket.token}/claim`, signedClaim(ticket.token), 201);
  await page.goto(`${origin}/peers?mesh=${mesh.id}`);
  await expect(page.locator(`[data-peer="${joined.peer_id}"]`)).toContainText('无需审批的笔记本');
  await expect(page.locator(`[data-peer="${joined.peer_id}"]`)).toContainText('网络设备');
  await page.goto(`${origin}/policy?mesh=${mesh.id}&source=peer:${joined.peer_id}`);
  await expect(page.locator('.access-context-banner')).toContainText('无需审批的笔记本');
});

test('guided invitation cancellation shows an ended state and retry recovers a failed status read', async ({ page }) => {
  const current = await openEnrollment(page);
  const url = `${origin}/api/v1/meshes/${current.mesh}/join-tickets/${current.ticket.id}`;
  expect((await page.request.delete(url, { headers: { 'If-Match': `"${current.ticket.version}"` } })).ok()).toBe(true);
  await page.route('**/join-tickets/' + current.ticket.id, route => route.abort());
  await check(page).click();
  await expect(review(page).getByRole('alert')).toBeVisible();
  await expect(review(page).getByText('正在等待新设备', { exact: true })).toHaveCount(0);
  await page.unroute('**/join-tickets/' + current.ticket.id);
  await check(page).click();
  await expect(review(page).getByRole('status')).toContainText('此邀请已结束');
  await page.getByRole('button', { name: '邀请下一台设备', exact: true }).click();
  await expect(page.getByRole('button', { name: '下一步', exact: true })).toBeVisible();
});

test('pending issue opens the exact application, survives reload, and rejection remains terminal', async ({ page }) => {
  const current = await openEnrollment(page);
  const pending = await submitClaim(page, current.path, current.claim, 202);
  const url = `/join-tickets?mesh=${current.mesh}&resource=${pending.application.id}`;
  await page.goto(`${origin}/operations?mesh=${current.mesh}`);
  const issue = page.locator('.issue-card').filter({has: page.locator(`a[href="${url}"]`)});
  await expect(issue).toBeVisible();
  await issue.locator('.issue-primary-action').click();
  await expect(review(page).getByText(current.claim.fingerprint, {exact:true})).toBeVisible();
  await page.reload();
  await expect(review(page).getByText(current.claim.fingerprint, {exact:true})).toBeVisible();
  await expect(page.locator('.enrollment-create-form')).toHaveCount(0);
  await review(page).getByRole('button',{name:'不是这台设备',exact:true}).click();
  await expect(review(page).getByText('这个申请已经结束。如果仍要加入这台设备，请重新生成一次性邀请。',{exact:true})).toBeVisible();
  const application = await (await page.request.get(`${origin}/api/v1/meshes/${current.mesh}/join-applications/${pending.application.id}`)).json();
  expect(application.status).toBe('rejected');
  expect((await page.request.post(current.path,{data:current.claim.body})).status()).toBe(409);
});
