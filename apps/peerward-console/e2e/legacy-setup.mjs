// These regressions exercise the preserved advanced editors. The v14 suite
// separately checks the default collapsed state and the primary guided flows.
import { expect, test } from '@playwright/test';
export function legacySetup(){test.beforeEach(async ({ page }) => {
  await page.addInitScript(() => {
    localStorage.setItem('peerward.console.locale', 'en-US');
    const openEditors = () => document.querySelectorAll('main > details.advanced-tools, main > .card.advanced-tools, .tool-sections > details.advanced-tools, #network-dns, .device-conditions details').forEach(node => { node.open = true; });
    document.addEventListener('DOMContentLoaded', () => {
      openEditors();
      new MutationObserver(openEditors).observe(document.body, { childList: true, subtree: true });
    });
  });
});}

// Open the current UI entry point explicitly; do not force a hidden modal open.
export async function openAdvancedTools(page) {
  const url = new URL(page.url());
  const labels = { '/peers': 'Advanced device tools…', '/services': 'Advanced sharing tools…', '/policy': 'Advanced access tools…' };
  const label = labels[url.pathname];
  if (!label || !url.searchParams.has('mesh')) return;
  await expect(page.locator('main')).toHaveAttribute('data-console-ready', 'true');
  const dialogName = url.pathname === '/policy' ? 'Access rules' : label.slice(0, -1);
  if (await page.getByRole('dialog', { name: dialogName, exact: true }).isVisible()) return;
  if (url.pathname === "/peers" && !await page.getByRole("button", { name: label, exact: true }).isVisible()) {
    await page.locator(".device-more > summary").click();
  }
  if (url.pathname === '/policy') await page.locator('#advanced-access > summary').click();
  await page.getByRole('button', { name: label, exact: true }).click();
  await expect(page.getByRole('dialog', { name: dialogName, exact: true })).toBeVisible();
  if (url.pathname === '/policy') await page.getByText('Resource rules and device groups', { exact: true }).click();
}
