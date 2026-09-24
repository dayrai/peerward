import { expect, test } from "@playwright/test";
import AxeBuilder from "@axe-core/playwright";
import { mkdir } from "node:fs/promises";
import path from "node:path";

const androidUrl = process.env.PEERWARD_ANDROID_WEB_E2E_URL ?? "http://127.0.0.1:28181";

const base = {
  profile: null,
  connection: "stopped",
  tasks: { rust_runtime: false, tun_open: false, packet_pump_running: false },
  relays: { primary_authenticated: false, standby_count: 0 },
  direct_peer_count: 0,
  signed_state: { revision: 0, complete: false },
  rotation: { state: "idle" },
  last_error: null,
  legacy_profile_present: false,
};

async function openWithSnapshot(page, payload) {
  await page.addInitScript(() => {
    window.peerwardNative = {
      onmessage: null,
      postMessage(raw) {
        window.__peerwardCommands ??= [];
        window.__peerwardCommands.push(JSON.parse(raw));
      },
    };
  });
  await page.goto(androidUrl);
  await expect.poll(() => page.evaluate(() => window.__peerwardCommands?.[0]?.kind))
    .toBe("subscribe");
  await page.evaluate((next) => {
    window.peerwardNative.onmessage({
      data: JSON.stringify({ version: 1, sequence: 1, kind: "snapshot", payload: next }),
    });
  }, { ...base, ...payload });
}

async function assertAccessible(page) {
  const result = await new AxeBuilder({ page })
    .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa"])
    .analyze();
  expect(result.violations.filter(({ impact }) => ["critical", "serious"].includes(impact)))
    .toEqual([]);
}

async function captureEvidence(page, name, options) {
  const directory = process.env.PEERWARD_EVIDENCE_SCREENSHOT_DIR;
  if (!directory) return;
  await mkdir(directory, { recursive: true });
  const { maxDiffPixelRatio: _, ...captureOptions } = options;
  await page.screenshot({ path: path.join(directory, name), ...captureOptions });
}

for (const fixture of [
  {
    name: "android-empty-en-light-mobile", width: 390, height: 844,
    locale: "en-US", theme: "light", payload: {}, status: "Disconnected",
  },
  {
    name: "android-permission-zh-dark-desktop", width: 1024, height: 800,
    locale: "zh-CN", theme: "dark", payload: {
      connection: "permission_required",
      profile: { mesh_name: "预览网络", address: "10.0.0.2/32", peer_id: "peer-1" },
    }, status: "等待 VPN 权限",
  },
  {
    name: "android-degraded-en-dark-mobile", width: 390, height: 844,
    locale: "en-US", theme: "dark", payload: {
      connection: "degraded",
      profile: { mesh_name: "Preview mesh", address: "10.0.0.2/32", peer_id: "peer-1" },
      tasks: { rust_runtime: true, tun_open: true, packet_pump_running: true },
      relays: { primary_authenticated: true, standby_count: 1 },
      signed_state: { revision: 0, complete: false },
      last_error: { code: "signed_state_incomplete", retryable: false },
    }, status: "Degraded",
  },
  {
    name: "android-failed-zh-light-desktop", width: 1024, height: 800,
    locale: "zh-CN", theme: "light", payload: {
      connection: "failed",
      profile: { mesh_name: "预览网络", address: "10.0.0.2/32", peer_id: "peer-1" },
      last_error: { code: "relay_authentication_failed", retryable: true },
    }, status: "连接失败",
  },
]) {
  test(`Android Web WCAG and visual state ${fixture.name}`, async ({ page }) => {
    await page.setViewportSize({ width: fixture.width, height: fixture.height });
    await openWithSnapshot(page, fixture.payload);
    await page.locator("#pw-language").selectOption(fixture.locale);
    await page.locator("#pw-theme").selectOption(fixture.theme);
    await expect(page.locator(".mobile-status")).toHaveText(fixture.status);
    if (fixture.payload.connection !== "healthy") {
      await expect(page.locator(".mobile-status")).not.toHaveText("Connected");
    }
    await assertAccessible(page);
    const screenshot = {
      animations: "disabled", caret: "hide", fullPage: true, maxDiffPixelRatio: 0.001,
    };
    await expect(page).toHaveScreenshot(`${fixture.name}.png`, screenshot);
    await captureEvidence(page, `${fixture.name}.png`, screenshot);
  });
}

test("Android diagnostics renders only the live healthy snapshot", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await openWithSnapshot(page, {
    connection: "healthy",
    profile: { mesh_name: "Preview mesh", address: "10.0.0.2/32", peer_id: "peer-1" },
    tasks: { rust_runtime: true, tun_open: true, packet_pump_running: true },
    relays: { primary_authenticated: true, standby_count: 1 },
    direct_peer_count: 2,
    signed_state: { revision: 42, complete: true },
  });
  await page.getByRole("link", { name: "Diagnostics", exact: true }).click();
  await expect(page.getByText("r42", { exact: false })).toBeVisible();
  await expect(page.getByText("2", { exact: true })).toBeVisible();
  await assertAccessible(page);
  const screenshot = {
    animations: "disabled", caret: "hide", fullPage: true, maxDiffPixelRatio: 0.001,
  };
  const name = "android-healthy-diagnostics-en-light-mobile.png";
  await expect(page).toHaveScreenshot(name, screenshot);
  await captureEvidence(page, name, screenshot);
});
