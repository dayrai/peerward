import { legacySetup } from "./legacy-setup.mjs";
legacySetup();
import { expect, test } from "@playwright/test";

const consoleUrl = process.env.PEERWARD_CONSOLE_E2E_URL ?? "http://127.0.0.1:28081";

test("an existing browser cache cannot pair an old client with a new document", async ({ page }) => {
  const errors = [];
  page.on("pageerror", (error) => errors.push(error.message));
  // Seed the actual previous release cache before the current worker activates.
  await page.goto(`${consoleUrl}/manifest.webmanifest`);
  await page.evaluate(async () => {
    const cache = await caches.open("peerward-static-v3");
    await cache.put("/assets/peerward-console-web.js?v=20260906.1", new Response(
      'throw new Error("stale Peerward client executed");',
      { headers: { "Content-Type": "text/javascript" } },
    ));
    await navigator.serviceWorker.register("/service-worker.js");
    await navigator.serviceWorker.ready;
  });
  const initialMesh = (await (await page.request.get(`${consoleUrl}/api/v1/meshes?limit=100`)).json()).items[0];
  await page.goto(`${consoleUrl}/peers?mesh=${initialMesh.id}`);
  await expect(page.locator("main")).toHaveAttribute("data-console-ready", "true");
  await page.locator(".account-menu > summary").click();
  await page.getByLabel("Language", { exact: true }).selectOption("zh-CN");
  await page.locator(".account-menu > summary").click();
  await page.locator(".device-more > summary").click();
  await expect(page.getByRole("button", { name: "高级设备工具…", exact: true })).toBeVisible();
  await page.reload();
  await expect(page.locator("main")).toHaveAttribute("data-console-ready", "true");
  expect(errors).toEqual([]);
  expect(await page.evaluate(() => caches.has("peerward-static-v3"))).toBe(false);
});

test("the device list renders without CSP violations", async ({ page }) => {
  await page.addInitScript(() => {
    window.__styleViolations = [];
    document.addEventListener("securitypolicyviolation", (event) => {
      if (event.effectiveDirective.startsWith("style-src")) {
        window.__styleViolations.push(event.effectiveDirective);
      }
    });
  });
  const meshes = await (await page.request.get(`${consoleUrl}/api/v1/meshes?limit=100`)).json();
  await page.goto(`${consoleUrl}/peers?mesh=${meshes.items[0].id}`);
  await expect(page.locator("main")).toHaveAttribute("data-console-ready", "true");
  expect(await page.evaluate(() => window.__styleViolations)).toEqual([]);
});
