import { legacySetup } from "./legacy-setup.mjs";
legacySetup();
import { expect, test } from "@playwright/test";

test.use({ serviceWorkers: "block" });

const consoleUrl = process.env.PEERWARD_CONSOLE_E2E_URL ?? "http://127.0.0.1:28081";
const expiredCursor = "00000000-0000-4000-8000-000000000001";

test("expired event cursors are not cached by the console proxy", async ({ request }) => {
  const response = await request.get(`${consoleUrl}/api/v1/events`, {
    headers: { "Last-Event-ID": expiredCursor },
  });
  expect(response.status()).toBe(410);
  expect((await response.json()).error.code).toBe("event_cursor_expired");
  expect(response.headers()["cache-control"]).toBe("no-store");
});

test("browser clears an expired cursor and resumes live updates without caching", async ({ page }) => {
  await page.addInitScript((cursor) => {
    const nativeFetch = window.fetch.bind(window);
    window.__eventRecovery = [];
    window.fetch = async (input, init) => {
      let request = new Request(input, init);
      if (new URL(request.url).pathname !== "/api/v1/events") return nativeFetch(input, init);
      const attempt = { cache: request.cache, cursor: request.headers.get("last-event-id") };
      window.__eventRecovery.push(attempt);
      if (window.__eventRecovery.length === 1) {
        const headers = new Headers(request.headers);
        headers.set("last-event-id", cursor);
        request = new Request(request, { headers });
      }
      const response = await nativeFetch(request);
      attempt.status = response.status;
      return response;
    };
  }, expiredCursor);
  await page.goto(`${consoleUrl}/meshes`);
  await expect(page.locator('[data-browser-ready="true"]')).toBeVisible();
  await page.getByLabel("Advanced: manual configuration").check();
  await expect.poll(() => page.evaluate(() => window.__eventRecovery.map((item) => item.status)))
    .toEqual([410, 200]);
  expect(await page.evaluate(() => window.__eventRecovery.map(({ cache, cursor }) => ({ cache, cursor }))))
    .toEqual([{ cache: "no-store", cursor: null }, { cache: "no-store", cursor: null }]);
  await expect(page.getByRole("status").filter({ hasText: "Live update" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Create", exact: true })).toBeEnabled();
});

test("an unavailable event stream does not block the server-rendered mesh form", async ({ page }) => {
  await page.addInitScript(() => {
    const nativeFetch = window.fetch.bind(window);
    window.__eventAttempted = false;
    window.fetch = (input, init) => {
      const request = new Request(input, init);
      if (new URL(request.url).pathname === "/api/v1/events") {
        window.__eventAttempted = true;
        return new Promise(() => {});
      }
      return nativeFetch(input, init);
    };
  });
  await page.goto(`${consoleUrl}/meshes`);
  await expect(page.locator('[data-browser-ready="true"]')).toBeVisible();
  await page.getByLabel("Advanced: manual configuration").check();
  await expect.poll(() => page.evaluate(() => window.__eventAttempted)).toBe(true);
  await expect(page.getByRole("region", { name: "Resource actions" }))
    .toHaveAttribute("data-browser-ready", "true");
  await expect(page.getByLabel("Mesh", { exact: true })).toBeEnabled();
  await expect(page.getByRole("button", { name: "Create", exact: true })).toBeEnabled();
  await expect(page.getByRole("status").filter({ hasText: "Loading" })).toHaveCount(0);
});

test("a committed write remains saved when the follow-up list read fails", async ({ page }) => {
  // Keep the event stream from racing the deliberately failed snapshot read.
  await page.route("**/api/v1/events", route => route.fulfill({
    status: 503, json: { error: { code: "control_unavailable", message: "Test stream paused", retryable: true } },
  }));
  const mesh = (await (await page.request.get(`${consoleUrl}/api/v1/meshes`)).json()).items[0];
  const endpoint = `${consoleUrl}/api/v1/meshes/${mesh.id}`;
  const updatedName = `${mesh.name}-refresh-regression`;
  let committed = false;
  let writes = 0;
  let failedReads = 0;
  await page.goto(`${consoleUrl}/meshes?mesh=${mesh.id}`);
  await expect(page.locator('[data-browser-ready="true"]')).toBeVisible();
  await page.getByLabel("Advanced: manual configuration").check();
  const actions = page.getByRole("region", { name: "Resource actions", exact: true });
  await actions.getByLabel("Resource", { exact: true }).selectOption(mesh.id);
  await actions.getByLabel("Name", { exact: true }).fill(updatedName);
  await page.route("**/api/v1/meshes?*", async route => {
    if (!committed) return route.continue();
    failedReads += 1;
    await route.fulfill({ status: 503, json: { error: {
      code: "control_unavailable", message: "Test read interrupted", retryable: true, field_errors: {},
    } } });
  });
  await page.route(endpoint, async route => {
    if (route.request().method() !== "PATCH") return route.continue();
    writes += 1;
    const response = await route.fetch();
    expect(response.ok()).toBe(true);
    committed = true;
    await route.fulfill({ response });
  });
  try {
    await actions.getByRole("button", { name: "Edit selected", exact: true }).click();
    await expect.poll(() => failedReads).toBeGreaterThan(0);
    await expect(actions.getByRole("status").filter({ hasText: "Saved, but the updated list could not be loaded" })).toBeVisible();
    await expect(actions.getByRole("status").filter({ hasText: "Saving" })).toHaveCount(0);
    expect((await (await page.request.get(endpoint)).json()).name).toBe(updatedName);
    expect(writes).toBe(1);
    await page.unroute("**/api/v1/meshes?*");
    await page.reload();
    await expect(actions.getByLabel("Resource", { exact: true }).locator(`option[value="${mesh.id}"]`)).toHaveText(updatedName);
    expect(writes).toBe(1);
  } finally {
    const saved = await (await page.request.get(endpoint)).json();
    expect((await page.request.patch(endpoint, {
      headers: { "If-Match": `"${saved.version}"` }, data: { name: mesh.name },
    })).ok()).toBe(true);
  }
});
