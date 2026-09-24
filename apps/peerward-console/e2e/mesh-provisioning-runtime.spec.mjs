import { expect, test } from "@playwright/test";
import { legacySetup } from "./legacy-setup.mjs";
legacySetup();

const consoleUrl = process.env.PEERWARD_CONSOLE_E2E_URL ?? "http://127.0.0.1:38081";
test.use({ serviceWorkers: "block" });
test.skip(process.env.PEERWARD_PROVISIONING_RUNTIME_E2E !== "1", "Requires an isolated Compose deployment with dynamic Mesh lifecycle enabled");

test("name-only creation initializes a real mesh and selects it after Relay readiness", async ({ page }) => {
  test.setTimeout(180_000);
  const errors = [];
  page.on("pageerror", (error) => errors.push(error.message));
  await page.goto(`${consoleUrl}/meshes`);
  await expect(page.locator('[data-browser-ready="true"]')).toBeVisible();
  await expect(page.getByLabel("Address CIDR", { exact: true })).toHaveCount(0);
  const name = `provision-runtime-${Date.now()}`;
  await page.getByLabel("Name", { exact: true }).fill(name);
  const created = page.waitForResponse((response) => response.url().endsWith("/api/v1/mesh-provisioning") && response.request().method() === "POST");
  await page.getByRole("button", { name: "Create Mesh", exact: true }).click();
  const response = await created;
  expect(response.status()).toBe(202);
  const requestId = response.request().postDataJSON().request_id;
  const job = await (await page.request.get(`${consoleUrl}/api/v1/mesh-provisioning/${requestId}`)).json();
  await expect.poll(async () => {
    let response;
    try {
      response = await page.request.get(`${consoleUrl}/api/v1/mesh-provisioning/${job.id}`);
    } catch {
      return "reconnecting";
    }
    if (!response.ok()) return "reconnecting";
    const current = await response.json();
    expect(current.status, current.error_code ?? "initialization failed").not.toBe("failed");
    return current.status;
  }, { timeout: 150_000, intervals: [1000] }).toBe("succeeded");
  await expect(page.getByLabel("Mesh", { exact: true })).toHaveValue(job.mesh_id);
  await expect(page.getByLabel("Resource", { exact: true })).toHaveValue(job.mesh_id);
  const authorities = await (await page.request.get(`${consoleUrl}/api/v1/meshes/${job.mesh_id}/authorities`)).json();
  const relays = await (await page.request.get(`${consoleUrl}/api/v1/meshes/${job.mesh_id}/relays`)).json();
  expect(authorities.items).toHaveLength(1);
  expect(relays.items).toHaveLength(1);
  expect(relays.items[0].peer_endpoints[0]).toMatch(/^tcp:\/\/127\.0\.0\.1:\d+$/);
  expect(errors).toEqual([]);
});
