import { legacySetup } from "./legacy-setup.mjs";
legacySetup();
import { expect, test } from "@playwright/test";

const consoleUrl = process.env.PEERWARD_CONSOLE_E2E_URL ?? "http://127.0.0.1:28081";
test.use({ serviceWorkers: "block" });

test("name-only initialization survives reload and a management interruption, then retries the same task", async ({ page }) => {
  const errors = [];
  page.on("pageerror", (error) => errors.push(error.message));
  const meshes = await (await page.request.get(`${consoleUrl}/api/v1/meshes?limit=100`)).json();
  // The new mesh is outside the original first page of meshes.
  const target = { ...meshes.items[0], id: "70772452-30f0-4b72-bd14-52c85335be63", name: "automatic-browser-test", authority_revision: 1, relay_revision: 1 };
  await page.route(`**/api/v1/meshes/${target.id}`, (route) => route.fulfill({ json: target }));
  let job;
  let submitted;
  let transientFailure = false;
  await page.route(url => url.pathname.startsWith('/api/v1/mesh-provisioning'), async (route) => {
    const request = route.request();
    if (request.method() === "POST" && request.url().endsWith("/retry")) {
      expect(request.url()).toContain(`/${job.id}/retry`);
      job = { ...job, status: "succeeded", stage: "complete", error_code: null, relay_endpoint: "relay.example:51820" };
      await route.fulfill({ json: job });
    } else if (request.method() === "POST") {
      submitted = request.postDataJSON();
      job = {
        id: submitted.request_id, mesh_id: target.id, name: submitted.name, existing_mesh: false,
        status: "running", stage: "signer", error_code: null, relay_endpoint: null,
        created_at: "2026-09-06T00:00:00Z", updated_at: "2026-09-06T00:00:00Z",
      };
      transientFailure = true;
      await route.fulfill({ json: job });
    } else if (transientFailure) {
      transientFailure = false;
      await route.fulfill({ status: 503, json: { error: { code: "control_unavailable", message: "Restarting", request_id: "restart", retryable: true, field_errors: {} } } });
    } else {
      await route.fulfill({ json: { items: job ? [job] : [], next_cursor: null } });
    }
  });
  await page.goto(`${consoleUrl}/meshes`);
  await expect(page.locator('[data-browser-ready="true"]')).toBeVisible();
  await expect(page.getByLabel("Address CIDR", { exact: true })).toHaveCount(0);
  await page.getByLabel("Name", { exact: true }).fill("automatic-browser-test");
  await page.getByRole("button", { name: "Create Mesh", exact: true }).click();
  await expect(page.getByRole("region", { name: "Resource actions" }).getByRole("region", { name: "Mesh tasks" })).toContainText("Loading signing authority");
  expect(submitted.name).toBe("automatic-browser-test");
  expect(submitted.request_id).toMatch(/^[0-9a-f-]{36}$/);
  expect(submitted.existing_mesh_id ?? null).toBeNull();
  await expect(page.getByRole("region", { name: "Resource actions" }).getByRole("region", { name: "Mesh tasks" })).toContainText("Reconnecting");
  await page.reload();
  await expect(page.getByRole("region", { name: "Resource actions" }).getByRole("region", { name: "Mesh tasks" })).toContainText("automatic-browser-test");
  job = { ...job, status: "failed", stage: "health", error_code: "health_timeout" };
  await page.getByRole("button", { name: "Retry task", exact: true }).click();
  await expect(page.getByLabel("Mesh", { exact: true })).toHaveValue(target.id);
  await expect(page.getByRole("region", { name: "Resource actions" }).getByRole("region", { name: "Mesh tasks" })).not.toContainText("automatic-browser-test");
  await expect(page.getByLabel("Resource", { exact: true })).toHaveValue(target.id);
  await expect(page.getByRole("button", { name: "Initialize selected empty mesh", exact: true })).toHaveCount(0);
  await page.getByLabel("Advanced: manual configuration").check();
  await expect(page.getByLabel("Address CIDR", { exact: true })).toBeVisible();
  await expect(page.getByRole("button", { name: "Edit selected", exact: true })).toBeEnabled();
  expect(errors).toEqual([]);
});
