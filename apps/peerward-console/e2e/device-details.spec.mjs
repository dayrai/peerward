import { legacySetup } from "./legacy-setup.mjs";
legacySetup();
import { expect, test } from "@playwright/test";
import AxeBuilder from "@axe-core/playwright";

const consoleUrl = process.env.PEERWARD_CONSOLE_E2E_URL ?? "http://127.0.0.1:29481";
test.use({ serviceWorkers: "block" });
test.skip(process.env.PEERWARD_DEVICE_DETAILS_E2E !== "1", "Requires the isolated console_review_fixture API");

async function fixture(page) {
  const response = await page.request.get(`${consoleUrl}/api/v1/meshes?limit=100`);
  const mesh = (await response.json()).items.find((mesh) => mesh.name.startsWith("console-"));
  expect(mesh, "start the isolated console_review_fixture first").toBeTruthy();
  return mesh;
}

test("device IP and descriptions survive an edit and reload without changing identity or labels", async ({ page }, testInfo) => {
  const mesh = await fixture(page);
  const path = `/api/v1/meshes/${mesh.id}/peers`;
  const peer = (await (await page.request.get(`${consoleUrl}${path}`)).json()).items.find((peer) => peer.name === "home-nas");
  await page.goto(`${consoleUrl}/peers?mesh=${mesh.id}`);
  await expect(page.locator('main')).toHaveAttribute('data-console-ready', 'true');
  await expect(page.getByRole("heading", { level: 1, name: "Devices", exact: true })).toBeVisible();
  await expect(page.locator(`.device-list-row[data-peer="${peer.id}"]`)).toContainText("100.96.195.2");
  await expect(page.locator(`.device-list-row[data-peer="${peer.id}"]`)).toContainText("Offline");
  await page.locator("#device-search").fill("home-nas");
  await page.getByRole("button", { name: peer.display_name, exact: true }).click();
  await expect(page).toHaveURL(new RegExp(`resource=${peer.id}`));
  await expect(page.getByRole("dialog").getByRole("heading", { name: peer.display_name, exact: true })).toBeVisible();
  await page.locator(".device-detail-technical > summary").click();
  await expect(page.locator(".device-detail-technical")).toContainText(peer.id);
  await page.goBack();
  await expect(page.getByRole("dialog")).toHaveCount(0);
  await expect(page.locator("#device-search")).toHaveValue("home-nas");
  await page.getByRole("button", { name: peer.display_name, exact: true }).click();
  await page.getByRole("dialog").getByRole("button",{name:"Edit basic information",exact:true}).click();
  await page.getByLabel("Display name", { exact: true }).fill("家庭 NAS 与记忆库");
  await page.getByLabel("Location description", { exact: true }).fill("书房 · 二楼");
  await page.getByRole("button", { name: "Save changes", exact: true }).click();
  await expect.poll(async () => (await (await page.request.get(`${consoleUrl}${path}/${peer.id}`)).json()).display_name).toBe("家庭 NAS 与记忆库");
  const updated = await (await page.request.get(`${consoleUrl}${path}/${peer.id}`)).json();
  expect(updated.name).toBe(peer.name);
  expect(updated.labels).toEqual(peer.labels);
  expect(updated.mesh_addresses).toEqual(["100.96.195.2"]);
  expect(updated.location).toBe("书房 · 二楼");
  await expect(page.getByRole("dialog").getByRole("status").filter({hasText:/^Saved$/})).toHaveText("Saved");
  await page.getByRole("dialog").getByRole("button", { name: "Back to status", exact: true }).click();
  await expect(page.getByRole("dialog").getByRole("tab", { name: "Status", exact: true })).toHaveClass(/active/);
  await page.reload();
  await expect(page).toHaveURL(new RegExp(`resource=${peer.id}`));
  await expect(page.getByRole("dialog").getByRole("heading", { name: "家庭 NAS 与记忆库", exact: true })).toBeVisible();
  await expect(page.locator(`.device-list-row[data-peer="${peer.id}"]`)).toContainText("书房 · 二楼");
  await page.getByRole("dialog").getByRole("button",{name:"Close / 关闭"}).click();
  await expect(page).not.toHaveURL(/resource=/);
  await page.locator(".account-menu > summary").click();
  await page.locator("#pw-language").selectOption("zh-CN");
  await page.locator(".account-menu > summary").click();
  await page.getByRole("button", { name: "家庭 NAS 与记忆库", exact: true }).click();
  await expect(page.getByRole("region", { name: "设备详情" })).toContainText("100.96.195.2");
  await page.screenshot({ path: testInfo.outputPath("devices-desktop-zh.png"), fullPage: true });
  const accessibility = await new AxeBuilder({ page }).withTags(["wcag2a", "wcag2aa"]).analyze();
  expect(accessibility.violations.filter((issue) => ["serious", "critical"].includes(issue.impact))).toEqual([]);
  await page.setViewportSize({ width: 390, height: 844 });
  await expect(page.locator(`.device-list-row[data-peer="${peer.id}"]`)).toContainText("100.96.195.2");
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
  await page.screenshot({ path: testInfo.outputPath("devices-mobile-zh.png"), fullPage: true });
});

test("completed Mesh history is absent while unfinished cleanup remains visible", async ({ page }) => {
  const mesh = await fixture(page);
  const base = { mesh_id: mesh.id, existing_mesh: false, error_code: null, relay_endpoint: null,
    created_at: "2026-09-08T00:00:00Z", updated_at: "2026-09-08T00:00:00Z" };
  await page.route("**/api/v1/mesh-provisioning**", (route) => route.fulfill({ json: { items: [
    { ...base, id: "a4273412-5f6c-4a92-b6d9-435541620841", name: "deleted-regression-mesh", operation: "delete", status: "succeeded", stage: "complete" },
    { ...base, id: "75b75de0-ec39-4a80-92c2-5e460ee31b23", name: "old-successful-create", operation: "create", status: "succeeded", stage: "complete" },
    { ...base, id: "3c5aa7f0-882d-4b5b-8758-0e218d2b2910", name: "waiting-mesh", operation: "delete", status: "running", stage: "waiting_for_relay" },
    { ...base, id: "4c5aa7f0-882d-4b5b-8758-0e218d2b2910", mesh_id: "5c5aa7f0-882d-4b5b-8758-0e218d2b2910", name: "another-network-task", operation: "delete", status: "running", stage: "waiting_for_relay" },
  ], next_cursor: null } }));
  await page.goto(`${consoleUrl}/meshes?mesh=${mesh.id}`);
  await expect(page.locator(".settings-danger").getByRole("region", { name: "Current network tasks" })).toContainText("waiting-mesh");
  await expect(page.locator(".settings-danger")).not.toContainText("another-network-task");
  await expect(page.getByText("deleted-regression-mesh", { exact: true })).toHaveCount(0);
  await expect(page.getByText("old-successful-create", { exact: true })).toHaveCount(0);
  await expect(page.locator("#network-name")).toHaveValue(mesh.name);
});

test("signing authorities remain available under advanced security", async ({ page }) => {
  const mesh = await fixture(page);
  await page.goto(`${consoleUrl}/peers?mesh=${mesh.id}`);
  await expect(page.locator('main')).toHaveAttribute('data-console-ready', 'true');
  await expect(page.getByRole("navigation", { name: "Primary navigation" }).getByRole("link", { name: "Signing authorities" })).toHaveCount(0);
  const advanced = page.locator(".advanced-navigation");
  await expect(advanced).not.toHaveAttribute("open");
  await advanced.locator("summary").click();
  await advanced.getByRole("link", { name: "Credentials and authorities", exact: true }).click();
  await expect(page.getByRole("heading", { level: 1, name: "Credentials and authorities", exact: true })).toBeVisible();
  await expect(advanced).toHaveAttribute("open");
});
