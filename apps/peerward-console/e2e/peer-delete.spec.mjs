import { legacySetup, openAdvancedTools } from "./legacy-setup.mjs";
legacySetup();
import { expect, test } from "@playwright/test";

const consoleUrl = process.env.PEERWARD_CONSOLE_E2E_URL ?? "http://127.0.0.1:28081";

test("retired peers require saved disabled state and exact confirmation before deletion", async ({ page }) => {
  const initialMesh = (await (await page.request.get(`${consoleUrl}/api/v1/meshes?limit=100`)).json()).items[0];
  await page.goto(`${consoleUrl}/peers?mesh=${initialMesh.id}`);
  await openAdvancedTools(page);
  await expect(page.getByRole("region", { name: "Resource actions" }))
    .toHaveAttribute("data-browser-ready", "true");
  const meshes = await page.evaluate(async () => (await (await fetch("/api/v1/meshes?limit=100")).json()).items);
  expect(meshes.length).toBeGreaterThan(0);
  await page.getByLabel("Mesh", { exact: true }).selectOption(meshes[0].id);
  await expect(page.locator("main .eyebrow")).toHaveText(meshes[0].name);
  const name = `delete-e2e-${Date.now()}`;
  const removal = page.getByRole("button", { name: "Delete selected Peer", exact: true });
  await expect(removal).toBeDisabled();
  // Enrollment now starts through the invitation wizard. Seed a disposable
  // uncredentialed record to exercise the advanced retirement/delete controls.
  const creation = await page.request.post(`${consoleUrl}/api/v1/meshes/${meshes[0].id}/peers`, {data:{name}});
  expect(creation.status()).toBe(201);
  const createdPeer = await creation.json();
  await page.reload();
  await openAdvancedTools(page);
  await expect(page.getByRole("region", {name:"Resource actions"})).toHaveAttribute("data-browser-ready", "true");
  const row = page.locator(`[data-peer="${createdPeer.id}"]`);
  await expect(row).toBeVisible();
  const selection = page.getByLabel("Resource", { exact: true });
  const peerId = await selection.locator("option").filter({ hasText: name }).getAttribute("value");
  expect(peerId).toBeTruthy();
  await selection.selectOption(peerId);
  const meshId = await page.getByLabel("Mesh", { exact: true }).inputValue();
  const member = `/api/v1/meshes/${meshId}/peers/${peerId}`;
  const confirmation = page.getByLabel("Type the exact resource name");
  await confirmation.fill(name);
  await expect(removal).toBeDisabled();
  // An unsaved editor value must never satisfy the server-state prerequisite.
  await page.getByLabel("Administrative state", { exact: true }).selectOption("disabled");
  await expect(removal).toBeDisabled();
  await page.getByRole("button", { name: "Disable or revoke selected", exact: true }).click();
  await expect.poll(() => page.evaluate(async (path) => (await (await fetch(path)).json()).administrative_state, member))
    .toBe("disabled");
  await expect(confirmation).toHaveValue("");
  await expect(removal).toBeDisabled();
  await expect(row).toBeVisible();
  await confirmation.fill("incorrect-name");
  await expect(removal).toBeDisabled();
  await confirmation.fill(name);
  await expect(removal).toBeEnabled();
  await expect(page.getByRole("button", { name: "Disable or revoke selected", exact: true })).toBeDisabled();
  const response = page.waitForResponse((response) =>
    response.url().endsWith(`${member}/delete`) && response.request().method() === "POST");
  await removal.click();
  expect((await response).status()).toBe(204);
  await expect(row).toHaveCount(0);
  await expect(selection).toHaveValue("");
  await expect(page.getByLabel("Name", { exact: true })).toHaveValue("");
  await expect(removal).toBeDisabled();
  await expect(page.getByRole("link", { name: "＋ Add device", exact: true })).toBeVisible();
  await page.reload();
  await openAdvancedTools(page);
  await expect(page.getByRole("region", { name: "Resource actions" }))
    .toHaveAttribute("data-browser-ready", "true");
  await expect(row).toHaveCount(0);
  expect(await page.evaluate(async (path) => (await fetch(path)).status, member)).toBe(404);
});
