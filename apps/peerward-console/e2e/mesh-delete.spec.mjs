import { legacySetup } from "./legacy-setup.mjs";
legacySetup();
import { expect, test } from "@playwright/test";

const consoleUrl = process.env.PEERWARD_CONSOLE_E2E_URL ?? "http://127.0.0.1:28081";
test.use({ serviceWorkers: "block" });

// Exercise the shipped browser code while intercepting every mutation: these
// tests must never delete a Mesh in the stack supplying the SSR document.
async function deletionFixture(page, rejection) {
  let deleted = false;
  await page.addInitScript(() => {
    const nativeFetch = window.fetch.bind(window);
    window.fetch = async (input, init) => {
      const request = input instanceof Request ? input : new Request(input, init);
      if (new URL(request.url).pathname !== "/api/v1/events") return nativeFetch(input, init);
      const response = new Response(new ReadableStream({ start(controller) { window.meshEvents = controller; } }), { headers: { "content-type": "text/event-stream" } });
      Object.defineProperty(response, "url", { value: request.url });
      return response;
    };
  });
  let request;
  const { items } = await (await page.request.get(`${consoleUrl}/api/v1/meshes?limit=100`)).json();
  expect(items.length).toBeGreaterThan(0);
  const target = items[0];
  await page.route("**/api/v1/**", async (route) => {
    const incoming = route.request();
    const url = new URL(incoming.url());
    if (incoming.method() === "DELETE" && url.pathname === `/api/v1/meshes/${target.id}`) {
      request = { body: incoming.postDataJSON(), version: incoming.headers()["if-match"] };
      if (rejection) {
        await route.fulfill({ status: 409, json: { error: {
          code: "revision_conflict", message: rejection, request_id: "mesh-delete-rejected",
          retryable: false, field_errors: {},
        } } });
      } else {
        deleted = true;
        await route.fulfill({ status: 202, json: { mesh_id: target.id, job_id: "62687088-8b9d-4325-a6db-d46925d207f9" } });
      }
    } else if (!["GET", "HEAD"].includes(incoming.method())) {
      await route.abort();
      throw new Error(`Unexpected mutation: ${incoming.method()} ${url.pathname}`);
    } else if (url.pathname === "/api/v1/meshes") {
      await route.fulfill({ json: { items: items.filter((mesh) => !deleted || mesh.id !== target.id), next_cursor: null } });
    } else if (deleted && url.pathname === `/api/v1/meshes/${target.id}`) {
      await route.fulfill({ status: 404, json: { error: { code: "not_found", message: "Mesh not found", request_id: "deleted", retryable: false, field_errors: {} } } });
    } else if (url.pathname === "/api/v1/mesh-provisioning") {
      await route.fulfill({ json: { items: [], next_cursor: null } });
    } else if (url.pathname === "/api/v1/events") {
      await route.fulfill({ contentType: "text/event-stream", body: ": keepalive\n\n" });
    } else {
      await route.continue();
    }
  });
  await page.goto(`${consoleUrl}/meshes?mesh=${target.id}`);
  await expect(page.getByRole("region", { name: "Resource actions" })).toHaveAttribute("data-browser-ready", "true");
  return { target, others: items.slice(1), request: () => request, removeFromList: () => { deleted = true; } };
}

test("admin can select a Mesh without Advanced and delete only after exact saved-name confirmation", async ({ page }) => {
  const fixture = await deletionFixture(page);
  const { target } = fixture;
  await expect(page.getByLabel("Advanced: manual configuration")).not.toBeChecked();
  await expect(page.getByLabel("Address CIDR", { exact: true })).toHaveCount(0);
  const selection = page.getByLabel("Resource", { exact: true });
  await expect(selection).toBeVisible();
  const removal = page.getByRole("button", { name: "Delete selected Mesh", exact: true });
  await expect(removal).toBeDisabled();
  await selection.selectOption(target.id);
  await expect(page.getByLabel("Address CIDR", { exact: true })).toHaveCount(0);
  const confirmation = page.getByLabel("Type the exact resource name");
  await expect(confirmation).toHaveValue("");
  await page.getByLabel("Name", { exact: true }).fill("unsaved-name");
  await confirmation.fill("unsaved-name");
  await expect(removal).toBeDisabled();
  await confirmation.fill(`${target.name} `);
  await expect(removal).toBeDisabled();
  await confirmation.fill(target.name);
  await expect(removal).toBeEnabled();
  await removal.click();
  await expect.poll(fixture.request).toEqual({ body: { confirmation_name: target.name }, version: `"${target.version}"` });
  await expect(page.getByRole("row").filter({hasText: target.name})).toHaveCount(0);
  await expect(selection).toHaveValue("");
  await expect(page.getByLabel("Mesh", { exact: true })).toHaveValue("");
  await expect(page).toHaveURL(`${consoleUrl}/meshes`);
  await expect(page.getByLabel("Name", { exact: true })).toHaveValue("");
  await expect(removal).toBeDisabled();
  await page.getByLabel("Name", { exact: true }).fill("next-mesh");
  await expect(page.getByRole("button", { name: "Create Mesh", exact: true })).toBeEnabled();
});

test("failed Mesh deletion preserves selection and displays the backend reason", async ({ page }) => {
  const reason = "This Mesh changed after it was selected. Refresh and confirm again.";
  const { target } = await deletionFixture(page, reason);
  await page.getByLabel("Resource", { exact: true }).selectOption(target.id);
  await page.getByLabel("Type the exact resource name").fill(target.name);
  await page.getByRole("button", { name: "Delete selected Mesh", exact: true }).click();
  await expect(page.getByRole("alert")).toContainText(reason);
  await expect(page.getByLabel("Resource", { exact: true })).toHaveValue(target.id);
  await expect(page.locator("#network-name")).toHaveValue(target.name);
});

test("operators cannot see the admin Mesh delete action", async ({ page }) => {
  await deletionFixture(page);
  await page.route("**/auth/session", async (route) => {
    const response = await route.fetch();
    const session = await response.json();
    await route.fulfill({ json: { ...session, role: "operator", capabilities: session.capabilities.filter((capability) => capability !== "trust_manage") } });
  });
  // Route navigation reuses the existing session snapshot. A ready handshake
  // reloads capabilities, as it does when the event stream reconnects.
  await page.evaluate(() => window.meshEvents.enqueue(new TextEncoder().encode(
    'event: peerward.ready\ndata: {"cursor":null}\n\n'
  )));
  await expect(page.locator(".account-menu summary").getByText("Operator", { exact: true })).toBeVisible();
  await expect(page.getByRole("button", { name: "Delete selected Mesh", exact: true })).toHaveCount(0);
});


test("Mesh deletion in another tab refreshes the list and clears a removed selection", async ({ page }) => {
  const fixture = await deletionFixture(page);
  await page.getByLabel("Resource", { exact: true }).selectOption(fixture.target.id);
  fixture.removeFromList();
  await page.evaluate((id) => window.meshEvents.enqueue(new TextEncoder().encode(
    `id: deleted-selected\nevent: mesh.deleted\ndata: ${JSON.stringify({ mesh_id: id, resource_type: "mesh" })}\n\n`
  )), fixture.target.id);
  await expect(page.getByRole("row").filter({hasText: fixture.target.name})).toHaveCount(0);
  await expect(page.getByLabel("Mesh", { exact: true })).toHaveValue("");
  await expect(page.getByLabel("Resource", { exact: true })).toHaveValue("");
  await expect(page).toHaveURL(`${consoleUrl}/meshes`);
  await expect(page.getByRole("alert")).toHaveCount(0);
});
