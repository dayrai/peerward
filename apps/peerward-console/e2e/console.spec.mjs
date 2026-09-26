import { legacySetup } from "./legacy-setup.mjs";
legacySetup();
import { expect, test } from "@playwright/test";
import AxeBuilder from "@axe-core/playwright";

const consoleUrl = process.env.PEERWARD_CONSOLE_E2E_URL ?? "http://127.0.0.1:28081";
const oidcExpected = process.env.PEERWARD_EXPECT_OIDC === "1";
const oidcProviderUrl = process.env.PEERWARD_OIDC_PROVIDER_URL ?? "http://127.0.0.1:29000/";
const authorityCertificateFile = process.env.PEERWARD_CONSOLE_E2E_AUTHORITY_CERT;

async function waitFor(url) {
  for (let attempt = 0; attempt < 120; attempt += 1) {
    try {
      const response = await fetch(url);
      if (response.ok) return;
    } catch (_) {
      // The real Compose stack has not completed its health gates yet.
    }
    await new Promise((resolve) => setTimeout(resolve, 500));
  }
  throw new Error(`real Peerward Console did not become ready at ${url}`);
}

async function api(page, path) {
  return page.evaluate(async (requestPath) => {
    const response = await fetch(requestPath);
    const text = await response.text();
    if (!response.ok) throw new Error(`${response.status}: ${text}`);
    return text ? JSON.parse(text) : {};
  }, path);
}

async function operationalMesh(page, meshes) {
  for (const mesh of meshes.items) {
    const authorities = await api(page, `/api/v1/meshes/${mesh.id}/authorities?limit=100`);
    if (authorities.items.some((authority) => authority.lifecycle === "active")) return mesh;
  }
  throw new Error("the real stack has no mesh with an active Authority");
}

async function selectResource(page, id) {
  const selection = page.getByLabel("Resource", { exact: true });
  await selection.selectOption(id);
  await expect(selection).toHaveValue(id);
}

async function waitForBrowser(page) {
  if (new URL(page.url()).pathname === '/policy') {
    await expect(page.locator('main')).toHaveAttribute('data-console-ready', 'true');
    await page.getByRole('button', { name: 'Configure device access', exact: true }).click();
    await expect(page.locator('.policy-savebar')).toContainText('All rules saved');
    return;
  }
  await expect(page.getByRole("region", { name: "Resource actions" }))
    .toHaveAttribute("data-browser-ready", "true");
}

async function selectMesh(page, mesh) {
  await page.getByLabel("Mesh", { exact: true }).selectOption(mesh.id);
  await expect(page.getByLabel("Mesh", { exact: true })).toHaveValue(mesh.id);
  await expect(page.locator("main .eyebrow")).toHaveText(mesh.name);
}

async function navigate(page, name) {
  const routes={Devices:"peers",Relays:"relays",Services:"services",Policy:"policy","Signing authorities":"authorities","Join tickets":"join-tickets",Meshes:"meshes",Audit:"audit"};
  const mesh=await page.getByLabel("Mesh",{exact:true}).inputValue();
  const discard=dialog=>dialog.accept();page.once("dialog",discard);
  await page.goto(`${consoleUrl}/${routes[name]}${mesh?`?mesh=${mesh}`:""}`);
  page.off("dialog",discard);
  if(name!=="Audit")await waitForBrowser(page);
}

async function exerciseBoundedSse(page, meshId) {
  await page.addInitScript((selectedMesh) => {
    if (sessionStorage.getItem("peerward-sse-e2e-complete") === "1") return;
    const nativeFetch = window.fetch.bind(window);
    const stats = {
      attempts: 0,
      peerRequests: 0,
      peerInflight: 0,
      maxPeerInflight: 0,
      peerRequestTimes: [],
      lastEventId: "",
      secondLastEventId: null,
    };
    window.__peerwardSseStats = stats;
    window.__peerwardRestoreFetch = () => {
      sessionStorage.setItem("peerward-sse-e2e-complete", "1");
      window.fetch = nativeFetch;
    };

    window.fetch = async (input, init) => {
      const request = input instanceof Request ? input : new Request(input, init);
      const url = new URL(request.url, window.location.href);
      if (url.pathname === `/api/v1/meshes/${selectedMesh}/peers`) {
        stats.peerRequests += 1;
        stats.peerInflight += 1;
        stats.maxPeerInflight = Math.max(stats.maxPeerInflight, stats.peerInflight);
        stats.peerRequestTimes.push(performance.now());
        try {
          return await nativeFetch(input, init);
        } finally {
          stats.peerInflight -= 1;
        }
      }
      if (url.pathname !== "/api/v1/events") return nativeFetch(input, init);

      stats.attempts += 1;
      const mockResponse = (body, options = {}) => {
        const response = new Response(body, options);
        Object.defineProperty(response, "url", { value: request.url });
        return response;
      };
      if (stats.attempts === 1) {
        return mockResponse(JSON.stringify({
          error: {
            code: "event_cursor_expired",
            message: "event cursor expired",
            request_id: crypto.randomUUID(),
            field_errors: {},
            retryable: false,
          },
        }), { status: 410, headers: { "content-type": "application/json" } });
      }
      if (stats.attempts === 2) {
        stats.secondLastEventId = request.headers.get("last-event-id");
        const eventIds = Array.from({ length: 1_000 }, () => crypto.randomUUID());
        stats.lastEventId = eventIds.at(-1);
        const events = eventIds.map((id, index) =>
          `id: ${id}\r\nevent: peer.updated\r\ndata: ${JSON.stringify({
            mesh_id: selectedMesh,
            resource_type: "peer",
            label: index === 0 ? "中文" : "burst",
          })}\r\n\r\n`).join("");
        const bytes = new TextEncoder().encode(
          `event: peerward.ready\r\ndata: {"cursor":null}\r\n\r\n${events}`,
        );
        const marker = new TextEncoder().encode("中文");
        let split = -1;
        for (let index = 0; index <= bytes.length - marker.length; index += 1) {
          if (marker.every((byte, offset) => bytes[index + offset] === byte)) {
            split = index + 1;
            break;
          }
        }
        if (split < 0) throw new Error("UTF-8 split marker missing");
        const body = new ReadableStream({
          start(controller) {
            controller.enqueue(bytes.slice(0, split));
            controller.enqueue(bytes.slice(split));
            controller.close();
          },
        });
        return mockResponse(body, { headers: { "content-type": "text/event-stream" } });
      }
      if (stats.attempts === 3) {
        return mockResponse(`data: ${"x".repeat(256 * 1024 + 1)}\n\n`, {
          headers: { "content-type": "text/event-stream" },
        });
      }
      return mockResponse("unavailable", { status: 503 });
    };
  }, meshId);

  await page.goto(`${consoleUrl}/peers?mesh=${meshId}`);
  await waitForBrowser(page);
  await expect.poll(async () => page.evaluate(() => window.__peerwardSseStats?.attempts ?? 0))
    .toBeGreaterThanOrEqual(3);
  const stats = await page.evaluate(() => window.__peerwardSseStats);
  expect(stats.secondLastEventId).toBeNull();
  expect(stats.peerRequests).toBe(2);
  expect(stats.maxPeerInflight).toBe(1);
  expect(stats.peerRequestTimes).toHaveLength(2);
  expect(stats.peerRequestTimes[1] - stats.peerRequestTimes[0]).toBeGreaterThanOrEqual(150);
  await expect(page.getByRole("status").filter({ hasText: stats.lastEventId })).toBeVisible();

  await page.evaluate(() => window.__peerwardRestoreFetch());
  await page.reload();
  await waitForBrowser(page);
}

test.beforeAll(async () => {
  await waitFor(`${consoleUrl}/`);
});

test("real PostgreSQL 18 CRUD, multi-endpoint Relay, policy v2, join secret, audit, and SSE", async ({ page }) => {
  const suffix = Date.now().toString(36);
  const peerName = `e2e-peer-${suffix}`;
  const editedPeerName = `${peerName}-edited`;
  const meshName = `e2e-mesh-${suffix}`;

  if (oidcExpected) {
    const providerBefore = await fetch(new URL("debug", oidcProviderUrl))
      .then((response) => response.json());
    await page.goto(`${consoleUrl}/api/v1/auth/login`);
    await expect(page).toHaveURL((url) => url.origin === consoleUrl && url.pathname === "/");
    const session = await api(page, "/auth/session");
    expect(session.authenticated).toBe(true);
    expect(session.role).toBe("admin");
    expect(session.csrf_token).toBeTruthy();
    const cookies = await page.context().cookies();
    const sessionCookie = cookies.find((cookie) => cookie.name === "peerward_session");
    const csrfCookie = cookies.find((cookie) => cookie.name === "peerward_csrf");
    expect(sessionCookie).toMatchObject({ httpOnly: true, secure: true, sameSite: "Lax" });
    expect(csrfCookie).toMatchObject({ httpOnly: false, secure: true, sameSite: "Strict" });
    const rejected = await page.evaluate(async () => {
      const response = await fetch("/auth/logout", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: "{}",
      });
      return response.status;
    });
    expect(rejected).toBe(403);
    const provider = await fetch(new URL("debug", oidcProviderUrl)).then((response) => response.json());
    expect(provider.authorizations - providerBefore.authorizations).toBe(1);
    expect(provider.exchanges - providerBefore.exchanges).toBe(1);
    expect(provider.pkce_validations - providerBefore.pkce_validations).toBe(1);
    expect(provider.rotations - providerBefore.rotations).toBe(1);
    expect(provider.unused_codes).toBe(providerBefore.unused_codes);
  }

  const initialMesh = (await (await page.request.get(`${consoleUrl}/api/v1/meshes?limit=100`)).json()).items[0];
  await page.goto(`${consoleUrl}/peers?mesh=${initialMesh.id}`);
  await waitForBrowser(page);
  const accessibility = await new AxeBuilder({ page })
    .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa"])
    .analyze();
  expect(
    accessibility.violations.filter(({ impact }) => impact === "critical" || impact === "serious"),
    "serious or critical WCAG 2.2 AA violations",
  ).toEqual([]);
  await expect(page.getByRole("heading", { name: "Devices", exact: true, level: 1 })).toBeVisible();
  const meshes = await api(page, "/api/v1/meshes?limit=100");
  expect(meshes.items.length).toBeGreaterThan(0);
  const primary = await operationalMesh(page, meshes);
  const primaryMesh = primary.id;
  await selectMesh(page, primary);
  await exerciseBoundedSse(page, primaryMesh);
  await selectMesh(page, primary);

  await navigate(page, "Signing authorities");
  await selectMesh(page, primary);
  await page.getByLabel("Authority certificate file").setInputFiles(authorityCertificateFile);
  const certificatePreview = page.getByRole("group", { name: "Parsed certificate preview" });
  await expect(certificatePreview).toBeVisible();
  await expect(certificatePreview.getByText(primaryMesh, { exact: true })).toBeVisible();

  await navigate(page, "Devices");
  await selectMesh(page, primary);

  // The primary device creation flow is now invitation-based (covered by the
  // guided suite). Seed an uncredentialed record for these advanced CRUD checks.
  expect(await page.evaluate(async ({mesh,name})=>{
    const session=await(await fetch("/auth/session")).json();
    const headers={"content-type":"application/json"};if(session.csrf_token)headers["x-csrf-token"]=session.csrf_token;
    return (await fetch(`/api/v1/meshes/${mesh}/peers`,{method:"POST",headers,body:JSON.stringify({name,labels:{suite:"playwright"}})})).status;
  },{mesh:primaryMesh,name:peerName})).toBe(201);
  await page.reload();await waitForBrowser(page);
  await expect(page.getByRole("cell", { name: peerName, exact: true })).toBeVisible();
  const peers = await api(page, `/api/v1/meshes/${primaryMesh}/peers?limit=100`);
  const peerId = peers.items.find((peer) => peer.name === peerName)?.id;
  expect(peerId).toBeTruthy();

  await selectResource(page, peerId);
  await page.getByLabel("Name", { exact: true }).fill(editedPeerName);
  await page.getByLabel("Labels (key=value, comma-separated)").fill("suite=edited");
  await page.getByRole("button", { name: "Edit selected" }).click();
  await expect(page.getByRole("cell", { name: editedPeerName, exact: true })).toBeVisible();
  await expect(page.getByRole("status").filter({ hasText: /Live update applied:/ })).toBeVisible();

  await navigate(page, "Relays");
  const relayName = `e2e-relay-${suffix}`;
  await page.getByLabel("Name", { exact: true }).fill(relayName);
  await page.getByLabel("Peer endpoints (comma-separated)")
    .fill("tcp://LOCALHOST:17777, tcp://127.0.0.1:17779");
  await page.getByLabel("Backbone endpoints (comma-separated)")
    .fill("tcp://LOCALHOST:17778, tcp://127.0.0.1:17780");
  await page.getByRole("button", { name: "Create", exact: true }).click();
  await expect(page.getByRole("cell", { name: relayName, exact: true })).toBeVisible();
  const relays = await api(page, `/api/v1/meshes/${primaryMesh}/relays?limit=100`);
  const relay = relays.items.find((item) => item.name === relayName);
  expect(relay?.peer_endpoints).toEqual([
    "tcp://localhost:17777",
    "tcp://127.0.0.1:17779",
  ]);
  expect(relay?.backbone_endpoints).toHaveLength(2);

  await navigate(page, "Services");
  await page.getByLabel("Publishing Peer ID").fill(peerId);
  await page.getByLabel("Service protocol").selectOption("both");
  await page.getByLabel("Public Mesh listen port").fill("18080");
  await page.getByLabel("DNS alias (optional)").fill("");
  await page.getByLabel("Labels (key=value, comma-separated)").fill("suite=playwright");
  await page.getByRole("button", { name: "Create", exact: true }).click();
  await expect.poll(async () => {
    const current = await api(page, `/api/v1/meshes/${primaryMesh}/services?limit=100`);
    return current.items.find((item) =>
      item.peer_id === peerId && item.listen_port === 18080)?.id ?? "";
  }).not.toBe("");
  const services = await api(page, `/api/v1/meshes/${primaryMesh}/services?limit=100`);
  const service = services.items.find((item) =>
    item.peer_id === peerId && item.listen_port === 18080);
  const serviceId = service?.id;
  expect(serviceId).toBeTruthy();
  expect(service.alias).toBeNull();
  expect(service.protocols).toEqual(["tcp", "udp"]);
  await expect(page.locator("article.sharing-row").filter({hasText:editedPeerName}).filter({hasText:"18080"})).toBeVisible();

  await navigate(page, "Relays");
  await selectResource(page, relay.id);
  await page.getByLabel("New Noise public key").fill("11".repeat(32));
  await page.getByRole("button", { name: "Rotate credential" }).click();
  await expect.poll(async () => {
    const current = await api(page, `/api/v1/meshes/${primaryMesh}/relays/${relay.id}`);
    return current.credentials.pending?.serial ?? "";
  }).not.toBe("");
  const rotatedRelay = await api(page, `/api/v1/meshes/${primaryMesh}/relays/${relay.id}`);
  const stagedSerial = rotatedRelay.credentials.pending?.serial;
  expect(stagedSerial).toBeTruthy();
  await page.getByLabel("Credential serial").selectOption(stagedSerial);
  await page.getByLabel("Type the exact resource name").fill(relayName);
  await page.getByRole("button", { name: "Activate credential serial" }).click();
  await expect.poll(async () => {
    const current = await api(page, `/api/v1/meshes/${primaryMesh}/relays/${relay.id}`);
    return current.credentials.active?.serial ?? "";
  }).toBe(stagedSerial);

  await navigate(page, "Devices");
  await selectResource(page, peerId);
  await expect(page.getByRole("button", { name: "Rotate credential" })).toHaveCount(0);

  await navigate(page, "Policy");
  const policy = await api(page, `/api/v1/meshes/${primaryMesh}/policy`);
  await page.getByText('Advanced rule editing', { exact: true }).click();
  await page.getByLabel("Default action").selectOption("deny");
  const ruleId = crypto.randomUUID();
  await page.locator("summary").filter({ hasText: "Advanced JSON import/export" }).click();
  await page.getByLabel("Advanced JSON import/export", { exact: true }).fill(JSON.stringify([{
    id: ruleId,
    priority: 100,
    action: "allow",
    enabled: false,
    log: true,
    source: { peer_ids: [peerId], labels: { suite: "edited" }, cidrs: [] },
    destination: { peer_ids: [], labels: {}, cidrs: [] },
    protocol: "any",
    destination_ports: [],
  }]));
  await page.getByRole("button", { name: "Save rules", exact: true }).click();
  await expect(page.locator('.policy-savebar')).toContainText('Rules saved');
  expect((await api(page, `/api/v1/meshes/${primaryMesh}/policy`)).revision).toBe(policy.revision + 1);
  await expect.poll(async () => (await api(page, `/api/v1/meshes/${primaryMesh}/policy`)).rules[0]?.id).toBe(ruleId);
  const replacedPolicy = await api(page, `/api/v1/meshes/${primaryMesh}/policy`);
  expect(replacedPolicy.rules[0].id).toBe(ruleId);
  expect(replacedPolicy.rules[0].source.peer_ids).toEqual([peerId]);
  expect(replacedPolicy.rules[0].protocol).toBe("any");

  await navigate(page, "Join tickets");
  await page.getByLabel("Ticket lifetime (seconds)").fill("300");
  await page.getByRole("button", { name: "Create", exact: true }).click();
  await expect(page.getByRole("heading", { name: "Join link — shown once" })).toBeVisible();
  await expect(page.getByLabel("Peerward join QR code")).toBeVisible();
  await expect(page.locator("pre.join-link")).toContainText("peerward://join?bundle=");
  await page.reload();
  await expect(page.getByRole("heading", { name: "Join link — shown once" })).toHaveCount(0);

  await navigate(page, "Meshes");
  await selectResource(page, "");
  await page.getByLabel("Advanced: manual configuration").check();
  await page.getByLabel("Name", { exact: true }).fill(meshName);
  const subnet = Number.parseInt(suffix.slice(-4), 36) % 250;
  await page.getByLabel("Address CIDR").fill(`10.219.${subnet}.0/24`);
  await page.getByLabel("Gateway address").fill(`10.219.${subnet}.1`);
  await page.getByLabel("DNS suffix").fill(`${suffix}.e2e.peerward`);
  await page.getByLabel("Mesh MTU").fill("1380");
  await page.getByLabel("Reserved addresses (comma-separated)").fill("");
  await page.getByLabel("Default policy").selectOption("deny");
  await page.getByLabel("Address quarantine (seconds)").fill("60");
  await page.getByLabel("Credential overlap (seconds)").fill("3600");
  await page.getByRole("button", { name: "Create", exact: true }).click();
  await expect(page.getByRole("row").filter({hasText:meshName})).toBeVisible();
  const updatedMeshes = await api(page, "/api/v1/meshes?limit=100");
  const isolatedMesh = updatedMeshes.items.find((mesh) => mesh.name === meshName)?.id;
  expect(isolatedMesh).toBeTruthy();
  await navigate(page, "Devices");
  await selectMesh(page, { id: isolatedMesh, name: meshName });
  await expect(page.getByText(editedPeerName, { exact: true })).toHaveCount(0);
  await selectMesh(page, primary);
  await expect(page.getByRole("cell", { name: editedPeerName, exact: true })).toBeVisible();

  await navigate(page, "Services");
  await selectResource(page, serviceId);
  await page.getByLabel("Type the exact resource name").fill(await page.getByLabel("Type the exact resource name").getAttribute("placeholder"));
  await page.getByRole("button", { name: "Disable or revoke selected" }).click();
  await expect.poll(async () => {
    const current = await api(page, `/api/v1/meshes/${primaryMesh}/services?limit=100`);
    return current.items.find((service) => service.id === serviceId)?.state;
  }).toBe("disabled");

  await navigate(page, "Relays");
  await selectResource(page, relay.id);
  await page.getByLabel("Credential serial").selectOption(stagedSerial);
  await page.getByLabel("Type the exact resource name").fill(relayName);
  await page.getByRole("button", { name: "Revoke credential serial" }).click();
  await expect.poll(async () => {
    const current = await api(page, `/api/v1/meshes/${primaryMesh}/relays/${relay.id}`);
    return current.credentials.active;
  }).toBeNull();
  await page.getByLabel("Type the exact resource name").fill(relayName);
  await page.getByRole("button", { name: "Disable or revoke selected" }).click();
  await expect.poll(async () => {
    const current = await api(page, `/api/v1/meshes/${primaryMesh}/relays?limit=100`);
    return current.items.find((item) => item.id === relay.id)?.administrative_state;
  }).toBe("disabled");

  await navigate(page, "Devices");
  await selectResource(page, peerId);
  await page.getByLabel("Type the exact resource name").fill(editedPeerName);
  await page.getByRole("button", { name: "Disable or revoke selected" }).click();
  await expect.poll(async () => {
    const current = await api(page, `/api/v1/meshes/${primaryMesh}/peers/${peerId}`);
    return current.administrative_state;
  }).toBe("disabled");
  await expect(page.getByRole("cell", { name: editedPeerName, exact: true })).toBeVisible();

  await navigate(page,"Audit");
  await expect(page.getByRole("table", { name: "Audit records visible to the current role" }))
    .toContainText("peer");

  if (oidcExpected) {
    const result = await page.evaluate(async () => {
      const session = await fetch("/auth/session").then((response) => response.json());
      const logout = await fetch("/auth/logout", {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "x-csrf-token": session.csrf_token,
        },
        body: "{}",
      });
      const after = await fetch("/auth/session");
      return { logout: logout.status, after: after.status };
    });
    expect(result).toEqual({ logout: 204, after: 401 });
  }
});
