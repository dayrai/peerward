import { legacySetup, openAdvancedTools } from "./legacy-setup.mjs";
legacySetup();
import { expect, test } from "@playwright/test";
import AxeBuilder from "@axe-core/playwright";
import { randomUUID } from "node:crypto";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";

// Requires the disposable console_review_fixture. It intentionally has no real
// Relay/client, so an application result must remain unknown throughout this test.
test.skip(process.env.PEERWARD_NETWORK_MANAGEMENT_E2E !== "1", "isolated fixture required");
test.use({ serviceWorkers: "block" });
const origin = process.env.PEERWARD_CONSOLE_E2E_URL ?? "http://127.0.0.1:29481";

test("Capacity remains unknown without samples and isolates selected host responses",async({page})=>{
  const hosts=(await(await page.request.get(`${origin}/api/v1/relay-hosts`)).json()).items;
  await page.goto(`${origin}/relays`);
  const panel=page.getByRole("region",{name:"Relay capacity and observation",exact:true});
  await expect(panel.getByRole("combobox",{name:"Select capacity host",exact:true})).toBeEnabled();
  for(const host of hosts.slice(0,2)){
    await panel.getByRole("combobox",{name:"Select capacity host",exact:true}).selectOption(host.id);
    await expect(panel.getByRole("button",{name:"Refresh capacity",exact:true})).toBeEnabled();
    await expect(panel.getByRole("status")).toContainText("Unknown or stale");
    const observed=await(await page.request.get(`${origin}/api/v1/relay-hosts/${host.id}/capacity`)).json();
    expect(observed.fresh).toBe(false);expect(observed.report).toBeNull();
    await expect(panel.getByText("Framed bytes read in this process",{exact:true})).toHaveCount(0);
  }
  expect((await new AxeBuilder({page}).include('[aria-label="Relay capacity and observation"]').analyze()).violations).toEqual([]);
});

test("Deployment runner registration keeps secrets one-time and blocks unobserved backups",async({page})=>{
  await page.goto(`${origin}/relays`);
  const panel=page.getByRole("region",{name:"Installation maintenance",exact:true});
  await panel.locator("summary").filter({hasText:"Register deployment runner"}).click();
  const name=`linux-backup-${randomUUID().slice(0,8)}`;
  await expect(panel.getByLabel("Runner name",{exact:true})).toBeEnabled();
  await panel.getByLabel("Runner name",{exact:true}).fill(name);
  await panel.getByLabel("Local profile digest",{exact:true}).fill("z".repeat(64));
  await panel.getByRole("button",{name:"Register deployment runner",exact:true}).click();
  await expect(panel.getByRole("alert")).toContainText("invalid_deployment_operation");
  await expect(panel.getByLabel("Runner name",{exact:true})).toHaveValue(name);
  await panel.getByLabel("Local profile digest",{exact:true}).fill("a".repeat(64));
  await panel.getByRole("button",{name:"Register deployment runner",exact:true}).click();
  const connection=JSON.parse(await panel.getByRole("textbox",{name:"One-time runner connection",exact:true}).inputValue());
  expect(connection.token).toMatch(/^pw_runner_[A-Za-z0-9_-]{44}$/);
  const runners=await(await page.request.get(`${origin}/api/v1/deployment-runners`)).json();
  expect(JSON.stringify(runners)).not.toContain(connection.token);
  expect(JSON.stringify(runners)).not.toContain("token_digest");
  await panel.getByRole("combobox",{name:"Installation runner",exact:true}).selectOption(connection.runner_id);
  await expect(panel.getByText("No current executable preview is available.",{exact:false})).toBeVisible();
  await expect(panel.getByRole("button",{name:"Start installation backup",exact:true})).toHaveCount(0);
  await panel.getByRole("button",{name:"Close credential",exact:true}).click();
  await expect(panel.getByRole("textbox",{name:"One-time runner connection",exact:true})).toHaveCount(0);
  await panel.getByRole("button",{name:"Review runner revocation",exact:true}).click();
  await expect(panel.getByRole("button",{name:"Confirm operation",exact:true})).toBeDisabled();
  await panel.getByRole("checkbox",{name:"I have reviewed this operation and its impact",exact:true}).check();
  await panel.getByRole("button",{name:"Confirm operation",exact:true}).click();
  await expect(panel.getByRole("button",{name:"Review runner revocation",exact:true})).toHaveCount(0);
  expect((await new AxeBuilder({page}).analyze()).violations).toEqual([]);
});

test("Native upgrade confirmation and reported outcome remain distinct from backup jobs",async({page})=>{
  const id=randomUUID(),profile="c".repeat(64),digest="d".repeat(64);
  const registered=await(await page.request.post(`${origin}/api/v1/deployment-runners`,{data:{id,name:`upgrade-${id.slice(0,8)}`,profile_digest:profile,ttl_seconds:3600}})).json();
  const preview={digest,services_to_pause:["relay"],online_files:1,meshes:0,relay_hosts:0,
    upgrade:{role:"relay",current_version:"1.0.0",version:"1.0.1",manifest_sha256:"e".repeat(64),artifact_sha256:"f".repeat(64),artifact_bytes:100,rollback_floor:"1.0.0",repair:false}};
  const exchange=(sequence,reports=[])=>page.request.post(`${origin}/api/v1/deployment-runners/${id}/exchange`,{
    headers:{authorization:`Bearer ${registered.token}`},data:{sequence,profile_digest:profile,preview,reports}});
  expect((await exchange(1)).status()).toBe(200);
  await page.goto(`${origin}/relays`);
  const panel=page.getByRole("region",{name:"Installation maintenance",exact:true});
  await expect(panel.getByRole("button",{name:"Refresh deployment tasks",exact:true})).toBeEnabled();
  await panel.getByRole("button",{name:"Refresh deployment tasks",exact:true}).click();
  await panel.getByRole("combobox",{name:"Installation runner",exact:true}).selectOption(id);
  const start=panel.getByRole("button",{name:"Start staged upgrade",exact:true});
  await expect(start).toBeDisabled();
  await expect(panel.getByText("This role will restart using the staged signed release.",{exact:false})).toBeVisible();
  await expect(panel.getByRole("button",{name:"Start installation backup",exact:true})).toHaveCount(0);
  await panel.getByRole("checkbox",{name:"I have reviewed this operation and its impact",exact:true}).check();
  await start.click();
  await expect(panel.getByRole("button",{name:"Refresh deployment tasks",exact:true})).toBeEnabled();
  const tasks=await(await page.request.get(`${origin}/api/v1/deployment-tasks`)).json();
  const task=tasks.items.find(item=>item.runner_id===id);
  expect(task.operation).toBe("native_upgrade");expect(task.status).toBe("queued");
  const assigned=await(await exchange(2)).json();expect(assigned.task.id).toBe(task.id);
  expect((await exchange(3,[{task_id:task.id,local_version:1,status:"recovery_required",stage:"native_recovery_required",error_code:"native_recovery_required",artifact:null}])).status()).toBe(200);
  await panel.getByRole("button",{name:"Refresh deployment tasks",exact:true}).click();
  await panel.getByRole("combobox",{name:"Installation runner",exact:true}).selectOption("");
  await panel.getByRole("button",{name:"Review native recovery",exact:true}).click();
  await expect(panel.getByRole("combobox",{name:"Installation runner",exact:true})).toHaveValue(id);
  await expect(panel.getByText("After fixing the local cause, resume this exact role transaction",{exact:false})).toBeVisible();
  const recoveryRequests=[];
  await page.route(`**/api/v1/deployment-tasks/${task.id}/recover`,async route=>{
    recoveryRequests.push({body:route.request().postDataJSON(),version:route.request().headers()["if-match"]});
    const response=await route.fetch();
    if(recoveryRequests.length===1)await route.abort("failed");
    else await route.fulfill({response});
  });
  await panel.getByRole("checkbox",{name:"I have reviewed this operation and its impact",exact:true}).check();
  const confirm=panel.getByRole("button",{name:"Confirm operation",exact:true});
  await confirm.click();
  await expect.poll(()=>recoveryRequests.length).toBe(1);
  await expect(panel.getByRole("alert")).toBeVisible();
  const acknowledgment=panel.getByRole("checkbox",{name:"I have reviewed this operation and its impact",exact:true});
  await expect(acknowledgment).not.toBeChecked();
  await acknowledgment.check();
  await expect(confirm).toBeEnabled();
  await confirm.click();
  await expect.poll(()=>recoveryRequests.length).toBe(2);
  expect(recoveryRequests[1]).toEqual(recoveryRequests[0]);
  await expect(panel.getByRole("button",{name:"Refresh deployment tasks",exact:true})).toBeEnabled();
  const recovering=await(await exchange(4)).json();
  expect(recovering.task.recovery_generation).toBe(1);
  expect(recovering.task.status).toBe("running");
  expect((await exchange(5,[{task_id:task.id,local_version:2,status:"succeeded",stage:"succeeded",error_code:null,
    artifact:{sha256:"f".repeat(64),bytes:100,files:1},upgrade:{role:"relay",version:"1.0.1",manifest_sha256:"e".repeat(64),
    current_sha256:"f".repeat(64),state:"succeeded",runtime_checked:true}}])).status()).toBe(200);
  await panel.getByRole("button",{name:"Refresh deployment tasks",exact:true}).click();
  await expect(panel.getByText("Upgrade completed; the runner checked the selected executable and readiness.",{exact:true})).toBeVisible();
  expect((await new AxeBuilder({page}).include('[aria-label="Installation maintenance"]').analyze()).violations).toEqual([]);
});

test("Maintenance uses named hosts, validates impact and blocks unconfirmed offline execution",async({page})=>{
  const mesh=(await(await page.request.get(`${origin}/api/v1/meshes`)).json()).items[0];
  const hosts=(await(await page.request.get(`${origin}/api/v1/relay-hosts`)).json()).items;
  const source=hosts.find(item=>item.name==="offline-maintenance-source");
  const replacement=hosts.find(item=>item.name==="offline-maintenance-replacement");
  await page.goto(`${origin}/relays?mesh=${mesh.id}`);
  const panel=page.getByRole("region",{name:"Relay maintenance",exact:true});
  await panel.getByRole("combobox",{name:"Host to maintain",exact:true}).selectOption(source.id);
  await panel.getByRole("combobox",{name:"Replacement host",exact:true}).selectOption(replacement.id);
  const preview=panel.getByRole("button",{name:"Check readiness and preview",exact:true});
  await panel.getByLabel("Grace period (seconds)",{exact:true}).fill("1");
  await expect(preview).toBeDisabled();
  await panel.getByLabel("Grace period (seconds)",{exact:true}).fill("15");
  await preview.click();
  await expect(panel.getByText("Host is disabled or its observation is stale.",{exact:false})).toBeVisible();
  await expect(panel.getByText("Replacement is not ready for every affected Mesh.",{exact:false})).toBeVisible();
  await panel.getByRole("checkbox",{name:"I reviewed the affected networks and connection impact.",exact:true}).check();
  await expect(panel.getByRole("button",{name:"Start maintenance task",exact:true})).toBeDisabled();
  await panel.getByRole("combobox",{name:"Operation",exact:true}).selectOption("relay_resume");
  await expect(panel.getByRole("button",{name:"Start maintenance task",exact:true})).toHaveCount(0);
  expect((await new AxeBuilder({page}).analyze()).violations).toEqual([]);
  expect((await(await page.request.get(`${origin}/api/v1/maintenance-tasks`)).json()).items).toEqual([]);
});

test("Webhook configuration stays disabled, preserves rejected drafts and deletes explicitly",async({page})=>{
  test.setTimeout(90_000);
  const mesh=(await(await page.request.get(`${origin}/api/v1/meshes`)).json()).items[0];
  await page.goto(`${origin}/webhooks?mesh=${mesh.id}`);
  const panel=page.locator("#webhooks-panel");
  const name=`notifications-${randomUUID().slice(0,8)}`;
  await expect(panel.getByLabel("Name",{exact:true})).toBeEnabled();
  await panel.getByLabel("Name",{exact:true}).fill(name);
  await panel.getByLabel("Receiver endpoint (HTTPS, port 443)",{exact:true}).fill("https://127.0.0.1/notify");
  await expect(panel.getByLabel("Enable external notifications",{exact:true})).not.toBeChecked();
  await panel.getByRole("button",{name:"Save",exact:true}).click();
  await expect(panel.getByRole("alert")).toContainText("webhook_endpoint");
  await expect(panel.getByLabel("Name",{exact:true})).toHaveValue(name);
  await panel.getByLabel("Receiver endpoint (HTTPS, port 443)",{exact:true}).fill("https://events.example.com/peerward");
  await panel.getByRole("button",{name:"Save",exact:true}).click();
  const card=panel.getByRole("article").filter({has:page.getByRole("heading",{name,exact:true})});
  await expect(card.getByText("Disabled",{exact:true})).toBeVisible();
  await card.getByRole("button",{name:"Deliveries",exact:true}).click();
  await expect(panel.getByText("No deliveries on this page.",{exact:true})).toBeVisible();
  await card.getByRole("button",{name:"Edit",exact:true}).click();
  await panel.getByLabel("Enable external notifications",{exact:true}).check();
  await expect(panel.getByRole("button",{name:"Save",exact:true})).toBeDisabled();
  // No notification is enabled and no request leaves the isolated fixture.
  await panel.getByLabel("Enable external notifications",{exact:true}).uncheck();
  await panel.getByRole("button",{name:"Save",exact:true}).click();
  await expect(panel.getByLabel("Name",{exact:true})).toHaveValue("");
  expect((await new AxeBuilder({page}).include("#webhooks-panel").withTags(["wcag2a","wcag2aa"]).analyze()).violations).toEqual([]);
  await card.getByRole("button",{name:"Delete",exact:true}).click();
  await expect(card.getByText("Deleting clears the delivery queue.",{exact:false})).toBeVisible();
  await card.getByRole("button",{name:"Confirm",exact:true}).click();
  await expect(card).toHaveCount(0);
});

test("Configuration import, atomic review, conflict and exact automation retry",async({page})=>{
  test.setTimeout(120_000);
  const mesh=(await(await page.request.get(`${origin}/api/v1/meshes`)).json()).items[1];
  const base=`${origin}/api/v1/meshes/${mesh.id}`;
  await page.goto(`${origin}/webhooks?mesh=${mesh.id}`);
  const panel=page.getByRole("region",{name:"Network configuration",exact:true});
  const editor=panel.getByRole("textbox",{name:"Configuration draft",exact:true});
  await expect(editor).not.toHaveValue("");
  const document=JSON.parse(await editor.inputValue());
  const id=randomUUID();
  document.resources.push({id,definition:{name:"Repository printer",target:{kind:"subnet",prefix:"192.168.246.50/32",site_id:randomUUID()}}});
  const file=test.info().outputPath("network.json");
  await writeFile(file,JSON.stringify(document));
  await panel.getByLabel("Import configuration JSON",{exact:true}).setInputFiles(file);
  await expect(editor).toHaveValue(JSON.stringify(document));
  await panel.getByRole("button",{name:"Preview configuration changes",exact:true}).click();
  await expect(panel.getByText("resources: created",{exact:false})).toBeVisible();
  expect((await page.request.get(`${base}/network-resources/${id}`)).status()).toBe(404);
  const apply=panel.getByRole("button",{name:"Apply reviewed configuration",exact:true});
  await expect(apply).toBeDisabled();
  await panel.getByRole("checkbox").check();await apply.click();
  await expect(panel.getByText("Configuration saved atomically.",{exact:false})).toBeVisible();
  expect((await page.request.get(`${base}/network-resources/${id}`)).status()).toBe(200);
  document.resources[0].definition.name="Retained conflicting draft";
  await editor.fill(JSON.stringify(document));
  await panel.getByRole("button",{name:"Preview configuration changes",exact:true}).click();
  await expect(panel.getByText("resources: updated",{exact:false})).toBeVisible();
  const row=await(await page.request.get(`${base}/network-resources/${id}`)).json();
  expect((await page.request.put(`${base}/network-resources/${id}`,{headers:{"if-match":`"${row.version}"`},data:{...row.definition,name:"Concurrent manual update"}})).status()).toBe(200);
  await panel.getByRole("checkbox").check();await apply.click();
  await expect(panel.getByRole("alert")).toContainText("version_conflict");
  await expect(editor).toHaveValue(JSON.stringify(document));
  await panel.getByRole("button",{name:"Load current version",exact:true}).click();
  await expect(panel.getByText("Current version loaded.",{exact:false})).toBeVisible();
  await panel.getByRole("button",{name:"Preview configuration changes",exact:true}).click();
  await expect(panel.getByText("resources: updated",{exact:false})).toBeVisible();
  await panel.getByRole("checkbox").check();await apply.click();
  await expect(panel.getByText("Configuration saved atomically.",{exact:false})).toBeVisible();
  expect((await(await page.request.get(`${base}/network-resources/${id}`)).json()).definition.name).toBe("Retained conflicting draft");
  expect((await new AxeBuilder({page}).analyze()).violations).toEqual([]);

  // Execute the actual repository client with a Mesh-scoped credential against
  // this isolated HTTP server. Tokens stay out of artifacts and subprocess args.
  const credentialId=randomUUID();
  const credential=await(await page.request.post(`${base}/machine-credentials`,{data:{id:credentialId,name:"GitOps fixture",capabilities:["resource_read","resource_write"],ttl_seconds:3600}})).json();
  const ownership=await(await page.request.get(`${base}/configuration/ownership`)).json();
  expect((await page.request.put(`${base}/configuration/ownership`,{headers:{"if-match":`"${ownership.version}"`},data:{owner_machine_id:credentialId}})).status()).toBe(200);
  const environment={...process.env,PEERWARD_CONTROL_URL:origin,PEERWARD_MESH_ID:mesh.id,PEERWARD_MACHINE_TOKEN:credential.token};
  const client=resolve("../../../scripts/peerward-config.py");
  const run=async(...args)=>JSON.parse((await promisify(execFile)("python3",[client,...args],{env:environment,timeout:30000})).stdout);
  const exported=test.info().outputPath("export.json"),review=test.info().outputPath("review.json");
  await run("export","--output",exported);
  const exportedDocument=JSON.parse(await readFile(exported,"utf8"));exportedDocument.resources[0].definition.name="Reviewed repository update";
  await writeFile(exported,JSON.stringify(exportedDocument));
  expect((await run("validate","--file",exported)).can_apply).toBe(true);
  const preview=await run("preview","--file",exported,"--output",review);
  expect(preview.changes.length).toBeGreaterThan(0);
  const committed=await run("apply","--file",exported,"--preview",review);
  expect(committed.applied).toBe(true);
  expect(await run("apply","--file",exported,"--preview",review)).toEqual(committed);
  expect(await readFile(review,"utf8")).not.toContain(credential.token);
  const latest=await(await page.request.get(`${base}/configuration/ownership`)).json();
  expect((await page.request.put(`${base}/configuration/ownership`,{headers:{"if-match":`"${latest.version}"`},data:{owner_machine_id:null}})).status()).toBe(200);
});

test("Automatic approval, manual withdrawal and explicit re-evaluation", async ({ page }) => {
  test.setTimeout(90_000);
  page.on("pageerror",error=>console.error(error.message));
  const mesh = (await (await page.request.get(`${origin}/api/v1/meshes`)).json()).items[0];
  const base = `${origin}/api/v1/meshes/${mesh.id}`;
  const peer = (await (await page.request.get(`${base}/peers`)).json()).items.find(value => value.name === "home-nas");
  const resource = randomUUID(), site = randomUUID(), binding = randomUUID(), group = randomUUID();
  const fixtures = [
    ["network-resources", { id: resource, definition: { name: "Auto LAN", target: { kind: "subnet", site_id: site, prefix: "192.168.99.50/32" } } }],
    ["collections", { id: group, definition: { name: "Office routers", kind: "devices", members: [peer.id], labels: {} } }],
    ["gateway-bindings", { id: binding, resource_id: resource, peer_id: peer.id, priority: 100 }],
  ];
  for (const [path, data] of fixtures) expect((await page.request.post(`${base}/${path}`, { data })).status()).toBe(201);
  await page.goto(`${origin}/services?mesh=${mesh.id}`);
  await openAdvancedTools(page);
  const automatic = page.getByRole("region", { name: "Automatic path approval", exact: true });
  await expect(automatic.getByRole("button", { name: "New automatic approval rule", exact: true })).toBeEnabled();
  await expect(automatic.getByLabel("Enable automatic approval", { exact: true })).not.toBeChecked();
  await automatic.getByLabel("Name", { exact: true }).fill("Office automatic rule");
  await automatic.getByRole("combobox", { name:"Controlled device collection", exact:true }).selectOption(group);
  await automatic.getByRole("combobox").last().selectOption(site);
  await automatic.getByLabel("Allowed prefixes (one CIDR per line)", { exact: true }).fill("192.168.99.0/24");
  await automatic.getByLabel("Enable automatic approval", { exact: true }).check();
  await automatic.getByRole("button", { name: "Save automatic approval rule", exact: true }).click();
  await expect(automatic.getByRole("button", { name: "Office automatic rule", exact: true })).toBeVisible();
  const bindingValue = async () => (await (await page.request.get(`${base}/gateway-bindings/${binding}`)).json());
  await expect.poll(async () => (await bindingValue()).approved).toBe(true);
  expect((await bindingValue()).approval_source.kind).toBe("automatic");
  const network = page.getByRole("region", { name: "Network resources", exact: true });
  await network.getByRole("button", { name: "Refresh list", exact: true }).click();
  await network.getByRole("button", { name: "Auto LAN", exact: true }).click();
  await network.getByRole("button", { name: "Withdraw approval", exact: true }).click();
  await expect.poll(async () => (await bindingValue()).approved).toBe(false);
  await automatic.getByRole("button", { name: "Save automatic approval rule", exact: true }).click();
  await expect(automatic.getByText("Saved. Distribution, device application and connectivity require separate confirmation.")).toBeVisible();
  expect((await bindingValue()).approved).toBe(false);
  await network.getByRole("button", { name: "Evaluate current automatic rules", exact: true }).click();
  await expect.poll(async () => (await bindingValue()).approved).toBe(true);
  await automatic.getByLabel("Allowed prefixes (one CIDR per line)", { exact: true }).fill("192.168.99.0/27");
  await automatic.getByRole("button", { name: "Save automatic approval rule", exact: true }).click();
  await expect.poll(async () => (await bindingValue()).approved).toBe(false);
  expect((await new AxeBuilder({ page }).include(".network-management").analyze()).violations).toEqual([]);
});

test("A delayed response cannot replace a newer visit to the same Mesh", async ({ page }) => {
  const meshes=(await (await page.request.get(`${origin}/api/v1/meshes`)).json()).items;
  expect(meshes.length).toBeGreaterThan(1);
  const [a,b]=meshes;
  const id=randomUUID();
  const body={id,definition:{name:"Current scope resource",target:{kind:"subnet",prefix:"192.168.98.50/32",site_id:randomUUID()}}};
  expect((await page.request.post(`${origin}/api/v1/meshes/${a.id}/network-resources`,{data:body})).status()).toBe(201);
  let release, held=false, served=false;
  const pending=new Promise(resolve=>{release=resolve;});
  await page.route(`**/api/v1/meshes/${a.id}/network-resources?**`,async route=>{
    const url=new URL(route.request().url());
    if(held || url.searchParams.get("limit")!=="50")return route.continue();
    const response=await route.fetch();
    const value=await response.json();
    value.items=value.items.map(item=>item.id===id?{...item,definition:{...item.definition,name:"STALE FIRST VISIT"}}:item);
    held=true;
    await pending;
    await route.fulfill({response,json:value});
    served=true;
  });
  try {
    await page.goto(`${origin}/services?mesh=${a.id}`);
    await openAdvancedTools(page);
    await expect.poll(()=>held).toBe(true);
    const selector=page.locator("#live-mesh-selection");
    await expect(selector).toBeEnabled();
    await selector.selectOption(b.id);
    await openAdvancedTools(page);
    await expect(selector).toBeEnabled();
    await selector.selectOption(a.id);
    await openAdvancedTools(page);
    const network=page.getByRole("region",{name:"Network resources",exact:true});
    await expect(network.getByRole("button",{name:"Current scope resource",exact:true})).toBeVisible();
    release();
    await expect.poll(()=>served).toBe(true);
    await network.getByLabel("Name",{exact:true}).fill("Draft after returning");
    await expect(network.getByRole("button",{name:"STALE FIRST VISIT",exact:true})).toHaveCount(0);
    await expect(network.getByRole("button",{name:"Current scope resource",exact:true})).toBeVisible();
    await expect(network.getByLabel("Name",{exact:true})).toHaveValue("Draft after returning");
  } finally { release(); }
});

test("Configuration ownership explicitly transfers to automation and back",async({page})=>{
  const mesh=(await(await page.request.get(`${origin}/api/v1/meshes`)).json()).items[0];
  const base=`${origin}/api/v1/meshes/${mesh.id}`;
  const id=randomUUID();
  expect((await page.request.post(`${base}/machine-credentials`,{data:{id,name:"Configuration repository",ttl_seconds:3600,capabilities:["resource_read","resource_write"]}})).status()).toBe(201);
  await page.goto(`${origin}/authorities?mesh=${mesh.id}`);
  const panel=page.getByRole("region",{name:"Configuration ownership",exact:true});
  const save=panel.getByRole("button",{name:"Transfer configuration ownership",exact:true});
  await expect(panel.getByRole("combobox",{name:"New owner",exact:true})).toBeEnabled();
  await expect(save).toBeDisabled();
  await panel.getByRole("combobox",{name:"New owner",exact:true}).selectOption(id);
  await panel.getByRole("checkbox").check();
  await save.click();
  await expect(panel.getByText("Current owner: Configuration repository",{exact:true})).toBeVisible();
  const resource={id:randomUUID(),definition:{name:"Ownership must reject this",target:{kind:"subnet",prefix:"192.168.242.50/32",site_id:randomUUID()}}};
  const blocked=await page.request.post(`${base}/network-resources`,{data:resource});
  expect(blocked.status()).toBe(409);
  expect((await blocked.json()).error.code).toBe("configuration_owned");
  await panel.getByRole("combobox",{name:"New owner",exact:true}).selectOption("");
  await panel.getByRole("checkbox").check();
  await save.click();
  await expect(panel.getByText("Current owner: Manual management",{exact:true})).toBeVisible();
  expect((await page.request.post(`${base}/network-resources`,{data:resource})).status()).toBe(201);
  expect((await new AxeBuilder({page}).include('section[aria-label="Configuration ownership"]').analyze()).violations).toEqual([]);
});

test("LAN target, approval, tested rules, withdrawal and scoped DNS", async ({ page }) => {
  test.setTimeout(120_000);
  const failures = [];
  let dnsReads = 0;
  page.on("request", request => { if (request.method() === "GET" && new URL(request.url()).pathname.endsWith("/dns-profiles")) dnsReads += 1; });
  page.on("pageerror", error => { failures.push(error.message); console.error(error.message); });
  const meshes = await (await page.request.get(`${origin}/api/v1/meshes`)).json();
  const mesh = meshes.items[0];
  const base = `${origin}/api/v1/meshes/${mesh.id}`;
  const peers = await (await page.request.get(`${base}/peers`)).json();
  const gateway = peers.items.find(peer => peer.name === "home-nas");
  const source = peers.items.find(peer => peer.name === "test-consumer");
  expect(source?.mesh_addresses.length).toBeGreaterThan(0);
  const name = `Printer ${randomUUID().slice(0, 8)}`;
  const initialPolicy = await (await page.request.get(`${base}/resource-policy`)).json();
  try {
  await page.goto(`${origin}/services?mesh=${mesh.id}`);
  await openAdvancedTools(page);
  await expect(page.locator('[data-browser-ready="true"]')).toBeVisible();
  const sharing = page.getByRole("region", { name: "Network resources", exact: true });
  await expect(sharing.getByRole("button", { name: "New resource", exact: true })).toBeEnabled();
  await sharing.getByLabel("Name", { exact: true }).fill(name);
  await sharing.getByLabel("IP address or CIDR", { exact: true }).fill("192.168.45.50");
  await sharing.getByText("Target service probe (optional)",{exact:true}).click();
  await sharing.getByLabel("Probe IP",{exact:true}).fill("192.168.46.50");
  await sharing.getByLabel("Probe TCP port",{exact:true}).fill("631");
  await expect(sharing.getByRole("button",{name:"Save target",exact:true})).toBeDisabled();
  await sharing.getByLabel("Probe IP",{exact:true}).fill("192.168.45.50");
  await sharing.getByRole("button", { name: "Save target", exact: true }).click();
  await expect(sharing.getByRole("button", { name, exact: true })).toBeVisible();
  await sharing.getByRole("combobox", { name: "2. Provider (Linux gateway)", exact: true }).selectOption(gateway.id);
  await sharing.getByRole("button", { name: "Register provider", exact: true }).click();
  await expect(sharing.getByText("Awaiting approval", { exact: true })).toBeVisible();
  await sharing.getByRole("button", { name: "Approve path", exact: true }).click();
  await expect(sharing.getByRole("button", { name: "Withdraw approval", exact: true })).toBeEnabled();
  await sharing.getByLabel("Priority (lower first)", { exact: true }).last().fill("50");
  await sharing.getByRole("button", { name: "Save priority", exact: true }).click();
  await expect(sharing.getByRole("button", { name: "Withdraw approval", exact: true })).toBeEnabled();
  const bindings = await (await page.request.get(`${base}/gateway-bindings`)).json();
  expect(bindings.items.some(binding => binding.peer_id === gateway.id && binding.priority === 50 && binding.approved)).toBe(true);
  await sharing.getByRole("button",{name:"Check target service",exact:true}).click();
  const health=sharing.getByRole("region",{name:"Target service probe (optional)",exact:true});
  await expect(health.getByText(/Unknown or expired observation/)).toBeVisible();
  await sharing.getByRole("button", { name: "View application results", exact: true }).click();
  await expect(sharing.getByText("Connectivity: unknown; verify from a client.")).toBeVisible();
  const targets = await (await page.request.get(`${base}/network-resources`)).json();
  const target = targets.items.find(resource => resource.definition.name === name);

  await sharing.getByRole("link", { name: "3. Set access rules", exact: true }).click();
  await openAdvancedTools(page);
  const rules = page.getByRole("region", { name: "LAN resource access rules", exact: true });
  const collections = page.getByRole("region", { name: "Device and resource collections", exact: true });
  await expect(collections.getByRole("button", { name: "Save collection", exact: true })).toBeDisabled();
  await collections.getByLabel("Name", { exact: true }).fill("Printing devices");
  await collections.getByLabel(source.name, { exact: true }).check();
  await collections.getByRole("button", { name: "Save collection", exact: true }).click();
  await expect(collections.getByRole("button", { name: "Printing devices", exact: true })).toBeVisible();
  await collections.getByRole("button", { name: "New collection", exact: true }).click();
  await collections.getByLabel("Name", { exact: true }).fill("Shared printers");
  await collections.getByRole("combobox", { name: "Collection kind", exact: true }).selectOption("resources");
  await collections.getByLabel(name, { exact: true }).check();
  await collections.getByRole("button", { name: "Save collection", exact: true }).click();
  await expect(collections.getByRole("button", { name: "Shared printers", exact: true })).toBeVisible();
  await rules.getByRole("button", { name: "Reload current version (keep draft)", exact: true }).click();
  const groups = await (await page.request.get(`${base}/collections`)).json();
  const deviceGroup = groups.items.find(item => item.definition.name === "Printing devices");
  const targetGroup = groups.items.find(item => item.definition.name === "Shared printers");
  await rules.getByRole("combobox", { name: "Source collection", exact: true }).selectOption(deviceGroup.id);
  await rules.getByRole("combobox", { name: "Target collection", exact: true }).selectOption(targetGroup.id);

  await rules.getByRole("combobox", { name: "Source device", exact: true }).selectOption(source.id);
  await rules.getByRole("combobox", { name: "Target resource", exact: true }).selectOption(target.id);
  await rules.getByLabel("Destination port or range", { exact: true }).fill("631");
  await rules.getByRole("button", { name: "Add to draft", exact: true }).click();
  await rules.getByLabel("IP address or CIDR", { exact: true }).fill("192.168.45.50");
  await rules.getByRole("combobox", { name: "2. Provider (Linux gateway)", exact: true }).selectOption(gateway.id);
  await rules.getByRole("button", { name: "Simulate draft", exact: true }).click();
  await expect(rules.getByText("Policy decision: allow. Connectivity still needs verification.")).toBeVisible();
  await rules.getByRole("button", { name: "Save test in draft", exact: true }).click();
  await rules.getByLabel("Destination port or range", { exact: true }).fill("80");
  await rules.getByLabel("Expect allow (uncheck for expected deny)", { exact: true }).uncheck();
  await rules.getByRole("button", { name: "Simulate draft", exact: true }).click();
  await expect(rules.getByText("Policy decision: deny. Inspect details for matching rules or path issues.")).toBeVisible();
  await rules.getByRole("button", { name: "Save test in draft", exact: true }).click();
  await rules.getByRole("button", { name: "Check tests and publication differences", exact: true }).click();
  const publish = rules.getByRole("button", { name: "Publish this draft", exact: true });
  await expect(publish).toBeEnabled();
  await publish.click();
  await expect(rules.getByText("Saved. Distribution, device application and connectivity require separate confirmation.")).toBeVisible();
  const published = await (await page.request.get(`${base}/resource-policy`)).json();
  expect(published.document.tests).toHaveLength(initialPolicy.document.tests.length + 2);
  expect(published.document.rules).toHaveLength(initialPolicy.document.rules.length + 1);
  for (const preserved of initialPolicy.document.rules) expect(published.document.rules).toContainEqual(preserved);
  expect(published.document.rules[0].source.peers).toEqual([]);
  expect(published.document.rules[0].resources).toEqual([]);
  expect(published.document.rules[0].source_collections).toEqual([deviceGroup.id]);
  await collections.getByRole("button", { name: "Printing devices", exact: true }).click();
  await collections.getByRole("button", { name: "Clear explicit members", exact: true }).click();
  await collections.getByRole("button", { name: "Save collection", exact: true }).click();
  await expect(collections.getByText("Saved. Distribution, device application and connectivity require separate confirmation.")).toBeVisible();
  await rules.getByLabel("Destination port or range", { exact: true }).fill("631");
  await rules.getByRole("button", { name: "Simulate draft", exact: true }).click();
  await expect(rules.getByText("Policy decision: deny. Inspect details for matching rules or path issues.")).toBeVisible();

  await rules.getByRole("listitem").filter({hasText:"Printing devices → Shared printers"}).getByRole("button", { name: "Remove from draft", exact: true }).click();
  await rules.getByRole("button", { name: "Check tests and publication differences", exact: true }).click();
  await expect(rules.getByText(/Failed tests: 1/)).toBeVisible();
  await expect(publish).toBeEnabled(); // A positive assertion must never block revocation.
  await publish.click();
  await expect(rules.getByText("Saved. Distribution, device application and connectivity require separate confirmation.")).toBeVisible();

  await page.goto(`${origin}/meshes?mesh=${mesh.id}`);
  await expect(page.locator('[data-browser-ready="true"]')).toBeVisible();
  const dns = page.getByRole("region", { name: "Network DNS settings", exact: true });
  try {
    await expect(dns.getByRole("button", { name: "Save DNS profile", exact: true })).toBeEnabled();
  } catch (error) {
    await test.info().attach("dns-failure.html", { body: await dns.evaluate(node => node.outerHTML), contentType: "text/html" });
    console.error(await dns.evaluate(node => node.outerHTML));
    throw error;
  }
  await dns.getByLabel("Internal fully qualified name", { exact: true }).fill("printer.office.test");
  await dns.getByLabel("IPv4, IPv6 or alias target", { exact: true }).fill("192.168.45.50");
  await dns.getByRole("button", { name: "Add internal record to draft", exact: true }).click();
  await dns.getByRole("combobox", { name: "Preview effective configuration for", exact: true }).selectOption(source.id);
  await dns.getByRole("button", { name: "Check conflicts and preview", exact: true }).click();
  await expect(dns.getByText("Merged effective configuration (not saved)", { exact: true })).toBeVisible();
  await dns.getByRole("button", { name: "Save DNS profile", exact: true }).click();
  await expect(dns.getByText("Saved. Distribution, device application and connectivity require separate confirmation.")).toBeVisible();
  const savedDns = await (await page.request.get(`${base}/dns-profiles/${mesh.id}`)).json();
  expect(savedDns.profile.records["printer.office.test"]).toEqual([{ type: "A", value: "192.168.45.50" }]);
  const accessibility = await new AxeBuilder({ page }).include(".network-management").analyze();
  expect(accessibility.violations).toEqual([]);
  await page.screenshot({ path: test.info().outputPath("network-dns-desktop.png"), fullPage: true });
  await page.setViewportSize({ width: 390, height: 844 });
  await page.screenshot({ path: test.info().outputPath("network-dns-mobile.png"), fullPage: true });
  expect(dnsReads).toBeLessThanOrEqual(3); // State updates must not restart the loading effect.
  expect(failures).toEqual([]);
  } finally {
    // This scenario deliberately retains a failing positive assertion after
    // revocation. Remove only its test assertions before another spec creates
    // resources in the shared disposable Mesh; keep the revoked policy intact.
    const current = await (await page.request.get(`${base}/resource-policy`)).json();
    const reset = await page.request.put(`${base}/resource-policy`, {
      headers: { 'If-Match': `"${current.version}"` },
      data: { ...current.document, tests: initialPolicy.document.tests },
    });
    expect(reset.ok(), await reset.text()).toBe(true);
  }
});

test("Internet target and scoped automation credential lifecycle", async ({ page }) => {
  test.setTimeout(90_000);
  const meshes = await (await page.request.get(`${origin}/api/v1/meshes`)).json();
  const mesh = meshes.items[0];
  await page.goto(`${origin}/services?mesh=${mesh.id}`);
  await openAdvancedTools(page);
  const network = page.getByRole("region", { name: "Network resources", exact: true });
  await expect(network.getByRole("button", { name: "New resource", exact: true })).toBeEnabled();
  await network.getByLabel("Name", { exact: true }).fill(`Exit ${randomUUID().slice(0,8)}`);
  await network.getByLabel("Sharing type", { exact: true }).selectOption("internet_dual");
  await expect(network.getByLabel("IP address or CIDR", { exact: true })).toHaveCount(0);
  await network.getByRole("button", { name: "Save target", exact: true }).click();
  await expect(network.getByRole("button", { name: "Register provider", exact: true })).toBeVisible();

  await page.goto(`${origin}/authorities?mesh=${mesh.id}`);
  const credentials = page.getByRole("region", { name: "Automation credentials", exact: true });
  const name = `automation-${randomUUID().slice(0,8)}`;
  await expect(credentials.getByLabel("Name", { exact: true })).toBeEnabled();
  await credentials.getByLabel("Name", { exact: true }).fill(name);
  await credentials.getByLabel("Capabilities", { exact: true }).selectOption("read");
  await credentials.getByLabel("Validity in days", { exact: true }).selectOption("86400");
  await credentials.getByRole("button", { name: "Create credential", exact: true }).click();
  await expect(credentials.getByLabel("Secret (select to copy)", { exact: true })).toHaveValue(/^pw_machine_[A-Za-z0-9_-]{44}$/);
  await credentials.getByRole("button", { name: "Saved; hide secret", exact: true }).click();
  await expect(credentials.getByLabel("Secret (select to copy)", { exact: true })).toHaveCount(0);
  const entry = credentials.getByRole("article").filter({ has: page.getByRole("heading", { name, exact: true }) });
  await entry.getByRole("button", { name: "Revoke credential", exact: true }).click();
  await expect(entry.getByText(/Subsequent requests will be rejected/)).toBeVisible();
  await entry.getByRole("button", { name: "Revoke credential", exact: true }).click();
  await expect(entry.getByText("Revoked", { exact: true })).toBeVisible();
  await page.reload();
  await expect(credentials.getByRole("heading", { name, exact: true })).toBeVisible();
  await expect(credentials.getByLabel("Secret (select to copy)", { exact: true })).toHaveCount(0);
  const accessibility = await new AxeBuilder({ page }).include('[aria-label="Automation credentials"]').withTags(["wcag2a","wcag2aa"]).analyze();
  expect(accessibility.violations).toEqual([]);
});


test("Device conditions validate, preserve conflicting drafts, and show missing evidence",async({page})=>{
  const mesh=(await(await page.request.get(`${origin}/api/v1/meshes`)).json()).items[0];
  const base=`${origin}/api/v1/meshes/${mesh.id}`;
  const peer=(await(await page.request.get(`${base}/peers`)).json()).items.find(item=>item.name==="home-nas");
  await page.goto(`${origin}/meshes?mesh=${mesh.id}`);
  const panel=page.getByRole("region",{name:"Device conditions",exact:true});
  const save=panel.getByRole("button",{name:"Save device conditions",exact:true});
  await expect(panel.getByLabel("Minimum software version (optional)",{exact:true})).toBeEnabled();
  await panel.getByLabel("Minimum software version (optional)",{exact:true}).fill("latest");
  await expect(panel.getByRole("alert")).toContainText("SemVer");
  await expect(save).toBeDisabled();
  await panel.getByLabel("Minimum software version (optional)",{exact:true}).fill("1.0.0-technical-preview.4");
  await panel.getByLabel("Enable device conditions",{exact:true}).check();
  await panel.getByLabel("I reviewed the impact:",{exact:false}).check();
  await expect(save).toBeEnabled();
  const current=await(await page.request.get(`${base}/device-conditions`)).json();
  expect((await page.request.put(`${base}/device-conditions`,{headers:{"if-match":`"${current.version}"`},data:current.definition})).status()).toBe(200);
  await save.click();await expect(panel.getByRole("alert")).toContainText("version_conflict");
  await expect(panel.getByLabel("Minimum software version (optional)",{exact:true})).toHaveValue("1.0.0-technical-preview.4");
  await panel.getByRole("button",{name:"Discard edits and reload",exact:true}).click();
  await expect(panel.getByLabel("Minimum software version (optional)",{exact:true})).toHaveValue("");
  await panel.getByLabel("Enable device conditions",{exact:true}).check();
  await panel.getByLabel("I reviewed the impact:",{exact:false}).check();
  await save.click();await expect(panel.getByRole("status")).toContainText("Saved");
  await panel.getByRole("combobox",{name:"Inspect device conditions",exact:true}).selectOption(peer.id);
  await panel.getByRole("button",{name:"Inspect device conditions",exact:true}).click();
  await expect(panel.getByText("Current evidence is unavailable:",{exact:false})).toBeVisible();
  expect((await new AxeBuilder({page}).analyze()).violations).toEqual([]);
  const final=await(await page.request.get(`${base}/device-conditions`)).json();
  expect((await page.request.put(`${base}/device-conditions`,{headers:{"if-match":`"${final.version}"`},data:{...final.definition,enabled:false}})).status()).toBe(200);
});
