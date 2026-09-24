import { spawn } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { startOidcProvider } from "./oidc-provider.mjs";

const here = path.dirname(fileURLToPath(import.meta.url));
const repository = path.resolve(here, "../../..");
const temporary = await mkdtemp(path.join(tmpdir(), "peerward-console-oidc-"));
const children = [];

function parseEnvironment(document) {
  return Object.fromEntries(document
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line && !line.startsWith("#"))
    .map((line) => {
      const separator = line.indexOf("=");
      if (separator < 1) throw new Error(`invalid .env line: ${line}`);
      return [line.slice(0, separator), line.slice(separator + 1)];
    }));
}

function terminate(child) {
  if (child.exitCode === null && child.signalCode === null) child.kill("SIGINT");
}

function spawnService(command, arguments_, environment) {
  const child = spawn(command, arguments_, {
    cwd: repository,
    env: environment,
    stdio: "inherit",
  });
  children.push(child);
  return child;
}

async function waitFor(url, child) {
  for (let attempt = 0; attempt < 240; attempt += 1) {
    if (child.exitCode !== null || child.signalCode !== null) {
      throw new Error(`service exited before ${url} became ready`);
    }
    try {
      const response = await fetch(url);
      if (response.ok) return;
    } catch (_) {
      // Compilation and startup may still be in progress.
    }
    await new Promise((resolve) => setTimeout(resolve, 500));
  }
  throw new Error(`service did not become ready at ${url}`);
}

let provider;
try {
  const environmentDocument = await readFile(process.env.PEERWARD_CONSOLE_E2E_ENV_FILE, "utf8");
  const composeEnvironment = parseEnvironment(environmentDocument);
  const state = composeEnvironment.PEERWARD_STATE;
  if (!state) throw new Error("An isolated installation environment is required");
  const database = new URL(composeEnvironment.PEERWARD_DATABASE_URL);
  database.hostname = "127.0.0.1";
  database.port = process.env.PEERWARD_OIDC_POSTGRES_PORT ?? "35432";

  const consoleUrl = new URL(process.env.PEERWARD_CONSOLE_E2E_URL ?? "http://127.0.0.1:38081/");
  const redirectUri = new URL("auth/callback", consoleUrl).toString();
  provider = await startOidcProvider(redirectUri);
  let control = await readFile(path.join(state, "control/control.toml"), "utf8");
  control = control
    .replace(/^database_url = .*$/m, `database_url = ${JSON.stringify(database.toString())}`)
    .replace(/^http_address = .*$/m, 'http_address = "0.0.0.0:38080"')
    .replace(/^management_address = .*$/m, 'management_address = "127.0.0.1:39090"');
  const dynamic = (await readFile(path.join(state, "control/dynamic.toml"), "utf8"))
    .replaceAll("/etc/peerward", path.join(state, "control"))
    .replaceAll("/var/lib/peerward/meshes", path.join(state, "control/meshes"))
    .replaceAll("/var/lib/peerward/recovery", path.join(state, "control/recovery"))
    .replace(/^host_address = .*$/m, 'host_address = "127.0.0.1:39091"');
  const dynamicPath = path.join(temporary, "dynamic.toml");
  await writeFile(dynamicPath, dynamic, { mode: 0o600 });
  control += `\n[oidc]\nissuer_url = "${provider.issuer}"\nclient_id = "${provider.clientId}"\nclient_secret = "${provider.clientSecret}"\nredirect_uri = "${provider.redirectUri}"\nscopes = "openid profile email"\ngroups_claim = "groups"\nauditor_groups = ["peerward-auditor"]\noperator_groups = ["peerward-operator"]\nadmin_groups = ["peerward-admin"]\n`;
  const configPath = path.join(temporary, "control.toml");
  await writeFile(configPath, control, { mode: 0o600 });

  const controlEnvironment = { ...process.env, PEERWARD_DATABASE_URL: database.toString(), PEERWARD_DYNAMIC_CONFIG: dynamicPath };
  delete controlEnvironment.PEERWARD_DEV_BEARER;
  delete controlEnvironment.PEERWARD_BOOTSTRAP_TOKEN;
  const controlProcess = spawnService(
    process.env.PEERWARD_TEST_BINARY ?? path.join(repository, "target/debug/peerward"),
    ["control", "run", "--config", configPath],
    controlEnvironment,
  );
  await waitFor("http://127.0.0.1:39090/livez", controlProcess);

  const playwrightEnvironment = {
    ...process.env,
    PEERWARD_CONSOLE_E2E_URL: consoleUrl.toString().replace(/\/$/, ""),
    PEERWARD_EXPECT_OIDC: "1",
    PEERWARD_OIDC_PROVIDER_URL: provider.issuer,
  };
  for (const specification of ["visual.spec.mjs", "console.spec.mjs"]) {
    const playwrightArguments = [
      path.join(here, "node_modules/@playwright/test/cli.js"),
      "test", specification,
      "--config", path.join(here, "playwright.config.mjs"), "--reporter=line",
    ];
    if (process.env.PEERWARD_UPDATE_SNAPSHOTS === "1") {
      playwrightArguments.push("--update-snapshots");
    }
    const playwright = spawnService(process.execPath, playwrightArguments, playwrightEnvironment);
    const exitCode = await new Promise((resolve) => playwright.once("exit", resolve));
    if (exitCode !== 0) {
      process.exitCode = typeof exitCode === "number" ? exitCode : 1;
      break;
    }
  }
} finally {
  for (const child of children.toReversed()) terminate(child);
  await Promise.all(children.map((child) => new Promise((resolve) => {
    if (child.exitCode !== null || child.signalCode !== null) resolve();
    else child.once("exit", resolve);
  })));
  if (provider) await provider.close();
  await rm(temporary, { recursive: true, force: true });
}
