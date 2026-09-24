import { spawn } from "node:child_process";
import { mkdir, mkdtemp, rm, symlink } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { tmpdir } from "node:os";
import path from "node:path";

const here = path.dirname(fileURLToPath(import.meta.url));
const repository = path.resolve(here, "../../..");
const publicDirectory = path.join(
  repository, "target/dx/peerward-android-ui/release/web/public",
);
const temporary = await mkdtemp(path.join(tmpdir(), "peerward-android-web-"));
const assetDirectory = path.join(temporary, "assets");
await mkdir(assetDirectory);
await symlink(publicDirectory, path.join(assetDirectory, "dioxus"), "dir");
const port = process.env.PEERWARD_ANDROID_WEB_PORT ?? "28181";
const url = `http://127.0.0.1:${port}/assets/dioxus/`;
const server = spawn("python3", ["-m", "http.server", port, "--bind", "127.0.0.1"], {
  cwd: temporary,
  stdio: "inherit",
});

try {
  let ready = false;
  for (let attempt = 0; attempt < 100; attempt += 1) {
    try {
      if ((await fetch(url)).ok) {
        ready = true;
        break;
      }
    } catch (_) {
      if (server.exitCode !== null) throw new Error("Android Web test server exited");
    }
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  if (!ready) throw new Error(`Android Web test server did not become ready at ${url}`);
  const arguments_ = [
    path.join(here, "node_modules/@playwright/test/cli.js"),
    "test", "android-web.spec.mjs", "--reporter=line",
  ];
  if (process.env.PEERWARD_UPDATE_SNAPSHOTS === "1") arguments_.push("--update-snapshots");
  const playwright = spawn(process.execPath, arguments_, {
    cwd: here,
    env: { ...process.env, PEERWARD_ANDROID_WEB_E2E_URL: url },
    stdio: "inherit",
  });
  const code = await new Promise((resolve) => playwright.once("exit", resolve));
  if (code !== 0) process.exitCode = typeof code === "number" ? code : 1;
} finally {
  if (server.exitCode === null) server.kill("SIGINT");
  await new Promise((resolve) => {
    if (server.exitCode !== null) resolve();
    else server.once("exit", resolve);
  });
  await rm(temporary, { recursive: true, force: true });
}
