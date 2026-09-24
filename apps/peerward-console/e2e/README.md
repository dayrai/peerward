# Console browser regressions

Run the device details tests against an isolated database and API fixture. They
edit records; do not point them at a running installation. The fixture has no
Relay or signing worker, so it covers management UI/API behavior, not device
connectivity or the full Mesh lifecycle.

From the repository root, start an empty PostgreSQL 18 test database:

```sh
docker run --rm -d --name peerward-console-review-db \
  -e POSTGRES_PASSWORD=console-review-test \
  -e POSTGRES_DB=peerward_test \
  -p 127.0.0.1:29432:5432 postgres:18-alpine
docker exec peerward-console-review-db pg_isready -U postgres
```

Once the database is ready, start the fixture in its own terminal. It applies
migrations and creates a device with a real address allocation, Unicode display
name and location. The bearer below is only for this loopback test fixture.

```sh
PEERWARD_TEST_DATABASE_URL=postgres://postgres:console-review-test@127.0.0.1:29432/peerward_test \
  cargo run --locked -p peerward-control --example console_review_fixture
```

Build and run Console in another terminal. The web build requires the
`wasm32-unknown-unknown` Rust target and `wasm-bindgen-cli` version `0.2.100`.

```sh
./apps/peerward-console/build-web.sh
PEERWARD_CONTROL_URL=http://127.0.0.1:29480 \
PEERWARD_DEV_BEARER=console-review-test \
PEERWARD_CONSOLE_LISTEN=127.0.0.1:29481 \
PEERWARD_CONSOLE_ASSET_DIR="$PWD/apps/peerward-console/dist" \
  cargo run --locked -p peerward-console --bin peerward-console
```

Run the targeted tests in a third terminal:

```sh
cd apps/peerward-console/e2e
npm ci
npx playwright install --with-deps chromium
PEERWARD_CONSOLE_E2E_URL=http://127.0.0.1:29481 PEERWARD_DEVICE_DETAILS_E2E=1 \
  npx playwright test device-details.spec.mjs mesh-delete.spec.mjs \
  mesh-provisioning.spec.mjs peer-delete.spec.mjs --reporter=line
```

Device metadata edits use the real API and PostgreSQL. Lifecycle page tests
simulate task responses to cover completed history, pending cleanup, retries
and permissions. Screenshots of the Chinese desktop/mobile device page are
written under `test-results/`; these are test data, not deployment screenshots.

Stop the two local Rust processes with Ctrl+C, then remove only this fixture's
container and volume:

```sh
docker rm -f -v peerward-console-review-db
```

## Resource management workflow

Resource management tests are included in `scripts/test-console-v14.sh`.
Run it from the repository root after installing the
Rust WebAssembly target, matching `wasm-bindgen-cli`, and Playwright Chromium.
The script builds the UI/API, allocates loopback ports and a fresh PostgreSQL
container, runs resource approval, policy tests/publication/revocation and DNS
configuration, then stops only its own processes and container. Failure logs are
retained in the printed temporary directory. Screenshots remain in `test-results/`.
The assigned fixture devices do not run real tunnels; application and connectivity
status must stay unknown. This is not an enrollment or Android acceptance test.

## v14 guided console

Run `scripts/test-console-v14.sh` to build SSR and WASM, start a fresh PostgreSQL
fixture on random loopback ports, and run the guided flows plus the retained
advanced editor, event recovery, enrollment and device lifecycle regressions.
It also checks four visual/accessibility baselines, then starts a separate database
and real OIDC provider/Control/Console fixture to verify locking, session revocation
and return to the original page. All ports for this script are dynamically allocated.
An intentionally delayed WASM response verifies that top-bar actions remain
disabled until hydration and the first search click works after loading.
`guided-enrollment.spec.mjs` covers invitation-scoped approval, signed claims,
bearer completion, cancellation, failed-read recovery, approval success retained
after refresh failure, and issue deep links. The OIDC suite also logs in as a real
viewer and verifies both hidden mutation controls and Control's 403 responses.
The new flows use Chinese by default and cover English, themes, mobile, keyboard
access, device editing, all three sharing wizards, effective access, pause/resume,
grant revocation/restoration for all three resource kinds, service transport/address
conditions, group-search navigation, issue acknowledgement, target editing with gateway reapproval,
gateway priority/approval changes, and preserving conflicting drafts.
`prototype-pages.spec.mjs` additionally covers the network portfolio and creation
centered modal with a persisted unique identifier, versioned network settings, conflict reload, exact-name deletion with
pending progress, device-condition scope preservation, a matrix across devices,
current-page audit export, empty scope and all twelve pages on desktop and
mobile. Its executor transitions are explicitly mocked; the remaining settings,
matrix and audit queries use the fixture's real PostgreSQL API. The legacy suite
explicitly selects English and opens the current advanced-tool drawers for its existing checks.
Request-interception tests block service workers so their delayed responses are actually
observed. Keyboard coverage holds an access-matrix response while moving between
detail tabs: read-only loading must not block navigation, while submission still
prevents dismissal and repeated writes. Language and theme changes use the account menu.

For a targeted rerun, set `PEERWARD_CONSOLE_E2E_GREP` to a Playwright title pattern;
the default runs the entire suite. The independent OIDC lock test still runs.
By default the wrapper writes reproducible screenshots to `artifacts/console-v14/screenshots/`.
Set `PEERWARD_EVIDENCE_SCREENSHOT_DIR` to another artifact directory when needed.
For an intentional visual change, `PEERWARD_CONSOLE_UPDATE_SNAPSHOTS=1` updates the
four checked-in visual-test baselines; inspect those images before accepting them.
Generate fresh reports under `artifacts/`; historical run reports and the retired
static prototype are not distributed as regression inputs. Current implementation
scope and outstanding acceptance work are documented in
[the implementation status](../../../docs/status.zh-CN.md).
Device connectivity remains unknown in this management fixture. Signed credential
commands and actual Noise/TCP delivery have separate Rust runtime tests.

`python3 scripts/test-wireguard-product.py --management-network --output artifacts/console-real-network`
builds a disposable privileged network namespace fixture with real Linux TUN,
Control/Relay and PostgreSQL. It verifies console sharing creation and exact
retry, grant revocation/restoration and pause/resume by observing actual LAN
traffic. The surrounding suite also checks dual-stack LAN/exit forwarding, DNS,
gateway evidence, Relay maintenance, failover and recovery. It does not use the
existing installation or host network namespace; Internet targets are controlled
fixture endpoints, not public Internet or application-authentication proof.

For the real Linux TUN renewal chain, run
`python3 scripts/test-console-linux-renewal.py --output artifacts/console-linux-renewal-NEW`
from the repository root. It creates a temporary installation and PostgreSQL database,
starts a disposable Linux peer, requests renewal through Control, retries the same
request and waits for authenticated completion with a new credential.

`ANDROID_HOME=/path/to/android/sdk scripts/run-android-emulator.sh 36` runs Android
native platform tests and the isolated backend flow, including an administrative
renewal request. The host retains administrative credentials; instrumentation checks
the device's actual Keystore/profile update and healthy reconnection. The resulting
`console-renewal.json` contains only public identifiers and status. Emulator results
do not establish physical-device, Doze, long-running stability or TUN throughput.

For a connected physical Android device, the same flow can be initiated through
the actual browser console:

```sh
ANDROID_HOME=/path/to/android/sdk scripts/run-android-physical.sh \
  --serial DEVICE_SERIAL --lan-address HOST_LAN_IPV4 --console-ui --tun-peer \
  --power-seconds 60 --restart-process --os-revoke
```

`--console-ui` starts a separate SSR/WASM Console on a random loopback port and
uses `physical-renewal.mjs` to submit the request in the device drawer, replay the
exact request, observe trusted completion, and verify it after reloading. Reports
and before/completed screenshots contain public identifiers and UI state. The
admin credential stays in the host Console process. TUN echoes, Doze and process
recovery have separate assertions; completion of renewal alone does not prove them.

The full installation workflow remains
`python3 scripts/dynamic-mesh/console-e2e.py --output artifacts/console-install-NEW`.
It builds separately named images and a disposable Compose project, runs lifecycle
and real OIDC CRUD/visual tests, then removes only that project's containers/volumes.
Its OIDC runner uses dedicated ports 29000, 38080, 39090 and 39091; ensure they are
free before running. Do not substitute an existing installation environment.

## Release-candidate pass

After UI structure is frozen, prefer the repository-level wrapper instead of
assembling an ad-hoc list of browser commands:

```sh
scripts/run-release-candidate.sh console
```

It binds the core build/test run, this v14 Playwright suite and deployment
contract checks to one clean commit and stores logs under
`artifacts/release-candidate/`. The generated summary is explicitly local and
not release-gate eligible. Use `full` only when the machine is prepared for the
complete local gate and disposable Linux updater rollback rehearsal. The manual
keyboard/focus/screen-reader follow-up remains required even when axe and the
automated keyboard tests pass; see
[`docs/release-candidate.zh-CN.md`](../../../docs/release-candidate.zh-CN.md).


`device-prototype.spec.mjs` 验证原型设备列表结构以及真实服务计数、IP / 标签搜索、导出、
设备详情 / 访问来源 / 添加设备跳转和手机可访问性；桌面截图使用 1920 × 1130，视觉基线由本目录的快照测试维护。
