# Development guide

Peerward is an independent implementation based on open standards. Follow
[`CLEAN_ROOM.md`](../CLEAN_ROOM.md), work only from the frozen specs and public
library documentation, and never copy project-specific code from another
implementation. Public descriptions use this phrasing rather than absolute
claims of originality.

Install Rust 1.95.0 with rustfmt/clippy, Git, Docker, and Python 3.11 or newer
(`tomllib` is used by the verification scripts). Java 17 and Android SDK 36 are
needed when working on mobile. The repository does not contain GitHub Actions
workflows; local execution is the maintained automation path. Validate the ordinary
Linux/Android target before a pull request:

```sh
scripts/run-local-gate.sh standard
```

Recorded gates, source-size checks and release tooling require a Git checkout.
A source archive can run the Cargo commands from the project README and
`python3 scripts/check-documentation.py`; these checks do not create a commit-bound
acceptance record. The documentation checker uses Git's tracked/non-ignored file
list in a checkout, or scans source directories while pruning known build,
test-output and installation-state directories in an archive. It checks local
inline Markdown link paths, not remote URLs or heading anchors.

Native workspace Clippy does not cover browser-only code. After installing
`wasm32-unknown-unknown`, check Console explicitly:

```sh
cargo clippy --locked -p peerward-console --no-default-features --features web \
  --target wasm32-unknown-unknown -- -D warnings
```

Building the browser assets additionally requires `wasm-bindgen-cli` 0.2.100;
use `apps/peerward-console/build-web.sh`. Android UI has its own browser entry in
`apps/peerward-android-ui`; Console SSR and Android native tests do not execute
that interface.

The core verifier checks local documentation paths, release metadata and
bootstrap identity-preservation regressions. It uses a fresh temporary Cargo target for Clippy so stale
compiler diagnostics cannot be mistaken for a result. It records tool versions
in the log and then runs the locked tests against the normal build cache.
`scripts/verify.sh postgres` requires `PEERWARD_TEST_DATABASE_URL` when invoked
directly. `scripts/verify.sh all` and the recorded `standard` target instead
start a disposable digest-pinned PostgreSQL 18 container when the URL is
absent, wait for readiness, run every database target, and remove only that
uniquely named container. The `supply-chain` mode runs the locked dependency
audit and is included by `all`. The deployment mode validates the same-host and cloud/local Compose configurations
in a temporary installation, then checks repository release artifacts. It does
not start containers or require Kubernetes tooling.

`run-local-gate.sh` captures the exact commit, target arguments, dirty-worktree
flag, UTC bounds, tool versions, full output and output SHA-256 under ignored
`artifacts/`. It also fingerprints the complete version-controlled diff and
every non-ignored untracked file before and after execution. A changed
fingerprint invalidates the run instead of emitting a pass. Its JSON is
explicitly `release_gate_eligible: false`: it supplies a reviewable local
regression record, not an independent stable-release attestation.

The Android verifier builds Debug artifacts unconditionally. With the complete
`PEERWARD_ANDROID_KEYSTORE`, `PEERWARD_ANDROID_KEY_ALIAS`,
`PEERWARD_ANDROID_STORE_PASSWORD`, and `PEERWARD_ANDROID_KEY_PASSWORD` set, it
also builds Release APK/AAB, verifies their signatures, and checks that the APK
contains only the Release native outputs. `scripts/local-ci.sh standard`
creates a one-day throwaway verification key when no signing environment is
provided; those outputs are not accepted as stable release evidence.
`scripts/release-local.sh artifacts` instead requires the protected product
keystore and a clean committed worktree.

The sole cryptographic audit exception is transitive through `openidconnect`: Peerward
uses `rsa` only for Provider public-key JWT verification, while
RUSTSEC-2023-0071 requires observable RSA private-key operations and currently
has no fixed release. `cargo-deny` checks the complete supported graph.
`cargo-audit` scans the complete lockfile and compares every
finding against `scripts/allowed-rustsec.txt` before applying exceptions. A new
finding and an exception that no longer matches both fail local verification. Remove the RSA
entry as soon as the dependency graph has a patched version.

The MPL-2.0 exceptions are scoped to `attohttpc@0.30.1` (UPnP HTTP transport)
and `gotatun@0.9.2` (WireGuard session library with only the ring feature).
A version or dependency change requires review. GotaTun license and source
notices are retained in `third_party/gotatun` and included in distributions.
See [protocol](protocol.md) for the current integration and
[release evidence](release-evidence.md) for qualification boundaries.

`scripts/audit-dependencies.sh` also compares `cargo tree --duplicates` against
an exact, versioned inventory. `allowed-core-duplicates.txt` covers reviewed
OIDC/HTTP, SQLx, Android JNI, gateway-mapping, cryptographic, and proc-macro compatibility. Any
new, removed, or upgraded entry fails the audit until its cause and
consolidation options are reviewed.

Explicit PostgreSQL tests use an ephemeral database named `peerward_test` and
must not return early when its URL is missing. Privileged Linux coverage runs
`peerward-platform/tests/netns.rs` with `PEERWARD_RUN_PRIVILEGED=1`:

```sh
export PEERWARD_TEST_DATABASE_URL=postgres://postgres:peerward_test@127.0.0.1:5432/peerward_test
cargo test --locked -p peerward-store --features postgres-integration --test postgres
cargo test --locked -p peerward-store --features postgres-integration --test postgres_presence
cargo test --locked -p peerward-store --features postgres-integration --test postgres_provision
cargo test --locked -p peerward-store --features postgres-integration \
  --test postgres_scale -- --test-threads=1
cargo test --locked -p peerward-control --features postgres-integration --test join_postgres
cargo test --locked -p peerward-control --features postgres-integration --test controlled_join_postgres
cargo test --locked -p peerward-control --features postgres-integration --lib
cargo test --locked -p peerward-control --features postgres-integration --test oidc_postgres
cargo test --locked -p peerward-relay --features postgres-integration \
  --test postgres_network -- --test-threads=1
sudo env "PATH=$PATH" PEERWARD_RUN_PRIVILEGED=1 \
  cargo test --locked -p peerward-platform --features privileged-netns --test netns -- --nocapture
```

These targets use Cargo `required-features` instead of `#[ignore]`; the local
gate must compile and execute them in its provisioned environment. The PostgreSQL
tests parse SQLx connection options and require the actual database name to equal
`peerward_test`; this name in a username, password, query or database suffix is
insufficient. The
ordinary PostgreSQL test has 1,000 independent concurrent ticket claims and
1,000 competitors for one single-use ticket. The separate scale target creates
and atomically allocates 10,000 real PostgreSQL Peer rows and unique addresses.

The privileged target also launches separate standard WireGuard probe
processes across the namespace NAT. It proves encrypted direct traffic,
authenticated NAT return traffic, replay rejection, and authenticated endpoint
migration while netem is active. It is a mandatory deterministic gate; the
larger physical-NAT and full daemon matrix remains a release audit rather than
being inferred from this probe.

The `console-e2e` local target uses a separate Compose project and the test-only overlay at
`apps/peerward-console/e2e/compose.oidc.yaml`. Its local Provider validates the
authorization request, one-time code, confidential-client authentication,
redirect binding, and S256 verifier, and rotates its Ed25519 JWKS between
authorization and exchange. Playwright then checks the real Control/Console
proxy, Secure/HttpOnly/SameSite cookies, CSRF rejection and acceptance, every
resource workflow, SSE, and logout. The guarded entry creates the bootstrap
only when both state locations are absent, then allocates an isolated Compose
project and ports:

```sh
scripts/run-local-gate.sh console-e2e
```

The overlay removes the development bearer from Console. It does not alter the
default four-service Compose deployment (PostgreSQL, Control, Relay and Console) or its persistent volume.

Fuzz smoke (seed the ignored corpus from the reviewed repository inputs first):

```sh
python3 scripts/seed-fuzz-corpus.py
cargo +nightly fuzz run --sanitizer address credential_codecs -- -max_total_time=30 -timeout=2
cargo +nightly fuzz run --sanitizer address gateway_mapping_codecs -- -max_total_time=30 -timeout=2
cargo +nightly fuzz run --sanitizer address packet_and_directory -- -max_total_time=30 -timeout=2
cargo +nightly fuzz run --sanitizer address v2_documents -- -max_total_time=30 -timeout=2
cargo +nightly fuzz run --sanitizer address wire_reassembly_update -- -max_total_time=30 -timeout=2
cargo +nightly fuzz run --sanitizer address wireguard_and_stun -- -max_total_time=30 -timeout=2
cargo +nightly fuzz run --sanitizer address quic_fragments -- -max_total_time=30 -timeout=2
```

`scripts/run-local-gate.sh fuzz-smoke` executes 30 seconds per target by
default. The recorded long-running targets are
`scripts/run-local-gate.sh nightly fuzz|miri|coverage`.
`scripts/verify-nightly.sh all` runs all seven machine-local corpora for 600
seconds per target, Miri and LCOV; set a machine-local cron or systemd timer if
recurring execution is desired. Every corpus must be non-empty, and the runner
writes and logs sorted per-file SHA-256 manifests before and after fuzzing so
the ignored, evolving input set remains reviewable. Crash corpora remain under
the ignored fuzz artifact directory and LCOV is written under `artifacts/`.

Miri covers the pure types, policy, and dataplane crates. Address allocation is
verified against PostgreSQL, including the 10,000-Peer scale target. Coverage is
diagnostic: Peerward has no arbitrary
global percentage gate, while test and security scenario requirements remain
mandatory.

`scripts/run-local-gate.sh android-target 28` or `36` requires exactly one
already-running authorized target with the requested API, bootstraps an
isolated real Compose stack, uses ADB reverse for Control/Relay, issues a fresh
one-time Join link, and passes it as mandatory instrumentation input. It fails
instead of silently skipping a missing backend, link or wrong API. Run the two
API levels sequentially on separately provisioned emulators. Alternatively,
`scripts/run-local-gate.sh android-emulator API` creates and destroys a fresh
headless AVD around the same target.

Historical UI validation passed on the API 36 image with WebView 133 before
the WireGuard cutover; it does not qualify the current APK. The API 28 Play
Store image used in that run had WebView 69, which lacks the
secure message-listener bridge and cannot parse the current wasm-bindgen
`externref` output. That target is intentionally recorded as failed; do not
weaken the bridge to `addJavascriptInterface`, silently skip it, or call
`minSdk = 28` a passed API 28 runtime matrix. Use an API 28 target with an
updated supported WebView or produce and separately verify a legacy-compatible
UI bundle.

The former hosted job set is mapped as follows:

| Local command | Scope |
| --- | --- |
| `scripts/run-local-gate.sh standard` | SPEC/version/evidence, isolated Clippy, Rust tests, Console SSR, disposable PostgreSQL 18, Android Debug/Release packaging, supply chain and deployment manifests |
| `scripts/run-local-gate.sh privileged-network` | privileged Linux netns/NAT/netem/routing recovery; uses passwordless sudo when available, otherwise a digest-pinned Ubuntu 26.04 privileged container |
| `scripts/run-local-gate.sh console-e2e` | real OIDC/Control/Console Playwright suite |
| `scripts/run-local-gate.sh android-web` | Android embedded UI build, visual and accessibility checks |
| `scripts/run-local-gate.sh wcag-visual` | Console + Android automated axe/baseline checks and nine hashed screenshots; candidate remains unverified until independent keyboard/focus/manual review |
| `scripts/run-local-gate.sh android-target API` | one already-running API 28 or API 36 emulator/device against a real backend |
| `scripts/run-local-gate.sh android-emulator API` | fresh headless API 28 or 36 AVD around the same real-backend target |
| `scripts/run-local-gate.sh component-load` | production Noise component generator at 100/1,000/10,000 Peer tiers; never capacity evidence |
| `scripts/run-local-gate.sh deployment-runtime` | Compose smoke, Dockerfile build checks and systemd unit verification |
| `scripts/run-local-gate.sh nightly fuzz|miri|coverage` | recorded long fuzz, Miri or LCOV diagnostic |

`scripts/local-ci.sh full` combines host-runnable ordinary, netns, browser,
fuzz and deployment targets; hardware/API-specific Android targets remain
explicit so absence of a second emulator cannot be mistaken for a skip.

Keep unsafe Rust denied outside the reviewed Android JNI boundary, resource
bounds explicit, schemas strict, secrets redacted, persistent IDs typed UUIDv4,
and tests deterministic. `scripts/check-unsafe-boundary.py` pins the reviewed unsafe
blocks and JNI exports; do not broaden its inventory as a mechanical lint
fix. Do not change
or publish a stable-channel release until ordinary, database, privileged-network,
browser, supported API 28/36 Android runtime, packaging, physical-device, soak, and
clean-room validation gates all pass.

For shared WireGuard checkpoint regressions independent of WebView, run
`ANDROID_HOME=/path/to/sdk python3 scripts/test-android-checkpoint.py --serial emulator-NNNN`.
It builds the shared Rust core tests with NDK API 28, runs ten persistence/locking
regressions on the selected disposable 64-bit emulator, removes its temporary test
files and records the target binary digest. These adb-shell results complement,
but do not replace, app-sandbox JNI and complete real-backend acceptance.
For an authorized physical target, add `--allow-physical --serial SERIAL`; the
report records `physical: true` without collecting its serial or network addresses.

Physical APK tests use a separate app so their destructive test-profile cleanup
cannot remove a regular Peerward identity. Build from `apps/peerward-android` with
`./gradlew -PpeerwardValidation=true :app:assembleDebug :app:assembleDebugAndroidTest`.
This creates `io.github.peerward.peerward.validation` (label `Peerward Validation`)
and its test package; the JNI namespace and release application ID stay stable.
Then run `ANDROID_HOME=/path/to/sdk python3 scripts/test-android-wireguard.py
--serial SERIAL --allow-physical --validation-app --native-only` for 18 tests.
For the full 19-test gate, replace `--native-only` with `--lan-address HOST_WIFI_IPV4`.
It provisions temporary PostgreSQL/Control/Relay, forwards only enrollment over
ADB, and uses real Wi-Fi sockets for Relay/STUN. Wi-Fi must already be enabled,
airplane mode disabled and no other VPN active. The test briefly toggles Wi-Fi and
restores it, retains TUN/WireGuard ownership, then exercises staged rotation recovery.
Only temporary peer/STUN listeners bind the chosen LAN address; management remains
on loopback. APK manifests are checked before installation, and identical installed
APK digests avoid repeated OEM install prompts. OS installation/VPN confirmation
may require interaction. Add `--tun-peer` to the full physical gate to join a fresh
Linux peer in a separate Docker bridge container, with its own TUN and firewall.
The phone verifies twenty 1200-byte echoes before and twenty after Wi-Fi replacement
using the same application UDP socket. Linux packet counters and echo counts are
retained. This requires Docker and the full gate's LAN address; it does not modify
host routes or a deployed Mesh. Select `--relay-carrier quic` or `wss-connect`
to exercise those real carriers. `--network-attempts 100` records all trials and
the recovery p95. `--power-seconds 60` checks forced Doze and recovery with the
same TUN owner; it does not measure battery drain. `--restart-process` and
`--reboot-device` verify explicit foreground restoration from committed profile
and Keystore after process death or reboot; secure reboot requires a user unlock.
`--os-revoke` exercises OS-level VPN replacement. `--backend-only` runs just the
product scenario and explicitly leaves the native component gate unclaimed.
Every result records its APK digest, scope and failures. These tests do not
establish a physical NAT matrix, throughput, battery drain or 24-hour stability.

For production Linux TUN-to-TUN acceptance, run `python3 scripts/test-wireguard-product.py`.
It builds the real CLI, provisions a disposable PostgreSQL/Control/Relay/Root/Mesh,
and joins two production peers in namespaces inside a dedicated `--network none`
container. Privileged routing/firewall changes stay in that fixture. It tests large
packets without Relay forwarding, an MTU blackhole that preserves small probes,
direct/Relay transitions on one TCP connection, native IPv6, and 320 seconds of
Control/Relay-offline flow across observed WireGuard handshakes. Signed deny and
Mesh deletion must stop access and release TUN/DNS/firewall resources. Wire
observation counts public packet types and fragmentation, without retaining packet
payloads or candidate addresses. `--offline-seconds` accepts 320..3600. Every attempt,
including failures, stays under `artifacts/wireguard/product-tun/`; none is an
eligible release report or a substitute for the full NAT and performance matrix.

## Maintained test inputs

See the [script entry points](../scripts/README.md) and
[example inventory](../examples/README.md) before adding another launcher or
removing a fixture. Third-party license files under `third_party/` remain required
packaging inputs even though the dependency source is fetched through Cargo.

Reviewed [fuzz seeds](../fuzz/seeds/README.md), browser screenshot baselines and
webhook signature vectors are source inputs. Generated corpora, local reports,
installation data and build outputs are ignored; do not remove regression inputs
just because they are not production data. Packaged role configuration examples
are parsed by the CLI tests against the current schemas.

| Files | Maintenance rule |
| --- | --- |
| `fuzz/seeds/`, `*.spec.mjs-snapshots/`, `examples/webhooks/signature-vector.json` | Keep reviewed regression inputs; update alongside intentional behavior changes. |
| `test-results/`, `playwright-report/` (root or E2E directory) | Disposable browser output, including `.last-run.json`; excluded from version control and Docker builds. |
| `target/`, Android `build/`, `dist/`, `fuzz/corpus/`, `fuzz/artifacts/`, `artifacts/` | Generated outputs and local evidence; never present an old result as validation of new source. |
| `docs/analysis/` | Retained protocol migration context; historical results do not qualify current artifacts. |
| `apps/peerward-console/` | Current Console implementation and browser regression baselines; the retired standalone mock UI is not a build input. |
| `crates/peerward-store/migrations/`, `spec/legacy-0.2/` | Ordered schema inputs and frozen specifications; retain even when an earlier runtime generation is unsupported. |

The synthetic `ConsoleSnapshot::sample` and native `RawStaticDh` helper compile
only in Rust unit tests; production builds load authenticated state and use the
platform key provider. Documentation validation has its own regression command:

```sh
python3 scripts/test-documentation.py
python3 scripts/check-documentation.py
```

Maintenance boundary tests use only temporary files and loopback servers:

```sh
python3 scripts/test-compose-bootstrap.py
python3 -m unittest discover -s scripts/maintenance -p 'test_*.py'
```

The archive tests require `age` and `age-keygen` on PATH, or explicit
`PEERWARD_TEST_AGE` and `PEERWARD_TEST_AGE_KEYGEN` paths. The separate
`scripts/maintenance/test_installation.py` executable provisions a full disposable
installation; unittest discovery does not execute that integration scenario.
