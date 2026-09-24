# Peerward

Peerward is an independent implementation based on open standards. It is a
self-hosted, identity-aware private mesh with a Rust control plane, encrypted
relay and direct transports, Linux and Android peers, and a Dioxus management
console.

The product direction is a private network for personal and family agents and
memory services: connect household devices and let agents access explicitly
authorized information. Household delegation and content-level authorization
are planned integrations, not capabilities claimed by the current preview.
See the [家庭智能体与记忆网络定位](docs/home-agent-network.zh-CN.md) and
[产品化路线图](docs/product-roadmap.zh-CN.md). External agent runtimes are covered
by the [Harness 与 claw-code 接入规划](docs/harness-integration.zh-CN.md);
compatibility remains unverified.

**Development migration in progress:** Linux and Android use the shared
WireGuard data runtime with the Wire 5 / Schema 4 credential contract. QUIC and
WSS are connected to the Relay pool and host/backbone paths. Full migration
acceptance and release remain incomplete; see the
[gap closure record](docs/analysis/wireguard-gap-closure.zh-CN.md) for results
bound to individual binaries and APKs, failures, and outstanding gates.

Peerward `0.1.0` is a clean-install technical preview with
Schema 4 and Wire major 5. Its updater channel is `canary`; it is not a stable
support declaration.
Current implementation entry points and outstanding acceptance work are in the
[implementation status](docs/status.zh-CN.md).
It deliberately rejects older databases and incompatible configuration, client state,
and Wire messages instead of attempting cross-generation migration or downgrade. Normative inputs
are frozen under [`spec/`](spec/) with digests in [`SPEC.lock`](SPEC.lock);
the unchanged 0.2 inputs are retained under [`spec/legacy-0.2`](spec/legacy-0.2/).
This local repository starts a new product version series at `0.1.0`, retaining
Schema 4 / Wire 5 and the existing migration chain. The former
`1.0.0-technical-preview.4` series is not an automatic downgrade path; use a
separate fresh installation. See [changelog](CHANGELOG.md) and
[version management](docs/versioning.md) for the new baseline and retained history.
Local Android Wi-Fi/Doze, Linux NAT models, and Console visual checks have
recorded results. Actual carrier/hardware NAT coverage, energy measurements,
the completed 24-hour multi-Relay soak, independent clean-room rebuild,
declared capacity runs, and an external security audit remain separate
stable-release gates.

Production guidance includes a non-HA minimum topology, fail-closed preflight,
multi-Relay expansion runbook, and vendor-neutral cost model. No
100/1,000/10,000 Peer tier is claimed without a signed real-Noise report.
The included `peerward-load` command is an explicitly unverified production-
Noise component generator; it cannot satisfy the end-to-end capacity gate.

## Components

- `peerward control run`: PostgreSQL-backed `/api/v1` control service.
- `peerward relay run`: shared QUIC/WSS/TCP ingress and backbone, retaining
  Noise IK/KK identity authentication around opaque WireGuard traffic.
- `peerward peer run`: Linux TUN, stateful policy, P2P/relay failover, split
  DNS, and protected local service forwarding.
- `peerward peer install --profile DIR`: install a joined Linux profile for the
  native service account; see [background installation](docs/peer-install.zh-CN.md).
- `peerward-console`: responsive SSR plus hydrated browser management UI.
- `apps/peerward-android`: thin Android `VpnService`/permission/Keystore bridge
  hosting the Rust + Dioxus 0.7.10 mobile application and shared Rust runtime.
- `peerward update`: signed release selection, verification, atomic install,
  and rollback without automatic privilege escalation.

See [architecture](docs/architecture.md), [protocol](docs/protocol.md), and
[threat model](docs/threat-model.md) for trust boundaries and wire behavior.

## Build and test

Rust 1.95.0, PostgreSQL 18, and the checked-in Rust 2024 workspace are the base
toolchain:

```sh
sha256sum --check SPEC.lock
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked --workspace --all-targets
cargo test --locked --workspace --doc
```

The browser has separate conditional code. After installing the
`wasm32-unknown-unknown` target, also check the Console browser build:

```sh
cargo clippy --locked -p peerward-console --no-default-features --features web \
  --target wasm32-unknown-unknown -- -D warnings
```

`scripts/verify.sh all` provisions a disposable PostgreSQL 18 container when
no explicit `peerward_test` URL is supplied. Privileged namespace, browser,
fuzz, Android target and deployment-runtime checks are explicit local targets.
The repository intentionally has no GitHub Actions workflows; developer setup,
recorded local gates and exact commands are in
[docs/development.md](docs/development.md).

## Run locally

Generate a fixed-host installation with TLS identities, recovery keys, configuration,
and `.env`, then start the complete PostgreSQL 18 stack. Repeated runs reuse the
installation referenced by the root `.env`:

```sh
./deploy/compose/bootstrap.sh
docker compose up -d --build --wait
```

The console binds to `127.0.0.1:28081`, Control to `127.0.0.1:28080`, and the
development PostgreSQL 18 service to `127.0.0.1:5432`; Relay uses ports
7777/7778. The bootstrap is idempotent and never overwrites an existing
identity. Back up the selected installation's `offline/` directory to offline storage.
For existing legacy files or a separate installation directory, see the
[local deployment guide](docs/local-linux-deployment.zh-CN.md).

## Deploy and operate

- Images share `ghcr.io/dayrai/peerward` and use immutable role-qualified
  tags such as `0.1.0-control`,
  `0.1.0-relay`, and
  `0.1.0-console` when those artifacts are published.
- Compose: [`compose.yaml`](compose.yaml) runs PostgreSQL, Control, Console,
  and one shared Relay. Start with the [Linux quickstart](docs/cloud-local-linux-quickstart.zh-CN.md):
  all four services on one server, Peers on household devices, no additional
  WireGuard tunnel. The [split deployment](docs/cloud-local-linux-split-deployment.zh-CN.md)
  is an advanced option for keeping Control and PostgreSQL at home.
- Linux packages: nfpm definitions produce deb, rpm, and apk packages with
  hardened systemd units and canonical `/etc/peerward`, `/var/lib/peerward`,
  and `/run/peerward` paths.
Start with [deployment](docs/deployment.md), then read
[configuration](docs/configuration.md), [observability](docs/observability.md),
and [backup/restore](docs/backup-restore.md). Upgrade and signed updater
procedures are in [upgrade and recovery](docs/upgrade-recovery.md).

## Security

Root keys remain offline. Online authority, directory, and service keys have
separate roles. Peers and relays authenticate fixed-transcript credentials;
exact serial revocation, ordered policy revisions, presence fencing, bounded
state, strict packet parsing, and transactional host rollback limit failure
impact. Report suspected compromise privately to repository maintainers and
follow [incident response](docs/incident-response.md).

Dependency, license, advisory, and source policies are enforced by
`cargo-deny` and `cargo-audit`; parser and packet fuzz targets run through the
local smoke/nightly entries. Release artifacts include SHA-256 checksums, SBOM,
local build metadata, a cosign signature, and a separately Ed25519-signed
updater manifest.

## Documentation

Start with the [documentation index](docs/README.md) for current guides, version
contracts, and the scope of historical validation records.

- [家庭智能体与记忆网络定位](docs/home-agent-network.zh-CN.md)
- [产品化路线图](docs/product-roadmap.zh-CN.md)
- [API usage](docs/api.md)
- [Web Console 操作指南](docs/web-console-guide.md)
- [Android client](docs/android.md)
- [Key rotation and revocation](docs/key-rotation.md)
- [Developer guide](docs/development.md)

Peerward is licensed under Apache-2.0. The pinned GotaTun dependency uses
MPL-2.0; its retained license is in [third_party/gotatun/LICENSE](third_party/gotatun/LICENSE).
