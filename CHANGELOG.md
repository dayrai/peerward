# Changelog

## Unreleased

- Bound policy denial-audit throttle state, reclaim expired identities through
  a time index, and suppress new audit identities while the table is full.
- Preserve TCP SYN/SYN-ACK retransmissions in the stateful firewall and avoid
  overflowing flow and UDP association deadlines.
- Support IPv4 and IPv6 loopback UDP targets, retain live associations when
  queues fill, and cancel their workers when forwarding stops. Bound local
  management requests/responses and the complete client exchange.
- Index IP fragment expiry, check only neighboring intervals for overlap, and
  track payload coverage without scanning every stored fragment.
- Reuse Console SSR Control connections with per-request cookies; reject HTTP
  redirects in the native typed API client. Account for additional ephemeral
  port collisions in the concurrent DNS binding regression.
- Update both lockfiles to rustls 0.23.45 and require that patch or newer for
  [RUSTSEC-2026-0285](https://rustsec.org/advisories/RUSTSEC-2026-0285/).
- Remove the unused in-memory `peerward-ipam` crate and its standalone tests.
  Production allocation remains in PostgreSQL, with concurrent allocation,
  quarantine and pool-boundary regression coverage.
- Correct IPv6 allocation at the last pool address while retaining IPv4
  broadcast exclusion.
- Load Console topology for Issues and maintenance on initial load and refresh;
  remove the unused device-selection callback and duplicate topology loading.
- Validate the actual database name in all PostgreSQL test fixtures before
  connecting, and include the previously omitted presence regression in the
  database verifier. Update the migration inventory assertion to 52.
- Reject non-integer/out-of-range release metadata before synchronization.
  Build release archives in isolated temporary directories and publish complete
  files without overwriting existing artifacts; test reproducible output and
  failure cleanup.
- Allow detail-tab navigation during read-only loading while preserving submission
  and unsaved-draft guards. Keep advanced drawer editors from covering later controls.
  Match access-source deep links during hydration and restore readable issue tags
  in dark mode.
- Exclude local enrollment credentials from Docker build contexts. Refresh
  browser regressions for current drawers, tabs and explicit follow-up actions.

## 0.1.0 — 2026-09-21

Initial source baseline for the new local repository, on the `canary` channel.
It retains the implementation previously labelled `1.0.0-technical-preview.4`;
the new version series does not establish stable support or new runtime acceptance.

- Rust Control/PostgreSQL, shared Relay, Linux Peer, Android native core/UI,
  Dioxus Console and signed updater are included.
- Schema 4, Wire 5, `/api/v1`, Peer/Android profile format 4 and all 52 database
  migrations are retained. Android versionCode remains 4. The historical database
  `product_major = 1` marker is independent of product SemVer and is unchanged.
- Release metadata accepts a rollback floor below the candidate version, allowing
  compatible patch upgrades such as `0.1.0` to `0.1.1` with floor `0.1.0`.
  Anti-downgrade and schema/Wire checks remain enforced.
- Tests tied to the running software version read the actual build/release
  metadata. Generic version-ordering fixtures retain their explicit test values.
- The initial import includes code/test-data cleanup and documentation fixes;
  generated builds, installation state and local evidence are excluded from Git.
- Normative inputs are re-frozen for this baseline. The imported API specification
  previously differed from its recorded digest; adopting its current content as a
  new baseline does not retroactively validate the old lock or old test reports.

Use a separate fresh installation. The signed updater rejects a downgrade from
the previous `1.0.0-technical-preview.4` version series. Historical evidence retains
its original versions and hashes. Physical-device coverage, long-running soak,
capacity, independent reproducibility, accessibility review and external security
audit remain subject to the [release evidence gates](docs/release-evidence.md).

See [version management](docs/versioning.md) for subsequent local releases.
