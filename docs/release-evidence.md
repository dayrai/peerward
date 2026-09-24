# Release evidence

Peerward stable releases require all eight gates in
[`release-evidence.preview.json`](../release/release-evidence.preview.json).
Keeping a gate as `missing` is valid for a canary and is safer than attaching an
incomplete report. A test run, local script or unsigned candidate is
not release evidence.

Every passed report uses schema version 1 and contains its exact gate name,
status, UTC start/finish timestamps, environment, tool versions, artifact
digests, gate-specific results and an `evidence_binding` for the full commit
and canonical artifact-set SHA-256. The release manifest references the report
digest, cosign bundle, certificate identity and OIDC issuer. The validator
rejects reports with unknown/missing fields, a mismatched binding or a bundle
that does not verify on the stable channel.

Build and evidence assembly order is fixed:

1. Build all release artifacts.
2. Create a sorted `SHA256SUMS` inventory that excludes the evidence reports,
   bundles and the checksum's own signature files.
3. Hash that inventory to obtain `artifact_set_sha256`.
4. Bind each gate report to the commit and artifact-set digest, then sign the
   exact UTF-8 JSON bytes.
5. Stage only reports and bundles named by passed gates, validate the completed
   release evidence, and finally sign `SHA256SUMS`.

The two reproducible-build reports must name different builder and run
identities and contain identical target/name/digest inventories. Android
physical evidence requires device/API/security-patch data, two or more real
network profiles and all lifecycle/NAT scenarios. Soak evidence requires at
least two distinct Relay identities and 86,400 measured seconds. Clean-room,
WCAG/visual, capacity and external-audit reports have similarly mandatory,
machine-checked result fields. See
[`evidence-report.schema.json`](../release/evidence-report.schema.json) and
`scripts/validate-release-evidence.py`.

The repository intentionally has no GitHub Actions workflows. For a final local
release-candidate pass, `scripts/run-release-candidate.sh console` records the
core build/test result, guided Console/Playwright regression and deployment
contract checks for one clean commit. `scripts/run-release-candidate.sh full`
adds the full local gate and disposable updater rollback rehearsal. Both records
are explicitly `release_gate_eligible=false`; see
[`release-candidate.zh-CN.md`](release-candidate.zh-CN.md). They are diagnostic
inputs and never replace signed gate evidence.

Run ordinary
checks with `scripts/run-local-gate.sh`, Android physical observations with
`scripts/run-android-physical.sh --serial DEVICE --lan-address HOST_LAN_IPV4`, and Linux capacity/soak candidates with
`scripts/run-linux-stability-lab.py`. Physical observations retain `release_gate_eligible=false`; candidate reports remain
`unverified`. These are inputs to independent review, never automatic gate
closures. A stable release therefore needs independently retained/signed logs
and gate reports for the exact clean commit; a developer's local green record
alone is insufficient.

`scripts/run-local-gate.sh wcag-visual` emits nine hashed Console/Android
screenshots after automated axe and baseline checks, but leaves keyboard,
focus, manual review and gate eligibility as missing. Local records bind target
arguments plus the complete tracked/untracked worktree fingerprint and become
`invalidated` if that fingerprint changes during execution. Neither mechanism
turns a dirty-tree developer run into stable-release evidence.

Local artifact assembly is deliberately split at the artifact digest boundary:

```sh
export PEERWARD_RELEASE_SEQUENCE=1
export PEERWARD_ANDROID_KEYSTORE=/protected/peerward-release.p12
export PEERWARD_ANDROID_KEY_ALIAS=peerward
export PEERWARD_ANDROID_STORE_PASSWORD='read-from-a-secret-manager'
export PEERWARD_ANDROID_KEY_PASSWORD='read-from-a-secret-manager'
export PEERWARD_UPDATE_SIGNING_KEY_FILE=/protected/update-signing.key
scripts/release-local.sh artifacts dist
# Generate/review/sign evidence reports against the printed artifact_set_sha256.
scripts/release-local.sh finalize dist
```

For key-based checksum signing, set `PEERWARD_COSIGN_KEY`; the finalizer emits
the corresponding public key and a Sigstore bundle, then immediately verifies
that bundle. For keyless signing, also set
`PEERWARD_COSIGN_CERTIFICATE_IDENTITY` and
`PEERWARD_COSIGN_CERTIFICATE_OIDC_ISSUER` to the exact expected Fulcio identity
and issuer. Final validation fails if the bundled signature cannot be verified
against that explicit identity. The commands use the Cosign 3 bundle interface;
the current local baseline is Cosign 3.1.2.

The artifact stage requires a clean committed worktree and an empty output
directory, runs the ordinary local gate unless
`PEERWARD_SKIP_LOCAL_VERIFY=1` is explicitly set, builds both Linux targets,
native packages, Console web/chart and signed Android APK/AAB, writes the
updater manifest, SBOM, build metadata and normalized `SHA256SUMS`, then stops.
The finalize stage rechecks every digest, binds/stages only declared passed
evidence, validates all gates, and signs the checksum into
`SHA256SUMS.bundle` with `cosign`. Set
`PEERWARD_COSIGN_KEY` for key-based signing; without it cosign uses its
interactive keyless flow. `scripts/release-local.sh images dist` creates local
multi-platform OCI archives. None of these commands uploads an artifact,
creates a GitHub release or pushes an image.
