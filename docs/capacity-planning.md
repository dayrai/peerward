# Capacity evidence

Peerward does not publish inferred capacity guarantees. The 100, 1,000, and
10,000 Peer tiers are **unverified** until a signed report for the exact
release commit and artifact digest is accepted by `release-evidence.json`.

Each run must use real Noise sessions and cover connection establishment,
steady forwarding, reconnect storms, loss of one Relay, and PostgreSQL
failure/recovery. Record fixed hardware and kernel versions, Peerward version
and commit, duration and traffic distribution, p50/p95/p99 latency, successful
and failed throughput, CPU/RAM, Relay ingress/egress bandwidth, PostgreSQL
TPS/WAL, and observed recovery time. Synthetic cryptographic or socket stubs
cannot be reported as a validated tier.

The repository includes a bounded component generator that uses the production
Noise IK and encrypted record implementations:

```sh
cargo run --release --locked -p peerward-load -- \
  --peers 1000 --messages-per-peer 100 --reconnect-rounds 1 \
  --hardware "describe the fixed generator host" \
  --traffic-model "uniform 1200-byte component traffic" \
  --output noise-component.json
```

Run all three component tiers with a local, worktree-bound record using:

```sh
scripts/run-local-gate.sh component-load
```

Its report is always `status: unverified` and `scope: noise_component`. It is
for sizing load generators and catching crypto/framing regressions only; the
release validator deliberately rejects it as capacity evidence. A passed
capacity gate must match [`capacity-report.schema.json`](../release/capacity-report.schema.json),
declare `scope: end_to_end`, include every required deployed failure scenario
and metric, bind the exact release commit/artifact digest, and carry the cosign
bundle referenced by `release-evidence.json`.

Use a separate signed JSON report per tier. A report must say `unverified`
instead of supplying a guarantee when any required scenario or measurement is
absent. Every report is UTF-8 JSON and contains an `evidence_binding` object
with the exact `commit_sha` and `artifact_set_sha256` from
`release-evidence.json`. The stable release validator checks that binding, the
report digest, and its cosign bundle.
Each passed gate also pins the exact certificate identity and OIDC issuer that
the validator supplies to `cosign verify-blob`; an unscoped keyless signature
is not accepted.

`scripts/run-linux-stability-lab.py` is the local repository adapter for an
independently provisioned two-Relay lab. The lab host must provide a driver
implementing the fixed
arguments and JSON result contract in
[`stability-driver.schema.json`](../release/stability-driver.schema.json). The
adapter rejects duplicate Relay identities, missing failure scenarios,
non-monotonic latency percentiles, incomplete metrics, a mismatched version or
a soak shorter than 86,400 seconds. The driver is invoked with exact `--mode`,
`--duration-seconds`, `--tier`, `--commit-sha`, `--artifact-set-sha256` and
`--output` arguments. Its result must repeat the requested mode/tier/binding,
declare `scope: end_to_end`, span the measured duration in UTC timestamps and
reference unique, non-symlink attachments by basename and SHA-256. The adapter
rejects a commit change while the lab is running and refuses to overwrite an
existing candidate or attachment. It always emits `status: unverified`;
independent review and cosign verification are separate release actions.

Example local invocations (the soak command rejects durations below 86,400
seconds):

```sh
scripts/run-linux-stability-lab.py capacity \
  --driver /opt/peerward/bin/stability-driver --duration-seconds 3600 \
  --tier 100 --artifact-set-sha256 "$ARTIFACT_SET_SHA256" \
  --output artifacts/evidence-capacity-candidate.json
scripts/run-linux-stability-lab.py soak \
  --driver /opt/peerward/bin/stability-driver --duration-seconds 86400 \
  --tier 100 --artifact-set-sha256 "$ARTIFACT_SET_SHA256" \
  --output artifacts/evidence-soak-candidate.json
```

The vendor-neutral monthly model is:

```sh
python3 scripts/multiregion-cost.py deploy/cost-model.example.json
```

All price fields deliberately default to zero and must be filled from the
operator's current provider quote. The output separates Relay bandwidth,
cross-region bandwidth, and fixed application/Relay/PostgreSQL/ingress costs.
