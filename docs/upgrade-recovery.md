# Upgrade and recovery

## Before upgrade

1. Verify SHA-256, keyless signature/certificate, provenance, SBOM, and the
   expected repository/ref for every artifact or image.
2. Take and test a PostgreSQL backup plus encrypted external-secret backup.
3. Confirm current authority overlap and credential validity will cover the
   maintenance window.
4. Render Compose configuration or inspect package/systemd changes before applying.

Database migrations are forward-only. The newly started Control executes its
own migration set under the Store lock; an older updater must not run its old
migrations as if they belonged to a new artifact. Explicit `db migrate` remains
available for an operator-managed rollout. Do not scale a single relay identity
beyond one replica.

The current canary release uses Wire 5, Schema 4, and Peer/Android
configuration format 4. It is delivered for a new installation: run the complete
immutable migration chain on a new database. Existing installations are rejected
as incompatible; do not point this release at an old installation to migrate it
in place. Keep existing deployments and recovery material intact. Configuration
import carries management intent only and cannot restore identities or old
leases into a new installation. A successful build or restart does not establish
that the P0–P3 acceptance gates passed; consult the implementation evidence ledger.

The following describes the historical Relay topology/trace rollout within a
compatible Wire/storage generation, not a rollback path across Wire 5 / Schema 4. Apply migrations first, deploy Control in
read-compatible mode, then roll Relay and Peer binaries. Sparse topology remains
disabled automatically until every active Relay advertises the capability.
Within that compatible generation, rollback a mixed fleet by restoring its previous Relay/Peer binaries; Control publishes
full mesh without an outage. Do not remove the nullable trace columns or Relay
region/weight columns during rollback. Symmetric-NAT prediction remains an
explicit per-Peer canary setting.

Migration 8 keeps the legacy `relay_presence` uniqueness contract intact and
adds `relay_standby_presence_v1` plus the read-only `relay_presence_all` view.
This is intentional: old Relay processes can continue their original standby
upsert while upgraded Relays use independent per-Relay fences. Do not drop the
extension table or view during binary rollback. Old binaries safely ignore
them; rows expire through upgraded maintenance or may be removed only after no
upgraded Relay is running.

Before stopping a Linux Peer, keep
`/var/lib/peerward/network-state-v1.json`. On restart the Peer recovers owned
DNS/routes/firewall state before preparing new state. If recovery reports an
external edit, restore host networking manually and leave automatic takeover
disabled until the conflict is understood; never delete the journal merely to
silence the diagnostic.

## Signed updater

`peerward update check` fetches only HTTPS (or explicit local paths), verifies
the exact Ed25519 domain-separated manifest, selects one channel/platform/arch
binary, and prints its signed digest and size. `update apply` verifies the
download before same-directory replacement and keeps `.peerward.rollback`.
It never invokes `sudo`, a package manager, or an elevation prompt.

Prefer the system package manager for packaged installations. For an
owner-writable standalone binary:

```sh
peerward update apply \
  --manifest https://releases.example/release-manifest.json \
  --signature https://releases.example/release-manifest.sig \
  --public-key /etc/peerward/update.pub
peerward update rollback --install-path /opt/peerward/bin/peerward
```

Versions are strict canonical SemVer. A candidate lower than the running
selected role version is always rejected, including prerelease precedence; build metadata
does not create a downgrade exception. A repeated manifest sequence is accepted
only with the same canonical digest. Automatic apply never performs a
downgrade. `update rollback` is the sole downgrade path and restores only the
retained previous artifact. Versioned role rollback verifies the stored
compatibility metadata, artifact digest, current Wire/storage versions, and
rollback floor. Missing metadata or an old Wire generation is rejected; the
release floor is defined by `rollback_floor` in `release.toml`.
The legacy standalone `--install-path` operation restores its local rollback
copy without this versioned compatibility check. Do not use it to cross the
Wire 5 / Schema 4 boundary.

For the standalone operation, stop the affected service before replacement and
start it only after config validation. Versioned operations use the recorded
systemd role. Binary rollback does not restore a database or reconcile security
decisions made after a backup.

## Versioned Linux roles

These operations support Control, Relay and Peer. Console uses a separate
executable and assets; the unified binary cannot register or update it. This is
a local Linux operation that can also run through the restricted deployment runner
below. It does not perform a Compose image rollout.

First register the signed binary of a compatible new installation. Registration
verifies the exact manifest and installed bytes, stages an immutable version,
and generates a drop-in without changing systemd:

```sh
peerward update register \
  --manifest /srv/releases/release-manifest.json \
  --signature /srv/releases/release-manifest.sig \
  --public-key /etc/peerward/update.pub \
  --binary /usr/bin/peerward --installation-root /opt/peerward --role relay
```

Inspect `/opt/peerward/roles/relay/systemd.conf`. It retains the installed unit's
sandbox while selecting the versioned executable for config checking and startup.
The generated file assumes the repository's `/etc/peerward/<role>.toml` layout.
Then install the reviewed file and restart that role during its maintenance window:

```sh
install -d /etc/systemd/system/peerward-relay.service.d
install -m 0644 /opt/peerward/roles/relay/systemd.conf \
  /etc/systemd/system/peerward-relay.service.d/10-versioned.conf
systemctl daemon-reload
systemctl restart peerward-relay.service
```

Register all initial roles with the same signed release when sharing a root.
Each subsequent operation takes `update.lock`. A role must run its registered
executable before ordinary apply; a symlink alone is not readiness.

```sh
peerward update apply \
  --manifest /srv/releases/next/release-manifest.json \
  --signature /srv/releases/next/release-manifest.sig \
  --public-key /etc/peerward/update.pub \
  --installation-root /opt/peerward --role relay \
  --health-url http://127.0.0.1:9092/readyz
peerward update status --installation-root /opt/peerward --role relay
```

Use the role's configured readiness address, not an unrelated HTTP service.
For Peer use `--health-url unix:///run/peerward/peer.sock` (or its configured
management socket). The socket must belong to the systemd MainPID running the
selected artifact. A fixed `health` child runs as that daemon's UID with a cleared
environment; the same-UID local API restriction remains in force. Readiness needs
`status=ok`, TUN, supervised tasks and signed state. Control preflight requires
`PEERWARD_DATABASE_URL` in the operator's protected environment, or `--database-url`;
the URL is never copied into the update journal. Prefer the environment to avoid
placing database secrets in shell history or process arguments.

For offline delivery add `--artifact-file /srv/releases/next/peerward`; its length
and digest must still match the signed artifact. Missing or mismatched bytes do
not switch the role. Downloaded artifacts use HTTPS with redirects disabled.

Before approving a role change, use the same arguments with `update preview`.
This reads the existing registration under a shared lock without consuming the
release sequence. It prints the concrete target, retained transaction, health
location, process identity and `digest`. Pass that digest as `--preview-digest`
to `apply`; a changed process or transaction requires a new preview. The approved
digest is written with the first durable intent, so an interrupted task retains
its identity. Exact completed retries report the original result without restarting.

The private `roles/<role>/update-transaction.json` records target, retained version,
manifest, readiness location, direction and phase. Accepted-state format 2 persists
both the manifest sequence/digest and the strongest accepted rollback floor. This
new-installation format rejects an incomplete or older state file; deleting it is
not a migration or recovery procedure. Recovery rechecks installed bytes and
compatibility and does not need to download an expired manifest again.

| Status | Meaning and next action |
| --- | --- |
| `prepared` | Intent is durable; pointer reconciliation or restart may not have completed. Run `recover`. |
| `restart_pending` | Pointer changes are durable; startup/readiness has not been confirmed. Run `recover` after interruption. |
| `recovery_required` | Readiness or activation failed. Inspect service logs, repair the cause, then recover the recorded direction. |
| `succeeded` | The selected executable and configured readiness passed at completion time. |
| `rolled_back` | The recorded previous executable was restored and checked. Repeating rollback does not toggle links. |

`status` is read-only and reports `health=not_observed`; a past successful task is
not a live health observation. Restart is bounded to one minute and readiness to
30 seconds per attempt. The systemd job may continue after its invoking process
dies; the durable intent remains the authority for the next operation.

```sh
peerward update recover --installation-root /opt/peerward --role relay
peerward update rollback --installation-root /opt/peerward --role relay
```

Relay/Peer readiness failure attempts the precisely recorded compatible previous
version. If restoration fails or the accepted floor prevents it, the transaction
remains recovery-required. Control failure keeps the selected version and database
for forward recovery; versioned Control rollback is refused. A newer migration
unknown to an older Control returns `newer_schema_unsupported` at startup.

When the failed artifact itself needs replacement, use `update apply --repair`
with a newer signed release and the same versioned role arguments. It is accepted
only for `recovery_required`, requires a higher manifest sequence and a different,
non-decreasing version, and retains the last failed record in
`previous-update-transaction.json`. It cannot replace an in-progress transaction.
The local journal keeps current and last superseded failure, not an unlimited
deployment history; Console task integration remains separate work.

`deploy/systemd/update.toml` and its timer remain disabled by default. Its Peer
health location uses the protected Unix socket. Unattended retries do not implicitly
supersede a failed transaction; inspect `status` first.


## Console-triggered native maintenance

The deployment operator first enables the versioned systemd layout above, then
stages a particular release in a new private directory. A profile is bound to
one role and one release; subsequent releases use new profiles. Control also
requires `--database-url-file` pointing to an owned `0600` file. The database URL,
local paths and release bytes stay on this host.

```sh
install -d -m 0700 /srv/peerward/upgrade-next
python3 scripts/peerward-maintain.py register-upgrade \
  --installation-root /opt/peerward --role relay \
  --health-url http://127.0.0.1:9092/readyz \
  --program /usr/bin/peerward \
  --manifest /srv/releases/next/release-manifest.json \
  --signature /srv/releases/next/release-manifest.sig \
  --public-key /etc/peerward/update.pub \
  --artifact /srv/releases/next/peerward \
  --output /srv/peerward/upgrade-next/profile.json
```

This copies bounded local inputs into private files, pins their hashes, validates
the signed preview and prints the profile digest. It does not switch a service.
Use **Operations → Installation maintenance → Register deployment runner** with
that digest. Save its once-only connection information in an owned `0600` file,
set the actual Control origin and optional trusted `ca_file`, then run:

```sh
python3 scripts/peerward-maintain.py serve \
  --profile /srv/peerward/upgrade-next/profile.json \
  --connection /srv/peerward/upgrade-next/connection.json
```

In the Console, refresh and select this runner. Check the named role, current and
target versions, and restart impact; confirm **Start staged upgrade**. A missing
preview is not readiness. The API only sends the fixed operation and approved
digest. Credentials are limited to this runner's exchange endpoint and cannot
read or change ordinary resources. Inputs are rechecked before invocation.

If interrupted, keep both local task and updater journals. Heartbeats report the
unfinished state without repeatedly restarting. Fix the local cause, then select
**Review native recovery**, confirm the impact and submit. A fresh connected
runner is required, but a new release preview is not. The request ID and expected
task version make confirmation retries idempotent; a completed recovery generation
is not replayed. A local `peerward-maintain.py recover --profile ... --task ...`
can continue the same transaction while Control is unavailable.

For a faulty Control artifact, stage a newer signed release in a new profile with
`register-upgrade --repair`. Confirm its distinct repair preview. Only the matching
failed native task may be superseded; an active backup or unrelated role blocks
it. The old task remains unfinished until the replacement updater intent exists.
Its journal is retained, and the original runner reports `failed` / `superseded`
after reconciliation. Keep that runner available long enough to deliver its final
observation; missing reports are not fabricated. Installation operations remain
serialized locally even when multiple registered runners are connected.

The runner result includes the checked artifact and readiness outcome at execution
time. It does not prove present health, uninterrupted application sessions or
production cross-version compatibility. Native upgrade tasks never count as backups.
Console executable/assets and Compose image switching require their own workflows.


## Linux updater verification

For a repeatable RC rehearsal, run:

```sh
scripts/test-upgrade-rollback-rehearsal.sh
```

The wrapper builds the pinned netns base and isolated systemd image, builds the
current `peerward` CLI, and writes the updater fixture record under
`artifacts/upgrade-rollback/`. It is also included in
`scripts/run-release-candidate.sh full`. A successful record is intentionally
limited to updater/systemd transaction behavior; it is not permission to roll a
full installation across an incompatible Schema/Wire boundary.

`scripts/test-linux-updater.py` verifies real signatures, CLI registration/apply,
production systemd unit sandboxing, process identity, repeated rollback, SIGKILL,
Peer same-UID socket checks and Control forward recovery in an isolated container
with a private cgroup namespace. Build its test image with
`deploy/tests/updater-systemd.Dockerfile` after preparing `peerward-netns-test:ubuntu26`.
It uses synthetic role executables and an independent PostgreSQL instance; it does
not prove application migration compatibility, network continuity or a complete
product rollout. The script removes only its own containers and keeps a verification
record and journals in the requested output directory.

## Failed rollout

Freeze mutations, capture request IDs and logs, stop the new workload, and
determine whether schema/data changed. Restore the old binary/image only when
its schema is compatible and the corresponding workflow explicitly supports it.
Otherwise repair forward or verify PostgreSQL and external secrets together in
isolation. Restoring a snapshot does not recreate later revocations, ticket
consumption or trust floors. Do not reopen ingress merely because a restored
database starts; security reconciliation or a fresh trust domain is required.
Restored production activation is not implemented by the current isolated
restore verifier; see [backup and restore](backup-restore.md).

Existing migration files remain immutable; add a new numbered migration for
schema changes. Rebuilding a designated development database is a separate
operation, not permission to rewrite applied migrations. The retained 0.2
protocol is not an upgrade or rollback target. `release.toml` is authoritative for product, Android,
Schema, Wire, and rollback floor; run
`scripts/sync-release-metadata.py --check` before packaging or recovery drills.
