# Deployment

Peerward technical preview 4 uses storage compatibility 4 and Wire major 5. Pin versions or image
digests, verify release signatures, and test only schema-compatible rollback.
Use the assembly and gate rules in [release evidence](release-evidence.md);
never promote a candidate report merely because a local script completed.

## Minimum production topology

The smallest reference is deliberately **not HA**: one hardened application
node runs Control, Web Console, and the first Relay; PostgreSQL, OIDC, and TLS
ingress are external. Public HTTPS terminates at ingress, management listeners
remain isolated, and the offline Root is never mounted. A second Relay uses a
second host and a distinct identity.

Production PostgreSQL should use multi-availability-zone replication and PITR,
with target RPO at most 5 minutes and RTO at most 60 minutes. Run and retain a
restore drill quarterly. These are operational objectives; development Compose
does not provide HA.

Before first traffic and after material topology changes, run the fail-closed
preflight with every Relay config and secret explicitly listed:

```sh
scripts/deployment-preflight.py \
  --database-url "$PEERWARD_DATABASE_URL" \
  --oidc-issuer https://id.example.com/realms/peerward \
  --tls-url https://peerward.example.com/ \
  --relay-config /etc/peerward/relay.toml \
  --secret /etc/peerward/relay/tls.key \
  --management-listener 127.0.0.1:9090 \
  --relay-port 7777 --relay-port 7778 \
  --offline-root /media/peerward-root \
  --backup-evidence /var/lib/peerward/evidence/last-restore.json \
  --firewall-evidence /var/lib/peerward/evidence/firewall-review.json
```

Evidence and secret files must have no group/other permissions. Any failed
check blocks deployment. See [capacity planning](capacity-planning.md) and the
[multi-Relay runbook](relay-scale-out.md).

Peers on OpenWrt, Alpine, and minimal/container hosts do not require D-Bus.
Use the `openresolv` or guarded `resolv_conf` backend and follow the capability,
durable-journal, bind-mount, and rollback examples in
[embedded Linux deployment](embedded-linux.md).

## Containers

The exact images are:

- `ghcr.io/dayrai/peerward:0.1.0-control`
- `ghcr.io/dayrai/peerward:0.1.0-relay`
- `ghcr.io/dayrai/peerward:0.1.0-console`

They run as UID/GID 65532. Mount `/etc/peerward` and identity material
read-only, use tmpfs for `/run/peerward`, and provide only
`/var/lib/peerward` as writable state. Control/relay accept PostgreSQL through
`PEERWARD_DATABASE_URL`. Terminate public HTTPS outside the containers.
Set `RUST_LOG` only when the default structured `info` tracing is insufficient;
container log rotation and retention remain the operator's responsibility.
The OCI labels `io.peerward.image.role` and
`org.opencontainers.image.ref.name` must match the selected role and release
ref. Compose uses the `control` target for migrate/Control and the
`relay` target only for Relay; the smoke test inspects the running containers'
labels rather than trusting service names.

The root [`compose.yaml`](../compose.yaml) starts four fixed services:
`postgres:18-alpine`, Control, a shared Relay host, and Console. The optional
`maintenance` profile provides an installation/upgrade migration command;
Mesh creation and deletion never start containers. PostgreSQL
uses a named volume mounted at `/var/lib/postgresql`, matching the PostgreSQL 18
image layout. The database network is internal. For local development,
PostgreSQL is also bound to host loopback on port 5432 so migration tools and
IDE clients can connect without exposing it on a LAN. Never replace the
`127.0.0.1` bind with a public address. Each container receives only its
required environment variables: Console never receives database or bootstrap
credentials, and Relay never receives Control admin credentials.

For a new development installation:

```sh
./deploy/compose/bootstrap.sh 203.0.113.10  # omit the address for loopback only
docker compose up -d --build --wait
docker compose ps -a
```

Bootstrap creates the default state only when both `.env` and
`deploy/compose/state/` are absent; subsequent runs validate and reuse the installation
referenced by root `.env`'s `PEERWARD_STATE`, preserving project and port overrides.
Use `./deploy/compose/bootstrap.sh --state-dir PATH` to explicitly select another
installation (or create an empty one at a new path). Selection backs up the previous
root `.env` under `artifacts/bootstrap/` before replacing it. Existing non-default
installations must record their actual `COMPOSE_PROJECT_NAME` in their `.env` so selection
keeps the same database volume; new non-default installations get a separate project.
Legacy or incomplete state is never automatically regenerated, and an explicit address
that differs from an existing Relay endpoint is rejected. The offline recovery private key is never mounted into a
long-running container. Per-Mesh roots are transiently generated and encrypted by Control. The optional installation/upgrade `migrate` job must exit with status zero;
Control, Relay, Console, and PostgreSQL must report healthy. Host ports 28080
and 28081 can be changed through `PEERWARD_CONTROL_PORT` and
`PEERWARD_CONSOLE_PORT`; Relay ports use `PEERWARD_RELAY_PORT` and
`PEERWARD_BACKBONE_PORT`; the loopback PostgreSQL port uses
`PEERWARD_POSTGRES_PORT` and defaults to 5432.

`scripts/compose-smoke.sh` creates an isolated Compose project and temporary
PostgreSQL volume, builds and starts the full stack, checks live/ready endpoints,
reruns migrations, restarts PostgreSQL, and verifies persistence. Its guarded
project name prevents it from cleaning a normal development deployment.
Build/runtime helper images are pinned to digests. The operator supplies the
strictly monotonic positive `PEERWARD_RELEASE_SEQUENCE` to the local release
assembler; release review must reject reuse of a sequence with a different
artifact digest.

## systemd and native packages

For a joined Linux profile, the native package supplies the service account and unit:

```sh
sudo peerward peer install --profile ./peerward-device
sudo systemctl enable --now peerward-peer.service
sudo -u peerward peerward doctor --config /etc/peerward/peer.toml --json
```

Stop existing runtimes before installation. Configuration lives in `/etc/peerward/peer.toml`;
rotatable identity and checkpoints live in `/var/lib/peerward/peer`. Repeated installation
of the same device preserves the installed state. See [Linux service installation](peer-install.zh-CN.md)
for recovery and permissions, and [HTTPS/OIDC setup](public-entry.zh-CN.md) for device-reachable invitations.

deb/rpm/apk packages place configs in `/etc/peerward`, state in
`/var/lib/peerward`, runtime sockets in `/run/peerward`, and units in
`/usr/lib/systemd/system`. Keep example relay/peer configs disabled until their
unique identities exist. Enable only required roles:

```sh
systemctl enable --now peerward-control.service peerward-console.service
systemctl status peerward-control.service
```

The peer unit alone retains `CAP_NET_ADMIN` and `/dev/net/tun`; it also needs
`CAP_NET_BIND_SERVICE` for its managed DNS listener on port 53. Do not grant
those capabilities to control, relay, or console. The Relay unit retains only
`CAP_NET_BIND_SERVICE` so its non-root account can bind host-configured QUIC/WSS
listeners on UDP/TCP 443, including hosts with a privileged-port threshold of 1024.
Review `systemd-analyze security` after local overrides.

Dynamic Mesh installation and cloud/local templates: [deployment and recovery guide](cloud-local-deployment-plan.zh-CN.md). Mesh operations never invoke Docker.

## Compose reports an unhealthy Control after rebuilding

A successful image build does not imply that its database is compatible. Start with
`docker compose logs --tail=80 control`. If it reports `legacy_schema_unsupported`,
the selected installation belongs to an older Wire/storage generation. This release
rejects that database before applying migrations. Do not change its installation
marker or run `docker compose down -v` to bypass the check.

Create a separate installation and Compose project:

```sh
sh deploy/compose/bootstrap.sh 127.0.0.1 --state-dir "$PWD/deploy/compose/state-v4-local"
docker compose up -d --build --wait
```

Use a previously unused directory. Bootstrap backs up the previous root `.env`
under `artifacts/bootstrap/`, creates fresh identities, and derives a separate
Compose project name, so PostgreSQL uses a new named volume. Existing configuration,
keys and database volumes remain intact. If the old PostgreSQL container remains
running on port 5432, set `PEERWARD_POSTGRES_PORT` to an unused loopback port in the
new `.env` before starting; internal database traffic still uses port 5432. Likewise,
choose unused application ports or stop only the old application containers before
reusing their ports. An old installation can run only with its matching release.

New `installation.json` files record product, Schema and Wire versions. Repeated
bootstrap verifies the selected installation and refuses missing or incompatible
compatibility metadata without rewriting files. Control logs preserve a sanitized
error code and remediation message; database credentials are not printed.
