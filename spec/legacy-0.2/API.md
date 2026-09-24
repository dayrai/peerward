# Peerward management and CLI contract

## HTTP

All JSON endpoints live under `/api/v1`.  Errors use:

```json
{"error":{"code":"stable_machine_code","message":"human description","request_id":"uuid"}}
```

List endpoints return `{"items":[],"next_cursor":null}` and accept `cursor`
plus `limit` from 1 through 500.  Mutations require CSRF protection for cookie
sessions and emit both audit and transactional event records.

Required routes:

- `GET /api/v1/live`, `/ready`, `/metrics`, `/status`
- `GET|POST /api/v1/meshes`
- `GET|PATCH /api/v1/meshes/{mesh_id}`
- `GET|POST /api/v1/meshes/{mesh_id}/authorities`
- `POST /api/v1/meshes/{mesh_id}/authorities/{authority_id}/activate`
- `DELETE /api/v1/meshes/{mesh_id}/authorities/{authority_id}`
- `GET|POST /api/v1/meshes/{mesh_id}/peers`
- `GET|PATCH|DELETE /api/v1/meshes/{mesh_id}/peers/{peer_id}`
- `GET /api/v1/meshes/{mesh_id}/peers/{peer_id}/credentials`
- `POST /api/v1/meshes/{mesh_id}/peers/{peer_id}/credentials/rotate`
- `POST|DELETE /api/v1/meshes/{mesh_id}/peers/{peer_id}/credentials/{credential_serial}`
- `GET|POST /api/v1/meshes/{mesh_id}/relays`
- `PATCH|DELETE /api/v1/meshes/{mesh_id}/relays/{relay_id}`
- `GET /api/v1/meshes/{mesh_id}/relays/{relay_id}/credentials`
- `POST /api/v1/meshes/{mesh_id}/relays/{relay_id}/credentials/rotate`
- `POST|DELETE /api/v1/meshes/{mesh_id}/relays/{relay_id}/credentials/{credential_serial}`
- `GET|POST /api/v1/meshes/{mesh_id}/join-tickets`
- `DELETE /api/v1/meshes/{mesh_id}/join-tickets/{ticket_id}`
- `POST /api/v1/join/{token}/claim`
- `GET|PUT /api/v1/meshes/{mesh_id}/policy`
- `GET|POST /api/v1/meshes/{mesh_id}/services`
- `DELETE /api/v1/meshes/{mesh_id}/services/{service_id}`
- `GET /api/v1/meshes/{mesh_id}/audit`
- `GET /api/v1/events` as SSE with `Last-Event-ID` replay
- `GET /api/v1/auth/login`, `GET /auth/callback`, `GET /auth/session`
- `POST /api/v1/auth/bootstrap`, `POST /auth/logout`

Read access requires viewer.  Normal peer, relay, service, and policy mutations
require operator.  Mesh creation, trust changes, bootstrap, revocation, and role
mapping require admin.

`GET /api/v1/auth/session` returns a typed authenticated-session document with
the stable actor identifier, effective role, and CSRF token.  The CSRF token is
present only for browser cookie sessions and must never be accepted from a URL.
Resource summaries expose a human-readable `name`; service responses may supply
their optional DNS alias through the `alias` field.

Relay create, patch, list, join, and signed-directory projections use
`peer_endpoints` and `backbone_endpoints`.  Each is a duplicate-free list of
one through sixteen canonical `tcp://host:port` endpoints.  Join responses use
a typed `relays` list whose entries bind one Relay ID, its peer endpoint list,
and its Noise public key; parallel ID and endpoint arrays are forbidden.
ASCII DNS and hexadecimal IPv6 input are case-normalized before duplicate
checking; responses and signed state always contain the canonical lowercase
form. Paths, credentials, queries, fragments, zero ports, and non-ASCII hosts
are rejected before a database transaction begins.

Policy selector documents contain `peer_ids`, `labels`, and `cidrs`.  Nonempty
dimensions are combined with AND, values inside one dimension with OR, and an
empty selector matches all peers.  Rule protocols are `any`, `tcp`, `udp`, and
`icmp`; rules also expose `enabled` and `log` booleans.

Service documents contain `protocols`, `listen_port`, optional `alias`, and
labels.  `protocols` is exactly `["tcp"]`, `["udp"]`, or the canonical
`["tcp","udp"]`.  Loopback target details exist only on the local Peer
management API and are never returned by Control.

All request and response documents are represented by shared typed DTOs.
Peer `online` is true only when the peer and owning relay are enabled and both
the relay runtime lease and peer presence lease are current.  Authority and
credential projections expose staged, active, overlap, and revoked lifecycle
without returning private keys or plaintext tokens.  Relay rotation accepts a
new public Noise key; the control service signs the staged credential with the
current active authority.

A join-ticket creation response returns its plaintext token exactly once.
Subsequent list and read responses expose only identifier, expiry, and consumed
state.  Console clients construct `peerward://join` links locally from that
one-time response.

## CLI

The binary is `peerward` and exposes:

```
peerward control run --config PATH
peerward relay run --config PATH
peerward peer run --config PATH
peerward db migrate --database-url URL
peerward identity root generate --private PATH --public PATH
peerward identity authority issue --root-private PATH --mesh-id UUID \
  --authority-public PATH --output PATH
peerward identity noise generate --private PATH --public PATH
peerward identity verify --root-public PATH --mesh-id UUID \
  --authority-certificate PATH [--credential PATH] \
  [--distribution-certificate PATH]
peerward join accept BUNDLE --output-dir PATH
peerward service publish --listen-port PORT --target 127.0.0.1:PORT \
  [--protocol tcp|udp|both] [--name NAME]
peerward service list
peerward service remove UUID
peerward config check --role control|relay|peer [--online] PATH
peerward doctor [--config PATH] [--json]
peerward health
```

Exit code 0 is success, 2 is invalid input/configuration, 3 is unavailable
dependency, 4 is authentication/authorization failure, and 1 is other failure.
Secret values are redacted from human and JSON diagnostics.

## Configuration

Every TOML document denies unknown fields and begins with
`schema_version = 1`.  Relative credential paths resolve from the config file
directory.  Private key files on Unix must not be group/world readable.

Defaults:

- control HTTP: `127.0.0.1:8080`
- relay peer TCP/UDP: `0.0.0.0:7777`
- relay backbone TCP: `0.0.0.0:7778`
- peer local management: Unix socket `/run/peerward/peer.sock`
- peer MTU: 1380
- keepalive: 10 seconds; unhealthy after 3 missed replies

Database URL comes from `PEERWARD_DATABASE_URL` when absent from the control or
relay document.  Key path overrides use explicit `PEERWARD_*_KEY_FILE`
variables.  The one-time bootstrap token is `PEERWARD_BOOTSTRAP_TOKEN`.

Control configuration supplies a per-mesh authority private-key directory.
The database active authority serial selects the only key permitted to sign new
credentials and state.  Online validation fails if the selected key, rooted
certificate, database record, and lifecycle do not agree.

Peer configuration accepts no more than eight static `p2p_endpoints` and eight
STUN servers.  The resulting advertised candidate set is deduplicated and
bounded to sixteen entries.

The optional updater document is `/etc/peerward/update.toml`.  It selects the
signed manifest, public key, stable or canary channel, installed role and
health timeout.  Automatic updates are disabled unless the corresponding
systemd timer is explicitly enabled.
