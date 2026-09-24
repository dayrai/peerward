# Configuration reference

Control accepts `config_version = 1` or `2`; generated installations use `2`.
Shared Relay hosts use `2`, while the single-Mesh Relay configuration uses `1`.
Linux Peer requires `config_version = 4`. These role-specific formats are
independent of Schema 4 and Wire 5. Put the version first; unknown fields are
rejected. Old Peer profiles must join again to obtain an independent
`wireguard_private_key_file`; copying a Noise key is not a migration. Validate before restart:

```sh
peerward config check --role control /etc/peerward/control.toml
peerward config check --role relay /etc/peerward/relay.toml
peerward config check --role peer /etc/peerward/peer.toml
```

All binaries accept the standard `RUST_LOG` environment variable and write
structured JSON tracing to standard error. This setting is operational and is
not part of the strict role TOML schema. Keep production at `info` unless a
bounded diagnostic window requires a more specific module filter.

## Control

`http_address` defaults to loopback `:8080`; set it explicitly behind a trusted
TLS ingress. The public listener never serves health or metrics.
`management_address` defaults to loopback `:9090` and serves `/livez`,
`/readyz`, and `/metrics` for private probes. `database_url` may be omitted when
`PEERWARD_DATABASE_URL` is set.
Optional `public_url` is the device-reachable HTTPS origin used for invitation claims.
It cannot contain user credentials, a path, a query, or a fragment; loopback HTTP is
accepted for development. Control returns the resulting `claim_url` when creating a
ticket. With this field absent, Console retains its local-origin development behavior.
See [public entry setup](public-entry.zh-CN.md) for the OIDC/HTTPS bootstrap flags.
`max_connections` bounds the PostgreSQL pool to 2–256 connections; at least two
are required so a revision snapshot can retain its cluster lock while the
signed projection is persisted. Optional `[oidc]` contains the
HTTPS issuer discovery URL, client ID, HTTPS redirect URI, scopes including
`openid`, group claim name, and deterministic `auditor_groups`,
`operator_groups`, and `admin_groups` mappings. Match precedence is admin,
operator, auditor, then viewer.
Authorization, token, and JWKS endpoints are accepted only from issuer
discovery.

Each `[[join_issuers]]` names one mesh UUIDv4, active database authority UUIDv4,
hex authority seed, hex root public key, base64url root authority certificate,
hex directory/service seeds, a hex X25519 audit-recipient private key, and
credential validity seconds. The Authority-signed Distribution Certificate
binds the derived audit public key alongside both update verifiers. This complete
document is a secret: mode 0600, never a ConfigMap, image layer, log, or backup
without encryption. Prefer a secret manager mounted read-only.

`stun_servers` is an optional list of at most eight DNS or IP-literal endpoints
with explicit nonzero ports (IPv6 is bracketed). It is returned in the authenticated join bundle so Linux
and Android peers can discover direct-path candidates without accepting an
untrusted runtime override.

Development bearer auth uses `PEERWARD_DEV_BEARER`; one-time bootstrap uses the
separate `PEERWARD_BOOTSTRAP_TOKEN`. Both are disabled from bearer use when
OIDC is configured. Production uses OIDC, HTTPS, secure cookies,
state/nonce/PKCE, and CSRF headers.

`[maintenance]` defaults to `interval_seconds = 60`, `batch_size = 1000`,
`event_retention_seconds = 86400`, `event_max_rows = 100000`,
`signed_state_versions = 2`, and `terminal_retention_seconds = 86400`.
Permitted ranges are 10–3600, 100–10000, 3600–604800, 10000–1000000, 1–10,
and 3600–604800 respectively. PostgreSQL advisory election means only one
Control instance cleans per pass; lowering an interval never removes more than
one configured batch from any table in that pass. Audit rows are excluded.

## Relay

The shared host uses `config_version = 2`, `host_id`, `control_url`,
`ca_file`, `certificate_file`, `private_key_file`, `state_directory`,
`health_address`, and PostgreSQL (the same environment fallback is accepted).
Control supplies authenticated Mesh assignments and independent Relay identities.
`peer_address` and `backbone_address` are distinct fixed TCP listeners;
`max_peer_sessions`, `max_mesh_contexts`, `max_pending_handshakes` and
`max_pending_handshakes_per_ip` bound shared resources. Host `/livez` and
`/readyz` use the private health listener. Private keys are owner-readable only.

Optional `[quic]` contains `address`, `certificate_file`, `private_key_file`
and `additional_address` for the other IP family. Optional `[wss]` contains
`address` and its separate TLS files; plaintext upgrade is allowed only on a
loopback reverse-proxy backend. Every listener serves all Meshes and both Peer
and backbone roles. UDP 443 QUIC and TCP 443 WSS can coexist. QUIC must not
conflict with STUN on the same family and port. Deployment examples and the
required paired Wire 5 update are in [QUIC](relay-quic.zh-CN.md) and
[WSS/CONNECT](relay-wss.zh-CN.md).

## Peer

A peer names mesh/peer UUIDv4, credential and private-key files, at least one
relay ID/address/public key, bounded queue/keepalive/failover values, protected
management socket, durable service state, optional STUN endpoints, and the
directory/policy distribution verifier, independent service distribution
verifier, and Authority-bound Control audit recipient.

Relay endpoint lists accept `quic://host:port`, `wss://host:port/peerward`
and advanced `tcp://host:port`. Default preference is QUIC, WSS, then TCP.
`relay_transport.ca_pem` optionally selects an explicit private CA trust store;
otherwise public WebPKI roots are used. `relay_transport.http_connect_proxy = "tcp://proxy:port"`
selects WSS through an explicit HTTP CONNECT proxy. These are local settings,
not candidate addresses or diagnostics sent to Control.

Linux `[linux]` adds interface, assigned IPv4 prefix, routes, DNS suffix/server,
non-looping upstream resolvers, `auto`, `systemd_resolved`, `network_manager`,
`openresolv`, or transactional `resolv_conf` DNS, MTU,
nft allow bootstrap rules, and flow-state limits/shards. Omit
`attached_tun_file` for standalone TUN creation; use it only for a deliberately
inherited test/service-manager descriptor.

`auto` probes usable resolved, a fully configured NetworkManager connection,
openresolv, then `/etc/resolv.conf`. `resolv_conf_path` can select a container-
specific file and `platform_state_file` defaults to
`/var/lib/peerward/network-state-v1.json`. The mode-0600 journal must be on
durable local storage. Startup recovers it before creating TUN state; an
external resolver edit is preserved and stops automatic takeover. The
systemd-resolved, NetworkManager, and direct `resolv.conf` backends all journal
their original and installed values before mutation and use compare-and-swap
rollback. Mesh routes are added with a Peerward-owned route protocol and fail
on an existing destination instead of replacing an operator route.

Platform-neutral P2P defaults are `nat_mapping = "auto"`,
`symmetric_nat_prediction = false`, and `relay_pool_size = 3`. Mapping tries
PCP, NAT-PMP, then UPnP against the existing direct UDP port. Prediction must be
explicitly enabled on a canary. A network-generation change withdraws and
recreates the old mapping rather than renewing it. PCP/NAT-PMP epoch regression
is treated as a gateway restart, and an expired lease is removed from the
published candidate set even when rediscovery fails. On Android, PCP/NAT-PMP
reuse the protected direct socket; every separate SSDP/UPnP HTTP socket is
protected and pinned to the selected underlay before I/O. `nat_mapping = "off"`
is persisted in the encrypted Android profile and suppresses all three probes.

`dns_backend` defaults to `auto` when omitted. The transitional spelling
`open_resolv` remains accepted, but new profiles use `openresolv`. Join profile
generation therefore works unchanged on hosts without D-Bus.

Canonical examples are in [`examples/config`](../examples/config). Replace
every UUID, address, endpoint, and key placeholder. The Relay example is for
a single Mesh; generate a complete shared-host installation with
`deploy/compose/bootstrap.sh` or `deploy/compose/install.py`. Generate Peer
identity files through `peerward peer join`; a TOML example alone does not
create credentials or the three independent private keys.

## Shared Relay STUN discovery

An installation-level Relay (`config_version = 2`) can run a public STUN Binding
service on a fixed pair of host sockets:

```toml
stun_addresses = ["0.0.0.0:3478", "[::]:3478"]
```

The default is an empty list (disabled). At most one address per IP family is
accepted. IPv6 sockets use `IPV6_V6ONLY`; both listeners may use the same port.
The sockets are independent of Mesh creation/deletion. Publish and permit the
chosen UDP port in the host firewall or container port configuration.

The service answers exact, attribute-free RFC 8489 Binding requests with an
IPv4 or IPv6 XOR-MAPPED-ADDRESS. It limits requests globally and per IPv4 address
or IPv6 /64, and bounds the client table. Observations produce candidates only;
they do not authenticate a Peer or demonstrate a working direct path.
