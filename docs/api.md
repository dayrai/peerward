# API usage

The normative route and envelope contract is [`spec/API.md`](../spec/API.md).
All public operator paths use `/api/v1`, JSON, stable error bodies, request
IDs, and cursor pagination. `/livez`, `/readyz`, and `/metrics` exist only on
the private management listener; `/api/v1/status` requires authorization.

For local HTTP health diagnostics, point `peerward doctor --control-url` at the
private management origin (for example `http://127.0.0.1:9090`), which serves
`/livez` and `/readyz`. A Peer Relay diagnostic authenticates the remote identity
without acquiring a presence lease or replacing the live device connection.

Development bearer example:

```sh
curl --fail --silent \
  -H "Authorization: Bearer $PEERWARD_DEV_TOKEN" \
  'https://console.example/api/v1/meshes?limit=50'
```

Browser sessions use OIDC Authorization Code with PKCE/state/nonce. Mutating
cookie-authenticated requests must echo the CSRF token in the configured
header. Do not place bearer, ticket, session, or CSRF values in URLs or logs.

The principal workflows are:

- meshes and root-anchored Authority stage/activate/revoke;
- mesh-scoped peers/relays, including credential list, rotate, activate, and
  revoke lifecycle operations;
- one-time join ticket create/list/revoke and idempotent signed ticket claim;
- ordered policy GET/PUT plus side-effect-free
  `POST /api/v1/meshes/{mesh_id}/policy/validate`, which returns normalized
  output, a canonical SHA-256, field errors, and operational warnings;
- canonical policy questions through
  `POST /api/v1/meshes/{mesh_id}/policy/simulate`; viewers may use only the
  current policy, while operators/admins may submit an unsaved draft;
- privacy-safe `GET /api/v1/meshes/{mesh_id}/topology`, containing only
  Peer-to-Relay presence and never centralized Peer-to-Peer direct edges;
- bounded large-mesh topology routes: `/topology/summary`, keyset-paginated
  `/topology/nodes?kind=&relay_id=&region=&cursor=&limit=`, and
  `/topology/edges?kind=presence|backbone&cursor=&limit=`; limit is 100 by
  default and 200 maximum, while the legacy route returns
  `409 topology_pagination_required` above its global ceiling;
- strong numeric ETags on Mesh/Authority/Peer/Relay/Join Ticket/Service member GETs;
  conditional mutations fail with `428 precondition_required` or
  `409 revision_conflict` before changing state;
- transactional same-family bulk preview/commit at
  `/api/v1/meshes/{mesh_id}/bulk/{preview,commit}`, bounded to 100 items and
  excluding Authority;
- encrypted, Peer-identity-signed current runtime health delivered through the
  opaque audit transport; Control keeps only the newest monotonic value with a
  90-second TTL and no relationship history;
- service list/revoke;
- audit cursor pagination and `/api/v1/events` SSE replay.

Mesh deletion uses `DELETE /api/v1/meshes/{mesh_id}` with a current
`If-Match` and `{"confirmation_name":"exact stored name"}`. It requires
`trust_manage` and applicable CSRF validation, and returns `202` with `mesh_id`
and `job_id`. Populated Meshes are supported: acceptance marks the Mesh
`deleting`, fences new mutations, and queues asynchronous cleanup. Offline
Relays remain pending until removal acknowledgement. Repeated deletion returns
the same job; historical audit and outbox rows remain intact. Shared hosts and
unrelated Meshes continue running.

A successful join claim returns the rooted identity and signed distribution
bundle, assigned address and routes, DNS/MTU settings, Relay set, and the
issuer's bounded `stun_servers` list. The peer validates every field before it
atomically commits a profile. Join schema 2 binds the claim ID, Ed25519 identity
key, Noise X25519 key, independent `wireguard_public_key`, client version, and
Wire major 5 with proof of possession. The WireGuard data key is never reused
as the Relay authentication key.

The Console presents resource-specific forms and constructs only the typed
fields accepted by the selected operation. Administrators may request Peer
credential renewal through the Console; the device generates its own keys and
executes rotation over the authenticated Relay control channel. Control never
generates or stores Peer private keys. A submitted request is not a completed
rotation: unsupported clients require an upgrade, offline devices wait, and
completion requires authenticated reconnection using the new credential.
Relay rotation imports a locally generated Noise public key;
Control signs the staged credential with the active Mesh Authority. Peer and
Relay removal is an irreversible
administrative disable that revokes credentials and presence.

The guided Console contracts are defined in
[`peerward-api/src/console.rs`](../crates/peerward-api/src/console.rs) and
registered in [`console_routes.rs`](../crates/peerward-control/src/control/console_routes.rs).
Under `/api/v1/meshes/{mesh_id}/console`, they include paginated devices,
sharing, issues and grants; full-scope overview counts; atomic sharing/grant
preview and apply; target/gateway edit previews; reversible resource state;
effective access simulation; and credential renewal requests. Global search
uses `/api/v1/console/search` with an optional `mesh` scope.

`POST .../console/matrix` accepts service targets with optional `address` and
numeric IP `protocol` (6 or 17). The address must belong to the publishing Peer,
the protocol must be configured on the Service, and the port comes from its
saved definition. Omitted conditions aggregate the configured transports and
shared address families; differing decisions return `partial`. Network targets
require address, gateway and protocol, plus a port for TCP/UDP. These responses
describe policy decisions, not observed connectivity.

`GET .../console/network-resources/{id}/grants` returns current policy rules
affecting a LAN or Internet target with `version`, `enabled`, source names,
protocol/ports and an `advanced` flag. Conditional
`PUT .../console/network-resources/{id}/grants/{grant_id}` accepts
`{"enabled":false,"reason":"..."}` to revoke, or `true` to restore. It changes
only a safe single-source, single-resource allow rule; advanced rules return
`409 advanced_grant_required`. It preserves priority and all other predicates,
checks saved policy assertions, and audits the reason and overlapping targets.
The equivalent `services/{id}/grants` routes manage generated Service grants.

SSE clients persist the last accepted cursor, reconnect with that exact cursor,
deduplicate by event ID, and refresh only affected resources. A cursor rejected
as too old requires a full resource reload before resuming.

With no `Last-Event-ID`, Control first captures the durable high-water and sends
`peerward.ready` with `{"cursor":"<uuid>"}` or `{"cursor":null}`; no historical
event is replayed. The client opens this stream before reading its snapshot and
queues subsequent events while the snapshot is applied. A malformed UUIDv4 is
`400 invalid_event_cursor`, while an unknown/pruned cursor is
`410 event_cursor_expired`. Retained cursors replay precisely the events after
them. Streams receive 15-second keepalives; one Control instance admits at most
256 streams and returns `429 sse_capacity` beyond that limit.

List cursors are opaque unpadded Base64URL compound keys. Ordinary resources
use `(created_at,id)` ascending and audit uses `(occurred_at,id)` descending;
invalid values are `400 invalid_cursor`. Never synthesize cursors from UUID
ordering. Control limits request bodies to 2 MiB. Rust, Console, and Android
clients bound streamed responses before strict UTF-8/JSON decoding: join 1 MiB,
Console success 2 MiB, error 64 KiB, and an SSE event 256 KiB.

Errors have `code`, safe `message`, and `request_id`. Treat codes as stable
machine data, display the request ID to operators, and never infer authorization
from an empty list. Authorization uses explicit capabilities rather than role
ordering. Auditor has `status_audit_read`; viewer adds `resource_read`;
operator adds `resource_write`; admin adds `trust_manage`. The OIDC precedence
is admin, operator, auditor, viewer. Server enforcement remains authoritative
regardless of Console visibility, and auditor SSE is reduced to audit-change
notifications without resource or Mesh identifiers.

Every request accepts only a UUIDv4 `x-request-id`; absent or invalid values are
replaced. The response header, error body, and structured log use exactly the
same ID. Sensitive headers, tickets, cookies, keys, and payloads are never
logged.

Control also accepts strict W3C version-00 `traceparent`. It creates a child
span rather than reusing the caller span ID. Event JSON contains independent
`request_id` and `traceparent` fields, and correlation continues through outbox,
the linked `state.publish` span, capable Relay receive/apply spans, and capable
Peer receive spans. Baggage is deliberately ignored, and external sampled flags
cannot override the locally configured sampler.

### 自动创建网络的可读标识

`POST /api/v1/mesh-provisioning` 接受 `request_id`（UUID v4）、`name`、可选的 `network_identifier`。标识为 1–63 位小写 ASCII 字母、数字、连字符，首尾不能为连字符；它与不可变的 `mesh_id`、DNS 后缀独立。旧的仅名称请求仍兼容；不能在 `existing_mesh_id` 请求中指定新标识。

`network_identifier` 随网络和任务在一个事务中保存，当前安装内唯一、创建后只读，`GET /api/v1/meshes` 和详情返回该字段（旧网络为 `null`）。重复标识返回 `409 network_identifier_exists`；同一请求 ID 改用其他标识返回 `409 request_id_conflict`。初始化失败重试原任务，不能将 HTTP 202 当作网络已就绪。
