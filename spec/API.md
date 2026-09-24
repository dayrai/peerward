# Peerward REST and management contract

All public JSON endpoints remain under `/api/v1`. Unknown request fields are
rejected. Mesh, Authority, Peer, Relay, Join Ticket, and Service resources carry a
strictly positive monotonic `version`; member GET responses return the strong
numeric ETag `"<version>"`. PATCH, disable/cancel, credential rotation,
activation, and revocation require the matching `If-Match`. Missing
preconditions return `428 precondition_required`, malformed values return
`400 invalid_if_match`, and stale values return `409 revision_conflict` before
any mutation. Policy keeps its explicit document revision. Errors have the stable form:

```json
{"error":{"code":"stable_code","message":"localized-safe description","request_id":"uuid","field_errors":{},"retryable":false}}
```

Control accepts a valid UUIDv4 `x-request-id` or generates one. The same value
appears in the response header, error body, and structured request log. Invalid
incoming values are replaced. Request bodies are limited to 2 MiB before JSON
extraction and fail as `413 request_too_large`; malformed or non-UTF-8 JSON is
`400 invalid_json`. Tokens, tickets, cookies, private keys, and request/response
payloads are never request-log fields.

List responses remain `{"items":[],"next_cursor":null}`. A cursor is unpadded
Base64URL over version byte `1`, signed 64-bit creation time in Unix
microseconds, and the 16 UUID bytes. Ordinary resources order by
`(created_at,id)` ascending; audit orders by `(occurred_at,id)` descending.
Malformed/version-unknown cursors are `400 invalid_cursor`. This compound
ordering, not UUIDv4 ordering alone, defines concurrent pagination.

The authenticated operator surface covers status, Mesh, Authority, Peer and
Credential, Relay, Policy, Service, Join Ticket, Audit, and events. `/status`
requires viewer/auditor authorization. `/livez`, `/readyz`, and `/metrics` are
served only by the private management listener and never under public
`/api/v1`.

`/auth/session` returns a stable `capabilities` array. Authorization is an
explicit matrix: auditor has `status_audit_read`; viewer additionally has
`resource_read`; operator additionally has `resource_write`; admin additionally
has `trust_manage`. Trust management covers Authority and Mesh lifecycle operations.
`DELETE /api/v1/meshes/{mesh_id}` requires `If-Match` and JSON
`{"confirmation_name":"exact stored name"}` and returns `202` with `mesh_id` and
`job_id`. Populated Meshes are supported. Acceptance atomically marks the Mesh
`deleting`, fences new mutations, retains history and records `mesh.delete.request`
and `mesh.deleting`. Cleanup continues asynchronously; an offline Relay remains
pending until its removal acknowledgement. Repeated deletion returns the same job.
OIDC
group precedence is admin, operator, auditor, viewer. Auditor SSE events contain
only an audit-change cursor/timestamp and never ordinary resource identifiers.

`GET /api/v1/meshes/{mesh_id}/topology` returns current Peer/Relay nodes and
Peer-to-Relay presence edges. It never returns Peer-to-Peer direct edges. The
compatibility route has a global result ceiling and returns
`409 topology_pagination_required` above it. Large callers use the database-
aggregated `/topology/summary` and keyset-paginated `/topology/nodes` and
`/topology/edges` routes. Their limit defaults to 100 and is capped at 200;
node filters are `kind`, `relay_id`, and `region`, while edge kind is exactly
`presence` or `backbone`.
`POST /api/v1/meshes/{mesh_id}/policy/simulate` invokes the canonical policy
evaluator for a real source Peer, target Service and protocol. Viewer requests
cannot contain `draft_policy`; operator/admin requests may simulate a draft.

`POST /api/v1/meshes/{mesh_id}/bulk/preview` and `/bulk/commit` accept 1–100
unique resources from exactly one of Peer, Relay, Join Ticket, or Service.
Authority is not a bulk family. Preview returns each current state and version;
commit sorts and locks every row, revalidates all captured versions and states,
then applies the whole operation and its revision changes in one transaction.
Any failure rolls the transaction back, so partial commit is impossible.

Peers send an encrypted and identity-signed runtime health record through the
existing opaque Relay-to-Control channel every 30 seconds or after a runtime
state change. The complete encrypted envelope is at most 4 KiB and contains
only direct-path count, Relay/direct packet counters, bounded degradation
codes, and signed-state revision. Control retains one monotonically newer row
per Peer until 90 seconds after the signed observation time. Delayed or replayed
delivery never extends that deadline, including after retention deletes the row.
Reports older than that window or more than 30 seconds ahead of Control are
rejected; a future observation within clock tolerance stays hidden until its
observation time. It never retains report history, Peer-to-Peer edges,
addresses, ports, endpoints, or DNS data. Topology may expose only this current
aggregate and Peer-to-Relay presence.

`POST /api/v1/join/{token}/claim` binds claim ID, Ed25519 identity key, Noise X25519
key, independent `wireguard_public_key`, client version, and supported Wire major with a signature from the new
identity under Join schema 2. The exact transcript is defined in
[WIREGUARD_CREDENTIALS.md](WIREGUARD_CREDENTIALS.md). Ticket lock, Peer/address/credential creation, canonical response,
audit, and outbox commit together. The same ticket, claim ID, and canonical
signed transcript return the identical HTTP status and response bytes; any
different claim ID or field set for a consumed ticket returns `409`.

Fresh Schema 4 deployments also accept immutable ticket `settings`: optional
DNS-safe `name`, administrator-controlled `labels`, and `mode`. The mode is
exactly one of `{ "kind": "bearer" }`, `{ "kind": "prebound",
"identity_fingerprint": "<64 lowercase SHA-256 hex characters>" }`, or
`{ "kind": "approval" }`. Labels cannot replace device self-report metadata.
The fingerprint is SHA-256 over the raw 32-byte Ed25519 verifier and must be
verified over a trusted independent channel; PoP alone does not prove intended
admission. Ticket list/detail retain terminal metadata and the associated Peer,
never the token. History remains subject to the configured retention policy.

Approval mode reserves the first valid signed request, without allocating an
address or issuing a network credential. HTTP 202 returns `PendingJoinResponse`
with an application ID, version, fingerprint, independent 30-minute expiry and
five-second retry interval. Repeating the exact claim retrieves status or the
committed HTTP 201 response. Polling never extends the deadline. The first
reservation remains exclusive after rejection, cancellation or expiry.
`GET /api/v1/meshes/{mesh_id}/join-applications` uses ordinary pagination;
`GET .../join-applications/{id}` returns one versioned metadata record.
`POST .../{id}/approve` requires resource-write authorization, CSRF where
applicable, `If-Match`, and an `identity_fingerprint` body verified by the
administrator. `POST .../{id}/reject` requires the same authorization and version.
Approval creates both IP assignments, Peer, credential, response, audit and
outbox atomically under parent/ticket/application locks. Exact approval retries
using the original version return the same result, including after key rotation
makes the original online issuer unavailable. Responses contain no plaintext
private keys. An approval is not an application or connectivity receipt.

Linux `join prepare --output-dir` retains device identity for prebinding. Both
Linux and Android durably retain the original claim before the HTTP request;
network failure does not regenerate keys or discard an uncertain claim. Resume
requires the same invitation, including when its original submission TTL has
elapsed; the server still enforces reservation and approval deadlines. Android
stores token-free pending metadata encrypted with AndroidKeyStore and excludes
it from platform backup. Explicit local abandonment does not release the ticket.


Invitation `settings.lifecycle` is one of `{"kind":"long_lived"}` (default),
`{"kind":"ephemeral"}`, or `{"kind":"expiring","valid_until":<Unix seconds>}`.
The device deadline is independent of the invitation and pending-approval TTL.
Creation requires more than 60 seconds remaining; final enrollment rechecks the
absolute deadline. Every initial and rotated subject credential is bounded by
that deadline. Peer responses expose `admission`, `admission_ended_at` and
`admission_end_reason` (`expired` or `ephemeral_offline`). A terminal admission
cannot be re-enabled; a fresh invitation creates a new identity and assignment.

Ephemeral retirement requires 1800 continuously observed offline seconds. Only
successful publication passes with all enabled Relay runtimes healthy count.
An elected per-Mesh observer combines process monotonic elapsed time with a
bounded database-clock cross-check; observer takeover, Relay generation changes,
failed publication, stale observations, clock discontinuity, or live presence
reset the interval. Retirement transactionally disables the Peer, revokes its
credentials and services, cancels pending rotations, removes presence, quarantines
both addresses, and writes audit/outbox. Address quarantine cannot precede the
last issued authorization's expiry and execution margin. Cleanup is not the
credential-expiry enforcement mechanism and may conservatively pause.

Peer list/detail responses include `mesh_addresses`, containing only currently
allocated Mesh IP addresses (also available while a device is offline), and
`display_name` / `location`. The latter are optional administrator-entered text,
independent of the DNS-safe `name` and policy `labels`; they do not imply GPS or
IP-derived geolocation. Create defaults both descriptions to empty. PATCH leaves
omitted fields unchanged; an empty string clears the corresponding description.
Each description is trimmed, contains no control characters, and is bounded to
128 Unicode characters. Edits use the existing resource-write capability,
`If-Match` precondition, and audit transaction. Neither public endpoints nor
private direct-path discovery candidates are added to these responses.

Peer credential rotation is executed only by an authenticated Peer over its
encrypted Relay control channel; OIDC management sessions cannot stage a Peer
key. An administrator with `trust_manage` may create a signed renewal request
at `POST /api/v1/meshes/{mesh_id}/console/devices/{peer_id}/renewals` using the
current Peer `If-Match`, CSRF where applicable, and a body containing UUIDv4
`request_id`, `current_serial`, `valid_for_seconds` (300–604800), and `reason`.
Exact retries by the same actor return the existing request; reuse with changed
content is rejected. GET on the same path lists requests with cursor pagination.
Requests bind the Mesh, Peer, current credential and expiry; Wire 5 capability
negotiation gates delivery. Offline or unsupported clients do not count as
success. Only authenticated reconnection with the activated replacement key
completes the request. Private keys remain on the device.
Relay credential rotation has explicit create and activate operations.
Policy uses
`POST /api/v1/meshes/{mesh_id}/policy/validate` for side-effect-free validation
that returns normalized output, canonical SHA-256, warnings, and field errors;
the authoritative write remains a revision-conditional PUT.

Web OIDC uses Authorization Code with PKCE, HttpOnly Secure SameSite cookies,
CSRF validation, nonce/state checks, issuer discovery restrictions, and no
token exposure to browser JavaScript.

## Durable events

An accepted W3C `traceparent` and UUIDv4 `x-request-id` are independent. Control
creates a new server span ID, stores the correlation fields with outbox and
signed-state revisions, and emits `request_id` plus `traceparent` in event JSON.
Malformed trace context is replaced and baggage is never accepted or emitted.
Publisher coalescing links at most 32 causal contexts and always creates a new
publication request ID.

`GET /api/v1/events` uses UUIDv4 SSE event IDs. Without `Last-Event-ID`, it
captures the durable event high-water, emits exactly one `peerward.ready` event
whose JSON is `{"cursor":"<uuid>"}` or `{"cursor":null}`, and then emits only
events committed after that high-water. With a retained cursor it replays every
later event in database order. A non-UUIDv4 header is
`400 invalid_event_cursor`; an unknown or pruned cursor is
`410 event_cursor_expired`, including a previously returned high-water cursor
whose corresponding outbox row has since been pruned. A fresh stream still
starts after the durable numeric high-water and reports a null ready cursor
when no retained row can name that position.

The server sends a keepalive at least every 15 seconds, caps one instance at
256 streams (`429 sse_capacity`), and rejects any stored/decoded SSE event over
256 KiB. Notifications are wakeups only: all delivery and replay comes from the
ordered database log. Clients must bound deduplication, establish the stream
and receive `peerward.ready` before applying the initial snapshot, queue events
during that snapshot, and perform the same sequence after a 410 reset.


## Dynamic Mesh API

New Meshes default to an inner IP MTU of 1280 bytes. Bootstrap, management
forms, provisioning and platform profile defaults use the same value. Explicit
MTUs remain configurable from 1280 through 9000; changing this default does not
rewrite an existing Mesh's MTU.

`POST /api/v1/meshes` accepts an optional UUIDv4 `request_id` for exact replay,
executes full asynchronous initialization, and returns 202 with `lifecycle` and
`lifecycle_job`. The provisioning endpoint adapts to the same engine. Deletion
requires the exact name and If-Match, accepts populated Meshes, and returns 202
with `mesh_id` and `job_id`. Repeated deletion returns the same job.
`/api/v1/mesh-lifecycle` lists tasks; `/{id}` reads one; `/{id}/retry` retries a
failed task. `/api/v1/mesh-recovery/{mesh}` exports only an encrypted archive to
an administrator. `/api/v1/meshes/{mesh}/termination` is a public signed-record
query that survives removal. `/api/v1/relay-hosts` lists registered hosts;
POST `/api/v1/meshes/{mesh}/relay-hosts` assigns an additional registered host.

The separate mTLS listener exposes `/internal/v1/relay-host/assignments`,
`/public-key` and `/ack`. The verified client-certificate fingerprint selects
the registered host. These endpoints do not accept the developer bearer.

Assignment responses contain at most 256 entries and a `next_mesh` cursor.
Subsequent pages supply `after` and the first page's `expected_revision`;
configuration changes during a scan return 409, requiring a new full scan.
The host reconciles periodic full scans as well as change notifications, and
never applies an older version or treats a partial scan as proof of removal.
Assignment IDs and revisions fence enrollment and acknowledgement; only public
trust material crosses this channel. Every deployment topology uses this API.

## Local client preferences and automation credentials

Linux exposes `client_preferences` on the existing protected management socket;
Android exposes the same request semantics through its application-private JNI
bridge. `operation: "get"` accepts no other fields. `operation: "set"` contains
`change: { request_id, expected_version, preferences }`. Request IDs are UUIDv4;
preferences are `accept_private_routes`, `accept_dns`, `allow_inbound`,
`exit_resource` (UUID or null), and `allow_local_lan`. Selecting an exit requires
DNS enabled and a currently approved remote provider. Preferences narrow grants;
they cannot create authorization. The exact latest retry returns the same saved
version; another body or stale version is rejected. Persistence, platform
application and application reachability remain separate observations.

Linux commands are `peerward client preferences`, `peerward client set`,
`peerward client exit list|select|off`, with `--config FILE`. `set` accepts boolean
`--accept-routes`, `--dns`, `--inbound`; `exit select` requires `--resource NAME_OR_ID`
and accepts `--allow-local-lan`. `exit off --offline` requires the profile's
exclusive local runtime lock, restores owned network state, then removes the
persistent exit guard. It does not require a live control connection or an
unexpired device credential. Failed cleanup retains protection.

Android network observations contain both `configuration_version` and
`preferences_version`; neither an older local preference nor an older signed
configuration can acknowledge the current network intent. Android default exit
protection lasts while VPN capture is active. Process-independent blocking must
be verified through the system Always-on/Lockdown state.

After restart or suspend invalidates a device's monotonic authorization lifetime,
the existing signed `Applied` operation can report category `core`, result
`rejected`, reason `fresh_authorization_required`, and its persisted configuration
version/digest and lease sequence. The normal identity, freshness, replay and
configuration-binding checks apply. Control coalesces such receipts for the
current lease into one newer signed lease, preserving the configuration and all
grants. Receipts for older leases and unrelated rejection reasons do not force
renewal. The client remains closed until it verifies the newer lease and every
dependency; neither reconnecting nor replaying the old lease restores permission.
This uses the existing Wire 5 management envelope and receipt schema.

`GET|POST /api/v1/meshes/{mesh_id}/machine-credentials` and
`DELETE /api/v1/meshes/{mesh_id}/machine-credentials/{id}` require `trust_manage`.
List uses standard pagination. Create takes `{id,name,capabilities,ttl_seconds}`;
allowed capabilities are `status_audit_read`, `resource_read`, `resource_write`,
without duplicates. TTL is 300–7776000 seconds; at most 100 active credentials
per Mesh. The creation response contains `credential` metadata and a `token`,
with `Cache-Control: no-store`. Only the digest persists. A lost creation response
cannot redisplay the token: `credential_already_issued` requires revoking that ID
and creating a replacement. DELETE requires If-Match; repeating a completed
revocation is idempotent and never reactivates the credential.

Use `Authorization: Bearer pw_machine_...` for automation. These tokens work
alongside production OIDC without enabling development authentication. They can
only access their assigned `/api/v1/meshes/{mesh_id}` subtree and their explicit
capabilities, cannot create browser sessions, issue machine credentials, or
change trust. Expired/revoked tokens return 401; out-of-scope resources/capabilities
return 403. Audit actors use `machine:{credential_id}`. Revoking a machine token
blocks subsequent API requests; previously issued network authorizations retain
their own lease semantics.

### Local gateway path observations (Wire 5)

The protected client preference response includes `gateway_paths`, a list of `binding_id`, `peer_id`, and `health` (`unknown`, `healthy`, `unhealthy`). These are local transport-path observations; they do not attest LAN application health. A selected provider remains subject to current rules, binding approval, publication, and authorization expiry. Missing observations do not constitute an application receipt.

Gateway checks use the existing authenticated WireGuard coordination channel: message kinds 6 (binding UUID) and 7 (binding UUID plus a strict 0/1 readiness byte), the binding version in the generation field, and a fresh 16-byte transaction. Requests for a provider are coalesced. A reply must match the pending transaction, local and remote keys, binding version, original carrier path, and the five-second deadline; it is consumed once. Failure of three consecutive checks excludes the path. Recovery requires consecutive successful checks and a 30-second stability window for new flows; existing healthy-provider connections remain pinned. Advertised readiness changes invalidate affected connections and pending output, without erasing unrelated healthy connection state.

`PATCH /api/v1/meshes/{mesh_id}/gateway-bindings/{id}` accepts only `{ "priority": <u32> }` and requires the current `If-Match` version and resource-write capability. It preserves the current approval source, increments the binding version, atomically audits the change, and requires the provider to advertise that new version. Concurrent losers receive `409 version_conflict`; client drafts remain available for review and retry.

## Automatic path approval (Wire 5 / Schema 4)

Mesh-scoped `auto-approval-rules` supports `GET/POST` collection and `GET/PUT/DELETE {id}`; readers require `resource_read`, writes `resource_write`, and mutations preserve existing CSRF/auth rules. Create takes `{id, definition}`; update takes the strict definition with `If-Match`. Definitions contain `name`, `enabled` (default false), `device_collection`, `site_id` and 1–32 canonical non-default `prefixes`. Maximum 64 rules per Mesh; list uses the standard cursor contract. The selected collection must contain devices in this Mesh, and the site must already have a LAN resource.

Enabled rules may approve only SNAT subnet bindings whose provider is currently enabled, unexpired and in that controlled collection, whose site matches, and whose entire prefix is covered. They do not grant packet access or mark a provider ready. The selected authority is the first matching rule in stable UUID order; `approval_source` records its ID/version. Rule, collection and controlled device-label mutations reassess eligible bindings atomically with audits, events and configuration revision. Missing evidence does not grant approval; automatic revocation is not blocked by positive access assertions.

An explicit manual approval or withdrawal removes automatic eligibility. Retargeting a resource also removes eligibility and its old grant. `POST gateway-bindings/{id}/automatic-approval` takes strictly `{}` with `If-Match` and deliberately resumes automatic assessment; the response is the current binding, which may still be unapproved. Internet exits and preserved-source paths require manual approval. Automatic approval never overrides an existing manual grant or resurrects a manually withdrawn path merely because a rule changes. Removing the sole matching rule revokes its grants; another matching rule can remain authoritative.

Signed resource withdrawal items contain `{target, providers}`. The bounded provider set is captured transactionally before resource retarget/delete cascades remove the old bindings. Original providers exclude that old private prefix from automatic VPN capture; other clients retain its deny shadow. The exclusion does not authorize packets, suppress policy evaluation, bypass lease checks or allow fallback to a broader path. Exact newly approved targets alone release the matching withdrawal.

### Mesh configuration ownership and declarations (Schema 4 / Wire 5)

All routes below remain under `/api/v1/meshes/{mesh_id}/configuration` with existing Mesh scope, capability checks, strict fields and request size bounds. `GET/PUT ownership` returns an ETag/version and accepts `{owner_machine_id: UUID|null}` on conditional PUT; transfer requires `trust_manage`. `null` means interactive management; machine credentials require explicit ownership for writes. An assigned owner fences interactive configuration writes until explicit takeover. Identity retirement and credential revocation remain independently authorized and invalidate old previews. OIDC and machine audit actors have separate `oidc:` / `machine:` namespaces.

`GET export` requires `resource_read` and returns `{version,document}`. The declaration contains Schema 4 / Wire 5, this Mesh UUID, resources, bindings, collections, automatic approval rules, DNS profiles, peer policy, resource policy and its tests. It excludes identities, secrets, invitations, addresses, live advertisements, signed state and audit. Automatic approval is an intent mode, never exported as an equivalent manual grant. A binding's target/provider/forwarding identity is immutable; changing it needs a new binding UUID.

`POST validate` accepts a declaration and evaluates the current dependency snapshot. `POST preview` also requires `If-Match` for the exported version. Both require `resource_write`, stage the same transactional validation/application path and roll back all effects. The result contains version, canonical document digest, preview digest, per-object changes, failed assertions, a conservative only-removes-grants result, can-apply and `applied:false`. Validation includes reference scope, approved providers, target conflicts, collection resolution, DNS namespaces and effective signed resource limits.

`POST apply` requires `resource_write`, matching configuration ownership, `If-Match`, and `{request_id,document,preview_digest}`. The UUID v4 request identity is bound to its authenticated actor, original version and normalized request content. Concurrent/exact retries return the original committed response; reuse with different content is rejected. The server re-evaluates the preview under the Mesh lock before committing all changes, audit, outbox and response together. No-op apply leaves configuration and resource versions unchanged. Restoration of older content creates a new version. Positive access assertions cannot block a conservatively proven withdrawal; a failed negative assertion still blocks publication. Saved state does not prove client application or reachability.

Errors include `version_conflict`, `configuration_owned`, `preview_changed`, `request_reused`, `policy_tests_failed` and the existing typed validation errors. Clients retain drafts and the original request after an unknown result. Per-Mesh exact application responses are bounded at 10,000 records; maintenance must archive older records before exhaustion. Configuration revision is separate from periodically refreshed route advertisements and authorization lease sequences.

### Concrete addresses and overlapping resource descriptions

Packet execution, packet simulation and saved policy assertions resolve the
actual destination address before authorization. The most specific matching LAN
prefix wins over broader subnets and the selected Internet resource. Equal-prefix
aliases at the same site share the existing `(priority, Deny-before-Allow, rule
UUID)` ordering. An Allow must match an approved binding for that resource and
provider; a Deny matching another alias cannot be bypassed by selecting a name.
Neither an unapproved nor a withdrawn more-specific target falls back to a wider
route. Connection tracking records the chosen real resource and provider.
Simulation includes an alias/shadow warning when appropriate and remains policy
evidence, not forwarding or application-health evidence.

### Webhook notifications (Schema 4)

Under `/api/v1/meshes/{mesh_id}`:

| Operation | Contract |
| --- | --- |
| `GET/POST webhooks` | Cursor listing / create `{id,name,endpoint,enabled,event_types}`; enabled defaults false |
| `GET/PUT/DELETE webhooks/{id}` | Read / replace strict definition / delete; mutation requires `If-Match` |
| `GET webhook-event-types` | Exact supported event names; no wildcard subscription |
| `GET webhooks/{id}/deliveries` | Cursor listing of queued, sending, succeeded, failed and cancelled attempts |
| `POST webhooks/{id}/deliveries/{delivery_id}/retry` | Conditional explicit retry of a failed delivery under the current enabled configuration |

Read uses `resource_read`; create, edit, delete and retry require `trust_manage`
and existing CSRF protections. Mesh machine credentials cannot administer
notifications. Create is idempotent for the same UUID/body. Maximum 16 hooks per
Mesh, 32 selected event types per hook. Activation requires an active signing
issuer. A configuration change cancels the older pending version; bytes already
transmitted cannot be retracted.

Destinations require HTTPS port 443 without credentials, query or fragment.
Local/special addresses and local DNS suffixes are rejected. Each attempt resolves
again, rejects mixed public/private or overlarge address sets, pins the verified
addresses, validates the TLS hostname/certificate, disables proxy inheritance and
refuses redirects. There is no API option to disable these checks.

The transaction outbox writes a minimal event identity into a bounded persistent
queue. Notification bodies contain `version:1`, `mesh_id`, `webhook_id`, stable
`delivery_id`, `attempt`, `sent_at` and `event` (`id`, `sequence`, `occurred_at`,
`kind`, `resource_kind`, optional `resource_id`). Bodies are at most 16 KiB and
exclude event payloads, actor identities, labels and secrets. The distribution
Ed25519 key signs `peerward/webhook-notification/v1\0` followed by the exact body
bytes; the header is `Peerward-Signature: ed25519=<base64url without padding>`.
`Peerward-Delivery-Id` repeats the signed ID. The authenticated management API
provides the verification public key. Receivers pin Mesh/hook/key, reject messages
outside a 300-second clock window and commit delivery deduplication with local
acceptance before returning 2xx. The shared test vector and persistent receiver
are in `examples/webhooks`.

A worker holds a 15-second fenced claim; HTTP work has an eight-second total
budget. Failed transient requests use bounded exponential backoff with jitter,
up to 10 attempts in 24 hours. Redirects and non-retryable 4xx fail permanently;
408, 429, 5xx and transport failures may retry. Attempt ownership and number fence
late results. An explicit failed-delivery retry keeps its delivery ID, starts a
new bounded attempt window and requires its current ETag. Completed delivery
records are retained seven days; each hook stores at most 10,000 records. A full
queue increments the visible drop counter without blocking the business event.
Network notification delivery never participates in an authorization transaction.
A 2xx result confirms HTTP acceptance, not downstream business completion.

### Target service observations (Schema 4 / Wire 5)

`ResourceDefinition.health_probe` is optional `{address: IpAddr, port: u16}`. It specifies a numeric address inside the approved resource; loopback, link-local, multicast, unspecified and IPv4-mapped IPv6 targets are rejected. At most 64 probes may be configured per Mesh, including declarations. Linux providers attempt a TCP connection every 30 seconds, with a two-second timeout and eight concurrent attempts. No application bytes are sent. This observation never grants access or selects an HA provider.

`GET /api/v1/meshes/{mesh_id}/network-resources/{resource_id}/health` requires `resource_read`. The response contains `resource_id`, `resource_version`, `probe`, and ordered `bindings`. Each binding reports its IDs, device name, versions, `status` (`reachable`, `refused`, `timeout`, `unavailable`, `unknown`), `source: gateway_tcp_connect`, `observed_at`, and `valid_until`. `authorization_evaluated` is false and `application_authentication` is `not_tested`. Missing, expired, revoked or different-version evidence is `unknown`; timestamps of earlier observations remain diagnostic details.

The device-signed `PeerOperation::TargetHealth` binds `binding_id`, `binding_version`, `resource_version` and `result` to the existing authenticated command identity, credential and monotonic sequence. Only the current approved provider may submit. New reports must be within 30 seconds of server time; accepted observations expire in 90 seconds. Exact replay does not refresh expiry. Unchanged fresh results refresh their bounded observation row without repeatedly appending immutable audit events. Observation changes remain audited.

### Configuration response retention

Exact configuration application responses are retained for 30 days. Maintenance then clears the response while retaining the request ID, actor, digest and archival time. An otherwise valid exact retry returns HTTP 410 with `configuration_response_archived`; changed content or authority with that ID remains a conflict. Clients must export current state and preview a new request. The 10,000-response limit counts unarchived responses. Single-use Join tickets and approval history are not deleted by short operational retention. Signed device command retry digests may be removed after eight days; persistent sequence floors remain, and stale requests cannot execute again.

### Device conditions (Schema 4 / Wire 5)

`GET/PUT /api/v1/meshes/{mesh}/device-conditions` reads or conditionally replaces
Mesh device admission requirements. Reads require `resource_read`; mutations
require `resource_write`, the existing CSRF protections and `If-Match`. Conditions
include `enabled`, `scope`, `minimum_version`, `platforms`,
`required_capabilities` and `minimum_credential_seconds`. An empty scope selects
all devices; a CIDR matching either device address selects the entire device.
Versions use canonical SemVer precedence, excluding build metadata.

`GET /api/v1/meshes/{mesh}/peers/{peer}/device-condition` separates the control
admission decision, signed device software statement, source and expiry from
client configuration application. Linux reports software evidence through the
existing signed `PeerManagement` operation every five minutes. Reports must be
fresh within 30 seconds, expire after 900 seconds, and use the authenticated
credential and persistent request sequence. Replaying the same report cannot
renew it. Software/platform/capabilities are self-reported; credential validity
is verified by Control. Neither is hardware attestation or malware detection.

The computed admission table is included in signed resource configuration.
Unknown or expired evidence denies selected devices; ordinary Peer traffic,
resource sources and providers all enforce this decision. Changes invalidate
queued packets and connection state. Restricted devices retain authenticated
control reporting and credential recovery. Android evidence reporting remains
an implementation gap and must not be presented as available.

### Relay maintenance tasks (Schema 4 / Wire 5)

All following global endpoints require `trust_manage`; writes retain CSRF checks.
Mesh-scoped machine credentials cannot operate these endpoints.

| Endpoint | Operation |
| --- | --- |
| `POST /api/v1/maintenance-tasks/preview` | Validate a fixed plan and return affected Meshes, blockers, host revisions and a canonical digest |
| `GET/POST /api/v1/maintenance-tasks` | Paginated task history or idempotent creation with `id`, `plan`, `preview_digest` |
| `GET /api/v1/maintenance-tasks/{id}` | Current persistent task version, stage, result and reason |
| `POST /api/v1/maintenance-tasks/{id}/retry` | Retry a failed task using its current `If-Match` version |

A plan specifies `operation` (`relay_drain` or `relay_resume`), `host_id`, optional
`replacement_host_id`, and `grace_seconds` (default 60, range 15–900). Drain requires
a distinct replacement; resume rejects a replacement. Preview examines at most
256 existing assignments and rejects a Mesh lifecycle transition. A replacement
must have fresh host and assignment observations (30 seconds), the exact applied
revision, an active runtime lease, valid credentials and the current published
Relay directory for each affected Mesh. Create rechecks the preview and readiness.
The same request ID, actor and content returns its original task; altered content
conflicts. No endpoint accepts commands, scripts or filesystem paths.

Tasks use small database-atomic steps, at most eight per two-second pass. Failed
or unfinished tasks block new host assignments so the reviewed scope cannot grow
silently. Draining refuses new Peer sessions while retaining existing runtimes
through the grace period; its acknowledgement waits for in-progress registration.
The next step suspends runtimes. Completion requires current suspended
acknowledgements and the absence of live runtime leases. Missing evidence never
means completion. Replacement failure pauses progress; after 30 minutes the task
fails while retaining the current maintenance state. Explicit retry preserves
its stage and starts another bounded attempt window.

Suspension preserves local keys and does not create a Mesh termination record.
Resume waits for actual runtime/credential/directory readiness and cannot
reactivate revoked serials. Draining the default host moves that default to its
replacement; resuming does not move it back. Existing connections may reconnect.
Host acknowledgements use the existing certificate-pinned mTLS identity, Mesh,
Relay and assignment revision. `draining` and `suspended` are distinct desired
and acknowledged states; `removed` retains its signed Mesh termination semantics.
Installation backup uses the separate restricted runner contract below. Isolated
restore verification is local-only; production restore activation and Compose
image rollout are not exposed. Native systemd role upgrades use the fixed runner below.

### Deployment runners, installation backups and native upgrades (Schema 4)

These installation-wide resources are separate from Mesh machine credentials.
Administration requires `trust_manage` and existing CSRF protection; responses
are paginated using the existing cursor/limit convention.

| Method and path | Contract |
| --- | --- |
| `GET/POST /api/v1/deployment-runners` | Create with UUID `id`, `name`, immutable `profile_digest`, and `ttl_seconds` (300–7,776,000). At most 64 unrevoked, unexpired runners. Return the `pw_runner_` credential once with `Cache-Control: no-store`; lists exclude token and exchange digests/cached responses. `ready` is computed from credential validity and current 30-second preview/heartbeat observations. |
| `DELETE /api/v1/deployment-runners/{id}` | Current `If-Match` required. Revoke exchange access and cancel queued tasks. Already running local recovery must still finish; missing final reports remain unknown. |
| `GET/POST /api/v1/deployment-tasks` | Create with UUID `id`, `runner_id`, and `preview_digest`. Omitted `operation` retains the canonical `installation_backup` request; native requests explicitly use `operation: native_upgrade`. The preview must match that type. There are no command, path or script parameters. Current preview required; same actor/ID/request is idempotent. One queued/running/recovery-required task per runner. |
| `GET /api/v1/deployment-tasks/{id}` | Stored stage, status, versions, authenticated report and observation timestamp. A queued or assigned task is not execution evidence. |
| `POST /api/v1/deployment-tasks/{id}/cancel` | Current `If-Match` required; queued tasks only. Local service recovery cannot be cancelled remotely. |
| `POST /api/v1/deployment-tasks/{id}/recover` | Current `If-Match`, UUID v4 `request_id`, a recovery-required native task, and a connected original runner required. A fresh release preview is not required to continue the recorded transaction. Atomically increment `recovery_generation` and queue explicit recovery. Exact actor/request/task/version retries return the existing generation; the ID cannot be reused for another intent. |
| `POST /api/v1/deployment-runners/{id}/exchange` | Only the matching runner credential can invoke this exact method/path. The credential has no other management or browser capability, including on another runner. |

Exchange bodies contain a positive increasing `sequence`, the registered
`profile_digest`, optional readiness `preview`, and at most 16 task `reports`.
A preview contains its digest, named `services_to_pause`, `online_files`, `meshes`
and `relay_hosts`. All fields are strict. Reports identify an assigned task and
positive increasing `local_version`, status, bounded stage/error code and optional
artifact `{sha256,bytes,files}`. Success requires a complete artifact and no error.
Final tasks cannot return to a running state. Same local version must carry the
same report; mismatched or older observations abort the transaction.

A native preview additionally includes `upgrade` with role (`control`, `relay`,
`peer`), canonical current/target versions, manifest/artifact SHA-256 digests,
artifact byte length, rollback floor and `repair`. Its digest binds the actual
local process, selected executable, authenticated release, health location and
prior transaction. Preview is read-only and does not consume a release sequence.
The runner stages and pins all local inputs before registration; changed inputs
are rejected before invocation. Native reports optionally add `upgrade` with
role, version, manifest digest, selected artifact digest, state and
`runtime_checked`. Success requires the exact preview target/digest/length and a
completed executable/readiness check. A backup-shaped result cannot prove an
upgrade. A rollback receipt requires Relay/Peer, the original preview version,
and a matching checked artifact; Control rollback receipts are rejected. A historical
successful report is not current health or hardware evidence.
Installation backup summaries exclude native upgrade tasks.

Runner lists expose `connected` separately from `ready`: the former requires a
valid credential and heartbeat within 30 seconds, the latter also requires a
current executable preview. Native heartbeats only reconcile observations.
Only an explicit new recovery generation or a local `recover` command authorizes
continuing an interrupted native transaction. Durable pending generations survive
runner interruption; a recorded completed generation is not executed again.
The updater's original approved digest is included in its first atomic journal
write. Recovery after pointer/restart interruption retains the original direction;
Control never rolls back its database or selects an old binary automatically.
An explicitly staged newer `repair` release can supersede only its matching failed
local native task. That predecessor remains unfinished until the new native
journal is durable; its failed journal is retained and its original runner reports
`failed` / `superseded`. Missing that runner's final observation remains unknown.

The runner persists the complete pending exchange before transmission. Repeating
its latest sequence with identical canonical content returns the persisted
response without extending freshness; older/different exchanges are rejected.
New sequences transactionally apply reports, update readiness, and assign at most
one queued task. A task whose preview changed or whose 15-minute start window
elapsed fails before assignment. The local runner independently checks the start
window and actual pinned installation before its first side effect. Existing
interrupted work is recovered even after that start window.

Assigned operations are never redistributed on heartbeat timeout. The same runner
receives the same ID, consults its durable journal, and either reports its existing
result or recovers the exact original services. Unknown observations are not
synthetic failures or successes. Reports and lifecycle changes are audited;
ordinary heartbeats are not an unbounded audit stream. Local decryption identities,
database secrets, backup bytes and arbitrary diagnostics do not enter this API.

### Relay capacity observations and operations status

The shared host's existing private mTLS listener adds:

- `GET /internal/v1/relay-host/capacity-challenge` returns a UUIDv4 `nonce`, scoped to the authenticated enabled host, valid for 30 seconds. Repeated reads return the current unconsumed challenge.
- `POST /internal/v1/relay-host/capacity` accepts the strict [`RelayCapacityReport`](../crates/peerward-api/src/relay_capacity.rs): nonce, process UUID, monotonic uptime, framed read/accepted-write bytes, admitted Peer and established backbone sessions, host limits, queue usage and cumulative drop/audit counters. No Peer IDs, addresses or payloads are accepted.
- An exact last-report retry returns 204 without refreshing its observation timestamp. A changed retry, expired challenge or regressing counter within a process returns 409. The next accepted process UUID clears interval baselines. These reports are software telemetry, never an authorization input.

Existing global `trust_manage` protects `GET /api/v1/relay-hosts/{host_id}/capacity`
and `GET /api/v1/operations/status`. Ordinary machine and deployment-runner credentials
cannot read them. The capacity response provides `fresh`, `observed_at`, `measurement`,
`report` (without the challenge) and `last_interval`. A missing/older-than-30-seconds
sample is unknown; retained counters are historical, not current throughput. The
operations response summarizes audit storage sampling, missing host observations and
reported backup/maintenance outcomes. No new resource is published or authorized.

Audit sampling is serialized, cached for 15 seconds and bounded to two seconds per
read. The first growth sample, a database statistics reset or a detected counter
regression has no growth estimate. PostgreSQL statistical estimates, carrier-accepted
writes and runner-reported backup success retain their distinct limitations.
Shared `/metrics` stays on the private health listener; unknown paths return 404.
