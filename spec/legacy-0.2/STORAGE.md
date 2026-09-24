# Peerward v1 storage invariants

The first release uses PostgreSQL and one initial migration.  It creates no
objects intended for compatibility with an earlier schema.

## Relations

- `meshes`: address CIDR, gateway, DNS suffix, default policy, quarantine and
  rotation settings, current authority/policy/directory/relay revisions.
- `mesh_authorities`: certified authority serials, public keys, validity,
  lifecycle state, replacement link, and overlap deadline.
- `peers`: mesh, unique enabled name, labels, administrative state, timestamps.
- `peer_addresses`: one active IPv4 address per peer, release/quarantine state.
- `peer_credentials`: serial, peer, public key, validity, lifecycle state,
  replacement link, overlap, signature and directory signature.
- `relays` and `relay_credentials`: one-to-sixteen canonical peer endpoints,
  one-to-sixteen canonical backbone endpoints, keys, lifecycle and validity.
- `relay_presence`: mesh, peer, relay, attachment, role, fencing generation,
  lease deadline; only one live primary generation is routable.
- `join_tickets`: random-token digest, mesh, expiry, creator, consumed timestamp,
  claimed peer; plaintext tokens are never stored.
- `policies`, `policy_rules`, and selector relations: one current policy
  revision per mesh, deterministic ordering, multi-peer and multi-CIDR
  selectors, protocol, enabled/audit flags, ranges and label JSON.
- `services`: peer owner, canonical nonempty protocol set, mesh listen port,
  optional unique DNS alias, labels and state.  Loopback targets are not stored
  by Control.
- `audit_log`: immutable actor/action/target/result metadata.
- `event_outbox`: monotonically ordered UUID cursor, mesh, event type, resource,
  sanitized JSON payload, committed timestamp.
- `oidc_flows` and `web_sessions`: hashed secrets, expiry, nonce/PKCE/session
  state and roles.
- `bootstrap_state`: singleton recording irreversible bootstrap completion.

## Transactions

- Mesh creation, its address pool, initial empty policy and outbox event commit
  atomically.
- Join claim locks the ticket, verifies unused/unexpired state, allocates an
  address, creates the peer and credential, consumes the ticket, advances the
  directory revision and writes an event in one transaction.
- Policy replacement validates all rules before atomically replacing the active
  revision and advancing policy/directory revisions.
- Presence acquisition locks the peer presence key and increments a fencing
  generation.  Renewals must present the same relay, attachment and generation.
- Every successful externally visible mutation appends one outbox event in the
  same transaction.  A dispatcher publishes committed cursors on PostgreSQL
  channel `peerward_events_v1`; consumers always replay from the table.
- Relay admission snapshot reads all signed families, root-certified authority
  lifecycle, current presence/runtime generations, and the outbox sequence
  high-water in one repeatable-read read-only transaction.  A restart takes a
  fresh snapshot; an in-process consumer replays strictly increasing sequence
  values and treats `NOTIFY` only as a wakeup.
- Migration uses advisory lock key `peerward/schema/v1` and is idempotent at the
  migration runner level.

## Validation

All mesh-scoped foreign keys prevent cross-mesh references.  Authority, signed
state, and presence revisions are nonnegative and monotonic.  CIDRs and ports are
validated before SQL.  Database constraints enforce unique active names,
aliases, credentials, addresses, nonnegative revisions, and sensible validity
intervals.  Deleting a mesh cascades its operational records but audit entries
retain sanitized identifiers.

The schema evolves through forward-only migrations.  Endpoint, Policy v2, and
Service v2 changes are separate migrations so an operator can attribute and
recover a failed step.  They do not create compatibility objects for an
unrelated database schema.

Any migration that changes signed transcript bytes advances every signed-state
family to a strictly newer revision in the same transaction. Existing immutable
signed revisions remain stored for audit and rollback detection. Policy rows and
their selector relations are copied to the new revision before the canonical
document is re-encoded; a wire epoch must never reuse an existing revision with
different bytes.
