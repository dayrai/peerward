# Peerward storage invariants

The current database uses Schema 4, installation marker `product_major = 1`,
and Wire major 5. This historical marker is a storage generation identifier,
independent of the product SemVer major, which starts at 0 in the new repository. A fresh
installation applies immutable migration 0001 and the complete registered
follow-up chain through 0052. The final `peerward_installation` marker must
match product 1 / Wire 5; earlier deployments without that marker are rejected
before changes. `peerward_install_intent` permits retry of this release's own
interrupted fresh installation, not an implicit upgrade from earlier releases.
Historical migration contents are not rewritten. A recorded migration higher
than the binary's registered chain causes `newer_schema_unsupported` before any
mutation, including when the product/Wire marker otherwise matches. This also
prevents an older binary from silently running after a failed newer upgrade.

Every resource mutation, immutable audit record, and signed-state outbox event
commits in one PostgreSQL transaction. The publisher consumes monotonically by
revision and is idempotent. Signed documents have strict schema/version,
canonical serialization, monotonic revision, `issued_at`, and `expires_at`.

`mesh_names(mesh_id, normalized_name)` is the sole concurrency boundary for
Peer hostnames and Service aliases. IDNA/DNS normalization is shared by create
and patch paths. Unique, foreign-key, check, missing-row, and serialization
failures map to stable 409, 409, 400, 404, and retryable conflict errors.

Join rows retain the UUIDv4 claim ID, digest of the complete canonical signed
request transcript, and exact canonical response document bytes. Ticket lock,
Peer/address/credential creation, audit/outbox, and response persistence occur
in one transaction, so a lost first response is replayed byte-for-byte without
creating or consuming a second resource.

Rotation rows retain the current serial, requested identity, Noise and WireGuard public
keys, current-identity request signature, server challenge, staged credential,
new-identity activation signature, and lifecycle. Activation atomically moves
the old credential to overlap, the staged credential to active, and emits
audit/outbox. Local key commit is a Peer state-machine concern and occurs only
after the exact active serial and all three public keys appear in a verified signed
directory. Replaying any completed transition is safe.

Updater state stores the highest accepted signed manifest sequence and the
canonical manifest digest with atomic 0600 replacement. A sequence may repeat
only with the same digest.

`encrypted_audit_inbox` temporarily stores only Relay-authenticated Mesh/Peer
metadata, ciphertext digest, and the opaque HPKE envelope. Collectors lease
rows with `FOR UPDATE SKIP LOCKED`, verify the Peer identity signature, decrypt,
and atomically insert `processed_peer_audit_batches`, immutable `audit_log`
summaries, and delete the inbox row. The processed-batch primary key makes a
crash or Relay replay a no-op rather than a duplicate audit record.

## Event and maintenance bounds

`event_stream_state` is the singleton durable sequence/high-water and retained
floor. Every `event_outbox` insert, UUIDv4 cursor, and high-water update commits
in the resource transaction; the cursor is unique and the time/sequence replay
indexes are authoritative. Cleanup may remove outbox rows but cannot erase the
last high-water, so consumers distinguish an empty stream from a retention gap.
Relay snapshot and high-water are installed atomically; notifications wake the
reader, while a five-second poll closes notification gaps. A retention gap
causes one complete atomic admission/signed-state snapshot.

Only one Control instance performs each maintenance pass, elected by PostgreSQL
advisory transaction lock. Each table removes at most the configured batch
(default 1000) per pass. Events retain 24 hours and at most the newest 100000;
OIDC flows, web sessions, expired presence/runtime leases, terminal tickets and
rotations retain 24 hours; processed audit batch IDs retain 8 days; released
addresses retain their quarantine plus 24 hours. Signed state and policy retain
the newest two revisions per family/Mesh. Superseded credentials and
Authorities are removed only after `not_after + 24h` and only without a live
reference. `audit_log` is immutable and is never automatically deleted.

The Mesh row stores the next IPAM candidate. Allocation locks that row, performs
indexed point lookups for reserved, active, and quarantined addresses, advances
with wraparound, and reports exhaustion only after one complete range scan. It
must not load the allocation set into application memory. Pagination,
credential lifecycle, presence, session expiry, cleanup, and projection reads
have matching compound or partial indexes.

Presence has exactly one globally fenced primary per Mesh/Peer and independent
standby fences per Relay. Migration 8 deliberately preserves the original
`relay_presence(mesh_id, peer_id, role)` conflict target for binaries that are
still running during a rolling upgrade. New standby leases are stored in the
per-Relay `relay_standby_presence_v1` extension and all upgraded projections
read the deduplicated `relay_presence_all` view. A standby generation starts
above an equivalent legacy row and thereafter increases per Relay, so a
legacy-to-upgraded handoff cannot roll its fence backward. Peer or Relay
deletion cascades through both stores; disable and maintenance paths explicitly
clear both.

Publisher work is revision-driven. Startup reconciles all families; event
wakeups are coalesced for 100 ms; a five-second interval is a fallback. Only
changed state families may scan/build/sign, and a pass with no changed revision
does zero projection builds. Audit collection is independently scheduled.
Multiple instances use a per-Mesh advisory lock before signing.

The five-second publisher fallback also runs bounded lifecycle reconciliation:
active rows at `not_after` and overlap rows at `overlap_deadline` atomically
become revoked, emit audit/outbox records, and advance only their affected
signed-state families. Time passing therefore cannot leave stale DNS, policy,
service, admission, or revocation projections behind an unchanged revision.

Every stored signed-state body is nonempty and at most 32 MiB. This database
constraint is identical to the bounded Wire reassembly limit, so a successfully
published revision is distributable to Linux and Android consumers.


## Dynamic Mesh lifecycle (release schema 2)

Migrations 0013 and 0014 add lifecycle/revision, registered Relay hosts, unique
(host, Mesh) assignments, fenced leased jobs and public signed tombstones.
Migration 0015 pins validation-function search paths for isolated dump restoration.
Historical migrations remain immutable. Request UUID identifies one create job
and one generated Mesh; delete is unique per Mesh. Deleting is terminal.
Ordinary child mutations take a parent lifecycle lock; job updates compare
lease owner, expiry and generation. Successful waiting polls do not count as
failures. Audit/outbox history and encrypted recovery archives survive business
row deletion. Pending host removal remains visible until that host confirms
the exact version. Private keys never reside in these tables.

Control and each Relay use separate private persistent storage, owner-only
permissions, temporary files, fsync and atomic rename. A managed bundle is
written once before database identity publication and reused after a crash.
Per-Mesh Root recovery uses RFC 9180 Base mode X25519/HKDF-SHA256/ChaCha20Poly1305,
with `peerward/root-recovery/v1` domain separation, Mesh/root binding and a Root
signature. Only the recipient public key is installed on Control. Online
Authority seeds and distribution/audit seeds stay in the Control private volume;
Relay Noise seeds are generated on the assigned host. Offline imports must
match the staged Root-certified Authority before Control reloads them.

Credential columns first added by migration 0018 and the current exact generation bindings are
defined in [WIREGUARD_CREDENTIALS.md](WIREGUARD_CREDENTIALS.md).

Migration 0019 replaces the endpoint validator in place to admit canonical
`wss://host:port/peerward` alongside `tcp://host:port`. Endpoint lists retain
their count/uniqueness constraints. Numeric IPs must be canonical, nonzero and
nonmulticast; WSS requires an explicit port and its fixed path. Historical
migrations remain unchanged. A database upgraded through 0019 is required
before publishing WSS host assignments. This historical migration was introduced
under storage compatibility 3; current compatibility is 4.

Migration 0020 extends that validator to canonical `quic://host:port` endpoints
without a path, query, fragment or user information. The nonzero explicit port,
canonical numeric address and bounded unique list rules are unchanged. Upgrade
through 0020 before advertising QUIC Peer/backbone assignments. Historical
migrations are not rewritten. The historical QUIC carrier format remains unchanged;
The current release uses authenticated Wire major 5 and storage compatibility 4.

Management migrations 0021–0046 add approved resources/bindings and withdrawal
fences, tested resource policy, signed-configuration leases and receipts, controlled
enrollment/lifecycles, dual-stack allocation, scoped DNS/collections/automation,
maintenance tasks, restricted installation runners and host capacity observations.
Migration 0044 stores only one latest and one previous aggregate observation per
host. Nonces and observations never grant network authority. Backup inventory
uses the complete current migration checksums and rejects an older binary
masquerading as this deployment; restore verification never starts applications.
Migration 0045 permits the fixed native upgrade operation. Migration 0046 stores
independent task recovery generations and immutable recovery request IDs bound to
task, expected version and actor. Recovery requests, task updates and audit events
commit together. They authorize a fixed local continuation, never a supplied command.
