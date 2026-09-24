# Peerward Noise protocol v1

## Cryptographic suites

- Peer to relay and peer to peer: `Noise_IK_25519_ChaChaPoly_BLAKE2s`.
- Relay to relay: `Noise_KK_25519_ChaChaPoly_BLAKE2s`.
- Credential and directory signatures: Ed25519.
- Root and authority public keys are 32 bytes; Noise static keys are 32 bytes.
- Implementations erase private key buffers on drop where the platform permits.

The Noise prologue is the ASCII byte string `peerward/noise/v1`.  Handshake
payloads carry a protocol major of 1, minor version, capability bitset, typed
credential, and a fresh attachment UUID.  The responder rejects unsupported
major versions and must negotiate only the intersection of capabilities.

## Signed transcripts

Each transcript begins with its ASCII domain followed by NUL.  Integers are
unsigned big-endian.  UUIDs and fixed keys use their raw bytes.  Variable byte
strings are prefixed by a 32-bit length.  Optional values use a one-byte tag.
Collections are sorted by their canonical key before encoding.

Domains are:

- `peerward/root-authority/v1`
- `peerward/subject-credential/v1`
- `peerward/authority-bundle/v1`
- `peerward/peer-directory-entry/v1`
- `peerward/peer-directory-revision/v1`
- `peerward/policy-bundle/v1`
- `peerward/key-rotation/v1`
- `peerward/relay-directory/v2`
- `peerward/policy-document/v2`
- `peerward/service-directory/v2`
- `peerward/direct-candidates/v1`

Golden vectors for every transcript and signature are release-blocking.

## Encrypted stream records

After a Noise handshake, a TCP stream is a sequence of records:

```
uint32 ciphertext_length_be
byte[ciphertext_length] noise_ciphertext
```

Plaintext is `uint16 kind_be`, `uint16 flags_be`, then a Prost payload or raw IP
packet according to kind.  Ciphertext length is at most 65535.  Empty records,
unknown critical flags, kind/payload mismatches, truncated payloads, and trailing
bytes are fatal protocol errors.  Directory data larger than one record is
split into independently bounded chunks carrying revision, index, and count.

Transport keys are rekeyed after 1,048,576 messages or one hour, whichever is
first.  Peers terminate sessions before sequence counters wrap.

## Encrypted UDP datagrams

The authenticated header is:

```
magic        4 bytes = "PWD1"
session_id   uint64 big-endian
packet_no    uint64 big-endian
payload_len  uint16 big-endian
```

The remaining bytes are one Noise ciphertext whose AAD is the complete header.
Each direction uses a random session ID derived during handshake and a strictly
increasing packet number.  A 1024-packet sliding bitmap accepts reordering once,
rejects replay, and rejects packets older than the window.  A datagram from a
new endpoint changes the active endpoint only after authentication succeeds.

The default peer interface MTU is 1380.  Oversized direct packets use relay
fallback rather than unauthenticated application fragmentation.

## Message families

The Prost envelope is a `oneof` with distinct kinds for:

- hello, welcome, keepalive, graceful close;
- root-anchored authority bundle chunks;
- peer directory chunks and policy bundles;
- relay directory chunks, presence updates, and forwarded packets;
- direct-path offers, answers, probes, and results;
- destination-specific direct-path requests;
- service snapshots;
- credential rotation request, replacement, activation, and revocation.

Every resource-bearing message includes its mesh ID.  Revisioned objects reject
lower revisions.  Keepalive replies echo a monotonic timestamp for RTT only;
wall-clock time is never inferred from it.

## Authority bundles

An authority bundle contains a mesh ID, monotonic revision, one active
authority certificate, zero or more unexpired overlap certificates, sorted
revoked authority serials, the signer serial, and an Ed25519 signature.  Every
certificate is independently verified by the configured mesh root.  The signer
must be the active certificate named by the bundle.  A verifier atomically
replaces its trust set only after the complete bundle, signature, validity,
ordering, and revision checks succeed.

## Direct-path identity

Direct-path control messages name both source and destination peer IDs.  The
lower UUID endpoint is the unique IK initiator; the other endpoint may send a
bounded request asking it to start.  Pending handshakes, established sessions,
replay state, endpoint migration, probes, and backoff are independent per
remote peer.  An IP packet may use only the session whose signed directory
entry owns its destination, and received source addresses must match that
session's authenticated peer.

Offers and answers contain at most sixteen canonical IP socket candidates with
a source kind and deterministic priority.  Candidate probing is bounded per
remote peer; the first authenticated Noise IK path wins and all later paths are
ignored unless an authenticated migration is accepted.

## Relay endpoints

Relay directory v2 binds each Relay ID and Noise identity to ordered,
duplicate-free peer and backbone endpoint lists.  Lists contain one through
sixteen canonical TCP URIs.  Receivers resolve DNS names for each connection
attempt, stagger IPv6 and IPv4 attempts, retain per-endpoint health, and reject
the connection unless Noise authenticates the signed Relay identity.

## Policy and services

Policy document v2 signs enabled and audit flags, conjunctive multi-value
selectors, the Any protocol, and deterministic deny-before-allow ordering.
Unknown IP protocol numbers are retained for Any matching but never create
generic connection-tracking state.

Service directory v2 binds a Service ID to its owner, one or both supported
transport protocols, mesh listen port, optional alias, labels and revision.
The peer-local loopback target is intentionally absent from the signed
directory.

## Relay state consistency

Relay startup obtains authority, directory, policy, service, revocation,
admission, presence, runtime generation, and event high-water state from one
repeatable-read snapshot.  Relay-to-relay presence messages carry peer, relay,
attachment, role, fencing generation, and deadline.  They are accepted only on
an authenticated KK link from the named relay and only when their generation
is not older than committed cache state.  The packet forwarding path never
performs a synchronous database lookup.
