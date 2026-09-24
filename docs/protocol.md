# Protocol guide

The normative wire contract is [`spec/PROTOCOL.md`](../spec/PROTOCOL.md). This
guide explains operational consequences without replacing the frozen text.

The development contract is Wire major 5 with Schema 4. Implementation status
is tracked in the [management implementation status](management-implementation-status.zh-CN.md).
Linux and Android use the shared WireGuard runtime; the legacy device session
engine has been removed. Release qualification remains incomplete and is
recorded separately from implementation and component interoperability.

Wire 5 binds an independent WireGuard public key to each Peer credential
through the Root-certified Authority signature. Credentials are exactly 225
bytes. Join schema 2, Linux Peer config 4, and Android profile 4 require all
three independent identity, Relay Noise and WireGuard public keys. The signed
Peer directory carries one active and at most one previous complete credential,
including the previous generation's exclusive overlap deadline. See
[`WIREGUARD_CREDENTIALS.md`](../spec/WIREGUARD_CREDENTIALS.md) for byte layouts,
transcripts, persistence and rollback constraints.

The device data flow is validated IP and outbound ACL, standard
WireGuard, carrier selection, remote WireGuard, signed source ownership and
inbound ACL, then TUN. All carriers share a credential pair's WireGuard session.
Only authenticated direct round trips confirm a direct path. Candidate exchange
uses encrypted inner IP/UDP on reserved port 51821; packets from TUN cannot
enter that internal channel. Candidate changes must not replace cryptographic
sessions. QUIC DATAGRAM and WSS are connected to the formal Peer pool, shared
Relay host and backbone. Android replaces protected underlay sockets while
retaining valid WireGuard sessions and TUN ownership. QUIC fragments opaque
ciphertext within bounded carrier reassembly; it does not rely on IP
fragmentation. WSS supports an explicitly configured HTTP CONNECT proxy.

Peer-to-Relay stream authentication retains Noise
`Noise_IK_25519_ChaChaPoly_BLAKE2s` with the `peerward/noise/v4` prologue.
Shared Relay ingress binds the exact 56-byte `PWR4` routing preface into the
Noise prologue. Only Wire major 5 is accepted by new binaries. Relay-to-Relay
sessions retain deterministic Noise KK dial direction and opaque forwarding.
The optional bits `TRACE_CONTEXT_V1`, `EXTENDED_CANDIDATES_V1`, and
`SPARSE_BACKBONE_V1` retain their assignments. The extended-candidate bit does
not enable retired Offer/Answer messages or expose candidates to Relay.

After Relay link authentication, a four-byte big-endian length prefixes
encrypted Prost records. Relays accept control and opaque routing envelopes
and reject plaintext IPv4/IPv6 records. Retired device Offer/Answer tags and the
old opaque frame kind are rejected. Device KDF, PWD2 records and custom
generation rekey have been removed; Wire 5 provides no old data-protocol fallback.
Relay stream links retain parallel replacement and draining: a replacement
becomes eligible after authenticated `Welcome(link_ready)`. The old stream's
60-minute / `2^20` message hard limit remains enforced. These Relay-link limits
do not replace standard WireGuard data-session timers.

The six original signed distribution families (Authority, Peer, Relay, policy,
service, and exact revocation), plus independent Relay topology state, are revisioned and transported in nonempty chunks no
larger than 48 KiB. A complete state is capped at 32 MiB and 1024 chunks. A
consumer rejects rollback, mixed or duplicate chunks, invalid signatures,
wrong mesh, stale credentials, and over-bound assembly before replacing live
state. Exact revocations name credential UUIDv4 serials; a replacement
credential remains valid unless its own serial is revoked.

Wire 5 also requires a signed configuration delivery. Its manifest binds exact
versions and digests of Authority, Peer, policy, resource, DNS and revocation
components. A separate signed lease binds that manifest to a monotonic sequence
and a 300, 900 or 3600 second validity interval. Peers enable forwarding only
when all dependencies match and the lease is live; restart and suspend require
fresh authorization. Relay startup requires this delivery alongside the six
original signed families. See the [configuration contract](../crates/peerward-management/src/configuration.rs)
and [lease validation](../crates/peerward-management/src/leases.rs).

Sparse backbone activates only at eight or more active, capability-compatible
Relays. Mixed versions remain full mesh. Routed records carry a signed topology
revision, destination, hop limit four, and bounded visited set; current and
previous revisions overlap for 60 seconds. Presence propagation deduplicates
`(relay_id,generation)`, while forwarded payloads stay end-to-end encrypted.
Authenticated backbone keepalives run every 15 seconds. Each Relay retains an
RTT EWMA and a 32-result loss window, reports bounded neighbor summaries in its
fenced runtime lease, and Control aggregates both directions into signed edge
RTT/loss costs at most once every 30 seconds. Every Relay derives the same
four-hop-bounded primary/backup next hops from those costs without adding
identity labels to metrics.

Sparse construction keeps two forward rings per region, adds two deterministic
high-weight regional gateway spokes, and connects regional gateways through two
global shortcuts. This retains O(N) edges while bounding both intra- and
inter-region paths to four hops. Membership, capability, or edge-set changes
publish immediately for safety; only health-only revisions are throttled to
once per 30 seconds.

Endpoints must parse IP lengths, extension headers, fragments, checksums,
TCP flags, ICMP related payloads, and record boundaries before policy. Unknown,
malformed, spoofed, stale-fenced, or unauthenticated traffic fails closed.
