# Wire 5 encrypted connection coordination

This is a Peerward channel inside standard WireGuard IP packets. It is not an
extension to the WireGuard handshake or an ICE interoperability protocol.

## Inner packet

Both UDP ports are 51821. IPv4 uses a 20-byte header without options or fragments;
IPv6 uses a 40-byte header and UDP directly, without extension headers. Normal IP
length and checksum validation applies, including the IPv6 UDP checksum. Source
and destination must match the exact authenticated credential bindings in the
Root-verified signed directory. Coordination is intercepted before application
ACL evaluation and never delivered to TUN. TUN-origin traffic with either UDP
port equal to 51821 is denied, including traffic reassembled from fragments.

## UDP payload version 1

All integers are unsigned, big endian. Trailing bytes, unknown versions/types,
nonzero reserved bytes, malformed lengths and duplicate endpoints are rejected.

| Offset | Bytes | Meaning |
| --- | --- | --- |
| 0 | 1 | Version, exactly 1 |
| 1 | 1 | 1 candidates, 2 candidate acknowledgement, 3 probe, 4 probe acknowledgement, 5 padded MTU probe, 6 gateway check, 7 gateway acknowledgement |
| 2 | 2 | Zero |
| 4 | 8 | Sender path generation for types 1–5; binding version for types 6–7; acknowledgements echo the initiating value |
| 12 | 16 | Random transaction; acknowledgements echo it exactly |
| 28 | variable | Candidate list for type 1; 1..9000 zero bytes for type 5; binding UUID for type 6; binding UUID and readiness byte for type 7; empty for types 2–4 |

A candidate list begins with a one-byte count, 0 through 32. Each endpoint is a
one-byte family (4 or 6), four or sixteen address bytes, and a two-byte nonzero
UDP port. The largest candidate payload is 637 bytes. The largest padded probe payload is 9028 bytes. Unspecified, loopback, multicast,
IPv4 limited-broadcast and IPv6 link-local/scoped addresses are not candidates.
An empty list is valid and preserves Relay fallback. Priority follows list order;
no public key, policy, service, arbitrary command or diagnostic payload is carried.

Candidate updates and their acknowledgements travel over authenticated Relay
ingress, after WireGuard encryption. Candidate transactions are retried after two
seconds until acknowledged. A lower remote generation, or different advertised
endpoints within the same generation, is rejected. A local network update
invalidates pending probes and prior path validation, but retains WireGuard
sessions. At startup the private signed-state checkpoint reserves a local range
of 2^32 generations above both its previous durable ceiling and the wall-clock
startup seed. The ceiling is committed before candidates can be advertised; restart
and clock rollback never reuse the previous range. Exhaustion rejects further path
updates until a new range is allocated by restarting the owner. Network changes
within a range do not cause disk writes or rekey WireGuard. Candidate addresses and
remote candidate observations remain memory-only; this does not protect against
restoration of the entire device filesystem or provide hardware monotonic storage.

## STUN discovery configuration

Join and device profiles accept up to eight unique STUN endpoints, encoded as
`host:port` or `[IPv6]:port`, with a required nonzero UDP port. ASCII DNS names
are normalized to lowercase; URI schemes, credentials, paths, scoped/link-local
IPv6, unspecified, multicast and limited-broadcast literals are rejected. Empty
lists remain valid. STUN server addresses are discovery inputs, never authorized
Peer candidates or direct-connectivity evidence by themselves.

Dynamic installations configure `stun_servers` once at the top level of
`control/dynamic.toml`; all managed issuers use it for new Join responses,
including previously created Meshes. Reading existing issuer bundles overlays
only this discovery metadata in memory and preserves credential material on disk.
The Relay's `stun_addresses` are host-level listeners independent of Mesh count.
New Compose installations use a shared UDP 3478 listener; the installer can
select a different published host port. Existing installation files are never
rewritten by bootstrap. Already joined clients need a local configuration update
or a new Join to receive changed STUN settings; online distribution is not yet
implemented. Native test installations opt in to a separately reserved UDP port.

Linux resolves afresh for each discovery round; Android resolves on the same
`Network` as its protected data socket and refreshes every 60 seconds (15 seconds
after an empty result). Resolution has a one-second waiting budget and returns
completed results despite another server's failure. Each family keeps at most
eight unique resolved destinations, giving each configured server a slot before
additional answers. Blocking OS lookups may outlive the wait, but occupy bounded
process resources until completion: 16 Linux permits, four Android workers with
no waiting queue. DNS completion never delays an established Relay or TUN owner.
OS resolver caching/TTL and DNS64 behavior remain underlay-dependent; this is not
a measured NAT64 reachability guarantee.

STUN requests, responses and WireGuard continue to use the same family-specific
data socket and transaction demultiplexer. Android replaces only the STUN
transactions and observations when resolved endpoints change, retaining the
WireGuard session and data socket. Old observation indices cannot refer to new
DNS destinations. No candidate addresses are added to diagnostic uploads.
Android network resolution follows the documented
[Network.getAllByName contract](https://developer.android.com/reference/android/net/Network#getAllByName(java.lang.String)).

## Confirmation, budgets and fallback

Path probes (types 3–5) and their acknowledgements are accepted only on actual direct UDP ingress.
A successful probe acknowledgement must match the credential, local generation,
transaction and exact probed endpoint, within one second. A Relay-delivered copy,
an unsolicited reply or the first authenticated incoming probe cannot validate a
path. An incoming probe may create a bounded triggered check for its source.
Probes are encrypted only when a WireGuard session is immediately ready; they
are not retained in a plaintext queue or counted after a delayed handshake.

Only the active local and remote credential pair owns coordination state; valid
overlap engines continue to process application traffic. The current scheduler
limits each Peer to 32 remote endpoints, 128 local/remote candidate pairs and
four simultaneous checks; each Mesh has 64 checks and 256 tracked Peers,
and the process has 256 checks. At most eight actual local socket endpoints
participate. Pairing is address-family compatible and visits every remote
candidate before assigning further local choices. The local socket identity is
internal runtime metadata, never an additional field in the encrypted candidate
message. An ACK must return through both the exact remote endpoint and the
actual local socket used for its transaction. Linux binds each socket to its
interface/address; Android binds protected sockets to addresses of its Network.
An empty local socket set produces no direct checks and retains Relay service.
Check permits are released on reply, timeout, network change, credential removal
and runtime drop. Changing candidates never rebuilds a WireGuard engine.
Inbound coordination is limited to 32 messages per remote credential, 1024 per
Mesh and 4096 per process per second.

Active checks run at one-second intervals; without successful replies, direct
health expires after three seconds. After 30 seconds without application data,
checks use 25-second intervals and a 30-second health lifetime. Probe traffic
does not itself make an idle application active. Switching between healthy
endpoints requires five seconds on the current selection and an improvement of
at least 20 percent plus five milliseconds in measured cost. Cost combines RTT
EWMA and the loss fraction of authenticated health checks (one second penalty
at total loss); missing oversized MTU probes do not penalize small-packet health.
Active healthy paths check one alternate candidate pair every five seconds,
within the same concurrency budgets. Idle paths avoid this extra work.
A failed current path may switch
immediately to another verified endpoint or use Relay.

Before a size proof, direct forwarding is limited to 96 ciphertext bytes,
no more than the actual small authenticated check. A small response cannot
establish an assumed 1280-byte underlay. After a direct round trip, the
scheduler sends a type 5 probe with a legal inner IP packet padded to the
configured TUN MTU. The type 4 reply echoes its transaction and generation.
Only its timely, exact pair acknowledgement proves the actual ciphertext
size: inner packet plus 32 WireGuard bytes. The first/full probe is capped at
the configured TUN MTU (including odd MTUs); intermediate sizes are multiples
of 16 to account exactly for standard WireGuard padding.

Three unanswered size probes lower the search ceiling; successful probes raise
the known lower bound. The bounded search converges within a 16-byte interval,
refreshes the working size, and retries the full TUN size after 30 seconds.
Small health acknowledgements do not refresh a larger size proof. Proofs expire
after three seconds while active or 30 seconds while idle, and are discarded
on selected-pair or network-generation replacement. Probe traffic shares the
Peer/Mesh/process budgets. Lost large packets may therefore use Relay while
smaller authenticated traffic continues over the same direct WireGuard session.

Linux and Android disable IPv4/IPv6 source fragmentation on their data sockets,
including Android IPv4-mapped sockets. A direct probe or reply that cannot be
sent is discarded, never queued for Relay. Application ciphertext may fall back
without resealing on writer failure. The measured size belongs only to the
probed endpoint, direction, credential and network generation; this mechanism
does not claim full RFC 8899 state-machine conformance. QUIC ciphertext
fragmentation is specified separately in [QUIC_CARRIER.md](QUIC_CARRIER.md);
WSS relies on TCP segmentation. Neither changes standard WireGuard datagrams.

Linux maintains independent mapping leases per bound path and gateway. IPv6 link-local PCP destinations carry the
interface scope of the selected data socket.
PCP/NAT-PMP exchanges use that same data socket, with bounded retransmission,
source/nonce/internal-port matching and a separate demultiplexing registry.
Renewal retains the assigned endpoint; NAT-PMP deletion sends external port
zero. Cleanup never deletes a renewed PCP/NAT-PMP mapping merely because its
external endpoint changed. UPnP discovery/renewal/deletion must select the
expected gateway, and renewal refreshes its external IP. Removing one path
retires its leases without closing unrelated sockets. Candidate observations
are refreshed at most 60 seconds apart (25 seconds with prediction enabled).
IPv4 and IPv6 default gateways are enumerated independently per interface.

## Queue lifecycle

Root/Authority, directory, policy and expiry checks precede data admission.
Queued original IP fragments retain the complete reassembled flow decision;
authorization and policy are checked again when WireGuard can encrypt them.
Platform-bound decrypted deliveries and Relay-bound ciphertext carry a local
authorization epoch and a three-second deadline. Neither field is serialized
into WireGuard. A signed-state change invalidates the corresponding old queue
decisions before the platform writer accepts them.

References: [WireGuard protocol](https://www.wireguard.com/protocol/),
[ICE connectivity checks](https://www.rfc-editor.org/rfc/rfc8445.html).

## Approved gateway checks

Types 6 and 7 are fixed-size gateway checks on the existing encrypted carrier.
The body contains a version-4 UUID identifying an approved binding; type 7 adds
one readiness byte, exactly zero or one. The header generation is the positive
binding version and its transaction is freshly random for each attempt. These
messages contain no command, external probe address or application payload.

The consumer coalesces bindings per provider and sends one check every five
seconds through the current authenticated direct path, or Relay when no direct
path is available. A response must match the pending transaction, binding version,
both active keys, exact carrier path and five-second deadline. It is consumed once.
The provider acknowledges readiness only while its signed authorization and OS
resource transaction are live, and the referenced binding is approved and published.
A gateway check establishes transport readiness, not LAN application health.

A new approved provider starts as unknown with a bounded 15-second discovery
window. Three consecutive failed checks exclude it. Recovery needs three successful
checks and a continuous 30-second stability window before new connections prefer
a recovered primary. Equal priorities use stable Peer and binding identifiers.
Healthy backup connections stay pinned; no SNAT connection state is replicated.
Peerward does not promise loss-free datagrams during queued-output invalidation.

Checks are bounded by the signed binding set (at most 8192), with one outstanding
check per provider; replies are limited to 512 per runtime per second. The existing
carrier queues and credential/session limits still apply. This is distinct from
the candidate-probe budgets above and is not a measured maximum deployment size.
