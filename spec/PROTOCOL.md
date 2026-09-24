# Peerward Wire v5 and WireGuard session specification

## Version and suites

- Authenticated Wire major is exactly `5`; other majors are rejected during the Noise handshake before admission or business records.
- Link Noise retains the carrier-format prologue `peerward/noise/v4`. This domain and the v4 routing preface identify the unchanged carrier layout, not the authenticated Wire major.
- Peer-to-Relay links use Noise IK; Relay backbone uses Noise KK.
- End-to-end device data uses standard WireGuard with GotaTun 0.9.2;
  its handshake, cookie and data datagrams are unchanged.
- Signed identities and canonical directories use Ed25519.
- Peer security audits use HPKE Base mode with DHKEM(X25519, HKDF-SHA256),
  HKDF-SHA256, and ChaCha20-Poly1305. The Control recipient X25519 key is
  Authority-bound in the 208-byte Distribution Certificate.
- Named optional capability bits are `TRACE_CONTEXT_V1` (`1 << 0`),
  `EXTENDED_CANDIDATES_V1` (`1 << 1`), and `SPARSE_BACKBONE_V1` (`1 << 2`).
  A runtime advertises only implemented bits; it never uses an all-bits mask.

## Layering

Link Noise authenticates the connecting Peer or Relay and carries control or
opaque routing records. Relay discards plaintext IPv4/IPv6 records. A Peer
creates one Peer-to-Peer session whose ciphertext is identical on direct UDP
and Relay paths. Direct candidates, migration, and path-switch messages are
inside the end-to-end encrypted control stream.

`ControlEnvelope` protobuf tag 25 optionally carries a UUIDv4 request ID,
16-byte nonzero trace ID, 8-byte nonzero span ID, and flags. The receiver
strictly validates it and creates a new stage span ID. Baggage is not carried.
Old consumers ignore the field, and it is excluded from all existing signed
credential and directory transcripts.

`RelayEnvelopeV2` contains only mesh ID, destination Peer ID, frame kind,
length, and opaque payload. The authenticated link overwrites the source Peer
ID; a client-supplied source is never trusted. Relay validates admission,
revocation, length, rate, queue, and resource limits, then routes without
opening the payload.

`OpaqueFrameKind::Audit` uses the all-zero, non-UUID destination reserved for
Control. The Relay binds the authenticated link source and enqueues the opaque
envelope through a bounded database actor; it never decodes the envelope.
Peers aggregate at most 64 payload-free direction/reason/count records per
batch. The HPKE associated data and Ed25519 identity signature bind Wire major,
Mesh, source Peer, UUIDv4 batch ID, encapsulated key, and ciphertext digest.
Control accepts active/overlap identity keys, rejects stale timestamps and
source mismatches, and deduplicates the batch ID transactionally. IP addresses,
ports, DNS names, service identifiers, and packet payloads are never collected.

Standard WireGuard receiver indices select existing sessions; initial handshakes
undergo MAC validation and rate limits before authorized-key lookup. Every
decrypted source address must belong to the authenticated Peer before ingress
ACL evaluation. No legacy device generation or Offer/Answer fallback is allowed.
Wire 5 retains the retired ControlEnvelope tags 10, 11, 12, 13 and 23;
canonical decoding rejects their old Offer/Answer/probe/request encodings.
Opaque frame kind 0 is retired; kind 1 contains standard WireGuard datagrams
(including their handshakes), and kind 2 contains HPKE audit material.
The old PWD2 records, device KDF and generation negotiation are removed from
production crates and fuzz targets. Relay Noise remains independently authenticated.
Credential and directory encodings are defined in [WIREGUARD_CREDENTIALS.md](WIREGUARD_CREDENTIALS.md).

## Link records and signed-state distribution

Every post-handshake link record has a four-byte big-endian ciphertext length;
zero and values above 65535 are rejected before allocation. All Authority,
Peer, Relay, policy, service, and exact-revocation signed states are transported
as typed chunks carrying Mesh UUID, signed revision, zero-based index, exact
count, and a nonempty body. Senders use bodies no larger than 48 KiB. Receivers
allow at most 1024 chunks and 32 MiB for one complete state, reject wrong Mesh,
rollback, duplicate/missing/mixed chunks and revision mismatches, and install
only after complete reassembly, strict decoding, and signature verification.
No signed-state family may rely on a single Noise record fitting its complete
serialized representation.

`RelayTopologyV1` is an independently domain-separated signed state; it does
not change the Relay Directory signature. Fewer than eight Relays, or any
active Relay without `SPARSE_BACKBONE_V1`, selects full mesh. Otherwise each
region connects two forward rings, every member connects to two stable
high-weight regional gateways, adjacent regions retain two gateway-ring lanes,
and regional gateways connect through two deterministic global shortcuts. The
resulting edge set is O(N) and has a four-hop diameter. Routed records bind
topology revision, origin,
optional destination, hop limit (maximum four), and at most four unique visited
Relays. Current and previous revisions overlap for 60 seconds. A Relay rejects
loops, non-neighbors, expired revisions, and exhausted paths. Signed edges
carry bounded RTT EWMA and loss-permyriad costs aggregated by Control from the
fenced 15-second neighbor reports. Membership, capability, or edge-set changes
publish immediately; health-only topology publication is rate-limited to one
revision per 30 seconds. Every Relay deterministically selects the lowest
cost primary and backup paths within the four-hop bound.

Mapped candidates target the corresponding family data socket and try PCP,
NAT-PMP, then UPnP. A network-generation change forces rediscovery; gateway epoch
regression invalidates the lease, and expired mappings are withdrawn. Port
prediction remains opt-in and bounded. Mapping or STUN success only creates a
candidate. Candidate exchange and authenticated round-trip checks follow
[WIREGUARD_COORDINATION.md](WIREGUARD_COORDINATION.md); they never use legacy
Offer/Answer or replace WireGuard sessions on network changes.

A Peer maintains one control-primary Relay and at most two warm standbys. The
primary Presence fence is global; standby fences are keyed by Relay. Opaque
data sent on a standby remains flow-pinned and does not promote that session.
Only an authenticated control mutation promotes a standby and replaces the
single primary fence. During rolling upgrade, the legacy single-standby row is
kept readable alongside per-Relay standby rows and exact duplicates are
suppressed.

## Rekey state machine

WireGuard timers own device handshake retry, keepalive, cookie handling,
replay windows and rekey. The adapter is driven at most 250 ms apart while
active, including while Control or Relay is offline. Path changes retain the
same session; only a credential/key generation change creates a new device
engine with a bounded previous-generation overlap. Link Noise is refreshed by
a separate connection, confirmation, routing switch and old-connection drain.

## Credential rotation

Rotation is a crash-recoverable transaction. The old Ed25519 identity signs a
canonical request covering Mesh, Peer, rotation ID, current serial, and all three
new public keys. Control persists pending state and a random one-time
challenge. After Authority issuance, the new identity signs a canonical
activation transcript covering the issued serial and challenge. Control then
atomically activates the staged credential, moves the old credential to
overlap, and writes audit/outbox. Relay admits only active/overlap signed-state
credentials and never activates database state. The Peer stages all four
local artifacts, waits until a signed directory publishes the exact new active
serial plus identity, Noise and WireGuard keys, and only then commits local state and replaces
connections. Every request, issuance, activation, publication, and local file
transition is idempotent.

## Shared Relay routing preface (carrier format 4)

Before a length-prefixed Noise frame, Peer and Backbone reliable carriers send
exactly 56 bytes. No variable-length field or Mesh key trial is permitted.

| Offset | Length | Encoding |
| --- | --- | --- |
| 0 | 4 | ASCII `PWR4` |
| 4 | 1 | Routing preface format `4`; authenticated Wire major is carried inside Noise |
| 5 | 1 | Role `1` Peer or `2` Backbone |
| 6 | 2 | Zero reserved bytes |
| 8 | 16 | Mesh UUIDv4, network byte order |
| 24 | 16 | Target logical Relay UUIDv4 |
| 40 | 16 | Source logical Relay UUIDv4 for Backbone; all zero for Peer |

The source and target of a Backbone cannot be identical. Prologue is
`peerward/noise/v4` followed by `/relay`, one NUL byte, and all 56 preface bytes.
The selected Mesh context must independently authenticate Noise identity,
Root/Authority trust, validity, revocation and the exact local Relay assignment.
Admission quotas and a five-second preface timeout apply before context lookup.
Direct Peer transport uses standard WireGuard datagrams. The existing
`RelayEnvelopeV2` type name is a Relay framing identifier, not acceptance of
Wire major 2. Peers and backbone links reject old majors.

### WSS reliable carrier

The canonical endpoint is `wss://host:port/peerward`, with an explicit nonzero
port (including 443), ASCII DNS or bracketed IPv6 host, and no user information,
query or fragment. TLS validates the server chain and endpoint hostname. Public
WebPKI roots are the default; explicitly configured private CA PEM replaces
them. There is no certificate-validation bypass. Native `tcp://host:port`
remains an advanced Wire 5 carrier using the existing framing.

WebSocket binary messages carry the unchanged reliable byte stream: preface,
u16-length Noise handshake, then u32-length Noise records. Message boundaries
are independent of Wire record boundaries. Text messages are rejected; each
frame/message is bounded to 65539 bytes. Each direction has a 65536-byte pipe
plus bounded message buffering. Flush/shutdown wait for accepted bytes to be
written. Ping/Pong are carrier maintenance, never evidence of direct reachability.

One host-level WSS listener serves every Mesh and both roles, routed by the
authenticated preface. Global session, handshake and source-IP budgets apply
before TLS/WebSocket upgrade. A plaintext upgrade backend is allowed only on
loopback behind an HTTPS reverse proxy; client endpoints remain WSS. Forwarded
HTTP headers do not override admission identity or source-IP budgets.

An explicitly configured HTTP CONNECT proxy may carry WSS. The client connects
to the proxy through the platform-protected socket and asks for the target
authority (bracketed for IPv6), then validates end-server TLS and Relay identity
inside the tunnel. It accepts status 200 only, does not follow redirects, bounds
response headers to 8192 bytes and leaves coalesced tunnel bytes unread. Upgrade
is bounded to five seconds. Environment/PAC proxies and proxy authentication
are not implemented. WSS uses TCP segmentation and does not modify WireGuard
packets. QUIC DATAGRAM framing is defined in [QUIC_CARRIER.md](QUIC_CARRIER.md).

### Peer connection selection

After Root-authenticated IK (and QUIC exporter binding where applicable), the
selected Peer connection sends a ControlEnvelope Welcome with the exact Mesh,
no trace context, and body `link_admit`. The server waits at most five seconds
before allocating presence/primary generation, then replies with `link_ready`.
Prepared, losing address/carrier attempts must close without `link_admit`; they
must not replace the winning connection's lease. This phase applies to all
Wire 5 Peer carriers, including native TCP and WSS, but not KK backbone links.
This development protocol requires paired client/server rebuilds; there is no
fallback to a pre-selection-phase development build.

A deleted Mesh may return a u16-length-prefixed signed terminal record instead
of a Noise response. This unauthenticated transport is safe only when the Peer
verifies the record against its pinned Mesh Root before acting. Unknown Meshes
are closed without key search. A terminal record is also carried in the existing
`GracefulClose.body` on authenticated online links.

## Permanent Mesh termination

The canonical record is 228 bytes: `PWM1` (4), monotonic lifecycle revision
(u64 big endian), termination Unix time (u64 big endian), Root-signed Authority
certificate (144), and Authority Ed25519 signature (64). Signature binds the
record's fixed domain and all prior fields. Verification checks the original
Mesh/Root, the Authority at the termination time, no excessive future timestamp,
and a strictly newer lifecycle revision. Before accepting a new statement,
Peers also reject an Authority serial in their trusted revocation history:
the signer-controlled termination time cannot override a known revocation.
Expiry after signing does not expire an otherwise trusted permanent statement.
Peers persist it before shutting down Mesh resources;
restart cannot restore old state. Offline devices that have not received it keep
the existing direct-session/credential policy.
