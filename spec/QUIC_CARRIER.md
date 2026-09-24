# Wire 5 QUIC Relay carrier (carrier format 4)

Canonical endpoints are `quic://host:port` with an explicit nonzero port, ASCII
DNS or bracketed IPv6 host, no user information/path/query/fragment. Optional
host UDP listeners (at most one per family) serve all assigned Meshes and both Peer/backbone roles. Ports
are host configuration, not allocated per Mesh. TCP 443 WSS and UDP 443 QUIC may
coexist. Explicit HTTP CONNECT selects WSS; QUIC cannot traverse that proxy.

## Authentication and selection

TLS 1.3 validates the certificate chain and endpoint hostname using public
WebPKI roots or explicitly configured local CA PEM. ALPN is `peerward-relay-4`.
ALPN and exporter names retain carrier format 4; the authenticated Noise payload
must independently declare Wire major 5. These names do not permit a Wire 4 client.
Early business data is forbidden: the client awaits full TLS, the server permits
no early data. One bidirectional reliable stream and zero unidirectional streams
are allowed. Before TLS acceptance the host applies existing global session,
source-IP and handshake limits, retrying unvalidated addresses statelessly.
Connection migration is disabled; platform network replacement opens a new
protected carrier while retaining the WireGuard owner and valid sessions.

The stream carries the canonical 56-byte preface, u16-length Noise IK/KK and
existing Root/Authority, Mesh, role, static-key, credential validity, revocation
and assignment checks. Unknown Meshes do not trigger a key search. Only after
these checks does the runtime admit QUIC DATAGRAMs. TLS alone is not Mesh
authorization. Peer selection uses `link_admit` / `link_ready` as specified in
[PROTOCOL.md](PROTOCOL.md); losing prepared attempts never acquire presence.

Both directions first exchange an authenticated Noise Welcome with the exact
Mesh, no trace, and body:

`quic_datagram_binding_v1\0 || exporter[32] || receive_token[32]`

TLS exporter label is `EXPORTER-Peerward-Relay-Wire4`, context is the entire
canonical preface. The random receive token is unique per connection/direction.
Binding must match in both directions within five seconds; the binding record
is at most 256 bytes. Each outgoing DATAGRAM starts with the remote receive
token. This prevents pre-binding cached datagrams or relayed Noise authentication
on a different TLS connection from becoming admitted traffic.

## Reliable records and receipts

After binding, a canonical ControlEnvelope is wrapped in Noise Welcome:

`quic_record_v1\0 || sequence:u64be || canonical_control_envelope`

The receiving carrier returns another Noise Welcome:

`quic_receipt_v1\0 || sequence:u64be`

Each direction starts at one and advances monotonically without reuse. Receipt
is cumulative, bounded by the last sent sequence. At most 32 complete locally
accepted frames may await completion and each expires after five seconds.
Receipt means the entire frame was copied to the bounded runtime input pipe;
it is **not** proof of durable policy/deletion processing. Local flush waits for
this receipt; a final authenticated Close is flushed before retiring the link.
For pre-Noise `PWM1` signed terminal responses, the Peer first verifies its Root
signature and exact Mesh, then sends `PWTA`; the server waits at most five seconds.

The in-process record adapter uses `u32be length || PWLC || ControlEnvelope`,
with at most 65535 bytes after the length prefix and a 65536-byte duplex pipe.
This codec is created only by the carrier and is never transmitted on the
network. It cannot be decoded as a Noise network record. Partial reads survive
cancellation; canceled/failed reliable writes fence both halves. Existing Noise
soft/hard rekey limits include binding time and still trigger replacement.
At most two additional encoded frames (131078 bytes) may await delivery to the
pipe. DATAGRAM reads pause while a delivery is pending; reliable reads continue
while one frame slot remains, so data backpressure does not hide heartbeats or
receipts. Reliable frames are never discarded to make room for ciphertext.

## Ciphertext DATAGRAMs

The reassembled message is a **canonical whole ControlEnvelope** whose message
is Opaque Session or the existing Forwarded backbone wrapper around Opaque
Session. Peer-side Forwarded messages are forbidden. The wrapper preserves all
source/destination generations, origin/destination Relays, topology revision,
hop and visited metadata. Existing authorization, source overwrite, presence
generation fences, quota and loop checks run after reassembly as before.

The Opaque Mesh must match. Peer source is empty before authenticated source
binding; Relay source is exactly one Peer ID. DirectOffer/Answer, plaintext IP,
audit and arbitrary control messages cannot use this lane. WireGuard decryption,
inner source attribution, replay and ACL checks remain in the shared engine.
Candidate coordination remains encrypted inside WireGuard, never in Relay
control metadata. Receiving a Relay DATAGRAM cannot confirm a direct path.

Each DATAGRAM contains `receive_token[32] || fragment_header[24] || payload`.
The fragment header is big endian:

| Field | Bytes | Rule |
| --- | ---: | --- |
| magic | 4 | `PWQ1` |
| frame ID | 8 | Starts at one, strictly increasing per sending connection |
| total size | 4 | 1–65535 including the canonical envelope |
| stride | 2 | Payload size of each nonfinal fragment |
| index | 2 | Zero based |
| count | 2 | 1–64; equals ceil(total size / stride) |
| reserved | 2 | Zero |

Each connection admits at most 32 unfinished frames and 256 KiB, reserving the
whole size on the first fragment. Shared process budget is 64 MiB; each Mesh
budget is 4 MiB, with at most 1024 live Mesh budget entries. All layers reserve
atomically or release on failure. Two-second fixed expiry cannot be extended
by duplicates. Conflicts discard the whole frame. A 1024-ID sliding window
rejects completed, expired, quota-discarded and too-old IDs. Close releases all
reservations immediately. The receive actor sweeps expiry even without traffic.

Senders check available queue space for **all** fragments before sending any;
queue pressure drops ciphertext without buffering plaintext or silently moving
it to the reliable lane. Actual loss can still yield an incomplete frame. Only
complete validated envelopes enter application routing or WireGuard.

Current implementation caps outer UDP payloads at 1200, disables upward PMTU
discovery and UDP GSO, and calculates each fragment against Quinn's actual
DATAGRAM limit after token/header overhead. IP fragmentation is not used to
carry oversized ciphertext. A path unable to carry QUIC's minimum payload
requires another carrier. This conservative choice needs throughput evaluation.

## Health and platform lifecycle

Authenticated internal Welcome bodies `quic_ping_v1\0 || sequence:u64be` and
`quic_pong_v1\0 || sequence:u64be` test remote carrier progress. Active means
ciphertext data seen within three seconds. Active probes use 500 ms intervals,
750 ms deadlines and two misses before retirement; idle intervals are 25 seconds.
Ping sequences increase, at most four per second. Only the exact outstanding
pong clears misses. Neither pong nor receipt implies direct path health.

Linux races Root-authenticated prepared endpoints and address families at 250 ms
stagger, preferring QUIC, WSS, then advanced TCP. Android races platform-selected
carrier establishment using Network DNS and protected/bound TCP or UDP sockets;
only the selected carrier enters Noise and Root verification. JNI installs a
closeable handle before blocking TLS/QUIC/CONNECT. Cancellation closes losing
attempts without holding the process-wide session registry. Android network
replacement preserves TUN, policy and effective WireGuard sessions.

References: [RFC 9000 §14](https://www.rfc-editor.org/rfc/rfc9000.html#section-14),
[RFC 9221](https://www.rfc-editor.org/rfc/rfc9221.html),
[TLS exporters](https://www.rfc-editor.org/rfc/rfc8446.html#section-7.5).
