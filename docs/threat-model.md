# Threat model

Peerward protects mesh confidentiality, endpoint identity, address ownership,
policy integrity, update ordering, and administrative auditability against
untrusted networks, compromised peers, replay, stale relays, and accidental
operator error.

## Assumptions

- The offline root key and operator recovery material remain confidential.
- Host kernels, Android Keystore, PostgreSQL, and configured upstream DNS/TLS
  roots behave as documented.
- Operators secure the control/console ingress with HTTPS and protect external
  secret delivery and backups.
- Denial of service by an on-path adversary cannot be eliminated; queues,
  parsing, assembly, sessions, and audit emission are bounded.

Control request bodies are capped at 2 MiB. Join, Console success/error, and
SSE-event reads are capped at 1 MiB, 2 MiB/64 KiB, and 256 KiB using
`Content-Length` preflight plus streamed `limit+1` reads. The Console proxy
accepts only a credential-free HTTP(S) origin with no query, fragment, or
subpath, removes hop-by-hop headers, and times out connect/request/SSE idle at
5/15/45 seconds.

## Controls

Credentials bind mesh, role, subject, independent Ed25519 identity and X25519
Relay Noise keys, independent per-generation WireGuard keys for Peers, serial,
and validity with domain-separated transcripts. Link
Noise authenticates routing identities; path-independent WireGuard sessions
reject replay and hide virtual traffic from Relay. Signed ordered directories
prevent address spoofing and stale topology. Stateful endpoint ACL permits
return traffic only for allowed initiations;
fragment and related-ICMP handling requires prior state. PostgreSQL fencing
rejects superseded relay attachments.

Authority-set changes are accepted only as a monotonic bundle whose active
signer certificate is rooted in the offline mesh key. A compromised database
cannot introduce an unrooted authority. Relay opaque-frame forwarding uses an
authenticated presence cache; an authenticated higher fencing generation wins
immediately, including while PostgreSQL is temporarily unavailable. Relay
observes relationship, length, timing, and volume metadata but not virtual
addresses, ports, DNS, or payload; Peerward is not an anonymity network.

Every direct UDP session is bound to one remote peer and its signed address.
The sender cannot reuse a healthy session for another destination, and the
receiver rejects a packet whose source address is not owned by the authenticated
remote peer.

Each family data socket has one UDP receive owner. It classifies STUN only by
magic, exact transaction ID, and expected source before fulfilling a bounded
waiter; WireGuard datagrams use a separate direct queue. Receiver indices select
sessions, and initial handshakes pass MAC/rate checks before authorized-key
lookup. Unmatched, late, and forged replies are dropped. Candidate coordination
is encrypted inside WireGuard; TUN traffic cannot inject into reserved UDP port
51821, and Relay ingress cannot confirm or refresh direct-path health.
PCP/NAT-PMP codecs are length- and field-strict, UPnP is timeout-bounded, and
mapping failure always retains Relay fallback. Network replacement forces
mapping rediscovery; a PCP/NAT-PMP epoch regression invalidates the old lease,
and an expired lease is withdrawn before candidate publication. Android sends
PCP/NAT-PMP only through the protected direct socket. Its separate SSDP and
UPnP HTTP sockets are protected and underlay-bound before I/O; discovery is
source-bound and accepts only bounded numeric-IPv4 HTTP locations. Symmetric-NAT
prediction is off by default, rate limited, narrowly bounded, and cooled after
repeated unstable rounds.

Sparse Relay routes are accepted only against a current/overlap signed topology
and an authenticated adjacent Relay. Revision, hop limit, and visited set bound
loops and stale-path amplification. Mixed capabilities force full mesh. Trace
metadata is strictly sized, contains no baggage, and never changes an
authorization or cryptographic signature decision.

Ticket claims are idempotent transactions. The client signs a claim ID,
Ed25519 identity key, separate Relay Noise and WireGuard X25519 keys, client
version, and supported Wire major; the
server locks the ticket and commits Peer/address/credential/canonical response
with the outbox. The exact same ticket and keys replay the same result while a
key mismatch returns conflict. Android checks the invited root fingerprint and
rooted distribution-key binding before transport. That binding includes the
Control HPKE recipient, so a substituted audit key fails before VPN startup.

Externally controlled cardinality is validated in API, binary decoder, Store,
and critical SQL constraints: 64 labels, 1024 policy rules, 1024 Peer IDs/64
labels/256 CIDRs per selector, 256 port ranges per rule, and 4096 reserved
addresses. SSE replay deduplication retains only 1024 IDs; Control admits only
256 simultaneous streams per instance.

Linux and Android aggregate payload-free policy/security reasons, encrypt them
with HPKE to Control, and sign ciphertext metadata with the Peer identity.
Relay only queues opaque bytes and the authenticated source. Control verifies
active/overlap identities and commits batch deduplication with immutable audit
rows in one transaction.

Android uses direct non-exportable Keystore X25519 for Relay Noise only after a
capability self-test. Otherwise, Rust generates that scalar on-device and Android
stores only AES-GCM ciphertext authenticated with version, alias, and public-key
metadata under a non-exportable Keystore key. Transient scalar buffers are
cleared after wrapping or one agreement. The independent WireGuard scalar is
always wrapped by Keystore and transferred to the Rust engine, whose live key
material is destroyed when that credential generation is removed. Logout and VPN revocation delete the
wrapped record and Keystore aliases. The Peer identity key is generated on-
device. Credential certificate signatures belong to the mesh authority;
device identity signatures prove key possession without exporting the key.

## Out of scope

Compromise of an unlocked root key, a fully compromised endpoint kernel, or an
authorized administrator can subvert that trust domain. Traffic analysis and
availability attacks remain possible. Peerward does not make public traffic
anonymous and does not replace endpoint patching, disk encryption, database
access control, or a tested disaster-recovery program.
