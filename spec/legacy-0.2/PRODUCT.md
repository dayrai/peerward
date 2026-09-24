# Peerward v1 product specification

Status: frozen input for independent implementation.

## Product

Peerward is a self-hosted, identity-aware private IPv4 mesh.  A deployment has
one control service, one or more relays, Linux peers, an Android peer, and a
management console.  Peers prefer authenticated direct UDP paths and
immediately fall back to relays when a direct path is absent or unhealthy.

The first public release is 1.0.0.  It has no compatibility contract with any
earlier product, configuration, database, credential, API, URI, or wire format.

## Vocabulary

- Mesh: isolation, addressing, naming, policy, and trust boundary.
- Peer: enrolled workload or user device attached to exactly one mesh.
- Relay: public rendezvous and encrypted packet-forwarding service.
- Join ticket: single-use, expiring authorization to create one peer.
- Authority: online per-mesh signer certified by an offline root.
- Policy: ordered rules controlling initiation between peers and services.
- Service: a peer-owned TCP or UDP endpoint advertised inside a mesh.

All persistent resource identifiers are UUIDv4 values wrapped by distinct Rust
newtypes.  Human names are mutable; identifiers are not.

## Trust and lifecycle

1. An operator creates an offline Ed25519 root.
2. The root certifies an Ed25519 authority for a single mesh and validity
   interval.  Root private material is never required by a running service.
3. A peer or relay owns an X25519 static Noise key.  The authority signs a
   typed credential binding role, mesh, subject, public key, serial, and time
   interval.
4. Credentials support staged replacement, bounded overlap, activation, and
   exact-serial revocation.  Revoking an old serial must not revoke its valid
   replacement.
5. Authorities support overlap during rotation.  Peers retain a root-anchored
   authority set and reject unanchored authority changes.  The set is a signed,
   revisioned bundle containing exactly one active authority, bounded valid
   overlap authorities, and exact revoked serials.  A newly active authority
   must become usable by running peers and relays without restarting them.
6. Every signed object uses a fixed binary transcript and a distinct
   `peerward/.../v1` or explicitly versioned successor domain prefix.  JSON
   serialization is never signed, and incompatible transcript revisions are
   never accepted as the same document type.

## Addressing and naming

- A mesh owns one private IPv4 CIDR, one gateway address, one DNS suffix, and a
  set of explicitly reserved addresses.
- Address allocation is stable per peer, transactional under concurrency, and
  skips network, broadcast, gateway, and reservations.
- Released addresses enter a configurable quarantine before reuse.
- Enabled peer names and service aliases share one case-insensitive DNS label
  namespace inside a mesh.
- Peers receive A and PTR answers only for policy-visible destinations.
- Split DNS captures only the configured mesh suffix and must restore prior OS
  state during shutdown or failed startup.

## Policy

Policies are ordered by ascending priority, then deny before allow, then rule
UUID, and default to deny unless the mesh explicitly selects allow.  A rule
contains an enabled flag, an audit flag, an action, source selector,
destination selector, protocol, and destination port ranges.  A selector may
combine peer IDs, labels, and CIDRs: dimensions are conjunctive while values
inside one dimension are alternatives.  Empty selectors match any peer.
Protocols are any, TCP, UDP, and ICMP.  Empty TCP or UDP ranges mean all ports;
Any and ICMP rules do not carry port ranges.

Enforcement occurs at peer egress, relay forwarding, and destination ingress.
Unknown IP protocol numbers remain parseable so an Any rule can decide them.
The state tracker supports TCP, UDP, ICMP echo, related ICMP errors, fragments,
bounded memory, expiry budgets, and revision-based invalidation.  A permitted
initiating packet may create return-flow state; unsolicited return traffic is
denied.  Denials produce rate-limited audit events without packet contents.

## Relay and direct paths

- A peer maintains a primary relay attachment and, when available, a warm
  standby on a different relay.
- Presence leases use monotonically increasing fencing generations.  A stale
  relay cannot reclaim or forward for a peer after another relay owns a newer
  generation.
- Relays load admission state and its durable event high-water in one
  repeatable-read snapshot.  Notifications only wake a cursor replay loop.
  Database unavailability older than 60 seconds rejects new sessions; existing
  authenticated sessions may use the last verified state for at most 15
  minutes, while a known higher fence or revocation remains immediate.
- Relays form authenticated pairwise links.  Exactly one endpoint initiates a
  link, determined by ordering relay UUID bytes.
- A relay identity publishes between one and sixteen peer-facing endpoints and
  between one and sixteen backbone endpoints.  Endpoints are canonical TCP
  URIs containing an IP address or ASCII DNS name.  DNS is resolved again on
  every connection attempt; only the signed Noise identity, not an address or
  DNS answer, authenticates the relay.
- The control service distributes signed, revisioned, chunkable peer and relay
  directories.  Receivers reject mixed revisions, invalid signatures, wrong
  mesh IDs, invalid endpoints, and rollback.
- Peers combine bounded configured host candidates with STUN-discovered UDP
  candidates.  Direct offers carry a prioritized, bounded candidate set.
  Direct sessions authenticate with peer credentials and Noise IK, race
  candidates with bounded concurrency, and accept endpoint migration only
  after a valid authenticated datagram.
- A peer keeps independent bounded direct-path state per remote peer.  Packet
  destination determines the only direct session that may carry it, and the
  authenticated remote peer constrains the source address of received packets.
  Missing or unhealthy destination-specific state falls back to a relay in the
  same send attempt.
- Direct-path probes use bounded exponential backoff with jitter.  Relayed
  traffic continues while probing and becomes the immediate fallback after
  direct-path health failure.

## Services and clients

- Linux peers expose loopback TCP, UDP, or dual-protocol services without
  binding the host service to a public interface.  The mesh listen port is
  independent from the loopback target port.  A service alias is optional and
  the private target address never leaves the publishing peer.
- The Android client uses `VpnService`, creates its private key on-device,
  protects control/data sockets from VPN recursion, and stores its profile in
  app-private storage.  Default-network and link-property changes rebuild all
  protected upstream sockets without replacing the enrolled identity or
  leaking traffic outside the authenticated relay fallback.
- A join bundle uses `peerward://join?bundle=...`; it contains an HTTPS claim
  URL, mesh root fingerprint, expiry, and random nonce.  The claim sends only a
  public Noise key and device metadata.  Tickets are single-use even under
  concurrent claims.

## Management and authorization

- The control API supports OIDC Authorization Code with PKCE, state, and nonce.
- Roles are `viewer`, `operator`, and `admin`, with a fixed monotonic hierarchy.
- A one-time bootstrap token may initialize OIDC and may be used as an explicit
  development bearer token when OIDC is disabled.
- Browser sessions use Secure, HttpOnly, SameSite=Lax cookies and a separate
  CSRF token for mutations.
- Audit records include actor, action, target, mesh, timestamp, result, and
  structured metadata; secrets and raw credentials are never recorded.

## Operations

Configuration files start with `schema_version = 1`.  Canonical paths are
`/etc/peerward`, `/var/lib/peerward`, and `/run/peerward`.  Environment
variables start with `PEERWARD_`; metrics start with `peerward_`.

The local peer management endpoint reports independent health, status, and
metrics views.  Health is derived from live TUN, signed-state, and relay task
state rather than a constant response.  Status exposes no secret material.

The signed updater is opt-in, selects a configured stable or canary channel,
installs into an atomic version directory, restarts the selected role, and
restores the previous version when a bounded health check fails.

The deliverable includes a single CLI binary, Dioxus web/desktop console,
Dioxus Android application, Docker image, Helm chart, systemd units, Linux
packages, signed updater, CI, and operator documentation.  Windows and macOS
VPN peers are not part of v1.
