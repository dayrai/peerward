# Architecture

Peerward is an independent implementation based on open standards. Its primary
isolation boundary is a mesh UUIDv4; persistent IDs are typed UUIDv4 values and
must never be reused across resource kinds.

## Source layout

The workspace members and feature gates are declared in
[`Cargo.toml`](../Cargo.toml). Start with these implementation boundaries:

| Area | Source and responsibility |
| --- | --- |
| Commands | [`peerward-cli`](../crates/peerward-cli/src/lib.rs) dispatches Control, Relay, Peer, enrollment and updater commands. [`peerward-load`](../crates/peerward-load/) is a component load tool, not capacity certification. |
| Control and persistence | [`peerward-control`](../crates/peerward-control/src/lib.rs) owns HTTP routes and workers; [`peerward-store`](../crates/peerward-store/) owns PostgreSQL queries, ordered migrations and transactional [address allocation](../crates/peerward-store/src/store/support.rs). |
| Shared contracts | [`peerward-api`](../crates/peerward-api/) defines API payloads; [`peerward-management`](../crates/peerward-management/) defines resource and configuration semantics; [`peerward-types`](../crates/peerward-types/) supplies identifiers and common types. |
| Trust and packet rules | [`peerward-credentials`](../crates/peerward-credentials/) and [`peerward-directory`](../crates/peerward-directory/) validate signed identities/state; [`peerward-policy`](../crates/peerward-policy/) and [`peerward-dataplane`](../crates/peerward-dataplane/) evaluate packet policy and parse packets. |
| Transports | [`peerward-wire`](../crates/peerward-wire/) defines Relay Noise records; [`peerward-wireguard`](../crates/peerward-wireguard/) wraps WireGuard sessions; [`peerward-carrier`](../crates/peerward-carrier/) supplies framed/QUIC carriers; [`peerward-p2p`](../crates/peerward-p2p/) handles discovery and mapping. |
| Runtime and platforms | [`peerward-peer-core`](../crates/peerward-peer-core/) is shared state/runtime logic; [`peerward-peer`](../crates/peerward-peer/) integrates Linux, [`peerward-platform`](../crates/peerward-platform/) owns host adapters, [`peerward-service`](../crates/peerward-service/) provides local management/service support, and [`peerward-relay`](../crates/peerward-relay/) implements Relay hosts. [`peerward-android-core`](../crates/peerward-android-core/) supplies native mobile/JNI integration. |
| Applications | [`peerward-console`](../apps/peerward-console/) is SSR plus browser UI. [`peerward-android-ui`](../apps/peerward-android-ui/) is the mobile UI hosted by the [Android application](../apps/peerward-android/). [`peerward-ui`](../apps/peerward-ui/) shares UI primitives; [`peerward-dioxus`](../crates/peerward-dioxus/) is the workspace Dioxus facade. |
| Installation and updates | [`peerward-updater`](../crates/peerward-updater/) implements signed update transactions; [`deploy/`](../deploy/), [`packaging/`](../packaging/) and [`scripts/maintenance/`](../scripts/maintenance/) supply deployment and maintenance entrypoints. |

Several crates use `include!` to split a module across source files; a file
without a `mod` declaration can still be compiled. Platform, browser and
integration-test feature gates must also be checked before removing apparently
unused code. Test-input retention rules are in the
[development guide](development.md#maintained-test-inputs).

## Trust chain

An offline Ed25519 root certifies short-lived online authorities. Authorities
issue fixed-transcript peer and relay credentials containing mesh, subject,
an Ed25519 identity key, an independent X25519 Relay Noise key, exact credential
serial, and validity interval. Peer credentials also bind an independent
WireGuard public key for that credential generation. Authorities
also bind online directory and service verifiers. Root private material is not
needed by control, relay, console, or peer runtimes.

Running components consume a monotonic authority bundle containing the current
active and overlap certificates. The bundle is signed by its Root-certified
active authority, so rotations replace trust atomically without distributing a
new static configuration to every peer and relay.

## Runtime components

The control service is the source of durable intent. PostgreSQL transactions
cover tickets, IPAM, credentials, authority transitions, revisions, audit, and
outbox events. Console/API instances are stateless apart from OIDC sessions in
the database.

Relays authenticate peer links with Noise IK and form a deterministic Noise KK
backbone. Presence leases carry fencing generations. The Relay routes only
bounded `RelayEnvelopeV2` opaque payloads and overwrites the source Peer ID from
the authenticated link. It does not parse virtual packets, DNS, ports, service
content, or endpoint policy. An old fence or exact revocation still wins over
cached admission state.

Relay startup installs one repeatable-read admission snapshot and durable event
high-water before opening listeners. A cursor replay worker refreshes an
in-memory presence and signed-state cache. Noise KK presence exchange keeps the
packet path independent of synchronous PostgreSQL queries during the bounded
database outage window.

Outbox insertion and `event_stream_state` high-water advance in the same
transaction. PostgreSQL notification is only a wakeup; Control SSE and Relay
always replay ordered rows, with a five-second poll fallback. Retention gaps
cause Relay to install one new atomic snapshot. Control uses one LISTEN pump for
all SSE clients instead of one polling loop per client.

Signed-state publication is revision-driven: startup reconciliation, 100 ms
event coalescing, a five-second fallback, changed-family-only projection, and a
per-Mesh PostgreSQL advisory signing lock. Audit collection runs on its own
schedule. Mesh IPAM locks only the Mesh cursor row and advances by indexed point
lookups with wraparound instead of materializing all allocations.

Address allocation is implemented only in `peerward-store`; the former
standalone in-memory `peerward-ipam` model had no runtime callers and has been
removed. Both address families use the database transaction. IPv4 broadcast is
excluded; the last IPv6 address remains usable. A wrapped cursor still skips
the network address, gateway, reservations, active leases and quarantine.

Linux and Android derive privacy-safe runtime health from the same Rust
contract and deterministic lifecycle/fault state machine. Android reports only
permission, TUN, underlay, task, and protected-socket facts through JNI; Rust
alone derives `healthy`, `degraded`, `reconnecting`, and the reconnect delay.
Reports reuse the HPKE-encrypted, Ed25519-signed opaque
Relay-to-Control path, are capped at 4 KiB, and are emitted on state changes or
every 30 seconds. PostgreSQL stores only one `current_peer_runtime_health` row
per Peer with a 90-second expiry. Reports contain aggregate path counters and
bounded reason codes only; remote Peer IDs, IP addresses, ports, DNS names, and
endpoints cannot be encoded or retained.

Peers keep one primary and up to two warm-standby Relay links while maintaining
path-independent standard WireGuard sessions through the shared Rust runtime.
The same WireGuard datagrams travel over direct UDP or Relay. Linux and Android
validate outbound IP packets and ACL before encryption, and validate signed
source ownership and inbound ACL after decryption. Direct failure selects an
available Relay without changing session identity, replay, rekey, or policy state.
Direct state is indexed by destination peer; a path authenticated to one peer
can never carry packets addressed to another.
Primary Presence remains globally unique, while standby Presence is fenced per
Relay so two backups can coexist. A standby may carry flow-pinned opaque data
without becoming the control primary; control mutations still promote exactly
one session and fence its predecessor. Primary and standby leases use separate
tables exposed through one
deduplicated read view. Current binaries require Schema 4 and Wire 5; the
retained migration history does not permit older database generations or
Wire clients. Incompatible devices must be rebuilt and rejoined.
QUIC DATAGRAM and WSS are integrated into Peer connection selection and the
shared host/backbone. QUIC uses authenticated reliable control plus bounded
opaque-datagram fragmentation and reassembly; WSS also supports an explicitly
configured HTTP CONNECT proxy. Listener counts depend on host configuration,
not the number of Meshes.
Peers start immediately with static/host candidates and Relay forwarding. STUN
discovery then runs in the background with a two-second total budget, at most
four concurrent probes over eight servers, and a jittered five-minute refresh;
candidate updates reach the shared WireGuard coordinator without blocking the
packet pump. IPv4 and IPv6 each use their own data socket for discovery and
direct traffic. Candidates are exchanged only inside encrypted IP/UDP on
reserved port 51821; a mapping becomes a usable path only after an authenticated
direct round trip. Empty candidate sets retain Relay connectivity.
The Linux underlay monitor consumes netlink address, route and link events,
coalesces changes, and retains a two-second bounded fingerprint fallback. A
change invalidates
mapping discovery, re-evaluates the default gateway, and best-effort deletes a
lease owned on the replaced gateway.

Each Relay backbone direction sends a 15-second authenticated keepalive whose
direction bit prevents echo loops. Routing health uses an RTT EWMA and the last
32 probe outcomes; three consecutive missed replies replace the link. Fenced
runtime renewal publishes a bounded per-neighbor summary to PostgreSQL, while
Control combines both directions into signed edge costs at most every 30
seconds. Relays then deterministically derive the same primary/backup next-hop
order from the signed RTT/loss costs. Metrics expose aggregate values only.

The console proxies only the configured control origin. Its main routes are
Overview, Devices, Sharing, Access, and Issues and maintenance. The aggregate
topology is a troubleshooting section under Issues and maintenance; the device
page uses server-side search, filters and cursor pagination with 50 results per
page. The retained advanced resource table has a virtual Peer list and a
deduplicated 1,000-row client cache.
SSR page requests share one Control HTTP connection pool while cookies and
correlation context are installed on each request's cloned client. Native typed
API calls reject redirects, matching the proxy's configured-origin boundary.
Console and Android have separate Rust applications using exact Dioxus 0.7.10;
they share the `peerward-ui` components, locale/theme support and visual tokens.
Android
Kotlin is restricted to Activity/VpnService permissions, notification,
Keystore wrapping, network callbacks, `protect(fd)`, TUN descriptor, WebView
asset hosting, and lifecycle bridging; cryptographic and mesh state live in
Rust. Android Join request construction and response trust verification are
native; the durable profile is a Rust-versioned opaque blob wrapped and written
by the platform adapter. A live Relay authentication is insufficient for UI
health: only the native runtime's complete accepted revisions for Authority,
Peer, Relay, policy, service and revocation state can produce `healthy`.
The same runtime scheduler emits bounded observation, keepalive and encrypted
health-report deadlines; Kotlin executes the returned action but does not own
those intervals.

That boundary is implemented by a versioned request-ID platform protocol.
Rust owns Relay slot selection/promotion/retry/replacement, takes ownership of
protected Relay TCP and TUN FDs, moves TUN and Relay bytes, and produces complete
opaque rotation commit/cleanup blobs. Kotlin executes Android system calls only:
it returns owned descriptors or bounded results and atomically writes the exact
Rust-produced blob. Protected external DNS socket I/O remains a platform
operation; its UDP/TCP flow state, fallback, segmentation and checksums are
native.

## Host and deployment boundaries

Linux host changes implement `HostNetworkTransaction`: recovery precedes
prepare, the in-process DNS listener starts before `activate_dns`, and commit
is recorded only after firewall activation. TUN addresses and routes use rtnetlink,
split DNS uses systemd-resolved, NetworkManager, openresolv, or a guarded
`resolv.conf` fallback, and
nftables policy is submitted as one batch. Changes either commit together or
roll back in reverse order. A mode-0600, fsynced, atomically replaced journal
supports crash recovery and compare-and-swap ownership. The Mesh DNS gateway is installed as a local host
address on the TUN so UDP/TCP queries reach the in-process authoritative
server. Application containers use read-only root filesystems and the installation
UID/GID selected by bootstrap; release images default to UID/GID 65532.
PostgreSQL uses its own image user and writable data volume. Database credentials
and identity keys are supplied by the installation. Only a Linux peer needs
`CAP_NET_ADMIN` and
`/dev/net/tun`.

The platform boundary is three traits: `TunnelDevice` for packet I/O/MTU and
lifecycle, `HostNetworkTransaction` for recovery and host mutation, and
`UnderlayNetwork` for protected sockets, gateway discovery, and network-change
notifications. Linux implements these host traits; Android supplies VpnService,
Network-bound protected descriptors and Keystore through JNI. Fake adapters
exercise the contract for future Wintun and NetworkExtension implementations.

Implementation does not establish release qualification. Current per-version
results and remaining device, soak, source-review and independent-audit gates
are recorded in the [gap-closure report](analysis/wireguard-gap-closure.zh-CN.md).
