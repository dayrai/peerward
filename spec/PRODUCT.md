# Peerward product specification

Status: frozen normative input for Peerward `0.1.0`.

## Compatibility boundary

The current canary is a clean-install release. It does not read, migrate, negotiate,
or silently delete 0.2 databases, daemon configuration, Android profiles,
client state, signed documents, or Wire messages. Every daemon configuration
declares its format and rejects unknown fields. Control and shared Relay use
`config_version = 2`; Linux Peer and Android profiles use format 4. Wire
`protocol_major = 5` is mandatory and has no downgrade path. The public
operator API remains under `/api/v1`.

The supported products are Control, Relay, Linux Peer, Android Peer, Web
Console, updater, Docker Compose, and systemd. A Desktop Console is not a product
or release artifact. Windows, macOS, and iOS Peers are outside the current product scope.
Android supports API 28 through target API 36.

## Security and routing model

Each Peer owns independent Ed25519 identity, Noise X25519 authentication and
WireGuard X25519 data keys. An Authority credential binds all three keys, Mesh, Peer identity, serial, role,
validity, and lifecycle. Peer-to-Relay and Relay-to-Relay Noise sessions
authenticate links and protect routing metadata. A path-independent Peer-to-
Peer standard WireGuard session encrypts every virtual IP, port, DNS message, service
payload, and direct-path control message before it reaches a Relay.

Relay is a blind, bounded forwarder. It may observe transport source, mesh,
authenticated source/destination Peer IDs, opaque frame type and length,
timing, and volume. It cannot inspect virtual packets or application payload.
Peerward does not claim anonymity or traffic-relationship hiding.

Both endpoints enforce the canonical `peerward-policy` evaluator. The sender
enforces egress policy; the receiver enforces authoritative ingress policy and
checks that the decrypted source IP belongs to the authenticated source Peer.

## Product experience

All visible Web and Android UI, routing, localization, state, and business
interaction is Rust with exact Dioxus `0.7.10`. Android state crosses a
versioned, ordered `MobileRuntimeSnapshot` bridge and is never inferred from
URL parameters or optimistic UI state. Rust owns Join validation, lifecycle
phase, backoff, runtime observation, keepalive and health-report cadence,
authenticated Relay/direct sessions, signed state, packet policy, Mesh DNS
answers, credential proofs, and diagnostics. Relay slot scheduling, endpoint
retry/promotion/replacement, TUN and Relay TCP byte movement, and rotation
commit/cleanup state are Rust-owned behind the bounded request-ID platform
protocol. Kotlin executes an exact outstanding request and returns only an
owned protected descriptor or bounded result; atomic persistence writes the
complete opaque blob produced by Rust. The Kotlin boundary is Activity/WebView, VPN permission
and notification, `VpnService.Builder`, protected/bound sockets, connectivity
callbacks, AndroidKeyStore, atomic file I/O, system export, and process
lifecycle. The UI formally maintains `zh-CN` and `en-US`, follows or overrides
system light/dark theme, is responsive, and targets WCAG 2.2 AA.

Android UDP/TCP DNS interception, flow bounds, retransmission, segmentation,
fallback response construction, and checksums are Rust-owned. Kotlin may only
perform the requested protected UDP/TCP upstream exchange and return the
bounded answer against a single-use native token.

## Operations

Liveness, readiness, and metrics use private management listeners. Release
artifacts are content-addressed and signed; updater manifests carry an expiry,
monotonic sequence, schema/Wire ranges, and rollback floor. Production release
requires the acceptance matrix, fuzz gates, Android signing, SBOM/provenance,
two clean reproducible builds, 24-hour soak, and `CLEAN_ROOM.md` verification.

All externally supplied collections are bounded at both API and persistence
boundaries: 64 labels, 1024 policy rules, 1024 Peer IDs and 64 labels and 256
CIDRs per selector, 256 port ranges per rule, and 4096 reserved Mesh addresses.
The binary policy decoder applies the same limits. Join responses are at most
1 MiB, Console success/error responses 2 MiB/64 KiB, and one SSE event 256 KiB.

The canonical maintenance defaults are interval 60 seconds, batch 1000, event
retention 86400 seconds/100000 rows, two signed versions, and terminal-state
retention 86400 seconds. Accepted ranges are respectively 10–3600,
100–10000, 3600–604800, 10000–1000000, 1–10, and 3600–604800.

`release.toml` is the unique source for product version, channel, Android
versionCode, Schema, Wire, and rollback floor. A deterministic sync tool owns Cargo, Gradle,
Compose, Bake, image labels, and documentation copies; CI uses its
`--check` mode. Product versions use strict canonical SemVer. An updater never
accepts a candidate below the selected installed role version. Versioned Linux
Relay/Peer failure recovery and explicit rollback may restore only the precisely
recorded compatible previous artifact above the strongest accepted rollback floor.
Control retains its selected binary and database for forward recovery; native
versioned Control rollback is refused. Before switching links, a private durable
transaction records its target and direction. Recovery replays that intent, never
blindly swaps links. A newer signed repair requires an explicit operator request
and a recovery-required transaction. Local status records historical completion,
not a fresh service observation. The restricted deployment runner may execute a
locally staged native release after Console approval of its concrete preview.
The first updater intent atomically includes that approved digest. Explicit,
versioned recovery requests are distinct from ordinary observation heartbeats.
Console executable/assets and Compose image rollout remain separate workflows.
