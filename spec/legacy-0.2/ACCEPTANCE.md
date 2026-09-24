# Peerward v1 black-box acceptance matrix

Tests must be written from this document and public standards.  Test source from
another implementation may not be imported or translated.

## Mandatory functional scenarios

1. Create two meshes with overlapping IPv4 CIDRs; prove that peers, directories,
   policies, DNS, services, relay presence, and events cannot cross boundaries.
2. Claim 1,000 tickets concurrently; every successful peer receives a unique,
   stable usable address and every ticket succeeds at most once.
3. Exhaust an address pool, release one address, verify quarantine, then reclaim
   it after expiry without violating uniqueness.
4. Rotate authorities, peer keys, and relay keys through staged, overlap, active,
   and revoked states without restarting peers or relays.  Exact old-serial
   revocation preserves replacements and authority-bundle rollback is rejected.
5. Connect two peers through one relay, two relays, warm standby promotion, relay
   restart, and a stale fencing generation.  No duplicate live primary may
   forward traffic.
6. Establish direct UDP through STUN, accept authenticated endpoint migration,
   reject replay and tampering, inject loss/reorder/delay, and demonstrate
   immediate relay fallback without session identity loss.
   Four peers must simultaneously maintain destination-specific direct sessions;
   no packet may be delivered through another peer's session.
7. Enforce ordered allow/deny policy for TCP, UDP, ICMP, ports, labels, CIDRs,
   fragments, stateful return traffic, related ICMP errors, revision invalidation
   and bounded state memory.  Also exercise combined selectors, Any against an
   otherwise unsupported IP protocol, empty TCP/UDP ranges, disabled rules,
   deny tie-breaking, and rate-limited rule auditing.
8. Resolve permitted peer and service A/PTR records, hide denied destinations,
   reject alias collisions, forward out-of-suffix DNS, and restore split-DNS OS
   state after normal and abnormal exits.
9. Publish loopback TCP, UDP, and dual-protocol services with distinct mesh and
   target ports, preserve TCP half-close, expire UDP associations, omit an
   alias, atomically roll back a partial dual-protocol bind, and reject
   non-loopback targets.
10. Exercise OIDC state, nonce and PKCE, role hierarchy, CSRF, cookie flags,
    logout, session expiry, one-time bootstrap and constant-time token checks.
11. Complete Android join, key generation, `VpnService` permission/lifecycle,
    protected sockets, packet forwarding, DNS fragmentation, default-network
    switching and reconnection against real Control and Relay processes.
12. Render and hydrate the Dioxus console for all resource workflows and verify
    REST pagination, error envelopes, one-time join links, resource selection,
    multi-mesh isolation and SSE cursor replay against a real Control service.
13. Disconnect PostgreSQL while two relays carry authenticated traffic.  New
    sessions are rejected after 60 seconds, existing sessions use cached state
    for no more than 15 minutes, recovery replays every committed cursor, and a
    newer fencing generation or revocation wins immediately.
14. Verify local peer health, status, and metrics reflect actual TUN, relay,
    direct-path, policy revision, DNS, reconnect, packet and fallback state.
15. Publish multiple IP and DNS endpoints for one Relay identity, change DNS
    answers and fail individual addresses, and verify Peer and backbone
    reconnect without identity or presence-generation changes.
16. Install a signed stable and canary update, reject invalid manifests and
    artifacts, and automatically restore the prior version after migration,
    startup, or bounded health-check failure.  Disabled timers do no work.
17. Launch the native desktop console against the same real OIDC, Control and
    Console proxy used by browser tests and complete every resource workflow.

## Engineering gates

- `cargo fmt --all -- --check`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo test --workspace --all-targets`
- documentation tests and renderer-specific Dioxus builds
- PostgreSQL integration tests against a real ephemeral database
- privileged Linux namespace NAT/netem tests
- 10,000-peer IPAM capacity test
- Android emulator instrumentation
- Android API 36 lint, build and real-backend emulator interoperability
- real-backend Playwright workflows for every management resource
- dependency license/advisory policy and parser/security fuzz smoke
- reproducible release archives, container, Helm rendering and package install

## Independent-source gate

An audit outside the implementation environment compares all tracked text and
source against reference material.  Excluding generated files and standard
license text, release fails on an identical source blob or an exact normalized
eight-line window.  All tracked files are scanned for prohibited legacy brand
tokens.  The audit report is stored outside this repository.
