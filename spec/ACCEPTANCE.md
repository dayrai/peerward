# Peerward acceptance matrix

All scenarios run on clean release Schema 4, Wire major 5, endpoint-encrypted Relay
frames, and exact product version `0.1.0`.
This matrix defines stable-release requirements; listing a scenario is not a
claim that evidence currently exists. A canary technical preview may ship with
missing gates only when its release notes enumerate them. Stable publication
requires the signed `release-evidence.json` reports for the exact commit and
artifact-set digest.

1. Mesh isolation holds for addressing, policy, DNS, services, state, and audit.
2. Concurrent Join claims allocate unique addresses and lost-response replay returns the same result; key mismatch is `409`.
3. Address exhaustion, release quarantine, and later reuse preserve uniqueness.
4. Authority and credential pending/activate/publish/local-commit rotation survives a crash at each stage.
5. One/two Relay routing, standby promotion, restart, and fencing never create duplicate primary delivery.
6. Direct STUN/migration/replay/loss tests switch repeatedly to Relay without changing end-to-end identity or state.
7. Exact 45/60 minute and `2^19`/`2^20` boundaries prove signalled rekey, overlap, replay rejection, and hard fail-close.
8. Relay packet capture and memory probes cannot find injected IP, port, DNS, or payload plaintext.
9. Policy ordering/selectors/state/related ICMP/source spoof checks use the one canonical evaluator at both endpoints.
10. IPv4/IPv6, extension, TCP offset, checksum, malicious overlap/contradiction/quota fragments, and reassembly are strict.
11. Split DNS validates transaction/question/source, supports TCP fallback, applies visibility, and one timeout does not block other queries.
12. TCP/UDP Services enforce ACL, preserve half-close, bound mappings/queues, and one timeout does not block other flows.
13. PostgreSQL blackhole does not block established forwarding; routing locks, queues, leases, and audit remain bounded.
14. Linux apply/reapply/rollback/crash recovery restores exact routes, DNS, link, MTU, and owned nftables objects only.
15. Web/Android Dioxus routes, zh-CN/en-US, themes, permissions, keyboard/focus, WCAG AA, hydration, and visual regressions pass.
16. Compose network isolation, fixed-container lifecycle invariants, management probes, updater downgrade/expiry/compatibility, SBOM/provenance, reproducibility, and Android release signing pass.
17. Fuzz/sanitizer gates, API 28/36 emulators, physical NAT/Doze/network/kill tests, 24-hour multi-Relay soak, fault injection, and clean-room rebuild pass.
18. Request/response limits test absent, exact, and oversized `Content-Length`, streamed `limit+1`, invalid UTF-8/JSON, and stable 413/request IDs.
19. SSE tests cover no-history ready, UUID 400/unknown 410, pruned high-water, arbitrary UTF-8/CRLF chunks, 256 KiB failure, 1024-ID dedup, reconnect, and a 1000-event burst without concurrent refresh.
20. PostgreSQL tests prove outbox/high-water atomicity, retention-gap snapshot, bounded cleanup and dual-instance election, concurrent compound pagination, IPAM wrap/quarantine/exhaustion, and a 10000-Peer indexed allocation plan.
21. Publisher tests prove startup reconciliation, 100 ms coalescing, per-Mesh election, changed-family-only builds, and zero projection scans/builds without a revision change.
22. Version drift, strict SemVer downgrade/prerelease/build metadata, repeated manifest attempts, OCI role/ref labels, pinned action/image references, stale dependency exceptions, and Android lock/checksum metadata are release blockers.
23. Wire tests split every signed-state family below the 65535-byte Noise record ceiling, reassemble multi-megabyte states under the shared 32 MiB/1024-chunk bound, and reject mixing, duplication, rollback, and overflow on Linux and Android.
24. Android and Linux replay the same Rust lifecycle/fault traces and bounded backoff; no Kotlin-owned Relay-pool, packet-pump, STUN, DNS flow/fallback, or rotation scheduling policy remains outside the bounded request-ID platform protocol. Kotlin may execute protected DNS socket I/O only for a Rust-issued single-use query token.

25. Linux maintenance gates verify signed, isolated installation operations, backup inventory/ciphertext checks, interrupted-service recovery and process-scoped Relay byte/session/queue observations. Replayed or expired samples never refresh freshness; backup verification never activates old authorization. Upgrade, recovery activation and physical/long-running tests require their own evidence.

Release is blocked by any open severity-blocking security defect or failure of a
mandatory scenario.
