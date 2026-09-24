# Observability

Monitor each layer without logging secrets or packet payloads.

All long-running binaries emit newline-delimited JSON tracing records to
standard error. Configure the filter with `RUST_LOG`; for example,
`RUST_LOG=peerward_control=debug,peerward_relay=info`. Container deployments
should keep the default `info` level and let the runtime rotate logs. Debug
records are metadata-only and must never contain credentials, bearer/session
tokens, join tickets, private keys, Noise payloads, or packet bodies.

Control exposes `/livez`, `/readyz`, and `/metrics` only on its dedicated
private management listener. `/api/v1/status` remains operator/auditor
authenticated. Track request rate, stable
error code, latency, request ID, role decision, database pool saturation,
outbox lag, SSE cursor age, failed OIDC state/nonce/CSRF checks, ticket claim
conflicts, and audit-write failures. A successful liveness probe is not
database readiness. Metrics include bounded request and authentication-
rejection counters, signed Join claim/completion/replay counters, policy
validation/rejection counters, publisher success/failure time series, and
verified/deduplicated/rejected encrypted Peer audit batch counters. Audit rows
contain only direction, stable reason, and count.
Control also exposes current SSE connections/capacity rejections/cursor resets,
Publisher builds/skips/failures, maintenance deletions/batch-saturated backlog/failures, and approximate
immutable audit-table rows, total bytes, and estimated insertion growth per
hour. Sampling is serialized and cached for 15 seconds; check
`peerward_control_audit_storage_available`, `peerward_control_audit_growth_available`
and `peerward_control_audit_sample_seconds` before interpreting cached values.
A detected statistics reset discards the growth baseline. None of these metrics uses Mesh, Peer, Relay, or request ID as a label.
Readiness compares all seven published signed-state revisions to the authoritative
Mesh revisions, so a pending publication is reported as unready. The management
listener must not be Internet-routed.

Relays report admitted Peer sessions separately from pending handshakes; backbone
session gauges count established links rather than pending forwarding channels.
Additional diagnostics include current fence
generation, directory/policy revision, primary/standby attachment changes,
queue depth/drops, keepalive RTT/misses, reconnect delay, exact revocations,
and rate-limited deny reasons. Relay audit is metadata-only: transport source,
mesh, authenticated source/destination Peer IDs, opaque kind/length, timing,
volume, queue outcome, and reason—never virtual addresses, ports, DNS names,
packet contents, service payloads, or key bytes.
Relay metrics separately count ciphertext batches accepted by or dropped
before its bounded persistence actor; a PostgreSQL outage cannot hold a routing
lock or block established packet forwarding. The
`peerward_relay_link_rekeys_total` counter records confirmed Peer or backbone
make-before-break replacements observed by that Relay.
Relay separately counts invalid opaque/control forwarding frames, unavailable routes, and bounded
queue/capacity backpressure. Peer metrics expose the same three classifications
plus aggregate Relay queue pressure and switch counts, STUN successes/failures,
unmatched or forged STUN-shaped responses,
gateway mapping successes/failures, detected gateway restarts, stable/unstable
prediction rounds, unrecognized UDP datagrams, and direct-receive queue drops; STUN server
addresses are not metric labels. Relay backbone probes publish only aggregate
RTT, loss-permyriad, and sample-count gauges. The bounded per-neighbor window is
persisted for routing, but Relay IDs are never Prometheus labels.

The Relay health listener serves `/livez`, `/readyz`, and `/metrics`. Bind it to
a private management network. The shared host reports assignment synchronization
within 30 seconds and database readiness; each Mesh assignment and resource
keeps its own application status. Standalone Relay readiness additionally checks
its installed signed snapshot. Unknown paths return 404. A live process can be unready.

`peerward_relay_framed_received_bytes_total` and
`peerward_relay_framed_accepted_bytes_total` count completed I/O on activated
framed carriers, including Peer and backbone links. They exclude initial
handshakes and IP/TCP/TLS/QUIC overhead. Accepted writes may still be buffered;
these are neither NIC counters, provider billing, nor end-to-end delivery.
Counters survive Mesh runtime replacement within one process and reset on process
restart. Summing both sides of a backbone counts the same traffic at multiple
observation points. Do not infer bytes from packet percentages.

Peer queue metrics expose message count and encoded bytes; backbone/audit
channel metrics expose occupied or reserved slots, excluding in-flight work.
Prometheus exports no Peer, Mesh, IP or DNS labels. The management UI displays
current queue rejection, audit drop and malformed-frame increments only for
recent samples with the same process baseline.

Shared hosts submit aggregate observations over their existing mTLS connection
every 10 seconds. A server nonce expires after 30 seconds; duplicate submissions
never refresh the stored timestamp. `GET /api/v1/relay-hosts/{host_id}/capacity`
is restricted by existing global `trust_manage`; expired samples are marked
unknown, and a new process ID clears rate/delta baselines. The authenticated
`GET /api/v1/operations/status` summarizes audit storage, unobserved hosts and
reported maintenance/backup outcomes. No response authorizes traffic or proves
resource availability. Backups reported successful still require separate
isolated restore validation.

PostgreSQL row and insertion statistics are estimates and may lag or reset;
a database reset marker or a counter decrease discards the growth baseline.
A table-specific reset followed by enough new writes may be unobservable between
samples, so growth remains an estimate. See the
[PostgreSQL statistics documentation](https://www.postgresql.org/docs/current/monitoring-stats.html).

Peers expose protected local `peerward status` and `peerward metrics`. Track
TUN packet counts, strict parse failures, ACL allow/deny/state occupancy,
direct/relay path health, failover, DNS response class/truncation/upstream
errors, signed revisions, service mappings, and rollback outcome. The
`peerward_peer_relay_rekeys_total` counter advances only after a parallel,
Root-authenticated replacement link is ready; ordinary reconnects remain in
`peerward_peer_relay_reconnects_total`. Scrape the local socket through a
trusted host agent; do not expose it on TCP.

There is no dedicated Peer replay-rejection counter. The WireGuard adapter
maps rejected encrypted packets to authentication errors without exposing a
separate replay classification. The former
`peerward_peer_replay_rejected_total` metric had no producer and always returned
zero; it has been removed. Remove queries for that metric from local dashboards.
Replay protection remains enforced by WireGuard and covered by its packet tests.

Alert on readiness loss, fence rejection spikes, policy/directory rollback,
authority expiry horizon, repeated exact revocation, sustained queue pressure,
database/outbox lag, backup failure, or host-network rollback failure. Correlate
by request/event/peer/relay UUID, not by credentials or tokens.

`audit_log` is permanent and maintenance never deletes it. Back it up with the
database, archive a transaction-consistent copy to operator-controlled storage,
and alert on row/byte growth and forecast capacity. At minimum alert before 70%
disk consumption, page urgently before 85%, and test restore plus audit
continuity on the normal backup cadence. Choose stricter thresholds when WAL,
index rebuild, or snapshot headroom requires them.

Set `PEERWARD_OTLP_ENDPOINT` to an OTLP/gRPC collector endpoint such as
`http://otel-collector:4317` to export spans in addition to JSON logs. The
exporter is optional, but a configured exporter must initialize successfully;
an invalid endpoint or TLS/transport configuration fails startup. Peerward
flushes and shuts down the trace provider before normal process exit. Keep the
collector on a protected management network and apply sampling at the
collector; packet payloads and credentials are never span attributes.
`PEERWARD_TRACE_SAMPLE_RATIO` is a local value from 0 through 1 (default 1 for
an enabled exporter). The sampler is deliberately not parent-forced, so an
external sampled flag cannot override local policy. Service resources are
`peerward-control`, `peerward-relay`, `peerward-peer`, and
`peerward-console`/`peerward-cli` as appropriate.

W3C version-00 trace context is propagated without baggage across HTTP,
PostgreSQL outbox, SSE, signed-state publication, Relay, and Peer control
handling. Each stage uses a new span ID; publisher coalescing records at most 32
causal links on a real `state.publish` span. HTTP, Relay receive/apply, and Peer
receive spans attach the transported context as their OpenTelemetry remote
parent; the local sampler remains authoritative. Packet forwarding never
creates per-packet spans. Direct Answer, Result, and request-driven replacement
messages derive a child context instead of copying the inbound span ID. Never add
credentials, Noise bodies, DNS questions, Peer endpoints, Mesh/Peer/Relay IDs,
or request IDs as metric labels. Relay metrics expose only aggregate session,
forwarded-hop, TTL/loop drop, queue, and topology-revision values.

Import [`prometheus-rules.yaml`](../deploy/observability/prometheus-rules.yaml)
and [`grafana-dashboard.json`](../deploy/observability/grafana-dashboard.json)
as optional starting assets. The rules warn before the Relay's 60-second
new-session database grace boundary and cover readiness, signed-state
publication, bounded queues, aggregate backbone loss, STUN, gateway mapping and
path recovery. The dashboard intentionally aggregates across scrape targets;
do not add Mesh, Peer, Relay, endpoint, DNS question or request identifiers as
labels when adapting it. Validate thresholds against a measured deployment
rather than treating the supplied values as an SLA.
