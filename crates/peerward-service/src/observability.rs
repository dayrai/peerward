use std::sync::RwLock as StdRwLock;

use peerward_peer_core::{RuntimeEvent, RuntimeOrchestrator, RuntimePhase};

include!("observability_types.rs");

#[derive(Default)]
struct RuntimeMetrics {
    state_generation: AtomicU64,
    egress_packets: AtomicU64,
    egress_bytes: AtomicU64,
    ingress_packets: AtomicU64,
    ingress_bytes: AtomicU64,
    acl_denied: AtomicU64,
    direct_packets: AtomicU64,
    relay_packets: AtomicU64,
    direct_relay_switches: AtomicU64,
    dns_queries: AtomicU64,
    relay_reconnects: AtomicU64,
    relay_route_switches: AtomicU64,
    relay_probe_successes: AtomicU64,
    relay_probe_failures: AtomicU64,
    relay_rtt_ewma_millis: AtomicU64,
    relay_queue_pressure_permyriad: AtomicU64,
    relay_rekeys: AtomicU64,
    service_mutations: AtomicU64,
    invalid_packets: AtomicU64,
    no_route: AtomicU64,
    queue_full: AtomicU64,
    stun_successes: AtomicU64,
    stun_failures: AtomicU64,
    stun_unmatched_responses: AtomicU64,
    gateway_mapping_successes: AtomicU64,
    gateway_mapping_failures: AtomicU64,
    gateway_restarts: AtomicU64,
    nat_prediction_successes: AtomicU64,
    nat_prediction_failures: AtomicU64,
    udp_unrecognized_datagrams: AtomicU64,
    udp_direct_queue_drops: AtomicU64,
}

/// Shared, secret-free local Peer health/status/metrics state.
#[derive(Clone, Default)]
pub struct PeerObservability {
    state: Arc<StdRwLock<RuntimeState>>,
    metrics: Arc<RuntimeMetrics>,
    client_management: Arc<StdRwLock<Option<Arc<dyn ClientManagement>>>>,
}

impl PeerObservability {
    fn changed(&self) {
        self.metrics
            .state_generation
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Initializes stable identities and the configured primary/standby Relay set.
    pub fn initialize(&self, mesh_id: impl ToString, peer_id: impl ToString, relays: &[String]) {
        if let Ok(mut state) = self.state.write() {
            state.mesh_id = mesh_id.to_string();
            state.peer_id = peer_id.to_string();
            state.relay_attachments = relays
                .iter()
                .enumerate()
                .map(|(index, relay_id)| RelayAttachmentStatus {
                    relay_id: relay_id.clone(),
                    role: if index == 0 { "primary" } else { "standby" },
                    healthy: false,
                    carrier: None,
                })
                .collect();
        }
        self.changed();
    }

    /// Updates whether the platform TUN is attached and usable.
    pub fn set_tun(&self, up: bool) {
        if let Ok(mut state) = self.state.write() {
            state.tun_up = up;
        }
        self.changed();
    }

    /// Updates one supervised task state.
    pub fn set_task(&self, task: PeerTask, alive: bool) {
        if let Ok(mut state) = self.state.write() {
            state.tasks.set(task, alive);
        }
        self.changed();
    }

    /// Records host DNS transaction readiness separately from listener task liveness.
    pub fn set_dns_host_ready(&self, ready: bool) {
        if let Ok(mut state) = self.state.write() {
            state.dns_host_ready = Some(ready);
        }
        self.changed();
    }

    /// Updates one configured Relay attachment without exposing endpoints or credentials.
    pub fn set_relay(&self, index: usize, healthy: bool) {
        if let Ok(mut state) = self.state.write()
            && let Some(relay) = state.relay_attachments.get_mut(index)
        {
            relay.healthy = healthy;
            if !healthy {
                relay.carrier = None;
            }
            if healthy && state.fallback_reason != Some(PeerFallbackReason::DirectPathUnavailable) {
                state.fallback_reason = None;
            } else if !state.relay_attachments.iter().any(|relay| relay.healthy) {
                state.fallback_reason = Some(PeerFallbackReason::AllRelaysUnavailable);
            }
        }
        self.changed();
    }

    /// Records the connected carrier kind without exposing its endpoint.
    pub fn set_relay_carrier(&self, index: usize, carrier: &'static str) {
        if !matches!(carrier, "quic" | "wss" | "tcp") {
            return;
        }
        if let Ok(mut state) = self.state.write()
            && let Some(relay) = state.relay_attachments.get_mut(index)
        {
            relay.carrier = Some(carrier);
        }
        self.changed();
    }

    /// Marks one attachment as primary after a successful failover.
    pub fn promote_relay(&self, index: usize) {
        if let Ok(mut state) = self.state.write() {
            for (position, relay) in state.relay_attachments.iter_mut().enumerate() {
                relay.role = if position == index {
                    "primary"
                } else {
                    "standby"
                };
            }
        }
        self.changed();
    }

    /// Records an application-layer Relay route migration without identity labels.
    pub fn record_relay_switch(&self) {
        self.metrics
            .relay_route_switches
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Records one keepalive outcome and a privacy-safe aggregate RTT gauge.
    pub fn record_relay_probe(&self, success: bool, rtt_millis: Option<u64>) {
        let counter = if success {
            &self.metrics.relay_probe_successes
        } else {
            &self.metrics.relay_probe_failures
        };
        counter.fetch_add(1, Ordering::Relaxed);
        if let Some(sample) = rtt_millis {
            let current = self.metrics.relay_rtt_ewma_millis.load(Ordering::Relaxed);
            let next = if current == 0 {
                sample.max(1)
            } else {
                current.saturating_mul(4).saturating_add(sample) / 5
            };
            self.metrics
                .relay_rtt_ewma_millis
                .store(next, Ordering::Relaxed);
        }
    }

    /// Records the highest bounded Relay command-queue pressure without a Relay label.
    pub fn record_relay_queue_pressure(&self, pressure_permyriad: u16) {
        self.metrics
            .relay_queue_pressure_permyriad
            .store(u64::from(pressure_permyriad.min(10_000)), Ordering::Relaxed);
    }

    /// Records a fully verified, monotonically newer signed revision.
    pub fn signed_revision(&self, family: SignedStateFamily, revision: u64) {
        if let Ok(mut state) = self.state.write() {
            state.signed_revisions.set(family, revision);
            state.signed_state_updated_at = Some(unix_seconds());
        }
        self.changed();
    }

    /// Replaces the bounded set of currently authenticated direct Peers.
    pub fn set_direct_peers<I, T>(&self, peers: I)
    where
        I: IntoIterator<Item = T>,
        T: ToString,
    {
        if let Ok(mut state) = self.state.write() {
            let mut values = peers
                .into_iter()
                .map(|peer| peer.to_string())
                .collect::<Vec<_>>();
            values.sort();
            values.dedup();
            if values.is_empty() && !state.direct_peers.is_empty() {
                state.fallback_reason = Some(PeerFallbackReason::DirectPathUnavailable);
                self.metrics.direct_relay_switches.fetch_add(1, Ordering::Relaxed);
            } else if !values.is_empty() && state.fallback_reason == Some(PeerFallbackReason::DirectPathUnavailable) {
                state.fallback_reason = None;
            }
            state.direct_peers = values;
        }
        self.changed();
    }

    /// Records a bounded machine-readable fallback reason.
    pub fn fallback(&self, reason: PeerFallbackReason) {
        if let Ok(mut state) = self.state.write() {
            state.fallback_reason = Some(reason);
        }
        self.changed();
        self.metrics
            .direct_relay_switches
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Records an accepted or ACL-denied egress packet.
    pub fn record_egress(&self, bytes: usize, allowed: bool, direct: bool) {
        if !allowed {
            self.metrics.acl_denied.fetch_add(1, Ordering::Relaxed);
            return;
        }
        self.metrics.egress_packets.fetch_add(1, Ordering::Relaxed);
        self.metrics
            .egress_bytes
            .fetch_add(bytes as u64, Ordering::Relaxed);
        let path = if direct {
            &self.metrics.direct_packets
        } else {
            &self.metrics.relay_packets
        };
        path.fetch_add(1, Ordering::Relaxed);
    }

    /// Records an accepted or ACL-denied ingress packet.
    pub fn record_ingress(&self, bytes: usize, allowed: bool) {
        if !allowed {
            self.metrics.acl_denied.fetch_add(1, Ordering::Relaxed);
            return;
        }
        self.metrics.ingress_packets.fetch_add(1, Ordering::Relaxed);
        self.metrics
            .ingress_bytes
            .fetch_add(bytes as u64, Ordering::Relaxed);
    }

    /// Records a Relay reconnect attempt.
    pub fn record_reconnect(&self) {
        self.metrics
            .relay_reconnects
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Records one authenticated make-before-break Relay link key refresh.
    pub fn record_rekey(&self) {
        self.metrics.relay_rekeys.fetch_add(1, Ordering::Relaxed);
    }

    /// Records one split-DNS query.
    pub fn record_dns_query(&self) {
        self.metrics.dns_queries.fetch_add(1, Ordering::Relaxed);
    }

    /// Records one committed service publication mutation.
    pub fn record_service_mutation(&self) {
        self.metrics
            .service_mutations
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Records one packet rejected by strict IP parsing or reassembly.
    pub fn record_invalid_packet(&self) {
        self.metrics.invalid_packets.fetch_add(1, Ordering::Relaxed);
    }

    /// Records one packet for which no authenticated path was available.
    pub fn record_no_route(&self) {
        self.metrics.no_route.fetch_add(1, Ordering::Relaxed);
    }

    /// Records one packet rejected by a bounded queue.
    pub fn record_queue_full(&self) {
        self.metrics.queue_full.fetch_add(1, Ordering::Relaxed);
    }

    /// Records the outcome of one bounded STUN probe without labeling the server.
    pub fn record_stun_result(&self, success: bool) {
        let metric = if success {
            &self.metrics.stun_successes
        } else {
            &self.metrics.stun_failures
        };
        metric.fetch_add(1, Ordering::Relaxed);
    }

    /// Records a STUN-shaped response without an exact source/transaction waiter.
    pub fn record_stun_unmatched_response(&self) {
        self.metrics
            .stun_unmatched_responses
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Records a datagram that is neither a recognized STUN response nor `WireGuard`.
    pub fn record_udp_unrecognized_datagram(&self) {
        self.metrics
            .udp_unrecognized_datagrams
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Records a `WireGuard` datagram discarded by the bounded direct receive queue.
    pub fn record_udp_direct_queue_drop(&self) {
        self.metrics
            .udp_direct_queue_drops
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Returns the independent health view.
    pub fn health_json(&self) -> serde_json::Value {
        let Ok(state) = self.state.read() else {
            return serde_json::json!({"status":"failed","reason":"state_poisoned"});
        };
        let relay_healthy = state.relay_attachments.iter().any(|relay| relay.healthy);
        let tasks_alive = state.tasks.all_alive();
        let signed_state_complete = state.signed_revisions.complete();
        let mut runtime = RuntimeOrchestrator::default();
        runtime.transition(RuntimeEvent::StartRequested);
        if state.tun_up && tasks_alive {
            runtime.transition(RuntimeEvent::TunOpened);
        }
        let lifecycle = runtime.transition(RuntimeEvent::TransportObserved {
            primary_relay_authenticated: relay_healthy,
            standby_relay_count: u16::try_from(
                state
                    .relay_attachments
                    .iter()
                    .filter(|relay| relay.healthy)
                    .count()
                    .saturating_sub(1),
            )
            .unwrap_or(u16::MAX),
            direct_path_count: u32::try_from(state.direct_peers.len()).unwrap_or(u32::MAX),
            signed_state_complete,
            signed_state_revision: state.signed_revisions.minimum(),
        });
        serde_json::json!({
            "status": if lifecycle.phase == RuntimePhase::Healthy && state.dns_host_ready != Some(false) { "ok" } else { "degraded" },
            "tun_up": state.tun_up,
            "relay_healthy": relay_healthy,
            "tasks_alive": tasks_alive,
            "signed_state_complete": signed_state_complete,
            "dns_host_ready": state.dns_host_ready,
        })
    }

    /// Returns the bounded current values allowed in encrypted Control health reports.
    pub fn runtime_report(&self) -> PeerRuntimeReport {
        let generation = self.metrics.state_generation.load(Ordering::Relaxed);
        let direct_packets = self.metrics.direct_packets.load(Ordering::Relaxed);
        let relay_packets = self.metrics.relay_packets.load(Ordering::Relaxed);
        let Ok(state) = self.state.read() else {
            return PeerRuntimeReport {
                generation,
                direct_path_count: 0,
                relay_packets,
                direct_packets,
                degraded_reasons: vec![PeerDegradedReason::PacketPumpUnavailable],
                signed_revision: 0,
            };
        };
        let mut degraded_reasons = Vec::new();
        if !state.relay_attachments.iter().any(|relay| relay.healthy) {
            degraded_reasons.push(PeerDegradedReason::RelayUnavailable);
        }
        if !state.signed_revisions.complete() {
            degraded_reasons.push(PeerDegradedReason::SignedStateIncomplete);
        }
        if state.fallback_reason == Some(PeerFallbackReason::DirectPathUnavailable) {
            degraded_reasons.push(PeerDegradedReason::DirectPathUnavailable);
        }
        if !state.tasks.dns || state.dns_host_ready == Some(false) {
            degraded_reasons.push(PeerDegradedReason::DnsDegraded);
        }
        if !state.tun_up {
            degraded_reasons.push(PeerDegradedReason::UnderlayUnavailable);
        }
        if !state.tasks.packet {
            degraded_reasons.push(PeerDegradedReason::PacketPumpUnavailable);
        }
        let signed_revision = state.signed_revisions.minimum();
        PeerRuntimeReport {
            generation,
            direct_path_count: u32::try_from(state.direct_peers.len()).unwrap_or(u32::MAX),
            relay_packets,
            direct_packets,
            degraded_reasons,
            signed_revision,
        }
    }

    /// Returns the detailed secret-free runtime view.
    pub fn status_json(&self) -> serde_json::Value {
        let mut status = self.state
            .read()
            .ok()
            .and_then(|state| serde_json::to_value(&*state).ok())
            .unwrap_or_else(|| serde_json::json!({"status":"unavailable"}));
        let observed_at = unix_seconds();
        status["observed_at"] = observed_at.into();
        status["diagnostics"] = self.runtime_report().degraded_reasons.into_iter().map(|code| {
            serde_json::json!(peerward_types::RuntimeDiagnostic::new(code.into(), Some(observed_at)))
        }).collect();
        status
    }

    /// Returns monotonic Prometheus-style counter names as JSON.
    pub fn metrics_json(&self) -> serde_json::Value {
        serde_json::json!({
            "peerward_peer_egress_packets_total": self.metrics.egress_packets.load(Ordering::Relaxed),
            "peerward_peer_egress_bytes_total": self.metrics.egress_bytes.load(Ordering::Relaxed),
            "peerward_peer_ingress_packets_total": self.metrics.ingress_packets.load(Ordering::Relaxed),
            "peerward_peer_ingress_bytes_total": self.metrics.ingress_bytes.load(Ordering::Relaxed),
            "peerward_peer_acl_denied_total": self.metrics.acl_denied.load(Ordering::Relaxed),
            "peerward_peer_direct_packets_total": self.metrics.direct_packets.load(Ordering::Relaxed),
            "peerward_peer_relay_packets_total": self.metrics.relay_packets.load(Ordering::Relaxed),
            "peerward_peer_direct_relay_switches_total": self.metrics.direct_relay_switches.load(Ordering::Relaxed),
            "peerward_peer_dns_queries_total": self.metrics.dns_queries.load(Ordering::Relaxed),
            "peerward_peer_relay_reconnects_total": self.metrics.relay_reconnects.load(Ordering::Relaxed),
            "peerward_peer_relay_route_switches_total": self.metrics.relay_route_switches.load(Ordering::Relaxed),
            "peerward_peer_relay_probe_successes_total": self.metrics.relay_probe_successes.load(Ordering::Relaxed),
            "peerward_peer_relay_probe_failures_total": self.metrics.relay_probe_failures.load(Ordering::Relaxed),
            "peerward_peer_relay_rtt_ewma_millis": self.metrics.relay_rtt_ewma_millis.load(Ordering::Relaxed),
            "peerward_peer_relay_queue_pressure_permyriad": self.metrics.relay_queue_pressure_permyriad.load(Ordering::Relaxed),
            "peerward_peer_relay_rekeys_total": self.metrics.relay_rekeys.load(Ordering::Relaxed),
            "peerward_peer_service_mutations_total": self.metrics.service_mutations.load(Ordering::Relaxed),
            "peerward_peer_invalid_packets_total": self.metrics.invalid_packets.load(Ordering::Relaxed),
            "peerward_peer_no_route_total": self.metrics.no_route.load(Ordering::Relaxed),
            "peerward_peer_queue_full_total": self.metrics.queue_full.load(Ordering::Relaxed),
            "peerward_peer_stun_successes_total": self.metrics.stun_successes.load(Ordering::Relaxed),
            "peerward_peer_stun_failures_total": self.metrics.stun_failures.load(Ordering::Relaxed),
            "peerward_peer_stun_unmatched_responses_total": self.metrics.stun_unmatched_responses.load(Ordering::Relaxed),
            "peerward_peer_gateway_mapping_successes_total": self.metrics.gateway_mapping_successes.load(Ordering::Relaxed),
            "peerward_peer_gateway_mapping_failures_total": self.metrics.gateway_mapping_failures.load(Ordering::Relaxed),
            "peerward_peer_gateway_restarts_total": self.metrics.gateway_restarts.load(Ordering::Relaxed),
            "peerward_peer_nat_prediction_successes_total": self.metrics.nat_prediction_successes.load(Ordering::Relaxed),
            "peerward_peer_nat_prediction_failures_total": self.metrics.nat_prediction_failures.load(Ordering::Relaxed),
            "peerward_peer_udp_unrecognized_datagrams_total": self.metrics.udp_unrecognized_datagrams.load(Ordering::Relaxed),
            "peerward_peer_udp_direct_queue_drops_total": self.metrics.udp_direct_queue_drops.load(Ordering::Relaxed),
        })
    }
}

fn unix_seconds() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

fn merge_metrics(
    observability: Option<&PeerObservability>,
    service: serde_json::Value,
) -> serde_json::Value {
    let mut combined = observability.map_or_else(serde_json::Map::new, |runtime| {
        runtime
            .metrics_json()
            .as_object()
            .cloned()
            .unwrap_or_default()
    });
    if let Some(service) = service.as_object() {
        combined.extend(service.clone());
    }
    serde_json::Value::Object(combined)
}
