//! Platform-neutral STUN transaction scheduling for a socket's receive demux.

use std::{
    collections::{BTreeMap, VecDeque},
    net::SocketAddr,
};

use crate::{P2pError, StunRequest, SymmetricNatPredictionGate, predicted_ports};

const MAX_SERVERS: usize = 8;
const TRANSACTION_MILLIS: u64 = 2_000;
const REFRESH_BASE_MILLIS: u64 = 60_000;
const REFRESH_JITTER_MILLIS: u64 = 6_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StunProbe {
    pub server_index: u8,
    pub server: SocketAddr,
    pub request: [u8; 20],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StunPoll {
    pub probes: Vec<StunProbe>,
    pub next_poll_millis: u64,
}

/// Matching server-reflexive observation; not proof of a direct path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StunMapping {
    pub server_index: u8,
    pub mapped: SocketAddr,
    pub predicted: Vec<SocketAddr>,
}

struct Pending {
    probe: StunProbe,
    retry: u64,
    backoff: u64,
    deadline: u64,
}

/// Owns requests and deadlines without owning or receiving from a socket.
/// Call `poll` using a monotonic clock and send its requests on the data socket.
/// Pass that same clock to `accept`, including after platform suspension.
pub struct StunRuntime {
    servers: Vec<SocketAddr>,
    pending: BTreeMap<[u8; 12], Pending>,
    waiting: VecDeque<(u8, SocketAddr)>,
    next_refresh: Option<u64>,
    polled_at: Option<u64>,
    prediction: Option<SymmetricNatPredictionGate>,
    prediction_active: bool,
    observations: BTreeMap<u8, SocketAddr>,
    current_predictions: Vec<SocketAddr>,
}

impl StunRuntime {
    pub fn new(servers: Vec<SocketAddr>) -> Result<Self, P2pError> {
        Self::with_prediction(servers, false)
    }

    pub fn with_prediction(mut servers: Vec<SocketAddr>, enabled: bool) -> Result<Self, P2pError> {
        if servers.is_empty()
            || servers.len() > MAX_SERVERS
            || servers.iter().any(|server| {
                server.port() == 0 || server.ip().is_unspecified() || server.ip().is_multicast()
            })
        {
            return Err(P2pError::Candidate);
        }
        let count = servers.len();
        servers.sort_unstable();
        servers.dedup();
        if servers.len() != count {
            return Err(P2pError::Candidate);
        }
        Ok(Self {
            servers,
            pending: BTreeMap::new(),
            waiting: VecDeque::new(),
            next_refresh: None,
            polled_at: None,
            prediction: enabled.then(SymmetricNatPredictionGate::default),
            prediction_active: false,
            observations: BTreeMap::new(),
            current_predictions: Vec::new(),
        })
    }

    /// Cancels all outstanding observations after replacing the data socket.
    pub fn reset_network(&mut self) {
        self.pending.clear();
        self.waiting.clear();
        self.next_refresh = None;
        self.polled_at = None;
        self.observations.clear();
        self.current_predictions.clear();
        self.prediction_active = false;
        self.prediction = self
            .prediction
            .is_some()
            .then(SymmetricNatPredictionGate::default);
    }

    pub fn poll(&mut self, now: u64) -> StunPoll {
        if self.polled_at.is_some_and(|previous| now < previous) {
            self.reset_network();
        }
        self.polled_at = Some(now);
        if self.next_refresh.is_none_or(|next| now >= next) {
            self.finish_prediction(now, false);
            self.pending.clear();
            self.waiting = (0_u8..).zip(self.servers.iter().copied()).collect();
            self.observations.clear();
            self.current_predictions.clear();
            self.prediction_active = self
                .prediction
                .as_mut()
                .is_some_and(|gate| gate.begin_round(now / 1000));
            let jitter = StunRequest::random();
            let seed = u64::from_be_bytes(
                jitter.transaction[..8]
                    .try_into()
                    .expect("fixed transaction"),
            );
            let interval = REFRESH_BASE_MILLIS - REFRESH_JITTER_MILLIS
                + seed % (2 * REFRESH_JITTER_MILLIS + 1);
            self.next_refresh = Some(now.saturating_add(interval));
        }
        let expired = self.pending.values().any(|pending| now >= pending.deadline);
        self.pending.retain(|_, pending| now < pending.deadline);
        if expired {
            // A missing ordered observation invalidates this prediction round.
            self.finish_prediction(now, false);
        }
        // Serial issue order is essential for port-allocation observations.
        let parallel = if self.prediction_active { 1 } else { 4 };
        while self.pending.len() < parallel {
            let Some((server_index, server)) = self.waiting.pop_front() else {
                break;
            };
            let request = StunRequest::random();
            self.pending.insert(
                request.transaction,
                Pending {
                    probe: StunProbe {
                        server_index,
                        server,
                        request: request.bytes,
                    },
                    retry: now,
                    backoff: 250,
                    deadline: now.saturating_add(TRANSACTION_MILLIS),
                },
            );
        }
        let mut probes = Vec::new();
        let mut next = self.next_refresh.unwrap_or(now.saturating_add(1));
        for pending in self.pending.values_mut() {
            if now >= pending.retry {
                probes.push(pending.probe.clone());
                pending.retry = now.saturating_add(pending.backoff);
                pending.backoff = (pending.backoff * 2).min(1_000);
            }
            next = next.min(pending.retry).min(pending.deadline);
        }
        StunPoll {
            probes,
            next_poll_millis: next.saturating_sub(now).max(1),
        }
    }

    pub fn accept(
        &mut self,
        source: SocketAddr,
        response: &[u8],
        now: u64,
    ) -> Result<StunMapping, P2pError> {
        if !(20..=1024).contains(&response.len())
            || self.polled_at.is_none_or(|previous| now < previous)
        {
            return Err(P2pError::Stun);
        }
        let transaction: [u8; 12] = response[8..20].try_into().map_err(|_| P2pError::Stun)?;
        let pending = self.pending.get(&transaction).ok_or(P2pError::Stun)?;
        if pending.probe.server != source {
            return Err(P2pError::Stun);
        }
        if now >= pending.deadline {
            self.pending.remove(&transaction);
            self.finish_prediction(now, false);
            return Err(P2pError::Timeout);
        }
        let server_index = pending.probe.server_index;
        let mapped = StunRequest::from_transaction(transaction).parse_response(response)?;
        self.pending.remove(&transaction);
        self.observations.insert(server_index, mapped);
        if self.prediction_active {
            let observed: Vec<_> = self.observations.values().copied().collect();
            let ports = predicted_ports(&observed);
            if !ports.is_empty() {
                self.current_predictions = ports
                    .into_iter()
                    .map(|port| SocketAddr::new(mapped.ip(), port))
                    .collect();
                self.finish_prediction(now, true);
            } else if self.pending.is_empty() && self.waiting.is_empty() {
                self.finish_prediction(now, false);
            }
        }
        Ok(StunMapping {
            server_index,
            mapped,
            predicted: self.current_predictions.clone(),
        })
    }

    fn finish_prediction(&mut self, now: u64, success: bool) {
        if self.prediction_active
            && let Some(gate) = &mut self.prediction
        {
            gate.complete_round(now / 1000, success);
        }
        self.prediction_active = false;
    }
}

#[cfg(test)]
#[path = "stun_runtime_tests.rs"]
mod tests;
