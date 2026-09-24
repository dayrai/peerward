use thiserror::Error;

use crate::RuntimeOrchestrator;

const MAX_RELAY_SLOTS: usize = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RelayConnectRequest {
    pub request_id: u64,
    pub slot: u8,
    pub endpoint_index: u16,
    pub candidate_generation: u64,
    pub replacing_generation: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RelayConnectCommit {
    pub slot: u8,
    pub generation: u64,
    pub replaced_generation: Option<u64>,
    pub primary: Option<RelayRoute>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RelayRoute {
    pub slot: u8,
    pub generation: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum RelayPoolError {
    #[error("relay slot configuration is outside its bound")]
    InvalidConfiguration,
    #[error("relay request or generation is stale")]
    Stale,
    #[error("relay request ID space is exhausted")]
    Exhausted,
}

#[derive(Debug, Clone, Copy)]
struct PendingConnect {
    request_id: u64,
    endpoint_index: u16,
    candidate_generation: u64,
    replacing_generation: Option<u64>,
}

#[derive(Debug, Clone)]
struct RelaySlot {
    endpoint_count: u16,
    next_endpoint: u16,
    active_endpoint: Option<u16>,
    active_generation: Option<u64>,
    pending: Option<PendingConnect>,
    due_millis: Option<u64>,
    attempt: u8,
}

/// Rust owner for Relay selection, promotion, replacement and retry timing.
#[derive(Debug)]
pub struct RelayPoolOrchestrator {
    slots: Vec<RelaySlot>,
    next_request_id: u64,
    next_generation: u64,
    closed: bool,
}

impl RelayPoolOrchestrator {
    pub fn new(endpoint_counts: &[u16]) -> Result<Self, RelayPoolError> {
        if endpoint_counts.is_empty()
            || endpoint_counts.len() > MAX_RELAY_SLOTS
            || endpoint_counts.contains(&0)
        {
            return Err(RelayPoolError::InvalidConfiguration);
        }
        Ok(Self {
            slots: endpoint_counts
                .iter()
                .copied()
                .map(|endpoint_count| RelaySlot {
                    endpoint_count,
                    next_endpoint: 0,
                    active_endpoint: None,
                    active_generation: None,
                    pending: None,
                    due_millis: Some(0),
                    attempt: 0,
                })
                .collect(),
            next_request_id: 1,
            next_generation: 1,
            closed: false,
        })
    }

    pub fn poll(&mut self, now_millis: u64) -> Result<Vec<RelayConnectRequest>, RelayPoolError> {
        if self.closed {
            return Ok(Vec::new());
        }
        let mut requests = Vec::with_capacity(self.slots.len());
        for (slot_index, slot) in self.slots.iter_mut().enumerate() {
            if slot.pending.is_some() || slot.due_millis.is_none_or(|due| due > now_millis) {
                continue;
            }
            let request_id = self.next_request_id;
            self.next_request_id = self
                .next_request_id
                .checked_add(1)
                .ok_or(RelayPoolError::Exhausted)?;
            let candidate_generation = self.next_generation;
            self.next_generation = self
                .next_generation
                .checked_add(1)
                .ok_or(RelayPoolError::Exhausted)?;
            let endpoint_index = slot.next_endpoint;
            let pending = PendingConnect {
                request_id,
                endpoint_index,
                candidate_generation,
                replacing_generation: slot.active_generation,
            };
            slot.pending = Some(pending);
            slot.due_millis = None;
            requests.push(RelayConnectRequest {
                request_id,
                slot: u8::try_from(slot_index).map_err(|_| RelayPoolError::Exhausted)?,
                endpoint_index,
                candidate_generation,
                replacing_generation: pending.replacing_generation,
            });
        }
        Ok(requests)
    }

    pub fn complete(
        &mut self,
        request_id: u64,
        success: bool,
        now_millis: u64,
    ) -> Result<Option<RelayConnectCommit>, RelayPoolError> {
        let (slot_index, pending) = self
            .slots
            .iter()
            .enumerate()
            .find_map(|(index, slot)| {
                slot.pending
                    .filter(|pending| pending.request_id == request_id)
                    .map(|pending| (index, pending))
            })
            .ok_or(RelayPoolError::Stale)?;
        let slot = &mut self.slots[slot_index];
        slot.pending = None;
        if !success {
            Self::schedule_retry(slot, slot_index, pending.endpoint_index, now_millis);
            return Ok(None);
        }
        if self.closed || slot.active_generation != pending.replacing_generation {
            return Err(RelayPoolError::Stale);
        }
        let replaced_generation = slot.active_generation.replace(pending.candidate_generation);
        slot.active_endpoint = Some(pending.endpoint_index);
        slot.attempt = 0;
        slot.due_millis = None;
        Ok(Some(RelayConnectCommit {
            slot: u8::try_from(slot_index).map_err(|_| RelayPoolError::Exhausted)?,
            generation: pending.candidate_generation,
            replaced_generation,
            primary: self.primary(),
        }))
    }

    pub fn failed(
        &mut self,
        route: RelayRoute,
        now_millis: u64,
    ) -> Result<Option<RelayRoute>, RelayPoolError> {
        let slot_index = usize::from(route.slot);
        let slot = self
            .slots
            .get_mut(slot_index)
            .ok_or(RelayPoolError::Stale)?;
        if slot.active_generation != Some(route.generation) {
            return Err(RelayPoolError::Stale);
        }
        slot.active_generation = None;
        slot.pending = None;
        let endpoint_index = slot.active_endpoint.take().ok_or(RelayPoolError::Stale)?;
        Self::schedule_retry(slot, slot_index, endpoint_index, now_millis);
        Ok(self.primary())
    }

    pub fn refresh(&mut self, route: RelayRoute, now_millis: u64) -> Result<(), RelayPoolError> {
        let slot = self
            .slots
            .get_mut(usize::from(route.slot))
            .ok_or(RelayPoolError::Stale)?;
        if slot.active_generation != Some(route.generation) {
            return Err(RelayPoolError::Stale);
        }
        if slot.pending.is_none() {
            slot.due_millis = Some(now_millis);
            slot.attempt = 0;
            slot.next_endpoint = 0;
        }
        Ok(())
    }

    pub fn primary(&self) -> Option<RelayRoute> {
        self.slots.iter().enumerate().find_map(|(slot, state)| {
            state.active_generation.map(|generation| RelayRoute {
                slot: u8::try_from(slot).expect("relay slot bound fits u8"),
                generation,
            })
        })
    }

    pub fn active(&self) -> Vec<RelayRoute> {
        self.slots
            .iter()
            .enumerate()
            .filter_map(|(slot, state)| {
                state.active_generation.map(|generation| RelayRoute {
                    slot: u8::try_from(slot).expect("relay slot bound fits u8"),
                    generation,
                })
            })
            .collect()
    }

    /// Fences inbound delivery to the exact current primary generation.
    pub fn accepts_inbound(&self, route: RelayRoute) -> bool {
        !self.closed && self.primary() == Some(route)
    }

    pub fn next_poll_millis(&self, now_millis: u64) -> u64 {
        self.slots
            .iter()
            .filter_map(|slot| slot.due_millis)
            .map(|due| due.saturating_sub(now_millis).max(1))
            .min()
            .unwrap_or(1_000)
            .min(10_000)
    }

    pub fn close(&mut self) -> Vec<RelayRoute> {
        self.closed = true;
        self.slots
            .iter_mut()
            .enumerate()
            .filter_map(|(slot, state)| {
                state.pending = None;
                state.active_endpoint = None;
                state.due_millis = None;
                state.active_generation.take().map(|generation| RelayRoute {
                    slot: u8::try_from(slot).expect("relay slot bound fits u8"),
                    generation,
                })
            })
            .collect()
    }

    fn schedule_retry(
        slot: &mut RelaySlot,
        slot_index: usize,
        endpoint_index: u16,
        now_millis: u64,
    ) {
        let entropy =
            (u64::try_from(slot_index).unwrap_or(u64::MAX) << 32) | u64::from(endpoint_index);
        let delay = RuntimeOrchestrator::reconnect_delay(slot.attempt, entropy);
        // Retry backoff saturates; carrier rotation must continue indefinitely.
        slot.attempt = slot.attempt.saturating_add(1).min(6);
        slot.next_endpoint = (endpoint_index + 1) % slot.endpoint_count;
        slot.due_millis =
            Some(now_millis.saturating_add(u64::try_from(delay.as_millis()).unwrap_or(u64::MAX)));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn promotion_retry_replacement_and_stale_results_are_rust_owned() {
        let mut pool = RelayPoolOrchestrator::new(&[2, 1]).unwrap();
        let initial = pool.poll(0).unwrap();
        let first = pool
            .complete(initial[0].request_id, true, 0)
            .unwrap()
            .unwrap();
        pool.complete(initial[1].request_id, true, 0)
            .unwrap()
            .unwrap();
        assert_eq!(
            first.primary,
            Some(RelayRoute {
                slot: 0,
                generation: 1
            })
        );
        assert_eq!(
            pool.failed(first.primary.unwrap(), 10)
                .unwrap()
                .unwrap()
                .slot,
            1
        );
        let due = 10 + pool.next_poll_millis(10);
        let retry = pool.poll(due).unwrap().remove(0);
        assert_eq!((retry.slot, retry.endpoint_index), (0, 1));
        pool.complete(retry.request_id, true, due).unwrap().unwrap();
        let active = pool.primary().unwrap();
        assert!(pool.accepts_inbound(active));
        assert!(!pool.accepts_inbound(first.primary.unwrap()));
        pool.refresh(active, 20_000).unwrap();
        let replacement = pool.poll(20_000).unwrap().remove(0);
        let commit = pool
            .complete(replacement.request_id, true, 20_000)
            .unwrap()
            .unwrap();
        assert_eq!(commit.replaced_generation, Some(active.generation));
        assert_eq!(
            pool.complete(replacement.request_id, true, 20_000),
            Err(RelayPoolError::Stale)
        );
    }

    #[test]
    fn prolonged_outage_keeps_trying_all_carriers_after_backoff_saturates() {
        let mut pool = RelayPoolOrchestrator::new(&[3]).unwrap();
        let mut now = 0;
        for attempt in 0..600_u16 {
            let request = pool.poll(now).unwrap().remove(0);
            assert_eq!(
                request.endpoint_index,
                attempt % 3,
                "carrier at retry {attempt}"
            );
            assert!(
                pool.complete(request.request_id, false, now)
                    .unwrap()
                    .is_none()
            );
            let delay = pool.next_poll_millis(now);
            assert!(delay <= 10_000);
            now += delay;
            // The scheduler may cap a sleep shorter than the actual jittered deadline.
            while pool.slots[0].due_millis.is_some_and(|due| due > now) {
                now += pool.next_poll_millis(now);
            }
        }
        let ready = pool.poll(now).unwrap().remove(0);
        assert_eq!(ready.endpoint_index, 0);
        assert!(
            pool.complete(ready.request_id, true, now)
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn closing_fences_pending_and_returns_owned_generations() {
        let mut pool = RelayPoolOrchestrator::new(&[1]).unwrap();
        let request = pool.poll(0).unwrap().remove(0);
        let active = pool.complete(request.request_id, true, 0).unwrap().unwrap();
        assert_eq!(
            pool.close(),
            vec![RelayRoute {
                slot: active.slot,
                generation: active.generation
            }]
        );
        assert!(pool.poll(1).unwrap().is_empty());
    }

    #[test]
    fn default_sized_pool_maintains_one_primary_and_two_standbys() {
        let mut pool = RelayPoolOrchestrator::new(&[1, 1, 1]).unwrap();
        let requests = pool.poll(0).unwrap();
        assert_eq!(requests.len(), 3);
        for request in requests {
            pool.complete(request.request_id, true, 0).unwrap().unwrap();
        }
        assert_eq!(pool.active().len(), 3);
        assert_eq!(pool.primary().unwrap().slot, 0);
        assert!(RelayPoolOrchestrator::new(&[1, 1, 1, 1]).is_err());
    }
}
