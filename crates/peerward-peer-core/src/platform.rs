use std::collections::BTreeMap;

use thiserror::Error;

/// Android/Linux system capability requested by the Rust runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PlatformRequestKind {
    VpnPermission = 1,
    OpenTun = 2,
    ProtectedTcpSocket = 3,
    ProtectedUdpSocket = 4,
    KeystoreOperation = 5,
    AtomicPersistence = 6,
    AcquireUnderlay = 7,
    ExportDocument = 8,
    CloseRuntimeResources = 9,
}

/// Opaque correlation token. Sensitive request parameters stay in bounded FFI buffers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PlatformRequest {
    pub request_id: u64,
    pub generation: u64,
    pub kind: PlatformRequestKind,
}

/// Rejection from the bounded request/result protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum PlatformProtocolError {
    #[error("platform request table is full")]
    Capacity,
    #[error("platform request ID or generation is stale")]
    Stale,
    #[error("platform request ID space is exhausted")]
    Exhausted,
}

/// Request-ID broker that fences delayed platform responses after network/lifecycle changes.
#[derive(Debug)]
pub struct PlatformRequestBroker {
    generation: u64,
    next_request_id: u64,
    capacity: usize,
    pending: BTreeMap<u64, PlatformRequest>,
}

impl PlatformRequestBroker {
    /// Creates one bounded protocol owner.
    pub fn new(capacity: usize) -> Result<Self, PlatformProtocolError> {
        if capacity == 0 {
            return Err(PlatformProtocolError::Capacity);
        }
        Ok(Self {
            generation: 1,
            next_request_id: 1,
            capacity,
            pending: BTreeMap::new(),
        })
    }

    /// Emits one request for the current platform generation.
    pub fn issue(
        &mut self,
        kind: PlatformRequestKind,
    ) -> Result<PlatformRequest, PlatformProtocolError> {
        if self.pending.len() == self.capacity {
            return Err(PlatformProtocolError::Capacity);
        }
        let request = PlatformRequest {
            request_id: self.next_request_id,
            generation: self.generation,
            kind,
        };
        self.next_request_id = self
            .next_request_id
            .checked_add(1)
            .ok_or(PlatformProtocolError::Exhausted)?;
        self.pending.insert(request.request_id, request);
        Ok(request)
    }

    /// Accepts one exact result once and returns its original request kind.
    pub fn complete(
        &mut self,
        request_id: u64,
        generation: u64,
    ) -> Result<PlatformRequestKind, PlatformProtocolError> {
        let request = *self
            .pending
            .get(&request_id)
            .ok_or(PlatformProtocolError::Stale)?;
        if request.generation != generation || generation != self.generation {
            return Err(PlatformProtocolError::Stale);
        }
        self.pending.remove(&request_id);
        Ok(request.kind)
    }

    /// Invalidates every outstanding response after an underlay/lifecycle generation change.
    pub fn advance_generation(&mut self) -> Result<u64, PlatformProtocolError> {
        self.generation = self
            .generation
            .checked_add(1)
            .ok_or(PlatformProtocolError::Exhausted)?;
        self.pending.clear();
        Ok(self.generation)
    }

    /// Number of requests awaiting one exact response.
    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_ids_are_single_use_bounded_and_generation_fenced() {
        let mut broker = PlatformRequestBroker::new(2).unwrap();
        let tun = broker.issue(PlatformRequestKind::OpenTun).unwrap();
        let socket = broker
            .issue(PlatformRequestKind::ProtectedTcpSocket)
            .unwrap();
        assert_eq!(
            broker.issue(PlatformRequestKind::ProtectedUdpSocket),
            Err(PlatformProtocolError::Capacity)
        );
        assert_eq!(
            broker.complete(tun.request_id, tun.generation),
            Ok(PlatformRequestKind::OpenTun)
        );
        assert_eq!(
            broker.complete(tun.request_id, tun.generation),
            Err(PlatformProtocolError::Stale)
        );
        broker.advance_generation().unwrap();
        assert_eq!(
            broker.complete(socket.request_id, socket.generation),
            Err(PlatformProtocolError::Stale)
        );
        assert_eq!(broker.pending_count(), 0);
    }
}
