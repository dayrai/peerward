//! Bounded ciphertext fragmentation, independent of QUIC packet boundaries.
//! No partial payload leaves this module. Call only after carrier admission.
use std::{
    collections::BTreeMap,
    io,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

pub const MAX_FRAME: usize = 65_535;
pub const HEADER: usize = 24;
pub const MAX_FRAGMENTS: usize = 64;
pub const MAX_INCOMPLETE: usize = 32;
pub const MAX_BUFFERED: usize = 256 * 1024;
pub const LIFETIME: Duration = Duration::from_secs(2);
const MAGIC: &[u8; 4] = b"PWQ1";

/// Share one process budget across listeners and one Mesh budget across its
/// connections. Reservations include the entire advertised ciphertext size.
#[derive(Clone, Debug)]
pub struct Budget(Arc<BudgetState>);
#[derive(Debug)]
struct BudgetState {
    limit: usize,
    used: AtomicUsize,
}
impl Budget {
    pub fn new(limit: usize) -> Self {
        Self(Arc::new(BudgetState {
            limit,
            used: AtomicUsize::new(0),
        }))
    }
    pub(crate) fn shared(&self) -> bool {
        Arc::strong_count(&self.0) > 1
    }
    pub fn used(&self) -> usize {
        self.0.used.load(Ordering::Relaxed)
    }
    fn reserve(&self, size: usize) -> Option<Reservation> {
        let mut used = self.0.used.load(Ordering::Relaxed);
        loop {
            let next = used
                .checked_add(size)
                .filter(|next| *next <= self.0.limit)?;
            match self.0.used.compare_exchange_weak(
                used,
                next,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(current) => used = current,
            }
        }
        Some(Reservation {
            budget: self.clone(),
            size,
        })
    }
}
struct Reservation {
    budget: Budget,
    size: usize,
}
impl Drop for Reservation {
    fn drop(&mut self) {
        self.budget.0.used.fetch_sub(self.size, Ordering::Relaxed);
    }
}

/// A frame ID must never be reused within a QUIC connection/direction.
/// The entire fragment count is checked before allocating or transmitting.
pub fn split(id: u64, frame: &[u8], datagram_limit: usize) -> io::Result<Vec<Vec<u8>>> {
    if id == 0 || frame.is_empty() || frame.len() > MAX_FRAME {
        return Err(super::invalid("invalid QUIC ciphertext frame"));
    }
    let stride = datagram_limit.saturating_sub(HEADER).min(MAX_FRAME);
    if stride == 0 || frame.len().div_ceil(stride) > MAX_FRAGMENTS {
        return Err(super::invalid(
            "QUIC path cannot carry bounded ciphertext fragments",
        ));
    }
    let total = u32::try_from(frame.len()).map_err(io::Error::other)?;
    let stride_wire = u16::try_from(stride).map_err(io::Error::other)?;
    let count = u16::try_from(frame.len().div_ceil(stride)).map_err(io::Error::other)?;
    frame
        .chunks(stride)
        .enumerate()
        .map(|(index, body)| {
            let mut fragment = Vec::with_capacity(HEADER + body.len());
            fragment.extend_from_slice(MAGIC);
            fragment.extend_from_slice(&id.to_be_bytes());
            fragment.extend_from_slice(&total.to_be_bytes());
            fragment.extend_from_slice(&stride_wire.to_be_bytes());
            fragment.extend_from_slice(
                &u16::try_from(index)
                    .map_err(io::Error::other)?
                    .to_be_bytes(),
            );
            fragment.extend_from_slice(&count.to_be_bytes());
            fragment.extend_from_slice(&[0; 2]);
            fragment.extend_from_slice(body);
            Ok(fragment)
        })
        .collect()
}

struct Header {
    id: u64,
    total: usize,
    stride: usize,
    index: usize,
    count: usize,
}
impl Header {
    fn parse(bytes: &[u8]) -> io::Result<Self> {
        if bytes.len() <= HEADER || &bytes[..4] != MAGIC || bytes[22..24] != [0; 2] {
            return Err(super::invalid("invalid QUIC fragment header"));
        }
        let value = Self {
            id: u64::from_be_bytes(bytes[4..12].try_into().expect("fixed header")),
            total: u32::from_be_bytes(bytes[12..16].try_into().expect("fixed header")) as usize,
            stride: usize::from(u16::from_be_bytes([bytes[16], bytes[17]])),
            index: usize::from(u16::from_be_bytes([bytes[18], bytes[19]])),
            count: usize::from(u16::from_be_bytes([bytes[20], bytes[21]])),
        };
        if value.id == 0
            || value.total == 0
            || value.total > MAX_FRAME
            || value.stride == 0
            || value.count == 0
            || value.count > MAX_FRAGMENTS
            || value.index >= value.count
            || value.total.div_ceil(value.stride) != value.count
            || bytes.len() - HEADER != value.stride.min(value.total - value.index * value.stride)
        {
            return Err(super::invalid("invalid QUIC fragment geometry"));
        }
        Ok(value)
    }
}
struct Partial {
    data: Vec<u8>,
    stride: usize,
    count: usize,
    seen: u64,
    deadline: Instant,
    _process: Reservation,
    _mesh: Reservation,
}

/// Fixed 1024-ID horizon also retires expired, conflicting and budget-dropped
/// messages. Replaying a fragment cannot renew its deadline or reservation.
#[derive(Default)]
struct Retired {
    highest: u64,
    bits: [u64; 16],
}
impl Retired {
    fn contains(&self, id: u64) -> bool {
        if id > self.highest {
            return false;
        }
        let age = self.highest - id;
        age >= 1024
            || self.bits[usize::try_from(age).expect("bounded replay age") / 64] & (1 << (age % 64))
                != 0
    }
    fn insert(&mut self, id: u64) {
        if id > self.highest {
            let shift = (id - self.highest).min(1024) as usize;
            let old = self.bits;
            self.bits.fill(0);
            let words = shift / 64;
            let bits = shift % 64;
            for index in words..16 {
                self.bits[index] = old[index - words] << bits;
                if bits != 0 && index > words {
                    self.bits[index] |= old[index - words - 1] >> (64 - bits);
                }
            }
            self.highest = id;
        }
        let age = self.highest - id;
        if age < 1024 {
            self.bits[usize::try_from(age).expect("bounded replay age") / 64] |= 1 << (age % 64);
        }
    }
}

pub struct Reassembler {
    frames: BTreeMap<u64, Partial>,
    buffered: usize,
    retired: Retired,
    process: Budget,
    mesh: Budget,
}
impl Reassembler {
    pub fn new(process: Budget, mesh: Budget) -> Self {
        Self {
            frames: BTreeMap::new(),
            buffered: 0,
            retired: Retired::default(),
            process,
            mesh,
        }
    }
    pub fn buffered(&self) -> usize {
        self.buffered
    }
    pub fn incomplete(&self) -> usize {
        self.frames.len()
    }
    /// Release all connection reservations immediately on admission withdrawal.
    pub fn clear(&mut self) {
        self.frames.clear();
        self.buffered = 0;
    }
    /// Call on a timer even when no further datagram arrives.
    pub fn expire(&mut self, now: Instant) {
        let expired = self
            .frames
            .iter()
            .filter(|(id, frame)| frame.deadline <= now || self.retired.contains(**id))
            .map(|(id, _)| *id)
            .collect::<Vec<_>>();
        for id in expired {
            self.remove(id);
            self.retired.insert(id);
        }
    }
    fn remove(&mut self, id: u64) -> Option<Partial> {
        let frame = self.frames.remove(&id)?;
        self.buffered -= frame.data.len();
        Some(frame)
    }
    pub fn push(&mut self, bytes: &[u8], now: Instant) -> io::Result<Option<Vec<u8>>> {
        self.expire(now);
        let header = Header::parse(bytes)?;
        if self.retired.contains(header.id) {
            return Ok(None);
        }
        if let Some(frame) = self.frames.get(&header.id) {
            if frame.data.len() != header.total
                || frame.stride != header.stride
                || frame.count != header.count
            {
                self.remove(header.id);
                self.retired.insert(header.id);
                return Err(super::invalid("conflicting QUIC fragment geometry"));
            }
        } else {
            let reserve = || {
                if self.frames.len() >= MAX_INCOMPLETE
                    || self.buffered + header.total > MAX_BUFFERED
                {
                    return None;
                }
                Some((
                    self.process.reserve(header.total)?,
                    self.mesh.reserve(header.total)?,
                ))
            };
            let Some((process, mesh)) = reserve() else {
                self.retired.insert(header.id);
                return Ok(None);
            };
            self.frames.insert(
                header.id,
                Partial {
                    data: vec![0; header.total],
                    stride: header.stride,
                    count: header.count,
                    seen: 0,
                    deadline: now + LIFETIME,
                    _process: process,
                    _mesh: mesh,
                },
            );
            self.buffered += header.total;
        }
        let frame = self.frames.get_mut(&header.id).expect("reserved above");
        let start = header.index * header.stride;
        let end = start + bytes.len() - HEADER;
        let bit = 1_u64 << header.index;
        if frame.seen & bit != 0 {
            if frame.data[start..end] != bytes[HEADER..] {
                self.remove(header.id);
                self.retired.insert(header.id);
                return Err(super::invalid("conflicting duplicate QUIC fragment"));
            }
            return Ok(None);
        }
        frame.data[start..end].copy_from_slice(&bytes[HEADER..]);
        frame.seen |= bit;
        if frame.seen.count_ones() as usize != frame.count {
            return Ok(None);
        }
        let frame = self.remove(header.id).expect("completed frame");
        self.retired.insert(header.id);
        Ok(Some(frame.data))
    }
}

#[cfg(test)]
#[path = "fragments_tests.rs"]
mod tests;
