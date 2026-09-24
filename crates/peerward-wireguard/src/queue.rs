use std::{collections::VecDeque, time::Instant};

use zeroize::Zeroizing;

use crate::{Error, Limits};

pub(crate) struct Pending {
    pub(crate) packet: Zeroizing<Vec<u8>>,
    pub(crate) expires: Instant,
    pub(crate) authorization: u64,
}

#[derive(Default)]
pub(crate) struct Queue {
    packets: VecDeque<Pending>,
    bytes: usize,
}

impl Queue {
    pub(crate) fn push(
        &mut self,
        packet: &[u8],
        now: Instant,
        limits: &Limits,
        authorization: u64,
    ) -> Result<(), Error> {
        self.expire(now);
        if self.packets.len() >= limits.queued_packets
            || packet.len() > limits.queued_bytes.saturating_sub(self.bytes)
        {
            return Err(Error::QueueFull);
        }
        self.bytes += packet.len();
        self.packets.push_back(Pending {
            packet: Zeroizing::new(packet.to_vec()),
            expires: now + limits.queue_lifetime,
            authorization,
        });
        Ok(())
    }

    pub(crate) fn pop(&mut self) -> Option<Pending> {
        let packet = self.packets.pop_front()?;
        self.bytes -= packet.packet.len();
        Some(packet)
    }

    pub(crate) fn restore(&mut self, packet: Pending) {
        self.bytes += packet.packet.len();
        self.packets.push_front(packet);
    }

    pub(crate) fn expire(&mut self, now: Instant) {
        while self.packets.front().is_some_and(|p| p.expires <= now) {
            self.pop();
        }
    }

    pub(crate) fn clear(&mut self) {
        self.packets.clear();
        self.bytes = 0;
    }

    pub(crate) const fn bytes(&self) -> usize {
        self.bytes
    }
}
