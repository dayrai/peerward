//! Authenticated datagram size search. Health ACKs cannot refresh a size proof.
use super::{Duration, Instant, Message};

#[derive(Default)]
pub(super) struct Mtu {
    proof: Option<(usize, Instant)>,
    sent: Option<Instant>,
    failures: u8,
    bounds: Option<(usize, usize, usize)>, // known inner size, search upper, TUN ceiling
    target: usize,
    retry_full: Option<Instant>,
}

impl Mtu {
    pub fn limit(&self, now: Instant, lifetime: Duration, baseline: usize) -> usize {
        self.proof
            .filter(|(_, confirmed)| now.saturating_duration_since(*confirmed) < lifetime)
            .map_or(baseline, |(limit, _)| limit.max(baseline))
    }

    pub fn next(
        &mut self,
        ceiling: usize,
        ipv6: bool,
        now: Instant,
        interval: Duration,
    ) -> Option<(Message, usize)> {
        let minimum = if ipv6 { 80 } else { 64 };
        if self.bounds.is_none_or(|(_, _, old)| old != ceiling) {
            self.bounds = Some((minimum, ceiling, ceiling));
            self.target = ceiling;
            self.failures = 0;
            self.proof = None;
        }
        if self
            .sent
            .is_some_and(|sent| now.saturating_duration_since(sent) < interval)
        {
            return None;
        }
        if self.retry_full.is_some_and(|retry| now >= retry) {
            let (lower, _, ceiling) = self.bounds?;
            self.bounds = Some((lower, ceiling, ceiling));
            self.target = ceiling;
            self.retry_full = None;
        }
        probe(self.target, ipv6)
    }

    pub fn sent(&mut self, now: Instant) {
        self.sent = Some(now);
    }

    pub fn failed(&mut self, now: Instant, limit: usize) {
        if limit != 32 + self.target {
            return;
        }
        self.failures = self.failures.saturating_add(1);
        if self.failures < 3 {
            return;
        }
        self.failures = 0;
        let Some((lower, upper, ceiling)) = self.bounds else {
            return;
        };
        // A previously working size can become a black hole after an MTU change.
        let lower = if self.target <= lower { 64 } else { lower };
        let upper = upper.min(self.target.saturating_sub(1)).max(lower);
        self.bounds = Some((lower, upper, ceiling));
        self.choose_target(now);
    }

    pub fn confirm(&mut self, limit: usize, now: Instant) {
        self.proof = Some((limit, now));
        self.failures = 0;
        if let Some((lower, upper, ceiling)) = self.bounds {
            self.bounds = Some((lower.max(limit.saturating_sub(32)), upper, ceiling));
            self.choose_target(now);
        }
    }

    fn choose_target(&mut self, now: Instant) {
        let Some((lower, upper, ceiling)) = self.bounds else {
            return;
        };
        if lower >= upper || upper - lower < 16 {
            self.target = lower;
            if lower < ceiling && self.retry_full.is_none() {
                self.retry_full = Some(now + Duration::from_secs(30));
            }
        } else {
            // Intermediate probes are multiples of 16, so the reported size includes
            // exactly the padding GotaTun emits. The final probe may use an odd TUN MTU.
            self.target = (lower.midpoint(upper) / 16 * 16).max(lower + 16).min(upper);
        }
    }
}

pub(super) fn probe(mtu: usize, ipv6: bool) -> Option<(Message, usize)> {
    let padding = u16::try_from(mtu.checked_sub(if ipv6 { 76 } else { 56 })?).ok()?;
    if padding == 0 || padding > crate::coordination::MAX_PROBE_PADDING {
        return None;
    }
    Some((Message::MtuProbe(padding), 32 + mtu))
}
