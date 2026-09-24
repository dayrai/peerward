//! Per-candidate measured health. Only authenticated check ACKs improve a score.
use super::{Duration, Instant};

#[derive(Default)]
pub(super) struct Quality {
    rtt: Option<Duration>,
    loss: u32,
    samples: u32,
    pub confirmed: Option<Instant>,
}

impl Quality {
    pub fn success(&mut self, rtt: Duration, now: Instant) {
        self.rtt = Some(self.rtt.map_or(rtt, |old| (old * 7 + rtt) / 8));
        self.sample(false);
        self.confirmed = Some(now);
    }

    pub fn failure(&mut self) {
        self.sample(true);
    }

    fn sample(&mut self, lost: bool) {
        self.samples = self.samples.saturating_add(1).min(8);
        // The initial average has no imaginary successes; subsequent samples use EWMA.
        self.loss = (self.loss * (self.samples - 1) + u32::from(lost) * 1000) / self.samples;
    }

    pub fn score(&self) -> Duration {
        self.rtt.unwrap_or(Duration::from_secs(1)) + Duration::from_millis(u64::from(self.loss))
    }
}
