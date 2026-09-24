//! Detect system sleep without confusing network changes, process scheduling or wall-clock edits.
//! Linux/Android MONOTONIC stops in suspend; BOOTTIME includes it. Sample MONOTONIC
//! around BOOTTIME so preemption during measurement cannot manufacture a sleep interval.

pub(super) struct SuspendClock {
    upper: i128,
}

impl SuspendClock {
    pub(super) fn new() -> Self {
        Self { upper: sample().1 }
    }

    pub(super) fn resumed(&mut self) -> bool {
        let (lower, upper) = sample();
        self.observe(lower, upper)
    }

    fn observe(&mut self, lower: i128, upper: i128) -> bool {
        // Accumulate tiny sleeps; one millisecond tolerates clock sampling precision.
        if lower > self.upper.saturating_add(1_000_000) {
            self.upper = upper;
            return true;
        }
        self.upper = self.upper.min(upper);
        false
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn sample() -> (i128, i128) {
    use rustix::time::{ClockId, clock_gettime};
    let read = |clock| {
        let time = clock_gettime(clock);
        i128::from(time.tv_sec) * 1_000_000_000 + i128::from(time.tv_nsec)
    };
    let before = read(ClockId::Monotonic);
    let boot = read(ClockId::Boottime);
    let after = read(ClockId::Monotonic);
    (boot - after, boot - before)
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn sample() -> (i128, i128) {
    // Other platforms must notify resume explicitly before adopting the shared runtime.
    (0, 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_suspend_but_not_preemption_or_repeated_observations() {
        let mut clock = SuspendClock { upper: 100 };
        assert!(!clock.observe(-5_000_000_000, 100)); // Descheduled after BOOTTIME.
        assert!(!clock.observe(0, 5_000_000_000)); // Descheduled before BOOTTIME.
        assert!(!clock.observe(600_000, 600_100));
        assert!(clock.observe(1_200_000, 1_200_100)); // Cumulative short sleeps.
        assert!(!clock.observe(1_200_000, 1_200_100));
        assert!(clock.observe(240_000_000_000, 240_000_000_100));
        assert!(!clock.observe(240_000_000_000, 240_000_000_100));
    }
}
