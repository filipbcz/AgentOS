//! CPU-local monotonic milliseconds from an ordered, calibrated TSC.
//! Clock epochs are deliberately local: do not compare timestamps across CPUs.
//! No time is returned before the owner CPU initializes the clock.
//! Does not promise UTC, sleep accuracy, global synchronization or an
//! invariant TSC on hardware which does not advertise one.
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

pub struct Clock {
    hz: u64,
    origin: AtomicU64,
    last_ms: AtomicU64,
    ready: AtomicBool,
}

impl Clock {
    pub const fn new(hz: u64) -> Self {
        Self { hz, origin: AtomicU64::new(0), last_ms: AtomicU64::new(0),
               ready: AtomicBool::new(false) }
    }

    /// Call once on the owning CPU, before it can accept user syscalls.
    pub fn start(&self, tsc: u64) -> bool {
        if self.hz == 0 || self.ready.load(Ordering::Acquire) { return false; }
        self.origin.store(tsc, Ordering::Relaxed);
        self.last_ms.store(0, Ordering::Relaxed);
        self.ready.store(true, Ordering::Release);
        true
    }

    pub fn millis(&self, tsc: u64) -> Option<u64> {
        if !self.ready.load(Ordering::Acquire) { return None; }
        let origin = self.origin.load(Ordering::Relaxed);
        // Using u128 prevents overflow when a high-rate counter runs for years.
        let delta = tsc.saturating_sub(origin);
        let ms = ((delta as u128 * 1000) / self.hz as u128)
            .min(isize::MAX as u128) as u64;
        let prior = self.last_ms.fetch_max(ms, Ordering::Relaxed);
        Some(prior.max(ms))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn requiresInitializationAndNonzeroFrequency() {
        let clock = Clock::new(0);
        assert!(!clock.start(9));
        assert_eq!(clock.millis(99), None);
        let clock = Clock::new(2_000);
        assert_eq!(clock.millis(90), None);
        assert!(clock.start(100));
        assert!(!clock.start(200));
        assert_eq!(clock.millis(100), Some(0));
        assert_eq!(clock.millis(2_100), Some(1_000));
    }
    #[test]
    fn roundsDownAndNeverDecreasesOnCounterRegression() {
        let clock = Clock::new(3_000_000);
        assert!(clock.start(5_000));
        assert_eq!(clock.millis(3_004_999), Some(0));
        assert_eq!(clock.millis(3_005_000), Some(1_000));
        assert_eq!(clock.millis(5_000), Some(1_000));
        assert_eq!(clock.millis(1), Some(1_000));
        assert_eq!(clock.millis(6_005_000), Some(2_000));
    }
    #[test]
    fn saturatesAtSignedSyscallLimitWithoutOverflow() {
        let clock = Clock::new(1);
        assert!(clock.start(1));
        assert_eq!(clock.millis(u64::MAX), Some(isize::MAX as u64));
    }
    #[test]
    fn clocksUseIndependentCpuLocalEpochs() {
        let a = Clock::new(1_000);
        let b = Clock::new(2_000);
        assert!(a.start(100));
        assert!(b.start(25_000));
        assert_eq!(a.millis(1_100), Some(1_000));
        assert_eq!(b.millis(27_000), Some(1_000));
    }
    #[test]
    fn nonBlockingConcurrentReadRemainsMonotonic() {
        use std::{sync::Arc, thread};
        let clock = Arc::new(Clock::new(1_000));
        assert!(clock.start(0));
        let writers: Vec<_> = (0..4).map(|cpu| {
            let clock = Arc::clone(&clock);
            thread::spawn(move || {
                for tick in (0..50_000u64).rev() {
                    let _ = clock.millis(tick + cpu * 10);
                }
            })
        }).collect();
        for worker in writers { worker.join().unwrap(); }
        assert_eq!(clock.millis(0), Some(50_029));
    }
}
