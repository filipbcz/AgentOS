//! Owner-CPU one-shot LAPIC policy. No MMIO, allocation or IRQ operations.
//! `sample` must precede `plan` after reading the hardware current counter.
//! Count actual consumed LAPIC ticks, including intervals cut short by I/O,
//! so the independent stalled-TSC guard has the same duration in busy and
//! tickless operation. Never reset an earlier pending timer merely because
//! another unrelated interrupt arrived.
#![allow(non_snake_case)]

const QUANTUM_MS: u64 = 10;
const WATCHDOG_MS: u64 = 1000;
const STALL_MS: u64 = 5000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action { Keep, Disable, Arm(u32) }

pub struct Timer {
    fQuantumCounts: u32,
    fRemaining: u32,
    fLastClockMs: Option<u64>,
    fStalledCounts: u64,
}

impl Timer {
    pub const fn new(aQuantumCounts: u32) -> Self {
        Self { fQuantumCounts: aQuantumCounts, fRemaining: 0,
               fLastClockMs: None, fStalledCounts: 0 }
    }

    /// Begin a new scheduler session after disarming any boot-owned timer.
    pub fn reset(&mut self, aNow: Option<u64>) {
        self.fRemaining = 0;
        self.fLastClockMs = aNow;
        self.fStalledCounts = 0;
    }

    /// Returns true when the calibrated TSC did not progress for about five
    /// seconds measured by the independent LAPIC countdown, or is missing.
    /// Timer expiry counts once even if another IRQ observes zero first.
    pub fn sample(&mut self, aRemaining: u32, aNow: Option<u64>) -> bool {
        let pConsumed = self.fRemaining.saturating_sub(aRemaining) as u64;
        self.fRemaining = aRemaining;
        let Some(pNow) = aNow else { return true; };
        if self.fLastClockMs.map_or(true, |pBefore| pNow > pBefore) {
            self.fLastClockMs = Some(pNow);
            self.fStalledCounts = 0;
        } else {
            self.fStalledCounts = self.fStalledCounts.saturating_add(pConsumed);
        }
        self.fQuantumCounts == 0 ||
            self.fStalledCounts >= self.fQuantumCounts as u64 * (STALL_MS / QUANTUM_MS)
    }

    /// A runnable task receives at most one preemption quantum; an earlier
    /// waiter deadline can shorten it. With all tasks blocked, arm only the
    /// nearest timeout or the sparse watchdog.
    /// The countdown is capped to hardware width; this can wake early but
    /// never extends a deadline or claims that TSC time actually elapsed.
    pub fn plan(&mut self, aRunnable: bool, aDeadline: Option<u64>, aNow: u64) -> Action {
        let pLimit = if aRunnable { QUANTUM_MS } else { WATCHDOG_MS };
        let pMs = if let Some(pDeadline) = aDeadline {
            pDeadline.saturating_sub(aNow).clamp(1, pLimit)
        } else if aRunnable {
            QUANTUM_MS
        } else {
            self.fRemaining = 0;
            return Action::Disable;
        };
        // ceil(counts_per_10ms * milliseconds / 10), including fractional
        // millisecond hardware counts without integer truncation to zero.
        let pCounts = ((self.fQuantumCounts as u64 * pMs + QUANTUM_MS - 1) / QUANTUM_MS)
            .clamp(1, u32::MAX as u64) as u32;
        if self.fRemaining == 0 || pCounts < self.fRemaining {
            self.fRemaining = pCounts;
            Action::Arm(pCounts)
        } else { Action::Keep }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn idleWithoutDeadlineDisarmsAndRunnableWorkGetsQuantum() {
        let mut pTimer = Timer::new(1000);
        pTimer.reset(Some(0));
        assert_eq!(pTimer.plan(false, None, 0), Action::Disable);
        assert_eq!(pTimer.plan(true, None, 0), Action::Arm(1000));
        assert!(!pTimer.sample(750, Some(2)));
        assert_eq!(pTimer.plan(true, None, 2), Action::Keep);
        assert_eq!(pTimer.plan(false, None, 2), Action::Disable);
    }

    #[test]
    fn allBlockedUsesRealDeadlineInsteadOfTenMillisecondPolling() {
        let mut pTimer = Timer::new(1000);
        pTimer.reset(Some(100));
        assert_eq!(pTimer.plan(false, Some(850), 100), Action::Arm(75_000));
        assert!(!pTimer.sample(0, Some(850)));
        assert_eq!(pTimer.plan(true, None, 850), Action::Arm(1000));
    }

    #[test]
    fn longIdleKeepsOnlySparseClockWatchdog() {
        let mut pTimer = Timer::new(1000);
        pTimer.reset(Some(0));
        for pSecond in 0..5 {
            assert_eq!(pTimer.plan(false, Some(60_000), pSecond*1000), Action::Arm(100_000));
            assert!(!pTimer.sample(0, Some((pSecond+1)*1000)));
        }
    }

    #[test]
    fn unrelatedIoDoesNotPostponeIdleDeadlineOrWatchdog() {
        let mut pTimer = Timer::new(1000);
        pTimer.reset(Some(0));
        assert_eq!(pTimer.plan(false, Some(60_000), 0), Action::Arm(100_000));
        for pRemaining in (1..100).rev() {
            assert!(!pTimer.sample(pRemaining*1000, Some(0)));
            assert_eq!(pTimer.plan(false, Some(60_000), 0), Action::Keep);
        }
        assert!(!pTimer.sample(0, Some(0)));
        assert_eq!(pTimer.plan(false, Some(60_000), 0), Action::Arm(100_000));
    }

    #[test]
    fn earlierTimeoutAndIoWakeShortenPendingIdleTimer() {
        let mut pTimer = Timer::new(1000);
        pTimer.reset(Some(100));
        assert_eq!(pTimer.plan(false, Some(60_000), 100), Action::Arm(100_000));
        assert!(!pTimer.sample(90_000, Some(200)));
        assert_eq!(pTimer.plan(false, Some(225), 200), Action::Arm(2500));
        assert!(!pTimer.sample(2000, Some(205)));
        assert_eq!(pTimer.plan(true, Some(225), 205), Action::Arm(1000));
    }

    #[test]
    fn pendingEarlierDeadlineIsNotExtendedByRunnableWork() {
        let mut pTimer = Timer::new(1000);
        pTimer.reset(Some(0));
        assert_eq!(pTimer.plan(false, Some(3), 0), Action::Arm(300));
        assert!(!pTimer.sample(200, Some(1)));
        assert_eq!(pTimer.plan(true, None, 1), Action::Keep);
    }

    #[test]
    fn runnableTaskCannotDelayNewDeadlineUntilEndOfQuantum() {
        let mut pTimer = Timer::new(1000);
        pTimer.reset(Some(0));
        assert_eq!(pTimer.plan(true, Some(2), 0), Action::Arm(200));
        pTimer.reset(Some(0));
        assert_eq!(pTimer.plan(true, Some(5000), 0), Action::Arm(1000));
        assert!(!pTimer.sample(800, Some(2)));
        assert_eq!(pTimer.plan(true, Some(3), 2), Action::Arm(100));
        assert!(!pTimer.sample(0, Some(3)));
        assert_eq!(pTimer.plan(true, None, 3), Action::Arm(1000));
    }

    #[test]
    fn fiveWatchdogsDetectFrozenClockWithoutFabricatingTime() {
        let mut pTimer = Timer::new(1000);
        pTimer.reset(Some(10));
        for pSecond in 1..=5 {
            assert_eq!(pTimer.plan(false, Some(60_010), 10), Action::Arm(100_000));
            assert_eq!(pTimer.sample(0, Some(10)), pSecond==5);
        }
        assert!(!pTimer.sample(0, Some(11))); // recovery requires actual TSC progress
    }

    #[test]
    fn fiveHundredBusyQuantaUseSameFrozenClockBudget() {
        let mut pTimer = Timer::new(1000);
        pTimer.reset(Some(0));
        for pTick in 1..=500 {
            assert_eq!(pTimer.plan(true, None, 0), Action::Arm(1000));
            assert_eq!(pTimer.sample(0, Some(0)), pTick==500);
        }
    }

    #[test]
    fn fragmentedCountdownConsumptionCountsWithoutDoubleChargingExpiry() {
        let mut pTimer = Timer::new(1000);
        pTimer.reset(Some(0));
        assert_eq!(pTimer.plan(false, Some(60_000), 0), Action::Arm(100_000));
        assert!(!pTimer.sample(50_000, Some(0)));
        assert_eq!(pTimer.plan(true, None, 0), Action::Arm(1000));
        for pTick in 1..=450 {
            assert_eq!(pTimer.sample(0, Some(0)), pTick==450);
            if pTick<450 { assert_eq!(pTimer.plan(true, None, 0), Action::Arm(1000)); }
        }
        let pBefore=pTimer.fStalledCounts;
        assert!(pTimer.sample(0, Some(0)));
        assert_eq!(pTimer.fStalledCounts,pBefore);
    }

    #[test]
    fn advancingClockCannotAccumulateStaleWatchdogBudget() {
        let mut pTimer = Timer::new(1000);
        pTimer.reset(Some(0));
        for pNow in 0..1000 {
            pTimer.plan(true, None, pNow);
            assert!(!pTimer.sample(0, Some(pNow+1)));
        }
    }

    #[test]
    fn deadlineArithmeticHandlesPastValuesMaximumAndHardwareWidth() {
        let mut pTimer = Timer::new(u32::MAX);
        pTimer.reset(Some(u64::MAX));
        assert_eq!(pTimer.plan(false, Some(1), u64::MAX), Action::Arm(429_496_730));
        pTimer.reset(Some(0));
        assert_eq!(pTimer.plan(false, Some(u64::MAX), 0), Action::Arm(u32::MAX));
        let mut pSmall = Timer::new(1);
        assert_eq!(pSmall.plan(false, Some(0), 0), Action::Arm(1));
    }

    #[test]
    fn unavailableClockAndInvalidCalibrationFailClosed() {
        let mut pTimer = Timer::new(1000);
        pTimer.reset(None);
        assert!(pTimer.sample(0,None));
        assert!(!pTimer.sample(0,Some(0)));
        assert!(Timer::new(0).sample(0,Some(0)));
    }
}
