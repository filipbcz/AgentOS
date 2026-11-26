//! CPU-local boot-time deadlines. This transport is deliberately not a
//! system-wide monotonic epoch. A TSC rate on one processor authorizes
//! bounded local waits only; it says nothing about another CPU's offset.
use crate::reference_clock::{ReferenceClock, WaitError};
use core::hint::spin_loop;

const MAX_POLLS: u32 = 100_000_000;
const MAX_STALLED: u32 = 1_000_000;

#[derive(Clone, Copy)]
pub(crate) enum BringupClock {
    Physical(ReferenceClock),
    LocalTsc { hz: u64 },
}

impl BringupClock {
    pub fn name(self) -> &'static [u8] {
        match self {
            Self::Physical(clock) => clock.name(),
            Self::LocalTsc { .. } => b"BRINGUP CLOCK: calibrated local TSC (not global time)",
        }
    }

    pub fn tsc_hz(self) -> Option<u64> {
        match self { Self::Physical(_) => None, Self::LocalTsc { hz } => Some(hz) }
    }

    /// No CPU-frequency estimate, poll count, or zero divisor is
    /// substituted for the actual elapsed hardware time.
    pub(crate) fn local_poll(hz: u64, timeout_ns: u64, max_polls: u32, max_stalled: u32,
                             mut read: impl FnMut() -> u64,
                             mut complete: impl FnMut() -> bool)
        -> Result<Option<u64>, WaitError>
    {
        if hz == 0 { return Err(WaitError::Unresponsive); }
        if complete() { return Ok(None); }
        if timeout_ns == 0 { return Ok(Some(0)); }
        let start = read();
        let mut previous = start;
        let mut stalled = 0;
        for _ in 0..max_polls {
            let now = read();
            if now < previous { return Err(WaitError::Unresponsive); }
            let elapsed = (now-start) as u128 * 1_000_000_000 / hz as u128;
            if elapsed >= timeout_ns as u128 {
                return Ok(Some(elapsed.min(u64::MAX as u128) as u64));
            }
            if complete() { return Ok(None); }
            if now == previous {
                stalled += 1;
                if stalled >= max_stalled { return Err(WaitError::Unresponsive); }
            } else { stalled = 0; }
            previous = now;
            spin_loop();
        }
        Err(WaitError::Unresponsive)
    }

    pub unsafe fn wait_until(self, timeout_ns: u64, complete: impl FnMut() -> bool)
        -> Result<(), WaitError>
    {
        match self {
            Self::Physical(clock) => clock.wait_until(timeout_ns, complete),
            Self::LocalTsc { hz } => match Self::local_poll(hz, timeout_ns, MAX_POLLS,
                MAX_STALLED, || crate::tsc::read(), complete)? {
                None => Ok(()),
                Some(_) => Err(WaitError::Timeout),
            },
        }
    }

    pub unsafe fn delay_ns(self, duration_ns: u64) -> Result<u64, WaitError> {
        match self {
            Self::Physical(clock) => clock.delay_ns(duration_ns),
            Self::LocalTsc { hz } => Self::local_poll(hz, duration_ns, MAX_POLLS, MAX_STALLED,
                || crate::tsc::read(), || false)?.ok_or(WaitError::Unresponsive),
        }
    }
}
