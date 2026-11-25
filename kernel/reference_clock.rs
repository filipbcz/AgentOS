//! Shared hardware reference for short boot, calibration and IPI intervals.
//! Unlike a process clock, samples are not an absolute ABI epoch. All
//! accesses use the ACPI-declared transport and actual counter width.
//! No scheduler, interrupt delivery or allocator is required.
use core::{arch::asm, hint::spin_loop, ptr};

const PM_HZ: u64 = 3_579_545;
const NS_PER_SECOND: u64 = 1_000_000_000;
const FS_PER_NS: u64 = 1_000_000;
const MAX_POLLS: u32 = 100_000_000;
const MAX_STALLED_POLLS: u32 = 1_000_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PmAccess { Io(u16), Memory(usize) }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PmTimer { pub access: PmAccess, pub wide: bool }

impl PmTimer {
    /// ACPI PM_TMR is always read as a DWORD. Counter width is from
    /// FADT TMR_VAL_EXT, not from the Generic Address Structure.
    pub fn from_address(space: u8, address: u64, wide: bool) -> Option<Self> {
        let access = match space {
            0 if address >= 4096 && address % 4 == 0 &&
                address <= (1u64 << 39) - 4 => PmAccess::Memory(address as usize),
            1 if address != 0 && address <= u16::MAX as u64 - 3 =>
                PmAccess::Io(address as u16),
            _ => return None,
        };
        Some(Self { access, wide })
    }

    pub fn mmio(self) -> Option<usize> {
        match self.access { PmAccess::Memory(address) => Some(address), _ => None }
    }

    unsafe fn read(self) -> u32 {
        match self.access {
            PmAccess::Io(port) => {
                let value: u32;
                asm!("in eax, dx", in("dx") port, out("eax") value,
                     options(nomem, nostack, preserves_flags));
                value
            }
            PmAccess::Memory(address) => ptr::read_volatile(address as *const u32),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReferenceClock {
    Pm(PmTimer),
    Hpet { base: usize, period_fs: u64 },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WaitError { Timeout, Unresponsive }

impl ReferenceClock {
    pub fn name(self) -> &'static [u8] {
        match self {
            Self::Pm(PmTimer { access: PmAccess::Io(_), .. }) => b"REFERENCE CLOCK: ACPI PM TIMER I/O",
            Self::Pm(PmTimer { access: PmAccess::Memory(_), .. }) => b"REFERENCE CLOCK: ACPI PM TIMER MMIO",
            Self::Hpet { .. } => b"REFERENCE CLOCK: HPET",
        }
    }

    fn mask(self) -> u64 {
        match self {
            Self::Pm(timer) => if timer.wide { u32::MAX as u64 } else { 0xff_ffff },
            Self::Hpet { .. } => u64::MAX,
        }
    }

    fn ticks_to_ns(self, ticks: u64) -> u64 {
        let ns = match self {
            Self::Pm(_) => ticks as u128 * NS_PER_SECOND as u128 / PM_HZ as u128,
            Self::Hpet { period_fs, .. } => ticks as u128 * period_fs as u128 / FS_PER_NS as u128,
        };
        ns.min(u64::MAX as u128) as u64
    }

    fn delta(self, before: u64, after: u64) -> Option<u64> {
        let mask = self.mask();
        let delta = after.wrapping_sub(before) & mask;
        // Successive samples in these short waits must be less than half
        // a wrap apart. Reject ambiguous jumps/reset rather than treating
        // a regressed clock as a completed hardware delay.
        (delta <= mask / 2).then_some(delta)
    }

    pub fn elapsed_ns(self, before: u64, after: u64) -> Option<u64> {
        Some(self.ticks_to_ns(self.delta(before, after)?))
    }

    /// Safety: every MMIO source must be mapped UC and owned by its driver;
    /// the PM I/O port is taken from a validated FADT.
    pub unsafe fn sample(self) -> u64 {
        let value = match self {
            Self::Pm(timer) => timer.read() as u64,
            Self::Hpet { base, .. } => ptr::read_volatile((base + 0xf0) as *const u64),
        };
        value & self.mask()
    }

    /// Select a progressing ACPI reference, retaining the established PM
    /// calibration preference. An absent/frozen PM timer must not block a
    /// machine with a usable HPET. Both are already discovered and mapped.
    pub(crate) fn choose(pm: Option<PmTimer>, hpet: Option<(usize, u64)>,
                         mut progressing: impl FnMut(Self) -> bool) -> Option<Self> {
        if let Some(timer) = pm {
            let clock = Self::Pm(timer);
            if progressing(clock) { return Some(clock); }
        }
        if let Some((base, period_fs)) = hpet {
            if base != 0 && base % 4096 == 0 &&
               period_fs != 0 && period_fs <= 100_000_000 {
                let clock = Self::Hpet { base, period_fs };
                if progressing(clock) { return Some(clock); }
            }
        }
        None
    }

    pub unsafe fn select(pm: Option<PmTimer>, hpet: Option<(usize, u64)>) -> Option<Self> {
        Self::choose(pm, hpet, |clock| {
            let start = clock.sample();
            for _ in 0..MAX_STALLED_POLLS {
                match clock.delta(start, clock.sample()) {
                    Some(0) => spin_loop(),
                    Some(_) => return true,
                    None => return false,
                }
            }
            false
        })
    }

    /// Pure polling engine with injectable hardware reads for host tests.
    /// Extend short counters between consecutive observations, retaining
    /// fractional ticks by converting accumulated ticks only when needed.
    /// The iteration bounds are last-resort failure guards, never a
    /// replacement for elapsed time or a source of synthetic clock time.
    pub(crate) fn poll(self, timeout_ns: u64, max_polls: u32, max_stalled: u32,
                       mut read: impl FnMut() -> u64,
                       mut complete: impl FnMut() -> bool) -> Result<(), WaitError> {
        if complete() { return Ok(()); }
        let mut previous = read();
        let mut total_ticks = 0u64;
        let mut stalled = 0u32;
        for _ in 0..max_polls {
            let now = read();
            let delta = self.delta(previous, now).ok_or(WaitError::Unresponsive)?;
            previous = now;
            total_ticks = total_ticks.checked_add(delta).ok_or(WaitError::Unresponsive)?;
            if self.ticks_to_ns(total_ticks) >= timeout_ns { return Err(WaitError::Timeout); }
            if complete() { return Ok(()); }
            if delta == 0 {
                stalled += 1;
                if stalled >= max_stalled { return Err(WaitError::Unresponsive); }
            } else {
                stalled = 0;
            }
            spin_loop();
        }
        Err(WaitError::Unresponsive)
    }

    pub unsafe fn wait_until(self, timeout_ns: u64,
                             complete: impl FnMut() -> bool) -> Result<(), WaitError> {
        self.poll(timeout_ns, MAX_POLLS, MAX_STALLED_POLLS, || self.sample(), complete)
    }

    pub unsafe fn delay_ns(self, duration_ns: u64) -> Result<(), WaitError> {
        match self.wait_until(duration_ns, || false) {
            Err(WaitError::Timeout) => Ok(()),
            result => result,
        }
    }
}
