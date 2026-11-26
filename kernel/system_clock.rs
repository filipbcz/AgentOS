//! Single system-wide monotonic epoch shared by syscalls and drivers.
//! A source is selected before SMP and is never reset by another CPU.
//! Read + wrap extension are serialized with local interrupts masked.
use crate::reference_clock::{PmTimer, ReferenceClock};
use core::{arch::asm, cell::UnsafeCell, hint::spin_loop,
    sync::atomic::{AtomicBool, AtomicU64, Ordering}};

pub(crate) struct Epoch {
    source: ReferenceClock,
    last: u64,
    ticks: u128,
    valid: bool,
}

impl Epoch {
    pub(crate) fn new(source: ReferenceClock, first: u64) -> Self {
        Self { source, last: first & source.mask(), ticks: 0, valid: true }
    }

    pub(crate) fn observe(&mut self, raw: u64) -> Option<u64> {
        if !self.valid { return None; }
        let raw = raw & self.source.mask();
        let Some(delta) = self.source.delta(self.last, raw) else {
            // An ambiguous jump/reset cannot be interpreted as elapsed time.
            // The epoch is no longer trustworthy; never restart it silently.
            self.valid = false;
            return None;
        };
        self.last = raw;
        self.ticks = self.ticks.saturating_add(delta as u128);
        Some(self.source.ticks_to_ms(self.ticks))
    }
}

pub(crate) fn choose(pm: Option<PmTimer>, hp: Option<ReferenceClock>,
                     mut progressing: impl FnMut(ReferenceClock) -> bool) -> Option<ReferenceClock> {
    // Prefer HPET, including a 32-bit device when maintenance is feasible.
    // The ACPI PM timer is an independent standard fallback, not a TSC
    // approximation; all CPUs see the same physical counter and epoch.
    for source in [hp, pm.map(ReferenceClock::Pm)].into_iter().flatten() {
        if source.maintenance_ms() != Some(0) && progressing(source) {
            return Some(source);
        }
    }
    None
}

struct SharedClock {
    gate: AtomicBool,
    epoch: UnsafeCell<Option<Epoch>>,
    maintenance: AtomicU64, // 0 = no short-counter maintenance needed
}

unsafe impl Sync for SharedClock {}

impl SharedClock {
    const fn new() -> Self {
        Self { gate: AtomicBool::new(false), epoch: UnsafeCell::new(None),
               maintenance: AtomicU64::new(0) }
    }

    // No MMIO or other kernel locks may call back into this gate. Interrupt
    // masking prevents a local timer/syscall from deadlocking its owner.
    fn with<R>(&self, operation: impl FnOnce(&mut Option<Epoch>) -> R) -> R {
        let flags: usize;
        unsafe { asm!("pushfq", "pop {}", "cli", out(reg) flags); }
        while self.gate.swap(true, Ordering::Acquire) {
            while self.gate.load(Ordering::Relaxed) { spin_loop(); }
        }
        let result = operation(unsafe { &mut *self.epoch.get() });
        self.gate.store(false, Ordering::Release);
        if flags & (1 << 9) != 0 { unsafe { asm!("sti", options(nostack)); } }
        result
    }
}

static CLOCK: SharedClock = SharedClock::new();

pub unsafe fn init(pm: Option<PmTimer>, hp: Option<ReferenceClock>)
    -> Result<ReferenceClock, &'static [u8]> {
    CLOCK.with(|epoch| {
        if epoch.is_some() { return Err(b"system clock already initialized" as &[u8]); }
        let source = choose(pm, hp, |s| s.progressing())
            .ok_or(b"no progressing system clock with maintainable wrap interval" as &[u8])?;
        *epoch = Some(Epoch::new(source, source.sample()));
        CLOCK.maintenance.store(source.maintenance_ms().unwrap_or(0), Ordering::Release);
        Ok(source)
    })
}

pub fn millis() -> Option<u64> {
    CLOCK.with(|epoch| {
        let epoch = epoch.as_mut()?;
        let raw = unsafe { epoch.source.sample() };
        epoch.observe(raw)
    })
}

/// Read the same shared epoch once, returning the normal ABI value and
/// precise time for independent clock comparison. A nanosecond overflow
/// does not truncate the much larger signed-millisecond ABI range.
pub(crate) fn snapshot() -> Option<(u64, Option<u64>)> {
    CLOCK.with(|epoch| {
        let epoch = epoch.as_mut()?;
        let raw = unsafe { epoch.source.sample() };
        let ms = epoch.observe(raw)?;
        Some((ms, epoch.source.total_ns(epoch.ticks)))
    })
}

/// Only one online CPU is required to sample a shared short counter when
/// there are no runnable tasks or timed waiters. Other CPUs stay tickless.
pub fn maintenance_ms() -> Option<u64> {
    let interval = CLOCK.maintenance.load(Ordering::Acquire);
    (interval != 0).then_some(interval)
}

pub fn name(source: ReferenceClock) -> &'static [u8] {
    match source {
        ReferenceClock::Hpet { wide: true, .. } => b"SYSTEM CLOCK: HPET64",
        ReferenceClock::Hpet { wide: false, .. } => b"SYSTEM CLOCK: HPET32",
        ReferenceClock::Pm(timer) => if timer.wide {
            b"SYSTEM CLOCK: ACPI PM32"
        } else { b"SYSTEM CLOCK: ACPI PM24" },
    }
}
