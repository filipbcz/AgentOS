//! HPET register ownership, independent of the system clock policy.
//! The main counter can be 32 or 64 bits. Comparator/legacy interrupts
//! are disabled; the LAPIC remains the scheduler interrupt source.
use crate::reference_clock::ReferenceClock;
use core::{ptr, sync::atomic::{AtomicU8, AtomicU64, AtomicUsize, Ordering}};

type Error = &'static [u8];
const CAPABILITIES: usize = 0;
const CONFIGURATION: usize = 0x10;
const COUNTER: usize = 0xf0;
const COUNTER64: u64 = 1 << 13;
const TIMER_INTERRUPT: u64 = 1 << 2;
const TIMER_FSB_INTERRUPT: u64 = 1 << 14;

pub(crate) struct Hpet {
    state: AtomicU8, // 0=unused, 1=initializing, 2=ready32, 3=ready64
    base: AtomicUsize,
    period: AtomicU64,
}

impl Hpet {
    pub(crate) const fn new() -> Self {
        Self { state: AtomicU8::new(0), base: AtomicUsize::new(0), period: AtomicU64::new(0) }
    }

    /// The caller owns an exclusive, supervisor-only UC register page.
    /// Progress is validated before the source is published.
    pub(crate) unsafe fn initialize(&self, address: usize, progressing: impl FnOnce(ReferenceClock) -> bool)
        -> Result<(), Error> {
        if address < 4096 || address % 4096 != 0 || address >= 1usize << 47 {
            return Err(b"missing or invalid HPET address");
        }
        if self.state.compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed).is_err() {
            return Err(b"HPET already initialized");
        }
        let caps = ptr::read_volatile((address + CAPABILITIES) as *const u64);
        let period = caps >> 32;
        let wide = caps & COUNTER64 != 0;
        if caps & 255 == 0 || period == 0 || period > 100_000_000 {
            self.state.store(0, Ordering::Release);
            return Err(b"invalid HPET capabilities");
        }
        let config = (address + CONFIGURATION) as *mut u64;
        let disabled = ptr::read_volatile(config) & !3;
        ptr::write_volatile(config, disabled);
        if ptr::read_volatile(config) & 3 != 0 {
            self.state.store(0, Ordering::Release);
            return Err(b"HPET counter disable failed");
        }
        let count = ((caps >> 8) & 31) as usize + 1;
        for index in 0..count {
            let timer = (address + 0x100 + index * 0x20) as *mut u64;
            ptr::write_volatile(timer, ptr::read_volatile(timer) & !(TIMER_INTERRUPT | TIMER_FSB_INTERRUPT));
            if ptr::read_volatile(timer) & (TIMER_INTERRUPT | TIMER_FSB_INTERRUPT) != 0 {
                self.state.store(0, Ordering::Release);
                return Err(b"HPET comparator interrupt disable failed");
            }
        }
        if wide {
            ptr::write_volatile((address + COUNTER) as *mut u64, 0);
        } else {
            ptr::write_volatile((address + COUNTER) as *mut u32, 0);
        }
        ptr::write_volatile(config, disabled | 1);
        let source = ReferenceClock::Hpet { base: address, period_fs: period, wide };
        if ptr::read_volatile(config) & 3 != 1 || !progressing(source) {
            ptr::write_volatile(config, disabled);
            self.state.store(0, Ordering::Release);
            return Err(b"HPET main counter not progressing");
        }
        self.period.store(period, Ordering::Relaxed);
        self.base.store(address, Ordering::Relaxed);
        self.state.store(if wide { 3 } else { 2 }, Ordering::Release);
        Ok(())
    }

    pub(crate) fn reference(&self) -> Option<ReferenceClock> {
        let wide = match self.state.load(Ordering::Acquire) {
            2 => false, 3 => true, _ => return None,
        };
        Some(ReferenceClock::Hpet { base: self.base.load(Ordering::Relaxed),
            period_fs: self.period.load(Ordering::Relaxed), wide })
    }
}

static HPET: Hpet = Hpet::new();

pub unsafe fn init(address: usize) -> Result<(), Error> {
    HPET.initialize(address, |source| source.progressing())
}

pub fn reference() -> Option<ReferenceClock> { HPET.reference() }
