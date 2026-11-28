//! Exclusive HPET register owner. The main counter is the only service
//! used: comparators and legacy replacement interrupts stay disabled.
//! A programmed but non-progressing counter remains an owned candidate,
//! not a published boot reference.
use crate::reference_clock::ReferenceClock;
use core::{ptr, sync::atomic::{AtomicU8, AtomicU64, AtomicUsize, Ordering}};

type Error = &'static [u8];
const CAPABILITIES: usize = 0;
const CONFIGURATION: usize = 0x10;
const INTERRUPT_STATUS: usize = 0x20;
const COUNTER: usize = 0xf0;
const COUNTER64: u64 = 1 << 13;
const TIMER_INTERRUPT: u64 = 1 << 2;
const TIMER_FSB_INTERRUPT: u64 = 1 << 14;

fn valid_caps(caps: u64) -> bool {
    let period = caps >> 32;
    caps & 255 != 0 && period != 0 && period <= 100_000_000
}

unsafe fn stop(address: usize) -> Result<u64, Error> {
    let config = (address + CONFIGURATION) as *mut u64;
    let disabled = ptr::read_volatile(config) & !3;
    ptr::write_volatile(config, disabled);
    if ptr::read_volatile(config) & 3 != 0 {
        return Err(b"HPET counter disable failed");
    }
    Ok(disabled)
}

/// IA-PC HPET 1.0a, sections 2.3.5--2.3.8: halt before writing
/// the main counter, disable all implemented comparator routes, clear
/// pending level interrupts with W1C, then enable only the main counter.
/// This is a finite register transaction, not a progress measurement.
unsafe fn program(address: usize, caps: u64) -> Result<(), Error> {
    let disabled = stop(address)?;
    let count = ((caps >> 8) & 31) as usize + 1;
    for index in 0..count {
        let timer = (address + 0x100 + index * 0x20) as *mut u64;
        ptr::write_volatile(timer, ptr::read_volatile(timer) & !(TIMER_INTERRUPT | TIMER_FSB_INTERRUPT));
        if ptr::read_volatile(timer) & (TIMER_INTERRUPT | TIMER_FSB_INTERRUPT) != 0 {
            return Err(b"HPET comparator interrupt disable failed");
        }
    }
    let status = (address + INTERRUPT_STATUS) as *mut u64;
    let pending = ptr::read_volatile(status) & ((1u64 << count)-1);
    if pending != 0 { ptr::write_volatile(status, pending); }
    if caps & COUNTER64 != 0 {
        let counter = (address + COUNTER) as *mut u64;
        ptr::write_volatile(counter, 0);
        if ptr::read_volatile(counter) != 0 { return Err(b"HPET main counter reset failed"); }
    } else {
        let counter = (address + COUNTER) as *mut u32;
        ptr::write_volatile(counter, 0);
        if ptr::read_volatile(counter) != 0 { return Err(b"HPET main counter reset failed"); }
    }
    let config = (address + CONFIGURATION) as *mut u64;
    ptr::write_volatile(config, disabled | 1);
    if ptr::read_volatile(config) & 3 != 1 {
        let _ = stop(address);
        return Err(b"HPET counter enable failed");
    }
    Ok(())
}

pub(crate) struct Hpet {
    // 0 unowned, 1 programming, 2/3 progressing at boot,
    // 4/5 owned candidate, respectively 32/64 bit.
    state: AtomicU8,
    base: AtomicUsize,
    caps: AtomicU64,
}

impl Hpet {
    pub(crate) const fn new() -> Self {
        Self { state: AtomicU8::new(0), base: AtomicUsize::new(0), caps: AtomicU64::new(0) }
    }

    fn source(address: usize, caps: u64) -> ReferenceClock {
        ReferenceClock::Hpet { base: address, period_fs: caps >> 32, wide: caps & COUNTER64 != 0 }
    }

    /// The caller owns an exclusive, supervisor-only UC register page.
    /// Only an actually progressing source is a boot reference.
    pub(crate) unsafe fn initialize(&self, address: usize, progressing: impl FnOnce(ReferenceClock) -> bool)
        -> Result<(), Error> {
        if address < 4096 || address % 4096 != 0 || address >= 1usize << 47 {
            return Err(b"missing or invalid HPET address");
        }
        if self.state.compare_exchange(0, 1, Ordering::AcqRel, Ordering::Relaxed).is_err() {
            return Err(b"HPET already initialized");
        }
        let caps = ptr::read_volatile((address + CAPABILITIES) as *const u64);
        if !valid_caps(caps) {
            self.state.store(0, Ordering::Release);
            return Err(b"invalid HPET capabilities");
        }
        if let Err(reason) = program(address, caps) {
            // Do not expose a device whose basic configuration was
            // never established successfully.
            let _ = stop(address);
            self.state.store(0, Ordering::Release);
            return Err(reason);
        }
        let source = Self::source(address, caps);
        let wide = (caps & COUNTER64 != 0) as u8;
        self.caps.store(caps, Ordering::Relaxed);
        self.base.store(address, Ordering::Relaxed);
        if !progressing(source) {
            let _ = stop(address);
            self.state.store(4+wide, Ordering::Release);
            return Err(b"HPET main counter not progressing");
        }
        self.state.store(2+wide, Ordering::Release);
        Ok(())
    }

    /// Boot/calibration reference only. After a runtime reset, the
    /// timekeeper owns progress qualification, not this register owner.
    pub(crate) fn reference(&self) -> Option<ReferenceClock> {
        match self.state.load(Ordering::Acquire) {
            2 | 3 => Some(Self::source(self.base.load(Ordering::Relaxed), self.caps.load(Ordering::Relaxed))),
            _ => None,
        }
    }

    /// Retain the validated identity even when boot progress failed.
    pub(crate) fn candidate(&self) -> Option<ReferenceClock> {
        match self.state.load(Ordering::Acquire) {
            2..=5 => Some(Self::source(self.base.load(Ordering::Relaxed), self.caps.load(Ordering::Relaxed))),
            _ => None,
        }
    }

    /// Safety: the caller must exclusively own clock lifecycle decisions
    /// under the shared timekeeper gate. No active epoch or boot polling
    /// reader may use this device. Successful programming does NOT
    /// prove that the hardware runs or that the new rate is correct.
    pub(crate) unsafe fn restart_quarantined(&self, source: ReferenceClock) -> Result<(), Error> {
        let state = self.state.load(Ordering::Acquire);
        if !(2..=5).contains(&state) || self.candidate() != Some(source) {
            return Err(b"HPET restart identity mismatch");
        }
        if self.state.compare_exchange(state, 1, Ordering::AcqRel, Ordering::Relaxed).is_err() {
            return Err(b"HPET register owner busy");
        }
        let address = self.base.load(Ordering::Relaxed);
        let caps = self.caps.load(Ordering::Relaxed);
        let result: Result<(), Error> = if ptr::read_volatile((address + CAPABILITIES) as *const u64) != caps {
            // A changed descriptor cannot be safely reconfigured with
            // the previously validated width or comparator count.
            Err(b"HPET capabilities changed")
        } else {
            let result = program(address, caps);
            if result.is_err() { let _ = stop(address); }
            result
        };
        self.state.store(4+(caps & COUNTER64 != 0) as u8, Ordering::Release);
        result
    }
}

static HPET: Hpet = Hpet::new();

pub unsafe fn init(address: usize) -> Result<(), Error> {
    HPET.initialize(address, |source| source.progressing())
}

pub fn reference() -> Option<ReferenceClock> { HPET.reference() }
pub fn candidate() -> Option<ReferenceClock> { HPET.candidate() }

pub(crate) unsafe fn restart_quarantined(source: ReferenceClock) -> Result<(), Error> {
    HPET.restart_quarantined(source)
}
