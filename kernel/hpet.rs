//! One shared, free-running 64-bit HPET clock for native ABI v2 processes.
//! LAPIC remains the interrupt source; no HPET comparator interrupt is enabled.
//! All CPUs read the same counter, so migration cannot change a deadline epoch.
#![allow(non_snake_case, non_upper_case_globals)]

use core::{ptr, sync::atomic::{AtomicU8, AtomicU64, AtomicUsize, Ordering}};

type Error = &'static [u8];
const gCapabilities: usize = 0x00;
const gConfiguration: usize = 0x10;
const gCounter: usize = 0xf0;
const gCounter64: u64 = 1 << 13;
const gTimerInterrupt: u64 = 1 << 2;
const gTimerFsbInterrupt: u64 = 1 << 14;
const gFsPerMs: u128 = 1_000_000_000_000;

struct Hpet {
    fState: AtomicU8, // 0=uninitialized, 1=exclusive initialization, 2=ready
    fBase: AtomicUsize,
    fPeriodFs: AtomicU64,
    fLastMs: AtomicU64,
}

impl Hpet {
    const fn new() -> Self {
        Self { fState: AtomicU8::new(0), fBase: AtomicUsize::new(0),
               fPeriodFs: AtomicU64::new(0), fLastMs: AtomicU64::new(0) }
    }

    /// The caller owns this device and has mapped its whole register page as
    /// supervisor-only, uncacheable MMIO. This mapping must outlive the clock.
    unsafe fn initialize(&self, aAddress: usize) -> Result<(), Error> {
        if aAddress == 0 || aAddress & 4095 != 0 || aAddress >= (1usize << 47) {
            return Err(b"missing or invalid HPET address");
        }
        if self.fState.compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed).is_err() {
            return Err(b"HPET already initialized");
        }
        let pCapabilities = ptr::read_volatile((aAddress + gCapabilities) as *const u64);
        let pPeriodFs = pCapabilities >> 32;
        // HPET 1.0a requires at least 10 MHz. A zero period, 32-bit counter,
        // absent device (all ones) or invalid revision cannot serve this ABI.
        if pCapabilities & 255 == 0 || pCapabilities & gCounter64 == 0 ||
           pPeriodFs == 0 || pPeriodFs > 100_000_000 {
            self.fState.store(0, Ordering::Release);
            return Err(b"HPET requires a valid 64-bit counter");
        }
        let pConfiguration = (aAddress + gConfiguration) as *mut u64;
        let pDisabled = ptr::read_volatile(pConfiguration) & !3;
        // Disable before resetting the shared epoch. Never leave firmware's
        // legacy replacement or comparator/FSB interrupts active.
        ptr::write_volatile(pConfiguration, pDisabled);
        let pTimers = ((pCapabilities >> 8) & 31) as usize + 1;
        for pIndex in 0..pTimers {
            let pTimer = (aAddress + 0x100 + pIndex * 0x20) as *mut u64;
            ptr::write_volatile(pTimer,
                ptr::read_volatile(pTimer) & !(gTimerInterrupt | gTimerFsbInterrupt));
        }
        ptr::write_volatile((aAddress + gCounter) as *mut u64, 0);
        ptr::write_volatile(pConfiguration, pDisabled | 1);
        if ptr::read_volatile(pConfiguration) & 3 != 1 {
            self.fState.store(0, Ordering::Release);
            return Err(b"HPET counter enable failed");
        }
        self.fPeriodFs.store(pPeriodFs, Ordering::Relaxed);
        self.fBase.store(aAddress, Ordering::Relaxed);
        self.fLastMs.store(0, Ordering::Relaxed);
        self.fState.store(2, Ordering::Release);
        Ok(())
    }

    fn millis(&self) -> Option<u64> {
        if self.fState.load(Ordering::Acquire) != 2 { return None; }
        let pAddress = self.fBase.load(Ordering::Relaxed);
        let pTicks = unsafe { ptr::read_volatile((pAddress + gCounter) as *const u64) };
        Some(self.observe(pTicks))
    }

    fn observe(&self, aTicks: u64) -> u64 {
        let pPeriodFs = self.fPeriodFs.load(Ordering::Relaxed);
        let pMs = ((aTicks as u128 * pPeriodFs as u128) / gFsPerMs)
            .min(isize::MAX as u128) as u64;
        // Readers can finish out of order on different CPUs. Returning an
        // already observed value is safe; it never invents future clock time.
        let pBefore = self.fLastMs.fetch_max(pMs, Ordering::Relaxed);
        pBefore.max(pMs)
    }
}

static gHpet: Hpet = Hpet::new();

/// Start the system-wide process epoch once on the BSP before scheduling.
/// `aAddress` is the validated ACPI HPET base, mapped as one MMIO page.
pub unsafe fn init(aAddress: usize) -> Result<(), Error> { gHpet.initialize(aAddress) }

/// Boot-epoch milliseconds shared by every CPU, or None before initialization.
/// A stalled counter stays stalled; the LAPIC policy detects clock failure.
pub fn millis() -> Option<u64> { gHpet.millis() }

/// A read-only short-interval reference sharing the initialized HPET
/// counter. No second reset or ownership transfer is permitted.
pub fn reference() -> Option<(usize, u64)> {
    if gHpet.fState.load(Ordering::Acquire) != 2 { return None; }
    Some((gHpet.fBase.load(Ordering::Relaxed), gHpet.fPeriodFs.load(Ordering::Relaxed)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[repr(align(4096))]
    struct Registers([u64; 512]);

    fn registers(aPeriodFs: u64) -> Box<Registers> {
        let mut pRegisters = Box::new(Registers([0; 512]));
        pRegisters.0[gCapabilities / 8] = (aPeriodFs << 32) | gCounter64 | (2 << 8) | 1;
        pRegisters
    }

    #[test]
    fn requiresInitializationAndRejectsMissingDeviceWithoutPublication() {
        let pClock = Hpet::new();
        assert_eq!(pClock.millis(), None);
        assert!(unsafe { pClock.initialize(0) }.is_err());
        assert!(unsafe { pClock.initialize(1) }.is_err());
        assert!(unsafe { pClock.initialize(1usize << 47) }.is_err());
        assert_eq!(pClock.millis(), None);
    }

    #[test]
    fn invalidCounterCapabilitiesDoNotModifyHardware() {
        for pCapabilities in [0, u64::MAX, (100_000_000 << 32) | 1,
            (100_000_001 << 32) | gCounter64 | 1, gCounter64 | 1,
            (100_000_000 << 32) | gCounter64] {
            let pClock = Hpet::new();
            let mut pRegisters = registers(100_000_000);
            pRegisters.0[gCapabilities / 8] = pCapabilities;
            pRegisters.0[gConfiguration / 8] = 3;
            pRegisters.0[gCounter / 8] = 99;
            assert!(unsafe { pClock.initialize(pRegisters.0.as_mut_ptr() as usize) }.is_err());
            assert_eq!(pRegisters.0[gConfiguration / 8], 3);
            assert_eq!(pRegisters.0[gCounter / 8], 99);
            assert_eq!(pClock.millis(), None);
        }
    }

    #[test]
    fn startsOneSharedEpochWithoutComparatorOrLegacyInterrupts() {
        let pClock = Hpet::new();
        let mut pRegisters = registers(100_000_000);
        pRegisters.0[gConfiguration / 8] = 3;
        pRegisters.0[gCounter / 8] = 500;
        for pIndex in 0..3 {
            pRegisters.0[(0x100 + pIndex * 0x20) / 8] =
                gTimerInterrupt | gTimerFsbInterrupt | (1 << 5);
        }
        let pAddress = pRegisters.0.as_mut_ptr() as usize;
        assert_eq!(unsafe { pClock.initialize(pAddress) }, Ok(()));
        assert_eq!(pRegisters.0[gConfiguration / 8], 1);
        assert_eq!(pRegisters.0[gCounter / 8], 0);
        for pIndex in 0..3 {
            assert_eq!(pRegisters.0[(0x100 + pIndex * 0x20) / 8], 1 << 5);
        }
        assert!(unsafe { pClock.initialize(pAddress) }.is_err());
        assert_eq!(pClock.millis(), Some(0));
        pRegisters.0[gCounter / 8] = 10_000;
        assert_eq!(pClock.millis(), Some(1));
    }

    #[test]
    fn roundsDownAndPreservesFractionalClockPeriod() {
        let pClock = Hpet::new();
        let mut pRegisters = registers(69_841_279);
        assert_eq!(unsafe { pClock.initialize(pRegisters.0.as_mut_ptr() as usize) }, Ok(()));
        assert_eq!(pClock.observe(14_318), 0);
        assert_eq!(pClock.observe(14_319), 1);
        assert_eq!(pClock.observe(14_318_179), 999);
        assert_eq!(pClock.observe(14_318_181), 1000);
    }

    #[test]
    fn counterRegressionCannotChangeEpochOrFabricateElapsedTime() {
        let pClock = Hpet::new();
        let mut pRegisters = registers(100_000_000);
        assert_eq!(unsafe { pClock.initialize(pRegisters.0.as_mut_ptr() as usize) }, Ok(()));
        assert_eq!(pClock.observe(50_000_000), 5_000);
        assert_eq!(pClock.observe(1), 5_000);
        assert_eq!(pClock.observe(0), 5_000);
        assert_eq!(pClock.observe(50_010_000), 5_001);
    }

    #[test]
    fn largeCounterUsesWideArithmetic() {
        let pClock = Hpet::new();
        let mut pRegisters = registers(100_000_000);
        assert_eq!(unsafe { pClock.initialize(pRegisters.0.as_mut_ptr() as usize) }, Ok(()));
        assert_eq!(pClock.observe(u64::MAX), (u64::MAX as u128 / 10_000) as u64);
    }

    #[test]
    fn concurrentCpuSamplesShareOneMonotonicDomain() {
        use std::{sync::Arc, thread};
        let pClock = Arc::new(Hpet::new());
        pClock.fPeriodFs.store(100_000_000, Ordering::Relaxed);
        let pThreads: Vec<_> = (0..4).map(|pCpu| {
            let pClock = Arc::clone(&pClock);
            thread::spawn(move || {
                let mut pLast = 0;
                for pTick in 0..20_000 {
                    let pNow = pClock.observe((pTick * 10_000 + pCpu * 20_000) as u64);
                    assert!(pNow >= pLast);
                    pLast = pNow;
                }
            })
        }).collect();
        for pThread in pThreads { pThread.join().unwrap(); }
        assert_eq!(pClock.observe(0), 20_005);
    }
}
