//! Bounded kernel log history with a non-blocking SMP/IRQ-safe owner gate.
//! Callers MUST NOT hold this gate while doing UART/framebuffer I/O or sleeping.
//! Acquisition fails immediately rather than deadlocking on a same-CPU interrupt;
//! loss is counted explicitly. Records carry owned bytes, not borrowed pointers.
use core::{cell::UnsafeCell, sync::atomic::{AtomicBool, AtomicU64, Ordering}};
use crate::{log_policy::Level, log_ring::{ReadResult, Ring}};

pub static LOGGER: Logger = Logger::new();

pub struct Logger {
    gate: AtomicBool,
    ring: UnsafeCell<Ring>,
    dropped: AtomicU64,
}
// SAFETY: mutable Ring access is exclusively guarded by atomic compare_exchange;
// no guard is retained across a blocking operation. A contending IRQ drops its
// event rather than spinning on an interrupted owner.
unsafe impl Sync for Logger {}

struct Guard<'a>(&'a AtomicBool);
impl Drop for Guard<'_> {
    fn drop(&mut self) { self.0.store(false, Ordering::Release); }
}

impl Logger {
    pub const fn new() -> Self {
        Self { gate: AtomicBool::new(false), ring: UnsafeCell::new(Ring::new()), dropped: AtomicU64::new(0) }
    }

    fn try_guard(&self) -> Option<Guard<'_>> {
        self.gate.compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .ok().map(|_| Guard(&self.gate))
    }

    fn note_drop(&self) {
        // Saturate rather than wrapping; no indefinite retry in IRQ context.
        let _ = self.dropped.fetch_update(Ordering::Relaxed, Ordering::Relaxed,
            |n| if n == u64::MAX { None } else { Some(n + 1) });
    }

    /// Non-blocking even in IRQ context. false means contention or exhausted
    /// sequence space, never an unreported silent overwrite.
    pub fn record(&self, ticks: u64, cpu: u32, level: Level, message: &[u8]) -> bool {
        let Some(_guard) = self.try_guard() else { self.note_drop(); return false; };
        // SAFETY: _guard is the unique writer; readers use the same gate.
        let result = unsafe { (*self.ring.get()).push(ticks, cpu, level, message) };
        if !result { self.note_drop(); }
        result
    }

    /// A None result means a busy producer/reader, not an absent record.
    pub fn read(&self, sequence: u64) -> Option<ReadResult> {
        let _guard = self.try_guard()?;
        // SAFETY: ReadResult owns its Record; no borrow escapes the gate.
        Some(unsafe { (*self.ring.get()).read(sequence) })
    }

    pub fn dropped(&self) -> u64 { self.dropped.load(Ordering::Relaxed) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{sync::Arc, thread};

    #[test]
    fn storesOwnedRecordAndPreservesMetadata() {
        let log = Logger::new();
        let mut input = *b"hello";
        assert!(log.record(29, 7, Level::Error, &input));
        input[0] = b'X';
        match log.read(0) {
            Some(ReadResult::Record(r)) => {
                assert_eq!(r.message(), b"hello");
                assert_eq!(r.timestamp, 29);
                assert_eq!(r.cpu, 7);
                assert_eq!(r.level, Level::Error);
            }
            _ => panic!("missing record"),
        }
    }

    #[test]
    fn reentrantIrqNeverSpinsAndCountsLoss() {
        let log = Logger::new();
        let guard = log.try_guard().expect("first owner");
        assert!(!log.record(0, 0, Level::Info, b"interrupt"));
        assert!(log.read(0).is_none());
        assert_eq!(log.dropped(), 1);
        drop(guard);
        assert!(log.record(0, 0, Level::Info, b"after IRQ"));
    }

    #[test]
    fn concurrentProducersAccountForEveryAttempt() {
        const THREADS: usize = 4;
        const ITERATIONS: usize = 1000;
        let log = Arc::new(Logger::new());
        let successes: usize = thread::scope(|scope| {
            let mut threads = Vec::new();
            for cpu in 0..THREADS {
                let log = Arc::clone(&log);
                threads.push(scope.spawn(move || {
                    (0..ITERATIONS).filter(|&i| log.record(i as u64, cpu as u32, Level::Info, b"event")).count()
                }));
            }
            threads.into_iter().map(|h| h.join().unwrap()).sum()
        });
        assert_eq!(successes + log.dropped() as usize, THREADS * ITERATIONS);
    }

    #[test]
    fn boundedInOneKernelFrame() {
        assert!(core::mem::size_of::<Logger>() <= 4096);
    }
}
