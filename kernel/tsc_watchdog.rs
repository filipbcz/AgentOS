//! Runtime TSC qualification against the independently maintained system
//! clock. Never substitutes TSC for that clock on disagreement: two
//! disagreeing counters alone cannot identify which counter failed.
//! Samples include actual readout uncertainty and the measured CPU offset.
use crate::tsc::Alignment;
use core::{cell::UnsafeCell, hint::spin_loop,
    sync::atomic::{AtomicBool, AtomicU8, AtomicU32, AtomicU64, Ordering}};

pub const INTERVAL_MS: u64 = 1000;
const WINDOW_NS: u64 = 500_000_000;
const MAX_GAP_NS: u64 = 2_500_000_000;
const MAX_READ_NS: u64 = 50_000;
const BASE_ERROR_NS: u64 = 2_000;
const GOOD_WINDOWS: u8 = 3;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Health { Pending, Verified, Unverified, Rejected }

impl Health {
    pub fn message(self) -> &'static [u8] {
        match self {
            Self::Pending => b"TSC WATCHDOG: acquiring independent observations",
            Self::Verified => b"TSC WATCHDOG: rate and CPU offset verified",
            Self::Unverified => b"TSC WATCHDOG: observation unavailable or stale",
            Self::Rejected => b"TSC WATCHDOG: counters disagree; TSC not safe as clocksource",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Sample {
    pub reference_ns: u64,
    pub before: u64,
    pub after: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Point {
    ns: u64,
    low: i128,
    high: i128,
}

impl Sample {
    fn point(self, hz: u64, alignment: Alignment) -> Option<Point> {
        if hz == 0 ||
           self.after.checked_sub(self.before)? as u128 * 1_000_000_000 >
               hz as u128 * MAX_READ_NS as u128 {
            return None;
        }
        let low = alignment.normalize(self.before)? as i128;
        let high = alignment.normalize(self.after)? as i128;
        let error = alignment.uncertainty_ticks as i128;
        Some(Point { ns: self.reference_ns, low: low-error, high: high+error })
    }

    fn local(self, hz: u64) -> Option<Point> {
        self.point(hz, Alignment { offset: 0, uncertainty_ticks: 0 })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Comparison { Match, Disagree, Stale }

/// Compare signed intervals, allowing the other CPU's observation to have
/// happened either before or after ours. Use a rate error budget of 1000
/// ppm plus two microseconds for reference tick quantization. Bracket and
/// initial AP alignment uncertainties are already included in the ranges.
/// All products are bounded: a comparison never spans more than 2.5 s.
fn compare(earlier: Point, later: Point, hz: u64) -> Comparison {
    if hz == 0 { return Comparison::Disagree; }
    let elapsed = later.ns as i128 - earlier.ns as i128;
    if elapsed.unsigned_abs() > MAX_GAP_NS as u128 { return Comparison::Stale; }
    let error = (elapsed.unsigned_abs()/1000 + BASE_ERROR_NS as u128) as i128;
    let scale = 1_000_000_000i128;
    let expected_low = (elapsed-error) * hz as i128;
    let expected_high = (elapsed+error) * hz as i128;
    let observed_low = (later.low-earlier.high) * scale;
    let observed_high = (later.high-earlier.low) * scale;
    if observed_low <= expected_high && expected_low <= observed_high {
        Comparison::Match
    } else { Comparison::Disagree }
}

pub(crate) struct Watchdog {
    baseline: Option<Point>,
    last: Option<Sample>,
    good: u8,
    health: Health,
}

impl Watchdog {
    pub const fn new() -> Self {
        Self { baseline: None, last: None, good: 0, health: Health::Pending }
    }
    pub fn health(&self) -> Health { self.health }

    fn unverified(&mut self) -> Health {
        self.baseline = None;
        self.good = 0;
        self.health = Health::Unverified;
        self.health
    }

    fn reject(&mut self) -> Health {
        self.good = 0;
        self.health = Health::Rejected;
        self.health
    }

    /// Only the owning CPU mutates this state, with its local IRQs masked.
    /// Frequent syscalls/interrupts do not rebase a short observation:
    /// three distinct >=500ms windows are required, not three reads.
    fn observe(&mut self, sample: Sample, hz: u64, cross: Comparison) -> Health {
        if self.health == Health::Rejected { return self.health; }
        if sample.before > sample.after || self.last.map_or(false, |last|
            sample.before < last.after || sample.reference_ns < last.reference_ns) {
            return self.reject();
        }
        self.last = Some(sample);
        let Some(point) = sample.local(hz) else { return self.unverified(); };
        if cross == Comparison::Disagree { return self.reject(); }
        if cross == Comparison::Stale { return self.unverified(); }

        let Some(base) = self.baseline else {
            self.baseline = Some(point);
            return self.health;
        };
        let elapsed = point.ns-base.ns;
        // If the reference has stopped, compare based on observed TSC
        // progress as well; never wait for a frozen clock to reach a deadline.
        let tsc_advanced = (point.low-base.high).max(0) as u128 *
            1_000_000_000 >= hz as u128 * WINDOW_NS as u128;
        if elapsed < WINDOW_NS && !tsc_advanced { return self.health; }
        match compare(base, point, hz) {
            Comparison::Disagree => self.reject(),
            Comparison::Stale => {
                self.unverified();
                self.baseline = Some(point);
                self.health
            }
            Comparison::Match => {
                if elapsed < WINDOW_NS { return self.health; }
                self.baseline = Some(point);
                self.good = self.good.saturating_add(1);
                self.health = if self.good >= GOOD_WINDOWS { Health::Verified } else { Health::Pending };
                self.health
            }
        }
    }
}

/// Shared BSP anchor. Each AP uses its startup offset to compare its current
/// normalized TSC with a recent independent observation from the BSP.
/// A gap is not evidence of success; a clear mismatch revokes this candidate
/// for the entire machine until a future explicit requalification lifecycle.
pub(crate) struct RuntimeMonitor {
    state: AtomicU8, // 0 disabled, 1 active, 2 rejected
    bsp: AtomicU32,
    hz: AtomicU64,
    gate: AtomicBool,
    anchor: UnsafeCell<Option<Point>>,
}

// SAFETY: anchor access is serialized by gate. Initialization precedes
// publication to APs. Every caller of observe is a kernel CPU with IRQs
// masked; no hardware read or other lock acquisition occurs inside gate.
unsafe impl Sync for RuntimeMonitor {}

impl RuntimeMonitor {
    pub const fn new() -> Self {
        Self { state: AtomicU8::new(0), bsp: AtomicU32::new(0), hz: AtomicU64::new(0),
               gate: AtomicBool::new(false), anchor: UnsafeCell::new(None) }
    }

    /// Once, on the BSP before runtime publication, only if every enabled
    /// CPU has an independently qualified rate and bounded startup offset.
    pub fn start(&self, bsp: u32, hz: u64) {
        if hz == 0 || self.state.load(Ordering::Relaxed) != 0 { return; }
        self.bsp.store(bsp, Ordering::Relaxed);
        self.hz.store(hz, Ordering::Relaxed);
        self.state.store(1, Ordering::Release);
    }

    pub fn active(&self) -> bool { self.state.load(Ordering::Acquire) == 1 }

    fn with_anchor<R>(&self, f: impl FnOnce(&mut Option<Point>) -> R) -> R {
        while self.gate.swap(true, Ordering::Acquire) {
            while self.gate.load(Ordering::Relaxed) { spin_loop(); }
        }
        let result = f(unsafe { &mut *self.anchor.get() });
        self.gate.store(false, Ordering::Release);
        result
    }

    /// IRQs must be masked; the caller owns its Watchdog. Measurements have
    /// already been acquired, so lock ordering cannot involve MMIO or time.
    pub fn observe(&self, cpu: u32, rate: u64, alignment: Alignment,
                   watchdog: &mut Watchdog, sample: Option<Sample>) -> Health {
        if !self.active() { return watchdog.health(); }
        let Some(sample) = sample else { return watchdog.unverified(); };
        let hz = self.hz.load(Ordering::Relaxed);
        let bsp = cpu == self.bsp.load(Ordering::Relaxed);
        let normalized = sample.point(rate, alignment);
        let cross = if bsp {
            Comparison::Match
        } else if let Some(point) = normalized {
            self.with_anchor(|anchor| match *anchor {
                Some(origin) => compare(origin, point, hz),
                None => Comparison::Stale,
            })
        } else {
            Comparison::Stale
        };
        let health = watchdog.observe(sample, rate, cross);
        if health == Health::Rejected {
            self.state.store(2, Ordering::Release);
        } else if bsp && normalized.is_some() {
            self.with_anchor(|anchor| {
                // A wide or invalid sample must not replace a usable anchor.
                if anchor.map_or(true, |old| sample.reference_ns >= old.ns) {
                    *anchor = normalized;
                }
            });
        }
        health
    }
}

pub(crate) static MONITOR: RuntimeMonitor = RuntimeMonitor::new();
