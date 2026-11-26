//! Runtime TSC qualification against the independently maintained system
//! clock. Never substitutes TSC for that clock on disagreement: two
//! disagreeing counters alone cannot identify which counter failed.
//! Samples include actual readout uncertainty and the measured CPU offset.
use crate::{clock_quorum::Witness, tsc::Alignment};
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

// A fleet lease is expressed in normalized TSC ticks, not the currently
// selected physical epoch: a stopped physical clock cannot indefinitely
// extend a previously verified lease. Account conservatively for cross-CPU
// alignment, readout and the full comparison-window rate error.
const FLEET_GUARD_NS: u128 = 6_000_000;

#[derive(Clone, Copy)]
struct Member {
    alignment: Option<Alignment>,
    last_raw: Option<u64>,
    last_witness: Option<u64>,
    verified: Option<Point>,
    generation: u64,
}
impl Member {
    const fn new() -> Self { Self { alignment: None, last_raw: None, last_witness: None, verified: None, generation: 0 } }
}

struct Fleet {
    expected: [u64; 4],
    members: [Member; 256],
}
impl Fleet {
    const fn new() -> Self {
        Self { expected: [0; 4], members: [Member::new(); 256] }
    }

    fn register(&mut self, bsp: u32, ids: impl IntoIterator<Item = u8>) -> bool {
        // The current APIC topology uses xAPIC IDs, not a dense CPU index.
        // Publish only a complete, nonduplicated enabled CPU roster.
        let mut mask = [0u64; 4];
        for id in ids {
            let index = id as usize;
            let bit = 1u64 << (index % 64);
            if mask[index/64] & bit != 0 { return false; }
            mask[index/64] |= bit;
        }
        if bsp >= 256 || mask[bsp as usize / 64] & (1u64 << (bsp % 64)) == 0 {
            return false;
        }
        self.expected = mask;
        true
    }

    fn contains(&self, cpu: u32) -> bool {
        cpu < 256 && self.expected[cpu as usize / 64] & (1u64 << (cpu % 64)) != 0
    }

    fn revoke(&mut self, cpu: u32) {
        if self.contains(cpu) { self.members[cpu as usize].verified = None; }
    }

    fn observe(&mut self, cpu: u32, alignment: Alignment, sample: Sample,
               point: Option<Point>, health: Health, completed_window: bool) {
        let member = &mut self.members[cpu as usize];
        member.alignment = Some(alignment);
        member.last_raw = Some(sample.after);
        // Refresh only from a newly completed independent window. Merely
        // reading the candidate repeatedly never renews its own lease.
        if health != Health::Verified {
            member.verified = None;
        } else if completed_window {
            member.verified = point;
        }
    }

    fn witness(&mut self, cpu: u8, alignment: Alignment, raw: u64, hz: u64) -> Option<Witness> {
        if hz == 0 || !self.contains(cpu as u32) { return None; }
        let local = &self.members[cpu as usize];
        if local.alignment != Some(alignment) || raw < local.last_raw? ||
           local.last_witness.map_or(false, |last| raw < last) { return None; }
        let ticks = alignment.normalize(raw)?;
        let guard = u64::try_from((hz as u128 * FLEET_GUARD_NS + 999_999_999)
            / 1_000_000_000).ok()?;
        let uncertainty = guard.checked_add(alignment.uncertainty_ticks)?;
        let now_high = ticks.checked_add(uncertainty)?;
        let max_age = hz as u128 * MAX_GAP_NS as u128 / 1_000_000_000;
        // Use only registered CPU IDs, including sparse APIC IDs. All
        // verified observations must still be fresh on the common scale.
        for (word, mut pending) in self.expected.into_iter().enumerate() {
            while pending != 0 {
                let index = word*64 + pending.trailing_zeros() as usize;
                pending &= pending-1;
                let point = self.members[index].verified?;
                let low = u64::try_from(point.low).ok()?;
                if low > now_high || (now_high-low) as u128 > max_age {
                    return None;
                }
            }
        }
        // A later read may not move backward even within the same
        // qualification lease. This is evidence, never lease renewal.
        self.members[cpu as usize].last_witness = Some(raw);
        Some(Witness { cpu, ticks, hz, uncertainty_ticks: uncertainty })
    }
}

struct MonitorData {
    anchor: Option<Point>,
    fleet: Fleet,
    generation: u64,
}

/// Shared BSP anchor and machine-wide, time-bounded TSC qualification.
/// A gap is not evidence of success; a clear mismatch revokes the entire
/// candidate until a future explicit requalification lifecycle.
pub(crate) struct RuntimeMonitor {
    state: AtomicU8, // 0 disabled, 1 active, 2 rejected
    bsp: AtomicU32,
    hz: AtomicU64,
    gate: AtomicBool,
    data: UnsafeCell<MonitorData>,
}

// SAFETY: data access is serialized by gate. Initialization precedes
// publication to APs. Every runtime caller masks local IRQs. No hardware
// reads or other kernel lock acquisitions occur inside gate.
unsafe impl Sync for RuntimeMonitor {}

impl RuntimeMonitor {
    pub const fn new() -> Self {
        Self { state: AtomicU8::new(0), bsp: AtomicU32::new(0), hz: AtomicU64::new(0),
               gate: AtomicBool::new(false),
               data: UnsafeCell::new(MonitorData { anchor: None, fleet: Fleet::new(), generation: 0 }) }
    }

    /// Once, on the BSP before runtime publication, only if every enabled
    /// CPU has an independently qualified rate and bounded startup offset.
    pub fn start(&self, bsp: u32, hz: u64, ids: impl IntoIterator<Item = u8>) -> bool {
        self.with_data(|data| {
            if hz == 0 || self.state.load(Ordering::Relaxed) != 0 ||
               !data.fleet.register(bsp, ids) { return false; }
            self.bsp.store(bsp, Ordering::Relaxed);
            self.hz.store(hz, Ordering::Relaxed);
            self.state.store(1, Ordering::Release);
            true
        })
    }

    pub fn active(&self) -> bool { self.state.load(Ordering::Acquire) == 1 }

    fn with_data<R>(&self, f: impl FnOnce(&mut MonitorData) -> R) -> R {
        while self.gate.swap(true, Ordering::Acquire) {
            while self.gate.load(Ordering::Relaxed) { spin_loop(); }
        }
        let result = f(unsafe { &mut *self.data.get() });
        self.gate.store(false, Ordering::Release);
        result
    }

    /// IRQs must be masked. The caller owns its per-CPU Watchdog.
    pub fn observe(&self, cpu: u32, rate: u64, alignment: Alignment,
                   watchdog: &mut Watchdog, sample: Option<Sample>) -> Health {
        self.observe_at(Some(0), cpu, rate, alignment, watchdog, sample)
    }

    /// A recovered independent physical epoch starts a new reference
    /// generation. Invalidate the entire fleet before accepting any new
    /// measurement; an in-flight sample of the old generation must never
    /// renew a lease. The caller passes the generation of the actual
    /// clock snapshot, not one obtained later from another read.
    pub fn observe_at(&self, generation: Option<u64>, cpu: u32, rate: u64,
                      alignment: Alignment, watchdog: &mut Watchdog,
                      sample: Option<Sample>) -> Health {
        self.with_data(|data| {
            if !self.active() { return watchdog.health(); }
            if !data.fleet.contains(cpu) { return watchdog.unverified(); }
            if let Some(generation) = generation {
                if generation < data.generation { return watchdog.health(); }
                if generation > data.generation {
                    data.generation = generation;
                    data.anchor = None;
                    for member in &mut data.fleet.members { member.verified = None; }
                }
            }
            let Some(sample) = sample.filter(|_| generation.is_some()) else {
                data.fleet.revoke(cpu);
                return watchdog.unverified();
            };
            let member = &mut data.fleet.members[cpu as usize];
            if member.generation != data.generation {
                // Restart reference interval measurements, not the raw
                // monotonicity and startup alignment of the actual CPU.
                if member.last_raw.map_or(false, |last| sample.before < last) ||
                   member.last_witness.map_or(false, |last| sample.after < last) {
                    self.state.store(2, Ordering::Release);
                    return watchdog.reject();
                }
                *watchdog = Watchdog::new();
                member.generation = data.generation;
            }
            let hz = self.hz.load(Ordering::Relaxed);
            let bsp = cpu == self.bsp.load(Ordering::Relaxed);
            let normalized = sample.point(rate, alignment);
            let old_alignment = data.fleet.members[cpu as usize].alignment;
            let cross = if rate == 0 || rate.abs_diff(hz) as u128 * 1000 > rate.min(hz) as u128 ||
                           old_alignment.map_or(false, |old| old != alignment) {
                Comparison::Disagree
            } else if bsp {
                Comparison::Match
            } else if let Some(point) = normalized {
                match data.anchor {
                    Some(origin) => compare(origin, point, hz),
                    None => Comparison::Stale,
                }
            } else {
                Comparison::Stale
            };
            let previous = watchdog.baseline.map(|p| p.ns);
            let health = watchdog.observe(sample, rate, cross);
            let completed_window = watchdog.baseline.map(|p| p.ns) != previous;
            data.fleet.observe(cpu, alignment, sample, normalized, health, completed_window);
            if health == Health::Rejected {
                self.state.store(2, Ordering::Release);
            } else if bsp && normalized.is_some() &&
                      data.anchor.map_or(true, |old| sample.reference_ns >= old.ns) {
                data.anchor = normalized;
            }
            health
        })
    }

    /// This reads only evidence already published by independent watchdog
    /// observations. The caller samples the local TSC outside this lock,
    /// with IRQs masked; witness acquisition never calls the system clock.
    pub fn witness(&self, cpu: u8, alignment: Alignment, raw: u64) -> Option<Witness> {
        self.witness_at(0, cpu, alignment, raw)
    }

    pub fn witness_at(&self, generation: u64, cpu: u8,
                      alignment: Alignment, raw: u64) -> Option<Witness> {
        if !self.active() { return None; }
        self.with_data(|data| {
            if !self.active() || generation != data.generation { return None; }
            data.fleet.witness(cpu, alignment, raw, self.hz.load(Ordering::Relaxed))
        })
    }

    /// Two independent physical clocks contradicted the candidate. Stop
    /// granting leases and remove its maintenance requirement. This never
    /// changes the system clock or reads any hardware under the gate.
    pub fn reject(&self) {
        self.with_data(|_| {
            if self.active() { self.state.store(2, Ordering::Release); }
        });
    }
}

pub(crate) static MONITOR: RuntimeMonitor = RuntimeMonitor::new();
