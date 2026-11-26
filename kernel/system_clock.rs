//! A shared monotonic epoch with a continuously qualified hardware standby.
//! Physical counter reads, modulo extension and source transitions are
//! serialized by one IRQ-safe SMP gate. Qualified normalized TSC can
//! preserve time during bounded holdover, never certify its own rate.
use crate::{clock_quorum::{self, Span, TscBracket, Verdict, Witness},
    reference_clock::{PmTimer, ReferenceClock}};
use core::{arch::asm, cell::UnsafeCell, hint::spin_loop,
    sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering}};

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

    fn ns(&self) -> u128 { self.source.wide_ns(self.ticks) }

    fn advance(&mut self, raw: u64) -> Option<u128> {
        if !self.valid { return None; }
        let raw = raw & self.source.mask();
        let Some(delta) = self.source.delta(self.last, raw) else {
            self.valid = false;
            return None;
        };
        self.last = raw;
        self.ticks = self.ticks.saturating_add(delta as u128);
        Some(self.ns())
    }

    pub(crate) fn observe(&mut self, raw: u64) -> Option<u64> {
        self.advance(raw)?;
        Some(self.source.ticks_to_ms(self.ticks))
    }
}

pub(crate) fn choose(pm: Option<PmTimer>, hp: Option<ReferenceClock>,
                     mut progressing: impl FnMut(ReferenceClock) -> bool) -> Option<ReferenceClock> {
    [hp, pm.map(ReferenceClock::Pm)].into_iter().flatten()
        .find(|&source| source.maintenance_ms() != Some(0) && progressing(source))
}

const WINDOW_NS: u128 = 100_000_000;
const QUALIFY_WINDOWS: u8 = 3;
const BRACKET_NS: u128 = 200_000;
const JITTER_NS: u128 = 100_000;
const MAX_GAP_NS: u128 = 2_000_000_000;
const MAX_ANCHOR_AGE_NS: u128 = 2_500_000_000;
const STALL_NS: u128 = 100_000_000;
const RECOVERY_MS: u64 = 100;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum ClockEvent {
    StandbyRetired = 1, PromotedPm = 2, PromotedHpet = 3,
    Unavailable = 4, StandbyRebased = 5, TscRejected = 6, PromotedTsc = 7,
    RecoveredPm = 8, RecoveredHpet = 9, StandbyRecovered = 10,
}

impl ClockEvent {
    pub fn message(self) -> &'static [u8] {
        match self {
            Self::StandbyRetired => b"SYSTEM CLOCK: standby counter invalid; retaining active source",
            Self::PromotedPm => b"SYSTEM CLOCK: switched to qualified ACPI PM timer",
            Self::PromotedHpet => b"SYSTEM CLOCK: switched to qualified HPET",
            Self::Unavailable => b"SYSTEM CLOCK: no trustworthy elapsed time; epoch unavailable",
            Self::StandbyRebased => b"SYSTEM CLOCK: standby wrap ambiguous; requalifying",
            Self::TscRejected => b"SYSTEM CLOCK: two physical references disagree with TSC; witness retired",
            Self::PromotedTsc => b"SYSTEM CLOCK: physical references invalid; qualified TSC holdover",
            Self::RecoveredPm => b"SYSTEM CLOCK: requalified ACPI PM timer; leaving TSC holdover",
            Self::RecoveredHpet => b"SYSTEM CLOCK: requalified HPET; leaving TSC holdover",
            Self::StandbyRecovered => b"SYSTEM CLOCK: quarantined standby requalified and restored",
        }
    }
    pub fn error(self) -> bool { self == Self::Unavailable }
}

#[derive(Clone, Copy)]
struct Pair { low: u128, high: u128, shadow: u128 }

#[derive(Clone, Copy)]
struct Anchor { global: u128, shadow: u128 }

#[derive(Clone, Copy)]
struct TripleAnchor {
    pair: Pair,
    tsc: TscBracket,
    global: u128,
}

#[derive(Clone, Copy)]
struct SingleAnchor { physical: Span, tsc: TscBracket, global: u128 }

/// Keep the original independently verified anchor for the entire
/// holdover. Never accumulate uncertain per-read deltas or rebase the
/// origin from TSC-derived time. The provider must independently grant
/// a fresh fleet lease on every read.
struct Holdover {
    origin: TscBracket,
    latest: TscBracket,
    global: u128,
}

impl Holdover {
    fn advance(&mut self, current: TscBracket) -> Option<u128> {
        let span = self.origin.elapsed(current)?;
        if span.high > MAX_ANCHOR_AGE_NS { return None; }
        self.latest = self.latest.advance(current)?;
        // Lower elapsed bound avoids charging uncertain read latency to
        // an existing absolute deadline. Publish clamps overlapping
        // cross-CPU samples to the prior global high-water mark.
        self.global.checked_add(span.low)
    }
}

/// A previously failed device is not a clocksource until its *new* raw
/// history agrees with the still independently qualified TSC. No old
/// modulo residue, device reset, or absolute counter value is trusted.
struct RecoveryHistory {
    epoch: Epoch,
    origin: TscBracket,
    previous: TscBracket,
    checkpoint: TscBracket,
    checkpoint_ns: u128,
    windows: u8,
}

struct Recovery {
    source: ReferenceClock,
    history: Option<RecoveryHistory>,
}

impl Recovery {
    fn new(source: ReferenceClock) -> Self { Self { source, history: None } }

    fn reset(&mut self, raw: u64, bracket: TscBracket) {
        self.history = Some(RecoveryHistory {
            epoch: Epoch::new(self.source, raw),
            origin: bracket, previous: bracket, checkpoint: bracket,
            checkpoint_ns: 0, windows: 0,
        });
    }

    fn observe(&mut self, raw: u64, bracket: TscBracket) -> bool {
        // Check the gap before interpreting a modulo delta. A plausible
        // residue after an ambiguous wrap cannot qualify a device.
        let Some(history) = self.history.as_mut() else {
            self.reset(raw, bracket);
            return false;
        };
        let gap = history.previous.elapsed(bracket);
        let total = history.origin.elapsed(bracket);
        let window = history.checkpoint.elapsed(bracket);
        let elapsed = history.epoch.advance(raw);
        let (Some(gap), Some(total), Some(window), Some(ns)) =
            (gap, total, window, elapsed) else {
                self.reset(raw, bracket);
                return false;
            };
        let Some(delta) = ns.checked_sub(history.checkpoint_ns) else {
            self.reset(raw, bracket);
            return false;
        };
        if gap.high > self.source.half_span_ns() ||
           gap.high > MAX_GAP_NS || total.high > MAX_GAP_NS ||
           !Span::exact(ns).agrees(total) || !Span::exact(delta).agrees(window) {
            self.reset(raw, bracket);
            return false;
        }
        history.previous = bracket;
        if window.low >= WINDOW_NS {
            if delta < WINDOW_NS/2 {
                self.reset(raw, bracket);
                return false;
            }
            history.windows = history.windows.saturating_add(1);
            history.checkpoint = bracket;
            history.checkpoint_ns = ns;
        }
        history.windows >= QUALIFY_WINDOWS
    }
}

/// Physical-only standby qualification. The primary is already the
/// authoritative independent reference; the quarantined device cannot
/// influence that epoch, watchdog evidence, or a failover before it
/// completes a new history. Bracket the shadow read with primary reads.
struct StandbyProbe {
    epoch: Epoch,
    origin: Span,
    previous: Span,
    checkpoint: Span,
    checkpoint_ns: u128,
    windows: u8,
}

impl StandbyProbe {
    fn new(source: ReferenceClock, raw: u64, primary: Span) -> Self {
        Self { epoch: Epoch::new(source, raw), origin: primary,
               previous: primary, checkpoint: primary, checkpoint_ns: 0, windows: 0 }
    }

    /// None means all preceding evidence must be discarded. A plausible
    /// modulo residue after an excessive sampling gap is not evidence.
    fn observe(&mut self, raw: u64, primary: Span) -> Option<bool> {
        let gap = Span::elapsed(self.previous, primary)?;
        let total = Span::elapsed(self.origin, primary)?;
        let window = Span::elapsed(self.checkpoint, primary)?;
        if gap.high > self.epoch.source.half_span_ns() ||
           gap.high > MAX_GAP_NS || total.high > MAX_GAP_NS { return None; }
        let ns = self.epoch.advance(raw)?;
        let delta = ns.checked_sub(self.checkpoint_ns)?;
        if !Span::exact(ns).agrees(total) || !Span::exact(delta).agrees(window) {
            return None;
        }
        self.previous = primary;
        if window.low >= WINDOW_NS {
            if delta == 0 { return None; }
            self.windows = self.windows.saturating_add(1);
            self.checkpoint = primary;
            self.checkpoint_ns = ns;
        }
        Some(self.windows >= QUALIFY_WINDOWS)
    }
}

#[derive(Clone, Copy)]
struct WitnessHooks {
    read: fn(u64) -> Option<Witness>,
    reject: fn(),
}

/// The pure transition logic receives actual register observations through
/// one read operation. Host fixtures exercise the identical implementation.
pub(crate) struct ClockSet {
    primary: Epoch,
    standby: Option<Epoch>,
    base_ns: u128,
    published_ns: u128,
    baseline: Option<Pair>,
    good_windows: u8,
    anchor: Option<Anchor>,
    stall_samples: u8,
    failed: bool,
    event: Option<ClockEvent>,
    triple: Option<TripleAnchor>,
    single: Option<SingleAnchor>,
    single_qualified: bool,
    holdover: Option<Holdover>,
    recovery: [Option<Recovery>; 2],
    standby_probe: Option<StandbyProbe>,
    reference_generation: u64,
    witness_rejected: bool,
    witness_hooks: Option<WitnessHooks>,
}

impl ClockSet {
    pub(crate) fn new(primary: (ReferenceClock, u64),
                      standby: Option<(ReferenceClock, u64)>) -> Self {
        let standby = standby.filter(|(source, _)| *source != primary.0)
            .map(|(source, first)| Epoch::new(source, first));
        let recovery = [Some(Recovery::new(primary.0)),
            standby.as_ref().map(|epoch| Recovery::new(epoch.source))];
        Self { primary: Epoch::new(primary.0, primary.1), standby,
            base_ns: 0, published_ns: 0, baseline: None, good_windows: 0,
            anchor: None, stall_samples: 0, failed: false, event: None,
            triple: None, single: None, single_qualified: false,
            holdover: None, recovery, standby_probe: None, reference_generation: 0,
            witness_rejected: false, witness_hooks: None }
    }

    pub(crate) fn source(&self) -> Option<ReferenceClock> {
        (!self.failed && self.holdover.is_none()).then_some(self.primary.source)
    }

    pub(crate) fn using_tsc(&self) -> bool { !self.failed && self.holdover.is_some() }

    pub(crate) fn view(&self, ns: u128) -> ClockSnapshot {
        let holdover = self.using_tsc();
        ClockSnapshot {
            millis: (ns / 1_000_000).min(isize::MAX as u128) as u64,
            independent_ns: if holdover { None } else { u64::try_from(ns).ok() },
            holdover,
            reference_generation: self.reference_generation,
        }
    }
    pub(crate) fn qualified(&self) -> bool { self.anchor.is_some() && !self.failed }
    pub(crate) fn take_event(&mut self) -> Option<ClockEvent> { self.event.take() }

    pub(crate) fn maintenance_ms(&self) -> Option<u64> {
        if self.failed { return None; }
        if self.using_tsc() {
            // Probe often enough to qualify before the independent TSC
            // lease expires, also respecting any narrow counter width.
            return Some(self.recovery.iter().flatten()
                .filter_map(|candidate| candidate.source.maintenance_ms())
                .fold(RECOVERY_MS, u64::min));
        }
        let active = self.primary.source.maintenance_ms();
        let standby = if self.standby.is_none() {
            self.quarantined_source().map(Self::probe_interval_ms)
        } else {
            self.standby.as_ref().and_then(|s| s.source.maintenance_ms())
        };
        match (active, standby) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (Some(a), None) | (None, Some(a)) => Some(a),
            _ => None,
        }
    }

    /// Only devices discovered, mapped and successfully initialized at
    /// boot are retained in this catalog. Do not touch arbitrary MMIO
    /// addresses or an uninitialized timer during runtime recovery.
    fn quarantined_source(&self) -> Option<ReferenceClock> {
        if self.standby.is_some() { return None; }
        self.recovery.iter().flatten()
            .map(|candidate| candidate.source)
            .find(|&source| source != self.primary.source)
    }

    fn probe_interval_ms(source: ReferenceClock) -> u64 {
        source.maintenance_ms().unwrap_or(RECOVERY_MS).min(RECOVERY_MS)
    }

    fn due_probe(&self, low: u128) -> Option<ReferenceClock> {
        let source = self.quarantined_source()?;
        if let Some(probe) = &self.standby_probe {
            if probe.epoch.source == source &&
               low.saturating_sub(probe.previous.high) <
                   Self::probe_interval_ms(source) as u128 * 1_000_000 {
                return None;
            }
        }
        Some(source)
    }

    fn qualify_standby_probe(&mut self, source: ReferenceClock, raw: u64,
                             primary: Span, witness_available: bool) {
        // The primary read itself must be usable. If an independent TSC
        // witness was available, the single-source checker must also
        // confirm a consistent physical/TSC pair before rejoining.
        if primary.high-primary.low > BRACKET_NS ||
           (witness_available && !self.single_qualified) {
            self.standby_probe = None;
            return;
        }
        let result = self.standby_probe.as_mut()
            .filter(|probe| probe.epoch.source == source)
            .and_then(|probe| probe.observe(raw, primary));
        match result {
            None => self.standby_probe = Some(StandbyProbe::new(source, raw, primary)),
            Some(false) => {},
            Some(true) => {
                // The three new windows are precisely the normal
                // physical qualification, with an additional cumulative
                // check. Attach the new counter with a fresh epoch and
                // a bracketed anchor; no prior failed elapsed value
                // crosses the quarantine boundary.
                self.standby = Some(Epoch::new(source, raw));
                self.standby_probe = None;
                self.triple = None;
                self.baseline = Some(Pair {
                    low: primary.low, high: primary.high, shadow: 0,
                });
                self.good_windows = QUALIFY_WINDOWS;
                self.stall_samples = 0;
                self.anchor = Some(Anchor {
                    global: self.base_ns.saturating_add(primary.low), shadow: 0,
                });
                self.event = Some(ClockEvent::StandbyRecovered);
            }
        }
    }

    fn clear_qualification(&mut self) {
        self.baseline = None;
        self.good_windows = 0;
        self.anchor = None;
        self.stall_samples = 0;
    }

    fn retire_standby(&mut self) {
        self.standby_probe = None;
        self.triple = None;
        self.standby = None;
        self.clear_qualification();
        self.event = Some(ClockEvent::StandbyRetired);
    }

    fn rebase_standby(&mut self, source: ReferenceClock, raw: u64) {
        // Unknown elapsed history invalidates only the standby epoch.
        // Re-observe agreement before it may preserve absolute time.
        self.triple = None;
        self.standby = Some(Epoch::new(source, raw));
        self.standby_probe = None;
        self.clear_qualification();
        self.event = Some(ClockEvent::StandbyRebased);
    }

    fn unavailable(&mut self) -> Option<u128> {
        self.failed = true;
        self.standby_probe = None;
        self.triple = None;
        self.single = None;
        self.single_qualified = false;
        self.holdover = None;
        self.clear_qualification();
        self.event = Some(ClockEvent::Unavailable);
        None
    }

    fn publish(&mut self, time: u128) -> Option<u128> {
        if time < self.published_ns { return self.unavailable(); }
        self.published_ns = time;
        Some(time)
    }

    /// Preserve the last published epoch and every existing absolute
    /// deadline. Do not reset time to the standby's power-on value.
    /// The anchor is the lower end of the bounded primary read bracket.
    fn promote(&mut self, shadow_ns: u128, step: u128) -> Option<u128> {
        let Some(anchor) = self.anchor else { return self.unavailable(); };
        let Some(elapsed) = shadow_ns.checked_sub(anchor.shadow) else {
            return self.unavailable();
        };
        if step > MAX_GAP_NS || elapsed == 0 || elapsed > MAX_ANCHOR_AGE_NS {
            return self.unavailable();
        }
        let Some(time) = anchor.global.checked_add(elapsed) else { return self.unavailable(); };
        let Some(standby) = self.standby.take() else { return self.unavailable(); };
        let time = time.max(self.published_ns);
        self.base_ns = time;
        self.primary = Epoch::new(standby.source, standby.last);
        self.standby_probe = None;
        self.triple = None;
        self.clear_qualification();
        self.event = Some(match self.primary.source {
            ReferenceClock::Pm(_) => ClockEvent::PromotedPm,
            ReferenceClock::Hpet { .. } => ClockEvent::PromotedHpet,
        });
        self.publish(time)
    }

    fn enter_holdover(&mut self, origin: TscBracket, current: TscBracket,
                      global: u128) -> Option<u128> {
        let Some(span) = origin.elapsed(current) else { return self.unavailable(); };
        if self.witness_rejected || span.high > MAX_GAP_NS { return self.unavailable(); }
        let mut holdover = Holdover { origin, latest: origin, global };
        let Some(time) = holdover.advance(current) else { return self.unavailable(); };
        self.standby = None;
        self.triple = None;
        self.single = None;
        self.single_qualified = false;
        self.clear_qualification();
        for candidate in self.recovery.iter_mut().flatten() { candidate.history = None; }
        self.standby_probe = None;
        self.holdover = Some(holdover);
        self.event = Some(ClockEvent::PromotedTsc);
        self.publish(time.max(self.published_ns))
    }

    fn continue_holdover(&mut self, mut read: impl FnMut(ReferenceClock) -> u64,
                         mut witness: impl FnMut() -> Option<Witness>) -> Option<u128> {
        // Only read the already initialized, mapped physical devices.
        // Their failed Epoch objects are never used to compute time again.
        let Some(before) = witness() else { return self.unavailable(); };
        let raw = core::array::from_fn::<_, 2, _>(|i|
            self.recovery[i].as_ref().map(|candidate| read(candidate.source)));
        let Some(after) = witness() else { return self.unavailable(); };
        if before.cpu != after.cpu || before.hz != after.hz || after.ticks < before.ticks {
            return self.unavailable();
        }
        let Some(current) = TscBracket::new(after, after) else { return self.unavailable(); };
        let Some(time) = self.holdover.as_mut().and_then(|h| h.advance(current))
            else { return self.unavailable(); };
        let time = time.max(self.published_ns);
        let Some(bracket) = TscBracket::new(before, after) else {
            // A slow or uncertain register read cannot corroborate a
            // device. It does not itself prove TSC has failed.
            for candidate in self.recovery.iter_mut().flatten() { candidate.history = None; }
            return self.publish(time);
        };

        let mut ready = [false; 2];
        for i in 0..2 {
            if let (Some(candidate), Some(raw)) = (&mut self.recovery[i], raw[i]) {
                ready[i] = candidate.observe(raw, bracket);
            }
        }
        if let Some(index) = ready.iter().position(|&qualified| qualified) {
            // A new physical epoch starts at the current monotonic time;
            // arbitrary reset values never become absolute timestamps.
            // The other recovered source, if present, must qualify again
            // as a standby against the restored physical primary.
            let source = self.recovery[index].as_ref().unwrap().source;
            let Some(first) = raw[index] else { return self.unavailable(); };
            let other = 1-index;
            let standby = if ready[other] {
                self.recovery[other].as_ref().zip(raw[other])
                    .map(|(candidate, first)| Epoch::new(candidate.source, first))
            } else { None };
            let Some(generation) = self.reference_generation.checked_add(1)
                else { return self.unavailable(); };
            self.base_ns = time;
            self.primary = Epoch::new(source, first);
            self.standby = standby;
            self.standby_probe = None;
            self.holdover = None;
            self.reference_generation = generation;
            self.clear_qualification();
            self.event = Some(match source {
                ReferenceClock::Pm(_) => ClockEvent::RecoveredPm,
                ReferenceClock::Hpet { .. } => ClockEvent::RecoveredHpet,
            });
        }
        self.publish(time)
    }

    /// Called by the scheduler's independent LAPIC stalled-clock guard.
    /// A stopped TSC cannot measure the end of its own lease.
    pub(crate) fn invalidate_holdover(&mut self) {
        if self.using_tsc() { let _ = self.unavailable(); }
    }

    /// One remaining physical reference cannot arbitrate an arbitrary
    /// disagreement against TSC. It can still establish a trusted
    /// anchor for explicit invalidation of that reference (regression).
    /// Require another independent interval after fleet qualification.
    fn sample_single(&mut self, first: Option<u128>, last: Option<u128>,
                     tsc: Option<TscBracket>) -> Option<u128> {
        let (Some(low), Some(high)) = (first, last) else {
            if let (true, Some(old), Some(current)) = (self.single_qualified, self.single, tsc) {
                return self.enter_holdover(old.tsc, current, old.global);
            }
            return self.unavailable();
        };
        let time = self.base_ns.saturating_add(high);
        if let Some(current) = tsc.filter(|_| high-low <= BRACKET_NS) {
            let next = SingleAnchor { physical: Span { low, high }, tsc: current,
                                      global: self.base_ns.saturating_add(low) };
            if let Some(old) = self.single {
                let physical = Span::elapsed(old.physical, next.physical);
                let elapsed = old.tsc.elapsed(current);
                match (physical, elapsed) {
                    (Some(p), Some(t)) if t.high <= MAX_GAP_NS && p.agrees(t) => {
                        if t.low >= WINDOW_NS && p.low != 0 {
                            self.single_qualified = true;
                            self.single = Some(next);
                        }
                    }
                    _ => {
                        self.single_qualified = false;
                        self.single = Some(next);
                    }
                }
            } else {
                self.single = Some(next);
                self.single_qualified = false;
            }
        } else {
            self.single = None;
            self.single_qualified = false;
        }
        self.publish(time)
    }

    /// A shadow read is enclosed by two primary reads. Compare elapsed
    /// intervals, including read uncertainty and a 1% rate / 100us budget.
    /// A new anchor must agree even between complete 100ms windows.
    fn qualify_pair(&mut self, pair: Pair) -> bool {
        if pair.high-pair.low > BRACKET_NS {
            self.clear_qualification();
            return false;
        }
        let Some(base) = self.baseline else {
            self.baseline = Some(pair);
            return false;
        };
        let Some(shadow_elapsed) = pair.shadow.checked_sub(base.shadow) else {
            self.clear_qualification();
            return false;
        };
        let Some(high) = pair.high.checked_sub(base.low) else {
            self.clear_qualification();
            return false;
        };
        let low = pair.low.saturating_sub(base.high);
        let error = shadow_elapsed / 100 + JITTER_NS;
        let window = high.max(shadow_elapsed) >= WINDOW_NS;
        if high.max(shadow_elapsed) > MAX_GAP_NS ||
           low > shadow_elapsed.saturating_add(error) ||
           high.saturating_add(error) < shadow_elapsed ||
           (window && (shadow_elapsed == 0 || low == 0)) {
            self.clear_qualification();
            self.baseline = Some(pair);
            return false;
        }
        if window {
            self.baseline = Some(pair);
            self.good_windows = self.good_windows.saturating_add(1);
        }
        true
    }

    pub(crate) fn sample(&mut self, read: impl FnMut(ReferenceClock) -> u64) -> Option<u128> {
        self.sample_with_witness(read, || None)
    }

    /// The provider only grants a bracket while all enabled CPUs have
    /// fresh independent qualification. TSC arbitrates physical source
    /// disputes and, only on explicit loss, provides bounded holdover.
    pub(crate) fn sample_with_witness(&mut self, mut read: impl FnMut(ReferenceClock) -> u64,
        mut witness: impl FnMut() -> Option<Witness>) -> Option<u128> {
        if self.failed { return None; }
        if self.using_tsc() { return self.continue_holdover(read, witness); }
        let before = if !self.witness_rejected { witness() } else { None };
        let active = self.primary.source;
        let prior = self.primary.ns();
        let first = self.primary.advance(read(active));
        let Some(standby) = self.standby.as_mut() else {
            // A retired source is read only at a bounded maintenance
            // cadence. It cannot supply elapsed time until requalified.
            let probe = first.and_then(|low| self.due_probe(low))
                .map(|source| (source, read(source)));
            let last = if before.is_some() || probe.is_some() {
                self.primary.advance(read(active))
            } else { first };
            let bracket = before.and_then(|b| witness().and_then(|a| TscBracket::new(b, a)));
            let time = self.sample_single(first, last, bracket)?;
            if let (Some((source, raw)), Some(low), Some(high)) = (probe, first, last) {
                self.qualify_standby_probe(source, raw, Span { low, high }, before.is_some());
            } else if before.is_some() && !self.single_qualified {
                // A newly contradicted or unavailable TSC observation
                // invalidates in-progress recovery even between probes.
                self.standby_probe = None;
            }
            return Some(time);
        };
        let shadow_source = standby.source;
        let shadow_prior = standby.ns();
        let shadow_raw = read(shadow_source);
        let shadow = standby.advance(shadow_raw);
        let last = self.primary.advance(read(active));

        // Bracket the *same* physical register reads with normalized TSC
        // observations. The provider does not read the system clock.
        let bracket = before.and_then(|b| witness().and_then(|a| TscBracket::new(b, a)));
        if bracket.is_none() { self.triple = None; }
        if let (Some(old), Some(current)) = (self.triple, bracket) {
            let tsc = old.tsc.elapsed(current);
            if tsc.map_or(true, |span| span.high > clock_quorum::MAX_GAP_NS) {
                // Missing, regressed or stale evidence cannot authorize a vote.
                self.triple = None;
            } else {
                let a = first.zip(last).and_then(|(low, high)| {
                    // A jump inside the primary read bracket must not
                    // become a huge interval which agrees with everything.
                    // The independent TSC has bounded the real read time.
                    if high.checked_sub(low)? > BRACKET_NS { return None; }
                    Span::elapsed(Span { low: old.pair.low, high: old.pair.high },
                                  Span { low, high })
                });
                let b = shadow.and_then(|ns| ns.checked_sub(old.pair.shadow)).map(Span::exact);
                // Both physical epochs explicitly failed validation.
                // This is not the ambiguous case of three valid but
                // disagreeing observations. Only here can the last
                // independently corroborated TSC bridge the loss.
                if last.is_none() && shadow.is_none() {
                    return self.enter_holdover(old.tsc, current, old.global);
                }
                match clock_quorum::decide(a, b, tsc) {
                    Verdict::AllAgree => {
                        // Retain a sufficiently long common baseline so
                        // frequent reads cannot hide cumulative rate errors.
                        if tsc.map_or(false, |s| s.low >= WINDOW_NS) {
                            if let (Some(low), Some(high), Some(shadow)) = (first,last,shadow) {
                                self.triple = Some(TripleAnchor {
                                    pair: Pair { low, high, shadow }, tsc: current,
                                    global: self.base_ns.saturating_add(low),
                                });
                            }
                        }
                    }
                    Verdict::ActiveAndTsc => {
                        let Some(high) = last else { return self.unavailable(); };
                        if a.map_or(false, |span| span.low > shadow_source.half_span_ns()) {
                            self.rebase_standby(shadow_source, shadow_raw);
                        } else {
                            self.retire_standby();
                            // This surviving pair agreed against the
                            // previously corroborated triple anchor.
                            if let Some(low) = first {
                                self.single = Some(SingleAnchor {
                                    physical: Span { low, high }, tsc: current,
                                    global: self.base_ns.saturating_add(low),
                                });
                                self.single_qualified = true;
                            }
                        }
                        return self.publish(self.base_ns.saturating_add(high));
                    }
                    Verdict::StandbyAndTsc => {
                        let Some(ns) = shadow else { return self.unavailable(); };
                        // This anchor was independently corroborated by
                        // all three clocks, not refreshed by a bad source.
                        self.anchor = Some(Anchor { global: old.global, shadow: old.pair.shadow });
                        let time = self.promote(ns, ns-shadow_prior)?;
                        self.single = Some(SingleAnchor {
                            physical: Span::exact(0), tsc: current, global: time,
                        });
                        self.single_qualified = true;
                        return Some(time);
                    }
                    Verdict::TscRejected => {
                        self.triple = None;
                        self.witness_rejected = true;
                        self.event = Some(ClockEvent::TscRejected);
                        if let Some(hooks) = self.witness_hooks.take() { (hooks.reject)(); }
                    }
                    Verdict::PhysicalAgree => {
                        // Nontransitive overlap is insufficient to reject
                        // a candidate. Keep the agreeing physical pair.
                        self.triple = None;
                    }
                    Verdict::Inconclusive => {
                        // TSC's uncertainty overlaps both conflicting
                        // physical readings. It cannot justify promotion.
                        // Keep the last common triple anchor, not the
                        // disputed pair. Subsequent accumulated evidence
                        // may disambiguate this bounded overlap.
                        self.clear_qualification();
                        let Some(high) = last else { return self.unavailable(); };
                        return self.publish(self.base_ns.saturating_add(high));
                    }
                    Verdict::Ambiguous => return self.unavailable(),
                }
            }
        }

        // The known elapsed interval can exceed the standby's modulo
        // ambiguity bound even when its raw residue appears plausible.
        if let Some(high) = last {
            if high-prior > shadow_source.half_span_ns() {
                self.rebase_standby(shadow_source, shadow_raw);
                return self.publish(self.base_ns.saturating_add(high));
            }
        }
        let Some(shadow_ns) = shadow else {
            self.retire_standby();
            let Some(ns) = last else { return self.unavailable(); };
            return self.publish(self.base_ns.saturating_add(ns));
        };
        let step = shadow_ns-shadow_prior;
        let (Some(low), Some(high)) = (first, last) else {
            // A detected active regression can only use a recent,
            // previously qualified standby.
            return self.promote(shadow_ns, step);
        };

        if step > active.half_span_ns() {
            // Two disagreeing sources cannot prove a missing wrap. Only
            // a previously qualified witness can invalidate this epoch;
            // an unqualified optional device cannot disable the OS.
            if self.qualified() { return self.unavailable(); }
            self.rebase_standby(shadow_source, shadow_raw);
            return self.publish(self.base_ns.saturating_add(high));
        }
        if step > MAX_GAP_NS || high-prior > MAX_GAP_NS {
            self.clear_qualification();
        }

        let time = self.base_ns.saturating_add(high);
        if high == prior {
            if let Some(anchor) = self.anchor {
                let Some(elapsed) = shadow_ns.checked_sub(anchor.shadow) else {
                    return self.unavailable();
                };
                if elapsed > MAX_ANCHOR_AGE_NS {
                    self.clear_qualification();
                } else {
                    // Do not mistake one large standby jump or repeated
                    // identical reads for evidence of a stalled primary.
                    if step != 0 { self.stall_samples = self.stall_samples.saturating_add(1); }
                    if elapsed >= STALL_NS && self.stall_samples >= 2 {
                        return self.promote(shadow_ns, step);
                    }
                    return self.publish(time);
                }
            }
        }
        self.stall_samples = 0;
        let consistent = self.qualify_pair(Pair { low, high, shadow: shadow_ns });
        if consistent && self.good_windows >= QUALIFY_WINDOWS && high > prior {
            let global = self.base_ns.saturating_add(low);
            self.anchor = Some(Anchor { global, shadow: shadow_ns });
            if self.triple.is_none() && !self.witness_rejected {
                if let Some(tsc) = bracket {
                    self.triple = Some(TripleAnchor {
                        pair: Pair { low, high, shadow: shadow_ns }, tsc, global,
                    });
                }
            }
        }
        self.publish(time)
    }
}

struct SharedClock {
    gate: AtomicBool,
    clocks: UnsafeCell<Option<ClockSet>>,
    maintenance: AtomicU64,
    event: AtomicU8,
}
unsafe impl Sync for SharedClock {}

impl SharedClock {
    const fn new() -> Self {
        Self { gate: AtomicBool::new(false), clocks: UnsafeCell::new(None),
            maintenance: AtomicU64::new(0), event: AtomicU8::new(0) }
    }

    // Local IRQ masking prevents recursion on the owning CPU. A TSC
    // witness provider may inspect its watchdog gate, which must never
    // acquire the system clock gate or perform I/O/logging.
    fn with<R>(&self, operation: impl FnOnce(&mut Option<ClockSet>) -> R) -> R {
        let flags: usize;
        unsafe { asm!("pushfq", "pop {}", "cli", out(reg) flags); }
        while self.gate.swap(true, Ordering::Acquire) {
            while self.gate.load(Ordering::Relaxed) { spin_loop(); }
        }
        let result = operation(unsafe { &mut *self.clocks.get() });
        self.gate.store(false, Ordering::Release);
        if flags & (1 << 9) != 0 { unsafe { asm!("sti", options(nostack)); } }
        result
    }
}

static CLOCK: SharedClock = SharedClock::new();

pub unsafe fn init(pm: Option<PmTimer>, hp: Option<ReferenceClock>)
    -> Result<ReferenceClock, &'static [u8]> {
    CLOCK.with(|clocks| {
        if clocks.is_some() { return Err(b"system clock already initialized" as &[u8]); }
        let source = choose(pm, hp, |s| s.progressing())
            .ok_or(b"no progressing system clock with maintainable wrap interval" as &[u8])?;
        let standby = [hp, pm.map(ReferenceClock::Pm)].into_iter().flatten()
            .find(|&s| s != source && s.maintenance_ms() != Some(0) && s.progressing());
        let first = source.sample();
        let standby = standby.map(|s| (s, s.sample()));
        let set = ClockSet::new((source, first), standby);
        CLOCK.maintenance.store(set.maintenance_ms().unwrap_or(0), Ordering::Release);
        *clocks = Some(set);
        Ok(source)
    })
}

/// Install the runtime provider after SMP CPU-local state is initialized.
/// Until every CPU independently qualifies, its read returns None.
pub(crate) fn attach_witness(read: fn(u64) -> Option<Witness>, reject: fn()) -> bool {
    CLOCK.with(|clocks| {
        let Some(clocks) = clocks.as_mut() else { return false; };
        if clocks.failed || clocks.witness_rejected ||
           clocks.witness_hooks.is_some() { return false; }
        clocks.witness_hooks = Some(WitnessHooks { read, reject });
        true
    })
}

pub fn millis() -> Option<u64> { snapshot().map(|s| s.millis) }

/// The physical reference for the watchdog is deliberately absent
/// during TSC holdover. Consumers still receive the shared ABI time,
/// but must never use that time as independent TSC rate evidence.
pub(crate) struct ClockSnapshot {
    pub millis: u64,
    pub independent_ns: Option<u64>,
    pub holdover: bool,
    pub reference_generation: u64,
}

pub(crate) fn snapshot() -> Option<ClockSnapshot> {
    CLOCK.with(|clocks| {
        let clocks = clocks.as_mut()?;
        let read = clocks.witness_hooks.map(|hooks| hooks.read);
        let generation = clocks.reference_generation;
        let result = clocks.sample_with_witness(|source| unsafe { source.sample() },
            || read.and_then(|f| f(generation)));
        let maintenance = clocks.maintenance_ms().unwrap_or(0);
        if CLOCK.maintenance.load(Ordering::Relaxed) != maintenance {
            CLOCK.maintenance.store(maintenance, Ordering::Release);
        }
        if let Some(event) = clocks.take_event() {
            CLOCK.event.store(event as u8, Ordering::Release);
        }
        let ns = result?;
        Some(clocks.view(ns))
    })
}

/// Independent LAPIC progress can diagnose a frozen holdover even when
/// TSC itself never advances far enough to age out its qualification.
pub(crate) fn expire_stalled_holdover() {
    CLOCK.with(|clocks| {
        if let Some(clocks) = clocks.as_mut() {
            if clocks.using_tsc() {
                clocks.invalidate_holdover();
                CLOCK.maintenance.store(0, Ordering::Release);
                if let Some(event) = clocks.take_event() {
                    CLOCK.event.store(event as u8, Ordering::Release);
                }
            }
        }
    });
}

pub(crate) fn take_event() -> Option<ClockEvent> {
    match CLOCK.event.swap(0, Ordering::AcqRel) {
        1 => Some(ClockEvent::StandbyRetired),
        2 => Some(ClockEvent::PromotedPm),
        3 => Some(ClockEvent::PromotedHpet),
        4 => Some(ClockEvent::Unavailable),
        5 => Some(ClockEvent::StandbyRebased),
        6 => Some(ClockEvent::TscRejected),
        7 => Some(ClockEvent::PromotedTsc),
        8 => Some(ClockEvent::RecoveredPm),
        9 => Some(ClockEvent::RecoveredHpet),
        10 => Some(ClockEvent::StandbyRecovered),
        _ => None,
    }
}

/// The BSP maintains the shortest active or standby wrap interval.
/// All other idle CPUs retain their ordinary timer policy.
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
