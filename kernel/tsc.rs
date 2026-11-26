//! Qualify the invariant TSC and measure startup alignment between CPUs.
//! Invariance is a rate guarantee, not a guarantee of equal counter values.
//! Independent repeated measurements qualify the rate; full CPU
//! alignment is a separate prerequisite for a shared TSC clocksource.
use crate::reference_clock::ReferenceClock;
use core::{arch::{asm, x86_64::__cpuid}, fmt::{self, Write},
    sync::atomic::{AtomicBool, AtomicI64, AtomicU32, AtomicU64, Ordering}};

const MEASURE_NS: u64 = 50_000_000;
const MAX_MEASURE_NS: u64 = 250_000_000;
const PPM: u128 = 1_000_000;
pub(crate) const RATE_TOLERANCE_PPM: u128 = 1000;
const MAX_READ_UNCERTAINTY_PPM: u128 = 1000;
const ALIGNMENT_NS: u64 = 100_000;
const EXCHANGES: u32 = 8;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Capabilities {
    pub available: bool,
    pub invariant: bool,
    pub nominal_hz: Option<u64>,
}

/// Intel CPUID.15H enumerates the crystal frequency and TSC ratio.
/// Zero in any field means that an absolute rate was not enumerated.
/// CPUID.16H core frequency is NOT a TSC rate.
pub(crate) fn crystal_rate(denominator: u32, numerator: u32, crystal: u32) -> Option<u64> {
    if denominator == 0 || numerator == 0 || crystal == 0 { return None; }
    let hz = (crystal as u128 * numerator as u128) / denominator as u128;
    u64::try_from(hz).ok().filter(|&rate| rate != 0)
}

pub(crate) fn capabilities(max_basic: u32, leaf1_edx: u32, max_extended: u32,
                           invariant_edx: u32, ratio: [u32; 3]) -> Capabilities {
    let available = max_basic >= 1 && leaf1_edx & (1 << 4) != 0;
    let invariant = available && max_extended >= 0x8000_0007 && invariant_edx & (1 << 8) != 0;
    let nominal_hz = if invariant && max_basic >= 0x15 {
        crystal_rate(ratio[0], ratio[1], ratio[2])
    } else { None };
    Capabilities { available, invariant, nominal_hz }
}

pub(crate) unsafe fn detect() -> Capabilities {
    let basic = __cpuid(0).eax;
    let extended = __cpuid(0x8000_0000).eax;
    let flags = if basic >= 1 { __cpuid(1).edx } else { 0 };
    let invariant = if extended >= 0x8000_0007 { __cpuid(0x8000_0007).edx } else { 0 };
    let ratio = if basic >= 0x15 {
        let leaf = __cpuid(0x15);
        [leaf.eax, leaf.ebx, leaf.ecx]
    } else { [0; 3] };
    capabilities(basic, flags, extended, invariant, ratio)
}

/// Ordered kernel read. Call only on a processor with architectural TSC.
#[inline]
pub unsafe fn read() -> u64 {
    let (lo, hi): (u32, u32);
    asm!("lfence", "rdtsc", "lfence", out("eax") lo, out("edx") hi, options(nostack));
    (hi as u64) << 32 | lo as u64
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Observation {
    pub before_start: u64,
    pub after_start: u64,
    pub before_end: u64,
    pub after_end: u64,
    pub reference_ns: u64,
}

/// Bounds account for the time taken to read both reference registers.
/// A preempted or unusually slow bracket is unsuitable for calibration.
pub(crate) fn measured_rate(o: Observation) -> Option<u64> {
    measured_rate_checked(o).ok()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CalibrationFault {
    Unsupported, ReferenceDuration, RawOrder, Uncertain, RateRange,
    PreviousFailure, ExcessSamples, BetweenSamples, Incomplete,
    RateSpread, NominalMismatch,
}

pub(crate) fn measured_rate_checked(o: Observation) -> Result<u64, CalibrationFault> {
    use CalibrationFault::*;
    if !(MEASURE_NS..=MAX_MEASURE_NS).contains(&o.reference_ns) { return Err(ReferenceDuration); }
    if o.before_start > o.after_start || o.before_end > o.after_end { return Err(RawOrder); }
    let lower = o.before_end.checked_sub(o.after_start).ok_or(RawOrder)? as u128;
    let upper = o.after_end.checked_sub(o.before_start).ok_or(RawOrder)? as u128;
    let midpoint = (lower + upper) / 2;
    if lower == 0 || upper < lower ||
       (upper-lower) * PPM > midpoint * MAX_READ_UNCERTAINTY_PPM { return Err(Uncertain); }
    let hz = midpoint * 1_000_000_000 / o.reference_ns as u128;
    u64::try_from(hz).ok().filter(|&rate| rate != 0).ok_or(RateRange)
}

fn compatible(a: u64, b: u64) -> bool {
    a != 0 && b != 0 &&
        a.abs_diff(b) as u128 * PPM <= a.min(b) as u128 * RATE_TOLERANCE_PPM
}

pub(crate) fn qualified_rate(caps: Capabilities, samples: [u64; 3]) -> Option<u64> {
    qualified_rate_checked(caps, samples).ok()
}

pub(crate) fn qualified_rate_checked(caps: Capabilities, mut samples: [u64; 3]) -> Result<u64, CalibrationFault> {
    use CalibrationFault::*;
    if !caps.available || !caps.invariant { return Err(Unsupported); }
    if samples[0] > samples[1] { samples.swap(0, 1); }
    if samples[1] > samples[2] { samples.swap(1, 2); }
    if samples[0] > samples[1] { samples.swap(0, 1); }
    if !compatible(samples[0], samples[2]) { return Err(RateSpread); }
    if let Some(nominal) = caps.nominal_hz {
        if !samples.into_iter().all(|hz| compatible(hz, nominal)) { return Err(NominalMismatch); }
        Ok(nominal)
    } else { Ok(samples[1]) }
}

/// An opaque rate token: CPUID or an arbitrary integer cannot create it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct QualifiedRate { hz:u64, first:u64, last:u64 }

impl QualifiedRate {
    pub(crate) fn hz(self) -> u64 { self.hz }
}

/// Three separate, independently timed observations on the same CPU.
/// Check raw continuity across measurements as well as each bracket.
pub(crate) struct Calibration {
    caps: Capabilities,
    samples: [u64; 3],
    len: usize,
    first: u64,
    last: Option<u64>,
    failed: bool,
}

impl Calibration {
    pub(crate) fn new(caps: Capabilities) -> Self {
        Self { caps, samples: [0;3], len: 0, first:0, last: None, failed: false }
    }
    pub(crate) fn observe(&mut self, observation: Observation) -> Option<()> {
        self.observe_checked(observation).ok().map(|_| ())
    }
    pub(crate) fn observe_checked(&mut self, observation: Observation) -> Result<u64, CalibrationFault> {
        use CalibrationFault::*;
        let result = if self.failed { Err(PreviousFailure) }
            else if self.len == self.samples.len() { Err(ExcessSamples) }
            else if self.last.map_or(false, |last| observation.before_start < last) { Err(BetweenSamples) }
            else { measured_rate_checked(observation) };
        let rate = match result {
            Ok(rate) => rate,
            Err(reason) => { self.failed = true; return Err(reason); }
        };
        if self.last.is_none() { self.first=observation.before_start; }
        self.samples[self.len] = rate;
        self.len += 1;
        self.last = Some(observation.after_end);
        Ok(rate)
    }
    /// A physical measurement with insufficient precision has no rate
    /// proof, but its ordered raw endpoints are still evidence of continuity.
    /// Preserve them, including the first attempted start, without counting
    /// this span as one of the three required independent observations.
    pub(crate) fn observe_unqualified_span(&mut self, before:u64, after:u64)
        -> Result<(),CalibrationFault> {
        use CalibrationFault::*;
        let failure=if self.failed { Some(PreviousFailure) }
            else if self.len==self.samples.len() { Some(ExcessSamples) }
            else if after<before { Some(RawOrder) }
            else if self.last.map_or(false,|last|before<last) { Some(BetweenSamples) }
            else { None };
        if let Some(reason)=failure { self.failed=true; return Err(reason); }
        if self.last.is_none() { self.first=before; }
        self.last=Some(after);
        Ok(())
    }

    pub(crate) fn finish(self) -> Option<QualifiedRate> {
        self.finish_checked().ok()
    }
    pub(crate) fn finish_checked(self) -> Result<QualifiedRate, CalibrationFault> {
        use CalibrationFault::*;
        if self.failed { return Err(PreviousFailure); }
        if self.len != self.samples.len() { return Err(Incomplete); }
        Ok(QualifiedRate{hz:qualified_rate_checked(self.caps,self.samples)?,
            first:self.first,last:self.last.ok_or(Incomplete)?})
    }
}

pub(crate) fn rates_match(a: QualifiedRate, b: QualifiedRate) -> bool {
    compatible(a.hz(), b.hz())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum QualificationError { Unsupported, ReferenceUnavailable, Inconsistent }

/// Each logical CPU measures its own rate against the independent
/// reference. Distinguish an unavailable timer (which permits an
/// independent PIT fallback) from conflicting observations (which do
/// not). CPUID alone is never proof of synchronization or rate.
pub(crate) unsafe fn qualify_reference(reference: ReferenceClock, mut maintain: impl FnMut())
    -> Result<QualifiedRate, QualificationError> {
    use QualificationError::*;
    let caps = detect();
    if !caps.invariant { return Err(Unsupported); }
    let mut calibration = Calibration::new(caps);
    for _ in 0..3 {
        let before_start = read();
        let start = reference.sample();
        let after_start = read();
        let waited = reference.delay_ns_with(MEASURE_NS, &mut maintain)
            .map_err(|_| ReferenceUnavailable)?;
        let before_end = read();
        let end = reference.sample();
        let after_end = read();
        let reference_ns = reference.elapsed_ns(start, end).ok_or(Inconsistent)?;
        if reference_ns < waited { return Err(Inconsistent); }
        calibration.observe(Observation { before_start, after_start,
            before_end, after_end, reference_ns }).ok_or(Inconsistent)?;
    }
    calibration.finish().ok_or(Inconsistent)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Bracket {
    pub before: u64,
    pub remote: u64,
    pub after: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Alignment {
    pub offset: i64, // add to AP's TSC to estimate the BSP's TSC
    pub uncertainty_ticks: u64,
}

impl Alignment {
    pub(crate) fn normalize(self, raw: u64) -> Option<u64> {
        u64::try_from(raw as i128 + self.offset as i128).ok()
    }

    /// Intersect offset intervals rather than rebase to a changed offset.
    pub(crate) fn intersect(self, other: Self) -> Option<Self> {
        let lo=(self.offset as i128-self.uncertainty_ticks as i128)
            .max(other.offset as i128-other.uncertainty_ticks as i128);
        let hi=(self.offset as i128+self.uncertainty_ticks as i128)
            .min(other.offset as i128+other.uncertainty_ticks as i128);
        if lo>hi { return None; }
        Some(Self { offset:i64::try_from(lo+(hi-lo)/2).ok()?,
            uncertainty_ticks:u64::try_from((hi-lo+1)/2).ok()? })
    }
}

/// A remote sample was taken after the BSP's release request and before
/// the BSP observed the corresponding acquire response. Intersect the
/// implied offset intervals; never equate the remote value with one end
/// of the round trip or silently accept conflicting observations.
pub(crate) fn align(bsp_hz: u64, ap_hz: u64,
                    mut exchange: impl FnMut(u32) -> Option<Bracket>) -> Option<Alignment> {
    if !compatible(bsp_hz, ap_hz) { return None; }
    let (mut lo, mut hi) = (i128::MIN, i128::MAX);
    let mut previous: Option<Bracket> = None;
    for sequence in 1..=EXCHANGES {
        let sample = exchange(sequence)?;
        if sample.after < sample.before || previous.map_or(false, |p|
            sample.before < p.after || sample.remote <= p.remote) { return None; }
        previous = Some(sample);
        lo = lo.max(sample.before as i128 - sample.remote as i128);
        hi = hi.min(sample.after as i128 - sample.remote as i128);
        if lo > hi { return None; }
    }
    let width = (hi-lo) as u128;
    let uncertainty = u64::try_from((width+1)/2).ok()?;
    if uncertainty as u128 * 1_000_000_000 > bsp_hz as u128 * ALIGNMENT_NS as u128 {
        return None;
    }
    let offset = i64::try_from(lo + (hi-lo)/2).ok()?;
    Some(Alignment { offset, uncertainty_ticks: uncertainty })
}

/// One BSP requester and one AP responder during CPU bring-up. The two
/// Release/Acquire edges make the timestamp bracket valid even on SMP.
pub(crate) struct Peer {
    ready: AtomicBool,
    sealed: AtomicBool,
    hz: AtomicU64,
    first_raw: AtomicU64,
    last_raw: AtomicU64,
    request: AtomicU32,
    response: AtomicU32,
    remote: AtomicU64,
    offset: AtomicI64,
    uncertainty: AtomicU64,
}

impl Peer {
    pub const fn new() -> Self {
        Self { ready: AtomicBool::new(false), sealed: AtomicBool::new(false), hz: AtomicU64::new(0),
            first_raw: AtomicU64::new(0), last_raw: AtomicU64::new(0),
            request: AtomicU32::new(0), response: AtomicU32::new(0),
            remote: AtomicU64::new(0), offset: AtomicI64::new(0),
            uncertainty: AtomicU64::new(u64::MAX) }
    }

    /// Publish once, on the CPU being qualified, before answering requests.
    pub fn publish_rate(&self, rate: Option<QualifiedRate>) {
        // One owner CPU during boot, before the SMP release barrier.
        if self.ready() { return; }
        if let Some(rate)=rate {
            self.first_raw.store(rate.first,Ordering::Relaxed);
            self.last_raw.store(rate.last,Ordering::Relaxed);
            self.hz.store(rate.hz(),Ordering::Relaxed);
        }
        self.ready.store(true, Ordering::Release);
    }

    pub(crate) fn qualification(&self) -> Option<QualifiedRate> {
        Some(QualifiedRate{hz:self.rate()?,
            first:self.first_raw.load(Ordering::Relaxed),
            last:self.last_raw.load(Ordering::Acquire)})
    }

    /// An independently repeated rate measurement must also continue
    /// raw time. Keep the original qualified rate and extend only the
    /// observed floor, before sealing startup metadata.
    pub(crate) fn confirm_rate(&self, again:QualifiedRate)->bool {
        let Some(first)=self.qualification() else {return false;};
        if self.sealed.load(Ordering::Acquire) || !rates_match(first,again) ||
            again.first<first.last { return false; }
        self.last_raw.store(again.last,Ordering::Release);
        true
    }

    pub(crate) fn last_verified_raw(&self)->u64 {
        self.last_raw.load(Ordering::Acquire).max(self.remote.load(Ordering::Acquire))
    }

    pub fn ready(&self) -> bool { self.ready.load(Ordering::Acquire) }

    pub fn rate(&self) -> Option<u64> {
        if !self.ready() { return None; }
        let hz = self.hz.load(Ordering::Relaxed);
        (hz != 0).then_some(hz)
    }

    pub(crate) fn respond(&self, timestamp: impl FnOnce() -> u64) -> bool {
        let sequence = self.request.load(Ordering::Acquire);
        if sequence == 0 || sequence == self.response.load(Ordering::Relaxed) ||
           self.rate().is_none() { return false; }
        self.remote.store(timestamp(), Ordering::Relaxed);
        self.response.store(sequence, Ordering::Release);
        true
    }

    pub(crate) fn exchange(&self, sequence: u32, mut timestamp: impl FnMut() -> u64,
                            wait: impl FnOnce(&Self, u32) -> bool) -> Option<Bracket> {
        if sequence == 0 || sequence <= self.request.load(Ordering::Relaxed) ||
           self.rate().is_none() { return None; }
        let previous=self.remote.load(Ordering::Acquire);
        let before = timestamp();
        self.request.store(sequence, Ordering::Release);
        if !wait(self, sequence) || !self.answered(sequence) { return None; }
        let after = timestamp();
        let remote = self.remote.load(Ordering::Relaxed);
        if remote<self.last_raw.load(Ordering::Acquire) ||
            (previous!=0 && remote<=previous) {return None;}
        Some(Bracket { before, remote, after })
    }

    pub(crate) fn answered(&self, sequence: u32) -> bool {
        self.response.load(Ordering::Acquire) == sequence
    }

    pub fn publish_alignment(&self, alignment: Alignment) -> bool {
        // BSP is the sole writer before global source publication.
        if self.sealed.load(Ordering::Acquire) { return false; }
        self.offset.store(alignment.offset, Ordering::Relaxed);
        self.uncertainty.store(alignment.uncertainty_ticks, Ordering::Release);
        true
    }

    /// Called after all boot exchanges with APs behind the release barrier.
    pub(crate) fn seal(&self) -> bool {
        if self.qualification().is_none() || self.alignment().is_none() { return false; }
        self.sealed.store(true,Ordering::Release);
        true
    }

    pub(crate) fn last_request(&self) -> u32 {
        self.request.load(Ordering::Relaxed)
    }

    pub(crate) fn refine_alignment(&self, alignment: Alignment) -> Option<Alignment> {
        let alignment=match self.alignment() {
            Some(old)=>old.intersect(alignment)?,
            None=>alignment,
        };
        self.publish_alignment(alignment).then_some(alignment)
    }

    pub fn alignment(&self) -> Option<Alignment> {
        let uncertainty_ticks = self.uncertainty.load(Ordering::Acquire);
        if uncertainty_ticks == u64::MAX { return None; }
        Some(Alignment { offset: self.offset.load(Ordering::Relaxed), uncertainty_ticks })
    }

    /// The AP continues ordinary startup on failure. Do not invent an
    /// alignment or reset a hardware TSC. This operation is optional.
    pub unsafe fn synchronize(&self, bsp_hz: u64, reference: ReferenceClock,
                              mut maintain: impl FnMut()) -> Option<Alignment> {
        reference.wait_until(1_000_000_000, || {
            maintain();
            self.ready()
        }).ok()?;
        let ap_hz = self.rate()?;
        let start=self.last_request();
        let alignment = align(bsp_hz, ap_hz, |sequence| {
            // Maintain the shared epoch between (not within) the measured
            // round trips. The fast acquire path gives a tight bracket.
            maintain();
            self.exchange(start.checked_add(sequence)?, || read(), |peer, seq| {
                reference.wait_until(20_000_000, || peer.answered(seq)).is_ok()
            })
        })?;
        self.refine_alignment(alignment)
    }
}

// Bounded, allocation-free operational diagnostic, subject to BOOT.LOG.
pub(crate) struct Diagnostic { data: [u8; 96], len: usize }
impl Write for Diagnostic {
    fn write_str(&mut self, value: &str) -> fmt::Result {
        let end = self.len.checked_add(value.len()).ok_or(fmt::Error)?;
        let dst = self.data.get_mut(self.len..end).ok_or(fmt::Error)?;
        dst.copy_from_slice(value.as_bytes());
        self.len = end;
        Ok(())
    }
}
impl Diagnostic {
    pub(crate) fn formatted(args: fmt::Arguments<'_>) -> Self {
        let mut out = Self { data: [0; 96], len: 0 };
        if out.write_fmt(args).is_err() {
            out.len = 0;
            let _ = out.write_str("TSC diagnostic overflow");
        }
        out
    }

    pub fn new(id: u8, peer: &Peer) -> Self {
        let mut out = Self { data: [0; 96], len: 0 };
        if let Some(hz) = peer.rate() {
            if let Some(a) = peer.alignment() {
                if write!(&mut out, "TSC APIC={} HZ={} OFFSET={} ERROR-TICKS={}",
                          id, hz, a.offset, a.uncertainty_ticks).is_err() {
                    out.len = 0;
                    let _ = write!(&mut out, "TSC APIC={} QUALIFIED; DIAGNOSTIC TOO LONG", id);
                }
            } else {
                let _ = write!(&mut out, "TSC APIC={} HZ={} UNSYNCHRONIZED", id, hz);
            }
        } else {
            let _ = write!(&mut out, "TSC APIC={} NOT QUALIFIED", id);
        }
        out
    }
    pub fn bytes(&self) -> &[u8] { &self.data[..self.len] }
}
