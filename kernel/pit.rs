//! Exclusive 8254 channel-2 boot calibration, independent of HPET/ACPI PM.
//! Only the legacy-compatible platform path may probe these I/O ports.
//! Channel 0 (IRQ0) and channel 1 are never programmed. Channel 2 is
//! reserved by the kernel; the speaker and gate are left disabled.
//! The terminal-count edge, not a number of polls, measures elapsed time.
use crate::tsc::{self, Observation};
use core::{arch::asm, hint::spin_loop, sync::atomic::{AtomicBool, Ordering}};

const CONTROL: u16 = 0x43;
const CHANNEL2: u16 = 0x42;
const GATE: u16 = 0x61;
const GATE_ENABLE: u8 = 1;
const SPEAKER_ENABLE: u8 = 2;
const OUT2: u8 = 1 << 5;
const MODE0: u8 = 0xb0; // counter 2, LSB/MSB, mode 0, binary
const STATUS2: u8 = 0xe8; // 8254 read-back: latch channel-2 status only
const MAX_POLLS: u32 = 1_000_000;
const PIT_HZ: u64 = 1_193_182;
// ceil(50ms * PIT_HZ), leaving room for a 16-bit divisor.
const DIVISOR: u16 = 59_660;
const INTERVAL_NS: u64 = DIVISOR as u64 * 1_000_000_000 / PIT_HZ;
const MAX_EDGE_UNCERTAINTY_PPM:u128=960;
const PPM:u128=1_000_000;
const PIT_PHASE_TICKS:u128=2;
// A poor timestamp bracket is not an observation of an inconsistent rate.
// Bound the acquisition to three valid windows plus at most six fresh
// attempts (450 ms of nominal one-shot time), within the AP startup budget.
// Never retry a hardware fault, raw regression or incompatible valid rate.
const MAX_DISCARDED: usize = 6;

#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Error { NotDeclared, Configuration, NoEdge, Regression, Uncertain }

/// Exact failed operation and operands already observed by the driver.
/// No diagnostic reads of an active PIT, and no clock/port access by reporting.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Stage {
    NotDeclared, DisableGate, ProgramStatus, ProgramGate, StartRaw, PollRaw,
    PollGate, FirstHigh, TerminalStatus, EdgeRaw, EdgeUncertain, PollLimit, CleanupGate,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct MeasureFailure {
    pub stage: Stage,
    pub values: [u64; 4],
    pub cleanup_state: Option<u8>,
}

impl MeasureFailure {
    fn new(stage: Stage, values: [u64; 4]) -> Self {
        Self { stage, values, cleanup_state: None }
    }
    /// Retry only an observed terminal edge with an actually positive
    /// lower duration bound and excessive read uncertainty. Missing edges,
    /// regressions, zero duration and failed cleanup remain fatal.
    fn imprecise_edge(self) -> bool {
        if self.stage!=Stage::EdgeUncertain || self.cleanup_state.is_some() { return false; }
        let [a,b,c,d]=self.values;
        if a>b || b>=c || c>d { return false; }
        let lo=(c-b) as u128;
        let hi=(d-a) as u128;
        (hi-lo)*PPM>((hi+lo)/2)*MAX_EDGE_UNCERTAINTY_PPM
    }
    // Preserve the historical coarse API for the independent host tests.
    #[cfg(test)]
    fn error(self) -> Error {
        use Stage::*;
        if self.cleanup_state.is_some() { return Error::Configuration; }
        match self.stage {
            NotDeclared => Error::NotDeclared,
            FirstHigh | PollLimit => Error::NoEdge,
            StartRaw | PollRaw | EdgeRaw => Error::Regression,
            EdgeUncertain => Error::Uncertain,
            _ => Error::Configuration,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum QualificationReason {
    NotDeclared, Unsupported, OwnerBusy, Measure(Stage), Calibration(tsc::CalibrationFault),
    PrecisionBudget, DiscardedRangeConflict,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct QualificationFailure {
    pub reason: QualificationReason,
    pub window: u8,
    pub values: [u64; 4],
    pub rates: [u64; 3],
    pub nominal: Option<u64>,
    pub cleanup_state: Option<u8>,
}

impl QualificationFailure {
    fn new(reason: QualificationReason, nominal: Option<u64>) -> Self {
        Self { reason, window: 0, values: [0; 4], rates: [0; 3], nominal, cleanup_state: None }
    }

    /// Bounded error records usable on any legacy-compatible platform.
    /// A/B/C/D are the operands for the named failed operation:
    /// edge and observation = before/after start, before/after end;
    /// BetweenSamples = previous end, new before/after start, new after end;
    /// PollRaw = previous, before, after, poll index;
    /// status/gate failures = observed register byte, plus poll where relevant;
    /// PollLimit = start bracket, last timestamp, number of polls;
    /// FirstHigh = start bracket, terminal timestamp, poll index.
    /// RATE fields contain only already accepted individual observations.
    pub(crate) fn report(self, cpu: u8, phase: &str, mut emit: impl FnMut(&[u8])) {
        let line=tsc::Diagnostic::formatted(format_args!(
            "PIT TSC APIC={} PHASE={} WINDOW={} FAULT={:?}",
            cpu,phase,self.window,self.reason));
        emit(line.bytes());
        let [a,b,c,d]=self.values;
        let line=tsc::Diagnostic::formatted(format_args!(
            "PIT TSC APIC={} A={:016x} B={:016x} C={:016x} D={:016x}",cpu,a,b,c,d));
        emit(line.bytes());
        let [a,b,c]=self.rates;
        let line=tsc::Diagnostic::formatted(format_args!(
            "PIT TSC APIC={} H1={:016x} H2={:016x} H3={:016x}",cpu,a,b,c));
        emit(line.bytes());
        let line=tsc::Diagnostic::formatted(format_args!(
            "PIT TSC APIC={} NOMINAL={:016x}",cpu,self.nominal.unwrap_or(0)));
        emit(line.bytes());
        if let Some(state)=self.cleanup_state {
            let line=tsc::Diagnostic::formatted(format_args!(
                "PIT TSC APIC={} CLEANUP GATE={:02x}",cpu,state));
            emit(line.bytes());
        }
    }
}

pub(crate) trait Ports {
    fn read(&mut self, port: u16) -> u8;
    fn write(&mut self, port: u16, value: u8);
}

struct Io;
impl Ports for Io {
    fn read(&mut self, port: u16) -> u8 {
        let value: u8;
        unsafe { asm!("in al, dx", in("dx") port, out("al") value,
            options(nomem, nostack, preserves_flags)); }
        value
    }
    fn write(&mut self, port: u16, value: u8) {
        unsafe { asm!("out dx, al", in("dx") port, in("al") value,
            options(nomem, nostack, preserves_flags)); }
    }
}

/// A host fixture can supply the same port operations and ordered
/// timestamp brackets. No privileged access or fabricated time is
/// compiled into the production path.
#[cfg(test)]
pub(crate) fn measure(allowed: bool, io: &mut impl Ports, max_polls: u32,
                      timestamp: impl FnMut() -> u64,
                      maintain: impl FnMut()) -> Result<Observation, Error> {
    measure_detailed(allowed,io,max_polls,timestamp,maintain).map_err(MeasureFailure::error)
}

pub(crate) fn measure_detailed(allowed: bool, io: &mut impl Ports, max_polls: u32,
                      mut timestamp: impl FnMut() -> u64,
                      mut maintain: impl FnMut()) -> Result<Observation, MeasureFailure> {
    use Stage::*;
    let fail=MeasureFailure::new;
    if !allowed { return Err(fail(NotDeclared,[0;4])); }

    // Only bits 0..3 are legacy writable control bits; do not echo
    // OUT/refresh/NMI status bits into the register.
    let control = io.read(GATE) & 0x0c;
    io.write(GATE, control);
    let result = (|| {
        let gate=io.read(GATE);
        if gate & (GATE_ENABLE | SPEAKER_ENABLE) != 0 {
            return Err(fail(DisableGate,[gate as u64,0,0,0]));
        }
        io.write(CONTROL, MODE0);
        io.write(CHANNEL2, DIVISOR as u8);
        io.write(CHANNEL2, (DIVISOR >> 8) as u8);
        io.write(CONTROL, STATUS2);
        let status = io.read(CHANNEL2);
        // Mode/access/binary fields must echo the programming. OUT
        // must be low, but NULL COUNT may still be set until a PIT tick.
        if status & 0x3f != 0x30 || status & 0x80 != 0 {
            return Err(fail(ProgramStatus,[status as u64,0,0,0]));
        }
        let gate=io.read(GATE);
        if gate & (GATE_ENABLE | SPEAKER_ENABLE | OUT2) != 0 {
            return Err(fail(ProgramGate,[gate as u64,0,0,0]));
        }
        let before_start = timestamp();
        io.write(GATE, control | GATE_ENABLE);
        let after_start = timestamp();
        if after_start < before_start {
            return Err(fail(StartRaw,[before_start,after_start,0,0]));
        }
        let mut previous = after_start;
        let mut last_low = None;
        for poll in 0..max_polls {
            // Keeping an existing independent epoch sampled may take
            // time. Include any such delay in the terminal-edge bracket.
            maintain();
            let before = timestamp();
            let state = io.read(GATE);
            let after = timestamp();
            if before < previous || after < before {
                return Err(fail(PollRaw,[previous,before,after,poll as u64]));
            }
            previous = after;
            if state & (GATE_ENABLE | SPEAKER_ENABLE) != GATE_ENABLE {
                return Err(fail(PollGate,[state as u64,poll as u64,before,after]));
            }
            if state & OUT2 != 0 {
                // An already-high or fabricated immediate terminal
                // output cannot establish an observed interval.
                let before_end = last_low.ok_or_else(||
                    fail(FirstHigh,[before_start,after_start,after,poll as u64]))?;
                io.write(CONTROL, STATUS2);
                let status=io.read(CHANNEL2);
                if status != 0xb0 {
                    return Err(fail(TerminalStatus,[status as u64,poll as u64,before_end,after]));
                }
                let o = Observation { before_start, after_start,
                    before_end, after_end: after, reference_ns: INTERVAL_NS };
                // The 8254 loads/synchronizes on the next timer edge.
                // At this divisor two PIT ticks contribute <34 ppm.
                // Reserve this separately from the measured bracket.
                let operands=[before_start,after_start,before_end,after];
                let lower = before_end.checked_sub(after_start)
                    .ok_or_else(||fail(EdgeRaw,operands))? as u128;
                let upper = after.checked_sub(before_start)
                    .ok_or_else(||fail(EdgeRaw,operands))? as u128;
                let middle = (lower+upper)/2;
                if lower == 0 || (upper-lower)*PPM > middle*MAX_EDGE_UNCERTAINTY_PPM {
                    return Err(fail(EdgeUncertain,operands));
                }
                return Ok(o);
            }
            last_low = Some(before);
            spin_loop();
        }
        Err(fail(PollLimit,[before_start,after_start,previous,max_polls as u64]))
    })();
    // Do not restore the inherited gate/speaker state: the original
    // channel mode/count has been replaced by the exclusive owner.
    // Preserve the other control bits and silence the reserved channel.
    io.write(GATE, control);
    let state=io.read(GATE);
    if state & (GATE_ENABLE | SPEAKER_ENABLE) != 0 {
        // A cleanup failure must not hide the earlier physical rejection.
        let mut fault=match result {
            Err(fault)=>fault,
            Ok(_)=>fail(CleanupGate,[state as u64,0,0,0]),
        };
        fault.cleanup_state=Some(state);
        return Err(fault);
    }
    result
}

/// Each rejected but monotonic, complete physical observation remains
/// available for operational diagnosis and a conservative contradiction
/// check. An imprecise window must never itself contribute a rate token.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct DiscardedWindow {
    pub window:u8,
    pub attempt:u8,
    pub values:[u64;4],
}
impl DiscardedWindow {
    /// The real rate lies in [lo * PIT_HZ/(DIVISOR+2),
    /// hi * PIT_HZ/(DIVISOR-2)] under the existing PIT calibration
    /// assumptions, allowing the same two PIT ticks for load phase.
    /// If even this wide interval cannot agree with a qualified rate
    /// under the existing 1000 ppm tolerance, do not hide a contradiction
    /// by collecting a later narrow observation. No rounded rate is used.
    pub(crate) fn compatible_with(self,hz:u64)->bool {
        let [a,b,c,d]=self.values;
        if hz==0 || a>b || b>=c || c>d {return false;}
        let lo=(c-b) as u128*PIT_HZ as u128;
        let hi=(d-a) as u128*PIT_HZ as u128;
        let hz=hz as u128;
        let compatible_scale=PPM+tsc::RATE_TOLERANCE_PPM;
        lo*PPM<=hz*(DIVISOR as u128+PIT_PHASE_TICKS)*compatible_scale &&
            hi*compatible_scale>=hz*(DIVISOR as u128-PIT_PHASE_TICKS)*PPM
    }
}

/// Bounded diagnostic storage, local to one qualification, not a global
/// test flag. All discarded brackets are emitted after exclusive ownership
/// is released; no UART or log operations between measured edges.
pub(crate) struct DiscardedWindows {
    entries:[Option<DiscardedWindow>;MAX_DISCARDED],
    len:usize,
}
impl DiscardedWindows {
    pub const fn new()->Self {Self{entries:[None;MAX_DISCARDED],len:0}}
    pub(crate) fn len(&self)->usize {self.len}
    fn push(&mut self,window:DiscardedWindow)->bool {
        if self.len==self.entries.len(){return false;}
        self.entries[self.len]=Some(window);
        self.len+=1;
        true
    }
    pub(crate) fn iter(&self)->impl Iterator<Item=DiscardedWindow>+'_ {
        self.entries[..self.len].iter().flatten().copied()
    }
    pub(crate) fn report(&self,cpu:u8,phase:&str,mut emit:impl FnMut(&[u8])) {
        for entry in self.iter() {
            let line=tsc::Diagnostic::formatted(format_args!(
                "PIT TSC APIC={} PHASE={} WINDOW={} ATTEMPT={} RETRY=EdgeUncertain",
                cpu,phase,entry.window,entry.attempt));
            emit(line.bytes());
            let [a,b,c,d]=entry.values;
            let line=tsc::Diagnostic::formatted(format_args!(
                "PIT TSC APIC={} A={:016x} B={:016x} C={:016x} D={:016x}",cpu,a,b,c,d));
            emit(line.bytes());
        }
    }
}

/// Collect the first three sufficiently precise, independent observations
/// in order. Only insufficient precision permits a bounded fresh one-shot.
/// Neither a previous observation nor a known conflicting rate may be
/// replaced. Preserve raw continuity even across discarded measurements.
pub(crate) fn qualify_samples(caps: tsc::Capabilities, io: &mut impl Ports, max_polls: u32,
    mut timestamp: impl FnMut()->u64, mut maintain: impl FnMut(), discarded:&mut DiscardedWindows)
    -> Result<tsc::QualifiedRate, QualificationFailure> {
    use QualificationReason::*;
    *discarded=DiscardedWindows::new();
    let mut calibration=tsc::Calibration::new(caps);
    let mut rates=[0u64;3];
    let mut last=0u64;
    let mut i=0usize;
    let mut attempt=0u8;
    while i<3 {
        attempt+=1;
        let window=i as u8+1;
        let observation=match measure_detailed(true,io,max_polls,&mut timestamp,&mut maintain) {
            Ok(o)=>o,
            Err(fault) if fault.imprecise_edge()=>{
                let [a,b,_,d]=fault.values;
                calibration.observe_unqualified_span(a,d).map_err(|reason|QualificationFailure {
                    reason:Calibration(reason),window,values:[last,a,b,d],
                    rates,nominal:caps.nominal_hz,cleanup_state:None,
                })?;
                last=d;
                let entry=DiscardedWindow{window,attempt,values:fault.values};
                // Existing accepted observations or an enumerated nominal
                // rate already provide a contradiction check. Do not wait
                // for three more samples when we can reject immediately.
                let conflict=rates[..i].iter().any(|&hz|!entry.compatible_with(hz)) ||
                    caps.nominal_hz.map_or(false,|hz|!entry.compatible_with(hz));
                if conflict {
                    return Err(QualificationFailure {reason:DiscardedRangeConflict,window,
                        values:fault.values,rates,nominal:caps.nominal_hz,cleanup_state:None});
                }
                if !discarded.push(entry) {
                    return Err(QualificationFailure {reason:PrecisionBudget,window,
                        values:fault.values,rates,nominal:caps.nominal_hz,cleanup_state:None});
                }
                continue;
            }
            Err(fault)=>return Err(QualificationFailure {
                reason: Measure(fault.stage),window,values:fault.values,
                rates,nominal:caps.nominal_hz,cleanup_state:fault.cleanup_state,
            }),
        };
        rates[i]=calibration.observe_checked(observation).map_err(|fault| {
            let values=if fault==tsc::CalibrationFault::BetweenSamples {
                [last,observation.before_start,observation.after_start,observation.after_end]
            } else {
                [observation.before_start,observation.after_start,observation.before_end,observation.after_end]
            };
            QualificationFailure { reason: Calibration(fault),window,values,
                rates,nominal:caps.nominal_hz,cleanup_state:None }
        })?;
        last=observation.after_end;
        // A previously discarded bracket can rule out this new rate even
        // when it was too wide to authorize any rate of its own.
        if let Some(entry)=discarded.iter().find(|entry|!entry.compatible_with(rates[i])) {
            return Err(QualificationFailure {reason:DiscardedRangeConflict,window:entry.window,
                values:entry.values,rates,nominal:caps.nominal_hz,cleanup_state:None});
        }
        i+=1;
    }
    let rate=calibration.finish_checked().map_err(|fault| QualificationFailure {
        reason:Calibration(fault),window:0,values:[0;4],rates,
        nominal:caps.nominal_hz,cleanup_state:None,
    })?;
    // CPUID or the median chosen by Calibration must also be consistent
    // with each discarded physical span. They can only reject, not qualify.
    if let Some(entry)=discarded.iter().find(|entry|!entry.compatible_with(rate.hz())) {
        return Err(QualificationFailure {reason:DiscardedRangeConflict,window:entry.window,
            values:entry.values,rates,nominal:caps.nominal_hz,cleanup_state:None});
    }
    Ok(rate)
}

static OWNER: AtomicBool = AtomicBool::new(false);

/// Boot-only hardware calibration. Serialize all channel-2 command/data
/// transactions across CPUs with local interrupts masked. The callback
/// may maintain the *other* timekeeper; it must never acquire this owner.
/// Acquire is bounded; a wedged owner is an error, not a fake interval.
pub(crate) unsafe fn qualify(allowed: bool, mut maintain: impl FnMut(), discarded:&mut DiscardedWindows)
    -> Result<tsc::QualifiedRate,QualificationFailure> {
    use QualificationReason::*;
    *discarded=DiscardedWindows::new();
    if !allowed { return Err(QualificationFailure::new(NotDeclared,None)); }
    let caps = tsc::detect();
    if !caps.invariant { return Err(QualificationFailure::new(Unsupported,caps.nominal_hz)); }
    let flags: usize;
    asm!("pushfq", "pop {}", "cli", out(reg) flags);
    let mut acquired = false;
    for _ in 0..MAX_POLLS {
        if OWNER.compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed).is_ok() {
            acquired = true;
            break;
        }
        maintain();
        spin_loop();
    }
    let rate = if acquired {
        let result=qualify_samples(caps,&mut Io,MAX_POLLS,||tsc::read(),&mut maintain,discarded);
        OWNER.store(false, Ordering::Release);
        result
    } else { Err(QualificationFailure::new(OwnerBusy,caps.nominal_hz)) };
    if flags & (1 << 9) != 0 { asm!("sti", options(nostack)); }
    rate
}

