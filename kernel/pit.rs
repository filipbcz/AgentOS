//! Exclusive 8254 channel-2 boot calibration, independent of HPET/ACPI PM.
//! Only the legacy-compatible platform path may probe these I/O ports.
//! Channel 0 (IRQ0) and channel 1 are never programmed. Channel 2 is
//! reserved by the kernel; the speaker and gate are left disabled.
//! Independently timed terminal edges or latched count differences, not
//! a number of polls, measure elapsed time. Both validate terminal state.
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
const COUNT_STATUS2:u8=0xc8; // read-back: simultaneously latch status AND count of channel 2
const MAX_POLLS: u32 = 1_000_000;
const PIT_HZ: u64 = 1_193_182;
// ceil(50ms * PIT_HZ), leaving room for a 16-bit divisor.
const DIVISOR: u16 = 59_660;
const COUNT_DIVISOR:u16=u16::MAX; // leave ~4.9ms headroom around a >=50ms measured count span
const INTERVAL_NS: u64 = DIVISOR as u64 * 1_000_000_000 / PIT_HZ;
const MAX_EDGE_UNCERTAINTY_PPM:u128=960;
const PPM:u128=1_000_000;
const PIT_PHASE_TICKS:u128=2;
// A poor timestamp bracket is not an observation of an inconsistent rate.
// Bound the acquisition to three valid windows plus at most six fresh
// attempts (at most ~495 ms of nominal one-shot time), within the AP startup budget.
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
    LatchStatus, LatchCount, LatchTerminal, LatchStartLate, CountUncertain,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct MeasureFailure {
    pub stage: Stage,
    pub values: [u64; 4],
    pub cleanup_state: Option<u8>,
    pub reference_ticks:u16,
    pub span_start:u64,
    pub span_end:u64,
}

impl MeasureFailure {
    fn new(stage: Stage, values: [u64; 4]) -> Self {
        Self { stage, values, cleanup_state: None, reference_ticks:DIVISOR,
            span_start:values[0],span_end:values[3] }
    }
    /// Retry only a complete verified physical observation with an actually
    /// positive lower duration bound and excessive read uncertainty.
    /// Missing edges, regressions, zero duration and failed cleanup are fatal.
    fn imprecise_window(self) -> bool {
        if !matches!(self.stage,Stage::EdgeUncertain|Stage::CountUncertain) ||
            self.cleanup_state.is_some() || self.reference_ticks<DIVISOR ||
            self.span_start>self.values[0] || self.span_end<self.values[3] { return false; }
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
            EdgeUncertain | CountUncertain => Error::Uncertain,
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
    pub reference_ticks:u16,
}

impl QualificationFailure {
    fn new(reason: QualificationReason, nominal: Option<u64>) -> Self {
        Self { reason, window: 0, values: [0; 4], rates: [0; 3], nominal, cleanup_state: None,reference_ticks:0 }
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
            "PIT TSC APIC={} NOMINAL={:016x} TICKS={}",cpu,self.nominal.unwrap_or(0),self.reference_ticks));
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
        program(io,DIVISOR)?;
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
    silence(io,control,result)
}

fn program(io:&mut impl Ports,divisor:u16)->Result<(),MeasureFailure> {
    use Stage::*;
    let fail=MeasureFailure::new;
    let gate=io.read(GATE);
    if gate & (GATE_ENABLE | SPEAKER_ENABLE) != 0 {
        return Err(fail(DisableGate,[gate as u64,0,0,0]));
    }
    io.write(CONTROL, MODE0);
    io.write(CHANNEL2, divisor as u8);
    io.write(CHANNEL2, (divisor >> 8) as u8);
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
    Ok(())
}

fn silence<T>(io:&mut impl Ports,control:u8,result:Result<T,MeasureFailure>)->Result<T,MeasureFailure> {
    // Do not restore inherited gate/speaker state; their mode was replaced.
    // Preserve the other control bits and silence the reserved channel.
    io.write(GATE,control);
    let state=io.read(GATE);
    if state&(GATE_ENABLE|SPEAKER_ENABLE)!=0 {
        let mut fault=match result {
            Err(fault)=>fault,
            Ok(_)=>MeasureFailure::new(Stage::CleanupGate,[state as u64,0,0,0]),
        };
        fault.cleanup_state=Some(state);
        return Err(fault);
    }
    result
}

/// One independent counter window. The larger raw span includes gate
/// programming/terminal validation, while only the two latch commands
/// delimit the rate observation.
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub(crate) struct CountMeasurement {
    pub observation:Observation,
    pub start_count:u16,
    pub end_count:u16,
    pub span_start:u64,
    pub span_end:u64,
}

#[derive(Clone,Copy)]
struct CountSnapshot {count:u16,before:u64,after:u64}

/// The 8254 read-back command latches status and count at the same hardware
/// operation. Read status, LSB and MSB in that order; the count is held
/// until read, so neither data-read latency nor inter-poll delay belongs
/// to the timestamp bracket. Validate mode, null-count, OUT and count
/// progress, and independently observe the same mode-0 terminal state.
pub(crate) fn measure_latched(allowed:bool,io:&mut impl Ports,max_polls:u32,
    mut timestamp:impl FnMut()->u64,mut maintain:impl FnMut())
    ->Result<CountMeasurement,MeasureFailure> {
    use Stage::*;
    let fail=MeasureFailure::new;
    if !allowed {return Err(fail(NotDeclared,[0;4]));}
    let control=io.read(GATE)&0x0c;
    io.write(GATE,control);
    let result=(||{
        program(io,COUNT_DIVISOR)?;
        let span_start=timestamp();
        io.write(GATE,control|GATE_ENABLE);
        let mut previous=timestamp();
        if previous<span_start {return Err(fail(StartRaw,[span_start,previous,0,0]));}
        let mut first:Option<CountSnapshot>=None;
        let mut last_count:Option<u16>=None;
        // After a sufficiently long count span, continue only to the actual
        // terminal OUT/status check. This is not a measured rate endpoint.
        let mut measured:Option<CountMeasurement>=None;
        for poll in 0..max_polls {
            maintain();
            if let Some(mut m)=measured {
                let before=timestamp();
                let state=io.read(GATE);
                let after=timestamp();
                if before<previous || after<before {return Err(fail(PollRaw,[previous,before,after,poll as u64]));}
                previous=after;
                if state&(GATE_ENABLE|SPEAKER_ENABLE)!=GATE_ENABLE {
                    return Err(fail(PollGate,[state as u64,poll as u64,before,after]));
                }
                if state&OUT2==0 {spin_loop();continue;}
                io.write(CONTROL,STATUS2);
                let status=io.read(CHANNEL2);
                if status!=0xb0 {return Err(fail(TerminalStatus,[status as u64,poll as u64,before,after]));}
                let tail=timestamp();
                if tail<after {return Err(fail(PollRaw,[after,after,tail,poll as u64]));}
                m.span_end=tail;
                let o=m.observation;
                let values=[o.before_start,o.after_start,o.before_end,o.after_end];
                let ticks=m.start_count-m.end_count;
                let lo=o.before_end.checked_sub(o.after_start).ok_or_else(||fail(EdgeRaw,values))? as u128;
                let hi=o.after_end.checked_sub(o.before_start).ok_or_else(||fail(EdgeRaw,values))? as u128;
                if lo==0 || (hi-lo)*PPM>((hi+lo)/2)*MAX_EDGE_UNCERTAINTY_PPM {
                    return Err(MeasureFailure{stage:CountUncertain,values,cleanup_state:None,
                        reference_ticks:ticks,span_start,span_end:tail});
                }
                return Ok(m);
            }

            let before=timestamp();
            io.write(CONTROL,COUNT_STATUS2);
            let after=timestamp();
            // Always drain the complete latched transaction, even when the
            // timestamp or status is rejected. Do not leave stale count data.
            let status=io.read(CHANNEL2);
            let low=io.read(CHANNEL2);
            let high=io.read(CHANNEL2);
            let count=u16::from_le_bytes([low,high]);
            let gate=io.read(GATE);
            if before<previous || after<before {return Err(fail(PollRaw,[previous,before,after,poll as u64]));}
            previous=after;
            if gate&(GATE_ENABLE|SPEAKER_ENABLE)!=GATE_ENABLE {
                return Err(fail(PollGate,[gate as u64,poll as u64,before,after]));
            }
            if status&0x3f!=0x30 {return Err(fail(LatchStatus,[status as u64,count as u64,before,after]));}
            // OUT high is sticky until reprogramming: the terminal count
            // may already have wrapped and cannot be used as an endpoint.
            if status&0x80!=0 {return Err(fail(LatchTerminal,[status as u64,count as u64,before,after]));}
            if status&0x40!=0 {
                if first.is_some() || gate&OUT2!=0 {
                    return Err(fail(LatchStatus,[status as u64,count as u64,before,after]));
                }
                spin_loop();continue;
            }
            if count==0 || last_count.map_or(false,|last|count>last) {
                return Err(fail(LatchCount,[last_count.unwrap_or(0) as u64,count as u64,before,after]));
            }
            last_count=Some(count);
            if let Some(start)=first {
                let ticks=start.count-count;
                if ticks>=DIVISOR {
                    measured=Some(CountMeasurement {
                        observation:Observation{before_start:start.before,after_start:start.after,
                            before_end:before,after_end:after,
                            reference_ns:ticks as u64*1_000_000_000/PIT_HZ},
                        start_count:start.count,end_count:count,span_start,span_end:after,
                    });
                    continue;
                }
            } else {
                if count<=DIVISOR {return Err(fail(LatchStartLate,[count as u64,poll as u64,before,after]));}
                first=Some(CountSnapshot{count,before,after});
            }
            if gate&OUT2!=0 {return Err(fail(LatchTerminal,[status as u64,count as u64,before,after]));}
            spin_loop();
        }
        Err(fail(PollLimit,[span_start,previous,last_count.unwrap_or(0) as u64,max_polls as u64]))
    })();
    silence(io,control,result)
}

/// Each rejected but monotonic, complete physical observation remains
/// available for operational diagnosis and a conservative contradiction
/// check. An imprecise window must never itself contribute a rate token.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct DiscardedWindow {
    pub window:u8,
    pub attempt:u8,
    pub values:[u64;4],
    pub reference_ticks:u16,
    pub stage:Stage,
}
impl DiscardedWindow {
    /// The real rate lies in [lo * PIT_HZ/(reference_ticks+2),
    /// hi * PIT_HZ/(reference_ticks-2)] under the existing PIT calibration
    /// assumptions, allowing the same two PIT ticks for load phase.
    /// If even this wide interval cannot agree with a qualified rate
    /// under the existing 1000 ppm tolerance, do not hide a contradiction
    /// by collecting a later narrow observation. No rounded rate is used.
    pub(crate) fn compatible_with(self,hz:u64)->bool {
        let [a,b,c,d]=self.values;
        if hz==0 || self.reference_ticks<DIVISOR || a>b || b>=c || c>d {return false;}
        let lo=(c-b) as u128*PIT_HZ as u128;
        let hi=(d-a) as u128*PIT_HZ as u128;
        let hz=hz as u128;
        let compatible_scale=PPM+tsc::RATE_TOLERANCE_PPM;
        let ticks=self.reference_ticks as u128;
        lo*PPM<=hz*(ticks+PIT_PHASE_TICKS)*compatible_scale &&
            hi*compatible_scale>=hz*(ticks-PIT_PHASE_TICKS)*PPM
    }
}

/// Bounded diagnostic storage, local to one qualification, not a global
/// test flag. All discarded brackets are emitted after exclusive ownership
/// is released; no UART or log operations between measured edges.
pub(crate) struct AcquisitionEvidence {
    entries:[Option<DiscardedWindow>;MAX_DISCARDED],
    len:usize,
    count_samples:[Option<(u8,CountMeasurement)>;3],
}
impl AcquisitionEvidence {
    pub const fn new()->Self {Self{entries:[None;MAX_DISCARDED],len:0,count_samples:[None;3]}}
    #[cfg(test)]
    pub(crate) fn len(&self)->usize {self.len}
    #[cfg(test)]
    pub(crate) fn count_len(&self)->usize {self.count_samples.iter().flatten().count()}
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
                "PIT TSC APIC={} PHASE={} WINDOW={} ATTEMPT={} TICKS={} RETRY={:?}",
                cpu,phase,entry.window,entry.attempt,entry.reference_ticks,entry.stage));
            emit(line.bytes());
            let [a,b,c,d]=entry.values;
            let line=tsc::Diagnostic::formatted(format_args!(
                "PIT TSC APIC={} A={:016x} B={:016x} C={:016x} D={:016x}",cpu,a,b,c,d));
            emit(line.bytes());
        }
        for (i,sample) in self.count_samples.iter().enumerate() {
            if let Some((attempt,m))=sample {
                let line=tsc::Diagnostic::formatted(format_args!(
                    "PIT TSC APIC={} PHASE={} WINDOW={} ATTEMPT={} COUNT {}->{} TICKS={}",
                    cpu,phase,i+1,attempt,m.start_count,m.end_count,m.start_count-m.end_count));
                emit(line.bytes());
                let o=m.observation;
                let line=tsc::Diagnostic::formatted(format_args!(
                    "PIT TSC APIC={} A={:016x} B={:016x} C={:016x} D={:016x}",
                    cpu,o.before_start,o.after_start,o.before_end,o.after_end));
                emit(line.bytes());
            }
        }
    }
}

/// Collect the first three sufficiently precise, independent observations
/// in order. Only insufficient precision permits a bounded fresh one-shot.
/// Neither a previous observation nor a known conflicting rate may be
/// replaced. Preserve raw continuity even across discarded measurements.
pub(crate) fn qualify_samples(caps: tsc::Capabilities, io: &mut impl Ports, max_polls: u32,
    mut timestamp: impl FnMut()->u64, mut maintain: impl FnMut(), evidence:&mut AcquisitionEvidence)
    -> Result<tsc::QualifiedRate, QualificationFailure> {
    use QualificationReason::*;
    *evidence=AcquisitionEvidence::new();
    let mut calibration=tsc::Calibration::new(caps);
    let mut rates=[0u64;3];
    let mut last=0u64;
    let mut i=0usize;
    let mut attempt=0u8;
    let mut latched=false;
    while i<3 {
        attempt+=1;
        let window=i as u8+1;
        let result=if latched {
            measure_latched(true,io,max_polls,&mut timestamp,&mut maintain)
                .map(|m|(m.observation,m.span_start,m.span_end,Some(m)))
        } else {
            measure_detailed(true,io,max_polls,&mut timestamp,&mut maintain)
                .map(|o|(o,o.before_start,o.after_end,None))
        };
        let (observation,span_start,span_end,count_proof)=match result {
            Ok(o)=>o,
            Err(fault) if fault.imprecise_window()=>{
                let [a,_,_,_]=fault.values;
                calibration.observe_unqualified_span(fault.span_start,fault.span_end)
                    .map_err(|reason|QualificationFailure {
                        reason:Calibration(reason),window,values:[last,fault.span_start,a,fault.span_end],
                        rates,nominal:caps.nominal_hz,cleanup_state:None,reference_ticks:fault.reference_ticks,
                    })?;
                last=fault.span_end;
                let entry=DiscardedWindow{window,attempt,values:fault.values,
                    reference_ticks:fault.reference_ticks,stage:fault.stage};
                let conflict=rates[..i].iter().any(|&hz|!entry.compatible_with(hz)) ||
                    caps.nominal_hz.map_or(false,|hz|!entry.compatible_with(hz));
                if conflict {
                    return Err(QualificationFailure {reason:DiscardedRangeConflict,window,
                        values:fault.values,rates,nominal:caps.nominal_hz,cleanup_state:None,
                        reference_ticks:fault.reference_ticks});
                }
                if !evidence.push(entry) {
                    return Err(QualificationFailure {reason:PrecisionBudget,window,
                        values:fault.values,rates,nominal:caps.nominal_hz,cleanup_state:None,
                        reference_ticks:fault.reference_ticks});
                }
                // Edge acquisition may include two slow I/O reads and
                // their polling gap. Use a fresh counter window with two
                // independently timed latch commands, never a wide edge
                // recast as a precise observation. No platform special case.
                latched=true;
                continue;
            }
            Err(fault)=>return Err(QualificationFailure {
                reason: Measure(fault.stage),window,values:fault.values,
                rates,nominal:caps.nominal_hz,cleanup_state:fault.cleanup_state,
                reference_ticks:fault.reference_ticks,
            }),
        };
        let ticks=count_proof.map_or(DIVISOR,|m|m.start_count-m.end_count);
        rates[i]=calibration.observe_checked_span(observation,span_start,span_end).map_err(|fault| {
            let values=if fault==tsc::CalibrationFault::BetweenSamples {
                [last,span_start,observation.before_start,span_end]
            } else {
                [observation.before_start,observation.after_start,observation.before_end,observation.after_end]
            };
            QualificationFailure { reason: Calibration(fault),window,values,
                rates,nominal:caps.nominal_hz,cleanup_state:None,reference_ticks:ticks }
        })?;
        last=span_end;
        // Retain actual accepted latch measurements even on a subsequent
        // conflict, so the rejection can be diagnosed from the operands.
        if let Some(m)=count_proof {evidence.count_samples[i]=Some((attempt,m));}
        if let Some(entry)=evidence.iter().find(|entry|!entry.compatible_with(rates[i])) {
            return Err(QualificationFailure {reason:DiscardedRangeConflict,window:entry.window,
                values:entry.values,rates,nominal:caps.nominal_hz,cleanup_state:None,
                reference_ticks:entry.reference_ticks});
        }
        i+=1;
    }
    let rate=calibration.finish_checked().map_err(|fault| QualificationFailure {
        reason:Calibration(fault),window:0,values:[0;4],rates,
        nominal:caps.nominal_hz,cleanup_state:None,reference_ticks:0,
    })?;
    if let Some(entry)=evidence.iter().find(|entry|!entry.compatible_with(rate.hz())) {
        return Err(QualificationFailure {reason:DiscardedRangeConflict,window:entry.window,
            values:entry.values,rates,nominal:caps.nominal_hz,cleanup_state:None,
            reference_ticks:entry.reference_ticks});
    }
    Ok(rate)
}

static OWNER: AtomicBool = AtomicBool::new(false);

/// Boot-only hardware calibration. Serialize all channel-2 command/data
/// transactions across CPUs with local interrupts masked. The callback
/// may maintain the *other* timekeeper; it must never acquire this owner.
/// Acquire is bounded; a wedged owner is an error, not a fake interval.
pub(crate) unsafe fn qualify(allowed: bool, mut maintain: impl FnMut(), discarded:&mut AcquisitionEvidence)
    -> Result<tsc::QualifiedRate,QualificationFailure> {
    use QualificationReason::*;
    *discarded=AcquisitionEvidence::new();
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

