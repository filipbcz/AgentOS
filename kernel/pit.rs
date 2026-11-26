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
                if lower == 0 || (upper-lower)*1_000_000 > middle*960 {
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

/// The same independent three-window qualification used by hardware and
/// separate host fixtures. Do not retry, substitute or discard measurements.
pub(crate) fn qualify_samples(caps: tsc::Capabilities, io: &mut impl Ports, max_polls: u32,
    mut timestamp: impl FnMut()->u64, mut maintain: impl FnMut())
    -> Result<tsc::QualifiedRate, QualificationFailure> {
    use QualificationReason::*;
    let mut calibration=tsc::Calibration::new(caps);
    let mut rates=[0u64;3];
    let mut last=0u64;
    for i in 0..3 {
        let observation=measure_detailed(true,io,max_polls,&mut timestamp,&mut maintain)
            .map_err(|fault| QualificationFailure {
                reason: Measure(fault.stage),window:i as u8+1,values:fault.values,
                rates,nominal:caps.nominal_hz,cleanup_state:fault.cleanup_state,
            })?;
        rates[i]=calibration.observe_checked(observation).map_err(|fault| {
            let values=if fault==tsc::CalibrationFault::BetweenSamples {
                [last,observation.before_start,observation.after_start,observation.after_end]
            } else {
                [observation.before_start,observation.after_start,observation.before_end,observation.after_end]
            };
            QualificationFailure { reason: Calibration(fault),window:i as u8+1,values,
                rates,nominal:caps.nominal_hz,cleanup_state:None }
        })?;
        last=observation.after_end;
    }
    calibration.finish_checked().map_err(|fault| QualificationFailure {
        reason:Calibration(fault),window:0,values:[0;4],rates,
        nominal:caps.nominal_hz,cleanup_state:None,
    })
}

static OWNER: AtomicBool = AtomicBool::new(false);

/// Boot-only hardware calibration. Serialize all channel-2 command/data
/// transactions across CPUs with local interrupts masked. The callback
/// may maintain the *other* timekeeper; it must never acquire this owner.
/// Acquire is bounded; a wedged owner is an error, not a fake interval.
pub(crate) unsafe fn qualify(allowed: bool, mut maintain: impl FnMut())
    -> Result<tsc::QualifiedRate,QualificationFailure> {
    use QualificationReason::*;
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
        let result=qualify_samples(caps,&mut Io,MAX_POLLS,||tsc::read(),&mut maintain);
        OWNER.store(false, Ordering::Release);
        result
    } else { Err(QualificationFailure::new(OwnerBusy,caps.nominal_hz)) };
    if flags & (1 << 9) != 0 { asm!("sti", options(nostack)); }
    rate
}

