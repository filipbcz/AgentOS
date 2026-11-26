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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Error { NotDeclared, Configuration, NoEdge, Regression, Uncertain }

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
pub(crate) fn measure(allowed: bool, io: &mut impl Ports, max_polls: u32,
                      mut timestamp: impl FnMut() -> u64,
                      mut maintain: impl FnMut()) -> Result<Observation, Error> {
    if !allowed { return Err(Error::NotDeclared); }

    // Only bits 0..3 are legacy writable control bits; do not echo
    // OUT/refresh/NMI status bits into the register.
    let control = io.read(GATE) & 0x0c;
    io.write(GATE, control);
    let result = (|| {
        if io.read(GATE) & (GATE_ENABLE | SPEAKER_ENABLE) != 0 {
            return Err(Error::Configuration);
        }
        io.write(CONTROL, MODE0);
        io.write(CHANNEL2, DIVISOR as u8);
        io.write(CHANNEL2, (DIVISOR >> 8) as u8);
        io.write(CONTROL, STATUS2);
        let status = io.read(CHANNEL2);
        // Mode/access/binary fields must echo the programming. OUT
        // must be low, but NULL COUNT may still be set until a PIT tick.
        if status & 0x3f != 0x30 || status & 0x80 != 0 ||
           io.read(GATE) & (GATE_ENABLE | SPEAKER_ENABLE | OUT2) != 0 {
            return Err(Error::Configuration);
        }
        let before_start = timestamp();
        io.write(GATE, control | GATE_ENABLE);
        let after_start = timestamp();
        if after_start < before_start { return Err(Error::Regression); }
        let mut previous = after_start;
        let mut last_low = None;
        for _ in 0..max_polls {
            // Keeping an existing independent epoch sampled may take
            // time. Include any such delay in the terminal-edge bracket.
            maintain();
            let before = timestamp();
            let state = io.read(GATE);
            let after = timestamp();
            if before < previous || after < before { return Err(Error::Regression); }
            previous = after;
            if state & (GATE_ENABLE | SPEAKER_ENABLE) != GATE_ENABLE {
                return Err(Error::Configuration);
            }
            if state & OUT2 != 0 {
                // An already-high or fabricated immediate terminal
                // output cannot establish an observed interval.
                let before_end = last_low.ok_or(Error::NoEdge)?;
                io.write(CONTROL, STATUS2);
                if io.read(CHANNEL2) != 0xb0 { return Err(Error::Configuration); }
                let o = Observation { before_start, after_start,
                    before_end, after_end: after, reference_ns: INTERVAL_NS };
                // The 8254 loads/synchronizes on the next timer edge.
                // At this divisor two PIT ticks contribute <34 ppm.
                // Reserve this separately from the measured bracket.
                let lower = before_end.checked_sub(after_start).ok_or(Error::Regression)? as u128;
                let upper = after.checked_sub(before_start).ok_or(Error::Regression)? as u128;
                let middle = (lower+upper)/2;
                if lower == 0 || (upper-lower)*1_000_000 > middle*960 {
                    return Err(Error::Uncertain);
                }
                return Ok(o);
            }
            last_low = Some(before);
            spin_loop();
        }
        Err(Error::NoEdge)
    })();
    // Do not restore the inherited gate/speaker state: the original
    // channel mode/count has been replaced by the exclusive owner.
    // Preserve the other control bits and silence the reserved channel.
    io.write(GATE, control);
    if io.read(GATE) & (GATE_ENABLE | SPEAKER_ENABLE) != 0 {
        return Err(Error::Configuration);
    }
    result
}

static OWNER: AtomicBool = AtomicBool::new(false);

/// Boot-only hardware calibration. Serialize all channel-2 command/data
/// transactions across CPUs with local interrupts masked. The callback
/// may maintain the *other* timekeeper; it must never acquire this owner.
/// Acquire is bounded; a wedged owner is an error, not a fake interval.
pub(crate) unsafe fn qualify(allowed: bool, mut maintain: impl FnMut()) -> Option<tsc::QualifiedRate> {
    if !allowed { return None; }
    let caps = tsc::detect();
    if !caps.invariant { return None; }
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
        let result = (|| {
            let mut calibration=tsc::Calibration::new(caps);
            let mut io = Io;
            for _ in 0..3 {
                // Reprogram a complete finite one-shot for each sample.
                let observation = measure(true, &mut io, MAX_POLLS,
                    || tsc::read(), &mut maintain).ok()?;
                calibration.observe(observation)?;
            }
            calibration.finish()
        })();
        OWNER.store(false, Ordering::Release);
        result
    } else { None };
    if flags & (1 << 9) != 0 { asm!("sti", options(nostack)); }
    rate
}

