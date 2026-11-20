//! Bounded 8042 first-port PS/2 initialization, set-1 translation.
//! All functions are BSP-only and must be called with interrupts disabled.
//! Failure is nonfatal: caller keeps the COM1 console available.
use crate::{input, out};

const DATA: u16 = 0x60;
const STATUS: u16 = 0x64;
const LIMIT: usize = 100_000;

unsafe fn wait_write() -> bool {
    for _ in 0..LIMIT { if input(STATUS) & 2 == 0 { return true; } }
    false
}
unsafe fn cmd(value: u8) -> bool {
    if !wait_write() { return false; }
    out(STATUS, value); true
}
unsafe fn send(value: u8) -> bool {
    if !wait_write() { return false; }
    out(DATA, value); true
}
unsafe fn recv() -> Option<u8> {
    for _ in 0..LIMIT {
        let status = input(STATUS);
        if status & 1 != 0 {
            let byte = input(DATA);
            return (status & 0xe0 == 0).then_some(byte);
        }
    }
    None
}
fn flush() {
    unsafe {
        for _ in 0..32 {
            if input(STATUS) & 1 == 0 { break; }
            let _ = input(DATA);
        }
    }
}
/// Saved controller config for restoring the pre-shell state.
/// We require translation enabled; without it the decoder would misread set 2.
pub struct Saved { pub controller: u8, pub scan_set: u8 }

unsafe fn keyboard_command(value: u8) -> bool {
    // Keyboard can request resend (0xfe); retries are strictly bounded.
    for _ in 0..3 {
        if !send(value) { return false; }
        match recv() { Some(0xfa) => return true, Some(0xfe) => continue, _ => return false }
    }
    false
}

unsafe fn keyboard_set(set: u8) -> bool {
    keyboard_command(0xf0) && keyboard_command(set)
}

pub unsafe fn enable() -> Option<Saved> {
    // Read the original configuration BEFORE changing the clock state. In
    // particular, bit 4 tells us whether the first port was already disabled.
    // If this read fails, leave the controller unchanged.
    if !cmd(0x20) { return None; }
    let previous = recv()?;
    if !cmd(0xad) { return None; }
    flush();

    // Only change controller configuration after preserving its original value.
    // A failure after this point always attempts to restore the saved state.
    // Keep IRQ1 masked while exchanging device commands; route IRQ1 only
    // after the final ACK has been consumed.
    let configured = cmd(0x60) && send((previous | 0x40) & !0x11) && cmd(0xae);
    if !configured {
        let _ = restore_controller(previous);
        return None;
    }
    // Query the original scan-code set (F0 00). Query results are encoded
    // as 0x43=set1, 0x41=set2, 0x3f=set3 by common PS/2 keyboards.
    // With controller translation enabled, the response may be translated;
    // temporarily clear translation while querying and setting the device.
    if !cmd(0xad) || !cmd(0x60) || !send(previous & !0x51) || !cmd(0xae) {
        let _ = restore_controller(previous);
        return None;
    }
    if !keyboard_command(0xf0) || !keyboard_command(0x00) {
        let _ = restore_controller(previous);
        return None;
    }
    let scan_set = match recv() {
        Some(0x43) | Some(1) => 1,
        Some(0x41) | Some(2) => 2,
        Some(0x3f) | Some(3) => 3,
        _ => { let _ = restore_controller(previous); return None; }
    };
    if !keyboard_set(2) || !keyboard_command(0xf4) {
        let _ = keyboard_set(scan_set);
        let _ = restore_controller(previous);
        return None;
    }
    flush();
    // Publish the final IRQ1-enabled configuration only after device ACKs.
    if !cmd(0xad) || !cmd(0x60) || !send((previous | 0x41) & !0x10) || !cmd(0xae) {
        let _ = restore(previous);
        return None;
    }
    Some(Saved { controller: previous, scan_set })
}

/// Best-effort restore with an explicit success result. The caller can report
/// failures; a controller that no longer accepts commands cannot be repaired
/// in software. Restoring the original command byte also restores IRQ1 state.
unsafe fn restore_controller(previous: u8) -> bool {
    if !cmd(0xad) { return false; }
    flush();
    if !cmd(0x60) || !send(previous) { return false; }
    if previous & 0x10 == 0 { cmd(0xae) } else { true }
}
/// Restore keyboard mode first with IRQ masked, then controller config.
/// A failed keyboard command still attempts controller recovery.
pub unsafe fn restore(saved: Saved) -> bool {
    let previous = saved.controller;
    let ready = cmd(0xad) && cmd(0x60) && send(previous & !0x51) && cmd(0xae);
    let keyboard_ok = ready && keyboard_set(saved.scan_set);
    let controller_ok = restore_controller(previous);
    keyboard_ok && controller_ok
}
/// Drain at most 64 bytes in one interrupt; caller invalidates input if more
/// data remain or if parity/timeout errors are observed.
pub unsafe fn drain(mut feed: impl FnMut(Result<u8, ()>)) {
    for _ in 0..64 {
        let status = input(STATUS);
        if status & 1 == 0 { return; }
        let byte = input(DATA);
        if status & 0xe0 != 0 { feed(Err(())); } else { feed(Ok(byte)); }
    }
    if input(STATUS) & 1 != 0 { feed(Err(())); }
}
