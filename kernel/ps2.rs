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
pub unsafe fn enable() -> Option<u8> {
    if !cmd(0xad) { return None; } // first-port clock off
    flush();
    if !cmd(0x20) { return None; }
    let previous = recv()?;
    // Enable IRQ1 and translation, clear first-port clock disable.
    if !cmd(0x60) || !send((previous | 0x41) & !0x10) || !cmd(0xae) { return None; }
    // Explicitly request scan-code set 2 on the device. Controller translation
    // turns this into set 1. Acknowledgements must be consumed before IRQ1.
    if !send(0xf0) || recv() != Some(0xfa) ||
       !send(0x02) || recv() != Some(0xfa) ||
       !send(0xf4) || recv() != Some(0xfa) {
        restore(previous);
        return None;
    }
    flush();
    Some(previous)
}
pub unsafe fn restore(previous: u8) {
    if !cmd(0xad) { return; }
    flush();
    if !cmd(0x60) || !send(previous) { return; }
    if previous & 0x10 == 0 { let _ = cmd(0xae); }
}
/// Drain at most 64 bytes in one interrupt; caller invalidates input if more
/// data remain or if parity/timeout errors are observed.
pub unsafe fn drain(mut feed: impl FnMut(u8), mut invalid: impl FnMut()) {
    for _ in 0..64 {
        let status = input(STATUS);
        if status & 1 == 0 { return; }
        let byte = input(DATA);
        if status & 0xe0 != 0 { invalid(); } else { feed(byte); }
    }
    if input(STATUS) & 1 != 0 { invalid(); }
}
