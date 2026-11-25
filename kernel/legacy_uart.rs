//! Conventional PC 16550-compatible I/O UART, optional on x86-64 systems.
//! PCI serial devices and other ACPI-described serial transports are separate
//! drivers. An absent legacy UART is not an error in platform initialization.
use crate::{input, out};

/// Probe a conventional UART without changing its divisor, line format,
/// interrupt enables or modem controls. Restore the scratch register even on
/// failure. A floating/unimplemented I/O bus must not be mistaken for THRE.
pub unsafe fn present(base: u16) -> bool {
    if base == 0 || base > u16::MAX - 7 { return false; }
    if input(base + 5) == 0xff || input(base + 2) == 0xff { return false; }
    let saved = input(base + 7);
    out(base + 7, 0x55);
    let first = input(base + 7) == 0x55;
    out(base + 7, 0xaa);
    let second = input(base + 7) == 0xaa;
    out(base + 7, saved);
    first && second && input(base + 7) == saved
}

/// Configure the detected legacy UART for 115200 baud, 8N1, no IRQs.
/// The PC legacy UART clock is 1.8432 MHz; nonlegacy clocks need their own
/// discovery/configuration. Called once on the BSP, before publishing it.
pub unsafe fn initialize(base: u16) -> bool {
    if !present(base) { return false; }
    // DLAB may be set by firmware; clear it before writing IER.
    out(base + 3, 3);
    out(base + 1, 0);
    out(base + 3, 0x83);
    out(base, 1);
    out(base + 1, 0);
    out(base + 3, 3);
    out(base + 2, 7);
    out(base + 4, 3);
    input(base + 3) == 3 && input(base + 1) == 0 && input(base + 5) != 0xff
}

/// Early output has no clock dependency; bound each wait and stop the
/// message on failure. Do not write if the bus returns the absent value.
pub unsafe fn transmit(base: u16, byte: u8) -> bool {
    for _ in 0..100_000 {
        let status = input(base + 5);
        if status == 0xff { return false; }
        if status & 0x20 != 0 { out(base, byte); return true; }
        core::hint::spin_loop();
    }
    false
}
