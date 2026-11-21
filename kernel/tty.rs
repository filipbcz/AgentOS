//! First canonical TTY. The device IRQs stay routed to their BSP while
//! descriptors may move between CPUs. A private IRQ-masked gate protects the
//! complete line, UART and framebuffer state in one owned writable frame.
#![allow(non_snake_case)]
use crate::{acpi::Platform, fb_console::Console, input, ioapic::Route, keyboard::Keyboard,
            line::{LineInput, Read}, log_policy::Level, logger::LOGGER, out, ps2, COM};
use core::{cell::UnsafeCell, hint::spin_loop, sync::atomic::{AtomicBool, Ordering}};

pub const VECTOR: u32 = 0xe1;
pub const KEYBOARD_VECTOR: u32 = 0xe2;
pub struct Terminal {
    fLocked: AtomicBool,
    fState: UnsafeCell<TerminalState>,
}

// Every access to the state takes fLocked with local IRQs masked. The device
// routes and framebuffer backing remain alive until all session tasks stop.
unsafe impl Sync for Terminal {}

struct TerminalState {
    fInput: LineInput,
    fRoute: Route,
    fKeyboardRoute: Option<Route>,
    fKeyboard: Keyboard,
    fKeyboardConfig: Option<ps2::Saved>,
    fScreen: Option<Console>,
    fCpu: u8,
    fErrors: u8,
    fLastCr: bool,
    fEnabled: bool,
}
const _: () = assert!(core::mem::size_of::<Terminal>() <= 4096);

impl Terminal {
    pub unsafe fn new(aPlatform: &Platform, aCpu: u8) -> Result<Self, &'static [u8]> {
        Ok(Self { fLocked: AtomicBool::new(false),
                  fState: UnsafeCell::new(TerminalState::new(aPlatform, aCpu)?) })
    }

    /// Acquire after the process/queue and optional frame gate. IRQ handlers
    /// release this gate before taking Frames or waking scheduler queues.
    /// No callback may acquire a new frame/queue gate while holding this one.
    fn withState<R>(&self, aOperation: impl FnOnce(&mut TerminalState) -> R) -> R {
        #[cfg(not(test))]
        let pFlags: usize;
        #[cfg(not(test))]
        unsafe { core::arch::asm!("pushfq", "pop {}", "cli", out(reg) pFlags); }
        #[cfg(test)]
        let pFlags = 0;
        while self.fLocked.swap(true, Ordering::Acquire) {
            while self.fLocked.load(Ordering::Relaxed) { spin_loop(); }
        }
        let _pGuard = TerminalGuard { fLocked: &self.fLocked, fFlags: pFlags };
        aOperation(unsafe { &mut *self.fState.get() })
    }

    pub fn attach_screen(&self, aConsole: Console) {
        self.withState(|pState| pState.attach_screen(aConsole));
    }
    pub unsafe fn enable(&self) { self.withState(|pState| pState.enable()); }
    pub unsafe fn disable(&self) { self.withState(|pState| pState.disable()); }
    pub unsafe fn write(&self, aData: &[u8]) -> Result<usize, isize> {
        self.withState(|pState| pState.write(aData))
    }
    pub unsafe fn diagnostic(&self, aData: &[u8]) {
        self.withState(|pState| pState.diagnostic(aData));
    }
    pub fn ready(&self) -> bool { self.withState(|pState| pState.ready()) }
    pub fn read<F>(&self, aLimit: usize, aCopy: F) -> Result<Option<usize>, isize>
        where F: FnOnce(&[u8]) -> Result<(), isize>
    {
        self.withState(|pState| pState.read(aLimit, aCopy))
    }
    pub unsafe fn keyboard_interrupt(&self) {
        self.withState(|pState| pState.keyboard_interrupt());
    }
    pub unsafe fn interrupt(&self) { self.withState(|pState| pState.interrupt()); }
}

struct TerminalGuard<'a> {
    fLocked: &'a AtomicBool,
    fFlags: usize,
}

impl Drop for TerminalGuard<'_> {
    fn drop(&mut self) {
        self.fLocked.store(false, Ordering::Release);
        if self.fFlags & (1 << 9) != 0 {
            #[cfg(not(test))]
            unsafe { core::arch::asm!("sti", options(nostack)); }
        }
    }
}

impl TerminalState {
    pub unsafe fn new(aPlatform: &Platform, aCpu: u8) -> Result<Self, &'static [u8]> {
        Ok(Self { fInput: LineInput::new(), fRoute: Route::serial(aPlatform, aCpu, VECTOR)?,
                  fKeyboardRoute: Route::keyboard(aPlatform, aCpu, KEYBOARD_VECTOR).ok(),
                  fKeyboard: Keyboard::new(), fKeyboardConfig: None,
                  fScreen: None, fCpu: aCpu,
                  fErrors: 0, fLastCr: false, fEnabled: false })
    }

    /// Sole BSP owner; attach before starting the shell's IRQ routes.
    pub fn attach_screen(&mut self, console: Console) { self.fScreen = Some(console); }

    pub unsafe fn enable(&mut self) {
        out(COM + 1, 0);
        out(COM + 2, 0x03); // FIFO on, clear RX only; do not discard boot output.
        let _ = input(COM + 5);
        let _ = input(COM + 6);
        self.fErrors = 0;
        out(COM + 4, 0x0b); // DTR, RTS, OUT2 gates the PC UART interrupt.
        self.fEnabled = true;
        self.fRoute.enable();
        out(COM + 1, 0x05); // receive data and line-status errors; no TX IRQ.
        if let Some(route) = &self.fKeyboardRoute {
            // Failure to initialize PS/2 must not prevent serial recovery.
            self.fKeyboardConfig = ps2::enable();
            if self.fKeyboardConfig.is_some() { route.enable(); }
        }
    }

    pub unsafe fn disable(&mut self) {
        out(COM + 1, 0);
        self.fRoute.disable();
        if let Some(route) = &self.fKeyboardRoute { route.disable(); }
        if let Some(config) = self.fKeyboardConfig.take() {
            if !ps2::restore(config) {
                let _ = LOGGER.record(crate::logger::ticks(), self.fCpu as u32, Level::Error, b"PS2 restore failed");
                // Controller recovery failure must be visible even when the
                // canonical input device is being torn down.
                self.diagnostic(b"AGENTOS PS2 RESTORE FAILED\r\n");
            }
        }
        self.fKeyboard.reset();
        self.fEnabled = false;
    }

    unsafe fn status(&mut self) -> u8 {
        let pStatus = input(COM + 5);
        // Reading LSR clears RX errors, including during transmit polling.
        self.fErrors |= pStatus & 0x1e;
        pStatus
    }

    fn damage(&mut self) -> bool {
        if self.fErrors == 0 { return false; }
        self.fErrors = 0;
        self.fInput.invalidate();
        let _ = LOGGER.record(crate::logger::ticks(), self.fCpu as u32, Level::Error, b"UART RX error");
        true
    }

    unsafe fn byte(&mut self, aByte: u8) -> bool {
        for _ in 0..100_000 {
            if self.status() & 0x20 != 0 {
                out(COM, aByte);
                self.fLastCr = aByte == b'\r';
                return true;
            }
        }
        false
    }

    unsafe fn output(&mut self, aData: &[u8], aCooked: bool) -> Result<usize, isize> {
        // A display-only shell must remain usable if UART TX is wedged. A byte
        // counts as written if at least one of its two sinks accepted it.
        // Without GOP, preserve the original partial-write UART contract.
        let mut pWritten = 0;
        let mut serial_failed = false;
        for &pByte in aData {
            let sent = if serial_failed { false } else {
                ( !aCooked || pByte != b'\n' || self.fLastCr || self.byte(b'\r') )
                    && self.byte(pByte)
            };
            if !sent { serial_failed = true; }
            if let Some(screen) = &mut self.fScreen {
                screen.write(&[pByte]);
            } else if !sent {
                return if pWritten == 0 { Err(-5) } else { Ok(pWritten) };
            }
            pWritten += 1;
        }
        if serial_failed {
            let _ = LOGGER.record(crate::logger::ticks(), self.fCpu as u32, Level::Error,
                b"UART TX failed; GOP fallback active");
        }
        Ok(pWritten)
    }

    pub unsafe fn write(&mut self, aData: &[u8]) -> Result<usize, isize> { self.output(aData, true) }
    pub unsafe fn diagnostic(&mut self, aData: &[u8]) { let _ = self.output(aData, false); }

    pub fn ready(&self) -> bool { self.fErrors != 0 || self.fInput.ready() }

    pub fn read<F>(&mut self, aLimit: usize, aCopy: F) -> Result<Option<usize>, isize>
        where F: FnOnce(&[u8]) -> Result<(), isize>
    {
        if aLimit == 0 { return Ok(Some(0)); }
        if !self.fEnabled { return Err(-5); }
        self.damage();
        let pCount = match self.fInput.peek(aLimit) {
            None => return Ok(None),
            Some(Read::Overflow) => { self.fInput.consume(0); return Err(-75); }
            Some(Read::Eof) => 0,
            Some(Read::Data(pBytes)) => { aCopy(pBytes)?; pBytes.len() }
        };
        self.fInput.consume(pCount);
        Ok(Some(pCount))
    }

    pub unsafe fn keyboard_interrupt(&mut self) {
        ps2::drain(|result| match result {
            Ok(scan) => {
                if let Some(byte) = self.fKeyboard.feed(scan) {
                    let echo = self.fInput.push(byte);
                    self.diagnostic(echo.asBytes());
                }
            }
            Err(()) => {
                self.fKeyboard.reset();
                self.fInput.invalidate();
                let _ = LOGGER.record(crate::logger::ticks(), self.fCpu as u32, Level::Error, b"PS2 RX error");
            }
        });
    }

    pub unsafe fn interrupt(&mut self) {
        // Force the edge source low while draining. Reenabling below produces
        // a new assertion for a byte that arrives after the last empty check.
        out(COM + 1, 0);
        let mut pDrained = false;
        for _ in 0..256 {
            let pStatus = self.status();
            let pDamaged = self.damage();
            if pStatus & 1 == 0 { pDrained = true; break; }
            let pByte = input(COM);
            if !pDamaged {
                let pEcho = self.fInput.push(pByte);
                self.diagnostic(pEcho.asBytes());
            }
        }
        if !pDrained {
            // Never leave an edge-triggered FIFO asserted indefinitely, and
            // never treat a surviving suffix of damaged input as a command.
            self.fInput.invalidate();
            out(COM + 2, 0x03);
            let _ = self.status();
            self.damage();
        }
        out(COM + 1, 0x05);
    }
}
