//! First canonical TTY. All state lives in one owned writable frame; only its
//! BSP and same-CPU descriptors may access it, with interrupts masked.
#![allow(non_snake_case)]
use crate::{acpi::Platform, fb_console::Console, input, ioapic::Route, keyboard::Keyboard,
            line::{LineInput, Read}, log_policy::Level, logger::LOGGER, out, ps2, COM};

pub const VECTOR: u32 = 0xe1;
pub const KEYBOARD_VECTOR: u32 = 0xe2;
pub struct Terminal {
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
                let _ = LOGGER.record(0, self.fCpu as u32, Level::Error, b"PS2 restore failed");
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
        let _ = LOGGER.record(0, self.fCpu as u32, Level::Error, b"UART RX error");
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
        let mut pWritten = 0;
        for &pByte in aData {
            if (aCooked && pByte == b'\n' && !self.fLastCr && !self.byte(b'\r')) || !self.byte(pByte) {
                return if pWritten == 0 { Err(-5) } else { Ok(pWritten) };
            }
            if let Some(screen) = &mut self.fScreen { screen.write(&[pByte]); }
            pWritten += 1;
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
                let _ = LOGGER.record(0, self.fCpu as u32, Level::Error, b"PS2 RX error");
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
