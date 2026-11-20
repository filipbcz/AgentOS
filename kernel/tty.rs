//! First canonical TTY. All state lives in one owned writable frame; only its
//! BSP and same-CPU descriptors may access it, with interrupts masked.
#![allow(non_snake_case)]
use crate::{acpi::Platform, input, ioapic::Route, line::{LineInput, Read}, out, COM};

pub const VECTOR: u32 = 0xe1;
pub struct Terminal {
    fInput: LineInput,
    fRoute: Route,
    fErrors: u8,
    fLastCr: bool,
    fEnabled: bool,
}
const _: () = assert!(core::mem::size_of::<Terminal>() <= 4096);

impl Terminal {
    pub unsafe fn new(aPlatform: &Platform, aCpu: u8) -> Result<Self, &'static [u8]> {
        Ok(Self { fInput: LineInput::new(), fRoute: Route::serial(aPlatform, aCpu, VECTOR)?,
                  fErrors: 0, fLastCr: false, fEnabled: false })
    }

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
    }

    pub unsafe fn disable(&mut self) {
        out(COM + 1, 0);
        self.fRoute.disable();
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
