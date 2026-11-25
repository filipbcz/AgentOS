//! Boot-time owner of the Oxford PCIe UART and its PCI message interrupts.
//! CPU startup is serialized. A route is quiesced before the next CPU owns it.
use crate::{frames::Frames, system_clock, paging, pci::Console};
use core::{arch::asm, fmt::Write, ptr, sync::atomic::{AtomicPtr, AtomicU32, AtomicU64, Ordering}};

type Error = &'static [u8];
pub const MSI: u8 = 0xe4;
pub const MSIX: u8 = 0xe5;
const ENABLE_X: u16 = 1 << 15;
const MASK_X: u16 = 1 << 14;
const INTX_DISABLE: u16 = 1 << 10;

unsafe fn rd<T: Copy>(addr: usize) -> T { ptr::read_volatile(addr as *const T) }
unsafe fn wr<T>(addr: usize, val: T) { ptr::write_volatile(addr as *mut T, val); }

// Standard capability registers and MSI-X vector 0, the vector used by UART0.
struct Messages {
    msi: usize,
    msix: usize,
    entry: usize,
    pending: usize,
}

impl Messages {
    unsafe fn disable(&self) {
        if self.msi != 0 { wr(self.msi + 2, rd::<u16>(self.msi + 2) & !1); }
        if self.msix != 0 {
            wr(self.msix + 2, (rd::<u16>(self.msix + 2) | MASK_X) & !ENABLE_X);
            wr(self.entry + 12, 1u32);
        }
    }

    unsafe fn route(&self, vector: u8, dest: u8) -> Result<(), Error> {
        let addr = 0xfee0_0000u32 | (u32::from(dest) << 12);
        self.disable();
        if vector == MSI {
            let ctrl = rd::<u16>(self.msi + 2) & !0x71; // one fixed-delivery message
            let wide = ctrl & 0x80 != 0;
            let data = self.msi + if wide { 12 } else { 8 };
            wr(self.msi + 4, addr);
            if wide { wr(self.msi + 8, 0u32); }
            wr(data, u16::from(vector));
            if ctrl & 0x100 != 0 { wr(data + 4, rd::<u32>(data + 4) & !1); }
            wr(self.msi + 2, ctrl | 1);
            if rd::<u16>(self.msi + 2) != ctrl | 1 || rd::<u32>(self.msi + 4) != addr ||
                (wide && rd::<u32>(self.msi + 8) != 0) || rd::<u16>(data) != u16::from(vector) {
                return Err(b"MSI route readback");
            }
        } else {
            let ctrl = rd::<u16>(self.msix + 2);
            wr(self.msix + 2, ctrl | ENABLE_X | MASK_X);
            wr(self.entry, addr);
            wr(self.entry + 4, 0u32);
            wr(self.entry + 8, u32::from(vector));
            if rd::<u32>(self.entry) != addr || rd::<u32>(self.entry + 4) != 0 ||
                rd::<u32>(self.entry + 8) != u32::from(vector) || rd::<u32>(self.entry + 12) & 1 == 0 {
                return Err(b"MSI-X table readback");
            }
            wr(self.msix + 2, (ctrl | ENABLE_X) & !MASK_X);
            if rd::<u16>(self.msix + 2) & (ENABLE_X | MASK_X) != ENABLE_X {
                return Err(b"MSI-X function enable");
            }
        }
        Ok(())
    }
}

pub struct Oxford {
    segment: u16,
    bdf: u16,
    cfg: usize,
    base: usize,
    messages: Messages,
}

static PORT: AtomicPtr<Oxford> = AtomicPtr::new(ptr::null_mut());
static SAMPLE: AtomicU64 = AtomicU64::new(0);
static RECEIVED: AtomicU32 = AtomicU32::new(0);

impl Oxford {
    pub unsafe fn discover(segment: u16, bdf: u16, cfg: usize, msi: u8, msix: u8) -> Result<Self, Error> {
        let bar = |index: usize| -> Result<usize, Error> {
            let value = rd::<u32>(cfg + 0x10 + index * 4);
            if value == 0 || value & 15 != 0 { return Err(b"Oxford requires assigned 32-bit memory BARs"); }
            Ok(value as usize)
        };
        let base = bar(0)?;
        let cap = |offset: u8| if offset == 0 { 0 } else { cfg + usize::from(offset) };
        if msi > 0xe8 || msix > 0xf4 { return Err(b"truncated PCI message capability"); }
        let mut messages = Messages { msi: cap(msi), msix: cap(msix), entry: 0, pending: 0 };
        if msix != 0 {
            // The VirtualBox Oxford function exposes a dedicated 64 KiB BAR1.
            // Both offsets and the advertised vector count come from the device.
            let table_bar = bar(1)?;
            let n = usize::from(rd::<u16>(messages.msix + 2) & 0x7ff) + 1;
            let region = |reg: usize, size: usize| -> Result<usize, Error> {
                let loc = rd::<u32>(messages.msix + reg) as usize;
                let offset = loc & !7;
                if loc & 7 != 1 || offset + size > 65536 { return Err(b"Oxford MSI-X BAR extent"); }
                Ok(table_bar + offset)
            };
            messages.entry = region(4, n * 16)?;
            messages.pending = region(8, ((n + 63) / 64) * 8)?;
            if messages.entry < messages.pending + ((n + 63) / 64) * 8 &&
                messages.pending < messages.entry + n * 16 { return Err(b"overlapping MSI-X regions"); }
        }
        Ok(Self { segment, bdf, cfg, base, messages })
    }

    pub unsafe fn bind(self, root: usize, frames: &mut Frames<'_>) -> Result<(), Error> {
        paging::claim_config(root, self.cfg).ok_or(b"Oxford ECAM permissions" as Error)?;
        let mut pages = [self.base, self.base + 4096, self.messages.entry,
                         self.messages.entry + 12, self.messages.pending];
        for i in 0..pages.len() {
            pages[i] &= !4095;
            if pages[i] != 0 && !pages[..i].contains(&pages[i]) {
                paging::map_device(root, frames, pages[i]).ok_or(b"Oxford MMIO mapping" as Error)?;
            }
        }
        let frame = frames.alloc().ok_or(b"Oxford device storage" as Error)?;
        let device = frame.into_address() as *mut Oxford;
        device.write(self);
        PORT.store(device, Ordering::Release);
        Ok(())
    }

    unsafe fn exchange(&self, vector: u8, cpu: u8, byte: u8) -> Result<(), Error> {
        let uart = self.base + 4096;
        let before = RECEIVED.load(Ordering::Acquire);
        // Wait for the previous transmit shift register to drain with the
        // receiver's loopback disconnected. Only the ISR can consume RX.
        until(|| rd::<u8>(uart + 5) & 0x40 != 0, b"Oxford transmitter busy")?;
        if rd::<u32>(self.base + 8) & 1 != 0 { return Err(b"Oxford RX already asserted"); }
        let msix = vector == MSIX;
        if msix {
            wr(self.messages.entry + 12, 1u32);
            if rd::<u32>(self.messages.entry + 12) & 1 == 0 || rd::<u32>(self.messages.pending) & 1 != 0 {
                return Err(b"MSI-X vector mask or stale pending bit");
            }
        }
        wr(uart + 4, 0x18u8); // local loopback and OUT2
        wr(self.base + 0x0c, 1u32);
        wr(uart, byte);
        asm!("sti", options(nostack));
        let result = (|| {
            if msix {
                until(|| rd::<u32>(self.messages.pending) & 1 != 0, b"MSI-X masked message timeout")?;
                if RECEIVED.load(Ordering::Acquire) != before { return Err(b"masked MSI-X delivered" as Error); }
                wr(self.messages.entry + 12, 0u32);
            }
            until(|| RECEIVED.load(Ordering::Acquire) != before, b"Oxford message delivery timeout")
        })();
        asm!("cli", options(nostack));
        result?;
        let sample = SAMPLE.load(Ordering::Acquire);
        let rx = sample as u8;
        let iir = (sample >> 8) as u8;
        let delivered = (sample >> 16) as u8;
        let apic = (sample >> 24) as u8;
        let service = sample >> 32;
        let count = RECEIVED.load(Ordering::Acquire);
        if count != before + 1 || rx != byte || iir & 15 != 4 || delivered != vector ||
            apic != cpu || service != 3 || (msix && rd::<u32>(self.messages.pending) & 1 != 0) {
            let _ = writeln!(Console, "DEVICE IRQ MISMATCH vector={vector:02x} cpu={cpu} tx={byte:02x} sample={sample:016x} before={before} after={count}\r");
            return Err(b"Oxford interrupt source, vector, CPU, data or EOI mismatch");
        }
        let _ = writeln!(Console, "AGENTOS DEVICE IRQ BDF={:04x}:{:02x}:{:02x}.{} MODE={} VECTOR={:02x} APIC={:02x} TX={:02x} RX={:02x} IIR={:02x} ACK={} EOI={} PENDING={} COUNT={}\r",
            self.segment, self.bdf >> 8, (self.bdf >> 3) & 31, self.bdf & 7,
            if msix { "MSIX" } else { "MSI" }, delivered, apic, byte, rx, iir, service & 1,
            service >> 1, u8::from(msix), count);
        Ok(())
    }

    unsafe fn run(&self, cpu: u8) -> Result<(), Error> {
        let cmd = rd::<u16>(self.cfg + 4);
        let m = &self.messages;
        if (m.msi != 0 && rd::<u16>(m.msi + 2) & 1 != 0) ||
            (m.msix != 0 && rd::<u16>(m.msix + 2) & ENABLE_X != 0) { return Err(b"Oxford already routed"); }
        wr(self.cfg + 4, cmd | INTX_DISABLE | 2);
        if rd::<u16>(self.cfg + 4) & (INTX_DISABLE | 2) != INTX_DISABLE | 2 ||
            rd::<u32>(self.base) != 0x00070002 || rd::<u32>(self.base + 4) == 0 {
            wr(self.cfg + 4, cmd);
            return Err(b"Oxford memory decode or device identity");
        }
        let result = (|| {
            let uart = self.base + 4096;
            wr(uart + 3, 3u8); // 8N1, DLAB clear
            wr(uart + 1, 0u8);
            wr(uart + 2, 0u8); // single-byte RX
            wr(self.base + 0x10, 1u32); // arm the source separately for each transfer
            for (vector, cap) in [(MSI, m.msi), (MSIX, m.msix)] {
                if cap == 0 { continue; }
                m.route(vector, cpu)?;
                wr(uart + 1, 1u8); // received-data interrupts only
                for payload in [0x53, 0xa6] { self.exchange(vector, cpu, payload ^ cpu ^ vector)?; }
                wr(uart + 1, 0u8);
            }
            Ok(())
        })();
        wr(self.base + 0x10, 1u32);
        wr(self.base + 0x1000 + 1, 0u8);
        m.disable();
        wr(self.base + 0x1000 + 4, 0u8);
        wr(self.cfg + 4, cmd);
        result
    }
}

fn until(mut condition: impl FnMut() -> bool, timeout: Error) -> Result<(), Error> {
    let start = system_clock::millis().ok_or(b"missing IRQ deadline clock" as Error)?;
    for _ in 0..10_000_000 {
        if condition() { return Ok(()); }
        if system_clock::millis().map_or(true, |now| now - start >= 750) { break; }
        core::hint::spin_loop();
    }
    Err(timeout)
}

pub unsafe fn exercise(cpu: u8) -> Result<(), Error> {
    match PORT.load(Ordering::Acquire).as_ref() { Some(port) => port.run(cpu), None => Ok(()) }
}

// Called exclusively from the two device IDT gates. Reading RBR consumes
// the byte; check at the device that this removed the asserted cause.
pub unsafe fn acknowledge() -> u64 {
    let Some(port) = PORT.load(Ordering::Acquire).as_ref() else { return 0 };
    let uart = port.base + 4096;
    let pending = rd::<u32>(port.base + 8) & 1 != 0;
    let iir = rd::<u8>(uart + 2);
    if !pending || iir & 15 != 4 { return 0; }
    // End this one-byte transfer while RBR still contains its byte. The
    // transmitter may finish draining after RX is ready (VBox 7.1.12).
    wr(port.base + 0x10, 1u32);
    wr(uart + 4, 0u8);
    // LSR reads update the Oxford interrupt output. Consume RX before that
    // read so the still-asserted condition cannot request a second message.
    let byte = rd::<u8>(uart);
    let cleared = rd::<u8>(uart + 5) & 0x1f == 0 && rd::<u32>(port.base + 8) & 1 == 0 &&
                  rd::<u8>(uart + 2) & 1 != 0;
    u64::from(byte) | (u64::from(iir) << 8) | (u64::from(cleared) << 32)
}

pub fn record(vector: u8, apic: u8, eoi: bool, sample: u64) {
    SAMPLE.store(sample | (u64::from(vector) << 16) | (u64::from(apic) << 24) |
                 (u64::from(eoi) << 33), Ordering::Release);
    RECEIVED.fetch_add(1, Ordering::Release);
}
