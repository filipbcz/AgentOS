//! Read-only PCI discovery on the bootstrap processor, before SMP or device IRQs.
use crate::acpi::Ecam;
use core::{arch::asm, fmt::{self, Write}, ptr};

enum Config { Ports, Ecam(Ecam) }

impl Config {
    // Caller owns the CF8/CFC pair exclusively during early boot. ECAM pages
    // are supervisor-only, uncached and read-only in the active address space.
    unsafe fn read(&self, bus: u8, devfn: u8, offset: u8) -> u32 {
        debug_assert!(offset % 4 == 0);
        match self {
            Self::Ports => {
                let selector = 0x8000_0000 | (u32::from(bus) << 16) |
                               (u32::from(devfn) << 8) | u32::from(offset);
                asm!("out dx, eax", in("dx") 0xcf8u16, in("eax") selector, options(nostack, preserves_flags));
                let value;
                asm!("in eax, dx", in("dx") 0xcfcu16, out("eax") value, options(nostack, preserves_flags));
                value
            }
            Self::Ecam(w) => {
                let address = w.base + ((bus as usize) << 20) + ((devfn as usize) << 12) + usize::from(offset);
                ptr::read_volatile(address as *const u32)
            }
        }
    }
}

pub(super) struct Console;
impl Write for Console {
    fn write_str(&mut self, text: &str) -> fmt::Result {
        unsafe { crate::serial(text.as_bytes()); }
        Ok(())
    }
}

type Error = &'static [u8];

#[derive(Default)]
pub struct Devices {
    pub oxford: Option<crate::pci_irq::Oxford>,
    pub ahci: Option<crate::ahci::Controller>,
}

// Decode only assigned resources. Sizing by writing all ones would disrupt
// hardware the firmware may still have decoding, including the display.
fn resources(read: &impl Fn(u8) -> u32, header: u8, visit: &mut impl FnMut(u8, &'static str, u64))
    -> Result<(), Error>
{
    let slots = match header { 0 => 6, 1 => 2, _ => 0 };
    let mut index = 0;
    while index < slots {
        let slot = index;
        let low = read(0x10 + 4 * slot);
        index += 1;
        let (kind, address) = if low & 1 != 0 {
            ("io", u64::from(low & !3))
        } else {
            let base = u64::from(low & !15);
            match (low >> 1) & 3 {
                0 => ("mem32", base),
                1 => ("mem1m", base),
                2 if index < slots => {
                    let high = u64::from(read(0x10 + 4 * index));
                    index += 1;
                    ("mem64", base | high << 32)
                }
                _ => return Err(b"invalid memory BAR"),
            }
        };
        if address != 0 { visit(slot, kind, address); }
    }
    Ok(())
}

fn capabilities(read: &impl Fn(u8) -> u32, header: u8) -> Result<[u8; 3], Error> {
    let mut caps = [0; 3]; // MSI, MSI-X, PCI Express capability offsets
    if read(4) & (1 << 20) == 0 { return Ok(caps); }
    let mut next = read(if header == 2 { 0x14 } else { 0x34 }) as u8 & !3;
    let mut seen = 0u64;
    while next != 0 {
        let bit = 1u64 << (next / 4);
        if next < 0x40 || seen & bit != 0 { return Err(b"invalid capability chain"); }
        seen |= bit;
        let cap = read(next);
        let slot = match cap as u8 { 5 => Some(0), 0x11 => Some(1), 0x10 => Some(2), _ => None };
        if let Some(slot) = slot {
            if caps[slot] != 0 { return Err(b"duplicate capability"); }
            caps[slot] = next;
        }
        next = (cap >> 8) as u8 & !3;
    }
    Ok(caps)
}

unsafe fn scan(config: Config, segment: u16, first: u8, last: u8,
               devices: &mut Devices) -> Result<usize, Error> {
    let mut count = 0;
    for bus in first..=last {
        for device in 0..32 {
            for function in 0..8 {
                let read = |offset| config.read(bus, device * 8 + function, offset);
                let id = read(0);
                if id as u16 == 0xffff {
                    if function == 0 { break; }
                    continue;
                }
                let class_rev = read(8);
                let header = (read(0x0c) >> 16) as u8;
                let layout = header & 0x7f;
                let [msi, msix, pcie] = capabilities(&read, layout)?;
                if id == 0xc308_1415 && class_rev >> 8 == 0x070002 && layout == 0 &&
                    (msi != 0 || msix != 0) && devices.oxford.is_none() {
                    if let Config::Ecam(w) = &config {
                        let bdf = (u16::from(bus) << 8) | u16::from(device * 8 + function);
                        let page = w.base + (usize::from(bdf) << 12);
                        devices.oxford = Some(crate::pci_irq::Oxford::discover(segment, bdf, page, msi, msix)?);
                    }
                }
                if class_rev >> 8 == 0x010601 && layout == 0 && devices.ahci.is_none() {
                    if let Config::Ecam(w) = &config {
                        let bdf = (u16::from(bus) << 8) | u16::from(device * 8 + function);
                        let bar = read(0x24);
                        if bar != 0 && bar & 15 == 0 {
                            devices.ahci = Some(crate::ahci::Controller {
                                cfg: w.base + (usize::from(bdf) << 12), abar: bar as usize,
                            });
                        }
                    }
                }
                let _ = write!(Console, "AGENTOS PCI DEV {:04x}:{:02x}:{:02x}.{} ID={:04x}:{:04x} CLASS={:06x} REV={:02x} MSI={:02x} MSIX={:02x} PCIE={:02x}\r\n",
                    segment, bus, device, function, id as u16, id >> 16, class_rev >> 8, class_rev as u8, msi, msix, pcie);
                resources(&read, layout, &mut |slot, kind, address| {
                    let _ = write!(Console, "AGENTOS PCI BAR {:04x}:{:02x}:{:02x}.{} {} {} {:016x}\r\n",
                                   segment, bus, device, function, slot, kind, address);
                })?;
                count += 1;
                if function == 0 && header & 0x80 == 0 { break; }
            }
        }
    }
    Ok(count)
}

pub unsafe fn inventory(windows: &[Ecam]) -> Result<Devices, Error> {
    let mut devices = Devices::default();
    let count = if windows.is_empty() {
        crate::serial(b"AGENTOS PCI CONFIG CF8\r\n");
        scan(Config::Ports, 0, 0, 255, &mut devices)?
    } else {
        crate::serial(b"AGENTOS PCI CONFIG ECAM\r\n");
        let mut count = 0;
        for &w in windows { count += scan(Config::Ecam(w), w.segment, w.first, w.last, &mut devices)?; }
        count
    };
    let _ = write!(Console, "AGENTOS PCI END FUNCTIONS={}\r\n", count);
    Ok(devices)
}
