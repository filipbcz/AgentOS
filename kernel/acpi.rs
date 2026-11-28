use crate::{BootInfo, cpu_topology::CpuTopology, reference_clock::PmTimer};
use core::slice;

fn u32_at(bytes: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes(bytes.get(offset..offset+4)?.try_into().ok()?))
}

fn u64_at(bytes: &[u8], offset: usize) -> Option<u64> {
    Some(u64::from_le_bytes(bytes.get(offset..offset+8)?.try_into().ok()?))
}

fn checksum(bytes: &[u8]) -> bool {
    bytes.iter().fold(0u8, |sum, b| sum.wrapping_add(*b)) == 0
}

struct Firmware<'a> { map: &'a [u8], stride: usize }

impl Firmware<'_> {
    // Firmware identity mappings are still active. Only read within a described
    // firmware allocation. No references to the tables survive the CR3 switch.
    unsafe fn bytes(&self, address: u64, size: usize) -> Option<&[u8]> {
        let end = address.checked_add(size as u64)?;
        if address == 0 || end > 1 << 47 { return None; }
        for d in self.map.chunks_exact(self.stride) {
            if !matches!(u32_at(d, 0)?, 2 | 4 | 6 | 9 | 10) { continue; }
            let first = u64_at(d, 8)?;
            let limit = first.checked_add(u64_at(d, 24)?.checked_mul(4096)?)?;
            if first <= address && end <= limit {
                return Some(slice::from_raw_parts(address as *const u8, size));
            }
        }
        None
    }

    unsafe fn table(&self, address: u64) -> Option<&[u8]> {
        let header = self.bytes(address, 36)?;
        let length = u32_at(header, 4)? as usize;
        if length < 36 { return None; }
        let bytes = self.bytes(address, length)?;
        checksum(bytes).then_some(bytes)
    }
}

#[derive(Clone, Copy)]
pub struct IoApic { pub address: usize, pub gsi: u32 }
#[derive(Clone, Copy)]
pub struct IsaInterrupt { pub gsi: u32, pub low: bool, pub level: bool }

#[derive(Clone, Copy)]
pub struct Ecam {
    pub base: usize, // ACPI MCFG addresses are relative to bus zero.
    pub segment: u16,
    pub first: u8,
    pub last: u8,
}

impl Ecam {
    pub fn mapping(self) -> (usize, usize) {
        (self.base + ((self.first as usize) << 20),
         (usize::from(self.last) + 1 - usize::from(self.first)) << 20)
    }
}

pub struct PciWindows {
    entries: [Ecam; 16],
    count: usize,
}

impl PciWindows {
    fn new() -> Self {
        Self { entries: [Ecam { base: 0, segment: 0, first: 0, last: 0 }; 16], count: 0 }
    }
    pub fn windows(&self) -> &[Ecam] { &self.entries[..self.count] }

    fn parse(&mut self, table: &[u8]) -> Option<()> {
        let rows = table.get(44..)?;
        if self.count != 0 || rows.is_empty() || rows.len() % 16 != 0 { return None; }
        for row in rows.chunks_exact(16) {
            let base = usize::try_from(u64_at(row, 0)?).ok()?;
            let window = Ecam { base, segment: u16::from_le_bytes([row[8], row[9]]),
                                first: row[10], last: row[11] };
            if base == 0 || base & 0xfffff != 0 || window.first > window.last ||
                base.checked_add((usize::from(window.last) + 1) << 20)? > 1 << 39 { return None; }
            let (start, size) = window.mapping();
            for &other in self.windows() {
                let (address, length) = other.mapping();
                if (window.segment == other.segment && window.first <= other.last && other.first <= window.last)
                    || (start < address + length && address < start + size) { return None; }
            }
            *self.entries.get_mut(self.count)? = window;
            self.count += 1;
        }
        Some(())
    }
}

pub struct Platform {
    pub pci: PciWindows,
    pub lapic: usize,
    pub pm_timer: Option<PmTimer>,
    pub hpet: usize,
    pub topology: CpuTopology,
    pub legacy_pic: bool,
    pub legacy_pit_probe: bool,
    pub ps2_controller: bool,
    pub io_apics: [IoApic; 8],
    pub io_count: usize,
    pub serial_irq: IsaInterrupt,
    pub keyboard_irq: IsaInterrupt,
    serial_override: bool,
    keyboard_override: bool,
}

/// This profile maps one complete HPET register page, with 64-bit MMIO reads.
/// Capability/period validation happens against the device before it is used.
#[allow(non_snake_case)]
fn hpetAddress(aBytes: &[u8]) -> Option<usize> {
    if aBytes.len() < 56 || aBytes.get(..4)? != b"HPET" ||
       u32_at(aBytes, 4)? as usize != aBytes.len() || !checksum(aBytes) ||
       aBytes[40] != 0 || !matches!(aBytes[41], 0 | 32 | 64) ||
       aBytes[42] != 0 || !matches!(aBytes[43], 0 | 3 | 4) { return None; }
    let pAddress = usize::try_from(u64_at(aBytes, 44)?).ok()?;
    // Keep hardware outside the sole user PML4 slot and canonical low half.
    (pAddress != 0 && pAddress & 4095 == 0 && pAddress < (1usize << 39))
        .then_some(pAddress)
}

/// FADT IA-PC Boot Architecture Flags, offset 109, bit 1 (ACPI §5.2.9).
/// FADT revision 1/2 predates the 8042 flag; retain conventional legacy
/// discovery there. A truncated modern FADT is invalid, not permission to
/// probe an undeclared controller.
pub(crate) fn fadt_8042(table: &[u8]) -> Option<bool> {
    if table.len() < 36 || table.get(..4)? != b"FACP" ||
       u32_at(table, 4)? as usize != table.len() || !checksum(table) {
        return None;
    }
    if table[8] < 3 { return Some(true); }
    let flags = u16::from_le_bytes(table.get(109..111)?.try_into().ok()?);
    Some(flags & 2 != 0)
}

/// MADT PCAT_COMPAT declares the legacy dual 8259 interrupt model,
/// not proof of an 8254. Permit only a bounded, validated legacy PIT
/// probe on that compatibility path, with a valid non-reduced FADT.
/// IA-PC LEGACY_DEVICES alone describes user-visible ISA/LPC devices,
/// and is not a PIT presence flag. Never probe on reduced platforms.
pub(crate) fn legacy_pit_probe(legacy_pic: bool, fadt: Option<&[u8]>) -> bool {
    if !legacy_pic { return false; }
    let Some(table) = fadt else { return false; };
    table.len() >= 116 && table.get(..4) == Some(b"FACP") &&
        u32_at(table, 4) == Some(table.len() as u32) && checksum(table) &&
        u32_at(table, 112).map_or(false, |flags| flags & (1 << 20) == 0)
}

/// ACPI 6.6 FADT §5.2.9 and PM_TMR §4.8.3.3. Prefer a usable
/// extended address, otherwise the legacy I/O address. HW_REDUCED_ACPI
/// machines need not implement any of these registers.
pub(crate) fn fadt_pm_timer(table: &[u8], mut usable: impl FnMut(PmTimer) -> bool) -> Option<PmTimer> {
    if table.len() < 116 || table.get(..4)? != b"FACP" ||
       u32_at(table, 4)? as usize != table.len() || !checksum(table) { return None; }
    let flags = u32_at(table, 112)?;
    if flags & (1 << 20) != 0 || table[91] != 4 { return None; }
    let wide = flags & (1 << 8) != 0;
    if let Some(gas) = table.get(208..220) {
        // A declared 24-bit counter still occupies a 32-bit register.
        // Access size 0 is the legacy unspecified encoding.
        if gas[2] == 0 && matches!(gas[3], 0 | 3) &&
           (matches!(gas[1], 0 | 32) || gas[1] == 24 && !wide) {
            if let Some(timer) = PmTimer::from_address(gas[0], u64_at(gas, 4)?, wide) {
                if usable(timer) { return Some(timer); }
            }
        }
    }
    let timer = PmTimer::from_address(1, u32_at(table, 76)? as u64, wide)?;
    usable(timer).then_some(timer)
}

/// Only permit a UC device mapping if the containing page is not firmware
/// data, loader data/code or conventional RAM. A firmware MMIO aperture
/// need not appear in GetMemoryMap at all.
pub(crate) fn timer_mmio_page_ok(map: &[u8], stride: usize, address: usize) -> bool {
    if stride < 40 || map.len() % stride != 0 { return false; }
    let first = (address & !4095) as u64;
    for d in map.chunks_exact(stride) {
        let Some(kind) = u32_at(d, 0) else { return false; };
        let Some(start) = u64_at(d, 8) else { return false; };
        let Some(end) = u64_at(d, 24).and_then(|n| n.checked_mul(4096))
            .and_then(|n| start.checked_add(n)) else { return false; };
        if first < end && start < first + 4096 && !matches!(kind, 0 | 11) {
            return false;
        }
    }
    true
}

impl Platform {
    pub(crate) fn new() -> Self {
        Self { pci: PciWindows::new(), lapic: 0, pm_timer: None, hpet: 0, topology: CpuTopology::new(), legacy_pic: false, legacy_pit_probe: false, ps2_controller: true,
        io_apics: [IoApic { address: 0, gsi: 0 }; 8], io_count: 0,
        serial_irq: IsaInterrupt { gsi: 4, low: false, level: false }, serial_override: false,
        keyboard_irq: IsaInterrupt { gsi: 1, low: false, level: false }, keyboard_override: false }
    }

    pub fn pm_timer_mmio(&self) -> Option<usize> { self.pm_timer.and_then(PmTimer::mmio) }

    pub(crate) fn madt(&mut self, bytes: &[u8]) -> Option<()> {
        self.lapic = u32_at(bytes, 36)? as usize;
        self.legacy_pic = u32_at(bytes, 40)? & 1 != 0;
        let mut rest = bytes.get(44..)?;
        while !rest.is_empty() {
            let length = *rest.get(1)? as usize;
            if length < 2 { return None; }
            let e = rest.get(..length)?;
            match e[0] {
                0 => {
                    if e.len() != 8 { return None; }
                    self.topology.add(u32::from(e[3]), u32_at(e, 4)?, true)?;
                }
                1 => {
                    let address = u32_at(e, 4)? as usize;
                    let gsi = u32_at(e, 8)?;
                    if address == 0 || address % 4096 != 0 ||
                        self.io_apics[..self.io_count].iter().any(|io| io.address == address || io.gsi == gsi) { return None; }
                    *self.io_apics.get_mut(self.io_count)? = IoApic { address, gsi };
                    self.io_count += 1;
                }
                2 if e.get(2) == Some(&0) && (e.get(3) == Some(&4) || e.get(3) == Some(&1)) => {
                    let keyboard = e[3] == 1;
                    if if keyboard { self.keyboard_override } else { self.serial_override } { return None; }
                    let flags = u16::from_le_bytes(e.get(8..10)?.try_into().ok()?);
                    if flags & !15 != 0 || flags & 3 == 2 || (flags >> 2) & 3 == 2 { return None; }
                    let irq = IsaInterrupt { gsi: u32_at(e, 4)?, low: flags & 3 == 3,
                                             level: (flags >> 2) & 3 == 3 };
                    if keyboard { self.keyboard_irq = irq; self.keyboard_override = true; }
                    else { self.serial_irq = irq; self.serial_override = true; }
                }
                9 => {
                    if e.len() != 16 { return None; }
                    let flags = u32_at(e, 8)?;
                    if flags & 3 != 0 && e[2..4] != [0, 0] { return None; }
                    self.topology.add(u32_at(e, 4)?, flags, false)?;
                }
                5 => { self.lapic = u64_at(e, 4)? as usize; }
                _ => (),
            }
            rest = &rest[length..];
        }
        (!self.topology.enabled().ids().is_empty() && self.lapic != 0 && self.lapic % 4096 == 0).then_some(())
    }
}

pub unsafe fn discover(info: &BootInfo, map: &[u8]) -> Option<Platform> {
    let fw = Firmware { map, stride: info.descriptor_size as usize };
    let rsdp = fw.bytes(info.rsdp, 36)?;
    if &rsdp[..8] != b"RSD PTR " || rsdp[15] < 2 || !checksum(&rsdp[..20]) { return None; }
    let length = u32_at(rsdp, 20)? as usize;
    if length < 36 || !checksum(fw.bytes(info.rsdp, length)?) { return None; }
    let xsdt = u64_at(rsdp, 24)?;
    let (root, width) = if xsdt != 0 {
        (fw.table(xsdt)?, 8)
    } else {
        (fw.table(u32_at(rsdp, 16)? as u64)?, 4)
    };
    if &root[..4] != (if width == 8 { b"XSDT" } else { b"RSDT" }) ||
        (root.len()-36) % width != 0 { return None; }
    let mut p = Platform::new();
    let mut fadt_table = None;
    let mut hpet_seen = false;
    for entry in root[36..].chunks_exact(width) {
        let address = if width == 8 { u64_at(entry, 0)? } else { u32_at(entry, 0)? as u64 };
        match fw.bytes(address, 4)? {
            b"MCFG" => p.pci.parse(fw.table(address)?)?,
            b"APIC" => p.madt(fw.table(address)?)?,
            b"HPET" => {
                if hpet_seen { return None; }
                hpet_seen = true;
                // HPET is optional. An invalid table cannot authorize MMIO.
                p.hpet = fw.table(address).and_then(hpetAddress).unwrap_or(0);
            }
            b"FACP" => {
                if fadt_table.is_some() { return None; }
                let fadt = fw.table(address)?;
                p.ps2_controller = fadt_8042(fadt)?;
                fadt_table = Some(fadt);
            }
            _ => (),
        }
    }
    if p.hpet != 0 {
        let fb_start = info.framebuffer as usize;
        let fb_end = (info.stride as usize).checked_mul(info.height as usize)?
            .checked_mul(4)?.checked_add(fb_start)?;
        if !timer_mmio_page_ok(map, fw.stride, p.hpet) ||
           (p.hpet < fb_end && fb_start < p.hpet + 4096) ||
           p.hpet == p.lapic || p.io_apics[..p.io_count].iter().any(|io| io.address == p.hpet) ||
           p.pci.windows().iter().any(|w| {
               let (start, size) = w.mapping();
               (start..start+size).contains(&p.hpet)
           }) { p.hpet = 0; }
    }
    p.legacy_pit_probe = legacy_pit_probe(p.legacy_pic, fadt_table);
    if let Some(fadt) = fadt_table {
        p.pm_timer = fadt_pm_timer(fadt, |timer| {
            let Some(address) = timer.mmio() else { return true; };
            let page = address & !4095;
            let fb_start = info.framebuffer as usize;
            let Some(fb_end) = (info.stride as usize).checked_mul(info.height as usize)
                .and_then(|pixels| pixels.checked_mul(4)).and_then(|size| fb_start.checked_add(size))
                else { return false; };
            // The framebuffer is also MMIO, often absent from the firmware
            // map. Never remap any of its pages read-only as a timer.
            !(page < fb_end && fb_start < page + 4096) &&
                timer_mmio_page_ok(map, fw.stride, address) &&
                page != p.lapic && page != p.hpet &&
                !p.io_apics[..p.io_count].iter().any(|io| io.address == page) &&
                !p.pci.windows().iter().any(|w| {
                    let (start, size) = w.mapping();
                    (start..start+size).contains(&page)
                })
        });
    }
    (p.lapic != 0).then_some(p)
}

#[cfg(test)]
#[allow(non_snake_case)]
mod tests {
    use super::*;

    fn fixChecksum(aBytes: &mut [u8]) {
        aBytes[9] = 0;
        aBytes[9] = 0u8.wrapping_sub(aBytes.iter().fold(0u8, |pSum, pByte| pSum.wrapping_add(*pByte)));
    }

    fn hpetTable() -> Vec<u8> {
        let mut pBytes = vec![0u8; 56];
        pBytes[..4].copy_from_slice(b"HPET");
        pBytes[4..8].copy_from_slice(&56u32.to_le_bytes());
        pBytes[8] = 1;
        pBytes[36..40].copy_from_slice(&0x8086_a201u32.to_le_bytes());
        pBytes[44..52].copy_from_slice(&0xfed0_0000u64.to_le_bytes());
        fixChecksum(&mut pBytes);
        pBytes
    }

    #[test]
    fn acceptsSystemMemoryWithDeclaredOrUnspecifiedRegisterWidth() {
        let mut pBytes = hpetTable();
        assert_eq!(hpetAddress(&pBytes), Some(0xfed0_0000));
        pBytes[41] = 32;
        pBytes[43] = 3;
        fixChecksum(&mut pBytes);
        assert_eq!(hpetAddress(&pBytes), Some(0xfed0_0000));
        pBytes[41] = 64;
        pBytes[43] = 4;
        fixChecksum(&mut pBytes);
        assert_eq!(hpetAddress(&pBytes), Some(0xfed0_0000));
    }

    #[test]
    fn rejectsMalformedHeaderChecksumAndGasBeforeMapping() {
        let pValid = hpetTable();
        for pLength in 0..56 { assert_eq!(hpetAddress(&pValid[..pLength]), None); }
        for (pOffset, pValue) in [(0, b'X'), (4, 55), (9, pValid[9].wrapping_add(1)),
            (40, 1), (41, 16), (42, 1), (43, 2)] {
            let mut pBytes = pValid.clone();
            pBytes[pOffset] = pValue;
            if pOffset != 9 { fixChecksum(&mut pBytes); }
            assert_eq!(hpetAddress(&pBytes), None);
        }
    }

    #[test]
    fn rejectsZeroUnalignedAndUserRegionAddresses() {
        for pAddress in [0u64, 0xfed0_0008, 1 << 39, 1 << 47, u64::MAX] {
            let mut pBytes = hpetTable();
            pBytes[44..52].copy_from_slice(&pAddress.to_le_bytes());
            fixChecksum(&mut pBytes);
            assert_eq!(hpetAddress(&pBytes), None);
        }
    }
}
