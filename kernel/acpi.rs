use crate::BootInfo;
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
    pub timer_port: u16,
    pub hpet: usize,
    pub ids: [u8; 255],
    pub count: usize,
    pub legacy_pic: bool,
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
       aBytes[40] != 0 || !matches!(aBytes[41], 0 | 64) ||
       aBytes[42] != 0 || !matches!(aBytes[43], 0 | 4) { return None; }
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

impl Platform {
    fn madt(&mut self, bytes: &[u8]) -> Option<()> {
        self.lapic = u32_at(bytes, 36)? as usize;
        self.legacy_pic = u32_at(bytes, 40)? & 1 != 0;
        let mut rest = bytes.get(44..)?;
        while !rest.is_empty() {
            let length = *rest.get(1)? as usize;
            if length < 2 { return None; }
            let e = rest.get(..length)?;
            let id = match e[0] {
                0 if u32_at(e, 4)? & 1 != 0 => Some(e[3] as u32),
                1 => {
                    let address = u32_at(e, 4)? as usize;
                    let gsi = u32_at(e, 8)?;
                    if address == 0 || address % 4096 != 0 ||
                        self.io_apics[..self.io_count].iter().any(|io| io.address == address || io.gsi == gsi) { return None; }
                    *self.io_apics.get_mut(self.io_count)? = IoApic { address, gsi };
                    self.io_count += 1;
                    None
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
                    None
                }
                9 if u32_at(e, 8)? & 1 != 0 => Some(u32_at(e, 4)?),
                5 => { self.lapic = u64_at(e, 4)? as usize; None }
                _ => None,
            };
            if let Some(id) = id {
                if id >= 255 || self.ids[..self.count].contains(&(id as u8)) { return None; }
                *self.ids.get_mut(self.count)? = id as u8;
                self.count += 1;
            }
            rest = &rest[length..];
        }
        (self.count > 0 && self.lapic != 0 && self.lapic % 4096 == 0).then_some(())
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
    let mut p = Platform { pci: PciWindows::new(), lapic: 0, timer_port: 0, hpet: 0, ids: [0; 255], count: 0, legacy_pic: false, ps2_controller: true,
        io_apics: [IoApic { address: 0, gsi: 0 }; 8], io_count: 0,
        serial_irq: IsaInterrupt { gsi: 4, low: false, level: false }, serial_override: false,
        keyboard_irq: IsaInterrupt { gsi: 1, low: false, level: false }, keyboard_override: false };
    for entry in root[36..].chunks_exact(width) {
        let address = if width == 8 { u64_at(entry, 0)? } else { u32_at(entry, 0)? as u64 };
        match fw.bytes(address, 4)? {
            b"MCFG" => p.pci.parse(fw.table(address)?)?,
            b"APIC" => p.madt(fw.table(address)?)?,
            b"HPET" => {
                if p.hpet != 0 { return None; }
                p.hpet = hpetAddress(fw.table(address)?)?;
            }
            b"FACP" => {
                let fadt = fw.table(address)?;
                p.ps2_controller = fadt_8042(fadt)?;
                let extended = u64_at(fadt, 212).unwrap_or(0);
                let port = if extended != 0 {
                    if fadt[208] != 1 || fadt[210] != 0 { return None; }
                    extended
                } else { u32_at(fadt, 76)? as u64 };
                p.timer_port = u16::try_from(port).ok()?;
            }
            _ => (),
        }
    }
    if p.hpet != 0 && (p.hpet == p.lapic ||
       p.io_apics[..p.io_count].iter().any(|pIo| pIo.address == p.hpet)) { return None; }
    (p.lapic != 0 && p.timer_port != 0).then_some(p)
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
            (40, 1), (41, 32), (42, 1), (43, 3)] {
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
