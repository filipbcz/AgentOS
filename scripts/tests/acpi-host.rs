//! Compile the actual ACPI parser and its HPET table validation on the host.
//! No firmware address is dereferenced by these pure table-decoding tests.
#![allow(dead_code, non_snake_case)]

pub struct BootInfo {
    pub rsdp: u64, pub descriptor_size: u64, pub framebuffer: *mut u32,
    pub stride: u32, pub height: u32,
}

#[path = "../../kernel/reference_clock.rs"]
mod reference_clock;

#[path = "../../kernel/acpi.rs"]
mod acpi;


fn fadt(revision: u8, length: usize, flags: u16) -> Vec<u8> {
    let mut table=vec![0u8;length];
    table[..4].copy_from_slice(b"FACP");
    table[4..8].copy_from_slice(&(length as u32).to_le_bytes());
    table[8]=revision;
    if length>=111 { table[109..111].copy_from_slice(&flags.to_le_bytes()); }
    table[9]=0u8.wrapping_sub(table.iter().fold(0u8,|sum,b|sum.wrapping_add(*b)));
    table
}
#[test]
fn fadtControlsLegacy8042Discovery() {
    assert_eq!(acpi::fadt_8042(&fadt(1,116,0)),Some(true));
    for revision in [3,4,5,6] {
        for flags in [0,1,2,3,4,0x100,0x102] {
            assert_eq!(acpi::fadt_8042(&fadt(revision,244,flags)),Some(flags&2!=0));
        }
        assert_eq!(acpi::fadt_8042(&fadt(revision,110,0)),None);
    }
    let mut invalid=fadt(6,244,2);
    invalid[109]^=1;
    assert_eq!(acpi::fadt_8042(&invalid),None);
}

use reference_clock::{PmAccess, PmTimer};

fn pm_fadt(length: usize, flags: u32, legacy: u32, extended: Option<(u8,u8,u8,u8,u64)>) -> Vec<u8> {
    let mut table = fadt(if length == 116 { 1 } else { 6 }, length, 0);
    table[76..80].copy_from_slice(&legacy.to_le_bytes());
    table[91] = 4;
    table[112..116].copy_from_slice(&flags.to_le_bytes());
    if let Some((space,width,offset,access,address)) = extended {
        table[208..212].copy_from_slice(&[space,width,offset,access]);
        table[212..220].copy_from_slice(&address.to_le_bytes());
    }
    fix_pm_checksum(&mut table);
    table
}

fn fix_pm_checksum(table: &mut [u8]) {
    table[9] = 0;
    table[9] = 0u8.wrapping_sub(table.iter().fold(0u8, |sum,b| sum.wrapping_add(*b)));
}

#[test]
fn acpi_pm_timer_width_transport_and_extended_precedence() {
    for wide in [false,true] {
        let flags = if wide { 1 << 8 } else { 0 };
        let legacy = pm_fadt(116, flags, 0x408, None);
        assert_eq!(acpi::fadt_pm_timer(&legacy, |_| true),
                   Some(PmTimer { access: PmAccess::Io(0x408), wide }));
        let extended_io = pm_fadt(244, flags, 0x408, Some((1,32,0,3,0x804)));
        assert_eq!(acpi::fadt_pm_timer(&extended_io, |_| true),
                   Some(PmTimer { access: PmAccess::Io(0x804), wide }));
        let extended_mmio = pm_fadt(244, flags, 0x408, Some((0,32,0,3,0xfed8_0010)));
        assert_eq!(acpi::fadt_pm_timer(&extended_mmio, |_| true),
                   Some(PmTimer { access: PmAccess::Memory(0xfed8_0010), wide }));
        // Mapping policy may reject an otherwise valid extended address.
        assert_eq!(acpi::fadt_pm_timer(&extended_mmio, |t| t.mmio().is_none()),
                   Some(PmTimer { access: PmAccess::Io(0x408), wide }));
    }
}

#[test]
fn acpi_pm_timer_optional_reduced_and_malformed_metadata() {
    let absent = pm_fadt(244, 0, 0, None);
    assert_eq!(acpi::fadt_pm_timer(&absent, |_| true), None);
    let reduced = pm_fadt(244, 1<<20, 0x408, Some((1,32,0,3,0x804)));
    assert_eq!(acpi::fadt_pm_timer(&reduced, |_| true), None);
    for gas in [(2,32,0,3,0x408), (1,16,0,3,0x408), (1,32,1,3,0x408),
                (1,32,0,2,0x408), (1,32,0,3,0xfffe), (0,32,0,3,0xfed8_0002),
                (0,32,0,3,1u64<<39), (0,32,0,3,0)] {
        let table = pm_fadt(244, 0, 0, Some(gas));
        assert_eq!(acpi::fadt_pm_timer(&table, |_| true), None);
    }
    let mut table = pm_fadt(244, 0, 0x408, None);
    table[91] = 2;
    fix_pm_checksum(&mut table);
    assert_eq!(acpi::fadt_pm_timer(&table, |_| true), None);
    table[91] = 4; // checksum is now wrong
    assert_eq!(acpi::fadt_pm_timer(&table, |_| true), None);
    for length in 0..116 {
        assert_eq!(acpi::fadt_pm_timer(&table[..length], |_| true), None);
    }
}

#[test]
fn pm_mmio_mapping_refuses_conflicting_firmware_pages() {
    let mut descriptor = [0u8;48];
    let address = 0xfed8_0010usize;
    descriptor[8..16].copy_from_slice(&((address & !4095) as u64).to_le_bytes());
    descriptor[24..32].copy_from_slice(&1u64.to_le_bytes());
    for kind in [0u32,11] {
        descriptor[..4].copy_from_slice(&kind.to_le_bytes());
        assert!(acpi::timer_mmio_page_ok(&descriptor,48,address));
    }
    for kind in [1u32,2,3,4,5,6,7,8,9,10,12,13,14] {
        descriptor[..4].copy_from_slice(&kind.to_le_bytes());
        assert!(!acpi::timer_mmio_page_ok(&descriptor,48,address));
    }
    assert!(acpi::timer_mmio_page_ok(&descriptor,48,address+4096));
    assert!(!acpi::timer_mmio_page_ok(&descriptor[..47],48,address));
    descriptor[24..32].copy_from_slice(&u64::MAX.to_le_bytes());
    assert!(!acpi::timer_mmio_page_ok(&descriptor,48,address));
}
