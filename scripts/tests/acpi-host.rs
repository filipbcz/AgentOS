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
#[path = "../../kernel/cpu_topology.rs"]
mod cpu_topology;
#[path = "../../kernel/ioapic.rs"]
mod ioapic;


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


#[test]
fn legacy_pit_probe_requires_legacy_pic_and_valid_nonreduced_acpi() {
    let normal=pm_fadt(244,0,0,None);
    assert!(acpi::legacy_pit_probe(true,Some(&normal)));
    assert!(!acpi::legacy_pit_probe(false,Some(&normal)));
    assert!(!acpi::legacy_pit_probe(true,None));
    // A user-visible ISA/LPC device declaration is not a PIT declaration.
    let legacy_devices=fadt(6,244,1);
    assert!(!acpi::legacy_pit_probe(false,Some(&legacy_devices)));
    let reduced=pm_fadt(244,1<<20,0,None);
    assert!(!acpi::legacy_pit_probe(true,Some(&reduced)));
    let mut malformed=normal.clone();
    malformed[112]^=1;
    assert!(!acpi::legacy_pit_probe(true,Some(&malformed)));
    for size in 0..116 {
        assert!(!acpi::legacy_pit_probe(true,Some(&normal[..size])));
    }
    assert!(acpi::legacy_pit_probe(true,Some(&pm_fadt(116,0,0,None))));
}

// Actual MADT record parser, including ACPI type 0 and type 9. No
// hardware MMIO is executed: invalid destinations are rejected first.
fn lapic_record(id: u8, flags: u32) -> Vec<u8> {
    let mut entry=vec![0,8,0,id];
    entry.extend_from_slice(&flags.to_le_bytes());
    entry
}
fn x2apic_record(id: u32, flags: u32) -> Vec<u8> {
    let mut entry=vec![9,16,0,0];
    entry.extend_from_slice(&id.to_le_bytes());
    entry.extend_from_slice(&flags.to_le_bytes());
    entry.extend_from_slice(&id.to_le_bytes());
    entry
}
fn parse_madt(records: &[Vec<u8>]) -> Option<acpi::Platform> {
    let mut table=vec![0u8;44];
    table[..4].copy_from_slice(b"APIC");
    table[8]=5;
    table[36..40].copy_from_slice(&0xfee0_0000u32.to_le_bytes());
    table[40..44].copy_from_slice(&1u32.to_le_bytes());
    for entry in records { table.extend_from_slice(entry); }
    let len=table.len() as u32;
    table[4..8].copy_from_slice(&len.to_le_bytes());
    fix_pm_checksum(&mut table);
    let mut platform=acpi::Platform::new();
    platform.madt(&table)?;
    Some(platform)
}

#[test]
fn madt_full_ids_dense_slots_and_firmware_order() {
    let high=0xffff_fffe;
    let platform=parse_madt(&[x2apic_record(256,1),lapic_record(201,1),
        x2apic_record(high,1),lapic_record(0,1),x2apic_record(255,1),
        x2apic_record(0x8000_0000,2)]).unwrap();
    let enabled=platform.topology.enabled();
    assert_eq!(enabled.ids(), &[0,201,255,256,high]);
    assert_eq!(enabled.firmware_order().collect::<Vec<_>>(), vec![256,201,high,0,255]);
    for (index,&id) in enabled.ids().iter().enumerate() {
        let slot=enabled.slot(id).unwrap();
        assert_eq!(slot.index(),index);
        assert_eq!(enabled.id_at(slot),Some(id));
    }
    assert_eq!(platform.topology.online_capable().ids(), &[0x8000_0000]);
    assert!(enabled.slot(0x8000_0000).is_none());
    assert!(enabled.slot(1).is_none());
    assert_eq!(enabled.validate_legacy(0),Err(b"APIC ID requires x2APIC transport" as &[u8]));
    for id in [255,256,high] {
        assert_eq!(enabled.legacy_target(id),Err(b"APIC ID requires x2APIC transport" as &[u8]));
    }
    for id in [1,0x8000_0000,u32::MAX] {
        assert_eq!(enabled.legacy_target(id),Err(b"APIC target absent or disabled" as &[u8]));
    }
}

#[test]
fn madt_boot_bsp_and_physical_destination_checks_precede_irq_mmio() {
    let platform=parse_madt(&[lapic_record(201,1),x2apic_record(7,1),
        lapic_record(254,1),lapic_record(8,2)]).unwrap();
    let roster=platform.topology.enabled();
    assert_eq!(roster.validate_legacy(201).unwrap().index(),1);
    assert!(roster.validate_legacy(8).is_err());
    assert!(roster.validate_legacy(0).is_err());
    assert!(roster.validate_legacy(256).is_err());
    for id in [7,201,254] {
        let target=roster.legacy_target(id).unwrap();
        assert_eq!(u32::from(target.id()),id);
        assert_eq!(target.high(),id<<24);
        assert_eq!(target.msi_address(),0xfee0_0000 | id<<12);
    }
    // Empty IOAPIC list is sufficient to test the real route entry point:
    // unknown/disabled targets fail before inspecting MMIO or GSI.
    for id in [8,0,255,256] {
        assert_eq!(unsafe { ioapic::Route::serial(&platform,id,0xe1) }.err(),
                   Some(b"APIC target absent or disabled" as &[u8]));
        assert_eq!(unsafe { ioapic::Route::keyboard(&platform,id,0xe2) }.err(),
                   Some(b"APIC target absent or disabled" as &[u8]));
    }
    assert_eq!(unsafe { ioapic::Route::serial(&platform,201,0xe1) }.err(),
               Some(b"ISA GSI has no IOAPIC" as &[u8]));
    let wide_only=parse_madt(&[x2apic_record(256,1)]).unwrap();
    assert_eq!(wide_only.topology.enabled().validate_legacy(0),
               Err(b"APIC ID requires x2APIC transport" as &[u8]));
    let wide=parse_madt(&[lapic_record(0,1),x2apic_record(256,1)]).unwrap();
    assert_eq!(unsafe { ioapic::Route::keyboard(&wide,256,0xe2) }.err(),
               Some(b"APIC ID requires x2APIC transport" as &[u8]));
}

#[test]
fn madt_enabled_online_capable_duplicates_and_reserved_ids() {
    // Neither flag: ignore contents, including broadcast placeholder IDs
    // and duplicates of an enabled record. Online Capable alone is offline.
    let platform=parse_madt(&[lapic_record(0,1),lapic_record(255,0),
        x2apic_record(u32::MAX,0),x2apic_record(0,0),x2apic_record(256,2)]).unwrap();
    assert_eq!(platform.topology.enabled().ids(), &[0]);
    assert_eq!(platform.topology.online_capable().ids(), &[256]);
    assert!(platform.topology.enabled().validate_legacy(0).is_ok());
    for entries in [
        vec![lapic_record(0,1),x2apic_record(0,1)],
        vec![lapic_record(0,1),x2apic_record(256,1),x2apic_record(256,1)],
        vec![lapic_record(0,1),x2apic_record(256,2),x2apic_record(256,1)],
        vec![lapic_record(0,1),x2apic_record(256,2),x2apic_record(256,2)],
        vec![lapic_record(0,1),lapic_record(255,1)],
        vec![lapic_record(0,1),lapic_record(255,2)],
        vec![lapic_record(0,1),x2apic_record(u32::MAX,1)],
        vec![lapic_record(0,1),x2apic_record(u32::MAX,2)],
        vec![lapic_record(0,1),x2apic_record(256,3)],
        vec![lapic_record(0,1),x2apic_record(256,5)],
        vec![lapic_record(0,1),x2apic_record(256,6)],
        vec![x2apic_record(256,2)],
    ] {
        assert!(parse_madt(&entries).is_none(),"accepted malformed roster");
    }
    let mut malformed=x2apic_record(256,1);
    malformed[2]=1;
    assert!(parse_madt(&[lapic_record(0,1),malformed]).is_none());
    let mut truncated=x2apic_record(256,1);
    truncated.pop();
    assert!(parse_madt(&[lapic_record(0,1),truncated]).is_none());
    let mut short=lapic_record(1,1);
    short[1]=7;short.pop();
    assert!(parse_madt(&[lapic_record(0,1),short]).is_none());
}

#[test]
fn madt_cpu_capacity_is_a_count_not_the_largest_id() {
    let mut entries=(0..cpu_topology::MAX_CPUS as u32).rev()
        .map(|i| x2apic_record(0xf000_0000+i*256,1)).collect::<Vec<_>>();
    let platform=parse_madt(&entries).unwrap();
    let enabled=platform.topology.enabled();
    assert_eq!(enabled.ids().len(),cpu_topology::MAX_CPUS);
    assert_eq!(enabled.slot(0xf000_0000).unwrap().index(),0);
    assert_eq!(enabled.slot(0xf000_0000+(cpu_topology::MAX_CPUS as u32-1)*256).unwrap().index(),
               cpu_topology::MAX_CPUS-1);
    assert_eq!(enabled.firmware_order().next(),Some(0xf000_0000+(cpu_topology::MAX_CPUS as u32-1)*256));
    entries.push(x2apic_record(0,1));
    assert!(parse_madt(&entries).is_none());
}
