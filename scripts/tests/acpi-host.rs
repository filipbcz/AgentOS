//! Compile the actual ACPI parser and its HPET table validation on the host.
//! No firmware address is dereferenced by these pure table-decoding tests.
#![allow(dead_code, non_snake_case)]

pub struct BootInfo { pub rsdp: u64, pub descriptor_size: u64 }

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
