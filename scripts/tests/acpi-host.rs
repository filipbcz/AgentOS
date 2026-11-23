//! Compile the actual ACPI parser and its HPET table validation on the host.
//! No firmware address is dereferenced by these pure table-decoding tests.
#![allow(dead_code, non_snake_case)]

pub struct BootInfo { pub rsdp: u64, pub descriptor_size: u64 }

#[path = "../../kernel/acpi.rs"]
mod acpi;
