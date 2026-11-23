//! One fixed physical IRQ route, configured on the BSP with IF=0.
//! Register layout: Intel 82093AA, 290566-001, sections 3.1/3.2.
#![allow(non_snake_case)]
use crate::acpi::{Platform, IsaInterrupt};
use core::ptr;

const MASK: u32 = 1 << 16;
pub struct Route { fBase: usize, fRegister: u32, fLow: u32 }

unsafe fn read(aBase: usize, aRegister: u32) -> u32 {
    ptr::write_volatile(aBase as *mut u32, aRegister);
    ptr::read_volatile((aBase + 0x10) as *const u32)
}

unsafe fn write(aBase: usize, aRegister: u32, aValue: u32) {
    ptr::write_volatile(aBase as *mut u32, aRegister);
    ptr::write_volatile((aBase + 0x10) as *mut u32, aValue);
}

impl Route {
    pub unsafe fn serial(aPlatform: &Platform, aDestination: u8, aVector: u32) -> Result<Self, &'static [u8]> {
        Self::irq(aPlatform, aPlatform.serial_irq, aDestination, aVector)
    }

    pub unsafe fn keyboard(aPlatform: &Platform, aDestination: u8, aVector: u32) -> Result<Self, &'static [u8]> {
        Self::irq(aPlatform, aPlatform.keyboard_irq, aDestination, aVector)
    }

    unsafe fn irq(aPlatform: &Platform, aIrq: IsaInterrupt, aDestination: u8, aVector: u32) -> Result<Self, &'static [u8]> {
        let mut pRoute = None;
        for pIo in &aPlatform.io_apics[..aPlatform.io_count] {
            let pVersion = read(pIo.address, 1);
            let pLast = (pVersion >> 16) & 255;
            if pVersion == 0 || pVersion == u32::MAX || pLast > 119 { return Err(b"IOAPIC version or register range"); }
            let Some(pPin) = aIrq.gsi.checked_sub(pIo.gsi) else { continue; };
            if pPin > pLast { continue; }
            if pRoute.is_some() { return Err(b"overlapping IOAPIC GSI ranges"); }
            let pLow = aVector | (if aIrq.low { 1 << 13 } else { 0 })
                               | (if aIrq.level { 1 << 15 } else { 0 });
            pRoute = Some(Self { fBase: pIo.address, fRegister: 0x10 + 2 * pPin, fLow: pLow });
        }
        let pRoute = pRoute.ok_or(b"ISA GSI has no IOAPIC" as &'static [u8])?;
        // Mask the old route before changing its destination, then leave it
        // masked until the UART, IDT, TTY and owning process are ready.
        write(pRoute.fBase, pRoute.fRegister, read(pRoute.fBase, pRoute.fRegister) | MASK);
        write(pRoute.fBase, pRoute.fRegister + 1, (aDestination as u32) << 24);
        write(pRoute.fBase, pRoute.fRegister, pRoute.fLow | MASK);
        if read(pRoute.fBase, pRoute.fRegister) & 0x1afff != (pRoute.fLow | MASK) ||
            read(pRoute.fBase, pRoute.fRegister + 1) >> 24 != aDestination as u32 { return Err(b"IOAPIC route readback"); }
        Ok(pRoute)
    }

    pub unsafe fn enable(&self) { write(self.fBase, self.fRegister, self.fLow); }
    pub unsafe fn disable(&self) { write(self.fBase, self.fRegister, self.fLow | MASK); }
}
