use super::*;
use crate::block::{BlockDevice, Geometry};

// Private, device-addressable staging lets callers use ordinary virtual slices.
// The exclusive device borrow serializes commands. Both frames remain owned even
// on timeout, until close proves the controller can no longer access them.
pub struct AhciDisk {
    hba: Controller,
    control: Frame,
    control_bus: BusAddress,
    data: Frame,
    data_bus: BusAddress,
    geometry: Geometry,
    failed: bool,
}

impl AhciDisk {
    pub unsafe fn open(hba: Controller, root: usize, frames: &mut Frames<'_>) -> Result<Self, Error> {
        let mask = hba.prepare(root, frames)?;
        if (read(hba.abar) >> 8) & 31 == 0 { return Err(b"AHCI needs two command slots"); }
        let control = frames.alloc_zeroed().ok_or(b"AHCI command frame" as Error)?;
        let Some(data) = frames.alloc_zeroed() else { frames.release(control); return Err(b"AHCI data frame"); };
        let (Some(control_bus), Some(data_bus)) = (BusAddress::of(&control, mask), BusAddress::of(&data, mask)) else {
            frames.release(data); frames.release(control); return Err(b"AHCI DMA address mask");
        };
        let mut disk = Self { hba, control, control_bus, data, data_bus,
                              geometry: Geometry { blocks: 0, block_size: 512 }, failed: false };
        if let Err(err) = disk.hba.start(control_bus).and_then(|()| disk.identify()) {
            disk.close(frames)?;
            return Err(err);
        }
        Ok(disk)
    }

    unsafe fn identify(&mut self) -> Result<(), Error> {
        self.issue(0xec, 0, 512, 0)?;
        let words = self.data.address() as *const u16;
        let word = |n: usize| ptr::read_volatile(words.add(n));
        if word(83) & 0xe400 != 0x6400 { return Err(b"ATA device lacks LBA48 or FLUSH CACHE EXT"); }
        let blocks = (0..4).fold(0u64, |v, i| v | (u64::from(word(100 + i)) << (16*i)));
        let size = if word(106) & 0xd000 == 0x5000 {
            (usize::from(word(117)) | (usize::from(word(118)) << 16)) * 2
        } else { 512 };
        if blocks == 0 || blocks > 1 << 48 || !(512..=PAGE).contains(&size) || !size.is_power_of_two() {
            return Err(b"unsupported ATA geometry");
        }
        self.geometry = Geometry { blocks, block_size: size };
        Ok(())
    }

    unsafe fn issue(&mut self, opcode: u8, lba: u64, bytes: usize, sectors: u16) -> Result<(), Error> {
        if self.failed { return Err(b"AHCI device offline"); }
        self.failed = true;
        let p = self.hba.port();
        if read(p + CI) != 0 || read(p + SACT) != 0 { return Err(b"AHCI port busy"); }
        command(&self.control, self.control_bus, 0, opcode, lba, sectors, opcode == 0x35, &[(self.data_bus, bytes)]);
        write(p + IS, u32::MAX);
        fence(Ordering::Release);
        write(p + CI, 1);
        wait(|| read(p + CI) == 0 || read(p + IS) & 0x7d00_0000 != 0, 8000, b"AHCI block timeout")?;
        fence(Ordering::Acquire);
        let status = read(p + IS);
        let fis = read(self.control.address() + 1024 + 0x40);
        if read(p + CI) != 0 || status & 1 == 0 || status & 0x7d00_0000 != 0 || read(p + TFD) & 0xa9 != 0 ||
            fis as u8 != 0x34 || (fis >> 16) & 0xa9 != 0 || read(self.control.address() + 4) != bytes as u32 {
            return Err(b"AHCI block command or transfer length");
        }
        self.failed = false;
        Ok(())
    }

    pub fn close(self, frames: &mut Frames<'_>) -> Result<(), Error> {
        unsafe {
            if self.failed {
                self.hba.drain_read(&self.control, self.control_bus)?;
            } else {
                self.hba.stop()?;
                self.hba.bus_master(false)?;
            }
            address(self.hba.port() + CLB, 0);
            address(self.hba.port() + FB, 0);
        }
        frames.release(self.data);
        frames.release(self.control);
        Ok(())
    }
}

impl BlockDevice for AhciDisk {
    fn geometry(&self) -> Geometry { self.geometry }

    fn read_blocks(&mut self, mut lba: u64, dst: &mut [u8]) -> Result<(), Error> {
        self.geometry.check(lba, dst.len())?;
        for chunk in dst.chunks_mut(PAGE) {
            let sectors = (chunk.len() / self.geometry.block_size) as u16;
            unsafe {
                self.issue(0x25, lba, chunk.len(), sectors)?;
                ptr::copy_nonoverlapping(self.data.address() as *const u8, chunk.as_mut_ptr(), chunk.len());
            }
            lba += u64::from(sectors);
        }
        Ok(())
    }

    fn write_blocks(&mut self, mut lba: u64, src: &[u8]) -> Result<(), Error> {
        self.geometry.check(lba, src.len())?;
        if self.failed { return Err(b"AHCI device offline"); }
        for chunk in src.chunks(PAGE) {
            let sectors = (chunk.len() / self.geometry.block_size) as u16;
            unsafe {
                ptr::copy_nonoverlapping(chunk.as_ptr(), self.data.address() as *mut u8, chunk.len());
                self.issue(0x35, lba, chunk.len(), sectors)?;
            }
            lba += u64::from(sectors);
        }
        Ok(())
    }

    fn flush(&mut self) -> Result<(), Error> {
        if self.failed { return Err(b"AHCI device offline"); }
        self.failed = true;
        unsafe { self.hba.flush_cache(&self.control, self.control_bus)?; }
        self.failed = false;
        Ok(())
    }
}
