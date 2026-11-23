//! Synchronous logical-block I/O. A successful write transfers the buffer to the
//! device. Flush completes all preceding writes. Multi-command failures may have
//! transferred a prefix; the driver never silently retries an uncertain write.
pub type Error = &'static [u8];

#[derive(Clone, Copy)]
pub struct Geometry {
    pub blocks: u64,
    pub block_size: usize,
}

impl Geometry {
    pub fn check(self, lba: u64, bytes: usize) -> Result<(), Error> {
        if bytes == 0 || bytes % self.block_size != 0 { return Err(b"unaligned or empty block request"); }
        let count = (bytes / self.block_size) as u64;
        if lba.checked_add(count).map_or(true, |end| end > self.blocks) { return Err(b"block range"); }
        Ok(())
    }
}

pub trait BlockDevice {
    fn geometry(&self) -> Geometry;
    fn read_blocks(&mut self, lba: u64, dst: &mut [u8]) -> Result<(), Error>;
    fn write_blocks(&mut self, lba: u64, src: &[u8]) -> Result<(), Error>;
    fn flush(&mut self) -> Result<(), Error>;
}
