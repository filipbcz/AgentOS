//! Exclusive early-boot NVMe block device. Polled queues, one command in
//! flight, owned coherent DMA pages. Only an explicit test build activates it.
mod protocol;
use crate::{block::{BlockDevice, Error, Geometry}, dma::BusAddress, frames::{Frame, Frames},
            hpet, paging, pci::Console};
use core::{fmt::Write, ptr, sync::atomic::{fence, Ordering}};
use protocol::{Capabilities, QueueState, PAGE};

pub struct Controller { pub cfg: usize, pub bar: usize, pub wide: bool, pub msi: u8, pub msix: u8 }
const CC: usize = 0x14;
const CSTS: usize = 0x1c;
const AQA: usize = 0x24;
const ASQ: usize = 0x28;
const ACQ: usize = 0x30;
const INTMS: usize = 0x0c;

unsafe fn read(addr: usize) -> u32 { ptr::read_volatile(addr as *const u32) }
unsafe fn write(addr: usize, value: u32) { ptr::write_volatile(addr as *mut u32, value); }
unsafe fn read16(addr: usize) -> u16 { ptr::read_volatile(addr as *const u16) }
unsafe fn write16(addr: usize, value: u16) { ptr::write_volatile(addr as *mut u16, value); }
unsafe fn address(reg: usize, bus: u64) {
    write(reg, bus as u32); write(reg + 4, (bus >> 32) as u32);
}
fn now() -> Result<u64, Error> { hpet::millis().ok_or(b"NVMe clock unavailable") }
fn wait(mut ready: impl FnMut() -> Result<bool, Error>, ms: u64, reason: Error) -> Result<(), Error> {
    let start = now()?;
    for _ in 0..50_000_000 {
        if ready()? { return Ok(()); }
        if now()?.saturating_sub(start) >= ms { break; }
        core::hint::spin_loop();
    }
    Err(reason)
}
impl Controller {
    unsafe fn bus_master(&self, enable: bool) -> Result<(), Error> {
        let reg = self.cfg + 4;
        let next = ((read16(reg) | 2 | (1 << 10)) & !5) | if enable { 4 } else { 0 };
        write16(reg, next);
        if read16(reg) & (6 | (1 << 10)) != next & (6 | (1 << 10)) {
            return Err(b"NVMe PCI command readback");
        }
        Ok(())
    }
    // Size only the selected controller with memory and bus mastering off,
    // never change BARs while doing general read-only PCI inventory.
    unsafe fn prepare(&mut self, root: usize, frames: &mut Frames<'_>) -> Result<Capabilities, Error> {
        paging::claim_config(root, self.cfg).ok_or(b"NVMe ECAM mapping" as Error)?;
        let cmd = self.cfg + 4;
        write16(cmd, (read16(cmd) | (1 << 10)) & !7);
        if read16(cmd) & 7 != 0 { return Err(b"NVMe PCI decoding still active"); }
        if self.msi != 0 {
            let reg = self.cfg + usize::from(self.msi) + 2;
            write16(reg, read16(reg) & !1);
            if read16(reg) & 1 != 0 { return Err(b"NVMe MSI still enabled"); }
        }
        if self.msix != 0 {
            let reg = self.cfg + usize::from(self.msix) + 2;
            write16(reg, read16(reg) & !(1 << 15));
            if read16(reg) & (1 << 15) != 0 { return Err(b"NVMe MSI-X still enabled"); }
        }
        let reg = self.cfg + 0x10;
        let low = read(reg);
        let high = if self.wide { read(reg + 4) } else { 0 };
        write(reg, u32::MAX);
        if self.wide { write(reg + 4, u32::MAX); }
        let mask_low = read(reg) & !15;
        let mask_high = if self.wide { read(reg + 4) } else { u32::MAX };
        if self.wide { write(reg + 4, high); }
        write(reg, low);
        if read(reg) != low || (self.wide && read(reg + 4) != high) { return Err(b"NVMe BAR restore failed"); }
        let mask = (u64::from(mask_high) << 32) | u64::from(mask_low);
        let size = (!mask).wrapping_add(1);
        if size < 8192 || !size.is_power_of_two() || self.bar == 0 ||
            self.bar as u64 & (size - 1) != 0 || self.bar.checked_add(8192).is_none() {
            return Err(b"unsupported NVMe BAR aperture");
        }
        // BAR0 is a physical bus resource, not necessarily a usable CPU VA.
        // Preserve the firmware assignment and map a supervisor-only window.
        let physical = self.bar;
        self.bar = paging::map_device_window(root, frames, physical, 2)
            .ok_or(b"NVMe register/doorbell mapping" as Error)?;
        let _ = writeln!(Console, "AGENTOS MMIO NVME PA={physical:016x} VA={:016x} PAGES=2\r", self.bar);
        self.bus_master(false)?;
        let cap = u64::from(read(self.bar)) | (u64::from(read(self.bar + 4)) << 32);
        let caps = Capabilities::parse(cap, size)?;
        self.disable(caps.timeout_ms)?;
        Ok(caps)
    }
    unsafe fn disable(&self, ms: u64) -> Result<(), Error> {
        write(self.bar + CC, read(self.bar + CC) & !1);
        let stopped = wait(|| Ok(read(self.bar + CSTS) & 1 == 0), ms, b"NVMe disable timeout");
        // Attempt bus-master disable even on failed controller reset.
        let master = self.bus_master(false);
        stopped?;
        master?;
        fence(Ordering::Acquire);
        Ok(())
    }
    fn doorbell(&self, caps: Capabilities, qid: u16, completion: bool) -> usize {
        self.bar + 0x1000 + (2 * usize::from(qid) + completion as usize) * caps.stride
    }
}
struct Queue { sq: usize, cq: usize, state: QueueState }
pub struct NvmeDisk {
    controller: Controller, caps: Capabilities, frames: [Frame; 5], bus: [BusAddress; 5],
    admin: Queue, io: Queue, geometry: Geometry, failed: bool, uncertain: bool,
}
impl NvmeDisk {
    pub unsafe fn open(mut controller: Controller, root: usize, frames: &mut Frames<'_>) -> Result<Self, Error> {
        let caps = controller.prepare(root, frames)?;
        let mut owned: [Option<Frame>; 5] = core::array::from_fn(|_| None);
        for i in 0..owned.len() {
            match frames.alloc_zeroed() {
                Some(page) => owned[i] = Some(page),
                None => {
                    for page in owned.into_iter().flatten() { frames.release(page); }
                    return Err(b"NVMe queue/data allocation");
                }
            }
        }
        let pages = owned.map(|page| page.unwrap());
        if pages.iter().any(|page| BusAddress::of(page, u64::MAX).is_none()) {
            for page in pages { frames.release(page); }
            return Err(b"NVMe DMA address");
        }
        let bus = core::array::from_fn(|i| BusAddress::of(&pages[i], u64::MAX).unwrap());
        let admin = Queue { sq: pages[0].address(), cq: pages[1].address(), state: QueueState::new(caps.depth) };
        let io = Queue { sq: pages[2].address(), cq: pages[3].address(), state: QueueState::new(caps.depth) };
        let mut disk = Self { controller, caps, frames: pages, bus, admin, io,
            geometry: Geometry { blocks: 0, block_size: 512 }, failed: false, uncertain: false };
        if let Err(reason) = disk.initialize() {
            disk.close(frames)?;
            return Err(reason);
        }
        Ok(disk)
    }
    unsafe fn issue(&mut self, qid: u16, mut words: [u32; 16]) -> Result<u16, Error> {
        if self.failed { return Err(b"NVMe controller offline"); }
        self.failed = true;
        let queue = if qid == 0 { &mut self.admin } else { &mut self.io };
        if read(self.controller.bar + CSTS) & 3 != 1 { return Err(b"NVMe controller not ready"); }
        let s = queue.state.submit(&mut words)?;
        let sqe = (queue.sq + usize::from(s.slot) * 64) as *mut u32;
        for (i, word) in words.into_iter().enumerate() { ptr::write_volatile(sqe.add(i), word); }
        self.uncertain = true;
        fence(Ordering::Release);
        write(self.controller.doorbell(self.caps, qid, false), u32::from(s.tail));
        let cqe = queue.cq + usize::from(queue.state.head()) * 16;
        let bar = self.controller.bar;
        wait(|| {
            if read(bar + CSTS) & 3 != 1 { return Err(b"NVMe fatal status"); }
            Ok(queue.state.phase_matches(read16(cqe + 14)))
        }, 8000, b"NVMe completion timeout")?;
        fence(Ordering::Acquire);
        let status = read16(cqe + 14);
        let succeeded = queue.state.complete(qid, read16(cqe + 10), read16(cqe + 8), read16(cqe + 12), status)?;
        self.uncertain = false;
        write(self.controller.doorbell(self.caps, qid, true), u32::from(queue.state.head()));
        if !succeeded {
            let _ = writeln!(Console, "AGENTOS NVME STATUS QID={qid} CID={} STATUS={status:04x}\r", s.cid);
            return Err(b"NVMe command status");
        }
        self.failed = false;
        Ok(s.cid)
    }
    unsafe fn initialize(&mut self) -> Result<(), Error> {
        let bar = self.controller.bar;
        let entries = u32::from(self.caps.depth - 1);
        write(bar + INTMS, u32::MAX);
        write(bar + AQA, entries | (entries << 16));
        address(bar + ASQ, self.bus[0].value());
        address(bar + ACQ, self.bus[1].value());
        self.controller.bus_master(true)?;
        fence(Ordering::Release);
        write(bar + CC, (6 << 16) | (4 << 20) | 1);
        wait(|| {
            let status = read(bar + CSTS);
            if status & 2 != 0 { return Err(b"NVMe controller fatal during enable"); }
            Ok(status & 1 != 0)
        }, self.caps.timeout_ms, b"NVMe enable timeout")?;
        let data = self.bus[4].value();
        self.issue(0, protocol::command(6, 0, data, 1, 0, 0))?;
        let page = self.frames[4].address() as *const u8;
        let sqes = ptr::read_volatile(page.add(512));
        let cqes = ptr::read_volatile(page.add(513));
        let nn = read(self.frames[4].address() + 516);
        if sqes & 15 > 6 || sqes >> 4 < 6 || cqes & 15 > 4 || cqes >> 4 < 4 || nn == 0 {
            return Err(b"unsupported NVMe controller command format");
        }
        // Explicit NSID 1; never select another namespace automatically.
        // One 4K PRP is within MDTS for all accepted controllers.
        self.issue(0, protocol::command(6, 1, data, 0, 0, 0))?;
        let (blocks, block_size) = protocol::geometry(&*(page as *const [u8; PAGE]))?;
        self.geometry = Geometry { blocks, block_size };
        self.issue(0, protocol::command(9, 0, 0, 7, 0, 0))?;
        self.issue(0, protocol::command(5, 0, self.bus[3].value(), 1 | (entries << 16), 1, 0))?;
        self.issue(0, protocol::command(1, 0, self.bus[2].value(), 1 | (entries << 16), 1 | (1 << 16), 0))?;
        let _ = writeln!(Console, "AGENTOS NVME READY NSID=1 BLOCKS={blocks} SIZE={block_size} DEPTH={} STRIDE={}\r",
                         self.caps.depth, self.caps.stride);
        Ok(())
    }
    unsafe fn transfer(&mut self, opcode: u8, lba: u64, blocks: u16) -> Result<(), Error> {
        let prp = if opcode == 0 { 0 } else { self.bus[4].value() };
        let cid = self.issue(1, protocol::io(opcode, lba, blocks, prp)?)?;
        let _ = writeln!(Console, "AGENTOS NVME IO OP={opcode:02x} LBA={lba} BLOCKS={blocks} CID={cid}\r");
        Ok(())
    }
    pub fn close(self, frames: &mut Frames<'_>) -> Result<(), Error> {
        // Do not release uncertain DMA even if the controller appears stopped.
        // Frame has no automatic allocator release on drop.
        unsafe { self.controller.disable(self.caps.timeout_ms)?; }
        if self.uncertain { return Err(b"NVMe uncertain DMA quarantined"); }
        for page in self.frames { frames.release(page); }
        let _ = writeln!(Console, "AGENTOS NVME CLOSED RDY=0 MASTER=0 DMA=5\r");
        Ok(())
    }
}
impl BlockDevice for NvmeDisk {
    fn geometry(&self) -> Geometry { self.geometry }
    fn read_blocks(&mut self, mut lba: u64, dst: &mut [u8]) -> Result<(), Error> {
        self.geometry.check(lba, dst.len())?;
        for chunk in dst.chunks_mut(PAGE) {
            let blocks = (chunk.len() / self.geometry.block_size) as u16;
            unsafe {
                self.transfer(2, lba, blocks)?;
                ptr::copy_nonoverlapping(self.frames[4].address() as *const u8, chunk.as_mut_ptr(), chunk.len());
            }
            lba += u64::from(blocks);
        }
        Ok(())
    }
    fn write_blocks(&mut self, mut lba: u64, src: &[u8]) -> Result<(), Error> {
        self.geometry.check(lba, src.len())?;
        if self.failed { return Err(b"NVMe controller offline"); }
        for chunk in src.chunks(PAGE) {
            let blocks = (chunk.len() / self.geometry.block_size) as u16;
            unsafe {
                ptr::copy_nonoverlapping(chunk.as_ptr(), self.frames[4].address() as *mut u8, chunk.len());
                self.transfer(1, lba, blocks)?;
            }
            lba += u64::from(blocks);
        }
        Ok(())
    }
    fn flush(&mut self) -> Result<(), Error> { unsafe { self.transfer(0, 0, 0) } }
}
