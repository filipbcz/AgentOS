//! Polling, non-NCQ READ DMA EXT on the dedicated acceptance HBA. The boot
//! disk is on a separate controller. Only the signed DMA profile calls exercise.
use crate::{dma::{BusAddress, Mapping, PAGE}, frames::{Frame, Frames}, hpet, paging, pci::Console};
use core::{fmt::Write, ptr, sync::atomic::{fence, Ordering}};

type Error = &'static [u8];
const BYTES: usize = 2 * PAGE;
const ST: u32 = 1;
const FRE: u32 = 1 << 4;
const FR: u32 = 1 << 14;
const CR: u32 = 1 << 15;
const AE: u32 = 1 << 31;
const CLB: usize = 0;
const FB: usize = 8;
const IS: usize = 0x10;
const CMD: usize = 0x18;
const TFD: usize = 0x20;
const SERR: usize = 0x30;
const SACT: usize = 0x34;
const CI: usize = 0x38;

unsafe fn read(addr: usize) -> u32 { ptr::read_volatile(addr as *const u32) }
unsafe fn write(addr: usize, value: u32) { ptr::write_volatile(addr as *mut u32, value); }
unsafe fn address(reg: usize, bus: u64) {
    write(reg, bus as u32);
    write(reg + 4, (bus >> 32) as u32);
}
fn now() -> Result<u64, Error> { hpet::millis().ok_or(b"AHCI clock") }
fn wait(mut ready: impl FnMut() -> bool, ms: u64, error: Error) -> Result<(), Error> {
    let start = now()?;
    for _ in 0..50_000_000 {
        if ready() { return Ok(()); }
        if now()? - start >= ms { break; }
        core::hint::spin_loop();
    }
    Err(error)
}

pub struct Controller { pub cfg: usize, pub abar: usize }

impl Controller {
    unsafe fn bus_master(&self, enable: bool) -> Result<(), Error> {
        let cmd = (self.cfg + 4) as *mut u16;
        let value = ptr::read_volatile(cmd);
        ptr::write_volatile(cmd, if enable { value | 6 } else { (value | 2) & !4 });
        if ptr::read_volatile(cmd) & 6 != if enable { 6 } else { 2 } { return Err(b"PCI bus master readback"); }
        Ok(())
    }

    fn port(&self) -> usize { self.abar + 0x100 }

    unsafe fn stop(&self) -> Result<(), Error> {
        let p = self.port();
        write(p + CMD, read(p + CMD) & !ST);
        wait(|| read(p + CMD) & (ST | CR) == 0, 1000, b"AHCI command engine still active")?;
        write(p + CMD, read(p + CMD) & !FRE);
        wait(|| read(p + CMD) & (FRE | FR) == 0, 1000, b"AHCI FIS engine still active")
    }

    unsafe fn reset(&self) -> Result<(), Error> {
        self.stop()?;
        self.bus_master(false)?;
        write(self.abar + 4, AE | 1);
        wait(|| read(self.abar + 4) & 1 == 0, 2000, b"AHCI reset timeout")?;
        let p = self.port();
        if read(p + CMD) & (ST | CR | FRE | FR) != 0 || read(p + CI) != 0 || read(p + SACT) != 0 {
            return Err(b"AHCI reset did not quiesce DMA");
        }
        Ok(())
    }

    unsafe fn start(&self, control: BusAddress) -> Result<(), Error> {
        let p = self.port();
        self.bus_master(true)?;
        write(self.abar + 4, AE); // polling; leave global and port IRQs disabled
        write(p + 0x14, 0);
        address(p + CLB, control.value());
        address(p + FB, control.value() + 1024);
        write(p + SERR, u32::MAX);
        write(p + IS, u32::MAX);
        write(p + CMD, read(p + CMD) | FRE);
        wait(|| read(p + CMD) & FR != 0, 1000, b"AHCI FIS start")?;
        wait(|| read(p + TFD) & 0x88 == 0, 1000, b"AHCI device busy")?;
        write(p + CMD, read(p + CMD) | ST);
        wait(|| read(p + CMD) & CR != 0, 1000, b"AHCI command start")
    }

    pub unsafe fn exercise(self, root: usize, frames: &mut Frames<'_>) -> Result<(), Error> {
        paging::claim_config(root, self.cfg).ok_or(b"AHCI config mapping" as Error)?;
        paging::map_device(root, frames, self.abar).ok_or(b"AHCI BAR mapping" as Error)?;
        // Accept only the isolated single-port HBA set up by the host profile.
        if read(self.abar + 0x0c) != 1 || read(self.port() + 0x28) & 15 != 3 ||
            read(self.port() + CI) != 0 || read(self.port() + SACT) != 0 { return Err(b"AHCI profile topology"); }
        let mask = if read(self.abar) & (1 << 31) != 0 { u64::MAX } else { u32::MAX as u64 };
        self.stop()?;
        let baseline = frames.available();
        let control = frames.alloc_zeroed().ok_or(b"AHCI control allocation" as Error)?;
        let Some(bus) = BusAddress::of(&control, mask) else { frames.release(control); return Err(b"AHCI DMA mask"); };
        // Command list, received FIS and command table occupy aligned, disjoint
        // ranges in one owned frame, held until both engines have stopped.
        let result = (|| {
            self.start(bus)?;
            let mut digest = None;
            let mut stopped = None;
            let mut tag = 1;
            while tag <= 33 {
                let outcome = self.transfer(frames, &control, bus, mask, tag, if tag == 1 { 8000 } else { 15 })?;
                match outcome {
                    Outcome::Done(value) => {
                        if *digest.get_or_insert(value) != value { return Err(b"AHCI inconsistent VDI data" as Error); }
                    }
                    Outcome::Stopped(reused) => { stopped = Some(reused); break; }
                }
                tag += 1;
            }
            let canary = stopped.ok_or(b"AHCI timeout scenario did not leave a command pending" as Error)?;
            self.start(bus)?;
            let recovered = self.transfer(frames, &control, bus, mask, tag + 1, 8000)?;
            if !matches!(recovered, Outcome::Done(value) if Some(value) == digest) { return Err(b"AHCI recovery read"); }
            for page in canary {
                if (0..PAGE).any(|i| ptr::read_volatile((page.address()+i) as *const u8) != 0x5a) {
                    return Err(b"AHCI late DMA after reclamation");
                }
                frames.release(page);
            }
            Ok(())
        })();
        // Quarantine the control frame on unconfirmed stop. Any active data
        // mapping abandoned by the error path independently retains its pins.
        self.reset()?;
        address(self.port() + CLB, 0);
        address(self.port() + FB, 0);
        frames.release(control);
        result?;
        if frames.available() != baseline { return Err(b"AHCI DMA frame accounting"); }
        let _ = writeln!(Console, "AGENTOS DMA END FREE={baseline} CANARY=ok\r");
        Ok(())
    }

    unsafe fn transfer(&self, frames: &mut Frames<'_>, control: &Frame, bus: BusAddress,
                       mask: u64, tag: u32, ms: u64) -> Result<Outcome, Error> {
        let p = self.port();
        if read(p + CI) != 0 || read(p + SACT) != 0 || read(p + CMD) & (CR | FR) != CR | FR {
            return Err(b"AHCI slot unavailable");
        }
        let (mapping, spacer) = buffer(frames, mask)?;
        let pages = *mapping.pages();
        let list = control.address();
        let table = list + 1280;
        // Do not overwrite the live received-FIS area while FRE=1.
        ptr::write_bytes(list as *mut u8, 0, 32);
        ptr::write_bytes(table as *mut u8, 0, 160);
        write(list, 5 | (2 << 16)); // five FIS dwords, read, two PRDs
        address(list + 8, bus.value() + 1280);
        let lba = 2048 + (tag - 1) * 16;
        write(table, 0x0025_8027); // Register H2D: C=1, READ DMA EXT
        write(table + 4, 0x4000_0000 | lba);
        write(table + 12, 16); // sixteen 512-byte logical sectors
        for (i, page) in mapping.addresses().iter().enumerate() {
            let prd = table + 128 + i * 16;
            address(prd, page.value());
            write(prd + 12, PAGE as u32 - 1);
        }
        write(p + IS, u32::MAX);
        let refs = |f: &Frames<'_>| pages.map(|a| f.references(a).unwrap_or(0));
        if refs(frames) != [1, 1] { return Err(b"AHCI pins after owner release"); }
        let _ = writeln!(Console, "AGENTOS DMA PIN TAG={tag} LBA={lba} A={:x} B={:x} REFS=1,1\r", pages[0], pages[1]);
        let active = mapping.submit();
        let start = now()?;
        write(p + CI, 1);
        let mut spins = 0;
        let (done, ci, elapsed) = loop {
            let elapsed = now()? - start;
            let ci = read(p + CI);
            if ci & 1 == 0 { break (true, ci, elapsed); }
            if elapsed >= ms { break (false, ci, elapsed); }
            spins += 1;
            if spins == 50_000_000 { return Err(b"AHCI clock stalled"); }
            core::hint::spin_loop();
        };
        if refs(frames) != [1, 1] { return Err(b"AHCI lost active DMA pins"); }
        let mut hash = 2166136261u32;
        let mapping = if done {
            fence(Ordering::Acquire);
            let bytes = read(list + 4);
            let status = read(p + IS);
            let tfd = read(p + TFD);
            let fis = read(list + 1024 + 0x40);
            if bytes != BYTES as u32 || status & 1 == 0 || status & 0x7d00_0000 != 0 ||
                tfd & 0xa9 != 0 || fis as u8 != 0x34 || (fis >> 16) & 0xa9 != 0 {
                return Err(b"AHCI unsuccessful READ DMA EXT");
            }
            let map = active.reclaim();
            for &page in map.pages() {
                for i in 0..PAGE {
                    hash = (hash ^ u32::from(ptr::read_volatile((page+i) as *const u8))).wrapping_mul(16777619);
                }
            }
            let _ = writeln!(Console, "AGENTOS DMA DONE TAG={tag} CI={ci:x} IS={status:x} TFD={tfd:x} FIS={fis:x} BYTES={bytes} FNV={hash:08x}\r");
            map
        } else {
            let cmd = read(p + CMD);
            // No console I/O between the pending snapshot and requesting stop.
            self.reset()?;
            let stopped = read(p + CMD);
            let idle = read(p + CI);
            let sact = read(p + SACT);
            let pci = ptr::read_volatile((self.cfg + 4) as *const u16);
            if refs(frames) != [1, 1] { return Err(b"AHCI lost pins during reset"); }
            let _ = writeln!(Console, "AGENTOS DMA TIMEOUT TAG={tag} MS={elapsed} LIMIT={ms} CI={ci:x} CMD={cmd:x} REFS=1,1\r");
            let _ = writeln!(Console, "AGENTOS DMA STOP TAG={tag} CMD={stopped:x} CI={idle:x} SACT={sact:x} PCI={pci:x} REFS=1,1\r");
            active.reclaim()
        };
        let before = frames.available();
        mapping.unmap(frames);
        let after = frames.available();
        if after != before + 2 || refs(frames) != [0, 0] { return Err(b"AHCI unmap accounting"); }
        let a = frames.alloc().ok_or(b"AHCI reuse first" as Error)?;
        let b = frames.alloc().ok_or(b"AHCI reuse second" as Error)?;
        if [a.address(), b.address()] != pages { return Err(b"AHCI exact page reuse"); }
        let _ = writeln!(Console, "AGENTOS DMA REUSE TAG={tag} A={:x} B={:x} BEFORE={before} AFTER={after}\r", a.address(), b.address());
        frames.release(spacer);
        if done {
            frames.release(a); frames.release(b);
            Ok(Outcome::Done(hash))
        } else {
            for page in [&a, &b] { ptr::write_bytes(page.address() as *mut u8, 0x5a, PAGE); }
            Ok(Outcome::Stopped([a, b]))
        }
    }
}

enum Outcome { Done(u32), Stopped([Frame; 2]) }

// A live spacer forces two distinct scatter/gather regions. Release all CPU
// owners before the doorbell: only the driver's mapping can keep either page.
fn buffer(frames: &mut Frames<'_>, mask: u64) -> Result<(Mapping<2>, Frame), Error> {
    let a = frames.alloc_zeroed().ok_or(b"AHCI buffer allocation" as Error)?;
    let Some(gap) = frames.alloc() else { frames.release(a); return Err(b"AHCI spacer allocation"); };
    let Some(b) = frames.alloc_zeroed() else {
        frames.release(gap); frames.release(a); return Err(b"AHCI buffer allocation");
    };
    let owners = [a, b];
    let mapped = Mapping::pin(frames, &owners, mask);
    for frame in owners { frames.release(frame); }
    match mapped {
        Some(mapping) => Ok((mapping, gap)),
        None => { frames.release(gap); Err(b"AHCI DMA pin or address mask") }
    }
}
