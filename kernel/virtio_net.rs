//! Exclusive early-boot modern VirtIO-net PCI transport.
//! Poll split RX/TX queues, one owned DMA descriptor per queue, no offloads
//! or IRQs. An explicit profile exercises L2 frames, then resets the device.
mod protocol;
use crate::{dma::BusAddress, frames::{Frame, Frames}, system_clock, paging, pci::Console};
use core::{fmt::Write, ptr, sync::atomic::{fence, Ordering}};
use protocol::{Error, Ring, PAGE, DEPTH, DESC, AVAIL, USED, HEADER, MAX_FRAME, MIN_FRAME};

pub struct Controller { pub cfg: usize, pub msi: u8, pub msix: u8 }
struct Transport { common: usize, device: usize, notify: usize, layout: protocol::Layout }
const STATUS: usize = 20;
const FEATURES_OK: u8 = 8;
const DRIVER_OK: u8 = 4;
const BAD: u8 = 0xc0;

unsafe fn rd<T: Copy>(addr: usize) -> T { ptr::read_volatile(addr as *const T) }
unsafe fn wr<T>(addr: usize, value: T) { ptr::write_volatile(addr as *mut T, value); }
unsafe fn write_address(addr: usize, value: u64) {
    wr(addr,value as u32); wr(addr+4,(value>>32) as u32);
}
fn wait(mut ready: impl FnMut() -> Result<bool,Error>, ms: u64, error: Error) -> Result<(),Error> {
    let start = system_clock::millis().ok_or(b"VirtIO clock unavailable" as Error)?;
    for _ in 0..100_000_000 {
        if ready()? { return Ok(()); }
        if system_clock::millis().ok_or(b"VirtIO clock unavailable" as Error)?.saturating_sub(start) >= ms { break; }
        core::hint::spin_loop();
    }
    Err(error)
}

impl Controller {
    unsafe fn command(&self, decode: bool, master: bool) -> Result<(),Error> {
        let reg=self.cfg+4;
        let value=(rd::<u16>(reg)&!7) | (1<<10) | if decode {2} else {0} | if master {4} else {0};
        wr(reg,value);
        if rd::<u16>(reg)&0x407 != value&0x407 { return Err(b"VirtIO PCI command readback"); }
        Ok(())
    }
    unsafe fn reset(&self, common: usize) -> Result<(),Error> {
        wr(common+STATUS,0u8);
        let result=wait(|| Ok(rd::<u8>(common+STATUS)==0),1000,b"VirtIO reset timeout");
        let master=self.command(true,false);
        result?; master?;
        fence(Ordering::Acquire);
        Ok(())
    }
    unsafe fn prepare(&self, root: usize, frames: &mut Frames<'_>) -> Result<Transport,Error> {
        paging::claim_config(root,self.cfg).ok_or(b"VirtIO ECAM mapping" as Error)?;
        let cfg: [u8;256]=core::array::from_fn(|i| rd::<u8>(self.cfg+i));
        let layout=protocol::layout(&cfg)?;
        self.command(false,false)?;
        for (cap,mask) in [(self.msi,1u16),(self.msix,1<<15)] {
            if cap!=0 {
                let reg=self.cfg+usize::from(cap)+2;
                wr(reg,rd::<u16>(reg)&!mask);
                if rd::<u16>(reg)&mask!=0 { return Err(b"VirtIO message IRQ still enabled"); }
            }
        }
        let mut mapped=[(0usize,0usize);6];
        for region in [layout.common,layout.notify,layout.isr,layout.device] {
            let slot=usize::from(region.bar);
            if mapped[slot].0==0 {
                let (physical,wide)=protocol::bar(&cfg,region.bar)?;
                let reg=self.cfg+0x10+slot*4;
                let low=rd::<u32>(reg);
                let high=if wide {rd::<u32>(reg+4)} else {0};
                // Only the exclusively selected device, with decoding and
                // bus mastering disabled; restore the firmware BAR exactly.
                wr(reg,u32::MAX); if wide {wr(reg+4,u32::MAX);}
                let mask_low=rd::<u32>(reg)&!15;
                let mask_high=if wide {rd::<u32>(reg+4)} else {u32::MAX};
                if wide {wr(reg+4,high);} wr(reg,low);
                if rd::<u32>(reg)!=low || (wide && rd::<u32>(reg+4)!=high) {return Err(b"VirtIO BAR restore");}
                let mask=(u64::from(mask_high)<<32)|u64::from(mask_low);
                let size=(!mask).wrapping_add(1);
                if !(PAGE as u64..=16*PAGE as u64).contains(&size) ||
                   !size.is_power_of_two() || physical as u64&(size-1)!=0 {
                    return Err(b"VirtIO unsupported BAR size");
                }
                let va=paging::map_device_window(root,frames,physical,size as usize/PAGE)
                    .ok_or(b"VirtIO BAR mapping" as Error)?;
                mapped[slot]=(va,size as usize);
                let _=writeln!(Console,"AGENTOS MMIO VIRTIO BAR={slot} PA={physical:016x} VA={va:016x} PAGES={}\r",size as usize/PAGE);
            }
            if !region.within(mapped[slot].1) {return Err(b"VirtIO capability exceeds sized BAR");}
        }
        let address=|r:protocol::Region| mapped[usize::from(r.bar)].0+r.offset;
        let t=Transport { common:address(layout.common),device:address(layout.device),
                          notify:address(layout.notify),layout };
        self.command(true,false)?;
        self.reset(t.common)?;
        Ok(t)
    }
}

struct Queue { id:u16, ring:usize, data:usize, ring_bus:u64, data_bus:u64, notify:usize, state:Ring }
impl Queue {
    unsafe fn setup(&mut self,t:&Transport) -> Result<(),Error> {
        let c=t.common;
        wr(c+22,self.id);
        let size=rd::<u16>(c+24);
        if size<DEPTH || !size.is_power_of_two() || rd::<u16>(c+28)!=0 {return Err(b"VirtIO unsupported queue size/state");}
        let offset=protocol::notify_offset(t.layout.notify,t.layout.multiplier,rd(c+30))?;
        self.notify=t.notify+offset;
        wr(c+24,DEPTH);
        wr(c+26,0xffffu16); // no MSI-X vector
        wr(self.ring+AVAIL,1u16); // VRING_AVAIL_F_NO_INTERRUPT
        write_address(c+32,self.ring_bus+DESC as u64);
        write_address(c+40,self.ring_bus+AVAIL as u64);
        write_address(c+48,self.ring_bus+USED as u64);
        fence(Ordering::Release);
        wr(c+28,1u16);
        if rd::<u16>(c+24)!=DEPTH || rd::<u16>(c+28)!=1 {return Err(b"VirtIO queue configuration readback");}
        Ok(())
    }
    unsafe fn submit(&mut self,len:usize,rx:bool) -> Result<(),Error> {
        let ticket=self.state.submit()?;
        let desc=self.ring+DESC+16*usize::from(ticket.id);
        wr(desc,self.data_bus);
        wr(desc+8,len as u32);
        wr(desc+12,if rx {2u16} else {0u16});
        wr(desc+14,0u16);
        wr(self.ring+AVAIL+4+2*usize::from(ticket.slot),ticket.id);
        fence(Ordering::Release);
        wr(self.ring+AVAIL+2,ticket.next);
        // Always notify; the device may suppress notifications, but redundant
        // doorbells are legal. Publish the avail index before notifying.
        fence(Ordering::SeqCst);
        wr(self.notify,self.id);
        Ok(())
    }
    unsafe fn complete(&mut self,common:usize,rx:bool) -> Result<usize,Error> {
        let index=self.ring+USED+2;
        let state=&mut self.state;
        wait(|| {
            let status=rd::<u8>(common+STATUS);
            if status&BAD!=0 || status&DRIVER_OK==0 {return Err(b"VirtIO device needs reset");}
            state.ready(rd::<u16>(index))
        },10000,b"VirtIO completion timeout")?;
        fence(Ordering::Acquire);
        let entry=self.ring+USED+4+8*state.slot();
        state.complete(rd(index),rd(entry),rd(entry+4),rx)
    }
}

/// Owns four frames until device reset is acknowledged and mastering disabled.
/// No automatic Drop: on failed quiescence, the allocator keeps every frame.
pub struct VirtioNet {
    controller:Controller, transport:Transport, pages:[Frame;4],
    rx:Queue, tx:Queue, mac:[u8;6], merged:bool, failed:bool,
}
impl VirtioNet {
    pub unsafe fn open(controller:Controller,root:usize,frames:&mut Frames<'_>)->Result<Self,Error> {
        let transport=controller.prepare(root,frames)?;
        let mut owned:[Option<Frame>;4]=core::array::from_fn(|_|None);
        for page in &mut owned {
            match frames.alloc_zeroed() {
                Some(value)=>*page=Some(value),
                None=>{for value in owned.into_iter().flatten(){frames.release(value);} return Err(b"VirtIO DMA allocation");}
            }
        }
        let pages=owned.map(|p|p.unwrap());
        if pages.iter().any(|p|BusAddress::of(p,u64::MAX).is_none()) {
            for page in pages {frames.release(page);} return Err(b"VirtIO DMA address");
        }
        let queue=|id:u16|{
            let i=usize::from(id)*2;
            Queue{id,ring:pages[i].address(),data:pages[i+1].address(),
                  ring_bus:BusAddress::of(&pages[i],u64::MAX).unwrap().value(),
                  data_bus:BusAddress::of(&pages[i+1],u64::MAX).unwrap().value(),notify:0,state:Ring::new()}
        };
        let rx=queue(0); let tx=queue(1);
        let mut net=Self{controller,transport,pages,rx,tx,mac:[0;6],merged:false,failed:true};
        if let Err(error)=net.initialize() {net.close(frames)?; return Err(error);}
        net.failed=false;
        Ok(net)
    }
    unsafe fn initialize(&mut self)->Result<(),Error>{
        let c=self.transport.common;
        wr(c+STATUS,1u8); wr(c+STATUS,3u8); // ACKNOWLEDGE, DRIVER
        wr(c,0u32); let low=rd::<u32>(c+4);
        wr(c,1u32); let high=rd::<u32>(c+4);
        let selected=protocol::features(u64::from(low)|(u64::from(high)<<32))?;
        self.merged=selected&protocol::MRG_RXBUF!=0;
        wr(c+8,0u32); wr(c+12,selected as u32);
        wr(c+8,1u32); wr(c+12,(selected>>32) as u32);
        wr(c+STATUS,3u8|FEATURES_OK);
        if rd::<u8>(c+STATUS)!=3|FEATURES_OK || rd::<u16>(c+18)<2 {
            return Err(b"VirtIO feature negotiation rejected");
        }
        let mut stable=false;
        for _ in 0..8 {
            let generation=rd::<u8>(c+21);
            self.mac=core::array::from_fn(|i|rd::<u8>(self.transport.device+i));
            if generation==rd::<u8>(c+21) {stable=true;break;}
        }
        if !stable || !protocol::mac_valid(self.mac) {return Err(b"VirtIO invalid MAC configuration");}
        wr(c+16,0xffffu16);
        self.rx.setup(&self.transport)?; self.tx.setup(&self.transport)?;
        self.controller.command(true,true)?;
        fence(Ordering::Release);
        wr(c+STATUS,3u8|FEATURES_OK|DRIVER_OK);
        if rd::<u8>(c+STATUS)!=3|FEATURES_OK|DRIVER_OK {return Err(b"VirtIO DRIVER_OK rejected");}
        Ok(())
    }
    pub fn mac(&self)->[u8;6]{self.mac}
    pub fn arm_receive(&mut self)->Result<(),Error>{
        if self.failed || self.rx.state.pending(){return Err(b"VirtIO receive unavailable");}
        self.failed=true;
        unsafe{
            ptr::write_bytes(self.rx.data as *mut u8,0,HEADER+MAX_FRAME);
            self.rx.submit(HEADER+MAX_FRAME,true)?;
        }
        self.failed=false; Ok(())
    }
    pub fn receive(&mut self,dst:&mut [u8])->Result<usize,Error>{
        if self.failed || !self.rx.state.pending() || dst.len()<MAX_FRAME {return Err(b"VirtIO receive buffer unavailable");}
        self.failed=true;
        let n=unsafe{
            let n=self.rx.complete(self.transport.common,true)?;
            let hdr=ptr::read(self.rx.data as *const [u8;HEADER]);
            protocol::rx_header(&hdr,self.merged)?;
            ptr::copy_nonoverlapping((self.rx.data+HEADER) as *const u8,dst.as_mut_ptr(),n);
            n
        };
        self.failed=false; Ok(n)
    }
    pub fn send(&mut self,src:&[u8])->Result<(),Error>{
        if self.failed || self.tx.state.pending() || !(MIN_FRAME..=MAX_FRAME).contains(&src.len()){
            return Err(b"VirtIO invalid transmit frame/state");
        }
        self.failed=true;
        unsafe {
            ptr::write_bytes(self.tx.data as *mut u8,0,HEADER);
            ptr::copy_nonoverlapping(src.as_ptr(),(self.tx.data+HEADER) as *mut u8,src.len());
            self.tx.submit(HEADER+src.len(),false)?;
            self.tx.complete(self.transport.common,false)?;
        }
        self.failed=false; Ok(())
    }
    pub fn close(self,frames:&mut Frames<'_>)->Result<(),Error>{
        unsafe{self.controller.reset(self.transport.common)?;}
        // A successful status=0 reset terminates all virtqueues; master=0
        // independently read back. In the error case, quarantine pages with
        // an uncertain completion even after reset (same policy as NVMe).
        if self.rx.state.pending() || self.tx.state.pending(){return Err(b"VirtIO uncertain DMA quarantined");}
        for page in self.pages{frames.release(page);}
        let _=writeln!(Console,"AGENTOS VIRTIO NET CLOSED STATUS=0 MASTER=0 DMA=4\r");
        Ok(())
    }
}

/// Isolated acceptance only: a host endpoint supplies unpredictable bytes.
/// Respond through the real TX queue, never through the serial channel.
pub fn exercise(net:&mut VirtioNet)->Result<(),Error>{
    let mac=net.mac();
    let mut frame=[0u8;MAX_FRAME];
    net.arm_receive()?;
    let _=writeln!(Console,"AGENTOS VIRTIO NET READY MAC={:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} DEPTH={} ROUNDS={} MRG={}\r",
                  mac[0],mac[1],mac[2],mac[3],mac[4],mac[5],DEPTH,protocol::ROUNDS,net.merged as u8);
    for i in 0..protocol::ROUNDS {
        let len=net.receive(&mut frame)?;
        let rx=protocol::fnv(&frame[..len]);
        protocol::reply(&mut frame[..len],mac)?;
        let tx=protocol::fnv(&frame[..len]);
        if i+1<protocol::ROUNDS{net.arm_receive()?;}
        net.send(&frame[..len])?;
        let _=writeln!(Console,"AGENTOS VIRTIO NET FRAME ROUND={} LEN={len} RX={rx:08x} TX={tx:08x} RXUSED={} TXUSED={}\r",
                     i+1,net.rx.state.count(),net.tx.state.count());
    }
    Ok(())
}
