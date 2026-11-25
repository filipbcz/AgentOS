//! Isolated BSP xHCI controller lifecycle, hotplug, port reset and
//! command/event rings. USB device addressing and EP0 transfers follow in
//! the next increment; do not present this profile as a USB HID driver.
mod protocol;
use crate::{dma::BusAddress,frames::{Frame,Frames},hpet,paging,pci::Console};
use core::{fmt::Write,ptr,sync::atomic::{fence,Ordering}};
use protocol::{Caps,CommandRing,Error,EventRing,PortProtocol,Trb,PAGE,COMMANDS,EVENTS};

pub struct Controller { pub cfg:usize,pub bar:usize,pub wide:bool,pub msi:u8,pub msix:u8 }
const HCH:u32=1;
const HCRST:u32=2;
const CNR:u32=1<<11;
const FATAL:u32=(1<<2)|(1<<12);

unsafe fn rd(addr:usize)->u32{ptr::read_volatile(addr as *const u32)}
unsafe fn wr(addr:usize,value:u32){ptr::write_volatile(addr as *mut u32,value);}
unsafe fn rd16(addr:usize)->u16{ptr::read_volatile(addr as *const u16)}
unsafe fn wr16(addr:usize,value:u16){ptr::write_volatile(addr as *mut u16,value);}
unsafe fn address(reg:usize,value:u64){wr(reg,value as u32);wr(reg+4,(value>>32) as u32);}
fn wait(mut ready:impl FnMut()->Result<bool,Error>,ms:u64,reason:Error)->Result<(),Error>{
    let start=hpet::millis().ok_or(b"xHCI clock unavailable" as Error)?;
    // A second finite budget protects even against a stalled HPET.
    for _ in 0..200_000_000u32{
        if ready()?{return Ok(());}
        if hpet::millis().ok_or(b"xHCI clock unavailable" as Error)?.saturating_sub(start)>=ms{break;}
        core::hint::spin_loop();
    }
    Err(reason)
}
unsafe fn publish(addr:usize,t:Trb){
    // The controller may observe the cycle bit immediately: write it last.
    ptr::write_volatile(addr as *mut u64,t.parameter);
    wr(addr+8,t.status);
    fence(Ordering::Release);
    wr(addr+12,t.control);
}
impl Controller{
    unsafe fn command(&self,decode:bool,master:bool)->Result<(),Error>{
        let reg=self.cfg+4;
        let value=(rd16(reg)&!7)|(1<<10)|if decode{2}else{0}|if master{4}else{0};
        wr16(reg,value);
        if rd16(reg)&0x407!=value&0x407{return Err(b"xHCI PCI command readback");}
        Ok(())
    }
    unsafe fn prepare(&self,root:usize,frames:&mut Frames<'_>)->Result<(usize,Caps,[PortProtocol;protocol::MAX_PORTS]),Error>{
        paging::claim_config(root,self.cfg).ok_or(b"xHCI ECAM mapping" as Error)?;
        self.command(false,false)?;
        for (cap,mask) in [(self.msi,1u16),(self.msix,1<<15)]{
            if cap!=0{
                let reg=self.cfg+usize::from(cap)+2;
                wr16(reg,rd16(reg)&!mask);
                if rd16(reg)&mask!=0{return Err(b"xHCI IRQ still enabled");}
            }
        }
        let reg=self.cfg+0x10;
        let low=rd(reg);let high=if self.wide{rd(reg+4)}else{0};
        wr(reg,u32::MAX);if self.wide{wr(reg+4,u32::MAX);}
        let masklo=rd(reg)&!15;
        let maskhi=if self.wide{rd(reg+4)}else{u32::MAX};
        if self.wide{wr(reg+4,high);}wr(reg,low);
        if rd(reg)!=low||(self.wide&&rd(reg+4)!=high){return Err(b"xHCI BAR restore");}
        let size=(!((u64::from(maskhi)<<32)|u64::from(masklo))).wrapping_add(1);
        if !(PAGE as u64..=16*PAGE as u64).contains(&size)||!size.is_power_of_two()||
           self.bar==0||self.bar as u64&(size-1)!=0{return Err(b"xHCI unsupported BAR size");}
        let va=paging::map_device_window(root,frames,self.bar,size as usize/PAGE)
            .ok_or(b"xHCI BAR mapping" as Error)?;
        self.command(true,false)?;
        let caps=Caps::parse(core::array::from_fn(|i|rd(va+4*i)),size as usize)?;
        let protocols=protocol::protocols(caps,size as usize,|off|rd(va+off))?;
        let _=writeln!(Console,"AGENTOS MMIO XHCI BAR=0 PA={:016x} VA={va:016x} PAGES={}\r",self.bar,size as usize/PAGE);
        Ok((va,caps,protocols))
    }
    unsafe fn reset(&self,op:usize)->Result<(),Error>{
        // Stop first; HCRST is only legal while halted. Always turn off bus
        // mastering on teardown, including a failed halt/reset handshake.
        let stopped:Result<(),Error>=(||{
            wait(||Ok(rd(op+4)&CNR==0),1000,b"xHCI controller not ready")?;
            wr(op,0);
            wait(||Ok(rd(op+4)&HCH!=0),1000,b"xHCI halt timeout")?;
            wr(op,HCRST);
            wait(||Ok(rd(op)&HCRST==0&&rd(op+4)&CNR==0&&rd(op+4)&HCH!=0),
                 1000,b"xHCI reset timeout")?;
            Ok(())
        })();
        let master=self.command(true,false);
        stopped?;master?;
        fence(Ordering::Acquire);
        Ok(())
    }
}

pub struct Xhci{
    controller:Controller,base:usize,caps:Caps,protocols:[PortProtocol;protocol::MAX_PORTS],
    pages:[Frame;4],bus:[u64;4],commands:CommandRing,events:EventRing,slot:u8,
}
impl Xhci{
    fn op(&self)->usize{self.base+self.caps.op}
    fn intr(&self)->usize{self.base+self.caps.runtime+0x20}
    fn port(&self,id:u8)->usize{self.op()+0x400+16*usize::from(id-1)}
    unsafe fn healthy(&self)->Result<(),Error>{
        if rd(self.op()+4)&(HCH|CNR|FATAL)!=0{return Err(b"xHCI stopped/fatal controller");}
        Ok(())
    }
    pub unsafe fn open(controller:Controller,root:usize,frames:&mut Frames<'_>)->Result<Self,Error>{
        let (base,caps,protocols)=controller.prepare(root,frames)?;
        controller.reset(base+caps.op)?;
        if rd(base+caps.op+8)&1==0{return Err(b"xHCI 4KiB pages required");}
        let mut owned:[Option<Frame>;4]=core::array::from_fn(|_|None);
        for i in 0..owned.len(){
            match frames.alloc_zeroed(){
                Some(page)=>owned[i]=Some(page),
                None=>{for page in owned.into_iter().flatten(){frames.release(page);}return Err(b"xHCI DMA allocation");}
            }
        }
        let pages=owned.map(|p|p.unwrap());
        let mask=if caps.ac64{u64::MAX}else{u32::MAX as u64};
        if pages.iter().any(|p|BusAddress::of(p,mask).is_none()){
            for p in pages{frames.release(p);}return Err(b"xHCI DMA address width");
        }
        let bus=core::array::from_fn(|i|BusAddress::of(&pages[i],mask).unwrap().value());
        let mut hc=Self{controller,base,caps,protocols,pages,bus,
            commands:CommandRing::new(bus[0]),events:EventRing::new(),slot:0};
        if let Err(reason)=hc.initialize(){hc.close(frames)?;return Err(reason);}
        Ok(hc)
    }
    unsafe fn initialize(&mut self)->Result<(),Error>{
        let op=self.op();let intr=self.intr();
        // Pages: command ring, event ring, ERST, DCBAA. No scratchpad pages
        // were accepted by capability validation. No device contexts yet.
        ptr::write_volatile(self.pages[2].address() as *mut u64,self.bus[1]);
        wr(self.pages[2].address()+8,EVENTS as u32);
        wr(self.pages[2].address()+12,0);
        // Publish all owned DMA memory, then enable mastering while the
        // controller is still halted. Writing ERSTBA starts event-ring
        // initialization; an xHC may fetch ERST immediately, not only at Run
        // (xHCI spec 4.9.4/5.5.2.3.2). Keep all pages owned until reset.
        fence(Ordering::SeqCst);
        self.controller.command(true,true)?;
        // Empty command ring has cycle zero; publish Link only when wrapping.
        wr(op+0x14,0);
        address(op+0x30,self.bus[3]);
        address(op+0x18,self.bus[0]|1);
        wr(op+0x38,u32::from(self.caps.slots));
        wr(intr,1);wr(intr+4,0);wr(intr+8,1);
        address(intr+0x18,self.bus[1]);
        address(intr+0x10,self.bus[2]);
        fence(Ordering::SeqCst);
        wr(op,1); // Run, no interrupts
        wait(||Ok(rd(op+4)&HCH==0),1000,b"xHCI run timeout")?;
        self.healthy()?;
        for port in 1..=self.caps.ports{
            let reg=self.port(port);let old=rd(reg);
            let action=if self.caps.ppc{protocol::PP}else{0};
            wr(reg,protocol::port_write(old,action|(old&protocol::CHANGES)));
        }
        let _=writeln!(Console,"AGENTOS XHCI READY VERSION={:04x} PORTS={} SLOTS={} CMD={:016x} EVENT={:016x} RING=16\r",
            self.caps.version,self.caps.ports,self.caps.slots,self.bus[0],self.bus[1]);
        Ok(())
    }
    unsafe fn pop(&mut self)->Result<Option<Trb>,Error>{
        self.healthy()?;
        let entry=self.pages[1].address()+16*self.events.index();
        let control=rd(entry+12);
        if !self.events.ready(control){return Ok(None);}
        fence(Ordering::Acquire);
        let event=Trb{parameter:ptr::read_volatile(entry as *const u64),status:rd(entry+8),control};
        self.events.consume(event)?;
        fence(Ordering::SeqCst);
        // ERDP always points at the *next* unconsumed TRB; acknowledge EHB.
        address(self.intr()+0x18,(self.bus[1]+16*self.events.index() as u64)|8);
        wr(self.intr(),1); // clear IP, do not enable IRQ
        wr(self.op()+4,(1<<3)|(1<<4)); // USBSTS EINT/PCD W1C
        Ok(Some(event))
    }
    unsafe fn port_event(&self,event:Trb)->Result<(u8,u32),Error>{
        let port=event.port(self.caps.ports)?;
        let reg=self.port(port);let status=rd(reg);
        let _=writeln!(Console,"AGENTOS XHCI PORT EVENT ID={port} STATUS={status:08x}\r");
        wr(reg,protocol::port_write(status,status&protocol::CHANGES));
        Ok((port,status))
    }
    unsafe fn command(&mut self,kind:u8,slot:u8,slot_type:u8)->Result<u8,Error>{
        self.healthy()?;
        let (ticket,trb,link)=self.commands.submit(kind,slot,slot_type)?;
        if let Some(link)=link{publish(self.pages[0].address()+16*(COMMANDS-1),link);}
        publish(self.pages[0].address()+16*ticket.index,trb);
        fence(Ordering::SeqCst);
        wr(self.base+self.caps.doorbell,0);
        let mut result=None;
        wait(||{
            if let Some(event)=self.pop()?{
                if event.kind()==protocol::PORT_CHANGE{self.port_event(event)?;return Ok(false);}
                let id=self.commands.complete(event,self.caps.slots)?;
                result=Some(id);
                return Ok(true);
            }
            Ok(false)
        },3000,b"xHCI command completion timeout")?;
        let id=result.ok_or(b"xHCI missing completion" as Error)?;
        let _=writeln!(Console,"AGENTOS XHCI COMMAND N={} TYPE={kind} PTR={:016x} CYCLE={} SLOT={id} CODE=1\r",
            self.commands.count(),ticket.pointer,ticket.cycle as u8);
        Ok(id)
    }
    unsafe fn await_port(&mut self,expected:Option<u8>,change:u32,connected:bool)->Result<(u8,u32),Error>{
        let mut observed=None;
        wait(||{
            if let Some(event)=self.pop()?{
                let (port,status)=self.port_event(event)?;
                if expected.map_or(true,|id|id==port) && status&change!=0 &&
                   (status&protocol::CCS!=0)==connected {
                    observed=Some((port,status));return Ok(true);
                }
            }
            Ok(false)
        },20000,b"xHCI port event timeout")?;
        observed.ok_or(b"xHCI port event missing")
    }
    pub unsafe fn exercise(&mut self)->Result<(),Error>{
        // QEMU attaches one device after READY. Observe the real hardware
        // port event, not only a successful read of PORTSC.
        let (port,_)=self.await_port(None,protocol::CSC,true)?;
        let proto=self.protocols[usize::from(port-1)];
        if proto.major!=2{return Err(b"xHCI first profile needs a USB2 device");}
        for other in 1..=self.caps.ports{
            if other!=port&&rd(self.port(other))&protocol::CCS!=0{return Err(b"xHCI fixture has multiple attached devices");}
        }
        let reg=self.port(port);
        let old=rd(reg);
        wr(reg,protocol::port_write(old,protocol::PR));
        let (_,status)=self.await_port(Some(port),protocol::PRC,true)?;
        let speed=protocol::speed(status,proto)?;
        let _=writeln!(Console,"AGENTOS XHCI PORT RESET ID={port} USB={} SPEED={speed} STATUS={status:08x}\r",proto.major);
        self.slot=self.command(protocol::ENABLE_SLOT,0,proto.slot_type)?;
        for _ in 0..protocol::NOOPS{self.command(protocol::NOOP,0,0)?;}
        self.command(protocol::DISABLE_SLOT,self.slot,0)?;
        self.slot=0;
        let _=writeln!(Console,"AGENTOS XHCI WAIT DETACH PORT={port}\r");
        self.await_port(Some(port),protocol::CSC,false)?;
        if rd(reg)&protocol::CCS!=0{return Err(b"xHCI device still attached");}
        let _=writeln!(Console,"AGENTOS XHCI DETACHED PORT={port} COMMANDS={} EVENTS={}\r",self.commands.count(),self.events.count());
        Ok(())
    }
    pub fn close(self,frames:&mut Frames<'_>)->Result<(),Error>{
        unsafe{self.controller.reset(self.op())?;}
        // Keep pins on uncertain ownership (even if reset subsequently
        // acknowledges). A successful exercise has no owned command or slot.
        if self.commands.pending()||self.slot!=0{return Err(b"xHCI uncertain DMA quarantined");}
        for page in self.pages{frames.release(page);}
        let _=writeln!(Console,"AGENTOS XHCI CLOSED HALTED=1 MASTER=0 DMA=4\r");
        Ok(())
    }
}
