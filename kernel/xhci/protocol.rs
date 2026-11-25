//! xHCI register/capability bounds and the ownership state of polled TRB rings.
pub type Error = &'static [u8];
pub const PAGE: usize = 4096;
pub const MAX_PORTS: usize = 32;
pub const COMMANDS: usize = 16;
pub const EVENTS: usize = 16;
pub const NOOPS: usize = 40;
pub const LINK: u8 = 6;
pub const ENABLE_SLOT: u8 = 9;
pub const DISABLE_SLOT: u8 = 10;
pub const NOOP: u8 = 23;
pub const COMMAND_COMPLETE: u8 = 33;
pub const PORT_CHANGE: u8 = 34;
pub const CCS: u32 = 1;
pub const PED: u32 = 2;
pub const PR: u32 = 1 << 4;
pub const PP: u32 = 1 << 9;
pub const CHANGES: u32 = 0x00fe0000;
pub const CSC: u32 = 1 << 17;
pub const PRC: u32 = 1 << 21;

#[derive(Clone, Copy, Debug)]
pub struct Caps {
    pub version: u16, pub op: usize, pub runtime: usize, pub doorbell: usize,
    pub slots: u8, pub ports: u8, pub ac64: bool, pub ppc: bool, pub ext: usize,
}
fn range(start: usize, size: usize, aperture: usize) -> bool {
    start.checked_add(size).map_or(false, |end| end <= aperture)
}
impl Caps {
    pub fn parse(raw: [u32; 7], aperture: usize) -> Result<Self, Error> {
        let version = (raw[0] >> 16) as u16;
        let op = (raw[0] & 0xff) as usize;
        let slots = raw[1] as u8;
        let ports = (raw[1] >> 24) as u8;
        let intrs = (raw[1] >> 8) & 0x7ff;
        let scratchpads = ((raw[2] >> 21) & 31) * 32 + ((raw[2] >> 27) & 31);
        let runtime = (raw[6] & !31) as usize;
        let doorbell = (raw[5] & !3) as usize;
        let ext = ((raw[4] >> 16) as usize) * 4;
        let operational_size = 0x400 + 16 * usize::from(ports);
        if !(0x100..=0x120).contains(&version) || op < 0x20 || op % 4 != 0 ||
           slots == 0 || ports == 0 || usize::from(ports) > MAX_PORTS || intrs == 0 ||
           scratchpads != 0 || ext < 0x20 || ext >= op ||
           runtime < op + operational_size || doorbell < op + operational_size ||
           !range(op, operational_size, aperture) || !range(runtime, 0x40, aperture) ||
           !range(doorbell, 4, aperture) ||
           (runtime < doorbell + 4 && doorbell < runtime + 0x40) {
            return Err(b"unsupported xHCI capability/register profile");
        }
        Ok(Self { version, op, runtime, doorbell, slots: slots.min(8), ports,
                  ac64: raw[4]&1 != 0, ppc: raw[4]&8 != 0, ext })
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PortProtocol { pub major: u8, pub slot_type: u8 }
impl PortProtocol { const NONE: Self = Self { major: 0, slot_type: 0 }; }

// The first profile supports standard USB2/USB3 speed IDs only. Never
// traverse a capability outside the assigned BAR. Refuse firmware legacy
// ownership rather than taking over an SMI-producing controller implicitly.
pub fn protocols(caps: Caps, aperture: usize, mut read: impl FnMut(usize) -> u32)
    -> Result<[PortProtocol; MAX_PORTS], Error>
{
    let mut table = [PortProtocol::NONE; MAX_PORTS];
    let mut at = caps.ext;
    for _ in 0..64 {
        if at < 0x20 || at%4 != 0 || !range(at,4,aperture) {
            return Err(b"xHCI extended capability outside BAR");
        }
        let head = read(at);
        let id = head as u8;
        let next = ((head >> 8)&255) as usize * 4;
        if id == 0 || id == 255 { return Err(b"xHCI malformed extended capability"); }
        if id == 1 { return Err(b"xHCI legacy BIOS ownership handoff not implemented"); }
        if id == 2 {
            if !range(at,16,aperture) || (next != 0 && next < 16) {
                return Err(b"xHCI truncated protocol capability");
            }
            let major = (head >> 24) as u8;
            let ports = read(at+8);
            let first = (ports&255) as usize;
            let count = ((ports>>8)&255) as usize;
            let slot_type = (read(at+12)&31) as u8;
            if read(at+4) != 0x20425355 || !matches!(major,2|3) ||
               first == 0 || count == 0 || first-1+count > usize::from(caps.ports) ||
               ports>>28 != 0 {
                return Err(b"unsupported xHCI port protocol/speed table");
            }
            for entry in &mut table[first-1..first-1+count] {
                if *entry != PortProtocol::NONE { return Err(b"xHCI overlapping port protocols"); }
                *entry = PortProtocol { major, slot_type };
            }
        }
        if next == 0 {
            if table[..usize::from(caps.ports)].iter().any(|p| p.major == 0) {
                return Err(b"xHCI missing port protocol");
            }
            return Ok(table);
        }
        at = at.checked_add(next).ok_or(b"xHCI extended capability overflow" as Error)?;
    }
    Err(b"xHCI extended capability traversal limit")
}

// PORTSC mixes read-only, W1C, W1S and RW fields. Never echo the raw value.
// Preserve power, port indicators and wake-enable bits only.
pub fn port_write(old: u32, actions: u32) -> u32 {
    (old & (PP | (3<<14) | (7<<25))) | actions
}
pub fn speed(status: u32, proto: PortProtocol) -> Result<u8, Error> {
    let id = ((status >> 10) & 15) as u8;
    if status & (CCS|PED|PR|PP) != CCS|PED|PP ||
       (status >> 5)&15 != 0 ||
       !((proto.major == 2 && (1..=3).contains(&id)) || (proto.major == 3 && id == 4)) {
        return Err(b"xHCI port not enabled at supported speed");
    }
    Ok(id)
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Trb { pub parameter: u64, pub status: u32, pub control: u32 }
impl Trb {
    pub fn kind(self) -> u8 { ((self.control >> 10)&63) as u8 }
    pub fn cycle(self) -> bool { self.control & 1 != 0 }
    pub fn slot(self) -> u8 { (self.control >> 24) as u8 }
    pub fn code(self) -> u8 { (self.status >> 24) as u8 }
    pub fn command(kind: u8, slot: u8, slot_type: u8, cycle: bool) -> Result<Self, Error> {
        if !((kind == NOOP && slot == 0 && slot_type == 0) ||
             (kind == ENABLE_SLOT && slot == 0 && slot_type < 32) ||
             (kind == DISABLE_SLOT && slot != 0 && slot_type == 0)) {
            return Err(b"xHCI unsupported command");
        }
        Ok(Self { parameter: 0, status: 0, control: (u32::from(kind)<<10) |
            (u32::from(slot)<<24) | (u32::from(slot_type)<<16) | cycle as u32 })
    }
    pub fn link(base: u64, cycle: bool) -> Self {
        Self { parameter: base, status: 0, control: (u32::from(LINK)<<10) | 2 | cycle as u32 }
    }
    pub fn port(self, max: u8) -> Result<u8, Error> {
        let port = (self.parameter >> 24) as u8;
        if self.kind()!=PORT_CHANGE || self.code()!=1 || self.slot()!=0 ||
           self.parameter != u64::from(port)<<24 || port == 0 || port > max {
            return Err(b"xHCI invalid port status event");
        }
        Ok(port)
    }
}
#[derive(Clone, Copy, Debug)]
pub struct Ticket { pub index: usize, pub cycle: bool, pub pointer: u64, pub kind: u8, pub slot: u8 }
pub struct CommandRing {
    base: u64, next: usize, cycle: bool, pending: Option<Ticket>, completed: usize,
}
impl CommandRing {
    pub fn new(base: u64) -> Self {
        assert!(base != 0 && base % 64 == 0);
        Self { base, next: 0, cycle: true, pending: None, completed: 0 }
    }
    pub fn submit(&mut self, kind: u8, slot: u8, slot_type: u8) -> Result<(Ticket,Trb,Option<Trb>),Error> {
        if self.pending.is_some() { return Err(b"xHCI command still owned"); }
        let trb = Trb::command(kind,slot,slot_type,self.cycle)?;
        let ticket = Ticket { index:self.next, cycle:self.cycle,
            pointer:self.base+16*self.next as u64, kind,slot };
        self.next += 1;
        let link = if self.next == COMMANDS-1 {
            let link=Trb::link(self.base,self.cycle);
            self.next=0; self.cycle=!self.cycle;
            Some(link)
        } else {None};
        self.pending=Some(ticket);
        Ok((ticket,trb,link))
    }
    pub fn complete(&mut self, event: Trb, max_slots: u8) -> Result<u8,Error> {
        let t=self.pending.ok_or(b"xHCI completion without command" as Error)?;
        let slot=event.slot();
        if event.kind()!=COMMAND_COMPLETE || event.parameter!=t.pointer || event.code()!=1 ||
           (t.kind==ENABLE_SLOT && (slot==0 || slot>max_slots)) ||
           (t.kind!=ENABLE_SLOT && slot!=t.slot) {
            return Err(b"xHCI command completion identity/status");
        }
        self.pending=None; self.completed+=1;
        Ok(slot)
    }
    pub fn count(&self)->usize{self.completed}
    pub fn pending(&self)->bool{self.pending.is_some()}
}
pub struct EventRing { index: usize, cycle: bool, consumed: usize }
impl EventRing {
    pub const fn new()->Self{Self{index:0,cycle:true,consumed:0}}
    pub fn index(&self)->usize{self.index}
    pub fn ready(&self,control:u32)->bool{(control&1!=0)==self.cycle}
    pub fn consume(&mut self,event:Trb)->Result<(),Error>{
        if event.cycle()!=self.cycle{return Err(b"xHCI stale event cycle");}
        self.index+=1; self.consumed+=1;
        if self.index==EVENTS{self.index=0;self.cycle=!self.cycle;}
        Ok(())
    }
    pub fn count(&self)->usize{self.consumed}
}
#[cfg(test)]
mod tests {
    use super::*;
    fn cap()->[u32;7]{[0x01000040,0x04000120,15,0,0x00080001,0x2000,0x1000]}
    fn proto(c:Caps)->Result<[PortProtocol;MAX_PORTS],Error>{
        protocols(c,0x4000,|at|match at{
            0x20=>0x02000402,0x24=>0x20425355,0x28=>0x0203,0x2c=>0,
            0x30=>0x03000002,0x34=>0x20425355,0x38=>0x0201,0x3c=>0,_=>0})
    }
    #[test]
    fn registerAndProtocolBounds(){
        let c=Caps::parse(cap(),0x4000).unwrap();
        assert_eq!((c.op,c.runtime,c.doorbell,c.slots,c.ports),(0x40,0x1000,0x2000,8,4));
        assert_eq!(proto(c).unwrap()[2].major,2);
        assert_eq!(proto(c).unwrap()[0].major,3);
        for (i,value) in [(0,0x01000004),(1,0),(2,1<<27),(4,0),(5,0x1000),(6,0x300)]{
            let mut raw=cap();raw[i]=value;assert!(Caps::parse(raw,0x4000).is_err());
        }
        assert!(Caps::parse(cap(),0x1000).is_err());
        assert!(protocols(c,0x4000,|_|1).is_err());
        assert!(protocols(c,0x4000,|_|0x0200ff02).is_err());
        assert!(protocols(c,0x4000,|at|match at{0x20=>0x02000402,0x24=>0x20425355,
            0x28=>0x0301,0x30=>0x03000002,0x34=>0x20425355,0x38=>0x0203,_=>0}).is_err());
    }
    #[test]
    fn commandAndEventOwnershipWrap(){
        let base=0x100000;
        let mut cmd=CommandRing::new(base);let mut event=EventRing::new();
        for i in 0..80 {
            let (t,trb,link)=cmd.submit(NOOP,0,0).unwrap();
            assert_eq!(t.index,i%15);assert_eq!(trb.cycle(),i/15%2==0);
            assert_eq!(link.is_some(),i%15==14);
            if let Some(l)=link{assert_eq!(l,Trb::link(base,t.cycle));}
            assert!(cmd.submit(NOOP,0,0).is_err());
            let mut e=Trb{parameter:t.pointer,status:1<<24,control:(33<<10)|(i/16%2==0) as u32};
            assert!(event.ready(e.control));
            assert!(cmd.complete(Trb{parameter:t.pointer+16,..e},8).is_err());
            assert!(cmd.complete(Trb{status:5<<24,..e},8).is_err());
            assert!(cmd.pending());
            assert_eq!(cmd.complete(e,8),Ok(0));event.consume(e).unwrap();
            e.control^=1; // only stale cycle is rejected
            assert_eq!(event.index(),(i+1)%16);
            assert_eq!(cmd.count(),i+1);
        }
        assert_eq!(event.count(),80);
        let (t,_,_)=cmd.submit(ENABLE_SLOT,0,0).unwrap();
        let e=Trb{parameter:t.pointer,status:1<<24,control:(33<<10)|(9<<24)};
        assert!(cmd.complete(e,8).is_err());
        assert_eq!(cmd.complete(Trb{control:(33<<10)|(2<<24),..e},8),Ok(2));
        assert!(Trb::command(DISABLE_SLOT,0,0,true).is_err());
    }
    #[test]
    fn portWritesAndSpeed(){
        assert_eq!(port_write(u32::MAX,PR),PP|(3<<14)|(7<<25)|PR);
        let p=PortProtocol{major:2,slot_type:0};
        assert_eq!(speed(CCS|PED|PP|(3<<10),p),Ok(3));
        assert!(speed(CCS|PP|(3<<10),p).is_err());
        assert!(speed(CCS|PED|PP|(4<<10),p).is_err());
        let e=Trb{parameter:3<<24,status:1<<24,control:34<<10};
        assert_eq!(e.port(4),Ok(3));
        assert!(e.port(2).is_err());
    }
}
