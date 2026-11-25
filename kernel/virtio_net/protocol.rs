//! Modern VirtIO PCI capability parsing and one-in-flight split-ring ownership.
//! Wire state contains no MMIO or DMA pointers; test the same code on the host.
pub type Error = &'static [u8];
pub const PAGE: usize = 4096;
pub const DEPTH: u16 = 8;
pub const DESC: usize = 0;
pub const AVAIL: usize = 128;
pub const USED: usize = 256;
pub const HEADER: usize = 12; // modern virtio_net_hdr, including num_buffers
pub const MIN_FRAME: usize = 60;
pub const MAX_FRAME: usize = 1514; // Ethernet without FCS or VLAN/jumbo offload
pub const ROUNDS: usize = 12;
pub const TEST_LEN: usize = 96;
pub const PEER: [u8; 6] = [0x02, 0x41, 0x47, 0x4e, 0x54, 0x01];
pub const ETHERTYPE: [u8; 2] = [0x88, 0xb5];
pub const VERSION_1: u64 = 1 << 32;
pub const MAC: u64 = 1 << 5;
pub const MRG_RXBUF: u64 = 1 << 15;

#[derive(Clone, Copy, Debug)]
pub struct Region { pub bar: u8, pub offset: usize, pub len: usize }

impl Region {
    pub fn within(self, aperture: usize) -> bool {
        self.offset.checked_add(self.len).map_or(false, |end| end <= aperture)
    }
}

pub struct Layout {
    pub common: Region, pub notify: Region, pub isr: Region, pub device: Region,
    pub multiplier: usize,
}

fn word(cfg: &[u8; 256], at: usize) -> u32 {
    u32::from_le_bytes(cfg[at..at+4].try_into().unwrap())
}

pub fn layout(cfg: &[u8; 256]) -> Result<Layout, Error> {
    if cfg[6] & 16 == 0 || cfg[14] & 0x7f != 0 { return Err(b"VirtIO PCI capability list missing"); }
    let mut seen = 0u64;
    let mut at = usize::from(cfg[0x34]);
    let mut found = [None; 4];
    let mut multiplier = 0usize;
    while at != 0 {
        if !(0x40..=0xfc).contains(&at) || at & 3 != 0 || seen & (1u64 << (at/4)) != 0 {
            return Err(b"VirtIO malformed capability chain");
        }
        seen |= 1u64 << (at/4);
        if cfg[at] == 9 {
            let len = usize::from(cfg[at+2]);
            let kind = cfg[at+3];
            if len < 4 || at + len > 256 { return Err(b"VirtIO truncated vendor capability"); }
            if (1..=4).contains(&kind) {
                if len < 16 || (kind == 2 && len < 20) {
                    return Err(b"VirtIO truncated transport capability");
                }
                let region = Region { bar: cfg[at+4], offset: word(cfg, at+8) as usize,
                    len: word(cfg, at+12) as usize };
                let min = match kind { 1 => 56, 2 => 2, 3 => 1, _ => 6 };
                if region.bar >= 6 || region.len < min || region.offset.checked_add(region.len).is_none() ||
                   (kind == 1 && region.offset % 4 != 0) || (kind == 2 && region.offset % 2 != 0) {
                    return Err(b"VirtIO invalid transport aperture");
                }
                let slot = usize::from(kind-1);
                if found[slot].is_some() { return Err(b"VirtIO duplicate transport capability"); }
                if kind == 2 {
                    multiplier = word(cfg, at+16) as usize;
                    if multiplier != 0 && (multiplier < 2 || !multiplier.is_power_of_two()) {
                        return Err(b"VirtIO invalid notify multiplier");
                    }
                }
                found[slot] = Some(region);
            }
        }
        at = usize::from(cfg[at+1]);
    }
    let [Some(common), Some(notify), Some(isr), Some(device)] = found else {
        return Err(b"VirtIO modern transport incomplete");
    };
    let regions = [common, notify, isr, device];
    for (i, a) in regions.iter().enumerate() {
        for b in &regions[..i] {
            if a.bar == b.bar && a.offset < b.offset + b.len && b.offset < a.offset + a.len {
                return Err(b"VirtIO overlapping transport regions");
            }
        }
    }
    Ok(Layout { common, notify, isr, device, multiplier })
}

pub fn bar(cfg: &[u8; 256], target: u8) -> Result<(usize, bool), Error> {
    let mut i = 0;
    while i < 6 {
        let low = word(cfg, 0x10 + 4*i);
        let wide = low & 7 == 4;
        if wide && i == 5 { return Err(b"VirtIO truncated 64-bit BAR"); }
        if i == usize::from(target) {
            if low & 1 != 0 || (!wide && low & 7 != 0) { return Err(b"VirtIO needs memory BAR"); }
            let addr = u64::from(low & !15) |
                if wide { u64::from(word(cfg, 0x14 + 4*i)) << 32 } else { 0 };
            if addr == 0 || addr % PAGE as u64 != 0 { return Err(b"VirtIO unassigned or unaligned BAR"); }
            return Ok((addr as usize, wide));
        }
        i += if wide { 2 } else { 1 };
    }
    Err(b"VirtIO invalid BAR slot")
}

pub fn notify_offset(region: Region, multiplier: usize, queue_offset: u16) -> Result<usize, Error> {
    let delta = usize::from(queue_offset).checked_mul(multiplier).ok_or(b"VirtIO notify overflow" as Error)?;
    if delta.checked_add(2).map_or(true, |end| end > region.len) || delta & 1 != 0 {
        return Err(b"VirtIO notify outside BAR capability");
    }
    Ok(delta)
}

pub fn features(offered: u64) -> Result<u64, Error> {
    let required = VERSION_1 | MAC;
    if offered & required != required { return Err(b"VirtIO VERSION_1/MAC required"); }
    // Optional mergeable-RX feature: one descriptor is large enough for the
    // complete standard frame, so completion must still describe one buffer.
    Ok(required | (offered & MRG_RXBUF))
}

#[derive(Clone, Copy)]
pub struct Ticket { pub id: u16, pub slot: u16, pub next: u16 }

pub struct Ring {
    avail: u16, used: u16, active: Option<Ticket>,
}

impl Ring {
    pub const fn new() -> Self { Self { avail: 0, used: 0, active: None } }
    pub fn pending(&self) -> bool { self.active.is_some() }
    pub fn count(&self) -> u16 { self.used }
    pub fn slot(&self) -> usize { usize::from(self.used % DEPTH) }
    pub fn submit(&mut self) -> Result<Ticket, Error> {
        if self.active.is_some() || self.avail != self.used { return Err(b"VirtIO descriptor still owned by device"); }
        let ticket = Ticket { id: self.avail % DEPTH, slot: self.avail % DEPTH, next: self.avail.wrapping_add(1) };
        self.avail = ticket.next;
        self.active = Some(ticket);
        Ok(ticket)
    }
    pub fn ready(&self, observed: u16) -> Result<bool, Error> {
        let active = self.active.ok_or(b"VirtIO no outstanding descriptor" as Error)?;
        if observed == self.used { return Ok(false); }
        if observed != active.next { return Err(b"VirtIO unexpected used index"); }
        Ok(true)
    }
    pub fn complete(&mut self, observed: u16, id: u32, len: u32, rx: bool) -> Result<usize, Error> {
        if !self.ready(observed)? { return Err(b"VirtIO completion not published"); }
        let ticket = self.active.unwrap();
        let len = len as usize;
        if id != u32::from(ticket.id) ||
           (rx && !(HEADER+MIN_FRAME..=HEADER+MAX_FRAME).contains(&len)) ||
           (!rx && len != 0) { return Err(b"VirtIO invalid used descriptor identity/length"); }
        self.active = None;
        self.used = observed;
        Ok(if rx { len - HEADER } else { 0 })
    }
}

pub fn rx_header(header: &[u8; HEADER], merged: bool) -> Result<(), Error> {
    // With no checksum/GSO offloads, flags and GSO type must be zero.
    // Some modern non-MRG devices (including QEMU 8.2) leave the unused
    // num_buffers field untouched. Ownership is then exactly one descriptor.
    if header[0] != 0 || header[1] != 0 ||
       (merged && u16::from_le_bytes([header[10], header[11]]) != 1) {
        return Err(b"VirtIO invalid receive header");
    }
    Ok(())
}

pub fn mac_valid(mac: [u8; 6]) -> bool { mac[0] & 1 == 0 && mac != [0; 6] }

pub fn fnv(bytes: &[u8]) -> u32 {
    bytes.iter().fold(2166136261u32, |hash, &b| (hash ^ u32::from(b)).wrapping_mul(16777619))
}

// A deliberately private L2 acceptance protocol, not part of the network API.
pub fn reply(frame: &mut [u8], mac: [u8; 6]) -> Result<(), Error> {
    if frame.len() != TEST_LEN || frame[..6] != mac || frame[6..12] != PEER || frame[12..14] != ETHERTYPE {
        return Err(b"VirtIO unexpected test Ethernet frame");
    }
    frame[..6].copy_from_slice(&PEER);
    frame[6..12].copy_from_slice(&mac);
    for byte in &mut frame[14..] { *byte ^= 0xa5; }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn config() -> [u8; 256] {
        let mut cfg = [0u8; 256];
        cfg[6] = 16;
        cfg[0x34] = 0x40;
        cfg[0x20..0x24].copy_from_slice(&4u32.to_le_bytes());
        cfg[0x24..0x28].copy_from_slice(&0xc0u32.to_le_bytes());
        for (i, (kind, offset, len)) in [(1, 0u32, 56u32), (2, 0x1000, 64), (3, 0x2000, 1), (4, 0x3000, 6)].into_iter().enumerate() {
            let at = 0x40+20*i;
            cfg[at..at+5].copy_from_slice(&[9, if i == 3 {0} else {(at+20) as u8}, 20, kind, 4]);
            cfg[at+8..at+12].copy_from_slice(&offset.to_le_bytes());
            cfg[at+12..at+16].copy_from_slice(&len.to_le_bytes());
            if kind == 2 { cfg[at+16..at+20].copy_from_slice(&4u32.to_le_bytes()); }
        }
        cfg
    }
    #[test]
    fn capabilitiesAndHighBar() {
        let cfg = config();
        let l = layout(&cfg).unwrap();
        assert_eq!(bar(&cfg,4).unwrap(),(0xc000000000,true));
        assert!(bar(&cfg,5).is_err());
        assert_eq!(notify_offset(l.notify,l.multiplier,3),Ok(12));
        assert!(notify_offset(l.notify,l.multiplier,16).is_err());
        assert!(l.device.within(16384));
        assert!(!l.device.within(8192));
        for (at,v) in [(0x41,0x40),(0x42,8),(0x44,6),(0x54+16,3),(0x54+3,1),(0x40+8,2)] {
            let mut bad = cfg; bad[at]=v;
            assert!(layout(&bad).is_err(), "bad cap at {at:x}");
        }
        let mut overlap = cfg;
        overlap[0x54+8..0x54+12].fill(0);
        assert!(layout(&overlap).is_err());
    }
    #[test]
    fn featureSubsetAndReceiveHeader() {
        assert_eq!(features(u64::MAX),Ok(VERSION_1|MAC|MRG_RXBUF));
        assert!(features(MAC).is_err());
        assert!(features(VERSION_1).is_err());
        let mut h=[0;HEADER];
        assert!(rx_header(&h,false).is_ok());
        assert!(rx_header(&h,true).is_err());
        h[10]=1; assert!(rx_header(&h,true).is_ok());
        h[0]=1; assert!(rx_header(&h,true).is_err());
    }
    #[test]
    fn ringOwnershipAndSixteenBitWrap() {
        let mut ring=Ring::new();
        for i in 0..65539u32 {
            let t=ring.submit().unwrap();
            assert_eq!(t.id,(i%8) as u16);
            assert!(ring.submit().is_err());
            assert_eq!(ring.ready(i as u16),Ok(false));
            assert!(ring.ready(t.next.wrapping_add(1)).is_err());
            assert!(ring.complete(t.next,u32::from(t.id)^1,108,true).is_err());
            assert!(ring.complete(t.next,u32::from(t.id),4097,true).is_err());
            assert!(ring.pending());
            assert_eq!(ring.complete(t.next,u32::from(t.id),108,true),Ok(96));
            assert!(!ring.pending());
        }
        assert_eq!(ring.count(),3);
        let t=ring.submit().unwrap();
        assert!(ring.complete(t.next,u32::from(t.id),96,false).is_err());
        assert_eq!(ring.complete(t.next,u32::from(t.id),0,false),Ok(0));
    }
    #[test]
    fn testFrameTransformsOnlyAddressAndPayload() {
        let mac=[0x52,0x54,0,0x12,0x34,0x56];
        let mut frame=[0x10;TEST_LEN];
        frame[..6].copy_from_slice(&mac); frame[6..12].copy_from_slice(&PEER);
        frame[12..14].copy_from_slice(&ETHERTYPE);
        reply(&mut frame,mac).unwrap();
        assert_eq!(&frame[..6],&PEER); assert_eq!(&frame[6..12],&mac);
        assert_eq!(&frame[12..14],&ETHERTYPE); assert!(frame[14..].iter().all(|b|*b==0xb5));
        assert!(reply(&mut frame,mac).is_err());
    }
}
