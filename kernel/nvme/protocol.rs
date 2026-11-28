//! Wire encoding and single-outstanding-command queue state.
pub type Error = &'static [u8];
pub const PAGE: usize = 4096;
pub const DEPTH: u16 = 8;

#[derive(Clone, Copy)]
pub struct Capabilities { pub depth: u16, pub stride: usize, pub timeout_ms: u64 }
impl Capabilities {
    pub fn parse(cap: u64, aperture: u64) -> Result<Self, Error> {
        if cap & (1 << 37) == 0 || (cap >> 48) & 15 != 0 {
            return Err(b"NVMe requires NVM commands and 4K pages");
        }
        let depth = (u32::from(cap as u16) + 1).min(u32::from(DEPTH)) as u16;
        let stride = 4usize << ((cap >> 32) & 15);
        let timeout_ms = ((cap >> 24) & 255).max(1) * 500;
        if depth < 2 || stride > 1024 || aperture < (0x1000 + 3 * stride + 4) as u64 ||
            timeout_ms > 30000 {
            return Err(b"unsupported NVMe queue/doorbell/timeout profile");
        }
        Ok(Self { depth, stride, timeout_ms })
    }
}
pub fn geometry(ns: &[u8; PAGE]) -> Result<(u64, usize), Error> {
    let blocks = u64::from_le_bytes(ns[0..8].try_into().unwrap());
    let capacity = u64::from_le_bytes(ns[8..16].try_into().unwrap());
    let flbas = ns[26];
    let format = usize::from(flbas & 15);
    if blocks == 0 || capacity == 0 || capacity > blocks || flbas & 0xf0 != 0 ||
        format > usize::from(ns[25]) || ns[29] & 7 != 0 {
        return Err(b"unsupported NVMe namespace geometry");
    }
    let offset = 128 + 4 * format;
    let shift = ns[offset + 2];
    if ns[offset] != 0 || ns[offset + 1] != 0 || !(9..=12).contains(&shift) {
        return Err(b"unsupported NVMe sector or metadata format");
    }
    Ok((blocks, 1usize << shift))
}
pub fn command(opcode: u8, nsid: u32, prp: u64, cdw10: u32, cdw11: u32, cdw12: u32) -> [u32; 16] {
    let mut words = [0; 16];
    words[0] = u32::from(opcode);
    words[1] = nsid;
    words[6] = prp as u32;
    words[7] = (prp >> 32) as u32;
    words[10] = cdw10;
    words[11] = cdw11;
    words[12] = cdw12;
    words
}
pub fn io(opcode: u8, lba: u64, blocks: u16, prp: u64) -> Result<[u32; 16], Error> {
    match opcode {
        0 if lba == 0 && blocks == 0 && prp == 0 => Ok(command(0, 1, 0, 0, 0, 0)),
        1 | 2 if blocks != 0 && prp != 0 && prp & (PAGE as u64 - 1) == 0 =>
            Ok(command(opcode, 1, prp, lba as u32, (lba >> 32) as u32, u32::from(blocks - 1))),
        _ => Err(b"invalid NVMe I/O command"),
    }
}
#[derive(Clone, Copy)]
pub struct Submission { pub slot: u16, pub tail: u16, pub cid: u16 }
pub struct QueueState {
    depth: u16, tail: u16, head: u16, phase: bool, next_cid: u16,
    pending: Option<Submission>,
}
impl QueueState {
    pub fn new(depth: u16) -> Self {
        assert!((2..=DEPTH).contains(&depth));
        Self { depth, tail: 0, head: 0, phase: true, next_cid: 1, pending: None }
    }
    pub fn submit(&mut self, words: &mut [u32; 16]) -> Result<Submission, Error> {
        if self.pending.is_some() { return Err(b"NVMe queue already owns a command"); }
        let s = Submission { slot: self.tail, tail: (self.tail + 1) % self.depth, cid: self.next_cid };
        self.next_cid = self.next_cid.wrapping_add(1);
        self.tail = s.tail;
        words[0] = (words[0] & 0xffff) | (u32::from(s.cid) << 16);
        self.pending = Some(s);
        Ok(s)
    }
    pub fn head(&self) -> u16 { self.head }
    pub fn phase_matches(&self, status: u16) -> bool { (status & 1 != 0) == self.phase }
    pub fn complete(&mut self, qid: u16, sqid: u16, sqhd: u16, cid: u16, status: u16)
        -> Result<bool, Error>
    {
        let s = self.pending.ok_or(b"unexpected NVMe completion" as Error)?;
        if !self.phase_matches(status) || sqid != qid || sqhd != s.tail || cid != s.cid {
            return Err(b"NVMe completion identity or phase");
        }
        self.pending = None;
        self.head = (self.head + 1) % self.depth;
        if self.head == 0 { self.phase = !self.phase; }
        Ok(status >> 1 == 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn capability_limits_and_doorbells() {
        let cap = (1 << 37) | (2 << 24) | 7;
        let c = Capabilities::parse(cap, 8192).unwrap();
        assert_eq!((c.depth, c.stride, c.timeout_ms), (8, 4, 1000));
        for bad in [0, cap & !0xffff, cap | (1 << 48), cap | (15 << 32)] {
            assert!(Capabilities::parse(bad, 8192).is_err());
        }
        assert!(Capabilities::parse(cap, 4096).is_err());
    }
    #[test]
    fn namespace_formats_and_bounds() {
        let mut ns = [0; PAGE];
        ns[0..8].copy_from_slice(&16384u64.to_le_bytes());
        ns[8..16].copy_from_slice(&16384u64.to_le_bytes());
        ns[130] = 9;
        assert_eq!(geometry(&ns), Ok((16384, 512)));
        ns[25] = 1; ns[26] = 1; ns[134] = 12;
        assert_eq!(geometry(&ns), Ok((16384, 4096)));
        ns[132] = 8; assert!(geometry(&ns).is_err());
        ns[132] = 0; ns[26] = 0x11; assert!(geometry(&ns).is_err());
        ns[26] = 2; assert!(geometry(&ns).is_err());
        ns[26] = 0; ns[29] = 1; assert!(geometry(&ns).is_err());
        ns[29] = 0; ns[0..8].fill(0); assert!(geometry(&ns).is_err());
    }
    #[test]
    fn command_encoding() {
        let words = io(1, 0x1122334455667788, 8, 0x1_2345_6000).unwrap();
        assert_eq!([words[0], words[1], words[6], words[7], words[10], words[11], words[12]],
                   [1, 1, 0x23456000, 1, 0x55667788, 0x11223344, 7]);
        assert_eq!(io(0, 0, 0, 0).unwrap(), command(0, 1, 0, 0, 0, 0));
        assert!(io(2, 0, 0, 4096).is_err());
        assert!(io(2, 0, 1, 4097).is_err());
    }
    #[test]
    fn ownership_and_phase_wrap_reject_stale_or_foreign_completions() {
        let mut q = QueueState::new(2);
        let mut words = [0; 16];
        let first = q.submit(&mut words).unwrap();
        assert_eq!((first.slot, first.tail, first.cid, words[0]), (0, 1, 1, 1 << 16));
        assert!(q.submit(&mut words).is_err());
        for (sqid, sqhd, cid, status) in [(0,1,1,1), (1,0,1,1), (1,1,2,1), (1,1,1,0)] {
            assert!(q.complete(1, sqid, sqhd, cid, status).is_err());
        }
        assert_eq!(q.head(), 0);
        assert_eq!(q.complete(1, 1, 1, 1, 1), Ok(true));
        let second = q.submit(&mut words).unwrap();
        assert_eq!((second.slot, second.tail, second.cid), (1,0,2));
        assert_eq!(q.complete(1, 1, 0, 2, 3), Ok(false));
        assert_eq!(q.head(), 0);
        assert!(!q.phase_matches(1));
        let third = q.submit(&mut words).unwrap();
        assert_eq!(third.cid, 3);
        assert_eq!(q.complete(1, 1, 1, 3, 0), Ok(true));
    }
}
