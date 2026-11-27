//! Qualified, normalized invariant TSC as a monotonic clocksource.
//! Boot calibration and CPU synchronization are independent of runtime
//! conversion. No PIT programming or scheduler deadline is a time sample.
use crate::{clock_quorum::{TscBracket,Witness}, tsc::{Peer,QualifiedRate},
    cpu_topology::{CpuRoster, MAX_CPUS}};
const MAX_ALIGNMENT_NS: u128 = 100_000;

/// Exact immutable CPU qualification records; CPU state is kept alive
/// throughout the boot session.
pub(crate) struct Roster<'a> {
    cpus: CpuRoster,
    peers: [Option<&'a Peer>; MAX_CPUS],
    bsp: u32,
    rate: QualifiedRate,
}

impl<'a> Roster<'a> {
    pub(crate) fn qualify(bsp:u32, ids:&[u32],
        members:impl IntoIterator<Item=(u32,&'a Peer)>) -> Option<Self> {
        let cpus=CpuRoster::from_ids(ids.iter().copied())?;
        let bsp_slot=cpus.slot(bsp)?.index();
        let mut peers:[Option<&Peer>;MAX_CPUS]=[None;MAX_CPUS];
        for (id,peer) in members {
            let index=cpus.slot(id)?.index();
            if peers[index].is_some() || peers.iter().flatten().any(|p| core::ptr::eq(*p,peer)) {
                return None;
            }
            peers[index]=Some(peer);
        }
        let bsp_peer=peers[bsp_slot]?;
        let rate=bsp_peer.qualification()?;
        let hz=rate.hz() as u128;
        for (index,peer) in peers.iter().enumerate() {
            if (index<cpus.ids().len())!=peer.is_some() { return None; }
            if let Some(peer)=peer {
                let local=peer.qualification()?;
                let a=peer.alignment()?;
                if !crate::tsc::rates_match(rate,local) ||
                   a.uncertainty_ticks as u128*1_000_000_000>hz*MAX_ALIGNMENT_NS {
                    return None;
                }
                if index==bsp_slot && (a.offset!=0 || a.uncertainty_ticks!=0) {
                    return None;
                }
            }
        }
        for peer in peers.iter().flatten() {
            if !peer.seal() { return None; }
        }
        Some(Self{cpus,peers,bsp,rate})
    }

    fn bracket(&self,s:Sample)->Result<TscBracket,Fault> {
        let index=self.cpus.slot(s.id).ok_or(Fault::UnknownCpu)?.index();
        let peer=self.peers[index].ok_or(Fault::UnknownCpu)?;
        let a=peer.alignment().ok_or(Fault::UnqualifiedCpu)?;
        let local=peer.qualification().ok_or(Fault::UnqualifiedCpu)?;
        if !crate::tsc::rates_match(self.rate,local) ||
            a.uncertainty_ticks as u128*1_000_000_000>
                self.rate.hz() as u128*MAX_ALIGNMENT_NS {
            return Err(Fault::UnqualifiedCpu);
        }
        let w=Witness{cpu:s.id,hz:self.rate.hz(),
            ticks:a.normalize(s.raw).ok_or(Fault::Normalization)?,
            uncertainty_ticks:a.uncertainty_ticks};
        TscBracket::checked(w,w).map_err(|_|Fault::Normalization)
    }
}

/// Prefer an already qualified physical epoch. A failed qualification
/// cannot authorize a TSC clocksource.
pub(crate) enum BootSource<'a> { Physical, Tsc(Roster<'a>) }

pub(crate) fn select<'a>(physical_ready:bool,
    qualify:impl FnOnce()->Option<Roster<'a>>) -> Option<BootSource<'a>> {
    if physical_ready { Some(BootSource::Physical) }
    else { qualify().map(BootSource::Tsc) }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Sample { pub id:u32, pub raw:u64 }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum Fault {
    UnknownCpu=1, UnqualifiedCpu=2, Normalization=3, RawRegression=4,
    GlobalRegression=5, Stalled=6,
}

impl Fault {
    pub(crate) fn from_code(code:u8)->Option<Self> {
        Some(match code {
            1=>Self::UnknownCpu,2=>Self::UnqualifiedCpu,3=>Self::Normalization,
            4=>Self::RawRegression,5=>Self::GlobalRegression,6=>Self::Stalled,
            _=>return None,
        })
    }
    pub(crate) fn message(self)->&'static [u8] {
        match self {
            Self::UnknownCpu=>b"SYSTEM CLOCK: TSC unavailable: CPU outside qualified roster",
            Self::UnqualifiedCpu=>b"SYSTEM CLOCK: TSC unavailable: invalid CPU qualification",
            Self::Normalization=>b"SYSTEM CLOCK: TSC unavailable: normalized counter out of range",
            Self::RawRegression=>b"SYSTEM CLOCK: TSC unavailable: local raw counter regressed",
            Self::GlobalRegression=>b"SYSTEM CLOCK: TSC unavailable: disjoint cross-CPU regression",
            Self::Stalled=>b"SYSTEM CLOCK: TSC unavailable: LAPIC progress detected stall",
        }
    }
}

/// Fixed origin and greatest proven lower bound. Overlapping alignment
/// uncertainty can clamp a read, but cannot hide disjoint regression.
pub(crate) struct Epoch<'a> {
    roster:Roster<'a>,
    origin:TscBracket,
    latest:TscBracket,
    last_raw:[u64;MAX_CPUS],
    seen:[bool;MAX_CPUS],
    published:u128,
    fault:Option<Fault>,
}

impl<'a> Epoch<'a> {
    pub(crate) fn new(roster:Roster<'a>,first:Sample)->Option<Self> {
        if first.id!=roster.bsp { return None; }
        let initial=roster.bracket(first).ok()?;
        let mut last_raw=[0;MAX_CPUS];
        let mut seen=[false;MAX_CPUS];
        for (id,peer) in roster.peers.iter().enumerate() {
            if let Some(peer)=peer {
                last_raw[id]=peer.last_verified_raw();
                seen[id]=true;
            }
        }
        let index=roster.cpus.slot(first.id)?.index();
        if first.raw<last_raw[index] {return None;}
        last_raw[index]=first.raw;
        seen[index]=true;
        Some(Self{roster,origin:initial,latest:initial,last_raw,seen,published:0,fault:None})
    }

    pub(crate) fn invalidate(&mut self,fault:Fault)->Fault {
        *self.fault.get_or_insert(fault)
    }
    pub(crate) fn failed(&self)->bool { self.fault.is_some() }
    pub(crate) fn fault(&self)->Option<Fault> { self.fault }

    pub(crate) fn observe(&mut self,s:Sample)->Result<u128,Fault> {
        if let Some(fault)=self.fault { return Err(fault); }
        let result=(|| {
            let current=self.roster.bracket(s)?;
            let index=self.roster.cpus.slot(s.id).ok_or(Fault::UnknownCpu)?.index();
            if self.seen[index] && s.raw<self.last_raw[index] {return Err(Fault::RawRegression);}
            let latest=self.latest.advance(current).ok_or(Fault::GlobalRegression)?;
            let elapsed=self.origin.elapsed(latest).ok_or(Fault::GlobalRegression)?.low;
            self.last_raw[index]=s.raw;
            self.seen[index]=true;
            self.latest=latest;
            self.published=self.published.max(elapsed);
            Ok(self.published)
        })();
        match result { Ok(time)=>Ok(time),Err(fault)=>Err(self.invalidate(fault)) }
    }
}
