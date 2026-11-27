//! Qualified, normalized invariant TSC as a monotonic clocksource.
//! Boot calibration and CPU synchronization are independent of runtime
//! conversion. No PIT programming or scheduler deadline is a time sample.
use crate::{clock_quorum::{TscBracket,Witness}, tsc::{Peer,QualifiedRate},
    cpu_topology::{CpuRoster, MAX_CPUS}};
const MAX_ALIGNMENT_NS: u128 = 100_000;

/// Exact immutable CPU qualification records; CPU state is kept alive
/// throughout the boot session.
struct Roster<'a> {
    cpus: CpuRoster,
    peers: [Option<&'a Peer>; MAX_CPUS],
    bsp: u32,
    rate: Option<QualifiedRate>,
}

impl<'a> Roster<'a> {
    const fn empty() -> Self {
        Self { cpus:CpuRoster::new(), peers:[None;MAX_CPUS], bsp:0, rate:None }
    }

    fn clear(&mut self) {
        self.rate=None;
        self.bsp=0;
        self.cpus.clear();
        self.peers.fill(None);
    }

    // Fill the destination owned by the clock. The caller resets it on
    // every error; no reader can see it before a complete epoch is ready.
    fn qualify(&mut self, bsp:u32, ids:&[u32],
        members:impl IntoIterator<Item=(u32,&'a Peer)>) -> Option<()> {
        for &id in ids { self.cpus.insert(id)?; }
        let bsp_slot=self.cpus.slot(bsp)?.index();
        for (id,peer) in members {
            let index=self.cpus.slot(id)?.index();
            if self.peers[index].is_some() || self.peers.iter().flatten().any(|p| core::ptr::eq(*p,peer)) {
                return None;
            }
            self.peers[index]=Some(peer);
        }
        let bsp_peer=self.peers[bsp_slot]?;
        let rate=bsp_peer.qualification()?;
        let hz=rate.hz() as u128;
        for (index,peer) in self.peers.iter().enumerate() {
            if (index<self.cpus.ids().len())!=peer.is_some() { return None; }
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
        for peer in self.peers.iter().flatten() {
            if !peer.seal() { return None; }
        }
        self.bsp=bsp;
        self.rate=Some(rate);
        Some(())
    }

    fn bracket(&self,s:Sample)->Result<TscBracket,Fault> {
        let index=self.cpus.slot(s.id).ok_or(Fault::UnknownCpu)?.index();
        let peer=self.peers[index].ok_or(Fault::UnknownCpu)?;
        let a=peer.alignment().ok_or(Fault::UnqualifiedCpu)?;
        let local=peer.qualification().ok_or(Fault::UnqualifiedCpu)?;
        let rate=self.rate.ok_or(Fault::UnqualifiedCpu)?;
        if !crate::tsc::rates_match(rate,local) ||
            a.uncertainty_ticks as u128*1_000_000_000>
                rate.hz() as u128*MAX_ALIGNMENT_NS {
            return Err(Fault::UnqualifiedCpu);
        }
        let w=Witness{cpu:s.id,hz:rate.hz(),
            ticks:a.normalize(s.raw).ok_or(Fault::Normalization)?,
            uncertainty_ticks:a.uncertainty_ticks};
        TscBracket::checked(w,w).map_err(|_|Fault::Normalization)
    }
}

/// Prefer an already qualified physical epoch. A failed qualification
/// cannot authorize a TSC clocksource.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum BootSource { Physical, Tsc }

pub(crate) fn select<E>(physical_ready:bool,
    publish:impl FnOnce()->Result<(),E>) -> Result<BootSource,E> {
    if physical_ready { Ok(BootSource::Physical) }
    else { publish().map(|()| BootSource::Tsc) }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum InitError { Roster, Sample, AlreadyPublished }

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
/// This small value is the commit point for the initialized history.
struct Timeline {
    origin:TscBracket,
    latest:TscBracket,
    published:u128,
}

pub(crate) struct Epoch<'a> {
    roster:Roster<'a>,
    timeline:Option<Timeline>,
    last_raw:[u64;MAX_CPUS],
    seen:[bool;MAX_CPUS],
    fault:Option<Fault>,
}

impl<'a> Epoch<'a> {
    pub(crate) const fn empty()->Self {
        Self { roster:Roster::empty(), timeline:None, last_raw:[0;MAX_CPUS],
            seen:[false;MAX_CPUS], fault:None }
    }

    fn reset_unpublished(&mut self) {
        debug_assert!(self.timeline.is_none());
        self.roster.clear();
        self.last_raw.fill(0);
        self.seen.fill(false);
        self.fault=None;
    }

    /// A clock owner exclusively borrows its final storage until this
    /// returns. Failed qualification or initial sampling leaves it empty;
    /// an already published (even failed) epoch cannot be rebased.
    pub(crate) fn initialize(&mut self, bsp:u32, ids:&[u32],
        members:impl IntoIterator<Item=(u32,&'a Peer)>,
        first:impl FnOnce()->Sample)->Result<(),InitError> {
        if self.timeline.is_some() { return Err(InitError::AlreadyPublished); }
        self.reset_unpublished();
        if self.roster.qualify(bsp,ids,members).is_none() {
            self.reset_unpublished();
            return Err(InitError::Roster);
        }
        // As before, sample the BSP only after the complete roster is sealed.
        if self.initialize_history(first()).is_none() {
            self.reset_unpublished();
            return Err(InitError::Sample);
        }
        Ok(())
    }

    fn initialize_history(&mut self, first:Sample)->Option<()> {
        if first.id!=self.roster.bsp { return None; }
        let initial=self.roster.bracket(first).ok()?;
        for (index,peer) in self.roster.peers.iter().enumerate() {
            if let Some(peer)=peer {
                self.last_raw[index]=peer.last_verified_raw();
                self.seen[index]=true;
            }
        }
        let index=self.roster.cpus.slot(first.id)?.index();
        if first.raw<self.last_raw[index] {return None;}
        self.last_raw[index]=first.raw;
        self.seen[index]=true;
        self.timeline=Some(Timeline{origin:initial,latest:initial,published:0});
        Some(())
    }

    pub(crate) fn invalidate(&mut self,fault:Fault)->Fault {
        *self.fault.get_or_insert(fault)
    }
    pub(crate) fn failed(&self)->bool { self.fault.is_some() }
    pub(crate) fn fault(&self)->Option<Fault> { self.fault }

    pub(crate) fn observe(&mut self,s:Sample)->Result<u128,Fault> {
        if let Some(fault)=self.fault { return Err(fault); }
        // An unpublished epoch cannot serve any time or establish a fault
        // in a future, independently qualified epoch.
        let Some(timeline)=self.timeline.as_mut() else { return Err(Fault::UnqualifiedCpu); };
        let result=(|| {
            let current=self.roster.bracket(s)?;
            let index=self.roster.cpus.slot(s.id).ok_or(Fault::UnknownCpu)?.index();
            if self.seen[index] && s.raw<self.last_raw[index] {return Err(Fault::RawRegression);}
            let latest=timeline.latest.advance(current).ok_or(Fault::GlobalRegression)?;
            let elapsed=timeline.origin.elapsed(latest).ok_or(Fault::GlobalRegression)?.low;
            self.last_raw[index]=s.raw;
            self.seen[index]=true;
            timeline.latest=latest;
            timeline.published=timeline.published.max(elapsed);
            Ok(timeline.published)
        })();
        match result { Ok(time)=>Ok(time),Err(fault)=>Err(self.invalidate(fault)) }
    }
}
