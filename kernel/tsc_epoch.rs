//! A global TSC epoch published only after all enabled CPUs have been
//! independently rate-qualified and aligned to the BSP. Finite PIT
//! windows independently corroborate each observation. No modulo wrap
//! reconstruction or self-renewing TSC watchdog is allowed.
use crate::{clock_quorum::{Span, TscBracket, Witness}, pit, tsc::Alignment};

const MAX_ID: usize = 256;
const MAX_ALIGNMENT_NS: u128 = 100_000;
const MAX_REARM_NS: u128 = 500_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Member {
    pub id: u8,
    pub hz: u64,
    pub alignment: Alignment,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Sample {
    pub member: Member,
    pub raw: u64,
}

fn rate_matches(a: u64, b: u64) -> bool {
    a != 0 && b != 0 && a.abs_diff(b) as u128 * 1000 <= a.min(b) as u128
}

fn bit(id: u8) -> (usize, u64) {
    (id as usize/64, 1u64 << (id%64))
}

fn valid_member(hz: u64, member: Member) -> bool {
    rate_matches(hz, member.hz) &&
        member.alignment.uncertainty_ticks as u128 * 1_000_000_000 <=
            hz as u128 * MAX_ALIGNMENT_NS
}

pub(crate) struct Roster {
    mask: [u64; 4],
    hz: u64,
}

impl Roster {
    /// Exact enabled topology, not the number of successful responders.
    /// A missing CPU, duplicate ID, mismatched rate or unbounded offset
    /// prevents publication, including on single-CPU machines.
    pub(crate) fn qualify(bsp: u8, hz: u64, ids: &[u8],
                          members: impl IntoIterator<Item=Member>) -> Option<Self> {
        let mut expected = [0u64;4];
        for &id in ids {
            let (word, flag)=bit(id);
            if expected[word]&flag != 0 { return None; }
            expected[word]|=flag;
        }
        let mut actual=[0u64;4];
        let (word,flag)=bit(bsp);
        if hz==0 || expected[word]&flag==0 { return None; }
        for member in members {
            let (word,flag)=bit(member.id);
            if expected[word]&flag==0 || actual[word]&flag!=0 || !valid_member(hz,member) {
                return None;
            }
            if member.id==bsp && (member.hz!=hz ||
                member.alignment.offset!=0 || member.alignment.uncertainty_ticks!=0) {
                return None;
            }
            actual[word]|=flag;
        }
        (actual==expected).then_some(Self{mask:expected,hz})
    }

    fn bracket(&self, before: Sample, after: Sample) -> Option<TscBracket> {
        let member=before.member;
        let (word,flag)=bit(member.id);
        if member!=after.member || self.mask[word]&flag==0 ||
           !valid_member(self.hz,member) || after.raw<before.raw {
            return None;
        }
        let witness=|sample:Sample| Some(Witness {
            cpu:member.id, hz:self.hz,
            ticks:member.alignment.normalize(sample.raw)?,
            uncertainty_ticks:member.alignment.uncertainty_ticks,
        });
        TscBracket::new(witness(before)?,witness(after)?)
    }
}

pub(crate) struct Epoch {
    roster: Roster,
    origin: TscBracket,
    window: TscBracket,
    previous: TscBracket,
    window_count: u16,
    count: u16,
    last_raw: [u64;MAX_ID],
    seen: [u64;4],
    published: u128,
    failed: bool,
}

impl Epoch {
    pub(crate) fn new(roster: Roster, before: Sample, after: Sample, count: u16) -> Option<Self> {
        if count==0 || count<=pit::REARM_COUNT {return None;}
        let initial=roster.bracket(before,after)?;
        let mut epoch=Self { roster, origin:initial,window:initial,previous:initial,
            window_count:count,count,last_raw:[0;MAX_ID],seen:[0;4],
            published:0,failed:false };
        epoch.record(before,after)?;
        Some(epoch)
    }

    fn record(&mut self, before: Sample, after: Sample) -> Option<TscBracket> {
        let current=self.roster.bracket(before,after)?;
        let id=before.member.id;
        let (word,flag)=bit(id);
        if self.seen[word]&flag!=0 && before.raw<self.last_raw[id as usize] {
            return None;
        }
        self.seen[word]|=flag;
        self.last_raw[id as usize]=after.raw;
        Some(current)
    }

    pub(crate) fn invalidate(&mut self) { self.failed=true; }
    pub(crate) fn failed(&self)->bool { self.failed }

    /// Both adjacent samples and the complete finite window must agree.
    /// The PIT counts are independently observed; TSC cannot invent
    /// elapsed ticks. Overlap between bounded cross-CPU offset intervals
    /// may clamp publication but never move it backward.
    pub(crate) fn observe(&mut self, before: Sample, after: Sample, count: u16) -> Option<u128> {
        if self.failed {return None;}
        let result=(|| {
            let current=self.record(before,after)?;
            let step=pit::count_elapsed_ns(self.count,count)?;
            let total=pit::count_elapsed_ns(self.window_count,count)?;
            if !Span::exact(step).agrees(self.previous.elapsed(current)?) ||
               !Span::exact(total).agrees(self.window.elapsed(current)?) {
                return None;
            }
            let time=self.origin.elapsed(current)?.low.max(self.published);
            self.previous=current;
            self.count=count;
            self.published=time;
            Some(time)
        })();
        if result.is_none(){self.invalidate();}
        result
    }

    /// A fresh count starts a new independent rate-check window, not a
    /// new global epoch. Reset overhead is bracketed and bounded; time
    /// from the reset is not itself published as independent evidence.
    pub(crate) fn rearm(&mut self,before:Sample,after:Sample,count:u16)->bool {
        if self.failed{return false;}
        let result=(||{
            if self.count>pit::REARM_COUNT || count<=pit::REARM_COUNT{return None;}
            let current=self.record(before,after)?;
            if self.previous.elapsed(current)?.high>MAX_REARM_NS{return None;}
            self.previous=current;
            self.window=current;
            self.window_count=count;
            self.count=count;
            Some(())
        })();
        if result.is_none(){self.invalidate();}
        result.is_some()
    }
}
