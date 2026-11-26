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

/// First irreversible failure of an already published TSC/PIT epoch.
/// Codes are also retained in the timekeeper's operational crash state.
/// Zero is reserved for no recorded failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum Fault {
    LocalBefore = 1,
    LocalAfter = 2,
    PitInactive = 3,
    PitReadConfig = 4,
    PitReadTerminal = 5,
    PitReadNotLoaded = 6,
    PitReadOther = 7,
    InvalidBracket = 8,
    RawRegression = 9,
    LatePitCount = 10,
    StepCount = 11,
    WindowCount = 12,
    StepElapsed = 13,
    WindowElapsed = 14,
    StepMismatch = 15,
    WindowMismatch = 16,
    OriginElapsed = 17,
    RearmLocalBefore = 18,
    RearmLocalAfter = 19,
    RearmInactive = 20,
    RearmReadConfig = 21,
    RearmReadTerminal = 22,
    RearmReadNotLoaded = 23,
    RearmReadOther = 24,
    RearmOldCount = 25,
    RearmProgramConfig = 26,
    RearmProgramNoEdge = 27,
    RearmProgramRegression = 28,
    RearmProgramOther = 29,
    RearmCount = 30,
    RearmElapsed = 31,
    RearmTooLong = 32,
    Stalled = 33,
}

impl Fault {
    pub(crate) fn from_code(code: u8) -> Option<Self> {
        match code {
            1 => Some(Self::LocalBefore),
            2 => Some(Self::LocalAfter),
            3 => Some(Self::PitInactive),
            4 => Some(Self::PitReadConfig),
            5 => Some(Self::PitReadTerminal),
            6 => Some(Self::PitReadNotLoaded),
            7 => Some(Self::PitReadOther),
            8 => Some(Self::InvalidBracket),
            9 => Some(Self::RawRegression),
            10 => Some(Self::LatePitCount),
            11 => Some(Self::StepCount),
            12 => Some(Self::WindowCount),
            13 => Some(Self::StepElapsed),
            14 => Some(Self::WindowElapsed),
            15 => Some(Self::StepMismatch),
            16 => Some(Self::WindowMismatch),
            17 => Some(Self::OriginElapsed),
            18 => Some(Self::RearmLocalBefore),
            19 => Some(Self::RearmLocalAfter),
            20 => Some(Self::RearmInactive),
            21 => Some(Self::RearmReadConfig),
            22 => Some(Self::RearmReadTerminal),
            23 => Some(Self::RearmReadNotLoaded),
            24 => Some(Self::RearmReadOther),
            25 => Some(Self::RearmOldCount),
            26 => Some(Self::RearmProgramConfig),
            27 => Some(Self::RearmProgramNoEdge),
            28 => Some(Self::RearmProgramRegression),
            29 => Some(Self::RearmProgramOther),
            30 => Some(Self::RearmCount),
            31 => Some(Self::RearmElapsed),
            32 => Some(Self::RearmTooLong),
            33 => Some(Self::Stalled),
            _ => None,
        }
    }

    pub(crate) fn message(self) -> &'static [u8] {
        match self {
            Self::LocalBefore => b"SYSTEM CLOCK: TSC/PIT epoch unavailable: missing local TSC before PIT read",
            Self::LocalAfter => b"SYSTEM CLOCK: TSC/PIT epoch unavailable: missing local TSC after PIT read",
            Self::PitInactive => b"SYSTEM CLOCK: TSC/PIT epoch unavailable: PIT monitor inactive",
            Self::PitReadConfig => b"SYSTEM CLOCK: TSC/PIT epoch unavailable: PIT read configuration invalid",
            Self::PitReadTerminal => b"SYSTEM CLOCK: TSC/PIT epoch unavailable: PIT read terminal or zero count",
            Self::PitReadNotLoaded => b"SYSTEM CLOCK: TSC/PIT epoch unavailable: PIT read null count",
            Self::PitReadOther => b"SYSTEM CLOCK: TSC/PIT epoch unavailable: PIT read rejected",
            Self::InvalidBracket => b"SYSTEM CLOCK: TSC/PIT epoch unavailable: invalid normalized TSC bracket",
            Self::RawRegression => b"SYSTEM CLOCK: TSC/PIT epoch unavailable: local raw TSC regressed",
            Self::LatePitCount => b"SYSTEM CLOCK: TSC/PIT epoch unavailable: PIT count below rearm minimum",
            Self::StepCount => b"SYSTEM CLOCK: TSC/PIT epoch unavailable: adjacent PIT count regressed",
            Self::WindowCount => b"SYSTEM CLOCK: TSC/PIT epoch unavailable: window PIT count regressed",
            Self::StepElapsed => b"SYSTEM CLOCK: TSC/PIT epoch unavailable: invalid adjacent TSC interval",
            Self::WindowElapsed => b"SYSTEM CLOCK: TSC/PIT epoch unavailable: invalid window TSC interval",
            Self::StepMismatch => b"SYSTEM CLOCK: TSC/PIT epoch unavailable: adjacent TSC/PIT intervals disagree",
            Self::WindowMismatch => b"SYSTEM CLOCK: TSC/PIT epoch unavailable: finite TSC/PIT window disagrees",
            Self::OriginElapsed => b"SYSTEM CLOCK: TSC/PIT epoch unavailable: invalid TSC origin interval",
            Self::RearmLocalBefore => b"SYSTEM CLOCK: TSC/PIT epoch unavailable: missing local TSC before PIT rearm",
            Self::RearmLocalAfter => b"SYSTEM CLOCK: TSC/PIT epoch unavailable: missing local TSC after PIT rearm",
            Self::RearmInactive => b"SYSTEM CLOCK: TSC/PIT epoch unavailable: PIT monitor inactive at rearm",
            Self::RearmReadConfig => b"SYSTEM CLOCK: TSC/PIT epoch unavailable: PIT rearm read configuration invalid",
            Self::RearmReadTerminal => b"SYSTEM CLOCK: TSC/PIT epoch unavailable: PIT rearm read terminal or zero count",
            Self::RearmReadNotLoaded => b"SYSTEM CLOCK: TSC/PIT epoch unavailable: PIT rearm read null count",
            Self::RearmReadOther => b"SYSTEM CLOCK: TSC/PIT epoch unavailable: PIT rearm read rejected",
            Self::RearmOldCount => b"SYSTEM CLOCK: TSC/PIT epoch unavailable: PIT rearm outside old finite window",
            Self::RearmProgramConfig => b"SYSTEM CLOCK: TSC/PIT epoch unavailable: PIT reprogram configuration invalid",
            Self::RearmProgramNoEdge => b"SYSTEM CLOCK: TSC/PIT epoch unavailable: PIT reprogram no observed progress",
            Self::RearmProgramRegression => b"SYSTEM CLOCK: TSC/PIT epoch unavailable: PIT reprogram count regressed",
            Self::RearmProgramOther => b"SYSTEM CLOCK: TSC/PIT epoch unavailable: PIT reprogram rejected",
            Self::RearmCount => b"SYSTEM CLOCK: TSC/PIT epoch unavailable: epoch rearm count outside valid window",
            Self::RearmElapsed => b"SYSTEM CLOCK: TSC/PIT epoch unavailable: invalid TSC rearm interval",
            Self::RearmTooLong => b"SYSTEM CLOCK: TSC/PIT epoch unavailable: TSC rearm interval exceeds bound",
            Self::Stalled => b"SYSTEM CLOCK: TSC/PIT epoch unavailable: independent LAPIC progress detected stall",
        }
    }

    pub(crate) fn pit_read(error: pit::MonitorError) -> Self {
        use pit::{Error, MonitorError};
        match error {
            MonitorError::Inactive => Self::PitInactive,
            MonitorError::Read(Error::Configuration) => Self::PitReadConfig,
            MonitorError::Read(Error::NoEdge) => Self::PitReadTerminal,
            MonitorError::NotLoaded => Self::PitReadNotLoaded,
            _ => Self::PitReadOther,
        }
    }

    pub(crate) fn pit_rearm(error: pit::MonitorError) -> Self {
        use pit::{Error, MonitorError};
        match error {
            MonitorError::Inactive => Self::RearmInactive,
            MonitorError::Read(Error::Configuration) => Self::RearmReadConfig,
            MonitorError::Read(Error::NoEdge) => Self::RearmReadTerminal,
            MonitorError::Read(_) => Self::RearmReadOther,
            MonitorError::NotLoaded => Self::RearmReadNotLoaded,
            MonitorError::OutsideRearmWindow => Self::RearmOldCount,
            MonitorError::Program(Error::Configuration) => Self::RearmProgramConfig,
            MonitorError::Program(Error::NoEdge) => Self::RearmProgramNoEdge,
            MonitorError::Program(Error::Regression) => Self::RearmProgramRegression,
            MonitorError::Program(_) => Self::RearmProgramOther,
        }
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
    fault: Option<Fault>,
}

impl Epoch {
    pub(crate) fn new(roster: Roster, before: Sample, after: Sample, count: u16) -> Option<Self> {
        if count==0 || count<=pit::REARM_COUNT {return None;}
        let initial=roster.bracket(before,after)?;
        let mut epoch=Self { roster, origin:initial,window:initial,previous:initial,
            window_count:count,count,last_raw:[0;MAX_ID],seen:[0;4],
            published:0,fault:None };
        epoch.record(before,after).ok()?;
        Some(epoch)
    }

    fn record(&mut self, before: Sample, after: Sample) -> Result<TscBracket, Fault> {
        let current=self.roster.bracket(before,after).ok_or(Fault::InvalidBracket)?;
        let id=before.member.id;
        let (word,flag)=bit(id);
        if self.seen[word]&flag!=0 && before.raw<self.last_raw[id as usize] {
            return Err(Fault::RawRegression);
        }
        self.seen[word]|=flag;
        self.last_raw[id as usize]=after.raw;
        Ok(current)
    }

    pub(crate) fn invalidate(&mut self, fault: Fault) {
        if self.fault.is_none() { self.fault=Some(fault); }
    }
    pub(crate) fn failed(&self)->bool { self.fault.is_some() }
    pub(crate) fn fault(&self)->Option<Fault> { self.fault }

    /// Both adjacent samples and the complete finite window must agree.
    /// The PIT counts are independently observed; TSC cannot invent
    /// elapsed ticks. Overlap between bounded cross-CPU offset intervals
    /// may clamp publication but never move it backward.
    pub(crate) fn observe(&mut self, before: Sample, after: Sample, count: u16) -> Option<u128> {
        if self.failed() {return None;}
        let result=(|| {
            let current=self.record(before,after)?;
            if count<pit::MIN_REARM_COUNT {return Err(Fault::LatePitCount);}
            let step=pit::count_elapsed_ns(self.count,count).ok_or(Fault::StepCount)?;
            let total=pit::count_elapsed_ns(self.window_count,count).ok_or(Fault::WindowCount)?;
            if !Span::exact(step).agrees(self.previous.elapsed(current).ok_or(Fault::StepElapsed)?) {
                return Err(Fault::StepMismatch);
            }
            if !Span::exact(total).agrees(self.window.elapsed(current).ok_or(Fault::WindowElapsed)?) {
                return Err(Fault::WindowMismatch);
            }
            let time=self.origin.elapsed(current).ok_or(Fault::OriginElapsed)?.low.max(self.published);
            self.previous=current;
            self.count=count;
            self.published=time;
            Ok(time)
        })();
        match result {
            Ok(time)=>Some(time),
            Err(fault)=>{self.invalidate(fault); None}
        }
    }

    /// A fresh count starts a new independent rate-check window, not a
    /// new global epoch. Reset overhead is bracketed and bounded; time
    /// from the reset is not itself published as independent evidence.
    pub(crate) fn rearm(&mut self,before:Sample,after:Sample,count:u16)->bool {
        if self.failed(){return false;}
        let result=(||{
            if self.count>pit::REARM_COUNT || self.count<pit::MIN_REARM_COUNT ||
               count<=pit::REARM_COUNT{return Err(Fault::RearmCount);}
            let current=self.record(before,after)?;
            if self.previous.elapsed(current).ok_or(Fault::RearmElapsed)?.high>MAX_REARM_NS{
                return Err(Fault::RearmTooLong);
            }
            self.previous=current;
            self.window=current;
            self.window_count=count;
            self.count=count;
            Ok(())
        })();
        match result {
            Ok(())=>true,
            Err(fault)=>{self.invalidate(fault); false}
        }
    }
}
