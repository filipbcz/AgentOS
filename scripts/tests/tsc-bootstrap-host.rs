//! Pure tests of the real startup transport and the runtime epoch.
#![allow(dead_code)]
#[path="../../kernel/reference_clock.rs"] mod reference_clock;
#[path="../../kernel/tsc.rs"] mod tsc;
#[path="../../kernel/clock_quorum.rs"] mod clock_quorum;
#[path="../../kernel/pit.rs"] mod pit;
#[path="../../kernel/bringup_clock.rs"] mod bringup_clock;
#[path="../../kernel/tsc_epoch.rs"] mod tsc_epoch;

use bringup_clock::BringupClock;
use reference_clock::WaitError;
use tsc::Alignment;
use tsc_epoch::{Epoch,Fault,Member,ObservationPhase,Roster,Sample};
const HZ:u64=3_000_000_000;
const BASE:u64=3_000_000_000;
const BSP:Member=Member{id:7,hz:HZ,alignment:Alignment{offset:0,uncertainty_ticks:0}};
const AP:Member=Member{id:201,hz:HZ,alignment:Alignment{offset:-30_000,uncertainty_ticks:300}};

fn at(member:Member,normalized:u64)->Sample {
    Sample{member,raw:u64::try_from(normalized as i128-member.alignment.offset as i128).unwrap()}
}
fn epoch()->Epoch {
    let roster=Roster::qualify(7,HZ,&[7,201],[BSP,AP]).unwrap();
    let first=at(BSP,BASE);
    Epoch::new(roster,first,first,65_000).unwrap()
}
fn ticks(pit_ticks:u16)->u64 {
    (pit_ticks as u128*HZ as u128/1_193_182) as u64
}

#[test]
fn startup_waits_use_elapsed_local_hardware_not_poll_count() {
    let mut raw=100u64;
    assert_eq!(BringupClock::local_poll(HZ,1_000,10,5,||{raw+=300;raw},||false),Ok(Some(1_000)));
    assert_eq!(BringupClock::local_poll(HZ,1_000_000,10,5,||10,||false),Err(WaitError::Unresponsive));
    let mut raw=100u64;
    assert_eq!(BringupClock::local_poll(HZ,1_000_000,10,5,||{raw-=1;raw},||false),Err(WaitError::Unresponsive));
    assert_eq!(BringupClock::local_poll(0,100,10,5,||panic!("invalid rate"),||false),Err(WaitError::Unresponsive));
    assert_eq!(BringupClock::local_poll(HZ,100,10,5,||panic!("already complete"),||true),Ok(None));
}

#[test]
fn incomplete_duplicate_or_misaligned_fleet_cannot_publish() {
    assert!(Roster::qualify(7,HZ,&[7,201],[BSP]).is_none());
    assert!(Roster::qualify(7,HZ,&[7,201],[BSP,BSP]).is_none());
    assert!(Roster::qualify(7,HZ,&[7,7],[BSP]).is_none());
    assert!(Roster::qualify(7,HZ,&[201],[AP]).is_none());
    assert!(Roster::qualify(7,HZ,&[7,201],[BSP,Member{hz:HZ+10_000_000,..AP}]).is_none());
    assert!(Roster::qualify(7,HZ,&[7,201],[BSP,Member{alignment:Alignment{uncertainty_ticks:300_001,..AP.alignment},..AP}]).is_none());
    assert!(Roster::qualify(7,HZ,&[7],[Member{alignment:Alignment{offset:1,..BSP.alignment},..BSP}]).is_none());
    assert!(Roster::qualify(7,HZ,&[7],[BSP]).is_some());
    assert!(Roster::qualify(7,HZ,&[7,201],[AP,BSP]).is_some());
}

#[test]
fn missing_or_late_independent_count_prevents_publication() {
    for count in [0,100,pit::REARM_COUNT] {
        let roster=Roster::qualify(7,HZ,&[7,201],[BSP,AP]).unwrap();
        let s=at(BSP,BASE);
        assert!(Epoch::new(roster,s,s,count).is_none());
    }
    let roster=Roster::qualify(7,HZ,&[7,201],[BSP,AP]).unwrap();
    assert!(Epoch::new(roster,at(BSP,BASE),at(AP,BASE),65_000).is_none());
}

#[test]
fn normalized_cpu_reads_and_rearm_preserve_the_same_absolute_epoch() {
    let mut e=epoch();
    let mut count=65_000u16;
    let mut normalized=BASE;
    let mut published=0;
    for i in 0..100 {
        count-=11_932;
        normalized+=ticks(11_932);
        let member=if i%2==0 {AP}else{BSP};
        let s=at(member,normalized);
        let ns=e.observe(s,s,count).unwrap();
        assert!(ns>=published);
        assert!(ns.abs_diff((normalized-BASE) as u128*1_000_000_000/HZ as u128)<1_000);
        published=ns;
        if count<=pit::REARM_COUNT {
            normalized+=30_000; // bounded actual reprogramming interval
            count=65_000;
            let s=at(member,normalized);
            assert_eq!(e.rearm(s,s,count),Ok(()));
        }
    }
    assert!(published>=1_000_000_000);
}

#[test]
fn cross_cpu_overlap_is_clamped_without_accepting_raw_regression() {
    let mut e=epoch();
    let raw=BASE+ticks(1193);
    let s=at(BSP,raw);
    let first=e.observe(s,s,65_000-1193).unwrap();
    // A different CPU's normalized lower bound may be slightly earlier
    // inside its startup alignment uncertainty.
    let a=at(AP,raw-100);
    assert_eq!(e.observe(a,a,65_000-1193),Ok(first));
    let bad=Sample{raw:a.raw-1,..a};
    assert_eq!(e.observe(bad,bad,65_000-1193),Err(Fault::RawRegression));
    assert!(e.failed());
    assert_eq!(e.observe(a,a,65_000-1193),Err(Fault::RawRegression));
}

#[test]
fn frozen_or_conflicting_independent_reference_invalidates_epoch() {
    for (tsc_ticks,count) in [
        (ticks(11_932),65_000), // PIT stuck
        (0,53_068),            // TSC stuck
        (ticks(11_932)*2,53_068), // TSC rate jump
        (ticks(11_932),65_001), // raw PIT regression
        (ticks(11_932),0),      // terminal count
        (ticks(11_932),pit::MIN_REARM_COUNT-1),
    ] {
        let mut e=epoch();
        let s=at(BSP,BASE+tsc_ticks);
        assert!(e.observe(s,s,count).is_err());
        assert!(e.failed());
    }
}

#[test]
fn cannot_hide_a_bad_window_by_rearming_or_migrating_mid_sample() {
    let mut e=epoch();
    let s=at(BSP,BASE+ticks(11_932));
    assert!(e.observe(s,s,53_068).is_ok());
    assert_eq!(e.rearm(s,s,65_000),Err(Fault::RearmCount)); // too soon to reset the evidence
    assert!(e.failed());

    let mut e=epoch();
    let s=at(BSP,BASE+ticks(35_796));
    assert!(e.observe(s,s,29_204).is_ok());
    let late=at(BSP,s.raw+HZ/1000);
    assert_eq!(e.rearm(late,late,65_000),Err(Fault::RearmTooLong));
    assert!(e.failed());

    let mut e=epoch();
    let s=at(BSP,BASE+ticks(11_932));
    assert_eq!(e.observe(s,at(AP,s.raw),53_068),Err(Fault::MemberCpuMismatch));
}

#[test]
fn first_epoch_fault_is_specific_and_sticky() {
    let mut e=epoch();
    let s=at(BSP,BASE+ticks(11_932));
    assert_eq!(e.observe(s,s,65_000),Err(Fault::StepMismatch));
    assert_eq!(e.fault(),Some(Fault::StepMismatch));
    e.invalidate(Fault::Stalled);
    assert_eq!(e.observe(s,s,53_068),Err(Fault::StepMismatch));
    assert_eq!(e.fault(),Some(Fault::StepMismatch));

    let mut e=epoch();
    assert_eq!(e.observe(s,s,pit::MIN_REARM_COUNT-1),Err(Fault::LatePitCount));
    assert_eq!(e.fault(),Some(Fault::LatePitCount));

    let mut e=epoch();
    assert_eq!(e.observe(s,s,65_001),Err(Fault::StepCount));
    assert_eq!(e.fault(),Some(Fault::StepCount));

    let mut e=epoch();
    assert!(e.observe(s,s,53_068).is_ok());
    let bad=Sample{raw:s.raw-1,..s};
    assert_eq!(e.observe(bad,bad,53_068),Err(Fault::RawRegression));
    assert_eq!(e.fault(),Some(Fault::RawRegression));

    let mut e=epoch();
    assert!(e.observe(s,s,53_068).is_ok());
    assert_eq!(e.rearm(s,s,65_000),Err(Fault::RearmCount));
    assert_eq!(e.fault(),Some(Fault::RearmCount));

    let mut e=epoch();
    let s=at(BSP,BASE+ticks(35_796));
    assert!(e.observe(s,s,29_204).is_ok());
    let late=at(BSP,s.raw+HZ/1000);
    assert_eq!(e.rearm(late,late,65_000),Err(Fault::RearmTooLong));
    assert_eq!(e.fault(),Some(Fault::RearmTooLong));
}

#[test]
fn operational_failure_codes_and_pit_stages_remain_distinct() {
    use pit::{Error,MonitorError};
    assert_eq!(Fault::from_code(0),None);
    for code in 1..=Fault::BracketUpperOverflow as u8 {
        let fault=Fault::from_code(code).unwrap();
        assert_eq!(fault as u8,code);
        assert!(fault.message().starts_with(b"SYSTEM CLOCK: TSC/PIT epoch unavailable: "));
        assert!(fault.message().len()<=96);
    }
    assert_eq!(Fault::pit_read(MonitorError::Read(Error::NoEdge)),Fault::PitReadTerminal);
    assert_eq!(Fault::pit_rearm(MonitorError::Read(Error::NoEdge)),Fault::RearmReadTerminal);
    assert_eq!(Fault::pit_rearm(MonitorError::Program(Error::NoEdge)),Fault::RearmProgramNoEdge);
    assert_eq!(Fault::pit_rearm(MonitorError::OutsideRearmWindow),Fault::RearmOldCount);
    assert_eq!(Fault::pit_read(MonitorError::NotLoaded),Fault::PitReadNotLoaded);
}

#[test]
fn roster_rejects_each_distinct_condition_without_generic_fallback() {
    let good=at(BSP,BASE);
    let wrong_id=Sample{member:Member{id:8,..BSP},..good};
    let wrong_rate=Sample{member:Member{hz:HZ+10_000_000,..BSP},..good};
    let zero_rate=Sample{member:Member{hz:0,..BSP},..good};
    let uncertain=Sample{member:Member{alignment:Alignment{uncertainty_ticks:300_001,..BSP.alignment},..BSP},..good};
    let backwards=Sample{raw:good.raw-1,..good};
    let under=Sample{member:Member{alignment:Alignment{offset:-1,..BSP.alignment},..BSP},raw:0};
    let over_before=Sample{member:Member{alignment:Alignment{offset:1,..BSP.alignment},..BSP},raw:u64::MAX-1};
    let over_after=Sample{raw:u64::MAX,..over_before};
    let lower=Sample{member:Member{alignment:Alignment{uncertainty_ticks:1,..BSP.alignment},..BSP},raw:0};
    let upper=Sample{member:lower.member,raw:u64::MAX};
    let width=Sample{raw:good.raw+600_001,..good};
    for (before,after,fault) in [
        (good,wrong_id,Fault::MemberCpuMismatch),
        (good,wrong_rate,Fault::MemberRateMismatch),
        (good,uncertain,Fault::MemberAlignmentMismatch),
        (wrong_id,wrong_id,Fault::MemberAbsent),
        (zero_rate,zero_rate,Fault::RosterZeroRate),
        (wrong_rate,wrong_rate,Fault::RosterRateMismatch),
        (uncertain,uncertain,Fault::RosterUncertainty),
        (good,backwards,Fault::BracketRawRegression),
        (under,under,Fault::NormalizeBefore),
        (over_before,over_after,Fault::NormalizeAfter),
        (lower,lower,Fault::BracketLowerUnderflow),
        (upper,upper,Fault::BracketUpperOverflow),
        (good,width,Fault::BracketWidth),
    ] {
        let mut e=epoch();
        assert_eq!(e.observe(before,after,53_068),Err(fault));
        assert_eq!(e.fault(),Some(fault));
        assert_eq!(e.invalidate(Fault::Stalled),fault);
        assert_eq!(e.observe(good,good,53_068),Err(fault));
    }
}

#[test]
fn checked_bracket_preserves_exact_width_and_arithmetic_limits() {
    use clock_quorum::{BracketError as E,TscBracket,Witness};
    let w=Witness{cpu:7,ticks:BASE,hz:HZ,uncertainty_ticks:0};
    assert!(TscBracket::checked(w,Witness{ticks:BASE+600_000,..w}).is_ok());
    let long=Witness{ticks:BASE+600_001,..w};
    for (a,b,reason) in [
        (w,Witness{cpu:8,..w},E::CpuMismatch),
        (Witness{hz:0,..w},w,E::ZeroRate),
        (w,Witness{hz:HZ+1,..w},E::RateMismatch),
        (w,Witness{ticks:BASE-1,..w},E::Regression),
        (w,long,E::Width),
        (w,Witness{uncertainty_ticks:30_000_001,..w},E::Uncertainty),
        (Witness{ticks:0,uncertainty_ticks:1,..w},Witness{ticks:0,..w},E::LowerUnderflow),
        (Witness{ticks:u64::MAX,..w},Witness{ticks:u64::MAX,uncertainty_ticks:1,..w},E::UpperOverflow),
    ] {
        assert_eq!(TscBracket::checked(a,b),Err(reason));
        assert_eq!(TscBracket::new(a,b),None);
    }
}

#[test]
fn rejected_complete_observation_retains_raw_inputs_and_stage() {
    let mut e=epoch();
    let s=at(BSP,BASE+ticks(35_796));
    assert!(e.observe(s,s,29_204).is_ok());
    let after=Sample{raw:s.raw+600_001,..s};
    assert_eq!(e.rearm(s,after,65_000),Err(Fault::BracketWidth));
    assert_eq!(e.failure_words(Fault::BracketWidth,ObservationPhase::Rearm,s,after,65_000),
        [1,Fault::BracketWidth as u64,2,65_000,29_204,HZ,7,7,s.raw,after.raw,HZ,HZ,0,0,0,0]);
    assert_eq!(e.invalidate(Fault::Stalled),Fault::BracketWidth);
    assert_eq!(e.rearm(s,s,65_000),Err(Fault::BracketWidth));
    let mut e=epoch();
    let before=at(AP,BASE+ticks(11_932));
    let after=Sample{raw:before.raw+600_001,..before};
    assert_eq!(e.observe(before,after,53_068),Err(Fault::BracketWidth));
    assert_eq!(e.failure_words(Fault::BracketWidth,ObservationPhase::Observe,before,after,53_068),
        [1,Fault::BracketWidth as u64,1,53_068,65_000,HZ,201,201,before.raw,after.raw,
         HZ,HZ,(-30_000i64) as u64,(-30_000i64) as u64,300,300]);
}

#[test]
fn short_new_latch_does_not_justify_unobserved_rearm_time() {
    use clock_quorum::{BracketError, TscBracket, Witness};
    let roster=Roster::qualify(BSP.id,HZ,&[BSP.id],[BSP]).unwrap();
    let first=at(BSP,BASE);
    let mut e=Epoch::new(roster,first,first,65_000).unwrap();
    let old=at(BSP,BASE+ticks(65_000-27_124));
    assert!(e.observe(old,old,27_124).is_ok());

    // Long programming/verification work is not necessarily a wide
    // count latch. A tight new latch by itself proves no continuity
    // over the disabled old counter. The present single-channel API
    // must not be fed a shortened bracket in place of the whole reset.
    let new_before=Sample{raw:old.raw+700_000,..old};
    let new_after=Sample{raw:new_before.raw+3_000,..new_before};
    let witness=|s:Sample| Witness{cpu:s.member.id,hz:s.member.hz,
        ticks:s.raw,uncertainty_ticks:0};
    assert!(TscBracket::checked(witness(new_before),witness(new_after)).is_ok());
    assert_eq!(e.rearm(old,new_after,65_458),Err(Fault::BracketWidth));
    assert_eq!(e.fault(),Some(Fault::BracketWidth));

    // A genuinely wide count observation must still be rejected, even
    // with no programming delay and no CPU or alignment change.
    let wide=Sample{raw:new_before.raw+600_001,..new_before};
    assert_eq!(TscBracket::checked(witness(new_before),witness(wide)),
        Err(BracketError::Width));
}
