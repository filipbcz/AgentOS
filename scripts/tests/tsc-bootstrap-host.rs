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
use tsc_epoch::{Epoch,Member,Roster,Sample};
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
            assert!(e.rearm(s,s,count));
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
    assert_eq!(e.observe(a,a,65_000-1193),Some(first));
    let bad=Sample{raw:a.raw-1,..a};
    assert_eq!(e.observe(bad,bad,65_000-1193),None);
    assert!(e.failed());
    assert_eq!(e.observe(a,a,65_000-1193),None);
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
        assert_eq!(e.observe(s,s,count),None);
        assert!(e.failed());
    }
}

#[test]
fn cannot_hide_a_bad_window_by_rearming_or_migrating_mid_sample() {
    let mut e=epoch();
    let s=at(BSP,BASE+ticks(11_932));
    assert!(e.observe(s,s,53_068).is_some());
    assert!(!e.rearm(s,s,65_000)); // too soon to reset the evidence
    assert!(e.failed());

    let mut e=epoch();
    let s=at(BSP,BASE+ticks(35_796));
    assert!(e.observe(s,s,29_204).is_some());
    let late=at(BSP,s.raw+HZ/1000);
    assert!(!e.rearm(late,late,65_000));
    assert!(e.failed());

    let mut e=epoch();
    let s=at(BSP,BASE+ticks(11_932));
    assert_eq!(e.observe(s,at(AP,s.raw),53_068),None);
}
