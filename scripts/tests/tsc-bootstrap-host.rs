//! Actual boot transport, qualified source selection and TSC epoch.
#![allow(dead_code)]
#[path="../../kernel/reference_clock.rs"] mod reference_clock;
#[path="../../kernel/tsc.rs"] mod tsc;
#[path="../../kernel/clock_quorum.rs"] mod clock_quorum;
#[path="../../kernel/bringup_clock.rs"] mod bringup_clock;
#[path="../../kernel/tsc_epoch.rs"] mod tsc_epoch;
#[path = "../../kernel/cpu_topology.rs"]
mod cpu_topology;

use bringup_clock::BringupClock;
use reference_clock::WaitError;
use tsc::{Alignment,Peer};
use tsc_epoch::{BootSource,Epoch,Fault,InitError,Sample,select};
const HZ:u64=3_000_000_000;
const BASE:u64=3_000_000_000;
const BSP:u32=7;
const AP:u32=201;
const ZERO:Alignment=Alignment{offset:0,uncertainty_ticks:0};
const OFFSET:Alignment=Alignment{offset:-30_000,uncertainty_ticks:300};


// Synthetic independent observations, never privileged hardware I/O.
// The test uses the production proof constructor.
fn proof(hz:u64)->tsc::QualifiedRate {
    let caps=tsc::Capabilities{available:true,invariant:true,nominal_hz:Some(hz)};
    let mut calibration=tsc::Calibration::new(caps);
    for i in 0..3u64 {
        let start=1_000_000+i*(hz/10);
        let end=start+hz/20;
        calibration.observe(tsc::Observation{before_start:start,after_start:start,
            before_end:end,after_end:end,reference_ns:50_000_000}).unwrap();
    }
    calibration.finish().unwrap()
}

fn peer(rate:Option<tsc::QualifiedRate>,alignment:Option<Alignment>)->Peer {
    let p=Peer::new();
    p.publish_rate(rate);
    if let Some(a)=alignment { assert!(p.publish_alignment(a)); }
    p
}
fn fleet()->(Peer,Peer) {
    (peer(Some(proof(HZ)),Some(ZERO)),peer(Some(proof(HZ)),Some(OFFSET)))
}
fn initialized<'a>(bsp:u32,ids:&[u32],
    members:impl IntoIterator<Item=(u32,&'a Peer)>, first:Sample)->Result<Epoch<'a>,InitError> {
    let mut epoch=Epoch::empty();
    epoch.initialize(bsp,ids,members,||first)?;
    Ok(epoch)
}
fn qualify<'a>(bsp:u32,ids:&[u32],members:impl IntoIterator<Item=(u32,&'a Peer)>)
    ->Result<(),InitError> {
    let mut epoch=Epoch::empty();
    epoch.initialize(bsp,ids,members,||Sample{id:bsp,raw:BASE})
}
fn epoch<'a>(bsp:&'a Peer,ap:&'a Peer)->Epoch<'a> {
    initialized(BSP,&[BSP,AP],[(BSP,bsp),(AP,ap)],Sample{id:BSP,raw:BASE}).unwrap()
}
fn at(id:u32,normalized:u64)->Sample {
    Sample{id,raw:if id==AP { normalized+30_000 } else { normalized }}
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
fn safe_selection_prefers_physical_and_requires_complete_proof() {
    assert_eq!(select::<InitError>(true,||panic!("physical source needs no TSC")),Ok(BootSource::Physical));
    assert_eq!(select(false,||Err(InitError::Roster)),Err(InitError::Roster));
    let (bsp,ap)=fleet();
    assert_eq!(select(false,||qualify(BSP,&[BSP,AP],[(BSP,&bsp),(AP,&ap)])),Ok(BootSource::Tsc));
    let unqualified=peer(None,Some(OFFSET));
    assert_eq!(select(false,||qualify(BSP,&[BSP,AP],[(BSP,&bsp),(AP,&unqualified)])),Err(InitError::Roster));
}

#[test]
fn incomplete_duplicate_or_misaligned_fleet_cannot_publish() {
    let (bsp,ap)=fleet();
    assert!(qualify(BSP,&[BSP,AP],[(BSP,&bsp)]).is_err());
    assert!(qualify(BSP,&[BSP,AP],[(BSP,&bsp),(BSP,&bsp)]).is_err());
    assert!(qualify(BSP,&[BSP,AP],[(BSP,&bsp),(AP,&bsp)]).is_err());
    assert!(qualify(BSP,&[BSP,BSP],[(BSP,&bsp)]).is_err());
    assert!(qualify(BSP,&[AP],[(AP,&ap)]).is_err());
    for p in [
        peer(None,Some(OFFSET)),
        peer(Some(proof(HZ)),None),
        peer(Some(proof(HZ+10_000_000)),Some(OFFSET)),
        peer(Some(proof(HZ)),Some(Alignment{uncertainty_ticks:300_001,..OFFSET})),
    ] {
        assert!(qualify(BSP,&[BSP,AP],[(BSP,&bsp),(AP,&p)]).is_err());
    }
    let bad_bsp=peer(Some(proof(HZ)),Some(Alignment{offset:1,..ZERO}));
    assert!(qualify(BSP,&[BSP],[(BSP,&bad_bsp)]).is_err());
    assert!(qualify(BSP,&[BSP],[(BSP,&bsp)]).is_ok());
    assert!(qualify(BSP,&[BSP,AP],[(AP,&ap),(BSP,&bsp)]).is_ok());
}

#[test]
fn only_bsp_may_publish_new_epoch_and_first_sample_must_be_valid() {
    let (bsp,ap)=fleet();
    let mut epoch=Epoch::empty();
    assert_eq!(epoch.initialize(BSP,&[BSP,AP],[(BSP,&bsp),(AP,&ap)],||at(AP,BASE)),
        Err(InitError::Sample));
    assert_eq!(epoch.observe(at(BSP,BASE)),Err(Fault::UnqualifiedCpu));
    assert_eq!(epoch.initialize(BSP,&[BSP,AP],[(BSP,&bsp),(AP,&ap)],||Sample{id:BSP,raw:1}),
        Err(InitError::Sample));
    assert_eq!(epoch.observe(at(BSP,BASE)),Err(Fault::UnqualifiedCpu));
    assert_eq!(epoch.initialize(BSP,&[BSP,AP],[(BSP,&bsp),(AP,&ap)],||at(BSP,BASE)),Ok(()));
    assert_eq!(epoch.observe(at(BSP,BASE+HZ)),Ok(1_000_000_000));
}

#[test]
fn normalized_reads_across_sparse_cpus_and_long_idle_use_one_origin() {
    let (bsp,ap)=fleet();
    let mut e=epoch(&bsp,&ap);
    let mut last=0;
    for i in 1..=100u64 {
        let normalized=BASE+i*HZ;
        let id=if i%2==0 { BSP } else { AP };
        let ns=e.observe(at(id,normalized)).unwrap();
        assert!(ns>=last);
        assert!(ns.abs_diff(i as u128*1_000_000_000)<=100);
        last=ns;
    }
    assert!(last>=100_000_000_000);
    // A long tickless wait requires neither a renewed calibration nor a
    // counter-wrap assumption. Time comes from actual qualified raw TSC.
    assert_eq!(e.observe(at(BSP,BASE+HZ*3600)),Ok(3_600_000_000_000));
    assert!(!ap.publish_alignment(ZERO));
}

#[test]
fn cross_cpu_overlap_is_clamped_but_local_regression_is_sticky() {
    let (bsp,ap)=fleet();
    let mut e=epoch(&bsp,&ap);
    let raw=BASE+HZ;
    let ns=e.observe(at(BSP,raw)).unwrap();
    let sample=at(AP,raw-100);
    assert_eq!(e.observe(sample),Ok(ns));
    assert_eq!(e.observe(Sample{raw:sample.raw-1,..sample}),Err(Fault::RawRegression));
    assert_eq!(e.invalidate(Fault::Stalled),Fault::RawRegression);
    assert_eq!(e.observe(at(BSP,raw+HZ)),Err(Fault::RawRegression));
}

#[test]
fn disjoint_cross_cpu_regression_and_outsider_never_publish() {
    let (bsp,ap)=fleet();
    let mut e=epoch(&bsp,&ap);
    assert!(e.observe(at(BSP,BASE+HZ)).is_ok());
    assert_eq!(e.observe(at(AP,BASE+HZ-301)),Err(Fault::GlobalRegression));
    let mut e=epoch(&bsp,&ap);
    assert_eq!(e.observe(at(0,BASE+HZ)),Err(Fault::UnknownCpu));
    assert_eq!(e.observe(at(BSP,BASE+2*HZ)),Err(Fault::UnknownCpu));
    let mut e=epoch(&bsp,&ap);
    assert_eq!(e.observe(Sample{id:AP,raw:29_999}),Err(Fault::Normalization));
    let mut e=epoch(&bsp,&ap);
    assert_eq!(e.observe(Sample{id:AP,raw:100_000}),Err(Fault::RawRegression));
}

#[test]
fn repeated_overlapping_reads_cannot_gradually_move_bound_backwards() {
    let (bsp,ap)=fleet();
    let mut e=epoch(&bsp,&ap);
    let raw=BASE+HZ;
    let ns=e.observe(at(BSP,raw)).unwrap();
    for i in 0..=300 {
        assert_eq!(e.observe(at(AP,raw-300+i)),Ok(ns));
    }
    // The BSP's raw value is not locally regressing, but it is now
    // behind a newer nonoverlapping observation from the AP.
    assert!(e.observe(at(AP,raw+1000)).unwrap()>ns);
    assert_eq!(e.observe(at(BSP,raw+699)),Err(Fault::GlobalRegression));
}

#[test]
fn stall_guard_cannot_renew_failed_epoch() {
    let (bsp,ap)=fleet();
    let mut e=epoch(&bsp,&ap);
    assert_eq!(e.observe(at(BSP,BASE)),Ok(0));
    assert_eq!(e.invalidate(Fault::Stalled),Fault::Stalled);
    assert_eq!(e.observe(at(AP,BASE+HZ)),Err(Fault::Stalled));
    for code in 1..=6 {
        let f=Fault::from_code(code).unwrap();
        assert_eq!(f as u8,code);
        assert!(f.message().len()<=96);
    }
    assert_eq!(Fault::from_code(0),None);
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
fn wide_cpu_ids_use_independent_epoch_slots_and_full_witness_identity() {
    let bsp=peer(Some(proof(HZ)),Some(ZERO));
    let ap=peer(Some(proof(HZ)),Some(OFFSET));
    let high=peer(Some(proof(HZ)),Some(ZERO));
    let high_id=0xffff_fffe;
    let ids=[high_id,0,256];
    assert!(qualify(0,&[0,256,256],[(0,&bsp),(256,&ap)]).is_err());
    assert!(qualify(0,&ids,[(0,&bsp),(256,&ap),(512,&high)]).is_err());
    assert!(qualify(0,&ids,[(0,&bsp),(256,&ap),(high_id,&ap)]).is_err());
    let mut epoch=initialized(0,&ids,[(high_id,&high),(256,&ap),(0,&bsp)],Sample{id:0,raw:BASE}).unwrap();
    let time=BASE+HZ;
    assert_eq!(epoch.observe(Sample{id:0,raw:time}),Ok(1_000_000_000));
    // CPU 256 is not CPU 0, even though their legacy low byte is identical.
    assert_eq!(epoch.observe(Sample{id:256,raw:time+30_000-100}),Ok(1_000_000_000));
    assert_eq!(epoch.observe(Sample{id:high_id,raw:time}),Ok(1_000_000_000));
    assert_eq!(epoch.observe(Sample{id:256,raw:time+30_000-101}),Err(Fault::RawRegression));
    let mut epoch=initialized(0,&ids,[(0,&bsp),(256,&ap),(high_id,&high)],Sample{id:0,raw:BASE}).unwrap();
    assert_eq!(epoch.observe(Sample{id:512,raw:time}),Err(Fault::UnknownCpu));
    let w=clock_quorum::Witness{cpu:0,ticks:time,hz:HZ,uncertainty_ticks:0};
    assert_eq!(clock_quorum::TscBracket::new(w,clock_quorum::Witness{cpu:256,..w}),None);
    assert_eq!(clock_quorum::TscBracket::new(w,clock_quorum::Witness{cpu:high_id,..w}),None);
}

#[test]
fn failed_roster_discards_partial_members_and_published_epoch_cannot_rebase() {
    let (bsp,ap)=fleet();
    let high=peer(Some(proof(HZ)),Some(ZERO));
    let high_id=0xffff_fffe;
    let mut e=Epoch::empty();
    assert_eq!(e.initialize(BSP,&[BSP,AP,high_id],
        [(BSP,&bsp),(high_id,&high)],||panic!("incomplete roster sampled")),Err(InitError::Roster));
    assert_eq!(e.observe(at(BSP,BASE)),Err(Fault::UnqualifiedCpu));
    assert_eq!(e.initialize(BSP,&[BSP,AP],[(AP,&ap),(BSP,&bsp)],||at(BSP,BASE)),Ok(()));
    assert_eq!(e.observe(at(BSP,BASE+HZ)),Ok(1_000_000_000));
    assert_eq!(e.initialize(BSP,&[BSP],[(BSP,&bsp)],||panic!("published epoch sampled")),
        Err(InitError::AlreadyPublished));
    assert_eq!(e.observe(at(AP,BASE+2*HZ)),Ok(1_999_999_900));
    assert_eq!(e.observe(Sample{id:high_id,raw:BASE+3*HZ}),Err(Fault::UnknownCpu));
    assert_eq!(e.initialize(BSP,&[BSP],[(BSP,&bsp)],||panic!("failed epoch sampled")),
        Err(InitError::AlreadyPublished));
    assert_eq!(e.observe(at(BSP,BASE+4*HZ)),Err(Fault::UnknownCpu));
}
