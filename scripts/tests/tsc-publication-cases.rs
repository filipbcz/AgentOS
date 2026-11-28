//! Exercise the actual clock storage and shared gate without privileged IRQ
//! instructions. Host threads are not guest CPUs.
use super::*;
use crate::{tsc::{Alignment,Calibration,Capabilities,Observation,Peer},tsc_epoch::Sample};
use std::{sync::Barrier, thread};

const HZ:u64=3_000_000_000;
const BASE:u64=3_000_000_000;
static RAW:AtomicU64=AtomicU64::new(BASE);
fn local()->Sample { Sample{id:0,raw:RAW.load(Ordering::Acquire)} }
fn wrong_cpu()->Sample { Sample{id:256,raw:BASE} }

fn peer()->&'static Peer {
    let mut calibration=Calibration::new(Capabilities{available:true,invariant:true,nominal_hz:Some(HZ)});
    for i in 0..3 {
        let start=1_000_000+i*(HZ/10);
        calibration.observe(Observation{before_start:start,after_start:start,
            before_end:start+HZ/20,after_end:start+HZ/20,reference_ns:50_000_000}).unwrap();
    }
    let p=Box::leak(Box::new(Peer::new()));
    p.publish_rate(Some(calibration.finish().unwrap()));
    assert!(p.publish_alignment(Alignment{offset:0,uncertainty_ticks:0}));
    p
}

#[test]
fn publication_gate_hides_partial_history_and_failure_preserves_state() {
    let clock=SharedClock::new();
    let bsp=peer();
    let ap=peer();
    let high=peer();
    let ids=[0,256,0xffff_fffe];
    let members=[(0,bsp),(256,ap),(0xffff_fffe,high)];
    RAW.store(BASE,Ordering::Release);
    let invalid=b"invalid TSC epoch publication state" as &[u8];
    let incomplete=b"incomplete qualified TSC roster" as &[u8];

    clock.with_locked(|state| {
        assert_eq!(clock.publish_tsc_locked(state,0,&ids,members,local),Err(invalid));
        state.initialized=true;
        assert_eq!(clock.publish_tsc_locked(state,0,&ids,members,wrong_cpu),
                   Err(b"invalid initial normalized TSC sample" as &[u8]));
        assert!(state.fallback.local.is_none());
        assert!(clock.snapshot_locked(state).is_none());
        assert_eq!(clock.maintenance.load(Ordering::Acquire),0);
    });

    // Stop after inserting a member while the writer owns the actual gate.
    // A reader racing that construction must see only the final outcome.
    for complete in [false,true] {
        let in_writer=Barrier::new(2);
        let reader_started=Barrier::new(2);
        let release=Barrier::new(2);
        thread::scope(|scope| {
            let writer=scope.spawn(|| clock.with_locked(|state| {
                let take=if complete {3} else {2};
                clock.publish_tsc_locked(state,0,&ids,members.into_iter().take(take)
                    .enumerate().map(|(index,member)| {
                        if index==1 {
                            in_writer.wait();
                            release.wait();
                        }
                        member
                    }),local)
            }));
            in_writer.wait();
            let reader=scope.spawn(|| {
                reader_started.wait();
                clock.with_locked(|state| {
                    (clock.snapshot_locked(state),state.fallback.local.is_some())
                })
            });
            reader_started.wait();
            let held=clock.gate.load(Ordering::Acquire);
            let maintenance=clock.maintenance.load(Ordering::Acquire);
            release.wait();
            let publication=writer.join().unwrap();
            let (result,active)=reader.join().unwrap();
            assert!(held);
            assert_eq!(maintenance,0);
            assert_eq!(publication,if complete {Ok(())} else {Err(incomplete)});
            assert_eq!(active,complete);
            assert_eq!(result.is_some(),complete);
            if let Some(snapshot)=result {
                assert_eq!(snapshot.millis,0);
                assert!(snapshot.independent_ns.is_none() && !snapshot.holdover);
            }
        });
    }
    assert_eq!(clock.maintenance.load(Ordering::Acquire),1000);
    RAW.store(BASE+HZ,Ordering::Release);
    clock.with_locked(|state| {
        assert_eq!(clock.snapshot_locked(state).unwrap().millis,1000);
        assert_eq!(clock.publish_tsc_locked(state,0,&[0],[(0,bsp)],wrong_cpu),Err(invalid));
        assert_eq!(clock.snapshot_locked(state).unwrap().millis,1000);
        RAW.store(BASE+2*HZ,Ordering::Release);
        assert_eq!(clock.snapshot_locked(state).unwrap().millis,2000);
    });
}

#[test]
fn physical_epoch_never_replaced_by_tsc_publication() {
    let clock=SharedClock::new();
    let bsp=peer();
    clock.with_locked(|state| {
        state.initialized=true;
        let source=ReferenceClock::Pm(PmTimer{access:crate::reference_clock::PmAccess::Io(0x408),wide:false});
        state.physical=Some(ClockSet::new((source,0),None));
        assert_eq!(clock.publish_tsc_locked(state,0,&[0],[(0,bsp)],wrong_cpu),
            Err(b"invalid TSC epoch publication state" as &[u8]));
        assert!(state.fallback.local.is_none());
        assert_eq!(state.physical.as_ref().unwrap().source(),Some(source));
    });
}
