//! Exercise production TSC qualification and AP/BSP exchange logic.
//! Hardware reads are injected only by this separate host harness.
#![allow(dead_code)]
#[path = "../../kernel/reference_clock.rs"]
mod reference_clock;
#[path = "../../kernel/tsc.rs"]
mod tsc;
use tsc::{Capabilities, Observation, Bracket, Alignment, Peer};

#[test]
fn cpuid_range_and_invariant_flag_are_required() {
    let ratio = [2, 250, 24_000_000];
    let c = tsc::capabilities(0x15, 1<<4, 0x8000_0007, 1<<8, ratio);
    assert_eq!(c,Capabilities {available:true,invariant:true,nominal_hz:Some(3_000_000_000)});
    for (basic, flags, extended, invariant) in [
        (0,1<<4,0x8000_0007,1<<8), (0x15,0,0x8000_0007,1<<8),
        (0x15,1<<4,0x8000_0006,1<<8), (0x15,1<<4,0x8000_0007,0)
    ] {
        let c=tsc::capabilities(basic,flags,extended,invariant,ratio);
        assert!(!c.invariant);
        assert_eq!(c.nominal_hz,None);
        assert_eq!(tsc::qualified_rate(c,[3_000_000_000;3]),None);
    }
    assert_eq!(tsc::capabilities(0x14,1<<4,0x8000_0007,1<<8,ratio).nominal_hz,None);
    for x in [[0,1,1],[1,0,1],[1,1,0],[2,1,1]] {
        assert_eq!(tsc::crystal_rate(x[0],x[1],x[2]),None);
    }
    assert_eq!(tsc::crystal_rate(1,u32::MAX,u32::MAX),
               Some(u32::MAX as u64*u32::MAX as u64));
}

#[test]
fn calibration_requires_consistent_bounded_independent_observations() {
    let c=Capabilities{available:true,invariant:true,nominal_hz:None};
    assert_eq!(tsc::qualified_rate(c,[2_999_900_000,3_000_000_000,3_000_100_000]),Some(3_000_000_000));
    assert_eq!(tsc::qualified_rate(c,[2_900_000_000,3_000_000_000,3_000_000_000]),None);
    assert_eq!(tsc::qualified_rate(c,[0,3_000_000_000,3_000_000_000]),None);
    let nominal=Capabilities{nominal_hz:Some(3_000_000_000),..c};
    assert_eq!(tsc::qualified_rate(nominal,[3_000_100_000;3]),Some(3_000_000_000));
    assert_eq!(tsc::qualified_rate(nominal,[2_800_000_000;3]),None);

    let o=Observation{before_start:100,after_start:200,before_end:150_000_100,
                      after_end:150_000_200,reference_ns:50_000_000};
    assert_eq!(tsc::measured_rate(o),Some(3_000_000_000));
    for bad in [Observation{reference_ns:0,..o}, Observation{reference_ns:1_000_000_000,..o},
                Observation{after_start:99,..o},Observation{before_end:1,..o},
                Observation{after_end:160_000_200,..o},Observation{after_end:150_000_099,..o}] {
        assert_eq!(tsc::measured_rate(bad),None);
    }
}

#[test]
fn alignment_intersects_bounds_and_handles_both_offset_signs() {
    for offset in [-10_000i64,10_000] {
        let a=tsc::align(3_000_000_000,3_000_000_000,|seq|{
            let remote=1_000_000+1000*seq as u64;
            let local=(remote as i64+offset) as u64;
            let margin=100-seq as u64*10;
            Some(Bracket{before:local-margin,remote,after:local+margin})
        }).unwrap();
        assert_eq!(a,Alignment{offset,uncertainty_ticks:20});
        assert_eq!(a.normalize(1_000_000),Some((1_000_000i64+offset) as u64));
    }
    assert_eq!(Alignment{offset:-10,uncertainty_ticks:0}.normalize(5),None);
    assert_eq!(Alignment{offset:10,uncertainty_ticks:0}.normalize(u64::MAX),None);
}

#[test]
fn uncertain_conflicting_or_missing_alignment_is_rejected() {
    let hz=3_000_000_000;
    assert_eq!(tsc::align(hz,hz+10_000_000,|_|panic!("incompatible rates")),None);
    assert_eq!(tsc::align(hz,hz,|_|None),None);
    assert_eq!(tsc::align(hz,hz,|_|Some(Bracket{before:10,remote:8,after:9})),None);
    assert_eq!(tsc::align(hz,hz,|seq|Some(Bracket{
        before:10+100*seq as u64,remote:1,after:20+100*seq as u64})),None);
    assert_eq!(tsc::align(hz,hz,|_|Some(Bracket{before:0,remote:1_000_000,after:1_000_000})),None);
    assert_eq!(tsc::align(hz,hz,|_|Some(Bracket{before:0,remote:u64::MAX,after:0})),None);
}

#[test]
fn real_mailbox_handshake_never_reuses_a_response() {
    let peer=Peer::new();
    assert!(!peer.ready());
    assert_eq!(peer.rate(),None);
    assert!(!peer.respond(||panic!("no request")));
    assert_eq!(peer.alignment(),None);
    peer.publish_rate(Some(proof(3_000_000_000)));
    assert!(peer.ready());
    assert_eq!(peer.rate(),Some(3_000_000_000));
    let aligned=std::thread::scope(|scope|{
        let worker=scope.spawn(|| {
            for i in 1..=8 {
                let until = std::time::Instant::now() + std::time::Duration::from_secs(5);
                while !peer.respond(||1_000_000_000+1000*i) {
                    assert!(std::time::Instant::now() < until, "BSP stopped requesting");
                    std::thread::yield_now();
                }
            }
        });
        let result=tsc::align(3_000_000_000,peer.rate().unwrap(),|seq|{
            let center=1_000_000_500+1000*seq as u64;
            let mut times=[center-10,center+10].into_iter();
            peer.exchange(seq,||times.next().unwrap(),|p,s|{
                let until = std::time::Instant::now() + std::time::Duration::from_secs(5);
                while std::time::Instant::now() < until {
                    if p.answered(s) {return true;}
                    std::thread::yield_now();
                }
                false
            })
        });
        // All eight replies must be consumed before publishing alignment.
        assert!(result.is_some());
        worker.join().unwrap();
        result.unwrap()
    });
    assert_eq!(aligned,Alignment{offset:500,uncertainty_ticks:10});
    peer.publish_alignment(aligned);
    assert_eq!(peer.alignment(),Some(aligned));
    assert!(!peer.respond(||panic!("duplicate response")));
    assert_eq!(peer.exchange(8,||panic!("stale sequence"),|_,_|true),None);
    assert_eq!(peer.exchange(9,||0,|_,_|false),None);
    assert_eq!(peer.exchange(9,||panic!("cancelled sequence"),|_,_|true),None);
    let diagnostic=tsc::Diagnostic::new(3,&peer);
    assert_eq!(diagnostic.bytes(),b"TSC APIC=3 HZ=3000000000 OFFSET=500 ERROR-TICKS=10");
    let unsupported=Peer::new();
    unsupported.publish_rate(None);
    assert_eq!(unsupported.exchange(1,||panic!("unsupported"),|_,_|true),None);
}

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

#[test]
fn rate_token_requires_three_monotonic_independent_windows() {
    let caps=Capabilities{available:true,invariant:true,nominal_hz:Some(3_000_000_000)};
    let observation=|start:u64,delta:u64| Observation{before_start:start,after_start:start,
        before_end:start+delta,after_end:start+delta,reference_ns:50_000_000};
    let mut c=tsc::Calibration::new(caps);
    c.observe(observation(100,150_000_000)).unwrap();
    assert_eq!(c.finish(),None);
    let mut c=tsc::Calibration::new(caps);
    c.observe(observation(100,150_000_000)).unwrap();
    assert_eq!(c.observe(observation(99,150_000_000)),None);
    assert_eq!(c.observe(observation(500_000_000,150_000_000)),None);
    assert_eq!(c.finish(),None);
    let mut c=tsc::Calibration::new(caps);
    for (start,delta) in [(100,150_000_000),(200_000_000,140_000_000),
                          (400_000_000,150_000_000)] {
        c.observe(observation(start,delta)).unwrap();
    }
    assert_eq!(c.finish(),None);
    let mut c=tsc::Calibration::new(Capabilities{invariant:false,..caps});
    for start in [100,200_000_000,400_000_000] {
        c.observe(observation(start,150_000_000)).unwrap();
    }
    assert_eq!(c.finish(),None);
    assert_eq!(proof(3_000_000_000).hz(),3_000_000_000);
}

#[test]
fn offset_refinement_rejects_changed_or_regressing_cpus() {
    let hz=3_000_000_000;
    let a=Alignment{offset:100,uncertainty_ticks:10};
    assert_eq!(a.intersect(Alignment{offset:105,uncertainty_ticks:5}),
        Some(Alignment{offset:105,uncertainty_ticks:5}));
    assert_eq!(a.intersect(Alignment{offset:121,uncertainty_ticks:10}),None);
    assert_eq!(tsc::align(hz,hz,|seq| {
        let raw=1_000_000-100*seq as u64;
        Some(Bracket{before:raw,remote:raw,after:raw+1})
    }),None);
    assert_eq!(tsc::align(hz,hz,|seq| {
        let raw=1_000_000+100*seq as u64;
        Some(Bracket{before:raw-10,remote:1_000_000,after:raw+10})
    }),None);
    let peer=Peer::new();
    peer.publish_rate(Some(proof(hz)));
    assert!(peer.publish_alignment(a));
    assert_eq!(peer.refine_alignment(Alignment{offset:121,uncertainty_ticks:10}),None);
    assert_eq!(peer.alignment(),Some(a));
    assert!(peer.seal());
    assert!(!peer.publish_alignment(Alignment{offset:0,uncertainty_ticks:0}));
    peer.publish_rate(Some(proof(hz+1_000)));
    assert_eq!(peer.rate(),Some(hz));
    assert_eq!(peer.alignment(),Some(a));
}

#[test]
fn repeat_rate_must_continue_raw_history_before_sealing() {
    let hz=3_000_000_000;
    let peer=Peer::new();
    peer.publish_rate(Some(proof(hz)));
    assert!(!peer.confirm_rate(proof(hz))); // same old evidence cannot renew qualification
    let caps=Capabilities{available:true,invariant:true,nominal_hz:Some(hz)};
    let mut calibration=tsc::Calibration::new(caps);
    for i in 0..3u64 {
        let start=2*hz+i*(hz/10);
        let end=start+hz/20;
        calibration.observe(Observation{before_start:start,after_start:start,
            before_end:end,after_end:end,reference_ns:50_000_000}).unwrap();
    }
    let next=calibration.finish().unwrap();
    assert!(peer.confirm_rate(next));
    assert_eq!(peer.last_verified_raw(),2*hz+hz/4);
    assert!(peer.publish_alignment(Alignment{offset:0,uncertainty_ticks:0}));
    assert!(peer.seal());
    assert!(!peer.confirm_rate(next));
}
