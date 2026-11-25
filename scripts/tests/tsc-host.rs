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
    peer.publish_rate(Some(3_000_000_000));
    assert!(peer.ready());
    assert_eq!(peer.rate(),Some(3_000_000_000));
    let aligned=std::thread::scope(|scope|{
        let worker=scope.spawn(|| {
            for i in 1..=8 {
                let until = std::time::Instant::now() + std::time::Duration::from_secs(5);
                while !peer.respond(||1_000_000+1000*i) {
                    assert!(std::time::Instant::now() < until, "BSP stopped requesting");
                    std::thread::yield_now();
                }
            }
        });
        let result=tsc::align(3_000_000_000,peer.rate().unwrap(),|seq|{
            let center=1_000_500+1000*seq as u64;
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
