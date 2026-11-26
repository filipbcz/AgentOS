//! Actual epoch math and source selection, with hardware register reads
//! supplied by a host fixture. No privileged IRQ operations are executed.
#![allow(dead_code)]
#[path = "../../kernel/reference_clock.rs"]
mod reference_clock;
#[path = "../../kernel/clock_quorum.rs"]
mod clock_quorum;
#[path = "../../kernel/system_clock.rs"]
mod system_clock;
#[path = "../../kernel/timer.rs"]
mod timer;

use reference_clock::{PmAccess, PmTimer, ReferenceClock};
use system_clock::{Epoch, choose};

fn pm(wide: bool) -> ReferenceClock {
    ReferenceClock::Pm(PmTimer { access: PmAccess::Io(0x408), wide })
}
fn hp(wide: bool, period_fs: u64) -> ReferenceClock {
    ReferenceClock::Hpet { base: 0xfed0_0000, period_fs, wide }
}

#[test]
fn real_rates_and_wraps_preserve_one_epoch() {
    for (source, mask, advance, rate) in [
        (pm(false), 0xff_ffff, 100_000u64, 3_579_545u128),
        (pm(true), 0xffff_ffff, 10_000_000, 3_579_545),
        (hp(false,100_000_000), 0xffff_ffff, 10_000_000, 10_000_000),
    ] {
        let mut raw = mask - 10;
        let mut epoch = Epoch::new(source, raw);
        let mut ticks = 0u128;
        for _ in 0..2000 {
            raw = (raw+advance)&mask;
            ticks += advance as u128;
            assert_eq!(epoch.observe(raw), Some((ticks*1000/rate) as u64));
        }
    }
}

#[test]
fn fractional_conversion_and_regression_fail_closed() {
    let mut epoch = Epoch::new(hp(true,69_841_279),0);
    assert_eq!(epoch.observe(14_318),Some(0));
    assert_eq!(epoch.observe(14_319),Some(1));
    assert_eq!(epoch.observe(14_318_179),Some(999));
    assert_eq!(epoch.observe(14_318_181),Some(1000));
    assert_eq!(epoch.observe(1),None);
    assert_eq!(epoch.observe(20_000_000),None);
    let mut epoch = Epoch::new(pm(false),1000);
    assert_eq!(epoch.observe(999),None);
    assert_eq!(epoch.observe(1001),None);
}

#[test]
fn chooses_only_maintainable_progressing_sources() {
    let p = PmTimer { access: PmAccess::Io(0x408), wide:false };
    let h = hp(false,100_000_000);
    assert_eq!(choose(Some(p),Some(h),|_|true),Some(h));
    assert_eq!(choose(Some(p),Some(h),|s|s==pm(false)),Some(pm(false)));
    assert_eq!(choose(Some(p),None,|_|true),Some(pm(false)));
    assert_eq!(choose(Some(p),Some(hp(false,1)),|_|true),Some(pm(false)));
    assert_eq!(choose(None,Some(h),|_|false),None);
    assert_eq!(choose(None,None,|_|true),None);
    assert_eq!(pm(false).maintenance_ms(),Some(1000));
    assert_eq!(hp(true,100_000_000).maintenance_ms(),None);
    assert_eq!(hp(false,1_000).maintenance_ms(),Some(1));
}

#[test]
fn serialized_cpu_observations_preserve_shared_epoch_across_wrap() {
    use std::sync::{Arc, Mutex};
    let state = Arc::new(Mutex::new((0xfff000u64, Epoch::new(pm(false),0xfff000))));
    let threads: Vec<_> = (0..4).map(|_| {
        let state = Arc::clone(&state);
        std::thread::spawn(move || {
            let mut previous = 0;
            for _ in 0..20_000 {
                let mut state = state.lock().unwrap();
                state.0 = (state.0+2000)&0xffffff;
                let raw = state.0;
                let now = state.1.observe(raw).unwrap();
                assert!(now>=previous);
                previous=now;
            }
        })
    }).collect();
    for t in threads { t.join().unwrap(); }
    let mut state=state.lock().unwrap();
    let raw=state.0;
    assert_eq!(state.1.observe(raw),Some(160_000_000u64*1000/3_579_545));
}

#[test]
fn owner_timer_maintains_wrap_without_runnable_tasks_or_deadlines() {
    use timer::{Timer,Action};
    let mut timer=Timer::new(1000,Some(1000));
    timer.reset(Some(0));
    assert_eq!(timer.plan(false,None,0),Action::Arm(100_000));
    assert!(!timer.sample(50_000,Some(500)));
    assert_eq!(timer.plan(false,None,500),Action::Keep);
    assert_eq!(timer.plan(false,Some(510),500),Action::Arm(1000));
    let mut timer=Timer::new(1000,Some(2));
    assert_eq!(timer.plan(true,None,0),Action::Arm(200));
    assert_eq!(timer.plan(false,None,0),Action::Keep);
    let mut other=Timer::new(1000,None);
    assert_eq!(other.plan(false,None,0),Action::Disable);
}

#[test]
fn saturates_abi_and_does_not_invent_progress_when_counter_stops() {
    let source=hp(true,100_000_000);
    assert_eq!(source.ticks_to_ms(u128::MAX),isize::MAX as u64);
    let mut epoch=Epoch::new(source,123);
    assert_eq!(epoch.observe(123),Some(0));
    assert_eq!(epoch.observe(123),Some(0));
    assert_eq!(epoch.observe(10123),Some(1));
}

#[test]
fn exact_reference_nanoseconds_do_not_truncate_the_millisecond_abi() {
    assert_eq!(pm(false).total_ns(3_579_545),Some(1_000_000_000));
    assert_eq!(pm(true).total_ns(1),Some(279));
    assert_eq!(hp(true,100_000_000).total_ns(10_000_001),Some(1_000_000_100));
    assert_eq!(hp(true,100_000_000).total_ns(u128::MAX),None);
    assert_eq!(pm(false).total_ns(u128::MAX),None);
    assert_eq!(hp(true,100_000_000).ticks_to_ms(u128::MAX),isize::MAX as u64);
}


use system_clock::{ClockSet, ClockEvent};

struct Rig {
    clocks: ClockSet,
    primary: ReferenceClock,
    shadow: ReferenceClock,
    active_raw: u64,
    shadow_raw: u64,
}

impl Rig {
    fn new(primary: ReferenceClock, shadow: ReferenceClock, start: u64) -> Self {
        Self {
            clocks: ClockSet::new((primary, start & primary.mask()),
                Some((shadow, start & shadow.mask()))),
            primary, shadow, active_raw: start & primary.mask(),
            shadow_raw: start & shadow.mask(),
        }
    }

    fn observe(&mut self) -> Option<u128> {
        let (primary, shadow, a, b) = (self.primary, self.shadow,
                                      self.active_raw, self.shadow_raw);
        self.clocks.sample(|source| {
            if source == primary { a }
            else { assert_eq!(source, shadow); b }
        })
    }

    fn advance(&mut self, active_ticks: u64, shadow_ticks: u64) -> Option<u128> {
        self.active_raw = self.active_raw.wrapping_add(active_ticks) & self.primary.mask();
        self.shadow_raw = self.shadow_raw.wrapping_add(shadow_ticks) & self.shadow.mask();
        self.observe()
    }
}

fn qualified_pair() -> Rig {
    let mut rig = Rig::new(hp(true,100_000_000), pm(false), 0xfff000);
    assert_eq!(rig.clocks.maintenance_ms(),Some(1000));
    assert_eq!(rig.observe(),Some(0));
    // Four 200ms windows, including a genuine standby PM24 wrap.
    for i in 1..=4 {
        assert_eq!(rig.advance(2_000_000,715_909),Some(i*200_000_000));
    }
    assert!(rig.clocks.qualified());
    assert_eq!(rig.clocks.source(),Some(rig.primary));
    rig
}

#[test]
fn qualified_standby_preserves_epoch_after_primary_regression() {
    let mut rig=qualified_pair();
    rig.active_raw -= 1;
    let t=rig.advance(0,715_909).unwrap();
    assert_eq!(t,1_000_000_000);
    assert_eq!(rig.clocks.source(),Some(rig.shadow));
    assert_eq!(rig.clocks.take_event(),Some(ClockEvent::PromotedPm));
    assert!(!rig.clocks.qualified());
    assert_eq!(rig.advance(0,715_909),Some(1_200_000_000));
    assert_eq!(rig.clocks.take_event(),None);
    // The failed primary is not recycled, even when it later progresses.
    rig.shadow_raw=rig.shadow_raw.wrapping_sub(1)&rig.shadow.mask();
    assert_eq!(rig.advance(10_000_000,0),None);
    assert_eq!(rig.clocks.take_event(),Some(ClockEvent::Unavailable));
    assert_eq!(rig.advance(10_000_000,715_909),None);
}

#[test]
fn stalled_primary_needs_sustained_standby_progress() {
    let mut rig=qualified_pair();
    assert_eq!(rig.advance(0,715_909),Some(800_000_000));
    assert_eq!(rig.clocks.source(),Some(rig.primary));
    for _ in 0..20 { assert_eq!(rig.observe(),Some(800_000_000)); }
    assert_eq!(rig.advance(0,715_909),Some(1_200_000_000));
    assert_eq!(rig.clocks.source(),Some(rig.shadow));
    assert_eq!(rig.clocks.take_event(),Some(ClockEvent::PromotedPm));
    assert_eq!(rig.advance(0,715_909),Some(1_400_000_000));
}

#[test]
fn broken_standby_does_not_interrupt_healthy_primary() {
    let mut rig=qualified_pair();
    rig.shadow_raw=rig.shadow_raw.wrapping_sub(1)&rig.shadow.mask();
    assert_eq!(rig.advance(2_000_000,0),Some(1_000_000_000));
    assert_eq!(rig.clocks.source(),Some(rig.primary));
    assert_eq!(rig.clocks.take_event(),Some(ClockEvent::StandbyRetired));
    assert_eq!(rig.clocks.maintenance_ms(),None);
    assert_eq!(rig.advance(2_000_000,0),Some(1_200_000_000));
    assert!(!rig.clocks.qualified());
}

#[test]
fn unqualified_or_disagreeing_standby_cannot_replace_primary() {
    let mut rig=Rig::new(hp(true,100_000_000),pm(false),100);
    assert_eq!(rig.observe(),Some(0));
    for i in 1..=8 {
        assert_eq!(rig.advance(2_000_000,1_000_000),Some(i*200_000_000));
    }
    assert!(!rig.clocks.qualified());
    rig.active_raw -= 1;
    assert_eq!(rig.advance(0,715_909),None);
    assert_eq!(rig.clocks.source(),None);
    assert_eq!(rig.clocks.take_event(),Some(ClockEvent::Unavailable));
}

#[test]
fn late_sample_requalifies_standby_instead_of_reusing_ambiguous_residue() {
    let mut rig=qualified_pair();
    assert_eq!(rig.advance(50_000_000,17_897_725),Some(5_800_000_000));
    assert_eq!(rig.clocks.take_event(),Some(ClockEvent::StandbyRebased));
    assert_eq!(rig.clocks.source(),Some(rig.primary));
    assert!(!rig.clocks.qualified());
    for _ in 0..4 {rig.advance(2_000_000,715_909);}
    assert!(rig.clocks.qualified());
    rig.active_raw-=1;
    assert_eq!(rig.advance(0,715_909),Some(6_800_000_000));
    assert_eq!(rig.clocks.source(),Some(rig.shadow));

    let mut rig=Rig::new(pm(false),hp(true,100_000_000),10);
    rig.observe();
    for _ in 0..4 {rig.advance(715_909,2_000_000);}
    assert!(rig.clocks.qualified());
    // No third independent witness can resolve the active short counter.
    assert_eq!(rig.advance(17_897_725,50_000_000),None);
    assert_eq!(rig.clocks.take_event(),Some(ClockEvent::Unavailable));
}

#[test]
fn either_hardware_source_can_be_promoted_and_two_failures_are_terminal() {
    let mut rig=Rig::new(pm(true),hp(true,100_000_000),100);
    assert_eq!(rig.observe(),Some(0));
    for _ in 0..4 {rig.advance(715_909,2_000_000);}
    assert!(rig.clocks.qualified());
    rig.active_raw -= 1;
    assert_eq!(rig.advance(0,2_000_000),Some(1_000_000_000));
    assert_eq!(rig.clocks.source(),Some(rig.shadow));
    assert_eq!(rig.clocks.take_event(),Some(ClockEvent::PromotedHpet));
    let mut both=qualified_pair();
    both.active_raw-=1;
    both.shadow_raw=both.shadow_raw.wrapping_sub(1)&both.shadow.mask();
    assert_eq!(both.observe(),None);
    assert_eq!(both.clocks.take_event(),Some(ClockEvent::Unavailable));
}

#[test]
fn wide_read_bracket_and_stale_anchor_do_not_authorize_switch() {
    let mut rig=qualified_pair();
    let a=rig.active_raw;
    let b=rig.shadow_raw;
    let mut reads=0;
    let ns=rig.clocks.sample(|source| {
        if source==rig.primary {
            reads+=1;
            if reads==1 {a} else {a+10_000}
        } else {b}
    });
    assert_eq!(ns,Some(801_000_000));
    assert!(!rig.clocks.qualified());
    rig.active_raw=a+9999;
    assert_eq!(rig.advance(0,715_909),None);
    let mut rig=qualified_pair();
    rig.active_raw-=1;
    assert_eq!(rig.advance(0,8_590_908),None);
    assert_eq!(rig.clocks.take_event(),Some(ClockEvent::Unavailable));
}

#[test]
fn contradictory_sample_between_windows_invalidates_anchor() {
    let mut rig=qualified_pair();
    assert_eq!(rig.advance(10_000,35_795),Some(801_000_000));
    assert!(!rig.clocks.qualified());
    rig.active_raw-=1;
    assert_eq!(rig.advance(0,715_909),None);
}

#[test]
fn optional_unqualified_source_cannot_disable_primary_by_a_forward_jump() {
    let mut rig=Rig::new(pm(false),hp(true,100_000_000),10);
    rig.observe();
    assert_eq!(rig.advance(715_909,50_000_000),Some(200_000_000));
    assert_eq!(rig.clocks.take_event(),Some(ClockEvent::StandbyRebased));
    assert_eq!(rig.clocks.source(),Some(rig.primary));
    assert!(!rig.clocks.qualified());
}

#[test]
fn transient_stall_and_promotion_preserve_absolute_deadline() {
    let mut rig=qualified_pair();
    let deadline_ms=1100u128;
    assert_eq!(rig.advance(0,357_954).unwrap()/1_000_000,800);
    assert_eq!(rig.advance(2_000_000,357_955).unwrap()/1_000_000,1000);
    assert_eq!(rig.clocks.source(),Some(rig.primary));
    assert!(rig.clocks.qualified());
    rig.active_raw-=1;
    let now=rig.advance(0,715_909).unwrap()/1_000_000;
    assert_eq!(now,1200);
    assert!(now>=deadline_ms);
}

#[test]
fn concurrent_readers_use_one_continuous_epoch_after_promotion() {
    use std::sync::{Arc,Mutex};
    let state=Arc::new(Mutex::new(qualified_pair()));
    let mut threads=Vec::new();
    for _ in 0..4 {
        let shared=Arc::clone(&state);
        threads.push(std::thread::spawn(move || {
            let mut last=0;
            for _ in 0..1000 {
                let t=shared.lock().unwrap().advance(0,3579).unwrap();
                assert!(t>=last);
                last=t;
            }
        }));
    }
    for t in threads {t.join().unwrap();}
    let rig=state.lock().unwrap();
    assert_eq!(rig.clocks.source(),Some(rig.shadow));
}


// The real transition machine receives three independently controlled
// raw counter streams. Production code is never compiled in a test mode.
use clock_quorum::{Witness, TscBracket, Span, Verdict, decide};
const TSC_HZ: u64 = 3_000_000_000;
const TSC_ERROR: u64 = 18_000_000; // six milliseconds on the BSP scale

struct TripleRig {
    hardware: Rig,
    tsc_ticks: u64,
}

impl TripleRig {
    fn new() -> Self {
        Self { hardware: Rig::new(hp(true,100_000_000), pm(false), 0xfff000),
               tsc_ticks: 1_000_000_000 }
    }

    fn qualified() -> Self {
        let mut rig = Self::new();
        assert_eq!(rig.advance(0,0,0),Some(0));
        for i in 1..=4 {
            assert_eq!(rig.advance(2_000_000,715_909,200_000_000),Some(i*200_000_000));
        }
        assert!(rig.hardware.clocks.qualified());
        rig
    }

    fn witness(&self, cpu: u8) -> Witness {
        Witness { cpu, ticks: self.tsc_ticks, hz: TSC_HZ, uncertainty_ticks: TSC_ERROR }
    }

    fn advance_raw(&mut self, primary: u64, standby: u64, ns: u64) {
        let h=&mut self.hardware;
        h.active_raw=h.active_raw.wrapping_add(primary)&h.primary.mask();
        h.shadow_raw=h.shadow_raw.wrapping_add(standby)&h.shadow.mask();
        self.tsc_ticks+=ns*3;
    }

    fn observe(&mut self, before: Option<Witness>, after: Option<Witness>) -> Option<u128> {
        let h=&mut self.hardware;
        let (a,b,ar,br)=(h.primary,h.shadow,h.active_raw,h.shadow_raw);
        let mut samples=[before,after].into_iter();
        h.clocks.sample_with_witness(|source|{
            if source==a {ar} else {assert_eq!(source,b);br}
        },||samples.next().flatten())
    }

    fn advance(&mut self, primary: u64, standby: u64, ns: u64) -> Option<u128> {
        self.advance_raw(primary,standby,ns);
        let w=self.witness(0);
        self.observe(Some(w),Some(w))
    }
}

#[test]
fn qualified_third_clock_catches_forward_jump_before_publication() {
    let mut rig=TripleRig::qualified();
    assert_eq!(rig.advance(8_000_000,715_909,200_000_000),Some(1_000_000_000));
    assert_eq!(rig.hardware.clocks.source(),Some(rig.hardware.shadow));
    assert_eq!(rig.hardware.clocks.take_event(),Some(ClockEvent::PromotedPm));
    assert_eq!(rig.advance(0,715_909,200_000_000),Some(1_200_000_000));
}

#[test]
fn two_agreeing_sources_can_retire_either_bad_standby_or_bad_tsc() {
    let mut rig=TripleRig::qualified();
    assert_eq!(rig.advance(2_000_000,3_579_545,200_000_000),Some(1_000_000_000));
    assert_eq!(rig.hardware.clocks.source(),Some(rig.hardware.primary));
    assert_eq!(rig.hardware.clocks.take_event(),Some(ClockEvent::StandbyRetired));

    let mut rig=TripleRig::qualified();
    assert_eq!(rig.advance(2_000_000,715_909,800_000_000),Some(1_000_000_000));
    assert_eq!(rig.hardware.clocks.source(),Some(rig.hardware.primary));
    assert_eq!(rig.hardware.clocks.take_event(),Some(ClockEvent::TscRejected));
    // The retired witness is never read again. A later physical
    // disagreement must not use the same witness to force a switch.
    let h=&mut rig.hardware;
    h.active_raw+=2_000_000;
    h.shadow_raw=(h.shadow_raw+715_909)&h.shadow.mask();
    let (a,b,ar,br)=(h.primary,h.shadow,h.active_raw,h.shadow_raw);
    assert_eq!(h.clocks.sample_with_witness(|source|{
        if source==a {ar} else {assert_eq!(source,b);br}
    },||panic!("retired TSC must not be sampled")),Some(1_200_000_000));
}

#[test]
fn three_conflicting_clocks_cannot_publish_an_arbitrary_jump() {
    let mut rig=TripleRig::qualified();
    assert_eq!(rig.advance(6_000_000,1_431_818,200_000_000),None);
    assert_eq!(rig.hardware.clocks.source(),None);
    assert_eq!(rig.hardware.clocks.take_event(),Some(ClockEvent::Unavailable));
}

#[test]
fn jump_inside_primary_read_bracket_is_not_valid_evidence() {
    let mut rig=TripleRig::qualified();
    rig.advance_raw(0,715_909,200_000_000);
    let w=rig.witness(0);
    let h=&mut rig.hardware;
    let (a,b,ar,br)=(h.primary,h.shadow,h.active_raw,h.shadow_raw);
    let mut calls=0;
    assert_eq!(h.clocks.sample_with_witness(|source|{
        if source==a {
            calls+=1;
            if calls==1 {ar} else {ar+8_000_000}
        } else {assert_eq!(source,b);br}
    },||Some(w)),Some(1_000_000_000));
    assert_eq!(h.clocks.source(),Some(b));
}

#[test]
fn incomplete_or_migrated_tsc_bracket_clears_previous_triple_evidence() {
    for migrate in [false,true] {
        let mut rig=TripleRig::qualified();
        rig.advance_raw(4_000_000,715_909,200_000_000);
        let w=rig.witness(0);
        let after=if migrate {Some(rig.witness(1))} else {None};
        // Preserve the established two-source policy, not an expired
        // third vote. This disagreement invalidates the physical anchor.
        assert_eq!(rig.observe(Some(w),after),Some(1_200_000_000));
        assert_eq!(rig.hardware.clocks.source(),Some(rig.hardware.primary));
        assert!(!rig.hardware.clocks.qualified());
        rig.hardware.active_raw-=1;
        assert_eq!(rig.advance(0,715_909,200_000_000),None);
    }
}

#[test]
fn bounded_overlap_does_not_replace_common_anchor_with_disputed_time() {
    let mut rig=TripleRig::qualified();
    // Primary says 200ms, standby about 205ms. Both fit within the
    // TSC uncertainty; no unambiguous outlier yet.
    assert_eq!(rig.advance(2_000_000,733_807,202_000_000),Some(1_000_000_000));
    assert_eq!(rig.hardware.clocks.source(),Some(rig.hardware.primary));
    assert!(!rig.hardware.clocks.qualified());
    // Accumulated evidence now identifies a forward jump of primary.
    let now=rig.advance(8_000_000,715_909,200_000_000).unwrap();
    assert!((1_204_999_000..=1_205_001_000).contains(&now));
    assert_eq!(rig.hardware.clocks.source(),Some(rig.hardware.shadow));
}

#[test]
fn stale_third_clock_observation_is_not_used_to_choose_source() {
    let mut rig=TripleRig::qualified();
    // All readings progress but the interval exceeds the 2s vote
    // window. No qualified physical anchor may survive this gap.
    assert_eq!(rig.advance(21_000_000,7_517_044,2_100_000_000),Some(2_900_000_000));
    assert!(!rig.hardware.clocks.qualified());
    rig.hardware.active_raw-=1;
    assert_eq!(rig.advance(0,715_909,200_000_000),None);
}

#[test]
fn quorum_distinguishes_absence_overlap_and_disagreement() {
    let ms=|v:u128| Some(Span::exact(v*1_000_000));
    assert_eq!(decide(ms(200),ms(200),None),Verdict::PhysicalAgree);
    assert_eq!(decide(ms(200),ms(300),None),Verdict::Ambiguous);
    assert_eq!(decide(ms(200),ms(300),ms(200)),Verdict::ActiveAndTsc);
    assert_eq!(decide(ms(200),ms(300),ms(300)),Verdict::StandbyAndTsc);
    assert_eq!(decide(ms(200),ms(200),ms(300)),Verdict::TscRejected);
    assert_eq!(decide(ms(200),ms(210),Some(Span{low:195_000_000,high:215_000_000})),Verdict::Inconclusive);
    assert_eq!(decide(ms(200),ms(200),ms(200)),Verdict::AllAgree);
    assert_eq!(decide(ms(200),ms(400),ms(600)),Verdict::Ambiguous);
}

#[test]
fn tsc_bracket_validation_and_cross_cpu_normalized_elapsed_bounds() {
    let w=Witness{cpu:7,ticks:1_000_000_000,hz:TSC_HZ,uncertainty_ticks:3};
    let later=Witness{cpu:19,ticks:w.ticks+600_000_000,..w};
    let first=TscBracket::new(w,w).unwrap();
    let last=TscBracket::new(later,later).unwrap();
    assert_eq!(first.elapsed(last),Some(Span{low:199_999_998,high:200_000_002}));
    assert_eq!(last.elapsed(first),None);
    assert_eq!(TscBracket::new(w,Witness{cpu:19,..w}),None);
    assert_eq!(TscBracket::new(w,Witness{ticks:w.ticks+1_000_000,..w}),None);
    assert_eq!(TscBracket::new(w,Witness{ticks:w.ticks-1,..w}),None);
    assert_eq!(TscBracket::new(w,Witness{hz:0,..w}),None);
    assert_eq!(TscBracket::new(Witness{uncertainty_ticks:31_000_000,..w},w),None);
}
