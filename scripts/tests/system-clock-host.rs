//! Actual epoch math and source selection, with hardware register reads
//! supplied by a host fixture. No privileged IRQ operations are executed.
#![allow(dead_code)]
#[path = "../../kernel/reference_clock.rs"]
mod reference_clock;
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
