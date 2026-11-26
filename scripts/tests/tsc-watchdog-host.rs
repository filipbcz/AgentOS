//! Real production clock comparison and runtime state machine; samples are
//! supplied by an isolated host fixture. No privileged IRQ or hardware access.
#![allow(dead_code)]
#[path="../../kernel/reference_clock.rs"] mod reference_clock;
#[path="../../kernel/tsc.rs"] mod tsc;
#[path="../../kernel/clock_quorum.rs"] mod clock_quorum;
#[path="../../kernel/tsc_watchdog.rs"] mod tsc_watchdog;
#[path="../../kernel/timer.rs"] mod timer;
use tsc::Alignment;
use tsc_watchdog::{Health, RuntimeMonitor, Sample, Watchdog};
const HZ: u64 = 3_000_000_000;
const ZERO: Alignment = Alignment { offset: 0, uncertainty_ticks: 0 };
const AP: Alignment = Alignment { offset: -10_000, uncertainty_ticks: 30 };

fn sample(ns:u64, offset:u64)->Sample {
    let tick=100_000_000+3*ns+offset;
    Sample{reference_ns:ns,before:tick-60,after:tick+60}
}

#[test]
fn both_cpus_require_three_distinct_windows_and_shared_alignment() {
    let monitor=RuntimeMonitor::new();
    let mut bsp=Watchdog::new();
    let mut ap=Watchdog::new();
    assert!(monitor.start(7,HZ,[7,19]));
    assert!(monitor.active());
    for i in 0..=3 {
        let ns=i*500_000_000;
        let expected=if i==3 {Health::Verified} else {Health::Pending};
        assert_eq!(monitor.observe(7,HZ,ZERO,&mut bsp,Some(sample(ns,0))),expected);
        assert_eq!(monitor.observe(19,HZ,AP,&mut ap,Some(sample(ns+10_000,10_000))),expected);
        if i<3 {
            for j in 1..=10 {
                assert_ne!(monitor.observe(19,HZ,AP,&mut ap,
                           Some(sample(ns+10_000+j*100_000,10_000))),Health::Verified);
            }
        }
    }
}

#[test]
fn a_shift_on_one_cpu_revokes_machine_candidate() {
    let monitor=RuntimeMonitor::new();
    let mut bsp=Watchdog::new();
    let mut ap=Watchdog::new();
    assert!(monitor.start(0,HZ,[0,1]));
    assert_eq!(monitor.observe(0,HZ,ZERO,&mut bsp,Some(sample(0,0))),Health::Pending);
    monitor.observe(1,HZ,AP,&mut ap,Some(sample(10_000,10_000)));
    monitor.observe(0,HZ,ZERO,&mut bsp,Some(sample(500_000_000,0)));
    // One AP jumped 20ms relative to the BSP and the physical reference.
    assert_eq!(monitor.observe(1,HZ,AP,&mut ap,Some(sample(500_010_000,60_010_000))),Health::Rejected);
    assert!(!monitor.active());
    assert!(!monitor.start(0,HZ,[0,1]));
    assert!(!monitor.active());
}

#[test]
fn reference_freeze_or_tsc_regression_is_not_certified() {
    let monitor=RuntimeMonitor::new();
    let mut bsp=Watchdog::new();
    assert!(monitor.start(0,HZ,[0]));
    monitor.observe(0,HZ,ZERO,&mut bsp,Some(sample(10,0)));
    let mut stopped=sample(1_000_000_000,0);
    stopped.reference_ns=10;
    assert_eq!(monitor.observe(0,HZ,ZERO,&mut bsp,Some(stopped)),Health::Rejected);
    assert!(!monitor.active());

    let monitor=RuntimeMonitor::new();
    let mut bsp=Watchdog::new();
    assert!(monitor.start(0,HZ,[0]));
    monitor.observe(0,HZ,ZERO,&mut bsp,Some(sample(500_000_000,0)));
    let mut regression=sample(1,0);
    regression.reference_ns=600_000_000;
    assert_eq!(monitor.observe(0,HZ,ZERO,&mut bsp,Some(regression)),Health::Rejected);
}

#[test]
fn bounded_brackets_and_long_gaps_requalify_instead_of_inventing_time() {
    let monitor=RuntimeMonitor::new();
    let mut bsp=Watchdog::new();
    assert!(monitor.start(0,HZ,[0]));
    for i in 0..=3 {monitor.observe(0,HZ,ZERO,&mut bsp,Some(sample(i*500_000_000,0)));}
    assert_eq!(bsp.health(),Health::Verified);
    let mut slow=sample(2_000_000_000,0);
    slow.after+=HZ/100;
    assert_eq!(monitor.observe(0,HZ,ZERO,&mut bsp,Some(slow)),Health::Unverified);
    assert!(monitor.active());
    for i in 0..=3 {monitor.observe(0,HZ,ZERO,&mut bsp,Some(sample(3_000_000_000+i*500_000_000,0)));}
    assert_eq!(bsp.health(),Health::Verified);
    assert_eq!(monitor.observe(0,HZ,ZERO,&mut bsp,Some(sample(9_000_000_000,0))),Health::Unverified);
    assert_eq!(monitor.observe(0,HZ,ZERO,&mut bsp,None),Health::Unverified);
    assert!(monitor.active());
}

#[test]
fn cross_cpu_brackets_may_be_ordered_in_either_direction() {
    let monitor=RuntimeMonitor::new();
    let mut bsp=Watchdog::new();
    let mut ap=Watchdog::new();
    assert!(monitor.start(0,HZ,[0,1]));
    monitor.observe(0,HZ,ZERO,&mut bsp,Some(sample(100_000,0)));
    // The AP completed its measurement before the BSP published its anchor.
    assert_eq!(monitor.observe(1,HZ,AP,&mut ap,Some(sample(90_000,10_000))),Health::Pending);
    assert!(monitor.active());
    assert_eq!(monitor.observe(1,HZ,AP,&mut ap,Some(sample(3_000_000_000,10_000))),Health::Unverified);
    assert!(monitor.active());
}

#[test]
fn maintenance_updates_preserve_pending_earlier_deadline() {
    use timer::{Action,Timer};
    let mut t=Timer::new(1000,None);
    t.reset(Some(0));
    assert_eq!(t.plan(false,None,0),Action::Disable);
    t.set_maintenance(Some(1000));
    assert_eq!(t.plan(false,None,0),Action::Arm(100_000));
    assert!(!t.sample(98_000,Some(20)));
    assert_eq!(t.plan(false,Some(25),20),Action::Arm(500));
    t.set_maintenance(Some(500));
    assert_eq!(t.plan(false,Some(25),20),Action::Keep);
    t.set_maintenance(None);
    assert_eq!(t.plan(false,Some(25),20),Action::Keep);
    assert_eq!(t.plan(false,None,25),Action::Disable);
}

#[test]
fn complete_sparse_fleet_must_be_verified_before_witness_is_available() {
    let monitor=RuntimeMonitor::new();
    assert!(!monitor.start(7,HZ,[19,201]));
    assert!(!monitor.start(7,HZ,[7,19,19]));
    assert!(!monitor.start(7,0,[7]));
    assert!(monitor.start(7,HZ,[7,19,201]));
    assert!(!monitor.start(7,HZ,[7]));
    let mut bsp=Watchdog::new();
    let mut ap1=Watchdog::new();
    let mut ap2=Watchdog::new();
    let local=sample(1_500_100_000,0).after;
    for i in 0..=3 {
        let ns=i*500_000_000;
        monitor.observe(7,HZ,ZERO,&mut bsp,Some(sample(ns,0)));
        monitor.observe(19,HZ,AP,&mut ap1,Some(sample(ns+10_000,10_000)));
        if i<3 {
            monitor.observe(201,HZ,ZERO,&mut ap2,Some(sample(ns+20_000,0)));
        }
    }
    assert_eq!(monitor.witness(7,ZERO,local),None);
    assert_eq!(ap2.health(),Health::Pending);
    monitor.observe(201,HZ,ZERO,&mut ap2,Some(sample(1_500_020_000,0)));
    assert_eq!(ap2.health(),Health::Verified);
    let witness=monitor.witness(7,ZERO,local).unwrap();
    assert_eq!(witness.ticks,local);
    assert_eq!(witness.hz,HZ);
    let ap_raw=local+10_000;
    assert_eq!(monitor.witness(19,AP,ap_raw).unwrap().ticks,local);
    assert_eq!(monitor.witness(20,ZERO,local),None);
    assert_eq!(monitor.witness(19,ZERO,ap_raw),None);
    assert_eq!(monitor.witness(7,ZERO,1),None);
    // Regression after a granted witness must also be rejected, even
    // if it is still later than the last independent watchdog sample.
    assert!(monitor.witness(7,ZERO,local+300_000).is_some());
    assert_eq!(monitor.witness(7,ZERO,local+299_999),None);
    assert!(monitor.witness(7,ZERO,local+300_001).is_some());
}

#[test]
fn a_missing_or_expired_member_cannot_be_renewed_by_reading_tsc() {
    let monitor=RuntimeMonitor::new();
    assert!(monitor.start(0,HZ,[0,1]));
    let mut bsp=Watchdog::new();
    let mut ap=Watchdog::new();
    for i in 0..=3 {
        let ns=i*500_000_000;
        monitor.observe(0,HZ,ZERO,&mut bsp,Some(sample(ns,0)));
        monitor.observe(1,HZ,AP,&mut ap,Some(sample(ns+10_000,10_000)));
    }
    let now=sample(1_600_000_000,0).after;
    assert!(monitor.witness(0,ZERO,now).is_some());
    // Frequent reads are not independent verification windows.
    for _ in 0..100 {
        assert!(monitor.witness(0,ZERO,now).is_some());
    }
    for i in 4..=8 {
        let ns=i*500_000_000;
        monitor.observe(0,HZ,ZERO,&mut bsp,Some(sample(ns,0)));
    }
    assert_eq!(monitor.witness(0,ZERO,sample(4_100_000_000,0).after),None);
    // Missing AP data invalidates its lease immediately; require three
    // fresh full windows again, not merely a successful short read.
    assert_eq!(monitor.observe(1,HZ,AP,&mut ap,None),Health::Unverified);
    for i in 0..=3 {
        let ns=4_200_000_000+i*500_000_000;
        monitor.observe(0,HZ,ZERO,&mut bsp,Some(sample(ns,0)));
        monitor.observe(1,HZ,AP,&mut ap,Some(sample(ns+10_000,10_000)));
        if i<3 {
            assert_eq!(monitor.witness(0,ZERO,sample(ns+20_000,0).after),None);
        }
    }
    assert!(monitor.witness(0,ZERO,sample(5_710_000_000,0).after).is_some());
    monitor.reject();
    assert!(!monitor.active());
    assert_eq!(monitor.witness(0,ZERO,sample(5_720_000_000,0).after),None);
}
