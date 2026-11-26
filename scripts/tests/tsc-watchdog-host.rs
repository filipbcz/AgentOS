//! Real production clock comparison and runtime state machine; samples are
//! supplied by an isolated host fixture. No privileged IRQ or hardware access.
#![allow(dead_code)]
#[path="../../kernel/reference_clock.rs"] mod reference_clock;
#[path="../../kernel/tsc.rs"] mod tsc;
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
    monitor.start(7,HZ);
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
    monitor.start(0,HZ);
    assert_eq!(monitor.observe(0,HZ,ZERO,&mut bsp,Some(sample(0,0))),Health::Pending);
    monitor.observe(1,HZ,AP,&mut ap,Some(sample(10_000,10_000)));
    monitor.observe(0,HZ,ZERO,&mut bsp,Some(sample(500_000_000,0)));
    // One AP jumped 20ms relative to the BSP and the physical reference.
    assert_eq!(monitor.observe(1,HZ,AP,&mut ap,Some(sample(500_010_000,60_010_000))),Health::Rejected);
    assert!(!monitor.active());
    monitor.start(0,HZ);
    assert!(!monitor.active());
}

#[test]
fn reference_freeze_or_tsc_regression_is_not_certified() {
    let monitor=RuntimeMonitor::new();
    let mut bsp=Watchdog::new();
    monitor.start(0,HZ);
    monitor.observe(0,HZ,ZERO,&mut bsp,Some(sample(10,0)));
    let mut stopped=sample(1_000_000_000,0);
    stopped.reference_ns=10;
    assert_eq!(monitor.observe(0,HZ,ZERO,&mut bsp,Some(stopped)),Health::Rejected);
    assert!(!monitor.active());

    let monitor=RuntimeMonitor::new();
    let mut bsp=Watchdog::new();
    monitor.start(0,HZ);
    monitor.observe(0,HZ,ZERO,&mut bsp,Some(sample(500_000_000,0)));
    let mut regression=sample(1,0);
    regression.reference_ns=600_000_000;
    assert_eq!(monitor.observe(0,HZ,ZERO,&mut bsp,Some(regression)),Health::Rejected);
}

#[test]
fn bounded_brackets_and_long_gaps_requalify_instead_of_inventing_time() {
    let monitor=RuntimeMonitor::new();
    let mut bsp=Watchdog::new();
    monitor.start(0,HZ);
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
    monitor.start(0,HZ);
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
