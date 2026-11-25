//! Exercises the same short-interval conversion, source selection and
//! bounded polling as the kernel. Hardware reads alone are supplied by
//! the host fixture; no privileged instructions or test-only kernel mode.
#![allow(dead_code)]

#[path = "../../kernel/reference_clock.rs"]
mod reference_clock;
use reference_clock::{PmAccess, PmTimer, ReferenceClock, WaitError};

fn pm(wide: bool) -> ReferenceClock {
    ReferenceClock::Pm(PmTimer { access: PmAccess::Io(0x408), wide })
}
fn hpet() -> ReferenceClock {
    ReferenceClock::Hpet { base: 0xfed0_0000, period_fs: 100_000_000 }
}

#[test]
fn actual_counter_width_and_exact_rate() {
    assert_eq!(pm(false).elapsed_ns(0,3_579_545), Some(1_000_000_000));
    assert_eq!(pm(false).elapsed_ns(0xfffffe,1), Some(838));
    assert_eq!(pm(true).elapsed_ns(0xffff_fffe,1), Some(838));
    assert_eq!(pm(true).elapsed_ns(0xfffffe,0x1000001), Some(838));
    assert_eq!(pm(true).elapsed_ns(0,7_159_090), Some(2_000_000_000));
    assert_eq!(pm(false).elapsed_ns(100,99), None);
    assert_eq!(hpet().elapsed_ns(100,99), None);
    assert_eq!(hpet().elapsed_ns(1,10_001), Some(1_000_000));
}

#[test]
fn fallback_uses_only_a_progressing_discovered_clock() {
    let timer = PmTimer { access: PmAccess::Io(0x408), wide: false };
    let hp = Some((0xfed0_0000, 100_000_000));
    let mut visited = Vec::new();
    assert_eq!(ReferenceClock::choose(Some(timer),hp,|c| {visited.push(c); c==hpet()}),Some(hpet()));
    assert_eq!(visited, vec![pm(false),hpet()]);
    assert_eq!(ReferenceClock::choose(Some(timer),hp,|_| true),Some(pm(false)));
    assert_eq!(ReferenceClock::choose(None,hp,|_| true),Some(hpet()));
    assert_eq!(ReferenceClock::choose(Some(timer),hp,|_| false),None);
    assert_eq!(ReferenceClock::choose(None,Some((0xfed0_0000,0)),|_| true),None);
    assert_eq!(ReferenceClock::choose(None,None,|_| true),None);
}

#[test]
fn polling_times_out_only_after_real_elapsed_ticks() {
    let mut value = 0xffff00u64;
    let mut samples = 0;
    let result = pm(false).poll(1_000_000,50,5,|| {
        let old = value;
        value = (value + 256) & 0xffffff;
        samples += 1;
        old
    },|| false);
    assert_eq!(result,Err(WaitError::Timeout));
    assert_eq!(samples,15); // 14 * 256 ticks = 3584, just over 1 ms
}

#[test]
fn condition_completion_and_stalls_are_distinct() {
    let mut checks = 0;
    let mut value = 0;
    assert_eq!(hpet().poll(100_000,50,5,|| {value+=1;value},|| {
        checks+=1;
        checks==5
    }), Ok(()));
    assert_eq!(hpet().poll(100_000,50,5,|| 7,|| false), Err(WaitError::Unresponsive));
    let mut value = 0;
    assert_eq!(hpet().poll(1_000_000,3,5,|| {value+=1;value},|| false),
               Err(WaitError::Unresponsive));
    let mut value = 100;
    assert_eq!(hpet().poll(1_000_000,50,5,|| {value-=1;value},|| false),
               Err(WaitError::Unresponsive));
    assert_eq!(hpet().poll(1,0,0,|| panic!("no read needed"),|| true),Ok(()));
}

#[test]
fn no_fractional_ticks_are_lost_at_wrap_or_repeated_samples() {
    let values = [0xfffffd,0xfffffe,0xfffffe,0xffffff,0,1,2];
    let mut it = values.into_iter();
    assert_eq!(pm(false).poll(1_000,10,3,|| it.next().unwrap(),|| false),
               Err(WaitError::Timeout));
}
