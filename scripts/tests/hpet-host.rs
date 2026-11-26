//! Hardware register fixture exercises the actual HPET owner. Only
//! progress validation is injected: host memory does not free-run.
#![allow(dead_code)]
#[path = "../../kernel/reference_clock.rs"]
mod reference_clock;
#[path = "../../kernel/hpet.rs"]
mod hpet;
use hpet::Hpet;
use reference_clock::ReferenceClock;
#[repr(align(4096))]
struct Registers([u64;512]);
const COUNTER64:u64=1<<13;
const INTERRUPTS:u64=(1<<2)|(1<<14);
fn registers(caps:u64)->Box<Registers>{
    let mut r=Box::new(Registers([0;512]));
    r.0[0]=caps;
    r.0[0x10/8]=3;
    r.0[0xf0/8]=99;
    for i in 0..3 {r.0[(0x100+i*0x20)/8]=INTERRUPTS|(1<<5);}
    r
}
#[test]
fn starts_and_publishes_both_counter_widths() {
    for wide in [false,true] {
        let clock=Hpet::new();
        let mut r=registers((100_000_000<<32)|(2<<8)|1|if wide{COUNTER64}else{0});
        let base=r.0.as_mut_ptr() as usize;
        // Host pointers may exceed the kernel identity slot. The register
        // owner accepts canonical addresses; ACPI enforces its mapping limit.
        let result=unsafe{clock.initialize(base,|s|{
            assert_eq!(s,ReferenceClock::Hpet{base,period_fs:100_000_000,wide});
            true
        })};
        assert_eq!(result,Ok(()));
        assert_eq!(clock.reference(),Some(ReferenceClock::Hpet{base,period_fs:100_000_000,wide}));
        assert_eq!(r.0[0x10/8],1);
        assert_eq!(r.0[0xf0/8],0);
        for i in 0..3 {assert_eq!(r.0[(0x100+i*0x20)/8],1<<5);}
        assert!(unsafe{clock.initialize(base,|_|true)}.is_err());
    }
}
#[test]
fn bad_caps_or_stopped_device_are_never_published() {
    let clock=Hpet::new();
    for caps in [0,u64::MAX,(100_000_001<<32)|1,1,100_000_000<<32] {
        let mut r=registers(caps);
        let base=r.0.as_mut_ptr() as usize;
        assert!(unsafe{clock.initialize(base,|_|panic!("bad caps"))}.is_err());
        assert_eq!(r.0[0x10/8],3);
        assert_eq!(r.0[0xf0/8],99);
        assert_eq!(clock.reference(),None);
    }
    let mut r=registers((100_000_000<<32)|1);
    let base=r.0.as_mut_ptr() as usize;
    assert!(unsafe{clock.initialize(base,|_|false)}.is_err());
    assert_eq!(r.0[0x10/8]&3,0);
    assert_eq!(clock.reference(),None);
    assert_eq!(clock.candidate(),Some(ReferenceClock::Hpet{base,period_fs:100_000_000,wide:false}));
    for bad in [0,1,1usize<<47] {assert!(unsafe{clock.initialize(bad,|_|true)}.is_err());}
}


#[test]
fn stopped_boot_candidate_can_be_reprogrammed_without_claiming_progress() {
    for wide in [false,true] {
        let clock=Hpet::new();
        let mut r=registers((100_000_000<<32)|(2<<8)|1|if wide{COUNTER64}else{0});
        let base=r.0.as_mut_ptr() as usize;
        let source=ReferenceClock::Hpet{base,period_fs:100_000_000,wide};
        assert!(unsafe{clock.initialize(base,|_|false)}.is_err());
        assert_eq!(clock.reference(),None);
        assert_eq!(clock.candidate(),Some(source));
        assert_eq!(r.0[0x10/8]&3,0);
        // Model reset firmware configuration, not progression of time.
        r.0[0x10/8]=3|(1<<9);
        r.0[0xf0/8]=0x1234;
        for i in 0..3 {r.0[(0x100+i*0x20)/8]=INTERRUPTS|(1<<5);}
        assert_eq!(unsafe{clock.restart_quarantined(source)},Ok(()));
        assert_eq!(r.0[0x10/8],1|(1<<9));
        assert_eq!(r.0[0xf0/8],0);
        for i in 0..3 {assert_eq!(r.0[(0x100+i*0x20)/8],1<<5);}
        assert_eq!(clock.candidate(),Some(source));
        // Register programming cannot certify that this memory fixture
        // or a physical counter progresses at the expected rate.
        assert_eq!(clock.reference(),None);
    }
}

#[test]
fn restart_refuses_wrong_identity_or_changed_capabilities_before_register_writes() {
    let clock=Hpet::new();
    let mut r=registers((100_000_000<<32)|(2<<8)|1|COUNTER64);
    let base=r.0.as_mut_ptr() as usize;
    assert_eq!(unsafe{clock.initialize(base,|_|true)},Ok(()));
    let source=clock.reference().unwrap();
    r.0[0xf0/8]=987;
    let wrong=ReferenceClock::Hpet{base,period_fs:100_000_000,wide:false};
    assert!(unsafe{clock.restart_quarantined(wrong)}.is_err());
    assert_eq!(r.0[0xf0/8],987);
    assert_eq!(r.0[0x10/8],1);
    assert_eq!(clock.reference(),Some(source));

    r.0[0] ^= COUNTER64;
    assert!(unsafe{clock.restart_quarantined(source)}.is_err());
    assert_eq!(r.0[0xf0/8],987);
    assert_eq!(r.0[0x10/8],1);
    assert_eq!(clock.reference(),None);
    assert!(unsafe{Hpet::new().restart_quarantined(source)}.is_err());
}

#[test]
fn maximum_comparator_count_and_narrow_counter_writes_are_bounded() {
    let clock=Hpet::new();
    let mut r=registers((100_000_000<<32)|(31<<8)|1);
    let base=r.0.as_mut_ptr() as usize;
    for i in 0..32 {r.0[(0x100+i*0x20)/8]=INTERRUPTS|(1<<5);}
    r.0[0xf0/8]=0x1234_5678_ffff_ffff;
    r.0[(0x100+32*0x20)/8]=0xfeed;
    assert!(unsafe{clock.initialize(base,|_|false)}.is_err());
    assert_eq!(r.0[0xf0/8],0x1234_5678_0000_0000);
    assert_eq!(unsafe{clock.restart_quarantined(clock.candidate().unwrap())},Ok(()));
    for i in 0..32 {assert_eq!(r.0[(0x100+i*0x20)/8],1<<5);}
    assert_eq!(r.0[(0x100+32*0x20)/8],0xfeed);
}
