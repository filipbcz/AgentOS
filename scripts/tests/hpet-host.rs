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
    for bad in [0,1,1usize<<47] {assert!(unsafe{clock.initialize(bad,|_|true)}.is_err());}
}
