//! Exercise the real legacy UART code against absent, read-only and valid
//! register banks. Hardware I/O alone is replaced in this host test.
use std::cell::RefCell;
#[path="../../kernel/legacy_uart.rs"]
mod legacy_uart;
const BASE:u16=0x3f8;

struct Bus { regs:[u8;8], floating:bool, scratch_writable:bool, writes:Vec<(u16,u8)> }
thread_local! { static BUS:RefCell<Bus>=RefCell::new(Bus{
    regs:[0,0,1,0x80,0,0x60,0,0x37],floating:false,scratch_writable:true,writes:Vec::new()
}); }
unsafe fn input(port:u16)->u8 {
    BUS.with(|b|{let b=b.borrow();if b.floating {0xff}else{b.regs[(port-BASE) as usize]}})
}
unsafe fn out(port:u16,value:u8){
    BUS.with(|b|{
        let mut b=b.borrow_mut();b.writes.push((port,value));
        if b.floating || (port==BASE+7&&!b.scratch_writable){return;}
        b.regs[(port-BASE) as usize]=value;
    });
}

#[test]
fn absentBusNeverReceivesAWrite() {
    BUS.with(|b| b.borrow_mut().floating=true);
    unsafe {
        assert!(!legacy_uart::present(BASE));
        assert!(!legacy_uart::initialize(BASE));
        assert!(!legacy_uart::transmit(BASE,b'x'));
        assert!(!legacy_uart::present(0));
        assert!(!legacy_uart::present(u16::MAX));
    }
    BUS.with(|b|assert!(b.borrow().writes.is_empty()));
}

#[test]
fn nonWritableScratchCannotPassDiscovery() {
    BUS.with(|b| b.borrow_mut().scratch_writable=false);
    assert!(!unsafe{legacy_uart::initialize(BASE)});
    BUS.with(|b|{
        let b=b.borrow();
        assert_eq!(b.regs[7],0x37);
        assert!(b.writes.iter().all(|&(p,_)|p==BASE+7));
    });
}

#[test]
fn presentProbePreservesConfigurationAndInitDisablesIrqBeforeDivisor() {
    let before=BUS.with(|b|b.borrow().regs);
    assert!(unsafe{legacy_uart::present(BASE)});
    BUS.with(|b|{
        let mut b=b.borrow_mut();
        assert_eq!(b.regs,before);
        b.writes.clear();
    });
    assert!(unsafe{legacy_uart::initialize(BASE)});
    BUS.with(|b|{
        let b=b.borrow();
        assert_eq!(&b.writes[3..6],&[(BASE+3,3),(BASE+1,0),(BASE+3,0x83)]);
        assert_eq!(b.regs[7],0x37);
        assert_eq!(b.regs[3],3);
        assert_eq!(b.regs[1],0);
    });
    assert!(unsafe{legacy_uart::transmit(BASE,b'A')});
    BUS.with(|b|{let mut b=b.borrow_mut();b.regs[5]=0;b.writes.clear();});
    assert!(!unsafe{legacy_uart::transmit(BASE,b'B')});
    BUS.with(|b|assert!(b.borrow().writes.is_empty()));
}
