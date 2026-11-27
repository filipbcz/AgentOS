//! Host tests of the real TTY and line discipline with a controlled UART boundary.
//! These exercise Rust state transitions, not an IOAPIC, UART, or VM implementation.
#![allow(non_snake_case, non_upper_case_globals)]

use std::{cell::RefCell, collections::VecDeque, sync::{Arc, Barrier, Mutex}, thread};

#[path = "../../kernel/line.rs"]
mod line;
#[path = "../../kernel/tty.rs"]
mod tty;
#[path = "../../kernel/keyboard.rs"]
mod keyboard;
#[path = "../../kernel/fb_console.rs"]
mod fb_console;
#[path = "../../kernel/log_policy.rs"]
mod log_policy;
#[path = "../../kernel/log_ring.rs"]
mod log_ring;
#[path = "../../kernel/logger.rs"]
mod logger;

mod ps2 {
    use std::{cell::RefCell, collections::VecDeque};
    thread_local! { static SCANS: RefCell<VecDeque<Result<u8, ()>>> = RefCell::new(VecDeque::new()); }
    pub fn inject(codes: &[Result<u8, ()>]) {
        SCANS.with(|s| s.borrow_mut().extend(codes.iter().copied()));
    }
    pub struct Saved { pub controller: u8, pub scan_set: u8 }
    pub unsafe fn enable() -> Option<Saved> {
        super::ports(|p| {
            p.fPs2Enables += 1;
            (!p.fKeyboardMissing).then_some(Saved { controller: 0, scan_set: 2 })
        })
    }
    pub unsafe fn restore(_: Saved) -> bool {
        super::ports(|p| p.fPs2Restores += 1);
        true
    }
    pub unsafe fn drain(mut feed: impl FnMut(Result<u8, ()>)) {
        super::ports(|p| p.fPs2Drains += 1);
        SCANS.with(|s| {
            for code in s.borrow_mut().drain(..) { feed(code); }
        });
    }
}

const COM: u16 = 0x3f8;

mod acpi { pub struct Platform { pub ps2_controller: bool } }

mod ioapic {
    pub struct Route(bool);
    impl Route {
        pub unsafe fn serial(_: &crate::acpi::Platform, _: u32, _: u32) -> Result<Self, &'static [u8]> {
            super::ports(|p| {
                p.fSerialRouteAttempts += 1;
                if p.fSerialRouteMissing { Err(b"missing GSI" as &[u8]) } else { Ok(Self(true)) }
            })
        }
        pub unsafe fn keyboard(_: &crate::acpi::Platform, _: u32, _: u32) -> Result<Self, &'static [u8]> {
            super::ports(|p| {
                p.fKeyboardRouteAttempts += 1;
                if p.fKeyboardRouteMissing { Err(b"missing GSI" as &[u8]) } else { Ok(Self(false)) }
            })
        }
        pub unsafe fn enable(&self) { super::ports(|p| {
            if self.0 { p.fRouteEnabled = true; } else { p.fKeyboardRouteEnabled = true; }
        }); }
        pub unsafe fn disable(&self) { super::ports(|p| {
            if self.0 { p.fRouteEnabled = false; } else { p.fKeyboardRouteEnabled = false; }
        }); }
    }
}

#[derive(Default)]
struct Ports {
    fReceive: VecDeque<u8>,
    fTransmit: Vec<u8>,
    fWrites: Vec<(u16, u8)>,
    fLineErrors: u8,
    fInterruptEnable: u8,
    fRouteEnabled: bool,
    fKeyboardRouteEnabled: bool,
    fSerialRouteMissing: bool,
    fKeyboardRouteMissing: bool,
    fKeyboardMissing: bool,
    fSerialRouteAttempts: usize,
    fKeyboardRouteAttempts: usize,
    fPs2Enables: usize,
    fPs2Restores: usize,
    fPs2Drains: usize,
    fReadCount: usize,
    fFloodByte: Option<u8>,
    fTransmitRemaining: Option<usize>,
}

thread_local! { static PORTS: RefCell<Ports> = RefCell::new(Ports::default()); }
thread_local! { static gSharedPorts: RefCell<Option<Arc<Mutex<Ports>>>> = RefCell::new(None); }

fn ports<R>(aOperation: impl FnOnce(&mut Ports) -> R) -> R {
    let pShared = gSharedPorts.with(|pPorts| pPorts.borrow().clone());
    if let Some(pPorts) = pShared {
        let pResult = aOperation(&mut pPorts.lock().unwrap());
        // Only an individual emulated port access is serialized here. Yield
        // between bytes so complete-message atomicity must come from TTY.
        thread::yield_now();
        pResult
    } else {
        PORTS.with(|pPorts| aOperation(&mut pPorts.borrow_mut()))
    }
}

unsafe fn input(aPort: u16) -> u8 {
    ports(|pPorts| match aPort - COM {
        0 => {
            pPorts.fReadCount += 1;
            pPorts.fReceive.pop_front().or(pPorts.fFloodByte).expect("empty RX read")
        }
        5 => {
            let pData = u8::from(!pPorts.fReceive.is_empty() || pPorts.fFloodByte.is_some());
            let pTransmit = if pPorts.fTransmitRemaining == Some(0) { 0 } else { 0x20 };
            // Real UART LSR reads acknowledge the receive error bits, including
            // when the caller only wanted to test transmitter readiness.
            let pErrors = std::mem::take(&mut pPorts.fLineErrors);
            pData | pTransmit | pErrors
        }
        6 => 0,
        _ => panic!("unexpected input port {aPort:x}"),
    })
}

unsafe fn out(aPort: u16, aValue: u8) {
    ports(|pPorts| {
        pPorts.fWrites.push((aPort, aValue));
        match aPort - COM {
            0 => {
                if let Some(pRemaining) = &mut pPorts.fTransmitRemaining {
                    assert!(*pRemaining > 0, "TX write while not ready");
                    *pRemaining -= 1;
                }
                pPorts.fTransmit.push(aValue);
            }
            1 => pPorts.fInterruptEnable = aValue,
            2 => {
                if aValue & 2 != 0 {
                    pPorts.fReceive.clear();
                    pPorts.fFloodByte = None;
                }
                assert_eq!(aValue & 4, 0, "TTY must not reset the transmit FIFO");
            }
            4 => (),
            _ => panic!("unexpected output port {aPort:x}"),
        }
    });
}

fn terminal() -> tty::Terminal {
    ports(|p| *p = Ports::default());
    let pTerminal = unsafe { tty::Terminal::new(&acpi::Platform { ps2_controller: true }, 0, true) };
    unsafe { pTerminal.enable(); }
    pTerminal
}

fn attach_screen(term:&tty::Terminal,pixels:&mut [u32],width:usize,height:usize)
    ->(Vec<u8>,fb_console::Renderer) {
    let geometry=unsafe{fb_console::Geometry::new(pixels.as_mut_ptr(),width,height,width,0)}.unwrap();
    let mut backing=vec![0xa5;geometry.storage_bytes().unwrap()];
    let (screen,mut renderer)=unsafe{fb_console::Console::new(geometry,backing.as_mut_ptr(),backing.len())}.unwrap();
    renderer.initialize();
    term.attach_screen(screen);
    assert!(term.snapshot_screen(&mut renderer));renderer.render();
    (backing,renderer)
}
fn flush_screen(term:&tty::Terminal,renderer:&mut fb_console::Renderer)->usize {
    if term.snapshot_screen(renderer) {renderer.render()} else {0}
}

fn receive(aTerminal: &mut tty::Terminal, aBytes: &[u8]) {
    ports(|p| p.fReceive.extend(aBytes.iter().copied()));
    unsafe { aTerminal.interrupt(); }
}

fn read(aTerminal: &mut tty::Terminal, aLimit: usize) -> Result<(Option<usize>, Vec<u8>), isize> {
    let mut pBytes = Vec::new();
    let pCount = aTerminal.read(aLimit, |pData| { pBytes.extend_from_slice(pData); Ok(()) })?;
    Ok((pCount, pBytes))
}

#[test]
fn waitsForACompleteLineAndRearmsReceiveInterrupts() {
    let mut pTerminal = terminal();
    assert_eq!(read(&mut pTerminal, 64), Ok((None, vec![])));
    receive(&mut pTerminal, b"echo hi");
    assert!(!pTerminal.ready());
    assert_eq!(read(&mut pTerminal, 64), Ok((None, vec![])));
    receive(&mut pTerminal, b"\r\n");
    assert!(pTerminal.ready());
    assert_eq!(read(&mut pTerminal, 64), Ok((Some(8), b"echo hi\n".to_vec())));
    assert!(!pTerminal.ready());
    ports(|p| {
        assert_eq!(p.fTransmit, b"echo hi\r\n");
        assert_eq!(p.fInterruptEnable, 5);
        assert!(p.fRouteEnabled);
        let pIer: Vec<_> = p.fWrites.iter().filter(|&&(pPort, _)| pPort == COM + 1)
            .map(|&(_, pValue)| pValue).collect();
        assert_eq!(pIer, [0, 5, 0, 5, 0, 5]);
    });
}

#[test]
fn failedCopyAndZeroReadPreserveTheRecord() {
    let mut pTerminal = terminal();
    receive(&mut pTerminal, b"abc\r");
    assert_eq!(pTerminal.read(0, |_| panic!("zero read copied data")), Ok(Some(0)));
    assert_eq!(pTerminal.read(2, |_| Err(-14)), Err(-14));
    assert!(pTerminal.ready());
    assert_eq!(read(&mut pTerminal, 2), Ok((Some(2), b"ab".to_vec())));
    assert_eq!(pTerminal.read(2, |_| Err(-14)), Err(-14));
    assert_eq!(read(&mut pTerminal, 2), Ok((Some(2), b"c\n".to_vec())));
    assert!(!pTerminal.ready());
}

#[test]
fn eofAndDisabledInputDoNotCopyData() {
    let mut pTerminal = terminal();
    receive(&mut pTerminal, &[4]);
    assert_eq!(pTerminal.read(0, |_| panic!("zero read copied data")), Ok(Some(0)));
    assert!(pTerminal.ready());
    assert_eq!(pTerminal.read(1, |_| panic!("EOF copied data")), Ok(Some(0)));
    assert!(!pTerminal.ready());
    unsafe { pTerminal.disable(); }
    assert_eq!(pTerminal.read(1, |_| panic!("disabled TTY copied data")), Err(-5));
    ports(|p| { assert_eq!(p.fInterruptEnable, 0); assert!(!p.fRouteEnabled); });
}

#[test]
fn receiveErrorsRejectTheDamagedLineAndAllowRecovery() {
    let mut pTerminal = terminal();
    ports(|p| p.fLineErrors = 0x04);
    receive(&mut pTerminal, b"bad\r\nvalid\r");
    assert_eq!(pTerminal.read(64, |_| panic!("damaged data escaped")), Err(-75));
    assert_eq!(read(&mut pTerminal, 64), Ok((Some(6), b"valid\n".to_vec())));
    assert!(!pTerminal.ready());
}

#[test]
fn transmitPollingCannotLoseReceiveErrors() {
    let mut pTerminal = terminal();
    receive(&mut pTerminal, b"unsafe prefix");
    ports(|p| p.fLineErrors = 0x02);
    assert_eq!(unsafe { pTerminal.write(b"output") }, Ok(6));
    ports(|p| assert_eq!(p.fLineErrors, 0, "LSR error should have been acknowledged"));
    assert!(pTerminal.ready());
    assert_eq!(pTerminal.read(64, |_| panic!("damaged data escaped")), Err(-75));
    receive(&mut pTerminal, b"unsafe suffix\r\nvalid\r");
    assert_eq!(read(&mut pTerminal, 64), Ok((Some(6), b"valid\n".to_vec())));
    assert!(!pTerminal.ready());
}

#[test]
fn receiveBudgetBoundsFloodAndDiscardsItsRemainder() {
    let mut pTerminal = terminal();
    // Repeated backspace on an empty edit never overflows the line discipline;
    // the driver budget itself must detect and recover from this endless FIFO.
    ports(|p| p.fFloodByte = Some(8));
    unsafe { pTerminal.interrupt(); }
    ports(|p| {
        assert_eq!(p.fReadCount, 256);
        assert_eq!(p.fFloodByte, None);
        assert_eq!(p.fInterruptEnable, 5);
        assert_eq!(p.fWrites.iter().filter(|&&(pPort, pValue)| pPort == COM + 2 && pValue == 3).count(), 2);
    });
    assert_eq!(pTerminal.read(64, |_| panic!("flood data escaped")), Err(-75));
    receive(&mut pTerminal, b"remainder\r\nvalid\r");
    assert_eq!(read(&mut pTerminal, 64), Ok((Some(6), b"valid\n".to_vec())));
    assert!(!pTerminal.ready());
}

#[test]
fn cookedOutputHandlesSplitCrlfAndPartialWrites() {
    let mut pTerminal = terminal();
    assert_eq!(unsafe { pTerminal.write(b"a\n") }, Ok(2));
    assert_eq!(unsafe { pTerminal.write(b"b\r") }, Ok(2));
    assert_eq!(unsafe { pTerminal.write(b"\nc") }, Ok(2));
    ports(|p| { assert_eq!(p.fTransmit, b"a\r\nb\r\nc"); p.fTransmitRemaining = Some(1); });
    // The inserted CR may reach the UART even though no source byte completed.
    assert_eq!(unsafe { pTerminal.write(b"\n") }, Err(-5));
    ports(|p| p.fTransmitRemaining = None);
    assert_eq!(unsafe { pTerminal.write(b"\n") }, Ok(1));
    ports(|p| assert_eq!(p.fTransmit, b"a\r\nb\r\nc\r\n"));
    ports(|p| p.fTransmitRemaining = Some(1));
    assert_eq!(unsafe { pTerminal.write(b"xy") }, Ok(1));
    ports(|p| p.fTransmitRemaining = None);
    assert_eq!(unsafe { pTerminal.write(b"y") }, Ok(1));
    ports(|p| assert!(p.fTransmit.ends_with(b"xy")));
}

#[test]
fn keyboardAndSerialShareCanonicalLine() {
    let mut terminal = terminal();
    ps2::inject(&[Ok(0x12), Ok(0x2e), Ok(0x23), Ok(0x18)]); // echo
    unsafe { terminal.keyboard_interrupt(); }
    receive(&mut terminal, b" test");
    ps2::inject(&[Ok(0x1c)]);
    unsafe { terminal.keyboard_interrupt(); }
    assert_eq!(read(&mut terminal, 64), Ok((Some(10), b"echo test\n".to_vec())));
}

#[test]
fn damagedKeyboardInputCannotExecuteTruncatedCommand() {
    let mut terminal = terminal();
    ps2::inject(&[Ok(0x12), Ok(0x2d), Ok(0x17), Ok(0x14), Err(()), Ok(0x1c)]);
    unsafe { terminal.keyboard_interrupt(); }
    assert_eq!(terminal.read(64, |_| panic!("damaged command executed")), Err(-75));
    ps2::inject(&[Ok(0x23), Ok(0x12), Ok(0x26), Ok(0x19), Ok(0x1c)]); // help
    unsafe { terminal.keyboard_interrupt(); }
    assert_eq!(read(&mut terminal, 64), Ok((Some(5), b"help\n".to_vec())));
}

#[test]
fn shellAndKeyboardOutputAreMirroredToFramebuffer() {
    let width=96usize;let height=27usize;
    let mut pixels=vec![0u32;width*height];
    let mut term=terminal();
    let (_backing,mut renderer)=attach_screen(&term,&mut pixels,width,height);
    let before=pixels.clone();
    assert_eq!(unsafe{term.write(b"shell> ")},Ok(7));
    assert_eq!(pixels,before,"producer drew under TTY gate");
    assert!(flush_screen(&term,&mut renderer)>0);
    assert_ne!(pixels,before,"shell prompt never reached framebuffer");
    receive(&mut term,b"x");
    ps2::inject(&[Ok(0x2e),Ok(0x1c)]); // 'c', Enter
    unsafe{term.keyboard_interrupt();}
    assert_eq!(read(&mut term,64),Ok((Some(3),b"xc\n".to_vec())));
    assert!(flush_screen(&term,&mut renderer)>0);
    assert!(pixels.iter().any(|&v|v==0xffffff),"no rendered glyph pixels");
    ports(|p|assert!(p.fTransmit.ends_with(b"xc\r\n")));
}

#[test]
fn framebufferShellStaysUsableWhenUartTransmitStalls() {
    let width=60usize;let height=27usize;
    let mut pixels=vec![0u32;width*height];
    let mut term=terminal();
    let (_backing,mut renderer)=attach_screen(&term,&mut pixels,width,height);
    let initial=pixels.clone();
    ports(|p|p.fTransmitRemaining=Some(0));
    assert_eq!(unsafe{term.write(b"hello\n")},Ok(6));
    assert_eq!(pixels,initial);
    assert!(flush_screen(&term,&mut renderer)>0);
    assert_ne!(pixels,initial,"serial failure must not suppress screen output");
    ports(|p|assert!(p.fTransmit.is_empty()));
    receive(&mut term,b"ok\r");
    assert_eq!(read(&mut term,16),Ok((Some(3),b"ok\n".to_vec())));
}

#[test]
fn concurrentDescriptorWritersKeepCompleteCookedMessagesTogether() {
    let pTerminal = terminal();
    let pPorts = Arc::new(Mutex::new(Ports::default()));
    let pStart = Barrier::new(2);
    let pWrite = |aByte: u8| {
        gSharedPorts.with(|pShared| *pShared.borrow_mut() = Some(Arc::clone(&pPorts)));
        let mut pMessage = [aByte; 13];
        pMessage[12] = b'\n';
        pStart.wait();
        for _ in 0..64 {
            assert_eq!(unsafe { pTerminal.write(&pMessage) }, Ok(pMessage.len()));
        }
        gSharedPorts.with(|pShared| *pShared.borrow_mut() = None);
    };
    thread::scope(|pScope| {
        let pFirst = pScope.spawn(|| pWrite(b'A'));
        let pSecond = pScope.spawn(|| pWrite(b'B'));
        pFirst.join().unwrap();
        pSecond.join().unwrap();
    });
    let pPorts = pPorts.lock().unwrap();
    assert_eq!(pPorts.fTransmit.len(), 2 * 64 * 14);
    let mut pCounts = [0; 2];
    for pMessage in pPorts.fTransmit.chunks_exact(14) {
        assert_eq!(&pMessage[12..], b"\r\n");
        let pByte = pMessage[0];
        assert!(pByte == b'A' || pByte == b'B');
        assert!(pMessage[..12].iter().all(|&pOther| pOther == pByte), "TTY messages interleaved");
        pCounts[usize::from(pByte == b'B')] += 1;
    }
    assert_eq!(pCounts, [64, 64]);
}

#[test]
fn concurrentReadersConsumeEachCanonicalRecordExactlyOnce() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let mut pTerminal = terminal();
    receive(&mut pTerminal, b"first\nsecond\nthird\nfourth\n");
    let pStart = Barrier::new(2);
    let pCopyOwners = AtomicUsize::new(0);
    let pRead = || {
        let mut pRecords = Vec::new();
        pStart.wait();
        loop {
            let pCount = pTerminal.read(256, |pBytes| {
                assert_eq!(pCopyOwners.fetch_add(1, Ordering::SeqCst), 0,
                    "two CPUs copied the same line state concurrently");
                for _ in 0..32 { thread::yield_now(); }
                pRecords.push(pBytes.to_vec());
                assert_eq!(pCopyOwners.fetch_sub(1, Ordering::SeqCst), 1);
                Ok(())
            }).unwrap();
            if pCount.is_none() { break; }
            thread::yield_now();
        }
        pRecords
    };
    let (mut pFirst, pSecond) = thread::scope(|pScope| {
        let pFirstThread = pScope.spawn(&pRead);
        let pSecondThread = pScope.spawn(&pRead);
        (pFirstThread.join().unwrap(), pSecondThread.join().unwrap())
    });
    pFirst.extend(pSecond);
    pFirst.sort_unstable();
    assert_eq!(pFirst, [b"first\n".to_vec(), b"fourth\n".to_vec(), b"second\n".to_vec(), b"third\n".to_vec()]);
    assert!(!pTerminal.ready());
    assert_eq!(pCopyOwners.load(Ordering::SeqCst), 0);
}

#[test]
fn localKeyboardAndGopOperateWithoutAnyUart() {
    ports(|p| *p = Ports::default());
    let mut terminal = unsafe { tty::Terminal::new(&acpi::Platform { ps2_controller: true }, 0, false) };
    let mut pixels = vec![0u32; 96*27];
    let (_backing,mut renderer)=attach_screen(&terminal,&mut pixels,96,27);
    let before = pixels.clone();
    unsafe { terminal.enable(); terminal.enable(); }
    assert!(!terminal.ready());
    assert_eq!(unsafe { terminal.write(b"agentos> ") }, Ok(9));
    assert_eq!(pixels,before);
    assert!(flush_screen(&terminal,&mut renderer)>0);
    assert_ne!(pixels,before);
    ps2::inject(&[Ok(0x23), Ok(0x12), Ok(0x26), Ok(0x19), Ok(0x1c)]);
    unsafe { terminal.keyboard_interrupt(); terminal.interrupt(); }
    assert_eq!(read(&mut terminal,64),Ok((Some(5),b"help\n".to_vec())));
    unsafe { terminal.disable(); terminal.disable(); terminal.keyboard_interrupt(); terminal.interrupt(); }
    ports(|p| {
        assert_eq!(p.fSerialRouteAttempts,0);
        assert!(p.fWrites.is_empty() && p.fReadCount==0 && p.fTransmit.is_empty());
        assert_eq!((p.fPs2Enables,p.fPs2Restores,p.fPs2Drains),(1,1,1));
        assert!(!p.fKeyboardRouteEnabled);
    });
}

#[test]
fn uartOutputSurvivesMissingSerialIrqAndFirmwareDisallowsPs2() {
    ports(|p| *p = Ports { fSerialRouteMissing:true, ..Ports::default() });
    let mut terminal = unsafe { tty::Terminal::new(&acpi::Platform { ps2_controller:false },0,true) };
    unsafe { terminal.enable(); }
    assert!(terminal.ready()); // error ready, not a wait on absent IRQ sources
    assert_eq!(read(&mut terminal,64),Err(-19));
    assert_eq!(unsafe{terminal.write(b"diagnostic\n")},Ok(11));
    unsafe { terminal.keyboard_interrupt(); terminal.interrupt(); terminal.disable(); }
    ports(|p| {
        assert_eq!(p.fTransmit,b"diagnostic\r\n");
        assert_eq!(p.fKeyboardRouteAttempts,0);
        assert_eq!((p.fPs2Enables,p.fPs2Drains,p.fPs2Restores),(0,0,0));
        assert!(p.fWrites.iter().all(|&(port,value)|port!=COM+1||value==0));
    });
}

#[test]
fn missingKeyboardRouteOrControllerDoesNotTouchAnAbsentUart() {
    for route_missing in [false,true] {
        ports(|p| *p=Ports { fKeyboardRouteMissing:route_missing, fKeyboardMissing:true, ..Ports::default() });
        let mut terminal=unsafe{tty::Terminal::new(&acpi::Platform{ps2_controller:true},0,false)};
        unsafe{terminal.enable();terminal.keyboard_interrupt();terminal.interrupt();}
        assert!(terminal.ready());
        assert_eq!(read(&mut terminal,64),Err(-19));
        assert_eq!(unsafe{terminal.write(b"no sinks")},Err(-5));
        unsafe{terminal.disable();}
        ports(|p|{
            assert_eq!(p.fPs2Enables,usize::from(!route_missing));
            assert_eq!((p.fPs2Drains,p.fPs2Restores),(0,0));
            assert!(p.fWrites.is_empty());
        });
    }
}


#[test]
fn short_writes_and_irq_echo_coalesce_without_losing_pending_work() {
    let mut term=terminal();
    let mut pixels=vec![0u32;96*27];
    let (_backing,mut renderer)=attach_screen(&term,&mut pixels,96,27);
    let before=pixels.clone();
    for _ in 0..64 {assert_eq!(unsafe{term.write(b"x\n")},Ok(2));}
    receive(&mut term,b"echo");
    assert_eq!(pixels,before);
    assert!(term.snapshot_screen(&mut renderer));
    assert!(!term.screen_pending());
    assert_eq!(unsafe{term.write(b"later")},Ok(5));
    receive(&mut term,b" hi\r");
    assert!(term.screen_pending());
    assert!(renderer.render()>0);
    let first=pixels.clone();
    assert!(flush_screen(&term,&mut renderer)>0);
    assert_ne!(pixels,first);
    assert!(!term.screen_pending());
    assert_eq!(flush_screen(&term,&mut renderer),0);
    assert_eq!(read(&mut term,64),Ok((Some(8),b"echo hi\n".to_vec())));
}
