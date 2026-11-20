//! Host tests of the real TTY and line discipline with a controlled UART boundary.
//! These exercise Rust state transitions, not an IOAPIC, UART, or VM implementation.
#![allow(non_snake_case)]

use std::{cell::RefCell, collections::VecDeque};

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
    pub unsafe fn enable() -> Option<Saved> { None } // absent hardware in UART tests
    pub unsafe fn restore(_: Saved) -> bool { true }
    pub unsafe fn drain(mut feed: impl FnMut(Result<u8, ()>)) {
        SCANS.with(|s| {
            for code in s.borrow_mut().drain(..) { feed(code); }
        });
    }
}

const COM: u16 = 0x3f8;

mod acpi { pub struct Platform; }

mod ioapic {
    pub struct Route;
    impl Route {
        pub unsafe fn serial(_: &crate::acpi::Platform, _: u8, _: u32) -> Result<Self, &'static [u8]> {
            Ok(Self)
        }
        pub unsafe fn keyboard(_: &crate::acpi::Platform, _: u8, _: u32) -> Result<Self, &'static [u8]> {
            Ok(Self) // route exists but 8042 enable() reports no hardware
        }
        pub unsafe fn enable(&self) { super::ports(|p| p.fRouteEnabled = true); }
        pub unsafe fn disable(&self) { super::ports(|p| p.fRouteEnabled = false); }
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
    fReadCount: usize,
    fFloodByte: Option<u8>,
    fTransmitRemaining: Option<usize>,
}

thread_local! { static PORTS: RefCell<Ports> = RefCell::new(Ports::default()); }

fn ports<R>(aOperation: impl FnOnce(&mut Ports) -> R) -> R {
    PORTS.with(|pPorts| aOperation(&mut pPorts.borrow_mut()))
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
    let mut pTerminal = unsafe { tty::Terminal::new(&acpi::Platform, 0).unwrap() };
    unsafe { pTerminal.enable(); }
    pTerminal
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
    let screen=unsafe{fb_console::Console::new(pixels.as_mut_ptr(),width,height,width,0)}.unwrap();
    let before=pixels.clone();
    let mut term=terminal();
    term.attach_screen(screen);
    assert_eq!(unsafe{term.write(b"shell> ")},Ok(7));
    assert_ne!(pixels,before,"shell prompt never reached framebuffer");
    receive(&mut term,b"x");
    ps2::inject(&[Ok(0x2e),Ok(0x1c)]); // 'c', Enter
    unsafe{term.keyboard_interrupt();}
    assert_eq!(read(&mut term,64),Ok((Some(3),b"xc\n".to_vec())));
    assert!(pixels.iter().any(|&v|v==0xffffff),"no rendered glyph pixels");
    ports(|p|assert!(p.fTransmit.ends_with(b"xc\n")));
}

#[test]
fn framebufferShellStaysUsableWhenUartTransmitStalls() {
    let width=60usize;let height=27usize;
    let mut pixels=vec![0u32;width*height];
    let screen=unsafe{fb_console::Console::new(pixels.as_mut_ptr(),width,height,width,0)}.unwrap();
    let initial=pixels.clone();
    let mut term=terminal();
    term.attach_screen(screen);
    ports(|p|p.fTransmitRemaining=Some(0));
    assert_eq!(unsafe{term.write(b"hello\n")},Ok(6));
    assert_ne!(pixels,initial,"serial failure must not suppress screen output");
    ports(|p|assert!(p.fTransmit.is_empty()));
    receive(&mut term,b"ok\r");
    assert_eq!(read(&mut term,16),Ok((Some(3),b"ok\n".to_vec())));
}
