//! Deterministic simulation of 8042 controller and PS/2 keyboard.
//! Tests real kernel/ps2.rs; does not prove hardware/VM IRQ behavior.
#![allow(dead_code)]
use std::{cell::RefCell,collections::VecDeque};
struct Device {
    config:u8, scan_set:u8, enabled:bool, command_pending:bool,
    set_pending:bool, responses:VecDeque<u8>, fail_query:bool,
    busy:bool, nack:bool, resend_once:bool, resend_sent:bool,
    irq_during_command:bool, writes:Vec<(u16,u8)>,
}
impl Default for Device {
    fn default()->Self {Self {config:0,scan_set:2,enabled:true,
        command_pending:false,set_pending:false,responses:VecDeque::new(),
        fail_query:false,busy:false,nack:false,resend_once:false,
        resend_sent:false,irq_during_command:false,writes:Vec::new()}}
}
thread_local! {static DEVICE:RefCell<Device>=RefCell::new(Device::default());}
fn device<T>(f:impl FnOnce(&mut Device)->T)->T {DEVICE.with(|d|f(&mut d.borrow_mut()))}
unsafe fn input(port:u16)->u8 {
    device(|d|match port {
        0x64 => u8::from(!d.responses.is_empty()) | if d.busy {2} else {0},
        0x60 => d.responses.pop_front().unwrap_or(0),
        _ => panic!("invalid port")
    })
}
unsafe fn out(port:u16,value:u8) {
    device(|d| {
        d.writes.push((port,value));
        match (port,value) {
            (0x64,0xad)=>d.config|=0x10,
            (0x64,0xae)=>d.config&=!0x10,
            (0x64,0x20)=>{if !d.fail_query {d.responses.push_back(d.config);}},
            (0x64,0x60)=>d.command_pending=true,
            (0x60,v) if d.command_pending=>{d.config=v;d.command_pending=false;},
            (0x60,v)=>{
                if d.config&1!=0 {d.irq_during_command=true;}
                if d.nack {d.responses.push_back(0xfc);return;}
                if d.resend_once&&!d.resend_sent {
                    d.resend_sent=true;d.responses.push_back(0xfe);return;
                }
                d.responses.push_back(0xfa);
                if d.set_pending {
                    d.set_pending=false;
                    if v==0 {
                        d.responses.push_back(match d.scan_set {1=>0x43,2=>0x41,3=>0x3f,_=>0});
                    } else {d.scan_set=v;}
                } else if v==0xf0 {d.set_pending=true;}
                else if v==0xf4 {d.enabled=true;}
            }
            _=>()
        }
    });
}
#[path="../../kernel/ps2.rs"] mod ps2;
fn reset(config:u8,scan_set:u8) {
    device(|d|*d=Device{config,scan_set,..Device::default()});
}
#[test] fn preserveOriginallyDisabledPortAndScanSet() {
    reset(0x10,3);
    let saved=unsafe{ps2::enable()}.expect("enable");
    assert_eq!(saved.controller,0x10);
    assert_eq!(saved.scan_set,3);
    device(|d| {assert_eq!(d.scan_set,2);assert_eq!(d.config&0x41,0x41);assert!(!d.irq_during_command);});
    assert!(unsafe{ps2::restore(saved)});
    device(|d| {assert_eq!(d.scan_set,3);assert_eq!(d.config,0x10);});
}
#[test] fn restoreOriginallyEnabledPortAndIrq() {
    reset(0x01,1);
    let saved=unsafe{ps2::enable()}.expect("enable");
    assert!(unsafe{ps2::restore(saved)});
    device(|d| {assert_eq!(d.config,0x01);assert_eq!(d.scan_set,1);assert!(!d.irq_during_command);});
}
#[test] fn missingControllerReplyLeavesPortUntouched() {
    reset(0x10,2);
    device(|d|d.fail_query=true);
    assert!(unsafe{ps2::enable()}.is_none());
    device(|d|{assert_eq!(d.config,0x10);assert!(d.writes.iter().all(|&(p,v)|p!=0x64||v!=0xad));});
}
#[test] fn busyControllerDoesNotMutate() {
    reset(0x10,2);device(|d|d.busy=true);
    assert!(unsafe{ps2::enable()}.is_none());
    device(|d|assert!(d.writes.is_empty()));
}
#[test] fn nackRestoresController() {
    reset(0x10,3);device(|d|d.nack=true);
    assert!(unsafe{ps2::enable()}.is_none());
    device(|d|{assert_eq!(d.config,0x10);assert_eq!(d.scan_set,3);});
}
#[test] fn resendIsBoundedAndAccepted() {
    reset(0,3);device(|d|d.resend_once=true);
    let saved=unsafe{ps2::enable()}.expect("resend");
    assert_eq!(saved.scan_set,3);
    assert!(unsafe{ps2::restore(saved)});
}
#[test] fn restoreTimeoutReported() {
    reset(0,2);device(|d|d.busy=true);
    assert!(!unsafe{ps2::restore(ps2::Saved{controller:0,scan_set:2})});
}
