//! Execute the real 8042 driver against a deterministic first-port controller.
//! This checks the I/O commands and rollback, not real IRQ delivery.
#![allow(dead_code)]
use std::{cell::RefCell, collections::VecDeque};
#[derive(Default)]
struct Device {
    config: u8, disabled: bool, command_byte_pending: bool,
    response: VecDeque<u8>, writes: Vec<(u16,u8)>,
    fail_config_reply: bool, nack_device: bool, block_commands: bool,
    irq_while_device_command: bool,
}
thread_local! { static DEVICE: RefCell<Device> = RefCell::new(Device::default()); }
fn device<T>(f: impl FnOnce(&mut Device)->T)->T {
    DEVICE.with(|d| f(&mut d.borrow_mut()))
}
unsafe fn input(port: u16)->u8 {
    device(|d| match port {
        0x64 => u8::from(!d.response.is_empty()) | if d.block_commands { 2 } else { 0 },
        0x60 => d.response.pop_front().unwrap_or(0),
        _ => panic!("invalid port"),
    })
}
unsafe fn out(port:u16,value:u8) {
    device(|d| {
        d.writes.push((port,value));
        match (port,value) {
            (0x64,0xad) => { d.disabled=true; d.config |= 0x10; },
            (0x64,0xae) => { d.disabled=false; d.config &= !0x10; },
            (0x64,0x20) => {
                if !d.fail_config_reply { d.response.push_back(d.config); }
            }
            (0x64,0x60) => d.command_byte_pending=true,
            (0x60,v) if d.command_byte_pending => {
                d.config=v;
                d.command_byte_pending=false;
            }
            (0x60,0xf0 | 0x02 | 0xf4) => {
                if d.config & 1 != 0 { d.irq_while_device_command = true; }
                d.response.push_back(if d.nack_device { 0xfe } else { 0xfa });
            }
            _ => (),
        }
    });
}
#[path="../../kernel/ps2.rs"]
mod ps2;
#[test]
fn normalEnableAndRestore() {
    device(|d| *d=Device{config:0x10,disabled:true,..Device::default()});
    let old=unsafe{ps2::enable()}.expect("enable");
    assert_eq!(old,0x10);
    device(|d| {assert_eq!(d.config & 0x41,0x41);assert!(!d.disabled);assert!(!d.irq_while_device_command);});
    assert!(unsafe{ps2::restore(old)});
    device(|d| {assert_eq!(d.config,0x10);assert!(d.disabled);});
}
#[test]
fn missingConfigReplyRestoresClock() {
    device(|d| *d=Device{fail_config_reply:true,..Device::default()});
    assert_eq!(unsafe{ps2::enable()},None);
    device(|d| {assert!(!d.disabled);assert!(!d.writes.contains(&(0x64,0xad)));});
}
#[test]
fn deviceNackRestoresConfig() {
    device(|d| *d=Device{config:0x10,disabled:true,nack_device:true,..Device::default()});
    assert_eq!(unsafe{ps2::enable()},None);
    device(|d| {assert_eq!(d.config,0x10);assert!(d.disabled);});
}

#[test]
fn disabledPortUnchangedWhenConfigReadFails() {
    device(|d| *d=Device{config:0x10,disabled:true,fail_config_reply:true,..Device::default()});
    assert_eq!(unsafe{ps2::enable()},None);
    device(|d| {assert!(d.disabled);assert_eq!(d.config,0x10);assert!(!d.writes.contains(&(0x64,0xad)));});
}
#[test]
fn originallyEnabledPortRestoredAfterNack() {
    device(|d| *d=Device{config:0x00,disabled:false,nack_device:true,..Device::default()});
    assert_eq!(unsafe{ps2::enable()},None);
    device(|d| {assert!(!d.disabled);assert_eq!(d.config,0);});
}

#[test]
fn controllerBusyDoesNotMutateState() {
    device(|d| *d=Device{config:0x10,disabled:true,block_commands:true,..Device::default()});
    assert_eq!(unsafe{ps2::enable()},None);
    device(|d| {assert!(d.disabled);assert_eq!(d.config,0x10);assert!(d.writes.is_empty());});
}
#[test]
fn restoreReportsControllerTimeout() {
    device(|d| *d=Device{config:0x41,disabled:false,block_commands:true,..Device::default()});
    assert!(!unsafe{ps2::restore(0x10)});
    device(|d| assert!(d.writes.is_empty()));
}

#[test]
fn deviceCommandsRunWithIrqMaskedEvenIfOriginallyEnabled() {
    device(|d| *d=Device{config:0x01,disabled:false,..Device::default()});
    let saved=unsafe{ps2::enable()}.expect("enable");
    device(|d| {
        assert!(!d.irq_while_device_command);
        assert_eq!(d.config & 0x41,0x41);
    });
    assert!(unsafe{ps2::restore(saved)});
    device(|d| assert_eq!(d.config,0x01));
}
