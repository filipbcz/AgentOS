//! The actual 8254 driver, with a separate model of port I/O and CPU
//! counter samples. Host tests never access real privileged I/O ports.
#![allow(dead_code)]
#[path = "../../kernel/reference_clock.rs"]
mod reference_clock;
#[path = "../../kernel/tsc.rs"]
mod tsc;
#[path = "../../kernel/pit.rs"]
mod pit;

use core::cell::Cell;
use pit::{Ports, Error};

#[derive(Clone, Copy, PartialEq, Eq)]
enum Fault { None, Stopped, InitialHigh, ImmediateHigh, WrongStatus, TerminalNull, GateStuck, CleanupStuck }

struct Model<'a> {
    ticks: &'a Cell<u64>,
    hz: u64,
    control: u8,
    programmed: bool,
    status_latched: bool,
    count: [u8; 2],
    count_bytes: usize,
    gate_start: Option<u64>,
    fault: Fault,
    writes: Vec<(u16,u8)>,
    reads: usize,
    started: bool,
}

impl<'a> Model<'a> {
    fn new(ticks: &'a Cell<u64>, hz: u64, fault: Fault) -> Self {
        Self { ticks, hz, control: 0x0f, programmed: false, status_latched: false,
            count: [0;2], count_bytes: 0, gate_start: None, fault,
            writes: Vec::new(), reads: 0, started: false }
    }

    fn out_high(&self) -> bool {
        if self.fault==Fault::InitialHigh { return true; }
        if !self.programmed { return true; }
        let Some(start)=self.gate_start else { return false; };
        if self.fault==Fault::Stopped { return false; }
        if self.fault==Fault::ImmediateHigh { return true; }
        let divisor=u16::from_le_bytes(self.count) as u128;
        (self.ticks.get().saturating_sub(start) as u128)*1_193_182 >= divisor*self.hz as u128
    }

    fn io_delay(&self) { self.ticks.set(self.ticks.get()+self.hz/10_000_000); }
}

impl Ports for Model<'_> {
    fn read(&mut self, port:u16)->u8 {
        self.reads+=1;
        self.io_delay();
        match port {
            0x61 => self.control | 0xd0 | if self.out_high(){0x20}else{0},
            0x42 => {
                assert!(self.status_latched);
                self.status_latched=false;
                if self.fault==Fault::WrongStatus { return 0xff; }
                let high=self.out_high();
                0x30 | if high{0x80}else{0} |
                    if !high || self.fault==Fault::TerminalNull {0x40}else{0}
            }
            _=>panic!("unexpected read {port:#x}"),
        }
    }

    fn write(&mut self, port:u16, value:u8) {
        self.io_delay();
        self.writes.push((port,value));
        match port {
            0x61 => {
                assert_eq!(value&!0x0f,0,"read-only status echoed into control port");
                if self.fault==Fault::GateStuck {return;}
                if self.fault==Fault::CleanupStuck && self.started && value&1==0 {return;}
                self.control=value;
                if value&1!=0 {
                    self.gate_start=Some(self.ticks.get());
                    self.started=true;
                }
            }
            0x43 if value==0xb0 => {
                assert_eq!(self.control&3,0);
                self.programmed=true;
                self.count_bytes=0;
                self.gate_start=None;
            }
            0x43 if value==0xe8 => {
                assert!(self.programmed);
                assert_eq!(self.count_bytes,2);
                self.status_latched=true;
            }
            0x42 => {
                assert!(self.programmed);
                assert!(self.count_bytes<2);
                self.count[self.count_bytes]=value;
                self.count_bytes+=1;
            }
            _=>panic!("unexpected write {port:#x} {value:#x}"),
        }
    }
}

fn sample(model: &mut Model<'_>, max_polls:u32, step_ns:u64)
    -> Result<tsc::Observation,Error> {
    let ticks=model.ticks;
    let step=(model.hz as u128*step_ns as u128/1_000_000_000) as u64;
    pit::measure(true,model,max_polls,||ticks.get(),||ticks.set(ticks.get()+step))
}

#[test]
fn real_driver_never_touches_ports_on_undeclared_platform() {
    let ticks=Cell::new(0);
    let mut model=Model::new(&ticks,3_000_000_000,Fault::None);
    assert_eq!(pit::measure(false,&mut model,1,
        ||panic!("timestamp"),||panic!("maintenance")),Err(Error::NotDeclared));
    assert!(model.writes.is_empty());
    assert_eq!(model.reads,0);
}

#[test]
fn complete_finite_one_shots_measure_independent_tsc_rates() {
    for hz in [1_000_000_000,3_000_000_000,4_800_000_000] {
        let ticks=Cell::new(1_000_000);
        let mut model=Model::new(&ticks,hz,Fault::None);
        let mut rates=[0;3];
        for rate in &mut rates {
            let observation=sample(&mut model,30_000,4_000).unwrap();
            assert_eq!(observation.reference_ns,59_660u64*1_000_000_000/1_193_182);
            *rate=tsc::measured_rate(observation).unwrap();
            assert!(rate.abs_diff(hz) < hz/1000);
            assert_eq!(model.control,0x0c);
            assert_eq!(model.count,59_660u16.to_le_bytes());
        }
        let caps=tsc::Capabilities{available:true,invariant:true,nominal_hz:Some(hz)};
        assert_eq!(tsc::qualified_rate(caps,rates),Some(hz));
        let bad=tsc::Capabilities{nominal_hz:Some(hz*2),..caps};
        assert_eq!(tsc::qualified_rate(bad,rates),None);
        // Each finite measurement uses exactly the documented channel-2
        // control and data operations, and does not touch IRQ0/channel 1.
        let expected=[
            (0x61,0x0c),(0x43,0xb0),(0x42,59_660u16 as u8),
            (0x42,(59_660u16>>8) as u8),(0x43,0xe8),
            (0x61,0x0d),(0x43,0xe8),(0x61,0x0c)
        ];
        assert_eq!(model.writes,expected.repeat(3));
    }
}

#[test]
fn absent_frozen_or_immediate_terminal_count_cannot_qualify() {
    for (fault,error) in [
        (Fault::Stopped,Error::NoEdge),
        (Fault::InitialHigh,Error::Configuration),
        (Fault::ImmediateHigh,Error::NoEdge),
        (Fault::WrongStatus,Error::Configuration),
        (Fault::TerminalNull,Error::Configuration),
    ] {
        let ticks=Cell::new(0);
        let mut model=Model::new(&ticks,3_000_000_000,fault);
        assert_eq!(sample(&mut model,30_000,4_000),Err(error));
        assert_eq!(model.control&3,0);
        assert_eq!(model.writes.last(),Some(&(0x61,0x0c)));
        assert!(model.reads<=30_010);
    }
}

#[test]
fn malformed_gate_and_failed_cleanup_are_errors_not_calibration() {
    for fault in [Fault::GateStuck,Fault::CleanupStuck] {
        let ticks=Cell::new(0);
        let mut model=Model::new(&ticks,3_000_000_000,fault);
        assert_eq!(sample(&mut model,30_000,4_000),Err(Error::Configuration));
        assert_eq!(model.writes.last(),Some(&(0x61,0x0c)));
    }
}

#[test]
fn regressions_and_unbounded_terminal_edge_brackets_are_rejected() {
    let ticks=Cell::new(1_000_000);
    let mut model=Model::new(&ticks,3_000_000_000,Fault::None);
    let mut calls=0;
    assert_eq!(pit::measure(true,&mut model,100,
        ||{calls+=1; if calls==3 {0} else {ticks.get()}},
        ||ticks.set(ticks.get()+3000)),Err(Error::Regression));
    assert_eq!(model.control&3,0);

    let ticks=Cell::new(0);
    let mut model=Model::new(&ticks,3_000_000_000,Fault::None);
    assert_eq!(sample(&mut model,100,10_000_000),Err(Error::Uncertain));
    assert_eq!(model.control&3,0);
}

#[test]
fn poll_limit_never_becomes_synthetic_elapsed_time() {
    let ticks=Cell::new(0);
    let mut model=Model::new(&ticks,3_000_000_000,Fault::None);
    for max in [0,1,10] {
        assert_eq!(sample(&mut model,max,4_000),Err(Error::NoEdge));
        assert_eq!(model.control&3,0);
    }
}


#[test]
fn independent_pit_observations_create_rate_proof_and_leave_channel_silent() {
    let hz=3_000_000_000;
    let caps=tsc::Capabilities{available:true,invariant:true,nominal_hz:Some(hz)};
    let ticks=Cell::new(1_000_000);
    let mut model=Model::new(&ticks,hz,Fault::None);
    let mut calibration=tsc::Calibration::new(caps);
    for _ in 0..3 {
        calibration.observe(sample(&mut model,30_000,4_000).unwrap()).unwrap();
        assert_eq!(model.control&3,0);
    }
    assert_eq!(calibration.finish().unwrap().hz(),hz);
    // A subsequent failed physical observation cannot yield a new token.
    let mut rejected=tsc::Calibration::new(caps);
    rejected.observe(sample(&mut model,30_000,4_000).unwrap()).unwrap();
    model.fault=Fault::Stopped;
    assert_eq!(sample(&mut model,30_000,4_000),Err(Error::NoEdge));
    assert!(rejected.finish().is_none());
    assert_eq!(model.control&3,0);
}

#[test]
fn missed_terminal_interval_cannot_become_a_calibration() {
    let ticks=Cell::new(1_000_000);
    let mut model=Model::new(&ticks,3_000_000_000,Fault::None);
    // Miss more than two finite counter periods before the first poll.
    assert_eq!(sample(&mut model,10,200_000_000),Err(Error::NoEdge));
    assert_eq!(model.control&3,0);
}

#[test]
fn rejected_physical_measurements_preserve_the_actual_operation_and_operands() {
    use pit::Stage::*;
    let hz=3_000_000_000;
    for (fault,stage) in [(Fault::Stopped,PollLimit),(Fault::InitialHigh,ProgramStatus),
        (Fault::ImmediateHigh,FirstHigh),(Fault::WrongStatus,ProgramStatus),
        (Fault::TerminalNull,TerminalStatus),(Fault::GateStuck,DisableGate),
        (Fault::CleanupStuck,CleanupGate)] {
        let ticks=Cell::new(1_000_000);
        let mut model=Model::new(&ticks,hz,fault);
        let result=pit::measure_detailed(true,&mut model,30_000,||ticks.get(),
            ||ticks.set(ticks.get()+12_000)).unwrap_err();
        assert_eq!(result.stage,stage);
        assert_eq!(result.cleanup_state.is_some(),fault==Fault::CleanupStuck || fault==Fault::GateStuck);
    }
    let ticks=Cell::new(1_000_000);
    let mut model=Model::new(&ticks,hz,Fault::None);
    let caps=tsc::Capabilities{available:true,invariant:true,nominal_hz:Some(hz)};
    let rejection=pit::qualify_samples(caps,&mut model,100,||ticks.get(),
        ||ticks.set(ticks.get()+30_000_000)).unwrap_err();
    assert_eq!(rejection.reason,pit::QualificationReason::Measure(EdgeUncertain));
    assert_eq!(rejection.window,1);
    assert_eq!(rejection.rates,[0;3]);
    let [a,b,c,d]=rejection.values;
    let lo=c-b; let hi=d-a;
    assert!((hi-lo) as u128*1_000_000>((hi+lo)/2) as u128*960);
    assert_eq!(model.control&3,0);
    assert_eq!(model.writes.iter().filter(|&&(port,value)|port==0x43&&value==0xb0).count(),1);
    let mut messages=Vec::new();
    rejection.report(254,"bsp-confirm",|line|messages.push(line.to_vec()));
    assert_eq!(messages.len(),4);
    assert!(messages[0].ends_with(b"FAULT=Measure(EdgeUncertain)"));
    assert!(messages[1].ends_with(format!("D={d:016x}").as_bytes()));
    assert!(messages.iter().all(|line|line.len()<=96));
}

#[test]
fn rejected_calibration_preserves_prior_rates_and_disagrees_with_nominal() {
    let ticks=Cell::new(1_000_000);
    let hz=3_000_000_000;
    let mut model=Model::new(&ticks,hz,Fault::None);
    let caps=tsc::Capabilities{available:true,invariant:true,nominal_hz:Some(hz*2)};
    let fault=pit::qualify_samples(caps,&mut model,30_000,||ticks.get(),
        ||ticks.set(ticks.get()+12_000)).unwrap_err();
    assert_eq!(fault.reason,pit::QualificationReason::Calibration(tsc::CalibrationFault::NominalMismatch));
    assert_eq!(fault.window,0);
    assert!(fault.rates.iter().all(|rate|rate.abs_diff(hz)<hz/1000));
    assert_eq!(fault.nominal,Some(hz*2));
    assert_eq!(model.control&3,0);
}
