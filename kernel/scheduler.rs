//! Per-CPU round robin for kernel threads. Queue access on its owner CPU
//! requires IF=0. A timer interrupt owns the outgoing frame until IRETQ.
use crate::frames::{Frame, Frames};
use crate::process::{Process, Programs, STACK};
use core::{mem::size_of, ptr};

extern "C" { fn task_return(); }

// Matches timer_gate in traps.S; hardware pushes SS, RSP, RFLAGS, CS and RIP.
#[repr(C, align(16))]
pub struct Context {
    fx: [u8; 512],
    pub registers: [usize; 15],
    pub rip: usize,
    cs: usize,
    flags: usize,
    pub rsp: usize,
    ss: usize,
}
const _: () = assert!(size_of::<Context>() == 512 + 20 * 8);
impl Context { pub fn user(&self) -> bool { self.cs & 3 == 3 } }

struct Task {
    stack: Frame,
    context: usize,
    runnable: bool,
    waiting: Option<crate::files::Wait>,
    preemptions: usize,
    process: Option<Process>,
}

const CAPACITY: usize = 8;
pub struct Queue {
    tasks: [Option<Task>; CAPACITY],
    count: usize,
    current: Option<usize>,
    caller: usize,
    pub active: bool,
}

impl Queue {
    pub fn new() -> Self {
        Self { tasks: core::array::from_fn(|_| None), count: 0, current: None, caller: 0, active: false }
    }

    pub fn spawn(&mut self, frames: &mut Frames<'_>, entry: extern "C" fn(usize), arg: usize) -> Option<()> {
        if self.active || self.count == CAPACITY { return None; }
        let stack = frames.alloc_zeroed()?;
        let top = stack.address() + 4096;
        let context = (top - 16 - size_of::<Context>()) as *mut Context;
        unsafe {
            // Fresh x87/SSE state and SysV function-entry stack alignment.
            ptr::write_unaligned((*context).fx.as_mut_ptr() as *mut u16, 0x037f);
            ptr::write_unaligned((*context).fx.as_mut_ptr().add(24) as *mut u32, 0x1f80);
            (*context).registers[10] = arg; // RDI
            (*context).rip = entry as usize;
            (*context).cs = 8;
            (*context).flags = 0x202;
            (*context).rsp = top - 8;
            (*context).ss = 16;
            ((top - 8) as *mut usize).write(task_return as usize);
        }
        self.tasks[self.count] = Some(Task { stack, context: context as usize, runnable: true, waiting: None, preemptions: 0, process: None });
        self.count += 1;
        Some(())
    }

    pub unsafe fn spawn_process(&mut self, frames: &mut Frames<'_>, programs: &Programs, name: &[u8],
                                parent: usize) -> Result<usize, isize> {
        let slot = self.tasks.iter().position(Option::is_none).ok_or(-11isize)?;
        let stack = frames.alloc_zeroed().ok_or(-12isize)?;
        let credentials = self.process().map_or(crate::process::Credentials::BOOT_USER, |p| p.credentials);
        let mut process = match programs.load(frames, name, parent, credentials) {
            Ok(process) => process,
            Err(e) => { frames.release(stack); return Err(e); }
        };
        if let Some(caller) = self.process() { process.files.inherit(&caller.files); }
        let context = (stack.address() + 4096 - size_of::<Context>()) as *mut Context;
        ptr::write_unaligned((*context).fx.as_mut_ptr() as *mut u16, 0x037f);
        ptr::write_unaligned((*context).fx.as_mut_ptr().add(24) as *mut u32, 0x1f80);
        (*context).rip = process.entry;
        (*context).cs = 0x33;
        (*context).flags = 0x202;
        (*context).rsp = STACK;
        (*context).ss = 0x2b;
        let pid = process.pid;
        self.tasks[slot] = Some(Task { stack, context: context as usize, runnable: true, waiting: None, preemptions: 0,
                                      process: Some(process) });
        self.count = self.count.max(slot+1);
        Ok(pid)
    }

    pub fn process(&self) -> Option<&Process> { self.tasks[self.current?].as_ref()?.process.as_ref() }
    pub fn process_mut(&mut self) -> Option<&mut Process> { self.tasks[self.current?].as_mut()?.process.as_mut() }

    pub fn block(&mut self, wait: crate::files::Wait) {
        let t = self.tasks[self.current.unwrap()].as_mut().unwrap();
        t.runnable = false;
        t.waiting = Some(wait);
    }

    pub fn wake_io(&mut self) {
        for t in self.tasks.iter_mut().flatten() {
            if t.waiting.map_or(false, |w| w.ready()) {
                t.waiting = None;
                t.runnable = true;
            }
        }
    }

    pub fn user_stack_top(&self) -> Option<usize> {
        Some(self.tasks[self.current?].as_ref()?.stack.address() + 4096)
    }

    pub fn terminate(&mut self, status: usize, frames: &mut Frames<'_>) {
        let task = self.tasks[self.current.unwrap()].as_mut().unwrap();
        let process = task.process.as_mut().unwrap();
        process.files.close_all(frames);
        process.status = Some(status);
        task.runnable = false;
        self.wake_io();
    }

    pub fn collect(&mut self, frames: &mut Frames<'_>, parent: usize, pid: usize) -> Result<usize, isize> {
        let (i, process) = self.tasks.iter().enumerate()
            .filter_map(|(i, task)| Some((i, task.as_ref()?.process.as_ref()?)))
            .find(|(_, p)| p.parent == parent && p.pid == pid).ok_or(-10isize)?;
        let status = process.status.ok_or(-11isize)?;
        self.release_task(i, frames);
        Ok(status)
    }

    fn release_task(&mut self, i: usize, frames: &mut Frames<'_>) {
        if let Some(task) = self.tasks[i].take() {
            if let Some(p) = task.process { p.files.release(frames); unsafe { p.space.release(frames); } }
            frames.release(task.stack);
        }
    }

    pub fn select(&mut self, outgoing: usize, timer: bool) -> usize {
        if !self.active { return outgoing; }
        let first = if let Some(i) = self.current {
            self.tasks[i].as_mut().unwrap().context = outgoing;
            i + 1
        } else {
            self.caller = outgoing;
            0
        };
        for offset in 0..self.count {
            let next = (first + offset) % self.count;
            if !self.tasks[next].as_ref().map_or(false, |task| task.runnable) { continue; }
            if let Some(prev) = self.current {
                let previous = self.tasks[prev].as_mut().unwrap();
                if timer && prev != next && previous.runnable { previous.preemptions += 1; }
            }
            self.current = Some(next);
            return self.tasks[next].as_ref().unwrap().context;
        }
        self.current = None;
        self.active = self.tasks.iter().flatten().any(|t| t.waiting.is_some());
        self.caller
    }

    pub fn finish_current(&mut self) {
        self.tasks[self.current.unwrap()].as_mut().unwrap().runnable = false;
    }

    pub fn preemptions(&self, i: usize) -> usize {
        self.tasks[i].as_ref().unwrap().preemptions
    }

    pub fn reap(&mut self, frames: &mut Frames<'_>) {
        assert!(!self.active && self.current.is_none());
        for i in 0..self.count { self.release_task(i, frames); }
        self.count = 0;
    }
}
