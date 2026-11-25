//! Per-CPU round robin. Queue access requires IF=0 and its CPU queue lock.
//! Cross-CPU transfer holds both queue locks in ascending CPU order. Lifecycle
//! and shared I/O metadata additionally require the common Frames gate.
#![allow(non_snake_case)]
use crate::frames::Frames;
use crate::stack::KernelStack;
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
    stack: KernelStack,
    context: usize,
    runnable: bool,
    waiting: Option<crate::files::Wait>,
    timed: Option<TimedWait>,
    clock_error: bool,
    preemptions: usize,
    fHasRun: bool,
    fMigrations: usize,
    process: Option<Process>,
}

const CAPACITY: usize = 8;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MigrationInfo {
    pub fPid: usize,
    pub fContext: usize,
    pub fRoot: usize,
    pub fStackTop: usize,
    pub fMigrations: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TimedWait {
    Sleep(u64),
    Child { pid: usize, deadline: u64 },
    /// Untimed wait for a direct child: only the lifecycle event wakes it.
    ChildExit { pid: usize },
    /// Wait for any watched local IPC message, a direct-child exit, or timeout.
    Events { mask: u32, deadline: u64 },
}
impl TimedWait {
    fn deadline(self) -> Option<u64> {
        match self {
            Self::Sleep(ms) | Self::Child { deadline: ms, .. } | Self::Events { deadline: ms, .. } => Some(ms),
            Self::ChildExit { .. } => None,
        }
    }
}

pub struct Queue {
    tasks: [Option<Task>; CAPACITY],
    count: usize,
    current: Option<usize>,
    fRetiring: Option<usize>,
    fRuntimeIdle: bool,
    fPrograms: *const Programs,
    caller: usize,
    /// Bootstrap root identity of this CPU acceptance run. Runtime parent and
    /// reaper relationships live in Programs::fRegistry and may cross CPUs.
    init_pid: Option<usize>,
    /// Kernel-held BSP root across boot checks and TTY handoff.
    boot_parked: Option<usize>,
    /// Never allow PID 1 to initiate a second bootstrap handoff after TTY.
    boot_handoff_done: bool,
    pub active: bool,
}

impl Queue {
    pub fn new() -> Self {
        Self { tasks: core::array::from_fn(|_| None), count: 0, current: None, fRetiring: None, fRuntimeIdle: false, fPrograms: ptr::null(), caller: 0, init_pid: None, boot_parked: None, boot_handoff_done: false, active: false }
    }

    pub fn spawn(&mut self, frames: &mut Frames<'_>, entry: extern "C" fn(usize), arg: usize) -> Option<()> {
        if self.active || self.count == CAPACITY { return None; }
        let stack = KernelStack::allocate(frames)?;
        let top = stack.top();
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
        self.tasks[self.count] = Some(Task { stack, context: context as usize, runnable: true, waiting: None, timed: None,
                                          clock_error: false, preemptions: 0, fHasRun: false, fMigrations: 0, process: None });
        self.count += 1;
        Some(())
    }

    pub unsafe fn spawn_process(&mut self, frames: &mut Frames<'_>, programs: &Programs, name: &[u8],
                                parent: usize, flags: usize) -> Result<usize, isize> {
        // Validate before allocating any frame or consuming a PID.
        const SPAWN_STDIO_ONLY: usize = 1;
        if flags & !SPAWN_STDIO_ONLY != 0 { return Err(-22); }
        if !self.fPrograms.is_null() && self.fPrograms != programs as *const Programs { return Err(-22); }
        let slot = self.tasks.iter().position(Option::is_none).ok_or(-11isize)?;
        let stack = KernelStack::allocate(frames).ok_or(-12isize)?;
        let credentials = self.process().map_or(crate::process::Credentials::BOOT_USER, |p| p.credentials);
        let mut process = match programs.load(frames, name, parent, credentials) {
            Ok(process) => process,
            Err(e) => { stack.release(frames); return Err(e); }
        };
        if let Some(caller) = self.process() {
            if flags & SPAWN_STDIO_ONLY != 0 { process.files.inherit_stdio(frames, &caller.files); }
            else { process.files.inherit(frames, &caller.files); }
        }
        let context = (stack.top() - size_of::<Context>()) as *mut Context;
        ptr::write_unaligned((*context).fx.as_mut_ptr() as *mut u16, 0x037f);
        ptr::write_unaligned((*context).fx.as_mut_ptr().add(24) as *mut u32, 0x1f80);
        (*context).rip = process.entry;
        (*context).cs = 0x33;
        (*context).flags = 0x202;
        (*context).rsp = STACK;
        (*context).ss = 0x2b;
        let pid = process.pid;
        self.fPrograms = programs;
        self.tasks[slot] = Some(Task { stack, context: context as usize, runnable: true, waiting: None, timed: None,
                                      clock_error: false, preemptions: 0, fHasRun: false, fMigrations: 0, process: Some(process) });
        self.count = self.count.max(slot+1);
        if parent == 0 && self.init_pid.is_none() { self.init_pid = Some(pid); }
        Ok(pid)
    }

    /// fork(2)-style clone with CPU-independent lifecycle identity. The child continues at the instruction
    /// after SYSCALL with RAX=0 and its own kernel interrupt stack. The parent
    /// receives the child's PID. Both user stacks start as shared RO/COW pages.
    /// All potentially failing allocations and descriptor retention happen
    /// before fork_cow commits the parent's writable PTE protection.
    pub unsafe fn fork_process(&mut self, frames: &mut Frames<'_>, programs: &Programs,
                               parent_context: &Context) -> Result<usize, isize> {
        if self.fPrograms != programs as *const Programs { return Err(-22); }
        let slot = self.tasks.iter().position(Option::is_none).ok_or(-11isize)?;
        let parent = self.process().ok_or(-1isize)?;
        let stack = KernelStack::allocate(frames).ok_or(-12isize)?;
        let Some(mut files) = crate::files::Descriptors::new(frames) else {
            stack.release(frames);
            return Err(-12);
        };
        files.inherit(frames, &parent.files);
        let child_pid = match programs.allocate_pid() {
            Ok(pid) => pid,
            Err(error) => {
                files.release(frames);
                stack.release(frames);
                return Err(error);
            }
        };
        let pLifecycle = match programs.fRegistry.register(frames, child_pid, parent.pid) {
            Ok(pEntry) => pEntry,
            Err(pError) => { files.release(frames); stack.release(frames); return Err(pError); }
        };
        let space = match parent.space.fork_cow(frames, programs.kernel_root) {
            Ok(space) => space,
            Err(error) => {
                pLifecycle.release(frames);
                files.release(frames);
                stack.release(frames);
                return Err(error);
            }
        };
        let child = Process {
            credentials: parent.credentials, space, entry: parent.entry,
            parent: parent.pid, pid: child_pid, status: None, files, fLifecycle: pLifecycle,
        };
        let context = (stack.top() - size_of::<Context>()) as *mut Context;
        ptr::copy_nonoverlapping(parent_context, context, 1);
        (*context).registers[14] = 0; // child SYS_FORK return value
        self.tasks[slot] = Some(Task {
            stack, context: context as usize, runnable: true,
            waiting: None, timed: None, clock_error: false, preemptions: 0, fHasRun: false, fMigrations: 0,
            process: Some(child),
        });
        self.count = self.count.max(slot + 1);
        Ok(child_pid)
    }

    pub fn process(&self) -> Option<&Process> { self.tasks[self.current?].as_ref()?.process.as_ref() }
    pub fn process_mut(&mut self) -> Option<&mut Process> { self.tasks[self.current?].as_mut()?.process.as_mut() }
    pub fn running(&self) -> bool { self.current.is_some() }
    pub fn all_blocked(&self) -> bool {
        self.active && !self.tasks.iter().flatten().any(|task| task.runnable)
    }

    pub fn terminal(&mut self, pid: usize, terminal: *mut crate::tty::Terminal) -> Result<(), isize> {
        if self.active || self.current.is_some() { return Err(-16); }
        self.tasks.iter_mut().flatten().filter_map(|task| task.process.as_mut())
            .find(|p| p.pid == pid).ok_or(-3isize)?.files.terminal(terminal)
    }

    /// Only the first root may park, and only after reaping all descendants.
    /// Its saved syscall context remains attached to the same PID/address space.
    pub fn park_boot_root(&mut self, frames: &mut Frames<'_>, pid: usize) -> Result<(), isize> {
        if self.init_pid != Some(pid) || self.boot_parked.is_some() ||
           self.boot_handoff_done ||
           self.process().map(|p| p.pid) != Some(pid) ||
           self.child_after(frames, pid, 0) != Err(-10) { return Err(-16); }
        self.tasks[self.current.unwrap()].as_mut().unwrap().runnable = false;
        self.boot_parked = Some(pid);
        Ok(())
    }

    pub fn parked_root(&self) -> Option<usize> {
        if !self.active && self.current.is_none() { self.boot_parked } else { None }
    }

    #[allow(non_snake_case)]
    pub fn parkedSpace(&self) -> Option<&crate::paging::UserSpace> {
        let pPid = self.parked_root()?;
        self.tasks.iter().flatten().filter_map(|pTask| pTask.process.as_ref())
            .find(|pProcess| pProcess.pid == pPid && pProcess.status.is_none())
            .map(|pProcess| &pProcess.space)
    }

    pub fn resume_boot_root(&mut self, pid: usize) -> Result<(), isize> {
        if self.parked_root() != Some(pid) { return Err(-16); }
        let task = self.tasks.iter_mut().flatten().find(|t| t.process.as_ref()
            .map_or(false, |p| p.pid == pid && p.status.is_none())).ok_or(-3isize)?;
        task.runnable = true;
        self.boot_parked = None;
        self.boot_handoff_done = true;
        Ok(())
    }

    pub fn block(&mut self, wait: crate::files::Wait) {
        let t = self.tasks[self.current.unwrap()].as_mut().unwrap();
        t.runnable = false;
        t.waiting = Some(wait);
    }

    /// Called exclusively by the owner CPU with interrupts disabled. The
    /// original syscall is restarted on wake, and checks its own deadline.
    pub fn block_sleep(&mut self, deadline: u64, now: u64) {
        self.block_timed(TimedWait::Sleep(deadline), now);
    }

    pub fn block_child(&mut self, pid: usize, deadline: u64, now: u64) {
        self.block_timed(TimedWait::Child { pid, deadline }, now);
    }

    pub fn block_child_exit(&mut self, pid: usize) {
        self.block_timed(TimedWait::ChildExit { pid }, 0);
    }

    pub fn block_events(&mut self, mask: u32, deadline: u64, now: u64) {
        self.block_timed(TimedWait::Events { mask, deadline }, now);
    }

    pub fn has_exited_child(&self, aFrames: &mut Frames<'_>, aParent: usize) -> bool {
        unsafe { self.fPrograms.as_ref() }.map_or(false, |pPrograms|
            pPrograms.fRegistry.hasExitedChild(aFrames, aParent))
    }

    fn block_timed(&mut self, wait: TimedWait, _now: u64) {
        let task = self.tasks[self.current.unwrap()].as_mut().unwrap();
        task.runnable = false;
        task.waiting = None;
        task.timed = Some(wait);
        task.clock_error = false;
    }

    /// A timed syscall that resumed due to an unresponsive clock reports -5.
    /// Read before retrying a deadline; the failure is consumed only once.
    pub fn take_clock_error(&mut self) -> bool {
        let task = self.tasks[self.current.unwrap()].as_mut().unwrap();
        let error = task.clock_error;
        task.clock_error = false;
        error
    }

    /// The LAPIC policy measures its own consumed countdown independently of
    /// TSC. A failed/stalled clock wakes waiters with EIO, never with a made-up
    /// timeout. A child exit remains valid even when time is unavailable.
    pub fn wake_timed(&mut self, aFrames: &mut Frames<'_>, aNow: u64, aClockError: bool) {
        let pPrograms = unsafe { self.fPrograms.as_ref() };
        for pTask in self.tasks.iter_mut().flatten() {
            let Some(pWait) = pTask.timed else { continue; };
            let pParent = pTask.process.as_ref().map(|pProcess| pProcess.pid);
            let pFinished = match (pWait, pPrograms, pParent) {
                (TimedWait::Child { pid, .. } | TimedWait::ChildExit { pid }, Some(pPrograms), Some(pParent)) =>
                    !pPrograms.fRegistry.childRunning(aFrames, pParent, pid),
                (TimedWait::Events { .. }, Some(pPrograms), Some(pParent)) =>
                    pPrograms.fRegistry.hasExitedChild(aFrames, pParent),
                _ => false,
            };
            let pDeadline = pWait.deadline();
            if pFinished || (!aClockError && pDeadline.is_some_and(|ms| aNow >= ms)) {
                pTask.timed = None;
                pTask.runnable = true;
            } else if aClockError && pDeadline.is_some() {
                pTask.timed = None;
                pTask.clock_error = true;
                pTask.runnable = true;
            }
        }
    }

    pub fn has_timed_waiters(&self) -> bool {
        self.tasks.iter().flatten().any(|task| task.timed.and_then(TimedWait::deadline).is_some())
    }

    /// Earliest scheduler-owned timeout, independent of task slot order.
    /// The CPU uses this only after selecting work, with local IRQs masked.
    pub fn next_deadline(&self) -> Option<u64> {
        self.tasks.iter().flatten().filter_map(|task| task.timed.and_then(TimedWait::deadline)).min()
    }

    /// The caller holds the local queue lock and Frames. Remote I/O/exit
    /// events request an IPI; the destination performs this scan itself.
    pub fn wake_io(&mut self, aFrames: &mut Frames<'_>) {
        let pPrograms = unsafe { self.fPrograms.as_ref() };
        for pTask in self.tasks.iter_mut().flatten() {
            if pTask.waiting.map_or(false, |pWait| pWait.ready(aFrames)) {
                pTask.waiting = None;
                pTask.runnable = true;
            }
            let Some(pProcess) = pTask.process.as_ref() else { continue; };
            let pReady = match pTask.timed {
                Some(TimedWait::Child { pid, .. } | TimedWait::ChildExit { pid }) => pPrograms.map_or(false, |pPrograms|
                    !pPrograms.fRegistry.childRunning(aFrames, pProcess.pid, pid)),
                Some(TimedWait::Events { mask, .. }) =>
                    pProcess.files.ipc_ready_mask(aFrames, mask).unwrap_or(0) != 0 ||
                    pPrograms.map_or(false, |pPrograms| pPrograms.fRegistry.hasExitedChild(aFrames, pProcess.pid)),
                _ => false,
            };
            if pReady { pTask.timed = None; pTask.runnable = true; }
        }
    }

    pub fn user_stack_top(&self) -> Option<usize> {
        Some(self.tasks[self.current?].as_ref()?.stack.top())
    }

    pub fn child_after(&self, aFrames: &mut Frames<'_>, aParent: usize, aCursor: usize)
        -> Result<usize, isize>
    {
        unsafe { self.fPrograms.as_ref() }.ok_or(-10isize)?
            .fRegistry.childAfter(aFrames, aParent, aCursor)
    }

    /// Only the owner stops a task and closes its descriptors. Registry
    /// requests from another CPU are consumed before returning to user mode.
    pub fn processPendingKills(&mut self, aFrames: &mut Frames<'_>) -> bool {
        let mut pChanged = false;
        loop {
            let mut pPassChanged = false;
            for pTask in self.tasks.iter_mut().flatten() {
                let Some(pProcess) = pTask.process.as_mut() else { continue; };
                let pState = pProcess.synchronizeMetadata(aFrames);
                if pState.fKillPending && pState.fStatus.is_none() {
                    pProcess.finish(aFrames, 137);
                    pPassChanged = true;
                }
                if pProcess.status.is_some() {
                    pTask.runnable = false;
                    pTask.waiting = None;
                    pTask.timed = None;
                    if self.init_pid == Some(pProcess.pid) { self.init_pid = None; }
                }
            }
            pChanged |= pPassChanged;
            // A root in a later migrated slot can request termination of an
            // earlier slot. Consume that request before any user return.
            if !pPassChanged { break; }
        }
        // An intermediate parent may have adopted an earlier local slot.
        for pTask in self.tasks.iter_mut().flatten() {
            if let Some(pProcess) = pTask.process.as_mut() { pProcess.synchronizeMetadata(aFrames); }
        }
        self.wake_io(aFrames);
        pChanged
    }

    pub fn terminate(&mut self, aStatus: usize, aFrames: &mut Frames<'_>) {
        let pTask = self.tasks[self.current.unwrap()].as_mut().unwrap();
        pTask.process.as_mut().unwrap().finish(aFrames, aStatus);
        pTask.runnable = false;
        pTask.waiting = None;
        pTask.timed = None;
        self.processPendingKills(aFrames);
    }

    pub fn kill_child(&mut self, aFrames: &mut Frames<'_>, aParent: usize, aPid: usize)
        -> Result<usize, isize>
    {
        let pResult = unsafe { self.fPrograms.as_ref() }.ok_or(-3isize)?
            .fRegistry.requestKill(aFrames, aParent, aPid)?;
        self.processPendingKills(aFrames);
        Ok(pResult)
    }

    pub fn collect(&mut self, aFrames: &mut Frames<'_>, aParent: usize, aPid: usize)
        -> Result<usize, isize>
    {
        let pStatus = unsafe { self.fPrograms.as_ref() }.ok_or(-10isize)?
            .fRegistry.collect(aFrames, aParent, aPid)?;
        self.collectRetired(aFrames);
        Ok(pStatus)
    }

    /// Reclaim only after status consumption and after the CPU stopped using
    /// both the address space and stack. Remote CPUs never free this Task.
    pub fn collectRetired(&mut self, aFrames: &mut Frames<'_>) -> usize {
        let mut pCount = 0;
        for pIndex in 0..self.count {
            if self.current == Some(pIndex) || self.fRetiring == Some(pIndex) { continue; }
            let pReady = self.tasks[pIndex].as_ref().and_then(|pTask| pTask.process.as_ref())
                .map_or(false, |pProcess| {
                    let pState = pProcess.fLifecycle.snapshot(aFrames);
                    pState.fStatus.is_some() && pState.fCollected
                });
            if pReady { self.release_task(pIndex, aFrames); pCount += 1; }
        }
        while self.count != 0 && self.tasks[self.count - 1].is_none() { self.count -= 1; }
        pCount
    }

    fn release_task(&mut self, aIndex: usize, aFrames: &mut Frames<'_>) {
        assert!(self.current != Some(aIndex) && self.fRetiring != Some(aIndex), "reaping an executing stack");
        if let Some(pTask) = self.tasks[aIndex].take() {
            if let Some(pProcess) = pTask.process { pProcess.release(aFrames); }
            pTask.stack.release(aFrames);
        }
    }

    /// Called by the restore trampoline only after RSP points at the incoming
    /// context. Before then the outgoing stack remains a CPU-owned hazard.
    pub fn completeSwitch(&mut self) { self.fRetiring = None; }

    pub fn setRuntimeIdle(&mut self, aEnabled: bool) {
        self.fRuntimeIdle = aEnabled;
        if aEnabled { self.active = true; }
    }

    pub fn runnableCount(&self) -> usize {
        self.tasks.iter().flatten().filter(|pTask| pTask.runnable).count()
    }
    pub fn taskCount(&self) -> usize { self.tasks.iter().flatten().count() }
    pub fn hasFreeSlot(&self) -> bool { self.tasks.iter().any(Option::is_none) }
    pub fn currentMigrations(&self) -> usize {
        self.current.and_then(|pIndex| self.tasks[pIndex].as_ref())
            .map_or(0, |pTask| pTask.fMigrations)
    }

    /// The caller holds both CPU queue locks in ascending CPU order, with
    /// local IRQs masked. No allocation, shared frame operation or remote
    /// hardware access occurs here. A full target leaves ownership untouched.
    pub fn moveRunnableTo(&mut self, aTarget: &mut Queue) -> Result<MigrationInfo, isize> {
        let pTargetSlot = aTarget.tasks.iter().position(Option::is_none).ok_or(-11isize)?;
        if !aTarget.fPrograms.is_null() && aTarget.fPrograms != self.fPrograms { return Err(-22); }
        let pSourceSlot = (0..self.count).find(|&pIndex| {
            if self.current == Some(pIndex) || self.fRetiring == Some(pIndex) { return false; }
            self.tasks[pIndex].as_ref().map_or(false, |pTask| {
                let Some(pProcess) = pTask.process.as_ref() else { return false; };
                pTask.runnable && pTask.fHasRun && pProcess.status.is_none() &&
                    self.boot_parked != Some(pProcess.pid) &&
                    !(self.init_pid == Some(pProcess.pid) && !self.boot_handoff_done)
            })
        }).ok_or(-3isize)?;
        let mut pTask = self.tasks[pSourceSlot].take().unwrap();
        pTask.fMigrations = pTask.fMigrations.saturating_add(1);
        let pProcess = pTask.process.as_ref().unwrap();
        let pInfo = MigrationInfo { fPid: pProcess.pid, fContext: pTask.context,
            fRoot: pProcess.space.root, fStackTop: pTask.stack.top(), fMigrations: pTask.fMigrations };
        aTarget.tasks[pTargetSlot] = Some(pTask);
        aTarget.fPrograms = self.fPrograms;
        aTarget.count = aTarget.count.max(pTargetSlot + 1);
        aTarget.active = true;
        while self.count != 0 && self.tasks[self.count - 1].is_none() { self.count -= 1; }
        Ok(pInfo)
    }

    pub fn select(&mut self, outgoing: usize, timer: bool) -> usize {
        if !self.active { return outgoing; }
        assert!(self.fRetiring.is_none(), "switch completion not acknowledged");
        let pPrevious = self.current;
        let first = if let Some(i) = pPrevious {
            self.tasks[i].as_mut().unwrap().context = outgoing;
            i + 1
        } else {
            self.caller = outgoing;
            0
        };
        for offset in 0..self.count {
            let next = (first + offset) % self.count;
            if !self.tasks[next].as_ref().map_or(false, |task| task.runnable) { continue; }
            if let Some(prev) = pPrevious {
                let previous = self.tasks[prev].as_mut().unwrap();
                if timer && prev != next && previous.runnable { previous.preemptions += 1; }
                if prev != next { self.fRetiring = Some(prev); }
            }
            self.current = Some(next);
            let pTask = self.tasks[next].as_mut().unwrap();
            pTask.fHasRun = true;
            return pTask.context;
        }
        self.current = None;
        self.fRetiring = pPrevious;
        self.active = self.fRuntimeIdle || self.tasks.iter().flatten()
            .any(|t| t.waiting.is_some() || t.timed.is_some());
        self.caller
    }

    pub fn finish_current(&mut self) {
        self.tasks[self.current.unwrap()].as_mut().unwrap().runnable = false;
    }

    pub fn preemptions(&self, i: usize) -> usize {
        self.tasks[i].as_ref().unwrap().preemptions
    }

    pub fn reap(&mut self, frames: &mut Frames<'_>) {
        assert!(!self.active && self.current.is_none() && self.fRetiring.is_none());
        for i in 0..self.count { self.release_task(i, frames); }
        self.count = 0;
        self.init_pid = None;
        self.boot_parked = None;
    }
}

#[cfg(test)]
mod timed_tests {
    use super::*;

    struct Harness {
        fPrograms: Box<Programs>,
        fFrames: Frames<'static>,
        fQueues: [Queue; 2],
    }
    impl Harness {
        fn new(aChild: bool) -> Self {
            let mut pSelf = Self {
                fPrograms: Box::new(Programs::new(&[], 0x1000)),
                fFrames: Frames::test_dummy(), fQueues: [Queue::new(), Queue::new()],
            };
            assert_eq!(pSelf.add(0, 0), 1);
            if aChild { assert_eq!(pSelf.add(0, 1), 2); }
            pSelf.fQueues[0].current = Some(0);
            pSelf.fQueues[0].active = true;
            pSelf.fQueues[0].caller = 10;
            pSelf
        }
        fn add(&mut self, aCpu: usize, aParent: usize) -> usize {
            let pPid = self.fPrograms.allocate_pid().unwrap();
            let pEntry = unsafe { self.fPrograms.fRegistry.register(&mut self.fFrames, pPid, aParent).unwrap() };
            let pQueue = &mut self.fQueues[aCpu];
            pQueue.fPrograms = &*self.fPrograms;
            let pSlot = pQueue.tasks.iter().position(Option::is_none).unwrap();
            let mut pSpace = crate::paging::UserSpace::test_dummy();
            pSpace.root = 0x100000 + pPid * 4096;
            pQueue.tasks[pSlot] = Some(Task {
                stack: KernelStack::test_dummy(), context: pPid * 4096,
                runnable: true, waiting: None, timed: None, clock_error: false,
                preemptions: 0, fHasRun: true, fMigrations: 0,
                process: Some(Process { pid: pPid, parent: aParent, status: None,
                    credentials: crate::process::Credentials::BOOT_USER, entry: 0,
                    space: pSpace, files: crate::files::Descriptors::test_dummy(), fLifecycle: pEntry }),
            });
            pQueue.count = pQueue.count.max(pSlot + 1);
            if aParent == 0 && pQueue.init_pid.is_none() { pQueue.init_pid = Some(pPid); }
            pPid
        }
        fn select(&mut self, aCpu: usize, aOutgoing: usize, aTimer: bool) -> usize {
            let pContext = self.fQueues[aCpu].select(aOutgoing, aTimer);
            self.fQueues[aCpu].completeSwitch();
            pContext
        }
        fn moveTask(&mut self, aFrom: usize) -> Result<MigrationInfo, isize> {
            let [pLeft, pRight] = &mut self.fQueues;
            if aFrom == 0 { pLeft.moveRunnableTo(pRight) } else { pRight.moveRunnableTo(pLeft) }
        }
        fn state(&mut self, aPid: usize) -> crate::lifecycle::Snapshot {
            self.fQueues.iter().flat_map(|pQueue| pQueue.tasks.iter().flatten())
                .filter_map(|pTask| pTask.process.as_ref()).find(|pProcess| pProcess.pid == aPid)
                .unwrap().fLifecycle.snapshot(&mut self.fFrames)
        }
    }
    impl Drop for Harness {
        fn drop(&mut self) {
            for pQueue in &mut self.fQueues {
                pQueue.completeSwitch();
                pQueue.current = None;
                pQueue.active = false;
                pQueue.reap(&mut self.fFrames);
            }
            assert!(!self.fPrograms.fRegistry.hasProcesses(&mut self.fFrames));
            assert_eq!(self.fFrames.used(), 0, "registry frame leak");
        }
    }

    #[test]
    fn timerKeepsAllBlockedParentRunnableAfterDeadline() {
        let mut p = Harness::new(true);
        p.fQueues[0].tasks[1].as_mut().unwrap().runnable = false;
        p.fQueues[0].block_sleep(125, 100);
        assert_eq!(p.select(0, 77, false), 10);
        assert!(p.fQueues[0].active && !p.fQueues[0].running());
        p.fQueues[0].wake_timed(&mut p.fFrames, 124, false);
        assert!(p.fQueues[0].has_timed_waiters());
        p.fQueues[0].wake_timed(&mut p.fFrames, 125, false);
        assert_eq!(p.select(0, 11, true), 77);
        assert!(!p.fQueues[0].take_clock_error());
    }

    #[test]
    fn migratedLiveChildDoesNotBecomeAFabricatedExit() {
        let mut p = Harness::new(true);
        assert_eq!(p.moveTask(0).unwrap().fPid, 2);
        p.fQueues[0].block_child(2, 900, 100);
        assert_eq!(p.select(0, 99, false), 10);
        p.fQueues[0].wake_timed(&mut p.fFrames, 101, false);
        p.fQueues[0].wake_io(&mut p.fFrames);
        assert!(p.fQueues[0].has_timed_waiters() && !p.fQueues[0].running());
        assert_eq!(p.fQueues[0].collect(&mut p.fFrames, 1, 2), Err(-11));
        assert_eq!(p.fQueues[0].child_after(&mut p.fFrames, 1, 0), Ok(2));
    }

    #[test]
    fn remoteChildExitWakesParentBeforeDeadlineWithoutPolling() {
        let mut p = Harness::new(true);
        p.moveTask(0).unwrap();
        p.fQueues[0].block_child(2, 900, 100);
        p.select(0, 99, false);
        assert_eq!(p.select(1, 200, false), 8192);
        p.fQueues[1].terminate(42, &mut p.fFrames);
        p.fQueues[0].wake_io(&mut p.fFrames);
        assert!(!p.fQueues[0].has_timed_waiters());
        assert_eq!(p.select(0, 11, false), 99);
        assert_eq!(p.fQueues[0].collect(&mut p.fFrames, 1, 2), Ok(42));
        // The child still owns its outgoing kernel stack on CPU1.
        assert_eq!(p.fQueues[1].collectRetired(&mut p.fFrames), 0);
        p.select(1, 0, false);
        assert_eq!(p.fQueues[1].collectRetired(&mut p.fFrames), 1);
        assert_eq!(p.fFrames.used(), 1);
    }

    #[test]
    fn untimedWaitForMigratedChildNeedsNoClockOrTimer() {
        let mut p = Harness::new(true);
        assert_eq!(p.moveTask(0).unwrap().fPid, 2);
        p.fQueues[0].block_child_exit(2);
        assert_eq!(p.select(0, 99, false), 10);
        assert_eq!(p.fQueues[0].next_deadline(), None);
        assert!(!p.fQueues[0].has_timed_waiters());
        assert!(p.fQueues[0].active && !p.fQueues[0].running());
        p.fQueues[0].wake_timed(&mut p.fFrames, u64::MAX, true);
        p.fQueues[0].wake_io(&mut p.fFrames);
        assert!(!p.fQueues[0].tasks[0].as_ref().unwrap().runnable);
        assert_eq!(p.fQueues[0].collect(&mut p.fFrames, 1, 2), Err(-11));
        assert_eq!(p.select(1, 200, false), 8192);
        p.fQueues[1].terminate(42, &mut p.fFrames);
        p.fQueues[0].wake_io(&mut p.fFrames);
        assert_eq!(p.select(0, 11, false), 99);
        assert!(!p.fQueues[0].take_clock_error());
        assert_eq!(p.fQueues[0].collect(&mut p.fFrames, 1, 2), Ok(42));
        assert_eq!(p.fQueues[0].collect(&mut p.fFrames, 1, 2), Err(-10));
        p.select(1, 0, false);
        assert_eq!(p.fQueues[1].collectRetired(&mut p.fFrames), 1);
    }

    #[test]
    fn permanentlyFrozenClockReturnsErrorRatherThanTimeout() {
        let mut p = Harness::new(false);
        p.fQueues[0].block_sleep(10_000, 100);
        p.select(0, 77, false);
        let mut pTimer = crate::timer::Timer::new(1000);
        pTimer.reset(Some(100));
        for pSecond in 1..=5 {
            assert_eq!(pTimer.plan(false, p.fQueues[0].next_deadline(), 100), crate::timer::Action::Arm(100_000));
            p.fQueues[0].wake_timed(&mut p.fFrames, 100, pTimer.sample(0, Some(100)));
            assert_eq!(p.fQueues[0].has_timed_waiters(), pSecond < 5);
        }
        assert_eq!(p.select(0, 11, true), 77);
        assert!(p.fQueues[0].take_clock_error());
        assert!(!p.fQueues[0].take_clock_error());
    }

    #[test]
    fn advancingClockDoesNotBecomeAFalseFailure() {
        let mut p = Harness::new(false);
        p.fQueues[0].block_sleep(20_000, 0);
        p.select(0, 77, false);
        for pNow in 1..=1000 { p.fQueues[0].wake_timed(&mut p.fFrames, pNow, false); }
        assert!(p.fQueues[0].has_timed_waiters());
        assert!(!p.fQueues[0].tasks[0].as_ref().unwrap().clock_error);
    }

    #[test]
    fn deadlineWakeDoesNotCollectAStillRunningRemoteChild() {
        let mut p = Harness::new(true);
        p.moveTask(0).unwrap();
        p.fQueues[0].block_child(2, 200, 100);
        p.select(0, 99, false);
        p.fQueues[0].wake_timed(&mut p.fFrames, 200, false);
        assert!(!p.fQueues[0].has_timed_waiters());
        assert_eq!(p.state(2).fStatus, None);
        assert_eq!(p.fQueues[0].collect(&mut p.fFrames, 1, 2), Err(-11));
    }

    #[test]
    fn remoteKillChecksOwnershipAndWaitsForOwnerAcknowledgement() {
        let mut p = Harness::new(true);
        p.moveTask(0).unwrap();
        p.select(1, 200, false);
        assert_eq!(p.fQueues[0].kill_child(&mut p.fFrames, 3, 2), Err(-1));
        assert_eq!(p.fQueues[0].kill_child(&mut p.fFrames, 1, 1), Err(-22));
        assert_eq!(p.fQueues[0].kill_child(&mut p.fFrames, 1, 999), Err(-3));
        assert_eq!(p.fQueues[0].kill_child(&mut p.fFrames, 1, 2), Ok(0));
        assert!(p.state(2).fKillPending);
        assert_eq!(p.state(2).fStatus, None);
        assert_eq!(p.fQueues[0].collect(&mut p.fFrames, 1, 2), Err(-11));
        assert!(p.fQueues[1].processPendingKills(&mut p.fFrames));
        assert_eq!(p.state(2).fStatus, Some(137));
        assert_eq!(p.fQueues[0].kill_child(&mut p.fFrames, 1, 2), Ok(1));
        assert!(!p.fQueues[1].tasks[0].as_ref().unwrap().runnable);
    }

    #[test]
    fn aConcurrentKillOfTheCallerPreventsItsNextUserSelection() {
        let mut p = Harness::new(true);
        p.add(0, 2); //3, child of the current syscall caller
        p.fQueues[0].current = Some(1);
        assert_eq!(p.fPrograms.fRegistry.requestKill(&mut p.fFrames, 1, 2), Ok(0));
        assert_eq!(p.fQueues[0].kill_child(&mut p.fFrames, 2, 3), Ok(0));
        assert_eq!(p.fQueues[0].process().unwrap().status, Some(137));
        assert_eq!(p.fPrograms.fRegistry.parentOf(&mut p.fFrames, 3), Some(1));
        assert_eq!(p.select(0, 0, false), 4096);
        assert_eq!(p.fQueues[0].process().unwrap().pid, 1);
    }

    #[test]
    fn bootRootParksAndResumesWithIdenticalPidAndContext() {
        let mut p = Harness::new(false);
        assert!(p.fQueues[0].parkedSpace().is_none());
        assert_eq!(p.fQueues[0].park_boot_root(&mut p.fFrames, 1), Ok(()));
        assert_eq!(p.select(0, 0x222, false), 10);
        assert_eq!(p.fQueues[0].parked_root(), Some(1));
        assert!(p.fQueues[0].parkedSpace().is_some());
        assert_eq!(p.moveTask(0), Err(-3));
        assert_eq!(p.fQueues[0].resume_boot_root(999), Err(-16));
        assert_eq!(p.fQueues[0].resume_boot_root(1), Ok(()));
        assert_eq!(p.fQueues[0].resume_boot_root(1), Err(-16));
        p.fQueues[0].active = true;
        assert_eq!(p.select(0, 0x333, false), 0x222);
        assert_eq!(p.fQueues[0].process().unwrap().pid, 1);
        assert_eq!(p.fQueues[0].park_boot_root(&mut p.fFrames, 1), Err(-16));
    }

    #[test]
    fn eventWaitWakesOnRemoteChildExitEvenWhenClockFails() {
        let mut p = Harness::new(true);
        p.moveTask(0).unwrap();
        p.fQueues[0].block_events(0, 900, 100);
        p.select(0, 77, false);
        p.select(1, 200, false);
        p.fQueues[1].terminate(42, &mut p.fFrames);
        p.fQueues[0].wake_timed(&mut p.fFrames, 100, true);
        assert_eq!(p.select(0, 11, false), 77);
        assert!(!p.fQueues[0].take_clock_error());
        assert!(p.fQueues[0].has_exited_child(&mut p.fFrames, 1));
        assert!(!p.fQueues[0].has_exited_child(&mut p.fFrames, 2));
    }

    #[test]
    fn nearestDeadlineTracksSleepAndEventWaiters() {
        let mut p = Harness::new(true);
        p.fQueues[0].block_sleep(900, 100);
        p.select(0, 77, false);
        p.fQueues[0].block_events(0, 250, 100);
        assert_eq!(p.fQueues[0].next_deadline(), Some(250));
        p.select(0, 88, false);
        p.fQueues[0].wake_timed(&mut p.fFrames, 249, false);
        assert_eq!(p.fQueues[0].next_deadline(), Some(250));
        p.fQueues[0].wake_timed(&mut p.fFrames, 250, false);
        assert_eq!(p.fQueues[0].next_deadline(), Some(900));
        assert_eq!(p.select(0, 99, true), 88);
        p.fQueues[0].wake_timed(&mut p.fFrames, 900, false);
        assert_eq!(p.fQueues[0].next_deadline(), None);
        assert!(!p.fQueues[0].has_exited_child(&mut p.fFrames, 1));
    }

    #[test]
    fn untrustedExpiredTimeCannotOverrideClockFailure() {
        let mut p = Harness::new(false);
        p.fQueues[0].block_events(0, 200, 100);
        p.select(0, 77, false);
        p.fQueues[0].wake_timed(&mut p.fFrames, 999, true);
        assert_eq!(p.select(0, 88, false), 77);
        assert!(p.fQueues[0].take_clock_error());
    }

    #[test]
    fn adoptionAcrossCpusPreservesLiveAndZombieChildren() {
        let mut p = Harness::new(true);
        assert_eq!(p.add(1, 1), 3);
        assert_eq!(p.add(1, 3), 4);
        assert_eq!(p.add(0, 3), 5);
        p.fQueues[0].current = Some(2); // grandchild5 exits before parent3
        p.fQueues[0].terminate(19, &mut p.fFrames);
        p.select(0, 0, false);
        p.fQueues[1].active = true;
        p.select(1, 200, false); // intermediate parent3
        p.fQueues[1].terminate(0, &mut p.fFrames);
        assert_eq!(p.fPrograms.fRegistry.parentOf(&mut p.fFrames, 4), Some(1));
        assert_eq!(p.fPrograms.fRegistry.parentOf(&mut p.fFrames, 5), Some(1));
        assert_eq!(p.fQueues[0].child_after(&mut p.fFrames, 1, 3), Ok(4));
        assert_eq!(p.fQueues[0].child_after(&mut p.fFrames, 1, 4), Ok(5));
        assert_eq!(p.fQueues[0].collect(&mut p.fFrames, 3, 4), Err(-10));
        assert_eq!(p.fQueues[0].kill_child(&mut p.fFrames, 3, 4), Err(-1));
        assert_eq!(p.fQueues[0].collect(&mut p.fFrames, 1, 5), Ok(19));
        assert_eq!(p.fQueues[0].kill_child(&mut p.fFrames, 1, 4), Ok(0));
        p.fQueues[1].processPendingKills(&mut p.fFrames);
        assert_eq!(p.fQueues[0].collect(&mut p.fFrames, 1, 4), Ok(137));
        assert_eq!(p.fQueues[0].collect(&mut p.fFrames, 1, 3), Ok(0));
        assert_eq!(p.fQueues[0].child_after(&mut p.fFrames, 1, 0), Ok(2));
    }

    #[test]
    fn killingIntermediateParentAlsoAdoptsRemoteGrandchild() {
        let mut p = Harness::new(true);
        p.add(1, 1); //3
        p.add(1, 3); //4
        assert_eq!(p.fQueues[0].kill_child(&mut p.fFrames, 1, 3), Ok(0));
        p.fQueues[1].processPendingKills(&mut p.fFrames);
        assert_eq!(p.fPrograms.fRegistry.parentOf(&mut p.fFrames, 4), Some(1));
        assert_eq!(p.fQueues[0].kill_child(&mut p.fFrames, 1, 4), Ok(0));
        p.fQueues[1].processPendingKills(&mut p.fFrames);
        assert_eq!(p.fQueues[0].collect(&mut p.fFrames, 1, 3), Ok(137));
        assert_eq!(p.fQueues[0].collect(&mut p.fFrames, 1, 4), Ok(137));
    }

    #[test]
    fn rootExitStopsRemoteDescendantsAndWaitsForTheirStackCleanup() {
        let mut p = Harness::new(true);
        p.add(1, 1); //3
        p.add(1, 3); //4
        p.fQueues[1].active = true;
        p.select(1, 200, false);
        p.fQueues[0].terminate(7, &mut p.fFrames);
        assert_eq!(p.fQueues[0].init_pid, None);
        assert!(p.state(3).fKillPending && p.state(4).fKillPending);
        assert!(p.fPrograms.fRegistry.sessionChildrenRemain(&mut p.fFrames, 1));
        p.fQueues[1].processPendingKills(&mut p.fFrames);
        assert_eq!(p.state(3).fStatus, Some(137));
        assert_eq!(p.state(4).fStatus, Some(137));
        p.fQueues[1].collectRetired(&mut p.fFrames);
        assert!(!p.fPrograms.fRegistry.sessionEmpty(&mut p.fFrames, 1));
        p.select(1, 0, false);
        p.fQueues[1].collectRetired(&mut p.fFrames);
        p.select(0, 0, false);
        assert_eq!(p.fQueues[0].collect(&mut p.fFrames, 0, 1), Ok(7));
        assert!(p.fPrograms.fRegistry.sessionEmpty(&mut p.fFrames, 1));
        assert_eq!(p.fFrames.used(), 0);
    }

    #[test]
    fn pendingRootKillAlsoStopsChildrenInEarlierMigratedSlots() {
        let mut p = Harness::new(true);
        // Migration can place a reaper after an already-resident child.
        p.fQueues[0].tasks.swap(0, 1);
        p.fQueues[0].current = Some(0); // child2 is the interrupted process
        assert_eq!(p.fPrograms.fRegistry.requestKill(&mut p.fFrames, 0, 1), Ok(0));
        assert!(p.fQueues[0].processPendingKills(&mut p.fFrames));
        assert_eq!(p.state(1).fStatus, Some(137));
        assert_eq!(p.state(2).fStatus, Some(137));
        assert_eq!(p.fQueues[0].runnableCount(), 0);
        assert_eq!(p.select(0, 0, false), 10);
        assert_eq!(p.fQueues[0].collect(&mut p.fFrames, 0, 1), Ok(137));
        assert_eq!(p.fFrames.used(), 0);
    }

    #[test]
    fn migrationPreservesIdentityContextAndResourcesAcrossRepeatedTransfers() {
        let mut p = Harness::new(true);
        let pBefore = p.state(2);
        let pInitial = p.moveTask(0).unwrap();
        assert_eq!(pInitial.fPid, 2);
        assert_eq!(pInitial.fContext, 8192);
        assert_eq!(pInitial.fRoot, 0x102000);
        assert_eq!(pInitial.fMigrations, 1);
        for pIteration in 1..=100 {
            let pInfo = p.moveTask(pIteration % 2).unwrap();
            assert_eq!(pInfo.fPid, pInitial.fPid);
            assert_eq!(pInfo.fContext, pInitial.fContext);
            assert_eq!(pInfo.fRoot, pInitial.fRoot);
            assert_eq!(pInfo.fStackTop, pInitial.fStackTop);
            assert_eq!(pInfo.fMigrations, pIteration + 1);
            assert_eq!(p.fQueues[0].taskCount() + p.fQueues[1].taskCount(), 2);
            assert_eq!(p.state(2), pBefore);
            assert_eq!(p.fFrames.used(), 2);
        }
    }

    #[test]
    fn outgoingStackCannotMoveOrBeReapedBeforeSwitchAcknowledgement() {
        let mut p = Harness::new(true);
        p.fQueues[0].boot_handoff_done = true; // root becomes generally movable
        assert_eq!(p.fQueues[0].select(77, false), 8192);
        assert_eq!(p.moveTask(0), Err(-3)); // current child and retiring parent
        p.fQueues[0].completeSwitch();
        assert_eq!(p.moveTask(0).unwrap().fPid, 1);
        p.fQueues[0].terminate(42, &mut p.fFrames);
        assert_eq!(p.fPrograms.fRegistry.collect(&mut p.fFrames, 1, 2), Ok(42));
        assert_eq!(p.fQueues[0].select(0, false), 10);
        assert_eq!(p.fQueues[0].collectRetired(&mut p.fFrames), 0); // retiring child
        p.fQueues[0].completeSwitch();
        assert_eq!(p.fQueues[0].collectRetired(&mut p.fFrames), 1);
    }

    #[test]
    fn fullDestinationDoesNotChangeSourceOwnership() {
        let mut p = Harness::new(true);
        for _ in 0..CAPACITY { p.add(1, 1); }
        assert_eq!(p.moveTask(0), Err(-11));
        assert_eq!(p.fQueues[0].taskCount(), 2);
        assert_eq!(p.fQueues[0].tasks[1].as_ref().unwrap().fMigrations, 0);
        assert_eq!(p.fQueues[1].taskCount(), CAPACITY);
        assert_eq!(p.fFrames.used(), CAPACITY + 2);
    }

    #[test]
    fn neverRunBlockedDeadAndKernelTasksAreNotMigrationCandidates() {
        let mut p = Harness::new(true);
        p.fQueues[0].tasks[1].as_mut().unwrap().fHasRun = false;
        assert_eq!(p.moveTask(0), Err(-3));
        p.fQueues[0].tasks[1].as_mut().unwrap().fHasRun = true;
        p.fQueues[0].tasks[1].as_mut().unwrap().runnable = false;
        assert_eq!(p.moveTask(0), Err(-3));
        p.fQueues[0].tasks[1].as_mut().unwrap().runnable = true;
        p.fQueues[0].kill_child(&mut p.fFrames, 1, 2).unwrap();
        assert_eq!(p.moveTask(0), Err(-3));
        p.fQueues[0].collect(&mut p.fFrames, 1, 2).unwrap();
        p.fQueues[0].tasks[1] = Some(Task {
            stack: KernelStack::test_dummy(), context: 99, runnable: true,
            waiting: None, timed: None, clock_error: false, preemptions: 0,
            fHasRun: true, fMigrations: 0, process: None,
        });
        p.fQueues[0].count = 2;
        assert_eq!(p.moveTask(0), Err(-3));
    }

    #[test]
    fn persistentEmptyRuntimeQueueKeepsItsKernelIdleCaller() {
        let mut pQueue = Queue::new();
        pQueue.setRuntimeIdle(true);
        assert_eq!(pQueue.select(77, false), 77);
        assert!(pQueue.active && pQueue.all_blocked());
        assert_eq!(pQueue.next_deadline(), None);
        assert_eq!(pQueue.runnableCount(), 0);
        pQueue.completeSwitch();
        pQueue.setRuntimeIdle(false);
        assert_eq!(pQueue.select(88, false), 88);
        assert!(!pQueue.active);
    }

    #[test]
    fn exitedStatusCanOnlyBeConsumedOnceWhileZombieStillHasAStack() {
        let mut p = Harness::new(true);
        p.select(0, 77, false);
        p.fQueues[0].terminate(42, &mut p.fFrames);
        assert_eq!(p.fPrograms.fRegistry.collect(&mut p.fFrames, 1, 2), Ok(42));
        assert_eq!(p.fPrograms.fRegistry.collect(&mut p.fFrames, 1, 2), Err(-10));
        assert!(!p.fQueues[0].has_exited_child(&mut p.fFrames, 1));
        assert!(p.fPrograms.fRegistry.sessionChildrenRemain(&mut p.fFrames, 1));
        assert_eq!(p.fQueues[0].collectRetired(&mut p.fFrames), 0);
        p.select(0, 0, false);
        assert_eq!(p.fQueues[0].collectRetired(&mut p.fFrames), 1);
    }
}
