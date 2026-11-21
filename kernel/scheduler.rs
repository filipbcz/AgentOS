//! Per-CPU round robin for kernel threads. Queue access on its owner CPU
//! requires IF=0. A timer interrupt owns the outgoing frame until IRETQ.
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
    process: Option<Process>,
}

const CAPACITY: usize = 8;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TimedWait {
    Sleep(u64),
    Child { pid: usize, deadline: u64 },
    /// Wait for any watched local IPC message, a direct-child exit, or timeout.
    Events { mask: u32, deadline: u64 },
}
impl TimedWait {
    fn deadline(self) -> u64 {
        match self { Self::Sleep(ms) | Self::Child { deadline: ms, .. } | Self::Events { deadline: ms, .. } => ms }
    }
}

pub struct Queue {
    tasks: [Option<Task>; CAPACITY],
    count: usize,
    current: Option<usize>,
    caller: usize,
    /// First parent=0 userspace task of this CPU run. Never reassign while
    /// it is alive; no parent/child relationship crosses CPU ownership.
    init_pid: Option<usize>,
    /// Kernel-held BSP root across boot checks and TTY handoff.
    boot_parked: Option<usize>,
    /// Never allow PID 1 to initiate a second bootstrap handoff after TTY.
    boot_handoff_done: bool,
    pub active: bool,
}

impl Queue {
    pub fn new() -> Self {
        Self { tasks: core::array::from_fn(|_| None), count: 0, current: None, caller: 0, init_pid: None, boot_parked: None, boot_handoff_done: false, active: false }
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
                                          clock_error: false, preemptions: 0, process: None });
        self.count += 1;
        Some(())
    }

    pub unsafe fn spawn_process(&mut self, frames: &mut Frames<'_>, programs: &Programs, name: &[u8],
                                parent: usize) -> Result<usize, isize> {
        let slot = self.tasks.iter().position(Option::is_none).ok_or(-11isize)?;
        let stack = KernelStack::allocate(frames).ok_or(-12isize)?;
        let credentials = self.process().map_or(crate::process::Credentials::BOOT_USER, |p| p.credentials);
        let mut process = match programs.load(frames, name, parent, credentials) {
            Ok(process) => process,
            Err(e) => { stack.release(frames); return Err(e); }
        };
        if let Some(caller) = self.process() { process.files.inherit(&caller.files); }
        let context = (stack.top() - size_of::<Context>()) as *mut Context;
        ptr::write_unaligned((*context).fx.as_mut_ptr() as *mut u16, 0x037f);
        ptr::write_unaligned((*context).fx.as_mut_ptr().add(24) as *mut u32, 0x1f80);
        (*context).rip = process.entry;
        (*context).cs = 0x33;
        (*context).flags = 0x202;
        (*context).rsp = STACK;
        (*context).ss = 0x2b;
        let pid = process.pid;
        self.tasks[slot] = Some(Task { stack, context: context as usize, runnable: true, waiting: None, timed: None,
                                      clock_error: false, preemptions: 0, process: Some(process) });
        self.count = self.count.max(slot+1);
        if parent == 0 && self.init_pid.is_none() { self.init_pid = Some(pid); }
        Ok(pid)
    }

    /// fork(2)-style CPU-local clone. The child continues at the instruction
    /// after SYSCALL with RAX=0 and its own kernel interrupt stack. The parent
    /// receives the child's PID. Both user stacks start as shared RO/COW pages.
    /// All potentially failing allocations and descriptor retention happen
    /// before fork_cow commits the parent's writable PTE protection.
    pub unsafe fn fork_process(&mut self, frames: &mut Frames<'_>, programs: &Programs,
                               parent_context: &Context) -> Result<usize, isize> {
        let slot = self.tasks.iter().position(Option::is_none).ok_or(-11isize)?;
        let parent = self.process().ok_or(-1isize)?;
        let stack = KernelStack::allocate(frames).ok_or(-12isize)?;
        let Some(mut files) = crate::files::Descriptors::new(frames) else {
            stack.release(frames);
            return Err(-12);
        };
        files.inherit(&parent.files);
        let child_pid = match programs.allocate_pid() {
            Ok(pid) => pid,
            Err(error) => {
                files.release(frames);
                stack.release(frames);
                return Err(error);
            }
        };
        let space = match parent.space.fork_cow(frames, programs.kernel_root) {
            Ok(space) => space,
            Err(error) => {
                files.release(frames);
                stack.release(frames);
                return Err(error);
            }
        };
        let child = Process {
            credentials: parent.credentials, space, entry: parent.entry,
            parent: parent.pid, pid: child_pid, status: None, files,
        };
        let context = (stack.top() - size_of::<Context>()) as *mut Context;
        ptr::copy_nonoverlapping(parent_context, context, 1);
        (*context).registers[14] = 0; // child SYS_FORK return value
        self.tasks[slot] = Some(Task {
            stack, context: context as usize, runnable: true,
            waiting: None, timed: None, clock_error: false, preemptions: 0,
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
    pub fn park_boot_root(&mut self, pid: usize) -> Result<(), isize> {
        if self.init_pid != Some(pid) || self.boot_parked.is_some() ||
           self.boot_handoff_done ||
           self.process().map(|p| p.pid) != Some(pid) ||
           self.child_after(pid, 0) != Err(-10) { return Err(-16); }
        self.tasks[self.current.unwrap()].as_mut().unwrap().runnable = false;
        self.boot_parked = Some(pid);
        Ok(())
    }

    pub fn parked_root(&self) -> Option<usize> {
        if !self.active && self.current.is_none() { self.boot_parked } else { None }
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

    pub fn block_events(&mut self, mask: u32, deadline: u64, now: u64) {
        self.block_timed(TimedWait::Events { mask, deadline }, now);
    }

    pub fn has_exited_child(&self, parent: usize) -> bool {
        self.tasks.iter().flatten().filter_map(|task| task.process.as_ref())
            .any(|p| p.parent == parent && p.status.is_some())
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
    pub fn wake_timed(&mut self, now: u64, clock_error: bool) {
        for i in 0..self.count {
            let Some(wait) = self.tasks[i].as_ref().and_then(|t| t.timed) else { continue; };
            let child_finished = match wait {
                TimedWait::Child { pid, .. } =>
                    !self.tasks.iter().flatten().any(|t|
                        t.process.as_ref().map_or(false, |p| p.pid == pid && p.status.is_none())),
                TimedWait::Sleep(_) | TimedWait::Events { .. } => false,
            };
            let task = self.tasks[i].as_mut().unwrap();
            if child_finished || (!clock_error && now >= wait.deadline()) {
                task.timed = None;
                task.runnable = true;
            } else if clock_error {
                task.timed = None;
                task.clock_error = true;
                task.runnable = true;
            }
        }
    }

    pub fn has_timed_waiters(&self) -> bool {
        self.tasks.iter().flatten().any(|task| task.timed.is_some())
    }

    /// Earliest scheduler-owned timeout, independent of task slot order.
    /// The CPU uses this only after selecting work, with local IRQs masked.
    pub fn next_deadline(&self) -> Option<u64> {
        self.tasks.iter().flatten().filter_map(|task| task.timed.map(TimedWait::deadline)).min()
    }

    /// Eagerly wake parents when a child exits, independently of the APIC
    /// timer period. The syscall retries and performs authorized reaping.
    fn wake_child(&mut self, pid: usize) {
        let parent = self.tasks.iter().flatten().filter_map(|t| t.process.as_ref())
            .find(|p| p.pid == pid).map(|p| p.parent);
        for task in self.tasks.iter_mut().flatten() {
            let specified = matches!(task.timed, Some(TimedWait::Child { pid: child, .. }) if child == pid);
            let any_child = matches!(task.timed, Some(TimedWait::Events { .. })) &&
                task.process.as_ref().map(|p| p.pid) == parent;
            if specified || any_child {
                task.timed = None;
                task.runnable = true;
            }
        }
    }

    pub fn wake_io(&mut self) {
        for t in self.tasks.iter_mut().flatten() {
            if t.waiting.map_or(false, |w| w.ready()) {
                t.waiting = None;
                t.runnable = true;
            }
            if let Some(TimedWait::Events { mask, .. }) = t.timed {
                if t.process.as_ref().and_then(|p| p.files.ipc_ready_mask(mask).ok()).unwrap_or(0) != 0 {
                    t.timed = None;
                    t.runnable = true;
                }
            }
        }
    }

    pub fn user_stack_top(&self) -> Option<usize> {
        Some(self.tasks[self.current?].as_ref()?.stack.top())
    }

    /// Reassign all immediate children of an exiting process to this CPU's
    /// root user task. An already-exited child must also be adopted: its
    /// reaping right cannot remain attached to an uncollectable dead parent.
    /// If the root itself exits, no replacement supervisor exists. Fail
    /// closed by stopping all remaining userspace processes; reap() later
    /// frees their address spaces on the kernel stack, never in an IRQ.
    fn orphan_children(&mut self, frames: &mut Frames<'_>, exited_pid: usize) {
        let reaper = self.init_pid.filter(|&root| root != exited_pid &&
            self.tasks.iter().flatten().any(|t| t.process.as_ref()
                .map_or(false, |p| p.pid == root && p.status.is_none())));
        if let Some(root) = reaper {
            for task in self.tasks.iter_mut().flatten() {
                if let Some(process) = task.process.as_mut() {
                    if process.parent == exited_pid { process.parent = root; }
                }
            }
        } else if self.init_pid == Some(exited_pid) {
            // The root supervisor died. No ordinary user task can adopt the
            // descendants. Prevent indefinitely runnable unattended services.
            self.init_pid = None;
            for task in self.tasks.iter_mut().flatten() {
                let Some(process) = task.process.as_mut() else { continue; };
                if process.pid == exited_pid || process.status.is_some() { continue; }
                process.files.close_all(frames);
                process.status = Some(137);
                process.parent = 0;
                task.runnable = false;
                task.waiting = None;
                task.timed = None;
            }
        }
    }

    /// Enumerate only caller-owned children, in PID order. This is useful
    /// when a child was created by another process and adopted by init.
    /// The PID cursor avoids returning an unrelated task or private identity.
    pub fn child_after(&self, parent: usize, cursor: usize) -> Result<usize, isize> {
        self.tasks.iter().flatten().filter_map(|task| task.process.as_ref())
            .filter(|process| process.parent == parent && process.pid > cursor)
            .map(|process| process.pid).min().ok_or(-10)
    }

    pub fn terminate(&mut self, status: usize, frames: &mut Frames<'_>) {
        let task = self.tasks[self.current.unwrap()].as_mut().unwrap();
        let process = task.process.as_mut().unwrap();
        process.files.close_all(frames);
        let pid = process.pid;
        process.status = Some(status);
        task.runnable = false;
        self.orphan_children(frames, pid);
        self.wake_child(pid);
        self.wake_io();
    }

    /// Terminate a direct child without switching to its address space.
    /// A stopped child remains a zombie until its parent collects the status.
    /// Only the owner CPU may call this with interrupts masked.
    pub fn kill_child(&mut self, frames: &mut Frames<'_>, parent: usize, pid: usize)
        -> Result<usize, isize>
    {
        if pid == 0 || pid == parent { return Err(-22); }
        let mut found = false;
        let mut already_exited = false;
        for task in self.tasks.iter_mut().flatten() {
            let Some(process) = task.process.as_mut() else { continue; };
            if process.pid != pid { continue; }
            if process.parent != parent { return Err(-1); }
            if process.status.is_none() {
                process.files.close_all(frames);
                process.status = Some(137); // forced termination, SIGKILL convention
                task.runnable = false;
                task.waiting = None;
                task.timed = None;
            } else {
                already_exited = true;
            }
            found = true;
            break;
        }
        if !found { return Err(-3); }
        if !already_exited { self.orphan_children(frames, pid); }
        self.wake_child(pid);
        // A closed channel or pipe can unblock other tasks on this CPU.
        self.wake_io();
        Ok(usize::from(already_exited))
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
            task.stack.release(frames);
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
        self.active = self.tasks.iter().flatten().any(|t| t.waiting.is_some() || t.timed.is_some());
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
        self.init_pid = None;
        self.boot_parked = None;
    }
}

#[cfg(test)]
mod timed_tests {
    use super::*;

    fn task(pid: usize, parent: usize) -> Task {
        Task {
            stack: KernelStack::test_dummy(), context: pid * 4096,
            runnable: true, waiting: None, timed: None,
            clock_error: false,
            preemptions: 0,
            process: Some(Process {
                pid, parent, status: None,
                credentials: crate::process::Credentials::BOOT_USER,
                entry: 0, space: crate::paging::UserSpace::test_dummy(),
                files: crate::files::Descriptors::test_dummy(),
            }),
        }
    }

    fn queue() -> Queue {
        let mut q = Queue::new();
        q.tasks[0] = Some(task(1, 0));
        q.tasks[1] = Some(task(2, 1));
        q.count = 2;
        q.active = true;
        q.current = Some(0);
        q.caller = 10; // context of the kernel HLT/schedule loop
        q.init_pid = Some(1);
        q
    }

    #[test]
    fn timerKeepsAllBlockedParentRunnableAfterDeadline() {
        let mut q = queue();
        q.tasks[1].as_mut().unwrap().runnable = false;
        q.block_sleep(125, 100);
        assert_eq!(q.select(10, false), 10); // back to kernel HLT caller
        assert!(q.active && q.has_timed_waiters() && !q.running());
        q.wake_timed(124, false);
        assert!(q.has_timed_waiters());
        q.wake_timed(125, false);
        assert!(!q.has_timed_waiters());
        assert_eq!(q.select(11, true), 10); // parent's saved syscall context
        assert!(!q.take_clock_error());
    }

    #[test]
    fn childExitWakesParentBeforeDeadlineWithoutPolling() {
        let mut q = queue();
        q.block_child(2, 900, 100);
        assert_eq!(q.select(99, false), 8192); // child runs
        assert!(q.has_timed_waiters());
        // User-mode child exits; queue notifies parent while holding IF=0.
        let mut frames = crate::frames::Frames::test_dummy();
        q.terminate(42, &mut frames);
        assert!(!q.has_timed_waiters());
        assert!(q.tasks[0].as_ref().unwrap().runnable);
        assert_eq!(q.select(0, false), 99);
        assert!(!q.take_clock_error());
    }

    #[test]
    fn elapsedTimeIsNotConfusedWithStalledClock() {
        let mut q = queue();
        q.tasks[1].as_mut().unwrap().runnable = false;
        q.block_sleep(20_000, 0);
        q.select(1, false);
        for tick in 1..=1000 {
            q.wake_timed(tick, false);
        }
        assert!(q.has_timed_waiters());
        assert!(!q.tasks[0].as_ref().unwrap().clock_error);
    }

    #[test]
    fn permanentlyFrozenClockEventuallyReturnsErrorNotTimeout() {
        let mut q = queue();
        q.tasks[1].as_mut().unwrap().runnable = false;
        q.block_sleep(10_000, 100);
        q.select(1, false);
        let mut pTimer = crate::timer::Timer::new(1000);
        pTimer.reset(Some(100));
        for pSecond in 1..=5 {
            assert_eq!(pTimer.plan(false, q.next_deadline(), 100), crate::timer::Action::Arm(100_000));
            q.wake_timed(100, pTimer.sample(0, Some(100)));
            assert_eq!(q.has_timed_waiters(), pSecond < 5);
        }
        assert!(!q.has_timed_waiters());
        assert_eq!(q.select(1, true), 1);
        assert!(q.take_clock_error());
        assert!(!q.take_clock_error()); // consumed exactly once
    }

    #[test]
    fn childWaitAlsoWakesAtDeadlineWithoutCollecting() {
        let mut q = queue();
        q.block_child(2, 200, 100);
        q.select(99, false);
        q.wake_timed(200, false);
        assert!(!q.has_timed_waiters());
        assert!(q.tasks[1].as_ref().unwrap().process.as_ref().unwrap().status.is_none());
        assert!(q.tasks[0].as_ref().unwrap().runnable);
    }

    #[test]
    fn killChildRejectsUnownedTargetAndWakesParentWait() {
        let mut q = queue();
        let mut frames = crate::frames::Frames::test_dummy();
        assert_eq!(q.kill_child(&mut frames, 3, 2), Err(-1));
        assert_eq!(q.kill_child(&mut frames, 1, 1), Err(-22));
        assert_eq!(q.kill_child(&mut frames, 1, 999), Err(-3));
        q.block_child(2, 700, 100);
        assert_eq!(q.select(99, false), 8192);
        assert_eq!(q.kill_child(&mut frames, 1, 2), Ok(0));
        assert!(q.tasks[0].as_ref().unwrap().runnable);
        assert_eq!(q.kill_child(&mut frames, 1, 2), Ok(1));
        assert_eq!(q.tasks[1].as_ref().unwrap().process.as_ref().unwrap().status, Some(137));
    }

    #[test]
    fn bootRootParksAndResumesWithIdenticalPidAndContext() {
        let mut q=queue();
        q.tasks[1]=None;
        q.count=1;
        assert_eq!(q.park_boot_root(1),Ok(()));
        assert_eq!(q.select(0x222, false),10); // back to the kernel caller
        assert_eq!(q.parked_root(),Some(1));
        assert_eq!(q.resume_boot_root(999),Err(-16));
        assert_eq!(q.resume_boot_root(1),Ok(()));
        assert_eq!(q.resume_boot_root(1),Err(-16)); // one-shot
        q.active=true;
        assert_eq!(q.select(0x333,false),0x222); // original saved context
        assert_eq!(q.process().unwrap().pid,1);
        assert_eq!(q.park_boot_root(1),Err(-16)); // actual one-shot, after rescheduling
    }

    #[test]
    fn eventWaitWakesOnAnyDirectChildExitWithoutTimeoutPolling() {
        let mut q=queue();
        q.block_events(0, 900, 100);
        assert_eq!(q.select(77,false),8192);
        let mut frames=crate::frames::Frames::test_dummy();
        q.terminate(42,&mut frames);
        assert!(!q.has_timed_waiters());
        assert!(q.tasks[0].as_ref().unwrap().runnable);
        assert!(q.has_exited_child(1));
        assert!(!q.has_exited_child(2));
        assert_eq!(q.select(0,false),77);
    }

    #[test]
    fn eventWaitDeadlineDoesNotReapOrFabricateChildExit() {
        let mut q=queue();
        q.tasks[1].as_mut().unwrap().runnable=false;
        q.block_events(0,220,100);
        q.select(0x456,false);
        q.wake_timed(219,false);
        assert!(q.has_timed_waiters());
        q.wake_timed(220,false);
        assert!(!q.has_timed_waiters());
        assert!(!q.has_exited_child(1));
        assert!(q.tasks[1].as_ref().unwrap().process.as_ref().unwrap().status.is_none());
    }

    #[test]
    fn nearestDeadlineTracksIndependentSleepAndEventWaiters() {
        let mut q=queue();
        q.block_sleep(900,100);
        q.select(77,false);
        q.block_events(0,250,100);
        assert_eq!(q.next_deadline(),Some(250));
        q.select(88,false);
        assert!(!q.running());
        q.wake_timed(249,false);
        assert_eq!(q.next_deadline(),Some(250));
        q.wake_timed(250,false);
        assert_eq!(q.next_deadline(),Some(900));
        assert_eq!(q.select(99,true),88);
        q.wake_timed(900,false);
        assert_eq!(q.next_deadline(),None);
    }

    #[test]
    fn unavailableClockReturnsErrorEvenIfAnUntrustedTimeLooksExpired() {
        let mut q=queue();
        q.tasks[1].as_mut().unwrap().runnable=false;
        q.block_events(0,200,100);
        q.select(77,false);
        q.wake_timed(999,true);
        assert_eq!(q.next_deadline(),None);
        assert_eq!(q.select(88,false),77);
        assert!(q.take_clock_error());
        assert!(!q.has_exited_child(1));
    }

    #[test]
    fn realChildCompletionDoesNotBecomeClockFailure() {
        let mut q=queue();
        q.block_child(2,900,100);
        q.select(77,false);
        q.tasks[1].as_mut().unwrap().process.as_mut().unwrap().status=Some(42);
        q.tasks[1].as_mut().unwrap().runnable=false;
        q.wake_timed(100,true);
        assert_eq!(q.select(88,false),77);
        assert!(!q.take_clock_error());
        assert!(q.has_exited_child(1));
    }

    fn nested_queue() -> Queue {
        let mut q = queue();
        q.tasks[2] = Some(task(3, 1));
        q.tasks[3] = Some(task(4, 3));
        q.count = 4;
        q
    }

    #[test]
    fn exitingIntermediateParentAdoptsLiveChildToCpuLocalInit() {
        let mut q = nested_queue();
        let mut frames = crate::frames::Frames::test_dummy();
        q.current = Some(2);
        q.terminate(0, &mut frames);
        assert_eq!(q.tasks[3].as_ref().unwrap().process.as_ref().unwrap().parent, 1);
        assert!(q.tasks[3].as_ref().unwrap().runnable);
        assert_eq!(q.child_after(1, 2), Ok(3));
        assert_eq!(q.child_after(1, 3), Ok(4));
        assert_eq!(q.child_after(1, 4), Err(-10));
        assert_eq!(q.collect(&mut frames, 3, 4), Err(-10));
        assert_eq!(q.kill_child(&mut frames, 3, 4), Err(-1));
        assert_eq!(q.kill_child(&mut frames, 1, 4), Ok(0));
        assert_eq!(q.collect(&mut frames, 1, 4), Ok(137));
        assert_eq!(q.collect(&mut frames, 1, 3), Ok(0));
        assert_eq!(q.child_after(1, 0), Ok(2));
    }

    #[test]
    fn exitingIntermediateParentAdoptsAlreadyZombieChild() {
        let mut q = nested_queue();
        let mut frames = crate::frames::Frames::test_dummy();
        q.tasks[3].as_mut().unwrap().process.as_mut().unwrap().status = Some(19);
        q.tasks[3].as_mut().unwrap().runnable = false;
        q.current = Some(2);
        q.terminate(0, &mut frames);
        assert_eq!(q.child_after(1, 3), Ok(4));
        assert_eq!(q.kill_child(&mut frames, 1, 4), Ok(1));
        assert_eq!(q.collect(&mut frames, 1, 4), Ok(19));
        assert_eq!(q.collect(&mut frames, 1, 3), Ok(0));
    }

    #[test]
    fn killingIntermediateParentAlsoAdoptsLiveGrandchild() {
        let mut q = nested_queue();
        let mut frames = crate::frames::Frames::test_dummy();
        assert_eq!(q.kill_child(&mut frames, 1, 3), Ok(0));
        assert_eq!(q.tasks[3].as_ref().unwrap().process.as_ref().unwrap().parent, 1);
        assert_eq!(q.kill_child(&mut frames, 1, 4), Ok(0));
        assert_eq!(q.collect(&mut frames, 1, 3), Ok(137));
        assert_eq!(q.collect(&mut frames, 1, 4), Ok(137));
    }

    #[test]
    fn rootExitStopsAllLiveDescendantsWithoutLeakingRunnableServices() {
        let mut q = nested_queue();
        let mut frames = crate::frames::Frames::test_dummy();
        q.current = Some(0);
        q.terminate(7, &mut frames);
        assert_eq!(q.init_pid, None);
        for i in 1..4 {
            let t=q.tasks[i].as_ref().unwrap();
            assert_eq!(t.process.as_ref().unwrap().status, Some(137));
            assert!(!t.runnable && t.waiting.is_none() && t.timed.is_none());
        }
        assert_eq!(q.tasks[0].as_ref().unwrap().process.as_ref().unwrap().status, Some(7));
        assert_eq!(q.select(42, false), 10); // return to kernel caller
        assert!(!q.active);
    }

    #[test]
    fn adoptedChildEnumerationIsSortedAndOwnerScoped() {
        let mut q=nested_queue();
        let mut frames=crate::frames::Frames::test_dummy();
        assert_eq!(q.child_after(1, 0), Ok(2));
        assert_eq!(q.child_after(1, 2), Ok(3));
        assert_eq!(q.child_after(1, 3), Err(-10)); // grandchild still hidden
        assert_eq!(q.child_after(2, 0), Err(-10));
        q.current=Some(2);
        q.terminate(0, &mut frames);
        assert_eq!(q.child_after(1, 3), Ok(4)); // adopted by root
        assert_eq!(q.child_after(3, 0), Err(-10));
        assert_eq!(q.child_after(1, usize::MAX), Err(-10));
    }
}
