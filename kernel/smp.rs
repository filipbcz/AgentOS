#![allow(non_snake_case, non_upper_case_globals)]
use crate::{acpi::Platform, exceptions::{hex, Descriptors}, frames::{Exhaustion, Frames, SharedFrames},
            halt, out, process::Programs, scheduler::{Context, Queue}, serial, stress::{self, Load}};
use crate::{bringup_clock::BringupClock, reference_clock::{ReferenceClock, WaitError}};
use core::{arch::{asm, x86_64::__cpuid}, cell::UnsafeCell, hint::spin_loop, ptr,
           sync::atomic::{fence, AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering}};

extern "C" {
    static ap_start: u8;
    static ap_end: u8;
    static ap_pm: u8;
    static ap_long: u8;
    static ap_gdt: u8;
    static after_hlt: u8;
    fn wait_for_irq();
    fn idle_wait(stamps: *mut u64);
}

type Error = &'static [u8];
const PAGE: usize = 4096;
const TIMER: u32 = 0xe0;
const MASK: u32 = 1 << 16;
const WAKEUPS: u32 = 3;
const OOM_PHASE: u32 = 1;
const PROCESS_PHASE: u32 = 2;
const IDLE_PHASE: u32 = 3;
const OOM_CHECKED: u32 = 4;
const IDLE_FINISHED: u32 = 5;
const PROCESSES_FINISHED: u32 = 6;
const RUNTIME_PHASE: u32 = 4;
const RESCHEDULE: u32 = 0xe3;
const EMPTY_CPU: AtomicUsize = AtomicUsize::new(0);
static gCpus: [AtomicUsize; 255] = [EMPTY_CPU; 255];
static gOnlineCount: AtomicUsize = AtomicUsize::new(0);
static gBspQualifiedTscHz: AtomicU64 = AtomicU64::new(0);
static gRuntimeEnabled: AtomicBool = AtomicBool::new(false);
static gTerminal: AtomicUsize = AtomicUsize::new(0);
static gMigrations: AtomicUsize = AtomicUsize::new(0);
static gRemoteWakeups: AtomicUsize = AtomicUsize::new(0);

// All runqueue entries, including selection and the retiring-stack hazard,
// are protected by their own CPU gate. IRQs must already be masked. A transfer
// takes two gates in APIC-ID order; no frame/TTY lock may precede a queue gate.
struct QueueGuard<'a> { fCpu: &'a Cpu }
impl core::ops::Deref for QueueGuard<'_> {
    type Target = Queue;
    fn deref(&self) -> &Queue { unsafe { &*self.fCpu.queue.get() } }
}
impl core::ops::DerefMut for QueueGuard<'_> {
    fn deref_mut(&mut self) -> &mut Queue { unsafe { &mut *self.fCpu.queue.get() } }
}
impl Drop for QueueGuard<'_> {
    fn drop(&mut self) {
        self.fCpu.fRunnable.store(self.runnableCount(), Ordering::Release);
        self.fCpu.fHasSlot.store(self.hasFreeSlot(), Ordering::Release);
        self.fCpu.fQueueLocked.store(false, Ordering::Release);
    }
}

// Runtime diagnostics are published as complete lines, serialized by the
// shared terminal (or the early UART gate), never as interleaved fragments.
struct Diagnostic { fBytes: [u8; 320], fLength: usize }
impl Diagnostic {
    fn new(aPrefix: &[u8]) -> Self {
        let mut pLine = Self { fBytes: [0; 320], fLength: 0 };
        pLine.text(aPrefix); pLine
    }
    fn text(&mut self, aBytes: &[u8]) {
        self.fBytes[self.fLength..self.fLength + aBytes.len()].copy_from_slice(aBytes);
        self.fLength += aBytes.len();
    }
    fn field(&mut self, aName: &[u8], aValue: u64) {
        self.text(aName);
        for pShift in (0..16).rev() {
            self.fBytes[self.fLength] = b"0123456789abcdef"[((aValue >> (pShift * 4)) & 15) as usize];
            self.fLength += 1;
        }
    }
    unsafe fn publish(mut self, aCpu: &Cpu) {
        self.text(b"\r\n"); aCpu.output(&self.fBytes[..self.fLength]);
    }
}

/// Report a completed, rejected independent qualification. The PIT owner
/// has been released, and its gate/speaker cleanup has already been checked.
/// Mandatory failures retain the native fatal serial diagnostic path; optional
/// source failures are recorded in the normal kernel history only.
unsafe fn pit_diagnostic(cpu:u8,mandatory:bool,level:crate::log_policy::Level,line:&[u8]) {
    let _=crate::logger::LOGGER.record(0,cpu as u32,level,line);
    if mandatory {
        let mut record=Diagnostic::new(line);
        record.text(b"\r\n");
        serial(&record.fBytes[..record.fLength]);
    }
}
unsafe fn report_pit_failure(cpu: u8, phase: &str, mandatory: bool, fault: crate::pit::QualificationFailure) {
    fault.report(cpu,phase,|line|pit_diagnostic(cpu,mandatory,crate::log_policy::Level::Error,line));
}
unsafe fn report_pit_discarded(cpu:u8,phase:&str,mandatory:bool,discarded:&crate::pit::DiscardedWindows) {
    discarded.report(cpu,phase,|line|pit_diagnostic(cpu,mandatory,crate::log_policy::Level::Info,line));
}

unsafe fn registeredCpus() -> impl Iterator<Item = &'static Cpu> {
    gCpus.iter().filter_map(|pSlot| {
        let pAddress = pSlot.load(Ordering::Acquire);
        (pAddress != 0).then(|| &*(pAddress as *const Cpu))
    })
}

unsafe fn notifyRemote() {
    if !gRuntimeEnabled.load(Ordering::Acquire) { return; }
    let pCurrent = current_cpu();
    for pCpu in registeredCpus() {
        if pCpu.expected_id != pCurrent.expected_id && pCpu.fRuntimeReady.load(Ordering::Acquire) {
            pCurrent.requestReschedule(pCpu);
        }
    }
}

unsafe fn timerSnapshot() -> (u64, u64) {
    let mut pTotal = 0u64; let mut pIdle = 0u64;
    for pCpu in registeredCpus() {
        let (pTimers, pIdles) = loop {
            let pBefore = pCpu.fTimerSequence.load(Ordering::Acquire);
            if pBefore & 1 != 0 { spin_loop(); continue; }
            let pTimers = pCpu.runtime_timer_irqs.load(Ordering::Relaxed);
            let pIdles = pCpu.runtime_idle_irqs.load(Ordering::Relaxed);
            fence(Ordering::Acquire);
            if pBefore == pCpu.fTimerSequence.load(Ordering::Relaxed) { break (pTimers, pIdles); }
        };
        pTotal += pTimers as u64; pIdle += pIdles as u64;
    }
    (pTotal, pIdle)
}

// Event-driven load balancing. Require a difference of at least two runnable
// tasks; only already executed, saved user contexts can be moved. Publishing
// the whole Task under the ordered pair of queue gates makes ownership atomic.
unsafe fn balanceQueues() {
    if !gRuntimeEnabled.load(Ordering::Acquire) || gOnlineCount.load(Ordering::Acquire) < 2 { return; }
    let pTarget = registeredCpus().filter(|pCpu| pCpu.fRuntimeReady.load(Ordering::Acquire) &&
        pCpu.fHasSlot.load(Ordering::Acquire))
        .min_by_key(|pCpu| pCpu.fRunnable.load(Ordering::Acquire));
    let pSource = registeredCpus().filter(|pCpu| pCpu.fRuntimeReady.load(Ordering::Acquire))
        .max_by_key(|pCpu| pCpu.fRunnable.load(Ordering::Acquire));
    let (Some(pSource), Some(pTarget)) = (pSource, pTarget) else { return; };
    if pSource.expected_id == pTarget.expected_id ||
        pSource.fRunnable.load(Ordering::Acquire) < pTarget.fRunnable.load(Ordering::Acquire) + 2 { return; }
    let (pFirst, pSecond) = if pSource.expected_id < pTarget.expected_id { (pSource, pTarget) } else { (pTarget, pSource) };
    let Some(mut pFirstGuard) = pFirst.tryQueue() else { return; };
    let Some(mut pSecondGuard) = pSecond.tryQueue() else { return; };
    let (pSourceQueue, pTargetQueue) = if pSource.expected_id < pTarget.expected_id {
        (&mut *pFirstGuard, &mut *pSecondGuard)
    } else { (&mut *pSecondGuard, &mut *pFirstGuard) };
    let pMoved = if pSourceQueue.runnableCount() >= pTargetQueue.runnableCount() + 2 {
        pSourceQueue.moveRunnableTo(pTargetQueue).is_ok()
    } else { false };
    // Publish the ownership-generation count before either queue is released.
    // A task that runs (or is reaped) on its new owner must not expose that
    // transfer while sched_stats still reports the preceding global count.
    if pMoved { gMigrations.fetch_add(1, Ordering::Relaxed); }
    drop(pSecondGuard); drop(pFirstGuard);
    if pMoved {
        let pCpu = current_cpu();
        // Include self: this callback may have just returned to an idle
        // kernel caller with its timer disabled before accepting this task.
        pCpu.requestReschedule(pTarget);
        // The source's next quantum/deadline was computed before the move.
        if pSource.expected_id != pCpu.expected_id { pCpu.requestReschedule(pSource); }
    }
}


unsafe fn timestamp() -> u64 { crate::tsc::read() }

#[derive(Default)]
struct IdleSample { wakes: u64, timers: u32, elapsed: u64, active: u64 }

#[derive(Clone, Copy)]
struct Lapic(usize);
impl Lapic {
    unsafe fn read(self, offset: usize) -> u32 { ptr::read_volatile((self.0 + offset) as *const u32) }
    unsafe fn write(self, offset: usize, value: u32) { ptr::write_volatile((self.0 + offset) as *mut u32, value); }
    unsafe fn id(self) -> u8 { (self.read(0x20) >> 24) as u8 }

    unsafe fn enable(self) -> Result<(), Error> {
        if __cpuid(1).edx & (1 << 9) == 0 { return Err(b"missing APIC"); }
        let (lo, hi): (u32, u32);
        asm!("rdmsr", in("ecx") 0x1bu32, out("eax") lo, out("edx") hi);
        if lo & 0xc00 != 0x800 || ((hi as usize) << 32 | (lo as usize & 0xfffff000)) != self.0 {
            return Err(b"xAPIC base or mode");
        }
        self.write(0x80, 0);             // task priority
        self.write(0x350, MASK);          // LINT0 (firmware ExtINT)
        self.write(0x360, MASK);          // LINT1
        self.write(0x320, MASK | TIMER);
        self.write(0x380, 0);             // disarm inherited timer
        self.write(0xf0, 0x100 | 0xff);   // software enable, spurious vector
        self.write(0x3e0, 3);             // divide timer clock by 16
        Ok(())
    }

    unsafe fn calibrate(self, clock: &BringupClock) -> Result<(u32, u64), Error> {
        // VirtualBox Minimal advertises TSC and undivided APIC kHz. Use the
        // guest clocks' nominal rates rather than assuming a short PM-timer
        // calibration remains representative during virtual-clock catch-up.
        if clock.tsc_hz().is_none() && __cpuid(1).ecx & (1 << 31) != 0 && __cpuid(0x40000000).eax >= 0x40000010 {
            let rates = __cpuid(0x40000010);
            let quantum = (rates.ebx as u64 * 1000 / (16 * 100)) as u32;
            if rates.eax != 0 && quantum != 0 { return Ok((quantum, rates.eax as u64 * 1000)); }
        }
        self.write(0x380, u32::MAX);
        let tsc_start = timestamp();
        let delayed = clock.delay_ns(100_000_000);
        let tsc_delta = timestamp().checked_sub(tsc_start);
        let counted = u32::MAX - self.read(0x390);
        // Never leave the calibration timer armed on a failed reference.
        self.write(0x380, 0);
        let elapsed = delayed.map_err(|_| b"timer calibration reference stopped" as Error)?;
        if elapsed < 100_000_000 { return Err(b"timer calibration interval"); }
        let tsc_delta = tsc_delta.ok_or(b"TSC regression" as Error)?;
        if counted == 0 || counted == u32::MAX { return Err(b"timer calibration"); }
        let per_10ms = u32::try_from(counted as u128 * 10_000_000 / elapsed as u128)
            .map_err(|_| b"LAPIC calibration overflow" as Error)?;
        let tsc_hz = u64::try_from(tsc_delta as u128 * 1_000_000_000 / elapsed as u128)
            .map_err(|_| b"TSC calibration overflow" as Error)?;
        if per_10ms == 0 || tsc_hz == 0 { return Err(b"zero timer interval"); }
        Ok((per_10ms, clock.tsc_hz().unwrap_or(tsc_hz)))
    }

    unsafe fn send_runtime(self, id: u8, command: u32) -> Result<(), Error> {
        let start = crate::system_clock::millis();
        self.write(0x310, (id as u32) << 24);
        self.write(0x300, command);
        // An already completed delivery does not depend on clock health.
        // Bound a genuinely pending delivery even if all clocks stop.
        for _ in 0..100_000_000u32 {
            if self.read(0x300) & (1 << 12) == 0 { return Ok(()); }
            let (Some(before), Some(now)) = (start, crate::system_clock::millis()) else {
                return Err(b"IPI system clock unavailable");
            };
            if now.saturating_sub(before) >= 1000 { return Err(b"IPI delivery timeout"); }
            spin_loop();
        }
        Err(b"IPI delivery polling limit")
    }

    unsafe fn send(self, id: u8, command: u32, clock: &BringupClock) -> Result<(), Error> {
        self.write(0x310, (id as u32) << 24);
        self.write(0x300, command);
        clock.wait_until(1_000_000_000, || self.read(0x300) & (1 << 12) == 0)
            .map_err(|error| match error {
                WaitError::Timeout => b"IPI delivery timeout" as Error,
                WaitError::Unresponsive => b"IPI reference clock stopped" as Error,
            })
    }
}

#[repr(C)]
struct Cpu {
    self_address: usize,     // GS:0 on this processor
    syscall_user_rsp: UnsafeCell<usize>, // GS:8, scratch with IRQs masked
    syscall_stack: UnsafeCell<usize>,    // GS:16, current thread's privilege stack
    rsp0: usize,
    programs: &'static Programs,
    apic: Lapic,
    expected_id: u8,
    interval: u32,
    tsc_hz: u64,
    reference: BringupClock,
    legacy_pit_probe: bool,
    tsc: crate::tsc::Peer,
    tsc_watchdog: UnsafeCell<crate::tsc_watchdog::Watchdog>,
    timer_policy: UnsafeCell<crate::timer::Timer>,
    runtime_timer_irqs: AtomicUsize,
    fTimerSequence: AtomicUsize,
    fQueueLocked: AtomicBool,
    fRuntimeReady: AtomicBool,
    fWakePending: AtomicBool,
    fRunnable: AtomicUsize,
    fHasSlot: AtomicBool,
    runtime_idle_irqs: AtomicUsize,
    interrupts: AtomicU32,
    hlt_wakes: AtomicU32,
    complete: AtomicU32,
    phase: AtomicU32,
    idle: UnsafeCell<IdleSample>,
    descriptors: Option<Descriptors>,
    queue: UnsafeCell<Queue>,
    boot_baseline: UnsafeCell<Option<crate::frames::BitmapSnapshot>>,
    terminal: UnsafeCell<*mut crate::tty::Terminal>,
    load: &'static Load,
    released: [AtomicUsize; stress::TASKS],
}

// Queue state is protected by its per-CPU gate with local IRQs disabled.
// Boot-only raw accesses occur before runtime publication or after an explicit
// completion barrier. Shared resources additionally require the Frames gate.
unsafe impl Sync for Cpu {}
const _: () = assert!(core::mem::size_of::<Cpu>() <= PAGE && core::mem::size_of::<Load>() <= PAGE);

impl Cpu {
    fn lockQueue(&self) -> QueueGuard<'_> {
        loop { if let Some(pGuard) = self.tryQueue() { return pGuard; } spin_loop(); }
    }
    fn tryQueue(&self) -> Option<QueueGuard<'_>> {
        self.fQueueLocked.compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .ok().map(|_| QueueGuard { fCpu: self })
    }
    unsafe fn requestReschedule(&self, aTarget: &Cpu) {
        if aTarget.fWakePending.swap(true, Ordering::AcqRel) { return; }
        // Runtime IPI waits follow the same resilient absolute clock as
        // all other deadlines. Never retry the ICR command after timeout.
        let delivery = if gRuntimeEnabled.load(Ordering::Acquire) {
            self.apic.send_runtime(aTarget.expected_id, RESCHEDULE)
        } else { self.local_reference().ok_or(b"unqualified local TSC" as Error)
            .and_then(|clock| self.apic.send(aTarget.expected_id, RESCHEDULE, &clock)) };
        if delivery.is_err() {
            serial(b"SMP FAILED: reschedule IPI delivery\r\n"); halt();
        }
        if aTarget.expected_id != self.expected_id { gRemoteWakeups.fetch_add(1, Ordering::Relaxed); }
    }
    unsafe fn create(frames: &mut Frames<'_>, apic: Lapic, id: u8, interval: u32, tsc_hz: u64,
                     reference: BringupClock, legacy_pit_probe: bool,
                     descriptors: Option<Descriptors>, load: &'static Load, programs: &'static Programs,
                     rsp0: usize) -> Result<&'static Self, Error> {
        let addr = frames.alloc().ok_or(b"CPU allocation" as Error)?.into_address();
        let cpu = addr as *mut Self;
        cpu.write(Self { self_address: addr, syscall_user_rsp: UnsafeCell::new(0), syscall_stack: UnsafeCell::new(0),
                         rsp0, programs, apic, expected_id: id, interval, tsc_hz, reference, legacy_pit_probe,
                         tsc: crate::tsc::Peer::new(),
                         tsc_watchdog: UnsafeCell::new(crate::tsc_watchdog::Watchdog::new()),
                         timer_policy: UnsafeCell::new(crate::timer::Timer::new(interval,
                             if descriptors.is_none() { crate::system_clock::maintenance_ms() } else { None })),
                         runtime_timer_irqs: AtomicUsize::new(0), fTimerSequence: AtomicUsize::new(0),
                         fQueueLocked: AtomicBool::new(false), fRuntimeReady: AtomicBool::new(false),
                         fWakePending: AtomicBool::new(false), fRunnable: AtomicUsize::new(0),
                         fHasSlot: AtomicBool::new(true), runtime_idle_irqs: AtomicUsize::new(0),
                         interrupts: AtomicU32::new(0), hlt_wakes: AtomicU32::new(0),
                         complete: AtomicU32::new(0), phase: AtomicU32::new(0), terminal: UnsafeCell::new(ptr::null_mut()),
                         idle: UnsafeCell::new(IdleSample::default()), descriptors, load, queue: UnsafeCell::new(Queue::new()), boot_baseline: UnsafeCell::new(None),
                         released: core::array::from_fn(|_| AtomicUsize::new(0)) });
        for i in 0..stress::TASKS {
            (*(*cpu).queue.get()).spawn(frames, allocation_task, i).ok_or(b"task stack" as Error)?;
        }
        Ok(&*cpu)
    }

    /// The PIT provides an independent finite interval when a direct
    /// ACPI calibration reference has become unresponsive. A reference
    /// that actually measured inconsistent rates must not be bypassed.
    unsafe fn qualify_tsc(&self, phase: &str) -> Option<crate::tsc::QualifiedRate> {
        let mut maintain = || { let _ = crate::system_clock::millis(); };
        let mandatory=self.reference.tsc_hz().is_some();
        if let BringupClock::Physical(reference)=self.reference {
            match crate::tsc::qualify_reference(reference, &mut maintain) {
                Ok(hz)=>return Some(hz),
                Err(crate::tsc::QualificationError::ReferenceUnavailable)=>{},
                Err(_)=>return None,
            }
        }
        let mut discarded=crate::pit::DiscardedWindows::new();
        let result=crate::pit::qualify(self.legacy_pit_probe,&mut maintain,&mut discarded);
        report_pit_discarded(self.expected_id,phase,mandatory,&discarded);
        match result {
            Ok(rate)=>Some(rate),
            Err(fault)=>{
                report_pit_failure(self.expected_id,phase,mandatory,fault);
                None
            }
        }
    }

    fn local_reference(&self) -> Option<BringupClock> {
        match self.reference {
            BringupClock::Physical(_) => Some(self.reference),
            BringupClock::LocalTsc { .. } =>
                Some(BringupClock::LocalTsc { hz: self.tsc.rate()? }),
        }
    }

    /// Install CPU-local kernel identity and the native syscall transport
    /// before this processor is declared initialized. Neither a userspace
    /// test program nor a scheduler/idle acceptance phase owns these MSRs.
    unsafe fn initialize_local_cpu(&self) -> Result<(), Error> {
        if self.apic.id() != self.expected_id { return Err(b"wrong executing APIC ID"); }
        asm!("wrmsr", in("ecx") 0xc0000101u32, in("eax") self.self_address as u32,
             in("edx") (self.self_address >> 32) as u32);
        unsafe fn msr(index: u32, value: u64) {
            asm!("wrmsr", in("ecx") index, in("eax") value as u32, in("edx") (value >> 32) as u32);
        }
        extern "C" { fn native_syscall(); }
        // User threads currently own x87/SSE context and flat FS/GS selectors.
        let cr4: usize;
        asm!("mov {}, cr4", out(reg) cr4);
        asm!("mov cr4, {}", in(reg) (cr4 & !((1<<16) | (1<<18) | (1<<8))));
        msr(0xc0000100, 0);
        msr(0xc0000102, 0);
        if __cpuid(1).edx & (1 << 11) != 0 { msr(0x174, 0); } // disable legacy SYSENTER
        msr(0xc0000081, (8u64 << 32) | (0x20u64 << 48));
        msr(0xc0000082, native_syscall as usize as u64);
        msr(0xc0000084, 0xffff_ffff);
        asm!("rdmsr", "or eax, 1", "wrmsr", in("ecx") 0xc0000080u32, out("eax") _, out("edx") _);
        Ok(())
    }

    unsafe fn run_task(&self) -> Result<(), Error> {
        let id = self.apic.id();
        self.apic.write(0x320, TIMER);    // one-shot, unmasked
        for wakeup in 1..=WAKEUPS {
            self.apic.write(0x380, self.interval);
            // IF is clear on both sides. STI's interrupt shadow covers HLT.
            loop {
                wait_for_irq();
                let seen = self.interrupts.load(Ordering::Acquire);
                if seen == wakeup { break; }
                if seen > wakeup { return Err(b"duplicate timer interrupt"); }
            }
        }
        self.apic.write(0x320, MASK | TIMER);
        let wakes = self.hlt_wakes.load(Ordering::Acquire);
        if wakes != WAKEUPS { return Err(b"timer did not interrupt HLT"); }
        serial(b"AGENTOS TASK ");
        if self.descriptors.is_some() { serial(b"AP"); } else { serial(b"BSP"); }
        serial(b" APIC="); hex(id as u64);
        serial(b" TIMER-WAKES="); hex(wakes as u64);
        serial(b"\r\n");
        crate::pci_irq::exercise(id,self.local_reference().ok_or(b"unqualified local TSC" as Error)?)
    }

    unsafe fn schedule(&self) {
        (*self.queue.get()).active = true;
        // The first quantum enters the run queue from the kernel caller.
        // Subsequent arms are one-shot: runnable quantum, earliest deadline,
        // or a sparse independent-clock watchdog when every task is asleep.
        self.apic.write(0x320, MASK | TIMER);
        self.apic.write(0x380, 0);
        let now = crate::system_clock::millis();
        (*self.timer_policy.get()).reset(now);
        self.arm_timer(true, None, now.unwrap_or(0));
        while ptr::addr_of!((*self.queue.get()).active).read_volatile() { wait_for_irq(); }
        self.apic.write(0x320, MASK | TIMER);
        self.apic.write(0x380, 0);
    }

    unsafe fn runtimeWorker(&self) -> ! {
        {
            let mut pQueue = self.lockQueue();
            pQueue.setRuntimeIdle(true);
        }
        self.apic.write(0x320, MASK | TIMER);
        self.apic.write(0x380, 0);
        self.fRuntimeReady.store(true, Ordering::Release);
        let now = self.runtime_clock();
        (*self.timer_policy.get()).reset(now);
        self.arm_timer(false, None, now.unwrap_or(0));
        // The first IRQ records this kernel caller context before selecting
        // incoming work. Idle queues need only a real maintenance deadline.
        loop { wait_for_irq(); }
    }

    unsafe fn runtimeSession(&self, aRootPid: usize) -> Result<usize, Error> {
        {
            let mut pQueue = self.lockQueue();
            pQueue.setRuntimeIdle(true);
        }
        self.fRuntimeReady.store(true, Ordering::Release);
        gRuntimeEnabled.store(true, Ordering::Release);
        let pNow = self.runtime_clock();
        (*self.timer_policy.get()).reset(pNow);
        self.arm_timer(true, None, pNow.unwrap_or(0));
        let mut pStatus = None;
        loop {
            let mut pChanged = false;
            if pStatus.is_none() {
                match self.load.frames.with(|pFrames| self.programs.fRegistry.collect(pFrames, 0, aRootPid)) {
                    Ok(pExit) => { pStatus = Some(pExit); pChanged = true; }
                    Err(-11) => (),
                    Err(_) => { serial(b"SMP FAILED: runtime root identity\r\n"); halt(); },
                }
            }
            // Executing here means no user task owns this CPU's active stack.
            // Local reaping must also progress on a single-CPU machine without
            // relying on a remote IPI to consume its final collected zombie.
            {
                let mut pQueue = self.lockQueue();
                self.load.frames.with(|pFrames| {
                    pChanged |= pQueue.processPendingKills(pFrames);
                    pChanged |= pQueue.collectRetired(pFrames) != 0;
                    pQueue.wake_io(pFrames);
                });
                let pNow = self.runtime_clock().unwrap_or(0);
                self.arm_timer(pQueue.runnableCount() != 0, pQueue.next_deadline(), pNow);
            }
            if pChanged { notifyRemote(); }
            if let Some(pExit) = pStatus {
                if self.load.frames.with(|pFrames| !self.programs.fRegistry.hasProcesses(pFrames)) {
                    let mut pQueue = self.lockQueue();
                    pQueue.setRuntimeIdle(false);
                    pQueue.active = false;
                    drop(pQueue);
                    self.apic.write(0x320, MASK | TIMER);
                    self.apic.write(0x380, 0);
                    self.fRuntimeReady.store(false, Ordering::Release);
                    gRuntimeEnabled.store(false, Ordering::Release);
                    return Ok(pExit);
                }
            }
            wait_for_irq();
        }
    }

    /// Use a single independent-clock sample for the scheduler and, when
    /// eligible, the local invariant-TSC watchdog. IRQs are masked by the
    /// scheduler/interrupt caller; the watchdog has exactly one CPU owner.
    unsafe fn runtime_clock(&self) -> Option<u64> {
        let now = self.runtime_clock_sample();
        // The timekeeper publishes events while holding its own gate.
        // Record them here after release, without a clock/log lock cycle.
        if let Some(event) = crate::system_clock::take_event() {
            let level = if event.error() { crate::log_policy::Level::Error }
                        else { crate::log_policy::Level::Info };
            let _ = crate::logger::LOGGER.record(crate::logger::ticks(),
                self.expected_id as u32, level, event.message());
        }
        now
    }

    unsafe fn runtime_clock_sample(&self) -> Option<u64> {
        use crate::tsc_watchdog::{Health, Sample, MONITOR};
        if !self.fRuntimeReady.load(Ordering::Acquire) || !MONITOR.active() {
            return crate::system_clock::millis();
        }
        let (Some(rate), Some(alignment)) = (self.tsc.rate(), self.tsc.alignment()) else {
            return crate::system_clock::millis();
        };
        let before = crate::tsc::read();
        let now = crate::system_clock::snapshot();
        let after = crate::tsc::read();
        // Holdover supplies real ABI time, but it is derived from TSC.
        // Feeding it back to the watchdog would falsely renew the lease
        // from the very counter it is supposed to qualify independently.
        if now.as_ref().map_or(false, |s| s.holdover) {
            return now.map(|s| s.millis);
        }
        let sample = now.as_ref().and_then(|s| s.independent_ns)
            .map(|reference_ns| Sample { reference_ns, before, after });
        let watchdog = &mut *self.tsc_watchdog.get();
        let previous = watchdog.health();
        let generation = now.as_ref().map(|s| s.reference_generation);
        let health = MONITOR.observe_at(generation, self.expected_id as u32,
                                        rate, alignment, watchdog, sample);
        if previous != health && health != Health::Pending {
            let level = if health == Health::Rejected { crate::log_policy::Level::Error }
                        else { crate::log_policy::Level::Info };
            let _ = crate::logger::LOGGER.record(after, self.expected_id as u32, level, health.message());
        }
        now.map(|s| s.millis)
    }

    unsafe fn arm_timer(&self, runnable: bool, deadline: Option<u64>, now: u64) {
        let base = if self.descriptors.is_none() { crate::system_clock::maintenance_ms() } else { None };
        let maintenance = if self.fRuntimeReady.load(Ordering::Acquire) && crate::tsc_watchdog::MONITOR.active() {
            Some(base.map_or(crate::tsc_watchdog::INTERVAL_MS, |ms| ms.min(crate::tsc_watchdog::INTERVAL_MS)))
        } else { base };
        let policy = &mut *self.timer_policy.get();
        policy.set_maintenance(maintenance);
        match policy.plan(runnable, deadline, now) {
            crate::timer::Action::Keep => (),
            crate::timer::Action::Disable => {
                self.apic.write(0x320, MASK | TIMER);
                self.apic.write(0x380, 0);
            }
            crate::timer::Action::Arm(counts) => {
                self.apic.write(0x320, TIMER); // one-shot, never periodic
                self.apic.write(0x380, counts);
            }
        }
    }

    unsafe fn switch(&self, outgoing: usize, timer: bool) -> usize {
        let mut pGuard = self.lockQueue();
        let queue = &mut *pGuard;
        let scheduled = queue.active;
        let measured = self.runtime_clock();
        let now = measured.unwrap_or(0);
        let mut pChanged = false;
        if scheduled {
            let clock_error = (*self.timer_policy.get()).sample(self.apic.read(0x390), measured);
            if clock_error { crate::system_clock::expire_stalled_holdover(); }
            self.load.frames.with(|pFrames| {
                pChanged |= queue.processPendingKills(pFrames);
                pChanged |= queue.collectRetired(pFrames) != 0;
                queue.wake_io(pFrames);
                queue.wake_timed(pFrames, now, clock_error);
            });
        }
        let next = queue.select(outgoing, timer);
        if scheduled { self.arm_timer(queue.running(), queue.next_deadline(), now); }
        let root = if let Some(p) = queue.process() {
            let top = queue.user_stack_top().unwrap();
            ptr::write_unaligned(self.rsp0 as *mut usize, top);
            self.syscall_stack.get().write(top);
            p.space.root
        } else { self.programs.kernel_root };
        drop(pGuard);
        if pChanged { notifyRemote(); }
        // PCID and PGE are disabled. Always flush, even for the same CR3:
        // shared kernel-stack virtual slots may have been reused by another
        // CPU while this CPU was running a different owner/context.
        asm!("mov cr3, {}", in(reg) root);
        next
    }

    unsafe fn output(&self, bytes: &[u8]) {
        let terminal = gTerminal.load(Ordering::Acquire) as *mut crate::tty::Terminal;
        if terminal.is_null() { serial(bytes); } else { (*terminal).diagnostic(bytes); }
    }

    unsafe fn hex(&self, value: u64) {
        let mut digits = [b'0'; 16];
        for (i, d) in digits.iter_mut().enumerate() { *d = b"0123456789abcdef"[((value >> (60 - i*4)) & 15) as usize]; }
        self.output(&digits);
    }

    #[allow(non_snake_case)]
    unsafe fn process_test(&self) -> Result<(), Error> {
        // BSP's first process is the actual numeric PID 1, retained through
        // the boot tests; AP tests still use independent finite sessions.
        let bsp_root = self.descriptors.is_none();
        let baseline = self.load.frames.with(|f| f.snapshot()).ok_or(b"process snapshot" as Error)?;
        let pid = self.load.frames.with(|f| (*self.queue.get()).spawn_process(f, self.programs, b"init", 0, 0))
            .map_err(|_| b"user init ELF" as Error)?;
        let resident = if bsp_root {
            Some(self.load.frames.with(|f| f.snapshot()).ok_or(b"PID1 test snapshot" as Error)?)
        } else { None };
        self.schedule();
        let ok = self.load.frames.with(|f| {
            let q = &mut *self.queue.get();
            if let Some(mut resident) = resident {
                let valid = pid == 1 && q.parked_root() == Some(pid) &&
                    q.child_after(f, pid, 0) == Err(-10) &&
                    // Lazy spawn had no private user tables/data yet. Account
                    // only the exact frames now reachable from the retained
                    // PID1 space; every unrelated allocation/free still fails.
                    q.parkedSpace().map_or(false, |pSpace| pSpace.visitResidentFrames(
                        |pAddress| resident.includeAllocatedFrame(f, pAddress))) && resident.matches(f);
                resident.release(f);
                if valid { (*self.boot_baseline.get()).replace(baseline); }
                else { baseline.release(f); }
                valid && f.probe()
            } else {
                let result = q.collect(f, 0, pid);
                q.reap(f);
                let matched = baseline.matches(f);
                baseline.release(f);
                result == Ok(0) && matched && f.probe()
            }
        });
        if !ok { return Err(b"user process result or frame leak"); }
        serial(b"AGENTOS PROCESS OK APIC="); hex(self.expected_id as u64);
        serial(b" PARENT="); hex(pid as u64); serial(b"\r\n");
        Ok(())
    }

    fn check_empty(&self) -> bool {
        self.load.frames.with(|frames| {
            let before = frames.available();
            let plain = frames.alloc();
            let zeroed = frames.alloc_zeroed();
            let rejected = plain.is_none() && zeroed.is_none();
            for frame in [plain, zeroed].into_iter().flatten() { frames.release(frame); }
            before == 0 && rejected && frames.available() == 0
        })
    }

    unsafe fn measure_idle(&self) -> Result<(), Error> {
        let baseline = self.interrupts.load(Ordering::Acquire);
        // 30 s at divide-by-128, using the 10 ms calibration at divide-by-16.
        let count = self.interval.checked_mul(375).ok_or(b"idle interval overflow" as Error)?;
        self.apic.write(0x3e0, 0xa);
        self.apic.write(0x320, TIMER);
        let start = timestamp();
        // Bound even long idle intervals by the real short-counter service
        // requirement on the BSP. Wide sources preserve the original long arm.
        let max_count = if self.descriptors.is_none() {
            crate::system_clock::maintenance_ms().map(|ms|
                (self.interval as u64 * ms / 80).clamp(1, count as u64) as u32)
                .unwrap_or(count)
        } else { count };
        self.apic.write(0x380, max_count);
        let mut waiting = 0;
        let mut wakes = 0;
        let mut timers = 0;
        let target = 30 * self.tsc_hz;
        let elapsed = loop {
            let mut stamps = [0u64; 2];
            idle_wait(stamps.as_mut_ptr());
            if stamps[0] < start || stamps[1] <= stamps[0] { return Err(b"idle IRQ timestamp"); }
            waiting += stamps[1] - stamps[0];
            wakes += 1;
            let seen = self.interrupts.load(Ordering::Acquire).wrapping_sub(baseline);
            if seen == timers { continue; } // a non-timer interrupt woke HLT
            if seen != timers + 1 || self.apic.read(0x390) != 0 { return Err(b"invalid idle timer"); }
            timers = seen;
            let elapsed = timestamp() - start;
            if elapsed >= target - target / 100 { break elapsed; }
            // A virtual APIC may advance faster than TSC while catching up.
            // Charge every early expiration and wait for the remaining time.
            let remaining_ms = (target - elapsed) * 1000 / self.tsc_hz;
            self.apic.write(0x380, (count as u64 * remaining_ms / 30_000).clamp(1, max_count as u64) as u32);
        };
        if waiting >= elapsed { return Err(b"invalid idle accounting"); }
        self.apic.write(0x320, MASK | TIMER);
        self.apic.write(0x3e0, 3);
        self.idle.get().write(IdleSample { wakes, timers, elapsed, active: elapsed - waiting });
        Ok(())
    }
}

unsafe fn current_cpu() -> &'static Cpu {
    let cpu: *const Cpu;
    asm!("mov {}, gs:[0]", out(reg) cpu, options(readonly, nostack));
    &*cpu
}

/// Called only after SMP publishes CPU-local state and with local IRQs
/// masked by the system clock gate. It does not acquire that gate again.
fn clock_witness(generation: u64) -> Option<crate::clock_quorum::Witness> {
    use crate::tsc_watchdog::MONITOR;
    if !MONITOR.active() { return None; }
    let cpu = unsafe { current_cpu() };
    if !cpu.fRuntimeReady.load(Ordering::Acquire) { return None; }
    let alignment = cpu.tsc.alignment()?;
    MONITOR.witness_at(generation, cpu.expected_id, alignment, unsafe { crate::tsc::read() })
}

// Installed only after GS, rate and alignment are available on every
// enabled CPU. No scheduler, global clock or watchdog lock recursion.
fn local_tsc_sample() -> crate::tsc_epoch::Sample {
    let cpu=unsafe { current_cpu() };
    crate::tsc_epoch::Sample { id:cpu.expected_id, raw:unsafe { crate::tsc::read() } }
}

fn reject_clock_witness() {
    crate::tsc_watchdog::MONITOR.reject();
}

unsafe fn active_root() -> usize {
    let root: usize;
    asm!("mov {}, cr3", out(reg) root, options(nomem, nostack));
    root
}

extern "C" fn allocation_task(slot: usize) {
    let cpu = unsafe { current_cpu() };
    let worker = cpu.expected_id as usize * stress::TASKS + slot;
    let pages = cpu.load.exercise(worker, &cpu.interrupts);
    cpu.released[slot].store(pages, Ordering::Release);
}

#[no_mangle]
unsafe extern "C" fn finish_task() -> ! {
    asm!("cli", options(nostack));
    current_cpu().lockQueue().finish_current();
    loop { wait_for_irq(); }
}

#[no_mangle]
unsafe extern "C" fn timer_interrupt(context: *mut Context) -> usize {
    let cpu = current_cpu();
    // ISR register for vectors 224..255. A software INT cannot pass this check.
    if cpu.apic.read(0x170) & 1 == 0 {
        serial(b"SMP FAILED: unexpected timer interrupt\r\n"); halt();
    }
    cpu.apic.write(0xb0, 0);              // EOI before returning to the task
    if (*context).rip == ptr::addr_of!(after_hlt) as usize { cpu.hlt_wakes.fetch_add(1, Ordering::Release); }
    cpu.interrupts.fetch_add(1, Ordering::Release);
    let (pScheduled, pIdle) = {
        let pQueue = cpu.lockQueue(); (pQueue.active, pQueue.all_blocked())
    };
    if pScheduled {
        cpu.fTimerSequence.fetch_add(1, Ordering::AcqRel);
        cpu.runtime_timer_irqs.fetch_add(1, Ordering::Relaxed);
        if pIdle { cpu.runtime_idle_irqs.fetch_add(1, Ordering::Relaxed); }
        cpu.fTimerSequence.fetch_add(1, Ordering::Release);
    }
    if (*context).user() && (*context).rsp >= (1usize << 47) {
        return user_fault(13, 0, 0);
    }
    cpu.switch(context as usize, true)
}

#[no_mangle]
unsafe extern "C" fn pci_interrupt(context: *mut Context, vector: u8) -> usize {
    let cpu = current_cpu();
    let isr = 0x100 + 16 * (vector as usize / 32);
    let bit = 1 << (vector % 32);
    let in_service = cpu.apic.read(isr) & bit != 0;
    let sample = crate::pci_irq::acknowledge();
    cpu.apic.write(0xb0, 0);
    crate::pci_irq::record(vector, cpu.apic.id(), in_service && cpu.apic.read(isr) & bit == 0, sample);
    context as usize
}

#[no_mangle]
unsafe extern "C" fn keyboard_interrupt(context: *mut Context) -> usize {
    let cpu = current_cpu();
    let terminal = *cpu.terminal.get();
    if cpu.apic.read(0x170) & 4 == 0 || terminal.is_null() {
        serial(b"SMP FAILED: unexpected keyboard interrupt\r\n"); halt();
    }
    (*terminal).keyboard_interrupt();
    cpu.apic.write(0xb0, 0);
    if (*context).user() && (*context).rsp >= 1usize << 47 { return user_fault(13, 0, 0); }
    // Device state is committed and its TTY gate released before queue/frame
    // readiness checks. Pending IPI closes the check-to-block race remotely.
    notifyRemote();
    cpu.switch(context as usize, false)
}

#[no_mangle]
unsafe extern "C" fn serial_interrupt(context: *mut Context) -> usize {
    let cpu = current_cpu();
    let terminal = *cpu.terminal.get();
    if cpu.apic.read(0x170) & 2 == 0 || terminal.is_null() {
        serial(b"SMP FAILED: unexpected serial interrupt\r\n"); halt();
    }
    (*terminal).interrupt();
    cpu.apic.write(0xb0, 0); // Device deasserted/rearmed before EOI.
    if (*context).user() && (*context).rsp >= 1usize << 47 { return user_fault(13, 0, 0); }
    // Device state is committed and its TTY gate released before queue/frame
    // readiness checks. Pending IPI closes the check-to-block race remotely.
    notifyRemote();
    cpu.switch(context as usize, false)
}

#[no_mangle]
unsafe extern "C" fn reschedule_interrupt(aContext: *mut Context) -> usize {
    let pCpu = current_cpu();
    if pCpu.apic.read(0x170) & 8 == 0 {
        serial(b"SMP FAILED: unexpected reschedule interrupt\r\n"); halt();
    }
    pCpu.fWakePending.store(false, Ordering::Release);
    pCpu.apic.write(0xb0, 0);
    if (*aContext).user() && (*aContext).rsp >= 1usize << 47 { return user_fault(13, 0, 0); }
    pCpu.switch(aContext as usize, false)
}

#[no_mangle]
unsafe extern "C" fn finish_context_switch() {
    let pCpu = current_cpu();
    let pFreed = {
        let mut pQueue = pCpu.lockQueue();
        pQueue.completeSwitch();
        pCpu.load.frames.with(|pFrames| pQueue.collectRetired(pFrames))
    };
    if pFreed != 0 { notifyRemote(); }
    balanceQueues();
}

/// Retry an authorized demand/COW access at the same user RIP. Kernel
/// copy-in/out explicitly invokes the pager through physical aliases instead
/// of taking a nested kernel fault while holding the frame allocator lock.
#[allow(non_snake_case)]
pub unsafe fn userPageFault(aAddress: usize, aError: u64) -> bool {
    let pCpu = current_cpu();
    let pQueue = pCpu.lockQueue();
    let Some(pProcess) = pQueue.process() else { return false; };
    let pResult = pCpu.load.frames.with(|pFrames| pProcess.space.resolveFault(pFrames, aAddress, aError));
    if pResult == Err(-12) {
        let mut pLine = Diagnostic::new(b"AGENTOS PAGE OOM");
        pLine.field(b" PID=", pProcess.pid as u64);
        pLine.field(b" ADDRESS=", aAddress as u64); pLine.publish(pCpu);
    }
    pResult.is_ok()
}

pub unsafe fn user_fault(vector: u64, error: u64, addr: u64) -> usize {
    let cpu = current_cpu();
    let mut pGuard = cpu.lockQueue();
    let q = &mut *pGuard;
    let p = q.process().unwrap();
    let pParent = cpu.load.frames.with(|pFrames| cpu.programs.fRegistry.parentOf(pFrames, p.pid)).unwrap_or(0);
    let mut pLine = Diagnostic::new(b"AGENTOS USER FAULT");
    pLine.field(b" PID=", p.pid as u64); pLine.field(b" PARENT=", pParent as u64);
    pLine.field(b" CR3=", active_root() as u64); pLine.field(b" VECTOR=", vector);
    pLine.field(b" ERROR=", error); pLine.field(b" ADDRESS=", addr); pLine.publish(cpu);
    cpu.load.frames.with(|f| q.terminate(256 + vector as usize, f));
    drop(pGuard); notifyRemote();
    cpu.switch(0, false)
}

#[no_mangle]
#[allow(non_snake_case)]
unsafe extern "C" fn dispatch_syscall(ctx: &mut Context) -> usize {
    let cpu = current_cpu();
    if ctx.rsp >= 1usize << 47 { return user_fault(13, 0, 0); }
    let mut pGuard = cpu.lockQueue();
    let q = &mut *pGuard;
    let pChanged = cpu.load.frames.with(|pFrames| {
        let pKilled = q.processPendingKills(pFrames);
        pKilled | (q.collectRetired(pFrames) != 0)
    });
    if q.process().map_or(false, |pProcess| pProcess.status.is_some()) {
        drop(pGuard); notifyRemote(); return cpu.switch(0, false);
    }
    let p = q.process_mut().unwrap();
    let pid = p.pid;
    let [a, b, c] = [ctx.registers[10], ctx.registers[11], ctx.registers[12]]; // RDI, RSI, RDX
    let pNotify = pChanged || matches!(ctx.registers[14], 0x10002..=0x10005 | 0x10008..=0x1000f |
        0x10011 | 0x10014 | 0x10015 | 0x10019);
    macro_rules! switchNow {
        ($pOutgoing:expr) => {{
            let pOutgoing = $pOutgoing;
            drop(pGuard);
            if pNotify { notifyRemote(); }
            return cpu.switch(pOutgoing, false);
        }};
    }
    let result: isize = match ctx.registers[14] {
        0x10001 => pid as isize,
        // Native ABI v2 uses one HPET boot epoch on every CPU.
        0x10010 => crate::system_clock::millis().map(|v| v as isize).unwrap_or(-5),
        // Read-only, versioned global timer diagnostics. All fields are
        // captured with IF=0, and the destination is validated before writing.
        // Counts cover scheduled operation, excluding boot/idle timer probes.
        0x10018 => {
            if b != 32 || c != 0 { -22 }
            else if let Some(now) = crate::system_clock::millis() {
                let (pTimers, pIdle) = timerSnapshot();
                let fields = [2u64, now, pTimers, pIdle];
                let mut bytes = [0u8; 32];
                for (i, field) in fields.iter().enumerate() {
                    bytes[i*8..(i+1)*8].copy_from_slice(&field.to_le_bytes());
                }
                cpu.load.frames.with(|f| p.space.write(f, a, &bytes)).map_or_else(|e| e, |_| 0)
            } else { -5 }
        }
        // Scheduling identity is sampled while this CPU owns the task gate.
        0x1001b => {
            if b != 64 || c != 0 { -22 }
            else {
                let pMigrations = q.currentMigrations();
                let pProcess = q.process().unwrap();
                cpu.load.frames.with(|pFrames| {
                    let pParent = cpu.programs.fRegistry.parentOf(pFrames, pid).ok_or(-3isize)?;
                    let pFields = [1u64, cpu.expected_id as u64, gOnlineCount.load(Ordering::Acquire) as u64,
                        pMigrations as u64, gMigrations.load(Ordering::Relaxed) as u64,
                        gRemoteWakeups.load(Ordering::Relaxed) as u64, pid as u64, pParent as u64];
                    let mut pBytes = [0u8; 64];
                    for (pIndex, pValue) in pFields.iter().enumerate() {
                        pBytes[pIndex*8..(pIndex+1)*8].copy_from_slice(&pValue.to_le_bytes());
                    }
                    pProcess.space.write(pFrames, a, &pBytes)
                }).map_or_else(|pError| pError, |_| 0)
            }
        }
        // Versioned read-only VM accounting. Fault in the destination before
        // taking the snapshot, so its own frames are included consistently.
        0x1001a => {
            if b != 64 || c != 0 { -22 }
            else {
                cpu.load.frames.with(|f| {
                    p.space.writable(f, a, 64)?;
                    let pFields = p.space.stats();
                    let mut pBytes = [0u8; 64];
                    for (pIndex, pField) in pFields.iter().enumerate() {
                        pBytes[pIndex*8..(pIndex+1)*8].copy_from_slice(&pField.to_le_bytes());
                    }
                    p.space.write(f, a, &pBytes)
                }).map_or_else(|e| e, |_| 0)
            }
        }
        // SYS_WAIT_CHILD(child_pid, 0, 0): pure lifecycle wait, independent
        // of the availability and progression of the monotonic clock.
        0x1001c => {
            if b != 0 || c != 0 { -22 }
            else {
                match cpu.load.frames.with(|f| q.collect(f, pid, a)) {
                    Ok(status) => status as isize,
                    Err(-11) => {
                        q.block_child_exit(a);
                        ctx.rip -= 2;
                        switchNow!(ctx as *mut Context as usize);
                    }
                    Err(error) => error,
                }
            }
        }
        // SYS_WAIT_CHILD_UNTIL(child_pid, absolute_deadline_ms):
        // nonblocking if already reaped/finished, otherwise sleep until child
        // termination or the shared monotonic deadline. Reaps on success.
        0x10011 => {
            if b > isize::MAX as usize { -22 }
            else if q.take_clock_error() { -5 }
            else {
                match cpu.load.frames.with(|f| q.collect(f, pid, a)) {
                    Ok(status) => status as isize,
                    Err(-11) => match crate::system_clock::millis() {
                        None => -5,
                        Some(now) if now >= b as u64 => -110,
                        Some(now) => {
                            q.block_child(a, b as u64, now);
                            ctx.rip -= 2;
                            switchNow!(ctx as *mut Context as usize);
                        }
                    },
                    Err(error) => error,
                }
            }
        }
        // SYS_SLEEP_UNTIL(absolute_deadline_ms): timer-driven sleep. It must
        // not treat a frozen shared counter as actual passage of time.
        0x10012 => {
            if a > isize::MAX as usize { -22 }
            else if q.take_clock_error() { -5 }
            else {
                match crate::system_clock::millis() {
                    None => -5,
                    Some(now) if now >= a as u64 => 0,
                    Some(now) => {
                        q.block_sleep(a as u64, now);
                        ctx.rip -= 2;
                        switchNow!(ctx as *mut Context as usize);
                    }
                }
            }
        }
        op @ (0x10002 | 0x10008 | 0x1000d | 0x1000e | 0x10015 | 0x10019) => {
            let io = match op {
                0x10002 => cpu.load.frames.with(|f| p.files.write(f, &p.space, a, b, c)),
                0x10008 => cpu.load.frames.with(|f| p.files.read(f, &p.space, a, b, c)),
                0x1000d | 0x10019 => cpu.load.frames.with(|f| p.files.message(f, crate::ipc::Operation::Send, p, a, b, c)),
                _ => cpu.load.frames.with(|f| p.files.message(f, crate::ipc::Operation::Receive, p, a, b, c)),
            };
            // Lazy copy-in may allocate, but slow UART/GOP output must not
            // keep every other CPU waiting for the shared frame allocator.
            let io = match io {
                Ok(crate::files::Io::Output(pOutput)) => pOutput.complete().map(crate::files::Io::Bytes),
                pOther => pOther,
            };
            match io {
                Ok(crate::files::Io::Bytes(n)) => { cpu.load.frames.with(|f| q.wake_io(f)); n as isize }
                Ok(crate::files::Io::Output(_)) => unreachable!(),
                Ok(crate::files::Io::Sleep(_)) if op == 0x10015 || op == 0x10019 => -11,
                Ok(crate::files::Io::Sleep(wait)) => {
                    // No bytes committed. Retry SYSCALL with its original
                    // registers when data, space, or the last close wakes it.
                    ctx.rip -= 2;
                    q.block(wait);
                    switchNow!(ctx as *mut Context as usize);
                }
                Err(error) => { cpu.load.frames.with(|f| q.wake_io(f)); error }
            }
        }
        // Bootstrap-only pause: not a general process or service control.
        0x10016 => {
            if pid != 1 || cpu.load.frames.with(|f| q.park_boot_root(f, pid)).is_err() { -16 }
            else {
                let mut pLine = Diagnostic::new(b"AGENTOS USER PARK");
                pLine.field(b" PID=", pid as u64); pLine.field(b" CR3=", active_root() as u64);
                pLine.field(b" STATUS=", 0); pLine.publish(cpu);
                ctx.registers[14] = 0;
                switchNow!(ctx as *mut Context as usize);
            }
        }
        // Atomic wait on a validated set of shared IPC endpoints and any
        // exited direct child. An IPI retries readiness after a remote IPC or exit event.
        // Bit 32 of the positive result denotes a child exit; bits 0..31
        // denote sockets with queued messages or EOF, 0 denotes timeout.
        0x10017 => {
            if a > u32::MAX as usize || b > isize::MAX as usize || c != 0 { -22 }
            else if q.take_clock_error() { -5 }
            else {
                match cpu.load.frames.with(|f| q.process().unwrap().files.ipc_ready_mask(f, a as u32)) {
                    Err(error) => error,
                    Ok(mask) => {
                        let events = mask as usize |
                            if cpu.load.frames.with(|f| q.has_exited_child(f, pid)) { 1usize << 32 } else { 0 };
                        if events != 0 { events as isize }
                        else {
                            match crate::system_clock::millis() {
                                None => -5,
                                Some(now) if now >= b as u64 => 0,
                                Some(now) => {
                                    q.block_events(a as u32, b as u64, now);
                                    ctx.rip -= 2;
                                    switchNow!(ctx as *mut Context as usize);
                                }
                            }
                        }
                    }
                }
            }
        }
        0x10003 => {
            let mut pLine = Diagnostic::new(b"AGENTOS USER EXIT");
            pLine.field(b" PID=", pid as u64); pLine.field(b" CR3=", active_root() as u64);
            pLine.field(b" STATUS=", (a & 255) as u64); pLine.publish(cpu);
            cpu.load.frames.with(|f| q.terminate(a & 255, f));
            switchNow!(0);
        }
        op @ (crate::native_abi::SYS_SPAWN | crate::native_abi::SYS_SPAWN_FLAGS) => {
            let mut name = [0; crate::vfs::PATH_MAX];
            match crate::native_abi::spawn_flags(op, b, c, name.len()) {
                Err(error) => error,
                Ok(flags) => {
                    if let Err(error) = cpu.load.frames.with(|f| p.space.read(f, a, &mut name[..b])) { error }
                    else { cpu.load.frames.with(|f| q.spawn_process(f, cpu.programs, &name[..b], pid, flags))
                               .map(|v| v as isize).unwrap_or_else(|e| e) }
                }
            }
        }
        0x10005 => cpu.load.frames.with(|f| q.collect(f, pid, a)).map(|v| v as isize).unwrap_or_else(|e| e),
        // Parent gets the new PID. The child resumes at the same return RIP
        // with RAX=0, a private kernel stack and COW userspace pages.
        0x10014 => cpu.load.frames.with(|f| q.fork_process(f, cpu.programs, ctx))
            .map(|v| v as isize).unwrap_or_else(|e| e),
        // Child enumeration is owner-scoped, never global. The zero cursor
        // returns the oldest living or zombie direct child (including
        // grandchildren adopted when their intermediate parent exited).
        0x10013 => if a > isize::MAX as usize { -22 }
            else { cpu.load.frames.with(|f| q.child_after(f, pid, a)).map(|v| v as isize).unwrap_or_else(|e| e) },
        0x1000f => {
            let result = cpu.load.frames.with(|f| q.kill_child(f, pid, a));
            if matches!(result, Ok(0)) {
                let mut pLine = Diagnostic::new(b"AGENTOS USER KILL");
                pLine.field(b" PID=", a as u64); pLine.field(b" PARENT=", pid as u64);
                pLine.field(b" STATUS=", 137); pLine.publish(cpu);
            }
            result.map(|v| v as isize).unwrap_or_else(|e| e)
        }
        0x10006 => { ctx.registers[14] = 0; switchNow!(ctx as *mut Context as usize); }
        0x10007 => {
            let mut path = [0; crate::vfs::PATH_MAX];
            if c != 0 { -30 } else if b > path.len() { -36 }
            else if let Err(error) = cpu.load.frames.with(|f| p.space.read(f, a, &mut path[..b])) { error }
            else { cpu.programs.vfs.file(&path[..b]).and_then(|data|
                cpu.load.frames.with(|f| p.files.open(f, data))).map(|n| n as isize).unwrap_or_else(|e| e) }
        }
        0x10009 | 0x1000b => {
            let res = cpu.load.frames.with(|f| if ctx.registers[14] == 0x10009 {
                p.files.close(f, a)
            } else { p.files.dup2(f, a, b) });
            cpu.load.frames.with(|f| q.wake_io(f));
            res.map(|v| v as isize).unwrap_or_else(|e| e)
        }
        op @ (0x1000a | 0x1000c) => cpu.load.frames.with(|f| p.files.pair(f, &p.space, a, op == 0x1000c)).map(|v| v as isize).unwrap_or_else(|e| e),
        _ => -38,
    };
    // A lifecycle operation may also have consumed a remote stop request for
    // its caller. A published zombie must never return to user instructions.
    if q.process().map_or(false, |pProcess| pProcess.status.is_some()) {
        drop(pGuard); notifyRemote(); return cpu.switch(0, false);
    }
    ctx.registers[14] = result as usize;
    drop(pGuard);
    if pNotify { notifyRemote(); }
    ctx as *mut Context as usize
}

#[no_mangle]
unsafe extern "C" fn ap_main(cpu: &'static Cpu) -> ! {
    cpu.descriptors.as_ref().unwrap().load();
    match cpu.apic.enable().and_then(|_| {
        cpu.initialize_local_cpu()?;
        // On the TSC-only bring-up path each AP must first measure its
        // own rate against PIT. Do not use the BSP's raw TSC as its clock.
        if let Some(bsp_hz)=cpu.reference.tsc_hz() {
            let rate=cpu.qualify_tsc("ap-start").ok_or(b"AP independent TSC calibration failed" as Error)?;
            if rate.hz().abs_diff(bsp_hz) as u128*1000>rate.hz().min(bsp_hz) as u128 {
                return Err(b"AP TSC rate mismatch" as Error);
            }
            cpu.tsc.publish_rate(Some(rate));
        }
        cpu.run_task()
    }) {
        Ok(()) => {
            cpu.complete.store(1, Ordering::Release);
            // With an independent ACPI epoch, TSC is optional. With
            // TSC-only bring-up its local rate was qualified above.
            if cpu.reference.tsc_hz().is_none() {
                let rate = if gBspQualifiedTscHz.load(Ordering::Acquire) != 0 {
                    cpu.qualify_tsc("ap-optional")
                } else { None };
                cpu.tsc.publish_rate(rate);
            }
            while !cpu.load.started.load(Ordering::Acquire) {
                cpu.tsc.respond(|| crate::tsc::read());
                spin_loop();
            }
            cpu.schedule();
            cpu.complete.store(2, Ordering::Release);
            while cpu.phase.load(Ordering::Acquire) < OOM_PHASE { spin_loop(); }
            if !cpu.check_empty() { cpu.complete.store(3, Ordering::Release); halt(); }
            cpu.complete.store(OOM_CHECKED, Ordering::Release);
            while cpu.phase.load(Ordering::Acquire) < PROCESS_PHASE { spin_loop(); }
            if let Err(reason) = cpu.process_test() {
                serial(b"SMP FAILED: "); serial(reason); serial(b"\r\n");
                cpu.complete.store(3, Ordering::Release); halt();
            }
            cpu.complete.store(PROCESSES_FINISHED, Ordering::Release);
            while cpu.phase.load(Ordering::Acquire) < IDLE_PHASE { spin_loop(); }
            match cpu.measure_idle() {
                Ok(()) => {
                    cpu.complete.store(IDLE_FINISHED, Ordering::Release);
                    while cpu.phase.load(Ordering::Acquire) < RUNTIME_PHASE { spin_loop(); }
                    cpu.runtimeWorker();
                },
                Err(reason) => {
                    serial(b"SMP FAILED: "); serial(reason); serial(b"\r\n");
                    cpu.complete.store(3, Ordering::Release);
                }
            }
        }
        Err(reason) => {
            serial(b"SMP FAILED: "); serial(reason); serial(b"\r\n");
            cpu.complete.store(3, Ordering::Release);
        }
    }
    halt()
}

pub unsafe fn copy_startup(base: usize) {
    let start = ptr::addr_of!(ap_start) as usize;
    let len = ptr::addr_of!(ap_end) as usize - start;
    assert!(len <= PAGE);
    for offset in 0..len {
        ptr::write_volatile((base + offset) as *mut u8, *((start + offset) as *const u8));
    }
}

unsafe fn start_ap(cpu: &Cpu, root: usize, base: usize, stack: usize, clock: &BringupClock) -> Result<(), Error> {
    let mailbox = base + PAGE;
    let dest = |label: *const u8| (base + (label as usize - ptr::addr_of!(ap_start) as usize)) as u32;
    (mailbox as *mut u32).write(u32::try_from(root).map_err(|_| b"AP bootstrap CR3 above 4 GiB" as Error)?);
    ((mailbox+8) as *mut usize).write(stack);
    ((mailbox+16) as *mut usize).write(cpu.self_address);
    ((mailbox+24) as *mut u16).write(31);
    ptr::write_unaligned((mailbox+26) as *mut u32, dest(ptr::addr_of!(ap_gdt)));
    ((mailbox+32) as *mut u32).write(dest(ptr::addr_of!(ap_pm)));
    ((mailbox+36) as *mut u16).write(8);
    ((mailbox+40) as *mut u32).write(dest(ptr::addr_of!(ap_long)));
    ((mailbox+44) as *mut u16).write(24);
    ((mailbox+48) as *mut usize).write(ap_main as *const () as usize);
    fence(Ordering::SeqCst);
    cpu.apic.send(cpu.expected_id, 0xc500, clock)?; // level-triggered INIT, assert
    clock.delay_ns(10_000_000).map_err(|_| b"AP INIT delay reference stopped" as Error)?;
    let sipi = 0x4600 | (base >> 12) as u32;
    cpu.apic.send(cpu.expected_id, sipi, clock)?;
    clock.delay_ns(200_000).map_err(|_| b"AP SIPI delay reference stopped" as Error)?;
    cpu.apic.send(cpu.expected_id, sipi, clock)?;
    clock.wait_until(2_000_000_000, || {
        let _ = crate::system_clock::millis();
        cpu.complete.load(Ordering::Acquire) != 0
    })
        .map_err(|error| match error {
            WaitError::Timeout => b"AP task timeout" as Error,
            WaitError::Unresponsive => b"AP task reference clock stopped" as Error,
        })?;
    if cpu.complete.load(Ordering::Acquire) != 1 { return Err(b"AP task failed"); }
    Ok(())
}

pub unsafe fn run(platform: &Platform, base: usize, root: usize, mut frames: Frames<'static>,
                  bsp_rsp0: usize, archive: &'static [u8], log: &mut crate::BootLog<'_>,
                  physical_ready: bool,
                  initialize_timed_devices: impl FnOnce(&mut Frames<'static>) -> Result<(),Error>) -> Result<(), Error> {
    let guard_probe = crate::stack::KernelStack::allocate(&mut frames).ok_or(b"kernel guard stack" as Error)?;
    let guarded = crate::exceptions::probe_guard(guard_probe.guard()) &&
        crate::exceptions::probe_guard(guard_probe.top());
    guard_probe.release(&mut frames);
    if !guarded { return Err(b"kernel stack guard probe"); }
    serial(b"AGENTOS KERNEL STACK GUARD OK\r\n");
    if platform.legacy_pic { out(0x21, 0xff); out(0xa1, 0xff); }
    let apic = Lapic(platform.lapic);
    apic.enable()?;
    let (clock,boot_rate) = if physical_ready {
        (BringupClock::Physical(ReferenceClock::select(platform.pm_timer,crate::hpet::reference())
            .ok_or(b"no progressing hardware reference clock" as Error)?),None)
    } else {
        // An enumerated crystal ratio is useful for diagnosing the
        // platform, but cannot authorize a public epoch by itself.
        let mut discarded=crate::pit::DiscardedWindows::new();
        let result=crate::pit::qualify(platform.legacy_pit_probe,||{},&mut discarded);
        report_pit_discarded(apic.id(),"bsp-start",true,&discarded);
        let rate=result.map_err(|fault| {
                report_pit_failure(apic.id(),"bsp-start",true,fault);
                if crate::tsc::detect().nominal_hz.is_some() {
                    b"enumerated TSC rate but no independent bootstrap reference" as Error
                } else { b"no independent TSC bootstrap calibration" as Error }
            })?;
        (BringupClock::LocalTsc { hz:rate.hz() },Some(rate))
    };
    log.event(1, clock.name());
    let (interval, tsc_hz) = apic.calibrate(&clock)?;
    log.event(2, b"APIC TIMER READY");
    let bsp = apic.id();
    let ids = &platform.ids[..platform.count];
    if !ids.contains(&bsp) { return Err(b"BSP absent from MADT"); }
    let storage = frames.alloc().ok_or(b"shared allocator storage" as Error)?.into_address() as *mut Load;
    let programs = frames.alloc().ok_or(b"program storage" as Error)?.into_address() as *mut Programs;
    programs.write(Programs::new(archive, root));
    let programs = &*programs;
    storage.write(Load::new(SharedFrames::new(frames), ids.len()));
    let load = &*storage;
    let boot_cpu = load.frames.with(|f| Cpu::create(f, apic, bsp, interval, tsc_hz, clock, platform.legacy_pit_probe, None, load, programs, bsp_rsp0))?;
    gCpus[bsp as usize].store(boot_cpu.self_address, Ordering::Release);
    if let Some(rate)=boot_rate { boot_cpu.tsc.publish_rate(Some(rate)); }
    boot_cpu.initialize_local_cpu()?;
    boot_cpu.run_task()?;
    let bsp_proof = if let Some(rate)=boot_rate { Some(rate) } else {
        let rate=boot_cpu.qualify_tsc("bsp-optional");
        boot_cpu.tsc.publish_rate(rate);
        rate
    };
    let bsp_rate=bsp_proof.map(crate::tsc::QualifiedRate::hz);
    if let Some(hz) = bsp_rate {
        boot_cpu.tsc.publish_alignment(crate::tsc::Alignment { offset: 0, uncertainty_ticks: 0 });
        gBspQualifiedTscHz.store(hz, Ordering::Release);
    }
    log.event(1, crate::tsc::Diagnostic::new(bsp, &boot_cpu.tsc).bytes());
    let mut cpus = [None; 255];
    cpus[bsp as usize] = Some(boot_cpu);
    for &id in ids {
        if id == bsp { continue; }
        let cpu = load.frames.with(|f| {
            let descriptors = Descriptors::new(f).ok_or(b"AP descriptors" as Error)?;
            let rsp0 = descriptors.rsp0_slot();
            Cpu::create(f, apic, id, interval, tsc_hz, clock, platform.legacy_pit_probe, Some(descriptors), load, programs, rsp0)
        })?;
        let stack = load.frames.with(crate::stack::KernelStack::allocate)
            .ok_or(b"AP stack" as Error)?.into_top();
        gCpus[id as usize].store(cpu.self_address, Ordering::Release);
        start_ap(cpu, root, base, stack, &clock)?;
        if let Some(hz) = bsp_rate {
            let alignment=clock.synchronize(&cpu.tsc,hz,||{ let _=crate::system_clock::millis(); });
            if !physical_ready && alignment.is_none() { return Err(b"AP TSC alignment failed"); }
        }
        log.event(1, crate::tsc::Diagnostic::new(id, &cpu.tsc).bytes());
        cpus[id as usize] = Some(cpu);
    }
    gOnlineCount.store(ids.len(), Ordering::Release);
    log.event(1, b"PROCESSORS ONLINE");
    if !physical_ready {
        // Independent BSP measurements separate the two alignment rounds.
        // Each AP already passed its own independent calibration.
        let first=bsp_proof.ok_or(b"unqualified BSP TSC" as Error)?;
        let again=boot_cpu.qualify_tsc("bsp-confirm").ok_or(b"BSP TSC stability qualification failed" as Error)?;
        if !boot_cpu.tsc.confirm_rate(again) { return Err(b"BSP TSC frequency or raw time changed"); }
        for cpu in cpus.iter().flatten().filter(|cpu|cpu.expected_id!=bsp) {
            clock.synchronize(&cpu.tsc,first.hz(),||{})
                .ok_or(b"AP TSC alignment changed during qualification" as Error)?;
            log.event(1,crate::tsc::Diagnostic::new(cpu.expected_id,&cpu.tsc).bytes());
        }
    }
    match crate::tsc_epoch::select(physical_ready,||
        crate::tsc_epoch::Roster::qualify(bsp,ids,
            cpus.iter().flatten().map(|cpu|{let cpu=*cpu;(cpu.expected_id,&cpu.tsc)})))
        .ok_or(b"incomplete qualified TSC roster" as Error)? {
        crate::tsc_epoch::BootSource::Physical=>(),
        crate::tsc_epoch::BootSource::Tsc(roster)=>{
            crate::system_clock::publish_tsc(roster,local_tsc_sample)?;
            log.event(1,b"SYSTEM CLOCK: TSC (qualified invariant clocksource)");
        }
    }
    // APs are initialized and still behind the ordinary startup barrier.
    // Timed device operations run only after a real epoch exists, and
    // before releasing the scheduler and user tasks.
    load.frames.with(initialize_timed_devices)?;
    if crate::system_clock::millis().is_none() { return Err(b"system clock unavailable before scheduler"); }
    let baseline = load.frames.with(|f| f.snapshot()).ok_or(b"bitmap snapshot" as Error)?;
    load.started.store(true, Ordering::Release);
    boot_cpu.schedule();
    for cpu in cpus.iter().flatten() {
        if cpu.expected_id != bsp {
            while cpu.complete.load(Ordering::Acquire) != 2 { let _ = crate::system_clock::millis(); spin_loop(); }
        }
        for slot in 0..stress::TASKS {
            let switches = (*cpu.queue.get()).preemptions(slot);
            let pages = cpu.released[slot].load(Ordering::Acquire);
            if switches < 2 || pages != stress::BATCH * stress::BATCHES { return Err(b"preemption or page stress"); }
            serial(b"AGENTOS SCHED APIC="); hex(cpu.expected_id as u64);
            serial(b" TASK="); hex(slot as u64);
            serial(b" PREEMPTIONS="); hex(switches as u64);
            serial(b" PAGES="); hex(pages as u64); serial(b"\r\n");
        }
    }
    if !load.frames.with(|f| baseline.matches(f)) { return Err(b"free bitmap changed"); }
    serial(b"AGENTOS FRAME STRESS BITMAP OK HELD="); hex(load.overlapping_pages() as u64);
    serial(b" FREE-BEFORE="); hex(baseline.count as u64);
    serial(b" FREE-AFTER="); hex(load.frames.with(|f| f.available()) as u64); serial(b"\r\n");
    let held = load.frames.with(Exhaustion::drain);
    let drained = held.count;
    for cpu in cpus.iter().flatten() { cpu.phase.store(OOM_PHASE, Ordering::Release); }
    let mut rejected = boot_cpu.check_empty() as usize;
    for cpu in cpus.iter().flatten().filter(|c| c.expected_id != bsp) {
        while cpu.complete.load(Ordering::Acquire) == 2 { let _ = crate::system_clock::millis(); spin_loop(); }
        if cpu.complete.load(Ordering::Acquire) == OOM_CHECKED { rejected += 1; }
    }
    let restored = load.frames.with(|f| held.recover(f) && baseline.matches(f) && f.probe() && baseline.matches(f));
    if !restored || drained != baseline.count || rejected != ids.len() {
        return Err(b"physical memory exhaustion or recovery");
    }
    serial(b"AGENTOS OOM OK DRAINED="); hex(drained as u64);
    serial(b" REJECT-CPUS="); hex(rejected as u64);
    serial(b" RESTORED="); hex(load.frames.with(|f| f.available()) as u64); serial(b"\r\n");
    load.frames.with(|f| {
        baseline.release(f);
        for cpu in cpus.iter().flatten() { (*cpu.queue.get()).reap(f); }
    });
    log.event(1, b"STARTING USER PROCESSES");
    boot_cpu.process_test()?;
    for cpu in cpus.iter().flatten().filter(|c| c.expected_id != bsp) {
        cpu.phase.store(PROCESS_PHASE, Ordering::Release);
        while cpu.complete.load(Ordering::Acquire) == OOM_CHECKED { let _ = crate::system_clock::millis(); spin_loop(); }
        if cpu.complete.load(Ordering::Acquire) != PROCESSES_FINISHED { return Err(b"AP user processes"); }
    }
    serial(b"AGENTOS IDLE BEGIN TSC-HZ="); hex(tsc_hz); serial(b"\r\n");
    for cpu in cpus.iter().flatten() { cpu.phase.store(IDLE_PHASE, Ordering::Release); }
    boot_cpu.measure_idle()?;
    for cpu in cpus.iter().flatten() {
        if cpu.expected_id != bsp {
            while cpu.complete.load(Ordering::Acquire) == PROCESSES_FINISHED { let _ = crate::system_clock::millis(); spin_loop(); }
            if cpu.complete.load(Ordering::Acquire) != IDLE_FINISHED { return Err(b"AP idle sample"); }
        }
        let sample = &*cpu.idle.get();
        serial(b"AGENTOS IDLE APIC="); hex(cpu.expected_id as u64);
        serial(b" WAKES="); hex(sample.wakes);
        serial(b" TIMERS="); hex(sample.timers as u64);
        serial(b" TSC-TOTAL="); hex(sample.elapsed);
        serial(b" TSC-ACTIVE="); hex(sample.active); serial(b"\r\n");
    }
    // An invariant TSC cannot be a system-wide candidate unless every
    // enabled CPU has a qualified rate and bounded alignment. Monitor
    // continuously from ordinary runtime startup, including idle CPUs.
    if let Some(hz) = bsp_rate.filter(|_| physical_ready) {
        if cpus.iter().flatten().all(|cpu| cpu.tsc.rate().is_some() && cpu.tsc.alignment().is_some()) {
            if crate::tsc_watchdog::MONITOR.start(bsp as u32, hz,
                cpus.iter().flatten().map(|cpu| cpu.expected_id)) {
                log.event(1, b"TSC runtime watchdog enabled");
                if crate::system_clock::attach_witness(clock_witness, reject_clock_witness) {
                    log.event(1, b"TSC witness registered for independent clock comparison");
                }
            }
        }
    }
    for pCpu in cpus.iter().flatten().filter(|pCpu| pCpu.expected_id != bsp) {
        pCpu.phase.store(RUNTIME_PHASE, Ordering::Release);
    }
    clock.wait_until(2_000_000_000, || {
        let _=crate::system_clock::millis();
        cpus.iter().flatten().filter(|cpu| cpu.expected_id != bsp)
            .all(|cpu| cpu.fRuntimeReady.load(Ordering::Acquire))
    })
        .map_err(|error| match error {
            WaitError::Timeout => b"runtime CPU startup timeout" as Error,
            WaitError::Unresponsive => b"runtime CPU startup reference clock stopped" as Error,
        })?;
    if crate::system_clock::millis().is_none() {
        return Err(b"system clock unavailable at runtime publication");
    }

    Ok(())
}

/// Resume the original numeric BSP PID 1 after boot and idle acceptance.
/// It gains a trusted terminal without changing PID or reaper ownership.
pub unsafe fn shell(platform: &Platform, info: &crate::BootInfo) -> Result<(), Error> {
    let cpu = current_cpu();
    let baseline = (*cpu.boot_baseline.get()).take().ok_or(b"PID1 baseline missing" as Error)?;
    let Some(storage) = cpu.load.frames.with(|f| f.alloc()) else {
        cpu.load.frames.with(|f| baseline.release(f));
        return Err(b"TTY allocation");
    };
    let terminal = storage.address() as *mut crate::tty::Terminal;
    let mut initialized = false;
    let started = (|| -> Result<usize, Error> {
        terminal.write(crate::tty::Terminal::new(platform, cpu.expected_id, crate::serial_available()));
        initialized = true;
        // The BSP TTY owns the mapped GOP framebuffer for the entire shell
        // session; the serial path remains available if GOP validation fails.
        if let Some(screen) = crate::fb_console::Console::below_boot_status(
            info.framebuffer, info.width as usize, info.height as usize,
            info.stride as usize, info.pixel_format
        ) {
            (*terminal).attach_screen(screen);
        } else {
            let _ = crate::logger::LOGGER.record(timestamp(), cpu.expected_id as u32,
                crate::log_policy::Level::Error, b"TTY GOP unavailable");
        }
        let queue = &mut *cpu.queue.get();
        let pid = queue.parked_root().ok_or(b"PID1 not parked" as Error)?;
        if pid != 1 { return Err(b"invalid PID1 identity"); }
        queue.terminal(pid, terminal).map_err(|_| b"PID1 terminal descriptors" as Error)?;
        queue.resume_boot_root(pid).map_err(|_| b"PID1 resume" as Error)?;
        let _ = crate::logger::LOGGER.record(timestamp(), cpu.expected_id as u32,
            crate::log_policy::Level::Info, b"service manager session started");
        serial(b"AGENTOS MANAGER SESSION START PID="); hex(pid as u64); serial(b"\r\n");
        cpu.terminal.get().write(terminal);
        gTerminal.store(terminal as usize, Ordering::Release);
        (*terminal).enable();
        let pStatus = cpu.runtimeSession(pid)?;
        if pStatus != 0 { return Err(b"service manager exit status"); }
        Ok(pid)
    })();
    if initialized { (*terminal).disable(); }
    cpu.terminal.get().write(ptr::null_mut());
    gTerminal.store(0, Ordering::Release);
    let mut pCleanupQueue = cpu.lockQueue();
    let result = cpu.load.frames.with(|f| {
        let q = &mut *pCleanupQueue;
        let status = started;
        q.reap(f);
        f.release(storage);
        let matched = baseline.matches(f);
        baseline.release(f);
        if matched && f.probe() { status } else { Err(b"manager session frame leak" as Error) }
    });
    drop(pCleanupQueue);
    let pid = result?;
    let _ = crate::logger::LOGGER.record(timestamp(), cpu.expected_id as u32,
        crate::log_policy::Level::Info, b"service manager session stopped");
    serial(b"AGENTOS MANAGER SESSION STOP PID="); hex(pid as u64);
    serial(b" STATUS=0000000000000000 FRAMES=OK\r\n");
    Ok(())
}
