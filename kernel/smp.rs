use crate::{acpi::Platform, exceptions::{hex, Descriptors}, frames::{Exhaustion, Frames, SharedFrames},
            halt, out, process::{Programs, EFAULT}, scheduler::{Context, Queue}, serial, stress::{self, Load}};
use core::{arch::{asm, x86_64::__cpuid}, cell::UnsafeCell, hint::spin_loop, ptr,
           sync::atomic::{fence, AtomicU32, AtomicUsize, Ordering}};

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
const PM_HZ: u32 = 3_579_545;
const WAKEUPS: u32 = 3;
const OOM_PHASE: u32 = 1;
const PROCESS_PHASE: u32 = 2;
const IDLE_PHASE: u32 = 3;
const OOM_CHECKED: u32 = 4;
const IDLE_FINISHED: u32 = 5;
const PROCESSES_FINISHED: u32 = 6;

unsafe fn timestamp() -> u64 {
    let (lo, hi): (u32, u32);
    asm!("lfence", "rdtsc", "lfence", out("eax") lo, out("edx") hi, options(nostack));
    ((hi as u64) << 32) | lo as u64
}

#[derive(Default)]
struct IdleSample { wakes: u64, timers: u32, elapsed: u64, active: u64 }

struct PmClock(u16);
impl PmClock {
    unsafe fn now(&self) -> u32 {
        let value: u32;
        asm!("in eax, dx", in("dx") self.0, out("eax") value, options(nomem, nostack));
        value
    }
    unsafe fn elapsed(&self, start: u32) -> u32 {
        // Intervals here are shorter than one wrap of the 24-bit ACPI timer.
        self.now().wrapping_sub(start) & 0xff_ffff
    }
    unsafe fn delay(&self, ticks: u32) {
        let start = self.now();
        while self.elapsed(start) < ticks { spin_loop(); }
    }
}

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

    unsafe fn calibrate(self, clock: &PmClock) -> Result<(u32, u64), Error> {
        // VirtualBox Minimal advertises TSC and undivided APIC kHz. Use the
        // guest clocks' nominal rates rather than assuming a short PM-timer
        // calibration remains representative during virtual-clock catch-up.
        if __cpuid(1).ecx & (1 << 31) != 0 && __cpuid(0x40000000).eax >= 0x40000010 {
            let rates = __cpuid(0x40000010);
            let quantum = (rates.ebx as u64 * 1000 / (16 * 100)) as u32;
            if rates.eax != 0 && quantum != 0 { return Ok((quantum, rates.eax as u64 * 1000)); }
        }
        self.write(0x380, u32::MAX);
        let start = clock.now();
        let tsc_start = timestamp();
        clock.delay(PM_HZ / 10);
        let tsc_delta = timestamp() - tsc_start;
        let elapsed = clock.elapsed(start);
        let counted = u32::MAX - self.read(0x390);
        self.write(0x380, 0);
        if elapsed == 0 || counted == 0 || counted == u32::MAX { return Err(b"timer calibration"); }
        let per_10ms = (counted as u64 * PM_HZ as u64 / (100 * elapsed as u64)) as u32;
        let tsc_hz = tsc_delta * PM_HZ as u64 / elapsed as u64;
        if per_10ms == 0 || tsc_hz == 0 { return Err(b"zero timer interval"); }
        Ok((per_10ms, tsc_hz))
    }

    unsafe fn send(self, id: u8, command: u32, clock: &PmClock) -> Result<(), Error> {
        self.write(0x310, (id as u32) << 24);
        self.write(0x300, command);
        let start = clock.now();
        while self.read(0x300) & (1 << 12) != 0 {
            if clock.elapsed(start) > PM_HZ { return Err(b"IPI delivery timeout"); }
            spin_loop();
        }
        Ok(())
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
    clock: crate::monotonic::Clock,
    interrupts: AtomicU32,
    hlt_wakes: AtomicU32,
    complete: AtomicU32,
    phase: AtomicU32,
    idle: UnsafeCell<IdleSample>,
    descriptors: Option<Descriptors>,
    queue: UnsafeCell<Queue>,
    terminal: UnsafeCell<*mut crate::tty::Terminal>,
    load: &'static Load,
    released: [AtomicUsize; stress::TASKS],
}

// The owner changes queue state with IRQs disabled. The BSP prepares it before
// startup and reads/reaps it only after acquiring the completion signal.
unsafe impl Sync for Cpu {}
const _: () = assert!(core::mem::size_of::<Cpu>() <= PAGE && core::mem::size_of::<Load>() <= PAGE);

impl Cpu {
    unsafe fn create(frames: &mut Frames<'_>, apic: Lapic, id: u8, interval: u32, tsc_hz: u64,
                     descriptors: Option<Descriptors>, load: &'static Load, programs: &'static Programs,
                     rsp0: usize) -> Result<&'static Self, Error> {
        let addr = frames.alloc().ok_or(b"CPU allocation" as Error)?.into_address();
        let cpu = addr as *mut Self;
        cpu.write(Self { self_address: addr, syscall_user_rsp: UnsafeCell::new(0), syscall_stack: UnsafeCell::new(0),
                         rsp0, programs, apic, expected_id: id, interval, tsc_hz,
                         clock: crate::monotonic::Clock::new(tsc_hz),
                         interrupts: AtomicU32::new(0), hlt_wakes: AtomicU32::new(0),
                         complete: AtomicU32::new(0), phase: AtomicU32::new(0), terminal: UnsafeCell::new(ptr::null_mut()),
                         idle: UnsafeCell::new(IdleSample::default()), descriptors, load, queue: UnsafeCell::new(Queue::new()),
                         released: core::array::from_fn(|_| AtomicUsize::new(0)) });
        for i in 0..stress::TASKS {
            (*(*cpu).queue.get()).spawn(frames, allocation_task, i).ok_or(b"task stack" as Error)?;
        }
        Ok(&*cpu)
    }

    unsafe fn run_task(&self) -> Result<(), Error> {
        let id = self.apic.id();
        if id != self.expected_id { return Err(b"wrong executing APIC ID"); }
        if !self.clock.start(timestamp()) { return Err(b"monotonic clock initialization"); }
        asm!("wrmsr", in("ecx") 0xc0000101u32, in("eax") self.self_address as u32,
             in("edx") (self.self_address >> 32) as u32);
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
        Ok(())
    }

    unsafe fn schedule(&self) {
        (*self.queue.get()).active = true;
        self.apic.write(0x320, TIMER | (1 << 17)); // periodic time slices
        self.apic.write(0x380, self.interval);
        while ptr::addr_of!((*self.queue.get()).active).read_volatile() { wait_for_irq(); }
        self.apic.write(0x320, MASK | TIMER);
        self.apic.write(0x380, 0);
    }

    unsafe fn switch(&self, outgoing: usize, timer: bool) -> usize {
        let queue = &mut *self.queue.get();
        let scheduled = queue.active;
        let running = queue.running();
        // Periodic APIC IRQs are the fallback for timed sleeps and also
        // detect clock stalls; process exit may wake child waiters sooner.
        let now = self.clock.millis(timestamp()).unwrap_or(0);
        queue.wake_timed(now, timer);
        let next = queue.select(outgoing, timer);
        // Boot/idle probes own their one-shot timers while queue.active=false.
        // Only scheduled work uses time slices, and no tick is needed when all
        // tasks sleep on I/O. The UART can wake and select a reader directly.
        if scheduled {
            if !queue.running() {
                // An all-blocked timed wait still requires APIC ticks to
                // observe its deadline. Do not disable the last wake source.
                if !queue.has_timed_waiters() {
                    self.apic.write(0x320, MASK | TIMER);
                    self.apic.write(0x380, 0);
                }
            } else if !running {
                self.apic.write(0x320, TIMER | (1 << 17));
                self.apic.write(0x380, self.interval);
            }
        }
        let root = if let Some(p) = queue.process() {
            let top = queue.user_stack_top().unwrap();
            ptr::write_unaligned(self.rsp0 as *mut usize, top);
            self.syscall_stack.get().write(top);
            p.space.root
        } else { self.programs.kernel_root };
        if root != active_root() { asm!("mov cr3, {}", in(reg) root); }
        next
    }

    unsafe fn output(&self, bytes: &[u8]) {
        let terminal = *self.terminal.get();
        if terminal.is_null() { serial(bytes); } else { (*terminal).diagnostic(bytes); }
    }

    unsafe fn hex(&self, value: u64) {
        let mut digits = [b'0'; 16];
        for (i, d) in digits.iter_mut().enumerate() { *d = b"0123456789abcdef"[((value >> (60 - i*4)) & 15) as usize]; }
        self.output(&digits);
    }

    unsafe fn process_test(&self) -> Result<(), Error> {
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
        let snapshot = self.load.frames.with(|f| f.snapshot()).ok_or(b"process snapshot" as Error)?;
        let pid = self.load.frames.with(|f| (*self.queue.get()).spawn_process(f, self.programs, b"init", 0))
            .map_err(|_| b"user init ELF" as Error)?;
        self.schedule();
        let ok = self.load.frames.with(|f| {
            let q = &mut *self.queue.get();
            let result = q.collect(f, 0, pid);
            q.reap(f);
            let matched = snapshot.matches(f);
            snapshot.release(f);
            result == Ok(0) && matched && f.probe()
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
        self.apic.write(0x380, count);
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
            self.apic.write(0x380, (count as u64 * remaining_ms / 30_000).max(1) as u32);
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
    (*current_cpu().queue.get()).finish_current();
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
    if (*context).user() && (*context).rsp >= (1usize << 47) {
        return user_fault(13, 0, 0);
    }
    cpu.switch(context as usize, true)
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
    (*cpu.queue.get()).wake_io();
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
    (*cpu.queue.get()).wake_io();
    cpu.switch(context as usize, false)
}

/// A genuine CPL3 write protection fault may be a COW fault. Resolve it
/// in the current address space without killing the process, or reject it
/// as an ordinary isolation violation. The CPU returns to the *same* RIP.
pub unsafe fn user_cow_fault(addr: usize) -> bool {
    let cpu = current_cpu();
    let queue = &mut *cpu.queue.get();
    let Some(process) = queue.process() else { return false; };
    cpu.load.frames.with(|frames| process.space.resolve_cow(frames, addr)) == Some(true)
}

pub unsafe fn user_fault(vector: u64, error: u64, addr: u64) -> usize {
    let cpu = current_cpu();
    let q = &mut *cpu.queue.get();
    let p = q.process().unwrap();
    cpu.output(b"AGENTOS USER FAULT PID="); cpu.hex(p.pid as u64);
    cpu.output(b" PARENT="); cpu.hex(p.parent as u64); cpu.output(b" CR3="); cpu.hex(active_root() as u64);
    cpu.output(b" VECTOR="); cpu.hex(vector); cpu.output(b" ERROR="); cpu.hex(error);
    cpu.output(b" ADDRESS="); cpu.hex(addr); cpu.output(b"\r\n");
    cpu.load.frames.with(|f| q.terminate(256 + vector as usize, f));
    cpu.switch(0, false)
}

#[no_mangle]
unsafe extern "C" fn dispatch_syscall(ctx: &mut Context) -> usize {
    let cpu = current_cpu();
    if ctx.rsp >= 1usize << 47 { return user_fault(13, 0, 0); }
    let q = &mut *cpu.queue.get();
    let p = q.process_mut().unwrap();
    let pid = p.pid;
    let [a, b, c] = [ctx.registers[10], ctx.registers[11], ctx.registers[12]]; // RDI, RSI, RDX
    let result: isize = match ctx.registers[14] {
        0x10001 => pid as isize,
        // Current CPU-local monotonic millisecond epoch; never compare across CPUs.
        0x10010 => cpu.clock.millis(timestamp()).map(|v| v as isize).unwrap_or(-5),
        // SYS_WAIT_CHILD_UNTIL(child_pid, absolute_deadline_ms):
        // nonblocking if already reaped/finished, otherwise sleep until child
        // termination or the CPU-local monotonic deadline. Reaps on success.
        0x10011 => {
            if b > isize::MAX as usize { -22 }
            else if q.take_clock_error() { -5 }
            else {
                match cpu.load.frames.with(|f| q.collect(f, pid, a)) {
                    Ok(status) => status as isize,
                    Err(-11) => match cpu.clock.millis(timestamp()) {
                        None => -5,
                        Some(now) if now >= b as u64 => -110,
                        Some(now) => {
                            q.block_child(a, b as u64, now);
                            ctx.rip -= 2;
                            return cpu.switch(ctx as *mut Context as usize, false);
                        }
                    },
                    Err(error) => error,
                }
            }
        }
        // SYS_SLEEP_UNTIL(absolute_deadline_ms): timer-driven sleep. It must
        // not treat frozen TSC ticks as actual passage of time.
        0x10012 => {
            if a > isize::MAX as usize { -22 }
            else if q.take_clock_error() { -5 }
            else {
                match cpu.clock.millis(timestamp()) {
                    None => -5,
                    Some(now) if now >= a as u64 => 0,
                    Some(now) => {
                        q.block_sleep(a as u64, now);
                        ctx.rip -= 2;
                        return cpu.switch(ctx as *mut Context as usize, false);
                    }
                }
            }
        }
        op @ (0x10002 | 0x10008 | 0x1000d | 0x1000e) => {
            let io = match op {
                0x10002 => p.files.write(&p.space, a, b, c),
                0x10008 => cpu.load.frames.with(|f| p.files.read(f, &p.space, a, b, c)),
                0x1000d => cpu.load.frames.with(|f| p.files.message(f, crate::ipc::Operation::Send, p, a, b, c)),
                _ => cpu.load.frames.with(|f| p.files.message(f, crate::ipc::Operation::Receive, p, a, b, c)),
            };
            match io {
                Ok(crate::files::Io::Bytes(n)) => { q.wake_io(); n as isize }
                Ok(crate::files::Io::Sleep(wait)) => {
                    // No bytes committed. Retry SYSCALL with its original
                    // registers when data, space, or the last close wakes it.
                    ctx.rip -= 2;
                    q.block(wait);
                    return cpu.switch(ctx as *mut Context as usize, false);
                }
                Err(error) => { q.wake_io(); error }
            }
        }
        0x10003 => {
            cpu.output(b"AGENTOS USER EXIT PID="); cpu.hex(pid as u64);
            cpu.output(b" CR3="); cpu.hex(active_root() as u64); cpu.output(b" STATUS="); cpu.hex((a & 255) as u64); cpu.output(b"\r\n");
            cpu.load.frames.with(|f| q.terminate(a & 255, f));
            return cpu.switch(0, false);
        }
        0x10004 => {
            let mut name = [0; 64];
            if b == 0 || b > name.len() { -22 }
            else if p.space.read(a, &mut name[..b]).is_none() { EFAULT }
            else { cpu.load.frames.with(|f| q.spawn_process(f, cpu.programs, &name[..b], pid))
                       .map(|v| v as isize).unwrap_or_else(|e| e) }
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
            else { q.child_after(pid, a).map(|v| v as isize).unwrap_or_else(|e| e) },
        0x1000f => {
            let result = cpu.load.frames.with(|f| q.kill_child(f, pid, a));
            if matches!(result, Ok(0)) {
                cpu.output(b"AGENTOS USER KILL PID="); cpu.hex(a as u64);
                cpu.output(b" PARENT="); cpu.hex(pid as u64);
                cpu.output(b" STATUS=0000000000000089\r\n");
            }
            result.map(|v| v as isize).unwrap_or_else(|e| e)
        }
        0x10006 => { ctx.registers[14] = 0; return cpu.switch(ctx as *mut Context as usize, false); }
        0x10007 => {
            let mut path = [0; crate::vfs::PATH_MAX];
            if c != 0 { -30 } else if b > path.len() { -36 }
            else if p.space.read(a, &mut path[..b]).is_none() { EFAULT }
            else { cpu.programs.vfs.file(&path[..b]).and_then(|data|
                cpu.load.frames.with(|f| p.files.open(f, data))).map(|n| n as isize).unwrap_or_else(|e| e) }
        }
        0x10009 | 0x1000b => {
            let res = cpu.load.frames.with(|f| if ctx.registers[14] == 0x10009 {
                p.files.close(f, a)
            } else { p.files.dup2(f, a, b) });
            q.wake_io();
            res.map(|v| v as isize).unwrap_or_else(|e| e)
        }
        op @ (0x1000a | 0x1000c) => cpu.load.frames.with(|f| p.files.pair(f, &p.space, a, op == 0x1000c)).map(|v| v as isize).unwrap_or_else(|e| e),
        _ => -38,
    };
    ctx.registers[14] = result as usize;
    ctx as *mut Context as usize
}

#[no_mangle]
unsafe extern "C" fn ap_main(cpu: &'static Cpu) -> ! {
    cpu.descriptors.as_ref().unwrap().load();
    match cpu.apic.enable().and_then(|_| cpu.run_task()) {
        Ok(()) => {
            cpu.complete.store(1, Ordering::Release);
            while !cpu.load.started.load(Ordering::Acquire) { spin_loop(); }
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
                Ok(()) => cpu.complete.store(IDLE_FINISHED, Ordering::Release),
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

unsafe fn start_ap(cpu: &Cpu, root: usize, base: usize, stack: usize, clock: &PmClock) -> Result<(), Error> {
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
    fence(Ordering::SeqCst);
    cpu.apic.send(cpu.expected_id, 0xc500, clock)?; // level-triggered INIT, assert
    clock.delay(PM_HZ / 100 + 1);
    let sipi = 0x4600 | (base >> 12) as u32;
    cpu.apic.send(cpu.expected_id, sipi, clock)?;
    clock.delay(PM_HZ / 5000 + 1);
    cpu.apic.send(cpu.expected_id, sipi, clock)?;
    let start = clock.now();
    while cpu.complete.load(Ordering::Acquire) == 0 {
        if clock.elapsed(start) > 2 * PM_HZ { return Err(b"AP task timeout"); }
        spin_loop();
    }
    if cpu.complete.load(Ordering::Acquire) != 1 { return Err(b"AP task failed"); }
    Ok(())
}

pub unsafe fn run(platform: &Platform, base: usize, root: usize, mut frames: Frames<'static>,
                  bsp_rsp0: usize, archive: &'static [u8], log: &mut crate::BootLog<'_>) -> Result<(), Error> {
    if platform.legacy_pic { out(0x21, 0xff); out(0xa1, 0xff); }
    let apic = Lapic(platform.lapic);
    apic.enable()?;
    let clock = PmClock(platform.timer_port);
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
    let boot_cpu = load.frames.with(|f| Cpu::create(f, apic, bsp, interval, tsc_hz, None, load, programs, bsp_rsp0))?;
    boot_cpu.run_task()?;
    let mut cpus = [None; 255];
    cpus[bsp as usize] = Some(boot_cpu);
    for &id in ids {
        if id == bsp { continue; }
        let cpu = load.frames.with(|f| {
            let descriptors = Descriptors::new(f).ok_or(b"AP descriptors" as Error)?;
            let rsp0 = descriptors.rsp0_slot();
            Cpu::create(f, apic, id, interval, tsc_hz, Some(descriptors), load, programs, rsp0)
        })?;
        let stack = load.frames.with(|f| f.alloc()).ok_or(b"AP stack" as Error)?.into_address() + PAGE;
        start_ap(cpu, root, base, stack, &clock)?;
        cpus[id as usize] = Some(cpu);
    }
    log.event(1, b"PROCESSORS ONLINE");
    let baseline = load.frames.with(|f| f.snapshot()).ok_or(b"bitmap snapshot" as Error)?;
    load.started.store(true, Ordering::Release);
    boot_cpu.schedule();
    for cpu in cpus.iter().flatten() {
        if cpu.expected_id != bsp {
            while cpu.complete.load(Ordering::Acquire) != 2 { spin_loop(); }
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
        while cpu.complete.load(Ordering::Acquire) == 2 { spin_loop(); }
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
        while cpu.complete.load(Ordering::Acquire) == OOM_CHECKED { spin_loop(); }
        if cpu.complete.load(Ordering::Acquire) != PROCESSES_FINISHED { return Err(b"AP user processes"); }
    }
    serial(b"AGENTOS IDLE BEGIN TSC-HZ="); hex(tsc_hz); serial(b"\r\n");
    for cpu in cpus.iter().flatten() { cpu.phase.store(IDLE_PHASE, Ordering::Release); }
    boot_cpu.measure_idle()?;
    for cpu in cpus.iter().flatten() {
        if cpu.expected_id != bsp {
            while cpu.complete.load(Ordering::Acquire) == PROCESSES_FINISHED { spin_loop(); }
            if cpu.complete.load(Ordering::Acquire) != IDLE_FINISHED { return Err(b"AP idle sample"); }
        }
        let sample = &*cpu.idle.get();
        serial(b"AGENTOS IDLE APIC="); hex(cpu.expected_id as u64);
        serial(b" WAKES="); hex(sample.wakes);
        serial(b" TIMERS="); hex(sample.timers as u64);
        serial(b" TSC-TOTAL="); hex(sample.elapsed);
        serial(b" TSC-ACTIVE="); hex(sample.active); serial(b"\r\n");
    }
    Ok(())
}

/// Start only after the boot tests, idle measurements and framebuffer marker.
/// The BSP owns this terminal until all session descriptors have been reaped.
pub unsafe fn shell(platform: &Platform, info: &crate::BootInfo) -> Result<(), Error> {
    let cpu = current_cpu();
    let snapshot = cpu.load.frames.with(|f| f.snapshot()).ok_or(b"shell snapshot" as Error)?;
    let Some(storage) = cpu.load.frames.with(|f| f.alloc()) else {
        cpu.load.frames.with(|f| snapshot.release(f));
        return Err(b"TTY allocation");
    };
    let terminal = storage.address() as *mut crate::tty::Terminal;
    let mut initialized = false;
    let started = (|| -> Result<usize, Error> {
        terminal.write(crate::tty::Terminal::new(platform, cpu.expected_id)?);
        initialized = true;
        // The BSP TTY owns the mapped GOP framebuffer for the entire shell
        // session; the serial path remains available if GOP validation fails.
        if let Some(screen) = crate::fb_console::Console::new(
            info.framebuffer, info.width as usize, info.height as usize,
            info.stride as usize, info.pixel_format
        ) {
            (*terminal).attach_screen(screen);
        } else {
            let _ = crate::logger::LOGGER.record(timestamp(), cpu.expected_id as u32,
                crate::log_policy::Level::Error, b"TTY GOP unavailable");
        }
        let pid = cpu.load.frames.with(|f| (*cpu.queue.get()).spawn_process(f, cpu.programs, b"shell", 0))
            .map_err(|_| b"shell ELF" as Error)?;
        (*cpu.queue.get()).terminal(pid, terminal).map_err(|_| b"shell descriptors" as Error)?;
        let _ = crate::logger::LOGGER.record(timestamp(), cpu.expected_id as u32,
            crate::log_policy::Level::Info, b"shell started");
        serial(b"AGENTOS SHELL START PID="); hex(pid as u64); serial(b"\r\n");
        cpu.terminal.get().write(terminal);
        (*terminal).enable();
        cpu.schedule();
        Ok(pid)
    })();
    if initialized { (*terminal).disable(); }
    cpu.terminal.get().write(ptr::null_mut());
    let result = cpu.load.frames.with(|f| {
        let q = &mut *cpu.queue.get();
        let status = started.and_then(|pid| {
            if q.collect(f, 0, pid) == Ok(0) { Ok(pid) } else { Err(b"shell exit status" as Error) }
        });
        q.reap(f);
        f.release(storage);
        let matched = snapshot.matches(f);
        snapshot.release(f);
        if matched && f.probe() { status } else { Err(b"shell frame leak" as Error) }
    });
    let pid = result?;
    let _ = crate::logger::LOGGER.record(timestamp(), cpu.expected_id as u32,
        crate::log_policy::Level::Info, b"shell stopped");
    serial(b"AGENTOS SHELL STOP PID="); hex(pid as u64);
    serial(b" STATUS=0000000000000000 FRAMES=OK\r\n");
    Ok(())
}
