use crate::{frames::Frames, halt, serial};
use core::{arch::global_asm, ptr};

global_asm!(include_str!("traps.S"));
extern "C" {
    static vectors: [u64; 32];
    static after_break: u8;
    static read_site: u8;
    static write_site: u8;
    static nx_target: u8;
    static probe_pass: u8;
    fn timer_gate();
    fn serial_gate();
    fn keyboard_gate();
    fn spurious_gate();
    fn load_descriptors(gdt: &Descriptor, idt: &Descriptor);
    fn probe_break() -> u64;
    fn probe_read(addr: u64) -> u64;
    fn probe_ro(addr: u64) -> u64;
    fn probe_nx(addr: u64) -> u64;
}

#[repr(C, packed)]
struct Descriptor { limit: u16, base: u64 }

pub struct Descriptors { gdt: usize, idt: usize }

impl Descriptors {
    pub unsafe fn new(frames: &mut Frames<'_>) -> Option<Self> {
        let idt = frames.alloc_zeroed()?.into_address();
        let gdt = frames.alloc_zeroed()?.into_address();
        let emergency_top = frames.alloc()?.into_address() + 4096;
        // GDT and the 104-byte long-mode TSS share a permanently owned frame.
        let tss = gdt + 64;
        ptr::write_unaligned((tss + 36) as *mut u64, emergency_top as u64); // IST1
        ptr::write_unaligned((tss + 102) as *mut u16, 104); // no I/O bitmap
        let slots = gdt as *mut u64;
        slots.add(1).write(0x00af9b000000ffff);
        slots.add(2).write(0x00cf93000000ffff);
        let base = tss as u64;
        slots.add(3).write(103 | ((base & 0xffffff) << 16) | (0x89 << 40) |
                           (((base >> 24) & 255) << 56));
        slots.add(4).write(base >> 32);
        slots.add(5).write(0x00cff3000000ffff); // DPL3 data
        slots.add(6).write(0x00affb000000ffff); // DPL3 long-mode code
        let install_gate = |i: usize, addr: u64| {
            let gate = (idt as *mut u64).add(2*i);
            let ist = u64::from(i == 8);
            gate.write((addr & 0xffff) | (8 << 16) | (ist << 32) | (0x8e << 40) |
                       ((addr & 0xffff0000) << 32));
            gate.add(1).write(addr >> 32);
        };
        for (i, &addr) in vectors.iter().enumerate() { install_gate(i, addr); }
        install_gate(0xe0, timer_gate as usize as u64);
        install_gate(crate::tty::VECTOR as usize, serial_gate as usize as u64);
        install_gate(crate::tty::KEYBOARD_VECTOR as usize, keyboard_gate as usize as u64);
        install_gate(0xff, spurious_gate as usize as u64);
        Some(Self { gdt, idt })
    }

    pub unsafe fn load(&self) {
        load_descriptors(&Descriptor { limit: 55, base: self.gdt as u64 },
                         &Descriptor { limit: 4095, base: self.idt as u64 });
    }
    pub fn rsp0_slot(&self) -> usize { self.gdt + 64 + 4 }
}

#[repr(C)]
struct Trap { vector: u64, error: u64, rip: u64, cs: u64 }

pub(super) unsafe fn hex(value: u64) {
    let mut digits = [b'0'; 16];
    for (i, d) in digits.iter_mut().enumerate() {
        *d = b"0123456789abcdef"[((value >> (60 - i*4)) & 15) as usize];
    }
    serial(&digits);
}

#[no_mangle]
unsafe extern "C" fn dispatch_exception(trap: &mut Trap, cr2: u64, operand: u64) -> usize {
    if trap.cs & 3 == 3 && matches!(trap.vector, 0 | 1 | 3..=7 | 10..=14 | 16 | 17 | 19 | 21) {
        // Present + write + user is the only fault that may promote a
        // previously shared COW leaf. An NX access, missing page or
        // supervisor-only page remains a fatal fault for the user task.
        if trap.vector == 14 && trap.error & 7 == 7 &&
           crate::smp::user_cow_fault(cr2 as usize) {
            return 0; // IRETQ retries the faulting user instruction
        }
        return crate::smp::user_fault(trap.vector, trap.error, cr2);
    }
    let nx = ptr::addr_of!(nx_target) as u64;
    let expected = match (trap.vector, trap.error) {
        (3, 0) => trap.rip == ptr::addr_of!(after_break) as u64,
        (14, 0) => trap.rip == ptr::addr_of!(read_site) as u64 && cr2 == operand,
        (14, 3) => trap.rip == ptr::addr_of!(write_site) as u64 && cr2 == nx && operand == nx,
        (14, 17) => trap.rip == nx && cr2 == nx && operand == nx,
        _ => false,
    };
    if expected {
        trap.rip = ptr::addr_of!(probe_pass) as u64;
        return 0;
    }
    serial(b"FATAL VECTOR="); hex(trap.vector);
    serial(b" ERROR="); hex(trap.error);
    serial(b" RIP="); hex(trap.rip);
    serial(b" CR2="); hex(cr2);
    serial(b"\r\n"); halt();
}

pub unsafe fn probe(guard: u64) -> bool {
    let ro = ptr::addr_of!(nx_target) as u64;
    probe_break() == 1 && probe_read(0) == 1 && probe_read(guard) == 1 &&
        probe_ro(ro) == 1 && probe_nx(ro) == 1
}
