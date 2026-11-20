#![no_std]
#![no_main]

use core::{arch::asm, panic::PanicInfo, ptr::write_volatile};
mod frames;
mod paging;
mod exceptions;
mod acpi;
mod smp;
mod scheduler;
mod stress;
mod process;
mod files;
mod ipc;
mod vfs;
mod line;
mod ioapic;
mod tty;
mod keyboard;
mod ps2;
mod log_policy;
mod log_ring;
mod logger;

// Version 3, shared with boot/loader.c. Addresses are identity mapped at handoff.
#[repr(C)]
pub struct BootInfo {
    version: u64,
    framebuffer: *mut u32,
    width: u32,
    height: u32,
    stride: u32,
    pixel_format: u32,
    memory_map: u64,
    map_size: u64,
    descriptor_size: u64,
    descriptor_version: u64,
    rsdp: u64,
    initramfs: u64,
    initramfs_size: u64,
    image_base: u64,
    image_size: u64,
    stack_base: u64,
    ap_boot: usize,
    log_level: u64,
}

fn halt() -> ! {
    loop { unsafe { asm!("cli", "hlt", options(nomem, nostack)); } }
}

#[panic_handler]
fn panic(_: &PanicInfo) -> ! { halt() }

unsafe fn out(port: u16, value: u8) {
    asm!("out dx, al", in("dx") port, in("al") value, options(nomem, nostack));
}

unsafe fn input(port: u16) -> u8 {
    let value: u8;
    asm!("in al, dx", in("dx") port, out("al") value, options(nomem, nostack));
    value
}

const COM: u16 = 0x3f8;

unsafe fn init_serial() {
    out(COM + 1, 0);
    out(COM + 3, 0x80);
    out(COM, 1);
    out(COM + 1, 0);
    out(COM + 3, 3);
    out(COM + 2, 7);
    out(COM + 4, 3);
}

unsafe fn serial(message: &[u8]) {
    for &byte in message {
        for _ in 0..100_000 {
            let status: u8;
            asm!("in al, dx", in("dx") COM + 5, out("al") status, options(nomem, nostack));
            if status & 0x20 != 0 { out(COM, byte); break; }
        }
    }
}

// Five-bit rows, most significant pixel on the left.
fn glyph(c: u8) -> [u8; 7] {
    match c {
        b'A' => [14,17,17,31,17,17,17], b'G' => [14,17,16,23,17,17,14],
        b'E' => [31,16,16,30,16,16,31], b'N' => [17,25,25,21,19,19,17],
        b'T' => [31,4,4,4,4,4,4], b'O' => [14,17,17,17,17,17,14],
        b'S' => [15,16,16,14,1,1,30], b'K' => [17,18,20,24,20,18,17],
        b'R' => [30,17,17,30,20,18,17], b'L' => [16,16,16,16,16,16,31],
        b'B' => [30,17,17,30,17,17,30], b'C' => [14,17,16,16,16,17,14],
        b'D' => [30,17,17,17,17,17,30], b'F' => [31,16,16,30,16,16,16],
        b'H' => [17,17,17,31,17,17,17], b'I' => [14,4,4,4,4,4,14],
        b'J' => [7,2,2,2,2,18,12], b'M' => [17,27,21,21,17,17,17],
        b'P' => [30,17,17,30,16,16,16], b'Q' => [14,17,17,17,21,18,13],
        b'U' => [17,17,17,17,17,17,14], b'V' => [17,17,17,17,17,10,4],
        b'W' => [17,17,17,21,21,27,17], b'X' => [17,17,10,4,10,17,17],
        b'Y' => [17,17,10,4,4,4,4], b'Z' => [31,1,2,4,8,16,31],
        b'[' => [14,8,8,8,8,8,14], b']' => [14,2,2,2,2,2,14],
        b'1' => [4,12,4,4,4,4,14], _ => [0; 7],
    }
}

#[no_mangle]
pub unsafe extern "sysv64" fn kernel_main(info: &BootInfo) -> ! {
    const MESSAGE: &[u8] = b"AGENTOS KERNEL OK STAGE 1";
    init_serial();
    if info.version != 3 { serial(b"BOOT HANDOFF VERSION ERROR\r\n"); halt(); }
    let mut log = BootLog::new(info);
    log.event(1, b"KERNEL ENTRY");
    if info.descriptor_version != 1 || info.memory_map == 0 || info.map_size == 0 ||
       info.map_size > isize::MAX as u64 { log.event(0, b"INVALID MEMORY MAP"); halt(); }
    let map = core::slice::from_raw_parts(info.memory_map as *const u8, info.map_size as usize);
    let Some(mut frames) = frames::Frames::from_uefi(map, info.descriptor_size as usize) else {
        log.event(0, b"FRAME MAP INVALID"); halt();
    };
    if !frames.probe() { log.event(0, b"FRAME PROBE FAILED"); halt(); }
    log.event(1, b"PHYSICAL MEMORY READY");
    serial(b"AGENTOS PHYSICAL FRAMES OK\r\n");
    let Some(platform) = acpi::discover(info, map) else { log.event(0, b"ACPI DISCOVERY FAILED"); halt(); };
    log.event(2, b"ACPI TABLES READY");
    let Some(descriptors) = exceptions::Descriptors::new(&mut frames) else { log.event(0, b"IDT INIT FAILED"); halt(); };
    descriptors.load();
    smp::copy_startup(info.ap_boot);
    let Some(root) = paging::install(info, map, &mut frames, &platform) else {
        log.event(0, b"PAGING INIT FAILED"); halt();
    };
    serial(b"AGENTOS OWN CR3="); exceptions::hex(root as u64); serial(b"\r\n");
    if !exceptions::probe(info.stack_base) || !frames.probe() {
        log.event(0, b"EXCEPTION OR RAM PROBE FAILED"); halt();
    }
    serial(b"AGENTOS IDT OK: BP PF-NULL PF-GUARD PF-WP PF-NX\r\n");
    log.event(1, b"PAGING AND IDT READY");
    if info.initramfs < info.image_base || info.initramfs.checked_add(info.initramfs_size)
        .zip(info.image_base.checked_add(info.image_size)).map_or(true, |(end, limit)| end > limit) { log.event(0, b"INVALID INITRAMFS"); halt(); }
    let archive = core::slice::from_raw_parts(info.initramfs as *const u8, info.initramfs_size as usize);
    log.event(2, b"INITRAMFS LOCATED");
    if let Err(reason) = smp::run(&platform, info.ap_boot, root, frames, descriptors.rsp0_slot(), archive, &mut log) {
        log.event(0, b"SMP FAILED");
        serial(b"SMP FAILED: "); serial(reason); serial(b"\r\n"); halt();
    }
    log.event(1, b"BOOT COMPLETE");
    serial(MESSAGE);
    serial(b"\r\n");
    let scale = ((info.width as usize - 16) / (MESSAGE.len() * 6)).clamp(1, 4);
    draw(info, MESSAGE, 8, 16, scale);
    log.event(1, b"STARTING INTERACTIVE SHELL");
    if let Err(reason) = smp::shell(&platform) {
        log.event(0, b"SHELL FAILED");
        serial(b"SHELL FAILED: "); serial(reason); serial(b"\r\n");
    } else { log.event(1, b"INTERACTIVE SHELL STOPPED"); }
    halt()
}

fn draw(info: &BootInfo, line: &[u8], left: usize, top: usize, scale: usize) {
    for (i, &c) in line.iter().enumerate() {
        for (row, bits) in glyph(c).iter().enumerate() {
            for column in 0..5 {
                if bits & (16 >> column) == 0 { continue; }
                for dy in 0..scale { for dx in 0..scale {
                    let x = left + (i * 6 + column) * scale + dx;
                    let y = top + row * scale + dy;
                    if x < info.width as usize && y < info.height as usize {
                        unsafe { write_volatile(info.framebuffer.add(y * info.stride as usize + x), 0xffffff); }
                    }
                }}
            }
        }
    }
}

pub struct BootLog<'a> { info: &'a BootInfo, row: usize, scale: usize }
impl<'a> BootLog<'a> {
    fn new(info: &'a BootInfo) -> Self {
        let mut log = Self { info, row: 52, scale: ((info.width as usize - 16)/240).clamp(1, 2) };
        if info.log_level & 0x200 != 0 { log.clear_from(0); }
        log
    }
    fn clear_from(&mut self, top: usize) {
        for y in top..self.info.height as usize {
            for x in 0..self.info.width as usize {
                unsafe { write_volatile(self.info.framebuffer.add(y*self.info.stride as usize+x), 0x181818); }
            }
        }
    }
    fn event(&mut self, level: u64, message: &[u8]) {
        let severity = match level {
            0 => log_policy::Level::Error,
            1 => log_policy::Level::Info,
            _ => log_policy::Level::Debug,
        };
        // History is independent of display policy: even BOOT.LOG=none leaves
        // bounded diagnostics for later kernel inspection. The logger never
        // performs UART/MMIO while holding its nonblocking SMP/IRQ gate.
        let _ = logger::LOGGER.record(0, 0, severity, message);
        let policy = log_policy::Policy::new(self.info.log_level);
        let serial_enabled = policy.enabled(severity, log_policy::Sink::Serial);
        let screen_enabled = policy.enabled(severity, log_policy::Sink::Screen);
        if !serial_enabled && !screen_enabled { return; }
        let prefix = log_policy::Policy::prefix(severity);
        if serial_enabled {
            unsafe { serial(prefix); serial(message); serial(b"\r\n"); }
        }
        if !screen_enabled { return; }
        if self.row+7*self.scale > self.info.height as usize { self.clear_from(52); self.row = 52; }
        draw(self.info, prefix, 8, self.row, self.scale);
        draw(self.info, message, 8+6*self.scale*prefix.len(), self.row, self.scale);
        self.row += 9*self.scale;
    }
}
