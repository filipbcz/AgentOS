#![no_std]
#![no_main]

use core::{arch::asm, panic::PanicInfo, ptr::write_volatile};
mod frames;
mod stack;
mod paging;
mod exceptions;
mod acpi;
mod pci;
mod pci_irq;
mod dma;
mod ahci;
mod block;
#[cfg(nvme_block_acceptance)]
mod nvme;
#[cfg(virtio_net_acceptance)]
mod virtio_net;
#[cfg(xhci_acceptance)]
mod xhci;
#[cfg(any(ahci_block_acceptance, nvme_block_acceptance))]
mod block_acceptance;
mod smp;
mod scheduler;
mod stress;
mod process;
mod lifecycle;
mod hpet;
mod native_abi;
mod files;
mod ipc;
mod vfs;
mod line;
mod ioapic;
mod tty;
mod legacy_uart;
mod keyboard;
mod ps2;
mod log_policy;
mod log_ring;
mod logger;
mod monotonic;
mod timer;
mod fb_console;
use fb_console::glyph;

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
#[allow(non_snake_case)]
fn panic(aInfo: &PanicInfo) -> ! {
    // Keep failure evidence available even before a terminal exists. Bounded
    // formatting uses no allocator and cannot recursively overflow its buffer.
    struct PanicText { fBytes: [u8; 256], fLength: usize }
    impl core::fmt::Write for PanicText {
        fn write_str(&mut self, aText: &str) -> core::fmt::Result {
            let pLength = aText.len().min(self.fBytes.len() - self.fLength);
            self.fBytes[self.fLength..self.fLength + pLength].copy_from_slice(&aText.as_bytes()[..pLength]);
            self.fLength += pLength;
            Ok(())
        }
    }
    let mut pText = PanicText { fBytes: [0; 256], fLength: 0 };
    let _ = core::fmt::write(&mut pText, format_args!("AGENTOS KERNEL PANIC: {}\r\n", aInfo));
    unsafe { serial(&pText.fBytes[..pText.fLength]); }
    halt()
}

unsafe fn out(port: u16, value: u8) {
    asm!("out dx, al", in("dx") port, in("al") value, options(nomem, nostack));
}

unsafe fn input(port: u16) -> u8 {
    let value: u8;
    asm!("in al, dx", in("dx") port, out("al") value, options(nomem, nostack));
    value
}

const COM: u16 = 0x3f8;
static SERIAL_LOCK: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);
static SERIAL_PRESENT: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

pub(crate) fn serial_available() -> bool {
    SERIAL_PRESENT.load(core::sync::atomic::Ordering::Acquire)
}

unsafe fn init_serial() {
    SERIAL_PRESENT.store(legacy_uart::initialize(COM), core::sync::atomic::Ordering::Release);
}

unsafe fn serial(message: &[u8]) {
    if !serial_available() { return; }
    // Each call publishes one complete message. Mask local interrupts before
    // taking the SMP gate, so the UART IRQ cannot recursively wait on it.
    let flags: usize;
    asm!("pushfq", "pop {}", "cli", out(reg) flags);
    while SERIAL_LOCK.compare_exchange_weak(false, true, core::sync::atomic::Ordering::Acquire,
        core::sync::atomic::Ordering::Relaxed).is_err() { core::hint::spin_loop(); }
    for &byte in message {
        if !legacy_uart::transmit(COM, byte) { break; }
    }
    SERIAL_LOCK.store(false, core::sync::atomic::Ordering::Release);
    if flags & 0x200 != 0 { asm!("sti", options(nomem, nostack)); }
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
    smp::copy_startup(info.ap_boot);
    let windows = platform.pci.windows();
    let Some(root) = paging::install(info, map, &mut frames, &platform, windows.iter().map(|w| w.mapping())) else {
        log.event(0, b"PAGING INIT FAILED"); halt();
    };
    // IST stacks use the guarded pool in the newly active kernel page tables.
    let Some(descriptors) = exceptions::Descriptors::new(&mut frames) else { log.event(0, b"IDT INIT FAILED"); halt(); };
    descriptors.load();
    if let Err(reason) = hpet::init(platform.hpet) {
        serial(b"GLOBAL CLOCK FAILED: "); serial(reason); serial(b"\r\n"); halt();
    }
    serial(b"AGENTOS OWN CR3="); exceptions::hex(root as u64); serial(b"\r\n");
    if !exceptions::probe(info.stack_base) || !frames.probe() {
        log.event(0, b"EXCEPTION OR RAM PROBE FAILED"); halt();
    }
    serial(b"AGENTOS IDT OK: BP PF-NULL PF-GUARD PF-WP PF-NX\r\n");
    log.event(1, b"PAGING AND IDT READY");
    if let Err(reason) = pci::inventory(windows).and_then(|devices| {
        if let Some(device) = devices.oxford { device.bind(root, &mut frames)?; }
        #[cfg(ahci_dma_acceptance)]
        {
            devices.ahci.ok_or(b"AHCI missing" as &[u8])?.exercise(root, &mut frames)?;
        }
        #[cfg(ahci_block_acceptance)]
        {
            let mut disk = ahci::AhciDisk::open(devices.ahci.ok_or(b"AHCI missing" as &[u8])?, root, &mut frames)?;
            let result = block_acceptance::run(&mut disk);
            disk.close(&mut frames)?;
            result?;
        }
        #[cfg(nvme_block_acceptance)]
        {
            if devices.nvme_count != 1 { return Err(b"NVMe profile requires exactly one controller" as &[u8]); }
            let mut disk = nvme::NvmeDisk::open(devices.nvme.ok_or(b"NVMe ECAM/BAR missing" as &[u8])?, root, &mut frames)?;
            let result = block_acceptance::run(&mut disk);
            disk.close(&mut frames)?;
            result?;
        }
        #[cfg(virtio_net_acceptance)]
        {
            if devices.virtio_net_count != 1 { return Err(b"VirtIO profile requires exactly one network controller" as &[u8]); }
            let mut net = virtio_net::VirtioNet::open(devices.virtio_net.ok_or(b"VirtIO modern ECAM missing" as &[u8])?, root, &mut frames)?;
            let result = virtio_net::exercise(&mut net);
            net.close(&mut frames)?;
            result?;
        }
        #[cfg(xhci_acceptance)]
        {
            if devices.xhci_count != 1 { return Err(b"xHCI profile requires exactly one controller" as &[u8]); }
            let mut hc = xhci::Xhci::open(devices.xhci.ok_or(b"xHCI ECAM/BAR missing" as &[u8])?, root, &mut frames)?;
            let result = hc.exercise();
            hc.close(&mut frames)?;
            result?;
        }
        Ok(())
    }) {
        serial(b"AGENTOS PCI FAILED: "); serial(reason); serial(b"\r\n"); halt();
    }
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
    if let Err(reason) = smp::shell(&platform, info) {
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
        let serial_requested = policy.enabled(severity, log_policy::Sink::Serial);
        let serial_enabled = serial_requested && serial_available();
        // A serial-only configuration must not discard diagnostics simply
        // because the optional legacy UART is absent. Explicit none still
        // suppresses ordinary output; the history above is always recorded.
        let screen_enabled = policy.enabled(severity, log_policy::Sink::Screen)
            || (serial_requested && !serial_available());
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
