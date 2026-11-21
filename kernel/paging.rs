use crate::{frames::{ram, Frames}, BootInfo};
use core::{arch::{asm, x86_64::__cpuid}, ptr};

const PAGE: usize = 4096;
const PRESENT: u64 = 1;
const WRITE: u64 = 2;
const NX: u64 = 1 << 63;
const MMIO: u64 = NX | WRITE | (1 << 3) | (1 << 4);
const ADDRESS: u64 = 0x000f_ffff_ffff_f000;
const USER: u64 = 4;
// OS-owned software PTE bit. A COW page is present and user-readable, but
// not hardware-writable until the last-owner promotion or a private copy.
const COW: u64 = 1 << 9;
pub const USER_BASE: usize = 1 << 39;
pub const USER_END: usize = 2 << 39;

// A single private PML4 slot. All inherited slots remain supervisor-only.
pub struct UserSpace { pub root: usize }

impl UserSpace {
    pub unsafe fn new(frames: &mut Frames<'_>, kernel: usize) -> Option<Self> {
        if *((kernel as *const u64).add(1)) != 0 { return None; }
        let root = frames.alloc()?.into_address();
        ptr::copy_nonoverlapping(kernel as *const u64, root as *mut u64, 512);
        Some(Self { root })
    }

    /// Clone the user subtree without copying its private data pages.
    /// Construct the child first and roll back on any OOM; only after a
    /// complete successful clone do we write-protect the parent's writable
    /// PTEs. Both address spaces are pinned to the owner CPU and this method
    /// executes with its interrupts masked by SharedFrames::with.
    pub unsafe fn fork_cow(&self, frames: &mut Frames<'_>, kernel: usize) -> Result<Self, isize> {
        unsafe fn copy_branch(frames: &mut Frames<'_>, from: usize, to: usize, level: u8) -> Option<()> {
            for i in 0..512 {
                let value = *((from as *const u64).add(i));
                if value & PRESENT == 0 { continue; }
                if level == 1 {
                    // Only writable pages become COW. A read-only executable
                    // page remains read-only in both processes.
                    frames.retain((value & ADDRESS) as usize)?;
                    let flags = if value & WRITE != 0 { (value & !WRITE) | COW } else { value };
                    *((to as *mut u64).add(i)) = flags;
                } else {
                    let branch = frames.alloc_zeroed()?.into_address();
                    *((to as *mut u64).add(i)) = branch as u64 | (value & !ADDRESS);
                    copy_branch(frames, (value & ADDRESS) as usize, branch, level-1)?;
                }
            }
            Some(())
        }
        unsafe fn protect_branch(table: usize, level: u8) {
            for i in 0..512 {
                let entry = (table as *mut u64).add(i);
                let value = *entry;
                if value & PRESENT == 0 { continue; }
                if level == 1 {
                    if value & WRITE != 0 { *entry = (value & !WRITE) | COW; }
                } else {
                    protect_branch((value & ADDRESS) as usize, level-1);
                }
            }
        }
        let child = Self::new(frames, kernel).ok_or(-12isize)?;
        let original = *((self.root as *const u64).add(1));
        if original & PRESENT != 0 {
            let Some(first) = frames.alloc_zeroed() else {
                child.release(frames);
                return Err(-12);
            };
            *((child.root as *mut u64).add(1)) = first.into_address() as u64 | (original & !ADDRESS);
            if copy_branch(frames, (original & ADDRESS) as usize,
                           (*((child.root as *const u64).add(1)) & ADDRESS) as usize, 3).is_none() {
                // All successfully retained leaf pages and allocated child
                // tables are now owned by child.release, even on partial OOM.
                child.release(frames);
                return Err(-12);
            }
            protect_branch((original & ADDRESS) as usize, 3);
            // User leaf PTE updates need a TLB shootdown. Only one CPU can
            // execute this process (per-CPU scheduler); parent CR3 is active.
            #[cfg(not(test))]
            asm!("mov cr3, {}", in(reg) self.root, options(nostack));
        }
        Ok(child)
    }

    unsafe fn leaf(&self, va: usize) -> Option<*mut u64> {
        if !(USER_BASE..USER_END).contains(&va) { return None; }
        let mut node = self.root;
        for shift in [39, 30, 21] {
            let value = *((node as *const u64).add((va >> shift) & 511));
            if value & (PRESENT | USER) != PRESENT | USER { return None; }
            node = (value & ADDRESS) as usize;
        }
        Some((node as *mut u64).add((va >> 12) & 511))
    }

    /// Resolve a private writable user page before a user #PF or a kernel
    /// copy_to_user. Read-only executable or unmapped addresses are rejected.
    pub unsafe fn resolve_cow(&self, frames: &mut Frames<'_>, va: usize) -> Option<bool> {
        let leaf = self.leaf(va)?;
        let previous = *leaf;
        if previous & (PRESENT | USER | COW) != PRESENT | USER | COW ||
           previous & WRITE != 0 { return Some(false); }
        let old = (previous & ADDRESS) as usize;
        let count = frames.references(old)?;
        let address = if count == 1 { old } else {
            let fresh = frames.alloc()?.into_address();
            ptr::copy_nonoverlapping(old as *const u8, fresh as *mut u8, PAGE);
            fresh
        };
        *leaf = ((previous & !ADDRESS) & !COW) | WRITE | address as u64;
        // If this was shared, the old mapping has lost one reference. If
        // unique, promotion needs no allocation or reference adjustment.
        if count > 1 {
            frames.release(crate::frames::Frame::from_owned_address(old));
        }
        #[cfg(not(test))]
        asm!("invlpg [{}]", in(reg) (va & !(PAGE-1)), options(nostack, preserves_flags));
        Some(true)
    }

    pub unsafe fn map(&self, frames: &mut Frames<'_>, va: usize, write: bool, execute: bool) -> Result<usize, isize> {
        if !(USER_BASE..USER_END).contains(&va) || va % PAGE != 0 || (write && execute) { return Err(-8); }
        let mut node = self.root;
        for shift in [39, 30, 21] {
            let entry = (node as *mut u64).add((va >> shift) & 511);
            if *entry == 0 {
                *entry = frames.alloc_zeroed().ok_or(-12isize)?.into_address() as u64 | USER | PRESENT | WRITE;
            }
            node = (*entry & ADDRESS) as usize;
        }
        let leaf = (node as *mut u64).add((va >> 12) & 511);
        if *leaf != 0 { return Err(-8); }
        let page = frames.alloc_zeroed().ok_or(-12isize)?.into_address();
        *leaf = page as u64 | USER | PRESENT | (if write { WRITE } else { 0 }) | (if execute { 0 } else { NX });
        Ok(page)
    }

    unsafe fn translate(&self, va: usize, writing: bool) -> Option<usize> {
        if !(USER_BASE..USER_END).contains(&va) { return None; }
        let mut node = self.root;
        for shift in [39, 30, 21, 12] {
            let entry = *((node as *const u64).add((va >> shift) & 511));
            let required = USER | PRESENT | if writing { WRITE } else { 0 };
            if entry & required != required { return None; }
            node = (entry & ADDRESS) as usize;
        }
        Some(node + va % PAGE)
    }

    pub fn read(&self, va: usize, dst: &mut [u8]) -> Option<()> {
        va.checked_add(dst.len())?;
        let mut done = 0;
        while done < dst.len() {
            let addr = va + done;
            let n = (PAGE - addr % PAGE).min(dst.len() - done);
            unsafe { ptr::copy_nonoverlapping(self.translate(addr, false)? as *const u8, dst.as_mut_ptr().add(done), n); }
            done += n;
        }
        Some(())
    }

    pub fn writable(&self, frames: &mut Frames<'_>, va: usize, len: usize) -> Option<()> {
        let end = va.checked_add(len)?;
        let mut pos = va;
        // Validate the complete destination before making any COW mapping
        // writable. It must have either WRITE or the explicit COW marker.
        while pos < end {
            let value = unsafe { *self.leaf(pos)? };
            if value & (PRESENT | USER) != PRESENT | USER ||
               value & (WRITE | COW) == 0 { return None; }
            pos += (PAGE - pos % PAGE).min(end-pos);
        }
        pos = va;
        while pos < end {
            if unsafe { self.translate(pos, true) }.is_none() {
                if unsafe { self.resolve_cow(frames, pos) } != Some(true) { return None; }
            }
            pos += (PAGE - pos % PAGE).min(end-pos);
        }
        Some(())
    }

    pub fn write(&self, frames: &mut Frames<'_>, va: usize, src: &[u8]) -> Option<()> {
        self.writable(frames, va, src.len())?;
        let mut done = 0;
        while done < src.len() {
            let addr = va + done;
            let n = (PAGE - addr % PAGE).min(src.len() - done);
            unsafe { ptr::copy_nonoverlapping(src.as_ptr().add(done), self.translate(addr, true)? as *mut u8, n); }
            done += n;
        }
        Some(())
    }

    // Caller has switched away from this root. No other CPU runs the process.
    pub unsafe fn release(self, frames: &mut Frames<'_>) {
        unsafe fn free_branch(frames: &mut Frames<'_>, page: usize, level: u8) {
            if level > 0 {
                for &entry in core::slice::from_raw_parts(page as *const u64, 512) {
                    if entry & PRESENT != 0 { free_branch(frames, (entry & ADDRESS) as usize, level - 1); }
                }
            }
            frames.release(crate::frames::Frame::from_owned_address(page));
        }
        let branch = *((self.root as *const u64).add(1));
        if branch & PRESENT != 0 { free_branch(frames, (branch & ADDRESS) as usize, 3); }
        free_branch(frames, self.root, 0);
    }
}

extern "C" { static kernel_begin: u8; static kernel_ro: u8; static kernel_rw: u8; static kernel_end: u8; }

struct Tables<'a, 'b> {
    root: usize,
    frames: &'a mut Frames<'b>,
}

impl Tables<'_, '_> {
    // Build only before publishing CR3. Conflicting aliases of the same identity
    // address indicate an invalid handoff; never silently widen permissions.
    unsafe fn identity(&mut self, start: usize, size: usize, flags: u64) -> Option<()> {
        if size == 0 { return Some(()); }
        let end = start.checked_add(size)?;
        if start < PAGE || end > 1 << 47 { return None; }
        let first_page = start & !(PAGE - 1);
        for page in (first_page..end).step_by(PAGE) {
            let mut node = self.root;
            for shift in [39, 30, 21] {
                let entry = ((node as *mut u64).add((page >> shift) & 511)).as_mut()?;
                if *entry == 0 {
                    *entry = self.frames.alloc_zeroed()?.into_address() as u64 | PRESENT | WRITE;
                }
                node = (*entry & ADDRESS) as usize;
            }
            let leaf = (node as *mut u64).add((page >> 12) & 511);
            let value = page as u64 | flags | PRESENT;
            if *leaf != 0 && *leaf != value { return None; }
            *leaf = value;
        }
        Some(())
    }
}

/// Called once by the BSP with interrupts disabled, on the loader-provided stack.
pub unsafe fn install(info: &BootInfo, map: &[u8], frames: &mut Frames<'_>, platform: &crate::acpi::Platform) -> Option<usize> {
    let cr4: usize;
    asm!("mov {}, cr4", out(reg) cr4);
    if cr4 & (1 << 12) != 0 || __cpuid(0x80000000).eax < 0x80000001 ||
       __cpuid(0x80000001).edx & (1 << 20) == 0 { return None; }
    let root = frames.alloc_zeroed()?.into_address();
    let mut tables = Tables { root, frames };
    for (first, end) in map.chunks_exact(info.descriptor_size as usize).filter_map(ram) {
        tables.identity(first * PAGE, (end-first) * PAGE, WRITE | NX)?;
    }
    let begin = ptr::addr_of!(kernel_begin) as usize;
    let ro = ptr::addr_of!(kernel_ro) as usize;
    let rw = ptr::addr_of!(kernel_rw) as usize;
    let end = ptr::addr_of!(kernel_end) as usize;
    // All three boundaries come from kernel.ld and are page aligned.
    // A writable global must never share a page with executable or read-only
    // data. Validate defensively before allocating the kernel page tables.
    if begin & (PAGE-1) != 0 || ro & (PAGE-1) != 0 ||
       rw & (PAGE-1) != 0 || end & (PAGE-1) != 0 ||
       !(begin < ro && ro <= rw && rw <= end) ||
       end-begin > 16*1024*1024 { return None; }
    tables.identity(begin, ro-begin, 0)?;         // executable, never writable
    tables.identity(ro, rw-ro, NX)?;              // data, read-only, NX
    tables.identity(rw, end-rw, WRITE | NX)?;     // .data/.bss, writable, NX
    tables.identity(info.image_base as usize, info.image_size as usize, NX)?;
    tables.identity(info.memory_map as usize, info.map_size as usize, NX)?;
    if info.rsdp != 0 { tables.identity(info.rsdp as usize, 36, NX)?; }
    // The lowest of the eight loader stack pages remains an unmapped guard.
    tables.identity(info.stack_base as usize + PAGE, 7*PAGE, WRITE | NX)?;
    tables.identity(info.ap_boot, PAGE, 0)?;
    tables.identity(info.ap_boot + PAGE, PAGE, WRITE | NX)?;
    tables.identity(platform.lapic, PAGE, MMIO)?;
    for io in &platform.io_apics[..platform.io_count] { tables.identity(io.address, PAGE, MMIO)?; }
    tables.identity(info.framebuffer as usize, info.stride as usize * info.height as usize * 4, MMIO)?;

    // Firmware may leave global translations in the TLB. Flush those as well.
    asm!("rdmsr", "bts eax, 11", "wrmsr", in("ecx") 0xc0000080u32,
         out("eax") _, out("edx") _);
    let active: usize;
    asm!("mov cr4, {cr4}", "mov cr3, {root}", "mov {tmp}, cr0",
         "bts {tmp}, 16", "mov cr0, {tmp}", "mov {tmp}, cr3",
         cr4=in(reg) (cr4 & !(1 << 7)), root=in(reg) root, tmp=out(reg) active);
    (active == root).then_some(root)
}
