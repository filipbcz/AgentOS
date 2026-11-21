#![allow(non_snake_case)]
use crate::{frames::Frames, paging::{UserSpace, USER_BASE, USER_END}};
use core::sync::atomic::{AtomicUsize, Ordering};

pub const EFAULT: isize = -14;
const ENOEXEC: isize = -8;
const ENOMEM: isize = -12;
const PAGE: usize = 4096;
const STACK_PAGES: usize = 4;
pub const STACK: usize = USER_END - 16;

pub struct Programs {
    pub vfs: crate::vfs::Vfs,
    pub kernel_root: usize,
    next_pid: AtomicUsize,
    pub fRegistry: crate::lifecycle::Registry,
}
#[derive(Clone, Copy)]
pub struct Credentials { pub uid: u32, pub gid: u32 }
impl Credentials {
    pub const BOOT_USER: Self = Self { uid: 1000, gid: 1000 };
}
pub struct Process {
    pub credentials: Credentials,
    pub space: UserSpace,
    pub entry: usize,
    pub pid: usize,
    /// Owner-local cache. Cross-CPU parent/status decisions use fLifecycle;
    /// synchronizeMetadata refreshes this cache at kernel entry.
    pub parent: usize,
    pub status: Option<usize>,
    pub files: crate::files::Descriptors,
    pub fLifecycle: crate::lifecycle::Entry,
}

impl Process {
    pub fn synchronizeMetadata(&mut self, aFrames: &mut Frames<'_>) -> crate::lifecycle::Snapshot {
        let pState = self.fLifecycle.snapshot(aFrames);
        self.parent = pState.fParent;
        self.status = pState.fStatus;
        pState
    }

    pub fn finish(&mut self, aFrames: &mut Frames<'_>, aStatus: usize) {
        if self.status.is_some() { return; }
        self.files.close_all(aFrames);
        self.fLifecycle.finish(aFrames, aStatus);
        self.synchronizeMetadata(aFrames);
    }

    /// The owner must have switched away from this address space and its
    /// kernel stack before reclaiming a process marked collected remotely.
    pub fn release(self, aFrames: &mut Frames<'_>) {
        self.files.release(aFrames);
        unsafe { self.space.release(aFrames); }
        self.fLifecycle.release(aFrames);
    }
}

fn word<const N: usize>(data: &[u8], at: usize) -> Option<[u8; N]> {
    data.get(at..at.checked_add(N)?)?.try_into().ok()
}
fn u16_at(data: &[u8], at: usize) -> Option<u16> { Some(u16::from_le_bytes(word(data, at)?)) }
fn u64_at(data: &[u8], at: usize) -> Option<usize> { Some(u64::from_le_bytes(word(data, at)?) as usize) }

impl Programs {
    /// Reserve a never-reused process ID, including across fork and spawn.
    pub fn allocate_pid(&self) -> Result<usize, isize> {
        self.next_pid.fetch_update(Ordering::Relaxed, Ordering::Relaxed,
            |p| (p < isize::MAX as usize).then_some(p + 1)).map_err(|_| -11isize)
    }

    pub fn new(archive: &'static [u8], kernel_root: usize) -> Self {
        Self { vfs: crate::vfs::Vfs::new(archive), kernel_root, next_pid: AtomicUsize::new(1),
            fRegistry: crate::lifecycle::Registry::new() }
    }

    /// Programs must remain at a stable address while any returned Process
    /// lives. Production Programs is allocated once before CPU startup.
    pub unsafe fn load(&self, frames: &mut Frames<'_>, name: &[u8], parent: usize, credentials: Credentials) -> Result<Process, isize> {
        let elf = self.vfs.file(name)?;
        // Discriminate the native ABI before even allocating a private root.
        // Rejecting an invalid/unmarked note needs no page-table/data frames.
        if !crate::native_abi::validate(elf) { return Err(ENOEXEC); }
        let space = UserSpace::new(frames, self.kernel_root).ok_or(ENOMEM)?;
        let result = load_elf(&space, elf).and_then(|entry| {
            let pid = self.allocate_pid()?;
            let files = crate::files::Descriptors::new(frames).ok_or(ENOMEM)?;
            let lifecycle = match self.fRegistry.register(frames, pid, parent) {
                Ok(pEntry) => pEntry,
                Err(pError) => { files.release(frames); return Err(pError); }
            };
            Ok((entry, pid, files, lifecycle))
        });
        match result {
            Ok((entry, pid, files, lifecycle)) => Ok(Process {
                space, entry, pid, parent, credentials, status: None, files, fLifecycle: lifecycle,
            }),
            Err(error) => { space.release(frames); Err(error) }
        }
    }
}

unsafe fn load_elf(space: &UserSpace, elf: &'static [u8]) -> Result<usize, isize> {
    // Programs::load validated the native ABI before creating this space.
    if elf.get(..7) != Some(b"\x7fELF\x02\x01\x01") || u16_at(elf, 16) != Some(2) ||
        u16_at(elf, 18) != Some(62) || word(elf, 20) != Some(1u32.to_le_bytes()) ||
        u16_at(elf, 52) != Some(64) || u16_at(elf, 54) != Some(56) { return Err(ENOEXEC); }
    let entry = u64_at(elf, 24).ok_or(ENOEXEC)?;
    let phoff = u64_at(elf, 32).ok_or(ENOEXEC)?;
    let size = 56 * u16_at(elf, 56).ok_or(ENOEXEC)? as usize;
    let headers = elf.get(phoff..phoff.checked_add(size).ok_or(ENOEXEC)?).ok_or(ENOEXEC)?;
    let mut executable_entry = false;
    for h in headers.chunks_exact(56) {
        match u32::from_le_bytes(word(h, 0).unwrap()) {
            1 => (),
            2 | 3 => return Err(ENOEXEC), // dynamic linking and interpreters
            _ => continue,
        }
        let flags = u32::from_le_bytes(word(h, 4).unwrap());
        let offset = u64_at(h, 8).unwrap();
        let va = u64_at(h, 16).unwrap();
        let filesz = u64_at(h, 32).unwrap();
        let memsz = u64_at(h, 40).unwrap();
        if filesz > memsz { return Err(ENOEXEC); }
        if memsz == 0 { continue; }
        let align = u64_at(h, 48).unwrap();
        if align > 1 && (!align.is_power_of_two() || va % align != offset % align) { return Err(ENOEXEC); }
        let end = va.checked_add(memsz).ok_or(ENOEXEC)?;
        let contents = elf.get(offset..offset.checked_add(filesz).ok_or(ENOEXEC)?).ok_or(ENOEXEC)?;
        if va < USER_BASE || end > USER_END - (STACK_PAGES+1)*PAGE || va % PAGE != offset % PAGE ||
            !matches!(flags, 4 | 5 | 6) { return Err(ENOEXEC); }
        if flags == 5 && (va..va+filesz).contains(&entry) { executable_entry = true; }
        // Initramfs remains immutable and resident for the system lifetime.
        // Keep its backing slice and the segment's zero-fill extent; the
        // first authorized user or syscall access will populate each page.
        space.reserve(va, memsz, contents, flags == 6, flags == 5)?;
    }
    if !executable_entry { return Err(ENOEXEC); }
    // The page below the fixed stack extent remains outside all regions.
    space.reserve(USER_END - STACK_PAGES*PAGE, STACK_PAGES*PAGE, &[], true, false)?;
    Ok(entry)
}
