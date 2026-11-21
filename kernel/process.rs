use crate::{frames::Frames, paging::{UserSpace, USER_BASE, USER_END}};
use core::{ptr, sync::atomic::{AtomicUsize, Ordering}};

pub const EFAULT: isize = -14;
const ENOEXEC: isize = -8;
const ENOMEM: isize = -12;
const PAGE: usize = 4096;
const STACK_PAGES: usize = 4;
pub const STACK: usize = USER_END - 16;

pub struct Programs { pub vfs: crate::vfs::Vfs, pub kernel_root: usize, next_pid: AtomicUsize }
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
    pub parent: usize,
    pub status: Option<usize>,
    pub files: crate::files::Descriptors,
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
        Self { vfs: crate::vfs::Vfs::new(archive), kernel_root, next_pid: AtomicUsize::new(1) }
    }

    pub unsafe fn load(&self, frames: &mut Frames<'_>, name: &[u8], parent: usize, credentials: Credentials) -> Result<Process, isize> {
        let elf = self.vfs.file(name)?;
        let space = UserSpace::new(frames, self.kernel_root).ok_or(ENOMEM)?;
        let result = load_elf(&space, frames, elf).and_then(|entry| {
            let pid = self.allocate_pid()?;
            let files = crate::files::Descriptors::new(frames).ok_or(ENOMEM)?;
            Ok((entry, pid, files))
        });
        match result {
            Ok((entry, pid, files)) => Ok(Process { space, entry, pid, parent, credentials, status: None, files }),
            Err(error) => { space.release(frames); Err(error) }
        }
    }
}

unsafe fn load_elf(space: &UserSpace, frames: &mut Frames<'_>, elf: &[u8]) -> Result<usize, isize> {
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
        let first = va & !(PAGE-1);
        for page in (first..end).step_by(PAGE) {
            let physical = space.map(frames, page, flags == 6, flags == 5)?;
            let start = page.max(va);
            let stop = (page+PAGE).min(va+filesz);
            if start < stop {
                ptr::copy_nonoverlapping(contents.as_ptr().add(start-va), (physical+start-page) as *mut u8, stop-start);
            }
        }
    }
    if !executable_entry { return Err(ENOEXEC); }
    for page in (USER_END - STACK_PAGES*PAGE..USER_END).step_by(PAGE) {
        space.map(frames, page, true, false)?;
    }
    Ok(entry)
}
