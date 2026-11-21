//! Conventional RAM is initialized on the BSP, then shared by all CPUs.
use core::{arch::asm, cell::UnsafeCell, hint::spin_loop, mem::size_of, ptr, slice,
           sync::atomic::{AtomicBool, Ordering}};

const PAGE: usize = 4096;
const WORD_BITS: usize = usize::BITS as usize;

// Ownership of an allocated frame can be moved, but not copied.
pub struct Frame(usize);

impl Frame {
    // Reclaim a frame whose ownership was transferred into a private PTE.
    pub unsafe fn from_owned_address(address: usize) -> Self { Self(address) }
    pub fn address(&self) -> usize { self.0 }
    // Transfer permanent ownership to a boot-CPU table or emergency stack.
    pub fn into_address(self) -> usize { self.0 }
}

pub struct Frames<'a> {
    free: &'a mut [usize],
    // One reference for every allocated page, including page tables. Forked
    // user PTEs can retain a page without transferring its original owner.
    refs: &'a mut [u16],
    next_word: usize,
    available: usize,
}

pub struct SharedFrames {
    locked: AtomicBool,
    frames: UnsafeCell<Frames<'static>>,
}

// The bitmap and its cursor are accessed only inside with(), with local IRQs
// disabled so a timer cannot switch away from a task holding the lock.
unsafe impl Sync for SharedFrames {}

impl SharedFrames {
    pub fn new(frames: Frames<'static>) -> Self {
        Self { locked: AtomicBool::new(false), frames: UnsafeCell::new(frames) }
    }

    pub fn with<R>(&self, operation: impl FnOnce(&mut Frames<'static>) -> R) -> R {
        let flags: usize;
        unsafe { asm!("pushfq", "pop {}", "cli", out(reg) flags); }
        while self.locked.swap(true, Ordering::Acquire) {
            while self.locked.load(Ordering::Relaxed) { spin_loop(); }
        }
        let result = operation(unsafe { &mut *self.frames.get() });
        self.locked.store(false, Ordering::Release);
        if flags & (1 << 9) != 0 { unsafe { asm!("sti", options(nostack)); } }
        result
    }
}

fn field(desc: &[u8], offset: usize) -> usize {
    u64::from_le_bytes(desc[offset..offset + 8].try_into().unwrap()) as usize
}

pub(super) fn ram(desc: &[u8]) -> Option<(usize, usize)> {
    if desc[..4] != 7u32.to_le_bytes() || field(desc, 32) >> 63 != 0 {
        return None;
    }
    let start = field(desc, 8);
    let first = start / PAGE;
    let end = first.checked_add(field(desc, 24))?;
    if start % PAGE != 0 || end > isize::MAX as usize / PAGE { return None; }
    // Keep low memory available for legacy firmware structures and future AP startup.
    let first = first.max(0x100000 / PAGE);
    (first < end).then_some((first, end))
}

impl Frames<'_> {
    pub fn available(&self) -> usize { self.available }

    // Allocate all snapshot pages before copying so their own bits are included.
    pub fn snapshot(&mut self) -> Option<BitmapSnapshot> {
        let mut snapshot = BitmapSnapshot { first: 0, count: 0 };
        for _ in 0..self.free.len().div_ceil(SNAPSHOT_WORDS) {
            let Some(frame) = self.alloc() else { snapshot.release(self); return None; };
            let page = frame.into_address();
            unsafe { (page as *mut usize).write(snapshot.first); }
            snapshot.first = page;
        }
        let mut page = snapshot.first as *mut usize;
        for chunk in self.free.chunks(SNAPSHOT_WORDS) {
            unsafe {
                ptr::copy_nonoverlapping(chunk.as_ptr(), page.add(1), chunk.len());
                page = page.read() as *mut usize;
            }
        }
        snapshot.count = self.available;
        Some(snapshot)
    }
    /// The caller owns the final firmware map after ExitBootServices, the
    /// descriptors are disjoint, and conventional RAM is identity mapped.
    /// Call exactly once, before any CPU consumes conventional pages.
    pub unsafe fn from_uefi(map: &[u8], stride: usize) -> Option<Self> {
        if stride < 40 || map.len() % stride != 0 { return None; }
        let regions = || map.chunks_exact(stride).filter_map(ram);
        let highest = regions().map(|(_, end)| end).max()?;
        let words = highest.div_ceil(WORD_BITS);
        let metadata_bytes = words.checked_mul(size_of::<usize>())?
            .checked_add(highest.checked_mul(size_of::<u16>())?)?;
        let metadata_pages = metadata_bytes.div_ceil(PAGE);
        let (metadata, _) = regions().find(|(first, end)| end - first >= metadata_pages)?;
        let bitmap = (metadata * PAGE) as *mut usize;
        let refs = bitmap.add(words) as *mut u16;
        for i in 0..words { ptr::write_volatile(bitmap.add(i), 0); }
        for i in 0..highest { ptr::write(refs.add(i), 0); }
        let mut frames = Self {
            free: slice::from_raw_parts_mut(bitmap, words),
            refs: slice::from_raw_parts_mut(refs, highest),
            next_word: 0, available: 0,
        };
        for (first, end) in regions() {
            for i in first..end {
                if i >= metadata && i - metadata < metadata_pages { continue; }
                frames.free[i / WORD_BITS] |= 1 << (i % WORD_BITS);
                frames.available += 1;
            }
        }
        Some(frames)
    }

    pub fn alloc(&mut self) -> Option<Frame> {
        if self.available == 0 { return None; }
        while self.free[self.next_word] == 0 { self.next_word += 1; }
        let bits = &mut self.free[self.next_word];
        let bit = bits.trailing_zeros() as usize;
        *bits &= *bits - 1;
        self.available -= 1;
        let index = self.next_word * WORD_BITS + bit;
        assert_eq!(self.refs[index], 0, "allocated frame retained by another owner");
        self.refs[index] = 1;
        Some(Frame(index * PAGE))
    }

    pub fn alloc_zeroed(&mut self) -> Option<Frame> {
        let frame = self.alloc()?;
        let words = frame.0 as *mut usize;
        for i in 0..PAGE / size_of::<usize>() {
            unsafe { ptr::write_volatile(words.add(i), 0); }
        }
        Some(frame)
    }

    /// A page is free only when its final mapping/owner releases it. Caller
    /// must hold the SharedFrames lock and own a real reference.
    pub fn release(&mut self, frame: Frame) {
        let i = frame.0 / PAGE;
        assert!(frame.0 % PAGE == 0 && i < self.refs.len() &&
                self.refs[i] != 0, "release of unowned physical page");
        self.refs[i] -= 1;
        if self.refs[i] == 0 {
            assert_eq!(self.free[i / WORD_BITS] & (1 << (i % WORD_BITS)), 0,
                       "frame double free");
            self.free[i / WORD_BITS] |= 1 << (i % WORD_BITS);
            self.next_word = self.next_word.min(i / WORD_BITS);
            self.available += 1;
        }
    }

    /// Retain a *currently allocated* page before installing a second PTE.
    /// The u16 count is bounded and never silently wraps on many forks.
    pub fn retain(&mut self, address: usize) -> Option<()> {
        if address % PAGE != 0 { return None; }
        let i = address / PAGE;
        let count = self.refs.get_mut(i)?;
        if *count == 0 || *count == u16::MAX { return None; }
        *count += 1;
        Some(())
    }

    pub fn references(&self, address: usize) -> Option<u16> {
        if address % PAGE != 0 { return None; }
        let i = address / PAGE;
        self.refs.get(i).copied().filter(|&count| count != 0)
    }

    pub fn probe(&mut self) -> bool {
        let initial = self.available;
        let Some(first) = self.alloc() else { return false; };
        let Some(second) = self.alloc() else { self.release(first); return false; };
        let address = first.0;
        let a = address as *mut u64;
        let b = second.0 as *mut u64;
        let distinct = unsafe {
            ptr::write_volatile(a, 0x1234);
            ptr::write_volatile(b, 0x5678);
            ptr::read_volatile(a) == 0x1234 && ptr::read_volatile(b) == 0x5678
        };
        self.release(first);
        let Some(reused) = self.alloc() else { return false; };
        let same = address == reused.0;
        self.release(reused);
        self.release(second);
        distinct && same && initial == self.available
    }
}

// Hold physical pages without requiring heap storage as memory runs out.
// Each owned page stores the previous address in its first word.
pub struct Exhaustion { head: usize, pub count: usize }

impl Exhaustion {
    pub fn drain(frames: &mut Frames<'_>) -> Self {
        let mut held = Self { head: 0, count: 0 };
        let initial = frames.available();
        while held.count < initial {
            let Some(frame) = frames.alloc() else { break; };
            let address = frame.into_address();
            unsafe { (address as *mut usize).write(held.head); }
            held.head = address;
            held.count += 1;
        }
        held
    }

    fn pop(&mut self) -> Option<Frame> {
        if self.head == 0 { return None; }
        let frame = Frame(self.head);
        self.head = unsafe { (self.head as *const usize).read() };
        Some(frame)
    }

    pub fn recover(mut self, frames: &mut Frames<'_>) -> bool {
        let Some(spare) = self.pop() else { return false; };
        let address = spare.address();
        unsafe { ptr::write_bytes(address as *mut u8, 0xa5, PAGE); }
        frames.release(spare);
        // A two-page request must roll back cleanly with only one page left.
        let partial_ok = !frames.probe() && frames.available() == 1;
        let mut reused = false;
        if let Some(frame) = frames.alloc_zeroed() {
            reused = frame.address() == address && frames.available() == 0 &&
                (0..PAGE / size_of::<usize>()).all(|i| unsafe {
                    (frame.address() as *const usize).add(i).read_volatile() == 0
                });
            frames.release(frame);
        }
        while let Some(frame) = self.pop() { frames.release(frame); }
        partial_ok && reused
    }
}

const SNAPSHOT_WORDS: usize = PAGE / size_of::<usize>() - 1;
pub struct BitmapSnapshot { first: usize, pub count: usize }

impl BitmapSnapshot {
    pub fn matches(&self, frames: &Frames<'_>) -> bool {
        let mut page = self.first as *const usize;
        for chunk in frames.free.chunks(SNAPSHOT_WORDS) {
            for (i, word) in chunk.iter().enumerate() {
                if *word != unsafe { page.add(i+1).read() } { return false; }
            }
            page = unsafe { page.read() as *const usize };
        }
        frames.available == self.count
    }

    pub fn release(self, frames: &mut Frames<'_>) {
        let mut page = self.first;
        while page != 0 {
            let next = unsafe { (page as *const usize).read() };
            frames.release(Frame(page));
            page = next;
        }
    }
}
