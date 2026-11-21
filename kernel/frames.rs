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
    // Shared kernel PML4 with a permanently prepared guarded-stack subtree.
    kernel_root: usize,
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
    pub fn kernel_root(&self) -> Option<usize> {
        (self.kernel_root != 0).then_some(self.kernel_root)
    }
    pub(super) fn install_kernel_root(&mut self, root: usize) {
        assert!(self.kernel_root == 0 && root != 0 && root % PAGE == 0);
        self.kernel_root = root;
    }

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
            next_word: 0, available: 0, kernel_root: 0,
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
    /// Extend an earlier snapshot by one frame proven reachable from the
    /// retained process. It must have been free at snapshot time and now have
    /// exactly one owner. Duplicate, old, free or shared frames are rejected.
    /// The caller establishes process ownership by walking its actual PTEs;
    /// matches() still checks every other bit and the exact free-frame count.
    #[allow(non_snake_case)]
    pub fn includeAllocatedFrame(&mut self, aFrames: &Frames<'_>, aAddress: usize) -> bool {
        if aFrames.references(aAddress) != Some(1) { return false; }
        let pIndex = aAddress / PAGE;
        let pWord = pIndex / WORD_BITS;
        let pMask = 1usize << (pIndex % WORD_BITS);
        if aFrames.free[pWord] & pMask != 0 { return false; }
        let Some(pCount) = self.count.checked_sub(1) else { return false; };
        let mut pPage = self.first as *mut usize;
        for _ in 0..pWord / SNAPSHOT_WORDS {
            if pPage.is_null() { return false; }
            pPage = unsafe { pPage.read() as *mut usize };
        }
        if pPage.is_null() { return false; }
        let pSaved = unsafe { pPage.add(1+pWord % SNAPSHOT_WORDS) };
        if unsafe { pSaved.read() } & pMask == 0 { return false; }
        unsafe { pSaved.write(pSaved.read() & !pMask); }
        self.count = pCount;
        true
    }

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


#[cfg(test)]
#[allow(non_snake_case)]
mod snapshotTests {
    use super::*;

    #[repr(align(4096))]
    struct SnapshotPage([usize; PAGE / size_of::<usize>()]);

    // Use real bitmap/refcount and snapshot code with synthetic physical frame
    // numbers. Only the snapshot's storage is host memory; no privileged I/O or
    // allocation of a fictitious physical address is performed by these tests.
    fn withSnapshot(aInitial: &[usize], aRun: impl FnOnce(&mut Frames<'_>, &mut BitmapSnapshot)) {
        let mut pFree = aInitial.to_vec();
        let mut pRefs = vec![0; pFree.len()*WORD_BITS];
        let pCount = pFree.iter().map(|pWord| pWord.count_ones() as usize).sum();
        let mut pPages: Vec<Box<SnapshotPage>> = (0..pFree.len().div_ceil(SNAPSHOT_WORDS))
            .map(|_| Box::new(SnapshotPage([0; PAGE / size_of::<usize>()]))).collect();
        for pIndex in 0..pPages.len() {
            let pNext = if pIndex+1 < pPages.len() {
                pPages[pIndex+1].0.as_ptr() as usize
            } else { 0 };
            pPages[pIndex].0[0] = pNext;
        }
        for (pPage,pWords) in pPages.iter_mut().zip(pFree.chunks(SNAPSHOT_WORDS)) {
            pPage.0[1..1+pWords.len()].copy_from_slice(pWords);
        }
        let mut pSnapshot = BitmapSnapshot { first: pPages[0].0.as_ptr() as usize, count: pCount };
        let mut pFrames = Frames { free: &mut pFree, refs: &mut pRefs, next_word: 0,
                                  available: pCount, kernel_root: 0 };
        aRun(&mut pFrames,&mut pSnapshot);
    }

    fn allocateNumber(aFrames: &mut Frames<'_>, aIndex: usize, aReferences: u16) {
        let pMask = 1usize << (aIndex % WORD_BITS);
        assert_ne!(aFrames.free[aIndex / WORD_BITS] & pMask,0);
        aFrames.free[aIndex / WORD_BITS] &= !pMask;
        aFrames.refs[aIndex] = aReferences;
        aFrames.available -= 1;
    }

    #[test]
    fn includesOnlyNewUniquelyOwnedFramesAndRejectsDuplicate() {
        withSnapshot(&[(1<<4)|(1<<5)],|pFrames,pSnapshot| {
            assert!(pSnapshot.matches(pFrames));
            allocateNumber(pFrames,4,1);
            assert!(!pSnapshot.matches(pFrames));
            assert!(pSnapshot.includeAllocatedFrame(pFrames,4*PAGE));
            assert_eq!(pSnapshot.count,1);
            assert!(pSnapshot.matches(pFrames));
            assert!(!pSnapshot.includeAllocatedFrame(pFrames,4*PAGE));
            assert!(pSnapshot.matches(pFrames));
        });
    }

    #[test]
    fn rejectsOldFreeSharedUnalignedAndOutOfRangeFramesWithoutMutation() {
        withSnapshot(&[(1<<4)|(1<<5)],|pFrames,pSnapshot| {
            pFrames.refs[2]=1; // already owned before this snapshot
            allocateNumber(pFrames,4,2); // new, but still shared with a child
            let pSaved=unsafe { (pSnapshot.first as *const usize).add(1).read() };
            for pAddress in [2*PAGE,4*PAGE,5*PAGE,6*PAGE,4*PAGE+1,WORD_BITS*PAGE,usize::MAX] {
                assert!(!pSnapshot.includeAllocatedFrame(pFrames,pAddress));
                assert_eq!(pSnapshot.count,2);
                assert_eq!(unsafe { (pSnapshot.first as *const usize).add(1).read() },pSaved);
            }
            pFrames.refs[4]=1;
            assert!(pSnapshot.includeAllocatedFrame(pFrames,4*PAGE));
            assert!(pSnapshot.matches(pFrames));
        });
    }

    #[test]
    fn omittedLeakedFrameStillFailsExactBitmapAndCount() {
        withSnapshot(&[(1<<4)|(1<<5)],|pFrames,pSnapshot| {
            allocateNumber(pFrames,4,1); // reachable user page
            allocateNumber(pFrames,5,1); // unrelated leaked frame
            assert!(pSnapshot.includeAllocatedFrame(pFrames,4*PAGE));
            assert!(!pSnapshot.matches(pFrames));
            assert_eq!(pSnapshot.count,1);
            assert_eq!(pFrames.available(),0);
        });
    }

    #[test]
    fn unexpectedFreeCannotHideBehindEqualAvailableCount() {
        withSnapshot(&[(1<<4)|(1<<5)],|pFrames,pSnapshot| {
            pFrames.refs[2]=1;
            allocateNumber(pFrames,4,1);
            pFrames.release(unsafe {Frame::from_owned_address(2*PAGE)});
            assert_eq!(pFrames.available(),pSnapshot.count);
            assert!(!pSnapshot.matches(pFrames));
            assert!(pSnapshot.includeAllocatedFrame(pFrames,4*PAGE));
            assert!(!pSnapshot.matches(pFrames));
        });
    }

    #[test]
    fn followsSnapshotChainAcrossBitmapPageBoundary() {
        let mut pInitial=vec![0;SNAPSHOT_WORDS+1];
        pInitial[0]=1<<4;
        pInitial[SNAPSHOT_WORDS]=1<<5;
        withSnapshot(&pInitial,|pFrames,pSnapshot| {
            let pDistant=SNAPSHOT_WORDS*WORD_BITS+5;
            allocateNumber(pFrames,4,1);
            allocateNumber(pFrames,pDistant,1);
            assert!(pSnapshot.includeAllocatedFrame(pFrames,pDistant*PAGE));
            assert!(!pSnapshot.matches(pFrames));
            assert!(pSnapshot.includeAllocatedFrame(pFrames,4*PAGE));
            assert!(pSnapshot.matches(pFrames));
            assert_eq!(pSnapshot.count,0);
        });
    }
}
