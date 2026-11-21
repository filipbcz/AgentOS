//! Guarded kernel stacks shared by every address space. The page-table pool is
//! installed once before CR3 publication. Allocate and release only while the
//! frame allocator is exclusively borrowed (SharedFrames::with after SMP).
//!
//! Tasks never migrate between CPUs. A stack is unmapped only after its owner
//! stopped running; the allocating CPU invalidates each reused virtual page.
//! No other CPU may retain a live reference to the released stack.
#![allow(non_snake_case)]

use crate::frames::{Frame, Frames};

const PAGE: usize = 4096;
const BASE: usize = 0xffff_8000_0000_0000;
const SLOT_COUNT: usize = 4096;
const DATA_PAGES: usize = 4;
const SLOT_PAGES: usize = DATA_PAGES + 2;
const TABLE_COUNT: usize = SLOT_COUNT * SLOT_PAGES / 512;
const PRESENT: u64 = 1;
const WRITE: u64 = 2;
const NX: u64 = 1 << 63;
const ADDRESS: u64 = 0x000f_ffff_ffff_f000;
const FLAGS: u64 = PRESENT | WRITE | NX;

/// Owns the physical pages and their unique guarded virtual slot. No Drop:
/// releasing requires the frame lock and must never free the executing stack.
pub struct KernelStack {
    fBase: usize,
    fFrames: [usize; DATA_PAGES],
}

/// Prepare all supervisor-only tables before any user root copies the kernel
/// PML4. A failed allocation leaves the root and frame ownership unchanged.
pub unsafe fn prepare(aFrames: &mut Frames<'_>, aRoot: usize) -> Option<()> {
    if aRoot == 0 || aRoot % PAGE != 0 || aFrames.kernel_root().is_some() {
        return None;
    }
    let pEntry = (aRoot as *mut u64).add(256);
    if pEntry.read() != 0 { return None; }
    let mut pPages = [0usize; TABLE_COUNT + 2];
    for pIndex in 0..pPages.len() {
        let Some(pPage) = aFrames.alloc_zeroed() else {
            for &pAddress in &pPages[..pIndex] {
                aFrames.release(Frame::from_owned_address(pAddress));
            }
            return None;
        };
        pPages[pIndex] = pPage.into_address();
    }
    (pPages[0] as *mut u64).write(pPages[1] as u64 | FLAGS);
    for pIndex in 0..TABLE_COUNT {
        (pPages[1] as *mut u64).add(pIndex).write(pPages[pIndex + 2] as u64 | FLAGS);
    }
    // install_kernel_root cannot fail after the checks above. Publish the root
    // only once every subtree is initialized, while no CPU can observe it.
    aFrames.install_kernel_root(aRoot);
    pEntry.write(pPages[0] as u64 | FLAGS);
    Some(())
}

unsafe fn leaf(aRoot: usize, aPage: usize) -> *mut u64 {
    let pPdpt = ((aRoot as *const u64).add(256).read() & ADDRESS) as *const u64;
    let pPd = (pPdpt.read() & ADDRESS) as *const u64;
    let pPt = (pPd.add(aPage / 512).read() & ADDRESS) as *mut u64;
    pPt.add(aPage % 512)
}

fn invalidate(aAddress: usize) {
    #[cfg(not(test))]
    unsafe { core::arch::asm!("invlpg [{}]", in(reg) aAddress, options(nostack, preserves_flags)); }
    #[cfg(test)]
    let _ = aAddress;
}

impl KernelStack {
    pub fn allocate(aFrames: &mut Frames<'_>) -> Option<Self> {
        let pRoot = aFrames.kernel_root()?;
        let pSlot = (0..SLOT_COUNT).find(|&pSlot| unsafe {
            leaf(pRoot, pSlot * SLOT_PAGES + 1).read() == 0
        })?;
        let pFirst = pSlot * SLOT_PAGES + 1;
        let mut pFrames = [0usize; DATA_PAGES];
        for pIndex in 0..DATA_PAGES {
            let Some(pPage) = aFrames.alloc_zeroed() else {
                for &pAddress in &pFrames[..pIndex] {
                    unsafe { aFrames.release(Frame::from_owned_address(pAddress)); }
                }
                return None;
            };
            pFrames[pIndex] = pPage.into_address();
        }
        let pBase = BASE + pFirst * PAGE;
        for (pIndex, &pAddress) in pFrames.iter().enumerate() {
            unsafe {
                let pLeaf = leaf(pRoot, pFirst + pIndex);
                assert_eq!(pLeaf.read(), 0, "kernel stack slot already mapped");
                pLeaf.write(pAddress as u64 | FLAGS);
            }
            invalidate(pBase + pIndex * PAGE);
        }
        Some(Self { fBase: pBase, fFrames: pFrames })
    }

    pub fn top(&self) -> usize { self.fBase + DATA_PAGES * PAGE }
    pub fn guard(&self) -> usize { self.fBase - PAGE }

    /// Transfer ownership to a permanently retained AP or double-fault stack.
    pub fn into_top(self) -> usize { self.top() }

    pub fn release(self, aFrames: &mut Frames<'_>) {
        let pRoot = aFrames.kernel_root().expect("kernel stack pool not installed");
        let pFirst = (self.fBase - BASE) / PAGE;
        for (pIndex, &pAddress) in self.fFrames.iter().enumerate() {
            unsafe {
                let pLeaf = leaf(pRoot, pFirst + pIndex);
                assert_eq!(pLeaf.read() & ADDRESS, pAddress as u64, "kernel stack owner mismatch");
                pLeaf.write(0);
            }
            invalidate(self.fBase + pIndex * PAGE);
        }
        for pAddress in self.fFrames {
            unsafe { aFrames.release(Frame::from_owned_address(pAddress)); }
        }
    }
}
