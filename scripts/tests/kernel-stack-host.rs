//! Execute the actual guarded-stack allocator and its page-table walks using
//! owned, aligned host pages. Only INVLPG is suppressed by cfg(test).
#![allow(dead_code, non_snake_case)]

mod frames {
    use std::{marker::PhantomData, ptr};

    #[repr(align(4096))]
    struct Page([u8; 4096]);
    pub struct Frame(usize);
    impl Frame {
        pub unsafe fn from_owned_address(aAddress: usize) -> Self { Self(aAddress) }
        pub fn into_address(self) -> usize { self.0 }
    }
    pub struct Frames<'a> {
        fPool: Vec<Box<Page>>,
        fUsed: Vec<bool>,
        fBudget: usize,
        fRoot: usize,
        fLifetime: PhantomData<&'a ()>,
    }
    impl Frames<'_> {
        pub fn new(aCount: usize) -> Self {
            Self {
                fPool: (0..aCount).map(|_| Box::new(Page([0xa5; 4096]))).collect(),
                fUsed: vec![false; aCount], fBudget: usize::MAX, fRoot: 0,
                fLifetime: PhantomData,
            }
        }
        pub fn alloc_zeroed(&mut self) -> Option<Frame> {
            if self.fBudget == 0 { return None; }
            let pIndex = self.fUsed.iter().position(|&pUsed| !pUsed)?;
            self.fUsed[pIndex] = true;
            self.fBudget -= 1;
            let pAddress = self.fPool[pIndex].0.as_mut_ptr() as usize;
            unsafe { ptr::write_bytes(pAddress as *mut u8, 0, 4096); }
            Some(Frame(pAddress))
        }
        pub fn release(&mut self, aFrame: Frame) {
            let pIndex = self.fPool.iter().position(|pPage| pPage.0.as_ptr() as usize == aFrame.0).unwrap();
            assert!(self.fUsed[pIndex], "double-free");
            self.fUsed[pIndex] = false;
        }
        pub fn kernel_root(&self) -> Option<usize> { (self.fRoot != 0).then_some(self.fRoot) }
        pub fn install_kernel_root(&mut self, aRoot: usize) {
            assert!(self.fRoot == 0 && aRoot != 0 && aRoot % 4096 == 0);
            self.fRoot = aRoot;
        }
        pub fn used(&self) -> usize { self.fUsed.iter().filter(|&&pUsed| pUsed).count() }
        pub fn allow(&mut self, aCount: usize) { self.fBudget = aCount; }
    }
}

#[path = "../../kernel/stack.rs"]
mod stack;
use frames::Frames;
use stack::KernelStack;

const PAGE: usize = 4096;
const ADDRESS: u64 = 0x000f_ffff_ffff_f000;
const FLAGS: u64 = (1 << 63) | 3;

unsafe fn entry(aRoot: usize, aAddress: usize) -> u64 {
    let mut pTable = aRoot;
    for pShift in [39, 30, 21] {
        let pValue = (pTable as *const u64).add((aAddress >> pShift) & 511).read();
        assert_eq!(pValue & !ADDRESS, FLAGS, "intermediate table must be supervisor RW/NX");
        pTable = (pValue & ADDRESS) as usize;
    }
    (pTable as *const u64).add((aAddress >> 12) & 511).read()
}

fn setup(aPages: usize) -> (Frames<'static>, usize) {
    let mut pFrames = Frames::new(aPages);
    let pRoot = pFrames.alloc_zeroed().unwrap().into_address();
    unsafe { stack::prepare(&mut pFrames, pRoot).unwrap(); }
    assert_eq!(pFrames.used(), 51); // root + PDPT + PD + 48 PT pages
    (pFrames, pRoot)
}

#[test]
fn bothGuardsAreAbsentAndAllStackPagesAreZeroedSupervisorNx() {
    let (mut pFrames, pRoot) = setup(55);
    let pStack = KernelStack::allocate(&mut pFrames).unwrap();
    assert_eq!(pStack.guard(), 0xffff_8000_0000_0000);
    assert_eq!(pStack.top() - pStack.guard(), 5 * PAGE);
    unsafe {
        assert_eq!(entry(pRoot, pStack.guard()), 0);
        assert_eq!(entry(pRoot, pStack.top()), 0);
        for pIndex in 1..=4 {
            let pValue = entry(pRoot, pStack.guard() + pIndex * PAGE);
            assert_eq!(pValue & !ADDRESS, FLAGS, "stack must be supervisor RW/NX");
            let pBytes = std::slice::from_raw_parts((pValue & ADDRESS) as *const u8, PAGE);
            assert!(pBytes.iter().all(|&pByte| pByte == 0));
        }
        // Both ends of the preallocated 96 MiB virtual pool are reachable
        // through tables, while unmapped data leaves still own no frames.
        assert_eq!(entry(pRoot, 0xffff_8000_0000_0000 + (4096 * 6 - 1) * PAGE), 0);
    }
    pStack.release(&mut pFrames);
    assert_eq!(pFrames.used(), 51);
}

#[test]
fn prepareFailureRollsBackAtEveryTableAllocationAndCanRetry() {
    for pBudget in 0..50 {
        let mut pFrames = Frames::new(51);
        let pRoot = pFrames.alloc_zeroed().unwrap().into_address();
        pFrames.allow(pBudget);
        assert!(unsafe { stack::prepare(&mut pFrames, pRoot) }.is_none());
        assert_eq!(pFrames.used(), 1);
        assert_eq!(pFrames.kernel_root(), None);
        assert_eq!(unsafe { (pRoot as *const u64).add(256).read() }, 0);
        pFrames.allow(50);
        assert!(unsafe { stack::prepare(&mut pFrames, pRoot) }.is_some());
        assert_eq!(pFrames.used(), 51);
        assert!(unsafe { stack::prepare(&mut pFrames, pRoot) }.is_none());
        assert_eq!(pFrames.used(), 51);
    }
}

#[test]
fn failedStackAllocationPreservesLeavesAndReleasedSlotIsZeroedOnReuse() {
    let (mut pFrames, pRoot) = setup(59);
    let pLive = KernelStack::allocate(&mut pFrames).unwrap();
    let pNext = pLive.guard() + 6 * PAGE;
    for pBudget in 0..4 {
        pFrames.allow(pBudget);
        assert!(KernelStack::allocate(&mut pFrames).is_none());
        assert_eq!(pFrames.used(), 55);
        for pPage in 0..6 { assert_eq!(unsafe { entry(pRoot, pNext + pPage * PAGE) }, 0); }
    }
    pFrames.allow(4);
    let pOther = KernelStack::allocate(&mut pFrames).unwrap();
    assert_eq!(pOther.guard(), pNext);
    let pOld = pLive.guard();
    unsafe {
        for pPage in 1..=4 {
            let pAddress = (entry(pRoot, pOld + pPage * PAGE) & ADDRESS) as *mut u8;
            std::ptr::write_bytes(pAddress, 0x6b, PAGE);
        }
    }
    pLive.release(&mut pFrames);
    for pPage in 0..6 { assert_eq!(unsafe { entry(pRoot, pOld + pPage * PAGE) }, 0); }
    pFrames.allow(4);
    let pReused = KernelStack::allocate(&mut pFrames).unwrap();
    assert_eq!(pReused.guard(), pOld);
    unsafe {
        for pPage in 1..=4 {
            let pAddress = (entry(pRoot, pOld + pPage * PAGE) & ADDRESS) as *const u8;
            assert!(std::slice::from_raw_parts(pAddress, PAGE).iter().all(|&pByte| pByte == 0));
        }
        assert_ne!(entry(pRoot, pOther.guard() + PAGE), 0);
    }
    pReused.release(&mut pFrames);
    pOther.release(&mut pFrames);
    assert_eq!(pFrames.used(), 51);
}

#[test]
fn slotsCrossPageTableBoundariesAndRetainedStacksStayAllocated() {
    let (mut pFrames, pRoot) = setup(51 + 172 * 4);
    let mut pStacks = Vec::new();
    for pIndex in 0..172 {
        let pStack = KernelStack::allocate(&mut pFrames).unwrap();
        assert_eq!(pStack.guard(), 0xffff_8000_0000_0000 + pIndex * 6 * PAGE);
        unsafe {
            assert_eq!(entry(pRoot, pStack.guard()), 0);
            assert_eq!(entry(pRoot, pStack.top()), 0);
            for pPage in 1..=4 {
                assert_eq!(entry(pRoot, pStack.guard() + pPage * PAGE) & !ADDRESS, FLAGS);
            }
        }
        pStacks.push(pStack);
    }
    assert!(KernelStack::allocate(&mut pFrames).is_none());
    let pPermanent = pStacks.pop().unwrap().into_top();
    for pStack in pStacks { pStack.release(&mut pFrames); }
    assert_eq!(pFrames.used(), 55);
    assert_ne!(unsafe { entry(pRoot, pPermanent - PAGE) }, 0);
    assert_eq!(unsafe { entry(pRoot, pPermanent) }, 0);
}
