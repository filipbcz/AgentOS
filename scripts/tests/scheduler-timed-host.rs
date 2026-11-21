//! Execute the actual scheduler, lifecycle registry and process cleanup code.
//! Host-owned aligned pages replace physical frames; traps, MMIO and ELF page
//! contents are outside this fixture (covered by the process/pager suite).
#![allow(dead_code, unused_variables, non_snake_case)]

mod frames {
    use core::marker::PhantomData;
    use std::collections::BTreeSet;
    #[repr(align(4096))]
    struct Page([u8; 4096]);
    pub struct Frame(pub usize);
    impl Frame {
        pub unsafe fn from_owned_address(aAddress: usize) -> Self { Self(aAddress) }
        pub fn address(&self) -> usize { self.0 }
        pub fn into_address(self) -> usize { self.0 }
    }
    pub struct Frames<'a> { fLive: BTreeSet<usize>, fBudget: usize, fLifetime: PhantomData<&'a ()> }
    impl Frames<'_> {
        pub fn test_dummy() -> Self {
            Self { fLive: BTreeSet::new(), fBudget: usize::MAX, fLifetime: PhantomData }
        }
        pub fn allow(&mut self, aBudget: usize) { self.fBudget = aBudget; }
        pub fn used(&self) -> usize { self.fLive.len() }
        pub fn alloc(&mut self) -> Option<Frame> {
            if self.fBudget == 0 { return None; }
            self.fBudget -= 1;
            let pAddress = Box::into_raw(Box::new(Page([0xa5; 4096]))) as usize;
            assert!(self.fLive.insert(pAddress));
            Some(Frame(pAddress))
        }
        pub fn alloc_zeroed(&mut self) -> Option<Frame> {
            let pFrame = self.alloc()?;
            unsafe { core::ptr::write_bytes(pFrame.0 as *mut u8, 0, 4096); }
            Some(pFrame)
        }
        pub fn release(&mut self, aFrame: Frame) {
            assert!(self.fLive.remove(&aFrame.0), "double free or foreign lifecycle frame");
            unsafe { drop(Box::from_raw(aFrame.0 as *mut Page)); }
        }
    }
}

mod stack {
    use core::sync::atomic::{AtomicUsize, Ordering};
    static NEXT: AtomicUsize = AtomicUsize::new(0x10000000);
    pub struct KernelStack { fTop: usize }
    impl KernelStack {
        pub fn test_dummy() -> Self { Self { fTop: NEXT.fetch_add(0x6000, Ordering::Relaxed) } }
        pub fn allocate(_: &mut crate::frames::Frames<'_>) -> Option<Self> { None }
        pub fn top(&self) -> usize { self.fTop }
        pub fn release(self, _: &mut crate::frames::Frames<'_>) {}
    }
}

mod paging {
    pub const USER_BASE: usize = 1 << 39;
    pub const USER_END: usize = 1 << 40;
    pub struct UserSpace { pub root: usize }
    impl UserSpace {
        pub fn test_dummy() -> Self { Self { root: 0 } }
        pub fn new(_: &mut crate::frames::Frames<'_>, _: usize) -> Option<Self> { None }
        pub fn reserve(&self, _: usize, _: usize, _: &'static [u8], _: bool, _: bool) -> Result<(),isize> { Err(-12) }
        pub unsafe fn release(&self, _: &mut crate::frames::Frames<'_>) {}
        pub unsafe fn fork_cow(&self, _: &mut crate::frames::Frames<'_>, _: usize) -> Result<Self,isize> { Err(-12) }
    }
}

mod files {
    #[derive(Clone, Copy)]
    pub struct Wait;
    impl Wait { pub fn ready(self, _: &mut crate::frames::Frames<'_>) -> bool { false } }
    pub struct Descriptors;
    impl Descriptors {
        pub fn test_dummy() -> Self { Self }
        pub fn new(_: &mut crate::frames::Frames<'_>) -> Option<Self> { Some(Self) }
        pub fn inherit(&mut self, _: &mut crate::frames::Frames<'_>, _: &Self) {}
        pub fn terminal(&mut self, _: *mut crate::tty::Terminal) -> Result<(),isize> { Ok(()) }
        pub fn ipc_ready_mask(&self, _: &mut crate::frames::Frames<'_>, _: u32) -> Result<u32, isize> { Ok(0) }
        pub fn close_all(&mut self, _: &mut crate::frames::Frames<'_>) {}
        pub fn release(self, _: &mut crate::frames::Frames<'_>) {}
    }
}

mod tty { pub struct Terminal; }
mod vfs {
    pub struct Vfs;
    impl Vfs {
        pub fn new(_: &'static [u8]) -> Self { Self }
        pub fn file(&self, _: &[u8]) -> Result<&'static [u8], isize> { Err(-2) }
    }
}
mod native_abi { pub fn validate(_: &[u8]) -> bool { false } }

#[path = "../../kernel/lifecycle.rs"]
mod lifecycle;
#[path = "../../kernel/process.rs"]
mod process;
#[no_mangle]
pub extern "C" fn task_return() {}
#[path = "../../kernel/scheduler.rs"]
mod scheduler;
#[path = "../../kernel/timer.rs"]
mod timer;
