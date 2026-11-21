//! Compile and execute the actual kernel/scheduler.rs timed-wait implementation.
//! The minimal process/frame mocks are never used for scheduling semantics;
//! no native AgentOS syscall, IRQ or MMIO is executed on the host.
#![allow(dead_code, unused_variables)]

mod frames {
    use core::marker::PhantomData;
    pub struct Frame(pub usize);
    impl Frame {
        pub unsafe fn from_owned_address(addr: usize) -> Self { Self(addr) }
        pub fn address(&self) -> usize { self.0 }
    }
    pub struct Frames<'a>(PhantomData<&'a ()>);
    impl Frames<'_> {
        pub fn test_dummy() -> Self { Self(PhantomData) }
        pub fn alloc_zeroed(&mut self) -> Option<Frame> { None }
        pub fn release(&mut self, _: Frame) {}
    }
}

mod paging {
    pub struct UserSpace { pub root: usize }
    impl UserSpace {
        pub fn test_dummy() -> Self { Self {root:0} }
        pub unsafe fn release(&self, _: &mut crate::frames::Frames<'_>) {}
        pub unsafe fn fork_cow(&self, _: &mut crate::frames::Frames<'_>, _: usize) -> Result<Self,isize> {
            Err(-12)
        }
    }
}

mod files {
    #[derive(Clone, Copy)]
    pub struct Wait;
    impl Wait { pub fn ready(self) -> bool { false } }

    pub struct Descriptors;
    impl Descriptors {
        pub fn test_dummy() -> Self { Self }
        pub fn new(_: &mut crate::frames::Frames<'_>) -> Option<Self> { Some(Self) }
        pub fn inherit(&mut self, _: &Self) {}
        pub fn terminal(&mut self, _: *mut crate::tty::Terminal) -> Result<(),isize> { Ok(()) }
        pub fn close_all(&mut self, _: &mut crate::frames::Frames<'_>) {}
        pub fn release(&self, _: &mut crate::frames::Frames<'_>) {}
    }
}

mod tty { pub struct Terminal; }

mod process {
    pub const STACK: usize=0x200000;
    #[derive(Clone, Copy)]
    pub struct Credentials;
    impl Credentials { pub const BOOT_USER: Self = Self; }
    pub struct Process {
        pub credentials: Credentials,
        pub space: crate::paging::UserSpace,
        pub entry: usize,
        pub pid: usize,
        pub parent: usize,
        pub status: Option<usize>,
        pub files: crate::files::Descriptors,
    }
    pub struct Programs { pub kernel_root: usize }
    impl Programs {
        pub fn allocate_pid(&self) -> Result<usize,isize> { Ok(8) }
        pub unsafe fn load(&self, _: &mut crate::frames::Frames<'_>, _: &[u8],
                          _: usize, _: Credentials) -> Result<Process,isize> {
            Err(-8)
        }
    }
}

#[no_mangle]
pub extern "C" fn task_return() {}

#[path = "../../kernel/scheduler.rs"]
mod scheduler;
