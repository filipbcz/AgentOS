//! Exercise the real ELF loader, pager, descriptor operations and IPC together.
//! Owned, page-aligned host memory replaces physical frames; boot/MMIO/TTY are
//! deliberately unavailable, and the serial boundary captures actual bytes.
//! Every tested byte travels through the actual kernel copy-in/copy-out.
#![allow(dead_code, non_snake_case, non_upper_case_globals)]

use std::{cell::RefCell, marker::PhantomData, ptr};

const gPage: usize = 4096;
const gCode: usize = (1usize << 39) + gPage;
const gData: usize = (1usize << 39) + 4 * gPage;
const gDataPages: usize = 4096;
const gTextOffset: usize = 4096;
const gDataOffset: usize = 8192;
const gDataHeader: usize = 64 + 2 * 56;
const gFileData: &[u8] = b"0123456789abcdef";

pub struct BootInfo {
    pub descriptor_size: u64, pub image_base: u64, pub image_size: u64,
    pub memory_map: u64, pub map_size: u64, pub rsdp: u64,
    pub stack_base: u64, pub ap_boot: usize, pub framebuffer: *mut u32,
    pub stride: u32, pub height: u32,
}

mod acpi {
    pub struct Io { pub address: usize }
    pub struct Platform { pub lapic: usize, pub io_apics: [Io; 1], pub io_count: usize }
}

mod frames {
    use super::*;

    #[repr(align(4096))]
    pub struct Page([u8; gPage]);
    pub struct Frame(usize);
    impl Frame {
        pub unsafe fn from_owned_address(aAddress: usize) -> Self { Self(aAddress) }
        pub fn address(&self) -> usize { self.0 }
        pub fn into_address(self) -> usize { self.0 }
    }

    pub struct Frames<'a> {
        fPool: Vec<Box<Page>>,
        fReferences: Vec<u16>,
        fBudget: usize,
        fLifetime: PhantomData<&'a ()>,
    }
    pub fn ram(_: &[u8]) -> Option<(usize, usize)> { None }

    impl Frames<'_> {
        pub fn new(aCount: usize) -> Self {
            Self {
                // Deliberately dirty pages detect missing zeroing, including
                // partial ELF pages, BSS and allocator reuse after rollback.
                fPool: (0..aCount).map(|_| Box::new(Page([0xa5; gPage]))).collect(),
                fReferences: vec![0; aCount], fBudget: usize::MAX,
                fLifetime: PhantomData,
            }
        }
        pub fn used(&self) -> usize { self.fReferences.iter().filter(|&&pCount| pCount != 0).count() }
        pub fn allow(&mut self, aCount: usize) { self.fBudget = aCount; }
        pub fn alloc(&mut self) -> Option<Frame> {
            if self.fBudget == 0 { return None; }
            let pIndex = self.fReferences.iter().position(|&pCount| pCount == 0)?;
            self.fBudget -= 1;
            self.fReferences[pIndex] = 1;
            Some(Frame(self.fPool[pIndex].0.as_ptr() as usize))
        }
        pub fn alloc_zeroed(&mut self) -> Option<Frame> {
            let pFrame = self.alloc()?;
            unsafe { ptr::write_bytes(pFrame.0 as *mut u8, 0, gPage); }
            Some(pFrame)
        }
        fn index(&self, aAddress: usize) -> Option<usize> {
            self.fPool.iter().position(|pPage| pPage.0.as_ptr() as usize == aAddress)
        }
        pub fn references(&self, aAddress: usize) -> Option<u16> {
            let pIndex = self.index(aAddress)?;
            (self.fReferences[pIndex] != 0).then_some(self.fReferences[pIndex])
        }
        pub fn retain(&mut self, aAddress: usize) -> Option<()> {
            let pIndex = self.index(aAddress)?;
            let pCount = &mut self.fReferences[pIndex];
            if *pCount == 0 || *pCount == u16::MAX { return None; }
            *pCount += 1;
            Some(())
        }
        pub fn release(&mut self, aFrame: Frame) {
            let pIndex = self.index(aFrame.0).expect("release of foreign frame");
            assert!(self.fReferences[pIndex] > 0, "double free");
            self.fReferences[pIndex] -= 1;
        }
    }
}

mod stack {
    pub unsafe fn prepare(_: &mut crate::frames::Frames<'_>, _: usize) -> Option<()> {
        panic!("boot-only stack preparation cannot run in this host test");
    }
}

mod tty {
    pub struct Terminal;
    impl Terminal {
        pub fn ready(&self) -> bool { panic!("TTY excluded from this host fixture"); }
        pub fn read<F>(&mut self, _: usize, _: F) -> Result<Option<usize>, isize>
            where F: FnOnce(&[u8]) -> Result<(), isize>
        { panic!("TTY excluded from this host fixture"); }
        pub unsafe fn write(&mut self, _: &[u8]) -> Result<usize, isize> {
            panic!("TTY excluded from this host fixture");
        }
    }
}

thread_local! { static gConsoleOutput: RefCell<Vec<u8>> = RefCell::new(Vec::new()); }

unsafe fn serial(aBytes: &[u8]) {
    gConsoleOutput.with(|pOutput| pOutput.borrow_mut().extend_from_slice(aBytes));
}

#[path = "../../kernel/paging.rs"]
mod paging;
#[path = "../../kernel/native_abi.rs"]
mod native_abi;
#[path = "../../kernel/vfs.rs"]
mod vfs;
#[path = "../../kernel/process.rs"]
mod process;
#[path = "../../kernel/files.rs"]
mod files;
#[path = "../../kernel/ipc.rs"]
mod ipc;

fn put16(aBytes: &mut [u8], aAt: usize, aValue: u16) {
    aBytes[aAt..aAt + 2].copy_from_slice(&aValue.to_le_bytes());
}
fn put32(aBytes: &mut [u8], aAt: usize, aValue: u32) {
    aBytes[aAt..aAt + 4].copy_from_slice(&aValue.to_le_bytes());
}
fn put64(aBytes: &mut [u8], aAt: usize, aValue: usize) {
    aBytes[aAt..aAt + 8].copy_from_slice(&(aValue as u64).to_le_bytes());
}

fn textByte(aIndex: usize) -> u8 { ((aIndex * 37 + 11) % 256) as u8 }
fn dataByte(aIndex: usize) -> u8 { (aIndex + 0x40) as u8 }

fn programImage() -> Vec<u8> {
    let mut pElf = vec![0; gDataOffset + 37];
    pElf[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
    put16(&mut pElf, 16, 2);
    put16(&mut pElf, 18, 62);
    put32(&mut pElf, 20, 1);
    put64(&mut pElf, 24, gCode);
    put64(&mut pElf, 32, 64);
    put16(&mut pElf, 52, 64);
    put16(&mut pElf, 54, 56);
    put16(&mut pElf, 56, 3);

    // A real native v1 ELF note and two non-overlapping PT_LOAD segments.
    put32(&mut pElf, 64, 4);
    put64(&mut pElf, 72, 256);
    put64(&mut pElf, 96, 28);
    put64(&mut pElf, 112, 4);
    put32(&mut pElf, 256, 8);
    put32(&mut pElf, 260, 8);
    put32(&mut pElf, 264, 1);
    pElf[268..276].copy_from_slice(b"AgentOS\0");
    put32(&mut pElf, 276, 1);

    for (pHeader, pAddress, pOffset, pFileSize, pMemorySize, pFlags) in [
        (120, gCode, gTextOffset, gPage, gPage, 5),
        (gDataHeader, gData, gDataOffset, 37, gDataPages * gPage, 6),
    ] {
        put32(&mut pElf, pHeader, 1);
        put32(&mut pElf, pHeader + 4, pFlags);
        put64(&mut pElf, pHeader + 8, pOffset);
        put64(&mut pElf, pHeader + 16, pAddress);
        put64(&mut pElf, pHeader + 32, pFileSize);
        put64(&mut pElf, pHeader + 40, pMemorySize);
        put64(&mut pElf, pHeader + 48, gPage);
    }
    for pIndex in 0..gPage { pElf[gTextOffset + pIndex] = textByte(pIndex); }
    for pIndex in 0..37 { pElf[gDataOffset + pIndex] = dataByte(pIndex); }
    pElf
}

fn appendEntry(aArchive: &mut Vec<u8>, aName: &[u8], aContent: &[u8]) {
    let pStart = aArchive.len();
    aArchive.extend_from_slice(&[b'0'; 110]);
    aArchive[pStart..pStart + 6].copy_from_slice(b"070701");
    for (pAt, pValue) in [(14, 0o100644), (54, aContent.len()), (94, aName.len() + 1)] {
        let pField = format!("{pValue:08x}");
        aArchive[pStart + pAt..pStart + pAt + 8].copy_from_slice(pField.as_bytes());
    }
    aArchive.extend_from_slice(aName);
    aArchive.push(0);
    while aArchive.len() % 4 != 0 { aArchive.push(0); }
    aArchive.extend_from_slice(aContent);
    while aArchive.len() % 4 != 0 { aArchive.push(0); }
}

struct Harness {
    fFrames: frames::Frames<'static>,
    fKernelRoot: usize,
    fPrograms: process::Programs,
}

impl Harness {
    fn new(aElf: Vec<u8>) -> Self {
        let mut pArchive = Vec::new();
        appendEntry(&mut pArchive, b"program", &aElf);
        appendEntry(&mut pArchive, b"data", gFileData);
        appendEntry(&mut pArchive, b"TRAILER!!!", &[]);
        // The production initramfs outlives all processes and lazy mappings.
        let pArchive: &'static [u8] = Box::leak(pArchive.into_boxed_slice());
        let mut pFrames = frames::Frames::new(96);
        let pKernelRoot = pFrames.alloc_zeroed().unwrap().into_address();
        Self {
            fFrames: pFrames, fKernelRoot: pKernelRoot,
            fPrograms: process::Programs::new(pArchive, pKernelRoot),
        }
    }
    fn load(&mut self) -> Result<process::Process, isize> {
        unsafe { self.fPrograms.load(&mut self.fFrames, b"program", 77, process::Credentials::BOOT_USER) }
    }
    fn finish(mut self) {
        assert_eq!(self.fFrames.used(), 1, "process, page-table or descriptor leak");
        self.fFrames.release(unsafe { frames::Frame::from_owned_address(self.fKernelRoot) });
        assert_eq!(self.fFrames.used(), 0);
    }
}

fn releaseProcess(aFrames: &mut frames::Frames<'_>, aProcess: process::Process) {
    aProcess.files.release(aFrames);
    unsafe { aProcess.space.release(aFrames); }
}

fn count(aResult: Result<files::Io, isize>) -> Result<usize, isize> {
    aResult.map(|pIo| match pIo {
        files::Io::Bytes(pCount) => pCount,
        files::Io::Sleep(_) => panic!("unexpected blocking operation"),
        files::Io::Output(_) => panic!("hardware output requires explicit completion"),
    })
}

fn pair(aProcess: &mut process::Process, aFrames: &mut frames::Frames<'_>, aSocket: bool) -> (usize, usize) {
    let pOutput = gData + 256;
    assert_eq!(aProcess.files.pair(aFrames, &aProcess.space, pOutput, aSocket), Ok(0));
    let mut pBytes = [0; 8];
    aProcess.space.read(aFrames, pOutput, &mut pBytes).unwrap();
    (u32::from_le_bytes(pBytes[..4].try_into().unwrap()) as usize,
     u32::from_le_bytes(pBytes[4..].try_into().unwrap()) as usize)
}

#[test]
fn loaderReservesLargeElfBssAndStackWithoutAllocatingTheirPages() {
    let mut pHarness = Harness::new(programImage());
    let pProcess = pHarness.load().ok().expect("valid ELF rejected");
    assert_eq!(pProcess.entry, gCode);
    assert_eq!(pProcess.parent, 77);
    assert_eq!(pProcess.credentials.uid, 1000);
    assert_eq!(pProcess.space.stats(), [1, (gDataPages + 5) as u64, 0, 1, 1, 0, 0, 0]);
    assert_eq!(pHarness.fFrames.used(), 4, "only kernel/user roots, VMA metadata and fd table");

    // Neither invalid instruction fetches nor the unmapped stack guard may
    // allocate data or quietly widen a region's declared protections.
    let pGuard = paging::USER_END - 5 * gPage;
    for (pAddress, pError) in [(0, 4), (pGuard, 6), (gData, 20), (gCode, 6)] {
        assert_eq!(unsafe { pProcess.space.resolveFault(&mut pHarness.fFrames, pAddress, pError) }, Err(-14));
    }
    assert_eq!(pProcess.space.stats()[2], 0);
    assert_eq!(pHarness.fFrames.used(), 4);

    assert_eq!(unsafe { pProcess.space.resolveFault(&mut pHarness.fFrames, gCode, 20) }, Ok(()));
    let mut pText = [0; 32];
    pProcess.space.read(&mut pHarness.fFrames, gCode, &mut pText).unwrap();
    assert_eq!(pText, std::array::from_fn::<u8, 32, _>(textByte));
    let mut pInitializedAndBss = [0xff; 64];
    pProcess.space.read(&mut pHarness.fFrames, gData, &mut pInitializedAndBss).unwrap();
    for pIndex in 0..37 { assert_eq!(pInitializedAndBss[pIndex], dataByte(pIndex)); }
    assert_eq!(&pInitializedAndBss[37..], &[0; 27]);
    let mut pFarBss = [0xff; 32];
    pProcess.space.read(&mut pHarness.fFrames, gData + (gDataPages - 1) * gPage, &mut pFarBss).unwrap();
    assert_eq!(pFarBss, [0; 32]);
    pProcess.space.write(&mut pHarness.fFrames, process::STACK - 8, b"stack").unwrap();
    let pStats = pProcess.space.stats();
    assert_eq!(pStats[2], 4);
    assert_eq!(pStats[5], 4);
    assert_eq!(pStats[2] + pStats[3] + pStats[4] + 2, pHarness.fFrames.used() as u64);
    releaseProcess(&mut pHarness.fFrames, pProcess);
    pHarness.finish();
}

#[test]
fn malformedLoadableRegionsAreRejectedAndReleaseAllLoaderAllocations() {
    let mut pVariants = Vec::new();
    for (pAt, pValue) in [
        (24, gData),
        (gDataHeader + 16, gCode),
        (gDataHeader + 16, paging::USER_END),
        (gDataHeader + 8, usize::MAX - 1),
        (gDataHeader + 32, gDataPages * gPage + 1),
        (gDataHeader + 40, usize::MAX),
        (gDataHeader + 48, 3),
        (gDataHeader + 16, gData + 1),
    ] {
        let mut pElf = programImage();
        put64(&mut pElf, pAt, pValue);
        pVariants.push(pElf);
    }
    for (pAt, pValue) in [(124, 7), (gDataHeader + 4, 0), (gDataHeader, 2)] {
        let mut pElf = programImage();
        put32(&mut pElf, pAt, pValue);
        pVariants.push(pElf);
    }
    for pElf in pVariants {
        let mut pHarness = Harness::new(pElf);
        assert_eq!(pHarness.load().err(), Some(-8));
        pHarness.finish();
    }
}

#[test]
fn invalidNativeNoteFailsBeforeMemoryAllocationAndLoaderOomRollsBack() {
    for (pAt, pValue) in [(64, 0), (276, 2), (280, 1)] {
        let mut pElf = programImage();
        put32(&mut pElf, pAt, pValue);
        let mut pHarness = Harness::new(pElf);
        pHarness.fFrames.allow(0);
        assert_eq!(pHarness.load().err(), Some(-8));
        pHarness.finish();
    }
    // Root, VMA registry and descriptors are the only spawn allocations.
    for pBudget in 0..3 {
        let mut pHarness = Harness::new(programImage());
        pHarness.fFrames.allow(pBudget);
        assert_eq!(pHarness.load().err(), Some(-12));
        pHarness.finish();
    }
    let mut pHarness = Harness::new(programImage());
    pHarness.fFrames.allow(3);
    let pProcess = pHarness.load().ok().expect("lazy load should need only three frames");
    assert_eq!(pProcess.space.stats()[2], 0);
    releaseProcess(&mut pHarness.fFrames, pProcess);
    pHarness.finish();
}

#[test]
fn forkPreservesUnmaterializedElfReservationsAndPrivateBssContents() {
    let mut pHarness = Harness::new(programImage());
    let pParent = pHarness.load().ok().unwrap();
    let pBaseline = pHarness.fFrames.used();
    for pBudget in 0..2 {
        pHarness.fFrames.allow(pBudget);
        assert_eq!(unsafe { pParent.space.fork_cow(&mut pHarness.fFrames, pHarness.fKernelRoot) }.err(), Some(-12));
        assert_eq!(pHarness.fFrames.used(), pBaseline);
        assert_eq!(pParent.space.stats()[2], 0);
    }
    pHarness.fFrames.allow(usize::MAX);
    let pChild = unsafe { pParent.space.fork_cow(&mut pHarness.fFrames, pHarness.fKernelRoot).unwrap() };
    assert_eq!(pChild.stats(), pParent.space.stats());
    let pFar = gData + 30 * gPage;
    pChild.write(&mut pHarness.fFrames, pFar, b"child").unwrap();
    let mut pParentBytes = [0xff; 5];
    pParent.space.read(&mut pHarness.fFrames, pFar, &mut pParentBytes).unwrap();
    assert_eq!(pParentBytes, [0; 5]);
    let mut pChildBytes = [0; 5];
    pChild.read(&mut pHarness.fFrames, pFar, &mut pChildBytes).unwrap();
    assert_eq!(&pChildBytes, b"child");
    // Untouched file-backed regions retain their original source in each copy.
    let mut pText = [0; 12];
    pChild.read(&mut pHarness.fFrames, gCode, &mut pText).unwrap();
    assert_eq!(pText, std::array::from_fn::<u8, 12, _>(textByte));
    assert_eq!(pParent.space.stats()[2], 1);
    assert_eq!(pChild.stats()[2], 2);
    unsafe { pChild.release(&mut pHarness.fFrames); }
    releaseProcess(&mut pHarness.fFrames, pParent);
    pHarness.finish();
}

#[test]
fn fileReadOomOrInvalidDestinationDoesNotAdvanceOffsetOrPartiallyCopy() {
    let mut pHarness = Harness::new(programImage());
    let mut pProcess = pHarness.load().ok().unwrap();
    let pFile = pHarness.fPrograms.vfs.file(b"data").unwrap();
    let pFd = pProcess.files.open(&mut pHarness.fFrames, pFile).unwrap();
    let pDestination = gData + 6 * gPage - 4;
    pProcess.space.write(&mut pHarness.fFrames, pDestination, b"KEEP").unwrap();
    pHarness.fFrames.allow(0);
    assert_eq!(count(pProcess.files.read(&mut pHarness.fFrames, &pProcess.space, pFd, pDestination, 8)), Err(-12));
    let mut pUntouched = [0; 4];
    pProcess.space.read(&mut pHarness.fFrames, pDestination, &mut pUntouched).unwrap();
    assert_eq!(&pUntouched, b"KEEP");
    assert_eq!(count(pProcess.files.read(&mut pHarness.fFrames, &pProcess.space, pFd, paging::USER_END - 1, 8)), Err(-14));
    pHarness.fFrames.allow(usize::MAX);
    assert_eq!(count(pProcess.files.read(&mut pHarness.fFrames, &pProcess.space, pFd, pDestination, 8)), Ok(8));
    let mut pBytes = [0; 16];
    pProcess.space.read(&mut pHarness.fFrames, pDestination, &mut pBytes[..8]).unwrap();
    assert_eq!(count(pProcess.files.read(&mut pHarness.fFrames, &pProcess.space, pFd, pDestination, 8)), Ok(8));
    pProcess.space.read(&mut pHarness.fFrames, pDestination, &mut pBytes[8..]).unwrap();
    assert_eq!(&pBytes, gFileData);
    assert_eq!(count(pProcess.files.read(&mut pHarness.fFrames, &pProcess.space, pFd, pDestination, 8)), Ok(0));
    releaseProcess(&mut pHarness.fFrames, pProcess);
    pHarness.finish();
}

#[test]
fn failedPipeAndSocketPairCopyOutReleasesFramesAndDoesNotInstallDescriptors() {
    for pSocket in [false, true] {
        let mut pHarness = Harness::new(programImage());
        let mut pProcess = pHarness.load().ok().unwrap();
        let pBaseline = pHarness.fFrames.used();
        for _ in 0..20 {
            assert_eq!(pProcess.files.pair(&mut pHarness.fFrames, &pProcess.space, gCode, pSocket), Err(-14));
            assert_eq!(pHarness.fFrames.used(), pBaseline);
        }
        // One frame buys the pipe/channel; prefault must fail, and the
        // unpublished object must be freed along with incomplete page tables.
        pHarness.fFrames.allow(1);
        assert_eq!(pProcess.files.pair(&mut pHarness.fFrames, &pProcess.space, gData + 256, pSocket), Err(-12));
        assert_eq!(pHarness.fFrames.used(), pBaseline);
        assert_eq!(pProcess.space.stats()[2], 0);
        pHarness.fFrames.allow(usize::MAX);
        assert_eq!(pair(&mut pProcess, &mut pHarness.fFrames, pSocket), (0, 2));
        releaseProcess(&mut pHarness.fFrames, pProcess);
        pHarness.finish();
    }
}

#[test]
fn consoleOutputRunsOnlyAfterExplicitCompletionAndOwnsCopiedBytes() {
    gConsoleOutput.with(|pOutput| pOutput.borrow_mut().clear());
    let mut pHarness = Harness::new(programImage());
    let pProcess = pHarness.load().ok().unwrap();
    pHarness.fFrames.allow(0);
    assert_eq!(count(pProcess.files.write(&mut pHarness.fFrames, &pProcess.space, 1, paging::USER_END - 1, 8)), Err(-14));
    assert_eq!(count(pProcess.files.write(&mut pHarness.fFrames, &pProcess.space, 1, gData, 5)), Err(-12));
    assert_eq!(count(pProcess.files.write(&mut pHarness.fFrames, &pProcess.space, 1, gData, 257)), Err(-22));
    gConsoleOutput.with(|pOutput| assert!(pOutput.borrow().is_empty(), "failed prefault wrote to hardware"));
    pHarness.fFrames.allow(usize::MAX);
    // Copy-in must materialize the ELF-backed source while access to Frames
    // is available, but this preparation phase must not touch the UART.
    assert_eq!(pProcess.space.stats()[2], 0);
    let pPending = match pProcess.files.write(&mut pHarness.fFrames, &pProcess.space, 1, gData, 5).unwrap() {
        files::Io::Output(pOutput) => pOutput,
        _ => panic!("console write did not return deferred output"),
    };
    assert_eq!(pProcess.space.stats()[2], 1);
    gConsoleOutput.with(|pOutput| assert!(pOutput.borrow().is_empty(), "UART write happened during frame-lock phase"));
    // The pending write must own a snapshot, not retain a user pointer to
    // revisit after the allocator lock has been released.
    pProcess.space.write(&mut pHarness.fFrames, gData, b"other").unwrap();
    assert_eq!(pPending.complete(), Ok(5));
    gConsoleOutput.with(|pOutput| assert_eq!(&pOutput.borrow()[..], &std::array::from_fn::<u8, 5, _>(dataByte)));
    releaseProcess(&mut pHarness.fFrames, pProcess);
    pHarness.finish();
}

#[test]
fn pipeCopyInAndCopyOutFaultsPreserveQueuedDataAndWakeState() {
    let mut pHarness = Harness::new(programImage());
    let mut pProcess = pHarness.load().ok().unwrap();
    let (pReader, pWriter) = pair(&mut pProcess, &mut pHarness.fFrames, false);
    // Source ELF text is still absent. A failed prefault cannot publish data.
    pHarness.fFrames.allow(0);
    assert_eq!(count(pProcess.files.write(&mut pHarness.fFrames, &pProcess.space, pWriter, gCode, 32)), Err(-12));
    let pWaiting = pProcess.files.read(&mut pHarness.fFrames, &pProcess.space, pReader, gData + 512, 32).unwrap();
    let pWait = match pWaiting { files::Io::Sleep(pWait) => pWait, _ => panic!("failed write published pipe bytes") };
    assert!(!pWait.ready());
    pHarness.fFrames.allow(usize::MAX);
    assert_eq!(count(pProcess.files.write(&mut pHarness.fFrames, &pProcess.space, pWriter, gCode, 32)), Ok(32));
    assert!(pWait.ready());
    let pFar = gData + 20 * gPage;
    pHarness.fFrames.allow(0);
    assert_eq!(count(pProcess.files.read(&mut pHarness.fFrames, &pProcess.space, pReader, pFar, 32)), Err(-12));
    assert_eq!(count(pProcess.files.read(&mut pHarness.fFrames, &pProcess.space, pReader, gCode, 32)), Err(-14));
    assert!(pWait.ready(), "failed copy-out must preserve queued data");
    // The already resident first data page needs no allocation to recover.
    assert_eq!(count(pProcess.files.read(&mut pHarness.fFrames, &pProcess.space, pReader, gData + 512, 32)), Ok(32));
    let mut pBytes = [0; 32];
    pProcess.space.read(&mut pHarness.fFrames, gData + 512, &mut pBytes).unwrap();
    assert_eq!(pBytes, std::array::from_fn::<u8, 32, _>(textByte));
    assert!(!pWait.ready());
    releaseProcess(&mut pHarness.fFrames, pProcess);
    pHarness.finish();
}

#[test]
fn wrappedPipeWriteFailureLeavesOriginalDataAndPublishesNoPartialMessage() {
    let mut pHarness = Harness::new(programImage());
    let mut pProcess = pHarness.load().ok().unwrap();
    let (pReader, pWriter) = pair(&mut pProcess, &mut pHarness.fFrames, false);
    assert_eq!(count(pProcess.files.write(&mut pHarness.fFrames, &pProcess.space, pWriter, gCode, 900)), Ok(900));
    assert_eq!(count(pProcess.files.read(&mut pHarness.fFrames, &pProcess.space, pReader, gData + 512, 800)), Ok(800));
    // Head=800, tail=900. The next 600-byte write wraps the 1024-byte ring.
    let pSource = gData + 8 * gPage - 100;
    pProcess.space.write(&mut pHarness.fFrames, pSource, &[0x55; 100]).unwrap();
    pHarness.fFrames.allow(0);
    assert_eq!(count(pProcess.files.write(&mut pHarness.fFrames, &pProcess.space, pWriter, pSource, 600)), Err(-12));
    assert_eq!(count(pProcess.files.read(&mut pHarness.fFrames, &pProcess.space, pReader, gData + 512, 200)), Ok(100));
    let mut pOldBytes = [0; 100];
    pProcess.space.read(&mut pHarness.fFrames, gData + 512, &mut pOldBytes).unwrap();
    assert_eq!(pOldBytes, std::array::from_fn::<u8, 100, _>(|pIndex| textByte(800 + pIndex)));
    pHarness.fFrames.allow(usize::MAX);
    assert_eq!(count(pProcess.files.write(&mut pHarness.fFrames, &pProcess.space, pWriter, pSource, 600)), Ok(600));
    assert_eq!(count(pProcess.files.read(&mut pHarness.fFrames, &pProcess.space, pReader, gData + 512, 600)), Ok(600));
    let mut pNewBytes = [0xff; 600];
    pProcess.space.read(&mut pHarness.fFrames, gData + 512, &mut pNewBytes).unwrap();
    assert_eq!(&pNewBytes[..100], &[0x55; 100]);
    assert_eq!(&pNewBytes[100..], &[0; 500]);
    releaseProcess(&mut pHarness.fFrames, pProcess);
    pHarness.finish();
}

#[test]
fn ipcPrefaultFailuresPreserveMessageIdentityPayloadAndReceiveBuffer() {
    let mut pHarness = Harness::new(programImage());
    let mut pProcess = pHarness.load().ok().unwrap();
    let (pSender, pReceiver) = pair(&mut pProcess, &mut pHarness.fFrames, true);
    pHarness.fFrames.allow(0);
    assert_eq!(count(pProcess.files.message(&mut pHarness.fFrames, ipc::Operation::Send, &pProcess, pSender, gCode, 32)), Err(-12));
    assert_eq!(pProcess.files.ipc_ready_mask(1 << pReceiver), Ok(0));
    pHarness.fFrames.allow(usize::MAX);
    assert_eq!(count(pProcess.files.message(&mut pHarness.fFrames, ipc::Operation::Send, &pProcess, pSender, gCode, 32)), Ok(32));
    let pDestination = gData + 4 * gPage - 4;
    pProcess.space.write(&mut pHarness.fFrames, pDestination, b"KEEP").unwrap();
    pHarness.fFrames.allow(0);
    assert_eq!(count(pProcess.files.message(&mut pHarness.fFrames, ipc::Operation::Receive, &pProcess, pReceiver, pDestination, 32)), Err(-12));
    let mut pUntouched = [0; 4];
    pProcess.space.read(&mut pHarness.fFrames, pDestination, &mut pUntouched).unwrap();
    assert_eq!(&pUntouched, b"KEEP");
    assert_eq!(count(pProcess.files.message(&mut pHarness.fFrames, ipc::Operation::Receive, &pProcess, pReceiver, gCode, 32)), Err(-14));
    assert_eq!(pProcess.files.ipc_ready_mask(1 << pReceiver), Ok(1 << pReceiver));
    pHarness.fFrames.allow(usize::MAX);
    assert_eq!(count(pProcess.files.message(&mut pHarness.fFrames, ipc::Operation::Receive, &pProcess, pReceiver, pDestination, 32)), Ok(32));
    let mut pMessage = [0; 48];
    pProcess.space.read(&mut pHarness.fFrames, pDestination, &mut pMessage).unwrap();
    assert_eq!(u64::from_le_bytes(pMessage[..8].try_into().unwrap()), pProcess.pid as u64);
    assert_eq!(u32::from_le_bytes(pMessage[8..12].try_into().unwrap()), pProcess.credentials.uid);
    assert_eq!(u32::from_le_bytes(pMessage[12..16].try_into().unwrap()), pProcess.credentials.gid);
    assert_eq!(&pMessage[16..], &std::array::from_fn::<u8, 32, _>(textByte));
    assert_eq!(pProcess.files.ipc_ready_mask(1 << pReceiver), Ok(0));
    releaseProcess(&mut pHarness.fFrames, pProcess);
    pHarness.finish();
}
