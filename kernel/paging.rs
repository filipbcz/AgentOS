//! Process regions reserve virtual memory independently of resident pages.
//! The owner CPU serializes updates with IRQs masked; frame allocation and
//! COW reference changes also hold SharedFrames. Processes do not migrate yet.
#![allow(non_snake_case)]
use crate::{frames::{ram, Frame, Frames}, BootInfo};
use core::{arch::{asm, x86_64::__cpuid}, ptr};

const PAGE: usize = 4096;
const PRESENT: u64 = 1;
const WRITE: u64 = 2;
const NX: u64 = 1 << 63;
const MMIO: u64 = NX | WRITE | (1 << 3) | (1 << 4);
const ADDRESS: u64 = 0x000f_ffff_ffff_f000;
const USER: u64 = 4;
const COW: u64 = 1 << 9;
const EFAULT: isize = -14;
const ENOMEM: isize = -12;
const ENOEXEC: isize = -8;
pub const USER_BASE: usize = 1 << 39;
pub const USER_END: usize = 2 << 39;
pub const MAX_REGIONS: usize = 64;
// Permanent supervisor-only PCI MMIO window, disjoint from slot 1 (users)
// and slot 256 (guarded stacks). Map only explicitly claimed device pages.
const DEVICE_BASE: usize = 0xffff_9000_0000_0000;
const DEVICE_PHYS_LIMIT: usize = 1 << 44; // first 16 TiB of device physical space
const MAX_DEVICE_PAGES: usize = 16;

#[derive(Clone, Copy)]
struct Region {
    fStart: usize,
    fEnd: usize,
    fContents: &'static [u8],
    fWrite: bool,
    fExecute: bool,
}
impl Region {
    const EMPTY: Self = Self { fStart: 0, fEnd: 0, fContents: &[], fWrite: false, fExecute: false };
    fn firstPage(self) -> usize { self.fStart & !(PAGE-1) }
    fn pageEnd(self) -> usize { (self.fEnd + PAGE-1) & !(PAGE-1) }
    fn permits(self, aAccess: Access) -> bool {
        match aAccess { Access::Read => true, Access::Write => self.fWrite, Access::Execute => self.fExecute }
    }
}
struct Regions {
    fCount: usize,
    fDemandPages: u64,
    fCowCopies: u64,
    fCowPromotions: u64,
    fRegions: [Region; MAX_REGIONS],
}
const _: () = assert!(core::mem::size_of::<Regions>() <= PAGE);
#[derive(Clone, Copy)]
enum Access { Read, Write, Execute }

// Keep the per-task value small: Cpu embeds eight task/process slots in one
// frame. Region metadata owns a separate frame and is never mapped to CPL3.
pub struct UserSpace { pub root: usize, fMetadata: usize }

impl UserSpace {
    pub unsafe fn new(aFrames: &mut Frames<'_>, aKernel: usize) -> Option<Self> {
        if *((aKernel as *const u64).add(1)) != 0 { return None; }
        let pRoot = aFrames.alloc()?;
        let Some(pMetadata) = aFrames.alloc_zeroed() else { aFrames.release(pRoot); return None; };
        ptr::copy_nonoverlapping(aKernel as *const u64, pRoot.address() as *mut u64, 512);
        (pMetadata.address() as *mut Regions).write(Regions {
            fCount: 0, fDemandPages: 0, fCowCopies: 0, fCowPromotions: 0,
            fRegions: [Region::EMPTY; MAX_REGIONS],
        });
        Some(Self { root: pRoot.into_address(), fMetadata: pMetadata.into_address() })
    }

    /// Reserve a loader-validated region without allocating page tables or
    /// data. Page-rounded regions must not overlap, including ELF padding.
    /// Contents refer only to the immutable initramfs, which outlives processes.
    /// This profile supports 64 regions, all readable, optionally writable OR
    /// executable. Invalid inputs/capacity return ENOEXEC without mutation.
    pub unsafe fn reserve(&self, aStart: usize, aLength: usize, aContents: &'static [u8],
                          aWrite: bool, aExecute: bool) -> Result<(), isize> {
        let pEnd = aStart.checked_add(aLength).ok_or(ENOEXEC)?;
        if aLength == 0 || aStart < USER_BASE || pEnd > USER_END ||
           aContents.len() > aLength || (aWrite && aExecute) { return Err(ENOEXEC); }
        let pRegion = Region { fStart: aStart, fEnd: pEnd, fContents: aContents, fWrite: aWrite, fExecute: aExecute };
        let pMetadata = &mut *(self.fMetadata as *mut Regions);
        if pMetadata.fCount == MAX_REGIONS || pMetadata.fRegions[..pMetadata.fCount].iter().any(|pOther|
            pRegion.firstPage() < pOther.pageEnd() && pOther.firstPage() < pRegion.pageEnd()) { return Err(ENOEXEC); }
        pMetadata.fRegions[pMetadata.fCount] = pRegion;
        pMetadata.fCount += 1;
        Ok(())
    }

    fn region(&self, aVa: usize) -> Option<Region> {
        let pMetadata = unsafe { &*(self.fMetadata as *const Regions) };
        pMetadata.fRegions[..pMetadata.fCount].iter().copied()
            .find(|pRegion| pRegion.firstPage() <= aVa && aVa < pRegion.pageEnd())
    }

    /// Clone metadata including absent reservations, and retain resident data.
    /// Nothing changes in the parent until every child allocation succeeds.
    pub unsafe fn fork_cow(&self, aFrames: &mut Frames<'_>, aKernel: usize) -> Result<Self, isize> {
        unsafe fn copyBranch(aFrames: &mut Frames<'_>, aFrom: usize, aTo: usize, aLevel: u8) -> Option<()> {
            for pIndex in 0..512 {
                let pValue = *((aFrom as *const u64).add(pIndex));
                if pValue & PRESENT == 0 { continue; }
                if aLevel == 1 {
                    aFrames.retain((pValue & ADDRESS) as usize)?;
                    let pFlags = if pValue & WRITE != 0 { (pValue & !WRITE) | COW } else { pValue };
                    *((aTo as *mut u64).add(pIndex)) = pFlags;
                } else {
                    let pBranch = aFrames.alloc_zeroed()?.into_address();
                    *((aTo as *mut u64).add(pIndex)) = pBranch as u64 | (pValue & !ADDRESS);
                    copyBranch(aFrames, (pValue & ADDRESS) as usize, pBranch, aLevel-1)?;
                }
            }
            Some(())
        }
        unsafe fn protectBranch(aTable: usize, aLevel: u8) {
            for pIndex in 0..512 {
                let pEntry = (aTable as *mut u64).add(pIndex);
                let pValue = *pEntry;
                if pValue & PRESENT == 0 { continue; }
                if aLevel == 1 {
                    if pValue & WRITE != 0 { *pEntry = (pValue & !WRITE) | COW; }
                } else { protectBranch((pValue & ADDRESS) as usize, aLevel-1); }
            }
        }
        let pChild = Self::new(aFrames, aKernel).ok_or(ENOMEM)?;
        ptr::copy_nonoverlapping(self.fMetadata as *const Regions, pChild.fMetadata as *mut Regions, 1);
        let pMetadata = &mut *(pChild.fMetadata as *mut Regions);
        pMetadata.fDemandPages = 0;
        pMetadata.fCowCopies = 0;
        pMetadata.fCowPromotions = 0;
        let pOriginal = *((self.root as *const u64).add(1));
        if pOriginal & PRESENT != 0 {
            let Some(pFirst) = aFrames.alloc_zeroed() else { pChild.release(aFrames); return Err(ENOMEM); };
            *((pChild.root as *mut u64).add(1)) = pFirst.into_address() as u64 | (pOriginal & !ADDRESS);
            if copyBranch(aFrames, (pOriginal & ADDRESS) as usize,
                          (*((pChild.root as *const u64).add(1)) & ADDRESS) as usize, 3).is_none() {
                pChild.release(aFrames);
                return Err(ENOMEM);
            }
            protectBranch((pOriginal & ADDRESS) as usize, 3);
            // Both spaces remain pinned to this CPU; invalidate its writable
            // parent translations only after the clone transaction succeeds.
            #[cfg(not(test))]
            asm!("mov cr3, {}", in(reg) self.root, options(nostack));
        }
        Ok(pChild)
    }

    unsafe fn leaf(&self, aVa: usize) -> Option<*mut u64> {
        if !(USER_BASE..USER_END).contains(&aVa) { return None; }
        let mut pNode = self.root;
        for pShift in [39, 30, 21] {
            let pValue = *((pNode as *const u64).add((aVa >> pShift) & 511));
            if pValue & (PRESENT | USER) != (PRESENT | USER) { return None; }
            pNode = (pValue & ADDRESS) as usize;
        }
        Some((pNode as *mut u64).add((aVa >> 12) & 511))
    }

    unsafe fn resolveCow(&self, aFrames: &mut Frames<'_>, aVa: usize) -> Result<bool, isize> {
        let pLeaf = self.leaf(aVa).ok_or(EFAULT)?;
        let pPrevious = *pLeaf;
        if pPrevious & (PRESENT | USER | COW) != (PRESENT | USER | COW) ||
           pPrevious & WRITE != 0 { return Ok(false); }
        let pOld = (pPrevious & ADDRESS) as usize;
        let pCount = aFrames.references(pOld).ok_or(EFAULT)?;
        let pAddress = if pCount == 1 { pOld } else {
            let pFresh = aFrames.alloc().ok_or(ENOMEM)?.into_address();
            ptr::copy_nonoverlapping(pOld as *const u8, pFresh as *mut u8, PAGE);
            pFresh
        };
        *pLeaf = ((pPrevious & !ADDRESS) & !COW) | WRITE | pAddress as u64;
        if pCount > 1 { aFrames.release(Frame::from_owned_address(pOld)); }
        let pMetadata = &mut *(self.fMetadata as *mut Regions);
        if pCount > 1 { pMetadata.fCowCopies = pMetadata.fCowCopies.saturating_add(1); }
        else { pMetadata.fCowPromotions = pMetadata.fCowPromotions.saturating_add(1); }
        #[cfg(not(test))]
        asm!("invlpg [{}]", in(reg) (aVa & !(PAGE-1)), options(nostack, preserves_flags));
        Ok(true)
    }

    #[cfg(test)]
    pub unsafe fn resolve_cow(&self, aFrames: &mut Frames<'_>, aVa: usize) -> Option<bool> {
        self.resolveCow(aFrames, aVa).ok()
    }

    /// Allocate an absent page transactionally. Any new page-table branch is
    /// private until its data page and contents are ready. Every OOM point
    /// frees all unpublished tables and leaves the live page tree unchanged.
    unsafe fn materialize(&self, aFrames: &mut Frames<'_>, aVa: usize, aAccess: Access) -> Result<(), isize> {
        let pRegion = self.region(aVa).filter(|pRegion| pRegion.permits(aAccess)).ok_or(EFAULT)?;
        if let Some(pLeaf) = self.leaf(aVa) {
            if *pLeaf & PRESENT != 0 {
                if matches!(aAccess, Access::Write) && self.translate(aVa, true).is_none() {
                    if !self.resolveCow(aFrames, aVa)? { return Err(EFAULT); }
                }
                return self.translate(aVa, matches!(aAccess, Access::Write)).map(|_| ()).ok_or(EFAULT);
            }
        }
        let pPage = aVa & !(PAGE-1);
        let mut pTables = [0usize; 3];
        let mut pTableCount = 0;
        let mut pPublishEntry: *mut u64 = ptr::null_mut();
        let mut pPublishValue = 0;
        let mut pNode = self.root;
        let pResult = (|| {
            for pShift in [39, 30, 21] {
                let pEntry = (pNode as *mut u64).add((pPage >> pShift) & 511);
                let pValue = *pEntry;
                if pValue == 0 {
                    let pAddress = aFrames.alloc_zeroed().ok_or(ENOMEM)?.into_address();
                    pTables[pTableCount] = pAddress;
                    pTableCount += 1;
                    let pNew = pAddress as u64 | USER | PRESENT | WRITE;
                    if pPublishEntry.is_null() { pPublishEntry = pEntry; pPublishValue = pNew; }
                    else { *pEntry = pNew; }
                    pNode = pAddress;
                } else {
                    if pValue & (PRESENT | USER | WRITE) != (PRESENT | USER | WRITE) { return Err(EFAULT); }
                    pNode = (pValue & ADDRESS) as usize;
                }
            }
            let pLeaf = (pNode as *mut u64).add((pPage >> 12) & 511);
            if *pLeaf != 0 { return Err(EFAULT); }
            let pData = aFrames.alloc_zeroed().ok_or(ENOMEM)?.into_address();
            let pStart = pPage.max(pRegion.fStart);
            let pStop = (pPage+PAGE).min(pRegion.fStart+pRegion.fContents.len());
            if pStart < pStop {
                ptr::copy_nonoverlapping(pRegion.fContents.as_ptr().add(pStart-pRegion.fStart),
                    (pData+pStart-pPage) as *mut u8, pStop-pStart);
            }
            *pLeaf = pData as u64 | USER | PRESENT | (if pRegion.fWrite { WRITE } else { 0 }) |
                (if pRegion.fExecute { 0 } else { NX });
            if !pPublishEntry.is_null() { *pPublishEntry = pPublishValue; }
            Ok(())
        })();
        if pResult.is_err() {
            for &pTable in pTables[..pTableCount].iter().rev() { aFrames.release(Frame::from_owned_address(pTable)); }
            return pResult;
        }
        let pMetadata = &mut *(self.fMetadata as *mut Regions);
        pMetadata.fDemandPages = pMetadata.fDemandPages.saturating_add(1);
        #[cfg(not(test))]
        asm!("invlpg [{}]", in(reg) pPage, options(nostack, preserves_flags));
        Ok(())
    }

    /// Only supported, genuine CPL3 page-fault causes may create a mapping.
    /// Reject reserved-bit, protection-key, shadow-stack and instruction NX
    /// violations; a protection fault resolves only an explicit COW write.
    pub unsafe fn resolveFault(&self, aFrames: &mut Frames<'_>, aVa: usize, aError: u64) -> Result<(), isize> {
        if aError == 7 {
            if !self.region(aVa).map_or(false, |pRegion| pRegion.fWrite) { return Err(EFAULT); }
            return if self.resolveCow(aFrames, aVa)? { Ok(()) } else { Err(EFAULT) };
        }
        let pAccess = match aError { 4 => Access::Read, 6 => Access::Write, 20 => Access::Execute, _ => return Err(EFAULT) };
        if self.leaf(aVa).map_or(false, |pLeaf| *pLeaf & PRESENT != 0) { return Err(EFAULT); }
        self.materialize(aFrames, aVa, pAccess)
    }

    #[cfg(test)]
    pub unsafe fn map(&self, aFrames: &mut Frames<'_>, aVa: usize, aWrite: bool, aExecute: bool) -> Result<usize, isize> {
        if aVa % PAGE != 0 { return Err(ENOEXEC); }
        let pOldCount = (*(self.fMetadata as *const Regions)).fCount;
        self.reserve(aVa, PAGE, &[], aWrite, aExecute)?;
        if let Err(pError) = self.materialize(aFrames, aVa, Access::Read) {
            (*(self.fMetadata as *mut Regions)).fCount = pOldCount;
            return Err(pError);
        }
        self.translate(aVa, false).ok_or(EFAULT)
    }

    unsafe fn translate(&self, aVa: usize, aWriting: bool) -> Option<usize> {
        if !(USER_BASE..USER_END).contains(&aVa) { return None; }
        let mut pNode = self.root;
        for pShift in [39, 30, 21, 12] {
            let pEntry = *((pNode as *const u64).add((aVa >> pShift) & 511));
            let pRequired = USER | PRESENT | if aWriting { WRITE } else { 0 };
            if pEntry & pRequired != pRequired { return None; }
            pNode = (pEntry & ADDRESS) as usize;
        }
        Some(pNode + aVa % PAGE)
    }

    fn validateRange(&self, aVa: usize, aLength: usize, aAccess: Access) -> Result<usize, isize> {
        let pEnd = aVa.checked_add(aLength).ok_or(EFAULT)?;
        let mut pPosition = aVa;
        while pPosition < pEnd {
            if !self.region(pPosition).map_or(false, |pRegion| pRegion.permits(aAccess)) { return Err(EFAULT); }
            pPosition += (PAGE-pPosition % PAGE).min(pEnd-pPosition);
        }
        Ok(pEnd)
    }

    /// Validate all pages before any allocation, then prepare every page before
    /// copying bytes. On multipage OOM, successfully prepared pages may remain
    /// resident (and COW may already be separated), but no bytes/I/O commit.
    fn prepareRange(&self, aFrames: &mut Frames<'_>, aVa: usize, aLength: usize, aAccess: Access) -> Result<(), isize> {
        let pEnd = self.validateRange(aVa, aLength, aAccess)?;
        let mut pPosition = aVa;
        while pPosition < pEnd {
            unsafe { self.materialize(aFrames, pPosition, aAccess)?; }
            pPosition += (PAGE-pPosition % PAGE).min(pEnd-pPosition);
        }
        Ok(())
    }

    pub fn readable(&self, aFrames: &mut Frames<'_>, aVa: usize, aLength: usize) -> Result<(), isize> {
        self.prepareRange(aFrames, aVa, aLength, Access::Read)
    }
    pub fn writable(&self, aFrames: &mut Frames<'_>, aVa: usize, aLength: usize) -> Result<(), isize> {
        self.prepareRange(aFrames, aVa, aLength, Access::Write)
    }
    pub fn read(&self, aFrames: &mut Frames<'_>, aVa: usize, aDst: &mut [u8]) -> Result<(), isize> {
        self.readable(aFrames, aVa, aDst.len())?;
        let mut pDone = 0;
        while pDone < aDst.len() {
            let pAddress = aVa+pDone;
            let pCount = (PAGE-pAddress % PAGE).min(aDst.len()-pDone);
            unsafe { ptr::copy_nonoverlapping(self.translate(pAddress, false).ok_or(EFAULT)? as *const u8,
                                             aDst.as_mut_ptr().add(pDone), pCount); }
            pDone += pCount;
        }
        Ok(())
    }
    pub fn write(&self, aFrames: &mut Frames<'_>, aVa: usize, aSrc: &[u8]) -> Result<(), isize> {
        self.writable(aFrames, aVa, aSrc.len())?;
        let mut pDone = 0;
        while pDone < aSrc.len() {
            let pAddress = aVa+pDone;
            let pCount = (PAGE-pAddress % PAGE).min(aSrc.len()-pDone);
            unsafe { ptr::copy_nonoverlapping(aSrc.as_ptr().add(pDone),
                                             self.translate(pAddress, true).ok_or(EFAULT)? as *mut u8, pCount); }
            pDone += pCount;
        }
        Ok(())
    }

    /// Per-address-space counts, excluding all shared kernel mappings. The
    /// cumulative counters start at zero in a newly forked child; its current
    /// resident/table counts still reflect inherited mappings.
    pub fn stats(&self) -> [u64; 8] {
        unsafe fn countBranch(aTable: usize, aLevel: u8) -> (u64, u64) {
            if aLevel == 0 { return (1, 0); }
            let (mut pData, mut pTables) = (0, 1);
            for &pEntry in core::slice::from_raw_parts(aTable as *const u64, 512) {
                if pEntry & PRESENT == 0 { continue; }
                let (pChildData, pChildTables) = countBranch((pEntry & ADDRESS) as usize, aLevel-1);
                pData += pChildData;
                pTables += pChildTables;
            }
            (pData, pTables)
        }
        let pMetadata = unsafe { &*(self.fMetadata as *const Regions) };
        let pReserved = pMetadata.fRegions[..pMetadata.fCount].iter()
            .map(|pRegion| ((pRegion.pageEnd()-pRegion.firstPage())/PAGE) as u64).sum();
        let pBranch = unsafe { *((self.root as *const u64).add(1)) };
        let (pData, pTables) = if pBranch & PRESENT != 0 {
            unsafe { countBranch((pBranch & ADDRESS) as usize, 3) }
        } else { (0, 0) };
        [1, pReserved, pData, 1+pTables, 1, pMetadata.fDemandPages, pMetadata.fCowCopies, pMetadata.fCowPromotions]
    }

    /// Enumerate only the private user page-table branch and resident data.
    /// Root/region metadata already existed at lazy spawn and are excluded.
    /// The owner must hold IRQ/frame serialization while consuming the list.
    /// A callback failure stops immediately; callers must reject that attempt.
    pub fn visitResidentFrames(&self, mut aVisit: impl FnMut(usize) -> bool) -> bool {
        unsafe fn visitBranch(aPage: usize, aLevel: u8, aVisit: &mut impl FnMut(usize) -> bool) -> bool {
            if !aVisit(aPage) { return false; }
            if aLevel > 0 {
                for &pEntry in core::slice::from_raw_parts(aPage as *const u64, 512) {
                    if pEntry & PRESENT != 0 &&
                       !visitBranch((pEntry & ADDRESS) as usize, aLevel-1, aVisit) { return false; }
                }
            }
            true
        }
        let pBranch = unsafe { *((self.root as *const u64).add(1)) };
        pBranch & PRESENT == 0 || unsafe { visitBranch((pBranch & ADDRESS) as usize, 3, &mut aVisit) }
    }

    // Caller has switched away from this root. No other CPU runs the process.
    pub unsafe fn release(self, aFrames: &mut Frames<'_>) {
        unsafe fn freeBranch(aFrames: &mut Frames<'_>, aPage: usize, aLevel: u8) {
            if aLevel > 0 {
                for &pEntry in core::slice::from_raw_parts(aPage as *const u64, 512) {
                    if pEntry & PRESENT != 0 { freeBranch(aFrames, (pEntry & ADDRESS) as usize, aLevel-1); }
                }
            }
            aFrames.release(Frame::from_owned_address(aPage));
        }
        let pBranch = *((self.root as *const u64).add(1));
        if pBranch & PRESENT != 0 { freeBranch(aFrames, (pBranch & ADDRESS) as usize, 3); }
        freeBranch(aFrames, self.root, 0);
        aFrames.release(Frame::from_owned_address(self.fMetadata));
    }
}

extern "C" { static kernel_begin: u8; static kernel_ro: u8; static kernel_rw: u8; static kernel_end: u8; }

/// Actual runtime image base, used for crash symbolization and diagnostics.
pub fn image_base() -> usize { unsafe { ptr::addr_of!(kernel_begin) as usize } }

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

// Add a device page before the first secondary CPU or process is started.
pub unsafe fn map_device(root: usize, frames: &mut Frames<'_>, address: usize) -> Option<()> {
    if address >= USER_BASE || address & (PAGE - 1) != 0 { return None; }
    Tables { root, frames }.identity(address, PAGE, MMIO)?;
    asm!("invlpg [{}]", in(reg) address, options(nostack, preserves_flags));
    Some(())
}

// Inspect a supervisor leaf without creating a mapping. Reject huge pages,
// malformed ancestors and user-owned branches rather than treating them as free.
unsafe fn device_leaf(root: usize, va: usize) -> Option<u64> {
    let mut node = root;
    for shift in [39, 30, 21] {
        let value = *((node as *const u64).add((va >> shift) & 511));
        if value == 0 { return Some(0); }
        if value & (PRESENT | WRITE | USER | (1 << 7)) != PRESENT | WRITE {
            return None;
        }
        node = (value & ADDRESS) as usize;
        if node == 0 { return None; }
    }
    Some(*((node as *const u64).add((va >> 12) & 511)))
}

// Must be called by the BSP before publishing any process root or starting APs.
// For low device addresses retain the existing uncached identity convention;
// high BARs may occupy the *physical* range reserved for user virtual memory.
// Give those pages a separate supervisor-only canonical VA instead. Never
// create a conflicting cached alias of an existing identity mapping.
pub unsafe fn map_device_window(root: usize, frames: &mut Frames<'_>,
                                physical: usize, pages: usize) -> Option<usize> {
    // Host tests use synthetic physical addresses independently of host CPUID.
    #[cfg(test)]
    let bits = 52u32;
    #[cfg(not(test))]
    let bits = if __cpuid(0x80000000).eax >= 0x80000008 {
        __cpuid(0x80000008).eax & 0xff
    } else { return None; };
    if !(32..=52).contains(&bits) || physical < PAGE || physical % PAGE != 0 ||
       pages == 0 || pages > MAX_DEVICE_PAGES || root == 0 || root % PAGE != 0 {
        return None;
    }
    let end = physical.checked_add(pages.checked_mul(PAGE)?)?;
    if end > (1usize << bits) || end > DEVICE_PHYS_LIMIT ||
       (physical < USER_BASE && end > USER_BASE) { return None; }
    let high = physical >= USER_BASE;
    let base = if high { DEVICE_BASE.checked_add(physical)? } else { physical };
    let ad = (1 << 5) | (1 << 6);
    for i in 0..pages {
        let pa = physical + i * PAGE;
        if high && device_leaf(root, pa)? != 0 { return None; }
        let old = device_leaf(root, base + i * PAGE)?;
        if old != 0 && old & !ad != pa as u64 | PRESENT | MMIO { return None; }
    }

    // Publish new branches only while this root is exclusive. Roll back every
    // newly allocated page table on OOM. Do not modify any leaf until all
    // branches are ready, so existing mappings remain intact on failure.
    let mut allocated = [(ptr::null_mut::<u64>(), 0usize); MAX_DEVICE_PAGES * 3];
    let mut count = 0;
    let mut leaves = [ptr::null_mut::<u64>(); MAX_DEVICE_PAGES];
    let result = (|| {
        for (i, leaf) in leaves[..pages].iter_mut().enumerate() {
            let va = base + i * PAGE;
            let mut node = root;
            for shift in [39, 30, 21] {
                let entry = (node as *mut u64).add((va >> shift) & 511);
                if *entry == 0 {
                    let address = frames.alloc_zeroed()?.into_address();
                    allocated[count] = (entry, address);
                    count += 1;
                    *entry = address as u64 | PRESENT | WRITE | NX;
                }
                // Preflight inspected old branches; new branches are ours.
                node = (*entry & ADDRESS) as usize;
            }
            *leaf = (node as *mut u64).add((va >> 12) & 511);
        }
        Some(())
    })();
    if result.is_none() {
        for &(entry, address) in allocated[..count].iter().rev() {
            *entry = 0;
            frames.release(Frame::from_owned_address(address));
        }
        return None;
    }
    for (i, &leaf) in leaves[..pages].iter().enumerate() {
        if *leaf == 0 { *leaf = (physical + i * PAGE) as u64 | PRESENT | MMIO; }
        #[cfg(not(test))]
        asm!("invlpg [{}]", in(reg) (base + i * PAGE), options(nostack, preserves_flags));
    }
    Some(base)
}

// Grant write access only to the driver's previously mapped ECAM function.
pub unsafe fn claim_config(root: usize, page: usize) -> Option<()> {
    if page >= USER_BASE || page & (PAGE - 1) != 0 { return None; }
    let mut node = root;
    for shift in [39, 30, 21] {
        let entry = *((node as *const u64).add((page >> shift) & 511));
        if entry & PRESENT == 0 || entry & (1 << 7) != 0 { return None; }
        node = (entry & ADDRESS) as usize;
    }
    let leaf = (node as *mut u64).add((page >> 12) & 511);
    if *leaf & !(1 << 5) != (page as u64 | (MMIO & !WRITE) | PRESENT) { return None; }
    *leaf |= WRITE;
    asm!("invlpg [{}]", in(reg) page, options(nostack, preserves_flags));
    Some(())
}

/// Called once by the BSP with interrupts disabled, on the loader-provided stack.
pub unsafe fn install(info: &BootInfo, map: &[u8], frames: &mut Frames<'_>, platform: &crate::acpi::Platform,
                      pci_windows: impl Iterator<Item=(usize, usize)>) -> Option<usize> {
    let cr4: usize;
    asm!("mov {}, cr4", out(reg) cr4);
    if cr4 & (1 << 12) != 0 || __cpuid(0x80000000).eax < 0x80000001 ||
       __cpuid(0x80000001).edx & (1 << 20) == 0 { return None; }
    // APs load this shared bootstrap CR3 from a 32-bit protected-mode
    // trampoline (MOV CR3,EAX) before entering long mode. Other page-table
    // pages use 64-bit physical pointers and do not need this restriction.
    let root = frames.alloc_zeroed_below(u32::MAX as u64)?.into_address();
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
    if platform.hpet != 0 { tables.identity(platform.hpet, PAGE, MMIO)?; }
    for io in &platform.io_apics[..platform.io_count] { tables.identity(io.address, PAGE, MMIO)?; }
    tables.identity(info.framebuffer as usize, info.stride as usize * info.height as usize * 4, MMIO)?;
    for (start, size) in pci_windows {
        tables.identity(start, size, MMIO & !WRITE)?;
    }

    // User roots copy this shared upper-half subtree; runtime stack allocation
    // changes only its preallocated leaf tables, never an individual root.
    crate::stack::prepare(tables.frames, root)?;

    // Firmware may leave global translations in the TLB. Flush those as well.
    asm!("rdmsr", "bts eax, 11", "wrmsr", in("ecx") 0xc0000080u32,
         out("eax") _, out("edx") _);
    let active: usize;
    asm!("mov cr4, {cr4}", "mov cr3, {root}", "mov {tmp}, cr0",
         "bts {tmp}, 16", "mov cr0, {tmp}", "mov {tmp}, cr3",
         cr4=in(reg) (cr4 & !(1 << 7)), root=in(reg) root, tmp=out(reg) active);
    (active == root).then_some(root)
}
