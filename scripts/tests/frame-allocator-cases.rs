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


// Physical numbers in these tests are deliberately independent of virtual
// host pointers. The real allocator uses exactly these free/refcount slices.
fn withFree(aFree: &[usize], aRun: impl FnOnce(&mut Frames<'_>)) {
    let highest = aFree.iter().copied().max().unwrap_or(0) + 1;
    let mut free = vec![0usize; highest.div_ceil(WORD_BITS)];
    let mut refs = vec![0u16; highest];
    for &i in aFree { free[i / WORD_BITS] |= 1 << (i % WORD_BITS); }
    let available = free.iter().map(|w| w.count_ones() as usize).sum();
    let mut frames = Frames {
        free: &mut free, refs: &mut refs, next_word: 0, available, kernel_root: 0
    };
    aRun(&mut frames);
}

#[test]
fn fullPageMustFitDmaMaskIncludingFinalByte() {
    let boundary = (1usize << 32) / PAGE;
    withFree(&[boundary-2, boundary-1, boundary, boundary+1], |f| {
        let low = f.alloc_below((boundary*PAGE-2) as u64).unwrap();
        assert_eq!(low.address(), (boundary-2)*PAGE);
        let before = (f.free.to_vec(), f.refs.to_vec(), f.next_word, f.available());
        assert!(f.alloc_below((boundary*PAGE-2) as u64).is_none());
        assert_eq!((f.free.to_vec(), f.refs.to_vec(), f.next_word, f.available()), before);
        let edge = f.alloc_below(u32::MAX as u64).unwrap();
        assert_eq!(edge.address(), (1usize<<32)-PAGE);
        assert!(crate::dma::BusAddress::of(&edge, u32::MAX as u64).is_some());
        assert!(f.alloc_below(u32::MAX as u64).is_none());
        let high = f.alloc().unwrap();
        assert_eq!(high.address(), 1usize<<32);
        assert!(crate::dma::BusAddress::of(&high, u32::MAX as u64).is_none());
        assert!(crate::dma::BusAddress::of(&high, u64::MAX).is_some());
        for frame in [high, edge, low] { f.release(frame); }
        assert_eq!(f.available(),4);
        let restored = f.alloc_below(u32::MAX as u64).unwrap();
        assert_eq!(restored.address(), (boundary-2)*PAGE);
        f.release(restored);
    });
}

#[test]
fn contiguousAlignedRangeCrossesBitmapWordsAndRespectsHoles() {
    // 64-bit bitmap words; 62..=67 straddles one word, and a hole at
    // 69 prevents selecting the otherwise aligned 68..=71 interval.
    let free: Vec<_> = (60..=95).filter(|&i| i != 69 && i != 73).collect();
    withFree(&free, |f| {
        let n = f.available();
        let range = f.alloc_contiguous(6, 2*PAGE, 61*PAGE as u64, 68*PAGE as u64-1).unwrap();
        assert_eq!((range.address(),range.page_count(),range.byte_len()),(62*PAGE,6,6*PAGE));
        for i in 62..68 { assert_eq!(f.references(i*PAGE),Some(1)); }
        let higher = f.alloc_contiguous(4, 4*PAGE, 68*PAGE as u64, 96*PAGE as u64-1).unwrap();
        assert_eq!(higher.address(),76*PAGE);
        let ordinary = f.alloc().unwrap();
        assert_eq!(ordinary.address(),60*PAGE); // range search did not skip lower free RAM
        assert_eq!(f.available(),n-11);
        f.retain(64*PAGE).unwrap();
        f.release_range(range);
        assert_eq!(f.references(64*PAGE),Some(1));
        assert_eq!(f.references(63*PAGE),None);
        f.release_range(higher);
        f.release(ordinary);
        assert_eq!(f.available(),n-1);
        f.release(unsafe { Frame::from_owned_address(64*PAGE) });
        assert_eq!(f.available(),n);
        let all = f.alloc_contiguous(22, PAGE, 74*PAGE as u64, 96*PAGE as u64-1).unwrap();
        assert_eq!(all.address(),74*PAGE);
        f.release_range(all);
        assert_eq!(f.available(),n);
    });
}

#[test]
fn failedRangesAreTransactionalAndDoNotOverflow() {
    withFree(&[1,2,4,5,7,8,9,65],|f|{
        let before = (f.free.to_vec(),f.refs.to_vec(),f.next_word,f.available());
        for (pages,alignment,min,max) in [
            (0,PAGE,0,u64::MAX),
            (1,1,0,u64::MAX),
            (1,3*PAGE,0,u64::MAX),
            (1,PAGE,10,9),
            (usize::MAX,PAGE,0,u64::MAX),
            (1,PAGE,0,4094),
            (1,PAGE,u64::MAX,u64::MAX),
            (1,PAGE,65*PAGE as u64+1,66*PAGE as u64-1),
            (3,PAGE,0,7*PAGE as u64-1),
            (1,1usize<<63,1,u64::MAX),
            (1,PAGE,66*PAGE as u64,u64::MAX)
        ] {
            assert!(f.alloc_contiguous(pages,alignment,min,max).is_none(),
                    "accepted invalid range: {pages} {alignment} {min} {max}");
            assert_eq!((f.free.to_vec(),f.refs.to_vec(),f.next_word,f.available()),before);
        }
        // A failed zeroed allocation may not touch fictitious RAM either.
        assert!(f.alloc_zeroed_contiguous(3,PAGE,0,7*PAGE as u64-1).is_none());
        assert!(f.alloc_zeroed_below(4094).is_none());
        assert_eq!((f.free.to_vec(),f.refs.to_vec(),f.next_word,f.available()),before);
    });
}

#[test]
fn constrainedAllocatorMatchesReferenceSearch() {
    // Deterministic mixed allocate/free workloads across holes, alignment,
    // inclusive partial boundaries and cursor changes. No external crate.
    let capacity = 3*WORD_BITS+7;
    let free: Vec<_> = (1..capacity).filter(|i| i%11!=0 && i%17!=0).collect();
    withFree(&free, |f| {
        let mut model=vec![false;capacity];
        for &i in &free { model[i]=true; }
        let mut held:Vec<FrameRange>=Vec::new();
        let mut state=0x7834_bef2u64;
        let mut random=||{state=state.wrapping_mul(6364136223846793005).wrapping_add(1);(state>>32) as usize};
        for _ in 0..1500 {
            if !held.is_empty() && random()%4==0 {
                let token=held.swap_remove(random()%held.len());
                let start=token.address()/PAGE;
                for bit in &mut model[start..start+token.page_count()] {*bit=true;}
                f.release_range(token);
            } else {
                let pages=random()%13+1;
                let alignment=1usize<<(random()%5);
                let min=random()%(capacity*PAGE);
                let max=random()%(capacity*PAGE);
                let expected=(0..capacity).find(|&i|{
                    i%alignment==0 && i*PAGE>=min && i+pages<=capacity &&
                    (i+pages)*PAGE-1<=max && model[i..i+pages].iter().all(|&bit|bit)
                });
                let actual=f.alloc_contiguous(pages,alignment*PAGE,min as u64,max as u64);
                assert_eq!(actual.as_ref().map(|v|v.address()/PAGE),expected);
                if let Some(range)=actual {
                    let start=range.address()/PAGE;
                    for bit in &mut model[start..start+pages] {*bit=false;}
                    held.push(range);
                }
            }
            assert_eq!(f.available(),model.iter().filter(|&&bit|bit).count());
            for (i,&bit) in model.iter().enumerate(){
                assert_eq!(f.free[i/WORD_BITS]&(1usize<<(i%WORD_BITS))!=0,bit);
            }
        }
        for token in held { f.release_range(token); }
        assert_eq!(f.available(),free.len());
    });
}

#[test]
fn dmaMappingKeepsConstrainedPagesUntilReclaimed() {
    withFree(&[16,17,18],|f|{
        let mask=(18*PAGE-1) as u64;
        let frames=[f.alloc_below(mask).unwrap(),f.alloc_below(mask).unwrap()];
        let mapping=crate::dma::Mapping::pin(f,&frames,mask).unwrap();
        for frame in frames { f.release(frame); }
        let active=mapping.submit();
        assert!(f.alloc_below(mask).is_none());
        let mapping=unsafe { active.reclaim() };
        assert_eq!(mapping.addresses()[0].value(),16*PAGE as u64);
        assert_eq!(mapping.addresses()[1].value(),17*PAGE as u64);
        mapping.unmap(f);
        assert_eq!(f.available(),3);
    });
}

// The production zeroing path dereferences physical addresses. Use real,
// mapped low virtual pages as their physical aliases on Linux x86-64.
#[cfg(all(target_os="linux", target_arch="x86_64"))]
#[test]
fn zeroedRangeClearsOnlyItsOwnedPagesAndClearsReusedContents() {
    use core::ffi::c_void;
    extern "C" {
        fn mmap(addr:*mut c_void,len:usize,prot:i32,flags:i32,fd:i32,offset:i64)->*mut c_void;
        fn munmap(addr:*mut c_void,len:usize)->i32;
    }
    struct Region(*mut c_void);
    impl Drop for Region { fn drop(&mut self){unsafe{munmap(self.0,6*PAGE);}} }
    let memory=unsafe{mmap(core::ptr::null_mut(),6*PAGE,3,0x22|0x40,-1,0)};
    assert_ne!(memory as usize,usize::MAX,"mmap MAP_32BIT");
    let region=Region(memory);
    let base=region.0 as usize;
    let first=base/PAGE;
    assert!(base+6*PAGE-1<=u32::MAX as usize);
    unsafe{core::ptr::write_bytes(memory as *mut u8,0xa5,6*PAGE);}
    withFree(&[first+1,first+2,first+3,first+4],|f|{
        let min=(base+PAGE) as u64;
        let max=(base+5*PAGE-1) as u64;
        let range=f.alloc_zeroed_contiguous(3,PAGE,min,max).unwrap();
        assert_eq!(range.address(),base+PAGE);
        let bytes=unsafe{core::slice::from_raw_parts(memory as *const u8,6*PAGE)};
        assert!(bytes[..PAGE].iter().all(|&v|v==0xa5));
        assert!(bytes[PAGE..4*PAGE].iter().all(|&v|v==0));
        assert!(bytes[4*PAGE..].iter().all(|&v|v==0xa5));
        unsafe{core::ptr::write_bytes((base+PAGE) as *mut u8,0x37,3*PAGE);}
        f.release_range(range);
        let page=f.alloc_zeroed_below(max).unwrap();
        assert_eq!(page.address(),base+PAGE);
        let bytes=unsafe{core::slice::from_raw_parts(memory as *const u8,6*PAGE)};
        assert!(bytes[PAGE..2*PAGE].iter().all(|&v|v==0));
        assert!(bytes[2*PAGE..4*PAGE].iter().all(|&v|v==0x37));
        assert!(bytes[4*PAGE..].iter().all(|&v|v==0xa5));
        f.release(page);
        assert_eq!(f.available(),4);
    });
}
