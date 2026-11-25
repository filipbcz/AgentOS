//! Test the actual kernel/paging.rs clone/resolve implementation using
//! page-aligned owned host memory; suppress only privileged TLB instructions.
//! Every page table and data leaf uses the same actual pointer-walk code.
// lowerCamelCase follows the project's naming convention in this harness.
#![allow(dead_code, non_snake_case)]
use std::{marker::PhantomData, ptr};

pub struct BootInfo {
    pub descriptor_size: u64, pub image_base: u64, pub image_size: u64,
    pub memory_map: u64, pub map_size: u64, pub rsdp: u64,
    pub stack_base: u64, pub ap_boot: usize, pub framebuffer: *mut u32,
    pub stride: u32, pub height: u32,
}
mod acpi {
    pub struct Io { pub address: usize }
    pub struct Platform {
        pub lapic: usize, pub hpet: usize, pub io_apics: [Io; 1], pub io_count: usize,
    }
}
mod frames {
    use super::*;
    #[repr(align(4096))]
    pub struct Page([u8;4096]);
    pub struct Frame(pub usize);
    impl Frame {
        pub unsafe fn from_owned_address(address:usize)->Self { Self(address) }
        pub fn address(&self)->usize {self.0}
        pub fn into_address(self)->usize {self.0}
    }
    pub struct Frames<'a> {
        pool: Vec<Box<Page>>, counts: Vec<u16>, budget: usize, root: usize, _l:PhantomData<&'a ()>,
    }
    pub fn ram(_desc:&[u8])->Option<(usize,usize)> {None}
    impl Frames<'_> {
        pub fn new(n:usize)->Self {
            let pool=(0..n).map(|_|Box::new(Page([0;4096]))).collect();
            Self{pool,counts:vec![0;n],budget:usize::MAX,root:0,_l:PhantomData}
        }
        pub fn used(&self)->usize {self.counts.iter().filter(|&&r|r!=0).count()}
        pub fn kernel_root(&self)->Option<usize> {(self.root!=0).then_some(self.root)}
        pub fn install_kernel_root(&mut self,root:usize) {
            assert!(self.root==0 && root!=0 && root%4096==0);
            self.root=root;
        }
        pub fn alloc(&mut self)->Option<Frame> {
            if self.budget==0 {return None}
            let i=self.counts.iter().position(|&n| n==0)?;
            self.budget-=1;
            self.counts[i]=1;
            Some(Frame(self.pool[i].0.as_ptr() as usize))
        }
        pub fn alloc_zeroed(&mut self)->Option<Frame> {
            let frame=self.alloc()?;
            unsafe {ptr::write_bytes(frame.0 as *mut u8,0,4096);}
            Some(frame)
        }
        pub fn retain(&mut self,addr:usize)->Option<()> {
            let i=self.pool.iter().position(|p|p.0.as_ptr() as usize==addr)?;
            if self.counts[i]==0 || self.counts[i]==u16::MAX{return None}
            self.counts[i]+=1;Some(())
        }
        pub fn references(&self,addr:usize)->Option<u16> {
            let i=self.pool.iter().position(|p|p.0.as_ptr() as usize==addr)?;
            (self.counts[i]!=0).then_some(self.counts[i])
        }
        pub fn release(&mut self,frame:Frame) {
            let i=self.pool.iter().position(|p|p.0.as_ptr() as usize==frame.0).unwrap();
            assert!(self.counts[i]>0,"double free");
            self.counts[i]-=1;
        }
        pub fn no_allocations(&mut self) {self.budget=0;}
        pub fn allow(&mut self,n:usize){self.budget=n}
    }
}
#[path="../../kernel/stack.rs"]
mod stack;
#[path="../../kernel/paging.rs"]
mod paging;
use paging::{UserSpace, USER_BASE};

fn setup()->(frames::Frames<'static>,usize,UserSpace) {
    let mut frames=frames::Frames::new(96);
    let root=frames.alloc_zeroed().unwrap().into_address();
    let user=unsafe {UserSpace::new(&mut frames,root).unwrap()};
    (frames,root,user)
}

#[test]
fn guardedKernelStacksRemainSharedAcrossPrivateUserRoots() {
    let mut frames=frames::Frames::new(64);
    let root=frames.alloc_zeroed().unwrap().into_address();
    unsafe {stack::prepare(&mut frames,root).unwrap();}
    let user=unsafe {UserSpace::new(&mut frames,root).unwrap()};
    let before=frames.used();
    let stack=stack::KernelStack::allocate(&mut frames).unwrap();
    let guard=stack.guard();
    unsafe {
        assert_eq!((root as *const u64).add(256).read(),(user.root as *const u64).add(256).read());
        let walk=|mut table:usize,va:usize| {
            for shift in [39,30,21] {
                let value=(table as *const u64).add((va>>shift)&511).read();
                assert_eq!(value&7,3,"kernel subtree may not become user accessible");
                table=(value&0x000f_ffff_ffff_f000) as usize;
            }
            (table as *const u64).add((va>>12)&511).read()
        };
        assert_eq!(walk(user.root,guard),0);
        assert_eq!(walk(user.root,stack.top()),0);
        for offset in 1..=4 {
            let va=guard+offset*4096;
            assert_eq!(walk(user.root,va),walk(root,va));
            assert_eq!(walk(user.root,va)&((1<<63)|7),(1<<63)|3);
        }
        stack.release(&mut frames);
        assert_eq!(frames.used(),before);
        assert_eq!(walk(user.root,guard+4096),0);
        user.release(&mut frames);
    }
    assert_eq!(frames.used(),51,"user destruction must preserve shared pool tables");
}

#[test]
fn childAndParentUserDataRemainIndependentAfterWrites() {
    let (mut frames,root,parent)=setup();
    let va=USER_BASE+0x3000;
    unsafe { parent.map(&mut frames,va,true,false).unwrap(); }
    parent.write(&mut frames,va,b"before").unwrap();
    let before=frames.used();
    let child=unsafe {parent.fork_cow(&mut frames,root).unwrap()};
    assert!(frames.used()>before);
    assert_eq!(frames.references(unsafe {get_page(&parent,va)}),Some(2));
    let mut buf=[0u8;6];
    child.read(&mut frames,va,&mut buf).unwrap();
    assert_eq!(&buf,b"before");
    child.write(&mut frames,va,b"child!").unwrap();
    child.read(&mut frames,va,&mut buf).unwrap();
    assert_eq!(&buf,b"child!");
    parent.read(&mut frames,va,&mut buf).unwrap();
    assert_eq!(&buf,b"before");
    parent.write(&mut frames,va,b"parent").unwrap();
    parent.read(&mut frames,va,&mut buf).unwrap();
    assert_eq!(&buf,b"parent");
    unsafe {child.release(&mut frames);parent.release(&mut frames);}
    assert_eq!(frames.used(),1);
    frames.release(unsafe {frames::Frame::from_owned_address(root)});
    assert_eq!(frames.used(),0);
}
unsafe fn get_page(space:&UserSpace,va:usize)->usize {
    let mut p=space.root;
    for shift in [39,30,21,12] {
        let value=*((p as *const u64).add((va>>shift)&511));
        p=(value & 0x000f_ffff_ffff_f000) as usize;
    }
    p
}
#[test]
fn pagePermissionsStaySeparatedAndReadonlyCodeNeverPromotes() {
    let (mut frames,root,parent)=setup();
    let code=USER_BASE+0x1000;
    let stack=USER_BASE+0x9000;
    unsafe {
        parent.map(&mut frames,code,false,true).unwrap();
        parent.map(&mut frames,stack,true,false).unwrap();
    }
    parent.write(&mut frames,stack,b"SAFE").unwrap();
    let child=unsafe {parent.fork_cow(&mut frames,root).unwrap()};
    assert!(child.write(&mut frames,code,b"EVIL").is_err());
    assert_eq!(unsafe {child.resolve_cow(&mut frames,code)},Some(false));
    child.write(&mut frames,stack,b"COPY").unwrap();
    let mut b=[0;4];
    parent.read(&mut frames,stack,&mut b).unwrap();
    assert_eq!(&b,b"SAFE");
    unsafe {child.release(&mut frames);parent.release(&mut frames);}
    assert_eq!(frames.used(),1);
}
#[test]
fn cloneOutOfMemoryDoesNotMutateParentOrLeakSharedPages() {
    for allocation_limit in 0..5 {
        let (mut frames,root,parent)=setup();
        let va=USER_BASE+0x2000;
        unsafe {parent.map(&mut frames,va,true,false).unwrap();}
        parent.write(&mut frames,va,b"ok").unwrap();
        let baseline=frames.used();
        frames.allow(allocation_limit);
        assert!(unsafe {parent.fork_cow(&mut frames,root)}.is_err());
        assert_eq!(frames.used(),baseline);
        frames.allow(20);
        // Parent PTE remains hardware writable after failed clone.
        parent.write(&mut frames,va,b"OK").unwrap();
        let mut b=[0;2];parent.read(&mut frames,va,&mut b).unwrap();
        assert_eq!(&b,b"OK");
        unsafe {parent.release(&mut frames);}
        assert_eq!(frames.used(),1);
    }
}
#[test]
fn syscallCopyToUserResolvesCOWAcrossMultiplePages() {
    let (mut frames,root,parent)=setup();
    let va=USER_BASE+0x3000;
    unsafe {
        parent.map(&mut frames,va,true,false).unwrap();
        parent.map(&mut frames,va+4096,true,false).unwrap();
    }
    let original=vec![0x11u8;64];
    parent.write(&mut frames,va+4096-32,&original).unwrap();
    let child=unsafe {parent.fork_cow(&mut frames,root).unwrap()};
    let new=vec![0x42u8;64];
    child.write(&mut frames,va+4096-32,&new).unwrap();
    let mut buf=[0u8;64];
    child.read(&mut frames,va+4096-32,&mut buf).unwrap();
    assert_eq!(&buf[..],&new);
    parent.read(&mut frames,va+4096-32,&mut buf).unwrap();
    assert_eq!(&buf[..],&original);
    unsafe {child.release(&mut frames);parent.release(&mut frames);}
    assert_eq!(frames.used(),1);
}

#[test]
fn repeatedAndNestedForksPreserveReferenceCountsAndLastOwnerWrite() {
    let (mut frames,root,parent)=setup();
    let va=USER_BASE+0x5000;
    unsafe {parent.map(&mut frames,va,true,false).unwrap();}
    parent.write(&mut frames,va,b"shared").unwrap();
    let physical=unsafe {get_page(&parent,va)};
    let sibling1=unsafe {parent.fork_cow(&mut frames,root).unwrap()};
    let sibling2=unsafe {parent.fork_cow(&mut frames,root).unwrap()};
    assert_eq!(frames.references(physical),Some(3));
    // A third generation forks from a page that is *already* COW.
    let grandchild=unsafe {sibling2.fork_cow(&mut frames,root).unwrap()};
    assert_eq!(frames.references(physical),Some(4));
    sibling1.write(&mut frames,va,b"FIRST!").unwrap();
    assert_eq!(frames.references(physical),Some(3));
    grandchild.write(&mut frames,va,b"THIRD!").unwrap();
    assert_eq!(frames.references(physical),Some(2));
    let mut buf=[0u8;6];
    sibling2.read(&mut frames,va,&mut buf).unwrap();
    assert_eq!(&buf,b"shared");
    parent.read(&mut frames,va,&mut buf).unwrap();
    assert_eq!(&buf,b"shared");
    unsafe {sibling1.release(&mut frames);grandchild.release(&mut frames);}
    assert_eq!(frames.references(physical),Some(2));
    unsafe {sibling2.release(&mut frames);}
    assert_eq!(frames.references(physical),Some(1));
    // A last-owner COW promotion changes the PTE without a new allocation.
    frames.no_allocations();
    parent.write(&mut frames,va,b"latest").unwrap();
    parent.read(&mut frames,va,&mut buf).unwrap();
    assert_eq!(&buf,b"latest");
    frames.allow(96);
    unsafe {parent.release(&mut frames);}
    assert_eq!(frames.used(),1);
}


#[test]
fn userSpaceConstructionRollsBackMetadataAllocationFailure() {
    for pBudget in 0..2 {
        let mut pFrames=frames::Frames::new(16);
        let pRoot=pFrames.alloc_zeroed().unwrap().into_address();
        pFrames.allow(pBudget);
        assert!(unsafe {UserSpace::new(&mut pFrames,pRoot)}.is_none());
        assert_eq!(pFrames.used(),1);
        pFrames.release(unsafe {frames::Frame::from_owned_address(pRoot)});
        assert_eq!(pFrames.used(),0);
    }
}

#[test]
fn reservationsAllocateNoDataAndUnalignedElfPaddingAndBssAreZero() {
    static G_CONTENTS:[u8;4096+19]=[0x5a;4096+19];
    let (mut pFrames,_,pSpace)=setup();
    let pVa=USER_BASE+0x2025;
    let pBaseline=pFrames.used();
    unsafe {pSpace.reserve(pVa,2*4096+137,&G_CONTENTS,true,false).unwrap();}
    assert_eq!(pFrames.used(),pBaseline);
    assert_eq!(pSpace.stats(),[1,3,0,1,1,0,0,0]);
    let mut pBefore=[0xff;37];
    pSpace.read(&mut pFrames,pVa-37,&mut pBefore).unwrap();
    assert_eq!(pBefore,[0;37]);
    assert_eq!(pSpace.stats(),[1,3,1,4,1,1,0,0]);
    let mut pBytes=[0;4096+19];
    pSpace.read(&mut pFrames,pVa,&mut pBytes).unwrap();
    assert_eq!(pBytes,G_CONTENTS);
    assert_eq!(pSpace.stats()[2],2);
    let mut pTail=[0xff;128];
    pSpace.read(&mut pFrames,pVa+2*4096,&mut pTail).unwrap();
    assert_eq!(pTail,[0;128]);
    let mut pPadding=[0xff;8];
    pSpace.read(&mut pFrames,USER_BASE+0x4ff8,&mut pPadding).unwrap();
    assert_eq!(pPadding,[0;8]);
    assert_eq!(pSpace.stats(),[1,3,3,4,1,3,0,0]);
    unsafe {pSpace.release(&mut pFrames);}
    assert_eq!(pFrames.used(),1);
}

#[test]
fn invalidAndOverlappingReservationsDoNotMutateSpace() {
    let (mut pFrames,_,pSpace)=setup();
    unsafe {pSpace.reserve(USER_BASE+37,20,b"data",false,true).unwrap();}
    let pStats=pSpace.stats();
    let pBaseline=pFrames.used();
    for (pStart,pLength,pContents,pWrite,pExecute) in [
        (USER_BASE,0,&b""[..],false,false),
        (USER_BASE-1,1,&b""[..],false,false),
        (paging::USER_END,1,&b""[..],false,false),
        (paging::USER_END-1,2,&b""[..],false,false),
        (usize::MAX-1,8,&b""[..],false,false),
        (USER_BASE+8192,1,&b"too long"[..],false,false),
        (USER_BASE+8192,4096,&b""[..],true,true),
        // Byte ranges are disjoint, but they would share a hardware page.
        (USER_BASE+200,10,&b""[..],false,false),
    ] {
        assert_eq!(unsafe {pSpace.reserve(pStart,pLength,pContents,pWrite,pExecute)},Err(-8));
        assert_eq!(pSpace.stats(),pStats);
        assert_eq!(pFrames.used(),pBaseline);
    }
    unsafe {pSpace.release(&mut pFrames);}
    assert_eq!(pFrames.used(),1);
}

#[test]
fn boundedRegionRegistryIncludesAbsentPagesAndRejectsOverflow() {
    let (mut pFrames,_,pSpace)=setup();
    for pIndex in 0..paging::MAX_REGIONS {
        unsafe {pSpace.reserve(USER_BASE+pIndex*8192,4096,&[],true,false).unwrap();}
    }
    assert_eq!(pSpace.stats(),[1,64,0,1,1,0,0,0]);
    assert_eq!(unsafe {pSpace.reserve(USER_BASE+64*8192,4096,&[],true,false)},Err(-8));
    unsafe {pSpace.release(&mut pFrames);}
    assert_eq!(pFrames.used(),1);
}

#[test]
fn everyLazyPageTableAndDataOomPointRollsBackWithoutPublishing() {
    // First fault needs 3 new tables; other cases extend an existing PDPT or PD.
    for (pDistance,pNeeded) in [(0usize,4usize),(1<<21,2),(1<<30,3)] {
        for pBudget in 0..pNeeded {
            let (mut pFrames,_,pSpace)=setup();
            unsafe {pSpace.reserve(USER_BASE,4096,&[],true,false).unwrap();}
            let pTarget=USER_BASE+pDistance;
            if pDistance!=0 {
                unsafe {
                    pSpace.resolveFault(&mut pFrames,USER_BASE,4).unwrap();
                    pSpace.reserve(pTarget,4096,&[],true,false).unwrap();
                }
            }
            let pBaseline=pFrames.used();
            let pStats=pSpace.stats();
            pFrames.allow(pBudget);
            assert_eq!(unsafe {pSpace.resolveFault(&mut pFrames,pTarget,6)},Err(-12));
            assert_eq!(pFrames.used(),pBaseline,"unpublished table leak at distance {pDistance}, budget {pBudget}");
            assert_eq!(pSpace.stats(),pStats);
            pFrames.allow(pNeeded);
            unsafe {pSpace.resolveFault(&mut pFrames,pTarget,6).unwrap();}
            assert_eq!(pSpace.stats()[2],pStats[2]+1);
            unsafe {pSpace.release(&mut pFrames);}
            assert_eq!(pFrames.used(),1);
        }
    }
}

#[test]
fn invalidRangeIsRejectedBeforeAnyPrefaultOrCopy() {
    let (mut pFrames,_,pSpace)=setup();
    unsafe {pSpace.reserve(USER_BASE,4096,&[],true,false).unwrap();}
    let pStats=pSpace.stats();
    let pBaseline=pFrames.used();
    let mut pDst=[0xa5;32];
    assert_eq!(pSpace.read(&mut pFrames,USER_BASE+4096-16,&mut pDst),Err(-14));
    assert_eq!(pSpace.write(&mut pFrames,USER_BASE+4096-16,&[0x77;32]),Err(-14));
    assert_eq!(pSpace.readable(&mut pFrames,usize::MAX-10,20),Err(-14));
    assert_eq!(pSpace.writable(&mut pFrames,0,1),Err(-14));
    assert_eq!(pSpace.stats(),pStats);
    assert_eq!(pFrames.used(),pBaseline);
    assert_eq!(pDst,[0xa5;32]);
    assert_eq!(pSpace.read(&mut pFrames,usize::MAX,&mut []),Ok(()));
    assert_eq!(pSpace.write(&mut pFrames,0,&[]),Ok(()));
    unsafe {pSpace.release(&mut pFrames);}
    assert_eq!(pFrames.used(),1);
}

#[test]
fn multipageOomMayRetainReadyPagesButNeverPartiallyCopiesBytes() {
    let (mut pFrames,_,pSpace)=setup();
    unsafe {pSpace.reserve(USER_BASE,8192,&[],true,false).unwrap();}
    // Exactly enough for three page tables and the first data page.
    pFrames.allow(4);
    assert_eq!(pSpace.write(&mut pFrames,USER_BASE,&[0x77;8192]),Err(-12));
    assert_eq!(pSpace.stats(),[1,2,1,4,1,1,0,0]);
    let mut pFirst=[0xff;4096];
    pSpace.read(&mut pFrames,USER_BASE,&mut pFirst).unwrap();
    assert_eq!(pFirst,[0;4096]);
    let mut pDst=[0xa5;8192];
    assert_eq!(pSpace.read(&mut pFrames,USER_BASE,&mut pDst),Err(-12));
    assert_eq!(pDst,[0xa5;8192]);
    pFrames.allow(1);
    pSpace.write(&mut pFrames,USER_BASE,&[0x77;8192]).unwrap();
    pSpace.read(&mut pFrames,USER_BASE,&mut pDst).unwrap();
    assert_eq!(pDst,[0x77;8192]);
    assert_eq!(pSpace.stats(),[1,2,2,4,1,2,0,0]);
    unsafe {pSpace.release(&mut pFrames);}
    assert_eq!(pFrames.used(),1);
}

#[test]
fn onlyValidUserFaultsMaterializePagesAndGuardsNeverBecomeMapped() {
    let (mut pFrames,_,pSpace)=setup();
    let pData=USER_BASE;
    let pCode=USER_BASE+8192;
    unsafe {
        pSpace.reserve(pData,4096,&[],true,false).unwrap();
        pSpace.reserve(pCode,4096,b"code",false,true).unwrap();
    }
    for pError in [0,1,2,3,5,7,12,22,36,68,32772,u64::MAX] {
        assert_eq!(unsafe {pSpace.resolveFault(&mut pFrames,pData,pError)},Err(-14));
        assert_eq!(pSpace.stats()[2],0);
    }
    for (pAddress,pError) in [(pData,20),(pCode,6),(pData+4096,4),(0,4),(paging::USER_END,4)] {
        assert_eq!(unsafe {pSpace.resolveFault(&mut pFrames,pAddress,pError)},Err(-14));
        assert_eq!(pSpace.stats()[2],0);
    }
    unsafe {
        pSpace.resolveFault(&mut pFrames,pCode,20).unwrap();
        pSpace.resolveFault(&mut pFrames,pData,6).unwrap();
    }
    assert_eq!(pSpace.stats()[2],2);
    // Wrong fault causes cannot promote readonly code or be mistaken for COW.
    for pError in [4,6,7,20,21,23] {
        assert_eq!(unsafe {pSpace.resolveFault(&mut pFrames,pCode,pError)},Err(-14));
    }
    assert_eq!(pSpace.write(&mut pFrames,pCode,b"bad!"),Err(-14));
    let mut pCodeBytes=[0;4];
    pSpace.read(&mut pFrames,pCode,&mut pCodeBytes).unwrap();
    assert_eq!(&pCodeBytes,b"code");
    unsafe {pSpace.release(&mut pFrames);}
    assert_eq!(pFrames.used(),1);
}

#[test]
fn forkBeforeFirstTouchPreservesIndependentAbsentReservations() {
    let (mut pFrames,pRoot,pParent)=setup();
    let pVa=USER_BASE;
    unsafe {pParent.reserve(pVa,8192,b"original",true,false).unwrap();}
    let pChild=unsafe {pParent.fork_cow(&mut pFrames,pRoot).unwrap()};
    assert_eq!(pParent.stats(),[1,2,0,1,1,0,0,0]);
    assert_eq!(pChild.stats(),[1,2,0,1,1,0,0,0]);
    pChild.write(&mut pFrames,pVa,b"modified").unwrap();
    pParent.write(&mut pFrames,pVa+4096,b"parent").unwrap();
    let mut pBytes=[0xff;8];
    pParent.read(&mut pFrames,pVa,&mut pBytes).unwrap();
    assert_eq!(&pBytes,b"original");
    pChild.read(&mut pFrames,pVa+4096,&mut pBytes).unwrap();
    assert_eq!(pBytes,[0;8]);
    assert_eq!(pParent.stats(),[1,2,2,4,1,2,0,0]);
    assert_eq!(pChild.stats(),[1,2,2,4,1,2,0,0]);
    unsafe {pChild.release(&mut pFrames);pParent.release(&mut pFrames);}
    assert_eq!(pFrames.used(),1);
}

#[test]
fn lazyCowCountersRestartInChildAndCountCopiesAndUniquePromotions() {
    let (mut pFrames,pRoot,pParent)=setup();
    let pVa=USER_BASE;
    unsafe {pParent.reserve(pVa,8192,b"original",true,false).unwrap();}
    let mut pBytes=[0;8];
    pParent.read(&mut pFrames,pVa,&mut pBytes).unwrap();
    let pChild=unsafe {pParent.fork_cow(&mut pFrames,pRoot).unwrap()};
    assert_eq!(pParent.stats(),[1,2,1,4,1,1,0,0]);
    assert_eq!(pChild.stats(),[1,2,1,4,1,0,0,0]);
    pFrames.no_allocations();
    assert_eq!(unsafe {pChild.resolveFault(&mut pFrames,pVa,7)},Err(-12));
    assert_eq!(pChild.stats(),[1,2,1,4,1,0,0,0]);
    pFrames.allow(1);
    unsafe {pChild.resolveFault(&mut pFrames,pVa,7).unwrap();}
    assert_eq!(pChild.stats(),[1,2,1,4,1,0,1,0]);
    pChild.write(&mut pFrames,pVa,b"modified").unwrap();
    // Only parent retains the original frame: promotion needs no allocation.
    pFrames.no_allocations();
    pParent.write(&mut pFrames,pVa,b"parent!!").unwrap();
    assert_eq!(pParent.stats(),[1,2,1,4,1,1,0,1]);
    pChild.read(&mut pFrames,pVa,&mut pBytes).unwrap();
    assert_eq!(&pBytes,b"modified");
    unsafe {pChild.release(&mut pFrames);pParent.release(&mut pFrames);}
    assert_eq!(pFrames.used(),1);
}


#[test]
fn residentVisitorEnumeratesOnlyPrivateTablesAndDataAndStopsOnFailure() {
    let (mut pFrames,pKernel,pSpace)=setup();
    unsafe {pSpace.reserve(USER_BASE,8192,&[],true,false).unwrap();}
    let mut pCalls=0;
    assert!(pSpace.visitResidentFrames(|_| { pCalls+=1; true }));
    assert_eq!(pCalls,0,"absent reservations must not appear as owned data");
    pSpace.write(&mut pFrames,USER_BASE,b"ready").unwrap();
    let pUnrelated=pFrames.alloc().unwrap();
    let mut pVisited=std::collections::BTreeSet::new();
    assert!(pSpace.visitResidentFrames(|pAddress| {
        assert_ne!(pAddress,pKernel);
        assert_ne!(pAddress,pSpace.root);
        assert_ne!(pAddress,pUnrelated.address());
        assert_eq!(pFrames.references(pAddress),Some(1));
        pVisited.insert(pAddress)
    }));
    assert_eq!(pVisited.len() as u64,pSpace.stats()[2]+pSpace.stats()[3]-1);
    assert_eq!(pVisited.len(),4);
    pCalls=0;
    assert!(!pSpace.visitResidentFrames(|_| { pCalls+=1; pCalls<2 }));
    assert_eq!(pCalls,2);
    let pChild=unsafe {pSpace.fork_cow(&mut pFrames,pKernel).unwrap()};
    assert!(!pSpace.visitResidentFrames(|pAddress| pFrames.references(pAddress)==Some(1)),
            "a surviving COW child must prevent unique-owner normalization");
    unsafe {pChild.release(&mut pFrames);}
    assert!(pSpace.visitResidentFrames(|pAddress| pFrames.references(pAddress)==Some(1)));
    pFrames.release(pUnrelated);
    unsafe {pSpace.release(&mut pFrames);}
    assert_eq!(pFrames.used(),1);
}

#[test]
fn highPciBarIsNotIdentityMappedIntoPrivateUserSpace() {
    const physical: usize = 0x0000_00c0_0000_0000;
    const addressMask: u64 = 0x000f_ffff_ffff_f000;
    const flags: u64 = (1 << 63) | 0x1b; // NX, supervisor, writable, UC
    let mut frames = frames::Frames::new(32);
    let root = frames.alloc_zeroed().unwrap().into_address();
    let va = unsafe { paging::map_device_window(root, &mut frames, physical, 2).unwrap() };
    assert_eq!(va, 0xffff_9000_0000_0000 + physical);
    assert_eq!(unsafe { (root as *const u64).add(1).read() }, 0);
    let count = frames.used();
    assert_eq!(unsafe { paging::map_device_window(root, &mut frames, physical, 2) }, Some(va));
    assert_eq!(frames.used(), count);
    let user = unsafe { UserSpace::new(&mut frames, root).unwrap() };
    let leaf = |mut table: usize, va: usize| unsafe {
        for shift in [39, 30, 21] {
            let entry = (table as *const u64).add((va >> shift) & 511).read();
            assert_eq!(entry & 7, 3);
            table = (entry & addressMask) as usize;
        }
        (table as *mut u64).add((va >> 12) & 511)
    };
    for i in 0..2 {
        let address = va + i * 4096;
        let entry = unsafe { leaf(root, address).read() };
        assert_eq!(entry, (physical + i * 4096) as u64 | flags);
        assert_eq!(unsafe { leaf(user.root, address).read() }, entry);
    }
    // The same numeric address remains usable as an ordinary private user VA.
    let frame = unsafe { user.map(&mut frames, physical, true, false).unwrap() };
    assert_ne!(frame, physical);
    assert!(user.read(&mut frames, va, &mut [0u8; 1]).is_err());
    unsafe { user.release(&mut frames); }
    assert_eq!(frames.used(), count);
    // Existing A/D bits don't create a false conflict. A cached or user leaf
    // is a real conflict and may never be silently widened/retyped.
    unsafe {
        *leaf(root, va) |= (1 << 5) | (1 << 6);
        assert_eq!(paging::map_device_window(root, &mut frames, physical, 2), Some(va));
        *leaf(root, va + 4096) &= !(1 << 4);
        assert!(paging::map_device_window(root, &mut frames, physical, 2).is_none());
    }
    assert_eq!(frames.used(), count);
}

#[test]
fn deviceWindowRollsBackAllocationAndRejectsInvalidRanges() {
    // Cross a PT boundary so the second page requires another table.
    let physical = USER_BASE + 0x1ff000;
    for budget in 0..4 {
        let mut frames = frames::Frames::new(16);
        let root = frames.alloc_zeroed().unwrap().into_address();
        frames.allow(budget);
        assert!(unsafe { paging::map_device_window(root, &mut frames, physical, 2) }.is_none());
        assert_eq!(frames.used(), 1);
        assert!(unsafe { core::slice::from_raw_parts(root as *const u64, 512) }
                .iter().all(|&value| value == 0));
    }
    let mut frames = frames::Frames::new(16);
    let root = frames.alloc_zeroed().unwrap().into_address();
    for (pa, pages) in [(0, 1), (physical + 1, 1), (physical, 0), (physical, 17),
                        (USER_BASE - 4096, 2), (1usize << 44, 1), (usize::MAX - 4095, 2)] {
        assert!(unsafe { paging::map_device_window(root, &mut frames, pa, pages) }.is_none());
        assert_eq!(frames.used(), 1);
    }
    // An existing identity-mapped high physical page must not receive an
    // uncached alias: even a cached mapping with a different VA is unsafe.
    let pdpt = frames.alloc_zeroed().unwrap().into_address();
    let pd = frames.alloc_zeroed().unwrap().into_address();
    let pt = frames.alloc_zeroed().unwrap().into_address();
    unsafe {
        (root as *mut u64).add(1).write(pdpt as u64 | 3);
        (pdpt as *mut u64).write(pd as u64 | 3);
        (pd as *mut u64).write(pt as u64 | 3);
        (pt as *mut u64).write(USER_BASE as u64 | 3);
        assert!(paging::map_device_window(root, &mut frames, USER_BASE, 1).is_none());
    }
    assert_eq!(frames.used(), 4);
    assert_eq!(unsafe { (root as *const u64).add(288).read() }, 0);
}

#[test]
fn lowDeviceWindowKeepsExistingIdentityConvention() {
    let mut frames = frames::Frames::new(16);
    let root = frames.alloc_zeroed().unwrap().into_address();
    assert_eq!(unsafe { paging::map_device_window(root, &mut frames, 0xf0000000, 2) },
               Some(0xf0000000));
    let count = frames.used();
    assert_eq!(unsafe { paging::map_device_window(root, &mut frames, 0xf0000000, 2) },
               Some(0xf0000000));
    assert_eq!(frames.used(), count);
    assert_eq!(unsafe { (root as *const u64).add(1).read() }, 0);
}
