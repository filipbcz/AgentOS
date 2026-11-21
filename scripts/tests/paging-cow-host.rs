//! Test the actual kernel/paging.rs clone/resolve implementation using
//! page-aligned owned host memory; suppress only privileged TLB instructions.
//! Every page table and data leaf uses the same actual pointer-walk code.
#![allow(dead_code)]
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
        pub lapic: usize, pub io_apics: [Io; 1], pub io_count: usize,
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
        pool: Vec<Box<Page>>, counts: Vec<u16>, budget: usize, _l:PhantomData<&'a ()>,
    }
    pub fn ram(_desc:&[u8])->Option<(usize,usize)> {None}
    impl Frames<'_> {
        pub fn new(n:usize)->Self {
            let pool=(0..n).map(|_|Box::new(Page([0;4096]))).collect();
            Self{pool,counts:vec![0;n],budget:usize::MAX,_l:PhantomData}
        }
        pub fn used(&self)->usize {self.counts.iter().filter(|&&r|r!=0).count()}
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
    child.read(va,&mut buf).unwrap();
    assert_eq!(&buf,b"before");
    child.write(&mut frames,va,b"child!").unwrap();
    child.read(va,&mut buf).unwrap();
    assert_eq!(&buf,b"child!");
    parent.read(va,&mut buf).unwrap();
    assert_eq!(&buf,b"before");
    parent.write(&mut frames,va,b"parent").unwrap();
    parent.read(va,&mut buf).unwrap();
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
    assert!(child.write(&mut frames,code,b"EVIL").is_none());
    assert_eq!(unsafe {child.resolve_cow(&mut frames,code)},Some(false));
    child.write(&mut frames,stack,b"COPY").unwrap();
    let mut b=[0;4];
    parent.read(stack,&mut b).unwrap();
    assert_eq!(&b,b"SAFE");
    unsafe {child.release(&mut frames);parent.release(&mut frames);}
    assert_eq!(frames.used(),1);
}
#[test]
fn cloneOutOfMemoryDoesNotMutateParentOrLeakSharedPages() {
    for allocation_limit in 0..4 {
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
        let mut b=[0;2];parent.read(va,&mut b).unwrap();
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
    child.read(va+4096-32,&mut buf).unwrap();
    assert_eq!(&buf[..],&new);
    parent.read(va+4096-32,&mut buf).unwrap();
    assert_eq!(&buf[..],&original);
    unsafe {child.release(&mut frames);parent.release(&mut frames);}
    assert_eq!(frames.used(),1);
}
