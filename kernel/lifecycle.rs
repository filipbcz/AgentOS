//! Stable process identities and parent/reaper relationships, independent of
//! the CPU run queue. Every access requires the shared Frames gate. This is
//! lifecycle metadata, not a global runnable queue or scheduling lock.
#![allow(non_snake_case)]

use crate::frames::{Frame, Frames};
use core::{cell::UnsafeCell, ptr};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Snapshot {
    pub fPid: usize,
    pub fParent: usize,
    pub fReaper: usize,
    pub fStatus: Option<usize>,
    pub fKillPending: bool,
    pub fCollected: bool,
}

struct Node { fNext: usize, fState: Snapshot }
const _: () = assert!(core::mem::size_of::<Node>() <= 4096);

pub struct Registry { fHead: UnsafeCell<usize> }

// All metadata is protected by the same SharedFrames gate, including reads.
unsafe impl Sync for Registry {}

/// Owns one registry node. The Registry must remain at a stable address until
/// all its entries are released. In the kernel it belongs to permanent Programs.
pub struct Entry { fAddress: usize, fRegistry: *const Registry }

// Moving the sole Entry owner does not access its node. Shared metadata is
// still read/written only under the registry's common Frames gate.
unsafe impl Send for Entry {}

impl Registry {
    pub const fn new() -> Self { Self { fHead: UnsafeCell::new(0) } }

    fn find(&self, aPid: usize) -> Option<*mut Node> {
        let mut pAddress = unsafe { *self.fHead.get() };
        while pAddress != 0 {
            let pNode = pAddress as *mut Node;
            unsafe {
                if (*pNode).fState.fPid == aPid { return Some(pNode); }
                pAddress = (*pNode).fNext;
            }
        }
        None
    }

    /// Called only while Frames is exclusively held. The returned entry owns
    /// its allocation; a failed fork/load must release it before unlocking.
    /// The caller guarantees this Registry stays at its current address.
    pub unsafe fn register(&self, aFrames: &mut Frames<'_>, aPid: usize, aParent: usize)
        -> Result<Entry, isize>
    {
        if aPid == 0 || self.find(aPid).is_some() { return Err(-22); }
        let pReaper = if aParent == 0 { aPid } else {
            let pParent = self.find(aParent).ok_or(-3isize)?;
            let pState = (*pParent).fState;
            if pState.fStatus.is_some() || pState.fCollected || pState.fKillPending { return Err(-3); }
            pState.fReaper
        };
        let pAddress = aFrames.alloc().ok_or(-12isize)?.into_address();
        (pAddress as *mut Node).write(Node {
            fNext: *self.fHead.get(),
            fState: Snapshot { fPid: aPid, fParent: aParent, fReaper: pReaper,
                fStatus: None, fKillPending: false, fCollected: false },
        });
        *self.fHead.get() = pAddress;
        Ok(Entry { fAddress: pAddress, fRegistry: self })
    }

    pub fn childAfter(&self, _aFrames: &mut Frames<'_>, aParent: usize, aCursor: usize)
        -> Result<usize, isize>
    {
        let mut pResult = None;
        let mut pAddress = unsafe { *self.fHead.get() };
        while pAddress != 0 {
            let pNode = unsafe { &*(pAddress as *const Node) };
            let pState = pNode.fState;
            if !pState.fCollected && pState.fParent == aParent && pState.fPid > aCursor {
                pResult = Some(pResult.map_or(pState.fPid, |pPid: usize| pPid.min(pState.fPid)));
            }
            pAddress = pNode.fNext;
        }
        pResult.ok_or(-10)
    }

    pub fn hasExitedChild(&self, _aFrames: &mut Frames<'_>, aParent: usize) -> bool {
        let mut pAddress = unsafe { *self.fHead.get() };
        while pAddress != 0 {
            let pNode = unsafe { &*(pAddress as *const Node) };
            if !pNode.fState.fCollected && pNode.fState.fParent == aParent &&
               pNode.fState.fStatus.is_some() { return true; }
            pAddress = pNode.fNext;
        }
        false
    }

    pub fn childRunning(&self, _aFrames: &mut Frames<'_>, aParent: usize, aPid: usize) -> bool {
        self.find(aPid).map_or(false, |pNode| unsafe {
            let pState = (*pNode).fState;
            pState.fParent == aParent && !pState.fCollected && pState.fStatus.is_none()
        })
    }

    pub fn parentOf(&self, _aFrames: &mut Frames<'_>, aPid: usize) -> Option<usize> {
        self.find(aPid).map(|pNode| unsafe { (*pNode).fState.fParent })
    }

    pub fn hasProcesses(&self, _aFrames: &mut Frames<'_>) -> bool {
        unsafe { *self.fHead.get() != 0 }
    }

    pub fn sessionEmpty(&self, _aFrames: &mut Frames<'_>, aReaper: usize) -> bool {
        let mut pAddress = unsafe { *self.fHead.get() };
        while pAddress != 0 {
            let pNode = unsafe { &*(pAddress as *const Node) };
            if pNode.fState.fReaper == aReaper { return false; }
            pAddress = pNode.fNext;
        }
        true
    }

    /// Consuming an exit status never frees a remotely executing stack. The
    /// owner queue reclaims the marked zombie after its switch has completed.
    pub fn collect(&self, _aFrames: &mut Frames<'_>, aParent: usize, aPid: usize)
        -> Result<usize, isize>
    {
        let pNode = self.find(aPid).ok_or(-10isize)?;
        unsafe {
            let pState = &mut (*pNode).fState;
            if pState.fParent != aParent || pState.fCollected { return Err(-10); }
            let pStatus = pState.fStatus.ok_or(-11isize)?;
            pState.fCollected = true;
            Ok(pStatus)
        }
    }

    /// Remote termination is a request. Only the task owner closes handles
    /// and publishes the exit status after stopping execution in user mode.
    pub fn requestKill(&self, _aFrames: &mut Frames<'_>, aParent: usize, aPid: usize)
        -> Result<usize, isize>
    {
        if aPid == 0 || aPid == aParent { return Err(-22); }
        let pNode = self.find(aPid).ok_or(-3isize)?;
        unsafe {
            let pState = &mut (*pNode).fState;
            if pState.fCollected { return Err(-3); }
            if pState.fParent != aParent { return Err(-1); }
            if pState.fStatus.is_some() { return Ok(1); }
            pState.fKillPending = true;
            Ok(0)
        }
    }

    /// Includes collected zombies awaiting owner-side cleanup. A stopped
    /// session cannot claim its frame baseline while such nodes remain.
    pub fn sessionChildrenRemain(&self, _aFrames: &mut Frames<'_>, aReaper: usize) -> bool {
        let mut pAddress = unsafe { *self.fHead.get() };
        while pAddress != 0 {
            let pNode = unsafe { &*(pAddress as *const Node) };
            if pNode.fState.fReaper == aReaper && pNode.fState.fPid != aReaper { return true; }
            pAddress = pNode.fNext;
        }
        false
    }

    unsafe fn finish(&self, aAddress: usize, aStatus: usize) {
        let pState = (*(aAddress as *mut Node)).fState;
        if pState.fStatus.is_some() { return; }
        (*(aAddress as *mut Node)).fState.fStatus = Some(aStatus);
        (*(aAddress as *mut Node)).fState.fKillPending = false;
        let pReaperAlive = pState.fPid != pState.fReaper && self.find(pState.fReaper)
            .map_or(false, |pRoot| {
                let pRootState = (*pRoot).fState;
                pRootState.fStatus.is_none() && !pRootState.fKillPending && !pRootState.fCollected
            });
        let mut pAddress = *self.fHead.get();
        while pAddress != 0 {
            let pNode = &mut *(pAddress as *mut Node);
            let pChild = &mut pNode.fState;
            if pChild.fPid != pState.fPid {
                if pState.fPid == pState.fReaper && pChild.fReaper == pState.fReaper {
                    pChild.fParent = 0;
                    pChild.fCollected = true;
                    pChild.fKillPending = pChild.fStatus.is_none();
                } else if pChild.fParent == pState.fPid {
                    if pReaperAlive { pChild.fParent = pState.fReaper; }
                    else {
                        pChild.fParent = 0;
                        pChild.fCollected = true;
                        pChild.fKillPending = pChild.fStatus.is_none();
                    }
                }
            }
            pAddress = pNode.fNext;
        }
    }
}

impl Entry {
    pub fn snapshot(&self, _aFrames: &mut Frames<'_>) -> Snapshot {
        unsafe { (*(self.fAddress as *const Node)).fState }
    }
    pub fn finish(&self, _aFrames: &mut Frames<'_>, aStatus: usize) {
        unsafe { (*self.fRegistry).finish(self.fAddress, aStatus); }
    }
    pub fn release(self, aFrames: &mut Frames<'_>) {
        unsafe {
            let pRegistry = &*self.fRegistry;
            let mut pLink = pRegistry.fHead.get();
            while *pLink != self.fAddress {
                assert_ne!(*pLink, 0, "process registry owner mismatch");
                pLink = ptr::addr_of_mut!((*(*pLink as *mut Node)).fNext);
            }
            *pLink = (*(self.fAddress as *const Node)).fNext;
            aFrames.release(Frame::from_owned_address(self.fAddress));
        }
    }
}
