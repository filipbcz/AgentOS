//! Execute the real cross-CPU lifecycle registry with owned, aligned backing
//! pages. A shared Mutex<Frames> is the host equivalent of SharedFrames; no
//! registry operation, process identity or ownership transition is mocked.
#![allow(non_snake_case)]

use std::{sync::{mpsc, Barrier, Mutex}, thread, time::{Duration, Instant}};

mod frames {
    use core::marker::PhantomData;

    #[repr(align(4096))]
    struct Page([u8; 4096]);

    pub struct Frame(usize);
    impl Frame {
        pub unsafe fn from_owned_address(aAddress: usize) -> Self { Self(aAddress) }
        pub fn into_address(self) -> usize { self.0 }
    }

    pub struct Frames<'a> {
        fPages: Vec<Box<Page>>,
        fLive: Vec<bool>,
        fBudget: usize,
        fLifetime: PhantomData<&'a ()>,
    }

    impl Frames<'_> {
        pub fn new(aCount: usize) -> Self {
            Self { fPages: (0..aCount).map(|_| Box::new(Page([0xa5; 4096]))).collect(),
                fLive: vec![false; aCount], fBudget: usize::MAX, fLifetime: PhantomData }
        }
        pub fn used(&self) -> usize { self.fLive.iter().filter(|&&pLive| pLive).count() }
        pub fn allow(&mut self, aCount: usize) { self.fBudget = aCount; }
        pub fn alloc(&mut self) -> Option<Frame> {
            if self.fBudget == 0 { return None; }
            let pIndex = self.fLive.iter().position(|&pLive| !pLive)?;
            self.fBudget -= 1;
            self.fLive[pIndex] = true;
            Some(Frame(self.fPages[pIndex].0.as_ptr() as usize))
        }
        pub fn release(&mut self, aFrame: Frame) {
            let pIndex = self.fPages.iter().position(|pPage| pPage.0.as_ptr() as usize == aFrame.0)
                .expect("release of a foreign lifecycle frame");
            assert!(self.fLive[pIndex], "double release of lifecycle frame");
            self.fLive[pIndex] = false;
            self.fPages[pIndex].0.fill(0xdd);
        }
    }
}

#[path = "../../kernel/lifecycle.rs"]
mod lifecycle;

#[test]
fn invalidIdentityParentAndStoppedParentNeverPublishOrAllocate() {
    let pRegistry = lifecycle::Registry::new();
    let mut pFrames = frames::Frames::new(8);
    assert_eq!(unsafe { pRegistry.register(&mut pFrames, 0, 0) }.err(), Some(-22));
    assert_eq!(unsafe { pRegistry.register(&mut pFrames, 2, 99) }.err(), Some(-3));
    assert_eq!(pFrames.used(), 0);
    assert!(!pRegistry.hasProcesses(&mut pFrames));

    let pRoot = unsafe { pRegistry.register(&mut pFrames, 1, 0) }.unwrap();
    assert_eq!(unsafe { pRegistry.register(&mut pFrames, 1, 0) }.err(), Some(-22));
    assert_eq!(pRegistry.requestKill(&mut pFrames, 0, 1), Ok(0));
    assert_eq!(unsafe { pRegistry.register(&mut pFrames, 2, 1) }.err(), Some(-3));
    assert_eq!(pFrames.used(), 1);
    pRoot.finish(&mut pFrames, 137);
    assert_eq!(unsafe { pRegistry.register(&mut pFrames, 2, 1) }.err(), Some(-3));
    assert_eq!(pRegistry.collect(&mut pFrames, 0, 1), Ok(137));
    assert_eq!(unsafe { pRegistry.register(&mut pFrames, 2, 1) }.err(), Some(-3));
    assert_eq!(pFrames.used(), 1);
    pRoot.release(&mut pFrames);
    assert!(!pRegistry.hasProcesses(&mut pFrames));
    assert_eq!(pFrames.used(), 0);
}

#[test]
fn registrationOomPreservesExistingOwnershipAndAllowsCleanRetry() {
    let pRegistry = lifecycle::Registry::new();
    let mut pFrames = frames::Frames::new(8);
    let pRoot = unsafe { pRegistry.register(&mut pFrames, 1, 0) }.unwrap();
    let pBefore = pRoot.snapshot(&mut pFrames);
    pFrames.allow(0);
    assert_eq!(unsafe { pRegistry.register(&mut pFrames, 2, 1) }.err(), Some(-12));
    assert_eq!(pRoot.snapshot(&mut pFrames), pBefore);
    assert_eq!(pRegistry.childAfter(&mut pFrames, 1, 0), Err(-10));
    assert!(!pRegistry.sessionChildrenRemain(&mut pFrames, 1));
    assert_eq!(pFrames.used(), 1);

    pFrames.allow(1);
    let pChild = unsafe { pRegistry.register(&mut pFrames, 2, 1) }.unwrap();
    assert_eq!(pRegistry.childAfter(&mut pFrames, 1, 0), Ok(2));
    assert_eq!(pChild.snapshot(&mut pFrames).fReaper, 1);
    // An unpublished fork/load failure may release its node before execution.
    pChild.release(&mut pFrames);
    assert_eq!(pRoot.snapshot(&mut pFrames), pBefore);
    assert!(!pRegistry.sessionChildrenRemain(&mut pFrames, 1));
    pRoot.release(&mut pFrames);
    assert!(pRegistry.sessionEmpty(&mut pFrames, 1));
    assert_eq!(pFrames.used(), 0);
}

#[test]
fn remoteCollectConsumesStatusExactlyOnceWithoutFreeingOwnerNode() {
    let pRegistry = lifecycle::Registry::new();
    let mut pFrames = frames::Frames::new(8);
    let pRoot = unsafe { pRegistry.register(&mut pFrames, 1, 0) }.unwrap();
    let pChild = unsafe { pRegistry.register(&mut pFrames, 2, 1) }.unwrap();
    assert_eq!(pRegistry.collect(&mut pFrames, 1, 2), Err(-11));
    assert_eq!(pRegistry.requestKill(&mut pFrames, 99, 2), Err(-1));
    assert!(pRegistry.childRunning(&mut pFrames, 1, 2));
    pChild.finish(&mut pFrames, 42);
    assert!(pRegistry.hasExitedChild(&mut pFrames, 1));
    assert_eq!(pRegistry.collect(&mut pFrames, 99, 2), Err(-10));
    assert_eq!(pRegistry.collect(&mut pFrames, 1, 2), Ok(42));
    assert_eq!(pRegistry.collect(&mut pFrames, 1, 2), Err(-10));
    assert_eq!(pRegistry.requestKill(&mut pFrames, 1, 2), Err(-3));
    assert_eq!(pRegistry.childAfter(&mut pFrames, 1, 0), Err(-10));
    assert!(!pRegistry.hasExitedChild(&mut pFrames, 1));
    assert!(!pRegistry.childRunning(&mut pFrames, 1, 2));
    assert_eq!(pRegistry.parentOf(&mut pFrames, 2), Some(1));
    assert!(pChild.snapshot(&mut pFrames).fCollected);
    assert!(pRegistry.sessionChildrenRemain(&mut pFrames, 1));
    assert_eq!(pFrames.used(), 2, "collection must not free a remotely owned node");
    pChild.release(&mut pFrames);
    assert!(!pRegistry.sessionChildrenRemain(&mut pFrames, 1));
    assert_eq!(pRegistry.parentOf(&mut pFrames, 2), None);
    assert_eq!(pFrames.used(), 1);
    pRoot.release(&mut pFrames);
    assert_eq!(pFrames.used(), 0);
}

#[test]
fn rootDeathStopsOnlyItsOwnFamilyAndRetainsNodesUntilOwnersAcknowledge() {
    let pRegistry = lifecycle::Registry::new();
    let mut pFrames = frames::Frames::new(8);
    let pRoot = unsafe { pRegistry.register(&mut pFrames, 1, 0) }.unwrap();
    let pParent = unsafe { pRegistry.register(&mut pFrames, 2, 1) }.unwrap();
    let pChild = unsafe { pRegistry.register(&mut pFrames, 3, 2) }.unwrap();
    let pOtherRoot = unsafe { pRegistry.register(&mut pFrames, 17, 0) }.unwrap();
    let pOtherParent = unsafe { pRegistry.register(&mut pFrames, 18, 17) }.unwrap();
    let pOtherChild = unsafe { pRegistry.register(&mut pFrames, 19, 18) }.unwrap();
    let pOtherBefore = [pOtherRoot.snapshot(&mut pFrames), pOtherParent.snapshot(&mut pFrames),
        pOtherChild.snapshot(&mut pFrames)];

    pRoot.finish(&mut pFrames, 0);
    for pEntry in [&pParent, &pChild] {
        let pState = pEntry.snapshot(&mut pFrames);
        assert_eq!(pState.fParent, 0);
        assert_eq!(pState.fReaper, 1);
        assert!(pState.fCollected && pState.fKillPending);
        assert_eq!(pState.fStatus, None, "root exit cannot impersonate remote owner completion");
    }
    assert_eq!([pOtherRoot.snapshot(&mut pFrames), pOtherParent.snapshot(&mut pFrames),
        pOtherChild.snapshot(&mut pFrames)], pOtherBefore);
    assert!(pRegistry.sessionChildrenRemain(&mut pFrames, 1));
    assert_eq!(pFrames.used(), 6);

    pChild.finish(&mut pFrames, 137);
    pChild.release(&mut pFrames);
    pParent.finish(&mut pFrames, 137);
    pParent.release(&mut pFrames);
    assert!(!pRegistry.sessionChildrenRemain(&mut pFrames, 1));
    assert_eq!(pRegistry.collect(&mut pFrames, 0, 1), Ok(0));
    pRoot.release(&mut pFrames);
    assert!(pRegistry.sessionEmpty(&mut pFrames, 1));
    assert!(!pRegistry.sessionEmpty(&mut pFrames, 17));
    assert_eq!(pFrames.used(), 3);
    assert_eq!(pRegistry.childAfter(&mut pFrames, 17, 0), Ok(18));
    assert_eq!(pRegistry.childAfter(&mut pFrames, 18, 0), Ok(19));
    pOtherChild.release(&mut pFrames);
    pOtherParent.release(&mut pFrames);
    pOtherRoot.release(&mut pFrames);
    assert!(!pRegistry.hasProcesses(&mut pFrames));
    assert_eq!(pFrames.used(), 0);
}

#[test]
fn adoptionPreservesLiveChildrenAndAlreadyExitedChildStatuses() {
    let pRegistry = lifecycle::Registry::new();
    let mut pFrames = frames::Frames::new(8);
    let pRoot = unsafe { pRegistry.register(&mut pFrames, 1, 0) }.unwrap();
    let pParent = unsafe { pRegistry.register(&mut pFrames, 2, 1) }.unwrap();
    let pLive = unsafe { pRegistry.register(&mut pFrames, 3, 2) }.unwrap();
    let pZombie = unsafe { pRegistry.register(&mut pFrames, 4, 2) }.unwrap();
    pZombie.finish(&mut pFrames, 9);
    pParent.finish(&mut pFrames, 42);
    assert_eq!(pLive.snapshot(&mut pFrames).fParent, 1);
    assert_eq!(pZombie.snapshot(&mut pFrames).fParent, 1);
    assert!(pRegistry.childRunning(&mut pFrames, 1, 3));
    assert_eq!(pRegistry.childAfter(&mut pFrames, 1, 0), Ok(2));
    assert_eq!(pRegistry.childAfter(&mut pFrames, 1, 2), Ok(3));
    assert_eq!(pRegistry.childAfter(&mut pFrames, 1, 3), Ok(4));
    assert_eq!(pRegistry.collect(&mut pFrames, 2, 4), Err(-10));
    assert_eq!(pRegistry.collect(&mut pFrames, 1, 4), Ok(9));
    assert_eq!(pRegistry.collect(&mut pFrames, 1, 2), Ok(42));
    assert_eq!(pRegistry.requestKill(&mut pFrames, 1, 3), Ok(0));
    assert_eq!(pLive.snapshot(&mut pFrames).fStatus, None);
    pLive.finish(&mut pFrames, 137);
    assert_eq!(pRegistry.collect(&mut pFrames, 1, 3), Ok(137));
    pParent.release(&mut pFrames);
    pZombie.release(&mut pFrames);
    pLive.release(&mut pFrames);
    pRoot.release(&mut pFrames);
    assert_eq!(pFrames.used(), 0);
}

#[test]
fn unlinkHeadMiddleAndTailAllowsSafeFrameReuseWithoutStaleIdentity() {
    let pRegistry = lifecycle::Registry::new();
    let mut pFrames = frames::Frames::new(4);
    let pTail = unsafe { pRegistry.register(&mut pFrames, 11, 0) }.unwrap();
    let pRemaining = unsafe { pRegistry.register(&mut pFrames, 22, 0) }.unwrap();
    let pMiddle = unsafe { pRegistry.register(&mut pFrames, 33, 0) }.unwrap();
    let pHead = unsafe { pRegistry.register(&mut pFrames, 44, 0) }.unwrap();
    pMiddle.release(&mut pFrames);
    assert_eq!(pRegistry.parentOf(&mut pFrames, 33), None);
    // The pool has exactly one free page, so this reuses the removed node's
    // physical backing, which was poisoned on release rather than zeroed.
    let pReused = unsafe { pRegistry.register(&mut pFrames, 55, 0) }.unwrap();
    assert_eq!(pRegistry.parentOf(&mut pFrames, 33), None);
    assert_eq!(pRegistry.parentOf(&mut pFrames, 55), Some(0));
    pTail.release(&mut pFrames);
    assert_eq!(pRegistry.childAfter(&mut pFrames, 0, 0), Ok(22));
    pReused.release(&mut pFrames);
    pHead.release(&mut pFrames);
    assert_eq!(pRemaining.snapshot(&mut pFrames).fPid, 22);
    assert_eq!(pRegistry.childAfter(&mut pFrames, 0, 22), Err(-10));
    assert_eq!(pFrames.used(), 1);
    pRemaining.release(&mut pFrames);
    assert!(!pRegistry.hasProcesses(&mut pFrames));
    assert_eq!(pFrames.used(), 0);
}

#[test]
fn simultaneousKillExitAndCollectPreserveOneStatusUntilOwnerRelease() {
    for _ in 0..16 {
        let pRegistry = lifecycle::Registry::new();
        let mut pFrames = frames::Frames::new(4);
        let pRoot = unsafe { pRegistry.register(&mut pFrames, 1, 0) }.unwrap();
        let pChild = unsafe { pRegistry.register(&mut pFrames, 2, 1) }.unwrap();
        let pFrames = Mutex::new(pFrames);
        let pStart = Barrier::new(3);
        let (pReleaseSend, pReleaseReceive) = mpsc::sync_channel(1);
        thread::scope(|pScope| {
            let pFrames = &pFrames;
            let pStart = &pStart;
            let pRegistry = &pRegistry;
            let pOwner = pScope.spawn(move || {
                pStart.wait();
                let pStatus = {
                    let mut pGuard = pFrames.lock().unwrap();
                    let pStatus = if pChild.snapshot(&mut pGuard).fKillPending { 137 } else { 42 };
                    pChild.finish(&mut pGuard, pStatus);
                    pStatus
                };
                pReleaseReceive.recv_timeout(Duration::from_secs(5)).expect("owner release not authorized by test");
                pChild.release(&mut pFrames.lock().unwrap());
                pStatus
            });
            let pKiller = pScope.spawn(move || {
                pStart.wait();
                pRegistry.requestKill(&mut pFrames.lock().unwrap(), 1, 2)
            });
            let pCollector = pScope.spawn(move || {
                pStart.wait();
                let pUntil = Instant::now() + Duration::from_secs(5);
                loop {
                    let pResult = pRegistry.collect(&mut pFrames.lock().unwrap(), 1, 2);
                    match pResult {
                        Ok(pStatus) => break pStatus,
                        Err(-11) => {
                            assert!(Instant::now() < pUntil, "owner never published an exit status");
                            thread::yield_now();
                        }
                        pOther => panic!("unexpected collection result: {pOther:?}"),
                    }
                }
            });
            assert!(matches!(pKiller.join().unwrap(), Ok(0) | Ok(1) | Err(-3)));
            let pStatus = pCollector.join().unwrap();
            assert!(pStatus == 42 || pStatus == 137);
            {
                let mut pGuard = pFrames.lock().unwrap();
                assert_eq!(pGuard.used(), 2, "remote collect freed the owner node");
                assert_eq!(pRegistry.collect(&mut pGuard, 1, 2), Err(-10));
                assert!(pRegistry.sessionChildrenRemain(&mut pGuard, 1));
                assert_eq!(pRegistry.parentOf(&mut pGuard, 2), Some(1));
            }
            pReleaseSend.send(()).unwrap();
            assert_eq!(pOwner.join().unwrap(), pStatus);
        });
        let mut pFrames = pFrames.into_inner().unwrap();
        assert_eq!(pFrames.used(), 1);
        assert!(!pRegistry.sessionChildrenRemain(&mut pFrames, 1));
        assert_eq!(pRegistry.parentOf(&mut pFrames, 2), None);
        pRoot.release(&mut pFrames);
        assert_eq!(pFrames.used(), 0);
    }
}

// Preserve the existing explicit-kill and independent-family tests. This
// case independently checks the ordinary natural-exit adoption policy.
#[test]
fn adoptedNaturalExitsRemainCollectableOnlyOnceByOriginalRoot() {
    let pRegistry = lifecycle::Registry::new();
    let mut pFrames = frames::Frames::new(8);
    let pRoot = unsafe { pRegistry.register(&mut pFrames, 1, 0) }.unwrap();
    let pParent = unsafe { pRegistry.register(&mut pFrames, 2, 1) }.unwrap();
    let pLive = unsafe { pRegistry.register(&mut pFrames, 3, 2) }.unwrap();
    let pZombie = unsafe { pRegistry.register(&mut pFrames, 4, 2) }.unwrap();
    let pOther = unsafe { pRegistry.register(&mut pFrames, 5, 0) }.unwrap();
    pZombie.finish(&mut pFrames, 57);
    pParent.finish(&mut pFrames, 0);
    assert_eq!(pRegistry.collect(&mut pFrames, 1, 2), Ok(0));
    assert_eq!(pRegistry.collect(&mut pFrames, 1, 4), Ok(57));
    assert_eq!(pRegistry.collect(&mut pFrames, 1, 4), Err(-10));
    for _ in 0..3 {
        let pState = pLive.snapshot(&mut pFrames);
        assert_eq!((pState.fParent, pState.fReaper, pState.fStatus), (1, 1, None));
        assert!(!pState.fKillPending && !pState.fCollected);
        assert_eq!(pRegistry.collect(&mut pFrames, 1, 3), Err(-11));
        assert_eq!(pRegistry.collect(&mut pFrames, 5, 3), Err(-10));
        assert_eq!(pRegistry.requestKill(&mut pFrames, 5, 3), Err(-1));
    }
    pLive.finish(&mut pFrames, 59);
    assert_eq!(pRegistry.collect(&mut pFrames, 1, 3), Ok(59));
    assert_eq!(pRegistry.collect(&mut pFrames, 1, 3), Err(-10));
    assert_eq!(pRegistry.requestKill(&mut pFrames, 1, 3), Err(-3));
    pLive.release(&mut pFrames);
    pZombie.release(&mut pFrames);
    pParent.release(&mut pFrames);
    assert!(!pRegistry.sessionChildrenRemain(&mut pFrames, 1));
    pOther.release(&mut pFrames);
    pRoot.release(&mut pFrames);
    assert_eq!(pFrames.used(), 0);
}
