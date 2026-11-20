use crate::frames::{Frame, SharedFrames};
use core::{hint::spin_loop, sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering}};

pub const TASKS: usize = 2;
pub const BATCH: usize = 8;
pub const BATCHES: usize = 512;
const SYNC_INTERVAL: usize = 32;
pub const PHASES: usize = BATCHES / SYNC_INTERVAL;
extern "C" { fn check_preempted_registers(ticks: *const AtomicU32, token: usize) -> usize; }

pub struct Load {
    pub frames: SharedFrames,
    pub started: AtomicBool,
    pages_at_barriers: AtomicUsize,
    checked: AtomicUsize,
    failed: AtomicBool,
    workers: usize,
}

impl Load {
    pub fn new(frames: SharedFrames, cpus: usize) -> Self {
        Self { frames, started: AtomicBool::new(false), pages_at_barriers: AtomicUsize::new(0),
               checked: AtomicUsize::new(0), failed: AtomicBool::new(false), workers: TASKS * cpus }
    }

    fn rendezvous(&self, arrived: &AtomicUsize, increment: usize, target: usize) {
        arrived.fetch_add(increment, Ordering::AcqRel);
        while arrived.load(Ordering::Acquire) < target &&
              !self.failed.load(Ordering::Acquire) { spin_loop(); }
    }

    pub fn overlapping_pages(&self) -> usize {
        self.pages_at_barriers.load(Ordering::Acquire) / PHASES
    }

    pub fn exercise(&self, worker: usize, ticks: &AtomicU32) -> usize {
        let mut released = 0;
        for batch in 0..BATCHES {
            let mut owned: [Option<Frame>; BATCH] = core::array::from_fn(|_| None);
            let tag = 1 + ((worker * BATCHES + batch) * BATCH);
            for (i, slot) in owned.iter_mut().enumerate() {
                let Some(frame) = self.frames.with(|f| f.alloc()) else {
                    self.failed.store(true, Ordering::Release); break;
                };
                let page = frame.address() as *mut usize;
                unsafe { page.write_volatile(tag+i); page.add(511).write_volatile(!(tag+i)); }
                *slot = Some(frame);
            }
            let synchronized = batch % SYNC_INTERVAL == 0;
            let target = (1 + batch / SYNC_INTERVAL) * self.workers;
            if synchronized {
                self.rendezvous(&self.pages_at_barriers, owned.iter().flatten().count(), target * BATCH);
            }
            if batch == 0 {
                // Both threads execute this non-yielding loop with distinct
                // live GPR/XMM values across eight local timer ticks.
                if unsafe { check_preempted_registers(ticks, tag) } != tag {
                    self.failed.store(true, Ordering::Release);
                }
            }
            for (i, frame) in owned.iter().enumerate() {
                if let Some(frame) = frame {
                    let page = frame.address() as *const usize;
                    if unsafe { page.read_volatile() != tag+i || page.add(511).read_volatile() != !(tag+i) } {
                        self.failed.store(true, Ordering::Release);
                    }
                }
            }
            if synchronized { self.rendezvous(&self.checked, 1, target); }
            for frame in owned.into_iter().rev().flatten() {
                self.frames.with(|f| f.release(frame));
                released += 1;
            }
            if self.failed.load(Ordering::Acquire) { return 0; }
        }
        released
    }
}
