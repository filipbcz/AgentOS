//! Coherent x86 direct DMA (no IOMMU). One allocator reference per mapped page.
use crate::frames::{Frame, Frames};
use core::sync::atomic::{fence, Ordering};

pub const PAGE: usize = 4096;

#[derive(Clone, Copy)]
pub struct BusAddress(u64);

impl BusAddress {
    pub fn of(frame: &Frame, mask: u64) -> Option<Self> {
        let first = frame.address() as u64;
        (first.checked_add(PAGE as u64 - 1)? <= mask).then_some(Self(first))
    }
    pub fn value(self) -> u64 { self.0 }
}

pub struct Mapping<const N: usize> {
    physical: [usize; N],
    bus: [BusAddress; N],
}

#[must_use]
pub struct InFlight<const N: usize>(Mapping<N>);

impl<const N: usize> Mapping<N> {
    pub fn pin(frames: &mut Frames<'_>, pages: &[Frame; N], mask: u64) -> Option<Self> {
        let mut bus = [BusAddress(0); N];
        for (address, frame) in bus.iter_mut().zip(pages) { *address = BusAddress::of(frame, mask)?; }
        let physical = core::array::from_fn(|i| pages[i].address());
        for (i, &address) in physical.iter().enumerate() {
            if frames.retain(address).is_none() {
                for &held in &physical[..i] { frames.release(unsafe { Frame::from_owned_address(held) }); }
                return None;
            }
        }
        Some(Self { physical, bus })
    }
    pub fn addresses(&self) -> &[BusAddress; N] { &self.bus }
    pub fn pages(&self) -> &[usize; N] { &self.physical }
    pub fn submit(self) -> InFlight<N> {
        fence(Ordering::Release); // publish descriptors before the device doorbell
        InFlight(self)
    }
    pub fn unmap(self, frames: &mut Frames<'_>) {
        for address in self.physical { frames.release(unsafe { Frame::from_owned_address(address) }); }
    }
}

impl<const N: usize> InFlight<N> {
    /// The caller observed hardware completion or proved the device quiescent.
    /// Dropping a still-active handle leaves its pins in the allocator.
    pub unsafe fn reclaim(self) -> Mapping<N> {
        fence(Ordering::Acquire);
        self.0
    }
}
