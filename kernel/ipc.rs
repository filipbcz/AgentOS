//! One bounded message in flight in each direction of a local channel.
//! Endpoints may belong to processes on different CPUs. The shared frame
//! allocator gate serializes message, readiness and endpoint-reference access.
#![allow(non_snake_case)]
use crate::{frames::Frames, paging::UserSpace, process::Credentials};

pub const MAX_MESSAGE: usize = 1024;
#[derive(Clone, Copy)]
pub enum Operation { Send, Receive }

struct Message {
    length: usize, // zero also represents an empty slot; empty sends are rejected
    peer: [u8; 16],
    data: [u8; MAX_MESSAGE],
}

pub struct Channel {
    refs: [usize; 2],
    inbox: [Message; 2],
}
const _: () = assert!(core::mem::size_of::<Channel>() <= 4096);

impl Channel {
    /// Initialize a fresh zeroed channel before publishing either endpoint.
    pub fn initialize(&mut self, _aFrames: &mut Frames<'_>) {
        assert_eq!(self.refs, [0, 0]);
        self.refs = [1, 1];
    }

    pub fn retain(&mut self, _aFrames: &mut Frames<'_>, aSide: usize) {
        assert!(self.refs[aSide] != 0);
        self.refs[aSide] += 1;
    }

    /// Return true only when the caller may release the channel's frame.
    pub fn release(&mut self, _aFrames: &mut Frames<'_>, aSide: usize) -> bool {
        assert!(self.refs[aSide] != 0);
        self.refs[aSide] -= 1;
        self.refs == [0, 0]
    }

    pub fn ready(&self, _aFrames: &mut Frames<'_>, side: usize, op: Operation) -> bool {
        self.refs[1-side] == 0 || match op {
            Operation::Send => self.inbox[1-side].length == 0,
            Operation::Receive => self.inbox[side].length != 0,
        }
    }

    pub fn send(&mut self, frames: &mut Frames<'_>, side: usize, pid: usize, credentials: Credentials,
                space: &UserSpace, address: usize, len: usize) -> Result<Option<usize>, isize> {
        if len == 0 || len > MAX_MESSAGE { return Err(-90); }
        if self.refs[1-side] == 0 { return Err(-32); }
        let slot = &mut self.inbox[1-side];
        if slot.length != 0 { return Ok(None); }
        space.read(frames, address, &mut slot.data[..len])?;
        slot.peer[..8].copy_from_slice(&(pid as u64).to_le_bytes());
        slot.peer[8..12].copy_from_slice(&credentials.uid.to_le_bytes());
        slot.peer[12..].copy_from_slice(&credentials.gid.to_le_bytes());
        slot.length = len;
        Ok(Some(len))
    }

    pub fn receive(&mut self, frames: &mut Frames<'_>, side: usize, space: &UserSpace, address: usize,
                   capacity: usize) -> Result<Option<usize>, isize> {
        let slot = &mut self.inbox[side];
        if slot.length == 0 { return Ok((self.refs[1-side] == 0).then_some(0)); }
        let len = slot.length;
        if capacity < len { return Err(-90); }
        space.writable(frames, address, slot.peer.len()+len)?;
        space.write(frames, address, &slot.peer)?;
        space.write(frames, address+slot.peer.len(), &slot.data[..len])?;
        slot.length = 0;
        Ok(Some(len))
    }
}
