//! One bounded message in flight in each direction of a local channel.
//! Channel access is serialized by its endpoints' CPU with interrupts masked.
use crate::{paging::UserSpace, process::{Credentials, EFAULT}};

pub const MAX_MESSAGE: usize = 1024;
#[derive(Clone, Copy)]
pub enum Operation { Send, Receive }

struct Message {
    length: usize, // zero also represents an empty slot; empty sends are rejected
    peer: [u8; 16],
    data: [u8; MAX_MESSAGE],
}

pub struct Channel {
    pub refs: [usize; 2],
    inbox: [Message; 2],
}
const _: () = assert!(core::mem::size_of::<Channel>() <= 4096);

impl Channel {
    pub fn ready(&self, side: usize, op: Operation) -> bool {
        self.refs[1-side] == 0 || match op {
            Operation::Send => self.inbox[1-side].length == 0,
            Operation::Receive => self.inbox[side].length != 0,
        }
    }

    pub fn send(&mut self, side: usize, pid: usize, credentials: Credentials,
                space: &UserSpace, address: usize, len: usize) -> Result<Option<usize>, isize> {
        if len == 0 || len > MAX_MESSAGE { return Err(-90); }
        if self.refs[1-side] == 0 { return Err(-32); }
        let slot = &mut self.inbox[1-side];
        if slot.length != 0 { return Ok(None); }
        space.read(address, &mut slot.data[..len]).ok_or(EFAULT)?;
        slot.peer[..8].copy_from_slice(&(pid as u64).to_le_bytes());
        slot.peer[8..12].copy_from_slice(&credentials.uid.to_le_bytes());
        slot.peer[12..].copy_from_slice(&credentials.gid.to_le_bytes());
        slot.length = len;
        Ok(Some(len))
    }

    pub fn receive(&mut self, side: usize, space: &UserSpace, address: usize,
                   capacity: usize) -> Result<Option<usize>, isize> {
        let slot = &mut self.inbox[side];
        if slot.length == 0 { return Ok((self.refs[1-side] == 0).then_some(0)); }
        let len = slot.length;
        if capacity < len { return Err(-90); }
        space.writable(address, slot.peer.len()+len).ok_or(EFAULT)?;
        space.write(address, &slot.peer).ok_or(EFAULT)?;
        space.write(address+slot.peer.len(), &slot.data[..len]).ok_or(EFAULT)?;
        slot.length = 0;
        Ok(Some(len))
    }
}
