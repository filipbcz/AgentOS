//! Descriptor tables belong to processes. Shared descriptions are reachable
//! only by dup2 and inheritance on the same CPU, with local IRQs masked.
#![allow(non_snake_case)]
use crate::{frames::{Frame, Frames}, paging::UserSpace, process::EFAULT, serial};
use core::mem;
use crate::ipc::{Channel, Operation};

const SLOTS: usize = 32;
const PIPE_SIZE: usize = 1024;
struct OpenFile { data: &'static [u8], offset: usize, refs: usize }
struct Pipe { readers: usize, writers: usize, head: usize, used: usize, buf: [u8; PIPE_SIZE] }

#[derive(Clone, Copy)]
enum Handle { Empty, Console, File(*mut OpenFile), Reader(*mut Pipe), Writer(*mut Pipe), Socket(*mut Channel, usize),
              TerminalInput(*mut crate::tty::Terminal), TerminalOutput(*mut crate::tty::Terminal) }
pub struct Descriptors(Frame);
const _: () = assert!(mem::size_of::<[Handle; SLOTS]>() <= 4096 && mem::size_of::<Pipe>() <= 4096);

#[derive(Clone, Copy)]
pub enum Wait { Pipe { end: PipeWait, need: usize }, Socket(*mut Channel, usize, Operation), Terminal(*mut crate::tty::Terminal) }
#[derive(Clone, Copy)]
pub struct PipeWait(Handle);
pub enum Io { Bytes(usize), Sleep(Wait), Output(PendingOutput) }

/// A bounded copy of user bytes, prepared while page allocation is locked.
/// Complete hardware output only after releasing the shared frame lock. The
/// descriptor/session remains owned by this CPU until the syscall returns.
pub struct PendingOutput {
    fTarget: Handle,
    fBytes: [u8; 256],
    fLength: usize,
}

impl PendingOutput {
    pub fn complete(self) -> Result<usize, isize> {
        let pBytes = &self.fBytes[..self.fLength];
        match self.fTarget {
            Handle::Console => { unsafe { serial(pBytes); } Ok(self.fLength) }
            Handle::TerminalOutput(pTerminal) => unsafe { (*pTerminal).write(pBytes) },
            _ => unreachable!(),
        }
    }
}

impl Wait {
    pub fn ready(self) -> bool {
        // The sleeping process still owns this endpoint until its call returns.
        let (end, need) = match self {
            Self::Terminal(p) => return unsafe { (*p).ready() },
            Self::Socket(p, side, op) => return unsafe { (*p).ready(side, op) },
            Self::Pipe { end, need } => (end.0, need),
        };
        unsafe { match end {
            Handle::Reader(p) => (*p).used != 0 || (*p).writers == 0,
            Handle::Writer(p) => PIPE_SIZE - (*p).used >= need || (*p).readers == 0,
            _ => unreachable!(),
        } }
    }
}

impl Handle {
    unsafe fn retain(self) -> Self {
        match self {
            Self::File(p) => (*p).refs += 1,
            Self::Reader(p) => (*p).readers += 1,
            Self::Writer(p) => (*p).writers += 1,
            Self::Socket(p, side) => (*p).refs[side] += 1,
            _ => (),
        }
        self
    }

    unsafe fn release(self, frames: &mut Frames<'_>) {
        let dead = match self {
            Self::Socket(p, side) => {
                (*p).refs[side] -= 1;
                ((*p).refs == [0, 0]).then_some(p as usize)
            }
            Self::File(p) => { (*p).refs -= 1; ((*p).refs == 0).then_some(p as usize) }
            Self::Reader(p) | Self::Writer(p) => {
                if matches!(self, Self::Reader(_)) { (*p).readers -= 1; } else { (*p).writers -= 1; }
                ((*p).readers == 0 && (*p).writers == 0).then_some(p as usize)
            }
            _ => None,
        };
        if let Some(addr) = dead { frames.release(Frame::from_owned_address(addr)); }
    }
}

impl Descriptors {
    pub fn new(frames: &mut Frames<'_>) -> Option<Self> {
        let frame = frames.alloc()?;
        let slots = frame.address() as *mut Handle;
        for i in 0..SLOTS { unsafe { slots.add(i).write(Handle::Empty); } }
        unsafe { slots.add(1).write(Handle::Console); }
        Some(Self(frame))
    }
    fn slots(&self) -> &[Handle; SLOTS] { unsafe { &*(self.0.address() as *const _) } }
    fn slots_mut(&mut self) -> &mut [Handle; SLOTS] { unsafe { &mut *(self.0.address() as *mut _) } }
    fn handle(&self, fd: usize) -> Result<Handle, isize> {
        match self.slots().get(fd) { None | Some(Handle::Empty) => Err(-9), Some(&h) => Ok(h) }
    }
    fn free_slots(&self) -> impl Iterator<Item=usize> + '_ {
        self.slots().iter().enumerate().filter_map(|(i, h)| matches!(h, Handle::Empty).then_some(i))
    }

    // Called once on a newly created child's table, before it becomes runnable.
    pub fn inherit(&mut self, parent: &Self) {
        for (slot, &h) in self.slots_mut().iter_mut().zip(parent.slots()) { *slot = unsafe { h.retain() }; }
    }

    // Attach only to the fresh shell, preserving the acceptance programs' fd0.
    // The session owner outlives all inherited descriptors and sleeping tasks.
    pub fn terminal(&mut self, terminal: *mut crate::tty::Terminal) -> Result<(), isize> {
        if !matches!(self.slots()[0], Handle::Empty) || !matches!(self.slots()[1], Handle::Console) ||
            !matches!(self.slots()[2], Handle::Empty) { return Err(-22); }
        self.slots_mut()[0] = Handle::TerminalInput(terminal);
        self.slots_mut()[1] = Handle::TerminalOutput(terminal);
        self.slots_mut()[2] = Handle::TerminalOutput(terminal);
        Ok(())
    }
    pub fn close(&mut self, frames: &mut Frames<'_>, fd: usize) -> Result<usize, isize> {
        let h = self.handle(fd)?;
        self.slots_mut()[fd] = Handle::Empty;
        unsafe { h.release(frames); }
        Ok(0)
    }
    pub fn close_all(&mut self, frames: &mut Frames<'_>) {
        for slot in self.slots_mut() { unsafe { mem::replace(slot, Handle::Empty).release(frames); } }
    }
    pub fn release(mut self, frames: &mut Frames<'_>) {
        self.close_all(frames);
        frames.release(self.0);
    }
    pub fn dup2(&mut self, frames: &mut Frames<'_>, old: usize, new: usize) -> Result<usize, isize> {
        let h = self.handle(old)?;
        let target = self.slots_mut().get_mut(new).ok_or(-9isize)?;
        if old != new { unsafe { mem::replace(target, h.retain()).release(frames); } }
        Ok(new)
    }
    pub fn open(&mut self, frames: &mut Frames<'_>, data: &'static [u8]) -> Result<usize, isize> {
        let fd = self.free_slots().next().ok_or(-24isize)?;
        let p = frames.alloc().ok_or(-12isize)?.into_address() as *mut OpenFile;
        unsafe { p.write(OpenFile { data, offset: 0, refs: 1 }); }
        self.slots_mut()[fd] = Handle::File(p);
        Ok(fd)
    }
    pub fn pair(&mut self, frames: &mut Frames<'_>, space: &UserSpace, output: usize, socket: bool) -> Result<usize, isize> {
        let (r, w) = {
            let mut free = self.free_slots();
            (free.next().ok_or(-24isize)?, free.next().ok_or(-24isize)?)
        };
        let frame = frames.alloc_zeroed().ok_or(-12isize)?;
        let pair = (r as u64 | ((w as u64) << 32)).to_le_bytes();
        if let Err(error) = space.write(frames, output, &pair) { frames.release(frame); return Err(error); }
        let address = frame.into_address();
        let (first, second) = if socket {
            let p = address as *mut Channel;
            unsafe { (*p).refs = [1, 1]; }
            (Handle::Socket(p, 0), Handle::Socket(p, 1))
        } else {
            let p = address as *mut Pipe;
            unsafe { (*p).readers = 1; (*p).writers = 1; }
            (Handle::Reader(p), Handle::Writer(p))
        };
        self.slots_mut()[r] = first;
        self.slots_mut()[w] = second;
        Ok(0)
    }

    /// Validate the entire watch set before going to sleep. Each selected
    /// handle must be a live local IPC socket. Closure of its peer is readable
    /// (EOF), so waiting callers never get stranded on a dead service.
    pub fn ipc_ready_mask(&self, mask: u32) -> Result<u32, isize> {
        let mut ready = 0u32;
        for fd in 0..SLOTS {
            let bit = 1u32 << fd;
            if mask & bit == 0 { continue; }
            let Handle::Socket(channel, side) = self.handle(fd)? else { return Err(-88); };
            if unsafe { (*channel).ready(side, Operation::Receive) } { ready |= bit; }
        }
        Ok(ready)
    }

    pub fn message(&self, frames: &mut Frames<'_>, op: Operation, process: &crate::process::Process, fd: usize,
                   address: usize, len: usize) -> Result<Io, isize> {
        let Handle::Socket(p, side) = self.handle(fd)? else { return Err(-88); };
        let channel = unsafe { &mut *p };
        let result = match op {
            Operation::Send => channel.send(frames, side, process.pid, process.credentials, &process.space, address, len),
            Operation::Receive => channel.receive(frames, side, &process.space, address, len),
        }?;
        Ok(result.map_or(Io::Sleep(Wait::Socket(p, side, op)), Io::Bytes))
    }

    pub fn read(&self, frames: &mut Frames<'_>, space: &UserSpace, fd: usize, va: usize, len: usize) -> Result<Io, isize> {
        let end = self.handle(fd)?;
        match end {
            Handle::TerminalInput(p) => {
                let n = unsafe { (*p).read(len, |bytes| space.write(frames, va, bytes))? };
                Ok(n.map_or(Io::Sleep(Wait::Terminal(p)), Io::Bytes))
            }
            Handle::File(p) => {
                let file = unsafe { &mut *p };
                let n = len.min(file.data.len() - file.offset);
                space.write(frames, va, &file.data[file.offset..file.offset+n])?;
                file.offset += n;
                Ok(Io::Bytes(n))
            }
            Handle::Reader(p) => {
                let pipe = unsafe { &mut *p };
                if len == 0 { return Ok(Io::Bytes(0)); }
                if pipe.used == 0 && pipe.writers != 0 { return Ok(Io::Sleep(Wait::Pipe { end: PipeWait(end), need: 1 })); }
                let n = len.min(pipe.used);
                space.writable(frames, va, n)?;
                let first = n.min(PIPE_SIZE - pipe.head);
                space.write(frames, va, &pipe.buf[pipe.head..pipe.head+first])?;
                space.write(frames, va+first, &pipe.buf[..n-first])?;
                pipe.head = (pipe.head+n) % PIPE_SIZE;
                pipe.used -= n;
                Ok(Io::Bytes(n))
            }
            _ => Err(-9),
        }
    }

    pub fn write(&self, frames: &mut Frames<'_>, space: &UserSpace, fd: usize, va: usize, len: usize) -> Result<Io, isize> {
        let end = self.handle(fd)?;
        match end {
            Handle::TerminalOutput(_) | Handle::Console => {
                let mut pBytes = [0; 256];
                if matches!(end, Handle::Console) && len > pBytes.len() { return Err(-22); }
                let pLength = len.min(pBytes.len());
                space.read(frames, va, &mut pBytes[..pLength])?;
                Ok(Io::Output(PendingOutput { fTarget: end, fBytes: pBytes, fLength: pLength }))
            }
            Handle::Writer(p) => {
                let pipe = unsafe { &mut *p };
                if len == 0 { return Ok(Io::Bytes(0)); }
                if pipe.readers == 0 { return Err(-32); }
                let free = PIPE_SIZE - pipe.used;
                let need = if len <= PIPE_SIZE { len } else { 1 };
                if free < need { return Ok(Io::Sleep(Wait::Pipe { end: PipeWait(end), need })); }
                let n = len.min(free);
                va.checked_add(n).ok_or(EFAULT)?;
                // Validate and fault in the entire source before touching
                // either half of the ring. A later page/OOM failure must not
                // leave a partial write or commit any pipe bytes.
                space.readable(frames, va, n)?;
                let tail = (pipe.head + pipe.used) % PIPE_SIZE;
                let first = n.min(PIPE_SIZE - tail);
                space.read(frames, va, &mut pipe.buf[tail..tail+first])?;
                space.read(frames, va+first, &mut pipe.buf[..n-first])?;
                pipe.used += n;
                Ok(Io::Bytes(n))
            }
            _ => Err(-9),
        }
    }
}
