//! Fixed-size, allocation-free log history storage.
//! Single-owner component: NOT safe to share across CPUs or call reentrantly.
//! No UART/framebuffer writes, locks, clocks or interrupts in this module.
//! Integrate only after defining CPU-local ownership and IRQ-safe draining.
use crate::log_policy::Level;

pub const CAPACITY: usize = 32;
pub const MESSAGE_BYTES: usize = 96;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Record {
    pub sequence: u64,
    pub timestamp: u64, // caller-supplied monotonic ticks; zero if unavailable
    pub cpu: u32,
    pub level: Level,
    len: u8,
    truncated: bool,
    bytes: [u8; MESSAGE_BYTES],
}
impl Record {
    const EMPTY: Self = Self {
        sequence: 0, timestamp: 0, cpu: 0, level: Level::Info,
        len: 0, truncated: false, bytes: [0; MESSAGE_BYTES],
    };
    pub fn message(&self) -> &[u8] { &self.bytes[..self.len as usize] }
    pub fn truncated(&self) -> bool { self.truncated }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReadResult {
    Record(Record),
    Empty,
    Overwritten { next_available: u64 },
    Exhausted,
}

pub struct Ring {
    records: [Record; CAPACITY],
    next: u64,
    count: usize,
}
impl Ring {
    pub const fn new() -> Self {
        Self { records: [Record::EMPTY; CAPACITY], next: 0, count: 0 }
    }
    /// Returns false when sequence numbers are exhausted; no silent wrap.
    pub fn push(&mut self, timestamp: u64, cpu: u32, level: Level, message: &[u8]) -> bool {
        if self.next == u64::MAX { return false; }
        let index = (self.next % CAPACITY as u64) as usize;
        let n = core::cmp::min(message.len(), MESSAGE_BYTES);
        let mut record = Record::EMPTY;
        record.sequence = self.next;
        record.timestamp = timestamp;
        record.cpu = cpu;
        record.level = level;
        record.len = n as u8;
        record.truncated = n != message.len();
        record.bytes[..n].copy_from_slice(&message[..n]);
        self.records[index] = record;
        self.next += 1;
        if self.count < CAPACITY { self.count += 1; }
        true
    }
    pub fn next_sequence(&self) -> u64 { self.next }
    pub fn oldest_sequence(&self) -> u64 { self.next - self.count as u64 }
    /// Cursor is the sequence requested, not an array offset.
    /// Overwritten means the consumer must advance to next_available.
    pub fn read(&self, cursor: u64) -> ReadResult {
        if cursor < self.oldest_sequence() {
            return ReadResult::Overwritten { next_available: self.oldest_sequence() };
        }
        if cursor >= self.next { return ReadResult::Empty; }
        let record = self.records[(cursor % CAPACITY as u64) as usize];
        if record.sequence != cursor { return ReadResult::Exhausted; }
        ReadResult::Record(record)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn emptyAndOrdered() {
        let mut r = Ring::new();
        assert_eq!(r.read(0), ReadResult::Empty);
        assert!(r.push(12, 2, Level::Info, b"start"));
        assert!(r.push(13, 1, Level::Debug, b"ready"));
        match r.read(0) {
            ReadResult::Record(v) => {
                assert_eq!(v.sequence, 0);
                assert_eq!(v.timestamp, 12);
                assert_eq!(v.cpu, 2);
                assert_eq!(v.level, Level::Info);
                assert_eq!(v.message(), b"start");
                assert!(!v.truncated());
            }
            _ => panic!("missing first entry"),
        }
        assert_eq!(r.read(2), ReadResult::Empty);
    }
    #[test]
    fn wrapSignalsOverwrittenRecords() {
        let mut r = Ring::new();
        for i in 0..CAPACITY + 3 {
            assert!(r.push(i as u64, 0, Level::Info, b"x"));
        }
        assert_eq!(r.oldest_sequence(), 3);
        assert_eq!(r.read(0), ReadResult::Overwritten { next_available: 3 });
        match r.read(3) {
            ReadResult::Record(v) => assert_eq!(v.timestamp, 3),
            _ => panic!("oldest record missing"),
        }
        match r.read((CAPACITY + 2) as u64) {
            ReadResult::Record(v) => assert_eq!(v.timestamp, (CAPACITY + 2) as u64),
            _ => panic!("newest record missing"),
        }
    }
    #[test]
    fn truncationIsExplicit() {
        let mut r = Ring::new();
        let data = [b'A'; MESSAGE_BYTES + 1];
        assert!(r.push(0, 0, Level::Error, &data));
        match r.read(0) {
            ReadResult::Record(v) => {
                assert_eq!(v.message().len(), MESSAGE_BYTES);
                assert!(v.truncated());
            }
            _ => panic!("missing record"),
        }
    }
    #[test]
    fn copiesInputAndDoesNotRetainBorrow() {
        let mut r = Ring::new();
        let mut bytes = [b'x'; 3];
        assert!(r.push(0, 0, Level::Info, &bytes));
        bytes[0] = b'y';
        match r.read(0) {
            ReadResult::Record(v) => assert_eq!(v.message(), b"xxx"),
            _ => panic!("missing record"),
        }
    }
    #[test]
    fn futureCursorIsEmpty() {
        let mut r = Ring::new();
        assert!(r.push(0, 0, Level::Info, b"one"));
        assert_eq!(r.read(999), ReadResult::Empty);
    }
    #[test]
    fn ringIsBounded() {
        assert!(core::mem::size_of::<Ring>() <= 4096);
    }
}
