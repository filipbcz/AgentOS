//! Pure, allocation-free policy for early kernel boot logging.
//! BootInfo v3 field: bits 0..1 severity, bit 8 COM1, bit 9 framebuffer.
//! This module does not perform I/O; callers remain responsible for
//! serialization and for preserving mandatory acceptance/fatal diagnostics.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Level { Error = 0, Info = 1, Debug = 2 }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Sink { Serial, Screen }
pub const SERIAL: u64 = 0x100;
pub const SCREEN: u64 = 0x200;
const LEVEL_MASK: u64 = 3;
pub const DEFAULT: u64 = Level::Info as u64 | SERIAL | SCREEN;

pub struct Policy { flags: u64 }
impl Policy {
    pub const fn new(flags: u64) -> Self { Self { flags } }
    pub fn enabled(&self, level: Level, sink: Sink) -> bool {
        let mask = match sink { Sink::Serial => SERIAL, Sink::Screen => SCREEN };
        self.flags & mask != 0 && (level as u64) <= (self.flags & LEVEL_MASK)
    }
    pub const fn prefix(level: Level) -> &'static [u8] {
        match level {
            Level::Error => b"[ERROR] ",
            Level::Info => b"[INFO] ",
            Level::Debug => b"[DEBUG] ",
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn defaultRoutesInfoToBoth() {
        let p = Policy::new(DEFAULT);
        assert!(p.enabled(Level::Error, Sink::Serial));
        assert!(p.enabled(Level::Info, Sink::Screen));
        assert!(!p.enabled(Level::Debug, Sink::Serial));
    }
    #[test]
    fn quietStillAllowsErrorsOnSelectedSink() {
        let p = Policy::new(SERIAL);
        assert!(p.enabled(Level::Error, Sink::Serial));
        assert!(!p.enabled(Level::Info, Sink::Serial));
        assert!(!p.enabled(Level::Error, Sink::Screen));
    }
    #[test]
    fn debugSerialDoesNotTouchScreen() {
        let p = Policy::new(2 | SERIAL);
        for level in [Level::Error, Level::Info, Level::Debug] {
            assert!(p.enabled(level, Sink::Serial));
            assert!(!p.enabled(level, Sink::Screen));
        }
    }
    #[test]
    fn noneDisablesOrdinaryEvents() {
        let p = Policy::new(2);
        for level in [Level::Error, Level::Info, Level::Debug] {
            assert!(!p.enabled(level, Sink::Serial));
            assert!(!p.enabled(level, Sink::Screen));
        }
    }
    #[test]
    fn prefixesAreStableForLogConsumers() {
        assert_eq!(Policy::prefix(Level::Error), b"[ERROR] ");
        assert_eq!(Policy::prefix(Level::Info), b"[INFO] ");
        assert_eq!(Policy::prefix(Level::Debug), b"[DEBUG] ");
    }
}
