//! PS/2 scan-code set 1, US-QWERTY ASCII decoder.
//! No I/O, allocation or terminal policy: usable in host tests and no_std kernel.
#![allow(non_snake_case)]
pub struct Keyboard {
    left_shift: bool, right_shift: bool, left_ctrl: bool, right_ctrl: bool,
    left_alt: bool, right_alt: bool, caps: bool, extended: bool, pause_tail: u8,
}
impl Keyboard {
    pub const fn new() -> Self {
        Self { left_shift: false, right_shift: false, left_ctrl: false,
               right_ctrl: false, left_alt: false, right_alt: false,
               caps: false, extended: false, pause_tail: 0 }
    }
    pub fn reset(&mut self) { *self = Self::new(); }
    fn shift(&self) -> bool { self.left_shift || self.right_shift }
    fn ctrl(&self) -> bool { self.left_ctrl || self.right_ctrl }
    fn alt(&self) -> bool { self.left_alt || self.right_alt }
    /// Convert MAKE events to ASCII; ignore BREAK and unsupported keys.
    pub fn feed(&mut self, byte: u8) -> Option<u8> {
        if self.pause_tail > 0 { self.pause_tail -= 1; return None; }
        if byte == 0xe1 { self.pause_tail = 5; self.extended = false; return None; }
        if byte == 0xe0 { self.extended = true; return None; }
        let ext = core::mem::replace(&mut self.extended, false);
        let up = byte & 0x80 != 0;
        let code = byte & 0x7f;
        if ext {
            match code {
                0x1d => self.right_ctrl = !up,
                0x38 => self.right_alt = !up,
                0x1c if !up => return Some(b'\r'),
                0x35 if !up && !self.ctrl() && !self.alt() => return Some(b'/'),
                0x53 if !up => return Some(127),
                _ => (),
            }
            return None;
        }
        match code {
            0x2a => self.left_shift = !up,
            0x36 => self.right_shift = !up,
            0x1d => self.left_ctrl = !up,
            0x38 => self.left_alt = !up,
            0x3a if !up => self.caps = !self.caps,
            _ => (),
        }
        if up || self.alt() { return None; }
        match code {
            0x0e => return Some(8), 0x0f => return Some(b'\t'),
            0x1c => return Some(b'\r'), 0x39 => return Some(b' '),
            _ => (),
        }
        let letter = match code {
            0x10 => b'q', 0x11 => b'w', 0x12 => b'e', 0x13 => b'r',
            0x14 => b't', 0x15 => b'y', 0x16 => b'u', 0x17 => b'i',
            0x18 => b'o', 0x19 => b'p', 0x1e => b'a', 0x1f => b's',
            0x20 => b'd', 0x21 => b'f', 0x22 => b'g', 0x23 => b'h',
            0x24 => b'j', 0x25 => b'k', 0x26 => b'l', 0x2c => b'z',
            0x2d => b'x', 0x2e => b'c', 0x2f => b'v', 0x30 => b'b',
            0x31 => b'n', 0x32 => b'm', _ => 0,
        };
        if letter != 0 {
            if self.ctrl() { return (letter == b'd').then_some(4); }
            return Some(if self.shift() ^ self.caps { letter.to_ascii_uppercase() } else { letter });
        }
        if self.ctrl() { return None; }
        let (normal, shifted) = match code {
            0x02 => (b'1', b'!'), 0x03 => (b'2', b'@'),
            0x04 => (b'3', b'#'), 0x05 => (b'4', b'$'),
            0x06 => (b'5', b'%'), 0x07 => (b'6', b'^'),
            0x08 => (b'7', b'&'), 0x09 => (b'8', b'*'),
            0x0a => (b'9', b'('), 0x0b => (b'0', b')'),
            0x0c => (b'-', b'_'), 0x0d => (b'=', b'+'),
            0x1a => (b'[', b'{'), 0x1b => (b']', b'}'),
            0x27 => (b';', b':'), 0x28 => (b'\'', b'"'),
            0x29 => (b'\x60', b'~'), 0x2b => (b'\\', b'|'),
            0x33 => (b',', b'<'), 0x34 => (b'.', b'>'),
            0x35 => (b'/', b'?'), _ => return None,
        };
        Some(if self.shift() { shifted } else { normal })
    }
}
#[cfg(test)]
mod tests {
    use super::Keyboard;
    fn decode(codes: &[u8]) -> Vec<u8> {
        let mut keyboard = Keyboard::new();
        codes.iter().filter_map(|&c| keyboard.feed(c)).collect()
    }
    #[test]
    fn lettersReleasesAndEnter() {
        assert_eq!(decode(&[0x10,0x90,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1c]), b"qwertyuiop\r");
    }
    #[test]
    fn shiftCapsAndDigits() {
        assert_eq!(decode(&[0x2a,0x1e,0xaa,0x3a,0xba,0x1e,0x36,0x1e,0x02,0xb6,0x02,0x3a,0x1e]), b"AAa!1a");
    }
    #[test]
    fn editingAndCtrlD() {
        assert_eq!(decode(&[0x0f,0x0e,0xe0,0x53,0xe0,0x1c,0x1d,0x20,0x9d,0x20]), b"\t\x08\x7f\r\x04d");
    }
    #[test]
    fn rightModifiersAndExtendedNoise() {
        assert_eq!(decode(&[0xe0,0x1d,0x20,0xe0,0x9d,0xe0,0x35,0xe0,0x2a,0xe0,0xaa,0x20,0xe0,0x38,0x20,0xe0,0xb8,0x20]), b"\x04/dd");
    }
    #[test]
    fn pauseAndUnsupportedIgnored() {
        assert_eq!(decode(&[0xe1,0x1d,0x45,0xe1,0x9d,0xc5,0x3b,0xbb,0xe0,0x48,0xe0,0xc8,0x1e]), b"a");
    }
    #[test]
    fn resetClearsStuckModifier() {
        let mut k = Keyboard::new(); k.feed(0x2a);
        assert_eq!(k.feed(0x1e), Some(b'A'));
        k.reset();
        assert_eq!(k.feed(0x1e), Some(b'a'));
    }
    #[test]
    fn boundedASCII() {
        let mut k = Keyboard::new();
        for byte in 0u8..=255 {
            if let Some(c) = k.feed(byte) {
                assert!(c == 4 || c == 8 || c == 9 || c == 13 ||
                        c == 127 || (32..=126).contains(&c));
            }
        }
    }
}
