//! Owned GOP text console for the BSP TTY. Does not allocate or touch UART.
//! The framebuffer must remain identity-mapped and exclusively owned while used.
//! Only call with interrupts masked (TTY and its IRQ handler share one owner).
use core::ptr::{read_volatile, write_volatile};
const W: usize = 6;
const H: usize = 9;
const BG: u32 = 0x181818;
const FG: u32 = 0xffffff;
// Keep the boot identity and the first diagnostic rows visible above the
// scrolling terminal. The console owns only the region below this boundary.
// 88 = 52 + 2 * 18 also ends on a BOOT.LOG row boundary at both font scales.
pub const BOOT_STATUS_HEIGHT: usize = 88;

/// Five-bit rows with the high bit on the left, covering printable ASCII.
/// All unsupported control characters are handled by Console::write.
pub fn glyph(c: u8) -> [u8; 7] {
    match c {
        b' ' => [0;7],
        b'!' => [4,4,4,4,4,0,4],
        b'"' => [10,10,10,0,0,0,0],
        b'#' => [10,10,31,10,31,10,10],
        b'$' => [4,15,20,14,5,30,4],
        b'%' => [25,25,2,4,8,19,19],
        b'&' => [12,18,20,8,21,18,13],
        b'\'' => [4,4,8,0,0,0,0],
        b'(' => [2,4,8,8,8,4,2],
        b')' => [8,4,2,2,2,4,8],
        b'*' => [0,4,21,14,21,4,0],
        b'+' => [0,4,4,31,4,4,0],
        b',' => [0,0,0,0,4,4,8],
        b'-' => [0,0,0,31,0,0,0],
        b'.' => [0,0,0,0,0,12,12],
        b'/' => [1,1,2,4,8,16,16],
        b'0' => [14,17,19,21,25,17,14],
        b'1' => [4,12,4,4,4,4,14],
        b'2' => [14,17,1,2,4,8,31],
        b'3' => [30,1,1,14,1,1,30],
        b'4' => [2,6,10,18,31,2,2],
        b'5' => [31,16,16,30,1,1,30],
        b'6' => [14,16,16,30,17,17,14],
        b'7' => [31,1,2,4,8,8,8],
        b'8' => [14,17,17,14,17,17,14],
        b'9' => [14,17,17,15,1,1,14],
        b':' => [0,12,12,0,12,12,0],
        b';' => [0,12,12,0,12,4,8],
        b'<' => [2,4,8,16,8,4,2],
        b'=' => [0,0,31,0,31,0,0],
        b'>' => [8,4,2,1,2,4,8],
        b'?' => [14,17,1,2,4,0,4],
        b'@' => [14,17,23,21,23,16,15],
        b'A' => [14,17,17,31,17,17,17],
        b'B' => [30,17,17,30,17,17,30],
        b'C' => [14,17,16,16,16,17,14],
        b'D' => [30,17,17,17,17,17,30],
        b'E' => [31,16,16,30,16,16,31],
        b'F' => [31,16,16,30,16,16,16],
        b'G' => [14,17,16,23,17,17,14],
        b'H' => [17,17,17,31,17,17,17],
        b'I' => [14,4,4,4,4,4,14],
        b'J' => [7,2,2,2,2,18,12],
        b'K' => [17,18,20,24,20,18,17],
        b'L' => [16,16,16,16,16,16,31],
        b'M' => [17,27,21,21,17,17,17],
        b'N' => [17,25,25,21,19,19,17],
        b'O' => [14,17,17,17,17,17,14],
        b'P' => [30,17,17,30,16,16,16],
        b'Q' => [14,17,17,17,21,18,13],
        b'R' => [30,17,17,30,20,18,17],
        b'S' => [15,16,16,14,1,1,30],
        b'T' => [31,4,4,4,4,4,4],
        b'U' => [17,17,17,17,17,17,14],
        b'V' => [17,17,17,17,17,10,4],
        b'W' => [17,17,17,21,21,27,17],
        b'X' => [17,17,10,4,10,17,17],
        b'Y' => [17,17,10,4,4,4,4],
        b'Z' => [31,1,2,4,8,16,31],
        b'[' => [14,8,8,8,8,8,14],
        b'\\' => [16,16,8,4,2,1,1],
        b']' => [14,2,2,2,2,2,14],
        b'^' => [4,10,17,0,0,0,0],
        b'_' => [0,0,0,0,0,0,31],
        b'\x60' => [8,4,2,0,0,0,0],
        b'a' => [0,0,14,1,15,17,15],
        b'b' => [16,16,30,17,17,17,30],
        b'c' => [0,0,15,16,16,16,15],
        b'd' => [1,1,15,17,17,17,15],
        b'e' => [0,0,14,17,31,16,14],
        b'f' => [6,9,8,28,8,8,8],
        b'g' => [0,15,17,17,15,1,14],
        b'h' => [16,16,30,17,17,17,17],
        b'i' => [4,0,12,4,4,4,14],
        b'j' => [2,0,6,2,2,18,12],
        b'k' => [16,16,18,20,24,20,18],
        b'l' => [12,4,4,4,4,4,14],
        b'm' => [0,0,26,21,21,21,21],
        b'n' => [0,0,30,17,17,17,17],
        b'o' => [0,0,14,17,17,17,14],
        b'p' => [0,30,17,17,30,16,16],
        b'q' => [0,15,17,17,15,1,1],
        b'r' => [0,0,22,25,16,16,16],
        b's' => [0,0,15,16,14,1,30],
        b't' => [8,8,28,8,8,9,6],
        b'u' => [0,0,17,17,17,19,13],
        b'v' => [0,0,17,17,17,10,4],
        b'w' => [0,0,17,17,21,21,10],
        b'x' => [0,0,17,10,4,10,17],
        b'y' => [0,17,17,15,1,17,14],
        b'z' => [0,0,31,2,4,8,31],
        b'{' => [6,8,8,16,8,8,6],
        b'|' => [4,4,4,4,4,4,4],
        b'}' => [12,2,2,1,2,2,12],
        b'~' => [0,0,9,22,0,0,0],
        _ => [14,17,1,2,4,0,4],
    }
}

pub struct Console {
    base: *mut u32,
    width: usize,
    height: usize,
    stride: usize,
    cols: usize,
    rows: usize,
    x: usize,
    y: usize,
}

impl Console {
    /// Retain the actual boot status pixels while the interactive region
    /// scrolls. Small displays use the whole framebuffer to retain usable
    /// terminal space. No framebuffer snapshot or test-only pause is needed.
    pub unsafe fn below_boot_status(base: *mut u32, width: usize, height: usize,
                                    stride: usize, format: u32) -> Option<Self> {
        if base.is_null() || stride < width { return None; }
        let pBytes = stride.checked_mul(height)?.checked_mul(4)?;
        if pBytes > isize::MAX as usize { return None; }
        (base as usize).checked_add(pBytes)?;
        let pTop = if height >= BOOT_STATUS_HEIGHT + 2*H { BOOT_STATUS_HEIGHT } else { 0 };
        Self::new(base.add(pTop.checked_mul(stride)?), width, height-pTop, stride, format)
    }

    /// Valid GOP format 0 (RGB) or 1 (BGR), both use identical black/white.
    /// Caller owns a mapped, writable framebuffer for the entire lifetime.
    pub unsafe fn new(base: *mut u32, width: usize, height: usize, stride: usize, format: u32) -> Option<Self> {
        if base.is_null() || width < W || height < H || stride < width || format > 1 { return None; }
        let bytes = stride.checked_mul(height)?.checked_mul(4)?;
        (bytes <= isize::MAX as usize).then_some(())?;
        (base as usize).checked_add(bytes)?;
        let mut screen = Self {base,width,height,stride,cols:width/W,rows:height/H,x:0,y:0};
        screen.clear();
        Some(screen)
    }

    fn pixel(&self, x: usize, y: usize, color: u32) {
        // SAFETY: all callers bound x/y by width/height, with checked total size.
        unsafe { write_volatile(self.base.add(y*self.stride+x),color); }
    }

    fn toggle_cursor(&self) {
        let y = self.y*H + 7;
        let x = self.x*W;
        if self.x < self.cols && y < self.height && x + 5 <= self.width {
            for dx in 0..5 {
                unsafe {
                    let p=self.base.add(y*self.stride+x+dx);
                    write_volatile(p,read_volatile(p)^FG);
                }
            }
        }
    }

    fn cell(&self, col: usize, row: usize, c: u8) {
        let bits = glyph(c);
        for dy in 0..H {
            for dx in 0..W {
                let fg = dy<7 && dx<5 && bits[dy] & (16 >> dx) != 0;
                self.pixel(col*W+dx,row*H+dy,if fg {FG} else {BG});
            }
        }
    }

    fn scroll(&mut self) {
        let h=self.rows*H;
        let w=self.cols*W;
        // Copy top-to-bottom, so source always comes from a later row.
        for y in 0..h-H {
            for x in 0..w {
                unsafe {
                    let src=self.base.add((y+H)*self.stride+x);
                    let dst=self.base.add(y*self.stride+x);
                    write_volatile(dst,read_volatile(src));
                }
            }
        }
        for y in h-H..h {for x in 0..w {self.pixel(x,y,BG);}}
        self.y=self.rows-1;
    }

    fn newline(&mut self) {
        self.x=0;
        if self.y+1 == self.rows {self.scroll();} else {self.y+=1;}
    }

    fn put(&mut self, b: u8) {
        match b {
            b'\r'=>self.x=0,
            b'\n'=>self.newline(),
            8=>{if self.x>0{self.x-=1;}else if self.y>0{self.y-=1;self.x=self.cols-1;}},
            b'\t'=>{let spaces=4-(self.x%4);for _ in 0..spaces {self.put(b' ');}},
            0x20..=0x7e=>{
                // Defer wrapping so the bottom-right glyph remains visible.
                if self.x==self.cols {self.newline();}
                self.cell(self.x,self.y,b);
                self.x+=1;
            }
            _=>(),
        }
    }

    pub fn write(&mut self, data:&[u8]) {
        self.toggle_cursor();
        for &b in data {self.put(b);}
        self.toggle_cursor();
    }

    pub fn clear(&mut self) {
        for y in 0..self.height {for x in 0..self.width {self.pixel(x,y,BG);}}
        self.x=0;self.y=0;self.toggle_cursor();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn printableAsciiIsRepresented() {
        assert_eq!(glyph(b' '), [0;7]);
        for code in 33..=126 {
            assert!(glyph(code).iter().any(|v|*v!=0),"missing {code}");
            assert!(glyph(code).iter().all(|v| *v<32),"oversized glyph {code}");
        }
    }
    #[test]
    fn invalidGeometryRejected() {
        let mut buffer=[0u32;200];
        let ptr=buffer.as_mut_ptr();
        assert!(unsafe{Console::new(ptr,0,10,10,0)}.is_none());
        assert!(unsafe{Console::new(ptr,10,10,9,0)}.is_none());
        assert!(unsafe{Console::new(ptr,10,10,10,2)}.is_none());
        assert!(unsafe{Console::new(ptr,10,10,usize::MAX,0)}.is_none());
    }
    #[test]
    fn wrappingScrollingAndBackspaceAreBounded() {
        let width=13;let height=19;let stride=17;
        let mut pixels=vec![0xdeadbeef;7+stride*height+7];
        let ptr=unsafe{pixels.as_mut_ptr().add(7)};
        let mut screen=unsafe{Console::new(ptr,width,height,stride,0)}.unwrap();
        screen.write(b"abcd\n1\rZ\x08X\n222\n333\n");
        assert!(pixels[..7].iter().all(|x|*x==0xdeadbeef));
        assert!(pixels[7+stride*height..].iter().all(|x|*x==0xdeadbeef));
        for row in 0..height {for x in width..stride {
            assert_eq!(pixels[7+row*stride+x],0xdeadbeef,"stride padding touched");
        }}
    }
    #[test]
    fn lastCellIsVisibleUntilAnotherGlyphRequiresWrapping() {
        let mut buffer=vec![0u32;6*9];
        let mut console=unsafe{Console::new(buffer.as_mut_ptr(),6,9,6,0)}.unwrap();
        console.write(b"A");
        // A's top row is 01110: at x=1 it must remain illuminated.
        assert_eq!(buffer[1],FG,"the last-cell character was scrolled away");
        console.write(b"B");
        // A subsequent character is allowed to scroll; B starts 11110.
        assert_eq!(buffer[0],FG);
    }
    #[test]
    fn scrollingRetainsLastVisibleLines() {
        let mut a=vec![0;12*18];
        let mut b=vec![0;12*18];
        let mut scrolling=unsafe{Console::new(a.as_mut_ptr(),12,18,12,1)}.unwrap();
        let mut expected=unsafe{Console::new(b.as_mut_ptr(),12,18,12,1)}.unwrap();
        scrolling.write(b"A\nB\nC");
        expected.write(b"B\nC");
        assert_eq!(a,b);
    }

    #[test]
    fn interactiveScrollingAndClearPreserveBootStatusPixels() {
        let pWidth=42; let pStride=47; let pHeight=BOOT_STATUS_HEIGHT+4*H;
        let mut pPixels=vec![0x12345678; pStride*pHeight+8];
        let pHeader=pPixels[..BOOT_STATUS_HEIGHT*pStride].to_vec();
        let mut pConsole=unsafe {Console::below_boot_status(
            pPixels.as_mut_ptr(),pWidth,pHeight,pStride,0)}.unwrap();
        for _ in 0..12 { pConsole.write(b"ready\r\n"); }
        pConsole.clear();
        assert_eq!(&pPixels[..BOOT_STATUS_HEIGHT*pStride], &pHeader);
        for pRow in BOOT_STATUS_HEIGHT..pHeight {
            assert!(pPixels[pRow*pStride+pWidth..(pRow+1)*pStride]
                .iter().all(|&pValue|pValue==0x12345678));
        }
        assert!(pPixels[pStride*pHeight..].iter().all(|&pValue|pValue==0x12345678));
        pConsole.write(b"A");
        assert_eq!(pPixels[BOOT_STATUS_HEIGHT*pStride+1],FG);
    }

    #[test]
    fn smallDisplaysRemainUsableAndHeaderOffsetCannotOverflow() {
        let mut pPixels=vec![0x12345678;12*18];
        let mut pConsole=unsafe {Console::below_boot_status(
            pPixels.as_mut_ptr(),12,18,12,1)}.unwrap();
        pConsole.write(b"A");
        assert_eq!(pPixels[1],FG);
        assert!(unsafe {Console::below_boot_status(
            pPixels.as_mut_ptr(),12,usize::MAX,12,0)}.is_none());
    }
}
