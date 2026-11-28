//! Text ring and exclusive write-only GOP renderer. Producers update RAM;
//! the scheduled display owner paints immutable snapshots outside device gates.
use core::ptr::write_volatile;
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

/// Validated metadata of the interactive region, not a pixel shadow.
#[derive(Clone,Copy)]
pub struct Geometry {
    base:*mut u32, width:usize, height:usize, stride:usize, cols:usize, rows:usize,
}
impl Geometry {
    pub unsafe fn below_boot_status(base:*mut u32,width:usize,height:usize,stride:usize,format:u32)->Option<Self> {
        Self::new(base,width,height,stride,format)?;
        let top=if height>=BOOT_STATUS_HEIGHT+2*H {BOOT_STATUS_HEIGHT} else {0};
        Self::new(base.add(top.checked_mul(stride)?),width,height-top,stride,format)
    }
    pub unsafe fn new(base:*mut u32,width:usize,height:usize,stride:usize,format:u32)->Option<Self> {
        if base.is_null() || (base as usize)%4!=0 || width<W || height<H || stride<width || format>1 {return None;}
        let bytes=stride.checked_mul(height)?.checked_mul(4)?;
        if bytes>isize::MAX as usize {return None;}
        (base as usize).checked_add(bytes)?;
        let g=Self{base,width,height,stride,cols:width/W,rows:height/H};
        g.storage_bytes()?;
        Some(g)
    }
    fn cells(&self)->usize {self.cols*self.rows}
    /// Live ring, immutable snapshot, last presented text; three bytes/cell.
    pub fn storage_bytes(&self)->Option<usize> {
        let bytes=self.cols.checked_mul(self.rows)?.checked_mul(3)?;
        (bytes<=isize::MAX as usize).then_some(bytes)
    }
    fn pixel(&self,x:usize,y:usize,color:u32) {
        // The renderer's sole framebuffer accessor is write-only.
        unsafe{write_volatile(self.base.add(y*self.stride+x),color);}
    }
}

/// Live text, exclusively mutated under the terminal gate.
pub struct Console {
    cells:*mut u8, cols:usize, rows:usize, first:usize, x:usize, y:usize, dirty:bool,
}
/// Exclusive display owner. The snapshot is stable even if preempted while
/// the TTY receives more bytes. None of its buffers contains pixel data.
pub struct Renderer {
    geometry:Geometry, snapshot:*mut u8, presented:*mut u8,
    cursor:Option<usize>, presented_cursor:Option<usize>, initialized:bool,
}
impl Console {
    /// Caller owns mapped GOP and a disjoint, separately owned RAM range for
    /// both objects' lifetimes. Invalid storage never writes to GOP or RAM.
    pub unsafe fn new(g:Geometry,backing:*mut u8,bytes:usize)->Option<(Self,Renderer)> {
        let need=g.storage_bytes()?;
        if backing.is_null() || bytes<need {return None;}
        (backing as usize).checked_add(need)?;
        let n=g.cells();
        core::ptr::write_bytes(backing,b' ',need);
        Some((Self{cells:backing,cols:g.cols,rows:g.rows,first:0,x:0,y:0,dirty:true},
              Renderer{geometry:g,snapshot:backing.add(n),presented:backing.add(2*n),
                cursor:None,presented_cursor:None,initialized:false}))
    }
    fn newline(&mut self) {
        self.x=0;
        if self.y+1==self.rows {
            self.first=(self.first+1)%self.rows;
            let bottom=(self.first+self.rows-1)%self.rows;
            // Recycle exactly one row. No other text or framebuffer moves.
            unsafe{core::ptr::write_bytes(self.cells.add(bottom*self.cols),b' ',self.cols);}
        } else {self.y+=1;}
    }
    fn put(&mut self,b:u8) {
        match b {
            b'\r'=>{self.dirty|=self.x!=0;self.x=0;},
            b'\n'=>{self.dirty=true;self.newline();},
            8=>{if self.x>0{self.x-=1;self.dirty=true;}
                else if self.y>0{self.y-=1;self.x=self.cols-1;self.dirty=true;}},
            b'\t'=>{let n=4-(self.x%4);for _ in 0..n{self.put(b' ');}},
            0x20..=0x7e=>{
                // Deferred wrap preserves the bottom-right glyph.
                if self.x==self.cols{self.newline();}
                let at=((self.first+self.y)%self.rows)*self.cols+self.x;
                unsafe{self.cells.add(at).write(b);}
                self.x+=1;self.dirty=true;
            },
            _=>(),
        }
    }
    pub fn write(&mut self,data:&[u8]) {for &b in data{self.put(b);}}
    pub fn pending(&self)->bool {self.dirty}
    /// Under the producer gate: two ordinary RAM copies at most. Publish a
    /// consistent view, clear dirty atomically with respect to later writers.
    pub fn snapshot(&mut self,r:&mut Renderer)->bool {
        if !self.dirty{return false;}
        assert_eq!((self.cols,self.rows),(r.geometry.cols,r.geometry.rows));
        let n=self.cols*self.rows;
        let offset=self.first*self.cols;
        unsafe {
            core::ptr::copy_nonoverlapping(self.cells.add(offset),r.snapshot,n-offset);
            core::ptr::copy_nonoverlapping(self.cells,r.snapshot.add(n-offset),offset);
        }
        r.cursor=(self.x<self.cols).then_some(self.y*self.cols+self.x);
        self.dirty=false;
        true
    }
    pub fn clear(&mut self) {
        unsafe{core::ptr::write_bytes(self.cells,b' ',self.cols*self.rows);}
        self.first=0;self.x=0;self.y=0;self.dirty=true;
    }
}
impl Renderer {
    /// Once, before publishing the terminal. Preserve boot header and stride.
    pub fn initialize(&mut self) {
        assert!(!self.initialized);
        for y in 0..self.geometry.height{for x in 0..self.geometry.width{self.geometry.pixel(x,y,BG);}}
        self.initialized=true;
    }
    fn color(bits:&[u8;7],dx:usize,dy:usize,cursor:bool)->u32 {
        if cursor && dy==7 && dx<5{BG^FG}
        else if dy<7 && dx<5 && bits[dy]&(16>>dx)!=0{FG}
        else{BG}
    }
    /// Compare only text and cursor state; write only pixels that change.
    /// Finish the whole immutable snapshot before accepting another, so
    /// sustained writers cannot restart or starve a batch. Returns writes.
    pub fn render(&mut self)->usize {
        assert!(self.initialized);
        let mut writes=0;
        for i in 0..self.geometry.cells() {
            let(old,new)=unsafe{(self.presented.add(i).read(),self.snapshot.add(i).read())};
            let oc=self.presented_cursor==Some(i);let nc=self.cursor==Some(i);
            if old==new && oc==nc{continue;}
            let before=glyph(old);let after=glyph(new);
            let x=(i%self.geometry.cols)*W;let y=(i/self.geometry.cols)*H;
            for dy in 0..H{for dx in 0..W{
                let a=Self::color(&before,dx,dy,oc);let b=Self::color(&after,dx,dy,nc);
                if a!=b{self.geometry.pixel(x+dx,y+dy,b);writes+=1;}
            }}
            unsafe{self.presented.add(i).write(new);}
        }
        self.presented_cursor=self.cursor;
        writes
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    struct TestConsole { text:Console,renderer:Renderer,_storage:Vec<u8> }
    impl TestConsole {
        unsafe fn with_geometry(g:Geometry)->Self {
            let mut storage=vec![0xa5;g.storage_bytes().unwrap()];
            let (mut text,mut renderer)=Console::new(g,storage.as_mut_ptr(),storage.len()).unwrap();
            renderer.initialize();assert!(text.snapshot(&mut renderer));renderer.render();
            Self{text,renderer,_storage:storage}
        }
        unsafe fn new(base:*mut u32,w:usize,h:usize,s:usize,f:u32)->Option<Self>{
            Some(Self::with_geometry(Geometry::new(base,w,h,s,f)?))
        }
        unsafe fn below_boot_status(base:*mut u32,w:usize,h:usize,s:usize,f:u32)->Option<Self>{
            Some(Self::with_geometry(Geometry::below_boot_status(base,w,h,s,f)?))
        }
        fn flush(&mut self)->usize{if self.text.snapshot(&mut self.renderer){self.renderer.render()}else{0}}
        fn write(&mut self,b:&[u8]){self.text.write(b);self.flush();}
        fn clear(&mut self){self.text.clear();self.flush();}
    }
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
        assert!(unsafe{TestConsole::new(ptr,0,10,10,0)}.is_none());
        assert!(unsafe{TestConsole::new(ptr,10,10,9,0)}.is_none());
        assert!(unsafe{TestConsole::new(ptr,10,10,10,2)}.is_none());
        assert!(unsafe{TestConsole::new(ptr,10,10,usize::MAX,0)}.is_none());
    }
    #[test]
    fn wrappingScrollingAndBackspaceAreBounded() {
        let width=13;let height=19;let stride=17;
        let mut pixels=vec![0xdeadbeef;7+stride*height+7];
        let ptr=unsafe{pixels.as_mut_ptr().add(7)};
        let mut screen=unsafe{TestConsole::new(ptr,width,height,stride,0)}.unwrap();
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
        let mut console=unsafe{TestConsole::new(buffer.as_mut_ptr(),6,9,6,0)}.unwrap();
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
        let mut scrolling=unsafe{TestConsole::new(a.as_mut_ptr(),12,18,12,1)}.unwrap();
        let mut expected=unsafe{TestConsole::new(b.as_mut_ptr(),12,18,12,1)}.unwrap();
        scrolling.write(b"A\nB\nC");
        expected.write(b"B\nC");
        assert_eq!(a,b);
    }

    #[test]
    fn interactiveScrollingAndClearPreserveBootStatusPixels() {
        let pWidth=42; let pStride=47; let pHeight=BOOT_STATUS_HEIGHT+4*H;
        let mut pPixels=vec![0x12345678; pStride*pHeight+8];
        let pHeader=pPixels[..BOOT_STATUS_HEIGHT*pStride].to_vec();
        let mut pConsole=unsafe {TestConsole::below_boot_status(
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
        let mut pConsole=unsafe {TestConsole::below_boot_status(
            pPixels.as_mut_ptr(),12,18,12,1)}.unwrap();
        pConsole.write(b"A");
        assert_eq!(pPixels[1],FG);
        assert!(unsafe {TestConsole::below_boot_status(
            pPixels.as_mut_ptr(),12,usize::MAX,12,0)}.is_none());
    }

    #[test]
    fn burstCoalescesWhileSnapshotRemainsImmutable() {
        let(w,h,stride)=(1280,800,1283);
        let mut pixels=vec![0xfeedface;stride*h];
        let g=unsafe{Geometry::below_boot_status(pixels.as_mut_ptr(),w,h,stride,0)}.unwrap();
        assert_eq!(g.storage_bytes(),Some(3*213*79));
        let mut screen=unsafe{TestConsole::with_geometry(g)};
        let before=pixels.clone();
        for i in 0..400{screen.text.write(if i%2==0{b"alpha\r\n"}else{b"beta\r\n"});}
        assert_eq!(pixels,before,"producer touched GOP");
        assert!(screen.text.snapshot(&mut screen.renderer));
        screen.text.write(b"new output");
        let writes=screen.renderer.render();
        assert!(writes>0 && writes<=g.cells()*W*H && screen.text.pending());
        let mut expected=vec![0xfeedface;stride*h];
        let mut reference=unsafe{TestConsole::below_boot_status(expected.as_mut_ptr(),w,h,stride,0)}.unwrap();
        for i in 0..400{reference.text.write(if i%2==0{b"alpha\r\n"}else{b"beta\r\n"});}
        reference.flush();assert_eq!(pixels,expected);
        reference.write(b"new output");assert!(screen.flush()>0);assert_eq!(pixels,expected);
        assert_eq!(screen.flush(),0);assert_eq!(screen.renderer.render(),0);
    }
    #[test]
    fn cursorUsesKnownColorsAndUnchangedPixelsAreNotWritten() {
        let(w,h,stride)=(24,18,27);
        let mut pixels=vec![0xdeadbeef;stride*h];
        let mut s=unsafe{TestConsole::new(pixels.as_mut_ptr(),w,h,stride,1)}.unwrap();
        for dx in 0..5{pixels[7*stride+dx]=0xdeadbeef;}
        pixels[2*W+1]=0x12345678;
        s.text.write(b"\rA");let writes=s.flush();
        assert!(writes>0 && writes<=2*W*H);
        for dx in 0..5{assert_eq!(pixels[7*stride+dx],BG);assert_eq!(pixels[7*stride+W+dx],BG^FG);}
        assert_eq!(pixels[2*W+1],0x12345678);
    }
    #[test]
    fn badStorageDoesNotModifyEitherRegion() {
        let mut pixels=vec![0xdeadbeef;60*27];
        let g=unsafe{Geometry::new(pixels.as_mut_ptr(),60,27,60,0)}.unwrap();
        let mut bytes=vec![0xa5;g.storage_bytes().unwrap()-1];
        assert!(unsafe{Console::new(g,bytes.as_mut_ptr(),bytes.len())}.is_none());
        assert!(unsafe{Console::new(g,core::ptr::null_mut(),usize::MAX)}.is_none());
        assert!(pixels.iter().all(|&v|v==0xdeadbeef));assert!(bytes.iter().all(|&v|v==0xa5));
    }
    #[test]
    fn mixedControlsMatchIndependentLinearTextReference() {
        let(w,h,stride)=(37,38,43);
        let mut pixels=vec![0xdeadbeef;stride*h];
        let mut s=unsafe{TestConsole::new(pixels.as_mut_ptr(),w,h,stride,0)}.unwrap();
        let(cols,rows)=(w/W,h/H);
        let mut cells=vec![b' ';cols*rows];let(mut x,mut y)=(0usize,0usize);
        fn newline(c:&mut[u8],cols:usize,rows:usize,x:&mut usize,y:&mut usize) {
            *x=0;if *y+1<rows{*y+=1;}else{c.rotate_left(cols);c[(rows-1)*cols..].fill(b' ');}
        }
        fn put(c:&mut[u8],cols:usize,rows:usize,x:&mut usize,y:&mut usize,b:u8) {
            match b {
                b'\r'=>*x=0,b'\n'=>newline(c,cols,rows,x,y),
                8=>if *x>0{*x-=1;}else if *y>0{*y-=1;*x=cols-1;},
                b'\t'=>{let n=4-(*x%4);for _ in 0..n{put(c,cols,rows,x,y,b' ');}},
                32..=126=>{if *x==cols{newline(c,cols,rows,x,y);}c[*y*cols+*x]=b;*x+=1;},
                _=>(),
            }
        }
        for chunk in [b"abcdef".as_slice(),b"g\nXYZ\tq",b"\x08\x08R\rZ",b"\n\n0123456789",b"\r\t\nA\x07B",b"\x08 \x08",b"123456\n\n\n\n"] {
            for &byte in chunk{put(&mut cells,cols,rows,&mut x,&mut y,byte);s.text.write(&[byte]);}
            s.flush();
            let mut expected=vec![0xdeadbeef;stride*h];
            for py in 0..h{for px in 0..w{expected[py*stride+px]=BG;}}
            for row in 0..rows{for col in 0..cols{
                let bits=glyph(cells[row*cols+col]);
                for dy in 0..H{for dx in 0..W{
                    let color=if x<cols && col==x && row==y && dy==7 && dx<5{BG^FG}
                    else if dy<7 && dx<5 && bits[dy]&(16>>dx)!=0{FG}else{BG};
                    expected[(row*H+dy)*stride+col*W+dx]=color;
                }}
            }}
            assert_eq!(pixels,expected);
        }
    }

    #[test]
    fn fullScreenChangeIsBoundedAndDoesNotRestart() {
        let(w,h)=(1280,800);
        let mut pixels=vec![0u32;w*h];
        let mut s=unsafe{TestConsole::new(pixels.as_mut_ptr(),w,h,w,0)}.unwrap();
        let n=s.renderer.geometry.cells();
        s.text.write(&vec![b'W';n]);assert!(s.flush()>0);
        s.text.write(&vec![b'M';n]);assert!(s.text.snapshot(&mut s.renderer));
        s.text.write(b"\nnew");
        let writes=s.renderer.render();
        assert!(writes>0 && writes<=n*W*H);
        assert!(s.text.pending());assert!(s.flush()>0);assert!(!s.text.pending());
    }

}
