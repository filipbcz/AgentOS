//! Two cold boots, each explicitly selected by the host after device discovery.
use crate::{block::{BlockDevice, Error}, hpet, pci::Console};
use core::fmt::Write;

pub unsafe fn run(disk: &mut impl BlockDevice) -> Result<(), Error> {
    let geo = disk.geometry();
    if geo.blocks != 16384 || geo.block_size != 512 { return Err(b"wrong block fixture geometry"); }
    let mut header = [0; 512];
    disk.read_blocks(2048, &mut header)?;
    if &header[..16] != b"AgentOS-VDI-test" { return Err(b"missing dedicated disk signature"); }
    let mut expected = [0; 4608];
    for (i, byte) in expected.iter_mut().enumerate() {
        *byte = header[16 + i % 256] ^ (i / 256) as u8;
    }
    let lba = geo.blocks - 9;
    let mut actual = [0; 4608];
    if disk.read_blocks(u64::MAX, &mut header).is_ok() { return Err(b"block range overflow accepted"); }
    let _ = writeln!(Console, "AGENTOS BLOCK READY BLOCKS={} SIZE={}\r", geo.blocks, geo.block_size);
    let start = hpet::millis().ok_or(b"block clock" as Error)?;
    let mode = loop {
        if crate::input(crate::COM + 5) & 1 != 0 { break crate::input(crate::COM); }
        if hpet::millis().ok_or(b"block clock" as Error)? - start >= 30000 { return Err(b"missing block phase"); }
        core::hint::spin_loop();
    };
    disk.read_blocks(lba, &mut actual)?;
    let digest = |data: &[u8]| data.iter().fold(2166136261u32, |h,b| (h ^ u32::from(*b)).wrapping_mul(16777619));
    match mode {
        b'W' => {
            if actual.iter().any(|&b| b != 0) { return Err(b"block target already populated"); }
            // Validate the whole range before sending even its first sector.
            if disk.write_blocks(geo.blocks - 1, &expected).is_ok() ||
                disk.write_blocks(lba, &expected[..511]).is_ok() { return Err(b"invalid block write accepted"); }
            disk.write_blocks(lba, &expected)?;
            let _ = writeln!(Console, "AGENTOS BLOCK WRITE LBA={lba} BYTES=4608 FNV={:08x}\r", digest(&expected));
            disk.flush()?;
            let _ = writeln!(Console, "AGENTOS BLOCK FLUSH OK\r");
        }
        b'R' => {
            if actual != expected { return Err(b"block readback differs after restart"); }
            let _ = writeln!(Console, "AGENTOS BLOCK READ LBA={lba} BYTES=4608 FNV={:08x}\r", digest(&actual));
        }
        _ => return Err(b"invalid block phase"),
    }
    Ok(())
}
