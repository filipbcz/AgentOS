//! Explicit native ABI discriminator in static ELF64 programs.
//! Only this note selects native syscalls. Unmarked ELF remains reserved for
//! the future Linux compatibility loader, and is currently rejected.
#![allow(non_snake_case)]

pub const SYS_SPAWN: usize = 0x10004;
pub const SYS_SPAWN_FLAGS: usize = 0x1001d;
pub const SPAWN_STDIO_ONLY: usize = 1;

/// ABI v2 already exposes a two-argument spawn. Its RDX is unspecified and
/// must never be interpreted as flags: assembly and older binaries can
/// legitimately leave any prior value there. The extended syscall has its
/// own number and validates its flags before touching user memory.
pub fn spawn_flags(op: usize, length: usize, rdx: usize, path_max: usize) -> Result<usize, isize> {
    match op {
        SYS_SPAWN => {
            if length == 0 || length > 64 || length > path_max { Err(-22) }
            else { Ok(0) }
        }
        SYS_SPAWN_FLAGS => {
            if length == 0 || rdx & !SPAWN_STDIO_ONLY != 0 { Err(-22) }
            else if length > path_max { Err(-36) }
            else { Ok(rdx) }
        }
        _ => Err(-38),
    }
}

fn span(aData: &[u8], aStart: usize, aLength: usize) -> Option<&[u8]> {
    aData.get(aStart..aStart.checked_add(aLength)?)
}
fn u16At(aData: &[u8], aAt: usize) -> Option<u16> {
    Some(u16::from_le_bytes(span(aData,aAt,2)?.try_into().ok()?))
}
fn u32At(aData: &[u8], aAt: usize) -> Option<u32> {
    Some(u32::from_le_bytes(span(aData,aAt,4)?.try_into().ok()?))
}
fn sizeAt(aData: &[u8], aAt: usize) -> Option<usize> {
    usize::try_from(u64::from_le_bytes(span(aData,aAt,8)?.try_into().ok()?)).ok()
}
fn padded(aLength: usize) -> Option<usize> { Some(aLength.checked_add(3)? & !3) }

/// Recognize exactly one AgentOS type-1 note with version 2 and no flags.
/// Version 1 used CPU-local clock/deadline semantics and is deliberately
/// rejected before process allocation; it is never silently reinterpreted.
/// Malformed unrelated notes are rejected too, so no truncated/overlapping
/// note stream can hide a duplicate or unsupported native declaration.
pub fn validate(aElf: &[u8]) -> bool { validateInner(aElf) == Some(()) }

fn validateInner(aElf: &[u8]) -> Option<()> {
    if aElf.get(..7)? != b"\x7fELF\x02\x01\x01" ||
       u16At(aElf,16)? != 2 || u16At(aElf,18)? != 62 || u32At(aElf,20)? != 1 ||
       u16At(aElf,52)? != 64 || u16At(aElf,54)? != 56 { return None; }
    let pCount = u16At(aElf,56)? as usize;
    let pHeaders = span(aElf,sizeAt(aElf,32)?,pCount.checked_mul(56)?)?;
    let mut pFound = false;
    for pHeader in pHeaders.chunks_exact(56) {
        match u32At(pHeader,0)? {
            2 | 3 => return None, // no PT_DYNAMIC or PT_INTERP in this profile
            4 => (), // PT_NOTE
            _ => continue,
        }
        let pOffset = sizeAt(pHeader,8)?;
        let pLength = sizeAt(pHeader,32)?;
        let pAlignment = sizeAt(pHeader,48)?;
        if pOffset % 4 != 0 || !matches!(pAlignment,0 | 1 | 4) { return None; }
        let mut pNotes = span(aElf,pOffset,pLength)?;
        while !pNotes.is_empty() {
            let pNameSize = u32At(pNotes,0)? as usize;
            let pDescSize = u32At(pNotes,4)? as usize;
            let pType = u32At(pNotes,8)?;
            let pName = span(pNotes,12,pNameSize)?;
            // A nonempty ELF note owner includes its terminating NUL.
            if !pName.is_empty() && pName.last() != Some(&0) { return None; }
            let pDescAt = 12usize.checked_add(padded(pNameSize)?)?;
            let pDesc = span(pNotes,pDescAt,pDescSize)?;
            let pEnd = pDescAt.checked_add(padded(pDescSize)?)?;
            if pName == b"AgentOS\0" {
                if pFound || pType != 1 || pDescSize != 8 ||
                    u32At(pDesc,0)? != 2 || u32At(pDesc,4)? != 0 { return None; }
                pFound = true;
            }
            pNotes = pNotes.get(pEnd..)?;
        }
    }
    pFound.then_some(())
}

#[cfg(test)]
#[path = "../scripts/tests/native-abi-cases.rs"]
mod tests;
