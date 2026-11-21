//! Explicit native ABI discriminator in static ELF64 programs.
//! Only this note selects native syscalls. Unmarked ELF remains reserved for
//! the future Linux compatibility loader, and is currently rejected.
#![allow(non_snake_case)]

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

/// Recognize exactly one AgentOS type-1 note with version 1 and no flags.
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
                    u32At(pDesc,0)? != 1 || u32At(pDesc,4)? != 0 { return None; }
                pFound = true;
            }
            pNotes = pNotes.get(pEnd..)?;
        }
    }
    pFound.then_some(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn put16(aBytes: &mut [u8], aAt: usize, aValue: u16) {
        aBytes[aAt..aAt+2].copy_from_slice(&aValue.to_le_bytes());
    }
    fn put32(aBytes: &mut [u8], aAt: usize, aValue: u32) {
        aBytes[aAt..aAt+4].copy_from_slice(&aValue.to_le_bytes());
    }
    fn put64(aBytes: &mut [u8], aAt: usize, aValue: u64) {
        aBytes[aAt..aAt+8].copy_from_slice(&aValue.to_le_bytes());
    }
    fn nativeNote() -> Vec<u8> {
        let mut pNote=vec![0;28];
        put32(&mut pNote,0,8);put32(&mut pNote,4,8);put32(&mut pNote,8,1);
        pNote[12..20].copy_from_slice(b"AgentOS\0");
        put32(&mut pNote,20,1);
        pNote
    }
    fn image(aNote: &[u8]) -> Vec<u8> {
        let mut pElf=vec![0;120];
        pElf[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
        put16(&mut pElf,16,2);put16(&mut pElf,18,62);put32(&mut pElf,20,1);
        put64(&mut pElf,32,64);put16(&mut pElf,52,64);
        put16(&mut pElf,54,56);put16(&mut pElf,56,1);
        put32(&mut pElf,64,4);put64(&mut pElf,72,120);
        put64(&mut pElf,96,aNote.len() as u64);put64(&mut pElf,112,4);
        pElf.extend_from_slice(aNote);
        pElf
    }

    #[test]
    fn explicitNativeV1AcceptedAndUnmarkedProfileRejected() {
        assert!(validate(&image(&nativeNote())));
        let mut pElf=image(&nativeNote());
        put32(&mut pElf,64,1); // no PT_NOTE remains
        assert!(!validate(&pElf));
        assert!(!validate(&image(&[])));
    }

    #[test]
    fn unsupportedVersionFlagsTypeAndDescriptorSizeRejected() {
        for (pOffset,pValue) in [(20,2),(24,1),(8,2),(4,4),(4,12)] {
            let mut pNote=nativeNote();put32(&mut pNote,pOffset,pValue);
            assert!(!validate(&image(&pNote)));
        }
    }

    #[test]
    fn duplicateDeclarationsInSameOrDifferentSegmentsRejected() {
        let pNote=nativeNote();
        let mut pBoth=pNote.clone();pBoth.extend_from_slice(&pNote);
        assert!(!validate(&image(&pBoth)));
        let mut pElf=image(&pNote);
        pElf.splice(120..120,vec![0;56]);
        put16(&mut pElf,56,2);put64(&mut pElf,72,176);
        let pHeader=pElf[64..120].to_vec();
        pElf[120..176].copy_from_slice(&pHeader);
        // Even identical overlapping note segments are ambiguous declarations.
        assert!(!validate(&pElf));
    }

    #[test]
    fn malformedHeaderAndProgramHeaderRangesRejected() {
        let pValid=image(&nativeNote());
        for pLength in 0..120 { assert!(!validate(&pValid[..pLength])); }
        for (pOffset,pValue) in [(16,3),(18,3),(52,63),(54,55),(56,65535)] {
            let mut pElf=pValid.clone();put16(&mut pElf,pOffset,pValue);
            assert!(!validate(&pElf));
        }
        let mut pElf=pValid.clone();put64(&mut pElf,32,u64::MAX-8);
        assert!(!validate(&pElf));
        pElf[4]=1;
        assert!(!validate(&pElf));
    }

    #[test]
    fn malformedNoteBoundsAndAlignmentRejected() {
        let pValid=image(&nativeNote());
        for (pOffset,pValue) in [(72,u64::MAX),(96,u64::MAX),(112,3),(72,121)] {
            let mut pElf=pValid.clone();put64(&mut pElf,pOffset,pValue);
            assert!(!validate(&pElf));
        }
        for pLength in 0..28 { assert!(!validate(&image(&nativeNote()[..pLength]))); }
        let mut pNote=nativeNote();put32(&mut pNote,0,u32::MAX);
        assert!(!validate(&image(&pNote)));
        let mut pNote=nativeNote();put32(&mut pNote,4,u32::MAX);
        assert!(!validate(&image(&pNote)));
        let mut pNote=nativeNote();pNote[19]=b'x';
        assert!(!validate(&image(&pNote)));
    }

    #[test]
    fn wellFormedForeignNotesUseTheirOwnPadding() {
        // Namesz=3 and descsz=1 both need one independent padding step.
        let mut pForeign=vec![0;20];
        put32(&mut pForeign,0,3);put32(&mut pForeign,4,1);put32(&mut pForeign,8,999);
        pForeign[12..15].copy_from_slice(b"XY\0");pForeign[16]=42;
        assert!(!validate(&image(&pForeign)));
        pForeign.extend_from_slice(&nativeNote());
        assert!(validate(&image(&pForeign)));
        let mut pNativeThenForeign=nativeNote();pNativeThenForeign.extend_from_slice(&pForeign[..20]);
        assert!(validate(&image(&pNativeThenForeign)));
        pNativeThenForeign.pop();
        assert!(!validate(&image(&pNativeThenForeign)));
    }
}
