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
    put32(&mut pNote,20,2);
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
fn explicitNativeV2AcceptedAndUnmarkedProfileRejected() {
    assert!(validate(&image(&nativeNote())));
    let mut pElf=image(&nativeNote());
    put32(&mut pElf,64,1); // no PT_NOTE remains
    assert!(!validate(&pElf));
    assert!(!validate(&image(&[])));
}

#[test]
fn unsupportedVersionFlagsTypeAndDescriptorSizeRejected() {
    for (pOffset,pValue) in [(20,0),(20,1),(20,3),(24,1),(8,2),(4,4),(4,12)] {
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


#[test]
fn legacySpawnIgnoresUnspecifiedThirdRegister() {
    for rdx in [0,1,2,8,usize::MAX] {
        assert_eq!(spawn_flags(SYS_SPAWN,5,rdx,128),Ok(0));
        assert_eq!(spawn_flags(SYS_SPAWN,64,rdx,128),Ok(0));
        assert_eq!(spawn_flags(SYS_SPAWN,0,rdx,128),Err(-22));
        assert_eq!(spawn_flags(SYS_SPAWN,65,rdx,128),Err(-22));
    }
}

#[test]
fn extendedSpawnValidatesFlagsAndPathBeforeCopy() {
    assert_eq!(spawn_flags(SYS_SPAWN_FLAGS,128,0,128),Ok(0));
    assert_eq!(spawn_flags(SYS_SPAWN_FLAGS,128,SPAWN_STDIO_ONLY,128),Ok(1));
    assert_eq!(spawn_flags(SYS_SPAWN_FLAGS,129,0,128),Err(-36));
    for flags in [2,3,usize::MAX] {
        assert_eq!(spawn_flags(SYS_SPAWN_FLAGS,5,flags,128),Err(-22));
    }
    assert_eq!(spawn_flags(SYS_SPAWN_FLAGS,0,0,128),Err(-22));
    assert_eq!(spawn_flags(SYS_SPAWN_FLAGS,usize::MAX,1,128),Err(-36));
    assert_eq!(spawn_flags(usize::MAX,5,0,128),Err(-38));
}
