"""Validate real guest demand-paging, lazy syscall and protection evidence.

This checks a captured COM1 transcript, not a VM's provenance. The guest probes
use the production loader, page-fault path and syscalls, with actual memory
statistics and user-process faults. Synthetic logs belong only in host tests.
"""
import argparse
from pathlib import Path
import re
import sys


class VerificationError(ValueError):
    pass


gHex = r"[0-9a-f]{16}"
gPhase = re.compile(
    rf"AGENTOS DEMAND (BEGIN|IO|CHILD|REAPS|GUARD|NX|RO|FAULT|ENDED) "
    rf"ROOT=({gHex}) CHILD=({gHex}) ADDRESS=({gHex})")
gStats = re.compile(
    rf"AGENTOS DEMAND (BASE|TOUCH) ROOT=({gHex}) RESERVED=({gHex}) "
    rf"RESIDENT=({gHex}) TABLES=({gHex}) META=({gHex}) DEMAND=({gHex}) "
    rf"COPIES=({gHex}) PROMOTES=({gHex})")
gExit = re.compile(rf"AGENTOS USER EXIT PID=({gHex}) CR3=({gHex}) STATUS=({gHex})")
gFault = re.compile(
    rf"AGENTOS USER FAULT PID=({gHex}) PARENT=({gHex}) CR3=({gHex}) "
    rf"VECTOR=({gHex}) ERROR=({gHex}) ADDRESS=({gHex})")
gCheck = re.compile(rf"AGENTOS PROCESS OK APIC=({gHex}) PARENT=({gHex})")
gCowEnd = re.compile(rf"AGENTOS COW ENDED ROOT=({gHex}) CHILD=({gHex})")
gExpected = ("BASE", "TOUCH", "IO", "CHILD", "exit", "REAPS",
             "GUARD", "fault", "FAULT", "NX", "fault", "FAULT",
             "RO", "fault", "FAULT", "ENDED")


def require(aCondition, aMessage):
    if not aCondition:
        raise VerificationError(aMessage)


def verify_absent(text):
    require("AGENTOS DEMAND " not in text, "Historical demand workload present in ordinary boot/session")


def verify_interval(pRoot, pEvents, pSeenPids):
    """Validate lazy statistics, kernel-buffer access and exact protection faults."""
    require(tuple(pKind for pKind, _ in pEvents) == gExpected,
            f"Missing, duplicated or reordered demand event for root {pRoot}")
    pFields = [pData for _, pData in pEvents]
    pBase, pTouch, pIo, pChild, pExit, pReaps = pFields[:6]
    # root, reservations, resident leaves, private tables, metadata,
    # cumulative demand pages, copies, promotions. The first-touch fixture
    # touches four pages; a few code/stack pages may fault during reporting.
    for pStats in (pBase, pTouch):
        require(pStats[0] == pRoot and pStats[1] >= 4096 and
                0 < pStats[2] < 256 and pStats[3] >= 4 and pStats[4] == 1 and
                pStats[2] < pStats[1] and pStats[5] > 0,
                "Statistics do not prove a large mostly-unmaterialized address space")
    pResidentDelta = pTouch[2] - pBase[2]
    pDemandDelta = pTouch[5] - pBase[5]
    require(pBase[1] == pTouch[1] and 4 <= pResidentDelta <= 12 and
            pDemandDelta == pResidentDelta and pTouch[3] >= pBase[3] and
            pTouch[6] >= pBase[6] and pTouch[7] >= pBase[7],
            "First touches did not materialize only the required pages")
    require(pIo == (pRoot, 0, 0), "Lazy syscall probes did not complete")
    pChildPid = pChild[1]
    require(pChild[0] == pRoot and pChild[2] == 0 and pChildPid > 0 and
            pChildPid not in pSeenPids and pExit[0] == pChildPid and
            pExit[1] != 0 and pExit[1] % 4096 == 0 and pExit[2] == 0 and
            pReaps == pChild,
            "Fork did not preserve lazy reservations and isolate resident/COW writes")
    pSeenPids.add(pChildPid)
    for pOffset, pKind, pError in ((6, "GUARD", 4), (9, "NX", 20), (12, "RO", 6)):
        pStart, pFault, pReaped = pFields[pOffset:pOffset + 3]
        pAddress = pStart[2]
        require(pStart[:2] == (pRoot, 0) and pAddress != 0 and
                pFault[0] > 0 and pFault[0] not in pSeenPids and pFault[1] == pRoot and
                pFault[2] != 0 and pFault[2] % 4096 == 0 and
                pFault[3:] == (14, pError, pAddress) and
                pReaped == (pRoot, pFault[0], pAddress),
                f"{pKind} protection did not fault and reap exactly the offending child")
        if pKind == "GUARD":
            require(pAddress == 0x10000000000 - 5 * 4096, "Wrong user stack guard address")
        else:
            require(0x8000000000 <= pAddress < 0x10000000000 - 5 * 4096,
                    "Protection probe address is outside the user image")
        pSeenPids.add(pFault[0])
    require(pFields[-1] == (pRoot, 0, 0), "Demand scenario did not end cleanly")
    children=[(pChildPid,pExit[1],0)]
    for pOffset in (6,9,12):
        pFault=pFields[pOffset+1]
        children.append((pFault[0],pFault[2],270))
    return {"base":list(pBase),"touch":list(pTouch),"children":children,
            "protection_errors":[4,20,6]}


def verify(aText, aCpus):
    require(aCpus in (1, 2), "Expected one or two CPU demand-paging scenarios")
    pCurrent = None
    pPhases, pChecks = [], []
    pCowRoots = []
    for pNumber, pLine in enumerate(aText.splitlines(), 1):
        pMatch = gPhase.fullmatch(pLine)
        if pMatch:
            pName = pMatch[1]
            pFields = tuple(int(pValue, 16) for pValue in pMatch.groups()[1:])
            if pName == "BEGIN":
                require(pCurrent is None and pFields[0] > 0 and pFields[1:] == (0, 0),
                        f"Invalid or nested demand interval at line {pNumber}")
                require(len(pCowRoots) == len(pPhases) + 1 and pCowRoots[-1] == pFields[0],
                        f"Demand interval must follow its COW scenario at line {pNumber}")
                pCurrent = (pFields[0], [])
            else:
                require(pCurrent is not None and pFields[0] == pCurrent[0],
                        f"Demand event outside its owner's interval at line {pNumber}")
                pCurrent[1].append((pName, pFields))
                if pName == "ENDED":
                    pPhases.append(pCurrent)
                    pCurrent = None
            continue
        pMatch = gStats.fullmatch(pLine)
        if pMatch:
            require(pCurrent is not None and int(pMatch[2], 16) == pCurrent[0],
                    f"Memory statistics outside their owner's interval at line {pNumber}")
            pCurrent[1].append((pMatch[1], tuple(int(pValue, 16) for pValue in pMatch.groups()[1:])))
            continue
        require(not pLine.startswith("AGENTOS DEMAND "),
                f"Malformed demand evidence at line {pNumber}")
        if pCurrent is not None:
            for pName, pPattern in (("exit", gExit), ("fault", gFault)):
                pMatch = pPattern.fullmatch(pLine)
                if pMatch:
                    pCurrent[1].append((pName, tuple(int(pValue, 16) for pValue in pMatch.groups())))
                    break
            else:
                require(not pLine.startswith(("AGENTOS USER ", "AGENTOS PROCESS ",
                                              "AGENTOS COW ", "AGENTOS ORPHAN ",
                                              "AGENTOS SUPERVISOR ", "AGENTOS PAGE ",
                                              "AGENTOS MANAGER ")),
                        f"Unexpected process event in demand interval at line {pNumber}")
        else:
            pMatch = gCowEnd.fullmatch(pLine)
            if pMatch:
                pCowRoots.append(int(pMatch[1], 16))
            pMatch = gCheck.fullmatch(pLine)
            if pMatch:
                pChecks.append(tuple(int(pValue, 16) for pValue in pMatch.groups()))

    require(pCurrent is None, "Unterminated demand-paging interval")
    require(len(pPhases) == len(pChecks) == aCpus,
            f"Expected {aCpus} complete demand-paging/CPU scenarios")
    pSeenPids, pSeenCpus = set(), set()
    for pIndex, (pRoot, pEvents) in enumerate(pPhases):
        pCpu, pCheckedRoot = pChecks[pIndex]
        require(pCheckedRoot == pRoot and pCpu not in pSeenCpus and pRoot not in pSeenPids,
                "Demand owner does not match the unique CPU process completion")
        pSeenCpus.add(pCpu)
        pSeenPids.add(pRoot)
        verify_interval(pRoot,pEvents,pSeenPids)
    return len(pPhases)


def main():
    pParser = argparse.ArgumentParser(description=__doc__)
    pParser.add_argument("--log", required=True, type=Path)
    pParser.add_argument("--cpus", type=int, choices=(1, 2), required=True)
    pArgs = pParser.parse_args()
    try:
        pCount = verify(pArgs.log.read_text(encoding="ascii", errors="replace"), pArgs.cpus)
    except (OSError, VerificationError) as pError:
        print(f"Demand paging acceptance failed: {pError}", file=sys.stderr)
        return 1
    print(f"Verified {pCount} real lazy ELF/BSS/syscall/fork/protection scenarios")
    return 0


if __name__ == "__main__":
    sys.exit(main())
