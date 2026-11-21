"""Validate actual resumed-process migration, shared I/O and deadline evidence.

The signed guest uses ordinary fork/IPC/pipe/file/wait syscalls and the normal
balancer. This verifier accepts interleaving between four distinct workers,
but validates each worker's complete state machine and the parent's reaping.
It does not turn an initial CPU assignment or a synthetic log into a VM run.
"""
import argparse
from pathlib import Path
import re
import sys


class VerificationError(ValueError):
    pass


gHex = r"[0-9a-f]{16}"
gBoundary = re.compile(
    rf"AGENTOS MIGRATION (BEGIN|ENDED) ROOT=({gHex}) CPUS=({gHex}) "
    rf"WORKERS=({gHex}) OBSERVED=({gHex}) MIGRATIONS=({gHex}) WAKEUPS=({gHex}) NOW=({gHex})")
gEvent = re.compile(
    rf"AGENTOS MIGRATION (START|MOVED|IO|SLEEP|DONE) ROOT=({gHex}) CHILD=({gHex}) "
    rf"SLOT=({gHex}) CPU=({gHex}) MOVES=({gHex}) WORK=({gHex}) NOW=({gHex}) UNTIL=({gHex})"
    rf"(?: OFFSET=({gHex}) FNV=({gHex}))?")
gAuth = re.compile(
    rf"AGENTOS MIGRATION AUTH ROOT=({gHex}) CHILD=({gHex}) SLOT=({gHex}) "
    rf"UID=({gHex}) GID=({gHex}) SENDER=({gHex}) READER=({gHex}) FNV=({gHex})")
gReap = re.compile(
    rf"AGENTOS MIGRATION REAP ROOT=({gHex}) CHILD=({gHex}) SLOT=({gHex}) STATUS=({gHex})")
gExit = re.compile(rf"AGENTOS USER EXIT PID=({gHex}) CR3=({gHex}) STATUS=({gHex})")
gSession = re.compile(rf"AGENTOS MANAGER SESSION START PID=({gHex})")
gPark = re.compile(rf"AGENTOS USER PARK PID=({gHex}) CR3=({gHex}) STATUS=0000000000000000")
gManager = re.compile(rf"AGENTOS MANAGER BEGIN ROOT=({gHex}) COUNT=00000003")
gCpu = re.compile(rf"AGENTOS TASK (?:BSP|AP) APIC=({gHex}) TIMER-WAKES=0000000000000003")


def require(aCondition, aMessage):
    if not aCondition:
        raise VerificationError(aMessage)


def expectedDigest(aOffset):
    pDigest = 2166136261
    for pPosition in range(aOffset, aOffset + 16):
        pDigest = ((pDigest ^ ((pPosition * 73 + pPosition // 251 * 19) & 255)) * 16777619) & 0xffffffff
    return pDigest


def verify(aText, aCpus=None):
    pLines = aText.splitlines()
    pMarkers = [(pIndex, gBoundary.fullmatch(pLine)) for pIndex, pLine in enumerate(pLines)
                if pLine.startswith(("AGENTOS MIGRATION BEGIN", "AGENTOS MIGRATION ENDED"))]
    require(len(pMarkers) == 2 and all(pMatch for _, pMatch in pMarkers) and
            pMarkers[0][1][1] == "BEGIN" and pMarkers[1][1][1] == "ENDED",
            "Expected exactly one complete migration interval")
    (pBeginAt, pBegin), (pEndAt, pEnd) = pMarkers
    pRoot, pCount, pWorkers, pObserved, pMoves, pWakeups, pStartTime = (
        int(pValue, 16) for pValue in pBegin.groups()[1:])
    if aCpus is None:
        aCpus = pCount
    require(aCpus in (1, 2) and pCount == aCpus and pRoot == 1 and
            pWorkers == 4 and pObserved == 0 and pBeginAt < pEndAt and pStartTime <= 0x7fffffffffffffff,
            "Invalid migration root, CPU count, worker count or baseline")
    pSessions = [(pIndex, gSession.fullmatch(pLine)) for pIndex, pLine in enumerate(pLines)
                 if pLine.startswith("AGENTOS MANAGER SESSION START")]
    require(len(pSessions) == 1 and pSessions[0][1] is not None and
            int(pSessions[0][1][1], 16) == pRoot and pSessions[0][0] < pBeginAt,
            "Migration must follow resumption of the original manager root")
    pParks = [(pIndex, gPark.fullmatch(pLine)) for pIndex, pLine in enumerate(pLines[:pBeginAt])
              if pLine.startswith("AGENTOS USER PARK")]
    require(len(pParks) == 1 and pParks[0][1] is not None and
            int(pParks[0][1][1], 16) == pRoot and int(pParks[0][1][2], 16) > 0 and
            int(pParks[0][1][2], 16) % 4096 == 0 and pParks[0][0] < pSessions[0][0],
            "Migration root was not retained from the boot acceptance session")
    pManagers = [(pIndex, gManager.fullmatch(pLine)) for pIndex, pLine in enumerate(pLines)
                 if pLine.startswith("AGENTOS MANAGER BEGIN")]
    require(len(pManagers) == 1 and pManagers[0][1] is not None and
            int(pManagers[0][1][1], 16) == pRoot and pManagers[0][0] > pEndAt,
            "Service manager must begin only after migration acceptance")
    pKnownCpus = {int(pMatch[1], 16) for pLine in pLines
                  if (pMatch := gCpu.fullmatch(pLine))}
    require(not pKnownCpus or len(pKnownCpus) == aCpus, "Boot CPU evidence disagrees with migration")
    pPriorPids = {int(pMatch[1], 16) for pLine in pLines[:pBeginAt]
                  if (pMatch := re.match(rf"AGENTOS USER (?:EXIT|FAULT|KILL) PID=({gHex})", pLine))}
    pStates, pPids = {}, set()
    pMoveEvents = 0
    pIoOrder, pAuthOrder, pReapOrder = [], [], []
    for pIndex, pLine in enumerate(pLines):
        if not pBeginAt < pIndex < pEndAt:
            require(not pLine.startswith("AGENTOS MIGRATION") or pIndex in (pBeginAt, pEndAt),
                    f"Migration record outside its complete interval at line {pIndex + 1}")
            continue
        pMatch = gEvent.fullmatch(pLine)
        if pMatch:
            pKind = pMatch[1]
            pOwner, pChild, pSlot, pCpuId, pTaskMoves, pWork, pNow, pUntil = (
                int(pValue, 16) for pValue in pMatch.groups()[1:9])
            require(pOwner == pRoot and 0 <= pSlot < pWorkers and pChild > pRoot and
                    0 <= pCpuId < 255 and (not pKnownCpus or pCpuId in pKnownCpus) and
                    pWork > 0 and pStartTime <= pNow <= 0x7fffffffffffffff and
                    pStartTime < pUntil <= 0x7fffffffffffffff,
                    f"Invalid worker identity, CPU, work or time at line {pIndex + 1}")
            require((pKind == "IO") == (pMatch[10] is not None and pMatch[11] is not None),
                    "Only I/O records carry offset and digest fields")
            if pKind == "START":
                require(pSlot not in pStates and pChild not in pPids and pChild not in pPriorPids and
                        pUntil - pNow == 5000 and pWork == 1,
                        "Duplicate/reused worker or missing pre-migration absolute deadline")
                pStates[pSlot] = {"pid": pChild, "cpu": pCpuId, "moves": pTaskMoves,
                    "startMoves": pTaskMoves, "work": pWork, "now": pNow, "until": pUntil,
                    "phase": "running", "observed": 0, "auth": False}
                pPids.add(pChild)
                continue
            require(pSlot in pStates, "Worker event precedes its START")
            pState = pStates[pSlot]
            require(pState["pid"] == pChild and pUntil == pState["until"] and
                    pTaskMoves >= pState["moves"] and pWork >= pState["work"] and pNow >= pState["now"] and
                    pState["phase"] not in ("done", "exited", "reaped"),
                    "Migration changed identity/deadline, lost work/time, or continued after completion")
            if pKind == "MOVED":
                require(aCpus == 2 and pCpuId != pState["cpu"] and
                        pTaskMoves > pState["moves"] and pWork > pState["work"] and pNow > pState["now"],
                        "A migration must change CPU after prior execution and advance work/time/counter")
                pState["observed"] += 1
                pMoveEvents += 1
            else:
                require(pCpuId == pState["cpu"], "CPU changed without a MOVED continuation record")
                if pKind == "IO":
                    pOffset, pDigest = int(pMatch[10], 16), int(pMatch[11], 16)
                    require(pState["phase"] == "running" and pOffset == 16 * (pSlot + 1) and
                            pDigest == expectedDigest(pOffset) and pNow < pUntil,
                            "Shared file offset, lazy/COW I/O content or phase is wrong")
                    pState["phase"] = "io"
                    pState["digest"] = pDigest
                    pIoOrder.append(pSlot)
                elif pKind == "SLEEP":
                    require(pState["phase"] == "io" and pState["auth"] and 0 < pUntil - pNow <= 250,
                            "Original pre-migration deadline was already expired or not used for blocking")
                    pState["phase"] = "sleep"
                elif pKind == "DONE":
                    require(pState["phase"] == "sleep" and pNow >= pUntil,
                            "Worker completed before authenticated I/O or its original deadline")
                    pState["phase"] = "done"
            pState.update(cpu=pCpuId, moves=pTaskMoves, work=pWork, now=pNow)
            continue
        pMatch = gAuth.fullmatch(pLine)
        if pMatch:
            pOwner, pChild, pSlot, pUid, pGid, pSender, pReader, pDigest = (
                int(pValue, 16) for pValue in pMatch.groups())
            require(pSlot in pStates and pOwner == pRoot, "Foreign authenticated reply")
            pState = pStates[pSlot]
            require(pChild == pState["pid"] and pState["phase"] == "io" and not pState["auth"] and
                    pUid == pGid == 1000 and pSender == pState["cpu"] and
                    0 <= pReader < 255 and (not pKnownCpus or pReader in pKnownCpus) and
                    pDigest == pState["digest"], "IPC identity, CPU or payload contradicts the worker I/O")
            pState["auth"] = True
            pAuthOrder.append(pSlot)
            continue
        pMatch = gExit.fullmatch(pLine)
        if pMatch:
            pChild, pRootPage, pStatus = (int(pValue, 16) for pValue in pMatch.groups())
            pSlots = [pSlot for pSlot, pState in pStates.items() if pState["pid"] == pChild]
            require(len(pSlots) == 1 and pRootPage > 0 and pRootPage % 4096 == 0 and pStatus == 0,
                    "Unknown worker, invalid CR3 or failed process exit")
            pState = pStates[pSlots[0]]
            require(pState["phase"] == "done" and len(pStates) == pWorkers and
                    all(pValue["phase"] in ("done", "exited", "reaped") for pValue in pStates.values()),
                    "Worker exited before successful completion or twice")
            pState["phase"] = "exited"
            continue
        pMatch = gReap.fullmatch(pLine)
        if pMatch:
            pOwner, pChild, pSlot, pStatus = (int(pValue, 16) for pValue in pMatch.groups())
            require(pOwner == pRoot and pSlot in pStates and pStatus == 0 and
                    pStates[pSlot]["pid"] == pChild and pStates[pSlot]["phase"] == "exited",
                    "Parent did not reap exactly the actually exited worker")
            pStates[pSlot]["phase"] = "reaped"
            pReapOrder.append(pSlot)
            continue
        require(not pLine.startswith("AGENTOS "),
                f"Unexpected or malformed kernel/guest event in migration interval at line {pIndex + 1}")
    pEndRoot, pEndCpus, pEndWorkers, pEndObserved, pEndMoves, pEndWakes, pEndTime = (
        int(pValue, 16) for pValue in pEnd.groups()[1:])
    require(pEndRoot == pRoot and pEndCpus == aCpus and pEndWorkers == pWorkers and
            pEndObserved == pMoveEvents and set(pStates) == set(range(pWorkers)) and
            all(pState["phase"] == "reaped" for pState in pStates.values()) and
            pIoOrder == pAuthOrder == pReapOrder == list(range(pWorkers)) and
            pEndTime >= max(pState["now"] for pState in pStates.values()) and
            pEndTime - pStartTime < 15000 and pEndMoves - pMoves >=
            sum(pState["moves"] for pState in pStates.values()) and pEndWakes >= pWakeups,
            "Migration interval did not finish all workers, I/O, deadlines and reaping consistently")
    if aCpus == 1:
        require(pMoveEvents == pEndMoves == pMoves == pEndWakes == pWakeups == 0 and
                all(pState["moves"] == pState["startMoves"] == 0 for pState in pStates.values()),
                "Single-CPU run claims impossible migrations")
    else:
        require(pMoveEvents >= 2 and pEndMoves - pMoves >= pMoveEvents and pEndWakes > pWakeups,
                "Two-CPU run lacks repeated actual migration and cross-CPU wakeups")
    return {"root": pRoot, "cpus": aCpus, "workers": pWorkers, "observed_moves": pMoveEvents,
            "migrations": pEndMoves - pMoves, "cross_cpu_wakeups": pEndWakes - pWakeups,
            "begin_line": pBeginAt, "end_line": pEndAt}


def main():
    pParser = argparse.ArgumentParser(description=__doc__)
    pParser.add_argument("--log", type=Path, required=True)
    pParser.add_argument("--cpus", type=int, choices=(1, 2), required=True)
    pArgs = pParser.parse_args()
    try:
        pResult = verify(pArgs.log.read_text(encoding="ascii", errors="replace"), pArgs.cpus)
    except (VerificationError, OSError) as pError:
        print(f"Migration acceptance failed: {pError}", file=sys.stderr)
        return 1
    print(f"Verified {pResult['workers']} workers, {pResult['observed_moves']} actual CPU continuations, "
          "shared I/O, authenticated IPC, original deadlines and reaping")
    return 0


if __name__ == "__main__":
    sys.exit(main())
