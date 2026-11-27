"""Protocol mutation tests; generated fixtures are never guest-run evidence."""
import importlib.util
from pathlib import Path
import unittest
import re


def imported(aFile, aName):
    pSpec = importlib.util.spec_from_file_location(aName, Path(__file__).with_name(aFile))
    pModule = importlib.util.module_from_spec(pSpec)
    pSpec.loader.exec_module(pModule)
    return pModule


gMigration = imported("verify-migration.py", "migrationEvidence")
gManagerFixture = imported("test-verify-service-manager.py", "migrationManagerFixture")


def boundary(aName, aCpus, aObserved, aMoves, aWakes, aNow):
    return (f"AGENTOS MIGRATION {aName} ROOT=0000000000000001 CPUS={aCpus:016x} "
            f"WORKERS=0000000000000004 OBSERVED={aObserved:016x} MIGRATIONS={aMoves:016x} "
            f"WAKEUPS={aWakes:016x} NOW={aNow:016x}")


def event(aName, aSlot, aCpu, aMoves, aWork, aNow):
    pLine = (f"AGENTOS MIGRATION {aName} ROOT=0000000000000001 CHILD={70 + aSlot:016x} "
             f"SLOT={aSlot:016x} CPU={aCpu:016x} MOVES={aMoves:016x} WORK={aWork:016x} "
             f"NOW={aNow:016x} UNTIL={6000 + aSlot * 10:016x}")
    if aName == "IO":
        pOffset = 16 * (aSlot + 1)
        pLine += f" OFFSET={pOffset:016x} FNV={gMigration.expectedDigest(pOffset):016x}"
    return pLine


def killProof(aKind, aCpus, aNow):
    pTotal = 3 if aCpus == 2 else 0
    pOwner = 1 if aCpus == 2 else 0
    pLine = (f"AGENTOS MIGRATION {aKind} ROOT=0000000000000001 CHILD=0000000000000047 "
             f"SLOT=0000000000000001 CPU=0000000000000000 OWNER={pOwner:016x} TOTAL={pTotal:016x} "
             f"NOW={aNow:016x} UNTIL={11041:016x}")
    return pLine + (" STATUS=0000000000000089" if aKind == "COLLECT" else "")


def block(aCpus=2):
    pMoved = 2 if aCpus == 2 else 0
    pLines = [boundary("BEGIN", aCpus, 0, 0, 0, 990)]
    for pSlot in range(4):
        pLines.append(event("START", pSlot, pSlot % aCpus, 0, 1, 1000 + pSlot * 10))
    if aCpus == 2:
        pLines += [event("MOVED", 0, 1, 1, 100, 1100), event("MOVED", 0, 0, 2, 200, 1200)]
    for pSlot in range(4):
        pCpu = pSlot % aCpus
        pDigest = gMigration.expectedDigest(16 * (pSlot + 1))
        pLines += [event("IO", pSlot, pCpu, pMoved if pSlot == 0 else 0, 1000, 1300 + pSlot * 10),
            f"AGENTOS MIGRATION AUTH ROOT=0000000000000001 CHILD={70 + pSlot:016x} "
            f"SLOT={pSlot:016x} UID=00000000000003e8 GID=00000000000003e8 "
            f"SENDER={pCpu:016x} READER=0000000000000000 FNV={pDigest:016x}"]
    for pSlot in range(4):
        pLines.append(event("SLEEP", pSlot, pSlot % aCpus, pMoved if pSlot == 0 else 0,
                            2000, 5800 + pSlot * 10))
    for pSlot in range(4):
        pLines.append(event("DONE", pSlot, pSlot % aCpus, pMoved if pSlot == 0 else 0,
                            3000, 6001 + pSlot * 10))
    pLines += [event("ARMED", 1, 1 % aCpus, 0, 3001, 6040) +
               f" TOTAL={pMoved + (1 if aCpus == 2 else 0):016x}",
               killProof("KILL", aCpus, 6041),
               "AGENTOS USER KILL PID=0000000000000047 PARENT=0000000000000001 STATUS=0000000000000089",
               killProof("COLLECT", aCpus, 6042)]
    for pSlot in (2, 0, 3):
        pLines.append(f"AGENTOS USER EXIT PID={70 + pSlot:016x} CR3={0x400000 + pSlot * 4096:016x} "
                      "STATUS=0000000000000000")
    for pSlot in range(4):
        pLines.append(f"AGENTOS MIGRATION REAP ROOT=0000000000000001 CHILD={70 + pSlot:016x} "
                      f"SLOT={pSlot:016x} STATUS={137 if pSlot == 1 else 0:016x}")
    pLines.append(boundary("ENDED", aCpus, pMoved, pMoved + (1 if aCpus == 2 else 0),
                           12 if aCpus == 2 else 0, 6050))
    return pLines


def foreground(apics=(7,19), root=200, shell=9):
    """Synthetic host mutation fixture; never a VM receipt."""
    records=[]
    for record in block(len(apics)):
        record=record.replace("ROOT=0000000000000001",f"ROOT={root:016x}")
        record=record.replace("PARENT=0000000000000001",f"PARENT={root:016x}")
        record=re.sub(r"\b(CHILD|PID)=([0-9a-f]{16})",
                      lambda m:f"{m[1]}={root+1+int(m[2],16)-70:016x}",record)
        record=re.sub(r"\b(CPU|OWNER|SENDER|READER)=([0-9a-f]{16})",
                      lambda m:f"{m[1]}={apics[int(m[2],16)]:016x}",record)
        record=re.sub(r"CR3=([0-9a-f]{16})",
                      lambda m:f"CR3={int(m[1],16)+0x300000:016x}",record)
        if record.startswith("AGENTOS MIGRATION REAP"):
            record+=" AGAIN=fffffffffffffff6"
        records.append(record)
    def owner(kind):
        return (f"AGENTOS MIGRATION {kind} ROOT={root:016x} PARENT={shell:016x} "
                f"CPU={apics[0]:016x} FDS=0000000000000007 CHILD_AFTER=fffffffffffffff6")
    records=[owner("OWNER"),*records,owner("CLEAN"),
             f"AGENTOS USER EXIT PID={root:016x} CR3=0000000000600000 STATUS=0000000000000000",
             "exit status 0"]
    return ("\r\n".join(records)+"\r\nagentos> ").encode("ascii")


def scenario(aCpus=2):
    pLines = gManagerFixture.transcript().splitlines()
    pAt = next(pIndex for pIndex, pLine in enumerate(pLines) if pLine.startswith("AGENTOS MANAGER BEGIN"))
    pLines[pAt:pAt] = block(aCpus)
    pCpus = [f"AGENTOS TASK {'BSP' if pIndex == 0 else 'AP'} APIC={pIndex:016x} "
             "TIMER-WAKES=0000000000000003" for pIndex in range(aCpus)]
    return "\r\n".join(pCpus + pLines) + "\r\n"


class MigrationEvidenceTests(unittest.TestCase):
    def rejected(self, aLog, aCpus=2):
        with self.assertRaises(gMigration.VerificationError):
            gMigration.verify(aLog, aCpus)

    def testCompleteOneAndTwoCpuScenariosCoexistWithServiceManager(self):
        pManager = imported("verify-service-manager.py", "migrationServiceVerifier")
        for pCpus in (1, 2):
            pLog = scenario(pCpus)
            pResult = gMigration.verify(pLog, pCpus)
            self.assertEqual(pResult["workers"], 4)
            self.assertEqual(pResult["observed_moves"], 2 if pCpus == 2 else 0)
            self.assertEqual(pResult["work_observed_moves"], 2 if pCpus == 2 else 0)
            self.assertEqual(pResult["killed_pid"], 71)
            self.assertEqual(pResult["remote_kill"], pCpus == 2)
            self.assertEqual(pResult["kill_owner_cpu"], 1 if pCpus == 2 else 0)
            self.assertEqual(pManager.verify(pLog), (1, 105))

    def testForegroundIdentityRosterExitAndActualTransitions(self):
        for apics in ((7,), (7,19)):
            data=foreground(apics)
            n,result,pids=gMigration.verify_foreground(data,9,0x300000,{1,9},set(apics))
            self.assertEqual(n,len(data))
            self.assertEqual(result["parent"],9)
            self.assertEqual(result["cr3"],0x600000)
            self.assertEqual(pids,set(range(200,205)))
            self.assertEqual(result["worker_apics"],list(apics))
            self.assertEqual(result["work_observed_moves"],2 if len(apics)==2 else 0)
            for old,new in ((b"PARENT=0000000000000009",b"PARENT=0000000000000001"),
                            (b"CPU=0000000000000007",b"CPU=0000000000000008"),
                            (b"AGAIN=fffffffffffffff6",b"AGAIN=0000000000000000"),
                            (b"FDS=0000000000000007",b"FDS=000000000000000f"),
                            (b"CR3=0000000000600000",b"CR3=0000000000300000"),
                            (b"exit status 0",b"exit status 137"),
                            (b"AGENTOS MIGRATION ENDED",b"AGENTOS MIGRATION LOST"),
                            (b"STATUS=0000000000000089",b"STATUS=0000000000000000")):
                with self.subTest(old=old),self.assertRaises(gMigration.VerificationError):
                    gMigration.verify_foreground(data.replace(old,new,1),9,0x300000,{1,9},set(apics))
            with self.assertRaises(gMigration.VerificationError):
                gMigration.verify_foreground(data,9,0x300000,{1,9,201},set(apics))
        bad=foreground().replace(b"MOVED",b"ARMED",1)
        with self.assertRaises(gMigration.VerificationError):
            gMigration.verify_foreground(bad,9,0x300000,{1,9},{7,19})
        with self.assertRaises(gMigration.VerificationError):
            gMigration.verify(foreground().decode("ascii"),2)

    def testEveryProtocolRecordIsRequiredAndDuplicatesAreRejected(self):
        pLines = scenario().splitlines()
        pBegin = next(pIndex for pIndex, pLine in enumerate(pLines) if pLine.startswith("AGENTOS MIGRATION BEGIN"))
        pEnd = next(pIndex for pIndex, pLine in enumerate(pLines) if pLine.startswith("AGENTOS MIGRATION ENDED"))
        for pIndex in range(pBegin, pEnd + 1):
            with self.subTest(missing=pIndex):
                self.rejected("\n".join(pLines[:pIndex] + pLines[pIndex + 1:]))
            with self.subTest(duplicate=pIndex):
                self.rejected("\n".join(pLines[:pIndex] + [pLines[pIndex]] + pLines[pIndex:]))

    def testPlacementWithoutContinuationAndMissingRepeatedMigrationFail(self):
        pLog = scenario()
        for pBefore, pAfter in (
            ("CPU=0000000000000001 MOVES=0000000000000001", "CPU=0000000000000000 MOVES=0000000000000001"),
            ("CPU=0000000000000001 MOVES=0000000000000001", "CPU=0000000000000001 MOVES=0000000000000000"),
            ("MOVES=0000000000000001 WORK=0000000000000064", "MOVES=0000000000000001 WORK=0000000000000001"),
            ("WORK=0000000000000064 NOW=000000000000044c", "WORK=0000000000000064 NOW=00000000000003e8"),
        ):
            with self.subTest(mutation=pBefore):
                self.assertIn(pBefore, pLog)
                self.rejected(pLog.replace(pBefore, pAfter, 1))
        self.rejected(scenario(1).replace("CPUS=0000000000000001", "CPUS=0000000000000002"))
        self.rejected(scenario(), 1)

    def testPidCpuAndDeadlineChangesCannotHideInInterleaving(self):
        pLog = scenario()
        pMove = event("MOVED", 0, 1, 1, 100, 1100)
        for pAltered in (
            pMove.replace("CHILD=0000000000000046", "CHILD=0000000000000047"),
            pMove.replace("ROOT=0000000000000001", "ROOT=0000000000000002"),
            pMove.replace("CPU=0000000000000001", "CPU=0000000000000003"),
            pMove.replace("UNTIL=0000000000001770", "UNTIL=0000000000001771"),
        ):
            self.rejected(pLog.replace(pMove, pAltered))

    def testUnverifiedOrAlreadyExpiredSleepIsRejected(self):
        pLog = scenario()
        pSleep = event("SLEEP", 0, 0, 2, 2000, 5800)
        self.rejected(pLog.replace(pSleep, event("SLEEP", 0, 0, 2, 2000, 6000)))
        self.rejected(pLog.replace(pSleep, event("SLEEP", 0, 0, 2, 2000, 5500)))
        pDone = event("DONE", 0, 0, 2, 3000, 6001)
        self.rejected(pLog.replace(pDone, event("DONE", 0, 0, 2, 3000, 5999)))

    def testFileOffsetContentAndAuthenticatedIdentityAreMandatory(self):
        pLog = scenario()
        for pBefore, pAfter in (
            ("OFFSET=0000000000000010", "OFFSET=0000000000000020"),
            (f"FNV={gMigration.expectedDigest(16):016x}", "FNV=0000000000000000"),
            ("UID=00000000000003e8", "UID=0000000000000000"),
            ("GID=00000000000003e8", "GID=0000000000000000"),
            ("SENDER=0000000000000000", "SENDER=0000000000000001"),
        ):
            with self.subTest(mutation=pBefore):
                self.rejected(pLog.replace(pBefore, pAfter, 1))

    def testWrongExitsReapingAndAggregateCountersAreRejected(self):
        pLog = scenario()
        for pBefore, pAfter in (
            ("CR3=0000000000400000 STATUS=0000000000000000", "CR3=0000000000400000 STATUS=0000000000000001"),
            ("CR3=0000000000400000", "CR3=0000000000000000"),
            ("WORKERS=0000000000000004 OBSERVED=0000000000000002", "WORKERS=0000000000000004 OBSERVED=0000000000000003"),
            ("MIGRATIONS=0000000000000003", "MIGRATIONS=0000000000000001"),
            ("WAKEUPS=000000000000000c", "WAKEUPS=0000000000000000"),
        ):
            with self.subTest(mutation=pBefore):
                self.rejected(pLog.replace(pBefore, pAfter, 1))

    def testUnexpectedKernelFailureAndBoundaryMovementAreNotIgnored(self):
        pLog = scenario()
        pBegin = block()[0]
        self.rejected(pLog.replace(pBegin, pBegin + "\nAGENTOS PAGE OOM PID=0000000000000046"))
        self.rejected(pLog.replace(pBegin, pBegin + "\nAGENTOS MIGRATION FAILED ROOT=0000000000000001"))
        self.rejected(pLog.replace(pBegin, pBegin + "\n" + pBegin))
        self.rejected(pLog + event("MOVED", 0, 1, 3, 4000, 7000))
        self.rejected(pLog.replace("AGENTOS MANAGER SESSION START PID=0000000000000001", ""))
        self.rejected(pLog.replace("AGENTOS USER PARK PID=0000000000000001", "AGENTOS USER PARK PID=0000000000000002"))

    def testRemoteKillRequiresFreshOwnerAndUnchangedGlobalCounterThroughCollection(self):
        pLog = scenario()
        pKill = killProof("KILL", 2, 6041)
        pCollected = killProof("COLLECT", 2, 6042)
        for pBefore,pAfter in (
            (pKill,pKill.replace("OWNER=0000000000000001","OWNER=0000000000000000")),
            (pKill,pKill.replace("CPU=0000000000000000","CPU=0000000000000001")),
            (pKill,pKill.replace("TOTAL=0000000000000003","TOTAL=0000000000000004")),
            (pCollected,pCollected.replace("TOTAL=0000000000000003","TOTAL=0000000000000004")),
            (pCollected,pCollected.replace("CPU=0000000000000000","CPU=0000000000000001")),
            (pCollected,pCollected.replace("STATUS=0000000000000089","STATUS=0000000000000000")),
            (pCollected,pCollected.replace(f"NOW={6042:016x}",f"NOW={11042:016x}")),
            (pCollected,pCollected.replace(f"UNTIL={11041:016x}",f"UNTIL={11042:016x}")),
            ("USER KILL PID=0000000000000047","USER KILL PID=0000000000000046"),
            ("CHILD=0000000000000047 SLOT=0000000000000001 STATUS=0000000000000089",
             "CHILD=0000000000000047 SLOT=0000000000000001 STATUS=0000000000000000"),
        ):
            with self.subTest(mutation=pAfter):
                self.rejected(pLog.replace(pBefore,pAfter,1))
        pFakeExit = "AGENTOS USER EXIT PID=0000000000000047 CR3=0000000000401000 STATUS=0000000000000089"
        self.rejected(pLog.replace(pCollected,pFakeExit))

    def testArmRefreshMayMoveButCannotReplaceOriginalWorkloadMigrations(self):
        pLog = scenario()
        pArm = event("ARMED", 1, 1, 0, 3001, 6040) + " TOTAL=0000000000000003"
        pRefresh = (event("MOVED", 0, 1, 3, 3001, 6035) + "\r\n" +
                    event("ARMED", 0, 1, 3, 3002, 6036) + " TOTAL=0000000000000003\r\n")
        pChanged = pLog.replace(pArm,pRefresh+pArm).replace(
            "WORKERS=0000000000000004 OBSERVED=0000000000000002",
            "WORKERS=0000000000000004 OBSERVED=0000000000000003")
        pResult = gMigration.verify(pChanged,2)
        self.assertEqual(pResult["observed_moves"],3)
        self.assertEqual(pResult["work_observed_moves"],2)
        pEarlyMove = event("MOVED", 0, 0, 2, 200, 1200)
        # Keep every identity/CPU/counter transition valid while moving one
        # of the two continuations past DONE. ARM work must not replace the
        # original asymmetric-load acceptance criterion.
        pOnlyOneEarly = pLog.replace(pEarlyMove+"\r\n", "")
        for pKind,pWork,pNow in (("IO",1000,1300),("SLEEP",2000,5800),("DONE",3000,6001)):
            pOnlyOneEarly = pOnlyOneEarly.replace(event(pKind,0,0,2,pWork,pNow),
                                                 event(pKind,0,1,1,pWork,pNow))
        pAuth = next(pLine for pLine in pLog.splitlines()
                     if pLine.startswith("AGENTOS MIGRATION AUTH ROOT=0000000000000001 CHILD=0000000000000046"))
        pOnlyOneEarly = pOnlyOneEarly.replace(pAuth,pAuth.replace("SENDER=0000000000000000",
                                                                "SENDER=0000000000000001"))
        pLateMove = (event("MOVED",0,0,2,3001,6035)+"\r\n"+
                     event("ARMED",0,0,2,3002,6036)+" TOTAL=0000000000000003\r\n")
        pOnlyOneEarly = pOnlyOneEarly.replace(pArm,pLateMove+pArm)
        with self.assertRaisesRegex(gMigration.VerificationError,"Two-CPU run lacks repeated actual migration"):
            gMigration.verify(pOnlyOneEarly,2)

    def testServiceVerifierCannotSkipAnIncompleteMigrationInterval(self):
        pManager = imported("verify-service-manager.py", "brokenMigrationManager")
        pLog = scenario()
        pEnd = block()[-1]
        with self.assertRaises(pManager.VerificationError):
            pManager.verify(pLog.replace(pEnd, ""))


if __name__ == "__main__":
    unittest.main()
