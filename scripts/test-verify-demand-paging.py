"""Negative mutation tests of guest evidence, never substitutes for a VM run."""
import importlib.util
from pathlib import Path
import unittest


gRoot = Path(__file__).resolve().parent


def imported(aName, aAlias):
    pSpec = importlib.util.spec_from_file_location(aAlias, gRoot / aName)
    pModule = importlib.util.module_from_spec(pSpec)
    pSpec.loader.exec_module(pModule)
    return pModule


gDemand = imported("verify-demand-paging.py", "demandVerifier")
gProcess = imported("verify-processes.py", "demandProcessVerifier")
gCow = imported("verify-cow.py", "demandCowVerifier")
gOrphans = imported("verify-orphans.py", "demandOrphanVerifier")
gSupervisor = imported("verify-supervisor.py", "demandSupervisorVerifier")
gFixtures = imported("test-verify-cow.py", "demandFixtures")


def phase(aName, aRoot, aChild=0, aAddress=0):
    return f"AGENTOS DEMAND {aName} ROOT={aRoot:016x} CHILD={aChild:016x} ADDRESS={aAddress:016x}"


def stats(aName, aRoot, aResident, aTables):
    return (f"AGENTOS DEMAND {aName} ROOT={aRoot:016x} RESERVED=0000000000001020 "
            f"RESIDENT={aResident:016x} TABLES={aTables:016x} META=0000000000000001 "
            f"DEMAND={aResident:016x} COPIES=0000000000000001 PROMOTES=0000000000000002")


def block(aRoot):
    pChild = aRoot + 12
    pLines = [phase("BEGIN", aRoot), stats("BASE", aRoot, 32, 5),
              stats("TOUCH", aRoot, 36, 8), phase("IO", aRoot),
              phase("CHILD", aRoot, pChild),
              f"AGENTOS USER EXIT PID={pChild:016x} CR3=0000000000400000 STATUS=0000000000000000",
              phase("REAPS", aRoot, pChild)]
    for pKind, pAddress, pError in (
        ("GUARD", 0x10000000000 - 5 * 4096, 4),
        ("NX", 0x8001200000, 20),
        ("RO", 0x8000420009, 6),
    ):
        pChild += 1
        pLines += [phase(pKind, aRoot, 0, pAddress),
                   f"AGENTOS USER FAULT PID={pChild:016x} PARENT={aRoot:016x} "
                   f"CR3=0000000000400000 VECTOR=000000000000000e ERROR={pError:016x} ADDRESS={pAddress:016x}",
                   phase("FAULT", aRoot, pChild, pAddress)]
    pLines.append(phase("ENDED", aRoot))
    return pLines


def scenario(aRoot=1, aApic=0):
    pLines = gFixtures.scenario(aRoot, aApic).splitlines()
    pIndex = next(pIndex for pIndex, pLine in enumerate(pLines)
                  if pLine.startswith(f"AGENTOS USER EXIT PID={aRoot:016x}"))
    pLines[pIndex:pIndex] = block(aRoot)
    return "\n".join(pLines) + "\n"


class DemandEvidenceTests(unittest.TestCase):
    def rejected(self, aLog, aCpus=1):
        with self.assertRaises(gDemand.VerificationError):
            gDemand.verify(aLog, aCpus)

    def testActualTraceProtocolCoexistsWithAllPriorVerifiers(self):
        for pCpus in (1, 2):
            pLog = scenario() + (scenario(33, 1) if pCpus == 2 else "")
            self.assertEqual(gDemand.verify(pLog, pCpus), pCpus)
            gProcess.verify(pLog, list(range(pCpus)))
            gCow.verify(pLog, pCpus)
            gOrphans.verify(pLog, pCpus)
            gSupervisor.verify_absent(pLog)

    def testMissingAndDuplicatedEvidenceIsRejected(self):
        pLines = scenario().splitlines()
        pFirst = next(pIndex for pIndex, pLine in enumerate(pLines) if pLine.startswith("AGENTOS DEMAND BEGIN"))
        pLast = next(pIndex for pIndex, pLine in enumerate(pLines) if pLine.startswith("AGENTOS DEMAND ENDED"))
        for pIndex in range(pFirst, pLast + 1):
            with self.subTest(missing=pIndex):
                self.rejected("\n".join(pLines[:pIndex] + pLines[pIndex + 1:]))
            with self.subTest(duplicate=pIndex):
                self.rejected("\n".join(pLines[:pIndex] + [pLines[pIndex]] + pLines[pIndex:]))

    def testReorderedAndNestedScenariosAreRejected(self):
        pLines = scenario().splitlines()
        pFirst = next(pIndex for pIndex, pLine in enumerate(pLines) if pLine.startswith("AGENTOS DEMAND BEGIN"))
        pLines[pFirst + 1], pLines[pFirst + 2] = pLines[pFirst + 2], pLines[pFirst + 1]
        self.rejected("\n".join(pLines))
        pLog = scenario()
        self.rejected(pLog.replace(phase("IO", 1), phase("BEGIN", 1), 1))
        self.rejected(pLog.replace(phase("BEGIN", 1), phase("BEGIN", 33), 1))

    def testEagerOrUnmeasuredAllocationsDoNotPass(self):
        pLog = scenario()
        for pBefore, pAfter in (
            ("RESERVED=0000000000001020", "RESERVED=0000000000000020"),
            ("RESIDENT=0000000000000020", "RESIDENT=0000000000001020"),
            ("RESIDENT=0000000000000024", "RESIDENT=0000000000000020"),
            ("RESIDENT=0000000000000024", "RESIDENT=0000000000000100"),
            ("DEMAND=0000000000000024", "DEMAND=0000000000000020"),
            ("TABLES=0000000000000008", "TABLES=0000000000000001"),
            ("META=0000000000000001", "META=0000000000000000"),
        ):
            with self.subTest(field=pBefore):
                self.rejected(pLog.replace(pBefore, pAfter, 1))

    def testWrongProtectionFaultsAndAddressesAreRejected(self):
        pLog = scenario()
        for pBefore, pAfter in (
            ("ERROR=0000000000000014", "ERROR=0000000000000004"),
            ("ERROR=0000000000000006", "ERROR=0000000000000007"),
            ("VECTOR=000000000000000e ERROR=0000000000000014",
             "VECTOR=000000000000000d ERROR=0000000000000014"),
        ):
            with self.subTest(field=pBefore):
                self.assertIn(pBefore, pLog)
                self.rejected(pLog.replace(pBefore, pAfter, 1))
        pGuard = 0x10000000000 - 5 * 4096
        self.rejected(pLog.replace(f"ADDRESS={pGuard:016x}", f"ADDRESS={pGuard + 4096:016x}"))

    def testFailedForkAndForeignOrReusedChildrenAreRejected(self):
        pLog = scenario()
        for pBefore, pAfter in (
            ("AGENTOS USER EXIT PID=000000000000000d CR3=0000000000400000 STATUS=0000000000000000",
             "AGENTOS USER EXIT PID=000000000000000d CR3=0000000000400000 STATUS=0000000000000001"),
            ("DEMAND CHILD ROOT=0000000000000001 CHILD=000000000000000d",
             "DEMAND CHILD ROOT=0000000000000001 CHILD=0000000000000001"),
            ("PID=000000000000000e PARENT=0000000000000001",
             "PID=000000000000000e PARENT=0000000000000002"),
            ("PID=000000000000000f PARENT=0000000000000001",
             "PID=000000000000000e PARENT=0000000000000001"),
            ("DEMAND REAPS ROOT=0000000000000001 CHILD=000000000000000d",
             "DEMAND REAPS ROOT=0000000000000001 CHILD=000000000000000c"),
        ):
            with self.subTest(field=pBefore):
                self.rejected(pLog.replace(pBefore, pAfter, 1))

    def testMissingSecondCpuAndUnexpectedKernelFailuresAreRejected(self):
        self.rejected(scenario(), 2)
        self.rejected(scenario() + scenario(33, 0), 2)
        self.rejected(gFixtures.scenario())
        pLog = scenario()
        self.rejected(pLog.replace("AGENTOS DEMAND IO", "AGENTOS PAGE OOM PID=0000000000000001 ADDRESS=0000008000400000\nAGENTOS DEMAND IO", 1))

    def testProcessVerifierRejectsBrokenDemandBoundaries(self):
        pLog = scenario()
        for pFragment in (phase("BEGIN", 1) + "\n", phase("ENDED", 1) + "\n"):
            with self.subTest(fragment=pFragment):
                with self.assertRaises(gProcess.VerificationError):
                    gProcess.verify(pLog.replace(pFragment, "", 1), [0])


if __name__ == "__main__":
    unittest.main()
