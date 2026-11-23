"""Negative mutation checks for fork/COW evidence and strict IPC coexistence."""
import importlib.util
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parent
def imported(path,alias):
    spec=importlib.util.spec_from_file_location(alias,ROOT/path)
    obj=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(obj)
    return obj

cow=imported("verify-cow.py","cow_verifier")
processes=imported("verify-processes.py","ipc_verifier")
orphans=imported("verify-orphans.py","orphan_verifier")
supervisor=imported("verify-supervisor.py","supervisor_verifier")
fixtures=imported("test-verify-orphans.py","orphan_fixtures")


def block(root):
    child=root+11
    return [
        f"AGENTOS COW BEGIN ROOT={root:016x} CHILD=0000000000000000",
        f"AGENTOS COW CHILD ROOT={root:016x} CHILD={child:016x}",
        f"AGENTOS USER EXIT PID={child:016x} CR3=0000000000400000 STATUS=0000000000000000",
        f"AGENTOS COW REAPS ROOT={root:016x} CHILD={child:016x}",
        f"AGENTOS COW ENDED ROOT={root:016x} CHILD={child:016x}",
    ]


def scenario(root=1,apic=0):
    prior=fixtures.scenario(root,apic).splitlines()
    index=next(i for i,v in enumerate(prior) if v.startswith(f"AGENTOS USER EXIT PID={root:016x}"))
    prior[index:index]=block(root)
    return "\n".join(prior)+"\n"


class CowEvidenceTests(unittest.TestCase):
    def test_one_and_two_cpu_pass_all_original_strict_verifiers(self):
        log=scenario()
        self.assertEqual(cow.verify(log,1),1)
        processes.verify(log,[0])
        orphans.verify(log,1)
        supervisor.verify(log,1)
        log=scenario(1,0)+scenario(25,1)
        self.assertEqual(cow.verify(log,2),2)
        processes.verify(log,[0,1])
        orphans.verify(log,2)
        supervisor.verify(log,2)

    def rejected(self,log):
        with self.assertRaises(cow.VerificationError):
            cow.verify(log,1)

    def test_missing_reordered_duplicated_events_fail(self):
        original=scenario().splitlines()
        first=next(i for i,line in enumerate(original) if line.startswith("AGENTOS COW BEGIN"))
        last=next(i for i,line in enumerate(original) if line.startswith("AGENTOS COW ENDED"))
        for i in range(first,last+1):
            with self.subTest(removed=i):
                self.rejected("\n".join(original[:i]+original[i+1:]))
        bad=original.copy()
        bad[first+1],bad[first+2]=bad[first+2],bad[first+1]
        self.rejected("\n".join(bad))
        self.rejected("\n".join(original[:last]+[original[first+1]]+original[last:]))

    def test_wrong_owner_identity_status_and_address_space_fail(self):
        log=scenario()
        for before,after in (
            ("COW BEGIN ROOT=0000000000000001","COW BEGIN ROOT=0000000000000002"),
            ("COW CHILD ROOT=0000000000000001","COW CHILD ROOT=0000000000000002"),
            ("COW CHILD ROOT=0000000000000001 CHILD=000000000000000c",
             "COW CHILD ROOT=0000000000000001 CHILD=0000000000000000"),
            ("AGENTOS COW REAPS ROOT=0000000000000001 CHILD=000000000000000c",
             "AGENTOS COW REAPS ROOT=0000000000000001 CHILD=000000000000000b"),
            ("AGENTOS COW ENDED ROOT=0000000000000001 CHILD=000000000000000c",
             "AGENTOS COW ENDED ROOT=0000000000000002 CHILD=000000000000000c"),
            ("AGENTOS USER EXIT PID=000000000000000c CR3=0000000000400000 STATUS=0000000000000000",
             "AGENTOS USER EXIT PID=000000000000000c CR3=0000000000400000 STATUS=0000000000000001"),
            ("AGENTOS USER EXIT PID=000000000000000c CR3=0000000000400000 STATUS=0000000000000000",
             "AGENTOS USER EXIT PID=000000000000000c CR3=0000000000000000 STATUS=0000000000000000"),
        ):
            with self.subTest(before=before):
                self.rejected(log.replace(before,after,1))

    def test_reject_missing_second_cpu_and_unauthorized_extra_child(self):
        self.rejected(fixtures.scenario())
        with self.assertRaises(cow.VerificationError):
            cow.verify(scenario(),2)
        log=scenario()
        insertion="AGENTOS USER EXIT PID=00000000000000ac CR3=0000000000400000 STATUS=0000000000000000\n"
        self.rejected(log.replace("AGENTOS COW CHILD",insertion+"AGENTOS COW CHILD",1))

    def test_parent_verifier_rejects_unclosed_or_wrong_order(self):
        log=scenario()
        for fragment in (
            "AGENTOS COW BEGIN ROOT=0000000000000001 CHILD=0000000000000000\n",
            "AGENTOS COW ENDED ROOT=0000000000000001 CHILD=000000000000000c\n",
        ):
            with self.subTest(fragment=fragment):
                with self.assertRaises(processes.VerificationError):
                    processes.verify(log.replace(fragment,""),[0])


if __name__=="__main__":
    unittest.main()
