"""Mutation tests for real COM1 orphan adoption and legacy verifier coexistence."""
from pathlib import Path
import importlib.util
import unittest


ROOT = Path(__file__).resolve().parent

def imported(path, module):
    spec=importlib.util.spec_from_file_location(module, ROOT/path)
    obj=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(obj)
    return obj

orphans=imported("verify-orphans.py","orphan_verifier")
processes=imported("verify-processes.py","process_verifier")
supervisor=imported("verify-supervisor.py","supervisor_verifier")
fixtures=imported("test-verify-processes.py","process_fixtures")


def orphan_interval(root):
    parent=root+9
    child=root+10
    return [
        f"AGENTOS ORPHAN BEGIN ROOT={root:016x}",
        f"AGENTOS USER EXIT PID={parent:016x} CR3=0000000000400000 STATUS=0000000000000000",
        f"AGENTOS ORPHAN ADOPT ROOT={root:016x} PARENT={parent:016x} CHILD={child:016x} STATUS=0000000000000000",
        f"AGENTOS USER KILL PID={child:016x} PARENT={root:016x} STATUS=0000000000000089",
        f"AGENTOS ORPHAN REAPS ROOT={root:016x} PARENT={parent:016x} CHILD={child:016x} STATUS=0000000000000089",
        f"AGENTOS ORPHAN ENDED ROOT={root:016x}",
    ]


def scenario(root=1, apic=0):
    baseline=fixtures.scenario(apic,root).splitlines()
    root_exit=f"AGENTOS USER EXIT PID={root:016x}"
    index=next(i for i,line in enumerate(baseline) if line.startswith(root_exit))
    baseline[index:index]=orphan_interval(root)
    return "\n".join(baseline)+"\n"


class OrphanEvidenceTests(unittest.TestCase):
    def test_one_and_two_cpu_are_consistent_without_boot_supervisor(self):
        log=scenario()
        self.assertEqual(orphans.verify(log,1),1)
        supervisor.verify_absent(log)
        processes.verify(log,[0])
        log=scenario(1,0)+scenario(20,1)
        self.assertEqual(orphans.verify(log,2),2)
        supervisor.verify_absent(log)
        processes.verify(log,[0,1])

    def rejects(self, log):
        with self.assertRaises(orphans.VerificationError):
            orphans.verify(log,1)

    def test_every_required_line_and_order_is_checked(self):
        lines=scenario().splitlines()
        first=next(i for i,line in enumerate(lines) if line.startswith("AGENTOS ORPHAN BEGIN"))
        last=next(i for i,line in enumerate(lines) if line.startswith("AGENTOS ORPHAN ENDED"))
        for i in range(first,last+1):
            with self.subTest(missing=i):
                self.rejects("\n".join(lines[:i]+lines[i+1:]))
        swapped=lines[:]
        swapped[first+2],swapped[first+3]=swapped[first+3],swapped[first+2]
        self.rejects("\n".join(swapped))
        self.rejects("\n".join(lines[:last]+[lines[first+2]]+lines[last:]))

    def test_adoption_identity_authorization_and_exit_status_are_strict(self):
        log=scenario()
        for old,new in (
            ("ORPHAN BEGIN ROOT=0000000000000001","ORPHAN BEGIN ROOT=0000000000000002"),
            ("ORPHAN ADOPT ROOT=0000000000000001","ORPHAN ADOPT ROOT=0000000000000002"),
            ("PARENT=000000000000000a CHILD=000000000000000b","PARENT=0000000000000008 CHILD=000000000000000b"),
            ("CHILD=000000000000000b STATUS=0000000000000089","CHILD=000000000000000c STATUS=0000000000000089"),
            ("AGENTOS ORPHAN REAPS ROOT=0000000000000001 PARENT=000000000000000a CHILD=000000000000000b STATUS=0000000000000089",
             "AGENTOS ORPHAN REAPS ROOT=0000000000000001 PARENT=000000000000000a CHILD=000000000000000b STATUS=0000000000000088"),
            ("AGENTOS ORPHAN REAPS","AGENTOS ORPHAN ADOPT"),
            ("AGENTOS USER KILL PID=000000000000000b PARENT=0000000000000001",
             "AGENTOS USER KILL PID=000000000000000b PARENT=000000000000000a"),
            ("AGENTOS USER EXIT PID=000000000000000a CR3=0000000000400000 STATUS=0000000000000000",
             "AGENTOS USER EXIT PID=000000000000000a CR3=0000000000400000 STATUS=0000000000000001"),
        ):
            with self.subTest(old=old):
                self.rejects(log.replace(old,new,1))

    def test_missing_orphan_second_cpu_and_unterminated_phase_rejected(self):
        self.rejects(fixtures.scenario())
        self.rejects(scenario().replace("AGENTOS ORPHAN ENDED ROOT=0000000000000001",""))
        with self.assertRaises(orphans.VerificationError):
            orphans.verify(scenario(),2)
        with self.assertRaises(orphans.VerificationError):
            orphans.verify(scenario()+fixtures.scenario(1,20),2)

    def test_orphan_must_follow_its_actual_authenticated_ipc_root(self):
        log=scenario()
        begin="AGENTOS ORPHAN BEGIN ROOT=0000000000000001"
        for bad in (log.replace(begin,"AGENTOS ORPHAN BEGIN ROOT=0000000000000002"),
                    log.replace(begin,begin+"\n"+begin)):
            with self.assertRaises(processes.VerificationError):
                processes.verify(bad,[0])
        lines=log.splitlines()
        index=next(i for i,line in enumerate(lines) if line==begin)
        lines[index-1],lines[index]=lines[index],lines[index-1]
        with self.assertRaises(processes.VerificationError):
            processes.verify("\n".join(lines),[0])

    def test_legacy_verifier_rejects_broken_orphan_boundaries(self):
        log=scenario()
        processes.verify(log,[0])
        for line in ("AGENTOS ORPHAN BEGIN ROOT=0000000000000001",
                     "AGENTOS ORPHAN ENDED ROOT=0000000000000001"):
            with self.subTest(line=line):
                with self.assertRaises(processes.VerificationError):
                    processes.verify(log.replace(line,""),[0])


if __name__=="__main__":
    unittest.main()
