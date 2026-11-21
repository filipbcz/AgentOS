"""Tamper tests for persistent registry boot receipts, not fake VM evidence."""
import importlib.util
from pathlib import Path
import unittest

spec=importlib.util.spec_from_file_location("svc_verify",Path(__file__).with_name("verify-service-manager.py"))
v=importlib.util.module_from_spec(spec)
spec.loader.exec_module(v)

def transcript():
    root=1
    lines=[
        f"AGENTOS USER PARK PID={root:016x} CR3=0000000000700000 STATUS=0000000000000000",
        f"AGENTOS MANAGER SESSION START PID={root:016x}",
        f"AGENTOS MANAGER BEGIN ROOT={root:016x} COUNT=00000003",
        f"AGENTOS MANAGER START ROOT={root:016x} SERVICE=core  PID={101:016x} ATTEMPT=00000001",
        f"AGENTOS MANAGER READY ROOT={root:016x} SERVICE=core  PID={101:016x} ATTEMPT=00000001",
    ]
    for attempt,pid in ((1,102),(2,103),(3,104)):
        lines+= [
            f"AGENTOS MANAGER START ROOT={root:016x} SERVICE=flaky PID={pid:016x} ATTEMPT={attempt:08x}",
            f"AGENTOS MANAGER READY ROOT={root:016x} SERVICE=flaky PID={pid:016x} ATTEMPT={attempt:08x}",
            f"AGENTOS USER EXIT PID={pid:016x} CR3=0000000000700000 STATUS=000000000000002a",
            f"AGENTOS MANAGER {'RETRY' if attempt<3 else 'LIMIT'} ROOT={root:016x} SERVICE=flaky PID=0000000000000000 ATTEMPT={attempt:08x}",
        ]
    lines +=[
        f"AGENTOS MANAGER ONLIN ROOT={root:016x} COUNT=00000003",
        f"AGENTOS MANAGER START ROOT={root:016x} SERVICE=shell PID={105:016x} ATTEMPT=00000001",
        f"AGENTOS SHELL START PID={105:016x}",
        "AGENTOS SHELL READY",
        "agentos> ",
    ]
    return "\r\n".join(lines)+"\r\n"

class ManagerEvidenceTests(unittest.TestCase):
    def test_good_registry_dependency_crash_budget_and_shell(self):
        self.assertEqual(v.verify(transcript()),(1,105))

    def rejected(self,s):
        with self.assertRaises(v.VerificationError):v.verify(s)

    def test_every_critical_record_required(self):
        lines=transcript().splitlines()
        for i in range(len(lines)-1):
            with self.subTest(missing=i):
                self.rejected("\r\n".join(lines[:i]+lines[i+1:]))

    def test_reordered_boot_dependency_and_restart_attempts_fail(self):
        lines=transcript().splitlines()
        for a,b in ((2,3),(3,4),(6,7),(10,11),(14,15),(16,17)):
            with self.subTest(swapped=(a,b)):
                altered=lines[:]
                altered[a],altered[b]=altered[b],altered[a]
                self.rejected("\r\n".join(altered))
        self.rejected(transcript().replace("ATTEMPT=00000003","ATTEMPT=00000004",1))

    def test_wrong_identity_and_exit_status_are_rejected(self):
        sample=transcript()
        for old,new in (
            ("AGENTOS USER PARK PID=0000000000000001","AGENTOS USER PARK PID=0000000000000002"),
            ("ROOT=0000000000000001","ROOT=0000000000000002"),
            ("SERVICE=core ","SERVICE=coreX"),
            ("SERVICE=flaky PID=0000000000000066","SERVICE=flaky PID=0000000000000065"),
            ("STATUS=000000000000002a","STATUS=0000000000000000"),
            ("CR3=0000000000700000","CR3=0000000000000000"),
            ("SHELL START PID=0000000000000069","SHELL START PID=0000000000000068"),
        ):
            with self.subTest(old=old):
                self.rejected(sample.replace(old,new,1))

    def test_duplicate_session_or_shell_and_missing_ready_rejected(self):
        sample=transcript()
        self.rejected(sample+sample)
        self.rejected(sample.replace("AGENTOS SHELL READY","AGENTOS SHELL GO"))
        self.rejected(sample.replace("AGENTOS MANAGER ONLIN","AGENTOS MANAGER BOGUS"))


if __name__=="__main__":unittest.main()
