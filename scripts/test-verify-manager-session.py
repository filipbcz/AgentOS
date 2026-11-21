"""Tamper tests for real UART COM1 service registry/ordered shutdown receipts."""
import importlib.util
from pathlib import Path
import unittest

spec=importlib.util.spec_from_file_location("manager_session",Path(__file__).with_name("verify-manager-session.py"))
v=importlib.util.module_from_spec(spec)
spec.loader.exec_module(v)

def transcript():
    return (
        b"AGENTOS MANAGER SESSION START PID=0000000000000064\r\n"
        b"AGENTOS SHELL START PID=0000000000000069\r\n"
        b"AGENTOS SHELL READY\r\nagentos> services\r\n"
        b"core: running (attempts=1)\r\n"
        b"flaky: failed (attempts=3)\r\n"
        b"shell: running (attempts=1)\r\n"
        b"agentos> exit\r\nAGENTOS SHELL EXIT\r\n"
        b"AGENTOS USER EXIT PID=0000000000000069 CR3=0000000000700000 STATUS=0000000000000000\r\n"
        b"AGENTOS MANAGER SHUTD ROOT=0000000000000064 COUNT=00000003\r\n"
        b"AGENTOS USER KILL PID=0000000000000065 PARENT=0000000000000064 STATUS=0000000000000089\r\n"
        b"AGENTOS MANAGER ENDED ROOT=0000000000000064 COUNT=00000003\r\n"
        b"AGENTOS USER EXIT PID=0000000000000064 CR3=0000000000710000 STATUS=0000000000000000\r\n"
        b"AGENTOS MANAGER SESSION STOP PID=0000000000000064 STATUS=0000000000000000 FRAMES=OK\r\n"
    )
class SessionEvidenceTests(unittest.TestCase):
    def test_exact_realistic_session(self):
        self.assertEqual(v.verify(transcript()),(100,105,101))

    def test_each_missing_or_duplicate_line_fails(self):
        lines=transcript().splitlines(keepends=True)
        for i in range(len(lines)):
            with self.subTest(index=i):
                altered=b"".join(lines[:i]+lines[i+1:])
                with self.assertRaises(v.VerificationError):v.verify(altered)
                altered=b"".join(lines[:i]+[lines[i],lines[i]]+lines[i+1:])
                with self.assertRaises(v.VerificationError):v.verify(altered)

    def test_wrong_identity_status_or_snapshot_fails(self):
        text=transcript()
        for original,forged in (
            (b"flaky: failed (attempts=3)",b"flaky: running (attempts=3)"),
            (b"core: running (attempts=1)",b"core: failed (attempts=3)"),
            (b"SHELL START PID=0000000000000069",b"SHELL START PID=000000000000006a"),
            (b"USER KILL PID=0000000000000065",b"USER KILL PID=0000000000000069"),
            (b"PARENT=0000000000000064 STATUS=0000000000000089",
             b"PARENT=0000000000000069 STATUS=0000000000000089"),
            (b"FRAMES=OK",b"FRAMES=LEAK"),
            (b"CR3=0000000000700000",b"CR3=0000000000000000"),
            (b"STATUS=0000000000000000 FRAMES=OK",b"STATUS=0000000000000001 FRAMES=OK"),
        ):
            with self.subTest(original=original):
                with self.assertRaises(v.VerificationError):v.verify(text.replace(original,forged,1))
if __name__=="__main__":unittest.main()
