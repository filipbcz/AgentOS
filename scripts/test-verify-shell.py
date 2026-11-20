"""Synthetic transcript tests; these are not evidence of a VirtualBox run."""
import importlib.util
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
pScript = Path(__file__).with_name("verify-shell.py")
pSpec = importlib.util.spec_from_file_location("verifyShell", pScript)
gVerifier = importlib.util.module_from_spec(pSpec)
pSpec.loader.exec_module(gVerifier)


def transcript(aPid=9):
    return (b"AGENTOS KERNEL OK STAGE 1\r\n" +
            f"AGENTOS SHELL START PID={aPid:016x}\r\n".encode("ascii") +
            b"AGENTOS SHELL READY\r\nagentos> help\r\n"
            b"help       List commands\r\npid        Show process ID\r\n"
            b"echo TEXT  Print text\r\ncat PATH   Read an initramfs file\r\n"
            b"exit       Close the shell\r\nagentos> pid\r\n" + str(aPid).encode("ascii") +
            b"\r\nagentos> echo shell-ox\b \bk\r\nshell-ok\r\n"
            b"agentos> cat /stage\r\nAgentOS stage 1\r\n"
            b"agentos> cat /missing\r\ncat: open failed (-2)\r\n"
            b"agentos> no-such-command\r\nerror: unknown command or arguments; use help\r\n"
            b"agentos> exit\r\nAGENTOS SHELL EXIT\r\n" +
            f"AGENTOS USER EXIT PID={aPid:016x} CR3=0000000000700000 STATUS=0000000000000000\r\n"
            f"AGENTOS SHELL STOP PID={aPid:016x} STATUS=0000000000000000 FRAMES=OK\r\n".encode("ascii"))


class ShellEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.pLog = transcript()

    def rejected(self, aLog, aInput=None):
        with self.assertRaises(gVerifier.VerificationError):
            gVerifier.verify(aLog, aInput)

    def test_complete_transcript_and_input(self):
        for pPid in (5, 9, 12345):
            self.assertEqual(gVerifier.verify(transcript(pPid), gVerifier.INPUT), pPid)

    def test_each_required_response_is_needed(self):
        for pResponse in (b"help       List commands\r\n", b"9\r\n", b"shell-ok\r\n",
                          b"AgentOS stage 1\r\n", b"cat: open failed (-2)\r\n",
                          b"error: unknown command or arguments; use help\r\n"):
            with self.subTest(response=pResponse):
                self.rejected(self.pLog.replace(pResponse, b"", 1))

    def test_command_echo_alone_is_insufficient(self):
        self.rejected(self.pLog.replace(b"\r\nshell-ok\r\n", b"\r\n"))
        self.rejected(self.pLog.replace(b"\r\nAgentOS stage 1\r\n", b"\r\ncat /stage\r\n"))

    def test_wrong_identity_and_pid_command(self):
        self.rejected(self.pLog.replace(b"SHELL STOP PID=0000000000000009", b"SHELL STOP PID=0000000000000008"))
        self.rejected(self.pLog.replace(b"USER EXIT PID=0000000000000009", b"USER EXIT PID=0000000000000008"))
        self.rejected(self.pLog.replace(b"pid\r\n9\r\n", b"pid\r\n8\r\n"))
        self.rejected(transcript(0))

    def test_failed_status_or_frame_restore(self):
        self.rejected(self.pLog.replace(b"STATUS=0000000000000000", b"STATUS=0000000000000001", 1))
        self.rejected(self.pLog.replace(b"STATUS=0000000000000000 FRAMES=OK", b"STATUS=0000000000000001 FRAMES=OK"))
        self.rejected(self.pLog.replace(b"FRAMES=OK", b"FRAMES=FAILED"))

    def test_invalid_address_space(self):
        for pRoot in (b"0000000000000000", b"0000000000700001"):
            self.rejected(self.pLog.replace(b"CR3=0000000000700000", b"CR3=" + pRoot))

    def test_backspace_input_and_result(self):
        self.rejected(self.pLog.replace(b"shell-ox\b \bk", b"shell-oxk"))
        self.rejected(self.pLog.replace(b"\r\nshell-ok\r\n", b"\r\nshell-oxk\r\n"))
        self.rejected(self.pLog, gVerifier.INPUT.replace(b"\x08", b""))

    def test_missing_duplicate_malformed_boundaries(self):
        for pLine in self.pLog.splitlines(keepends=True):
            if pLine.startswith((b"AGENTOS SHELL START", b"AGENTOS SHELL STOP")):
                with self.subTest(line=pLine):
                    self.rejected(self.pLog.replace(pLine, b""))
                    self.rejected(self.pLog.replace(pLine, pLine + pLine))
        self.rejected(b"AGENTOS SHELL START PID=bad\r\n" + self.pLog)

    def test_wrong_order_and_extra_records(self):
        self.rejected(self.pLog.replace(b"agentos> pid\r\n9\r\n", b"agentos> cat /stage\r\nAgentOS stage 1\r\n"))
        self.rejected(self.pLog + b"AGENTOS USER EXIT PID=000000000000000a\r\n")
        self.rejected(self.pLog.replace(b"AGENTOS SHELL EXIT\r\n", b"AGENTOS SHELL EXIT\r\nAGENTOS SHELL EXIT\r\n"))

    def test_truncated_output(self):
        for pRemoved in (1, 10, 100, 250):
            self.rejected(self.pLog[:-pRemoved])

    def test_cli_results_and_missing_file(self):
        with tempfile.TemporaryDirectory() as pDir:
            pLog = Path(pDir) / "synthetic shell.log"
            pInput = Path(pDir) / "input.bin"
            pLog.write_bytes(self.pLog)
            pInput.write_bytes(gVerifier.INPUT)
            pCommand = [sys.executable, str(pScript), "--log", str(pLog), "--input", str(pInput)]
            pResult = subprocess.run(pCommand, capture_output=True)
            self.assertEqual(pResult.returncode, 0, pResult.stderr)
            pInput.write_bytes(b"wrong")
            self.assertEqual(subprocess.run(pCommand, capture_output=True).returncode, 1)
            pLog.unlink()
            self.assertEqual(subprocess.run(pCommand, capture_output=True).returncode, 1)


if __name__ == "__main__":
    unittest.main()
