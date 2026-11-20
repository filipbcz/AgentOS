"""Host behavior tests of the native shell with a mocked syscall boundary.

These run user/shell.c, not the AgentOS kernel, UART, or VirtualBox.
Requires an x86-64 Linux C compiler (CC or gcc) and Python 3, e.g. in WSL.
"""
import json
import os
from pathlib import Path
import shlex
import subprocess
import tempfile
import unittest


class ShellTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.pTemp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.pTemp.cleanup)
        cls.pRoot = Path(__file__).resolve().parent.parent
        cls.pBinary = Path(cls.pTemp.name) / "shell-host"
        cls.pFile = Path(cls.pTemp.name) / "fixture.bin"
        cls.pFile.write_bytes(bytes(range(256)) * 3 + b"end")
        pCompiler = shlex.split(os.environ.get("CC", "gcc"))
        subprocess.run([*pCompiler, "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror",
                        "-ffreestanding", "-fno-stack-protector", "-mno-red-zone",
                        str(cls.pRoot / "scripts/tests/shell-host.c"), "-o", str(cls.pBinary)],
                       check=True)

    def runShell(self, aInput, aRead=64, aWrite=256, aMode="normal", aStatus=0):
        pResult = subprocess.run([str(self.pBinary), str(aRead), str(aWrite), aMode, str(self.pFile)],
                                 input=aInput, capture_output=True, timeout=3)
        self.assertEqual(pResult.returncode, aStatus, pResult.stderr)
        return pResult.stdout, json.loads(pResult.stderr)

    def test_help_pid_echo_and_exit(self):
        pOutput, _ = self.runShell(b"help\npid\necho hello  world  \nexit\necho ignored\n")
        self.assertTrue(pOutput.startswith(b"AGENTOS SHELL READY\r\nagentos> "))
        self.assertIn(b"cat PATH   Read an initramfs file\r\n", pOutput)
        self.assertIn(b"4242\r\n", pOutput)
        self.assertIn(b"hello  world  \r\n", pOutput)
        self.assertNotIn(b"ignored", pOutput)
        self.assertEqual(pOutput.count(b"AGENTOS SHELL EXIT\r\n"), 1)

    def test_fragmented_input_and_partial_output(self):
        pInput = b"echo one\npid\necho two\nexit\n"
        pExpected, _ = self.runShell(pInput)
        for pRead, pWrite in ((1, 1), (3, 2), (17, 7)):
            with self.subTest(read=pRead, write=pWrite):
                pOutput, _ = self.runShell(pInput, pRead, pWrite)
                self.assertEqual(pOutput, pExpected)

    def test_blank_lines_spaces_tabs_and_empty_echo(self):
        pOutput, _ = self.runShell(b"\n  \t\n  echo\tvalue\n echo \n exit \t\n")
        self.assertNotIn(b"error:", pOutput)
        self.assertIn(b"value\r\nagentos> \r\nagentos> ", pOutput)

    def test_unknown_command_and_extra_arguments_recover(self):
        pOutput, _ = self.runShell(b"missing\nexit now\npid x\nhelp x\necho recovered\nexit\n")
        self.assertEqual(pOutput.count(b"error: unknown command or arguments; use help"), 4)
        self.assertIn(b"recovered\r\n", pOutput)

    def test_exact_capacity_and_overlong_command(self):
        pPayload = b"x" * 250
        pOutput, _ = self.runShell(b"echo " + pPayload + b"\necho " + b"y" * 251 + b"\necho recovered\nexit\n", 7)
        self.assertIn(pPayload + b"\r\n", pOutput)
        self.assertNotIn(b"y" * 20, pOutput)
        self.assertEqual(pOutput.count(b"error: command too long"), 1)
        self.assertIn(b"recovered\r\n", pOutput)

    def test_long_line_does_not_execute_truncated_exit(self):
        pOutput, _ = self.runShell(b"exit" + b" " * 3000 + b"\necho recovered\nexit\n", 1)
        self.assertIn(b"error: command too long", pOutput)
        self.assertIn(b"recovered\r\n", pOutput)

    def test_invalid_command_bytes_never_execute_prefix(self):
        for pByte in (b"\0", b"\x01", b"\r", b"\x7f", b"\xff"):
            with self.subTest(byte=pByte):
                pOutput, _ = self.runShell(b"exit" + pByte + b"\necho recovered\nexit\n")
                self.assertIn(b"error: invalid command byte", pOutput)
                self.assertIn(b"recovered\r\n", pOutput)

    def test_eof_and_final_unterminated_line(self):
        pOutput, _ = self.runShell(b"")
        self.assertTrue(pOutput.endswith(b"\r\nAGENTOS SHELL EXIT\r\n"))
        pOutput, _ = self.runShell(b"echo final")
        self.assertIn(b"final\r\n", pOutput)
        self.assertEqual(pOutput.count(b"AGENTOS SHELL EXIT"), 1)
        pOutput, _ = self.runShell(b"echo " + b"x" * 251)
        self.assertIn(b"error: command too long", pOutput)
        self.assertNotIn(b"x" * 20, pOutput)

    def test_cat_binary_data_short_reads_and_writes(self):
        pOutput, pStats = self.runShell(b"cat /fixture\nexit\n", 13, 7)
        self.assertIn(self.pFile.read_bytes(), pOutput)
        self.assertEqual((pStats["opens"], pStats["closes"]), (1, 1))

    def test_cat_usage_and_missing_file(self):
        pOutput, pStats = self.runShell(b"cat\ncat /fixture extra\ncat /missing\ncat /fixture  \nexit\n")
        self.assertEqual(pOutput.count(b"usage: cat PATH"), 2)
        self.assertIn(b"cat: open failed (-2)", pOutput)
        self.assertEqual((pStats["opens"], pStats["closes"]), (1, 1))

    def test_cat_errors_close_descriptor_and_continue(self):
        for pMode, pMessage in (("file-error", b"cat: read failed (-5)"),
                                ("close-error", b"cat: close failed (-5)")):
            with self.subTest(mode=pMode):
                pOutput, pStats = self.runShell(b"cat /fixture\necho recovered\nexit\n", aMode=pMode)
                self.assertIn(pMessage, pOutput)
                self.assertIn(b"recovered\r\n", pOutput)
                self.assertEqual((pStats["opens"], pStats["closes"]), (1, 1))

    def test_cat_output_failure_closes_descriptor(self):
        _, pStats = self.runShell(b"cat /fixture\n", aMode="cat-write-zero", aStatus=2)
        self.assertEqual((pStats["opens"], pStats["closes"]), (1, 1))

    def test_input_error_and_tty_overflow(self):
        pOutput, _ = self.runShell(b"", aMode="input-error", aStatus=1)
        self.assertIn(b"shell: input failed (-5)", pOutput)
        self.assertNotIn(b"AGENTOS SHELL EXIT", pOutput)
        pOutput, _ = self.runShell(b"echo recovered\nexit\n", aMode="input-overflow")
        self.assertIn(b"error: input line too long", pOutput)
        self.assertIn(b"recovered\r\n", pOutput)
        # The TTY can discard the rest of a line whose prefix was already read.
        pOutput, _ = self.runShell(b"exitecho recovered\nexit\n", aRead=4,
                                  aMode="input-overflow-after-prefix")
        self.assertIn(b"error: input line too long", pOutput)
        self.assertIn(b"recovered\r\n", pOutput)
        self.assertNotIn(b"unknown command", pOutput)

    def test_output_zero_or_error_does_not_loop(self):
        for pMode in ("write-zero", "write-error"):
            with self.subTest(mode=pMode):
                pOutput, pStats = self.runShell(b"exit\n", aMode=pMode, aStatus=2)
                self.assertEqual(pOutput, b"")
                self.assertEqual(pStats["writeCalls"], 1)

    def test_pid_error_is_reported_without_ending_shell(self):
        pOutput, _ = self.runShell(b"pid\necho recovered\nexit\n", aMode="pid-error")
        self.assertIn(b"pid: failed (-5)", pOutput)
        self.assertIn(b"recovered\r\n", pOutput)


if __name__ == "__main__":
    unittest.main()
