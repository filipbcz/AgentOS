"""Synthetic log regression tests, not evidence of an AgentOS VM run."""
import importlib.util
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.dont_write_bytecode = True
SCRIPT = Path(__file__).with_name("verify-processes.py")
SPEC = importlib.util.spec_from_file_location("verify_processes", SCRIPT)
verifier = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(verifier)


def scenario(cpu=0, parent=1):
    # Child roots may be reused after the previous child has been collected.
    return (
        f"AGENTOS USER FAULT PID={parent+1:016x} PARENT={parent:016x} "
        "CR3=0000000000400000 VECTOR=000000000000000e ERROR=0000000000000005 "
        "ADDRESS=0000000002000000\n"
        "AGENTOS USER SURVIVED\n"
        f"AGENTOS PIPE RECEIVED PID={parent+2:016x} BYTES=00002001 FNV32=1490a95f\n"
        f"AGENTOS USER EXIT PID={parent+2:016x} CR3=0000000000400000 STATUS=0000000000000000\n"
        f"AGENTOS PIPE SENT PID={parent:016x} CHILD={parent+2:016x}\n"
        f"AGENTOS IPC SERVICE PID={parent+3:016x} PEER={parent:016x} UID=000003e8 GID=000003e8\n"
        f"AGENTOS USER EXIT PID={parent+3:016x} CR3=0000000000400000 STATUS=0000000000000000\n"
        f"AGENTOS IPC REPLY PID={parent:016x} PEER={parent+3:016x} UID=000003e8 GID=000003e8\n"
        f"AGENTOS USER EXIT PID={parent:016x} CR3=0000000000300000 STATUS=0000000000000000\n"
        f"AGENTOS PROCESS OK APIC={cpu:016x} PARENT={parent:016x}\n"
    )


class ProcessEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.log = scenario()
        self.lines = self.log.splitlines()

    def rejected(self, log, cpus=(0,)):
        with self.assertRaises(verifier.VerificationError):
            verifier.verify(log, cpus)

    def test_one_cpu_and_unrelated_boot_messages(self):
        verifier.verify("AGENTOS STARTING USER PROCESSES\n" + self.log +
                        "AGENTOS IDLE BEGIN TSC-HZ=0000000000000001\n", [0])

    def test_two_cpus_and_crlf(self):
        verifier.verify((scenario(7, 1) + scenario(2, 5)).replace("\n", "\r\n"), [2, 7])

    def test_missing_records(self):
        for index in range(len(self.lines)):
            with self.subTest(index=index):
                self.rejected("\n".join(self.lines[:index] + self.lines[index+1:]))

    def test_duplicate_records(self):
        for index in range(len(self.lines)):
            with self.subTest(index=index):
                self.rejected("\n".join(self.lines[:index] + [self.lines[index]] + self.lines[index:]))

    def test_old_pipe_only_log(self):
        self.rejected("\n".join(self.lines[:5] + self.lines[8:]))

    def test_out_of_order_and_interleaved_cpus(self):
        lines = self.lines.copy()
        lines[6], lines[7] = lines[7], lines[6]
        self.rejected("\n".join(lines))
        other = scenario(1, 5).splitlines()
        self.rejected("\n".join(self.lines[:5] + other[:5] + self.lines[5:] + other[5:]), [0, 1])

    def test_malformed_and_unknown_records(self):
        for extra in ("AGENTOS IPC SERVICE PID=bad", "AGENTOS IPC UNKNOWN", self.lines[5] + " extra"):
            with self.subTest(extra=extra):
                self.rejected(self.log + extra)

    def test_peer_ids_and_credentials(self):
        for index in (5, 7):
            fields = self.lines[index].split()
            for field in fields[3:]:
                key = field.split("=")[0]
                replacement = key + "=" + ("0" * (8 if key in ("UID", "GID") else 16))
                with self.subTest(record=index, field=key):
                    lines = self.lines.copy()
                    lines[index] = lines[index].replace(field, replacement)
                    self.rejected("\n".join(lines))

    def test_nonzero_exit_statuses(self):
        for index in (3, 6, 8):
            with self.subTest(index=index):
                lines = self.lines.copy()
                lines[index] = lines[index].replace("STATUS=0000000000000000", "STATUS=0000000000000001")
                self.rejected("\n".join(lines))

    def test_exit_pid_correspondence(self):
        for index in (3, 6, 8):
            with self.subTest(index=index):
                lines = self.lines.copy()
                lines[index] = lines[index].replace(lines[index].split()[3], "PID=00000000000000ff")
                self.rejected("\n".join(lines))

    def test_private_address_spaces(self):
        self.rejected(self.log.replace("CR3=0000000000400000", "CR3=0000000000300000"))
        self.rejected(self.log.replace("CR3=0000000000400000", "CR3=0000000000000000"))
        self.rejected(self.log.replace("CR3=0000000000300000", "CR3=0000000000000000"))

    def test_wrong_fault_or_pipe_evidence(self):
        replacements = {
            "VECTOR=000000000000000e": "VECTOR=000000000000000d",
            "ERROR=0000000000000005": "ERROR=0000000000000000",
            "ADDRESS=0000000002000000": "ADDRESS=0000000002000001",
            "BYTES=00002001": "BYTES=00002000",
            "FNV32=1490a95f": "FNV32=1490a950",
            "CHILD=0000000000000003": "CHILD=0000000000000004",
        }
        for old, new in replacements.items():
            with self.subTest(field=old):
                self.rejected(self.log.replace(old, new))

    def test_zero_and_reused_pids(self):
        self.rejected(scenario(parent=0))
        self.rejected(self.log.replace("0000000000000004", "0000000000000003"))
        self.rejected(self.log + scenario(1, 1), [0, 1])

    def test_unexpected_missing_duplicate_cpus(self):
        self.rejected(self.log, [1])
        self.rejected(self.log, [0, 1])
        self.rejected(self.log + scenario(0, 5), [0, 1])
        self.rejected(self.log, [0, 0])
        self.rejected(self.log, [])

    def test_extra_process_exit(self):
        self.rejected(self.log + "AGENTOS USER EXIT PID=0000000000000099 "
                      "CR3=0000000000500000 STATUS=0000000000000000\n")

    def test_cli_accepts_multiple_apics_and_propagates_errors(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "synthetic COM1.log"
            command = [sys.executable, str(SCRIPT), "--log", str(path),
                       "--apic-ids", "0000000000000000", "0000000000000001"]
            path.write_text(self.log + scenario(1, 5), encoding="utf-8")
            result = subprocess.run(command, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("2 CPU(s)", result.stdout)
            path.write_text(self.log, encoding="utf-8")
            result = subprocess.run(command, capture_output=True, text=True)
            self.assertEqual(result.returncode, 1)
            self.assertIn("Process verification failed", result.stderr)
            path.unlink()
            result = subprocess.run(command, capture_output=True, text=True)
            self.assertEqual(result.returncode, 1)


if __name__ == "__main__":
    unittest.main()
