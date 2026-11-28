"""Synthetic positive and negative BOOT.LOG COM1 policy checks."""
import importlib.util
from pathlib import Path
import unittest


SPEC = importlib.util.spec_from_file_location(
    "boot_log_verifier", Path(__file__).with_name("verify-boot-log.py"))
mod = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(mod)

BOOT = b"AGENTOS KERNEL OK STAGE 1\r\n"
INFO = b"[INFO] KERNEL ENTRY\r\n[INFO] BOOT COMPLETE\r\n"
DEBUG = b"[DEBUG] ACPI TABLES READY\r\n[DEBUG] INITRAMFS LOCATED\r\n"


class BootLogTests(unittest.TestCase):
    def test_valid_all_severity_sink_combinations(self):
        for level in mod.LEVELS:
            for output in mod.SINKS:
                with self.subTest(level=level, output=output):
                    serial = output in ("serial", "both")
                    data = BOOT
                    if serial and level != "quiet":
                        data += INFO
                    if serial and level == "debug":
                        data += DEBUG
                    mod.verify(data, level, output, historical_boot_oom=True)

    def test_missing_raw_marker_is_never_accepted(self):
        for level in mod.LEVELS:
            for sink in mod.SINKS:
                with self.subTest(level=level, sink=sink):
                    with self.assertRaises(mod.VerificationError):
                        mod.verify(INFO + DEBUG, level, sink, historical_boot_oom=True)

    def test_nonserial_sinks_reject_structured_markers(self):
        for sink in ("none", "screen"):
            for line in (INFO, DEBUG, b"[ERROR] FAILED\r\n"):
                with self.subTest(sink=sink, line=line):
                    with self.assertRaises(mod.VerificationError):
                        mod.verify(BOOT + line, "debug", sink, historical_boot_oom=True)

    def test_severity_enforced_and_no_forged_lifecycle(self):
        for level, payload in (
            ("quiet", INFO),
            ("quiet", DEBUG),
            ("info", INFO + DEBUG),
            ("info", b"[INFO] KERNEL ENTRY\r\n"),
            ("debug", INFO),
            ("debug", INFO + b"[DEBUG] ACPI TABLES READY\r\n"),
        ):
            with self.subTest(level=level, payload=payload):
                with self.assertRaises(mod.VerificationError):
                    mod.verify(BOOT + payload, level, "serial", historical_boot_oom=True)

    def test_unrelated_critical_serial_markers_are_allowed(self):
        for level in mod.LEVELS:
            content = BOOT + b"AGENTOS FRAME STRESS BITMAP OK\r\n"
            if level != "quiet":
                content += INFO
            if level == "debug":
                content += DEBUG
            mod.verify(content, level, "serial", historical_boot_oom=True)


if __name__ == "__main__":
    unittest.main()
