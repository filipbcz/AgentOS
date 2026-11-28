"""Synthetic verifier fixtures only: real OOM results come from the Rust runner."""
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
import physical_oom_evidence as oom


def load(name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(name))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


boot = load("verify-boot-log.py")
smp = load("test-verify-basic-smp.py")
VALID_LOG = ("\nrunning 4 tests\n" +
             "".join("test " + name + " ... ok\n" for name in sorted(oom.TESTS)) +
             "\ntest result: ok. 4 passed; 0 failed; 0 ignored; 0 measured; 10 filtered out; finished in 0.01s\n").encode("ascii")
BOOT_LOG = b"AGENTOS KERNEL OK STAGE 1\r\n[INFO] KERNEL ENTRY\r\n[INFO] BOOT COMPLETE\r\n"


class PhysicalOomEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="synthetic-oom-verifier-")
        self.addCleanup(self.temp.cleanup)
        self.folder = Path(self.temp.name)
        self.root = oom.ROOT
        self.commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=self.root, text=True).strip()
        self.tree = oom.source_tree(self.root, self.commit)
        self.record = {"schema": 1, "contract": oom.CONTRACT, "result": "pass",
                       "source_commit": self.commit, "source_tree": self.tree,
                       "host_system": "Linux", "host_arch": "x86_64",
                       "host_workers": [1, 2, 4, 8], "exit_status": 0,
                       "rustc_version": "rustc 1.75.0 synthetic fixture",
                       "source_sha256": oom.source_hashes(self.root)}
        self.write_log(VALID_LOG)

    def write_record(self):
        (self.folder/oom.RECEIPT).write_text(json.dumps(self.record), encoding="utf-8")

    def write_log(self, log):
        (self.folder/oom.LOG).write_bytes(log)
        self.record["test_log_sha256"] = oom.sha(self.folder/oom.LOG)
        self.write_record()

    def verify(self):
        return oom.verify(self.root, self.folder, self.commit)

    def test_current_receipt_and_boot_require_both_proofs(self):
        proof = self.verify()
        self.assertEqual(proof["source_tree"], self.tree)
        self.assertEqual(proof["host_workers"], [1, 2, 4, 8])
        boot.verify(BOOT_LOG, "info", "both", physical_oom_dir=self.folder, source_commit=self.commit)
        with self.assertRaises(ValueError):
            boot.verify(BOOT_LOG, "info", "both")
        with self.assertRaises(ValueError):
            boot.verify(BOOT_LOG, "info", "both", physical_oom_dir=self.folder)
        with self.assertRaises(ValueError):
            boot.verify(BOOT_LOG + oom.MARKER + b"\r\n", "info", "both",
                        physical_oom_dir=self.folder, source_commit=self.commit)
        with self.assertRaises(ValueError):
            boot.verify(BOOT_LOG, "info", "both", physical_oom_dir=self.folder,
                        source_commit=self.commit, historical_boot_oom=True)
        boot.verify(BOOT_LOG + oom.MARKER + b"\r\n", "info", "both", historical_boot_oom=True)
        for name in (oom.LOG, oom.RECEIPT):
            path = self.folder/name
            saved = path.read_bytes()
            path.unlink()
            with self.assertRaises(OSError):
                self.verify()
            path.write_bytes(saved)

    def test_stale_or_inconsistent_receipt_rejected(self):
        for key, value in (("source_commit", "0"*40), ("source_tree", "0"*40),
                           ("source_sha256", {}), ("contract", "guest-cpu"),
                           ("host_workers", [1, 2, 4]), ("host_system", "Windows"),
                           ("host_arch", "aarch64"), ("result", "fail"),
                           ("exit_status", 1), ("test_log_sha256", "0"*64)):
            with self.subTest(key=key):
                original = self.record[key]
                self.record[key] = value
                self.write_record()
                with self.assertRaises(ValueError):
                    self.verify()
                self.record[key] = original
                self.write_record()

    def test_rehashed_missing_duplicate_or_failed_worker_rejected(self):
        lines = VALID_LOG.splitlines(keepends=True)
        tests = [line for line in lines if line.startswith(b"test frames::")]
        for invalid in (VALID_LOG.replace(tests[0], b"", 1),
                        VALID_LOG.replace(tests[0], tests[1], 1),
                        VALID_LOG.replace(b" ... ok", b" ... FAILED", 1),
                        VALID_LOG.replace(b"0 failed", b"1 failed", 1),
                        VALID_LOG.replace(b"0 ignored", b"1 ignored", 1),
                        VALID_LOG.replace(b"running 4 tests", b"running 3 tests", 1),
                        VALID_LOG + b"test frames::unexpected ... ok\n"):
            with self.subTest(invalid=invalid):
                self.write_log(invalid)
                with self.assertRaises(ValueError):
                    self.verify()

    def test_current_smp_rejects_old_marker_or_missing_proof_and_preserves_history(self):
        for cpus in (4, 8):
            historical, qmp = smp.records(cpus)
            current = "".join(line for line in historical.splitlines(keepends=True)
                              if not line.startswith(oom.MARKER.decode("ascii")))
            old = smp.basic.verify_progress(historical, cpus, qmp, historical_boot_oom=True)
            self.assertEqual(old["frame_accounting"]["boot_oom_rejected"], cpus)
            proof = smp.basic.verify_progress(current, cpus, qmp,
                                             physical_oom_dir=self.folder, source_commit=self.commit)
            self.assertEqual(proof["frame_accounting"]["physical_oom"]["host_workers"], [1, 2, 4, 8])
            self.assertNotIn("boot_oom_rejected", proof["frame_accounting"])
            self.assertTrue(proof["final_shutdown"])
            for invalid in (historical, current.replace("FRAMES=OK", "FRAMES=LEAK", 1),
                            current.replace("FREE-AFTER=0000000000001000", "FREE-AFTER=0000000000001001", 1)):
                with self.assertRaises(ValueError):
                    smp.basic.verify_progress(invalid, cpus, qmp,
                                              physical_oom_dir=self.folder, source_commit=self.commit)
            with self.assertRaises(ValueError):
                smp.basic.verify_progress(current, cpus, qmp)
            with self.assertRaises(ValueError):
                smp.basic.verify_progress(current, cpus, qmp, historical_boot_oom=True)


if __name__ == "__main__":
    unittest.main()
