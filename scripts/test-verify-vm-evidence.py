"""Regression tests for signed EFI and VirtualBox evidence receipt verification."""
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import tempfile
import unittest


SPEC = importlib.util.spec_from_file_location(
    "vm_evidence", Path(__file__).with_name("verify-vm-evidence.py"))
evidence = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(evidence)

SHA = "a" * 40


class VmEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.build = self.root / "build"
        self.run = self.build / "runs" / "AgentOS-signed-test"
        self.run.mkdir(parents=True)
        (self.root / "scripts").mkdir()
        self.write(self.root / "scripts/toolchain.lock", b"locked compiler versions\n")
        self.write(self.root / "scripts/test-vbox.ps1", b"# exact acceptance harness\n")
        contents = {
            "agentos.unsigned.efi": b"unsigned EFI",
            "agentos.efi": b"signed EFI",
            "db.cer": b"cert",
            "db.esl": b"db certificate",
        }
        for name, raw in contents.items():
            self.write(self.build / name, raw)
        self.provenance = {
            "schema": 1, "source_commit": SHA, "source_clean": True,
            "rustc_version": "rustc 1.75.0 (82e1608df 2023-12-21)",
            "gcc_version": "13.3.0", "initramfs_sha256": "b" * 64,
            "toolchain_lock_sha256": evidence.sha256(self.root / "scripts/toolchain.lock"),
            "artifacts": {name: evidence.sha256(self.build / name) for name in contents},
        }
        self.save_provenance()
        self.write(self.run / "esp.raw", b"mock raw disk")
        self.write(self.run / "esp.vdi", b"mock VDI disk")
        self.write(self.run / "display.png", b"mock GOP screenshot")
        self.write(self.run / "shell-before.png", b"mock prompt")
        self.write(self.run / "shell-keyboard.png", b"mock typed response")
        self.write(self.run / "com1-input.bin", b"mock transmitted UART bytes")
        self.write(self.run / "com1.log",
                   b"AGENTOS KERNEL OK STAGE 1\r\n"
                   b"AGENTOS MANAGER SESSION START PID=0000000000000001\r\n"
                   b"AGENTOS MANAGER SESSION STOP PID=0000000000000001 "
                   b"STATUS=0000000000000000 FRAMES=OK\r\n")
        self.manifest = {
            "schema": 1, "result": "pass", "vm": self.run.name,
            "source_commit": SHA,
            "build_provenance_sha256": evidence.sha256(self.build / "build-provenance.json"),
            "harness_sha256": evidence.sha256(self.root / "scripts/test-vbox.ps1"),
            "virtualbox_version": "7.1.12r169651",
            "case": "signed", "cpus": 2, "shell": True,
            "keyboard": True, "boot_log_level": "info",
            "boot_log_output": "serial", "host_elapsed_seconds": 42.125,
            "boot_image_sha256": evidence.sha256(self.build / "agentos.efi"),
            "artifacts": {
                name: evidence.sha256(self.run / name)
                for name in ("esp.raw", "esp.vdi", "display.png",
                             "shell-before.png", "shell-keyboard.png", "com1.log", "com1-input.bin")
            },
        }
        self.save_manifest()

    def write(self, path, data):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)

    def save_provenance(self):
        (self.build / "build-provenance.json").write_text(
            json.dumps(self.provenance), encoding="utf-8")

    def save_manifest(self):
        (self.run / "acceptance.json").write_text(
            json.dumps(self.manifest), encoding="utf-8")

    def rejected(self):
        with self.assertRaises((evidence.EvidenceError, OSError)):
            evidence.verify_run(self.root, self.run)

    def test_valid_signed_keyboard_and_serial_profiles(self):
        self.assertEqual(evidence.verify_run(self.root, self.run)["cpus"], 2)
        self.manifest["keyboard"] = False
        self.write(self.run / "com1-input.bin", b"help\r")
        self.manifest["artifacts"].pop("shell-keyboard.png")
        self.manifest["artifacts"]["com1-input.bin"] = evidence.sha256(
            self.run / "com1-input.bin")
        self.save_manifest()
        self.assertEqual(evidence.verify_run(self.root, self.run)["shell"], True)

    def test_valid_mutation_rejected_by_firmware(self):
        self.manifest.update({"case": "loader", "shell": False, "keyboard": False})
        self.write(self.run / "changed.efi", b"altered signed EFI")
        self.write(self.run / "com1.log", b"BdsDxe: failed to load EFI\\BOOT\\BOOTX64.EFI HARDDISK Access Denied\r\n")
        self.manifest["boot_image_sha256"] = evidence.sha256(self.run / "changed.efi")
        for name in ("shell-before.png", "shell-keyboard.png"):
            self.manifest["artifacts"].pop(name)
        self.manifest["artifacts"]["changed.efi"] = evidence.sha256(self.run / "changed.efi")
        self.manifest["artifacts"]["com1.log"] = evidence.sha256(self.run / "com1.log")
        self.save_manifest()
        self.assertEqual(evidence.verify_run(self.root, self.run)["case"], "loader")

    def demandLog(self):
        pSpec = importlib.util.spec_from_file_location(
            "receiptDemandFixtures", Path(__file__).with_name("test-verify-demand-paging.py"))
        pFixtures = importlib.util.module_from_spec(pSpec)
        pSpec.loader.exec_module(pFixtures)
        pScenarios = (pFixtures.scenario() + pFixtures.scenario(33, 1)).replace("\n", "\r\n").encode("ascii")
        pOriginal = (self.run / "com1.log").read_bytes()
        return pOriginal.replace(b"AGENTOS MANAGER SESSION START", pScenarios + b"AGENTOS MANAGER SESSION START", 1)

    def testDemandTraceIsStrictlyVerifiedWhenPresent(self):
        self.write(self.run / "com1.log", self.demandLog())
        self.manifest["artifacts"]["com1.log"] = evidence.sha256(self.run / "com1.log")
        self.save_manifest()
        self.assertEqual(evidence.verify_run(self.root, self.run)["result"], "pass")

    def testRehashedIncompleteOrContradictoryDemandTraceIsRejected(self):
        pOriginal = self.demandLog()
        pTouch = next(pLine for pLine in pOriginal.splitlines(keepends=True)
                      if pLine.startswith(b"AGENTOS DEMAND TOUCH"))
        for pAltered in (
            pOriginal.replace(pTouch, b"", 1),
            pOriginal.replace(b"RESIDENT=0000000000000020", b"RESIDENT=0000000000001020", 1),
            pOriginal.replace(b"ERROR=0000000000000014", b"ERROR=0000000000000004", 1),
        ):
            with self.subTest(log=pAltered):
                self.write(self.run / "com1.log", pAltered)
                # The receipt deliberately has the updated hash, exercising
                # semantic validation independently of tamper detection.
                self.manifest["artifacts"]["com1.log"] = evidence.sha256(self.run / "com1.log")
                self.save_manifest()
                self.rejected()

    def test_session_receipt_matches_actual_kernel_producer(self):
        # This contract test reads the real emitter, not another hand-maintained
        # fixture. Renaming a kernel session boundary must update its consumer.
        source = (Path(__file__).resolve().parents[1] / "kernel/smp.rs").read_text()
        prefixes = re.findall(r'serial\(b"(AGENTOS MANAGER SESSION (?:START|STOP) PID=)"\)', source)
        self.assertEqual(len(prefixes), 2)
        log = (b"AGENTOS KERNEL OK STAGE 1\r\n" +
               prefixes[0].encode() + b"0000000000000001\r\n" +
               prefixes[1].encode() + b"0000000000000001 STATUS=0000000000000000 FRAMES=OK\r\n")
        self.write(self.run / "com1.log", log)
        self.manifest["artifacts"]["com1.log"] = evidence.sha256(self.run / "com1.log")
        self.save_manifest()
        self.assertEqual(evidence.verify_run(self.root, self.run)["result"], "pass")

    def migrationLog(self):
        pSpec = importlib.util.spec_from_file_location(
            "receiptMigrationFixtures", Path(__file__).with_name("test-verify-migration.py"))
        pFixtures = importlib.util.module_from_spec(pSpec)
        pSpec.loader.exec_module(pFixtures)
        return (b"AGENTOS KERNEL OK STAGE 1\r\n" + pFixtures.scenario(2).encode("ascii") +
                b"AGENTOS MANAGER SESSION STOP PID=0000000000000001 "
                b"STATUS=0000000000000000 FRAMES=OK\r\n")

    def testMigrationTraceIsStrictlyVerifiedWhenPresent(self):
        self.write(self.run / "com1.log", self.migrationLog())
        self.manifest["artifacts"]["com1.log"] = evidence.sha256(self.run / "com1.log")
        self.save_manifest()
        self.assertEqual(evidence.verify_run(self.root, self.run)["result"], "pass")

    def testRehashedPartialOrFabricatedMigrationIsRejected(self):
        pOriginal = self.migrationLog()
        pMove = next(pLine for pLine in pOriginal.splitlines(keepends=True)
                     if pLine.startswith(b"AGENTOS MIGRATION MOVED"))
        for pAltered in (
            pOriginal.replace(pMove, b"", 1),
            pOriginal.replace(b"WAKEUPS=000000000000000c", b"WAKEUPS=0000000000000000", 1),
            pOriginal.replace(b"UID=00000000000003e8", b"UID=0000000000000000", 1),
        ):
            with self.subTest(log=pAltered):
                self.write(self.run / "com1.log", pAltered)
                self.manifest["artifacts"]["com1.log"] = evidence.sha256(self.run / "com1.log")
                self.save_manifest()
                self.rejected()

    def test_old_duplicate_foreign_or_failed_session_receipt_is_rejected(self):
        path = self.run / "com1.log"
        original = path.read_bytes()
        for altered in (
            original.replace(b"MANAGER SESSION STOP", b"SHELL STOP"),
            original.replace(b"STOP PID=0000000000000001", b"STOP PID=0000000000000002"),
            original.replace(b"STATUS=0000000000000000", b"STATUS=0000000000000001"),
            original + original.splitlines(keepends=True)[-1],
            original.replace(b"AGENTOS MANAGER SESSION START PID=0000000000000001\r\n", b""),
        ):
            with self.subTest(log=altered):
                self.write(path, altered)
                self.manifest["artifacts"]["com1.log"] = evidence.sha256(path)
                self.save_manifest()
                self.rejected()

    def test_reject_failed_incomplete_or_wrong_vm(self):
        for key, wrong in (("result", "fail"), ("cpus", 4),
                           ("virtualbox_version", "7.2.0r123"),
                           ("source_commit", "f" * 40),
                           ("vm", "other-run"),
                           ("boot_image_sha256", "0" * 64)):
            with self.subTest(key=key):
                saved = self.manifest[key]
                self.manifest[key] = wrong
                self.save_manifest()
                self.rejected()
                self.manifest[key] = saved

    def test_reject_mutated_or_missing_evidence_files(self):
        for filename in self.manifest["artifacts"]:
            with self.subTest(filename=filename):
                path = self.run / filename
                original = path.read_bytes()
                self.write(path, original + b"tamper")
                self.rejected()
                self.write(path, original)
        self.manifest["artifacts"].pop("shell-keyboard.png")
        self.save_manifest()
        self.rejected()

    def test_keyboard_profile_still_requires_transmitted_uart_evidence(self):
        self.manifest["artifacts"].pop("com1-input.bin")
        self.save_manifest()
        self.rejected()

    def test_reject_modified_signed_efi_or_build_receipt(self):
        image = self.build / "agentos.efi"
        self.write(image, b"older image")
        self.rejected()
        self.write(image, b"signed EFI")
        self.provenance["source_clean"] = False
        self.save_provenance()
        self.manifest["build_provenance_sha256"] = evidence.sha256(
            self.build / "build-provenance.json")
        self.save_manifest()
        self.rejected()

    def test_reject_modified_test_harness(self):
        script = self.root / "scripts/test-vbox.ps1"
        self.write(script, b"altered checks")
        self.rejected()

    def test_reject_changed_toolchain_or_missing_kernel_completion(self):
        self.write(self.root / "scripts/toolchain.lock", b"unexpected compiler")
        self.rejected()
        self.write(self.root / "scripts/toolchain.lock", b"locked compiler versions\n")
        log = self.run / "com1.log"
        self.write(log, b"AGENTOS SHELL STOP PID=0 STATUS=0000000000000000 FRAMES=OK\r\n")
        self.manifest["artifacts"]["com1.log"] = evidence.sha256(log)
        self.save_manifest()
        self.rejected()

    def test_reject_path_escape_and_injected_artifacts(self):
        self.manifest["artifacts"]["../agentos.efi"] = "0" * 64
        self.save_manifest()
        self.rejected()
        self.manifest["artifacts"].pop("../agentos.efi")

    def test_reject_missing_build_and_invalid_provenance_schema(self):
        (self.build / "build-provenance.json").unlink()
        self.rejected()
        self.provenance["schema"] = 99
        self.save_provenance()
        self.rejected()


if __name__ == "__main__":
    unittest.main()
