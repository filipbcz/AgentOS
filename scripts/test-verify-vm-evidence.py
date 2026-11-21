"""Regression tests for signed EFI and VirtualBox evidence receipt verification."""
import hashlib
import importlib.util
import json
from pathlib import Path
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
        self.write(self.run / "com1.log",
                   b"AGENTOS KERNEL OK STAGE 1\r\n"
                   b"AGENTOS SHELL STOP PID=0000000000000008 "
                   b"STATUS=0000000000000000 FRAMES=OK\r\n")
        self.manifest = {
            "schema": 1, "result": "pass", "vm": self.run.name,
            "source_commit": SHA,
            "build_provenance_sha256": evidence.sha256(self.build / "build-provenance.json"),
            "virtualbox_version": "7.1.12r169651",
            "case": "signed", "cpus": 2, "shell": True,
            "keyboard": True, "boot_log_level": "info",
            "boot_log_output": "serial", "host_elapsed_seconds": 42.125,
            "boot_image_sha256": evidence.sha256(self.build / "agentos.efi"),
            "artifacts": {
                name: evidence.sha256(self.run / name)
                for name in ("esp.raw", "esp.vdi", "display.png",
                             "shell-before.png", "shell-keyboard.png", "com1.log")
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
        self.write(self.run / "com1.log", b"BdsDxe: failed to load Access Denied\r\n")
        self.manifest["boot_image_sha256"] = evidence.sha256(self.run / "changed.efi")
        for name in ("shell-before.png", "shell-keyboard.png"):
            self.manifest["artifacts"].pop(name)
        self.manifest["artifacts"]["changed.efi"] = evidence.sha256(self.run / "changed.efi")
        self.manifest["artifacts"]["com1.log"] = evidence.sha256(self.run / "com1.log")
        self.save_manifest()
        self.assertEqual(evidence.verify_run(self.root, self.run)["case"], "loader")

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
