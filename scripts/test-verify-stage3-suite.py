"""Negative tests of all-or-nothing stage-3 acceptance matrix completeness."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock


SPEC = importlib.util.spec_from_file_location(
    "stage3_suite", Path(__file__).with_name("verify-stage3-suite.py"))
suite = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(suite)

SHA = "a" * 40
IMAGE = "b" * 64


class SuiteTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.runs = self.root / "build" / "runs"
        self.runs.mkdir(parents=True)
        self.observed = {}
        self.summary = {"schema": 1, "source_commit": SHA,
                        "signed_efi_sha256": IMAGE, "runs": []}
        for index, profile in enumerate(sorted(suite.EXPECTED)):
            case, cpus, shell, keyboard, level, output = profile
            vm = f"AgentOS-{case}-{index:010x}"
            directory = self.runs / vm
            directory.mkdir()
            text = json.dumps({"fake_receipt": index, "profile": profile}).encode()
            (directory / "acceptance.json").write_bytes(text)
            self.summary["runs"].append({
                "vm": vm, "sha256": suite.receipt.sha256(directory / "acceptance.json")
            })
            self.observed[vm] = {
                "case": case, "cpus": cpus, "shell": shell, "keyboard": keyboard,
                "boot_log_level": level, "boot_log_output": output,
                "source_commit": SHA,
            }
        self.summary_file = self.runs / "stage3-acceptance.json"
        self.save()

    def save(self):
        self.summary_file.write_text(json.dumps(self.summary), encoding="utf-8")

    def verify(self):
        with mock.patch.object(suite.receipt, "verify_build",
                               return_value={"artifacts": {"agentos.efi": IMAGE}}), \
             mock.patch.object(suite.receipt, "verify_run",
                               side_effect=lambda root, directory: self.observed[directory.name]):
            return suite.verify(self.root, self.summary_file)

    def rejects(self):
        with self.assertRaises((suite.receipt.EvidenceError, OSError)):
            self.verify()

    def test_exact_thirteen_profiles_pass(self):
        self.assertEqual(len(suite.EXPECTED), 13)
        self.assertEqual(self.verify(), 13)

    def test_missing_run_or_duplicate_run_fails(self):
        original = self.summary["runs"].pop()
        self.save()
        self.rejects()
        self.summary["runs"].append(self.summary["runs"][0])
        self.save()
        self.rejects()
        self.summary["runs"][-1] = original

    def test_tampered_receipt_is_rejected(self):
        vm = self.summary["runs"][0]["vm"]
        path = self.runs / vm / "acceptance.json"
        path.write_bytes(path.read_bytes() + b"tamper")
        self.rejects()

    def test_unexpected_profile_does_not_substitute_for_required_profile(self):
        vm = self.summary["runs"][0]["vm"]
        self.observed[vm]["boot_log_output"] = "none"
        self.rejects()

    def test_failed_run_cannot_be_hidden_by_summary(self):
        vm = self.summary["runs"][4]["vm"]
        with mock.patch.object(suite.receipt, "verify_build",
                               return_value={"artifacts": {"agentos.efi": IMAGE}}), \
             mock.patch.object(suite.receipt, "verify_run",
                               side_effect=lambda root, directory:
                                   (_ for _ in ()).throw(suite.receipt.EvidenceError("failed VM"))
                                   if directory.name == vm else self.observed[directory.name]):
            with self.assertRaises(suite.receipt.EvidenceError):
                suite.verify(self.root, self.summary_file)

    def test_wrong_source_or_signed_efi_fails(self):
        for key, value in (("source_commit", "f" * 40),
                           ("signed_efi_sha256", "0" * 64)):
            with self.subTest(key=key):
                original = self.summary[key]
                self.summary[key] = value
                self.save()
                self.rejects()
                self.summary[key] = original
        self.save()

    def test_path_traversal_is_rejected(self):
        self.summary["runs"][0]["vm"] = "../AgentOS-signed-aaaaaaaaaa"
        self.save()
        self.rejects()


if __name__ == "__main__":
    unittest.main()
