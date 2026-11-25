"""Negative tests of all-or-nothing stage-3 acceptance matrix completeness."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
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
                "artifacts": {"idle.csv": IMAGE} if case == "signed" else {},
            }
        self.summary_file = self.runs / "stage3-acceptance.json"
        self.save()
        # Matrix fixtures isolate receipt/profile checks. The real Git gate
        # has separate temporary-repository tests below.
        current = mock.patch.object(suite, "verify_current_checkout")
        self.checkout = current.start()
        self.addCleanup(current.stop)

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
        self.checkout.assert_called_once_with(self.root, SHA)

    def test_storage_build_cannot_count_as_stage3_matrix(self):
        with mock.patch.object(suite.receipt, "verify_build",
                               return_value={"profile": "nvme-block", "artifacts": {"agentos.efi": IMAGE}}):
            with self.assertRaises(suite.receipt.EvidenceError):
                suite.verify(self.root, self.summary_file)

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

    def test_missing_timed_idle_evidence_fails(self):
        signed = next(run for run in self.observed.values() if run["case"] == "signed")
        signed["artifacts"].clear()
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


class CurrentCheckoutTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.git("init", "--quiet", "--template=")
        (self.root / ".gitignore").write_text("/build/\n", encoding="utf-8")
        self.source = self.root / "source.txt"
        self.source.write_text("initial\n", encoding="utf-8")
        self.git("add", ".gitignore", "source.txt")
        self.commit()
        self.revision = self.git("rev-parse", "HEAD")

    def git(self, *arguments):
        return subprocess.run(
            ["git", "-C", str(self.root), *arguments], check=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True).stdout.strip()

    def commit(self):
        self.git("-c", "user.name=AgentOS Test", "-c", "user.email=test@example.invalid",
                 "commit", "--quiet", "--no-gpg-sign", "--no-verify", "-m", "test fixture")

    def test_current_clean_checkout_allows_ignored_vm_artifacts(self):
        (self.root / "build").mkdir()
        (self.root / "build/receipt.json").write_text("{}\n", encoding="utf-8")
        suite.verify_current_checkout(self.root, self.revision)

    def test_verifier_import_does_not_create_untracked_bytecode(self):
        scripts = self.root / "scripts"
        scripts.mkdir()
        for name in ("verify-stage3-suite.py", "verify-vm-evidence.py"):
            (scripts / name).write_bytes(Path(__file__).with_name(name).read_bytes())
        self.git("add", "scripts")
        self.commit()
        revision = self.git("rev-parse", "HEAD")
        environment = dict(os.environ)
        environment.pop("PYTHONDONTWRITEBYTECODE", None)
        subprocess.run([sys.executable, str(scripts / "verify-stage3-suite.py"), "--help"],
                       check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=environment)
        suite.verify_current_checkout(self.root, revision)

    def test_previous_commit_is_not_current_acceptance(self):
        self.source.write_text("next revision\n", encoding="utf-8")
        self.git("add", "source.txt")
        self.commit()
        with self.assertRaisesRegex(suite.receipt.EvidenceError, "current Git HEAD"):
            suite.verify_current_checkout(self.root, self.revision)

    def test_tracked_staged_and_untracked_source_changes_fail(self):
        self.source.write_text("uncommitted\n", encoding="utf-8")
        for staged in (False, True):
            if staged:
                self.git("add", "source.txt")
            with self.subTest(staged=staged), self.assertRaisesRegex(
                    suite.receipt.EvidenceError, "modified/untracked"):
                suite.verify_current_checkout(self.root, self.revision)
        self.git("reset", "--hard", "HEAD")
        (self.root / "new-source.txt").write_text("untracked\n", encoding="utf-8")
        with self.assertRaisesRegex(suite.receipt.EvidenceError, "modified/untracked"):
            suite.verify_current_checkout(self.root, self.revision)

    def test_missing_git_and_nonrepository_fail_clearly(self):
        with mock.patch.object(suite.subprocess, "run", side_effect=FileNotFoundError):
            with self.assertRaisesRegex(suite.receipt.EvidenceError, "Git must be available"):
                suite.verify_current_checkout(self.root, self.revision)
        with tempfile.TemporaryDirectory() as other:
            with self.assertRaisesRegex(suite.receipt.EvidenceError, "repository with a committed HEAD"):
                suite.verify_current_checkout(Path(other), self.revision)


if __name__ == "__main__":
    unittest.main()
