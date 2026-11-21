"""Verify all required *current* stage-3 signed EFI/VirtualBox integration profiles.

A green host CI does not satisfy this suite. Each of the thirteen receipts
must document a real VirtualBox 7.1.12 run, include integrity hashes, and
match the exact source commit and signed image. Passing this matrix does NOT\nsatisfy the still-open stage-3 COW, PID1 registry or recovery requirements.\nThe original VirtualBox
harness independently verifies COM1, screenshots and Secure Boot rejection.
"""
import argparse
import importlib.util
import json
from pathlib import Path
import re
import sys

SPEC = importlib.util.spec_from_file_location(
    "vm_receipt", Path(__file__).with_name("verify-vm-evidence.py"))
receipt = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(receipt)

EXPECTED = set()
for cpu in (1, 2):
    EXPECTED.update((
        ("signed", cpu, False, False, "info", "both"),
        ("signed", cpu, True, False, "debug", "serial"),
        ("signed", cpu, True, True, "info", "serial"),
        ("signed", cpu, False, False, "quiet", "none"),
        ("signed", cpu, False, False, "debug", "screen"),
    ))
for mutation in ("loader", "kernel", "initrd"):
    EXPECTED.add((mutation, 1, False, False, "info", "both"))

VM_NAME = re.compile(r"AgentOS-(signed|loader|kernel|initrd)-[0-9a-f]{10}\Z")


def verify(root, manifest_path):
    root = Path(root)
    manifest_path = Path(manifest_path)
    data = receipt.json_file(manifest_path)
    receipt.require(data.get("schema") == 1, "Unsupported stage-3 suite schema")
    source = data.get("source_commit")
    receipt.require(isinstance(source, str) and receipt.HEX_COMMIT.fullmatch(source),
                    "Invalid suite commit")
    build = receipt.verify_build(root, source)
    receipt.require(data.get("signed_efi_sha256") ==
                    build["artifacts"]["agentos.efi"],
                    "Suite signed image differs from its original build")
    records = data.get("runs")
    receipt.require(isinstance(records, list) and len(records) == len(EXPECTED),
                    f"Suite must contain exactly {len(EXPECTED)} accepted VM runs")
    seen_vms = set()
    seen_profiles = set()
    for entry in records:
        receipt.require(isinstance(entry, dict) and set(entry) == {"vm", "sha256"},
                        "Invalid matrix entry")
        vm = entry["vm"]
        digest = entry["sha256"]
        receipt.require(isinstance(vm, str) and VM_NAME.fullmatch(vm) and
                        vm not in seen_vms, "Unsafe or duplicate VM name")
        receipt.require(isinstance(digest, str) and receipt.HEX_SHA.fullmatch(digest),
                        f"Invalid acceptance receipt hash for {vm}")
        seen_vms.add(vm)
        directory = root / "build/runs" / vm
        receipt.require(receipt.sha256(directory / "acceptance.json") == digest,
                        f"Acceptance receipt modified: {vm}")
        observed = receipt.verify_run(root, directory)
        profile = (observed["case"], observed["cpus"], observed["shell"],
                   observed["keyboard"], observed["boot_log_level"],
                   observed["boot_log_output"])
        receipt.require(profile in EXPECTED and profile not in seen_profiles,
                        f"Unexpected or duplicated VM profile: {profile}")
        seen_profiles.add(profile)
        receipt.require(observed["source_commit"] == source,
                        f"Different source revision in {vm}")
    receipt.require(seen_profiles == EXPECTED,
                    f"Missing stage-3 profiles: {sorted(EXPECTED-seen_profiles)}")
    return len(seen_profiles)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--manifest", required=True, type=Path)
    args = parser.parse_args()
    try:
        count = verify(args.root, args.manifest)
    except (receipt.EvidenceError, OSError, TypeError, ValueError) as error:
        print(f"Stage-3 acceptance matrix failed: {error}", file=sys.stderr)
        return 1
    print(f"Verified all {count} independent signed/negative VirtualBox acceptance runs")
    return 0


if __name__ == "__main__":
    sys.exit(main())
