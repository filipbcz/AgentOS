"""Verify immutable-by-hash VM acceptance receipts against their actual files.

Receipts preserve reproducible evidence but are not signed attestations. Only
VirtualBox execution and its strict COM1/screenshot verifiers prove guest
behavior. This checker rejects stale signed images, uncommitted source trees,
altered logs, missing screenshots, and failed/incomplete acceptance runs.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import sys

# An offline receipt check must not dirty the source checkout it verifies.
sys.dont_write_bytecode = True


class EvidenceError(ValueError):
    pass


HEX_SHA = re.compile(r"[0-9a-f]{64}\Z")
HEX_COMMIT = re.compile(r"[0-9a-f]{40}\Z")
VBox_VERSION = re.compile(r"7\.1\.12(?:r[0-9]+)?\Z")
ARTIFACTS = frozenset({
    "esp.raw", "esp.vdi", "changed.efi", "com1.log", "com1-input.bin",
    "display.png", "shell-before.png", "shell-keyboard.png"
})
BUILD_ARTIFACTS = frozenset({
    "agentos.unsigned.efi", "agentos.efi", "db.cer", "db.esl"
})
SESSION_START = re.compile(rb"(?m)^AGENTOS MANAGER SESSION START PID=([0-9a-f]{16})\r\n")
SESSION_STOP = re.compile(rb"(?m)^AGENTOS MANAGER SESSION STOP PID=([0-9a-f]{16}) "
                          rb"STATUS=0000000000000000 FRAMES=OK\r\n")


def require(condition, reason):
    if not condition:
        raise EvidenceError(reason)


def sha256(path):
    result = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            result.update(block)
    return result.hexdigest()


def json_file(path):
    try:
        value = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, ValueError) as error:
        raise EvidenceError(f"Cannot read JSON from {path}: {error}") from error
    require(isinstance(value, dict), f"Expected object in {path}")
    return value


def verify_build(root, commit=None):
    root = Path(root)
    out = root / "build"
    data = json_file(out / "build-provenance.json")
    require(data.get("schema") == 1, "Unsupported build provenance schema")
    source = data.get("source_commit")
    require(isinstance(source, str) and HEX_COMMIT.fullmatch(source),
            "Invalid source commit")
    if commit is not None:
        require(source == commit, "Stale image from different source commit")
    require(data.get("source_clean") is True, "Build used modified/untracked source")
    require(data.get("rustc_version", "").startswith("rustc 1.75.0 "),
            "Build did not use pinned Rust 1.75.0")
    require(isinstance(data.get("gcc_version"), str) and
            data["gcc_version"].startswith("13."), "Build did not use GCC 13")
    require(isinstance(data.get("initramfs_sha256"), str) and
            HEX_SHA.fullmatch(data["initramfs_sha256"]),
            "Missing embedded initramfs digest")
    require(data.get("toolchain_lock_sha256") == sha256(root / "scripts/toolchain.lock"),
            "Toolchain lock differs from the signed image build")
    artifacts = data.get("artifacts")
    require(isinstance(artifacts, dict) and set(artifacts) == BUILD_ARTIFACTS,
            "Missing signed-image, unsigned-image or Secure Boot db receipt")
    for name in BUILD_ARTIFACTS:
        expected = artifacts[name]
        require(isinstance(expected, str) and HEX_SHA.fullmatch(expected),
                f"Invalid build digest for {name}")
        require(sha256(out / name) == expected, f"Build artifact changed: {name}")
    return data


def verify_run(root, run_dir, require_pass=True):
    root, run_dir = Path(root), Path(run_dir)
    data = json_file(run_dir / "acceptance.json")
    require(data.get("schema") == 1, "Unsupported VM receipt schema")
    require(data.get("result") in ("pass", "fail"), "VM test result missing")
    if require_pass:
        require(data["result"] == "pass", "VM run did not pass acceptance checks")
    image = verify_build(root, data.get("source_commit"))
    require(data.get("build_provenance_sha256") ==
            sha256(root / "build/build-provenance.json"),
            "VM run references a changed build provenance receipt")
    require(data.get("harness_sha256") == sha256(root / "scripts/test-vbox.ps1"),
            "VM acceptance test script differs from recorded source")
    require(data.get("vm") == run_dir.name, "VirtualBox VM name does not match run directory")
    require(isinstance(data.get("virtualbox_version"), str) and
            VBox_VERSION.fullmatch(data["virtualbox_version"]),
            "VM was not run with pinned VirtualBox 7.1.12")
    cpus = data.get("cpus")
    case = data.get("case")
    shell = data.get("shell")
    keyboard = data.get("keyboard")
    require(type(cpus) is int and cpus in (1, 2), "Invalid vCPU count")
    require(case in ("signed", "loader", "kernel", "initrd"), "Invalid mutation case")
    require(type(shell) is bool and type(keyboard) is bool, "Invalid shell flags")
    require(not keyboard or shell, "Keyboard mode requires shell")
    require(not shell or case == "signed", "Shell acceptance requires signed image")
    require(data.get("boot_log_level") in ("quiet", "info", "debug"),
            "Invalid boot logging level")
    require(data.get("boot_log_output") in ("serial", "screen", "both", "none"),
            "Invalid boot log sink")
    duration = data.get("host_elapsed_seconds")
    require(type(duration) in (int, float) and 0 <= duration < 86400,
            "Invalid VM host wall-time measurement")
    artifacts = data.get("artifacts")
    require(isinstance(artifacts, dict) and set(artifacts) <= ARTIFACTS,
            "Run contains invalid artifact names")
    expected = {"esp.raw", "esp.vdi", "com1.log", "display.png"}
    if case != "signed":
        expected.add("changed.efi")
    elif shell:
        expected.add("shell-before.png")
        # Keyboard profiles also run the full UART service/idle sequence,
        # then inject editing and exit through the independent PS/2 path.
        expected.add("com1-input.bin")
        if keyboard:
            expected.add("shell-keyboard.png")
    require(expected <= set(artifacts), f"Missing required VM artifacts: {sorted(expected-set(artifacts))}")
    for name, digest in artifacts.items():
        require(isinstance(digest, str) and HEX_SHA.fullmatch(digest),
                f"Invalid VM artifact digest: {name}")
        try:
            measured = sha256(run_dir / name)
        except OSError as error:
            raise EvidenceError(f"Missing VM artifact {name}: {error}") from error
        require(measured == digest, f"VM artifact altered: {name}")
    if case == "signed":
        require(data.get("boot_image_sha256") == image["artifacts"]["agentos.efi"],
                "VM boot image is not the signed build artifact")
        log = (run_dir / "com1.log").read_bytes()
        require(b"AGENTOS KERNEL OK STAGE 1\r\n" in log,
                "Signed VM receipt lacks final kernel boot marker")
        # Older receipts predate this milestone and remain valid inputs. If a
        # demand trace is present, verify its contents as well as its hash;
        # malformed/partial traces must never pass as unrelated serial text.
        if b"AGENTOS DEMAND" in log:
            pSpec = importlib.util.spec_from_file_location(
                "receiptDemandEvidence", Path(__file__).with_name("verify-demand-paging.py"))
            pVerifier = importlib.util.module_from_spec(pSpec)
            pSpec.loader.exec_module(pVerifier)
            try:
                pVerifier.verify(log.decode("ascii", errors="replace"), cpus)
            except pVerifier.VerificationError as pError:
                raise EvidenceError(f"Invalid demand-paging evidence: {pError}") from pError
        if shell:
            starts = list(SESSION_START.finditer(log))
            stops = list(SESSION_STOP.finditer(log))
            require(len(starts) == len(stops) == 1 and
                    starts[0][1] == stops[0][1] == b"0000000000000001" and
                    starts[0].end() <= stops[0].start(),
                    "Signed shell receipt lacks successful clean exit")
    else:
        require(data.get("boot_image_sha256") == sha256(run_dir / "changed.efi"),
                "Negative VM test boot hash mismatch")
        log = (run_dir / "com1.log").read_bytes()
        require(b"AGENTOS KERNEL OK STAGE 1" not in log,
                "Firmware accepted modified EFI")
        require(re.search(rb"BdsDxe: failed to load .*HARDDISK.*"
                          rb"(Access Denied|Security Violation)", log) is not None,
                "Firmware rejection is unproven; timeout is inconclusive")
    return data


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--run-dir", type=Path)
    parser.add_argument("--commit")
    args = parser.parse_args()
    try:
        if args.run_dir:
            data = verify_run(args.root, args.run_dir)
            print(f"VM acceptance receipt verified: {data['vm']}, "
                  f"commit {data['source_commit']}, {data['cpus']} vCPU")
        else:
            data = verify_build(args.root, args.commit)
            print(f"Signed EFI build provenance verified: {data['source_commit']}")
    except (EvidenceError, OSError, TypeError) as error:
        print(f"VM evidence verification failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
