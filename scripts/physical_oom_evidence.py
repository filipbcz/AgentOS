"""Separate production allocator regression. Host threads are NOT guest CPUs."""
import argparse
import hashlib
import json
from pathlib import Path
import os
import platform
import re
import subprocess
import sys
import tempfile

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parent.parent
CONTRACT = "host-shared-allocator-v1"
SOURCES = ("kernel/frames.rs", "kernel/dma.rs", "scripts/tests/frame-snapshot-host.rs",
           "scripts/tests/frame-allocator-cases.rs", "scripts/physical_oom_evidence.py")
WORKERS = [1, 2, 4, 8]
TESTS = {"frames::allocatorTests::physicalExhaustionRecovery" + name
         for name in ("OneHostWorker", "TwoHostWorkers", "FourHostWorkers", "EightHostWorkers")}
LOG = "physical-oom.log"
RECEIPT = "physical-oom.json"
MARKER = b"AGENTOS OOM OK"


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def source_hashes(root):
    return {name: sha(root/name) for name in SOURCES}


def source_tree(root, commit):
    require(isinstance(commit, str) and re.fullmatch(r"[0-9a-f]{40}", commit), "Invalid source commit")
    tree = subprocess.check_output(["git", "rev-parse", "--verify", commit+"^{tree}"],
                                   cwd=root, text=True).strip()
    actual = subprocess.check_output(["git", "rev-parse", "--verify", "HEAD^{tree}"],
                                     cwd=root, text=True).strip()
    require(re.fullmatch(r"[0-9a-f]{40}", tree) and actual == tree,
            "Physical allocator evidence requires the exact source tree")
    return tree


def verify_log(data):
    lines = data.decode("ascii").splitlines()
    require(lines.count("running 4 tests") == 1, "Missing four actual host tests")
    tests = [line for line in lines if line.startswith("test ") and not line.startswith("test result:")]
    require(len(tests) == 4 and set(tests) == {"test " + name + " ... ok" for name in TESTS},
            "Missing, duplicated or unsuccessful allocator worker test")
    summaries = [line for line in lines if line.startswith("test result:")]
    require(len(summaries) == 1 and re.fullmatch(
        r"test result: ok\. 4 passed; 0 failed; 0 ignored; 0 measured; \d+ filtered out; finished in \d+\.\d+s",
        summaries[0]), "Invalid physical allocator test summary")


def verify(root, directory, commit):
    root, directory = Path(root), Path(directory)
    tree = source_tree(root, commit)
    record = json.loads((directory/RECEIPT).read_text(encoding="utf-8"))
    require(isinstance(record, dict) and record.get("schema") == 1 and
            record.get("contract") == CONTRACT and record.get("result") == "pass" and
            record.get("source_commit") == commit and record.get("source_tree") == tree and
            record.get("host_workers") == WORKERS and
            record.get("host_system") == "Linux" and record.get("host_arch") == "x86_64" and
            type(record.get("exit_status")) is int and record["exit_status"] == 0 and
            isinstance(record.get("rustc_version"), str) and record["rustc_version"].startswith("rustc "),
            "Incomplete or stale separate physical OOM evidence")
    require(record.get("source_sha256") == source_hashes(root), "Allocator regression source differs")
    raw = (directory/LOG).read_bytes()
    require(record.get("test_log_sha256") == hashlib.sha256(raw).hexdigest(), "Allocator test log changed")
    verify_log(raw)
    return {"contract": CONTRACT, "source_commit": commit, "source_tree": tree, "host_workers": WORKERS,
            "receipt_sha256": sha(directory/RECEIPT), "log_sha256": sha(directory/LOG)}


def verify_boot(log, root, directory, commit):
    require(MARKER not in log, "Historic forced boot OOM marker in current boot")
    return verify(root, directory, commit)


def run(root, directory, commit):
    root, directory = Path(root).resolve(), Path(directory).resolve()
    directory.mkdir(parents=True, exist_ok=True)
    for name in (LOG, RECEIPT):
        (directory/name).unlink(missing_ok=True)
    actual = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()
    require(actual == commit, "Physical allocator regression requires exact checkout")
    require(not subprocess.check_output(["git", "status", "--porcelain", "--untracked-files=normal"],
                                        cwd=root, text=True).strip(), "Physical allocator regression requires clean source")
    require(platform.system() == "Linux" and platform.machine() == "x86_64",
            "Physical allocator test requires Linux x86_64 host (WSL is supported)")
    tree = source_tree(root, commit)
    before = source_hashes(root)
    rustc = os.environ.get("RUSTC") or ("/usr/bin/rustc" if Path("/usr/bin/rustc").is_file() else "rustc")
    version = subprocess.check_output([rustc, "--version"], cwd=root, text=True).strip()
    with tempfile.TemporaryDirectory(prefix="agentos-physical-oom-") as tmp:
        binary = Path(tmp)/"frame-tests"
        subprocess.run([rustc, "--edition", "2021", "--test",
                        str(root/"scripts/tests/frame-snapshot-host.rs"), "-o", str(binary)],
                       cwd=root, check=True, timeout=60)
        result = subprocess.run([str(binary), "physicalExhaustionRecovery", "--test-threads=1"],
                                cwd=root, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=60)
    (directory/LOG).write_bytes(result.stdout)
    require(result.returncode == 0, "Physical allocator tests failed")
    verify_log(result.stdout)
    require(source_hashes(root) == before and source_tree(root, commit) == tree and
            subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip() == commit and
            not subprocess.check_output(["git", "status", "--porcelain", "--untracked-files=normal"],
                                        cwd=root, text=True).strip(),
            "Source changed during allocator tests")
    record = {"schema": 1, "contract": CONTRACT, "result": "pass", "source_commit": commit,
              "source_tree": tree,
              "host_system": platform.system(), "host_arch": platform.machine(), "host_workers": WORKERS,
              "exit_status": result.returncode, "rustc_version": version, "source_sha256": before,
              "test_log_sha256": sha(directory/LOG)}
    (directory/RECEIPT).write_text(json.dumps(record, indent=2, sort_keys=True)+"\n", encoding="utf-8")
    return verify(root, directory, commit)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--verify", action="store_true")
    parser.add_argument("--boot-log", type=Path, help="Additionally reject the historical boot OOM marker")
    args = parser.parse_args()
    if args.boot_log and not args.verify:
        parser.error("--boot-log requires --verify")
    try:
        if args.boot_log:
            proof = verify_boot(args.boot_log.read_bytes(), args.root, args.directory, args.commit)
        else:
            proof = (verify if args.verify else run)(args.root, args.directory, args.commit)
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print(f"Physical OOM evidence failed: {error}", file=sys.stderr)
        return 1
    print(json.dumps(proof, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
