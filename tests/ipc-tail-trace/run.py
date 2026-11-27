#!/usr/bin/env python3
"""A single diagnostic session, not a replacement acceptance harness.

Run the original signed qemu-smoke implementation and original criteria.
Only this wrapper adds the existing QEMU GDB chardev and records UART
timestamps. Attach immediately before the ordinary IPC command, after
all preceding foreground programs have returned. No guest image edits.
"""
import ast
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import time
import traceback

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
DEST = ROOT / "build/check/qemu-cpu2-no-hpet-session-sv-test"
HERE = Path(__file__).resolve().parent
EXPECTED = {
    "build/kernel.elf": "ae7dbc731ea84e98a4559dfba0642271ca0c2970f508f47e29656446e31f746c",
    "build/initramfs.cpio": "23974b23c3bad07110806c19f10e808495dfd7541846045c828cf71652dbab25",
    "build/supervisor-staging/test.cpio": "24b760b8dda39b4f46e5a8c041191992f27c58236af8e9728da51be40c3c106d",
    "build/supervisor-staging/ipc-runner": "0a25e6d359e8ec27a5106c43f1bddae662604148018988e353ed8e83b610ad6e",
}

def save(name, value):
    (DEST / name).write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")

def capture(*args):
    return subprocess.check_output(args, cwd=ROOT, text=True, timeout=30).strip()

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

class TimestampedLink:
    def __init__(self, link):
        self.link = link
        self.events = []
        self.rx = 0
        self.tx = 0

    def __getattr__(self, name):
        return getattr(self.link, name)

    def recv(self, length):
        packet = self.link.recv(length)
        self.events.append({"event": "rx", "host_ns": time.monotonic_ns(),
                            "offset": self.rx, "length": len(packet)})
        self.rx += len(packet)
        return packet

    def sendall(self, packet):
        before = time.monotonic_ns()
        self.link.sendall(packet)
        self.events.append({"event": "tx", "host_ns": time.monotonic_ns(),
                            "begin_ns": before, "offset": self.tx,
                            "length": len(packet), "hex": packet.hex()})
        self.tx += len(packet)

def load_smoke():
    sys.path.insert(0, str(ROOT / "scripts"))
    spec = importlib.util.spec_from_file_location("original_smoke", ROOT/"scripts/qemu-smoke.py")
    smoke = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(smoke)
    return smoke

def require(condition, message):
    if not condition:
        raise RuntimeError(message)

def preflight_inputs():
    paths = [ROOT/p for p in EXPECTED] + [
        ROOT/"build/build-provenance.json", ROOT/"build/agentos.efi",
        ROOT/"build/agentos.unsigned.efi", ROOT/"build/db.cer", ROOT/"build/db.esl",
        ROOT/"build/supervisor-staging/identity.json",
        ROOT/"build/supervisor-staging/test.efi",
        ROOT/"build/supervisor-staging/test.unsigned.efi",
        ROOT/"build/supervisor-staging/ipc-service",
        Path("/usr/share/OVMF/OVMF_CODE_4M.secboot.fd"),
        Path("/usr/share/OVMF/OVMF_VARS_4M.fd"),
        Path.home()/".local/share/agentos/stage1-test-keys/db.crt",
        HERE/"run.py", HERE/"trace.py", ROOT/"scripts/qemu-smoke.py",
    ]
    return {str(p): sha(p) for p in paths}

def preflight():
    """Run on the actual CI checkout after the signed build, without a guest."""
    DEST.mkdir(parents=True, exist_ok=True)
    receipt = {"result": "fail", "guest_started": False, "qemu_count": 0,
               "stage": "checkout", "expected": EXPECTED}
    try:
        receipt.update(commit=capture("git", "rev-parse", "HEAD"),
                       tree=capture("git", "rev-parse", "HEAD^{tree}"))
        require(not capture("git", "status", "--porcelain", "--untracked-files=normal"),
                "Preflight requires the same clean checkout as the ordinary harness")
        receipt["stage"] = "full_harness_import"
        smoke = load_smoke()
        modules = {name: getattr(smoke, name) for name in (
            "evidence", "processes", "supervisor", "orphans", "cow", "demand",
            "migration", "service_manager", "boot_log", "physical_oom", "session", "console")}
        modules["smoke"] = smoke
        receipt["imports"] = {}
        for name, module in modules.items():
            path = Path(module.__file__).resolve()
            require(path.parent == ROOT/"scripts", "Wrong harness module: "+name)
            receipt["imports"][name] = {"path": str(path.relative_to(ROOT)), "sha256": sha(path)}
        require(Path(smoke.boot_log.physical_oom.__file__).resolve() ==
                ROOT/"scripts/physical_oom_evidence.py", "Wrong sibling physical OOM module")
        require(callable(smoke.main) and callable(smoke.boot) and
                all(callable(getattr(smoke.UartCapture, name, None))
                    for name in ("__init__", "send", "close")) and
                smoke.session.IPC_INPUT == b"run /ipc-runner\r" and
                hasattr(smoke.session.SHELL_START, "finditer"),
                "Original wrapper/harness interface changed")
        # Also load the real modules deferred by the staged session and identity checks.
        receipt["stage"] = "deferred_imports"
        for filename in ("verify-supervisor-image.py", "verify-boot-roots.py",
                         "verify-supervisor-locality.py", "verify-pipe-transfer.py",
                         "verify-memory-workload.py", "verify-ipc-workload.py",
                         "verify-fault-workload.py", "verify-adoption.py",
                         "verify-user-abi.py", "verify-oom-workload.py"):
            module = smoke.load("preflight_"+filename, filename)
            path = Path(module.__file__).resolve()
            require(path == ROOT/"scripts"/filename, "Wrong deferred module: "+filename)
            receipt["imports"][filename] = {"path": str(path.relative_to(ROOT)), "sha256": sha(path)}
            if filename == "verify-supervisor-image.py":
                paired = module
        receipt["stage"] = "host_dependencies"
        receipt["tools"] = {}
        for name in ("git", "bash", "gcc-13", "ld", "objcopy", "objdump", "rustc",
                     "truncate", "sgdisk", "mformat", "mmd", "mcopy", "virt-fw-vars",
                     "openssl", "sbverify", "qemu-system-x86_64", "gdb", "dpkg-query", "uname"):
            path = shutil.which(name)
            require(path is not None, "Missing executable: "+name)
            receipt["tools"][name] = path
        capture("bash", "-n", "scripts/disk.sh")
        receipt["stage"] = "input_hashes"
        actual = {p: sha(ROOT/p) for p in EXPECTED}
        receipt["hashes"] = actual
        require(actual == EXPECTED, "ELF/CPIO identity changed; offsets not valid")
        receipt["inputs"] = preflight_inputs()
        cert = Path.home()/".local/share/agentos/stage1-test-keys/db.crt"
        der = subprocess.check_output(["openssl", "x509", "-in", str(cert), "-outform", "der"])
        require(der == (ROOT/"build/db.cer").read_bytes(), "Wrong enrolled certificate")
        receipt["firmware_vars"] = capture("virt-fw-vars", "--input",
            "/usr/share/OVMF/OVMF_VARS_4M.fd", "--print", "--verbose")
        receipt["stage"] = "real_signed_identity"
        build = smoke.evidence.verify_build(ROOT, receipt["commit"])
        identity = paired.verify_identity(ROOT)
        require(identity["source_commit"] == receipt["commit"] and
                identity["source_tree"] == receipt["tree"], "Staged identity is not this checkout")
        receipt["build_artifacts"] = build["artifacts"]
        receipt["staged_identity"] = identity
        receipt["stage"] = "tracer_interface"
        source = (HERE/"trace.py").read_text()
        compile(source, str(HERE/"trace.py"), "exec")
        constants = {}
        for node in ast.parse(source).body:
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name) and target.id in ("SITES", "CALLS"):
                        constants[target.id] = ast.literal_eval(node.value)
        kernel = (ROOT/"build/kernel.elf").read_bytes()
        runner = (ROOT/"build/supervisor-staging/ipc-runner").read_bytes()
        require(set(constants) == {"SITES", "CALLS"} and
                {"move_before", "move_after_increment", "sched_stats_loaded", "exit_committed",
                 "collect_result", "ipc_send_committed", "ipc_receive_committed"}
                <= set(constants["SITES"].values()) and
                {"RUNNER", "ENDED", "PEER_END"} <= set(constants["CALLS"].values()),
                "Incomplete tracer interface")
        for key, data in (("SITES", kernel), ("CALLS", runner)):
            require(all(type(offset) is int and 0 <= offset and
                        0x1000+offset+12 <= len(data) for offset in constants[key]),
                    "Tracer ELF offset outside file: "+key)
        receipt["sites"] = constants["SITES"]
        receipt["calls"] = constants["CALLS"]
        # GDB's actual embedded Python, without attaching or loading a guest.
        code = ("import gdb, json, os, time; from pathlib import Path; "
                "compile(Path("+repr(str(HERE/"trace.py"))+").read_text(), 'trace.py', 'exec'); "
                "assert all(hasattr(gdb, n) for n in ('Breakpoint','BP_HARDWARE_BREAKPOINT',"
                "'selected_inferior','selected_thread','parse_and_eval','execute','GdbError')); "
                "assert all(hasattr(gdb.Inferior,n) for n in ('read_memory','threads')); "
                "assert hasattr(gdb.Breakpoint,'delete') and callable(time.monotonic_ns); "
                "print('IPC_TRACE_GDB_PREFLIGHT_OK')")
        result = subprocess.run(["gdb", "-nx", "-nh", "-batch", "-ex", "python "+code],
                                cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                text=True, timeout=30)
        receipt["gdb_preflight"] = {"returncode": result.returncode, "output": result.stdout}
        require(result.returncode == 0 and "IPC_TRACE_GDB_PREFLIGHT_OK" in result.stdout,
                "GDB embedded Python/trace API preflight failed")
        require(receipt["inputs"] == preflight_inputs(), "Preflight changed an input")
        receipt["stage"] = "complete"
        receipt["result"] = "pass"
    except Exception as exc:
        receipt["error"] = str(exc)
        receipt["traceback"] = traceback.format_exc()
    finally:
        save("trace-preflight.json", receipt)
        print("IPC preflight:", receipt["result"], receipt["stage"],
              receipt.get("error", ""), flush=True)
    return 0 if receipt["result"] == "pass" else 1

def require_preflight():
    receipt = json.loads((DEST/"trace-preflight.json").read_text())
    require(receipt.get("result") == "pass" and receipt.get("stage") == "complete" and
            receipt.get("guest_started") is False and receipt.get("qemu_count") == 0 and
            receipt.get("commit") == capture("git", "rev-parse", "HEAD") and
            receipt.get("tree") == capture("git", "rev-parse", "HEAD^{tree}") and
            receipt.get("hashes") == EXPECTED and receipt.get("inputs") == preflight_inputs(),
            "Missing or stale successful preflight; diagnostic guest forbidden")

def run():
    DEST.mkdir(parents=True, exist_ok=True)
    require_preflight()
    actual = {p: sha(ROOT/p) for p in EXPECTED}
    save("trace-environment.json", {
        "commit": capture("git", "rev-parse", "HEAD"),
        "tree": capture("git", "rev-parse", "HEAD^{tree}"),
        "hashes": actual, "expected": EXPECTED,
        "qemu_version": capture("qemu-system-x86_64", "--version"),
        "gdb_version": capture("gdb", "--version"),
        "packages": capture("dpkg-query", "-W", "qemu-system-x86", "ovmf", "gdb", "rustc"),
        "uname": capture("uname", "-a"),
        "image_os": os.environ.get("ImageOS"), "image_version": os.environ.get("ImageVersion"),
        "host_cpu_count": os.cpu_count(),
        "ovmf_code_sha256": sha(Path("/usr/share/OVMF/OVMF_CODE_4M.secboot.fd")),
    })
    if actual != EXPECTED:
        save("trace-wrapper.json", {"result": "blocked", "reason": "ELF/CPIO identity changed; offsets not valid",
                                    "guest_started": False})
        return 1

    smoke = load_smoke()
    original_capture = smoke.UartCapture
    state = {"qemu_count": 0, "attach_count": 0, "process": None,
             "uart": None, "attach_ns": None, "ready_ns": None}
    with tempfile.TemporaryDirectory(prefix="agentos-ipc-gdb-") as temp:
        sock = Path(temp)/"gdb.sock"
        class SubprocessProxy:
            def __getattr__(self, name):
                return getattr(subprocess, name)
            def Popen(self, command, *args, **kwargs):
                if isinstance(command, list) and command and command[0] == "qemu-system-x86_64":
                    state["qemu_count"] += 1
                    if state["qemu_count"] != 1:
                        raise RuntimeError("diagnostic may boot exactly one guest")
                    actual_command = command + ["-chardev",
                        f"socket,id=ipcdbg,path={sock},server=on,wait=off",
                        "-gdb", "chardev:ipcdbg"]
                    save("trace-actual-qemu-command.json", actual_command)
                    return subprocess.Popen(actual_command, *args, **kwargs)
                return subprocess.Popen(command, *args, **kwargs)

        class Capture(original_capture):
            def __init__(self, link, destination):
                wrapped = TimestampedLink(link)
                state["uart"] = wrapped
                super().__init__(wrapped, destination)

            def send(self, command):
                if command == smoke.session.IPC_INPUT:
                    state["attach_count"] += 1
                    if state["attach_count"] != 1:
                        raise RuntimeError("IPC trace may attach exactly once")
                    transcript = self.destination.read_bytes()
                    bases = re.findall(rb"\[INFO\] KERNEL IMAGE BASE=([0-9a-f]{16})", transcript)
                    shells = list(smoke.session.SHELL_START.finditer(transcript))
                    if len(bases) != 1 or len(shells) != 1 or b"SYSTEM CLOCK: ACPI PM" not in transcript:
                        raise RuntimeError("missing unique actual kernel base/shell/PM clock")
                    request = {"base": int(bases[0], 16), "shell": int(shells[0][1],16),
                               "destination": str(DEST), "root": str(ROOT)}
                    save("trace-request.json", request)
                    env = os.environ.copy()
                    env["AGENTOS_IPC_TRACE_REQUEST"] = str(DEST/"trace-request.json")
                    state["attach_ns"] = time.monotonic_ns()
                    with (DEST/"gdb.log").open("wb") as log:
                        state["process"] = subprocess.Popen(
                            ["gdb", "-nx", "-nh", "-batch", "-ex", "set confirm off",
                             "-ex", "set pagination off", "-ex", "set architecture i386:x86-64",
                             "-ex", f"target remote {sock}", "-x", str(HERE/"trace.py")],
                            cwd=ROOT, env=env, stdout=log, stderr=subprocess.STDOUT)
                    until = time.monotonic()+10
                    while not (DEST/"trace-ready.json").exists():
                        if state["process"].poll() is not None:
                            raise RuntimeError("GDB exited before arming trace; see gdb.log")
                        if time.monotonic() >= until:
                            raise RuntimeError("GDB attach/identity preflight did not finish")
                        time.sleep(.01)
                    state["ready_ns"] = time.monotonic_ns()
                return super().send(command)

        smoke.subprocess = SubprocessProxy()
        smoke.UartCapture = Capture
        sys.argv = ["qemu-smoke.py", "--cpus", "2", "--session", "--runtime-process-regression",
                    "--supervisor-image", "test", "--no-hpet", "--accel", "tcg",
                    "--ovmf-code", "/usr/share/OVMF/OVMF_CODE_4M.secboot.fd",
                    "--ovmf-vars", "/usr/share/OVMF/OVMF_VARS_4M.fd", "--timeout", "720"]
        status = 1
        try:
            status = smoke.main()
        finally:
            debugger = state["process"]
            if debugger is not None:
                try:
                    debugger.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    debugger.terminate()
                    try:
                        debugger.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        debugger.kill()
                        debugger.wait()
            uart = state["uart"]
            if uart is not None:
                events = sorted(uart.events, key=lambda e: e["host_ns"])
                with (DEST/"uart-timestamps.jsonl").open("w") as file:
                    for event in events:
                        file.write(json.dumps(event, sort_keys=True)+"\n")
            result_path = DEST/"trace-result.json"
            trace = json.loads(result_path.read_text()) if result_path.exists() else None
            result = {"result": "recorded" if trace and trace.get("result")=="complete" else "incomplete",
                      "smoke_status": status, "qemu_count": state["qemu_count"],
                      "attach_count": state["attach_count"], "attach_ns": state["attach_ns"],
                      "ready_ns": state["ready_ns"], "gdb_returncode": debugger.returncode if debugger else None,
                      "trace": trace}
            save("trace-wrapper.json", result)
            print("IPC diagnostic result:", json.dumps(result, sort_keys=True), flush=True)
        return 0 if status == 0 and result["result"]=="recorded" and result["gdb_returncode"]==0 else 1

if __name__ == "__main__":
    if sys.argv[1:] == ["--preflight"]:
        raise SystemExit(preflight())
    if sys.argv[1:]:
        raise SystemExit("Expected no arguments or --preflight")
    raise SystemExit(run())
