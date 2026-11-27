#!/usr/bin/env python3
"""A single diagnostic session, not a replacement acceptance harness.

Run the original signed qemu-smoke implementation and original criteria.
Only this wrapper adds the existing QEMU GDB chardev and records UART
timestamps. Attach immediately before the ordinary supervisor command, after
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
PROFILE = "qemu-cpu2-session-sv-test"
DEST = ROOT / "build/check" / PROFILE
HERE = Path(__file__).resolve().parent
ARM_COMMAND = "run /supervisor-runner"
ARM_INPUT = (ARM_COMMAND+"\r").encode("ascii")
SMOKE_ARGS = ["--cpus", "2", "--memory-mib", "256", "--session",
              "--runtime-process-regression", "--supervisor-image", "test",
              "--guest-oom", "--accel", "tcg",
              "--ovmf-code", "/usr/share/OVMF/OVMF_CODE_4M.secboot.fd",
              "--ovmf-vars", "/usr/share/OVMF/OVMF_VARS_4M.fd", "--timeout", "720"]
EXPECTED = {
    "build/kernel.elf": "ae7dbc731ea84e98a4559dfba0642271ca0c2970f508f47e29656446e31f746c",
    "build/initramfs.cpio": "23974b23c3bad07110806c19f10e808495dfd7541846045c828cf71652dbab25",
    "build/supervisor-staging/test.cpio": "24b760b8dda39b4f46e5a8c041191992f27c58236af8e9728da51be40c3c106d",
    "build/supervisor-staging/ipc-runner": "0a25e6d359e8ec27a5106c43f1bddae662604148018988e353ed8e83b610ad6e",
    "build/supervisor-staging/supervisor-runner": "29204eedf0f068e7b6dd751c62fdb60543904145cafb955c7685eebf464593c4",
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

def arm_requested(command):
    return command == ARM_INPUT

def verify_arm(smoke):
    require(smoke.session.SUPERVISOR_COMMAND == ARM_COMMAND and
            smoke.session.SUPERVISOR_INPUT == ARM_INPUT and
            arm_requested(smoke.session.SUPERVISOR_INPUT) and
            not any(arm_requested(value) for name,value in vars(smoke.session).items()
                    if name.endswith("_INPUT") and name != "SUPERVISOR_INPUT" and isinstance(value,bytes)) and
            not arm_requested(ARM_COMMAND.encode("ascii")) and
            not arm_requested(b"run /supervisor-runner\n"),
            "Supervisor ARM command is not the unique actual harness input")
    return {"command": ARM_COMMAND, "input_hex": ARM_INPUT.hex(),
            "profile": PROFILE, "smoke_args": SMOKE_ARGS}

def verify_symbols(constants):
    # Decoded from the archived failed HPET supervisor ELF and matching kernel.
    # Addresses are relative to the kernel image / fixed user ELF base.
    sites = {0xb98f:"move_before", 0xba78:"move_after_increment",
             0x15b80:"sched_stats_loaded", 0x20428:"exit_committed",
             0x1fe9d:"wake_io", 0x820d:"wake_timed", 0x81df:"wake_clock_error",
             0x1f9ac:"blocked_child", 0xcf71:"collect_result",
             0x26da7:"ipc_send_committed", 0x26cba:"ipc_receive_committed"}
    calls = {0xa3a:"RUNNER", 0x1080:"PEER_BEGIN", 0x11f9:"PEER_END",
             0x12fe:"BEGIN", 0x13c8:"ENDED", 0x1bc1:"COMPLETE"}
    require(constants == {"SITES":sites,"CALLS":calls}, "Wrong supervisor tracer site/return map")
    kernel_path=ROOT/"build/kernel.elf"
    runner_path=ROOT/"build/supervisor-staging/supervisor-runner"
    kernel,runner=kernel_path.read_bytes(),runner_path.read_bytes()
    # Exact instruction bytes at every breakpoint and supporting return PC.
    code = {
        0xb98f:"e8ac4f010048837c2408000f", 0xba78:"4d8da7b80100004c89e7e849",
        0x15b80:"4c8b1559d10200488b0948c7", 0x20428:"41c687d00000000049c74758",
        0x1fe9d:"41c741780400000041c681d0", 0x820d:"c7477804000000c687d00000",
        0x81df:"c7477804000000c687d10000", 0x1f9ac:"58c3488d15bb070200be0900",
        0xcf71:"4883bc24e001000000488bb4", 0x26da7:"4d89f9eb2fb8010000004c29",
        0x26cba:"4c8b4c2410e91701000048c7",
        0xd37c:"4889d64885c0480f44f0e909", 0xc608:"4883c41041c64424380041f7",
        0x154b4:"4883c410c643380041f7c600", 0xc8f3:"488b4424704883f80a0f847f",
        0x20940:"554157415641554154534883", 0x15600:"41574156415453504889f349",
    }
    symbols = {
        "finish_context_switch":0xb560, "dispatch_syscall":0xc2b0,
        "_ZN4main6frames12SharedFrames4with17hb00e6cb9ee26f98cE":0x15ae0,
        "_ZN4main9scheduler5Queue9terminate17h78822d9be4f1dcb7E":0x203e0,
        "_ZN4main9scheduler5Queue7wake_io17h73db3196f0f37af5E":0x1fe50,
        "_ZN4main3smp3Cpu6switch17hb7417c7cd214c040E":0x7e00,
        "_ZN4main9scheduler5Queue11block_child17ha7a88421d688fc3aE":0x1f960,
        "_ZN4main5files11Descriptors7message17haa9559fe4cf1fe18E":0x26a60,
        "_ZN4main6frames12SharedFrames4with17h5e0295aa47836cd7E":0x15450,
        "_ZN4main6frames12SharedFrames4with17h731fd3ed52612c53E":0x15600,
        "_ZN4main9scheduler5Queue14moveRunnableTo17heb15b9282e1d5070E":0x20940,
        "_ZN4main3smp5gCpus17h5763cf52e37c3718E":0x424c0,
        "_ZN4main3smp12gOnlineCount17he11f3f5949bf833aE.0":0x42cd0,
        "_ZN4main3smp11gMigrations17h0099a42543e68e47E":0x42cd8,
    }
    observed={}
    for line in capture("nm","-n",str(kernel_path)).splitlines():
        fields=line.split()
        if len(fields)==3 and re.fullmatch("[0-9a-fA-F]+",fields[0]):
            observed[fields[2]]=int(fields[0],16)
    require(all(observed.get(name)==address for name,address in symbols.items()),
            "Kernel symbol identity mismatch")
    def instructions(path):
        result={}
        for line in capture("objdump","-d","-M","intel","--no-show-raw-insn",str(path)).splitlines():
            match=re.match(r"^\s*([0-9a-f]+):\s+(.+)$",line)
            if match:
                result[int(match[1],16)]=match[2].strip()
        return result
    kd,ud=instructions(kernel_path),instructions(runner_path)
    for offset,expected in code.items():
        require(offset in kd and kernel[0x1000+offset:0x1000+offset+12].hex()==expected,
                f"Kernel instruction/offset mismatch: {offset:#x}")
    # The sample syscall's return and each actual call-return PC, not a later
    # instruction on its successful branch. The user ELF is stripped.
    user={0x49:"c80f054989c14885c075dbb8100001",
          0xa3a:"00ffd085c0750ab842000000e96e14",
          0x1080:"41ffd485c0750abf50000000e9ba03",
          0x11f9:"00ffd085c0750abf53000000e94102",
          0x12fe:"41ffd4bf4900000085c00f843d0100",
          0x13c8:"41ffd485c074e7488b450048398424",
          0x1bc1:"00ffd085c074de48b8503040008000"}
    u=0x8000400000
    for offset,expected in user.items():
        require(u+offset in ud and runner[0x1000+offset-3:0x1000+offset+12].hex()==expected,
                f"Supervisor sample return mismatch: {offset:#x}")
    page=runner[0x1000:0x2000]
    require(hashlib.sha256(page).hexdigest()=="9b83d9ab1e63d586e8c3c9c0aaea6aa367db2935bdf358ce170562924e99a1a5" and
            all(p.read_bytes()[0x1000:0x2000]!=page for p in runner_path.parent.glob("*-runner") if p!=runner_path),
            "Supervisor entry page is not distinct from other staged runners")
    return {"kernel_symbols":symbols,
            "kernel_code":{hex(a):{"bytes":b,"instruction":kd[a]} for a,b in code.items()},
            "supervisor_returns":{hex(a):{"bytes_from_minus3":b,"instruction":ud[u+a]} for a,b in user.items()},
            "entry_page_sha256":hashlib.sha256(page).hexdigest(),
            "collect_boundary":"kernel_collect_result (not userland return)"}

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
        HERE/"run.py", HERE/"trace.py", HERE/"test_mailbox.py", ROOT/"scripts/qemu-smoke.py",
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
                smoke.session.SUPERVISOR_INPUT == ARM_INPUT and
                hasattr(smoke.session.SHELL_START, "finditer"),
                "Original wrapper/harness interface changed")
        receipt["stage"] = "arm_command"
        receipt["arm"] = verify_arm(smoke)
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
        for name in ("git", "bash", "gcc-13", "ld", "objcopy", "objdump", "nm", "rustc",
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
        receipt["stage"] = "mailbox_host_test"
        command = [sys.executable, str(HERE/"test_mailbox.py")]
        result = subprocess.run(command, cwd=ROOT, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, text=True, timeout=30)
        receipt["mailbox_host_test"] = {"command": command, "returncode": result.returncode,
                                        "output": result.stdout}
        require(result.returncode == 0, "Host mailbox callback regression failed")
        receipt["stage"] = "tracer_interface"
        source = (HERE/"trace.py").read_text()
        compile(source, str(HERE/"trace.py"), "exec")
        constants = {}
        for node in ast.parse(source).body:
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name) and target.id in ("SITES", "CALLS"):
                        constants[target.id] = ast.literal_eval(node.value)
        receipt["symbol_evidence"] = verify_symbols(constants)
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
            receipt.get("mailbox_host_test", {}).get("returncode") == 0 and
            receipt.get("arm") == {"command": ARM_COMMAND, "input_hex": ARM_INPUT.hex(),
                                   "profile": PROFILE, "smoke_args": SMOKE_ARGS} and
            receipt.get("symbol_evidence", {}).get("entry_page_sha256") ==
            "9b83d9ab1e63d586e8c3c9c0aaea6aa367db2935bdf358ce170562924e99a1a5" and
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
        "arm_command": ARM_COMMAND, "profile": PROFILE, "smoke_args": SMOKE_ARGS,
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
    verify_arm(smoke)
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
                    require(command[command.index("-machine")+1]=="q35,accel=tcg,smm=on,hpet=on" and
                            command[command.index("-smp")+1]=="2" and command[command.index("-m")+1]=="256" and
                            any(str(DEST/"esp.raw") in str(arg) for arg in command), "Wrong HPET supervisor guest profile")
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
                if arm_requested(command):
                    state["attach_count"] += 1
                    if state["attach_count"] != 1:
                        raise RuntimeError("Supervisor trace may attach exactly once")
                    transcript = self.destination.read_bytes()
                    bases = re.findall(rb"\[INFO\] KERNEL IMAGE BASE=([0-9a-f]{16})", transcript)
                    shells = list(smoke.session.SHELL_START.finditer(transcript))
                    clocks = re.findall(rb"(?m)^\[INFO\] SYSTEM CLOCK: (HPET64|HPET32)\r?$", transcript)
                    if len(bases) != 1 or len(shells) != 1 or len(clocks)!=1:
                        raise RuntimeError("missing unique actual kernel base/shell/HPET clock")
                    request = {"base": int(bases[0], 16), "shell": int(shells[0][1],16),
                               "destination": str(DEST), "root": str(ROOT),
                               "arm_command": ARM_COMMAND, "profile": PROFILE,
                               "runner_sha256": EXPECTED["build/supervisor-staging/supervisor-runner"],
                               "clock": clocks[0].decode("ascii")}
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
        sys.argv = ["qemu-smoke.py", *SMOKE_ARGS]
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
            print("Supervisor diagnostic result:", json.dumps(result, sort_keys=True), flush=True)
        return 0 if status == 0 and result["result"]=="recorded" and result["gdb_returncode"]==0 else 1

if __name__ == "__main__":
    if sys.argv[1:] == ["--preflight"]:
        raise SystemExit(preflight())
    if sys.argv[1:]:
        raise SystemExit("Expected no arguments or --preflight")
    raise SystemExit(run())
