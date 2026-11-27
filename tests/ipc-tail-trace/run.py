#!/usr/bin/env python3
"""A single diagnostic session, not a replacement acceptance harness.

Run the original signed qemu-smoke implementation and original criteria.
Only this wrapper adds the existing QEMU GDB chardev and records UART
timestamps. Attach immediately before the ordinary IPC command, after
all preceding foreground programs have returned. No guest image edits.
"""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time

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

def run():
    DEST.mkdir(parents=True, exist_ok=True)
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

    spec = importlib.util.spec_from_file_location("original_smoke", ROOT/"scripts/qemu-smoke.py")
    smoke = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(smoke)
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
    raise SystemExit(run())
