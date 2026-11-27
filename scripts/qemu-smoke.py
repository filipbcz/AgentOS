"""Supplementary *real guest boot* in QEMU TCG with UEFI Secure Boot.

This is NOT the mandatory VirtualBox 7.1.12 acceptance. It boots the same
signed EFI on an independent emulator, checks process, IPC and PID1 evidence
on real COM1. --session additionally drives the emulated 16550 UART and PS/2
keyboard, verifies actual GOP glyphs, START/STOP/RESTART, runtime idle timer
counts and clean manager shutdown. It does not claim VirtualBox acceptance.
Every failure is recorded, never converted into a success by a timeout.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import socket
import time
import threading


# Loading sibling evidence modules must not leave untracked bytecode in the
# source checkout; a later VirtualBox acceptance requires a clean tree.
sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parent.parent


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


evidence = load("qemu_build_evidence", "verify-vm-evidence.py")
processes = load("qemu_process_evidence", "verify-processes.py")
supervisor = load("qemu_supervisor_evidence", "verify-supervisor.py")
orphans = load("qemu_orphan_evidence", "verify-orphans.py")
cow = load("qemu_cow_evidence", "verify-cow.py")
demand = load("qemu_demand_evidence", "verify-demand-paging.py")
migration = load("qemu_migration_evidence", "verify-migration.py")
service_manager = load("qemu_service_manager_evidence", "verify-service-manager.py")
boot_log = load("qemu_boot_log_evidence", "verify-boot-log.py")
session = load("qemu_stage3_session", "verify-stage3-session.py")
console = load("qemu_console_image", "verify-console-image.py")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cpus", type=int, choices=(1, 2), required=True)
    parser.add_argument("--memory-mib", type=int, choices=(256, 512), default=256)
    parser.add_argument("--no-hpet", action="store_true", help="Disable HPET in actual QEMU hardware")
    parser.add_argument("--accel", choices=("tcg","kvm"), default="tcg",
                        help="Use real KVM for matching control runs; ordinary regression defaults to TCG")
    parser.add_argument("--session", action="store_true",
                        help="Drive UART/PS2 editing, service control, runtime idle and shutdown")
    parser.add_argument("--runtime-process-regression", action="store_true",
                        help="Separate foreground ELF/fault regression through the ordinary shell")
    parser.add_argument("--supervisor-image", choices=("control","test"),
                        help="Host-only paired signed image regression")
    parser.add_argument("--timeout", type=int, default=720)
    parser.add_argument("--ovmf-code", type=Path, required=True)
    parser.add_argument("--ovmf-vars", type=Path, required=True)
    args = parser.parse_args()
    if args.runtime_process_regression and not args.session:
        parser.error("--runtime-process-regression requires --session")
    if args.supervisor_image and not args.runtime_process_regression:
        parser.error("--supervisor-image requires --session --runtime-process-regression")
    try:
        return boot(args)
    except Exception as error:
        print(f"QEMU Secure Boot smoke test failed: {error}", file=sys.stderr)
        return 1


def snapshot(monitor, dest):
    # Capture the guest's real GOP screen, even if UEFI refuses the EFI.
    # A screenshot is evidence, not proof of successful boot on its own.
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.settimeout(3)
            client.connect(str(monitor))
            client.recv(4096)
            client.sendall(f"screendump {dest}\n".encode("ascii"))
            client.recv(4096)
        return dest.exists() and dest.stat().st_size > 64
    except (OSError, UnicodeError):
        return False


def connect_uart(path, process):
    """Attach to a real emulated 16550 COM1, not a fabricated transcript."""
    until = time.monotonic() + 20
    while time.monotonic() < until:
        if process.poll() is not None:
            raise RuntimeError("QEMU quit before its COM1 UART socket was ready")
        client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            client.connect(str(path))
        except OSError:
            client.close()
            time.sleep(0.05)
            continue
        client.settimeout(0.2)
        return client
    raise TimeoutError("QEMU 16550 UART was not ready for a real COM1 session")


class UartCapture:
    """Continuously drain a real 16550 guest COM1 UART while the CPU runs.

    Reading only every 250ms lost actual kernel output and could stall QEMU's
    socket back-end. A dedicated reader makes the capture backpressure-free.
    Writes go directly to an unbuffered file consumed by strict verifiers;
    no expected transcript bytes are ever synthesized.
    """
    def __init__(self, link, destination):
        self.link = link
        self.destination = destination
        self.stop = threading.Event()
        self.error = None
        self.worker = threading.Thread(target=self._read, daemon=True)
        self.worker.start()

    def _read(self):
        try:
            with self.destination.open("wb", buffering=0) as log:
                while not self.stop.is_set():
                    try:
                        packet = self.link.recv(65536)
                    except socket.timeout:
                        continue
                    if not packet:
                        raise RuntimeError("Emulated UART disconnected before session complete")
                    log.write(packet)
        except (OSError, RuntimeError) as error:
            if not self.stop.is_set():
                self.error = error

    def send(self, command):
        if self.error is not None:
            raise RuntimeError(f"UART reader stopped: {self.error}")
        # A paced, real UART stream exercises the canonical input path and
        # cannot overflow the emulated 16550 before its IRQ drains the FIFO.
        with self.destination.with_name("com1-input.bin").open("ab", buffering=0) as sent:
            for byte in command:
                packet = bytes([byte])
                self.link.sendall(packet)
                sent.write(packet)
                time.sleep(0.002)

    def close(self):
        self.stop.set()
        try:
            self.link.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self.worker.join(timeout=3)
        self.link.close()
        if self.worker.is_alive():
            raise RuntimeError("UART capture thread did not stop")


class Qmp:
    """Small QMP client; input is delivered to QEMU's emulated keyboard."""
    def __init__(self, path):
        self.link = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.link.settimeout(5)
        self.link.connect(str(path))
        self.file = self.link.makefile("rwb", buffering=0)
        self.sequence = 0
        greeting = self._receive()
        if "QMP" not in greeting:
            raise RuntimeError("QEMU did not send its QMP greeting")
        self.execute("qmp_capabilities")

    def _receive(self):
        line = self.file.readline(1024 * 1024)
        if not line or not line.endswith(b"\n"):
            raise RuntimeError("Truncated or disconnected QMP response")
        return json.loads(line)

    def execute(self, name, arguments=None):
        self.sequence += 1
        command = {"execute": name, "id": self.sequence}
        if arguments is not None:
            command["arguments"] = arguments
        self.file.write(json.dumps(command).encode("ascii") + b"\r\n")
        until = time.monotonic() + 10
        while time.monotonic() < until:
            response = self._receive()
            if "event" in response:
                continue
            if response.get("id") != self.sequence:
                raise RuntimeError("QMP reply ID does not match the request")
            if "error" in response:
                raise RuntimeError(f"QMP {name}: {response['error']}")
            if "return" not in response:
                raise RuntimeError(f"Invalid QMP {name} response")
            return response["return"]
        raise TimeoutError(f"QMP {name} did not complete")

    def screenshot(self, path):
        path.unlink(missing_ok=True)
        self.execute("screendump", {"filename": str(path)})
        if not path.is_file():
            raise RuntimeError("QEMU did not capture its actual guest framebuffer")

    def keyboard(self, command):
        # QMP send-key accepts QKeyCode, including explicit Backspace/Return.
        # https://www.qemu.org/docs/master/interop/qemu-qmp-ref.html#command-send-key
        special = {" ": "spc", "-": "minus", "\b": "backspace", "\r": "ret"}
        for char in command + "\r":
            if char not in special and not re.fullmatch("[a-z0-9]", char):
                raise ValueError(f"Unsupported acceptance keyboard character: {char!r}")
            self.execute("send-key", {"keys": [{"type": "qcode", "data": special.get(char, char)}],
                                      "hold-time": 20})
            time.sleep(0.06)

    def close(self):
        self.file.close()
        self.link.close()


def wait_session(process, capture, serial, predicate, description, seconds=30):
    until = time.monotonic() + seconds
    while time.monotonic() < until:
        if capture.error is not None:
            raise RuntimeError(f"UART capture stopped: {capture.error}")
        content = serial.read_bytes()
        if re.search(rb"SMP FAILED|FATAL VECTOR|SHELL FAILED", content):
            raise RuntimeError("Guest failed during the interactive session")
        if predicate(content):
            return content
        if process.poll() is not None:
            raise RuntimeError("QEMU exited during the interactive session")
        time.sleep(0.025)
    raise TimeoutError(f"Interactive guest did not complete {description}")


def run_session(process, capture, qmp, destination, runtime_process_regression=False,
                supervisor_image=None):
    serial = destination / "com1.log"
    children = list(session.SHELL_START.finditer(serial.read_bytes()))
    if len(children) != 1:
        raise RuntimeError("Cannot identify the real managed shell")
    shell = int(children[0][1], 16)
    if runtime_process_regression:
        for command, status in session.RUNTIME_PROGRAMS:
            offset = serial.stat().st_size
            print(f"QEMU separate runtime process regression: {command!r}", flush=True)
            capture.send((command+"\r").encode("ascii"))
            reply = f"exit status {status}\r\nagentos> ".encode("ascii")
            wait_session(process, capture, serial,
                         lambda data: reply in data[offset:], command, 30)
    if supervisor_image is not None:
        for command,request in ((session.SUPERVISOR_COMMAND,session.SUPERVISOR_INPUT),
                                (session.PIPE_COMMAND,session.PIPE_INPUT),
                                *((command,(command+"\r").encode("ascii"))
                                  for command in session.MEMORY_COMMANDS)):
            offset = serial.stat().st_size
            print(f"QEMU {supervisor_image} signed image: {command!r}", flush=True)
            capture.send(request)
            reply = (session.SUPERVISOR_MISSING if supervisor_image=="control"
                     else b"exit status 0\r\nagentos> ")
            wait_session(process, capture, serial,
                         lambda data: reply in data[offset:], command, 30)
        offset=serial.stat().st_size
        print(f"QEMU {supervisor_image} signed image: {session.ADOPTION_COMMAND!r}",flush=True)
        capture.send(session.ADOPTION_INPUT)
        if supervisor_image=="test":
            for step,status in ((1,57),(2,58),(3,59)):
                wait=re.compile(rb"AGENTOS ADOPTION TEST WAIT STEP="+f"{step:016x}".encode()+
                                rb" PID=([0-9a-f]{16})\r\n")
                def collected(data):
                    view=data[offset:]
                    match=wait.search(view)
                    if not match:
                        return False
                    record=(b"AGENTOS MANAGER REAP ROOT=0000000000000001 PID="+match[1]+
                            b" STATUS="+f"{status:016x}".encode()+b"\r\n")
                    return record in view
                wait_session(process,capture,serial,collected,f"actual PID1 collection at adoption gate {step}",30)
                capture.send(session.ADOPTION_BYTES[step-1:step])
        reply=(session.SUPERVISOR_MISSING if supervisor_image=="control"
               else b"exit status 0\r\nagentos> ")
        wait_session(process,capture,serial,lambda data: reply in data[offset:],
                     session.ADOPTION_COMMAND,30)
    for step in session.steps(shell, True):
        if step["screenshot"]:
            qmp.screenshot(destination / "keyboard-before.ppm")
        offset = serial.stat().st_size
        print(f"QEMU session: {step['transport']} {step['command']!r}", flush=True)
        if step["transport"] == "keyboard":
            qmp.keyboard(step["command"])
        else:
            capture.send((step["command"] + "\r").encode("ascii"))
        pattern = re.compile(step["pattern"].encode("ascii"))
        wait_session(process, capture, serial,
                     lambda data: pattern.search(session.without_kernel_events(data[offset:])),
                     step["command"], 45 if step["command"] == "idle" else 30)
        if step["wait_exits"]:
            wait_session(process, capture, serial,
                         lambda data: len(list(session.EXIT.finditer(data[offset:]))) >= step["wait_exits"],
                         "autonomous bounded service restart")
        if step["screenshot"]:
            qmp.screenshot(destination / "keyboard-after.ppm")
            console.verify(destination / "keyboard-after.ppm", destination / "keyboard-before.ppm",
                           "ps2-ok", "info", "both")
    wait_session(process, capture, serial, lambda data: session.SESSION_STOP.search(data),
                 "frame-clean manager shutdown")
    # BOOT.LOG is enabled for QEMU. Wait for the final real write rather than
    # closing the UART immediately after the preceding native stop record.
    wait_session(process, capture, serial, lambda data: data.endswith(b"[INFO] INTERACTIVE SHELL STOPPED\r\n"),
                 "final structured completion log")


def boot(args):
    root = ROOT
    commit = subprocess.check_output(["git", "rev-parse", "--verify", "HEAD"],
                                     cwd=root, text=True).strip()
    image = evidence.verify_build(root, commit)
    image_path = "build/agentos.efi"
    image_sha = image["artifacts"]["agentos.efi"]
    supervisor_image = getattr(args, "supervisor_image", None)
    if supervisor_image is not None:
        if not args.session or not getattr(args, "runtime_process_regression", False):
            raise ValueError("Supervisor pair requires the full foreground and shell regressions")
        paired = load("supervisor_image_evidence", "verify-supervisor-image.py")
        identity = paired.verify_identity(root)
        if supervisor_image=="test":
            image_path = "build/supervisor-staging/test.efi"
            image_sha = identity["test"]["signed_sha256"]
    profile = f"qemu-cpu{args.cpus}"
    if args.memory_mib != 256:
        profile += f"-ram{args.memory_mib}"
    if args.no_hpet:
        profile += "-no-hpet"
    if args.accel != "tcg":
        profile += "-"+args.accel
    if args.session:
        profile += "-session"
    if supervisor_image is not None:
        profile += "-sv-"+supervisor_image
    elif getattr(args, "runtime_process_regression", False):
        profile += "-runtime-process-regression"
    destination = root / "build/check" / profile
    destination.mkdir(parents=True, exist_ok=True)
    if supervisor_image is not None:
        for name in ("smoke.json", "failure.json"):
            (destination/name).unlink(missing_ok=True)
    raw = destination / "esp.raw"
    if raw.exists():
        raw.unlink()
    subprocess.run(["bash", "scripts/disk.sh", str(destination),
                    image_path, "info both"], cwd=root, check=True)
    # Independently re-read the exact signed EFI from the ESP. A GPT image
    # that merely exists is not evidence its fallback boot file was copied.
    copied = destination / "esp-bootx64.efi"
    if copied.exists():
        copied.unlink()
    subprocess.run(["mcopy", "-i", f"{raw}@@1048576",
                    "::EFI/BOOT/BOOTX64.EFI", str(copied)], check=True)
    if evidence.sha256(copied) != image_sha:
        raise RuntimeError("EFI on QEMU ESP differs from the signed build output")
    vm_vars = destination / "OVMF_VARS.secboot.fd"
    if vm_vars.exists():
        vm_vars.unlink()
    cert = Path.home() / ".local/share/agentos/stage1-test-keys/db.crt"
    # Avoid convenience enrollment shortcuts: define the exact authority
    # chain explicitly. The same isolated test certificate signs the EFI and
    # is inserted as PK, KEK and db with the db.esl owner GUID from build.sh.
    # Firmware rejecting BOOTX64.EFI before kernel entry must be debuggable.
    owner = "d7663630-f07a-4739-bc6f-b9f6d6444865"
    subprocess.run(["virt-fw-vars",
                    "--input", str(args.ovmf_vars),
                    "--output", str(vm_vars),
                    "--set-pk", owner, str(cert),
                    "--add-kek", owner, str(cert),
                    "--add-db", owner, str(cert),
                    "--secure-boot"], check=True)
    assert vm_vars.is_file() and vm_vars.stat().st_size > 0
    # Ensure the exact X.509 DER bytes are really inside the generated flash.
    der = subprocess.check_output(["openssl", "x509", "-in", str(cert),
                                   "-outform", "der"])
    if der not in vm_vars.read_bytes():
        raise RuntimeError("QEMU OVMF Secure Boot NVRAM is missing our signed EFI certificate")
    # Record exactly what firmware was provisioned with, before OVMF alters
    # its NVRAM. The image is known signed; Access Denied may instead mean its
    # signer was never enrolled in db or SecureBoot/SetupMode is inconsistent.
    variables = subprocess.run(["virt-fw-vars", "--input", str(vm_vars),
                                "--print", "--verbose"],
                               check=True, capture_output=True, text=True)
    (destination / "secureboot-vars.txt").write_text(
        variables.stdout + variables.stderr, encoding="utf-8")
    monitor_socket = destination / "qemu-monitor.sock"
    monitor_socket.unlink(missing_ok=True)
    qmp_socket = destination / "qemu-qmp.sock"
    qmp_socket.unlink(missing_ok=True)
    (destination / "com1-input.bin").unlink(missing_ok=True)
    serial = destination / "com1.log"
    serial_socket = destination / "real-com1.sock"
    if args.session:
        serial_socket.unlink(missing_ok=True)
        # wait=on prevents losing early signed-firmware messages before the
        # capture client is connected. Data and input pass through the guest's
        # real emulated 16550 controller, including UART interrupts.
        serial_options = ["-chardev",
                          f"socket,id=uart,path={serial_socket},server=on,wait=on",
                          "-serial", "chardev:uart"]
    else:
        serial_options = ["-serial", f"file:{serial}"]
    qemu = [
        "qemu-system-x86_64",
        "-machine", f"q35,accel={args.accel},smm=on,hpet=" + ("off" if args.no_hpet else "on"),
        "-cpu", "host,x2apic=off,invtsc=on,enforce=on" if args.accel=="kvm" else "max",
        "-smp", str(args.cpus), "-m", str(args.memory_mib),
        "-global", "driver=cfi.pflash01,property=secure,value=on",
        "-drive", f"if=pflash,format=raw,unit=0,readonly=on,file={args.ovmf_code}",
        "-drive", f"if=pflash,format=raw,unit=1,file={vm_vars}",
        "-drive", f"if=none,format=raw,id=esp,file={raw}",
        "-device", "ich9-ahci,id=sata",
        "-device", "ide-hd,drive=esp,bus=sata.0",
        "-monitor", f"unix:{monitor_socket},server=on,wait=off",
        "-qmp", f"unix:{qmp_socket},server=on,wait=off",
        "-vga", "std", "-display", "none", *serial_options,
        "-nic", "none", "-boot", "order=c", "-no-reboot", "-no-shutdown",
    ]
    stdout = destination / "qemu-stderr.log"
    if serial.exists():
        serial.unlink()
    start = time.monotonic()
    last_progress = start
    last_size = -1
    run_succeeded = False
    actual_kvm = None
    qmp = None
    (destination / "qemu-command.json").write_text(json.dumps(qemu,indent=2)+"\n")
    serial_capture = None
    with stdout.open("wb") as diagnostic:
        process = subprocess.Popen(qemu, cwd=root, stdin=subprocess.DEVNULL,
                                   stdout=diagnostic, stderr=subprocess.STDOUT)
        try:
            if args.session:
                serial_capture = UartCapture(connect_uart(serial_socket, process), serial)
            while time.monotonic() - start < args.timeout:
                if serial_capture is not None and serial_capture.error is not None:
                    raise RuntimeError(f"Real UART capture stopped: {serial_capture.error}")
                content = serial.read_bytes() if serial.exists() else b""
                if len(content) != last_size:
                    last_size = len(content)
                    last_progress = time.monotonic()
                if b"SMP FAILED:" in content or b"FATAL VECTOR" in content or b"SHELL FAILED" in content:
                    raise RuntimeError("Guest reported critical kernel failure; see COM1")
                if b"AGENTOS SHELL READY\r\nagentos> " in content:
                    qmp = Qmp(qmp_socket)
                    actual_kvm=qmp.execute("query-kvm")
                    if bool(actual_kvm["enabled"]) != (args.accel=="kvm"):
                        raise RuntimeError("Unexpected actual accelerator")
                    qmp.screenshot(destination / "shell-screen.ppm")
                    console.verify(destination / "shell-screen.ppm", aLevel="info", aOutput="both")
                    if args.session:
                        run_session(process, serial_capture, qmp, destination,
                                    getattr(args, "runtime_process_regression", False), supervisor_image)
                    run_succeeded = True
                    break
                if process.poll() is not None:
                    snapshot(destination / "qemu-monitor.sock", destination / "failed-screen.ppm")
                    raise RuntimeError(f"QEMU exited before shell became ready: {process.returncode}")
                if time.monotonic() - last_progress > 180:
                    raise TimeoutError(
                        "Guest COM1 stopped making progress for 180 seconds "
                        f"(last {len(content)} bytes); inspect firmware/guest screenshot")
                time.sleep(0.25)
            if not run_succeeded:
                raise TimeoutError(f"Guest did not reach shell in {args.timeout} host seconds")
        except Exception as error:
            snapshot(destination / "qemu-monitor.sock", destination / "failed-screen.ppm")
            tail = (serial.read_bytes()[-4096:].decode("ascii", errors="replace")
                    if serial.exists() else "")
            failure = {
                "schema": 1, "result": "fail", "source_commit": commit,
                "cpu_count": args.cpus, "memory_mib": args.memory_mib,
                "hpet_enabled": not args.no_hpet, "accelerator":args.accel,
                "failure": str(error),
                "last_com1_bytes": tail,
                "host_elapsed_seconds": round(time.monotonic() - start, 3),
                "signed_efi_sha256": image_sha,
            }
            (destination / "failure.json").write_text(
                json.dumps(failure, indent=2, sort_keys=True) + "\n",
                encoding="utf-8")
            # CI must expose fatal guest details without requiring privileged
            # artifact access. Bound the output to the captured final 4KiB.
            print("QEMU COM1 failure tail:\n" + tail, file=sys.stderr, flush=True)
            fatal = re.search(r"FATAL VECTOR=[0-9a-f]{16} ERROR=[0-9a-f]{16} "
                              r"RIP=([0-9a-f]{16})", tail)
            kernel_elf = root / "build/kernel.elf"
            base_match = None
            if serial.exists():
                with serial.open("rb") as captured:
                    base_match = re.search(rb"\[INFO\] KERNEL IMAGE BASE=([0-9a-f]{16})\r?\n",
                                           captured.read(65536))
            if fatal and kernel_elf.is_file() and base_match:
                rip, base = int(fatal[1], 16), int(base_match[1], 16)
                if base <= rip < base + 16*1024*1024:
                    disasm = subprocess.run(
                        ["objdump", "-drwC", f"--adjust-vma={base}",
                         f"--start-address={max(base,rip-128)}",
                         f"--stop-address={rip+192}", str(kernel_elf)],
                        capture_output=True, text=True, check=False)
                    print("Relocated kernel ELF instructions near fatal RIP:\n" + disasm.stdout,
                          file=sys.stderr, flush=True)
            raise
        finally:
            if qmp is not None:
                qmp.close()
            if serial_capture is not None:
                serial_capture.close()
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=10)
    text = serial.read_text(encoding="ascii", errors="replace")
    boot_log.verify(text.encode("ascii", errors="replace"), "info", "both")
    if text.splitlines().count("AGENTOS KERNEL STACK GUARD OK") != 1:
        raise RuntimeError("Missing actual guarded kernel stack fault-probe evidence")
    marker = re.compile(r"(?m)^AGENTOS TASK (?:BSP|AP) APIC=([0-9a-f]{16}) "
                        r"TIMER-WAKES=0000000000000003$")
    apics = [int(x, 16) for x in marker.findall(text)]
    if len(apics) != args.cpus or len(set(apics)) != args.cpus:
        raise RuntimeError(f"Missing per-CPU APIC timer evidence: {apics}")
    processes.verify(text, apics)
    if supervisor_image!="test":
        supervisor.verify_absent(text)
    # The test image must pass the full authenticated runtime session below.
    orphans.verify(text, args.cpus)
    # Staged memory evidence belongs exclusively to the strict foreground
    # verifier below. Every other profile must lack it entirely.
    if supervisor_image!="test":
        cow.verify_absent(text)
        demand.verify_absent(text)
    migration_result = migration.verify(text, args.cpus)
    service_manager.verify(text)
    session_result = None
    if args.session:
        session_result = session.verify(serial.read_bytes(), (destination / "com1-input.bin").read_bytes(),
                                        True, args.cpus,
                                        aRuntimeProcess=getattr(args,"runtime_process_regression",False),
                                        aSupervisorImage=supervisor_image)
    bases = re.findall(r"(?m)^\[INFO\] KERNEL IMAGE BASE=([0-9a-f]{16})\r?$", text)
    if len(bases) != 1:
        raise RuntimeError(f"Expected one actual runtime kernel image address: {bases}")
    image_base = int(bases[0], 16)
    if image_base < 4096 or image_base % 4096 or image_base >= 1 << 39:
        raise RuntimeError(f"Invalid runtime kernel image address: {image_base:#x}")
    clocks = re.findall(r"(?m)^\[INFO\] SYSTEM CLOCK: (HPET64|HPET32|ACPI PM24|ACPI PM32)\r?$", text)
    if len(clocks) != 1:
        raise RuntimeError(f"Missing unique system clock selection: {clocks}")
    if args.no_hpet and not clocks[0].startswith("ACPI PM"):
        raise RuntimeError("Actual no-HPET guest did not use the ACPI PM timer")
    receipt = {
        "schema": 1,
        "result": "pass",
        "emulator": f"QEMU {args.accel.upper()} with OVMF Secure Boot",
        "accelerator":args.accel,"qmp_kvm":actual_kvm,
        "qemu_version":subprocess.check_output(["qemu-system-x86_64","--version"],text=True).splitlines()[0],
        "source_commit": commit,
        "cpus": args.cpus,
        "memory_mib": args.memory_mib,
        "kernel_image_base": image_base,
        "hpet_enabled": not args.no_hpet,
        "system_clock": clocks[0],
        "interactive_com1_manager_session": args.session,
        "ps2_keyboard_session": args.session,
        "runtime_session": session_result,
        "migration": migration_result,
        "gop_sha256": evidence.sha256(destination / "shell-screen.ppm"),
        "host_elapsed_seconds": round(time.monotonic()-start, 3),
        "signed_efi_sha256": image_sha,
        "ovmf_code_sha256": evidence.sha256(args.ovmf_code),
        "esp_sha256": evidence.sha256(raw),
        "esp_boot_efi_sha256": evidence.sha256(copied),
        "com1_sha256": evidence.sha256(serial),
        "firmware_vars_sha256_after_boot": evidence.sha256(vm_vars),
    }
    if supervisor_image is not None:
        receipt["supervisor_image"] = supervisor_image
    if args.session:
        receipt["com1_input_sha256"] = evidence.sha256(destination / "com1-input.bin")
        receipt["ps2_before_sha256"] = evidence.sha256(destination / "keyboard-before.ppm")
        receipt["ps2_after_sha256"] = evidence.sha256(destination / "keyboard-after.ppm")
    (destination / "smoke.json").write_text(
        json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"QEMU Secure Boot smoke OK: {args.cpus} CPUs, "
          f"COM1 session={args.session}, "
          f"{receipt['host_elapsed_seconds']} s, commit {commit}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
