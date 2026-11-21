"""Supplementary *real guest boot* in QEMU TCG with UEFI Secure Boot.

This is NOT the mandatory VirtualBox 7.1.12 acceptance. It boots the same
signed EFI on an independent emulator, checks process, IPC and PID1 evidence
on real COM1. --session additionally sends real bytes through QEMU's emulated
16550 UART, validates authenticated interactive shell service control and
clean root-manager shutdown, but does not claim PS/2/GOP acceptance.
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
service_manager = load("qemu_service_manager_evidence", "verify-service-manager.py")
boot_log = load("qemu_boot_log_evidence", "verify-boot-log.py")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cpus", type=int, choices=(1, 2), required=True)
    parser.add_argument("--session", action="store_true",
                        help="Drive real COM1 services/exit commands and prove clean shutdown")
    parser.add_argument("--timeout", type=int, default=720)
    parser.add_argument("--ovmf-code", type=Path, required=True)
    parser.add_argument("--ovmf-vars", type=Path, required=True)
    args = parser.parse_args()
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
        client.setblocking(False)
        return client
    raise TimeoutError("QEMU 16550 UART was not ready for a real COM1 session")


def capture_uart(client, destination):
    """Drain actual transmitted UART bytes into the same integrity-checked log."""
    with destination.open("ab") as log:
        for _ in range(128):
            try:
                packet = client.recv(65536)
            except BlockingIOError:
                break
            if not packet:
                raise RuntimeError("QEMU real COM1 channel closed during guest boot")
            log.write(packet)


def send_uart_command(client, command):
    if command not in (b"services\r", b"exit\r"):
        raise ValueError("Only fixed acceptance commands may be sent")
    client.settimeout(5)
    try:
        client.sendall(command)
    finally:
        client.setblocking(False)


def boot(args):
    root = ROOT
    commit = subprocess.check_output(["git", "rev-parse", "--verify", "HEAD"],
                                     cwd=root, text=True).strip()
    image = evidence.verify_build(root, commit)
    destination = root / "build/check" / (
        f"qemu-cpu{args.cpus}-session" if args.session else f"qemu-cpu{args.cpus}")
    destination.mkdir(parents=True, exist_ok=True)
    raw = destination / "esp.raw"
    if raw.exists():
        raw.unlink()
    subprocess.run(["bash", "scripts/disk.sh", str(destination),
                    "build/agentos.efi", "info both"], cwd=root, check=True)
    # Independently re-read the exact signed EFI from the ESP. A GPT image
    # that merely exists is not evidence its fallback boot file was copied.
    copied = destination / "esp-bootx64.efi"
    if copied.exists():
        copied.unlink()
    subprocess.run(["mcopy", "-i", f"{raw}@@1048576",
                    "::EFI/BOOT/BOOTX64.EFI", str(copied)], check=True)
    if evidence.sha256(copied) != image["artifacts"]["agentos.efi"]:
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
        "-machine", "q35,accel=tcg,smm=on",
        "-cpu", "max", "-smp", str(args.cpus), "-m", "256",
        "-global", "driver=cfi.pflash01,property=secure,value=on",
        "-drive", f"if=pflash,format=raw,unit=0,readonly=on,file={args.ovmf_code}",
        "-drive", f"if=pflash,format=raw,unit=1,file={vm_vars}",
        "-drive", f"if=none,format=raw,id=esp,file={raw}",
        "-device", "ich9-ahci,id=sata",
        "-device", "ide-hd,drive=esp,bus=sata.0",
        "-monitor", f"unix:{monitor_socket},server=on,wait=off",
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
    interactive_stage = 0
    interactive_start = None
    serial_link = None
    with stdout.open("wb") as diagnostic:
        process = subprocess.Popen(qemu, cwd=root, stdin=subprocess.DEVNULL,
                                   stdout=diagnostic, stderr=subprocess.STDOUT)
        try:
            if args.session:
                serial_link = connect_uart(serial_socket, process)
            while time.monotonic() - start < args.timeout:
                if serial_link is not None:
                    capture_uart(serial_link, serial)
                content = serial.read_bytes() if serial.exists() else b""
                if len(content) != last_size:
                    last_size = len(content)
                    last_progress = time.monotonic()
                if b"SMP FAILED:" in content or b"FATAL VECTOR" in content or b"SHELL FAILED" in content:
                    raise RuntimeError("Guest reported critical kernel failure; see COM1")
                if b"AGENTOS SHELL READY\r\nagentos> " in content and interactive_stage == 0:
                    snapshot(monitor_socket, destination / "shell-screen.ppm")
                    if not args.session:
                        run_succeeded = True
                        break
                    interactive_start = time.monotonic()
                    time.sleep(0.25)
                    send_uart_command(serial_link, b"services\r")
                    interactive_stage = 1
                if interactive_stage == 1 and (
                    b"core: running (attempts=1)\r\n" in content and
                    b"flaky: failed (attempts=3)\r\n" in content and
                    b"shell: running (attempts=1)\r\nagentos> " in content
                ):
                    send_uart_command(serial_link, b"exit\r")
                    interactive_stage = 2
                if interactive_stage == 2 and re.search(
                    rb"AGENTOS MANAGER SESSION STOP PID=[0-9a-f]{16} "
                    rb"STATUS=0000000000000000 FRAMES=OK\r\n", content):
                    run_succeeded = True
                    break
                if interactive_start is not None and time.monotonic()-interactive_start > 45:
                    raise TimeoutError(
                        f"COM1 interactive session stalled at stage {interactive_stage} "
                        "for more than 45 host seconds")
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
                "cpu_count": args.cpus, "failure": str(error),
                "last_com1_bytes": tail,
                "host_elapsed_seconds": round(time.monotonic() - start, 3),
                "signed_efi_sha256": image["artifacts"]["agentos.efi"],
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
            if fatal and kernel_elf.is_file():
                rip = int(fatal[1], 16)
                disasm = subprocess.run(
                    ["objdump", "-drwC", f"--start-address={max(0,rip-128)}",
                     f"--stop-address={rip+192}", str(kernel_elf)],
                    capture_output=True, text=True, check=False)
                print("Kernel ELF instructions near fatal RIP:\n" + disasm.stdout,
                      file=sys.stderr, flush=True)
            raise
        finally:
            if serial_link is not None:
                try:
                    capture_uart(serial_link, serial)
                except OSError:
                    pass
                serial_link.close()
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=10)
    text = serial.read_text(encoding="ascii", errors="replace")
    boot_log.verify(text.encode("ascii", errors="replace"), "info", "both")
    marker = re.compile(r"(?m)^AGENTOS TASK (?:BSP|AP) APIC=([0-9a-f]{16}) "
                        r"TIMER-WAKES=0000000000000003$")
    apics = [int(x, 16) for x in marker.findall(text)]
    if len(apics) != args.cpus or len(set(apics)) != args.cpus:
        raise RuntimeError(f"Missing per-CPU APIC timer evidence: {apics}")
    processes.verify(text, apics)
    supervisor.verify(text, args.cpus)
    orphans.verify(text, args.cpus)
    cow.verify(text, args.cpus)
    service_manager.verify(text)
    if args.session:
        session = load("qemu_manager_session_evidence", "verify-manager-session.py")
        session.verify(serial.read_bytes())
    receipt = {
        "schema": 1,
        "result": "pass",
        "emulator": "QEMU TCG with OVMF Secure Boot",
        "source_commit": commit,
        "cpus": args.cpus,
        "interactive_com1_manager_session": args.session,
        "host_elapsed_seconds": round(time.monotonic()-start, 3),
        "signed_efi_sha256": image["artifacts"]["agentos.efi"],
        "ovmf_code_sha256": evidence.sha256(args.ovmf_code),
        "esp_sha256": evidence.sha256(raw),
        "esp_boot_efi_sha256": evidence.sha256(copied),
        "com1_sha256": evidence.sha256(serial),
        "firmware_vars_sha256_after_boot": evidence.sha256(vm_vars),
    }
    (destination / "smoke.json").write_text(
        json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"QEMU Secure Boot smoke OK: {args.cpus} CPUs, "
          f"COM1 session={args.session}, "
          f"{receipt['host_elapsed_seconds']} s, commit {commit}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
