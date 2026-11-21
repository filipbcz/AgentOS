"""Supplementary *real guest boot* in QEMU TCG with UEFI Secure Boot.

This is NOT the mandatory VirtualBox 7.1.12 acceptance. It boots the same
signed EFI on an independent emulator, checks process, IPC and PID1 evidence
on real COM1, then exits at the shell-ready boundary (without PS/2/GOP tests).
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
boot_log = load("qemu_boot_log_evidence", "verify-boot-log.py")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cpus", type=int, choices=(1, 2), required=True)
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


def boot(args):
    root = ROOT
    commit = subprocess.check_output(["git", "rev-parse", "--verify", "HEAD"],
                                     cwd=root, text=True).strip()
    image = evidence.verify_build(root, commit)
    destination = root / "build/check" / f"qemu-cpu{args.cpus}"
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
    subprocess.run(["virt-fw-vars",
                    "--input", str(args.ovmf_vars),
                    "--output", str(vm_vars),
                    "--enroll-cert", str(cert), "--sb"], check=True)
    assert vm_vars.is_file() and vm_vars.stat().st_size > 0
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
        "-monitor", f"unix:{destination / 'qemu-monitor.sock'},server=on,wait=off",
        "-vga", "std", "-display", "none", "-serial",
        f"file:{destination / 'com1.log'}",
        "-nic", "none", "-boot", "order=c", "-no-reboot", "-no-shutdown",
    ]
    stdout = destination / "qemu-stderr.log"
    serial = destination / "com1.log"
    if serial.exists():
        serial.unlink()
    start = time.monotonic()
    last_progress = start
    last_size = -1
    run_succeeded = False
    with stdout.open("wb") as diagnostic:
        process = subprocess.Popen(qemu, cwd=root, stdin=subprocess.DEVNULL,
                                   stdout=diagnostic, stderr=subprocess.STDOUT)
        try:
            while time.monotonic() - start < args.timeout:
                content = serial.read_bytes() if serial.exists() else b""
                if len(content) != last_size:
                    last_size = len(content)
                    last_progress = time.monotonic()
                if b"SMP FAILED:" in content or b"FATAL VECTOR" in content or b"SHELL FAILED" in content:
                    raise RuntimeError("Guest reported critical kernel failure; see COM1")
                if b"AGENTOS SHELL READY\r\nagentos> " in content:
                    run_succeeded = True
                    snapshot(destination / "qemu-monitor.sock", destination / "shell-screen.ppm")
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
                "cpu_count": args.cpus, "failure": str(error),
                "last_com1_bytes": tail,
                "host_elapsed_seconds": round(time.monotonic() - start, 3),
                "signed_efi_sha256": image["artifacts"]["agentos.efi"],
            }
            (destination / "failure.json").write_text(
                json.dumps(failure, indent=2, sort_keys=True) + "\n",
                encoding="utf-8")
            raise
        finally:
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
    receipt = {
        "schema": 1,
        "result": "pass",
        "emulator": "QEMU TCG with OVMF Secure Boot",
        "source_commit": commit,
        "cpus": args.cpus,
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
          f"{receipt['host_elapsed_seconds']} s, commit {commit}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
