"""Supplementary real QEMU NVMe NVM I/O, flush and two cold OVMF boots.

Use a new raw fixture only; never accept a host block device or existing image.
This is separate from mandatory VirtualBox and physical hardware acceptance.
"""
import argparse
import importlib.util
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import time

sys.dont_write_bytecode = True
from ahci_block_evidence import create, BYTES
from nvme_block_evidence import expected_disk, verify_guest, require

ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location("qemu_smoke", ROOT / "scripts/qemu-smoke.py")
smoke = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(smoke)


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def backend_stats(records):
    devices = [entry for entry in records if entry.get("device") == "nvdata"]
    require(len(devices) == 1, "QMP did not identify exactly one nvdata backend")
    stats = devices[0]["stats"]
    keys = ("rd_bytes", "wr_bytes", "rd_operations", "wr_operations", "flush_operations")
    require(all(type(stats.get(key)) is int and stats[key] >= 0 for key in keys),
            "Missing NVMe backend counters")
    for key in ("failed_rd_operations", "failed_wr_operations", "failed_flush_operations",
                "invalid_rd_operations", "invalid_wr_operations", "invalid_flush_operations"):
        require(stats.get(key, 0) == 0, f"NVMe backend reported {key}")
    return {key: stats[key] for key in keys}


def verify_stats(before, after, phase):
    # QEMU 8.2.2 hw/nvme/ctrl.c:nvme_flush_ns_cb calls blk_aio_flush
    # without block_acct_start(BLOCK_ACCT_FLUSH). Its QMP flush counter is
    # therefore insufficient. verify_trace independently requires the actual
    # namespace flush and successful completion in the emulator itself.
    start, stop = backend_stats(before), backend_stats(after)
    delta = {key: stop[key] - start[key] for key in start}
    require(all(value >= 0 for value in delta.values()), "QMP block counters regressed")
    require(delta["rd_bytes"] == BYTES and delta["rd_operations"] == 2,
            "QEMU backend did not complete the two expected reads")
    if phase == "write":
        require(delta["wr_bytes"] == BYTES and delta["wr_operations"] == 2,
                f"QEMU backend did not complete the two writes: {delta}")
    else:
        require(phase == "read" and delta["wr_bytes"] == delta["wr_operations"] == 0 and
                delta["flush_operations"] == 0, "Read boot issued unexpected writes or flush")
    require(start["wr_bytes"] == start["wr_operations"] == 0,
            "Unexpected backend write before explicit phase command")
    return delta


TRACE_EVENTS = (
    "pci_nvme_io_cmd",
    "pci_nvme_flush_ns",
    "pci_nvme_enqueue_req_completion",
)
TRACE_PREFIX = r"^(?:\d+@\d+\.\d+:)?"
TRACE_IO = re.compile(TRACE_PREFIX +
    r"pci_nvme_io_cmd cid (\d+) nsid 0x([0-9a-f]+) sqid (\d+) opc 0x([0-9a-f]+) opname '[^']*'$")
TRACE_FLUSH = re.compile(TRACE_PREFIX + r"pci_nvme_flush_ns nsid 0x([0-9a-f]+)$")
TRACE_CQ = re.compile(TRACE_PREFIX +
    r"pci_nvme_enqueue_req_completion cid (\d+) cqid (\d+) dw0 0x[0-9a-f]+ dw1 0x[0-9a-f]+ status 0x([0-9a-f]+)$")


def verify_trace(text, phase):
    """Match actual controller-side commands and CQ success before power-off.

    QEMU's admin queues (qid 0), including firmware traffic, are not I/O
    evidence. Reject missing/malformed records, unrelated namespace/queue
    traffic, premature completions, failed statuses and read-phase writes.
    Never synthesize a trace from the guest transcript or QMP counters.
    """
    events = []
    for line in text.splitlines():
        if m := TRACE_IO.fullmatch(line):
            cid, nsid, sqid, opcode = m.groups()
            events.append(("io", int(cid), int(nsid, 16), int(sqid), int(opcode, 16)))
        elif m := TRACE_FLUSH.fullmatch(line):
            events.append(("flush", int(m[1], 16)))
        elif m := TRACE_CQ.fullmatch(line):
            cid, cqid, status = m.groups()
            if int(cqid) != 0:
                events.append(("cq", int(cid), int(cqid), int(status, 16)))
        elif any(name + " " in line for name in TRACE_EVENTS):
            raise ValueError(f"Unrecognized QEMU NVMe trace line: {line!r}")
    require(phase in ("write", "read"), "Invalid NVMe trace phase")
    expected = []
    ops = (2, 2, 2, 1, 1, 0) if phase == "write" else (2, 2, 2)
    for cid, opcode in enumerate(ops, 1):
        expected.append(("io", cid, 1, 1, opcode))
        if opcode == 0:
            expected.append(("flush", 1))
        expected.append(("cq", cid, 1, 0))
    require(events == expected,
            f"Independent NVMe controller trace mismatch: expected {expected!r}, observed {events!r}")
    return {"io_commands": len(ops), "flush_commands": ops.count(0),
            "successful_completions": len(ops)}


def check_attachment(qmp, raw, guest):
    blocks = qmp.execute("query-block")
    devices = [entry for entry in blocks if entry.get("device") == "nvdata"]
    require(len(devices) == 1, "Missing dedicated QEMU NVMe backend")
    inserted = devices[0]["inserted"]
    require(inserted["drv"] == "raw" and
            Path(inserted["file"]).resolve() == raw.resolve() and
            inserted["ro"] is False and inserted["cache"]["no-flush"] is False,
            "Wrong NVMe backend or flush disabled")
    pci = qmp.execute("query-pci")

    def walk(devices):
        for device in devices:
            yield device
            if "pci_bridge" in device:
                yield from walk(device["pci_bridge"].get("devices", []))

    matches = [d for bus in pci for d in walk(bus["devices"])
               if d.get("qdev_id") == "agentos-nvme"]
    require(len(matches) == 1, "Missing real NVMe PCI function in QMP")
    d = matches[0]
    require(d["class_info"]["class"] == 0x0108, "QMP device is not NVMe")
    bdf = f"0000:{d['bus']:02x}:{d['slot']:02x}.{d['function']}"
    expected = f"AGENTOS PCI DEV {bdf} ID={d['id']['vendor']:04x}:{d['id']['device']:04x} CLASS=010802 "
    require(guest.count(expected) == 1, "Guest NVMe identity differs from QMP PCI configuration")
    return {"block": blocks, "pci": pci, "bdf": bdf}


def wait_guest(process, capture, serial, marker, seconds):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if capture.error is not None:
            raise RuntimeError(f"Real COM1 capture stopped: {capture.error}")
        content = serial.read_bytes() if serial.exists() else b""
        if re.search(rb"AGENTOS PCI FAILED|SMP FAILED|FATAL VECTOR|SHELL FAILED", content):
            raise RuntimeError("Guest reported an actual kernel failure")
        if marker in content:
            return content
        if process.poll() is not None:
            raise RuntimeError(f"QEMU exited prematurely: {process.returncode}")
        time.sleep(0.025)
    raise TimeoutError(f"Missing real guest marker {marker!r}")


def phase(args, out, raw, vars_file, esp, mode, expected_details):
    name = "write" if mode == b"W" else "read"
    folder = out / name
    folder.mkdir()
    serial = folder / "com1.log"
    monitor = None
    capture = None
    started = time.monotonic()
    with tempfile.TemporaryDirectory(prefix="agentos-nvme-") as sock_dir:
        uart_path = Path(sock_dir) / "uart"
        qmp_path = Path(sock_dir) / "qmp"
        hmp_path = Path(sock_dir) / "hmp"
        trace_events = folder / "trace-events.txt"
        trace_events.write_text("\n".join(TRACE_EVENTS) + "\n", encoding="ascii")
        trace = folder / "nvme-trace.log"
        cmd = [
            "qemu-system-x86_64", "-trace", f"events={trace_events}", "-D", str(trace), "-machine", "q35,accel=tcg,smm=on,hpet=on",
            "-cpu", "max", "-smp", str(args.cpus), "-m", "256",
            "-global", "driver=cfi.pflash01,property=secure,value=on",
            "-drive", f"if=pflash,format=raw,unit=0,readonly=on,file={args.ovmf_code}",
            "-drive", f"if=pflash,format=raw,unit=1,file={vars_file}",
            "-drive", f"if=none,format=raw,id=esp,file={esp}",
            "-device", "ich9-ahci,id=sata",
            "-device", "ide-hd,drive=esp,bus=sata.0,bootindex=1",
            "-drive", f"if=none,format=raw,id=nvdata,file={raw},cache=writeback",
            "-device", "nvme,id=agentos-nvme,serial=AgentOS-Test,drive=nvdata",
            "-chardev", f"socket,id=uart,path={uart_path},server=on,wait=on",
            "-serial", "chardev:uart", "-qmp", f"unix:{qmp_path},server=on,wait=off",
            "-monitor", f"unix:{hmp_path},server=on,wait=off",
            "-display", "none", "-vga", "std", "-nic", "none", "-boot", "order=c",
            "-no-reboot", "-no-shutdown",
        ]
        write_json(folder / "command.json", cmd)
        with (folder / "qemu-stderr.log").open("wb") as diagnostic:
            process = subprocess.Popen(cmd, cwd=ROOT, stdin=subprocess.DEVNULL,
                                       stdout=diagnostic, stderr=subprocess.STDOUT)
            try:
                capture = smoke.UartCapture(smoke.connect_uart(uart_path, process), serial)
                print(f"QEMU NVMe {name} boot, {args.cpus} vCPU", flush=True)
                ready = wait_guest(process, capture, serial,
                                   b"AGENTOS BLOCK READY BLOCKS=16384 SIZE=512\r\n", args.timeout)
                monitor = smoke.Qmp(qmp_path)
                # Host independently identifies the NVMe controller and its actual
                # backend; capture counters before sending the explicit W/R byte.
                attachment = check_attachment(monitor, raw, ready.decode("ascii", errors="replace"))
                write_json(folder / "attachment.json", attachment)
                before = monitor.execute("query-blockstats")
                write_json(folder / "stats-before.json", before)
                capture.send(mode)
                data = wait_guest(process, capture, serial,
                                  b"AGENTOS NVME CLOSED RDY=0 MASTER=0 DMA=5\r\n", 60)
                verify_guest(data.decode("ascii", errors="replace"), name, expected_details)
                after = monitor.execute("query-blockstats")
                write_json(folder / "stats-after.json", after)
                print(f"QEMU NVMe {name} QMP stats: {backend_stats(before)} -> {backend_stats(after)}",
                      flush=True)
                delta = verify_stats(before, after, name)
                # Capture the controller trace before quit, so a teardown
                # flush cannot be mistaken for an acknowledged guest command.
                trace_before_quit = trace.read_text("utf-8", errors="strict")
                trace_result = verify_trace(trace_before_quit, name)
                (folder / "nvme-trace-before-quit.log").write_text(trace_before_quit, encoding="utf-8")
                if name == "read":
                    # Demonstrate that the fresh kernel can proceed beyond the
                    # controller teardown and actually bring up all configured CPUs.
                    data = wait_guest(process, capture, serial,
                                      b"AGENTOS SHELL READY\r\nagentos> ", args.timeout)
                    text = data.decode("ascii", errors="replace")
                    smoke.boot_log.verify(data, "info", "both")
                    apics = re.findall(r"(?m)^AGENTOS TASK (?:BSP|AP) APIC=([0-9a-f]{16}) "
                                       r"TIMER-WAKES=0000000000000003\r?$", text)
                    require(len(apics) == args.cpus and len(set(apics)) == args.cpus,
                            "Missing real per-CPU timer evidence after NVMe close")
                    smoke.processes.verify(text, [int(x, 16) for x in apics], ipc_staged=True, root_orphan_v1=True)
                    smoke.supervisor.verify_absent(text)
                    smoke.orphans.verify(text, args.cpus)
                    smoke.cow.verify_absent(text)
                    smoke.demand.verify_absent(text)
                    smoke.migration.verify_boot(text)
                    smoke.service_manager.verify(text,migration_staged=True)
                    monitor.screenshot(folder / "shell-screen.ppm")
                    smoke.console.verify(folder / "shell-screen.ppm", aLevel="info", aOutput="both")
                # Stop the emulator process, not a guest reset or snapshot.
                # The second invocation uses the same raw file and varstore.
                monitor.execute("quit")
                require(process.wait(timeout=15) == 0, "QEMU did not exit cleanly")
                result = {"phase": name, "qemu_pid": process.pid,
                          "exit_code": process.returncode, "backend_delta": delta,
                          "controller_trace": trace_result, "bdf": attachment["bdf"], "seconds": round(time.monotonic()-started, 3)}
                write_json(folder / "phase.json", result)
                print(f"QEMU NVMe {name}: {json.dumps(result)}", flush=True)
                return result
            except Exception:
                smoke.snapshot(hmp_path, folder / "failure.ppm")
                tail = serial.read_bytes()[-4096:] if serial.exists() else b""
                print("QEMU NVMe COM1 failure tail:\n" + tail.decode("ascii", errors="replace"),
                      file=sys.stderr, flush=True)
                raise
            finally:
                if monitor is not None:
                    monitor.close()
                if capture is not None:
                    capture.close()
                if process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=10)


def run(args):
    sha = smoke.evidence.sha256
    commit = subprocess.check_output(["git", "rev-parse", "--verify", "HEAD"], cwd=ROOT, text=True).strip()
    build = smoke.evidence.verify_build(ROOT, commit)
    require(build.get("profile") == "nvme-block", "Build with scripts/build.sh --nvme-block first")
    root = ROOT / "build/check" / f"qemu-nvme-cpu{args.cpus}"
    root.mkdir(parents=True, exist_ok=True)
    out = Path(tempfile.mkdtemp(prefix="run-", dir=root))
    print(f"QEMU_NVME_DIR={out}", flush=True)
    try:
        subprocess.run(["bash", "scripts/disk.sh", str(out), "build/agentos.efi", "info both"],
                       cwd=ROOT, check=True)
        esp = out / "esp.raw"
        copied = out / "esp-bootx64.efi"
        subprocess.run(["mcopy", "-i", f"{esp}@@1048576", "::EFI/BOOT/BOOTX64.EFI", str(copied)], check=True)
        require(sha(copied) == build["artifacts"]["agentos.efi"], "ESP differs from signed EFI")
        vars_file = out / "OVMF_VARS.secboot.fd"
        cert = Path.home() / ".local/share/agentos/stage1-test-keys/db.crt"
        owner = "d7663630-f07a-4739-bc6f-b9f6d6444865"
        subprocess.run(["virt-fw-vars", "--input", str(args.ovmf_vars), "--output", str(vars_file),
                        "--set-pk", owner, str(cert), "--add-kek", owner, str(cert),
                        "--add-db", owner, str(cert), "--secure-boot"], check=True)
        der = subprocess.check_output(["openssl", "x509", "-in", str(cert), "-outform", "der"])
        require(der in vars_file.read_bytes(), "Missing enrolled EFI signer")
        initial = out / "block.raw"
        raw = out / "nvme.raw"
        create(initial)
        shutil.copyfile(initial, raw)
        expected, details = expected_disk(initial)
        first = phase(args, out, raw, vars_file, esp, b"W", details)
        require(raw.read_bytes() == expected, "Full disk differs after write boot")
        shutil.copyfile(raw, out / "block-after.raw")
        require(der in vars_file.read_bytes(), "Cold reboot lost the enrolled signer")
        second = phase(args, out, raw, vars_file, esp, b"R", details)
        require(raw.read_bytes() == expected, "Read boot modified the disk")
        require(first["bdf"] == second["bdf"], "NVMe PCI address changed between boots")
        shutil.copyfile(raw, out / "block-read-after.raw")
        files = ("block.raw", "block-after.raw", "block-read-after.raw", "esp-bootx64.efi",
                 "OVMF_VARS.secboot.fd", "write/phase.json", "read/phase.json",
                 "write/com1.log", "read/com1.log", "write/stats-before.json",
                 "write/stats-after.json", "read/stats-before.json", "read/stats-after.json",
                 "write/attachment.json", "read/attachment.json", "write/com1-input.bin",
                 "read/com1-input.bin", "read/shell-screen.ppm", "write/command.json", "read/command.json",
                 "write/nvme-trace-before-quit.log", "read/nvme-trace-before-quit.log",
                 "write/nvme-trace.log", "read/nvme-trace.log",
                 "write/trace-events.txt", "read/trace-events.txt")
        result = {"schema": 1, "result": "pass", "source_commit": commit, "cpus": args.cpus,
                  "emulator": subprocess.check_output(["qemu-system-x86_64", "--version"], text=True).splitlines()[0],
                  "signed_efi_sha256": build["artifacts"]["agentos.efi"], "details": details,
                  "ovmf_code_sha256": sha(args.ovmf_code), "phases": [first, second],
                  "artifacts": {name: sha(out / name) for name in files}}
        write_json(out / "nvme.json", result)
        print("QEMU_NVME_PASS=" + json.dumps(result, sort_keys=True), flush=True)
    except Exception as error:
        write_json(out / "failure.json", {"result": "fail", "source_commit": commit,
                                           "cpus": args.cpus, "failure": str(error)})
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cpus", type=int, choices=(1, 2), required=True)
    parser.add_argument("--ovmf-code", type=Path, required=True)
    parser.add_argument("--ovmf-vars", type=Path, required=True)
    parser.add_argument("--timeout", type=int, default=300)
    args = parser.parse_args()
    try:
        run(args)
    except Exception as error:
        print(f"QEMU NVMe failed: {error}", file=sys.stderr, flush=True)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
