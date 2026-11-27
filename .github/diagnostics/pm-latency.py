"""One-off host/guest PM latency diagnosis; never an acceptance substitute."""
import bisect
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import sys
import time

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "build/pm-latency"
BASE = "6661155688a7780da9f609a95bcafa1d6d60f60b"
EXPECTED = {
    "kernel.elf": "64cb6b044589aee4ded9e9815b2d97937b9a7a8128ba055e91adf7994527c09e",
    "initramfs.cpio": "f47386603d9022a0124866525fcc74b3530d1ccfe3edca3a90a8b3bef6ccdbd1",
    "agentos.unsigned.efi": "ac817772221305d452c405a686c574eb1469fd9775db88f9e15559a3c19abbf4",
    "supervisor-staging/loader.o": "d0abfce715fe6c643569dc5c70d1b06800ddbf969f77790ac84319c7c78e6023",
    "supervisor-staging/layout.ld": "86069c283841fb20c5c464cbb9122b66ec1aa58340789bd3e27db755c43fc054",
    "supervisor-staging/supervisor.o": "51655bca953c257a6a8061eb7be048c9bc9d05575676613e3646af3661b0d4a6",
    "supervisor-staging/pipe-runner": "68628b93c78c54c1dabd81072f7f4a04a388988b93042d39754edf397515e84d",
    "supervisor-staging/pipe-receiver": "c3d487c71a7dbc51b3b1a9e887fbe357ff388c4ca3d3a74fbc4eeef3a391ff89",
}
OLD_RUNNER = "29204eedf0f068e7b6dd751c62fdb60543904145cafb955c7685eebf464593c4"
CAP = 131072  # per direction, per boot; bounded RAM, no live sidecar disk I/O
FW = "/usr/share/OVMF/OVMF_CODE_4M.secboot.fd"
VARS = "/usr/share/OVMF/OVMF_VARS_4M.fd"


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def require(ok, why):
    if not ok:
        raise RuntimeError(why)


def sha(path):
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def save(path, obj):
    path.write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n")


def prepare():
    # Keep the branch's product and existing test sources untouched.
    # Only in the isolated runner checkout, commit a diagnostic failure branch
    # so the existing clean-tree build/identity verifiers remain authoritative.
    OUT.mkdir(parents=True, exist_ok=True)
    changed = subprocess.check_output(["git", "diff", "--name-only", BASE, "HEAD"], cwd=ROOT, text=True).splitlines()
    require(set(changed) <= {"PLAN_IMPLEMENTACE.md", ".github/diagnostics/pm-latency.py",
                            ".github/workflows/qemu-pm-latency-probe.yml"},
            "Unexpected change relative to the tested product")
    original = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    path = ROOT / "scripts/tests/supervisor-runner.c"
    old = """    if (ms<0 || ms>gDeadline-(run?runReserveMs:0) ||
        !selectCandidate(gPids[slot],apic,run) || !postReadySend(slot,round,run?runCommand:stopCommand,apic)) return -1;"""
    new = """#ifndef PIPE_WORKLOAD
    const long limit=gDeadline-(run?runReserveMs:0);
    if (ms<0 || ms>limit) {
        const char *const names[]={" ROOT="," PID="," ROUND="," RUN="," NOW="," LIMIT="," DEADLINE="};
        const unsigned long v[]={gRoot,(unsigned long)gPids[slot],round,(unsigned long)run,
                                 (unsigned long)ms,(unsigned long)limit,(unsigned long)gDeadline};
        (void)record("START_REJECT",names,v,7);
        return -1;
    }
    if (!selectCandidate(gPids[slot],apic,run) || !postReadySend(slot,round,run?runCommand:stopCommand,apic)) return -1;
#else
""" + old + "\n#endif"
    source = path.read_text()
    require(source.count(old) == 1, "Expected unique controller guard")
    path.write_text(source.replace(old, new))
    patch = subprocess.check_output(["git", "diff", "--", str(path.relative_to(ROOT))], cwd=ROOT)
    (OUT / "diagnostic.patch").write_bytes(patch)
    subprocess.run(["git", "add", str(path.relative_to(ROOT))], cwd=ROOT, check=True)
    subprocess.run(["git", "-c", "user.name=AgentOS diagnostic", "-c", "user.email=diagnostic@invalid",
                    "commit", "-m", "Local-only supervisor rejected-start observation"], cwd=ROOT, check=True)
    save(OUT / "source.json", {"product": BASE, "workflow_checkout": original,
         "diagnostic_checkout": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
         "source_tree": subprocess.check_output(["git", "rev-parse", "HEAD^{tree}"], cwd=ROOT, text=True).strip(),
         "patch_sha256": sha(OUT / "diagnostic.patch")})


def identity():
    images = load("scripts/verify-supervisor-image.py", "probe_images")
    current = images.verify_identity(ROOT)  # re-read actual signed PE/CPIO and independently relink
    build = ROOT / "build"
    measured = {name: sha(build / name) for name in EXPECTED}
    require(measured == EXPECTED, "Non-diagnostic payload differs from 66611556")
    actual_runner = sha(build / "supervisor-staging/supervisor-runner")
    require(actual_runner != OLD_RUNNER, "Missing diagnostic supervisor ELF")
    require(current["runner_sha256"] == actual_runner, "Staged runner mismatch")
    info = {"expected": EXPECTED, "actual": measured, "original_runner": OLD_RUNNER,
            "diagnostic_runner": actual_runner, "staged_cpio": sha(build/"supervisor-staging/test.cpio"),
            "identity_sha256": sha(build/"supervisor-staging/identity.json"), "identity": current}
    save(OUT/"payload-comparison.json", info)
    print("Verified identical non-diagnostic payloads:", json.dumps(info["actual"], sort_keys=True), flush=True)


class TimedSocket:
    """Transparent socket proxy; UartCapture still owns every raw read/write."""
    def __init__(self, sock):
        self.sock = sock
        self.rx, self.tx = [], []
        self.rx_offset = self.tx_offset = 0
        self.rx_overflow = self.tx_overflow = False

    def __getattr__(self, name):
        return getattr(self.sock, name)

    def recv(self, *args, **kwargs):
        before = time.monotonic_ns()
        data = self.sock.recv(*args, **kwargs)
        after = time.monotonic_ns()
        if data:
            if len(self.rx) < CAP:
                self.rx.append((self.rx_offset, len(data), before, after))
            else:
                self.rx_overflow = True
            self.rx_offset += len(data)
        return data

    def sendall(self, data, *args, **kwargs):
        before = time.monotonic_ns()
        self.sock.sendall(data, *args, **kwargs)
        after = time.monotonic_ns()
        if len(self.tx) < CAP:
            self.tx.append((self.tx_offset, len(data), before, after))
        else:
            self.tx_overflow = True
        self.tx_offset += len(data)


def check_rows(rows, size):
    at = 0
    previous = -1
    for offset, length, before, after in rows:
        require(offset == at and length > 0 and previous <= before <= after,
                "Timing rows not contiguous/monotonic")
        at += length
        previous = after
    require(at == size, "Sidecar does not cover exactly the untouched raw file")


def correlate(folder, link, keyboard, start, end, rc):
    log = (folder/"com1.log").read_bytes() if (folder/"com1.log").is_file() else b""
    sent = (folder/"com1-input.bin").read_bytes() if (folder/"com1-input.bin").is_file() else b""
    sidecar = {"schema": 1, "clock": "time.monotonic_ns", "columns": ["offset", "length", "before_ns", "after_ns"],
               "clock_resolution_s": time.get_clock_info("monotonic").resolution,
               "clock_implementation": time.get_clock_info("monotonic").implementation,
               "limit_per_direction": CAP, "boot_call_start_ns": start, "boot_call_end_ns": end,
               "rc": rc, "keyboard": keyboard, "capture_connected": link is not None,
               "rx": link.rx if link else [], "tx": link.tx if link else [],
               "rx_overflow": link.rx_overflow if link else False, "tx_overflow": link.tx_overflow if link else False,
               "com1_sha256": hashlib.sha256(log).hexdigest(), "input_sha256": hashlib.sha256(sent).hexdigest()}
    save(folder/"com1-timing.json", sidecar)  # always preserve, including failures
    require(link is not None and not link.rx_overflow and not link.tx_overflow, "Missing or overflowing timing sidecar")
    check_rows(link.rx, len(log))
    check_rows(link.tx, len(sent))
    require(bool(link.rx), "No received COM1 bytes")
    ends = [r[0]+r[1] for r in link.rx]

    def locate(a, b):
        # Exact first/last overlapping recv blocks. The return timestamps
        # observe the delivery to Python, NOT guest execution or UART TX.
        i, j = bisect.bisect_right(ends, a), bisect.bisect_right(ends, b-1)
        first, last = link.rx[i], link.rx[j]
        return {"offset": a, "length": b-a, "first_block": i, "last_block": j,
                "first_recv_before_ns": first[2], "first_recv_after_ns": first[3],
                "last_recv_before_ns": last[2], "last_recv_after_ns": last[3],
                "first_block_bytes": first[1], "last_block_bytes": last[1]}

    records = []
    for match in re.finditer(rb"[^\n]*\n|[^\n]+$", log):
        line = match[0].decode("ascii", "replace").rstrip("\r\n")
        if not any(k in line for k in ("AGENTOS TEST ", "AGENTOS SERVICE DURATION", "AGENTOS PIPE TEST ",
               "AGENTOS USER EXIT", "AGENTOS USER KILL", "AGENTOS IDLE", "SYSTEM CLOCK:",
               "exit status ", "agentos> ", "FRAMES=OK", "INTERACTIVE SHELL STOPPED")):
            continue
        record = {"line": line, **locate(match.start(), match.end())}
        field = re.search(r"\bMS=([0-9a-f]{16})\b", line)
        if field:
            record["guest_ms"] = int(field[1], 16)
        records.append(record)
    commands = []
    at = 0
    # Original UartCapture sends one byte at a time, with 2ms pacing.
    for command in sent.splitlines(keepends=True):
        # splitlines on bytes recognizes LF/CR, includes the actual terminator.
        if not command:
            continue
        last = at+len(command)-1
        require(link.tx[at][0]==at and link.tx[last][0]==last and
                all(row[1]==1 for row in link.tx[at:last+1]), "Unexpected UART send granularity")
        commands.append({"command": command.decode("ascii", "replace"), "offset": at, "length": len(command),
                         "first_send_before_ns": link.tx[at][2], "last_send_after_ns": link.tx[last][3]})
        at += len(command)
    require(at == len(sent), "Incomplete serial command reconstruction")
    summary = {"records": records, "commands": commands,
               "rx_blocks": len(link.rx), "rx_bytes": len(log), "max_rx_block": max(r[1] for r in link.rx),
               "max_recv_call_ns": max(r[3]-r[2] for r in link.rx), "tx_blocks": len(link.tx),
               "tx_bytes": len(sent), "clock_resolution_s": sidecar["clock_resolution_s"],
               "sidecar_sha256": sha(folder/"com1-timing.json"),
               "com1_sha256": sidecar["com1_sha256"], "input_sha256": sidecar["input_sha256"],
               "limitations": "recv return is host observation; queue backlog, host scheduling and UART/GOP output can delay/batch guest events. WAIT_ENTER is logged retrospectively. Same block has no within-block time resolution. No guaranteed guest-to-host latency bound."}
    save(folder/"correlated.json", summary)
    print(folder.name, json.dumps({k:v for k,v in summary.items() if k not in ("records","commands")}, sort_keys=True), flush=True)
    for r in records:
        if "AGENTOS TEST " in r["line"] or "AGENTOS IDLE " in r["line"] or "exit status " in r["line"]:
            print(f'RX {r["offset"]}+{r["length"]} block={r["first_block"]}:{r["last_block"]} '
                  f'host_end_ns={r["last_recv_after_ns"]} {r["line"]}', flush=True)


def run():
    identity()
    smoke = load("scripts/qemu-smoke.py", "probe_smoke")
    original_connect = smoke.connect_uart
    original_keyboard = smoke.Qmp.keyboard
    results = {}
    for variant in ("control", "test"):
        # Identical full session inputs. Control must reject the absent staged
        # runners; test must actually run both through the normal shell.
        folder = ROOT / "build/check" / f"qemu-cpu2-no-hpet-kvm-session-sv-{variant}"
        folder.mkdir(parents=True, exist_ok=True)
        links, keyboard = [], []

        def connect(*args, **kwargs):
            require(not links, "Unexpected second UART capture")
            proxy = TimedSocket(original_connect(*args, **kwargs))
            links.append(proxy)
            return proxy

        def key(qmp, command):
            before = time.monotonic_ns()
            try:
                return original_keyboard(qmp, command)
            finally:
                keyboard.append({"command": command, "before_ns": before, "after_ns": time.monotonic_ns()})

        smoke.connect_uart = connect
        smoke.Qmp.keyboard = key
        sys.argv = ["qemu-smoke.py", "--cpus", "2", "--accel", "kvm", "--no-hpet", "--session",
                    "--runtime-process-regression", "--supervisor-image", variant,
                    "--ovmf-code", FW, "--ovmf-vars", VARS, "--timeout", "180"]
        start = time.monotonic_ns()
        rc = 1
        try:
            rc = smoke.main()
        finally:
            end = time.monotonic_ns()
            smoke.connect_uart = original_connect
            smoke.Qmp.keyboard = original_keyboard
            try:
                correlate(folder, links[0] if links else None, keyboard, start, end, rc)
                # Re-read the actual boot file from the ESP even on a failed guest.
                extracted = folder/"postboot-bootx64.efi"
                subprocess.run(["mcopy","-i",str(folder/"esp.raw")+"@@1048576",
                                "::EFI/BOOT/BOOTX64.EFI",str(extracted)],check=True)
                expected = ROOT/"build"/("agentos.efi" if variant=="control" else "supervisor-staging/test.efi")
                require(sha(extracted)==sha(expected), "Actual ESP differs from signed image")
                # Profile and clock must match, never silently accept another source.
                raw = (folder/"com1.log").read_bytes()
                require(raw.count(b"[INFO] SYSTEM CLOCK: ACPI PM24\r\n")==1,
                        "Not the exact historical PM24 profile")
                results[variant] = {"smoke_rc": rc, "timing_valid": True, "actual_efi_sha256": sha(extracted)}
            except Exception as e:
                print("Diagnostic evidence incomplete:", e, file=sys.stderr, flush=True)
                results[variant] = {"smoke_rc": rc, "timing_valid": False, "error": str(e)}
            save(OUT/"results.json", results)
    return 0 if all(v["smoke_rc"]==0 and v["timing_valid"] for v in results.values()) else 1


if __name__ == "__main__":
    if sys.argv[1:] == ["prepare"]:
        prepare()
    elif sys.argv[1:] == ["run"]:
        sys.exit(run())
    else:
        raise SystemExit("prepare or run required")
