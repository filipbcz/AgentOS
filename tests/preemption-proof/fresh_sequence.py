"""Fresh single-host 1/2/4/8 receipt linkage, NOT a layout or guest verifier.

Use the existing preflight/result receipts. The caller supplies the independently
verified candidate (git commit/tree, basic.verify_image control, checked layout
hash, symbols and runtime bytes) and a mandatory strict profile replayer.
Never derive this trusted input from the receipts being checked. The replayer
must verify the actual signed staged payload/ESP, exact client/layout, boot and
lifecycle gates, then replay raw contexts with the candidate's verified decoder
(the proof.verify_smp contract). Historical fixed offsets are not a default.
The returned result digests are links, not an attestation or a guest PASS.
"""
import hashlib
import json
from pathlib import Path
import re

PROFILES = (1, 2, 4, 8)
ARM = b"run /preempt-runner\r"
PRODUCT = {"kernel.elf": "kernel_sha256", "initramfs.cpio": "initramfs_sha256",
           "agentos.efi": "signed_sha256", "agentos.unsigned.efi": "unsigned_sha256",
           "db.cer": "db_cer_sha256", "build-provenance.json": "build_provenance_sha256"}
# Hash after normal shell shutdown, debugger and QEMU cleanup. In particular,
# hash the actual disk, not merely the preflight copy of BOOTX64.EFI.
EVIDENCE = ("preflight.json", "guest-start.json", "trace-request.json",
            "trace-ready.json", "trace-result.json", "qmp-roster.json", "arm.json",
            "irq-trace.jsonl", "com1.log", "com1-input.bin", "preempt-runner",
            "client.symbols.elf", "test.cpio", "test.unsigned.efi", "test.efi",
            "esp-bootx64.efi", "esp.raw", "OVMF_VARS.secboot.fd", "gdb.log",
            "qemu-stderr.log", "physical-oom.log", "physical-oom.json",
            "startup-host.json", "failure-host.json")
HEX = rb"([0-9a-f]{16})"
EXIT = re.compile(rb"AGENTOS USER EXIT PID=" + HEX + rb" CR3=" + HEX + rb" STATUS=" + HEX + rb"\r\n")


def require(ok, message):
    if not ok:
        raise ValueError(message)


def sha(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def decode(data):
    def unique(pairs):
        out = {}
        for key, value in pairs:
            require(key not in out, "Duplicate JSON key")
            out[key] = value
        return out
    return json.loads(data, object_pairs_hook=unique)


def record(path):
    return decode(Path(path).read_bytes())


def evidence_hashes(directory):
    return {name: sha(directory / name) for name in EVIDENCE}


def check_candidate(build, layout, candidate):
    commit, tree, control = (candidate[k] for k in ("commit", "tree", "control"))
    require(all(isinstance(v, str) and re.fullmatch(r"[0-9a-f]{40}", v)
                for v in (commit, tree)), "Missing independently verified source commit/tree")
    require(control["source_commit"] == commit and control["signature_verified"] is True,
            "Wrong verified distribution identity")
    require(all(sha(build / name) == control[key] for name, key in PRODUCT.items()),
            "Candidate product bytes changed")
    provenance = record(build / "build-provenance.json")
    require(provenance["source_commit"] == commit and provenance["source_clean"] is True and
            provenance["profile"] == "default" and
            provenance["initramfs_sha256"] == control["initramfs_sha256"] and
            all(provenance["artifacts"][name] == control[PRODUCT[name]]
                for name in ("agentos.efi", "agentos.unsigned.efi", "db.cer")),
            "Wrong clean build provenance")
    require(sha(layout) == candidate["layout_sha256"] and candidate["kernel_symbols"] and
            candidate["runtime_bytes"], "Missing or changed verified layout")


def lifecycle(log, arm, result, apics):
    offset = arm["offset"]
    require(type(offset) is int and 0 < offset < len(log), "Wrong foreground boundary")
    before, foreground = log[:offset], log[offset:]
    require(foreground.startswith(ARM + b"\n") and b"exit status 0\r\nagentos> " in foreground and
            log.endswith(b"[INFO] INTERACTIVE SHELL STOPPED\r\n"), "Missing foreground/shutdown")
    stops = re.findall(rb"(?m)^AGENTOS MANAGER SESSION STOP PID=" + HEX +
                       rb" STATUS=0000000000000000 FRAMES=OK\r$", foreground)
    shells = re.findall(rb"(?m)^AGENTOS SHELL START PID=" + HEX + rb"\r$", before)
    roster = re.findall(rb"(?m)^AGENTOS TASK (BSP|AP) APIC=" + HEX +
                        rb" TIMER-WAKES=0000000000000003\r$", before)
    require(stops == [b"0000000000000001"] and len(shells) == 1 and
            int(shells[0], 16) == result["shell"] and len(roster) == len(apics) and
            {int(v, 16) for _, v in roster} == apics and
            sum(role == b"BSP" for role, _ in roster) == 1, "Wrong lifecycle/boot roster")
    def pid(mark):
        found = re.findall(rb"(?m)^" + mark + rb" PID=" + HEX + rb"\r$", foreground)
        require(len(found) == 1, "Missing/duplicate foreground identity")
        return int(found[0], 16)
    root = pid(b"REG ROOT")
    earlier = {int(m[1], 16) for m in EXIT.finditer(before)}
    ids = result["identities"]
    require(root == result["root"] and root > result["shell"] and root not in earlier and
            pid(b"REG COMPLETE") == root and set(ids) == {chr(65+i) for i in range(2*len(apics))} and
            len({v[0] for v in ids.values()}) == len(ids) and len({v[2] for v in ids.values()}) == len(ids),
            "Wrong root/worker roster")
    for label, (worker, parent, cr3) in ids.items():
        mark = b"REG " + label.encode("ascii")
        require(worker > root and worker not in earlier and parent == root and
                pid(mark) == worker and all(pid(mark+b" "+v) == worker for v in (b"BEGIN", b"OK", b"REAP")),
                "Wrong worker lifecycle")
        exits = [m for m in EXIT.finditer(foreground) if int(m[1], 16) == worker]
        require(len(exits) == 1 and int(exits[0][2], 16) == cr3 and int(exits[0][3], 16) == 0 and
                foreground.index(mark+b" BEGIN PID=") < foreground.index(mark+b" OK PID=") <
                exits[0].start() < foreground.index(mark+b" REAP PID=") < foreground.index(b"REG COMPLETE PID="),
                "Wrong worker exit/reap")
    exits = [m for m in EXIT.finditer(foreground) if int(m[1], 16) == root]
    require(len(exits) == 1 and int(exits[0][3], 16) == 0 and
            foreground.index(b"REG COMPLETE PID=") < exits[0].start() < foreground.index(b"exit status 0\r\nagentos> "),
            "Wrong root exit")


def verify_prefix(build, layout, candidate, directories, *, replay):
    """Replay exactly an ordered prefix; use the final digest in next preflight.

    replay(directory, rows, request, ready, identities, bounds) must return the
    actual independently recomputed chains, never read result.json as its answer.
    It must be bound to the already verified candidate/layout and validate the
    signed stage and full boot/process/orphan gates before invoking the strict
    raw verifier. No default decoder or historical fallback is provided.
    """
    require(callable(replay), "Candidate-specific raw replayer required")
    build, layout = Path(build), Path(layout)
    check_candidate(build, layout, candidate)
    dirs = [Path(v).resolve() for v in directories]
    require(len(dirs) <= len(PROFILES) and len(set(dirs)) == len(dirs), "Duplicate/excess profiles")
    links, seen, finished = [], set(), 0
    for cpus, directory in zip(PROFILES, dirs):
        pre = record(directory / "preflight.json")
        result_path = directory / "result.json"
        result_bytes = result_path.read_bytes()
        result = decode(result_bytes)
        expected = links[-1] if links else None
        require("fresh_previous_result_sha256" in pre and "prior_proof" not in pre and
                pre["fresh_previous_result_sha256"] == expected, "Missing fresh predecessor or historical replay")
        for receipt, guests in ((pre, 0), (result, 1)):
            require(receipt["result"] == "pass" and type(receipt["cpus"]) is int and receipt["cpus"] == cpus and
                    type(receipt["guests"]) is int and receipt["guests"] == guests and
                    receipt["commit"] == candidate["commit"] and receipt["tree"] == candidate["tree"] and
                    receipt["layout_sha256"] == candidate["layout_sha256"] and "error" not in receipt,
                    "Wrong profile/source/layout or incomplete receipt")
        require(pre["stage"] == "complete" and pre["workers"] == 2*cpus and
                pre["control"] == candidate["control"] and pre["kernel_symbols"] == candidate["kernel_symbols"] and
                pre["runtime_bytes"] == candidate["runtime_bytes"] and pre["arm"] == ARM.hex() and
                result["shutdown"] is True, "Wrong candidate preflight/shutdown")
        hashes = evidence_hashes(directory)
        require(result["evidence_sha256"] == hashes and result["com1_sha256"] == hashes["com1.log"] and
                result["trace_sha256"] == hashes["irq-trace.jsonl"], "Changed raw evidence")
        require(hashes["test.efi"] == hashes["esp-bootx64.efi"], "Wrong staged EFI copy")
        immutable = {name: candidate["control"][key] for name, key in PRODUCT.items()}
        immutable.update({name: hashes[name] for name in ("preempt-runner", "client.symbols.elf",
            "test.cpio", "test.efi", "test.unsigned.efi", "esp-bootx64.efi", "startup-host.json", "failure-host.json")})
        for name, digest in immutable.items():
            require([value for path, value in pre["inputs"].items() if Path(path).name == name] == [digest],
                    "Wrong immutable preflight input: " + name)
        unique = {hashes[n] for n in ("guest-start.json", "irq-trace.jsonl", "com1.log")}
        require(len(unique) == 3 and not seen & unique, "Repeated guest evidence")
        seen.update(unique)
        start, request, ready, trace, qmp, arm = (record(directory / (name+".json")) for name in
            ("guest-start", "trace-request", "trace-ready", "trace-result", "qmp-roster", "arm"))
        require(start["guests"] == 1 and start["cpus"] == cpus and start["command"].count("-smp") == 1 and
                start["command"][start["command"].index("-smp")+1] == str(cpus), "Wrong actual launch profile")
        require(request["cpus"] == cpus and request["layout_sha256"] == candidate["layout_sha256"] and
                request["qmp"] == qmp and request["runtime_bytes"] == pre["runtime_bytes"] and
                request["windows"] == pre["windows"] and request["iterations"] == pre["iterations"] == result["iterations"],
                "Wrong raw replay request")
        # The strict existing SMP decoder additionally authenticates QMP/GDB/GS
        # and raw local IRQ identities. This layer only binds the profile roster.
        apics = {c["apic-id"] for c in qmp["cpus"]}
        require(qmp["accelerator"] == "tcg" and qmp["kvm"]["enabled"] is False and
                len(qmp["cpus"]) == len(apics) == cpus and
                all(type(v) is int and 0 <= v < 255 for v in apics) and ready["threads"] == ready["online"] == cpus and
                {v["apic"] for v in ready["bindings"]} == apics and len(ready["bindings"]) == cpus,
                "Wrong QMP/GDB roster")
        rows = [decode(line) for line in (directory / "irq-trace.jsonl").read_bytes().splitlines()]
        bounds = result["bounds"]
        require(len(bounds) == 2, "Wrong foreground bounds")
        times = (start["host_ns"], ready["armed_ns"], arm["arm_ns"], arm["sent_ns"], bounds[1], result["finished_ns"])
        require(all(type(v) is int for v in times) and finished < times[0] <= times[1] <= times[2] <= times[3] == bounds[0] <= times[4] < times[5] and
                arm["ready"] == ready and arm["command"] == ARM.hex() and
                result["trace"] == trace and trace["complete"] is True and trace["error"] is None and
                trace["armed_ns"] == ready["armed_ns"] and ready["armed_ns"] <= trace["end_ns"] <= times[-1] and
                trace["stops"] == len(rows) and len(rows) >= 6*cpus and
                all(ready["armed_ns"] <= row["host_ns"] <= trace["end_ns"] for row in rows) and
                (directory / "com1-input.bin").read_bytes() == ARM+b"exit\r", "Incomplete/reordered actual run")
        log = (directory / "com1.log").read_bytes()
        bases = re.findall(rb"(?m)^\[INFO\] KERNEL IMAGE BASE=" + HEX + rb"\r$", log[:arm["offset"]])
        require(len(bases) == 1 and int(bases[0], 16) == request["base"], "Wrong actual kernel base")
        lifecycle(log, arm, result, apics)
        chains = replay(directory, rows, request, ready, result["identities"], tuple(bounds))
        require(chains == result["chains"] and set(chains) == {str(v) for v in apics} and
                all(len(v) >= 6 for v in chains.values()), "Missing complete replayed APIC chains")
        # Detect modifications even if the replay function or another process
        # changes a file during replay. The predecessor hashes the exact receipt.
        require(evidence_hashes(directory) == hashes and result_path.read_bytes() == result_bytes,
                "Evidence changed during replay")
        links.append(hashlib.sha256(result_bytes).hexdigest())
        finished = times[-1]
    check_candidate(build, layout, candidate)
    return tuple(links)


def verify_sequence(build, layout, candidate, directories, *, replay):
    directories = tuple(directories)
    require(len(directories) == len(PROFILES), "Missing full fresh 1/2/4/8 sequence")
    return verify_prefix(build, layout, candidate, directories, replay=replay)
