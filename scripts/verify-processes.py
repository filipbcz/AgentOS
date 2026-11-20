"""Check COM1 evidence for isolation, pipe transfer and authenticated local IPC.

This checks a captured log; it does not boot a VM or establish its provenance.
The current kernel runs each CPU's process scenario sequentially.
"""
import argparse
import re
import sys
from pathlib import Path


class VerificationError(ValueError):
    pass


def hex_field(name, digits=16):
    return rf"(?P<{name}>[0-9a-f]{{{digits}}})"


PID = hex_field("pid")
PEER = (f"PID={PID} PEER={hex_field('peer')} "
        f"UID={hex_field('uid', 8)} GID={hex_field('gid', 8)}")
PATTERNS = {
    "fault": f"AGENTOS USER FAULT PID={PID} PARENT={hex_field('parent')} "
             f"CR3={hex_field('cr3')} VECTOR={hex_field('vector')} "
             f"ERROR={hex_field('error')} ADDRESS={hex_field('address')}",
    "survived": "AGENTOS USER SURVIVED",
    "exit": f"AGENTOS USER EXIT PID={PID} CR3={hex_field('cr3')} "
            f"STATUS={hex_field('status')}",
    "check": f"AGENTOS PROCESS OK APIC={hex_field('apic')} PARENT={hex_field('parent')}",
    "received": f"AGENTOS PIPE RECEIVED PID={PID} BYTES={hex_field('bytes', 8)} "
                f"FNV32={hex_field('fnv', 8)}",
    "sent": f"AGENTOS PIPE SENT PID={PID} CHILD={hex_field('child')}",
    "service": f"AGENTOS IPC SERVICE {PEER}",
    "reply": f"AGENTOS IPC REPLY {PEER}",
}
PATTERNS = {kind: re.compile(pattern) for kind, pattern in PATTERNS.items()}
PREFIXES = ("AGENTOS USER ", "AGENTOS PIPE ", "AGENTOS IPC ", "AGENTOS PROCESS ")
ORDER = ("fault", "survived", "received", "exit", "sent", "service", "exit",
         "reply", "exit", "check")


def require(condition, message):
    if not condition:
        raise VerificationError(message)


def verify(text, apic_ids):
    """Reject incomplete, malformed, contradictory or repeated process evidence."""
    expected_cpus = set(apic_ids)
    require(expected_cpus and len(expected_cpus) == len(apic_ids),
            "Expected APIC IDs must be nonempty and unique")
    events = []
    for number, line in enumerate(text.splitlines(), 1):
        if not line.startswith(PREFIXES):
            continue
        for kind, pattern in PATTERNS.items():
            match = pattern.fullmatch(line)
            if match:
                fields = {key: int(value, 16) for key, value in match.groupdict().items()}
                events.append((kind, fields, number))
                break
        else:
            raise VerificationError(f"Malformed process evidence at line {number}: {line}")

    require(len(events) == len(ORDER) * len(expected_cpus),
            f"Incomplete or extra process evidence: expected {len(ORDER) * len(expected_cpus)} "
            f"records, found {len(events)}")
    seen_cpus, seen_pids = set(), set()
    for offset in range(0, len(events), len(ORDER)):
        block = events[offset:offset + len(ORDER)]
        require(tuple(event[0] for event in block) == ORDER,
                f"Invalid process event order starting at line {block[0][2]}")
        fault, _, received, receiver_exit, sent, service, service_exit, reply, parent_exit, check = (
            event[1] for event in block)
        cpu, parent = check["apic"], check["parent"]
        child, receiver, server = fault["pid"], received["pid"], service["pid"]
        context = f"APIC {cpu:016x}, parent {parent:016x}"
        pids = {parent, child, receiver, server}
        require(cpu in expected_cpus and cpu not in seen_cpus,
                f"Unexpected or repeated CPU: {context}")
        require(len(pids) == 4 and 0 not in pids and not (pids & seen_pids),
                f"Process IDs must be nonzero, distinct and unreused: {context}")
        require(fault["parent"] == parent and parent_exit["pid"] == parent and
                (fault["vector"], fault["error"], fault["address"]) == (14, 5, 0x02000000),
                f"Invalid isolation fault or parent identity: {context}")
        require(received["bytes"] == 8193 and received["fnv"] == 0x1490a95f and
                sent["pid"] == parent and sent["child"] == receiver and
                receiver_exit["pid"] == receiver,
                f"Invalid two-process pipe transfer: {context}")
        require(service["peer"] == parent and reply["pid"] == parent and
                reply["peer"] == server and service_exit["pid"] == server and
                service["uid"] == service["gid"] == reply["uid"] == reply["gid"] == 1000,
                f"Invalid IPC peer identity: {context}")
        exits = (receiver_exit, service_exit, parent_exit)
        require(all(record["status"] == 0 for record in exits),
                f"User process exited unsuccessfully: {context}")
        roots = (fault["cr3"], receiver_exit["cr3"], service_exit["cr3"])
        require(parent_exit["cr3"] != 0 and all(root and root != parent_exit["cr3"] for root in roots),
                f"Missing private child address space: {context}")
        # Sequential children may reuse a released physical page-table root.
        seen_cpus.add(cpu)
        seen_pids.update(pids)


def apic_id(value):
    if not re.fullmatch(r"[0-9a-fA-F]{1,16}", value):
        raise argparse.ArgumentTypeError("APIC IDs must be 1-16 hexadecimal digits")
    return int(value, 16)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--log", required=True, type=Path)
    parser.add_argument("--apic-ids", required=True, nargs="+", type=apic_id)
    args = parser.parse_args()
    try:
        verify(args.log.read_text(encoding="utf-8", errors="replace"), args.apic_ids)
    except (OSError, VerificationError) as error:
        print(f"Process verification failed: {error}", file=sys.stderr)
        return 1
    print(f"Process log verified for {len(args.apic_ids)} CPU(s): {args.log}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
