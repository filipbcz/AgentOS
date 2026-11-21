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
SHELL_START = re.compile(r"AGENTOS SHELL START PID=([0-9a-f]{16})")
SUPERVISOR_BEGIN = re.compile(r"AGENTOS SUPERVISOR BEGIN PARENT=([0-9a-f]{16})")
SUPERVISOR_END = re.compile(r"AGENTOS SUPERVISOR ENDED PARENT=([0-9a-f]{16})")
ORPHAN_BEGIN = re.compile(r"AGENTOS ORPHAN BEGIN ROOT=([0-9a-f]{16})")
ORPHAN_END = re.compile(r"AGENTOS ORPHAN ENDED ROOT=([0-9a-f]{16})")
COW_BEGIN = re.compile(r"AGENTOS COW BEGIN ROOT=([0-9a-f]{16}) CHILD=0000000000000000")
COW_END = re.compile(r"AGENTOS COW ENDED ROOT=([0-9a-f]{16}) CHILD=([0-9a-f]{16})")


def require(condition, message):
    if not condition:
        raise VerificationError(message)


def verify(text, apic_ids):
    """Reject incomplete, malformed, contradictory or repeated process evidence."""
    expected_cpus = set(apic_ids)
    require(expected_cpus and len(expected_cpus) == len(apic_ids),
            "Expected APIC IDs must be nonempty and unique")
    events = []
    supervisor_open = None
    supervised_parents = []
    orphan_open = None
    orphan_roots = []
    cow_open = None
    cow_roots = []
    for number, line in enumerate(text.splitlines(), 1):
        if line.startswith("AGENTOS COW "):
            begin = COW_BEGIN.fullmatch(line)
            end = COW_END.fullmatch(line)
            require(supervisor_open is None and orphan_open is None,
                    f"COW phase overlaps prior stage at line {number}")
            if begin:
                require(cow_open is None and len(orphan_roots) > len(cow_roots),
                        f"Nested COW phase or missing orphan test at line {number}")
                cow_open = int(begin[1], 16)
                require(cow_open > 0, f"Zero fork root at line {number}")
            elif end:
                require(cow_open is not None and cow_open == int(end[1], 16) and
                        int(end[2], 16) != 0,
                        f"Unmatched COW phase end at line {number}")
                cow_roots.append(cow_open)
                cow_open = None
            else:
                require(cow_open is not None, f"COW event outside phase at line {number}")
            continue
        if cow_open is not None:
            # verify-cow.py checks the exact forked child, exit and parent
            # isolation evidence; do not mistake its USER EXIT for pipe IPC.
            continue
        if line.startswith("AGENTOS ORPHAN "):
            begin = ORPHAN_BEGIN.fullmatch(line)
            end = ORPHAN_END.fullmatch(line)
            require(supervisor_open is None, f"Orphan phase overlaps supervisor at {number}")
            if begin:
                require(orphan_open is None and len(supervised_parents) > len(orphan_roots),
                        f"Orphan phase is nested or precedes supervisor at line {number}")
                orphan_open = int(begin[1], 16)
                require(orphan_open != 0, f"Zero orphan root at line {number}")
            elif end:
                require(orphan_open is not None and orphan_open == int(end[1], 16),
                        f"Unmatched orphan interval at line {number}")
                orphan_roots.append(orphan_open)
                orphan_open = None
            else:
                require(orphan_open is not None, f"Orphan event outside interval at {number}")
            continue
        if orphan_open is not None:
            # verify-orphans.py independently validates the exact USER EXIT,
            # KILL, adoption and reaping subtrace inside these boundaries.
            continue
        if line.startswith("AGENTOS SUPERVISOR "):
            begin = SUPERVISOR_BEGIN.fullmatch(line)
            end = SUPERVISOR_END.fullmatch(line)
            if begin:
                require(supervisor_open is None,
                        f"Nested supervisor boundary at line {number}")
                require(events and events[-1][0] == "reply",
                        f"Supervisor must follow authenticated IPC test at line {number}")
                supervisor_open = int(begin[1], 16)
                require(supervisor_open > 0,
                        f"Zero supervisor PID at line {number}")
            elif end:
                require(supervisor_open is not None and
                        supervisor_open == int(end[1], 16),
                        f"Unmatched supervisor end at line {number}")
                supervised_parents.append(supervisor_open)
                supervisor_open = None
            else:
                raise VerificationError(f"Malformed supervisor boundary at line {number}")
            continue
        if supervisor_open is not None:
            # The independently validated supervisor test owns this subtrace.
            # We must not interpret its service-child exits as IPC child exits.
            continue
        if line.startswith("AGENTOS SHELL START"):
            require(orphan_open is None and cow_open is None,
                    "Unterminated orphan/COW interval before shell")
            match = SHELL_START.fullmatch(line)
            require(match is not None and int(match[1], 16) != 0,
                    f"Malformed shell phase boundary at line {number}")
            # The shell has its own exit and verifier. Earlier required process
            # counts and identities below must still pass before this boundary.
            break
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

    require(supervisor_open is None, "Unterminated supervisor interval")
    require(orphan_open is None, "Unterminated orphan interval")
    require(cow_open is None, "Unterminated COW interval")
    require(not cow_roots or len(cow_roots) == len(expected_cpus),
            "Missing fork/COW interval on one or more CPUs")
    require(not supervised_parents or len(supervised_parents) == len(expected_cpus),
            "Missing supervisor interval on one or more CPUs")
    require(not orphan_roots or len(orphan_roots) == len(expected_cpus),
            "Missing orphan interval on one or more CPUs")
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
        if supervised_parents:
            require(supervised_parents[len(seen_cpus)] == parent,
                    f"Supervisor interval does not belong to this parent: {context}")
        if orphan_roots:
            require(orphan_roots[len(seen_cpus)] == parent,
                    f"Orphan interval does not belong to this parent: {context}")
        if cow_roots:
            require(cow_roots[len(seen_cpus)] == parent,
                    f"COW interval does not belong to this parent: {context}")
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
