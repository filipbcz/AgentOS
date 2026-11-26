"""Strict independent COM1 evidence check for PID1 service supervision.

The kernel's USER EXIT/KILL markers and the parent supervisor's SERVICE
markers must agree on identity, status, attempt count and exact ordering.
A transcript proves only its own consistency, not VirtualBox provenance.
"""
import argparse
from pathlib import Path
import re
import sys


class VerificationError(ValueError):
    pass


HEX16 = r"[0-9a-f]{16}"
HEX8 = r"[0-9a-f]{8}"
BEGIN = re.compile(rf"AGENTOS SUPERVISOR BEGIN PARENT=({HEX16})")
END = re.compile(rf"AGENTOS SUPERVISOR ENDED PARENT=({HEX16})")
EXIT = re.compile(rf"AGENTOS USER EXIT PID=({HEX16}) CR3=({HEX16}) STATUS=({HEX16})")
KILL = re.compile(rf"AGENTOS USER KILL PID=({HEX16}) PARENT=({HEX16}) STATUS=({HEX16})")
DURATION = re.compile(
    rf"AGENTOS SERVICE DURATION PARENT=({HEX16}) CHILD=({HEX16}) MS=({HEX16})"
)
EVENT = re.compile(
    rf"AGENTOS SERVICE (DONE|REAP|STOP|TIME) "
    rf"PARENT=({HEX16}) CHILD=({HEX16}) STATUS=({HEX16}) ATTEMPT=({HEX8})"
)
CHECK = re.compile(rf"AGENTOS PROCESS OK APIC=({HEX16}) PARENT=({HEX16})")
SHELL = re.compile(r"AGENTOS SHELL START")
EXPECTED_ORDER = ("exit", "DONE", "exit", "REAP", "exit", "REAP",
                  "exit", "REAP", "STOP", "kill", "duration", "TIME", "STOP")


def require(ok, message):
    if not ok:
        raise VerificationError(message)


def event(line):
    match = EXIT.fullmatch(line)
    if match:
        cr3 = int(match[2], 16)
        require(cr3 != 0 and cr3 % 4096 == 0, "Child exit has invalid CR3")
        return ("exit", int(match[1], 16), 0, int(match[3], 16), 0)
    match = KILL.fullmatch(line)
    if match:
        return ("kill", int(match[1], 16), int(match[2], 16), int(match[3], 16), 0)
    match = DURATION.fullmatch(line)
    if match:
        return ("duration", int(match[2], 16), int(match[1], 16), int(match[3], 16), 0)
    match = EVENT.fullmatch(line)
    if match:
        return (match[1], int(match[3], 16), int(match[2], 16),
                int(match[4], 16), int(match[5], 16))
    return None


def verify(text, cpus):
    require(cpus in (1, 2), "Expected 1 or 2 CPUs")
    sections = []
    current = None
    checks = []
    for number, line in enumerate(text.splitlines(), 1):
        if SHELL.match(line):
            require(current is None, f"Unclosed supervisor phase at line {number}")
            break
        match = BEGIN.fullmatch(line)
        if match:
            require(current is None, f"Nested supervisor phase at line {number}")
            parent = int(match[1], 16)
            require(parent != 0, "Zero parent PID")
            current = [parent, []]
            continue
        match = END.fullmatch(line)
        if match:
            require(current is not None and current[0] == int(match[1], 16),
                    f"Unmatched supervisor end at line {number}")
            sections.append(tuple(current))
            current = None
            continue
        if line.startswith("AGENTOS SUPERVISOR"):
            raise VerificationError(f"Malformed supervisor phase at line {number}")
        match = CHECK.fullmatch(line)
        if match and current is None:
            checks.append((int(match[1], 16), int(match[2], 16)))
        if current is None:
            continue
        item = event(line)
        require(item is not None or not line.startswith(
            ("AGENTOS USER", "AGENTOS SERVICE", "AGENTOS SUPERVISOR")),
            f"Unrecognized service evidence at line {number}")
        if item:
            current[1].append(item)
    require(current is None, "Unclosed supervisor phase")
    require(len(sections) == cpus, f"Expected {cpus} supervisor phase(s), got {len(sections)}")
    require(len(checks) >= cpus, "Missing process completion records")
    parents = [p for p, _ in sections]
    require(len(set(parents)) == cpus, "Reused supervisor parent PID")
    require([p for _, p in checks[:cpus]] == parents, "Supervisor parent/process check mismatch")
    all_pids = set(parents)
    for parent, records in sections:
        verify_interval(parent, records, all_pids)
    return len(sections)


def verify_interval(parent, records, all_pids):
    """The original strict interval checks, also used for the foreground runner."""
    require(len(records) == len(EXPECTED_ORDER),
            f"Wrong service evidence count for parent {parent}")
    require(tuple(item[0] for item in records) == EXPECTED_ORDER,
            f"Wrong service evidence order for parent {parent}")
    healthy, done = records[0:2]
    require(healthy[1] > 0 and healthy[3] == 0 and
            done == ("DONE", healthy[1], parent, 0, 1),
            f"Healthy child not collected by parent {parent}")
    failed = []
    for attempt in range(1, 4):
        ex = records[attempt * 2]
        note = records[attempt * 2 + 1]
        require(ex[1] > 0 and ex[3] == 42 and
                note == ("REAP", ex[1], parent, 42, attempt),
                f"Uncollected crash / incorrect attempt {attempt} for parent {parent}")
        failed.append(ex[1])
    require(records[8] == ("STOP", failed[-1], parent, 42, 3),
            f"Failure restart cap not enforced for parent {parent}")
    killed, duration, time, stop = records[9:]
    require(killed[1] > 0 and killed[2] == parent and killed[3] == 137 and
            duration[1] == killed[1] and duration[2] == parent and
            250 <= duration[3] < (1 << 63) and
            time == ("TIME", killed[1], parent, 137, 1) and
            stop == ("STOP", killed[1], parent, 137, 1),
            f"Stalled child not killed and collected by parent {parent}")
    children = [healthy[1], *failed, killed[1]]
    require(len(set(children)) == 5 and not (set(children) & all_pids),
            f"Duplicate service child PID for parent {parent}")
    all_pids.update(children)
    return {"healthy_pid": healthy[1], "failed_pids": failed,
            "killed_pid": killed[1], "duration_ms": duration[3]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--log", required=True, type=Path)
    parser.add_argument("--cpus", required=True, choices=(1, 2), type=int)
    args = parser.parse_args()
    try:
        count = verify(args.log.read_text(encoding="utf-8", errors="replace"), args.cpus)
    except (OSError, VerificationError) as error:
        print(f"Service supervision verification failed: {error}", file=sys.stderr)
        return 1
    print(f"Verified bounded PID1 service supervision for {count} CPU scenario(s): {args.log}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
