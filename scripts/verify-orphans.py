"""Verify real CPU-local orphan reparenting and complete descendant reaping.

The source of evidence is a captured COM1 transcript, not a host mock.
The parent's exit must precede adopted-child discovery, and only the CPU-local
root may force its newly adopted child to exit. Repeated, missing, reordered or
contradictory records fail closed. See verify-processes.py for sibling checks.
"""
import argparse
from pathlib import Path
import re
import sys


class VerificationError(ValueError):
    pass


HEX = r"[0-9a-f]{16}"
BEGIN = re.compile(rf"AGENTOS ORPHAN BEGIN ROOT=({HEX})")
END = re.compile(rf"AGENTOS ORPHAN ENDED ROOT=({HEX})")
ADOPT = re.compile(rf"AGENTOS ORPHAN ADOPT ROOT=({HEX}) PARENT=({HEX}) CHILD=({HEX}) STATUS=({HEX})")
REAPS = re.compile(rf"AGENTOS ORPHAN REAPS ROOT=({HEX}) PARENT=({HEX}) CHILD=({HEX}) STATUS=({HEX})")
EXIT = re.compile(rf"AGENTOS USER EXIT PID=({HEX}) CR3=({HEX}) STATUS=({HEX})")
KILL = re.compile(rf"AGENTOS USER KILL PID=({HEX}) PARENT=({HEX}) STATUS=({HEX})")
CHECK = re.compile(rf"AGENTOS PROCESS OK APIC=({HEX}) PARENT=({HEX})")
SHELL = re.compile("AGENTOS SHELL START")
EXPECTED = ("exit", "adopt", "kill", "reaps")


def require(ok, message):
    if not ok:
        raise VerificationError(message)


def parse_event(line):
    for kind, pattern in (("exit", EXIT), ("adopt", ADOPT),
                          ("kill", KILL), ("reaps", REAPS)):
        match = pattern.fullmatch(line)
        if match:
            fields = tuple(int(group, 16) for group in match.groups())
            return kind, fields
    return None


def verify(text, cpus, *, basic_smp=False):
    require(cpus in ((4,8) if basic_smp else (1,2)),
            "CPU count outside explicit orphan verification profile")
    opened = None
    sections = []
    checks = []
    for number, line in enumerate(text.splitlines(), 1):
        if SHELL.match(line):
            require(opened is None, f"Unterminated orphan interval at {number}")
            break
        begin = BEGIN.fullmatch(line)
        end = END.fullmatch(line)
        if begin:
            require(opened is None, f"Nested orphan interval at {number}")
            root = int(begin[1], 16)
            require(root != 0, f"Zero root PID at {number}")
            opened = (root, [])
        elif end:
            require(opened is not None and opened[0] == int(end[1], 16),
                    f"Unmatched orphan interval end at {number}")
            sections.append(opened)
            opened = None
        elif line.startswith("AGENTOS ORPHAN "):
            require(opened is not None, f"Orphan event outside interval at {number}")
            event = parse_event(line)
            require(event is not None and event[0] in ("adopt", "reaps"),
                    f"Malformed orphan event at {number}")
            opened[1].append(event)
        elif opened is not None:
            event = parse_event(line)
            if event is not None:
                require(event[0] in ("exit", "kill"),
                        f"Unexpected user event during orphan adoption at {number}")
                opened[1].append(event)
            else:
                require(not line.startswith(("AGENTOS USER ", "AGENTOS PROCESS ",
                                              "AGENTOS SERVICE ", "AGENTOS IPC ")),
                        f"Unexpected process evidence inside orphan interval at {number}")
        else:
            match = CHECK.fullmatch(line)
            if match:
                checks.append((int(match[1], 16), int(match[2], 16)))
    require(opened is None, "Missing orphan interval end")
    require(len(sections) == cpus, f"Expected {cpus} orphan intervals, found {len(sections)}")
    require(len(checks) >= cpus, "Missing per-CPU process completion evidence")
    roots = [root for root, _ in sections]
    require(len(set(roots)) == cpus, "Duplicate root PID across CPU intervals")
    require([root for _, root in checks[:cpus]] == roots,
            "Orphan root PID disagrees with process identity report")
    known = set(roots)
    for root, events in sections:
        require(tuple(kind for kind, _ in events) == EXPECTED,
                f"Wrong orphan event ordering for root {root}")
        exit_data, adopted, killed, reaped = (data for _, data in events)
        old_parent, cr3, exit_status = exit_data
        reaper, parent, child, marker_status = adopted
        require(exit_status == 0 and old_parent != 0 and cr3 != 0 and
                cr3 % 4096 == 0, f"Intermediate parent did not exit cleanly: {root}")
        require(reaper == root and parent == old_parent and marker_status == 0
                and child > parent and child != root,
                f"Child was not adopted by the correct root: {root}")
        require(killed == (child, root, 137),
                f"Only the adopting init may kill its orphan: {root}")
        require(reaped == (root, parent, child, 137),
                f"Adopted child was not reaped with status 137: {root}")
        require(not ({parent, child} & known),
                f"Duplicate or reused orphan process IDs: {root}")
        known.update((parent, child))
    return len(sections)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--log", required=True, type=Path)
    parser.add_argument("--cpus", required=True, choices=(1, 2), type=int)
    args = parser.parse_args()
    try:
        count = verify(args.log.read_text(encoding="utf-8", errors="replace"), args.cpus)
    except (VerificationError, OSError) as error:
        print(f"Orphan reparenting verification failed: {error}", file=sys.stderr)
        return 1
    print(f"Verified adopted orphan and complete reaping on {count} CPU(s): {args.log}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
