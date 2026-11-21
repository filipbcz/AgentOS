"""Strict independent COM1 verifier for actual fork and copy-on-write.

This does not emulate user memory: it requires a signed-booted AgentOS
transcript in which child COW writes, a kernel SYS_READ to shared .bss and
parent isolation have succeeded before their user-mode success markers.
"""
import argparse
from pathlib import Path
import re
import sys

class VerificationError(ValueError):
    pass

HEX = r"[0-9a-f]{16}"
BEGIN = re.compile(rf"AGENTOS COW BEGIN ROOT=({HEX}) CHILD=({HEX})")
CHILD = re.compile(rf"AGENTOS COW CHILD ROOT=({HEX}) CHILD=({HEX})")
REAPS = re.compile(rf"AGENTOS COW REAPS ROOT=({HEX}) CHILD=({HEX})")
ENDED = re.compile(rf"AGENTOS COW ENDED ROOT=({HEX}) CHILD=({HEX})")
EXIT = re.compile(rf"AGENTOS USER EXIT PID=({HEX}) CR3=({HEX}) STATUS=({HEX})")
CHECK = re.compile(rf"AGENTOS PROCESS OK APIC=({HEX}) PARENT=({HEX})")
EXPECTED = ("child", "exit", "reaps", "ended")


def require(condition, message):
    if not condition:
        raise VerificationError(message)


def verify(text, cpus):
    require(cpus in (1, 2), "Expected one or two CPU-local fork scenarios")
    phases = []
    current = None
    roots = []
    for n, line in enumerate(text.splitlines(), 1):
        start = BEGIN.fullmatch(line)
        if start:
            require(current is None, f"Nested COW interval at line {n}")
            root, child = (int(part, 16) for part in start.groups())
            require(root > 0 and child == 0, f"Invalid COW beginning at line {n}")
            current = [root, []]
            continue
        if line.startswith("AGENTOS COW "):
            require(current is not None, f"COW event outside interval at line {n}")
            event = None
            for kind, pattern in (("child", CHILD), ("reaps", REAPS), ("ended", ENDED)):
                match = pattern.fullmatch(line)
                if match:
                    event = (kind, tuple(int(part,16) for part in match.groups()))
                    break
            require(event is not None, f"Malformed COW event at line {n}")
            current[1].append(event)
            if event[0] == "ended":
                phases.append(current)
                current = None
            continue
        if current is not None:
            match = EXIT.fullmatch(line)
            if match:
                current[1].append(("exit", tuple(int(part,16) for part in match.groups())))
            else:
                require(not line.startswith(("AGENTOS USER ", "AGENTOS PROCESS ",
                                              "AGENTOS ORPHAN ", "AGENTOS SERVICE ")),
                        f"Unexpected process event in COW interval at line {n}")
        else:
            match = CHECK.fullmatch(line)
            if match:
                roots.append((int(match[1],16), int(match[2],16)))
    require(current is None, "Unterminated COW interval")
    require(len(phases) == cpus and len(roots) >= cpus,
            f"Missing or duplicated COW phases: expected {cpus}, found {len(phases)}")
    seen = set()
    for index, (root, events) in enumerate(phases):
        require(tuple(k for k, _ in events) == EXPECTED,
                f"Invalid COW child/exit/reap/end ordering for root {root}")
        name, exit_status, reaped, ended = (fields for _, fields in events)
        child = name[1]
        require(name[0] == root and child not in seen and child > 0 and child != root,
                "COW child identity inconsistent")
        require(exit_status[0] == child and exit_status[1] != 0 and
                exit_status[1] % 4096 == 0 and exit_status[2] == 0,
                "Forked child did not exit successfully in its own address space")
        require(reaped == (root, child) and ended == (root, child),
                "COW parent did not reap successful child or preserve its identity")
        require(roots[index][1] == root,
                "COW parent PID disagrees with CPU process completion")
        seen.update((root, child))
    return len(phases)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--log", type=Path, required=True)
    parser.add_argument("--cpus", type=int, choices=(1, 2), required=True)
    args = parser.parse_args()
    try:
        count = verify(args.log.read_text(encoding="ascii", errors="replace"), args.cpus)
    except (VerificationError, OSError) as error:
        print(f"COW fork acceptance failed: {error}", file=sys.stderr)
        return 1
    print(f"Verified {count} real COW fork/user-write/kernel-write/parent-isolation scenarios")
    return 0

if __name__ == "__main__":
    sys.exit(main())
