"""Check COM1 evidence for isolation and authenticated local IPC during ordinary boot.

This checks a captured log; it does not boot a VM or establish its provenance.
The current kernel runs each CPU's process scenario sequentially.
"""
import argparse
import importlib.util
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
    "exit": f"AGENTOS USER (?:EXIT|PARK) PID={PID} CR3={hex_field('cr3')} "
            f"STATUS={hex_field('status')}",
    "check": f"AGENTOS PROCESS OK APIC={hex_field('apic')} PARENT={hex_field('parent')}",
    "service": f"AGENTOS IPC SERVICE {PEER}",
    "reply": f"AGENTOS IPC REPLY {PEER}",
}
PATTERNS = {kind: re.compile(pattern) for kind, pattern in PATTERNS.items()}
PREFIXES = ("AGENTOS USER ", "AGENTOS IPC ", "AGENTOS PROCESS ")
ORDER = ("fault", "survived", "service", "exit", "reply", "exit", "check")
RELOCATED_ORDER = ("fault", "survived", "exit", "check")
SHELL_START = re.compile(r"AGENTOS SHELL START PID=([0-9a-f]{16})")
MANAGER_SESSION = re.compile(r"AGENTOS MANAGER SESSION START PID=([0-9a-f]{16})")
ORPHAN_BEGIN = re.compile(r"AGENTOS ORPHAN BEGIN ROOT=([0-9a-f]{16})")
ORPHAN_END = re.compile(r"AGENTOS ORPHAN ENDED ROOT=([0-9a-f]{16})")
COW_BEGIN = re.compile(r"AGENTOS COW BEGIN ROOT=([0-9a-f]{16}) CHILD=0000000000000000")
COW_END = re.compile(r"AGENTOS COW ENDED ROOT=([0-9a-f]{16}) CHILD=([0-9a-f]{16})")
gDemandBegin = re.compile(r"AGENTOS DEMAND BEGIN ROOT=([0-9a-f]{16}) CHILD=0000000000000000 ADDRESS=0000000000000000")
gDemandEnd = re.compile(r"AGENTOS DEMAND ENDED ROOT=([0-9a-f]{16}) CHILD=0000000000000000 ADDRESS=0000000000000000")


def require(condition, message):
    if not condition:
        raise VerificationError(message)


def verify(text, apic_ids, *, ipc_staged=False, allow_ipc_workload=False,
           root_orphan_v1=False, require_shutdown=False):
    """Reject incomplete, malformed, contradictory or repeated process evidence."""
    expected_cpus = set(apic_ids)
    require(expected_cpus and len(expected_cpus) == len(apic_ids),
            "Expected APIC IDs must be nonempty and unique")
    # The historical boot-only transfer is forbidden even after the shell boundary.
    # The separately authenticated foreground verifier owns staged PIPE TEST records.
    require(re.search(r"AGENTOS PIPE (?!TEST )", text) is None,
            "Historical boot pipe transfer is not permitted")
    # A caller must select the current product contract explicitly. Never
    # infer it from missing historical records. The CLI remains historical
    # until VirtualBox runs both signed variants with the new foreground gate.
    require(not allow_ipc_workload or ipc_staged,"Mixed historical and staged IPC evidence")
    if ipc_staged:
        require(re.search(r"AGENTOS IPC (?!TEST )",text) is None,
                "Historical boot IPC evidence is forbidden in current images")
        require(allow_ipc_workload or "AGENTOS IPC TEST " not in text,
                "IPC test executed in the ordinary distribution")
    require(not root_orphan_v1 or ipc_staged,"Explicit root/orphan contract requires staged IPC")
    require(not require_shutdown or root_orphan_v1,"Shutdown correlation requires explicit root/orphan contract")
    if root_orphan_v1:
        spec=importlib.util.spec_from_file_location(
            "bootRootEvidence",Path(__file__).with_name("verify-boot-roots.py"))
        module=importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module.verify(text,apic_ids,require,require_shutdown=require_shutdown)
    order=RELOCATED_ORDER if ipc_staged else ORDER
    events = []
    orphan_open = None
    orphan_roots = []
    cow_open = None
    cow_roots = []
    pDemandOpen = None
    pDemandRoots = []
    manager_open = False
    for number, line in enumerate(text.splitlines(), 1):
        # Only the separate foreground verifier owns the relocated workload.
        require(not any(marker in line for marker in
                        ("AGENTOS SUPERVISOR", "AGENTOS SERVICE ", "AGENTOS TEST ", "AGENTOS PIPE ", "AGENTOS IPC TEST ")),
                f"Acceptance workload executed during ordinary boot at line {number}")
        if line.startswith("AGENTOS MANAGER SESSION START"):
            match = MANAGER_SESSION.fullmatch(line)
            require(match is not None and int(match[1],16)>0 and not manager_open and
                    orphan_open is None and cow_open is None and pDemandOpen is None and
                    sum(kind=="check" for kind,_,_ in events)==len(expected_cpus),
                    f"Operational root manager began before CPU process tests completed at {number}")
            manager_open=True
            continue
        if manager_open:
            if line.startswith("AGENTOS SHELL START"):
                match=SHELL_START.fullmatch(line)
                require(match is not None and int(match[1],16)>0,
                        f"Invalid managed shell boundary at {number}")
                break
            # verify-service-manager.py strictly authenticates the entire
            # ongoing registry/worker/ready/restart subtrace. Do not mistake
            # its worker process EXIT records for the boot IPC child.
            continue
        if line.startswith("AGENTOS DEMAND "):
            pBegin = gDemandBegin.fullmatch(line)
            pEnd = gDemandEnd.fullmatch(line)
            require(orphan_open is None and cow_open is None,
                    f"Demand phase overlaps prior stage at line {number}")
            if pBegin:
                require(pDemandOpen is None and len(cow_roots) > len(pDemandRoots) and
                        int(pBegin[1], 16) == cow_roots[-1],
                        f"Demand phase is nested or precedes its COW test at line {number}")
                pDemandOpen = int(pBegin[1], 16)
            elif pEnd:
                require(pDemandOpen is not None and int(pEnd[1], 16) == pDemandOpen,
                        f"Unmatched demand phase end at line {number}")
                pDemandRoots.append(pDemandOpen)
                pDemandOpen = None
            else:
                require(pDemandOpen is not None, f"Demand event outside interval at line {number}")
            continue
        if pDemandOpen is not None:
            # The dedicated mandatory verifier owns all lazy fork/protection
            # child exits and faults inside these explicit boundaries.
            require(not line.startswith(("AGENTOS COW ", "AGENTOS ORPHAN ",
                                         "AGENTOS SUPERVISOR ", "AGENTOS PROCESS ",
                                         "AGENTOS SHELL ")),
                    f"Unterminated demand interval at line {number}")
            continue
        if line.startswith("AGENTOS COW "):
            begin = COW_BEGIN.fullmatch(line)
            end = COW_END.fullmatch(line)
            require(orphan_open is None,
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
            # isolation evidence; do not mistake its USER EXIT for boot IPC.
            continue
        if line.startswith("AGENTOS ORPHAN "):
            begin = ORPHAN_BEGIN.fullmatch(line)
            end = ORPHAN_END.fullmatch(line)
            if begin:
                if ipc_staged:
                    follows=(len(events)>=2 and events[-1][0]=="survived" and
                             events[-2][0]=="fault" and events[-2][1]["parent"]==int(begin[1],16) and
                             len(orphan_roots)<sum(kind=="survived" for kind,_,_ in events))
                else:
                    follows=(events and events[-1][0]=="reply" and events[-1][1]["pid"]==int(begin[1],16) and
                             len(orphan_roots)<sum(kind=="reply" for kind,_,_ in events))
                require(orphan_open is None and follows,
                        f"Orphan phase is nested or does not follow its authenticated root at line {number}")
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

    require(orphan_open is None, "Unterminated orphan interval")
    require(cow_open is None, "Unterminated COW interval")
    require(pDemandOpen is None, "Unterminated demand interval")
    require(not pDemandRoots or len(pDemandRoots) == len(expected_cpus),
            "Missing demand interval on one or more CPUs")
    require(not cow_roots or len(cow_roots) == len(expected_cpus),
            "Missing fork/COW interval on one or more CPUs")
    require(not orphan_roots or len(orphan_roots) == len(expected_cpus),
            "Missing orphan interval on one or more CPUs")
    if ipc_staged:
        require(len(orphan_roots)==len(expected_cpus) and not cow_roots and not pDemandRoots,
                "Current boot must preserve every orphan family without relocated memory workloads")
    require(len(events) == len(order) * len(expected_cpus),
            f"Incomplete or extra process evidence: expected {len(order) * len(expected_cpus)} "
            f"records, found {len(events)}")
    seen_cpus, seen_pids = set(), set()
    for offset in range(0, len(events), len(order)):
        block = events[offset:offset + len(order)]
        require(tuple(event[0] for event in block) == order,
                f"Invalid process event order starting at line {block[0][2]}")
        if ipc_staged:
            fault, _, parent_exit, check = (event[1] for event in block)
        else:
            fault, _, service, service_exit, reply, parent_exit, check = (event[1] for event in block)
        cpu, parent = check["apic"], check["parent"]
        child = fault["pid"]
        context = f"APIC {cpu:016x}, parent {parent:016x}"
        pids = {parent, child} if ipc_staged else {parent,child,service["pid"]}
        if orphan_roots:
            require(orphan_roots[len(seen_cpus)] == parent,
                    f"Orphan interval does not belong to this parent: {context}")
        if cow_roots:
            require(cow_roots[len(seen_cpus)] == parent,
                    f"COW interval does not belong to this parent: {context}")
        if pDemandRoots:
            require(pDemandRoots[len(seen_cpus)] == parent,
                    f"Demand interval does not belong to this parent: {context}")
        require(cpu in expected_cpus and cpu not in seen_cpus,
                f"Unexpected or repeated CPU: {context}")
        require(len(pids) == (2 if ipc_staged else 3) and 0 not in pids and not (pids & seen_pids),
                f"Process IDs must be nonzero, distinct and unreused: {context}")
        require(fault["parent"] == parent and parent_exit["pid"] == parent and
                (fault["vector"], fault["error"], fault["address"]) == (14, 5, 0x02000000),
                f"Invalid isolation fault or parent identity: {context}")
        if not ipc_staged:
            server=service["pid"]
            require(service["peer"] == parent and reply["pid"] == parent and
                    reply["peer"] == server and service_exit["pid"] == server and
                    service["uid"] == service["gid"] == reply["uid"] == reply["gid"] == 1000,
                    f"Invalid IPC peer identity: {context}")
        exits = (parent_exit,) if ipc_staged else (service_exit, parent_exit)
        require(all(record["status"] == 0 for record in exits),
                f"User process exited unsuccessfully: {context}")
        roots = (fault["cr3"],) if ipc_staged else (fault["cr3"], service_exit["cr3"])
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
