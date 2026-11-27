"""Explicit root-orphan-v1 boot contract. No dependency on a fault child."""
import re

HEX = r"[0-9a-f]{16}"
TASK = re.compile(rf"AGENTOS TASK (BSP|AP) APIC=({HEX}) TIMER-WAKES=0000000000000003")
BEGIN = re.compile(rf"AGENTOS ORPHAN BEGIN ROOT=({HEX})")
END = re.compile(rf"AGENTOS ORPHAN ENDED ROOT=({HEX})")
ADOPT = re.compile(rf"AGENTOS ORPHAN ADOPT ROOT=({HEX}) PARENT=({HEX}) CHILD=({HEX}) STATUS=({HEX})")
REAPS = re.compile(rf"AGENTOS ORPHAN REAPS ROOT=({HEX}) PARENT=({HEX}) CHILD=({HEX}) STATUS=({HEX})")
EXIT = re.compile(rf"AGENTOS USER EXIT PID=({HEX}) CR3=({HEX}) STATUS=({HEX})")
PARK = re.compile(rf"AGENTOS USER PARK PID=({HEX}) CR3=({HEX}) STATUS=({HEX})")
KILL = re.compile(rf"AGENTOS USER KILL PID=({HEX}) PARENT=({HEX}) STATUS=({HEX})")
CHECK = re.compile(rf"AGENTOS PROCESS OK APIC=({HEX}) PARENT=({HEX})")
MANAGER = re.compile(rf"AGENTOS MANAGER SESSION START PID=({HEX})")
MANAGER_BEGIN = re.compile(rf"AGENTOS MANAGER BEGIN ROOT=({HEX}) COUNT=00000003")
STOP = re.compile(rf"AGENTOS MANAGER SESSION STOP PID=({HEX}) STATUS=0000000000000000 FRAMES=OK")
SHELL = re.compile(rf"AGENTOS SHELL START PID=({HEX})")
USER_PID = re.compile(rf"AGENTOS USER (?:EXIT|FAULT|KILL) PID=({HEX})(?: |$)")


def verify(text, apic_ids, require, *, require_shutdown=False):
    """Bind actual sequential kernel completions to complete orphan families.

    The dedicated orphan and manager/session verifiers remain mandatory at
    the caller. PROCESS OK is emitted only after kernel collection/park and
    exact frame accounting. Never infer a missing root from a runtime test.
    """
    lines = text.splitlines()
    expected = set(apic_ids)
    require(expected and len(expected) == len(apic_ids), "Invalid expected CPU roster")

    def unique(prefix, pattern):
        found = [(i, pattern.fullmatch(line)) for i,line in enumerate(lines)
                 if line.startswith(prefix)]
        require(len(found)==1 and found[0][1] is not None,
                "Missing, malformed or repeated "+prefix)
        return found[0]

    start,manager = unique("AGENTOS MANAGER SESSION START",MANAGER)
    begin_at,begin = unique("AGENTOS MANAGER BEGIN",MANAGER_BEGIN)
    shell_at,shell = unique("AGENTOS SHELL START",SHELL)
    ready = [i for i,line in enumerate(lines) if line.startswith("AGENTOS SHELL READY")]
    require(len(ready)==1 and lines[ready[0]]=="AGENTOS SHELL READY" and
            start<begin_at<shell_at<ready[0] and int(manager[1],16)==int(begin[1],16)==1,
            "Invalid original PID1 manager/shell readiness boundary")
    ready_at=ready[0]
    require(not any("AGENTOS USER SURVIVED" in line for line in lines) and
            not any(line.startswith("AGENTOS USER FAULT") for line in lines[:ready_at+1]),
            "Historical fault/syscall regression leaked into boot")
    require(not any(any(marker in line for marker in ("AGENTOS SUPERVISOR", "AGENTOS SERVICE ",
                "AGENTOS TEST ", "AGENTOS PIPE ", "AGENTOS IPC TEST ", "AGENTOS COW ", "AGENTOS DEMAND "))
                for line in lines[:ready_at+1]), "Acceptance workload executed during ordinary boot")

    roster=[]
    events=[]
    for i,line in enumerate(lines[:start]):
        if line.startswith("AGENTOS TASK "):
            m=TASK.fullmatch(line)
            require(m is not None and not events,"Malformed or late CPU roster record")
            roster.append((m[1],int(m[2],16)))
        elif line.startswith(("AGENTOS USER ","AGENTOS ORPHAN ","AGENTOS PROCESS ")):
            events.append((i,line))
    require(len(roster)==len(expected) and {cpu for _,cpu in roster}==expected and
            [kind for kind,_ in roster].count("BSP")==1,"Missing or repeated actual BSP/AP roster")
    bsp=next(cpu for kind,cpu in roster if kind=="BSP")
    require(len(events)==8*len(expected),"Incomplete or extra boot root/orphan records")
    # No later boot-family record can be mistaken for foreground evidence.
    require(not any(line.startswith(("AGENTOS ORPHAN ","AGENTOS PROCESS ","AGENTOS TASK ",
                                    "AGENTOS USER PARK")) for line in lines[start:]),
            "Boot family evidence outside the boot interval")

    def fields(pattern, row):
        m=pattern.fullmatch(row[1])
        require(m is not None,f"Invalid root/orphan event at line {row[0]+1}")
        return tuple(int(v,16) for v in m.groups())

    seen=set()
    covered=set()
    families=[]
    bsp_cr3=0
    for offset in range(0,len(events),8):
        block=events[offset:offset+8]
        root,=fields(BEGIN,block[0])
        parent,parent_cr3,parent_status=fields(EXIT,block[1])
        adopter,old_parent,child,adopt_status=fields(ADOPT,block[2])
        killed=fields(KILL,block[3])
        collected=fields(REAPS,block[4])
        ended,=fields(END,block[5])
        root_pid,cr3,status=fields(PARK if offset==0 else EXIT,block[6])
        apic,checked=fields(CHECK,block[7])
        require(root>max(seen|{0}) and root<parent<child and root==root_pid==ended==checked and
                (adopter,old_parent,adopt_status)==(root,parent,0) and
                killed==(child,root,137) and collected==(root,parent,child,137),
                "Foreign, reused or incompletely collected boot orphan family")
        require(apic in expected and apic not in covered and
                ((offset==0 and apic==bsp and root==1) or
                 (offset!=0 and apic!=bsp and root!=1)),
                "Wrong BSP/AP ownership or repeated CPU completion")
        require(parent_status==status==0 and cr3>0 and cr3%4096==0 and
                parent_cr3>0 and parent_cr3%4096==0 and parent_cr3!=cr3 and
                (offset==0 or bsp_cr3 not in (cr3,parent_cr3)),
                "Invalid private boot root/parent CR3 or park/exit status")
        if offset==0:
            bsp_cr3=cr3
        covered.add(apic)
        seen.update((root,parent,child))
        families.append({"apic":apic,"root_pid":root,"root_cr3":cr3,
                         "terminal":"park" if offset==0 else "exit",
                         "parent_pid":parent,"parent_cr3":parent_cr3,"child_pid":child,
                         "collected_status":137})
    require(covered==expected and int(shell[1],16)>max(seen),
            "Missing CPU family or reused shell PID")
    root_exits=[]
    shell_exits=[]
    stops=[]
    for i,line in enumerate(lines[start+1:],start+1):
        if line.startswith("AGENTOS MANAGER SESSION STOP"):
            m=STOP.fullmatch(line)
            require(m is not None and int(m[1],16)==1,"Wrong manager stop or frame restoration")
            stops.append(i)
        if line.startswith(("AGENTOS USER EXIT ","AGENTOS USER FAULT ","AGENTOS USER KILL ")):
            m=USER_PID.match(line)
            require(m is not None,"Malformed runtime process identity")
            pid=int(m[1],16)
            if pid==1:
                m=EXIT.fullmatch(line)
                require(m is not None and (int(m[2],16),int(m[3],16))==(bsp_cr3,0),
                        "Resumed PID1 does not exit from its parked CR3")
                root_exits.append(i)
            else:
                require(pid>max(seen),"Reused boot root or orphan PID in manager/runtime")
                if pid==int(shell[1],16):
                    m=EXIT.fullmatch(line)
                    require(m is not None and int(m[3],16)==0 and int(m[2],16)>0 and
                            int(m[2],16)%4096==0 and int(m[2],16)!=bsp_cr3,
                            "Managed shell did not exit from its private CR3")
                    shell_exits.append(i)
    require((not require_shutdown and not shell_exits and not root_exits and not stops) or
            (len(shell_exits)==len(root_exits)==len(stops)==1 and
             ready_at<shell_exits[0]<root_exits[0]<stops[0]),
            "Missing, repeated or out-of-order original PID1 shutdown")
    return {"contract":"root-orphan-v1","bsp_apic":bsp,"bsp_cr3":bsp_cr3,
            "manager_pid":1,"shell_pid":int(shell[1],16),"families":families,
            "shutdown_verified":bool(stops)}
