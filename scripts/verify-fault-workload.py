"""Verify the staged syscall/fault workload inside an actual locality bracket."""
import re

STACK_END = 0x10000000000
SENTINEL = STACK_END-8
MASK = (1 << 64)-1


def neg(value):
    return value & MASK


def verify_interval(line,pid,before,seen,supervisor,require):
    def fields(kind,names):
        pattern="AGENTOS TEST FAULT "+kind+"".join(
            " "+name+"=("+supervisor.HEX16+")" for name in names)
        match=re.fullmatch(pattern,line())
        require(match is not None,"Missing or malformed syscall/fault "+kind)
        return tuple(int(v,16) for v in match.groups())

    original=fields("BEFORE",("PID","VA","VALUE","INVALID","CROSS","UNKNOWN","EMPTY"))
    require(original==(pid,SENTINEL,pid,neg(-14),neg(-14),neg(-38),neg(-10)),
            "Wrong syscall error, initial private sentinel or descendant state")

    child,parent,cpu,cpus,moves,total,ms,va,value=fields("PROBE",
        ("PID","PARENT","APIC","CPUS","MOVES","TOTAL","MS","VA","VALUE"))
    require(child>max(seen|{pid}) and parent==pid and va==SENTINEL and
            value==MASK and before["ms"]<=ms<2**63 and
            before["total"]<=total<2**63 and 0<=moves<=total,
            "Foreign/reused fault child, wrong private sentinel or stale placement")

    fault=re.fullmatch("AGENTOS USER FAULT PID=("+supervisor.HEX16+
        ") PARENT=("+supervisor.HEX16+") CR3=("+supervisor.HEX16+
        ") VECTOR=("+supervisor.HEX16+") ERROR=("+supervisor.HEX16+
        ") ADDRESS=("+supervisor.HEX16+")",line())
    require(fault is not None,"Missing actual controlled user fault")
    actual,owner,cr3,vector,error,address=(int(v,16) for v in fault.groups())
    require((actual,owner,vector,error,address)==(child,pid,14,5,0x02000000)
            and cr3>0 and cr3%4096==0,
            "Wrong fault identity, address space, vector, access type or address")

    collector,spawned,start,until,end,status,again,empty,va,value=fields("COLLECT",
        ("PID","CHILD","START","UNTIL","END","STATUS","AGAIN","EMPTY","VA","VALUE"))
    require((collector,spawned,status,again,empty,va,value)==
            (pid,child,270,neg(-10),neg(-10),SENTINEL,pid),
            "Wrong actual collection, repeated wait or preserved private sentinel")
    require(before["ms"]<=start<=end<=until<2**63 and until==start+5000 and ms<=end,
            "Original bounded child wait or measured time not preserved")
    seen.add(child)
    return {"duration_ms":end-before["ms"],"child_pid":child,"child_cr3":cr3,
            "child_statuses":[status],"fault":{"vector":vector,"error":error,"address":address},
            "child":{"pid":child,"parent":parent,"apic":cpu,"cpus":cpus,
                     "moves":moves,"total":total,"ms":ms},
            "syscall_results":[-14,-14,-38],"sentinel":{"address":SENTINEL,
                "before":original[2],"child":MASK,"after":value},
            "wait_start_ms":start,"wait_deadline_ms":until,"wait_end_ms":end,
            "collected_status":status,"second_wait":-10,"remaining_children":-10},[cr3]


def verify_bracket(outcome,before,after,apics,local,require):
    child=outcome["child"]
    require(child["apic"] in apics and child["cpus"]==len(apics) and
            before["ms"]<=child["ms"]<=outcome["wait_end_ms"]<=after["ms"] and
            before["total"]<=child["total"]<=after["total"] and
            (len(apics)!=1 or child["moves"]==child["total"]==0),
            "Fault child is outside its authenticated CPU/time/migration bracket")
    if local:
        # The counter is monotonic for every completed migration. Its equality
        # at both parent boundaries covers spawn, actual child snapshot, fault
        # and collection, not just the configured CPU count or child's hint.
        require(child["apic"]==before["apic"]==after["apic"] and
                child["moves"]==0 and child["total"]==before["total"]==after["total"],
                "Fault child was not stationary through the full local interval")
