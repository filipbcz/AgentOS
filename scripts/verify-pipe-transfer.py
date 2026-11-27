"""Validate one real foreground transfer; the shared locality gate owns its enclosing interval."""
import re

H16=r"[0-9a-f]{16}"
H8=r"[0-9a-f]{8}"


def verify_interval(line, parent, before, seen, supervisor, require):
    def match(pattern, message):
        m=re.fullmatch(pattern,line())
        require(m is not None,message)
        return tuple(int(v,16) for v in m.groups())

    def snap(kind):
        names=("PID","PARENT","APIC","CPUS","MOVES","TOTAL","MS")
        values=match("AGENTOS PIPE TEST "+kind+"".join(" "+name+"=("+H16+")" for name in names),
                     "Missing receiver "+kind+" scheduler identity")
        return dict(zip(("pid","parent","apic","cpus","moves","total","ms"),values))

    start=snap("BEGIN")
    end=snap("ENDED")
    child=start["pid"]
    require(child>max(seen) and start["parent"]==parent and end["pid"]==child and
            end["parent"]==parent,"Foreign or replayed receiver identity")
    require(start["cpus"]==end["cpus"] and start["cpus"] in (1,2) and
            start["apic"]<=0xffffffff and end["apic"]<=0xffffffff and
            before["ms"]<=start["ms"]<=end["ms"] and
            before["total"]<=start["total"]<=end["total"] and
            0<=start["moves"]<=start["total"] and
            0<=end["moves"]-start["moves"]<=end["total"]-start["total"] and
            (start["apic"]==end["apic"] or end["moves"]>start["moves"]),
            "Regressed receiver time, APIC or migration counters")
    received=match(r"AGENTOS PIPE TEST RECEIVED PID=("+H16+r") BYTES=("+H8+r") FNV32=("+H8+r") EOF=("+H8+r")",
                   "Missing actual receiver contents and repeated EOF")
    require(received==(child,8193,0x1490a95f,2),"Incorrect received bytes/hash/EOF")
    exited=match(supervisor.EXIT.pattern,"Missing actual receiver exit")
    require(exited[0]==child and exited[1]>0 and exited[1]%4096==0 and exited[2]==0,
            "Receiver did not exit from a private address space with status zero")
    sent=match("AGENTOS PIPE TEST SENT"+"".join(" "+name+"=("+H16+")"
                for name in ("PID","CHILD","BYTES","DIRECT","DUP","WRITES","SHORT")),
               "Missing actual sender collection and transfer counts")
    require(sent[:3]==(parent,child,8193) and sent[3:5]==(12,11) and
            0<sent[6]<sent[5] and sent[5]==sum(sent[3:5])+sent[6],
            "Invalid shared-offset or partial-write transfer")
    seen.add(child)
    return {"child_pid":child,"child_cr3":exited[1],"child_before":start,"child_after":end,
            "bytes":received[1],"fnv32":received[2],"eof_reads":received[3],
            "direct_reads":sent[3],"duplicate_reads":sent[4],"writes":sent[5],
            "partial_writes":sent[6],"duration_ms":end["ms"]-start["ms"],
            "child_statuses":[0]},[exited[1]]


def verify_bracket(outcome,before,after,apics,local,require):
    a,b=outcome["child_before"],outcome["child_after"]
    require(a["cpus"]==b["cpus"]==len(apics) and a["apic"] in apics and b["apic"] in apics and
            before["ms"]<=a["ms"]<=b["ms"]<=after["ms"] and
            before["total"]<=a["total"]<=b["total"]<=after["total"],
            "Receiver not contained in authenticated parent interval")
    if local:
        require(a["apic"]==b["apic"]==before["apic"] and a["moves"]==b["moves"]==0,
                "Receiver was not local for the entire transfer")
