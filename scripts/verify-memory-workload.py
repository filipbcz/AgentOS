"""Separate foreground memory workload verification over the existing locality protocol.

No boot CPU completion or synthetic kernel event substitutes for actual
runtime evidence. The old boot verifiers remain usable on historical logs;
their interval checks are shared here, with stronger identity requirements.
"""
import importlib.util
from pathlib import Path

def load(name):
    spec=importlib.util.spec_from_file_location(name,Path(__file__).with_name(name))
    module=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

cow=load("verify-cow.py")
demand=load("verify-demand-paging.py")


def verify_interval(line, pid, before, seen, supervisor, require, kind):
    """Read exactly one complete workload, returning actual descendant CR3s."""
    require(pid in seen and before["pid"]==pid,"Unknown memory worker")
    previous=max(seen)
    records=[]
    try:
        if kind=="cow":
            first=cow.BEGIN.fullmatch(line())
            require(first is not None and tuple(int(v,16) for v in first.groups())==(pid,0),
                    "Wrong COW foreground owner")
            for event,pattern in (("child",cow.CHILD),("exit",cow.EXIT),
                                  ("reaps",cow.REAPS),("ended",cow.ENDED)):
                match=pattern.fullmatch(line())
                require(match is not None,"Missing actual COW "+event)
                records.append((event,tuple(int(v,16) for v in match.groups())))
            child,cr3=cow.verify_interval(pid,records,seen)
            descendants=[(child,cr3,0)]
            result={"child_pid":child,"child_status":0}
        elif kind=="demand":
            first=demand.gPhase.fullmatch(line())
            require(first is not None and first[1]=="BEGIN" and
                    tuple(int(v,16) for v in first.groups()[1:])==(pid,0,0),
                    "Wrong demand foreground owner")
            for event in demand.gExpected:
                pattern={"BASE":demand.gStats,"TOUCH":demand.gStats,
                         "exit":demand.gExit,"fault":demand.gFault}.get(event,demand.gPhase)
                match=pattern.fullmatch(line())
                require(match is not None,"Missing actual demand "+event)
                groups=match.groups()
                if event not in ("exit","fault"):
                    require(groups[0]==event,"Wrong demand event order")
                    groups=groups[1:]
                records.append((event,tuple(int(v,16) for v in groups)))
            result=demand.verify_interval(pid,records,set(seen))
            descendants=result["children"]
        else:
            require(False,"Unknown memory workload")
    except (cow.VerificationError,demand.VerificationError) as error:
        require(False,"Foreground memory: "+str(error))
    children=[c[0] for c in descendants]
    require(children==sorted(set(children)) and min(children)>previous,
            "Foreign, reused or reordered memory descendant PID")
    seen.update(children)
    # Parent/runner/shell live CR3 distinctness is checked when the real
    # candidate and controller exit. Sequential reaped descendants may reuse
    # physical page tables. A fault record carries the real kernel parent PID;
    # successful fork exit and the checked reap bind the nonfaulting child.
    result.update({"duration_ms":0,"child_statuses":[c[2] for c in descendants],
                   "child_cr3s":[c[1] for c in descendants]})
    return result,[c[1] for c in descendants]
