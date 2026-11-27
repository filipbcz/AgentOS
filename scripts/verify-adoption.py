"""Verify actual PID1 adoption and reap accounting, independently of the driver."""
import re

HEX=rb"[0-9a-f]{16}"
MARKER=b"AGENTOS ADOPTION TEST "
REAP_MARKER=b"AGENTOS MANAGER REAP "
REAP=re.compile(REAP_MARKER+rb"ROOT=("+HEX+rb") PID=("+HEX+rb") STATUS=("+HEX+rb")")
EXIT=re.compile(rb"AGENTOS USER EXIT PID=("+HEX+rb") CR3=("+HEX+rb") STATUS=("+HEX+rb")")
SNAP_FIELDS=("role","step","pid","parent","apic","cpus","moves","total","token","aux")
SNAP=re.compile(MARKER+rb"SNAP"+b"".join(b" "+f.upper().encode()+b"=("+HEX+b")" for f in SNAP_FIELDS))
ACTION=re.compile(MARKER+rb"(PARENT_REAP|WAIT|GO|DONE) STEP=("+HEX+rb") PID=("+HEX+rb")")
ORDER=(("snap",4,0),("snap",0,0),("snap",1,0),("snap",2,0),
       ("PARENT_REAP",0),("WAIT",1),("GO",1),("snap",1,1),
       ("snap",2,1),("WAIT",2),("GO",2),("snap",1,2),
       ("WAIT",3),("GO",3),("snap",0,4),("snap",3,0),
       ("PARENT_REAP",4),("snap",3,1),("DONE",3))


def values(match):
    return tuple(int(x,16) for x in match.groups())


def token(role,step):
    return 0x9b1735ac82000000 | role<<8 | step


def verify(data, root, shell, shell_cr3, prior, apics, require):
    """The shell command echo has already been consumed. Return precise
    consumed bytes, all actual PIDs and the expected live shutdown child.
    """
    reply=b"exit status 0\r\nagentos> "
    end=data.find(reply)
    require(end>=0,"Adoption foreground never returned status 0")
    prefix=data[:end]
    require(prefix.endswith(b"\r\n"),"Incomplete adoption foreground interval")
    actions=[]
    snapshots={}
    exits={}
    reaps={}
    for at,line in enumerate(prefix[:-2].split(b"\r\n")):
        match=SNAP.fullmatch(line)
        if match:
            s=dict(zip(SNAP_FIELDS,values(match)))
            role,step=s["role"],s["step"]
            require((role,step) not in snapshots,"Duplicate adoption snapshot")
            snapshots[role,step]=(at,s)
            actions.append((("snap",role,step),at,s["pid"]))
            require(s["pid"]>0 and s["apic"] in apics and s["cpus"]==len(apics) and
                    0<=s["moves"]<=s["total"]<2**63 and (len(apics)!=1 or s["total"]==0),
                    "Invalid actual scheduling snapshot")
            require(s["token"]==(1<<32 if (role,step)==(0,0) else token(role,step)) and
                    ((role,step)==(0,0) or s["aux"]==0),"Incorrect authenticated IPC challenge or zombie event")
            continue
        match=ACTION.fullmatch(line)
        if match:
            action=match[1].decode("ascii")
            step,pid=(int(x,16) for x in match.groups()[1:])
            actions.append(((action,step),at,pid))
            continue
        match=EXIT.fullmatch(line)
        if match:
            pid,cr3,status=values(match)
            require(pid not in exits and cr3>0 and cr3%4096==0 and cr3!=shell_cr3,
                    "Duplicate exit or non-private process address space")
            exits[pid]=(at,cr3,status)
            continue
        match=REAP.fullmatch(line)
        if match:
            owner,pid,status=values(match)
            require(owner==root and pid not in reaps,"Foreign or duplicate real PID1 collection")
            reaps[pid]=(at,status)
            continue
        require(False,"Unexpected event in actual adoption interval: "+repr(line))
    require(tuple(a[0] for a in actions)==ORDER,"Missing, reordered or fabricated adoption IPC evidence")
    runner=snapshots[4,0][1]["pid"]
    parent=snapshots[0,0][1]["pid"]
    zombie=snapshots[0,0][1]["aux"]
    live,pulse,shutdown=(snapshots[r,0][1]["pid"] for r in (1,2,3))
    shutdown_parent=snapshots[0,4][1]["pid"]
    pids=[runner,parent,zombie,live,pulse,shutdown_parent,shutdown]
    require(pids==sorted(set(pids)) and runner>max(set(prior)|{shell,root}),
            "Foreign or reused adoption PID")
    require(snapshots[4,0][1]["parent"]==shell and snapshots[0,0][1]["parent"]==runner and
            snapshots[0,4][1]["parent"]==runner,
            "Foreground controller/intermediate parent identity mismatch")
    for role,pid in ((1,live),(2,pulse),(3,shutdown)):
        previous=None
        for step in range((3,2,2)[role-1]):
            s=snapshots[role,step][1]
            original=shutdown_parent if role==3 else parent
            require(s["pid"]==pid and s["parent"]==(original if step==0 else root),
                    "Child did not retain identity across adoption into original PID1")
            if previous:
                require(0<=s["moves"]-previous["moves"]<=s["total"]-previous["total"] and
                        (s["apic"]==previous["apic"] or s["moves"]>previous["moves"]),
                        "Regressed or inconsistent migration evidence")
            previous=s
    expected={zombie:57,parent:0,pulse:58,live:59,shutdown_parent:0,runner:0}
    require(set(exits)==set(expected) and set(reaps)=={zombie,pulse,live},
            "Missing or extra actual natural exit/collection")
    require(all(exits[pid][2]==status for pid,status in expected.items()) and
            all(reaps[pid][1]==expected[pid] for pid in reaps),
            "Original natural exit status was lost")
    # All these spaces were allocated while the corresponding earlier
    # processes still existed, so none may share the same CR3.
    require(len({exits[pid][1] for pid in (runner,parent,zombie,live,pulse)})==5 and
            exits[shutdown_parent][1]!=exits[runner][1],
            "Aliased concurrently live or uncollected address space")
    positions={key:(at,pid) for key,at,pid in actions}
    require(exits[zombie][0]<snapshots[0,0][0] and
            snapshots[2,0][0]<exits[parent][0]<positions["PARENT_REAP",0][0] and
            positions["PARENT_REAP",0][1]==parent and
            exits[parent][0]<reaps[zombie][0],
            "Missing non-consuming pre-adoption zombie evidence or intermediate collection")
    for step,pid in ((1,zombie),(2,pulse),(3,live)):
        wait,wait_pid=positions["WAIT",step]
        go,go_pid=positions["GO",step]
        require(wait_pid==go_pid==pid and exits[pid][0]<reaps[pid][0]<go and wait<go,
                "Host advanced without actual PID1 collection of the expected child")
    require(positions["GO",1][0]<exits[pulse][0] and
            positions["GO",2][0]<exits[live][0] and
            snapshots[1,1][0]<reaps[pulse][0]<snapshots[1,2][0] and
            reaps[live][0]<snapshots[0,4][0]<snapshots[3,0][0]<exits[shutdown_parent][0]<
            positions["PARENT_REAP",4][0]<snapshots[3,1][0] and
            positions["PARENT_REAP",4][1]==shutdown_parent,
            "Live adoptee did not survive distinct passes or shutdown adoption is unproved")
    require(positions["DONE",3][1]==shutdown and positions["DONE",3][0]<exits[runner][0]==
            len(prefix[:-2].split(b"\r\n"))-1,
            "Foreground completion or still-live shutdown child mismatch")
    return end+len(reply),{
        "absent":False,"root_pid":root,"runner_pid":runner,"parent_pid":parent,
        "preexisting_zombie_pid":zombie,"live_pid":live,"pulse_pid":pulse,
        "shutdown_parent_pid":shutdown_parent,"shutdown_pid":shutdown,
        "snapshots":[s for _,s in sorted(snapshots.values(),key=lambda v:v[0])],
        "natural_exits":[{"pid":pid,"cr3":exits[pid][1],"status":status} for pid,status in expected.items()],
        "normal_collections":[{"pid":pid,"status":reaps[pid][1]} for pid in (zombie,pulse,live)]
    },set(pids)
