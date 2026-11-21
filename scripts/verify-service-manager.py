"""Verify the *actual* long-running operational service manager bootstrap.

This consumes a real guest COM1 transcript. The core worker must become ready
before any dependent worker starts. Three distinct flaky children each send
an authenticated readiness handshake, then exit 42 and get reaped; after two
bounded restarts the manager records a FAILED service without preventing local
shell login. The shell child does not print SHELL READY until its handshake
was accepted. It remains a separate process, owned by an active manager root.

The operational manager must be the first BSP PID 1, parked by the kernel
between boot acceptance and TTY initialization. Runtime control/cleanup is
checked separately by the authenticated interactive shell verifier.
"""
import argparse
import importlib.util
from pathlib import Path
import re
import sys


HEX=r"[0-9a-f]{16}"
PARK=re.compile(rf"AGENTOS USER PARK PID=({HEX}) CR3=({HEX}) STATUS=0000000000000000")
SESSION=re.compile(rf"AGENTOS MANAGER SESSION START PID=({HEX})")
PHASE=re.compile(rf"AGENTOS MANAGER (BEGIN|ONLIN|SHUTD|ENDED) ROOT=({HEX}) COUNT=00000003")
EVENT=re.compile(rf"AGENTOS MANAGER (START|READY|RETRY|LIMIT) ROOT=({HEX}) SERVICE=(core |flaky|shell) PID=({HEX}) ATTEMPT=([0-9a-f]{{8}})")
EXIT=re.compile(rf"AGENTOS USER EXIT PID=({HEX}) CR3=({HEX}) STATUS=({HEX})")
SHELL_START=re.compile(rf"AGENTOS SHELL START PID=({HEX})")

class VerificationError(ValueError):
    pass

def require(value,message):
    if not value: raise VerificationError(message)

def verify(text):
    lines=text.splitlines()
    pMigration = None
    if "AGENTOS MIGRATION" in text:
        pSpec = importlib.util.spec_from_file_location(
            "managerMigrationEvidence", Path(__file__).with_name("verify-migration.py"))
        pModule = importlib.util.module_from_spec(pSpec)
        pSpec.loader.exec_module(pModule)
        try:
            pMigration = pModule.verify(text)
        except pModule.VerificationError as pError:
            raise VerificationError(f"Invalid migration prelude: {pError}") from pError
    starts=[(i,SESSION.fullmatch(v)) for i,v in enumerate(lines) if v.startswith("AGENTOS MANAGER SESSION START")]
    require(len(starts)==1 and starts[0][1] is not None,"Expected one valid operational manager session")
    start,match=starts[0]
    root=int(match[1],16)
    require(root==1,"Operational manager must retain original BSP PID 1")
    parked=[(i,PARK.fullmatch(line)) for i,line in enumerate(lines[:start])
            if line.startswith("AGENTOS USER PARK")]
    require(len(parked)==1 and parked[0][1] is not None and
            int(parked[0][1][1],16)==root and
            int(parked[0][1][2],16)!=0 and int(parked[0][1][2],16)%4096==0,
            "Original PID 1 never parked after boot tests or used invalid CR3")

    shell=[i for i,v in enumerate(lines) if v.startswith("AGENTOS SHELL START")]
    require(len(shell)==1 and shell[0]>start,"Expected one shell child after root manager startup")
    shell_index=shell[0]
    ready=[i for i,v in enumerate(lines) if v=="AGENTOS SHELL READY"]
    require(len(ready)==1 and ready[0]>shell_index,"Shell did not acknowledge manager readiness")
    # Strict event order; unknown process exits or malformed manager events
    # cannot silently be skipped as background noise.
    events=[]
    for n in range(start+1,shell_index+1):
        # Migration runs after the SAME parked root resumes, before it opens
        # the service registry. Exclude only an independently complete and
        # strictly validated subtrace; arbitrary process exits remain errors.
        if pMigration is not None and pMigration["begin_line"] <= n <= pMigration["end_line"]:
            continue
        line=lines[n]
        if line.startswith("AGENTOS MANAGER "):
            phase=PHASE.fullmatch(line)
            record=EVENT.fullmatch(line)
            require(phase is not None or record is not None,
                    f"Malformed service manager record at line {n+1}")
            if phase:
                events.append((phase[1].lower(),(int(phase[2],16),)))
            else:
                events.append((record[1].lower(),
                    (int(record[2],16),record[3].strip(),int(record[4],16),int(record[5],16))))
        elif line.startswith("AGENTOS USER EXIT"):
            match=EXIT.fullmatch(line)
            require(match is not None,f"Malformed child exit at line {n+1}")
            events.append(("exit",tuple(int(v,16) for v in match.groups())))
        elif line.startswith("AGENTOS SHELL START"):
            match=SHELL_START.fullmatch(line)
            require(match is not None,"Malformed shell start")
            events.append(("shell_start",(int(match[1],16),)))
        elif line.startswith(("AGENTOS USER ","AGENTOS IPC ","AGENTOS SHELL ")):
            raise VerificationError(f"Unexpected process/IPC event at line {n+1}")
    require(events and events[0]==("begin",(root,)),"Root manager does not open its registry")
    i=1
    seen={root}
    def event(kind,service,pid=None,attempt=None):
        nonlocal i
        require(i<len(events) and events[i][0]==kind,
                f"Expected {kind} for {service} at step {i}")
        r,name,child,number=events[i][1]
        require(r==root and name==service and
                (pid is None or child==pid) and
                (attempt is None or number==attempt),
                f"Unexpected {kind} service PID/attempt/owner: {events[i]}")
        i+=1
        return child
    core=event("start","core",attempt=1)
    require(core>root and core not in seen,"Invalid core PID")
    seen.add(core)
    event("ready","core",core,1)
    for attempt in (1,2,3):
        child=event("start","flaky",attempt=attempt)
        require(child>0 and child not in seen and child!=core,"Flaky worker PID reused")
        seen.add(child)
        event("ready","flaky",child,attempt)
        require(i<len(events) and events[i][0]=="exit","Flaky service did not actually terminate")
        ex_pid,cr3,status=events[i][1]
        require(ex_pid==child and cr3!=0 and cr3%4096==0 and status==42,
                "Flaky worker exited with wrong PID, CR3 or crash status")
        i+=1
        if attempt<3: event("retry","flaky",0,attempt)
        else: event("limit","flaky",0,attempt)
    require(i<len(events) and events[i]==("onlin",(root,)),
            "Manager did not remain online after bounded service failure")
    i+=1
    shell_pid=event("start","shell",attempt=1)
    require(shell_pid!=root and shell_pid not in seen and shell_pid>0,
            "Shell reuses worker/root PID")
    seen.add(shell_pid)
    require(i<len(events) and events[i]==("shell_start",(shell_pid,)) and i==len(events)-1,
            "Shell child started before dependency probation or had wrong PID")
    return root,shell_pid

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--log",type=Path,required=True)
    args=parser.parse_args()
    try:
        root,shell=verify(args.log.read_text(encoding="ascii",errors="replace"))
    except (VerificationError,OSError) as error:
        print(f"Service manager guest verification failed: {error}",file=sys.stderr)
        return 1
    print(f"Verified operational root {root}, three authenticated restart-limited attempts and child shell {shell}")
    return 0

if __name__=="__main__":
    sys.exit(main())
