"""Strict authenticated 60-second SMP workload trace, independent of boot CPU work."""
import re

COMMAND="run /smp-soak"
INPUT=(COMMAND+"\r").encode("ascii")
MARKER=b"AGENTOS TEST SMP SOAK "
HEX=rb"[0-9a-f]{16}"
MASK=(1<<64)-1
EPOCHS=30
EPOCH_MS=2000
DURATION=60000
WINDOW_EPOCHS=5
PAYLOAD=128
EXIT=re.compile(rb"AGENTOS USER EXIT PID=("+HEX+rb") CR3=("+HEX+rb") STATUS=("+HEX+rb")")

class VerificationError(ValueError):
    pass

def require(ok,message):
    if not ok:
        raise VerificationError(message)

def payload_digest(pid,epoch,sequence):
    # Recompute independently from the received sequence and authenticated PID.
    h=14695981039346656037
    for i in range(PAYLOAD):
        byte=(pid*73+epoch*29+sequence*19+i*37+(i>>3)*11+
              ((sequence>>8)^(pid>>3)^(epoch*7)))&255
        h=((h^byte)*1099511628211)&MASK
    return h

def verify_prefix(data,shell,shell_cr3,prior,apics):
    """Consume exactly the foreground command, actual child exits, and reply."""
    require(len(apics) in (4,8),"SMP soak needs actual 4/8 CPU roster")
    cpus=len(apics)
    count=cpus+2
    echo=(COMMAND+"\r\n").encode("ascii")
    require(data.startswith(echo),"Missing SMP soak shell command echo")
    pos=len(echo)
    def line():
        nonlocal pos
        end=data.find(b"\r\n",pos)
        require(end>=0,"Incomplete SMP soak record")
        row=data[pos:end]
        pos=end+2
        return row
    def fields(kind,names):
        prefix=MARKER+kind.encode("ascii")
        pattern=re.escape(prefix)+b"".join(b" "+k.encode("ascii")+b"=("+HEX+b")" for k in names.split())
        row=line()
        match=re.fullmatch(pattern,row)
        require(match is not None and len(row)+2<=256,"Bad or missing SMP soak "+kind)
        return tuple(int(v,16) for v in match.groups())
    def next_is(kind):
        return data.startswith(MARKER+kind.encode("ascii")+b" ",pos)
    root,parent,n,workers,cpu,setup,setup_limit=fields("ROOT","PID PARENT CPUS WORKERS APIC MS LIMIT")
    require(parent==shell and root>max(set(prior)|{shell}) and n==cpus and workers==count and
            cpu in apics and setup_limit==setup+20000 and setup_limit<(1<<63)-100000,
            "Wrong foreground owner or setup deadline")
    pids=[]
    for slot in range(count):
        owner,s,child=fields("SPAWN","PID SLOT CHILD")
        require(owner==root and s==slot and child>max([root]+pids),"Lost or duplicated forked child")
        pids.append(child)
    states={}
    for _ in pids:
        pid,parent,slot,cpu,n,moves,ms,uid,gid=fields("READY","PID PARENT SLOT APIC CPUS MOVES MS UID GID")
        require(slot<count and pid==pids[slot] and pid not in states and
                parent==root and cpu in apics and n==cpus and setup<=ms<setup_limit and uid==gid==1000,
                "Wrong authenticated READY identity")
        states[pid]={"apic":cpu,"moves":moves,"time":ms,"work":0,"samples":[]}
    owner,go,start,end,deadline=fields("GO","PID MS START END DEADLINE")
    require(owner==root and max(s["time"] for s in states.values())<=go<setup_limit and
            start==go+2000 and end==start+DURATION and deadline==end+15000,
            "Incorrect common time gate or deadline")
    done={}
    all_samples=[{} for _ in range(EPOCHS)]
    last_rx=go
    while len(done)<count:
        if next_is("SAMPLE"):
            pid,epoch,begin,mid,finish,before,middle,after=fields(
                "SAMPLE","PID EPOCH START MID END BEFORE MIDDLE AFTER")
            sender,e,apic0,apic1,moves0,moves1,digest,rx=fields(
                "DATA","PID EPOCH APIC0 APIC1 MOVE0 MOVE1 HASH RX")
            require(pid in states and pid not in done and sender==pid and e==epoch and epoch<EPOCHS,
                    "Foreign, mispaired or duplicate data record")
            previous=states[pid]
            base=start+epoch*EPOCH_MS
            require(epoch==len(previous["samples"]) and base<=begin<=base+500 and
                    base+750<=mid<=base+1100 and base+1500<=finish<=base+EPOCH_MS and
                    begin<mid<finish and begin>=previous["time"] and
                    before>=previous["work"] and before<middle<after and
                    (middle-before)%64==0 and (after-middle)%64==0 and
                    apic0 in apics and apic1 in apics and
                    moves1>=moves0>=previous["moves"] and
                    (apic0==previous["apic"] or moves0>previous["moves"]) and
                    (apic0==apic1 or moves1>moves0) and
                    max(finish,last_rx)<=rx<=min(deadline,base+EPOCH_MS+3000),
                    "Invalid clock, real-work or CPU identity interval")
            require(digest==payload_digest(pid,epoch,after),"Receiver data integrity mismatch")
            sample={"pid":pid,"epoch":epoch,"start":begin,"mid":mid,"end":finish,"before":before,
                    "middle":middle,"after":after,"apic0":apic0,"apic1":apic1,"moves0":moves0,
                    "moves1":moves1,"stable":apic0==apic1 and moves0==moves1,
                    "hash":f"{digest:016x}","received_ms":rx}
            require(pid not in all_samples[epoch],"Duplicate process sample")
            all_samples[epoch][pid]=sample
            previous["samples"].append(sample)
            previous.update(apic=apic1,moves=moves1,time=finish,work=after)
            last_rx=rx
        elif next_is("DONE"):
            pid,cpu,moves,ms,work,again=fields("DONE","PID APIC MOVES MS WORK TRY")
            require(pid in states and pid not in done,"Unknown or repeated DONE")
            previous=states[pid]
            require(len(previous["samples"])==EPOCHS and cpu in apics and moves>=previous["moves"] and
                    (cpu==previous["apic"] or moves>previous["moves"]) and end<=ms<=end+2000 and
                    work>previous["work"] and again==((-11)&MASK),"Worker did not remain alive through the common window")
            done[pid]={"apic":cpu,"moves":moves,"ms":ms,"work":work}
        else:
            raise VerificationError("Missing authenticated sample or DONE; premature exit or unexpected output")
    windows=[]
    for first in range(0,EPOCHS,WINDOW_EPOCHS):
        covered=set()
        overlaps=[]
        stable_samples=0
        for e in range(first,first+WINDOW_EPOCHS):
            samples=all_samples[e]
            require(set(samples)==set(pids),"Incomplete simultaneous worker roster")
            shared_start=max(s["start"] for s in samples.values())
            shared_end=min(s["end"] for s in samples.values())
            require(shared_end-shared_start>=500,"No real common work interval")
            stable=[s for s in samples.values() if s["stable"]]
            local={s["apic0"] for s in stable}
            require(len(local)>=2,"No overlapping stable work on distinct CPUs")
            covered.update(local)
            stable_samples+=len(stable)
            overlaps.append({"epoch":e,"start":shared_start,"end":shared_end,
                             "stable_apics":sorted(local)})
        require(covered==set(apics),f"Missing actual APIC work in window {first//WINDOW_EPOCHS}: {sorted(set(apics)-covered)}")
        windows.append({"window":first//WINDOW_EPOCHS,"start":start+first*EPOCH_MS,
                        "end":start+(first+WINDOW_EPOCHS)*EPOCH_MS,"apics":sorted(covered),
                        "stable_samples":stable_samples,"overlap":overlaps})
    owner,release,number,limit=fields("RELEASE","PID MS COUNT DEADLINE")
    require(owner==root and number==count and limit==deadline and
            max(last_rx,max(d["ms"] for d in done.values()))<=release<deadline,
            "Premature release or missing live worker roster")
    exits={}
    collected=set()
    while len(collected)<count:
        if next_is("REAP"):
            owner,child,status,again=fields("REAP","PID CHILD STATUS AGAIN")
            require(owner==root and child in exits and child not in collected and
                    status==0 and again==((-10)&MASK),"Lost, foreign or double collection")
            collected.add(child)
        else:
            match=EXIT.fullmatch(line())
            require(match is not None,"Missing real kernel worker exit")
            pid,cr3,status=(int(x,16) for x in match.groups())
            require(pid in done and pid not in exits and cr3>0 and cr3%4096==0 and
                    cr3!=shell_cr3 and cr3 not in exits.values() and status==0,
                    "Foreign, duplicated or failed worker exit")
            exits[pid]=cr3
    owner,empty,finish=fields("FINAL","PID EMPTY MS")
    require(owner==root and empty==((-10)&MASK) and release<=finish<deadline,
            "Incomplete bounded final collection")
    match=EXIT.fullmatch(line())
    require(match is not None,"Missing real foreground owner exit")
    pid,cr3,status=(int(x,16) for x in match.groups())
    require(pid==root and cr3>0 and cr3%4096==0 and cr3!=shell_cr3 and cr3 not in exits.values() and status==0,
            "Wrong foreground process exit")
    reply=b"exit status 0\r\nagentos> "
    require(data[pos:].startswith(reply),"Shell did not return normally")
    return pos+len(reply),{"contract":"sustained-smp-v1","root_pid":root,"parent_pid":shell,
        "root_cr3":cr3,"worker_pids":pids,"worker_cr3":exits,"start_ms":start,"end_ms":end,
        "deadline_ms":deadline,"released_ms":release,"finish_ms":finish,"duration_ms":DURATION,
        "windows":windows,"samples":sum(len(x) for x in all_samples),
        "payload_bytes":sum(len(x) for x in all_samples)*PAYLOAD,
        "workers":[{"pid":pid,"ready_and_samples":states[pid],"done":done[pid],
                    "status":0,"second_wait":-10} for pid in pids],"remaining_children":-10},set(pids)|{root}
