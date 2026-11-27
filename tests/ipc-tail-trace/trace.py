"""Read-only, all-stop hardware breakpoints in one exact archived kernel.

Offsets and Rust enum layout were decoded from the real optimized ELF, not
assumed from source ABI. run.py refuses different ELF/CPIO hashes, and every
breakpoint's actual instruction bytes are compared with that ELF before use.
This observes the normal guest: no INT3, guest writes, injected test markers,
forced scheduling, altered clocks or extended session deadline.
"""
import gdb
import json
import os
from pathlib import Path
import time

request = json.loads(Path(os.environ["AGENTOS_IPC_TRACE_REQUEST"]).read_text())
base, shell = request["base"], request["shell"]
dest, rootdir = Path(request["destination"]), Path(request["root"])
kernel = (rootdir/"build/kernel.elf").read_bytes()
runner = (rootdir/"build/supervisor-staging/ipc-runner").read_bytes()
inferior = gdb.selected_inferior()
U = 0x8000400000
Q = 0x1b8
TASKS = 0x40
STRIDE = 0xd8
SITES = {
    0xb98f: "move_before", 0xba78: "move_after_increment",
    0x15b80: "sched_stats_loaded", 0x20428: "exit_committed",
    0x1fe9d: "wake_io", 0x820d: "wake_timed", 0x81df: "wake_clock_error",
    0x1f9ac: "blocked_child", 0xcf71: "collect_result",
    0x26da7: "ipc_send_committed", 0x26cba: "ipc_receive_committed",
}
# Return PCs in sample()'s callers (from exact stripped ipc-runner ELF).
CALLS = {0xa3a: "RUNNER", 0x1080: "PEER_BEGIN", 0x11f9: "PEER_END",
         0x12fe: "BEGIN", 0x13cc: "ENDED", 0x1bc5: "COMPLETE"}
root_pid = None
pre = {}
counts = {}
events = 0
stops = 0
stop_ns = 0
max_stop_ns = 0
armed_ns = None
breakpoints = []
out = (dest/"scheduler-trace.jsonl").open("w", buffering=1)

def require(condition, message):
    if not condition:
        raise RuntimeError(message)

def reg(name):
    return int(gdb.parse_and_eval("$"+name)) & ((1<<64)-1)

def mem(address, size):
    return bytes(inferior.read_memory(address, size))

def val(raw, offset=0, size=8):
    return int.from_bytes(raw[offset:offset+size], "little")

def word(address):
    return val(mem(address, 8))

def signed(value):
    return value if value < 1<<63 else value-(1<<64)

def record(kind, **values):
    global events
    events += 1
    counts[kind] = counts.get(kind, 0)+1
    event = {"event": kind, "seq": events, "host_ns": time.monotonic_ns(),
             "thread": list(gdb.selected_thread().ptid), "pc": reg("pc"),
             **values}
    out.write(json.dumps(event, sort_keys=True)+"\n")
    return events

def global_count():
    return word(base+0x42cd8)

def task(raw, slot):
    tag = val(raw)
    require(tag in (0,1,2,3), "invalid Task/Process option tag")
    if tag == 3:
        return {"slot": slot, "tag": tag, "present": False}
    p = {"slot": slot, "tag": tag, "present": True,
         "runnable": val(raw,0xd0,1), "has_run": val(raw,0xd2,1),
         "clock_error": val(raw,0xd1,1), "moves": val(raw,0xc8),
         "context": val(raw,0xb8), "waiting_tag": val(raw,0x58),
         "timed_tag": val(raw,0x78,4), "timed_arg": val(raw,0x80),
         "timed_deadline_raw": val(raw,0x88)}
    require(p["runnable"] in (0,1) and p["has_run"] in (0,1), "invalid task bool")
    if tag < 2:
        p.update(pid=val(raw,0x30), parent_cached=val(raw,0x38),
                 cr3=val(raw,0x18), lifecycle=val(raw,0x48),
                 status=None if tag==0 else val(raw,8))
        require(p["pid"]>0, "invalid process identity")
    return p

def option(raw, offset):
    tag = val(raw, offset)
    require(tag in (0,1), "invalid Option<usize> tag")
    return val(raw, offset+8) if tag else None

def queue(address, full=False):
    cpu = address-Q
    require(cpu in cpus, "queue not owned by actual registered CPU")
    prefix = mem(cpu+0x150, 0x18)
    raw = mem(address, 0x800)
    current, retiring = option(raw,0), option(raw,0x10)
    init, parked = option(raw,0x20), option(raw,0x30)
    count, handoff = val(raw,0x7e0), val(raw,0x7f9,1)
    require(count<=9 and all(v is None or v<9 for v in (current,retiring)),
            "invalid queue count/owner slot")
    tasks = [task(raw[TASKS+i*STRIDE:TASKS+(i+1)*STRIDE],i) for i in range(9)]
    for t in tasks:
        i = t["slot"]
        t["current"] = i==current
        t["retiring"] = i==retiring
        t["eligible"] = bool(i<count and i!=current and i!=retiring and
            t["tag"]==0 and t["runnable"] and t["has_run"] and
            t["pid"]!=parked and not (t["pid"]==init and not handoff))
    result = {"cpu_pointer":cpu,"apic":cpus[cpu], "queue":address,
              "gate":val(prefix,0,1), "runtime_ready":val(prefix,1,1),
              "cached_runnable":val(prefix,8), "cached_free_slot":val(prefix,0x10,1),
              "count":count, "current":current, "retiring":retiring,
              "init_pid":init, "boot_parked":parked, "boot_handoff_done":handoff,
              "runnable":sum(t.get("runnable",0) for t in tasks[:8]),
              "free_slots":[t["slot"] for t in tasks[:8] if not t["present"]],
              "tasks":tasks}
    if full:
        result.update(raw_queue=raw.hex(), raw_gate_prefix=prefix.hex())
    return result

def current(cpu):
    require(cpu in cpus,"unrecognized CPU pointer")
    q = cpu+Q
    slot = option(mem(q,16),0)
    require(slot is not None and slot<9,"no current task at syscall")
    t = task(mem(q+TASKS+slot*STRIDE,STRIDE),slot)
    require(t["tag"]<2,"syscall owner not a user process")
    return t

def task_at(address):
    for cpu,apic in cpus.items():
        delta = address-(cpu+Q+TASKS)
        if 0<=delta<9*STRIDE and delta%STRIDE==0:
            return cpu, task(mem(address,STRIDE),delta//STRIDE)
    raise RuntimeError("task pointer not a registered queue slot")

def related(t):
    return root_pid is not None and (t.get("pid")==root_pid or t.get("parent_cached")==root_pid)

def context(address):
    raw=mem(address+0x278,0x28)
    return {"rip":val(raw), "cs":val(raw,8), "rsp":val(raw,0x18),
            "address":address}

def code_matches(address, length=12):
    return U<=address<=U+0x35fc-length and mem(address,length)==runner[
        0x1000+address-U:0x1000+address-U+length]

def sched_stats():
    global root_pid
    sp=reg("rsp")
    require(word(sp+0x88)==base+0xd37c,"unexpected SCHED_STATS closure caller")
    ctx=context(word(sp+0x78)) # saved dispatch r15
    if ctx["rip"] != U+0x49:
        return
    if not code_matches(ctx["rip"]):
        return
    caller=word(ctx["rsp"]+8) # sample() saved rbx, then caller PC
    if not code_matches(caller):
        return
    pid=word(reg("rcx"))
    parent,apic,own,total=reg("rdx"),reg("rax"),reg("r8"),reg("r9")
    cpu=word(reg("rsi"))
    require(cpu in cpus and cpus[cpu]==apic,"SCHED_STATS CPU mismatch")
    t=current(cpu)
    require(t["pid"]==pid and t["moves"]==own,"SCHED_STATS owner mismatch")
    label=CALLS.get(caller-U,"OTHER")
    if root_pid is None and label=="RUNNER" and parent==shell:
        root_pid=pid
        record("root_identified",pid=pid,parent=parent,apic=apic,cr3=t["cr3"])
    if pid!=root_pid and parent!=root_pid:
        return
    record("sched_stats_loaded",label=label,caller=caller,pid=pid,parent=parent,
           apic=apic,moves=own,total=total,cpus=reg("rdi"),context=ctx,
           owner_gate=val(mem(cpu+0x150,1)))

def migration_before():
    sp=reg("rsp")
    source,target=queue(reg("rsi"),True),queue(reg("rdx"),True)
    sc,tc=word(sp),reg("rax")-2
    checks={"both_locked":source["gate"]==target["gate"]==1,
            "real_counts_match":(sc,tc)==(source["runnable"],target["runnable"]),
            "imbalance":sc>=tc+2}
    seq=record("move_before",source=source,target=target,locked_source_count=sc,
               locked_target_count=tc,global_before=global_count(),checks=checks)
    pre[tuple(gdb.selected_thread().ptid)]=(seq,source,target,global_count(),checks)

def migration_after():
    result=mem(reg("rsp")+8,48)
    require(val(result)==0,"global increment without actual successful move")
    pid,ctx,cr3,stack,moves=[val(result,n) for n in (8,16,24,32,40)]
    key=tuple(gdb.selected_thread().ptid)
    require(key in pre,"successful move lacks prior locked observation")
    seq,old_source,old_target,old_global,checks=pre.pop(key)
    source,target=queue(reg("r13"),True),queue(reg("r12"),True)
    total=global_count()
    eligible=[t for t in old_source["tasks"] if t["eligible"]]
    old=next((t for t in old_source["tasks"] if t.get("pid")==pid),None)
    new=next((t for t in target["tasks"] if t.get("pid")==pid),None)
    checks={**checks,"same_queues":source["queue"]==old_source["queue"] and target["queue"]==old_target["queue"],
            "still_locked":source["gate"]==target["gate"]==1,
            "selected_first_eligible":bool(eligible and eligible[0].get("pid")==pid),
            "ownership_and_identity":bool(old and new and new["cr3"]==old["cr3"]==cr3 and
                new["context"]==old["context"]==ctx and all(t.get("pid")!=pid for t in source["tasks"])),
            "migration_generations":bool(old and new and moves==new["moves"]==min(old["moves"]+1,2**64-1)
                                         and total==old_global+1),
            "runnable_transfer":source["runnable"]==old_source["runnable"]-1 and
                                target["runnable"]==old_target["runnable"]+1,
            "current_retiring_unchanged":all(q[k]==p[k] for q,p in
                ((source,old_source),(target,old_target)) for k in ("current","retiring"))}
    record("move_success",before_seq=seq,pid=pid,context=ctx,cr3=cr3,stack_top=stack,
           moves=moves,global_after=total,source=source,target=target,
           result_raw=result.hex(),checks=checks)

def wake(site):
    addr=reg("r9" if site==0x1fe9d else "rdi")
    cpu,t=task_at(addr)
    if related(t):
        record(SITES[site],apic=cpus[cpu],task=t,global_count=global_count(),
               gate=val(mem(cpu+0x150,1)),raw_task=mem(addr,STRIDE).hex())

def blocked_child():
    cpu,t=task_at(reg("rax"))
    if related(t):
        record("blocked_child",apic=cpus[cpu],task=t,global_count=global_count(),
               gate=val(mem(cpu+0x150,1)))

def collect():
    sp=reg("rsp")
    cpu=reg("rbx")
    t=current(cpu)
    if related(t) or t["pid"]==shell:
        record("collect_result",pid=t["pid"],apic=cpus[cpu],
               child=word(sp+0x10),tag=word(sp+0x1e0),
               status=signed(word(sp+0x1e8)),global_count=global_count(),
               gate=val(mem(cpu+0x150,1)))

def exit_committed():
    cpu,t=task_at(reg("r15"))
    if related(t):
        lifecycle=mem(t["lifecycle"],0x38)
        require(val(lifecycle)==1,"exit breakpoint before lifecycle status commit")
        record("exit_committed",pid=t["pid"],apic=cpus[cpu],task=t,
               status=val(lifecycle,8),lifecycle_raw=lifecycle.hex(),
               global_count=global_count(),gate=val(mem(cpu+0x150,1)))
        return t["pid"]==root_pid
    return False

def mailbox(site):
    if reg("r13")!=24 or root_pid is None:
        return
    sp=reg("rsp")
    sending=site==0x26da7
    if sending:
        channel=reg("r15")
        data=channel+reg("r12")+0x10
    else:
        channel=word(sp+0x10)
        data=reg("r15")
    raw=mem(data,0x418)
    kind,round_,token=val(raw),val(raw,8),val(raw,16)
    sender=val(raw,0x400)
    if sender!=root_pid or kind not in (1,2,3,4,5):
        return
    ret=word(sp+0x68)
    if sending:
        require(ret==base+0xc608,"unexpected send caller")
        cpu=word(sp+0x38)
    else:
        require(ret==base+0x154b4 and word(sp+0x98)==base+0xc8f3,"unexpected receive caller")
        cpu=word(sp+0x88)
    t=current(cpu)
    ctx=context(word(sp+0x58))
    side=reg("r14")
    require(side in (0,1),"invalid mailbox side")
    require(val(raw,0x410)==(24 if sending else 0),"mailbox commit length mismatch")
    if sending:
        require(t["pid"]==sender,"send owner identity mismatch")
    else:
        require(t["parent_cached"]==root_pid,"receive owner identity mismatch")
    record(SITES[site],pid=t["pid"],apic=cpus[cpu],sender=sender,channel=channel,
           side=side,kind=kind,round=round_,token=token,context=ctx,
           payload=raw[:24].hex(),authenticated_peer=raw[0x400:0x410].hex(),
           mailbox_length=val(raw,0x410),global_count=global_count(),
           gate=val(mem(cpu+0x150,1)))

def save(name,value):
    (dest/name).write_text(json.dumps(value,indent=2,sort_keys=True)+"\n")

def main():
    global cpus,stops,stop_ns,max_stop_ns,armed_ns
    raw=mem(base+0x424c0,255*8)
    pointers=[val(raw,i) for i in range(0,len(raw),8) if val(raw,i)]
    cpus={p:val(mem(p+0x30,4),0,4) for p in pointers}
    require(len(pointers)==len(cpus)==2 and sorted(cpus.values())==[0,1] and
            word(base+0x42cd0)==2 and len(inferior.threads())==2,"unexpected runtime CPU roster")
    for offset,kind in SITES.items():
        expected=kernel[0x1000+offset:0x1000+offset+12]
        observed=mem(base+offset,len(expected))
        require(expected==observed,f"runtime text differs at {offset:#x}")
        breakpoints.append(gdb.Breakpoint(f"*{base+offset:#x}",type=gdb.BP_HARDWARE_BREAKPOINT))
    armed_ns=time.monotonic_ns()
    save("trace-ready.json",{"base":base,"registered_cpus":cpus,"sites":SITES,
         "host_ns":armed_ns,"all_stop":True,"hardware_execute_breakpoints":True,
         "runtime_text_verified":True,"initial_global":global_count()})
    while True:
        gdb.execute("continue")
        stopped=time.monotonic_ns()
        site=reg("pc")-base
        stops+=1
        require(site in SITES,f"unexpected debug stop {reg('pc'):#x}")
        done=False
        if site==0xb98f:
            migration_before()
        elif site==0xba78:
            migration_after()
        elif site==0x15b80:
            sched_stats()
        elif site==0x20428:
            done=exit_committed()
        elif site in (0x1fe9d,0x820d,0x81df):
            wake(site)
        elif site==0x1f9ac:
            blocked_child()
        elif site==0xcf71:
            collect()
        elif site in (0x26da7,0x26cba):
            mailbox(site)
        elapsed=time.monotonic_ns()-stopped
        stop_ns+=elapsed
        max_stop_ns=max(max_stop_ns,elapsed)
        if done:
            break

result={"result":"fail"}
try:
    main()
    result["result"]="complete"
except Exception as exc:
    result["error"]=str(exc)
    print("IPC debugger blocked:",repr(exc))
finally:
    result.update(root_pid=root_pid,events=events,event_counts=counts,stops=stops,
                  handler_ns=stop_ns,max_handler_ns=max_stop_ns,armed_ns=armed_ns,
                  end_ns=time.monotonic_ns(),
                  timing_note="All vCPUs stop on each breakpoint. Handler time is a lower bound on pauses; remote round trips and step-over are additional.")
    save("trace-result.json",result)
    out.close()
    for bp in breakpoints:
        bp.delete()
    try:
        gdb.execute("detach")
    except gdb.error as exc:
        print("detach:",exc)
    if result["result"]!="complete":
        raise gdb.GdbError(result.get("error","incomplete trace"))
