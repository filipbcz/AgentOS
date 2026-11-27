"""Host-only verifier and single-CPU GDB observer; never reads user virtual memory."""
import copy
import json
import os
from pathlib import Path
import struct
import time

SITE = 0x18b
STACK_BASE = 0xffff800000000000
STACK_LIMIT = STACK_BASE + 4096 * 6 * 4096
SIZE = 0x2a0
ITERATIONS = 0x4000000
TAGS = {"A": (0x1122334455667788, 0x89abcdef01234567),
        "B": (0x76543210fedcba98, 0x8877665544332211)}


def require(ok, message):
    if not ok:
        raise ValueError(message)


def word(data, offset):
    return struct.unpack_from("<Q", data, offset)[0]


def raw(value, size):
    data = bytes.fromhex(value)
    require(len(data) == size, "Wrong raw structure size")
    return data


def stack_context(task):
    base = word(task, 0xb0)
    if (STACK_BASE < base < STACK_LIMIT and
            (base-STACK_BASE) % 0x6000 == 0x1000 and
            base+0x4000 <= STACK_LIMIT):
        return base+0x4000-SIZE
    return None


def decode(task, context, address, windows):
    task, context = raw(task, 0xd8), raw(context, SIZE)
    require(word(task, 0) == 0 and task[0xd0] == task[0xd2] == 1,
            "Not a live, already-run runnable process")
    require(word(task, 0xb8) == address == stack_context(task),
            "Context not owned by task's guarded kernel stack")
    rip, cs, flags, sp, ss = struct.unpack_from("<5Q", context, 0x278)
    require(cs == 0x33 and ss == 0x2b and flags & 0x200 and 0 < sp < 1 << 47,
            "Not a userspace IRQ frame")
    labels = [label for label, pcs in windows.items() if rip in pcs]
    require(len(labels) == 1, "Not inside exact syscall-free loop")
    label = labels[0]
    a, b = TAGS[label]
    remaining = word(context, 0x268)
    require(0 <= remaining <= ITERATIONS and word(context, 0x238) == a and
            word(context, 0x208) == b and
            context[160:176] == struct.pack("<2Q", a, b) and
            context[400:416] == struct.pack("<2Q", b, a),
            "Wrong GPR/XMM sentinel or loop progress")
    pid, parent, cr3 = word(task, 0x30), word(task, 0x38), word(task, 0x18)
    require(pid > parent > 0 and cr3 > 0 and cr3 % 4096 == 0,
            "Invalid process identity")
    return dict(label=label, pid=pid, parent=parent, cr3=cr3, address=address,
                remaining=remaining, preemptions=word(task, 0xc0),
                context=context.hex())


def pair(row, config, identities=None, bounds=None):
    require(row["pc"] == config["base"]+SITE and row["online"] == 1 and
            row["runtime"] == row["active"] == 1 and row["lock"] == 0 and
            row["eflags"] & 0x200 == 0 and row["apic"] == config["apic"] and row["irq"] > 0,
            "Not an ordinary runtime timer return on the sole CPU")
    if bounds is not None:
        require(bounds[0] <= row["host_ns"] <= bounds[1], "Outside host ARM interval")
    current, next_slot, retiring, out_slot = struct.unpack("<4Q", raw(row["queue"], 32))
    require(current == retiring == 1 and 0 <= next_slot < 9 and 0 <= out_slot < 9 and
            next_slot != out_slot and row["rsp"] != row["rax"],
            "No real task switch")
    a = decode(row["out_task"], row["out_context"], row["rsp"], config["windows"])
    b = decode(row["next_task"], row["next_context"], row["rax"], config["windows"])
    require(a["pid"] != b["pid"] and a["label"] != b["label"] and
            a["cr3"] != b["cr3"] and a["parent"] == b["parent"] and a["preemptions"] > 0,
            "Foreign or non-distinct competitors")
    if identities is not None:
        for p in (a,b):
            require((p["pid"],p["parent"],p["cr3"]) == tuple(identities[p["label"]]),
                    "Wrong authenticated worker identity")
    return a,b


def find_chain(rows, config, identities=None, bounds=None):
    chain = []
    last_ns = -1
    for seq,row in enumerate(rows,1):
        require(row["seq"] == seq and row["host_ns"] >= last_ns, "Replayed or reordered sample")
        last_ns = row["host_ns"]
        try:
            a,b = pair(row, config, identities, bounds)
        except (ValueError, KeyError, TypeError, struct.error):
            chain = []
            continue
        current = (row,a,b)
        if chain:
            previous,pa,pb = chain[-1]
            # Returning to the exact untouched outgoing frame, then running
            # the loop far enough to decrement RCX, is stronger than selection.
            if (row["irq"] != previous["irq"]+1 or
                    (a["pid"],a["cr3"],a["address"]) != (pb["pid"],pb["cr3"],pb["address"]) or
                    a["remaining"] >= pb["remaining"] or
                    a["preemptions"] != pb["preemptions"]+1 or
                    b != pa):
                chain = []
        chain.append(current)
        # Six consecutive A/B switches show two departed-and-resumed
        # intervals WITH subsequent instruction progress for each worker.
        if len(chain) == 6:
            return [{"seq":r["seq"], "irq":r["irq"], "out":a, "next":b}
                    for r,a,b in chain]
    return None


def verify(rows, config, identities, bounds):
    chain = find_chain(rows,config,identities,bounds)
    require(chain is not None,"No six-switch chain with two completed resume/progress intervals per worker")
    require({p["out"]["label"] for p in chain[:2]} == set(TAGS), "Missing worker")
    return chain


def selftest():
    config = dict(base=0x100000, apic=0, windows={"A":[0x8000400100],"B":[0x8000400200]})
    identities = {"A":(12,11,0x5000),"B":(13,11,0x6000)}
    def task(label, remaining, count):
        pid,parent,cr3 = identities[label]
        base = STACK_BASE+(pid-12)*0x6000+0x1000
        address = base+0x4000-SIZE
        t,c = bytearray(0xd8),bytearray(SIZE)
        for offset,value in ((0x18,cr3),(0x30,pid),(0x38,parent),(0xb0,base),(0xb8,address),(0xc0,count)):
            struct.pack_into("<Q",t,offset,value)
        t[0xd0] = t[0xd2] = 1
        a,b=TAGS[label]
        struct.pack_into("<Q",c,0x238,a)
        struct.pack_into("<Q",c,0x208,b)
        struct.pack_into("<Q",c,0x268,remaining)
        struct.pack_into("<2Q",c,160,a,b)
        struct.pack_into("<2Q",c,400,b,a)
        struct.pack_into("<5Q",c,0x278,config["windows"][label][0],0x33,0x202,0x8000800000,0x2b)
        return t.hex(),c.hex(),address
    state={"A":task("A",1000,0),"B":task("B",1000,0)}
    rows=[]
    for i in range(6):
        a,b=("A","B") if i%2==0 else ("B","A")
        state[a]=task(a,900-(i//2)*100,1+i//2)
        t,c,sp=state[a]
        u,d,ax=state[b]
        rows.append(dict(seq=i+1,host_ns=100+i,irq=50+i,pc=config["base"]+SITE,
                         online=1,runtime=1,active=1,lock=0,apic=0,eflags=2,
                         queue=struct.pack("<4Q",1,1-i%2,1,i%2).hex(),
                         rsp=sp,rax=ax,out_task=t,next_task=u,out_context=c,next_context=d))
    def reject(name, change):
        bad=copy.deepcopy(rows)
        change(bad)
        try:
            verify(bad,config,identities,(100,110))
        except ValueError:
            print("NEGATIVE REJECTED:",name)
            return
        raise ValueError("Accepted invalid "+name)
    def mutate(row,key,offset,value):
        data=bytearray.fromhex(row[key])
        struct.pack_into("<Q",data,offset,value)
        row[key]=data.hex()
    require(len(verify(rows,config,identities,(100,110)))==6,"Positive fixture failed")
    reject("boot",lambda r:r[2].update(runtime=0))
    reject("before ARM",lambda r:r[0].update(host_ns=99))
    reject("IRQ no switch",lambda r:r[2].update(rax=r[2]["rsp"]))
    reject("syscall path",lambda r:r[2].update(pc=config["base"]+0x2b6))
    reject("blocked outgoing",lambda r:mutate(r[2],"out_task",0xd0,0))
    reject("outside no-syscall window",lambda r:mutate(r[2],"out_context",0x278,0x8000400300))
    reject("replay",lambda r:r[2].update(seq=r[1]["seq"]))
    reject("IRQ repeated",lambda r:r[2].update(irq=r[1]["irq"]))
    reject("foreign PID",lambda r:mutate(r[2],"out_task",0x30,99))
    reject("wrong CR3",lambda r:mutate(r[2],"out_task",0x18,0x9000))
    reject("wrong XMM",lambda r:mutate(r[2],"out_context",160,0))
    reject("wrong GPR",lambda r:mutate(r[2],"out_context",0x238,0))
    reject("no resumed progress",lambda r:mutate(r[2],"out_context",0x268,900))
    print("PREEMPTION VERIFIER POSITIVE + 13 NEGATIVE OK")


def observe():
    import gdb
    request=json.loads(Path(os.environ["AGENTOS_PREEMPT_REQUEST"]).read_text())
    dest=Path(request["destination"])
    base=request["base"]
    def mem(address,size):
        return bytes(gdb.selected_inferior().read_memory(address,size))
    def reg(name):
        return int(gdb.parse_and_eval("$"+name)) & ((1<<64)-1)
    def q(address):
        return word(mem(address,8),0)
    require(len(gdb.selected_inferior().threads())==1,"Not one GDB CPU")
    # Only identity-mapped kernel ELF/data, a registered CPU, its inline
    # queue, and validated high-half kernel-stack contexts are ever read.
    for offset,data in request["runtime_bytes"].items():
        expected=bytes.fromhex(data)
        require(mem(base+int(offset),len(expected))==expected,"Runtime kernel code mismatch")
    cpus=struct.unpack("<255Q",mem(base+0x424c0,255*8))
    cpus=[p for p in cpus if p]
    require(len(cpus)==1 and q(base+0x42cd0)==1,"Wrong runtime CPU roster")
    cpu=cpus[0]
    require(0x100000<=cpu<256*1024*1024-4096 and cpu%4096==0 and q(cpu)==cpu,
            "Invalid CPU kernel pointer")
    require(int.from_bytes(mem(cpu+0x30,4),"little")==request["apic"],"Wrong APIC")
    require(mem(base+0x42cc0,1)==b"\1","Runtime not enabled")
    bp=gdb.Breakpoint("*"+hex(base+SITE),type=gdb.BP_HARDWARE_BREAKPOINT)
    armed=time.monotonic_ns()
    (dest/"trace-ready.json").write_text(json.dumps(dict(armed_ns=armed,cpu=cpu,site=base+SITE,
        hardware=True,threads=1,apic=request["apic"])))
    rows=[]
    spent=0
    maximum=0
    error=None
    try:
        with (dest/"irq-trace.jsonl").open("w",buffering=1) as stream:
            while len(rows)<1500 and not (dest/"stop-trace").exists():
                gdb.execute("continue",to_string=True)
                start=time.monotonic_ns()
                require(reg("pc")==base+SITE,"Unexpected debugger stop")
                header=mem(cpu+0x1b8,32)
                cur,nxt,ret,prev=struct.unpack("<4Q",header)
                row=dict(seq=len(rows)+1,host_ns=start,pc=reg("pc"),rsp=reg("rsp"),rax=reg("rax"),
                         eflags=reg("eflags"),online=q(base+0x42cd0),runtime=mem(base+0x42cc0,1)[0],
                         active=mem(cpu+0x9b2,1)[0],lock=mem(cpu+0x150,1)[0],
                         apic=int.from_bytes(mem(cpu+0x30,4),"little"),irq=q(cpu+0x140),queue=header.hex())
                if cur==ret==1 and 0<=nxt<9 and 0<=prev<9 and nxt!=prev:
                    for key,slot,address in (("out",prev,row["rsp"]),("next",nxt,row["rax"])):
                        t=mem(cpu+0x1b8+0x40+slot*0xd8,0xd8)
                        row[key+"_task"]=t.hex()
                        if word(t,0)==0 and address==word(t,0xb8)==stack_context(t):
                            row[key+"_context"]=mem(address,SIZE).hex()
                rows.append(row)
                stream.write(json.dumps(row,sort_keys=True)+"\n")
                found=find_chain(rows[-6:],request) if len(rows)==6 else None
                # The offline verifier checks the entire raw sequence. For
                # an early detach use the same decoder on the last six
                # actual stops with local sequence numbering only.
                if len(rows)>=6:
                    tail=[dict(r,seq=i+1) for i,r in enumerate(rows[-6:])]
                    found=find_chain(tail,request)
                elapsed=time.monotonic_ns()-start
                spent+=elapsed
                maximum=max(maximum,elapsed)
                if found:
                    break
    except Exception as exc:
        error=repr(exc)
    finally:
        end=time.monotonic_ns()
        bp.delete()
        gdb.execute("detach")
        (dest/"trace-result.json").write_text(json.dumps(dict(error=error,stops=len(rows),
            armed_ns=armed,end_ns=end,handler_ns=spent,max_handler_ns=maximum)))
    require(error is None,"Debugger observation failed: "+str(error))


if __name__=="__main__":
    selftest()
elif __name__=="__preemption_gdb__":
    observe()
