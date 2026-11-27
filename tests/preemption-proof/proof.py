"""Host verifier and CPU-local GDB observer; never reads user virtual memory."""
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


def decode(task, context, address, windows, tags=TAGS):
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
    a, b = tags[label]
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



# SMP proof preserves the single-CPU contract above. Never infer APIC from a
# GDB thread number or -smp. Each six-IRQ chain is strictly CPU-local.
CPU_BYTES = 0x9b3
QUEUE = 0x1b8
CPU_TABLE = 0x424c0
ONLINE = 0x42cd0
RUNTIME = 0x42cc0


def smp_tags(cpus):
    require(cpus in (2,4,8),"Unsupported SMP proof count")
    return {chr(65+i): (TAGS["B"] if i==1 else
            (TAGS["A"][0] ^ (i*0x0101010101010101),
             TAGS["A"][1] ^ (i*0x0001000100010001))) for i in range(2*cpus)}


def qmp_roster(record, cpus):
    require(record["accelerator"]=="tcg" and record["kvm"]["enabled"] is False,
            "Wrong actual accelerator")
    actual=record["cpus"]
    require(len(actual)==cpus and all(
        type(c["cpu-index"]) is int and c["cpu-index"]>=0 and
        type(c["thread-id"]) is int and c["thread-id"]>0 and
        c["target"]=="x86_64" and isinstance(c["qom-path"],str) and c["qom-path"] and
        type(c["apic-id"]) is int and 0<=c["apic-id"]<255 for c in actual),
        "Invalid live QMP/QOM roster")
    for key in ("cpu-index","thread-id","qom-path","apic-id"):
        require(len({c[key] for c in actual})==cpus,"Repeated QMP identity "+key)
    return {c["cpu-index"]:c["apic-id"] for c in actual}


def thread_packet(ptid):
    require(len(ptid)==3 and all(type(v) is int for v in ptid) and
            ptid[0]>0 and ptid[1]>0 and ptid[2]==0,"Unsupported remote thread ID")
    return "qThreadExtraInfo,p%x.%x"%(ptid[0],ptid[1])


def thread_index(response):
    # QEMU 8.2.2 gdbstub handle_query_thread_extra, one Q35 CPU cluster.
    import re
    m=re.search(r'(?m)^received:\s*"([0-9a-fA-F]+)"\s*$',response)
    require(m is not None,"Missing QEMU remote thread metadata")
    name=bytes.fromhex(m[1]).decode("ascii")
    m=re.fullmatch(r"CPU#([0-9]+) \[(?:halted *|running)\]",name)
    require(m is not None,"Unexpected QEMU CPU metadata "+name)
    return int(m[1])


def bind_roster(config, ready):
    cpus=config["cpus"]
    qmp=qmp_roster(config["qmp"],cpus)
    require(ready["threads"]==cpus and ready["hardware"] is True and
            ready["site"]==config["base"]+SITE and
            ready["online"]==cpus and ready["runtime"]==1,
            "Wrong armed SMP observer")
    table=struct.unpack("<255Q",raw(ready["kernel_roster"],255*8))
    pointers=[v for v in table if v]
    require(len(pointers)==len(set(pointers))==cpus and
            all(0x100000<=v<=256*1024*1024-4096 and v%4096==0 for v in pointers),
            "Wrong registered kernel CPU pointers")
    bound={}
    for item in ready["bindings"]:
        ptid=tuple(item["thread"])
        index=thread_index(item["response"])
        require(item["packet"]==thread_packet(ptid) and index in qmp and
                item["cpu_index"]==index and item["apic"]==qmp[index],
                "GDB thread metadata disagrees with QMP")
        cpu=item["cpu"]
        header=raw(item["identity"],0x34)
        require(cpu in pointers and word(header,0)==cpu and
                struct.unpack_from("<I",header,0x30)[0]==qmp[index] and
                {item["gs_base"],item["kernel_gs_base"]}=={0,cpu},
                "Thread GS/MSR and registered kernel APIC disagree")
        require(ptid not in bound,"Repeated GDB thread")
        bound[ptid]=(index,qmp[index],cpu)
    require(len(bound)==cpus and len(set(bound.values()))==cpus and
            {v[0] for v in bound.values()}==set(qmp) and
            {v[2] for v in bound.values()}==set(pointers),
            "Incomplete one-to-one GDB/QMP/kernel roster")
    return bound


def row_cpu(row, config, bound):
    ptid=tuple(row["thread"])
    require(ptid in bound,"Unbound stopped GDB thread")
    index,apic,cpu=bound[ptid]
    require(row["cpu_index"]==index and row["apic"]==apic and
            row["cpu"]==row["gs_base"]==cpu and row["kernel_gs_base"]==0 and
            row["cs"]&3==0 and row["pc"]==config["base"]+SITE,
            "Cross-APIC or non-kernel timer stop")
    image=raw(row["cpu_image"],CPU_BYTES)
    require(word(image,0)==cpu and struct.unpack_from("<I",image,0x30)[0]==apic,
            "Raw kernel CPU identity mismatch")
    irq=word(image,0x140)
    require(row["irq"]==irq and irq>0,"Wrong raw local IRQ counter")
    return image


def smp_pair(row, config, image, identities, bounds):
    require(row["online"]==config["cpus"] and row["runtime"]==image[0x9b2]==1 and
            image[0x150]==0 and row["eflags"]&0x200==0,
            "Not a consistent runtime timer return")
    if bounds is not None:
        require(bounds[0]<=row["host_ns"]<=bounds[1],"Outside foreground ARM interval")
    cur,nxt,ret,prev=struct.unpack_from("<4Q",image,QUEUE)
    require(cur==ret==1 and 0<=nxt<9 and 0<=prev<9 and nxt!=prev and
            row["rsp"]!=row["rax"],"No actual local task switch")
    def task(slot):
        offset=QUEUE+0x40+slot*0xd8
        return image[offset:offset+0xd8]
    tags=smp_tags(config["cpus"])
    a,b=(decode(task(slot).hex(),row[key+"_context"],row[reg],config["windows"],tags)
         for slot,key,reg in ((prev,"out","rsp"),(nxt,"next","rax")))
    a["moves"]=word(task(prev),0xc8)
    b["moves"]=word(task(nxt),0xc8)
    require(a["pid"]!=b["pid"] and a["label"]!=b["label"] and
            a["parent"]==b["parent"] and a["cr3"]!=b["cr3"] and
            a["preemptions"]>0 and row["cr3"]==b["cr3"],
            "Wrong local outgoing/next or actual installed CR3")
    if identities is not None:
        for p in (a,b):
            require((p["pid"],p["parent"],p["cr3"])==tuple(identities[p["label"]]),
                    "Wrong authenticated worker identity")
    return a,b


class SmpScan:
    def __init__(self,config,ready,identities=None,bounds=None):
        self.config=config
        self.bound=bind_roster(config,ready)
        self.identities=identities
        self.bounds=bounds
        require(set(config["windows"])==set(smp_tags(config["cpus"])) and
                len({pc for pcs in config["windows"].values() for pc in pcs})==
                sum(len(pcs) for pcs in config["windows"].values()),
                "Missing or overlapping worker windows")
        if identities is not None:
            require(set(identities)==set(config["windows"]),"Wrong authenticated worker roster")
            require(len({v[0] for v in identities.values()})==len(identities) and
                    len({v[2] for v in identities.values()})==len(identities) and
                    len({v[1] for v in identities.values()})==1,
                    "Aliased authenticated process roster")
        self.local={v[1]:[] for v in self.bound.values()}
        self.candidates={apic:{} for apic in self.local}
        self.last_irq={}
        self.seen=0
        self.last_ns=-1

    def feed(self,row):
        require(row["seq"]==self.seen+1 and row["host_ns"]>=self.last_ns,
                "Replayed or reordered global stop")
        self.seen+=1
        self.last_ns=row["host_ns"]
        image=row_cpu(row,self.config,self.bound)
        apic=row["apic"]; irq=row["irq"]
        last=self.last_irq.get(apic)
        require(last is None or irq>last,"Repeated/reversed local IRQ")
        self.last_irq[apic]=irq
        chain=self.local[apic]
        if last is not None and irq!=last+1:
            chain.clear()
        try:
            a,b=smp_pair(row,self.config,image,self.identities,self.bounds)
        except (ValueError,KeyError,TypeError,struct.error):
            # Nonqualifying local stop breaks that CPU's chain; an interposed
            # stop on another CPU never enters this local chain.
            chain.clear()
            return
        if chain:
            p=chain[-1]
            pa,pb=p["out"],p["next"]
            identity=lambda v:(v["label"],v["pid"],v["parent"],v["cr3"],v["address"],v["moves"])
            if (irq!=p["irq"]+1 or identity(a)!=identity(pb) or
                    a["remaining"]>=pb["remaining"] or a["preemptions"]!=pb["preemptions"]+1 or
                    b!=pa):
                chain.clear()
        chain.append(dict(seq=row["seq"],irq=irq,apic=apic,out=a,next=b))
        if len(chain)>6:
            del chain[0]
        if len(chain)==6:
            key=tuple(sorted((v["label"],v["pid"],v["parent"],v["cr3"]) for v in (a,b)))
            self.candidates[apic].setdefault(key,copy.deepcopy(chain))

    def selection(self):
        apics=sorted(self.candidates,key=lambda a:len(self.candidates[a]))
        if any(not self.candidates[a] for a in apics):
            return None
        def search(i,labels,pids,roots,cr3s,result):
            if i==len(apics):
                return result if labels==set(self.config["windows"]) and len(roots)==1 else None
            apic=apics[i]
            for key,chain in self.candidates[apic].items():
                new_labels={v[0] for v in key}; new_pids={v[1] for v in key}
                new_roots={v[2] for v in key}; new_cr3s={v[3] for v in key}
                if labels&new_labels or pids&new_pids or cr3s&new_cr3s or len(roots|new_roots)!=1:
                    continue
                found=search(i+1,labels|new_labels,pids|new_pids,roots|new_roots,
                             cr3s|new_cr3s,{**result,str(apic):chain})
                if found is not None:
                    return found
            return None
        return search(0,set(),set(),set(),set(),{})


def verify_smp(rows,config,ready,identities,bounds):
    scan=SmpScan(config,ready,identities,bounds)
    for row in rows:
        scan.feed(row)
    chains=scan.selection()
    require(chains is not None,"No disjoint complete six-IRQ chains for every APIC and worker; candidates="+
            repr({a:[list(k) for k in c] for a,c in scan.candidates.items()}))
    return chains


def smp_selftest():
    # Deliberately unordered QMP index, thread ID and APIC maps.
    base=0x100000
    ptrs=(0x300000,0x500000)
    pts=((1,17,0),(1,3,0))
    indices=(5,2)
    qmp=dict(accelerator="tcg",kvm={"enabled":False},cpus=[
        dict(**{"cpu-index":indices[i],"thread-id":900+i,"target":"x86_64",
                "qom-path":"/cpu"+str(i),"apic-id":i}) for i in (1,0)])
    windows={l:[0x8000400100+i*0x100] for i,l in enumerate("ABCD")}
    config=dict(base=base,cpus=2,qmp=qmp,windows=windows)
    ids={l:(20+i,19,0x6000+i*4096) for i,l in enumerate("ABCD")}
    def cpu_bytes(apic,irq):
        data=bytearray(CPU_BYTES)
        struct.pack_into("<Q",data,0,ptrs[apic])
        struct.pack_into("<I",data,0x30,apic)
        struct.pack_into("<Q",data,0x140,irq)
        data[0x9b2]=1
        return data
    ready=dict(threads=2,hardware=True,site=base+SITE,online=2,runtime=1,
               kernel_roster=struct.pack("<255Q",*ptrs,*([0]*253)).hex(),bindings=[])
    for i in (1,0):
        ready["bindings"].append(dict(thread=list(pts[i]),cpu_index=indices[i],apic=i,cpu=ptrs[i],
            gs_base=0,kernel_gs_base=ptrs[i],identity=cpu_bytes(i,1)[:0x34].hex(),
            packet=thread_packet(pts[i]),response='received: "'+f"CPU#{indices[i]} [running]".encode().hex()+'"'))
    def task(label,remaining,count):
        pid,parent,cr3=ids[label]
        stack=STACK_BASE+(pid-20)*0x6000+0x1000
        address=stack+0x4000-SIZE
        t,c=bytearray(0xd8),bytearray(SIZE)
        for offset,value in ((0x18,cr3),(0x30,pid),(0x38,parent),(0xb0,stack),(0xb8,address),(0xc0,count)):
            struct.pack_into("<Q",t,offset,value)
        t[0xd0]=t[0xd2]=1
        a,b=smp_tags(2)[label]
        struct.pack_into("<Q",c,0x238,a)
        struct.pack_into("<Q",c,0x208,b)
        struct.pack_into("<Q",c,0x268,remaining)
        struct.pack_into("<2Q",c,160,a,b)
        struct.pack_into("<2Q",c,400,b,a)
        struct.pack_into("<5Q",c,0x278,windows[label][0],0x33,0x202,0x8000800000,0x2b)
        return t,c.hex(),address
    state={l:task(l,1000,0) for l in ids}
    rows=[]
    for i in range(6):
        for apic in (0,1):
            a,b=("AB","CD")[apic]
            if i%2: a,b=b,a
            state[a]=task(a,900-(i//2)*100,1+i//2)
            t,c,sp=state[a]; u,d,ax=state[b]
            irq=(74,210)[apic]+i
            image=cpu_bytes(apic,irq)
            struct.pack_into("<4Q",image,QUEUE,1,1-i%2,1,i%2)
            for slot,raw_task in ((i%2,t),(1-i%2,u)):
                off=QUEUE+0x40+slot*0xd8
                image[off:off+0xd8]=raw_task
            rows.append(dict(seq=len(rows)+1,host_ns=100+len(rows),irq=irq,
                pc=base+SITE,online=2,runtime=1,apic=apic,thread=list(pts[apic]),
                cpu_index=indices[apic],cpu=ptrs[apic],gs_base=ptrs[apic],kernel_gs_base=0,
                cs=8,eflags=2,cr3=ids[b][2],cpu_image=image.hex(),rsp=sp,rax=ax,
                out_context=c,next_context=d))
    def verify_fixture(data,mapping=ready):
        return verify_smp(data,config,mapping,ids,(100,120))
    chains=verify_fixture(rows)
    require([v["irq"] for v in chains["0"]]==list(range(74,80)) and
            [v["seq"] for v in chains["0"]]==[1,3,5,7,9,11] and
            [v["irq"] for v in chains["1"]]==list(range(210,216)),
            "Interleaved local chain not recovered")
    print("SMP POSITIVE CPU0 IRQ74-79 interleaved CPU1 IRQ210-215")
    def reject(name,mutate,mutate_ready=None):
        bad=copy.deepcopy(rows); mapping=copy.deepcopy(ready)
        mutate(bad)
        if mutate_ready: mutate_ready(mapping)
        try:
            verify_fixture(bad,mapping)
        except (ValueError,KeyError,TypeError,struct.error):
            print("SMP NEGATIVE REJECTED:",name)
            return
        raise ValueError("Accepted invalid SMP "+name)
    def renumber(data):
        for i,row in enumerate(data,1):
            row["seq"]=i; row["host_ns"]=99+i
    def split_cross(data):
        # Even with valid per-stop CPU bindings, splitting A/B's chain
        # across CPUs cannot create a local proof.
        data[:]=data[::2]
        for i,row in enumerate(data):
            apic=i%2; irq=74+i
            image=bytearray.fromhex(row["cpu_image"])
            identity=cpu_bytes(apic,irq)
            image[:0x1b8]=identity[:0x1b8]
            row.update(apic=apic,irq=irq,cpu=ptrs[apic],gs_base=ptrs[apic],
                       thread=list(pts[apic]),cpu_index=indices[apic],cpu_image=image.hex())
        renumber(data)
        scan=SmpScan(config,ready,ids,(100,120))
        for row in data: scan.feed(row)
        require(not any(scan.candidates.values()),"Cross-APIC link produced a local candidate")
    reject("forged cross-APIC chain",split_cross)
    reject("wrong thread/APIC binding",lambda data:data[4].update(thread=list(pts[1])))
    reject("wrong stopped GS",lambda data:data[4].update(gs_base=ptrs[1]))
    reject("missing local IRQ",lambda data:(data.pop(4),renumber(data)))
    reject("nonqualifying local stop",lambda data:data[4].update(rax=data[4]["rsp"]))
    reject("repeated local IRQ",lambda data:data[4].update(irq=data[2]["irq"]))
    reject("wrong actual CR3",lambda data:data[4].update(cr3=0x9000))
    reject("reordered global record",lambda data:data[4].update(seq=data[3]["seq"]))
    reject("forged arm metadata",lambda data:None,lambda m:m["bindings"][0].update(gs_base=ptrs[0]))
    print("SMP VERIFIER POSITIVE + 9 NEGATIVE OK")


def observe_smp(request):
    import gdb
    dest=Path(request["destination"]); base=request["base"]; n=request["cpus"]
    def mem(address,size):
        return bytes(gdb.selected_inferior().read_memory(address,size))
    def reg(name):
        return int(gdb.parse_and_eval("$"+name)) & ((1<<64)-1)
    def q(address):
        return word(mem(address,8),0)
    require(gdb.parameter("non-stop") is False,"All-stop GDB required")
    threads=gdb.selected_inferior().threads()
    require(len(threads)==n,"Wrong actual GDB thread count")
    for offset,data in request["runtime_bytes"].items():
        expected=bytes.fromhex(data)
        require(mem(base+int(offset),len(expected))==expected,"Runtime kernel code mismatch")
    table=mem(base+CPU_TABLE,255*8)
    pointers=[v for v in struct.unpack("<255Q",table) if v]
    require(len(pointers)==len(set(pointers))==n and all(
        0x100000<=v<=256*1024*1024-4096 and v%4096==0 for v in pointers),
        "Wrong registered kernel roster")
    qmp=qmp_roster(request["qmp"],n)
    bindings=[]
    initial=gdb.selected_thread()
    for thread in threads:
        thread.switch()
        ptid=thread.ptid
        packet=thread_packet(ptid)
        response=gdb.execute("maintenance packet "+packet,to_string=True)
        index=thread_index(response)
        require(index in qmp,"GDB thread absent from QMP roster")
        gs,kgs=reg("gs_base"),reg("k_gs_base")
        found=set((gs,kgs))&set(pointers)
        require(len(found)==1 and {gs,kgs}=={0,next(iter(found))},"Cannot authenticate thread kernel GS")
        cpu=next(iter(found))
        identity=mem(cpu,0x34)
        bindings.append(dict(thread=list(ptid),packet=packet,response=response,cpu_index=index,
             apic=qmp[index],cpu=cpu,gs_base=gs,kernel_gs_base=kgs,identity=identity.hex()))
    initial.switch()
    ready=dict(armed_ns=0,site=base+SITE,hardware=True,threads=n,online=q(base+ONLINE),
               runtime=mem(base+RUNTIME,1)[0],kernel_roster=table.hex(),bindings=bindings)
    bound=bind_roster(request,ready)
    scan=SmpScan(request,ready)
    bp=gdb.Breakpoint("*"+hex(base+SITE),type=gdb.BP_HARDWARE_BREAKPOINT)
    ready["armed_ns"]=time.monotonic_ns()
    temp=dest/"trace-ready.tmp"
    temp.write_text(json.dumps(ready,sort_keys=True)); temp.replace(dest/"trace-ready.json")
    stops=0; spent=0; maximum=0; error=None; found=None
    try:
        with (dest/"irq-trace.jsonl").open("w",buffering=1) as stream:
            while stops<1500*n and not (dest/"stop-trace").exists():
                gdb.execute("continue",to_string=True)
                start=time.monotonic_ns()
                ptid=gdb.selected_thread().ptid
                require(ptid in bound,"Unknown selected GDB thread")
                index,apic,cpu=bound[ptid]
                gs,kgs=reg("gs_base"),reg("k_gs_base")
                cs,pc=reg("cs"),reg("pc")
                require(pc==base+SITE and cs&3==0 and gs==cpu and kgs==0,
                        "Stopped GDB thread does not own the kernel timer CPU")
                image=mem(cpu,CPU_BYTES)
                stops+=1
                row=dict(seq=stops,host_ns=start,thread=list(ptid),cpu_index=index,apic=apic,
                         cpu=cpu,gs_base=gs,kernel_gs_base=kgs,cs=cs,pc=pc,
                         rsp=reg("rsp"),rax=reg("rax"),cr3=reg("cr3"),eflags=reg("eflags"),
                         online=q(base+ONLINE),runtime=mem(base+RUNTIME,1)[0],
                         irq=word(image,0x140),cpu_image=image.hex())
                row_cpu(row,request,bound)
                cur,nxt,ret,prev=struct.unpack_from("<4Q",image,QUEUE)
                if image[0x150]==0 and cur==ret==1 and 0<=nxt<9 and 0<=prev<9 and nxt!=prev:
                    for key,slot,address in (("out",prev,row["rsp"]),("next",nxt,row["rax"])):
                        off=QUEUE+0x40+slot*0xd8
                        t=image[off:off+0xd8]
                        if word(t,0)==0 and address==word(t,0xb8)==stack_context(t):
                            row[key+"_context"]=mem(address,SIZE).hex()
                stream.write(json.dumps(row,sort_keys=True)+"\n")
                scan.feed(row)
                found=scan.selection()
                elapsed=time.monotonic_ns()-start
                spent+=elapsed; maximum=max(maximum,elapsed)
                if found is not None: break
    except Exception as exc:
        error=repr(exc)
    finally:
        end=time.monotonic_ns()
        bp.delete()
        gdb.execute("detach")
        (dest/"trace-result.json").write_text(json.dumps(dict(error=error,stops=stops,
             armed_ns=ready["armed_ns"],end_ns=end,handler_ns=spent,max_handler_ns=maximum,
             local_last_irq=scan.last_irq,candidate_counts={a:len(c) for a,c in scan.candidates.items()},
             complete=found is not None)))
    require(error is None,"Debugger observation failed: "+str(error))


def observe():
    import gdb
    request=json.loads(Path(os.environ["AGENTOS_PREEMPT_REQUEST"]).read_text())
    if request.get("cpus",1)!=1:
        return observe_smp(request)
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
    smp_selftest()
elif __name__=="__preemption_gdb__":
    observe()
