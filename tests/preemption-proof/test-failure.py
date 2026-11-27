"""Linux host execution of the real staged x86-64 client, no guest.

Only native syscall returns are injected by ptrace. Both original and current
ELFs execute their actual root branches/formatter. This is not OS execution
or a preemption proof; the existing signed guest gates remain mandatory.
"""
import argparse
import ctypes as C
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import subprocess as sp
import struct

HERE=Path(__file__).resolve().parent
ROOT=HERE.parent.parent
BASE="ea20b720deef8560a2d1853ec08c59326898ae19"
OLD_CLIENT="17f5bbda2a659dc127fa2c172d08c635b7263607"
PARENT="013763077a25d4d3b2d154c5ad76ea406f8e8a36"
PARENT_CLIENT="b16abb4394a894990654bf959cbc2fdcba770af0"
OLD_ITERATIONS=0x4000000
NEW_ITERATIONS=0x100000
MASK=(1<<64)-1
GETPID,WRITE,EXIT,TRY,YIELD,MONO,WAIT,CHILD,FORK=(
    0x10001,0x10002,0x10003,0x10005,0x10006,0x10010,0x10011,0x10013,0x10014)
FIELDS="STEP PID SLOT CHILD RAW NOW SETUP WAIT DETAIL".split()
START=1000
SETUP=START+6000
WAIT_LIMIT=SETUP+60000

def require(ok,message):
    if not ok: raise ValueError(message)

def command(*args):
    return sp.check_output([str(v) for v in args],cwd=ROOT)

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def symbols(path):
    return {p[2]:int(p[0],16) for l in command("nm","-n",path).decode().splitlines()
            if len(p:=l.split())==3 and re.fullmatch("[0-9a-fA-F]+",p[0])}

def instructions(path):
    syms=symbols(path)
    out=command("objdump","-d","-Mintel","--no-show-raw-insn",path).decode()
    end=syms["terminate"]+9
    result=[]
    for line in out.splitlines():
        m=re.match(r"^\s*([0-9a-f]+):\s+(.+)$",line)
        if not m: continue
        pc,body=int(m[1],16),m[2].strip()
        if not syms["_start"]<=pc<end: continue
        if re.search(r"\bnop\b",body) or re.fullmatch(r"xchg\s+ax,ax",body): continue
        fields=body.split(None,1)
        result.append((pc,fields[0],fields[1].strip() if len(fields)>1 else ""))
    require(result and result[0][0]==syms["_start"] and result[-1][1]=="ud2",
            "Incomplete original instruction range")
    return result,syms,out,end

def compare(old,new,dest):
    before,bs,bdis,be=instructions(old)
    after,ns,ndis,ne=instructions(new)
    (dest/"baseline-client-disassembly.txt").write_text(bdis)
    require(len(before)==len(after),"Changed successful instruction count")
    bidx={pc:i for i,(pc,_,_) in enumerate(before)}
    nidx={pc:i for i,(pc,_,_) in enumerate(after)}
    fail_count=0
    def normalize(args):
        args=re.sub(r"\s+"," ",args)
        # The diagnostic-only text may move data, not the accessed symbol.
        if "[rip" in args:
            require("#" in args and "<" in args,"Unresolved RIP-relative operand")
            code,comment=args.split("#",1)
            symbol=re.search(r"<([^>]+)>",comment)
            require(symbol is not None,"Missing referenced symbol")
            return re.sub(r"\[rip[+-]0x[0-9a-f]+\]","[rip+REL]",code).strip()+" <"+symbol[1]+">"
        return args
    reverse={v:k for k,v in ns.items() if k.startswith("diag_")}
    branches=[]
    immediates=[]
    begin={addr:name for name,addr in bs.items() if name.startswith('window_') and name.endswith('_begin')}
    for (bp,bo,ba),(np,no,na) in zip(before,after):
        require(bo==no,f"Changed instruction {bp:x}/{np:x}: {bo} != {no}")
        if bo.startswith("j") or bo=="call":
            bm=re.match(r"^([0-9a-f]+)\b",ba); nm=re.match(r"^([0-9a-f]+)\b",na)
            require(bm and nm,"Unexpected indirect branch")
            bt,nt=int(bm[1],16),int(nm[1],16)
            if bt==bs["failed"]:
                require(nt>=ne and nt in reverse,"Failure branch not redirected outside normal code")
                fail_count+=1
                branches.append(dict(old_pc=bp,new_pc=np,target=reverse[nt],condition=bo))
            else:
                require(bt in bidx and nt in nidx and bidx[bt]==nidx[nt],"Changed ordinary branch destination")
        else:
            if bp+5 in begin and bo=="mov":
                name=begin[bp+5]
                require(np+5==ns[name] and ba=="ecx,0x4000000" and na=="ecx,0x100000",
                        "Unexpected iteration immediate at "+name)
                immediates.append(name)
            else:
                require(normalize(ba)==normalize(na),f"Changed ordinary operand {bp:x}/{np:x}: {ba} != {na}")
    require(set(immediates)==set(begin.values()) and len(immediates)==len(begin),
            "Missing exact iteration changes in disassembly")
    require(fail_count>0,"No actual redirected failure branches")
    require(all(addr==ns[name] for name,addr in bs.items() if name.startswith("window_")),
            "Changed actual measured loop addresses")
    return dict(instructions=len(before),redirected=branches,iteration_changes=sorted(immediates),old_main_bytes=be-bs["_start"],
                new_main_bytes=ne-ns["_start"],
                windows={name:[addr,ns[name]] for name,addr in bs.items() if name.startswith("window_")})

def compile_client(source,cpus,dest,name):
    obj=dest/(name+".o")
    elf=dest/(name+".elf")
    stripped=dest/(name+".stripped.elf")
    defines=[] if cpus==1 else [f"-DPREEMPT_CPUS={cpus}"]
    command("gcc-13","-I",HERE,*defines,"-c",source,"-o",obj)
    command("ld","--no-undefined","--build-id=none","-z","noexecstack","-T",ROOT/"user/user.ld","-o",elf,obj)
    command("objcopy","--strip-all",elf,stripped)
    return elf,stripped

def workload_identity(actual,cpus,dest):
    require(command("git","rev-parse",PARENT+":tests/preemption-proof/client.S").decode().strip()==PARENT_CLIENT,
            "Wrong immediate parent client blob")
    parent_source=dest/"parent-client.S"
    parent_source.write_bytes(command("git","show",PARENT+":tests/preemption-proof/client.S"))
    parent,previous=compile_client(parent_source,cpus,dest,"parent-profile")
    stripped=dest/"actual-profile.stripped.elf"
    command("objcopy","--strip-all",actual,stripped)
    require(stripped.read_bytes()==(dest/"preempt-runner").read_bytes(),"Actual staged ELF differs from compiled client")
    # Whole stripped ELF comparison against the immediate parent: patch
    # precisely the imm32 after B9, and nothing else. This is stronger than
    # normalized instruction comparison (also covers diagnostic code/data).
    old=bytearray(previous.read_bytes())
    syms=symbols(parent)
    actual_syms=symbols(actual)
    offsets={}
    for name,addr in syms.items():
        if not (name.startswith("window_") and name.endswith("_begin")): continue
        require(actual_syms[name]==addr,"Moved measurement window")
        offset=0x1000+addr-0x8000400000-5
        require(old[offset:offset+5]==b"\xb9"+struct.pack("<I",OLD_ITERATIONS),
                "Wrong historical loop initializer")
        old[offset+1:offset+5]=struct.pack("<I",NEW_ITERATIONS)
        offsets[name]=offset+1
    require(len(offsets)==2*cpus and bytes(old)==stripped.read_bytes(),
            "Changed bytes beyond exact loop immediates")
    unchanged={}
    for n in (1,2):
        _,before=compile_client(parent_source,n,dest,f"parent-{n}cpu")
        _,after=compile_client(HERE/"client.S",n,dest,f"current-{n}cpu")
        require(before.read_bytes()==after.read_bytes(),"Changed 1/2 CPU client bytes")
        unchanged[str(n)]={"parent_sha256":sha(before),"current_sha256":sha(after)}
    # The original two-CPU proof predates failure diagnostics. Verify its
    # compiled bytes separately; never substitute the current 2 CPU variant.
    _,historical=compile_client(dest/"baseline-client.S",2,dest,"historical-2cpu")
    require(sha(historical)=="46ad9dd1b253614a5083c885774124f2ba43daeb4ef4575db290b011917a239c",
            "Historical compiled 2 CPU client differs from archived proof")
    return dict(parent_blob=PARENT_CLIENT,old_iterations=OLD_ITERATIONS,new_iterations=NEW_ITERATIONS,
                exact_immediate_offsets=offsets,parent_sha256=sha(previous),actual_sha256=sha(stripped),
                unchanged=unchanged,historical_two_sha256=sha(historical))

# Linux x86_64 user_regs_struct. The child is our own newly executed test ELF,
# not a guest or an arbitrary process. No native syscall reaches Linux:
# only the final expected native exit is translated to Linux exit(60).
class Regs(C.Structure):
    _fields_=[(name,C.c_ulonglong) for name in
              "r15 r14 r13 r12 rbp rbx r11 r10 r9 r8 rax rcx rdx rsi rdi orig_rax rip cs eflags rsp ss fs_base gs_base ds es fs gs".split()]

libc=C.CDLL(None,use_errno=True)
libc.ptrace.argtypes=[C.c_uint,C.c_int,C.c_void_p,C.c_void_p]
libc.ptrace.restype=C.c_long
def ptrace(op,pid,arg=0,data=0):
    C.set_errno(0)
    ret=libc.ptrace(op,pid,arg,data)
    if ret==-1 and C.get_errno(): raise OSError(C.get_errno(),os.strerror(C.get_errno()))
    return ret

def event(name,number,value,args=None,data=None,inject=None):
    return dict(name=name,number=number,value=value,args=args,data=data,inject=inject)

def line(mark,pid):
    return f"REG {mark} PID={pid:016x}\r\n".encode()

def root_script(n):
    s=[event("root_pid",GETPID,18),event("root_write",WRITE,None,data=line("ROOT",18)),
       event("initial_clock",MONO,START)]
    for i in range(1,n+1):
        l=chr(64+i); pid=18+i
        s.extend([event(f"clock_{i}",MONO,1100+i),event(f"fork_{i}",FORK,pid),
                  event(f"spawn_write_{i}",WRITE,None,data=line(l,pid)),event(f"yield_{i}",YIELD,0)])
    s.append(event("post_clock",MONO,2000))
    for i in range(1,n+1):
        l=chr(64+i); pid=18+i
        s.extend([event(f"wait_{i}",WAIT,0,(pid,WAIT_LIMIT,0)),event(f"try_{i}",TRY,-10,(pid,0,0)),
                  event(f"reap_write_{i}",WRITE,None,data=line(l+" REAP",pid))])
    s.extend([event("child_check",CHILD,-10,(0,0,0)),event("complete_pid",GETPID,18),
              event("complete_write",WRITE,None,data=line("COMPLETE",18)),event("exit",EXIT,0)])
    return s

def prefix(script,name,value):
    index=next(i for i,e in enumerate(script) if e["name"]==name)
    return script[:index]+[dict(script[index],value=value)]

def execute(elf,script):
    pid=os.fork()
    if pid==0:
        try:
            ptrace(0,0) # TRACEME
            os.execv(str(elf),[str(elf)])
        except BaseException:
            os._exit(127)
    mem=None; done=False; events=[]
    def stopped():
        _,status=os.waitpid(pid,0)
        return status
    def regs():
        r=Regs(); ptrace(12,pid,0,C.cast(C.byref(r),C.c_void_p)); return r
    def store(r):
        ptrace(13,pid,0,C.cast(C.byref(r),C.c_void_p))
    try:
        st=stopped()
        require(os.WIFSTOPPED(st) and os.WSTOPSIG(st)==signal.SIGTRAP,"Host exec/ptrace failed")
        ptrace(0x4200,pid,0,0x100001) # TRACESYSGOOD | EXITKILL
        mem=os.open(f"/proc/{pid}/mem",os.O_RDONLY)
        for e in script:
            ptrace(24,pid) # SYSCALL entry
            st=stopped()
            require(os.WIFSTOPPED(st) and os.WSTOPSIG(st)==(signal.SIGTRAP|0x80),"Missing syscall entry "+e["name"])
            r=regs()
            require(r.orig_rax==e["number"],f"Wrong syscall {e['name']}: {r.orig_rax:x}")
            if e["args"] is not None:
                require((r.rdi,r.rsi,r.rdx)==e["args"],"Wrong syscall args "+e["name"])
            rec=dict(name=e["name"],number=r.orig_rax)
            value=e["value"]
            if r.orig_rax==WRITE:
                require(r.rdi==1 and 0<r.rdx<=512,"Wrong write descriptor/length")
                data=os.pread(mem,r.rdx,r.rsi)
                require(len(data)==r.rdx,"Short host fixture memory read")
                if e["data"] is not None: require(data==e["data"],"Wrong actual report "+e["name"])
                rec["attempted"]=data.decode("ascii")
                rec["length"]=r.rdx
                if value is None: value=r.rdx
            if r.orig_rax==EXIT:
                require(r.rdi==value and e is script[-1],"Wrong actual exit code")
                r.orig_rax=60
                store(r); ptrace(24,pid)
                st=stopped()
                done=os.WIFEXITED(st) or os.WIFSIGNALED(st)
                require(os.WIFEXITED(st) and os.WEXITSTATUS(st)==value,"Host process exit mismatch")
                rec["status"]=value; events.append(rec)
                return events
            r.orig_rax=MASK # skip all native syscalls on Linux
            store(r); ptrace(24,pid)
            st=stopped()
            require(os.WIFSTOPPED(st) and os.WSTOPSIG(st)==(signal.SIGTRAP|0x80),"Missing syscall return")
            r=regs(); r.rax=value&MASK
            if e["inject"]:
                # A separate synthetic register-corruption fixture starts at
                # the actual end-of-window comparison, never claims a loop run.
                for k,v in e["inject"].items(): setattr(r,k,v)
            store(r)
            rec["return"]=value; events.append(rec)
        raise ValueError("Script omitted actual exit")
    finally:
        if mem is not None: os.close(mem)
        if not done:
            try: os.kill(pid,signal.SIGKILL)
            except ProcessLookupError: pass
            try: os.waitpid(pid,0)
            except ChildProcessError: pass

def diag_record(events):
    lines=[x["attempted"] for x in events if x["name"]=="diagnostic_write"]
    require(len(lines)==1,"Missing attempted actual diagnostic write")
    m=re.fullmatch("REG FAIL "+" ".join(k+r"=([0-9a-f]{16})" for k in FIELDS)+r"\r\n",lines[0])
    require(m is not None,"Malformed actual failure formatter output")
    return dict(zip(FIELDS,(int(v,16) for v in m.groups())))

def tests(old,new,cpus):
    n=2*cpus
    s=root_script(n)
    old_ok=execute(old,s); new_ok=execute(new,s)
    require(old_ok==new_ok,"Successful native syscall sequence changed")
    cases={"unchanged_success":dict(status=0,syscalls=len(new_ok))}
    def failure(name,pre,step,slot=0,child=0,raw=0,detail=0,now=8123,early=False,
                pid=18,write_return=None,baseline=False):
        if baseline:
            collapsed=execute(old,pre+[event("exit",EXIT,91)])
            require(collapsed[-1]["status"]==91,"Old common failure not reproduced")
        events=execute(new,pre+[event("diagnostic_pid",GETPID,pid),event("diagnostic_clock",MONO,now),
            event("diagnostic_write",WRITE,write_return),event("exit",EXIT,step)])
        actual=diag_record(events)
        want=dict(zip(FIELDS,(v&MASK for v in (step,pid,slot,child,raw,now,0 if early else SETUP,
                                              0 if early else WAIT_LIMIT,detail))))
        require(actual==want,f"{name}: diagnostic metadata mismatch {actual!r} != {want!r}")
        cases[name]=dict(status=step,fields=actual,actual_line=events[-2]["attempted"],
                         write_return=events[-2]["return"],original_failure=pre[-1]["name"],
                         baseline_exit91=baseline)
        print("FAILURE FIXTURE PASS",name,step,flush=True)
    failure("root_pid",prefix(s,"root_pid",-5),101,raw=-5,early=True)
    failure("initial_clock",prefix(s,"initial_clock",-5),102,raw=-5,early=True)
    failure("last_spawn_clock",prefix(s,f"clock_{n}",-5),103,slot=n,raw=-5)
    failure("last_spawn_deadline",prefix(s,f"clock_{n}",SETUP),104,slot=n,raw=SETUP)
    failure("last_fork",prefix(s,f"fork_{n}",-12),105,slot=n,raw=-12)
    failure("last_yield",prefix(s,f"yield_{n}",-5),106,slot=n,child=18+n,raw=-5)
    failure("last_retry_yield",prefix(s,f"fork_{n}",-11)+[event("retry_yield",YIELD,-5)],
            107,slot=n,raw=-5)
    failure("post_clock",prefix(s,"post_clock",-5),108,raw=-5,now=-5,baseline=True)
    failure("post_deadline",prefix(s,"post_clock",SETUP),109,raw=SETUP,baseline=True)
    failure("first_wait_errno",prefix(s,"wait_1",-110),110,slot=1,child=19,raw=-110,baseline=True)
    failure("first_wait_status",prefix(s,"wait_1",7),110,slot=1,child=19,raw=7)
    failure("try_wait",prefix(s,"try_1",-11),111,slot=1,child=19,raw=-11)
    failure("final_child_check",prefix(s,"child_check",19),112,raw=19)
    failure("diagnostic_write_errno",prefix(s,"post_clock",SETUP),109,raw=SETUP,write_return=-5)
    failure("diagnostic_write_short",prefix(s,"wait_1",-110),110,slot=1,child=19,raw=-110,write_return=1)
    failure("root_report",prefix(s,"root_write",-5),121,raw=-5,detail=len(line("ROOT",18)),early=True)
    failure("last_spawn_report",prefix(s,f"spawn_write_{n}",1),122,slot=n,child=18+n,raw=1,
            detail=len(line(chr(64+n),18+n)))
    failure("reap_report",prefix(s,"reap_write_1",-5),125,slot=1,child=19,raw=-5,detail=len(line("A REAP",19)))
    failure("complete_report",prefix(s,"complete_write",1),126,raw=1,detail=len(line("COMPLETE",18)))
    worker=prefix(s,"fork_1",0)
    failure("worker_clock",worker+[event("worker_clock",MONO,-5)],113,slot=1,pid=19,raw=-5)
    failure("worker_yield",worker+[event("worker_clock",MONO,2000),event("worker_yield",YIELD,-5)],
            114,slot=1,pid=19,raw=-5)
    begun=worker+[event("worker_clock",MONO,SETUP),event("worker_pid",GETPID,19)]
    failure("worker_begin_report",begun+[event("worker_begin",WRITE,-5,data=line("A BEGIN",19))],
            123,slot=1,pid=19,raw=-5,detail=len(line("A BEGIN",19)))
    # Execute actual R10 comparison and failure stub with a deliberately
    # corrupted register. Explicit fixture PC injection, no IRQ evidence.
    end=symbols(new)["window_A_end"]
    failure("worker_r10_sentinel",begun+[event("worker_begin",WRITE,None,data=line("A BEGIN",19),
            inject={"rip":end,"r10":0x123456789abcdef0})],115,slot=1,pid=19,
            raw=0x123456789abcdef0,detail=0x1122334455667788)
    return cases

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--cpus",type=int,choices=(4,8),required=True)
    ap.add_argument("--elf",type=Path,required=True)
    ap.add_argument("--receipt",type=Path,required=True)
    a=ap.parse_args()
    dest=a.receipt.resolve().parent
    old=dest/"baseline-client.elf"
    source=dest/"baseline-client.S"
    receipt=dict(result="fail",guests=0,cpus=a.cpus)
    try:
        require(command("git","rev-parse","HEAD^").decode().strip()==PARENT,"Wrong pinned source parent")
        require(command("git","rev-parse",BASE+":tests/preemption-proof/client.S").decode().strip()==OLD_CLIENT,
                "Wrong historical client blob")
        source.write_bytes(command("git","show",BASE+":tests/preemption-proof/client.S"))
        command("gcc-13","-I",HERE,f"-DPREEMPT_CPUS={a.cpus}","-c",source,"-o",dest/"baseline-client.o")
        command("ld","--no-undefined","--build-id=none","-z","noexecstack","-T",ROOT/"user/user.ld",
                "-o",old,dest/"baseline-client.o")
        receipt.update(baseline_blob=OLD_CLIENT,baseline_sha256=sha(old),actual_sha256=sha(a.elf),
                       source_sha256=sha(HERE/"client.S"),test_sha256=sha(Path(__file__)))
        receipt["disassembly"]=compare(old,a.elf,dest)
        receipt["workload_identity"]=workload_identity(a.elf,a.cpus,dest)
        receipt["cases"]=tests(old,a.elf.resolve(),a.cpus)
        receipt["result"]="pass"
        print("ACTUAL CLIENT FAILURE PATHS AND UNCHANGED SUCCESS PASS",flush=True)
    except Exception as exc:
        receipt["error"]=repr(exc)
        raise
    finally:
        a.receipt.write_text(json.dumps(receipt,sort_keys=True,indent=2)+"\n")

if __name__=="__main__":
    main()
