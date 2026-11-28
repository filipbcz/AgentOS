"""Strict evidence for a bounded private demand-write OOM in a 256 MiB guest."""
import re
import struct

PAGE=4096
PAGES=81920
STEP=4096
SIZE=PAGES*PAGE
MASK=(1<<64)-1
KEEP=0x7355525649564531
COMMAND="run /oom-runner"
INPUT=(COMMAND+"\r").encode("ascii")
MARKER=b"AGENTOS TEST OOM "
OOM=b"AGENTOS PAGE OOM"
HEX=rb"[0-9a-f]{16}"
MISSING=b"run: spawn failed (-2)\r\nagentos> "

class VerificationError(ValueError):
    pass

def require(ok,message):
    if not ok:
        raise VerificationError(message)

def verify_layout(data):
    """Check the actual linked ELF, not a proposed linker layout."""
    def span(off,size):
        require(0<=off<=len(data) and 0<=size<=len(data)-off,"truncated ELF")
        return data[off:off+size]
    require(len(data)<65536,"pressure ELF is not small")
    h=struct.unpack("<16sHHIQQQIHHHHHH",span(0,64))
    require(h[0][:7]==b"\x7fELF\x02\x01\x01" and h[1:4]==(2,62,1) and
            h[8:10]==(64,56) and h[11]==64 and 0<h[13]<h[12],"invalid ELF layout")
    programs=list(struct.iter_unpack("<IIQQQQQQ",span(h[5],h[10]*56)))
    rw=[p for p in programs if p[0]==1 and p[1]==6]
    require(len(rw)==1,"expected exactly one RW LOAD")
    _,_,off,base,_,filesz,memsz,align=rw[0]
    require(filesz==0 and memsz==SIZE and base%PAGE==off%PAGE==0 and
            align>=PAGE and align&(align-1)==0 and base%align==off%align and
            (1<<39)<=base<base+SIZE<=(1<<40)-5*PAGE and off<=len(data),
            "pressure LOAD must be a valid 320 MiB zero-file RW extent")
    sections=list(struct.iter_unpack("<IIQQQQIIQQ",span(h[6],h[12]*64)))
    names=span(sections[h[13]][4],sections[h[13]][5])
    bss=[s for s in sections if s[0]<len(names) and names[s[0]:].split(b"\0",1)[0]==b".bss"]
    require(len(bss)==1 and bss[0][1]==8 and bss[0][2]&7==3 and
            bss[0][3]==base and bss[0][5]==SIZE and bss[0][8]>=PAGE,
            "missing exact allocated writable NOBITS reservation")
    return {"base":base,"end":base+SIZE,"pages":PAGES,"file_bytes":len(data)}

def verify_prefix(data,shell,shell_cr3,prior,variant,apics,layout):
    """Consume exactly one authenticated foreground interval; no inferred OOM."""
    echo=COMMAND.encode("ascii")+b"\r\n"
    require(data.startswith(echo),"missing OOM command echo")
    if variant=="control":
        require(data[len(echo):].startswith(MISSING),"OOM client present in ordinary image")
        return len(echo)+len(MISSING),{"absent":True},set()
    require(variant=="test","unknown OOM image variant")
    require(layout["pages"]==PAGES and layout["end"]-layout["base"]==SIZE and
            layout["base"]%PAGE==0 and 0<layout["file_bytes"]<65536,
            "invalid linked pressure layout")
    require(len(apics) in (1,2),"invalid OOM CPU roster")
    pos=len(echo)
    def line():
        nonlocal pos
        end=data.find(b"\r\n",pos)
        require(end>=0,"incomplete OOM record")
        out=data[pos:end]
        pos=end+2
        return out
    def fields(prefix,names):
        pattern=re.escape(prefix)+b"".join(b" "+name.encode("ascii")+b"=("+HEX+b")" for name in names.split())
        match=re.fullmatch(pattern,line())
        require(match is not None,"bad or missing OOM record: "+prefix.decode("ascii"))
        return tuple(int(x,16) for x in match.groups())
    def test(kind,names):
        return fields(MARKER+kind.encode("ascii"),names)
    def who(pid,parent,cpu,cpus):
        require(pid>parent>0 and cpu in apics and cpus==len(apics),"invalid OOM process identity")
    def sentinel(pid,value,inverse):
        require(value==KEEP^pid and inverse==value^MASK,"corrupted private sentinel")
    root,parent,cpu,cpus,value,inverse,root_ms=test("ROOT","PID PARENT APIC CPUS VALUE INVERSE MS")
    who(root,parent,cpu,cpus)
    require(parent==shell and root>max(set(prior)|{shell}) and root_ms<(1<<63)-20000,
            "invalid foreground OOM owner")
    sentinel(root,value,inverse)
    survivor,parent,cpu,cpus,value,inverse=test("SURVIVOR_BEFORE","PID PARENT APIC CPUS VALUE INVERSE")
    who(survivor,parent,cpu,cpus)
    require(parent==root,"invalid independent survivor owner")
    sentinel(survivor,value,inverse)
    child,parent,cpu,cpus,base,end,reserved,resident,demand=test(
        "RESERVE","PID PARENT APIC CPUS BASE END RESERVED RESIDENT DEMAND")
    who(child,parent,cpu,cpus)
    require(child>survivor and parent==root and (base,end)==(layout["base"],layout["end"]) and
            PAGES+4<=reserved<=PAGES+32 and 0<resident<=32 and resident==demand,
            "pressure child did not start with the linked lazy reservation")
    pid,s,c,start,go,until,attempt,value,inverse=test("WAIT","PID SURVIVOR CHILD START GO UNTIL TRY VALUE INVERSE")
    require((pid,s,c,attempt)==(root,survivor,child,(-11)&MASK) and
            root_ms<=start<go<until and go==start+250 and until==root_ms+20000,
            "invalid bounded wait or child start gate")
    sentinel(root,value,inverse)
    pid,ms=test("BEGIN","PID MS")
    require(pid==child and go<=ms<until,"invalid pressure start")
    checkpoints=[]
    count=0
    previous=resident
    while data.startswith(MARKER+b"PROGRESS ",pos):
        pid,pages,res,dem,t=test("PROGRESS","PID PAGES RESIDENT DEMAND MS")
        require(pid==child and pages==count+STEP and pages<65536 and
                res>=previous+STEP and res>=resident+pages and res<65536 and
                dem==res and ms<=t<until,"invalid real demand-growth checkpoint")
        checkpoints.append({"pages":pages,"resident":res,"demand":dem,"ms":t})
        count,previous,ms=pages,res,t
    pid,address=fields(OOM,"PID ADDRESS")
    require(pid==child and base<=address<end and address%PAGE==0,"OOM outside linked pressure BSS")
    index=(address-base)//PAGE
    require(count>=STEP and count<=index<count+STEP and index<65536,
            "OOM not at the next bounded pressure page")
    pid,parent,pressure_cr3,vector,error,addr=fields(b"AGENTOS USER FAULT","PID PARENT CR3 VECTOR ERROR ADDRESS")
    require((pid,parent,vector,error,addr)==(child,root,14,6,address) and
            pressure_cr3>0 and pressure_cr3%PAGE==0,"OOM not paired with absent private user write")
    pid,c,status,again,finish,value,inverse=test("COLLECT","PID CHILD STATUS AGAIN END VALUE INVERSE")
    require((pid,c,status,again)==(root,child,270,(-10)&MASK) and ms<=finish<=until,
            "incorrect OOM child collection")
    sentinel(root,value,inverse)
    pid,parent,cpu,cpus,value,inverse=test("SURVIVOR_AFTER","PID PARENT APIC CPUS VALUE INVERSE")
    who(pid,parent,cpu,cpus)
    require((pid,parent)==(survivor,root),"different survivor after pressure")
    sentinel(survivor,value,inverse)
    pid,survivor_cr3,status=fields(b"AGENTOS USER EXIT","PID CR3 STATUS")
    require((pid,status)==(survivor,0),"survivor did not exit normally")
    pid,c,status,again,empty=test("SURVIVOR_COLLECT","PID CHILD STATUS AGAIN EMPTY")
    require((pid,c,status,again,empty)==(root,survivor,0,(-10)&MASK,(-10)&MASK),
            "incorrect survivor collection")
    pid,rec,pages,before,after,db,da=test(
        "RECOVERY_1","PID BASE PAGES BEFORE AFTER DEMAND_BEFORE DEMAND_AFTER")
    owner,total,value,inverse,t=test("RECOVERY_2","PID SUM VALUE INVERSE MS")
    require(pid==owner==root and rec%PAGE==0 and (1<<39)<=rec<rec+16*PAGE<=(1<<40)-5*PAGE and
            pages==16 and 0<before==db and after==da and after>=before+16 and
            total==136 and finish<=t<=until,"missing new resident fault-in and verified data")
    sentinel(root,value,inverse)
    pid,root_cr3,status=fields(b"AGENTOS USER EXIT","PID CR3 STATUS")
    require((pid,status)==(root,0),"OOM runner failed")
    roots={root_cr3,pressure_cr3,survivor_cr3,shell_cr3}
    require(len(roots)==4 and all(x>0 and x%PAGE==0 for x in roots),"non-private address spaces")
    prompt=b"exit status 0\r\nagentos> "
    require(data[pos:].startswith(prompt),"shell did not return after OOM recovery")
    return pos+len(prompt),{
        "root_pid":root,"parent_pid":shell,"root_cr3":root_cr3,
        "survivor_pid":survivor,"survivor_cr3":survivor_cr3,
        "pressure_pid":child,"pressure_cr3":pressure_cr3,
        "fault_address":address,"fault_page_index":index,"vector":vector,"error":error,
        "layout":layout,"initial_resident":resident,"initial_demand":demand,
        "checkpoints":checkpoints,"wait_start_ms":start,"gate_ms":go,
        "wait_deadline_ms":until,"collected_at_ms":finish,"status":270,"second_wait":-10,
        "root_sentinel":KEEP^root,"survivor_sentinel":KEEP^survivor,
        "survivor_status":0,"remaining_children":-10,
        "recovery":{"base":rec,"pages":pages,"resident_before":before,"resident_after":after,
                    "demand_before":db,"demand_after":da,"sum":total}}, {root,survivor,child}
