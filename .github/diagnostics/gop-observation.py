"""External observation of one ordinary signed staged KVM PM session.
No new guest code, altered commands, deadlines, or acceptance predicates.
Additional screenshots between commands measure actual display convergence;
they are diagnostic, not replacements for the normal matrix.
"""
import bisect
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import statistics
import subprocess
import sys
import time

sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[2]
OUT=ROOT/"build/console-observation"
FOLDER=ROOT/"build/check/qemu-cpu2-no-hpet-kvm-session-sv-test"
CAP=131072
POINTS={"run /svc_ok","run /svc_fail","run /fault","run /supervisor-runner",
        "run /pipe-runner","help","echo shell-ox\x08k","idle","echo ps2-ox\x08k"}
BOOT=b"AGENTOS MANAGER SESSION START PID="
PROMPT=b"agentos> "
W,H=6,9
BG,FG,CURSOR=b"\x18"*3,b"\xff"*3,b"\xe7"*3


def require(condition,message):
    if not condition: raise RuntimeError(message)


def sha(data): return hashlib.sha256(data).hexdigest()


def save(path,data): path.write_text(json.dumps(data,indent=2,sort_keys=True)+"\n")


def load(name,path):
    spec=importlib.util.spec_from_file_location(name,ROOT/path)
    mod=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class TimedSocket:
    def __init__(self,sock):
        self.sock=sock
        self.rx=[];self.tx=[]
        self.r=0;self.t=0
        self.overflow=False

    def __getattr__(self,name): return getattr(self.sock,name)

    def recv(self,*args,**kwargs):
        before=time.monotonic_ns()
        data=self.sock.recv(*args,**kwargs)
        after=time.monotonic_ns()
        if data:
            if len(self.rx)<CAP: self.rx.append((self.r,len(data),before,after))
            else: self.overflow=True
            self.r+=len(data)
        return data

    def sendall(self,data,*args,**kwargs):
        before=time.monotonic_ns()
        self.sock.sendall(data,*args,**kwargs)
        after=time.monotonic_ns()
        if len(self.tx)<CAP: self.tx.append((self.t,len(data),before,after))
        else: self.overflow=True
        self.t+=len(data)


def validate(rows,size):
    at=0;prev=-1
    for offset,length,before,after in rows:
        require(offset==at and length>0 and prev<=before<=after,"Invalid timing coverage/order")
        at+=length;prev=after
    require(at==size,"Timing sidecar does not cover raw bytes exactly")


def tty_origin(raw):
    m=list(re.finditer(rb"(?m)^AGENTOS MANAGER SESSION START PID=[0-9a-f]{16}\r\n",raw))
    require(len(m)==1,"Missing or duplicate terminal publication")
    return m[0].end()


def replay(raw,cols,rows):
    """Independent linear text model; no dependence on the kernel ring state."""
    cells=[bytearray(b" "*cols) for _ in range(rows)]
    x=y=0
    transitions=[]
    def newline(offset,kind):
        nonlocal x,y
        x=0
        scroll=y==rows-1
        if scroll:
            cells.pop(0);cells.append(bytearray(b" "*cols))
        else: y+=1
        transitions.append((offset,kind,scroll))
    def put(byte,offset):
        nonlocal x,y
        if byte==13:x=0
        elif byte==10:newline(offset,"LF")
        elif byte==8:
            if x:x-=1
            elif y:y-=1;x=cols-1
        elif byte==9:
            for _ in range(4-x%4):put(32,offset)
        elif 32<=byte<=126:
            if x==cols:newline(offset,"wrap")
            cells[y][x]=byte;x+=1
    start=tty_origin(raw)
    # The direct serial stop marker is emitted only after TTY removal.
    end=raw.find(b"AGENTOS MANAGER SESSION STOP PID=",start)
    if end<0:end=len(raw)
    for i in range(start,end):put(raw[i],i)
    return cells,(x,y),transitions,start,end


def expected_pixels(raw,image,console):
    width,height=image.fWidth,image.fHeight
    top=console.console_origin(height)
    cols,rows=width//W,(height-top)//H
    require(cols>0 and rows>0,"Invalid screenshot geometry")
    cells,(x,y),transitions,start,end=replay(raw,cols,rows)
    tile={}
    for c in range(32,127):
        glyph=console.FONT[chr(c)]
        tile[c]=tuple(b"".join(FG if dy<7 and dx<5 and glyph[dy]&(16>>dx) else BG
                               for dx in range(W)) for dy in range(H))
    scan=[]
    right=BG*(width%W)
    for row,line in enumerate(cells):
        for dy in range(H):
            parts=[tile[c][dy] for c in line]
            if dy==7 and row==y and x<cols:parts[x]=CURSOR*5+BG
            scan.append(b"".join(parts)+right)
    scan.append(BG*width*((height-top)%H))
    expected=b"".join(scan)
    actual=image.fRgb[top*width*3:]
    require(len(expected)==len(actual),"Unexpected raster length")
    return {"width":width,"height":height,"top":top,"cols":cols,"rows":rows,
            "cursor":[x,y],"expected_sha256":sha(expected),"actual_sha256":sha(actual),
            "header_sha256":sha(image.fRgb[:top*width*3]),
            "exact":expected==actual,"compared_pixels":len(actual)//3,
            "mismatched_pixels":sum(expected[i:i+3]!=actual[i:i+3] for i in range(0,len(actual),3))
                if expected!=actual else 0}


def analyze(raw,link,geometry):
    ends=[x[0]+x[1] for x in link.rx]
    def host(at): return link.rx[bisect.bisect_right(ends,at)][3]
    _,_,transitions,start,end=replay(raw,geometry["cols"],geometry["rows"])
    ready=raw.find(b"AGENTOS SHELL READY\r\nagentos> ",start)
    require(ready>=0,"No shell-ready boundary")
    groups={}
    rows=[]
    for offset,kind,scroll in transitions:
        if offset<ready or offset+1>=end:continue
        # UART sends the triggering byte before the console producer
        # processes it. Group the following gap, not the previous one.
        gap=(host(offset+1)-host(offset))/1e6
        key=kind+("-scroll" if scroll else "-no-scroll")
        groups.setdefault(key,[]).append(gap)
        rows.append([offset,key,gap])
    result={k:{"count":len(v),"median_ms":statistics.median(v),"min_ms":min(v),
               "max_ms":max(v),"ge_100ms":sum(g>=100 for g in v)} for k,v in groups.items()}
    brackets=[]
    for label,start_pat,end_pat in [
        ("supervisor",rb"(?m)^AGENTOS TEST RUNNER .+\r\n",rb"(?m)^AGENTOS TEST COMPLETE .+\r\n"),
        ("pipe",rb"(?m)^AGENTOS PIPE TEST RUNNER .+\r\n",rb"(?m)^AGENTOS PIPE TEST COMPLETE .+\r\n")]:
        a=re.search(start_pat,raw);b=re.search(end_pat,raw)
        if a and b:
            brackets.append({"kind":label,"start_offset":a.end()-1,"end_offset":b.end()-1,
                             "host_rx_ms":(host(b.end()-1)-host(a.end()-1))/1e6})
    return {"groups":result,"transitions":rows,"brackets":brackets,
            "rx_blocks":len(link.rx),"max_rx_block":max(r[1] for r in link.rx),
            "clock_resolution_s":time.get_clock_info("monotonic").resolution,
            "limitation":"recv return is host observation, not guest execution; extra screen observations between commands can extend those particular gaps."}


def run():
    OUT.mkdir(parents=True,exist_ok=True)
    smoke=load("observed_smoke","scripts/qemu-smoke.py")
    images=load("observed_images","scripts/verify-supervisor-image.py")
    console=smoke.console
    identity=images.verify_identity(ROOT)
    save(OUT/"identity.json",identity)
    links=[];captures=[];observations=[];errors=[];state={}
    original_connect=smoke.connect_uart
    original_screenshot=smoke.Qmp.screenshot
    original_wait=smoke.wait_session
    original_session=smoke.run_session
    def connect(*args,**kwargs):
        require(not links,"Unexpected second UART connection")
        link=TimedSocket(original_connect(*args,**kwargs));links.append(link);return link
    def screenshot(qmp,path):
        serial=FOLDER/"com1.log"
        before=serial.stat().st_size if serial.exists() else 0
        t0=time.monotonic_ns()
        original_screenshot(qmp,path)
        t1=time.monotonic_ns()
        after=serial.stat().st_size if serial.exists() else 0
        captures.append({"file":str(path.relative_to(ROOT)),"request_ns":t0,"return_ns":t1,
                         "com1_before":before,"com1_after":after,"ppm_sha256":sha(path.read_bytes())})
    def observed_session(process,capture,qmp,destination,*args,**kwargs):
        state["qmp"]=qmp
        return original_session(process,capture,qmp,destination,*args,**kwargs)
    def observe(description,serial,data):
        qmp=state["qmp"]
        # Retain every actual screenshot. Only compare against an exact
        # stable transcript prefix ending in the real shell prompt.
        tag=f"{len(observations):02d}"
        obs={"description":description,"detected_ns":time.monotonic_ns(),
             "detected_offset":len(data),"attempts":[]}
        observations.append(obs)
        for i in range(5):
            path=OUT/f"screen-{tag}-{i}.ppm"
            screenshot(qmp,path)
            row=dict(captures[-1])
            if row["com1_before"]==row["com1_after"]:
                prefix=serial.read_bytes()[:row["com1_after"]]
                if prefix.endswith(PROMPT):
                    row.update(expected_pixels(prefix,console.read_image(path),console))
                else:row["exact"]=False;row["reason"]="not at stable shell prompt"
            else:row["exact"]=False;row["reason"]="UART progressed during screen request"
            obs["attempts"].append(row)
            if row["exact"]:break
            if time.monotonic_ns()-obs["detected_ns"]>1_500_000_000:break
            time.sleep(0.02)
        if not obs["attempts"][-1]["exact"]: errors.append("No exact terminal raster: "+description)
        save(OUT/"screen-observations.json",observations)
    def wait(process,capture,serial,predicate,description,seconds=30):
        data=original_wait(process,capture,serial,predicate,description,seconds)
        if description in POINTS:
            try:observe(description,serial,data)
            except Exception as e:
                errors.append(description+": "+str(e))
                save(OUT/"observation-errors.json",errors)
        return data
    smoke.connect_uart=connect
    smoke.Qmp.screenshot=screenshot
    smoke.run_session=observed_session
    smoke.wait_session=wait
    sys.argv=["qemu-smoke.py","--cpus","2","--accel","kvm","--no-hpet","--session",
              "--runtime-process-regression","--supervisor-image","test",
              "--ovmf-code","/usr/share/OVMF/OVMF_CODE_4M.secboot.fd",
              "--ovmf-vars","/usr/share/OVMF/OVMF_VARS_4M.fd","--timeout","180"]
    rc=1
    try:rc=smoke.main()
    finally:
        raw=(FOLDER/"com1.log").read_bytes() if (FOLDER/"com1.log").is_file() else b""
        sent=(FOLDER/"com1-input.bin").read_bytes() if (FOLDER/"com1-input.bin").is_file() else b""
        link=links[0] if links else None
        save(OUT/"timing.json",{"columns":["offset","length","before_ns","after_ns"],
              "clock":"time.monotonic_ns","rx":link.rx if link else [],"tx":link.tx if link else [],
              "overflow":link.overflow if link else None,"com1_sha256":sha(raw),"input_sha256":sha(sent)})
        save(OUT/"captures.json",captures)
        save(OUT/"screen-observations.json",observations)
        save(OUT/"observation-errors.json",errors)
        save(OUT/"result.json",{"smoke_rc":rc,"observation_errors":errors})
    require(link is not None and not link.overflow,"Timing unavailable/overflow")
    validate(link.rx,len(raw));validate(link.tx,len(sent))
    require(raw.count(b"[INFO] SYSTEM CLOCK: ACPI PM24\r\n")==1,"Not actual PM24")
    # Re-read the exact boot file even when a guest regression failed.
    actual=OUT/"postboot-bootx64.efi"
    subprocess.run(["mcopy","-i",str(FOLDER/"esp.raw")+"@@1048576","::EFI/BOOT/BOOTX64.EFI",str(actual)],check=True)
    require(actual.read_bytes()==(ROOT/"build/supervisor-staging/test.efi").read_bytes(),"ESP payload differs")
    geometry=console.read_image(FOLDER/"shell-screen.ppm")
    top=console.console_origin(geometry.fHeight)
    summary=analyze(raw,link,{"cols":geometry.fWidth//W,"rows":(geometry.fHeight-top)//H})
    ends=[r[0]+r[1] for r in link.rx]
    def received(offset):return link.rx[bisect.bisect_right(ends,offset)][3]
    header=sha(geometry.fRgb[:top*geometry.fWidth*3])
    exact_count=0
    for obs in observations:
        for frame in obs["attempts"]:
            if frame["exact"]:
                require(frame["header_sha256"]==header,"Boot header changed")
                frame["from_last_rx_to_screenshot_request_ms"]=(frame["request_ns"]-received(frame["com1_after"]-1))/1e6
                frame["from_last_rx_to_screenshot_return_ms"]=(frame["return_ns"]-received(frame["com1_after"]-1))/1e6
                exact_count+=1
                break
    save(OUT/"screen-observations.json",observations)
    save(OUT/"summary.json",summary)
    print("UART timing groups:",json.dumps(summary["groups"],sort_keys=True),flush=True)
    print("Workload timing brackets:",json.dumps(summary["brackets"]),flush=True)
    for obs in observations:
        print("Screen",obs["description"],json.dumps(obs["attempts"][-1],sort_keys=True),flush=True)
    require(rc==0,"Unchanged smoke verifier failed")
    require({obs["description"] for obs in observations}==POINTS and exact_count==len(POINTS) and not errors,
            "Missing or invalid measured screen convergence")
    return 0

if __name__=="__main__":sys.exit(run())
