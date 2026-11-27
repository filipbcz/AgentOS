"""One signed PM24 session, observe only the two missing GOP checkpoints."""
import ast
import bisect
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import sys
import time
import zipfile

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "build/gop-convergence"
FOLDER = ROOT / "build/check/qemu-cpu2-no-hpet-kvm-session-sv-test"
TARGETS = {"run /fault": b"exit status 270\r\nagentos> ",
           "echo shell-ox\x08k": b"shell-ok\r\nagentos> "}
LIMIT_NS = 1_500_000_000
MAX_ATTEMPTS = 12
PAUSE = 0.020
CAP = 131072
W, H, TOP = 6, 9, 88
BG, FG, CURSOR = b"\x18" * 3, b"\xff" * 3, b"\xe7" * 3
OLD_SHA = "a3c0a4cbfe9d87fd3094f2ede5276e6ed7afc7f32226aaef5d89dabe1ae25496"
PAYLOADS = {
    "kernel.elf": "3e0232a1f48bcf4ea88b04db9ae6890c751c4757daa196129bbf0d751f67bf68",
    "initramfs.cpio": "f47386603d9022a0124866525fcc74b3530d1ccfe3edca3a90a8b3bef6ccdbd1",
    "supervisor-staging/test.cpio": "57f3cca5e865c83f9995ae74398f2fb540b1b9ea5b01c819a43fdb06977805fe",
    "agentos.unsigned.efi": "8cd81233b2ec0d088c75f27b2267e5e0b31726e0bc0b342c227c69d72fad4e5b",
    "supervisor-staging/test.unsigned.efi": "77515b6194b647cd3f6d855c626d43754ce058629a7ddd0756d218851011d26a",
}


def require(ok, message):
    if not ok:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def save(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def font(source):
    # Rust byte literals include escaped quote, backslash and hexadecimal `.
    result = {}
    for literal, values in re.findall(r"(?m)^\s*(b'(?:\\.|[^'\\])+')\s*=>\s*\[([0-9,; ]+)\],", source):
        byte = ast.literal_eval(literal)
        if ";" in values:
            value, count = map(int, values.split(";"))
            require(count == 7, "Invalid repeated glyph")
            rows = (value,) * count
        else:
            rows = tuple(map(int, values.split(",")))
        require(len(byte) == 1 and byte[0] not in result and len(rows) == 7
                and all(0 <= r < 32 for r in rows), "Invalid or duplicate glyph")
        result[byte[0]] = rows
    require(set(result) == set(range(32, 127)), "Incomplete printable ASCII font")
    require(result[32] == (0,) * 7 and result[96] == (8, 4, 2, 0, 0, 0, 0), "Unexpected space/backtick")
    return result


def ppm(data):
    m = re.match(rb"P6\s+(\d+)\s+(\d+)\s+255(?:\r\n|\n)", data)
    require(m is not None, "Empty or invalid P6 screenshot")
    w, h = int(m[1]), int(m[2])
    pixels = data[m.end():]
    require(w >= W and h >= TOP + 2*H and 0 < w*h <= 16*1024*1024
            and len(pixels) == w*h*3, "Invalid screenshot geometry/length")
    return w, h, pixels


def reference(raw, w, h, glyphs):
    # Independent linear text grid: no guest memory, no ring implementation.
    cols, rows = w//W, (h-TOP)//H
    cells = [bytearray(b" "*cols) for _ in range(rows)]
    x = y = 0
    def newline():
        nonlocal x, y
        x = 0
        if y == rows-1:
            cells.pop(0)
            cells.append(bytearray(b" "*cols))
        else:
            y += 1
    def put(b):
        nonlocal x, y
        if b == 13: x = 0
        elif b == 10: newline()
        elif b == 8:
            if x: x -= 1
            elif y: y -= 1; x = cols-1
        elif b == 9:
            for _ in range(4-x%4): put(32)
        elif 32 <= b <= 126:
            if x == cols: newline()
            cells[y][x] = b
            x += 1
    start = list(re.finditer(rb"(?m)^AGENTOS MANAGER SESSION START PID=[0-9a-f]{16}\r\n", raw))
    require(len(start) == 1 and b"AGENTOS MANAGER SESSION STOP PID=" not in raw[start[0].end():], "Not a live TTY prefix")
    for b in raw[start[0].end():]: put(b)
    tiles = {c: tuple(b"".join(FG if dy < 7 and dx < 5 and g[dy] & (16>>dx) else BG
                             for dx in range(W)) for dy in range(H)) for c, g in glyphs.items()}
    scan = []
    for row, line in enumerate(cells):
        for dy in range(H):
            parts = [tiles[c][dy] for c in line]
            if dy == 7 and row == y and x < cols:
                parts[x] = CURSOR*5 + BG
            scan.append(b"".join(parts) + BG*(w%W))
    scan.append(BG*w*((h-TOP)%H))
    return b"".join(scan), [x, y]


def compare(data, baseline, expected, cursor):
    w, h, pixels = ppm(data)
    bw, bh, header = baseline
    require((w, h) == (bw, bh), "GOP geometry changed")
    actual = pixels[TOP*w*3:]
    require(len(actual) == len(expected), "Raster size differs")
    head = pixels[:TOP*w*3]
    exact = actual == expected
    mismatches = 0 if exact else sum(a != b or c != d or e != f for a,b,c,d,e,f in
        zip(actual[::3], expected[::3], actual[1::3], expected[1::3], actual[2::3], expected[2::3]))
    return {"exact": exact and head == header, "header_equal": head == header,
            "header_sha256": sha(head), "expected_sha256": sha(expected),
            "actual_sha256": sha(actual), "mismatched_pixels": mismatches,
            "compared_pixels": len(actual)//3, "cursor": cursor, "geometry": [w,h]}


def check_attempt(row, data, baseline, expected, cursor, stable, deadline):
    row["exact"] = False
    row["stable_prefix"] = stable
    if not stable:
        row["reason"] = "COM1 prefix or input changed"
        return row
    if row.get("fatal_qmp"):
        row["reason"] = "QMP screenshot failed"
        return row
    try:
        row.update(compare(data, baseline, expected, cursor))
    except ValueError as e:
        row["reason"] = str(e)
    if row["return_ns"] > deadline:
        row["exact"] = False
        row["reason"] = "QMP return after observation deadline"
    return row


def poll(capture, persist, deadline, now=time.monotonic_ns, sleep=time.sleep):
    attempts = []
    for i in range(MAX_ATTEMPTS):
        if now() >= deadline: break
        row = capture(i)
        attempts.append(row)
        persist(attempts, "exact" if row["exact"] else "pending")
        if row["exact"]: return attempts, "exact"
        if not row["stable_prefix"]: return attempts, "prefix-changed"
        if row.get("fatal_qmp"): return attempts, "qmp-error"
        if now() >= deadline: break
        sleep(min(PAUSE, max(0, (deadline-now())/1e9)))
    return attempts, "expired"


def validate(rows, size):
    offset, prev = 0, -1
    for at, length, before, after in rows:
        require(at == offset and length > 0 and prev <= before <= after, "Invalid monotonic byte coverage")
        offset += length
        prev = after
    require(offset == size, "Incomplete monotonic byte coverage")


def received(rows, offset):
    ends = [r[0]+r[1] for r in rows]
    i = bisect.bisect_right(ends, offset-1)
    require(offset > 0 and i < len(rows) and rows[i][0] < offset, "No RX timestamp for prefix")
    return rows[i][3]


class TimedSocket:
    def __init__(self, sock):
        self.sock = sock
        self.rx, self.tx = [], []
        self.r = self.t = 0
        self.overflow = False
    def __getattr__(self, name): return getattr(self.sock, name)
    def recv(self, *args, **kwargs):
        before = time.monotonic_ns()
        data = self.sock.recv(*args, **kwargs)
        after = time.monotonic_ns()
        if data:
            if len(self.rx) < CAP: self.rx.append((self.r,len(data),before,after))
            else: self.overflow = True
            self.r += len(data)
        return data
    def sendall(self, data, *args, **kwargs):
        before = time.monotonic_ns()
        self.sock.sendall(data, *args, **kwargs)
        after = time.monotonic_ns()
        if len(self.tx) < CAP: self.tx.append((self.t,len(data),before,after))
        else: self.overflow = True
        self.t += len(data)


def historical(path, glyphs):
    require(sha(path.read_bytes()) == OLD_SHA, "Wrong historical archive")
    with zipfile.ZipFile(path) as z:
        require(z.testzip() is None, "Historical CRC error")
        raw = z.read("check/"+FOLDER.name+"/com1.log")
        sent = z.read("check/"+FOLDER.name+"/com1-input.bin")
        timing = json.loads(z.read("console-observation/timing.json"))
        require(sha(raw) == timing["com1_sha256"] and sha(sent) == timing["input_sha256"], "Historical transcript hash mismatch")
        validate(timing["rx"], len(raw)); validate(timing["tx"], len(sent))
        w,h,pixels = ppm(z.read("check/"+FOLDER.name+"/shell-screen.ppm"))
        baseline = (w,h,pixels[:TOP*w*3])
        counts = []
        for cap in json.loads(z.read("console-observation/captures.json")):
            data = z.read(cap["file"].removeprefix("build/"))
            off = cap["com1_before"]
            require(sha(data) == cap["ppm_sha256"] and off == cap["com1_after"], "Historical frame integrity")
            exp, cursor = reference(raw[:off], w,h,glyphs)
            result = compare(data, baseline, exp, cursor)
            require(result["header_equal"], "Historical header mismatch")
            counts.append(result["mismatched_pixels"])
            print("historical", cap["file"], off, result["mismatched_pixels"],
                  round((cap["return_ns"]-received(timing["rx"], off))/1e6,3))
        require(counts == [0,0,0,15597,0,0,0,85764,0,0,0,0], "Historical pixel reproduction differs")
        # Actual old frames exercise malformed, mismatch, exact, changed header.
        off = 20740
        expected, cursor = reference(raw[:off],w,h,glyphs)
        wrong = z.read("console-observation/screen-02-0.ppm")
        exact = b"P6\n%d %d\n255\n"%(w,h)+baseline[2]+expected
        deadline = 10
        def attempt(data, stable=True, stamp=1):
            return check_attempt({"return_ns":stamp}, data, baseline, expected, cursor, stable, deadline)
        require(not attempt(b"")["exact"] and "reason" in attempt(b""), "Empty screenshot accepted")
        require(attempt(wrong)["mismatched_pixels"] == 15597 and not attempt(wrong)["exact"], "Mismatch accepted")
        require(attempt(exact)["exact"], "Exact synthetic test frame rejected")
        require(not attempt(exact,False)["exact"] and not attempt(exact,stamp=11)["exact"], "Unstable/late frame accepted")
        bad = bytearray(exact); bad[len(exact)-len(expected)-1] ^= 1
        require(not attempt(bytes(bad))["header_equal"], "Header alteration accepted")
        frames = [b"",wrong,exact]
        seen, status = poll(lambda i: attempt(frames[i]), lambda a,s:None,10,lambda:0,lambda _:None)
        require(status == "exact" and len(seen) == 3, "Poll failed to retain misses")
        seen,status = poll(lambda i: attempt(b""),lambda a,s:None,10,lambda:0,lambda _:None)
        require(status == "expired" and len(seen)==MAX_ATTEMPTS, "Empty-only poll did not expire")
        seen,status = poll(lambda i: attempt(wrong),lambda a,s:None,10,lambda:10,lambda _:None)
        require(status == "expired" and not seen, "Zero attempts did not expire")
    print("Local historical replay and poll tests PASS, 95 glyphs")


def run(glyphs):
    OUT.mkdir(parents=True,exist_ok=True)
    smoke = load("gop_smoke", "scripts/qemu-smoke.py")
    images = load("gop_images", "scripts/verify-supervisor-image.py")
    build = ROOT/"build"
    hashes = {p:sha((build/p).read_bytes()) for p in PAYLOADS}
    save(OUT/"payload-hashes.json",hashes)
    require(hashes == PAYLOADS, "Historical unsigned payload differs; refusing boot")
    identity = images.verify_identity(ROOT)
    save(OUT/"identity.json",identity)
    for signed,unsigned,cpio in [("agentos.efi","agentos.unsigned.efi","initramfs.cpio"),
            ("supervisor-staging/test.efi","supervisor-staging/test.unsigned.efi","supervisor-staging/test.cpio")]:
        sections = images.signed_payload((build/unsigned).read_bytes(),(build/signed).read_bytes())
        require(sections[".kernel"][1] == (build/"kernel.elf").read_bytes() and sections[".initrd"][1] == (build/cpio).read_bytes(), "Embedded payload mismatch")
    links, observations = [], []
    state = {}
    original_connect, original_wait, original_session = smoke.connect_uart, smoke.wait_session, smoke.run_session
    def connect(*args,**kwargs):
        require(not links,"Unexpected second UART")
        link=TimedSocket(original_connect(*args,**kwargs)); links.append(link); return link
    def session(process,capture,qmp,destination,*args,**kwargs):
        state["qmp"]=qmp
        w,h,pix=ppm((destination/"shell-screen.ppm").read_bytes())
        state["baseline"]=(w,h,pix[:TOP*w*3])
        return original_session(process,capture,qmp,destination,*args,**kwargs)
    def observe(process, serial, data, description):
        detected=time.monotonic_ns()
        obs={"description":description,"detected_ns":detected,"offset":len(data),"prefix_sha256":sha(data),"attempts":[],"status":"started"}
        observations.append(obs); save(OUT/"observations.json",observations)
        require(data.endswith(TARGETS[description]),"Target reply not at exact raw prefix end")
        input_file=serial.with_name("com1-input.bin")
        sent=input_file.read_bytes()
        require(sent.endswith((description+"\r").encode("ascii")),"Wrong transmitted target command")
        obs["input_offset"]=len(sent); obs["input_sha256"]=sha(sent)
        rx=received(links[0].rx,len(data)); obs["last_rx_ns"]=rx
        deadline=detected+LIMIT_NS; obs["deadline_ns"]=deadline
        baseline=state["baseline"]
        expected,cursor=reference(data,*baseline[:2],glyphs)
        def capture(i):
            path=OUT/f"screen-{len(observations)-1}-{i:02d}.ppm"
            before=serial.read_bytes(); ib=input_file.read_bytes()
            row={"file":path.name,"com1_before":len(before),"before_sha256":sha(before),"input_before":len(ib),"request_ns":time.monotonic_ns()}
            try:
                require(process.poll() is None,"QEMU stopped")
                state["qmp"].screenshot(path)
            except Exception as error:
                row["fatal_qmp"]=str(error)
            row["return_ns"]=time.monotonic_ns()
            after=serial.read_bytes(); ia=input_file.read_bytes()
            row.update(com1_after=len(after),after_sha256=sha(after),input_after=len(ia),
                       from_rx_request_ms=(row["request_ns"]-rx)/1e6,from_rx_return_ms=(row["return_ns"]-rx)/1e6)
            frame=path.read_bytes() if path.is_file() else b""
            row["ppm_sha256"]=sha(frame)
            return check_attempt(row,frame,baseline,expected,cursor,before==after==data and ib==ia==sent,deadline)
        def persist(attempts,status):
            obs.update(attempts=attempts,status=status); save(OUT/"observations.json",observations)
        attempts,status=poll(capture,persist,deadline)
        persist(attempts,status)
        print("GOP",description,json.dumps(obs,sort_keys=True),flush=True)
        require(status=="exact","GOP convergence failed: "+description+": "+status)
    def wait(process,capture,serial,predicate,description,seconds=30):
        data=original_wait(process,capture,serial,predicate,description,seconds)
        if description in TARGETS:
            observe(process,serial,data,description)
        return data
    smoke.connect_uart=connect; smoke.wait_session=wait; smoke.run_session=session
    sys.argv=["qemu-smoke.py","--cpus","2","--accel","kvm","--no-hpet","--session",
              "--runtime-process-regression","--supervisor-image","test","--ovmf-code","/usr/share/OVMF/OVMF_CODE_4M.secboot.fd",
              "--ovmf-vars","/usr/share/OVMF/OVMF_VARS_4M.fd","--timeout","180"]
    rc=1
    try:
        rc=smoke.main()
    finally:
        raw=(FOLDER/"com1.log").read_bytes() if (FOLDER/"com1.log").is_file() else b""
        sent=(FOLDER/"com1-input.bin").read_bytes() if (FOLDER/"com1-input.bin").is_file() else b""
        link=links[0] if links else None
        save(OUT/"timing.json",{"columns":["offset","length","before_ns","after_ns"],"clock":"time.monotonic_ns",
             "rx":link.rx if link else [],"tx":link.tx if link else [],"overflow":link.overflow if link else None,
             "com1_sha256":sha(raw),"input_sha256":sha(sent)})
        save(OUT/"observations.json",observations)
        save(OUT/"result.json",{"smoke_rc":rc,"observation_statuses":[o["status"] for o in observations]})
    require(link is not None and not link.overflow,"Missing timing")
    validate(link.rx,len(raw)); validate(link.tx,len(sent))
    if (FOLDER/"esp.raw").is_file():
        post=OUT/"postboot-bootx64.efi"
        subprocess.run(["mcopy","-i",str(FOLDER/"esp.raw")+"@@1048576","::EFI/BOOT/BOOTX64.EFI",str(post)],check=True)
        require(post.read_bytes()==(build/"supervisor-staging/test.efi").read_bytes()==(FOLDER/"esp-bootx64.efi").read_bytes(),"ESP signed EFI mismatch")
    require(raw.count(b"[INFO] SYSTEM CLOCK: ACPI PM24\r\n")==1,"Not actual PM24")
    for obs in observations:
        off=obs["offset"]
        require(sha(raw[:off])==obs["prefix_sha256"],"Recorded RX prefix differs")
        if "input_offset" not in obs or "last_rx_ns" not in obs:
            require(obs["status"]!="exact","Exact observation lacks anchors")
            continue
        txoff=obs["input_offset"]
        require(sha(sent[:txoff])==obs["input_sha256"],"Recorded TX prefix differs")
        require(received(link.rx,off)==obs["last_rx_ns"],"RX anchor changed")
        if obs["attempts"] and obs["status"]=="exact":
            first=obs["attempts"][-1]
            next_tx=next((r[2] for r in link.tx if r[0]==txoff),None)
            obs["next_tx_ns"]=next_tx
            require(next_tx is not None and next_tx>=first["return_ns"],"Next input not proven after first match")
    save(OUT/"observations.json",observations)
    require(rc==0 and [o["description"] for o in observations]==list(TARGETS) and all(o["status"]=="exact" for o in observations),"Smoke or convergence failed")
    receipt=json.loads((FOLDER/"smoke.json").read_text())
    require(receipt["result"]=="pass" and receipt["cpus"]==2 and receipt["accelerator"]=="kvm" and receipt["qmp_kvm"]["enabled"] and receipt["system_clock"]=="ACPI PM24" and not receipt["hpet_enabled"],"Incorrect smoke profile")
    save(OUT/"result.json",{"smoke_rc":rc,"observation_statuses":[o["status"] for o in observations],"payload_verified":True,"result":"pass"})
    return 0


if __name__=="__main__":
    if len(sys.argv)==4 and sys.argv[1]=="--local-test":
        historical(Path(sys.argv[2]),font(Path(sys.argv[3]).read_text()))
    else:
        require(len(sys.argv)==1,"Unexpected arguments")
        sys.exit(run(font((ROOT/"kernel/fb_console.rs").read_text())))
