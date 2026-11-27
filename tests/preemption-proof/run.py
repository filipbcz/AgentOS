"""One independently staged signed SMP timer-context proof per ordered profile."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import socket
import struct
import subprocess as sp
import sys
import time
import traceback
import zipfile

sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
ROOT=HERE.parent.parent
OUT=ROOT/"build"
DEST=OUT/"preemption-proof"
CPUS=0
CLIENT="preempt-runner"
CODE=Path("/usr/share/OVMF/OVMF_CODE_4M.secboot.fd")
VARS=Path("/usr/share/OVMF/OVMF_VARS_4M.fd")
ARM=b"run /preempt-runner\r"
KERNEL="ae7dbc731ea84e98a4559dfba0642271ca0c2970f508f47e29656446e31f746c"
CPIO="23974b23c3bad07110806c19f10e808495dfd7541846045c828cf71652dbab25"
PRIOR_ZIP=OUT/"preemption-proof-prior-2cpu.zip"
PRIOR_COMMIT="6acac8d9f9b1d397ebea91712b9479a700b1c34b"
PRIOR_TREE="34ac70974494d5fe3a88eef85c50158746bc0736"
PRIOR_ZIP_SHA="cae8759a2decfa6092ab3b5cc983d3c74d5f3780b67a366353ebd3168ef64f94"
PRIOR_RESULT_SHA="4a40184d784af6acc36f72b4cc4f5484666fe0e92ba174ff6fd473d9a23ae901"
PRIOR_TRACE_SHA="f62196a9fd167ccee2fa064e9634e2e48057a4afaa2ef345be9432c7e8a657c0"
PRIOR_COM1_SHA="19d116d6a8e3e9ecb35e919beb2b718b6f81b9a890d9183e5b353a65560914ca"
PRIOR_CLIENT_SHA="46ad9dd1b253614a5083c885774124f2ba43daeb4ef4575db290b011917a239c"
sys.path.insert(0,str(ROOT/"scripts"))
import proof
require=proof.require

def load(name):
    spec=importlib.util.spec_from_file_location(name,ROOT/"scripts"/name)
    module=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

def cmd(*args,**kw):
    return sp.run([str(x) for x in args],cwd=ROOT,check=True,**kw)

def capture(*args):
    return cmd(*args,stdout=sp.PIPE,text=True).stdout.strip()

def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()

def save(name,value):
    (DEST/name).write_text(json.dumps(value,sort_keys=True,indent=2)+"\n")

def symbols(path):
    result={}
    for line in capture("nm","-n",path).splitlines():
        fields=line.split()
        if len(fields)==3 and re.fullmatch("[0-9a-fA-F]+",fields[0]):
            result[fields[2]]=int(fields[0],16)
    return result


def startup_remaining(deadline, description):
    remaining=deadline-time.monotonic()
    if remaining<=0:
        raise TimeoutError(description)
    return remaining


def wait_uart_reader(process, uart, serial, deadline):
    """Wait for the real capture thread's file, not for fabricated data."""
    while True:
        remaining=startup_remaining(deadline,"COM1 reader startup deadline expired")
        if uart.error is not None:
            raise RuntimeError(f"UART capture stopped during startup: {uart.error}")
        if process.poll() is not None:
            raise RuntimeError(f"QEMU exited during COM1 startup: {process.returncode}")
        if not uart.worker.is_alive():
            raise RuntimeError("COM1 reader thread exited during startup")
        if serial.is_file():
            return dict(reader_ready=True,bytes_at_readiness=serial.stat().st_size,
                        observed_ns=time.monotonic_ns(),shell_ready_verified=False)
        time.sleep(min(.01,remaining))


def wait_initial_session(smoke, process, uart, serial, predicate, deadline, on_reader):
    on_reader(wait_uart_reader(process,uart,serial,deadline))
    log=smoke.wait_session(process,uart,serial,predicate,"ordinary shell",
                           startup_remaining(deadline,"Shell startup deadline expired"))
    startup_remaining(deadline,"Shell startup deadline expired")
    return log


def wait_debugger_ready(debugger, path, deadline, cpus=1):
    """The observer writes JSON non-atomically; existence is not readiness."""
    while True:
        remaining=startup_remaining(deadline,"Debugger did not arm before deadline")
        if debugger.poll() is not None:
            raise RuntimeError(f"Debugger exited before arming: {debugger.returncode}")
        try:
            ready=json.loads(path.read_text())
        except (FileNotFoundError,json.JSONDecodeError):
            time.sleep(min(.01,remaining))
            continue
        if not isinstance(ready,dict) or ready.get("hardware") is not True or ready.get("threads")!=cpus:
            raise ValueError("Invalid debugger readiness record")
        startup_remaining(deadline,"Debugger did not arm before deadline")
        if debugger.poll() is not None:
            raise RuntimeError(f"Debugger exited before arming: {debugger.returncode}")
        return ready

def inputs():
    paths=[OUT/"kernel.elf",OUT/"initramfs.cpio",OUT/"agentos.efi",OUT/"agentos.unsigned.efi",
           OUT/"build-provenance.json",OUT/"db.cer",DEST/CLIENT,DEST/"client.symbols.elf",
           DEST/"test.cpio",DEST/"test.unsigned.efi",DEST/"test.efi",DEST/"esp-bootx64.efi",
           DEST/"esp.raw",DEST/"OVMF_VARS.secboot.fd",CODE,VARS,
           HERE/"client.S",HERE/"run.py",HERE/"proof.py",HERE/"test-startup.py",
           ROOT/"scripts/qemu-smoke.py",DEST/"startup-host.json",PRIOR_ZIP,
           HERE/"test-failure.py",DEST/"failure-host.json",DEST/"baseline-client.elf",
           DEST/"baseline-client-disassembly.txt",DEST/"client-disassembly.txt"]
    return {str(x):sha(x) for x in paths}

def historical_two_proof():
    # Reuse the exact completed two-CPU artifact, not a reconstructed result
    # JSON or a new boot. Read and replay its actual bytes before every guest.
    digest=lambda data:hashlib.sha256(data).hexdigest()
    require(sha(PRIOR_ZIP)==PRIOR_ZIP_SHA,"Wrong archived 2 CPU ZIP")
    old_blob="350f83d57395fa63de5649447abfa9302c388d39"
    old_source=cmd("git","show",PRIOR_COMMIT+":tests/preemption-proof/proof.py",stdout=sp.PIPE).stdout
    require(hashlib.sha1(b"blob "+str(len(old_source)).encode()+b"\0"+old_source).hexdigest()==old_blob,
            "Wrong immutable historical IRQ verifier")
    historical_verifier={"__name__":"__historical_preemption__"}
    exec(compile(old_source,"historical-proof.py","exec"),historical_verifier)
    with zipfile.ZipFile(PRIOR_ZIP) as archive:
        names=archive.namelist()
        require(len(names)==len(set(names)) and archive.testzip() is None,"Invalid archived ZIP")
        matches=[n for n in names if n.endswith("preemption-proof-2cpu/preflight.json")]
        require(len(matches)==1,"Missing exact archived two-CPU preflight")
        prefix=matches[0][:-len("preflight.json")]
        product=prefix[:-len("preemption-proof-2cpu/")]
        def raw(name):
            return archive.read(prefix+name)
        def record(name):
            return json.loads(raw(name))
        require(archive.read(product+"kernel.elf")== (OUT/"kernel.elf").read_bytes() and
                archive.read(product+"initramfs.cpio")== (OUT/"initramfs.cpio").read_bytes() and
                sha(OUT/"kernel.elf")==KERNEL and sha(OUT/"initramfs.cpio")==CPIO,
                "Historical/current product bytes differ")
        receipt=record("preflight.json")
        result=record("result.json")
        request=record("trace-request.json")
        ready=record("trace-ready.json")
        trace=record("trace-result.json")
        arm=record("arm.json")
        log=raw("com1.log")
        trace_bytes=raw("irq-trace.jsonl")
        rows=[json.loads(line) for line in trace_bytes.splitlines()]
        require(digest(raw("result.json"))==PRIOR_RESULT_SHA and digest(trace_bytes)==PRIOR_TRACE_SHA and
                digest(log)==PRIOR_COM1_SHA and digest(raw(CLIENT))==PRIOR_CLIENT_SHA,
                "Wrong archived result/trace/UART/client bytes")
        require(receipt["result"]=="pass" and receipt["cpus"]==2 and receipt["commit"]==PRIOR_COMMIT and
                receipt["tree"]==PRIOR_TREE and receipt["guests"]==0 and
                result["result"]=="pass" and result["cpus"]==2 and result["commit"]==PRIOR_COMMIT and
                result["tree"]==PRIOR_TREE and result["guests"]==1 and result["shutdown"] is True and
                request["cpus"]==2 and request["windows"]==receipt["windows"] and
                request["runtime_bytes"]==receipt["runtime_bytes"] and
                request["qmp"]==record("qmp-roster.json") and trace["error"] is None and
                trace["complete"] is True and len(rows)==trace["stops"] and
                result["com1_sha256"]==digest(log) and result["trace_sha256"]==digest(trace_bytes) and
                result["trace"]==trace and arm["ready"]==ready and arm["command"]==ARM.hex() and
                ready["armed_ns"]<=arm["arm_ns"]<=arm["sent_ns"]==result["bounds"][0]<=result["bounds"][1] and
                result["chains"]==historical_verifier["verify_smp"](rows,request,ready,result["identities"],result["bounds"]) and
                result["chains"]==proof.verify_smp(rows,request,ready,result["identities"],result["bounds"]),
                "Archived two-CPU replay failed")
        # Check the original real UART lifecycle against the authenticated
        # trace identities. The pinned result also binds the original full
        # boot/process/orphan gates, which were already executed on this log.
        smoke=load("qemu-smoke.py")
        offset=arm["offset"]
        foreground=log[offset:]
        require(0<offset<len(log) and foreground.startswith(b"run /preempt-runner\r\n") and
                b"exit status 0\r\nagentos> " in foreground and raw("com1-input.bin")==ARM+b"exit\r" and
                log.endswith(b"[INFO] INTERACTIVE SHELL STOPPED\r\n") and
                b"FRAMES=OK" in foreground and smoke.session.SESSION_STOP.search(log) and
                int(smoke.session.SESSION_STOP.search(log)[1],16)==1,
                "Archived normal foreground/manager shutdown missing")
        require(set(result["identities"])==set(proof.smp_tags(2)),"Wrong archived worker set")
        def pid(mark):
            found=re.findall(rb"(?m)^"+mark+rb" PID=([0-9a-f]{16})\r$",foreground)
            require(len(found)==1,"Missing archived lifecycle "+str(mark))
            return int(found[0],16)
        root=pid(b"REG ROOT")
        require(root==result["root"] and root>result["shell"] and pid(b"REG COMPLETE")==root,
                "Archived root identity mismatch")
        for label,(worker,parent,cr3) in result["identities"].items():
            mark=b"REG "+label.encode()
            require(parent==root and pid(mark)==worker and all(pid(mark+b" "+v)==worker
                    for v in (b"BEGIN",b"OK",b"REAP")),"Archived worker identity mismatch")
            exits=[m for m in smoke.session.EXIT.finditer(foreground) if int(m[1],16)==worker]
            require(len(exits)==1 and int(exits[0][2],16)==cr3 and int(exits[0][3],16)==0 and
                    foreground.index(mark+b" BEGIN PID=")<foreground.index(mark+b" OK PID=")<exits[0].start()<
                    foreground.index(mark+b" REAP PID="),"Archived worker exit/reap mismatch")
        exits=[m for m in smoke.session.EXIT.finditer(foreground) if int(m[1],16)==root]
        require(len(exits)==1 and int(exits[0][3],16)==0 and
                foreground.index(b"REG COMPLETE PID=")<exits[0].start(),"Archived root exit mismatch")
        return dict(cpus=2,commit=PRIOR_COMMIT,tree=PRIOR_TREE,artifact=15236044308,
                    zip_sha256=sha(PRIOR_ZIP),result_sha256=digest(raw("result.json")),
                    trace_sha256=digest(trace_bytes),com1_sha256=digest(log),
                    kernel_sha256=sha(OUT/"kernel.elf"),cpio_sha256=sha(OUT/"initramfs.cpio"),
                    client_sha256=digest(raw(CLIENT)),stops=len(rows),
                    replayed_apics=sorted(result["chains"]),lifecycle=True,original_verifier_blob=old_blob)

def prior_proof():
    historical=historical_two_proof()
    if CPUS==4:
        return historical
    require(CPUS==8,"Only continuation profiles 4 and 8 are authorized")
    previous=4
    dest=OUT/f"preemption-proof-{previous}cpu"
    receipt=json.loads((dest/"preflight.json").read_text())
    result=json.loads((dest/"result.json").read_text())
    request=json.loads((dest/"trace-request.json").read_text())
    ready=json.loads((dest/"trace-ready.json").read_text())
    trace=json.loads((dest/"trace-result.json").read_text())
    rows=[json.loads(line) for line in (dest/"irq-trace.jsonl").read_text().splitlines()]
    require(receipt["result"]=="pass" and receipt["cpus"]==previous and
            receipt["commit"]==capture("git","rev-parse","HEAD") and
            receipt["prior_proof"]==historical and
            receipt["failure_host_sha256"]==sha(dest/"failure-host.json") and
            result["result"]=="pass" and result["cpus"]==previous and result["guests"]==1 and
            result["commit"]==receipt["commit"] and result["tree"]==receipt["tree"] and
            result["shutdown"] is True and request["cpus"]==previous and
            receipt["iterations"]==request["iterations"]==proof.SHORT_ITERATIONS and
            request["windows"]==receipt["windows"] and request["runtime_bytes"]==receipt["runtime_bytes"] and
            request["qmp"]==json.loads((dest/"qmp-roster.json").read_text()) and result["trace"]==trace and
            trace["error"] is None and trace["complete"] is True and len(rows)==trace["stops"] and
            result["com1_sha256"]==sha(dest/"com1.log") and
            result["trace_sha256"]==sha(dest/"irq-trace.jsonl") and
            result["chains"]==proof.verify_smp(rows,request,ready,result["identities"],result["bounds"]),
            "Previous 4 CPU profile has no complete raw proof")
    # Independently replay the normal lifecycle from the preceding actual
    # foreground log, not merely the observer's complete flag.
    smoke=load("qemu-smoke.py")
    log=(dest/"com1.log").read_bytes()
    arm=json.loads((dest/"arm.json").read_text())
    offset=arm["offset"]
    foreground=log[offset:]
    require(arm["ready"]==ready and arm["command"]==ARM.hex() and
            ready["armed_ns"]<=arm["arm_ns"]<=arm["sent_ns"]==result["bounds"][0]<=result["bounds"][1] and
            0<offset<len(log) and foreground.startswith(b"run /preempt-runner\r\n") and
            b"exit status 0\r\nagentos> " in foreground and (dest/"com1-input.bin").read_bytes()==ARM+b"exit\r" and
            log.endswith(b"[INFO] INTERACTIVE SHELL STOPPED\r\n") and
            b"FRAMES=OK" in foreground and smoke.session.SESSION_STOP.search(log) and
            int(smoke.session.SESSION_STOP.search(log)[1],16)==1,
            "Previous 4 CPU normal foreground/manager shutdown missing")
    def pid(mark):
        found=re.findall(rb"(?m)^"+mark+rb" PID=([0-9a-f]{16})\r$",foreground)
        require(len(found)==1,"Missing previous lifecycle "+str(mark))
        return int(found[0],16)
    root=pid(b"REG ROOT")
    earlier={int(m[1],16) for m in smoke.session.EXIT.finditer(log[:offset])}
    ids=result["identities"]
    require(root==result["root"] and root>result["shell"] and root not in earlier and
            pid(b"REG COMPLETE")==root and set(ids)==set(proof.smp_tags(previous)) and
            len({v[0] for v in ids.values()})==len(ids) and len({v[2] for v in ids.values()})==len(ids),
            "Previous 4 CPU root/worker identities differ")
    for label,(worker,parent,cr3) in ids.items():
        mark=b"REG "+label.encode()
        require(worker>root and worker not in earlier and parent==root and pid(mark)==worker and
                all(pid(mark+b" "+v)==worker for v in (b"BEGIN",b"OK",b"REAP")),
                "Previous 4 CPU worker lifecycle missing")
        exits=[m for m in smoke.session.EXIT.finditer(foreground) if int(m[1],16)==worker]
        require(len(exits)==1 and int(exits[0][2],16)==cr3 and int(exits[0][3],16)==0 and
                foreground.index(mark+b" BEGIN PID=")<foreground.index(mark+b" OK PID=")<exits[0].start()<
                foreground.index(mark+b" REAP PID="),"Previous 4 CPU worker exit/reap mismatch")
    exits=[m for m in smoke.session.EXIT.finditer(foreground) if int(m[1],16)==root]
    require(len(exits)==1 and int(exits[0][3],16)==0 and
            foreground.index(b"REG COMPLETE PID=")<exits[0].start(),"Previous 4 CPU root exit mismatch")
    smoke.boot_log.verify(log,"info","both",physical_oom_dir=dest,source_commit=receipt["commit"])
    apics=smoke.session.bootCpuRoster(log[:offset],previous,aBasicSmp=True)
    smoke.processes.verify(log.decode("ascii"),sorted(apics),ipc_staged=True,root_orphan_v1=True,require_shutdown=True)
    smoke.orphans.verify(log.decode("ascii"),previous,basic_smp=True)
    return {"cpus":previous,"result_sha256":sha(dest/"result.json"),
            "trace_sha256":sha(dest/"irq-trace.jsonl"),"com1_sha256":sha(dest/"com1.log"),
            "replayed_apics":sorted(result["chains"]),"lifecycle":True,"historical_two":historical}

def preflight():
    require(not DEST.exists(),"Stale proof directory; no repeat")
    DEST.mkdir(parents=True)
    receipt={"result":"fail","guests":0,"stage":"source","cpus":CPUS,"workers":CPUS*2}
    try:
        commit=capture("git","rev-parse","HEAD")
        tree=capture("git","rev-parse","HEAD^{tree}")
        receipt.update(commit=commit,tree=tree)
        receipt["stage"]="prior_profile"
        receipt["prior_proof"]=prior_proof()
        require(not capture("git","status","--porcelain","--untracked-files=normal"),"Dirty checkout")
        receipt["stage"]="verifier"
        receipt["selftest"]=capture(sys.executable,HERE/"proof.py")
        require("PREEMPTION VERIFIER POSITIVE + 13 NEGATIVE OK" in receipt["selftest"] and
                "SMP VERIFIER POSITIVE + 9 NEGATIVE OK" in receipt["selftest"] and
                all(f"SHORT WINDOW VERIFIER {n} CPU POSITIVE + 3 NEGATIVE OK" in receipt["selftest"] for n in (4,8)),
                "Missing verifier test")
        print(receipt["selftest"],flush=True)
        receipt["stage"]="startup_host"
        cmd(sys.executable,HERE/"test-startup.py","--receipt",DEST/"startup-host.json")
        startup_host=json.loads((DEST/"startup-host.json").read_text())
        require(startup_host["result"]=="pass" and startup_host["guest_runs"]==0 and
                startup_host["sources"]=={"runner":sha(HERE/"run.py"),"smoke":sha(ROOT/"scripts/qemu-smoke.py"),
                                          "test":sha(HERE/"test-startup.py")} and
                set(startup_host["cases"])=={"old_uart_failure","delayed_uart_and_read","dead_process",
                    "reader_exception","missing_file_timeout","empty_file_not_ready","empty_file_reader",
                    "old_debugger_failure","delayed_debugger_record","debugger_timeout","debugger_death"},
                "Missing exact successful startup host regression")
        receipt["startup_host_sha256"]=sha(DEST/"startup-host.json")
        receipt["stage"]="tools"
        for name in ("gcc-13","ld","nm","objdump","objcopy","qemu-system-x86_64","gdb","mcopy",
                     "sgdisk","mformat","mmd","sbsign","sbverify","openssl","virt-fw-vars"):
            require(shutil.which(name),"Missing "+name)
        receipt["gdb"]=capture("gdb","-nx","-nh","-batch","-ex",
            "python import gdb, struct, json, time; assert hasattr(gdb.Inferior,'read_memory') and hasattr(gdb,'BP_HARDWARE_BREAKPOINT') and hasattr(gdb.InferiorThread,'switch') and hasattr(gdb.InferiorThread,'ptid'); print('GDB_API_OK')")
        require("GDB_API_OK" in receipt["gdb"],"GDB API preflight failed")
        receipt["qemu"]=capture("qemu-system-x86_64","--version")
        images=load("verify-supervisor-image.py")
        basic=load("verify-basic-smp.py")
        receipt["stage"]="exact_kernel"
        receipt["control"]=basic.verify_image(ROOT,OUT/"agentos.efi",commit)
        require(sha(OUT/"kernel.elf")==KERNEL and sha(OUT/"initramfs.cpio")==CPIO,"Wrong pinned product")
        ks=symbols(OUT/"kernel.elf")
        required={"timer_gate":0x12c,"timer_interrupt":0xa050,"restore_context":0x2b6,
          "finish_context_switch":0xb560,
          "_ZN4main3smp3Cpu6switch17hb7417c7cd214c040E":0x7e00,
          "_ZN4main9scheduler5Queue6select17h8bfd68f42f547138E":0x20cb0,
          "_ZN4main3smp5gCpus17h5763cf52e37c3718E":0x424c0,
          "_ZN4main3smp15gRuntimeEnabled17he397e046ee5837a0E.0":0x42cc0,
          "_ZN4main3smp12gOnlineCount17he11f3f5949bf833aE.0":0x42cd0}
        require(all(ks.get(k)==v for k,v in required.items()),"Pinned symbols changed")
        kernel=(OUT/"kernel.elf").read_bytes()
        require(kernel[0x1186:0x1190].hex()=="e8c59e0000e926010000" and
                kernel[0x1000+0x20dca:0x1000+0x20dd1].hex()=="48ff86c0000000",
                "Wrong timer return/preemption increment instruction")
        require(kernel[0x115c:0x115f].hex()=="0f01f8" and
                kernel[0x1000+0xa05a:0x1000+0xa063].hex()=="65488b3c2500000000",
                "Wrong timer SWAPGS / CPU GS load")
        receipt["kernel_symbols"]=required
        receipt["runtime_bytes"]={str(offset):kernel[0x1000+offset:0x1000+offset+size].hex()
            for offset,size in ((0x155,11),(0x17e,18),(0xa050,36),(0xa2b3,26),(0x20db0,49),(0x2b6,16),(0x84ee,8))}
        receipt["stage"]="client"
        cmd("gcc-13",f"-DPREEMPT_CPUS={CPUS}","-c",HERE/"client.S","-o",DEST/"entry.o")
        cmd("ld","--no-undefined","--build-id=none","-z","noexecstack","-T",ROOT/"user/user.ld",
            "-o",DEST/"client.symbols.elf",DEST/"entry.o")
        cmd("objcopy","--strip-all",DEST/"client.symbols.elf",DEST/CLIENT)
        elf=(DEST/CLIENT).read_bytes()
        load("verify-user-abi.py").verify(elf)
        user=symbols(DEST/"client.symbols.elf")
        windows={}
        tags=proof.smp_tags(CPUS)
        iterations=proof.smp_iterations(dict(cpus=CPUS,iterations=proof.SHORT_ITERATIONS))
        receipt["iterations"]=iterations
        require(set(name for name in user if name.startswith("window_"))==
                {"window_"+label+"_"+end for label in tags for end in ("begin","end")},
                "Unexpected actual compiled worker windows")
        for label,(a,b) in tags.items():
            lo,hi=(user["window_"+label+"_"+end] for end in ("begin","end"))
            require(hi-lo==7 and lo//4096==(hi-1)//4096,"Unexpected bounded loop")
            off=0x1000+lo-0x8000400000
            require(elf[off:off+7].hex()=="f39048ffc975f9","Unexpected loop instructions")
            setup=(bytes.fromhex("49ba")+struct.pack("<Q",a)+bytes.fromhex("49be")+struct.pack("<Q",b)+
                   bytes.fromhex("66490f6ec266490f6ece660f6cc1664d0f6efe66490f6eca66440f6cf9b9")+
                   struct.pack("<I",iterations))
            require(elf[off-len(setup):off]==setup,"Wrong actual GPR/XMM sentinel setup "+label)
            windows[label]=[lo,lo+2,lo+5]
        require(len({pc for pcs in windows.values() for pc in pcs})==3*len(tags),"Worker windows overlap")
        receipt["tags"]=tags
        receipt["windows"]=windows
        (DEST/"client-disassembly.txt").write_text(capture("objdump","-d","-Mintel",DEST/"client.symbols.elf")+"\n")
        receipt["stage"]="failure_host"
        cmd(sys.executable,HERE/"test-failure.py","--cpus",CPUS,"--elf",DEST/"client.symbols.elf",
            "--receipt",DEST/"failure-host.json",timeout=120)
        failure=json.loads((DEST/"failure-host.json").read_text())
        cases={"unchanged_success","root_pid","initial_clock","last_spawn_clock","last_spawn_deadline",
               "last_fork","last_yield","last_retry_yield","post_clock","post_deadline","first_wait_errno",
               "first_wait_status","try_wait","final_child_check","diagnostic_write_errno","diagnostic_write_short",
               "root_report","last_spawn_report","reap_report","complete_report","worker_clock","worker_yield",
               "worker_begin_report","worker_r10_sentinel"}
        require(failure["result"]=="pass" and failure["guests"]==0 and failure["cpus"]==CPUS and
                failure["baseline_blob"]=="17f5bbda2a659dc127fa2c172d08c635b7263607" and
                failure["baseline_sha256"]==sha(DEST/"baseline-client.elf") and
                failure["actual_sha256"]==sha(DEST/"client.symbols.elf") and
                failure["source_sha256"]==sha(HERE/"client.S") and
                failure["test_sha256"]==sha(HERE/"test-failure.py") and set(failure["cases"])==cases and
                failure["cases"]["unchanged_success"]["status"]==0 and
                all(old==new for old,new in failure["disassembly"]["windows"].values()),
                "Missing successful exact diagnostic host execution/disassembly")
        identity=failure["workload_identity"]
        require(identity["parent_blob"]=="b16abb4394a894990654bf959cbc2fdcba770af0" and
                identity["old_iterations"]==proof.ITERATIONS and identity["new_iterations"]==iterations and
                identity["actual_sha256"]==sha(DEST/CLIENT) and identity["historical_two_sha256"]==PRIOR_CLIENT_SHA and
                set(identity["exact_immediate_offsets"])=={"window_"+label+"_begin" for label in tags} and
                set(identity["unchanged"])=={"1","2"} and
                all(v["parent_sha256"]==v["current_sha256"] for v in identity["unchanged"].values()),
                "Missing exact workload/unchanged 1/2 CPU identity")
        receipt["workload_identity"]=identity
        receipt["failure_host_sha256"]=sha(DEST/"failure-host.json")
        receipt["stage"]="signed_stage"
        # Reuse the independently verified loader object/layout from the
        # existing host staging build, but add only this executable to the
        # untouched ordinary archive. No alternate production kernel.
        stage=OUT/"supervisor-staging"
        receipt["existing_pair"]=images.verify_identity(ROOT)
        archive=(OUT/"initramfs.cpio").read_bytes()
        original=images.verify_distribution(archive)
        def encode(name,fields,data):
            name=name.encode("ascii")+b"\0"
            fields=list(fields); fields[6]=len(data); fields[11]=len(name)
            record=b"070701"+b"".join(f"{n:08x}".encode() for n in fields)+name
            record+=bytes((-len(record))%4)+data
            return record+bytes((-len(record))%4)
        ino=max(f[0] for f,_ in original.values())+1
        extra=encode(CLIENT,(ino,0o100755,0,0,1,0,0,0,0,0,0,0,0),elf)
        trailer=encode("TRAILER!!!",(0,0,0,0,1,0,0,0,0,0,0,0,0),b"")
        test_cpio=b"".join(encode(n,f,p) for n,(f,p) in original.items())+extra+trailer
        (DEST/"test.cpio").write_bytes(test_cpio)
        added=images.cpio_entries(test_cpio)
        require(set(added)==set(original)|{CLIENT} and all(added[k]==v for k,v in original.items()) and
                added[CLIENT][1]==elf,"Separate archive changed distribution")
        for name in ("loader.o","layout.ld"):
            shutil.copyfile(stage/name,DEST/name)
        shutil.copyfile(OUT/"kernel.elf",DEST/"kernel.elf")
        for name,cpio in (("control.relinked",archive),("test.unsigned",test_cpio)):
            (DEST/"initramfs.cpio").write_bytes(cpio)
            images.command(DEST,"gcc-13","-c",str(ROOT/"boot/payload.S"),"-o","payload.o")
            images.command(DEST,"ld","-nostdlib","--build-id=none","-znocombreloc","-T","layout.ld",
                "-shared","-Bsymbolic","/usr/lib/crt0-efi-x86_64.o","loader.o","payload.o",
                "-L/usr/lib","-lefi","-lgnuefi","-o","loader.so")
            options=[arg for sec in images.SECTIONS for arg in ("-j",sec)]
            images.command(DEST,"objcopy","--strip-all",*options,"--target=efi-app-x86_64","loader.so",name+".efi")
        require(sha(DEST/"control.relinked.efi")==sha(OUT/"agentos.unsigned.efi"),"Loader relink mismatch")
        keys=Path.home()/".local/share/agentos/stage1-test-keys"
        cert=keys/"db.crt"
        cmd("sbsign","--key",keys/"db.key","--cert",cert,"--output",DEST/"test.efi",DEST/"test.unsigned.efi")
        cmd("sbverify","--cert",cert,DEST/"test.efi")
        sections=images.signed_payload((DEST/"test.unsigned.efi").read_bytes(),(DEST/"test.efi").read_bytes())
        require(sections[".kernel"][1]==kernel and sections[".initrd"][1]==test_cpio,"Wrong signed payload")
        receipt["stage"]="esp_and_dependencies"
        cmd("bash","scripts/disk.sh",DEST,DEST/"test.efi","info both")
        cmd("mcopy","-i",str(DEST/"esp.raw")+"@@1048576","::EFI/BOOT/BOOTX64.EFI",DEST/"esp-bootx64.efi")
        require(sha(DEST/"esp-bootx64.efi")==sha(DEST/"test.efi"),"Wrong ESP image")
        owner="d7663630-f07a-4739-bc6f-b9f6d6444865"
        cmd("virt-fw-vars","--input",VARS,"--output",DEST/"OVMF_VARS.secboot.fd",
            "--set-pk",owner,cert,"--add-kek",owner,cert,"--add-db",owner,cert,"--secure-boot")
        require((OUT/"db.cer").read_bytes() in (DEST/"OVMF_VARS.secboot.fd").read_bytes(),"Missing signing db")
        (DEST/"secureboot-vars.txt").write_text(capture("virt-fw-vars","--input",DEST/"OVMF_VARS.secboot.fd","--print","--verbose"))
        # Real existing host proof is required by the unchanged boot-log verifier.
        load("physical_oom_evidence.py").run(ROOT,DEST,commit)
        receipt["arm"]=ARM.hex()
        receipt["inputs"]=inputs()
        receipt.update(stage="complete",result="pass")
    except Exception as exc:
        receipt["error"]=repr(exc)
        receipt["traceback"]=traceback.format_exc()
    finally:
        save("preflight.json",receipt)
        print("PREEMPTION PREFLIGHT",receipt["result"],receipt["stage"],receipt.get("error",""),flush=True)
    return int(receipt["result"]!="pass")

def guest():
    receipt=json.loads((DEST/"preflight.json").read_text())
    require(receipt.get("result")=="pass" and receipt.get("guests")==0 and receipt["cpus"]==CPUS and
            receipt["iterations"]==proof.smp_iterations(dict(cpus=CPUS,iterations=proof.SHORT_ITERATIONS)) and
            receipt["prior_proof"]==prior_proof() and
            receipt["commit"]==capture("git","rev-parse","HEAD") and receipt["inputs"]==inputs() and
            receipt["arm"]==ARM.hex() and receipt["startup_host_sha256"]==sha(DEST/"startup-host.json") and
            receipt["failure_host_sha256"]==sha(DEST/"failure-host.json"),
            "Missing/stale successful preflight")
    require(not (DEST/"guest-start.json").exists(),"Second guest forbidden")
    smoke=load("qemu-smoke.py")
    basic=load("verify-basic-smp.py")
    serial=DEST/"com1.log"
    sock=DEST/"uart.sock"
    monitor=DEST/"monitor.sock"
    qmp_sock=DEST/"qmp.sock"
    with socket.socket() as temp:
        temp.bind(("127.0.0.1",0))
        port=temp.getsockname()[1]
    qemu=["qemu-system-x86_64","-machine","q35,accel=tcg,smm=on,hpet=on","-cpu","max","-smp",str(CPUS),"-m","256",
          "-global","driver=cfi.pflash01,property=secure,value=on",
          "-drive",f"if=pflash,format=raw,unit=0,readonly=on,file={CODE}",
          "-drive",f"if=pflash,format=raw,unit=1,file={DEST/'OVMF_VARS.secboot.fd'}",
          "-drive",f"if=none,format=raw,id=esp,file={DEST/'esp.raw'}",
          "-device","ich9-ahci,id=sata","-device","ide-hd,drive=esp,bus=sata.0",
          "-monitor",f"unix:{monitor},server=on,wait=off",
          "-qmp",f"unix:{qmp_sock},server=on,wait=off","-vga","std","-display","none",
          "-chardev",f"socket,id=uart,path={sock},server=on,wait=on","-serial","chardev:uart",
          "-nic","none","-boot","order=c","-no-reboot","-no-shutdown","-gdb",f"tcp:127.0.0.1:{port}"]
    save("guest-start.json",dict(guests=1,cpus=CPUS,command=qemu,host_ns=time.monotonic_ns()))
    result={"result":"fail","guests":1,"cpus":CPUS,"commit":receipt["commit"],"tree":receipt["tree"]}
    process=debugger=uart=qmp=None
    stderr=(DEST/"qemu-stderr.log").open("wb")
    dbglog=(DEST/"gdb.log").open("wb")
    try:
        boot_deadline=time.monotonic()+180
        process=sp.Popen(qemu,cwd=ROOT,stdin=sp.DEVNULL,stdout=stderr,stderr=sp.STDOUT)
        uart=smoke.UartCapture(smoke.connect_uart(sock,process),serial)
        def wait(predicate,description,seconds=60):
            return smoke.wait_session(process,uart,serial,predicate,description,seconds)
        startup={}
        def on_reader(record):
            startup.update(record,boot_deadline_ns=int(boot_deadline*1e9))
            save("uart-startup.json",startup)
        log=wait_initial_session(smoke,process,uart,serial,
            lambda d:b"AGENTOS SHELL READY\r\nagentos> " in d,boot_deadline,on_reader)
        startup.update(shell_ready_verified=True,shell_ready_ns=time.monotonic_ns(),shell_ready_bytes=len(log))
        save("uart-startup.json",startup)
        bases=re.findall(rb"(?m)^\[INFO\] KERNEL IMAGE BASE=([0-9a-f]{16})\r?$",log)
        shells=list(smoke.session.SHELL_START.finditer(log))
        require(len(bases)==len(shells)==1 and re.search(rb"SYSTEM CLOCK: HPET(?:64|32)",log),"Wrong boot/base/shell")
        base=int(bases[0],16)
        shell=int(shells[0][1],16)
        qmp=smoke.Qmp(qmp_sock)
        kvm=qmp.execute("query-kvm")
        require(not kvm["enabled"],"Unexpected KVM")
        actual=qmp.execute("query-cpus-fast")
        for cpu in actual:
            cpu["apic-id"]=qmp.execute("qom-get",{"path":cpu["qom-path"],"property":"apic-id"})
        qmp_record={"accelerator":"tcg","kvm":kvm,"cpus":actual}
        actual_apics=set(proof.qmp_roster(qmp_record,CPUS).values())
        save("qmp-roster.json",qmp_record)
        apics=smoke.session.bootCpuRoster(log,CPUS,aBasicSmp=CPUS in (4,8))
        require(apics==actual_apics,"QOM/COM1 APIC mismatch")
        qmp.screenshot(DEST/"shell-screen.ppm")
        smoke.console.verify(DEST/"shell-screen.ppm",aLevel="info",aOutput="both")
        request=dict(base=base,cpus=CPUS,iterations=receipt["iterations"],qmp=qmp_record,
                     windows=receipt["windows"],runtime_bytes=receipt["runtime_bytes"],
                     destination=str(DEST))
        save("trace-request.json",request)
        environment=dict(os.environ,AGENTOS_PREEMPT_REQUEST=str(DEST/"trace-request.json"))
        expression="exec(compile(open("+repr(str(HERE/"proof.py"))+").read(), 'proof.py', 'exec'), {'__name__':'__preemption_gdb__'})"
        debugger=sp.Popen(["gdb","-nx","-nh","-batch","-ex","set pagination off","-ex","set non-stop off","-ex","set architecture i386:x86-64",
                           "-ex",f"target remote 127.0.0.1:{port}","-ex","python "+expression],
                          cwd=ROOT,env=environment,stdout=dbglog,stderr=sp.STDOUT)
        ready=wait_debugger_ready(debugger,DEST/"trace-ready.json",time.monotonic()+20,CPUS)
        proof.bind_roster(request,ready)
        require(0<ready["armed_ns"]<=time.monotonic_ns(),"Wrong debugger readiness time")
        offset=serial.stat().st_size
        arm_ns=time.monotonic_ns()
        uart.send(ARM)
        sent_ns=time.monotonic_ns()
        save("arm.json",dict(ready=ready,arm_ns=arm_ns,sent_ns=sent_ns,offset=offset,command=ARM.hex()))
        log=wait(lambda d:b"exit status 0\r\nagentos> " in d[offset:] or
                          re.search(rb"exit status [1-9][0-9]*\r\nagentos> ",d[offset:]),"preemption foreground",120)
        finish_ns=time.monotonic_ns()
        (DEST/"stop-trace").touch()
        debugger_status=debugger.wait(timeout=15)
        # Finish the normal shell/manager lifecycle even if the separate proof fails.
        uart.send(b"exit\r")
        log=wait(lambda d:smoke.session.SESSION_STOP.search(d) and
                          d.endswith(b"[INFO] INTERACTIVE SHELL STOPPED\r\n"),"PID1 frame-clean shutdown",45)
        result["shutdown"]=True
        require(debugger_status==0,"Debugger failed")
        trace=json.loads((DEST/"trace-result.json").read_text())
        require(trace["error"] is None,"Debugger incomplete")
        raw=log[offset:]
        require(raw.startswith(b"run /preempt-runner\r\n") and
                b"exit status 0\r\nagentos> " in raw and
                (DEST/"com1-input.bin").read_bytes()==ARM+b"exit\r","Wrong foreground exchange")
        def pid(mark):
            found=re.findall(rb"(?m)^"+mark+rb" PID=([0-9a-f]{16})\r$",raw)
            require(len(found)==1,"Missing/duplicate marker "+str(mark))
            return int(found[0],16)
        root=pid(b"REG ROOT")
        require(root>shell and pid(b"REG COMPLETE")==root,"Wrong root")
        ids={}
        prior={int(m[1],16) for m in smoke.session.EXIT.finditer(log[:offset])}
        for label in proof.smp_tags(CPUS):
            mark=b"REG "+label.encode()
            worker=pid(mark)
            require(worker>root and worker not in prior and all(pid(mark+b" "+v)==worker
                    for v in (b"BEGIN",b"OK",b"REAP")),"Wrong worker lifecycle")
            matches=[m for m in smoke.session.EXIT.finditer(raw) if int(m[1],16)==worker]
            require(len(matches)==1 and int(matches[0][3],16)==0,"Missing real worker exit")
            require(raw.index(mark+b" BEGIN PID=")<raw.index(mark+b" OK PID=")<matches[0].start()<
                    raw.index(mark+b" REAP PID="),"Wrong worker completion order")
            ids[label]=(worker,root,int(matches[0][2],16))
        root_exit=[m for m in smoke.session.EXIT.finditer(raw) if int(m[1],16)==root]
        require(len(root_exit)==1 and int(root_exit[0][3],16)==0 and
                raw.index(b"REG COMPLETE PID=")<root_exit[0].start(),"Missing root completion")
        require(len(ids)==CPUS*2 and len({v[0] for v in ids.values()})==len(ids) and
                len({v[2] for v in ids.values()})==len(ids) and root not in prior,
                "Aliased or reused identity")
        require(int(smoke.session.SESSION_STOP.search(log)[1],16)==1,"Wrong reaper shutdown")
        smoke.boot_log.verify(log,"info","both",physical_oom_dir=DEST,source_commit=receipt["commit"])
        smoke.processes.verify(log.decode("ascii"),sorted(apics),ipc_staged=True,root_orphan_v1=True,require_shutdown=True)
        smoke.orphans.verify(log.decode("ascii"),CPUS,basic_smp=CPUS in (4,8))
        rows=[json.loads(l) for l in (DEST/"irq-trace.jsonl").read_text().splitlines()]
        require(len(rows)==trace["stops"] and ready["armed_ns"]<=arm_ns<=sent_ns<=finish_ns,"Invalid trace bounds")
        chains=proof.verify_smp(rows,request,ready,ids,(sent_ns,finish_ns))
        require(trace["complete"] is True,"Observer did not complete all APICs")
        result.update(result="pass",iterations=receipt["iterations"],identities=ids,chains=chains,trace=trace,
                      bounds=[sent_ns,finish_ns],shell=shell,root=root,shutdown=True,
                      com1_sha256=sha(serial),trace_sha256=sha(DEST/"irq-trace.jsonl"))
    except Exception as exc:
        result.update(error=repr(exc),traceback=traceback.format_exc())
    finally:
        if qmp is not None:
            qmp.close()
        if debugger is not None and debugger.poll() is None:
            debugger.kill(); debugger.wait()
        if uart is not None:
            uart.close()
        if process is not None and process.poll() is None:
            process.terminate()
            try: process.wait(timeout=10)
            except sp.TimeoutExpired: process.kill(); process.wait()
        stderr.close(); dbglog.close()
        save("result.json",result)
        print("PREEMPTION GUEST",result["result"],result.get("error",""),flush=True)
    return int(result["result"]!="pass")

if __name__=="__main__":
    require(len(sys.argv)==3 and sys.argv[1] in ("--preflight","--guest") and
            sys.argv[2] in ("4","8"),"Explicit continuation phase and 4/8 profile required")
    CPUS=int(sys.argv[2])
    DEST=OUT/f"preemption-proof-{CPUS}cpu"
    raise SystemExit(preflight() if sys.argv[1]=="--preflight" else guest())
