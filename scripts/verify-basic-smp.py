"""Independent host evidence for ordinary signed QEMU 4/8 CPU sessions."""
import hashlib
import importlib.util
import os
from pathlib import Path
import re
import subprocess
import sys

sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parent.parent
HEX=r"([0-9a-f]{16})"
TASK=re.compile(r"AGENTOS TASK (BSP|AP) APIC="+HEX+r" TIMER-WAKES="+HEX)
SCHED=re.compile(r"AGENTOS SCHED APIC="+HEX+r" TASK="+HEX+r" PREEMPTIONS="+HEX+r" PAGES="+HEX)
FRAME=re.compile(r"AGENTOS FRAME STRESS BITMAP OK HELD="+HEX+r" FREE-BEFORE="+HEX+r" FREE-AFTER="+HEX)
OOM=re.compile(r"AGENTOS OOM OK DRAINED="+HEX+r" REJECT-CPUS="+HEX+r" RESTORED="+HEX)
IDLE_BEGIN=re.compile(r"AGENTOS IDLE BEGIN TSC-HZ="+HEX)
IDLE=re.compile(r"AGENTOS IDLE APIC="+HEX+r" WAKES="+HEX+r" TIMERS="+HEX+r" TSC-TOTAL="+HEX+r" TSC-ACTIVE="+HEX)

class VerificationError(ValueError):
    pass

def require(ok,message):
    if not ok:
        raise VerificationError(message)

def load(name):
    spec=importlib.util.spec_from_file_location("basicSmp_"+name,ROOT/"scripts"/name)
    module=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

def host_capacity():
    # Record the real process affinity and the cgroup v2 quota. They bound
    # CPU supply; neither describes guest APIC IDs or simultaneous execution.
    affinity=sorted(os.sched_getaffinity(0))
    require(affinity,"Missing host CPU affinity")
    group=Path("/sys/fs/cgroup")
    entries=Path("/proc/self/cgroup").read_text().splitlines()
    v2=[row[3:] for row in entries if row.startswith("0::")]
    require(len(v2)==1,"Expected actual cgroup v2 CPU accounting")
    leaf=group/v2[0].lstrip("/")
    require(leaf.is_dir(),"Missing actual cgroup directory")
    # The root cgroup or a controller-disabled subtree need not expose cpu.max.
    # Read all visible ancestors; an absent file imposes no visible quota.
    quotas=[]
    for path in (leaf,*leaf.parents):
        if not path.is_relative_to(group):
            break
        quota=path/"cpu.max"
        if quota.is_file():
            raw=quota.read_text().strip()
            amount,period=raw.split()
            require(int(period)>0 and (amount=="max" or int(amount)>0),"Invalid CPU quota")
            quotas.append({"path":str(quota),"value":raw})
    capacity=min([float(len(affinity))]+[int(v["value"].split()[0])/int(v["value"].split()[1])
        for v in quotas if not v["value"].startswith("max ")])
    return {"logical_cpus":os.cpu_count(),"affinity":affinity,"affinity_count":len(affinity),
            "cgroup_v2_path":v2[0],"cpu_quotas":quotas,"effective_cpu_capacity":capacity,
            "lscpu":subprocess.check_output(["lscpu"],text=True)}

def qmp_ids(record,cpus):
    require(cpus in (4,8),"Invalid basic SMP CPU count")
    require(record["kvm"]["enabled"] is False and record["accelerator"]=="tcg",
            "Unexpected actual accelerator")
    actual=record["cpus"]
    require(len(actual)==cpus and all(type(c["cpu-index"]) is int and
            type(c["thread-id"]) is int and c["thread-id"]>0 and
            c["target"]=="x86_64" and isinstance(c["qom-path"],str) and c["qom-path"] for c in actual),
            "Missing live QMP vCPU identities")
    require(len({c["cpu-index"] for c in actual})==len({c["thread-id"] for c in actual})==
            len({c["qom-path"] for c in actual})==cpus,"Repeated QMP vCPU identity")
    ids=[c["apic-id"] for c in actual]
    require(all(type(v) is int and 0<=v<255 for v in ids) and len(set(ids))==cpus,
            "Missing or repeated actual QOM APIC IDs")
    return set(ids)

def capture_cpus(qmp,cpus,kvm):
    actual=qmp.execute("query-cpus-fast")
    for cpu in actual:
        # Read the actual CPU object's APIC property, not an APIC computed
        # from -smp, cpu-index or a topology assumption.
        cpu["apic-id"]=qmp.execute("qom-get",{"path":cpu["qom-path"],"property":"apic-id"})
    result={"accelerator":"tcg","kvm":kvm,"cpus":actual}
    qmp_ids(result,cpus)
    return result

def verify_image(root,efi,commit):
    root=Path(root)
    out=root/"build"
    evidence=load("verify-vm-evidence.py")
    images=load("verify-supervisor-image.py")
    build=evidence.verify_build(root,commit)
    require(build.get("profile")=="default","Not the production build")
    signed=Path(efi).read_bytes()
    require(signed==(out/"agentos.efi").read_bytes(),"Actual ESP EFI differs from distribution")
    sections=images.signed_payload((out/"agentos.unsigned.efi").read_bytes(),signed)
    kernel,cpio=sections[".kernel"][1],sections[".initrd"][1]
    require(kernel==(out/"kernel.elf").read_bytes() and cpio==(out/"initramfs.cpio").read_bytes(),
            "Actual signed payload differs from build")
    entries=images.verify_distribution(cpio)
    require(len(entries)==13,"Unexpected distribution entries")
    require(hashlib.sha256(cpio).hexdigest()==build["initramfs_sha256"],"Wrong initramfs provenance")
    # Use the exact public certificate covered by the build provenance.
    cert=Path(efi).parent/"verified-db.pem"
    subprocess.run(["openssl","x509","-inform","DER","-in",str(out/"db.cer"),"-out",str(cert)],check=True)
    subprocess.run(["sbverify","--cert",str(cert),str(efi)],check=True)
    return {"source_commit":commit,"build_provenance_sha256":evidence.sha256(out/"build-provenance.json"),
            "signed_sha256":evidence.sha256(Path(efi)),"unsigned_sha256":build["artifacts"]["agentos.unsigned.efi"],
            "kernel_sha256":hashlib.sha256(kernel).hexdigest(),"initramfs_sha256":build["initramfs_sha256"],
            "db_cer_sha256":build["artifacts"]["db.cer"],"entries":sorted(entries),"signature_verified":True}

def verify_progress(text,cpus,qmp,*,soak_interval=None):
    expected=qmp_ids(qmp,cpus)
    lines=text.splitlines()
    def records(prefix,pattern):
        found=[(i,pattern.fullmatch(s)) for i,s in enumerate(lines) if s.startswith(prefix)]
        require(all(m is not None for _,m in found),"Malformed "+prefix)
        return found
    def unique(value):
        found=[i for i,s in enumerate(lines) if s==value]
        require(len(found)==1,"Missing or repeated "+value)
        return found[0]
    def one(prefix,pattern):
        found=records(prefix,pattern)
        require(len(found)==1,"Missing or repeated "+prefix)
        i,m=found[0]
        return i,tuple(int(v,16) for v in m.groups())

    online=unique("[INFO] PROCESSORS ONLINE")
    users=unique("[INFO] STARTING USER PROCESSES")
    ready=unique("AGENTOS SHELL READY")
    done=unique("[INFO] INTERACTIVE SHELL STOPPED")
    require(done==len(lines)-1 and online<users<ready<done,"Incomplete boot/session lifecycle")
    outside=text
    if soak_interval is not None:
        require(soak_interval.startswith("run /smp-soak\n") and text.count(soak_interval)==1 and
                "AGENTOS TEST SMP SOAK " in soak_interval and
                re.search(r"AGENTOS TEST (?!SMP SOAK )",soak_interval) is None,
                "Missing explicit authenticated SMP interval")
        outside=text.replace(soak_interval,"",1)
    require("AGENTOS TEST " not in outside and not any(marker in text for marker in ("SMP FAILED:","SHELL FAILED","FATAL VECTOR",
                "AGENTOS PAGE OOM","AGENTOS MIGRATION","AGENTOS USER FAULT")),
            "Unexpected failure or acceptance workload in ordinary session")
    roster=records("AGENTOS TASK ",TASK)
    require(len(roster)==cpus and sum(m[1]=="BSP" for _,m in roster)==1 and
            {int(m[2],16) for _,m in roster}==expected and
            all(i<online and int(m[3],16)==3 for i,m in roster),
            "Actual BSP/AP timer roster differs from QOM APIC identities")
    by_cpu={int(m[2],16):{"role":m[1],"timer_wakes":int(m[3],16),"tasks":[]} for _,m in roster}
    frame_at,(held,before,after)=one("AGENTOS FRAME STRESS ",FRAME)
    oom_at,(drained,rejected,restored)=one("AGENTOS OOM OK",OOM)
    require(online<frame_at<oom_at<users and held==16*cpus and
            before==after==drained==restored and before>0 and rejected==cpus,
            "Incomplete existing boot frame accounting")
    sched=records("AGENTOS SCHED ",SCHED)
    seen=set()
    for i,m in sched:
        cpu,slot,preemptions,pages=(int(x,16) for x in m.groups())
        require(online<i<frame_at and cpu in expected and slot in (0,1) and
                (cpu,slot) not in seen and preemptions>=2 and pages==4096,
                "Missing, repeated or non-progressing CPU task")
        seen.add((cpu,slot))
        by_cpu[cpu]["tasks"].append({"slot":slot,"preemptions":preemptions,"pages":pages})
    require(seen=={(cpu,slot) for cpu in expected for slot in (0,1)},
            "Incomplete actual per-CPU scheduler work")
    idle_at,(hz,)=one("AGENTOS IDLE BEGIN",IDLE_BEGIN)
    require(users<idle_at<ready and hz>0,"Invalid boot idle boundary")
    checks=records("AGENTOS PROCESS OK ",re.compile(r"AGENTOS PROCESS OK APIC="+HEX+r" PARENT="+HEX))
    require(len(checks)==cpus and {int(m[1],16) for _,m in checks}==expected and
            all(users<i<idle_at for i,_ in checks),"Missing per-CPU process completion")
    manager=unique("AGENTOS MANAGER SESSION START PID=0000000000000001")
    idle_seen=set()
    for i,m in records("AGENTOS IDLE APIC=",IDLE):
        cpu,wakes,timers,total,active=(int(x,16) for x in m.groups())
        require(idle_at<i<manager and cpu in expected and cpu not in idle_seen and
                wakes>=timers>0 and total>active>0,"Missing or invalid actual CPU idle sample")
        idle_seen.add(cpu)
        by_cpu[cpu]["idle"]={"wakes":wakes,"timers":timers,"tsc_total":total,"tsc_active":active}
    require(idle_seen==expected,"Incomplete per-CPU idle roster")
    # Reuse, do not dilute, the original root/orphan lifecycle and CR3 gate.
    processes=load("verify-processes.py")
    orphans=load("verify-orphans.py")
    roots=processes.verify(text,sorted(expected),ipc_staged=True,root_orphan_v1=True,require_shutdown=True)
    require(orphans.verify(text,cpus,basic_smp=True)==cpus,"Incomplete orphan families")
    require(roots["shutdown_verified"] and roots["manager_pid"]==1 and
            all(by_cpu[f["apic"]]["role"]==("BSP" if f["terminal"]=="park" else "AP") for f in roots["families"]),
            "Boot root role mismatch or incomplete shutdown")
    return {"cpus":[{"apic":cpu,**by_cpu[cpu]} for cpu in sorted(expected)],
            "boot_roots":roots,"frame_accounting":{"held":held,"free_before":before,"free_after":after,
            "boot_oom_rejected":rejected,"restored":restored},"final_shutdown":True}
