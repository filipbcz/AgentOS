#!/usr/bin/env python3
"""One isolated, KVM-only low-ID -> sparse x2APIC firmware capability probe."""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import tempfile
import time
import uuid
import zlib

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "build/x2apic-probe"
CODE = Path("/usr/share/OVMF/OVMF_CODE_4M.secboot.fd")
VARS = Path("/usr/share/OVMF/OVMF_VARS_4M.fd")
OWNER = "d7663630-f07a-4739-bc6f-b9f6d6444865"
MODE = 0xc00

def require(condition, reason):
    if not condition:
        raise RuntimeError(reason)

def sha(path):
    with path.open("rb") as file:
        return hashlib.file_digest(file, "sha256").hexdigest()

def save(path, data):
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")

def capture(*cmd):
    result = subprocess.run(cmd, check=True, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, text=True, timeout=60)
    return result.stdout

def run(*cmd):
    subprocess.run([str(x) for x in cmd], check=True, timeout=60, cwd=ROOT)

def environment():
    info = {
        "checkout": capture("git", "rev-parse", "HEAD").strip(),
        "tree": capture("git", "rev-parse", "HEAD^{tree}").strip(),
        "pr_head": os.environ.get("PROBE_PR_HEAD"),
        "runner_os": os.environ.get("RUNNER_OS"),
        "image_os": os.environ.get("ImageOS"),
        "image_version": os.environ.get("ImageVersion"),
        "uname": capture("uname", "-a"),
        "lscpu": capture("lscpu"),
        "packages": capture("dpkg-query", "-W", "qemu-system-x86", "qemu-system-common",
                            "qemu-system-data", "ovmf", "gnu-efi", "gcc-13"),
        "qemu_version": capture("qemu-system-x86_64", "--version"),
        "accelerators": capture("qemu-system-x86_64", "-accel", "help"),
        "qemu_sha256": sha(Path(shutil.which("qemu-system-x86_64")).resolve()),
        "ovmf_code_sha256": sha(CODE),
        "ovmf_vars_template_sha256": sha(VARS),
    }
    save(OUT/"environment.json", info)
    # Use capability numbers from the installed Linux UAPI, not assumptions
    # about the runner's actual KVM implementation.
    macros = subprocess.check_output(
        ["gcc-13", "-dM", "-E", "-x", "c", "-include", "linux/kvm.h", "-"],
        input="", text=True, timeout=30)
    (OUT/"kvm-uapi.txt").write_text(macros)
    caps = ["KVM_CAP_IRQCHIP", "KVM_CAP_MAX_VCPUS", "KVM_CAP_MAX_VCPU_ID",
            "KVM_CAP_X2APIC_API", "KVM_CAP_SPLIT_IRQCHIP"]
    result = {}
    with open("/dev/kvm", "r+b", buffering=0) as dev:
        result["api_version"] = fcntl.ioctl(dev, 0xae00)
        for name in caps:
            match = re.search(r"(?m)^#define "+name+r"\s+(\d+)\s*$", macros)
            if not match:
                result[name] = {"header": "not defined"}
                continue
            number = int(match.group(1))
            result[name] = {"number": number, "value": fcntl.ioctl(dev, 0xae03, number)}
    save(OUT/"kvm-capabilities.json", result)
    require(result["api_version"] == 12, "unexpected KVM API version")
    return info

def build():
    source = ROOT/"tests/platform-x2apic/probe.c"
    obj, elf, unsigned, signed = (OUT/name for name in
                                   ("probe.o","probe.so","probe.unsigned.efi","probe.efi"))
    run("gcc-13","-I/usr/include/efi","-I/usr/include/efi/x86_64","-DGNU_EFI_USE_MS_ABI",
        "-O2","-Wall","-Wextra","-Werror","-fpic","-ffreestanding","-fno-stack-protector",
        "-fshort-wchar","-mno-red-zone","-c",source,"-o",obj)
    run("ld","-nostdlib","--build-id=none","-znocombreloc","-T","/usr/lib/elf_x86_64_efi.lds",
        "-shared","-Bsymbolic","/usr/lib/crt0-efi-x86_64.o",obj,"-L/usr/lib","-lefi","-lgnuefi",
        "-o",elf)
    run("objcopy","--strip-all","-j",".text","-j",".sdata","-j",".data","-j",".dynamic",
        "-j",".dynsym","-j",".rela","-j",".reloc","--target=efi-app-x86_64",elf,unsigned)
    cert=OUT/"probe.crt"
    with tempfile.TemporaryDirectory(prefix="agentos-probe-keys-") as temp:
        key=Path(temp)/"probe.key"
        run("openssl","req","-x509","-newkey","rsa:2048","-nodes","-days","2",
            "-subj","/CN=AgentOS isolated x2APIC firmware probe/","-keyout",key,"-out",cert)
        run("sbsign","--key",key,"--cert",cert,"--output",signed,unsigned)
        run("sbverify","--cert",cert,signed)
        run("virt-fw-vars","--input",VARS,"--output",OUT/"probe-vars.fd",
            "--set-pk",OWNER,cert,"--add-kek",OWNER,cert,"--add-db",OWNER,cert,"--secure-boot")
    save(OUT/"fixture.json", {"source_sha256":sha(source),"efi_sha256":sha(signed),
                             "vars_sha256":sha(OUT/"probe-vars.fd")})
    return signed

class Qmp:
    def __init__(self, directory, process):
        self.directory=directory
        self.socket=socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.socket.settimeout(10)
        deadline=time.monotonic()+20
        while True:
            require(process.poll() is None, f"QEMU exited before QMP (rc={process.returncode})")
            try:
                self.socket.connect(str(directory/"qmp.sock"))
                break
            except (FileNotFoundError, ConnectionRefusedError):
                require(time.monotonic()<deadline,"QMP socket timeout")
                time.sleep(.1)
        self.stream=self.socket.makefile("rwb")
        self.log=(directory/"qmp.jsonl").open("w")
        self.seq=0
        greeting=self.receive()
        require("QMP" in greeting,"missing QMP greeting")
        self.call("qmp_capabilities")
    def record(self, direction, data):
        self.log.write(json.dumps({"direction":direction,"data":data})+"\n")
        self.log.flush()
    def receive(self):
        raw=self.stream.readline()
        require(raw,"QMP closed")
        data=json.loads(raw)
        self.record("receive",data)
        return data
    def call(self, command, arguments=None, optional=False):
        self.seq+=1
        request={"execute":command,"id":self.seq}
        if arguments is not None:
            request["arguments"]=arguments
        self.record("send",request)
        self.stream.write(json.dumps(request).encode()+b"\n")
        self.stream.flush()
        while True:
            answer=self.receive()
            if "event" in answer:
                continue
            require(answer.get("id")==self.seq,"QMP response ID mismatch")
            if "error" in answer:
                if optional:
                    return {"qmp_error":answer["error"]}
                raise RuntimeError(f"{command}: {answer['error']}")
            return answer["return"]
    def close(self):
        self.stream.close()
        self.socket.close()
        self.log.close()

def uint(data, offset, width):
    require(0<=offset<=len(data)-width,"truncated firmware field")
    return int.from_bytes(data[offset:offset+width],"little")

class Acpi:
    """Read live guest physical memory through QMP, not generated ACPI blobs."""
    def __init__(self, qmp, directory):
        self.qmp=qmp
        self.directory=directory
    def read(self, name, address, size):
        require(0<address<256*1024*1024 and 0<size<=1024*1024 and
                address+size<=256*1024*1024,
                f"invalid firmware memory range {name}: {address:#x}/{size}")
        path=self.directory/(name+".bin")
        self.qmp.call("pmemsave",{"val":address,"size":size,"filename":str(path)})
        data=path.read_bytes()
        require(len(data)==size,"truncated guest memory dump")
        return data
    def table(self,name,address):
        hdr=self.read(name+"-header",address,36)
        length=uint(hdr,4,4)
        require(length>=36,"bad ACPI table length")
        data=self.read(name,address,length)
        require(not sum(data)%256,f"bad {name} checksum")
        return data
    def system(self,address):
        hdr=self.read("system-table-header",address,120)
        require(hdr[:8]==b"IBI SYST","EFI system table signature")
        size=uint(hdr,12,4)
        require(120<=size<=4096,"EFI system table size")
        table=self.read("system-table",address,size)
        crc=uint(table,16,4)
        require(zlib.crc32(table[:16]+b"\0"*4+table[20:])==crc,"EFI system table CRC")
        count,ptr=uint(table,104,8),uint(table,112,8)
        require(0<count<=128,"configuration table count")
        conf=self.read("configuration-tables",ptr,count*24)
        roots=[]
        acpi20=uuid.UUID("8868e871-e4f1-11d3-bc22-0080c73c8881").bytes_le
        acpi10=uuid.UUID("eb9d2d30-2d88-11d3-9a16-0090273fc14d").bytes_le
        for i in range(count):
            entry=conf[i*24:(i+1)*24]
            if entry[:16] in (acpi10,acpi20):
                roots.extend(self.rsdp(f"config-{i}",uint(entry,16,8),entry[:16]==acpi20))
        require(roots,"no ACPI roots")
        save(self.directory/"madt-roots.json",roots)
        return roots
    def rsdp(self,name,address,extended):
        first=self.read(name+"-rsdp20",address,20)
        require(first[:8]==b"RSD PTR " and not sum(first)%256,"RSDP signature/checksum")
        result=[]
        rsdt=uint(first,16,4)
        if rsdt:
            result.append(self.root(name+"-rsdt",rsdt,4))
        if extended or first[15]>=2:
            header=self.read(name+"-rsdp36",address,36)
            require(header[15]>=2 and uint(header,20,4)>=36,"invalid extended RSDP")
            data=self.read(name+"-rsdp",address,uint(header,20,4))
            require(not sum(data)%256,"extended RSDP checksum")
            xsdt=uint(data,24,8)
            require(xsdt,"missing XSDT")
            result.append(self.root(name+"-xsdt",xsdt,8))
        return result
    def root(self,name,address,width):
        data=self.table(name,address)
        require(data[:4]==(b"XSDT" if width==8 else b"RSDT") and
                (len(data)-36)%width==0,"invalid root")
        madts=[]
        signatures=[]
        for offset in range(36,len(data),width):
            child=uint(data,offset,width)
            hdr=self.read(f"{name}-child-{offset}",child,36)
            signatures.append(hdr[:4].decode("ascii","replace"))
            if hdr[:4]==b"APIC":
                madt=self.table(name+"-madt",child)
                madts.append(self.madt(madt))
        require(len(madts)==1,"root does not contain exactly one MADT")
        return {"root":name,"address":address,"tables":signatures,**madts[0]}
    @staticmethod
    def madt(data):
        require(len(data)>=44 and data[:4]==b"APIC","invalid MADT header")
        records=[]
        pos=44
        while pos<len(data):
            require(pos+2<=len(data),"truncated MADT record")
            kind,n=data[pos:pos+2]
            require(n>=2 and pos+n<=len(data),"invalid MADT record length")
            raw=data[pos:pos+n]
            record={"type":kind,"length":n,"offset":pos,"raw":raw.hex()}
            if kind==0:
                require(n==8,"invalid Local APIC record")
                record.update(id=raw[3],uid=raw[2],flags=uint(raw,4,4))
            elif kind==9:
                require(n==16,"invalid Local x2APIC record")
                record.update(id=uint(raw,4,4),uid=uint(raw,12,4),flags=uint(raw,8,4))
            if "flags" in record:
                flags=record["flags"]
                record["state"]="enabled" if flags&1 else ("online-capable" if flags&2 else "disabled")
            records.append(record)
            pos+=n
        return {"lapic_address":uint(data,36,4),"madt_flags":uint(data,40,4),
                "records":records}

def parse_lines(log, prefix):
    result=[]
    for line in log.splitlines():
        if line.startswith(prefix+" "):
            fields=dict(re.findall(r" ([A-Z_]+)=([0-9a-f]{16})(?= |$)",line))
            require(fields,f"missing fields in {line}")
            result.append({key:int(value,16) for key,value in fields.items()})
    return result

def validate_guest(log, expected, roots, receipt):
    sec=parse_lines(log,"SECURITY")
    require(len(sec)==1 and sec[0]=={"SECURE":1,"SETUP":0,"SECURE_STATUS":0,"SETUP_STATUS":0},
            "fixture not authenticated under enabled Secure Boot")
    counts=parse_lines(log,"MP COUNT")
    who=parse_lines(log,"MP WHO")
    infos=parse_lines(log,"MP INFO")
    receipt["firmware_mp_count"]=counts
    receipt["firmware_mp_info"]=infos
    receipt["firmware_bsp"]=who
    # Retain raw records even on firmware mismatch.
    cpuid=parse_lines(log,"CPU CPUID")
    before=parse_lines(log,"CPU BEFORE")
    active=parse_lines(log,"CPU ACTIVE")
    restored=parse_lines(log,"CPU RESTORED")
    startup=parse_lines(log,"MP STARTUP")
    receipt["guest_registers"]={"cpuid":cpuid,"topology":parse_lines(log,"CPU TOPOLOGY"),
        "before":before,"active":active,"restored":restored,"startup":startup}
    require(len(counts)==1 and counts[0]["STATUS"]==0 and counts[0]["ENABLED"]==2,
            "OVMF MP Services did not enumerate exactly two enabled CPUs")
    require(len(who)==1 and who[0]["STATUS"]==0,"OVMF WhoAmI failed")
    require(len(infos)==counts[0]["TOTAL"] and all(x["STATUS"]==0 for x in infos),
            "OVMF MP records incomplete")
    enabled=[x for x in infos if x["FLAGS"]&2]
    require(len(enabled)==2 and sorted(x["ID"] for x in enabled)==expected,
            "OVMF enabled CPU IDs differ from real QMP topology")
    require([x["ID"] for x in enabled if x["FLAGS"]&1 and x["INDEX"]==who[0]["BSP"]]==[0]
            and sum(bool(x["FLAGS"]&1) for x in enabled)==1,"OVMF BSP identity mismatch")
    summaries=[]
    for root in roots:
        cpu=[r for r in root["records"] if r["type"] in (0,9)]
        require(len({r["id"] for r in cpu})==len(cpu),"duplicate MADT CPU ID")
        states={state:sorted(r["id"] for r in cpu if r["state"]==state)
                for state in ("enabled","online-capable","disabled")}
        summaries.append({"root":root["root"],"states":states,
                          "record_types":{str(i):sum(r["type"]==i for r in cpu) for i in (0,9)},
                          "ioapic_count":sum(r["type"]==1 for r in root["records"]),
                          "dmar": "DMAR" in root["tables"]})
        require(states["enabled"]==expected,"live MADT enabled IDs differ from QMP")
        require(all(r["flags"] in (0,1,2) for r in cpu),"unexpected MADT flags")
        require(all(r["type"]==9 for r in cpu if r["id"]>=255),"wide MADT ID lacks type 9")
    receipt["madt_summary"]=summaries
    for entries in (cpuid,before,active,restored):
        require(len(entries)==2 and {x["INDEX"] for x in entries}=={x["INDEX"] for x in enabled},
                "missing or duplicate per-CPU register evidence")
    for cpu in enabled:
        index=cpu["INDEX"]
        cp=next(x for x in cpuid if x["INDEX"]==index)
        old=next(x for x in before if x["INDEX"]==index)
        new=next(x for x in active if x["INDEX"]==index)
        final=next(x for x in restored if x["INDEX"]==index)
        require(cp["ECX"]&(1<<21) and cp["EDX"]&(1<<9) and cp["EDX"]&(1<<5),
                "CPUID lacks x2APIC/APIC/MSR")
        require(old["BASE"]&MODE in (0x800,0xc00),"firmware APIC was disabled/invalid")
        require(new["BASE"]&MODE==0xc00 and new["ID"]==cpu["ID"],
                "active x2APIC register identity mismatch")
        require(bool(new["BASE"]&(1<<8))==(cpu["ID"]==0),"actual APIC BSP bit mismatch")
        require(final["BASE"]==old["BASE"],"firmware mode not restored")
    require(len(startup)==1 and startup[0]["STATUS"]==0 and
            startup[0]["INDEX"]!=who[0]["BSP"],"AP callback not completed")
    require(parse_lines(log,"END")==[{"STATUS":0}],"firmware probe did not complete")
    receipt["legacy_addressable_enabled_ids"]=[i for i in expected if i<255]
    receipt["external_irq_delivery_verified"]=False
    receipt["extended_interrupt_remapping_verified"]=False

def profile(name, expected, efi, info):
    directory=OUT/name
    directory.mkdir()
    receipt={"profile":name,"result":"fail","expected_present_ids":expected,
             "source_commit":info["checkout"],"source_tree":info["tree"],
             "ovmf_code_sha256":info["ovmf_code_sha256"]}
    process=None
    qmp=None
    stage="prepare"
    begin=time.monotonic()
    try:
        run("bash","scripts/disk.sh",directory,efi)
        run("mcopy","-i",str(directory/"esp.raw")+"@@1048576",
            "::EFI/BOOT/BOOTX64.EFI",directory/"esp-probe.efi")
        require(sha(efi)==sha(directory/"esp-probe.efi"),"ESP probe bytes differ")
        receipt["esp_efi_sha256"]=sha(efi)
        shutil.copyfile(OUT/"probe-vars.fd",directory/"vars.fd")
        smp="2,sockets=1,dies=1,cores=2,threads=1" if name=="low" else \
            "1,maxcpus=153,sockets=9,dies=1,cores=17,threads=1"
        command=["qemu-system-x86_64","-machine","q35,accel=kvm,smm=on,hpet=off,kernel-irqchip=on",
                 "-cpu","host,x2apic=on,invtsc=on,enforce=on","-smp",smp,"-m","256",
                 "-global","driver=cfi.pflash01,property=secure,value=on",
                 "-drive",f"if=pflash,format=raw,unit=0,readonly=on,file={CODE}",
                 "-drive",f"if=pflash,format=raw,unit=1,file={directory/'vars.fd'}",
                 "-drive",f"if=none,format=raw,id=esp,file={directory/'esp.raw'}",
                 "-device","ide-hd,drive=esp,bus=ide.0",
                 "-qmp",f"unix:{directory/'qmp.sock'},server=on,wait=off",
                 "-serial",f"file:{directory/'serial.log'}",
                 "-debugcon",f"file:{directory/'firmware.log'}","-global","isa-debugcon.iobase=0xe9",
                 "-vga","std","-display","none","-nic","none","-monitor","none",
                 "-boot","order=c","-no-reboot","-no-shutdown","-S"]
        if name=="sparse":
            command.extend(["-device","host-x86_64-cpu,id=highcpu,socket-id=8,die-id=0,core-id=0,thread-id=0"])
        save(directory/"command.json",command)
        stage="qemu-launch"
        with (directory/"qemu-stderr.log").open("wb") as stderr:
            process=subprocess.Popen(command,cwd=ROOT,stdin=subprocess.DEVNULL,
                                     stdout=stderr,stderr=subprocess.STDOUT)
            qmp=Qmp(directory,process)
            stage="qmp-before-boot"
            receipt["kvm"]=qmp.call("query-kvm")
            require(receipt["kvm"]["enabled"] and receipt["kvm"]["present"],"KVM not active")
            receipt["version"]=qmp.call("query-version")
            receipt["status_before"]=qmp.call("query-status")
            require(not receipt["status_before"]["running"],"guest ran before topology capture")
            slots=qmp.call("query-hotpluggable-cpus")
            cpus=qmp.call("query-cpus-fast")
            save(directory/"qmp-slots.json",slots)
            save(directory/"qmp-cpus.json",cpus)
            receipt["possible_slots"]=len(slots)
            receipt["occupied_slots"]=sum("qom-path" in slot for slot in slots)
            actual=[{"cpu":x,"apic_id":qmp.call("qom-get",{"path":x["qom-path"],"property":"apic-id"})}
                    for x in cpus]
            save(directory/"qmp-present-ids.json",actual)
            receipt["present_ids"]=sorted(x["apic_id"] for x in actual)
            require(receipt["present_ids"]==expected and receipt["occupied_slots"]==2 and
                    len(cpus)==2,"QMP present CPU identities/count differ from requested topology")
            require(receipt["possible_slots"]==(2 if name=="low" else 153),"QMP possible slot count")
            receipt["cpu_model"]=qmp.call("query-cpu-model-expansion",
                {"type":"full","model":{"name":"host","props":{"x2apic":True,"invtsc":True}}},optional=True)
            receipt["irqchip"]=qmp.call("qom-get",{"path":"/machine","property":"kernel-irqchip"},optional=True)
            for cmd in ("info qtree","info pic"):
                (directory/(cmd.replace(" ","-")+"-before.txt")).write_text(
                    qmp.call("human-monitor-command",{"command-line":cmd}))
            stage="firmware"
            qmp.call("cont")
            deadline=time.monotonic()+120
            log=""
            while time.monotonic()<deadline:
                path=directory/"firmware.log"
                if path.exists():
                    log=path.read_text(encoding="ascii",errors="replace")
                if re.search(r"(?m)^END STATUS=[0-9a-f]{16}\n",log):
                    break
                if process.poll() is not None:
                    break
                time.sleep(.1)
            require(process.poll() is None,f"guest process exited rc={process.returncode}")
            qmp.call("stop")
            receipt["status_after"]=qmp.call("query-status")
            log=(directory/"firmware.log").read_text(encoding="ascii",errors="replace")
            (directory/"info-registers-after.txt").write_text(qmp.call(
                "human-monitor-command",{"command-line":"info registers"}))
            receipt["guest_registers_raw"]= [line for line in log.splitlines()
                if line.startswith(("CPU ","MP ","SECURITY","TABLES","END"))]
            tables=parse_lines(log,"TABLES")
            stage="live-madt"
            require(len(tables)==1,"firmware application did not provide a unique live system table")
            roots=Acpi(qmp,directory).system(tables[0]["ST"])
            stage="guest-validation"
            validate_guest(log,expected,roots,receipt)
            receipt["result"]="pass"
            stage="complete"
    except Exception as exc:
        receipt["failure_stage"]=stage
        receipt["failure_message"]=str(exc)
        if process is not None:
            receipt["qemu_returncode_at_failure"]=process.poll()
        print(f"{name} FAIL at {stage}: {exc}",flush=True)
    finally:
        if qmp is not None:
            try:
                qmp.call("quit")
            except (OSError,RuntimeError):
                pass
            qmp.close()
        if process is not None:
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
            receipt["qemu_final_returncode"]=process.returncode
        # No socket or ephemeral private key in evidence.
        (directory/"qmp.sock").unlink(missing_ok=True)
        receipt["host_elapsed_seconds"]=round(time.monotonic()-begin,3)
        receipt["sha256"]={p.name:sha(p) for p in directory.iterdir() if p.is_file()}
        save(directory/"receipt.json",receipt)
        print(f"{name}: {receipt['result']} expected={expected} actual={receipt.get('present_ids')} "
              f"possible={receipt.get('possible_slots')}",flush=True)
    return receipt

def main():
    OUT.mkdir(parents=True,exist_ok=False)
    summary={"result":"fail","profiles":{}}
    try:
        info=environment()
        efi=build()
        low=profile("low",[0,1],efi,info)
        summary["profiles"]["low"]=low["result"]
        if low["result"]!="pass":
            summary["profiles"]["sparse"]="not-run: low-ID control failed"
            return 1
        sparse=profile("sparse",[0,256],efi,info)
        summary["profiles"]["sparse"]=sparse["result"]
        if sparse["result"]!="pass":
            return 1
        summary["result"]="pass"
        return 0
    except Exception as exc:
        summary["failure_message"]=str(exc)
        print(f"probe setup failed: {exc}",flush=True)
        return 1
    finally:
        save(OUT/"summary.json",summary)

if __name__=="__main__":
    raise SystemExit(main())
