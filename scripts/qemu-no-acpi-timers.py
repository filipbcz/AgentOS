"""Independent QEMU q35 fault-platform boot of the unchanged signed AgentOS EFI.

A separately signed EFI *test fixture* replaces the OS-visible ACPI roots and
disables ICH9 PM I/O decode at ExitBootServices. HPET is absent in the QEMU
machine itself. No kernel flag, marker, test payload or forced CPU feature.
The fixture is never part of a distribution image. Do not use on real hardware.
"""
import argparse
import binascii
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import sys
import time
import uuid

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("normal_qemu", ROOT / "scripts/qemu-smoke.py")
smoke = importlib.util.module_from_spec(spec)
spec.loader.exec_module(smoke)

ACPI20 = uuid.UUID("8868e871-e4f1-11d3-bc22-0080c73c8881").bytes_le
ACPI10 = uuid.UUID("eb9d2d30-2d88-11d3-9a16-0090273fc14d").bytes_le
MAX_TABLE = 1024 * 1024
HEX = r"([0-9a-f]{16})"
PREPARED = re.compile(r"(?m)^FIXTURE PREPARED ST="+HEX+r" PMPORT="+HEX+
                      r" RSDP20="+HEX+r" RSDP10="+HEX+r" INVTSC="+HEX+r"$")
DEFER = re.compile(r"(?m)^FIXTURE DEFER EBS_ENTRY="+HEX+r" CHILD_BASE="+HEX+
                   r" CHILD_SIZE="+HEX+r" ST="+HEX+r" PMPORT="+HEX+r"$")
EBS = re.compile(r"(?m)^FIXTURE EBS ST="+HEX+r" PMPORT="+HEX+r" LPC="+HEX+
                 r" PMBASE="+HEX+r" CTRL_BEFORE="+HEX+r" CTRL_AFTER="+HEX+
                 r" PORT_AFTER="+HEX+r"$")


def require(condition, description):
    if not condition:
        raise RuntimeError(description)


def uint(data, offset, width):
    require(0 <= offset <= len(data)-width, "Truncated firmware field")
    return int.from_bytes(data[offset:offset+width], "little")


def checksum(data):
    return sum(data) % 256 == 0


def write_json(path, data):
    path.write_text(json.dumps(data, indent=2, sort_keys=True)+"\n", encoding="utf-8")


def read_table(read, address, expected=None):
    head = read(address, 36)
    size = uint(head, 4, 4)
    require(36 <= size <= MAX_TABLE, "Invalid SDT length")
    table = read(address, size)
    require(table[:36] == head and checksum(table), "SDT changed or checksum invalid")
    if expected is not None:
        require(table[:4] == expected, "Wrong ACPI table signature")
    return table


def read_root(read, address, width, cpus, pm_port=None):
    root = read_table(read, address, b"XSDT" if width == 8 else b"RSDT")
    require((len(root)-36) % width == 0, "Truncated ACPI root entry")
    children = []
    for offset in range(36, len(root), width):
        child = uint(root, offset, width)
        table = read_table(read, child)
        children.append((child, table))
    require(len({addr for addr, _ in children}) == len(children), "Duplicate root pointer")
    signatures = [table[:4] for _, table in children]
    require(b"HPET" not in signatures, "HPET remains exposed by ACPI")
    require(signatures.count(b"FACP") == signatures.count(b"APIC") == 1,
            "Expected one valid FADT and MADT per root")
    fadt_addr, fadt = next((addr, table) for addr, table in children if table[:4] == b"FACP")
    require(len(fadt) >= 116, "Missing FADT fixed fields")
    if pm_port is None:
        require(uint(fadt, 76, 4) == 0 and fadt[91] == 0, "Legacy PM timer still exposed")
        require(uint(fadt,112,4) & ((1<<8)|(1<<15)|(1<<20)) == 0,
                "Unexpected PM clock flags or hardware-reduced platform")
        require(len(fadt) <= 208 or (len(fadt) >= 220 and fadt[208:220] == bytes(12)),
                "Extended PM timer GAS remains exposed or truncated")
    else:
        require(uint(fadt,76,4)==pm_port and fadt[91]==4 and
                not uint(fadt,112,4)&(1<<20),"Control lost its declared PM timer")
        require(len(fadt)<=208 or (len(fadt)>=220 and
                (uint(fadt,212,8)==0 or (fadt[208]==1 and uint(fadt,212,8)==pm_port))),
                "Control has conflicting extended PM GAS")
    madt_addr, madt = next((addr,table) for addr,table in children if table[:4] == b"APIC")
    require(len(madt) >= 44 and uint(madt,40,4)&1, "No PCAT-compatible MADT")
    ids = []
    offset = 44
    while offset < len(madt):
        require(offset+2 <= len(madt), "Truncated MADT entry")
        kind, size = madt[offset:offset+2]
        require(size >= 2 and offset+size <= len(madt), "Invalid MADT entry")
        if kind == 0:
            require(size >= 8, "Short LAPIC entry")
            if uint(madt,offset+4,4)&1:
                ids.append(madt[offset+3])
        if kind == 9:
            require(size >= 16, "Short x2APIC entry")
            if uint(madt,offset+8,4)&1:
                ids.append(uint(madt,offset+4,4))
        offset += size
    require(len(ids) == len(set(ids)) == cpus, "Wrong enabled MADT CPU roster")
    return {"address":address,"signature":root[:4].decode("ascii"),
            "tables":[{"address":addr,"signature":table[:4].decode("ascii")}
                      for addr,table in children],
            "fadt_address":fadt_addr,"fadt_pm_tmr_blk":uint(fadt,76,4),"fadt_pm_tmr_len":fadt[91],
            "fadt_x_pm_tmr_blk":fadt[208:220].hex() if len(fadt)>=220 else None,
            "madt_address":madt_addr,"enabled_apic_ids":sorted(ids)}


def read_rsdp(read, address, extended, cpus, pm_port=None):
    first = read(address,20)
    require(first[:8] == b"RSD PTR " and checksum(first), "Invalid RSDP checksum")
    roots = []
    rsdt = uint(first,16,4)
    if rsdt:
        roots.append(read_root(read,rsdt,4,cpus,pm_port))
    if extended or first[15] >= 2:
        head = read(address,36)
        size = uint(head,20,4)
        require(first[15]>=2 and 36<=size<=MAX_TABLE, "Invalid extended RSDP")
        full = read(address,size)
        require(full[:20]==first and checksum(full), "Invalid extended RSDP checksum")
        roots.append(read_root(read,uint(full,24,8),8,cpus,pm_port))
    require(roots, "Empty ACPI root set")
    require(all(r["enabled_apic_ids"]==roots[0]["enabled_apic_ids"] for r in roots),
            "ACPI root CPU disagreement")
    return roots


def inspect_tables(read, st, rsdp20, rsdp10, cpus, pm_port=None):
    # Read EFI_SYSTEM_TABLE itself after EBS, not just the fixture's
    # suggested FADT address. Both the firmware table CRC and all ACPI
    # roots/checksums must be valid in the actual guest physical memory.
    table = read(st,120)
    require(table[:8] == b"IBI SYST" and uint(table,12,4)==120, "Invalid EFI system table")
    crc = uint(table,16,4)
    require(binascii.crc32(table[:16]+bytes(4)+table[20:])&0xffffffff == crc,
            "EFI system table checksum mismatch")
    require(uint(table,96,8)==0, "BootServices not yet terminated")
    count = uint(table,104,8)
    require(1<=count<=128, "Invalid EFI configuration table count")
    entries = read(uint(table,112,8),count*24)
    actual = {}
    for offset in range(0,len(entries),24):
        guid = entries[offset:offset+16]
        if guid in (ACPI20,ACPI10):
            require(guid not in actual, "Duplicate ACPI configuration GUID")
            actual[guid] = uint(entries,offset+16,8)
    expected = {ACPI20:rsdp20}
    if rsdp10:
        expected[ACPI10]=rsdp10
    require(actual==expected, "Published EFI ACPI pointers differ from prepared platform")
    roots = []
    for guid,address in actual.items():
        roots.extend(read_rsdp(read,address,guid==ACPI20,cpus,pm_port))
    require(all(r["enabled_apic_ids"]==roots[0]["enabled_apic_ids"] for r in roots),
            "Enabled CPU disagreement between EFI ACPI versions")
    return {"system_table":st,"rsdp20":rsdp20,"rsdp10":rsdp10,"roots":roots}


def hmp(qmp, command):
    result = qmp.execute("human-monitor-command",{"command-line":command})
    require(isinstance(result,str) and result.strip() and
            not re.search(r"unknown command|invalid parameter|error:",result,re.I),
            f"HMP command failed: {command}: {result!r}")
    return result


def verify_pm_read(io, port, disabled=True):
    # HMP "i/xw" requests a 32-bit read; the output suffix is "l".
    match = re.fullmatch(r"portl\[0x([0-9a-f]+)\]\s*=\s*0x([0-9a-f]{8})",
                         io.strip(), re.I)
    require(match is not None and int(match[1],16)==port,
            f"Invalid 32-bit PM port read: {io!r}")
    value=int(match[2],16)
    require((value==0xffffffff)==disabled,
            f"PM I/O read does not match expected decode state: {io!r}")
    return value


def kernel_postmortem(qmp, dest, ram):
    """Read existing kernel-owned state after a terminal test outcome.

    Exact relocated symbol ranges from the ELF built in this job; no guessed
    Rust struct offsets or calls into the guest. Absence of a symbol or
    overwritten log history is inconclusive, never evidence of clock health.
    """
    data=(dest/"com1.log").read_bytes()
    bases=re.findall(rb"(?m)^\[INFO\] KERNEL IMAGE BASE=([0-9a-f]{16})\r?$",data)
    if len(bases)!=1:
        return {"result":"unavailable","reason":"No unique kernel relocation evidence"}
    base=int(bases[0],16)
    symbols=subprocess.check_output(["nm","-S","-C","--defined-only",str(ROOT/"build/kernel.elf")],text=True)
    result={"result":"diagnostic","kernel_base":base}
    for wanted,tag,maximum in [
        ("::logger::LOGGER","kernel-logger",4096),
        ("::system_clock::CLOCK","system-clock",65536),
        ("::system_clock::TSC_FAILURE","tsc-failure",1),
        ("::system_clock::TSC_FAILURE_DETAIL","tsc-failure-detail",32),
    ]:
        matches=[]
        for line in symbols.splitlines():
            match=re.fullmatch(r"([0-9a-f]+)\s+([0-9a-f]+)\s+([bBdD])\s+(.+)",line.strip())
            if match and re.search(re.escape(wanted)+r"(?:::h[0-9a-f]+)?$",match[4]):
                matches.append((int(match[1],16),int(match[2],16),match[4]))
        if len(matches)!=1:
            result[tag]={"available":False,"symbol_matches":matches}
            continue
        offset,size,symbol=matches[0]
        address=base+offset
        if not (0<size<=maximum and 4096<=address and address+size<=ram):
            result[tag]={"available":False,"reason":"unexpected symbol range","size":size}
            continue
        path=dest/(tag+".bin")
        qmp.execute("pmemsave",{"val":address,"size":size,"filename":str(path)})
        raw=path.read_bytes()
        require(len(raw)==size,"Truncated kernel postmortem")
        record={"available":True,"symbol":symbol,"address":address,"size":size,
                "sha256":smoke.evidence.sha256(path)}
        if tag=="kernel-logger":
            # The actual bounded log owns inline copies of message bytes.
            # Search only this precise mutable object, not ELF string data.
            record["unavailable_event_in_ring"]=(
                b"SYSTEM CLOCK: no trustworthy elapsed time; epoch unavailable" in raw or
                b"SYSTEM CLOCK: TSC unavailable:" in raw)
            record["clock_messages"]=[m.decode("ascii") for m in
                re.findall(rb"SYSTEM CLOCK: [\x20-\x7e]{1,82}",raw)]
        if tag=="tsc-failure":
            record["first_failure_code"]=raw[0]
        if tag=="tsc-failure-detail" and size==32:
            version,code,cpu,ticks=struct.unpack("<4Q",raw)
            record["consistent_with_first_fault"]=(version==1 and code!=0 and
                code==result.get("tsc-failure",{}).get("first_failure_code"))
            record["detail"]={"version":version,"fault_code":code,"cpu":cpu,"raw":ticks}
        result[tag]=record
    return result


def capture_platform(qmp, dest, cpus, accel, ram, profile="disabled"):
    # Do not pause a live finite-PIT epoch during the session. This is
    # called only after session completion or a recorded boot failure.
    qmp.execute("stop")
    state = qmp.execute("query-status")
    require(not state["running"], "QEMU did not pause for final read-only inspection")
    disabled=profile in ("disabled","deferred")
    callback_disabled=profile=="disabled"
    hidden=profile!="chain"
    try:
        diagnostic=kernel_postmortem(qmp,dest,ram)
        write_json(dest/"kernel-postmortem.json",diagnostic)
        print("Stopped kernel postmortem:",json.dumps(diagnostic,sort_keys=True),flush=True)
    except Exception as exc:
        print("Kernel postmortem unavailable:",exc,flush=True)
    # Capture stopped architectural state before any validation can fail.
    # No guest instruction, clock counter or RAM is changed.
    for command,name in [("info registers -a","registers-all.txt"),
                         ("info lapic","lapic.txt"),("info pic","pic.txt")]:
        try:
            output=hmp(qmp,command)
            (dest/name).write_text(output)
            if name=="registers-all.txt":
                print("Stopped CPU registers:",output,flush=True)
        except Exception as exc:
            print("Diagnostic unavailable:",command,exc,flush=True)
    for index in range(cpus):
        try:
            qmp.execute("human-monitor-command",{"command-line":f"cpu {index}"})
            registers=hmp(qmp,"info registers")
            (dest/f"cpu{index}-registers.txt").write_text(registers)
            match=re.search(r"\b(?:RIP|EIP)=([0-9a-fA-F]+)",registers)
            require(match is not None,"Stopped CPU instruction pointer unavailable")
            code=hmp(qmp,f"x/12i 0x{match[1]}")
            (dest/f"cpu{index}-instructions.txt").write_text(code)
            print(f"Stopped CPU {index} instructions:",code,flush=True)
        except Exception as exc:
            print("CPU instruction diagnostic unavailable:",exc,flush=True)
    qtree = hmp(qmp,"info qtree")
    mtree = hmp(qmp,"info mtree -f")
    (dest/"qtree.txt").write_text(qtree)
    (dest/"mtree.txt").write_text(mtree)
    cpu_info = qmp.execute("query-cpus-fast")
    kvm = qmp.execute("query-kvm")
    write_json(dest/"qmp-cpus.json",cpu_info)
    write_json(dest/"qmp-kvm.json",kvm)
    require(len(cpu_info)==cpus and len({c["cpu-index"] for c in cpu_info})==cpus,
            "QEMU actual vCPU count mismatch")
    require(bool(kvm["enabled"])==(accel=="kvm"), "Unexpected QEMU accelerator")
    require(not re.search(r"(?m)^\s*dev:\s*hpet(?:,|\s|$)",qtree,re.I) and
            not re.search(r"(?i)\bhpet\b",mtree), "HPET device or active mapping remains")
    require(re.search(r"(?m)^\s*dev:\s*(?:isa-pit|kvm-pit)(?:,|\s|$)",qtree),
            "No actual PIT device")
    require(bool(re.search(r"(?i)\b(?:acpi-tmr|ich9-pm)\b",mtree)) != disabled,
            "PM timer/bank mapping does not match requested profile")
    fixture = (dest/"fixture-debug.log").read_text(encoding="ascii",errors="replace")
    prepared,ebs=list(PREPARED.finditer(fixture)),list(EBS.finditer(fixture))
    require(len(prepared)==len(ebs)==1 and prepared[0].end()<ebs[0].start(),
            "Missing unique fixture preparation and EBS transition")
    require(fixture.count("FIXTURE VERIFIED LOAD\n")==1 and
            fixture.index("FIXTURE VERIFIED LOAD\n")<ebs[0].start(),
            "Unchanged production EFI not authenticated/started by firmware")
    st,port,r20,r10,invtsc=map(lambda v:int(v,16),prepared[0].groups())
    st2,port2,lpc,base,before,after,value=map(lambda v:int(v,16),ebs[0].groups())
    require(st==st2 and port==port2 and lpc==0x29188086 and base+8==port and
            before&0x80 and bool(after&0x80)!=callback_disabled and
            (value==0xffffffff)==callback_disabled,
            "Fixture EBS PM I/O state does not match profile")
    require(invtsc in (0,1), "Invalid guest CPUID evidence")
    files={}
    def read(address,size):
        require(type(address) is int and type(size) is int and
                4096<=address<ram and 0<size<=MAX_TABLE and address+size<=ram,
                "Firmware pointer outside bounded guest RAM")
        path=dest/f"guest-{address:08x}-{size}.bin"
        path.unlink(missing_ok=True)
        qmp.execute("pmemsave",{"val":address,"size":size,"filename":str(path)})
        data=path.read_bytes()
        require(len(data)==size,"Incomplete QEMU physical memory read")
        files[path.name]=smoke.evidence.sha256(path)
        return data
    tables=inspect_tables(read,st,r20,r10,cpus,None if hidden else port)
    if profile=="deferred":
        deferred=json.loads((dest/"deferred-removal.json").read_text())
        require(deferred["result"]=="pass" and deferred["system_table"]==st and
                deferred["pm_port"]==port and deferred["efi_status"]==0 and
                deferred["boot_services"]==0 and deferred["control_before"]&0x80 and
                not deferred["control_after"]&0x80 and deferred["port_after"]==0xffffffff,
                "Missing proven PM removal after successful EBS return")
    write_json(dest/"acpi-tables.json",tables)
    print("Actual EFI/ACPI tables:",json.dumps(tables,sort_keys=True),flush=True)
    # Independently read the former PM I/O port. Preserve the raw response
    # before checking its address, width and value.
    io = qmp.execute("human-monitor-command",{"command-line":f"i/xw {port:#x}"})
    require(isinstance(io,str),"Missing HMP I/O response")
    (dest/"pm-port-read.txt").write_text(io)
    print("Actual PM port read:",repr(io),flush=True)
    verify_pm_read(io,port,disabled)
    result={"result":"verified","profile":profile,"hpet_device_absent":True,"hpet_acpi_absent":True,
            "pm_timer_acpi_absent":hidden,"pm_io_decode_disabled":disabled,
            "former_pm_port":port,"former_pm_port_read":io.strip(),
            "pit_device_present":True,"guest_invariant_tsc":bool(invtsc),
            "accelerator":accel,"qmp_cpus":len(cpu_info),"qmp_kvm":kvm,
            "actual_efi_acpi":tables,"memory_artifacts_sha256":files,
            "qtree_sha256":smoke.evidence.sha256(dest/"qtree.txt"),
            "mtree_sha256":smoke.evidence.sha256(dest/"mtree.txt")}
    write_json(dest/"platform.json",result)
    print("Actual guest platform:",json.dumps(result,sort_keys=True),flush=True)
    return result


def run(cmd, **kwargs):
    return subprocess.run(cmd,check=True,cwd=ROOT,**kwargs)


def prepare_fixture(dest, signed_hash, args, image_path):
    keys=Path.home()/".local/share/agentos/stage1-test-keys"
    fixture=dest/"timer-fixture.efi"
    obj,elf,unsigned=(dest/n for n in ("timer-fixture.o","timer-fixture.so","timer-fixture.unsigned.efi"))
    run(["gcc-13","-I/usr/include/efi","-I/usr/include/efi/x86_64","-DGNU_EFI_USE_MS_ABI",
         "-O2","-Wall","-Wextra","-Werror","-fpic","-ffreestanding","-fno-stack-protector",
         "-fshort-wchar","-mno-red-zone",
         f"-DFIXTURE_HIDE_PM={int(args.profile!='chain')}",
         f"-DFIXTURE_DISABLE_PM={int(args.profile=='disabled')}",
         f"-DFIXTURE_DEFER_PM={int(args.profile=='deferred')}",
         "-c",str(ROOT/"scripts/tests/no-acpi-timers-efi.c"),"-o",str(obj)])
    run(["ld","-nostdlib","--build-id=none","-znocombreloc","-T","/usr/lib/elf_x86_64_efi.lds",
         "-shared","-Bsymbolic","/usr/lib/crt0-efi-x86_64.o",str(obj),"-L/usr/lib","-lefi","-lgnuefi","-o",str(elf)])
    run(["objcopy","--strip-all","-j",".text","-j",".sdata","-j",".data","-j",".dynamic",
         "-j",".dynsym","-j",".rela","-j",".reloc","--target=efi-app-x86_64",str(elf),str(unsigned)])
    run(["sbsign","--key",str(keys/"db.key"),"--cert",str(keys/"db.crt"),
         "--output",str(fixture),str(unsigned)])
    for path in (fixture, image_path):
        run(["sbverify","--cert",str(keys/"db.crt"),str(path)])
    # Separate isolated test ESP. The ordinary profile booted the same
    # AgentOS bytes from BOOTX64.EFI; this profile loads them via UEFI.
    raw=dest/"esp.raw"
    run(["bash","scripts/disk.sh",str(dest),str(fixture),"info both"])
    fat=f"{raw}@@1048576"
    run(["mcopy","-i",fat,str(image_path),"::EFI/BOOT/AGENTOS.EFI"])
    for remote,local,wanted in [
        ("BOOTX64.EFI","esp-fixture.efi",smoke.evidence.sha256(fixture)),
        ("AGENTOS.EFI","esp-agentos.efi",signed_hash),
    ]:
        run(["mcopy","-i",fat,"::EFI/BOOT/"+remote,str(dest/local)])
        require(smoke.evidence.sha256(dest/local)==wanted,"ESP file differs from signed input")
    vm_vars=dest/"OVMF_VARS.secboot.fd"
    owner="d7663630-f07a-4739-bc6f-b9f6d6444865"
    run(["virt-fw-vars","--input",str(args.ovmf_vars),"--output",str(vm_vars),
         "--set-pk",owner,str(keys/"db.crt"),"--add-kek",owner,str(keys/"db.crt"),
         "--add-db",owner,str(keys/"db.crt"),"--secure-boot"])
    der=subprocess.check_output(["openssl","x509","-in",str(keys/"db.crt"),"-outform","der"])
    require(der in vm_vars.read_bytes(),"Test signer absent from firmware variables")
    vars_info=run(["virt-fw-vars","--input",str(vm_vars),"--print","--verbose"],capture_output=True,text=True)
    (dest/"secureboot-vars.txt").write_text(vars_info.stdout+vars_info.stderr)
    return raw,vm_vars,smoke.evidence.sha256(fixture)


def scenario(args):
    commit=subprocess.check_output(["git","rev-parse","--verify","HEAD"],cwd=ROOT,text=True).strip()
    image=smoke.evidence.verify_build(ROOT,commit)
    require(image.get("profile","default")=="default","Only the ordinary signed EFI is permitted")
    digest=image["artifacts"]["agentos.efi"]
    image_path=ROOT/"build/agentos.efi"
    variant=getattr(args,"supervisor_image",None)
    variant_suffix="" if variant is None else "-sv-"+variant
    if variant is not None:
        paired=smoke.load("clock_supervisor_images","verify-supervisor-image.py")
        identity=paired.verify_identity(ROOT)
        if variant=="test":
            image_path=ROOT/"build/supervisor-staging/test.efi"
            digest=identity["test"]["signed_sha256"]
    baseline_path=ROOT/f"build/check/qemu-cpu{args.cpus}-session{variant_suffix}/smoke.json"
    baseline=json.loads(baseline_path.read_text())
    require(baseline["result"]=="pass" and baseline["source_commit"]==commit and
            baseline["signed_efi_sha256"]==digest and baseline["esp_boot_efi_sha256"]==digest and
            baseline["cpus"]==args.cpus and baseline["hpet_enabled"] and
            baseline["interactive_com1_manager_session"] and baseline.get("supervisor_image")==variant,
            "Missing ordinary interactive boot of the exact same signed EFI")
    suffix="no-acpi-timers" if args.profile=="disabled" else "clock-"+args.profile
    dest=ROOT/f"build/check/qemu-cpu{args.cpus}-{suffix}-session{variant_suffix}"
    # Never consume a previous result as current evidence.
    if dest.exists():
        shutil.rmtree(dest)
    dest.mkdir(parents=True)
    accel=args.accel
    if accel=="auto":
        accel="kvm" if os.access("/dev/kvm",os.R_OK|os.W_OK) else "tcg"
    receipt={"schema":1,"result":"fail","source_commit":commit,"cpus":args.cpus,
             "memory_mib":256,"signed_efi_sha256":digest,
             "ordinary_session_receipt_sha256":smoke.evidence.sha256(baseline_path),
             "ordinary_signed_efi_sha256":baseline["signed_efi_sha256"],
             "accelerator":accel,"requested_accelerator":args.accel,"profile":args.profile,
             "dev_kvm_accessible":os.access("/dev/kvm",os.R_OK|os.W_OK),
             "platform_verified":False,"boot_verified":False,
             "note":"QEMU-only; no VirtualBox/physical hardware claim"}
    if variant is not None:
        receipt["supervisor_image"]=variant
    start=time.monotonic()
    process=capture=qmp=None
    try:
        receipt["qemu_version"]=subprocess.check_output(["qemu-system-x86_64","--version"],text=True).splitlines()[0]
        # Matching direct KVM PM control (even failure is useful evidence).
        # A missing or differently configured comparison cannot imply causality.
        control=ROOT/f"build/check/qemu-cpu{args.cpus}-no-hpet-{accel}-session{variant_suffix}"
        for name in ("smoke.json","failure.json"):
            path=control/name
            if path.is_file():
                observed=json.loads(path.read_text())
                require(observed["source_commit"]==commit and observed["signed_efi_sha256"]==digest
                        and observed["accelerator"]==accel and observed.get("supervisor_image")==variant,
                        "Control was not the same signed EFI/accelerator")
                receipt["matched_direct_control"]={"result":observed["result"],
                    "receipt_sha256":smoke.evidence.sha256(path)}
                break
        if variant is not None:
            require(receipt.get("matched_direct_control",{}).get("result")=="pass",
                    "Missing matching signed PM supervisor control")
        raw,vars_file,fixture_hash=prepare_fixture(dest,digest,args,image_path)
        receipt["fixture_efi_sha256"]=fixture_hash
        receipt["esp_agentos_efi_sha256"]=smoke.evidence.sha256(dest/"esp-agentos.efi")
        receipt["ovmf_code_sha256"]=smoke.evidence.sha256(args.ovmf_code)
        require(receipt["ovmf_code_sha256"]==baseline["ovmf_code_sha256"],
                "Ordinary and fault-platform firmware code differs")
        # No force-features or fake CPUID. KVM is requested only when
        # available, and the CPU model must really provide invariant TSC.
        cpu="host,x2apic=off,invtsc=on,enforce=on" if accel=="kvm" else "max"
        serial_socket,qmp_socket,monitor_socket=(dest/name for name in ("uart.sock","qmp.sock","monitor.sock"))
        qemu=["qemu-system-x86_64","-machine",f"q35,accel={accel},smm=on,hpet=off",
              "-cpu",cpu,"-smp",str(args.cpus),"-m","256",
              "-global","driver=cfi.pflash01,property=secure,value=on",
              "-drive",f"if=pflash,format=raw,unit=0,readonly=on,file={args.ovmf_code}",
              "-drive",f"if=pflash,format=raw,unit=1,file={vars_file}",
              "-drive",f"if=none,format=raw,id=esp,file={raw}",
              "-device","ich9-ahci,id=sata","-device","ide-hd,drive=esp,bus=sata.0",
              "-monitor",f"unix:{monitor_socket},server=on,wait=off",
              "-qmp",f"unix:{qmp_socket},server=on,wait=off",
              "-chardev",f"socket,id=uart,path={serial_socket},server=on,wait=on",
              "-serial","chardev:uart","-debugcon",f"file:{dest/'fixture-debug.log'}",
              "-global","isa-debugcon.iobase=0xe9","-vga","std","-display","none",
              "-nic","none","-boot","order=c","-no-reboot","-no-shutdown"]
        if args.profile=="deferred":
            # UNIX socket inside the private run directory. QEMU is not
            # listening for external debug connections on a network port.
            qemu.extend(["-chardev",f"socket,id=ebsdbg,path={dest/'ebs-gdb.sock'},server=on,wait=off",
                         "-gdb","chardev:ebsdbg"])
        write_json(dest/"qemu-command.json",qemu)
        serial=dest/"com1.log"
        with (dest/"qemu-stderr.log").open("wb") as diagnostics:
            process=subprocess.Popen(qemu,cwd=ROOT,stdin=subprocess.DEVNULL,
                                     stdout=diagnostics,stderr=subprocess.STDOUT)
            capture=smoke.UartCapture(smoke.connect_uart(serial_socket,process),serial)
            last_progress=time.monotonic()
            last_size=-1
            deadline=last_progress+args.timeout
            deferred_done=False
            try:
                while time.monotonic()<deadline:
                    if args.profile=="deferred" and not deferred_done:
                        debug=dest/"fixture-debug.log"
                        if debug.exists():
                            matches=list(DEFER.finditer(debug.read_text(encoding="ascii",errors="replace")))
                            if len(matches)==1:
                                entry,child,size,st,port=map(lambda value:int(value,16),matches[0].groups())
                                require(4096<=entry<256*1024*1024 and 4096<=child and
                                        0<size<=16*1024*1024 and child+size<=256*1024*1024 and
                                        4096<=st<256*1024*1024-120 and 0<port<65536,
                                        "Invalid fixture debugger rendezvous")
                                request=dest/"deferred-request.json"
                                write_json(request,{"entry":entry,"child_base":child,"child_size":size,
                                    "system_table":st,"pm_port":port,"destination":str(dest)})
                                env=dict(os.environ,AGENTOS_EBS_REQUEST=str(request))
                                with (dest/"ebs-gdb.log").open("wb") as gdb_log:
                                    completed=subprocess.run(["gdb","-nx","-nh","-batch",
                                        "-ex","set pagination off","-ex","set confirm off",
                                        "-ex",f"target remote {dest/'ebs-gdb.sock'}",
                                        "-x",str(ROOT/"scripts/tests/defer-pm-gdb.py")],
                                        cwd=ROOT,env=env,stdout=gdb_log,stderr=subprocess.STDOUT,timeout=60)
                                print("Post-EBS debugger:",(dest/"ebs-gdb.log").read_text(errors="replace"),flush=True)
                                require(completed.returncode==0 and (dest/"deferred-removal.json").is_file(),
                                        "Post-EBS hardware removal did not complete")
                                deferred_done=True
                                last_progress=time.monotonic()
                    data=serial.read_bytes() if serial.exists() else b""
                    if capture.error:
                        raise RuntimeError(f"UART capture stopped: {capture.error}")
                    if re.search(rb"SMP FAILED|FATAL VECTOR|SHELL FAILED|AGENTOS KERNEL PANIC",data):
                        raise RuntimeError("Guest reported kernel failure")
                    if b"AGENTOS SHELL READY\r\nagentos> " in data:
                        qmp=smoke.Qmp(qmp_socket)
                        qmp.screenshot(dest/"shell-screen.ppm")
                        smoke.console.verify(dest/"shell-screen.ppm",aLevel="info",aOutput="both")
                        smoke.run_session(process,capture,qmp,dest,variant is not None,variant)
                        break
                    if process.poll() is not None:
                        raise RuntimeError(f"QEMU exited before shell: {process.returncode}")
                    if len(data)!=last_size:
                        last_size=len(data)
                        last_progress=time.monotonic()
                    if time.monotonic()-last_progress>90:
                        raise TimeoutError("No guest COM1 progress for 90 seconds")
                    time.sleep(0.1)
                else:
                    raise TimeoutError("Guest did not reach a complete interactive session")
                # Full standard session except for its explicit watchdog
                # budget. Never substitute a transcript for a real session.
                require(args.profile!="deferred" or deferred_done,"No completed post-EBS removal")
                data=serial.read_bytes()
                text=data.decode("ascii",errors="replace")
                smoke.boot_log.verify(data,"info","both")
                clocks=re.findall(r"(?m)^\[INFO\] SYSTEM CLOCK: (HPET64|HPET32|ACPI PM24|ACPI PM32|TSC \(qualified invariant clocksource\))\r?$",text)
                expected=("ACPI PM24","ACPI PM32") if args.profile=="chain" else ("TSC (qualified invariant clocksource)",)
                require(len(clocks)==1 and clocks[0] in expected,
                        "No unique expected actual clock selection")
                apics=[int(x,16) for x in re.findall(
                    r"(?m)^AGENTOS TASK (?:BSP|AP) APIC=([0-9a-f]{16}) TIMER-WAKES=0000000000000003\r?$",text)]
                require(len(apics)==len(set(apics))==args.cpus,"Missing actual per-CPU timer wakes")
                if args.profile!="chain":
                    # Ordinary diagnostics of the actual boot-qualified
                    # fleet, not fabricated test-only CPU capabilities.
                    qualified={}
                    for cpu,hz,offset,error in re.findall(
                        r"(?m)^\[INFO\] TSC APIC=(\d+) HZ=(\d+) OFFSET=(-?\d+) ERROR-TICKS=(\d+)\r?$",text):
                        qualified[int(cpu)]=(int(hz),int(offset),int(error))
                    require(set(qualified)==set(apics),"Incomplete qualified TSC diagnostic roster")
                    bsp=int(re.search(r"(?m)^AGENTOS TASK BSP APIC=([0-9a-f]{16}) ",text)[1],16)
                    rate=qualified[bsp][0]
                    require(rate>0 and qualified[bsp][1:]==(0,0),"Invalid BSP TSC qualification")
                    require(all(hz>0 and abs(hz-rate)*1000<=min(hz,rate) and
                                error*1_000_000_000<=rate*100_000
                                for hz,offset,error in qualified.values()),
                            "Inconsistent TSC fleet diagnostics")
                    receipt["qualified_tsc_cpus"]=qualified
                receipt["boot_roots"]=smoke.processes.verify(text,apics,ipc_staged=True,
                    allow_ipc_workload=variant=="test",root_orphan_v1=True,require_shutdown=True)
                receipt["boot_process_contract"]="root-orphan-v1"
                if variant!="test":
                    smoke.supervisor.verify_absent(text)
                # Staged proof is mandatory in the full runtime session below.
                smoke.orphans.verify(text,args.cpus)
                if variant!="test":
                    smoke.cow.verify_absent(text)
                    smoke.demand.verify_absent(text)
                smoke.migration.verify_boot(text,allow_foreground=variant=="test")
                smoke.service_manager.verify(text,migration_staged=True,allow_migration_workload=variant=="test")
                receipt["runtime_session"]=smoke.session.verify(data,(dest/"com1-input.bin").read_bytes(),
                    True,args.cpus,aClockMaintenanceMs=1000,aRuntimeProcess=variant is not None,
                    aSupervisorImage=variant,aMigrationStaged=True,aFaultStaged=True)
                receipt["migration_contract"]="foreground-v1"
                receipt["migration"]=receipt["runtime_session"].get("runtime_migration",{"absent":True})
                receipt["fault_contract"]="staged-v1"
                receipt["fault"]=receipt["runtime_session"].get("runtime_fault",{"absent":True})
                receipt["com1_input_sha256"]=smoke.evidence.sha256(dest/"com1-input.bin")
                receipt["system_clock"]=clocks[0]
                receipt["boot_verified"]=True
            finally:
                # Always try to preserve independent platform evidence,
                # even after a kernel refusal or timeout. Never treat an
                # unavailable proof as a successful no-reference boot.
                try:
                    if qmp is None:
                        qmp=smoke.Qmp(qmp_socket)
                    if not receipt["boot_verified"]:
                        try:
                            qmp.screenshot(dest/"failed-screen.ppm")
                        except Exception as exc:
                            print("Failure screenshot unavailable:",exc,file=sys.stderr,flush=True)
                    platform=capture_platform(qmp,dest,args.cpus,accel,256*1024*1024,args.profile)
                    receipt["platform_verified"]=True
                    receipt["guest_invariant_tsc"]=platform["guest_invariant_tsc"]
                    receipt["platform_sha256"]=smoke.evidence.sha256(dest/"platform.json")
                except Exception as exc:
                    receipt["platform_failure"]=str(exc)
                    print("Independent platform proof unavailable:",exc,file=sys.stderr,flush=True)
        require(receipt["boot_verified"] and receipt["platform_verified"] and
                receipt.get("guest_invariant_tsc") is True,
                "Missing actual successful qualified TSC boot or independently verified platform")
        receipt["result"]="pass"
    except Exception as exc:
        receipt["failure"]=str(exc)
        print("No-ACPI-timers scenario:",exc,file=sys.stderr,flush=True)
    finally:
        if qmp is not None:
            qmp.close()
        if capture is not None:
            capture.close()
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=10)
        for name in ("com1.log","fixture-debug.log","qemu-stderr.log"):
            path=dest/name
            if path.exists():
                receipt[name+"_sha256"]=smoke.evidence.sha256(path)
                if name=="com1.log":
                    data=path.read_bytes()
                    lines=data.decode("ascii",errors="replace").splitlines()
                    receipt["clock_diagnostics"]=[line for line in lines if
                        any(key in line for key in ("SYSTEM CLOCK:","BRINGUP CLOCK:",
                            "TSC-HZ=","TSC APIC=","TSC CPU","PIT TSC APIC=","AGENTOS TASK ","SMP FAILED"))][:80]
                    receipt["fallback_selected"]=("[INFO] SYSTEM CLOCK: TSC (qualified invariant clocksource)" in lines)
                    receipt["shell_ready"]=b"AGENTOS SHELL READY\r\nagentos> " in data
                    print("Actual clock/CPU diagnostics:",json.dumps(receipt["clock_diagnostics"]),flush=True)
                if receipt["result"]!="pass":
                    print(f"{name} tail:\n"+path.read_bytes()[-4096:].decode("ascii",errors="replace"),
                          file=sys.stderr,flush=True)
        receipt["host_elapsed_seconds"]=round(time.monotonic()-start,3)
        write_json(dest/"scenario.json",receipt)
        print("No-ACPI-timers receipt:",json.dumps(receipt,sort_keys=True),flush=True)
    return 0 if receipt["result"]=="pass" else 1


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cpus",type=int,choices=(1,2),required=True)
    parser.add_argument("--accel",choices=("auto","tcg","kvm"),default="auto")
    parser.add_argument("--profile",choices=("chain","hidden","disabled","deferred"),default="disabled",
                        help="Chain retains PM; hidden omits FADT PM; disabled removes PM during EBS; deferred removes after EBS return")
    parser.add_argument("--ovmf-code",type=Path,required=True)
    parser.add_argument("--ovmf-vars",type=Path,required=True)
    parser.add_argument("--timeout",type=int,default=360)
    parser.add_argument("--supervisor-image",choices=("control","test"))
    args=parser.parse_args()
    try:
        return scenario(args)
    except Exception as exc:
        print("No-ACPI-timers precondition failed:",exc,file=sys.stderr)
        return 1


if __name__=="__main__":
    sys.exit(main())
