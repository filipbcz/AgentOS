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


def read_root(read, address, width, cpus):
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
    require(uint(fadt, 76, 4) == 0 and fadt[91] == 0, "Legacy PM timer still exposed")
    require(uint(fadt,112,4) & ((1<<8)|(1<<15)|(1<<20)) == 0,
            "Unexpected PM clock flags or hardware-reduced platform")
    require(len(fadt) <= 208 or (len(fadt) >= 220 and fadt[208:220] == bytes(12)),
            "Extended PM timer GAS remains exposed or truncated")
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
            "fadt_address":fadt_addr,"fadt_pm_tmr_blk":0,"fadt_pm_tmr_len":0,
            "fadt_x_pm_tmr_blk":fadt[208:220].hex() if len(fadt)>=220 else None,
            "madt_address":madt_addr,"enabled_apic_ids":sorted(ids)}


def read_rsdp(read, address, extended, cpus):
    first = read(address,20)
    require(first[:8] == b"RSD PTR " and checksum(first), "Invalid RSDP checksum")
    roots = []
    rsdt = uint(first,16,4)
    if rsdt:
        roots.append(read_root(read,rsdt,4,cpus))
    if extended or first[15] >= 2:
        head = read(address,36)
        size = uint(head,20,4)
        require(first[15]>=2 and 36<=size<=MAX_TABLE, "Invalid extended RSDP")
        full = read(address,size)
        require(full[:20]==first and checksum(full), "Invalid extended RSDP checksum")
        roots.append(read_root(read,uint(full,24,8),8,cpus))
    require(roots, "Empty ACPI root set")
    require(all(r["enabled_apic_ids"]==roots[0]["enabled_apic_ids"] for r in roots),
            "ACPI root CPU disagreement")
    return roots


def inspect_tables(read, st, rsdp20, rsdp10, cpus):
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
        roots.extend(read_rsdp(read,address,guid==ACPI20,cpus))
    require(all(r["enabled_apic_ids"]==roots[0]["enabled_apic_ids"] for r in roots),
            "Enabled CPU disagreement between EFI ACPI versions")
    return {"system_table":st,"rsdp20":rsdp20,"rsdp10":rsdp10,"roots":roots}


def hmp(qmp, command):
    result = qmp.execute("human-monitor-command",{"command-line":command})
    require(isinstance(result,str) and result.strip() and
            not re.search(r"unknown command|invalid parameter|error:",result,re.I),
            f"HMP command failed: {command}: {result!r}")
    return result


def capture_platform(qmp, dest, cpus, accel, ram):
    # Do not pause a live finite-PIT epoch during the session. This is
    # called only after session completion or a recorded boot failure.
    qmp.execute("stop")
    state = qmp.execute("query-status")
    require(not state["running"], "QEMU did not pause for final read-only inspection")
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
    require(not re.search(r"(?i)\b(?:acpi-tmr|ich9-pm)\b",mtree),
            "ACPI PM timer/bank still mapped in a flat address space")
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
            before&0x80 and not after&0x80 and value==0xffffffff,
            "Fixture did not disable actual ICH9 PM I/O decode at EBS")
    require(invtsc in (0,1), "Invalid guest CPUID evidence")
    # An independent emulator port read after EBS must also be unmapped.
    # The fixture's own observation by itself is not sufficient.
    io = hmp(qmp,f"i/lx {port:#x}")
    (dest/"pm-port-read.txt").write_text(io)
    require(re.search(r"\b0xffffffff\b",io,re.I), "Former PM timer I/O port remains readable")
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
    tables=inspect_tables(read,st,r20,r10,cpus)
    result={"result":"verified","hpet_device_absent":True,"hpet_acpi_absent":True,
            "pm_timer_acpi_absent":True,"pm_io_decode_disabled":True,
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


def prepare_fixture(dest, signed_hash, args):
    keys=Path.home()/".local/share/agentos/stage1-test-keys"
    fixture=dest/"timer-fixture.efi"
    obj,elf,unsigned=(dest/n for n in ("timer-fixture.o","timer-fixture.so","timer-fixture.unsigned.efi"))
    run(["gcc-13","-I/usr/include/efi","-I/usr/include/efi/x86_64","-DGNU_EFI_USE_MS_ABI",
         "-O2","-Wall","-Wextra","-Werror","-fpic","-ffreestanding","-fno-stack-protector",
         "-fshort-wchar","-mno-red-zone","-c",str(ROOT/"scripts/tests/no-acpi-timers-efi.c"),"-o",str(obj)])
    run(["ld","-nostdlib","--build-id=none","-znocombreloc","-T","/usr/lib/elf_x86_64_efi.lds",
         "-shared","-Bsymbolic","/usr/lib/crt0-efi-x86_64.o",str(obj),"-L/usr/lib","-lefi","-lgnuefi","-o",str(elf)])
    run(["objcopy","--strip-all","-j",".text","-j",".sdata","-j",".data","-j",".dynamic",
         "-j",".dynsym","-j",".rela","-j",".reloc","--target=efi-app-x86_64",str(elf),str(unsigned)])
    run(["sbsign","--key",str(keys/"db.key"),"--cert",str(keys/"db.crt"),
         "--output",str(fixture),str(unsigned)])
    for path in (fixture, ROOT/"build/agentos.efi"):
        run(["sbverify","--cert",str(keys/"db.crt"),str(path)])
    # Separate isolated test ESP. The ordinary profile booted the same
    # AgentOS bytes from BOOTX64.EFI; this profile loads them via UEFI.
    raw=dest/"esp.raw"
    run(["bash","scripts/disk.sh",str(dest),str(fixture),"info both"])
    fat=f"{raw}@@1048576"
    run(["mcopy","-i",fat,str(ROOT/"build/agentos.efi"),"::EFI/BOOT/AGENTOS.EFI"])
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
    baseline_path=ROOT/f"build/check/qemu-cpu{args.cpus}-session/smoke.json"
    baseline=json.loads(baseline_path.read_text())
    require(baseline["result"]=="pass" and baseline["source_commit"]==commit and
            baseline["signed_efi_sha256"]==digest and baseline["esp_boot_efi_sha256"]==digest and
            baseline["cpus"]==args.cpus and baseline["hpet_enabled"] and
            baseline["interactive_com1_manager_session"],
            "Missing ordinary interactive boot of the exact same signed EFI")
    dest=ROOT/f"build/check/qemu-cpu{args.cpus}-no-acpi-timers-session"
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
             "accelerator":accel,"requested_accelerator":args.accel,
             "dev_kvm_accessible":os.access("/dev/kvm",os.R_OK|os.W_OK),
             "platform_verified":False,"boot_verified":False,
             "note":"QEMU-only; no VirtualBox/physical hardware claim"}
    start=time.monotonic()
    process=capture=qmp=None
    try:
        receipt["qemu_version"]=subprocess.check_output(["qemu-system-x86_64","--version"],text=True).splitlines()[0]
        raw,vars_file,fixture_hash=prepare_fixture(dest,digest,args)
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
        write_json(dest/"qemu-command.json",qemu)
        serial=dest/"com1.log"
        with (dest/"qemu-stderr.log").open("wb") as diagnostics:
            process=subprocess.Popen(qemu,cwd=ROOT,stdin=subprocess.DEVNULL,
                                     stdout=diagnostics,stderr=subprocess.STDOUT)
            capture=smoke.UartCapture(smoke.connect_uart(serial_socket,process),serial)
            last_progress=time.monotonic()
            last_size=-1
            deadline=last_progress+args.timeout
            try:
                while time.monotonic()<deadline:
                    data=serial.read_bytes() if serial.exists() else b""
                    if capture.error:
                        raise RuntimeError(f"UART capture stopped: {capture.error}")
                    if re.search(rb"SMP FAILED|FATAL VECTOR|SHELL FAILED|AGENTOS KERNEL PANIC",data):
                        raise RuntimeError("Guest reported kernel failure")
                    if b"AGENTOS SHELL READY\r\nagentos> " in data:
                        qmp=smoke.Qmp(qmp_socket)
                        qmp.screenshot(dest/"shell-screen.ppm")
                        smoke.console.verify(dest/"shell-screen.ppm",aLevel="info",aOutput="both")
                        smoke.run_session(process,capture,qmp,dest)
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
                data=serial.read_bytes()
                text=data.decode("ascii",errors="replace")
                smoke.boot_log.verify(data,"info","both")
                clocks=re.findall(r"(?m)^\[INFO\] SYSTEM CLOCK: (HPET64|HPET32|ACPI PM24|ACPI PM32|TSC \(independent finite PIT watchdog\))\r?$",text)
                require(clocks==["TSC (independent finite PIT watchdog)"],
                        "No unique actual TSC/PIT clock selection")
                apics=[int(x,16) for x in re.findall(
                    r"(?m)^AGENTOS TASK (?:BSP|AP) APIC=([0-9a-f]{16}) TIMER-WAKES=0000000000000003\r?$",text)]
                require(len(apics)==len(set(apics))==args.cpus,"Missing actual per-CPU timer wakes")
                smoke.processes.verify(text,apics)
                smoke.supervisor.verify(text,args.cpus)
                smoke.orphans.verify(text,args.cpus)
                smoke.cow.verify(text,args.cpus)
                smoke.demand.verify(text,args.cpus)
                receipt["migration"]=smoke.migration.verify(text,args.cpus)
                smoke.service_manager.verify(text)
                receipt["runtime_session"]=smoke.session.verify(data,(dest/"com1-input.bin").read_bytes(),
                    True,args.cpus,aClockMaintenanceMs=10)
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
                        qmp.screenshot(dest/"failed-screen.ppm")
                    platform=capture_platform(qmp,dest,args.cpus,accel,256*1024*1024)
                    receipt["platform_verified"]=True
                    receipt["guest_invariant_tsc"]=platform["guest_invariant_tsc"]
                    receipt["platform_sha256"]=smoke.evidence.sha256(dest/"platform.json")
                except Exception as exc:
                    receipt["platform_failure"]=str(exc)
                    print("Independent platform proof unavailable:",exc,file=sys.stderr,flush=True)
        require(receipt["boot_verified"] and receipt["platform_verified"] and
                receipt.get("guest_invariant_tsc") is True,
                "Missing actual successful TSC/PIT boot or independently verified platform")
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
    parser.add_argument("--ovmf-code",type=Path,required=True)
    parser.add_argument("--ovmf-vars",type=Path,required=True)
    parser.add_argument("--timeout",type=int,default=360)
    args=parser.parse_args()
    try:
        return scenario(args)
    except Exception as exc:
        print("No-ACPI-timers precondition failed:",exc,file=sys.stderr)
        return 1


if __name__=="__main__":
    sys.exit(main())
