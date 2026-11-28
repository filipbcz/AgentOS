"""Real xHCI command/event DMA and USB hotplug in isolated QEMU.

The host attaches and detaches an emulated keyboard through QMP only after
the guest owns the controller. Controller traces provide independent proof
of actual TRB fetch, event DMA, cycle wraps, port reset and slot lifecycle.
"""
import argparse
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time

sys.dont_write_bytecode=True
import xhci_evidence as xhci

ROOT=Path(__file__).resolve().parent.parent
SPEC=importlib.util.spec_from_file_location("qemu_net_helpers",ROOT/"scripts/qemu-virtio-net.py")
net=importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(net)
smoke=net.smoke
helpers=net.helpers
write_json=helpers.write_json
require=xhci.require


def info_usb(monitor):
    return monitor.execute("human-monitor-command",{"command-line":"info usb"})


def run(args):
    sha=smoke.evidence.sha256
    commit=subprocess.check_output(["git","rev-parse","--verify","HEAD"],cwd=ROOT,text=True).strip()
    build=smoke.evidence.verify_build(ROOT,commit)
    require(build.get("profile")=="xhci","Build with scripts/build.sh --xhci first")
    root=ROOT/"build/check"/f"qemu-xhci-cpu{args.cpus}"
    root.mkdir(parents=True,exist_ok=True)
    out=Path(tempfile.mkdtemp(prefix="run-",dir=root))
    print(f"QEMU_XHCI_DIR={out}",flush=True)
    try:
        oom_proof=smoke.physical_oom.run(ROOT,out,commit)
        subprocess.run(["bash","scripts/disk.sh",str(out),"build/agentos.efi","info both"],cwd=ROOT,check=True)
        esp=out/"esp.raw";copied=out/"esp-bootx64.efi"
        subprocess.run(["mcopy","-i",f"{esp}@@1048576","::EFI/BOOT/BOOTX64.EFI",str(copied)],check=True)
        require(sha(copied)==build["artifacts"]["agentos.efi"],"ESP differs from signed image")
        vars_file=out/"OVMF_VARS.secboot.fd"
        cert=Path.home()/".local/share/agentos/stage1-test-keys/db.crt"
        owner="d7663630-f07a-4739-bc6f-b9f6d6444865"
        subprocess.run(["virt-fw-vars","--input",str(args.ovmf_vars),"--output",str(vars_file),
                        "--set-pk",owner,str(cert),"--add-kek",owner,str(cert),
                        "--add-db",owner,str(cert),"--secure-boot"],check=True)
        der=subprocess.check_output(["openssl","x509","-in",str(cert),"-outform","der"])
        require(der in vars_file.read_bytes(),"Missing enrolled signer")
        trace_events=out/"trace-events.txt"
        trace_events.write_text("\n".join(xhci.TRACE_EVENTS)+"\n",encoding="ascii")
        trace=out/"xhci-trace.log"
        serial=out/"com1.log"
        capture=monitor=process=None
        with tempfile.TemporaryDirectory(prefix="agentos-xhci-") as directory:
            uart=Path(directory)/"uart";qmp=Path(directory)/"qmp";hmp=Path(directory)/"hmp"
            cmd=["qemu-system-x86_64","-trace",f"events={trace_events}","-D",str(trace),
                 "-machine","q35,accel=tcg,smm=on,hpet=on","-cpu","max","-smp",str(args.cpus),"-m","256",
                 "-global","driver=cfi.pflash01,property=secure,value=on",
                 "-drive",f"if=pflash,format=raw,unit=0,readonly=on,file={args.ovmf_code}",
                 "-drive",f"if=pflash,format=raw,unit=1,file={vars_file}",
                 "-drive",f"if=none,format=raw,id=esp,file={esp}",
                 "-device","ich9-ahci,id=sata","-device","ide-hd,drive=esp,bus=sata.0,bootindex=1",
                 "-device","qemu-xhci,id=agentos-xhci,p2=2,p3=2",
                 "-chardev",f"socket,id=uart,path={uart},server=on,wait=on",
                 "-serial","chardev:uart","-qmp",f"unix:{qmp},server=on,wait=off",
                 "-monitor",f"unix:{hmp},server=on,wait=off",
                 "-display","none","-vga","std","-nic","none","-boot","order=c","-no-reboot","-no-shutdown"]
            write_json(out/"command.json",cmd)
            started=time.monotonic()
            with (out/"qemu-stderr.log").open("wb") as diagnostic:
                try:
                    process=subprocess.Popen(cmd,cwd=ROOT,stdin=subprocess.DEVNULL,
                                             stdout=diagnostic,stderr=subprocess.STDOUT)
                    capture=smoke.UartCapture(smoke.connect_uart(uart,process),serial)
                    helpers.wait_guest(process,capture,serial,b"AGENTOS XHCI READY ",args.timeout)
                    ready=smoke.wait_session(process,capture,serial,
                        lambda data:re.search(rb"AGENTOS XHCI READY [^\r\n]+ RING=16\r\n",data),
                        "xHCI command/event rings",10)
                    monitor=smoke.Qmp(qmp)
                    pci=monitor.execute("query-pci")
                    write_json(out/"pci.json",pci)
                    bdf=xhci.verify_pci(ready.decode("ascii",errors="replace"),pci)
                    before=info_usb(monitor)
                    require("ID: agentos-kbd" not in before,"Keyboard attached before guest owns xHCI")
                    (out/"usb-before.txt").write_text(before)
                    prefix=trace.read_bytes()
                    require(prefix.endswith(b"\n") and b"usb_xhci_run" in prefix,
                            "No controller trace before hotplug")
                    offset=len(prefix)
                    write_json(out/"trace-start.json",{"offset":offset})
                    monitor.execute("device_add",{"driver":"usb-kbd","id":"agentos-kbd",
                                                 "bus":"agentos-xhci.0","port":"1"})
                    attached=info_usb(monitor)
                    (out/"usb-attached.txt").write_text(attached)
                    require("ID: agentos-kbd" in attached,"QMP failed to attach keyboard")
                    smoke.wait_session(process,capture,serial,
                        lambda data:re.search(rb"AGENTOS XHCI WAIT DETACH PORT=\d+\r\n",data),
                        "xHCI port reset and 42 completed commands",90)
                    monitor.execute("device_del",{"id":"agentos-kbd"})
                    helpers.wait_guest(process,capture,serial,b"AGENTOS XHCI CLOSED HALTED=1 MASTER=0 DMA=4\r\n",30)
                    detached=info_usb(monitor)
                    (out/"usb-detached.txt").write_text(detached)
                    speed=xhci.usb_speed(before,attached,detached)
                    data=helpers.wait_guest(process,capture,serial,b"AGENTOS SHELL READY\r\nagentos> ",args.timeout)
                    info=xhci.verify_guest(data.decode("ascii",errors="replace"),speed)
                    whole=trace.read_bytes()
                    require(whole.startswith(prefix),"Controller trace changed")
                    phase=whole[offset:].decode("utf-8",errors="strict")
                    (out/"xhci-exercise-trace.log").write_text(phase)
                    independent=xhci.verify_trace(phase,info)
                    net.verify_kernel(data,args.cpus,physical_oom_dir=out,source_commit=commit)
                    monitor.screenshot(out/"shell-screen.ppm")
                    smoke.console.verify(out/"shell-screen.ppm",aLevel="info",aOutput="both")
                    monitor.execute("quit")
                    require(process.wait(timeout=15)==0,"QEMU did not exit cleanly")
                    files=("physical-oom.log","physical-oom.json","command.json","pci.json","com1.log","usb-before.txt","usb-attached.txt",
                           "usb-detached.txt","trace-start.json","trace-events.txt","xhci-trace.log",
                           "xhci-exercise-trace.log","shell-screen.ppm","esp-bootx64.efi","OVMF_VARS.secboot.fd")
                    receipt={"schema":1,"result":"pass","source_commit":commit,"cpus":args.cpus,
                             "physical_oom":oom_proof,"signed_efi_sha256":build["artifacts"]["agentos.efi"],"pci_bdf":bdf,
                             "ovmf_code_sha256":sha(args.ovmf_code),
                             "emulator":subprocess.check_output(["qemu-system-x86_64","--version"],text=True).splitlines()[0],
                             "seconds":round(time.monotonic()-started,3),
                             "port":info["port"],"slot":info["slot"],"speed_id":speed,**independent,
                             "artifacts":{name:sha(out/name) for name in files}}
                    write_json(out/"xhci.json",receipt)
                    print("QEMU_XHCI_PASS="+json.dumps(receipt,sort_keys=True),flush=True)
                except Exception:
                    smoke.snapshot(hmp,out/"failure.ppm")
                    tail=serial.read_bytes()[-6000:] if serial.exists() else b""
                    print("QEMU xHCI COM1 failure tail:\n"+tail.decode("ascii",errors="replace"),
                          file=sys.stderr,flush=True)
                    if trace.exists():
                        print("xHCI trace tail:\n"+trace.read_text(errors="replace")[-4000:],file=sys.stderr)
                    raise
                finally:
                    if monitor is not None:monitor.close()
                    if capture is not None:capture.close()
                    if process is not None and process.poll() is None:
                        process.terminate()
                        try:process.wait(timeout=10)
                        except subprocess.TimeoutExpired:process.kill();process.wait(timeout=10)
    except Exception as error:
        write_json(out/"failure.json",{"result":"fail","source_commit":commit,"cpus":args.cpus,"failure":str(error)})
        raise


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cpus",type=int,choices=(1,2),required=True)
    parser.add_argument("--ovmf-code",type=Path,required=True)
    parser.add_argument("--ovmf-vars",type=Path,required=True)
    parser.add_argument("--timeout",type=int,default=300)
    try:run(parser.parse_args())
    except Exception as error:
        print(f"QEMU xHCI failed: {error}",file=sys.stderr,flush=True)
        return 1
    return 0


if __name__=="__main__":sys.exit(main())
