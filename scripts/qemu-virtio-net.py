"""Real modern VirtIO-net RX/TX in a signed QEMU/OVMF boot.

Socketpair is private to this process and QEMU. No bridge, tap, NAT, external
network, or host interface is exposed. QEMU's filter-dump provides an
independent Ethernet capture. The guest does not see the challenge on UART.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import socket
import struct
import subprocess
import sys
import tempfile
import time

sys.dont_write_bytecode = True
import virtio_net_evidence as net

ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location("qemu_nvme_helpers", ROOT / "scripts/qemu-nvme.py")
helpers = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(helpers)
smoke = helpers.smoke
write_json = helpers.write_json
require = net.require


def receive_exact(link, count, deadline):
    chunks = bytearray()
    while len(chunks) < count:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("Ethernet socket receive deadline")
        link.settimeout(remaining)
        chunk = link.recv(count-len(chunks))
        if not chunk:
            raise RuntimeError("QEMU Ethernet socket disconnected")
        chunks.extend(chunk)
    return bytes(chunks)


def receive_frame(link):
    deadline = time.monotonic() + 15
    length, = struct.unpack("!I", receive_exact(link, 4, deadline))
    require(14 <= length <= 1514, "Invalid QEMU socket Ethernet length")
    return receive_exact(link, length, deadline)


def exchange(link, records_path):
    records = []
    for number in range(1, net.ROUNDS+1):
        incoming = net.challenge(os.urandom(net.SIZE-14))
        link.settimeout(10)
        link.sendall(struct.pack("!I",len(incoming)) + incoming)
        outgoing = receive_frame(link)
        records.append({"round": number, "host_tx": incoming.hex(), "host_rx": outgoing.hex()})
        write_json(records_path, records)
        require(outgoing == net.reply(incoming), f"Ethernet reply {number} differs from challenge")
        print(f"VirtIO-net round {number}: {len(incoming)} RX, {len(outgoing)} TX, "
              f"{net.fnv(incoming)} -> {net.fnv(outgoing)}", flush=True)
    return records


def verify_kernel(data, cpus):
    text = data.decode("ascii",errors="replace")
    smoke.boot_log.verify(data,"info","both")
    apics = re.findall(r"(?m)^AGENTOS TASK (?:BSP|AP) APIC=([0-9a-f]{16}) "
                       r"TIMER-WAKES=0000000000000003\r?$",text)
    require(len(apics)==cpus and len(set(apics))==cpus,"Missing real per-CPU timer evidence")
    smoke.processes.verify(text,[int(x,16) for x in apics],ipc_staged=True)
    smoke.supervisor.verify_absent(text)
    smoke.orphans.verify(text,cpus)
    smoke.cow.verify_absent(text)
    smoke.demand.verify_absent(text)
    smoke.migration.verify(text,cpus)
    smoke.service_manager.verify(text)


def run(args):
    sha = smoke.evidence.sha256
    commit = subprocess.check_output(["git","rev-parse","--verify","HEAD"],cwd=ROOT,text=True).strip()
    build = smoke.evidence.verify_build(ROOT,commit)
    require(build.get("profile")=="virtio-net","Build with scripts/build.sh --virtio-net first")
    root = ROOT / "build/check" / f"qemu-virtio-net-cpu{args.cpus}"
    root.mkdir(parents=True,exist_ok=True)
    out = Path(tempfile.mkdtemp(prefix="run-",dir=root))
    print(f"QEMU_VIRTIO_NET_DIR={out}",flush=True)
    try:
        subprocess.run(["bash","scripts/disk.sh",str(out),"build/agentos.efi","info both"],cwd=ROOT,check=True)
        esp = out/"esp.raw"
        copied = out/"esp-bootx64.efi"
        subprocess.run(["mcopy","-i",f"{esp}@@1048576","::EFI/BOOT/BOOTX64.EFI",str(copied)],check=True)
        require(sha(copied)==build["artifacts"]["agentos.efi"],"ESP differs from signed image")
        vars_file = out/"OVMF_VARS.secboot.fd"
        cert = Path.home()/".local/share/agentos/stage1-test-keys/db.crt"
        owner = "d7663630-f07a-4739-bc6f-b9f6d6444865"
        subprocess.run(["virt-fw-vars","--input",str(args.ovmf_vars),"--output",str(vars_file),
                        "--set-pk",owner,str(cert),"--add-kek",owner,str(cert),
                        "--add-db",owner,str(cert),"--secure-boot"],check=True)
        der = subprocess.check_output(["openssl","x509","-in",str(cert),"-outform","der"])
        require(der in vars_file.read_bytes(),"Missing enrolled signer")
        serial = out/"com1.log"
        capture = monitor = process = None
        with tempfile.TemporaryDirectory(prefix="agentos-net-") as directory:
            uart = Path(directory)/"uart"
            qmp = Path(directory)/"qmp"
            hmp = Path(directory)/"hmp"
            host, peer = socket.socketpair(socket.AF_UNIX,socket.SOCK_STREAM)
            with host, peer, (out/"qemu-stderr.log").open("wb") as diagnostic:
                cmd = [
                    "qemu-system-x86_64","-machine","q35,accel=tcg,smm=on,hpet=on",
                    "-cpu","max","-smp",str(args.cpus),"-m","256",
                    "-global","driver=cfi.pflash01,property=secure,value=on",
                    "-drive",f"if=pflash,format=raw,unit=0,readonly=on,file={args.ovmf_code}",
                    "-drive",f"if=pflash,format=raw,unit=1,file={vars_file}",
                    "-drive",f"if=none,format=raw,id=esp,file={esp}",
                    "-device","ich9-ahci,id=sata",
                    "-device","ide-hd,drive=esp,bus=sata.0,bootindex=1",
                    "-netdev",f"socket,id=net0,fd={peer.fileno()}",
                    "-device","virtio-net-pci,id=agentos-net,netdev=net0,disable-legacy=on,disable-modern=off,mac=52:54:00:12:34:56,romfile=",
                    "-object",f"filter-dump,id=wire,netdev=net0,file={out/'wire.pcap'}",
                    "-chardev",f"socket,id=uart,path={uart},server=on,wait=on",
                    "-serial","chardev:uart","-qmp",f"unix:{qmp},server=on,wait=off",
                    "-monitor",f"unix:{hmp},server=on,wait=off",
                    "-display","none","-vga","std","-boot","order=c","-no-reboot","-no-shutdown",
                ]
                write_json(out/"command.json",cmd)
                started=time.monotonic()
                try:
                    process=subprocess.Popen(cmd,cwd=ROOT,stdin=subprocess.DEVNULL,
                                             stdout=diagnostic,stderr=subprocess.STDOUT,
                                             pass_fds=(peer.fileno(),))
                    peer.close()
                    capture=smoke.UartCapture(smoke.connect_uart(uart,process),serial)
                    ready=helpers.wait_guest(process,capture,serial,b"AGENTOS VIRTIO NET READY MAC=",args.timeout)
                    # READY is emitted only after an actual RX buffer is posted.
                    # Require its full line rather than a partially captured prefix.
                    ready=smoke.wait_session(process,capture,serial,
                         lambda data: re.search(rb"AGENTOS VIRTIO NET READY MAC=52:54:00:12:34:56 DEPTH=8 ROUNDS=12 MRG=[01]\r\n",data),
                         "negotiated VirtIO network",10)
                    monitor=smoke.Qmp(qmp)
                    pci=monitor.execute("query-pci")
                    write_json(out/"pci.json",pci)
                    bdf=net.verify_pci(ready.decode("ascii",errors="replace"),pci)
                    records=exchange(host,out/"packets.json")
                    helpers.wait_guest(process,capture,serial,b"AGENTOS VIRTIO NET CLOSED STATUS=0 MASTER=0 DMA=4\r\n",30)
                    data=helpers.wait_guest(process,capture,serial,b"AGENTOS SHELL READY\r\nagentos> ",args.timeout)
                    verify_kernel(data,args.cpus)
                    monitor.screenshot(out/"shell-screen.ppm")
                    smoke.console.verify(out/"shell-screen.ppm",aLevel="info",aOutput="both")
                    monitor.execute("quit")
                    require(process.wait(timeout=15)==0,"QEMU did not exit cleanly")
                    # Closing QEMU flushes its independent filter-dump PCAP.
                    result=net.verify(data.decode("ascii",errors="replace"),records,(out/"wire.pcap").read_bytes())
                    files=("command.json","pci.json","packets.json","wire.pcap","com1.log",
                           "shell-screen.ppm","esp-bootx64.efi","OVMF_VARS.secboot.fd")
                    receipt={"schema":1,"result":"pass","source_commit":commit,"cpus":args.cpus,
                             "signed_efi_sha256":build["artifacts"]["agentos.efi"],
                             "ovmf_code_sha256":sha(args.ovmf_code),"pci_bdf":bdf,
                             "emulator":subprocess.check_output(["qemu-system-x86_64","--version"],text=True).splitlines()[0],
                             "seconds":round(time.monotonic()-started,3),**result,
                             "artifacts":{name:sha(out/name) for name in files}}
                    write_json(out/"virtio-net.json",receipt)
                    print("QEMU_VIRTIO_NET_PASS="+json.dumps(receipt,sort_keys=True),flush=True)
                except Exception:
                    smoke.snapshot(hmp,out/"failure.ppm")
                    tail=serial.read_bytes()[-5000:] if serial.exists() else b""
                    print("QEMU VirtIO-net COM1 failure tail:\n"+tail.decode("ascii",errors="replace"),
                          file=sys.stderr,flush=True)
                    if diagnostic.tell():
                        print((out/"qemu-stderr.log").read_text(errors="replace")[-3000:],file=sys.stderr)
                    raise
                finally:
                    if monitor is not None:
                        monitor.close()
                    if capture is not None:
                        capture.close()
                    if process is not None and process.poll() is None:
                        process.terminate()
                        try:
                            process.wait(timeout=10)
                        except subprocess.TimeoutExpired:
                            process.kill()
                            process.wait(timeout=10)
    except Exception as error:
        write_json(out/"failure.json",{"result":"fail","source_commit":commit,"cpus":args.cpus,"failure":str(error)})
        raise


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cpus",type=int,choices=(1,2),required=True)
    parser.add_argument("--ovmf-code",type=Path,required=True)
    parser.add_argument("--ovmf-vars",type=Path,required=True)
    parser.add_argument("--timeout",type=int,default=300)
    args=parser.parse_args()
    try:
        run(args)
    except Exception as error:
        print(f"QEMU VirtIO-net failed: {error}",file=sys.stderr,flush=True)
        return 1
    return 0


if __name__=="__main__":
    sys.exit(main())
