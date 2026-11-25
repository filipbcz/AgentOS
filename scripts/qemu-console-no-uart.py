"""Boot the unchanged signed default image on a PC without a legacy UART.

Use QMP only as an external keyboard/screen and hardware inventory. No
guest serial connection, test build flag, or guest-side fixture is needed.
"""
import argparse
import importlib.util
import json
from pathlib import Path
import re
import secrets
import subprocess
import sys
import tempfile
import time

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location("qemu_smoke", ROOT/"scripts/qemu-smoke.py")
smoke = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(smoke)
console = smoke.console


def write_json(path, data):
    path.write_text(json.dumps(data, indent=2, sort_keys=True)+"\n", encoding="utf-8")


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def verify_hardware(tree):
    devices = re.findall(r"(?m)^\s*dev:\s*([^,\s]+)", tree)
    require("i8042" in devices, "No actual PC keyboard controller in QEMU inventory")
    require(not any(re.search(r"(^|[-_])serial(?:$|[-_])", device) for device in devices),
            "UART hardware still present in supposedly serial-free guest")


def connect_qmp(path, process):
    deadline = time.monotonic()+30
    while time.monotonic()<deadline:
        if process.poll() is not None:
            raise RuntimeError(f"QEMU exited during monitor startup: {process.returncode}")
        if path.exists():
            try:
                return smoke.Qmp(path)
            except ConnectionRefusedError:
                pass
        time.sleep(0.05)
    raise TimeoutError("QEMU monitor unavailable")


def wait_screen(qmp, process, path, verify, timeout):
    deadline = time.monotonic()+timeout
    error = "No screenshot captured"
    while time.monotonic()<deadline:
        if process.poll() is not None:
            raise RuntimeError(f"QEMU exited before screen response: {process.returncode}")
        qmp.screenshot(path)
        try:
            return verify(path)
        except console.VerificationError as e:
            error = str(e)
        time.sleep(0.25)
    raise TimeoutError(f"Guest console did not respond: {error}")


def verify_prompt(path):
    image = console.read_image(path)
    console.require(console.text_rows(image, "agentos> ", True), "No live complete shell prompt")
    return image.fWidth, image.fHeight


def verify_response(after, before, response):
    size = console.verify(after, before, response)
    image = console.read_image(after)
    row, = console.text_rows(image, response, True)
    console.require(any(prompt > row for prompt in console.text_rows(image, "agentos> ", True)),
                    "No new complete prompt following command response")
    return size


def run(args):
    sha = smoke.evidence.sha256
    commit = subprocess.check_output(["git","rev-parse","--verify","HEAD"],cwd=ROOT,text=True).strip()
    build = smoke.evidence.verify_build(ROOT,commit)
    require(build.get("profile","default")=="default", "Console test requires unchanged default image")
    root = ROOT/"build/check"/f"qemu-no-uart-cpu{args.cpus}"
    root.mkdir(parents=True,exist_ok=True)
    out = Path(tempfile.mkdtemp(prefix="run-",dir=root))
    print(f"QEMU_NO_UART_DIR={out}",flush=True)
    try:
        # Request only serial boot logs. With no UART present, operational
        # diagnostics must still be visible on the actual GOP framebuffer.
        subprocess.run(["bash","scripts/disk.sh",str(out),"build/agentos.efi","info serial"],cwd=ROOT,check=True)
        esp=out/"esp.raw"
        copied=out/"esp-bootx64.efi"
        subprocess.run(["mcopy","-i",f"{esp}@@1048576","::EFI/BOOT/BOOTX64.EFI",str(copied)],check=True)
        require(sha(copied)==build["artifacts"]["agentos.efi"],"ESP differs from signed EFI")
        vars_file=out/"OVMF_VARS.secboot.fd"
        cert=Path.home()/".local/share/agentos/stage1-test-keys/db.crt"
        owner="d7663630-f07a-4739-bc6f-b9f6d6444865"
        subprocess.run(["virt-fw-vars","--input",str(args.ovmf_vars),"--output",str(vars_file),
                        "--set-pk",owner,str(cert),"--add-kek",owner,str(cert),
                        "--add-db",owner,str(cert),"--secure-boot"],check=True)
        der=subprocess.check_output(["openssl","x509","-in",str(cert),"-outform","der"])
        require(der in vars_file.read_bytes(),"Missing enrolled signer")
        process=qmp=None
        with tempfile.TemporaryDirectory(prefix="agentos-console-") as directory:
            monitor=Path(directory)/"qmp"
            hmp=Path(directory)/"hmp"
            cmd=["qemu-system-x86_64","-machine","q35,accel=tcg,smm=on,hpet=on",
                 "-cpu","max","-smp",str(args.cpus),"-m","256",
                 "-global","driver=cfi.pflash01,property=secure,value=on",
                 "-drive",f"if=pflash,format=raw,unit=0,readonly=on,file={args.ovmf_code}",
                 "-drive",f"if=pflash,format=raw,unit=1,file={vars_file}",
                 "-drive",f"if=none,format=raw,id=esp,file={esp}",
                 "-device","ich9-ahci,id=sata","-device","ide-hd,drive=esp,bus=sata.0,bootindex=1",
                 "-serial","none","-qmp",f"unix:{monitor},server=on,wait=off",
                 "-monitor",f"unix:{hmp},server=on,wait=off",
                 "-display","none","-vga","std","-nic","none","-boot","order=c","-no-reboot","-no-shutdown"]
            write_json(out/"command.json",cmd)
            started=time.monotonic()
            with (out/"qemu-stderr.log").open("wb") as diagnostic:
                try:
                    process=subprocess.Popen(cmd,cwd=ROOT,stdin=subprocess.DEVNULL,
                                             stdout=diagnostic,stderr=subprocess.STDOUT)
                    qmp=connect_qmp(monitor,process)
                    tree=qmp.execute("human-monitor-command",{"command-line":"info qtree"})
                    (out/"qtree.txt").write_text(tree,encoding="utf-8")
                    verify_hardware(tree)
                    first=out/"shell-before.ppm"
                    def initial(path):
                        size=verify_prompt(path)
                        image=console.read_image(path)
                        scale=max(1,min(2,(image.fWidth-16)//240))
                        console.require(console.match_text(image,"[INFO] KERNEL ENTRY",8,52,scale),
                                        "Serial-only boot logging did not fall back to GOP")
                        return size
                    geometry=wait_screen(qmp,process,first,initial,args.timeout)
                    records=[]
                    before=first
                    for number in (1,2):
                        # Challenge generated only after the actual shell is
                        # running. Check real line editing as well as echo.
                        response="nouart-"+secrets.token_hex(4)
                        command="echo "+response[:-1]+"x\b"+response[-1]
                        require(not console.text_rows(console.read_image(before),response,True),
                                "Stale response before keyboard input")
                        records.append({"round":number,"command":command,"expected":response})
                        write_json(out/"keyboard.json",records)
                        qmp.keyboard(command)
                        after=out/f"shell-after-{number}.ppm"
                        require(wait_screen(qmp,process,after,
                                            lambda path:verify_response(path,before,response),30)==geometry,
                                "Guest screen geometry changed")
                        before=after
                        print(f"Verified actual GOP response to PS/2 command {number}: {response}",flush=True)
                    # Quit the VM through the host monitor. This is not a
                    # claim of orderly guest shutdown or storage durability.
                    qmp.execute("quit")
                    require(process.wait(timeout=15)==0,"QEMU did not exit")
                    files=("command.json","qtree.txt","keyboard.json","shell-before.ppm",
                           "shell-after-1.ppm","shell-after-2.ppm","esp-bootx64.efi","OVMF_VARS.secboot.fd")
                    receipt={"schema":1,"result":"pass","source_commit":commit,"cpus":args.cpus,
                             "signed_efi_sha256":build["artifacts"]["agentos.efi"],
                             "ovmf_code_sha256":sha(args.ovmf_code),"uart_present":False,
                             "ps2_keyboard":True,"boot_log":"info serial","gop_fallback":True,
                             "width":geometry[0],"height":geometry[1],"responses":len(records),
                             "seconds":round(time.monotonic()-started,3),
                             "artifacts":{name:sha(out/name) for name in files}}
                    write_json(out/"no-uart.json",receipt)
                    print("QEMU_NO_UART_PASS="+json.dumps(receipt,sort_keys=True),flush=True)
                except Exception:
                    smoke.snapshot(hmp,out/"failure.ppm")
                    raise
                finally:
                    if qmp is not None:qmp.close()
                    if process is not None and process.poll() is None:
                        process.terminate()
                        try:process.wait(timeout=10)
                        except subprocess.TimeoutExpired:process.kill();process.wait(timeout=10)
    except Exception as error:
        write_json(out/"failure.json",{"result":"fail","source_commit":commit,"cpus":args.cpus,
                                     "failure":str(error)})
        raise


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cpus",type=int,choices=(1,2),required=True)
    parser.add_argument("--ovmf-code",type=Path,required=True)
    parser.add_argument("--ovmf-vars",type=Path,required=True)
    parser.add_argument("--timeout",type=int,default=300)
    try:run(parser.parse_args())
    except Exception as error:
        print(f"QEMU serial-free console failed: {error}",file=sys.stderr,flush=True)
        return 1
    return 0


if __name__=="__main__":sys.exit(main())
