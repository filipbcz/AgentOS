"""Separate signed SMP-soak ELF packaging; never modifies the ordinary build."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parent.parent
CLIENT="smp-soak"
DIRECTORY="smp-soak-staging"

def load(name):
    spec=importlib.util.spec_from_file_location(name,ROOT/"scripts"/name)
    module=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

images=load("verify-supervisor-image.py")
basic=load("verify-basic-smp.py")
evidence=load("verify-vm-evidence.py")
require=images.require
digest=images.digest

def append_client(archive,elf):
    original=images.verify_distribution(archive)
    require(CLIENT not in original,"SMP workload in distribution")
    def encode(name,fields,payload):
        name=name.encode("ascii")+b"\0"
        fields=list(fields)
        fields[6]=len(payload)
        fields[11]=len(name)
        data=b"070701"+b"".join(f"{v:08x}".encode("ascii") for v in fields)+name
        data+=bytes((-len(data))%4)+payload
        return data+bytes((-len(data))%4)
    inode=max(fields[0] for fields,_ in original.values())+1
    fields=(inode,0o100755,0,0,1,0,len(elf),0,0,0,0,len(CLIENT)+1,0)
    return b"".join(encode(n,f,p) for n,(f,p) in original.items())+encode(CLIENT,fields,elf)+encode(
        "TRAILER!!!",(0,0,0,0,1,0,0,0,0,0,0,11,0),b"")

def verify_contents(control,staged,kernel,archive,stage_archive,elf):
    require(control[".kernel"][1]==staged[".kernel"][1]==kernel and
            control[".initrd"][1]==archive and staged[".initrd"][1]==stage_archive,
            "Signed SMP stage payload differs from common build")
    original=images.verify_distribution(archive)
    added=images.cpio_entries(stage_archive)
    require(set(added)==set(original)|{CLIENT} and all(added[k]==v for k,v in original.items()),
            "SMP stage changed common distribution entries")
    require(added[CLIENT][1]==elf and added[CLIENT][0][1]&0o170000==0o100000 and
            added[CLIENT][0][1]&0o111!=0 and b"AGENTOS TEST SMP SOAK " in elf,
            "SMP client not the separate executable")
    return {n:{"size":len(p),"sha256":digest(p)} for n,(_,p) in sorted(original.items())}

def verify_image(root,efi,commit):
    root=Path(root)
    out=root/"build"
    stage=out/DIRECTORY
    base=basic.verify_image(root,out/"agentos.efi",commit)
    signed=Path(efi).read_bytes()
    require(signed==(stage/"test.efi").read_bytes(),"Actual ESP differs from signed SMP stage")
    control=images.signed_payload((out/"agentos.unsigned.efi").read_bytes(),(out/"agentos.efi").read_bytes())
    staged=images.signed_payload((stage/"test.unsigned.efi").read_bytes(),signed)
    elf=(stage/CLIENT).read_bytes()
    load("verify-user-abi.py").verify(elf)
    common=verify_contents(control,staged,(out/"kernel.elf").read_bytes(),(out/"initramfs.cpio").read_bytes(),
                           (stage/"test.cpio").read_bytes(),elf)
    require((stage/"control.relinked.efi").read_bytes()==(out/"agentos.unsigned.efi").read_bytes(),
            "Common loader did not reproduce the ordinary EFI")
    cert=Path(efi).parent/"verified-soak-db.pem"
    subprocess.run(["openssl","x509","-inform","DER","-in",str(out/"db.cer"),"-out",str(cert)],check=True)
    subprocess.run(["sbverify","--cert",str(cert),str(efi)],check=True)
    return {"contract":"separate-smp-soak-image-v1","control":base,
            "signed_sha256":digest(signed),"unsigned_sha256":evidence.sha256(stage/"test.unsigned.efi"),
            "initramfs_sha256":evidence.sha256(stage/"test.cpio"),
            "client_sha256":digest(elf),"loader_sha256":evidence.sha256(stage/"loader.o"),
            "layout_sha256":evidence.sha256(stage/"layout.ld"),"common":common,
            "signature_verified":True}

def build(root=ROOT):
    root=Path(root).resolve()
    out=root/"build"
    stage=out/DIRECTORY
    commit=subprocess.check_output(["git","rev-parse","--verify","HEAD"],cwd=root,text=True).strip()
    provenance=evidence.verify_build(root,commit)
    require(provenance.get("profile")=="default" and not subprocess.check_output(
        ["git","status","--porcelain","--untracked-files=normal"],cwd=root),
        "SMP staging needs the clean ordinary build")
    if stage.exists():
        shutil.rmtree(stage)
    stage.mkdir()
    with tempfile.TemporaryDirectory(prefix="agentos-smp-soak-") as tmp:
        work=Path(tmp)
        command=lambda *args: images.command(work,*args)
        command("gcc-13","-c",str(root/"scripts/tests/smp-soak-entry.S"),"-o","entry.o")
        command("gcc-13",*images.CFLAGS,"-c",str(root/"scripts/tests/smp-soak.c"),"-o","client.o")
        command("ld","--no-undefined","--build-id=none","-z","noexecstack","-s",
                "-T",str(root/"user/user.ld"),"-o",CLIENT,"entry.o","client.o")
        elf=(work/CLIENT).read_bytes()
        load("verify-user-abi.py").verify(elf)
        shutil.copyfile(work/CLIENT,stage/CLIENT)
        command("gcc-13","-I/usr/include/efi","-I/usr/include/efi/x86_64",
                "-DGNU_EFI_USE_MS_ABI","-O2","-Wall","-Wextra","-Werror","-fpic","-ffreestanding",
                "-fno-stack-protector","-fshort-wchar","-mno-red-zone",
                "-c",str(root/"boot/loader.c"),"-o","loader.o")
        # The existing production layout, unchanged.
        with (work/"layout.ld").open("wb") as stream:
            subprocess.run(["sed",r"/^  \.data /i\  . = ALIGN(4096);\n  .kernel : { *(.kernel) }\n  . = ALIGN(4096);\n  .initrd : { *(.initrd) }\n  . = ALIGN(4096);",
                            "/usr/lib/elf_x86_64_efi.lds"],stdout=stream,check=True)
        for name in ("loader.o","layout.ld"):
            shutil.copyfile(work/name,stage/name)
        shutil.copyfile(out/"kernel.elf",work/"kernel.elf")
        archive=(out/"initramfs.cpio").read_bytes()
        test_archive=append_client(archive,elf)
        (stage/"test.cpio").write_bytes(test_archive)
        for name,cpio in (("control.relinked",archive),("test.unsigned",test_archive)):
            (work/"initramfs.cpio").write_bytes(cpio)
            command("gcc-13","-c",str(root/"boot/payload.S"),"-o","payload.o")
            command("ld","-nostdlib","--build-id=none","-znocombreloc","-T","layout.ld",
                    "-shared","-Bsymbolic","-Map",str(stage/(name+".map")),"/usr/lib/crt0-efi-x86_64.o",
                    "loader.o","payload.o","-L/usr/lib","-lefi","-lgnuefi","-o","loader.so")
            options=[arg for section in images.SECTIONS for arg in ("-j",section)]
            command("objcopy","--strip-all",*options,"--target=efi-app-x86_64","loader.so",str(stage/(name+".efi")))
        require((stage/"control.relinked.efi").read_bytes()==(out/"agentos.unsigned.efi").read_bytes(),
                "SMP profile failed reproduction of the default unsigned EFI")
        keys=Path(os.environ.get("XDG_DATA_HOME",str(Path.home()/".local/share")))/"agentos/stage1-test-keys"
        command("sbsign","--key",str(keys/"db.key"),"--cert",str(keys/"db.crt"),
                "--output",str(stage/"test.efi"),str(stage/"test.unsigned.efi"))
    identity=verify_image(root,stage/"test.efi",commit)
    (stage/"identity.json").write_text(json.dumps(identity,indent=2,sort_keys=True)+"\n")
    print("Signed separate SMP soak image:",json.dumps(identity,sort_keys=True),flush=True)

if __name__=="__main__":
    build()
