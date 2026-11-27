"""Host-only signed image and paired foreground supervisor verification.

Receipts describe verified files, not attestations. The actual signed images,
embedded archives, independent relinks and real UART captures are required.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import sys
import tempfile

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parent.parent
RUNNER = "supervisor-runner"
SECTIONS = (".text", ".sdata", ".data", ".dynamic", ".dynsym", ".rela",
            ".reloc", ".kernel", ".initrd")
CFLAGS = ("-std=c11", "-Os", "-Wall", "-Wextra", "-Werror", "-ffreestanding",
          "-fno-stack-protector", "-fno-pie", "-fno-asynchronous-unwind-tables",
          "-mno-red-zone", "-mcmodel=large")


class VerificationError(ValueError):
    pass


def require(ok, message):
    if not ok:
        raise VerificationError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def sha(path):
    return digest(path.read_bytes())


def load(root, filename):
    spec = importlib.util.spec_from_file_location(filename, root / "scripts" / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def span(data, offset, size):
    require(0 <= offset <= len(data) and 0 <= size <= len(data)-offset,
            "Image field exceeds file bounds")
    return data[offset:offset+size]


def pe_sections(data):
    require(span(data, 0, 2)==b"MZ", "Missing DOS header")
    pe = struct.unpack("<I", span(data, 60, 4))[0]
    require(span(data, pe, 4)==b"PE\0\0", "Missing PE signature")
    machine, count = struct.unpack("<HH", span(data, pe+4, 4))
    opt_size = struct.unpack("<H", span(data, pe+20, 2))[0]
    opt = pe+24
    header = span(data, opt, opt_size)
    require(machine==0x8664 and 0<count<=len(SECTIONS) and len(header)>=152 and
            struct.unpack_from("<H", header)[0]==0x20b and
            struct.unpack_from("<H", header, 68)[0]==10 and
            struct.unpack_from("<I", header, 108)[0]>=5,
            "Expected x86-64 PE32+ EFI application")
    cert = struct.unpack_from("<II", header, 144)
    table = opt+opt_size
    sections, ranges = {}, []
    for i in range(count):
        entry = span(data, table+40*i, 40)
        name = entry[:8].rstrip(b"\0").decode("ascii")
        size, rva, raw_size, offset = struct.unpack_from("<IIII", entry, 8)
        require(name in SECTIONS and name not in sections and 0<size<=raw_size and
                offset>=table+40*count, "Invalid or duplicate PE section: "+name)
        payload = span(data, offset, raw_size)
        ranges.append((offset, offset+raw_size))
        sections[name] = (rva, payload[:size])
    ranges.sort()
    require(all(a[1]<=b[0] for a,b in zip(ranges,ranges[1:])) and
            {".text", ".kernel", ".initrd"}<=set(sections),
            "Overlapping or missing PE sections")
    if cert!=(0,0):
        require(cert[0]%8==0 and cert[0]>=ranges[-1][1] and cert[1]>0 and
                cert[0]+cert[1]==len(data), "Invalid certificate table range")
    return opt, cert, sections


def signed_payload(unsigned, signed):
    """Authenticode signing may only update checksum/security directory and
    append the certificate. The actual signature is separately checked by
    sbverify against the build's enrolled certificate.
    """
    opt, cert, sections = pe_sections(unsigned)
    signed_opt, signed_cert, actual = pe_sections(signed)
    require(cert==(0,0) and signed_opt==opt and signed_cert[0]==len(unsigned) and
            signed_cert[1]>0 and sections==actual,
            "Signed EFI differs from its unsigned payload")
    before, after = bytearray(unsigned), bytearray(signed[:len(unsigned)])
    for offset, size in ((opt+64,4),(opt+144,8)):
        before[offset:offset+size]=after[offset:offset+size]=b"\0"*size
    require(before==after,"Signing changed bytes outside the Authenticode fields")
    return actual


def cpio_entries(data):
    """Parse the embedded newc stream, including trailer and padding.

    Names use the same canonical relative form as the current VFS. Reject
    aliases, duplicates, special files, hard-linked regular files and junk.
    """
    entries, at = {}, 0
    while True:
        header = span(data, at, 110)
        require(header[:6]==b"070701" and re.fullmatch(b"[0-9a-fA-F]{104}",header[6:]),
                "Invalid newc header")
        fields = tuple(int(header[i:i+8],16) for i in range(6,110,8))
        size, name_size = fields[6], fields[11]
        require(name_size>1 and fields[12]==0,"Invalid newc name or checksum")
        raw_name = span(data,at+110,name_size)
        require(raw_name[-1:]==b"\0" and b"\0" not in raw_name[:-1],"Invalid newc name")
        name = raw_name[:-1].decode("ascii")
        name_end = at+110+name_size
        start = (name_end+3)&~3
        end = start+size
        next_at = (end+3)&~3
        require(not any(span(data,name_end,start-name_end)) and
                not any(span(data,end,next_at-end)),"Nonzero newc alignment padding")
        payload = span(data,start,size)
        if name=="TRAILER!!!":
            require(size==0 and not any(data[next_at:]),"Invalid newc trailer or trailing data")
            return entries
        require(all(part not in ("", ".", "..") for part in name.split("/")) and
                name not in entries,"Duplicate or noncanonical newc path: "+name)
        kind=fields[1]&0o170000
        require((kind==0o100000 and fields[4]==1) or (kind==0o040000 and size==0),
                "Unsupported newc node: "+name)
        entries[name]=(fields,payload)
        at=next_at


def verify_contents(control, test, kernel, control_cpio, test_cpio, runner):
    for sections, archive in ((control,control_cpio),(test,test_cpio)):
        require(sections[".kernel"][1]==kernel and sections[".initrd"][1]==archive,
                "Actual embedded kernel/initramfs differs from build files")
    distribution, staged = cpio_entries(control_cpio), cpio_entries(test_cpio)
    require({"init","shell","svc_ok","svc_fail","svc_hang","fault"}<=set(distribution) and
            RUNNER not in distribution and set(staged)==set(distribution)|{RUNNER},
            "Staged archive must add exactly one runner, absent from distribution")
    require(all(staged[name]==entry for name,entry in distribution.items()),
            "A common CPIO entry changed")
    require(staged[RUNNER][0][1]&0o170000==0o100000 and
            staged[RUNNER][0][1]&0o111!=0 and staged[RUNNER][1]==runner,"Embedded runner differs from linked ELF")
    return {name: {"size":len(entry[1]), "sha256":digest(entry[1])}
            for name,entry in sorted(distribution.items())}


def command(work, *args):
    subprocess.run(args,cwd=work,check=True,
                   env={**os.environ,"LC_ALL":"C","SOURCE_DATE_EPOCH":"0"})


def reproduce(root, out, stage, write_maps):
    """Rebuild both complete unsigned EFI files from the one archived loader
    object and the actual CPIOs. This verifies all link-time changes, not just
    selected instruction bytes. Recompile the common object from the pinned
    source and check the linked runner and the supervisor-free production
    init, without touching either signed image.
    """
    with tempfile.TemporaryDirectory(prefix="agentos-relink-") as directory:
        work=Path(directory)
        for name in ("loader.o","supervisor.o","layout.ld"):
            shutil.copyfile(stage/name,work/name)
        shutil.copyfile(out/"kernel.elf",work/"kernel.elf")
        command(work,"gcc-13","-I/usr/include/efi","-I/usr/include/efi/x86_64",
                "-DGNU_EFI_USE_MS_ABI","-O2","-Wall","-Wextra","-Werror","-fpic",
                "-ffreestanding","-fno-stack-protector","-fshort-wchar","-mno-red-zone",
                "-c",str(root/"boot/loader.c"),"-o","loader.check.o")
        require((work/"loader.check.o").read_bytes()==(work/"loader.o").read_bytes(),
                "Common loader object does not match the source")
        # Independently reproduce the actual production /init from only its
        # remaining modules. No acceptance workload object may enter this link.
        command(work,"gcc-13","-c",str(root/"user/init.S"),"-o","init-entry.o")
        init_objects=["init-entry.o"]
        for name in ("transfer","client","orphans","forktest","demand","migration","service_manager"):
            obj=name+".init.o"
            command(work,"gcc-13",*CFLAGS,"-c",str(root/"user"/(name+".c")),"-o",obj)
            init_objects.append(obj)
        command(work,"ld","--no-undefined","--build-id=none","-z","noexecstack","-s",
                "-T",str(root/"user/user.ld"),"-o","init",*init_objects)
        require((work/"init").read_bytes()==cpio_entries((out/"initramfs.cpio").read_bytes())["init"][1],
                "Embedded production init does not reproduce without supervisor workload")
        command(work,"gcc-13",*CFLAGS,"-c",str(root/"scripts/tests/supervisor-workload.c"),"-o","supervisor.check.o")
        require((work/"supervisor.check.o").read_bytes()==(work/"supervisor.o").read_bytes(),
                "Runner supervisor object differs from source")
        command(work,"gcc-13","-c",str(root/"scripts/tests/supervisor-runner.S"),"-o","runner-entry.o")
        command(work,"gcc-13",*CFLAGS,"-c",str(root/"scripts/tests/supervisor-runner.c"),"-o","runner.o")
        command(work,"ld","--no-undefined","--build-id=none","-z","noexecstack","-s",
                "-T",str(root/"user/user.ld"),"-o",RUNNER,"runner-entry.o","runner.o","supervisor.o")
        require((work/RUNNER).read_bytes()==(stage/RUNNER).read_bytes(),"Runner relink differs")
        for variant,archive,expected in (
                ("control",out/"initramfs.cpio",out/"agentos.unsigned.efi"),
                ("test",stage/"test.cpio",stage/"test.unsigned.efi")):
            shutil.copyfile(archive,work/"initramfs.cpio")
            command(work,"gcc-13","-c",str(root/"boot/payload.S"),"-o","payload.o")
            command(work,"ld","-nostdlib","--build-id=none","-znocombreloc","-T","layout.ld",
                    "-shared","-Bsymbolic","-Map",variant+".map","/usr/lib/crt0-efi-x86_64.o",
                    "loader.o","payload.o","-L/usr/lib","-lefi","-lgnuefi","-o","loader.so")
            options=[arg for name in SECTIONS for arg in ("-j",name)]
            command(work,"objcopy","--strip-all",*options,"--target=efi-app-x86_64","loader.so","image.efi")
            require((work/"image.efi").read_bytes()==expected.read_bytes(),
                    variant+" unsigned image did not reproduce from common objects")
            if write_maps:
                shutil.copyfile(work/(variant+".map"),stage/(variant+".map"))
        # Verify both actual signed EFI files with the same enrolled public cert.
        command(work,"openssl","x509","-inform","DER","-in",str(out/"db.cer"),"-out","db.crt")
        for image in (out/"agentos.efi",stage/"test.efi"):
            command(work,"sbverify","--cert","db.crt",str(image))


def verify_identity(root=ROOT, *, write=False):
    root=Path(root).resolve()
    out,stage=root/"build",root/"build/supervisor-staging"
    path=stage/"identity.json"
    if write:
        path.unlink(missing_ok=True)
    evidence=load(root,"verify-vm-evidence.py")
    commit=subprocess.check_output(["git","rev-parse","--verify","HEAD"],cwd=root,text=True).strip()
    build=evidence.verify_build(root,commit)
    require(build.get("profile")=="default" and not subprocess.check_output(
        ["git","status","--porcelain","--untracked-files=normal"],cwd=root),
        "Staging requires the clean, ordinary production build")
    control_unsigned=(out/"agentos.unsigned.efi").read_bytes()
    control_signed=(out/"agentos.efi").read_bytes()
    test_unsigned=(stage/"test.unsigned.efi").read_bytes()
    test_signed=(stage/"test.efi").read_bytes()
    control=signed_payload(control_unsigned,control_signed)
    test=signed_payload(test_unsigned,test_signed)
    kernel,control_cpio,test_cpio,runner=(p.read_bytes() for p in
        (out/"kernel.elf",out/"initramfs.cpio",stage/"test.cpio",stage/RUNNER))
    require(build["initramfs_sha256"]==digest(control_cpio),"Distribution receipt archive mismatch")
    common=verify_contents(control,test,kernel,control_cpio,test_cpio,runner)
    load(root,"verify-user-abi.py").verify(runner)
    reproduce(root,out,stage,write)

    def describe(unsigned,signed,sections):
        return {"unsigned_sha256":digest(unsigned),"signed_sha256":digest(signed),
                "sections":{name:{"rva":rva,"size":len(payload),"sha256":digest(payload)}
                            for name,(rva,payload) in sorted(sections.items())}}

    result={"schema":1,"source_commit":commit,"source_tree":subprocess.check_output(
                ["git","rev-parse","HEAD^{tree}"],cwd=root,text=True).strip(),
            "build_provenance_sha256":sha(out/"build-provenance.json"),
            "loader_source_sha256":sha(root/"boot/loader.c"),
            "loader_object_sha256":sha(stage/"loader.o"),"layout_sha256":sha(stage/"layout.ld"),
            "supervisor_object_sha256":sha(stage/"supervisor.o"),"kernel_sha256":digest(kernel),
            "common_entries":common,"runner_sha256":digest(runner),
            "map_sha256":{v:sha(stage/(v+".map")) for v in ("control","test")},
            "control":describe(control_unsigned,control_signed,control),
            "test":describe(test_unsigned,test_signed,test)}
    require(result["control"]["signed_sha256"]!=result["test"]["signed_sha256"],"Expected distinct signed images")
    if write:
        path.write_text(json.dumps(result,sort_keys=True,indent=2)+"\n",encoding="utf-8")
    else:
        require(json.loads(path.read_text())==result,"Staging identity receipt differs from verified files")
    return result


def verify_pair(root, cpus, no_hpet=False):
    root=Path(root).resolve()
    clock_suffix="-no-hpet" if no_hpet else ""
    path=root/"build/supervisor-staging"/f"pair-cpu{cpus}{clock_suffix}.json"
    path.unlink(missing_ok=True)
    identity=verify_identity(root)
    session=load(root,"verify-stage3-session.py")
    records, inputs, receipts = {}, [], []
    for variant in ("control","test"):
        folder=root/"build/check"/f"qemu-cpu{cpus}{clock_suffix}-session-sv-{variant}"
        receipt=json.loads((folder/"smoke.json").read_text())
        expected=identity[variant]["signed_sha256"]
        require(receipt.get("result")=="pass" and receipt.get("supervisor_image")==variant and
                receipt.get("source_commit")==identity["source_commit"] and receipt.get("cpus")==cpus and
                receipt.get("interactive_com1_manager_session") is True and
                receipt.get("ps2_keyboard_session") is True and
                receipt.get("accelerator")=="tcg" and receipt.get("hpet_enabled") is (not no_hpet) and
                receipt.get("system_clock") in (("ACPI PM24","ACPI PM32") if no_hpet else ("HPET64","HPET32")) and
                receipt.get("signed_efi_sha256")==receipt.get("esp_boot_efi_sha256")==expected and
                sha(folder/"esp-bootx64.efi")==expected,
                "Incomplete or mismatched real signed boot: "+variant)
        log=(folder/"com1.log").read_bytes()
        sent=(folder/"com1-input.bin").read_bytes()
        require(digest(log)==receipt.get("com1_sha256") and digest(sent)==receipt.get("com1_input_sha256"),
                "Actual UART evidence differs from receipt: "+variant)
        result=session.verify(log,sent,True,cpus,aRuntimeProcess=True,aSupervisorImage=variant)
        require(result==receipt.get("runtime_session"),"Runtime evidence differs from receipt: "+variant)
        require(log.endswith(b"[INFO] INTERACTIVE SHELL STOPPED\r\n"),"Incomplete real shutdown")
        records[variant]={"receipt_sha256":sha(folder/"smoke.json"),"efi_sha256":expected,
                          "com1_sha256":digest(log),"com1_input_sha256":digest(sent),"runtime":result}
        inputs.append(sent)
        receipts.append(receipt)
    require(inputs[0]==inputs[1] and all(receipts[0].get(k)==receipts[1].get(k) for k in
            ("ovmf_code_sha256","memory_mib","accelerator","qemu_version","system_clock")),
            "Paired sessions did not use matching platform and input")
    result={"source_commit":identity["source_commit"],"cpus":cpus,
            "identity_sha256":sha(root/"build/supervisor-staging/identity.json"),"sessions":records}
    path.write_text(json.dumps(result,sort_keys=True,indent=2)+"\n",encoding="utf-8")
    return result


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root",type=Path,default=ROOT)
    mode=parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--write-identity",action="store_true")
    mode.add_argument("--cpus",type=int,choices=(1,2))
    parser.add_argument("--no-hpet",action="store_true")
    args=parser.parse_args()
    if args.write_identity:
        require(not args.no_hpet,"--no-hpet requires paired sessions")
        result=verify_identity(args.root,write=True)
        print("Verified signed image identity: "+json.dumps(result,sort_keys=True))
    else:
        print("Verified paired real supervisor sessions: "+json.dumps(verify_pair(args.root,args.cpus,args.no_hpet),sort_keys=True))
    return 0


if __name__=="__main__":
    sys.exit(main())
