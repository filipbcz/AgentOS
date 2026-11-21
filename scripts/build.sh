#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C SOURCE_DATE_EPOCH=0
root=$(cd "$(dirname "$0")/.." && pwd)
while IFS='=' read -r package expected || [[ -n "$package" ]]; do
    if ! actual=$(dpkg-query -W -f='${Version}' "$package" 2>/dev/null); then
        printf 'Missing pinned build package: %s (required version %s)\n' "$package" "$expected" >&2
        exit 1
    fi
    [[ "$actual" == "$expected" ]] || { echo "$package: expected $expected, found $actual" >&2; exit 1; }
    printf 'Pinned build dependency: %s=%s\n' "$package" "$actual"
done < "$root/scripts/toolchain.lock"
out="$root/build"
mkdir -p "$out"
# Never leave a success receipt from a previous build if the new build fails.
rm -f "$out/build-provenance.json"
work=$(mktemp -d)
trap 'rm -f "$work"/{libkernel.a,ap-start.o,kernel.elf,initramfs.cpio,layout.ld,loader.o,payload.o,loader.so,stage,user.o,transfer.o,client.o,receive.o,service.o,shell.o,supervisor.o,init,fault,receiver,service,shell,svc_ok,svc_fail,svc_hang,data/transfer.bin}; rmdir "$work/data" "$work"' EXIT
cd "$work"
mkdir data
rust_version=$(/usr/bin/rustc --version)
[[ "$rust_version" == "rustc 1.75.0 "* ]] || { printf 'Pinned Rust compiler mismatch: %s\n' "$rust_version" >&2; exit 1; }
/usr/bin/rustc --edition 2021 --crate-type staticlib -C lto=fat -C opt-level=2 -C panic=abort \
    -C relocation-model=static -C no-redzone=yes -C overflow-checks=no \
    --remap-path-prefix="$root"=/agentos "$root/kernel/main.rs" -o libkernel.a
gcc-13 -c -o ap-start.o "$root/kernel/ap-start.S"
ld --build-id=none --gc-sections -T "$root/kernel/kernel.ld" -o kernel.elf libkernel.a ap-start.o
python3 "$root/scripts/verify-kernel-layout.py" kernel.elf
printf 'AgentOS stage 1\n' > stage
for app in init fault receiver service shell svc_ok svc_fail svc_hang; do
    gcc-13 -c "$root/user/$app.S" -o user.o
    objects=(user.o)
    case "$app" in init) sources=(transfer client supervisor);; receiver) sources=(receive);; service) sources=(service);; shell) sources=(shell);; *) sources=();; esac
    for src in "${sources[@]}"; do
        gcc-13 -std=c11 -Os -Wall -Wextra -Werror -ffreestanding -fno-stack-protector -fno-pie \
            -fno-asynchronous-unwind-tables -mno-red-zone -mcmodel=large -c "$root/user/$src.c" -o "$src.o"
        objects+=("$src.o")
    done
    ld --build-id=none -z noexecstack -s -T "$root/user/user.ld" -o "$app" "${objects[@]}"
done
awk 'BEGIN {for (i=0;i<8193;i++) printf "%c",(i*73+int(i/251)*19)%256}' > data/transfer.bin
touch -d @0 stage init fault receiver service shell svc_ok svc_fail svc_hang data/transfer.bin data
printf '%s\n' stage init fault receiver service shell svc_ok svc_fail svc_hang data data/transfer.bin | cpio --quiet --reproducible --owner=0:0 -o -H newc > initramfs.cpio
gcc-13 -I/usr/include/efi -I/usr/include/efi/x86_64 -DGNU_EFI_USE_MS_ABI \
    -O2 -Wall -Wextra -Werror -fpic -ffreestanding -fno-stack-protector -fshort-wchar \
    -mno-red-zone -c "$root/boot/loader.c" -o loader.o
gcc-13 -c "$root/boot/payload.S" -o payload.o
sed '/^  \.data /i\  . = ALIGN(4096);\n  .kernel : { *(.kernel) }\n  . = ALIGN(4096);\n  .initrd : { *(.initrd) }\n  . = ALIGN(4096);' /usr/lib/elf_x86_64_efi.lds > layout.ld
ld -nostdlib --build-id=none -znocombreloc -T layout.ld -shared -Bsymbolic \
   /usr/lib/crt0-efi-x86_64.o loader.o payload.o -L/usr/lib -lefi -lgnuefi -o loader.so
objcopy --strip-all -j .text -j .sdata -j .data -j .dynamic -j .dynsym -j .rela -j .reloc \
    -j .kernel -j .initrd --target=efi-app-x86_64 loader.so "$out/agentos.unsigned.efi"
keys="${XDG_DATA_HOME:-$HOME/.local/share}/agentos/stage1-test-keys"
mkdir -p -m 700 "$keys"
if [[ ! -e "$keys/db.key" && ! -e "$keys/db.crt" ]]; then
    (umask 077; openssl req -new -x509 -newkey rsa:2048 -nodes -sha256 -days 3650 \
        -subj '/CN=AgentOS isolated VM test only/' -keyout "$keys/db.key" -out "$keys/db.crt")
fi
sbsign --key "$keys/db.key" --cert "$keys/db.crt" --output "$out/agentos.efi" "$out/agentos.unsigned.efi"
sbverify --cert "$keys/db.crt" "$out/agentos.efi"
openssl x509 -in "$keys/db.crt" -outform der -out "$out/db.cer"
cert-to-efi-sig-list -g d7663630-f07a-4739-bc6f-b9f6d6444865 "$keys/db.crt" "$out/db.esl"
# A reproducible *receipt*, not a cryptographic attestation. Its hashes
# bind the signed EFI to the current Git tree, toolchain lock and signing db.
# Do not copy private signing keys or include wall-clock timestamps here.
python3 - "$root" "$out" "$work/initramfs.cpio" <<'PY'
import hashlib
import json
from pathlib import Path
import subprocess
import sys

root, out, initrd = (Path(value) for value in sys.argv[1:])
def run(*cmd):
    return subprocess.check_output(cmd, cwd=root, text=True).strip()
def digest(path):
    result = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            result.update(block)
    return result.hexdigest()

receipt = {
    "schema": 1,
    "source_commit": run("git", "rev-parse", "--verify", "HEAD"),
    "source_clean": not bool(run("git", "status", "--porcelain", "--untracked-files=normal")),
    "toolchain_lock_sha256": digest(root / "scripts/toolchain.lock"),
    "rustc_version": run("/usr/bin/rustc", "--version"),
    "gcc_version": run("gcc-13", "-dumpfullversion"),
    "initramfs_sha256": digest(initrd),
    "artifacts": {
        name: digest(out / name)
        for name in ("agentos.unsigned.efi", "agentos.efi", "db.cer", "db.esl")
    },
}
path = out / "build-provenance.json"
temporary = out / "build-provenance.json.tmp"
temporary.write_text(json.dumps(receipt, sort_keys=True, indent=2) + "\n", encoding="utf-8")
temporary.replace(path)
print(f"Build provenance: {path} (commit {receipt['source_commit']}, clean={receipt['source_clean']})")
PY
sha256sum "$out/"*.efi
