#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C SOURCE_DATE_EPOCH=0
root=$(cd "$(dirname "$0")/.." && pwd)
profile=default
staging=0
rust_flags=()
if [[ $# -eq 1 && $1 == --supervisor-staging ]]; then
    staging=1 # Host packaging only; production compiler flags are unchanged.
elif [[ $# -eq 1 && $1 == --ahci-dma ]]; then
    profile=ahci-dma
    rust_flags=(--cfg ahci_dma_acceptance)
elif [[ $# -eq 1 && $1 == --ahci-block ]]; then
    profile=ahci-block
    rust_flags=(--cfg ahci_block_acceptance)
elif [[ $# -eq 1 && $1 == --nvme-block ]]; then
    profile=nvme-block
    rust_flags=(--cfg nvme_block_acceptance)
elif [[ $# -eq 1 && $1 == --virtio-net ]]; then
    profile=virtio-net
    rust_flags=(--cfg virtio_net_acceptance)
elif [[ $# -eq 1 && $1 == --xhci ]]; then
    profile=xhci
    rust_flags=(--cfg xhci_acceptance)
elif [[ $# -ne 0 ]]; then
    echo 'Usage: build.sh [--supervisor-staging|--ahci-dma|--ahci-block|--nvme-block|--virtio-net|--xhci]' >&2
    exit 2
fi
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
rm -rf -- "$out/supervisor-staging"
work=$(mktemp -d)
# Work directory was exclusively created by mktemp. New ELF programs and C
# objects must never make a successful, signed build fail in the EXIT trap.
trap 'rm -rf -- "$work"' EXIT
cd "$work"
mkdir data
rust_version=$(/usr/bin/rustc --version)
[[ "$rust_version" == "rustc 1.75.0 "* ]] || { printf 'Pinned Rust compiler mismatch: %s\n' "$rust_version" >&2; exit 1; }
/usr/bin/rustc --edition 2021 --crate-type staticlib -C lto=fat -C opt-level=2 -C panic=abort \
    -C relocation-model=pic -C no-redzone=yes -C overflow-checks=no \
    "${rust_flags[@]}" --remap-path-prefix="$root"=/agentos "$root/kernel/main.rs" -o libkernel.a
gcc-13 -c -o ap-start.o "$root/kernel/ap-start.S"
ld -pie -Bsymbolic --no-dynamic-linker --no-undefined -z text -z max-page-size=4096 \
    --build-id=none --gc-sections -T "$root/kernel/kernel.ld" -o kernel.elf libkernel.a ap-start.o
python3 "$root/scripts/verify-kernel-layout.py" kernel.elf
# Validate the same ELF contract used by the EFI loader before signing.
gcc-13 -std=c11 -O2 -Wall -Wextra -Werror "$root/scripts/tests/kernel-elf-host.c" -o kernel-elf-tests
./kernel-elf-tests kernel.elf
python3 "$root/scripts/verify-trap-return.py" kernel.elf
# Preserve the exact linked ELF for symbolization of a real guest fault.
cp kernel.elf "$out/kernel.elf"
printf 'AgentOS stage 1\n' > stage
for app in init fault shell svc_ok svc_fail svc_hang orphan_parent manager svc_alive svc_flaky; do
    entry="$app"
    if [[ "$app" == svc_alive || "$app" == svc_flaky ]]; then entry=svc_worker; fi
    gcc-13 -c "$root/user/$entry.S" -o user.o
    objects=(user.o)
    case "$app" in init) sources=(orphans service_manager);; shell) sources=(shell service_client);; manager) sources=(service_manager);; svc_alive|svc_flaky) sources=(svc_worker);; *) sources=();; esac
    for src in "${sources[@]}"; do
        defines=()
        if [[ "$app" == svc_flaky ]]; then defines=(-DAGENTOS_FLAKY); fi
        gcc-13 -std=c11 -Os -Wall -Wextra -Werror -ffreestanding -fno-stack-protector -fno-pie \
            -fno-asynchronous-unwind-tables -mno-red-zone -mcmodel=large "${defines[@]}" -c "$root/user/$src.c" -o "$src.o"
        objects+=("$src.o")
    done
    ld --build-id=none -z noexecstack -s -T "$root/user/user.ld" -o "$app" "${objects[@]}"
    python3 "$root/scripts/verify-user-abi.py" "$app"
done
awk 'BEGIN {for (i=0;i<8193;i++) printf "%c",(i*73+int(i/251)*19)%256}' > data/transfer.bin
files=(stage init fault shell svc_ok svc_fail svc_hang orphan_parent manager svc_alive svc_flaky data data/transfer.bin)
touch -d @0 "${files[@]}"
printf '%s\n' "${files[@]}" | cpio --quiet --reproducible --owner=0:0 -o -H newc > initramfs.cpio
python3 "$root/scripts/verify-supervisor-image.py" --distribution-archive initramfs.cpio
cp initramfs.cpio "$out/initramfs.cpio"
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
python3 - "$root" "$out" "$work/initramfs.cpio" "$profile" <<'PY'
import hashlib
import json
from pathlib import Path
import subprocess
import sys

root, out, initrd = map(Path, sys.argv[1:4])
def run(*cmd):
    return subprocess.check_output(cmd, cwd=root, text=True).strip()
def digest(path):
    result = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            result.update(block)
    return result.hexdigest()

receipt = {
    "profile": sys.argv[4],
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

# Both images reuse the same actual loader, kernel and customer binaries.
# Only the optional host packaging step adds the standalone test client.
if ((staging)); then
    stage_out="$out/supervisor-staging"
    mkdir "$stage_out"
    gcc-13 -std=c11 -Os -Wall -Wextra -Werror -ffreestanding -fno-stack-protector -fno-pie \
        -fno-asynchronous-unwind-tables -mno-red-zone -mcmodel=large \
        -c "$root/scripts/tests/supervisor-workload.c" -o supervisor.o
    cp loader.o supervisor.o layout.ld "$stage_out/"
    gcc-13 -c "$root/scripts/tests/supervisor-runner.S" -o runner-entry.o
    gcc-13 -std=c11 -Os -Wall -Wextra -Werror -ffreestanding -fno-stack-protector -fno-pie \
        -fno-asynchronous-unwind-tables -mno-red-zone -mcmodel=large \
        -c "$root/scripts/tests/supervisor-runner.c" -o runner.o
    ld --no-undefined --build-id=none -z noexecstack -s -T "$root/user/user.ld" \
        -o supervisor-runner runner-entry.o runner.o supervisor.o
    python3 "$root/scripts/verify-user-abi.py" supervisor-runner
    gcc-13 -std=c11 -Os -Wall -Wextra -Werror -ffreestanding -fno-stack-protector -fno-pie \
        -fno-asynchronous-unwind-tables -mno-red-zone -mcmodel=large -DPIPE_WORKLOAD \
        -c "$root/scripts/tests/supervisor-runner.c" -o pipe-runner.o
    gcc-13 -std=c11 -Os -Wall -Wextra -Werror -ffreestanding -fno-stack-protector -fno-pie \
        -fno-asynchronous-unwind-tables -mno-red-zone -mcmodel=large \
        -c "$root/scripts/tests/pipe-workload.c" -o pipe-workload.o
    ld --no-undefined --build-id=none -z noexecstack -s -T "$root/user/user.ld" \
        -o pipe-runner runner-entry.o pipe-runner.o pipe-workload.o
    gcc-13 -c "$root/scripts/tests/pipe-receiver.S" -o pipe-receiver-entry.o
    gcc-13 -std=c11 -Os -Wall -Wextra -Werror -ffreestanding -fno-stack-protector -fno-pie \
        -fno-asynchronous-unwind-tables -mno-red-zone -mcmodel=large \
        -c "$root/scripts/tests/pipe-receive.c" -o pipe-receive.o
    ld --no-undefined --build-id=none -z noexecstack -s -T "$root/user/user.ld" \
        -o pipe-receiver pipe-receiver-entry.o pipe-receive.o
    for app in pipe-runner pipe-receiver; do
        python3 "$root/scripts/verify-user-abi.py" "$app"
    done
    for app in cow demand ipc fault; do
        define="-D${app^^}_WORKLOAD"
        gcc-13 -std=c11 -Os -Wall -Wextra -Werror -ffreestanding -fno-stack-protector -fno-pie \
            -fno-asynchronous-unwind-tables -mno-red-zone -mcmodel=large "$define" \
            -c "$root/scripts/tests/supervisor-runner.c" -o "$app-runner.o"
        gcc-13 -std=c11 -Os -Wall -Wextra -Werror -ffreestanding -fno-stack-protector -fno-pie \
            -fno-asynchronous-unwind-tables -mno-red-zone -mcmodel=large \
            -c "$root/scripts/tests/$app-workload.c" -o "$app-workload.o"
        ld --no-undefined --build-id=none -z noexecstack -s -T "$root/user/user.ld" \
            -o "$app-runner" runner-entry.o "$app-runner.o" "$app-workload.o"
        python3 "$root/scripts/verify-user-abi.py" "$app-runner"
    done
    gcc-13 -c "$root/scripts/tests/adoption-runner.S" -o adoption-entry.o
    gcc-13 -std=c11 -Os -Wall -Wextra -Werror -ffreestanding -fno-stack-protector -fno-pie \
        -fno-asynchronous-unwind-tables -mno-red-zone -mcmodel=large \
        -c "$root/scripts/tests/adoption-runner.c" -o adoption-runner.o
    ld --no-undefined --build-id=none -z noexecstack -s -T "$root/user/user.ld" \
        -o adoption-runner adoption-entry.o adoption-runner.o
    python3 "$root/scripts/verify-user-abi.py" adoption-runner
    gcc-13 -c "$root/scripts/tests/ipc-service.S" -o ipc-service-entry.o
    gcc-13 -std=c11 -Os -Wall -Wextra -Werror -ffreestanding -fno-stack-protector -fno-pie \
        -fno-asynchronous-unwind-tables -mno-red-zone -mcmodel=large \
        -c "$root/scripts/tests/ipc-service.c" -o ipc-service.o
    ld --no-undefined --build-id=none -z noexecstack -s -T "$root/user/user.ld" \
        -o ipc-service ipc-service-entry.o ipc-service.o
    python3 "$root/scripts/verify-user-abi.py" ipc-service
    gcc-13 -c "$root/scripts/tests/migration-runner.S" -o migration-runner-entry.o
    gcc-13 -std=c11 -Os -Wall -Wextra -Werror -ffreestanding -fno-stack-protector -fno-pie \
        -fno-asynchronous-unwind-tables -mno-red-zone -mcmodel=large \
        -c "$root/scripts/tests/migration-workload.c" -o migration-workload.o
    ld --no-undefined --build-id=none -z noexecstack -s -T "$root/user/user.ld" \
        -o migration-runner migration-runner-entry.o migration-workload.o
    python3 "$root/scripts/verify-user-abi.py" migration-runner
    gcc-13 -c "$root/scripts/tests/fault-probe.S" -o fault-probe-entry.o
    gcc-13 -std=c11 -Os -Wall -Wextra -Werror -ffreestanding -fno-stack-protector -fno-pie \
        -fno-asynchronous-unwind-tables -mno-red-zone -mcmodel=large -DFAULT_PROBE \
        -c "$root/scripts/tests/fault-workload.c" -o fault-probe.o
    ld --no-undefined --build-id=none -z noexecstack -s -T "$root/user/user.ld" \
        -o fault-probe fault-probe-entry.o fault-probe.o
    python3 "$root/scripts/verify-user-abi.py" fault-probe
    gcc-13 -c "$root/scripts/tests/oom-entry.S" -o oom-entry.o
    for role in runner pressure survivor; do
        gcc-13 -std=c11 -Os -Wall -Wextra -Werror -ffreestanding -fno-stack-protector -fno-pie \
            -fno-asynchronous-unwind-tables -mno-red-zone -mcmodel=large "-DOOM_${role^^}" \
            -c "$root/scripts/tests/oom-workload.c" -o "oom-$role.o"
        ld --no-undefined --build-id=none -z noexecstack -s -T "$root/user/user.ld" \
            -o "oom-$role" oom-entry.o "oom-$role.o"
        python3 "$root/scripts/verify-user-abi.py" "oom-$role"
    done
    /usr/bin/rustc --edition 2021 --test "$root/scripts/tests/demand-process-host.rs" -o oom-loader-tests
    AGENTOS_OOM_ELF="$work/oom-pressure" ./oom-loader-tests --ignored --exact loaderAcceptsActualOomPressureElf --nocapture
    cp supervisor-runner pipe-runner pipe-receiver cow-runner demand-runner adoption-runner ipc-runner ipc-service migration-runner fault-runner fault-probe oom-runner oom-pressure oom-survivor "$stage_out/"
    touch -d @0 supervisor-runner pipe-runner pipe-receiver cow-runner demand-runner adoption-runner ipc-runner ipc-service migration-runner fault-runner fault-probe oom-runner oom-pressure oom-survivor
    printf '%s\n' "${files[@]}" supervisor-runner pipe-runner pipe-receiver cow-runner demand-runner adoption-runner ipc-runner ipc-service migration-runner fault-runner fault-probe oom-runner oom-pressure oom-survivor | cpio --quiet --reproducible --owner=0:0 -o -H newc > initramfs.cpio
    cp initramfs.cpio "$stage_out/test.cpio"
    gcc-13 -c "$root/boot/payload.S" -o payload.o
    ld -nostdlib --build-id=none -znocombreloc -T layout.ld -shared -Bsymbolic \
       /usr/lib/crt0-efi-x86_64.o loader.o payload.o -L/usr/lib -lefi -lgnuefi -o loader.so
    objcopy --strip-all -j .text -j .sdata -j .data -j .dynamic -j .dynsym -j .rela -j .reloc \
        -j .kernel -j .initrd --target=efi-app-x86_64 loader.so "$stage_out/test.unsigned.efi"
    sbsign --key "$keys/db.key" --cert "$keys/db.crt" --output "$stage_out/test.efi" "$stage_out/test.unsigned.efi"
    sbverify --cert "$keys/db.crt" "$stage_out/test.efi"
    python3 "$root/scripts/verify-supervisor-image.py" --write-identity
fi
