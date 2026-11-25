#!/usr/bin/env bash
# Host compilation/test gate. This does not create or sign an EFI image and
# does not replace build.sh's pinned toolchain or VirtualBox acceptance.
# RUSTC, CC, LD and PYTHON select executable names/paths, not shell commands.
set -euo pipefail
export LC_ALL=C SOURCE_DATE_EPOCH=0 PYTHONDONTWRITEBYTECODE=1
pRoot=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
pOut="$pRoot/build/check"
pRustc="${RUSTC:-rustc}"
pCc="${CC:-gcc}"
pLd="${LD:-ld}"
pPython="${PYTHON:-python3}"
pMissing=0
for pTool in "$pRustc" "$pCc" "$pLd" "$pPython"; do
    if ! command -v "$pTool" >/dev/null 2>&1; then
        printf 'Missing required host-check tool: %s\n' "$pTool" >&2
        pMissing=1
    fi
done
if ((pMissing)); then
    printf 'Install the missing tools, or set RUSTC/CC/LD/PYTHON to their executables. No downloads were attempted.\n' >&2
    exit 127
fi
# The shell harness parses CC as command words; preserve an executable path
# containing spaces while direct compiler calls below keep using the path.
CC=$("$pPython" -c 'import shlex, sys; print(shlex.quote(sys.argv[1]))' "$pCc")
export CC
mkdir -p "$pOut"
cd "$pRoot"

shopt -s nullglob
pTests=("$pRoot"/scripts/test-*.py)
if ((${#pTests[@]} == 0)); then
    printf 'No host Python tests found in %s/scripts\n' "$pRoot" >&2
    exit 1
fi
printf 'Parsing all Python harnesses (including optional QEMU diagnostics)\n'
"$pPython" - <<'PY'
import ast
from pathlib import Path
for source in sorted(Path("scripts").glob("*.py")):
    ast.parse(source.read_text(encoding="utf-8"), filename=str(source))
PY

for pTest in "${pTests[@]}"; do
    printf 'Running %s\n' "${pTest##*/}"
    "$pPython" "$pTest" -v
done

printf 'Testing canonical input and the actual TTY driver with %s\n' "$pRustc"
# This harness also includes line.rs's unit tests. Only port I/O and the IRQ
# route are replaced; the input discipline and Terminal implementation are real.
"$pRustc" --edition 2021 --test "$pRoot/scripts/tests/tty-host.rs" -o "$pOut/tty-tests"
"$pOut/tty-tests"

printf 'Testing PS/2 scan-code decoder with %s\n' "$pRustc"
"$pRustc" --edition 2021 --test "$pRoot/kernel/keyboard.rs" -o "$pOut/keyboard-tests"
"$pOut/keyboard-tests"

printf 'Testing early kernel logging policy with %s\n' "$pRustc"
"$pRustc" --edition 2021 --test "$pRoot/kernel/log_policy.rs" -o "$pOut/log-policy-tests"
"$pOut/log-policy-tests"

printf 'Testing PS/2 controller rollback with %s\n' "$pRustc"
"$pRustc" --edition 2021 --test "$pRoot/scripts/tests/ps2-host.rs" -o "$pOut/ps2-tests"
"$pOut/ps2-tests"

printf 'Testing bounded kernel log history with %s\n' "$pRustc"
"$pRustc" --edition 2021 --test "$pRoot/scripts/tests/log-ring-host.rs" -o "$pOut/log-ring-tests"
"$pOut/log-ring-tests"

printf 'Testing SMP/IRQ safe runtime logger with %s\n' "$pRustc"
"$pRustc" --edition 2021 --test "$pRoot/scripts/tests/logger-host.rs" -o "$pOut/logger-tests"
"$pOut/logger-tests"

printf 'Testing GOP text console bounds, ASCII and scrolling with %s\n' "$pRustc"
"$pRustc" --edition 2021 --test "$pRoot/scripts/tests/fb-console-host.rs" -o "$pOut/fb-console-tests"
"$pOut/fb-console-tests"

printf 'Testing actual COW paging clone, W^X and OOM rollback with %s\n' "$pRustc"
"$pRustc" --edition 2021 --test "$pRoot/scripts/tests/paging-cow-host.rs" -o "$pOut/paging-cow-tests"
"$pOut/paging-cow-tests"

printf 'Testing exact frame-snapshot accounting for retained lazy processes with %s\n' "$pRustc"
"$pRustc" --edition 2021 --test "$pRoot/scripts/tests/frame-snapshot-host.rs" -o "$pOut/frame-snapshot-tests"
"$pOut/frame-snapshot-tests"

printf 'Testing actual lazy ELF loader, file/pipe/IPC copies and OOM rollback with %s\n' "$pRustc"
"$pRustc" --edition 2021 --test "$pRoot/scripts/tests/demand-process-host.rs" -o "$pOut/demand-process-tests"
"$pOut/demand-process-tests"

printf 'Testing shared cross-CPU process lifecycle and deferred reaping with %s\n' "$pRustc"
"$pRustc" --edition 2021 --test "$pRoot/scripts/tests/lifecycle-host.rs" -o "$pOut/lifecycle-tests"
"$pOut/lifecycle-tests"

printf 'Testing shared HPET time and ACPI discovery with %s\n' "$pRustc"
"$pRustc" --edition 2021 --test "$pRoot/kernel/hpet.rs" -o "$pOut/hpet-tests"
"$pOut/hpet-tests"
"$pRustc" --edition 2021 --test "$pRoot/scripts/tests/acpi-host.rs" -o "$pOut/acpi-tests"
"$pOut/acpi-tests"

printf 'Testing native ELF ABI declaration and malformed input rejection with %s\n' "$pRustc"
"$pRustc" --edition 2021 --test "$pRoot/kernel/native_abi.rs" -o "$pOut/native-abi-tests"
"$pOut/native-abi-tests"

printf 'Testing kernel stack guard pages, permissions and allocation rollback with %s\n' "$pRustc"
"$pRustc" --edition 2021 --test "$pRoot/scripts/tests/kernel-stack-host.rs" -o "$pOut/kernel-stack-tests"
"$pOut/kernel-stack-tests"

printf 'Testing actual cross-CPU scheduler ownership, lifecycle and timed waits with %s\n' "$pRustc"
"$pRustc" --edition 2021 --test "$pRoot/scripts/tests/scheduler-timed-host.rs" -o "$pOut/scheduler-timed-tests"
"$pOut/scheduler-timed-tests"

printf 'Testing PID1 supervision and forced-child cleanup with %s\n' "$pCc"
"$pCc" -std=c11 -O2 -Wall -Wextra -Werror -fno-stack-protector \
    "$pRoot/scripts/tests/supervisor-host.c" -o "$pOut/supervisor-tests"
"$pOut/supervisor-tests"

printf 'Testing persistent service registry, authenticated readiness, capped restarts and shutdown with %s\n' "$pCc"
"$pCc" -std=c11 -O2 -Wall -Wextra -Werror -fno-stack-protector \
    "$pRoot/scripts/tests/service-manager-host.c" -o "$pOut/service-manager-tests"
"$pOut/service-manager-tests"

printf 'Testing actual managed service worker timer readiness, IPC handshake and failure isolation with %s\n' "$pCc"
"$pCc" -std=c11 -O2 -Wall -Wextra -Werror -fno-stack-protector \
    "$pRoot/scripts/tests/service-worker-host.c" -o "$pOut/service-worker-tests"
"$pOut/service-worker-tests"

"$pCc" -std=c11 -O2 -Wall -Wextra -Werror \
    "$pRoot/scripts/tests/migration-host.c" -o "$pOut/migration-tests"
"$pOut/migration-tests"

printf 'Testing actual orphan program and failure injection with %s\n' "$pCc"
"$pCc" -std=c11 -O2 -Wall -Wextra -Werror -fno-stack-protector \
    "$pRoot/scripts/tests/orphans-host.c" -o "$pOut/orphans-tests"
"$pOut/orphans-tests"

printf 'Testing per-CPU monotonic TSC time conversion with %s\n' "$pRustc"
"$pRustc" --edition 2021 --test "$pRoot/kernel/monotonic.rs" -o "$pOut/monotonic-tests"
"$pOut/monotonic-tests"

printf 'Testing NVMe wire format, geometry and queue ownership\n'
"$pRustc" --edition 2021 --test "$pRoot/kernel/nvme/protocol.rs" -o "$pOut/nvme-tests"
"$pOut/nvme-tests"

printf 'Testing VirtIO PCI capabilities, feature subset and split ring ownership\n'
"$pRustc" --edition 2021 --test "$pRoot/kernel/virtio_net/protocol.rs" -o "$pOut/virtio-net-tests"
"$pOut/virtio-net-tests"

printf 'Compiling and linking the kernel with %s and %s\n' "$pRustc" "$pCc"
"$pRustc" --version
"$pCc" --version
"$pRustc" --edition 2021 --crate-type staticlib -C lto=fat -C opt-level=2 -C panic=abort \
    -C relocation-model=static -C no-redzone=yes -C overflow-checks=no \
    --remap-path-prefix="$pRoot"=/agentos "$pRoot/kernel/main.rs" -o "$pOut/libkernel.a"
"$pCc" -c "$pRoot/kernel/ap-start.S" -o "$pOut/ap-start.o"
"$pLd" --no-undefined --build-id=none --gc-sections -T "$pRoot/kernel/kernel.ld" \
    -o "$pOut/kernel.elf" "$pOut/libkernel.a" "$pOut/ap-start.o"
"$pPython" "$pRoot/scripts/verify-kernel-layout.py" "$pOut/kernel.elf"
"$pPython" "$pRoot/scripts/verify-trap-return.py" "$pOut/kernel.elf"

# Also link the actual NVMe opt-in profile.
"$pRustc" --edition 2021 --crate-type staticlib -C lto=fat -C opt-level=2 -C panic=abort \
    -C relocation-model=static -C no-redzone=yes -C overflow-checks=no \
    --cfg nvme_block_acceptance --remap-path-prefix="$pRoot"=/agentos "$pRoot/kernel/main.rs" -o "$pOut/libkernel-nvme.a"
"$pLd" --no-undefined --build-id=none --gc-sections -T "$pRoot/kernel/kernel.ld" \
    -o "$pOut/kernel-nvme.elf" "$pOut/libkernel-nvme.a" "$pOut/ap-start.o"
"$pPython" "$pRoot/scripts/verify-kernel-layout.py" "$pOut/kernel-nvme.elf"
"$pPython" "$pRoot/scripts/verify-trap-return.py" "$pOut/kernel-nvme.elf"

# Link the real isolated VirtIO-net profile as well.
"$pRustc" --edition 2021 --crate-type staticlib -C lto=fat -C opt-level=2 -C panic=abort \
    -C relocation-model=static -C no-redzone=yes -C overflow-checks=no \
    --cfg virtio_net_acceptance --remap-path-prefix="$pRoot"=/agentos "$pRoot/kernel/main.rs" -o "$pOut/libkernel-virtio-net.a"
"$pLd" --no-undefined --build-id=none --gc-sections -T "$pRoot/kernel/kernel.ld" \
    -o "$pOut/kernel-virtio-net.elf" "$pOut/libkernel-virtio-net.a" "$pOut/ap-start.o"
"$pPython" "$pRoot/scripts/verify-kernel-layout.py" "$pOut/kernel-virtio-net.elf"
"$pPython" "$pRoot/scripts/verify-trap-return.py" "$pOut/kernel-virtio-net.elf"

for pApp in init fault receiver service shell svc_ok svc_fail svc_hang orphan_parent manager svc_alive svc_flaky; do
    printf 'Compiling and linking user program %s\n' "$pApp"
    pEntry="$pApp"
    if [[ "$pApp" == svc_alive || "$pApp" == svc_flaky ]]; then pEntry=svc_worker; fi
    "$pCc" -c "$pRoot/user/$pEntry.S" -o "$pOut/$pApp-entry.o"
    pObjects=("$pOut/$pApp-entry.o")
    case "$pApp" in
        init) pSources=(transfer client supervisor orphans forktest demand migration service_manager);;
        receiver) pSources=(receive);;
        service) pSources=(service);;
        shell) pSources=(shell service_client);;
        manager) pSources=(service_manager);;
        svc_alive|svc_flaky) pSources=(svc_worker);;
        *) pSources=();;
    esac
    for pSource in "${pSources[@]}"; do
        pDefines=()
        if [[ "$pApp" == svc_flaky ]]; then pDefines=(-DAGENTOS_FLAKY); fi
        "$pCc" -std=c11 -Os -Wall -Wextra -Werror -ffreestanding -fno-stack-protector -fno-pie \
            -fno-asynchronous-unwind-tables -mno-red-zone -mcmodel=large "${pDefines[@]}" \
            -c "$pRoot/user/$pSource.c" -o "$pOut/$pSource.o"
        pObjects+=("$pOut/$pSource.o")
    done
    "$pLd" --no-undefined --build-id=none -z noexecstack -s -T "$pRoot/user/user.ld" \
        -o "$pOut/$pApp" "${pObjects[@]}"
    "$pPython" "$pRoot/scripts/verify-user-abi.py" "$pOut/$pApp"
done
printf 'Host tests and kernel/user ELF links passed: %s\n' "$pOut"
printf 'EFI assembly/signing, pinned-toolchain reproducibility and VM execution remain separate checks.\n'
