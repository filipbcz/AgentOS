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

printf 'Testing PID1 supervision and forced-child cleanup with %s\n' "$pCc"
"$pCc" -std=c11 -O2 -Wall -Wextra -Werror -fno-stack-protector \
    "$pRoot/scripts/tests/supervisor-host.c" -o "$pOut/supervisor-tests"
"$pOut/supervisor-tests"

printf 'Compiling and linking the kernel with %s and %s\n' "$pRustc" "$pCc"
"$pRustc" --version
"$pCc" --version
"$pRustc" --edition 2021 --crate-type staticlib -C lto=fat -C opt-level=2 -C panic=abort \
    -C relocation-model=static -C no-redzone=yes -C overflow-checks=no \
    --remap-path-prefix="$pRoot"=/agentos "$pRoot/kernel/main.rs" -o "$pOut/libkernel.a"
"$pCc" -c "$pRoot/kernel/ap-start.S" -o "$pOut/ap-start.o"
"$pLd" --no-undefined --build-id=none --gc-sections -T "$pRoot/kernel/kernel.ld" \
    -o "$pOut/kernel.elf" "$pOut/libkernel.a" "$pOut/ap-start.o"

for pApp in init fault receiver service shell svc_ok svc_fail svc_hang; do
    printf 'Compiling and linking user program %s\n' "$pApp"
    "$pCc" -c "$pRoot/user/$pApp.S" -o "$pOut/$pApp-entry.o"
    pObjects=("$pOut/$pApp-entry.o")
    case "$pApp" in
        init) pSources=(transfer client supervisor);;
        receiver) pSources=(receive);;
        service) pSources=(service);;
        shell) pSources=(shell);;
        *) pSources=();;
    esac
    for pSource in "${pSources[@]}"; do
        "$pCc" -std=c11 -Os -Wall -Wextra -Werror -ffreestanding -fno-stack-protector -fno-pie \
            -fno-asynchronous-unwind-tables -mno-red-zone -mcmodel=large \
            -c "$pRoot/user/$pSource.c" -o "$pOut/$pSource.o"
        pObjects+=("$pOut/$pSource.o")
    done
    "$pLd" --no-undefined --build-id=none -z noexecstack -s -T "$pRoot/user/user.ld" \
        -o "$pOut/$pApp" "${pObjects[@]}"
done
printf 'Host tests and kernel/user ELF links passed: %s\n' "$pOut"
printf 'EFI assembly/signing, pinned-toolchain reproducibility and VM execution remain separate checks.\n'
