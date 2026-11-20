#!/usr/bin/env bash
set -euo pipefail
dir=$1
efi=$2
level=${3:-info}
case "$level" in quiet|info|debug) ;; *) exit 2;; esac
img="$dir/esp.raw"
[[ -d "$dir" && ! -e "$img" && -f "$efi" ]]
truncate -s 80M "$img"
sgdisk -n 1:2048:+70M -t 1:ef00 "$img" >/dev/null
fat="$img@@1048576"
mformat -i "$fat" -T 143360 -F -v AGENTOS ::
mmd -i "$fat" ::EFI ::EFI/BOOT
mcopy -i "$fat" "$efi" ::EFI/BOOT/BOOTX64.EFI
printf '%s\n' "$level" | mcopy -i "$fat" - ::EFI/BOOT/BOOT.LOG
