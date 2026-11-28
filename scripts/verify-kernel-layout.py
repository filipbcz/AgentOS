"""Check the *linked* AgentOS kernel ELF against kernel.ld and paging.rs.

The static PIE has three independent PT_LOAD segments. The UEFI loader
relocates it; the kernel installs matching RX, R/NX and RW/NX page tables.
Fail closed on any SHF_ALLOC orphan, writable/executable overlap, misplaced
mutable global or non-page-aligned W^X boundary. This check must be run on
every final kernel ELF, not just on individual compiler object files.
"""
import argparse
from pathlib import Path
import struct
import sys


class LayoutError(ValueError):
    pass


PAGE = 4096
KERNEL_START = 0
MAX_KERNEL = 16 * 1024 * 1024
SHF_WRITE, SHF_ALLOC, SHF_EXEC = 1, 2, 4


def require(condition, description):
    if not condition:
        raise LayoutError(description)


def parse_elf(blob):
    def get(fmt, at):
        size = struct.calcsize(fmt)
        require(at >= 0 and at + size <= len(blob), "Truncated kernel ELF")
        return struct.unpack_from(fmt, blob, at)

    require(blob[:7] == b"\x7fELF\x02\x01\x01", "Expected ELF64 little-endian")
    require(get("<HH", 16) == (3, 62), "Expected static PIE x86-64 ET_DYN")
    entry, phoff, shoff = get("<QQQ", 24)
    phsize, phnum, shsize, shnum = get("<HHHH", 54)
    require(phnum == 4 and phsize == 56 and shsize == 64 and
            shnum > 0 and shnum < 1024 and phoff >= 64,
            "Expected three PT_LOAD and one PT_DYNAMIC")
    segments = []
    next_address, previous_file_end = KERNEL_START, phoff + phnum*phsize
    for index, expected_flags in enumerate((5, 4, 6)):
        ptype, flags, offset, vaddr, paddr, filesz, memsz, alignment = get(
            "<IIQQQQQQ", phoff + index*phsize)
        require(ptype == 1 and flags == expected_flags and
                vaddr == next_address and paddr == vaddr and
                alignment == PAGE and offset % PAGE == 0 and
                offset >= previous_file_end and
                0 < filesz <= memsz and offset+filesz <= len(blob) and
                vaddr+memsz <= MAX_KERNEL and (index == 2 or filesz == memsz),
                "Invalid or overlapping static PIE load segment")
        segments.append((offset, vaddr, filesz, memsz))
        previous_file_end = offset+filesz
        next_address = (vaddr+memsz+PAGE-1)//PAGE*PAGE
    ptype, flags, offset, vaddr, paddr, filesz, memsz, alignment = get(
        "<IIQQQQQQ", phoff + 3*phsize)
    rw_off, rw_va, rw_filesz, _ = segments[2]
    require(ptype == 2 and flags == 6 and paddr == vaddr and
            alignment == 8 and vaddr % 8 == 0 and 0 < filesz == memsz and
            filesz % 16 == 0 and rw_va <= vaddr and
            vaddr+filesz <= rw_va+rw_filesz and offset == rw_off+vaddr-rw_va,
            "Invalid PT_DYNAMIC")
    # The C loader's separate host test checks the real dynamic table and
    # every relocation on every actual linked image.
    sections = [get("<IIQQQQIIQQ", shoff + i*shsize) for i in range(shnum)]
    symbols = {}
    for sec in sections:
        stype, start, size, link, entsize = sec[1], sec[4], sec[5], sec[6], sec[9]
        if stype != 2:
            continue
        require(entsize == 24 and size % entsize == 0 and link < shnum,
                "Malformed ELF symbol table")
        strings = sections[link]
        require(strings[1] == 3, "ELF symbol table has no string table")
        string_data = blob[strings[4]:strings[4]+strings[5]]
        require(len(string_data) == strings[5], "Truncated ELF names")
        for i in range(0, size, entsize):
            name, info, other, index, value, length = get("<IBBHQQ", start+i)
            if name < len(string_data):
                symbol = string_data[name:].split(b"\0", 1)[0].decode("ascii", errors="replace")
                symbols[symbol] = (value, length, index)
    return {
        "entry": entry,
        "segments": segments,
        "sections": sections,
        "symbols": symbols,
        "blob": blob,
    }


def classify(flags, address, limit, ro, rw, end):
    require(not (flags & SHF_WRITE and flags & SHF_EXEC),
            "Writable and executable kernel section detected")
    if flags & SHF_EXEC:
        require(KERNEL_START <= address < limit <= ro,
                "Executable code spills outside RX segment")
    elif flags & SHF_WRITE:
        require(rw <= address < limit <= end,
                "Mutable data outside RW/NX kernel segment")
    else:
        require(ro <= address < limit <= rw,
                "Read-only data outside R/NX kernel segment")


def verify_kernel(path):
    data = parse_elf(Path(path).read_bytes())
    symbols = data["symbols"]
    labels = ("kernel_begin", "kernel_ro", "kernel_rw", "kernel_end")
    require(all(label in symbols for label in labels),
            "Missing W^X linker boundary symbol")
    begin, ro, rw, end = (symbols[label][0] for label in labels)
    require(begin == KERNEL_START and begin < ro <= rw < end and
            end - begin <= MAX_KERNEL and
            all(addr % PAGE == 0 for addr in (begin, ro, rw, end)),
            "Invalid page-aligned kernel W^X region boundaries")
    segments = data["segments"]
    require(len(segments) == 3, "Missing distinct W^X load segments")
    for (off, vaddr, filesz, memsz), first, limit in zip(
            segments, (begin, ro, rw), (ro, rw, end)):
        require(vaddr == first and 0 < filesz <= memsz and
                (memsz+PAGE-1)//PAGE*PAGE == limit-first,
                "PT_LOAD fails to cover its complete W^X region")
    require(begin <= data["entry"] < ro, "kernel_main is not executable")
    writable = 0
    for section in data["sections"]:
        name, stype, flags, addr, fileoff, size = section[:6]
        if not flags & SHF_ALLOC or size == 0:
            continue
        require(addr >= begin and addr+size <= end and addr+size > addr,
                "Allocated section outside linker kernel_end")
        classify(flags, addr, addr+size, ro, rw, end)
        index = 0 if flags & SHF_EXEC else 2 if flags & SHF_WRITE else 1
        off, vaddr, filesz, memsz = segments[index]
        require(vaddr <= addr and addr+size <= vaddr+memsz,
                "Allocated section not covered by its PT_LOAD memory")
        if stype == 8:  # .bss / NOBITS; loader zeroes memsz-filesz.
            require(flags & SHF_WRITE, "Nonwritable NOBITS section")
        else:
            require(fileoff == off + (addr-vaddr) and
                    fileoff + size <= off + filesz,
                    "Allocated ELF section not included in loader file bytes")
        if flags & SHF_WRITE:
            writable += 1
    require(writable > 0, "Kernel mutable globals missing from PT_LOAD")
    # This symbol was the concrete cause of the first real QEMU page fault:
    # an orphan .data.* was *after* kernel_end, faulting at CR2=0x02015438.
    logger = [v for k, v in symbols.items() if "logger" in k and "LOGGER" in k and v[1]]
    require(logger, "Runtime kernel logger not linked into image")
    for address, size, index in logger:
        require(rw <= address and address+size <= end,
                "Kernel logger allocated outside mapped RW/NX segment")
    return {"code_pages": (ro-begin)//PAGE,
            "ro_pages": (rw-ro)//PAGE,
            "rw_pages": (end-rw)//PAGE,
            "logger_address": logger[0][0],
            "kernel_end": end}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("kernel_elf", type=Path)
    args = parser.parse_args()
    try:
        layout = verify_kernel(args.kernel_elf)
    except (LayoutError, OSError, struct.error) as error:
        print(f"Kernel W^X layout verification failed: {error}", file=sys.stderr)
        return 1
    print("Kernel W^X image accepted: "
          f"RX={layout['code_pages']} pages, "
          f"R/NX={layout['ro_pages']} pages, "
          f"RW/NX={layout['rw_pages']} pages, "
          f"LOGGER=0x{layout['logger_address']:x}, "
          f"end=0x{layout['kernel_end']:x}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
