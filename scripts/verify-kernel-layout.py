"""Check the *linked* AgentOS kernel ELF against kernel.ld and paging.rs.

The single PT_LOAD is copied by the UEFI loader. The kernel then installs
independent page tables: .text is RX, .rodata is R/NX and .data/.bss is RW/NX.
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
KERNEL_START = 0x02000000
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
    require(get("<HH", 16) == (2, 62), "Expected fixed-address x86-64 ET_EXEC")
    entry, phoff, shoff = get("<QQQ", 24)
    phsize, phnum, shsize, shnum = get("<HHHH", 54)
    require(phnum == 1 and phsize == 56 and shsize == 64 and
            shnum > 0 and shnum < 1024, "Expected exactly one valid PT_LOAD")
    ptype, flags, offset, vaddr, paddr, filesz, memsz, alignment = get("<IIQQQQQQ", phoff)
    require(ptype == 1 and flags == 5, "EFI loader requires a single RX PT_LOAD")
    require(vaddr == KERNEL_START and paddr == vaddr and
            alignment == PAGE and offset % PAGE == 0 and
            0 < filesz <= memsz <= MAX_KERNEL and offset+filesz <= len(blob),
            "Invalid or oversized fixed-address loader segment")
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
        "segment": (offset, vaddr, filesz, memsz),
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
    off, vaddr, filesz, memsz = data["segment"]
    require(vaddr == begin and (memsz + PAGE-1)//PAGE*PAGE >= end-begin,
            "PT_LOAD fails to cover writable kernel memory")
    require(begin <= data["entry"] < ro, "kernel_main is not executable")
    writable = 0
    for section in data["sections"]:
        name, stype, flags, addr, fileoff, size = section[:6]
        if not flags & SHF_ALLOC or size == 0:
            continue
        require(addr >= begin and addr+size <= end and addr+size > addr,
                "Allocated section outside linker kernel_end")
        classify(flags, addr, addr+size, ro, rw, end)
        if stype == 8:  # .bss / NOBITS; loader zeroes memsz-filesz.
            require(flags & SHF_WRITE, "Nonwritable NOBITS section")
        else:
            require(fileoff == off + (addr-begin) and
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
