#!/usr/bin/env python3
"""Verify native ABI v2 identification in actual linked static user ELF files."""
import argparse
from pathlib import Path
import struct


class AbiError(ValueError):
    pass


def require(aCondition, aMessage):
    if not aCondition:
        raise AbiError(aMessage)


def span(aData, aOffset, aSize):
    require(0 <= aOffset <= len(aData) and 0 <= aSize <= len(aData) - aOffset,
            "ELF field or note exceeds file bounds")
    return aData[aOffset:aOffset + aSize]


def verify(aData):
    pHeader = struct.unpack("<16sHHIQQQIHHHHHH", span(aData, 0, 64))
    require(pHeader[0][:7] == b"\x7fELF\x02\x01\x01", "Expected little-endian ELF64")
    require(pHeader[1:4] == (2, 62, 1), "Expected static x86-64 ET_EXEC ELF version 1")
    require(pHeader[8:10] == (64, 56), "Unexpected ELF/program-header size")
    pTable = span(aData, pHeader[5], pHeader[10] * 56)
    pFound = 0
    for pOffset in range(0, len(pTable), 56):
        pProgram = struct.unpack_from("<IIQQQQQQ", pTable, pOffset)
        require(pProgram[0] not in (2, 3), "Dynamic/interpreter segments are unsupported")
        if pProgram[0] != 4:
            continue
        require(pProgram[2] % 4 == 0 and pProgram[7] in (0, 1, 4),
                "Native profile requires four-byte ELF note alignment")
        pNotes = span(aData, pProgram[2], pProgram[5])
        pAt = 0
        while pAt < len(pNotes):
            pNameSize, pDescSize, pType = struct.unpack("<III", span(pNotes, pAt, 12))
            pName = span(pNotes, pAt + 12, pNameSize)
            require(not pName or pName.endswith(b"\0"), "ELF note owner lacks NUL terminator")
            pDescAt = pAt + 12 + ((pNameSize + 3) & ~3)
            pDesc = span(pNotes, pDescAt, pDescSize)
            pEnd = pDescAt + ((pDescSize + 3) & ~3)
            span(pNotes, pAt, pEnd - pAt)
            if pName == b"AgentOS\0":
                require(pFound == 0, "Duplicate native ABI declarations")
                require(pType == 1 and pDescSize == 8,
                        "Unsupported AgentOS ELF note type or descriptor size")
                require(struct.unpack("<II", pDesc) == (2, 0),
                        "Unsupported native ABI version or flags")
                pFound += 1
            pAt = pEnd
    require(pFound == 1, "Missing native ABI declaration; unmarked ELF is reserved for Linux ABI")


def main():
    pParser = argparse.ArgumentParser(description=__doc__)
    pParser.add_argument("elf", type=Path, nargs="+")
    pArgs = pParser.parse_args()
    for pPath in pArgs.elf:
        try:
            verify(pPath.read_bytes())
        except (AbiError, OSError, struct.error) as pError:
            pParser.exit(1, f"{pPath}: {pError}\n")
        print(f"Native ABI v2 ELF note verified: {pPath}")


if __name__ == "__main__":
    main()
