"""Check actual assembly/linker note output and reject incompatible ABI metadata."""
import importlib.util
import os
from pathlib import Path
import shlex
import struct
import subprocess
import tempfile
import unittest

pSpec = importlib.util.spec_from_file_location(
    "native_abi_evidence", Path(__file__).with_name("verify-user-abi.py"))
gEvidence = importlib.util.module_from_spec(pSpec)
pSpec.loader.exec_module(gEvidence)


class NativeAbiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fTemp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.fTemp.cleanup)
        pRoot = Path(__file__).resolve().parent.parent
        pObject = Path(cls.fTemp.name) / "entry.o"
        pElf = Path(cls.fTemp.name) / "native"
        subprocess.run(shlex.split(os.environ.get("CC", "gcc")) +
                       ["-c", str(pRoot / "user/fault.S"), "-o", str(pObject)],
                       check=True, capture_output=True)
        subprocess.run([os.environ.get("LD", "ld"), "--no-undefined", "--build-id=none",
                        "-z", "noexecstack", "-s", "-T", str(pRoot / "user/user.ld"),
                        "-o", str(pElf), str(pObject)], check=True, capture_output=True)
        cls.fElf = pElf.read_bytes()
        pHeader = struct.unpack_from("<16sHHIQQQIHHHHHH", cls.fElf)
        for pIndex in range(pHeader[10]):
            pAt = pHeader[5] + pIndex * 56
            pProgram = struct.unpack_from("<IIQQQQQQ", cls.fElf, pAt)
            if pProgram[0] == 4:
                cls.fProgramAt, cls.fNoteAt = pAt, pProgram[2]
                cls.fNote = cls.fElf[pProgram[2]:pProgram[2] + pProgram[5]]
                break
        else:
            raise AssertionError("Production assembler/linker dropped the native ELF note")

    def withNotes(self, aNotes):
        pElf = bytearray(self.fElf)
        pElf.extend(bytes((-len(pElf)) % 4))
        pOffset = len(pElf)
        pElf.extend(aNotes)
        struct.pack_into("<Q", pElf, self.fProgramAt + 8, pOffset)
        struct.pack_into("<Q", pElf, self.fProgramAt + 32, len(aNotes))
        struct.pack_into("<Q", pElf, self.fProgramAt + 40, len(aNotes))
        return pElf

    def test_actual_production_entry_and_linker_preserve_v1_note(self):
        gEvidence.verify(self.fElf)
        self.assertEqual(self.fNote, struct.pack("<III8sII", 8, 8, 1, b"AgentOS\0", 1, 0))

    def test_unmarked_elf_is_not_silently_treated_as_native(self):
        pElf = bytearray(self.fElf)
        struct.pack_into("<I", pElf, self.fProgramAt, 0)
        with self.assertRaises(gEvidence.AbiError):
            gEvidence.verify(pElf)

    def test_unsupported_version_flags_type_and_size(self):
        for pAt, pValue in ((20, 2), (24, 1), (8, 9), (4, 4), (4, 12)):
            with self.subTest(offset=pAt, value=pValue):
                pNote = bytearray(self.fNote)
                struct.pack_into("<I", pNote, pAt, pValue)
                with self.assertRaises(gEvidence.AbiError):
                    gEvidence.verify(self.withNotes(pNote))

    def test_duplicate_native_note_is_ambiguous(self):
        with self.assertRaises(gEvidence.AbiError):
            gEvidence.verify(self.withNotes(self.fNote + self.fNote))

    def test_truncated_records_and_padding_are_rejected(self):
        for pLength in range(len(self.fNote)):
            with self.subTest(length=pLength), self.assertRaises(gEvidence.AbiError):
                gEvidence.verify(self.withNotes(self.fNote[:pLength]))
        with self.assertRaises(gEvidence.AbiError):
            gEvidence.verify(self.withNotes(self.fNote + b"\0"))

    def test_unbounded_sizes_and_misaligned_note_segments_are_rejected(self):
        for pOffset, pValue in ((8, (1 << 64) - 1), (32, (1 << 64) - 1),
                               (48, 3), (8, self.fNoteAt + 1)):
            with self.subTest(offset=pOffset):
                pElf = bytearray(self.fElf)
                struct.pack_into("<Q", pElf, self.fProgramAt + pOffset, pValue)
                with self.assertRaises(gEvidence.AbiError):
                    gEvidence.verify(pElf)

    def test_foreign_note_padding_cannot_hide_native_note_or_malformed_tail(self):
        pForeign = struct.pack("<III", 3, 1, 99) + b"XY\0\0" + b"x\0\0\0"
        gEvidence.verify(self.withNotes(pForeign + self.fNote))
        gEvidence.verify(self.withNotes(self.fNote + pForeign))
        with self.assertRaises(gEvidence.AbiError):
            gEvidence.verify(self.withNotes(self.fNote + pForeign[:-1]))

    def test_elf_header_and_dynamic_profile_are_validated(self):
        for pOffset, pValue in ((16, 3), (18, 3), (52, 63), (54, 55)):
            pElf = bytearray(self.fElf)
            struct.pack_into("<H", pElf, pOffset, pValue)
            with self.assertRaises(gEvidence.AbiError):
                gEvidence.verify(pElf)
        for pKind in (2, 3):
            pElf = bytearray(self.fElf)
            struct.pack_into("<I", pElf, self.fProgramAt - 56, pKind)
            with self.assertRaises(gEvidence.AbiError):
                gEvidence.verify(pElf)


if __name__ == "__main__":
    unittest.main()
