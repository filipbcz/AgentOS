"""Regression tests for linker W^X and missing static logger mappings."""
import copy
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


SPEC = importlib.util.spec_from_file_location(
    "kernel_layout", Path(__file__).with_name("verify-kernel-layout.py"))
layout = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(layout)


def image():
    begin = layout.KERNEL_START
    ro, rw, end = begin+0x2000, begin+0x3000, begin+0x4000
    # ELF section tuple: (name, type, flags, vaddr, file_offset, size,
    #                     link, info, align, entry_size)
    def section(kind, flags, addr, offset, size):
        return (0, kind, flags, addr, offset, size, 0, 0, 8, 0)
    return {
        "entry": begin+0x100,
        "segments": [(0x1000, begin, 0x1800, 0x1800),
                     (0x3000, ro, 0x400, 0x400),
                     (0x4000, rw, 0x800, 0xb00)],
        "sections": [
            section(1, layout.SHF_ALLOC|layout.SHF_EXEC, begin, 0x1000, 0x1800),
            section(1, layout.SHF_ALLOC, ro, 0x3000, 0x400),
            section(1, layout.SHF_ALLOC|layout.SHF_WRITE, rw, 0x4000, 0x800),
            section(8, layout.SHF_ALLOC|layout.SHF_WRITE, rw+0x800, 0x4800, 0x300),
        ],
        "symbols": {
            "kernel_begin": (begin, 0, 1),
            "kernel_ro": (ro, 0, 2),
            "kernel_rw": (rw, 0, 3),
            "kernel_end": (end, 0, 3),
            "_ZN4main6logger6LOGGER17h0fe37c805650df92E": (rw+0x100, 0x400, 3),
        },
        "blob": b"",
    }


class KernelImageLayoutTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "kernel.elf"
        self.path.write_bytes(b"ELF fixture replaced with in-memory section model")

    def verify(self, model):
        with patch.object(layout, "parse_elf", return_value=model):
            return layout.verify_kernel(self.path)

    def rejected(self, model):
        with self.assertRaises(layout.LayoutError):
            self.verify(model)

    def test_accepts_separate_read_only_and_mutable_sections(self):
        result = self.verify(image())
        self.assertEqual((result["code_pages"], result["ro_pages"], result["rw_pages"]),
                         (2, 1, 1))

    def test_regression_2026_11_21_logger_beyond_kernel_end(self):
        model = image()
        # Real QEMU failure: CR2 0x02015438 was logger tail outside
        # kernel_end; this artificial structure reproduces the same class.
        model["symbols"]["_ZN4main6logger6LOGGER17h0fe37c805650df92E"] = (
            model["symbols"]["kernel_end"][0]-8, 3872, 3)
        self.rejected(model)

    def test_orphan_allocated_section_outside_end(self):
        model = image()
        model["sections"].append(
            (0, 1, layout.SHF_ALLOC|layout.SHF_WRITE,
             model["symbols"]["kernel_end"][0], 0x5000, 64, 0, 0, 8, 0))
        self.rejected(model)

    def test_mutable_data_may_not_be_mapped_readonly(self):
        model = image()
        sec = list(model["sections"][1])
        sec[2] |= layout.SHF_WRITE
        model["sections"][1] = tuple(sec)
        self.rejected(model)

    def test_writable_executable_alias_is_rejected(self):
        model = image()
        sec = list(model["sections"][0])
        sec[2] |= layout.SHF_WRITE
        model["sections"][0] = tuple(sec)
        self.rejected(model)

    def test_segment_must_cover_all_mutable_pages(self):
        model = image()
        model["segments"][2] = (0x4000, layout.KERNEL_START+0x3000, 0x800, 0x800)
        self.rejected(model)

    def test_bad_alignment_or_invalid_section_file_offsets(self):
        model = image()
        model["symbols"]["kernel_rw"] = (layout.KERNEL_START+0x3001, 0, 3)
        self.rejected(model)
        model = image()
        sec = list(model["sections"][2])
        sec[4] += 1
        model["sections"][2] = tuple(sec)
        self.rejected(model)

    def test_unrecognized_or_truncated_elf_fails(self):
        for content in (b"", b"not an ELF", b"\x7fELF\x02\x01\x01"):
            with self.subTest(content=content):
                with self.assertRaises(layout.LayoutError):
                    layout.parse_elf(content)


if __name__ == "__main__":
    unittest.main()
