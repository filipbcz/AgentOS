"""Host tests for QEMU NVMe evidence; not guest results."""
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location("qemu_nvme", Path(__file__).with_name("qemu-nvme.py"))
nvme = importlib.util.module_from_spec(spec)
spec.loader.exec_module(nvme)


def stats(rd=512, wr=0, reads=1, writes=0, flush=0):
    return [{"device": "nvdata", "stats": {"rd_bytes": rd, "wr_bytes": wr,
              "rd_operations": reads, "wr_operations": writes, "flush_operations": flush}}]


class StatsTests(unittest.TestCase):
    def test_write_then_read(self):
        self.assertEqual(nvme.verify_stats(stats(), stats(5120,4608,3,2,1), "write")["wr_bytes"], 4608)
        self.assertEqual(nvme.verify_stats(stats(), stats(5120,0,3,0,0), "read")["rd_bytes"], 4608)

    def test_qmp_zero_flush_counter_is_not_a_missing_guest_flush(self):
        # QEMU 8.2.2 does not account NVMe flushes in BlockStats. The separate
        # real controller trace (tested below) is still mandatory.
        self.assertEqual(nvme.verify_stats(stats(), stats(5120,4608,3,2,0), "write")["wr_bytes"], 4608)

    def test_reject_wrong_backend_or_unexpected_write(self):
        for start, end, phase in (
            (stats(), stats(5120,4608,3,2,1), "read"),
            (stats(), stats(5120,4096,3,1,1), "write"),
            (stats(), stats(5120,0,2,0,0), "read"),
            (stats(), stats(0,0,0,0,0), "read"),
            (stats(wr=512,writes=1), stats(5120,512,3,1,0), "read"),
            ([], stats(5120,0,3,0,0), "read"),
        ):
            with self.subTest(start=start, end=end, phase=phase), self.assertRaises(ValueError):
                nvme.verify_stats(start, end, phase)
        end = stats(5120,0,3,0,0)
        end[0]["stats"]["failed_rd_operations"] = 1
        with self.assertRaises(ValueError):
            nvme.verify_stats(stats(), end, "read")


def trace(phase, prefix=""):
    lines = [prefix + "pci_nvme_enqueue_req_completion cid 1 cqid 0 dw0 0x0 dw1 0x0 status 0x0"]
    ops = (2, 2, 2, 1, 1, 0) if phase == "write" else (2, 2, 2)
    for cid, op in enumerate(ops, 1):
        lines.append(prefix + f"pci_nvme_io_cmd cid {cid} nsid 0x1 sqid 1 opc 0x{op:x} opname 'test'")
        if op == 0:
            lines.append(prefix + "pci_nvme_flush_ns nsid 0x1")
        lines.append(prefix + f"pci_nvme_enqueue_req_completion cid {cid} cqid 1 dw0 0x0 dw1 0x0 status 0x0")
    return "\n".join(lines) + "\n"


class TraceTests(unittest.TestCase):
    def test_real_trace_format_including_optional_timestamp(self):
        for prefix in ("", "123@1730000000.123456:"):
            self.assertEqual(nvme.verify_trace(trace("write", prefix), "write")["flush_commands"], 1)
            self.assertEqual(nvme.verify_trace(trace("read", prefix), "read")["successful_completions"], 3)

    def test_flush_trace_and_successful_completion_are_both_required(self):
        good = trace("write")
        for bad in (
            good.replace("pci_nvme_flush_ns nsid 0x1\n", ""),
            good.replace("cid 6 cqid 1 dw0 0x0 dw1 0x0 status 0x0", "cid 6 cqid 1 dw0 0x0 dw1 0x0 status 0x2"),
            good.replace("cid 6 nsid 0x1 sqid 1 opc 0x0", "cid 6 nsid 0x2 sqid 1 opc 0x0"),
            good.replace("cid 6 nsid 0x1 sqid 1 opc 0x0", "cid 6 nsid 0x1 sqid 0 opc 0x0"),
            good.replace("cid 5 cqid 1", "cid 4 cqid 1"),
            "",
            trace("read"),
        ):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                nvme.verify_trace(bad, "write")
        with self.assertRaises(ValueError):
            nvme.verify_trace(good, "read")


if __name__ == "__main__":
    unittest.main()
