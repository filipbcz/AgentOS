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

    def test_reject_missing_flush_wrong_backend_or_unexpected_write(self):
        for start, end, phase in (
            (stats(), stats(5120,4608,3,2,0), "write"),
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


if __name__ == "__main__":
    unittest.main()
