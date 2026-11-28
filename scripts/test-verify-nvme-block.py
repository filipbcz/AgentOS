"""Synthetic rejection fixtures, never a guest acceptance result."""
import tempfile
import unittest
import uuid
from pathlib import Path
from ahci_block_evidence import SIZE, HEADER, MAGIC, BYTES
from pci_evidence import expected_records
from nvme_block_evidence import verify


class NvmeEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.run = Path(self.tmp.name) / "AgentOS-signed-0123456789"
        self.run.mkdir()
        seed = bytes(range(256))
        before = bytearray(SIZE)
        before[HEADER:HEADER+272] = MAGIC + seed
        before[-BYTES-512:-BYTES] = bytes([73]) * 512
        self.put("block.raw", before)
        payload = bytes(seed[i % 256] ^ (i // 256) for i in range(BYTES))
        digest = 2166136261
        for byte in payload:
            digest = ((digest ^ byte) * 16777619) & 0xffffffff
        after = before[:-BYTES] + payload
        self.put("block-after.raw", after)
        self.put("block-read-after.raw", after)
        medium = uuid.UUID("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
        self.put("block.vdi", bytes(392) + medium.bytes_le)
        attach = (f'name="{self.run.name}"\nVMState="poweroff"\n'
                  'UUID="11111111-2222-3333-4444-555555555555"\n'
                  'storagecontrollername1="NVMe"\nstoragecontrollertype1="NVMe"\n'
                  f'"NVMe-ImageUUID-0-0"="{medium}"\n'
                  f'"NVMe-0-0"="C:\\runs\\{self.run.name}\\block.vdi"\n')
        self.put("block-restart.txt", attach)
        self.put("block-read-poweroff.txt", attach)
        devices = []
        for bdf, vendor, device, code, offset, bar in (
            ("0000:00:01.0", 0x8086, 0x2829, 0x010601, 0x24, 0xf0000000),
            ("0000:00:02.0", 0x1af4, 0x1000, 0x020000, 0x10, 0xf0010000),
            ("0000:00:03.0", 0x80ee, 0x4e56, 0x010802, 0x10, 0xf0020004),
        ):
            cfg = bytearray(256)
            cfg[0:2] = vendor.to_bytes(2, "little")
            cfg[2:4] = device.to_bytes(2, "little")
            cfg[9:12] = code.to_bytes(3, "little")
            cfg[offset:offset+4] = bar.to_bytes(4, "little")
            devices.append((bdf, vendor, device, cfg))
        pci, guest_pci = [], ["AGENTOS PCI CONFIG ECAM"]
        for bdf, vendor, device, cfg in devices:
            pci += [f"{bdf[5:]} Device: {vendor:04x}-{device:04x}", "PCI registers:"]
            pci += [cfg[i:i+16].hex(" ") for i in range(0, 256, 16)]
            guest_pci += ["AGENTOS PCI " + s for s in expected_records(bdf, cfg)]
        guest_pci.append("AGENTOS PCI END FUNCTIONS=3")
        for name in ("block-write-pci.txt", "vbox-pci.txt"):
            self.put(name, "\n".join(pci) + "\n")
        ready = guest_pci + [
            "AGENTOS NVME READY NSID=1 BLOCKS=16384 SIZE=512 DEPTH=8 STRIDE=4",
            "AGENTOS NVME IO OP=02 LBA=2048 BLOCKS=1 CID=1",
            "AGENTOS BLOCK READY BLOCKS=16384 SIZE=512",
            "AGENTOS NVME IO OP=02 LBA=16375 BLOCKS=8 CID=2",
            "AGENTOS NVME IO OP=02 LBA=16383 BLOCKS=1 CID=3",
        ]
        for phase, serial, records in (
            ("write", "block-write-com1.log", [
                "AGENTOS NVME IO OP=01 LBA=16375 BLOCKS=8 CID=4",
                "AGENTOS NVME IO OP=01 LBA=16383 BLOCKS=1 CID=5",
                f"AGENTOS BLOCK WRITE LBA=16375 BYTES=4608 FNV={digest:08x}",
                "AGENTOS NVME IO OP=00 LBA=0 BLOCKS=0 CID=6",
                "AGENTOS BLOCK FLUSH OK",
            ]),
            ("read", "serial-com1.log", [
                f"AGENTOS BLOCK READ LBA=16375 BYTES=4608 FNV={digest:08x}",
            ]),
        ):
            self.put(serial, "\n".join(ready + records + [
                "AGENTOS NVME CLOSED RDY=0 MASTER=0 DMA=5"]) + "\n")
            hour = "10" if phase == "write" else "11"
            self.put(f"block-{phase}-vbox.log",
                     f"Log opened 2026-11-25T{hour}:00:00Z\n"
                     "NumCPUs <integer> = 0x2 (2)\n"
                     f"C:\\runs\\{self.run.name}\\block.vdi\n"
                     "Changing VM state from 'DESTROYING' to 'TERMINATED'\n")

    def put(self, name, data):
        (self.run / name).write_bytes(data.encode() if isinstance(data, str) else data)

    def test_complete_fixture(self):
        verify(self.run, 2)

    def test_missing_flush_wrong_cid_or_extra_write_rejected(self):
        for name, old, new in (
            ("block-write-com1.log", b"AGENTOS NVME IO OP=00 LBA=0 BLOCKS=0 CID=6\n", b""),
            ("block-write-com1.log", b"CID=4", b"CID=3"),
            ("serial-com1.log", b"OP=02 LBA=16383", b"OP=01 LBA=16383"),
            ("serial-com1.log", b"MASTER=0", b"MASTER=1"),
            ("block-read-poweroff.txt", b'VMState="poweroff"', b'VMState="running"'),
            ("block-restart.txt", b"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", b"aaaaaaaa-bbbb-cccc-dddd-ffffffffffff"),
            ("block-read-vbox.log", b"T11:00:00Z", b"T10:00:00Z"),
        ):
            original = (self.run / name).read_bytes()
            self.assertIn(old, original)
            with self.subTest(name=name, change=old):
                self.put(name, original.replace(old, new, 1))
                with self.assertRaises(ValueError):
                    verify(self.run, 2)
                self.put(name, original)

    def test_wrong_controller_or_changed_readback_rejected(self):
        for name in ("block-after.raw", "block-read-after.raw"):
            original = (self.run / name).read_bytes()
            self.put(name, bytes([original[0] ^ 1]) + original[1:])
            with self.assertRaises(ValueError):
                verify(self.run, 2)
            self.put(name, original)
        original = (self.run / "vbox-pci.txt").read_bytes()
        changed = original.replace(b"02 08 01", b"01 06 01", 1)
        self.assertNotEqual(original, changed)
        self.put("vbox-pci.txt", changed)
        with self.assertRaises(ValueError):
            verify(self.run, 2)


if __name__ == "__main__":
    unittest.main()
