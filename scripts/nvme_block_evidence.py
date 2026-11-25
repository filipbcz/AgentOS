"""Offline evidence for an isolated NVMe fixture, not a simulated guest test."""
from pathlib import Path
import re
import uuid
from ahci_block_evidence import SIZE, HEADER, MAGIC, BYTES, require
from pci_evidence import config_spaces, verify_inventory


def read_text(path):
    return path.read_text("utf-8-sig", errors="replace")


def medium_identity(run, text, medium):
    lines = text.splitlines()
    require(f'name="{run.name}"' in lines and 'VMState="poweroff"' in lines,
            "Missing named, powered-off VM")
    require(f'"NVMe-ImageUUID-0-0"="{medium}"' in lines,
            "Cold NVMe restart used another medium")
    require(any(line.lower().startswith('"nvme-0-0"=') and
                line.lower().endswith(f'\\{run.name.lower()}\\block.vdi"') for line in lines),
            "NVMe attachment is not the dedicated run VDI")
    controller = re.findall(r'^storagecontrollername(\d+)="NVMe"$', text, re.M)
    require(len(controller) == 1 and
            f'storagecontrollertype{controller[0]}="NVMe"' in lines,
            "Missing actual NVMe controller configuration")
    vm = re.findall(r'^UUID="([0-9a-f-]{36})"$', text, re.M | re.I)
    require(len(vm) == 1, "Missing persistent VM UUID")
    return uuid.UUID(vm[0])


def controller_identity(log, dump):
    verify_inventory(log, dump, "ich9")
    controllers = [(bdf, cfg) for bdf, cfg in config_spaces(dump).items()
                   if cfg[9:12] == b"\x02\x08\x01"]
    require(len(controllers) == 1, "Expected one NVMe controller")
    bdf, cfg = controllers[0]
    low = int.from_bytes(cfg[16:20], "little")
    base = low & ~15
    if low & 7 == 4:
        base |= int.from_bytes(cfg[20:24], "little") << 32
    require(low & 7 in (0, 4) and base != 0, "Missing NVMe BAR0")
    return bdf, cfg[:4], base


def expected_disk(path):
    before = Path(path).read_bytes()
    require(len(before) == SIZE and before[HEADER:HEADER+16] == MAGIC and
            before[-BYTES:] == bytes(BYTES), "Invalid initial disk")
    seed = before[HEADER+16:HEADER+272]
    require(len(set(seed)) > 1, "Missing random fixture")
    payload = bytes(seed[i % 256] ^ (i // 256) for i in range(BYTES))
    after = before[:-BYTES] + payload
    digest = 2166136261
    for byte in payload:
        digest = ((digest ^ byte) * 16777619) & 0xffffffff
    details = f"LBA=16375 BYTES={BYTES} FNV={digest:08x}"
    return after, details


def verify_guest(guest, phase, details):
    require(phase in ("write", "read"), "Invalid NVMe phase")
    events = [line for line in guest.splitlines()
              if line.startswith(("AGENTOS NVME ", "AGENTOS BLOCK "))]
    require(events, "Missing NVMe records")
    ready = re.fullmatch(r"AGENTOS NVME READY NSID=1 BLOCKS=16384 SIZE=512 DEPTH=(\d+) STRIDE=(\d+)", events[0])
    require(ready is not None, "Missing identified NVMe namespace")
    depth, stride = map(int, ready.groups())
    require(2 <= depth <= 8 and 4 <= stride <= 1024 and stride & (stride-1) == 0,
            "Invalid NVMe queue layout")
    expected = [
        events[0],
        "AGENTOS NVME IO OP=02 LBA=2048 BLOCKS=1 CID=1",
        "AGENTOS BLOCK READY BLOCKS=16384 SIZE=512",
        "AGENTOS NVME IO OP=02 LBA=16375 BLOCKS=8 CID=2",
        "AGENTOS NVME IO OP=02 LBA=16383 BLOCKS=1 CID=3",
    ]
    if phase == "write":
        expected += [
            "AGENTOS NVME IO OP=01 LBA=16375 BLOCKS=8 CID=4",
            "AGENTOS NVME IO OP=01 LBA=16383 BLOCKS=1 CID=5",
            f"AGENTOS BLOCK WRITE {details}",
            "AGENTOS NVME IO OP=00 LBA=0 BLOCKS=0 CID=6",
            "AGENTOS BLOCK FLUSH OK",
        ]
    else:
        expected.append(f"AGENTOS BLOCK READ {details}")
    expected.append("AGENTOS NVME CLOSED RDY=0 MASTER=0 DMA=5")
    require(events == expected and "AGENTOS PCI FAILED" not in guest,
            f"Incomplete or unexpected {phase} NVMe completions")


def verify(run, cpus):
    run = Path(run)
    after, details = expected_disk(run / "block.raw")
    require((run / "block-after.raw").read_bytes() == after,
            "Write boot disk differs from expected sectors")
    require((run / "block-read-after.raw").read_bytes() == after,
            "Read boot changed the disk")
    with (run / "block.vdi").open("rb") as stream:
        stream.seek(392)
        medium = uuid.UUID(bytes_le=stream.read(16))
    require(medium.int != 0, "Missing VDI UUID")
    vm = [medium_identity(run, read_text(run / name), medium)
          for name in ("block-restart.txt", "block-read-poweroff.txt")]
    require(vm[0] == vm[1], "Cold boots used different VMs")
    starts = []
    controllers = []
    for phase, serial, pci in (
        ("write", "block-write-com1.log", "block-write-pci.txt"),
        ("read", "serial-com1.log", "vbox-pci.txt"),
    ):
        guest = read_text(run / serial)
        host = read_text(run / f"block-{phase}-vbox.log")
        start = re.search(r"Log opened (\S+)", host)
        require(start and "to 'TERMINATED'" in host and
                re.search(rf"NumCPUs\s+<integer>.*\({cpus}\)", host) and
                f'\\{run.name.lower()}\\block.vdi' in host.lower(),
                "Missing distinct powered-off NVMe boot evidence")
        starts.append(start[1])
        controllers.append(controller_identity(guest, read_text(run / pci)))
        verify_guest(guest, phase, details)
    require(starts[0] < starts[1] and controllers[0] == controllers[1],
            "Missing distinct cold restart of the same NVMe controller")
