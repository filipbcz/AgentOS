"""Prepare a dedicated block fixture and verify both sides of a cold VM restart."""
import argparse
import os
from pathlib import Path
import re
import uuid

SIZE = 8 << 20
HEADER = 2048 * 512
MAGIC = b"AgentOS-VDI-test"
BYTES = 4608


def create(path):
    with path.open("xb") as disk:
        disk.truncate(SIZE)
        disk.seek(HEADER)
        disk.write(MAGIC + os.urandom(256))
        disk.seek(SIZE - BYTES - 512)
        disk.write(os.urandom(512))


def require(ok, msg):
    if not ok:
        raise ValueError(msg)


def verify(run, cpus):
    before = (run / "block.raw").read_bytes()
    require(len(before) == SIZE and before[HEADER:HEADER+16] == MAGIC and
            before[-BYTES:] == bytes(BYTES), "Invalid initial disk")
    seed = before[HEADER+16:HEADER+272]
    require(len(set(seed)) > 1, "Missing random fixture")
    payload = bytes(seed[i % 256] ^ (i // 256) for i in range(BYTES))
    require((run / "block-after.raw").read_bytes() == before[:-BYTES] + payload,
            "Cold disk export differs from the expected sector contents")
    digest = 2166136261
    for byte in payload:
        digest = ((digest ^ byte) * 16777619) & 0xffffffff
    details = f"LBA=16375 BYTES={BYTES} FNV={digest:08x}"
    ready = "AGENTOS BLOCK READY BLOCKS=16384 SIZE=512"
    starts = []
    for phase, serial, events in [
        ("write", "block-write-com1.log", [f"AGENTOS BLOCK WRITE {details}", "AGENTOS BLOCK FLUSH OK"]),
        ("read", "serial-com1.log", [f"AGENTOS BLOCK READ {details}"]),
    ]:
        guest = (run / serial).read_text("ascii", errors="replace")
        require([s for s in guest.splitlines() if s.startswith("AGENTOS BLOCK ")] == [ready, *events],
                f"Invalid {phase} boot command order, digest or geometry")
        host = (run / f"block-{phase}-vbox.log").read_text("utf-8", errors="replace")
        start = re.search(r"Log opened (\S+)", host)
        require(start and "to 'TERMINATED'" in host and
                re.search(rf"NumCPUs\s+<integer>.*\({cpus}\)", host), "Missing distinct VM boot evidence")
        starts.append(start[1])
        config = re.search(r"\[/Devices/ahci/0/LUN#0/Config/\]([^\[]+)", host)
        require(config and f'\\{run.name}\\block.vdi"' in config[1] and
                all(f'ahci/0/LUN#0/Config/{key}="0"' in host for key in ("IgnoreFlush", "IgnoreFlushAsync")),
                "Wrong AHCI disk or flush configuration")

        def stat(name):
            m = re.search(rf"/Public/Storage/AHCI0/Port0/{name}\s+(\d+) ", host)
            return int(m[1]) if m else 0  # VBox omits unused counters.

        require(stat("BytesRead") >= 512 + BYTES and stat("ReqsFailed") == 0, "Missing successful reads")
        if phase == "write":
            require(stat("BytesWritten") == BYTES and stat("ReqsWrite") == 2 and stat("ReqsFlush") >= 1,
                    "Missing AHCI device writes or flush")
        else:
            require(stat("ReqsWrite") == stat("BytesWritten") == 0, "Recovery boot rewrote the disk")
    power = (run / "block-restart.txt").read_text("utf-8-sig").splitlines()
    with (run / "block.vdi").open("rb") as disk:
        disk.seek(392)  # VDI 1.1 creation UUID
        medium = uuid.UUID(bytes_le=disk.read(16))
    require(f'"SATA-ImageUUID-0-0"="{medium}"' in power, "Cold restart used another medium")
    require(f'name="{run.name}"' in power and 'VMState="poweroff"' in power and starts[0] < starts[1],
            "Missing cold power-off boundary between boots")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--create", type=Path, required=True)
    create(parser.parse_args().create)
