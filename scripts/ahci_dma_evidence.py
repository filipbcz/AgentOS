"""Create the disposable disk and replay DMA lifetime transitions from COM1."""
import argparse
import os
from pathlib import Path
import re


def create(path):
    with path.open("xb") as disk:
        disk.truncate(8 << 20)
        disk.seek(1 << 20)
        disk.write(os.urandom(8192 * 33))


def require(ok, message):
    if not ok:
        raise ValueError(message)


def verify(log, path, host_log):
    records = iter(line[12:] for line in log.splitlines() if line.startswith("AGENTOS DMA "))

    def take(pattern):
        line = next(records, "")
        match = re.fullmatch(pattern, line)
        require(match, f"Unexpected transition {line!r}, expected {pattern}")
        return match.groups()

    stopped_pages = set()
    with path.open("rb") as disk:
        for tag in range(1, 35):
            lba, a, b = take(rf"PIN TAG={tag} LBA=(\d+) A=([0-9a-f]+) B=([0-9a-f]+) REFS=1,1")
            pages = {int(a, 16), int(b, 16)}
            expected_lba = 2048 if stopped_pages else 2048 + 16 * (tag - 1)
            require(int(lba) == expected_lba and len(pages) == 2 and
                    min(pages) > 0 and max(pages) - min(pages) > 4096 and
                    all(p % 4096 == 0 for p in pages) and not pages & stopped_pages,
                    "Invalid scatter/gather pages or recovery reused live canaries")
            line = next(records, "")
            if line.startswith("DONE "):
                match = re.fullmatch(rf"DONE TAG={tag} CI=0 IS=([0-9a-f]+) TFD=([0-9a-f]+) "
                                     r"FIS=([0-9a-f]+) BYTES=8192 FNV=([0-9a-f]{8})", line)
                require(match, "Incomplete DMA completion")
                status, tfd, fis, digest = (int(v, 16) for v in match.groups())
                disk.seek(int(lba) * 512)
                data = disk.read(8192)
                require(len(data) == 8192 and any(data[:4096]) and data[:4096] != data[4096:],
                        "Missing or degenerate DMA challenge")
                expected = 2166136261
                for byte in data:
                    expected = ((expected ^ byte) * 16777619) & 0xffffffff
                require(status & 1 and not status & 0x7d000000 and not tfd & 0xa9 and
                        fis & 255 == 0x34 and not (fis >> 16) & 0xa9 and expected == digest,
                        "Incorrect data or hardware completion")
                recovery = bool(stopped_pages)
            else:
                match = re.fullmatch(rf"TIMEOUT TAG={tag} MS=(\d+) LIMIT=15 CI=1 CMD=([0-9a-f]+) REFS=1,1", line)
                require(match and tag > 1 and not stopped_pages and int(match[1]) >= 15 and
                        int(match[2], 16) & 0xc011 == 0xc011, "No live command at the deadline")
                flush_is, flush_tfd = take(rf"DRAIN TAG={tag} SLOT=1 IS=([0-9a-f]+) TFD=([0-9a-f]+) REFS=1,1")
                require(int(flush_is, 16) & 1 and not int(flush_is, 16) & 0x7d000000
                        and not int(flush_tfd, 16) & 0xa9, "Missing successful drain")
                cmd, pci = take(rf"STOP TAG={tag} CMD=([0-9a-f]+) CI=0 SACT=0 PCI=([0-9a-f]+) REFS=1,1")
                require(not int(cmd, 16) & 0xc011 and not int(pci, 16) & 4, "DMA still enabled")
                offset = int(lba) * 512
                require(re.search(rf"AHCI#\d+P0: Canceled read at offset {offset} "
                                  r"\(8192 bytes left\) returned rc=VERR_PDM_MEDIAEX_IOREQ_CANCELED\b",
                                  host_log), "VirtualBox did not cancel the outstanding AHCI read")
                stopped_pages = pages
                recovery = False
            before, after = take(rf"REUSE TAG={tag} A={a} B={b} BEFORE=(\d+) AFTER=(\d+)")
            require(int(after) == int(before) + 2, "Unmap did not free both pages")
            if recovery:
                take(r"END FREE=[1-9]\d* CANARY=ok")
                require(next(records, None) is None, "Extra DMA records after recovery")
                return
    raise ValueError("Missing timeout, proven stop, page reuse or recovery read")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--create", type=Path, required=True)
    create(parser.parse_args().create)
