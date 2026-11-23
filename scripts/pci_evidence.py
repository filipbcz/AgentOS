"""Compare the guest's PCI discovery with independent VirtualBox config-space dumps."""
import re


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def config_spaces(dump):
    lines = dump.splitlines()
    functions = {}
    current = None
    for i, line in enumerate(lines):
        match = re.match(r"\s*([0-9a-f]{2}:[0-9a-f]{2}\.[0-7])\s+[^:]+:\s+([0-9a-f]{4})-([0-9a-f]{4})\b", line, re.I)
        if match:
            current = "0000:" + match[1].lower()
            require(current not in functions, f"Duplicate VirtualBox device {current}")
            functions[current] = None
        if line.strip() == "PCI registers:":
            require(current is not None and functions[current] is None, "Unmatched PCI register dump")
            data = bytes.fromhex(" ".join(lines[i + 1:i + 17]))
            require(len(data) == 256, f"Incomplete config space for {current}")
            functions[current] = data
    require(functions and all(functions.values()), "Missing VirtualBox PCI configuration data")
    return functions


def expected_records(bdf, data):
    def word(offset, length):
        return int.from_bytes(data[offset:offset + length], "little")

    header = data[14] & 127
    caps = {}
    if data[6] & 16:
        pos = data[0x14 if header == 2 else 0x34] & ~3
        seen = set()
        while pos:
            require(pos >= 0x40 and pos not in seen, f"Invalid capability chain for {bdf}")
            seen.add(pos)
            caps[data[pos]] = pos
            pos = data[pos + 1] & ~3
    yield (f"DEV {bdf} ID={word(0, 2):04x}:{word(2, 2):04x} CLASS={word(9, 3):06x} "
           f"REV={data[8]:02x} MSI={caps.get(5, 0):02x} MSIX={caps.get(17, 0):02x} "
           f"PCIE={caps.get(16, 0):02x}")
    slot = 0
    slots = {0: 6, 1: 2}.get(header, 0)
    while slot < slots:
        value = word(16 + 4 * slot, 4)
        start = slot
        slot += 1
        if value & 1:
            kind, base = "io", value & ~3
        else:
            kind = {0: "mem32", 2: "mem1m", 4: "mem64"}.get(value & 6)
            require(kind is not None, f"Reserved BAR type at {bdf}/{start}")
            base = value & ~15
            if kind == "mem64":
                require(slot < slots, f"Truncated 64-bit BAR at {bdf}/{start}")
                base |= word(16 + slot * 4, 4) << 32
                slot += 1
        if base:
            yield f"BAR {bdf} {start} {kind} {base:016x}"


def verify_inventory(log, dump, chipset):
    functions = config_spaces(dump)
    require(any(data[9:12] == b"\x01\x06\x01" and
                int.from_bytes(data[0x24:0x28], "little") & ~15 for data in functions.values()),
            "Expected an AHCI controller with an assigned register BAR")
    require(any(data[:2] == b"\xf4\x1a" and data[11] == 2 for data in functions.values()),
            "Expected a VirtIO network controller")
    prefix = "AGENTOS PCI "
    actual = [line[len(prefix):] for line in log.splitlines() if line.startswith(prefix)]
    transport = {"piix3": "CF8", "ich9": "ECAM"}[chipset]
    expected = [f"CONFIG {transport}"]
    for bdf, data in sorted(functions.items()):
        expected.extend(expected_records(bdf, data))
    expected.append(f"END FUNCTIONS={len(functions)}")
    for i, (observed, wanted) in enumerate(zip(actual, expected)):
        require(observed == wanted, f"PCI record {i + 1}: expected {wanted!r}, got {observed!r}")
    require(len(actual) == len(expected), "Missing or extra guest PCI records")


def verify_device_irqs(log, dump, cpus):
    devices = [bdf for bdf, data in config_spaces(dump).items() if data[:4] == b"\x15\x14\x08\xc3"]
    require(len(devices) == 1, "Expected one Oxford PCIe serial controller")
    bdf = devices[0]
    require(re.search(rf"(?m)^AGENTOS PCI DEV {re.escape(bdf)} ID=1415:c308 CLASS=070002 "
                      r"REV=.. MSI=(?!00)[0-9a-f]{2} MSIX=(?!00)[0-9a-f]{2} ", log),
            "Oxford did not expose MSI and MSI-X")
    tasks = re.findall(r"(?m)^AGENTOS TASK (BSP|AP) APIC=([0-9a-f]{16}) TIMER-WAKES=0000000000000003\r?$", log)
    require([role for role, _ in tasks] == ["BSP"] + ["AP"] * (cpus - 1) and
            len({apic for _, apic in tasks}) == cpus, "Missing CPU identity for device delivery")
    expected = []
    for _, apic in tasks:
        cpu = int(apic, 16)
        for mode, vector in (("MSI", 0xe4), ("MSIX", 0xe5)):
            for pattern in (0x53, 0xa6):
                byte = pattern ^ cpu ^ vector
                expected.append(f"AGENTOS DEVICE IRQ BDF={bdf} MODE={mode} VECTOR={vector:02x} "
                                f"APIC={cpu:02x} TX={byte:02x} RX={byte:02x} IIR=04 ACK=1 EOI=1 "
                                f"PENDING={int(mode == 'MSIX')} COUNT={len(expected)+1}")
    actual = [line for line in log.splitlines() if line.startswith("AGENTOS DEVICE IRQ")]
    require(actual == expected, "Incomplete, duplicate or inconsistent PCI interrupt delivery")
