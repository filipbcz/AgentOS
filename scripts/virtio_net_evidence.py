"""Check genuine Ethernet frames, guest queue records, PCI identity and PCAP.

No packet bytes are recovered or reconstructed from serial diagnostics.
The test harness records what it actually sends and receives via QEMU's
isolated network socket, and an independent QEMU filter captures both ways.
"""
import re
import struct

GUEST = bytes.fromhex("525400123456")
PEER = bytes.fromhex("0241474e5401")
TYPE = bytes.fromhex("88b5")
ROUNDS = 12
SIZE = 96


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def challenge(payload):
    require(len(payload) == SIZE - 14, "Wrong challenge payload length")
    return GUEST + PEER + TYPE + payload


def reply(frame):
    require(len(frame) == SIZE and frame[:14] == GUEST + PEER + TYPE,
            "Invalid Ethernet challenge")
    return PEER + GUEST + TYPE + bytes(x ^ 0xa5 for x in frame[14:])


def fnv(frame):
    result = 2166136261
    for b in frame:
        result = ((result ^ b) * 16777619) & 0xffffffff
    return f"{result:08x}"


def pcap_packets(data):
    require(len(data) >= 24, "Missing PCAP file header")
    endian = {b"\xd4\xc3\xb2\xa1": "<", b"\xa1\xb2\xc3\xd4": ">",
              b"\x4d\x3c\xb2\xa1": "<", b"\xa1\xb2\x3c\x4d": ">"}.get(data[:4])
    require(endian is not None, "Unsupported PCAP format")
    major, minor, _, _, snaplen, link = struct.unpack_from(endian + "HHIIII", data, 4)
    require((major, minor, link) == (2, 4, 1) and snaplen >= SIZE,
            "Not a complete Ethernet PCAP")
    frames = []
    at = 24
    while at < len(data):
        require(at + 16 <= len(data), "Truncated PCAP record header")
        _, _, captured, original = struct.unpack_from(endian + "IIII", data, at)
        at += 16
        require(14 <= captured <= original and captured <= snaplen and at + captured <= len(data),
                "Invalid/truncated PCAP frame")
        frame = data[at:at+captured]
        if frame[12:14] == TYPE:
            require(captured == original == SIZE, "Incomplete experimental Ethernet frame")
            frames.append(frame)
        at += captured
    return frames


def verify_pci(guest, pci):
    def walk(devices):
        for device in devices:
            yield device
            yield from walk(device.get("pci_bridge", {}).get("devices", []))

    matches = [d for bus in pci for d in walk(bus["devices"]) if d.get("qdev_id") == "agentos-net"]
    require(len(matches) == 1, "Missing uniquely named QEMU VirtIO NIC")
    d = matches[0]
    # Normal PCI functions also carry optional subsystem IDs in QMP.
    require(d["id"]["vendor"] == 0x1af4 and d["id"]["device"] == 0x1041 and
            d["class_info"]["class"] == 0x0200,
            "Not modern VirtIO Ethernet PCI")
    bdf = f"0000:{d['bus']:02x}:{d['slot']:02x}.{d['function']}"
    require(guest.count(f"AGENTOS PCI DEV {bdf} ID=1af4:1041 CLASS=020000 ") == 1,
            "Guest and QMP VirtIO PCI identity differ")
    mappings = re.findall(r"(?m)^AGENTOS MMIO VIRTIO BAR=(\d+) PA=([0-9a-f]{16}) VA=([0-9a-f]{16}) PAGES=(\d+)\r?$", guest)
    require(mappings and len({m[0] for m in mappings}) == len(mappings), "Missing/duplicate VirtIO BAR mappings")
    for slot, pa, va, pages in mappings:
        physical, virtual, count = int(pa, 16), int(va, 16), int(pages)
        regions = [r for r in d["regions"] if r.get("bar") == int(slot)]
        require(len(regions) == 1 and regions[0]["type"] == "memory" and
                regions[0]["address"] == physical and regions[0]["size"] == count * 4096,
                "QMP BAR extent differs from guest mapping")
        require(virtual == (physical if physical < 1 << 39 else 0xffff900000000000 + physical),
                "VirtIO BAR is not mapped to the supervisor MMIO window")
    return bdf


def verify(guest, records, pcap):
    require(len(records) == ROUNDS, "Missing completed host packet exchanges")
    expected = []
    packets = []
    challenges = set()
    for number, record in enumerate(records, 1):
        require(record["round"] == number, "Wrong exchange order")
        incoming = bytes.fromhex(record["host_tx"])
        outgoing = bytes.fromhex(record["host_rx"])
        require(incoming not in challenges and len(set(incoming[14:])) > 1,
                "Repeated or trivial host challenge")
        challenges.add(incoming)
        require(outgoing == reply(incoming), "Guest reply differs at Ethernet byte level")
        packets.extend((incoming, outgoing))
        expected.append(f"AGENTOS VIRTIO NET FRAME ROUND={number} LEN={SIZE} "
                        f"RX={fnv(incoming)} TX={fnv(outgoing)} RXUSED={number} TXUSED={number}")
    actual = [line for line in guest.splitlines() if line.startswith("AGENTOS VIRTIO NET ")]
    ready = re.fullmatch(r"AGENTOS VIRTIO NET READY MAC=52:54:00:12:34:56 DEPTH=8 ROUNDS=12 MRG=[01]", actual[0]) if actual else None
    require(ready is not None, "Missing negotiated VirtIO queues")
    require(actual == [actual[0], *expected, "AGENTOS VIRTIO NET CLOSED STATUS=0 MASTER=0 DMA=4"],
            "Incomplete/incorrect guest RX/TX or DMA shutdown evidence")
    require("AGENTOS PCI FAILED" not in guest, "Guest device failure")
    require(pcap_packets(pcap) == packets, "Independent QEMU PCAP differs from socket exchanges")
    return {"rounds": ROUNDS, "rx_bytes": ROUNDS*SIZE, "tx_bytes": ROUNDS*SIZE,
            "queue_depth": 8, "used_entries_per_queue": ROUNDS}
