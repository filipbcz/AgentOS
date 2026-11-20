"""Change one byte in a signed section of a test copy, keeping its signature."""
import struct
import sys
from pathlib import Path

source, target, case = sys.argv[1:]
section = {"loader": b".text", "kernel": b".kernel", "initrd": b".initrd"}[case]
image = bytearray(Path(source).read_bytes())
pe, = struct.unpack_from("<I", image, 60)
count, = struct.unpack_from("<H", image, pe + 6)
optional, = struct.unpack_from("<H", image, pe + 20)
for index in range(count):
    header = pe + 24 + optional + 40 * index
    if image[header:header+8].rstrip(b"\x00") == section:
        offset, = struct.unpack_from("<I", image, header + 20)
        image[offset] ^= 1
        with open(target, "xb") as f:
            f.write(image)
        break
else:
    raise ValueError("Missing signed section")
