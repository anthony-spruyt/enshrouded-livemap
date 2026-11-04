"""Looks in a saved regdump frames file for knowledge descriptors (0x30 bytes: +0 name {int32
offset from the field, uint32 length}, +8 id, +0xc index, +0x10 type 3/4/5, +0x11 player flag)
whose id is one of the markers' "visible" knowledge ids. Prints each match with its name.
Usage: python3 descscan.py frames.bin marker-ids.json"""

import json
import struct
import sys

import numpy as np

with open(sys.argv[2]) as f:
    ids_by = {int(k): v for k, v in json.load(f)["ids"].items()}
ids = np.array(sorted(ids_by), dtype=np.uint32)
found = 0
with open(sys.argv[1], "rb") as f:
    while True:
        head = f.read(16)
        if len(head) < 16:
            break
        start, length = struct.unpack("<QQ", head)
        data = f.read(length)
        a = np.frombuffer(data[: (len(data) // 4) * 4], "<u4")
        for i in np.nonzero(np.isin(a, ids))[0]:
            off = 4 * int(i)
            if off < 8 or off + 0x28 > len(data):
                continue
            idx = struct.unpack_from("<I", data, off + 4)[0]
            typ, flag = data[off + 8], data[off + 9]
            if idx < 20000 and typ in (3, 4, 5) and flag in (0, 1):
                rel, n = struct.unpack_from("<iI", data, off - 8)
                name_at = off - 8 + rel
                name = (
                    data[name_at : name_at + n].decode("utf-8", "replace")
                    if name_at >= 0 and n < 200 and name_at + n <= len(data)
                    else "?"
                )
                found += 1
                if found <= 40:
                    kind = "player" if flag else "world"
                    print(
                        f"{start + off - 8:#x} id {int(a[i]):08x} idx {idx} type {typ} {kind}  "
                        f"name={name!r}  template={ids_by[int(a[i])]}"
                    )
print("descriptor-like matches:", found)
