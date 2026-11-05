"""Hex view of a saved regdump frames file around an address, as uint32 rows, with known ids
marked.
Usage: python3 framedump.py frames.bin marker-ids.json <addr hex> [before] [after] [--root <dir>]
Every path must be inside the working directory (or a --root).
"""
import argparse
import json
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from paths import add_root_option, checked

ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
ap.add_argument("frames")
ap.add_argument("idfile")
ap.add_argument("addr")
ap.add_argument("before", nargs="?", default="0x100")
ap.add_argument("after", nargs="?", default="0x400")
add_root_option(ap)
args = ap.parse_args()
args.frames = checked(ap, args.frames, args.root)
args.idfile = checked(ap, args.idfile, args.root)
path, idfile, addr = args.frames, args.idfile, int(args.addr, 16)
before, after = int(args.before, 0), int(args.after, 0)
ids = {int(k): v for k, v in json.load(open(idfile))["ids"].items()}
with open(path, "rb") as f:
    while True:
        head = f.read(16)
        if len(head) < 16:
            sys.exit("address not in any frame")
        start, length = struct.unpack("<QQ", head)
        if start <= addr < start + length:
            data = f.read(length)
            break
        f.seek(length, 1)
lo = max(start, (addr - before) & ~0xF)
hi = min(start + length, addr + after)
print("region %#x len %#x" % (start, length))
for row in range(lo, hi, 16):
    words = struct.unpack_from("<4I", data, row - start)
    marks = ["*" + ids[w][9:40] if w in ids else "" for w in words]
    print("%#x  %s  %s" % (row, " ".join("%08x" % w for w in words), " ".join(m for m in marks if m)))
