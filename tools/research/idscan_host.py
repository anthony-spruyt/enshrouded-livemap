"""Reads regdump.py frames from stdin and finds where the map markers' "visible" knowledge ids
(uint32, from the templates) sit in the server's memory: every 4-byte aligned hit, then the
densest clusters (many different ids close together = a per-player "discovered" list or a
lookup table). Read-only analysis on the host (numpy).
Usage: ... | python3 idscan_host.py marker-ids.json [--save frames.bin] [--root <dir>]
Every path must be inside the working directory (or a --root).
"""

import argparse
import contextlib
import itertools
import json
import os
import struct
import sys
from collections import Counter

import numpy as np

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from paths import add_root_option, checked

ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
ap.add_argument("idfile")
ap.add_argument("--save", metavar="FRAMES")
add_root_option(ap)
args = ap.parse_args()
args.idfile = checked(ap, args.idfile, args.root)
args.save = checked(ap, args.save, args.root)

with open(args.idfile) as f:
    ids_by = {int(k): v for k, v in json.load(f)["ids"].items()}
ids = np.array(sorted(ids_by), dtype=np.uint32)
with contextlib.ExitStack() as stack:
    save = stack.enter_context(open(args.save, "wb")) if args.save else None
    inp = sys.stdin.buffer
    hits = []  # (address, id)
    total = 0
    while True:
        head = inp.read(16)
        if len(head) < 16:
            break
        start, length = struct.unpack("<QQ", head)
        data = inp.read(length)
        total += len(data)
        if save:
            save.write(head)
            save.write(data)
        if len(data) < 4:
            continue
        a = np.frombuffer(data[: (len(data) // 4) * 4], "<u4")
        m = np.isin(a, ids)
        hits.extend((start + 4 * int(i), int(a[i])) for i in np.nonzero(m)[0])
print(
    f"scanned {total / 1e6:.0f} MB, {len(hits)} hits of {len(ids)} ids, {len({h[1] for h in hits})} distinct ids found"
)
hits.sort()
# Clusters: hits less than 4 KB apart belong together.
clusters = []
cur = []
for h in hits:
    if cur and h[0] - cur[-1][0] > 4096:
        clusters.append(cur)
        cur = []
    cur.append(h)
if cur:
    clusters.append(cur)
clusters.sort(key=lambda c: -len({h[1] for h in c}))
for c in clusters[:15]:
    distinct = len({h[1] for h in c})
    strides = Counter(b[0] - a[0] for a, b in itertools.pairwise(c)).most_common(3)
    print(f"cluster {c[0][0]:#x}..{c[-1][0]:#x}  hits {len(c)} distinct {distinct}  strides {strides}")
    for addr, v in c[:4]:
        print(f"    {addr:#x}  {v:08x}  {ids_by[v]}")
