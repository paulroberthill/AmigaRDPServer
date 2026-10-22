#!/usr/bin/env python3
"""Decode the tiles printed by test_rle (native or 68k) with the spec-derived
decoder in testclient.py and check they round-trip exactly.
Usage: test_rle.py COMMAND [ARGS...]"""
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from testclient import rle_decompress  # noqa: E402

out = subprocess.run(sys.argv[1:], capture_output=True, text=True, check=True).stdout
tiles = fails = raw_total = sent_total = 0
for line in out.splitlines():
    parts = line.split()
    if len(parts) != 5 or not parts[0].isdigit():
        continue
    w, h, bpp_bytes = int(parts[0]), int(parts[1]), int(parts[2])
    raw = bytes.fromhex(parts[3])
    tiles += 1
    raw_total += len(raw)
    if parts[4] == "-":
        sent_total += len(raw)
        continue
    comp = bytes.fromhex(parts[4])
    sent_total += len(comp)
    bpp = {1: 8, 2: 16, 3: 24}[bpp_bytes]
    px = rle_decompress(comp, w, h, bpp)
    got = b"".join(v.to_bytes(bpp_bytes, "little") for v in px)
    if got != raw:
        fails += 1
        print("FAIL %dx%d %d bytes/pixel: decoded tile differs" % (w, h, bpp_bytes))
print("%d tiles, %d failures; %d of %d bytes (%d%%)" %
      (tiles, fails, sent_total, raw_total, sent_total * 100 // max(raw_total, 1)))
sys.exit(1 if fails or tiles == 0 else 0)
