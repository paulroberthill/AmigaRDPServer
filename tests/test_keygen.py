#!/usr/bin/env python3
"""Check the keys printed by test_keygen (native or 68k) with Python ints.
Usage: test_keygen.py COMMAND [ARGS...]"""
import secrets
import subprocess
import sys

out = subprocess.run(sys.argv[1:], capture_output=True, text=True, check=True).stdout
keys = fails = 0
for line in out.splitlines():
    parts = line.split()
    if len(parts) != 4 or len(parts[0]) != 128:
        continue
    keys += 1
    n = int.from_bytes(bytes.fromhex(parts[0]), "little")
    d = int.from_bytes(bytes.fromhex(parts[1]), "little")
    e, ms = int(parts[2]), int(parts[3])
    problems = []
    if n.bit_length() != 512:
        problems.append("modulus has %d bits" % n.bit_length())
    if n % 2 == 0 or any(n % p == 0 for p in range(3, 2000, 2)):
        problems.append("modulus has a small factor")
    if e != 65537:
        problems.append("e = %d" % e)
    if not 1 < d < n:
        problems.append("d out of range")
    for _ in range(20):
        m = secrets.randbelow(n)
        if pow(pow(m, e, n), d, n) != m:
            problems.append("encrypt/decrypt round trip failed")
            break
    print(("FAIL " if problems else "ok   ") + "key %d (%d ms) %s" % (keys, ms, "; ".join(problems)))
    fails += bool(problems)
print("%d keys, %d failures" % (keys, fails))
sys.exit(1 if fails or keys == 0 else 0)
