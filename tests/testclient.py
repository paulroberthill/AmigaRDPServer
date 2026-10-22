#!/usr/bin/env python3
"""
Independent RDP client for testing the prototype server end to end.

Implements the client side of the MS-RDPBCGR connection sequence with
Standard RDP Security (written from the spec, not from the server code):
negotiation (asks for TLS+CredSSP like mstsc, then falls back), GCC/MCS,
proprietary certificate signature check against the Terminal Services key,
client random exchange, key derivation, licensing, capability exchange,
finalisation, bitmap/palette decoding into a framebuffer, input, and RC4 key
updates in both directions (> 4096 packets each way).

Usage:
  testclient.py [--host H] [--port P] [--png out.png]   # against a running server
  testclient.py --spawn ./rdpserver [server args...]     # start server, test, stop
"""
import argparse
import hashlib
import os
import socket
import struct
import subprocess
import sys
import time
import zlib

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms

    class RC4:
        def __init__(self, key):
            self.c = Cipher(algorithms.ARC4(key), mode=None).encryptor()

        def crypt(self, data):
            return self.c.update(data)
except Exception:  # pure-Python fallback
    class RC4:
        def __init__(self, key):
            s = list(range(256))
            j = 0
            for i in range(256):
                j = (j + s[i] + key[i % len(key)]) & 255
                s[i], s[j] = s[j], s[i]
            self.s, self.i, self.j = s, 0, 0

        def crypt(self, data):
            s, i, j, out = self.s, self.i, self.j, bytearray(data)
            for k in range(len(out)):
                i = (i + 1) & 255
                j = (j + s[i]) & 255
                s[i], s[j] = s[j], s[i]
                out[k] ^= s[(s[i] + s[j]) & 255]
            self.i, self.j = i, j
            return bytes(out)

TS_N = int.from_bytes(bytes.fromhex(
    "3d3a5ebd72433ec94dbbc11e4aba5fcb3e882087eff5c1e2d7b76b9af2524595"
    "ce63656b583afeef7ce7bffe3df65c7d6c5e06091af561bb2093095f056dea87"), "little")
TS_E = int.from_bytes(bytes.fromhex("5b7b88c0"), "little")

PAD1 = b"\x36" * 40
PAD2 = b"\x5c" * 48


class Fail(Exception):
    pass


# Substrings the spawned server's log must contain (checked in main()).
EXPECT_LOG = []

# Clipboard test data (MS-RDPECLIP), and what the host should end up with
CLIENT_CLIP = "Hello from Windows \u00a3 \u2013 done\r\nline 2\r\n" + "x" * 3000 + "\r\n\U0001F600"
CLIENT_CLIP_ON_HOST = "Hello from Windows \\xa3 - done\\nline 2\\n"   # as the host logs it (escaped)
CLIENT_CLIP_HOST_LEN = len("Hello from Windows \u00a3 - done\nline 2\n" + "x" * 3000 + "\n?")
HOST_CLIP_ON_CLIENT = "Hello from the Amiga \u00a35\r\nLine 2\r\n" + "y" * 2000


class FileSock:
    """Socket-like transport over two growing files (for the vamos harness,
    which cannot open named pipes): we append to c2s and poll s2c."""

    server = None   # spawned server process, to fail fast if it dies

    def __init__(self, c2s, s2c):
        self.w = open(c2s, "ab", buffering=0)
        self.r = open(s2c, "rb", buffering=0)
        self.timeout = None

    def settimeout(self, t):
        self.timeout = t

    def sendall(self, data):
        self.w.write(data)

    def recv(self, n):
        end = None if self.timeout is None else time.time() + self.timeout
        while True:
            data = self.r.read(n)
            if data:
                return data
            if self.server and self.server.poll() is not None:
                return b""
            if end is not None and time.time() > end:
                raise socket.timeout()
            time.sleep(0.002)

    def close(self):
        self.w.close()
        self.r.close()


def u16(v): return struct.pack("<H", v)
def u32(v): return struct.pack("<I", v)
def be16(v): return struct.pack(">H", v)


def ber_len(n):
    if n < 0x80:
        return bytes([n])
    if n < 0x100:
        return b"\x81" + bytes([n])
    return b"\x82" + be16(n)


def per_len(n):
    return bytes([n]) if n < 0x80 else be16(0x8000 | n)


def read_ber_len(b, i):
    v = b[i]
    i += 1
    if v & 0x80:
        n = v & 0x7f
        v = int.from_bytes(b[i:i + n], "big")
        i += n
    return v, i


def read_per_len(b, i):
    v = b[i]
    if v & 0x80:
        return ((v & 0x7f) << 8) | b[i + 1], i + 2
    return v, i + 1


def rle_decompress(src, width, height, bpp):
    """Interleaved RLE decoder, following the MS-RDPBCGR 3.1.9 reference
    pseudo-code (all order types). Returns width*height pixels as ints in
    stream (bottom-up) order."""
    white = {8: 0xFF, 15: 0x7FFF, 16: 0xFFFF, 24: 0xFFFFFF}[bpp]
    psize = (bpp + 7) // 8
    out = []
    i, n = 0, len(src)
    fg = white
    insert_fg = False
    first_line = True

    def read_px():
        nonlocal i
        v = int.from_bytes(src[i:i + psize], "little")
        i += psize
        return v

    def above():
        return out[len(out) - width]

    def fgbg_bits(mask, count):
        for b in range(count):
            bit = (mask >> b) & 1
            if first_line:
                out.append(fg if bit else 0)
            else:
                out.append(above() ^ fg if bit else above())

    while i < n:
        if first_line and len(out) >= width:
            first_line = False
            insert_fg = False
        hdr = src[i]
        if (hdr & 0xC0) != 0xC0:
            code, form = hdr >> 5, "regular"
        elif (hdr & 0xF0) == 0xF0:
            code, form = hdr, "mega"
        else:
            code, form = hdr >> 4, "lite"
        # run length
        if form == "mega" and code in (0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF6, 0xF7, 0xF8):
            run = src[i + 1] | src[i + 2] << 8
            i += 3
        elif form == "mega":
            run = 0
            i += 1
        elif code in (0x2, 0xD):                    # FGBG image: x8 or +1
            mask = 0x1F if form == "regular" else 0x0F
            run = hdr & mask
            if run == 0:
                run = src[i + 1] + 1
                i += 2
            else:
                run *= 8
                i += 1
        else:
            mask, add = (0x1F, 32) if form == "regular" else (0x0F, 16)
            run = hdr & mask
            if run == 0:
                run = src[i + 1] + add
                i += 2
            else:
                i += 1

        if code in (0x0, 0xF0):                     # background run
            if insert_fg:
                out.append(fg if first_line else above() ^ fg)
                run -= 1
            if first_line:
                out += [0] * run
            else:
                # copy from the line above; at most one line per step so a
                # run longer than a line repeats what it has just written
                while run > 0:
                    step = min(run, width)
                    start = len(out) - width
                    out += out[start:start + step]
                    run -= step
            insert_fg = True
            continue
        insert_fg = False
        if code in (0x1, 0xF1, 0xC, 0xF6):          # foreground run
            if code in (0xC, 0xF6):
                fg = read_px()
            for _ in range(run):
                out.append(fg if first_line else above() ^ fg)
        elif code in (0xE, 0xF8):                   # dithered run (pairs)
            a, b = read_px(), read_px()
            for _ in range(run):
                out += [a, b]
        elif code in (0x3, 0xF3):                   # colour run
            c = read_px()
            out += [c] * run
        elif code in (0x2, 0xF2, 0xD, 0xF7):        # fg/bg image
            if code in (0xD, 0xF7):
                fg = read_px()
            while run > 8:
                fgbg_bits(src[i], 8)
                i += 1
                run -= 8
            if run > 0:
                fgbg_bits(src[i], run)
                i += 1
        elif code in (0x4, 0xF4):                   # colour image
            raw = src[i:i + run * psize]
            i += run * psize
            out += [int.from_bytes(raw[k:k + psize], "little") for k in range(0, len(raw), psize)]
        elif code == 0xF9:
            fgbg_bits(0x03, 8)
        elif code == 0xFA:
            fgbg_bits(0x05, 8)
        elif code == 0xFD:
            out.append(white)
        elif code == 0xFE:
            out.append(0)
        else:
            raise Fail("unknown RLE order 0x%02x" % hdr)
    if len(out) != width * height:
        raise Fail("RLE decoded %d pixels, expected %d" % (len(out), width * height))
    return out


class Keys:
    """Client side of MS-RDPBCGR 5.3.5.1 / 5.3.6.1 / 5.3.7.1."""

    def __init__(self, crandom, srandom):
        def salted(s, i):
            return hashlib.md5(s + hashlib.sha1(i + s + crandom + srandom).digest()).digest()

        pre = crandom[:24] + srandom[:24]
        master = salted(pre, b"A") + salted(pre, b"BB") + salted(pre, b"CCC")
        blob = salted(master, b"X") + salted(master, b"YY") + salted(master, b"ZZZ")
        final = lambda k: hashlib.md5(k + crandom + srandom).digest()
        self.mac_key = blob[:16]
        self.dec_init = self.dec_key = final(blob[16:32])   # = server encrypt
        self.enc_init = self.enc_key = final(blob[32:48])   # = server decrypt
        self.enc, self.dec = RC4(self.enc_key), RC4(self.dec_key)
        self.enc_n = self.dec_n = 0
        self.updates = [0, 0]

    @staticmethod
    def _update(init, cur):
        sha = hashlib.sha1(init + PAD1 + cur).digest()
        tmp = hashlib.md5(init + PAD2 + sha).digest()
        new = RC4(tmp).crypt(tmp)
        return new, RC4(new)

    def mac(self, data):
        sha = hashlib.sha1(self.mac_key + PAD1 + u32(len(data)) + data).digest()
        return hashlib.md5(self.mac_key + PAD2 + sha).digest()[:8]

    def encrypt(self, data):
        if self.enc_n == 4096:
            self.enc_key, self.enc = self._update(self.enc_init, self.enc_key)
            self.enc_n = 0
            self.updates[0] += 1
        self.enc_n += 1
        return self.enc.crypt(data)

    def decrypt(self, data):
        if self.dec_n == 4096:
            self.dec_key, self.dec = self._update(self.dec_init, self.dec_key)
            self.dec_n = 0
            self.updates[1] += 1
        self.dec_n += 1
        return self.dec.crypt(data)


class Client:
    def __init__(self, host, port, log, fifo=None, no_hdr_off=False):
        self.host, self.port, self.log, self.fifo = host, port, log, fifo
        self.no_hdr_off = no_hdr_off
        self.keys = None
        self.fb = None
        self.palette = None
        self.stats = {"bitmaps": 0, "pdus": 0, "shutdown_denied": 0, "compressed": 0,
                      "clip_before_login": 0}
        self.logged_in = False      # set once the password has been given
        self.rgb_cache = {}
        self.vc_buf = b""
        self.clip = {"caps": False, "ready": False, "server_formats": [],
                     "list_response": None, "from_server": None, "requested": []}

    # ---------------------------------------------------------- transport
    def recv_exact(self, n):
        b = b""
        while len(b) < n:
            c = self.sock.recv(n - len(b))
            if not c:
                raise Fail("connection closed by server")
            b += c
        return b

    def recv_pdu(self):
        # Only the first byte may time out; once a PDU has started, wait for
        # the rest so a short pump() timeout cannot desync the stream.
        h = self.recv_exact(1)
        saved = self.sock.timeout if self.fifo else self.sock.gettimeout()
        self.sock.settimeout(120)
        try:
            h += self.recv_exact(3)
            if h[0] != 3:
                raise Fail("server sent fast-path output (not advertised): %r" % h)
            n = struct.unpack(">H", h[2:4])[0]
            return self.recv_exact(n - 4)
        finally:
            self.sock.settimeout(saved)

    def send_x224(self, payload):
        data = b"\x02\xf0\x80" + payload
        self.sock.sendall(b"\x03\x00" + be16(len(data) + 4) + data)

    def send_mcs(self, channel, secflags, data, encrypt=True):
        if encrypt:
            sig = self.keys.mac(data)
            data = u16(secflags | 0x0008) + u16(0) + sig + self.keys.encrypt(data)
        else:
            data = u16(secflags) + u16(0) + data
        self.send_x224(b"\x64" + be16(self.user - 1001) + be16(channel) + b"\x70" +
                       per_len(len(data)) + data)

    def recv_mcs(self):
        """Returns (channel, secflags, plaintext) for a Send Data Indication."""
        b = self.recv_pdu()
        if b[:3] != b"\x02\xf0\x80":
            raise Fail("not an X.224 data TPDU")
        b = b[3:]
        if b[0] >> 2 != 26:
            raise Fail("expected MCS SendDataIndication, got choice %d" % (b[0] >> 2))
        chan = struct.unpack(">H", b[3:5])[0]
        if b[6] & 0xC0 == 0xC0:
            raise Fail("MCS length needs PER fragmentation (>= 16384 bytes): clients reject this")
        n, i = read_per_len(b, 6)
        body = b[i:i + n]
        if len(body) != n:
            raise Fail("MCS length mismatch")
        flags = struct.unpack("<H", body[:2])[0]
        data = body[4:]
        if flags & 0x0008:
            sig, data = data[:8], self.keys.decrypt(data[8:])
            if self.keys.mac(data) != sig:
                raise Fail("MAC mismatch on server PDU (flags 0x%04x)" % flags)
        self.stats["pdus"] += 1
        return chan, flags, data

    # ---------------------------------------------------------- connect
    def connect(self, requested):
        if self.fifo:
            self.sock = FileSock(*self.fifo)
            self.sock.settimeout(120)
        else:
            self.sock = socket.create_connection((self.host, self.port), timeout=20)
        cookie = b"Cookie: mstshash=tester\r\n"
        neg = b"\x01\x00\x08\x00" + u32(requested)
        x224 = bytes([6 + len(cookie) + len(neg), 0xe0, 0, 0, 0, 0, 0]) + cookie + neg
        self.sock.sendall(b"\x03\x00" + be16(len(x224) + 4) + x224)
        cc = self.recv_pdu()
        if cc[1] != 0xd0:
            raise Fail("expected X.224 Connection Confirm")
        if len(cc) >= 15:
            t, code = cc[7], struct.unpack("<I", cc[11:15])[0]
            if t == 3:
                self.log("negotiation failure code %d" % code)
                self.sock.close()
                return False
            if t != 2 or code != 0:
                raise Fail("unexpected negotiation response type %d proto %d" % (t, code))
            self.log("server selected PROTOCOL_RDP")
        self.requested = requested
        return True

    def mcs_connect(self, width, height, bpp):
        name = "TESTCLIENT".encode("utf-16-le").ljust(32, b"\0")
        core = (u32(0x00080004) + u16(width) + u16(height) + u16(0xca01) + u16(0xaa03) +
                u32(0x409) + u32(2600) + name + u32(4) + u32(0) + u32(12) + bytes(64) +
                u16(0xca01) + u16(1) + u32(0) + u16(bpp) + u16(0x000f) + u16(0x0001) +
                bytes(64) + b"\x00\x00" + u32(self.requested))
        sec = u32(0x1b) + u32(0)
        chans = [b"rdpdr", b"rdpsnd", b"cliprdr", b"drdynvc"]
        net = u32(len(chans)) + b"".join(c.ljust(8, b"\0") + u32(0x80800000) for c in chans)
        blocks = b"".join(u16(t) + u16(len(d) + 4) + d for t, d in
                          ((0xc001, core), (0xc002, sec), (0xc003, net)))
        ccr = b"\x00\x08\x00\x10\x00\x01\xc0\x00Duca" + per_len(len(blocks)) + blocks
        gcc = b"\x00\x05\x00\x14\x7c\x00\x01" + per_len(len(ccr)) + ccr
        def dp(*vals):  # BER DomainParameters: SEQUENCE of 8 INTEGERs
            ints = b""
            for v in vals:
                enc = v.to_bytes((v.bit_length() + 8) // 8, "big")  # room for sign bit
                ints += b"\x02" + bytes([len(enc)]) + enc
            return b"\x30" + ber_len(len(ints)) + ints

        body = (b"\x04\x01\x01" + b"\x04\x01\x01" + b"\x01\x01\xff" +
                dp(34, 2, 0, 1, 0, 1, 0xffff, 2) + dp(1, 1, 1, 1, 0, 1, 0x420, 2) +
                dp(0xff, 0xfc, 0xff, 1, 0, 1, 0xffff, 2) +
                b"\x04" + ber_len(len(gcc)) + gcc)
        self.send_x224(b"\x7f\x65" + ber_len(len(body)) + body)

        r = self.recv_pdu()[3:]
        if r[:2] != b"\x7f\x66":
            raise Fail("expected MCS Connect Response")
        _, i = read_ber_len(r, 2)
        if r[i:i + 3] != b"\x0a\x01\x00":
            raise Fail("MCS connect result not successful")
        j = r.find(b"McDn")
        if j < 0:
            raise Fail("no McDn key in GCC response")
        n, j = read_per_len(r, j + 4)
        blocks = r[j:j + n]
        if len(blocks) != n:
            raise Fail("GCC user data truncated")
        self.channels = []
        while blocks:
            t, ln = struct.unpack("<HH", blocks[:4])
            d, blocks = blocks[4:ln], blocks[ln:]
            if t == 0x0c01:
                ver, req = struct.unpack("<II", d[:8])
                if req != self.requested:
                    raise Fail("clientRequestedProtocols %d != %d" % (req, self.requested))
            elif t == 0x0c03:
                io, cnt = struct.unpack("<HH", d[:4])
                self.io = io
                self.channels = list(struct.unpack("<%dH" % cnt, d[4:4 + 2 * cnt]))
            elif t == 0x0c02:
                method, level, rl, cl = struct.unpack("<IIII", d[:16])
                if method != 2:
                    raise Fail("server chose encryption method %d" % method)
                self.srandom = d[16:16 + rl]
                self.parse_cert(d[16 + rl:16 + rl + cl])
        self.log("MCS connected: I/O channel %d, static channels %s" % (self.io, self.channels))

    def parse_cert(self, c):
        ver, sig_alg, key_alg, bt, bl = struct.unpack("<IIIHH", c[:16])
        if ver & 0x7fffffff != 1 or bt != 6:
            raise Fail("not a proprietary certificate")
        blob = c[16:16 + bl]
        magic, keylen, bitlen, datalen, e = struct.unpack("<4sIIII", blob[:20])
        if magic != b"RSA1":
            raise Fail("bad RSA1 magic")
        self.n = int.from_bytes(blob[20:20 + keylen], "little")
        self.e = e
        self.keybytes = bitlen // 8
        k = 16 + bl
        st, sl = struct.unpack("<HH", c[k:k + 4])
        sig = int.from_bytes(c[k + 4:k + 4 + sl - 8], "little")
        m = pow(sig, TS_E, TS_N).to_bytes(64, "little")
        h = hashlib.md5(c[:16 + bl]).digest()
        if m[:16] != h or m[16] != 0 or m[17:62] != b"\xff" * 45 or m[62] != 1:
            raise Fail("certificate signature does not verify with the TS key")
        self.log("server certificate signature verified (%d-bit key)" % bitlen)

    def join(self):
        self.send_x224(b"\x04\x01\x00\x01\x00")          # erect domain
        self.send_x224(b"\x28")                          # attach user
        r = self.recv_pdu()[3:]
        if r[0] >> 2 != 11 or r[1] != 0:
            raise Fail("attach user failed")
        self.user = 1001 + struct.unpack(">H", r[2:4])[0]
        for ch in [self.user, self.io] + self.channels:
            self.send_x224(b"\x38" + be16(self.user - 1001) + be16(ch))
            r = self.recv_pdu()[3:]
            if r[0] >> 2 != 15 or r[1] != 0 or struct.unpack(">H", r[6:8])[0] != ch:
                raise Fail("channel join %d failed" % ch)
        self.log("joined user channel %d and %d channels" % (self.user, 1 + len(self.channels)))

    def security_exchange(self):
        crandom = os.urandom(32)
        enc = pow(int.from_bytes(crandom, "little"), self.e, self.n)
        enc = enc.to_bytes(self.keybytes, "little") + bytes(8)
        self.send_mcs(self.io, 0x0001 | 0x0200, u32(len(enc)) + enc, encrypt=False)
        self.keys = Keys(crandom, self.srandom)

    def client_info(self, password=""):
        z = lambda s: s.encode("utf-16-le")
        dom, user, pw, shell, wd = z(""), z("tester"), z(password), z(""), z("")
        info = (u32(0) + u32(0x10 | 0x100 | 0x2) + u16(len(dom)) + u16(len(user)) +
                u16(len(pw)) + u16(len(shell)) + u16(len(wd)) +
                dom + b"\0\0" + user + b"\0\0" + pw + b"\0\0" + shell + b"\0\0" + wd + b"\0\0")
        self.send_mcs(self.io, 0x0040, info)

    # ---------------------------------------------------------- share layer
    def send_data(self, type2, payload):
        total = 18 + len(payload)
        hdr = (u16(total) + u16(0x17) + u16(self.user) + u32(self.share_id) + b"\x00\x01" +
               u16(total - 14) + bytes([type2, 0]) + u16(0))
        self.send_mcs(self.io, 0, hdr + payload)

    def capabilities(self):
        _, flags, d = self.recv_mcs()
        if not flags & 0x0080 or d[0] != 0xff or struct.unpack("<I", d[4:8])[0] != 7:
            raise Fail("expected License Error (valid client), flags 0x%04x" % flags)
        self.log("licensing skipped (STATUS_VALID_CLIENT, %s)" %
                 ("encrypted" if flags & 0x0008 else "plain"))
        _, flags, d = self.recv_mcs()
        total, ptype, src = struct.unpack("<HHH", d[:6])
        if ptype & 0xf != 1:
            raise Fail("expected Demand Active, got pdu type %d" % (ptype & 0xf))
        self.activate(d)

    def activate(self, d):
        """Answer a Demand Active (first, or after Deactivate All): Confirm
        Active, then connection finalisation, waiting for the server's side."""
        self.share_id, lsd, lcc = struct.unpack("<IHH", d[6:14])
        caps = d[14 + lsd:14 + lsd + lcc]
        ncaps = struct.unpack("<H", caps[:2])[0]
        caps, seen = caps[4:], []
        for _ in range(ncaps):
            t, ln = struct.unpack("<HH", caps[:4])
            if t == 2:
                self.bpp, _, _, _, self.w, self.h = struct.unpack("<6H", caps[4:16])
            seen.append(t)
            caps = caps[ln:]
        self.log("Demand Active: %dx%d @ %d bpp, capability sets %s" % (self.w, self.h, self.bpp, seen))
        self.fb = bytearray(self.w * self.h * 3)

        extra = 0x0005 if self.no_hdr_off else 0x0405   # 0x0400: NO_BITMAP_COMPRESSION_HDR
        self.no_hdr_ok = not self.no_hdr_off
        mycaps = [
            (1, u16(1) + u16(3) + u16(0x200) + u16(0) + u16(0) + u16(extra) + bytes(6) + b"\x01\x01"),
            (2, u16(self.bpp) + u16(1) * 3 + u16(self.w) + u16(self.h) + u16(0) + u16(1) + u16(1) +
             b"\x00\x00" + u16(1) + u16(0)),
            (3, bytes(20) + u16(1) + u16(20) + u16(0) + u16(1) + u16(0) + u16(0x22) + bytes(32) +
             bytes(8) + u32(230400) + bytes(8)),
            (13, u16(0x35) + u16(0) + u32(0x409) + u32(4) + u32(0) + u32(12) + bytes(64)),
        ]
        cs = b"".join(u16(t) + u16(len(v) + 4) + v for t, v in mycaps)
        body = (u32(self.share_id) + u16(1002) + u16(6) + u16(len(cs) + 4) + b"MSTSC\0" +
                u16(len(mycaps)) + u16(0) + cs)
        self.send_mcs(self.io, 0, u16(len(body) + 6) + u16(0x13) + u16(self.user) + body)

        self.send_data(0x1f, u16(1) + u16(1002))                    # synchronize
        self.send_data(0x14, u16(4) + u16(0) + u32(0))              # cooperate
        self.send_data(0x14, u16(1) + u16(0) + u32(0))              # request control
        self.send_data(0x27, u16(0) + u16(0) + u16(3) + u16(0x32))  # font list

        want = ["sync", "cooperate", "granted", "fontmap"]
        got = []
        while got != want:
            t2, d = self.recv_data()
            if t2 == 0x1f:
                got.append("sync")
            elif t2 == 0x14:
                a = struct.unpack("<H", d[:2])[0]
                got.append({4: "cooperate", 2: "granted"}.get(a, "control%d" % a))
            elif t2 == 0x28:
                got.append("fontmap")
            else:
                self.handle_update(t2, d)
        self.log("finalisation complete: %s" % ", ".join(got))
        self.active = True

    def recv_data(self):
        while True:
            chan, flags, d = self.recv_mcs()
            if chan != self.io:
                self.handle_vc(chan, d)
                continue
            total, ptype, src = struct.unpack("<HHH", d[:6])
            if ptype & 0xf == 7:
                return d[14], d[18:]
            if ptype & 0xf == 6:                           # Deactivate All
                self.stats["deactivations"] = self.stats.get("deactivations", 0) + 1
                self.active = False
                continue
            if ptype & 0xf == 1:                           # Demand Active again
                if self.active:
                    raise Fail("Demand Active without a Deactivate All first")
                self.activate(d)
                continue
            self.log("ignoring share pdu type %d" % (ptype & 0xf))

    def handle_update(self, t2, d):
        if t2 == 0x1b:
            return "pointer"
        if t2 == 0x25:
            self.stats["shutdown_denied"] += 1
            return "denied"
        if t2 == 0x22:                                     # Play Sound
            self.stats.setdefault("beeps", []).append(struct.unpack("<II", d[:8]))
            return "beep"
        if t2 != 0x02:
            self.log("ignoring data pdu 0x%02x" % t2)
            return None
        ut = struct.unpack("<H", d[:2])[0]
        if ut == 2:
            n = struct.unpack("<I", d[4:8])[0]
            self.palette = d[8:8 + 3 * n]
            self.rgb_cache = {}
            return "palette"
        if ut != 1:
            return None
        n = struct.unpack("<H", d[2:4])[0]
        i = 4
        bpp_bytes = (self.bpp + 7) // 8
        for _ in range(n):
            l, t, r, b, w, h, bpp, fl, ln = struct.unpack("<9H", d[i:i + 18])
            data = d[i + 18:i + 18 + ln]
            i += 18 + ln
            if bpp != self.bpp:
                raise Fail("bitmap bpp %d != session %d" % (bpp, self.bpp))
            if fl & 1:                              # interleaved RLE
                if bpp == 32:
                    raise Fail("RLE is not defined for 32 bpp")
                if fl & 0x400 and not self.no_hdr_ok:
                    raise Fail("NO_BITMAP_COMPRESSION_HDR used but client did not advertise it")
                if not fl & 0x400:                  # TS_CD_HEADER present
                    first, body, scan, unc = struct.unpack("<4H", data[:8])
                    # cbScanWidth: line size in bytes (as xrdp/rdesktop/Windows)
                    if first != 0 or scan != w * bpp_bytes or unc != w * h * bpp_bytes or body != ln - 8:
                        raise Fail("bad TS_CD_HEADER %r for %dx%d" % ((first, body, scan, unc), w, h))
                    data = data[8:]
                px = rle_decompress(data, w, h, bpp)
                self.stats["compressed"] += 1
            else:
                if ln != w * h * bpp_bytes:
                    raise Fail("bitmap header inconsistent: %dx%d@%d len %d" % (w, h, bpp, ln))
                if bpp_bytes == 1:
                    px = list(data)
                elif bpp_bytes == 2:
                    px = list(struct.unpack("<%dH" % (w * h), data))
                elif bpp_bytes == 4:
                    px = list(struct.unpack("<%dI" % (w * h), data))
                else:
                    px = [int.from_bytes(data[k:k + 3], "little") for k in range(0, len(data), 3)]
            # rows are bottom-up; convert through a value -> RGB cache
            cache = self.rgb_cache
            for row in range(b - t + 1):
                base = (h - 1 - row) * w
                vals = px[base:base + (r - l + 1)]
                line = b"".join(cache[v] if v in cache else self.to_rgb(v) for v in vals)
                o = ((t + row) * self.w + l) * 3
                self.fb[o:o + len(line)] = line
            self.stats["bitmaps"] += 1
        return "bitmap"

    # ------------------------------------------------ clipboard (cliprdr)
    def send_clip(self, msg_type, flags, data=b""):
        msg = u16(msg_type) + u16(flags) + u32(len(data)) + data
        chan = self.channels[2]                            # cliprdr
        for off in range(0, len(msg), 1600):
            chunk = msg[off:off + 1600]
            fl = (1 if off == 0 else 0) | (2 if off + 1600 >= len(msg) else 0) | 0x10
            self.send_mcs(chan, 0, u32(len(msg)) + u32(fl) + chunk)

    def handle_vc(self, chan, d):
        if chan != self.channels[2]:
            raise Fail("data on unexpected virtual channel %d" % chan)
        if not self.logged_in:
            self.stats["clip_before_login"] += 1
        total, flags = struct.unpack("<II", d[:8])
        if flags & 1:
            self.vc_buf = b""
        self.vc_buf += d[8:]
        if flags & 2:
            if len(self.vc_buf) != total:
                raise Fail("virtual channel reassembly: %d of %d bytes" % (len(self.vc_buf), total))
            self.handle_clip(self.vc_buf)

    def handle_clip(self, m):
        mtype, mflags, dlen = struct.unpack("<HHI", m[:8])
        data = m[8:8 + dlen]
        c = self.clip
        if mtype == 7:                                     # capabilities
            c["caps"] = True
        elif mtype == 1:                                   # monitor ready
            c["ready"] = True
            caps = u16(1) + u16(0) + u16(1) + u16(12) + u32(2) + u32(0x02)   # long names
            self.send_clip(7, 0, caps)
            # our clipboard: CF_UNICODETEXT plus a registered format
            fl = u32(13) + b"\0\0" + u32(0xC0FF) + "Rich Text Format".encode("utf-16-le") + b"\0\0"
            self.send_clip(2, 0, fl)
        elif mtype == 3:
            c["list_response"] = mflags
        elif mtype == 2:                                   # server's format list
            ids, i = [], 0
            while i + 4 <= len(data):
                ids.append(struct.unpack("<I", data[i:i + 4])[0])
                i += 4
                while data[i:i + 2] != b"\0\0":
                    i += 2
                i += 2
            c["server_formats"] = ids
            self.send_clip(3, 1)                           # list response OK
            if 13 in ids:
                self.send_clip(4, 0, u32(13))              # "paste": request the text
        elif mtype == 4:                                   # server wants our text
            fmt = struct.unpack("<I", data[:4])[0]
            c["requested"].append(fmt)
            if fmt == 13:
                self.send_clip(5, 1, CLIENT_CLIP.encode("utf-16-le") + b"\0\0")
            else:
                self.send_clip(5, 2)
        elif mtype == 5:                                   # server's text
            if mflags & 1:
                c["from_server"] = data.decode("utf-16-le").split("\0")[0]

    def clipboard_checks(self, checks):
        deadline = time.time() + (120 if self.fifo else 10)
        while time.time() < deadline and (self.clip["from_server"] is None or not self.clip["requested"]):
            self.pump(0.3)
        c = self.clip
        checks.append(("clipboard: server sent capabilities and Monitor Ready", c["caps"] and c["ready"]))
        checks.append(("clipboard: server accepted our format list", c["list_response"] == 1))
        checks.append(("clipboard: server asked for our CF_UNICODETEXT", c["requested"] == [13]))
        checks.append(("clipboard: server offered CF_UNICODETEXT", 13 in c["server_formats"]))
        got = c["from_server"]
        checks.append(("clipboard: host text arrived intact (%s chars, CRLF, pound sign)"
                       % (len(got) if got is not None else "no"), got == HOST_CLIP_ON_CLIENT))
        EXPECT_LOG.append("clipboard from client (%d bytes): %s" % (CLIENT_CLIP_HOST_LEN, CLIENT_CLIP_ON_HOST))

    def to_rgb(self, v):
        """Wire pixel value -> RGB bytes for the session depth (cached)."""
        bpp = self.bpp
        if bpp == 8:
            rgb = bytes(self.palette[v * 3:v * 3 + 3])
        elif bpp in (24, 32):
            rgb = bytes([(v >> 16) & 255, (v >> 8) & 255, v & 255])
        elif bpp == 16:
            rgb = bytes([(v >> 11) << 3, ((v >> 5) & 63) << 2, (v & 31) << 3])
        else:
            rgb = bytes([((v >> 10) & 31) << 3, ((v >> 5) & 31) << 3, (v & 31) << 3])
        self.rgb_cache[v] = rgb
        return rgb

    def pump(self, seconds):
        self.sock.settimeout(0.2)
        end = time.time() + seconds
        while time.time() < end:
            try:
                t2, d = self.recv_data()
            except socket.timeout:
                continue
            self.handle_update(t2, d)
        self.sock.settimeout(120 if self.fifo else 20)

    def pixel(self, x, y):
        o = (y * self.w + x) * 3
        return tuple(self.fb[o:o + 3])

    def save_png(self, path):
        raw = b"".join(b"\0" + bytes(self.fb[y * self.w * 3:(y + 1) * self.w * 3]) for y in range(self.h))
        chunk = lambda t, d: struct.pack(">I", len(d)) + t + d + struct.pack(">I", zlib.crc32(t + d))
        png = (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", self.w, self.h, 8, 2, 0, 0, 0)) +
               chunk(b"IDAT", zlib.compress(raw)) + chunk(b"IEND", b""))
        open(path, "wb").write(png)

    # ---------------------------------------------------------- input
    def mouse_slowpath(self, flags, x, y):
        ev = u32(0) + u16(0x8001) + u16(flags) + u16(x) + u16(y)
        self.send_data(0x1c, u16(1) + u16(0) + ev)

    # US layout, PC set-1 scancodes 0x00-0x39 (same table as src/login.c)
    US_PLAIN = "\0\0" "1234567890-=" "\0\0" "qwertyuiop[]" "\0\0" "asdfghjkl;'`" "\0\\" "zxcvbnm,./" "\0*\0 "
    US_SHIFT = "\0\0" "!@#$%^&*()_+" "\0\0" "QWERTYUIOP{}" "\0\0" "ASDFGHJKL:\"~" "\0|" "ZXCVBNM<>?" "\0*\0 "

    def type_text(self, text):
        """Type text as scancodes (US layout); '\n' presses Return."""
        for ch in text:
            if ch == "\n":
                self.key_fastpath(0x1c)
                self.key_fastpath(0x1c, release=True)
                continue
            shift = ch in self.US_SHIFT and ch not in self.US_PLAIN
            code = (self.US_SHIFT if shift else self.US_PLAIN).index(ch)
            if shift:
                self.key_fastpath(0x2a)
            self.key_fastpath(code)
            self.key_fastpath(code, release=True)
            if shift:
                self.key_fastpath(0x2a, release=True)

    def key_fastpath(self, code, release=False):
        events = bytes([(0 << 5) | (1 if release else 0), code])
        enc = self.keys.encrypt(events)
        sig = self.keys.mac(events)
        body = sig + enc
        hdr = bytes([(1 << 2) | 0x80])                     # 1 event, encrypted
        ln = len(body) + 2
        if ln + 1 > 0x7f:
            raise Fail("fast-path too long for test")
        self.sock.sendall(hdr + bytes([ln]) + body)


def run(args):
    log = lambda m: print("client: " + m, flush=True)
    fifo = None
    if args.files:
        fifo = (os.path.join(args.files, "c2s"), os.path.join(args.files, "s2c"))
    c = Client(args.host, args.port, log, fifo, args.with_cd_header)
    if not c.connect(0x3):                                  # PROTOCOL_SSL | PROTOCOL_HYBRID
        log("reconnecting with PROTOCOL_RDP only")
        if not c.connect(0x0):
            raise Fail("server refused PROTOCOL_RDP too")
    c.mcs_connect(1024, 768, 16)
    c.join()
    c.security_exchange()
    c.client_info(args.password or "")
    c.logged_in = args.type is None and not args.wrong
    c.capabilities()
    c.pump(1.5)
    log("received %d bitmap rectangles (%d RLE-compressed)"
        % (c.stats["bitmaps"], c.stats["compressed"]))

    checks = []
    is_red = lambda p: p[0] > 200 and p[1] < 80
    if args.type is not None or args.wrong:
        tl = c.pixel(5, 30)
        checks.append(("login prompt shown instead of the screen", not is_red(tl)))
        if args.png:
            c.save_png(args.png.replace(".png", "-login.png"))
    if args.wrong:
        for attempt in range(3):
            try:
                c.type_text("wrong%d\n" % attempt)
                c.pump(1.0)
            except (Fail, OSError) as e:    # closed, or reset mid-send
                if isinstance(e, socket.timeout):
                    raise
                log("after attempt %d: %s" % (attempt + 1, e))
                checks.append(("disconnected after 3 wrong passwords", attempt == 2))
                break
        else:
            checks.append(("disconnected after 3 wrong passwords", False))
        c.sock.close()
        return report(checks)
    if args.type is not None:
        c.type_text("nope\n")
        c.pump(1.0)
        checks.append(("still at the prompt after a wrong password", not is_red(c.pixel(5, 30))))
        c.logged_in = True
        c.type_text(args.type + "\n")
        c.pump(1.5)
        checks.append(("nothing sent on the clipboard channel before login (%d)"
                       % c.stats["clip_before_login"], c.stats["clip_before_login"] == 0))
    tl, br = c.pixel(5, 30), c.pixel(c.w - 5, c.h - 5)
    checks.append(("top-left marker is red", tl[0] > 200 and tl[1] < 80))
    checks.append(("bottom-right marker is green", br[1] > 180 and br[0] < 80))
    checks.append(("title bar is blue", c.pixel(300, 2)[2] > 150))

    # input: click to paint at (320,270) via slow path; a key via fast path
    c.mouse_slowpath(0x8000 | 0x1000, 320, 270)
    c.mouse_slowpath(0x1000, 320, 270)
    c.key_fastpath(0x1e)
    c.key_fastpath(0x1e, release=True)
    c.pump(1.0)
    p = c.pixel(320, 270)
    checks.append(("click painted an orange dot (got %r)" % (p,), p[0] > 200 and 100 < p[1] < 170 and p[2] < 60))

    # middle click: the test host switches to 800x600 (like an Amiga screen
    # switch), and a second middle click back to 640x512
    for want_w, want_h in ((800, 600), (640, 512)):
        c.mouse_slowpath(0x8000 | 0x4000, 50, 300)
        c.mouse_slowpath(0x4000, 50, 300)
        deadline = time.time() + (120 if args.files else 10)
        while time.time() < deadline and not (c.active and c.w == want_w):
            c.pump(0.3)
        c.pump(1.0)                                  # the full repaint
        br = c.pixel(c.w - 5, c.h - 5)
        checks.append(("resize to %dx%d via Deactivate All + Demand Active (now %dx%d, "
                       "BR marker %s)" % (want_w, want_h, c.w, c.h, "green" if br[1] > 180 else br),
                       c.w == want_w and c.h == want_h and br[1] > 180 and br[0] < 80))
    checks.append(("two deactivations seen (%d)" % c.stats.get("deactivations", 0),
                   c.stats.get("deactivations", 0) == 2))

    # right click: the test host answers with a beep (Play Sound PDU)
    c.mouse_slowpath(0x8000 | 0x2000, 400, 300)
    c.mouse_slowpath(0x2000, 400, 300)
    c.pump(1.0)
    beeps = c.stats.get("beeps", [])
    checks.append(("beep arrived as Play Sound PDU (%s)" % beeps, beeps == [(150, 880)]))

    if not args.no_clipboard:
        c.clipboard_checks(checks)

    # >4096 PDUs each way to exercise RC4 key updates on both sides
    n = args.flood
    if n:
        log("sending %d Shutdown Requests to force key updates..." % n)
        # in batches, reading replies in between, so pipe buffers never fill
        deadline = time.time() + (900 if args.files else 60)
        sent = 0
        while sent < n and time.time() < deadline:
            batch = min(100, n - sent)
            for _ in range(batch):
                c.send_data(0x24, b"")
            sent += batch
            while c.stats["shutdown_denied"] < sent and time.time() < deadline:
                c.pump(0.2)
        checks.append(("server answered all %d requests across key updates (%d)"
                       % (n, c.stats["shutdown_denied"]), c.stats["shutdown_denied"] == n))
        checks.append(("client saw server key update(s): %d" % c.keys.updates[1], c.keys.updates[1] >= 1))
        checks.append(("client performed own key update(s): %d" % c.keys.updates[0], c.keys.updates[0] >= 1))

    if args.png:
        c.save_png(args.png)
        log("screenshot written to %s" % args.png)
    c.send_x224(b"\x21\x80")                                # disconnect provider ultimatum
    c.sock.close()
    return report(checks)


def report(checks):
    ok = True
    for name, good in checks:
        print(("PASS " if good else "FAIL ") + name)
        ok &= good
    return ok


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=13389)
    ap.add_argument("--png")
    ap.add_argument("--files", help="talk over files DIR/c2s and DIR/s2c (created "
                    "here) instead of TCP; the --spawn command must use them")
    ap.add_argument("--password", help="send this password in the Client Info PDU "
                    "(like mstsc saved credentials)")
    ap.add_argument("--type", help="type this password at the server's login prompt")
    ap.add_argument("--with-cd-header", action="store_true",
                    help="don't advertise NO_BITMAP_COMPRESSION_HDR, so the server must "
                    "send TS_CD_HEADER")
    ap.add_argument("--no-clipboard", action="store_true",
                    help="skip the clipboard checks (server without clipboard support)")
    ap.add_argument("--wrong", action="store_true",
                    help="type 3 wrong passwords and expect to be disconnected")
    ap.add_argument("--flood", type=int, default=4200,
                    help="requests sent to force RC4 key updates (default 4200)")
    ap.add_argument("--spawn", nargs=argparse.REMAINDER,
                    help="start this server command (with -p PORT added), test, then stop it")
    args = ap.parse_args()
    proc = None
    if args.files:
        os.makedirs(args.files, exist_ok=True)
        for name in ("c2s", "s2c"):
            open(os.path.join(args.files, name), "wb").close()
    if args.spawn:
        cmd = args.spawn if args.files else args.spawn + ["-p", str(args.port)]
        # Server output goes to a file, not a pipe: a pipe nobody reads
        # until the end can fill up and block the server.
        import tempfile
        logf = tempfile.TemporaryFile(mode="w+")
        proc = subprocess.Popen(cmd, stdout=logf, stderr=subprocess.STDOUT, text=True)
        FileSock.server = proc
        time.sleep(0.5)
    ok = False
    try:
        ok = run(args)
    except (Fail, OSError) as e:
        print("FAIL %s: %s" % (type(e).__name__, e))
    finally:
        if proc:
            time.sleep(0.3)
            proc.terminate()
            proc.wait()
            logf.seek(0)
            out = logf.read()
            if "MAC mismatch" in out:
                print("FAIL server reported MAC mismatch")
                ok = False
            for want in EXPECT_LOG:
                good = want in out
                print(("PASS " if good else "FAIL ") + "server log has: " + want[:70])
                ok &= good
            print("--- server log ---")
            print("\n".join(l for l in out.splitlines() if not l.startswith("key:")
                            and not l.startswith("mouse:")))
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
