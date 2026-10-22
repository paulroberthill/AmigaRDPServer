# Amiga RDP server: Linux prototype

A minimal RDP server, written to find out whether the stock Windows Remote
Desktop client (mstsc) will connect using **Standard RDP Security**: RC4 plus a
512-bit RSA key exchange, with no TLS and no NLA. That is cheap enough to run on
a 68k Amiga. The prototype serves an 8-bit indexed test pattern, the way an
Amiga screen would look, and shows the mouse and keyboard input it receives.

## Build and test

    make            # builds ./rdpserver (generates src/serverkey.c on first build)
    make test       # crypto known-answer tests + end-to-end test with tests/testclient.py

`tests/testclient.py` is a separate client written from the spec (MS-RDPBCGR). It:

- performs the whole connection sequence;
- checks the certificate signature against the Terminal Services key;
- decodes the bitmaps and checks pixels;
- sends input;
- forces RC4 key updates in both directions (more than 4096 packets each way).

`--png FILE` saves what it received.

## Result (2026-10-22)

**mstsc works.** It was tested with Windows 10 mstsc (build 19041) at the
default settings: 640x512, 16 bpp. The connection sequence, display, mouse and
keyboard all worked, with no MAC errors.

- mstsc first asks for TLS, CredSSP and RDSTLS. After the server selects
  PROTOCOL_RDP, mstsc drops that connection and reconnects asking for
  PROTOCOL_RDP only, which succeeds. In practice that is the same as `-f`.
- mstsc's Confirm Active repeats its own size and depth (1920x1080 at 32 bpp)
  but uses the server's Demand Active values.
- Windows 11 has not been tested yet.

## Testing with mstsc

    ./rdpserver -P secret       # port 3389, 640x512, 16 bpp

Then, on Windows, run `mstsc /v:<linux-host-ip>`. If the "identity of the
remote computer cannot be verified" prompt appears, click Connect. The server
shows its own password prompt (see Authentication below). After you log in,
you should see the test pattern with a bouncing checkered box. Click to paint,
and type to see the scancodes.

If it fails, try these variants in turn:

| Option | What it changes |
|--------|-----------------|
| `-n` | No password (instead of `-P`): anyone who can connect gets control. |
| `-u` | Send bitmaps uncompressed, for comparison (RLE is the default). |
| `-f` | Refuses TLS with `RDP_NEG_FAILURE` (as xrdp does) instead of selecting PROTOCOL_RDP directly. mstsc should reconnect without TLS. |
| `-b 8/15/24/32` | Wire colour depth (mstsc asks for 32; the server overrides it). `-b 8` tests whether palette mode still works. |
| `-W 800 -H 600` | Desktop size (at least 640x400). |
| `-v` | Logs every PDU. |

The server log records each step of the connection sequence, so the last line
before a disconnect shows where the client gave up.

## Compression

Screen tiles are sent with RDP's interleaved RLE bitmap compression
(MS-RDPBCGR 3.1.9), which mstsc decodes natively.

- **What the encoder uses:** only three order types, so the decoder's subtler
  rules never come into play.
  - Background runs: pixels that repeat the scanline before them, which
    catches vertical edges, gradients and repeated lines.
  - Colour runs.
  - Literal pixels.
- **Fallback:** a tile that wouldn't get smaller is sent raw.
- **Colour depth:** RLE is defined for 8, 15, 16 and 24 bpp only, so
  `BPP=32` / `-b 32` tiles are always sent raw. Use 16 (the default) or 24.
- **Statistics:** at the end of each session the log shows tiles sent and
  bytes against raw. The test pattern goes down to under 1%.
- **Confirmed with mstsc:** Windows 10 mstsc accepts the compressed tiles, as
  tested on 2026-10-22. A first version that sent `TS_CD_HEADER` with
  `cbScanWidth` in pixels made mstsc fail with "Because of a protocol error,
  this session will be disconnected".
- **Turning it off:** `NOCOMPRESS` (Amiga) or `-u` (Linux) sends everything
  raw, for comparison.

`tests/test_rle.c` encodes tiles of many sizes and contents (noise, solid,
gradients, stripes, dither) at 1, 2 and 3 bytes per pixel.
`tests/test_rle.py` decodes them with an independent decoder written from the
spec's reference pseudo-code and checks they come back exactly. `make test`
runs it natively and `make test68k` as 68k code.

## Clipboard

Text is shared both ways over RDP's standard clipboard channel (`cliprdr`,
MS-RDPECLIP). mstsc enables it by default; it's the "Clipboard" box under
Local Resources.

- **Windows → Amiga:** when you copy text in Windows, the server fetches it
  immediately and writes it to the Amiga clipboard (`clipboard.device` unit 0,
  IFF FTXT), so any Amiga program can paste it.
- **Amiga → Windows:** the server polls the Amiga clip ID. When something new
  is copied, it offers it to Windows, and the text is read only when you paste.
  Whatever is on the Amiga clipboard when you connect is offered straight away.
- **Text conversion:** UTF-16 with CRLF line endings on Windows, Latin-1 with
  LF on the Amiga. Curly quotes, dashes, bullets and non-breaking spaces become
  their ASCII equivalents, and other characters outside Latin-1 become `?`.
- **Limits:** plain text only (no images or files), up to 512 KB.
- **Not before login:** nothing passes in either direction until the client
  has logged in.
- **Turning it off:** `NOCLIPBOARD` disables it on the Amiga.

## Beeps

On the Amiga, every `DisplayBeep()`, from any program, also plays a short beep
on the Windows PC. The server sends it to mstsc as a Play Sound PDU (880 Hz,
150 ms).

- **How it hooks in:** `src/amiga/beep.c` patches intuition's `DisplayBeep()`
  with `SetFunction()`.
- **The patch:** a 46-byte stub in its own memory. It `Signal()`s the server
  and then runs the original, so the Amiga still flashes or beeps as usual.
- **On exit:** the original is restored. If another program has patched
  `DisplayBeep()` on top in the meantime, the stub becomes a pass-through and
  stays in memory, so nothing ever jumps into freed code.
- **Before login:** no beeps are sent.
- **Turning it off:** `NOBEEP`.

`tests/test_beep.c` runs the stub under vamos. It checks that the stub calls
`Signal()` with the right task and mask (through a fake ExecBase, since
vamos's `Signal()` does nothing), and that it continues into the original
with the caller's `a0` intact.

## Authentication

Without NLA, mstsc connects without asking for credentials. So, as Windows and
xrdp do in this mode, the server draws its own login prompt. Until the client
logs in, it sees only that prompt, and its keystrokes go to the prompt, not to
the Amiga.

- **Saved credentials:** if the client sends a password in its Client Info
  PDU, it is checked first. Saved credentials in mstsc do this, and a match
  skips the prompt.
- **Wrong passwords:** after 3, the server disconnects, then pauses 2 seconds
  before accepting another connection.
- **Keyboard layout:** the prompt maps keys using a US or UK layout, chosen
  from the layout id the client reports. Passwords are compared as Latin-1, as
  typed on the Amiga, so `£` works on a UK keyboard.
- **What it protects against:** this stops casual access on your network. It
  is not strong security. Standard RDP Security uses RC4 with a 512-bit RSA key
  exchange and has no server authentication, so an attacker who can intercept
  traffic could capture the password. Do not expose the port to the internet.

## Amiga host (`build/rdpserver`)

It is built for a 68060 with Picasso96 and Roadshow. It was confirmed
working on real hardware with Windows 10 mstsc on 2026-10-22 (version 0.9):
the screen, input, password prompt, RLE compression, clipboard in both
directions, beeps, resizing when switching screens, and faster sampled screen
polling. Copy `build/rdpserver` to the Amiga and run it from a
Shell:

    RDPServer PASSWORD=secret [PORT=3389] [BPP=16] [INTERVAL=100] [SCAN=4] [NOCOMPRESS] [NOCLIPBOARD] [NOBEEP] [NEGFAIL] [VERBOSE]

- **Setting the password:** to keep it out of scripts, leave out `PASSWORD=`
  and put the password in `ENVARC:RDPServer/Password`. Copy it to `ENV:` (or
  reboot) for it to take effect. The server refuses to start with no password
  unless you give `NOPASSWORD`.

- **What it shares:** the front screen. When you switch to a screen of a
  different size, the server resizes the session using RDP's
  Deactivation-Reactivation Sequence (Deactivate All, then a new Demand
  Active), and mstsc adjusts its window to match. It's the same mechanism a
  Windows server uses when its resolution changes. Screens of the same size
  switch without that.
- **RTG screens** are read straight from the Picasso96 bitmap through the
  cybergraphics.library API. Only 64x64 tiles that changed are converted and
  sent. A 16-bit `RGB16PC` screen with `BPP=16` needs no conversion at all.
- **Native screens** fall back to `ReadPixelArray8()`. This is slower, and HAM
  is not supported.
- **Polling:** `INTERVAL` is the time from the end of one screen poll to the
  start of the next.
  - **Sampled rows:** reading the graphics card over Zorro is the expensive
    part. Each poll compares only every `SCAN`-th row (default 4) with the
    shadow copy, starting one row further down each time, and reads only the
    tiles where a sampled row differs in full. A static screen therefore costs
    about 1/`SCAN` of a full read.
  - **Latency:** changes at least `SCAN` rows tall are seen at the next poll.
    Smaller ones are seen within `SCAN` polls (400 ms with the defaults).
    `SCAN=1` compares every row, as before.
  - **Copying:** compares are done in longwords, and changed tiles are copied
    with exec's `CopyMemQuick()`, which 060 systems often patch to use
    `move16`.
  - **Measuring:** when a client disconnects, the Shell log shows the number
    of polls, the average time per poll and the KB read per poll. Use it to
    compare settings, for example `SCAN=1` against `SCAN=4`. Times are in
    `DateStamp()`'s 20 ms steps, averaged.
  - **Tests:** `tests/test_scan.c` checks the detection logic, natively and on
    68k, at 1-4 bytes per pixel and several `SCAN` values, with random changes
    down to single pixels. It checks that every change is caught within `SCAN`
    polls, that tall ones are caught at once, and that the shadow ends up
    exact.
- **Input** goes into input.device:
  - the mouse as absolute positions, plus NewMouse wheel events;
  - the keyboard as raw keys mapped from PC scancodes, using ISO/UK positions
    (`src/amiga/keymap.h`).
- **Quitting:** Ctrl-C quits.

`make test68k` runs the 68k build of the protocol core under vamos. It runs
the crypto tests, then `tests/pipehost.c`, which serves the test pattern to
`tests/testclient.py` over two plain files that each side appends to and polls
(vamos can't open named pipes). It exercises the same wire-format framebuffer
path the Amiga host uses, and it passed on 2026-10-22. vamos needs:
`python3 -m venv .venv && .venv/bin/pip install amitools==0.8.1 machine68k==0.3.0`.

## Layout

| Path | Contents |
|------|----------|
| `src/rdp.c` | Protocol core: X.224, MCS/GCC, security exchange, licensing bypass, capabilities, finalisation, input, bitmap updates. Platform-independent; I/O goes through `rdp_callbacks`. |
| `src/sec.c` | Standard RDP Security: key derivation, MAC, RC4, key updates. |
| `src/md5.c`, `src/sha1.c`, `src/rc4.c`, `src/bignum.c` | Small endian-neutral crypto. No OpenSSL needed. |
| `src/serverkey.c` | Generated by `tools/genkey.py`: the server's RSA key and a proprietary certificate signed with the published TS key. |
| `src/posix/main.c` | Linux host: sockets, serves the test pattern. |
| `src/amiga/main.c`, `src/amiga/keymap.h` | Amiga host: Roadshow sockets, screen capture, input.device injection. |
| `src/cliprdr.c` | Clipboard channel protocol (text), shared by both hosts. |
| `src/amiga/scan.c` | Change detection for screen polling (tested by `tests/test_scan.c`). |
| `src/amiga/beep.c` | `DisplayBeep()` patch (stub tested by `tests/test_beep.c`). |
| `src/amiga/ftxt.c` | IFF FTXT packing and parsing for the Amiga clipboard (unit-tested by `tests/test_ftxt.c`). |
| `src/testpattern.c` | Test pattern that echoes input, shared by the Linux host and `tests/pipehost.c`. |

