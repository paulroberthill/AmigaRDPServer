# RDPServer

An RDP server for AmigaOS 3.x. It lets you see and control your Amiga's
screen from Windows Remote Desktop Connection (mstsc), with keyboard, mouse,
clipboard and beeps.

It uses Standard RDP Security (RC4 with a 512-bit RSA key exchange) rather
than TLS, which is light enough for a 68k CPU.

## Requirements

- AmigaOS 3.0 or later, 68020 or better (one binary for 020 to 060)
- A TCP/IP stack providing `bsdsocket.library` (tested with Roadshow)
- For RTG screens, `cybergraphics.library` (tested with Picasso96). Native
  OCS/ECS/AGA screens also work, more slowly (HAM is not supported)
- Windows Remote Desktop Connection (tested with Windows 10)

## Quick start

On the Amiga, from a Shell:

    RDPServer PASSWORD=secret

The first run creates the server's encryption key, which takes from a few
seconds to a few minutes depending on the CPU. It is kept in
`ENVARC:RDPServer/ServerKey` and reused after that.

On Windows, run `mstsc /v:<amiga-ip-address>`. If a warning says the identity
of the remote computer cannot be verified, click Connect. Enter the password
at the Amiga's login prompt, or save it in mstsc's credentials to skip the
prompt. Press Ctrl-C in the Amiga Shell to stop the server, or start
RDPServer again: a second start stops the running server and exits.

You can also start it by double-clicking its icon. Its messages then appear
in a window; press Ctrl-C in that window, or double-click the icon again,
to stop it. Set options as tool
types in the icon (select it, then Icons > Information). The icon lists them
in parentheses, which turns them off; remove the parentheses to use one.
They take the same form as Shell arguments, such as `PORT=3390` or `NOBEEP`;
spaces before and after a value are ignored.
`PASSWORD=` works too, but it is stored as plain text in the icon, so prefer
`ENV:RDPServer/Password` (see below).

## Options

These are Shell arguments, or tool types when started from Workbench.

    RDPServer [PASSWORD=pw | NOPASSWORD] [PORT=n] [BPP=15|16|24|32]
              [INTERVAL=ms] [SCAN=n] [NOCOMPRESS] [NOCLIPBOARD] [NOBEEP]
              [NEWKEY] [NEGFAIL] [VERBOSE] [QUIET]

| Option | Meaning |
|--------|---------|
| `PASSWORD=pw` | Password clients must enter. |
| `NOPASSWORD` | Run without a password. Anyone who can connect gets control. |
| `PORT=n` | TCP port (default 3389). |
| `BPP=n` | Colour depth sent to the client: 15, 16 (default), 24 or 32. 32 is never compressed, so prefer 16 or 24. |
| `INTERVAL=ms` | Pause between screen polls (default 100, minimum 20). |
| `SCAN=n` | Compare every n-th row per poll (1-16, default 4). See Performance. |
| `NOCOMPRESS` | Send screen updates uncompressed. |
| `NOCLIPBOARD` | Don't share the clipboard. |
| `NOBEEP` | Don't forward beeps. |
| `NEWKEY` | Replace the server key with a new one. |
| `NEGFAIL` | Refuse TLS with an error rather than declining it. Try this if a client won't connect. |
| `VERBOSE` | Log protocol details to the Shell. |
| `QUIET` | Print only errors and warnings, not the startup and connection messages. From Workbench, no window opens unless there is one; double-click the icon again to stop it. |

### Keeping the password out of scripts

Leave out `PASSWORD=` and put the password in `ENVARC:RDPServer/Password`.
Copy it to `ENV:RDPServer/Password` (or reboot) for it to take effect. The
server will not start without a password unless you give `NOPASSWORD`.

## What it does

- **Screen:** shares the front screen. Switching to a screen of a different
  size resizes the client's window to match.
- **Input:** the mouse (including the wheel, as NewMouse events) and keyboard
  are passed to input.device. Keys are mapped by position from a PC keyboard.
  The right Ctrl key is the Right Amiga key, so right Ctrl-C copies and right
  Ctrl-V pastes in Amiga programs. Left Ctrl stays Ctrl.
- **Clipboard:** text copied on either side can be pasted on the other, up to
  512 KB. Characters that Latin-1 can't hold become their nearest ASCII
  equivalent or `?`. In mstsc this is the Clipboard option under Local
  Resources.
- **Beeps:** every `DisplayBeep()` also plays a short beep on the PC.
- **Login:** until the password is entered the client sees only the login
  prompt, and its keystrokes do not reach the Amiga. After three wrong
  attempts the server disconnects. The prompt understands US and UK keyboard
  layouts.
- **Sessions:** one client at a time.

## Performance

Reading the graphics card's memory is the slowest part. To keep it cheap,
each poll compares only every `SCAN`-th row with the previous picture,
starting one row lower each time, and reads in full only the 64x64 tiles that
changed. Changed tiles are compressed before being sent.

- Larger `SCAN` values cost less while the screen is idle. Small changes may
  take up to `SCAN` polls to show up (400 ms with the defaults). `SCAN=1`
  checks every row.
- A 16-bit RTG screen with `BPP=16` needs no colour conversion.
- When a client disconnects, the Shell shows the number of polls, the average
  time per poll and the data read per poll, so you can compare settings.

## Security

The password stops casual access on your local network. It is not strong
security: Standard RDP Security has weak encryption and does not prove the
server's identity, so someone who can intercept the traffic could capture
the password. Do not expose the port to the internet.

Each installation makes its own server key; none is built into the program.
`NEWKEY` replaces it.

## Building from source

The Amiga build uses bebbo's amiga-gcc in `/opt/amiga`. There is also a Linux
host that serves a test pattern, for testing the protocol code.

    make              # ./rdpserver (Linux) and build/RDPServer (Amiga)
    make test         # Linux: unit tests and end-to-end tests
    make test68k      # the same code as 68k, under vamos
    make test68k-keygen   # 68k key generation (slow)
    make release      # build/RDPServer.lha and its Aminet readme

The 68k tests need vamos:
`python3 -m venv .venv && .venv/bin/pip install amitools==0.8.1 machine68k==0.3.0`.

The end-to-end tests use `tests/testclient.py`, an independent RDP client
written from the specification. It checks the certificate, decodes the screen
and checks pixels, sends input, and exercises the clipboard, beeps, resizing
and RC4 key updates.

### Linux host

    ./rdpserver -P secret

It listens on port 3389 and shows a test pattern that echoes mouse and
keyboard input. Options: `-n` (no password), `-p port`, `-b 8|15|16|24|32`,
`-W width -H height`, `-u` (uncompressed), `-k` (new key at startup), `-f`
(as `NEGFAIL`), `-v` (verbose). It uses a key generated at build time in
`src/posix/hostkey.c`, which is never committed.

### Source layout

| Path | Contents |
|------|----------|
| `src/rdp.c` | Protocol core: connection sequence, capabilities, input, bitmap updates. Platform-independent. |
| `src/sec.c` | Standard RDP Security: key derivation, MAC, RC4, key updates. |
| `src/md5.c`, `src/sha1.c`, `src/rc4.c`, `src/bignum.c` | Small portable crypto. |
| `src/keygen.c`, `src/srvkey.c` | Server key generation, and the certificate built from it. |
| `src/mul32.h`, `src/amiga/cpu.c` | 68060-friendly multiply, and picking the RSA code for the CPU at startup. |
| `src/rle.c` | Interleaved RLE bitmap compression. |
| `src/cliprdr.c` | Clipboard channel. |
| `src/login.c` | Login prompt. |
| `src/amiga/main.c`, `src/amiga/keymap.h` | Amiga host: sockets, screen capture, input. |
| `src/amiga/scan.c` | Screen change detection. |
| `src/amiga/tooltypes.c` | Workbench tool types as `ReadArgs()` input. |
| `src/amiga/ftxt.c` | IFF FTXT for the Amiga clipboard. |
| `src/amiga/beep.c` | `DisplayBeep()` patch. |
| `src/posix/main.c`, `src/testpattern.c` | Linux host and its test pattern. |
| `dist/`, `tools/mkicon.py` | Aminet readme template, and the generator for the release's icons. |
| `tests/` | Unit tests, test hosts and the test client. |

## Licence

MIT; see `LICENSE`.
