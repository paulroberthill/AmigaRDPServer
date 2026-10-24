/*
 * AmigaOS 3.x host for the RDP server.
 *
 * Target: 68020 to 68060 (one binary), Picasso96 (through its
 * cybergraphics.library API), Roadshow (bsdsocket.library). Native
 * OCS/ECS/AGA screens work through a slower ReadPixelArray8() fallback
 * (no HAM).
 *
 *   RDPServer [PASSWORD=pw | NOPASSWORD] [PORT=n] [BPP=15|16|24|32]
 *             [INTERVAL=ms] [SCAN=n] [NOCOMPRESS] [NOCLIPBOARD] [NOBEEP]
 *             [NEWKEY] [NEGFAIL] [VERBOSE]
 *
 * From Workbench the same options are read from the icon's tool types.
 *
 * Server key: each install has its own RSA key, generated on the first run
 * (seconds to minutes, depending on the CPU) and kept in
 * ENVARC:RDPServer/ServerKey; no key is compiled into the binary. NEWKEY
 * replaces it.
 *
 * Without PASSWORD the password is read from ENV:RDPServer/Password; with
 * neither (and no NOPASSWORD) the server refuses to start. Clients see a
 * login prompt until they enter it (or send it as saved credentials).
 *
 * Screen updates: the front screen is polled every INTERVAL ms. Reading the
 * graphics card over Zorro is the expensive part, so each poll compares
 * only every SCAN-th row (default 4, starting one row further down each
 * poll) against a shadow copy in the screen's native pixel format; 64x64
 * tiles where a sampled row differs are then read in full, converted to the
 * wire format and sent. A change at least SCAN rows tall is seen at the next
 * poll, a smaller one within SCAN polls. SCAN=1 compares every row.
 *
 * Input: RDP mouse/keyboard events are injected with input.device
 * IND_WRITEEVENT (absolute pointer positions, raw keys, NewMouse wheel).
 *
 * Clipboard: clipboard.device unit 0 (IFF FTXT) is shared with the client.
 * Text copied in Windows is written to it straight away; Amiga copies are
 * noticed by polling the clip ID and offered to Windows.
 *
 * Beeps: DisplayBeep() is patched to signal this task (beep.c), and each
 * beep is sent to the client as a Play Sound PDU.
 */
#include <sys/types.h>      /* before the Roadshow headers (ssize_t) */
#include <exec/types.h>
#include <exec/memory.h>
#include <dos/dos.h>
#include <devices/clipboard.h>
#include <devices/input.h>
#include <devices/inputevent.h>
#include <graphics/gfx.h>
#include <graphics/rastport.h>
#include <graphics/view.h>
#include <intuition/intuitionbase.h>
#include <intuition/screens.h>
#include <cybergraphx/cybergraphics.h>
#include <workbench/startup.h>
#include <workbench/workbench.h>

/* "CyberGfxBase" would be auto-opened by the startup code as the
 * non-existent CyberGfx.library, so use another name. */
#define CYBERGFX_BASE_NAME RdpCyberGfxBase

#include <proto/exec.h>
#include <proto/dos.h>
#include <proto/graphics.h>
#include <proto/intuition.h>
#include <proto/cybergraphics.h>
#include <proto/icon.h>
#include <proto/bsdsocket.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../rdp.h"
#include "../crypto.h"
#include "beep.h"
#include "ftxt.h"
#include "scan.h"
#include "tooltypes.h"
#include "keymap.h"

unsigned long __stack = 65536;          /* honoured by libnix */

/* IntuitionBase and GfxBase are opened by the startup code. */
struct Library *SocketBase;
struct Library *RdpCyberGfxBase;

static const char version[] __attribute__((used)) = "$VER: RDPServer 1.2.4 (24.10.2026)";

#define TILE 64

#ifndef IECLASS_NEWMOUSE
#define IECLASS_NEWMOUSE 0x16   /* NewMouse standard (newmouse.h) */
#endif

static struct {
    LONG port, bpp, interval, scan;
    int negfail, verbose, nocompress, noclipboard, nobeep, quiet;
    char password[64];
} opt = { 3389, 16, 100, 4, 0, 0, 0, 0, 0, 0, "" };

static ULONG beep_sig;          /* signal mask set by the DisplayBeep() patch */

/* ------------------------------------------------------------------ */
/* Logging, time, randomness                                          */
/* ------------------------------------------------------------------ */

static void log_msg(void *ctx, const char *msg)
{
    (void)ctx;
    printf("%s\n", msg);
    fflush(stdout);
}

static ULONG now_ms(void)
{
    struct DateStamp ds;
    DateStamp(&ds);
    return (ULONG)ds.ds_Days * 86400000UL + (ULONG)ds.ds_Minute * 60000UL +
           (ULONG)ds.ds_Tick * 20UL;
}

/*
 * Entropy pool: SHA-1 over things an attacker on the network cannot know
 * precisely (video beam position samples, timestamps, input event timings).
 * Only used for the 32-byte server random of Standard RDP Security.
 */
static uint8_t pool[20];

static void stir(const void *data, size_t len)
{
    sha1_ctx c;
    volatile UWORD *vhposr = (volatile UWORD *)0xdff006;
    ULONG secs, micros;
    UWORD beam[8];
    int i;

    CurrentTime(&secs, &micros);
    for (i = 0; i < 8; i++)
        beam[i] = *vhposr;
    sha1_init(&c);
    sha1_update(&c, pool, sizeof(pool));
    sha1_update(&c, data, len);
    sha1_update(&c, &secs, sizeof(secs));
    sha1_update(&c, &micros, sizeof(micros));
    sha1_update(&c, beam, sizeof(beam));
    sha1_final(&c, pool);
}

/* More entropy before generating a key: timing jitter between the beam
 * position, the CIA timers and the CPU, plus system state. */
static void gather_entropy(void)
{
    volatile UBYTE *ciaa_tod = (volatile UBYTE *)0xbfe801;
    volatile UBYTE *ciab_ta = (volatile UBYTE *)0xbfd400;
    volatile UWORD *vhposr = (volatile UWORD *)0xdff006;
    struct DateStamp ds;
    UBYTE sample[64];
    ULONG mem[3];
    int i, j;

    for (i = 0; i < 256; i++) {
        for (j = 0; j < (int)sizeof(sample); j += 4) {
            volatile int spin = (*vhposr ^ *ciab_ta) & 15;
            while (spin--)
                ;
            sample[j] = (UBYTE)*vhposr;
            sample[j + 1] = *ciab_ta;
            sample[j + 2] = *ciaa_tod;
            sample[j + 3] = (UBYTE)(*vhposr >> 8);
        }
        stir(sample, sizeof(sample));
    }
    DateStamp(&ds);
    mem[0] = AvailMem(MEMF_ANY);
    mem[1] = AvailMem(MEMF_CHIP);
    mem[2] = (ULONG)FindTask(NULL);
    stir(&ds, sizeof(ds));
    stir(mem, sizeof(mem));
}

static void get_random(void *ctx, uint8_t *out, size_t len)
{
    static ULONG counter;
    (void)ctx;
    while (len) {
        size_t n = len < 16 ? len : 16;
        counter++;
        stir(&counter, sizeof(counter));
        memcpy(out, pool, n);   /* hand out 16 of the 20 bytes */
        out += n; len -= n;
    }
}

/* ------------------------------------------------------------------ */
/* Server key (ENVARC:RDPServer/ServerKey)                            */
/* ------------------------------------------------------------------ */

#define KEY_DIR   "ENVARC:RDPServer"
#define KEY_FILE  KEY_DIR "/ServerKey"
#define KEY_MAGIC "RDPKEY01"

/* File: 8-byte magic, 64-byte modulus, 64-byte private exponent (both
 * little-endian), 4-byte public exponent (big-endian). */
static int load_key(uint8_t n[64], uint8_t d[64], uint32_t *e)
{
    UBYTE buf[8 + 64 + 64 + 4];
    BPTR fh = Open((STRPTR)KEY_FILE, MODE_OLDFILE);
    LONG got;

    if (!fh)
        return -1;
    got = Read(fh, buf, sizeof(buf));
    Close(fh);
    if (got != (LONG)sizeof(buf) || memcmp(buf, KEY_MAGIC, 8))
        return -1;
    memcpy(n, buf + 8, 64);
    memcpy(d, buf + 72, 64);
    *e = ((uint32_t)buf[136] << 24) | ((uint32_t)buf[137] << 16) | ((uint32_t)buf[138] << 8) | buf[139];
    memset(buf, 0, sizeof(buf));
    return 0;
}

static int save_key(const uint8_t n[64], const uint8_t d[64], uint32_t e)
{
    UBYTE buf[8 + 64 + 64 + 4];
    BPTR lock = Lock((STRPTR)KEY_DIR, ACCESS_READ), fh;
    LONG put;

    if (!lock)
        lock = CreateDir((STRPTR)KEY_DIR);
    if (!lock)
        return -1;
    UnLock(lock);
    memcpy(buf, KEY_MAGIC, 8);
    memcpy(buf + 8, n, 64);
    memcpy(buf + 72, d, 64);
    buf[136] = (UBYTE)(e >> 24); buf[137] = (UBYTE)(e >> 16);
    buf[138] = (UBYTE)(e >> 8); buf[139] = (UBYTE)e;
    fh = Open((STRPTR)KEY_FILE, MODE_NEWFILE);
    if (!fh)
        return -1;
    put = Write(fh, buf, sizeof(buf));
    Close(fh);
    memset(buf, 0, sizeof(buf));
    return put == (LONG)sizeof(buf) ? 0 : -1;
}

/* Load this install's key, or generate (and save) one. */
static int setup_key(int force_new)
{
    uint8_t n[64], d[64];
    uint32_t e = 0;

    if (force_new || load_key(n, d, &e) || rdp_set_server_key(n, d, e)) {
        if (!opt.quiet) {
            printf("Generating this Amiga's server key (once; takes a few seconds)...\n");
            fflush(stdout);
        }
        gather_entropy();
        if (rdp_generate_server_key(n, d, &e, get_random, NULL) || rdp_set_server_key(n, d, e)) {
            printf("key generation failed\n");
            return -1;
        }
        if (save_key(n, d, e))
            printf("Could not save the key to %s: a new one will be made next time.\n", KEY_FILE);
        else if (!opt.quiet)
            printf("Saved to %s.\n", KEY_FILE);
    }
    memset(d, 0, sizeof(d));            /* the core keeps its own copy */
    return 0;
}

/* ------------------------------------------------------------------ */
/* Networking                                                         */
/* ------------------------------------------------------------------ */

static int net_send(void *ctx, const uint8_t *data, size_t len)
{
    LONG fd = *(LONG *)ctx;
    while (len) {
        LONG n = send(fd, (APTR)data, (LONG)len, 0);
        if (n <= 0)
            return -1;
        data += n; len -= (size_t)n;
    }
    return 0;
}

static int net_recv(void *ctx, uint8_t *data, size_t len)
{
    LONG fd = *(LONG *)ctx;
    while (len) {
        LONG n = recv(fd, data, (LONG)len, 0);
        if (n <= 0)
            return -1;
        data += n; len -= (size_t)n;
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* Screen capture                                                     */
/* ------------------------------------------------------------------ */

static struct {
    int w, h;               /* session desktop size */
    int wire_bpp, wire_bytes;
    uint8_t *wire;          /* framebuffer handed to the RDP core */

    struct Screen *scr;     /* screen the shadow belongs to */
    int sw, sh;             /* captured area (screen size clipped to w, h) */
    int rtg;                /* 1: CGX/P96 bitmap read directly */
    ULONG pixfmt;           /* RTG pixel format, or PIXFMT_LUT8 for native */
    int src_bytes;          /* bytes per pixel in the shadow */
    uint8_t *shadow;        /* last captured frame, native format, pitch w * 4 */
    ULONG pal32[256 * 3];   /* GetRGB32() result for indexed screens */
    uint8_t pal[256 * 3];
    int ncolors;
    int force;              /* reconvert and resend every tile on next poll */
    scan_ctx sc;            /* change detection state (scan.c) */
    ULONG polls, poll_ms, read_kb;  /* statistics */

    /* ReadPixelArray8 fallback for native screens */
    struct RastPort rp, temprp;
    struct BitMap *tempbm;
    uint8_t *band;
} cap;

static struct Screen *front_screen(void)
{
    ULONG lock = LockIBase(0);
    struct Screen *s = IntuitionBase->FirstScreen;
    UnlockIBase(lock);
    return s;
}

static void free_native_reader(void)
{
    if (cap.tempbm) {
        WaitBlit();
        FreeBitMap(cap.tempbm);
        cap.tempbm = NULL;
    }
}

/* Set up capture for screen s, just read from the front of the screen list. */
static int attach_screen(struct Screen *s)
{
    struct BitMap *bm = s->RastPort.BitMap;

    free_native_reader();
    cap.scr = s;
    cap.sw = s->Width < cap.w ? s->Width : cap.w;
    cap.sh = s->Height < cap.h ? s->Height : cap.h;
    cap.rtg = RdpCyberGfxBase && GetCyberMapAttr(bm, CYBRMATTR_ISCYBERGFX);
    if (cap.rtg) {
        cap.pixfmt = GetCyberMapAttr(bm, CYBRMATTR_PIXFMT);
        cap.src_bytes = (int)GetCyberMapAttr(bm, CYBRMATTR_BPPIX);
        if (cap.src_bytes < 1 || cap.src_bytes > 4)
            return -1;
    } else {
        ULONG depth = GetBitMapAttr(bm, BMA_DEPTH);
        if (s->ViewPort.Modes & HAM)
            printf("warning: HAM screens are not supported, colours will be wrong\n");
        cap.pixfmt = PIXFMT_LUT8;
        cap.src_bytes = 1;
        InitRastPort(&cap.rp);
        cap.rp.BitMap = bm;
        cap.temprp = cap.rp;
        cap.temprp.Layer = NULL;
        cap.tempbm = AllocBitMap(((cap.sw + 15) >> 4) << 4, 1, depth, 0, bm);
        if (!cap.tempbm)
            return -1;
        cap.temprp.BitMap = cap.tempbm;
    }
    cap.sc.width = cap.sw;      /* what scan.c compares */
    cap.sc.bytes_pp = cap.src_bytes;
    cap.ncolors = 0;            /* re-read the palette */
    cap.force = 1;
    if (!opt.quiet) {
        printf("capturing screen \"%s\": %dx%d, %s, %d byte(s)/pixel\n",
               s->Title ? (char *)s->Title : "", s->Width, s->Height,
               cap.rtg ? "RTG" : "native", cap.src_bytes);
        fflush(stdout);
    }
    return 0;
}

/* Read the palette of an indexed screen; returns 1 if it changed. */
static int update_palette(void)
{
    struct ViewPort *vp = &cap.scr->ViewPort;
    int n, i, changed;
    ULONG depth = cap.rtg ? 8 : GetBitMapAttr(cap.scr->RastPort.BitMap, BMA_DEPTH);
    ULONG table[256 * 3];
    uint8_t pal[256 * 3];

    n = depth >= 8 ? 256 : 1 << depth;
    if ((vp->Modes & EXTRA_HALFBRITE) && n == 64) {
        GetRGB32(vp->ColorMap, 0, 32, table);
        for (i = 0; i < 32 * 3; i++)
            table[32 * 3 + i] = (table[i] >> 1) & 0x7f7f7f7f;
    } else
        GetRGB32(vp->ColorMap, 0, (ULONG)n, table);
    memset(pal, 0, sizeof(pal));
    for (i = 0; i < n * 3; i++)
        pal[i] = (uint8_t)(table[i] >> 24);
    changed = n != cap.ncolors || memcmp(pal, cap.pal, sizeof(pal));
    memcpy(cap.pal, pal, sizeof(pal));
    cap.ncolors = n;
    return changed;
}

/* Native pixel -> 8-bit R, G, B. */
static void unpack(const uint8_t *p, uint8_t *rgb)
{
    unsigned v;

    switch (cap.pixfmt) {
    case PIXFMT_LUT8:
        memcpy(rgb, cap.pal + p[0] * 3, 3);
        return;
    case PIXFMT_RGB15:   v = (p[0] << 8) | p[1]; goto rgb15;
    case PIXFMT_RGB15PC: v = (p[1] << 8) | p[0];
    rgb15:
        rgb[0] = (uint8_t)((v >> 7) & 0xf8); rgb[1] = (uint8_t)((v >> 2) & 0xf8);
        rgb[2] = (uint8_t)(v << 3);
        return;
    case PIXFMT_BGR15:   v = (p[0] << 8) | p[1]; goto bgr15;
    case PIXFMT_BGR15PC: v = (p[1] << 8) | p[0];
    bgr15:
        rgb[2] = (uint8_t)((v >> 7) & 0xf8); rgb[1] = (uint8_t)((v >> 2) & 0xf8);
        rgb[0] = (uint8_t)(v << 3);
        return;
    case PIXFMT_RGB16:   v = (p[0] << 8) | p[1]; goto rgb16;
    case PIXFMT_RGB16PC: v = (p[1] << 8) | p[0];
    rgb16:
        rgb[0] = (uint8_t)((v >> 8) & 0xf8); rgb[1] = (uint8_t)((v >> 3) & 0xfc);
        rgb[2] = (uint8_t)(v << 3);
        return;
    case PIXFMT_BGR16:   v = (p[0] << 8) | p[1]; goto bgr16;
    case PIXFMT_BGR16PC: v = (p[1] << 8) | p[0];
    bgr16:
        rgb[2] = (uint8_t)((v >> 8) & 0xf8); rgb[1] = (uint8_t)((v >> 3) & 0xfc);
        rgb[0] = (uint8_t)(v << 3);
        return;
    case PIXFMT_RGB24:  rgb[0] = p[0]; rgb[1] = p[1]; rgb[2] = p[2]; return;
    case PIXFMT_BGR24:  rgb[0] = p[2]; rgb[1] = p[1]; rgb[2] = p[0]; return;
    case PIXFMT_ARGB32: rgb[0] = p[1]; rgb[1] = p[2]; rgb[2] = p[3]; return;
    case PIXFMT_BGRA32: rgb[0] = p[2]; rgb[1] = p[1]; rgb[2] = p[0]; return;
    case PIXFMT_RGBA32: rgb[0] = p[0]; rgb[1] = p[1]; rgb[2] = p[2]; return;
    default:            rgb[0] = rgb[1] = rgb[2] = 0; return;
    }
}

/* Does the native format already equal the wire format? */
static int native_is_wire(void)
{
    switch (cap.wire_bpp) {
    case 15: return cap.pixfmt == PIXFMT_RGB15PC;
    case 16: return cap.pixfmt == PIXFMT_RGB16PC;
    case 24: return cap.pixfmt == PIXFMT_BGR24;
    case 32: return cap.pixfmt == PIXFMT_BGRA32;
    }
    return 0;
}

/* Convert one tile of the shadow into the wire framebuffer. */
static void convert_tile(int tx, int ty)
{
    int x0 = tx * TILE, y0 = ty * TILE, x1 = x0 + TILE, y1 = y0 + TILE, x, y;
    int direct = native_is_wire();

    if (x1 > cap.w) x1 = cap.w;
    if (y1 > cap.h) y1 = cap.h;
    for (y = y0; y < y1; y++) {
        uint8_t *d = cap.wire + ((size_t)y * cap.w + x0) * cap.wire_bytes;
        /* shadow rows have pitch w * 4; pixels in them are src_bytes wide */
        const uint8_t *s = cap.shadow + (size_t)y * cap.w * 4 + (size_t)x0 * cap.src_bytes;
        int n = (y < cap.sh ? (x1 < cap.sw ? x1 : cap.sw) : x0) - x0;   /* pixels on screen */

        if (n < 0)
            n = 0;
        if (direct) {
            memcpy(d, s, (size_t)n * cap.wire_bytes);
            memset(d + n * cap.wire_bytes, 0, (size_t)(x1 - x0 - n) * cap.wire_bytes);
            continue;
        }
        for (x = 0; x < x1 - x0; x++, s += cap.src_bytes, d += cap.wire_bytes) {
            uint8_t rgb[3];
            unsigned v;
            if (x < n)
                unpack(s, rgb);
            else
                rgb[0] = rgb[1] = rgb[2] = 0;
            switch (cap.wire_bpp) {
            case 15:
                v = ((rgb[0] >> 3) << 10) | ((rgb[1] >> 3) << 5) | (rgb[2] >> 3);
                d[0] = (uint8_t)v; d[1] = (uint8_t)(v >> 8);
                break;
            case 16:
                v = ((rgb[0] >> 3) << 11) | ((rgb[1] >> 2) << 5) | (rgb[2] >> 3);
                d[0] = (uint8_t)v; d[1] = (uint8_t)(v >> 8);
                break;
            case 24:
                d[0] = rgb[2]; d[1] = rgb[1]; d[2] = rgb[0];
                break;
            default:
                d[0] = rgb[2]; d[1] = rgb[1]; d[2] = rgb[0]; d[3] = 0xff;
                break;
            }
        }
    }
}

/*
 * Compare `rows` source rows (at src, src_pitch bytes apart, sw pixels
 * wide) with the shadow starting at row y; copy changes into the shadow
 * and flag changed tile columns.
 */
/* scan.c copy hook: exec's CopyMemQuick() when aligned (on 040/060
 * systems it is usually patched to use move16, the fastest way to read VRAM). */
static void fast_copy(uint8_t *dst, const uint8_t *src, size_t n)
{
    if (!(((ULONG)dst | (ULONG)src | (ULONG)n) & 3))
        CopyMemQuick((APTR)src, dst, n);
    else
        memcpy(dst, src, n);
}

#define CAPTURE_RESIZE (-2)     /* capture(): the front screen changed size */
static int resize_w, resize_h;  /* its new size, for the caller */

/*
 * Poll the front screen once. Returns the number of tiles marked dirty, or
 * CAPTURE_RESIZE if the front screen now has a different size (the caller
 * resizes the session; the next poll then captures it).
 *
 * The shadow is stored with a pitch of w * 4 bytes whatever the pixel
 * size, so a screen switch never needs a reallocation.
 */
static int capture(rdp_session *sess)
{
    struct Screen *s = front_screen();
    int ty, tx, ntx = (cap.w + TILE - 1) / TILE, nty = (cap.h + TILE - 1) / TILE, dirty = 0;
    uint8_t changed[64];

    if (s != cap.scr) {
        if (!s)
            return 0;
        if ((s->Width & ~3) != cap.w || s->Height != cap.h) {
            resize_w = s->Width & ~3;
            resize_h = s->Height;
            return CAPTURE_RESIZE;
        }
        if (attach_screen(s))
            return 0;
    }
    if (cap.pixfmt == PIXFMT_LUT8 && update_palette())
        cap.force = 1;

    for (ty = 0; ty < nty; ty++) {
        int y = ty * TILE, rows = cap.sh - y < TILE ? cap.sh - y : TILE;

        memset(changed, cap.force, sizeof(changed));
        if (rows > 0) {
            if (cap.rtg) {
                APTR base = NULL;
                ULONG bpr = 0;
                /* Hold Intuition's lock so the screen cannot close while
                 * we read its bitmap; keep it to one band at a time. */
                ULONG ilock = LockIBase(0);
                APTR h = NULL;
                if (IntuitionBase->FirstScreen == cap.scr)
                    h = LockBitMapTags(cap.scr->RastPort.BitMap,
                                       LBMI_BASEADDRESS, (ULONG)&base,
                                       LBMI_BYTESPERROW, (ULONG)&bpr, TAG_DONE);
                if (h) {
                    scan_band(&cap.sc, (const uint8_t *)base + (size_t)y * bpr, (long)bpr,
                              y, rows, changed);
                    UnLockBitMap(h);
                }
                UnlockIBase(ilock);
                if (!h)
                    return dirty;   /* screen changed under us; retry next poll */
            } else {
                ULONG ilock = LockIBase(0);
                int ok = IntuitionBase->FirstScreen == cap.scr;
                if (ok)
                    ReadPixelArray8(&cap.rp, 0, (ULONG)y, (ULONG)cap.sw - 1,
                                    (ULONG)(y + rows - 1), cap.band, &cap.temprp);
                UnlockIBase(ilock);
                if (!ok)
                    return dirty;
                scan_band_full(&cap.sc, cap.band, ((cap.sw + 15) >> 4) << 4, y, rows, changed);
            }
        }
        for (tx = 0; tx < ntx; tx++) {
            if (changed[tx]) {
                convert_tile(tx, ty);
                rdp_mark_dirty(sess, tx * TILE, y, TILE, TILE);
                dirty++;
            }
        }
    }
    cap.force = 0;
    scan_next_poll(&cap.sc);                    /* sample other rows next time */
    cap.read_kb += cap.sc.read_bytes >> 10;
    cap.sc.read_bytes &= 1023;
    return dirty;
}

static int capture_init(int w, int h, int bpp)
{
    memset(&cap, 0, sizeof(cap));
    cap.w = w; cap.h = h;
    cap.wire_bpp = bpp;
    cap.wire_bytes = (bpp + 7) / 8;
    if (w > TILE * 64)
        return -1;
    cap.shadow = AllocVec((ULONG)w * h * 4, MEMF_ANY | MEMF_CLEAR);
    cap.wire = AllocVec((ULONG)w * h * cap.wire_bytes, MEMF_ANY | MEMF_CLEAR);
    cap.band = AllocVec((ULONG)(((w + 15) >> 4) << 4) * TILE, MEMF_ANY);
    cap.sc.shadow = cap.shadow;
    cap.sc.shadow_pitch = (size_t)w * 4;
    cap.sc.step = (int)opt.scan;
    cap.sc.copy = fast_copy;
    return cap.shadow && cap.wire && cap.band ? 0 : -1;
}

static void capture_free(void)
{
    free_native_reader();
    if (cap.shadow) FreeVec(cap.shadow);
    if (cap.wire) FreeVec(cap.wire);
    if (cap.band) FreeVec(cap.band);
    memset(&cap, 0, sizeof(cap));
}

/* ------------------------------------------------------------------ */
/* Input injection                                                    */
/* ------------------------------------------------------------------ */

static struct MsgPort *in_port;
static struct IOStdReq *in_req;

static UWORD kbd_qual;          /* shift/ctrl/alt/amiga/caps qualifiers */
static UWORD btn_qual;          /* mouse button qualifiers */
static UBYTE key_down[128];
static UBYTE prev1_code, prev1_qual, prev2_code, prev2_qual;
static int caps_on;

static void inject(struct InputEvent *ie)
{
    ULONG secs, micros;

    CurrentTime(&secs, &micros);
    ie->ie_NextEvent = NULL;
    ie->ie_TimeStamp.tv_secs = secs;
    ie->ie_TimeStamp.tv_micro = micros;
    in_req->io_Command = IND_WRITEEVENT;
    in_req->io_Data = ie;
    in_req->io_Length = sizeof(*ie);
    DoIO((struct IORequest *)in_req);
    stir(&micros, sizeof(micros));      /* input timing feeds the entropy pool */
}

static void send_rawkey(UWORD code, UWORD extra_qual)
{
    struct InputEvent ie;

    memset(&ie, 0, sizeof(ie));
    ie.ie_Class = IECLASS_RAWKEY;
    ie.ie_Code = code;
    ie.ie_Qualifier = kbd_qual | btn_qual | extra_qual;
    /* previous key-downs, for dead keys */
    ie.ie_position.ie_dead.ie_prev1DownCode = prev1_code;
    ie.ie_position.ie_dead.ie_prev1DownQual = prev1_qual;
    ie.ie_position.ie_dead.ie_prev2DownCode = prev2_code;
    ie.ie_position.ie_dead.ie_prev2DownQual = prev2_qual;
    inject(&ie);
    if (!(code & IECODE_UP_PREFIX)) {
        prev2_code = prev1_code; prev2_qual = prev1_qual;
        prev1_code = (UBYTE)code; prev1_qual = (UBYTE)ie.ie_Qualifier;
    }
}

static UWORD modifier_qual(unsigned raw)
{
    switch (raw) {
    case 0x60: return IEQUALIFIER_LSHIFT;
    case 0x61: return IEQUALIFIER_RSHIFT;
    case 0x63: return IEQUALIFIER_CONTROL;
    case 0x64: return IEQUALIFIER_LALT;
    case 0x65: return IEQUALIFIER_RALT;
    case 0x66: return IEQUALIFIER_LCOMMAND;
    case 0x67: return IEQUALIFIER_RCOMMAND;
    }
    return 0;
}

static void set_caps(int on)
{
    if (on == caps_on)
        return;
    caps_on = on;
    if (on)
        kbd_qual |= IEQUALIFIER_CAPSLOCK;
    else
        kbd_qual &= ~IEQUALIFIER_CAPSLOCK;
    /* The Amiga Caps Lock key reports down when it locks, up when it unlocks. */
    send_rawkey(on ? 0x62 : 0x62 | IECODE_UP_PREFIX, 0);
}

static void on_key(void *ctx, unsigned flags, unsigned scancode)
{
    int release = (flags & RDP_KBD_RELEASE) != 0;
    unsigned raw;
    UWORD q, extra = 0;

    (void)ctx;
    if (scancode >= 128 || (flags & RDP_KBD_EXTENDED1))
        return;
    raw = (flags & RDP_KBD_EXTENDED) ? pc_ext_to_amiga[scancode] : pc_to_amiga[scancode];
    if (raw == RK_NONE)
        return;
    if (opt.verbose)
        printf("key 0x%02x%s -> raw 0x%02x %s\n", scancode,
               flags & RDP_KBD_EXTENDED ? " (ext)" : "", raw, release ? "up" : "down");
    if (raw == 0x62) {                  /* Caps Lock toggles on press */
        if (!release)
            set_caps(!caps_on);
        return;
    }
    q = modifier_qual(raw);
    if (amiga_is_keypad(raw))
        extra |= IEQUALIFIER_NUMERICPAD;
    if (release) {
        kbd_qual &= ~q;
        key_down[raw] = 0;
        send_rawkey((UWORD)(raw | IECODE_UP_PREFIX), extra);
    } else {
        if (key_down[raw])
            extra |= IEQUALIFIER_REPEAT;
        key_down[raw] = 1;
        kbd_qual |= q;
        send_rawkey((UWORD)raw, extra);
    }
}

static void on_sync(void *ctx, unsigned toggles)
{
    (void)ctx;
    set_caps((toggles & 0x04) != 0);    /* TS_SYNC_CAPS_LOCK */
}

static void mouse_button(UWORD code, UWORD qual, int down)
{
    struct InputEvent ie;

    if (down)
        btn_qual |= qual;
    else
        btn_qual &= ~qual;
    memset(&ie, 0, sizeof(ie));
    ie.ie_Class = IECLASS_RAWMOUSE;
    ie.ie_Code = down ? code : code | IECODE_UP_PREFIX;
    ie.ie_Qualifier = kbd_qual | btn_qual | IEQUALIFIER_RELATIVEMOUSE;
    inject(&ie);
}

static void wheel(int up, int clicks)
{
    struct InputEvent ie;
    UWORD code = up ? 0x7a : 0x7b;      /* NM_WHEEL_UP / NM_WHEEL_DOWN */

    while (clicks-- > 0) {
        memset(&ie, 0, sizeof(ie));
        ie.ie_Qualifier = kbd_qual | btn_qual;
        /* NewMouse convention: raw key and IECLASS_NEWMOUSE, down + up */
        ie.ie_Class = IECLASS_RAWKEY;
        ie.ie_Code = code;
        inject(&ie);
        ie.ie_Code = code | IECODE_UP_PREFIX;
        inject(&ie);
        ie.ie_Class = IECLASS_NEWMOUSE;
        ie.ie_Code = code;
        inject(&ie);
        ie.ie_Code = code | IECODE_UP_PREFIX;
        inject(&ie);
    }
}

static void on_mouse(void *ctx, unsigned flags, unsigned x, unsigned y)
{
    int down = (flags & RDP_PTR_DOWN) != 0;

    (void)ctx;
    if (flags & RDP_PTR_WHEEL) {
        /* rotation in the low 9 bits, sign in WHEEL_NEGATIVE; 120 per notch */
        int amount = flags & 0x1ff;
        if (flags & RDP_PTR_WHEEL_NEG)
            amount = 0x200 - amount;
        wheel(!(flags & RDP_PTR_WHEEL_NEG), (amount + 60) / 120 ? (amount + 60) / 120 : 1);
        return;
    }
    if (cap.scr) {
        struct InputEvent ie;
        struct IEPointerPixel pp;

        if (x >= (unsigned)cap.sw) x = cap.sw - 1;
        if (y >= (unsigned)cap.sh) y = cap.sh - 1;
        memset(&ie, 0, sizeof(ie));
        pp.iepp_Screen = cap.scr;
        pp.iepp_Position.X = (WORD)x;
        pp.iepp_Position.Y = (WORD)y;
        ie.ie_Class = IECLASS_NEWPOINTERPOS;
        ie.ie_SubClass = IESUBCLASS_PIXEL;
        ie.ie_EventAddress = &pp;
        ie.ie_Qualifier = kbd_qual | btn_qual;
        inject(&ie);
    }
    if (flags & RDP_PTR_BUTTON1)
        mouse_button(IECODE_LBUTTON, IEQUALIFIER_LEFTBUTTON, down);
    if (flags & RDP_PTR_BUTTON2)
        mouse_button(IECODE_RBUTTON, IEQUALIFIER_RBUTTON, down);
    if (flags & RDP_PTR_BUTTON3)
        mouse_button(IECODE_MBUTTON, IEQUALIFIER_MIDBUTTON, down);
}

/* Release anything still held when a client goes away. */
static void release_all(void)
{
    unsigned k;

    for (k = 0; k < 128; k++) {
        if (key_down[k]) {
            key_down[k] = 0;
            kbd_qual &= ~modifier_qual(k);
            send_rawkey((UWORD)(k | IECODE_UP_PREFIX), 0);
        }
    }
    if (btn_qual & IEQUALIFIER_LEFTBUTTON) mouse_button(IECODE_LBUTTON, IEQUALIFIER_LEFTBUTTON, 0);
    if (btn_qual & IEQUALIFIER_RBUTTON) mouse_button(IECODE_RBUTTON, IEQUALIFIER_RBUTTON, 0);
    if (btn_qual & IEQUALIFIER_MIDBUTTON) mouse_button(IECODE_MBUTTON, IEQUALIFIER_MIDBUTTON, 0);
}

static int input_open(void)
{
    in_port = CreateMsgPort();
    if (!in_port)
        return -1;
    in_req = (struct IOStdReq *)CreateIORequest(in_port, sizeof(struct IOStdReq));
    if (!in_req)
        return -1;
    if (OpenDevice("input.device", 0, (struct IORequest *)in_req, 0)) {
        DeleteIORequest((struct IORequest *)in_req);
        in_req = NULL;
        return -1;
    }
    /* Caps Lock state arrives in the client's first sync event. */
    return 0;
}

static void input_close(void)
{
    if (in_req) {
        CloseDevice((struct IORequest *)in_req);
        DeleteIORequest((struct IORequest *)in_req);
    }
    if (in_port)
        DeleteMsgPort(in_port);
}

/* ------------------------------------------------------------------ */
/* Clipboard (clipboard.device unit 0, IFF FTXT)                      */
/* ------------------------------------------------------------------ */

#define CLIP_MAX (512 * 1024)

static struct MsgPort *clip_port;
static struct IOClipReq *clip_req;
static LONG clip_seen_id;       /* clip last offered to, or taken from, Windows */
static char *clip_text;         /* text handed to the RDP core by clip_get */

static int clip_open(void)
{
    clip_port = CreateMsgPort();
    if (!clip_port)
        return -1;
    clip_req = (struct IOClipReq *)CreateIORequest(clip_port, sizeof(struct IOClipReq));
    if (!clip_req)
        return -1;
    if (OpenDevice((STRPTR)"clipboard.device", PRIMARY_CLIP, (struct IORequest *)clip_req, 0)) {
        DeleteIORequest((struct IORequest *)clip_req);
        clip_req = NULL;
        return -1;
    }
    return 0;
}

static void clip_close(void)
{
    if (clip_req) {
        CloseDevice((struct IORequest *)clip_req);
        DeleteIORequest((struct IORequest *)clip_req);
    }
    if (clip_port)
        DeleteMsgPort(clip_port);
    if (clip_text)
        FreeVec(clip_text);
}

static LONG clip_current_id(void)
{
    clip_req->io_Command = CBD_CURRENTREADID;
    clip_req->io_ClipID = 0;
    DoIO((struct IORequest *)clip_req);
    return clip_req->io_ClipID;
}

/* Read the current clip's text (Latin-1). Returns its length or -1. */
static long clip_get(void *ctx, const char **text)
{
    UBYTE *raw = AllocVec(CLIP_MAX, MEMF_ANY), scratch[256];
    ULONG n = 0;
    long len = -1;

    (void)ctx;
    if (clip_text) {
        FreeVec(clip_text);
        clip_text = NULL;
    }
    clip_req->io_Offset = 0;
    clip_req->io_ClipID = 0;
    clip_req->io_Error = 0;
    /* Keep reading until 0 bytes come back: that ends the read and
     * releases the clip, even if our buffer is already full. */
    do {
        clip_req->io_Command = CMD_READ;
        if (raw && n < CLIP_MAX) {
            clip_req->io_Data = (STRPTR)(raw + n);
            clip_req->io_Length = CLIP_MAX - n;
        } else {
            clip_req->io_Data = (STRPTR)scratch;
            clip_req->io_Length = sizeof(scratch);
        }
        if (DoIO((struct IORequest *)clip_req))
            break;
        if (raw && n < CLIP_MAX)
            n += clip_req->io_Actual;
    } while (clip_req->io_Actual > 0);

    if (raw && n > 0) {
        clip_text = AllocVec(n + 1, MEMF_ANY);
        if (clip_text) {
            len = ftxt_parse(raw, n, clip_text, n);
            if (len >= 0)
                clip_text[len] = 0;
        }
    }
    if (raw)
        FreeVec(raw);
    *text = clip_text;
    return clip_text ? len : -1;
}

/* Put text from Windows into the Amiga clipboard. */
static void clip_set(void *ctx, const char *text, size_t len)
{
    ULONG size = ftxt_size(len);
    UBYTE *iff = AllocVec(size, MEMF_ANY);

    (void)ctx;
    if (!iff)
        return;
    ftxt_build(text, len, iff);
    clip_req->io_Offset = 0;
    clip_req->io_ClipID = 0;
    clip_req->io_Error = 0;
    clip_req->io_Command = CMD_WRITE;
    clip_req->io_Data = (STRPTR)iff;
    clip_req->io_Length = size;
    DoIO((struct IORequest *)clip_req);
    clip_req->io_Command = CMD_UPDATE;
    DoIO((struct IORequest *)clip_req);
    clip_seen_id = clip_req->io_ClipID;     /* don't offer it straight back */
    FreeVec(iff);
    if (opt.verbose)
        printf("clipboard: %lu characters from Windows\n", (unsigned long)len);
}

/* Offer the Amiga clipboard to Windows if something new was copied. */
static void clip_poll(rdp_session *sess)
{
    LONG id;

    if (!clip_req)
        return;
    id = clip_current_id();
    if (id != clip_seen_id) {
        clip_seen_id = id;
        rdp_clipboard_changed(sess);
    }
}

/* ------------------------------------------------------------------ */
/* Sessions                                                           */
/* ------------------------------------------------------------------ */

/* Returns 1 if Ctrl-C was pressed, 2 after a failed login. */
static int serve(LONG fd)
{
    rdp_config cfg;
    rdp_callbacks cb;
    rdp_session *sess;
    struct Screen *s = front_screen();
    ULONG last_poll = 0;        /* end of the previous screen poll (now_ms) */
    int polled = 0;             /* any poll yet this session? */
    int quit = 0;

    if (!s)
        return 0;
    memset(&cfg, 0, sizeof(cfg));
    memset(&cb, 0, sizeof(cb));
    cfg.width = s->Width & ~3;
    cfg.height = s->Height;
    cfg.bpp = (int)opt.bpp;
    cfg.fb_wire = 1;
    cfg.neg_fail = opt.negfail;
    cfg.verbose = opt.verbose;
    cfg.password = opt.password;
    cfg.no_compress = opt.nocompress;
    if (capture_init(cfg.width, cfg.height, cfg.bpp)) {
        printf("out of memory for a %dx%d screen\n", cfg.width, cfg.height);
        capture_free();
        return 0;
    }
    cfg.fb = cap.wire;

    cb.ctx = &fd;
    cb.send = net_send;
    cb.recv = net_recv;
    cb.random = get_random;
    cb.log = log_msg;
    cb.key = on_key;
    cb.mouse = on_mouse;
    cb.sync = on_sync;
    if (clip_req) {
        cb.clip_get = clip_get;
        cb.clip_set = clip_set;
    }
    sess = rdp_session_new(&cfg, &cb);
    if (!sess) {
        capture_free();
        return 0;
    }
    SetSignal(0, beep_sig);             /* forget beeps from before this session */
    if (clip_req) {                     /* offer what is on the clipboard now */
        clip_seen_id = clip_current_id();
        if (clip_seen_id > 0)
            rdp_clipboard_changed(sess);
    }

    for (;;) {
        fd_set rfds;
        struct __timeval tv;
        /*
         * now_ms() wraps (it is days * 86400000 in 32 bits), so only ever
         * look at differences, as unsigned: a signed comparison against an
         * absolute time is wrong whenever the clock value has its top bit
         * set, which in 2026 is the case all day.
         */
        ULONG sigs = SIGBREAKF_CTRL_C | beep_sig, elapsed = now_ms() - last_poll;
        LONG wait_ms = 1000, n;

        if (rdp_session_active(sess))
            wait_ms = !polled || elapsed >= (ULONG)opt.interval ? 0
                                                                 : (LONG)((ULONG)opt.interval - elapsed);
        tv.tv_sec = wait_ms / 1000;
        tv.tv_usec = (wait_ms % 1000) * 1000;
        FD_ZERO(&rfds);
        FD_SET(fd, &rfds);
        n = WaitSelect(fd + 1, &rfds, NULL, NULL, &tv, &sigs);
        if (n < 0)
            break;
        if (sigs & SIGBREAKF_CTRL_C) {
            quit = 1;
            break;
        }
        if (n > 0 && FD_ISSET(fd, &rfds) && rdp_session_process(sess))
            break;
        if ((sigs & beep_sig) && rdp_beep(sess, 880, 150))  /* ignored before login */
            break;
        if (rdp_session_active(sess) &&
            (!polled || now_ms() - last_poll >= (ULONG)opt.interval)) {
            ULONG t0 = now_ms();
            int got = capture(sess);
            if (got == CAPTURE_RESIZE) {
                /* Screen switch to a different size: new buffers, and the
                 * client is told the new desktop size. */
                if (!opt.quiet) {
                    printf("front screen is now %dx%d: resizing the session\n", resize_w, resize_h);
                    fflush(stdout);
                }
                capture_free();
                if (capture_init(resize_w, resize_h, (int)opt.bpp) ||
                    rdp_session_resize(sess, resize_w, resize_h, cap.wire, 0)) {
                    printf("resize failed (out of memory?)\n");
                    break;
                }
                polled = 0;             /* capture as soon as the client is back */
                continue;
            }
            /* the interval runs from the end of this poll, so a slow
             * capture never eats all the CPU */
            last_poll = now_ms();
            cap.polls++;
            cap.poll_ms += last_poll - t0;
            clip_poll(sess);
            polled = 1;
        }
        if (rdp_flush(sess))
            break;
    }
    if (cap.polls && !opt.quiet)
        printf("screen polls: %lu, average %lu ms each (20 ms resolution), "
               "%lu KB read per poll, SCAN=%ld\n", (unsigned long)cap.polls,
               (unsigned long)(cap.poll_ms / cap.polls),
               (unsigned long)(cap.read_kb / cap.polls), (long)opt.scan);
    release_all();
    if (!quit && rdp_session_auth_failed(sess))
        quit = 2;
    rdp_session_free(sess);
    capture_free();
    return quit;
}

/* ------------------------------------------------------------------ */
/* Workbench start                                                    */
/* ------------------------------------------------------------------ */

extern struct WBStartup *_WBenchMsg;    /* set by libnix when started from Workbench */

/*
 * Started from Workbench: the program icon's tool types, as a ReadArgs()
 * source (see tooltypes.c), so they are checked like Shell arguments.
 * Returns NULL if out of memory; free with wb_args_free().
 */
static struct RDArgs *wb_args(char **line)
{
    static const char *const none[] = { NULL };
    struct WBArg *arg = _WBenchMsg->sm_ArgList;     /* the program's own icon */
    struct DiskObject *dob;
    struct RDArgs *src;
    BPTR old;

    old = CurrentDir(arg->wa_Lock);
    dob = GetDiskObject(arg->wa_Name);
    CurrentDir(old);
    *line = tooltypes_to_args(RDPSERVER_TEMPLATE, dob && dob->do_ToolTypes ?
                              (const char *const *)dob->do_ToolTypes : none);
    if (dob)
        FreeDiskObject(dob);
    src = AllocDosObject(DOS_RDARGS, NULL);
    if (!*line || !src) {
        free(*line);
        if (src)
            FreeDosObject(DOS_RDARGS, src);
        return NULL;
    }
    src->RDA_Source.CS_Buffer = (UBYTE *)*line;
    src->RDA_Source.CS_Length = strlen(*line);
    src->RDA_Source.CS_CurChr = 0;
    src->RDA_Flags |= RDAF_NOPROMPT;
    return src;
}

static void wb_args_free(struct RDArgs *src, char *line)
{
    if (src)
        FreeDosObject(DOS_RDARGS, src);
    free(line);
}

int main(void)
{
    LONG args[13] = { 0 };
    int newkey;
    struct RDArgs *rda, *src = NULL;
    char *line = NULL;
    const char *pw_from;
    LONG lfd = -1;
    struct sockaddr_in addr;
    LONG one = 1;
    int rc = RETURN_FAIL;

    if (_WBenchMsg && !(src = wb_args(&line))) {
        printf("RDPServer: out of memory\n");
        return RETURN_FAIL;
    }
    rda = ReadArgs((STRPTR)RDPSERVER_TEMPLATE, args, src);
    if (!rda) {
        char msg[100];
        Fault(IoErr(), (STRPTR)(src ? "RDPServer tool types" : "RDPServer"), (STRPTR)msg, sizeof(msg));
        printf("%s\n", msg);
        wb_args_free(src, line);
        return RETURN_FAIL;
    }
    if (args[0]) opt.port = *(LONG *)args[0];
    if (args[1]) opt.bpp = *(LONG *)args[1];
    if (args[2]) opt.interval = *(LONG *)args[2];
    opt.negfail = args[3] != 0;
    opt.verbose = args[4] != 0;
    opt.nocompress = args[7] != 0;
    opt.noclipboard = args[8] != 0;
    opt.nobeep = args[9] != 0;
    opt.quiet = args[12] != 0;
    if (args[10]) opt.scan = *(LONG *)args[10];
    if (opt.scan < 1) opt.scan = 1;
    if (opt.scan > 16) opt.scan = 16;
    newkey = args[11] != 0;
    pw_from = args[5] ? (src ? "the PASSWORD tool type" : "PASSWORD=") : "ENV:RDPServer/Password";
    if (args[5])
        strncpy(opt.password, (const char *)args[5], sizeof(opt.password) - 1);
    else if (!args[6] &&
             GetVar((STRPTR)"RDPServer/Password", (STRPTR)opt.password,
                    sizeof(opt.password), GVF_GLOBAL_ONLY) < 0)
        opt.password[0] = 0;
    FreeArgs(rda);
    wb_args_free(src, line);
    if (!opt.password[0] && !args[6]) {
        printf("No password: give PASSWORD=..., put one in ENV:RDPServer/Password,\n"
               "or use NOPASSWORD to let anyone who can connect control this Amiga.\n");
        return RETURN_FAIL;
    }
    if (args[6])
        opt.password[0] = 0;
    if (opt.verbose && opt.password[0])     /* where it came from, not what it is */
        printf("Password: %lu characters, from %s%s\n", (unsigned long)strlen(opt.password), pw_from,
               strpbrk(opt.password, "\" \t") ? " (contains a space or quote)" : "");
    if (opt.bpp != 15 && opt.bpp != 16 && opt.bpp != 24 && opt.bpp != 32) {
        printf("BPP must be 15, 16, 24 or 32\n");
        return RETURN_FAIL;
    }
    if (opt.interval < 20)
        opt.interval = 20;

    SocketBase = OpenLibrary((STRPTR)"bsdsocket.library", 4);
    if (!SocketBase) {
        printf("bsdsocket.library not found (is Roadshow running?)\n");
        return RETURN_FAIL;
    }
    RdpCyberGfxBase = OpenLibrary((STRPTR)"cybergraphics.library", 40);
    if (!RdpCyberGfxBase)
        printf("cybergraphics.library not found: native screens only\n");
    if (input_open()) {
        printf("cannot open input.device\n");
        goto out;
    }
    if (!opt.nobeep) {
        BYTE bit = AllocSignal(-1);
        if (bit >= 0) {
            beep_sig = 1UL << bit;
            if (beep_install(beep_sig)) {
                FreeSignal(bit);
                beep_sig = 0;
            }
        }
        if (!beep_sig)
            printf("cannot patch DisplayBeep(): beeps will not be forwarded\n");
    }
    if (!opt.noclipboard && clip_open()) {
        printf("clipboard.device not available: clipboard sharing off\n");
        clip_close();
        clip_req = NULL;
        clip_port = NULL;
    }
    stir(&addr, sizeof(addr));          /* seed the pool */
    if (setup_key(newkey))
        goto out;

    lfd = socket(AF_INET, SOCK_STREAM, 0);
    if (lfd < 0)
        goto out;
    setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((UWORD)opt.port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    if (bind(lfd, (struct sockaddr *)&addr, sizeof(addr)) || listen(lfd, 2)) {
        printf("cannot listen on port %ld (error %ld)\n", (long)opt.port, (long)Errno());
        goto out;
    }
    if (!opt.quiet) {
        printf("RDPServer listening on port %ld, %ld bpp, polling every %ld ms, %s. Ctrl-C to quit.\n",
               (long)opt.port, (long)opt.bpp, (long)opt.interval,
               opt.password[0] ? "password required" : "NO PASSWORD");
        fflush(stdout);
    }

    for (;;) {
        fd_set rfds;
        ULONG sigs = SIGBREAKF_CTRL_C;
        struct sockaddr_in peer;
        socklen_t plen = sizeof(peer);
        LONG fd;

        FD_ZERO(&rfds);
        FD_SET(lfd, &rfds);
        if (WaitSelect(lfd + 1, &rfds, NULL, NULL, NULL, &sigs) < 0)
            break;
        if (sigs & SIGBREAKF_CTRL_C)
            break;
        if (!FD_ISSET(lfd, &rfds))
            continue;
        fd = accept(lfd, (struct sockaddr *)&peer, &plen);
        if (fd < 0)
            continue;
        setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
        if (!opt.quiet) {
            printf("=== connection from %s\n", Inet_NtoA(peer.sin_addr.s_addr));
            fflush(stdout);
        }
        stir(&peer, sizeof(peer));
        switch (serve(fd)) {
        case 1:                         /* Ctrl-C */
            CloseSocket(fd);
            goto quit;
        case 2:                         /* wrong passwords: slow down guessing */
            CloseSocket(fd);
            printf("=== connection closed after wrong passwords; pausing\n");
            fflush(stdout);
            Delay(2 * TICKS_PER_SECOND);
            continue;
        }
        CloseSocket(fd);
        if (!opt.quiet) {
            printf("=== connection closed\n");
            fflush(stdout);
        }
    }
quit:
    rc = RETURN_OK;
out:
    if (lfd >= 0)
        CloseSocket(lfd);
    input_close();
    clip_close();
    if (beep_sig) {
        BYTE bit;
        beep_remove();
        for (bit = 0; bit < 32 && !(beep_sig & (1UL << bit)); bit++)
            ;
        FreeSignal(bit);
    }
    if (RdpCyberGfxBase)
        CloseLibrary(RdpCyberGfxBase);
    CloseLibrary(SocketBase);
    memset(opt.password, 0, sizeof(opt.password));
    return rc;
}
