/*
 * Test host that runs the RDP core over two plain files instead of a TCP
 * socket, so the 68k build can be exercised under vamos (which has no
 * TCP/IP stack, and cannot open named pipes) by tests/testclient.py --files.
 *
 *   pipehost IN OUT [bpp] [wire] [pw=PASSWORD]
 *
 * The client appends client->server bytes to IN; this program appends
 * server->client bytes to OUT. Each side polls the other's file for more
 * data, like `tail -f`. With "wire", the
 * test pattern is converted to the wire pixel format and served with
 * fb_wire = 1 (the path the Amiga host uses for RTG screens).
 * Also builds natively on Linux.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#ifdef __amigaos__
#include <proto/dos.h>
#else
#include <fcntl.h>
#include <unistd.h>
#endif

#include "../src/rdp.h"
#include "../src/testpattern.h"

#ifdef __amigaos__
unsigned long __stack = 65536;          /* honoured by libnix */
#endif

#define W 640                   /* initial size; a middle click toggles 800x600 */
#define H 512
#define MAX_PIXELS (800 * 600)

static uint8_t *wire_fb;
static int wire_bpp;

#ifdef __amigaos__
/* vamos only flushes regular-file writes on DOS Flush(), so use DOS. */
static BPTR in_fh, out_fh;

static int open_files(const char *in, const char *out)
{
    in_fh = Open((STRPTR)in, MODE_OLDFILE);
    out_fh = Open((STRPTR)out, MODE_NEWFILE);
    return in_fh && out_fh ? 0 : -1;
}
static long file_read(uint8_t *p, size_t n) { return Read(in_fh, p, (LONG)n); }
static long file_write(const uint8_t *p, size_t n)
{
    LONG r = Write(out_fh, (APTR)p, (LONG)n);
    Flush(out_fh);
    return r;
}
static void idle(void) { Delay(1); }
#else
static int in_fd, out_fd;

static int open_files(const char *in, const char *out)
{
    in_fd = open(in, O_RDONLY);
    out_fd = open(out, O_WRONLY | O_TRUNC);
    return in_fd >= 0 && out_fd >= 0 ? 0 : -1;
}
static long file_read(uint8_t *p, size_t n) { return read(in_fd, p, n); }
static long file_write(const uint8_t *p, size_t n) { return write(out_fd, p, n); }
static void idle(void) { usleep(2000); }
#endif

static int p_send(void *ctx, const uint8_t *data, size_t len)
{
    (void)ctx;
    while (len) {
        long n = file_write(data, len);
        if (n <= 0)
            return -1;
        data += n; len -= (size_t)n;
    }
    return 0;
}

/* Reading at end of file means "no data yet": wait for the client. */
static int p_recv(void *ctx, uint8_t *data, size_t len)
{
    (void)ctx;
    while (len) {
        long n = file_read(data, len);
        if (n < 0)
            return -1;
        if (n == 0) {
            idle();
            continue;
        }
        data += n; len -= (size_t)n;
    }
    return 0;
}

static void p_random(void *ctx, uint8_t *out, size_t len)
{
    (void)ctx;
    while (len--)
        *out++ = (uint8_t)(rand() >> 7);
}

static void p_log(void *ctx, const char *msg)
{
    (void)ctx;
    printf("%s\n", msg);
    fflush(stdout);
}

/* Indexed test pattern -> wire format (what a real RTG capture would give). */
static void to_wire(void)
{
    const uint8_t *src = tp_fb(), *pal = tp_palette();
    int bpp = (wire_bpp + 7) / 8, i;

    for (i = 0; i < tp_width() * tp_height(); i++) {
        const uint8_t *c = pal + src[i] * 3;
        uint8_t *d = wire_fb + (size_t)i * bpp;
        unsigned v;
        switch (wire_bpp) {
        case 15:
            v = ((c[0] >> 3) << 10) | ((c[1] >> 3) << 5) | (c[2] >> 3);
            d[0] = (uint8_t)v; d[1] = (uint8_t)(v >> 8);
            break;
        case 16:
            v = ((c[0] >> 3) << 11) | ((c[1] >> 2) << 5) | (c[2] >> 3);
            d[0] = (uint8_t)v; d[1] = (uint8_t)(v >> 8);
            break;
        case 24:
            d[0] = c[2]; d[1] = c[1]; d[2] = c[0];
            break;
        case 32:
            d[0] = c[2]; d[1] = c[1]; d[2] = c[0]; d[3] = 0xff;
            break;
        }
    }
}

int main(int argc, char **argv)
{
    rdp_config cfg = { 0 };
    rdp_callbacks cb = { 0 };
    rdp_session *s;

    if (argc < 3) {
        fprintf(stderr, "usage: %s IN OUT [bpp] [wire]\n", argv[0]);
        return 2;
    }
    srand((unsigned)time(NULL));
    if (tp_init(W, H))
        return 1;
    cfg.width = W; cfg.height = H;
    cfg.bpp = argc > 3 ? atoi(argv[3]) : 16;
    cfg.fb = tp_fb(); cfg.palette = tp_palette();
    if (argc > 4 && !strncmp(argv[argc - 1], "pw=", 3))
        cfg.password = argv[--argc] + 3;
    if (argc > 4 && !strcmp(argv[4], "wire")) {
        wire_bpp = cfg.bpp;
        wire_fb = malloc((size_t)MAX_PIXELS * 4);
        if (!wire_fb || wire_bpp == 8)
            return 1;
        cfg.fb = wire_fb;
        cfg.fb_wire = 1;
    }

    if (open_files(argv[1], argv[2])) {
        fprintf(stderr, "cannot open %s / %s\n", argv[1], argv[2]);
        return 1;
    }
    printf("pipehost: %dx%d, %d bpp%s\n", W, H, cfg.bpp, cfg.fb_wire ? ", wire framebuffer" : "");
    fflush(stdout);

    cb.send = p_send; cb.recv = p_recv; cb.random = p_random; cb.log = p_log;
    tp_set_callbacks(&cb);
    s = rdp_session_new(&cfg, &cb);
    if (!s)
        return 1;
    tp_reset(s);
    rdp_clipboard_changed(s);
    if (wire_fb)
        to_wire();
    while (rdp_session_process(s) == 0) {
        int nw, nh;
        if (tp_resize_requested(&nw, &nh)) {
            if (tp_resize(nw, nh))
                break;
            if (wire_fb)
                to_wire();
            if (rdp_session_resize(s, nw, nh, wire_fb ? wire_fb : tp_fb(), 0))
                break;
        }
        if (wire_fb)
            to_wire();
        if (rdp_flush(s))
            break;
    }
    rdp_session_free(s);
    printf("pipehost: session ended\n");
    return 0;
}
