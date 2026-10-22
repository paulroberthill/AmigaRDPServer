/* Unit test for src/amiga/scan.c (natively and under vamos). */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../src/amiga/scan.h"

#ifdef __amigaos__
unsigned long __stack = 65536;
#endif

#define W 200
#define H 150
#define TX ((W + SCAN_TILE - 1) / SCAN_TILE)
#define TY ((H + SCAN_TILE - 1) / SCAN_TILE)

static uint8_t fb[H][W * 4], shadow[H][W * 4];
static unsigned long seed = 99;
static int rnd(int n) { seed = seed * 1103515245ul + 12345ul; return (int)((seed >> 16) % (unsigned long)n); }

static int fails;
static void check(int ok, const char *what, int bpp, int step)
{
    if (!ok) {
        printf("FAIL %s (bytes/pixel %d, step %d)\n", what, bpp, step);
        fails++;
    }
}

/* One poll over all bands; flags[] collects tiles reported changed. */
static void poll(scan_ctx *c, uint8_t flags[TY][TX], int force)
{
    int ty;
    for (ty = 0; ty < TY; ty++) {
        int y = ty * SCAN_TILE, rows = H - y < SCAN_TILE ? H - y : SCAN_TILE;
        uint8_t changed[TX];
        memset(changed, force, sizeof(changed));
        scan_band(c, &fb[y][0], sizeof(fb[0]), y, rows, changed);
        for (int tx = 0; tx < TX; tx++)
            flags[ty][tx] |= changed[tx];
    }
    scan_next_poll(c);
}

static int same(int bpp)
{
    for (int y = 0; y < H; y++)
        if (memcmp(fb[y], shadow[y], (size_t)W * bpp))
            return 0;
    return 1;
}

int main(void)
{
    static const int steps[] = { 1, 2, 4, 7 };
    int bpp, si, iter;

    for (bpp = 1; bpp <= 4; bpp++)
        for (si = 0; si < 4; si++) {
            scan_ctx c;
            uint8_t flags[TY][TX];
            int step = steps[si];

            memset(&c, 0, sizeof(c));
            c.shadow = &shadow[0][0];
            c.shadow_pitch = sizeof(shadow[0]);
            c.width = W;
            c.bytes_pp = bpp;
            c.step = step;
            for (int y = 0; y < H; y++)
                for (int x = 0; x < W * 4; x++)
                    fb[y][x] = (uint8_t)rnd(256);
            memset(shadow, 0, sizeof(shadow));
            memset(flags, 0, sizeof(flags));
            poll(&c, flags, 1);
            check(same(bpp), "forced first poll copies everything", bpp, step);

            /* static screen: about 1/step of it is read */
            c.read_bytes = 0;
            for (int i = 0; i < step; i++)
                poll(&c, flags, 0);
            check(c.read_bytes == (unsigned long)W * bpp * H, "static screen: each row read once per step polls",
                  bpp, step);

            for (iter = 0; iter < 200; iter++) {
                /* a random rectangle: sometimes one pixel, sometimes tall */
                int x = rnd(W), y = rnd(H), w = 1 + rnd(iter % 3 ? 3 : 80), h = 1 + rnd(iter % 2 ? 2 : 90);
                if (x + w > W) w = W - x;
                if (y + h > H) h = H - y;
                for (int yy = y; yy < y + h; yy++)
                    for (int xx = x * bpp; xx < (x + w) * bpp; xx++)
                        fb[yy][xx] ^= (uint8_t)(1 + rnd(255));

                memset(flags, 0, sizeof(flags));
                poll(&c, flags, 0);
                if (h >= step) {    /* tall enough: a sampled row hits it at once */
                    int ok = 0;
                    for (int ty = y / SCAN_TILE; ty <= (y + h - 1) / SCAN_TILE; ty++)
                        for (int tx = x / SCAN_TILE; tx <= (x + w - 1) / SCAN_TILE; tx++)
                            ok |= flags[ty][tx];
                    check(ok, "change of >= step rows seen on the next poll", bpp, step);
                }
                for (int i = 1; i < step; i++)
                    poll(&c, flags, 0);
                /* within step polls every row has been sampled: every tile of
                 * the rectangle (all of them really changed) must be flagged */
                for (int ty = y / SCAN_TILE; ty <= (y + h - 1) / SCAN_TILE; ty++)
                    for (int tx = x / SCAN_TILE; tx <= (x + w - 1) / SCAN_TILE; tx++)
                        check(flags[ty][tx], "every changed tile flagged within step polls", bpp, step);
                check(same(bpp), "shadow matches the screen after step polls", bpp, step);
            }
        }
    printf(fails ? "%d FAILED\n" : "all passed\n", fails);
    return fails != 0;
}
