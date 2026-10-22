/*
 * Prints RLE-encoded test tiles for tests/test_rle.py, which decodes them
 * with the spec-derived decoder in testclient.py and compares:
 *   one line per tile: "w h bytes_per_pixel raw_hex compressed_hex"
 * (compressed_hex is "-" when the encoder declined, i.e. no saving).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../src/rle.h"

#ifdef __amigaos__
unsigned long __stack = 65536;
#endif

static uint32_t seed = 12345;
static unsigned rnd(void) { seed = seed * 1103515245u + 12345u; return (seed >> 16) & 0x7fff; }

static void hex(const uint8_t *p, size_t n)
{
    size_t i;
    for (i = 0; i < n; i++)
        printf("%02x", p[i]);
}

static void emit(const uint8_t *raw, int w, int h, int bpp)
{
    static uint8_t out[64 * 64 * 3];
    size_t raw_len = (size_t)w * h * bpp;
    size_t n = rle_encode(raw, w, h, bpp, out, raw_len);

    printf("%d %d %d ", w, h, bpp);
    hex(raw, raw_len);
    printf(" ");
    if (n)
        hex(out, n);
    else
        printf("-");
    printf("\n");
}

int main(void)
{
    static uint8_t raw[64 * 64 * 3];
    static const int sizes[][2] = { {64, 64}, {4, 1}, {4, 64}, {64, 1}, {8, 3}, {60, 40}, {12, 33} };
    int bpp, si, pat;

    for (bpp = 1; bpp <= 3; bpp++)
        for (si = 0; si < (int)(sizeof(sizes) / sizeof(sizes[0])); si++)
            for (pat = 0; pat < 9; pat++) {
                int w = sizes[si][0], h = sizes[si][1], x, y, b;
                for (y = 0; y < h; y++)
                    for (x = 0; x < w; x++) {
                        unsigned v;
                        switch (pat) {
                        case 0: v = 0; break;                          /* black */
                        case 1: v = 0xffffff; break;                   /* white */
                        case 2: v = rnd() | (rnd() << 15); break;      /* noise */
                        case 3: v = x * 4; break;                      /* gradient across */
                        case 4: v = y * 7; break;                      /* gradient down */
                        case 5: v = ((x / 8) ^ (y / 8)) & 1 ? 0xff00ff : 0x00ff00; break;
                        case 6: v = (x % 3 == 0) ? 0x123456 : 0x654321; break;  /* short runs */
                        case 7: v = (rnd() % 7 == 0) ? rnd() : 0x4488cc; break; /* sparse noise */
                        default: v = (x + y) & 1 ? 0xaaaaaa : 0x555555; break;  /* dither */
                        }
                        for (b = 0; b < bpp; b++)
                            raw[(y * w + x) * bpp + b] = (uint8_t)(v >> (8 * b));
                    }
                emit(raw, w, h, bpp);
            }
    return 0;
}
