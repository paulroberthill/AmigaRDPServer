/*
 * Interleaved RLE encoder (MS-RDPBCGR 3.1.9 / 2.2.9.1.1.3.1.2.4).
 *
 * Only three of the many order types are used, which keeps the decoder's
 * subtle state rules out of play:
 *   - background run: pixels equal to the scanline before them in the
 *     stream. Never started on the first scanline (where it would mean
 *     black) and never emitted twice in a row (the decoder would insert a
 *     foreground pixel between two background runs);
 *   - colour run: n pixels of one colour;
 *   - colour image: n literal pixels.
 */
#include <string.h>
#include "rle.h"

#define BG_RUN      0x0     /* regular code ids (high 3 bits) */
#define COLOR_RUN   0x3
#define COLOR_IMAGE 0x4
#define MEGA(code)  (0xf0 | (code))     /* MEGA_MEGA variants: 0xF0, 0xF3, 0xF4 */

#define MIN_BG_RUN    3
#define MIN_COLOR_RUN 3

typedef struct {
    uint8_t *p, *end;
    int overflow;
} out_t;

static void put_byte(out_t *o, unsigned b)
{
    if (o->p < o->end)
        *o->p++ = (uint8_t)b;
    else
        o->overflow = 1;
}

static void put_bytes(out_t *o, const uint8_t *src, size_t n)
{
    if ((size_t)(o->end - o->p) >= n) {
        memcpy(o->p, src, n);
        o->p += n;
    } else
        o->overflow = 1;
}

/* Order header with run length: regular (1..31), extended (32..287) or
 * MEGA_MEGA (anything up to 65535). */
static void put_order(out_t *o, unsigned code, unsigned len)
{
    if (len < 32) {
        put_byte(o, (code << 5) | len);
    } else if (len < 32 + 256) {
        put_byte(o, code << 5);
        put_byte(o, len - 32);
    } else {
        put_byte(o, MEGA(code));
        put_byte(o, len & 0xff);
        put_byte(o, len >> 8);
    }
}

static uint32_t pixel(const uint8_t *src, size_t i, int bpp)
{
    const uint8_t *p = src + i * bpp;
    switch (bpp) {
    case 1:  return p[0];
    case 2:  return (uint32_t)p[0] | ((uint32_t)p[1] << 8);
    default: return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16);
    }
}

size_t rle_encode(const uint8_t *src, int w, int h, int bpp, uint8_t *out, size_t cap)
{
    size_t n = (size_t)w * h, i = 0, lit_start = 0, lit_len = 0;
    int last_was_bg = 0;
    out_t o;

    o.p = out; o.end = out + cap; o.overflow = 0;

    while (i < n && !o.overflow) {
        size_t bg = 0, run = 1;
        uint32_t c = pixel(src, i, bpp);

        /* Background run: only after the first scanline, and never
         * directly after another one. */
        if (i >= (size_t)w && !(last_was_bg && lit_len == 0)) {
            while (i + bg < n && bg < 65535 &&
                   pixel(src, i + bg, bpp) == pixel(src, i + bg - w, bpp))
                bg++;
        }
        while (i + run < n && run < 65535 && pixel(src, i + run, bpp) == c)
            run++;

        if (bg >= MIN_BG_RUN && bg >= run) {
            if (lit_len) {
                put_order(&o, COLOR_IMAGE, (unsigned)lit_len);
                put_bytes(&o, src + lit_start * bpp, lit_len * bpp);
                lit_len = 0;
            }
            put_order(&o, BG_RUN, (unsigned)bg);
            i += bg;
            last_was_bg = 1;
        } else if (run >= MIN_COLOR_RUN) {
            if (lit_len) {
                put_order(&o, COLOR_IMAGE, (unsigned)lit_len);
                put_bytes(&o, src + lit_start * bpp, lit_len * bpp);
                lit_len = 0;
            }
            put_order(&o, COLOR_RUN, (unsigned)run);
            put_bytes(&o, src + i * bpp, (size_t)bpp);
            i += run;
            last_was_bg = 0;
        } else {
            if (!lit_len)
                lit_start = i;
            lit_len++;
            i++;
            last_was_bg = 0;
            if (lit_len == 65535) {
                put_order(&o, COLOR_IMAGE, (unsigned)lit_len);
                put_bytes(&o, src + lit_start * bpp, lit_len * bpp);
                lit_len = 0;
            }
        }
    }
    if (lit_len) {
        put_order(&o, COLOR_IMAGE, (unsigned)lit_len);
        put_bytes(&o, src + lit_start * bpp, lit_len * bpp);
    }
    return o.overflow ? 0 : (size_t)(o.p - out);
}
