/* Change detection for screen polling: see scan.h. */
#include <string.h>
#include "scan.h"

/* Do n bytes differ? Compares 32-bit words when everything is aligned. */
static int bytes_differ(const uint8_t *a, const uint8_t *b, size_t n)
{
    if (!(((uintptr_t)a | (uintptr_t)b | n) & 3)) {
        const uint32_t *la = (const uint32_t *)a, *lb = (const uint32_t *)b;
        for (n >>= 2; n; n--)
            if (*la++ != *lb++)
                return 1;
        return 0;
    }
    return memcmp(a, b, n) != 0;
}

static void copy(scan_ctx *c, uint8_t *dst, const uint8_t *src, size_t n)
{
    if (c->copy)
        c->copy(dst, src, n);
    else
        memcpy(dst, src, n);
}

/* Byte offset and length of tile column tx within a row. */
static size_t tile_span(const scan_ctx *c, int tx, size_t *n)
{
    size_t tile_bytes = (size_t)SCAN_TILE * c->bytes_pp, off = (size_t)tx * tile_bytes;
    *n = (size_t)c->width * c->bytes_pp - off;
    if (*n > tile_bytes)
        *n = tile_bytes;
    return off;
}

void scan_band(scan_ctx *c, const uint8_t *src, long pitch, int y, int rows, uint8_t *changed)
{
    int r, tx, ntx = (c->width + SCAN_TILE - 1) / SCAN_TILE;

    /* first row in the band with (y + r) % step == phase */
    for (r = (c->phase - y % c->step + c->step) % c->step; r < rows; r += c->step) {
        const uint8_t *row = src + (size_t)r * pitch;
        uint8_t *sh = c->shadow + (size_t)(y + r) * c->shadow_pitch;
        for (tx = 0; tx < ntx; tx++) {
            size_t n, off = tile_span(c, tx, &n);
            if (!changed[tx]) {
                c->read_bytes += n;
                if (bytes_differ(sh + off, row + off, n))
                    changed[tx] = 1;
            }
        }
    }
    for (tx = 0; tx < ntx; tx++) {
        size_t n, off = tile_span(c, tx, &n);
        if (!changed[tx])
            continue;
        for (r = 0; r < rows; r++)
            copy(c, c->shadow + (size_t)(y + r) * c->shadow_pitch + off,
                 src + (size_t)r * pitch + off, n);
        c->read_bytes += n * rows;
    }
}

void scan_band_full(scan_ctx *c, const uint8_t *src, long pitch, int y, int rows, uint8_t *changed)
{
    int r, tx, ntx = (c->width + SCAN_TILE - 1) / SCAN_TILE;

    for (r = 0; r < rows; r++, src += pitch) {
        uint8_t *sh = c->shadow + (size_t)(y + r) * c->shadow_pitch;
        for (tx = 0; tx < ntx; tx++) {
            size_t n, off = tile_span(c, tx, &n);
            if (changed[tx] || bytes_differ(sh + off, src + off, n)) {
                copy(c, sh + off, src + off, n);
                changed[tx] = 1;
            }
        }
    }
}

void scan_next_poll(scan_ctx *c)
{
    c->phase = (c->phase + 1) % c->step;
}
