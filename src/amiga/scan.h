/*
 * Change detection for screen polling: compares a framebuffer (e.g. RTG
 * video memory) with a shadow copy, sampling every `step`-th row per poll.
 * Pure C apart from an optional fast copy hook, so it is unit-tested
 * natively (tests/test_scan.c).
 */
#ifndef RDP_SCAN_H
#define RDP_SCAN_H

#include <stddef.h>
#include <stdint.h>

#define SCAN_TILE 64

typedef struct {
    uint8_t *shadow;        /* last captured pixels, rows `shadow_pitch` apart */
    size_t shadow_pitch;
    int width;              /* pixels per row to compare */
    int bytes_pp;           /* bytes per pixel */
    int step, phase;        /* compare rows where row % step == phase */
    unsigned long read_bytes;   /* bytes read from the source (statistics) */
    /* Copy n bytes; NULL = memcpy. (The Amiga host uses CopyMemQuick.) */
    void (*copy)(uint8_t *dst, const uint8_t *src, size_t n);
} scan_ctx;

/*
 * Scan one band of `rows` rows starting at row `y` (src points at row y,
 * rows `pitch` bytes apart). Tile columns with a difference in a sampled
 * row (or already set in changed[]) are copied into the shadow in full
 * and set in changed[].
 */
void scan_band(scan_ctx *c, const uint8_t *src, long pitch, int y, int rows,
               uint8_t *changed);

/* Compare and copy every row of a band (for sources read row by row
 * anyway, like native screens via ReadPixelArray8()). */
void scan_band_full(scan_ctx *c, const uint8_t *src, long pitch, int y, int rows,
                    uint8_t *changed);

/* After all bands of a poll: sample the next rows next time. */
void scan_next_poll(scan_ctx *c);

#endif
