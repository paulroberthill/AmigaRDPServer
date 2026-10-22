/*
 * Interleaved RLE bitmap compression (MS-RDPBCGR 3.1.9), encoder side.
 * Valid for 8, 15, 16 and 24 bpp (32 bpp bitmaps need a different codec).
 */
#ifndef RDP_RLE_H
#define RDP_RLE_H

#include <stdint.h>
#include <stddef.h>

/*
 * Compress `h` scanlines of `w` pixels (`bpp_bytes` each, little-endian),
 * stored contiguously in wire order (bottom-up). Returns the compressed
 * size, or 0 if the result would not fit in `cap` bytes (send the bitmap
 * uncompressed instead).
 */
size_t rle_encode(const uint8_t *src, int w, int h, int bpp_bytes,
                  uint8_t *out, size_t cap);

#endif
