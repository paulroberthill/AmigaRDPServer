/*
 * Bounds-checked byte stream reader/writer. RDP mixes little-endian
 * (RDP structures) and big-endian (TPKT, MCS/PER/BER) fields, so both are
 * provided. Out-of-range access sets `err` instead of touching memory, so
 * callers can parse a whole structure and check once at the end.
 */
#ifndef RDP_STREAM_H
#define RDP_STREAM_H

#include <stdint.h>
#include <string.h>

typedef struct {
    uint8_t *p;     /* current position */
    uint8_t *end;   /* one past the last valid byte */
    int err;
} stream;

static inline void s_init(stream *s, uint8_t *buf, size_t len)
{
    s->p = buf; s->end = buf + len; s->err = 0;
}

static inline size_t s_left(const stream *s) { return (size_t)(s->end - s->p); }

static inline int s_check(stream *s, size_t n)
{
    if (s->err || s_left(s) < n) { s->err = 1; return 0; }
    return 1;
}

static inline void s_skip(stream *s, size_t n) { if (s_check(s, n)) s->p += n; }

static inline uint8_t s_u8(stream *s)
{
    return s_check(s, 1) ? *s->p++ : 0;
}

static inline uint16_t s_u16le(stream *s)
{
    uint16_t v = 0;
    if (s_check(s, 2)) { v = (uint16_t)(s->p[0] | (s->p[1] << 8)); s->p += 2; }
    return v;
}

static inline uint16_t s_u16be(stream *s)
{
    uint16_t v = 0;
    if (s_check(s, 2)) { v = (uint16_t)((s->p[0] << 8) | s->p[1]); s->p += 2; }
    return v;
}

static inline uint32_t s_u32le(stream *s)
{
    uint32_t v = 0;
    if (s_check(s, 4)) {
        v = (uint32_t)s->p[0] | ((uint32_t)s->p[1] << 8) |
            ((uint32_t)s->p[2] << 16) | ((uint32_t)s->p[3] << 24);
        s->p += 4;
    }
    return v;
}

static inline void s_read(stream *s, void *dst, size_t n)
{
    if (s_check(s, n)) { memcpy(dst, s->p, n); s->p += n; }
}

static inline void w_u8(stream *s, unsigned v)
{
    if (s_check(s, 1)) *s->p++ = (uint8_t)v;
}

static inline void w_u16le(stream *s, unsigned v)
{
    if (s_check(s, 2)) { s->p[0] = (uint8_t)v; s->p[1] = (uint8_t)(v >> 8); s->p += 2; }
}

static inline void w_u16be(stream *s, unsigned v)
{
    if (s_check(s, 2)) { s->p[0] = (uint8_t)(v >> 8); s->p[1] = (uint8_t)v; s->p += 2; }
}

static inline void w_u32le(stream *s, uint32_t v)
{
    if (s_check(s, 4)) {
        s->p[0] = (uint8_t)v; s->p[1] = (uint8_t)(v >> 8);
        s->p[2] = (uint8_t)(v >> 16); s->p[3] = (uint8_t)(v >> 24);
        s->p += 4;
    }
}

static inline void w_bytes(stream *s, const void *src, size_t n)
{
    if (s_check(s, n)) { memcpy(s->p, src, n); s->p += n; }
}

static inline void w_zero(stream *s, size_t n)
{
    if (s_check(s, n)) { memset(s->p, 0, n); s->p += n; }
}

/* Patch a little-endian u16 at an earlier position. */
static inline void put_u16le(uint8_t *p, unsigned v)
{
    p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8);
}

#endif
