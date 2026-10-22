/* SHA-1 (FIPS 180-1), straightforward portable implementation. */
#include <string.h>
#include "crypto.h"

#define ROTL(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

static void sha1_block(sha1_ctx *c, const uint8_t *p)
{
    uint32_t w[80], a, b, cc, d, e, f, k, t;
    int i;

    for (i = 0; i < 16; i++)
        w[i] = ((uint32_t)p[i * 4] << 24) | ((uint32_t)p[i * 4 + 1] << 16) |
               ((uint32_t)p[i * 4 + 2] << 8) | (uint32_t)p[i * 4 + 3];
    for (i = 16; i < 80; i++)
        w[i] = ROTL(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
    a = c->state[0]; b = c->state[1]; cc = c->state[2]; d = c->state[3]; e = c->state[4];
    for (i = 0; i < 80; i++) {
        if (i < 20)      { f = (b & cc) | (~b & d);           k = 0x5a827999; }
        else if (i < 40) { f = b ^ cc ^ d;                    k = 0x6ed9eba1; }
        else if (i < 60) { f = (b & cc) | (b & d) | (cc & d); k = 0x8f1bbcdc; }
        else             { f = b ^ cc ^ d;                    k = 0xca62c1d6; }
        t = ROTL(a, 5) + f + e + k + w[i];
        e = d; d = cc; cc = ROTL(b, 30); b = a; a = t;
    }
    c->state[0] += a; c->state[1] += b; c->state[2] += cc;
    c->state[3] += d; c->state[4] += e;
}

void sha1_init(sha1_ctx *c)
{
    c->state[0] = 0x67452301; c->state[1] = 0xefcdab89; c->state[2] = 0x98badcfe;
    c->state[3] = 0x10325476; c->state[4] = 0xc3d2e1f0;
    c->count_lo = c->count_hi = 0;
}

void sha1_update(sha1_ctx *c, const void *data, size_t len)
{
    const uint8_t *p = data;
    size_t used = c->count_lo & 63;

    if ((c->count_lo += (uint32_t)len) < (uint32_t)len)
        c->count_hi++;
    while (len) {
        size_t n = 64 - used;
        if (n > len) n = len;
        memcpy(c->buf + used, p, n);
        used += n; p += n; len -= n;
        if (used == 64) { sha1_block(c, c->buf); used = 0; }
    }
}

void sha1_final(sha1_ctx *c, uint8_t out[20])
{
    uint8_t pad[72];
    uint32_t lo = c->count_lo << 3, hi = (c->count_hi << 3) | (c->count_lo >> 29);
    size_t used = c->count_lo & 63, padlen = (used < 56) ? 56 - used : 120 - used;
    int i;

    memset(pad, 0, sizeof(pad));
    pad[0] = 0x80;
    for (i = 0; i < 4; i++) {
        pad[padlen + i] = (uint8_t)(hi >> (24 - 8 * i));
        pad[padlen + 4 + i] = (uint8_t)(lo >> (24 - 8 * i));
    }
    sha1_update(c, pad, padlen + 8);
    for (i = 0; i < 20; i++)
        out[i] = (uint8_t)(c->state[i >> 2] >> (24 - 8 * (i & 3)));
}
