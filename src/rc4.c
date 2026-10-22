/* RC4 stream cipher. */
#include "crypto.h"

void rc4_init(rc4_ctx *c, const uint8_t *key, size_t keylen)
{
    unsigned i;
    uint8_t j = 0, t;

    for (i = 0; i < 256; i++)
        c->s[i] = (uint8_t)i;
    for (i = 0; i < 256; i++) {
        j = (uint8_t)(j + c->s[i] + key[i % keylen]);
        t = c->s[i]; c->s[i] = c->s[j]; c->s[j] = t;
    }
    c->i = c->j = 0;
}

void rc4_crypt(rc4_ctx *c, uint8_t *data, size_t len)
{
    uint8_t i = c->i, j = c->j, t, *s = c->s;

    while (len--) {
        i++;
        j = (uint8_t)(j + s[i]);
        t = s[i]; s[i] = s[j]; s[j] = t;
        *data++ ^= s[(uint8_t)(s[i] + s[j])];
    }
    c->i = i; c->j = j;
}
