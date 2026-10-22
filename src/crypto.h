/*
 * Small, portable crypto primitives needed by RDP Standard Security:
 * MD5, SHA-1, RC4 and RSA modular exponentiation.
 *
 * Everything is byte-oriented and endian-neutral so the same code runs on
 * x86 Linux and big-endian 68k AmigaOS without changes.
 */
#ifndef RDP_CRYPTO_H
#define RDP_CRYPTO_H

#include <stdint.h>
#include <stddef.h>

typedef struct {
    uint32_t state[4];
    uint32_t count_lo, count_hi;  /* message length in bytes */
    uint8_t buf[64];
} md5_ctx;

void md5_init(md5_ctx *c);
void md5_update(md5_ctx *c, const void *data, size_t len);
void md5_final(md5_ctx *c, uint8_t out[16]);

typedef struct {
    uint32_t state[5];
    uint32_t count_lo, count_hi;
    uint8_t buf[64];
} sha1_ctx;

void sha1_init(sha1_ctx *c);
void sha1_update(sha1_ctx *c, const void *data, size_t len);
void sha1_final(sha1_ctx *c, uint8_t out[20]);

typedef struct {
    uint8_t s[256];
    uint8_t i, j;
} rc4_ctx;

void rc4_init(rc4_ctx *c, const uint8_t *key, size_t keylen);
void rc4_crypt(rc4_ctx *c, uint8_t *data, size_t len);

/*
 * out = base^exp mod mod. All numbers are little-endian byte strings of
 * `len` bytes (the RDP wire format); `mod` must be odd and len <= 256.
 * base must be < mod. Returns 0 on success, -1 on bad parameters.
 */
int rsa_modexp_le(uint8_t *out, const uint8_t *base, const uint8_t *exp,
                  size_t explen, const uint8_t *mod, size_t len);

#endif
