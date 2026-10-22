/* 512-bit RSA key generation for the server key (see keygen.c). */
#ifndef RDP_KEYGEN_H
#define RDP_KEYGEN_H

#include <stddef.h>
#include <stdint.h>

typedef void (*keygen_random)(void *ctx, uint8_t *out, size_t len);

/*
 * Generate a 512-bit RSA key with e = 65537. The modulus and private
 * exponent are written little-endian (the RDP wire order). Returns 0, or
 * -1 if no valid key resulted (practically impossible).
 */
int rsa512_generate(uint8_t n[64], uint8_t d[64], uint32_t *e,
                    keygen_random random, void *ctx);

#endif
