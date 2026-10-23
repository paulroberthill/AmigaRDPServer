/*
 * Per-CPU dispatch for the RSA code. The binary is built with -m68020-60,
 * which multiplies 32x32->64 with the 020-040 mulu.l Dl:Dh instruction. The
 * 68060 lacks it, so there every one traps into 68060.library's emulation,
 * which dominates key generation. The Makefile therefore compiles bignum.c
 * and keygen.c twice, renaming their entry points to *_020 (-m68020-60) and
 * *_060 (-m68060 -DRSA_060, which uses only 32-bit multiplies and divides in
 * the hot loops; see mul32.h), and these wrappers pick one from exec's
 * AttnFlags (AFF_68060 is set by 68060.library).
 */
#include <exec/execbase.h>
#include <proto/exec.h>

#include "../crypto.h"
#include "../keygen.h"

int rsa_modexp_le_020(uint8_t *out, const uint8_t *base, const uint8_t *exp,
                      size_t explen, const uint8_t *mod, size_t len);
int rsa_modexp_le_060(uint8_t *out, const uint8_t *base, const uint8_t *exp,
                      size_t explen, const uint8_t *mod, size_t len);
int rsa512_generate_020(uint8_t n[64], uint8_t d[64], uint32_t *e,
                        keygen_random random, void *ctx);
int rsa512_generate_060(uint8_t n[64], uint8_t d[64], uint32_t *e,
                        keygen_random random, void *ctx);

static int is_060(void)
{
    return (SysBase->AttnFlags & AFF_68060) != 0;
}

int rsa_modexp_le(uint8_t *out, const uint8_t *base, const uint8_t *exp,
                  size_t explen, const uint8_t *mod, size_t len)
{
    if (is_060())
        return rsa_modexp_le_060(out, base, exp, explen, mod, len);
    return rsa_modexp_le_020(out, base, exp, explen, mod, len);
}

int rsa512_generate(uint8_t n[64], uint8_t d[64], uint32_t *e,
                    keygen_random random, void *ctx)
{
    if (is_060())
        return rsa512_generate_060(n, d, e, random, ctx);
    return rsa512_generate_020(n, d, e, random, ctx);
}
