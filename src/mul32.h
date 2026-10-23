/*
 * 32x32->64 multiply for the RSA code (bignum.c, keygen.c).
 *
 * The 68060 has no 64-bit mulu.l (Dl:Dh) or divu.l (Dr:Dq); 68060.library
 * emulates them on a trap, slowly. GCC's libgcc __muldi3/__umoddi3 use those
 * same instructions, so -m68060 alone does not avoid them. Builds with
 * RSA_060 defined (the 060 copy in the Amiga binary, see src/amiga/cpu.c)
 * therefore compose the product from four 16x16 multiplies instead.
 */
#ifndef RDP_MUL32_H
#define RDP_MUL32_H

#include <stdint.h>

static inline uint64_t mul32x32(uint32_t a, uint32_t b)
{
#ifdef RSA_060
    uint32_t al = a & 0xffff, ah = a >> 16, bl = b & 0xffff, bh = b >> 16;
    uint32_t ll = al * bl, lh = al * bh, hl = ah * bl, hh = ah * bh;
    uint32_t mid = (ll >> 16) + (lh & 0xffff) + (hl & 0xffff);   /* < 3 * 2^16 */
    uint32_t lo = (mid << 16) | (ll & 0xffff);
    uint32_t hi = hh + (lh >> 16) + (hl >> 16) + (mid >> 16);
    return ((uint64_t)hi << 32) | lo;
#else
    return (uint64_t)a * b;
#endif
}

#endif
