/*
 * 512-bit RSA key generation (e = 65537) for the server key, so that each
 * install has its own key instead of one compiled into a shared binary.
 *
 * Primes: random 256-bit odd numbers with the top two bits set (so the
 * product has exactly 512 bits), trial division by small primes, then
 * Miller-Rabin using rsa_modexp_le(). The private exponent is computed as
 * d = (k * phi + 1) / e, where k makes the division exact; e is small, so
 * this needs only single-limb arithmetic on big numbers.
 *
 * Like bignum.c this avoids "shift a 64-bit value until zero" loops, which
 * GCC 6.5 miscompiles for m68k at -O2.
 */
#include <string.h>
#include "crypto.h"
#include "keygen.h"

#define PL 8                    /* limbs in a 256-bit prime */
#define E  65537u

typedef uint32_t limb;

static void to_bytes(uint8_t *out, const limb *x, int k)
{
    int i;
    for (i = 0; i < 4 * k; i++)
        out[i] = (uint8_t)(x[i / 4] >> (8 * (i % 4)));
}

static void from_bytes(limb *x, const uint8_t *in, int k)
{
    int i;
    memset(x, 0, sizeof(limb) * k);
    for (i = 0; i < 4 * k; i++)
        x[i / 4] |= (limb)in[i] << (8 * (i % 4));
}

static uint32_t mod_small(const limb *x, int k, uint32_t m)
{
    uint64_t r = 0;
    int i;
    for (i = k - 1; i >= 0; i--)
        r = ((r << 32) | x[i]) % m;
    return (uint32_t)r;
}

/* x == y ? */
static int equal(const limb *x, const limb *y, int k)
{
    return !memcmp(x, y, sizeof(limb) * k);
}

/* out (2k limbs) = a * b (k limbs each) */
static void mul(limb *out, const limb *a, const limb *b, int k)
{
    int i, j;
    memset(out, 0, sizeof(limb) * 2 * k);
    for (i = 0; i < k; i++) {
        uint64_t carry = 0;
        for (j = 0; j < k; j++) {
            uint64_t t = (uint64_t)a[i] * b[j] + out[i + j] + carry;
            out[i + j] = (limb)t;
            carry = t >> 32;
        }
        out[i + k] = (limb)carry;
    }
}

/* Miller-Rabin with `rounds` random bases < 2^224 (p has its top bit set). */
static int probably_prime(const limb *p, int rounds, keygen_random random, void *ctx)
{
    static const uint16_t small[] = {
        3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73,
        79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157,
        163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229, 233, 239,
        241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307, 311, 313, 317, 331,
        337, 347, 349, 353, 359, 367, 373, 379, 383, 389, 397, 401, 409, 419, 421,
        431, 433, 439, 443, 449, 457, 461, 463, 467, 479, 487, 491, 499, 503, 509
    };
    uint8_t pb[4 * PL], db[4 * PL], ab[4 * PL], xb[4 * PL], pm1b[4 * PL], one[4 * PL];
    limb d[PL];
    unsigned i;
    int s = 0, r, j;
    static const uint8_t two = 2;

    for (i = 0; i < sizeof(small) / sizeof(small[0]); i++)
        if (mod_small(p, PL, small[i]) == 0)
            return 0;

    /* p - 1 = d * 2^s */
    memcpy(d, p, sizeof(d));
    d[0] &= ~(limb)1;                   /* p is odd */
    to_bytes(pm1b, d, PL);
    while (!(d[0] & 1)) {
        for (j = 0; j < PL - 1; j++)
            d[j] = (d[j] >> 1) | (d[j + 1] << 31);
        d[PL - 1] >>= 1;
        s++;
    }
    to_bytes(pb, p, PL);
    to_bytes(db, d, PL);
    memset(one, 0, sizeof(one));
    one[0] = 1;

    for (r = 0; r < rounds; r++) {
        random(ctx, ab, sizeof(ab));
        ab[sizeof(ab) - 1] = ab[sizeof(ab) - 2] = ab[sizeof(ab) - 3] = ab[sizeof(ab) - 4] = 0;
        ab[0] |= 2;                     /* base >= 2 */
        if (rsa_modexp_le(xb, ab, db, sizeof(db), pb, sizeof(pb)))
            return 0;
        if (!memcmp(xb, one, sizeof(xb)) || !memcmp(xb, pm1b, sizeof(xb)))
            continue;
        for (j = 1; j < s; j++) {
            uint8_t t[4 * PL];
            rsa_modexp_le(t, xb, &two, 1, pb, sizeof(pb));
            memcpy(xb, t, sizeof(xb));
            if (!memcmp(xb, pm1b, sizeof(xb)))
                break;
        }
        if (j >= s)
            return 0;                   /* composite */
    }
    return 1;
}

static void random_prime(limb *p, keygen_random random, void *ctx)
{
    uint8_t b[4 * PL];

    for (;;) {
        random(ctx, b, sizeof(b));
        from_bytes(p, b, PL);
        p[PL - 1] |= 0xc0000000u;       /* top two bits: product has 512 bits */
        p[0] |= 1;
        /* gcd(e, p - 1) must be 1, i.e. p mod e != 1 (e is prime) */
        if (mod_small(p, PL, E) != 1 && probably_prime(p, 24, random, ctx))
            return;
    }
}

/* Inverse of a modulo m (m prime, a != 0) with the extended Euclid. */
static uint32_t inverse_small(uint32_t a, uint32_t m)
{
    int64_t t = 0, nt = 1, r = m, nr = a;
    while (nr) {
        int64_t q = r / nr, tmp;
        tmp = t - q * nt; t = nt; nt = tmp;
        tmp = r - q * nr; r = nr; nr = tmp;
    }
    return (uint32_t)(t < 0 ? t + m : t);
}

int rsa512_generate(uint8_t n_out[64], uint8_t d_out[64], uint32_t *e_out,
                    keygen_random random, void *ctx)
{
    limb p[PL], q[PL], n[2 * PL], phi[2 * PL + 1], kphi[2 * PL + 1];
    uint8_t m[64], c[64], m2[64], eb[4];
    uint32_t k, rem;
    uint64_t carry;
    int i, attempt;

    for (attempt = 0; attempt < 8; attempt++) {
        random_prime(p, random, ctx);
        do
            random_prime(q, random, ctx);
        while (equal(p, q, PL));
        mul(n, p, q, PL);

        /* phi = (p - 1)(q - 1); both are odd, so subtracting 1 never borrows */
        p[0] -= 1;
        q[0] -= 1;
        mul(phi, p, q, PL);
        phi[2 * PL] = 0;

        /* k * phi = -1 (mod e)  =>  d = (k * phi + 1) / e is exact */
        rem = mod_small(phi, 2 * PL, E);
        k = (uint32_t)(((uint64_t)(E - 1) * inverse_small(rem, E)) % E);
        carry = 1;                      /* the + 1 */
        for (i = 0; i < 2 * PL + 1; i++) {
            uint64_t t = (uint64_t)phi[i] * k + carry;
            kphi[i] = (limb)t;
            carry = t >> 32;
        }
        rem = 0;
        for (i = 2 * PL; i >= 0; i--) {
            uint64_t cur = ((uint64_t)rem << 32) | kphi[i];
            kphi[i] = (limb)(cur / E);
            rem = (uint32_t)(cur % E);
        }
        if (rem != 0 || kphi[2 * PL] != 0)
            continue;                   /* cannot happen; be safe */

        to_bytes(n_out, n, 2 * PL);
        to_bytes(d_out, kphi, 2 * PL);

        /* self-test: m^e^d == m for a random m < n */
        random(ctx, m, sizeof(m));
        m[63] = 0;
        eb[0] = (uint8_t)E; eb[1] = (uint8_t)(E >> 8); eb[2] = (uint8_t)(E >> 16); eb[3] = 0;
        if (rsa_modexp_le(c, m, eb, 4, n_out, 64) ||
            rsa_modexp_le(m2, c, d_out, 64, n_out, 64) || memcmp(m, m2, 64))
            continue;
        *e_out = E;
        return 0;
    }
    return -1;
}
