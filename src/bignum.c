/*
 * Minimal RSA modular exponentiation using Montgomery multiplication with
 * 32-bit limbs. Only used once per connection (decrypting the client
 * random), so it favours simplicity over speed.
 *
 * Note for the 68k port: this deliberately avoids "shift a 64-bit value
 * until it is zero" loops, which GCC 6.5 m68k miscompiles at -O2.
 */
#include <string.h>
#include "crypto.h"

#define MAXLIMBS 64   /* 2048 bits */

typedef uint32_t limb;
typedef uint64_t dlimb;

/* r = a * b * R^-1 mod n, R = 2^(32k). r may not alias a or b. */
static void mont_mul(limb *r, const limb *a, const limb *b, const limb *n,
                     limb n0inv, int k)
{
    limb t[MAXLIMBS + 2], m;
    dlimb acc;
    int i, j;

    memset(t, 0, sizeof(limb) * (k + 2));
    for (i = 0; i < k; i++) {
        acc = 0;
        for (j = 0; j < k; j++) {
            acc = (dlimb)a[j] * b[i] + t[j] + (acc >> 32);
            t[j] = (limb)acc;
        }
        acc = (dlimb)t[k] + (acc >> 32);
        t[k] = (limb)acc;
        t[k + 1] = (limb)(acc >> 32);

        m = t[0] * n0inv;
        acc = (dlimb)m * n[0] + t[0];
        for (j = 1; j < k; j++) {
            acc = (dlimb)m * n[j] + t[j] + (acc >> 32);
            t[j - 1] = (limb)acc;
        }
        acc = (dlimb)t[k] + (acc >> 32);
        t[k - 1] = (limb)acc;
        t[k] = t[k + 1] + (limb)(acc >> 32);
    }

    /* if t >= n then t -= n */
    if (t[k] == 0) {
        for (i = k - 1; i >= 0; i--)
            if (t[i] != n[i])
                break;
        if (i >= 0 && t[i] < n[i]) {
            memcpy(r, t, sizeof(limb) * k);
            return;
        }
    }
    acc = (dlimb)1 << 32;  /* t - n computed as t + ~n + 1 (carry in) */
    for (i = 0; i < k; i++) {
        acc = (dlimb)t[i] + (limb)~n[i] + (acc >> 32);
        r[i] = (limb)acc;
    }
}

static void from_le(limb *x, const uint8_t *b, size_t len, int k)
{
    size_t i;
    memset(x, 0, sizeof(limb) * k);
    for (i = 0; i < len; i++)
        x[i / 4] |= (limb)b[i] << (8 * (i % 4));
}

int rsa_modexp_le(uint8_t *out, const uint8_t *base, const uint8_t *exp,
                  size_t explen, const uint8_t *mod, size_t len)
{
    limb n[MAXLIMBS], a[MAXLIMBS], x[MAXLIMBS], r2[MAXLIMBS], one[MAXLIMBS];
    limb tmp[MAXLIMBS], n0inv, inv;
    int k = (int)((len + 3) / 4), i, bit, started = 0;
    size_t bi;

    if (len == 0 || len > MAXLIMBS * 4 || !(mod[0] & 1))
        return -1;
    from_le(n, mod, len, k);
    from_le(a, base, len, k);

    /* n0inv = -n^-1 mod 2^32 (Newton iteration, 5 steps gives 32 bits) */
    inv = 1;
    for (i = 0; i < 5; i++)
        inv *= 2 - n[0] * inv;
    n0inv = (limb)0 - inv;

    /* r2 = R^2 mod n, by doubling 1 a total of 2*32*k times */
    memset(r2, 0, sizeof(limb) * k);
    r2[0] = 1;
    for (i = 0; i < 64 * k; i++) {
        limb carry = 0;
        int j, ge;
        for (j = 0; j < k; j++) {
            limb v = r2[j];
            r2[j] = (v << 1) | carry;
            carry = v >> 31;
        }
        ge = carry;
        if (!ge) {
            for (j = k - 1; j >= 0; j--)
                if (r2[j] != n[j])
                    break;
            ge = (j < 0) || (r2[j] > n[j]);
        }
        if (ge) {
            dlimb acc = (dlimb)1 << 32;
            for (j = 0; j < k; j++) {
                acc = (dlimb)r2[j] + (limb)~n[j] + (acc >> 32);
                r2[j] = (limb)acc;
            }
        }
    }

    memset(one, 0, sizeof(limb) * k);
    one[0] = 1;
    mont_mul(tmp, a, r2, n, n0inv, k);   /* a in Montgomery form */
    memcpy(a, tmp, sizeof(limb) * k);
    mont_mul(x, one, r2, n, n0inv, k);   /* 1 in Montgomery form */

    for (bi = explen; bi-- > 0;) {
        for (bit = 7; bit >= 0; bit--) {
            if (started) {
                mont_mul(tmp, x, x, n, n0inv, k);
                memcpy(x, tmp, sizeof(limb) * k);
            }
            if ((exp[bi] >> bit) & 1) {
                mont_mul(tmp, x, a, n, n0inv, k);
                memcpy(x, tmp, sizeof(limb) * k);
                started = 1;
            }
        }
    }
    mont_mul(tmp, x, one, n, n0inv, k);  /* leave Montgomery form */

    for (bi = 0; bi < len; bi++)
        out[bi] = (uint8_t)(tmp[bi / 4] >> (8 * (bi % 4)));
    return 0;
}
